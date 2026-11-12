locals {
  keys_fn_name = "guardrail-key-quarantine"
}

data "archive_file" "key_quarantine" {
  type             = "zip"
  source_file      = "${path.module}/../lambdas/quarantine_keys/remediate.py"
  output_path      = "${path.module}/key_quarantine.zip"
  output_file_mode = "0666"
}

resource "aws_cloudwatch_log_group" "key_quarantine" {
  #checkov:skip=CKV_AWS_158:Lambda logs only (no secrets logged); AWS-owned-key encryption at rest is adequate for a lab project, avoiding extra KMS key-policy complexity
  #checkov:skip=CKV_AWS_338:14-day retention is a deliberate cost/noise control for a lab; the audit trail of record is CloudTrail -> the versioned, 30-day log bucket, not these execution logs
  name              = "/aws/lambda/${local.keys_fn_name}"
  retention_in_days = 14
}

data "aws_iam_policy_document" "key_quarantine_trust" {
  statement {
    sid     = "LambdaCanAssumeThisRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "key_quarantine_permissions" {
  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.key_quarantine.arn}:*"]
  }

  # Read keys/tags and deactivate keys on any user...
  statement {
    sid    = "ContainCompromisedUser"
    effect = "Allow"
    actions = [
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
      "iam:ListUserTags",
      "iam:TagUser",
    ]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
  }

  # ...except the break-glass admin: a hard IAM ceiling, even if code has a bug.
  statement {
    sid       = "NeverTouchAdmin"
    effect    = "Deny"
    actions   = ["iam:UpdateAccessKey", "iam:TagUser"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/${var.protected_iam_users}"]
  }

  statement {
    sid       = "SendAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role" "key_quarantine" {
  name               = "guardrail-key-quarantine"
  path               = "/guardrail/"
  assume_role_policy = data.aws_iam_policy_document.key_quarantine_trust.json
}

resource "aws_iam_role_policy" "key_quarantine" {
  name   = "key-quarantine-permissions"
  role   = aws_iam_role.key_quarantine.id
  policy = data.aws_iam_policy_document.key_quarantine_permissions.json
}

resource "aws_lambda_function" "key_quarantine" {
  #checkov:skip=CKV_AWS_116:No DLQ - every invocation already logs its outcome and sends an SNS alert; add a DLQ if this were handling untrusted, high-volume input
  #checkov:skip=CKV_AWS_117:No VPC - this function only calls AWS APIs over AWS's public endpoints, never a private network resource; a VPC would add a NAT gateway cost with no security benefit
  #checkov:skip=CKV_AWS_272:No code signing - AWS Signer is enterprise supply-chain tooling, disproportionate for a single-developer lab project
  #checkov:skip=CKV_AWS_173:Default AWS-owned-key encryption is adequate - none of these environment variables are secrets; no credentials are ever placed in Lambda environment variables
  #checkov:skip=CKV_AWS_50:X-Ray tracing is an observability nice-to-have, not a security control, and adds minor cost for a lab project
  reserved_concurrent_executions = 5 # caps runaway invocations/cost if an event storm ever occurs
  function_name                  = local.keys_fn_name
  role                           = aws_iam_role.key_quarantine.arn
  runtime                        = "python3.13"
  handler                        = "remediate.handler"
  filename                       = data.archive_file.key_quarantine.output_path
  source_code_hash               = data.archive_file.key_quarantine.output_base64sha256
  timeout                        = 30
  memory_size                    = 128

  environment {
    variables = {
      DRY_RUN         = tostring(var.keys_remediation_dry_run)
      TOPIC_ARN       = aws_sns_topic.alerts.arn
      PROTECTED_USERS = var.protected_iam_users
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.key_quarantine,
    aws_iam_role_policy.key_quarantine,
  ]
}

# Fires when the AWS compromised-key quarantine policy is attached to a user.
resource "aws_cloudwatch_event_rule" "key_quarantine" {
  name        = "guardrail-compromised-key-quarantine"
  description = "Fires when AWSCompromisedKeyQuarantine* is attached to an IAM user"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["AttachUserPolicy"]
      requestParameters = {
        policyArn = [{ prefix = "arn:${local.partition}:iam::aws:policy/AWSCompromisedKeyQuarantine" }]
      }
      errorCode = [{ exists = false }]
    }
  })
}

resource "aws_cloudwatch_event_target" "key_quarantine" {
  rule      = aws_cloudwatch_event_rule.key_quarantine.name
  target_id = "key-quarantine-lambda"
  arn       = aws_lambda_function.key_quarantine.arn
}

resource "aws_lambda_permission" "eventbridge_keys" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.key_quarantine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.key_quarantine.arn
}

output "key_quarantine_function_name" {
  value = aws_lambda_function.key_quarantine.function_name
}