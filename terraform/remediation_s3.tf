locals {
  s3_fn_name = "guardrail-s3-public-access"
}

# Zip up the Lambda code so Terraform can upload it.
data "archive_file" "s3_remediation" {
  type             = "zip"
  source_file      = "${path.module}/../lambdas/s3_public_access/remediate.py"
  output_path      = "${path.module}/s3_public_access.zip"
  output_file_mode = "0666"
}

# We create the log group ourselves so we control how long logs are kept.
resource "aws_cloudwatch_log_group" "s3_remediation" {
  #checkov:skip=CKV_AWS_158:Lambda logs only (no secrets logged); AWS-owned-key encryption at rest is adequate for a lab project, avoiding extra KMS key-policy complexity
  #checkov:skip=CKV_AWS_338:14-day retention is a deliberate cost/noise control for a lab; the audit trail of record is CloudTrail -> the versioned, 30-day log bucket, not these execution logs
  name              = "/aws/lambda/${local.s3_fn_name}"
  retention_in_days = 14
}

# Who may use this role: only the Lambda service.
data "aws_iam_policy_document" "s3_remediation_trust" {
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

# What the role may do: nothing more than the job needs.
data "aws_iam_policy_document" "s3_remediation_permissions" {
  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.s3_remediation.arn}:*"]
  }

  statement {
    sid    = "ReadAndFixBlockPublicAccess"
    effect = "Allow"
    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:PutBucketTagging",
    ]
    resources = ["arn:${local.partition}:s3:::*"]
  }

  statement {
    sid       = "SendAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role" "s3_remediation" {
  name               = "guardrail-s3-remediation"
  path               = "/guardrail/"
  assume_role_policy = data.aws_iam_policy_document.s3_remediation_trust.json
}

resource "aws_iam_role_policy" "s3_remediation" {
  name   = "s3-remediation-permissions"
  role   = aws_iam_role.s3_remediation.id
  policy = data.aws_iam_policy_document.s3_remediation_permissions.json
}

resource "aws_lambda_function" "s3_remediation" {
  #checkov:skip=CKV_AWS_116:No DLQ - every invocation already logs its outcome and sends an SNS alert; add a DLQ if this were handling untrusted, high-volume input
  #checkov:skip=CKV_AWS_117:No VPC - this function only calls AWS APIs over AWS's public endpoints, never a private network resource; a VPC would add a NAT gateway cost with no security benefit
  #checkov:skip=CKV_AWS_272:No code signing - AWS Signer is enterprise supply-chain tooling, disproportionate for a single-developer lab project
  #checkov:skip=CKV_AWS_173:Default AWS-owned-key encryption is adequate - DRY_RUN and TOPIC_ARN are not secrets; no credentials are ever placed in Lambda environment variables
  #checkov:skip=CKV_AWS_50:X-Ray tracing is an observability nice-to-have, not a security control, and adds minor cost for a lab project
  reserved_concurrent_executions = 5 # caps runaway invocations/cost if an event storm ever occurs
  function_name                  = local.s3_fn_name
  role                           = aws_iam_role.s3_remediation.arn
  runtime                        = "python3.13"
  handler                        = "remediate.handler"
  filename                       = data.archive_file.s3_remediation.output_path
  source_code_hash               = data.archive_file.s3_remediation.output_base64sha256
  timeout                        = 30
  memory_size                    = 128

  environment {
    variables = {
      DRY_RUN   = tostring(var.s3_remediation_dry_run)
      TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.s3_remediation,
    aws_iam_role_policy.s3_remediation,
  ]
}

# The trigger: S3 "who changed what" events that CloudTrail records.
resource "aws_cloudwatch_event_rule" "s3_public_access" {
  name        = "guardrail-s3-public-access-change"
  description = "Fires when someone changes an S3 bucket policy, ACL or Block Public Access settings"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
      ]
      # ignore calls that failed (for example access denied)
      errorCode = [{ exists = false }]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_remediation" {
  rule      = aws_cloudwatch_event_rule.s3_public_access.name
  target_id = "s3-remediation-lambda"
  arn       = aws_lambda_function.s3_remediation.arn
}

# Lets EventBridge (and only this rule) start the Lambda.
resource "aws_lambda_permission" "eventbridge_s3" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_access.arn
}

output "s3_remediation_function_name" {
  value = aws_lambda_function.s3_remediation.function_name
}