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
  function_name    = local.s3_fn_name
  role             = aws_iam_role.s3_remediation.arn
  runtime          = "python3.13"
  handler          = "remediate.handler"
  filename         = data.archive_file.s3_remediation.output_path
  source_code_hash = data.archive_file.s3_remediation.output_base64sha256
  timeout          = 30
  memory_size      = 128

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