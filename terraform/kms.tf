data "aws_iam_policy_document" "logs_key" {
  #checkov:skip=CKV_AWS_109:This is the KMS key's own resource policy, not an identity policy. A key policy is always scoped to the one key it is attached to, so "Resource" = "*" here means "this key" - it can never reach any other key or resource in the account, regardless of what is written here.
  #checkov:skip=CKV_AWS_111:Same reasoning as above - the "kms:*" write access in this statement is confined to this single key by the nature of a resource policy, not widened by "Resource" = "*".
  #checkov:skip=CKV_AWS_356:Same reasoning - "Resource" = "*" is the standard, AWS-documented syntax for a KMS key's own policy (see AWS's default key policy template); it is not an open wildcard the way it would be in an identity-based (IAM user/role) policy.
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AllowCloudTrailToDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "Guardrail: encrypts CloudTrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.logs_key.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/guardrail-logs"
  target_key_id = aws_kms_key.logs.key_id
}