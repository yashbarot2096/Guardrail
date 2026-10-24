data "aws_iam_policy_document" "lab_boundary" {
  statement {
    sid       = "AllowEverythingWithinGroupPermissions"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }

  statement {
    sid    = "DenyIdentityChanges"
    effect = "Deny"
    actions = [
      "iam:Create*",
      "iam:Delete*",
      "iam:Put*",
      "iam:Update*",
      "iam:Attach*",
      "iam:Detach*",
      "iam:Add*",
      "iam:Remove*",
      "iam:Set*",
      "iam:PassRole",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyTamperingWithCloudTrail"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyTamperingWithLogBucket"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
  }

  statement {
    sid    = "DenyTamperingWithLogKey"
    effect = "Deny"
    actions = [
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "kms:DisableKeyRotation",
      "kms:PutKeyPolicy",
    ]
    resources = [aws_kms_key.logs.arn]
  }
}

resource "aws_iam_policy" "lab_boundary" {
  name        = "guardrail-lab-boundary"
  path        = "/guardrail/"
  description = "Permission boundary for lab users: no IAM changes, no tampering with logging"
  policy      = data.aws_iam_policy_document.lab_boundary.json
}