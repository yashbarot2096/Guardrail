data "aws_iam_policy_document" "lab_boundary" {
  #checkov:skip=CKV_AWS_1:This is an IAM permission boundary, not a grant - it is a CEILING combined with each user's own narrower identity policy, never used alone. A boundary must start broad (Allow *) so it doesn't restrict more than intended; the real restriction is the Deny statements below plus each user's attached policy.
  #checkov:skip=CKV_AWS_49:See above - broad Allow is required boundary syntax, not an admin grant.
  #checkov:skip=CKV_AWS_107:See above - covered by the same boundary pattern; no credentials can be exfiltrated because iam:Create*/Put*/Update* are explicitly denied below.
  #checkov:skip=CKV_AWS_108:See above - data exfiltration via policy change is blocked by the identity-change denies below.
  #checkov:skip=CKV_AWS_109:See above - resource exposure via IAM/policy change is blocked by the identity-change denies below.
  #checkov:skip=CKV_AWS_110:See above - privilege escalation is specifically what the DenyIdentityChanges statement below exists to block.
  #checkov:skip=CKV_AWS_111:See above - unconstrained write access is narrowed by every attached identity policy; the boundary itself is intentionally the wide half of the pair.
  #checkov:skip=CKV_AWS_356:See above - "*" resources in a boundary's allow statement are expected; real restriction comes from the deny statements and each user's identity policy.
  #checkov:skip=CKV2_AWS_40:See above - this is a boundary, evaluated as an intersection with identity policies, not a standalone grant of full IAM privileges.
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
    not_resources = ["arn:${local.partition}:iam::${local.account_id}:mfa/*"]
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