data "aws_iam_policy_document" "require_mfa" {
  #checkov:skip=CKV_AWS_356:The "*" resources here belong to two kinds of statement that both require it: read-only list/describe MFA actions (no narrower ARN type exists), and the DenyEverythingUnlessMFA statement, which must cover "*" by design since it blocks all unauthenticated-by-MFA actions.
  statement {
    sid       = "AllowListVirtualMFADevices"
    effect    = "Allow"
    actions   = ["iam:ListVirtualMFADevices"]
    resources = ["*"]
  }

  statement {
    sid       = "AllowCreateVirtualMFADevice"
    effect    = "Allow"
    actions   = ["iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:mfa/*"]
  }

  statement {
    sid    = "AllowManageOwnMFA"
    effect = "Allow"
    actions = [
      "iam:EnableMFADevice",
      "iam:DeactivateMFADevice",
      "iam:ListMFADevices",
      "iam:ResyncMFADevice",
      "iam:GetUser",
      "iam:ChangePassword",
    ]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/guardrail/$${aws:username}"]
  }

  statement {
    sid    = "DenyEverythingElseWithoutMFA"
    effect = "Deny"
    not_actions = [
      "iam:ListVirtualMFADevices",
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:DeactivateMFADevice",
      "iam:ListMFADevices",
      "iam:ResyncMFADevice",
      "iam:GetUser",
      "iam:ChangePassword",
      "sts:GetSessionToken",
    ]
    resources = ["*"]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "require_mfa" {
  name        = "guardrail-require-mfa"
  path        = "/guardrail/"
  description = "Deny everything except MFA self-service until the user signs in with MFA"
  policy      = data.aws_iam_policy_document.require_mfa.json
}

resource "aws_iam_group_policy_attachment" "require_mfa" {
  for_each = aws_iam_group.department

  group      = each.value.name
  policy_arn = aws_iam_policy.require_mfa.arn
}