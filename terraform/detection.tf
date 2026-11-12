resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:This account intentionally is not part of an AWS Organization (joining one auto-upgrades the account's billing plan - a deliberate project decision); GuardDuty is enabled directly on this single account instead of via a delegated org admin.
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

locals {
  guardduty_optional_features = toset([
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
  ])
}

resource "aws_guardduty_detector_feature" "disabled" {
  for_each = local.guardduty_optional_features

  detector_id = aws_guardduty_detector.main.id
  name        = each.key
  status      = "DISABLED"

  # AWS added a sub-setting (RDS_DATA_RISK) under RDS_LOGIN_EVENTS that this
  # resource doesn't manage. It is off while the parent feature is off, so we
  # ignore it to keep the plan clean.
  lifecycle {
    ignore_changes = [additional_configuration]
  }
}

resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "guardrail-external-access"
  type          = "ACCOUNT"
}