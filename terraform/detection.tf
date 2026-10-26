resource "aws_guardduty_detector" "main" {
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
}

resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "guardrail-external-access"
  type          = "ACCOUNT"
}