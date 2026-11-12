resource "aws_sns_topic" "alerts" {
  name              = "guardrail-alerts"
  kms_master_key_id = "alias/aws/sns" # AWS-managed key: encrypts alerts at rest, no extra cost
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}