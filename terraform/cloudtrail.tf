resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_252:We route alerts through EventBridge -> Lambda -> a single shared SNS topic instead of CloudTrail's built-in SNS notification, which fires on every log delivery rather than only on security-relevant events.
  #checkov:skip=CKV2_AWS_10:Not yet streamed to CloudWatch Logs - EventBridge already receives these events natively for our automated response use case. Log-based CloudWatch Insights/alarms are a worthwhile future addition, tracked in the README roadmap.
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.logs.id
  kms_key_id     = aws_kms_key.logs.arn

  # Record activity in every region, not just us-east-1
  is_multi_region_trail = true

  # Include global services such as IAM and STS
  include_global_service_events = true

  # Create signed "digest" files so tampering can be detected later
  enable_log_file_validation = true

  enable_logging = true

  # The bucket must allow CloudTrail to write before the trail exists
  depends_on = [aws_s3_bucket_policy.logs]
}