resource "aws_cloudtrail" "main" {
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