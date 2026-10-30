variable "region" {
  description = "AWS region everything is deployed to"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives Guardrail alerts (set in terraform.tfvars, which git ignores)"
  type        = string
}

variable "s3_remediation_dry_run" {
  description = "true = only report public S3 buckets; false = actually fix them"
  type        = bool
  default     = true
}

variable "keys_remediation_dry_run" {
  description = "true = only report compromised IAM keys; false = actually deactivate them"
  type        = bool
  default     = true
}

variable "protected_iam_users" {
  description = "IAM user that the key-quarantine Lambda must never touch (your break-glass admin)"
  type        = string
  default     = "Yash_Admin"
}