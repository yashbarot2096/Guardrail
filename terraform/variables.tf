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
  description = "true = only report what would be fixed; false = actually fix public buckets"
  type        = bool
  default     = true
}