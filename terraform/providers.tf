provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "guardrail"
      ManagedBy = "terraform"
    }
  }
}