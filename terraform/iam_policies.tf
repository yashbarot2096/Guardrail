# --- Engineering: manage dev things only ---
data "aws_iam_policy_document" "engineering" {
  #checkov:skip=CKV_AWS_356:The "*" resource is on ec2:Describe* only, a read-only action type that AWS does not support scoping to a specific resource ARN.
  statement {
    sid       = "ReadOnlyDiscovery"
    effect    = "Allow"
    actions   = ["ec2:Describe*", "s3:ListAllMyBuckets"]
    resources = ["*"]
  }

  statement {
    sid       = "ManageDevInstancesOnly"
    effect    = "Allow"
    actions   = ["ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"]
    resources = ["arn:${local.partition}:ec2:*:${local.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Environment"
      values   = ["dev"]
    }
  }

  statement {
    sid       = "ListDevBuckets"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:${local.partition}:s3:::guardrail-dev-*"]
  }

  statement {
    sid       = "ReadWriteDevObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:${local.partition}:s3:::guardrail-dev-*/*"]
  }
}

resource "aws_iam_policy" "engineering" {
  name   = "guardrail-engineering-dev"
  path   = "/guardrail/"
  policy = data.aws_iam_policy_document.engineering.json
}

resource "aws_iam_group_policy_attachment" "engineering" {
  group      = aws_iam_group.department["engineering"].name
  policy_arn = aws_iam_policy.engineering.arn
}

# --- Data: read data buckets only ---
data "aws_iam_policy_document" "data_team" {
  statement {
    sid       = "ListAllBuckets"
    effect    = "Allow"
    actions   = ["s3:ListAllMyBuckets"]
    resources = ["*"]
  }

  statement {
    sid       = "ListDataBuckets"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:${local.partition}:s3:::guardrail-data-*"]
  }

  statement {
    sid       = "ReadDataObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:${local.partition}:s3:::guardrail-data-*/*"]
  }
}

resource "aws_iam_policy" "data_team" {
  name   = "guardrail-data-readonly"
  path   = "/guardrail/"
  policy = data.aws_iam_policy_document.data_team.json
}

resource "aws_iam_group_policy_attachment" "data_team" {
  group      = aws_iam_group.department["data"].name
  policy_arn = aws_iam_policy.data_team.arn
}

# --- Support: read-only troubleshooting ---
data "aws_iam_policy_document" "support" {
  statement {
    sid    = "ReadOnlyTroubleshooting"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:GetMetricData",
      "cloudwatch:ListMetrics",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "support" {
  #checkov:skip=CKV_AWS_356:The "*" resources are on ec2:Describe* and cloudwatch:Describe*/Get*/List*, read-only action types AWS does not support scoping to a specific resource ARN.
  name   = "guardrail-support-readonly"
  path   = "/guardrail/"
  policy = data.aws_iam_policy_document.support.json
}

resource "aws_iam_group_policy_attachment" "support" {
  group      = aws_iam_group.department["support"].name
  policy_arn = aws_iam_policy.support.arn
}

# --- Security: audit the account and read the CloudTrail logs ---
data "aws_iam_policy_document" "security_logs" {
  statement {
    sid       = "ListLogBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.logs.arn]
  }

  statement {
    sid       = "ReadLogObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/*"]
  }

  statement {
    sid       = "DecryptLogs"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.logs.arn]
  }
}

resource "aws_iam_policy" "security_logs" {
  name   = "guardrail-security-read-logs"
  path   = "/guardrail/"
  policy = data.aws_iam_policy_document.security_logs.json
}

resource "aws_iam_group_policy_attachment" "security_logs" {
  group      = aws_iam_group.department["security"].name
  policy_arn = aws_iam_policy.security_logs.arn
}

resource "aws_iam_group_policy_attachment" "security_audit" {
  group      = aws_iam_group.department["security"].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/SecurityAudit"
}

# --- Finance: view bills only ---
resource "aws_iam_group_policy_attachment" "finance_billing" {
  group      = aws_iam_group.department["finance"].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AWSBillingReadOnlyAccess"
}