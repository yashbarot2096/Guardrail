locals {
  roster      = yamldecode(file("${path.module}/users.yaml"))
  users       = { for u in local.roster.users : u.name => u }
  departments = toset([for u in local.roster.users : u.department])
}

resource "aws_iam_group" "department" {
  for_each = local.departments

  name = "guardrail-${each.key}"
  path = "/guardrail/"
}

resource "aws_iam_user" "lab" {
  for_each = local.users

  name                 = each.key
  path                 = "/guardrail/"
  permissions_boundary = aws_iam_policy.lab_boundary.arn

  tags = {
    Department = each.value.department
  }
}

resource "aws_iam_user_group_membership" "lab" {
  for_each = local.users

  user   = aws_iam_user.lab[each.key].name
  groups = [aws_iam_group.department[each.value.department].name]
}