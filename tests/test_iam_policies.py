"""Guardrail IAM tests: prove who can and cannot do what.

Each case asks the AWS policy simulator a question and checks the answer.
"""

import boto3
import pytest

iam = boto3.client("iam")
sts = boto3.client("sts")

ACCOUNT = sts.get_caller_identity()["Account"]
LOG_BUCKET = f"guardrail-logs-{ACCOUNT}"

LOG_OBJECT = f"arn:aws:s3:::{LOG_BUCKET}/AWSLogs/test.json.gz"
DEV_OBJECT = "arn:aws:s3:::guardrail-dev-test/file.txt"
DATA_OBJECT = "arn:aws:s3:::guardrail-data-test/file.csv"
MFA_DEVICE = f"arn:aws:iam::{ACCOUNT}:mfa/alice.johnson"

# (user, action, resource, signed in with MFA?, expected decision, why)
CASES = [
    ("alice.johnson", "s3:GetObject", DEV_OBJECT, True, "allowed", "engineer reads dev bucket"),
    ("alice.johnson", "s3:GetObject", LOG_OBJECT, True, "implicitDeny", "engineer cannot read logs"),
    ("alice.johnson", "s3:GetObject", DEV_OBJECT, False, "explicitDeny", "no MFA blocks normal work"),
    ("alice.johnson", "iam:CreateVirtualMFADevice", MFA_DEVICE, False, "allowed", "MFA setup works without MFA"),
    ("alice.johnson", "iam:CreateUser", "*", True, "explicitDeny", "boundary blocks IAM changes"),
    ("alice.johnson", "cloudtrail:StopLogging", "*", True, "explicitDeny", "boundary protects CloudTrail"),
    ("olivia.brown", "s3:GetObject", LOG_OBJECT, True, "allowed", "security reads logs"),
    ("olivia.brown", "s3:DeleteObject", LOG_OBJECT, True, "explicitDeny", "nobody deletes logs"),
    ("umar.khan", "s3:GetObject", DATA_OBJECT, True, "allowed", "data team reads data bucket"),
    ("umar.khan", "s3:PutObject", DATA_OBJECT, True, "implicitDeny", "data team cannot write"),
    ("carlos.mendez", "s3:GetObject", LOG_OBJECT, True, "implicitDeny", "finance cannot read logs"),
    ("kevin.lee", "ec2:DescribeInstances", "*", True, "allowed", "support views instances"),
    ("kevin.lee", "s3:GetObject", DEV_OBJECT, True, "implicitDeny", "support cannot read dev bucket"),
]


def decide(user, action, resource, has_mfa):
    """Ask the policy simulator: would this user be allowed to do this?"""
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    context = [
        {
            "ContextKeyName": "aws:MultiFactorAuthPresent",
            "ContextKeyValues": [str(has_mfa).lower()],
            "ContextKeyType": "boolean",
        },
        {
            "ContextKeyName": "aws:username",
            "ContextKeyValues": [user],
            "ContextKeyType": "string",
        },
    ]
    result = iam.simulate_principal_policy(
        PolicySourceArn=user_arn,
        ActionNames=[action],
        ResourceArns=[resource],
        ContextEntries=context,
    )
    return result["EvaluationResults"][0]["EvalDecision"]


@pytest.mark.parametrize(
    "user, action, resource, has_mfa, expected, why",
    CASES,
    ids=[case[5] for case in CASES],
)
def test_decision(user, action, resource, has_mfa, expected, why):
    got = decide(user, action, resource, has_mfa)
    assert got == expected, f"{why}: expected {expected}, got {got}"


def lab_users():
    names = []
    for page in iam.get_paginator("list_users").paginate(PathPrefix="/guardrail/"):
        names += [user["UserName"] for user in page["Users"]]
    return names


LAB_USERS = lab_users()


def test_lab_users_exist():
    assert len(LAB_USERS) > 0


@pytest.mark.parametrize("user", LAB_USERS)
def test_user_has_permission_boundary(user):
    boundary = iam.get_user(UserName=user)["User"].get("PermissionsBoundary")
    assert boundary is not None, "user has no permission boundary"
    assert boundary["PermissionsBoundaryArn"].endswith("/guardrail/guardrail-lab-boundary")


@pytest.mark.parametrize("user", LAB_USERS)
def test_user_has_no_credentials(user):
    assert iam.list_access_keys(UserName=user)["AccessKeyMetadata"] == []
    with pytest.raises(iam.exceptions.NoSuchEntityException):
        iam.get_login_profile(UserName=user)