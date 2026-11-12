"""Tests for the S3 auto-remediation Lambda.

These tests NEVER touch your real AWS account. moto (mock_aws) pretends to be
AWS inside your computer's memory, so we can create "public" buckets freely.
"""

import importlib.util
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

# Load the Lambda's remediate.py directly, under a name unique to THIS test
# file. Both Lambdas happen to be called remediate.py. A plain
# "import remediate" here, plus the same line in test_quarantine_keys.py,
# would collide: Python caches modules by name, so whichever test file's
# "import remediate" runs second would get handed back the FIRST file's
# already-loaded module instead of reading its own remediate.py. When both
# test files run together in one pytest process (as CI does), that silently
# swaps in the wrong Lambda's code. Giving each one a distinct name in
# sys.modules avoids the collision entirely.
LAMBDA_DIR = Path(__file__).resolve().parents[1] / "lambdas" / "s3_public_access"
_spec = importlib.util.spec_from_file_location("s3_remediate", LAMBDA_DIR / "remediate.py")
remediate = importlib.util.module_from_spec(_spec)
sys.modules["s3_remediate"] = remediate
_spec.loader.exec_module(remediate)

BUCKET = "guardrail-test-bucket"
NO_BLOCK = dict.fromkeys(remediate.BLOCK_KEYS, False)
FULL_BLOCK = dict.fromkeys(remediate.BLOCK_KEYS, True)


@pytest.fixture(autouse=True)
def fake_aws(monkeypatch):
    """Fake credentials + fake AWS for every test in this file."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("DRY_RUN", raising=False)
    with mock_aws():
        yield


@pytest.fixture
def s3():
    client = boto3.client("s3")
    client.create_bucket(Bucket=BUCKET)
    return client


@pytest.fixture
def alerts(monkeypatch):
    """Capture alerts instead of sending them."""
    sent = []
    monkeypatch.setattr(remediate, "notify", lambda subject, body: sent.append((subject, body)))
    return sent


def make_event(bucket=BUCKET, event_name="PutBucketPolicy"):
    return {
        "detail": {
            "eventName": event_name,
            "requestParameters": {"bucketName": bucket},
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/alice.johnson"},
        }
    }


def set_block(s3, config):
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=config)


def tags_of(s3):
    resp = s3.get_bucket_tagging(Bucket=BUCKET)
    return {t["Key"]: t["Value"] for t in resp["TagSet"]}


def test_dry_run_is_the_default_and_changes_nothing(s3, alerts):
    set_block(s3, NO_BLOCK)
    result = remediate.handler(make_event(), None)
    assert result["status"] == "dry_run_would_block"
    assert remediate.get_block_config(BUCKET) == NO_BLOCK
    assert len(alerts) == 1


def test_dry_run_true_changes_nothing(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    set_block(s3, NO_BLOCK)
    assert remediate.handler(make_event(), None)["status"] == "dry_run_would_block"
    assert remediate.get_block_config(BUCKET) == NO_BLOCK


def test_live_mode_blocks_public_access(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    set_block(s3, NO_BLOCK)
    result = remediate.handler(make_event(), None)
    assert result["status"] == "blocked"
    assert remediate.get_block_config(BUCKET) == FULL_BLOCK
    assert len(alerts) == 1
    assert "alice.johnson" in alerts[0][1]


def test_bucket_with_no_block_config_at_all_gets_blocked(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    # fresh bucket: no Block Public Access settings exist yet
    assert remediate.handler(make_event(), None)["status"] == "blocked"
    assert remediate.get_block_config(BUCKET) == FULL_BLOCK
    assert tags_of(s3)[remediate.PREVIOUS_TAG_KEY] == "0000"


def test_partially_open_bucket_is_fixed_and_old_settings_saved(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    partial = dict(NO_BLOCK, BlockPublicAcls=True)
    set_block(s3, partial)
    assert remediate.handler(make_event(), None)["status"] == "blocked"
    assert remediate.get_block_config(BUCKET) == FULL_BLOCK
    assert tags_of(s3)[remediate.PREVIOUS_TAG_KEY] == "1000"


def test_exempt_bucket_is_left_alone(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    set_block(s3, NO_BLOCK)
    s3.put_bucket_tagging(
        Bucket=BUCKET,
        Tagging={"TagSet": [{"Key": remediate.EXEMPT_TAG_KEY, "Value": "true"}]},
    )
    assert remediate.handler(make_event(), None)["status"] == "skipped_exempt"
    assert remediate.get_block_config(BUCKET) == NO_BLOCK
    assert alerts == []


def test_already_safe_bucket_is_a_quiet_no_op(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    set_block(s3, FULL_BLOCK)
    assert remediate.handler(make_event(), None)["status"] == "already_safe"
    assert alerts == []


def test_running_twice_is_safe(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    set_block(s3, NO_BLOCK)
    assert remediate.handler(make_event(), None)["status"] == "blocked"
    assert remediate.handler(make_event(), None)["status"] == "already_safe"
    assert len(alerts) == 1


def test_existing_tags_are_kept(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    set_block(s3, NO_BLOCK)
    s3.put_bucket_tagging(
        Bucket=BUCKET, Tagging={"TagSet": [{"Key": "Project", "Value": "guardrail"}]}
    )
    remediate.handler(make_event(), None)
    tags = tags_of(s3)
    assert tags["Project"] == "guardrail"
    assert tags[remediate.PREVIOUS_TAG_KEY] == "0000"


def test_original_settings_tag_is_not_overwritten(s3, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    set_block(s3, NO_BLOCK)
    remediate.handler(make_event(), None)  # saves "0000"
    set_block(s3, dict(NO_BLOCK, BlockPublicPolicy=True))  # someone re-opens it partly
    remediate.handler(make_event(), None)  # fixes again
    assert tags_of(s3)[remediate.PREVIOUS_TAG_KEY] == "0000"


def test_event_without_bucket_is_ignored(alerts):
    assert remediate.handler({"detail": {"eventName": "PutBucketPolicy"}}, None) == {
        "status": "ignored_no_bucket"
    }
    assert remediate.handler({}, None) == {"status": "ignored_no_bucket"}


def test_notify_publishes_to_the_topic(monkeypatch):
    topic_arn = boto3.client("sns").create_topic(Name="guardrail-alerts")["TopicArn"]
    monkeypatch.setenv("TOPIC_ARN", topic_arn)
    remediate.notify("subject", "body")  # raises if publishing fails