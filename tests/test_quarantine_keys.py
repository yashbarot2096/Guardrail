"""Tests for the leaked-key response Lambda. Uses moto (fake AWS) - never
touches a real account."""

import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

LAMBDA_DIR = Path(__file__).resolve().parents[1] / "lambdas" / "quarantine_keys"
sys.path.insert(0, str(LAMBDA_DIR))

import remediate  # noqa: E402

USER = "leaky.user"
QUAR_ARN = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"


@pytest.fixture(autouse=True)
def fake_aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("DRY_RUN", raising=False)
    monkeypatch.setenv("PROTECTED_USERS", "Yash_Admin,break.glass")
    with mock_aws():
        yield


@pytest.fixture
def iam():
    c = boto3.client("iam")
    c.create_user(UserName=USER)
    c.create_access_key(UserName=USER)
    return c


@pytest.fixture
def alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(remediate, "notify", lambda s, b: sent.append((s, b)))
    return sent


def event(user=USER, policy=QUAR_ARN):
    return {"detail": {
        "eventName": "AttachUserPolicy",
        "requestParameters": {"userName": user, "policyArn": policy},
        "userIdentity": {"arn": "arn:aws:iam::123456789012:root"},
    }}


def key_statuses(iam, user=USER):
    return [k["Status"] for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]]


def tags_of(iam, user=USER):
    return {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user).get("Tags", [])}


def test_dry_run_is_default_and_disables_nothing(iam, alerts):
    assert remediate.handler(event(), None)["status"] == "dry_run_would_disable"
    assert key_statuses(iam) == ["Active"]
    assert len(alerts) == 1


def test_live_disables_the_key(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    assert remediate.handler(event(), None)["status"] == "keys_disabled"
    assert key_statuses(iam) == ["Inactive"]
    assert len(alerts) == 1


def test_live_disables_multiple_keys(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    iam.create_access_key(UserName=USER)  # second key
    assert remediate.handler(event(), None)["status"] == "keys_disabled"
    assert key_statuses(iam) == ["Inactive", "Inactive"]


def test_protected_user_is_never_touched(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    iam.create_user(UserName="Yash_Admin")
    iam.create_access_key(UserName="Yash_Admin")
    assert remediate.handler(event(user="Yash_Admin"), None)["status"] == "skipped_protected"
    assert key_statuses(iam, "Yash_Admin") == ["Active"]
    assert "protected" in alerts[0][1]


def test_exempt_user_is_skipped(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    iam.tag_user(UserName=USER, Tags=[{"Key": "guardrail-exempt", "Value": "true"}])
    assert remediate.handler(event(), None)["status"] == "skipped_exempt"
    assert key_statuses(iam) == ["Active"]
    assert alerts == []


def test_already_contained_when_no_active_keys(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    kid = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"][0]["AccessKeyId"]
    iam.update_access_key(UserName=USER, AccessKeyId=kid, Status="Inactive")
    assert remediate.handler(event(), None)["status"] == "already_contained"
    assert alerts == []


def test_running_twice_is_safe(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    assert remediate.handler(event(), None)["status"] == "keys_disabled"
    assert remediate.handler(event(), None)["status"] == "already_contained"
    assert len(alerts) == 1


def test_quarantine_tags_are_written(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    remediate.handler(event(), None)
    t = tags_of(iam)
    assert "guardrail-quarantined" in t
    assert t["guardrail-keys-disabled"] == "1"


def test_non_quarantine_policy_is_ignored(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    res = remediate.handler(event(policy="arn:aws:iam::aws:policy/ReadOnlyAccess"), None)
    assert res["status"] == "ignored_not_quarantine"
    assert key_statuses(iam) == ["Active"]
    assert alerts == []


def test_event_without_user_is_ignored(alerts):
    res = remediate.handler({"detail": {"requestParameters": {"policyArn": QUAR_ARN}}}, None)
    assert res["status"] == "ignored_no_user"


def test_alert_masks_the_access_key_id(iam, alerts, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    real_kid = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"][0]["AccessKeyId"]
    remediate.handler(event(), None)
    body = alerts[0][1]
    assert real_kid not in body          # full key id must not appear
    assert "****" + real_kid[-4:] in body  # masked form does


def test_notify_publishes_to_topic(monkeypatch):
    topic = boto3.client("sns").create_topic(Name="guardrail-alerts")["TopicArn"]
    monkeypatch.setenv("TOPIC_ARN", topic)
    remediate.notify("subj", "body")