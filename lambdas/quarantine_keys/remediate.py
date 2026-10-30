"""Guardrail - leaked IAM access key response.

Triggered by EventBridge when the AWS compromised-key quarantine policy
(AWSCompromisedKeyQuarantine*) is attached to an IAM user. AWS attaches this
policy automatically when it detects a user's access key has been exposed
publicly (for example, pushed to GitHub).

When that happens this function DEACTIVATES the user's access keys so a thief
can no longer use them, unless:
  * DRY_RUN is not "false"                       -> only reports what it WOULD do
  * the user is on the PROTECTED_USERS list      -> never touched (e.g. admin)
  * the user has tag guardrail-exempt=true       -> skipped on purpose
  * the user has no active keys                  -> nothing to do (idempotent)

Keys are DEACTIVATED, never deleted. Deactivating stops the attacker but keeps
the key for investigation, and a human can re-activate it with one command.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)

EXEMPT_TAG_KEY = "guardrail-exempt"
QUARANTINE_MARKER = "AWSCompromisedKeyQuarantine"  # matches V1/V2/V3


def iam_client():
    return boto3.client("iam")


def sns_client():
    return boto3.client("sns")


def is_dry_run():
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


def protected_users():
    raw = os.environ.get("PROTECTED_USERS", "")
    return {u.strip() for u in raw.split(",") if u.strip()}


def mask(key_id):
    """Show only the last 4 characters of an access key id."""
    return "****" + key_id[-4:] if key_id and len(key_id) >= 4 else "****"


def get_tags(user):
    try:
        resp = iam_client().list_user_tags(UserName=user)
        return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
    except iam_client().exceptions.NoSuchEntityException:
        return {}


def tag_user(user, extra):
    tags = [{"Key": k, "Value": v} for k, v in extra.items()]
    try:
        iam_client().tag_user(UserName=user, Tags=tags)
    except Exception:
        logger.warning("Could not tag user %s", user, exc_info=True)


def notify(subject, body):
    sns_client().publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=subject[:100],
        Message=body,
    )


def respond(user, policy_arn, actor):
    """Decide what to do for one quarantined user. Returns a status string."""
    if user in protected_users():
        notify(
            f"Guardrail: key response SKIPPED (protected) - {user}",
            json.dumps({"user": user, "status": "skipped_protected",
                        "note": "user is on the protected list; no keys touched"}, indent=2),
        )
        return "skipped_protected"

    tags = get_tags(user)
    if tags.get(EXEMPT_TAG_KEY, "").strip().lower() == "true":
        return "skipped_exempt"

    keys = iam_client().list_access_keys(UserName=user).get("AccessKeyMetadata", [])
    active = [k for k in keys if k["Status"] == "Active"]
    if not active:
        return "already_contained"

    masked = [mask(k["AccessKeyId"]) for k in active]

    if is_dry_run():
        status = "dry_run_would_disable"
    else:
        for k in active:
            iam_client().update_access_key(
                UserName=user, AccessKeyId=k["AccessKeyId"], Status="Inactive")
        tag_user(user, {
            "guardrail-quarantined": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "guardrail-keys-disabled": str(len(active)),
        })
        status = "keys_disabled"

    notify(
        f"Guardrail: IAM key {status} - {user}",
        json.dumps({
            "user": user,
            "status": status,
            "active_keys": masked,
            "key_count": len(active),
            "quarantine_policy": policy_arn,
            "attached_by": actor,
            "dry_run": is_dry_run(),
        }, indent=2),
    )
    return status


def handler(event, context):
    detail = event.get("detail") or {}
    params = detail.get("requestParameters") or {}
    user = params.get("userName")
    policy_arn = params.get("policyArn", "")
    actor = (detail.get("userIdentity") or {}).get("arn", "unknown")

    if QUARANTINE_MARKER not in policy_arn:
        logger.info("Policy %s is not a quarantine policy, ignoring", policy_arn)
        return {"status": "ignored_not_quarantine"}

    if not user:
        logger.warning("No userName in event, ignoring: %s", json.dumps(event)[:500])
        return {"status": "ignored_no_user"}

    status = respond(user, policy_arn, actor)
    logger.info(json.dumps({"user": user, "status": status, "policy": policy_arn}))
    return {"status": status, "user": user}