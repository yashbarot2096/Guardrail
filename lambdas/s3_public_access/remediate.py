"""Guardrail - S3 public access auto-remediation.

Triggered by EventBridge when someone changes a bucket's policy, ACL or
Block Public Access settings. The function turns ON all four Block Public
Access settings for that bucket, unless:
  * DRY_RUN is not "false"          -> only reports what it WOULD do
  * the bucket has tag guardrail-exempt=true -> skipped on purpose
  * the bucket is already fully blocked      -> nothing to do (idempotent)

The fix is reversible: the old settings are saved in a bucket tag
(guardrail-previous-block) as four digits, in this order:
  BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets
Example "0000" = nothing was blocked before.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

EXEMPT_TAG_KEY = "guardrail-exempt"
PREVIOUS_TAG_KEY = "guardrail-previous-block"

# Order matters: it is also the order of the four digits in the previous-block tag.
BLOCK_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def s3_client():
    return boto3.client("s3")


def sns_client():
    return boto3.client("sns")


def is_dry_run():
    # Safe default: anything other than the exact word "false" means dry-run.
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


def get_block_config(bucket):
    """Return the bucket's Block Public Access settings (all False if none are set)."""
    try:
        resp = s3_client().get_public_access_block(Bucket=bucket)
        config = resp["PublicAccessBlockConfiguration"]
        return {key: bool(config.get(key, False)) for key in BLOCK_KEYS}
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {key: False for key in BLOCK_KEYS}
        raise


def get_tags(bucket):
    """Return the bucket's tags as a dict (empty if the bucket has no tags)."""
    try:
        resp = s3_client().get_bucket_tagging(Bucket=bucket)
        return {tag["Key"]: tag["Value"] for tag in resp["TagSet"]}
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchTagSet":
            return {}
        raise


def save_previous_config(bucket, tags, current):
    """Remember the old settings in a tag so a human can undo the fix."""
    if PREVIOUS_TAG_KEY in tags:
        return  # keep the ORIGINAL settings, do not overwrite them
    digits = "".join("1" if current[key] else "0" for key in BLOCK_KEYS)
    new_tags = dict(tags)
    new_tags[PREVIOUS_TAG_KEY] = digits
    tag_set = [{"Key": k, "Value": v} for k, v in new_tags.items()]
    try:
        s3_client().put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tag_set})
    except ClientError:
        # Blocking public access matters more than keeping the undo note.
        logger.warning("Could not save previous config tag on %s", bucket, exc_info=True)


def notify(subject, body):
    """Send an alert to the SNS topic."""
    sns_client().publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=subject[:100],
        Message=body,
    )


def remediate(bucket, event_name, actor):
    """Decide what to do for one bucket. Returns a short status string."""
    tags = get_tags(bucket)
    if tags.get(EXEMPT_TAG_KEY, "").strip().lower() == "true":
        return "skipped_exempt"

    current = get_block_config(bucket)
    if all(current.values()):
        return "already_safe"

    if is_dry_run():
        status = "dry_run_would_block"
    else:
        save_previous_config(bucket, tags, current)
        s3_client().put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={key: True for key in BLOCK_KEYS},
        )
        status = "blocked"

    notify(
        f"Guardrail: S3 {status} - {bucket}",
        json.dumps(
            {
                "bucket": bucket,
                "status": status,
                "trigger_event": event_name,
                "changed_by": actor,
                "dry_run": is_dry_run(),
                "settings_before": current,
            },
            indent=2,
        ),
    )
    return status


def handler(event, context):
    detail = event.get("detail") or {}
    bucket = (detail.get("requestParameters") or {}).get("bucketName")
    event_name = detail.get("eventName", "unknown")
    actor = (detail.get("userIdentity") or {}).get("arn", "unknown")

    if not bucket:
        logger.warning("No bucket name in event, ignoring: %s", json.dumps(event)[:500])
        return {"status": "ignored_no_bucket"}

    status = remediate(bucket, event_name, actor)
    logger.info(
        json.dumps(
            {"bucket": bucket, "event": event_name, "actor": actor, "status": status}
        )
    )
    return {"status": status, "bucket": bucket}