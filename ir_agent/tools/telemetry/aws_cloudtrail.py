"""AWS CloudTrail lookup.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample

log = logging.getLogger("ir_agent.tools.aws.cloudtrail")

VALID_ATTRS = {
    "EventName", "Username", "EventSource", "ResourceName",
    "ResourceType", "EventId", "AccessKeyId", "ReadOnly",
}


def lookup(
    attribute: str,
    value: str,
    start_time: str | None = None,
    end_time: str | None = None,
    region: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if attribute not in VALID_ATTRS:
        return {"error": f"invalid attribute {attribute!r}", "valid": sorted(VALID_ATTRS)}

    if in_sample_mode():
        events = load_sample("aws", "cloudtrail")
        filtered = [e for e in events if _matches(e, attribute, value)]
        return {"events": filtered[:500], "count": len(filtered), "mode": "sample"}

    try:
        import boto3
    except ImportError:
        return {"error": "boto3 not installed; pip install boto3"}

    kwargs: dict[str, Any] = {}
    if region:
        kwargs["region_name"] = region
    client = boto3.client("cloudtrail", **kwargs)

    params: dict[str, Any] = {
        "LookupAttributes": [{"AttributeKey": attribute, "AttributeValue": value}],
        "MaxResults": 50,
    }
    if start_time:
        params["StartTime"] = _parse_iso(start_time)
    if end_time:
        params["EndTime"] = _parse_iso(end_time)

    events: list[dict[str, Any]] = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(**params):
        for ev in page.get("Events", []):
            events.append(_normalize_event(ev))
        if len(events) >= 500:
            break
    return {"events": events[:500], "count": len(events), "mode": "live"}


def _matches(event: dict[str, Any], attribute: str, value: str) -> bool:
    if attribute == "EventName":
        return event.get("eventName") == value
    if attribute == "AccessKeyId":
        return event.get("userIdentity", {}).get("accessKeyId") == value
    if attribute == "Username":
        return event.get("userIdentity", {}).get("userName") == value
    if attribute == "EventSource":
        return event.get("eventSource") == value
    if attribute == "ResourceName":
        for r in event.get("resources", []) or []:
            if r.get("ResourceName") == value:
                return True
        return False
    if attribute == "EventId":
        return event.get("eventID") == value
    if attribute == "ReadOnly":
        return str(event.get("readOnly", "")).lower() == value.lower()
    return False


def _normalize_event(ev: dict[str, Any]) -> dict[str, Any]:
    import json as _json

    parsed = ev.get("CloudTrailEvent")
    body: dict[str, Any] = {}
    if isinstance(parsed, str):
        try:
            body = _json.loads(parsed)
        except _json.JSONDecodeError:
            body = {}
    return {
        "eventID": ev.get("EventId"),
        "eventName": ev.get("EventName"),
        "eventTime": ev.get("EventTime").isoformat() if ev.get("EventTime") else None,
        "sourceIPAddress": body.get("sourceIPAddress"),
        "userAgent": body.get("userAgent"),
        "userIdentity": body.get("userIdentity"),
        "awsRegion": body.get("awsRegion"),
        "requestParameters": body.get("requestParameters"),
        "responseElements": body.get("responseElements"),
        "errorCode": body.get("errorCode"),
        "errorMessage": body.get("errorMessage"),
    }


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
