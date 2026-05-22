"""AWS Config resource history — answers 'was this always permissive?'

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import time
from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def history(
    resource_type: str,
    resource_id: str,
    lookback_hours: int = 168,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        items = load_sample("aws", "config")
        filtered = [
            i for i in items
            if i.get("resourceType") == resource_type and i.get("resourceId") == resource_id
        ]
        return {"history": filtered, "count": len(filtered), "mode": "sample"}

    try:
        import boto3
    except ImportError:
        return {"error": "boto3 not installed"}

    client = boto3.client("config")
    later = int(time.time())
    earlier = later - lookback_hours * 3600

    try:
        resp = client.get_resource_config_history(
            resourceType=resource_type,
            resourceId=resource_id,
            laterTime=later,
            earlierTime=earlier,
            limit=20,
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    items = []
    for item in resp.get("configurationItems", []):
        items.append(
            {
                "configurationItemCaptureTime": str(item.get("configurationItemCaptureTime")),
                "configurationItemStatus": item.get("configurationItemStatus"),
                "resourceType": item.get("resourceType"),
                "resourceId": item.get("resourceId"),
                "resourceName": item.get("resourceName"),
                "configurationStateMd5Hash": item.get("configurationStateMd5Hash"),
                "configuration": item.get("configuration"),
            }
        )
    return {"history": items, "count": len(items), "mode": "live"}
