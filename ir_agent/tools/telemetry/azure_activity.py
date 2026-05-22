"""Azure Activity log (subscription control plane).

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def query(
    subscription_id: str | None = None,
    operation_name: str | None = None,
    caller: str | None = None,
    resource_id: str | None = None,
    timespan_hours: int = 24,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        events = load_sample("azure", "activity")
        out = [
            e for e in events
            if (not subscription_id or e.get("subscriptionId") == subscription_id)
            and (not operation_name or e.get("operationName") == operation_name)
            and (not caller or e.get("caller") == caller)
            and (not resource_id or resource_id in str(e.get("resourceId", "")))
        ]
        return {"events": out, "count": len(out), "mode": "sample"}

    if not subscription_id:
        return {"error": "subscription_id is required in live mode"}

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.monitor import MonitorManagementClient
    except ImportError:
        return {"error": "pip install azure-mgmt-monitor azure-identity"}

    cred = DefaultAzureCredential()
    client = MonitorManagementClient(cred, subscription_id)

    start = (datetime.now(timezone.utc) - timedelta(hours=timespan_hours)).isoformat()
    end = datetime.now(timezone.utc).isoformat()
    filter_parts = [f"eventTimestamp ge '{start}'", f"eventTimestamp le '{end}'"]
    if operation_name: filter_parts.append(f"operationName eq '{operation_name}'")
    if caller:         filter_parts.append(f"caller eq '{caller}'")
    if resource_id:    filter_parts.append(f"resourceUri eq '{resource_id}'")

    select = (
        "eventTimestamp,eventName,operationName,caller,callerIpAddress,"
        "resourceId,resourceGroupName,status,subStatus,correlationId,claims,properties"
    )

    try:
        items = list(
            client.activity_logs.list(filter=" and ".join(filter_parts), select=select)
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    rows = [_normalize(i) for i in items]
    return {"events": rows, "count": len(rows), "mode": "live"}


def _normalize(item: Any) -> dict[str, Any]:
    return {
        "eventTimestamp": str(item.event_timestamp),
        "operationName": item.operation_name.value if item.operation_name else None,
        "caller": item.caller,
        "callerIpAddress": item.caller_ip_address,
        "resourceId": item.resource_id,
        "resourceGroupName": item.resource_group_name,
        "status": item.status.value if item.status else None,
        "correlationId": item.correlation_id,
        "properties": dict(item.properties) if item.properties else None,
    }
