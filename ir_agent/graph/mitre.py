"""MITRE ATT&CK mapper — turns a cloud-event name into a technique.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.config import load_mitre_map


def map_event(cloud: str, event_name: str) -> dict[str, str] | None:
    """Return {id, name, phase} for a cloud-event-name match, or None."""
    if not event_name:
        return None
    full_map: dict[str, dict[str, dict[str, str]]] = load_mitre_map()
    cloud_map = full_map.get(cloud, {})
    if event_name in cloud_map:
        return cloud_map[event_name]
    # Tolerate Azure operation names that come back as 'ParentName/childName' —
    # try a suffix match if a direct lookup failed.
    for k, v in cloud_map.items():
        if event_name.endswith(k) or k.endswith(event_name):
            return v
    return None


def map_tool_call(cloud: str, tool_id: str, params: dict[str, Any]) -> dict[str, str] | None:
    """Best-effort mapping for tool-call-shaped lookups (CloudTrail eventName, Azure operationName)."""
    if tool_id == "aws.cloudtrail.lookup" and params.get("attribute") == "EventName":
        return map_event("aws", str(params.get("value", "")))
    if tool_id == "azure.activity.query" and params.get("operation_name"):
        return map_event("azure", str(params["operation_name"]))
    return None
