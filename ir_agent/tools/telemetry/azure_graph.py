"""Microsoft Graph Activity Logs query (queried via Sentinel KQL).

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample
from ir_agent.tools.telemetry.azure_sentinel import kql


def activity_logs(
    app_id: str | None = None,
    request_uri_contains: str | None = None,
    ip_address: str | None = None,
    timespan_hours: int = 24,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        rows = load_sample("azure", "graph_activity")
        if app_id:
            rows = [r for r in rows if r.get("appId") == app_id]
        if request_uri_contains:
            rows = [r for r in rows if request_uri_contains in (r.get("requestUri") or "")]
        if ip_address:
            rows = [r for r in rows if r.get("ipAddress") == ip_address]
        return {"events": rows, "count": len(rows), "mode": "sample"}

    parts = ["MicrosoftGraphActivityLogs", f"| where TimeGenerated > ago({timespan_hours}h)"]
    if app_id:               parts.append(f'| where AppId == "{app_id}"')
    if request_uri_contains: parts.append(f'| where RequestUri has "{request_uri_contains}"')
    if ip_address:           parts.append(f'| where IPAddress == "{ip_address}"')
    parts.append("| project TimeGenerated, UserPrincipalName, AppId, RequestUri, IPAddress, UserAgent, ResponseStatusCode")
    parts.append("| order by TimeGenerated desc | take 200")
    return kql("\n".join(parts), timespan_hours=timespan_hours)
