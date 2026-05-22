"""Azure Sentinel / Log Analytics KQL query.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def kql(query: str, timespan_hours: int = 24, **_: Any) -> dict[str, Any]:
    if in_sample_mode():
        sample: list[Any] = []
        ql = query.lower()
        if "signinlogs" in ql:
            sample = load_sample("azure", "signinlogs")
        elif "auditlogs" in ql:
            sample = load_sample("azure", "auditlogs")
        elif "azureactivity" in ql:
            sample = load_sample("azure", "activity")
        elif "officeactivity" in ql:
            sample = load_sample("azure", "officeactivity")
        return {"rows": sample, "count": len(sample), "mode": "sample"}

    workspace_id = os.environ.get("AZURE_SENTINEL_WORKSPACE_ID")
    if not workspace_id:
        return {"error": "AZURE_SENTINEL_WORKSPACE_ID not configured"}

    try:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus
    except ImportError:
        return {"error": "pip install azure-monitor-query azure-identity"}

    credential = DefaultAzureCredential()
    client = LogsQueryClient(credential)

    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timedelta(hours=timespan_hours),
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    if response.status != LogsQueryStatus.SUCCESS:
        return {"error": f"sentinel status={response.status}"}

    rows: list[dict[str, Any]] = []
    for table in response.tables:
        for row in table.rows:
            rows.append({col.name: row[i] for i, col in enumerate(table.columns)})
    return {"rows": rows, "count": len(rows), "mode": "live"}
