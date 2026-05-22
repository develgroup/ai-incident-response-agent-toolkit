"""AWS VPC Flow Logs query via CloudWatch Logs Insights.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import time
from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def query(
    log_group: str,
    src_addr: str | None = None,
    dst_addr: str | None = None,
    dst_port: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        flows = load_sample("aws", "vpcflow")
        filtered = [
            f for f in flows
            if (not src_addr or f.get("srcAddr") == src_addr)
            and (not dst_addr or f.get("dstAddr") == dst_addr)
            and (not dst_port or f.get("dstPort") == dst_port)
        ]
        return {"flows": filtered, "count": len(filtered), "mode": "sample"}

    try:
        import boto3
    except ImportError:
        return {"error": "boto3 not installed"}

    filters = []
    if src_addr:
        filters.append(f"srcAddr = '{src_addr}'")
    if dst_addr:
        filters.append(f"dstAddr = '{dst_addr}'")
    if dst_port:
        filters.append(f"dstPort = {dst_port}")
    where = " and ".join(filters) if filters else "action = 'ACCEPT'"

    query_str = (
        "fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action, protocol "
        f"| filter {where} "
        "| sort @timestamp desc "
        "| limit 100"
    )

    client = boto3.client("logs")
    now = int(time.time())
    start_epoch = _epoch(start_time) or (now - 86400)
    end_epoch = _epoch(end_time) or now

    start = client.start_query(
        logGroupName=log_group,
        startTime=start_epoch,
        endTime=end_epoch,
        queryString=query_str,
    )
    query_id = start["queryId"]

    for _ in range(60):
        result = client.get_query_results(queryId=query_id)
        status = result.get("status")
        if status in {"Complete", "Failed", "Cancelled"}:
            rows = [
                {field["field"]: field["value"] for field in row}
                for row in result.get("results", [])
            ]
            return {"flows": rows, "count": len(rows), "status": status, "mode": "live"}
        time.sleep(1)
    return {"error": "query timeout", "queryId": query_id}


def _epoch(ts: str | None) -> int | None:
    if not ts:
        return None
    from datetime import datetime
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
