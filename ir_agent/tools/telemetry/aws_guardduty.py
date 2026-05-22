"""AWS GuardDuty findings.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def findings(
    min_severity: float = 4.0,
    start_time: str | None = None,
    end_time: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        all_findings = load_sample("aws", "guardduty")
        filtered = [
            f for f in all_findings
            if float(f.get("Severity", 0)) >= float(min_severity)
        ]
        return {"findings": filtered, "count": len(filtered), "mode": "sample"}

    try:
        import boto3
    except ImportError:
        return {"error": "boto3 not installed"}

    client = boto3.client("guardduty")
    try:
        detectors = client.list_detectors().get("DetectorIds", [])
    except Exception as exc:  # noqa: BLE001
        return {"error": f"list_detectors: {exc}"}

    all_findings: list[dict[str, Any]] = []
    for detector_id in detectors:
        criteria = {"severity": {"Gte": min_severity}}
        try:
            ids = client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": criteria},
                MaxResults=50,
            ).get("FindingIds", [])
            if ids:
                detail = client.get_findings(DetectorId=detector_id, FindingIds=ids)
                all_findings.extend(detail.get("Findings", []))
        except Exception as exc:  # noqa: BLE001
            all_findings.append({"error": str(exc), "detector": detector_id})

    return {"findings": all_findings, "count": len(all_findings), "mode": "live"}
