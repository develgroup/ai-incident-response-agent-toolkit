"""Entra ID sign-in and audit logs via Microsoft Graph.

For sign-ins this queries all FOUR tables (Interactive / Non-Interactive /
ServicePrincipal / ManagedIdentity).

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def signin_logs(
    upn: str | None = None,
    app_id: str | None = None,
    ip_address: str | None = None,
    correlation_id: str | None = None,
    kinds: list[str] | None = None,
    timespan_hours: int = 24,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        rows = load_sample("azure", "signinlogs")
        filtered = [
            r for r in rows
            if (not upn or r.get("userPrincipalName") == upn)
            and (not app_id or r.get("appId") == app_id)
            and (not ip_address or r.get("ipAddress") == ip_address)
            and (not correlation_id or r.get("correlationId") == correlation_id)
        ]
        return {"signins": filtered, "count": len(filtered), "mode": "sample"}

    token = _graph_token()
    if not token:
        return {"error": "Azure credentials not configured"}

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=timespan_hours)).isoformat()
    base_filter = f"createdDateTime gt {cutoff}"
    if upn:            base_filter += f" and userPrincipalName eq '{upn}'"
    if app_id:         base_filter += f" and appId eq '{app_id}'"
    if ip_address:     base_filter += f" and ipAddress eq '{ip_address}'"
    if correlation_id: base_filter += f" and correlationId eq '{correlation_id}'"

    kinds = kinds or ["interactive", "non_interactive", "service_principal", "managed_identity"]
    headers = {"Authorization": f"Bearer {token}"}
    params = {"$filter": base_filter, "$top": 200}
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{GRAPH_BASE}/auditLogs/signIns", headers=headers, params=params)
    except httpx.HTTPError as exc:
        return {"error": f"transport: {exc}"}

    if resp.status_code >= 400:
        return {"error": f"graph {resp.status_code}: {resp.text[:500]}"}

    signins = resp.json().get("value", [])
    kind_filter = {
        "interactive":       "interactiveUser",
        "non_interactive":   "nonInteractiveUser",
        "service_principal": "servicePrincipal",
        "managed_identity":  "managedIdentity",
    }
    wanted = {kind_filter[k] for k in kinds if k in kind_filter}
    filtered = [
        s for s in signins
        if s.get("signInEventTypes") and any(t in wanted for t in s["signInEventTypes"])
    ]
    return {"signins": filtered, "count": len(filtered), "mode": "live"}


def audit_logs(
    operations: list[str] | None = None,
    actor_upn: str | None = None,
    target_app_id: str | None = None,
    timespan_hours: int = 24,
    **_: Any,
) -> dict[str, Any]:
    if in_sample_mode():
        rows = load_sample("azure", "auditlogs")
        if operations:
            rows = [r for r in rows if r.get("activityDisplayName") in operations]
        if actor_upn:
            rows = [r for r in rows if r.get("initiatedBy", {}).get("user", {}).get("userPrincipalName") == actor_upn]
        return {"events": rows, "count": len(rows), "mode": "sample"}

    token = _graph_token()
    if not token:
        return {"error": "Azure credentials not configured"}

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=timespan_hours)).isoformat()
    parts = [f"activityDateTime gt {cutoff}"]
    if actor_upn:
        parts.append(f"initiatedBy/user/userPrincipalName eq '{actor_upn}'")
    if operations:
        clauses = " or ".join(f"activityDisplayName eq '{op}'" for op in operations)
        parts.append(f"({clauses})")
    headers = {"Authorization": f"Bearer {token}"}
    params = {"$filter": " and ".join(parts), "$top": 200}
    with httpx.Client(timeout=20.0) as client:
        resp = client.get(f"{GRAPH_BASE}/auditLogs/directoryAudits", headers=headers, params=params)
    if resp.status_code >= 400:
        return {"error": f"graph {resp.status_code}: {resp.text[:500]}"}
    return {"events": resp.json().get("value", []), "mode": "live"}


def _graph_token() -> str | None:
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    if not all([tenant_id, client_id, client_secret]):
        return None
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
        if resp.status_code >= 400:
            return None
        return resp.json().get("access_token")
    except httpx.HTTPError:
        return None
