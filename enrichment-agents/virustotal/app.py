"""VirusTotal enrichment microservice.

Wraps the VirusTotal v3 public API behind a uniform /lookup endpoint so the
ir-agent never holds a third-party API key in process and never sees a
provider-specific response shape.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import base64
import os
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"

app = FastAPI(title="IR enrichment · VirusTotal", version="0.1.0")


class LookupRequest(BaseModel):
    indicator: str
    kind: Literal["hash", "url", "domain", "ip"]


class LookupResponse(BaseModel):
    indicator: str
    kind: str
    malicious: bool
    detections: int
    total_engines: int
    families: list[str]
    raw_attributes: dict


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "configured": bool(VT_API_KEY)}


@app.post("/lookup", response_model=LookupResponse)
async def lookup(req: LookupRequest) -> LookupResponse:
    if not VT_API_KEY:
        raise HTTPException(503, "VIRUSTOTAL_API_KEY not configured")

    path = _path_for(req.kind, req.indicator)
    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{VT_BASE}/{path}", headers=headers)

    if resp.status_code == 404:
        return LookupResponse(
            indicator=req.indicator,
            kind=req.kind,
            malicious=False,
            detections=0,
            total_engines=0,
            families=[],
            raw_attributes={"not_found": True},
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, f"VirusTotal API error: {resp.text}")

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}
    detections = int(stats.get("malicious", 0))
    total = sum(int(v or 0) for v in stats.values())
    family_names = sorted({
        result.get("result")
        for result in (attrs.get("last_analysis_results") or {}).values()
        if result.get("category") == "malicious" and result.get("result")
    })

    return LookupResponse(
        indicator=req.indicator,
        kind=req.kind,
        malicious=detections >= 3,
        detections=detections,
        total_engines=total,
        families=list(family_names),
        raw_attributes={
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "tags": attrs.get("tags", []),
        },
    )


def _path_for(kind: str, indicator: str) -> str:
    if kind == "hash":
        return f"files/{indicator}"
    if kind == "url":
        encoded = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        return f"urls/{encoded}"
    if kind == "domain":
        return f"domains/{indicator}"
    if kind == "ip":
        return f"ip_addresses/{indicator}"
    raise HTTPException(400, f"Unknown kind: {kind}")
