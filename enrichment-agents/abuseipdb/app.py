"""AbuseIPDB enrichment microservice.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

app = FastAPI(title="IR enrichment · AbuseIPDB", version="0.1.0")


class CheckRequest(BaseModel):
    ip: str
    max_age_in_days: int = 90


class CheckResponse(BaseModel):
    ip: str
    malicious: bool
    abuse_confidence_score: int
    total_reports: int
    country_code: str | None
    isp: str | None
    usage_type: str | None
    is_tor: bool
    last_reported_at: str | None


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "configured": bool(API_KEY)}


@app.post("/check", response_model=CheckResponse)
async def check(req: CheckRequest) -> CheckResponse:
    if not API_KEY:
        raise HTTPException(503, "ABUSEIPDB_API_KEY not configured")

    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": req.ip, "maxAgeInDays": req.max_age_in_days, "verbose": ""}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{ABUSEIPDB_BASE}/check", headers=headers, params=params)

    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, f"AbuseIPDB error: {resp.text}")

    data = resp.json().get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))

    return CheckResponse(
        ip=req.ip,
        malicious=score >= 50,
        abuse_confidence_score=score,
        total_reports=int(data.get("totalReports", 0)),
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        usage_type=data.get("usageType"),
        is_tor=bool(data.get("isTor", False)),
        last_reported_at=data.get("lastReportedAt"),
    )
