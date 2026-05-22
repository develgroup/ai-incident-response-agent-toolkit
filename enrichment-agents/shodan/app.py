"""Shodan host enrichment microservice.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_BASE = "https://api.shodan.io"

SUSPICIOUS_TAGS = {"tor", "proxy", "vpn", "hosting", "compromised"}

app = FastAPI(title="IR enrichment · Shodan", version="0.1.0")


class HostRequest(BaseModel):
    ip: str


class HostResponse(BaseModel):
    ip: str
    suspicious: bool
    ports: list[int]
    hostnames: list[str]
    tags: list[str]
    country_code: str | None
    org: str | None
    os: str | None
    last_update: str | None


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "configured": bool(API_KEY)}


@app.post("/host", response_model=HostResponse)
async def host(req: HostRequest) -> HostResponse:
    if not API_KEY:
        raise HTTPException(503, "SHODAN_API_KEY not configured")

    params = {"key": API_KEY}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{SHODAN_BASE}/shodan/host/{req.ip}", params=params)

    if resp.status_code == 404:
        return HostResponse(
            ip=req.ip,
            suspicious=False,
            ports=[],
            hostnames=[],
            tags=[],
            country_code=None,
            org=None,
            os=None,
            last_update=None,
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, f"Shodan error: {resp.text}")

    data = resp.json()
    tags = list(data.get("tags", []) or [])
    suspicious = bool(SUSPICIOUS_TAGS.intersection(tags))

    return HostResponse(
        ip=req.ip,
        suspicious=suspicious,
        ports=list(data.get("ports", []) or []),
        hostnames=list(data.get("hostnames", []) or []),
        tags=tags,
        country_code=data.get("country_code"),
        org=data.get("org"),
        os=data.get("os"),
        last_update=data.get("last_update"),
    )
