"""Shared HTTP client for enrichment microservices.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

log = logging.getLogger("ir_agent.tools.http")


def post_json(env_var: str, default_url: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base = os.environ.get(env_var, default_url).rstrip("/")
    url = f"{base}{path}"
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, json=payload)
        if resp.status_code >= 400:
            return {"error": f"upstream {resp.status_code}: {resp.text[:500]}"}
        return resp.json()
    except httpx.HTTPError as exc:
        log.warning("HTTP error to %s: %s", url, exc)
        return {"error": f"transport: {exc}"}
