"""YARA scan client.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools._http import post_json


def scan(content_b64: str | None = None, path: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if content_b64 is not None:
        payload["content_b64"] = content_b64
    if path is not None:
        payload["path"] = path
    if not payload:
        return {"error": "provide content_b64 or path"}
    return post_json(
        env_var="YARA_URL",
        default_url="http://localhost:8085",
        path="/scan",
        payload=payload,
    )
