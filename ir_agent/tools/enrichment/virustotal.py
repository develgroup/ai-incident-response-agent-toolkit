"""VirusTotal client — calls the local enrichment microservice.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools._http import post_json


def lookup(indicator: str, kind: str) -> dict[str, Any]:
    return post_json(
        env_var="VIRUSTOTAL_URL",
        default_url="http://localhost:8081",
        path="/lookup",
        payload={"indicator": indicator, "kind": kind},
    )
