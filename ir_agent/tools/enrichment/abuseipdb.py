"""AbuseIPDB client.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools._http import post_json


def check(ip: str, max_age_in_days: int = 90) -> dict[str, Any]:
    return post_json(
        env_var="ABUSEIPDB_URL",
        default_url="http://localhost:8082",
        path="/check",
        payload={"ip": ip, "max_age_in_days": max_age_in_days},
    )
