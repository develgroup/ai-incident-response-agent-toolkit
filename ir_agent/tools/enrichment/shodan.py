"""Shodan client.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools._http import post_json


def host(ip: str) -> dict[str, Any]:
    return post_json(
        env_var="SHODAN_URL",
        default_url="http://localhost:8083",
        path="/host",
        payload={"ip": ip},
    )
