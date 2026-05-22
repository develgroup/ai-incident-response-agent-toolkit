"""Windows running-process snapshot (sample mode).

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def snapshot(
    computer: str | None = None,
    name_contains: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Current process tree on the host.

    Sample mode reads `sample-telemetry/windows/processes.json`.
    """
    if in_sample_mode():
        procs = load_sample("windows", "processes")
        out = [
            p for p in procs
            if (not computer or p.get("Computer", "").lower() == computer.lower())
            and (not name_contains
                 or name_contains.lower() in p.get("Name", "").lower())
        ]
        return {"processes": out, "count": len(out), "mode": "sample"}

    return {
        "error": "live process snapshot requires EDR remote-shell authorization",
        "mode": "live-blocked",
    }
