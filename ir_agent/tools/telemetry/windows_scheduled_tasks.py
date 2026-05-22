"""Windows scheduled-task enumeration (sample mode).

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def list_tasks(
    computer: str | None = None,
    author_contains: str | None = None,
    action_contains: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Enumerate scheduled tasks on a host, optionally filtered.

    Sample mode reads `sample-telemetry/windows/scheduled_tasks.json`.
    """
    if in_sample_mode():
        tasks = load_sample("windows", "scheduled_tasks")
        out = [
            t for t in tasks
            if (not computer or t.get("Computer", "").lower() == computer.lower())
            and (not author_contains
                 or author_contains.lower() in (t.get("Author", "") or "").lower())
            and (not action_contains
                 or action_contains.lower() in str(t.get("Actions", "")).lower())
        ]
        return {"tasks": out, "count": len(out), "mode": "sample"}

    return {
        "error": "live scheduled-task enumeration requires EDR remote-shell authorization",
        "mode": "live-blocked",
    }
