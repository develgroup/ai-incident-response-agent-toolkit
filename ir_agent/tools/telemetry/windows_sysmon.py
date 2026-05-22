"""Windows Sysmon event query (sample mode).

Sysmon event IDs surfaced:
  1   ProcessCreate (with full CommandLine)
  3   NetworkConnect
  7   ImageLoaded
  10  ProcessAccess (LSASS-access detection)
  11  FileCreate
  13  RegistryValueSet
  22  DNSQuery

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def query(
    event_id: int | None = None,
    computer: str | None = None,
    image_contains: str | None = None,
    target_image_contains: str | None = None,
    parent_image_contains: str | None = None,
    command_line_contains: str | None = None,
    timespan_hours: int = 24,
    **_: Any,
) -> dict[str, Any]:
    """Filter Sysmon events from the sample dataset.

    All string filters are case-insensitive substring matches.
    """
    if in_sample_mode():
        events = load_sample("windows", "sysmon")

        def _matches(e: dict[str, Any]) -> bool:
            if event_id and int(e.get("EventID", 0)) != int(event_id):
                return False
            if computer and e.get("Computer", "").lower() != computer.lower():
                return False
            d = e.get("EventData", {})
            if image_contains and image_contains.lower() not in d.get("Image", "").lower():
                return False
            if (target_image_contains
                    and target_image_contains.lower() not in d.get("TargetImage", "").lower()):
                return False
            if (parent_image_contains
                    and parent_image_contains.lower() not in d.get("ParentImage", "").lower()):
                return False
            if (command_line_contains
                    and command_line_contains.lower() not in d.get("CommandLine", "").lower()):
                return False
            return True

        out = [e for e in events if _matches(e)]
        return {"events": out, "count": len(out), "mode": "sample"}

    return {
        "error": "live Sysmon queries require EDR remote-shell authorization",
        "mode": "live-blocked",
    }
