"""Windows Security / TaskScheduler / WinRM / PowerShell event log query.

Sample mode (default for the demo) reads pre-collected events from
`sample-telemetry/windows/security_events.json`. Live mode would shell out
to `Get-WinEvent` via the EDR remote-shell channel — operators MUST
confirm in-scope authorization before live execution; this module marks
the live path as TODO and refuses to invoke it autonomously.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def query(
    channel: str | None = None,
    event_id: int | None = None,
    computer: str | None = None,
    target_user: str | None = None,
    timespan_hours: int = 24,
    **_: Any,
) -> dict[str, Any]:
    """Filter the pre-collected Security log feed.

    Args:
        channel: 'Security' | 'Microsoft-Windows-TaskScheduler/Operational' |
            'Microsoft-Windows-PowerShell/Operational' (case-insensitive).
        event_id: Specific Windows event ID (e.g. 4624, 4625, 4698, 1102).
        computer: Hostname filter (e.g. 'fin-app-03.acme.local').
        target_user: TargetUserName filter (case-insensitive).
        timespan_hours: Reserved for live mode.
    """
    if in_sample_mode():
        events = load_sample("windows", "security_events")
        out = [
            e for e in events
            if (not channel or (e.get("Channel", "").lower() == channel.lower()))
            and (not event_id or int(e.get("EventID", 0)) == int(event_id))
            and (not computer or e.get("Computer", "").lower() == computer.lower())
            and (not target_user
                 or e.get("EventData", {}).get("TargetUserName", "").lower()
                    == target_user.lower())
        ]
        return {"events": out, "count": len(out), "mode": "sample"}

    return {
        "error": "live Windows Event Log queries require explicit EDR "
                 "remote-shell authorization — not invoked autonomously",
        "mode": "live-blocked",
    }
