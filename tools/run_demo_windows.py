"""Deterministic demo run — Windows host (PsExec lateral movement).

Produces out/report_windows.html without needing ANTHROPIC_API_KEY. Drives
the same tools the LLM would, in the same order, against the synthetic
Windows breach.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
os.environ["IR_AGENT_SAMPLE_MODE"] = "1"

from ir_agent.tools.enrichment.abuseipdb import check as ab_check
from ir_agent.tools.enrichment.shodan import host as sh_host
from ir_agent.tools.enrichment.virustotal import lookup as vt_lookup
from ir_agent.tools.telemetry.windows_eventlog import query as evt_query
from ir_agent.tools.telemetry.windows_sysmon import query as sysmon_query
from ir_agent.tools.telemetry.windows_scheduled_tasks import list_tasks
from ir_agent.tools.telemetry.windows_processes import snapshot as proc_snapshot
from ir_agent.tools.action.windows_stage import (
    isolate_host,
    kill_process,
    disable_account,
    remove_scheduled_task,
    stop_disable_service,
)
from ir_agent.graph.builder import build_graph_from_events
from ir_agent.orchestrator import InvestigationResult, StagedAction
from ir_agent.report.renderer import render_report


def main() -> None:
    signal = json.loads(
        (REPO_ROOT / "alerts/windows-psexec-lateral.json").read_text(encoding="utf-8")
    )
    host = signal["computer"]
    actor = "admin-alice"
    attacker_ip = signal["source_ip"]
    trace: list[dict] = []

    # ── ENRICH the external entry point ──────────────────────────
    trace.append({"tool_id": "abuseipdb.check",
                  "params": {"ip": attacker_ip},
                  "result": ab_check(ip=attacker_ip)})
    trace.append({"tool_id": "shodan.host",
                  "params": {"ip": attacker_ip},
                  "result": sh_host(ip=attacker_ip)})
    trace.append({"tool_id": "virustotal.lookup",
                  "params": {"indicator": attacker_ip, "kind": "ip"},
                  "result": vt_lookup(indicator=attacker_ip, kind="ip")})

    # ── OBSERVE the authentication chain (RDP → SMB → SYSTEM logon)
    for eid in (4624, 4672, 4698, 1102):
        trace.append({"tool_id": "windows.eventlog.query",
                      "params": {"channel": "Security", "event_id": eid},
                      "result": evt_query(channel="Security", event_id=eid)})

    # ── EXPAND with Sysmon (process, network, LSASS access, registry, file)
    for eid in (1, 3, 10, 13, 11):
        trace.append({"tool_id": "windows.sysmon.query",
                      "params": {"event_id": eid, "computer": host},
                      "result": sysmon_query(event_id=eid, computer=host)})

    # ── Persistence sweep
    trace.append({"tool_id": "windows.scheduled_tasks.list",
                  "params": {"computer": host, "author_contains": actor},
                  "result": list_tasks(computer=host, author_contains=actor)})

    # ── Process tree snapshot
    trace.append({"tool_id": "windows.processes.snapshot",
                  "params": {"computer": host},
                  "result": proc_snapshot(computer=host)})

    # ── STAGE containment (NEVER executed) ────────────────────────
    staged_results = [
        isolate_host(
            computer=host,
            rationale=(
                "PsExec service install, LSASS access from C:\\Windows\\Temp\\update.exe "
                "(GrantedAccess 0x1010 — Mimikatz pattern), Security log cleared. "
                "Network-isolate preserves memory for credential recovery."
            ),
        ),
        disable_account(
            sam_account_name=actor,
            domain="ACME",
            rationale=(
                "Initial admin-alice RDP from external IP 198.51.100.7 (two-source enriched), "
                "then SMB-pivot to fin-app-03. Disable + force pw reset + per-user TGT invalidate."
            ),
        ),
        stop_disable_service(
            computer=host,
            service_name="PSEXESVC",
            rationale="Attacker-installed PsExec service host. Stop + disable to block re-spawn.",
        ),
        remove_scheduled_task(
            computer=host,
            task_name="\\Acme\\OneDriveSyncMaintenance",
            rationale=(
                "Persistence task created by admin-alice running encoded PowerShell as SYSTEM "
                "every hour — name impersonates legitimate Microsoft task family."
            ),
        ),
        kill_process(
            computer=host,
            process_guid="{a1b2c3d4-0004-0000-0000-000000000004}",
            pid=7728,
            rationale=(
                "Running 'update.exe' from C:\\Windows\\Temp performed LSASS access — "
                "kill the process tree after isolation completes."
            ),
        ),
    ]

    inv = build_graph_from_events(
        cloud="windows",
        signal=signal,
        tool_calls=trace,
        narrative="Sample-mode reconstruction of PsExec lateral movement.",
    )

    narrative = (
        "Confirmed compromise of Windows host fin-app-03.acme.local. The Active Directory "
        "account 'ACME\\admin-alice' was used by an external actor (source IP 198.51.100.7 — "
        "enriched via AbuseIPDB / Shodan / VirusTotal) to:\n"
        "\n"
        "  1. RDP onto jump-host-02 (Security event 4624, LogonType 10 — T1078) and "
        "obtain special privileges (4672).\n"
        "  2. Pivot to fin-app-03 over SMB with NTLM (Security event 4624, LogonType 3 — "
        "T1021.002).\n"
        "  3. Install the PSEXESVC.exe service (Sysmon EventID 1, parent services.exe; "
        "Security 4624 LogonType 5 — T1543.003).\n"
        "  4. Launch PowerShell with an encoded payload that beacons to 198.51.100.7 "
        "(Sysmon EventID 3, port 80 — T1059) and drops C:\\Windows\\Temp\\update.exe.\n"
        "  5. Use update.exe to access lsass.exe with GrantedAccess 0x1010 — Mimikatz-class "
        "credential dumping (Sysmon EventID 10 — T1003.001).\n"
        "  6. Add a Defender exclusion for C:\\Windows\\Temp via registry "
        "(Sysmon EventID 13 — T1562.001) and stage an archive at "
        "C:\\Users\\admin-alice\\Documents\\stage.7z (Sysmon EventID 11 — T1074.001).\n"
        "  7. Register scheduled task '\\Acme\\OneDriveSyncMaintenance' running encoded "
        "PowerShell as SYSTEM hourly (Security event 4698 — T1053.005).\n"
        "  8. Clear the Security audit log (Security event 1102 — T1070.001).\n"
        "\n"
        "Five containment actions are staged pending human approval. Recommended order: "
        "EDR-isolate the host (preserves memory), disable + rotate admin-alice with TGT "
        "invalidation, stop+disable PSEXESVC, remove the persistence task, then kill the "
        "running update.exe process tree."
    )

    result = InvestigationResult(
        cloud="windows",
        signal=signal,
        iterations=len(trace),
        final_message=narrative,
        tool_calls=trace,
        staged_actions=[
            StagedAction(
                tool_id=f"windows.stage.{s['runbook']}",
                parameters=s["parameters"],
                result=s,
            )
            for s in staged_results
        ],
        investigation=inv,
    )

    out = REPO_ROOT / "out"
    out.mkdir(exist_ok=True)
    render_report(result, out / "report_windows.html", out / "report_windows.json")

    print(f"OK report_windows.html -> {(out / 'report_windows.html').resolve()}")
    print(f"OK report_windows.json -> {(out / 'report_windows.json').resolve()}")
    print(f"   nodes: {len(inv.nodes)}  edges: {len(inv.edges)}")
    print(f"   MITRE techniques: {[t['id'] for t in inv.mitre_coverage()]}")
    print(f"   staged containment actions: {len(staged_results)}")


if __name__ == "__main__":
    main()
