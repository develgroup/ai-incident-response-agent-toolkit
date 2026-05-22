"""Deterministic demo run — Azure / Entra ID AiTM token replay.

Produces out/report_azure.html without needing ANTHROPIC_API_KEY. Drives
the same tools the LLM would, in the same order, against the synthetic
Azure breach.

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
from ir_agent.tools.telemetry.azure_sentinel import kql
from ir_agent.tools.telemetry.azure_entra import signin_logs, audit_logs
from ir_agent.tools.telemetry.azure_activity import query as activity_query
from ir_agent.tools.telemetry.azure_graph import activity_logs as graph_activity
from ir_agent.tools.action.azure_stage import (
    revoke_sessions,
    remove_credential,
    disable_spn,
    ca_emergency_block,
    revoke_sas,
)
from ir_agent.graph.builder import build_graph_from_events
from ir_agent.orchestrator import InvestigationResult, StagedAction
from ir_agent.report.renderer import render_report


def main() -> None:
    signal = json.loads(
        (REPO_ROOT / "alerts/azure-aitm-token-replay.json").read_text(encoding="utf-8")
    )
    upn = signal["actor_upn"]
    app_id = signal["target_app_id"]
    attacker_ip = signal["ip_address"]
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

    # ── OBSERVE — sign-ins across all four tables ─────────────────
    trace.append({"tool_id": "azure.entra.signin_logs",
                  "params": {"upn": upn},
                  "result": signin_logs(upn=upn)})
    trace.append({"tool_id": "azure.entra.signin_logs",
                  "params": {"app_id": app_id, "ip_address": "203.0.113.55"},
                  "result": signin_logs(app_id=app_id, ip_address="203.0.113.55")})

    # ── EXPAND — Entra AuditLogs reveal credential add + role assignment
    trace.append({"tool_id": "azure.entra.audit_logs",
                  "params": {"actor_upn": upn},
                  "result": audit_logs(actor_upn=upn)})

    # ── Azure Activity log — SAS issuance by the compromised SPN
    trace.append({"tool_id": "azure.activity.query",
                  "params": {"subscription_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                  "result": activity_query(subscription_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")})

    # ── Microsoft Graph activity — the SPN mass-reading /messages
    trace.append({"tool_id": "azure.graph.activity_logs",
                  "params": {"app_id": app_id},
                  "result": graph_activity(app_id=app_id)})

    # ── KQL — sentinel signin search ──────────────────────────────
    trace.append({"tool_id": "azure.sentinel.kql",
                  "params": {"query": "SigninLogs | where TimeGenerated > ago(24h)"},
                  "result": kql("SigninLogs | where TimeGenerated > ago(24h)")})

    # ── STAGE containment (NEVER executed) ────────────────────────
    staged_results = [
        revoke_sessions(
            user_object_id="alice-objectid",
            rationale=(
                "AiTM token-replay confirmed: SigninLogs shows MFA satisfied via "
                "PreviousSession from 198.51.100.7. Force re-authentication."
            ),
        ),
        ca_emergency_block(
            user_object_id="alice-objectid",
            rationale=(
                "Block all sessions for alice@acme.example pending forensic clearance — "
                "complements revoke-sessions by preventing new token issuance."
            ),
        ),
        remove_credential(
            app_object_id="77777777-8888-9999-aaaa-bbbbbbbbbbbb",
            credential_id="NEW_PWD_CRED",
            credential_type="password",
            rationale=(
                "Audit log shows a passwordCredential added to 'Acme Reporting Connector' "
                "(privileged Mail.ReadWrite.All SPN) by alice — assumed attacker-controlled."
            ),
        ),
        disable_spn(
            spn_object_id="spn-acme-reporting-connector",
            rationale=(
                "Service principal authenticated from new IP 203.0.113.55 and mass-read "
                "alice@acme.example mailbox via Graph. Disable until rotation completes."
            ),
        ),
        revoke_sas(
            storage_account_id="/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/acmecustomerspii",
            key_name="key1",
            rationale=(
                "Compromised SPN issued an account SAS against acmecustomerspii via "
                "listAccountSas/action. Rotate storage key to invalidate every outstanding SAS."
            ),
        ),
    ]

    inv = build_graph_from_events(
        cloud="azure",
        signal=signal,
        tool_calls=trace,
        narrative="Sample-mode reconstruction of Entra ID AiTM token replay.",
    )

    narrative = (
        "Confirmed compromise in Azure tenant 11111111-2222-3333-4444-555555555555. "
        "An attacker at 198.51.100.7 (enriched via AbuseIPDB / Shodan / VirusTotal) "
        "intercepted alice@acme.example's sign-in session via an Adversary-in-the-Middle "
        "kit and replayed the MFA-satisfied token:\n"
        "\n"
        "  1. SigninLogs shows alice's interactive sign-in from 198.51.100.7 with "
        "MfaDetail.PreviousSession (MFA requirement satisfied by claim in the token) — "
        "the AiTM tell (T1078.004 + T1539).\n"
        "  2. AuditLogs show alice (now the attacker) adding a passwordCredential to "
        "the privileged 'Acme Reporting Connector' service principal "
        "(Mail.ReadWrite.All) — T1098.001 persistence.\n"
        "  3. AuditLogs show the SPN being granted an additional app role assignment "
        "(T1098.003 privilege escalation).\n"
        "  4. AADServicePrincipalSignInLogs show the SPN authenticating from a "
        "different IP (203.0.113.55) shortly after.\n"
        "  5. MicrosoftGraphActivityLogs show the SPN issuing GET "
        "/v1.0/users/alice/messages mass-read (T1114.002 — Remote Email Collection).\n"
        "  6. AzureActivity shows the SPN calling listAccountSas on storage account "
        "acmecustomerspii to issue an account SAS (staging for exfiltration).\n"
        "\n"
        "Five containment actions are staged pending human approval. Recommended order: "
        "revoke alice's sign-in sessions and apply emergency Conditional Access block "
        "(both contain the human-account leg), then remove the rogue SPN credential and "
        "disable the SPN (eradicate the persistence), then rotate the storage account "
        "key to invalidate any SAS the attacker already minted."
    )

    result = InvestigationResult(
        cloud="azure",
        signal=signal,
        iterations=len(trace),
        final_message=narrative,
        tool_calls=trace,
        staged_actions=[
            StagedAction(
                tool_id=f"azure.stage.{s['runbook']}",
                parameters=s["parameters"],
                result=s,
            )
            for s in staged_results
        ],
        investigation=inv,
    )

    out = REPO_ROOT / "out"
    out.mkdir(exist_ok=True)
    render_report(result, out / "report_azure.html", out / "report_azure.json")

    print(f"OK report_azure.html -> {(out / 'report_azure.html').resolve()}")
    print(f"OK report_azure.json -> {(out / 'report_azure.json').resolve()}")
    print(f"   nodes: {len(inv.nodes)}  edges: {len(inv.edges)}")
    print(f"   MITRE techniques: {[t['id'] for t in inv.mitre_coverage()]}")
    print(f"   staged containment actions: {len(staged_results)}")


if __name__ == "__main__":
    main()
