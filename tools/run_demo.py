"""Deterministic demo run — produces out/report.html without needing
   ANTHROPIC_API_KEY. Drives the same tools the LLM would, in the same
   order, against the synthetic AWS breach.

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

from ir_agent.tools.enrichment.virustotal import lookup as vt_lookup
from ir_agent.tools.enrichment.abuseipdb import check as ab_check
from ir_agent.tools.enrichment.shodan import host as sh_host
from ir_agent.tools.telemetry.aws_cloudtrail import lookup as ct_lookup
from ir_agent.tools.telemetry.aws_vpcflow import query as vpc_query
from ir_agent.tools.telemetry.aws_iam import get_principal
from ir_agent.tools.telemetry.aws_config import history as cfg_history
from ir_agent.tools.action.aws_stage import (
    disable_access_key, waf_block, isolate_instance,
    revoke_snapshot_share, rescope_role,
)
from ir_agent.graph.builder import build_graph_from_events
from ir_agent.orchestrator import InvestigationResult, StagedAction
from ir_agent.report.renderer import render_report


def main() -> None:
    signal = json.loads(
        (REPO_ROOT / "alerts/aws-guardduty-cred-exfil.json").read_text(encoding="utf-8")
    )
    ip = signal["source_ip"]
    akid = "AKIAEXAMPLELEAKED123"
    trace: list[dict] = []

    # ── ENRICH ────────────────────────────────────────────────────
    trace.append({"tool_id": "abuseipdb.check",
                  "params": {"ip": ip}, "result": ab_check(ip=ip)})
    trace.append({"tool_id": "shodan.host",
                  "params": {"ip": ip}, "result": sh_host(ip=ip)})
    trace.append({"tool_id": "virustotal.lookup",
                  "params": {"indicator": ip, "kind": "ip"},
                  "result": vt_lookup(indicator=ip, kind="ip")})

    # ── OBSERVE + EXPAND (CloudTrail) ─────────────────────────────
    trace.append({"tool_id": "aws.cloudtrail.lookup",
                  "params": {"attribute": "AccessKeyId", "value": akid},
                  "result": ct_lookup(attribute="AccessKeyId", value=akid)})
    for evt in ("PutUserPolicy", "CreateDBSnapshot", "ModifySnapshotAttribute"):
        trace.append({"tool_id": "aws.cloudtrail.lookup",
                      "params": {"attribute": "EventName", "value": evt},
                      "result": ct_lookup(attribute="EventName", value=evt)})

    # ── IAM principal + config history + VPC flow ─────────────────
    trace.append({"tool_id": "aws.iam.get_principal",
                  "params": {"access_key_id": akid},
                  "result": get_principal(access_key_id=akid)})
    trace.append({"tool_id": "aws.config.history",
                  "params": {"resource_type": "AWS::IAM::Role",
                             "resource_id": "AROAEXAMPLEXXXXX"},
                  "result": cfg_history(resource_type="AWS::IAM::Role",
                                        resource_id="AROAEXAMPLEXXXXX")})
    trace.append({"tool_id": "aws.vpcflow.query",
                  "params": {"log_group": "/aws/vpc/flowlogs", "dst_addr": ip},
                  "result": vpc_query(log_group="/aws/vpc/flowlogs", dst_addr=ip)})

    # ── STAGE containment (NEVER executed) ────────────────────────
    staged_results = [
        disable_access_key(
            access_key_id=akid,
            username="web-prod-ec2",
            rationale="Two-source malicious + key seen exfiltrating",
        ),
        waf_block(
            ip_set_arn="arn:aws:wafv2:us-east-1:111122223333:regional/ipset/ir-blocklist/abc",
            cidr=f"{ip}/32",
            rationale="AbuseIPDB + Shodan two-source confirmation",
        ),
        rescope_role(
            role_name="web-prod-ec2",
            policy_arn_to_detach="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            rationale="Wildcard policy enabled S3 PII access (Config history confirms widened 2026-05-18)",
        ),
        revoke_snapshot_share(
            snapshot_id="snap-0abc1234ef56789",
            external_account_id="999988887777",
            rationale="External-account share confirmed in CloudTrail ct-evt-0005 (ModifySnapshotAttribute)",
        ),
        isolate_instance(
            instance_id="i-0abc1234def567890",
            quarantine_sg_id="sg-quarantine-deny-all",
            rationale="Host issued the snapshot share; quarantine for memory + disk forensics",
        ),
    ]

    inv = build_graph_from_events(
        cloud="aws",
        signal=signal,
        tool_calls=trace,
        narrative="Sample-mode reconstruction.",
    )

    narrative = (
        "Confirmed compromise of AWS account 444455556666 (prod). "
        "Leaked IAM role credentials for the EC2 instance role 'web-prod-ec2' "
        "were used from 198.51.100.7 (a Tor-exit / hosting IP independently "
        "enriched via VirusTotal, AbuseIPDB, and Shodan) to:\n"
        "\n"
        "  1. Read 2 batches of customer PII from S3 bucket 'acme-customers-pii' "
        "(MITRE T1530 — Data from Cloud Storage).\n"
        "  2. Inline an admin wildcard policy on user 'svc-pipeline' via "
        "PutUserPolicy (T1098.003). AWS Config history confirms the role's "
        "policy set was widened on 2026-05-18, before the breach window.\n"
        "  3. Snapshot the production database 'prod-orders' (T1530).\n"
        "  4. Share the snapshot to external AWS account 999988887777 via "
        "ModifySnapshotAttribute (T1537 — exfiltration).\n"
        "\n"
        "Five containment actions are staged pending human approval — see the "
        "Containment Runbook section below. Recommended order: immediate "
        "access-key revocation and WAF block (CONTAIN), then policy rescope "
        "and external snapshot-share revocation (ERADICATE), then host "
        "quarantine for forensics."
    )

    result = InvestigationResult(
        cloud="aws",
        signal=signal,
        iterations=len(trace),
        final_message=narrative,
        tool_calls=trace,
        staged_actions=[
            StagedAction(
                tool_id=f"aws.stage.{s['runbook']}",
                parameters=s["parameters"],
                result=s,
            )
            for s in staged_results
        ],
        investigation=inv,
    )

    out = REPO_ROOT / "out"
    out.mkdir(exist_ok=True)
    render_report(result, out / "report.html", out / "report.json")

    print(f"OK report.html -> {(out / 'report.html').resolve()}")
    print(f"OK report.json -> {(out / 'report.json').resolve()}")
    print(f"   nodes: {len(inv.nodes)}  edges: {len(inv.edges)}")
    print(f"   MITRE techniques: {[t['id'] for t in inv.mitre_coverage()]}")
    print(f"   staged containment actions: {len(staged_results)}")


if __name__ == "__main__":
    main()
