"""Attack-graph builder.

Distills the orchestrator's tool-call trace into a node/edge graph:
- Each enrichment / telemetry call yields candidate nodes for the entities
  it touched (IPs, access keys, principals, snapshots, etc).
- Tool returns of `malicious=True` from enrichment promote a node to
  `confirmed`.
- MITRE ATT&CK mapping is attached when the tool call carries an event name
  the map knows about.

This produces a deterministic, evidenced graph alongside whatever narrative
text the model itself produced. The graph is the visualization; the narrative
is the executive summary.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ir_agent.graph.mitre import map_event, map_tool_call
from ir_agent.graph.schema import AttackEdge, AttackNode, Investigation

log = logging.getLogger("ir_agent.graph")

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def build_graph_from_events(
    *,
    cloud: str,
    signal: dict[str, Any],
    tool_calls: list[dict[str, Any]],
    narrative: str,
) -> Investigation:
    """Assemble an Investigation from the orchestrator's tool-call trace."""
    investigation = Investigation(cloud=cloud, point_a=signal, narrative=narrative)
    node_by_key: dict[str, AttackNode] = {}

    point_a = _make_point_a_node(cloud, signal)
    investigation.nodes.append(point_a)
    node_by_key[_key(point_a.entity_kind, point_a.entity_value)] = point_a

    prev_node: AttackNode = point_a

    for call in tool_calls:
        tool_id = call["tool_id"]
        params = call.get("params", {})
        result = call.get("result", {})
        if not isinstance(result, dict):
            continue

        attack = map_tool_call(cloud, tool_id, params)

        # Enrichment results — mark indicators confirmed when malicious.
        if tool_id.startswith("virustotal") or tool_id.startswith("abuseipdb") \
                or tool_id.startswith("shodan") or tool_id.startswith("malwarebazaar"):
            indicator, kind = _indicator_from_enrichment(tool_id, params, result)
            if not indicator:
                continue
            key = _key(kind, indicator)
            existing = node_by_key.get(key)
            confidence = "confirmed" if _is_malicious(tool_id, result) else "likely"
            evidence = {
                "tool": tool_id,
                "input": params,
                "summary": _summarize_enrichment(tool_id, result),
            }
            if existing:
                # Upgrade confidence on second-source malicious verdict.
                if confidence == "confirmed":
                    existing.confidence = "confirmed"
                existing.evidence.append(evidence)
            else:
                node = AttackNode(
                    id=f"n-{len(investigation.nodes) + 1}",
                    label=f"{kind} {indicator}",
                    phase="credential-use" if kind != "hash" else "execution",
                    confidence=confidence,
                    entity_kind=kind,
                    entity_value=indicator,
                    evidence=[evidence],
                )
                investigation.nodes.append(node)
                node_by_key[key] = node
                investigation.edges.append(
                    AttackEdge(src=prev_node.id, dst=node.id, label="enrichment", evidence_ref=tool_id)
                )

        # Telemetry — turn event records into nodes.
        elif (tool_id.startswith("aws.cloudtrail")
              or tool_id.startswith("azure.")
              or tool_id.startswith("windows.")):
            events = (
                result.get("events")
                or result.get("rows")
                or result.get("signins")
                or result.get("findings")
                or result.get("tasks")
                or result.get("processes")
                or []
            )
            for ev in events[:25]:
                node = _node_for_event(cloud, ev, attack)
                if node is None:
                    continue
                # Events with a MITRE technique deserve their own node, even
                # when the entity (IP / principal) is already tracked — same
                # actor performing different ATT&CK techniques is distinct
                # nodes in the attack graph.
                if node.attack_technique:
                    key = _key(
                        "event",
                        f"{node.attack_technique}:{node.entity_value}",
                    )
                else:
                    key = _key(node.entity_kind, node.entity_value)
                if key in node_by_key:
                    node_by_key[key].evidence.append(
                        {"tool": tool_id, "event": _trim_event(ev)}
                    )
                    continue
                node.id = f"n-{len(investigation.nodes) + 1}"
                node.evidence.append({"tool": tool_id, "event": _trim_event(ev)})
                investigation.nodes.append(node)
                node_by_key[key] = node
                investigation.edges.append(
                    AttackEdge(
                        src=prev_node.id,
                        dst=node.id,
                        label=node.phase,
                        evidence_ref=ev.get("eventID") or ev.get("correlationId"),
                    )
                )
                prev_node = node

    return investigation


def _make_point_a_node(cloud: str, signal: dict[str, Any]) -> AttackNode:
    kind = "alert"
    value = (
        signal.get("finding_id")
        or signal.get("alert_id")
        or signal.get("correlation_id")
        or signal.get("id")
        or "point-a"
    )
    label = signal.get("type") or signal.get("title") or "Point A"
    return AttackNode(
        id="n-0",
        label=str(label),
        phase="initial-access",
        confidence="hypothesis",
        attack_technique=None,
        entity_kind=kind,
        entity_value=str(value),
        evidence=[{"tool": "signal", "summary": str(label)}],
    )


def _key(kind: str | None, value: str | None) -> str:
    return f"{kind}:{value}"


def _indicator_from_enrichment(
    tool_id: str, params: dict[str, Any], result: dict[str, Any]
) -> tuple[str | None, str]:
    if tool_id.endswith("virustotal__lookup") or tool_id == "virustotal.lookup":
        return params.get("indicator"), params.get("kind", "indicator")
    if tool_id.endswith("abuseipdb__check") or tool_id == "abuseipdb.check":
        return params.get("ip"), "ip"
    if tool_id.endswith("shodan__host") or tool_id == "shodan.host":
        return params.get("ip"), "ip"
    if tool_id.endswith("malwarebazaar__query") or tool_id == "malwarebazaar.query":
        return params.get("sha256"), "hash"
    return None, "indicator"


def _is_malicious(tool_id: str, result: dict[str, Any]) -> bool:
    if "malicious" in result:
        return bool(result["malicious"])
    if "suspicious" in result:
        return bool(result["suspicious"])
    score = result.get("abuse_confidence_score") or result.get("detections")
    if isinstance(score, int):
        return score >= 50 if "abuse_confidence_score" in result else score >= 3
    return False


def _summarize_enrichment(tool_id: str, result: dict[str, Any]) -> str:
    if "abuse_confidence_score" in result:
        return f"AbuseIPDB score {result['abuse_confidence_score']}/100 · {result.get('total_reports')} reports"
    if "tags" in result:
        return f"Shodan tags={result['tags']} ports={result.get('ports')}"
    if "detections" in result:
        return f"VirusTotal {result['detections']}/{result.get('total_engines')} engines"
    if "signature" in result:
        return f"MalwareBazaar signature={result['signature']}"
    if "matches" in result:
        return f"YARA matched={len(result['matches'])}"
    return ""


def _node_for_event(
    cloud: str, ev: dict[str, Any], attack: dict[str, str] | None
) -> AttackNode | None:
    # AWS / Azure / generic event names
    event_name = (
        ev.get("eventName")
        or ev.get("operationName")
        or ev.get("activityDisplayName")
    )

    # Windows event ID — Security log entries carry EventID, Sysmon entries
    # also carry EventID but live on a different Channel; the MITRE map
    # keys them as plain "<id>" for Security and "sysmon-<id>" for Sysmon.
    if not event_name:
        eid = ev.get("EventID")
        if eid is not None:
            channel = (ev.get("Channel") or "").lower()
            key = f"sysmon-{eid}" if "sysmon" in channel else str(eid)
            if not attack:
                attack = map_event(cloud, key)
            # If we hit a sysmon event with no Channel field, still try sysmon-<id>
            if not attack:
                attack = map_event(cloud, f"sysmon-{eid}")
            event_name = key

    # Windows scheduled-task records (no EventID at all)
    if not event_name and ev.get("TaskName"):
        event_name = f"scheduled-task:{ev['TaskName']}"
        if not attack:
            attack = {
                "id": "T1053.005",
                "name": "Scheduled Task/Job: Scheduled Task",
                "phase": "persistence",
            }

    # Windows process snapshot entries
    if not event_name and ev.get("Name") and ev.get("PID"):
        event_name = f"process:{ev['Name']} (pid={ev['PID']})"

    if event_name and not attack:
        attack = map_event(cloud, str(event_name))

    label = event_name or ev.get("type") or ev.get("title") or "event"
    kind, value = _entity_for_event(ev)
    if value is None:
        return None

    phase = attack["phase"] if attack else "discovery"
    return AttackNode(
        id="",  # filled by caller
        label=str(label),
        phase=phase,
        confidence="confirmed" if attack else "likely",
        attack_technique=attack["id"] if attack else None,
        attack_technique_name=attack["name"] if attack else None,
        entity_kind=kind,
        entity_value=value,
        evidence=[],
    )


def _entity_for_event(ev: dict[str, Any]) -> tuple[str, str | None]:
    # Cloud-style fields first
    ip = (
        ev.get("sourceIPAddress")
        or ev.get("ipAddress")
        or ev.get("callerIpAddress")
    )
    if ip:
        return "ip", str(ip)

    # Windows event has nested EventData with an IpAddress field
    ed = ev.get("EventData")
    if isinstance(ed, dict):
        ip = ed.get("IpAddress") or ed.get("DestinationIp") or ed.get("SourceIp")
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            return "ip", str(ip)
        if ed.get("TargetUserName"):
            return "principal", f"{ed.get('TargetDomainName','')}\\{ed['TargetUserName']}".lstrip("\\")
        if ed.get("Image"):
            return "process", str(ed["Image"])
        if ed.get("TaskName"):
            return "task", str(ed["TaskName"])

    arn = (ev.get("userIdentity") or {}).get("arn") if isinstance(ev.get("userIdentity"), dict) else None
    if arn:
        return "principal", str(arn)
    actor = (
        ev.get("Actor")
        or ev.get("caller")
        or ((ev.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName")
    )
    if actor:
        return "principal", str(actor)

    # Windows scheduled-task / process snapshot top-level
    if ev.get("TaskName"):
        return "task", str(ev["TaskName"])
    if ev.get("Name") and ev.get("PID"):
        host = ev.get("Computer") or ""
        return "process", f"{host}:{ev['Name']}({ev['PID']})"

    resources = ev.get("resources") or ev.get("targetResources")
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            return "resource", str(first.get("ResourceName") or first.get("id") or first.get("displayName") or "")
    if ev.get("resourceId"):
        return "resource", str(ev["resourceId"])
    if ev.get("Computer"):
        return "host", str(ev["Computer"])
    return "event", str(ev.get("eventID") or ev.get("correlationId") or ev.get("EventRecordID") or ev.get("RecordID") or "")


def _trim_event(ev: dict[str, Any]) -> dict[str, Any]:
    """Strip event records to a citable shape — full payloads bloat the report."""
    keep = (
        # AWS / Azure
        "eventID", "eventName", "eventTime", "sourceIPAddress", "userAgent",
        "userIdentity", "awsRegion", "errorCode",
        "operationName", "callerIpAddress", "caller", "resourceId",
        "correlationId", "ipAddress", "userPrincipalName", "appId",
        "activityDisplayName", "Severity", "Title", "Id",
        # Windows event log / Sysmon / scheduled tasks
        "EventRecordID", "RecordID", "TimeCreated", "Channel", "EventID",
        "Computer", "EventData", "TaskName", "Author", "RunAsUser",
        "Actions", "Triggers", "Name", "PID", "ParentName", "User",
    )
    return {k: ev.get(k) for k in keep if k in ev}
