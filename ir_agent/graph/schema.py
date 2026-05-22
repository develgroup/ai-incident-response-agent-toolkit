"""Attack-graph data model.

A confirmed (or hypothesized) investigation is a directed graph:
  - Node = a confirmed event or entity (e.g. "IAM key AKIA... used from 198.51.100.7").
  - Edge = a proven causal link between two nodes.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Confidence = Literal["confirmed", "likely", "hypothesis"]
Phase = Literal[
    "initial-access", "credential-use", "execution", "persistence",
    "privilege-esc", "defense-evasion", "discovery", "lateral-movement",
    "collection", "exfiltration", "impact",
]


@dataclass
class AttackNode:
    id: str
    label: str
    phase: Phase
    confidence: Confidence
    attack_technique: str | None = None       # e.g. "T1078.004"
    attack_technique_name: str | None = None  # e.g. "Valid Cloud Accounts"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    entity_kind: str | None = None            # ip | key | role | bucket | spn | user | snapshot
    entity_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "phase": self.phase,
            "confidence": self.confidence,
            "attack_technique": self.attack_technique,
            "attack_technique_name": self.attack_technique_name,
            "evidence": self.evidence,
            "entity_kind": self.entity_kind,
            "entity_value": self.entity_value,
        }


@dataclass
class AttackEdge:
    src: str
    dst: str
    label: str
    evidence_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "label": self.label, "evidence_ref": self.evidence_ref}


@dataclass
class Investigation:
    cloud: str
    point_a: dict[str, Any]
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    narrative: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud": self.cloud,
            "point_a": self.point_a,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "narrative": self.narrative,
        }

    def mitre_coverage(self) -> list[dict[str, str]]:
        seen: dict[str, dict[str, str]] = {}
        for node in self.nodes:
            if node.attack_technique and node.attack_technique not in seen:
                seen[node.attack_technique] = {
                    "id": node.attack_technique,
                    "name": node.attack_technique_name or "",
                    "phase": node.phase,
                }
        return sorted(seen.values(), key=lambda t: t["id"])
