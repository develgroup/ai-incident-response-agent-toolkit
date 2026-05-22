"""Render report.html + report.json from an InvestigationResult.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, select_autoescape

if TYPE_CHECKING:  # avoid import cycle
    from ir_agent.orchestrator import InvestigationResult

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def render_report(
    result: "InvestigationResult",
    html_path: Path,
    json_path: Path,
) -> None:
    payload = _to_payload(result)
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        report=payload,
        graph_json=json.dumps(payload["graph"]),
    )
    html_path.write_text(html, encoding="utf-8")


def _to_payload(result: "InvestigationResult") -> dict:
    inv = result.investigation
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cloud": result.cloud,
        "iterations": result.iterations,
        "stopped_reason": result.stopped_reason,
        "signal": result.signal,
        "narrative": result.final_message,
        "graph": inv.to_dict() if inv else {"nodes": [], "edges": []},
        "mitre_coverage": inv.mitre_coverage() if inv else [],
        "tool_calls": [
            {"tool_id": c["tool_id"], "params": c["params"]}
            for c in result.tool_calls
        ],
        "staged_actions": [
            {
                "tool_id": a.tool_id,
                "parameters": a.parameters,
                "result": a.result,
                "proposed_at": a.proposed_at,
            }
            for a in result.staged_actions
        ],
    }
