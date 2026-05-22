"""Load a containment runbook template + render it with parameters.

Each runbook YAML lives at runbooks/<cloud>/<name>.yaml and contains the
exact command/payload to execute, blast-radius assessment, and rollback
notes. Staged-action tools return a rendered runbook dict — they never
execute the command themselves.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNBOOK_ROOT = REPO_ROOT / "runbooks"


def stage(cloud: str, runbook: str, params: dict[str, Any]) -> dict[str, Any]:
    """Render the runbook template and return a proposed-action object."""
    path = RUNBOOK_ROOT / cloud / f"{runbook}.yaml"
    if not path.is_file():
        return {"error": f"runbook not found: {path}"}

    raw = path.read_text(encoding="utf-8")
    rendered = Template(raw).safe_substitute({k: str(v) for k, v in params.items()})
    spec = yaml.safe_load(rendered)

    return {
        "approval_required": True,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "runbook": runbook,
        "cloud": cloud,
        "phase": spec.get("phase", "contain"),
        "action": spec.get("action"),
        "command": spec.get("command"),
        "blast_radius": spec.get("blast_radius"),
        "rollback": spec.get("rollback"),
        "rationale": params.get("rationale", ""),
        "parameters": params,
    }
