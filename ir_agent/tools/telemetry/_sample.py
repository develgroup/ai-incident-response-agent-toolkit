"""Sample-mode loader for the synthetic breach dataset.

When IR_AGENT_SAMPLE_MODE=1, telemetry tools read from
`sample-telemetry/<cloud>/<file>.json` instead of calling live cloud APIs.
This lets the demo end-to-end without AWS/Azure credentials.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_ROOT = REPO_ROOT / "sample-telemetry"


def in_sample_mode() -> bool:
    return os.environ.get("IR_AGENT_SAMPLE_MODE") == "1"


def load_sample(cloud: str, name: str) -> Any:
    path = SAMPLE_ROOT / cloud / f"{name}.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))
