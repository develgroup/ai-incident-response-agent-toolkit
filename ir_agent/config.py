"""Config loading — tools, tenant, enrichment, MITRE map.

The tool registry (`config/tools.yaml`) is the single source of truth for
which tools exist, which cloud they belong to, what the LLM sees, and which
Python function implements them.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import importlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
AGENTS_DIR = REPO_ROOT / "agents"


_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    """Expand ${VAR} and ${VAR:-default} inside string values."""
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            return os.environ.get(m.group(1), m.group(2) or "")
        return _ENV_REF.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass(frozen=True)
class ToolSpec:
    id: str
    phase: str
    cloud: str
    description: str
    handler: str
    input_schema: dict
    destructive: bool = False

    @property
    def callable(self) -> Callable[..., Any]:
        module_path, _, fn = self.handler.rpartition(".")
        module = importlib.import_module(module_path)
        return getattr(module, fn)

    def to_anthropic_tool(self) -> dict[str, Any]:
        return {
            "name": self.id.replace(".", "__"),
            "description": self.description.strip(),
            "input_schema": self.input_schema,
        }


def load_tools(
    cloud: str | None = None,
    enrich: list[str] | None = None,
) -> list[ToolSpec]:
    """Load tool specs, filtered by `--cloud` and `--enrich` flags.

    cloud:
        - None      -> include all clouds plus universal (any).
        - "aws"     -> only AWS telemetry/action + universal enrichment.
        - "azure"   -> only Azure telemetry/action + universal enrichment.

    enrich:
        - None      -> all enrichment providers enabled.
        - []        -> NO enrichment providers enabled.
        - ["virustotal","abuseipdb"] -> only the listed ones.
    """
    raw = yaml.safe_load((CONFIG_DIR / "tools.yaml").read_text(encoding="utf-8"))
    specs: list[ToolSpec] = []
    for entry in raw.get("tools", []):
        tool_cloud = entry.get("cloud", "any")
        phase = entry["phase"]

        # Filter by cloud (skip clouds that aren't selected).
        if cloud and tool_cloud not in {"any", cloud}:
            continue

        # Filter enrichment subset via enrich_id, if a subset was requested.
        if enrich is not None and phase == "enrichment":
            if entry.get("enrich_id") not in enrich:
                continue

        specs.append(
            ToolSpec(
                id=entry["id"],
                phase=phase,
                cloud=tool_cloud,
                description=entry["description"],
                handler=entry["handler"],
                input_schema=entry["input_schema"],
                destructive=bool(entry.get("destructive", False)),
            )
        )
    return specs


ENRICH_IDS = ("virustotal", "abuseipdb", "shodan", "malwarebazaar", "yara")


def parse_enrich_flag(value: str | None) -> list[str] | None:
    """Translate the --enrich CLI value into a list filter.

    Accepts:
      None    or "all"   -> return None  (no filtering, all enabled)
              or "none"  -> return []    (disable enrichment entirely)
      "vt,abuseipdb"     -> return ["virustotal","abuseipdb"]
                            (also accepts short aliases: vt -> virustotal,
                            ai -> abuseipdb, sh -> shodan, mb -> malwarebazaar)
    """
    if value is None or value.strip().lower() == "all":
        return None
    if value.strip().lower() == "none":
        return []
    alias = {
        "vt": "virustotal",
        "ai": "abuseipdb",
        "sh": "shodan",
        "mb": "malwarebazaar",
    }
    out: list[str] = []
    for raw in value.split(","):
        token = raw.strip().lower()
        if not token:
            continue
        canonical = alias.get(token, token)
        if canonical not in ENRICH_IDS:
            raise ValueError(
                f"Unknown enrichment provider {raw!r}. "
                f"Valid: {', '.join(ENRICH_IDS)}, plus aliases vt/ai/sh/mb, or 'all'/'none'."
            )
        out.append(canonical)
    return out


def tool_by_anthropic_name(specs: list[ToolSpec], name: str) -> ToolSpec | None:
    for spec in specs:
        if spec.id.replace(".", "__") == name:
            return spec
    return None


def load_tenant(cloud: str) -> dict[str, Any]:
    """Load the tenant profile YAML for the named cloud.

    Prefers `config/tenant.<cloud>.yaml`; falls back to the example.
    """
    candidates = [
        CONFIG_DIR / f"tenant.{cloud}.yaml",
        CONFIG_DIR / f"tenant.example.{cloud}.yaml",
    ]
    for path in candidates:
        if path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return _expand_env(data)
    raise FileNotFoundError(f"No tenant profile for cloud={cloud}")


def load_enrichment_config() -> dict[str, Any]:
    raw = yaml.safe_load((CONFIG_DIR / "enrichment.yaml").read_text(encoding="utf-8"))
    return _expand_env(raw)


def load_mitre_map() -> dict[str, Any]:
    return yaml.safe_load((CONFIG_DIR / "mitre-attack-map.yaml").read_text(encoding="utf-8"))


def load_system_prompt(name: str) -> str:
    """Load a system-prompt markdown file from agents/."""
    path = AGENTS_DIR / f"{name}.system.md"
    if not path.is_file():
        raise FileNotFoundError(f"System prompt not found: {path}")
    return path.read_text(encoding="utf-8")


def detect_cloud(signal: dict[str, Any]) -> str:
    """Best-effort cloud / platform inference from a Point A signal dict.

    Returns one of: aws, azure, gcp, windows.
    """
    if signal.get("cloud") in {"aws", "azure", "gcp", "windows"}:
        return signal["cloud"]
    if signal.get("platform") == "windows":
        return "windows"

    aws_markers = {"account_id", "resource_arn", "guardduty_finding_id"}
    azure_markers = {"tenant_id", "target_app_id", "actor_upn", "correlation_id", "subscription_id"}
    gcp_markers = {"org_id", "project_id", "principal_email"}
    windows_markers = {"computer", "hostname", "sam_account_name", "process_guid"}

    keys = set(signal.keys())
    arn = str(signal.get("resource_arn", ""))
    source = str(signal.get("source", "")).lower()

    # Windows first — host-class signals are distinctive (computer + EDR source).
    if keys & windows_markers or source in {
        "cortex_xdr", "defender_for_endpoint", "crowdstrike", "sysmon",
        "winlogbeat", "windows_eventlog",
    }:
        return "windows"
    if arn.startswith("arn:aws:") or keys & aws_markers or source in {
        "guardduty", "securityhub", "cloudtrail", "detective", "config",
    }:
        return "aws"
    if keys & azure_markers or source in {
        "defender_xdr", "sentinel", "entra_identity_protection", "purview",
    }:
        return "azure"
    if keys & gcp_markers or source in {"scc", "etd", "ctd", "cloud_audit"}:
        return "gcp"

    raise ValueError(
        "Cloud/platform not specified and could not be inferred. "
        "Pass --cloud {aws|azure|gcp|windows} or include 'cloud' in the signal."
    )
