"""ir-agent CLI entrypoint.

  ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json
  ir-agent investigate --signal <file> --cloud aws --enrich vt,abuseipdb,shodan
  ir-agent investigate --signal <file> --sample      # runs against sample-telemetry/

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

from ir_agent.config import parse_enrich_flag
from ir_agent.orchestrator import investigate
from ir_agent.report.renderer import render_report

console = Console()


@click.group()
@click.option(
    "--log-level",
    default=os.environ.get("IR_AGENT_LOG_LEVEL", "INFO"),
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
)
def main(log_level: str) -> None:
    """AI-driven incident response — reconstruct, map, contain."""
    logging.basicConfig(
        level=log_level.upper(),
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


@main.command("investigate")
@click.option(
    "--signal",
    "signal_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the Point A signal JSON file.",
)
@click.option(
    "--cloud",
    type=click.Choice(["aws", "azure", "gcp", "windows"], case_sensitive=False),
    default=None,
    help="Force routing — aws / azure / gcp / windows. Inferred from the signal when omitted.",
)
@click.option(
    "--enrich",
    "enrich_raw",
    type=str,
    default=None,
    help="Enrichment subset. Comma-separated provider IDs (virustotal, "
         "abuseipdb, shodan, malwarebazaar, yara), short aliases "
         "(vt, ai, sh, mb), 'all' (default), or 'none' to disable.",
)
@click.option(
    "--sample/--live",
    default=False,
    help="Use the synthetic breach dataset under sample-telemetry/ "
         "(no live cloud calls). Default: --live.",
)
@click.option(
    "--out",
    "out_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path(os.environ.get("IR_AGENT_OUTPUT_DIR", "./out")),
    help="Output directory for report.html and report.json.",
)
def investigate_cmd(
    signal_path: Path,
    cloud: str | None,
    enrich_raw: str | None,
    sample: bool,
    out_dir: Path,
) -> None:
    """Reconstruct the attack path starting at Point A."""
    signal = json.loads(signal_path.read_text(encoding="utf-8"))

    try:
        enrich = parse_enrich_flag(enrich_raw)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--enrich")

    cloud_lbl = (cloud or "auto").upper()
    enrich_lbl = "all" if enrich is None else (",".join(enrich) if enrich else "none")
    console.rule(
        f"[bold cyan]validating... expanding... mapping ATT&CK... "
        f"[dim](cloud={cloud_lbl} · enrich={enrich_lbl})[/dim]"
    )
    result = investigate(
        signal=signal,
        cloud=cloud.lower() if cloud else None,
        enrich=enrich,
        sample_telemetry=sample,
    )
    console.rule(f"[bold green]reconstruction complete · {result.iterations} iterations")

    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"
    json_path = out_dir / "report.json"

    render_report(result, html_path=html_path, json_path=json_path)

    console.print(f"[bold]Attack path reconstructed →[/bold] {html_path}")
    console.print(f"[bold]Machine-readable graph →[/bold]    {json_path}")
    if result.staged_actions:
        console.print(
            f"\n[bold yellow]{len(result.staged_actions)} containment actions staged "
            f"pending human approval.[/bold yellow]"
        )


if __name__ == "__main__":
    main(sys.argv[1:])  # pragma: no cover
