"""The IR-agent investigation loop.

Runs a manual Anthropic tool-use loop:
1. Load the cloud's specialist system prompt + tenant profile.
2. Build the tool definitions from `config/tools.yaml`.
3. Seed the conversation with the Point A signal.
4. Loop:
     - Call Claude with the available tools and prompt caching.
     - For each tool_use block in the response, execute the tool and append
       a tool_result. Track staged-containment actions separately so the
       report can render an approval gate for each.
     - Stop when stop_reason == "end_turn" or we exhaust the iteration
       budget.
5. Hand the final assistant message off to the report builder.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import anthropic

from ir_agent.config import (
    ToolSpec,
    detect_cloud,
    load_system_prompt,
    load_tenant,
    load_tools,
    tool_by_anthropic_name,
)
from ir_agent.graph.builder import build_graph_from_events
from ir_agent.graph.schema import Investigation
from ir_agent.llm.client import DEFAULT_MODEL, get_client, system_blocks

log = logging.getLogger("ir_agent.orchestrator")

MAX_ITERATIONS = int(os.environ.get("IR_AGENT_MAX_ITERATIONS", "40"))


@dataclass
class StagedAction:
    """A containment action the model proposed but did NOT execute."""
    tool_id: str
    parameters: dict[str, Any]
    result: dict[str, Any]
    proposed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class InvestigationResult:
    cloud: str
    signal: dict[str, Any]
    iterations: int
    final_message: str
    tool_calls: list[dict[str, Any]]
    staged_actions: list[StagedAction]
    investigation: Investigation | None = None
    stopped_reason: str = "end_turn"


def investigate(
    signal: dict[str, Any],
    *,
    cloud: str | None = None,
    enrich: list[str] | None = None,
    sample_telemetry: bool = False,
) -> InvestigationResult:
    """Run a full investigation starting from a Point A signal.

    Args:
        signal: the Point A JSON dict.
        cloud: 'aws' | 'azure' (forces routing). If None, inferred from the
            signal field set.
        enrich: list of enrichment provider IDs to enable. None = all,
            [] = none. Use `parse_enrich_flag` on the CLI string.
        sample_telemetry: when True, telemetry tools read from
            sample-telemetry/ instead of making live cloud SDK calls.
    """
    cloud = cloud or detect_cloud(signal)
    log.info(
        "starting investigation cloud=%s enrich=%s sample=%s",
        cloud, enrich if enrich is not None else "all", sample_telemetry,
    )

    tenant = load_tenant(cloud)
    specs = load_tools(cloud=cloud, enrich=enrich)
    system_prompt = _build_system_prompt(cloud, tenant)

    client = get_client()
    anthropic_tools = [s.to_anthropic_tool() for s in specs]

    # Sample-mode flag tells telemetry tools to read from sample-telemetry/
    # instead of calling the live cloud SDK.
    if sample_telemetry:
        os.environ["IR_AGENT_SAMPLE_MODE"] = "1"

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": _initial_user_message(signal, cloud, tenant),
        }
    ]

    tool_calls: list[dict[str, Any]] = []
    staged_actions: list[StagedAction] = []
    final_text = ""
    stopped_reason = "end_turn"
    iterations = 0

    for iterations in range(1, MAX_ITERATIONS + 1):
        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=16000,
                system=system_blocks(system_prompt),
                tools=anthropic_tools,
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                messages=messages,
            )
        except anthropic.APIStatusError as exc:
            log.error("LLM call failed (status=%s): %s", exc.status_code, exc.message)
            raise

        log.info(
            "iter=%d stop_reason=%s in=%d out=%d cache_read=%d",
            iterations,
            response.stop_reason,
            response.usage.input_tokens,
            response.usage.output_tokens,
            getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )

        # Capture any text from this turn (the final message is the last one).
        text_blocks = [b.text for b in response.content if b.type == "text"]
        if text_blocks:
            final_text = "\n".join(text_blocks)

        # End-of-turn: model has nothing more to do.
        if response.stop_reason == "end_turn":
            messages.append({"role": "assistant", "content": response.content})
            break

        # Continue server-side tool / pause-turn flow.
        if response.stop_reason == "pause_turn":
            messages.append({"role": "assistant", "content": response.content})
            continue

        # Tool use — execute and feed results back.
        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if not tool_use_blocks:
            # Model has nothing more to say or do — exit.
            messages.append({"role": "assistant", "content": response.content})
            break

        messages.append({"role": "assistant", "content": response.content})

        tool_results: list[dict[str, Any]] = []
        for block in tool_use_blocks:
            spec = tool_by_anthropic_name(specs, block.name)
            tool_result = _execute_tool(spec, dict(block.input))
            tool_calls.append(
                {
                    "tool_id": spec.id if spec else block.name,
                    "params": dict(block.input),
                    "result": tool_result,
                }
            )
            if spec and spec.destructive:
                staged_actions.append(
                    StagedAction(
                        tool_id=spec.id,
                        parameters=dict(block.input),
                        result=tool_result,
                    )
                )

            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(tool_result, default=str),
                }
            )
        messages.append({"role": "user", "content": tool_results})
    else:
        log.warning("hit iteration budget MAX_ITERATIONS=%d", MAX_ITERATIONS)
        stopped_reason = "iteration_budget"

    investigation = build_graph_from_events(
        cloud=cloud,
        signal=signal,
        tool_calls=tool_calls,
        narrative=final_text,
    )

    return InvestigationResult(
        cloud=cloud,
        signal=signal,
        iterations=iterations,
        final_message=final_text,
        tool_calls=tool_calls,
        staged_actions=staged_actions,
        investigation=investigation,
        stopped_reason=stopped_reason,
    )


def _build_system_prompt(cloud: str, tenant: dict[str, Any]) -> str:
    """Compose the master contract + cloud specialist + tenant profile."""
    master = load_system_prompt("ir-agent")
    specialist = load_system_prompt(f"{cloud}-ir")
    tenant_json = json.dumps(tenant, indent=2, default=str)
    return (
        f"{master}\n\n---\n\n"
        f"{specialist}\n\n---\n\n"
        f"## CURRENT TENANT PROFILE\n\n"
        f"```json\n{tenant_json}\n```\n"
    )


def _initial_user_message(
    signal: dict[str, Any], cloud: str, tenant: dict[str, Any]
) -> str:
    return (
        f"# POINT A · INVESTIGATION REQUEST\n\n"
        f"Cloud: **{cloud.upper()}**\n\n"
        f"## Triggering Signal\n\n"
        f"```json\n{json.dumps(signal, indent=2, default=str)}\n```\n\n"
        f"Run the standard validate-and-expand loop. Use the tools at your\n"
        f"disposal. For every node, cite the tool call and event/finding ID\n"
        f"that proves it. Map every node to MITRE ATT&CK. Stage containment\n"
        f"actions — do not execute. When the loop terminates (no new "
        f"in-scope entities or you reach the iteration budget), produce the\n"
        f"six-section report defined in the master contract.\n"
    )


def _execute_tool(spec: ToolSpec | None, params: dict[str, Any]) -> dict[str, Any]:
    if spec is None:
        return {"error": "unknown tool"}
    try:
        log.info("tool=%s params=%s", spec.id, list(params.keys()))
        result = spec.callable(**params)
        if not isinstance(result, dict):
            result = {"value": result}
        return result
    except Exception as exc:  # noqa: BLE001 — return errors to model
        log.exception("tool failure: %s", spec.id)
        return {"error": str(exc), "type": type(exc).__name__}
