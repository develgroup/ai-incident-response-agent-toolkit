"""Anthropic SDK wrapper for the IR-agent.

Defaults:
- Model: claude-opus-4-7
- Adaptive thinking (high effort) — investigations benefit from reasoning
- Prompt caching on the large system prompt (>4000 tokens)

The orchestrator drives a manual tool-use loop (rather than the tool runner)
because every staged-containment tool requires the loop to record the
proposed action to the runbook before returning the result to the model.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import os

import anthropic

DEFAULT_MODEL = os.environ.get("IR_AGENT_MODEL", "claude-opus-4-7")


def get_client() -> anthropic.Anthropic:
    """Return a configured Anthropic client.

    API key resolution falls through to the SDK's standard ANTHROPIC_API_KEY
    environment variable.
    """
    return anthropic.Anthropic()


def system_blocks(system_prompt: str) -> list[dict]:
    """Build the system prompt as a single cacheable text block.

    Prompt caching cuts the cost of these long system prompts by ~90% on
    repeat invocations within the 5-minute TTL. See
    docs.claude.com/en/build-with-claude/prompt-caching.
    """
    return [
        {
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }
    ]
