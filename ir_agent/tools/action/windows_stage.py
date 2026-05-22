"""Windows staged-containment actions. Never execute — always stage-only.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.action._runbook import stage


def isolate_host(computer: str, rationale: str, **_: Any) -> dict[str, Any]:
    return stage(
        cloud="windows",
        runbook="isolate-host",
        params={"computer": computer, "rationale": rationale},
    )


def kill_process(
    computer: str,
    process_guid: str,
    pid: int | str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="windows",
        runbook="kill-process",
        params={
            "computer": computer,
            "process_guid": process_guid,
            "pid": str(pid),
            "rationale": rationale,
        },
    )


def disable_account(
    sam_account_name: str,
    domain: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="windows",
        runbook="disable-account",
        params={
            "sam_account_name": sam_account_name,
            "domain": domain,
            "rationale": rationale,
        },
    )


def remove_scheduled_task(
    computer: str,
    task_name: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="windows",
        runbook="remove-scheduled-task",
        params={
            "computer": computer,
            "task_name": task_name,
            "rationale": rationale,
        },
    )


def stop_disable_service(
    computer: str,
    service_name: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="windows",
        runbook="stop-disable-service",
        params={
            "computer": computer,
            "service_name": service_name,
            "rationale": rationale,
        },
    )
