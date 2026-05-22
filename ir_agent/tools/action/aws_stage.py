"""AWS staged-containment actions.

These tools NEVER execute. Each call returns a runbook-derived proposed
action object that the human responder approves out-of-band.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.action._runbook import stage


def disable_access_key(access_key_id: str, rationale: str, username: str = "", **_: Any) -> dict[str, Any]:
    return stage(
        cloud="aws",
        runbook="revoke-access-key",
        params={"access_key_id": access_key_id, "username": username, "rationale": rationale},
    )


def waf_block(ip_set_arn: str, cidr: str, rationale: str, **_: Any) -> dict[str, Any]:
    return stage(
        cloud="aws",
        runbook="block-ip-waf",
        params={"ip_set_arn": ip_set_arn, "cidr": cidr, "rationale": rationale},
    )


def isolate_instance(
    instance_id: str,
    quarantine_sg_id: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="aws",
        runbook="isolate-instance",
        params={
            "instance_id": instance_id,
            "quarantine_sg_id": quarantine_sg_id,
            "rationale": rationale,
        },
    )


def revoke_snapshot_share(
    snapshot_id: str,
    external_account_id: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="aws",
        runbook="revoke-snapshot-share",
        params={
            "snapshot_id": snapshot_id,
            "external_account_id": external_account_id,
            "rationale": rationale,
        },
    )


def rescope_role(
    role_name: str,
    policy_arn_to_detach: str,
    rationale: str,
    replacement_policy_arn: str = "",
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="aws",
        runbook="rescope-role",
        params={
            "role_name": role_name,
            "policy_arn_to_detach": policy_arn_to_detach,
            "replacement_policy_arn": replacement_policy_arn,
            "rationale": rationale,
        },
    )
