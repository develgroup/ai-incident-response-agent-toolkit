"""Azure staged-containment actions. Never execute — always stage-only.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.action._runbook import stage


def revoke_sessions(user_object_id: str, rationale: str, **_: Any) -> dict[str, Any]:
    return stage(
        cloud="azure",
        runbook="revoke-sessions",
        params={"user_object_id": user_object_id, "rationale": rationale},
    )


def remove_credential(
    app_object_id: str,
    credential_id: str,
    credential_type: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="azure",
        runbook="remove-app-credential",
        params={
            "app_object_id": app_object_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "rationale": rationale,
        },
    )


def disable_spn(spn_object_id: str, rationale: str, **_: Any) -> dict[str, Any]:
    return stage(
        cloud="azure",
        runbook="disable-spn",
        params={"spn_object_id": spn_object_id, "rationale": rationale},
    )


def ca_emergency_block(user_object_id: str, rationale: str, **_: Any) -> dict[str, Any]:
    return stage(
        cloud="azure",
        runbook="conditional-access-emergency-block",
        params={"user_object_id": user_object_id, "rationale": rationale},
    )


def revoke_sas(
    storage_account_id: str,
    key_name: str,
    rationale: str,
    **_: Any,
) -> dict[str, Any]:
    return stage(
        cloud="azure",
        runbook="revoke-storage-sas",
        params={
            "storage_account_id": storage_account_id,
            "key_name": key_name,
            "rationale": rationale,
        },
    )
