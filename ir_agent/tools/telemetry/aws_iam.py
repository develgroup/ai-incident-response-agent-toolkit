"""AWS IAM principal resolution + policy enumeration.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from typing import Any

from ir_agent.tools.telemetry._sample import in_sample_mode, load_sample


def get_principal(
    access_key_id: str | None = None,
    principal_arn: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    if not access_key_id and not principal_arn:
        return {"error": "provide access_key_id or principal_arn"}

    if in_sample_mode():
        principals = load_sample("aws", "iam_principals")
        for p in principals:
            if access_key_id and access_key_id in (p.get("accessKeys") or []):
                return {"principal": p, "mode": "sample"}
            if principal_arn and p.get("Arn") == principal_arn:
                return {"principal": p, "mode": "sample"}
        return {"principal": None, "mode": "sample"}

    try:
        import boto3
    except ImportError:
        return {"error": "boto3 not installed"}

    iam = boto3.client("iam")

    # Resolve access key → user (only AWS API surface that does this is via list_access_keys per user).
    if access_key_id and not principal_arn:
        users = iam.list_users().get("Users", [])
        for user in users:
            keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
            if any(k.get("AccessKeyId") == access_key_id for k in keys):
                principal_arn = user["Arn"]
                break

    if not principal_arn:
        return {"principal": None, "note": "access key not found in current account"}

    # Detect user vs role from ARN.
    if ":user/" in principal_arn:
        name = principal_arn.rsplit("/", 1)[-1]
        attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
        inline = iam.list_user_policies(UserName=name).get("PolicyNames", [])
        return {
            "principal": {
                "Arn": principal_arn,
                "kind": "user",
                "AttachedPolicies": attached,
                "InlinePolicies": inline,
            },
            "mode": "live",
        }
    if ":role/" in principal_arn:
        name = principal_arn.rsplit("/", 1)[-1]
        role = iam.get_role(RoleName=name).get("Role", {})
        attached = iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
        inline = iam.list_role_policies(RoleName=name).get("PolicyNames", [])
        return {
            "principal": {
                "Arn": principal_arn,
                "kind": "role",
                "AssumeRolePolicyDocument": role.get("AssumeRolePolicyDocument"),
                "AttachedPolicies": attached,
                "InlinePolicies": inline,
            },
            "mode": "live",
        }
    return {"error": f"unsupported ARN: {principal_arn}"}
