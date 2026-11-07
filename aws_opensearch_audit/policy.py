"""Reasoning about OpenSearch domain access policies.

The access policy is the single field on a domain that can turn an index into a
public endpoint, so it gets its own module and its own tests.  Everything here
works on the parsed policy document and never touches AWS.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

# Condition keys that narrow a wildcard principal down to something reachable
# only from a known network or a known identity.
SCOPING_CONDITION_KEYS = (
    "aws:sourceip",
    "aws:principalarn",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:sourcearn",
    "aws:principalorgid",
    "aws:principalorgpaths",
)


class PolicyError(ValueError):
    """The access policy document could not be parsed."""


def parse_policy(raw: Any) -> dict[str, Any] | None:
    """Return the policy document as a dict, or None when there is no policy.

    OpenSearch hands the policy back as a JSON string inside the domain status,
    which is why this accepts both a string and an already-parsed dict.
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"access policy is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise PolicyError("access policy document is not a JSON object")
        return parsed
    raise PolicyError(f"unsupported access policy type: {type(raw).__name__}")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not policy:
        return []
    return [s for s in _as_list(policy.get("Statement")) if isinstance(s, dict)]


def principal_values(statement: dict[str, Any]) -> list[str]:
    """Flatten a statement's Principal into a list of principal strings."""
    principal = statement.get("Principal")
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        return [p for p in principal if isinstance(p, str)]
    if isinstance(principal, dict):
        out: list[str] = []
        for value in principal.values():
            out.extend(p for p in _as_list(value) if isinstance(p, str))
        return out
    return []


def is_wildcard_principal(statement: dict[str, Any]) -> bool:
    """True when the statement lets any AWS identity in.

    ``arn:aws:iam::*:root`` is treated as a wildcard too: the account id is the
    only thing it constrains, and it does not constrain it.
    """
    for value in principal_values(statement):
        stripped = value.strip()
        if stripped == "*":
            return True
        if stripped.startswith("arn:") and ":iam::*:" in stripped:
            return True
    return False


def condition_keys(statement: dict[str, Any]) -> list[str]:
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return []
    keys: list[str] = []
    for operand in condition.values():
        if isinstance(operand, dict):
            keys.extend(str(k).lower() for k in operand)
    return keys


def is_scoped(statement: dict[str, Any]) -> bool:
    """True when at least one condition key narrows who or where can call."""
    keys = condition_keys(statement)
    return any(key in SCOPING_CONDITION_KEYS for key in keys)


def statement_label(statement: dict[str, Any], index: int) -> str:
    sid = statement.get("Sid")
    if isinstance(sid, str) and sid.strip():
        return sid.strip()
    return f"statement #{index + 1}"


def open_statements(policy: dict[str, Any] | None) -> list[tuple[str, dict[str, Any]]]:
    """Return (label, statement) for every Allow statement that is wide open.

    "Wide open" means Effect Allow with a wildcard principal and no condition
    key that limits the source network or the calling identity.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    for index, statement in enumerate(statements(policy)):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        if not is_wildcard_principal(statement):
            continue
        if is_scoped(statement):
            continue
        found.append((statement_label(statement, index), statement))
    return found


def describe_actions(statement: dict[str, Any]) -> str:
    actions: Iterable[Any] = _as_list(statement.get("Action"))
    names = [str(a) for a in actions]
    if not names:
        return "no Action"
    if len(names) <= 3:
        return ", ".join(names)
    return ", ".join(names[:3]) + f" (+{len(names) - 3} more)"
