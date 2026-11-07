"""Rendering an audit result as text, JSON or Markdown."""

from __future__ import annotations

import json
from typing import Any

MARKS = {"ok": "ok", "warn": "WARN", "critical": "CRIT"}


def _header(result: dict[str, Any]) -> str:
    summary = result["summary"]
    region = result.get("region") or "unknown region"
    return (
        f"{region}: {summary['domains']} domain(s), "
        f"{summary['critical_domains']} critical, {summary['warn_domains']} warn, "
        f"{summary['ok_domains']} clean"
    )


def render_text(result: dict[str, Any]) -> str:
    lines = [_header(result), ""]
    if not result["domains"]:
        lines.append("No OpenSearch domains found.")
        return "\n".join(lines).rstrip() + "\n"
    for domain in result["domains"]:
        nodes = domain.get("instance_count")
        shape = f"{domain.get('instance_type') or '?'} x{nodes if nodes is not None else '?'}"
        lines.append(
            f"[{MARKS[domain['severity']]}] {domain['name']} "
            f"({domain.get('engine') or 'unknown engine'}, {domain['placement']}, {shape})"
        )
        if not domain["findings"]:
            lines.append("    nothing to report")
        for finding in domain["findings"]:
            lines.append(f"    {MARKS[finding['severity']]}  {finding['title']}  [{finding['rule']}]")
            lines.append(f"          why: {finding['detail']}")
            lines.append(f"          fix: {finding['fix']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=False) + "\n"


def render_markdown(result: dict[str, Any]) -> str:
    lines = ["# OpenSearch domain audit", "", _header(result), ""]
    if not result["domains"]:
        lines.append("No OpenSearch domains found.")
        return "\n".join(lines) + "\n"
    lines += ["| domain | engine | placement | severity | findings |", "| --- | --- | --- | --- | --- |"]
    for domain in result["domains"]:
        lines.append(
            f"| `{domain['name']}` | {domain.get('engine') or '?'} | {domain['placement']} "
            f"| {domain['severity']} | {len(domain['findings'])} |"
        )
    lines.append("")
    for domain in result["domains"]:
        if not domain["findings"]:
            continue
        lines += [f"## `{domain['name']}`", ""]
        for finding in domain["findings"]:
            lines.append(f"- **{finding['severity']}** {finding['title']} (`{finding['rule']}`)")
            lines.append(f"  - why: {finding['detail']}")
            lines.append(f"  - fix: {finding['fix']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render(result: dict[str, Any], fmt: str) -> str:
    try:
        return RENDERERS[fmt](result)
    except KeyError:  # pragma: no cover - argparse restricts the choices
        raise ValueError(f"unknown format: {fmt}") from None
