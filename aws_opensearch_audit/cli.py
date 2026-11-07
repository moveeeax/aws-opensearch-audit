"""Command line entry point.

Exit codes: 0 clean (or findings below --fail-on), 1 findings at or above
--fail-on, 2 the tool itself could not run.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__
from .collect import CollectError, collect, load_payload
from .report import render
from .rules import SEVERITY_RANK, Options, audit

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-opensearch-audit",
        description=(
            "Audit OpenSearch Service domains for resilience, encryption, access-policy "
            "and lifecycle misconfiguration."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--region", help="AWS region to audit (defaults to the boto3 session region)")
    parser.add_argument(
        "--domain",
        action="append",
        default=None,
        metavar="NAME",
        help="audit only this domain; repeat for several",
    )
    parser.add_argument(
        "--from-json",
        metavar="PATH",
        help="replay a saved describe-domains payload instead of calling AWS",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("warn", "critical", "none"),
        default="critical",
        help="lowest severity that makes the exit code 1 (default: critical)",
    )
    parser.add_argument(
        "--eol",
        metavar="VERSIONS",
        default="",
        help=(
            "comma-separated engine versions to treat as end of support in addition to the "
            "defaults (OpenSearch 1.x, Elasticsearch 7.9 and older), e.g. "
            "OpenSearch_2.3,Elasticsearch_7.10"
        ),
    )
    parser.add_argument(
        "--save-json",
        metavar="PATH",
        help="write the collected payload here so it can be replayed with --from-json",
    )
    return parser


def _options(args: argparse.Namespace) -> Options:
    extra = tuple(v.strip() for v in args.eol.split(",") if v.strip())
    return Options(eol_versions=extra)


def _exit_code(result: dict[str, Any], fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold = SEVERITY_RANK[fail_on]
    if SEVERITY_RANK.get(result["severity"], 0) >= threshold:
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.from_json and args.region:
        print("aws-opensearch-audit: --from-json and --region are mutually exclusive", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.from_json:
            payload = load_payload(args.from_json)
        else:
            payload = collect(region=args.region, only=args.domain)
    except CollectError as exc:
        print(f"aws-opensearch-audit: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.from_json and args.domain:
        wanted = set(args.domain)
        payload = {
            "region": payload.get("region"),
            "domains": [d for d in payload["domains"] if d.get("DomainName") in wanted],
        }

    if args.save_json:
        import json

        try:
            with open(args.save_json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            print(f"aws-opensearch-audit: cannot write {args.save_json}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    result = audit(payload, _options(args))
    sys.stdout.write(render(result, args.format))
    return _exit_code(result, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
