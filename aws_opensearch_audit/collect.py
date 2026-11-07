"""The only module that talks to AWS.

It returns plain dicts so the rule engine never has to know boto3 exists, and so
a payload can be saved to disk and replayed with ``--from-json``.
"""

from __future__ import annotations

import json
from typing import Any

DESCRIBE_BATCH = 5  # describe_domains caps DomainNames at 5 per call


class CollectError(RuntimeError):
    """Collecting the inventory failed."""


def _chunk(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def collect(region: str | None = None, only: list[str] | None = None) -> dict[str, Any]:
    """List every domain in the region and describe it.

    ``only`` narrows the run to the named domains.  boto3 is imported here on
    purpose: the rule engine and the tests must not need it installed.
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise CollectError(
            "boto3 is required for a live run; use --from-json to replay a saved payload"
        ) from exc

    client = boto3.client("opensearch", region_name=region) if region else boto3.client("opensearch")
    try:
        names = [
            d["DomainName"] for d in client.list_domain_names().get("DomainNames", []) if d.get("DomainName")
        ]
        if only:
            wanted = set(only)
            names = [n for n in names if n in wanted]
            missing = sorted(wanted - set(names))
            if missing:
                raise CollectError(f"no such domain in this region: {', '.join(missing)}")
        domains: list[dict[str, Any]] = []
        for batch in _chunk(sorted(names), DESCRIBE_BATCH):
            response = client.describe_domains(DomainNames=batch)
            domains.extend(response.get("DomainStatusList", []))
    except (BotoCoreError, ClientError) as exc:
        raise CollectError(f"AWS call failed: {exc}") from exc

    return {
        "region": region or client.meta.region_name,
        "domains": json.loads(json.dumps(domains, default=str)),
    }


def load_payload(path: str) -> dict[str, Any]:
    """Read a payload saved earlier. Raises CollectError on anything malformed."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise CollectError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise CollectError(f"{path} is not valid JSON: {exc}") from exc

    if isinstance(data, list):
        # Tolerate a bare DomainStatusList, which is what `aws opensearch
        # describe-domains --query DomainStatusList` hands you.
        return {"region": None, "domains": data}
    if not isinstance(data, dict):
        raise CollectError(f"{path} must contain an object or a list of domains")
    domains = data.get("domains")
    if domains is None:
        domains = data.get("DomainStatusList")
    if domains is None:
        raise CollectError(f"{path} has no 'domains' key")
    if not isinstance(domains, list):
        raise CollectError(f"{path}: 'domains' must be a list")
    for index, domain in enumerate(domains):
        if not isinstance(domain, dict):
            raise CollectError(f"{path}: domains[{index}] is not an object")
    return {"region": data.get("region"), "domains": domains}
