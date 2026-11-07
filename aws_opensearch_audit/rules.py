"""The rule engine.

Input is a plain dict shaped like one ``DomainStatus`` entry from
``opensearch:DescribeDomains``.  Output is a list of findings.  No AWS calls, no
globals, no I/O -- which is why every rule below is testable from a JSON
fixture.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from .policy import PolicyError, describe_actions, open_statements, parse_policy

SEVERITIES = ("ok", "warn", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# TLS policies at or above the 1.2 baseline.  Anything else is a 1.0 policy and
# still negotiates TLS 1.0/1.1 with whatever client asks for it.
TLS_12_POLICIES = frozenset(
    {
        "Policy-Min-TLS-1-2-2019-07",
        "Policy-Min-TLS-1-2-PFS-2023-10",
    }
)

MIN_MASTER_QUORUM = 3


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    fix: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class Options:
    """Knobs a caller can turn without editing rules."""

    eol_versions: tuple[str, ...] = ()
    max_master_count: int = MIN_MASTER_QUORUM
    tls_policies: frozenset[str] = field(default_factory=lambda: TLS_12_POLICIES)


def worst(severities: list[str]) -> str:
    if not severities:
        return "ok"
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


def domain_name(domain: dict[str, Any]) -> str:
    return str(domain.get("DomainName") or domain.get("domain_name") or "<unknown>")


def is_vpc_domain(domain: dict[str, Any]) -> bool:
    vpc = domain.get("VPCOptions") or {}
    return bool(vpc.get("SubnetIds") or vpc.get("VPCId"))


def engine_version(domain: dict[str, Any]) -> str:
    return str(domain.get("EngineVersion") or "")


def parse_engine(version: str) -> tuple[str, tuple[int, ...]] | None:
    """Split ``OpenSearch_2.11`` into ``("OpenSearch", (2, 11))``."""
    if "_" not in version:
        return None
    engine, _, rest = version.partition("_")
    parts: list[int] = []
    for chunk in rest.split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    if not parts:
        return None
    return engine, tuple(parts)


def is_eol_engine(version: str, extra: tuple[str, ...] = ()) -> bool:
    """Default policy: every OpenSearch 1.x, and Elasticsearch 7.9 and older."""
    if not version:
        return False
    if version in extra:
        return True
    parsed = parse_engine(version)
    if parsed is None:
        return False
    engine, numbers = parsed
    if engine.lower() == "opensearch":
        return numbers[0] <= 1
    if engine.lower() == "elasticsearch":
        return numbers[:2] <= (7, 9)
    return False


# --- resilience ------------------------------------------------------------


def rule_dedicated_master(domain: dict[str, Any], opts: Options) -> list[Finding]:
    cluster = domain.get("ClusterConfig") or {}
    enabled = bool(cluster.get("DedicatedMasterEnabled"))
    data_nodes = int(cluster.get("InstanceCount") or 0)
    if not enabled:
        return [
            Finding(
                rule="dedicated-master-disabled",
                severity="warn",
                title="no dedicated master nodes",
                detail=(
                    f"{data_nodes} data node(s) are also holding cluster state; losing one "
                    "takes the cluster's view of itself with it"
                ),
                fix=(
                    "set DedicatedMasterEnabled with DedicatedMasterCount 3 "
                    "(update-domain-config, rolling change)"
                ),
            )
        ]
    count = int(cluster.get("DedicatedMasterCount") or 0)
    if count < opts.max_master_count:
        return [
            Finding(
                rule="dedicated-master-quorum",
                severity="warn",
                title=f"dedicated master count is {count}",
                detail=(
                    f"a quorum needs {MIN_MASTER_QUORUM} masters; with {count} there is no "
                    "majority after a single master is lost"
                ),
                fix=f"raise DedicatedMasterCount to {MIN_MASTER_QUORUM}",
            )
        ]
    return []


def rule_zone_awareness(domain: dict[str, Any], opts: Options) -> list[Finding]:
    cluster = domain.get("ClusterConfig") or {}
    data_nodes = int(cluster.get("InstanceCount") or 0)
    enabled = bool(cluster.get("ZoneAwarenessEnabled"))
    out: list[Finding] = []
    if not enabled and data_nodes > 1:
        out.append(
            Finding(
                rule="zone-awareness-disabled",
                severity="warn",
                title="zone awareness is off",
                detail=(
                    f"all {data_nodes} data nodes sit in one availability zone, so an AZ event "
                    "is a full outage rather than a lost replica"
                ),
                fix="enable ZoneAwarenessEnabled with AvailabilityZoneCount 2 or 3",
            )
        )
    if enabled:
        az_count = int(((cluster.get("ZoneAwarenessConfig") or {}).get("AvailabilityZoneCount")) or 0)
        if az_count == 1:
            out.append(
                Finding(
                    rule="single-availability-zone",
                    severity="warn",
                    title="availability zone count is 1",
                    detail=(
                        "zone awareness is enabled but pinned to a single zone, which buys "
                        "nothing over having it off"
                    ),
                    fix="set ZoneAwarenessConfig.AvailabilityZoneCount to 2 or 3",
                )
            )
    return out


def rule_single_node(domain: dict[str, Any], opts: Options) -> list[Finding]:
    cluster = domain.get("ClusterConfig") or {}
    data_nodes = int(cluster.get("InstanceCount") or 0)
    if data_nodes == 1:
        return [
            Finding(
                rule="single-node-domain",
                severity="warn",
                title="single data node",
                detail=(
                    "one data node cannot hold a replica of its own shards; any node "
                    "replacement is downtime and a restore"
                ),
                fix="run at least 2 data nodes and set number_of_replicas to 1 on the indices",
            )
        ]
    return []


# --- encryption and transport ---------------------------------------------


def rule_encryption_at_rest(domain: dict[str, Any], opts: Options) -> list[Finding]:
    options = domain.get("EncryptionAtRestOptions") or {}
    if options.get("Enabled"):
        return []
    return [
        Finding(
            rule="encryption-at-rest-disabled",
            severity="critical",
            title="encryption at rest is disabled",
            detail=(
                "index data and automated snapshots are stored unencrypted; this cannot be changed in place"
            ),
            fix=(
                "create a new domain with EncryptionAtRestOptions enabled and reindex or "
                "restore into it -- there is no update-domain-config path"
            ),
        )
    ]


def rule_node_to_node(domain: dict[str, Any], opts: Options) -> list[Finding]:
    options = domain.get("NodeToNodeEncryptionOptions") or {}
    if options.get("Enabled"):
        return []
    return [
        Finding(
            rule="node-to-node-encryption-disabled",
            severity="warn",
            title="node-to-node encryption is disabled",
            detail="shard replication and cluster traffic cross the network in the clear",
            fix=(
                "enable NodeToNodeEncryptionOptions -- like encryption at rest this is "
                "creation-time only, so plan a replacement domain"
            ),
        )
    ]


def rule_enforce_https(domain: dict[str, Any], opts: Options) -> list[Finding]:
    endpoint = domain.get("DomainEndpointOptions") or {}
    if endpoint.get("EnforceHTTPS"):
        return []
    return [
        Finding(
            rule="enforce-https-disabled",
            severity="critical",
            title="HTTPS is not enforced on the endpoint",
            detail="the domain still answers on plain HTTP, including for basic-auth requests",
            fix="set DomainEndpointOptions.EnforceHTTPS to true",
        )
    ]


def rule_tls_policy(domain: dict[str, Any], opts: Options) -> list[Finding]:
    endpoint = domain.get("DomainEndpointOptions") or {}
    if not endpoint.get("EnforceHTTPS"):
        # enforce-https already fired; a TLS policy on an HTTP endpoint is noise.
        return []
    policy = str(endpoint.get("TLSSecurityPolicy") or "")
    if not policy or policy in opts.tls_policies:
        return []
    return [
        Finding(
            rule="tls-policy-stale",
            severity="warn",
            title=f"TLS policy {policy} is below the 1.2 baseline",
            detail="the endpoint will still negotiate TLS 1.0 or 1.1 with clients that ask",
            fix="set DomainEndpointOptions.TLSSecurityPolicy to Policy-Min-TLS-1-2-PFS-2023-10",
        )
    ]


# --- access ----------------------------------------------------------------


def rule_access_policy(domain: dict[str, Any], opts: Options) -> list[Finding]:
    raw = domain.get("AccessPolicies")
    try:
        policy = parse_policy(raw)
    except PolicyError as exc:
        return [
            Finding(
                rule="access-policy-unparseable",
                severity="warn",
                title="access policy could not be parsed",
                detail=str(exc),
                fix="fetch the policy with describe-domain-config and fix the document",
            )
        ]
    open_ones = open_statements(policy)
    if not open_ones:
        return []
    vpc = is_vpc_domain(domain)
    severity = "warn" if vpc else "critical"
    findings: list[Finding] = []
    for label, statement in open_ones:
        placement = (
            "the domain is inside a VPC, so reachability is still limited by the subnets and security groups"
            if vpc
            else "the domain has a public endpoint, so this is reachable from the internet"
        )
        findings.append(
            Finding(
                rule="access-policy-wildcard",
                severity=severity,
                title=f"{label} allows a wildcard principal",
                detail=(
                    f"Allow for Principal * on {describe_actions(statement)} with no "
                    f"aws:SourceIp or aws:PrincipalArn condition; {placement}"
                ),
                fix=(
                    "replace Principal * with the roles that need access, or add an "
                    "aws:SourceIp condition for the networks that do"
                ),
            )
        )
    return findings


def rule_fine_grained_access(domain: dict[str, Any], opts: Options) -> list[Finding]:
    advanced = domain.get("AdvancedSecurityOptions") or {}
    if advanced.get("Enabled"):
        return []
    return [
        Finding(
            rule="fine-grained-access-disabled",
            severity="warn",
            title="fine-grained access control is disabled",
            detail=(
                "authorization stops at the domain: anyone the access policy lets in can "
                "read and delete every index"
            ),
            fix=(
                "enable AdvancedSecurityOptions and map IAM roles to OpenSearch roles "
                "(requires HTTPS enforcement and both encryption options)"
            ),
        )
    ]


def rule_internal_user_database(domain: dict[str, Any], opts: Options) -> list[Finding]:
    advanced = domain.get("AdvancedSecurityOptions") or {}
    endpoint = domain.get("DomainEndpointOptions") or {}
    if not advanced.get("InternalUserDatabaseEnabled"):
        return []
    if endpoint.get("EnforceHTTPS"):
        return []
    return [
        Finding(
            rule="internal-user-db-without-https",
            severity="warn",
            title="internal user database is on while HTTPS is not enforced",
            detail="the master user password travels in a plaintext basic-auth header",
            fix="enforce HTTPS, or drop the internal user database and use IAM principals",
        )
    ]


# --- lifecycle -------------------------------------------------------------


def rule_automated_snapshots(domain: dict[str, Any], opts: Options) -> list[Finding]:
    engine = engine_version(domain)
    parsed = parse_engine(engine)
    # Elasticsearch 5.3+ and every OpenSearch version get hourly managed
    # snapshots; only the older Elasticsearch domains carry a configurable hour.
    legacy = parsed is not None and parsed[0].lower() == "elasticsearch" and parsed[1][:2] < (5, 3)
    if not legacy:
        return []
    options = domain.get("SnapshotOptions") or {}
    if options.get("AutomatedSnapshotStartHour") is not None:
        return []
    return [
        Finding(
            rule="automated-snapshot-missing",
            severity="warn",
            title="no automated snapshot hour configured",
            detail=(
                f"{engine} predates managed hourly snapshots and has no "
                "AutomatedSnapshotStartHour, so there is no automatic backup"
            ),
            fix="set SnapshotOptions.AutomatedSnapshotStartHour, or upgrade the engine",
        )
    ]


def rule_software_update(domain: dict[str, Any], opts: Options) -> list[Finding]:
    software = domain.get("ServiceSoftwareOptions") or {}
    if not software.get("UpdateAvailable"):
        return []
    current = software.get("CurrentVersion") or "unknown"
    new = software.get("NewVersion") or "a newer release"
    detail = f"service software {current} is behind {new}"
    if software.get("AutomatedUpdateDate"):
        detail += f"; AWS will force the update at {software['AutomatedUpdateDate']}"
    return [
        Finding(
            rule="service-software-update-available",
            severity="warn",
            title="service software update is pending",
            detail=detail,
            fix="run start-service-software-update inside a maintenance window you chose",
        )
    ]


def rule_engine_eol(domain: dict[str, Any], opts: Options) -> list[Finding]:
    version = engine_version(domain)
    if not is_eol_engine(version, opts.eol_versions):
        return []
    return [
        Finding(
            rule="engine-version-eol",
            severity="warn",
            title=f"engine {version} is past end of support",
            detail="no security patches and no upgrade path once the version is removed",
            fix="upgrade in place to a supported OpenSearch 2.x release",
        )
    ]


RULES: tuple[Callable[[dict[str, Any], Options], list[Finding]], ...] = (
    rule_dedicated_master,
    rule_zone_awareness,
    rule_single_node,
    rule_encryption_at_rest,
    rule_node_to_node,
    rule_enforce_https,
    rule_tls_policy,
    rule_access_policy,
    rule_fine_grained_access,
    rule_internal_user_database,
    rule_automated_snapshots,
    rule_software_update,
    rule_engine_eol,
)


def audit_domain(domain: dict[str, Any], opts: Options | None = None) -> dict[str, Any]:
    """Run every rule against one domain and return a result dict."""
    opts = opts or Options()
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(domain, opts))
    cluster = domain.get("ClusterConfig") or {}
    return {
        "name": domain_name(domain),
        "arn": domain.get("ARN"),
        "engine": engine_version(domain),
        "placement": "vpc" if is_vpc_domain(domain) else "public",
        "instance_type": cluster.get("InstanceType"),
        "instance_count": cluster.get("InstanceCount"),
        "severity": worst([f.severity for f in findings]),
        "findings": [f.as_dict() for f in findings],
    }


def audit(payload: dict[str, Any], opts: Options | None = None) -> dict[str, Any]:
    """Audit a whole collected payload: ``{"region": ..., "domains": [...]}``."""
    domains = payload.get("domains") or []
    results = [audit_domain(d, opts) for d in domains]
    results.sort(key=lambda r: (-SEVERITY_RANK.get(r["severity"], 0), r["name"]))
    counts = {name: 0 for name in SEVERITIES}
    for result in results:
        counts[result["severity"]] = counts.get(result["severity"], 0) + 1
    return {
        "region": payload.get("region"),
        "summary": {
            "domains": len(results),
            "findings": sum(len(r["findings"]) for r in results),
            **{f"{name}_domains": counts[name] for name in SEVERITIES},
        },
        "severity": worst([r["severity"] for r in results]),
        "domains": results,
    }
