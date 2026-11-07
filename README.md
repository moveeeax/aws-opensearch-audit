# aws-opensearch-audit

[![ci](https://github.com/moveeeax/aws-opensearch-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-opensearch-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A healthy OpenSearch domain and a fragile one look identical in the console. This reads
`describe_domains` and tells you which one you have: no dedicated masters, everything in one
availability zone, encryption missing, HTTPS not enforced, an access policy with a wildcard
principal, an engine past end of support. One line per finding, with the fix, and a non-zero
exit code for CI.

## Install

```shell
pip install git+https://github.com/moveeeax/aws-opensearch-audit
```

Needs Python 3.11+ and `boto3` for live runs. Replaying a saved payload with `--from-json`
needs neither credentials nor `boto3`.

## Usage

```shell
aws-opensearch-audit --region eu-central-1
aws-opensearch-audit --domain search-prod --fail-on critical
aws-opensearch-audit --format json | jq '.domains[] | select(.severity=="critical")'
aws-opensearch-audit --from-json examples/prod.json --format markdown
```

Real output against the bundled example payload:

```
$ aws-opensearch-audit --from-json examples/prod.json
eu-central-1: 5 domain(s), 1 critical, 3 warn, 1 clean

[CRIT] search-legacy (Elasticsearch_7.10, public, m5.large.elasticsearch x2)
    WARN  no dedicated master nodes  [dedicated-master-disabled]
          why: 2 data node(s) are also holding cluster state; losing one takes the cluster's view of itself with it
          fix: set DedicatedMasterEnabled with DedicatedMasterCount 3 (update-domain-config, rolling change)
    CRIT  encryption at rest is disabled  [encryption-at-rest-disabled]
          why: index data and automated snapshots are stored unencrypted; this cannot be changed in place
          fix: create a new domain with EncryptionAtRestOptions enabled and reindex or restore into it -- there is no update-domain-config path
    CRIT  HTTPS is not enforced on the endpoint  [enforce-https-disabled]
          why: the domain still answers on plain HTTP, including for basic-auth requests
          fix: set DomainEndpointOptions.EnforceHTTPS to true
    CRIT  OpenToTheWorld allows a wildcard principal  [access-policy-wildcard]
          why: Allow for Principal * on es:* with no aws:SourceIp or aws:PrincipalArn condition; the domain has a public endpoint, so this is reachable from the internet
          fix: replace Principal * with the roles that need access, or add an aws:SourceIp condition for the networks that do
    ...

[ok] search-prod (OpenSearch_2.17, vpc, r6g.large.search x3)
    nothing to report
$ echo $?
1
```

### Flags

| flag | what it does |
| --- | --- |
| `--region REGION` | region to audit; defaults to the boto3 session region |
| `--domain NAME` | audit only this domain, repeatable |
| `--from-json PATH` | replay a saved payload, no AWS calls |
| `--save-json PATH` | write the collected payload for later replay |
| `--format text\|json\|markdown` | output format, default `text` |
| `--fail-on warn\|critical\|none` | lowest severity that makes the exit code 1, default `critical` |
| `--eol VERSIONS` | extra engine versions to treat as end of support |

Exit codes: `0` clean or below the threshold, `1` findings at or above `--fail-on`, `2` the tool
could not run (bad `--from-json`, failed AWS call). A malformed payload is a message on stderr,
never a traceback.

## How it works

Three pieces that do not know about each other:

- `collect.py` is the only module that imports `boto3`. It calls `list_domain_names` and then
  `describe_domains` in batches of five (the API limit), and returns plain dicts.
- `rules.py` takes one `DomainStatus` dict and returns findings. Every rule is a function of the
  dict and an `Options` struct, so each one is tested from a JSON fixture with no AWS and no moto.
- `policy.py` does the access-policy reasoning: flatten `Principal`, decide whether it is a
  wildcard, decide whether a `Condition` key actually narrows it.

That split is why `--from-json` exists for free: a saved payload goes through the same rule
engine as a live run.

### Rules

**Resilience**

| rule | severity | fires when |
| --- | --- | --- |
| `dedicated-master-disabled` | warn | `DedicatedMasterEnabled` is false |
| `dedicated-master-quorum` | warn | dedicated masters exist but there are fewer than 3 |
| `zone-awareness-disabled` | warn | zone awareness off with more than one data node |
| `single-availability-zone` | warn | zone awareness on, `AvailabilityZoneCount` 1 |
| `single-node-domain` | warn | one data node, so no shard can have a replica |

**Encryption and transport**

| rule | severity | fires when |
| --- | --- | --- |
| `encryption-at-rest-disabled` | critical | `EncryptionAtRestOptions` off (creation-time only) |
| `enforce-https-disabled` | critical | `DomainEndpointOptions.EnforceHTTPS` false |
| `node-to-node-encryption-disabled` | warn | `NodeToNodeEncryptionOptions` off |
| `tls-policy-stale` | warn | TLS policy below the `Policy-Min-TLS-1-2` baseline |

**Access**

| rule | severity | fires when |
| --- | --- | --- |
| `access-policy-wildcard` | critical on a public domain, warn in a VPC | an Allow statement with `Principal: *` and no `aws:SourceIp` / `aws:PrincipalArn` / org condition |
| `access-policy-unparseable` | warn | the policy document is not valid JSON |
| `fine-grained-access-disabled` | warn | `AdvancedSecurityOptions` off |
| `internal-user-db-without-https` | warn | internal user database on while HTTPS is not enforced |

**Lifecycle**

| rule | severity | fires when |
| --- | --- | --- |
| `service-software-update-available` | warn | `ServiceSoftwareOptions.UpdateAvailable` |
| `engine-version-eol` | warn | OpenSearch 1.x, Elasticsearch 7.9 or older, or anything in `--eol` |
| `automated-snapshot-missing` | warn | Elasticsearch older than 5.3 with no `AutomatedSnapshotStartHour` |

Two deliberate omissions. `tls-policy-stale` stays quiet while `enforce-https-disabled` is firing,
because two findings about the same broken endpoint is noise and the order of the fix is not in
doubt. `automated-snapshot-missing` only applies to pre-5.3 Elasticsearch: every version after that
gets managed hourly snapshots, so an empty `SnapshotOptions` on a modern domain is normal and
flagging it would be a false positive on every single domain.

## Development

```shell
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check .
```

`tests/fixtures/` holds the payloads: a clean VPC domain, the same domain wide open on a public
endpoint, master-count and AZ variants, a pre-5.3 Elasticsearch domain, a policy that does not
parse, and several malformed payloads for the exit-code-2 path.

## License

MIT
