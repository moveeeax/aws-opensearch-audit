import pytest

from aws_opensearch_audit.rules import (
    MIN_MASTER_QUORUM,
    Options,
    audit,
    audit_domain,
    is_eol_engine,
    parse_engine,
    worst,
)


def rules_fired(result):
    return {f["rule"] for f in result["findings"]}


def finding(result, rule):
    matches = [f for f in result["findings"] if f["rule"] == rule]
    assert matches, f"{rule} did not fire; got {sorted(rules_fired(result))}"
    return matches[0]


# --- the clean baseline ----------------------------------------------------


def test_clean_vpc_domain_has_no_findings(one_domain):
    result = audit_domain(one_domain("clean_vpc.json"))
    assert result["findings"] == []
    assert result["severity"] == "ok"
    assert result["placement"] == "vpc"


def test_scoped_public_domain_is_ok(one_domain):
    """Principal * is fine when aws:SourceIp pins it to a known network."""
    result = audit_domain(one_domain("scoped_public.json"))
    assert result["severity"] == "ok"
    assert result["placement"] == "public"


# --- access policy ---------------------------------------------------------


def test_public_wildcard_policy_is_critical_and_names_the_statement(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    hit = finding(result, "access-policy-wildcard")
    assert hit["severity"] == "critical"
    assert "OpenToTheWorld" in hit["title"]
    assert "reachable from the internet" in hit["detail"]
    assert "es:*" in hit["detail"]


def test_the_same_domain_in_a_vpc_with_a_scoped_principal_is_clean_on_access(one_domain):
    result = audit_domain(one_domain("wide_open_fixed.json"))
    assert "access-policy-wildcard" not in rules_fired(result)


def test_wildcard_inside_a_vpc_is_only_a_warning(one_domain):
    domain = one_domain("wide_open_public.json")
    domain["VPCOptions"] = {"VPCId": "vpc-1", "SubnetIds": ["subnet-1"]}
    result = audit_domain(domain)
    assert finding(result, "access-policy-wildcard")["severity"] == "warn"


def test_unparseable_policy_warns_instead_of_crashing(one_domain):
    result = audit_domain(one_domain("broken_policy.json"))
    hit = finding(result, "access-policy-unparseable")
    assert hit["severity"] == "warn"


# --- resilience ------------------------------------------------------------


def test_no_dedicated_master_with_three_data_nodes_is_warn(one_domain):
    result = audit_domain(one_domain("master_variants.json", 0))
    hit = finding(result, "dedicated-master-disabled")
    assert hit["severity"] == "warn"
    assert "3 data node(s)" in hit["detail"]


def test_two_dedicated_masters_warns_and_names_the_quorum(one_domain):
    result = audit_domain(one_domain("master_variants.json", 1))
    hit = finding(result, "dedicated-master-quorum")
    assert hit["severity"] == "warn"
    assert hit["title"] == "dedicated master count is 2"
    assert str(MIN_MASTER_QUORUM) in hit["detail"]
    assert str(MIN_MASTER_QUORUM) in hit["fix"]


def test_three_dedicated_masters_do_not_fire(one_domain):
    assert "dedicated-master-quorum" not in rules_fired(audit_domain(one_domain("clean_vpc.json")))


def test_single_node_domain_reports_both_the_node_count_and_zone_awareness(one_domain):
    result = audit_domain(one_domain("master_variants.json", 2))
    assert "single-node-domain" in rules_fired(result)
    # zone awareness off with one node is not an AZ problem, it is a node problem
    assert "zone-awareness-disabled" not in rules_fired(result)


def test_zone_awareness_off_with_several_nodes_is_warn(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    hit = finding(result, "zone-awareness-disabled")
    assert "2 data nodes" in hit["detail"]


def test_zone_awareness_pinned_to_one_az_is_warn(one_domain):
    result = audit_domain(one_domain("master_variants.json", 3))
    assert finding(result, "single-availability-zone")["severity"] == "warn"


# --- encryption and transport ---------------------------------------------


def test_encryption_at_rest_is_critical_and_says_it_cannot_be_changed_in_place(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    hit = finding(result, "encryption-at-rest-disabled")
    assert hit["severity"] == "critical"
    assert "cannot be changed in place" in hit["detail"]
    assert "no update-domain-config path" in hit["fix"]


def test_enforce_https_false_is_critical(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    assert finding(result, "enforce-https-disabled")["severity"] == "critical"


def test_node_to_node_encryption_off_is_warn(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    assert finding(result, "node-to-node-encryption-disabled")["severity"] == "warn"


def test_stale_tls_policy_is_suppressed_while_https_is_not_enforced(one_domain):
    """Two findings about the same broken endpoint is noise; fix HTTPS first."""
    domain = one_domain("wide_open_public.json")
    assert "tls-policy-stale" not in rules_fired(audit_domain(domain))
    domain["DomainEndpointOptions"]["EnforceHTTPS"] = True
    hit = finding(audit_domain(domain), "tls-policy-stale")
    assert "Policy-Min-TLS-1-0-2019-07" in hit["title"]


def test_tls_12_policies_pass(one_domain):
    domain = one_domain("clean_vpc.json")
    for policy in ("Policy-Min-TLS-1-2-2019-07", "Policy-Min-TLS-1-2-PFS-2023-10"):
        domain["DomainEndpointOptions"]["TLSSecurityPolicy"] = policy
        assert "tls-policy-stale" not in rules_fired(audit_domain(domain))


# --- access control --------------------------------------------------------


def test_fine_grained_access_disabled_is_warn(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    assert finding(result, "fine-grained-access-disabled")["severity"] == "warn"


def test_internal_user_db_without_https_is_warn(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    assert finding(result, "internal-user-db-without-https")["severity"] == "warn"


def test_internal_user_db_with_https_does_not_fire(one_domain):
    domain = one_domain("clean_vpc.json")
    domain["AdvancedSecurityOptions"]["InternalUserDatabaseEnabled"] = True
    assert "internal-user-db-without-https" not in rules_fired(audit_domain(domain))


# --- lifecycle -------------------------------------------------------------


def test_pending_service_software_update_is_warn_and_names_the_forced_date(one_domain):
    result = audit_domain(one_domain("wide_open_public.json"))
    hit = finding(result, "service-software-update-available")
    assert "R20250115" in hit["detail"]
    assert "2026-12-01T00:00:00Z" in hit["detail"]


def test_legacy_elasticsearch_without_a_snapshot_hour_is_warn(one_domain):
    result = audit_domain(one_domain("legacy_es.json"))
    hit = finding(result, "automated-snapshot-missing")
    assert "Elasticsearch_5.1" in hit["detail"]


def test_modern_engines_do_not_get_a_snapshot_finding(one_domain):
    """OpenSearch takes managed hourly snapshots; an empty SnapshotOptions is normal."""
    assert "automated-snapshot-missing" not in rules_fired(audit_domain(one_domain("clean_vpc.json")))


def test_legacy_elasticsearch_is_reported_end_of_support(one_domain):
    assert "engine-version-eol" in rules_fired(audit_domain(one_domain("legacy_es.json")))


@pytest.mark.parametrize(
    "version,eol",
    [
        ("OpenSearch_2.17", False),
        ("OpenSearch_1.3", True),
        ("Elasticsearch_7.10", False),
        ("Elasticsearch_7.9", True),
        ("Elasticsearch_6.8", True),
        ("", False),
        ("garbage", False),
    ],
)
def test_default_eol_policy(version, eol):
    assert is_eol_engine(version) is eol


def test_extra_eol_versions_come_from_options(one_domain):
    domain = one_domain("wide_open_public.json")  # Elasticsearch_7.10, supported by default
    assert "engine-version-eol" not in rules_fired(audit_domain(domain))
    opts = Options(eol_versions=("Elasticsearch_7.10",))
    assert "engine-version-eol" in rules_fired(audit_domain(domain, opts))


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("OpenSearch_2.17", ("OpenSearch", (2, 17))),
        ("Elasticsearch_7.10", ("Elasticsearch", (7, 10))),
        ("OpenSearch_2", ("OpenSearch", (2,))),
        ("nounderscore", None),
        ("OpenSearch_x", None),
    ],
)
def test_parse_engine(raw, expected):
    assert parse_engine(raw) == expected


# --- aggregation -----------------------------------------------------------


def test_worst_picks_the_highest_severity():
    assert worst([]) == "ok"
    assert worst(["ok", "warn"]) == "warn"
    assert worst(["warn", "critical", "ok"]) == "critical"


def test_audit_sorts_critical_first_and_counts(payload):
    result = audit(
        {
            "region": "eu-central-1",
            "domains": payload("clean_vpc.json")["domains"]
            + payload("wide_open_public.json")["domains"]
            + payload("master_variants.json")["domains"],
        }
    )
    assert result["domains"][0]["severity"] == "critical"
    assert result["domains"][-1]["severity"] == "ok"
    assert result["severity"] == "critical"
    assert result["summary"]["domains"] == 6
    assert result["summary"]["critical_domains"] == 1
    assert result["summary"]["ok_domains"] == 1
    assert result["summary"]["findings"] == sum(len(d["findings"]) for d in result["domains"])


def test_audit_of_an_empty_region_is_ok(payload):
    result = audit(payload("empty.json"))
    assert result["severity"] == "ok"
    assert result["summary"]["domains"] == 0


def test_a_domain_missing_every_optional_block_still_audits():
    """describe_domains omits blocks on old domains; no rule may raise."""
    result = audit_domain({"DomainName": "bare"})
    assert result["name"] == "bare"
    assert result["severity"] == "critical"
    assert "encryption-at-rest-disabled" in rules_fired(result)
