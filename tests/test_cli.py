import json

import pytest

from aws_opensearch_audit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_from_json_reproduces_a_full_run_offline(capsys, fixture_path):
    code, out, err = run(capsys, "--from-json", fixture_path("wide_open_public.json"))
    assert err == ""
    assert "search-legacy" in out
    assert "encryption at rest is disabled" in out
    assert "OpenToTheWorld allows a wildcard principal" in out
    assert code == EXIT_FINDINGS


def test_clean_domain_exits_zero(capsys, fixture_path):
    code, out, _ = run(capsys, "--from-json", fixture_path("clean_vpc.json"))
    assert code == EXIT_OK
    assert "nothing to report" in out


def test_fail_on_critical_ignores_warnings(capsys, fixture_path):
    code, out, _ = run(capsys, "--from-json", fixture_path("master_variants.json"), "--fail-on", "critical")
    assert "WARN" in out
    assert code == EXIT_OK


def test_fail_on_warn_catches_warnings(capsys, fixture_path):
    code, _, _ = run(capsys, "--from-json", fixture_path("master_variants.json"), "--fail-on", "warn")
    assert code == EXIT_FINDINGS


def test_fail_on_none_never_fails(capsys, fixture_path):
    code, _, _ = run(capsys, "--from-json", fixture_path("wide_open_public.json"), "--fail-on", "none")
    assert code == EXIT_OK


def test_json_output_is_parseable_and_shaped_for_jq(capsys, fixture_path):
    code, out, _ = run(capsys, "--from-json", fixture_path("wide_open_public.json"), "--format", "json")
    data = json.loads(out)
    assert data["region"] == "eu-central-1"
    assert [d["name"] for d in data["domains"]] == ["search-legacy"]
    critical = [d for d in data["domains"] if d["severity"] == "critical"]
    assert len(critical) == 1
    assert set(critical[0]["findings"][0]) == {"rule", "severity", "title", "detail", "fix"}
    assert code == EXIT_FINDINGS


def test_markdown_output_has_a_table_and_per_domain_sections(capsys, fixture_path):
    _, out, _ = run(capsys, "--from-json", fixture_path("wide_open_public.json"), "--format", "markdown")
    assert "| domain | engine | placement | severity | findings |" in out
    assert "## `search-legacy`" in out


def test_malformed_json_exits_two_with_a_message_not_a_traceback(capsys, fixture_path):
    code, out, err = run(capsys, "--from-json", fixture_path("malformed.json"))
    assert code == EXIT_ERROR
    assert out == ""
    assert "is not valid JSON" in err
    assert "Traceback" not in err


def test_missing_file_exits_two(capsys, fixture_path):
    code, _, err = run(capsys, "--from-json", fixture_path("nope.json"))
    assert code == EXIT_ERROR
    assert "cannot read" in err


def test_payload_without_domains_key_exits_two(capsys, tmp_path):
    path = tmp_path / "x.json"
    path.write_text('{"region": "eu-central-1"}', encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(path))
    assert code == EXIT_ERROR
    assert "no 'domains' key" in err


def test_payload_with_a_non_object_domain_exits_two(capsys, fixture_path):
    code, _, err = run(capsys, "--from-json", fixture_path("not_an_object.json"))
    assert code == EXIT_ERROR
    assert "domains[0] is not an object" in err


def test_a_bare_describe_domains_list_is_accepted(capsys, fixture_path):
    code, out, _ = run(capsys, "--from-json", fixture_path("bare_list.json"))
    assert code == EXIT_OK
    assert "search-prod" in out


def test_domain_filter_narrows_a_replayed_payload(capsys, fixture_path):
    _, out, _ = run(capsys, "--from-json", fixture_path("master_variants.json"), "--domain", "search-single")
    assert "search-single" in out
    assert "search-nomaster" not in out


def test_eol_flag_adds_versions(capsys, fixture_path):
    _, before, _ = run(capsys, "--from-json", fixture_path("wide_open_public.json"))
    assert "past end of support" not in before
    _, after, _ = run(
        capsys, "--from-json", fixture_path("wide_open_public.json"), "--eol", "Elasticsearch_7.10"
    )
    assert "Elasticsearch_7.10 is past end of support" in after


def test_from_json_and_region_are_mutually_exclusive(capsys, fixture_path):
    code, _, err = run(capsys, "--from-json", fixture_path("clean_vpc.json"), "--region", "eu-central-1")
    assert code == EXIT_ERROR
    assert "mutually exclusive" in err


def test_save_json_round_trips(capsys, fixture_path, tmp_path):
    out_path = tmp_path / "saved.json"
    run(capsys, "--from-json", fixture_path("clean_vpc.json"), "--save-json", str(out_path))
    saved = json.loads(out_path.read_text(encoding="utf-8"))
    assert saved["domains"][0]["DomainName"] == "search-prod"
    code, out, _ = run(capsys, "--from-json", str(out_path))
    assert code == EXIT_OK
    assert "search-prod" in out


def test_empty_region_says_so(capsys, fixture_path):
    code, out, _ = run(capsys, "--from-json", fixture_path("empty.json"))
    assert code == EXIT_OK
    assert "No OpenSearch domains found." in out


def test_shipped_example_payload_runs(capsys):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "examples" / "prod.json"
    code, out, _ = run(capsys, "--from-json", str(example), "--format", "json")
    data = json.loads(out)
    assert data["summary"]["domains"] == 5
    assert code == EXIT_FINDINGS


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
