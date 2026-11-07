import json

import pytest

from aws_opensearch_audit.report import render, render_json, render_markdown, render_text
from aws_opensearch_audit.rules import audit


@pytest.fixture
def mixed(payload):
    return audit(
        {
            "region": "eu-central-1",
            "domains": payload("clean_vpc.json")["domains"] + payload("wide_open_public.json")["domains"],
        }
    )


def test_text_report_leads_with_the_counts(mixed):
    first = render_text(mixed).splitlines()[0]
    assert first == "eu-central-1: 2 domain(s), 1 critical, 0 warn, 1 clean"


def test_text_report_marks_severity_and_shows_the_fix(mixed):
    out = render_text(mixed)
    assert "[CRIT] search-legacy" in out
    assert "[ok] search-prod" in out
    assert "fix: set DomainEndpointOptions.EnforceHTTPS to true" in out
    assert out.endswith("\n")


def test_text_report_says_so_when_a_domain_is_clean(mixed):
    assert "nothing to report" in render_text(mixed)


def test_json_report_round_trips(mixed):
    assert json.loads(render_json(mixed)) == mixed


def test_markdown_report_has_one_table_row_per_domain(mixed):
    lines = render_markdown(mixed).splitlines()
    rows = [line for line in lines if line.startswith("| `")]
    assert len(rows) == 2
    assert "## `search-legacy`" in lines
    # the clean domain gets no detail section
    assert "## `search-prod`" not in lines


def test_empty_region_renders_in_every_format(payload):
    result = audit(payload("empty.json"))
    for fmt in ("text", "markdown"):
        assert "No OpenSearch domains found." in render(result, fmt)
    assert json.loads(render(result, "json"))["domains"] == []


def test_render_rejects_an_unknown_format(mixed):
    with pytest.raises(ValueError, match="unknown format"):
        render(mixed, "yaml")
