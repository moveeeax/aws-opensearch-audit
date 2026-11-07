"""Tests for the collector's pure parts.

The live path needs boto3 and credentials, so what is tested here is the
chunking, the payload loader and the error surface -- everything that decides
whether a bad input becomes a message or a traceback.
"""

import pytest

from aws_opensearch_audit.collect import DESCRIBE_BATCH, CollectError, _chunk, load_payload


def test_describe_batch_respects_the_api_limit():
    assert DESCRIBE_BATCH == 5


@pytest.mark.parametrize(
    "count,expected_sizes",
    [(0, []), (1, [1]), (5, [5]), (6, [5, 1]), (12, [5, 5, 2])],
)
def test_chunk_splits_into_api_sized_batches(count, expected_sizes):
    names = [f"d{i}" for i in range(count)]
    chunks = _chunk(names, DESCRIBE_BATCH)
    assert [len(c) for c in chunks] == expected_sizes
    assert [n for c in chunks for n in c] == names


def test_load_payload_reads_a_full_payload(fixture_path):
    data = load_payload(fixture_path("clean_vpc.json"))
    assert data["region"] == "eu-central-1"
    assert data["domains"][0]["DomainName"] == "search-prod"


def test_load_payload_accepts_a_describe_domains_query_result(fixture_path):
    data = load_payload(fixture_path("bare_list.json"))
    assert data["region"] is None
    assert len(data["domains"]) == 1


def test_load_payload_accepts_the_raw_api_key_name(tmp_path):
    path = tmp_path / "raw.json"
    path.write_text('{"DomainStatusList": [{"DomainName": "a"}]}', encoding="utf-8")
    assert load_payload(str(path))["domains"][0]["DomainName"] == "a"


def test_load_payload_rejects_a_scalar_document(tmp_path):
    path = tmp_path / "scalar.json"
    path.write_text("42", encoding="utf-8")
    with pytest.raises(CollectError, match="must contain an object or a list"):
        load_payload(str(path))


def test_load_payload_rejects_a_non_list_domains(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"domains": {"a": 1}}', encoding="utf-8")
    with pytest.raises(CollectError, match="must be a list"):
        load_payload(str(path))


def test_load_payload_rejects_malformed_json(fixture_path):
    with pytest.raises(CollectError, match="not valid JSON"):
        load_payload(fixture_path("malformed.json"))
