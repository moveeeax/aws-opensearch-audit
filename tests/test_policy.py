import json

import pytest

from aws_opensearch_audit.policy import (
    PolicyError,
    is_scoped,
    is_wildcard_principal,
    open_statements,
    parse_policy,
    principal_values,
    statement_label,
)


def test_parse_policy_accepts_string_and_dict():
    doc = {"Version": "2012-10-17", "Statement": []}
    assert parse_policy(json.dumps(doc)) == doc
    assert parse_policy(doc) == doc


@pytest.mark.parametrize("value", [None, "", "   "])
def test_parse_policy_treats_absent_policy_as_none(value):
    assert parse_policy(value) is None


def test_parse_policy_rejects_garbage():
    with pytest.raises(PolicyError):
        parse_policy("{not json")
    with pytest.raises(PolicyError):
        parse_policy("[1, 2, 3]")
    with pytest.raises(PolicyError):
        parse_policy(42)


@pytest.mark.parametrize(
    "principal,expected",
    [
        ("*", ["*"]),
        ({"AWS": "*"}, ["*"]),
        ({"AWS": ["arn:aws:iam::1:role/a", "arn:aws:iam::1:role/b"]}, 2),
        ({"Service": "lambda.amazonaws.com"}, ["lambda.amazonaws.com"]),
        (None, []),
    ],
)
def test_principal_values(principal, expected):
    got = principal_values({"Principal": principal})
    if isinstance(expected, int):
        assert len(got) == expected
    else:
        assert got == expected


@pytest.mark.parametrize(
    "principal,wildcard",
    [
        ("*", True),
        ({"AWS": "*"}, True),
        ({"AWS": "arn:aws:iam::*:root"}, True),
        ({"AWS": "arn:aws:iam::123456789012:role/app"}, False),
        ({"Service": "lambda.amazonaws.com"}, False),
    ],
)
def test_is_wildcard_principal(principal, wildcard):
    assert is_wildcard_principal({"Principal": principal}) is wildcard


@pytest.mark.parametrize(
    "condition,scoped",
    [
        ({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, True),
        ({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::1:role/*"}}, True),
        ({"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}, True),
        ({"StringEquals": {"es:RequestTag/env": "prod"}}, False),
        ({}, False),
        (None, False),
    ],
)
def test_is_scoped(condition, scoped):
    assert is_scoped({"Condition": condition}) is scoped


def test_open_statements_finds_the_wildcard_and_names_it():
    policy = {
        "Statement": [
            {"Sid": "OpenToTheWorld", "Effect": "Allow", "Principal": "*", "Action": "es:*"},
            {
                "Sid": "Scoped",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "es:ESHttpGet",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            },
            {"Sid": "Denied", "Effect": "Deny", "Principal": "*", "Action": "es:*"},
        ]
    }
    found = open_statements(policy)
    assert [label for label, _ in found] == ["OpenToTheWorld"]


def test_open_statements_falls_back_to_an_index_label():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "es:*"}]}
    assert open_statements(policy)[0][0] == "statement #1"
    assert statement_label({"Sid": "  "}, 2) == "statement #3"


def test_open_statements_handles_a_single_statement_object():
    policy = {"Statement": {"Effect": "Allow", "Principal": "*", "Action": "es:*"}}
    assert len(open_statements(policy)) == 1
    assert open_statements(None) == []
