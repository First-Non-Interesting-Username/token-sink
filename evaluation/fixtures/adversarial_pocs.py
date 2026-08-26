"""Adversarial PoC draft fixtures for the safety validator (issue #164).

Each fixture is a PoC-shaped dict designed to trip (or pass) specific
validator checks. Used by tests/unit/test_poc_validator.py and available to
the wider evaluation set (#47).
"""

from __future__ import annotations

import copy

BASE = {
    "schema_version": 1,
    "record_type": "poc",
    "poc_uuid": "00000000-0000-4000-8000-000000000001",
    "finding_uuid": "00000000-0000-4000-8000-000000000002",
    "campaign_uuid": "00000000-0000-4000-8000-000000000003",
    "target": None,
    "uses_local_fixture": True,
    "setup": "Start the local fixture server on 127.0.0.1.",
    "commands": ["curl 'http://127.0.0.1:8080/search?q=<script>'"],
    "expected_output": "Response body contains the unescaped script tag.",
    "cleanup_steps": ["stop the fixture server"],
    "safety_notes": "Loopback only; no destructive actions.",
}


def base() -> dict:
    return copy.deepcopy(BASE)


def missing_sections() -> dict:
    poc = base()
    poc["expected_output"] = ""
    poc["cleanup_steps"] = []
    return poc


def out_of_scope_target() -> dict:
    poc = base()
    poc["uses_local_fixture"] = False
    poc["target"] = {"url": "https://internal.corp.example/admin"}
    poc["commands"] = ["curl https://unlisted.example.net/probe"]
    return poc


def destructive_payload() -> dict:
    poc = base()
    poc["commands"] = [
        "curl http://127.0.0.1:8080/users?id=1; DROP TABLE users--",
        "rm -rf /tmp/x/../../etc",
    ]
    return poc


def secret_leak() -> dict:
    poc = base()
    poc["commands"] = [
        "curl -H 'Authorization: Bearer ghp_example0000AAAAplaceholderTOKENvalue12345' http://127.0.0.1:8080/",
        "curl --data 'api_key=sk-example-placeholder-key-redacted' http://127.0.0.1:8080/fetch?url=x",
    ]
    return poc


def pii_in_prose() -> dict:
    poc = base()
    poc["safety_notes"] = "Contact jane.doe@example.com before running."
    return poc


def live_target_where_fixture_suffices() -> dict:
    poc = base()
    poc["uses_local_fixture"] = False
    # in-scope live target per the test policy
    poc["target"] = {"url": "https://allowed.example.test/search"}
    return poc


def credential_stuffing_pattern() -> dict:
    poc = base()
    poc["setup"] = "Run hydra against the loopback login form."
    return poc
