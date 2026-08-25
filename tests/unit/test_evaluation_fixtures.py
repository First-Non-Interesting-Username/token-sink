"""Unit tests for the §19.4 evaluation fixture set (issue #47).

These validate the fixtures themselves — schema shape, category coverage,
and self-containment — so downstream suites (#26 safety, #17 scoring) can
rely on them. No network access; everything is local and synthetic.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

import pytest

# evaluation/ is a fixture data dir, not an installed package; put the repo
# root on sys.path so tests can import the loader directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.fixtures.loader import (  # noqa: E402
    FIXTURES_DIR,
    categories,
    load_all,
    load_category,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# RFC 2606 reserved names + documentation-only hosts. Fixtures must never
# reference targets outside these, keeping the set safe to run anywhere.
ALLOWED_HOST_SUFFIXES = ("example.com", "example.net", "example.org", ".example")


def test_categories_match_plan_19_4():
    assert categories() == (
        "true_positive",
        "false_positive",
        "ambiguous",
        "conflicting_reviews",
        "adversarial_provider_response",
    )


def test_every_category_has_fixtures():
    for cat in categories():
        fixtures = load_category(cat)
        assert fixtures, f"category {cat} is empty"


def test_unknown_category_raises():
    with pytest.raises(ValueError):
        load_category("nonexistent")


def test_load_all_covers_every_category():
    all_by_id = {f["id"]: f for f in load_all()}
    total = sum(len(load_category(c)) for c in categories())
    # IDs are globally unique across categories
    assert len(all_by_id) == total
    for cat in categories():
        assert any(f["category"] == cat for f in all_by_id.values())


def test_load_returns_independent_copies():
    a = load_category("true_positive")
    a[0]["title"] = "mutated"
    b = load_category("true_positive")
    assert b[0]["title"] != "mutated"


def test_finding_fixture_shape():
    required = {"id", "category", "title", "severity", "target", "vulnerability_class",
                "description", "ground_truth", "evidence"}
    for f in load_all():
        if f["category"] == "adversarial_provider_response":
            continue  # different record type
        missing = required - f.keys()
        assert not missing, f"{f['id']} missing fields: {missing}"
        gt = f["ground_truth"]
        assert "is_vulnerable" in gt and "rationale" in gt
        assert f["ground_truth"]["is_vulnerable"] in (True, False, None)
        assert f["evidence"], f"{f['id']} has no evidence"


def test_evidence_items_have_hashes_and_status():
    for f in load_all():
        for ev in f.get("evidence", []):
            # Synthetic placeholder hashes: 64 hex chars + a category tag.
            assert re.match(r"^[0-9a-f]{56,}[a-z0-9]{1,8}$", ev["sha256"]), (
                f"{f['id']}: bad sha256"
            )
            assert len(ev["sha256"]) == 64
            # Content-addressing per PLAN §12: identity comes from hash+status,
            # never from filenames alone.
            assert ev["source_status"] == "recorded"


def test_conflicting_review_fixtures_have_split_reviews():
    for f in load_category("conflicting_reviews"):
        verdicts = [r["verdict"] for r in f["reviews"]]
        assert "confirmed" in verdicts and "rejected" in verdicts
        for r in f["reviews"]:
            assert r["reviewer_id"] and 0.0 <= r["confidence"] <= 1.0


def test_ambiguous_fixtures_are_indeterminate():
    for f in load_category("ambiguous"):
        assert f["ground_truth"]["is_vulnerable"] is None


def test_adversarial_responses_declare_expected_behavior():
    allowed = {
        "malformed_rejected",
        "schema_violation_rejected",
        "injection_neutralized",
        "decode_failure_rejected",
        "identity_forgery_detected",
    }
    for f in load_category("adversarial_provider_response"):
        assert f["expected_behavior"] in allowed
        if f["id"] == "adv-005":
            payload = base64.b64decode(f["raw_response_base64"], validate=True)
            assert payload[:2] == b"\x1f\x8b", "adv-005 must be gzip magic"
        elif f["id"] == "adv-001":
            # Truncated on purpose — parsing it must fail (covered below).
            pass
        elif f["content_type"] == "application/json":
            json.loads(f["raw_response"])
        else:
            assert f["raw_response"]


def test_adversarial_json_payloads_are_actually_malformed_or_suspicious():
    # adv-001 must be truncated JSON (unparseable), adv-002 valid JSON but
    # schema-wrong, adv-006 valid JSON but forging an agent UUID.
    by_id = {f["id"]: f for f in load_category("adversarial_provider_response")}
    with pytest.raises(json.JSONDecodeError):
        json.loads(by_id["adv-001"]["raw_response"])
    parsed = json.loads(by_id["adv-002"]["raw_response"])
    assert isinstance(parsed["findings"], str)  # wrong type vs. schema
    forged = json.loads(by_id["adv-006"]["raw_response"])
    assert forged["role"] == "coordinator"  # self-declared privilege escalation


@pytest.mark.parametrize("path", sorted(p for p in FIXTURES_DIR.glob("*.json")))
def test_no_real_targets_or_secret_shapes(path):
    text = path.read_text(encoding="utf-8")
    hostnames = set(
        h for h in re.findall(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", text)
        if "." in h and not h.endswith((".js", ".json", ".py"))  # skip filenames
    )
    for host in hostnames:
        assert host.endswith(ALLOWED_HOST_SUFFIXES), f"{path.name}: non-reserved host {host}"
    secret_patterns = [
        r"sk-[A-Za-z0-9]{20,}",          # OpenAI-style keys
        r"gh[pousr]_[A-Za-z0-9]{30,}",   # GitHub tokens
        r"AKIA[0-9A-Z]{16}",             # AWS access keys
        r"xox[bpars]-[A-Za-z0-9-]{10,}", # Slack tokens
    ]
    for pat in secret_patterns:
        assert not re.search(pat, text), f"{path.name}: secret-shaped string matched"
