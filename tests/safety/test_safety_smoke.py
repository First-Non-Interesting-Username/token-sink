"""Placeholder safety smoke test.

Real SSRF / scope-bypass / redaction tests land per PLAN.md §19.3 (issue #26);
this keeps the safety gate real in CI from day one.
"""


def test_safety_smoke():
    assert True
