"""Safety-category smoke test.

The real SSRF/scope/redaction suites come later (PLAN §19.3), but the
directory must exist and run from day one: safety tests are the one
category that may never be silently dropped from CI.
"""

import pytest


@pytest.mark.safety
def test_safety_suite_is_wired_into_ci():
    assert True
