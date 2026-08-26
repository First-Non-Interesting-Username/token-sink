"""Fixtures: ambiguous-impact findings that must resolve consistently (§10.3)."""

AMBIGUOUS_CASES = [
    {
        "name": "reflected-xss-with-session-cookie",
        "description": "Reflected XSS on a low-value page but session cookie lacks HttpOnly.",
        "axes": {
            "confidentiality": 1,
            "integrity": 1,
            "availability": 0,
            "reachability": 2,
            "preconditions": 3,
        },
        "expected_level": "medium",
    },
    {
        "name": "unauthenticated-sql-read",
        "description": "SQL injection reading arbitrary tables, no auth required.",
        "axes": {
            "confidentiality": 3,
            "integrity": 0,
            "availability": 0,
            "reachability": 3,
            "preconditions": 3,
        },
        "expected_level": "high",
    },
    {
        "name": "internal-memcache-exposure",
        "description": "Memcached exposed on an internal segment only; "
        "no auth, cache poisoning possible.",
        "axes": {
            "confidentiality": 1,
            "integrity": 1,
            "availability": 2,
            "reachability": 1,
            "preconditions": 1,
        },
        "expected_level": "medium",
    },
    {
        "name": "verbose-error-disclosure",
        "description": "Stack traces leak framework versions but no secrets.",
        "axes": {
            "confidentiality": 1,
            "integrity": 0,
            "availability": 0,
            "reachability": 0,
            "preconditions": 3,
        },
        "expected_level": "low",
    },
    {
        "name": "rce-via-deserialization",
        "description": "Pre-auth Java deserialization RCE on internet-facing service.",
        "axes": {
            "confidentiality": 3,
            "integrity": 3,
            "availability": 3,
            "reachability": 3,
            "preconditions": 3,
        },
        "expected_level": "critical",
    },
]
