# MAVR documentation

> **Authorized security testing only.** MAVR is a tool for conducting
> security testing against systems you are explicitly authorized to
> test. It has no default target.

## Where to start

* [architecture.md](architecture.md) — high-level tour of the code base
* [installation.md](installation.md) — supported install paths on Linux
* [quickstart.md](quickstart.md) — your first end-to-end run
* [configuration.md](configuration.md) — every config knob explained
* [scope-policy.md](scope-policy.md) — how to write a scope policy
* [providers.md](providers.md) — provider / model / API-key setup
* [troubleshooting.md](troubleshooting.md) — common errors and fixes
* [threat-model.md](threat-model.md) — the adversary we defend against
* [safety-guarantees.md](safety-guarantees.md) — the enforced
  invariants
* [faq.md](faq.md) — frequently asked questions

## Reading order

If this is your first time using MAVR, read the pages in this
order:

1. **architecture.md** — so the package layout makes sense.
2. **installation.md** — so you have a working binary.
3. **quickstart.md** — so you can run a campaign end-to-end.
4. **scope-policy.md** — so you know what you are authorizing.
5. **configuration.md** — so you can tune the defaults.
6. **threat-model.md** — so you know what is and isn't defended.
7. **safety-guarantees.md** — so you can verify the guarantees on
   your install.
8. **troubleshooting.md** — for when things go wrong.
9. **faq.md** — for the questions that didn't fit elsewhere.

## Index of source documentation

The source code itself is heavily documented. The doc strings are
the source of truth for behavior; the pages above are the
human-readable narrative.

Key docstring locations:

* `mavr/policy/engine.py` — the scope policy engine
* `mavr/orchestrator/queue.py` — the task queue, leases, DAG
* `mavr/orchestrator/runtime.py` — the agent runtime
* `mavr/orchestrator/killswitch.py` — the global kill switch
* `mavr/orchestrator/redaction.py` — secret redaction
* `mavr/routers/pool.py` — the parallel router pool
* `mavr/search/safety.py` — SSRF and path-traversal defenses
* `mavr/findings/workflow.py` — the full review pipeline
* `mavr/observability/bundle.py` — run-bundle export
* `mavr/reports/submission.py` — submission flow

## Contributing

The documentation is part of the release. If you change a
behavior, update the relevant docstring *and* the relevant page
in this directory in the same PR.
