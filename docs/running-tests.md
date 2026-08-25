# Running tests locally

```
pip install -e '.[dev]'
pip install 'ruff==0.12.*'  # same pinned version as CI (not in .[dev])
pytest            # full suite
pytest tests/safety   # just the safety gate
ruff check .      # lint, same as CI
```
