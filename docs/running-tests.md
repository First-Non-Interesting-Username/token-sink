# Running tests locally

```
pip install -e '.[dev]'
pytest            # full suite
pytest tests/safety   # just the safety gate
ruff check .      # lint, same as CI
```
