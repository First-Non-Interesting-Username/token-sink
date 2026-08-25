# MAVR build / install targets
#
# Targets:
#   make install         Editable install with dev extras
#   make install-user    User-site install (no venv)
#   make wheel           Build a wheel into dist/
#   make sdist           Build an sdist into dist/
#   make dist            Build both wheel and sdist
#   make lint            Run ruff
#   make typecheck       Run mypy
#   make test            Run pytest
#   make test-load       Run pytest with the load marker
#   make test-security   Run pytest on the security/ folder
#   make test-fast       Run pytest with -m "not load"
#   make clean           Remove build artifacts
#   make pyinstaller     Build a single-file binary into dist/mavr/

PY ?= python3
PIP ?= $(PY) -m pip
PYTEST ?= $(PY) -m pytest
RUFF ?= $(PY) -m ruff
MYPY ?= $(PY) -m mypy

.PHONY: help install install-user wheel sdist dist lint typecheck \
        test test-load test-security test-fast clean pyinstaller

help:
	@echo "Targets:"
	@echo "  install         - editable install with dev extras"
	@echo "  install-user    - user-site install (no venv)"
	@echo "  wheel           - build a wheel into dist/"
	@echo "  sdist           - build an sdist into dist/"
	@echo "  dist            - build both wheel and sdist"
	@echo "  lint            - run ruff"
	@echo "  typecheck       - run mypy"
	@echo "  test            - run pytest"
	@echo "  test-load       - run pytest with the load marker"
	@echo "  test-security   - run pytest on tests/security/"
	@echo "  test-fast       - run pytest with -m 'not load'"
	@echo "  clean           - remove build artifacts"
	@echo "  pyinstaller     - build a single-file binary into dist/mavr/"

install:
	$(PIP) install -e ".[dev]"

install-user:
	$(PIP) install --user --break-system-packages ".[dev]" || \
		$(PIP) install --user ".[dev]"

wheel:
	$(PY) -m build --wheel

sdist:
	$(PY) -m build --sdist

dist: wheel sdist

lint:
	$(RUFF) check .

typecheck:
	$(MYPY) mavr

test:
	$(PYTEST) -q

test-load:
	$(PYTEST) -m load -q

test-security:
	$(PYTEST) tests/security -q

test-fast:
	$(PYTEST) -m "not load" -q

clean:
	rm -rf build/ dist/ *.egg-info mavr.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true

pyinstaller:
	$(PIP) install pyinstaller
	$(PY) -m PyInstaller --onefile --name mavr mavr/__main__.py
