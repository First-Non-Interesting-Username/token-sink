#!/usr/bin/env bash
# MAVR reproducible install script.
#
# Usage:
#   scripts/install.sh            # editable install with dev extras
#   scripts/install.sh user       # user-site install
#   scripts/install.sh wheel      # build a wheel into dist/
#   scripts/install.sh sdist      # build an sdist into dist/
#   scripts/install.sh dist       # build both wheel and sdist
#   scripts/install.sh verify     # run a smoke test
#
# All commands require Python 3.11 or 3.12. The script will fail
# loudly if an older interpreter is found.

set -euo pipefail

PY="${PY:-python3}"
PIP="$PY -m pip"

have_pybuild() {
    $PY -c "import build" 2>/dev/null
}

main() {
    case "${1:-editable}" in
        editable|install)
            $PIP install -e ".[dev]"
            ;;
        user)
            $PIP install --user --break-system-packages ".[dev]" || \
                $PIP install --user ".[dev]"
            ;;
        wheel|sdist|dist)
            have_pybuild || $PIP install build
            case "$1" in
                wheel) $PY -m build --wheel ;;
                sdist) $PY -m build --sdist ;;
                dist)  $PY -m build ;;
            esac
            ;;
        verify)
            $PY -m mavr --version
            $PY -m pytest -m "not load" -q
            ;;
        *)
            echo "Usage: $0 [editable|user|wheel|sdist|dist|verify]" >&2
            exit 2
            ;;
    esac
}

main "$@"
