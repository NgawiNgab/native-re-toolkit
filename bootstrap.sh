#!/usr/bin/env bash
# Bootstrap the native-re-toolkit development environment from scratch.
#
#   ./bootstrap.sh            create venv, install deps, run tests
#   ./bootstrap.sh --no-test  skip the test run
#   ./bootstrap.sh --yara     also install optional yara-python
#
# The environment is fully recoverable: this script is idempotent and
# rebuilds everything it needs (.venv, compiled test fixtures).
set -euo pipefail

cd "$(dirname "$0")"

WITH_YARA=0
RUN_TESTS=1
for arg in "$@"; do
    case "$arg" in
        --yara) WITH_YARA=1 ;;
        --no-test) RUN_TESTS=0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

PYTHON="${PYTHON:-python3}"
echo "==> using $($PYTHON --version 2>&1) at $(command -v "$PYTHON")"

if [ ! -d .venv ]; then
    echo "==> creating virtualenv .venv"
    "$PYTHON" -m venv .venv
fi

VPIP=.venv/bin/pip
VPY=.venv/bin/python

echo "==> upgrading pip"
"$VPIP" install -q --upgrade pip

EXTRAS="dev"
if [ "$WITH_YARA" -eq 1 ]; then
    EXTRAS="dev,yara"
fi

echo "==> installing native-re-toolkit[$EXTRAS] (editable)"
"$VPIP" install -q -e ".[$EXTRAS]"

echo "==> toolchain check"
for tool in gcc strip; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "    $tool: $(command -v "$tool")"
    else
        echo "    $tool: MISSING (fixture compilation tests will be skipped)"
    fi
done

if [ "$RUN_TESTS" -eq 1 ]; then
    echo "==> running test suite"
    "$VPY" -m pytest
fi

echo ""
echo "bootstrap complete. Try:"
echo "  .venv/bin/nrt --help"
echo "  .venv/bin/nrt info /bin/ls"
