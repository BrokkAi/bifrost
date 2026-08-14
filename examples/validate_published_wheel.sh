#!/usr/bin/env bash
#
# Validate the *published* brokk-bifrost-searchtools wheel end to end.
#
# Why this exists: inside this checkout, `import bifrost_searchtools` resolves to
# the local source tree and the locally built .so, so running the demo from here
# proves nothing about PyPI. This script:
#
#   1. generates a tiny, deterministic sample project to analyze,
#   2. builds a clean, throwaway venv,
#   3. installs the wheel straight from PyPI -- binary only, so it fails loudly
#      if no wheel matches this platform instead of silently compiling the sdist,
#   4. asserts the imported package really came from the venv (not this checkout),
#   5. runs the example app against the sample project.
#
# PASS means the published wheel loads its native extension and answers queries
# on this OS/arch. The version it validates is read from pyproject.toml -- i.e.
# the version you just published.
#
# Usage:
#   examples/validate_published_wheel.sh
#   BIFROST_VALIDATE_PYTHON=3.13 examples/validate_published_wheel.sh   # pin another interpreter
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$REPO_ROOT/examples/searchtools_demo.py"

# Validate the version you just published: read it from pyproject.toml the same
# way the publish workflow's verify-version step does.
PKG_VERSION="$(grep -m1 '^version' "$REPO_ROOT/pyproject.toml" | sed -E 's/version *= *"([^"]+)"/\1/')"
PKG="brokk-bifrost-searchtools==${PKG_VERSION}"
# The wheels are cp312-abi3, so 3.12 is the faithful target; abi3 also runs on
# newer interpreters if you override this.
PY_VERSION="${BIFROST_VALIDATE_PYTHON:-3.12}"

echo "==> Validating published wheel: $PKG  (python $PY_VERSION, $(uname -s)/$(uname -m))"

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

VENV="$WORKDIR/venv"
FIXTURE="$WORKDIR/sample_project"

# 1. Generate a tiny sample codebase so the native analyzer has real symbols.
mkdir -p "$FIXTURE"
cat > "$FIXTURE/calculator.py" <<'PY'
"""A tiny module so the native analyzer has real symbols to find."""


class Calculator:
    """Accumulates a running total."""

    def __init__(self) -> None:
        self.total = 0

    def add(self, value: int) -> int:
        self.total += value
        return self.total

    def multiply(self, factor: int) -> int:
        self.total *= factor
        return self.total


def compute(values: list[int]) -> int:
    calc = Calculator()
    for value in values:
        calc.add(value)
    return calc.total
PY

cat > "$FIXTURE/main.py" <<'PY'
from calculator import Calculator, compute


def run() -> int:
    return compute([1, 2, 3])
PY

# 2 + 3. Clean venv, install the wheel from PyPI (binary only). Prefer uv (the
# repo already uses it; it can fetch a managed CPython); fall back to stdlib venv.
if command -v uv >/dev/null 2>&1; then
  uv venv --python "$PY_VERSION" "$VENV"
  VENV_PY="$VENV/bin/python"
  uv pip install --python "$VENV_PY" --only-binary=:all: "$PKG"
else
  echo "    uv not found; falling back to 'python3 -m venv' (needs python >= 3.12 on PATH)"
  python3 -m venv "$VENV"
  VENV_PY="$VENV/bin/python"
  "$VENV_PY" -m pip install --quiet --upgrade pip
  "$VENV_PY" -m pip install --only-binary=:all: "$PKG"
fi

# 4. Assert the install actually provides the package + native module, and that
#    they live in the venv -- not this repo checkout. Run from the temp dir: a
#    `python -` script puts the cwd on sys.path, and the repo's ./bifrost_searchtools
#    would otherwise shadow the installed wheel (which is exactly what we're guarding against).
echo "==> Checking installed package origin"
( cd "$WORKDIR" && "$VENV_PY" - "$REPO_ROOT" ) <<'PY'
import sys

import bifrost_searchtools
from bifrost_searchtools import _native

repo_root = sys.argv[1]
pkg = bifrost_searchtools.__file__ or ""
nat = _native.__file__ or ""
print("  package:", pkg)
print("  native :", nat)
assert "site-packages" in pkg, f"package did not load from the venv: {pkg}"
assert repo_root not in pkg, f"package loaded from the repo checkout, not the wheel: {pkg}"
assert nat.endswith((".so", ".pyd", ".dylib")), f"native extension missing/odd: {nat}"
print("  OK: loaded from the installed wheel, native extension present")
PY

# 5. Run the example app against the sample project, from the temp dir so the
#    repo's ./bifrost_searchtools can never shadow the installed package.
echo "==> Running example app against the sample project"
( cd "$WORKDIR" && BIFROST_SEMANTIC_INDEX=off "$VENV_PY" "$DEMO" --root "$FIXTURE" Calculator compute )

echo
echo "PASS: published wheel $PKG works on $(uname -s)/$(uname -m)."
