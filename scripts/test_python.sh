#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
uv run --python 3.12 --with maturin python -m unittest discover -s python_tests -p 'test_*.py'
