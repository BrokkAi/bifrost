#!/usr/bin/env bash

# Prove every staged Python distribution carries the release version, and that
# the staging directory holds exactly the expected number of client wheels, CLI
# wheels and source distributions.
#
# This was the wheel-verify `run: |` block in release-readiness.yml, where the
# five-target matrices stage 5, 5 and 1. The release gate verifies its single
# Linux/x86 build the same way with 1, 1 and 1 (#3472).
#
# Usage: scripts/public/check-distribution-versions.sh <dist-dir> <version> <client-wheels> <cli-wheels> <sdists>

set -euo pipefail

dist_dir="${1:?usage: check-distribution-versions.sh DIST_DIR VERSION CLIENT_WHEELS CLI_WHEELS SDISTS}"
expected_version="${2:?usage: check-distribution-versions.sh DIST_DIR VERSION CLIENT_WHEELS CLI_WHEELS SDISTS}"
expected_client_wheels="${3:?usage: check-distribution-versions.sh DIST_DIR VERSION CLIENT_WHEELS CLI_WHEELS SDISTS}"
expected_cli_wheels="${4:?usage: check-distribution-versions.sh DIST_DIR VERSION CLIENT_WHEELS CLI_WHEELS SDISTS}"
expected_sdists="${5:?usage: check-distribution-versions.sh DIST_DIR VERSION CLIENT_WHEELS CLI_WHEELS SDISTS}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

shopt -s nullglob
artifacts=("$dist_dir"/*.whl "$dist_dir"/*.tar.gz)
(( ${#artifacts[@]} > 0 )) || die "no wheels or source distributions under $dist_dir"
for artifact in "${artifacts[@]}"; do
  case "$(basename "$artifact")" in
    *-"${expected_version}"-*|*-"${expected_version}".tar.gz) ;;
    *) die "Unexpected distribution version: $artifact" ;;
  esac
done

# The comparison stays inside an `if`: a bare `(( ... ))` that is false ends
# the script under `set -e` before anything is said about why.
require_count() {
  local label=$1 expected=$2
  shift 2
  local actual=$#
  if (( actual != expected )); then
    die "$dist_dir holds $actual $label, expected $expected: $*"
  fi
  echo "  $label: $actual"
}

echo "Distribution versions under $dist_dir:"
require_count "client wheels" "$expected_client_wheels" "$dist_dir"/brokk_bifrost_searchtools-*.whl
require_count "CLI wheels" "$expected_cli_wheels" "$dist_dir"/brokk_bifrost-*.whl
require_count "source distributions" "$expected_sdists" "$dist_dir"/brokk_bifrost_searchtools-*.tar.gz
