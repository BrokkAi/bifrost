#!/usr/bin/env bash

# Prove a qualification bundle holds every artifact a release publishes.
#
# The aggregate qualification job and the metadata-only re-qualification both
# hand a release its bundle, so both must make the same claim about it. They did
# not: re-qualification counted sidecars alone, which a bundle missing every
# wheel would still satisfy.
#
# Usage: scripts/public/check-qualification-inventory.sh <bundle-directory>

set -euo pipefail

bundle="${1:?a bundle directory is required}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/release-crates.sh
source "$script_directory/../lib/release-crates.sh"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

count_matching() {
  find "$bundle" -type f -name "$1" | wc -l | tr -d ' '
}

# The comparison is kept inside an `if`. A bare `(( ... ))` that evaluates false
# returns 1, which under `set -e` ends the script before the result can be
# reported -- failing closed, but with nothing said about why.
require_count() {
  local pattern=$1 comparison=$2 expected=$3 actual satisfied=1
  actual="$(count_matching "$pattern")"
  case "$comparison" in
    exactly) if (( actual == expected )); then satisfied=0; fi ;;
    at-least) if (( actual >= expected )); then satisfied=0; fi ;;
    more-than) if (( actual > expected )); then satisfied=0; fi ;;
    *) die "unknown comparison $comparison" ;;
  esac
  if (( satisfied != 0 )); then
    die "qualification bundle holds $actual $pattern, expected $comparison $expected"
  fi
  echo "  $pattern: $actual"
}

echo "Qualification inventory for $bundle:"
require_count '*.crate' exactly "${#RELEASE_CRATES[@]}"
require_count '*.crate.metadata.json' exactly "${#RELEASE_CRATES[@]}"
require_count '*.whl' exactly 10
require_count '*.vsix' exactly 1
require_count '*.tgz' more-than 0
require_count '*.sha256' at-least 7
[[ -f "$bundle/THIRD_PARTY_LICENSES.html" ]] ||
  die "qualification bundle has no THIRD_PARTY_LICENSES.html"
