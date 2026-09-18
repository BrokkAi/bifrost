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
require_count '*.tgz' at-least 2
require_count '*.sha256' at-least 7
require_count 'bifrost-semantic-pack' exactly 0
require_count 'bifrost-semantic-pack.sha256' exactly 0
require_count 'bifrost-semantic-pack-v*-x86_64-unknown-linux-gnu.tar.gz' exactly 1
require_count 'bifrost-semantic-pack-v*-x86_64-unknown-linux-gnu.tar.gz.sha256' exactly 1

installer_name="$(basename -- "$(find "$bundle" -type f -name 'bifrost-semantic-pack-v*-x86_64-unknown-linux-gnu.tar.gz' -print -quit)")"
release_tag="${installer_name#bifrost-semantic-pack-}"
release_tag="${release_tag%-x86_64-unknown-linux-gnu.tar.gz}"
case "$release_tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "qualification bundle has a non-release-tag semantic-pack installer: $installer_name" ;;
esac

installer_checksum="$(sha256sum "$bundle/$installer_name" | awk '{print $1}')"
sidecar_name="$installer_name.sha256"
sidecar_digest="$(awk 'NR == 1 { print $1; exit }' "$bundle/$sidecar_name")"
sidecar_record_name="$(awk 'NR == 1 { print $2; exit }' "$bundle/$sidecar_name")"
sidecar_record_name="${sidecar_record_name#\*}"
if [[ ! "$sidecar_digest" =~ ^[0-9a-f]{64}$ ]] ||
  [[ "$sidecar_record_name" != "$installer_name" ]] ||
  [[ "$sidecar_digest" != "$installer_checksum" ]]; then
  die "qualification bundle has an invalid semantic-pack installer checksum sidecar: $sidecar_name"
fi

echo "  semantic-pack installer: $installer_name"
echo "  semantic-pack installer checksum: verified"
[[ -f "$bundle/THIRD_PARTY_LICENSES.html" ]] ||
  die "qualification bundle has no THIRD_PARTY_LICENSES.html"
