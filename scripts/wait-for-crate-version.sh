#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 CRATE VERSION SHA256" >&2
  exit 2
fi

readonly crate=$1
readonly version=$2
readonly expected_checksum=$3
readonly endpoint="https://crates.io/api/v1/crates/${crate}/${version}"

for attempt in {1..10}; do
  response=$(curl --fail --silent --show-error "$endpoint" 2>/dev/null || true)
  checksum=$(jq -r '.version.checksum // empty' <<<"$response")
  if [[ -n "$checksum" ]]; then
    if [[ "$checksum" != "$expected_checksum" ]]; then
      echo "Registry checksum mismatch for ${crate} ${version}: expected ${expected_checksum}, got ${checksum}" >&2
      exit 1
    fi
    echo "Registry exposes ${crate} ${version} with checksum ${checksum}"
    exit 0
  fi

  if (( attempt < 10 )); then
    delay=$((attempt < 5 ? attempt * 2 : 10))
    echo "Waiting ${delay}s for crates.io to expose ${crate} ${version} (attempt ${attempt}/10)"
    sleep "$delay"
  fi
done

echo "crates.io did not expose ${crate} ${version} within the bounded retry window" >&2
exit 1
