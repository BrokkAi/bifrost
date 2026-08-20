#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_PATH" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output=$1
mkdir -p "$(dirname "$output")"

version=$(cd "$repo_root" && node scripts/public/release-version.mjs print)
if [[ -z "$version" ]]; then
  echo "could not read the workspace package version from Cargo.toml" >&2
  exit 1
fi

temporary=$(mktemp "${output}.tmp.XXXXXX")
trap 'rm -f "$temporary"' EXIT

cd "$repo_root"
cargo about generate \
  --offline \
  --config licenses/about.toml \
  --features python \
  --locked \
  --fail \
  licenses/about.hbs \
  -o "$temporary"

test -s "$temporary"
if grep -Fq "brokk-bifrost" "$temporary"; then
  echo "generated third-party notices contain first-party workspace packages" >&2
  exit 1
fi
grep -Fq "serde" "$temporary"

mv "$temporary" "$output"
trap - EXIT
echo "Generated Rust third-party notices for the Bifrost ${version} release graph at ${output}"
