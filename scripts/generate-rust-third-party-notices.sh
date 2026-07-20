#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_PATH" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$1
mkdir -p "$(dirname "$output")"

version=$(sed -nE 's/^version = "([^"]+)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)
if [[ -z "$version" ]]; then
  echo "could not read the package version from Cargo.toml" >&2
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
grep -Fq "brokk-bifrost" "$temporary"
grep -Fq "${version}</a>" "$temporary"

mv "$temporary" "$output"
trap - EXIT
echo "Generated Rust third-party notices for brokk-bifrost ${version} at ${output}"
