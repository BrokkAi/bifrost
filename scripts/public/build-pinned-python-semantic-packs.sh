#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIR WORK_DIR" >&2
  exit 2
fi

output_dir=$1
work_dir=$2
input_dir="${work_dir}/semantic-pack-inputs"
typeshed_dir="${work_dir}/typeshed"

mkdir -p "${input_dir}" "${typeshed_dir}"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${input_dir}/typeshed-1620e225476597f34177351ef913dc8390dade30.tar.gz" \
  "https://github.com/python/typeshed/archive/1620e225476597f34177351ef913dc8390dade30.tar.gz"

cd "${input_dir}"
shasum -a 256 --check <<'CHECKSUMS'
e4faf1d0ebbbc22a4932f56af7c3067f21334cd88146bd23deec41d529220626  typeshed-1620e225476597f34177351ef913dc8390dade30.tar.gz
CHECKSUMS
tar -C "${typeshed_dir}" -xzf typeshed-1620e225476597f34177351ef913dc8390dade30.tar.gz
# The pinned artifact is a source set, not one file. Its canonical digest
# covers the stub paths and bytes the specification lists, so `generate`
# verifies the extracted tree itself. The directory name is pinned too, so
# copy the stub root to the name the specification records.
cp -R \
  "${typeshed_dir}/typeshed-1620e225476597f34177351ef913dc8390dade30/stdlib" \
  "${input_dir}/typeshed-stdlib-1620e2254765"

cd - >/dev/null
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  "${output_dir}" \
  semantic-packs/python/typeshed-stdlib-2026.8.31.json \
  "${input_dir}/typeshed-stdlib-1620e2254765"
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  "${output_dir}"
