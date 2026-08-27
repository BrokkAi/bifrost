#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIR WORK_DIR" >&2
  exit 2
fi

output_dir=$1
work_dir=$2
input_dir="${work_dir}/semantic-pack-inputs"
archive_dir="${input_dir}/rust-docs-json-nightly-x86_64-unknown-linux-gnu"
source_dir="${input_dir}/rust-docs-json-nightly-2026-08-24"
archive_path="${input_dir}/rust-docs-json-nightly-x86_64-unknown-linux-gnu.tar.xz"
archive_url="https://static.rust-lang.org/dist/2026-08-24/rust-docs-json-nightly-x86_64-unknown-linux-gnu.tar.xz"

mkdir -p "${input_dir}"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${archive_path}" "${archive_url}"

cd "${input_dir}"
shasum -a 256 --check <<'CHECKSUMS'
0b18d55b97cee6756745744c0c169402ab6d3d506bb30267067b2438b3b5e000  rust-docs-json-nightly-x86_64-unknown-linux-gnu.tar.xz
CHECKSUMS
tar -xJf "${archive_path}"

mkdir -p "${source_dir}"
for crate in core alloc std; do
  cp "${archive_dir}/rust-docs-json-preview/share/doc/rust/json/${crate}.json" \
    "${source_dir}/${crate}.json"
done

cd - >/dev/null
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  "${output_dir}" \
  semantic-packs/rust/rust-stdlib-nightly-2026-08-24.json "${source_dir}"
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  "${output_dir}"
