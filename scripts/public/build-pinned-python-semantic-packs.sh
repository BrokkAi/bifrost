#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 OUTPUT_DIR WORK_DIR [CACHE_ROOT]" >&2
  exit 2
fi

output_dir=$1
work_dir=$2
cache_root=${3:-}
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
# copy the stub root to the name the specification records. Copying the
# contents keeps a repeated run in the same work directory idempotent instead
# of nesting a second `stdlib` directory below the pinned artifact root.
mkdir -p "${input_dir}/typeshed-stdlib-1620e2254765"
cp -R \
  "${typeshed_dir}/typeshed-1620e225476597f34177351ef913dc8390dade30/stdlib/." \
  "${input_dir}/typeshed-stdlib-1620e2254765/"

cd - >/dev/null
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  "${output_dir}" \
  semantic-packs/python/typeshed-stdlib-2026.8.31.json \
  "${input_dir}/typeshed-stdlib-1620e2254765"
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  "${output_dir}"

if [[ -n "${cache_root}" ]]; then
  catalog_version=$(sed -nE \
    's/^pub\(super\) const CURRENT_CATALOG_VERSION: i64 = ([0-9]+);$/\1/p' \
    crates/bifrost-analysis/src/analyzer/semantic_model/catalog/db.rs)
  if [[ ! "${catalog_version}" =~ ^[0-9]+$ ]]; then
    echo "could not derive exactly one numeric semantic-pack catalog version" >&2
    exit 2
  fi
  catalog_directory="semantic-pack-catalog.v${catalog_version}"
  mkdir -p "${cache_root}"
  cargo run --locked --release --features release-tooling \
    -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- install \
    "${output_dir}" "${cache_root}/${catalog_directory}"
  python3 - \
    "${output_dir}" "${cache_root}" "${catalog_version}" "${catalog_directory}" <<'PY'
import json
from pathlib import Path
import sys

output_dir = Path(sys.argv[1]).resolve()
cache_root = Path(sys.argv[2]).resolve()
catalog_version = int(sys.argv[3])
catalog_directory = sys.argv[4]
index = json.loads((output_dir / "index.json").read_text())
packs = index.get("packs", [])
if len(packs) != 1:
    raise SystemExit(f"expected one generated pack in {output_dir}, found {len(packs)}")
pack = packs[0]
receipt = {
    "schema_version": 1,
    "catalog_schema_version": catalog_version,
    "catalog_directory": catalog_directory,
    "pack_id": pack["pack_id"],
    "pack_version": pack["pack_version"],
    "manifest_digest": pack["manifest"]["sha256"],
    "bundle_path": str(output_dir),
}
receipt_path = cache_root / "type-flow-python-pack-activation.json"
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(f"wrote activation receipt {receipt_path}")
PY
fi
