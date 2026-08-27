#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIR WORK_DIR" >&2
  exit 2
fi

output_dir=$1
work_dir=$2
input_dir="${work_dir}/semantic-pack-inputs"
compiler_archive="${input_dir}/typescript-7.0.2.tgz"
library_archive="${input_dir}/typescript-linux-x64-7.0.2.tgz"
compiler_root="${input_dir}/typescript-7.0.2-package"
library_root="${input_dir}/typescript-linux-x64-7.0.2-package"
source_dir="${input_dir}/typescript-7.0.2"

mkdir -p "${input_dir}"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${compiler_archive}" \
  "https://registry.npmjs.org/typescript/-/typescript-7.0.2.tgz"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${library_archive}" \
  "https://registry.npmjs.org/@typescript/typescript-linux-x64/-/typescript-linux-x64-7.0.2.tgz"

cd "${input_dir}"
shasum -a 256 --check <<'CHECKSUMS'
da2513f4b95176d6dde8b51aab7afe8a927656c9d277369793f77f7e59371c08  typescript-7.0.2.tgz
7ecad6f67377e831856367ab062ef394f21506a611405bf8ac0ff039348637d3  typescript-linux-x64-7.0.2.tgz
CHECKSUMS
rm -rf "${compiler_root}" "${library_root}" "${source_dir}"
mkdir -p "${compiler_root}" "${library_root}" "${source_dir}/lib"
tar -C "${compiler_root}" -xzf "${compiler_archive}"
tar -C "${library_root}" -xzf "${library_archive}"
cp "${compiler_root}/package/package.json" "${source_dir}/package.json"
find "${library_root}/package/lib" -type f -name '*.d.ts' \
  -exec cp '{}' "${source_dir}/lib/" \;

cd - >/dev/null
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  "${output_dir}" \
  semantic-packs/typescript/typescript-7.0.2.json "${source_dir}"
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  "${output_dir}"
