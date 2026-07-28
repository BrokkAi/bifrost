#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

cargo_target="${CARGO_TARGET_DIR:-${repo_root}/target}"
if [[ "${cargo_target}" != /* ]]; then
  cargo_target="${repo_root}/${cargo_target}"
fi

cargo build --release --locked --bin bifrost --bin bifrost_benchmark
"${cargo_target}/release/bifrost_benchmark" validate \
  --manifest benchmark/interactive-latency.toml
BIFROST_BENCHMARK_BIFROST_BIN="${cargo_target}/release/bifrost" \
  "${cargo_target}/release/bifrost_benchmark" run \
    --manifest benchmark/interactive-latency.toml \
    --output interactive-latency-output \
    "$@"
