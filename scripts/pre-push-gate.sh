#!/usr/bin/env bash
# Local pre-push validation gate (#1454).
#
# Composition matches the documented gate in CLAUDE.md "Rust CI Checks":
# fmt, the featureless workspace test suites, and the isolated-target
# all-features workspace clippy. Two structural changes cut the wall clock
# roughly in half versus running the same steps by hand:
#
#   1. cargo-nextest schedules every test binary under one global scheduler
#      (the per-binary serialization of `cargo test` gated each suite's start
#      on the previous suite's slowest test) and enforces the per-test
#      slow-timeout in .config/nextest.toml, so a hung test is named and
#      killed instead of stalling the gate silently.
#   2. The all-features clippy shares nothing with the test target dir (it
#      runs under scripts/with-isolated-cargo-target.sh), so it runs
#      concurrently with the tests instead of after them.
#
# Nextest does not run doctests, so a `cargo test --doc` step remains.
#
# The all-features clippy needs a PyO3-capable interpreter. If PYO3_PYTHON is
# not already set and `uv` is available, the clippy leg runs through
# `uv run --python 3.12 --` per CLAUDE.md; otherwise it uses the ambient
# environment and fails loudly if that environment cannot link PyO3.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

if ! command -v cargo-nextest >/dev/null 2>&1; then
  echo "pre-push-gate: cargo-nextest is not installed (cargo install cargo-nextest --locked)" >&2
  exit 1
fi

# Tests must never download models or spawn semantic indexer threads.
export BIFROST_SEMANTIC_INDEX=off

# Cargo can find a rustup-managed compiler while PATH finds a Homebrew rustdoc.
# Pin both tools to one sysroot so their crate metadata remains compatible.
if [ -z "${RUSTC:-}" ]; then
  export RUSTC="$(command -v rustc)"
fi
rust_sysroot="$("${RUSTC}" --print sysroot)"
export PATH="${rust_sysroot}/bin:${PATH}"
export RUSTC="${rust_sysroot}/bin/rustc"
if [ -z "${RUSTDOC:-}" ]; then
  export RUSTDOC="${rust_sysroot}/bin/rustdoc"
fi
if [ ! -x "${RUSTDOC}" ]; then
  echo "pre-push-gate: matching rustdoc is not executable: ${RUSTDOC}" >&2
  exit 1
fi

gate_started=$(date +%s)
step() { echo "[pre-push-gate +$(( $(date +%s) - gate_started ))s] $*"; }

step "cargo fmt --check"
cargo fmt --check

# The nlp+python build tree is large; warn (do not fail) below the headroom
# CLAUDE.md recommends for all-features builds.
available_kib=$(df -Pk "${repo_root}" | awk 'NR == 2 { print $4 }')
available_gib=$(( ${available_kib:-0} / 1024 / 1024 ))
if [ "${available_gib:-0}" -lt 60 ]; then
  step "WARNING: ${available_gib}GiB free; the isolated all-features clippy build may exhaust disk"
fi

clippy_log="$(mktemp -t pre-push-gate-clippy-XXXXXX.log)"
clippy_cmd=(scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets --all-features -- -D warnings)
if [ -z "${PYO3_PYTHON:-}" ] && command -v uv >/dev/null 2>&1; then
  clippy_cmd=(uv run --python 3.12 -- "${clippy_cmd[@]}")
fi
step "all-features clippy started concurrently (log: ${clippy_log})"
"${clippy_cmd[@]}" >"${clippy_log}" 2>&1 &
clippy_pid=$!

# One scheduler across every featureless test binary in the workspace:
# the facade suites, the crates' lib tests, and the kept-standalone
# process-isolation binaries (each test already runs in its own process
# under nextest, which only strengthens their isolation assumptions).
step "cargo nextest run --workspace"
nextest_status=0
cargo nextest run --workspace || nextest_status=$?

step "cargo test --workspace --doc"
doc_status=0
cargo test --workspace --doc || doc_status=$?

step "waiting for all-features clippy"
clippy_status=0
wait "${clippy_pid}" || clippy_status=$?
if [ "${clippy_status}" -ne 0 ]; then
  echo "--- clippy log tail ---"
  tail -40 "${clippy_log}"
fi

step "done: tests=${nextest_status} doctests=${doc_status} clippy=${clippy_status}"
exit $(( nextest_status != 0 || doc_status != 0 || clippy_status != 0 ? 1 : 0 ))
