#!/usr/bin/env bash

run_semantic_pack_tool() {
  if [[ -n "${BIFROST_SEMANTIC_PACK_BIN:-}" ]]; then
    [[ -x "${BIFROST_SEMANTIC_PACK_BIN}" ]] || {
      echo "BIFROST_SEMANTIC_PACK_BIN must name an executable file" >&2
      exit 2
    }
    "${BIFROST_SEMANTIC_PACK_BIN}" "$@"
  else
    cargo run --locked --release --features release-tooling \
      -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- "$@"
  fi
}
