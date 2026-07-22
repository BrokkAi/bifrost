#!/usr/bin/env bash

set -euo pipefail

readonly max_crate_bytes="${MAX_CRATE_BYTES:-10000000}"

cargo package --locked --allow-dirty

shopt -s nullglob
archives=(target/package/brokk-bifrost-*.crate)
if (( ${#archives[@]} != 1 )); then
    echo "Expected one packaged crate, found ${#archives[@]}" >&2
    exit 1
fi

readonly archive="${archives[0]}"
actual_bytes=$(wc -c < "$archive")
echo "Packaged crate: ${actual_bytes} bytes (budget: ${max_crate_bytes})"
if (( actual_bytes > max_crate_bytes )); then
    echo "Packaged crate exceeds the temporary vendoring size budget" >&2
    exit 1
fi

readonly package_files="$(mktemp)"
trap 'rm -f "$package_files"' EXIT
tar -tzf "$archive" | sed 's@^[^/]*/@@' > "$package_files"

required_vendor_files=(
    vendor/tree-sitter-scala/LICENSE
    vendor/tree-sitter-scala/BIFROST_PATCH.md
    vendor/tree-sitter-scala/grammar.js
    vendor/tree-sitter-scala/src/parser.c
    vendor/tree-sitter-scala/src/scanner.c
    vendor/tree-sitter-scala/src/tree_sitter/alloc.h
    vendor/tree-sitter-scala/src/tree_sitter/array.h
    vendor/tree-sitter-scala/src/tree_sitter/parser.h
)

for required_file in "${required_vendor_files[@]}"; do
    if ! grep -Fqx "$required_file" "$package_files"; then
        echo "Packaged crate is missing required vendored file: ${required_file}" >&2
        exit 1
    fi
done
