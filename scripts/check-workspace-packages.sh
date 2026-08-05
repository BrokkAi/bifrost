#!/usr/bin/env bash

set -euo pipefail

readonly packages=(
  brokk-bifrost-core
  brokk-bifrost-go
  brokk-bifrost-python
  brokk-bifrost-rust
  brokk-bifrost-analysis
  brokk-bifrost-nlp
  brokk-bifrost-policy
  brokk-bifrost-semantic-packs
  brokk-bifrost-runtime
  brokk-bifrost-mcp
  brokk-bifrost-lsp
  brokk-bifrost
)
readonly max_crate_bytes="${MAX_CRATE_BYTES:-10000000}"
readonly repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly temporary=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-package-set.XXXXXX")
trap 'rm -rf "$temporary"' EXIT INT TERM

readonly package_target="$temporary/target"
mkdir -p "$package_target/package"
cd "$repo_root"

# Stable Cargo requires registry-resolvable versions even with --no-verify.
# These command-local patches make the not-yet-published implementation set
# resolvable while leaving each normalized archive manifest registry-ready.
readonly cargo_patch_args=(
  --config 'patch.crates-io.brokk-bifrost-core.path="crates/bifrost-core"'
  --config 'patch.crates-io.brokk-bifrost-go.path="crates/bifrost-go"'
  --config 'patch.crates-io.brokk-bifrost-python.path="crates/bifrost-python"'
  --config 'patch.crates-io.brokk-bifrost-rust.path="crates/bifrost-rust"'
  --config 'patch.crates-io.brokk-bifrost-analysis.path="crates/bifrost-analysis"'
  --config 'patch.crates-io.brokk-bifrost-nlp.path="crates/bifrost-nlp"'
  --config 'patch.crates-io.brokk-bifrost-policy.path="crates/bifrost-policy"'
  --config 'patch.crates-io.brokk-bifrost-semantic-packs.path="crates/bifrost-semantic-packs"'
  --config 'patch.crates-io.brokk-bifrost-runtime.path="crates/bifrost-runtime"'
  --config 'patch.crates-io.brokk-bifrost-mcp.path="crates/bifrost-mcp"'
  --config 'patch.crates-io.brokk-bifrost-lsp.path="crates/bifrost-lsp"'
)

for package in "${packages[@]}"; do
  CARGO_TARGET_DIR="$package_target" cargo package \
    --quiet \
    --locked \
    --allow-dirty \
    --no-verify \
    --package "$package" \
    --manifest-path "$repo_root/Cargo.toml" \
    "${cargo_patch_args[@]}"
done

shopt -s nullglob
archives=("$package_target"/package/*.crate)
if (( ${#archives[@]} != ${#packages[@]} )); then
  echo "Expected ${#packages[@]} packaged crates, found ${#archives[@]}" >&2
  exit 1
fi

version=$(cd "$repo_root" && node scripts/release-version.mjs print)
readonly version

archive_for() {
  local package=$1
  local archive="$package_target/package/${package}-${version}.crate"
  if [[ ! -f "$archive" ]]; then
    echo "Missing package archive: $archive" >&2
    exit 1
  fi
  printf '%s\n' "$archive"
}

require_archive_file() {
  local package=$1
  local relative_path=$2
  local archive
  local package_files
  archive=$(archive_for "$package")
  package_files=$(tar -tzf "$archive" | sed 's@^[^/]*/@@')
  if ! grep -Fqx "$relative_path" <<<"$package_files"; then
    echo "$package archive is missing required file: $relative_path" >&2
    exit 1
  fi
}

for package in "${packages[@]}"; do
  archive=$(archive_for "$package")
  actual_bytes=$(wc -c < "$archive")
  echo "Packaged $package: ${actual_bytes} bytes (budget: ${max_crate_bytes})"
  if (( actual_bytes > max_crate_bytes )); then
    echo "$package exceeds the package size budget" >&2
    exit 1
  fi
  require_archive_file "$package" Cargo.toml
  require_archive_file "$package" src/lib.rs
  package_files=$(tar -tzf "$archive" | sed 's@^[^/]*/@@')
  if grep -Eq '^(tests/|src/bin/.*-test-server[.]rs$)' <<<"$package_files"; then
    echo "$package archive contains package-test implementation files:" >&2
    grep -E '^(tests/|src/bin/.*-test-server[.]rs$)' <<<"$package_files" >&2
    exit 1
  fi
done

require_archive_file brokk-bifrost-core src/lib.rs
# The unified cache DB's migrations moved down with cache_db.rs.
require_archive_file brokk-bifrost-core migrations/cache/0001-current-baseline.sql
# The Go, Python and Rust tree-sitter query assets moved down with their
# language crates; the epoch salt hashes them from there, so a missing file is a
# silent epoch change.
require_archive_file brokk-bifrost-go resources/treesitter/go/definitions.scm
require_archive_file brokk-bifrost-go resources/treesitter/go/identifiers.scm
require_archive_file brokk-bifrost-go resources/treesitter/go/imports.scm
require_archive_file brokk-bifrost-python resources/treesitter/python/definitions.scm
require_archive_file brokk-bifrost-python resources/treesitter/python/identifiers.scm
require_archive_file brokk-bifrost-python resources/treesitter/python/imports.scm
require_archive_file brokk-bifrost-rust resources/treesitter/rust/definitions.scm
require_archive_file brokk-bifrost-rust resources/treesitter/rust/imports.scm
require_archive_file brokk-bifrost-analysis build.rs
require_archive_file brokk-bifrost-analysis migrations/semantic-pack-catalog/0001-current-baseline.sql
require_archive_file brokk-bifrost-analysis resources/treesitter/java/definitions.scm
require_archive_file brokk-bifrost-analysis testdata/semantic-model-packs/declarations-v1.json
require_archive_file brokk-bifrost-nlp src/lib.rs
require_archive_file brokk-bifrost-policy src/lib.rs
require_archive_file brokk-bifrost-policy policy-packs/bifrost.code-smells/manifest.json
require_archive_file brokk-bifrost-semantic-packs src/lib.rs
require_archive_file brokk-bifrost-semantic-packs src/release_bundle.rs
require_archive_file brokk-bifrost-semantic-packs src/bin/bifrost-semantic-pack.rs

required_analysis_vendor_files=(
  vendor/tree-sitter-scala/LICENSE
  vendor/tree-sitter-scala/BIFROST_PATCH.md
  vendor/tree-sitter-scala/grammar.js
  vendor/tree-sitter-scala/src/parser.c
  vendor/tree-sitter-scala/src/scanner.c
  vendor/tree-sitter-scala/src/tree_sitter/alloc.h
  vendor/tree-sitter-scala/src/tree_sitter/array.h
  vendor/tree-sitter-scala/src/tree_sitter/parser.h
  vendor/tree-sitter-kotlin/LICENSE
  vendor/tree-sitter-kotlin/BIFROST_PROVENANCE.md
  vendor/tree-sitter-kotlin/grammar.js
  vendor/tree-sitter-kotlin/src/parser.c
  vendor/tree-sitter-kotlin/src/scanner.c
  vendor/tree-sitter-kotlin/src/tree_sitter/alloc.h
  vendor/tree-sitter-kotlin/src/tree_sitter/array.h
  vendor/tree-sitter-kotlin/src/tree_sitter/parser.h
)
for required_file in "${required_analysis_vendor_files[@]}"; do
  require_archive_file brokk-bifrost-analysis "$required_file"
done

manifest_policy_files="$temporary/manifest-policy-files.txt"
checked_in_policy_files="$temporary/checked-in-policy-files.txt"
jq -r '.policies[].path' crates/bifrost-policy/policy-packs/bifrost.code-smells/manifest.json \
  | sed 's@^@policy-packs/bifrost.code-smells/@' \
  | LC_ALL=C sort > "$manifest_policy_files"
find crates/bifrost-policy/policy-packs/bifrost.code-smells/policies -type f -name '*.rqlp' -print \
  | sed 's@^crates/bifrost-policy/@@' \
  | LC_ALL=C sort > "$checked_in_policy_files"
if ! cmp -s "$manifest_policy_files" "$checked_in_policy_files"; then
  echo "Built-in policy manifest does not match the checked-in .rqlp inventory" >&2
  diff -u "$manifest_policy_files" "$checked_in_policy_files" >&2 || true
  exit 1
fi
while IFS= read -r required_file; do
  require_archive_file brokk-bifrost-policy "$required_file"
done < "$checked_in_policy_files"

require_archive_file brokk-bifrost-mcp resources/agent-guidance/bifrost-agents.md
require_archive_file brokk-bifrost scripts/embedding_sidecar.py
require_archive_file brokk-bifrost scripts/voyage_sidecar.py
require_archive_file brokk-bifrost schemas/semantic-model-pack-v1.schema.json

embedded_skill_count=0
while IFS= read -r skill_file; do
  require_archive_file brokk-bifrost "$skill_file"
  embedded_skill_count=$((embedded_skill_count + 1))
done < <(grep -oE 'plugins/bifrost-agent/skills/[^" ]+/SKILL[.]md' src/skill_install.rs | sort -u)
if (( embedded_skill_count == 0 )); then
  echo "Failed to derive the embedded skill roster from src/skill_install.rs" >&2
  exit 1
fi

root_archive=$(archive_for brokk-bifrost)
root_files="$temporary/root-files.txt"
tar -tzf "$root_archive" | sed 's@^[^/]*/@@' > "$root_files"
if grep -Eq '^(tests/.*[.]rs|tests/common/|python_tests/|[.]agents/|[.]github/|docs/|benchmark/)' "$root_files"; then
  echo "Facade archive contains repository-only content:" >&2
  grep -E '^(tests/.*[.]rs|tests/common/|python_tests/|[.]agents/|[.]github/|docs/|benchmark/)' "$root_files" >&2
  exit 1
fi

readonly unpacked="$temporary/unpacked"
mkdir -p "$unpacked"
for package in "${packages[@]}"; do
  tar -xzf "$(archive_for "$package")" -C "$unpacked"
done

readonly consumer="$temporary/consumer"
mkdir -p "$consumer/src"
cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "bifrost-package-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
brokk-bifrost = { path = "$unpacked/brokk-bifrost-$version" }

[features]
full = ["brokk-bifrost/nlp", "brokk-bifrost/python"]

[patch.crates-io]
brokk-bifrost-core = { path = "$unpacked/brokk-bifrost-core-$version" }
brokk-bifrost-go = { path = "$unpacked/brokk-bifrost-go-$version" }
brokk-bifrost-python = { path = "$unpacked/brokk-bifrost-python-$version" }
brokk-bifrost-rust = { path = "$unpacked/brokk-bifrost-rust-$version" }
brokk-bifrost-analysis = { path = "$unpacked/brokk-bifrost-analysis-$version" }
brokk-bifrost-nlp = { path = "$unpacked/brokk-bifrost-nlp-$version" }
brokk-bifrost-policy = { path = "$unpacked/brokk-bifrost-policy-$version" }
brokk-bifrost-semantic-packs = { path = "$unpacked/brokk-bifrost-semantic-packs-$version" }
brokk-bifrost-runtime = { path = "$unpacked/brokk-bifrost-runtime-$version" }
brokk-bifrost-mcp = { path = "$unpacked/brokk-bifrost-mcp-$version" }
brokk-bifrost-lsp = { path = "$unpacked/brokk-bifrost-lsp-$version" }
EOF
cat > "$consumer/src/main.rs" <<'EOF'
fn main() {
    let _ = brokk_bifrost::NavigationOperation::Definition;
}
EOF

CARGO_TARGET_DIR="$temporary/consumer-target" cargo check --quiet --manifest-path "$consumer/Cargo.toml"
PYO3_PYTHON="${PYO3_PYTHON:-python3}" CARGO_TARGET_DIR="$temporary/consumer-target" \
  cargo check --quiet --manifest-path "$consumer/Cargo.toml" --features full

readonly analysis_consumer="$temporary/analysis-consumer"
mkdir -p "$analysis_consumer/src"
cat > "$analysis_consumer/Cargo.toml" <<EOF
[package]
name = "bifrost-analysis-only-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
brokk-bifrost-analysis = { path = "$unpacked/brokk-bifrost-analysis-$version" }

[patch.crates-io]
brokk-bifrost-core = { path = "$unpacked/brokk-bifrost-core-$version" }
brokk-bifrost-go = { path = "$unpacked/brokk-bifrost-go-$version" }
brokk-bifrost-python = { path = "$unpacked/brokk-bifrost-python-$version" }
brokk-bifrost-rust = { path = "$unpacked/brokk-bifrost-rust-$version" }
EOF
cat > "$analysis_consumer/src/main.rs" <<'EOF'
fn main() {
    let _ = brokk_bifrost_analysis::Language::Java;
}
EOF
CARGO_TARGET_DIR="$temporary/consumer-target" \
  cargo check --quiet --manifest-path "$analysis_consumer/Cargo.toml"

echo "Validated all ${#packages[@]} package archives and their unpacked facade and analysis-only consumers"
