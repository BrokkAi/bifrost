#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=scripts/lib/release-crates.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/../lib/release-crates.sh"
readonly packages=("${RELEASE_CRATES[@]}")
readonly cargo_patch_args=("${RELEASE_CRATE_PATCH_ARGS[@]}")
readonly max_crate_bytes="${MAX_CRATE_BYTES:-10000000}"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
readonly repo_root
temporary=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-package-set.XXXXXX")
readonly temporary
trap 'rm -rf "$temporary"' EXIT INT TERM

readonly package_target="$temporary/target"
mkdir -p "$package_target/package"
cd "$repo_root"

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

version=$(cd "$repo_root" && node scripts/public/release-version.mjs print)
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
# The unified cache DB's migrations moved down with cache_db.rs. The baseline
# is named for the schema version it creates, which is 18: migrations 1..18
# were folded into it.
require_archive_file brokk-bifrost-core migrations/cache/0018-current-baseline.sql
require_archive_file brokk-bifrost-core migrations/cache/bridges/0016-optional-fact-manifest-after-19.sql
# The C++, C#, Go, Java, PHP, Python, Ruby, Rust and Scala tree-sitter query
# assets moved down with their language crates; the epoch salt hashes them from
# there, so a missing file is a silent epoch change. Kotlin's `highlights.scm`
# is never salted but `KotlinSupport::highlight_query` embeds it, so it is
# required for the same reason.
require_archive_file brokk-bifrost-cpp resources/treesitter/cpp/definitions.scm
require_archive_file brokk-bifrost-cpp resources/treesitter/cpp/identifiers.scm
require_archive_file brokk-bifrost-cpp resources/treesitter/cpp/imports.scm
require_archive_file brokk-bifrost-csharp resources/treesitter/c_sharp/definitions.scm
require_archive_file brokk-bifrost-csharp resources/treesitter/c_sharp/imports.scm
require_archive_file brokk-bifrost-go resources/treesitter/go/definitions.scm
require_archive_file brokk-bifrost-go resources/treesitter/go/identifiers.scm
require_archive_file brokk-bifrost-go resources/treesitter/go/imports.scm
require_archive_file brokk-bifrost-js-ts resources/treesitter/javascript/definitions.scm
require_archive_file brokk-bifrost-js-ts resources/treesitter/javascript/identifiers.scm
require_archive_file brokk-bifrost-js-ts resources/treesitter/javascript/imports.scm
require_archive_file brokk-bifrost-js-ts resources/treesitter/typescript/definitions.scm
require_archive_file brokk-bifrost-js-ts resources/treesitter/typescript/identifiers.scm
require_archive_file brokk-bifrost-js-ts resources/treesitter/typescript/imports.scm
require_archive_file brokk-bifrost-jvm resources/treesitter/java/definitions.scm
require_archive_file brokk-bifrost-jvm resources/treesitter/java/identifiers.scm
require_archive_file brokk-bifrost-jvm resources/treesitter/java/imports.scm
require_archive_file brokk-bifrost-jvm resources/treesitter/scala/definitions.scm
require_archive_file brokk-bifrost-jvm resources/treesitter/scala/imports.scm
require_archive_file brokk-bifrost-jvm resources/treesitter/kotlin/highlights.scm
require_archive_file brokk-bifrost-php resources/treesitter/php/definitions.scm
require_archive_file brokk-bifrost-php resources/treesitter/php/imports.scm
require_archive_file brokk-bifrost-python resources/treesitter/python/definitions.scm
require_archive_file brokk-bifrost-python resources/treesitter/python/identifiers.scm
require_archive_file brokk-bifrost-python resources/treesitter/python/imports.scm
require_archive_file brokk-bifrost-ruby resources/treesitter/ruby/definitions.scm
require_archive_file brokk-bifrost-ruby resources/treesitter/ruby/identifiers.scm
require_archive_file brokk-bifrost-ruby resources/treesitter/ruby/imports.scm
require_archive_file brokk-bifrost-rust resources/treesitter/rust/definitions.scm
require_archive_file brokk-bifrost-rust resources/treesitter/rust/imports.scm
require_archive_file brokk-bifrost-analysis migrations/semantic-pack-catalog/0001-current-baseline.sql
require_archive_file brokk-bifrost-analysis testdata/semantic-model-packs/declarations-v1.json
require_archive_file brokk-bifrost-policy src/lib.rs
require_archive_file brokk-bifrost-policy policy-packs/bifrost.code-smells/manifest.json
require_archive_file brokk-bifrost-semantic-packs src/lib.rs
require_archive_file brokk-bifrost-semantic-packs src/release_bundle.rs
require_archive_file brokk-bifrost-semantic-packs src/bin/bifrost-semantic-pack.rs
require_archive_file brokk-bifrost-runtime src/extension/mod.rs
require_archive_file brokk-bifrost-runtime src/extension/workspace.rs

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
require_archive_file brokk-bifrost schemas/semantic-model-pack-v1.schema.json
require_archive_file brokk-bifrost schemas/workspace-packs-v1.schema.json

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
full = ["brokk-bifrost/python"]

[patch.crates-io]
brokk-bifrost-core = { path = "$unpacked/brokk-bifrost-core-$version" }
brokk-bifrost-cpp = { path = "$unpacked/brokk-bifrost-cpp-$version" }
brokk-bifrost-csharp = { path = "$unpacked/brokk-bifrost-csharp-$version" }
brokk-bifrost-go = { path = "$unpacked/brokk-bifrost-go-$version" }
brokk-bifrost-js-ts = { path = "$unpacked/brokk-bifrost-js-ts-$version" }
brokk-bifrost-jvm = { path = "$unpacked/brokk-bifrost-jvm-$version" }
brokk-bifrost-php = { path = "$unpacked/brokk-bifrost-php-$version" }
brokk-bifrost-python = { path = "$unpacked/brokk-bifrost-python-$version" }
brokk-bifrost-ruby = { path = "$unpacked/brokk-bifrost-ruby-$version" }
brokk-bifrost-rust = { path = "$unpacked/brokk-bifrost-rust-$version" }
brokk-bifrost-analysis = { path = "$unpacked/brokk-bifrost-analysis-$version" }
brokk-bifrost-flow = { path = "$unpacked/brokk-bifrost-flow-$version" }
brokk-bifrost-rql = { path = "$unpacked/brokk-bifrost-rql-$version" }
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
brokk-bifrost-cpp = { path = "$unpacked/brokk-bifrost-cpp-$version" }
brokk-bifrost-csharp = { path = "$unpacked/brokk-bifrost-csharp-$version" }
brokk-bifrost-go = { path = "$unpacked/brokk-bifrost-go-$version" }
brokk-bifrost-js-ts = { path = "$unpacked/brokk-bifrost-js-ts-$version" }
brokk-bifrost-jvm = { path = "$unpacked/brokk-bifrost-jvm-$version" }
brokk-bifrost-php = { path = "$unpacked/brokk-bifrost-php-$version" }
brokk-bifrost-python = { path = "$unpacked/brokk-bifrost-python-$version" }
brokk-bifrost-ruby = { path = "$unpacked/brokk-bifrost-ruby-$version" }
brokk-bifrost-rust = { path = "$unpacked/brokk-bifrost-rust-$version" }
EOF
cat > "$analysis_consumer/src/main.rs" <<'EOF'
fn main() {
    let _ = brokk_bifrost_analysis::Language::Java;
}
EOF
CARGO_TARGET_DIR="$temporary/consumer-target" \
  cargo check --quiet --manifest-path "$analysis_consumer/Cargo.toml"

readonly extension_consumer="$temporary/extension-consumer"
mkdir -p "$extension_consumer/src"
cat > "$extension_consumer/Cargo.toml" <<EOF
[package]
name = "bifrost-extension-package-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
brokk-bifrost-runtime = { path = "$unpacked/brokk-bifrost-runtime-$version" }

[patch.crates-io]
brokk-bifrost-core = { path = "$unpacked/brokk-bifrost-core-$version" }
brokk-bifrost-cpp = { path = "$unpacked/brokk-bifrost-cpp-$version" }
brokk-bifrost-csharp = { path = "$unpacked/brokk-bifrost-csharp-$version" }
brokk-bifrost-go = { path = "$unpacked/brokk-bifrost-go-$version" }
brokk-bifrost-js-ts = { path = "$unpacked/brokk-bifrost-js-ts-$version" }
brokk-bifrost-jvm = { path = "$unpacked/brokk-bifrost-jvm-$version" }
brokk-bifrost-php = { path = "$unpacked/brokk-bifrost-php-$version" }
brokk-bifrost-python = { path = "$unpacked/brokk-bifrost-python-$version" }
brokk-bifrost-ruby = { path = "$unpacked/brokk-bifrost-ruby-$version" }
brokk-bifrost-rust = { path = "$unpacked/brokk-bifrost-rust-$version" }
brokk-bifrost-analysis = { path = "$unpacked/brokk-bifrost-analysis-$version" }
brokk-bifrost-flow = { path = "$unpacked/brokk-bifrost-flow-$version" }
brokk-bifrost-rql = { path = "$unpacked/brokk-bifrost-rql-$version" }
brokk-bifrost-policy = { path = "$unpacked/brokk-bifrost-policy-$version" }
EOF
cat > "$extension_consumer/src/main.rs" <<'EOF'
use brokk_bifrost_runtime::extension::{
    ExtensionCompatibility, ExtensionLimits, ExtensionWorkspace, ExtensionWorkspaceOptions,
    NormalizedRelativePath,
};

fn main() {
    let root = std::env::args_os().nth(1).expect("fixture root");
    let workspace = ExtensionWorkspace::open(ExtensionWorkspaceOptions::new(root)).unwrap();
    let path = NormalizedRelativePath::new("src/lib.rs").unwrap();
    let _ = ExtensionCompatibility::default();
    let _ = ExtensionLimits::default();
    println!("{} {} {}", workspace.describe().api.major, workspace.generation(), path.as_str());
}
EOF
mkdir -p "$extension_consumer/fixture/src"
cat > "$extension_consumer/fixture/src/lib.rs" <<'EOF'
pub fn package_seam() -> bool { true }
EOF
CARGO_TARGET_DIR="$temporary/consumer-target" \
  cargo run --quiet --manifest-path "$extension_consumer/Cargo.toml" -- "$extension_consumer/fixture"
extension_tree="$temporary/extension-tree.txt"
CARGO_TARGET_DIR="$temporary/consumer-target" \
  cargo tree --manifest-path "$extension_consumer/Cargo.toml" > "$extension_tree"
if grep -Eq 'brokk-bifrost-(mcp|lsp)' "$extension_tree"; then
  echo "Extension consumer unexpectedly depends on a transport host" >&2
  cat "$extension_tree" >&2
  exit 1
fi

echo "Validated all ${#packages[@]} package archives and their unpacked facade, analysis-only, and archive-only extension consumers"
