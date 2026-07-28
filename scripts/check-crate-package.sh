#!/usr/bin/env bash

set -euo pipefail

readonly max_crate_bytes="${MAX_CRATE_BYTES:-10000000}"

cargo package --quiet --locked --allow-dirty

shopt -s nullglob
readonly package_target_dir="${CARGO_TARGET_DIR:-target}"
archives=("$package_target_dir"/package/brokk-bifrost-*.crate)
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

if grep -Eq '^(tests/.*[.]rs|tests/common/|python_tests/)' "$package_files"; then
    echo "Packaged crate contains repository test implementation files:" >&2
    grep -E '^(tests/.*[.]rs|tests/common/|python_tests/)' "$package_files" >&2
    exit 1
fi

# Non-runtime repository content stays out of the archive. One prefix per
# line, ordered to match the [package].exclude list in Cargo.toml so the
# two lists can be compared side by side when either changes.
forbidden_patterns=(
    '[.]agents/'
    '[.]cargo/config[.]toml'
    '[.]claude-plugin/'
    '[.]cursor-plugin/'
    '[.]gitattributes'
    '[.]github/'
    '[.]gitignore'
    'AGENTS[.]md'
    'CLAUDE[.]md'
    'CODE_OF_CONDUCT[.]md'
    'CONTRIBUTING[.]md'
    'SECURITY[.]md'
    'tests/fixtures/mcp/'
    'tests/fixtures/policies/'
    'tests/fixtures/policy-cli/overrides/'
    'tests/fixtures/proxygroup_test_regression[.]go'
    'tests/fixtures/sarif/'
    'tests/fixtures/scala-issue-'
    'tests/fixtures/testcode-cpp/'
    'tests/fixtures/testcode-cs/'
    'tests/fixtures/testcode-git-rank-java/'
    'tests/fixtures/testcode-go/'
    'tests/fixtures/testcode-java/bin/'
    'docs/'
    'benchmark/'
    'editors/'
    'plugins/'
    'scripts/'
    'examples/'
)
forbidden_pattern="^($(IFS='|'; printf '%s' "${forbidden_patterns[*]}"))"
readonly forbidden_pattern

# Files deliberately negated back in from excluded directories via "!"
# entries in Cargo.toml's exclude list. This one list drives both the
# violation allow-filter and the required-presence check below, so the two
# cannot diverge. The embedded-skill roster is derived from its owner,
# src/skill_install.rs, so a newly embedded skill is guarded without
# editing this script. The two policies/*.rqlp entries are also asserted
# in required_inline_test_fixtures; listing them here keeps every "!"
# negation covered by exactly this list.
kept_exception_files=(
    editors/vscode/syntaxes/bifrost-rune-ir.tmLanguage.json
    scripts/voyage_sidecar.py
    tests/fixtures/policies/dynamic-eval.rqlp
    tests/fixtures/policies/endpoints/http-request-parameter.rqlp
)

embedded_skill_count=0
while IFS= read -r skill_file; do
    kept_exception_files+=("$skill_file")
    embedded_skill_count=$((embedded_skill_count + 1))
done < <(grep -oE 'plugins/bifrost-agent/skills/[^"]+/SKILL[.]md' src/skill_install.rs | sort -u)

if (( embedded_skill_count == 0 )); then
    echo "Failed to derive the embedded skill roster from src/skill_install.rs" >&2
    exit 1
fi

allowed_exceptions=''
for kept_file in "${kept_exception_files[@]}"; do
    allowed_exceptions+="${allowed_exceptions:+|}$(printf '%s' "$kept_file" | sed 's/[.]/[.]/g')"'$'
done
allowed_exceptions="^(${allowed_exceptions})"
readonly allowed_exceptions

# The trailing grep reads to EOF (no -q), so the leading grep cannot die
# from SIGPIPE and vanish under pipefail; "|| true" absorbs the benign
# no-match exit status.
violations="$(grep -E "$forbidden_pattern" "$package_files" | grep -Ev "$allowed_exceptions" || true)"
if [[ -n "$violations" ]]; then
    echo "Packaged crate contains non-runtime repository content:" >&2
    printf '%s\n' "$violations" >&2
    exit 1
fi

required_vendor_files=(
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

for required_file in "${required_vendor_files[@]}"; do
    if ! grep -Fqx "$required_file" "$package_files"; then
        echo "Packaged crate is missing required vendored file: ${required_file}" >&2
        exit 1
    fi
done

# Every kept exception (including the derived skill roster) must actually
# be present in the archive; a future exclude edit must not drop them.
for required_file in "${kept_exception_files[@]}"; do
    if ! grep -Fqx "$required_file" "$package_files"; then
        echo "Packaged crate is missing required kept exception: ${required_file}" >&2
        exit 1
    fi
done

# Inline #[cfg(test)] modules compile from the published crate and still need
# these source-backed fixtures even though integration-test targets are omitted.
required_inline_test_fixtures=(
    tests/fixtures/csharp-external/ExternalLibrary.dll
    tests/fixtures/csharp-external/ExternalLibrary.dll.sha256
    tests/fixtures/policies/dynamic-eval.rqlp
    tests/fixtures/policies/endpoints/http-request-parameter.rqlp
    tests/fixtures/policy-cli/project/policies/dynamic-eval.rqlp
    tests/fixtures/policy-cli/project/policies/endpoints/resource-acquire.rqlp
    tests/fixtures/policy-cli/project/policies/endpoints/resource-close.rqlp
    tests/fixtures/policy-cli/project/policies/resource-lifecycle.rqlp
    tests/fixtures/policy-cli/project/src/app.py
    tests/fixtures/policy-cli/project/src/resource.ts
    tests/fixtures/testcode-java/A.java
    tests/fixtures/typestate/resource-lifecycle.protocol.json
)

for required_file in "${required_inline_test_fixtures[@]}"; do
    if ! grep -Fqx "$required_file" "$package_files"; then
        echo "Packaged crate is missing inline-test fixture: ${required_file}" >&2
        exit 1
    fi
done
