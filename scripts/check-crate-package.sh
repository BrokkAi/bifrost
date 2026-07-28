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

# Non-runtime repository content stays out of the archive. The kept
# exceptions are compile-time or runtime inputs of the published crate:
# embedded agent skills, the Rune IR grammar an inline test include_str!'s,
# and the nlp voyage sidecar script.
readonly forbidden_pattern='^(docs/|benchmark/|examples/|[.]github/|[.]claude-plugin/|[.]cursor-plugin/|[.]cargo/config[.]toml|AGENTS[.]md|CLAUDE[.]md|CODE_OF_CONDUCT[.]md|CONTRIBUTING[.]md|SECURITY[.]md|editors/|plugins/|scripts/|tests/fixtures/(mcp/|sarif/|policy-cli/overrides/|proxygroup|scala-issue|testcode-(cpp|cs|go|git-rank-java)/|testcode-java/bin/))'
readonly allowed_exceptions='^(editors/vscode/syntaxes/bifrost-rune-ir[.]tmLanguage[.]json|plugins/bifrost-agent/skills/|scripts/voyage_sidecar[.]py)'

if grep -E "$forbidden_pattern" "$package_files" | grep -Evq "$allowed_exceptions"; then
    echo "Packaged crate contains non-runtime repository content:" >&2
    grep -E "$forbidden_pattern" "$package_files" | grep -Ev "$allowed_exceptions" >&2
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

# Compile-time and runtime inputs deliberately negated back in from excluded
# directories; a future exclude edit must not drop them.
required_kept_exceptions=(
    editors/vscode/syntaxes/bifrost-rune-ir.tmLanguage.json
    scripts/voyage_sidecar.py
    plugins/bifrost-agent/skills/adversarial-test-sweep/SKILL.md
    plugins/bifrost-agent/skills/bifrost-code-navigation/SKILL.md
    plugins/bifrost-agent/skills/bifrost-code-reading/SKILL.md
    plugins/bifrost-agent/skills/bifrost-codebase-search/SKILL.md
    plugins/bifrost-agent/skills/git-exploration/SKILL.md
    plugins/bifrost-agent/skills/guided-issue/SKILL.md
    plugins/bifrost-agent/skills/guided-review/SKILL.md
    plugins/bifrost-agent/skills/review/SKILL.md
    plugins/bifrost-agent/skills/review-pr/SKILL.md
    plugins/bifrost-agent/skills/today/SKILL.md
    plugins/bifrost-agent/skills/write-issue/SKILL.md
)

for required_file in "${required_kept_exceptions[@]}"; do
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
