#!/usr/bin/env bash
# Run the decision-grade issue #819 CFG algorithm benchmark.

set -euo pipefail

readonly vscode_commit='19e0f9e681ecb8e5c09d8784acaa601316ca4571'
readonly petclinic_commit='f182358d02e4a68e52bdbabf55ca7800288511e7'
readonly maximum_repeats=10

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

require_pinned_repo() {
    local variable_name=$1
    local expected_commit=$2
    local configured_path=${!variable_name-}
    local canonical_root
    local actual_commit
    local dirty_status

    if [[ -z $configured_path ]]; then
        printf '%s must point to the pinned benchmark worktree\n' "$variable_name" >&2
        exit 2
    fi
    canonical_root=$(git -C "$configured_path" rev-parse --show-toplevel 2>/dev/null) || {
        printf '%s is not inside a Git worktree: %s\n' \
            "$variable_name" "$configured_path" >&2
        exit 2
    }
    actual_commit=$(git -C "$canonical_root" rev-parse HEAD)
    if [[ $actual_commit != "$expected_commit" ]]; then
        printf '%s must be at %s, found %s in %s\n' \
            "$variable_name" "$expected_commit" "$actual_commit" "$canonical_root" >&2
        exit 2
    fi
    dirty_status=$(git -C "$canonical_root" status --porcelain --untracked-files=normal)
    if [[ -n $dirty_status ]]; then
        printf '%s must be clean at its pinned commit: %s\n' \
            "$variable_name" "$canonical_root" >&2
        printf '%s\n' "$dirty_status" | sed -n '1,40p' >&2
        exit 2
    fi
    printf -v "$variable_name" '%s' "$canonical_root"
    export "$variable_name"
}

require_pinned_repo BIFROST_SEMANTIC_TS_REPO "$vscode_commit"
require_pinned_repo BIFROST_SEMANTIC_JAVA_REPO "$petclinic_commit"

output_path=${BIFROST_CFG_ALGORITHM_BENCHMARK_OUTPUT:-"$repo_root/.agents/docs/issue-819-cfg-algorithm-benchmark-2026-07-24.json"}
repeats=${BIFROST_CFG_ALGORITHM_BENCHMARK_REPEATS:-3}

if [[ ! $repeats =~ ^[1-9][0-9]*$ ]] || (( repeats > maximum_repeats )); then
    printf 'BIFROST_CFG_ALGORITHM_BENCHMARK_REPEATS must be between 1 and %d\n' \
        "$maximum_repeats" >&2
    exit 2
fi

printf 'CFG algorithm benchmark: %s recomputations per graph\n' "$repeats" >&2
BIFROST_CFG_ALGORITHM_BENCHMARK_OUTPUT=$output_path \
BIFROST_CFG_ALGORITHM_BENCHMARK_REPEATS=$repeats \
BIFROST_SEMANTIC_INDEX=off \
cargo test --locked --release --lib \
    analyzer::semantic::cfg_algorithms::benchmark::cfg_algorithm_release_measurement \
    -- --ignored --nocapture

printf 'CFG algorithm benchmark written to %s\n' "$output_path" >&2
