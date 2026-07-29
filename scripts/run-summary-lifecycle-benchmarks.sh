#!/usr/bin/env bash
# Collect the issue #823 reusable-summary lifecycle evidence matrix.

set -euo pipefail

readonly result_prefix='BIFROST_SUMMARY_LIFECYCLE_BENCHMARK='
readonly vscode_commit='19e0f9e681ecb8e5c09d8784acaa601316ca4571'
readonly petclinic_commit='f182358d02e4a68e52bdbabf55ca7800288511e7'

export GIT_OPTIONAL_LOCKS=0

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

validate_repo() {
    local variable_name=$1
    local expected_commit=$2
    local configured_path=${!variable_name-}
    local canonical_root
    local actual_commit
    local dirty_status

    if [[ -z $configured_path ]]; then
        printf '%s is required\n' "$variable_name" >&2
        exit 2
    fi
    if [[ ! -d $configured_path ]]; then
        printf '%s points to a missing directory: %s\n' "$variable_name" "$configured_path" >&2
        exit 2
    fi
    if ! canonical_root=$(git -C "$configured_path" rev-parse --show-toplevel 2>/dev/null); then
        printf '%s is not inside a Git worktree: %s\n' "$variable_name" "$configured_path" >&2
        exit 2
    fi
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

validate_repo BIFROST_SEMANTIC_TS_REPO "$vscode_commit"
validate_repo BIFROST_SEMANTIC_JAVA_REPO "$petclinic_commit"

readonly cases=(
    semantic:generated_typescript_512
    semantic:inline_typescript
    semantic:inline_java
    semantic:external_vscode_typescript
    semantic:external_spring_petclinic_java
    protocol:inline_java
    taint:inline_java
)

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-summary-lifecycle.XXXXXX")
samples_file="$work_dir/retained-samples.jsonl"
: >"$samples_file"

cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

extract_result() {
    local log_file=$1
    local marker_count
    local marker_line

    marker_count=$(grep -F -c "$result_prefix" "$log_file" || true)
    if [[ $marker_count -ne 1 ]]; then
        printf 'expected exactly one benchmark marker in %s, found %s\n' \
            "$log_file" "$marker_count" >&2
        tail -n 240 "$log_file" >&2
        exit 1
    fi
    marker_line=$(grep -F "$result_prefix" "$log_file")
    printf '%s\n' "${marker_line#*${result_prefix}}"
}

for benchmark_case in "${cases[@]}"; do
    candidate=${benchmark_case%%:*}
    dataset=${benchmark_case#*:}
    for round in 0 1 2 3 4 5 6 7 8; do
        payload_file="$work_dir/${candidate}-${dataset}-${round}.json"
        for mode in build hydrate; do
            log_file="$work_dir/${candidate}-${dataset}-${round}-${mode}.log"
            printf 'summary lifecycle benchmark: %s %s round %s/8 %s\n' \
                "$candidate" "$dataset" "$round" "$mode" >&2
            if ! BIFROST_SUMMARY_LIFECYCLE_CANDIDATE=$candidate \
                BIFROST_SUMMARY_LIFECYCLE_DATASET=$dataset \
                BIFROST_SUMMARY_LIFECYCLE_MODE=$mode \
                BIFROST_SUMMARY_LIFECYCLE_ROUND=$round \
                BIFROST_SUMMARY_LIFECYCLE_PAYLOAD_FILE=$payload_file \
                BIFROST_SUMMARY_LIFECYCLE_FIXTURE_ROOT="$work_dir/fixtures" \
                BIFROST_SEMANTIC_INDEX=off \
                cargo test --locked --release --test suite_semantic \
                    measure_summary_lifecycle::summary_lifecycle_measurement -- --ignored --nocapture \
                    >"$log_file" 2>&1; then
                tail -n 240 "$log_file" >&2
                exit 1
            fi
            json=$(extract_result "$log_file")
            if [[ $round -ge 2 ]]; then
                printf '%s\n' "$json" >>"$samples_file"
            fi
        done
    done
done

aggregate_log="$work_dir/aggregate.log"
if ! BIFROST_SUMMARY_LIFECYCLE_SAMPLES_FILE=$samples_file \
    BIFROST_SEMANTIC_INDEX=off \
    cargo test --locked --release --test suite_semantic \
        measure_summary_lifecycle::summary_lifecycle_measurement -- --ignored --nocapture \
        >"$aggregate_log" 2>&1; then
    tail -n 240 "$aggregate_log" >&2
    exit 1
fi

aggregate_json=$(extract_result "$aggregate_log")
printf '%s%s\n' "$result_prefix" "$aggregate_json"
