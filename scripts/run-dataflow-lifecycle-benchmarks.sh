#!/usr/bin/env bash
# Collect the issue #817 bounded data-flow lifecycle matrix.

set -euo pipefail

readonly result_prefix='BIFROST_DATAFLOW_LIFECYCLE_BENCHMARK='
readonly vscode_commit='19e0f9e681ecb8e5c09d8784acaa601316ca4571'
readonly petclinic_commit='f182358d02e4a68e52bdbabf55ca7800288511e7'

# Sample provenance uses read-only Git queries. Prevent `git status` from
# refreshing the tracked index, which `build.rs` watches and would otherwise
# turn every fresh-process invocation into a redundant crate rebuild.
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

readonly datasets=(
    generated_typescript_branches_64
    generated_typescript_branches_512
    generated_typescript_calls_8
    generated_typescript_calls_32
    inline_typescript
    inline_java
    external_vscode_typescript
    external_spring_petclinic_java
)

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-dataflow-lifecycle.XXXXXX")
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

for dataset in "${datasets[@]}"; do
    for round in 0 1 2 3 4 5 6 7 8; do
        log_file="$work_dir/${dataset}-round-${round}.log"
        printf 'data-flow lifecycle benchmark: %s round %s/8\n' "$dataset" "$round" >&2
        if ! BIFROST_DATAFLOW_LIFECYCLE_DATASET=$dataset \
            BIFROST_DATAFLOW_LIFECYCLE_ROUND=$round \
            BIFROST_SEMANTIC_INDEX=off \
            cargo test --locked --release --test measure_dataflow_lifecycle \
                dataflow_lifecycle_measurement -- --ignored --nocapture \
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

aggregate_log="$work_dir/aggregate.log"
if ! BIFROST_DATAFLOW_LIFECYCLE_SAMPLES_FILE=$samples_file \
    BIFROST_SEMANTIC_INDEX=off \
    cargo test --locked --release --test measure_dataflow_lifecycle \
        dataflow_lifecycle_measurement -- --ignored --nocapture \
        >"$aggregate_log" 2>&1; then
    tail -n 240 "$aggregate_log" >&2
    exit 1
fi

aggregate_json=$(extract_result "$aggregate_log")
printf '%s%s\n' "$result_prefix" "$aggregate_json"
