#!/usr/bin/env bash
# Collect the predeclared semantic CFG representation matrix for issue #815.

set -euo pipefail

readonly result_prefix='BIFROST_SEMANTIC_CFG_BENCHMARK='
readonly vscode_commit='19e0f9e681ecb8e5c09d8784acaa601316ca4571'
readonly petclinic_commit='f182358d02e4a68e52bdbabf55ca7800288511e7'

usage() {
    printf 'usage: %s layout\n' "${0##*/}" >&2
}

if [[ $# -ne 1 || $1 != layout ]]; then
    usage
    exit 2
fi

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

validate_optional_repo() {
    local variable_name=$1
    local expected_commit=$2
    local configured_path=${!variable_name-}
    local canonical_root
    local actual_commit
    local dirty_status

    if [[ -z $configured_path ]]; then
        return
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

validate_optional_repo BIFROST_SEMANTIC_TS_REPO "$vscode_commit"
validate_optional_repo BIFROST_SEMANTIC_JAVA_REPO "$petclinic_commit"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-semantic-cfg-benchmark.XXXXXX")
samples_file="$work_dir/retained-samples.jsonl"
: >"$samples_file"

cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

extract_result() {
    local log_file=$1
    local marker_count
    local marker_line

    marker_count=$(grep -F -c "$result_prefix" "$log_file" || true)
    if [[ $marker_count -ne 1 ]]; then
        printf 'expected exactly one benchmark marker in %s, found %s\n' \
            "$log_file" "$marker_count" >&2
        sed -n '1,240p' "$log_file" >&2
        exit 1
    fi
    marker_line=$(grep -F "$result_prefix" "$log_file")
    printf '%s\n' "${marker_line#*${result_prefix}}"
}

run_sample() {
    local round=$1
    local layout=$2
    local log_file="$work_dir/round-${round}-${layout}.log"
    local json

    printf 'semantic CFG benchmark: round %s/8, layout %s\n' "$round" "$layout" >&2
    if ! BIFROST_SEMANTIC_CFG_LAYOUT=$layout \
        BIFROST_SEMANTIC_CFG_BENCH_ROUND=$round \
        BIFROST_SEMANTIC_INDEX=off \
        cargo test --release --test measure_semantic_cfg \
            semantic_cfg_representation_measurement -- --ignored --nocapture \
            >"$log_file" 2>&1; then
        sed -n '1,240p' "$log_file" >&2
        exit 1
    fi
    json=$(extract_result "$log_file")
    if [[ $round -ge 2 ]]; then
        printf '%s\n' "$json" >>"$samples_file"
    fi
}

for round in 0 1 2 3 4 5 6 7 8; do
    case $((round % 3)) in
        0) layouts=(flat outgoing bidirectional) ;;
        1) layouts=(bidirectional flat outgoing) ;;
        2) layouts=(outgoing bidirectional flat) ;;
    esac
    for layout in "${layouts[@]}"; do
        run_sample "$round" "$layout"
    done
done

aggregate_log="$work_dir/aggregate.log"
if ! BIFROST_SEMANTIC_CFG_SAMPLES_FILE=$samples_file \
    BIFROST_SEMANTIC_INDEX=off \
    cargo test --release --test measure_semantic_cfg \
        semantic_cfg_representation_measurement -- --ignored --nocapture \
        >"$aggregate_log" 2>&1; then
    sed -n '1,240p' "$aggregate_log" >&2
    exit 1
fi

aggregate_json=$(extract_result "$aggregate_log")
printf '%s%s\n' "$result_prefix" "$aggregate_json"
