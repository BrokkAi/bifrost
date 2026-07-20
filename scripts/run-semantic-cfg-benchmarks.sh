#!/usr/bin/env bash
# Collect the predeclared semantic CFG representation matrix for issue #815.

set -euo pipefail

readonly layout_result_prefix='BIFROST_SEMANTIC_CFG_BENCHMARK='
readonly persistence_result_prefix='BIFROST_SEMANTIC_CFG_PERSISTENCE_BENCHMARK='
readonly vscode_commit='19e0f9e681ecb8e5c09d8784acaa601316ca4571'
readonly petclinic_commit='f182358d02e4a68e52bdbabf55ca7800288511e7'

usage() {
    printf 'usage: %s layout|persistence\n' "${0##*/}" >&2
}

if [[ $# -ne 1 || ($1 != layout && $1 != persistence) ]]; then
    usage
    exit 2
fi
phase=$1

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

if [[ $phase == persistence ]]; then
    if [[ -z ${BIFROST_SEMANTIC_TS_REPO-} || -z ${BIFROST_SEMANTIC_JAVA_REPO-} ]]; then
        printf 'persistence requires BIFROST_SEMANTIC_TS_REPO and BIFROST_SEMANTIC_JAVA_REPO\n' >&2
        exit 2
    fi
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-semantic-cfg-benchmark.XXXXXX")
samples_file="$work_dir/retained-samples.jsonl"
: >"$samples_file"

cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

extract_result() {
    local log_file=$1
    local result_prefix=$2
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

run_persistence() {
    local samples_file="$work_dir/persistence-retained-samples.jsonl"
    local aggregate_log="$work_dir/persistence-aggregate.log"
    local datasets=(
        fixture_typescript
        fixture_java
        external_vscode_typescript
        external_spring_petclinic_java
    )
    : >"$samples_file"

    for dataset in "${datasets[@]}"; do
        local template="$work_dir/${dataset}-template.db"
        local seed_log="$work_dir/${dataset}-seed.log"
        printf 'semantic CFG persistence benchmark: seed %s\n' "$dataset" >&2
        if ! BIFROST_SEMANTIC_CFG_PERSIST_MODE=seed \
            BIFROST_SEMANTIC_CFG_PERSIST_DATASET=$dataset \
            BIFROST_SEMANTIC_CFG_PERSIST_DB=$template \
            BIFROST_SEMANTIC_CFG_BENCH_ROUND=0 \
            BIFROST_SEMANTIC_INDEX=off \
            cargo test --release --test measure_semantic_cfg_persistence \
                semantic_cfg_persistence_measurement -- --ignored --nocapture \
                >"$seed_log" 2>&1; then
            tail -n 240 "$seed_log" >&2
            exit 1
        fi
        extract_result "$seed_log" "$persistence_result_prefix" >/dev/null
    done

    for round in 0 1 2 3 4 5 6 7 8; do
        local modes
        local ordered_datasets
        case $((round % 4)) in
            0) modes=(rebuild build_write hydrate hydrate_cold) ;;
            1) modes=(hydrate_cold rebuild build_write hydrate) ;;
            2) modes=(hydrate build_write hydrate_cold rebuild) ;;
            3) modes=(build_write hydrate rebuild hydrate_cold) ;;
        esac
        case $((round % 4)) in
            0) ordered_datasets=("${datasets[@]}") ;;
            1) ordered_datasets=("${datasets[3]}" "${datasets[0]}" "${datasets[1]}" "${datasets[2]}") ;;
            2) ordered_datasets=("${datasets[2]}" "${datasets[3]}" "${datasets[0]}" "${datasets[1]}") ;;
            3) ordered_datasets=("${datasets[1]}" "${datasets[2]}" "${datasets[3]}" "${datasets[0]}") ;;
        esac
        for dataset in "${ordered_datasets[@]}"; do
            for mode in "${modes[@]}"; do
                local log_file="$work_dir/persistence-${round}-${dataset}-${mode}.log"
                local database="$work_dir/persistence-${round}-${dataset}-${mode}.db"
                local json
                printf 'semantic CFG persistence benchmark: round %s/8, %s, %s\n' \
                    "$round" "$dataset" "$mode" >&2
                if [[ $mode == hydrate || $mode == hydrate_cold ]]; then
                    cp "$work_dir/${dataset}-template.db" "$database"
                fi
                if ! BIFROST_SEMANTIC_CFG_PERSIST_MODE=$mode \
                    BIFROST_SEMANTIC_CFG_PERSIST_DATASET=$dataset \
                    BIFROST_SEMANTIC_CFG_PERSIST_DB=$database \
                    BIFROST_SEMANTIC_CFG_BENCH_ROUND=$round \
                    BIFROST_SEMANTIC_INDEX=off \
                    cargo test --release --test measure_semantic_cfg_persistence \
                        semantic_cfg_persistence_measurement -- --ignored --nocapture \
                        >"$log_file" 2>&1; then
                    tail -n 240 "$log_file" >&2
                    exit 1
                fi
                json=$(extract_result "$log_file" "$persistence_result_prefix")
                if [[ $round -ge 2 ]]; then
                    printf '%s\n' "$json" >>"$samples_file"
                fi
            done
        done
    done

    if ! BIFROST_SEMANTIC_CFG_PERSIST_SAMPLES_FILE=$samples_file \
        BIFROST_SEMANTIC_INDEX=off \
        cargo test --release --test measure_semantic_cfg_persistence \
            semantic_cfg_persistence_measurement -- --ignored --nocapture \
            >"$aggregate_log" 2>&1; then
        tail -n 240 "$aggregate_log" >&2
        exit 1
    fi
    local aggregate_json
    aggregate_json=$(extract_result "$aggregate_log" "$persistence_result_prefix")
    printf '%s%s\n' "$persistence_result_prefix" "$aggregate_json"
}

if [[ $phase == persistence ]]; then
    run_persistence
    exit 0
fi

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
        tail -n 240 "$log_file" >&2
        exit 1
    fi
    json=$(extract_result "$log_file" "$layout_result_prefix")
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
    tail -n 240 "$aggregate_log" >&2
    exit 1
fi

aggregate_json=$(extract_result "$aggregate_log" "$layout_result_prefix")
printf '%s%s\n' "$layout_result_prefix" "$aggregate_json"
