#!/usr/bin/env bash
# Collect the issue #824 production semantic-summary taint lifecycle matrix.

set -euo pipefail

readonly result_prefix='BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_BENCHMARK='

export GIT_OPTIONAL_LOCKS=0

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

campaign=${1:-smoke}
case "$campaign" in
    smoke)
        cases=(inline_s1_d1_src1_sink1)
        rounds=(0 1 2)
        cargo_profile_flag=''
        ;;
    full)
        cases=(
            inline_s1_d1_src1_sink1
            inline_s16_d1_src1_sink1
            inline_s64_d1_src1_sink1
            inline_s16_d4_src1_sink1
            inline_s16_d8_src1_sink1
            inline_s1_d1_src4_sink4
            inline_s1_d1_src16_sink16
        )
        rounds=(0 1 2 3 4 5 6 7 8)
        cargo_profile_flag='--release'
        ;;
    *)
        printf 'usage: %s [smoke|full]\n' "$0" >&2
        exit 2
        ;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-semantic-summary-taint-lifecycle.XXXXXX")
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
    for round in "${rounds[@]}"; do
        log_file="$work_dir/${benchmark_case}-round-${round}.log"
        printf 'semantic-summary taint lifecycle: %s round %s\n' \
            "$benchmark_case" "$round" >&2
        if ! BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_CASE=$benchmark_case \
            BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_ROUND=$round \
            BIFROST_SEMANTIC_INDEX=off \
            cargo test --locked ${cargo_profile_flag:+$cargo_profile_flag} --test suite_bench_policy \
                measure_semantic_summary_taint_lifecycle::semantic_summary_taint_lifecycle_measurement \
                -- --ignored --nocapture >"$log_file" 2>&1; then
            tail -n 240 "$log_file" >&2
            exit 1
        fi
        json=$(extract_result "$log_file")
        if [[ $campaign == smoke || $round -ge 2 ]]; then
            printf '%s\n' "$json" >>"$samples_file"
        fi
    done
done

aggregate_log="$work_dir/aggregate.log"
if ! BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_SAMPLES_FILE=$samples_file \
    BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_CAMPAIGN=$campaign \
    BIFROST_SEMANTIC_INDEX=off \
    cargo test --locked ${cargo_profile_flag:+$cargo_profile_flag} --test suite_bench_policy \
        measure_semantic_summary_taint_lifecycle::semantic_summary_taint_lifecycle_measurement \
        -- --ignored --nocapture >"$aggregate_log" 2>&1; then
    tail -n 240 "$aggregate_log" >&2
    exit 1
fi

aggregate_json=$(extract_result "$aggregate_log")
printf '%s%s\n' "$result_prefix" "$aggregate_json"
