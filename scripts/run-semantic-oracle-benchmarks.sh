#!/usr/bin/env bash
# Collect the predeclared generation-local oracle matrix for issue #816.

set -euo pipefail

readonly result_prefix='BIFROST_SEMANTIC_ORACLE_BENCHMARK='
readonly vscode_commit='19e0f9e681ecb8e5c09d8784acaa601316ca4571'
readonly petclinic_commit='f182358d02e4a68e52bdbabf55ca7800288511e7'

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

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-semantic-oracle-benchmark.XXXXXX")
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
        printf 'expected exactly one oracle benchmark marker in %s, found %s\n' \
            "$log_file" "$marker_count" >&2
        tail -n 240 "$log_file" >&2
        exit 1
    fi
    marker_line=$(grep -F "$result_prefix" "$log_file")
    printf '%s\n' "${marker_line#*${result_prefix}}"
}

for round in 0 1 2 3 4 5 6; do
    log_file="$work_dir/round-${round}.log"
    printf 'semantic oracle benchmark: round %s/6\n' "$round" >&2
    if ! BIFROST_SEMANTIC_ORACLE_BENCH_ROUND=$round \
        BIFROST_SEMANTIC_INDEX=off \
        cargo test --release --test measure_semantic_oracles \
            semantic_oracle_lifecycle_measurement -- --ignored --nocapture \
            >"$log_file" 2>&1; then
        tail -n 240 "$log_file" >&2
        exit 1
    fi
    json=$(extract_result "$log_file")
    if [[ $round -ge 2 ]]; then
        printf '%s\n' "$json" >>"$samples_file"
    fi
done

jq -cs '
    def median(field): map(field) | sort | .[length / 2 | floor];
    sort_by(.round) as $samples
    | ($samples | map(.datasets[]) | group_by(.name)) as $datasets
    | {
        format: "bifrost_semantic_oracle_benchmark/aggregate-v1",
        kind: "aggregate",
        retained_rounds: ($samples | map(.round)),
        sample_provenance: ($samples[0].provenance),
        query_caps: ($samples[0].query_caps),
        dataset_medians: [
            $datasets[]
            | {
                name: .[0].name,
                origin: .[0].origin,
                language: .[0].language,
                repository_commit: .[0].repository_commit,
                repository_dirty: .[0].repository_dirty,
                files_seen: .[0].files_seen,
                files_materialized: .[0].files_materialized,
                unavailable_files: .[0].unavailable_files,
                cold_materialization_ms: median(.cold_materialization_ms),
                warm_materialization_ms: median(.warm_materialization_ms),
                warm_arc_reuse_count: median(.warm_arc_reuse_count),
                warm_arc_reuse_ratio: (median(.warm_arc_reuse_count) / .[0].files_materialized),
                oracle_projection_ms: median(.oracle_projection_ms),
                receiver_structural_baseline_ms: median(.receiver.structural_baseline_ms),
                receiver_projection_ms: median(.receiver.receiver_projection_ms),
                receiver_compatibility_overhead_ms: median(.receiver.compatibility_overhead_ms),
                receiver_baseline_results: .[0].receiver.baseline_results,
                receiver_results: .[0].receiver.receiver_results,
                receiver_value_candidates: .[0].receiver.receiver_value_candidates,
                receiver_member_candidates: .[0].receiver.receiver_member_candidates,
                receiver_truncated: .[0].receiver.receiver_truncated,
                ir: .[0].ir,
                oracle: .[0].oracle
            }
        ],
        invalidation_medians: {
            disk_update_ms: ($samples | median(.invalidation.disk_update_ms)),
            overlay_update_ms: ($samples | median(.invalidation.overlay_update_ms)),
            disk_key_changed: ($samples | all(.invalidation.disk_key_changed)),
            disk_warm_arc_reused: ($samples | all(.invalidation.disk_warm_arc_reused)),
            overlay_key_changed: ($samples | all(.invalidation.overlay_key_changed)),
            overlay_warm_arc_reused: ($samples | all(.invalidation.overlay_warm_arc_reused)),
            incomplete_request_followed_by_complete: ($samples | all(.invalidation.incomplete_request_followed_by_complete))
        },
        samples: $samples,
        recommendation: $samples[0].recommendation
    }
' "$samples_file" | sed "s/^/${result_prefix}/"
