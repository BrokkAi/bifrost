use super::contracts::assert_serial_profile_reconciles;
use super::*;
use crate::analyzer::semantic::{
    SemanticBudget, SemanticBudgetDimension, SemanticEffect, SemanticRequest, SemanticValueKind,
    ValueFlowKind,
};
use crate::analyzer::semantic_model::{
    CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use crate::analyzer::usages::effects::EffectCoverage;
use crate::cancellation::CancellationToken;
use semver::Version;

#[test]
fn row_family_session_reuses_complete_occurrences_and_environment_across_queries() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.rs"))
        .write(
            "fn run() {\n    let mut values = vec![2, 1];\n    loop {\n        values.sort();\n        break;\n    }\n}\n",
        )
        .expect("write source");
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let queries = [
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["receiver_position"] }
        }),
        json!({
            "languages": ["rust"],
            "occurrences": { "role": ["receiver_position"] },
            "steps": [{ "op": "binding_of" }]
        }),
        json!({
            "languages": ["rust"],
            "scopes": {}
        }),
    ]
    .map(|source| CodeQuery::from_json(&source).expect("row-family query"));
    let mut session = CodeQueryRowFamilySession::default();

    for query in &queries {
        let expected = execute_code_query_detailed_eager_index_without_targets(
            &analyzer,
            query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        let actual =
            execute_code_query_detailed_eager_index_without_targets_with_row_family_session(
                &analyzer,
                query,
                CodeQueryExecutionLimits::default(),
                None,
                &mut session,
            );
        assert_eq!(
            serde_json::to_value(&actual.result).expect("cached result JSON"),
            serde_json::to_value(&expected.result).expect("ordinary result JSON")
        );
    }

    assert_eq!(
        session.stats(),
        CodeQueryRowFamilySessionStats {
            occurrence_derivations: 1,
            occurrence_reuses: 1,
            environment_derivations: 1,
            environment_reuses: 1,
            traced_occurrence_derivations: 0,
            traced_occurrence_reuses: 0,
        }
    );
}

#[test]
fn row_family_session_materializes_only_joined_occurrence_ast_ids() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.rs"))
        .write(
            "fn run() {\n    let mut values = vec![2, 1];\n    let mut other = vec![4, 3];\n    values.sort();\n    other.sort();\n}\n",
        )
        .expect("write source");
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let occurrence_query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "occurrences": { "role": ["receiver_position"] }
    }))
    .expect("occurrence query");
    let binding_query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "occurrences": { "role": ["receiver_position"] },
        "steps": [{ "op": "binding_of" }]
    }))
    .expect("binding query");
    let scope_query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "scopes": {}
    }))
    .expect("scope query");
    let ordinary = execute_code_query_detailed_eager_index_without_targets(
        &analyzer,
        &occurrence_query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    let ordinary_occurrences: Vec<&CodeQueryOccurrence> = ordinary
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::Occurrence { value } => Some(value.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(ordinary_occurrences.len(), 2);
    let selected_ast_id = ordinary_occurrences[0].ast_id.clone();
    let mut session = CodeQueryRowFamilySession::for_ast_ids(vec![selected_ast_id.clone()]);

    let occurrences =
        execute_code_query_detailed_eager_index_without_targets_with_row_family_session(
            &analyzer,
            &occurrence_query,
            CodeQueryExecutionLimits::default(),
            None,
            &mut session,
        );
    let retained_ast_ids: Vec<&str> = occurrences
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::Occurrence { value } => Some(value.ast_id.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(retained_ast_ids, vec![selected_ast_id.as_str()]);

    let bindings = execute_code_query_detailed_eager_index_without_targets_with_row_family_session(
        &analyzer,
        &binding_query,
        CodeQueryExecutionLimits::default(),
        None,
        &mut session,
    );
    let reached: Vec<(&str, u32)> = bindings
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::Binding { value } => value
                .reached_from_ast_id
                .as_deref()
                .map(|ast_id| (ast_id, value.declaring_scope_index)),
            _ => None,
        })
        .collect();
    assert_eq!(reached.len(), 1);
    assert_eq!(reached[0].0, selected_ast_id);

    let scopes = execute_code_query_detailed_eager_index_without_targets_with_row_family_session(
        &analyzer,
        &scope_query,
        CodeQueryExecutionLimits::default(),
        None,
        &mut session,
    );
    let scope_indices: Vec<u32> = scopes
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::LexicalScope { value } => Some(value.index),
            _ => None,
        })
        .collect();
    assert_eq!(scope_indices, vec![reached[0].1]);
    assert_eq!(session.stats().occurrence_derivations, 1);
    assert_eq!(session.stats().occurrence_reuses, 1);
    assert_eq!(session.stats().environment_derivations, 1);
    assert_eq!(session.stats().environment_reuses, 1);

    assert_ne!(
        reached[0].1, 0,
        "the binding must live after the file scope for this budget fixture"
    );
    let limited_scopes =
        execute_code_query_detailed_eager_index_without_targets_with_row_family_session(
            &analyzer,
            &scope_query,
            CodeQueryExecutionLimits {
                max_pipeline_rows: 1,
                ..CodeQueryExecutionLimits::default()
            },
            None,
            &mut session,
        );
    assert!(limited_scopes.result.results.is_empty());
    assert!(limited_scopes.result.truncated);
    assert_eq!(limited_scopes.work.pipeline_rows, 1);
    assert!(limited_scopes.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted
            && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
    }));
}

#[test]
fn where_globs_match_slash_normalized_paths() {
    let query = CodeQuery::from_json(&json!({
        "where": ["src/**/*.py"],
        "match": { "kind": "call" }
    }))
    .expect("query should parse");
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-structural-search"),
        std::path::PathBuf::from("src\\app.py"),
    );

    assert!(file_matches_globs(&file, query.seed().unwrap()));
}

#[test]
fn pipeline_render_cache_loads_each_source_once() {
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-pipeline-render-cache"),
        std::path::PathBuf::from("src/app.rs"),
    );
    let loads = Cell::new(0);
    let mut cache = PipelineRenderCache::default();

    for _ in 0..2 {
        let coordinates = cache
            .coordinates_for(&file, || {
                loads.set(loads.get() + 1);
                Some("fn demo() {}\n".to_string())
            })
            .expect("cached coordinates");
        assert_eq!(coordinates.line_starts, vec![0, 13]);
    }
    assert_eq!(loads.get(), 1);
}

#[test]
fn retained_execution_snapshot_wins_over_a_later_changed_source() {
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-retained-query-snapshot"),
        PathBuf::from("src/app.rs"),
    );
    let original = "fn before() {}\n";
    let changed = "// shifted\nfn before() {}\n";
    let loads = Cell::new(0);
    let mut cache = PipelineRenderCache::default();

    let coordinates = cache
        .coordinates_for(&file, || {
            loads.set(loads.get() + 1);
            Some(if loads.get() == 1 { original } else { changed }.to_string())
        })
        .expect("retained coordinates");

    assert_eq!(coordinates.source, original);
    let digest = source_slice_sha256(coordinates.source.as_str(), &(0..2));
    let coordinates = cache
        .coordinates_for(&file, || {
            loads.set(loads.get() + 1);
            Some(changed.to_string())
        })
        .expect("retained coordinates");
    assert_eq!(coordinates.source, original);
    assert_eq!(
        digest,
        source_slice_sha256(coordinates.source.as_str(), &(0..2))
    );
    assert_eq!(loads.get(), 1, "a later source loader must not run");
    assert!(
        !cache.retain_source_snapshot(&file, changed),
        "conflicting snapshots must not be treated as exact evidence"
    );
}

#[test]
fn conflicting_held_snapshots_are_negative_cached_and_typed_incomplete() {
    let file = ProjectFile::new(
        std::env::temp_dir().join("bifrost-conflicting-query-snapshot"),
        PathBuf::from("src/app.ts"),
    );
    let mut cache = PipelineRenderCache::default();
    let mut diagnostics = Vec::new();

    assert!(!retain_held_source_snapshot(
        &mut cache,
        &file,
        "fn before() {}\n",
        Language::Rust,
        Vec::new(),
        &mut diagnostics,
    ));
    assert!(retain_held_source_snapshot(
        &mut cache,
        &file,
        "// shifted\nfn before() {}\n",
        Language::Rust,
        vec![1],
        &mut diagnostics,
    ));
    assert!(cache.source_snapshot(&file).is_none());
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(diagnostics[0].branch == vec![1]);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_profile_replays_a_shared_seed_for_each_union_branch() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("export function shared() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({ "match": { "kind": "function", "name": "shared" } });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch],
        "limit": 10
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        true,
    );

    assert_eq!(detailed.result.results.len(), 1);
    let profile = detailed
        .profile
        .expect("valid execution should be profiled");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| {
                observation.operator == PhysicalQueryOperator::SequentialUnion
            })
            .count(),
        1
    );
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| observation.operator == PhysicalQueryOperator::Limit)
            .count(),
        1
    );
    let seed_observations = profile
        .operators
        .iter()
        .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .collect::<Vec<_>>();
    assert_eq!(seed_observations.len(), 2);
    assert_eq!(seed_observations[0].node, seed_observations[1].node);
    assert_eq!(seed_observations[0].branch, vec![0]);
    assert_eq!(seed_observations[1].branch, vec![1]);
    assert!(
        seed_observations
            .iter()
            .all(|observation| { observation.disposition == QueryOperatorDisposition::Completed })
    );
    assert_eq!(seed_observations[0].cache.seed_result.lookups, 1);
    assert_eq!(seed_observations[0].cache.seed_result.misses, 1);
    assert_eq!(seed_observations[0].cache.seed_result.builds, 1);
    assert_eq!(seed_observations[0].cache.seed_result.complete_builds, 1);
    assert_eq!(seed_observations[1].cache.seed_result.lookups, 1);
    assert_eq!(seed_observations[1].cache.seed_result.hits, 1);
    assert_eq!(seed_observations[1].cache.seed_result.complete_hits, 1);
    assert_eq!(seed_observations[1].cache.seed_result.replayed_items, 1);
    assert_eq!(profile.cache.seed_result.lookups, 2);
    assert_eq!(profile.cache.seed_result.misses, 1);
    assert_eq!(profile.cache.seed_result.hits, 1);
    assert_eq!(profile.cache.seed_result.complete_builds, 1);
    assert_eq!(profile.cache.seed_result.complete_hits, 1);
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    assert_eq!(union.input_rows, 2);
    assert_eq!(union.output_rows, 1);
    assert_eq!(union.rows_discarded, Some(1));
    assert!(union.temporary_capacity_bytes_lower_bound > 0);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn parallel_seed_union_matches_serial_fair_budget_roll_forward() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export const left = 1;\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write(
            "export function first() {}\nexport function second() {}\nexport function third() {}\n",
        )
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            {
                "where": ["left.ts"],
                "match": { "kind": "function", "name": "missing" }
            },
            {
                "where": ["right.ts"],
                "match": { "kind": "function" }
            }
        ],
        "limit": 10
    }))
    .expect("query");
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 3,
        ..CodeQueryExecutionLimits::default()
    };

    let sequential = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Sequential,
        true,
    );
    let parallel = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Parallel,
        true,
    );

    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential result serializes")
    );
    assert_eq!(parallel.work, sequential.work);
    assert_eq!(parallel.evidence, sequential.evidence);
    assert!(
        !parallel.result.truncated,
        "{:?}",
        parallel.result.diagnostics
    );
    assert_eq!(parallel.result.results.len(), 3);

    let profile = parallel.profile.expect("parallel profile");
    assert_eq!(profile.format, "bifrost_code_query_execution_profile/v4");
    assert_eq!(profile.scheduler.worker_limit, 2);
    assert_eq!(profile.scheduler.tasks_enqueued, 2);
    assert_eq!(profile.scheduler.tasks_completed, 2);
    assert!((1..=2).contains(&profile.peak_concurrency));
    assert_eq!(profile.peak_concurrency, profile.scheduler.peak_concurrency);
    let parallel_union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::ParallelUnion)
        .expect("parallel union observation");
    assert!(parallel_union.dependency_wait_ns > 0);
    assert!(parallel_union.scheduling_overhead_ns > 0);
    assert_eq!(
        parallel_union.total_elapsed_ns,
        parallel_union
            .elapsed_ns
            .saturating_add(parallel_union.dependency_wait_ns)
    );
    let operator_work = profile
        .operators
        .iter()
        .fold(QueryOperatorWorkProfile::default(), |work, observation| {
            work.saturating_add(observation.work)
        });
    assert_eq!(operator_work, profile.execution_work);
    assert!(
        sequential
            .profile
            .expect("sequential profile")
            .operators
            .iter()
            .any(|observation| { observation.operator == PhysicalQueryOperator::SequentialUnion })
    );
}

#[test]
fn parallel_seed_union_matches_serial_budget_exhaustion() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export function left_one() {}\nexport function left_two() {}\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write("export function right_one() {}\nexport function right_two() {}\n")
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "where": ["left.ts"], "match": { "kind": "function" } },
            { "where": ["right.ts"], "match": { "kind": "function" } }
        ]
    }))
    .expect("query");
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 3,
        ..CodeQueryExecutionLimits::default()
    };

    let sequential = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Sequential,
        false,
    );
    let parallel = execute_code_query_with_union_strategy(
        &analyzer,
        &query,
        limits,
        UnionExecutionStrategy::Parallel,
        false,
    );

    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential result serializes")
    );
    assert_eq!(parallel.work, sequential.work);
    assert_eq!(parallel.evidence, sequential.evidence);
    assert!(parallel.result.truncated);
    assert_eq!(parallel.result.results.len(), 3);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_union_charges_shared_scan_file_extraction_once() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("export function first() {}\nexport class Second {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    // Kind-only patterns provide no posting terms, so both branches take
    // Scan access over the same file with distinct seed cache keys.
    let probe = CodeQuery::from_json(&json!({ "match": { "kind": "function" }, "limit": 10 }))
        .expect("probe query");
    let probe_run = execute_internal(
        &analyzer,
        None,
        &probe,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
    );
    assert!(!probe_run.result.truncated);
    assert_eq!(probe_run.result.results.len(), 1);
    let scan_facts = usize::try_from(probe_run.work.fact_nodes).expect("facts fit usize");
    assert!(scan_facts > 0);

    let union = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "class" } }
        ],
        "limit": 10
    }))
    .expect("union query");
    // The fair split gives the first branch ceil(max/2) = one full scan;
    // without cross-branch sharing the second branch's identical full-file
    // charge pushes the total to twice the extraction and exhausts this cap.
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: scan_facts.saturating_mul(2).saturating_sub(1),
        ..CodeQueryExecutionLimits::default()
    };
    let detailed = execute_internal(&analyzer, None, &union, limits, None, None, false);

    assert!(
        !detailed.result.truncated,
        "{:?}",
        detailed.result.diagnostics
    );
    assert!(!detailed.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
    }));
    assert_eq!(detailed.result.results.len(), 2);
    assert_eq!(detailed.work.fact_nodes, probe_run.work.fact_nodes);
    assert_eq!(detailed.work.scanned_files, probe_run.work.scanned_files);
    assert_eq!(
        detailed.work.scanned_source_bytes,
        probe_run.work.scanned_source_bytes
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_union_still_charges_distinct_files_fully() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export function left() {}\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write("export function right_one() {}\nexport function right_two() {}\n")
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut probe_work = CodeQueryExecutionWork::default();
    for file in ["left.ts", "right.ts"] {
        let probe = CodeQuery::from_json(&json!({
            "where": [file],
            "match": { "kind": "function" },
            "limit": 10
        }))
        .expect("probe query");
        let probe_run = execute_internal(
            &analyzer,
            None,
            &probe,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            false,
        );
        assert!(!probe_run.result.truncated);
        probe_work = probe_work.saturating_add(probe_run.work);
    }

    let union = CodeQuery::from_json(&json!({
        "union": [
            { "where": ["left.ts"], "match": { "kind": "function" } },
            { "where": ["right.ts"], "match": { "kind": "function" } }
        ],
        "limit": 10
    }))
    .expect("union query");
    let detailed = execute_internal(
        &analyzer,
        None,
        &union,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
    );

    assert!(!detailed.result.truncated);
    assert_eq!(detailed.result.results.len(), 3);
    // Genuinely distinct scans keep accumulating: sharing only applies to
    // files an earlier seed scan in the same execution already charged.
    assert_eq!(detailed.work.scanned_files, probe_work.scanned_files);
    assert_eq!(
        detailed.work.scanned_source_bytes,
        probe_work.scanned_source_bytes
    );
    assert_eq!(detailed.work.fact_nodes, probe_work.fact_nodes);
}

#[test]
fn parallel_seed_union_matches_serial_shared_scan_charges() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("export function first() {}\nexport class Second {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let probe = CodeQuery::from_json(&json!({ "match": { "kind": "function" }, "limit": 10 }))
        .expect("probe query");
    let probe_run = execute_internal(
        &analyzer,
        None,
        &probe,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
    );
    let scan_facts = usize::try_from(probe_run.work.fact_nodes).expect("facts fit usize");
    let union = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "class" } }
        ],
        "limit": 10
    }))
    .expect("union query");
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: scan_facts.saturating_mul(2).saturating_sub(1),
        ..CodeQueryExecutionLimits::default()
    };

    let sequential = execute_code_query_with_union_strategy(
        &analyzer,
        &union,
        limits,
        UnionExecutionStrategy::Sequential,
        false,
    );
    let parallel = execute_code_query_with_union_strategy(
        &analyzer,
        &union,
        limits,
        UnionExecutionStrategy::Parallel,
        false,
    );

    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential result serializes")
    );
    assert_eq!(parallel.work, sequential.work);
    assert_eq!(parallel.evidence, sequential.evidence);
    assert!(
        !parallel.result.truncated,
        "{:?}",
        parallel.result.diagnostics
    );
    assert_eq!(parallel.result.results.len(), 2);
    assert_eq!(parallel.work.fact_nodes, probe_run.work.fact_nodes);
    assert_eq!(parallel.work.scanned_files, probe_run.work.scanned_files);
}

#[test]
fn forced_parallel_keeps_shared_and_stepped_unions_serial() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("export function first() {}\nexport function second() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let shared = json!({ "match": { "kind": "function", "name": "first" } });
    let stepped = CodeQuery::from_json(&json!({
        "union": [
            {
                "match": { "kind": "function", "name": "first" },
                "steps": [{ "op": "enclosing_decl" }]
            },
            {
                "match": { "kind": "function", "name": "second" },
                "steps": [{ "op": "enclosing_decl" }]
            }
        ]
    }))
    .expect("stepped query");
    let shared = CodeQuery::from_json(&json!({
        "union": [shared.clone(), shared]
    }))
    .expect("shared query");

    for query in [&shared, &stepped] {
        let profile = execute_code_query_with_union_strategy(
            &analyzer,
            query,
            CodeQueryExecutionLimits::default(),
            UnionExecutionStrategy::Parallel,
            true,
        )
        .profile
        .expect("profile");
        assert_eq!(profile.scheduler.tasks_enqueued, 0);
        assert!(
            profile.operators.iter().any(|observation| {
                observation.operator == PhysicalQueryOperator::SequentialUnion
            })
        );
        assert!(
            !profile.operators.iter().any(|observation| {
                observation.operator == PhysicalQueryOperator::ParallelUnion
            })
        );
    }
}

#[test]
fn absolute_exact_globs_cannot_panic_parallel_selection() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("inside.ts"))
        .write("export function inside() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    for (left, right) in [
        ("/outside/left.ts", "/outside/right.ts"),
        ("C:/outside/left.ts", "D:/outside/right.ts"),
    ] {
        let query = CodeQuery::from_json(&json!({
            "union": [
                {
                    "where": [left],
                    "languages": ["typescript"],
                    "match": { "kind": "function" }
                },
                {
                    "where": [right],
                    "languages": ["typescript"],
                    "match": { "kind": "function" }
                }
            ]
        }))
        .expect("absolute globs remain valid query syntax");
        let profile = execute_internal(
            &analyzer,
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            true,
        )
        .profile
        .expect("profile");
        assert!(
            profile
                .operators
                .iter()
                .any(|operator| { operator.operator == PhysicalQueryOperator::SequentialUnion })
        );
        assert!(
            !profile
                .operators
                .iter()
                .any(|operator| { operator.operator == PhysicalQueryOperator::ParallelUnion })
        );
    }
}

#[test]
fn cancellation_bearing_parallel_union_runs_cancellation_safe_tasks() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("left.ts"))
        .write("export function left() {}\n")
        .expect("write left source");
    ProjectFile::new(root.clone(), PathBuf::from("right.ts"))
        .write("export function right() {}\n")
        .expect("write right source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "where": ["left.ts"], "match": { "kind": "function" } },
            { "where": ["right.ts"], "match": { "kind": "function" } }
        ]
    }))
    .expect("query");
    let cancellation = CancellationToken::cancel_after_checks_for_test(2);

    let detailed = execute_internal_with_strategy(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        Some(&cancellation),
        None,
        true,
        UnionExecutionStrategy::Parallel,
        2,
        StructuralAccessMode::Auto,
        None,
    );

    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
    let profile = detailed.profile.expect("cancelled execution profile");
    assert!(
        profile
            .operators
            .iter()
            .any(|operator| { operator.operator == PhysicalQueryOperator::ParallelUnion })
    );
    assert_eq!(profile.scheduler.tasks_started, 2);
    assert_eq!(profile.scheduler.tasks_completed, 2);
    assert!(profile.scheduler.tasks_observed_cancelled_before_start > 0);
}

#[test]
fn fair_budget_wait_is_released_by_cancellation_and_worker_failure() {
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 1,
        ..CodeQueryExecutionLimits::default()
    };
    let projected = CodeQueryExecutionBudget {
        pipeline_rows: 1,
        ..CodeQueryExecutionBudget::default()
    };

    let cancellation = CancellationToken::default();
    let coordinator = FairSeedBudgetCoordinator::new(
        CodeQueryExecutionBudget::default(),
        limits,
        2,
        Some(&cancellation),
    );
    let lease = coordinator.lease(1);
    let cancelled_waiter = std::thread::spawn(move || lease.admit(projected));
    let deadline = Instant::now() + Duration::from_secs(1);
    while coordinator.waiting_branches() == 0 {
        assert!(
            Instant::now() < deadline,
            "budget branch did not start waiting"
        );
        std::thread::yield_now();
    }
    cancellation.cancel();
    assert!(matches!(
        cancelled_waiter.join().expect("cancelled waiter joins"),
        FairSeedBudgetAdmission::Cancelled
    ));

    let coordinator =
        FairSeedBudgetCoordinator::new(CodeQueryExecutionBudget::default(), limits, 2, None);
    let lease = coordinator.lease(1);
    let failed_waiter = std::thread::spawn(move || lease.admit(projected));
    let deadline = Instant::now() + Duration::from_secs(1);
    while coordinator.waiting_branches() == 0 {
        assert!(
            Instant::now() < deadline,
            "budget branch did not start waiting"
        );
        std::thread::yield_now();
    }
    coordinator.fail();
    assert!(matches!(
        failed_waiter.join().expect("failed waiter joins"),
        FairSeedBudgetAdmission::Cancelled
    ));
}

#[test]
fn profile_marks_truncated_seed_materialization_and_replay_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function first() {}\nfunction second() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({ "match": { "kind": "function" } });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            max_pipeline_rows: 2,
            ..CodeQueryExecutionLimits::default()
        },
        None,
        None,
        true,
    );

    assert!(detailed.result.truncated);
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.seed_result.lookups, 2);
    assert_eq!(profile.cache.seed_result.misses, 1);
    assert_eq!(profile.cache.seed_result.incomplete_builds, 1);
    assert_eq!(profile.cache.seed_result.hits, 1);
    assert_eq!(profile.cache.seed_result.incomplete_hits, 1);
    let seed_observations = profile
        .operators
        .iter()
        .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .collect::<Vec<_>>();
    assert_eq!(seed_observations.len(), 2);
    assert_eq!(seed_observations[0].cache.seed_result.incomplete_builds, 1);
    assert_eq!(seed_observations[1].cache.seed_result.incomplete_hits, 1);
    assert!(seed_observations.iter().all(|observation| {
        observation
            .terminations
            .contains(&QueryOperatorTermination::PipelineBudget)
    }));
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn profile_does_not_call_a_terminal_cap_seed_cache_complete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function first() {}\nfunction second() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "function" },
        "limit": 1
    }))
    .expect("query");

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert_eq!(detailed.result.results.len(), 1);
    assert!(detailed.result.truncated);
    // #2779 regression: the seed's own `TerminalCap` termination (below) is
    // an internal signal for the `Limit` operator above it, not a second
    // truncation to report -- the query must carry exactly the one
    // diagnostic the `Limit` operator names.
    assert_eq!(
        detailed
            .result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ResultLimitReached)
            .count(),
        1,
        "exactly one truncation diagnostic, no double report: {:?}",
        detailed.result.diagnostics
    );
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.seed_result.misses, 1);
    assert_eq!(profile.cache.seed_result.incomplete_builds, 1);
    assert_eq!(profile.cache.seed_result.complete_builds, 0);
    let seed = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .expect("seed observation");
    assert_eq!(seed.cache.seed_result.incomplete_builds, 1);
    assert_eq!(
        seed.terminations,
        vec![QueryOperatorTermination::TerminalCap]
    );
    let limit = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
        .expect("limit observation");
    assert_eq!(
        limit.terminations,
        vec![QueryOperatorTermination::ResultLimit]
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn profile_marks_unsupported_seed_materialization_and_replay_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function target(options: object) {}\ntarget({ flag: true });\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({
        "match": {
            "kind": "call",
            "kwargs": { "flag": { "kind": "boolean_literal" } }
        }
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert!(matches!(
        detailed.result.completion(),
        CodeQueryCompletion::Incomplete { codes }
            if codes.contains(&CodeQueryDiagnosticCode::UnsupportedStructuralFeature)
    ));
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.seed_result.incomplete_builds, 1);
    assert_eq!(profile.cache.seed_result.incomplete_hits, 1);
    let seeds = profile
        .operators
        .iter()
        .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .collect::<Vec<_>>();
    assert_eq!(seeds.len(), 2);
    assert!(seeds.iter().all(|observation| {
        observation
            .terminations
            .contains(&QueryOperatorTermination::UnsupportedAnalysis)
    }));
}

#[test]
fn profile_marks_unsupported_import_builds_and_replays_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.php"))
        .write("<?php\nfunction target() {}\n")
        .expect("write source");
    let analyzer = PhpAnalyzer::from_project(TestProject::new(root, Language::Php));
    let imports = json!({
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
    });
    let importers = json!({
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [imports.clone(), imports, importers.clone(), importers]
    }))
    .expect("query");

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert!(matches!(
        detailed.result.completion(),
        CodeQueryCompletion::Incomplete { codes }
            if codes.contains(&CodeQueryDiagnosticCode::UnsupportedImportAnalysis)
    ));
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.import_forward.lookups, 2);
    assert_eq!(profile.cache.import_forward.misses, 1);
    assert_eq!(profile.cache.import_forward.incomplete_builds, 1);
    assert_eq!(profile.cache.import_forward.complete_builds, 0);
    assert_eq!(profile.cache.import_forward.hits, 1);
    assert_eq!(profile.cache.import_forward.incomplete_hits, 1);
    assert_eq!(profile.cache.import_forward.complete_hits, 0);
    assert_eq!(profile.cache.import_reverse.lookups, 2);
    assert_eq!(profile.cache.import_reverse.misses, 1);
    assert_eq!(profile.cache.import_reverse.incomplete_builds, 1);
    assert_eq!(profile.cache.import_reverse.complete_builds, 0);
    assert_eq!(profile.cache.import_reverse.hits, 1);
    assert_eq!(profile.cache.import_reverse.incomplete_hits, 1);
    assert_eq!(profile.cache.import_reverse.complete_hits, 0);
    assert_eq!(profile.cache.direct_import_topology.lookups, 0);
    assert_eq!(profile.cache.direct_import_topology.misses, 0);
    assert_eq!(profile.cache.direct_import_topology.hits, 0);
    assert_eq!(profile.cache.direct_import_topology.builds, 0);
    assert_eq!(profile.cache.direct_import_topology.complete_builds, 0);
    assert_eq!(profile.cache.direct_import_topology.fallbacks, 0);
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| {
                observation.operator == PhysicalQueryOperator::PipelineStep
                    && observation
                        .terminations
                        .contains(&QueryOperatorTermination::UnsupportedAnalysis)
            })
            .count(),
        4
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn profile_distinguishes_seed_reuse_from_structural_facts_reuse() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("export function left() {}\nexport function right() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function", "name": "left" } },
            { "match": { "kind": "function", "name": "right" } }
        ]
    }))
    .expect("query");

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert_eq!(detailed.result.results.len(), 2);
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Complete);
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.seed_result.lookups, 2);
    assert_eq!(profile.cache.seed_result.misses, 2);
    assert_eq!(profile.cache.seed_result.hits, 0);
    assert_eq!(profile.cache.seed_result.complete_builds, 2);
    assert_eq!(profile.cache.seed_structural_facts.lookups, 2);
    assert_eq!(profile.cache.seed_structural_facts.extractions, 1);
    assert_eq!(profile.cache.seed_structural_facts.memory_hits, 1);
    assert_eq!(profile.cache.seed_structural_facts.replayed_files, 1);
    let seed_observations = profile
        .operators
        .iter()
        .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
        .collect::<Vec<_>>();
    assert_eq!(seed_observations.len(), 2);
    assert_eq!(seed_observations[0].branch, vec![0]);
    assert_eq!(
        seed_observations[0].cache.seed_structural_facts.extractions,
        1
    );
    assert_eq!(
        seed_observations[0].cache.seed_structural_facts.memory_hits,
        0
    );
    assert_eq!(seed_observations[1].branch, vec![1]);
    assert_eq!(
        seed_observations[1].cache.seed_structural_facts.memory_hits,
        1
    );
    assert_eq!(
        seed_observations[1]
            .cache
            .seed_structural_facts
            .replayed_files,
        1
    );
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    assert_eq!(union.input_rows, 2);
    assert_eq!(union.rows_visited, 2);
    assert_eq!(union.rows_discarded, Some(0));
    assert!(union.temporary_capacity_bytes_lower_bound > 0);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn profile_records_request_local_import_graph_reuse_without_snapshot_retention() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("bench/LeftHub.java"))
        .write("package bench;\npublic class LeftHub {}\n")
        .expect("write left hub");
    ProjectFile::new(root.clone(), PathBuf::from("bench/RightHub.java"))
        .write("package bench;\npublic class RightHub {}\n")
        .expect("write right hub");
    for name in ["One", "Two"] {
        ProjectFile::new(root.clone(), PathBuf::from(format!("bench/Node{name}.java")))
            .write(format!(
                "package bench;\nimport bench.LeftHub;\nimport bench.RightHub;\npublic class Node{name} {{}}\n"
            ))
            .expect("write importer");
    }
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
    let branch = |name: &str| {
        json!({
            "where": [format!("bench/{name}.java")],
            "languages": ["java"],
            "match": { "kind": "class", "name": name },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        })
    };
    let query = CodeQuery::from_json(&json!({
        "union": [branch("LeftHub"), branch("RightHub")]
    }))
    .expect("query");

    let deferred =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert_eq!(deferred.result.results.len(), 2);
    assert_eq!(deferred.result.completion(), CodeQueryCompletion::Complete);
    let deferred_profile = deferred.profile.expect("deferred profile");
    assert_serial_profile_reconciles(&deferred_profile);
    assert_eq!(deferred_profile.cache.direct_import_topology.lookups, 0);
    assert_eq!(deferred_profile.cache.direct_import_topology.misses, 0);
    assert_eq!(deferred_profile.cache.direct_import_topology.hits, 0);
    assert_eq!(deferred_profile.cache.direct_import_topology.builds, 0);
    assert_eq!(deferred_profile.cache.direct_import_topology.fallbacks, 0);

    let detailed =
        execute_code_query_profiled(&analyzer, &query, CodeQueryExecutionLimits::default());

    assert_eq!(detailed.result.results.len(), 2);
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Complete);
    let public_work = detailed.work;
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(public_work.scanned_files, profile.work.scanned_files);
    assert_eq!(
        public_work.scanned_source_bytes,
        profile.work.scanned_source_bytes
    );
    assert_eq!(public_work.fact_nodes, profile.work.fact_nodes);
    assert_eq!(public_work.pipeline_rows, profile.work.pipeline_rows);
    assert_eq!(
        public_work.examined_references,
        profile.work.examined_references
    );
    assert!(profile.work.import_files_resolved > 0);
    assert!(profile.work.import_edges_resolved > 0);
    assert_eq!(profile.cache.import_reverse.lookups, 2);
    assert_eq!(profile.cache.import_reverse.misses, 1);
    assert_eq!(profile.cache.import_reverse.complete_builds, 1);
    assert_eq!(profile.cache.import_reverse.hits, 1);
    assert_eq!(profile.cache.import_reverse.complete_hits, 1);
    assert!(profile.cache.import_reverse.replayed_items > 0);
    assert_eq!(profile.cache.direct_import_topology.lookups, 0);
    assert_eq!(profile.cache.direct_import_topology.misses, 0);
    assert_eq!(profile.cache.direct_import_topology.hits, 0);
    assert_eq!(profile.cache.direct_import_topology.builds, 0);
    assert_eq!(profile.cache.direct_import_topology.complete_builds, 0);
    assert_eq!(profile.cache.direct_import_topology.build_files, 0);
    assert_eq!(profile.cache.direct_import_topology.build_edges, 0);
    assert_eq!(profile.cache.direct_import_topology.retained_bytes, 0);
    let import_steps = profile
        .operators
        .iter()
        .filter(|observation| observation.cache.import_reverse.lookups > 0)
        .collect::<Vec<_>>();
    assert_eq!(import_steps.len(), 2);
    assert_eq!(import_steps[0].branch, vec![0]);
    assert_eq!(import_steps[0].cache.import_reverse.misses, 1);
    assert_eq!(import_steps[0].cache.import_reverse.complete_builds, 1);
    assert_eq!(import_steps[0].work.import_files_resolved, 4);
    assert_eq!(import_steps[0].work.import_edges_resolved, 4);
    assert_eq!(import_steps[1].branch, vec![1]);
    assert_eq!(import_steps[1].cache.import_reverse.hits, 1);
    assert_eq!(import_steps[1].cache.import_reverse.complete_hits, 1);
    assert_eq!(import_steps[1].work.import_files_resolved, 0);
    assert_eq!(import_steps[1].work.import_edges_resolved, 0);
    assert!(import_steps.iter().all(|observation| {
        observation.input_rows == 1
            && observation.rows_visited == 1
            && observation.relation_expansions == 2
            && observation.output_rows == 2
            && observation.rows_discarded.is_none()
    }));
}

#[test]
fn profile_preserves_incomplete_reference_cache_state_for_a_sibling() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let source =
        "export function target() {}\nfunction one() { target(); }\nfunction two() { target(); }\n";
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of" },
            { "op": "file_of" }
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: source.len().saturating_mul(2).saturating_add(4),
            ..CodeQueryExecutionLimits::default()
        },
        None,
        None,
        true,
    );

    assert!(detailed.result.truncated);
    assert!(
        detailed
            .result
            .results
            .iter()
            .all(|item| { !matches!(item.value, CodeQueryResultValue::File { .. }) })
    );
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    assert_eq!(profile.cache.inbound_reference.lookups, 2);
    assert_eq!(profile.cache.inbound_reference.misses, 1);
    assert_eq!(profile.cache.inbound_reference.incomplete_builds, 1);
    assert_eq!(profile.cache.inbound_reference.hits, 1);
    assert_eq!(profile.cache.inbound_reference.incomplete_hits, 1);
    let reference_steps = profile
        .operators
        .iter()
        .filter(|observation| observation.cache.inbound_reference.lookups > 0)
        .collect::<Vec<_>>();
    assert_eq!(reference_steps.len(), 2);
    assert!(
        reference_steps
            .iter()
            .all(|observation| observation.result_truncated)
    );
    assert!(
        reference_steps[0]
            .terminations
            .contains(&QueryOperatorTermination::AnalysisLimit)
    );
    assert!(
        reference_steps[1]
            .terminations
            .contains(&QueryOperatorTermination::AnalysisIncomplete),
        "sibling terminations: {:?}",
        reference_steps[1].terminations
    );
    assert_eq!(
        profile
            .operators
            .iter()
            .filter(|observation| {
                observation
                    .terminations
                    .contains(&QueryOperatorTermination::DependencyPipelineHalted)
            })
            .count(),
        2,
        "neither branch may continue a known-incomplete reference layer"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn profile_attributes_root_limit_probe_to_the_limit_operator() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write("function one() {}\nfunction two() {}\nfunction three() {}\nfunction four() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({ "match": { "kind": "function" } });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch],
        "limit": 2
    }))
    .expect("query");

    let detailed = execute_internal(
        &analyzer,
        None,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        true,
    );

    assert_eq!(detailed.result.results.len(), 2);
    assert!(detailed.result.truncated);
    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    let limit = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
        .expect("limit observation");
    assert!(limit.branch.is_empty());
    assert_eq!(limit.disposition, QueryOperatorDisposition::Completed);
    assert_eq!(limit.input_rows, 3);
    assert_eq!(limit.output_rows, 2);
    assert!(limit.operator_truncated);
    assert!(limit.result_truncated);
    assert!(!limit.result_cancelled);
    assert_eq!(limit.rows_visited, 3);
    assert_eq!(limit.rows_discarded, Some(1));
    assert_eq!(
        limit.terminations,
        vec![QueryOperatorTermination::ResultLimit]
    );
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    assert_eq!(union.input_rows, 8);
    assert_eq!(union.output_rows, 3);
    assert!(union.operator_truncated);
    assert!(!union.result_truncated);
    assert_eq!(union.rows_visited, 8);
    assert_eq!(union.rows_discarded, Some(5));
    assert!(union.temporary_capacity_bytes_lower_bound > 0);
    assert_eq!(
        union.terminations,
        vec![QueryOperatorTermination::TerminalCap]
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn skipped_set_profile_forwards_cancellation_safe_partial_cardinality() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(
            "function one() { sink(); }\nfunction two() { sink(); }\nfunction three() { sink(); }\n",
        )
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branch = json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "enclosing_decl" }]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("query");

    let detailed = (2..256)
        .find_map(|checks| {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let detailed = execute_internal(
                &analyzer,
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                Some(&cancellation),
                None,
                true,
            );
            let profile = detailed.profile.as_ref()?;
            let union = profile.operators.iter().find(|observation| {
                observation.operator == PhysicalQueryOperator::SequentialUnion
            })?;
            let limit = profile
                .operators
                .iter()
                .find(|observation| observation.operator == PhysicalQueryOperator::Limit)?;
            (union.disposition == QueryOperatorDisposition::Skipped
                && union.output_rows > 0
                && union.output_rows == limit.input_rows)
                .then_some(detailed)
        })
        .expect("cancellation should interrupt a final branch step after a partial row");

    let profile = detailed.profile.expect("profile");
    assert_serial_profile_reconciles(&profile);
    let union = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
        .expect("union observation");
    let limit = profile
        .operators
        .iter()
        .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
        .expect("limit observation");
    assert_eq!(union.disposition, QueryOperatorDisposition::Skipped);
    assert!(union.result_cancelled);
    assert_eq!(union.output_rows, limit.input_rows);
    assert!(limit.result_cancelled);
    assert_eq!(
        union.terminations,
        vec![QueryOperatorTermination::DependencyCancelled]
    );
    assert_eq!(
        limit.terminations,
        vec![QueryOperatorTermination::DependencyCancelled]
    );
    assert!(profile.operators.iter().any(|observation| {
        observation.disposition == QueryOperatorDisposition::Cancelled
            && observation
                .terminations
                .contains(&QueryOperatorTermination::CancellationDuringWork)
    }));
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
}

/// Two-language workspace whose volume is concentrated in the first-listed
/// union branch: the Rust files hold nearly all of the facts, the single
/// Python file almost none.
fn skewed_two_language_workspace(root: &std::path::Path) {
    for file in 0..8 {
        let mut source = String::new();
        for function in 0..12 {
            source.push_str(&format!(
                "pub fn rust_{file}_{function}(left: usize, right: usize) -> usize {{\n    let total = left.saturating_add(right);\n    total.saturating_mul({function} + 1)\n}}\n"
            ));
        }
        ProjectFile::new(root.to_path_buf(), PathBuf::from(format!("rust_{file}.rs")))
            .write(&source)
            .expect("write Rust source");
    }
    ProjectFile::new(root.to_path_buf(), PathBuf::from("tiny.py"))
        .write("def python_only():\n    return 1\n")
        .expect("write Python source");
}

fn two_language_analyzer(root: &std::path::Path) -> MultiAnalyzer {
    MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Rust,
            AnalyzerDelegate::Rust(RustAnalyzer::from_project(TestProject::new(
                root.to_path_buf(),
                Language::Rust,
            ))),
        ),
        (
            Language::Python,
            AnalyzerDelegate::Python(PythonAnalyzer::from_project(TestProject::new(
                root.to_path_buf(),
                Language::Python,
            ))),
        ),
    ]))
}

fn functions_in(language: &str) -> serde_json::Value {
    json!({ "languages": [language], "match": { "kind": "function" } })
}

/// Result identity without provenance: a branch's rows carry the union branch
/// index, which a single-branch query has no reason to report.
fn result_identities(result: &CodeQueryResult) -> Vec<serde_json::Value> {
    let mut values = result
        .results
        .iter()
        .map(|item| {
            let mut value = serde_json::to_value(item).expect("result item serializes");
            value
                .as_object_mut()
                .expect("result item is an object")
                .remove("provenance");
            value
        })
        .collect::<Vec<_>>();
    values.sort_by_key(ToString::to_string);
    values
}

/// Scan access keeps the metered lanes proportional to the workspace; the
/// posting index an earlier query may build would charge candidates only and
/// make these budgets non-binding.
fn scan_only_run(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> DetailedCodeQueryResult {
    execute_code_query_with_access_mode(
        analyzer,
        query,
        limits,
        StructuralAccessMode::ScanOnly,
        false,
    )
    .expect("scan access is always available")
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_union_retries_a_starved_first_branch() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    skewed_two_language_workspace(&root);
    let analyzer = two_language_analyzer(&root);

    // Calibrate: the union's total fact budget is exactly what the two
    // branches cost on their own, so only the fair split can truncate.
    let mut branch_facts = Vec::new();
    let mut branch_identities = Vec::new();
    for language in ["rust", "python"] {
        let query = CodeQuery::from_json(&json!({
            "languages": [language],
            "match": { "kind": "function" },
            "limit": 1000
        }))
        .expect("branch query");
        let run = scan_only_run(&analyzer, &query, CodeQueryExecutionLimits::default());
        assert!(!run.result.truncated, "{:?}", run.result.diagnostics);
        branch_facts.push(usize::try_from(run.work.fact_nodes).expect("facts fit usize"));
        branch_identities.push(result_identities(&run.result));
    }
    let total_facts = branch_facts[0].saturating_add(branch_facts[1]);
    assert!(
        branch_facts[0] > total_facts.div_ceil(2),
        "the first branch must not fit inside its half share: {branch_facts:?}"
    );

    let union = CodeQuery::from_json(&json!({
        "union": [functions_in("rust"), functions_in("python")],
        "limit": 1000
    }))
    .expect("union query");
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: total_facts,
        ..CodeQueryExecutionLimits::default()
    };

    let detailed = scan_only_run(&analyzer, &union, limits);

    assert!(
        !detailed.result.truncated,
        "{:?}",
        detailed.result.diagnostics
    );
    assert!(
        !detailed.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        detailed.result.diagnostics
    );
    let mut expected = branch_identities.concat();
    expected.sort_by_key(ToString::to_string);
    assert_eq!(result_identities(&detailed.result), expected);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn sequential_union_retry_keeps_reporting_genuine_exhaustion() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    skewed_two_language_workspace(&root);
    let analyzer = two_language_analyzer(&root);
    let probe = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": { "kind": "function" },
        "limit": 1000
    }))
    .expect("probe query");
    let probe_run = scan_only_run(&analyzer, &probe, CodeQueryExecutionLimits::default());
    assert!(!probe_run.result.truncated);
    let rust_facts = usize::try_from(probe_run.work.fact_nodes).expect("facts fit usize");

    let union = CodeQuery::from_json(&json!({
        "union": [functions_in("rust"), functions_in("python")],
        "limit": 1000
    }))
    .expect("union query");
    // Half of the first branch's own scan: no redistribution completes it.
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: rust_facts / 2,
        ..CodeQueryExecutionLimits::default()
    };

    let detailed = scan_only_run(&analyzer, &union, limits);

    assert!(detailed.result.truncated);
    assert!(
        detailed.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        detailed.result.diagnostics
    );
    assert!(
        usize::try_from(detailed.work.fact_nodes).expect("facts fit usize") <= rust_facts,
        "a retry must not spend more than the branch's own uncapped scan"
    );
}

#[test]
fn arity_predicate_selects_a_call_overload_by_argument_count() {
    // The OWASP Benchmark failure in miniature: a no-arg execute() shares its
    // name with execute(String). A name-only selector binds both; the arity
    // predicate keeps just the intended overload.
    let source = "public class Sink {\n\
        \x20   void run(java.sql.Statement stmt, String sql) throws Exception {\n\
        \x20       stmt.execute();\n\
        \x20       stmt.execute(sql);\n\
        \x20   }\n\
        }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "Sink.java")
        .write(source)
        .expect("write java source");
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(root, Language::Java)),
        AnalyzerConfig::default(),
    )
    .expect("ephemeral workspace should build");

    let match_texts = |query_source: &str| -> Vec<String> {
        let query = CodeQuery::from_source(query_source).expect("arity selector should parse");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
        .results
        .into_iter()
        .map(|item| match item.value {
            CodeQueryResultValue::StructuralMatch { value } => value.text,
            other => panic!("expected a structural match, got {other:?}"),
        })
        .collect()
    };

    // Baseline: the name-only selector binds both overloads.
    let both = match_texts(r#"(language java (call :callee (name "execute")))"#);
    assert_eq!(both.len(), 2, "{both:?}");

    // Arity 1 keeps only the one-argument call -- the overload carrying the
    // SQL string -- and drops the no-arg execute() that aborted binding.
    let one_arg = match_texts(r#"(language java (call :callee (name "execute") :arity 1))"#);
    assert_eq!(one_arg.len(), 1, "{one_arg:?}");
    assert!(one_arg[0].contains("execute(sql)"), "{one_arg:?}");

    // Arity 0 keeps only the no-arg overload.
    let zero_arg = match_texts(r#"(language java (call :callee (name "execute") (arity 0)))"#);
    assert_eq!(zero_arg.len(), 1, "{zero_arg:?}");
    assert!(zero_arg[0].contains("execute()"), "{zero_arg:?}");

    // An open-ended ">= 1 argument" range binds the same single overload, so a
    // sink can demand at least one operand without naming an exact arity.
    let at_least_one =
        match_texts(r#"(language java (call :callee (name "execute") (arity :min 1)))"#);
    assert_eq!(at_least_one.len(), 1, "{at_least_one:?}");
    assert!(at_least_one[0].contains("execute(sql)"), "{at_least_one:?}");
}

#[test]
fn callable_containment_excludes_go_package_initializers() {
    let source = r#"package main

import (
    "fmt"
    "os"
)

var packageFile, _ = os.Open("package.xlsx")

func localMisuse() string {
    file, _ := os.Open("local.xlsx")
    return file.Name()
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(
        r#"(language go
          (inside-decl (callable)
            (inside (assignment)
              (call :callee (name "Open") :receiver (identifier)))))"#,
    )
    .expect("callable-scoped Go query should parse");

    let matches = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
    .results
    .into_iter()
    .map(|item| match item.value {
        CodeQueryResultValue::StructuralMatch { value } => value.text,
        other => panic!("expected a structural match, got {other:?}"),
    })
    .collect::<Vec<_>>();

    assert_eq!(matches, vec!["os.Open(\"local.xlsx\")"]);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn flow_state_replays_the_exact_artifact_behind_result_handles() {
    use brokk_bifrost_core::analyzer::structural::flow_state::{FlowStateAxis, StateEventClass};

    let source = r#"package main

import "os"

func inspect(path string) bool {
    info, _ := os.Stat(path)
    return info.IsDir()
}

func unrelated(input int) int {
    value := input
    return value
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", source)
        .build();
    let first_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let exact_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("main.go");
    let cancellation = CancellationToken::default();
    let mut flow_cache = super::super::flow_state::FlowStateTraversalCache::default();

    // Populate the traversal cache from a distinct analyzer allocation with
    // the same durable artifact key. This is the deterministic form of the
    // cache-pressure seam: equal keys do not make allocation-scoped handles
    // interchangeable.
    let stale_state = flow_cache.for_file(&first_workspace, &file, Some(&cancellation));
    let mut budget = SemanticBudget::default();
    let exact_outcome = exact_workspace
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("Go artifact materialization");
    let exact_artifact = exact_outcome
        .available_value()
        .cloned()
        .expect("Go artifact remains available");
    let exact_state = flow_cache.for_materialized_file(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        Some(&cancellation),
    );
    assert!(
        !Arc::ptr_eq(&stale_state, &exact_state),
        "an unbound cache entry must be replaced by exact-artifact state"
    );
    let exact_hit = flow_cache.for_materialized_file(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        Some(&cancellation),
    );
    assert!(
        Arc::ptr_eq(&exact_state, &exact_hit),
        "the same outcome and artifact allocation reuse full-file state"
    );
    let unknown_state = flow_cache.for_materialized_file(
        &exact_workspace,
        &file,
        crate::analyzer::semantic::SemanticOutcome::Unknown {
            partial: Some(Arc::clone(&exact_artifact)),
            work: exact_outcome.work(),
        },
        Some(&cancellation),
    );
    assert!(
        !Arc::ptr_eq(&exact_state, &unknown_state),
        "outcome quality remains part of cached completeness identity"
    );
    assert!(
        !unknown_state
            .completeness
            .covers(FlowStateAxis::BindingEvents),
        "an Unknown outcome cannot reuse Complete flow state"
    );

    let (exact_derivation, procedure, root, aliases) = exact_state
        .procedures
        .iter()
        .find_map(|derivation| {
            let procedure = exact_artifact.procedure_handle(derivation.procedure)?;
            derivation
                .events
                .iter()
                .filter(|event| event.event_class == StateEventClass::Establish)
                .find_map(|event| {
                    let aliases =
                        derivation.exact_local_value_alias_closure(&procedure, &[event.event]);
                    let reads_info = aliases.reads.iter().filter(|read| {
                        let site = &derivation.event(**read).site.range;
                        source.get(site.start_byte..site.end_byte) == Some("info")
                    });
                    (reads_info.count() == 1)
                        .then(|| (derivation, procedure.clone(), event.event, aliases))
                })
        })
        .expect("the os.Stat info result has one structured read");
    assert!(!aliases.proof_open);
    assert_eq!(aliases.reads.len(), 1);

    let scoped_state = flow_cache.for_materialized_procedure(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        &procedure,
        Some(&cancellation),
    );
    let [scoped_derivation] = scoped_state.procedures.as_slice() else {
        panic!("one procedure-scoped derivation is cached: {scoped_state:#?}");
    };
    assert_eq!(scoped_derivation.procedure, procedure.id());
    assert_eq!(scoped_derivation.events, exact_derivation.events);
    assert_eq!(scoped_derivation.relations, exact_derivation.relations);
    assert!(
        exact_state.procedures.len() > scoped_state.procedures.len(),
        "the full-file and procedure scopes must remain distinct"
    );
    assert!(
        !Arc::ptr_eq(&exact_state, &scoped_state),
        "the procedure cache entry must not reuse a full-file derivation"
    );
    let scoped_hit = flow_cache.for_materialized_procedure(
        &exact_workspace,
        &file,
        exact_outcome.clone(),
        &procedure,
        Some(&cancellation),
    );
    assert!(
        Arc::ptr_eq(&scoped_state, &scoped_hit),
        "the same procedure scope and artifact allocation reuse state"
    );

    let mut foreign_budget = SemanticBudget::default();
    let foreign_outcome = first_workspace
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut foreign_budget, &cancellation),
        )
        .expect("foreign Go artifact materialization");
    let foreign_procedure = foreign_outcome
        .available_value()
        .expect("foreign Go artifact remains available")
        .procedure_handle(procedure.id())
        .expect("same durable procedure exists in the foreign allocation");
    let foreign_rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        flow_cache.for_materialized_procedure(
            &exact_workspace,
            &file,
            exact_outcome,
            &foreign_procedure,
            Some(&cancellation),
        )
    }));
    assert!(
        foreign_rejected.is_err(),
        "a populated same-id cache entry cannot accept a foreign artifact handle"
    );

    let stale_derivation = stale_state
        .procedures
        .iter()
        .find(|candidate| candidate.procedure == exact_derivation.procedure)
        .expect("both allocations lower the same procedure");
    let root_site = &exact_derivation.event(root).site;
    let stale_root = stale_derivation
        .events
        .iter()
        .find(|event| {
            event.event_class == StateEventClass::Establish && event.site.range == root_site.range
        })
        .expect("both allocations lower the same result establishment");
    let stale_aliases =
        stale_derivation.exact_local_value_alias_closure(&procedure, &[stale_root.event]);
    assert!(
        stale_aliases.proof_open,
        "a same-key derivation from another allocation cannot validate exact handles"
    );
}

fn execute_conditional_result_contract_fixture(source: &str) -> CodeQueryResult {
    execute_conditional_result_contract_files(&[("main.go", source)])
}

fn execute_conditional_result_contract_files(files: &[(&str, &str)]) -> CodeQueryResult {
    execute_conditional_result_contract_files_with_operation(files, "result_contract_uses")
}

fn execute_conditional_result_contract_files_with_operation(
    files: &[(&str, &str)],
    operation: &str,
) -> CodeQueryResult {
    let mut project = InlineTestProject::with_language(Language::Go);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-conditional-result-contract",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-conditional-result-contract",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.conditional-result-contract",
            "activation": [{}],
            "payload": {
                "kind": "procedure_summaries",
                "summaries": [
                    {
                        "id": "os.open",
                        "target": {
                            "path": "src/os/file.go",
                            "symbol": "os.Open(name string)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_result_count": 2,
                        "transfers": [],
                        "effects": [],
                        "result_contracts": [{
                            "result_ordinal": 0,
                            "condition_result_ordinal": 1,
                            "predicate": "null",
                            "result_success_predicate": "non_null",
                            "member_contracts": [
                                {
                                    "member": "Name",
                                    "parameter_count": 0,
                                    "completeness": "complete",
                                    "preconditions": [{
                                        "input": { "kind": "receiver" },
                                        "predicate": "non_null"
                                    }],
                                    "declared_effects": []
                                },
                                {
                                    "member": "Use",
                                    "parameter_count": 1,
                                    "completeness": "complete",
                                    "preconditions": [{
                                        "input": { "kind": "receiver" },
                                        "predicate": "non_null"
                                    }],
                                    "declared_effects": []
                                },
                                {
                                    "member": "UseTwo",
                                    "parameter_count": 2,
                                    "completeness": "complete",
                                    "preconditions": [{
                                        "input": { "kind": "receiver" },
                                        "predicate": "non_null"
                                    }],
                                    "declared_effects": []
                                }
                            ]
                        }]
                    },
                    {
                        "id": "errors.is",
                        "target": {
                            "path": "src/errors/wrap.go",
                            "symbol": "errors.Is(err, target error)",
                            "has_receiver": false,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_result_refinements": [{
                            "result_ordinal": 0,
                            "outcome": false,
                            "parameter_ordinal": 0,
                            "predicate": "null",
                            "proof_effect": "does_not_establish"
                        }]
                    },
                    {
                        "id": "errors.as",
                        "target": {
                            "path": "src/errors/wrap.go",
                            "symbol": "errors.As(err error, target any)",
                            "has_receiver": false,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_indirect_writes": [{
                            "result_ordinal": 0,
                            "outcome": true,
                            "parameter_ordinal": 1,
                            "target": "pointee"
                        }]
                    },
                    {
                        "id": "os-exec.exit-error-exit-code",
                        "target": {
                            "path": "src/os/exec/exec.go",
                            "symbol": "os/exec.ExitError.ExitCode()",
                            "has_receiver": true,
                            "parameter_count": 0
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "receiver" },
                            "predicate": "non_null"
                        }]
                    },
                    {
                        "id": "require.no-error",
                        "target": {
                            "path": "require/require.go",
                            "symbol": "github.com/stretchr/testify/require.NoError(t TestingT, err error, msgAndArgs ...interface{})",
                            "has_receiver": false,
                            "variadic": true,
                            "parameter_count": 3
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "normal_return_refinements": [{
                            "parameter_ordinal": 1,
                            "predicate": "null"
                        }]
                    },
                    {
                        "id": "assert.no-error",
                        "target": {
                            "path": "assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert.NoError(t TestingT, err error, msgAndArgs ...interface{})",
                            "has_receiver": false,
                            "variadic": true,
                            "parameter_count": 3
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_result_refinements": [
                            {
                                "result_ordinal": 0,
                                "outcome": true,
                                "parameter_ordinal": 1,
                                "predicate": "null",
                                "proof_effect": "establishes"
                            },
                            {
                                "result_ordinal": 0,
                                "outcome": false,
                                "parameter_ordinal": 1,
                                "predicate": "null",
                                "proof_effect": "does_not_establish"
                            }
                        ]
                    },
                    {
                        "id": "predicate.is-nil",
                        "target": {
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.IsNil(value error)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "conditional_result_refinements": [{
                            "result_ordinal": 0,
                            "outcome": true,
                            "parameter_ordinal": 0,
                            "predicate": "null",
                            "proof_effect": "establishes"
                        }]
                    },
                    {
                        "id": "predicate.checked",
                        "target": {
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.Checked(value error)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_result_count": 1,
                        "transfers": [],
                        "effects": [],
                        "normal_return_refinements": [{
                            "parameter_ordinal": 0,
                            "predicate": "null"
                        }]
                    },
                    {
                        "id": "consumer.require",
                        "target": {
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Require(label string, file *os.File)",
                            "has_receiver": false,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "parameter", "ordinal": 1 },
                            "predicate": "non_null"
                        }]
                    },
                    {
                        "id": "consumer.observe",
                        "target": {
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Observe(file *os.File)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": []
                    },
                    {
                        "id": "os.file.consume",
                        "target": {
                            "path": "src/os/file.go",
                            "symbol": "os.File.Consume(file *os.File)",
                            "has_receiver": true,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "parameter", "ordinal": 0 },
                            "predicate": "non_null"
                        }]
                    },
                    {
                        "id": "consumer.require-many",
                        "target": {
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.RequireMany(file *os.File, rest ...*os.File)",
                            "has_receiver": false,
                            "variadic": true,
                            "parameter_count": 2
                        },
                        "completeness": "complete",
                        "transfers": [],
                        "effects": [],
                        "preconditions": [{
                            "input": { "kind": "parameter", "ordinal": 0 },
                            "predicate": "non_null"
                        }]
                    }
                ]
            }
        }]
    }"#;
    let declaration_pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-conditional-result-contract-declarations",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-conditional-result-contract-declarations",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "partial",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.conditional.declarations",
            "activation": [{}],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    {
                        "id": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "os",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["os"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os"
                        }
                    },
                    {
                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "os.File",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "struct{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.File"
                        }
                    },
                    {
                        "id": "type.1eef3afbc23b6c534c6d054fc877197155006d5fdbdce518890a99d07a1f85d8",
                        "name": "errors",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["errors"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "errors/errors.go",
                            "symbol": "errors"
                        }
                    },
                    {
                        "id": "type.66dc4abf1c89685d48c53a4f98f69a160a61abbfad9f955c25a70a2bab3b79f8",
                        "name": "github.com/stretchr/testify/require",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["require"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/require/require.go",
                            "symbol": "github.com/stretchr/testify/require"
                        }
                    },
                    {
                        "id": "type.test.rql.os-exec.module",
                        "name": "os/exec",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["exec"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/exec/exec.go",
                            "symbol": "os/exec"
                        }
                    },
                    {
                        "id": "type.test.rql.os-exec.exit-error",
                        "name": "os/exec.ExitError",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "struct{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/exec/exec.go",
                            "symbol": "os/exec.ExitError"
                        }
                    },
                    {
                        "id": "type.253e4ec2c267b0a4d8e7ffbcb21aa17d591dd6f2557d12e01e32ba70dbe923b9",
                        "name": "github.com/stretchr/testify/require.TestingT",
                        "type_kind": "interface",
                        "visibility": "public",
                        "is_abstract": true,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "interface{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/require/require.go",
                            "symbol": "github.com/stretchr/testify/require.TestingT"
                        }
                    },
                    {
                        "id": "type.e7c2e010e38d28ef033ed9e87af4fc76e9606dc0ea77ccdfcf401bb586f3033b",
                        "name": "github.com/stretchr/testify/assert",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["assert"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert"
                        }
                    },
                    {
                        "id": "type.a72411f16a9045f73eb852c72f53af4caada3eb3eeb9b350e4eef9665e913d08",
                        "name": "github.com/stretchr/testify/assert.TestingT",
                        "type_kind": "interface",
                        "visibility": "public",
                        "is_abstract": true,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "interface{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert.TestingT"
                        }
                    },
                    {
                        "id": "type.test.rql.predicate.module",
                        "name": "example.com/predicate",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["predicate"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate"
                        }
                    },
                    {
                        "id": "type.test.rql.consumer.module",
                        "name": "example.com/app/consumer",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["consumer"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer"
                        }
                    }
                ],
                "members": [
                    {
                        "id": "member.e969c07a9215c885c075e9f2767d17d39f10922eb0ff1394d8222dd7dc40f38e",
                        "owner": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "Open",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "name",
                                "type": {
                                    "kind": "named",
                                    "name": "string",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }],
                            "returns": {
                                "kind": "tuple",
                                "elements": [
                                    {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                ]
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.Open"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.name",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "Name",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [],
                            "returns": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.Name"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.use",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "Use",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "value",
                                "type": {
                                    "kind": "named",
                                    "name": "string",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.Use"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.use_two",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "UseTwo",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "first",
                                    "type": {
                                        "kind": "named",
                                        "name": "string",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "second",
                                    "type": {
                                        "kind": "named",
                                        "name": "string",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ]
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.UseTwo"
                        }
                    },
                    {
                        "id": "member.test.rql.os.file.consume",
                        "owner": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "Consume",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "file",
                                "type": {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/file.go",
                            "symbol": "os.File.Consume"
                        }
                    },
                    {
                        "id": "member.f5464663c23ef077afc3ec4cc51c586c1df1ca48fbf68482840875b617208e4b",
                        "owner": "type.1eef3afbc23b6c534c6d054fc877197155006d5fdbdce518890a99d07a1f85d8",
                        "name": "Is",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "target",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "errors/errors.go",
                            "symbol": "errors.Is"
                        }
                    },
                    {
                        "id": "member.9fd565756088ca91d69be236b28ee436db05c9fa5b505d121a26fcf7d151992d",
                        "owner": "type.1eef3afbc23b6c534c6d054fc877197155006d5fdbdce518890a99d07a1f85d8",
                        "name": "As",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "target",
                                    "type": {
                                        "kind": "named",
                                        "name": "any",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "errors/errors.go",
                            "symbol": "errors.As"
                        }
                    },
                    {
                        "id": "member.3de3ee8d4154a940e5cf65b19f308ef5e6ba51eb72c419b7fc1294389ba3bdfb",
                        "owner": "type.66dc4abf1c89685d48c53a4f98f69a160a61abbfad9f955c25a70a2bab3b79f8",
                        "name": "NoError",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "t",
                                    "type": {
                                        "kind": "declared",
                                        "id": "type.253e4ec2c267b0a4d8e7ffbcb21aa17d591dd6f2557d12e01e32ba70dbe923b9",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "msgAndArgs",
                                    "type": {
                                        "kind": "named",
                                        "name": "interface{}",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": true
                                }
                            ]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/require/require.go",
                            "symbol": "github.com/stretchr/testify/require.NoError"
                        }
                    },
                    {
                        "id": "member.test.rql.os-exec.exit-error.exit-code",
                        "owner": "type.test.rql.os-exec.exit-error",
                        "name": "ExitCode",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [],
                            "returns": {
                                "kind": "named",
                                "name": "int",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "receiver": { "pointer": true },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/exec/exec.go",
                            "symbol": "os/exec.ExitError.ExitCode"
                        }
                    },
                    {
                        "id": "member.a122fd9a4bbd575d30d356130a13f0d70da5f107d578c96a97c583983c397b3f",
                        "owner": "type.e7c2e010e38d28ef033ed9e87af4fc76e9606dc0ea77ccdfcf401bb586f3033b",
                        "name": "NoError",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "t",
                                    "type": {
                                        "kind": "declared",
                                        "id": "type.a72411f16a9045f73eb852c72f53af4caada3eb3eeb9b350e4eef9665e913d08",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "err",
                                    "type": {
                                        "kind": "named",
                                        "name": "error",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "msgAndArgs",
                                    "type": {
                                        "kind": "named",
                                        "name": "interface{}",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": true
                                }
                            ],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "testify/assert/assertions.go",
                            "symbol": "github.com/stretchr/testify/assert.NoError"
                        }
                    },
                    {
                        "id": "member.test.rql.predicate.is_nil",
                        "owner": "type.test.rql.predicate.module",
                        "name": "IsNil",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "value",
                                "type": {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }],
                            "returns": {
                                "kind": "named",
                                "name": "bool",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.IsNil"
                        }
                    },
                    {
                        "id": "member.test.rql.predicate.checked",
                        "owner": "type.test.rql.predicate.module",
                        "name": "Checked",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "value",
                                "type": {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                },
                                "optional": false,
                                "variadic": false
                            }],
                            "returns": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            }
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "predicate/predicate.go",
                            "symbol": "example.com/predicate.Checked"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.require",
                        "owner": "type.test.rql.consumer.module",
                        "name": "Require",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "label",
                                    "type": {
                                        "kind": "named",
                                        "name": "string",
                                        "arguments": [],
                                        "nullable": false
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "file",
                                    "type": {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    "optional": false,
                                    "variadic": false
                                }
                            ]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Require"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.observe",
                        "owner": "type.test.rql.consumer.module",
                        "name": "Observe",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "file",
                                "type": {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Observe"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.unreviewed",
                        "owner": "type.test.rql.consumer.module",
                        "name": "Unreviewed",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [{
                                "name": "file",
                                "type": {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                "optional": false,
                                "variadic": false
                            }]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.Unreviewed"
                        }
                    },
                    {
                        "id": "member.test.rql.consumer.require_many",
                        "owner": "type.test.rql.consumer.module",
                        "name": "RequireMany",
                        "member_kind": "function",
                        "visibility": "public",
                        "is_static": true,
                        "is_abstract": false,
                        "is_virtual": false,
                        "signature": {
                            "type_parameters": [],
                            "parameters": [
                                {
                                    "name": "file",
                                    "type": {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    "optional": false,
                                    "variadic": false
                                },
                                {
                                    "name": "rest",
                                    "type": {
                                        "kind": "pointer",
                                        "element": {
                                            "kind": "declared",
                                            "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                            "arguments": [],
                                            "nullable": false
                                        }
                                    },
                                    "optional": false,
                                    "variadic": true
                                }
                            ]
                        },
                        "aliases": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "consumer/consumer.go",
                            "symbol": "example.com/app/consumer.RequireMany"
                        }
                    }
                ]
            }
        }]
    }"#;
    let pack = compile_source(SourceFormat::Json, pack_source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| {
            panic!("conditional result-contract pack failed: {diagnostics:#?}")
        });
    let declaration_pack = compile_source(
        SourceFormat::Json,
        declaration_pack_source,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("conditional declaration pack failed: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-conditional-result-contract".to_owned(),
            },
        )
        .expect("register conditional result-contract pack");
    catalog
        .register_session_pack(
            &declaration_pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-conditional-result-contract-declarations".to_owned(),
            },
        )
        .expect("register exact conditional-result declarations");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "test conditional result-contract pack activates: {activation:#?}"
    );

    let query = CodeQuery::from_json(&if operation == "nilness_operations" {
        json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": "exitCode" },
            "steps": [
                { "op": "procedure_of" },
                { "op": operation }
            ],
            "result_detail": "full"
        })
    } else {
        json!({
            "languages": ["go"],
            "match": { "kind": "call", "callee": { "name": "Open" } },
            "steps": [
                { "op": "call_shape" },
                { "op": "call_result_contracts" },
                { "op": operation }
            ],
            "result_detail": "full"
        })
    })
    .expect("conditional result-contract use query");
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn direct_result_contracts_preserve_raw_shape_and_prove_result_guards() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "os"

func unchecked(path string) os.File {
    file, _ := os.Open(path)
    return *file
}

func checked(path string) os.File {
    file, _ := os.Open(path)
    if file == nil { return os.File{} }
    return *file
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-direct-result-contract",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.7, <1.0.0", "toolchains": [] },
        "provenance": { "source": "test:rql-direct-result-contract", "revision": "reviewed" },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.direct-result-contract",
            "activation": [{}],
            "payload": {
                "kind": "procedure_summaries",
                "summaries": [{
                    "id": "os.open.direct",
                    "target": {
                        "path": "src/os/file.go",
                        "symbol": "os.Open(name string)",
                        "has_receiver": false,
                        "parameter_count": 1
                    },
                    "completeness": "complete",
                    "normal_result_count": 2,
                    "transfers": [],
                    "result_contracts": [{
                        "result_ordinal": 0,
                        "result_success_predicate": "non_null"
                    }]
                }]
            }
        }]
    }"#;
    let declaration_pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-direct-result-contract-declarations",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.7, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-direct-result-contract-declarations",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "partial",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.direct-result-contract.declarations",
            "activation": [{}],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    {
                        "id": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "os",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["os"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os"
                        }
                    },
                    {
                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "os.File",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.File"
                        }
                    }
                ],
                "members": [{
                    "id": "member.e969c07a9215c885c075e9f2767d17d39f10922eb0ff1394d8222dd7dc40f38e",
                    "owner": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                    "name": "Open",
                    "member_kind": "function",
                    "visibility": "public",
                    "is_static": true,
                    "is_abstract": false,
                    "is_virtual": false,
                    "signature": {
                        "type_parameters": [],
                        "parameters": [{
                            "name": "name",
                            "type": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            },
                            "optional": false,
                            "variadic": false
                        }],
                        "returns": {
                            "kind": "tuple",
                            "elements": [
                                {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                }
                            ]
                        }
                    },
                    "aliases": [],
                    "locator": {
                        "kind": "artifact",
                        "path": "os/os.go",
                        "symbol": "os.Open"
                    }
                }],
                "relations": []
            }
        }]
    }"#;
    let pack = compile_source(SourceFormat::Json, pack_source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| {
            panic!("direct result-contract pack failed: {diagnostics:#?}")
        });
    let declaration_pack = compile_source(
        SourceFormat::Json,
        declaration_pack_source,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| {
        panic!("direct result-contract declaration pack failed: {diagnostics:#?}")
    });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-direct-result-contract".to_owned(),
            },
        )
        .expect("register direct result-contract pack");
    catalog
        .register_session_pack(
            &declaration_pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-direct-result-contract-declarations".to_owned(),
            },
        )
        .expect("register direct result-contract declarations");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "test direct result-contract pack activates: {activation:#?}"
    );

    let contracts_query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" }
        ],
        "result_detail": "full"
    }))
    .expect("direct result-contract query");
    let contracts = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &contracts_query,
    );
    assert_eq!(
        contracts.completion(),
        CodeQueryCompletion::Complete,
        "{contracts:#?}"
    );
    assert_eq!(contracts.results.len(), 2, "{contracts:#?}");
    for item in &contracts.results {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("call_result_contracts returns its typed row: {item:#?}");
        };
        assert_eq!(value.result_ordinal, Some(0), "{value:#?}");
        assert_eq!(value.condition_result_ordinal, None, "{value:#?}");
        assert_eq!(value.predicate, None, "{value:#?}");
        assert_eq!(
            value.result_success_predicate,
            Some("non_null"),
            "{value:#?}"
        );
    }

    let uses_query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_operation_uses" }
        ],
        "result_detail": "full"
    }))
    .expect("direct result-contract use query");
    let uses = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &uses_query,
    );
    assert_eq!(
        uses.completion(),
        CodeQueryCompletion::Complete,
        "{uses:#?}"
    );
    let mut rows = uses
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                panic!("result_contract_operation_uses returns its typed row: {item:#?}");
            };
            assert_eq!(value.condition_result_ordinal, None, "{value:#?}");
            assert_eq!(value.acquisition_predicate, None, "{value:#?}");
            assert_eq!(
                value.result_success_predicate,
                Some("non_null"),
                "{value:#?}"
            );
            assert_eq!(value.required_predicate, Some("non_null"), "{value:#?}");
            assert_eq!(value.use_kind, "dereference", "{value:#?}");
            (value.range.start_line, value.guard)
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|(line, _)| *line);
    assert_eq!(rows, [(7, "unguarded"), (13, "guarded")], "{uses:#?}");
}

fn assert_single_open_unknown_result_contract(result: &CodeQueryResult) {
    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 0, "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
    assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

fn assert_single_guarded_open_unknown_result_contract(result: &CodeQueryResult) {
    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 1, "{value:#?}");
    assert_eq!(
        value.success_guard_coverage,
        Some(EffectCoverage::Exhaustive),
        "{value:#?}"
    );
    assert_eq!(value.success_guard_edges.len(), 1, "{value:#?}");
    assert_eq!(value.possible_success_guard_edges.len(), 1, "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
    assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

fn assert_single_exhaustive_violated_result_contract(result: &CodeQueryResult) {
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 0, "{value:#?}");
    assert_eq!(
        value.success_guard_coverage,
        Some(EffectCoverage::Exhaustive),
        "{value:#?}"
    );
    assert!(value.success_guard_edges.is_empty(), "{value:#?}");
    assert!(value.possible_success_guard_edges.is_empty(), "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(
        value.use_validation_coverage,
        Some("exhaustive"),
        "{value:#?}"
    );
}

fn assert_single_exhaustive_satisfied_result_contract(result: &CodeQueryResult) {
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 0, "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(0), "{value:#?}");
    assert_eq!(value.use_validation, Some("satisfied"), "{value:#?}");
    assert_eq!(
        value.use_validation_coverage,
        Some("exhaustive"),
        "{value:#?}"
    );
}

fn assert_open_unknown_result_contract_uses(
    result: &CodeQueryResult,
    expected_use_counts: &[usize],
) {
    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    assert_eq!(
        result.results.len(),
        expected_use_counts.len(),
        "{result:#?}"
    );
    for (item, expected_use_count) in result.results.iter().zip(expected_use_counts) {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("result-contract wrapper returns its typed row: {item:#?}")
        };
        assert_eq!(value.coverage, "exhaustive", "{value:#?}");
        assert_eq!(
            value.result_use_count,
            Some(*expected_use_count),
            "{value:#?}"
        );
        assert_eq!(value.success_guard_count, 0, "{value:#?}");
        assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
        assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
        assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
    }
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn go_exact_assignment_converted_result_and_condition_bindings_are_proven() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func reusedCondition(path string) string {
    var err error
    file, err := os.Open(path)
    if err != nil { return "" }
    return file.Name()
}

func reusedResultAndCondition(path string) string {
    var file *os.File
    var err error
    file, err = os.Open(path)
    if err != nil { return "" }
    return file.Name()
}
"#,
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_eq!(result.results.len(), 2, "{result:#?}");
    for item in &result.results {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("result-contract wrapper returns its typed row: {item:#?}")
        };
        assert_eq!(value.coverage, "exhaustive", "{value:#?}");
        assert_eq!(value.result_use_count, Some(1), "{value:#?}");
        assert_eq!(value.success_guard_count, 1, "{value:#?}");
        assert_eq!(value.unguarded_result_use_count, Some(0), "{value:#?}");
        assert_eq!(value.use_validation, Some("satisfied"), "{value:#?}");
        assert_eq!(
            value.use_validation_coverage,
            Some("exhaustive"),
            "{value:#?}"
        );
        assert_eq!(
            value.success_guard_coverage,
            Some(EffectCoverage::Exhaustive),
            "{value:#?}"
        );
        assert_eq!(value.success_guard_edges.len(), 1, "{value:#?}");
        assert_eq!(value.possible_success_guard_edges.len(), 1, "{value:#?}");
    }
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn go_assignment_converted_field_and_index_results_stay_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

type holder struct { file *os.File }

func storeField(target *holder, path string) string {
    target.file, _ = os.Open(path)
    return target.file.Name()
}

func storeIndex(target []*os.File, path string) {
    target[0], _ = os.Open(path)
}
"#,
    );

    assert_open_unknown_result_contract_uses(&result, &[1, 0]);
    for item in &result.results {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("result-contract wrapper returns its typed row: {item:#?}")
        };
        assert_eq!(
            value.success_guard_coverage,
            Some(EffectCoverage::Open),
            "the converted memory result can hide an unpositioned success guard: {value:#?}"
        );
        assert!(value.success_guard_edges.is_empty(), "{value:#?}");
        assert!(
            value.possible_success_guard_edges.is_empty(),
            "this fixture has no positioned null comparison to retain: {value:#?}"
        );
    }
}

#[test]
fn go_defer_capture_is_not_a_direct_assignment_conversion() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "os"

func deferred(path string) {
    file, _ := os.Open(path)
    defer file.Close()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("main.go");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("Go artifact materialization");
    let artifact = outcome
        .available_value()
        .expect("Go artifact remains available");
    let (procedure, defer_capture) = artifact
        .procedures()
        .iter()
        .find_map(|procedure| {
            procedure.points().iter().find_map(|point| {
                point.events.iter().find_map(|event| match &event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source: _,
                        target,
                    } if procedure.value(*target).is_some_and(|value| {
                        matches!(
                            &value.kind,
                            SemanticValueKind::LanguageDefined(kind)
                                if kind.as_ref() == "go.defer_capture"
                        )
                    }) =>
                    {
                        Some((procedure, *target))
                    }
                    _ => None,
                })
            })
        })
        .expect("defer receiver capture has structured language-defined flow");

    assert!(
        !super::super::effects::is_go_assignment_conversion_target(procedure, defer_capture),
        "a defer capture must not be mistaken for a Go assignment conversion"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn go_nilness_operations_project_scalar_pointer_facts() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type item struct { field int }

func run(flag bool) int {
    var maybe *item
    var guarded *item
    if flag { maybe = &item{} }
    if guarded == nil { guarded = &item{} }
    return maybe.field + guarded.field
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "nilness_operations" }
        ],
        "result_detail": "full"
    }))
    .expect("nilness operation query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let mut facts = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::NilnessOperation { value } = &item.value else {
                panic!("nilness_operations returns its typed row: {item:#?}");
            };
            assert_eq!(value.use_kind, "field");
            assert_eq!(value.proof, "exact");
            (value.range.start_line, value.fact)
        })
        .collect::<Vec<_>>();
    facts.sort_unstable();
    assert_eq!(facts, [(10, "maybe_nil"), (10, "non_nil")], "{result:#?}");
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn go_nilness_operations_apply_errors_as_write_only_on_true() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[(
            "main.go",
            r#"package main

import (
    "errors"
    "os/exec"
)

func exitCode(err error) int {
    var exitError *exec.ExitError
    if errors.As(err, &exitError) {
        return exitError.ExitCode()
    }
    return exitError.ExitCode()
}

"#,
        )],
        "nilness_operations",
    );
    let mut operations = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::NilnessOperation { value } = &item.value else {
                panic!("nilness_operations returns its typed row: {item:#?}");
            };
            (
                value.range.start_line,
                value.use_kind,
                value.fact,
                value.proof,
            )
        })
        .collect::<Vec<_>>();
    operations.sort_unstable();
    assert_eq!(
        operations,
        [
            (11, "receiver_call", "unknown", "unknown"),
            (13, "receiver_call", "nil", "exact")
        ],
        "the modeled true write invalidates only the true arm: {result:#?}"
    );
}

#[test]
fn go_switch_coverage_projects_closed_and_open_domains() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

func coverage(flag bool, n int, x any) {
    switch flag {
    case true: n++
    case false: n--
    }
    switch flag {
    case true: n++
    }
    switch n {
    case 1: n++
    default: n--
    }
    switch n {
    case 1: n++
    }
    switch {
    case flag: n++
    }
    switch {
    default: n--
    }
    switch v := x.(type) {
    case int: n += v
    default: n--
    }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "coverage" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "switch_coverage" }
        ],
        "result_detail": "full"
    }))
    .expect("switch coverage query");
    assert_eq!(
        query.validate_steps().unwrap(),
        crate::QueryValueKind::SwitchCoverage
    );
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::SwitchCoverage { value } = &item.value else {
                panic!("switch_coverage returns its typed row: {item:#?}");
            };
            assert!(
                !item.provenance.is_empty(),
                "switch row retains its procedure derivation"
            );
            (
                value.range.start_line,
                value.kind,
                value.selector_domain,
                value.verdict,
                value.proof,
                value.reason,
                value.has_true_case,
                value.has_false_case,
                value.default_present,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [
            (
                4,
                "expression",
                "boolean",
                "exhaustive",
                "exact",
                None,
                true,
                true,
                false,
            ),
            (
                8,
                "expression",
                "boolean",
                "non_exhaustive",
                "exact",
                Some("boolean_case_missing"),
                true,
                false,
                false,
            ),
            (
                11,
                "expression",
                "open",
                "exhaustive",
                "exact",
                None,
                false,
                false,
                true,
            ),
            (
                15,
                "expression",
                "open",
                "unknown",
                "unknown",
                Some("selector_domain_open"),
                false,
                false,
                false,
            ),
            (
                18,
                "expressionless",
                "open",
                "unknown",
                "unknown",
                Some("expressionless_without_default"),
                false,
                false,
                false,
            ),
            (
                21,
                "expressionless",
                "open",
                "exhaustive",
                "exact",
                None,
                false,
                false,
                true,
            ),
            (
                24,
                "type",
                "open",
                "unknown",
                "unknown",
                Some("type_switch"),
                false,
                false,
                true,
            ),
        ],
        "{result:#?}"
    );
}

#[test]
fn go_detached_task_transfers_project_arguments_receivers_and_captures() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type worker struct{}
func (w *worker) run(value int) {}
func consume(values ...any) {}

func spawn(w *worker, value int, flag bool) {
    go w.run(value)
    capturedWorker := w
    capturedValue := value
    go func() { consume(capturedWorker, capturedValue) }()
    consume(w)
    defer consume(value)

    var selected *worker
    if flag { selected = &worker{} } else { selected = &worker{} }
    go consume(selected)
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "spawn" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "detached_task_transfers" }
        ],
        "result_detail": "full"
    }))
    .expect("detached task transfer query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::DetachedTaskTransfer { value } = &item.value else {
                panic!("detached_task_transfers returns its typed row: {item:#?}");
            };
            assert_eq!(value.timing, "different_task");
            assert!(!item.provenance.is_empty());
            (
                value.range.start_line,
                value.role,
                value.ordinal,
                value.proof,
                value.coverage,
                value.reason,
                value.object_id.is_some(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        5,
        "ordinary and deferred calls are omitted: {result:#?}"
    );
    assert_eq!(
        rows.iter().map(|row| (row.1, row.2)).collect::<Vec<_>>(),
        [
            ("receiver", None),
            ("argument", Some(0)),
            ("capture", Some(0)),
            ("capture", Some(1)),
            ("argument", Some(0)),
        ],
        "{result:#?}"
    );
    assert!(
        rows[..2].iter().all(|row| row.3 == "exact" && row.6),
        "{result:#?}"
    );
    assert!(
        rows[2..4].iter().all(|row| {
            row.3 == "unknown" && row.4 == "open" && row.5 == Some("object_set_open") && !row.6
        }),
        "scalar immutable captures retain explicit open object identity: {result:#?}"
    );
    assert_eq!(
        (rows[4].3, rows[4].4, rows[4].5, rows[4].6),
        ("unknown", "open", Some("object_identity_ambiguous"), false),
        "{result:#?}"
    );
}

fn assert_exact_safe_concurrent_relations(result: &CodeQueryResult, verdict: &str) {
    assert!(
        !result.results.is_empty(),
        "expected at least one exact {verdict} concurrent relation: {result:#?}"
    );
    let mut found_expected_verdict = false;
    for item in &result.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        found_expected_verdict |= value.verdict == verdict;
        assert_eq!(
            (value.proof, value.coverage),
            ("proven", "exhaustive"),
            "{result:#?}"
        );
        assert_ne!(value.verdict, "conflict", "{result:#?}");
        assert!(value.reasons.is_empty(), "{result:#?}");
    }
    assert!(
        found_expected_verdict,
        "expected an exact {verdict} concurrent relation: {result:#?}"
    );
}

fn assert_no_concurrent_conflicts(result: &CodeQueryResult) {
    for item in &result.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        assert_ne!(value.verdict, "conflict", "{result:#?}");
    }
}

fn find_concurrent_relation(
    result: &CodeQueryResult,
    predicate: impl Fn(&CodeQueryConcurrentAccessConflict) -> bool,
) -> &CodeQueryConcurrentAccessConflict {
    result
        .results
        .iter()
        .find_map(|item| {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
            };
            predicate(value).then_some(value.as_ref())
        })
        .unwrap_or_else(|| panic!("expected concurrent relation was absent: {result:#?}"))
}

#[test]
fn go_concurrent_access_conflicts_project_exact_capture_races() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

func race() int {
    value := 0
    go func() { value = 1 }()
    return value
}

func joinedByChannel() int {
    value := 0
    done := make(chan struct{})
    go func() {
        value = 1
        close(done)
    }()
    <-done
    return value
}

func channel() chan struct{} { return nil }

func ambiguouslyJoined() int {
    value := 0
    sent := channel()
    received := channel()
    go func() {
        value = 1
        close(sent)
    }()
    <-received
    return value
}

func joinedByAllSelectArms() int {
    value := 0
    done := make(chan struct{})
    go func() {
        value = 1
        close(done)
    }()
    select {
    case <-done:
    case _, ok := <-done:
        _ = ok
    }
    return value
}

func selectWithDefaultIsUnjoined() int {
    value := 0
    done := make(chan struct{})
    go func() {
        value = 1
        close(done)
    }()
    select {
    case <-done:
    default:
    }
    return value
}

func selectCancellationShadowsResult(cancelled <-chan struct{}) error {
    var err error
    done := make(chan struct{})
    go func() {
        defer close(done)
        err = nil
    }()
    select {
    case <-cancelled:
        err := error(nil)
        _ = err
        return nil
    case <-done:
    }
    return err
}

func namedResultCancellationRace(cancelled <-chan struct{}, stop bool) (err error) {
    done := make(chan struct{})
    go func() {
        defer close(done)
        if stop {
            return
        }
        err = nil
    }()
    select {
    case <-cancelled:
        return nil
    case <-done:
    }
    return err
}

type cell struct { value int }

func writeCell(value *cell) { value.value = 1 }
func readCell(value *cell) int { return value.value }

func namedHelpers() int {
    value := &cell{}
    go writeCell(value)
    return readCell(value)
}

func distinctHelperObjects() int {
    written := &cell{}
    read := &cell{}
    go writeCell(written)
    return readCell(read)
}

func mutateFreshCell() {
    value := &cell{}
    value.value = 1
}

func perTaskAllocationsAreDistinct() {
    go mutateFreshCell()
    go mutateFreshCell()
}

func mapBackingRace() int {
    values := make(map[int]int)
    go func() { values[0] = 1 }()
    return values[1]
}

func arrayElementsAreDistinct() int {
    values := [2]int{}
    go func() { values[0] = 1 }()
    return values[1]
}

func arrayElementRace() int {
    values := [2]int{}
    go func() { values[0] = 1 }()
    return values[0]
}

func sliceAliasRace() int {
    values := make([]int, 2)
    alias := values
    go func() { alias[0] = 1 }()
    return values[0]
}

func distinctSliceElements() int {
    values := make([]int, 2)
    alias := values
    go func() { alias[0] = 1 }()
    return values[1]
}

var sharedGlobal int

func globalRace() int {
    go func() { sharedGlobal = 1 }()
    return sharedGlobal
}

func copiedScalarArgument() int {
    value := 0
    go func(copy int) { copy = 1 }(value)
    return value
}

type copiedOptions struct { term int }

func writeCopiedOptions(opts copiedOptions) { opts.term = 1 }

func copiedStructArguments() {
    var opts copiedOptions
    go writeCopiedOptions(opts)
    writeCopiedOptions(opts)
}

func childOnlyWrite() {
    value := 0
    go func() { value = 1 }()
}

func accessBeforeSpawn() {
    value := &cell{}
    value.value = 1
    go func() { _ = value.value }()
}

type fieldPair struct { left, right int }

func distinctFields() int {
    value := &fieldPair{}
    go func() { value.left = 1 }()
    return value.right
}

func siblingRace() {
    value := 0
    go func() { value = 1 }()
    go func() { value = 2 }()
}

func nestedRace() {
    value := 0
    go func() {
        go func() { value = 1 }()
        value = 2
    }()
}

func repeatedRace() {
    value := 0
    for index := 0; index < 2; index++ {
        go func() { value++ }()
    }
}

func unknownSliceIndex(first, second int) int {
    values := make([]int, 2)
    alias := values
    go func() { alias[first] = 1 }()
    return values[second]
}

func unknownIndicesOnDistinctSlices(first, second int) int {
    written := make([]int, 2)
    read := make([]int, 2)
    go func() { written[first] = 1 }()
    return read[second]
}

func unknownCell() *cell { return nil }

func unknownObjectAlias() int {
    written := unknownCell()
    read := unknownCell()
    go writeCell(written)
    return readCell(read)
}

func writeLeft(value *fieldPair) { value.left = 1 }
func readRight(value *fieldPair) int { return value.right }

func unknownObjectsDistinctFields() int {
    written := (*fieldPair)(nil)
    read := (*fieldPair)(nil)
    go writeLeft(written)
    return readRight(read)
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "race" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("concurrent access conflict query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
            };
            assert!(!item.provenance.is_empty());
            (
                value.task_relation,
                value.ordering,
                value.protection,
                value.proof,
                value.coverage,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [
            (
                "parent_child",
                "happens_before",
                "unprotected",
                "proven",
                "exhaustive"
            ),
            (
                "parent_child",
                "unordered",
                "unprotected",
                "proven",
                "exhaustive"
            )
        ],
        "{result:#?}"
    );

    let joined_query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "joinedByChannel" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("channel-joined concurrent access query");
    let joined = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &joined_query,
    );
    assert_eq!(
        joined.completion(),
        CodeQueryCompletion::Complete,
        "{joined:#?}"
    );
    assert_exact_safe_concurrent_relations(&joined, "ordered");

    let ambiguous_query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "ambiguouslyJoined" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("ambiguously joined concurrent access query");
    let ambiguous = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &ambiguous_query,
    );
    assert_eq!(
        ambiguous.completion(),
        CodeQueryCompletion::Complete,
        "{ambiguous:#?}"
    );
    let item = ambiguous
        .results
        .iter()
        .find(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict" && value.proof == "open"
            )
        })
        .unwrap_or_else(|| panic!("an open ambiguous synchronization row: {ambiguous:#?}"));
    let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
        panic!("ambiguous synchronization retains its typed row: {item:#?}");
    };
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("open", "open", "open"),
        "{ambiguous:#?}"
    );
    assert_eq!(value.reasons, ["unknown_location"], "{ambiguous:#?}");

    let named_query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "namedHelpers" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("named helper concurrent access query");
    let named = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &named_query,
    );
    assert_eq!(
        named.completion(),
        CodeQueryCompletion::Complete,
        "{named:#?}"
    );
    let value = find_concurrent_relation(&named, |value| value.verdict == "conflict");
    assert_eq!(
        (
            value.task_relation,
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        (
            "parent_child",
            "unordered",
            "unprotected",
            "proven",
            "exhaustive"
        ),
        "{named:#?}"
    );

    let distinct_query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "distinctHelperObjects" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("distinct helper object concurrent access query");
    let distinct = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &distinct_query,
    );
    assert_eq!(
        distinct.completion(),
        CodeQueryCompletion::Complete,
        "{distinct:#?}"
    );
    assert!(distinct.results.is_empty(), "{distinct:#?}");

    let conflicts_for = |name: &str| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("collection concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };
    for name in [
        "mapBackingRace",
        "arrayElementRace",
        "sliceAliasRace",
        "globalRace",
        "siblingRace",
        "nestedRace",
        "repeatedRace",
    ] {
        let result = conflicts_for(name);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        let item = result
            .results
            .iter()
            .find(|item| {
                matches!(
                    &item.value,
                    CodeQueryResultValue::ConcurrentAccessConflict { value }
                        if value.verdict == "conflict"
                )
            })
            .unwrap_or_else(|| panic!("{name} has an exact collection conflict: {result:#?}"));
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("{name} returns its typed conflict: {item:#?}");
        };
        assert_eq!(
            (value.proof, value.coverage),
            ("proven", "exhaustive"),
            "{name}: {result:#?}"
        );
    }
    for name in [
        "arrayElementsAreDistinct",
        "distinctSliceElements",
        "copiedScalarArgument",
        "childOnlyWrite",
        "distinctFields",
        "unknownIndicesOnDistinctSlices",
        "unknownObjectsDistinctFields",
        "perTaskAllocationsAreDistinct",
    ] {
        let result = conflicts_for(name);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        assert_no_concurrent_conflicts(&result);
    }
    for name in [
        "accessBeforeSpawn",
        "joinedByAllSelectArms",
        "selectCancellationShadowsResult",
    ] {
        let result = conflicts_for(name);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        assert_exact_safe_concurrent_relations(&result, "ordered");
    }
    let cancellation_race = conflicts_for("namedResultCancellationRace");
    assert_eq!(
        cancellation_race.completion(),
        CodeQueryCompletion::Complete,
        "{cancellation_race:#?}"
    );
    let value = find_concurrent_relation(&cancellation_race, |value| {
        value.verdict == "conflict" && value.proof == "proven"
    });
    assert_eq!(
        (
            value.first_access,
            value.second_access,
            value.task_relation,
            value.ordering,
            value.protection,
            value.proof,
            value.coverage,
        ),
        (
            "write",
            "write",
            "parent_child",
            "unordered",
            "unprotected",
            "proven",
            "exhaustive",
        ),
        "{cancellation_race:#?}"
    );
    let mut endpoint_lines = [value.first_range.start_line, value.second_range.start_line];
    endpoint_lines.sort_unstable();
    assert_eq!(
        endpoint_lines,
        [87, 91],
        "the exact pair is the child assignment and cancellation return: {cancellation_race:#?}"
    );
    let unknown_index = conflicts_for("unknownSliceIndex");
    assert_eq!(
        unknown_index.completion(),
        CodeQueryCompletion::Complete,
        "{unknown_index:#?}"
    );
    let value = find_concurrent_relation(&unknown_index, |value| value.proof == "open");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "open", "open"),
        "{unknown_index:#?}"
    );
    assert_eq!(value.reasons, ["unknown_location"], "{unknown_index:#?}");

    let unknown_alias = conflicts_for("unknownObjectAlias");
    assert_eq!(
        unknown_alias.completion(),
        CodeQueryCompletion::Complete,
        "{unknown_alias:#?}"
    );
    let value = find_concurrent_relation(&unknown_alias, |value| value.proof == "open");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "open", "open"),
        "{unknown_alias:#?}"
    );
    assert_eq!(
        value.reasons,
        ["unknown_location", "alias_set_truncated"],
        "{unknown_alias:#?}"
    );

    let copied_struct = conflicts_for("copiedStructArguments");
    assert_eq!(
        copied_struct.completion(),
        CodeQueryCompletion::Complete,
        "{copied_struct:#?}"
    );
    let value = find_concurrent_relation(&copied_struct, |value| value.proof == "open");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "open", "open"),
        "{copied_struct:#?}"
    );
    assert_eq!(
        value.reasons,
        ["unknown_location", "alias_set_truncated"],
        "{copied_struct:#?}"
    );

    let select_default = conflicts_for("selectWithDefaultIsUnjoined");
    assert_eq!(
        select_default.completion(),
        CodeQueryCompletion::Complete,
        "{select_default:#?}"
    );
    let value = find_concurrent_relation(&select_default, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{select_default:#?}"
    );
}

/// Spawning through a stable function-valued binding must reach the same
/// exact conflict as spawning the literal in place, and a rebound binding must
/// stay open instead of silently naming its first value.
///
/// `go check()` over a `check := func() { ... }` binding is the shape of
/// bbolt's published `TestTx_Check_ReadOnly` reproducer. While Go proved a
/// local target only for immediate literal syntax, that spawn resolved to
/// nothing, so the solver built no task for the spawned body and compared no
/// accesses at all -- an empty answer rather than a narrower one.
#[test]
fn go_spawn_through_a_stable_callable_binding_matches_the_literal_spawn() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

func literalSpawn() int {
    value := 0
    go func() { value = 1 }()
    return value
}

func aliasedSpawn() int {
    value := 0
    worker := func() { value = 1 }
    go worker()
    return value
}

func aliasedSynchronousCall() int {
    value := 0
    read := func() int { return value }
    go func() { value = 1 }()
    return read()
}

func reassignedSpawn(flag bool) int {
    value := 0
    worker := func() { value = 1 }
    if flag {
        worker = func() {}
    }
    go worker()
    return value
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let conflicts_for = |name: &str| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("callable binding concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    for name in ["literalSpawn", "aliasedSpawn", "aliasedSynchronousCall"] {
        let result = conflicts_for(name);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
        assert_eq!(
            (value.ordering, value.proof, value.coverage),
            ("unordered", "proven", "exhaustive"),
            "{name}: {result:#?}"
        );
    }

    let reassigned = conflicts_for("reassignedSpawn");
    assert_ne!(
        reassigned.completion(),
        CodeQueryCompletion::Complete,
        "a rebound callable leaves the spawn target open: {reassigned:#?}"
    );
    assert!(
        !reassigned.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
        )),
        "a rebound callable must not produce a proven conflict: {reassigned:#?}"
    );
}

/// A method reached through a receiver bound by multi-result destructuring
/// must be expanded, exactly as one bound from a single-result call is.
///
/// `SignatureMetadata` carried a single return identity, so the Go adapter
/// dropped the result type of any callable declaring more than one. A receiver
/// bound from such a call had no type, dispatch could not resolve the method,
/// and the concurrency solver never compared what the method body does. bbolt
/// binds its transaction exactly this way, in
/// `tx, err := readOnlyDB.Begin(false)`.
///
/// The method writes package state rather than a receiver field so this test
/// fails only for dispatch. Carrying a receiver field's identity across the
/// call is a separate open gap, and pinning it here would make this test fail
/// for two reasons at once.
#[test]
fn go_methods_dispatch_on_a_multi_result_bound_receiver() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type box struct{ n int }

var shared int

func newBox() (*box, error) { return &box{}, nil }

func newBoxOnly() *box { return &box{} }

func (b *box) bump() { shared = 1 }

func singleResultReceiver() int {
    b := newBoxOnly()
    go func() { b.bump() }()
    return shared
}

func multiResultReceiver() int {
    b, _ := newBox()
    go func() { b.bump() }()
    return shared
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for name in ["singleResultReceiver", "multiResultReceiver"] {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("multi-result receiver concurrent access query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
        assert_eq!(
            (value.ordering, value.proof, value.coverage),
            ("unordered", "proven", "exhaustive"),
            "{name}: {result:#?}"
        );
    }
}

#[test]
fn go_concurrent_access_conflicts_close_summarized_recursive_slices() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

func recursive() {
    recursive()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "recursive" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("recursive concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert!(result.results.is_empty(), "{result:#?}");
    assert!(result.diagnostics.is_empty(), "{result:#?}");
}

#[test]
fn go_concurrent_access_conflicts_report_unsafe_and_cgo_boundaries_without_poisoning() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "unsafe.go",
            r#"package main

import "unsafe"

func unsafeBoundary() int {
    value := 0
    pointer := unsafe.Pointer(&value)
    _ = pointer
    go func() { value = 1 }()
    return value
}
"#,
        )
        .file(
            "cgo.go",
            r#"package main

/* void noop(void) {} */
import "C"

func cgoBoundary() int {
    value := 0
    go func() {
        value = 1
        C.noop()
    }()
    C.noop()
    return value
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    for name in ["unsafeBoundary", "cgoBoundary"] {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("unsupported boundary concurrent access query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let item = result
            .results
            .iter()
            .find(|item| {
                matches!(
                    &item.value,
                    CodeQueryResultValue::ConcurrentAccessConflict { value }
                        if value.verdict == "conflict"
                )
            })
            .unwrap_or_else(|| panic!("{name} retains its exact conflict row: {result:#?}"));
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("{name} returns its typed conflict row: {item:#?}");
        };
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Incomplete {
                codes: vec![CodeQueryDiagnosticCode::SemanticAnalysisPartial]
            },
            "{name}: {result:#?}"
        );
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
                && diagnostic.message.contains("UnresolvedTarget")
        }));
        assert_eq!(
            (value.proof, value.coverage),
            ("proven", "exhaustive"),
            "an unrelated {name} boundary must not poison the exact ordinary race: {result:#?}"
        );
        assert!(value.reasons.is_empty(), "{result:#?}");
    }
}

#[test]
fn go_concurrent_access_conflicts_apply_exact_sync_models() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import (
    "sync"
    "sync/atomic"
)

func locked() int {
    mutex := &sync.Mutex{}
    value := 0
    go func() {
        mutex.Lock()
        value = 1
        mutex.Unlock()
    }()
    mutex.Lock()
    result := value
    mutex.Unlock()
    return result
}

type promotedMutex struct { sync.Mutex }

func promotedLock() int {
    guard := &promotedMutex{}
    value := 0
    go func() {
        guard.Lock()
        value = 1
        guard.Unlock()
    }()
    guard.Lock()
    result := value
    guard.Unlock()
    return result
}

type promotedTable struct {
    sync.Mutex
    items map[int]int
}

func (table *promotedTable) scan() {
    table.Lock()
    for range table.items {}
    table.Unlock()
}

func (table *promotedTable) addInternal() {
    table.items[0] = 1
    table.Unlock()
}

func (table *promotedTable) add() {
    table.Lock()
    table.addInternal()
}

func promotedInterproceduralLock() {
    table := &promotedTable{items: map[int]int{}}
    go table.scan()
    table.add()
}

func grouped() int {
    group := &sync.WaitGroup{}
    value := 0
    group.Go(func() { value = 1 })
    group.Wait()
    return value
}

func classicGroup() int {
    group := &sync.WaitGroup{}
    value := 0
    group.Add(1)
    go func() {
        defer group.Done()
        value = 1
    }()
    group.Wait()
    return value
}

func repeatedClassicGroup() int {
    total := 0
    for index := 0; index < 2; index++ {
        group := sync.WaitGroup{}
        first, second := 0, 0
        group.Add(2)
        go func() {
            defer func() { group.Done() }()
            first = 1
        }()
        go func() {
            defer group.Done()
            second = 2
        }()
        group.Wait()
        total += first + second
    }
    return total
}

func nestedRepeatedClassicGroup() {
    go func() { _ = repeatedClassicGroup() }()
}

func unknownGroupCount(delta int) int {
    group := &sync.WaitGroup{}
    value := 0
    group.Add(delta)
    go func() {
        defer group.Done()
        value = 1
    }()
    group.Wait()
    return value
}

func atomicOnly() int64 {
    var value int64
    go func() { atomic.StoreInt64(&value, 1) }()
    return atomic.LoadInt64(&value)
}

func mixedAtomic() int64 {
    var value int64
    go func() { atomic.StoreInt64(&value, 1) }()
    return value
}

func mutex() *sync.Mutex { return nil }

func ambiguousLock() int {
    first := mutex()
    second := mutex()
    value := 0
    go func() {
        first.Lock()
        value = 1
        first.Unlock()
    }()
    second.Lock()
    result := value
    second.Unlock()
    return result
}

func oneSidedLock() int {
    mutex := &sync.Mutex{}
    value := 0
    go func() {
        mutex.Lock()
        value = 1
        mutex.Unlock()
    }()
    return value
}

func unsupportedOnce() int {
    once := &sync.Once{}
    value := 0
    go func() {
        value = 1
        once.Do(func() {})
    }()
    once.Do(func() {})
    return value
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack = compile_source(
        SourceFormat::Json,
        br#"{
          "schema_version": 2,
          "pack_id": "test.go.concurrency",
          "version": "1.0.0",
          "producer": { "name": "test", "version": "1.0.0" },
          "language": "go",
          "ecosystem": "go",
          "compatibility": { "bifrost": ">=0.10.7, <1.0.0", "toolchains": [] },
          "provenance": { "source": "test", "revision": "1" },
          "license": "MIT",
          "completeness": "complete",
          "safety": { "generated_code_only": false, "review_required": false },
          "shards": [{
            "id": "sync.declarations",
            "activation": [{}],
            "payload": {
              "kind": "declaration_facts",
              "types": [
                {
                  "id": "type.1111111111111111111111111111111111111111111111111111111111111111",
                  "name": "sync",
                  "type_kind": "module",
                  "visibility": "package",
                  "is_abstract": false,
                  "is_sealed": false,
                  "has_explicit_type_terms": false,
                  "type_parameters": [],
                  "type_parameter_constraints": [],
                  "embedded_types": [],
                  "hierarchy": [],
                  "aliases": ["sync"],
                  "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync" }
                },
                {
                  "id": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "sync.Mutex",
                  "type_kind": "struct",
                  "visibility": "public",
                  "is_abstract": false,
                  "is_sealed": false,
                  "has_explicit_type_terms": false,
                  "type_parameters": [],
                  "type_parameter_constraints": [],
                  "embedded_types": [],
                  "hierarchy": [],
                  "aliases": [],
                  "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex" }
                },
                {
                  "id": "type.5555555555555555555555555555555555555555555555555555555555555555",
                  "name": "sync.WaitGroup",
                  "type_kind": "struct",
                  "visibility": "public",
                  "is_abstract": false,
                  "is_sealed": false,
                  "has_explicit_type_terms": false,
                  "type_parameters": [],
                  "type_parameter_constraints": [],
                  "embedded_types": [],
                  "hierarchy": [],
                  "aliases": [],
                  "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup" }
                },
                {
                  "id": "type.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                  "name": "sync.Once",
                  "type_kind": "struct",
                  "visibility": "public",
                  "is_abstract": false,
                  "is_sealed": false,
                  "has_explicit_type_terms": false,
                  "type_parameters": [],
                  "type_parameter_constraints": [],
                  "embedded_types": [],
                  "hierarchy": [],
                  "aliases": [],
                  "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/once.go", "symbol": "sync.Once" }
                },
                {
                  "id": "type.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "name": "sync/atomic",
                  "type_kind": "module",
                  "visibility": "package",
                  "is_abstract": false,
                  "is_sealed": false,
                  "has_explicit_type_terms": false,
                  "type_parameters": [],
                  "type_parameter_constraints": [],
                  "embedded_types": [],
                  "hierarchy": [],
                  "aliases": ["atomic"],
                  "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/atomic/doc.go", "symbol": "sync/atomic" }
                }
              ],
              "members": [
                {
                  "id": "member.3333333333333333333333333333333333333333333333333333333333333333",
                  "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "Lock",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Lock" }
                },
                {
                  "id": "member.4444444444444444444444444444444444444444444444444444444444444444",
                  "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "Unlock",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Unlock" }
                },
                {
                  "id": "member.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                  "owner": "type.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                  "name": "Do",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "f", "type": { "kind": "named", "name": "func()", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/once.go", "symbol": "sync.Once.Do" }
                },
                {
                  "id": "member.6666666666666666666666666666666666666666666666666666666666666666",
                  "owner": "type.5555555555555555555555555555555555555555555555555555555555555555",
                  "name": "Go",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "f", "type": { "kind": "named", "name": "func()", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Go" }
                },
                {
                  "id": "member.7777777777777777777777777777777777777777777777777777777777777777",
                  "owner": "type.5555555555555555555555555555555555555555555555555555555555555555",
                  "name": "Wait",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Wait" }
                },
                {
                  "id": "member.8888888888888888888888888888888888888888888888888888888888888888",
                  "owner": "type.5555555555555555555555555555555555555555555555555555555555555555",
                  "name": "Add",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "delta", "type": { "kind": "named", "name": "int", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Add" }
                },
                {
                  "id": "member.9999999999999999999999999999999999999999999999999999999999999999",
                  "owner": "type.5555555555555555555555555555555555555555555555555555555555555555",
                  "name": "Done",
                  "member_kind": "method",
                  "visibility": "public",
                  "is_static": false,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Done" }
                },
                {
                  "id": "member.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                  "owner": "type.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "name": "StoreInt64",
                  "member_kind": "function",
                  "visibility": "public",
                  "is_static": true,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "addr", "type": { "kind": "named", "name": "*int64", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "val", "type": { "kind": "named", "name": "int64", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/atomic/doc_64.go", "symbol": "sync/atomic.StoreInt64" }
                },
                {
                  "id": "member.cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  "owner": "type.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "name": "LoadInt64",
                  "member_kind": "function",
                  "visibility": "public",
                  "is_static": true,
                  "is_abstract": false,
                  "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "addr", "type": { "kind": "named", "name": "*int64", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "int64", "arguments": [], "nullable": false } },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/atomic/doc_64.go", "symbol": "sync/atomic.LoadInt64" }
                }
              ],
              "relations": []
            }
          }, {
            "id": "sync",
            "activation": [{}],
            "payload": {
              "kind": "procedure_summaries",
              "summaries": [
                {
                  "id": "mutex.lock",
                  "target": { "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Lock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
                },
                {
                  "id": "mutex.unlock",
                  "target": { "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Unlock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
                },
                {
                  "id": "once.do",
                  "target": { "path": "src/sync/once.go", "symbol": "sync.Once.Do(func())", "has_receiver": true, "parameter_count": 1 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "unsupported", "protocol": "sync.Once" }]
                },
                {
                  "id": "waitgroup.go",
                  "target": { "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Go(func())", "has_receiver": true, "parameter_count": 1 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 0 }, "group": { "kind": "receiver" } }]
                },
                {
                  "id": "waitgroup.wait",
                  "target": { "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Wait()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "wait_group_wait", "group": { "kind": "receiver" } }]
                },
                {
                  "id": "waitgroup.add",
                  "target": { "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Add(delta int)", "has_receiver": true, "parameter_count": 1 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "wait_group_add", "group": { "kind": "receiver" }, "delta": { "kind": "parameter", "ordinal": 0 } }]
                },
                {
                  "id": "waitgroup.done",
                  "target": { "path": "src/sync/waitgroup.go", "symbol": "sync.WaitGroup.Done()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "wait_group_done", "group": { "kind": "receiver" } }]
                },
                {
                  "id": "atomic.store-int64",
                  "target": { "path": "src/sync/atomic/doc_64.go", "symbol": "sync/atomic.StoreInt64(addr *int64, val int64)", "has_receiver": false, "parameter_count": 2 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "atomic", "location": { "kind": "parameter", "ordinal": 0 }, "operation": "store" }]
                },
                {
                  "id": "atomic.load-int64",
                  "target": { "path": "src/sync/atomic/doc_64.go", "symbol": "sync/atomic.LoadInt64(addr *int64)", "has_receiver": false, "parameter_count": 1 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "atomic", "location": { "kind": "parameter", "ordinal": 0 }, "operation": "load" }]
                }
              ]
            }
          }]
        }"#,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("sync model pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-concurrency-sync".to_owned(),
            },
        )
        .expect("register mutex model pack");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "sync models activate: {activation:#?}"
    );

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "locked" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("mutex-protected concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "protected");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "promotedInterproceduralLock" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("promoted interprocedural mutex-protected concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "protected");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "promotedLock" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("promoted mutex-protected concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "protected");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "nestedRepeatedClassicGroup" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("nested repeated classic WaitGroup-joined concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "ordered");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "repeatedClassicGroup" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("repeated classic WaitGroup-joined concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "ordered");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "atomicOnly" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("atomic-only concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "protected");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "mixedAtomic" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("mixed atomic and ordinary concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let item = result
        .results
        .iter()
        .find(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )
        })
        .unwrap_or_else(|| panic!("one mixed atomic/ordinary conflict: {result:#?}"));
    let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
        panic!("mixed atomic/ordinary access returns its typed row: {item:#?}");
    };
    assert_eq!(
        (
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        ("unordered", "unprotected", "proven", "exhaustive"),
        "{result:#?}"
    );

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "unsupportedOnce" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("unsupported Once synchronization query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::SemanticAnalysisPartial]
        },
        "{result:#?}"
    );
    let item = result
        .results
        .iter()
        .find(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict" && value.proof == "open"
            )
        })
        .unwrap_or_else(|| panic!("one binding-scoped unsupported Once row: {result:#?}"));
    let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
        panic!("unsupported Once retains its typed row: {item:#?}");
    };
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "open", "open"),
        "{result:#?}"
    );
    assert_eq!(
        value.reasons,
        ["unsupported_synchronization:sync.Once"],
        "{result:#?}"
    );

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "ambiguousLock" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("ambiguous mutex identity concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let value = find_concurrent_relation(&result, |value| {
        value.verdict == "conflict" && value.proof == "open"
    });
    assert_eq!(
        (
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        ("unordered", "open", "open", "open"),
        "{result:#?}"
    );
    assert_eq!(value.reasons, ["ambiguous_synchronization"], "{result:#?}");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "oneSidedLock" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("one-sided mutex concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        ("unordered", "unprotected", "proven", "exhaustive"),
        "{result:#?}"
    );

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "unknownGroupCount" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("unknown WaitGroup count concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let value = find_concurrent_relation(&result, |value| {
        value.verdict == "conflict" && value.proof == "open"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("open", "open", "open"),
        "{result:#?}"
    );
    assert_eq!(value.reasons, ["ambiguous_synchronization"], "{result:#?}");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "classicGroup" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("classic WaitGroup-joined concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "ordered");

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "grouped" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("WaitGroup.Go-joined concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "ordered");
}

#[test]
fn go_concurrent_access_conflicts_apply_rwmutex_and_errgroup_models() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import (
    "sync"
    "golang.org/x/sync/errgroup"
)

func rwExclusive() int {
    mutex := &sync.RWMutex{}
    value := 0
    go func() {
        mutex.Lock()
        value = 1
        mutex.Unlock()
    }()
    mutex.RLock()
    result := value
    mutex.RUnlock()
    return result
}

func rwSharedWrite() int {
    mutex := &sync.RWMutex{}
    value := 0
    go func() {
        mutex.RLock()
        value = 1
        mutex.RUnlock()
    }()
    mutex.RLock()
    result := value
    mutex.RUnlock()
    return result
}

func errgroupJoined() int {
    group, _ := errgroup.WithContext(nil)
    value := 0
    group.Go(func() error { value = 1; return nil })
    _ = group.Wait()
    return value
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack = compile_source(
        SourceFormat::Json,
        br#"{
          "schema_version": 2,
          "pack_id": "test.go.rwmutex-errgroup",
          "version": "1.0.0",
          "producer": { "name": "test", "version": "1.0.0" },
          "language": "go",
          "ecosystem": "go",
          "compatibility": { "bifrost": ">=0.10.7, <1.0.0", "toolchains": [] },
          "provenance": { "source": "test", "revision": "1" },
          "license": "MIT",
          "completeness": "complete",
          "safety": { "generated_code_only": false, "review_required": false },
          "shards": [{
            "id": "declarations",
            "activation": [{}],
            "payload": {
              "kind": "declaration_facts",
              "types": [
                {
                  "id": "type.1111111111111111111111111111111111111111111111111111111111111111",
                  "name": "sync", "type_kind": "module", "visibility": "package",
                  "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
                  "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
                  "hierarchy": [], "aliases": ["sync"], "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync" }
                },
                {
                  "id": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "sync.RWMutex", "type_kind": "struct", "visibility": "public",
                  "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
                  "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
                  "hierarchy": [], "aliases": [], "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex" }
                },
                {
                  "id": "type.d9a13c3593128df16b560fd8293a702e20b1a36f381b6d54f82a6ccbcd2737cd",
                  "name": "golang.org/x/sync/errgroup", "type_kind": "module", "visibility": "package",
                  "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
                  "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
                  "hierarchy": [], "aliases": ["errgroup"], "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup" }
                },
                {
                  "id": "type.0c4f21e4d6d55855f8189f63d90adcce32a1cd675cd25058d1416fba1c0a2927",
                  "name": "golang.org/x/sync/errgroup.Group", "type_kind": "struct", "visibility": "public",
                  "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
                  "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
                  "hierarchy": [], "aliases": [], "extension_surfaces": [],
                  "locator": { "kind": "artifact", "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group" }
                }
              ],
              "members": [
                {
                  "id": "member.1111111111111111111111111111111111111111111111111111111111111111",
                  "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "Lock", "member_kind": "method", "visibility": "public", "is_static": false,
                  "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true }, "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Lock" }
                },
                {
                  "id": "member.2222222222222222222222222222222222222222222222222222222222222222",
                  "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "Unlock", "member_kind": "method", "visibility": "public", "is_static": false,
                  "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true }, "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Unlock" }
                },
                {
                  "id": "member.3333333333333333333333333333333333333333333333333333333333333333",
                  "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "RLock", "member_kind": "method", "visibility": "public", "is_static": false,
                  "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true }, "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RLock" }
                },
                {
                  "id": "member.4444444444444444444444444444444444444444444444444444444444444444",
                  "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
                  "name": "RUnlock", "member_kind": "method", "visibility": "public", "is_static": false,
                  "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
                  "receiver": { "pointer": true }, "aliases": [],
                  "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RUnlock" }
                },
                {
                  "id": "member.8eba5e7e0d44e9a914e81eb4c18dadad146753487819400bd7f686a30da5c9cb",
                  "owner": "type.d9a13c3593128df16b560fd8293a702e20b1a36f381b6d54f82a6ccbcd2737cd",
                  "name": "WithContext", "member_kind": "function", "visibility": "public", "is_static": true,
                  "is_abstract": false, "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "ctx", "type": { "kind": "named", "name": "context.Context", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "tuple", "elements": [{ "kind": "pointer", "element": { "kind": "declared", "id": "type.0c4f21e4d6d55855f8189f63d90adcce32a1cd675cd25058d1416fba1c0a2927", "arguments": [], "nullable": false } }, { "kind": "named", "name": "context.Context", "arguments": [], "nullable": false }] } },
                  "aliases": [],
                  "locator": { "kind": "artifact", "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.WithContext" }
                },
                {
                  "id": "member.4d0432d587858f542855f7836d30c4e8e41ef7cc530c5d10e2adf7297cee2227",
                  "owner": "type.0c4f21e4d6d55855f8189f63d90adcce32a1cd675cd25058d1416fba1c0a2927",
                  "name": "Go", "member_kind": "method", "visibility": "public", "is_static": false,
                  "is_abstract": false, "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [{ "name": "f", "type": { "kind": "named", "name": "func", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
                  "receiver": { "pointer": true }, "aliases": [],
                  "locator": { "kind": "artifact", "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.Go" }
                },
                {
                  "id": "member.f4ccffe4aee7246f71dafc1d38211225e0c689dfa0068c64def4713ff8e989cd",
                  "owner": "type.0c4f21e4d6d55855f8189f63d90adcce32a1cd675cd25058d1416fba1c0a2927",
                  "name": "Wait", "member_kind": "method", "visibility": "public", "is_static": false,
                  "is_abstract": false, "is_virtual": false,
                  "signature": { "type_parameters": [], "parameters": [], "returns": { "kind": "named", "name": "error", "arguments": [], "nullable": false } },
                  "receiver": { "pointer": true }, "aliases": [],
                  "locator": { "kind": "artifact", "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.Wait" }
                }
              ],
              "relations": []
            }
          }, {
            "id": "behavior",
            "activation": [{}],
            "payload": {
              "kind": "procedure_summaries",
              "summaries": [
                {
                  "id": "rw.lock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Lock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete", "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
                },
                {
                  "id": "rw.unlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Unlock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete", "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
                },
                {
                  "id": "rw.rlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RLock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete", "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "shared" }]
                },
                {
                  "id": "rw.runlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RUnlock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete", "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "shared" }]
                },
                {
                  "id": "errgroup.with-context",
                  "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.WithContext(ctx context.Context)", "has_receiver": false, "parameter_count": 1 },
                  "completeness": "complete", "normal_result_count": 2,
                  "locations": [{ "id": "group", "location_kind": "heap" }],
                  "transfers": [{ "input": { "kind": "parameter", "ordinal": 0 }, "exit_kind": "normal", "output": { "kind": "indexed_normal_return", "ordinal": 1 } }],
                  "effects": [{ "kind": "allocation", "event": "group-allocation", "output": { "kind": "indexed_normal_return", "ordinal": 0 } }]
                },
                {
                  "id": "errgroup.go", "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.Go(f func() error)", "has_receiver": true, "parameter_count": 1 },
                  "completeness": "complete", "transfers": [],
                  "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 0 }, "group": { "kind": "receiver" } }]
                },
                {
                  "id": "errgroup.wait", "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.Wait()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete", "transfers": [],
                  "concurrency_effects": [{ "kind": "task_join", "group": { "kind": "receiver" } }]
                }
              ]
            }
          }]
        }"#,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("RWMutex/errgroup pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-rwmutex-errgroup".to_owned(),
            },
        )
        .expect("register RWMutex/errgroup model pack");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "RWMutex/errgroup models activate: {activation:#?}"
    );

    let conflicts_for = |name: &str| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("RWMutex/errgroup concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };
    for (name, verdict) in [("rwExclusive", "protected"), ("errgroupJoined", "ordered")] {
        let result = conflicts_for(name);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        assert_exact_safe_concurrent_relations(&result, verdict);
    }
    let shared = conflicts_for("rwSharedWrite");
    assert_eq!(
        shared.completion(),
        CodeQueryCompletion::Complete,
        "{shared:#?}"
    );
    let item = shared
        .results
        .iter()
        .find(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )
        })
        .unwrap_or_else(|| panic!("shared read locks do not protect a write: {shared:#?}"));
    let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
        panic!("RWMutex query returns its typed row: {item:#?}");
    };
    assert_eq!(
        (
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        ("unordered", "unprotected", "proven", "exhaustive"),
        "{shared:#?}"
    );
}

/// A conflict whose spawn root and whose written procedure are in two files of
/// one package.
///
/// Every other concurrency fixture is one file (the survey behind Milestone 4
/// of `.agents/plans/impact-sliced-diff-base.md` found none that crossed a file
/// boundary), and the `--diff-base` case the plan is about is exactly the
/// cross-file one: the edit is in the spawn root and the finding is anchored at
/// the write, in a file the edit never touched.
///
/// The same content in one file produces exactly one proven, exhaustive
/// conflict (`go_concurrent_access_conflict_identities_are_the_same_at_two_workspace_roots`
/// asserts it). Split across two files of one package it produces no row at
/// all -- and, worse, no open reason and no diagnostic, so a policy over it
/// reports a clean, complete, exhaustive verdict about a race that exists. The
/// same happens with the type in the spawn root's own file and only the
/// spawned procedure elsewhere, so what does not cross the boundary is the
/// spawn target's dispatch rather than the shared type. Fixing the concurrency
/// engine's cross-file expansion is not this milestone's work, so the case is
/// pinned here and reported.
#[test]
#[ignore = "finds real bug: a spawned callee in another file of the same Go package yields no task slice and no open reason"]
fn go_concurrent_access_conflicts_cross_a_file_boundary_in_one_package() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "a.go",
            r#"package fixture

func run() int {
    c := &cell{}
    go write(c)
    return c.value
}
"#,
        )
        .file(
            "b.go",
            r#"package fixture

type cell struct { value int }

func write(c *cell) { c.value = 1 }
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("cross-file conflict query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one cross-file conflict: {result:#?}");
    };
    let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
        panic!("the cross-file query returns its typed row: {item:#?}");
    };
    assert_eq!(
        (
            value.task_relation,
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        (
            "parent_child",
            "unordered",
            "unprotected",
            "proven",
            "exhaustive"
        ),
        "{result:#?}"
    );
    assert_eq!(
        (value.first_path.as_str(), value.second_path.as_str()),
        ("b.go", "a.go"),
        "the write and the read are in two files: {result:#?}"
    );
}

/// Every identity a conflict row publishes is mount-free.
///
/// A `--diff-base` run analyzes the base revision at a temporary root and the
/// head at the repository root, then joins the two by finding identity. The
/// data-race policy's finding identity is its group key, which is the rendered
/// `location_id`, and a reader diagnoses a conflict by its `id` and the three
/// procedure ids. If any of them folded the workspace mount -- which
/// `SemanticArtifactKey` does, through a hash of the absolute root -- every
/// data-race finding would be reported as new on every run.
///
/// Two analyses of byte-identical content at two different temporary roots are
/// exactly that comparison.
#[test]
fn go_concurrent_access_conflict_identities_are_the_same_at_two_workspace_roots() {
    const SOURCE: &str = r#"package main

type shared struct { value int }

func write(cell *shared) { cell.value = 1 }

func race() int {
    cell := &shared{}
    go write(cell)
    return cell.value
}
"#;

    let identities = |()| {
        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": "race" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("cross-procedure conflict query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{result:#?}"
        );
        let [item] = result.results.as_slice() else {
            panic!("one cross-procedure conflict: {result:#?}");
        };
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("the conflict query returns its typed row: {item:#?}");
        };
        (
            value.id.clone(),
            value.location_id.clone(),
            value.root_procedure_id.clone(),
            value.first_procedure_id.clone(),
            value.second_procedure_id.clone(),
        )
    };

    let first = identities(());
    let second = identities(());
    assert_eq!(
        first, second,
        "a conflict row names procedures and locations by content, never by workspace root"
    );
    let (id, location_id, root, first_site, second_site) = first;
    assert!(
        [&id, &location_id, &root, &first_site, &second_site]
            .iter()
            .all(|identity| !identity.is_empty()),
        "every published identity is a value, not an empty string"
    );
    assert_ne!(
        first_site, second_site,
        "the two access sites of a cross-procedure race are two procedures"
    );
}

#[test]
fn same_file_call_result_contracts_share_dispatch_parse_across_union_cache_misses() {
    const SOURCE: &str = r#"package main

func target() {}

func caller() {
    target()
    target()
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let branch = json!({
        "languages": ["go"],
        "match": { "kind": "call", "callee": { "name": "target" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" }
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch],
        "result_detail": "full"
    }))
    .expect("duplicated result-contract query");

    let detailed = super::super::execute_internal(
        workspace.analyzer(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
    );
    let result = &detailed.result;
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    assert!(
        result.diagnostics.iter().all(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }),
        "{result:#?}"
    );
    assert_eq!(detailed.work.semantic.materialization_attempts, 1);
    assert_eq!(detailed.work.semantic.unique_materialized_files, 1);
    assert_eq!(detailed.work.semantic.request_cache_hits, 0);
    assert_eq!(
        detailed.work.semantic.source_bytes,
        u64::try_from(SOURCE.len().saturating_mul(2)).expect("fixture size fits u64"),
        "one artifact source scan plus one retained exact-dispatch parse"
    );

    assert_eq!(result.results.len(), 2, "two distinct call sites survive");
    let mut target_shapes = Vec::new();
    for item in &result.results {
        let CodeQueryResultValue::CallResultContract { value } = &item.value else {
            panic!("call_result_contracts returns only its typed rows: {item:#?}")
        };
        assert!(value.terminal, "an unmodeled local target is terminal");
        assert_eq!(value.modeled_arm_count, 0);
        assert_eq!(value.arm_count, 1);
        assert_eq!(value.coverage, "exhaustive");
        assert_eq!(value.proof, Some("proven"));
        assert_eq!(value.success_guard_coverage, None);
        assert!(value.success_guard_edges.is_empty());
        assert!(value.possible_success_guard_edges.is_empty());
        assert_eq!(
            item.provenance
                .iter()
                .map(|provenance| provenance.branch.as_slice())
                .collect::<Vec<_>>(),
            vec![&[0][..], &[1][..]],
            "the second union branch reuses effect-cache answers without eager semantic work"
        );
        target_shapes.push((value.target_id.clone(), value.callee_symbol.clone()));
    }
    assert_eq!(
        target_shapes[0], target_shapes[1],
        "both source sites preserve the same dispatch target shape"
    );
}

const GO_WRAPPER_MODULE: &str = "module example.com/app\n\ngo 1.22\n";
const EXACT_ERRORS_IS_WRAPPER: &str = r#"package errors

import stderrors "errors"

func Is(x, y error) bool { return stderrors.Is(x, y) }
"#;

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn exact_call_arguments_use_reviewed_procedure_preconditions() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[
            ("go.mod", GO_WRAPPER_MODULE),
            (
                "main.go",
                r#"package main

import (
    "os"
    "example.com/app/consumer"
)

func unguarded(path string) {
    file, _ := os.Open(path)
    consumer.Require("open", file)
}

func guarded(path string) {
    file, err := os.Open(path)
    if err != nil {
        return
    }
    consumer.Require("open", file)
}

func reviewedEmpty(path string) {
    file, _ := os.Open(path)
    consumer.Observe(file)
}

func unreviewed(path string) {
    file, _ := os.Open(path)
    consumer.Unreviewed(file)
}
"#,
            ),
        ],
        "result_contract_operation_uses",
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "the exact unreviewed consumer remains open: {result:#?}"
    );
    let mut rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                panic!("result_contract_operation_uses returns its typed row: {item:#?}")
            };
            assert_eq!(value.use_kind, "call_argument", "{value:#?}");
            assert!(value.operation_site_id.is_some(), "{value:#?}");
            assert!(value.operation_site_ast_id.is_some(), "{value:#?}");
            assert_eq!(
                value.range.end_column - value.range.start_column,
                4,
                "the row is anchored to the exact `file` argument: {value:#?}"
            );
            (
                value.range.start_line,
                value.member.as_deref(),
                value.parameter_count,
                value.parameter_ordinal,
                value.applicability,
                value.required_predicate,
                value.guard,
                value.coverage,
                value.id.as_str(),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|row| row.0);
    assert_eq!(rows.len(), 4, "{result:#?}");
    assert_eq!(
        rows.iter().map(|row| row.8).collect::<HashSet<_>>().len(),
        4,
        "argument rows have distinct stable identities: {result:#?}"
    );
    let answers = rows
        .iter()
        .map(|row| (row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7))
        .collect::<Vec<_>>();
    assert_eq!(
        answers,
        [
            (
                10,
                Some("Require"),
                Some(2),
                Some(1),
                "required",
                Some("non_null"),
                "unguarded",
                "exhaustive",
            ),
            (
                18,
                Some("Require"),
                Some(2),
                Some(1),
                "required",
                Some("non_null"),
                "guarded",
                "exhaustive",
            ),
            (
                23,
                Some("Observe"),
                Some(1),
                Some(0),
                "not_required",
                None,
                "not_applicable",
                "exhaustive",
            ),
            (
                28,
                Some("Unreviewed"),
                Some(1),
                Some(0),
                "unknown",
                None,
                "unknown",
                "open",
            ),
        ],
        "{result:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn parenthesized_call_argument_keeps_its_exact_reviewed_precondition() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[
            ("go.mod", GO_WRAPPER_MODULE),
            (
                "main.go",
                r#"package main

import (
    "os"
    "example.com/app/consumer"
)

func parenthesized(path string) {
    file, _ := os.Open(path)
    consumer.Require("open", ((file)))
}
"#,
            ),
        ],
        "result_contract_operation_uses",
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one parenthesized call-argument use: {result:#?}");
    };
    let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
        panic!("the operation projects one typed use: {item:#?}");
    };
    assert_eq!(value.use_kind, "call_argument", "{value:#?}");
    assert_eq!(value.range.start_line, 10, "{value:#?}");
    assert_eq!(
        value.range.end_column - value.range.start_column,
        8,
        "{value:#?}"
    );
    assert_eq!(value.member.as_deref(), Some("Require"), "{value:#?}");
    assert_eq!(value.parameter_count, Some(2), "{value:#?}");
    assert_eq!(value.parameter_ordinal, Some(1), "{value:#?}");
    assert_eq!(value.applicability, "required", "{value:#?}");
    assert_eq!(value.required_predicate, Some("non_null"), "{value:#?}");
    assert_eq!(value.guard, "unguarded", "{value:#?}");
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn method_expression_receiver_is_not_a_formal_parameter() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[(
            "main.go",
            r#"package main

import "os"

func bound(path string, sink *os.File) {
    file, _ := os.Open(path)
    sink.Consume(file)
}

func methodExpression(path string) {
    file, _ := os.Open(path)
    (*os.File).Consume(file, nil)
}
"#,
        )],
        "result_contract_operation_uses",
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "the deliberately unsupported method-expression binding stays explicit: {result:#?}"
    );
    let mut rows = result
        .results
        .iter()
        .filter_map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                return None;
            };
            (value.use_kind == "call_argument").then_some(value)
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|row| row.range.start_line);
    let [bound, expression_receiver] = rows.as_slice() else {
        panic!("both structured argument uses remain visible: {result:#?}");
    };
    assert_eq!(bound.range.start_line, 7, "{bound:#?}");
    assert_eq!(bound.parameter_count, Some(1), "{bound:#?}");
    assert_eq!(bound.parameter_ordinal, Some(0), "{bound:#?}");
    assert_eq!(bound.applicability, "required", "{bound:#?}");
    assert_eq!(bound.required_predicate, Some("non_null"), "{bound:#?}");
    assert_eq!(bound.coverage, "exhaustive", "{bound:#?}");

    assert_eq!(
        expression_receiver.range.start_line, 12,
        "{expression_receiver:#?}"
    );
    assert_eq!(
        expression_receiver.parameter_count, None,
        "{expression_receiver:#?}"
    );
    assert_eq!(
        expression_receiver.parameter_ordinal, None,
        "{expression_receiver:#?}"
    );
    assert_eq!(
        expression_receiver.applicability, "unknown",
        "{expression_receiver:#?}"
    );
    assert_eq!(
        expression_receiver.coverage, "open",
        "{expression_receiver:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn spread_call_arguments_do_not_claim_a_formal_parameter() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[(
            "main.go",
            r#"package main

import (
    "os"
    "example.com/app/consumer"
)

func spread(path string, rest []*os.File) {
    file, _ := os.Open(path)
    consumer.RequireMany(file, rest...)
}
"#,
        )],
        "result_contract_operation_uses",
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "spread-to-formal mapping stays explicit unsupported coverage: {result:#?}"
    );
    let rows = result
        .results
        .iter()
        .filter_map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                return None;
            };
            (value.use_kind == "call_argument").then_some(value)
        })
        .collect::<Vec<_>>();
    let [row] = rows.as_slice() else {
        panic!("the direct result argument remains visible: {result:#?}");
    };
    assert_eq!(row.range.start_line, 10, "{row:#?}");
    assert_eq!(row.parameter_count, None, "{row:#?}");
    assert_eq!(row.parameter_ordinal, None, "{row:#?}");
    assert_eq!(row.applicability, "unknown", "{row:#?}");
    assert_eq!(row.coverage, "open", "{row:#?}");
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn pre_origin_gaps_do_not_hide_exact_failure_and_success_arm_uses() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[(
            "main.go",
            r#"package main

import "os"

type holder struct { values []int }

func failureArmThenOpenTarget(path string, h *holder) error {
    for range h.values {
        _ = h.values
    }
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open %s: %w", file.Name(), err)
    }
    _ = file.Name()
    return nil
}

func unrelatedEarlierConsumer(path string, h *holder) error {
    for range h.values {
        _ = h.values
    }
    file, err := os.Open(path)
    if err != nil {
        _ = fmt.Errorf("open: %w", err)
        _ = file.Name()
        return err
    }
    return nil
}
"#,
        )],
        "result_contract_operation_uses",
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let mut answers = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                panic!("result_contract_operation_uses returns its typed row: {item:#?}")
            };
            assert_eq!(value.member.as_deref(), Some("Name"), "{value:#?}");
            assert_eq!(value.applicability, "required", "{value:#?}");
            (value.range.start_line, value.guard, value.coverage)
        })
        .collect::<Vec<_>>();
    answers.sort_unstable_by_key(|(line, _, _)| *line);
    let [failure_arm, success_arm, unrelated_failure_arm] = answers.as_slice() else {
        panic!("the two os.Open results have three exact Name operations: {result:#?}")
    };
    assert!(failure_arm.0 < success_arm.0, "{result:#?}");
    assert_eq!(
        (failure_arm.1, failure_arm.2),
        ("unguarded", "exhaustive"),
        "the closed failure-arm negative remains reportable: {result:#?}"
    );
    assert_eq!(
        (success_arm.1, success_arm.2),
        ("guarded", "exhaustive"),
        "strict acyclic pre-origin gaps cannot bypass the retained guard: {result:#?}"
    );
    assert_eq!(
        (unrelated_failure_arm.1, unrelated_failure_arm.2),
        ("unguarded", "exhaustive"),
        "the unrelated failure-arm use remains an exact negative: {result:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn modeled_negative_arm_closes_a_use_despite_a_nonrejoining_sibling_call() {
    let result = execute_conditional_result_contract_files_with_operation(
        &[
            ("go.mod", GO_WRAPPER_MODULE),
            ("internal/errors/errors.go", EXACT_ERRORS_IS_WRAPPER),
            (
                "main.go",
                r#"package main

import (
    wrapped "example.com/app/internal/errors"
    "os"
)

type Printer interface { Println(string) }

func useOnFalseOutcome(path string, printer Printer) string {
    file, err := os.Open(path)
    if wrapped.Is(err, os.ErrNotExist) {
        printer.Println(file.Name())
        return ""
    }
    return file.Name()
}
"#,
            ),
        ],
        "result_contract_operation_uses",
    );

    let mut answers = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ResultContractUse { value } = &item.value else {
                panic!("result_contract_operation_uses returns its typed row: {item:#?}")
            };
            assert_eq!(value.member.as_deref(), Some("Name"), "{value:#?}");
            assert_eq!(value.applicability, "required", "{value:#?}");
            (value.range.start_line, value.guard, value.coverage)
        })
        .collect::<Vec<_>>();
    answers.sort_unstable_by_key(|(line, _, _)| *line);
    let [true_arm, false_arm] = answers.as_slice() else {
        panic!("two exact result operations: {result:#?}")
    };
    assert!(true_arm.0 < false_arm.0, "{result:#?}");
    assert_eq!(
        (true_arm.1, true_arm.2),
        ("unknown", "open"),
        "the open true arm remains unknown: {result:#?}"
    );
    assert_eq!(
        (false_arm.1, false_arm.2),
        ("unguarded", "exhaustive"),
        "the batched negative proof stays aligned to the false-arm and opposite-arm uses: {result:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn later_scalar_call_reassignment_does_not_poison_a_prior_wrapper_violation() {
    let result = execute_conditional_result_contract_files(&[
        ("go.mod", GO_WRAPPER_MODULE),
        ("internal/errors/errors.go", EXACT_ERRORS_IS_WRAPPER),
        (
            "main.go",
            r#"package main

import (
    wrapped "example.com/app/internal/errors"
    "os"
)

func useBeforeLaterGuard(path string) string {
    file, err := os.Open(path)
    if wrapped.Is(err, os.ErrNotExist) { return "" }
    name := file.Name()
    err = os.Chdir(path)
    if err != nil { return "" }
    return name
}
"#,
        ),
    ]);

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn later_scalar_call_guard_does_not_validate_the_old_result_definition() {
    let result = execute_conditional_result_contract_files(&[
        ("go.mod", GO_WRAPPER_MODULE),
        ("internal/errors/errors.go", EXACT_ERRORS_IS_WRAPPER),
        (
            "main.go",
            r#"package main

import (
    wrapped "example.com/app/internal/errors"
    "os"
)

func useAfterLaterGuard(path string) string {
    file, err := os.Open(path)
    if wrapped.Is(err, os.ErrNotExist) { return "" }
    err = os.Chdir(path)
    if err != nil { return "" }
    return file.Name()
}
"#,
        ),
    ]);

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn unmodeled_void_condition_consumer_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func inspect(error) {}

func unmodeledVoidConsumer(path string) string {
    file, err := os.Open(path)
    inspect(err)
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn discarded_testify_assert_no_error_does_not_guard_a_later_result_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func ignoredAssertion(t *testing.T, path string) string {
    file, err := os.Open(path)
    check.NoError(t, err, "open %s", path)
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn discarded_testify_assert_with_nested_argument_evaluation_does_not_guard() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

type suite struct{}
func (*suite) T() *testing.T { return nil }

func ignoredAssertion(s *suite, path string) string {
    file, err := os.Open(path)
    check.NoError(s.T(), err)
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn direct_testify_assert_no_error_true_arm_guards_the_result_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func checkedAssertion(t *testing.T, path string) string {
    file, err := os.Open(path)
    if check.NoError(t, err) {
        return file.Name()
    }
    return ""
}
"#,
    );

    assert_single_exhaustive_satisfied_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn consumed_testify_assert_no_error_results_stay_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func observe(bool) {}

func indirectAssertion(t *testing.T, path string) string {
    file, err := os.Open(path)
    ok := check.NoError(t, err)
    if ok {
        return file.Name()
    }
    return ""
}

func argumentAssertion(t *testing.T, path string) string {
    file, err := os.Open(path)
    observe(check.NoError(t, err))
    return file.Name()
}
"#,
    );

    assert_open_unknown_result_contract_uses(&result, &[1, 1]);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn unmodeled_condition_consumer_on_failure_arm_preserves_the_violation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func inspect(error) {}

func failureArmConsumer(path string) string {
    file, err := os.Open(path)
    if err != nil { inspect(err) }
    return file.Name()
}
"#,
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 1, "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(
        value.use_validation_coverage,
        Some("exhaustive"),
        "{value:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn failure_arm_modeled_normal_return_validator_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    must "github.com/stretchr/testify/require"
    "testing"
)

func modeledFailureArmValidator(t *testing.T, path string) string {
    file, err := os.Open(path)
    if err != nil { must.NoError(t, err) }
    return file.Name()
}
"#,
    );

    assert_single_guarded_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn failure_arm_modeled_conditional_positive_stays_open_without_a_collective_proof() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

func modeledConditionalOnFailureArm(path string) string {
    file, err := os.Open(path)
    if err != nil {
        if predicate.IsNil(err) {
        } else {
            return ""
        }
    }
    return file.Name()
}
"#,
    );

    assert_single_guarded_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn unmodeled_condition_consumer_on_success_arm_preserves_the_joined_violation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func inspect(error) {}

func successArmConsumer(path string) string {
    file, err := os.Open(path)
    if err == nil { inspect(err) }
    return file.Name()
}
"#,
    );

    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.coverage, "exhaustive", "{value:#?}");
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.success_guard_count, 1, "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(
        value.use_validation_coverage,
        Some("exhaustive"),
        "{value:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn parenthesized_unmodeled_predicate_argument_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func isNil(value error) bool { return value == nil }

func parenthesizedPredicate(path string) string {
    file, err := os.Open(path)
    if isNil((err)) { return file.Name() }
    return ""
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn address_mutation_before_modeled_predicate_keeps_condition_identity_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "errors"
    "os"
)

func clear(target *error) { *target = nil }

func mutatedBeforePredicate(path string) string {
    file, err := os.Open(path)
    clear(&err)
    if errors.Is(err, os.ErrNotExist) { return "" }
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn channel_send_address_escape_keeps_condition_identity_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func publishedCondition(path string, ch chan<- *error) string {
    file, err := os.Open(path)
    ch <- &err
    if err != nil { return "" }
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[test]
fn modeled_member_argument_validator_guards_at_invocation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

func guardedInArgument(path string) {
    file, err := os.Open(path)
    file.Use(predicate.Checked(err))
}
"#,
    );

    assert_single_exhaustive_satisfied_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn detached_normal_return_refinement_does_not_guard_parent_continuation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

func detachedValidation(path string) string {
    file, err := os.Open(path)
    go predicate.Checked(err)
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn later_member_argument_mutation_does_not_preserve_modeled_validation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "errors"
    "os"
    predicate "example.com/predicate"
)

func invalidate(target *error) string {
    *target = errors.New("late failure")
    return "invalidated"
}

func invalidatedInLaterArgument(path string) {
    file, err := os.Open(path)
    file.UseTwo(predicate.Checked(err), invalidate(&err))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn earlier_member_argument_escape_does_not_preserve_modeled_validation() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

type lateError struct{}
func (lateError) Error() string { return "late failure" }

func publish(target *error) string {
    go func() { *target = lateError{} }()
    return "published"
}

func escapedInEarlierArgument(path string) {
    file, err := os.Open(path)
    file.UseTwo(publish(&err), predicate.Checked(err))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[test]
fn captured_member_argument_mutation_after_validation_preserves_the_modeled_result() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    "os"
    predicate "example.com/predicate"
)

type capturedError struct{}
func (capturedError) Error() string { return "captured failure" }

func mutatedThroughCapture(path string) {
    file, err := os.Open(path)
    mutate := func() string {
        err = capturedError{}
        return "mutated"
    }
    file.UseTwo(predicate.Checked(err), mutate())
}
"#,
    );

    assert_single_exhaustive_satisfied_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn unmodeled_member_argument_validator_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func checked(err error) string {
    if err != nil { panic(err) }
    return "checked"
}

func maybeGuardedInArgument(path string) {
    file, err := os.Open(path)
    file.Use(checked(err))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn parenthesized_direct_receiver_retains_exact_unguarded_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func parenthesizedReceiver(path string) string {
    file, _ := os.Open(path)
    return (file).Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn channel_receive_retains_exact_unguarded_result_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func receiveBeforeUse(path string, stop <-chan int) string {
    file, _ := os.Open(path)
    received := <-stop
    _ = received
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[test]
fn captured_child_keeps_result_use_validation_unknown() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import "os"

func captured(path string) string {
    opened, _ := os.Open(path)
    file := opened
    invoke := func() string { return file.Name() }
    return invoke()
}
"#,
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "{result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.unguarded_result_use_count, None, "{value:#?}");
    assert_eq!(value.use_validation, Some("unknown"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

#[test]
fn later_capture_retains_both_the_earlier_direct_and_captured_result_uses() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func observe(*os.File) {}

func useBeforeCapture(t *testing.T, path string) string {
    file, err := os.Open(path)
    check.NoError(t, err)
    name := file.Name()
    go func() { observe(file) }()
    return name
}
"#,
    );

    assert!(
        matches!(
            result.completion(),
            CodeQueryCompletion::Incomplete { ref codes }
                if codes.contains(&CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        ),
        "the captured observation remains honestly open: {result:#?}"
    );
    let [item] = result.results.as_slice() else {
        panic!("one projected result contract: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value } = &item.value else {
        panic!("result-contract wrapper returns its typed row: {item:#?}")
    };
    assert_eq!(value.result_use_count, Some(2), "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn spawned_assertion_result_does_not_guard_later_result_use() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func observe(bool) {}

func spawnedAssertionConsumer(t *testing.T, path string) string {
    file, err := os.Open(path)
    go observe(check.NoError(t, err))
    return file.Name()
}
"#,
    );

    assert_single_exhaustive_violated_result_contract(&result);
}

#[test]
fn detached_assertion_result_sent_back_to_parent_keeps_the_use_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func send(result bool, results chan bool) { results <- result }

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go send(check.NoError(t, err), results)
    if <-results {
        return file.Name()
    }
    return ""
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn detached_assertion_feedback_across_a_blocking_receive_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func sendSuccess(result bool, results chan bool) {
    if result {
        results <- result
    }
}

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go sendSuccess(check.NoError(t, err), results)
    <-results
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn detached_assertion_feedback_across_an_ordinary_call_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func send(result bool, results chan bool) { results <- result }
func waitForSuccess(results chan bool) { <-results }

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go send(check.NoError(t, err), results)
    waitForSuccess(results)
    return file.Name()
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[test]
fn detached_assertion_feedback_across_unspecified_operand_order_stays_open() {
    let result = execute_conditional_result_contract_fixture(
        r#"package main

import (
    check "github.com/stretchr/testify/assert"
    "os"
    "testing"
)

func send(result bool, results chan bool) { results <- result }
func waitForSuccess(results chan bool) string { <-results; return "" }
func combine(left os.File, right string) string { return left.Name() + right }

func spawnedAssertionFeedback(t *testing.T, path string, results chan bool) string {
    file, err := os.Open(path)
    go send(check.NoError(t, err), results)
    return combine(*file, waitForSuccess(results))
}
"#,
    );

    assert_single_open_unknown_result_contract(&result);
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn result_contract_uses_executes_the_projected_contract_wrapper() {
    let source = r#"package main

import "os"

func observe(error) {}

func unchecked() string {
    file, _ := os.Open("missing.xlsx")
    return file.Name()
}

func earlyUse() string {
    file, err := os.Open("missing.xlsx")
    name := file.Name()
    observe(err)
    file.Close()
    return name
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-result-contract",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": { "source": "test:rql-result-contract", "revision": "reviewed" },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.os.open",
            "activation": [{}],
            "payload": {
                "kind": "procedure_summaries",
                "summaries": [{
                    "id": "os.open",
                    "target": {
                        "path": "src/os/file.go",
                        "symbol": "os.Open(name string)",
                        "has_receiver": false,
                        "parameter_count": 1
                    },
                    "completeness": "complete",
                    "normal_result_count": 2,
                    "transfers": [],
                    "effects": [],
                    "result_contracts": [{
                        "result_ordinal": 0,
                        "condition_result_ordinal": 1,
                        "predicate": "null",
                        "result_success_predicate": "non_null",
                        "member_contracts": [
                            {
                                "member": "Name",
                                "parameter_count": 0,
                                "completeness": "complete",
                                "preconditions": [{
                                    "input": { "kind": "receiver" },
                                    "predicate": "non_null"
                                }],
                                "declared_effects": []
                            },
                            {
                                "member": "Close",
                                "parameter_count": 0,
                                "completeness": "complete",
                                "preconditions": [],
                                "declared_effects": []
                            }
                        ]
                    }]
                }]
            }
        }]
    }"#;
    let declaration_pack_source = br#"{
        "schema_version": 2,
        "pack_id": "test.rql.go-result-contract-declarations",
        "version": "1.0.0",
        "producer": { "name": "bifrost-rql-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go",
        "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
        "provenance": {
            "source": "test:rql-result-contract-declarations",
            "revision": "reviewed"
        },
        "license": "Apache-2.0",
        "completeness": "partial",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "go.os.declarations",
            "activation": [{}],
            "payload": {
                "kind": "declaration_facts",
                "types": [
                    {
                        "id": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                        "name": "os",
                        "type_kind": "module",
                        "visibility": "package",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": ["os"],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os"
                        }
                    },
                    {
                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                        "name": "os.File",
                        "type_kind": "struct",
                        "visibility": "public",
                        "is_abstract": false,
                        "is_sealed": false,
                        "has_explicit_type_terms": false,
                        "type_parameters": [],
                        "type_parameter_constraints": [],
                        "underlying_type": {
                            "display": "struct{}",
                            "referenced_types": []
                        },
                        "embedded_types": [],
                        "hierarchy": [],
                        "aliases": [],
                        "extension_surfaces": [],
                        "locator": {
                            "kind": "artifact",
                            "path": "os/os.go",
                            "symbol": "os.File"
                        }
                    }
                ],
                "members": [{
                    "id": "member.e969c07a9215c885c075e9f2767d17d39f10922eb0ff1394d8222dd7dc40f38e",
                    "owner": "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d",
                    "name": "Open",
                    "member_kind": "function",
                    "visibility": "public",
                    "is_static": true,
                    "is_abstract": false,
                    "is_virtual": false,
                    "signature": {
                        "type_parameters": [],
                        "parameters": [{
                            "name": "name",
                            "type": {
                                "kind": "named",
                                "name": "string",
                                "arguments": [],
                                "nullable": false
                            },
                            "optional": false,
                            "variadic": false
                        }],
                        "returns": {
                            "kind": "tuple",
                            "elements": [
                                {
                                    "kind": "pointer",
                                    "element": {
                                        "kind": "declared",
                                        "id": "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147",
                                        "arguments": [],
                                        "nullable": false
                                    }
                                },
                                {
                                    "kind": "named",
                                    "name": "error",
                                    "arguments": [],
                                    "nullable": false
                                }
                            ]
                        }
                    },
                    "aliases": [],
                    "locator": {
                        "kind": "artifact",
                        "path": "os/os.go",
                        "symbol": "os.Open"
                    }
                }]
            }
        }]
    }"#;
    let pack = compile_source(SourceFormat::Json, pack_source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("result-contract pack failed: {diagnostics:#?}"));
    let declaration_pack = compile_source(
        SourceFormat::Json,
        declaration_pack_source,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| {
        panic!("result-contract declaration pack failed: {diagnostics:#?}")
    });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-result-contract".to_owned(),
            },
        )
        .expect("register result-contract pack");
    catalog
        .register_session_pack(
            &declaration_pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-result-contract-declarations".to_owned(),
            },
        )
        .expect("register exact result-contract declarations");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "test result-contract pack activates: {activation:#?}"
    );

    // Calibrate the exact nested-entry work of one artifact census plus the
    // three real source-dispatch operations: the two modeled calls plus the
    // `observe(err)` candidate that result-use validation checks for a normal-
    // return refinement. The RQL path below must fit that ledger exactly.
    // Calling materialization again inside any dispatch
    // adds one repeat-cache charge and therefore fails this regression even
    // though all genuine dispatch work still has room.
    let file = project.file("main.go");
    let cancellation = CancellationToken::default();
    let mut setup_budget = SemanticBudget::default();
    let materialized = workspace
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut setup_budget, &cancellation),
        )
        .expect("Go artifact materialization");
    let artifact = materialized
        .available_value()
        .cloned()
        .expect("Go artifact remains available");
    let artifact_nested = artifact.work().nested_entries;
    let mut dispatch_ranges = Vec::new();
    for procedure in artifact.procedures() {
        for call in procedure.call_sites() {
            let mapping = procedure
                .source_mapping(call.source)
                .expect("validated semantic call has a source mapping");
            let span = mapping.locator.anchor().span();
            let start = span.start_byte() as usize;
            let end = span.end_byte() as usize;
            if source
                .get(start..end)
                .is_some_and(|text| text.starts_with("os.Open(") || text == "observe(err)")
                && !dispatch_ranges
                    .iter()
                    .any(|range: &Range| range.start_byte == start && range.end_byte == end)
            {
                dispatch_ranges.push(Range {
                    start_byte: start,
                    end_byte: end,
                    start_line: span.start().line() as usize,
                    end_line: span.end().line() as usize,
                });
            }
        }
    }
    dispatch_ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    assert_eq!(
        dispatch_ranges.len(),
        3,
        "two os.Open calls and one modeled-validator candidate"
    );

    let mut required_nested = artifact_nested;
    let mut calibrated_dispatch_nested = Vec::new();
    for range in dispatch_ranges {
        let mut direct_budget = SemanticBudget::default();
        let direct = workspace
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut direct_budget, &cancellation),
            )
            .expect("direct source dispatch");
        assert!(
            direct.available_value().is_some() && direct.budget_exceeded().is_none(),
            "calibration dispatch remains available: {direct:#?}"
        );
        let dispatch_nested = direct_budget
            .used()
            .nested_entries
            .checked_sub(artifact_nested)
            .expect("direct dispatch includes one artifact census");
        calibrated_dispatch_nested.push(dispatch_nested);
        required_nested = required_nested.saturating_add(dispatch_nested);
    }
    // `result_contract_uses` is a second bounded artifact window. Reopening
    // the same artifact under the same semantic ledger performs one honest
    // repeat-cache lookup; unlike the removed per-dispatch materialization,
    // this lookup owns the next pipeline stage's artifact lifetime.
    required_nested = required_nested.saturating_add(1);
    assert!(required_nested > artifact_nested);

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_contract_calls" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_uses" }
        ],
        "result_detail": "full"
    }))
    .expect("result-contract use query");

    let defaults = CodeQueryExecutionLimits::default();
    let default_rows = semantic::semantic_budget_limits(defaults.semantic);
    let limits = CodeQueryExecutionLimits {
        semantic: CodeQuerySemanticLimits {
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                if dimension == SemanticBudgetDimension::NestedEntries {
                    required_nested
                } else {
                    default_rows.get(dimension)
                }
            })),
            ..defaults.semantic
        },
        ..defaults
    };
    let execution = super::super::execute_internal(
        workspace.analyzer(),
        Some(&workspace),
        &query,
        limits,
        None,
        None,
        false,
    );
    let result = execution.result;

    assert_eq!(
        execution.work.semantic.nested_entries,
        u64::try_from(required_nested).expect("test semantic work fits u64"),
        "artifact={artifact_nested}, dispatch={calibrated_dispatch_nested:?}"
    );
    assert_eq!(execution.work.semantic.materialization_attempts, 2);
    assert_eq!(execution.work.semantic.unique_materialized_files, 1);
    assert!(execution.work.semantic.request_cache_hits > 0);
    assert!(
        result.diagnostics.iter().all(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }),
        "cached full result-contract dispatch must fit its exact calibrated ledger: {result:#?}"
    );

    assert!(
        matches!(result.completion(), CodeQueryCompletion::Complete),
        "the exact early violation closes the only guarded operation: {result:#?}"
    );
    let [unchecked, early] = result.results.as_slice() else {
        panic!("two projected result contracts: {result:#?}")
    };
    let CodeQueryResultValue::CallResultContract { value: unchecked } = &unchecked.value else {
        panic!("result-contract wrapper returns its typed row: {unchecked:#?}")
    };
    assert_eq!(unchecked.result_use_count, Some(1));
    assert_eq!(unchecked.unguarded_result_use_count, Some(1));
    assert_eq!(unchecked.use_validation, Some("violated"));
    assert_eq!(unchecked.use_validation_coverage, Some("exhaustive"));

    let CodeQueryResultValue::CallResultContract { value: early } = &early.value else {
        panic!("result-contract wrapper returns its typed row: {early:#?}")
    };
    assert_eq!(
        early.result_use_count,
        Some(2),
        "Name and nil-tolerant Close are both exact structured operations"
    );
    assert_eq!(
        early.unguarded_result_use_count,
        Some(1),
        "only Name carries the reviewed non-null receiver precondition"
    );
    assert_eq!(early.use_validation, Some("violated"));
    assert_eq!(early.use_validation_coverage, Some("exhaustive"));
}

#[test]
fn union_query_over_root_limit_reports_exactly_one_truncation_diagnostic() {
    // Regression for issue #2779: a query whose logical plan wraps a `union`
    // set operator directly in the root `Limit` (`query.limit`) must report
    // `truncated=true` and name the cap that caused it, exactly once. This is
    // the shape the OWASP xss selector hit: more matching rows than the
    // policy-overridden `query.limit`, executed through the same detailed
    // path a policy selector uses
    // (`execute_code_query_detailed_eager_index`). The `Limit` operator's own
    // `push_truncation_diagnostic` call already fires whenever its direct
    // child (here, the `union` set) returns more rows than `count`, so this
    // pins that the new root-terminal-cap backstop
    // (`needs_root_terminal_cap_diagnostic`) does not add a second, duplicate
    // diagnostic for the same truncation.
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for i in 0..5 {
        ProjectFile::new(root.clone(), PathBuf::from(format!("f{i}.ts")))
            .write("function first() {}\nfunction second() {}\nfunction third() {}\n")
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let branches: Vec<_> = (0..5)
        .map(|i| json!({ "where": [format!("f{i}.ts")], "match": { "kind": "function" } }))
        .collect();
    let query = CodeQuery::from_json(&json!({
        "union": branches,
        "limit": 3
    }))
    .expect("query");

    let detailed = execute_code_query_detailed_eager_index(
        &analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );

    assert!(detailed.result.truncated);
    assert_eq!(detailed.result.results.len(), 3);
    assert_eq!(
        detailed
            .result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ResultLimitReached)
            .count(),
        1,
        "exactly one truncation diagnostic, no double report: {:?}",
        detailed.result.diagnostics
    );
}

#[test]
fn a_truncated_query_reports_identical_diagnostics_on_every_run() {
    // Regression for issue #2897: `result_limit_reached` interpolated the live
    // budget counters (`scanned_files`, `fact_nodes`, ...), which depend on
    // worker scheduling and on how far the scan got before the limit tripped.
    // Two executions of one query over an unchanged workspace reported
    // different messages (5178 facts on one run, 4927 on the next), so a
    // truncated result could not be documented, diffed, or snapshotted; the
    // #1132 cookbook had to drop its `limit: 2` example for that reason. The
    // second run below reuses the warm analyzer, which is the state that made
    // the counters diverge.
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for i in 0..8 {
        ProjectFile::new(root.clone(), PathBuf::from(format!("f{i}.ts")))
            .write("function first() {}\nfunction second() {}\nfunction third() {}\n")
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "languages": ["typescript"],
        "match": { "kind": "function" },
        "limit": 2
    }))
    .expect("query");

    let first = execute(&analyzer, &query);
    let second = execute(&analyzer, &query);

    assert!(first.truncated, "{:?}", first.diagnostics);
    assert_eq!(first.results.len(), 2);
    assert_eq!(
        first
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.message.as_str()))
            .collect::<Vec<_>>(),
        vec![(
            CodeQueryDiagnosticCode::ResultLimitReached,
            "query_code reached the query limit of 2 and returned the first 2 results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern",
        )],
    );
    assert_eq!(
        serde_json::to_value(&first).expect("serialize first run"),
        serde_json::to_value(&second).expect("serialize second run"),
        "two runs of one truncating query over an unchanged workspace must agree",
    );
}

/// A `builtins` subset in the schema the pack generator emits: `object` with
/// the members every class inherits, `int` with no members of its own, and
/// `str` with `strip`. The class-set steps need an active pack to classify
/// literals as `builtins.*`; the shipped typeshed pack is a generator spec, so
/// the tests compile this fixture pack the way `python_dependency_pack.rs`
/// does.
const TYPE_FLOW_BUILTINS_PACK: &str = r#"{
  "schema_version": 2,
  "pack_id": "fixture.type-flow-builtins",
  "version": "2026.9.2",
  "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
  "language": "python",
  "ecosystem": "python",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": [{ "name": "cpython", "requirement": ">=3.10.0, <3.15.0" }]
  },
  "provenance": { "source": "checked-in test source", "revision": "fixture-v1" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "python.builtins",
    "activation": [{
      "toolchain": { "name": "cpython", "version": ">=3.10.0, <3.15.0" },
      "targets": []
    }],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "type.builtins-object",
        "name": "builtins.object",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.object" }
      }, {
        "id": "type.builtins-int",
        "name": "builtins.int",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [{ "hierarchy_kind": "extends", "target": { "kind": "named", "name": "builtins.object" } }],
        "aliases": [],
        "extension_surfaces": [],
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.int" }
      }, {
        "id": "type.builtins-str",
        "name": "builtins.str",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [{ "hierarchy_kind": "extends", "target": { "kind": "named", "name": "builtins.object" } }],
        "aliases": [],
        "extension_surfaces": [],
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.str" }
      }],
      "members": [{
        "id": "member.builtins-object.class",
        "owner": "type.builtins-object",
        "name": "__class__",
        "member_kind": "property",
        "visibility": "public",
        "is_static": false,
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.object.__class__" }
      }, {
        "id": "member.builtins-object.eq",
        "owner": "type.builtins-object",
        "name": "__eq__",
        "member_kind": "method",
        "visibility": "public",
        "is_static": false,
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.object.__eq__" }
      }, {
        "id": "member.builtins-str.strip",
        "owner": "type.builtins-str",
        "name": "strip",
        "member_kind": "method",
        "visibility": "public",
        "is_static": false,
        "locator": { "kind": "artifact", "path": "builtins.pyi", "symbol": "builtins.str.strip" }
      }],
      "relations": []
    }
  }]
}"#;

/// The plan's Purpose example: `read_config` passes an `int` into a parameter
/// whose body calls `strip`, a member `builtins.int` does not declare.
const TYPE_FLOW_PURPOSE_FIXTURE: &str =
    "def normalize(x):\n    return x.strip()\n\ndef read_config():\n    return normalize(123)\n";

fn type_flow_workspace() -> (inline_project::BuiltInlineTestProject, WorkspaceAnalyzer) {
    type_flow_workspace_with_source(TYPE_FLOW_PURPOSE_FIXTURE)
}

fn type_flow_workspace_with_source(
    source: &str,
) -> (inline_project::BuiltInlineTestProject, WorkspaceAnalyzer) {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pack = compile_source(
        SourceFormat::Json,
        TYPE_FLOW_BUILTINS_PACK.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("builtins fixture pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:rql-type-flow.builtins".to_owned(),
            },
        )
        .expect("register builtins fixture pack");
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
                package: None,
                module: None,
                toolchain: Some(crate::analyzer::semantic_model::CatalogCoordinate {
                    name: "cpython".to_owned(),
                    version: Some(Version::parse("3.12.0").expect("toolchain version parses")),
                }),
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(
        matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
        "builtins fixture pack activates: {activation:#?}"
    );
    (project, workspace)
}

fn type_flow_query(root: &str, op: &str) -> serde_json::Value {
    json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": root },
        "steps": [
            { "op": "procedure_of" },
            { "op": op }
        ],
        "result_detail": "full"
    })
}

/// The class-set step reports, for the caller's parameter binding, the one
/// class that reaches `x.strip()` -- `builtins.int`, introduced by the literal
/// `123` -- and, for the isolated root, the honest unknown instead of a guess.
#[test]
fn python_class_set_rows_report_receiver_classes_and_unknown_origins() {
    let (_project, workspace) = type_flow_workspace();

    let query = CodeQuery::from_json(&type_flow_query("read_config", "class_set"))
        .expect("class_set query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ClassSetRow { value } = &item.value else {
                panic!("class_set returns its typed row: {item:#?}");
            };
            (
                value.file.as_str(),
                value.range.start_line,
                value.member.as_str(),
                value.class.as_deref(),
                value.origin.as_str(),
                value.status,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [(
            "app.py",
            2,
            "strip",
            Some("builtins.int"),
            "external",
            "known"
        )],
        "{result:#?}"
    );

    let query =
        CodeQuery::from_json(&type_flow_query("normalize", "class_set")).expect("class_set query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ClassSetRow { value } = &item.value else {
                panic!("class_set returns its typed row: {item:#?}");
            };
            (
                value.member.as_str(),
                value.class.as_deref(),
                value.origin.as_str(),
                value.status,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [("strip", None, "unknown:root_parameter", "partial")],
        "an unclassified receiver states its reason and carries no class: {result:#?}"
    );
}

/// The absent-member step reports the finding: the member, the class that
/// lacks it, the member-access range, the origin site that introduced the
/// class, the root it ran from, and the retained witness size.
#[test]
fn python_absent_member_rows_report_the_finding_and_its_origin() {
    let (_project, workspace) = type_flow_workspace();

    let query = CodeQuery::from_json(&type_flow_query("read_config", "absent_member"))
        .expect("absent_member query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let [item] = result.results.as_slice() else {
        panic!("exactly one absent-member finding: {result:#?}");
    };
    let CodeQueryResultValue::AbsentMemberFinding { value } = &item.value else {
        panic!("absent_member returns its typed row: {item:#?}");
    };
    assert_eq!(value.file, "app.py");
    assert_eq!(
        value.range.start_line, 2,
        "the `x.strip()` access: {value:#?}"
    );
    assert_eq!(value.member, "strip");
    assert_eq!(value.class, "builtins.int");
    assert_eq!(value.origin_file, "app.py");
    assert_eq!(
        value.origin_range.start_line, 5,
        "the `normalize(123)` call that introduced the class: {value:#?}"
    );
    assert_eq!(value.caller, "read_config");
    assert!(value.witness_steps >= 1, "{value:#?}");

    // The isolated root classifies nothing, and an unproven receiver is no
    // finding at all.
    let query = CodeQuery::from_json(&type_flow_query("normalize", "absent_member"))
        .expect("absent_member query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(
        result.results.is_empty(),
        "a partial class set produces no finding: {result:#?}"
    );
}

/// The query cost pin: one class-set solve per input procedure per query. Two
/// branches consuming the same procedure in one query share the cached solve.
#[test]
fn class_set_and_absent_member_share_one_solve_per_input_procedure() {
    let (_project, workspace) = type_flow_workspace();

    let branch = json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "union": [branch.clone(), branch]
    }))
    .expect("union profile query");
    let response = execute_workspace_request(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("a profile-mode query returns its profile: {response:#?}");
    };
    let type_flow = profile.work.semantic.type_flow;
    assert_eq!(type_flow.field_slot_builds, 1, "{type_flow:#?}");
    assert_eq!(type_flow.solves, 1, "{type_flow:#?}");
    assert_eq!(type_flow.cache_hits, 1, "{type_flow:#?}");
    assert_eq!(type_flow.class_set_rows, 2, "{type_flow:#?}");
    assert_eq!(type_flow.failed_solves, 0, "{type_flow:#?}");

    // The finding step shares the same accounting: one solve per input
    // procedure even when several roots go in.
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ]
    }))
    .expect("absent_member profile query");
    let response = execute_workspace_request(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("a profile-mode query returns its profile: {response:#?}");
    };
    let type_flow = profile.work.semantic.type_flow;
    assert_eq!(type_flow.field_slot_builds, 1, "{type_flow:#?}");
    assert_eq!(type_flow.solves, 2, "{type_flow:#?}");
    assert_eq!(type_flow.cache_hits, 0, "{type_flow:#?}");
    assert_eq!(type_flow.finding_rows, 1, "{type_flow:#?}");
    assert_eq!(type_flow.failed_solves, 0, "{type_flow:#?}");
}

/// A language with no registered adapter is an explicit unsupported
/// diagnostic, never an empty answer that reads as "no classes".
#[test]
fn class_set_reports_unsupported_languages() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            "package main\n\nfunc read_config() int { return 1 }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ]
    }))
    .expect("class_set query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(result.results.is_empty(), "{result:#?}");
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticCapabilityUnsupported
        }),
        "{result:#?}"
    );
}

/// #2956: a receiver no call in the closure produced, under a root kept
/// boundary-open by an unrelated external call, is an honest
/// `unknown:incomplete_root` row -- the pre-split vocabulary reported the
/// unexplained loss as `budget`.
#[test]
fn python_class_set_rows_name_incomplete_root_for_an_uncoverable_receiver() {
    let fixture = "import os\n\ndef root():\n    os.system(\"echo hi\")\n    def inner(x):\n        return x.foo()\n    return 1\n";
    let (_project, workspace) = type_flow_workspace_with_source(fixture);
    let query =
        CodeQuery::from_json(&type_flow_query("root", "class_set")).expect("class_set query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let rows = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ClassSetRow { value } = &item.value else {
                panic!("class_set returns its typed row: {item:#?}");
            };
            (
                value.range.start_line,
                value.member.as_str(),
                value.class.as_deref(),
                value.origin.as_str(),
                value.status,
            )
        })
        .collect::<Vec<_>>();
    assert!(
        rows.contains(&(6, "foo", None, "unknown:incomplete_root", "inconclusive")),
        "the never-called nested function's receiver states why it is unreached: {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|(_, _, _, origin, _)| *origin != "unknown:budget"),
        "the retired label is gone: {rows:?}"
    );
}

/// #2956: each root of one query solves against its own child of the query's
/// semantic budget. The cap below sits between one root's spend and the
/// cumulative spend of both roots (96 versus 246 program points measured
/// with the default limits): a shared ledger exhausts during the second
/// root, but per-root children let both roots classify. The query-wide
/// aggregate may still saturate the parent ledger's accounting -- that
/// ceiling must not touch the rows.
#[test]
fn class_set_roots_do_not_inherit_each_others_semantic_spend() {
    let (_project, workspace) = type_flow_workspace();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");
    let limits = |cap: usize| CodeQueryExecutionLimits {
        semantic: CodeQuerySemanticLimits {
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                if dimension == SemanticBudgetDimension::ProgramPoints {
                    cap
                } else {
                    1 << 20
                }
            })),
            ..CodeQuerySemanticLimits::default()
        },
        ..CodeQueryExecutionLimits::default()
    };
    let response = execute_workspace_request_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        limits(96),
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("a profile-mode query returns its profile: {response:#?}");
    };
    let mut origins: Vec<(String, Option<String>, String, String)> = profile
        .result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::ClassSetRow { value } = &item.value else {
                panic!("class_set returns its typed row: {item:#?}");
            };
            (
                value.member.clone(),
                value.class.clone(),
                value.origin.clone(),
                value.status.to_string(),
            )
        })
        .collect();
    origins.sort();
    assert_eq!(
        origins,
        vec![
            (
                "strip".to_string(),
                None,
                "unknown:root_parameter".to_string(),
                "partial".to_string(),
            ),
            (
                "strip".to_string(),
                Some("builtins.int".to_string()),
                "external".to_string(),
                "known".to_string(),
            ),
        ],
        "both roots classify exactly as with unconstrained limits: {profile:#?}",
    );
    let type_flow = profile.work.semantic.type_flow;
    assert_eq!(type_flow.solves, 2, "{type_flow:#?}");
    assert_eq!(type_flow.failed_solves, 0, "{type_flow:#?}");
}

/// #2956: a root whose own child ledger cannot fund its solve reports the
/// exhaustion twice over, honestly: the unreached sink carries the
/// `semantic_budget` reason, and the executor raises the
/// `SemanticBudgetExhausted` diagnostic the value-flow and typestate
/// executors already raise.
#[test]
fn semantic_budget_exhaustion_is_a_reason_label_and_a_diagnostic() {
    let (_project, workspace) = type_flow_workspace();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");
    let response = execute_workspace_request_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                    if dimension == SemanticBudgetDimension::ProgramPoints {
                        24
                    } else {
                        1 << 20
                    }
                })),
                ..CodeQuerySemanticLimits::default()
            },
            ..CodeQueryExecutionLimits::default()
        },
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("a profile-mode query returns its profile: {response:#?}");
    };
    assert!(
        profile.work.semantic.budget_exhausted,
        "the executor surfaces the exhaustion: {profile:#?}"
    );
    assert!(
        profile
            .result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted),
        "the diagnostic is raised: {profile:#?}"
    );
    let origins: Vec<&str> = profile
        .result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::ClassSetRow { value } => Some(value.origin.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        origins.contains(&"unknown:semantic_budget"),
        "the unreached sink names the semantic budget: {origins:?}"
    );
}
