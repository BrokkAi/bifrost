use super::contracts::assert_serial_profile_reconciles;
use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::semantic::{
    SemanticBudget, SemanticBudgetDimension, SemanticEffect, SemanticRequest, SemanticValueKind,
    ValueFlowKind,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use crate::analyzer::usages::effects::EffectCoverage;
use crate::cancellation::CancellationToken;
use semver::Version;

#[test]
fn row_filter_and_projection_execute_over_public_occurrence_fields() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "fn helper() {}\nfn run() { helper(); helper(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(
        r#"(filter :where (
                (class eq reference)
                (class ne declaration)
                (class in [reference])
                (candidates eq (field candidates))
                (candidates lt 2)
                (candidates le 1)
                (candidates gt 0)
                (candidates ge 1)
                (site ne "missing"))
              (project :columns ((ast_id site) (target_count candidates) class)
                (filter :where ((target_count is-not-null))
                  (occurrences :class reference))))"#,
    )
    .expect("typed row query");

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert_eq!(result.results.len(), 2, "{}", result.render_text());
    for item in &result.results {
        assert_eq!(
            item.row_projection
                .iter()
                .map(|column| (column.source.as_str(), column.name.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("ast_id", "site"),
                ("target_count", "candidates"),
                ("class", "class"),
            ]
        );
        let projected = UnitRowItem::project(item);
        assert!(projected.field("site").expect("site field").is_some());
        assert_eq!(
            projected.field("candidates").expect("candidate count"),
            Some(CodeQueryRowScalarRef::Integer(1))
        );
        assert_eq!(
            projected.field("class").expect("class field"),
            Some(CodeQueryRowScalarRef::ConstrainedEnum("reference"))
        );
        assert!(projected.field("ast_id").is_err());
    }

    let null_query = CodeQuery::from_source(
        "(filter :where ((target_id is-null)) (occurrences :class declaration))",
    )
    .expect("nullable row query");
    let null_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &null_query,
    );
    assert!(
        !null_result.results.is_empty(),
        "{}",
        null_result.render_text()
    );

    let absent_ne_query = CodeQuery::from_source(
        r#"(filter :where ((target_id ne "missing")) (occurrences :class declaration))"#,
    )
    .expect("absent comparison query");
    let absent_ne_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &absent_ne_query,
    );
    assert!(
        absent_ne_result.results.is_empty(),
        "absent values must not satisfy ne: {}",
        absent_ne_result.render_text()
    );
}

#[test]
fn direct_receiver_terminal_steps_match_explicit_receiver_analysis() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "struct Service;\nimpl Service { fn run(&self) {} }\nfn caller(service: Service) { service.run(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let execute_values = |source: &str| {
        let query = CodeQuery::from_source(source).expect("receiver row query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
        .results
        .into_iter()
        .map(|item| {
            let mut value = serde_json::to_value(item.value).expect("serializable row value");
            let object = value.as_object_mut().expect("result values are objects");
            object.remove("scope_nodes");
            object.remove("setup_nodes");
            value
        })
        .collect::<Vec<_>>()
    };

    let direct_outcomes =
        execute_values("(receiver-outcome (occurrences :role [member_position]))");
    let explicit_outcomes = execute_values(
        "(receiver-outcome (receiver-targets (occurrences :role [member_position])))",
    );
    assert!(!direct_outcomes.is_empty());
    assert_eq!(direct_outcomes, explicit_outcomes);

    let direct_evidence =
        execute_values("(receiver-evidence (occurrences :role [member_position]))");
    let explicit_evidence = execute_values(
        "(receiver-evidence (receiver-targets (occurrences :role [member_position])))",
    );
    assert!(!direct_evidence.is_empty());
    assert_eq!(direct_evidence, explicit_evidence);
}

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

#[derive(Clone)]
struct ImportUnsupportedAnalyzer {
    inner: PhpAnalyzer,
}

impl CodeUnitIndex for ImportUnsupportedAnalyzer {
    fn project(&self) -> &dyn crate::analyzer::Project {
        CodeUnitIndex::project(&self.inner)
    }

    fn languages(&self) -> BTreeSet<Language> {
        CodeUnitIndex::languages(&self.inner)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        CodeUnitIndex::all_declarations(&self.inner)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        CodeUnitIndex::search_definitions(&self.inner, pattern, auto_quote)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        CodeUnitIndex::enclosing_code_unit(&self.inner, file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        CodeUnitIndex::enclosing_code_unit_for_lines(&self.inner, file, start_line, end_line)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        CodeUnitIndex::get_skeleton(&self.inner, code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        CodeUnitIndex::get_skeleton_header(&self.inner, code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        CodeUnitIndex::get_source(&self.inner, code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        CodeUnitIndex::get_sources(&self.inner, code_unit, include_comments)
    }
}

impl IAnalyzer for ImportUnsupportedAnalyzer {
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: IAnalyzer::update(&self.inner, changed_files),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: IAnalyzer::update_all(&self.inner),
        }
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        IAnalyzer::extract_call_receiver(&self.inner, reference)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        IAnalyzer::is_access_expression(&self.inner, file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        IAnalyzer::find_nearest_declaration(&self.inner, file, start_byte, end_byte, ident)
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        IAnalyzer::structural_fact_providers(&self.inner)
    }
}

#[test]
fn profile_marks_unsupported_import_builds_and_replays_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.php"))
        .write("<?php\nfunction target() {}\n")
        .expect("write source");
    // Every shipped language now has an import provider. Hide PHP's provider
    // behind a test adapter while retaining its real structural facts so this
    // remains a capability-gap test instead of depending on a stale matrix.
    let analyzer = ImportUnsupportedAnalyzer {
        inner: PhpAnalyzer::from_project(TestProject::new(root, Language::Php)),
    };
    assert!(analyzer.import_analysis_provider().is_none());
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
fn go_assertion_payload_workspace_proof_requires_current_source_and_budget() {
    use crate::analyzer::semantic::{SemanticOutcome, TransferKind, ValueTransfer};
    use crate::analyzer::workspace_reference_assertion_accepts_payload;

    for (asserted, expected) in [("*Cell", true), ("*Other", false)] {
        let source = format!(
            "package p\ntype Cell struct {{ n int }}\ntype Other struct {{ n int }}\nfunc f() {{ shared := &Cell{{}}; var boxed any = shared; _ = boxed.({asserted}); boxed = &Other{{}} }}\n"
        );
        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", &source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go artifact");
        let artifact = outcome.available_value().expect("available artifact");
        let mut payload = None;
        let mut assertion = None;
        for procedure in artifact.procedures() {
            let handle = artifact.procedure_handle(procedure.id()).unwrap();
            for event in procedure.points().iter().flat_map(|point| &point.events) {
                match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::ReferenceBoxing,
                        source,
                        ..
                    } if payload.is_none() => {
                        payload = handle.value_handle(source);
                    }
                    SemanticEffect::ValueFlow {
                        kind:
                            ValueFlowKind::Transfer(ValueTransfer {
                                kind: TransferKind::Unboxing,
                                ..
                            }),
                        target,
                        ..
                    } => assertion = handle.value_handle(target),
                    _ => {}
                }
            }
        }
        let payload = payload.expect("boxed payload");
        let assertion = assertion.expect("mutable-interface assertion requires a query");
        let mut budget = SemanticBudget::default();
        let outcome = workspace_reference_assertion_accepts_payload(
            &workspace,
            &assertion,
            &payload,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
        assert!(
            matches!(outcome, SemanticOutcome::Complete { value, .. } if value == expected),
            "{outcome:?}"
        );
        assert_eq!(budget.used(), outcome.work(), "all query work is charged");
        assert_eq!(outcome.work().source_bytes, source.len());
        assert!(outcome.work().nested_entries > 0);

        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = 1;
        let mut bounded = SemanticBudget::new(limits).unwrap();
        assert!(matches!(
            workspace_reference_assertion_accepts_payload(
                &workspace,
                &assertion,
                &payload,
                &mut SemanticRequest::new(&mut bounded, &cancellation),
            )
            .unwrap(),
            SemanticOutcome::ExceededBudget { .. }
        ));
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            workspace_reference_assertion_accepts_payload(
                &workspace,
                &assertion,
                &payload,
                &mut SemanticRequest::new(&mut budget, &cancelled),
            )
            .unwrap(),
            SemanticOutcome::Cancelled { .. }
        ));

        file.write("package p\nfunc replacement() {}\n").unwrap();
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        assert!(
            workspace_reference_assertion_accepts_payload(
                &changed_workspace,
                &assertion,
                &payload,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .is_err(),
            "stale handles must not read the new source at old offsets"
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

fn assert_open_loop_cell_relations(result: &CodeQueryResult) {
    assert!(!result.results.is_empty(), "{result:#?}");
    for item in &result.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        assert_eq!(
            (value.location_kind.as_str(), value.proof, value.coverage),
            ("lexical_cell", "open", "open"),
            "loop-cell instance identity remains open: {result:#?}"
        );
        // The source joins each iteration's children, but a declaration-level
        // WaitGroup name does not prove that iteration correspondence. Any
        // retained relation stays unproven until those scoped facts exist.
        assert_eq!(value.reasons, ["unknown_location"], "{result:#?}");
    }
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
    // `writeCopiedOptions` declares a value parameter, so the binding is
    // refused before an alias set is built. The location is unknown because
    // the callee writes its own copy, and there is nothing left to truncate;
    // this used to report both reasons because it attempted the binding first.
    assert_eq!(value.reasons, ["unknown_location"], "{copied_struct:#?}");

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

/// A race on a variable declared in another package must be found, and the
/// two occurrences must be recognised as one storage.
///
/// Go's semantic adapter declares no intra-file dependencies, so it cannot
/// read the declaring file and records `pkg.Name` as an occurrence with its
/// identity marked unresolved. While that occurrence was dropped entirely, a
/// cross-package race produced no accesses, no compared pair, and no open
/// reason, so the shipped policy reported a clean and complete run on a racy
/// program. Every multi-package Go repository was affected.
#[test]
fn go_conflicts_resolve_a_variable_declared_in_another_package() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go.mod",
            "module example.com/xpkg

go 1.22
",
        )
        .file(
            "inner/inner.go",
            "package inner

var Shared int

var Other int
",
        )
        .file(
            "main.go",
            r#"package main

import "example.com/xpkg/inner"

func racesOnImportedVar() int {
    go func() { inner.Shared = 1 }()
    return inner.Shared
}

func distinctImportedVars() int {
    go func() { inner.Shared = 1 }()
    return inner.Other
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
        .expect("imported package variable concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    let raced = conflicts_for("racesOnImportedVar");
    let value = find_concurrent_relation(&raced, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // Resolving to the declaration must separate two variables of one package,
    // not merge everything reached through the same import.
    let distinct = conflicts_for("distinctImportedVars");
    assert!(
        !distinct.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict"
        )),
        "distinct imported variables must not alias: {distinct:#?}"
    );
}

/// A race on a package variable declared in another file of the same package
/// must be found, and two distinct such variables must stay apart.
///
/// `package_value_locators` is filled by walking one file, so a variable
/// declared elsewhere in the package was absent from it and its occurrences
/// became no location and no access at all. The race was missed with nothing
/// reported open, which is the shape bbolt's traversal hits at every hop
/// between `tx.go`, `bucket.go` and `node.go`.
#[test]
fn go_conflicts_resolve_a_package_variable_declared_in_another_file() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/crossfile\n\ngo 1.22\n")
        .file(
            "state.go",
            r#"package main

var counter int

var other int

func bumpCounter() { counter = 1 }

func bumpOther() { other = 1 }
"#,
        )
        .file(
            "main.go",
            r#"package main

func racesOnCrossFileVar() int {
    go bumpCounter()
    return counter
}

func distinctCrossFileVars() int {
    go bumpOther()
    return counter
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
        .expect("cross-file package variable concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    let raced = conflicts_for("racesOnCrossFileVar");
    let value = find_concurrent_relation(&raced, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // Resolving to the declaration is what separates two variables of one
    // file; giving every unresolved name one identity would merge them.
    let distinct = conflicts_for("distinctCrossFileVars");
    assert!(
        !distinct.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict"
        )),
        "distinct cross-file variables must not alias: {distinct:#?}"
    );
}

/// A field written directly inside a spawned closure must race with the same
/// field read in the parent, and distinct fields must stay apart.
///
/// The producer resolves a field only where it can type the receiver. A
/// capture inside the closure cannot be typed, so it anchored the member at
/// the use while the parent anchored at the declaration; the two then
/// described one field differently and the pair was declared disjoint with
/// nothing reported. A map or slice captured the same way was compared
/// correctly, which is why this stayed hidden.
#[test]
fn go_conflicts_compare_a_field_written_inside_a_spawned_closure() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    value int
    other int
}

func racesOnCapturedField() int {
    c := &cell{}
    go func() { c.value = 1 }()
    return c.value
}

func distinctCapturedFields() int {
    c := &cell{}
    go func() { c.other = 1 }()
    return c.value
}

func distinctCapturedObjects() int {
    written := &cell{}
    read := &cell{}
    go func() { written.value = 1 }()
    return read.value
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
        .expect("captured field concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    let raced = conflicts_for("racesOnCapturedField");
    let value = find_concurrent_relation(&raced, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // Naming the declaration must separate two fields of one struct, and two
    // objects of one type; giving every unresolved member one identity would
    // merge either pair.
    for name in ["distinctCapturedFields", "distinctCapturedObjects"] {
        let result = conflicts_for(name);
        assert!(
            !result.results.iter().any(|item| matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )),
            "{name} must not alias: {result:#?}"
        );
    }
}

#[test]
fn go_conflicts_follow_a_pointer_receiver_into_the_method_it_calls() {
    // The methods are declared away from their callers. A producer resolves a
    // field only where it can type the receiver, so a same-file fixture is
    // already answered by the caller's own typing and would pass without the
    // call-boundary binding this test covers.
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "cell.go",
            r#"package main

type cell struct {
    value int
}

func (c *cell) writeThrough() { c.value = 1 }

func (c cell) writeCopy() { c.value = 1 }
"#,
        )
        .file(
            "main.go",
            r#"package main

func racesThroughPointerReceiver() int {
    c := &cell{}
    go func() { c.writeThrough() }()
    return c.value
}

func copiesThroughValueReceiver() int {
    c := cell{}
    go func() { c.writeCopy() }()
    return c.value
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
        .expect("receiver binding concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    // Go copies the receiver. A pointer receiver copies the pointer, so the
    // method's write reaches the caller's object and races the caller's read.
    let raced = conflicts_for("racesThroughPointerReceiver");
    let value = find_concurrent_relation(&raced, |value| {
        value.verdict == "conflict" && value.location_kind == "field"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // A value receiver copies the fields it writes, so the caller's object is
    // never written and no race can be proven. Admitting every receiver
    // binding proved this pair instead, which was a false positive.
    let copied = conflicts_for("copiesThroughValueReceiver");
    assert!(
        !copied.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
        )),
        "a value receiver copies the field it writes: {copied:#?}"
    );
}

#[test]
fn go_conflicts_reach_a_body_named_by_a_function_valued_parameter() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type st struct {
    n int
}

func (s *st) bump() { s.n = 1 }

func eachOf(s *st, fn func(*st)) { fn(s) }
func eachValue(s st, fn func(st)) { fn(s) }

func reachesTheWriteThroughACallback() int {
    s := &st{}
    go func() { eachOf(s, func(x *st) { x.bump() }) }()
    return s.n
}

func reachesTheWriteDirectly() int {
    s := &st{}
    go s.bump()
    return s.n
}

func copiesTheValueThroughACallback() int {
    s := st{}
    go func() { eachValue(s, func(x st) { x.n = 1 }) }()
    return s.n
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
        .expect("callback parameter concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    // `fn(s)` names no declaration this procedure can resolve, because the
    // caller chooses the body. The producer records the flow from the `fn`
    // binding to the callable value, and the binding carries the callable
    // across the call, so the callback's write is compared after all.
    let through_callback = conflicts_for("reachesTheWriteThroughACallback");
    assert_eq!(
        through_callback.completion(),
        CodeQueryCompletion::Complete,
        "{through_callback:#?}"
    );
    let value = find_concurrent_relation(&through_callback, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{through_callback:#?}"
    );

    // The same write reached directly, as the control.
    let direct = conflicts_for("reachesTheWriteDirectly");
    assert_eq!(
        direct.completion(),
        CodeQueryCompletion::Complete,
        "{direct:#?}"
    );
    let value = find_concurrent_relation(&direct, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{direct:#?}"
    );
    let copied = conflicts_for("copiesTheValueThroughACallback");
    assert_no_proven_conflicts_with_explanation(&copied);
}

#[test]
fn go_concurrent_access_conflicts_keep_cross_file_parameter_copies_separate() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("types.go", "package main\ntype Cell struct { n int }\n")
        .file(
            "helpers.go",
            "package main\ntype CopyAlias = Cell\nfunc writeValue(c Cell) { c.n = 1 }\nfunc writeAlias(c CopyAlias) { c.n = 1 }\nfunc writePointer(c *Cell) { c.n = 1 }\n",
        )
        .file(
            "main.go",
            r#"package main
func crossFileCopy() int {
    c := Cell{}
    go writeValue(c)
    return c.n
}
func crossFilePointer() int {
    c := &Cell{}
    go writePointer(c)
    return c.n
}
func crossFileAliasCopy() int {
    c := Cell{}
    go writeAlias(c)
    return c.n
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let shared = go_invocation_conflicts(&workspace, "crossFilePointer");
    assert_proven_unordered_unprotected_conflict(&shared, "crossFilePointer");
    for root in ["crossFileCopy", "crossFileAliasCopy"] {
        let copied = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&copied);
    }
}

#[test]
fn go_conflicts_read_the_declared_parameter_before_crossing_a_call_boundary() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    value int
}

func writeThrough(c *cell) { c.value = 1 }

func writeCopy(c cell) { c.value = 1 }

func racesThroughPointerParameter() int {
    c := &cell{}
    go writeThrough(c)
    return c.value
}

func copiesThroughValueParameter() int {
    c := cell{}
    go writeCopy(c)
    return c.value
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
        .expect("parameter binding concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    // A pointer parameter copies the pointer, so the callee's write reaches
    // the caller's object and races the caller's read.
    let raced = conflicts_for("racesThroughPointerParameter");
    let value = find_concurrent_relation(&raced, |value| {
        value.verdict == "conflict" && value.location_kind == "field"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // A value parameter copies the fields it writes. The caller could type its
    // own local, which handed the binding a proven identity and proved a race
    // Go cannot have.
    let copied = conflicts_for("copiesThroughValueParameter");
    assert!(
        !copied.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
        )),
        "a value parameter copies the field it writes: {copied:#?}"
    );
}

#[test]
fn go_conflicts_name_a_field_loaded_through_another_field() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type inner struct {
    n int
}

type outer struct {
    in *inner
}

func (o *outer) writeNested() { o.in.n = 1 }

type innerValue struct {
    n int
}

type outerValue struct {
    in innerValue
}

func (o outerValue) writeCopiedChain() { o.in.n = 1 }

func (o outer) writeThroughCopiedPointer() { o.in.n = 1 }

type stats struct {
    count int
}

type transaction struct {
    counters stats
}

type holder struct {
    tx *transaction
}

func (h *holder) writeThreeDeep() { h.tx.counters.count = 1 }

func racesThroughNestedFields() int {
    o := &outer{in: &inner{}}
    go o.writeNested()
    return o.in.n
}

func copiesTheWholeChain() int {
    o := outerValue{}
    go o.writeCopiedChain()
    return o.in.n
}

func racesThroughACopiedPointerField() int {
    o := &outer{in: &inner{}}
    go o.writeThroughCopiedPointer()
    return o.in.n
}

func racesThroughThreeFieldSteps() int {
    h := &holder{tx: &transaction{}}
    go h.writeThreeDeep()
    return h.tx.counters.count
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
        .expect("nested field chain concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    // `o.in.n` loads a field out of a field. The inner load's result is
    // neither captured nor freshly allocated, so without composing the chain
    // it had no name and the write could not pair with anything at all. This
    // is bbolt's `b.tx.stats.CursorCount++`.
    let raced = conflicts_for("racesThroughNestedFields");
    let value = find_concurrent_relation(&raced, |value| {
        value.verdict == "conflict" && value.location_kind == "field"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // The chain is composed over the ordinary equivalence classes, not the
    // backing ones. Backing identity deliberately crosses a copy, because a
    // map or slice descriptor inside a copied struct still names one store; a
    // direct field does not survive one. Composing over backing classes
    // proved this pair, which is a race Go cannot have.
    let copied = conflicts_for("copiesTheWholeChain");
    assert!(
        !copied.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
        )),
        "a value receiver copies the whole chain it writes: {copied:#?}"
    );

    // A value receiver copies the struct, but a pointer field inside that copy
    // still addresses one object, so this does race. Refusing every value
    // receiver alike reported nothing here, which is the silent miss the copy
    // rule must not buy. The chain crossed a pointer field, so it may use the
    // identity that survives a copy.
    let through_pointer = conflicts_for("racesThroughACopiedPointerField");
    let value = find_concurrent_relation(&through_pointer, |value| {
        value.verdict == "conflict" && value.location_kind == "field"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{through_pointer:#?}"
    );

    // Three steps, which is bbolt's `b.tx.stats.CursorCount++`. Every step of
    // a composed chain must be named the way the outermost one already is.
    // Naming an inner step by its locator's own digest made the two sides
    // agree on their first and last steps and disagree in the middle, so a
    // chain of three reported nothing at all while a chain of two proved.
    let three_deep = conflicts_for("racesThroughThreeFieldSteps");
    let value = find_concurrent_relation(&three_deep, |value| {
        value.verdict == "conflict" && value.location_kind == "field"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{three_deep:#?}"
    );
}

#[test]
fn go_conflicts_report_a_write_the_producer_did_not_model() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

func writesThroughAPointerToALocal() int {
    value := 0
    cell := &value
    go func() { *cell = 1 }()
    return value
}

func writesTheLocalDirectly() int {
    value := 0
    go func() { value = 1 }()
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
        .expect("unmodeled memory concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    // Go does not lower a store through a pointer dereference and says so, in
    // a gap naming the capability it fell short of. Nothing consumed that, so
    // the write simply was not there and the answer read as clean. An omitted
    // access is not the absence of a race, it is an unasked question.
    let indirect = conflicts_for("writesThroughAPointerToALocal");
    assert_ne!(
        indirect.completion(),
        CodeQueryCompletion::Complete,
        "a write the producer did not model must not read as clean: \
         {indirect:#?}"
    );

    // The same write spelled directly is modelled, so it stays complete and
    // proven. The gap is read per procedure, not applied as a blanket doubt.
    let direct = conflicts_for("writesTheLocalDirectly");
    assert_eq!(
        direct.completion(),
        CodeQueryCompletion::Complete,
        "{direct:#?}"
    );
    let value = find_concurrent_relation(&direct, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{direct:#?}"
    );
}

#[test]
fn go_conflicts_name_one_object_reached_through_a_second_local() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    value int
}

type plain struct {
    value int
}

func racesThroughASecondLocal() int {
    first := &cell{}
    second := first
    go func() { second.value = 1 }()
    return first.value
}

func copiesIntoASecondLocal() int {
    first := plain{}
    second := first
    go func() { second.value = 1 }()
    return first.value
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
        .expect("second local concurrent access query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };

    // One object, reached two ways. The parent reads it as a value and names
    // the allocation; the closure reaches it through the cell the capture
    // unions and named the cell, so the pair read as disjoint. A cell written
    // once may now answer with the reference it holds.
    let raced = conflicts_for("racesThroughASecondLocal");
    let value = find_concurrent_relation(&raced, |value| {
        value.verdict == "conflict" && value.location_kind == "field"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{raced:#?}"
    );

    // `second := first` on a struct copies the object, so the two locals are
    // two objects and the closure writes its own. Only an allocation that
    // yields a reference may be carried onto the cell that stores it.
    let copied = conflicts_for("copiesIntoASecondLocal");
    assert!(
        !copied.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
        )),
        "assigning a struct to a second local copies it: {copied:#?}"
    );
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

func unsafeBoundaryAfter() int {
    value := 0
    go func() { value = 1 }()
    observed := value
    pointer := unsafe.Pointer(&value)
    _ = pointer
    return observed
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

func cgoBoundaryAfter() int {
    value := 0
    go func() {
        value = 1
        C.noop()
    }()
    observed := value
    C.noop()
    return observed
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    for (name, expected_proof, expected_coverage, expected_reasons) in [
        ("unsafeBoundary", "open", "open", vec!["unresolved_target"]),
        ("cgoBoundary", "open", "open", vec!["unresolved_target"]),
        ("unsafeBoundaryAfter", "proven", "exhaustive", vec![]),
        ("cgoBoundaryAfter", "proven", "exhaustive", vec![]),
    ] {
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
            (expected_proof, expected_coverage),
            "only a boundary after both observations is independent of their ordering: {name}: {result:#?}"
        );
        assert_eq!(value.reasons, expected_reasons, "{name}: {result:#?}");
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

type guardedFlag struct {
    lock sync.Mutex
    flag bool
}

// Keep a nested imported method selector in a real synchronization proof. The
// selector itself denotes the method, while the receiver field remains the
// lock subject; treating the terminal `Lock`/`Unlock` names as field storage
// introduces unrelated access rows.
func methodSelectorNoFieldRead() int {
    guarded := &guardedFlag{}
    value := 0
    go func() {
        guarded.lock.Lock()
        value = 1
        guarded.lock.Unlock()
    }()
    guarded.lock.Lock()
    result := value
    guarded.lock.Unlock()
    return result
}

type functionFieldHolder struct {
    callback func()
}

// The callback field is itself shared storage. Calling through it must retain
// the field load even when the stored value is a function.
func functionValuedFieldLoadRace() {
    holder := &functionFieldHolder{callback: func() {}}
    go func() { holder.callback = func() {} }()
    holder.callback()
}

func functionFieldAfterUnknownCall(before func()) {
    holder := &functionFieldHolder{callback: func() {}}
    go func() { holder.callback = func() {} }()
    before()
    holder.callback()
}

type boundMethodFieldHolder struct {
    callback func()
}

func (holder *boundMethodFieldHolder) callbackMethod() {}

// A bound method stored in a function field still requires reading that field
// at the call site. Target declaration kind must not suppress the field race.
func boundMethodFieldLoadRace() {
    holder := &boundMethodFieldHolder{}
    holder.callback = holder.callbackMethod
    go func() { holder.callback = holder.callbackMethod }()
    holder.callback()
}

func (guarded *guardedFlag) set() {
    guarded.lock.Lock()
    defer guarded.lock.Unlock()
    guarded.flag = true
}

func repeatedFieldMutex() {
    guarded := &guardedFlag{}
    for index := 0; index < 2; index++ {
        go guarded.set()
    }
}

type oppositeBranchGuard struct {
    first sync.Mutex
    second sync.Mutex
    value int
}

func oppositeBranchWrite(guarded *oppositeBranchGuard, chooseFirst bool) {
    if chooseFirst {
        guarded.first.Lock()
        guarded.value++
        guarded.first.Unlock()
    } else {
        guarded.second.Lock()
        guarded.value++
        guarded.second.Unlock()
    }
}

func repeatedOppositeBranchDistinctLocks() {
    guarded := &oppositeBranchGuard{}
    for index := 0; index < 2; index++ {
        go oppositeBranchWrite(guarded, index == 0)
    }
}

func nonrepeatedOppositeBranchDistinctLocks(chooseFirst bool) {
    guarded := &oppositeBranchGuard{}
    go oppositeBranchWrite(guarded, chooseFirst)
}

func oppositeBranchChild(guarded *oppositeBranchGuard, chooseFirst bool) {
    if chooseFirst {
        go func() {
            guarded.first.Lock()
            guarded.value++
            guarded.first.Unlock()
        }()
    } else {
        go func() {
            guarded.second.Lock()
            guarded.value++
            guarded.second.Unlock()
        }()
    }
}

func repeatedOppositeBranchChildTasks() {
    guarded := &oppositeBranchGuard{}
    for index := 0; index < 2; index++ {
        oppositeBranchChild(guarded, index == 0)
    }
}

func nonrepeatedOppositeBranchChildTasks(chooseFirst bool) {
    guarded := &oppositeBranchGuard{}
    oppositeBranchChild(guarded, chooseFirst)
}

// One field mutex reached three ways: from a closure that captures the
// struct, from the enclosing function directly, and from a method on it.
// A producer stores the field's declaration only where it can type the
// receiver, so these three occurrences carry different locators for one
// field, and every one of them has to compose the same lock identity.
func closureCapturedFieldMutex() int {
    guarded := &guardedFlag{}
    value := 0
    go func() {
        guarded.lock.Lock()
        value = 1
        guarded.lock.Unlock()
    }()
    guarded.lock.Lock()
    result := value
    guarded.lock.Unlock()
    return result
}

// A goroutine spawned inside a repeated task repeats with it. bbolt's own
// shape: the test spawns `check()` in a loop, `check()` calls `Tx.Check()`,
// and `Check()` spawns the body that carries the racing write. The write is
// in a grandchild task whose own spawn site is not in a loop.
type counter struct {
    total int
}

func (c *counter) bump() {
    c.total++
}

func (c *counter) spawnBump() {
    go c.bump()
}

func repeatedGrandchild() {
    c := &counter{}
    for index := 0; index < 2; index++ {
        go c.spawnBump()
    }
}

// The same field mutex reached only from closures, so no occurrence types
// either field at its declaration and the two still have to agree, about
// the lock they take and about the field they write under it.
func twoClosuresFieldMutex() {
    guarded := &guardedFlag{}
    go func() {
        guarded.lock.Lock()
        guarded.flag = true
        guarded.lock.Unlock()
    }()
    go func() {
        guarded.lock.Lock()
        guarded.flag = false
        guarded.lock.Unlock()
    }()
}

func grouped() int {
    group := &sync.WaitGroup{}
    value := 0
    group.Go(func() { value = 1 })
    group.Wait()
    return value
}

type invocationCell struct {
    n int
}

func launchWaitGroupAndWait(c *invocationCell) {
    group := &sync.WaitGroup{}
    group.Add(1)
    go func() {
        c.n++
        group.Done()
    }()
    group.Wait()
}

func joinedWaitGroupInvocations() {
    c := &invocationCell{}
    launchWaitGroupAndWait(c)
    launchWaitGroupAndWait(c)
}

func loopedWaitGroupInvocations() int {
    c := &invocationCell{}
    for index := 0; index < 2; index++ {
        launchWaitGroupAndWait(c)
    }
    return c.n
}

func launchWaitGroupAndMaybeWait(c *invocationCell, wait bool) {
    group := &sync.WaitGroup{}
    group.Add(1)
    go func() {
        c.n++
        group.Done()
    }()
    if wait {
        group.Wait()
    }
}

func conditionalWaitGroupInvocations(wait bool) {
    c := &invocationCell{}
    for index := 0; index < 2; index++ {
        launchWaitGroupAndMaybeWait(c, wait)
    }
}

func joinedWaitGroupParent(c *invocationCell) {
    for index := 0; index < 2; index++ {
        launchWaitGroupAndWait(c)
    }
}

func parallelWaitGroupParentTasks() {
    c := &invocationCell{}
    for index := 0; index < 2; index++ {
        go joinedWaitGroupParent(c)
    }
}

func launchWaitGroupDoneBeforeWrite(c *invocationCell) {
    group := &sync.WaitGroup{}
    group.Add(1)
    go func() {
        group.Done()
        c.n++
    }()
    group.Wait()
}

func doneBeforeWriteWaitGroupInvocations() {
    c := &invocationCell{}
    launchWaitGroupDoneBeforeWrite(c)
    launchWaitGroupDoneBeforeWrite(c)
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

func overflowingGroupCount() int {
    group := &sync.WaitGroup{}
    value := 0
    group.Add(9223372036854775807)
    group.Add(9223372036854775807)
    group.Add(3)
    go func() {
        defer group.Done()
        value = 1
    }()
    group.Wait()
    return value
}

func summarizedJoinedGroup() int {
    return summarizedJoinedGroupBody(&sync.WaitGroup{})
}
func summarizedJoinedGroupBody(group *sync.WaitGroup) int {
    value := 0
    group.Add(1)
    go func() {
        value = 1
        group.Done()
    }()
    group.Wait()
    return value
}
func summarizedUnknownGroup(count int) int {
    return summarizedUnknownGroupBody(&sync.WaitGroup{}, count)
}
func summarizedLocalGroup() int {
    return summarizedLocalGroupBody()
}
func summarizedLocalGroupBody() int {
    group := new(sync.WaitGroup)
    alias := group
    value := 0
    alias.Add(1)
    go func() {
        value = 1
        group.Done()
    }()
    alias.Wait()
    return value
}
func summarizedLocalDistinctGroup() int {
    return summarizedLocalDistinctGroupBody()
}
func summarizedLocalDistinctGroupBody() int {
    first := &sync.WaitGroup{}
    second := &sync.WaitGroup{}
    value := 0
    first.Add(1)
    go func() {
        value = 1
        second.Done()
    }()
    first.Wait()
    return value
}
func summarizedLocalLiteralGroup() int {
    return summarizedLocalLiteralGroupBody()
}
func summarizedLocalLiteralGroupBody() int {
    group := &sync.WaitGroup{}
    alias := group
    value := 0
    alias.Add(1)
    go func() { value = 1; group.Done() }()
    alias.Wait()
    return value
}
func summarizedLocalCopiedGroup() int {
    return summarizedLocalCopiedGroupBody()
}
func summarizedLocalCopiedGroupBody() int {
    group := sync.WaitGroup{}
    copied := group
    value := 0
    group.Add(1)
    go func() { value = 1; copied.Done() }()
    group.Wait()
    return value
}
func summarizedLocalReassignedGroup() int {
    return summarizedLocalReassignedGroupBody()
}
func summarizedLocalReassignedGroupBody() int {
    group := &sync.WaitGroup{}
    original := group
    group = &sync.WaitGroup{}
    value := 0
    original.Add(1)
    go func() { value = 1; group.Done() }()
    original.Wait()
    return value
}
func summarizedUnknownGroupBody(group *sync.WaitGroup, count int) int {
    value := 0
    group.Add(count)
    go func() {
        value = 1
        group.Done()
    }()
    group.Wait()
    return value
}

func summarizedCopiedGroup() int {
    return summarizedCopiedGroupBody(&sync.WaitGroup{})
}
func summarizedCopiedGroupBody(group *sync.WaitGroup) int {
    value := 0
    group.Add(1)
    go func(copied sync.WaitGroup) {
        value = 1
        copied.Done()
    }(*group)
    group.Wait()
    return value
}
func summarizedDistinctGroup() int {
    return summarizedDistinctGroupBody(&sync.WaitGroup{}, &sync.WaitGroup{})
}
func summarizedDistinctGroupBody(first, second *sync.WaitGroup) int {
    value := 0
    first.Add(1)
    go func() {
        value = 1
        second.Done()
    }()
    first.Wait()
    return value
}

func summarizedAtomicOnly() {
    var value int64
    go func() { atomic.StoreInt64(&value, 1) }()
    go func() { _ = atomic.LoadInt64(&value) }()
}
func summarizedMixedAtomic() {
    var value int64
    go func() { atomic.StoreInt64(&value, 1) }()
    go func() { _ = value }()
}
func recursiveAtomicWrite(value *int64, depth int) {
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicWrite(value, depth-1) }
}
func parameterAtomicWrite(value *int64) { atomic.StoreInt64(value, 1) }
func summarizedParameterAtomic() {
    var value int64
    go parameterAtomicWrite(&value)
    _ = atomic.LoadInt64(&value)
}
func summarizedDistinctParameterAtomic() {
    var first int64
    var second int64
    go parameterAtomicWrite(&first)
    _ = atomic.LoadInt64(&second)
}
func summarizedCopiedParameterAtomic() {
    var first int64
    second := first
    go parameterAtomicWrite(&first)
    _ = atomic.LoadInt64(&second)
}
func replaceParameterPointer(value **int64) { *value = new(int64) }
func summarizedPointerCellAtomic() {
    var value int64
    pointer := &value
    go replaceParameterPointer(&pointer)
    _ = atomic.LoadInt64(&value)
}
func summarizedAddressMutex() {
    var lock sync.Mutex
    value := 0
    go func() {
        (&lock).Lock()
        value = 1
        (&lock).Unlock()
    }()
    (&lock).Lock()
    _ = value
    (&lock).Unlock()
}
func summarizedDistinctAddressMutex() {
    var first sync.Mutex
    var second sync.Mutex
    value := 0
    go func() {
        (&first).Lock()
        value = 1
        (&first).Unlock()
    }()
    (&second).Lock()
    _ = value
    (&second).Unlock()
}
func summarizedCopiedAddressMutex() {
    var first sync.Mutex
    second := first
    value := 0
    go func() {
        (&first).Lock()
        value = 1
        (&first).Unlock()
    }()
    (&second).Lock()
    _ = value
    (&second).Unlock()
}
func summarizedRecursiveAtomic() {
    var value int64
    go recursiveAtomicWrite(&value, 3)
    _ = atomic.LoadInt64(&value)
}
func effectFreeRecursiveLeaf() {}
func effectFreeRecursiveHelper() { effectFreeRecursiveLeaf() }
func recursiveAtomicWithHelper(value *int64, depth int) {
    effectFreeRecursiveHelper()
    effectFreeRecursiveHelper()
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicWithHelper(value, depth-1) }
}
func summarizedRecursiveAtomicWithHelper() {
    var value int64
    go recursiveAtomicWithHelper(&value, 3)
    _ = atomic.LoadInt64(&value)
}
type continuationCell struct { value int }
func returningContinuationWrite(cell *continuationCell) {
    effectFreeRecursiveHelper()
    cell.value = 1
}
func nonReturningContinuationWrite(cell *continuationCell) {
    nonReturningRecursiveHelper()
    cell.value = 1
}
func returningContinuationRoot() {
    cell := &continuationCell{}
    go returningContinuationWrite(cell)
    _ = cell.value
}
func nonReturningContinuationRoot() {
    cell := &continuationCell{}
    go nonReturningContinuationWrite(cell)
    _ = cell.value
}
func earlyContinuationWrite(cell *continuationCell) {
    cell.value = 1
    nonReturningRecursiveHelper()
}
func earlyContinuationRoot() {
    cell := &continuationCell{}
    go earlyContinuationWrite(cell)
    _ = cell.value
}
func unreachableSpawnContinuationRoot() {
    cell := &continuationCell{}
    nonReturningRecursiveHelper()
    go returningContinuationWrite(cell)
    _ = cell.value
}
func conditionalContinuationWrite(cell *continuationCell, stop bool) {
    if stop { nonReturningRecursiveHelper() }
    cell.value = 1
}
func conditionalContinuationRoot(stop bool) {
    cell := &continuationCell{}
    go conditionalContinuationWrite(cell, stop)
    _ = cell.value
}
func cyclicContinuationWrite(cell *continuationCell) {
    cyclicEmptyHelper()
    cell.value = 1
}
func cyclicContinuationRoot() {
    cell := &continuationCell{}
    go cyclicContinuationWrite(cell)
    _ = cell.value
}
func callbackContinuationWrite(cell *continuationCell, helper func()) {
    helper()
    cell.value = 1
}
func callbackReturningContinuationRoot() {
    cell := &continuationCell{}
    go callbackContinuationWrite(cell, effectFreeRecursiveHelper)
    _ = cell.value
}
func callbackMixedContinuationRoot() {
    cell := &continuationCell{}
    go callbackContinuationWrite(cell, nonReturningRecursiveHelper)
    go callbackContinuationWrite(cell, effectFreeRecursiveHelper)
    _ = cell.value
}
func callbackNonReturningContinuationRoot() {
    cell := &continuationCell{}
    go callbackContinuationWrite(cell, nonReturningRecursiveHelper)
    _ = cell.value
}
func invokeContinuationHelper(helper func()) { helper() }
func wrappedCallbackContinuationWrite(cell *continuationCell, helper func()) {
    invokeContinuationHelper(helper)
    cell.value = 1
}
func wrappedCallbackReturningContinuationRoot() {
    cell := &continuationCell{}
    go wrappedCallbackContinuationWrite(cell, effectFreeRecursiveHelper)
    _ = cell.value
}
func wrappedCallbackNonReturningContinuationRoot() {
    cell := &continuationCell{}
    go wrappedCallbackContinuationWrite(cell, nonReturningRecursiveHelper)
    _ = cell.value
}
func wrappedCallbackMixedContinuationRoot() {
    cell := &continuationCell{}
    go wrappedCallbackContinuationWrite(cell, nonReturningRecursiveHelper)
    go wrappedCallbackContinuationWrite(cell, effectFreeRecursiveHelper)
    _ = cell.value
}
func replacedCallbackContinuationWrite(cell *continuationCell, helper func()) {
    helper = effectFreeRecursiveHelper
    invokeContinuationHelper(helper)
    cell.value = 1
}
func replacedCallbackContinuationRoot() {
    cell := &continuationCell{}
    go replacedCallbackContinuationWrite(cell, nonReturningRecursiveHelper)
    _ = cell.value
}
func callbackLoopSpawn(cell *continuationCell, helper func()) {
    for {
        go func() { cell.value = 1 }()
        helper()
    }
}
func callbackReturningLoopSpawnRoot() {
    cell := &continuationCell{}
    go callbackLoopSpawn(cell, effectFreeRecursiveHelper)
}
func callbackNonReturningLoopSpawnRoot() {
    cell := &continuationCell{}
    go callbackLoopSpawn(cell, nonReturningRecursiveHelper)
}
type continuationHolder struct { child *continuationCell }
func unreachableFieldReplacementRoot() {
    shared := &continuationCell{}
    holder := &continuationHolder{child: shared}
    go func() { holder.child.value = 1 }()
    _ = shared.value
    nonReturningRecursiveHelper()
    holder.child = &continuationCell{}
}
func unreachableFieldAliasRoot() {
    shared := &continuationCell{}
    holder := &continuationHolder{child: &continuationCell{}}
    go func() { holder.child.value = 1 }()
    _ = shared.value
    nonReturningRecursiveHelper()
    holder.child = shared
}
func unreachableBoxReplacementRoot() {
    shared := &continuationCell{}
    var boxed any = shared
    go func() { boxed.(*continuationCell).value = 1 }()
    _ = shared.value
    nonReturningRecursiveHelper()
    boxed = &continuationCell{}
}
func unreachableBoxAliasRoot() {
    shared := &continuationCell{}
    var boxed any = &continuationCell{}
    go func() { boxed.(*continuationCell).value = 1 }()
    _ = shared.value
    nonReturningRecursiveHelper()
    boxed = shared
}
func nonReturningRecursiveHelper() { for {} }
func recursiveAtomicAfterNonReturningHelper(value *int64, depth int) {
    nonReturningRecursiveHelper()
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicAfterNonReturningHelper(value, depth-1) }
}
func summarizedRecursiveNonReturningHelper() {
    var value int64
    go recursiveAtomicAfterNonReturningHelper(&value, 3)
    _ = value
}
func cyclicEmptyHelper() { cyclicEmptyHelper() }
func recursiveAtomicAfterCyclicHelper(value *int64, depth int) {
    cyclicEmptyHelper()
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicAfterCyclicHelper(value, depth-1) }
}
func summarizedRecursiveCyclicHelper() {
    var value int64
    go recursiveAtomicAfterCyclicHelper(&value, 3)
    _ = value
}
func mutatingRecursiveHelper(value *int64) { *value = 2 }
func recursiveAtomicWithMutatingHelper(value *int64, depth int) {
    mutatingRecursiveHelper(value)
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicWithMutatingHelper(value, depth-1) }
}
func summarizedRecursiveAtomicWithMutatingHelper() {
    var value int64
    go recursiveAtomicWithMutatingHelper(&value, 3)
    _ = atomic.LoadInt64(&value)
}
func unresolvedRecursiveHelper() { missingRecursiveHelper() }
func recursiveAtomicWithUnknownHelper(value *int64, depth int) {
    unresolvedRecursiveHelper()
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicWithUnknownHelper(value, depth-1) }
}
func summarizedRecursiveAtomicWithUnknownHelper() {
    var value int64
    go recursiveAtomicWithUnknownHelper(&value, 3)
    _ = atomic.LoadInt64(&value)
}
func recursiveAtomicWithDeferredHelper(value *int64, depth int) {
    defer effectFreeRecursiveHelper()
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicWithDeferredHelper(value, depth-1) }
}
func summarizedRecursiveAtomicWithDeferredHelper() {
    var value int64
    go recursiveAtomicWithDeferredHelper(&value, 3)
    _ = atomic.LoadInt64(&value)
}
func publishingRecursiveHelper(value *int64, queue chan *int64) { queue <- value }
func recursiveAtomicWithPublishingHelper(value *int64, queue chan *int64, depth int) {
    publishingRecursiveHelper(value, queue)
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveAtomicWithPublishingHelper(value, queue, depth-1) }
}
func summarizedRecursiveAtomicWithPublishingHelper() {
    var value int64
    queue := make(chan *int64, 4)
    go recursiveAtomicWithPublishingHelper(&value, queue, 3)
    _ = atomic.LoadInt64(&value)
}
func summarizedRecursiveMixedAtomic() {
    var value int64
    go recursiveAtomicWrite(&value, 3)
    _ = value
}
func recursiveChangingAtomic(value *int64, depth int) {
    atomic.StoreInt64(value, 1)
    if depth > 0 { recursiveChangingAtomic(new(int64), depth-1) }
}
func summarizedRecursiveChangingAtomic() {
    var value int64
    go recursiveChangingAtomic(&value, 3)
    _ = atomic.LoadInt64(&value)
}
func recursiveUnknownAtomic(value *int64, depth int) {
    atomic.StoreInt64(value, 1)
    unknownAtomicBoundary()
    if depth > 0 { recursiveUnknownAtomic(value, depth-1) }
}
func summarizedRecursiveUnknownAtomic() {
    var value int64
    go recursiveUnknownAtomic(&value, 3)
    _ = atomic.LoadInt64(&value)
}
func summarizedDistinctAtomic() {
    var first int64
    var second int64
    go func() { atomic.StoreInt64(&first, 1) }()
    go func() { _ = atomic.LoadInt64(&second) }()
}
func summarizedAtomicCopy() int64 {
    var value int64
    go func(copied int64) { atomic.StoreInt64(&copied, 1) }(value)
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

func oncePublishesCallback() int {
    once := &sync.Once{}
    value := 0
    go func() { once.Do(func() { value = 1 }) }()
    once.Do(func() {})
    return value
}

func onceBeforeDoStaysUnordered() int {
    once := &sync.Once{}
    value := 0
    go func() {
        value = 1
        once.Do(func() {})
    }()
    once.Do(func() {})
    return value
}

func onceSingleExecution() {
    once := &sync.Once{}
    value := 0
    go func() { once.Do(func() { value = 1 }) }()
    go func() { once.Do(func() { value = 2 }) }()
}

func onceLoopSingleExecution() {
    once := &sync.Once{}
    value := 0
    for i := 0; i < 3; i++ {
        go func() { once.Do(func() { value = 1 }) }()
    }
}

func onceLoopFreshObjects() {
    value := 0
    for i := 0; i < 3; i++ {
        once := &sync.Once{}
        go func() { once.Do(func() { value = 1 }) }()
    }
}

func onceConditionalDo(flag bool) int {
    once := &sync.Once{}
    value := 0
    go func() {
        if flag {
            once.Do(func() { value = 1 })
        }
    }()
    once.Do(func() {})
    return value
}

type doer interface{ Do(func()) }

func onceInterfaceReceiver(d doer) int {
    value := 0
    go func() { d.Do(func() { value = 1 }) }()
    d.Do(func() {})
    return value
}

func onceNonParticipant() int {
    once := &sync.Once{}
    value := 0
    go func() { once.Do(func() { value = 1 }) }()
    go func() { value = 2 }()
    return value
}

func onceDistinctObjects() int {
    first := &sync.Once{}
    second := &sync.Once{}
    value := 0
    go func() { first.Do(func() { value = 1 }) }()
    second.Do(func() {})
    return value
}

type onceLike struct{}

func (*onceLike) Do(f func()) {}

func onceSameNameOtherType() int {
    other := &onceLike{}
    value := 0
    go func() {
        value = 1
        other.Do(func() {})
    }()
    other.Do(func() {})
    return value
}

func onceUnknownCallable(once *sync.Once, f func()) int {
    value := 0
    once.Do(f)
    return value
}

func onceProjected(once *sync.Once) int {
    value := 0
    once.Do(func() { value = 1 })
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
                  "ordinary_heap_unchanged": true,
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
                },
                {
                  "id": "mutex.unlock",
                  "target": { "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Unlock()", "has_receiver": true, "parameter_count": 0 },
                  "completeness": "complete",
                  "ordinary_heap_unchanged": true,
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
                },
                {
                  "id": "once.do",
                  "target": { "path": "src/sync/once.go", "symbol": "sync.Once.Do(func())", "has_receiver": true, "parameter_count": 1 },
                  "completeness": "complete",
                  "transfers": [],
                  "concurrency_effects": [{ "kind": "once_do", "once": { "kind": "receiver" }, "callable": { "kind": "parameter", "ordinal": 0 } }]
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
    let snapshot = match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("sync models activate: {other:#?}"),
    };

    let cancellation = CancellationToken::default();
    let mut budget = crate::analyzer::semantic::SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("atomic wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("atomic wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let roots = [
        procedure("summarizedAtomicOnly"),
        procedure("summarizedMixedAtomic"),
        procedure("summarizedDistinctAtomic"),
        procedure("summarizedAtomicCopy"),
        procedure("summarizedJoinedGroup"),
        procedure("summarizedUnknownGroup"),
        procedure("summarizedCopiedGroup"),
        procedure("summarizedDistinctGroup"),
        procedure("summarizedLocalGroup"),
        procedure("summarizedLocalDistinctGroup"),
        procedure("summarizedLocalLiteralGroup"),
        procedure("summarizedLocalCopiedGroup"),
        procedure("summarizedLocalReassignedGroup"),
    ];
    let direct_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    // A source wrapper that owns the call but not the object keeps the
    // reviewed Once contract at its boundary: the projected summary names the
    // object port and the callable argument, and the direct, freshly
    // projected, and retained reports agree.
    let once_root = procedure("onceProjected");
    let once_summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&once_root),
            &icfg,
            &direct_provider,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Once wrapper summaries project");
    let once_summary = once_summaries
        .summary_for(&once_root)
        .expect("the Once wrapper has a projected summary");
    assert!(
        once_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::OnceDo {
                        once,
                        identity:
                            brokk_bifrost_flow::dataflow::SummaryConcurrencySubjectIdentity::Backing,
                        callable:
                            brokk_bifrost_flow::dataflow::SummaryConcurrencyCallable::SourceArgument(0),
                        ..
                    } if once.root() == &brokk_bifrost_flow::dataflow::SummaryPort::Parameter(0)
                )
        )),
        "the wrapper summary keeps the Once object port and callable argument: {once_summary:#?}"
    );
    let fresh_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(once_summaries),
    );
    let mut direct_once_budget = crate::analyzer::semantic::SemanticBudget::default();
    let direct_once_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &once_root,
        &mut crate::analyzer::semantic::SemanticRequest::new(
            &mut direct_once_budget,
            &cancellation,
        ),
    )
    .expect("direct Once wrapper report computes");
    assert!(
        direct_once_report.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }) && direct_once_report.reasons.is_empty(),
        "the wrapper's own Do publishes its callback: {direct_once_report:#?}"
    );
    let once_repository = brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new();
    let once_summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&once_root),
            &icfg,
            &direct_provider,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Once wrapper summaries project again");
    once_repository
        .publish_components(once_summaries.summaries(), once_summaries.components())
        .expect("Once wrapper component publishes");
    let retained_once =
        brokk_bifrost_flow::typestate::acquire_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&once_root),
            &icfg,
            &direct_provider,
            &once_repository,
            &brokk_bifrost_flow::dataflow::NoSummaryReadObserver,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Once wrapper component reacquires");
    assert_eq!(
        retained_once.kind(),
        brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Retained
    );
    let retained_once_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(retained_once.into_summaries()),
    );
    for provider in [&fresh_provider, &retained_once_provider] {
        let mut once_budget = crate::analyzer::semantic::SemanticBudget::default();
        let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            provider,
            &once_root,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut once_budget, &cancellation),
        )
        .expect("projected Once wrapper report computes");
        assert_eq!(
            report, direct_once_report,
            "projected and retained Once wrappers preserve the direct report"
        );
    }

    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &direct_provider,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("atomic wrappers project");
    let recursive_root = procedure("summarizedRecursiveAtomicWithHelper");
    let mut address_mutex_budget = crate::analyzer::semantic::SemanticBudget::default();
    let address_mutex_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &procedure("summarizedAddressMutex"),
        &mut crate::analyzer::semantic::SemanticRequest::new(
            &mut address_mutex_budget,
            &cancellation,
        ),
    )
    .expect("addressed mutex receiver report computes");
    assert!(
        address_mutex_report.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "addressed mutex receivers must name one lock: {address_mutex_report:#?}"
    );
    for name in [
        "summarizedDistinctAddressMutex",
        "summarizedCopiedAddressMutex",
    ] {
        let mut control_budget = crate::analyzer::semantic::SemanticBudget::default();
        let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &direct_provider,
            &procedure(name),
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut control_budget,
                &cancellation,
            ),
        )
        .expect("distinct addressed locks report computes");
        assert!(
            report.conflicts.iter().any(|conflict| {
                conflict.proven
                    && conflict.exhaustive
                    && conflict.ordering
                        == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                    && conflict.protection
                        == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
            }),
            "different lock cells cannot protect the shared value in {name}: {report:#?}"
        );
    }
    for name in [
        "summarizedDistinctParameterAtomic",
        "summarizedCopiedParameterAtomic",
        "summarizedPointerCellAtomic",
    ] {
        let mut control_budget = crate::analyzer::semantic::SemanticBudget::default();
        let control_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &direct_provider,
            &procedure(name),
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut control_budget,
                &cancellation,
            ),
        )
        .expect("distinct scalar address control computes");
        // Exposing a cell also exposes its initialization before the spawn.
        // Those ordered pairs are real; the two distinct atomic operands
        // must never produce an atomic-only pair or an unordered conflict.
        assert!(
            control_report.conflicts.iter().all(|conflict| {
                conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
                    && conflict.protection
                        != brokk_bifrost_flow::concurrency::ConcurrentProtection::AtomicOnly
            }),
            "distinct scalar storage must not alias in {name}: {control_report:#?}"
        );
    }
    let parameter_root = procedure("summarizedParameterAtomic");
    let mut parameter_budget = crate::analyzer::semantic::SemanticBudget::default();
    let parameter_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &parameter_root,
        &mut crate::analyzer::semantic::SemanticRequest::new(&mut parameter_budget, &cancellation),
    )
    .expect("nonrecursive pointer atomic report computes");
    assert!(
        parameter_report
            .conflicts
            .iter()
            .any(|conflict| conflict.proven
                && conflict.exhaustive
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::AtomicOnly),
        "nonrecursive pointer parameter must preserve the atomic location: {parameter_report:#?}"
    );
    let recursive_summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&recursive_root),
            &icfg,
            &direct_provider,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("recursive atomic summaries project");
    let recursive_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(recursive_summaries.clone()),
    );
    let mut recursive_budget = crate::analyzer::semantic::SemanticBudget::default();
    let recursive_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &recursive_provider,
        &recursive_root,
        &mut crate::analyzer::semantic::SemanticRequest::new(&mut recursive_budget, &cancellation),
    )
    .expect("recursive atomic report computes");
    assert!(
        !recursive_report
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion),
        "invariant recursive atomic effects must reach a complete fixed point: {recursive_report:#?}"
    );
    assert!(
        recursive_report
            .conflicts
            .iter()
            .any(|conflict| conflict.proven
                && conflict.exhaustive
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::AtomicOnly),
        "the complete recursive write/read pair is atomic-only: {recursive_report:#?}"
    );
    let recursive_repository =
        brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new();
    recursive_repository
        .publish_components(
            recursive_summaries.summaries(),
            recursive_summaries.components(),
        )
        .expect("recursive atomic component publishes");
    let retained =
        brokk_bifrost_flow::typestate::acquire_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&recursive_root),
            &icfg,
            &direct_provider,
            &recursive_repository,
            &brokk_bifrost_flow::dataflow::NoSummaryReadObserver,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("recursive atomic component reacquires");
    assert_eq!(
        retained.kind(),
        brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Retained
    );
    let retained_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(retained.into_summaries()),
    );
    let mut retained_budget = crate::analyzer::semantic::SemanticBudget::default();
    let retained_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &retained_provider,
        &recursive_root,
        &mut crate::analyzer::semantic::SemanticRequest::new(&mut retained_budget, &cancellation),
    )
    .expect("retained recursive atomic report computes");
    assert_eq!(
        retained_report, recursive_report,
        "retained recursive inventories preserve the full report"
    );
    for (name, expected_protection) in [
        (
            "summarizedRecursiveAtomic",
            Some(brokk_bifrost_flow::concurrency::ConcurrentProtection::AtomicOnly),
        ),
        (
            "summarizedRecursiveMixedAtomic",
            Some(brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected),
        ),
        ("summarizedRecursiveNonReturningHelper", None),
        ("summarizedRecursiveCyclicHelper", None),
        ("summarizedRecursiveAtomicWithMutatingHelper", None),
        ("summarizedRecursiveAtomicWithPublishingHelper", None),
        ("summarizedRecursiveAtomicWithUnknownHelper", None),
        ("summarizedRecursiveAtomicWithDeferredHelper", None),
        ("summarizedRecursiveChangingAtomic", None),
        ("summarizedRecursiveUnknownAtomic", None),
    ] {
        let root = procedure(name);
        let summaries =
            brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
                std::slice::from_ref(&root),
                &icfg,
                &direct_provider,
                &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("recursive atomic control projects");
        let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
            &workspace,
            Some(snapshot.clone()),
            Some(summaries),
        );
        let mut control_budget = crate::analyzer::semantic::SemanticBudget::default();
        let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &root,
            &mut crate::analyzer::semantic::SemanticRequest::new(
                &mut control_budget,
                &cancellation,
            ),
        )
        .expect("recursive atomic control computes");
        if let Some(protection) = expected_protection {
            assert!(
                !report.reasons.contains(
                    &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
                ) && report.conflicts.iter().any(|conflict| {
                    conflict.proven
                        && conflict.exhaustive
                        && conflict.ordering
                            == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                        && conflict.protection == protection
                }),
                "recursive inventory must close with {protection:?} protection in {name}: {report:#?}"
            );
        } else if matches!(
            name,
            "summarizedRecursiveNonReturningHelper" | "summarizedRecursiveCyclicHelper"
        ) {
            assert!(
                report.conflicts.is_empty() && report.reasons.is_empty(),
                "unreachable recursive accesses require no conflict or missing inventory: {report:#?}"
            );
        } else {
            assert!(
                report.reasons.contains(
                    &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::RecursiveExpansion
                ) && report.conflicts.iter().all(|conflict| !conflict.exhaustive),
                "changing objects or unresolved calls cannot use an invariant certificate in {name}: {report:#?}"
            );
        }
    }
    for (name, expected_race) in [
        ("returningContinuationRoot", true),
        ("nonReturningContinuationRoot", false),
        ("earlyContinuationRoot", true),
        ("unreachableSpawnContinuationRoot", false),
        ("conditionalContinuationRoot", true),
        ("cyclicContinuationRoot", false),
        ("callbackReturningContinuationRoot", true),
        ("callbackMixedContinuationRoot", true),
        ("callbackNonReturningContinuationRoot", false),
        ("wrappedCallbackReturningContinuationRoot", true),
        ("wrappedCallbackNonReturningContinuationRoot", false),
        ("wrappedCallbackMixedContinuationRoot", true),
        ("replacedCallbackContinuationRoot", true),
        ("callbackReturningLoopSpawnRoot", true),
        ("callbackNonReturningLoopSpawnRoot", false),
        ("unreachableFieldReplacementRoot", true),
        ("unreachableFieldAliasRoot", false),
        ("unreachableBoxReplacementRoot", true),
        ("unreachableBoxAliasRoot", false),
    ] {
        let root = procedure(name);
        let projection =
            brokk_bifrost_flow::concurrency::ConcurrencyProvider::continuation_projection(
                &direct_provider,
                &root,
                &mut crate::analyzer::semantic::SemanticRequest::new(
                    &mut crate::analyzer::semantic::SemanticBudget::default(),
                    &cancellation,
                ),
            )
            .expect("workspace provider supplies control projection");
        assert_eq!(projection.procedure(), &root);
        assert!(projection.reasons().is_empty(), "{projection:?}");
        let projected_summaries =
            brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
                std::slice::from_ref(&root),
                &icfg,
                &direct_provider,
                &mut crate::analyzer::semantic::SemanticRequest::new(
                    &mut crate::analyzer::semantic::SemanticBudget::default(),
                    &cancellation,
                ),
            )
            .expect("continuation control summaries project");
        let summary_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
            &workspace,
            Some(snapshot.clone()),
            Some(projected_summaries),
        );
        for provider in [&summary_provider, &direct_provider] {
            let mut control_budget = crate::analyzer::semantic::SemanticBudget::default();
            let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
                provider,
                &root,
                &mut crate::analyzer::semantic::SemanticRequest::new(
                    &mut control_budget,
                    &cancellation,
                ),
            )
            .expect("call-continuation control computes");
            if matches!(
                name,
                "callbackMixedContinuationRoot" | "wrappedCallbackMixedContinuationRoot"
            ) {
                assert_eq!(
                    report.conflicts.len(),
                    1,
                    "only the returning invocation writes the shared field: {report:#?}"
                );
            }
            if matches!(
                name,
                "unreachableFieldAliasRoot" | "unreachableBoxAliasRoot"
            ) {
                assert!(report.reasons.is_empty() && report.conflicts.iter().all(|conflict|
                    conflict.proven && conflict.exhaustive && conflict.ordering == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
                ), "an unreachable store must not alias distinct objects: {report:#?}");
                continue;
            }
            if name == "replacedCallbackContinuationRoot" {
                assert!(
                    !report.conflicts.is_empty(),
                    "replacing the helper must not reuse its incoming nonreturn proof: {report:#?}"
                );
                continue;
            }
            if expected_race {
                assert!(
                    report.conflicts.iter().any(|conflict| {
                        conflict.proven
                        && conflict.exhaustive
                        && conflict.ordering
                            == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                        && conflict.protection
                            == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
                    }),
                    "returning helper preserves the reachable race in {name}: {report:#?}"
                );
            } else {
                assert!(
                    report.conflicts.is_empty() && report.reasons.is_empty(),
                    "a write after a non-returning helper is unreachable in {name}: {report:#?}"
                );
            }
        }
    }
    let atomic_count = summaries.summaries().iter().flat_map(|summary| summary.effects())
        .filter(|effect| matches!(effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(effect.kind(), brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Atomic { .. })
        )).count();
    assert_eq!(
        atomic_count, 6,
        "all six atomic calls must retain witnessed effects"
    );
    let wait_group_count = summaries.summaries().iter().flat_map(|summary| summary.effects())
        .filter(|effect| matches!(effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::WaitGroupAdd { .. }
                    | brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::WaitGroupDone { .. }
                    | brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::WaitGroupWait { .. })
        )).count();
    assert_eq!(
        wait_group_count, 23,
        "complete reference inventories and captured Done rows must be retained"
    );
    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(summaries.clone()),
    );
    let repository = brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new();
    repository
        .publish_components(summaries.summaries(), summaries.components())
        .expect("atomic summaries publish");
    let acquisition =
        brokk_bifrost_flow::typestate::acquire_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &direct_provider,
            &repository,
            &brokk_bifrost_flow::dataflow::NoSummaryReadObserver,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("atomic summaries reacquire");
    assert_eq!(
        acquisition.kind(),
        brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Retained
    );
    let summaries = acquisition.into_summaries();
    let retained_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        Some(summaries.clone()),
    );
    let without_models = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        None,
        Some(summaries),
    );
    for (index, root) in roots.iter().enumerate() {
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &direct_provider,
            root,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("direct atomic report");
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &projected_provider,
            root,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("projected atomic report");
        assert_eq!(
            projected, direct,
            "atomic route {index} must agree under fresh projection"
        );
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let retained = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &retained_provider,
            root,
            &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("retained atomic report");
        assert_eq!(
            retained, direct,
            "atomic route {index} must agree under summary replay"
        );
        // Copied and reassigned locals intentionally lack complete inventories.
        if !matches!(index, 2 | 3 | 11 | 12) {
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            let replay_only = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
                &without_models,
                root,
                &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("stored atomic effects survive unavailable live models");
            assert_eq!(
                replay_only.conflicts, retained.conflicts,
                "stored effects must preserve access classification; missing dispatch evidence remains in report reasons"
            );
        }
        let unordered = retained
            .conflicts
            .iter()
            .filter(|conflict| {
                conflict.ordering == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
            })
            .collect::<Vec<_>>();
        let read_pairs = retained
            .conflicts
            .iter()
            .filter(|conflict| {
                // Captured group-pointer reads observe initialization before
                // spawning. The phase assertion concerns the parent's read
                // of the shared lexical value after Wait instead.
                [&conflict.first, &conflict.second].iter().any(|site| {
                    site.mode == brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Read
                        && site.access_kind
                            == crate::analyzer::semantic::MemoryAccessKind::LexicalCell
                })
            })
            .collect::<Vec<_>>();
        match index {
            0 => assert!(
                unordered.iter().any(|conflict| conflict.proven
                    && conflict.exhaustive
                    && conflict.protection
                        == brokk_bifrost_flow::concurrency::ConcurrentProtection::AtomicOnly),
                "{retained:#?}"
            ),
            1 => assert!(
                unordered.iter().any(|conflict| conflict.proven
                    && conflict.exhaustive
                    && conflict.protection
                        == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected),
                "{retained:#?}"
            ),
            2 => assert!(
                unordered.is_empty(),
                "distinct storage cannot conflict: {retained:#?}"
            ),
            3 => assert!(
                unordered.iter().all(|conflict| !conflict.proven),
                "copied values cannot prove a shared atomic access: {retained:#?}"
            ),
            4 | 8 | 10 => assert!(
                read_pairs.iter().any(|conflict| conflict.proven
                    && conflict.exhaustive
                    && conflict.ordering
                        == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore),
                "an exact summarized phase must order the child write before the read: {retained:#?}"
            ),
            5 => assert!(
                read_pairs.iter().any(|conflict| !conflict.proven
                    && conflict.ordering
                        == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Open),
                "an unknown summarized count must retain its open phase: {retained:#?}"
            ),
            6 | 7 | 9 | 11 | 12 => {
                assert!(
                    !read_pairs.is_empty(),
                    "the value access pair must remain visible: {retained:#?}"
                );
                assert!(
                    read_pairs.iter().all(|conflict| !conflict.proven
                        || conflict.ordering
                            != brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore),
                    "route {index}: a copied or distinct group cannot complete the original phase: {retained:#?}"
                );
            }
            _ => unreachable!(),
        }
    }

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

    // workerpool's shape: a repeated spawn of a method that guards its write
    // with a mutex held in a field of the receiver, released by `defer`. Both
    // halves are load-bearing. The lock is only modeled at all when the
    // receiver of `guarded.lock.Lock()` types through the field, and the pair
    // is only protected when the repeated-task self-comparison consults the
    // locks held rather than assuming none are.
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "repeatedFieldMutex" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("repeated field-mutex concurrent access query");
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

    // Opposite branches are exclusive within one parent activation, but both
    // branches can run across repeated parent tasks. Their distinct mutexes
    // therefore leave the shared value unprotected across those activations.
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "repeatedOppositeBranchDistinctLocks" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("repeated opposite-branch distinct-lock query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "repeated opposite branches: {result:#?}"
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (
            value.task_relation,
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        (
            "repeated",
            "unordered",
            "unprotected",
            "proven",
            "exhaustive"
        ),
        "distinct branch locks cannot protect repeated opposite branches: {result:#?}"
    );

    // With one nonrepeated parent activation, only one branch executes, so
    // distinct branch locks do not create a cross-task conflict.
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "nonrepeatedOppositeBranchDistinctLocks" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("nonrepeated opposite-branch distinct-lock query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "nonrepeated opposite branches: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "nonrepeated opposite branches must resolve completely: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);

    // Each branch now launches its own child task. The repeated parent still
    // reaches opposite branches in separate activations, so the shared value
    // must retain the unprotected cross-child conflict.
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "repeatedOppositeBranchChildTasks" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("repeated opposite-branch child-task query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "repeated opposite-branch child tasks: {result:#?}"
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (
            value.task_relation,
            value.ordering,
            value.protection,
            value.proof,
            value.coverage
        ),
        (
            "repeated",
            "unordered",
            "unprotected",
            "proven",
            "exhaustive"
        ),
        "distinct branch locks cannot protect repeated opposite child tasks: {result:#?}"
    );

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "nonrepeatedOppositeBranchChildTasks" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("nonrepeated opposite-branch child-task query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "nonrepeated opposite-branch child tasks: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "nonrepeated opposite child tasks must resolve completely: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);

    // A goroutine spawned inside a repeated task repeats with it, whatever
    // its own spawn site looks like. Without that, the grandchild believes it
    // runs once, its write is never compared against itself, and the race is
    // reported as nothing at all -- silently, because a task that runs once
    // has no gap to declare. This is bbolt's shape, reduced.
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "repeatedGrandchild" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("repeated grandchild concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (value.task_relation, value.protection, value.proof),
        ("repeated", "unprotected", "proven"),
        "{result:#?}"
    );

    // One field must compose one identity however it is reached. Each of
    // these guards its write with the same field mutex, and each reaches it
    // through a locator the producer anchored differently: at the field's
    // declaration where it could type the receiver, and at the use where it
    // could not. Rendering a field step from whichever locator arrived left
    // the two acquisitions of one lock naming different locks, so the lock
    // held across the write matched nothing and the write was reported as an
    // unprotected race.
    for guarded in ["closureCapturedFieldMutex", "twoClosuresFieldMutex"] {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": guarded },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("closure-captured field-mutex concurrent access query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{guarded}: {result:#?}"
        );
        assert_exact_safe_concurrent_relations(&result, "protected");
    }

    // A nested imported method selector contributes the receiver field used
    // by the lock model, but the terminal method name is not another memory
    // location. Keep this direct control separate from the closure-capture
    // identity checks above so a phantom Lock/Unlock field load cannot hide in
    // the broader protected fixture.
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "methodSelectorNoFieldRead" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("method-selector no-field-read concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "method selectors must not add unresolved field accesses: {result:#?}"
    );
    assert_exact_safe_concurrent_relations(&result, "protected");

    // A function-valued field is different: evaluating the callee reads the
    // field. The child store and parent call therefore retain a field conflict.
    // Include a field initialized with a bound method as a near miss for any
    // implementation that classifies the stored target as a method and drops
    // the caller-side field load.
    // The bound-method fixture also has unresolved callable/identity evidence;
    // preserve that limitation while requiring the actual read/write pair.
    for (field_call, proof, coverage, open_reason) in [
        ("functionValuedFieldLoadRace", "proven", "exhaustive", None),
        (
            "boundMethodFieldLoadRace",
            "open",
            "open",
            Some("unknown_location"),
        ),
        (
            "functionFieldAfterUnknownCall",
            "open",
            "open",
            Some("unresolved_target"),
        ),
    ] {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": field_call },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("function-valued field-load concurrent access query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let value = find_concurrent_relation(&result, |value| {
            value.verdict == "conflict"
                && value.location_kind == "field"
                && matches!(
                    (value.first_access, value.second_access),
                    ("read", "write") | ("write", "read")
                )
        });
        assert_eq!(
            (
                value.ordering,
                value.protection,
                value.proof,
                value.coverage,
            ),
            ("unordered", "unprotected", proof, coverage),
            "{field_call}: a function-valued field load must remain a race: {result:#?}"
        );
        if let Some(open_reason) = open_reason {
            assert!(
                value.reasons.iter().any(|reason| reason == open_reason),
                "{result:#?}"
            );
        }
    }

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
    // Each loop creates fresh first/second cells. The WaitGroup proves the
    // ordering, but a declaration identity does not select one runtime cell.
    assert_open_loop_cell_relations(&result);

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
    assert_open_loop_cell_relations(&result);

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

    let once_query = |name: &str| {
        CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .unwrap_or_else(|error| panic!("{name} concurrent access query: {error}"))
    };

    // A completed Do call publishes its callback: the write inside the one
    // execution is synchronized before the return of every Do on that object,
    // so the read after the caller's own Do is ordered rather than racy.
    let query = once_query("oncePublishesCallback");
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
    let ordered = find_concurrent_relation(&result, |value| value.ordering == "happens_before");
    assert_eq!(
        (ordered.verdict, ordered.proof, ordered.coverage),
        ("ordered", "proven", "exhaustive"),
        "{result:#?}"
    );
    assert!(
        result.results.iter().all(|item| {
            !matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )
        }),
        "the published callback leaves no unordered pair: {result:#?}"
    );

    // A write made before the Do is not part of the single execution, so the
    // return of the callback does not publish it: the pair stays a race.
    let query = once_query("onceBeforeDoStaysUnordered");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
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
    assert!(value.reasons.is_empty(), "{result:#?}");

    // A Do that only some paths reach still publishes whichever callback ran:
    // the completion belongs to the object, not to the branch that made the
    // call.
    let query = once_query("onceConditionalDo");
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
    assert!(
        result.results.iter().all(|item| {
            !matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )
        }),
        "a conditional Do publishes the callback it ran: {result:#?}"
    );

    // An interface receiver is not the reviewed declaration, so nothing here
    // publishes the write on the strength of a matching method name.
    let query = once_query("onceInterfaceReceiver");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(
        result.results.iter().all(|item| !matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "ordered"
        )),
        "an interface Do never publishes on the strength of a method name: {result:#?}"
    );
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::SemanticAnalysisPartial]
        },
        "an unresolved interface Do remains an explicit boundary: {result:#?}"
    );

    // Single execution: two callbacks bound to one object never run together,
    // so their writes are mutually exclusive rather than concurrent.
    let query = once_query("onceSingleExecution");
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
    assert!(
        result.results.iter().all(|item| {
            !matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )
        }),
        "one object runs one callback: {result:#?}"
    );

    // A callback inside a loop still runs at most once while every activation
    // observes the same object.
    let query = once_query("onceLoopSingleExecution");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(
        result.results.iter().all(|item| {
            !matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict"
            )
        }),
        "one object across loop activations runs one callback: {result:#?}"
    );

    // An object created inside the repeated scope is a new object for each
    // activation, so its callbacks may all run.
    let query = once_query("onceLoopFreshObjects");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(
        result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict"
        )),
        "an object recreated by each activation does not serialize its callbacks: {result:#?}"
    );

    // A goroutine that never calls Do is not ordered by another goroutine's
    // completed Do.
    let query = once_query("onceNonParticipant");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("unordered", "proven", "exhaustive"),
        "{result:#?}"
    );

    // Distinct Once objects share no completion state, so a callback bound to
    // one object never publishes an access after a Do on another.
    let query = once_query("onceDistinctObjects");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.protection),
        ("unordered", "unprotected"),
        "{result:#?}"
    );

    // A same-named method on another type is not the reviewed protocol: its
    // own body runs and publishes nothing.
    let query = once_query("onceSameNameOtherType");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let value = find_concurrent_relation(&result, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.protection, value.proof),
        ("unordered", "unprotected", "proven"),
        "{result:#?}"
    );

    // A Do whose callable cannot be resolved keeps the boundary open instead
    // of claiming the synchronous execution that follows it.
    let query = once_query("onceUnknownCallable");
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
        "match": { "kind": "function", "name": "overflowingGroupCount" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("overflowing WaitGroup count concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let value = find_concurrent_relation(&result, |value| {
        value.verdict == "conflict" && value.proof == "open"
    });
    assert_eq!(
        (value.ordering, value.proof, value.coverage),
        ("open", "open", "open"),
        "overflow cannot prove a completed WaitGroup phase: {result:#?}"
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

    // A local WaitGroup is fresh for every helper activation. Its mandatory
    // Wait orders each child before the next invocation, including when the
    // same helper is reached through a loop.
    let waitgroup_results = [
        ("joinedWaitGroupInvocations", true),
        ("loopedWaitGroupInvocations", true),
        ("conditionalWaitGroupInvocations", false),
        ("parallelWaitGroupParentTasks", false),
        ("doneBeforeWriteWaitGroupInvocations", false),
    ]
    .into_iter()
    .map(|(name, safe)| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": name },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("WaitGroup invocation identity query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        (name, safe, result)
    })
    .collect::<Vec<_>>();

    // An unknown conditional Wait, parallel parent activations, and Done
    // before the write all leave a real race or an explicit open result.
    for (name, safe, result) in waitgroup_results {
        if safe {
            assert_eq!(
                result.completion(),
                CodeQueryCompletion::Complete,
                "{name}: {result:#?}"
            );
            assert!(
                result.diagnostics.is_empty(),
                "{name} must use the structured WaitGroup model: {result:#?}"
            );
            assert_exact_safe_concurrent_relations(&result, "ordered");
        } else {
            assert_conflict_or_explicit_open(&result);
        }
    }
}

/// A closure that captures a parameter or receiver keeps the object that
/// formal names, and a copy still does not borrow the caller's.
///
/// The producer holds a captured formal in a lexical cell, and that cell's
/// only write is the call that bound the formal: a binding, not a body
/// statement, so no `MemoryStore` reported it and the cell was left with no
/// recorded store at all. The cell therefore never joined the formal's class,
/// carried no identity, and every access reaching through it resolved to
/// nothing -- silently, because a location with no name is not a gap any step
/// can report. Recording the binding as the store it is lets the ordinary
/// written-once rule name the cell.
///
/// The three roots here are the whole contract, and the last is what keeps the
/// fix from buying recall with precision:
///
/// - `repeatedCapturedReceiver`: the write is reported through a captured
///   pointer receiver. The closure is never called and never passed anywhere;
///   declaring it was enough to lose the receiver.
/// - `repeatedNoClosure`: the same write with no closure, which was always
///   reported and must stay so.
/// - `repeatedValueReceiver`: a *value* receiver copies the struct, so the
///   callee's write cannot reach the caller's object and must not be
///   reported. The written-once rule refuses it because a copy's canonical is
///   not a reference allocation.
///
/// A third negative, a parameter the body reassigns, is pre-existing and is
/// pinned separately in `go_reassigned_parameter_write_is_task_local`.
///
/// Found while measuring bbolt's issue-213 endpoint, whose `checkBucket` has
/// exactly this shape: its closures capture `tx` and `b`. Closing it does not
/// by itself reach that endpoint, so at least one further cause lies between
/// `checkBucket` and `Bucket.Cursor`; this one stands on its own evidence.
#[test]
fn go_closure_capture_of_a_formal_keeps_its_identity() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "types.go",
            r#"package main

type counters struct {
    total int
}

type inner struct {
    counters counters
}

type holder struct {
    inner *inner
}

type valueHolder struct {
    total int
}
"#,
        )
        .file(
            "use.go",
            r#"package main

// The closure is never called and never passed anywhere. Declaring it used to
// be enough to lose the receiver.
func (holding *holder) bumpWithUnusedClosure() {
    holding.inner.counters.total++
    _ = func() { _ = holding.inner }
}

func repeatedCapturedReceiver() {
    holding := &holder{inner: &inner{}}
    for index := 0; index < 2; index++ {
        go holding.bumpWithUnusedClosure()
    }
}

// The same write through the same receiver, with no closure.
func (holding *holder) bumpWithoutClosure() {
    holding.inner.counters.total++
}

func repeatedNoClosure() {
    holding := &holder{inner: &inner{}}
    for index := 0; index < 2; index++ {
        go holding.bumpWithoutClosure()
    }
}

// A value receiver copies the struct, so this write cannot reach the caller's
// object however the closure captures it.
func (holding valueHolder) bumpCopy() {
    holding.total++
    _ = func() { _ = holding.total }
}

func repeatedValueReceiver() {
    holding := valueHolder{}
    for index := 0; index < 2; index++ {
        go holding.bumpCopy()
    }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let conflicts = |root: &str| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": root },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("captured formal concurrent access query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let reported = result
            .results
            .iter()
            .filter(|item| {
                matches!(
                    &item.value,
                    CodeQueryResultValue::ConcurrentAccessConflict { value }
                        if value.verdict == "conflict"
                            && value.task_relation == "repeated"
                            && value.proof == "proven"
                )
            })
            .count();
        (reported, result)
    };

    for root in ["repeatedCapturedReceiver", "repeatedNoClosure"] {
        let (reported, result) = conflicts(root);
        // The increment has two access orientations at the same source site: the
        // write/read pair and the write/write pair. Both are part of the
        // exact result and must remain proven.
        assert_eq!(reported, 2, "{root} must report its races: {result:#?}");
    }
    let (reported, result) = conflicts("repeatedValueReceiver");
    assert_eq!(
        reported, 0,
        "a value receiver writes a copy and must not borrow the caller's identity: {result:#?}"
    );
}

/// A write in a procedure the recursion passes through is still reported when
/// the cycle closes through a callback.
///
/// The solver declines to expand a recursive edge and says so with
/// `RecursiveExpansion`, which sounds like it costs only what is on the cycle.
/// It used to cost the whole callee: the binding ran before the cycle check,
/// so the skipped edge still gave the callee's formal a second actual from a
/// call that was never expanded. The formal then had two conflicting actuals
/// and lost its identity, discarding the one instantiation that *was*
/// analyzed and correctly bound.
///
/// The three controls are what make the diagnosis specific rather than "the
/// recursive case is broken":
///
/// - `repeatedFlatCallback` passes a callback and does not recurse.
/// - `repeatedDirectRecursion` recurses, but not through the callback, so the
///   callee holding the write is not on the cycle.
/// - `repeatedCallbackRecursion` closes the cycle through the callback, which
///   is the shape that failed and is bbolt's `checkBucket`.
#[test]
fn go_callback_recursion_keeps_the_callee_write() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type tally struct {
    total int
}

type box struct {
    tally *tally
}

// The callee carries the write and invokes the callback.
func (b *box) each(visit func()) {
    b.tally.total++
    visit()
}

func (b *box) flat() {
    b.each(func() {})
}

func repeatedFlatCallback() {
    b := &box{tally: &tally{}}
    for index := 0; index < 2; index++ {
        go b.flat()
    }
}

func (b *box) direct(depth int) {
    b.each(func() {})
    if depth > 0 {
        b.direct(depth - 1)
    }
}

func repeatedDirectRecursion() {
    b := &box{tally: &tally{}}
    for index := 0; index < 2; index++ {
        go b.direct(2)
    }
}

func (b *box) throughCallback(depth int) {
    b.each(func() {
        if depth > 0 {
            b.throughCallback(depth - 1)
        }
    })
}

func repeatedCallbackRecursion() {
    b := &box{tally: &tally{}}
    for index := 0; index < 2; index++ {
        go b.throughCallback(2)
    }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    for root in [
        "repeatedFlatCallback",
        "repeatedDirectRecursion",
        "repeatedCallbackRecursion",
    ] {
        let query = CodeQuery::from_json(&json!({
            "languages": ["go"],
            "match": { "kind": "function", "name": root },
            "steps": [
                { "op": "procedure_of" },
                { "op": "concurrent_access_conflicts" }
            ],
            "result_detail": "full"
        }))
        .expect("callback recursion concurrent access query");
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let reported = result
            .results
            .iter()
            .filter(|item| {
                matches!(
                    &item.value,
                    CodeQueryResultValue::ConcurrentAccessConflict { value }
                        if value.verdict == "conflict" && value.task_relation == "repeated"
                )
            })
            .count();
        // The callee's `total++` yields one proven write/read relation and
        // one proven write/write relation for the repeated child tasks.
        assert_eq!(
            reported, 2,
            "{root} must report both callee access orientations: {result:#?}"
        );
    }
}

/// #2902's heap-identity routes: one object reached two ways is one location,
/// and two objects reached the same way are not.
///
/// This is the paired-near-miss coverage the issue asks for. Each route has a
/// positive that must report and a negative that must not, so a fix that
/// buys recall by collapsing distinct allocations fails here rather than
/// passing quietly.
///
/// The `result` and `interface` routes are absent on purpose: they do not hold
/// today and are pinned separately in
/// `go_heap_identity_survives_result_and_interface_routes`.
#[test]
fn go_heap_identity_survives_parameter_receiver_field_and_closure_routes() {
    let (_project, workspace) = heap_identity_workspace();
    // A positive asserts only that the object is recognised as shared. The
    // number of pairs follows from the access shape -- `c.n++` is a read and a
    // write, so it pairs twice -- and pinning it would make the test about
    // that rather than about identity.
    for route in [
        "sharedParameter",
        "sharedReceiver",
        "sharedField",
        "sharedClosure",
    ] {
        assert!(
            proven_conflicts(&workspace, route) >= 1,
            "{route}: one object reached from two tasks is one location"
        );
    }
    for route in [
        "distinctParameter",
        "distinctReceiver",
        "distinctField",
        "taskLocalAllocation",
    ] {
        assert_eq!(
            proven_conflicts(&workspace, route),
            0,
            "{route}: distinct allocations must stay disjoint"
        );
    }
}

/// #2902's container-copy semantics: a slice or map copy keeps its backing
/// store, while a struct or array copied by value gets distinct inline
/// storage. References nested inside either value copy still name their
/// original pointees.
#[test]
fn go_container_copies_keep_backing_and_value_copies_do_not() {
    let (_project, workspace) = heap_identity_workspace();
    for route in ["sliceCopy", "mapCopy", "appendWithinCapacity"] {
        assert!(
            proven_conflicts(&workspace, route) >= 1,
            "{route}: a reference-like copy keeps one backing store"
        );
    }
    assert_eq!(
        proven_conflicts(&workspace, "structValueCopy"),
        0,
        "a struct copied by value has its own field storage"
    );
    for route in [
        "arrayPointerElementCopy",
        "arrayPointerElementCopyChain",
        "arrayPointerElementCompositeLiteral",
        "arrayPointerElementKeyedCompositeLiteral",
        "structPointerFieldCopy",
        "structPointerFieldCopyChain",
    ] {
        let result = heap_identity_conflicts(&workspace, route);
        assert_proven_unordered_unprotected_conflict(
            &result,
            "copying an aggregate preserves its nested pointer payload",
        );
    }
    let distinct = heap_identity_conflicts(&workspace, "arrayPointerElementsStayDistinct");
    assert_no_proven_conflicts_with_explicit_evidence(&distinct);
    for route in [
        "arrayPointerElementConstLengthLiteral",
        "arrayValueCompositeLiteralCopy",
        "arrayPointerElementReplacedAfterCopy",
        "arrayPointerElementSourceReplacedAfterCopy",
        "structPointerFieldReplacedAfterCopy",
        "structPointerFieldSourceReplacedAfterCopy",
    ] {
        let result = heap_identity_conflicts(&workspace, route);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
}

#[test]
fn go_append_reallocation_distinguishes_backing_storage() {
    let (_project, workspace) = heap_identity_workspace();
    let replaced = heap_identity_conflicts(&workspace, "appendPastCapacity");
    assert_no_proven_conflicts_with_explanation(&replaced);
    assert_eq!(
        replaced.completion(),
        CodeQueryCompletion::Complete,
        "capacity proves that append allocated distinct backing storage: {replaced:#?}"
    );

    let unknown = heap_identity_conflicts(&workspace, "appendUnknownCapacity");
    assert_no_proven_conflicts_with_explicit_evidence(&unknown);
}

#[test]
fn go_slice_copy_retains_exact_element_reads_and_writes() {
    let (_project, workspace) = heap_identity_workspace();
    for root in ["copyDestinationRace", "copySourceRace"] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(
            &result,
            "an exact copy retains its source read and destination write",
        );
    }

    let distinct = heap_identity_conflicts(&workspace, "copyDistinctBacking");
    assert_no_proven_conflicts_with_explanation(&distinct);
    assert_eq!(
        distinct.completion(),
        CodeQueryCompletion::Complete,
        "copy accesses do not merge distinct backing stores: {distinct:#?}"
    );

    let unknown = heap_identity_conflicts(&workspace, "copyUnknownLength");
    assert_no_proven_conflicts_with_explicit_evidence(&unknown);
}

#[test]
fn go_slice_copy_preserves_reference_elements_and_replaces_destination_values() {
    let (_project, workspace) = heap_identity_workspace();
    let shared = heap_identity_conflicts(&workspace, "copySharedPointerElement");
    assert_proven_unordered_unprotected_conflict(
        &shared,
        "copying a pointer element preserves the pointed-to object",
    );

    let replaced = heap_identity_conflicts(&workspace, "copyReplacedPointerElement");
    assert_no_proven_conflicts_with_explanation(&replaced);

    let distinct = heap_identity_conflicts(&workspace, "copyDistinctPointerElements");
    assert_no_proven_conflicts_with_explanation(&distinct);
    assert_eq!(
        distinct.completion(),
        CodeQueryCompletion::Complete,
        "independent pointer-copy chains must resolve without aliasing: {distinct:#?}"
    );

    let value = heap_identity_conflicts(&workspace, "copyStructValueElement");
    assert_no_proven_conflicts_with_explicit_evidence(&value);

    let dynamic = heap_identity_conflicts(&workspace, "copyDynamicPointerElement");
    assert_no_proven_conflicts_with_explicit_evidence(&dynamic);
}

/// A Go array copy duplicates the elements, so the two arrays share nothing.
///
/// `b := a` on `[4]int` is reported as a proven race between `a[0]` and
/// `b[0]`. The index selector is compared correctly -- writing `a[1]` and
/// `b[0]` reports nothing -- so it is the *base* the two copies share, not the
/// element. The same shape on a slice must keep reporting, and does; that
/// pairing is what makes this a copy-semantics defect rather than a
/// container-identity one.
///
/// The producer distinguishes the two, marking an array assignment
/// `TransferKind::AggregateCopy` and a slice or map assignment
/// `ValueFlowKind::BackingStore`. Three places in the solver carried identity
/// across the copy anyway, and all three had to stop: the `ValueFlow` and
/// `Assignment` effects, and the backing store recorded for the cell the copy
/// is assigned into. Only the last one moved this test, which is why the other
/// two are not enough on their own.
///
/// #2902 acceptance: "Go array copies produce distinct storage while slice and
/// map copies retain backing identity".
#[test]
fn go_array_copy_is_distinct_storage() {
    let (_project, workspace) = heap_identity_workspace();
    assert!(
        proven_conflicts(&workspace, "sliceCopy") >= 1,
        "the slice pairing must keep reporting"
    );
    assert_eq!(
        proven_conflicts(&workspace, "arrayCopy"),
        0,
        "a Go array copy duplicates the elements"
    );
}

/// A pointer returned through `makeCell` and then copied through `identity`
/// remains one location when both child tasks use it. The distinct factory
/// result remains disjoint. This activates the result half of #2902's former
/// combined ignored test; before result binding, `sharedResult` loses its race.
#[test]
fn go_heap_identity_survives_result_routes() {
    let (_project, workspace) = heap_identity_workspace();
    let shared = heap_identity_conflicts(&workspace, "sharedResult");
    assert_proven_unordered_unprotected_conflict(
        &shared,
        "identity(c) must preserve the makeCell result's shared location",
    );

    let distinct = heap_identity_conflicts(&workspace, "distinctResult");
    assert_no_proven_conflicts_with_explanation(&distinct);
    assert_eq!(
        distinct.completion(),
        CodeQueryCompletion::Complete,
        "{distinct:#?}"
    );
}

/// A call result must follow the edited return semantics across analyzer
/// generations while a caller-owned flow state remains alive. The unchanged
/// allocator and root files make the update's content-keyed reuse boundary
/// explicit; only choose.go changes between each revision.
#[test]
fn go_heap_identity_keeps_call_result_identity_stable_across_warm_and_incremental_updates() {
    const ALLOC_SOURCE: &str = r#"package main

type cell struct {
    n int
}

func makeCell() *cell { return &cell{} }
"#;
    const ROOT_SOURCE: &str = r#"package main

func callResultIdentity() {
    c := makeCell()
    returned := choose(c)
    go func() { returned.n = 1 }()
    go func() { c.n = 2 }()
}
"#;
    const SAME_POINTER_SOURCE: &str = r#"package main

func choose(c *cell) *cell { return c }
"#;
    const DISTINCT_ALLOCATION_SOURCE: &str = r#"package main

func choose(c *cell) *cell { return makeCell() }
"#;
    const VALUE_COPY_SOURCE: &str = r#"package main

func choose(c *cell) cell { return *c }
"#;

    let project = InlineTestProject::with_language(Language::Go)
        .file("alloc.go", ALLOC_SOURCE)
        .file("choose.go", SAME_POINTER_SOURCE)
        .file("main.go", ROOT_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "callResultIdentity" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("incremental call-result concurrent access query");
    let run = |workspace: &WorkspaceAnalyzer,
               flow_state: &brokk_bifrost_flow::FlowWorkspaceState| {
        execute_workspace(workspace, flow_state, &query)
    };
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();

    let cold = run(&workspace, &flow_state);
    assert_proven_unordered_unprotected_conflict(
        &cold,
        "the initial pointer result must alias its input",
    );
    let warm = run(&workspace, &flow_state);
    assert_eq!(
        serde_json::to_value(&cold).expect("cold result serializes"),
        serde_json::to_value(&warm).expect("warm result serializes"),
        "warm execution must preserve the initial result rows and evidence",
    );

    let choose = project.file("choose.go");
    choose
        .write(DISTINCT_ALLOCATION_SOURCE)
        .expect("edit choose to return a fresh allocation");
    let distinct_workspace = workspace.update(&BTreeSet::from([choose.clone()]));
    let incremental_distinct = run(&distinct_workspace, &flow_state);
    assert_no_proven_conflicts_with_explanation(&incremental_distinct);
    let fresh_distinct_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let fresh_distinct = run(
        &fresh_distinct_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
    );
    assert_no_proven_conflicts_with_explanation(&fresh_distinct);
    assert_eq!(
        serde_json::to_value(&incremental_distinct).expect("incremental result serializes"),
        serde_json::to_value(&fresh_distinct).expect("fresh result serializes"),
        "incremental fresh-allocation identity must equal a fresh analysis",
    );

    choose
        .write(VALUE_COPY_SOURCE)
        .expect("edit choose to return a value copy");
    let value_workspace = distinct_workspace.update(&BTreeSet::from([choose]));
    let incremental_value = run(&value_workspace, &flow_state);
    assert_no_proven_conflicts_with_explanation(&incremental_value);
    let fresh_value_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let fresh_value = run(
        &fresh_value_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
    );
    assert_no_proven_conflicts_with_explanation(&fresh_value);
    assert_eq!(
        serde_json::to_value(&incremental_value).expect("incremental value result serializes"),
        serde_json::to_value(&fresh_value).expect("fresh value result serializes"),
        "incremental value-copy identity must equal a fresh analysis",
    );
}

#[test]
fn go_heap_identity_asserted_pointer_fields_never_disappear() {
    let (_project, workspace) = heap_identity_workspace();
    for root in ["sharedPointerAssertion", "sharedExplicitInterfaceAssertion"] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_conflict_or_explicit_open(&result);
    }
}

#[test]
fn go_heap_identity_preserves_asserted_pointer_payloads() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "sharedPointerAssertion",
        "sharedExplicitInterfaceAssertion",
        "sharedVarPointerAssertion",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(&result, root);
    }
}

#[test]
fn go_heap_identity_preserves_pointer_assertions_inside_a_child() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "sharedDirectPointerAssertion");
    assert_proven_unordered_unprotected_conflict(&result, "assertion inside a child");
}

#[test]
fn go_heap_identity_incompatible_assertions_never_prove_races() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "incompatibleSliceAssertion",
        "incompatibleMapAssertion",
        "incompatibleSliceElementAssertion",
        "incompatibleMapKeyAssertion",
        "incompatibleMapValueAssertion",
        "incompatibleNestedMapAssertion",
        "incompatibleSliceSelfAssertion",
        "incompatibleArraySelfAssertion",
        "incompatibleStructSelfAssertion",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
}

#[test]
fn go_heap_identity_does_not_prove_replaced_interface_payloads() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "replacedInterfacePayload",
        "replacedInterfacePayloadInClosure",
        "replacedInterfacePayloadInSelect",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
}

#[test]
fn go_heap_identity_keeps_unknown_interface_payload_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "unknownInterfacePayload");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_heap_identity_assertion_aliases_use_declaration_scope() {
    let (_project, workspace) = heap_identity_workspace();
    let shared = heap_identity_conflicts(&workspace, "shadowedSliceAssertion");
    assert_proven_unordered_unprotected_conflict(&shared, "slice alias keeps its declared type");
    let copied = heap_identity_conflicts(&workspace, "shadowedArrayAssertion");
    assert_no_proven_conflicts_with_explanation(&copied);
}

#[test]
fn go_heap_identity_preserves_asserted_backing_storage() {
    let (_project, workspace) = heap_identity_workspace();
    for root in ["sharedSliceAssertion", "sharedMapAssertion"] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(&result, root);
    }
}

#[test]
fn go_heap_identity_assertion_copies_and_distinct_payloads_never_prove_races() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "copiedValueAssertion",
        "copiedArrayAssertion",
        "distinctPointerAssertions",
        "distinctSliceAssertions",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
}

#[test]
fn go_heap_identity_survives_interface_route() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "sharedInterface");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "an interface carrying one stable pointer must preserve its shared location",
    );
}

#[test]
fn go_heap_identity_preserves_stable_interface_forwarding() {
    let (_project, workspace) = heap_identity_workspace();
    let shared = heap_identity_conflicts(&workspace, "sharedForwardedInterface");
    assert_proven_unordered_unprotected_conflict(
        &shared,
        "a stable interface-to-interface conversion retains its pointer payload",
    );

    let distinct = heap_identity_conflicts(&workspace, "distinctForwardedInterface");
    assert_no_proven_conflicts_with_explanation(&distinct);
    assert_eq!(
        distinct.completion(),
        CodeQueryCompletion::Complete,
        "{distinct:#?}"
    );

    let replaced = heap_identity_conflicts(&workspace, "replacedForwardedInterface");
    assert_no_proven_conflicts_with_explicit_evidence(&replaced);
}

#[test]
#[ignore = "finds real gap: #2771 must supply complete cross-file receiver type-flow feedback"]
fn go_heap_identity_preserves_cross_file_interface_dispatch() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "types.go",
            r#"package main

type crossFileCell struct { n int }
type crossFileBumper interface { bump() }

func (c *crossFileCell) bump() { c.n++ }
"#,
        )
        .file(
            "main.go",
            r#"package main

func sharedCrossFileInterface() {
    c := &crossFileCell{}
    var boxed crossFileBumper = c
    go boxed.bump()
    go c.bump()
}

func distinctCrossFileInterface() {
    first := &crossFileCell{}
    second := &crossFileCell{}
    var boxed crossFileBumper = first
    go boxed.bump()
    go second.bump()
}

func replacedCrossFileInterface() {
    original := &crossFileCell{}
    var boxed crossFileBumper = original
    boxed = &crossFileCell{}
    go boxed.bump()
    go original.bump()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let shared = heap_identity_conflicts(&workspace, "sharedCrossFileInterface");
    assert_proven_unordered_unprotected_conflict(
        &shared,
        "an exact cross-file interface dispatch retains its pointer payload",
    );

    let distinct = heap_identity_conflicts(&workspace, "distinctCrossFileInterface");
    assert_no_proven_conflicts_with_explanation(&distinct);

    let replaced = heap_identity_conflicts(&workspace, "replacedCrossFileInterface");
    assert_no_proven_conflicts_with_explicit_evidence(&replaced);
}

#[test]
fn go_heap_identity_interface_dispatch_does_not_fabricate_payload_identity() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "interfaceDistinctPayloads",
        "interfaceReplacedPayload",
        "interfaceValuePayload",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
    let value_receiver =
        heap_identity_conflicts(&workspace, "interfacePointerPayloadValueReceiver");
    assert_no_proven_conflicts_with_explicit_evidence(&value_receiver);
}

/// Returning a `cell` by value copies its inline field storage. A missing
/// value-result model may leave this route empty or explicitly open, but it
/// must never prove a race between the returned copy and the source pointer.
#[test]
fn go_heap_identity_value_result_copy_never_proves_a_race() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "structValueResultCopy");
    assert_no_proven_conflicts_with_explanation(&result);
}

/// The first and second pointer results must retain their exact ordinals when
/// both results carry the same actual pointer. Before indexed result binding,
/// this shared positive loses its proven conflict.
#[test]
fn go_heap_identity_preserves_same_pointer_result_ordinals() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "samePointerResultOrdinals");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "the two pointer result ordinals must preserve one shared actual",
    );
}

/// Distinct actual allocations returned in the two ordinals must not be
/// collapsed into one pointer result location.
#[test]
fn go_heap_identity_keeps_distinct_pointer_result_ordinals_disjoint() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "distinctPointerResultOrdinals");
    assert_no_proven_conflicts_with_explanation(&result);
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
}

/// If either branch returns the same pointer actual, the alternative result is
/// still one shared location. This is the positive control for branch binding.
#[test]
fn go_heap_identity_preserves_alternative_same_input_result() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "alternativeSameInput");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "both alternative returns carry the same input pointer",
    );
}

/// An unknown branch selecting between two distinct pointers cannot prove that
/// the returned result aliases the first input. It may remain open, but must
/// not fabricate a proven conflict.
#[test]
fn go_heap_identity_does_not_fabricate_alternative_distinct_input_race() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "alternativeDistinctInputs");
    assert_no_proven_conflicts_with_explanation(&result);
}

/// Unbound pointer inputs through the same alternative-return helper must keep
/// their missing object identity explicit when the route cannot be resolved.
#[test]
fn go_heap_identity_keeps_alternative_unknown_inputs_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "alternativeUnknownInputs");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_heap_identity_uses_invocation_control_for_reference_results() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }
func never() { for {} }
func neverSelect() { select {} }
func defaultSelect() { select { default: } }
func resultDefaultSelect(stop bool) {
    shared := &cell{}
    chosen := selectShared(stop, defaultSelect, shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
func resultReceivingSelect(stop bool, ready <-chan int) {
    shared := &cell{}
    chosen := selectShared(stop, func() { select { case <-ready: } }, shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
func selectShared(stop bool, wait func(), shared *cell) *cell {
    if stop { wait(); return &cell{} }
    return shared
}
func selectDistinct(stop bool, wait func(), shared *cell) *cell {
    if stop { wait(); return shared }
    return &cell{}
}
func resultReachableShared(stop bool) {
    shared := &cell{}
    chosen := selectShared(stop, never, shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
func resultReachableDistinct(stop bool) {
    shared := &cell{}
    chosen := selectDistinct(stop, never, shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
func selectReachableShared(stop bool) {
    shared := &cell{}
    chosen := selectShared(stop, neverSelect, shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
func selectReachableDistinct(stop bool) {
    shared := &cell{}
    chosen := selectDistinct(stop, neverSelect, shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
func selectOnlyShared(shared *cell) *cell { return shared }
func resultSharedControl() {
    shared := &cell{}
    chosen := selectOnlyShared(shared)
    go func() { chosen.n = 1 }()
    shared.n = 2
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let control = go_invocation_conflicts(&workspace, "resultSharedControl");
    assert_proven_unordered_unprotected_conflict(&control, "simple pointer-return control");
    let distinct = go_invocation_conflicts(&workspace, "resultReachableDistinct");
    assert_no_proven_unordered_unprotected_conflicts(&distinct);
    let select_distinct = go_invocation_conflicts(&workspace, "selectReachableDistinct");
    assert_no_proven_unordered_unprotected_conflicts(&select_distinct);
    for name in ["resultDefaultSelect", "resultReceivingSelect"] {
        let returning = go_invocation_conflicts(&workspace, name);
        assert_no_proven_conflicts_with_explicit_evidence(&returning);
    }
    let select_shared = go_invocation_conflicts(&workspace, "selectReachableShared");
    assert_proven_unordered_unprotected_conflict(
        &select_shared,
        "an empty select never resumes the competing return",
    );
    let shared = go_invocation_conflicts(&workspace, "resultReachableShared");
    assert_proven_unordered_unprotected_conflict(
        &shared,
        "a return after the bound nonreturning callback cannot compete with the shared result",
    );
}

/// Each repeated child calls the factory for its own cell before writing it.
/// The result allocations must stay disjoint; an unresolved result may remain
/// open, but a result-identity mistake must not become a proven race.
#[test]
fn go_heap_identity_keeps_repeated_factory_results_fresh() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "repeatedFactoryChildren");
    assert_no_proven_conflicts_with_explanation(&result);
}

/// A factory result created outside the child tasks is captured by both of
/// them, so its result identity must be preserved as one shared location.
#[test]
fn go_heap_identity_preserves_shared_factory_result_outside_children() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "sharedFactoryResult");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "a factory result shared outside child tasks must retain its race",
    );
}

/// The unnamed return evaluates the nil local before the defer assigns a fresh
/// cell. The guarded caller must not be treated as writing that fresh cell.
#[test]
fn go_heap_identity_does_not_bind_return_before_defer_local_to_fresh_cell() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "deferredLocalReturnUse");
    assert_no_proven_conflicts_with_explanation(&result);
}

/// The return value is the nonnil incoming pointer, while the deferred
/// parameter reassignment creates a separate cell for its spawned writer.
#[test]
fn go_heap_identity_does_not_bind_return_before_defer_parameter_to_fresh_cell() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "deferredParameterReturnUse");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

/// An explicit IndexedReturn observes the pre-cleanup `input` value. The named
/// result is replaced by a fresh cell in defer, so the two post-call writes are
/// disjoint and must not become a fabricated proven race.
#[test]
fn go_heap_identity_does_not_use_pre_cleanup_named_result_identity() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "deferredNamedResultUse");
    assert_no_proven_conflicts_with_explanation(&result);
}

/// A defer that leaves the returned pointer unchanged must preserve its shared
/// identity. This guards against treating every deferred result as unstable.
#[test]
fn go_heap_identity_preserves_stable_deferred_result_identity() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "stableDeferredResultUse");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "an unchanged deferred result must preserve one shared pointer",
    );
}

/// The returned pointer is evaluated before the escaped closure later
/// reassigns its captured binding. The closure is returned as a function
/// value, so its body is not necessarily expanded into the invocation graph.
/// Its later write targets the fresh cell and must stay open rather than
/// becoming a fabricated race with the returned old cell.
#[test]
fn go_heap_identity_keeps_escaped_result_mutation_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "escapedClosureMutationUse");
    assert_no_proven_conflicts_with_explanation(&result);
    assert_conflict_or_explicit_open(&result);
}

/// The callback runs before the helper returns, while `run` is obtained from a
/// function-valued result. This exercises the captured assignment on the
/// pre-return path even when that indirect callee is unavailable for graph
/// expansion. The returned `c` and original `first` are distinct allocations,
/// so the result relation must retain explicit uncertainty.
#[test]
fn go_heap_identity_keeps_pre_return_hidden_capture_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "preReturnHiddenCaptureUse");
    assert_no_proven_conflicts_with_explanation(&result);
    assert_conflict_or_explicit_open(&result);
}

/// `copied` reads the old pointer before `source` is assigned again.
/// The two returned pointer ordinals therefore refer to distinct
/// allocations; unresolved reaching-definition identity must not prove a race.
#[test]
fn go_heap_identity_keeps_copied_pointer_before_later_assignment_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "copiedPointerReadBeforeLaterAssignmentUse");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

/// A zero-valued pointer is copied before its source's only explicit store.
/// The guarded nil copy cannot race with the later fresh allocation.
#[test]
fn go_heap_identity_keeps_copy_before_sole_source_store_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "copyBeforeSoleSourceStoreUse");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

/// The unmodeled goto reaches a different return. A cut in the retained CFG
/// cannot prove that the first return is the only result at runtime.
#[test]
fn go_heap_identity_keeps_unmodeled_return_transfer_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "unmodeledReturnTransferUse");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_heap_identity_keeps_returned_slice_offsets_distinct_or_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "distinctReturnedSliceOffsets");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_heap_identity_preserves_returned_zero_offset_slices() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "sameReturnedSliceOffsets");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "zero-offset returned slices share backing elements",
    );
}

/// A same-file type alias deliberately leaves result storage metadata
/// unavailable. The input and returned pointer are equal at runtime, but the
/// analyzer must retain explicit uncertainty instead of proving a race from
/// an unsupported result type shape.
#[test]
fn go_heap_identity_keeps_unavailable_result_type_metadata_open() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "unavailableResultTypeMetadataUse");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_heap_identity_does_not_retain_reassigned_formal_entry_results() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "reassignedDirectResultParameter",
        "reassignedDirectResultReceiver",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
}

#[test]
fn go_heap_identity_does_not_retain_reassigned_formal_entry_allocations() {
    let (_project, workspace) = heap_identity_workspace();
    for root in [
        "reassignedDirectLiteralParameter",
        "reassignedDirectLiteralReceiver",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
}

#[test]
fn go_heap_identity_preserves_stable_formal_entry_results() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "stableDirectResultParameter");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "a named unchanged formal must retain the caller's allocation result",
    );
}

/// A channel publishes one object to another task.
///
/// #2902 asks that "exact channel/container transport can publish an object to
/// another task without treating every payload as globally aliased". Sending a
/// pointer and receiving it in a spawned task currently relates nothing, so the
/// receiver's write and the sender's write name the same allocation.
///
/// Owned by #2902.
#[test]
fn go_channel_transport_publishes_its_payload() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "channelPublish");
    assert!(
        result.results.iter().any(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict" && value.proof == "proven"
            )
        }),
        "a pointer sent through a channel is the same object on both sides: {result:#?}"
    );
}

#[test]
fn go_channel_transport_ignores_only_unreachable_publication() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }
func never() { for {} }
func publish(ch chan *cell)
func maybePublish(stop bool, wait func(), ch chan *cell) {
    if stop { wait(); publish(ch) }
}
func sharedControl() {
    shared := &cell{}
    ch := make(chan *cell, 1)
    ch <- shared
    go func() { chosen := <-ch; chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func unreachablePublication(stop bool) {
    shared := &cell{}
    ch := make(chan *cell, 1)
    maybePublish(stop, never, ch)
    ch <- shared
    go func() { chosen := <-ch; chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func distinctAfterUnreachablePublication(stop bool) {
    shared := &cell{}
    ch := make(chan *cell, 1)
    maybePublish(stop, never, ch)
    ch <- &cell{}
    go func() { chosen := <-ch; chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func rootUnreachablePublication(stop bool) {
    shared := &cell{}
    ch := make(chan *cell, 1)
    if stop { never(); publish(ch) }
    ch <- shared
    go func() { chosen := <-ch; chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func rootReachablePublication(stop bool) {
    shared := &cell{}
    ch := make(chan *cell, 1)
    if stop { publish(ch) }
    ch <- shared
    go func() { chosen := <-ch; chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let control = go_invocation_conflicts(&workspace, "sharedControl");
    assert_proven_unordered_unprotected_conflict(&control, "closed channel transport control");
    for root in [
        "rootReachablePublication",
        "distinctAfterUnreachablePublication",
    ] {
        let negative = go_invocation_conflicts(&workspace, root);
        assert_no_proven_unordered_unprotected_conflicts(&negative);
    }
    for root in ["rootUnreachablePublication", "unreachablePublication"] {
        let positive = go_invocation_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(
            &positive,
            "a publication after a proven nonreturning call cannot escape the channel",
        );
    }
}

#[test]
fn go_channel_received_capture_preserves_payload_type_and_identity() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }
func write(c *cell) { c.n = 1 }
func parameterControl() {
    shared := &cell{}
    ch := make(chan *cell, 1)
    ch <- shared
    chosen := <-ch
    go write(chosen)
    go func() { shared.n = 2 }()
}
func inferredCapture() {
    shared := &cell{}
    ch := make(chan *cell, 1)
    ch <- shared
    chosen := <-ch
    go func() { chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func typedCapture() {
    shared := &cell{}
    ch := make(chan *cell, 1)
    ch <- shared
    var chosen *cell = <-ch
    go func() { chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func distinctCapture() {
    shared := &cell{}
    ch := make(chan *cell, 1)
    ch <- &cell{}
    chosen := <-ch
    go func() { chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
func valueCapture() {
    shared := cell{}
    ch := make(chan cell, 1)
    ch <- shared
    chosen := <-ch
    go func() { chosen.n = 1 }()
    go func() { shared.n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for root in ["distinctCapture", "valueCapture"] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_unordered_unprotected_conflicts(&result);
    }
    for root in ["parameterControl", "typedCapture", "inferredCapture"] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(&result, root);
    }
}

#[test]
fn go_channel_descriptor_copy_preserves_exact_payload_transport() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "channelDescriptorCopy");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "a copied channel descriptor retains one exact channel object",
    );
}

#[test]
fn go_channel_formal_preserves_exact_payload_transport() {
    let (_project, workspace) = heap_identity_workspace();
    let result = heap_identity_conflicts(&workspace, "channelHelperPayload");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "a fresh caller channel passed through exact helpers retains its transported object",
    );
}

#[test]
fn go_channel_backing_transport_publishes_slice_and_map_storage() {
    let (_project, workspace) = heap_identity_workspace();
    for root in ["channelSlicePublish", "channelMapPublish"] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(
            &result,
            "a slice or map sent through one exact channel retains its backing storage",
        );
    }
}

#[test]
fn go_channel_transport_does_not_fabricate_payload_identity() {
    let (_project, workspace) = heap_identity_workspace();
    for root in ["channelStructValueCopy", "channelHelperValueCopy"] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{root}: {result:#?}"
        );
        assert!(result.diagnostics.is_empty(), "{root}: {result:#?}");
        assert!(
            result.results.iter().all(|item| {
                matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.task_relation != "siblings")
            }),
            "a copied scalar field has distinct storage: {root}: {result:#?}"
        );
    }
    for root in [
        "channelMultipleSends",
        "channelInterfacePayload",
        "channelParameterPayload",
        "channelReassignedHelper",
        "channelLoopSend",
        "channelCloseAlternative",
        "channelTupleAlias",
        "channelSliceOffset",
        "channelFieldSliceOffset",
    ] {
        let result = heap_identity_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
    let distinct = heap_identity_conflicts(&workspace, "channelDistinctBackingStore");
    assert_no_proven_conflicts_with_explanation(&distinct);
}

/// Count the proven conflicts a root reports, which is what every heap-identity
/// route above is asking about.
fn proven_conflicts(workspace: &WorkspaceAnalyzer, root: &str) -> usize {
    heap_identity_conflicts(workspace, root)
        .results
        .iter()
        .filter(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict" && value.proof == "proven"
            )
        })
        .count()
}

fn heap_identity_conflicts(workspace: &WorkspaceAnalyzer, root: &str) -> CodeQueryResult {
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": root },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("heap identity concurrent access query");
    execute_workspace(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

/// The project owns the temporary directory the analyzer reads from, so it is
/// returned with the workspace and must be held for as long as the workspace is
/// queried. Dropping it first makes every query fail with
/// `SemanticProviderFailed`, which reads exactly like an analysis gap.
fn heap_identity_workspace() -> (inline_project::BuiltInlineTestProject, WorkspaceAnalyzer) {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    n int
}

type wrap struct {
    c *cell
}

type valueWrap struct {
    c cell
}

type bumper interface {
    bump()
}

func (c *cell) bump() { c.n++ }

type valueBumper interface {
    bumpValue()
}

func (c cell) bumpValue() { c.n++ }

func viaParam(c *cell) { c.n = 1 }

func sharedParameter() {
    c := &cell{}
    go viaParam(c)
    go viaParam(c)
}

func distinctParameter() {
    go viaParam(&cell{})
    go viaParam(&cell{})
}

func sharedReceiver() {
    c := &cell{}
    go c.bump()
    go c.bump()
}

func distinctReceiver() {
    first := &cell{}
    second := &cell{}
    go first.bump()
    go second.bump()
}

func sharedField() {
    w := &wrap{c: &cell{}}
    go func() { w.c.n = 1 }()
    go func() { w.c.n = 2 }()
}

func distinctField() {
    first := &wrap{c: &cell{}}
    second := &wrap{c: &cell{}}
    go func() { first.c.n = 1 }()
    go func() { second.c.n = 2 }()
}

func sharedClosure() {
    c := &cell{}
    run := func() { c.n = 1 }
    go run()
    go func() { c.n = 2 }()
}

func taskLocalAllocation() {
    for index := 0; index < 2; index++ {
        go func() {
            local := &cell{}
            local.n = 1
        }()
    }
}

func makeCell() *cell { return &cell{} }

func identity(c *cell) *cell { return c }

func sharedResult() {
    c := makeCell()
    d := identity(c)
    go func() { d.n = 1 }()
    go func() { c.n = 2 }()
}

func distinctResult() {
    c := makeCell()
    d := makeCell()
    go func() { d.n = 1 }()
    go func() { c.n = 2 }()
}

func copyCell(c *cell) cell { return *c }

func structValueResultCopy() {
    c := makeCell()
    returned := copyCell(c)
    go func() { returned.n = 1 }()
    go func() { c.n = 2 }()
}

func pointerPair(first, second *cell) (*cell, *cell) {
    return first, second
}

func samePointerResultOrdinals() {
    c := makeCell()
    first, second := pointerPair(c, c)
    go func() { first.n = 1 }()
    go func() { second.n = 2 }()
}

func distinctPointerResultOrdinals() {
    first, second := pointerPair(makeCell(), makeCell())
    go func() { first.n = 1 }()
    go func() { second.n = 2 }()
}

func alternateCell(first, second *cell, chooseFirst bool) *cell {
    if chooseFirst {
        return first
    }
    return second
}

func alternativeSameInput(chooseFirst bool) {
    c := makeCell()
    returned := alternateCell(c, c, chooseFirst)
    go func() { returned.n = 1 }()
    go func() { c.n = 2 }()
}

func alternativeDistinctInputs(chooseFirst bool) {
    first := makeCell()
    second := makeCell()
    returned := alternateCell(first, second, chooseFirst)
    go func() { returned.n = 1 }()
    go func() { first.n = 2 }()
}

func alternativeUnknownInputs(chooseFirst bool, first, second *cell) {
    returned := alternateCell(first, second, chooseFirst)
    go func() { returned.n = 1 }()
    go func() { first.n = 2 }()
}

func repeatedFactoryChildren() {
    for {
        go func() {
            local := makeCell()
            local.n = 1
        }()
    }
}

func sharedFactoryResult() {
    c := makeCell()
    go func() { c.n = 1 }()
    go func() { c.n = 2 }()
}

func returnBeforeDeferLocal() *cell {
    var local *cell
    defer func() {
        local = &cell{}
        go func() { local.n = 1 }()
    }()
    return local
}

func deferredLocalReturnUse() {
    returned := returnBeforeDeferLocal()
    if returned != nil {
        go func() { returned.n = 2 }()
    }
}

func returnBeforeDeferParameter(input *cell) *cell {
    defer func() {
        input = &cell{}
        go func() { input.n = 1 }()
    }()
    return input
}

func deferredParameterReturnUse(input *cell) {
    if input == nil {
        return
    }
    returned := returnBeforeDeferParameter(input)
    go func() { returned.n = 2 }()
}

func namedResultDeferredMutation(input *cell) (returned *cell, ok bool) {
    defer func() {
        returned = &cell{}
    }()
    return input, true
}

func deferredNamedResultUse() {
    source := makeCell()
    returned, _ := namedResultDeferredMutation(source)
    go func() { returned.n = 1 }()
    go func() { source.n = 2 }()
}

func stableDeferredResult(input *cell) *cell {
    defer func() { _ = input }()
    return input
}

func stableDeferredResultUse() {
    c := makeCell()
    returned := stableDeferredResult(c)
    go func() { returned.n = 1 }()
    go func() { c.n = 2 }()
}

func escapedClosureResult() (*cell, func()) {
    c := makeCell()
    mutate := func() {
        c = makeCell()
        c.n = 1
    }
    return c, mutate
}

func escapedClosureMutationUse() {
    returned, mutate := escapedClosureResult()
    go func() { returned.n = 2 }()
    go mutate()
}

func callbackRunner() (int, func(func())) {
    return 0, func(f func()) { f() }
}

func preReturnHiddenCapture() (*cell, *cell) {
    _, run := callbackRunner()
    first := makeCell()
    c := first
    run(func() { c = makeCell() })
    return c, first
}

func preReturnHiddenCaptureUse() {
    current, original := preReturnHiddenCapture()
    go func() { current.n = 1 }()
    go func() { original.n = 2 }()
}

func copiedBeforeSourceAssignment() (*cell, *cell) {
    source := makeCell()
    copied := source
    source = makeCell()
    return copied, source
}

func copiedPointerReadBeforeLaterAssignmentUse() {
    copied, fresh := copiedBeforeSourceAssignment()
    go func() { copied.n = 1 }()
    go func() { fresh.n = 2 }()
}

func copyBeforeSoleSourceStore() (*cell, *cell) {
    var source *cell
    copied := source
    source = makeCell()
    return copied, source
}

func copyBeforeSoleSourceStoreUse() {
    copied, fresh := copyBeforeSoleSourceStore()
    if copied != nil {
        go func() { copied.n = 1 }()
    }
    go func() { fresh.n = 2 }()
}

func resultAcrossGoto(first, second *cell, chooseSecond bool) *cell {
    if chooseSecond {
        goto alternate
    }
    return first
alternate:
    return second
}

func unmodeledReturnTransferUse() {
    first := makeCell()
    second := makeCell()
    returned := resultAcrossGoto(first, second, true)
    go func() { returned.n = 1 }()
    go func() { first.n = 2 }()
}

func splitSliceResult() ([]int, []int) {
    values := make([]int, 2)
    return values[:1], values[1:]
}

func sameSliceResult() ([]int, []int) {
    values := make([]int, 2)
    return values[:1], values[:1]
}

func distinctReturnedSliceOffsets() {
    first, second := splitSliceResult()
    go func() { first[0] = 1 }()
    go func() { second[0] = 2 }()
}

func sameReturnedSliceOffsets() {
    first, second := sameSliceResult()
    go func() { first[0] = 1 }()
    go func() { second[0] = 2 }()
}

type opaquePointer = *cell

func opaquePointerResult(input opaquePointer) opaquePointer {
    return input
}

func replaceDirectResultParameter(p *cell) {
    p = opaquePointerResult(makeCell())
    p.n = 1
}

func (p *cell) replaceDirectResultReceiver() {
    p = opaquePointerResult(makeCell())
    p.n = 1
}

func writeStableResultParameter(p *cell) { p.n = 1 }

func reassignedDirectResultParameter() {
    original := makeCell()
    go replaceDirectResultParameter(original)
    go func() { original.n = 2 }()
}

func reassignedDirectResultReceiver() {
    original := makeCell()
    go original.replaceDirectResultReceiver()
    go func() { original.n = 2 }()
}

func stableDirectResultParameter() {
    original := makeCell()
    go writeStableResultParameter(original)
    go func() { original.n = 2 }()
}

func reassignedDirectLiteralParameter() {
    original := &cell{}
    go replaceDirectResultParameter(original)
    go func() { original.n = 2 }()
}

func reassignedDirectLiteralReceiver() {
    original := &cell{}
    go original.replaceDirectResultReceiver()
    go func() { original.n = 2 }()
}

func unavailableResultTypeMetadataUse() {
    source := makeCell()
    returned := opaquePointerResult(source)
    go func() {
        if returned != nil {
            returned.n = 1
        }
    }()
    go func() { source.n = 2 }()
}

func sharedPointerAssertion() {
    original := &cell{}
    var boxed any = original
    recovered := boxed.(*cell)
    go func() { recovered.n = 1 }()
    go func() { original.n = 2 }()
}

func sharedExplicitInterfaceAssertion() {
    original := &cell{}
    var boxed interface{} = original
    recovered := boxed.(*cell)
    go func() { recovered.n = 1 }()
    go func() { original.n = 2 }()
}

func sharedVarPointerAssertion() {
    original := &cell{}
    var boxed interface{} = original
    var recovered = boxed.(*cell)
    go func() { recovered.n = 1 }()
    go func() { original.n = 2 }()
}

func sharedDirectPointerAssertion() {
    original := &cell{}
    var boxed any = original
    go func() { boxed.(*cell).n = 1 }()
    go func() { original.n = 2 }()
}

func copiedValueAssertion() {
    original := cell{}
    var boxed any = original
    recovered := boxed.(cell)
    go func() { recovered.n = 1 }()
    go func() { original.n = 2 }()
}

func copiedArrayAssertion() {
    original := [1]int{}
    var boxed any = original
    recovered := boxed.([1]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func sharedSliceAssertion() {
    original := make([]int, 1)
    var boxed any = original
    recovered := boxed.([]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func sharedMapAssertion() {
    original := make(map[int]int)
    var boxed any = original
    recovered := boxed.(map[int]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func incompatibleSliceAssertion() {
    original := make(map[int]int)
    var boxed any = original
    recovered := boxed.([]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func incompatibleMapAssertion() {
    original := make([]int, 1)
    var boxed any = original
    recovered := boxed.(map[int]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func incompatibleSliceElementAssertion() {
    original := make([]int, 1)
    var boxed any = original
    recovered := boxed.([]string)
    go func() { recovered[0] = "value" }()
    go func() { original[0] = 2 }()
}

func incompatibleSliceSelfAssertion() {
    original := make([]int, 1)
    var boxed any = original
    recovered := boxed.([]string)
    go func() { recovered[0] = "one" }()
    go func() { recovered[0] = "two" }()
}

func incompatibleArraySelfAssertion() {
    original := [1]int{}
    var boxed any = original
    recovered := boxed.([1]string)
    go func() { recovered[0] = "one" }()
    go func() { recovered[0] = "two" }()
}

type assertionOtherCell struct { n int }

func incompatibleStructSelfAssertion() {
    original := cell{}
    var boxed any = original
    recovered := boxed.(assertionOtherCell)
    go func() { recovered.n = 1 }()
    go func() { recovered.n = 2 }()
}

func incompatibleMapKeyAssertion() {
    original := make(map[int]int)
    var boxed any = original
    recovered := boxed.(map[uint]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func incompatibleMapValueAssertion() {
    original := make(map[int]int)
    var boxed any = original
    recovered := boxed.(map[int]string)
    go func() { recovered[0] = "value" }()
    go func() { original[0] = 2 }()
}

type assertionMapKey int
type assertionMapValue int
type assertionOtherMapValue int

func incompatibleNestedMapAssertion() {
    original := map[assertionMapKey]map[string]assertionMapValue{0: {"key": 0}}
    var boxed any = original
    recovered := boxed.(map[assertionMapKey]map[string]assertionOtherMapValue)
    go func() { recovered[0]["key"] = 1 }()
    go func() { original[0]["key"] = 2 }()
}

func replacedInterfacePayload() {
    original := make([]int, 1)
    var boxed any = original
    boxed = make([]int, 1)
    recovered := boxed.([]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func replacedInterfacePayloadInClosure() {
    original := make([]int, 1)
    var boxed any = original
    replace := func() { boxed = make([]int, 1) }
    replace()
    recovered := boxed.([]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func unknownInterfacePayload(boxed any, original []int) {
    recovered := boxed.([]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

func replacedInterfacePayloadInSelect() {
    ch := make(chan any, 1)
    original := make([]int, 1)
    var boxed any = original
    ch <- make([]int, 1)
    select {
    case boxed = <-ch:
    }
    recovered := boxed.([]int)
    go func() { recovered[0] = 1 }()
    go func() { original[0] = 2 }()
}

type assertionSliceBase []int
type assertionSliceAlias = assertionSliceBase
type assertionArrayBase [1]int
type assertionArrayAlias = assertionArrayBase

func shadowedSliceAssertion() {
    original := assertionSliceAlias{0}
    var boxed any = original
    {
        type assertionSliceBase [1]int
        recovered := boxed.(assertionSliceAlias)
        go func() { recovered[0] = 1 }()
        go func() { original[0] = 2 }()
    }
}

func shadowedArrayAssertion() {
    original := assertionArrayAlias{0}
    var boxed any = original
    {
        type assertionArrayBase []int
        recovered := boxed.(assertionArrayAlias)
        go func() { recovered[0] = 1 }()
        go func() { original[0] = 2 }()
    }
}

func distinctSliceAssertions() {
    first := make([]int, 1)
    second := make([]int, 1)
    var firstBox any = first
    var secondBox any = second
    firstRecovered := firstBox.([]int)
    secondRecovered := secondBox.([]int)
    go func() { firstRecovered[0] = 1 }()
    go func() { secondRecovered[0] = 2 }()
}

func distinctPointerAssertions() {
    first := &cell{}
    second := &cell{}
    var firstBox any = first
    var secondBox any = second
    firstRecovered := firstBox.(*cell)
    secondRecovered := secondBox.(*cell)
    go func() { firstRecovered.n = 1 }()
    go func() { secondRecovered.n = 2 }()
}

func sharedInterface() {
    c := &cell{}
    var b bumper = c
    go b.bump()
    go c.bump()
}

func sharedForwardedInterface() {
    c := &cell{}
    var first bumper = c
    var forwarded bumper = first
    go forwarded.bump()
    go c.bump()
}

func distinctForwardedInterface() {
    first := &cell{}
    second := &cell{}
    var boxed bumper = first
    var forwarded bumper = boxed
    go forwarded.bump()
    go second.bump()
}

func replacedForwardedInterface() {
    original := &cell{}
    var boxed bumper = original
    boxed = &cell{}
    var forwarded bumper = boxed
    go forwarded.bump()
    go original.bump()
}

func interfaceDistinctPayloads() {
    first := &cell{}
    second := &cell{}
    var b bumper = first
    go b.bump()
    go second.bump()
}

func interfacePointerPayloadValueReceiver() {
    original := &cell{}
    var b valueBumper = original
    go b.bumpValue()
    go func() { original.n = 2 }()
}

func interfaceReplacedPayload() {
    original := &cell{}
    var b bumper = original
    b = &cell{}
    go b.bump()
    go original.bump()
}

func interfaceValuePayload() {
    original := cell{}
    var b valueBumper = original
    go b.bumpValue()
    go func() { original.n = 2 }()
}

func sliceCopy() {
    s := make([]int, 4)
    t := s
    go func() { t[0] = 1 }()
    go func() { s[0] = 2 }()
}

func mapCopy() {
    m := map[int]int{}
    n := m
    go func() { n[0] = 1 }()
    go func() { m[0] = 2 }()
}

func appendWithinCapacity() {
    s := make([]int, 1, 8)
    t := append(s, 1)
    go func() { t[0] = 1 }()
    go func() { s[0] = 2 }()
}

func appendPastCapacity() {
    s := make([]int, 1, 1)
    t := append(s, 1)
    go func() { t[0] = 1 }()
    go func() { s[0] = 2 }()
}

func appendUnknownCapacity(s []int) {
    t := append(s, 1)
    go func() { t[0] = 1 }()
    go func() { s[0] = 2 }()
}

func copySharedPointerElement() {
    source := make([]*cell, 1)
    source[0] = &cell{}
    target := make([]*cell, 1)
    copy(target, source)
    go writePointerElement(target)
    go writePointerElement(source)
}

func copyReplacedPointerElement() {
    original := &cell{}
    replacement := &cell{}
    source := make([]*cell, 1)
    source[0] = replacement
    target := make([]*cell, 1)
    target[0] = original
    copy(target, source)
    go writePointerElement(target)
    go func() { original.n = 2 }()
}

func copyDistinctPointerElements() {
    leftSource := make([]*cell, 1)
    leftSource[0] = &cell{}
    leftTarget := make([]*cell, 1)
    copy(leftTarget, leftSource)

    rightSource := make([]*cell, 1)
    rightSource[0] = &cell{}
    rightTarget := make([]*cell, 1)
    copy(rightTarget, rightSource)

    go writePointerElement(leftTarget)
    go writePointerElement(rightTarget)
}

func copyStructValueElement() {
    source := make([]cell, 1)
    target := make([]cell, 1)
    copy(target, source)
    go func() { target[0].n = 1 }()
    go func() { source[0].n = 2 }()
}

func copyDynamicPointerElement(index int) {
    source := make([]*cell, 1)
    source[index] = &cell{}
    target := make([]*cell, 1)
    copy(target, source)
    go writePointerElement(target)
    go writePointerElement(source)
}

func writePointerElement(values []*cell) { values[0].n = 1 }

func copyDestinationRace() {
    destination := []int{0}
    source := []int{1}
    go func() { destination[0] = 2 }()
    copy(destination, source)
}

func copySourceRace() {
    destination := []int{0}
    source := []int{1}
    go func() { source[0] = 2 }()
    copy(destination, source)
}

func copyDistinctBacking() {
    destination := []int{0}
    source := []int{1}
    other := []int{2}
    go func() { other[0] = 3 }()
    copy(destination, source)
}

func copyUnknownLength(destination, source []int) {
    go func() { destination[0] = 2 }()
    copy(destination, source)
}

func arrayCopy() {
    var a [4]int
    b := a
    go func() { b[0] = 1 }()
    go func() { a[0] = 2 }()
}

func structValueCopy() {
    v := valueWrap{}
    w := v
    go func() { w.c.n = 1 }()
    go func() { v.c.n = 2 }()
}

func structPointerFieldCopy() {
    c := &cell{}
    v := wrap{c: c}
    w := v
    go func() { w.c.n = 1 }()
    go func() { v.c.n = 2 }()
}

func structPointerFieldCopyChain() {
    c := &cell{}
    v := wrap{c: c}
    w := v
    x := w
    go func() { x.c.n = 1 }()
    go func() { v.c.n = 2 }()
}

func structPointerFieldReplacedAfterCopy() {
    c := &cell{}
    v := wrap{c: c}
    w := v
    w.c = &cell{}
    go func() { w.c.n = 1 }()
    go func() { v.c.n = 2 }()
}

func structPointerFieldSourceReplacedAfterCopy() {
    c := &cell{}
    v := wrap{c: c}
    w := v
    v.c = &cell{}
    go func() { w.c.n = 1 }()
    go func() { v.c.n = 2 }()
}

func arrayPointerElementCopy() {
    c := &cell{}
    var v [1]*cell
    v[0] = c
    w := v
    go func() { w[0].n = 1 }()
    go func() { v[0].n = 2 }()
}

func arrayPointerElementCopyChain() {
    c := &cell{}
    var v [1]*cell
    v[0] = c
    x := v
    w := x
    go func() { w[0].n = 1 }()
    go func() { v[0].n = 2 }()
}

func arrayPointerElementCompositeLiteral() {
    c := &cell{}
    v := [1]*cell{c}
    w := v
    go func() { w[0].n = 1 }()
    go func() { v[0].n = 2 }()
}

func arrayPointerElementKeyedCompositeLiteral() {
    c := &cell{}
    v := [3]*cell{2: c}
    w := v
    go func() { w[2].n = 1 }()
    go func() { v[2].n = 2 }()
}

func arrayValueCompositeLiteralCopy() {
    v := [1]cell{{}}
    w := v
    go func() { w[0].n = 1 }()
    go func() { v[0].n = 2 }()
}

func arrayPointerElementConstLengthLiteral() {
    const length = 1
    c := &cell{}
    v := [length]*cell{c}
    w := v
    go func() { w[0].n = 1 }()
    go func() { v[0].n = 2 }()
}

func arrayPointerElementsStayDistinct() {
    a := &cell{}
    b := &cell{}
    var left [1]*cell
    left[0] = a
    leftCopy := left
    var right [1]*cell
    right[0] = b
    rightCopy := right
    go func() { leftCopy[0].n = 1 }()
    go func() { rightCopy[0].n = 2 }()
}

func arrayPointerElementReplacedAfterCopy() {
    original := &cell{}
    replacement := &cell{}
    var v [1]*cell
    v[0] = original
    w := v
    w[0] = replacement
    go func() { w[0].n = 1 }()
    go func() { original.n = 2 }()
}

func arrayPointerElementSourceReplacedAfterCopy() {
    original := &cell{}
    replacement := &cell{}
    var v [1]*cell
    v[0] = original
    w := v
    v[0] = replacement
    go func() { w[0].n = 1 }()
    go func() { replacement.n = 2 }()
}

func channelPublish() {
    ch := make(chan *cell, 1)
    c := &cell{}
    ch <- c
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func channelDescriptorCopy() {
    ch := make(chan *cell, 1)
    copy := ch
    c := &cell{}
    ch <- c
    go func() {
        got := <-copy
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func sendCell(ch chan *cell, c *cell) { ch <- c }
func receiveCell(ch chan *cell) {
    got := <-ch
    got.n = 1
}
func channelHelperPayload() {
    ch := make(chan *cell, 1)
    c := &cell{}
    sendCell(ch, c)
    go receiveCell(ch)
    go func() { c.n = 2 }()
}

func sendCellValue(ch chan cell, c cell) { ch <- c }
func receiveCellValue(ch chan cell) {
    got := <-ch
    got.n = 1
}
func channelHelperValueCopy() {
    ch := make(chan cell, 1)
    c := cell{}
    sendCellValue(ch, c)
    go receiveCellValue(ch)
    go func() { c.n = 2 }()
}

func receiveCellReplacement(ch, replacement chan *cell) {
    ch = replacement
    got := <-ch
    got.n = 1
}
func channelReassignedHelper() {
    original := make(chan *cell, 1)
    replacement := make(chan *cell, 1)
    first := &cell{}
    second := &cell{}
    original <- first
    replacement <- second
    go receiveCellReplacement(original, replacement)
    go func() { first.n = 2 }()
}

func channelSlicePublish() {
    ch := make(chan []int, 1)
    values := make([]int, 1)
    ch <- values
    go func() {
        got := <-ch
        got[0] = 1
    }()
    go func() { values[0] = 2 }()
}

func channelMapPublish() {
    ch := make(chan map[int]int, 1)
    values := make(map[int]int)
    ch <- values
    go func() {
        got := <-ch
        got[0] = 1
    }()
    go func() { values[0] = 2 }()
}

func channelStructValueCopy() {
    ch := make(chan cell, 1)
    c := cell{}
    ch <- c
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func channelMultipleSends() {
    ch := make(chan *cell, 2)
    first := &cell{}
    second := &cell{}
    ch <- first
    ch <- second
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { second.n = 2 }()
}

func channelInterfacePayload() {
    ch := make(chan any, 1)
    c := &cell{}
    ch <- c
    go func() {
        got := (<-ch).(*cell)
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func channelParameterPayload(ch chan *cell) {
    c := &cell{}
    ch <- c
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func channelLoopSend() {
    ch := make(chan *cell, 1)
    c := &cell{}
    for i := 0; i < 1; i++ {
        ch <- c
    }
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func channelCloseAlternative() {
    ch := make(chan *cell, 1)
    c := &cell{}
    ch <- c
    close(ch)
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { c.n = 2 }()
}

func channelTupleAlias() {
    ch := make(chan *cell, 2)
    var alias chan *cell
    ignored := 0
    alias, ignored = ch, ignored
    first := &cell{}
    second := &cell{}
    alias <- first
    ch <- second
    go func() {
        got := <-ch
        got.n = 1
    }()
    go func() { second.n = 2 }()
}

func channelSliceOffset() {
    ch := make(chan []int, 1)
    values := make([]int, 2)
    tail := values[1:]
    ch <- tail
    go func() {
        got := <-ch
        got[0] = 1
    }()
    go func() { values[0] = 2 }()
}

type channelSliceHolder struct {
    values []int
}

func channelFieldSliceOffset() {
    ch := make(chan []int, 1)
    values := make([]int, 2)
    holder := channelSliceHolder{values: values[1:]}
    ch <- holder.values
    go func() {
        got := <-ch
        got[0] = 1
    }()
    go func() { values[0] = 2 }()
}

func channelDistinctBackingStore() {
    ch := make(chan []int, 1)
    first := make([]int, 1)
    second := make([]int, 1)
    ch <- first
    go func() {
        got := <-ch
        got[0] = 1
    }()
    go func() { second[0] = 2 }()
}

"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    (project, workspace)
}

/// A reassigned formal must not manufacture shared storage from conflicting
/// caller and callee allocation identities. Until assignment states are
/// separated, this route is explicitly incomplete rather than a proven race.
#[test]
fn go_reassigned_parameter_does_not_fabricate_shared_identity() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type counters struct {
    total int
}

type inner struct {
    counters counters
}

type holder struct {
    inner *inner
}

func (holding *holder) bumpReassigned(other *holder) {
    other = &holder{inner: &inner{}}
    other.inner.counters.total++
}

func repeatedReassignedParameter() {
    holding := &holder{inner: &inner{}}
    for index := 0; index < 2; index++ {
        go holding.bumpReassigned(holding)
    }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "repeatedReassignedParameter" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("reassigned parameter concurrent access query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let reported = result
        .results
        .iter()
        .filter(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.verdict == "conflict" && value.proof == "proven"
            )
        })
        .count();
    assert_eq!(
        reported, 0,
        "each instance allocates its own holder, so the write is task-local: {result:#?}"
    );
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
                && diagnostic.message.contains("UnknownLocation")
        }),
        "conflicting identity evidence must not become a complete empty answer: {result:#?}"
    );
}

/// A direct sibling race is the control for invocation-sensitive task identity.
#[test]
fn go_concurrent_access_conflicts_preserve_direct_sibling_control() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "directSameCell");
    assert_proven_exhaustive_sibling_conflicts(&result, 3);
}

/// A formal pair has no caller binding when the queried procedure is the root.
/// The solver must retain that missing identity as explicit open evidence rather
/// than silently returning a clean empty answer.
#[test]
fn go_concurrent_access_conflicts_keep_unbound_formals_open() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "inputs");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

/// Rebinding the same allocation to both pointer formals must preserve one
/// proven location across the two sibling children.
#[test]
fn go_concurrent_access_conflicts_project_same_pointer_formals() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "sameInput");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "same pointer actuals must retain their proven race",
    );
}

/// Distinct pointer actuals passed to one helper remain disjoint with complete
/// coverage and no hidden identity diagnostic.
#[test]
fn go_concurrent_access_conflicts_keep_distinct_pointer_formals_disjoint() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "differentInput");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "distinct pointer actuals must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "distinct pointer actuals must not hide an identity diagnostic: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);
}

/// Exact initializer payloads distinguish shared from independent pointees.
/// Unbound holder inputs still need explicit identity uncertainty.
#[test]
fn go_concurrent_access_conflicts_distinguish_holder_payloads() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let unknown = go_invocation_conflicts(&workspace, "holderInputs");
    assert_no_proven_conflicts_with_explicit_evidence(&unknown);

    let shared = go_invocation_conflicts(&workspace, "samePointeeInDifferentHolders");
    assert_proven_unordered_unprotected_conflict(&shared, "samePointeeInDifferentHolders");
    let distinct = go_invocation_conflicts(&workspace, "distinctPointeesInDifferentHolders");
    assert_no_proven_conflicts_with_explanation(&distinct);
    assert_eq!(distinct.completion(), CodeQueryCompletion::Complete);

    for result in [&shared, &distinct] {
        let mut initializers = 0;
        for item in &result.results {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("expected a concurrent-access relation: {item:#?}");
            };
            if value.first_procedure_id == value.root_procedure_id {
                initializers += 1;
                assert_eq!(
                    (value.ordering, value.verdict, value.proof),
                    ("happens_before", "ordered", "proven"),
                    "holder initialization precedes its child's field load: {result:#?}"
                );
            } else if value.verdict == "conflict" {
                assert_eq!(value.first_access, "write");
                assert_eq!(value.second_access, "write");
                assert_eq!(value.task_relation, "siblings");
            }
        }
        assert_eq!(
            initializers, 2,
            "both holder initializers remain visible: {result:#?}"
        );
    }
}

#[test]
fn go_concurrent_access_conflicts_do_not_prove_nil_holder_field_payloads() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in [
        "nilHolderFieldPayload",
        "explicitNilHolderFieldPayload",
        "overwrittenHolderFieldPayload",
        "nestedNilHolderFieldPayload",
        "storedNilHolderFieldPayload",
        "zeroHolderFieldPayload",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
}

#[test]
fn go_concurrent_access_conflicts_preserve_initialized_holder_field_payloads() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in ["sharedHolderFieldPayload", "assignedHolderFieldPayload"] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_proven_unordered_unprotected_conflict(&result, root);
    }
}

#[test]
fn go_concurrent_access_conflicts_do_not_prove_cleared_holder_field_payloads() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in [
        "capturedNilHolderFieldPayload",
        "copiedNilHolderFieldPayload",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
}

#[test]
fn go_concurrent_access_conflicts_keep_uncertain_holder_field_payloads_open() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in [
        "conditionalHolderFieldPayload",
        "opaqueHolderFieldPayload",
        "escapedHolderFieldPayload",
        "escapedCallbackHolderFieldPayload",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
}

/// A closure initializes a fresh holder once and is then published through a
/// package-level function value. Its captured field may be mutated by a later
/// invocation that the local query cannot account for, so the child accesses
/// must remain explicitly incomplete rather than inheriting one singleton
/// payload identity.
#[test]
fn go_concurrent_access_conflicts_keep_published_holder_initializer_open() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in [
        "publishedHolderInitializer",
        "publishedHolderInitializerThroughCaptureCell",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
}

/// Each repeated child invokes a helper that allocates both its holder and
/// pointer payload. The helper's allocation snapshot is per activation and
/// must not become a shared cross-activation field identity.
#[test]
fn go_concurrent_access_conflicts_keep_repeated_fresh_holder_helpers_disjoint() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in [
        "repeatedFreshHolderHelpers",
        "repeatedFreshPublishedFieldArguments",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
}

#[test]
fn go_concurrent_access_conflicts_order_conditional_write_before_spawn() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "conditionalWriteBeforeSpawn");
    assert_exact_safe_concurrent_relations(&result, "ordered");
}

#[test]
fn go_concurrent_access_conflicts_prove_conditional_write_after_spawn() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "conditionalWriteAfterSpawn");
    assert_proven_unordered_unprotected_conflict(&result, "conditional write after spawn");
}

/// Separate inline struct values have disjoint direct field storage, even
/// though both accesses use the same field selector.
#[test]
fn go_concurrent_access_conflicts_keep_distinct_inline_struct_fields_disjoint() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "distinctInlineStructFields");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "distinct inline struct fields must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "distinct inline struct fields must not hide an identity diagnostic: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);
}

/// Two synchronous calls to one helper launch two children that receive the
/// same pointer actual. Their accesses must retain the caller's allocation
/// identity through each invocation boundary.
#[test]
fn go_concurrent_access_conflicts_project_same_pointer_through_helper_invocations() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "sameCellThroughHelperCalls");
    // Both activations use the same source sites, so the two read/write
    // orientations project to one row, alongside the write/write row.
    assert_proven_exhaustive_sibling_conflicts(&result, 2);
}

/// Distinct pointer actuals passed through the same helper remain disjoint,
/// and the complete answer has no hidden identity diagnostic.
#[test]
fn go_concurrent_access_conflicts_keep_distinct_helper_actuals_complete() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "distinctPointerActuals");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "distinct helper actuals must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "disjoint helper actuals must not hide an identity diagnostic: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);
}

/// A helper that calls the same launcher from mutually exclusive branches
/// creates at most one child per invocation. Expanding both branch calls must
/// not manufacture a proven sibling race. If the branch proof is incomplete,
/// the result must say so explicitly.
#[test]
fn go_concurrent_access_conflicts_do_not_compare_mutually_exclusive_launcher_calls() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "conditionalAtMostOne");
    for item in &result.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        assert!(
            !(value.verdict == "conflict" && value.proof == "proven"),
            "mutually exclusive launcher branches cannot prove a sibling race: {result:#?}"
        );
        if value.proof != "proven" {
            assert!(
                !value.reasons.is_empty(),
                "an unproven conditional relation must retain an explicit reason: {result:#?}"
            );
        }
    }
    if result.results.is_empty() {
        assert!(
            result.completion() == CodeQueryCompletion::Complete || !result.diagnostics.is_empty(),
            "an empty conditional result needs complete coverage or an explicit diagnostic: {result:#?}"
        );
    } else if result.completion() != CodeQueryCompletion::Complete {
        assert!(
            !result.diagnostics.is_empty(),
            "an incomplete conditional result must retain its diagnostic: {result:#?}"
        );
    }
}

/// Calls with no shared input allocate their task-local object inside each
/// helper activation. The two child tasks must remain disjoint.
#[test]
fn go_concurrent_access_conflicts_keep_helper_local_allocations_disjoint() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "independentLocalInvocations");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "task-local helper allocations must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "task-local helper allocations must not hide an identity diagnostic: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);
}

/// Two synchronous helper invocations each launch a child and wait for it to
/// close its local channel. The shared pointer is reused safely because the
/// first child completes before the second invocation starts.
#[test]
fn go_concurrent_access_conflicts_keep_joined_helper_invocations_ordered() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "joinedHelperInvocations");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// Repeating the joined helper in a loop still completes each child before
/// the next invocation, so the shared pointer must not be reported as a race.
#[test]
fn go_concurrent_access_conflicts_keep_looped_joined_helper_invocations_ordered() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedJoinedHelperInvocations");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// A conditional receive does not establish a mandatory join. With an
/// unknown condition, the two helper invocations must retain a proven race.
#[test]
fn go_concurrent_access_conflicts_do_not_make_conditional_wait_mandatory() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "conditionalWaitHelperInvocations");
    let value = find_concurrent_relation(&result, |value| {
        value.verdict == "conflict" && value.proof == "proven"
    });
    assert_eq!(
        (value.ordering, value.protection, value.proof),
        ("unordered", "unprotected", "proven"),
        "conditional wait must leave an unprotected race: {result:#?}"
    );
}

/// Two parallel parent task activations each run joined children. The local
/// joins order accesses within a parent, but cannot order the two parents.
#[test]
fn go_concurrent_access_conflicts_keep_parallel_joined_parent_race() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "parallelJoinedParentTasks");
    let value = find_concurrent_relation(&result, |value| {
        value.verdict == "conflict" && value.proof == "proven"
    });
    assert_eq!(
        (value.ordering, value.protection, value.proof),
        ("unordered", "unprotected", "proven"),
        "parallel parent activations must retain their race: {result:#?}"
    );
}

/// Repeating a helper that allocates its object inside the helper must not
/// collapse those per-invocation allocations into one shared location.
#[test]
fn go_concurrent_access_conflicts_keep_looped_helper_locals_disjoint() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedLocalHelperInvocations");
    assert_no_proven_conflicts_with_explanation(&result);
}

/// Repeating a helper with one external pointer actual must keep that actual's
/// identity across every invocation, so the repeated children still race.
#[test]
fn go_concurrent_access_conflicts_keep_looped_shared_helper_race() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedSharedHelperInvocations");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "repeated shared helper query must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "repeated shared helper race must not retain identity diagnostics: {result:#?}"
    );
    let conflicts = result
        .results
        .iter()
        .filter_map(|item| {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
            };
            (value.verdict == "conflict").then_some(value)
        })
        .collect::<Vec<_>>();
    assert!(
        !conflicts.is_empty(),
        "repeated shared helper calls must retain a proven race: {result:#?}"
    );
    for value in conflicts {
        assert_eq!(
            (
                value.ordering,
                value.protection,
                value.proof,
                value.coverage
            ),
            ("unordered", "unprotected", "proven", "exhaustive"),
            "repeated shared helper conflicts must remain proven: {result:#?}"
        );
    }
}

/// A dynamic slice index has a known backing store but no exact element
/// identity. Repetition must keep that uncertainty visible even for one static
/// write, where only the self-comparison path can discover a repeated conflict.
#[test]
fn go_concurrent_access_conflicts_keep_repeated_unknown_index_routes_open() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "repeatedUnknownIndexOneWrite");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_concurrent_access_conflicts_keep_repeated_unknown_index_pairs_open() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "repeatedUnknownIndexTwoWrites");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
    let value = find_concurrent_relation(&result, |value| {
        value.location_kind == "index"
            && value.first_point_id != value.second_point_id
            && value.first_access == "write"
            && value.second_access == "write"
            && value.proof == "open"
            && value.coverage == "open"
    });
    assert!(
        value
            .reasons
            .iter()
            .any(|reason| reason == "unknown_location")
    );
}

/// A constant element of one slice remains one location across repeated child
/// instances. This is the positive control for the open dynamic-index routes.
#[test]
fn go_concurrent_access_conflicts_prove_repeated_constant_index_shared_slice_race() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "repeatedConstantIndexSharedSlice");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "a repeated constant-index write to one shared slice must race",
    );
}

/// A slice allocated inside each child has a distinct backing allocation,
/// even when its selected index is unknown. Keep this negative
/// complete so an allocation-context mistake cannot hide behind open evidence.
#[test]
fn go_concurrent_access_conflicts_keep_repeated_fresh_index_storage_complete() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "repeatedFreshIndexStorage");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "fresh repeated slice allocations must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "fresh repeated slice allocations must not hide an identity diagnostic: {result:#?}"
    );
    assert_no_concurrent_conflicts(&result);
}

/// A repeated worker sends its fresh cell before receiving from a two-slot
/// channel. The receive may obtain another worker's published cell, but that
/// payload identity is unresolved, so the local.n/got.n write pair stays open.
#[test]
fn go_concurrent_access_conflicts_keep_repeated_channel_publication_open() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "repeatedPublishedWorkers");
    assert_no_proven_conflicts_with_explanation(&result);
    let value = find_concurrent_relation(&result, |value| {
        value.verdict == "conflict"
            && value.task_relation == "repeated"
            && value.first_procedure_id == value.second_procedure_id
            && value.first_point_id != value.second_point_id
            && value.first_access == "write"
            && value.second_access == "write"
            && value.location_kind == "field"
            && value.proof == "open"
            && value.coverage == "open"
    });
    assert!(
        value
            .reasons
            .iter()
            .any(|reason| reason == "unknown_location"),
        "the local.n/got.n publication pair must retain unknown identity evidence: {result:#?}"
    );
}

/// An unjoined child from an earlier helper invocation can overlap the next
/// invocation's synchronous write through the shared pointer actual.
#[test]
fn go_concurrent_access_conflicts_keep_looped_unjoined_helper_race() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result =
        go_invocation_conflicts(&workspace, "loopedUnjoinedWriteThenReadHelperInvocations");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "looped unjoined helper invocations must retain their race",
    );
}

/// A mandatory receive completes each helper child before the next helper
/// invocation writes through the shared pointer actual.
#[test]
fn go_concurrent_access_conflicts_keep_looped_joined_helper_safe() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedJoinedWriteThenReadHelperInvocations");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// The direct loop has the same unjoined ordering boundary without an
/// invocation edge, so an earlier child can race with a later loop write.
#[test]
fn go_concurrent_access_conflicts_keep_looped_unjoined_direct_race() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedUnjoinedWriteThenReadDirectly");
    assert_proven_unordered_unprotected_conflict(
        &result,
        "looped unjoined direct accesses must retain their race",
    );
}

/// A mandatory receive in each direct loop iteration orders the child read
/// before the next write.
#[test]
fn go_concurrent_access_conflicts_keep_looped_joined_direct_safe() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedJoinedWriteThenReadDirectly");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// Parallel parents each allocate their own cell. Their unjoined children are
/// therefore disjoint despite the repeated parent task shape.
#[test]
fn go_concurrent_access_conflicts_keep_parallel_fresh_parent_tasks_safe() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "parallelFreshReadParentTasks");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// Each loop iteration allocates its own cell before launching its child. The
/// repeated allocation site must not make those distinct cells appear shared.
#[test]
fn go_concurrent_access_conflicts_keep_looped_fresh_direct_allocations_safe() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedFreshDirectAllocations");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// Each repeated helper activation allocates its cell locally before launching
/// its child. Per-activation allocations must remain disjoint.
#[test]
fn go_concurrent_access_conflicts_keep_looped_fresh_helper_allocations_safe() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedFreshHelperAllocations");
    assert_no_proven_unordered_unprotected_conflicts(&result);
}

/// Loop-declared lexical cells have one instance per iteration, while a
/// lexical cell declared outside the loop is shared by every child closure.
/// Keep the negative explicit when the distinct-cell proof is incomplete and
/// keep both access orientations of the shared-cell race exact.
#[test]
fn go_concurrent_access_conflicts_distinguish_loop_lexical_cells() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in [
        "freshLexicalCells",
        "freshVarLexicalCells",
        "freshRangeCells",
    ] {
        let fresh = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&fresh);
        assert!(
            fresh.results.iter().any(|item| matches!(
                &item.value,
                CodeQueryResultValue::ConcurrentAccessConflict { value }
                    if value.proof == "open"
                        && value.reasons.iter().any(|reason| reason == "unknown_location")
            )),
            "iteration-to-cell correspondence is still unresolved and must stay visible: {fresh:#?}"
        );
    }

    let unknown = go_invocation_conflicts(&workspace, "gotoLexicalCells");
    assert_no_proven_conflicts_with_explanation(&unknown);
    assert!(
        unknown
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("UnknownLocation")),
        "unavailable cell lifetime must remain incomplete even without a repeated-task row: {unknown:#?}"
    );

    for root in ["sharedLexicalCell", "sharedRangeCell"] {
        let shared = go_invocation_conflicts(&workspace, root);
        let conflicts = shared
            .results
            .iter()
            .filter_map(|item| {
                let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                    panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
                };
                (value.verdict == "conflict").then_some(value.as_ref())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            conflicts.len(),
            2,
            "shared lexical cell must retain both access orientations: {shared:#?}"
        );
        for value in conflicts {
            assert_eq!(
                (
                    value.task_relation,
                    value.location_kind.as_str(),
                    value.ordering,
                    value.protection,
                    value.proof,
                    value.coverage,
                ),
                (
                    "repeated",
                    "lexical_cell",
                    "unordered",
                    "unprotected",
                    "proven",
                    "exhaustive",
                ),
                "shared lexical cell conflict must remain proven and exhaustive: {shared:#?}"
            );
        }
    }
}

/// A holder value is recreated on every loop iteration. Its fresh pointer
/// payload must not be promoted to a proven cross-iteration race, whether the
/// holder is anonymous or named. If the analyzer cannot establish disjoint
/// payloads, it must retain an open relation or diagnostic.
#[test]
fn go_concurrent_access_conflicts_keep_loop_holder_pointer_origins_precise() {
    let (_project, workspace) = go_invocation_identity_workspace();
    for root in ["freshAnonymousHolderPointer", "freshNamedHolderPointer"] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
        assert_conflict_or_explicit_open(&result);
    }

    // These controls use one external pointee through separately-created
    // holder values. The composite initializer's payload identity is not yet
    // modeled, so this accepts a retained proven conflict or explicit open
    // evidence; a clean empty result would hide the unresolved route. Existing
    // composed-path positives are not certification for this initializer path.
    for root in ["sharedAnonymousHolderPointer", "sharedNamedHolderPointer"] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_conflict_or_explicit_open(&result);
    }
}

/// A reference payload of a fresh helper-local holder may itself be shared
/// or fresh. Its unresolved origin cannot inherit the container's lifetime.
#[test]
fn go_concurrent_access_conflicts_keep_helper_holder_pointer_origins_precise() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let fresh = go_invocation_conflicts(&workspace, "freshHelperHolderPointer");
    assert_no_proven_conflicts_with_explanation(&fresh);
    assert_conflict_or_explicit_open(&fresh);
    let shared = go_invocation_conflicts(&workspace, "sharedHelperHolderPointer");
    assert_conflict_or_explicit_open(&shared);
}

/// Nested value-field projection must preserve allocation origin through a
/// helper boundary. Fresh helper allocations stay disjoint or explicitly
/// open, while a shared nestedCell actual retains a proven conflict.
#[test]
fn go_concurrent_access_conflicts_keep_nested_helper_allocation_origins() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let fresh = go_invocation_conflicts(&workspace, "loopedNestedLocalHelpers");
    assert_no_proven_conflicts_with_explanation(&fresh);

    let shared = go_invocation_conflicts(&workspace, "loopedNestedSharedHelpers");
    assert_proven_unordered_unprotected_conflict(
        &shared,
        "a shared nestedCell actual must retain its helper race",
    );
}

/// A channel receive joins one parent activation. With two repeated parents
/// sharing the cell, a child read from one activation remains unordered with
/// the post-wait write in the other activation.
#[test]
fn go_concurrent_access_conflicts_do_not_cross_activation_channel_join() {
    let (_project, workspace) = go_invocation_identity_workspace();
    let result = go_invocation_conflicts(&workspace, "loopedChannelJoinParentTasks");
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "repeated channel-join parents must resolve completely: {result:#?}"
    );
    let relation = result
        .results
        .iter()
        .filter_map(|item| {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
            };
            let read_write = value.first_access != value.second_access
                && matches!(value.first_access, "read" | "write")
                && matches!(value.second_access, "read" | "write");
            (read_write && value.task_relation == "repeated"
                && value.first_procedure_id != value.second_procedure_id
                && value.location_kind == "field").then_some(value.as_ref())
        })
        .find(|value| value.ordering != "happens_before")
        .unwrap_or_else(|| {
            panic!(
                "a repeated cross-activation read/write relation must not be proven ordered: {result:#?}"
            )
        });
    assert_ne!(
        relation.ordering, "happens_before",
        "a channel join cannot order two repeated parent activations: {result:#?}"
    );
    if relation.ordering == "open" {
        assert!(
            !relation.reasons.is_empty(),
            "open ordering retains its reason: {result:#?}"
        );
    }
    let fresh = go_invocation_conflicts(&workspace, "loopedFreshChannelJoinParentTasks");
    assert_no_proven_unordered_unprotected_conflicts(&fresh);
}

fn assert_no_proven_unordered_unprotected_conflicts(result: &CodeQueryResult) {
    for item in &result.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        if value.verdict == "conflict"
            && value.ordering == "unordered"
            && value.protection == "unprotected"
        {
            assert_ne!(
                value.proof, "proven",
                "joined helper calls must not prove an unordered unprotected conflict: {result:#?}"
            );
            assert!(
                !value.reasons.is_empty(),
                "an unresolved joined conflict must retain an explicit reason: {result:#?}"
            );
        }
    }
    if result.completion() != CodeQueryCompletion::Complete {
        assert!(
            !result.diagnostics.is_empty(),
            "an incomplete joined helper result must retain its diagnostic: {result:#?}"
        );
    }
}

fn assert_proven_unordered_unprotected_conflict(result: &CodeQueryResult, message: &str) {
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{message}: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "{message} must not retain identity diagnostics: {result:#?}"
    );
    let value = find_concurrent_relation(result, |value| value.verdict == "conflict");
    assert_eq!(
        (value.ordering, value.protection, value.proof),
        ("unordered", "unprotected", "proven"),
        "{message}: {result:#?}"
    );
}

fn assert_conflict_or_explicit_open(result: &CodeQueryResult) {
    let retained = result.results.iter().any(|item| {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        value.verdict == "conflict" || (value.proof == "open" && !value.reasons.is_empty())
    });
    assert!(
        retained || !result.diagnostics.is_empty(),
        "a potentially shared access must retain a conflict or explicit open evidence: {result:#?}"
    );
}

#[test]
fn go_recursive_detached_slices_preserve_identity_and_open_effects() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct { n int }
func shared(p *cell) { p.n++; go shared(p) }
func fresh(p *cell) { p.n++; go fresh(&cell{}) }
func copied(c cell) { c.n++; go copied(c) }
func write(p *cell) { p.n++ }
func sharedRoot() { p := &cell{}; go shared(p); go shared(p) }
func freshRoot() { go fresh(&cell{}); go fresh(&cell{}) }
func copiedRoot() { c := cell{}; go copied(c); go copied(c) }
func directRoot() { p := &cell{}; go write(p); go write(p) }

func relay(start, finish chan struct{}, depth int) {
    if depth > 0 { go relay(start, finish, depth - 1); return }
    <-start
    close(finish)
}
func recursiveJoin() {
    n := 0
    start := make(chan struct{})
    finish := make(chan struct{})
    go func() { n = 1; close(start) }()
    go relay(start, finish, 5)
    go func() { <-finish; n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let shared = go_invocation_conflicts(&workspace, "sharedRoot");
    assert_conflict_or_explicit_open(&shared);
    assert!(
        !shared.results.is_empty(),
        "shared object must retain candidate pairs: {shared:#?}"
    );
    for root in ["sharedRoot", "freshRoot", "copiedRoot", "recursiveJoin"] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_ne!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{root}: {result:#?}"
        );
        assert!(!result.diagnostics.is_empty(), "{root}: {result:#?}");
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code
                    != CodeQueryDiagnosticCode::SemanticBudgetExhausted),
            "{root}: {result:#?}"
        );
        for item in &result.results {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("typed concurrency row: {item:#?}");
            };
            assert_eq!(value.proof, "open", "{root}: {result:#?}");
            assert!(
                value
                    .reasons
                    .iter()
                    .any(|reason| reason == "recursive_expansion"),
                "{root}: {result:#?}"
            );
        }
        if root == "freshRoot" {
            assert!(
                result.results.is_empty(),
                "distinct allocations must not acquire shared identity: {result:#?}"
            );
        }
    }
    let direct = go_invocation_conflicts(&workspace, "directRoot");
    assert_proven_unordered_unprotected_conflict(
        &direct,
        "independent sibling calls remain analyzed",
    );
}

#[test]
fn go_concurrent_access_conflicts_keep_competing_channel_senders_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

// The first receive is guaranteed to consume senderTwo. senderOne's n=1
// write happens before its release receive, but its send happens only after
// the receiver has written n=2. The two writes are therefore unordered.
func competingRoot() {
	ch := make(chan struct{})
	gate := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	n := 0

	go func() {
		n = 1
		<-release
		ch <- struct{}{}
	}()

	go func() {
		<-gate
		ch <- struct{}{}
	}()

	go func() {
		close(gate)
		<-ch
		n = 2
		close(release)
		<-ch
		close(done)
	}()

	<-done
	_ = n
}

// With one sender, the channel rendezvous orders n=1 before n=2. The sender
// completion signal also makes the final root read a direct join of the
// sender, rather than depending on a transitive channel proof.
func singleRoot() {
	ch := make(chan struct{})
	doneSender := make(chan struct{})
	doneReceiver := make(chan struct{})
	n := 0

	go func() {
		n = 1
		ch <- struct{}{}
		close(doneSender)
	}()

	go func() {
		<-ch
		n = 2
		close(doneReceiver)
	}()

	<-doneSender
	<-doneReceiver
	_ = n
}

// The capacity-two buffer permits the receiver to consume either sender's
// value. Both sends complete before the closer closes the channel.
func bufferedCompetingRoot() {
	ch := make(chan struct{}, 2)
	sentOne := make(chan struct{})
	sentTwo := make(chan struct{})
	closed := make(chan struct{})
	done := make(chan struct{})
	n := 0

	go func() {
		n = 1
		ch <- struct{}{}
		close(sentOne)
	}()

	go func() {
		ch <- struct{}{}
		close(sentTwo)
	}()

	go func() {
		<-sentOne
		<-sentTwo
		close(ch)
		close(closed)
	}()

	go func() {
		<-ch
		n = 2
		<-ch
		close(done)
	}()

	<-done
	<-closed
	_ = n
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    for root in ["competingRoot", "bufferedCompetingRoot"] {
        let result = go_invocation_conflicts(&workspace, root);
        let pair = find_concurrent_relation(&result, |value| {
            value.task_relation == "siblings"
                && value.first_access == "write"
                && value.second_access == "write"
        });
        assert_eq!(
            (pair.first_access, pair.second_access),
            ("write", "write"),
            "the retained {root} relation is the write pair: {result:#?}"
        );
        assert_eq!(
            (pair.ordering, pair.proof, pair.coverage),
            ("open", "open", "open"),
            "a competing sender cannot prove the sibling write ordering: {result:#?}"
        );
        assert!(
            pair.reasons
                .iter()
                .any(|reason| reason == "ambiguous_synchronization"),
            "the competing channel route retains its ambiguity reason: {result:#?}"
        );
    }

    let control = go_invocation_conflicts(&workspace, "singleRoot");
    assert_eq!(
        control.completion(),
        CodeQueryCompletion::Complete,
        "single sender control resolves completely: {control:#?}"
    );
    assert!(
        control.diagnostics.is_empty(),
        "single sender control has no diagnostics: {control:#?}"
    );
    let mut has_final_root_read = false;
    assert!(
        !control.results.is_empty(),
        "single sender control retains its access relations: {control:#?}"
    );
    for item in &control.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("singleRoot returned a non-concurrency row: {item:#?}");
        };
        has_final_root_read |= value.first_access == "read" || value.second_access == "read";
        assert_eq!(
            (value.ordering, value.proof, value.coverage),
            ("happens_before", "proven", "exhaustive"),
            "single sender control must prove every relation: {control:#?}"
        );
    }
    assert!(
        has_final_root_read,
        "single sender control includes the final root read: {control:#?}"
    );
}

#[test]
fn go_synchronous_recursive_relay_keeps_conflict_proof_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
func relay(start, finish chan struct{}, depth int) {
    if depth > 0 { relay(start, finish, depth - 1); return }
    <-start
    close(finish)
}
func directRelay(start, finish chan struct{}) { <-start; close(finish) }
func recursiveRoot() {
    n := 0
    start := make(chan struct{})
    finish := make(chan struct{})
    done := make(chan struct{})
    go func() { n = 1; close(start) }()
    go relay(start, finish, 5)
    go func() { <-finish; n = 2; close(done) }()
    <-done
    _ = n
}
func directRoot() {
    n := 0
    start := make(chan struct{})
    finish := make(chan struct{})
    done := make(chan struct{})
    go func() { n = 1; close(start) }()
    go directRelay(start, finish)
    go func() { <-finish; n = 2; close(done) }()
    <-done
    _ = n
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let recursive = go_invocation_conflicts(&workspace, "recursiveRoot");
    assert_ne!(recursive.completion(), CodeQueryCompletion::Complete);
    assert!(!recursive.diagnostics.is_empty(), "{recursive:#?}");
    assert!(
        recursive.results.iter().any(|item| {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("typed concurrency row: {item:#?}");
            };
            value.first_access == "write"
                && value.second_access == "write"
                && value.first_procedure_id != value.root_procedure_id
                && value.second_procedure_id != value.root_procedure_id
        }),
        "the omitted relay must retain the uncertain write pair: {recursive:#?}"
    );
    for item in &recursive.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("typed concurrency row: {item:#?}");
        };
        assert_eq!(value.proof, "open", "{recursive:#?}");
        assert_eq!(value.coverage, "open", "{recursive:#?}");
        assert!(
            value
                .reasons
                .iter()
                .any(|reason| reason == "recursive_expansion"),
            "a report-level warning cannot qualify an omitted synchronization path: {recursive:#?}"
        );
    }
    let direct = go_invocation_conflicts(&workspace, "directRoot");
    assert_eq!(
        direct.completion(),
        CodeQueryCompletion::Complete,
        "{direct:#?}"
    );
    assert!(!direct.results.is_empty(), "{direct:#?}");
    for item in &direct.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("typed concurrency row: {item:#?}");
        };
        assert_eq!(value.proof, "proven", "{direct:#?}");
        assert_eq!(value.coverage, "exhaustive", "{direct:#?}");
        assert_eq!(value.ordering, "happens_before", "{direct:#?}");
    }
}

#[test]
fn go_recursive_channel_payload_proves_exact_countdown() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }
func recursiveSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { recursiveSend(ch, c, depth - 1); return }
    ch <- c
}
func recursiveSendValue(ch chan cell, c cell, depth int) {
    if depth > 0 { recursiveSendValue(ch, c, depth - 1); return }
    ch <- c
}
func pointerRoot() {
    ch := make(chan *cell)
    c := &cell{}
    go recursiveSend(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func valueRoot() {
    ch := make(chan cell)
    c := cell{}
    go recursiveSendValue(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let pointer = go_invocation_conflicts(&workspace, "pointerRoot");
    let value = go_invocation_conflicts(&workspace, "valueRoot");
    assert_proven_exhaustive_sibling_conflicts(&pointer, 1);
    assert_no_proven_conflicts_with_explicit_evidence(&value);
    assert!(
        value
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("RecursiveExpansion")),
        "distinct copied field storage must not hide incomplete recursive coverage: {value:#?}"
    );
}

#[test]
fn go_recursive_channel_cardinality_controls_remain_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }

func unknownSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { unknownSend(ch, c, depth - 1); return }
    ch <- c
}
func nondecreasingSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { nondecreasingSend(ch, c, depth); return }
    ch <- c
}
func mutableSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { depth = depth - 1; mutableSend(ch, c, depth); return }
    ch <- c
}
func unrepresentedSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { unrepresentedSend(ch, c, depth / 2); return }
    ch <- c
}
func doubleSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { doubleSend(ch, c, depth - 1); return }
    ch <- c
    ch <- c
}
func cyclicSend(ch chan *cell, c *cell, depth int) {
    if depth > 0 { cyclicSend(ch, c, depth - 1); return }
    for i := 0; i < 1; i++ { ch <- c }
}

func unknownRoot(depth int) {
    ch := make(chan *cell)
    c := &cell{}
    go unknownSend(ch, c, depth)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func nondecreasingRoot() {
    ch := make(chan *cell)
    c := &cell{}
    go nondecreasingSend(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func mutableRoot() {
    ch := make(chan *cell)
    c := &cell{}
    go mutableSend(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func unrepresentedRoot() {
    ch := make(chan *cell)
    c := &cell{}
    go unrepresentedSend(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func doubleRoot() {
    ch := make(chan *cell, 2)
    c := &cell{}
    go doubleSend(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
func cyclicRoot() {
    ch := make(chan *cell)
    c := &cell{}
    go cyclicSend(ch, c, 1)
    go func() { got := <-ch; got.n = 1 }()
    go func() { c.n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for root in [
        "unknownRoot",
        "nondecreasingRoot",
        "mutableRoot",
        "unrepresentedRoot",
        "doubleRoot",
        "cyclicRoot",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
        assert!(
            result.results.iter().any(|item| {
                let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                    panic!("concurrent_access_conflicts returns a typed row: {item:#?}");
                };
                value.task_relation == "siblings"
                    && value.ordering == "unordered"
                    && value.proof == "open"
                    && value
                        .reasons
                        .iter()
                        .any(|reason| reason == "recursive_expansion")
            }),
            "an unproved recursive synchronization count must remain Open for {root}: {result:#?}"
        );
    }
}

#[test]
fn go_channel_receive_does_not_join_future_sender_iterations() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package sample

func cyclicRoot() {
	ch := make(chan struct{})
	senderDone := make(chan struct{})
	receiverDone := make(chan struct{})
	n := 0
	go func() {
		for i := 0; i < 2; i++ {
			n = 1
			ch <- struct{}{}
		}
		close(senderDone)
	}()
	go func() {
		<-ch
		n = 2
		<-ch
		close(receiverDone)
	}()
	<-senderDone
	<-receiverDone
	_ = n
}


type Cell struct { n int }
func writeThenSend(c *Cell, ch chan struct{}) { c.n = 1; ch <- struct{}{} }
func helperRoot() {
    c := &Cell{}
    ch := make(chan struct{})
    senderDone := make(chan struct{})
    receiverDone := make(chan struct{})
    go func() {
        for i := 0; i < 2; i++ { writeThenSend(c, ch) }
        close(senderDone)
    }()
    go func() {
        <-ch
        c.n = 2
        <-ch
        close(receiverDone)
    }()
    <-senderDone
    <-receiverDone
    _ = c.n
}

func closedRoot() {
    ch := make(chan struct{})
    done := make(chan struct{})
    n := 0
    go func() {
        for i := 0; i < 2; i++ { n = 1 }
        close(ch)
    }()
    go func() {
        <-ch
        n = 2
        close(done)
    }()
    <-done
    _ = n
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for root in ["cyclicRoot", "helperRoot"] {
        let result = go_invocation_conflicts(&workspace, root);
        let pair = find_concurrent_relation(&result, |value| {
            value.task_relation == "siblings"
                && value.first_access == "write"
                && value.second_access == "write"
        });
        assert_eq!(
            (pair.ordering, pair.proof, pair.coverage),
            ("open", "open", "open"),
            "a receive cannot join future iterations of its sender: {result:#?}"
        );
        assert!(
            pair.reasons
                .iter()
                .any(|reason| reason == "ambiguous_synchronization"),
            "iteration correspondence remains unresolved: {result:#?}"
        );
    }

    let control = go_invocation_conflicts(&workspace, "closedRoot");
    assert_eq!(
        control.completion(),
        CodeQueryCompletion::Complete,
        "{control:#?}"
    );
    assert!(!control.results.is_empty(), "{control:#?}");
    for row in &control.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &row.value else {
            panic!("unexpected row: {row:#?}")
        };
        assert_eq!(
            (value.ordering, value.proof, value.coverage),
            ("happens_before", "proven", "exhaustive"),
            "close after the loop orders every earlier iteration: {control:#?}"
        );
    }
}

#[test]
fn go_fresh_channels_do_not_serialize_unjoined_helper_activations() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package sample

type Cell struct { n int }
func localFanout(c *Cell, finished chan struct{}) {
    ch := make(chan struct{})
    go func() { c.n = 1; ch <- struct{}{} }()
    go func() { <-ch; c.n = 2; finished <- struct{}{} }()
}
func unjoinedRoot() {
    c := &Cell{}
    finished := make(chan struct{}, 2)
    go func() {
        for i := 0; i < 2; i++ { localFanout(c, finished) }
    }()
    <-finished
    <-finished
    _ = c.n
}

func joinedFanout(c *Cell) {
    ch := make(chan struct{})
    done := make(chan struct{})
    go func() { c.n = 1; ch <- struct{}{} }()
    go func() { <-ch; c.n = 2; close(done) }()
    <-done
}
func joinedRoot() {
    c := &Cell{}
    for i := 0; i < 2; i++ { joinedFanout(c) }
    _ = c.n
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let unjoined = go_invocation_conflicts(&workspace, "unjoinedRoot");
    let pair = find_concurrent_relation(&unjoined, |value| {
        value.task_relation == "repeated"
            && value.first_procedure_id != value.second_procedure_id
            && value.first_access == "write"
            && value.second_access == "write"
    });
    assert_eq!(
        (pair.ordering, pair.proof, pair.coverage),
        ("open", "open", "open"),
        "distinct per-helper channels cannot order shared storage across unjoined activations: {unjoined:#?}"
    );
    assert!(
        pair.reasons
            .iter()
            .any(|reason| reason == "ambiguous_synchronization"),
        "{unjoined:#?}"
    );

    let joined = go_invocation_conflicts(&workspace, "joinedRoot");
    let pair = find_concurrent_relation(&joined, |value| {
        value.task_relation == "repeated"
            && value.first_procedure_id != value.second_procedure_id
            && value.first_access == "write"
            && value.second_access == "write"
    });
    assert_eq!(
        (pair.ordering, pair.proof, pair.coverage),
        ("happens_before", "proven", "exhaustive"),
        "joining both children before returning serializes helper activations: {joined:#?}"
    );
    assert_no_proven_unordered_unprotected_conflicts(&joined);
}

#[test]
fn go_channel_formals_preserve_distinct_and_reassigned_descriptors() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
func wait(ch chan struct{}) { <-ch }
func waitReplacement(ch, replacement chan struct{}) { ch = replacement; <-ch }
func distinct() {
    n := 0
    first := make(chan struct{})
    second := make(chan struct{})
    done := make(chan struct{})
    go func() { n = 1; close(first) }()
    go func() { wait(second); n = 2; close(done) }()
    close(second)
    <-first
    <-done
    _ = n
}
func reassigned() {
    n := 0
    first := make(chan struct{})
    second := make(chan struct{})
    done := make(chan struct{})
    go func() { n = 1; close(first) }()
    go func() { waitReplacement(first, second); n = 2; close(done) }()
    close(second)
    <-first
    <-done
    _ = n
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for root in ["distinct", "reassigned"] {
        let result = go_invocation_conflicts(&workspace, root);
        let pair = find_concurrent_relation(&result, |value| {
            value.task_relation == "siblings"
                && value.first_access == "write"
                && value.second_access == "write"
        });
        assert!(
            pair.proof == "open" || pair.ordering == "unordered",
            "independent or replaced channels cannot order the writes: {root}: {result:#?}"
        );
        if root == "distinct" {
            assert_eq!(
                (pair.proof, pair.coverage, pair.ordering),
                ("proven", "exhaustive", "unordered"),
                "{result:#?}"
            );
        }
    }
}

#[test]
fn go_unknown_effects_require_private_storage_and_private_synchronization() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
import "context"
func privateContext(ctx context.Context, stop bool) (err error) {
    done := make(chan struct{})
    go func() { defer close(done); err = nil; if stop { return }; err = nil }()
    select { case <-ctx.Done(): return context.Canceled; case <-done: }
    return err
}
type privateCell struct { n int }
func mutatePrivate(cell *privateCell, stop bool) {
    cell.n = 1
    if stop { return }
    cell.n = 2
}
func privateArguments(ctx context.Context, stop bool) {
    cell := &privateCell{}
    go mutatePrivate(cell, stop)
    select { case <-ctx.Done(): cell.n = 3; default: cell.n = 4 }
}
func (cell *privateCell) mutate(stop bool) {
    cell.n = 1
    if stop { return }
    cell.n = 2
}
func privateReceiver(ctx context.Context, stop bool) {
    cell := &privateCell{}
    go cell.mutate(stop)
    select { case <-ctx.Done(): cell.n = 3; default: cell.n = 4 }
}
func makePrivate() *privateCell { return &privateCell{} }
func privateResult(ctx context.Context, stop bool) {
    cell := makePrivate()
    go mutatePrivate(cell, stop)
    select { case <-ctx.Done(): cell.n = 3; default: cell.n = 4 }
}
func publishPrivate(cell *privateCell, publish func(*privateCell)) {
    publish(cell)
    cell.n = 1
}
func publishedArguments(ctx context.Context, publish func(*privateCell)) {
    cell := &privateCell{}
    go publishPrivate(cell, publish)
    select { case <-ctx.Done(): cell.n = 2; default: cell.n = 3 }
}
func (cell *privateCell) publish(publish func(*privateCell)) {
    publish(cell)
    cell.n = 1
}
func publishedReceiver(ctx context.Context, publish func(*privateCell)) {
    cell := &privateCell{}
    go cell.publish(publish)
    select { case <-ctx.Done(): cell.n = 2; default: cell.n = 3 }
}
func makePublished(publish func(*privateCell)) *privateCell {
    cell := &privateCell{}
    publish(cell)
    return cell
}
func publishedResult(ctx context.Context, publish func(*privateCell)) {
    cell := makePublished(publish)
    go mutatePrivate(cell, false)
    select { case <-ctx.Done(): cell.n = 2; default: cell.n = 3 }
}
func makePair(publish func(*privateCell)) (*privateCell, *privateCell) {
    first := &privateCell{}
    second := &privateCell{}
    publish(first)
    return first, second
}
func privateSecondResult(ctx context.Context, publish func(*privateCell)) {
    _, cell := makePair(publish)
    go mutatePrivate(cell, false)
    select { case <-ctx.Done(): cell.n = 2; default: cell.n = 3 }
}
func publishedFirstResult(ctx context.Context, publish func(*privateCell)) {
    cell, _ := makePair(publish)
    go mutatePrivate(cell, false)
    select { case <-ctx.Done(): cell.n = 2; default: cell.n = 3 }
}
func publishedContext(ctx context.Context, publish func(*error, chan struct{})) (err error) {
    done := make(chan struct{})
    publish(&err, done)
    go func() { defer close(done); err = nil }()
    select { case <-ctx.Done(): return context.Canceled; case <-done: }
    return err
}
func unknownWorker(ctx context.Context, cb func()) (err error) {
    done := make(chan struct{})
    go func() { defer close(done); err = nil; cb() }()
    select { case <-ctx.Done(): return context.Canceled; case <-done: }
    return err
}
var gate chan struct{}
func globalWorker(ctx context.Context) (err error) {
    done := make(chan struct{})
    go func() { <-gate; err = nil; close(done) }()
    select { case <-ctx.Done(): return context.Canceled; case <-done: }
    return err
}
func publishedClosure(ctx context.Context, publish func(func())) (err error) {
    done := make(chan struct{})
    publish(func() { err = nil; close(done) })
    go func() { defer close(done); err = nil }()
    select { case <-ctx.Done(): return context.Canceled; case <-done: }
    return err
}
type localContext interface { Done() <-chan struct{} }
func lookalikeContext(ctx localContext) (err error) {
    done := make(chan struct{})
    go func() { defer close(done); err = nil }()
    select { case <-ctx.Done(): return context.Canceled; case <-done: }
    return err
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let private = go_invocation_conflicts(&workspace, "privateContext");
    assert!(
        private.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.proof == "proven" && value.ordering == "unordered"
                && value.protection == "unprotected" && value.verdict == "conflict")
        }),
        "a foreign receiver cannot synchronize a closed child through its unpublished channel or access the private captured cell: {private:#?}"
    );
    let private_arguments = go_invocation_conflicts(&workspace, "privateArguments");
    assert!(
        private_arguments.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.proof == "proven" && value.ordering == "unordered"
                && value.protection == "unprotected" && value.verdict == "conflict")
        }),
        "passing fresh storage only into a retained child must not publish it to an unrelated foreign call: {private_arguments:#?}"
    );
    let private_receiver = go_invocation_conflicts(&workspace, "privateReceiver");
    assert!(
        private_receiver.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.proof == "proven" && value.ordering == "unordered"
                && value.protection == "unprotected" && value.verdict == "conflict")
        }),
        "passing fresh storage only as a retained receiver must not publish it to an unrelated foreign call: {private_receiver:#?}"
    );
    let private_result = go_invocation_conflicts(&workspace, "privateResult");
    assert!(
        private_result.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.proof == "proven" && value.ordering == "unordered"
                && value.protection == "unprotected" && value.verdict == "conflict")
        }),
        "returning fresh storage only into a retained caller must not publish it to an unrelated foreign call: {private_result:#?}"
    );
    let private_second_result = go_invocation_conflicts(&workspace, "privateSecondResult");
    assert!(
        private_second_result.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.proof == "proven" && value.ordering == "unordered"
                && value.protection == "unprotected" && value.verdict == "conflict")
        }),
        "publishing one result ordinal must not publish a distinct returned allocation: {private_second_result:#?}"
    );
    for root in [
        "publishedContext",
        "publishedArguments",
        "publishedReceiver",
        "publishedResult",
        "publishedFirstResult",
        "unknownWorker",
        "globalWorker",
        "publishedClosure",
        "lookalikeContext",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_conflict_or_explicit_open(&result);
        assert_no_proven_unordered_unprotected_conflicts(&result);
    }
}

#[test]
fn go_unresolved_effects_cross_synchronous_calls() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
func invoke(cb func()) { cb() }
func helperBefore(cb func()) {
    n := 0
    go func() { invoke(cb); n = 1 }()
    go func() { invoke(cb); n = 2 }()
}
func helperAfter(cb func()) {
    n := 0
    go func() { n = 1; invoke(cb) }()
    go func() { n = 2; invoke(cb) }()
}
func callerBefore(cb func()) {
    n := 0
    go func() { cb(); func() { n = 1 }() }()
    go func() { cb(); func() { n = 2 }() }()
}
func callerAfter(cb func()) {
    n := 0
    go func() { func() { n = 1 }(); cb() }()
    go func() { func() { n = 2 }(); cb() }()
}
func mixedLocalPoints(cb func()) {
    n := 0
    go func() { n = 1; invoke(cb); _ = n }()
    go func() { n = 2; invoke(cb); _ = n }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for name in ["helperAfter", "callerAfter"] {
        let result = go_invocation_conflicts(&workspace, name);
        assert!(
            result.results.iter().any(|item| matches!(
                &item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
            )),
            "later unknown effects cannot alter earlier observations: {name}: {result:#?}"
        );
    }
    for name in ["helperBefore", "callerBefore"] {
        let result = go_invocation_conflicts(&workspace, name);
        assert!(
            !result.results.iter().any(|item| matches!(
                &item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "proven"
            )),
            "earlier unknown effects cross synchronous call boundaries: {name}: {result:#?}"
        );
        assert!(
            result.results.iter().any(|item| matches!(
                &item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
                if value.verdict == "conflict" && value.proof == "open"
                    && value.reasons.iter().any(|reason| reason == "unresolved_target")
            )),
            "retain the open conflict and its source uncertainty: {name}: {result:#?}"
        );
    }
    let mixed = go_invocation_conflicts(&workspace, "mixedLocalPoints");
    assert!(
        mixed.results.iter().any(|item| matches!(
            &item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.verdict == "conflict" && value.proof == "proven"
                && value.first_access == "write" && value.second_access == "write"
        )),
        "writes before the callback remain proven: {mixed:#?}"
    );
    assert!(
        mixed.results.iter().any(|item| matches!(
            &item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.verdict == "conflict" && value.proof == "open"
                && (value.first_access == "read" || value.second_access == "read")
                && value.reasons.iter().any(|reason| reason == "unresolved_target")
        )),
        "later reads in the same activation retain unknown effects: {mixed:#?}"
    );
    assert!(
        !mixed.results.iter().any(|item| matches!(
            &item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.verdict == "conflict" && value.proof == "proven"
                && (value.first_access == "read" || value.second_access == "read")
        )),
        "common caller reuse must not reuse an earlier local access point: {mixed:#?}"
    );
}

#[test]
fn go_model_reason_order_respects_expression_regions() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
func sample() int { return 1 }
func consume(a, b int) {}
func afterExpression(cb func()) {
    n := 0
    go func() {
        consume(n, sample())
        n = 1
        if cb != nil { cb() }
    }()
    go func() { n = 2 }()
}
func insideExpression(cb func() int) {
    n := 0
    go func() { consume(n, cb()) }()
    go func() { n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let after = go_invocation_conflicts(&workspace, "afterExpression");
    assert!(
        after.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.first_access == "write" && value.second_access == "write"
                && value.verdict == "conflict" && value.proof == "proven")
        }),
        "an earlier expression cannot reorder a later write and callback: {after:#?}"
    );
    let inside = go_invocation_conflicts(&workspace, "insideExpression");
    assert!(
        !inside.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.verdict == "conflict" && value.proof == "proven")
        }),
        "an unknown callback can precede a read in the same expression: {inside:#?}"
    );
    assert!(
        inside.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ConcurrentAccessConflict { value }
            if value.verdict == "conflict" && value.proof == "open"
                && value.reasons.iter().any(|reason| reason == "unresolved_target"))
        }),
        "a read and unknown callback in one expression retain ordering uncertainty: {inside:#?}"
    );
}

/// Inline reads must not repeatedly pay for a whole invocation inventory.
/// The unknown call still prevents proving the holder's reference payload.
#[test]
fn go_field_payload_budget_skips_unprovable_and_inline_loads() {
    let reads = "    sum += h.n\n".repeat(256);
    let source = format!(
        "package main\ntype cell struct {{ n int }}\ntype holder struct {{ n int; p *cell }}\nfunc unknown(h *holder)\nfunc manyInlineReads() int {{\n    h := &holder{{p: &cell{{}}}}\n    unknown(h)\n    sum := 0\n{reads}    go func() {{ h.p.n = 1 }}()\n    go func() {{ h.p.n = 2 }}()\n    return sum\n}}\n"
    );
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", &source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": "manyInlineReads" },
        "steps": [{ "op": "procedure_of" }, { "op": "concurrent_access_conflicts" }],
        "result_detail": "full"
    }))
    .unwrap();
    let defaults = CodeQueryExecutionLimits::default();
    let default_rows = semantic::semantic_budget_limits(defaults.semantic);
    // A bounded request exposes quadratic inventory prepayment without making
    // the per-push fixture itself large and expensive to analyze.
    let limits = CodeQueryExecutionLimits {
        semantic: CodeQuerySemanticLimits {
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                if dimension == SemanticBudgetDimension::NestedEntries {
                    500_000
                } else {
                    default_rows.get(dimension)
                }
            })),
            ..defaults.semantic
        },
        ..defaults
    };
    let result = super::super::execute_internal(
        workspace.analyzer(),
        Some(&workspace),
        &query,
        limits,
        None,
        None,
        false,
    )
    .result;
    assert!(
        result.diagnostics.iter().all(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }),
        "ordinary inline reads fit the query budget: {result:#?}"
    );
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

fn assert_no_proven_conflicts_with_explanation(result: &CodeQueryResult) {
    for item in &result.results {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        if value.verdict == "conflict" {
            assert_ne!(
                value.proof, "proven",
                "per-invocation helper locals must not prove a conflict: {result:#?}"
            );
            assert!(
                !value.reasons.is_empty(),
                "an unresolved local-allocation relation must retain an explicit reason: {result:#?}"
            );
        }
    }
    if result.completion() != CodeQueryCompletion::Complete {
        assert!(
            !result.diagnostics.is_empty(),
            "an incomplete local-allocation result must retain its diagnostic: {result:#?}"
        );
    }
}

fn assert_no_proven_conflicts_with_explicit_evidence(result: &CodeQueryResult) {
    assert_no_proven_conflicts_with_explanation(result);
    let open_result = result.results.iter().any(|item| {
        let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
            panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
        };
        value.proof == "open" && !value.reasons.is_empty()
    });
    let unknown_diagnostic = result.diagnostics.iter().any(|diagnostic| {
        diagnostic.message.contains("UnknownLocation")
            || diagnostic.message.contains("unknown_location")
    });
    assert!(
        open_result || unknown_diagnostic,
        "an unresolved formal or payload route must retain explicit open evidence: {result:#?}"
    );
}

fn assert_proven_exhaustive_sibling_conflicts(result: &CodeQueryResult, expected: usize) {
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "sibling identity query must resolve completely: {result:#?}"
    );
    assert!(
        result.diagnostics.is_empty(),
        "proven sibling conflicts must not retain identity diagnostics: {result:#?}"
    );
    let conflicts = result
        .results
        .iter()
        .filter_map(|item| {
            let CodeQueryResultValue::ConcurrentAccessConflict { value } = &item.value else {
                panic!("concurrent_access_conflicts returns its typed row: {item:#?}");
            };
            (value.verdict == "conflict").then_some(value)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        conflicts.len(),
        expected,
        "expected the stable sibling conflict count: {result:#?}"
    );
    for value in conflicts {
        assert_eq!(
            (
                value.task_relation,
                value.ordering,
                value.protection,
                value.proof,
                value.coverage,
            ),
            (
                "siblings",
                "unordered",
                "unprotected",
                "proven",
                "exhaustive"
            ),
            "each sibling conflict must be proven and exhaustive: {result:#?}"
        );
    }
}

fn go_invocation_conflicts(workspace: &WorkspaceAnalyzer, root: &str) -> CodeQueryResult {
    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "function", "name": root },
        "steps": [
            { "op": "procedure_of" },
            { "op": "concurrent_access_conflicts" }
        ],
        "result_detail": "full"
    }))
    .expect("invocation identity concurrent access query");
    execute_workspace(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

fn go_invocation_identity_workspace() -> (inline_project::BuiltInlineTestProject, WorkspaceAnalyzer)
{
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    n int
}

type holder struct {
    p *cell
}

type nestedHolder struct {
    inner *holder
}

type nestedCell struct {
    inner cell
}

func opaqueRetargetHolder(*holder)
func opaqueRetargetField(**cell)
func opaqueRun(func())

var publishedHolderCallback func()

func launch(c *cell) {
    go func() { c.n++ }()
}

func inputs(a, b *cell) {
    go func() { a.n = 1 }()
    go func() { b.n = 2 }()
}

func sameInput() {
    p := &cell{}
    inputs(p, p)
}

func differentInput() {
    inputs(&cell{}, &cell{})
}

func holderInputs(a, b *holder) {
    go func() { a.p.n = 1 }()
    go func() { b.p.n = 2 }()
}

func capturedNilHolderFieldPayload() {
    h := &holder{p: &cell{}}
    alias := h
    clear := func() { alias.p = nil }
    clear()
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func conditionalHolderFieldPayload(choose bool) {
    h := &holder{}
    if choose {
        h.p = &cell{}
    }
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func opaqueHolderFieldPayload() {
    h := &holder{p: &cell{}}
    opaqueRetargetHolder(h)
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func escapedHolderFieldPayload() {
    h := &holder{p: &cell{}}
    opaqueRetargetField(&h.p)
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func escapedCallbackHolderFieldPayload() {
    h := &holder{p: &cell{}}
    opaqueRun(func() { h.p = nil })
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func copiedNilHolderFieldPayload() {
    original := holder{}
    copied := original
    go func() { copied.p.n = 1 }()
    go func() { original.p.n = 2 }()
}

func nilHolderFieldPayload() {
    h := &holder{}
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func explicitNilHolderFieldPayload() {
    h := &holder{p: nil}
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func overwrittenHolderFieldPayload() {
    h := &holder{p: &cell{}}
    h.p = nil
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func nestedNilHolderFieldPayload() {
    h := &nestedHolder{inner: &holder{}}
    go func() { h.inner.p.n = 1 }()
    go func() { h.inner.p.n = 2 }()
}

func storedNilHolderFieldPayload() {
    h := &holder{}
    p := h.p
    go func() { p.n = 1 }()
    go func() { p.n = 2 }()
}

func conditionalWriteBeforeSpawn(choose bool) {
    p := &cell{}
    if choose {
        p.n = 1
    }
    go func() { p.n = 2 }()
}

func conditionalWriteAfterSpawn(choose bool) {
    p := &cell{}
    go func() { p.n = 1 }()
    if choose {
        p.n = 2
    }
}

func zeroHolderFieldPayload() {
    var h *holder
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func sharedHolderFieldPayload() {
    h := &holder{p: &cell{}}
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func assignedHolderFieldPayload() {
    h := &holder{}
    h.p = &cell{}
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func publishedHolderInitializer() {
    h := &holder{}
    init := func() { h.p = &cell{} }
    init()
    publishedHolderCallback = init
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func publishedHolderInitializerThroughCaptureCell() {
    h := &holder{}
    f := func() { h.p = &cell{} }
    f = func() { h.p = &cell{} }
    _ = func() { _ = f }
    h.p = &cell{}
    publishedHolderCallback = f
    go func() { h.p.n = 1 }()
    go func() { h.p.n = 2 }()
}

func samePointeeInDifferentHolders() {
    p := &cell{}
    holderInputs(&holder{p: p}, &holder{p: p})
}

func distinctPointeesInDifferentHolders() {
    holderInputs(&holder{p: &cell{}}, &holder{p: &cell{}})
}

func distinctInlineStructFields() {
    first := struct{ n int }{}
    second := struct{ n int }{}
    go func() { first.n = 1 }()
    go func() { second.n = 2 }()
}

func freshAnonymousHolderPointer() {
    for index := 0; index < 2; index++ {
        value := struct{ p *cell }{p: &cell{}}
        go func() { value.p.n++ }()
    }
}

func sharedAnonymousHolderPointer() {
    shared := &cell{}
    for index := 0; index < 2; index++ {
        value := struct{ p *cell }{p: shared}
        go func() { value.p.n++ }()
    }
}

func freshNamedHolderPointer() {
    for index := 0; index < 2; index++ {
        value := holder{p: &cell{}}
        go func() { value.p.n++ }()
    }
}

func sharedNamedHolderPointer() {
    shared := &cell{}
    for index := 0; index < 2; index++ {
        value := holder{p: shared}
        go func() { value.p.n++ }()
    }
}

func freshHolderHelper() {
    value := &holder{p: &cell{}}
    go func() { value.p.n++ }()
}

func freshHelperHolderPointer() {
    for index := 0; index < 2; index++ { freshHolderHelper() }
}

func freshHolderPayloadHelper() *holder {
    h := &holder{}
    h.p = &cell{}
    return h
}

func initializeHolderPayload(h *holder) {
    h.p = &cell{}
}

func repeatedFreshHolderHelpers() {
    for {
        go func() {
            h := freshHolderPayloadHelper()
            h.p.n = 1
        }()
    }
}

func repeatedFreshPublishedFieldArguments() {
    h := &holder{}
    for {
        initializeHolderPayload(h)
        p := h.p
        go func(value *cell) { value.n = 1 }(p)
    }
}

func sharedHolderHelper(shared *cell) {
    value := &holder{p: shared}
    go func() { value.p.n++ }()
}

func sharedHelperHolderPointer() {
    shared := &cell{}
    for index := 0; index < 2; index++ { sharedHolderHelper(shared) }
}

func nestedLocalHelper() {
    value := &nestedCell{}
    go func() { value.inner.n++ }()
}

func loopedNestedLocalHelpers() {
    for index := 0; index < 2; index++ {
        nestedLocalHelper()
    }
}

func nestedSharedHelper(value *nestedCell) {
    go func() { value.inner.n++ }()
}

func loopedNestedSharedHelpers() {
    value := &nestedCell{}
    for index := 0; index < 2; index++ {
        nestedSharedHelper(value)
    }
}

func directSameCell() {
    c := &cell{}
    go func() { c.n++ }()
    go func() { c.n++ }()
}

func sameCellThroughHelperCalls() {
    c := &cell{}
    launch(c)
    launch(c)
}

func distinctPointerActuals() {
    first := &cell{}
    second := &cell{}
    launch(first)
    launch(second)
}

func conditional(c *cell, choose bool) {
    if choose {
        launch(c)
    } else {
        launch(c)
    }
}

func conditionalAtMostOne(choose bool) {
    c := &cell{}
    conditional(c, choose)
}

func launchLocal() {
    c := &cell{}
    go func() { c.n++ }()
}

func independentLocalInvocations() {
    launchLocal()
    launchLocal()
}

func launchAndWait(c *cell) {
    done := make(chan struct{})
    go func() {
        c.n++
        close(done)
    }()
    <-done
}

func joinedHelperInvocations() {
    c := &cell{}
    launchAndWait(c)
    launchAndWait(c)
}

func loopedJoinedHelperInvocations() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        launchAndWait(c)
    }
}

func launchAndMaybeWait(c *cell, wait bool) {
    done := make(chan struct{})
    go func() {
        c.n++
        close(done)
    }()
    if wait {
        <-done
    }
}

func conditionalWaitHelperInvocations(wait bool) {
    c := &cell{}
    launchAndMaybeWait(c, wait)
    launchAndMaybeWait(c, wait)
}

func joinedParent(c *cell) {
    for index := 0; index < 2; index++ {
        launchAndWait(c)
    }
}

func parallelJoinedParentTasks() {
    c := &cell{}
    go joinedParent(c)
    go joinedParent(c)
}

func loopedLocalHelperInvocations() {
    for index := 0; index < 2; index++ {
        launchLocal()
    }
}

func loopedSharedHelperInvocations() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        launch(c)
    }
}

// The backing slice is shared, but the element selected by index is unknown.
func repeatedUnknownIndexOneWrite() {
    values := make([]int, 2)
    index := 0
    for {
        go func() { values[index] = 1 }()
    }
}

func repeatedUnknownIndexTwoWrites() {
    values := make([]int, 2)
    index := 0
    for {
        go func() {
            values[index] = 1
            values[index] = 2
        }()
    }
}

func repeatedConstantIndexSharedSlice() {
    values := make([]int, 1)
    for {
        go func() { values[0]++ }()
    }
}

func repeatedFreshIndexStorage(index int) {
    for {
        go func() {
            values := make([]int, 1)
            values[index]++
        }()
    }
}

func publishedWorker(ch chan *cell) {
    local := &cell{}
    ch <- local
    var got *cell
    got = <-ch
    local.n++
    got.n++
}

func repeatedPublishedWorkers() {
    ch := make(chan *cell, 2)
    for {
        go publishedWorker(ch)
    }
}

func launchWriteThenRead(c *cell) {
    c.n++
    go func() { _ = c.n }()
}

func loopedUnjoinedWriteThenReadHelperInvocations() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        launchWriteThenRead(c)
    }
}

func launchWriteThenReadAndWait(c *cell) {
    c.n++
    done := make(chan struct{})
    go func() {
        _ = c.n
        close(done)
    }()
    <-done
}

func loopedJoinedWriteThenReadHelperInvocations() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        launchWriteThenReadAndWait(c)
    }
}

func loopedUnjoinedWriteThenReadDirectly() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        c.n++
        go func() { _ = c.n }()
    }
}

func loopedJoinedWriteThenReadDirectly() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        c.n++
        done := make(chan struct{})
        go func() {
            _ = c.n
            close(done)
        }()
        <-done
    }
}

func freshReadParentTask() {
    c := &cell{}
    c.n++
    go func() { _ = c.n }()
}

func parallelFreshReadParentTasks() {
    for index := 0; index < 2; index++ {
        go freshReadParentTask()
    }
}

func loopedFreshDirectAllocations() {
    for index := 0; index < 2; index++ {
        c := &cell{}
        c.n++
        go func() { _ = c.n }()
    }
}

func freshWriteThenRead() {
    c := &cell{}
    c.n++
    go func() { _ = c.n }()
}

func loopedFreshHelperAllocations() {
    for index := 0; index < 2; index++ {
        freshWriteThenRead()
    }
}

func channelJoinParent(c *cell) {
    done := make(chan struct{})
    go func() {
        _ = c.n
        close(done)
    }()
    <-done
    c.n++
}

func loopedChannelJoinParentTasks() {
    c := &cell{}
    for index := 0; index < 2; index++ {
        go channelJoinParent(c)
    }
}

func freshChannelJoinParent() {
    c := &cell{}
    channelJoinParent(c)
}

func loopedFreshChannelJoinParentTasks() {
    for index := 0; index < 2; index++ {
        go freshChannelJoinParent()
    }
}

// Each iteration declares a new lexical cell for the child closure.
func freshLexicalCells() {
    for index := 0; index < 2; index++ {
        x := 0
        go func() { x++ }()
    }
}

func freshVarLexicalCells() {
    for index := 0; index < 2; index++ {
        var x int
        go func() { x++ }()
    }
}

func freshRangeCells(values []int) {
    for _, x := range values {
        go func() { x++ }()
    }
}

func sharedRangeCell(values []int) {
    x := 0
    for range values {
        go func() { x++ }()
    }
}

func gotoLexicalCells(again bool) {
next:
    x := 0
    go func() { x++ }()
    if again { goto next }
}

// Both child closures capture the lexical cell declared outside the loop.
func sharedLexicalCell() {
    x := 0
    for index := 0; index < 2; index++ {
        go func() { x++ }()
    }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    (project, workspace)
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

func summarizedErrgroupJoined() int { return summarizedErrgroupBody() }
func summarizedErrgroupBody() int {
    group := &errgroup.Group{}
    value := 0
    group.Go(func() error { value = 1; return nil })
    _ = group.Wait()
    return value
}

func summarizedErrgroupDistinct() int { return summarizedErrgroupDistinctBody() }
func summarizedErrgroupDistinctBody() int {
    group := &errgroup.Group{}
    other := &errgroup.Group{}
    value := 0
    group.Go(func() error { value = 1; return nil })
    _ = other.Wait()
    return value
}

func summarizedErrgroupCopied() int { return summarizedErrgroupCopiedBody() }
func summarizedErrgroupCopiedBody() int {
    group := errgroup.Group{}
    other := group
    value := 0
    group.Go(func() error { value = 1; return nil })
    _ = other.Wait()
    return value
}

func summarizedErrgroupUnknown(callback func() error) {
    summarizedErrgroupUnknownBody(callback)
}
func summarizedErrgroupUnknownBody(callback func() error) {
    group := &errgroup.Group{}
    group.Go(callback)
    _ = group.Wait()
}

type modeledCell struct { value int }

func setWrapped(mutex *sync.RWMutex, cell *modeledCell) {
    mutex.Lock()
    cell.value = 1
    mutex.Unlock()
}

func wrappedExclusive() {
    mutex := &sync.RWMutex{}
    cell := &modeledCell{}
    go setWrapped(mutex, cell)
    setWrapped(mutex, cell)
}

func setCopied(mutex sync.RWMutex, cell *modeledCell) {
    mutex.Lock()
    cell.value = 1
    mutex.Unlock()
}

func wrappedValueCopy() {
    mutex := sync.RWMutex{}
    cell := &modeledCell{}
    go setCopied(mutex, cell)
    setCopied(mutex, cell)
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
    let snapshot = match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("RWMutex/errgroup models activate: {other:#?}"),
    };

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("modeled wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("modeled wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap_or_else(|| panic!("missing {name} procedure"))
    };
    let wrapped = procedure("wrappedExclusive");
    let copied = procedure("wrappedValueCopy");
    let set_wrapped = procedure("setWrapped");
    let set_copied = procedure("setCopied");
    let joined = procedure("summarizedErrgroupJoined");
    let joined_body = procedure("summarizedErrgroupBody");
    let distinct = procedure("summarizedErrgroupDistinct");
    let unknown = procedure("summarizedErrgroupUnknown");
    let unknown_body = procedure("summarizedErrgroupUnknownBody");
    let copied_group = procedure("summarizedErrgroupCopied");
    let roots = [
        wrapped.clone(),
        copied.clone(),
        joined.clone(),
        distinct.clone(),
        unknown.clone(),
        copied_group.clone(),
    ];
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    let projection_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let mut budget = SemanticBudget::default();
    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("modeled wrapper summaries project");
    let unknown_summary = summaries
        .summary_for(&unknown_body)
        .expect("unknown callback summary");
    assert!(!unknown_summary.effects().iter().any(|effect| matches!(effect.key(),
        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
            if matches!(effect.kind(), brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskSpawn { .. })
    )), "an unavailable callback must not acquire an exhaustive task inventory: {unknown_summary:#?}");
    let joined_summary = summaries
        .summary_for(&joined_body)
        .expect("joined helper summary");
    assert_eq!(joined_summary.effects().iter().filter(|effect| matches!(
        effect.key(),
        brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
            if matches!(effect.kind(),
                brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskSpawn { .. }
                | brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskJoin { .. })
    )).count(), 2, "the exact Go/Wait pair must retain task and join effects: {joined_summary:#?}");
    for helper in [&set_wrapped, &set_copied] {
        let summary = summaries
            .summary_for(helper)
            .expect("modeled helper has a production summary");
        assert_eq!(
            summary
                .effects()
                .iter()
                .filter(|effect| matches!(
                    effect.key(),
                    brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                        if matches!(
                            effect.kind(),
                            brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::ModeledCall {
                                effect_count: 1
                            }
                        )
                ))
                .count(),
            2,
            "Lock and Unlock each retain one complete modeled inventory: {summary:#?}"
        );
        assert_eq!(
            summary
                .effects()
                .iter()
                .filter(|effect| matches!(
                    effect.key(),
                    brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                        if matches!(
                            effect.kind(),
                            brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Lock {
                                identity: brokk_bifrost_flow::dataflow::SummaryConcurrencySubjectIdentity::Backing,
                                ..
                            }
                        )
                ))
                .count(),
            2,
            "modeled receiver identity survives projection: {summary:#?}"
        );
    }

    let mut budget = SemanticBudget::default();
    let direct_joined = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projection_provider,
        &joined,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("direct errgroup report computes");
    assert!(
        direct_joined.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the direct Go/Wait pair must order the captured write before the parent read: {direct_joined:#?}"
    );

    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        Some(summaries.clone()),
    );
    let mut budget = SemanticBudget::default();
    let projected_joined = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &joined,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("fresh projected task report computes");
    assert_eq!(
        projected_joined, direct_joined,
        "fresh task summaries preserve the direct report"
    );
    let repository = brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new();
    repository
        .publish_components(summaries.summaries(), summaries.components())
        .expect("task summaries publish");
    let mut budget = SemanticBudget::default();
    let acquisition =
        brokk_bifrost_flow::typestate::acquire_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &repository,
            &brokk_bifrost_flow::dataflow::NoSummaryReadObserver,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("task summaries reacquire");
    assert_eq!(
        acquisition.kind(),
        brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Retained
    );
    let summaries = acquisition.into_summaries();

    // The consumer deliberately has no active semantic models. Its only lock
    // inventory is the stable, source-witnessed summary projected above.
    let retained_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        None,
        Some(summaries),
    );
    let no_models =
        super::super::concurrency::WorkspaceConcurrencyProvider::new(&workspace, None, None);
    let no_models_icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace, None,
        );
    let mut budget = SemanticBudget::default();
    let changed_models =
        brokk_bifrost_flow::typestate::acquire_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&joined),
            &no_models_icfg,
            &no_models,
            &repository,
            &brokk_bifrost_flow::dataflow::NoSummaryReadObserver,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("model removal recomputes the closure");
    assert_eq!(
        changed_models.kind(),
        brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Projected,
        "removing the errgroup model must reject the old modeled closure"
    );
    let changed_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        None,
        Some(changed_models.into_summaries()),
    );
    let mut budget = SemanticBudget::default();
    let changed_report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &changed_provider,
        &joined,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("model removal reports missing behavior");
    assert!(
        changed_report
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget),
        "removed models cannot leave a complete-looking retained report: {changed_report:#?}"
    );
    let mut budget = SemanticBudget::default();
    let no_models_direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &no_models,
        &joined,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("direct analysis without models computes");
    assert_eq!(
        changed_report, no_models_direct,
        "model-removal recomputation must equal direct analysis in that model environment"
    );
    let mut budget = SemanticBudget::default();
    let restored_models =
        brokk_bifrost_flow::typestate::acquire_production_semantic_summaries_with_concurrency(
            std::slice::from_ref(&joined),
            &icfg,
            &projection_provider,
            &repository,
            &brokk_bifrost_flow::dataflow::NoSummaryReadObserver,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("original model selection reacquires");
    assert_eq!(
        restored_models.kind(),
        brokk_bifrost_flow::typestate::ProductionSemanticSummaryAcquisitionKind::Retained,
        "restoring exact model behavior can reuse the original closure"
    );
    let mut budget = SemanticBudget::default();
    let replay_joined = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &retained_provider,
        &joined,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("stored errgroup task and join effects apply without live models");
    assert_eq!(
        replay_joined.conflicts, direct_joined.conflicts,
        "stored Go/Wait effects must preserve task accesses and their ordering; unavailable dispatch remains explicit in report reasons"
    );
    for provider in [&projection_provider, &retained_provider] {
        let mut budget = SemanticBudget::default();
        let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            provider,
            &unknown,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("unavailable callback report computes");
        assert!(
            report.reasons.contains(
                &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget
            ),
            "an unavailable callback must remain explicitly unresolved: {report:#?}"
        );
    }
    let mut budget = SemanticBudget::default();
    for provider in [&projection_provider, &retained_provider] {
        let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            provider,
            &copied_group,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("copied errgroup report computes");
        assert!(
            !report.conflicts.is_empty() || !report.reasons.is_empty(),
            "copied-group analysis must not silently lose the task: {report:#?}"
        );
        assert!(
            !report.conflicts.iter().any(|conflict| {
                conflict.proven
                    && conflict.ordering
                        == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
                    && [&conflict.first, &conflict.second].iter().any(|site| {
                        site.mode == brokk_bifrost_flow::concurrency::ConcurrentAccessMode::Read
                            && site.access_kind
                                == crate::analyzer::semantic::MemoryAccessKind::LexicalCell
                    })
            }),
            "waiting on a value copy cannot join the original group task: {report:#?}"
        );
    }
    let mut budget = SemanticBudget::default();
    let direct_distinct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projection_provider,
        &distinct,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("direct distinct-group report computes");
    assert!(
        direct_distinct.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "waiting on a distinct group must leave the shared access unordered: {direct_distinct:#?}"
    );
    let mut budget = SemanticBudget::default();
    let replay_distinct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &retained_provider,
        &distinct,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("stored distinct-group report computes");
    assert_eq!(
        replay_distinct.conflicts, direct_distinct.conflicts,
        "summary replay must preserve distinct group identity"
    );
    let mut budget = SemanticBudget::default();
    let retained = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &retained_provider,
        &wrapped,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("retained modeled locks apply");
    assert!(
        retained.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "retained wrapper summary establishes exact lock protection: {retained:#?}"
    );
    let mut budget = SemanticBudget::default();
    let retained_copy = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &retained_provider,
        &copied,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("retained copied-lock report computes");
    assert!(
        retained_copy.conflicts.iter().any(|conflict| {
            conflict.protection
                != brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
                && conflict.proven
                && conflict.exhaustive
        }),
        "retained summaries must prove distinct by-value mutex copies do not protect the shared access: {retained_copy:#?}"
    );

    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
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
        execute_workspace(&workspace, &flow_state, &query)
    };
    for (name, verdict) in [
        ("rwExclusive", "protected"),
        ("errgroupJoined", "ordered"),
        ("wrappedExclusive", "protected"),
    ] {
        let result = conflicts_for(name);
        assert_eq!(
            result.completion(),
            CodeQueryCompletion::Complete,
            "{name}: {result:#?}"
        );
        assert_exact_safe_concurrent_relations(&result, verdict);
    }
    let retained_wrapper = conflicts_for("wrappedExclusive");
    assert_eq!(
        retained_wrapper.completion(),
        CodeQueryCompletion::Complete,
        "{retained_wrapper:#?}"
    );
    assert_exact_safe_concurrent_relations(&retained_wrapper, "protected");

    let copied = conflicts_for("wrappedValueCopy");
    let copied_conflicts = copied
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::ConcurrentAccessConflict { value } => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        copied_conflicts
            .iter()
            .any(|value| value.verdict == "conflict"),
        "value-copy lock wrappers must retain the shared access conflict: {copied:#?}"
    );
    assert!(
        copied_conflicts
            .iter()
            .all(|value| value.protection != "protected"),
        "distinct copied mutexes must not become one protective lock: {copied:#?}"
    );
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

/// #2965: a spawned callee in another file of the same Go package retains
/// exact shared storage and complete cross-file conflict evidence.
#[test]
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
    let mut endpoints = [
        (value.first_path.as_str(), value.first_access),
        (value.second_path.as_str(), value.second_access),
    ];
    endpoints.sort_unstable();
    assert_eq!(
        endpoints,
        [("a.go", "read"), ("b.go", "write")],
        "the read and write retain their files regardless of pair ordering: {result:#?}"
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
fn channel_send_address_alias_and_selected_send_keep_condition_identity_open() {
    for publish in [
        "pointer := &err; ch <- pointer",
        "select { case ch <- &err: default: }",
    ] {
        let result = execute_conditional_result_contract_fixture(&format!(
            r#"package main
import "os"
func publishedCondition(path string, ch chan<- *error) string {{
    file, err := os.Open(path)
    {publish}
    if err != nil {{ return "" }}
    return file.Name()
}}
"#,
        ));
        assert_single_open_unknown_result_contract(&result);
    }
}

#[test]
fn channel_send_of_independent_value_keeps_original_condition_guard() {
    for (channel_type, publish) in [
        ("error", "ch <- err"),
        ("*error", "copied := err; ch <- &copied"),
    ] {
        let result = execute_conditional_result_contract_fixture(&format!(
            r#"package main
import "os"
func copiedCondition(path string, ch chan<- {channel_type}) string {{
    file, err := os.Open(path)
    {publish}
    if err != nil {{ return "" }}
    return file.Name()
}}
"#,
        ));
        assert_single_guarded_open_unknown_result_contract(&result);
    }
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
    activate_type_flow_builtins(&workspace);
    (project, workspace)
}

fn activate_type_flow_builtins(workspace: &WorkspaceAnalyzer) {
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
    assert!(type_flow.snapshot_cache_hits > 0, "{type_flow:#?}");
    assert!(type_flow.snapshot_cache_misses > 0, "{type_flow:#?}");
    assert!(type_flow.dispatch_cache_hits > 0, "{type_flow:#?}");
    assert!(type_flow.dispatch_cache_misses > 0, "{type_flow:#?}");
    assert_eq!(type_flow.finding_rows, 1, "{type_flow:#?}");
    assert_eq!(type_flow.failed_solves, 0, "{type_flow:#?}");
}

#[test]
fn field_slot_profile_distinguishes_ephemeral_build_and_memory_hit() {
    let (_project, workspace) = type_flow_workspace();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
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

    let cold = execute_workspace_request(&workspace, &flow_state, &query);
    let warm = execute_workspace_request(&workspace, &flow_state, &query);
    let (CodeQueryResponse::Profile(cold), CodeQueryResponse::Profile(warm)) = (cold, warm) else {
        panic!("profile-mode queries return profiles");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).expect("cold rows serialize"),
        serde_json::to_value(&warm.result.results).expect("warm rows serialize")
    );

    let cold = cold.work.semantic.type_flow;
    assert_eq!(cold.field_slot_builds, 1, "{cold:#?}");
    assert_eq!(cold.field_slot_memory_hits, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_hits, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_misses, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_rejections, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_publications, 0, "{cold:#?}");
    assert_eq!(cold.root_result_persistence_hits, 0, "{cold:#?}");
    assert_eq!(cold.root_result_publications, 0, "{cold:#?}");
    assert_eq!(cold.solves, 1, "{cold:#?}");

    let warm = warm.work.semantic.type_flow;
    assert_eq!(warm.field_slot_builds, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_memory_hits, 1, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_hits, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_misses, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_rejections, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_publications, 0, "{warm:#?}");
    assert_eq!(warm.root_result_persistence_hits, 0, "{warm:#?}");
    assert_eq!(warm.root_result_publications, 0, "{warm:#?}");
    assert_eq!(warm.solves, 1, "{warm:#?}");
}

#[test]
fn field_slot_profile_reopens_persisted_index_without_rebuild_or_republication() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    let warm = execute_workspace_request(
        &warm_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let (CodeQueryResponse::Profile(cold), CodeQueryResponse::Profile(warm)) = (cold, warm) else {
        panic!("profile-mode queries return profiles");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).expect("cold rows serialize"),
        serde_json::to_value(&warm.result.results).expect("warm rows serialize"),
        "persistent field-slot reuse must preserve canonical rows"
    );
    for result in [&cold.result, &warm.result] {
        assert!(
            result.diagnostics.iter().all(|diagnostic| !matches!(
                diagnostic.code,
                CodeQueryDiagnosticCode::Cancelled
                    | CodeQueryDiagnosticCode::SemanticProviderFailed
            )),
            "field-slot persistence must not introduce failure diagnostics: {result:#?}"
        );
    }

    let cold = cold.work.semantic.type_flow;
    assert_eq!(cold.field_slot_builds, 1, "{cold:#?}");
    assert_eq!(cold.field_slot_memory_hits, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_hits, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_misses, 1, "{cold:#?}");
    assert_eq!(cold.field_slot_persistence_rejections, 0, "{cold:#?}");
    assert_eq!(cold.field_slot_publications, 1, "{cold:#?}");

    let warm = warm.work.semantic.type_flow;
    assert_eq!(warm.field_slot_builds, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_memory_hits, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_hits, 1, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_misses, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_persistence_rejections, 0, "{warm:#?}");
    assert_eq!(warm.field_slot_publications, 0, "{warm:#?}");
}

#[test]
fn finding_free_root_result_persistence_reopens_before_discovery_and_serves_both_projections() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "class Missing:\n    pass\ndef normalize(items):\n    ''.strip()\n    item = items[0]\n    if isinstance(item, Missing):\n        return item.absent\n")
        .build();
    let branch = json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "union": [branch.clone(), branch],
        "result_detail": "full"
    }))
    .expect("combined type-flow profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let cold_store_snapshot = cold_workspace
        .store()
        .expect("persisted workspace has a store")
        .class_set_root_result_store_snapshot_for_test()
        .expect("cold root-result store snapshot");
    assert_eq!(cold_store_snapshot.generations.len(), 1);
    assert_eq!(cold_store_snapshot.results.len(), 1);
    assert!(!cold_store_snapshot.results[0].result.rows.is_empty());
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    assert_eq!(
        warm_workspace
            .store()
            .expect("persisted workspace has a store")
            .class_set_root_result_store_snapshot_for_test()
            .expect("pre-hit root-result store snapshot"),
        cold_store_snapshot
    );
    let warm = execute_workspace_request(
        &warm_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let absent_query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ],
        "result_detail": "full"
    }))
    .expect("absent-member profile query");
    let warm_absent = execute_workspace_request(
        &warm_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &absent_query,
    );
    assert_eq!(
        warm_workspace
            .store()
            .expect("persisted workspace has a store")
            .class_set_root_result_store_snapshot_for_test()
            .expect("post-hit root-result store snapshot"),
        cold_store_snapshot,
        "durable hits must not mutate rows or published_at"
    );
    let (CodeQueryResponse::Profile(cold), CodeQueryResponse::Profile(warm)) = (cold, warm) else {
        panic!("profile-mode queries return profiles");
    };
    let CodeQueryResponse::Profile(warm_absent) = warm_absent else {
        panic!("profile-mode query returns a profile");
    };
    assert!(
        cold.result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ClassSetRow { value }
                if value.class.as_deref() == Some("builtins.str")
                    && value.origin == "external"
                    && value.status == "known"
        )),
        "the cold solve must publish a nonempty known external projection: {cold:#?}"
    );
    assert!(
        cold.result.results.iter().any(|item| matches!(
            &item.value,
            CodeQueryResultValue::ClassSetRow { value }
                if value.class.as_deref() == Some("app.Missing")
                    && value.guard_only == Some(true)
        )),
        "guard-only evidence survives the projection: {cold:#?}"
    );
    assert!(
        cold.result
            .render_text()
            .contains("membership from guard only")
    );
    let guarded = cold
        .result
        .results
        .iter()
        .find(|item| {
            matches!(
                &item.value, CodeQueryResultValue::ClassSetRow { value }
                    if value.class.as_deref() == Some("app.Missing")
            )
        })
        .expect("guarded class row");
    assert!(matches!(
        guarded.value.row().field("guard_only"),
        Ok(Some(CodeQueryRowScalarRef::Boolean(true)))
    ));
    assert_eq!(
        serde_json::to_value(&cold.result.results).expect("cold rows serialize"),
        serde_json::to_value(&warm.result.results).expect("warm rows serialize"),
        "durable rows retain IDs, ordering, classes, reasons, status, and source ranges"
    );
    assert_eq!(
        serde_json::to_value(&cold.result.diagnostics).expect("cold diagnostics serialize"),
        serde_json::to_value(&warm.result.diagnostics).expect("warm diagnostics serialize")
    );

    let cold = cold.work.semantic.type_flow;
    assert_eq!(cold.root_result_persistence_hits, 0, "{cold:#?}");
    assert_eq!(cold.root_result_persistence_misses, 1, "{cold:#?}");
    assert_eq!(cold.root_result_persistence_rejections, 0, "{cold:#?}");
    assert_eq!(cold.root_result_store_failures, 0, "{cold:#?}");
    assert_eq!(cold.root_result_publications, 1, "{cold:#?}");
    assert_eq!(cold.solves, 1, "{cold:#?}");
    assert_eq!(cold.cache_hits, 1, "{cold:#?}");
    assert_eq!(cold.finding_rows, 0, "{cold:#?}");

    let warm = warm.work.semantic.type_flow;
    assert_eq!(warm.root_result_persistence_hits, 1, "{warm:#?}");
    assert_eq!(warm.root_result_persistence_misses, 0, "{warm:#?}");
    assert_eq!(warm.root_result_persistence_rejections, 0, "{warm:#?}");
    assert_eq!(warm.root_result_store_failures, 0, "{warm:#?}");
    assert_eq!(warm.root_result_publications, 0, "{warm:#?}");
    assert_eq!(warm.solves, 0, "{warm:#?}");
    assert_eq!(warm.cache_hits, 1, "{warm:#?}");
    assert_eq!(warm.snapshot_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.snapshot_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.dispatch_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.dispatch_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.binding_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.binding_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.summary_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.summary_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.root_summary_cache_hits, 0, "{warm:#?}");
    assert_eq!(warm.root_summary_observation_rejections, 0, "{warm:#?}");
    assert_eq!(warm.published_summaries, 0, "{warm:#?}");
    assert!(warm.summary_profile.is_empty(), "{warm:#?}");
    assert_eq!(warm.class_set_rows, cold.class_set_rows, "{warm:#?}");
    assert!(warm.class_set_rows > 0, "{warm:#?}");
    assert_eq!(warm.finding_rows, 0, "{warm:#?}");

    assert!(warm_absent.result.results.is_empty(), "{warm_absent:#?}");
    let warm_absent = warm_absent.work.semantic.type_flow;
    assert_eq!(
        warm_absent.root_result_persistence_hits, 1,
        "{warm_absent:#?}"
    );
    assert_eq!(warm_absent.solves, 0, "{warm_absent:#?}");
    assert_eq!(warm_absent.finding_rows, 0, "{warm_absent:#?}");
}

#[test]
fn finding_free_root_result_persistence_preserves_multiple_unknown_reason_order() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file(
            "app.py",
            "def commit(message, marker):\n    return message.split(marker)[0].rstrip()\n",
        )
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "commit" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");

    let mut runs = Vec::new();
    for _ in 0..2 {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        activate_type_flow_builtins(&workspace);
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        runs.push(profile);
    }
    let origins = |profile: &CodeQueryProfile| {
        profile
            .result
            .results
            .iter()
            .map(|item| {
                let CodeQueryResultValue::ClassSetRow { value } = &item.value else {
                    panic!("class_set returns typed rows: {item:#?}");
                };
                value.origin.clone()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        origins(&runs[0]),
        vec![
            "unknown:root_parameter".to_string(),
            "unknown:unmodeled_load".to_string(),
        ],
        "the root receiver and indexed element retain independent Unknown reasons; \
         an indexed load does not inherit the split call's container classification"
    );
    assert_eq!(
        serde_json::to_value(&runs[0].result.results).unwrap(),
        serde_json::to_value(&runs[1].result.results).unwrap(),
        "cold projection and store canonicalization use one atom order"
    );
    assert_eq!(
        runs[0].work.semantic.type_flow.root_result_publications, 1,
        "{:#?}",
        runs[0]
    );
    assert_eq!(
        runs[1].work.semantic.type_flow.root_result_persistence_hits, 1,
        "{:#?}",
        runs[1]
    );
    assert_eq!(runs[1].work.semantic.type_flow.solves, 0, "{:#?}", runs[1]);
}

#[test]
fn root_result_persistence_misses_when_non_root_workspace_content_changes() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "def normalize():\n    return ''.strip()\n")
        .file("sibling.py", "VALUE = 1\n")
        .build();
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
    .expect("class-set profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(cold) = cold else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        cold.work.semantic.type_flow.root_result_publications, 1,
        "{cold:#?}"
    );
    let expected = serde_json::to_value(&cold.result.results).expect("cold rows serialize");
    let before = cold_workspace
        .store()
        .expect("persisted workspace has a store")
        .class_set_root_result_store_snapshot_for_test()
        .expect("cold root-result snapshot");
    assert_eq!(before.results.len(), 1);
    drop(cold_workspace);

    project
        .file("sibling.py")
        .write("VALUE = 2\n")
        .expect("edit non-root file");
    project.commit("change sibling only");
    let changed_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("changed persisted workspace builds");
    activate_type_flow_builtins(&changed_workspace);
    let changed = execute_workspace_request(
        &changed_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(changed) = changed else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&changed.result.results).unwrap(),
        expected,
        "a non-root edit rotates the generation without changing the root projection"
    );
    let changed_work = changed.work.semantic.type_flow;
    assert_eq!(
        changed_work.root_result_persistence_hits, 0,
        "{changed_work:#?}"
    );
    assert_eq!(
        changed_work.root_result_persistence_misses, 1,
        "{changed_work:#?}"
    );
    assert_eq!(
        changed_work.root_result_publications, 1,
        "{changed_work:#?}"
    );
    assert_eq!(changed_work.solves, 1, "{changed_work:#?}");

    let after = changed_workspace
        .store()
        .expect("persisted workspace has a store")
        .class_set_root_result_store_snapshot_for_test()
        .expect("changed root-result snapshot");
    assert_eq!(after.generations.len(), 2);
    assert_eq!(after.results.len(), 2);
    assert_eq!(
        after.results[0].result.key.root_public_digest,
        after.results[1].result.key.root_public_digest,
        "the unchanged root keeps its public identity"
    );
    assert_ne!(
        after.results[0]
            .result
            .key
            .generation
            .workspace_content_digest,
        after.results[1]
            .result
            .key
            .generation
            .workspace_content_digest,
        "the sibling edit rotates the whole-workspace generation"
    );
}

#[test]
fn zero_row_finding_free_root_result_persistence_reopens_as_a_hit() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "def idle():\n    return 1\n")
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "idle" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set profile query");

    let mut work = Vec::new();
    for _ in 0..2 {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        activate_type_flow_builtins(&workspace);
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        assert!(profile.result.results.is_empty(), "{profile:#?}");
        work.push(profile.work.semantic.type_flow);
    }
    assert_eq!(work[0].root_result_publications, 1, "{:#?}", work[0]);
    assert_eq!(work[0].solves, 1, "{:#?}", work[0]);
    assert_eq!(work[1].root_result_persistence_hits, 1, "{:#?}", work[1]);
    assert_eq!(work[1].solves, 0, "{:#?}", work[1]);
}

#[test]
fn finding_bearing_root_result_persistence_never_publishes() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ],
        "result_detail": "full"
    }))
    .expect("absent-member profile query");

    let mut runs = Vec::new();
    for _ in 0..2 {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted workspace builds");
        activate_type_flow_builtins(&workspace);
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        runs.push(profile);
    }
    assert_eq!(
        serde_json::to_value(&runs[0].result.results).unwrap(),
        serde_json::to_value(&runs[1].result.results).unwrap()
    );
    for run in runs {
        let work = run.work.semantic.type_flow;
        assert_eq!(work.root_result_persistence_hits, 0, "{work:#?}");
        assert_eq!(work.root_result_persistence_misses, 1, "{work:#?}");
        assert_eq!(work.root_result_publications, 0, "{work:#?}");
        assert_eq!(work.solves, 1, "{work:#?}");
        assert_eq!(work.finding_rows, 1, "{work:#?}");
    }
}

#[test]
fn root_result_persistence_store_failure_falls_back_without_mutating_durable_rows() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
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
    .expect("class-set profile query");
    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(cold) = cold else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        cold.work.semantic.type_flow.root_result_publications, 1,
        "{cold:#?}"
    );
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    let store = warm_workspace
        .store()
        .expect("persisted workspace has a store");
    store.set_class_set_root_result_operational_failure_for_test(true);
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let fallback = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(fallback) = fallback else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).unwrap(),
        serde_json::to_value(&fallback.result.results).unwrap(),
        "an operational store failure falls back to the ordinary exact solve"
    );
    assert!(
        fallback
            .result
            .diagnostics
            .iter()
            .all(|diagnostic| !matches!(
                diagnostic.code,
                CodeQueryDiagnosticCode::Cancelled
                    | CodeQueryDiagnosticCode::SemanticProviderFailed
            ))
    );
    let fallback_work = fallback.work.semantic.type_flow;
    assert_eq!(
        fallback_work.root_result_store_failures, 1,
        "{fallback_work:#?}"
    );
    assert_eq!(
        fallback_work.root_result_persistence_hits, 0,
        "{fallback_work:#?}"
    );
    assert_eq!(
        fallback_work.root_result_publications, 0,
        "{fallback_work:#?}"
    );
    assert_eq!(fallback_work.solves, 1, "{fallback_work:#?}");

    store.set_class_set_root_result_operational_failure_for_test(false);
    let recovered = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(recovered) = recovered else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&cold.result.results).unwrap(),
        serde_json::to_value(&recovered.result.results).unwrap()
    );
    let recovered = recovered.work.semantic.type_flow;
    assert_eq!(recovered.root_result_persistence_hits, 1, "{recovered:#?}");
    assert_eq!(recovered.root_result_store_failures, 0, "{recovered:#?}");
    assert_eq!(recovered.root_result_publications, 0, "{recovered:#?}");
    assert_eq!(recovered.solves, 0, "{recovered:#?}");
}

#[test]
fn root_result_persistence_corrupt_and_overcap_rows_fall_back_and_repair_atomically() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", "def normalize():\n    return ''.strip()\n")
        .build();
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
    .expect("class-set profile query");
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted workspace builds");
    activate_type_flow_builtins(&workspace);
    let run = || {
        let response = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        let CodeQueryResponse::Profile(profile) = response else {
            panic!("profile-mode query returns a profile");
        };
        profile
    };

    let cold = run();
    assert_eq!(
        cold.work.semantic.type_flow.root_result_publications, 1,
        "{cold:#?}"
    );
    let expected = serde_json::to_value(&cold.result.results).expect("cold rows serialize");
    let store = workspace.store().expect("persisted workspace has a store");

    store
        .corrupt_only_class_set_root_result_content_digest_for_test()
        .expect("corrupt sole retained digest");
    let corrupt = run();
    assert_eq!(
        serde_json::to_value(&corrupt.result.results).unwrap(),
        expected
    );
    let corrupt_work = corrupt.work.semantic.type_flow;
    assert_eq!(
        corrupt_work.root_result_persistence_rejections, 1,
        "{corrupt_work:#?}"
    );
    assert_eq!(
        corrupt_work.root_result_store_failures, 0,
        "{corrupt_work:#?}"
    );
    assert_eq!(
        corrupt_work.root_result_publications, 1,
        "{corrupt_work:#?}"
    );
    assert_eq!(corrupt_work.solves, 1, "{corrupt_work:#?}");

    store
        .oversize_only_class_set_root_result_row_count_for_test()
        .expect("oversize sole retained row count");
    let overcap = run();
    assert_eq!(
        serde_json::to_value(&overcap.result.results).unwrap(),
        expected
    );
    let overcap_work = overcap.work.semantic.type_flow;
    assert_eq!(
        overcap_work.root_result_persistence_rejections, 1,
        "{overcap_work:#?}"
    );
    assert_eq!(
        overcap_work.root_result_store_failures, 0,
        "{overcap_work:#?}"
    );
    assert_eq!(
        overcap_work.root_result_publications, 1,
        "{overcap_work:#?}"
    );
    assert_eq!(overcap_work.solves, 1, "{overcap_work:#?}");

    let recovered = run();
    assert_eq!(
        serde_json::to_value(&recovered.result.results).unwrap(),
        expected
    );
    let recovered = recovered.work.semantic.type_flow;
    assert_eq!(recovered.root_result_persistence_hits, 1, "{recovered:#?}");
    assert_eq!(recovered.root_result_publications, 0, "{recovered:#?}");
    assert_eq!(recovered.solves, 0, "{recovered:#?}");
}

#[test]
fn field_slot_store_failure_falls_back_without_publishing_a_memory_hit() {
    let project = InlineTestProject::with_language(Language::Python)
        .with_git()
        .file("app.py", TYPE_FLOW_PURPOSE_FIXTURE)
        .build();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("cold persisted workspace builds");
    activate_type_flow_builtins(&cold_workspace);
    let cold = execute_workspace_request(
        &cold_workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(cold) = cold else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        cold.work.semantic.type_flow.field_slot_publications, 1,
        "{cold:#?}"
    );
    drop(cold_workspace);

    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("warm persisted workspace builds");
    activate_type_flow_builtins(&warm_workspace);
    let store = warm_workspace
        .store()
        .expect("persisted workspace has a store");
    store.set_class_set_field_slot_operational_failure_for_test(true);
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let failed_store = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(failed_store) = failed_store else {
        panic!("profile-mode query returns a profile");
    };
    let failed_work = failed_store.work.semantic.type_flow;
    assert_eq!(failed_work.field_slot_builds, 1, "{failed_work:#?}");
    assert_eq!(failed_work.field_slot_memory_hits, 0, "{failed_work:#?}");
    assert_eq!(
        failed_work.field_slot_persistence_hits, 0,
        "{failed_work:#?}"
    );
    assert_eq!(
        failed_work.field_slot_persistence_misses, 0,
        "{failed_work:#?}"
    );
    assert_eq!(
        failed_work.field_slot_persistence_rejections, 0,
        "an operational failure is not rejected persisted evidence: {failed_work:#?}"
    );
    assert_eq!(failed_work.field_slot_publications, 0, "{failed_work:#?}");
    store.set_class_set_field_slot_operational_failure_for_test(false);
    let recovered = execute_workspace_request(&warm_workspace, &flow_state, &query);
    let CodeQueryResponse::Profile(recovered) = recovered else {
        panic!("profile-mode query returns a profile");
    };
    assert_eq!(
        serde_json::to_value(&failed_store.result.results).expect("fallback rows serialize"),
        serde_json::to_value(&recovered.result.results).expect("recovered rows serialize")
    );
    let recovered = recovered.work.semantic.type_flow;
    assert_eq!(recovered.field_slot_builds, 0, "{recovered:#?}");
    assert_eq!(recovered.field_slot_memory_hits, 0, "{recovered:#?}");
    assert_eq!(
        recovered.field_slot_persistence_hits, 1,
        "a failed durable acquisition must not leave a ready memory value: {recovered:#?}"
    );
    assert_eq!(recovered.field_slot_persistence_misses, 0, "{recovered:#?}");
    assert_eq!(
        recovered.field_slot_persistence_rejections, 0,
        "{recovered:#?}"
    );
    assert_eq!(recovered.field_slot_publications, 0, "{recovered:#?}");
}

#[test]
fn class_set_reuses_provider_acquisition_across_queries_without_changing_rows() {
    let (_project, workspace) = type_flow_workspace();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("profile query");

    let first = execute_workspace_request(&workspace, &flow_state, &query);
    let second = execute_workspace_request(&workspace, &flow_state, &query);
    let (CodeQueryResponse::Profile(first), CodeQueryResponse::Profile(second)) = (first, second)
    else {
        panic!("profile-mode queries return profiles");
    };

    assert_eq!(
        serde_json::to_value(&first.result.results).expect("first rows serialize"),
        serde_json::to_value(&second.result.results).expect("second rows serialize"),
        "provider-cache warmth must not change canonical result rows"
    );
    let cold = first.work.semantic.type_flow;
    let warm = second.work.semantic.type_flow;
    assert!(cold.snapshot_cache_misses > 0, "{cold:#?}");
    assert!(cold.dispatch_cache_misses > 0, "{cold:#?}");
    assert!(warm.snapshot_cache_hits > 0, "{warm:#?}");
    assert!(warm.dispatch_cache_hits > 0, "{warm:#?}");
    assert_eq!(warm.snapshot_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.dispatch_cache_misses, 0, "{warm:#?}");
    assert_eq!(warm.binding_cache_misses, 0, "{warm:#?}");
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

const PYTHON_ABSENT_MEMBER_CAPABILITY_MESSAGE: &str =
    "python absent-member analysis requires an active Python declaration surface";

fn has_python_absent_member_capability_diagnostic(result: &CodeQueryResult) -> bool {
    result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticCapabilityUnsupported
            && diagnostic.message == PYTHON_ABSENT_MEMBER_CAPABILITY_MESSAGE
    })
}

#[test]
fn python_absent_member_without_procedures_reports_the_missing_declaration_surface() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "value = 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": "missing" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ]
    }))
    .expect("absent-member query");

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert!(
        result.results.is_empty(),
        "no procedures exist: {result:#?}"
    );
    assert!(
        has_python_absent_member_capability_diagnostic(&result),
        "an empty Python file selection must still name the missing declaration surface: {result:#?}"
    );
}

#[test]
fn php_absent_member_query_in_a_mixed_workspace_does_not_report_python_pack_missing() {
    let project = InlineTestProject::new()
        .file("app.py", "def python_only():\n    return 1\n")
        .file("app.php", "<?php\nfunction php_only() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["php"],
        "match": { "kind": "function", "name": "php_only" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ]
    }))
    .expect("PHP absent-member query");

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert!(
        !has_python_absent_member_capability_diagnostic(&result),
        "a PHP-only query must not report the Python declaration surface as missing: {result:#?}"
    );
}

#[test]
fn python_occurrence_target_to_procedure_does_not_bypass_absent_member_capability_gate() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "def normalize(x):\n    return x.strip()\n\ndef read_config():\n    return normalize(123)\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "occurrences": { "class": "reference" },
        "steps": [
            { "op": "occurrence_target" },
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ]
    }))
    .expect("occurrence-target absent-member query");

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    assert!(
        has_python_absent_member_capability_diagnostic(&result),
        "an occurrence-target -> declaration -> procedure route must use the same Python gate: {result:#?}"
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

/// The whole-workspace field-slot prepass has its own finite budget and can
/// pay artifacts that the query's selected structural rows did not visit. If
/// its aggregate scalar charge is larger than the query ledger, the root must
/// still inherit those paid identities instead of buying the same artifact
/// census again from its smaller child budget.
#[test]
fn class_set_root_inherits_artifacts_paid_by_the_field_slot_prepass() {
    let unrelated = (0..128)
        .map(|index| format!("def unrelated_{index}():\n    return {index}\n"))
        .collect::<String>();
    let helper = format!(
        "def mutate(value, name):\n    setattr(value, name, 1)\n\n\
         def normalize(value):\n    return value.strip()\n{unrelated}"
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            concat!(
                "from helper import mutate, normalize\n\n",
                "def read_config():\n",
                "    value = 123\n",
                "    mutate(value, 'extra')\n",
                "    return normalize(value)\n",
            ),
        )
        .file("helper.py", &helper)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    activate_type_flow_builtins(&workspace);

    let cancellation = CancellationToken::default();
    let mut measurement_budget = SemanticBudget::default();
    let helper_artifact = workspace
        .materialize_program_semantics(
            &project.file("helper.py"),
            &mut SemanticRequest::new(&mut measurement_budget, &cancellation),
        )
        .expect("helper semantics materialize")
        .available_value()
        .cloned()
        .expect("helper artifact remains available");
    let event_cap = helper_artifact
        .work()
        .events
        .checked_sub(1)
        .expect("inflated helper owns more than one event");

    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "languages": ["python"],
        "where": ["app.py"],
        "match": { "kind": "function", "name": "read_config" },
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
                    if dimension == SemanticBudgetDimension::Events {
                        event_cap
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
        profile.result.diagnostics.iter().all(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }),
        "the root does not repay the helper artifact: {profile:#?}"
    );
    assert!(
        profile.result.results.iter().any(|item| {
            matches!(&item.value, CodeQueryResultValue::ClassSetRow { value }
                if value.member == "strip"
                    && value.class.as_deref() == Some("builtins.int")
                    && value.status == "known")
        }),
        "the bounded root still classifies its cross-file receiver: {profile:#?}"
    );
    assert!(
        profile.work.semantic.type_flow.snapshot_cache_hits > 0,
        "the root reuses snapshots prepared by the dynamic-write prepass: {profile:#?}"
    );
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
                        26
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

/// A selected receive can replace a local pointer with a nil channel value.
/// The following field writes are unreachable at runtime, so stale identity
/// from the pre-select pointer must not become a proven sibling conflict.
#[test]
fn go_concurrent_access_conflicts_keep_selected_receive_rebinding_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    n int
}

func selectedReceiveRebinding() {
    ch := make(chan *cell, 1)
    ch <- nil
    pointer := &cell{}
    select {
    case pointer = <-ch:
    default:
    }
    go func() { pointer.n = 1 }()
    go func() { pointer.n = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = go_invocation_conflicts(&workspace, "selectedReceiveRebinding");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

/// A local nonzero-offset slice is returned through a helper and compared
/// with a zero-offset view of the same allocation. The two child writes reach
/// different elements; unresolved offset propagation must remain explicitly
/// open instead of proving a race.
#[test]
fn go_concurrent_access_conflicts_keep_local_tail_and_head_views_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

func localTail(values []int) []int {
    tail := values[1:]
    return tail
}

func localTailAndHeadViews() {
    values := make([]int, 2)
    tail := localTail(values)
    head := values[:1]
    go func() { tail[0] = 1 }()
    go func() { head[0] = 2 }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = go_invocation_conflicts(&workspace, "localTailAndHeadViews");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

/// A successful comma-ok assertion can still produce a nil pointer. Both
/// post-assertion field writes panic, so a stale pre-assertion parameter
/// identity must remain open instead of becoming a proven sibling conflict.
#[test]
fn go_heap_identity_keeps_comma_ok_assertion_rebindings_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

type cell struct {
    n int
}


func commaOkAssertion(boxed any, pointer *cell) {
    var ok bool
    pointer, ok = boxed.(*cell)
    _ = ok
    go func() { pointer.n = 1 }()
    go func() { pointer.n = 2 }()
}

func commaOkAssertionWithShortDeclaration(boxed any, pointer *cell) {
    pointer, ok := boxed.(*cell)
    _ = ok
    go func() { pointer.n = 1 }()
    go func() { pointer.n = 2 }()
}

func commaOkLocalAssertionRoot() {
    var boxed any = (*cell)(nil)
    pointer := &cell{}
    var ok bool
    pointer, ok = boxed.(*cell)
    _ = ok
    go func() { pointer.n = 1 }()
    go func() { pointer.n = 2 }()
}

func commaOkAssertionRoot() {
    var boxed any = (*cell)(nil)
    commaOkAssertion(boxed, &cell{})
}

func commaOkAssertionWithShortDeclarationRoot() {
    var boxed any = (*cell)(nil)
    commaOkAssertionWithShortDeclaration(boxed, &cell{})
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for root in [
        "commaOkLocalAssertionRoot",
        "commaOkAssertionRoot",
        "commaOkAssertionWithShortDeclarationRoot",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explicit_evidence(&result);
    }
}

#[test]
fn go_heap_identity_keeps_recursive_receiver_rebinding_open() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }
type box struct { p *cell }
func (b *box) replace(depth int) {
    if depth == 0 { return }
    b = &box{p: &cell{}}
    b.p.n++
    b.replace(depth - 1)
}
func recursiveReceiverRebinding() {
    original := &box{p: &cell{}}
    go original.replace(2)
    go func(v *box) { v.p.n++ }(original)
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = go_invocation_conflicts(&workspace, "recursiveReceiverRebinding");
    assert_no_proven_conflicts_with_explicit_evidence(&result);
}

#[test]
fn go_heap_identity_preserves_forwarded_callback_environments() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type callbackCell struct { n int }
type callbackHolder struct { p *callbackCell }
func invokeCallback(f func()) { f() }
func writeCallback(h *callbackHolder) { invokeCallback(func() { h.p.n++ }) }
func sharedCallbackEnvironment() {
    h := &callbackHolder{p: &callbackCell{}}
    go writeCallback(h)
    go writeCallback(h)
}
func distinctCallbackEnvironments() {
    go writeCallback(&callbackHolder{p: &callbackCell{}})
    go writeCallback(&callbackHolder{p: &callbackCell{}})
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let shared = go_invocation_conflicts(&workspace, "sharedCallbackEnvironment");
    assert_proven_unordered_unprotected_conflict(&shared, "sharedCallbackEnvironment");
    let distinct = go_invocation_conflicts(&workspace, "distinctCallbackEnvironments");
    assert_no_proven_conflicts_with_explanation(&distinct);
}

#[test]
fn go_heap_identity_does_not_retain_replaced_callable_targets() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
var replacementCallback func()
func unknownCallback() func() { return replacementCallback }
func replaceCallback(f func()) { f = unknownCallback(); f() }
func keepCallback(f func()) { f() }
func replacedCallableTarget() {
    counter := 0
    go replaceCallback(func() { counter++ })
    go func() { counter++ }()
}

func stableCallableTarget() {
    counter := 0
    go keepCallback(func() { counter++ })
    go func() { counter++ }()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let stable = go_invocation_conflicts(&workspace, "stableCallableTarget");
    assert_proven_unordered_unprotected_conflict(&stable, "stableCallableTarget");
    let replaced = go_invocation_conflicts(&workspace, "replacedCallableTarget");
    assert_no_proven_conflicts_with_explanation(&replaced);
    assert!(matches!(
        replaced.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert!(
        replaced
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.message.contains("UnresolvedTarget") }),
        "the replacement callable must retain its unresolved dispatch: {replaced:#?}"
    );
}

#[test]
fn go_heap_identity_keeps_repeated_mutable_capture_cells_distinct() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main
type cell struct { n int }
func repeatedMutableCapture() {
    p := &cell{}
    f := func() { p.n = 1 }
    p = &cell{}
    go f()
}
func distinctRepeatedMutableCapture() {
    for i := 0; i < 2; i++ { go repeatedMutableCapture() }
}
func localCounterCapture() {
    counter := 0
    go func() { counter++ }()
}
func distinctRepeatedCounterCapture() {
    for i := 0; i < 2; i++ { go localCounterCapture() }
}
func sharedCounterCapture() {
    counter := 0
    go func() { counter++ }()
    go func() { counter++ }()
}
func sharedRepeatedCounterCapture() {
    for i := 0; i < 2; i++ { go sharedCounterCapture() }
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for root in [
        "distinctRepeatedMutableCapture",
        "distinctRepeatedCounterCapture",
    ] {
        let result = go_invocation_conflicts(&workspace, root);
        assert_no_proven_conflicts_with_explanation(&result);
    }
    let shared = go_invocation_conflicts(&workspace, "sharedRepeatedCounterCapture");
    assert_proven_unordered_unprotected_conflict(&shared, "siblings share their creator's counter");
}

/// #3194: a root that exhausts a budget must be attributable from the
/// diagnostic alone. The diagnostic names each exhausting root's path and
/// qualified name, the lane that stopped it, and the charge it could not pay,
/// both as structured rows and in the message a policy report carries.
#[test]
fn an_exhausted_root_is_attributed_by_path_name_lane_and_charge() {
    let (_project, workspace) = type_flow_workspace();
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "function", "name": "normalize" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ],
        "result_detail": "full"
    }))
    .expect("class-set query");
    let result = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            value_flow: CodeQueryValueFlowLimits {
                solver_work: brokk_bifrost_flow::dataflow::SolverWork {
                    reached_states: 1,
                    ..brokk_bifrost_flow::dataflow::SolverWork::default_limits()
                },
                ..CodeQueryValueFlowLimits::default()
            },
            ..CodeQueryExecutionLimits::default()
        },
    );
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial)
        .unwrap_or_else(|| panic!("an incomplete root raises its diagnostic: {result:#?}"));
    let attributed = diagnostic
        .exhausted_roots
        .iter()
        .find(|root| root.lane == "solver/reached_states")
        .unwrap_or_else(|| panic!("the solver lane is named: {diagnostic:#?}"));
    assert!(
        attributed.path.ends_with("app.py"),
        "the root's path is carried: {attributed:#?}"
    );
    assert_eq!(
        attributed.procedure.as_deref(),
        Some("normalize"),
        "the root's qualified name is carried: {attributed:#?}"
    );
    let charge = attributed
        .charge
        .unwrap_or_else(|| panic!("the failed charge is carried: {attributed:#?}"));
    assert_eq!(charge.limit, 1, "{attributed:#?}");
    assert!(charge.attempted > charge.limit, "{attributed:#?}");
    assert_eq!(
        attributed.feedback_iteration,
        Some(0),
        "the feedback iteration is carried: {attributed:#?}"
    );
    for expected in [
        attributed.path.as_str(),
        "normalize",
        "solver/reached_states",
        &format!("charged {} limit {}", charge.attempted, charge.limit),
    ] {
        assert!(
            diagnostic.message.contains(expected),
            "the message renders `{expected}`: {diagnostic:#?}"
        );
    }
}
/// The reviewed try-acquire protocol pack shared by the TryLock guard tests:
/// sync.Mutex and sync.RWMutex with the call-result-true acquisition condition
/// on TryLock and TryRLock (issue #3369).
const TRY_LOCK_GUARD_PACK: &[u8] = br#"{
  "schema_version": 2,
  "pack_id": "test.go.trylock-guard",
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
          "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync" }
        },
        {
          "id": "type.2222222222222222222222222222222222222222222222222222222222222222",
          "name": "sync.Mutex", "type_kind": "struct", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex" }
        },
        {
          "id": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "sync.RWMutex", "type_kind": "struct", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex" }
        }
      ],
      "members": [
        {
          "id": "member.1111111111111111111111111111111111111111111111111111111111111111",
          "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
          "name": "Lock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Lock" }
        },
        {
          "id": "member.2222222222222222222222222222222222222222222222222222222222222222",
          "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
          "name": "Unlock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Unlock" }
        },
        {
          "id": "member.3333333333333333333333333333333333333333333333333333333333333333",
          "owner": "type.2222222222222222222222222222222222222222222222222222222222222222",
          "name": "TryLock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/mutex.go", "symbol": "sync.Mutex.TryLock" }
        },
        {
          "id": "member.4444444444444444444444444444444444444444444444444444444444444444",
          "owner": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "Lock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Lock" }
        },
        {
          "id": "member.5555555555555555555555555555555555555555555555555555555555555555",
          "owner": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "Unlock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Unlock" }
        },
        {
          "id": "member.6666666666666666666666666666666666666666666666666666666666666666",
          "owner": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "RLock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RLock" }
        },
        {
          "id": "member.7777777777777777777777777777777777777777777777777777777777777777",
          "owner": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "RUnlock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RUnlock" }
        },
        {
          "id": "member.8888888888888888888888888888888888888888888888888888888888888888",
          "owner": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "TryLock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.TryLock" }
        },
        {
          "id": "member.9999999999999999999999999999999999999999999999999999999999999999",
          "owner": "type.3333333333333333333333333333333333333333333333333333333333333333",
          "name": "TryRLock", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false, "signature": { "type_parameters": [], "parameters": [], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.TryRLock" }
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
          "id": "mu.lock", "target": { "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Lock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
        },
        {
          "id": "mu.unlock", "target": { "path": "src/sync/mutex.go", "symbol": "sync.Mutex.Unlock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
        },
        {
          "id": "mu.try-lock", "target": { "path": "src/sync/mutex.go", "symbol": "sync.Mutex.TryLock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive", "condition": "call_result_true" }]
        },
        {
          "id": "rw.lock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Lock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
        },
        {
          "id": "rw.unlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.Unlock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "exclusive" }]
        },
        {
          "id": "rw.rlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RLock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "shared" }]
        },
        {
          "id": "rw.runlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.RUnlock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_release", "lock": { "kind": "receiver" }, "mode": "shared" }]
        },
        {
          "id": "rw.try-lock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.TryLock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "exclusive", "condition": "call_result_true" }]
        },
        {
          "id": "rw.try-rlock", "target": { "path": "src/sync/rwmutex.go", "symbol": "sync.RWMutex.TryRLock()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete", "ordinary_heap_unchanged": true, "transfers": [],
          "concurrency_effects": [{ "kind": "lock_acquire", "lock": { "kind": "receiver" }, "mode": "shared", "condition": "call_result_true" }]
        }
      ]
    }
  }]
}"#;

fn try_lock_guard_snapshot(
    workspace: &WorkspaceAnalyzer,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    let pack = compile_source(
        SourceFormat::Json,
        TRY_LOCK_GUARD_PACK,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("TryLock guard pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-trylock-guard".to_owned(),
            },
        )
        .expect("register TryLock guard model pack");
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
    match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("TryLock guard models activate: {other:#?}"),
    }
}

#[test]
fn go_concurrent_access_conflicts_bind_try_lock_results() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "sync"

func tryLockRoot() int {
	mu := &sync.Mutex{}
	guarded := 0
	go func() {
		mu.Lock()
		guarded++
		mu.Unlock()
	}()
	if mu.TryLock() {
		guarded++
		mu.Unlock()
	}
	return 0
}

func falseBranchRoot() int {
	mu := &sync.Mutex{}
	branched := 0
	go func() {
		mu.Lock()
		branched++
		mu.Unlock()
	}()
	if mu.TryLock() {
		mu.Unlock()
	} else {
		branched++
	}
	return 0
}

func displacedRoot() int {
	mu := &sync.Mutex{}
	other := &sync.Mutex{}
	displaced := 0
	go func() {
		mu.Lock()
		displaced++
		mu.Unlock()
	}()
	if other.TryLock() {
		displaced++
		other.Unlock()
	}
	return 0
}

func unestablishedRoot() int {
	mu := &sync.Mutex{}
	unestablished := 0
	go func() {
		mu.Lock()
		unestablished++
		mu.Unlock()
	}()
	locked := mu.TryLock()
	unestablished++
	if locked {
		mu.Unlock()
	}
	return 0
}

func tryRLockRoot() int {
	rw := &sync.RWMutex{}
	rwwritten := 0
	go func() {
		rw.Lock()
		rwwritten++
		rw.Unlock()
	}()
	if rw.TryRLock() {
		rwwritten++
		rw.RUnlock()
	}
	return 0
}

type spinner struct{ n int }

func (s *spinner) TryLock() bool {
	s.n++
	return s.n%2 == 0
}

func sameNameRoot() int {
	sp := &sync.Mutex{}
	spun := 0
	go func() {
		sp.Lock()
		spun++
		sp.Unlock()
	}()
	s := &spinner{}
	if s.TryLock() {
		spun++
	}
	return 0
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = try_lock_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("TryLock guard semantics materialize")
        .available_value()
        .cloned()
        .expect("TryLock guard semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        None,
    );
    let report = |name: &str| {
        let mut budget = SemanticBudget::default();
        brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &procedure(name),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("{name} report computes: {error}"))
    };

    // Positive: both conflicting accesses hold the receiver lock exclusively on
    // the paths that reach them, so the guarded pair is compatible-lock
    // protected and the model reports no open boundary.
    let positive = report("tryLockRoot");
    assert!(
        !positive
            .reasons
            .iter()
            .any(|reason| matches!(reason, brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol) if protocol.contains("TryLock")))
    );
    assert!(
        positive.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "the TryLock success branch must protect the guarded accesses: {positive:#?}"
    );

    // Wrong branch: the false arm holds nothing, so the write inside it stays
    // unprotected and the conflict stays a proven race.
    let wrong_branch = report("falseBranchRoot");
    assert!(
        wrong_branch.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "the false-branch write must remain an unprotected proven race: {wrong_branch:#?}"
    );
    assert!(
        !wrong_branch.conflicts.iter().any(|conflict| {
            conflict.protection
                == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "no pair may claim receiver protection from the failed branch: {wrong_branch:#?}"
    );

    // Wrong object: a TryLock on one receiver cannot protect data guarded by
    // another mutex.
    let wrong_object = report("displacedRoot");
    assert!(
        wrong_object.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "the distinct-receiver guard must not protect the shared write: {wrong_object:#?}"
    );
    assert!(
        !wrong_object.conflicts.iter().any(|conflict| {
            conflict.protection
                == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "no pair may claim protection across distinct receivers: {wrong_object:#?}"
    );

    // Incomplete: a result no structured guard tests establishes no lock on
    // any path, and the typed boundary keeps the answer open.
    let incomplete = report("unestablishedRoot");
    assert!(
        incomplete.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("try-acquire result is not established")),
        ),
        "the unbound try-acquire result must keep its typed boundary: {incomplete:#?}"
    );
    assert!(
        incomplete.conflicts.iter().all(|conflict| {
            conflict.protection
                != brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "no pair may gain protection from an unestablished result: {incomplete:#?}"
    );

    // Reader mode: a proven TryRLock success protects against a blocking
    // exclusive writer exactly like RLock does.
    let reader = report("tryRLockRoot");
    assert!(
        reader.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "the TryRLock success branch protects in shared mode: {reader:#?}"
    );

    // Same name, wrong type: an unrelated TryLock method never binds the
    // reviewed sync.Mutex protocol.
    let same_name = report("sameNameRoot");
    assert!(
        !same_name.conflicts.iter().any(|conflict| {
            conflict.protection
                == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "an unrelated same-name method must not grant lock protection: {same_name:#?}"
    );
}

#[test]
fn go_projected_summaries_retain_try_lock_conditions() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "sync"

type guardedCell struct {
	mu  sync.Mutex
	sum int
}

func (c *guardedCell) tryLockSum() bool {
	return c.mu.TryLock()
}

func (c *guardedCell) guardedWriter() {
	if c.tryLockSum() {
		c.sum++
		c.mu.Unlock()
	}
}

func (c *guardedCell) blockingWriter() {
	c.mu.Lock()
	c.sum++
	c.mu.Unlock()
}

func wrappedRoot(cell *guardedCell) {
	go cell.guardedWriter()
	cell.blockingWriter()
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = try_lock_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let try_lock_sum = procedure("tryLockSum");
    let wrapped_root = procedure("wrappedRoot");

    // Project production summaries for the wrapper closure and prove that the
    // projected try-acquire keeps its call-result-true acquisition.
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    let projection_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let roots = [
        wrapped_root.clone(),
        procedure("guardedWriter"),
        procedure("blockingWriter"),
        try_lock_sum.clone(),
    ];
    let mut projection_budget = SemanticBudget::default();
    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &mut SemanticRequest::new(&mut projection_budget, &cancellation),
        )
        .expect("wrapper summaries project");
    let summary = summaries
        .summary_for(&try_lock_sum)
        .expect("the wrapper has a production summary");
    assert!(
        summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::Lock {
                        acquisition: brokk_bifrost_flow::dataflow::SummaryLockAcquisition::CallResultTrue,
                        ..
                    }
                )
        )),
        "the wrapper summary must carry the call-result-true acquisition: {summary:#?}"
    );

    // Direct expansion cannot see the caller's guard from inside the wrapper,
    // so the unbound result keeps its typed boundary and grants no protection.
    let direct_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let mut direct_budget = SemanticBudget::default();
    let direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &wrapped_root,
        &mut SemanticRequest::new(&mut direct_budget, &cancellation),
    )
    .expect("direct wrapper report computes");
    assert!(
        !direct.conflicts.iter().any(|conflict| {
            conflict.protection
                == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
        }),
        "direct expansion must not grant protection across the wrapper: {direct:#?}"
    );

    // The projected summary retains the condition, but applying a callee's
    // conditional acquisition inside the caller's guard context is the
    // remaining exact-wrapper-protection work: the solve must keep the typed
    // boundary open in both modes and must not grant protection.
    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(summaries),
    );
    let mut projected_budget = SemanticBudget::default();
    let projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &wrapped_root,
        &mut SemanticRequest::new(&mut projected_budget, &cancellation),
    )
    .expect("projected wrapper report computes");
    for report in [(&direct, "direct"), (&projected, "projected")] {
        let (report, mode) = report;
        assert!(
            report.reasons.iter().any(|reason| matches!(reason,
                brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
                if protocol.as_ref() == "try-acquire result is returned untested; its guard lives in a caller")),
            "the {mode} run must name the wrapper boundary: {report:#?}"
        );
        assert!(
            !report.conflicts.iter().any(|conflict| {
                conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::CompatibleLock
            }),
            "the {mode} run must not grant protection across the wrapper: {report:#?}"
        );
    }
}

/// The reviewed conditional-spawn protocol pack shared by the TryGo guard
/// tests: `golang.org/x/sync/errgroup.Group` with `Go` spawning
/// unconditionally, `Wait` joining the group, and `TryGo` spawning exactly
/// when the call's boolean result reports that it did (issue #3371).
const TRY_GO_GUARD_PACK: &[u8] = br#"{
  "schema_version": 2,
  "pack_id": "test.go.trygo-guard",
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
        },
        {
          "id": "member.7c1d0e5f9a8b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d",
          "owner": "type.0c4f21e4d6d55855f8189f63d90adcce32a1cd675cd25058d1416fba1c0a2927",
          "name": "TryGo", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "f", "type": { "kind": "named", "name": "func", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.TryGo" }
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
          "id": "errgroup.with-context",
          "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.WithContext(ctx context.Context)", "has_receiver": false, "parameter_count": 1 },
          "completeness": "complete",
          "normal_result_count": 2,
          "locations": [{ "id": "group", "location_kind": "heap" }],
          "transfers": [{ "input": { "kind": "parameter", "ordinal": 0 }, "exit_kind": "normal", "output": { "kind": "indexed_normal_return", "ordinal": 1 } }],
          "effects": [{ "kind": "allocation", "event": "group-allocation", "output": { "kind": "indexed_normal_return", "ordinal": 0 } }]
        },
        {
          "id": "errgroup.go",
          "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.Go(f func() error)", "has_receiver": true, "parameter_count": 1 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 0 }, "group": { "kind": "receiver" } }]
        },
        {
          "id": "errgroup.try-go",
          "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.TryGo(f func() error)", "has_receiver": true, "parameter_count": 1 },
          "completeness": "complete",
          "normal_result_count": 1,
          "transfers": [],
          "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 0 }, "group": { "kind": "receiver" }, "condition": "call_result_true" }]
        },
        {
          "id": "errgroup.wait",
          "target": { "path": "errgroup/errgroup.go", "symbol": "golang.org/x/sync/errgroup.Group.Wait()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "task_join", "group": { "kind": "receiver" } }]
        }
      ]
    }
  }]
}"#;

fn try_go_guard_snapshot(
    workspace: &WorkspaceAnalyzer,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    let pack = compile_source(
        SourceFormat::Json,
        TRY_GO_GUARD_PACK,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("TryGo guard pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-trygo-guard".to_owned(),
            },
        )
        .expect("register TryGo guard model pack");
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
    match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("TryGo guard models activate: {other:#?}"),
    }
}

#[test]
fn go_concurrent_access_conflicts_bind_try_go_results() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "golang.org/x/sync/errgroup"

func joinedRoot() int {
	group := &errgroup.Group{}
	joined := 0
	if group.TryGo(func() error { joined = 1; return nil }) {
		_ = group.Wait()
	}
	return joined
}

func falseBranchRoot() int {
	group := &errgroup.Group{}
	branched := 0
	if group.TryGo(func() error { branched = 1; return nil }) {
		_ = group.Wait()
	} else {
		branched = 2
	}
	return 0
}

func unjoinedRoot() int {
	group := &errgroup.Group{}
	unjoined := 0
	if group.TryGo(func() error { unjoined = 1; return nil }) {
		unjoined = 2
	}
	return 0
}

func wrongObjectRoot() int {
	group := &errgroup.Group{}
	other := &errgroup.Group{}
	displaced := 0
	if group.TryGo(func() error { displaced = 1; return nil }) {
		_ = other.Wait()
		displaced = 2
	}
	return 0
}

func unestablishedRoot() int {
	group := &errgroup.Group{}
	unestablished := 0
	started := group.TryGo(func() error { unestablished = 1; return nil })
	unestablished = 2
	if started {
		_ = group.Wait()
	}
	return 0
}

type spinner struct{ n int }

func (s *spinner) TryGo(f func() error) bool {
	s.n++
	return s.n%2 == 0
}

func sameNameRoot() int {
	spun := 0
	s := &spinner{}
	if s.TryGo(func() error { spun = 1; return nil }) {
		spun = 2
	}
	return 0
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = try_go_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("TryGo guard semantics materialize")
        .available_value()
        .cloned()
        .expect("TryGo guard semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        None,
    );
    let report = |name: &str| {
        let mut budget = SemanticBudget::default();
        brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &procedure(name),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("{name} report computes: {error}"))
    };

    // Positive: the guard establishes the spawn on the true edge and the join
    // covers the callback, so the callback write is ordered before the parent
    // read that only the established paths can reach.
    let positive = report("joinedRoot");
    assert!(
        positive.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the TryGo/Wait pair must order the callback write before the parent read: {positive:#?}"
    );
    assert!(
        !positive.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("TryGo"))),
        "the modeled protocol no longer opens an unsupported boundary: {positive:#?}"
    );

    // Wrong branch: the else arm establishes the result false, so the callback
    // never started on the path that writes there and the two writes cannot
    // run together.
    let wrong_branch = report("falseBranchRoot");
    assert!(
        !wrong_branch.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a write only the failed branch reaches cannot race the callback: {wrong_branch:#?}"
    );

    // No join: the callback starts on the established-true path and stays
    // unordered with the parent write there.
    let unjoined = report("unjoinedRoot");
    assert!(
        unjoined.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "an unjoined conditional spawn must stay a proven race: {unjoined:#?}"
    );

    // Wrong object: a join on another group does not cover this group's
    // callback.
    let wrong_object = report("wrongObjectRoot");
    assert!(
        wrong_object.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a join on a distinct group must not order this callback: {wrong_object:#?}"
    );

    // Incomplete: a result no structured guard tests establishes no spawn, so
    // the typed boundary keeps the answer open instead of inventing a task.
    let incomplete = report("unestablishedRoot");
    assert!(
        incomplete.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("try-spawn result is not established by a structured guard"))),
        "the unbound try-spawn result must keep its typed boundary: {incomplete:#?}"
    );
    assert!(
        !incomplete.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "no comparison may claim a task the established result does not start: {incomplete:#?}"
    );

    // Same name, wrong type: an unrelated TryGo method never binds the
    // reviewed errgroup protocol.
    let same_name = report("sameNameRoot");
    assert!(
        !same_name.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "an unrelated same-name method must not spawn a modeled task: {same_name:#?}"
    );
    assert!(
        !same_name.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("TryGo"))),
        "an unrelated same-name method is not the reviewed protocol: {same_name:#?}"
    );
}

#[test]
fn go_projected_summaries_retain_try_go_conditions() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "golang.org/x/sync/errgroup"

func tryGoJoinedBody(group *errgroup.Group) int {
	value := 0
	if group.TryGo(func() error { value = 1; return nil }) {
		_ = group.Wait()
	}
	return value
}

func summarizedRoot(group *errgroup.Group) int {
	return tryGoJoinedBody(group)
}

func tryGoThrough(group *errgroup.Group, f func() error) bool {
	return group.TryGo(f)
}

func forwardedRoot(group *errgroup.Group) int {
	value := 0
	if tryGoThrough(group, func() error { value = 1; return nil }) {
		_ = group.Wait()
	}
	return value
}

func ignoredTryGo(group *errgroup.Group, f func() error) {
	group.TryGo(f)
}

func tryGoInlineReturn(group *errgroup.Group, cell *int) bool {
	return group.TryGo(func() error { *cell = 1; return nil })
}

func inlineReturnRoot(group *errgroup.Group, cell *int) int {
	if tryGoInlineReturn(group, cell) {
		_ = group.Wait()
	}
	return *cell
}

func ignoredRoot(group *errgroup.Group) int {
	value := 0
	ignoredTryGo(group, func() error { value = 1; return nil })
	_ = group.Wait()
	return value
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = try_go_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let joined_body = procedure("tryGoJoinedBody");
    let summarized_root = procedure("summarizedRoot");
    let try_go_through = procedure("tryGoThrough");
    let forwarded_root = procedure("forwardedRoot");
    let ignored_try_go = procedure("ignoredTryGo");
    let inline_return_root = procedure("inlineReturnRoot");

    // Project production summaries for the wrapper closure and prove that a
    // wrapper keeps the conditional spawn, its join, and the formal callable
    // port through exact actual/formal substitution.
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    let projection_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let roots = [
        summarized_root.clone(),
        forwarded_root.clone(),
        joined_body.clone(),
        try_go_through.clone(),
        ignored_try_go.clone(),
    ];
    let mut projection_budget = SemanticBudget::default();
    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &mut SemanticRequest::new(&mut projection_budget, &cancellation),
        )
        .expect("wrapper summaries project");
    let body_summary = summaries
        .summary_for(&joined_body)
        .expect("the joined wrapper has a production summary");
    assert!(
        body_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskSpawn {
                        condition: brokk_bifrost_flow::dataflow::SummaryTaskSpawnCondition::CallResultTrue,
                        ..
                    }
                )
        )),
        "the joined wrapper must retain the call-result-true spawn: {body_summary:#?}"
    );
    assert!(
        body_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskJoin { .. }
                )
        )),
        "the joined wrapper must retain its join: {body_summary:#?}"
    );
    // The wrapper body keeps the guard and the join in one activation, so the
    // exact summary and the direct expansion agree on the ordered pair.
    let direct_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let mut direct_budget = SemanticBudget::default();
    let direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut direct_budget, &cancellation),
    )
    .expect("direct wrapper report computes");
    assert!(
        direct.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the wrapper body must order the callback write before the value read: {direct:#?}"
    );
    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(summaries),
    );
    let mut projected_budget = SemanticBudget::default();
    let projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut projected_budget, &cancellation),
    )
    .expect("projected wrapper report computes");
    assert_eq!(
        projected, direct,
        "fresh task summaries preserve the direct wrapper report"
    );

    // A wrapper that returns the modeled call's own result hands the guard to
    // its caller. Neither expansion mode can apply the caller's guard inside
    // the callee, so the boundary stays typed instead of granting an ordering
    // the callee cannot establish.
    let mut inline_budget = SemanticBudget::default();
    let inline_return = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &inline_return_root,
        &mut SemanticRequest::new(&mut inline_budget, &cancellation),
    )
    .expect("inline-return wrapper report computes");
    assert!(
        inline_return.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("try-spawn result is returned untested; its guard lives in a caller"))),
        "the returned result must name its caller guard boundary: {inline_return:#?}"
    );
    assert!(
        !inline_return.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "a returned result grants no ordering inside the callee: {inline_return:#?}"
    );

    // A forwarding wrapper returns the call's result untested to its own
    // caller, so neither expansion mode applies the guard: the boundary stays
    // typed instead of granting an ordering the callee cannot establish.
    let mut forwarded_budget = SemanticBudget::default();
    let forwarded = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &forwarded_root,
        &mut SemanticRequest::new(&mut forwarded_budget, &cancellation),
    )
    .expect("forwarding wrapper report computes");
    assert!(
        forwarded
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget),
        "a wrapper that forwards its callable keeps the typed callable boundary: {forwarded:#?}"
    );
    assert!(
        !forwarded.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "a forwarded result grants no ordering the callee cannot establish: {forwarded:#?}"
    );
}

/// The reviewed timer protocol pack shared by the timer stop tests:
/// `time.AfterFunc` spawning with its timer, `Timer.Stop` cancelling on a
/// true result, and `Timer.Reset` re-arming (issue #3382).
const TIMER_STOP_GUARD_PACK: &[u8] = br#"{
  "schema_version": 2,
  "pack_id": "test.go.timer-stop-guard",
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
          "id": "type.0e5eb8274d8a136652db26087e21a5a350ee36c3b7d9c47f2ffca11ec56d98e0",
          "name": "time", "type_kind": "module", "visibility": "package",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": ["time"], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/time/sleep.go", "symbol": "time" }
        },
        {
          "id": "type.093f2445cc8f7389a5299fa7e7d70ae8fadd6fa2291af0d0b16069cc3433b19f",
          "name": "time.Duration", "type_kind": "class", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/time/time.go", "symbol": "time.Duration" }
        },
        {
          "id": "type.2fd0aa06a7ead591780725343ef0ad1392e76f63c7759ee4578483f9badf438f",
          "name": "time.Timer", "type_kind": "struct", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/time/sleep.go", "symbol": "time.Timer" }
        }
      ],
      "members": [
        {
          "id": "member.348968f2fd5d260bd64344016c8075efec0787aeea2760759e5168da502c9f92",
          "owner": "type.0e5eb8274d8a136652db26087e21a5a350ee36c3b7d9c47f2ffca11ec56d98e0",
          "name": "AfterFunc", "member_kind": "function", "visibility": "public", "is_static": true,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "d", "type": { "kind": "declared", "id": "type.093f2445cc8f7389a5299fa7e7d70ae8fadd6fa2291af0d0b16069cc3433b19f", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "f", "type": { "kind": "named", "name": "func()", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "pointer", "element": { "kind": "declared", "id": "type.2fd0aa06a7ead591780725343ef0ad1392e76f63c7759ee4578483f9badf438f", "arguments": [], "nullable": false } } },
          "aliases": [],
          "locator": { "kind": "artifact", "path": "src/time/sleep.go", "symbol": "time.AfterFunc" }
        },
        {
          "id": "member.6ca7ee4ba1a9781805d964449cad26ea95aaa5ae7b613fb84ce056112268a09f",
          "owner": "type.2fd0aa06a7ead591780725343ef0ad1392e76f63c7759ee4578483f9badf438f",
          "name": "Stop", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/time/sleep.go", "symbol": "time.Timer.Stop" }
        },
        {
          "id": "member.ad262050e1892ca0cfefa1eb48f5bd50aed3de28f7d2c7893cbbe6d9be1e25ae",
          "owner": "type.2fd0aa06a7ead591780725343ef0ad1392e76f63c7759ee4578483f9badf438f",
          "name": "Reset", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "d", "type": { "kind": "declared", "id": "type.093f2445cc8f7389a5299fa7e7d70ae8fadd6fa2291af0d0b16069cc3433b19f", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/time/sleep.go", "symbol": "time.Timer.Reset" }
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
          "id": "time.after-func",
          "target": { "path": "src/time/sleep.go", "symbol": "time.AfterFunc(d time.Duration, f func())", "has_receiver": false, "parameter_count": 2 },
          "completeness": "complete",
          "normal_result_count": 1,
          "transfers": [],
          "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 1 }, "timer": { "kind": "indexed_normal_return", "ordinal": 0 } }]
        },
        {
          "id": "time.timer.stop",
          "target": { "path": "src/time/sleep.go", "symbol": "time.Timer.Stop()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete",
          "normal_result_count": 1,
          "ordinary_heap_unchanged": true,
          "transfers": [],
          "concurrency_effects": [{ "kind": "timer_stop", "timer": { "kind": "receiver" } }]
        },
        {
          "id": "time.timer.reset",
          "target": { "path": "src/time/sleep.go", "symbol": "time.Timer.Reset(d time.Duration)", "has_receiver": true, "parameter_count": 1 },
          "completeness": "complete",
          "normal_result_count": 1,
          "ordinary_heap_unchanged": true,
          "transfers": [],
          "concurrency_effects": [{ "kind": "timer_reset", "timer": { "kind": "receiver" } }]
        }
      ]
    }
  }]
}"#;

fn timer_stop_guard_snapshot(
    workspace: &WorkspaceAnalyzer,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    let pack = compile_source(
        SourceFormat::Json,
        TIMER_STOP_GUARD_PACK,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("timer stop guard pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-timer-stop-guard".to_owned(),
            },
        )
        .expect("register timer stop guard model pack");
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
    match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("timer stop guard models activate: {other:#?}"),
    }
}

#[test]
fn go_concurrent_access_conflicts_bind_timer_stop_results() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "time"

func spawnOrdersRoot() int {
	value := 0
	value = 1
	time.AfterFunc(0, func() { _ = value })
	return value
}

func unjoinedRoot() int {
	value := 0
	time.AfterFunc(0, func() { value = 1 })
	value = 2
	return value
}

func stopArmRoot() int {
	value := 0
	timer := time.AfterFunc(0, func() { value = 1 })
	if timer.Stop() {
		value = 2
	}
	return 0
}

func falseArmRoot() int {
	value := 0
	timer := time.AfterFunc(0, func() { value = 1 })
	if timer.Stop() {
		value = 2
	} else {
		value = 3
	}
	return 0
}

func wrongObjectRoot() int {
	value := 0
	timer := time.AfterFunc(0, func() { value = 1 })
	other := time.AfterFunc(0, func() {})
	if other.Stop() {
		value = 2
	}
	_ = timer
	return 0
}

func resetRoot() int {
	value := 0
	timer := time.AfterFunc(0, func() { value = 1 })
	if timer.Stop() {
		timer.Reset(0)
		value = 2
	}
	return 0
}

var sharedValue = 0

func sharedTarget() { sharedValue = 1 }

func sharedRoot() int {
	stopped := time.AfterFunc(0, sharedTarget)
	running := time.AfterFunc(0, sharedTarget)
	_ = running
	if stopped.Stop() {
		sharedValue = 2
	}
	return 0
}

type stopwatch struct{ stopped bool }

func (s *stopwatch) Stop() bool {
	s.stopped = true
	return s.stopped
}

func sameNameRoot() int {
	value := 0
	watch := &stopwatch{}
	time.AfterFunc(0, func() { value = 1 })
	if watch.Stop() {
		value = 2
	}
	return 0
}

func unresolvedRoot() int {
	value := 0
	var callback func()
	time.AfterFunc(0, callback)
	value = 2
	return value
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = timer_stop_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("timer stop guard semantics materialize")
        .available_value()
        .cloned()
        .expect("timer stop guard semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        None,
    );
    let report = |name: &str| {
        let mut budget = SemanticBudget::default();
        brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &procedure(name),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("{name} report computes: {error}"))
    };

    // Positive: the spawn edge orders a write before the call before the
    // callback's reads.
    let ordered = report("spawnOrdersRoot");
    assert!(
        ordered.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the AfterFunc spawn must order the write before the callback reads: {ordered:#?}"
    );

    // No stop: the callback stays unordered with the parent's later access,
    // because the returned timer is not a join.
    let unjoined = report("unjoinedRoot");
    assert!(
        unjoined.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "an unjoined timer callback must stay a proven race: {unjoined:#?}"
    );

    // Stop-true arm: the stopped callback never runs there, so the write
    // cannot race it.
    let stop_arm = report("stopArmRoot");
    assert!(
        !stop_arm.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a write only the stop-true arm reaches cannot race the callback: {stop_arm:#?}"
    );

    // False arm: the timer fired, so the callback may run with the write.
    let false_arm = report("falseArmRoot");
    assert!(
        false_arm.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "the stop-false arm must stay a proven race: {false_arm:#?}"
    );

    // Wrong object: stopping another timer cancels nothing for this callback.
    let wrong_object = report("wrongObjectRoot");
    assert!(
        wrong_object.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a stop on a distinct timer must not cancel this callback: {wrong_object:#?}"
    );

    // Reset: the stop-true arm re-arms the timer before writing, so the
    // callback may run again with the write.
    let reset = report("resetRoot");
    assert!(
        reset.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a reset after the stop must re-arm the proven race: {reset:#?}"
    );

    // Shared callback: stopping one timer leaves the same callback running
    // under the other.
    let shared = report("sharedRoot");
    assert!(
        shared.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "the callback running under the second timer must race the arm write: {shared:#?}"
    );

    // Same name, wrong type: an unrelated Stop method never binds the
    // reviewed timer protocol.
    let same_name = report("sameNameRoot");
    assert!(
        same_name.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "an unrelated same-name method must not cancel the modeled timer: {same_name:#?}"
    );

    // Incomplete: a callback the spawn cannot name keeps its typed boundary
    // instead of inventing a task.
    let incomplete = report("unresolvedRoot");
    assert!(
        incomplete
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget),
        "the unresolved callback must keep its typed boundary: {incomplete:#?}"
    );
    assert!(
        !incomplete.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "no comparison may claim a callback the spawn cannot name: {incomplete:#?}"
    );
}

#[test]
fn go_projected_summaries_retain_timer_stop_conditions() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "time"

func timerStopBody() int {
	value := 0
	timer := time.AfterFunc(0, func() { value = 1 })
	if timer.Stop() {
		value = 2
	}
	return 0
}

func summarizedTimerRoot() int {
	return timerStopBody()
}

func stopThrough(timer *time.Timer) bool {
	return timer.Stop()
}

func stopThroughRoot() int {
	value := 0
	timer := time.AfterFunc(0, func() { value = 1 })
	if stopThrough(timer) {
		value = 2
	}
	return 0
}

func ignoreStop(timer *time.Timer) {
	timer.Stop()
}

var scheduledValue = 0

func scheduleLiteral() *time.Timer {
	return time.AfterFunc(0, func() { scheduledValue = 1 })
}

func scheduleRoot() int {
	timer := scheduleLiteral()
	_ = timer
	return scheduledValue
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = timer_stop_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("timer wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("timer wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let stop_body = procedure("timerStopBody");
    let summarized_root = procedure("summarizedTimerRoot");
    let stop_through = procedure("stopThrough");
    let stop_through_root = procedure("stopThroughRoot");
    let ignore_stop = procedure("ignoreStop");
    let schedule_literal = procedure("scheduleLiteral");
    let schedule_root = procedure("scheduleRoot");

    // Project production summaries for the wrapper closure and prove that a
    // guard-consuming wrapper drops the spawn whose timer stays local, a
    // result-returning spawn wrapper keeps its spawn with the timer port, a
    // result-returning stop wrapper keeps its stop, and a discarding wrapper
    // drops the stop it cannot name.
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    let projection_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let roots = [
        summarized_root.clone(),
        stop_body.clone(),
        stop_through.clone(),
        stop_through_root.clone(),
        ignore_stop.clone(),
        schedule_literal.clone(),
        schedule_root.clone(),
    ];
    let mut projection_budget = SemanticBudget::default();
    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &mut SemanticRequest::new(&mut projection_budget, &cancellation),
        )
        .expect("timer wrapper summaries project");
    let body_summary = summaries
        .summary_for(&stop_body)
        .expect("the stop wrapper has a production summary");
    // The guard consumes the stop inside the body and the timer never
    // escapes, so the projection keeps no modeled rows at all and the live
    // model lookup keeps answering the body's own solve. There is no join:
    // the timer never joins its callback.
    assert!(
        !body_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskSpawn { .. }
                        | brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TimerStop { .. }
                        | brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskJoin { .. }
                )
        )),
        "the guard-consuming wrapper keeps no modeled rows and no join: {body_summary:#?}"
    );
    // A spawn wrapper that returns the modeled call's own timer keeps the
    // spawn with the timer port on its normal result.
    let schedule_summary = summaries
        .summary_for(&schedule_literal)
        .expect("the schedule wrapper has a production summary");
    assert!(
        schedule_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskSpawn {
                        timer: Some(timer),
                        ..
                    } if matches!(
                        timer.root(),
                        brokk_bifrost_flow::dataflow::SummaryPort::NormalReturn
                            | brokk_bifrost_flow::dataflow::SummaryPort::IndexedNormalReturn(0)
                    )
                )
        )),
        "the result-returning spawn wrapper must retain the spawn with its timer port: {schedule_summary:#?}"
    );
    // A wrapper that returns the modeled call's own result hands the stop to
    // its caller through the timer formal.
    let through_summary = summaries
        .summary_for(&stop_through)
        .expect("the stop-through wrapper has a production summary");
    assert!(
        through_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TimerStop {
                        timer,
                        ..
                    } if timer.root()
                        == &brokk_bifrost_flow::dataflow::SummaryPort::Parameter(0)
                )
        )),
        "the result-returning wrapper must retain the stop on its timer formal: {through_summary:#?}"
    );
    // A wrapper that discards the result drops the stop it cannot name, and
    // its callers keep the may-run answer instead of an invented exclusion.
    let ignore_summary = summaries
        .summary_for(&ignore_stop)
        .expect("the discarding wrapper has a production summary");
    assert!(
        !ignore_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TimerStop { .. }
                )
        )),
        "the discarding wrapper must not carry a stop it cannot name: {ignore_summary:#?}"
    );

    // The wrapper body holds the spawn and the guard in one activation, so
    // the exact summary and the direct expansion agree that the arm write
    // never races the callback.
    let direct_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let mut direct_budget = SemanticBudget::default();
    let direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut direct_budget, &cancellation),
    )
    .expect("direct timer wrapper report computes");
    assert!(
        !direct.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "the wrapper body must exclude the arm write from the callback: {direct:#?}"
    );
    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(summaries),
    );
    let mut projected_budget = SemanticBudget::default();
    let projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut projected_budget, &cancellation),
    )
    .expect("projected timer wrapper report computes");
    assert_eq!(
        projected, direct,
        "fresh task summaries preserve the direct timer wrapper report"
    );

    // A caller guard on a stop-through wrapper cannot bind inside the callee
    // yet, so both expansion modes keep the same answer instead of granting
    // an exclusion the callee cannot establish. Applying a callee's stop in
    // the caller's guard context is the remaining exact-wrapper work.
    let mut through_direct_budget = SemanticBudget::default();
    let through_direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &stop_through_root,
        &mut SemanticRequest::new(&mut through_direct_budget, &cancellation),
    )
    .expect("direct stop-through report computes");
    let mut through_projected_budget = SemanticBudget::default();
    let through_projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &stop_through_root,
        &mut SemanticRequest::new(&mut through_projected_budget, &cancellation),
    )
    .expect("projected stop-through report computes");
    assert_eq!(
        through_projected, through_direct,
        "fresh task summaries preserve the direct stop-through report"
    );

    // The schedule wrapper returns its timer but stops nothing, so the
    // callback stays unordered with the root's read in both modes.
    let mut schedule_direct_budget = SemanticBudget::default();
    let schedule_direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &schedule_root,
        &mut SemanticRequest::new(&mut schedule_direct_budget, &cancellation),
    )
    .expect("direct schedule report computes");
    assert!(
        schedule_direct.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "an unstopped scheduled callback must stay a proven race: {schedule_direct:#?}"
    );
    let mut schedule_projected_budget = SemanticBudget::default();
    let schedule_projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &schedule_root,
        &mut SemanticRequest::new(&mut schedule_projected_budget, &cancellation),
    )
    .expect("projected schedule report computes");
    assert_eq!(
        schedule_projected, schedule_direct,
        "fresh task summaries preserve the direct schedule report"
    );
}

const SUBTEST_GUARD_PACK: &[u8] = br#"{
  "schema_version": 2,
  "pack_id": "test.go.subtest-guard",
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
          "id": "type.test.subtest.module",
          "name": "testing", "type_kind": "module", "visibility": "package",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": ["testing"], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing" }
        },
        {
          "id": "type.test.subtest.t",
          "name": "testing.T", "type_kind": "struct", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing.T" }
        }
      ],
      "members": [
        {
          "id": "member.test.subtest.t.run",
          "owner": "type.test.subtest.t",
          "name": "Run", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "name", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "f", "type": { "kind": "named", "name": "func", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing.T.Run" }
        },
        {
          "id": "member.test.subtest.t.parallel",
          "owner": "type.test.subtest.t",
          "name": "Parallel", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing.T.Parallel" }
        },
        {
          "id": "member.test.subtest.t.cleanup",
          "owner": "type.test.subtest.t",
          "name": "Cleanup", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "f", "type": { "kind": "named", "name": "func", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing.T.Cleanup" }
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
          "id": "testing.t.run",
          "target": { "path": "src/testing/testing.go", "symbol": "testing.T.Run(name string, f func)", "has_receiver": true, "parameter_count": 2 },
          "completeness": "complete",
          "normal_result_count": 1,
          "transfers": [],
          "concurrency_effects": [{ "kind": "subtest_run", "callable": { "kind": "parameter", "ordinal": 1 }, "group": { "kind": "receiver" } }]
        },
        {
          "id": "testing.t.parallel",
          "target": { "path": "src/testing/testing.go", "symbol": "testing.T.Parallel()", "has_receiver": true, "parameter_count": 0 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "subtest_parallel", "receiver": { "kind": "receiver" } }]
        },
        {
          "id": "testing.t.cleanup",
          "target": { "path": "src/testing/testing.go", "symbol": "testing.T.Cleanup(f func)", "has_receiver": true, "parameter_count": 1 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "subtest_cleanup", "callable": { "kind": "parameter", "ordinal": 0 }, "group": { "kind": "receiver" } }]
        }
      ]
    }
  }]
}"#;

fn subtest_guard_snapshot(
    workspace: &WorkspaceAnalyzer,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    subtest_snapshot_from_pack(workspace, SUBTEST_GUARD_PACK, "test:go-subtest-guard")
}

fn subtest_snapshot_from_pack(
    workspace: &WorkspaceAnalyzer,
    pack_bytes: &[u8],
    source_id: &str,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    let pack = compile_source(SourceFormat::Json, pack_bytes, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("subtest guard pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: source_id.to_owned(),
            },
        )
        .expect("register subtest guard model pack");
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
    match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("subtest guard models activate: {other:#?}"),
    }
}

#[test]
fn go_concurrent_access_conflicts_models_subtests() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "testing"

var shared = 0

func parallelRaceRoot(t *testing.T) {
	t.Run("a", func(st *testing.T) {
		st.Parallel()
		shared = 1
	})
	t.Run("b", func(st *testing.T) {
		st.Parallel()
		shared = 2
	})
}

func sequentialRoot(t *testing.T) {
	t.Run("a", func(st *testing.T) {
		shared = 1
	})
	t.Run("b", func(st *testing.T) {
		shared = 2
	})
}

func parentAfterRunRoot(t *testing.T) {
	t.Run("a", func(st *testing.T) {
		shared = 1
	})
	shared = 2
}

func conditionalRoot(t *testing.T, flag bool) {
	t.Run("a", func(st *testing.T) {
		if flag {
			st.Parallel()
		}
		shared = 1
	})
	t.Run("b", func(st *testing.T) {
		st.Parallel()
		shared = 2
	})
}

func sharedBody(st *testing.T) {
	shared = 1
}

func sharedCallableRoot(t *testing.T) {
	t.Run("a", sharedBody)
	t.Run("b", sharedBody)
}

func cleanupRoot(t *testing.T) {
	t.Run("a", func(st *testing.T) {
		shared = 1
	})
	t.Run("b", func(st *testing.T) {
		shared = 2
	})
	t.Cleanup(func() {
		_ = shared
	})
}

type runner struct{ n int }

func (r *runner) Run(name string, f func(t *testing.T)) bool {
	r.n++
	f(nil)
	return r.n%2 == 0
}

func sameNameRoot(t *testing.T) {
	r := &runner{}
	shared = 0
	r.Run("a", func(st *testing.T) {
		shared = 1
	})
	shared = 2
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = subtest_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("subtest semantics materialize")
        .available_value()
        .cloned()
        .expect("subtest semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        None,
    );
    let report = |name: &str| {
        let mut budget = SemanticBudget::default();
        brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &procedure(name),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("{name} report computes: {error}"))
    };

    // Positive: two parallel subtests of one parent may run together, so
    // their writes to one package variable are a proven race.
    let parallel = report("parallelRaceRoot");
    assert!(
        parallel.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "two parallel subtests writing one variable must race: {parallel:#?}"
    );

    // Sequential: each Run joins its subtest, so the two writes are ordered
    // and the report explains the join.
    let sequential = report("sequentialRoot");
    assert!(
        !sequential.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "two sequential subtests never overlap: {sequential:#?}"
    );
    assert!(
        sequential.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the Run join must order the sequential subtests: {sequential:#?}"
    );

    // A parent write after a non-parallel Run is ordered after the subtest.
    let parent = report("parentAfterRunRoot");
    assert!(
        !parent.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "the Run join covers the subtest write: {parent:#?}"
    );
    assert!(
        parent.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the Run join must order the subtest before the parent write: {parent:#?}"
    );

    // Conditional: a Parallel call on some paths but not others keeps the
    // typed boundary instead of guessing a task.
    let conditional = report("conditionalRoot");
    assert!(
        conditional.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("subtest Parallel is conditional or unresolved"))),
        "the conditional Parallel must keep its typed boundary: {conditional:#?}"
    );
    assert!(
        !conditional.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "no comparison may claim a race the classification does not establish: {conditional:#?}"
    );

    // One named callback shared by two sequential Runs still joins each call.
    let shared = report("sharedCallableRoot");
    assert!(
        !shared.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a shared sequential callback still joins each Run: {shared:#?}"
    );

    // Cleanup: the registered callback runs after the subtests complete.
    let cleanup = report("cleanupRoot");
    assert!(
        !cleanup.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "Cleanup runs after the subtests complete: {cleanup:#?}"
    );
    assert!(
        cleanup.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the subtree join must order the subtests before the Cleanup read: {cleanup:#?}"
    );

    // Same name, wrong type: an unrelated Run method never binds the
    // reviewed testing protocol.
    let same_name = report("sameNameRoot");
    assert!(
        !same_name.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "an unrelated same-name method must not spawn a modeled task: {same_name:#?}"
    );
    assert!(
        !same_name.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("subtest"))),
        "an unrelated same-name method is not the reviewed protocol: {same_name:#?}"
    );
}

const SUBTEST_RUN_WITHOUT_PARALLEL_PACK: &[u8] = br#"{
  "schema_version": 2,
  "pack_id": "test.go.subtest-run-without-parallel",
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
          "id": "type.test.subtest.module",
          "name": "testing", "type_kind": "module", "visibility": "package",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": ["testing"], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing" }
        },
        {
          "id": "type.test.subtest.t",
          "name": "testing.T", "type_kind": "struct", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing.T" }
        }
      ],
      "members": [
        {
          "id": "member.test.subtest.t.run",
          "owner": "type.test.subtest.t",
          "name": "Run", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "name", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "f", "type": { "kind": "named", "name": "func", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "bool", "arguments": [], "nullable": false } },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/testing/testing.go", "symbol": "testing.T.Run" }
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
          "id": "testing.t.run",
          "target": { "path": "src/testing/testing.go", "symbol": "testing.T.Run(name string, f func)", "has_receiver": true, "parameter_count": 2 },
          "completeness": "complete",
          "normal_result_count": 1,
          "transfers": [],
          "concurrency_effects": [{ "kind": "subtest_run", "callable": { "kind": "parameter", "ordinal": 1 }, "group": { "kind": "receiver" } }]
        }
      ]
    }
  }]
}"#;

#[test]
fn go_subtest_run_without_parallel_keeps_its_typed_boundary() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "testing"

var shared = 0

func incoherentRoot(t *testing.T) {
	t.Run("a", func(st *testing.T) {
		shared = 1
	})
	shared = 2
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = subtest_snapshot_from_pack(
        &workspace,
        SUBTEST_RUN_WITHOUT_PARALLEL_PACK,
        "test:go-subtest-run-without-parallel",
    );

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("subtest semantics materialize")
        .available_value()
        .cloned()
        .expect("subtest semantics are available");
    let procedure = artifact
        .procedures()
        .iter()
        .find(|candidate| {
            candidate
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("incoherentRoot")
        })
        .and_then(|row| artifact.procedure_handle(row.id()))
        .expect("missing incoherentRoot");
    let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        None,
    );
    let mut budget = SemanticBudget::default();
    let report = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &provider,
        &procedure,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("incoherent report computes");

    // A Run model without its Parallel model cannot classify any callback,
    // so the Run stays unbound with a typed reason instead of reading every
    // parallel callback as sequential and hiding its races.
    assert!(
        report.reasons.iter().any(|reason| matches!(reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
            if protocol.contains("subtest Run is modeled but Parallel is not"))),
        "the incoherent pack must name its missing model: {report:#?}"
    );
    assert!(
        !report.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "no comparison may claim a race the missing model cannot establish: {report:#?}"
    );
}

#[test]
fn go_projected_summaries_retain_subtest_effects() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "testing"

var shared = 0

func runJoinedBody(t *testing.T) {
	t.Run("a", func(st *testing.T) {
		shared = 1
	})
	shared = 2
}

func summarizedRoot(t *testing.T) {
	runJoinedBody(t)
}

func runThrough(t *testing.T, name string, f func(*testing.T)) bool {
	return t.Run(name, f)
}

func forwardedRoot(t *testing.T) {
	shared = 0
	runThrough(t, "a", func(st *testing.T) {
		shared = 1
	})
	shared = 2
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = subtest_guard_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let joined_body = procedure("runJoinedBody");
    let summarized_root = procedure("summarizedRoot");
    let run_through = procedure("runThrough");
    let forwarded_root = procedure("forwardedRoot");

    // Project production summaries for the wrapper closure and prove that a
    // wrapper keeps the subtest spawn and its group through exact
    // actual/formal substitution.
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    let projection_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let roots = [
        summarized_root.clone(),
        forwarded_root.clone(),
        joined_body.clone(),
        run_through.clone(),
    ];
    let mut projection_budget = SemanticBudget::default();
    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &mut SemanticRequest::new(&mut projection_budget, &cancellation),
        )
        .expect("wrapper summaries project");
    let body_summary = summaries
        .summary_for(&joined_body)
        .expect("the joined wrapper has a production summary");
    assert!(
        body_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::SubtestRun { .. }
                )
        )),
        "the joined wrapper must retain the subtest spawn: {body_summary:#?}"
    );
    // The wrapper body holds the Run and the parent write in one activation,
    // so the exact summary and the direct expansion agree on the ordered pair.
    let direct_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let mut direct_budget = SemanticBudget::default();
    let direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut direct_budget, &cancellation),
    )
    .expect("direct wrapper report computes");
    assert!(
        direct.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the wrapper body must order the subtest write before the parent write: {direct:#?}"
    );
    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(summaries),
    );
    let mut projected_budget = SemanticBudget::default();
    let projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut projected_budget, &cancellation),
    )
    .expect("projected wrapper report computes");
    // Replayed summary accesses enumerate in a different position than
    // directly expanded ones, so the shared pair lists its sites in the
    // opposite order. The pair, its verdicts, and the report reasons must
    // still agree exactly.
    assert_eq!(
        projected.conflicts.len(),
        direct.conflicts.len(),
        "fresh task summaries preserve the direct wrapper pairs: {projected:#?} vs {direct:#?}"
    );
    for conflict in &direct.conflicts {
        assert!(
            projected.conflicts.iter().any(|candidate| {
                candidate.location == conflict.location
                    && candidate.task_relation == conflict.task_relation
                    && candidate.ordering == conflict.ordering
                    && candidate.protection == conflict.protection
                    && candidate.proven == conflict.proven
                    && candidate.exhaustive == conflict.exhaustive
                    && candidate.reasons == conflict.reasons
                    && ((candidate.first == conflict.first && candidate.second == conflict.second)
                        || (candidate.first == conflict.second
                            && candidate.second == conflict.first))
            }),
            "fresh task summaries preserve the direct wrapper pair: {projected:#?} vs {direct:#?}"
        );
    }
    assert_eq!(
        projected.reasons, direct.reasons,
        "fresh task summaries preserve the direct wrapper reasons"
    );

    // A wrapper that forwards its callable as a formal parameter cannot name
    // the callback's targets, so the caller keeps the typed callable
    // boundary instead of an ordering the wrapper cannot establish.
    let mut forwarded_budget = SemanticBudget::default();
    let forwarded = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &forwarded_root,
        &mut SemanticRequest::new(&mut forwarded_budget, &cancellation),
    )
    .expect("forwarding wrapper report computes");
    assert!(
        forwarded
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget),
        "a wrapper that forwards its callable keeps the typed callable boundary: {forwarded:#?}"
    );
    assert!(
        !forwarded.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "a forwarded callable grants no ordering the wrapper cannot establish: {forwarded:#?}"
    );
}

/// The reviewed `net/http` handler-registration protocol pack shared by the
/// handler tests: `http.HandleFunc` and `(*http.ServeMux).HandleFunc` spawn
/// an unbounded handler task with no join, `http.NewServeMux` constructs the
/// receiver, and the `http.Handler` interface forms name the typed
/// `net/http.Handler` boundary (issue #3408).
const HTTP_HANDLER_PACK: &[u8] = br#"{
  "schema_version": 2,
  "pack_id": "test.go.http-handler",
  "version": "1.0.0",
  "producer": { "name": "test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.11.3, <1.0.0", "toolchains": [] },
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
          "id": "type.b6eedc642c6132236bae5425a063fd44b150a8ea8555340b10ef1d3082dffe9a",
          "name": "net/http", "type_kind": "module", "visibility": "package",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": ["http"], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http" }
        },
        {
          "id": "type.93777606d63fbb9dc04087a876b5408f323d632fb8ff469033fa91b384dfd9cc",
          "name": "net/http.Handler", "type_kind": "interface", "visibility": "public",
          "is_abstract": true, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.Handler" }
        },
        {
          "id": "type.4c393b735855228a04f3c05bd17a970f4301acda0f7c16507fe4453daa72660b",
          "name": "net/http.ServeMux", "type_kind": "struct", "visibility": "public",
          "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
          "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
          "hierarchy": [], "aliases": [], "extension_surfaces": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.ServeMux" }
        }
      ],
      "members": [
        {
          "id": "member.9af6dc214e864d397e406b8857431d9aefac5766686e6d4d95adb3a67c494f10",
          "owner": "type.b6eedc642c6132236bae5425a063fd44b150a8ea8555340b10ef1d3082dffe9a",
          "name": "NewServeMux", "member_kind": "function", "visibility": "public", "is_static": true,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [], "returns": { "kind": "pointer", "element": { "kind": "declared", "id": "type.4c393b735855228a04f3c05bd17a970f4301acda0f7c16507fe4453daa72660b", "arguments": [], "nullable": false } } },
          "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.NewServeMux" }
        },
        {
          "id": "member.f7c17b594b5859f3dbea72f9e2190c4603ea8d4baadebf6f898bbdc08ef3a7a3",
          "owner": "type.b6eedc642c6132236bae5425a063fd44b150a8ea8555340b10ef1d3082dffe9a",
          "name": "HandleFunc", "member_kind": "function", "visibility": "public", "is_static": true,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "pattern", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "handler", "type": { "kind": "named", "name": "func(net/http.ResponseWriter,*net/http.Request)", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
          "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.HandleFunc" }
        },
        {
          "id": "member.a8b0914462fd948fbe3642097fe5e048c3614c50ec5556ad0dab49ea13ff3dfa",
          "owner": "type.b6eedc642c6132236bae5425a063fd44b150a8ea8555340b10ef1d3082dffe9a",
          "name": "Handle", "member_kind": "function", "visibility": "public", "is_static": true,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "pattern", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "handler", "type": { "kind": "named", "name": "net/http.Handler", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
          "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.Handle" }
        },
        {
          "id": "member.394649d2d0cefee027325c02c6cab04ae0035f4c17fabbbe8b193a0b5beed09a",
          "owner": "type.b6eedc642c6132236bae5425a063fd44b150a8ea8555340b10ef1d3082dffe9a",
          "name": "Serve", "member_kind": "function", "visibility": "public", "is_static": true,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "l", "type": { "kind": "named", "name": "net.Listener", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "handler", "type": { "kind": "named", "name": "net/http.Handler", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "error", "arguments": [], "nullable": false } },
          "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.Serve" }
        },
        {
          "id": "member.55c4eccff19fc50b68ff06dabf0c12527a27850d0e6a43f7793bab40e04f2124",
          "owner": "type.b6eedc642c6132236bae5425a063fd44b150a8ea8555340b10ef1d3082dffe9a",
          "name": "ListenAndServe", "member_kind": "function", "visibility": "public", "is_static": true,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "addr", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "handler", "type": { "kind": "named", "name": "net/http.Handler", "arguments": [], "nullable": false }, "optional": false, "variadic": false }], "returns": { "kind": "named", "name": "error", "arguments": [], "nullable": false } },
          "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.ListenAndServe" }
        },
        {
          "id": "member.54c86563d13dead12ac400f2e7ddf30b55152059bfd39bebf7b8cdc659b95768",
          "owner": "type.4c393b735855228a04f3c05bd17a970f4301acda0f7c16507fe4453daa72660b",
          "name": "HandleFunc", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "pattern", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "handler", "type": { "kind": "named", "name": "func(net/http.ResponseWriter,*net/http.Request)", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.ServeMux.HandleFunc" }
        },
        {
          "id": "member.b9bc67c1cc6e6c9efce3e637210d2e5357fa90a6c70ebe2ec348b658f5b11ffc",
          "owner": "type.4c393b735855228a04f3c05bd17a970f4301acda0f7c16507fe4453daa72660b",
          "name": "Handle", "member_kind": "method", "visibility": "public", "is_static": false,
          "is_abstract": false, "is_virtual": false,
          "signature": { "type_parameters": [], "parameters": [{ "name": "pattern", "type": { "kind": "named", "name": "string", "arguments": [], "nullable": false }, "optional": false, "variadic": false }, { "name": "handler", "type": { "kind": "named", "name": "net/http.Handler", "arguments": [], "nullable": false }, "optional": false, "variadic": false }] },
          "receiver": { "pointer": true }, "aliases": [],
          "locator": { "kind": "artifact", "path": "src/net/http/server.go", "symbol": "net/http.ServeMux.Handle" }
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
          "id": "net-http.handle-func",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.HandleFunc(pattern string, handler func(net/http.ResponseWriter, *net/http.Request))", "has_receiver": false, "parameter_count": 2 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 1 } }]
        },
        {
          "id": "net-http.serve-mux.handle-func",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.ServeMux.HandleFunc(pattern string, handler func(net/http.ResponseWriter, *net/http.Request))", "has_receiver": true, "parameter_count": 2 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "task_spawn", "callable": { "kind": "parameter", "ordinal": 1 } }]
        },
        {
          "id": "net-http.new-serve-mux",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.NewServeMux()", "has_receiver": false, "parameter_count": 0 },
          "completeness": "complete",
          "normal_result_count": 1,
          "locations": [{ "id": "net-http.new-serve-mux.mux", "location_kind": "heap" }],
          "transfers": [],
          "effects": [{ "kind": "allocation", "event": "net-http.new-serve-mux.allocation", "output": { "kind": "indexed_normal_return", "ordinal": 0 } }]
        },
        {
          "id": "net-http.handle",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.Handle(pattern string, handler net/http.Handler)", "has_receiver": false, "parameter_count": 2 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "unsupported", "protocol": "net/http.Handler" }]
        },
        {
          "id": "net-http.serve-mux.handle",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.ServeMux.Handle(pattern string, handler net/http.Handler)", "has_receiver": true, "parameter_count": 2 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "unsupported", "protocol": "net/http.Handler" }]
        },
        {
          "id": "net-http.serve",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.Serve(l net.Listener, handler net/http.Handler)", "has_receiver": false, "parameter_count": 2 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "unsupported", "protocol": "net/http.Handler" }]
        },
        {
          "id": "net-http.listen-and-serve",
          "target": { "path": "src/net/http/server.go", "symbol": "net/http.ListenAndServe(addr string, handler net/http.Handler)", "has_receiver": false, "parameter_count": 2 },
          "completeness": "complete",
          "transfers": [],
          "concurrency_effects": [{ "kind": "unsupported", "protocol": "net/http.Handler" }]
        }
      ]
    }
  }]
}"#;

fn http_handler_snapshot(
    workspace: &WorkspaceAnalyzer,
) -> std::sync::Arc<ActiveSemanticModelSnapshot> {
    let pack = compile_source(
        SourceFormat::Json,
        HTTP_HANDLER_PACK,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("http handler pack compiles: {diagnostics:#?}"));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("ephemeral semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:go-http-handler".to_owned(),
            },
        )
        .expect("register http handler model pack");
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
    match activation {
        SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
        other => panic!("http handler models activate: {other:#?}"),
    }
}

/// The handler fixtures shared by the protocol test: one root per modeled
/// clause.
const HTTP_HANDLER_SOURCE: &str = r#"package main

import "net/http"

var sharedValue = 0

func handlerA(w http.ResponseWriter, r *http.Request) { sharedValue = 1 }

func handlerB(w http.ResponseWriter, r *http.Request) { sharedValue = 2 }

func twoHandlersRoot() {
	http.HandleFunc("/a", handlerA)
	http.HandleFunc("/b", handlerB)
}

func muxHandlersRoot() {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", handlerA)
	mux.HandleFunc("/b", handlerB)
}

func postRegistrationRoot() int {
	http.HandleFunc("/a", handlerA)
	sharedValue = 3
	return sharedValue
}

var orderedValue = 0

func orderedReader(w http.ResponseWriter, r *http.Request) { _ = orderedValue }

func orderedRoot() int {
	orderedValue = 1
	http.HandleFunc("/r", orderedReader)
	return 0
}

type localMux struct{}

func (m *localMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
}

func sameNameRoot() int {
	mux := &localMux{}
	mux.HandleFunc("/a", handlerA)
	sharedValue = 3
	return sharedValue
}

func unresolvedRoot() int {
	var h func(http.ResponseWriter, *http.Request)
	http.HandleFunc("/u", h)
	sharedValue = 3
	return sharedValue
}

type sharedHandler struct{}

func (sharedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { sharedValue = 1 }

func interfaceRoot() int {
	mux := http.NewServeMux()
	var h http.Handler = sharedHandler{}
	mux.Handle("/a", h)
	mux.Handle("/b", h)
	sharedValue = 3
	return sharedValue
}

func serveRoot() int {
	var h http.Handler
	http.ListenAndServe(":8080", h)
	sharedValue = 3
	return sharedValue
}
"#;

#[test]
fn go_concurrent_access_conflicts_bind_http_handler_registrations() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", HTTP_HANDLER_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = http_handler_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("http handler semantics materialize")
        .available_value()
        .cloned()
        .expect("http handler semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot),
        None,
    );
    let report = |name: &str| {
        let mut budget = SemanticBudget::default();
        brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &procedure(name),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("{name} report computes: {error}"))
    };
    let proven_unordered = |name: &str| {
        report(name).conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        })
    };

    // Positive: two handlers registered on the default mux write one shared
    // variable from concurrent request goroutines.
    assert!(
        proven_unordered("twoHandlersRoot"),
        "two registered handlers must race on the shared variable: {:#?}",
        report("twoHandlersRoot")
    );

    // Positive: the ServeMux method form binds through the NewServeMux
    // receiver the declarations describe.
    assert!(
        proven_unordered("muxHandlersRoot"),
        "two mux-registered handlers must race on the shared variable: {:#?}",
        report("muxHandlersRoot")
    );

    // Positive: no net/http API joins the handler, so the registering
    // function's later write races the handler.
    assert!(
        proven_unordered("postRegistrationRoot"),
        "the handler must race the post-registration write: {:#?}",
        report("postRegistrationRoot")
    );

    // Ordering: the registration is the spawn edge, so a write before it is
    // ordered before the handler's reads.
    let ordered = report("orderedRoot");
    assert!(
        ordered.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::HappensBefore
        }),
        "the registration must order the earlier write before the handler reads: {ordered:#?}"
    );
    assert!(
        !ordered.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "an ordered write cannot race the handler: {ordered:#?}"
    );

    // Same name, wrong type: an unrelated HandleFunc method binds no reviewed
    // summary, so its argument never becomes a modeled task.
    let same_name = report("sameNameRoot");
    assert!(
        !same_name.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "a same-name method on another type spawns no modeled handler: {same_name:#?}"
    );

    // Incomplete: a handler value the registration cannot name keeps its
    // typed boundary instead of inventing a task.
    let incomplete = report("unresolvedRoot");
    assert!(
        incomplete
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget),
        "the unresolved handler value must keep its typed boundary: {incomplete:#?}"
    );
    assert!(
        !incomplete.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "no comparison may claim a handler the registration cannot name: {incomplete:#?}"
    );

    // Boundary: one handler value shared by two routes through the
    // http.Handler interface form names the typed boundary; the model does
    // not resolve the ServeHTTP dispatch, so no handler task is proven.
    let interface = report("interfaceRoot");
    assert!(
        interface.reasons.iter().any(|reason| matches!(
            reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
                if protocol.as_ref() == "net/http.Handler"
        )),
        "the interface registration must name the net/http.Handler boundary: {interface:#?}"
    );
    assert!(
        !interface.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "the unresolved interface dispatch proves no handler task: {interface:#?}"
    );

    // Boundary: ListenAndServe passes its handler through the same interface
    // form and names the same boundary.
    let serve = report("serveRoot");
    assert!(
        serve.reasons.iter().any(|reason| matches!(
            reason,
            brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnsupportedSynchronization(protocol)
                if protocol.as_ref() == "net/http.Handler"
        )),
        "ListenAndServe must name the net/http.Handler boundary: {serve:#?}"
    );
    assert!(
        !serve.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
        }),
        "ListenAndServe proves no handler task through the interface: {serve:#?}"
    );
}

#[test]
fn go_projected_summaries_retain_http_handler_spawns() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            r#"package main

import "net/http"

var sharedValue = 0

func handlerA(w http.ResponseWriter, r *http.Request) { sharedValue = 1 }

func registerRoutes() {
	http.HandleFunc("/a", handlerA)
}

func summarizedRoot() int {
	registerRoutes()
	sharedValue = 2
	return sharedValue
}

func forwardHandler(h func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc("/f", h)
}

func forwardedRoot() int {
	forwardHandler(handlerA)
	sharedValue = 3
	return sharedValue
}
"#,
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let snapshot = http_handler_snapshot(&workspace);

    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("main.go"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("http wrapper semantics materialize")
        .available_value()
        .cloned()
        .expect("http wrapper semantics are available");
    let procedure = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|row| artifact.procedure_handle(row.id()))
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let register_routes = procedure("registerRoutes");
    let summarized_root = procedure("summarizedRoot");
    let forward_handler = procedure("forwardHandler");
    let forwarded_root = procedure("forwardedRoot");

    // Project production summaries for the wrapper closure and prove that a
    // routes helper keeps its unbounded handler spawn through exact
    // actual/formal substitution, while a wrapper that forwards its callable
    // formal keeps the typed callable boundary.
    let icfg =
        crate::analyzer::semantic::WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &workspace,
            Some(snapshot.clone()),
        );
    let projection_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let roots = [
        summarized_root.clone(),
        register_routes.clone(),
        forward_handler.clone(),
        forwarded_root.clone(),
    ];
    let mut projection_budget = SemanticBudget::default();
    let summaries =
        brokk_bifrost_flow::typestate::project_production_semantic_summaries_with_concurrency(
            &roots,
            &icfg,
            &projection_provider,
            &mut SemanticRequest::new(&mut projection_budget, &cancellation),
        )
        .expect("http wrapper summaries project");
    let routes_summary = summaries
        .summary_for(&register_routes)
        .expect("the routes helper has a production summary");
    assert!(
        routes_summary.effects().iter().any(|effect| matches!(
            effect.key(),
            brokk_bifrost_flow::dataflow::SummaryEffectKey::Concurrency(effect)
                if matches!(
                    effect.kind(),
                    brokk_bifrost_flow::dataflow::SummaryConcurrencyEffectKind::TaskSpawn {
                        condition: brokk_bifrost_flow::dataflow::SummaryTaskSpawnCondition::Unconditional,
                        group: None,
                        timer: None,
                        ..
                    }
                )
        )),
        "the routes helper must retain its unbounded handler spawn with no join: {routes_summary:#?}"
    );

    // The helper holds the registration in one activation, so the exact
    // summary and the direct expansion agree that the handler races the
    // caller's later write.
    let direct_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        None,
    );
    let mut direct_budget = SemanticBudget::default();
    let direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut direct_budget, &cancellation),
    )
    .expect("direct http wrapper report computes");
    assert!(
        direct.conflicts.iter().any(|conflict| {
            conflict.proven
                && conflict.exhaustive
                && conflict.ordering
                    == brokk_bifrost_flow::concurrency::ConcurrentOrdering::Unordered
                && conflict.protection
                    == brokk_bifrost_flow::concurrency::ConcurrentProtection::Unprotected
        }),
        "the helper-registered handler must race the caller's later write: {direct:#?}"
    );
    let projected_provider = super::super::concurrency::WorkspaceConcurrencyProvider::new(
        &workspace,
        Some(snapshot.clone()),
        Some(summaries),
    );
    let mut projected_budget = SemanticBudget::default();
    let projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &summarized_root,
        &mut SemanticRequest::new(&mut projected_budget, &cancellation),
    )
    .expect("projected http wrapper report computes");
    assert_eq!(
        projected, direct,
        "fresh task summaries preserve the direct http wrapper report"
    );

    // A wrapper that forwards its callable formal cannot name the handler on
    // its summary boundary, so both expansion modes keep the typed callable
    // boundary instead of inventing a task.
    let mut forwarded_direct_budget = SemanticBudget::default();
    let forwarded_direct = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &direct_provider,
        &forwarded_root,
        &mut SemanticRequest::new(&mut forwarded_direct_budget, &cancellation),
    )
    .expect("direct forwarded report computes");
    assert!(
        forwarded_direct
            .reasons
            .contains(&brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::UnresolvedTarget),
        "a wrapper that forwards its callable keeps the typed callable boundary: {forwarded_direct:#?}"
    );
    let mut forwarded_projected_budget = SemanticBudget::default();
    let forwarded_projected = brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
        &projected_provider,
        &forwarded_root,
        &mut SemanticRequest::new(&mut forwarded_projected_budget, &cancellation),
    )
    .expect("projected forwarded report computes");
    assert_eq!(
        forwarded_projected, forwarded_direct,
        "fresh task summaries preserve the direct forwarded report"
    );
}
