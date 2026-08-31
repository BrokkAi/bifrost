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
        "schema_version": 1,
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
        "schema_version": 1,
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

    let query = CodeQuery::from_json(&json!({
        "languages": ["go"],
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": operation }
        ],
        "result_detail": "full"
    }))
    .expect("conditional result-contract use query");
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

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
        "schema_version": 1,
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
        "schema_version": 1,
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
fn captured_member_argument_mutation_does_not_preserve_modeled_validation() {
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

    assert_single_open_unknown_result_contract(&result);
}

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
fn later_capture_does_not_hide_an_earlier_direct_result_use() {
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
    assert_eq!(value.result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.unguarded_result_use_count, Some(1), "{value:#?}");
    assert_eq!(value.use_validation, Some("violated"), "{value:#?}");
    assert_eq!(value.use_validation_coverage, Some("open"), "{value:#?}");
}

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
        "schema_version": 1,
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
        "schema_version": 1,
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
