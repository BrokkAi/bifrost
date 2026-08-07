use super::contracts::assert_serial_profile_reconciles;
use super::*;

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
