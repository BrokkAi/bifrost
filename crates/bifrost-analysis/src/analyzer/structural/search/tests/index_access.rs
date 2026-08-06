use super::*;

#[test]
fn value_flow_registration_failures_keep_their_domain_in_mixed_queries() {
    let error = QueryAnalysisContextError::ValueFlowRegistrationInvalid {
        detail: Box::new(QueryAnalysisContextError::StaleArtifact {
            path: "src/Flow.java".into(),
        }),
    };
    let result = query_analysis_context_error_result(error);

    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(
        result.diagnostics[0].code,
        CodeQueryDiagnosticCode::ValueFlowRegistrationStale
    );
    assert!(
        result.diagnostics[0]
            .message
            .contains("value-flow registration")
    );
}

#[test]
fn semantic_projection_rejects_a_newer_source_than_the_retained_scan_seed() {
    let original = "function target() { const first = 1; }\n";
    let changed = "function target() { const other = 2; }\n";
    assert_eq!(original.len(), changed.len());
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "src/app.ts");
    file.write(original).expect("write original source");
    let overlay = Arc::new(OverlayProject::new(Arc::new(TestProject::new(
        root,
        Language::TypeScript,
    ))));
    let workspace = WorkspaceAnalyzer::build(
        Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>,
        AnalyzerConfig::default(),
    );
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .expect("valid CFG query");
    let provider = workspace
        .analyzer()
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::TypeScript)
        .expect("TypeScript structural provider");
    let facts = provider
        .structural_facts(&file)
        .expect("original structural facts");
    let fact_match = super::super::super::matcher::match_query(
        query.seed().expect("structural query seed"),
        &facts,
        1,
    )
    .into_iter()
    .next()
    .expect("target structural match");
    let seed = Arc::new(SeedMatch {
        language: Language::TypeScript,
        file: file.clone(),
        facts,
        fact_match,
    });
    let (declaration, projection_omitted) =
        enclosing_declaration_value(workspace.analyzer(), &seed, &mut HashMap::default());
    assert!(!projection_omitted);
    let declaration = declaration.expect("original seed has an enclosing declaration");

    assert!(overlay.set(file.abs_path(), changed.to_string()));
    let mut semantic = SemanticQueryContext::new(
        &workspace,
        None,
        CodeQueryExecutionLimits::default().semantic,
    );
    let composed_row = PipelineRow {
        value: PipelineValue::Declaration(declaration),
        traces: vec![PipelineTrace {
            branch: Vec::new(),
            seed: Arc::clone(&seed),
            steps: vec![],
        }],
        provenance_truncated: false,
    };
    assert!(
        !semantic_row_seed_generations_current(&mut semantic, &composed_row),
        "enclosing_decl composition must retain and reject the stale structural seed"
    );
    let procedures = semantic.procedure_of_match(&seed);
    let diagnostics = semantic.take_diagnostics();

    assert!(
        procedures.is_empty(),
        "a semantic row from the changed generation must not be joined to the retained seed"
    );
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
            && diagnostic.message.contains("source generation changed")
    }));
}

#[test]
fn indexed_postings_match_scan_results_in_every_structural_language() {
    let cases = [
        (
            Language::Cpp,
            "app.cpp",
            "void audit() {}\nvoid run() { audit(); }\n",
        ),
        (
            Language::CSharp,
            "App.cs",
            "class App { void Audit() {} void Run() { Audit(); } }\n",
        ),
        (
            Language::Go,
            "app.go",
            "package app\nfunc audit() {}\nfunc run() { audit() }\n",
        ),
        (
            Language::Java,
            "App.java",
            "class App { void audit() {} void run() { audit(); } }\n",
        ),
        (
            Language::JavaScript,
            "app.js",
            "function audit() {}\nfunction run() { audit(); }\n",
        ),
        (
            Language::Php,
            "app.php",
            "<?php\nfunction audit() {}\nfunction run() { audit(); }\n",
        ),
        (
            Language::Python,
            "app.py",
            "def audit():\n    pass\n\ndef run():\n    audit()\n",
        ),
        (
            Language::Ruby,
            "app.rb",
            "def audit; end\ndef run; audit(); end\n",
        ),
        (
            Language::Rust,
            "lib.rs",
            "fn audit() {}\nfn run() { audit(); }\n",
        ),
        (
            Language::Scala,
            "App.scala",
            "object App { def audit(): Unit = (); def run(): Unit = audit() }\n",
        ),
        (
            Language::TypeScript,
            "app.ts",
            "function audit(): void {}\nfunction run(): void { audit(); }\n",
        ),
    ];
    for (language, path, source) in cases {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), path)
            .write(source)
            .expect("write source");
        let analyzer = language_analyzer(language, TestProject::new(root, language));
        let callee = if language == Language::CSharp {
            "Audit"
        } else {
            "audit"
        };
        let query = CodeQuery::from_json(&json!({
            "match": {
                "kind": "call",
                "callee": { "name": callee }
            }
        }))
        .expect("query");
        let scan = execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::ScanOnly,
            true,
        )
        .expect("scan access");
        let indexed = execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::IndexedRequired,
            true,
        )
        .expect("indexed access");

        assert_eq!(
            serde_json::to_value(&indexed.result).expect("indexed result JSON"),
            serde_json::to_value(&scan.result).expect("scan result JSON"),
            "response mismatch for {language:?}"
        );
        assert_eq!(
            indexed.work.scanned_files, scan.work.scanned_files,
            "scanned-file charge mismatch for {language:?}"
        );
        assert_eq!(
            indexed.work.scanned_source_bytes, scan.work.scanned_source_bytes,
            "scanned-byte charge mismatch for {language:?}"
        );
        assert!(
            indexed.work.fact_nodes <= scan.work.fact_nodes,
            "posting access must never charge more fact work than a scan for {language:?}: \
             {} vs {}",
            indexed.work.fact_nodes,
            scan.work.fact_nodes
        );
        let profile = indexed.profile.expect("indexed profile");
        assert!(
            profile.access_path.selected.starts_with("posting:"),
            "unexpected access path for {language:?}: {:?}",
            profile.access_path
        );
        assert!(profile.access_path.candidate_facts > 0);
        assert!(
            profile.access_path.candidate_facts < profile.access_path.scoped_fact_nodes,
            "fixture must prove fact reduction for {language:?}: {:?}",
            profile.access_path
        );
    }
}

#[test]
fn anchored_alternation_regex_uses_role_name_postings_and_skips_candidate_free_files() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "hit.rs")
        .write("fn hot(mut values: Vec<u32>) {\n    for _ in 0..3 {\n        values.sort_by(|a, b| a.cmp(b));\n    }\n}\n")
        .expect("write hit source");
    // Mentions "sort" (survives the source anchor prefilter) but contains no
    // matching call, so the posting index has no candidate facts here.
    ProjectFile::new(root.clone(), "miss.rs")
        .write("/// Callers sort elsewhere.\nfn sort_free(values: &[u32]) -> usize {\n    values.len()\n}\n")
        .expect("write miss source");
    let analyzer = language_analyzer(Language::Rust, TestProject::new(root, Language::Rust));
    let query = CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "callee": { "name": { "regex": "^(sort|sort_by|sort_unstable)$" } }
        }
    }))
    .expect("query");

    let scan = execute_code_query_with_access_mode(
        analyzer.as_ref(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        true,
    )
    .expect("scan access");
    let indexed = execute_code_query_with_access_mode(
        analyzer.as_ref(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("indexed access");

    assert_eq!(
        serde_json::to_value(&indexed.result).expect("indexed result JSON"),
        serde_json::to_value(&scan.result).expect("scan result JSON"),
        "alternation regex results must not depend on the access path"
    );
    assert_eq!(indexed.result.results.len(), 1, "one sort_by call matches");

    let profile = indexed.profile.expect("indexed profile");
    assert!(
        profile.access_path.selected.contains("role_name"),
        "callee alternation must select role-name postings: {:?}",
        profile.access_path
    );
    assert!(
        indexed.work.fact_nodes < scan.work.fact_nodes,
        "files without candidate facts must not be charged under postings: \
         indexed {:?} vs scan {:?}",
        indexed.work,
        scan.work
    );
}

fn run_required_index(analyzer: &dyn IAnalyzer, name: &str) -> DetailedCodeQueryResult {
    run_class_query(analyzer, name, StructuralAccessMode::IndexedRequired)
}

fn run_class_query(
    analyzer: &dyn IAnalyzer,
    name: &str,
    access_mode: StructuralAccessMode,
) -> DetailedCodeQueryResult {
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": name }
    }))
    .expect("class query");
    execute_code_query_with_access_mode(
        analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        access_mode,
        true,
    )
    .expect("class query")
}

fn import_query(
    analyzer: &dyn IAnalyzer,
    language: &str,
    path: &str,
    name: &str,
    step: &str,
    limits: CodeQueryExecutionLimits,
    access_mode: StructuralAccessMode,
) -> DetailedCodeQueryResult {
    let query = CodeQuery::from_json(&json!({
        "languages": [language],
        "where": [path],
        "match": { "kind": "class", "name": name },
        "steps": [{ "op": "file_of" }, { "op": step }],
        "result_detail": "full",
        "limit": 100
    }))
    .expect("import query");
    execute_code_query_with_access_mode(analyzer, &query, limits, access_mode, true)
        .expect("import query execution")
}

#[test]
fn snapshot_import_topology_matches_request_local_and_reuses_across_requests() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "bench/Target.java")
        .write("package bench; public class Target {}\n")
        .expect("write target");
    for name in ["First", "Second"] {
        ProjectFile::new(root.clone(), format!("bench/{name}.java"))
            .write(format!(
                "package bench; import bench.Target; public class {name} {{}}\n"
            ))
            .expect("write importer");
    }
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
    let limits = CodeQueryExecutionLimits::default();

    let scan = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::ScanOnly,
    );
    let built = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(
        serde_json::to_value(&built.result).expect("snapshot result"),
        serde_json::to_value(&scan.result).expect("request-local result")
    );
    let built_profile = built.profile.expect("build profile");
    assert_eq!(built_profile.cache.direct_import_topology.lookups, 1);
    assert_eq!(built_profile.cache.direct_import_topology.misses, 1);
    assert_eq!(built_profile.cache.direct_import_topology.builds, 1);
    assert_eq!(
        built_profile.cache.direct_import_topology.complete_builds,
        1
    );
    assert_eq!(built_profile.cache.direct_import_topology.build_files, 3);
    assert_eq!(built_profile.cache.direct_import_topology.build_edges, 2);
    assert!(built_profile.cache.direct_import_topology.build_ns > 0);
    assert!(built_profile.cache.direct_import_topology.retained_bytes > 0);
    assert_eq!(built_profile.work.import_files_resolved, 3);
    assert_eq!(built_profile.work.import_edges_resolved, 2);

    let reused = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(
        serde_json::to_value(&reused.result).expect("reused result"),
        serde_json::to_value(&scan.result).expect("request-local result")
    );
    let reused_profile = reused.profile.expect("reuse profile");
    assert_eq!(reused_profile.cache.direct_import_topology.lookups, 1);
    assert_eq!(reused_profile.cache.direct_import_topology.hits, 1);
    assert_eq!(reused_profile.cache.direct_import_topology.complete_hits, 1);
    assert_eq!(reused_profile.cache.direct_import_topology.builds, 0);
    assert_eq!(reused_profile.work.import_files_resolved, 0);
    assert_eq!(reused_profile.work.import_edges_resolved, 0);

    let forward_scan = import_query(
        &analyzer,
        "java",
        "bench/First.java",
        "First",
        "imports_of",
        limits,
        StructuralAccessMode::ScanOnly,
    );
    let forward_reused = import_query(
        &analyzer,
        "java",
        "bench/First.java",
        "First",
        "imports_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(
        serde_json::to_value(&forward_reused.result).expect("snapshot forward result"),
        serde_json::to_value(&forward_scan.result).expect("request-local forward result")
    );
    let forward_profile = forward_reused.profile.expect("forward profile");
    assert_eq!(forward_profile.cache.direct_import_topology.hits, 1);
    assert_eq!(forward_profile.cache.import_forward.complete_hits, 1);
}

#[test]
fn auto_import_topology_builds_only_after_observing_reuse() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "bench/Target.java")
        .write("package bench; public class Target {}\n")
        .expect("write target");
    ProjectFile::new(root.clone(), "bench/Consumer.java")
        .write("package bench; import bench.Target; public class Consumer {}\n")
        .expect("write consumer");
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
    let limits = CodeQueryExecutionLimits::default();

    let scan = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::ScanOnly,
    );
    let first = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&first.result).expect("first Auto result"),
        serde_json::to_value(&scan.result).expect("scan result")
    );
    let first_profile = first.profile.expect("first Auto profile");
    assert_eq!(first_profile.cache.direct_import_topology.builds, 0);
    assert_eq!(first_profile.cache.direct_import_topology.misses, 1);
    assert_eq!(first_profile.cache.direct_import_topology.fallbacks, 1);

    let built = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&built.result).expect("built Auto result"),
        serde_json::to_value(&scan.result).expect("scan result")
    );
    assert_eq!(
        built
            .profile
            .expect("built Auto profile")
            .cache
            .direct_import_topology
            .builds,
        1
    );

    let hit = import_query(
        &analyzer,
        "java",
        "bench/Target.java",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&hit.result).expect("hit Auto result"),
        serde_json::to_value(&scan.result).expect("scan result")
    );
    assert_eq!(
        hit.profile
            .expect("hit Auto profile")
            .cache
            .direct_import_topology
            .hits,
        1
    );
}

#[test]
fn snapshot_import_topology_resets_on_update_and_mutable_overlay_generation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let consumer = ProjectFile::new(root.clone(), "bench/Consumer.java");
    ProjectFile::new(root.clone(), "bench/Before.java")
        .write("package bench; public class Before {}\n")
        .expect("write before");
    ProjectFile::new(root.clone(), "bench/After.java")
        .write("package bench; public class After {}\n")
        .expect("write after");
    consumer
        .write("package bench; import bench.Before; public class Consumer {}\n")
        .expect("write consumer");
    let project: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root.clone(), Language::Java));
    let analyzer = JavaAnalyzer::new(Arc::clone(&project));
    let limits = CodeQueryExecutionLimits::default();

    let before = import_query(
        &analyzer,
        "java",
        "bench/Before.java",
        "Before",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(before.result.results.len(), 1);
    assert_eq!(
        before
            .profile
            .expect("initial profile")
            .cache
            .direct_import_topology
            .builds,
        1
    );
    let cloned = analyzer.clone();
    assert_eq!(
        import_query(
            &cloned,
            "java",
            "bench/Before.java",
            "Before",
            "importers_of",
            limits,
            StructuralAccessMode::IndexedRequired,
        )
        .profile
        .expect("clone profile")
        .cache
        .direct_import_topology
        .hits,
        1
    );

    consumer
        .write("package bench; import bench.After; public class Consumer {}\n")
        .expect("update consumer");
    let updated = analyzer.update(&BTreeSet::from([consumer.clone()]));
    let after = import_query(
        &updated,
        "java",
        "bench/After.java",
        "After",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(after.result.results.len(), 1);
    assert_eq!(
        after
            .profile
            .expect("updated profile")
            .cache
            .direct_import_topology
            .builds,
        1
    );
    assert!(
        import_query(
            &updated,
            "java",
            "bench/Before.java",
            "Before",
            "importers_of",
            limits,
            StructuralAccessMode::IndexedRequired,
        )
        .result
        .results
        .is_empty()
    );

    consumer
        .write("package bench; import bench.Before; public class Consumer {}\n")
        .expect("restore disk consumer");
    let overlay = Arc::new(OverlayProject::new(project));
    let overlay_analyzer =
        JavaAnalyzer::new(Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>);
    assert_eq!(
        import_query(
            &overlay_analyzer,
            "java",
            "bench/Before.java",
            "Before",
            "importers_of",
            limits,
            StructuralAccessMode::IndexedRequired,
        )
        .result
        .results
        .len(),
        1
    );
    assert!(overlay.set(
        consumer.abs_path(),
        "package bench; import bench.After; public class Consumer {}\n".to_string()
    ));
    let overlay_after = import_query(
        &overlay_analyzer,
        "java",
        "bench/After.java",
        "After",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(overlay_after.result.results.len(), 1);
    assert_eq!(
        overlay_after
            .profile
            .expect("revised overlay profile")
            .cache
            .direct_import_topology
            .builds,
        1,
        "the revised overlay generation must not hit the old topology"
    );
    assert!(
        import_query(
            &overlay_analyzer,
            "java",
            "bench/Before.java",
            "Before",
            "importers_of",
            limits,
            StructuralAccessMode::IndexedRequired,
        )
        .result
        .results
        .is_empty()
    );
}

#[test]
fn multi_analyzer_owns_and_shares_one_workspace_import_topology() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "target.ts")
        .write("export class Target {}\n")
        .expect("write TypeScript target");
    ProjectFile::new(root.clone(), "consumer.ts")
        .write("import { Target } from './target'; export class Consumer extends Target {}\n")
        .expect("write TypeScript consumer");
    ProjectFile::new(root.clone(), "Extra.java")
        .write("public class Extra {}\n")
        .expect("write Java source");
    let project: Arc<dyn crate::analyzer::Project> = Arc::new(TestProject::with_languages(
        root,
        BTreeSet::from([Language::Java, Language::TypeScript]),
    ));
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let limits = CodeQueryExecutionLimits::default();

    let built = import_query(
        workspace.analyzer(),
        "typescript",
        "target.ts",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(built.result.results.len(), 1);
    assert_eq!(
        built
            .profile
            .expect("multi build profile")
            .cache
            .direct_import_topology
            .builds,
        1
    );
    let cloned = workspace.clone();
    let reused = import_query(
        cloned.analyzer(),
        "typescript",
        "target.ts",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(reused.result.results.len(), 1);
    assert_eq!(
        reused
            .profile
            .expect("multi reuse profile")
            .cache
            .direct_import_topology
            .hits,
        1
    );
}

#[test]
fn multi_analyzer_tracks_every_delegate_overlay_generation() {
    let java_temp = tempfile::tempdir().expect("Java temp dir");
    let java_root = java_temp.path().canonicalize().expect("Java root");
    ProjectFile::new(java_root.clone(), "Extra.java")
        .write("public class Extra {}\n")
        .expect("write Java source");
    let java_project = Arc::new(OverlayProject::new(Arc::new(TestProject::new(
        java_root,
        Language::Java,
    ))));
    let java = JavaAnalyzer::new(Arc::clone(&java_project) as Arc<dyn crate::analyzer::Project>);

    let ts_temp = tempfile::tempdir().expect("TypeScript temp dir");
    let ts_root = ts_temp.path().canonicalize().expect("TypeScript root");
    ProjectFile::new(ts_root.clone(), "before.ts")
        .write("export class Before {}\n")
        .expect("write before target");
    ProjectFile::new(ts_root.clone(), "after.ts")
        .write("export class After {}\n")
        .expect("write after target");
    let consumer = ProjectFile::new(ts_root.clone(), "consumer.ts");
    consumer
        .write("import { Before } from './before'; export class Consumer extends Before {}\n")
        .expect("write TypeScript consumer");
    let ts_project = Arc::new(OverlayProject::new(Arc::new(TestProject::new(
        ts_root,
        Language::TypeScript,
    ))));
    let typescript =
        TypescriptAnalyzer::new(Arc::clone(&ts_project) as Arc<dyn crate::analyzer::Project>);
    let analyzer = MultiAnalyzer::new(BTreeMap::from([
        (Language::Java, AnalyzerDelegate::Java(java)),
        (
            Language::TypeScript,
            AnalyzerDelegate::TypeScript(typescript),
        ),
    ]));
    let limits = CodeQueryExecutionLimits::default();

    let before = import_query(
        &analyzer,
        "typescript",
        "before.ts",
        "Before",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(before.result.results.len(), 1);
    assert_eq!(
        before
            .profile
            .expect("initial multi profile")
            .cache
            .direct_import_topology
            .builds,
        1
    );

    assert!(ts_project.set(
        consumer.abs_path(),
        "import { After } from './after'; export class Consumer extends After {}\n".to_string(),
    ));
    let after = import_query(
        &analyzer,
        "typescript",
        "after.ts",
        "After",
        "importers_of",
        limits,
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(after.result.results.len(), 1);
    assert_eq!(
        after
            .profile
            .expect("revised multi profile")
            .cache
            .direct_import_topology
            .builds,
        1,
        "a non-primary delegate generation must invalidate the workspace topology"
    );
}

#[test]
fn auto_import_topology_budget_fallback_matches_request_local_response() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "a.rb")
        .write("require_relative 'b'\ndef from_a; end\n")
        .expect("write a");
    ProjectFile::new(root.clone(), "b.rb")
        .write("require_relative 'c'\ndef from_b; end\n")
        .expect("write b");
    ProjectFile::new(root.clone(), "c.rb")
        .write("class Target; end\n")
        .expect("write c");
    let analyzer = RubyAnalyzer::from_project(TestProject::new(root, Language::Ruby));
    let limits = CodeQueryExecutionLimits {
        max_scanned_files: 1,
        ..CodeQueryExecutionLimits::default()
    };

    let scan = import_query(
        &analyzer,
        "ruby",
        "c.rb",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::ScanOnly,
    );
    let admitted = import_query(
        &analyzer,
        "ruby",
        "c.rb",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&admitted.result).expect("admission result"),
        serde_json::to_value(&scan.result).expect("request-local result")
    );
    let admitted_profile = admitted.profile.expect("admission profile");
    assert_eq!(admitted_profile.cache.direct_import_topology.builds, 0);
    assert_eq!(admitted_profile.cache.direct_import_topology.fallbacks, 1);

    let automatic = import_query(
        &analyzer,
        "ruby",
        "c.rb",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&automatic.result).expect("automatic result"),
        serde_json::to_value(&scan.result).expect("request-local result")
    );
    let profile = automatic.profile.expect("fallback profile");
    assert_eq!(profile.cache.direct_import_topology.lookups, 1);
    assert_eq!(profile.cache.direct_import_topology.unavailable, 1);
    assert_eq!(profile.cache.direct_import_topology.over_budget, 1);
    assert_eq!(profile.cache.direct_import_topology.fallbacks, 1);
    assert_eq!(profile.cache.direct_import_topology.complete_builds, 0);

    let suppressed = import_query(
        &analyzer,
        "ruby",
        "c.rb",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&suppressed.result).expect("suppressed result"),
        serde_json::to_value(&scan.result).expect("request-local result")
    );
    let suppressed = suppressed.profile.expect("suppressed profile");
    assert_eq!(suppressed.cache.direct_import_topology.builds, 0);
    assert_eq!(suppressed.cache.direct_import_topology.unavailable, 0);
    assert_eq!(suppressed.cache.direct_import_topology.fallbacks, 1);
}

#[test]
fn late_topology_edge_limit_reuses_partial_work_for_fallback() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "target.ts")
        .write("export class Target {}\n")
        .expect("write target");
    for index in 0..4 {
        ProjectFile::new(root.clone(), format!("consumer_{index}.ts"))
            .write(format!(
                "import {{ Target }} from './target'; export class Consumer{index} extends Target {{}}\n"
            ))
            .expect("write consumer");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let limits = CodeQueryExecutionLimits {
        max_pipeline_rows: 3,
        ..CodeQueryExecutionLimits::default()
    };

    let scan = import_query(
        &analyzer,
        "typescript",
        "target.ts",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::ScanOnly,
    );
    let admission = import_query(
        &analyzer,
        "typescript",
        "target.ts",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&admission.result).expect("admission response"),
        serde_json::to_value(&scan.result).expect("scan response")
    );
    let fallback = import_query(
        &analyzer,
        "typescript",
        "target.ts",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&fallback.result).expect("fallback response"),
        serde_json::to_value(&scan.result).expect("scan response")
    );
    let profile = fallback.profile.expect("late fallback profile");
    assert_eq!(profile.cache.direct_import_topology.over_budget, 1);
    assert_eq!(profile.cache.direct_import_topology.fallbacks, 1);
    assert!(
        profile.work.import_files_resolved
            <= u64::try_from(limits.max_scanned_files).unwrap_or(u64::MAX)
    );
    assert!(
        profile.work.import_edges_resolved
            <= u64::try_from(limits.max_pipeline_rows).unwrap_or(u64::MAX)
    );
}

#[test]
fn snapshot_index_reuses_clones_and_resets_updates_and_overlays() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "app.ts");
    file.write("class Before {}\n").expect("write source");
    let project: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root, Language::TypeScript));
    let analyzer = TypescriptAnalyzer::new(Arc::clone(&project));

    let first = run_required_index(&analyzer, "Before");
    assert_eq!(first.result.structural_matches().len(), 1);
    assert_eq!(
        first
            .profile
            .expect("first profile")
            .access_path
            .index_builds,
        1
    );

    let clone = analyzer.clone();
    let reused = run_required_index(&clone, "Before");
    let reused_profile = reused.profile.expect("clone profile");
    assert_eq!(reused.result.structural_matches().len(), 1);
    assert_eq!(reused_profile.access_path.index_hits, 1);
    assert_eq!(reused_profile.access_path.index_builds, 0);

    file.write("class After {}\n").expect("update source");
    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    let after = run_required_index(&updated, "After");
    assert_eq!(after.result.structural_matches().len(), 1);
    assert_eq!(
        after
            .profile
            .expect("update profile")
            .access_path
            .index_builds,
        1
    );
    assert!(
        run_required_index(&updated, "Before")
            .result
            .structural_matches()
            .is_empty()
    );

    let overlay = Arc::new(OverlayProject::new(Arc::clone(&project)));
    assert!(overlay.set(file.abs_path(), "class Overlay {}\n".to_string()));
    let snapshot = updated.clone_with_project(overlay as Arc<dyn crate::analyzer::Project>);
    let overlay_result = run_required_index(&snapshot, "Overlay");
    assert_eq!(overlay_result.result.structural_matches().len(), 1);
    assert_eq!(
        overlay_result
            .profile
            .expect("overlay profile")
            .access_path
            .index_builds,
        1
    );
}

#[test]
fn update_all_rebuilds_postings_for_added_and_deleted_files() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let before = ProjectFile::new(root.clone(), "before.ts");
    before
        .write("class Before {}\n")
        .expect("write original source");
    let project: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root.clone(), Language::TypeScript));
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    assert_eq!(
        run_required_index(workspace.analyzer(), "Before")
            .result
            .structural_matches()
            .len(),
        1
    );

    let added = ProjectFile::new(root, "added.ts");
    added.write("class Added {}\n").expect("write added source");
    let with_added = workspace.update_all();
    let added_result = run_required_index(with_added.analyzer(), "Added");
    assert_eq!(added_result.result.structural_matches().len(), 1);
    assert_eq!(
        added_result
            .profile
            .expect("added profile")
            .access_path
            .index_builds,
        1
    );

    std::fs::remove_file(before.abs_path()).expect("delete original source");
    let without_before = with_added.update_all();
    assert!(
        run_required_index(without_before.analyzer(), "Before")
            .result
            .structural_matches()
            .is_empty()
    );
    assert_eq!(
        run_required_index(without_before.analyzer(), "Added")
            .result
            .structural_matches()
            .len(),
        1
    );
}

#[test]
fn mutable_overlay_generation_invalidates_cached_postings() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "app.ts");
    file.write("class Before {}\n").expect("write source");
    let disk: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root, Language::TypeScript));
    let overlay = Arc::new(OverlayProject::new(disk));
    let analyzer =
        TypescriptAnalyzer::new(Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>);

    assert_eq!(
        run_required_index(&analyzer, "Before")
            .result
            .structural_matches()
            .len(),
        1
    );
    assert!(overlay.set(file.abs_path(), "class After {}\n".to_string()));

    assert!(
        run_class_query(&analyzer, "Before", StructuralAccessMode::ScanOnly)
            .result
            .structural_matches()
            .is_empty(),
        "the scan path must observe the revised live overlay"
    );
    assert_eq!(
        run_class_query(&analyzer, "After", StructuralAccessMode::ScanOnly)
            .result
            .structural_matches()
            .len(),
        1
    );
    let revised = run_required_index(&analyzer, "After");
    assert_eq!(revised.result.structural_matches().len(), 1);
    assert_eq!(
        revised
            .profile
            .expect("revised profile")
            .access_path
            .index_builds,
        1,
        "the revised overlay generation must not hit the old posting index"
    );
    assert!(
        run_required_index(&analyzer, "Before")
            .result
            .structural_matches()
            .is_empty(),
        "old negative evidence must not survive the generation change"
    );
}

#[test]
fn auto_reuses_but_does_not_build_a_whole_snapshot_for_a_narrow_scope() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "app.ts")
        .write("class App {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    let first = run_class_query(&analyzer, "App", StructuralAccessMode::Auto);
    let first_profile = first.profile.expect("auto profile");
    assert_eq!(first_profile.access_path.selected, "scan_only");
    assert_eq!(first_profile.access_path.index_lookups, 0);

    let built = run_required_index(&analyzer, "App");
    assert_eq!(
        built
            .profile
            .expect("build profile")
            .access_path
            .index_builds,
        1
    );

    let reused = run_class_query(&analyzer, "App", StructuralAccessMode::Auto);
    let reused_profile = reused.profile.expect("reuse profile");
    assert!(reused_profile.access_path.selected.starts_with("posting:"));
    assert_eq!(reused_profile.access_path.index_hits, 1);
    assert_eq!(reused_profile.access_path.cache_ready_lookups, 1);
}

#[test]
fn auto_builds_only_after_a_viable_scope_is_reused() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for index in 0..MIN_AUTO_STRUCTURAL_INDEX_FILES {
        ProjectFile::new(root.clone(), format!("file_{index}.ts"))
            .write(format!("class Type{index} {{}}\n"))
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

    let first = run_class_query(&analyzer, "Type0", StructuralAccessMode::Auto);
    let first_profile = first.profile.expect("first profile");
    assert_eq!(first_profile.access_path.selected, "scan_only");
    assert_eq!(first_profile.access_path.index_lookups, 0);

    let second = run_class_query(&analyzer, "Type0", StructuralAccessMode::Auto);
    let second_profile = second.profile.expect("second profile");
    assert_eq!(second_profile.access_path.index_builds, 1);
    assert!(second_profile.access_path.selected.starts_with("posting:"));

    let third = run_class_query(&analyzer, "Type0", StructuralAccessMode::Auto);
    let third_profile = third.profile.expect("third profile");
    assert_eq!(third_profile.access_path.index_hits, 1);
    assert_eq!(third_profile.access_path.index_builds, 0);
}

#[test]
fn indexed_rql_and_json_queries_are_response_equivalent() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "app.ts")
        .write("class App {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let json_query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "App" }
    }))
    .expect("JSON query");
    let rql_query = CodeQuery::from_source("(class :name \"App\")").expect("RQL query");

    let json_result = execute_code_query_with_access_mode(
        &analyzer,
        &json_query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("indexed JSON query");
    let rql_result = execute_code_query_with_access_mode(
        &analyzer,
        &rql_query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("indexed RQL query");

    assert_eq!(
        serde_json::to_value(&rql_result.result).expect("RQL result JSON"),
        serde_json::to_value(&json_result.result).expect("JSON result JSON")
    );
    assert_eq!(rql_result.work, json_result.work);
}

#[test]
fn indexed_candidates_preserve_nested_capture_negation_and_budget_cutoffs() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "a.ts")
        .write(
            "class Controller { run(): void { audit(\"ok\"); } }\nfunction audit(value: string): void {}\n",
        )
        .expect("write first source");
    ProjectFile::new(root.clone(), "b.ts")
        .write(
            "class Excluded { run(): void { audit(\"bad\"); } }\nfunction audit(value: string): void {}\n",
        )
        .expect("write second source");
    ProjectFile::new(root.clone(), "c.ts")
        .write(
            "class ControllerTwo { run(): void { audit(\"also-ok\"); } }\nfunction audit(value: string): void {}\n",
        )
        .expect("write third source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "callee": { "name": { "regex": "^audit$" } },
            "args": [{ "capture": "argument" }]
        },
        "inside": { "kind": "method", "name": "run" },
        "not_inside": { "kind": "class", "name": "Excluded" },
        "result_detail": "full",
        "limit": 1
    }))
    .expect("nested query");

    let full_scan = execute_code_query_with_access_mode(
        &analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        true,
    )
    .expect("unconstrained scan query");
    let complete_rows =
        serde_json::to_value(&full_scan.result.results).expect("unconstrained rows");

    // Fact-node budgets legitimately diverge: posting access charges only the
    // candidates and the verifier walk, so it can finish inside a budget that
    // truncates a scan. Every other cutoff is charged identically.
    for (limits, fact_limited) in [
        (CodeQueryExecutionLimits::default(), false),
        (
            CodeQueryExecutionLimits {
                max_scanned_files: 1,
                ..CodeQueryExecutionLimits::default()
            },
            false,
        ),
        (
            CodeQueryExecutionLimits {
                max_scanned_source_bytes: 1,
                ..CodeQueryExecutionLimits::default()
            },
            false,
        ),
        (
            CodeQueryExecutionLimits {
                max_fact_nodes: 1,
                ..CodeQueryExecutionLimits::default()
            },
            true,
        ),
        (
            CodeQueryExecutionLimits {
                max_pipeline_rows: 1,
                ..CodeQueryExecutionLimits::default()
            },
            false,
        ),
    ] {
        let scan = execute_code_query_with_access_mode(
            &analyzer,
            &query,
            limits,
            StructuralAccessMode::ScanOnly,
            true,
        )
        .expect("scan query");
        let indexed = execute_code_query_with_access_mode(
            &analyzer,
            &query,
            limits,
            StructuralAccessMode::IndexedRequired,
            true,
        )
        .expect("indexed query");
        if fact_limited {
            for row in serde_json::to_value(&indexed.result.results)
                .expect("indexed rows")
                .as_array()
                .expect("rows array")
            {
                assert!(
                    complete_rows
                        .as_array()
                        .expect("complete rows array")
                        .contains(row),
                    "fact-limited indexed rows must stay sound: {row}"
                );
            }
        } else {
            // Diagnostic messages embed the charged fact counts, which
            // legitimately differ between access paths; rows, truncation,
            // and diagnostic codes must not.
            assert_eq!(
                serde_json::to_value(&indexed.result.results).expect("indexed rows"),
                serde_json::to_value(&scan.result.results).expect("scan rows")
            );
            assert_eq!(indexed.result.truncated, scan.result.truncated);
            assert_eq!(
                indexed
                    .result
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code)
                    .collect::<Vec<_>>(),
                scan.result
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code)
                    .collect::<Vec<_>>()
            );
            assert!(
                indexed.work.fact_nodes <= scan.work.fact_nodes,
                "posting access must never charge more fact work than a scan"
            );
        }
    }
}
