use super::results::{ALL_DETAILED_CODE_QUERY_DOMAINS, CodeQueryRowScalarRef};
use super::*;
use crate::analyzer::structural::CodeQuery;
use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerDelegate, CSharpAnalyzer, CodeUnitType, CppAnalyzer, GoAnalyzer,
    JavaAnalyzer, JavascriptAnalyzer, MultiAnalyzer, OverlayProject, PhpAnalyzer, PythonAnalyzer,
    RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, TestProject, TypescriptAnalyzer, WorkspaceAnalyzer,
};
use serde_json::json;
use std::cell::Cell;
use std::path::PathBuf;

fn language_analyzer(language: Language, project: TestProject) -> Box<dyn IAnalyzer> {
    match language {
        Language::Cpp => Box::new(CppAnalyzer::from_project(project)),
        Language::CSharp => Box::new(CSharpAnalyzer::from_project(project)),
        Language::Go => Box::new(GoAnalyzer::from_project(project)),
        Language::Java => Box::new(JavaAnalyzer::from_project(project)),
        Language::JavaScript => Box::new(JavascriptAnalyzer::from_project(project)),
        Language::Php => Box::new(PhpAnalyzer::from_project(project)),
        Language::Python => Box::new(PythonAnalyzer::from_project(project)),
        Language::Ruby => Box::new(RubyAnalyzer::from_project(project)),
        Language::Rust => Box::new(RustAnalyzer::from_project(project)),
        Language::Scala => Box::new(ScalaAnalyzer::from_project(project)),
        Language::TypeScript => Box::new(TypescriptAnalyzer::from_project(project)),
        other => panic!("no structural differential fixture for {other:?}"),
    }
}

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
        "schema_version": 3,
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
    let fact_match =
        super::super::matcher::match_query(query.seed().expect("structural query seed"), &facts, 1)
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

fn diagnostic(
    code: CodeQueryDiagnosticCode,
    impact: CodeQueryDiagnosticImpact,
) -> CodeQueryDiagnostic {
    CodeQueryDiagnostic {
        code,
        impact,
        branch: Vec::new(),
        language: "workspace",
        message: "prose deliberately carries no classification words".to_string(),
    }
}

#[test]
fn execution_work_snapshot_is_the_single_budget_projection() {
    let snapshot = execution_work_snapshot(
        CodeQueryExecutionBudget {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            examined_references: 4,
            pipeline_rows: 5,
            provenance_steps: 6,
            import_files_resolved: 7,
            import_edges_resolved: 8,
        },
        CodeQuerySemanticWork::default(),
    );
    assert_eq!(
        snapshot,
        QueryOperatorWorkProfile {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            pipeline_rows: 5,
            examined_references: 4,
            provenance_steps: 6,
            import_files_resolved: 7,
            import_edges_resolved: 8,
            semantic: CodeQuerySemanticWork::default(),
        }
    );
    assert_eq!(
        public_execution_work(snapshot),
        CodeQueryExecutionWork {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            pipeline_rows: 5,
            examined_references: 4,
            semantic: CodeQuerySemanticWork::default(),
        }
    );
}

#[test]
fn semantic_execution_limits_require_each_dimension_to_be_positive() {
    let defaults = CodeQuerySemanticLimits::default();
    assert!(defaults.all_positive());

    for invalid in [
        CodeQuerySemanticLimits {
            max_materialized_files: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_source_bytes: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_rows_per_dimension: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_retained_bytes: 0,
            ..defaults
        },
        CodeQuerySemanticLimits {
            max_traversal_steps: 0,
            ..defaults
        },
    ] {
        assert!(!invalid.all_positive());
    }
}

fn assert_serial_profile_reconciles(profile: &QueryExecutionProfile) {
    assert_eq!(profile.format, "bifrost_code_query_execution_profile/v4");
    assert_eq!(profile.peak_concurrency, 1);
    assert_eq!(profile.scheduler.tasks_enqueued, 0);
    assert_eq!(profile.scheduler.peak_concurrency, 0);
    assert!(
        profile
            .planning_ns
            .saturating_add(profile.execution_ns)
            .saturating_add(profile.rendering_ns)
            <= profile.total_elapsed_ns,
        "named request phases must fit inside total request wall time"
    );
    for observation in &profile.operators {
        assert_eq!(
            observation.total_elapsed_ns,
            observation
                .elapsed_ns
                .saturating_add(observation.dependency_execution_ns),
            "operator self and inline dependency execution must reconcile"
        );
        assert_eq!(observation.dependency_wait_ns, 0);
        assert_eq!(observation.scheduling_overhead_ns, 0);
        assert!(observation.merge_ns <= observation.elapsed_ns);
    }
    let operator_work = profile
        .operators
        .iter()
        .fold(QueryOperatorWorkProfile::default(), |work, observation| {
            work.saturating_add(observation.work)
        });
    assert_eq!(operator_work, profile.execution_work);
    assert_eq!(
        profile
            .execution_work
            .saturating_add(profile.rendering_work),
        profile.work
    );
}

#[test]
fn public_explain_is_planning_only_and_exposes_shared_logical_dependencies() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "src/app.ts");
    file.write("class Shared {}\n").expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query =
        CodeQuery::from_sexp("(explain (union (class :name \"Shared\") (class :name \"Shared\")))")
            .expect("explain query");
    let providers = analyzer.structural_search_providers();
    let extractions_before = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();

    let CodeQueryResponse::Explain(explain) = execute_request(&analyzer, &query) else {
        panic!("explain mode must return a planning report")
    };

    let extractions_after = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();
    assert_eq!(extractions_after, extractions_before);
    assert_eq!(explain.scheduling.max_concurrency, 1);
    assert!(matches!(
        explain.scheduling.selected,
        super::super::execution::plan::CodeQuerySelectedScheduling::Sequential
    ));
    let shared_set = explain
        .logical_plan
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.operation,
                super::super::execution::plan::CodeQueryLogicalOperation::Set { .. }
            )
        })
        .expect("logical set node");
    assert_eq!(shared_set.dependencies.len(), 2);
    assert_eq!(shared_set.dependencies[0], shared_set.dependencies[1]);
}

#[test]
fn public_profile_nests_the_exact_ordered_ordinary_result() {
    let source = "class First {}\nclass Second {}\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/app.ts")
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut query =
        CodeQuery::from_json(&json!({ "match": { "kind": "class" } })).expect("results query");
    let CodeQueryResponse::Results(ordinary) = execute_request(&analyzer, &query) else {
        panic!("default mode must return ordinary results")
    };
    let ordinary_json = serde_json::to_value(&ordinary).expect("serialize ordinary result");
    assert_eq!(
        serde_json::to_value(CodeQueryResponse::Results(ordinary))
            .expect("serialize ordinary response"),
        ordinary_json,
        "default response must not add an enum envelope"
    );

    query.execution_mode = CodeQueryExecutionMode::Profile;
    let expected_explain = select_physical_plan(
        &query,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
    )
    .expect("profile query should select a plan")
    .public_explain(&query, CODE_QUERY_SCHEDULER_WORKERS);
    let CodeQueryResponse::Profile(profile) = execute_request(&analyzer, &query) else {
        panic!("profile mode must return a profile")
    };

    assert_eq!(profile.explain, expected_explain);
    assert_eq!(
        serde_json::to_value(&profile.result).expect("serialize profiled result"),
        ordinary_json
    );
    assert_eq!(profile.format, CodeQueryProfile::FORMAT);
    assert!(!profile.operators.is_empty());
    assert_eq!(profile.scheduling.peak_concurrency, 1);
    assert!(profile.scheduling.bounded_dispatch.is_none());
}

#[test]
fn response_parts_preserve_each_public_wire_shape() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/app.ts")
        .write("class Example {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut query = CodeQuery::from_json(&json!({ "match": { "kind": "class" } })).expect("query");

    for mode in [
        CodeQueryExecutionMode::Results,
        CodeQueryExecutionMode::Explain,
        CodeQueryExecutionMode::Profile,
    ] {
        query.execution_mode = mode;
        let response = execute_request(&analyzer, &query);
        let serialized = serde_json::to_value(&response).expect("serialize response");
        let pretty_report = response.render_report_pretty();
        let (actual_mode, result, report) = response.into_parts();
        assert_eq!(actual_mode, mode);
        match mode {
            CodeQueryExecutionMode::Results => {
                assert_eq!(
                    serde_json::to_value(result.expect("ordinary result"))
                        .expect("serialize ordinary result"),
                    serialized
                );
                assert!(report.is_none());
                assert!(pretty_report.is_none());
            }
            CodeQueryExecutionMode::Explain => {
                assert!(result.is_none());
                assert_eq!(report.expect("explain report"), serialized);
                assert!(
                    pretty_report
                        .expect("pretty explain report")
                        .starts_with("{\n  \"format\":")
                );
            }
            CodeQueryExecutionMode::Profile => {
                assert_eq!(
                    serde_json::to_value(result.expect("profiled result"))
                        .expect("serialize profiled result"),
                    serialized["result"]
                );
                assert_eq!(report.expect("profile report"), serialized);
                assert!(
                    pretty_report
                        .expect("pretty profile report")
                        .starts_with("{\n  \"format\":")
                );
            }
        }
    }
}

#[test]
fn shared_provenance_and_diagnostic_presentation_preserves_order_and_deduplicates() {
    let item = CodeQueryResultItem {
        value: CodeQueryResultValue::File {
            value: CodeQueryFile {
                package_fq: None,
                package_syntactic: None,
                path: "src/app.ts".to_string(),
                language: "typescript",
            },
        },
        provenance: vec![
            CodeQueryProvenance {
                branch: vec![1, 0],
                seed: CodeQueryResultRef::File {
                    path: "src/app.ts".to_string(),
                },
                steps: Vec::new(),
            },
            CodeQueryProvenance {
                branch: vec![1, 0],
                seed: CodeQueryResultRef::File {
                    path: "src/app.ts".to_string(),
                },
                steps: Vec::new(),
            },
            CodeQueryProvenance {
                branch: vec![0],
                seed: CodeQueryResultRef::File {
                    path: "src/app.ts".to_string(),
                },
                steps: Vec::new(),
            },
        ],
        provenance_truncated: true,
    };
    assert_eq!(
        item.provenance_summary().as_deref(),
        Some("provenance: 3 paths (truncated); branches 1.0, 0")
    );
    let diagnostic = CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: vec![1, 0],
        language: "typescript",
        message: "broad query".to_string(),
    };
    assert_eq!(
        diagnostic.presentation_label(),
        "advisory [broad_query] [branch 1.0]"
    );

    let rendered = CodeQueryResult {
        results: vec![item],
        truncated: false,
        diagnostics: vec![diagnostic],
    }
    .render_text();
    assert!(rendered.contains("  provenance: 3 paths (truncated); branches 1.0, 0\n"));
    assert!(rendered.contains("advisory [broad_query] [branch 1.0]: broad query\n"));
}

#[test]
fn semantic_result_contracts_serialize_render_and_retain_source_evidence() {
    let procedure_id = "11".repeat(32);
    let point_id = "22".repeat(32);
    let edge_id = "33".repeat(32);
    let target_id = "44".repeat(32);
    let path = "src/app.ts";
    let procedure_range = CodeQueryRange {
        start_line: 1,
        start_column: 1,
        end_line: 4,
        end_column: 2,
    };
    let point_range = CodeQueryRange {
        start_line: 2,
        start_column: 3,
        end_line: 2,
        end_column: 14,
    };
    let target_range = CodeQueryRange {
        start_line: 3,
        start_column: 3,
        end_line: 3,
        end_column: 10,
    };
    let complete = CodeQuerySemanticEvidence {
        proof: CodeQuerySemanticProof::Proven,
        proof_reason: None,
        completeness: CodeQuerySemanticCompleteness::Complete,
        completeness_reason: None,
    };
    let partial = CodeQuerySemanticEvidence {
        proof: CodeQuerySemanticProof::Unproven,
        proof_reason: Some("ambiguous enclosing procedure".to_string()),
        completeness: CodeQuerySemanticCompleteness::Partial,
        completeness_reason: Some("exceptional control flow is unsupported".to_string()),
    };
    let point_ref = CodeQueryProgramPointRef {
        id: point_id.clone(),
        procedure_id: procedure_id.clone(),
        path: path.to_string(),
        range: point_range,
        boundary: Some(CodeQueryProgramPointBoundary::Entry),
    };
    let target_ref = CodeQueryProgramPointRef {
        id: target_id.clone(),
        procedure_id: procedure_id.clone(),
        path: path.to_string(),
        range: target_range,
        boundary: None,
    };
    let result = CodeQueryResult {
        results: vec![
            CodeQueryResultItem {
                value: CodeQueryResultValue::Procedure {
                    value: CodeQueryProcedure {
                        id: procedure_id.clone(),
                        artifact_id: "aa".repeat(32),
                        path: path.to_string(),
                        language: "typescript",
                        procedure_kind: "function",
                        range: procedure_range,
                        evidence: complete.clone(),
                    },
                },
                provenance: Vec::new(),
                provenance_truncated: false,
            },
            CodeQueryResultItem {
                value: CodeQueryResultValue::ProgramPoint {
                    value: CodeQueryProgramPoint {
                        id: point_id.clone(),
                        procedure_id: procedure_id.clone(),
                        path: path.to_string(),
                        language: "typescript",
                        range: point_range,
                        boundary: Some(CodeQueryProgramPointBoundary::Entry),
                        event_count: 1,
                        evidence: partial.clone(),
                    },
                },
                provenance: Vec::new(),
                provenance_truncated: false,
            },
            CodeQueryResultItem {
                value: CodeQueryResultValue::ControlEdge {
                    value: Box::new(CodeQueryControlEdge {
                        id: edge_id.clone(),
                        procedure_id: procedure_id.clone(),
                        path: path.to_string(),
                        language: "typescript",
                        range: point_range,
                        edge_kind: "conditional_true",
                        source: point_ref,
                        target: target_ref,
                        evidence: complete,
                    }),
                },
                provenance: Vec::new(),
                provenance_truncated: false,
            },
        ],
        truncated: false,
        diagnostics: Vec::new(),
    };

    let serialized = serde_json::to_value(&result).expect("semantic results serialize");
    assert_eq!(serialized["results"][0]["result_type"], "procedure");
    assert_eq!(serialized["results"][1]["result_type"], "program_point");
    assert_eq!(serialized["results"][1]["boundary"], "entry");
    assert_eq!(serialized["results"][1]["evidence"]["proof"], "unproven");
    assert_eq!(
        serialized["results"][1]["evidence"]["completeness"],
        "partial"
    );
    assert_eq!(serialized["results"][2]["result_type"], "control_edge");
    assert_eq!(serialized["results"][2]["edge_kind"], "conditional_true");
    assert_eq!(serialized["results"][2]["source"]["id"], point_id);
    assert_eq!(serialized["results"][2]["target"]["id"], target_id);
    assert!(!serialized.to_string().contains("program_point_id"));
    assert!(!serialized.to_string().contains("control_edge_id"));

    let rendered = result.render_text();
    assert!(rendered.contains("[procedure; function; proven/complete]"));
    assert!(rendered.contains("[program point; entry; unproven/partial; 1 event]"));
    assert!(rendered.contains("[control edge; conditional_true; proven/complete]"));

    for reference in [
        CodeQueryResultRef::Procedure {
            id: procedure_id.clone(),
            path: path.to_string(),
            procedure_kind: "function",
            range: procedure_range,
        },
        CodeQueryResultRef::ProgramPoint {
            id: point_id.clone(),
            procedure_id: procedure_id.clone(),
            path: path.to_string(),
            range: point_range,
            boundary: Some(CodeQueryProgramPointBoundary::Entry),
        },
        CodeQueryResultRef::ControlEdge {
            id: edge_id.clone(),
            procedure_id: procedure_id.clone(),
            path: path.to_string(),
            range: point_range,
            edge_kind: "conditional_true",
            source_id: point_id.clone(),
            target_id: target_id.clone(),
        },
    ] {
        let serialized = serde_json::to_value(reference).expect("semantic reference serializes");
        assert!(serialized["id"].as_str().is_some());
        assert_eq!(serialized["path"], path);
        assert!(serialized["range"].is_object());
    }

    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root, path);
    let evidence_for = |index, domain, key: DetailedCodeQueryKey, id: &str| {
        let candidate = CodeQueryStableOwnerCandidate {
            namespace: "typescript".to_string(),
            derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
            semantic_key: id.to_string(),
        };
        DetailedCodeQueryEvidence {
            result_index: index,
            domain,
            key,
            file: file.clone(),
            byte_span: Some(0..1),
            stable_owner_candidate: Some(candidate.clone()),
            identities: DetailedCodeQueryProvenanceIdentities::Primary(Some(
                DetailedCodeQueryIdentityCandidate {
                    file: file.clone(),
                    candidate,
                },
            )),
            source_slice_sha256: Some([u8::try_from(index).unwrap(); 32]),
            provenance: Vec::new(),
        }
    };
    let detailed = DetailedCodeQueryResult {
        result,
        work: CodeQueryExecutionWork {
            pipeline_rows: 3,
            ..CodeQueryExecutionWork::default()
        },
        evidence: vec![
            evidence_for(
                0,
                DetailedCodeQueryDomain::Procedure,
                DetailedCodeQueryKey::Procedure {
                    id: procedure_id.clone(),
                },
                &procedure_id,
            ),
            evidence_for(
                1,
                DetailedCodeQueryDomain::ProgramPoint,
                DetailedCodeQueryKey::ProgramPoint {
                    id: point_id.clone(),
                    procedure_id: procedure_id.clone(),
                },
                &point_id,
            ),
            evidence_for(
                2,
                DetailedCodeQueryDomain::ControlEdge,
                DetailedCodeQueryKey::ControlEdge {
                    id: edge_id.clone(),
                    procedure_id,
                },
                &edge_id,
            ),
        ],
        profile: None,
    };
    detailed.assert_invariants();
}

#[test]
fn public_profile_retains_pre_execution_cancellation_observations() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/app.ts")
        .write("class Cancelled {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "class" }
    }))
    .expect("profile query");
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let CodeQueryResponse::Profile(profile) = execute_request_with_cancellation(
        &analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    ) else {
        panic!("pre-cancelled profile should retain its report")
    };

    assert_eq!(profile.result.completion(), CodeQueryCompletion::Cancelled);
    assert!(profile.operators.iter().any(|operator| {
        operator.result_cancelled
            || matches!(
                operator.disposition,
                super::super::execution::profile::CodeQueryOperatorDisposition::Cancelled
            )
    }));
}

#[test]
fn diagnostic_codes_have_exhaustive_stable_impacts_and_completion() {
    use CodeQueryDiagnosticCode as Code;
    use CodeQueryDiagnosticImpact as Impact;

    let cases = [
        (Code::InvalidPlan, Impact::Invalid),
        (Code::Cancelled, Impact::Incomplete),
        (Code::UnsupportedStructuralFeature, Impact::Incomplete),
        (Code::MissingStructuralAdapter, Impact::Incomplete),
        (Code::UnsupportedImportAnalysis, Impact::Incomplete),
        (Code::SemanticResultsOmitted, Impact::Incomplete),
        (Code::SemanticWorkspaceRequired, Impact::Incomplete),
        (Code::NoEnclosingProcedure, Impact::Advisory),
        (Code::SemanticCapabilityUnsupported, Impact::Incomplete),
        (Code::SemanticAnalysisPartial, Impact::Incomplete),
        (Code::SemanticBudgetExhausted, Impact::Incomplete),
        (Code::SemanticProviderFailed, Impact::Incomplete),
        (Code::ReceiverAnalysisPartial, Impact::Incomplete),
        (Code::ReceiverAnalysisFailed, Impact::Incomplete),
        (Code::CallRelationBudgetExhausted, Impact::Incomplete),
        (Code::CallRelationParseFailed, Impact::Incomplete),
        (Code::CallRelationCandidatesOmitted, Impact::Incomplete),
        (Code::CallRelationTargetsAmbiguous, Impact::Advisory),
        (Code::CallRelationCandidateLimit, Impact::Incomplete),
        (Code::CallRelationAnalysisFailed, Impact::Incomplete),
        (Code::ReferenceSourceBytesTruncated, Impact::Incomplete),
        (Code::ReferenceCandidateFilesTruncated, Impact::Incomplete),
        (Code::ReferenceCandidatesOmitted, Impact::Incomplete),
        (Code::ReferenceTargetsAmbiguous, Impact::Advisory),
        (Code::ReferenceCallsiteLimit, Impact::Incomplete),
        (Code::ReferenceAnalysisFailed, Impact::Incomplete),
        (Code::UsesParserUnsupported, Impact::Incomplete),
        (Code::UsesCandidateLimit, Impact::Incomplete),
        (Code::UsesTargetsAmbiguous, Impact::Advisory),
        (Code::UsesCandidatesOmitted, Impact::Incomplete),
        (Code::ExecutionBudgetExhausted, Impact::Incomplete),
        (Code::PipelineBudgetExhausted, Impact::Incomplete),
        (Code::ImportGraphBudgetExhausted, Impact::Incomplete),
        (Code::ResultLimitReached, Impact::Incomplete),
        (Code::BroadQuery, Impact::Advisory),
    ];

    for (code, impact) in cases {
        let result = CodeQueryResult {
            results: Vec::new(),
            truncated: false,
            diagnostics: vec![diagnostic(code, impact)],
        };
        let serialized = serde_json::to_value(&result).expect("serialize query result");
        assert_eq!(serialized["diagnostics"][0]["code"], code.as_str());
        assert_eq!(serialized["diagnostics"][0]["impact"], impact.as_str());
        assert!(
            result
                .render_text()
                .contains(&format!("{} [{}]", impact.as_str(), code.as_str())),
            "code {code:?} did not retain its typed label in text output"
        );
        let expected = match (code, impact) {
            (Code::InvalidPlan, _) => CodeQueryCompletion::Invalid {
                codes: vec![Code::InvalidPlan],
            },
            (Code::Cancelled, _) => CodeQueryCompletion::Cancelled,
            (_, Impact::DeclaredNonExhaustive) => {
                CodeQueryCompletion::ProvenSubset { codes: vec![code] }
            }
            (_, Impact::Incomplete) => CodeQueryCompletion::Incomplete { codes: vec![code] },
            (_, Impact::Advisory) => CodeQueryCompletion::Complete,
            (_, Impact::Invalid) => unreachable!("only InvalidPlan is invalid"),
        };
        assert_eq!(result.completion(), expected, "code {code:?}");
    }

    assert_eq!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: true,
            diagnostics: Vec::new(),
        }
        .completion(),
        CodeQueryCompletion::Incomplete { codes: Vec::new() }
    );
}

#[test]
fn typed_diagnostic_producers_cover_budget_output_and_cancellation() {
    let mut diagnostics = Vec::new();
    let budget = CodeQueryExecutionBudget::default();
    push_budget_diagnostic(&mut diagnostics, &budget);
    push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
    push_import_graph_budget_diagnostic(
        &mut diagnostics,
        &RequestLocalDirectImportGraph::default(),
    );
    push_truncation_diagnostic(&mut diagnostics, &budget, 1);
    push_broad_query_diagnostic(&mut diagnostics, &budget);

    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.impact))
            .collect::<Vec<_>>(),
        vec![
            (
                CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::PipelineBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::ResultLimitReached,
                CodeQueryDiagnosticImpact::Incomplete,
            ),
            (
                CodeQueryDiagnosticCode::BroadQuery,
                CodeQueryDiagnosticImpact::Advisory,
            ),
        ]
    );
    assert!(matches!(
        cancelled_query_result().completion(),
        CodeQueryCompletion::Cancelled
    ));
}

#[test]
fn call_relation_diagnostics_map_without_inspecting_messages() {
    use CallRelationDiagnosticCode as Lower;
    use CodeQueryDiagnosticCode as Code;
    use CodeQueryDiagnosticImpact as Impact;

    let cases = [
        (
            Lower::BudgetExhausted,
            Code::CallRelationBudgetExhausted,
            Impact::Incomplete,
        ),
        (
            Lower::ParseFailed,
            Code::CallRelationParseFailed,
            Impact::Incomplete,
        ),
        (
            Lower::CandidatesOmitted,
            Code::CallRelationCandidatesOmitted,
            Impact::Incomplete,
        ),
        (
            Lower::TargetsAmbiguous,
            Code::CallRelationTargetsAmbiguous,
            Impact::Advisory,
        ),
        (
            Lower::CandidateLimit,
            Code::CallRelationCandidateLimit,
            Impact::Incomplete,
        ),
        (
            Lower::AnalysisFailed,
            Code::CallRelationAnalysisFailed,
            Impact::Incomplete,
        ),
    ];
    for (lower, code, impact) in cases {
        let mapped = map_call_relation_diagnostic(
            "rust",
            CallRelationDiagnostic {
                code: lower,
                message: "same prose for every producer".to_string(),
                context: "crate::function".to_string(),
                reason_kind: (lower == Lower::AnalysisFailed)
                    .then(|| "unsupported_target_shape".to_string()),
            },
        );
        assert_eq!((mapped.code, mapped.impact), (code, impact));
    }
}

#[test]
fn call_cache_profile_uses_typed_diagnostics_for_completeness() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let unit = CodeUnit::new(
        ProjectFile::new(root, "src/missing.ts"),
        CodeUnitType::Function,
        "",
        "caller",
    );
    let mut cache = CallTraversalCache::default();
    let mut budget = CodeQueryExecutionBudget::default();
    let mut diagnostics = Vec::new();
    let mut profile = Some(QueryCacheProfile::default());

    let built = cached_call_relation(
        &analyzer,
        &unit,
        false,
        &mut cache,
        &mut budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut profile,
    );
    assert!(!built.truncated);
    assert!(!built.cancelled);
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == CallRelationDiagnosticCode::AnalysisFailed })
    );

    let replayed = cached_call_relation(
        &analyzer,
        &unit,
        false,
        &mut cache,
        &mut budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut profile,
    );
    assert_eq!(replayed.sites.len(), built.sites.len());
    assert_eq!(replayed.diagnostics, built.diagnostics);
    assert_eq!(replayed.truncated, built.truncated);
    assert_eq!(replayed.cancelled, built.cancelled);

    cache.incoming.insert(
        unit.clone(),
        CallRelationResult {
            diagnostics: vec![CallRelationDiagnostic {
                code: CallRelationDiagnosticCode::ParseFailed,
                message: "parse failed".to_string(),
                context: "caller".to_string(),
                reason_kind: None,
            }],
            ..CallRelationResult::default()
        },
    );
    let incoming = cached_call_relation(
        &analyzer,
        &unit,
        true,
        &mut cache,
        &mut budget,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut profile,
    );
    assert!(!incoming.truncated);
    assert!(!incoming.cancelled);

    let profile = profile.expect("cache profile");
    assert_eq!(profile.outgoing_call.lookups, 2);
    assert_eq!(profile.outgoing_call.misses, 1);
    assert_eq!(profile.outgoing_call.builds, 1);
    assert_eq!(profile.outgoing_call.incomplete_builds, 1);
    assert_eq!(profile.outgoing_call.complete_builds, 0);
    assert_eq!(profile.outgoing_call.hits, 1);
    assert_eq!(profile.outgoing_call.incomplete_hits, 1);
    assert_eq!(profile.outgoing_call.complete_hits, 0);
    assert_eq!(profile.incoming_call.lookups, 1);
    assert_eq!(profile.incoming_call.hits, 1);
    assert_eq!(profile.incoming_call.incomplete_hits, 1);
    assert_eq!(profile.incoming_call.complete_hits, 0);

    let advisory = CallRelationResult {
        diagnostics: vec![CallRelationDiagnostic {
            code: CallRelationDiagnosticCode::TargetsAmbiguous,
            message: "ambiguous".to_string(),
            context: "caller".to_string(),
            reason_kind: None,
        }],
        ..CallRelationResult::default()
    };
    assert!(call_relation_result_complete(&advisory));
}

#[test]
fn outbound_uses_missing_reference_or_definitions_is_typed_incomplete() {
    let root = std::env::temp_dir().join("bifrost-outbound-lookup-completeness");
    let file = ProjectFile::new(root, "src/app.ts");
    let definition = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
    let reference = ResolvedReferenceSite {
        path: "src/app.ts".to_string(),
        text: "target".to_string(),
        range: Range {
            start_byte: 10,
            end_byte: 16,
            start_line: 1,
            end_line: 1,
        },
        focus_start_byte: 10,
        focus_end_byte: 16,
    };
    let grouped = group_outbound_lookup_candidates(vec![
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::Ambiguous,
            reference: None,
            definitions: vec![definition],
            lexical_definition: None,
            diagnostics: Vec::new(),
        },
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::Ambiguous,
            reference: Some(reference),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        },
    ]);

    assert_eq!(grouped.omitted_sites, 2);
    assert_eq!(grouped.ambiguous_sites, 2);
    assert!(!grouped.ambiguous_candidates_complete);
    let mut diagnostics = Vec::new();
    append_outbound_lookup_diagnostics(
        &mut diagnostics,
        Language::TypeScript,
        &file,
        grouped.ambiguous_sites,
        grouped.ambiguous_candidates_complete,
        grouped.omitted_sites,
    );
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: false,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { codes }
            if codes == vec![CodeQueryDiagnosticCode::UsesCandidatesOmitted]
    ));
}

#[test]
fn outbound_uses_ambiguity_is_advisory_only_when_every_target_survives() {
    let root = std::env::temp_dir().join("bifrost-outbound-lookup-advisory");
    let file = ProjectFile::new(root, "src/app.ts");
    let mut diagnostics = Vec::new();
    append_outbound_lookup_diagnostics(&mut diagnostics, Language::TypeScript, &file, 1, true, 0);

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesTargetsAmbiguous
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Advisory);
}

#[test]
fn call_declaration_projection_reports_retained_file_scope_target_as_omitted() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let unprojectable = CodeUnit::file_scope(file.clone());
    let range = Range {
        start_byte: 0,
        end_byte: 1,
        start_line: 1,
        end_line: 1,
    };
    let declaration = DeclarationValue {
        unit: caller.clone(),
        range,
    };
    let site = CallSite {
        file,
        range,
        callee_range: range,
        caller: caller.clone(),
        callee: unprojectable,
        kind: CallSyntaxKind::Function,
        proof: UsageProof::Unproven,
        receiver: None,
        arguments: Vec::new(),
    };
    let mut cache = CallTraversalCache::default();
    cache.outgoing.insert(
        caller,
        CallRelationResult {
            sites: vec![site],
            diagnostics: vec![CallRelationDiagnostic {
                code: CallRelationDiagnosticCode::TargetsAmbiguous,
                message: "ambiguous".to_string(),
                context: "caller".to_string(),
                reason_kind: None,
            }],
            ..CallRelationResult::default()
        },
    );
    let mut diagnostics = Vec::new();

    let (expansions, exhausted) = call_declaration_expansions(
        &analyzer,
        &declaration,
        &QueryStep::Callees(CallTraversalFilter::default()),
        &CallTraversalFilter::default(),
        &mut IndexedDeclarations::default(),
        &mut cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        8,
        None,
        &mut diagnostics,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::CallRelationCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
}

#[test]
fn outbound_uses_projection_reports_unindexed_target_and_suppresses_advisory() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let declaration = DeclarationValue {
        unit: caller.clone(),
        range: Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        },
    };
    let mut cache = ReferenceTraversalCache::default();
    cache.outbound.insert(
        file.clone(),
        vec![ReferenceHit {
            file,
            range: declaration.range,
            enclosing_unit: caller,
            kind: None,
            resolved: CodeUnit::file_scope(declaration.unit.source().clone()),
            confidence: 1_000_000,
            usage_kind: UsageHitKind::Reference,
            proof: UsageProof::Unproven,
        }],
    );
    let mut diagnostics = vec![diagnostic(
        CodeQueryDiagnosticCode::UsesTargetsAmbiguous,
        CodeQueryDiagnosticImpact::Advisory,
    )];

    let (expansions, exhausted) = outbound_reference_expansions(
        &analyzer,
        &declaration,
        &ReferenceTraversalFilter::default(),
        &mut IndexedDeclarations::default(),
        &mut cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        8,
        None,
        &mut diagnostics,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
}

fn formal_call_site_value(binding: CallBindingStatus) -> CallSiteValue {
    let root = std::env::temp_dir().join("bifrost-call-input-completeness");
    let file = ProjectFile::new(root, "src/app.ts");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let callee = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "callee");
    let range = Range {
        start_byte: 0,
        end_byte: 1,
        start_line: 1,
        end_line: 1,
    };
    CallSiteValue(
        CallSite {
            file,
            range,
            callee_range: range,
            caller,
            callee,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Proven,
            receiver: None,
            arguments: vec![CallArgument {
                range,
                name: None,
                position: Some(0),
                formal_index: (binding == CallBindingStatus::Complete).then_some(0),
                formal_name: (binding == CallBindingStatus::Complete)
                    .then(|| "payload".to_string()),
                variadic: false,
                spread: false,
            }],
        },
        binding,
    )
}

#[test]
fn formal_call_input_with_unavailable_binding_is_incomplete() {
    let site = formal_call_site_value(CallBindingStatus::Unavailable);

    let (expansions, incomplete) =
        call_input_expansions(&site, &CallInputSelector::ParameterIndex(0));

    assert!(expansions.is_empty());
    assert!(incomplete);
}

#[test]
fn formal_call_input_with_known_nonmatching_binding_is_complete() {
    let site = formal_call_site_value(CallBindingStatus::Complete);

    let (missing, incomplete) = call_input_expansions(&site, &CallInputSelector::ParameterIndex(1));
    let (exact, exact_incomplete) = call_input_expansions(
        &site,
        &CallInputSelector::ParameterName("payload".to_string()),
    );

    assert!(missing.is_empty());
    assert!(!incomplete);
    assert_eq!(exact.len(), 1, "known exact bindings remain positive");
    assert!(!exact_incomplete);
}

#[test]
fn formal_call_input_with_spread_argument_is_incomplete() {
    let mut site = formal_call_site_value(CallBindingStatus::Complete);
    site.0.arguments[0].formal_index = None;
    site.0.arguments[0].formal_name = None;
    site.0.arguments[0].spread = true;

    let (expansions, incomplete) =
        call_input_expansions(&site, &CallInputSelector::ParameterIndex(0));

    assert!(expansions.is_empty());
    assert!(incomplete);
}

#[test]
fn m3_inbound_reference_distinguishes_missing_real_owner_from_file_scope() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
    let missing_owner = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let range = Range {
        start_byte: 0,
        end_byte: 1,
        start_line: 1,
        end_line: 1,
    };
    let declaration = DeclarationValue {
        unit: target.clone(),
        range,
    };
    let reference_hit = |enclosing_unit| ReferenceHit {
        file: file.clone(),
        range,
        enclosing_unit,
        kind: None,
        resolved: target.clone(),
        confidence: 1_000_000,
        usage_kind: UsageHitKind::Reference,
        proof: UsageProof::Unproven,
    };
    let filter = ReferenceTraversalFilter::default();
    let step = QueryStep::UsedBy(filter.clone());

    let mut missing_cache = ReferenceTraversalCache::default();
    missing_cache
        .inbound
        .insert(target.clone(), vec![reference_hit(missing_owner)]);
    let mut diagnostics = vec![diagnostic(
        CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
        CodeQueryDiagnosticImpact::Advisory,
    )];
    let (expansions, exhausted) = inbound_reference_expansions(
        &analyzer,
        &declaration,
        &step,
        &filter,
        &mut IndexedDeclarations::default(),
        &mut missing_cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        &mut diagnostics,
        8,
        None,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::ReferenceCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);

    let mut file_scope_cache = ReferenceTraversalCache::default();
    file_scope_cache.inbound.insert(
        target.clone(),
        vec![reference_hit(CodeUnit::file_scope(file.clone()))],
    );
    let mut diagnostics = Vec::new();
    let (expansions, exhausted) = inbound_reference_expansions(
        &analyzer,
        &declaration,
        &step,
        &filter,
        &mut IndexedDeclarations::default(),
        &mut file_scope_cache,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        &mut diagnostics,
        8,
        None,
        &mut None,
    );

    assert!(expansions.is_empty());
    assert!(!exhausted);
    assert!(diagnostics.is_empty());
}

#[test]
fn m3_inbound_reference_bounded_samples_remain_positive_and_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
    let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
    let sample_hits = [
        UsageHit::new(file.clone(), 1, 0, 6, caller.clone(), 1.0, "target"),
        UsageHit::new(file, 2, 8, 14, caller, 1.0, "target"),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    let (hits, incomplete) = reference_hits_for_target(
        &analyzer,
        FuzzyResult::TooManyCallsites {
            short_name: "target".to_string(),
            total_callsites: 2,
            limit: 1,
            sample_hits,
        },
        &target,
    );

    assert!(incomplete);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].resolved, target);
    assert_eq!(hits[0].proof, UsageProof::Proven);
}

#[test]
fn outbound_uses_scan_without_indexed_source_is_incomplete() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/missing.ts");
    let mut diagnostics = Vec::new();

    let (hits, exhausted) = scan_outbound_reference_hits(
        &analyzer,
        &file,
        &mut CodeQueryExecutionBudget::default(),
        CodeQueryExecutionLimits::default(),
        8,
        None,
        &mut diagnostics,
    );

    assert!(hits.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::UsesCandidatesOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
}

#[test]
fn members_projection_reports_unindexed_direct_child_as_semantic_omission() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let file = ProjectFile::new(root, "src/app.ts");
    let declaration = DeclarationValue {
        unit: CodeUnit::new(file.clone(), CodeUnitType::Class, "", "Owner"),
        range: Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        },
    };
    let mut omissions = BTreeMap::new();

    let (expansions, exhausted) = direct_member_expansions(
        &analyzer,
        &declaration,
        vec![CodeUnit::file_scope(file)],
        &mut IndexedDeclarations::default(),
        &mut CodeQueryExecutionBudget::default(),
        8,
        &mut omissions,
    );
    let mut diagnostics = Vec::new();
    append_semantic_omission_diagnostics(&mut diagnostics, &QueryStep::Members, omissions);

    assert!(expansions.is_empty());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: exhausted,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn hierarchy_projection_keeps_exact_rows_and_reports_unindexed_relations() {
    let source = "class Exact {}\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), "src/app.ts");
    file.write(source).expect("write source");
    let analyzer =
        TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
    let exact = analyzer
        .all_declarations()
        .find(|unit| unit.short_name() == "Exact")
        .expect("exact class declaration");
    let missing_file = ProjectFile::new(root, "src/missing.ts");
    let missing = CodeUnit::new(missing_file, CodeUnitType::Class, "", "Missing");
    let mut indexed = IndexedDeclarations::default();
    let mut omissions = BTreeMap::new();
    let mut exhausted = false;

    let retained = project_hierarchy_declaration(
        &analyzer,
        &exact,
        &mut indexed,
        &mut omissions,
        &mut exhausted,
    );
    let omitted = project_hierarchy_declaration(
        &analyzer,
        &missing,
        &mut indexed,
        &mut omissions,
        &mut exhausted,
    );
    let mut diagnostics = Vec::new();
    append_semantic_omission_diagnostics(
        &mut diagnostics,
        &QueryStep::Supertypes(HierarchyTraversal::Direct),
        omissions,
    );

    assert!(retained.is_some(), "an exact hierarchy row must survive");
    assert!(omitted.is_none());
    assert!(exhausted);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
    );
    assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: exhausted,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn enclosing_declaration_index_retains_exact_owner_and_reports_missing_real_range() {
    let root = std::env::temp_dir().join("bifrost-enclosing-declaration-completeness");
    let file = ProjectFile::new(root, "src/app.ts");
    let exact = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "exact");
    let missing = CodeUnit::new(file, CodeUnitType::Function, "", "missing");
    let exact_range = Range {
        start_byte: 0,
        end_byte: 20,
        start_line: 1,
        end_line: 2,
    };
    let seed_range = Range {
        start_byte: 5,
        end_byte: 10,
        start_line: 1,
        end_line: 1,
    };
    let mut index = EnclosingDeclarationIndex::default();
    index.retain(exact.clone(), [exact_range]);
    index.retain(missing, std::iter::empty());
    index.sort();

    let retained = index.enclosing(seed_range).expect("exact owner survives");

    assert_eq!(retained.unit, exact);
    assert!(index.projection_omitted);
    let mut diagnostics = Vec::new();
    append_semantic_omission_diagnostics(
        &mut diagnostics,
        &QueryStep::EnclosingDecl,
        BTreeMap::from([(
            (
                Language::TypeScript,
                "a real declaration in the seed file had no exact indexed range",
            ),
            1,
        )]),
    );
    assert!(matches!(
        CodeQueryResult {
            results: Vec::new(),
            truncated: index.projection_omitted,
            diagnostics,
        }
        .completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn enclosing_declaration_index_treats_file_scope_no_owner_as_complete() {
    let root = std::env::temp_dir().join("bifrost-enclosing-file-scope");
    let file = ProjectFile::new(root, "src/app.ts");
    let mut index = EnclosingDeclarationIndex::default();
    index.retain(CodeUnit::file_scope(file), std::iter::empty());

    assert!(index.exact.is_empty());
    assert!(!index.projection_omitted);
    assert!(
        index
            .enclosing(Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            })
            .is_none()
    );
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

#[test]
fn detailed_execution_aligns_evidence_hashes_owners_and_direct_work() {
    let source = r#"export function handler(input: string) {
sink(input);
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "result_detail": "full"
    }))
    .expect("query");

    let detailed =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);

    assert_eq!(detailed.result.results.len(), 1);
    assert!(
        detailed.profile.is_none(),
        "ordinary detailed execution should not pay profiling overhead"
    );
    assert_eq!(detailed.evidence.len(), 1);
    let evidence = &detailed.evidence[0];
    assert_eq!(evidence.result_index, 0);
    assert_eq!(evidence.domain, DetailedCodeQueryDomain::StructuralMatch);
    assert!(matches!(
        &evidence.key,
        DetailedCodeQueryKey::StructuralMatch {
            kind,
            analyzer_id: Some(_),
        } if kind == "call"
    ));
    let byte_span = evidence.byte_span.clone().expect("match byte span");
    assert_eq!(&source[byte_span.clone()], "sink(input)");
    assert_eq!(
        evidence.source_slice_sha256,
        Some(Sha256::digest(&source.as_bytes()[byte_span]).into())
    );
    assert!(matches!(
        &evidence.stable_owner_candidate,
        Some(CodeQueryStableOwnerCandidate {
            derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
            semantic_key,
            ..
        }) if semantic_key.contains("handler") && semantic_key.contains("sink")
    ));
    assert_eq!(detailed.work.scanned_files, 1);
    assert_eq!(
        detailed.work.scanned_source_bytes,
        u64::try_from(source.len()).expect("source length")
    );
    assert!(detailed.work.fact_nodes > 0);
    assert!(detailed.work.pipeline_rows >= 1);
    assert_eq!(detailed.work.examined_references, 0);
}

#[test]
fn detailed_file_terminal_is_artifact_only() {
    let source = "export function handler() { sink(); }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "steps": [{ "op": "file_of" }],
        "result_detail": "full"
    }))
    .expect("query");

    let detailed =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);

    assert!(matches!(
        detailed.result.results[0].value,
        CodeQueryResultValue::File { ref value } if value.path == "app.ts"
    ));
    assert_eq!(detailed.evidence[0].domain, DetailedCodeQueryDomain::File);
    assert_eq!(detailed.evidence[0].key, DetailedCodeQueryKey::File);
    assert!(detailed.evidence[0].byte_span.is_none());
    assert!(detailed.evidence[0].source_slice_sha256.is_none());
    assert!(detailed.evidence[0].stable_owner_candidate.is_none());
}

#[test]
fn detailed_execution_covers_every_semantic_terminal_domain() {
    let source = r#"export function target(payload: string) { return payload; }
export function caller() { return target("secret"); }
class Service { run() {} }
export function invoke(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let cases = [
        (
            DetailedCodeQueryDomain::Declaration,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "enclosing_decl" }],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::ReferenceSite,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "references_of", "proof": "proven" }
                ],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::CallSite,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" }
                ],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::ExpressionSite,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 }
                ],
                "result_detail": "full"
            }),
        ),
        (
            DetailedCodeQueryDomain::ReceiverAnalysis,
            json!({
                "match": { "kind": "call", "callee": { "name": "run" } },
                "steps": [{ "op": "receiver_targets" }],
                "result_detail": "full"
            }),
        ),
    ];

    for (expected_domain, query) in cases {
        let query = CodeQuery::from_json(&query).expect("query");
        let detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(
            detailed.result.results.len(),
            1,
            "terminal domain {expected_domain:?}: {}",
            detailed.result.render_text()
        );
        let evidence = &detailed.evidence[0];
        assert_eq!(evidence.domain, expected_domain);
        assert_eq!(evidence.result_index, 0);
        assert_eq!(evidence.file, file);
        assert!(evidence.byte_span.is_some());
        if expected_domain == DetailedCodeQueryDomain::ReceiverAnalysis {
            assert!(evidence.source_slice_sha256.is_none());
            assert!(evidence.stable_owner_candidate.is_none());
        } else {
            let byte_span = evidence.byte_span.clone().expect("byte span");
            assert_eq!(
                evidence.source_slice_sha256,
                Some(Sha256::digest(&source.as_bytes()[byte_span]).into())
            );
            assert!(matches!(
                evidence.stable_owner_candidate,
                Some(CodeQueryStableOwnerCandidate {
                    derivation: CodeQueryStableOwnerDerivation::AnalyzerDeclarationId,
                    ..
                })
            ));
        }
    }
}

#[test]
fn cross_file_declaration_hydration_is_charged_or_degrades_to_weak_evidence() {
    let target_source = "export function target() {}\n";
    let caller_source =
        "import { target } from './target';\nexport function caller() { target(); }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let target_file = ProjectFile::new(root.clone(), PathBuf::from("target.ts"));
    let caller_file = ProjectFile::new(root.clone(), PathBuf::from("caller.ts"));
    target_file.write(target_source).expect("write target");
    caller_file.write(caller_source).expect("write caller");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "where": ["target.ts"],
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callers", "proof": "proven" }
        ],
        "result_detail": "full"
    }))
    .expect("query");

    let complete =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);
    assert_eq!(complete.result.results.len(), 1);
    assert_eq!(
        complete.evidence[0].domain,
        DetailedCodeQueryDomain::Declaration
    );
    assert_eq!(complete.evidence[0].file, caller_file);
    assert!(complete.evidence[0].source_slice_sha256.is_some());
    assert!(complete.work.scanned_source_bytes >= caller_source.len() as u64);

    let tight_limit = usize::try_from(complete.work.scanned_source_bytes)
        .expect("work fits usize")
        .saturating_sub(1);
    let partial = execute_code_query_detailed(
        &analyzer,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: tight_limit,
            ..CodeQueryExecutionLimits::default()
        },
        None,
    );
    assert_eq!(
        partial.result.results.len(),
        1,
        "the already-produced declaration remains available"
    );
    assert_eq!(partial.evidence[0].file, caller_file);
    assert!(partial.evidence[0].source_slice_sha256.is_none());
    assert!(partial.result.truncated);
    assert!(partial.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
            && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
    }));
    assert!(partial.work.scanned_source_bytes <= tight_limit as u64);
}

#[test]
fn cross_file_call_nested_rendering_cannot_retry_an_exhausted_source() {
    let target_source = "export function target() {}\n";
    let caller_source =
        "import { target } from './target';\nexport function caller() { target(); }\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("target.ts"))
        .write(target_source)
        .expect("write target");
    let caller_file = ProjectFile::new(root.clone(), PathBuf::from("caller.ts"));
    caller_file.write(caller_source).expect("write caller");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "where": ["target.ts"],
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "call_sites_to", "proof": "proven" }
        ],
        "result_detail": "full"
    }))
    .expect("query");

    let complete =
        execute_code_query_detailed(&analyzer, &query, CodeQueryExecutionLimits::default(), None);
    assert_eq!(complete.result.results.len(), 1);
    assert_eq!(complete.evidence[0].file, caller_file);
    assert!(complete.evidence[0].source_slice_sha256.is_some());
    let tight_limit = usize::try_from(complete.work.scanned_source_bytes)
        .expect("work fits usize")
        .saturating_sub(1);

    let partial = execute_code_query_detailed(
        &analyzer,
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: tight_limit,
            ..CodeQueryExecutionLimits::default()
        },
        None,
    );
    assert_eq!(partial.result.results.len(), 1);
    assert!(partial.evidence[0].source_slice_sha256.is_none());
    assert!(partial.work.scanned_source_bytes <= tight_limit as u64);
    let CodeQueryResultValue::CallSite { value } = &partial.result.results[0].value else {
        panic!("expected call-site result");
    };
    assert!(
        value.caller.node_range.is_none(),
        "nested caller rendering must use the negative cache rather than retrying"
    );
    assert!(value.callee.node_range.is_some());
    assert!(partial.result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
    }));
}

#[test]
fn receiver_budget_projects_one_remaining_fact_cap_across_all_work() {
    let base = ReceiverAnalysisBudget::default();
    let bounded = receiver_budget_for_remaining_work(base, 100, usize::MAX);
    assert_eq!(bounded.max_scope_nodes, 75);
    assert_eq!(bounded.max_summary_expansions, 25);
    assert_eq!(
        bounded
            .max_scope_nodes
            .saturating_add(bounded.max_summary_expansions),
        100
    );

    let tiny = receiver_budget_for_remaining_work(base, 1, 1);
    assert!(
        tiny.max_scope_nodes
            .saturating_add(tiny.max_summary_expansions)
            <= 1
    );
    assert_eq!(tiny.max_targets, 1);

    let ample = receiver_budget_for_remaining_work(base, usize::MAX, usize::MAX);
    assert_eq!(ample, base);
}

#[test]
fn tiny_receiver_budget_returns_an_explicit_exceeded_row() {
    let source = r#"class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
const service = makeService();
service.run();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [{ "op": "receiver_targets" }]
    }))
    .expect("query");

    let result =
        execute_with_receiver_budget_for_test(&analyzer, &query, ReceiverAnalysisBudget::tiny());

    assert!(result.truncated);
    assert!(result.render_text().contains("limit -> scope_nodes"));
    assert!(matches!(
        result.results[0].value,
        CodeQueryResultValue::ReceiverAnalysis { ref value }
            if value.outcome == "exceeded_budget" && value.limit == Some("scope_nodes")
    ));

    let file_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [{ "op": "receiver_targets" }, { "op": "file_of" }]
    }))
    .expect("file query");
    let file_result = execute_with_receiver_budget_for_test(
        &analyzer,
        &file_query,
        ReceiverAnalysisBudget::tiny(),
    );
    assert!(file_result.truncated);
    assert!(matches!(
        file_result.results[0].value,
        CodeQueryResultValue::File { ref value } if value.path == "app.ts"
    ));

    let outcome_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "receiver_targets" },
            { "op": "receiver_outcome" }
        ],
        "result_detail": "full"
    }))
    .expect("outcome query");
    let outcome = execute_with_receiver_budget_for_test(
        &analyzer,
        &outcome_query,
        ReceiverAnalysisBudget::tiny(),
    );
    assert!(matches!(
        outcome.results.as_slice(),
        [CodeQueryResultItem {
            value: CodeQueryResultValue::ReceiverOutcome { value },
            ..
        }] if value.outcome == "exceeded_budget"
            && value.coverage == "truncated"
            && value.candidate_count == 0
            && value.site_id == value.id
    ));

    let evidence_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "receiver_targets" },
            { "op": "receiver_evidence" }
        ]
    }))
    .expect("evidence query");
    let evidence = execute_with_receiver_budget_for_test(
        &analyzer,
        &evidence_query,
        ReceiverAnalysisBudget::tiny(),
    );
    assert!(evidence.results.is_empty());
}

#[test]
fn receiver_evidence_rows_join_to_their_mandatory_outcome() {
    let source = r#"class Service { run() {} }
export function caller(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal| {
        CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [
                { "op": "receiver_targets" },
                { "op": terminal }
            ],
            "result_detail": "full"
        }))
        .expect("receiver row query")
    };

    let outcome = execute(&analyzer, &query("receiver_outcome"));
    let evidence = execute(&analyzer, &query("receiver_evidence"));
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcome.results[0].value else {
        panic!("expected receiver outcome")
    };
    assert_eq!(outcome.outcome, "precise");
    assert_eq!(outcome.coverage, "exhaustive");
    assert_eq!(outcome.candidate_count, 1);
    assert!(outcome.site_ast_id.is_some());
    assert_eq!(evidence.results.len(), 1, "{}", evidence.render_text());
    let CodeQueryResultValue::ReceiverEvidence { value: evidence } = &evidence.results[0].value
    else {
        panic!("expected receiver evidence")
    };
    assert_eq!(evidence.site_id, outcome.site_id);
    assert_eq!(evidence.ordinal, 0);
    assert_eq!(evidence.chain_hop, 0);
    assert_eq!(evidence.proof, "precise");
    assert_eq!(evidence.completeness, "exhaustive");
    assert!(evidence.declaration_id.is_some());
}

#[test]
fn member_occurrence_ast_id_correlates_receiver_and_resolution_rows() {
    let source = r#"class Service { run() {} }
export function caller(service: Service) { service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = |terminal: &str| {
        let mut steps = vec![json!({ "op": terminal })];
        if terminal == "member_targets" {
            steps.push(json!({ "op": "receiver_outcome" }));
        }
        CodeQuery::from_json(&json!({
            "where": ["app.ts"],
            "occurrences": {
                "role": ["member_position"]
            },
            "steps": steps,
            "result_detail": "full"
        }))
        .expect("occurrence relation query")
    };

    let candidates = execute(&analyzer, &query("candidates_of"));
    let outcomes = execute(&analyzer, &query("member_targets"));
    let CodeQueryResultValue::ResolutionCandidate { value: candidate } =
        &candidates.results[0].value
    else {
        panic!("expected resolution candidate")
    };
    let CodeQueryResultValue::ReceiverOutcome { value: outcome } = &outcomes.results[0].value
    else {
        panic!("expected receiver outcome")
    };
    assert_eq!(
        outcome.site_ast_id.as_deref(),
        Some(candidate.ast_id.as_str())
    );
    assert_eq!(outcome.outcome, "precise");
}

#[test]
fn receiver_factory_evidence_is_a_stable_parent_linked_chain() {
    let source = r#"class Service { run() {} }
function makeService() { return new Service(); }
export function caller() { const service = makeService(); service.run(); }
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
        .write(source)
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "callee": { "name": "run" },
            "receiver": { "capture": "receiver" }
        },
        "steps": [
            { "op": "points_to", "capture": "receiver" },
            { "op": "receiver_evidence" }
        ],
        "result_detail": "full"
    }))
    .expect("factory evidence query");

    let first = execute(&analyzer, &query);
    let second = execute(&analyzer, &query);
    assert_eq!(first.results.len(), 2, "{}", first.render_text());
    let rows = first
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::ReceiverEvidence { value } => value,
            _ => panic!("expected receiver evidence"),
        })
        .collect::<Vec<_>>();
    assert_eq!(rows[0].evidence_kind, "factory_return");
    assert!(rows[0].factory_id.is_some());
    assert_eq!(rows[0].parent_evidence_id, None);
    assert_eq!(
        rows[1].parent_evidence_id.as_deref(),
        Some(rows[0].id.as_str())
    );
    assert_eq!(rows[1].chain_hop, 1);
    let second_ids = second
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::ReceiverEvidence { value } => value.id.as_str(),
            _ => panic!("expected receiver evidence"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        second_ids,
        rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn csharp_cross_file_receiver_step_reuses_bounded_reference_facts() {
    let definitions = r#"
namespace Demo;
public class Service {
    public void Run() {}
}
"#;
    let usage = r#"
namespace Demo;
public class Caller {
    public void Call(Service service) { service.Run(); }
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "Definitions.cs")
        .write(definitions)
        .expect("write definitions");
    ProjectFile::new(root.clone(), "Usage.cs")
        .write(usage)
        .expect("write usage");
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
    let query = CodeQuery::from_json(&json!({
        "where": ["Definitions.cs"],
        "match": { "kind": "method", "name": "Run" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of", "proof": "proven" },
            { "op": "member_targets" }
        ]
    }))
    .expect("cross-file receiver query");
    let provider = workspace
        .analyzer()
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::CSharp)
        .expect("C# structural provider");
    let extractions_before = provider.structural_extraction_count();

    let result = execute_workspace(&workspace, &query);

    assert_eq!(
        provider.structural_extraction_count(),
        extractions_before + 2,
        "the seed and reference traversal each extract their own file; receiver analysis must not perform a third extraction"
    );
    assert!(
        matches!(
            result.results.as_slice(),
            [CodeQueryResultItem {
                value: CodeQueryResultValue::ReceiverAnalysis { value },
                ..
            }] if value.outcome == "precise"
                && matches!(
                    value.member_targets.as_slice(),
                    [target] if target.fq_name == "Demo.Service.Run"
                )
        ),
        "{}",
        result.render_text()
    );
}

#[test]
fn cancelled_composed_query_retains_no_partial_rows() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write("function alpha() {}\nfunction beta() {}\n")
        .expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function", "name": "alpha" } },
            { "match": { "kind": "function", "name": "beta" } }
        ]
    }))
    .expect("query");
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let result = execute_with_cancellation(
        &analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    );

    assert!(result.results.is_empty());
    assert!(result.truncated);
    assert_eq!(result.diagnostics.len(), 1);
    assert!(result.diagnostics[0].branch.is_empty());
    assert!(result.diagnostics[0].message.contains("cancelled"));
}

#[test]
fn cancellation_after_positive_rows_retains_aligned_partial_evidence() {
    let source = r#"export function caller() {
alpha();
beta();
gamma();
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "result_detail": "full"
    }))
    .expect("query");

    let detailed = (2..64)
        .find_map(|checks| {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let detailed = execute_code_query_detailed(
                &analyzer,
                &query,
                CodeQueryExecutionLimits::default(),
                Some(&cancellation),
            );
            (detailed
                .result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
                && detailed.work.pipeline_rows >= 3
                && !detailed.result.results.is_empty()
                && detailed.result.results.len() < 3)
                .then_some(detailed)
        })
        .expect("a deterministic cancellation checkpoint during detailed row rendering");

    assert!(detailed.result.truncated);
    assert!(detailed.result.results.len() < 3);
    assert_eq!(detailed.result.results.len(), detailed.evidence.len());
    assert!(
        detailed
            .evidence
            .iter()
            .enumerate()
            .all(|(index, evidence)| evidence.result_index == index
                && evidence.source_slice_sha256.is_some())
    );
    assert!(detailed.work.pipeline_rows >= detailed.evidence.len() as u64);
    assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
}

#[test]
fn canonical_ast_keys_stay_within_the_stable_identity_limit() {
    let shallow = vec![("module", None), ("function", Some("run"))];
    let key = bounded_canonical_ast_key(&shallow).expect("shallow key");
    assert_eq!(key, serde_json::to_string(&shallow).expect("json"));

    // A chain deep enough to overflow 256 bytes verbatim (closures in
    // closures) must still produce a valid bounded key that keeps the
    // outermost and innermost context and stays deterministic.
    let deep: Vec<(&str, Option<&str>)> = (0..40)
        .map(|depth| {
            if depth % 2 == 0 {
                ("call", Some("unwrap_or_else_with_a_long_name"))
            } else {
                ("lambda", None)
            }
        })
        .collect();
    let key = bounded_canonical_ast_key(&deep).expect("bounded key");
    assert!(key.len() <= 256, "key must fit the identity limit: {key}");
    let segments: Vec<(String, Option<String>)> =
        serde_json::from_str(&key).expect("bounded key stays canonical JSON");
    assert!(
        segments.iter().any(|(kind, name)| kind == "elided"
            && name.as_deref().is_some_and(|name| name.starts_with('h'))),
        "long chains elide their middle: {key}"
    );
    assert_eq!(
        segments.first().map(|(kind, _)| kind.as_str()),
        Some("call")
    );
    assert_eq!(
        segments.last().map(|(kind, _)| kind.as_str()),
        Some("lambda")
    );
    assert_eq!(
        bounded_canonical_ast_key(&deep).expect("deterministic"),
        key
    );

    // Distinct chains must keep distinct keys even when both are elided.
    let mut other = deep.clone();
    other[20] = ("call", Some("a_different_middle_segment"));
    assert_ne!(bounded_canonical_ast_key(&other).expect("other key"), key);
}

#[test]
fn detailed_row_field_registry_covers_every_domain_without_duplicate_fields() {
    let mut labels = std::collections::HashSet::new();
    for domain in ALL_DETAILED_CODE_QUERY_DOMAINS {
        assert!(labels.insert(domain.label()), "duplicate domain label");
        assert!(
            !domain.row_fields().is_empty(),
            "{} must declare an addressable scalar surface",
            domain.label()
        );
        let mut field_names = std::collections::HashSet::new();
        for field in domain.row_fields() {
            assert!(
                field_names.insert(field.name),
                "duplicate field {}.{}",
                domain.label(),
                field.name
            );
        }
    }
}

#[test]
fn occurrence_row_projection_exposes_typed_identity_and_rejects_unknown_fields() {
    let target = CodeQueryDeclaration {
        path: "src/lib.rs".to_string(),
        language: "rust",
        kind: "function",
        fq_name: "crate::target".to_string(),
        start_line: 1,
        end_line: 1,
        signature: None,
        id: Some("decl-1".to_string()),
        node_range: None,
        semantic_model: None,
    };
    let result = CodeQueryResultValue::Occurrence {
        value: Box::new(CodeQueryOccurrence {
            id: "occurrence-1".to_string(),
            ast_id: "ast-1".to_string(),
            path: "src/lib.rs".to_string(),
            language: "rust",
            class: "reference",
            role: "call_callee",
            namespace: "value",
            range: CodeQueryRange {
                start_line: 2,
                start_column: 5,
                end_line: 2,
                end_column: 11,
            },
            start_byte: 20,
            end_byte: 26,
            enclosing_symbol: Some("crate::caller".to_string()),
            raw_spelling: "target".to_string(),
            decoded_spelling: None,
            target: CodeQueryOccurrenceTarget::Resolved {
                units: vec![target],
            },
        }),
    };
    let row = result.row();

    assert_eq!(row.domain(), DetailedCodeQueryDomain::Occurrence);
    assert_eq!(
        row.field("ast_id").expect("registered field"),
        Some(CodeQueryRowScalarRef::StableId("ast-1"))
    );
    assert_eq!(
        row.field("target_id").expect("registered field"),
        Some(CodeQueryRowScalarRef::DeclarationIdentity("decl-1"))
    );
    assert_eq!(
        row.field("target_count").expect("registered field"),
        Some(CodeQueryRowScalarRef::Integer(1))
    );

    let error = row.field("range").expect_err("ranges are not join keys");
    assert_eq!(error.domain(), DetailedCodeQueryDomain::Occurrence);
    assert_eq!(error.field(), "range");
}

#[test]
fn occurrence_row_projection_does_not_invent_one_identity_for_ambiguous_targets() {
    let declaration = |id: &str| CodeQueryDeclaration {
        path: "src/lib.rs".to_string(),
        language: "rust",
        kind: "function",
        fq_name: format!("crate::{id}"),
        start_line: 1,
        end_line: 1,
        signature: None,
        id: Some(id.to_string()),
        node_range: None,
        semantic_model: None,
    };
    let result = CodeQueryResultValue::Occurrence {
        value: Box::new(CodeQueryOccurrence {
            id: "occurrence-ambiguous".to_string(),
            ast_id: "ast-ambiguous".to_string(),
            path: "src/lib.rs".to_string(),
            language: "rust",
            class: "reference",
            role: "call_callee",
            namespace: "value",
            range: CodeQueryRange {
                start_line: 2,
                start_column: 5,
                end_line: 2,
                end_column: 11,
            },
            start_byte: 20,
            end_byte: 26,
            enclosing_symbol: None,
            raw_spelling: "target".to_string(),
            decoded_spelling: None,
            target: CodeQueryOccurrenceTarget::Resolved {
                units: vec![declaration("decl-1"), declaration("decl-2")],
            },
        }),
    };
    let row = result.row();

    assert_eq!(row.field("target_id").expect("registered field"), None);
    assert_eq!(
        row.field("target_count").expect("registered field"),
        Some(CodeQueryRowScalarRef::Integer(2))
    );
}
