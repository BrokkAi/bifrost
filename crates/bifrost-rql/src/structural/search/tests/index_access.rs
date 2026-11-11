use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
fn value_flow_registration_failures_keep_their_domain_in_mixed_queries() {
    let error = QueryAnalysisContextError::ValueFlowRegistrationInvalid {
        detail: Box::new(QueryAnalysisContextError::StaleArtifact {
            path: "src/Flow.java".into(),
        }),
    };
    let result = query_analysis_context_error_result(None, error);

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
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>,
        AnalyzerConfig::default(),
    )
    .expect("ephemeral workspace should build");
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .expect("valid CFG query");
    let provider = workspace
        .analyzer()
        .structural_fact_providers()
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
        python_import: None,
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
            window_order: None,
            branch: Vec::new(),
            seed: Arc::clone(&seed),
            steps: vec![],
        }],
        provenance_truncated: false,
        row_projection: Vec::new(),
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
#[hardwon("#5297: indexed custom rules used node-plus-role work counts as node IDs")]
fn indexed_custom_rules_match_scan_with_role_edges() {
    let source = "\
function outer(value = inner()) {
    function inner() { return 1; }
    if (value) {}
    return value;
}
class Example { static run() { return outer(); } }
";
    for (language, path, source) in [
        (Language::JavaScript, "app.js", source),
        (Language::TypeScript, "app.ts", source),
        (
            Language::CSharp,
            "App.cs",
            "class Example { static int Run(int value) { if (value > 0) {} return Target(); } }",
        ),
    ] {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let file = project.file(path);
        let analyzer = language_analyzer(language, project.project().clone());
        let facts = analyzer.structural_fact_providers()[0]
            .structural_facts(&file)
            .expect("structural facts");
        assert!(
            facts.role_count() > 0,
            "fixture must separate nodes from work"
        );

        let relation_pattern = if language == Language::CSharp {
            json!({"kind": "block", "body_state": "empty"})
        } else {
            json!({
                "kind": "call",
                "language_rule": "js/nested-function-reference-in-default-parameter"
            })
        };
        for pattern in [
            relation_pattern,
            json!({"kind": "method", "modifier": "static"}),
        ] {
            let query = CodeQuery::from_json(&json!({"match": pattern})).expect("query");
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
            for result in [&scan.result, &indexed.result] {
                assert!(!result.truncated, "{language:?} {pattern:?}: {result:?}");
                assert!(result.diagnostics.is_empty(), "{result:?}");
                assert_eq!(
                    result.results.len(),
                    1,
                    "{language:?} {pattern:?}: {result:?}"
                );
            }
            assert_eq!(
                serde_json::to_value(&indexed.result).expect("indexed result JSON"),
                serde_json::to_value(&scan.result).expect("scan result JSON"),
                "response mismatch for {language:?} {pattern:?}"
            );
            assert!(
                indexed
                    .profile
                    .expect("indexed profile")
                    .access_path
                    .selected
                    .starts_with("posting:")
            );
        }
    }
}

#[test]
fn indexed_postings_match_scan_results_in_every_structural_language() {
    let cases = [
        (
            Language::Cpp,
            "app.cpp",
            "#define AUDIT() audit()\nstruct App { void audit() {} void run() { audit(); this->audit(); AUDIT(); } };\nvoid audit() {}\nvoid run() { audit(); ::audit(); App a; a.audit(); }\n",
        ),
        (
            Language::CSharp,
            "App.cs",
            "class App { void Audit() {} void Run() { Audit(); this.Audit(); } }\n",
        ),
        (
            Language::Go,
            "app.go",
            "package app\nfunc audit() {}\ntype App struct { audit func() }\nfunc (a App) run() { audit(); a.audit() }\n",
        ),
        (
            Language::Java,
            "App.java",
            "class App { void audit() {} void run() { audit(); this.audit(); Util.audit(); } }\nclass Util { static void audit() {} }\n",
        ),
        (
            Language::JavaScript,
            "app.js",
            "function audit() {}\nconst app = { audit };\nfunction run() { audit(); app.audit(); }\n",
        ),
        (
            Language::Kotlin,
            "App.kt",
            "fun audit() {}\nobject Util { fun audit() {} }\nclass App { fun audit() {}; fun run() { audit(); this.audit(); Util.audit() } }\nfun run() { audit(); App().audit() }\n",
        ),
        (
            Language::Php,
            "app.php",
            "<?php\nfunction audit() {}\nclass App { function audit() {} function run() { audit(); \\audit(); $this->audit(); } }\n",
        ),
        (
            Language::Python,
            "app.py",
            "def audit():\n    pass\n\nclass App:\n    def audit(self): pass\n    def run(self):\n        audit()\n        self.audit()\n",
        ),
        (
            Language::Ruby,
            "app.rb",
            "def audit; end\nclass App\n def audit; end\n def run; audit(); self.audit(); end\nend\n",
        ),
        (
            Language::Rust,
            "lib.rs",
            "fn audit() {}\nstruct App; impl App { fn audit(&self) {} }\nmacro_rules! call_audit { () => { audit() }; }\nfn run() { audit(); crate::audit(); App.audit(); call_audit!(); }\n",
        ),
        (
            Language::Scala,
            "App.scala",
            "object App { def audit(): Unit = (); def run(): Unit = { audit(); this.audit(); App.audit() } }\n",
        ),
        (
            Language::TypeScript,
            "app.ts",
            "function audit(): void {}\nconst app = { audit };\nfunction run(): void { audit(); app.audit(); }\n",
        ),
    ];
    for (language, path, source) in cases {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), path)
            .write(source)
            .expect("write source");
        // A trailing incomplete call forces parser recovery near the callee.
        let recovered_path = format!(
            "recovered.{ext}",
            ext = std::path::Path::new(path)
                .extension()
                .unwrap()
                .to_str()
                .unwrap()
        );
        ProjectFile::new(root.clone(), recovered_path)
            .write(format!("{source}\naudit("))
            .expect("write recovered source");
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
        check_role_name_index_contains_scan(analyzer.as_ref(), &query).unwrap();
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
#[hardwon("e52fe21d9294: keep Rust impl-owner resolution equal through scan and posting access")]
fn rust_inside_decl_owner_resolution_matches_between_scan_and_postings() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "Cargo.toml")
        .write("[package]\nname = \"owner-index\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
        .expect("write manifest");
    ProjectFile::new(root.clone(), "src/lib.rs")
        .write("mod model;\nmod pricing;\n")
        .expect("write crate root");
    ProjectFile::new(root.clone(), "src/model.rs")
        .write(
            "pub struct PriceCalculator { pub subtotal: u64 }\n\
             pub struct TaxCalculator { pub rate: u64 }\n",
        )
        .expect("write model source");
    ProjectFile::new(root.clone(), "src/pricing.rs")
        .write(
            "use crate::model::{PriceCalculator, TaxCalculator};\n\n\
             impl PriceCalculator { pub fn total() -> u64 { 10 } }\n\
             impl TaxCalculator { pub fn total() -> u64 { 2 } }\n",
        )
        .expect("write impl source");
    let project: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root, Language::Rust));
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .expect("build workspace");
    let analyzer = workspace.analyzer();
    let query = CodeQuery::from_source(
        r#"(inside-decl
              (class :name "PriceCalculator" :capture "owner"
                     :has (declaration :name "subtotal"))
              (method :name "total"))"#,
    )
    .expect("query");

    let scan = execute_code_query_with_access_mode(
        analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        true,
    )
    .expect("scan query");
    let indexed = execute_code_query_with_access_mode(
        analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("indexed query");

    assert_eq!(
        serde_json::to_value(&indexed.result).expect("indexed result JSON"),
        serde_json::to_value(&scan.result).expect("scan result JSON")
    );
    assert_eq!(indexed.result.results.len(), 1, "{:#?}", indexed.result);
    assert!(
        indexed
            .profile
            .expect("indexed profile")
            .access_path
            .selected
            .starts_with("posting:"),
        "inside-decl root method must retain posting access"
    );
}

#[test]
fn scan_only_kotlin_seed_hydrates_from_durable_facts_after_workspace_reopen() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let source = "package example\n\nopen class Table {\n    fun column() = 1\n}\n";
    ProjectFile::new(root.clone(), ".gitignore")
        .write(".bifrost/cache/\n")
        .expect("write gitignore");
    ProjectFile::new(root.clone(), "src/main/kotlin/example/Table.kt")
        .write(source)
        .expect("write Kotlin source");
    let repository = git2::Repository::init(&root).expect("initialize Git repository");
    let mut config = repository.config().expect("Git config");
    config
        .set_str("user.name", "Bifrost Test")
        .expect("Git user name");
    config
        .set_str("user.email", "bifrost@example.com")
        .expect("Git user email");
    let mut index = repository.index().expect("Git index");
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .expect("stage fixture");
    index.write().expect("write Git index");
    let tree_id = index.write_tree().expect("write Git tree");
    let tree = repository.find_tree(tree_id).expect("read Git tree");
    let signature =
        git2::Signature::now("Bifrost Test", "bifrost@example.com").expect("Git signature");
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Kotlin structural fixture",
            &tree,
            &[],
        )
        .expect("commit fixture");

    let project: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root, Language::Kotlin));
    let query = CodeQuery::from_json(&json!({
        "languages": ["kotlin"],
        "where": ["src/main/kotlin/example/Table.kt"],
        "match": { "kind": "class", "name": "Table" },
    }))
    .expect("Kotlin class query");

    let primed =
        WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
            .expect("build persisted Kotlin workspace");
    let prewarm = execute_code_query_with_access_mode(
        primed.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        true,
    )
    .expect("scan-only Kotlin prewarm");
    assert_eq!(prewarm.result.results.len(), 1, "{:#?}", prewarm.result);
    let prewarm_profile = prewarm.profile.expect("prewarm profile");
    assert_eq!(
        (
            prewarm_profile.cache.seed_structural_facts.extractions,
            prewarm_profile
                .cache
                .seed_structural_facts
                .persisted_hydrations,
        ),
        (0, 1),
        "the first query hydrates canonical facts published during initialization"
    );
    drop(primed);

    let reopened = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
        .expect("reopen persisted Kotlin workspace");
    let hydrated = execute_code_query_with_access_mode(
        reopened.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        true,
    )
    .expect("scan-only Kotlin query after reopen");
    assert_eq!(hydrated.result.results.len(), 1, "{:#?}", hydrated.result);
    let hydrated_profile = hydrated.profile.expect("hydrated profile");
    assert_eq!(
        hydrated_profile
            .cache
            .seed_structural_facts
            .persisted_hydrations,
        1,
        "reopened scan-only query must hydrate its Kotlin fact snapshot"
    );
    assert_eq!(
        hydrated_profile.cache.seed_structural_facts.extractions, 0,
        "reopened scan-only query must not re-extract its Kotlin fact snapshot"
    );
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

#[test]
#[hardwon("a4bc8f0ea610: bound warm verification work to indexed candidates")]
fn unrestricted_warm_index_verification_work_is_bounded_by_candidate_files() {
    let target_source = "pub fn read() -> String { std::fs::read_to_string(\"input\").unwrap() }\n";
    let run = |unrelated_files: usize| {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write(target_source)
            .expect("write candidate source");
        for index in 0..unrelated_files {
            ProjectFile::new(root.clone(), format!("src/unrelated-{index}.rs"))
                .write("// read_to_string appears only in this comment.\nfn unrelated() {}\n")
                .expect("write noncandidate source");
        }
        let analyzer = language_analyzer(Language::Rust, TestProject::new(root, Language::Rust));
        let query = CodeQuery::from_json(&json!({
            "languages": ["rust"],
            "match": {
                "kind": "call",
                "callee": { "name": "read_to_string" }
            }
        }))
        .expect("query");
        let warm_query = CodeQuery::from_json(&json!({
            "languages": ["rust"],
            "match": { "kind": "function", "name": "unrelated" }
        }))
        .expect("warm-up query");
        let scan = execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::ScanOnly,
            true,
        )
        .expect("scan access");
        execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &warm_query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::IndexedRequired,
            true,
        )
        .expect("warm structural index");
        let indexed = execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::IndexedRequired,
            true,
        )
        .expect("indexed access");
        (scan, indexed)
    };

    let (small_scan, small_indexed) = run(0);
    let (wide_scan, wide_indexed) = run(80);
    for (scan, indexed) in [(&small_scan, &small_indexed), (&wide_scan, &wide_indexed)] {
        assert_eq!(
            serde_json::to_value(&indexed.result).expect("indexed result JSON"),
            serde_json::to_value(&scan.result).expect("scan result JSON"),
            "candidate restriction must preserve complete result semantics"
        );
        assert_eq!(indexed.result.results.len(), 1);
        assert_eq!(indexed.work.scanned_files, 1);
        assert_eq!(
            indexed.work.scanned_source_bytes,
            target_source.len() as u64
        );
        let profile = indexed.profile.as_ref().expect("indexed profile");
        assert!(profile.access_path.selected.starts_with("posting:"));
        assert_eq!(profile.access_path.cache_ready_lookups, 1);
        assert_eq!(profile.access_path.candidate_files, 1);
        assert_eq!(
            profile.access_path.inspected_source_bytes,
            target_source.len() as u64
        );
        assert!(profile.access_path.examined_fact_nodes > 0);
    }

    let small_profile = &small_indexed.profile.as_ref().unwrap().access_path;
    let wide_profile = &wide_indexed.profile.as_ref().unwrap().access_path;
    assert_eq!(
        small_indexed.work.scanned_files,
        wide_indexed.work.scanned_files
    );
    assert_eq!(
        small_indexed.work.scanned_source_bytes,
        wide_indexed.work.scanned_source_bytes
    );
    assert_eq!(small_indexed.work.fact_nodes, wide_indexed.work.fact_nodes);
    assert_eq!(
        small_profile.inspected_source_bytes,
        wide_profile.inspected_source_bytes
    );
    assert_eq!(
        small_profile.examined_fact_nodes,
        wide_profile.examined_fact_nodes
    );
    assert_eq!(
        small_profile.materialized_fact_nodes,
        wide_profile.materialized_fact_nodes
    );
    assert_eq!(small_profile.candidate_facts, wide_profile.candidate_facts);
    assert!(small_profile.examined_fact_nodes <= small_profile.scoped_fact_nodes);
    assert!(wide_profile.scoped_files > small_profile.scoped_files);
    assert!(wide_profile.scoped_fact_nodes > small_profile.scoped_fact_nodes);
    assert!(wide_scan.work.scanned_files > wide_indexed.work.scanned_files);
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
#[hardwon("1a7880e32f73: durable workspace import adjacency bypasses snapshot-topology builds")]
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
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .expect("ephemeral workspace should build");
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
    // Since #4281, IndexedRequired reads the workspace's durable adjacency
    // before snapshot topology. Keep both lifecycle counters on the selected
    // import layer.
    let built_profile = built.profile.expect("multi build profile");
    assert_eq!(
        built_profile.cache.import_reverse.hits, 1,
        "the first indexed query uses the workspace persisted import topology"
    );
    assert_eq!(
        built_profile.cache.direct_import_topology.builds, 0,
        "durable workspace adjacency bypasses a snapshot-topology build"
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
    let reused_profile = reused.profile.expect("multi reuse profile");
    assert_eq!(
        reused_profile.cache.import_reverse.hits, 1,
        "the cloned workspace reuses its persisted import topology"
    );
    assert_eq!(
        reused_profile.cache.direct_import_topology.builds, 0,
        "the cloned workspace also bypasses snapshot-topology construction"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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
        (Language::Java, AnalyzerDelegate::new(java)),
        (Language::TypeScript, AnalyzerDelegate::new(typescript)),
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
#[hardwon(
    "c31c422146ff: edge-budget fallback preserves complete results after partial topology work"
)]
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
    // The provider materializes the whole canonical batch, but the
    // streaming work contract invokes this budget callback one file at a
    // time. Every consumer in this fixture contributes one edge, so the
    // callback that trips the budget can add exactly one attempted edge.
    let edge_work_bound = u64::try_from(limits.max_pipeline_rows)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    assert!(
        profile.work.import_edges_resolved <= edge_work_bound,
        "the per-file callback may charge one edge past the row budget: {} > {edge_work_bound}",
        profile.work.import_edges_resolved
    );
    assert_eq!(
        profile.work.import_edges_resolved, edge_work_bound,
        "the first over-budget consumer contributes the one-edge callback overshoot"
    );
    assert_eq!(
        profile.cache.direct_import_topology.build_edges, edge_work_bound,
        "derived-layer work records all materialized callback edges"
    );

    let cached_fallback = import_query(
        &analyzer,
        "typescript",
        "target.ts",
        "Target",
        "importers_of",
        limits,
        StructuralAccessMode::DerivedAutoForTest,
    );
    assert_eq!(
        serde_json::to_value(&cached_fallback.result).expect("cached fallback response"),
        serde_json::to_value(&scan.result).expect("scan response")
    );
    let cached_profile = cached_fallback.profile.expect("cached fallback profile");
    assert_eq!(cached_profile.cache.direct_import_topology.builds, 0);
    assert_eq!(cached_profile.cache.direct_import_topology.build_edges, 0);
    assert_eq!(cached_profile.cache.direct_import_topology.unavailable, 0);
    assert_eq!(cached_profile.cache.direct_import_topology.fallbacks, 1);
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
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .expect("ephemeral workspace should build");
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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
#[hardwon("#9179: small workspaces must retain their scan Scope dependency below index admission")]
fn small_auto_scope_scans_and_records_scope() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for index in 0..(MIN_AUTO_STRUCTURAL_INDEX_FILES - 1) {
        ProjectFile::new(root.clone(), format!("file_{index}.ts"))
            .write(format!("class Type{index} {{}}\n"))
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let (result, ledger) = crate::analyzer::capture_query_reads(&analyzer, || {
        run_class_query(&analyzer, "Type0", StructuralAccessMode::Auto)
    });
    assert_eq!(
        result.profile.expect("profile").access_path.selected,
        "scan_only"
    );
    assert!(
        ledger.keys().iter().any(|key| matches!(
            key,
            crate::analyzer::ReadKey::Scope { languages, .. }
                if languages.as_ref() == [Language::TypeScript]
        )),
        "{:?}",
        ledger.keys()
    );
}

#[test]
#[hardwon("#9179: a ready structural index hit omitted the exact-name inventory read")]
fn ready_snapshot_index_hit_records_inventory_lookups() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for index in 0..MIN_AUTO_STRUCTURAL_INDEX_FILES {
        ProjectFile::new(root.clone(), format!("file_{index}.ts"))
            .write(format!("class Type{index} {{}}\n"))
            .expect("write source");
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let built = run_class_query(&analyzer, "Type0", StructuralAccessMode::EagerAuto);
    assert_eq!(
        built
            .profile
            .expect("build profile")
            .access_path
            .index_builds,
        1
    );
    let (hit, ledger) = crate::analyzer::capture_query_reads(&analyzer, || {
        run_class_query(&analyzer, "Type0", StructuralAccessMode::EagerAuto)
    });
    assert_eq!(hit.profile.expect("hit profile").access_path.index_hits, 1);
    let keys = ledger.keys();
    assert!(
        keys.iter().any(|key| matches!(key,
            crate::analyzer::ReadKey::Lookup {
                kind: crate::analyzer::LookupKind::StructuralNameInventory,
                question: crate::analyzer::LookupQuestion::StructuralName { name, .. },
                ..
            } if name.as_ref() == "Type0"
        )),
        "{keys:?}"
    );
    assert!(
        keys.iter().any(|key| matches!(
            key,
            crate::analyzer::ReadKey::Lookup {
                kind: crate::analyzer::LookupKind::StructuralRecoveredInventory,
                ..
            }
        )),
        "{keys:?}"
    );
    // Other query consumers may retain an independent whole-language read.
    assert!(
        keys.iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Scope { .. })),
        "{keys:?}"
    );
}

#[test]
#[hardwon("#9179: occurrence-role changes must invalidate a recorded exact-name inventory")]
fn occurrence_role_edit_rejects_recorded_exact_name_lookup() {
    use crate::analyzer::{
        ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadKey,
        verify_read_set,
    };

    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let target = ProjectFile::new(root.clone(), "target.ts");
    target.write("class Target {}\n").expect("base source");
    for index in 1..MIN_AUTO_STRUCTURAL_INDEX_FILES {
        ProjectFile::new(root.clone(), format!("file_{index}.ts"))
            .write(format!("class Other{index} {{}}\n"))
            .expect("write source");
    }
    let base = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(root, Language::TypeScript)),
        AnalyzerConfig::default(),
    )
    .expect("base workspace");
    let (_, ledger) = crate::analyzer::capture_query_reads(base.analyzer(), || {
        run_class_query(base.analyzer(), "Target", StructuralAccessMode::EagerAuto)
    });
    let lookup = ledger
        .keys()
        .iter()
        .find(|key| {
            matches!(key, ReadKey::Lookup {
            kind: crate::analyzer::LookupKind::StructuralNameInventory,
            question: crate::analyzer::LookupQuestion::StructuralName { name, .. },
            ..
        } if name.as_ref() == "Target")
        })
        .expect("recorded exact-name lookup")
        .clone();
    let base_provider = base
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .next()
        .expect("base structural provider");
    let base_facts = base_provider.structural_facts(&target).expect("base facts");
    target.write("Target();\n").expect("edit occurrence role");
    let head = base.update(&BTreeSet::from([target.clone()]));
    let head_provider = head
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .next()
        .expect("head structural provider");
    let head_facts = head_provider.structural_facts(&target).expect("head facts");
    let roles = |facts: &crate::analyzer::structural::facts::FileFacts| {
        (0..facts.nodes().len())
            .flat_map(|node| facts.occurrence_roles(node as u32).iter().copied())
            .collect::<Vec<_>>()
    };
    assert_ne!(roles(&base_facts), roles(&head_facts));
    let StructuralIndexAcquisition::Ready { index, .. } = head_provider
        .snapshot_structural_index_cache()
        .expect("snapshot cache")
        .inner()
        .acquire(head_provider, &CancellationToken::default())
    else {
        panic!("head structural index");
    };
    assert_eq!(index.exact_name_inventory("Target").1, vec![target]);
    let digest = crate::analyzer::semantic::StableDigest::sha256(b"test inputs");
    let inputs = HeadInputs {
        models: digest,
        policy_semantic_hash: digest,
        policy_source: digest,
        configuration: digest,
        epoch: digest,
    };
    let verdict = verify_read_set(
        &head,
        &ChangedFacts::between(&base, &head),
        &inputs,
        &[lookup],
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    assert!(
        !verdict.is_unchanged(),
        "changed occurrence role: {verdict:?}"
    );
}

#[test]
#[hardwon(
    "#9179: a same-name edit changed structural kind or role without moving the posting path"
)]
fn exact_name_inventory_changes_for_source_kind_role_and_overlay_edits() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let target = ProjectFile::new(root.clone(), "target.ts");
    target.write("class Target {}\n").expect("base source");
    for index in 1..MIN_AUTO_STRUCTURAL_INDEX_FILES {
        ProjectFile::new(root.clone(), format!("file_{index}.ts"))
            .write(format!("class Other{index} {{}}\n"))
            .expect("write source");
    }
    let project: Arc<dyn crate::analyzer::Project> =
        Arc::new(TestProject::new(root, Language::TypeScript));
    let analyzer = TypescriptAnalyzer::new(Arc::clone(&project));
    let inventory = |analyzer: &TypescriptAnalyzer| {
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("structural provider");
        let cache = provider
            .snapshot_structural_index_cache()
            .expect("snapshot cache");
        let StructuralIndexAcquisition::Ready { index, .. } = cache
            .inner()
            .acquire(provider, &CancellationToken::default())
        else {
            panic!("complete structural index");
        };
        index.exact_name_inventory("Target")
    };
    let (base_digest, base_paths) = inventory(&analyzer);
    assert_eq!(base_paths, vec![target.clone()]);

    target.write("function Target() {}\n").expect("edit kind");
    let changed_kind = analyzer.update(&BTreeSet::from([target.clone()]));
    let (kind_digest, kind_paths) = inventory(&changed_kind);
    assert_eq!(kind_paths, base_paths);
    assert_ne!(kind_digest, base_digest);

    target
        .write("function Target(value: string) {}\n")
        .expect("edit parameter role");
    let changed_role = changed_kind.update(&BTreeSet::from([target.clone()]));
    let (role_digest, role_paths) = inventory(&changed_role);
    assert_eq!(role_paths, base_paths);
    assert_ne!(role_digest, kind_digest);

    let overlay = Arc::new(OverlayProject::new(project));
    assert!(overlay.set(
        target.abs_path(),
        "function Target(other: number) {}\n".to_string()
    ));
    let overlaid = changed_role.clone_with_project(overlay as Arc<dyn crate::analyzer::Project>);
    let (overlay_digest, overlay_paths) = inventory(&overlaid);
    assert_eq!(overlay_paths, base_paths);
    assert_ne!(overlay_digest, role_digest);
}

#[test]
#[hardwon("#9179: a stopped structural inventory replay could certify an empty head")]
fn stopped_structural_inventory_replay_refuses() {
    use crate::analyzer::{LookupReplayLimits, NoSummaryAnswers, replay_lookup};

    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("target.ts", "class Target {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let provider = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .next()
        .expect("structural provider");
    let question = crate::analyzer::LookupQuestion::StructuralName {
        language: Language::TypeScript,
        name: "Target".into(),
        authority: provider
            .structural_selection_authority()
            .expect("selection authority"),
    };
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let _scope =
        crate::analyzer::AnalyzerQueryScope::with_cancellation(workspace.analyzer(), &cancellation);
    assert!(
        replay_lookup(
            &workspace,
            crate::analyzer::LookupKind::StructuralNameInventory,
            &question,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
        )
        .is_none()
    );
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

#[test]
fn auto_defers_its_snapshot_build_to_the_background_warm_and_scans_until_it_lands() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    // Auto only admits a build for a scope worth indexing, so the fixture must
    // carry at least MIN_AUTO_STRUCTURAL_INDEX_FILES files.
    for index in 0..12 {
        ProjectFile::new(root.clone(), format!("bench/Unit{index}.java"))
            .write(format!(
                "package bench; public class Unit{index} {{ void run() {{ audit(); }} \
                 void audit() {{}} }}\n"
            ))
            .expect("write fixture");
    }
    let analyzer = language_analyzer(Language::Java, TestProject::new(root, Language::Java));
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } }
    }))
    .expect("query");
    let run = |mode| {
        execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &query,
            CodeQueryExecutionLimits::default(),
            mode,
            true,
        )
        .expect("query executes")
        .profile
        .expect("captured profile")
        .access_path
    };

    // Nothing has asked for a posting index yet, so there is nothing to warm.
    assert!(analyzer.structural_indexes_warm());

    let first = run(StructuralAccessMode::Auto);
    assert_eq!(first.selected, "scan_only", "{first:?}");
    assert_eq!(first.index_builds, 0, "{first:?}");
    assert!(
        !analyzer.structural_indexes_warm(),
        "the first Auto request must leave a posting index outstanding"
    );

    analyzer.warm_structural_indexes();
    assert!(
        analyzer.structural_indexes_warm(),
        "the warm must answer every outstanding posting index"
    );

    let after_warm = run(StructuralAccessMode::Auto);
    assert!(
        after_warm.selected.starts_with("posting:"),
        "the request after the warm must use the index: {after_warm:?}"
    );
    assert_eq!(after_warm.index_hits, 1, "{after_warm:?}");
    assert_eq!(after_warm.index_builds, 0, "{after_warm:?}");
}

#[hardwon("#5113: procedure rows pinned artifacts until the workspace-wide stage completed")]
#[test]
fn semantic_procedure_references_release_windows_and_reject_changed_revisions() {
    let original = "def target():\n    return 1\n";
    let changed = "def target():\n    return 2\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), "app.py");
    file.write(original).expect("write source");
    let overlay = Arc::new(OverlayProject::new(Arc::new(TestProject::new(
        root,
        Language::Python,
    ))));
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>,
        AnalyzerConfig::default(),
    )
    .expect("workspace");
    let mut semantic = SemanticQueryContext::new(
        &workspace,
        None,
        CodeQueryExecutionLimits::default().semantic,
    );
    let references = semantic.procedure_references(&file);
    let reference = references
        .iter()
        .find(|reference| reference.public.procedure_kind == "function")
        .expect("target reference");
    assert!(
        semantic.can_start_artifact_windows(),
        "identity inventory does not lower or retain artifacts"
    );
    semantic.start_artifact_window(file.clone());
    let procedure = semantic
        .resolve_procedure_reference(reference)
        .expect("exact reference resolves");
    let allocation = Arc::downgrade(procedure.handle.artifact());
    let snapshot = SemanticTraceSnapshot::of(&SemanticPipelineValue::Procedure(procedure.clone()));
    assert_eq!(
        serde_json::to_value(snapshot.public_ref()).unwrap(),
        serde_json::to_value(reference.public_ref()).unwrap()
    );
    drop(procedure);
    semantic.release_artifact_window();
    assert!(semantic.can_start_artifact_windows());
    // The analyzer's byte-capped shared cache may retain the allocation, but
    // a pipeline reference or provenance snapshot never owns that allocation.
    let before = allocation.strong_count();
    drop(snapshot);
    assert_eq!(allocation.strong_count(), before);
    assert!(overlay.set(file.abs_path(), changed.to_owned()));
    semantic.start_artifact_window(file.clone());
    assert!(semantic.resolve_procedure_reference(reference).is_none());
    semantic.release_artifact_window();
    assert!(semantic.take_diagnostics().iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
            && diagnostic.message.contains("source generation changed")
    }));
}

#[test]
fn role_name_receipt_detects_a_new_callee_file() {
    use crate::analyzer::{
        ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadKey,
        verify_read_set,
    };

    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for index in 0..MIN_AUTO_STRUCTURAL_INDEX_FILES {
        ProjectFile::new(root.clone(), format!("Unit{index}.java"))
            .write(format!(
                "class Unit{index} {{ void run() {{ other(); }} void other() {{}} }}\n"
            ))
            .expect("base source");
    }
    let base = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(root.clone(), Language::Java)),
        AnalyzerConfig::default(),
    )
    .expect("base workspace");
    let query = CodeQuery::from_json(&json!({
        "languages": ["java"],
        "match": { "kind": "call", "callee": { "name": "audit" } }
    }))
    .expect("callee query");
    let (_, ledger) = crate::analyzer::capture_query_reads(base.analyzer(), || {
        execute_code_query_with_access_mode(
            base.analyzer(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::EagerAuto,
            true,
        )
        .expect("base query")
    });
    let lookup = ledger
        .keys()
        .iter()
        .find(|key| {
            matches!(key,
                ReadKey::Lookup {
                    kind: crate::analyzer::LookupKind::StructuralRoleNameInventory,
                    question: crate::analyzer::LookupQuestion::StructuralRoleName {
                        role: brokk_bifrost_core::analyzer::structural::kinds::Role::Callee,
                        name, keyword: false, ..
                    }, ..
                } if name.as_ref() == "audit"
            )
        })
        .expect("role-name inventory receipt")
        .clone();
    let added = ProjectFile::new(root, "Added.java");
    added
        .write("class Added { void run() { audit(); } void audit() {} }\n")
        .expect("new callee source");
    let head = base.update(&BTreeSet::from([added]));
    let digest = crate::analyzer::semantic::StableDigest::sha256(b"test inputs");
    let inputs = HeadInputs {
        models: digest,
        policy_semantic_hash: digest,
        policy_source: digest,
        configuration: digest,
        epoch: digest,
    };
    let verdict = verify_read_set(
        &head,
        &ChangedFacts::between(&base, &head),
        &inputs,
        &[lookup],
        LookupReplayLimits::default(),
        &NoSummaryAnswers,
        &mut LookupMemo::new(),
    );
    assert!(!verdict.is_unchanged(), "new posting file: {verdict:?}");
}
