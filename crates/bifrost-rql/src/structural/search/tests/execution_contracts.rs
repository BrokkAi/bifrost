use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, UnitExecutionResult, execute_code_query_unit,
};
use brokk_bifrost_analysis::CodeUnitIndex;
use brokk_bifrost_test_macros::hardwon;

// Explain validates execution limits without needing semantic registrations.
fn explain_admission(step: serde_json::Value, limits: CodeQueryExecutionLimits) -> bool {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({"execution_mode": "explain", "match": {"kind": "function"}, "steps": [{"op": "procedure_of"}, step]})).unwrap();
    matches!(
        execute_request_with_limits(&analyzer, &query, limits),
        CodeQueryResponse::Explain(_)
    )
}

#[test]
#[hardwon("#12107: per-seed overlay receipt hashing and warm request basename index builds")]
fn preflight_overlay_inventory_receipt_is_scalar_and_replayed_per_consumer() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/preflight-cost\n\ngo 1.23\n")
        .file("main.go", "package example\nfunc run() {}\n")
        .build();
    let cache = Arc::new(
        brokk_bifrost_core::analyzer::project::WorkspaceFileListingCache::new(
            project.root().canonicalize().unwrap(),
        ),
    );
    let delegate: Arc<dyn crate::analyzer::Project> = Arc::new(
        crate::analyzer::FilesystemProject::with_cached_listing(project.root(), Arc::clone(&cache))
            .unwrap(),
    );
    delegate.all_files_shared().unwrap();
    let overlay = Arc::new(OverlayProject::new(Arc::clone(&delegate)));
    assert!(overlay.set(
        project.root().join("main.go"),
        "package example\nfunc edited() {}\n".to_owned()
    ));
    let overlay: Arc<dyn crate::analyzer::Project> = overlay;
    for (view, expected_hashes) in [(delegate, 0), (overlay, 1)] {
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(view, AnalyzerConfig::default()).unwrap();
        let analyzer = workspace.analyzer();
        for _ in 0..2 {
            let _request = crate::analyzer::AnalyzerQueryScope::new(analyzer);
            // Preflight receives the caller's already enumerated seed files.
            let _files = analyzer.analyzed_files();
            let cell = analyzer.workspace_file_inventory_cell().unwrap();
            assert!(
                cell.get().is_none(),
                "the receipt must die with its request"
            );
            let walks = cache.walk_count();
            let hashes =
                brokk_bifrost_core::analyzer::project_reads::file_set_receipt_build_count();
            for _ in 0..2 {
                let (certified, reads) = crate::analyzer::capture_query_reads(analyzer, || {
                    crate::analyzer::workspace_authority::record_request_workspace_file_inventory(
                        analyzer,
                    )
                });
                assert!(
                    certified,
                    "view hashes={expected_hashes}, cell={:?}, reads={:?}",
                    cell.get(),
                    reads
                );
                assert!(
                    reads.keys().iter().any(|key| matches!(
                        key,
                        crate::analyzer::ReadKey::Lookup {
                            question: crate::analyzer::LookupQuestion::WorkspaceFact {
                                family:
                                    crate::analyzer::WorkspaceFactFamily::WorkspaceFileInventory,
                                ..
                            },
                            ..
                        }
                    )),
                    "every consumer receives the scalar authority"
                );
            }
            assert_eq!(
                brokk_bifrost_core::analyzer::project_reads::file_set_receipt_build_count()
                    - hashes,
                expected_hashes,
                "warm production reuses its receipt; overlays build it once per request"
            );
            assert_eq!(
                cache.walk_count(),
                walks,
                "warm requests must not walk the workspace"
            );
            assert!(
                analyzer
                    .workspace_file_index_cell()
                    .unwrap()
                    .get()
                    .is_none()
            );
        }
    }
}

#[test]
#[hardwon("#9179: unused RQL preflight listings left a Rust Scope read on store Output units")]
fn query_without_file_inventory_consumer_records_no_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn value() {}\n")
        .file("config.json", "{\"port\": 8080}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "configuration_facts": {"formats": ["json"], "keys": ["port"]},
        "limit": 10
    }))
    .expect("configuration query");
    let (result, ledger) = crate::analyzer::capture_query_reads(workspace.analyzer(), || {
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    });
    assert_eq!(result.results.len(), 1, "{result:#?}");
    assert!(
        !ledger
            .keys()
            .iter()
            .any(|key| matches!(key, crate::analyzer::ReadKey::Scope { .. })),
        "{:?}",
        ledger.keys()
    );
}

#[test]
#[hardwon("#9179: a reused query-local file list could omit Scope from a later ledger")]
fn reused_file_inventory_replays_scope_to_each_consumer() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    struct UnattestedProject(std::path::PathBuf);
    impl crate::analyzer::Project for UnattestedProject {
        fn root(&self) -> &std::path::Path {
            &self.0
        }
        fn analyzer_languages(&self) -> std::collections::BTreeSet<Language> {
            std::collections::BTreeSet::from([Language::Python])
        }
        fn all_files(&self) -> std::io::Result<std::collections::BTreeSet<ProjectFile>> {
            Ok(std::collections::BTreeSet::from([ProjectFile::new(
                &self.0, "main.py",
            )]))
        }
        fn analyzable_files(
            &self,
            _: Language,
        ) -> std::io::Result<std::collections::BTreeSet<ProjectFile>> {
            self.all_files()
        }
        fn file_by_rel_path(&self, rel: &std::path::Path) -> Option<ProjectFile> {
            self.0
                .join(rel)
                .is_file()
                .then(|| ProjectFile::new(&self.0, rel))
        }
    }
    let analyzer = PythonAnalyzer::from_project(UnattestedProject(project.root().to_path_buf()));
    let _request = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": {"kind": "function"},
        "steps": [{"op": "procedure_of"}, {"op": "nilness_operations"}]
    }))
    .expect("relation query");
    assert!(relation_capabilities::needs_file_inventory(&query.plan));
    let inventory = QueryFileInventory::default();
    let (_, first) = crate::analyzer::capture_query_reads(&analyzer, || {
        let mut diagnostics = Vec::new();
        relation_capabilities::preflight(
            &query.plan,
            inventory.files(&analyzer, || analyzer.analyzed_files()),
            &analyzer,
            None,
            &mut diagnostics,
        );
        diagnostics
    });
    assert!(
        analyzer
            .workspace_file_inventory_cell()
            .unwrap()
            .get()
            .unwrap()
            .1
            .is_none(),
        "a custom getter without an attested inventory must retain the scope fallback"
    );
    let (languages, second) = crate::analyzer::capture_query_reads(&analyzer, || {
        inventory
            .files(&analyzer, || panic!("cached inventory was listed again"))
            .iter()
            .map(crate::analyzer::common::language_for_file)
            .collect::<std::collections::HashSet<_>>()
    });
    assert!(languages.contains(&Language::Python));
    for ledger in [&first, &second] {
        assert!(
            ledger.keys().iter().any(|key| matches!(key, crate::analyzer::ReadKey::Scope { languages, .. } if languages.as_ref() == [Language::Python])),
            "{:?}",
            ledger.keys()
        );
    }
}

#[test]
#[hardwon("#12107: subset preflight bypassed the file inventory receipt, including on memo hits")]
fn subset_preflight_receipt_rejects_added_and_removed_dialect_files() {
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupQuestion, LookupReplayLimits, NoSummaryAnswers, ReadKey,
        WorkspaceFactFamily, verify_read_set,
    };
    let project = InlineTestProject::new()
        .with_git()
        .file("go.mod", "module example.com/preflight\n\ngo 1.23\n")
        .file("src/main.go", "package preflight\nfunc run() {}\n")
        // Keep the Python analyzer present while the selected scope is Go-only.
        .file("outside.py", "def outside(): pass\n")
        .build();
    let query = CodeQuery::from_json(&json!({
        "languages": ["go", "python"], "where": ["src/**"],
        "match": {"kind": "function"},
        "steps": [{"op": "procedure_of"}, {"op": "nilness_operations"}]
    }))
    .expect("mixed dialect query");
    let capture = |workspace: &WorkspaceAnalyzer| {
        let analyzer = workspace.analyzer();
        let _request = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        // The narrowed-unit branch receives this enumeration from its caller,
        // outside its ledger; the consult itself must certify the dependency.
        let files = analyzer.analyzed_files();
        // Review found a whole-workspace hash rebuilt even without a consumer.
        // An uncaptured preflight must use only its supplied file list.
        let listings_before = analyzer.project().workspace_file_listing_count();
        let mut uncaptured = Vec::new();
        relation_capabilities::preflight(
            &query.plan,
            &files,
            analyzer,
            Some(workspace),
            &mut uncaptured,
        );
        assert_eq!(
            analyzer.project().workspace_file_listing_count(),
            listings_before,
            "an uncaptured preflight must not consult the workspace listing"
        );
        // Warm the production getter independently of this new request cell.
        analyzer.project().all_files_shared().unwrap();
        let hashes_before_consumers =
            brokk_bifrost_core::analyzer::project_reads::file_set_receipt_build_count();
        let listings_before_consumers = analyzer.project().workspace_file_listing_count();
        let inventory = QueryFileInventory::default();
        let mut receipts = Vec::new();
        let mut answer = Vec::new();
        for cached in [false, true] {
            let (diagnostics, receipt) = crate::analyzer::capture_query_reads(analyzer, || {
                let files = inventory.files(analyzer, || {
                    assert!(!cached, "exercise the actual inventory memo hit");
                    files.clone()
                });
                let mut diagnostics = Vec::new();
                relation_capabilities::preflight(
                    &query.plan,
                    files,
                    analyzer,
                    Some(workspace),
                    &mut diagnostics,
                );
                diagnostics
            });
            let reads = receipt.keys();
            assert!(
                reads.iter().any(|key| matches!(
                    key,
                    ReadKey::Lookup {
                        question: LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::WorkspaceFileInventory,
                            ..
                        },
                        ..
                    }
                )),
                "missing selected dialect membership receipt: {reads:?}"
            );
            if cached {
                assert_eq!(diagnostics, answer, "cold/warm preflight parity");
            }
            answer = diagnostics;
            receipts.push(reads);
        }
        // This counter includes cheap cached getter calls, not only walks.
        assert_eq!(
            analyzer.project().workspace_file_listing_count() - listings_before_consumers,
            1,
            "two warm consumers share one cached getter consult"
        );
        assert_eq!(
            brokk_bifrost_core::analyzer::project_reads::file_set_receipt_build_count(),
            hashes_before_consumers,
            "warm consumers must reuse the getter's scalar certificate without hashing"
        );
        assert!(
            analyzer
                .workspace_file_index_cell()
                .unwrap()
                .get()
                .is_none(),
            "preflight must not build the unrelated basename resolver index"
        );
        (answer, receipts)
    };
    let verify = |base: &WorkspaceAnalyzer, head: &WorkspaceAnalyzer, reads: &[ReadKey]| {
        verify_read_set(
            head,
            &ChangedFacts::between(base, head),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            reads,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
        .is_unchanged()
    };
    let base = project.certified_workspace_analyzer(AnalyzerConfig::default());
    let (before, base_receipts) = capture(&base);
    assert!(before.is_empty(), "Go supports nilness: {before:?}");
    for reads in &base_receipts {
        assert!(verify(&base, &base, reads));
    }
    project
        .file("src/main.go")
        .write("package preflight\nfunc run() { _ = 1 }\n")
        .expect("edit a body without changing dialect membership");
    let body_edit = project.certified_workspace_analyzer(AnalyzerConfig::default());
    let (same_coverage, _) = capture(&body_edit);
    assert_eq!(same_coverage, before);
    for reads in &base_receipts {
        assert!(
            verify(&base, &body_edit, reads),
            "body-only edits must reuse the preflight answer"
        );
    }
    let added = project.file("src/added.py");
    added
        .write("def added(): pass\n")
        .expect("add selected Python file");
    let head = project.certified_workspace_analyzer(AnalyzerConfig::default());
    let (after, head_receipts) = capture(&head);
    assert!(
        after.iter().any(|diagnostic| diagnostic.code
            == CodeQueryDiagnosticCode::UnsupportedStructuralFeature
            && diagnostic.language == "python"),
        "the added dialect changes preflight coverage: {after:?}"
    );
    for reads in &base_receipts {
        assert!(!verify(&base, &head, reads));
    }
    std::fs::remove_file(added.abs_path()).expect("remove selected Python file");
    let removed = project.certified_workspace_analyzer(AnalyzerConfig::default());
    let (restored, _) = capture(&removed);
    assert_eq!(restored, before);
    for reads in &head_receipts {
        assert!(!verify(&head, &removed, reads));
    }
    for reads in &base_receipts {
        assert!(verify(&base, &removed, reads));
    }
}

#[test]
#[hardwon("#9179: a stopped cached listing could be replayed as a complete empty inventory")]
fn stopped_file_inventory_refuses_each_consumer() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let _query = crate::analyzer::AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
    let inventory = QueryFileInventory::default();
    let (_, first) =
        crate::analyzer::capture_query_reads(&analyzer, || inventory.files(&analyzer, Vec::new));
    let (_, second) = crate::analyzer::capture_query_reads(&analyzer, || {
        inventory.files(&analyzer, || panic!("stopped inventory relisted"))
    });
    assert!(first.execution_dependences() > 0);
    assert!(second.execution_dependences() > 0);
}

#[test]
fn taint_projection_requires_positive_bytes() {
    // results/diagnostics.rs requires positive projected bytes.
    for value in [0, 1] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.taint.max_projected_bytes = value;
        assert_eq!(
            explain_admission(json!({"op": "taint", "taint_ref": "test:resource"}), limits),
            value == 1
        );
    }
}

#[test]
fn taint_origin_limit_accepts_the_full_documented_range() {
    // results/diagnostics.rs caps origins at 50,000.
    for value in [4096, 4097, 50000, 50001] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.taint.max_origins_per_finding = value;
        assert_eq!(
            explain_admission(json!({"op": "taint", "taint_ref": "test:resource"}), limits),
            value <= 50000
        );
    }
}

#[test]
fn value_flow_witness_limit_accepts_the_full_documented_range() {
    // results/diagnostics.rs caps witnesses at 50,000.
    for value in [4096, 4097, 50000, 50001] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.value_flow.max_witnesses = value;
        assert_eq!(
            explain_admission(
                json!({"op": "value_flow", "plan_ref": "test:resource"}),
                limits
            ),
            value <= 50000
        );
    }
}

#[test]
fn typestate_candidate_limit_accepts_one_candidate() {
    // results/diagnostics.rs requires positive candidates.
    for value in [0, 1, 2] {
        let mut limits = CodeQueryExecutionLimits::default();
        limits.typestate.max_candidates = value;
        assert_eq!(
            explain_admission(
                json!({"op": "typestate", "protocol_ref": "test:resource"}),
                limits
            ),
            value > 0
        );
    }
}

#[test]
fn unit_artifacts_preserve_workspace_diagnostic_attribution() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}, "steps": [{"op": "procedure_of"}, {"op": "typestate", "protocol_ref": "test:missing"}]})).unwrap();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert!(!unit.diagnostics.is_empty(), "{unit:?}");
    let wire = serde_json::to_value(&unit).unwrap();
    let decoded: UnitExecutionResult = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded.diagnostics[0].language, "workspace");
    let mut corrupt = wire;
    corrupt["diagnostics"][0]["language"] = json!("not-a-language");
    assert!(serde_json::from_value::<UnitExecutionResult>(corrupt).is_err());
}

#[test]
fn unit_artifacts_keep_nested_branch_diagnostics() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"union": [
        {"union": [{"match": {"kind": "function"}}, {"generation_sites": {}}]},
        {"match": {"kind": "function"}}
    ]}))
    .unwrap();
    let files = workspace.analyzer().analyzed_files();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files, &files),
    );
    assert!(!unit.diagnostics.is_empty(), "{unit:?}");
    let decoded: UnitExecutionResult =
        serde_json::from_value(serde_json::to_value(&unit).unwrap()).unwrap();
    assert!(
        decoded.diagnostics.iter().all(|d| d.branch == [0, 1]),
        "{decoded:?}"
    );
}

#[test]
fn union_units_preserve_all_leaf_contributions_before_global_limit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def first(): pass\ndef second(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = workspace.analyzer().analyzed_files();
    let query = CodeQuery::from_json(&json!({"union": [{"match": {"kind": "function"}}, {"match": {"kind": "function", "name": "second"}}], "limit": 1})).unwrap();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files, &files),
    );
    assert_eq!(
        unit.rows.len(),
        3,
        "both functions in the first leaf, second again in the second: {unit:?}"
    );
    assert!(!unit.truncated, "{unit:?}");
}

#[test]
fn semantic_file_refusal_renders_attempted_charge_before_limit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("first.py", "def first(): pass\n")
        .file("second.py", "def second(): pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(cfg-entry (procedure-of (function)))").unwrap();
    let mut limits = CodeQueryExecutionLimits::default();
    limits.semantic.max_materialized_files = 1;
    let result = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        limits,
    );
    let text = result.render_text();
    assert!(text.contains("charged 2 limit 1"), "{text}");
}

#[test]
fn rust_macro_access_receipt_rejects_shadowing_edits() {
    use crate::analyzer::{
        ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadKey, verify_read_set,
    };
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"macro_receipt\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", "mod calls;\n")
        .file(
            "src/calls.rs",
            "pub fn run() { let a = 1; println!(\"unrelated\"); assert_eq!(1, 1); }\n",
        )
        .build();
    let capture = |workspace: &WorkspaceAnalyzer, expected_access| {
        let analyzer = workspace.analyzer();
        let _request = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        let file = ProjectFile::new(project.root().to_path_buf(), "src/calls.rs");
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Rust)
            .unwrap()
            .structural_facts(&file)
            .unwrap();
        let mut cache = OccurrenceTraversalCache::default();
        let (_, reads) = crate::analyzer::capture_query_reads(analyzer, || {
            // Index fills and hits share the enclosing query capture and replay
            // the combined receipt, including cross-file identity reads.
            for _ in 0..2 {
                for node in facts
                    .nodes()
                    .iter()
                    .filter(|node| node.construct.as_deref() == Some("rust_macro_invocation"))
                {
                    let index = cache
                        .rust_macro_access_index(analyzer, &file, &facts, None)
                        .unwrap();
                    let actual = index.may_access(node.range.start_byte, node.range.end_byte, "a");
                    assert_eq!(actual, expected_access, "{node:?}");
                }
            }
        });
        assert!(
            reads.keys().iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/calls.rs")),
            "the invocation source and its lexical macro definitions must be recorded: {:?}",
            reads.keys()
        );
        reads.keys()
    };
    let base = project.certified_workspace_analyzer(AnalyzerConfig::default());
    let reads = capture(&base, false);
    project.file("src/lib.rs").write(
        "macro_rules! println { ($($t:tt)*) => {} }\nmacro_rules! assert_eq { ($($t:tt)*) => {} }\nmod calls;\n"
    ).unwrap();
    let edited = base.update_all();
    capture(&edited, true);
    assert!(
        !verify_read_set(
            &edited,
            &ChangedFacts::between(&base, &edited),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            &reads,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new()
        )
        .is_unchanged(),
        "a warm query must revalidate the changed macro definition"
    );
}

#[test]
fn rust_macro_access_index_is_built_once_for_many_bindings_and_invocations() {
    for count in [200, 400] {
        let bindings = (0..count)
            .map(|n| format!("let a{n}: usize; "))
            .collect::<String>();
        let source = format!(
            "pub fn run() {{ {bindings} {} }}",
            "println!(\"unrelated\");".repeat(count)
        );
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"macro_inventory\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let workspace = project.certified_workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let _request = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        let file = ProjectFile::new(project.root().to_path_buf(), "src/lib.rs");
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Rust)
            .unwrap()
            .structural_facts(&file)
            .unwrap();
        let mut cache = OccurrenceTraversalCache::default();
        crate::analyzer::capture_query_reads(analyzer, || {
            assert_eq!(
                facts
                    .nodes()
                    .iter()
                    .filter(|node| node.construct.as_deref() == Some("rust_macro_invocation"))
                    .count(),
                count
            );
            for n in 0..count {
                let index = cache
                    .rust_macro_access_index(analyzer, &file, &facts, None)
                    .unwrap();
                assert!(!index.may_access(0, usize::MAX, &format!("a{n}")));
            }
            assert_eq!(
                cache.rust_macro_definition_builds, 1,
                "{count} bindings and invocations"
            );
            assert_eq!(cache.rust_macro_proof_evaluations, count);
            assert_eq!(cache.rust_macro_index_builds, 1);
        });
    }
}
