//! Declaration index lookups under limits, budgets and cancellation.

use super::*;
use crate::analyzer::store::StoreLanguageAdapter;
use crate::analyzer::store::file_state::FileState;
use crate::analyzer::store::{CandidateFlags, HydratedCandidateRow, RelationalUnitFq};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::{CodeUnit, CodeUnitType, Language, Project, ProjectFile, TestProject};
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct PythonAdapter {
    cancellation_on_storage_key: Option<Arc<CancellationToken>>,
    storage_key_calls: Option<Arc<AtomicUsize>>,
    cancellation_enabled: Option<Arc<AtomicBool>>,
    cancel_after_storage_key_calls: usize,
    alternate_storage_key_on_call: Option<usize>,
    alternate_storage_key_enabled: Option<Arc<AtomicBool>>,
}

impl StoreLanguageAdapter for PythonAdapter {
    // Test adapter.
    fn parse_time_semantic_lowerer(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::service::ParseTimeSemanticLowerer> {
        None
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn storage_language_key_for_file(&self, _file: &ProjectFile) -> &'static str {
        let call = self
            .storage_key_calls
            .as_ref()
            .map(|calls| calls.fetch_add(1, Ordering::Relaxed) + 1);
        if let (Some(token), Some(enabled)) = (
            &self.cancellation_on_storage_key,
            &self.cancellation_enabled,
        ) && enabled.load(Ordering::Relaxed)
            && call == Some(self.cancel_after_storage_key_calls)
        {
            token.cancel();
        }
        if self
            .alternate_storage_key_enabled
            .as_ref()
            .is_some_and(|enabled| enabled.load(Ordering::Relaxed))
            && call == self.alternate_storage_key_on_call
        {
            "python-alt"
        } else {
            "python"
        }
    }
}

impl LanguageAdapter for PythonAdapter {
    fn line_data_kinds(&self) -> brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
        brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
            literals: &[],
            interpolations: &[],
            composites: &[],
        }
    }
    fn cross_file_children(
        &self,
        _analyzer: &TreeSitterAnalyzer<Self>,
        owner: &CodeUnit,
        _limit: usize,
    ) -> Option<Vec<(CodeUnit, Option<crate::analyzer::Range>)>> {
        (owner.identifier() == "Owner").then(|| {
            vec![(
                unit(&owner.source().clone(), "child", CodeUnitType::Function),
                None,
            )]
        })
    }

    fn query_directory(&self) -> &'static str {
        "python"
    }

    fn file_extension(&self) -> &'static str {
        "py"
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn parse_file(
        &self,
        file: &crate::analyzer::ProjectFile,
        source: &str,
        _tree: &tree_sitter::Tree,
    ) -> ParsedFile {
        let mut parsed = ParsedFile::new(String::new());
        parsed.add_file_scope(file, source);
        parsed
    }
}

fn analyzer(sources: &[(&str, &str)]) -> (tempfile::TempDir, TreeSitterAnalyzer<PythonAdapter>) {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace root");
    for (path, source) in sources {
        let file_path = root.join(path);
        std::fs::create_dir_all(file_path.parent().expect("fixture parent"))
            .expect("create fixture directory");
        std::fs::write(file_path, source).expect("write fixture source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
    (
        temp,
        TreeSitterAnalyzer::new(project, PythonAdapter::default()),
    )
}

#[test]
fn stored_publication_read_distinguishes_absent_head_from_missing_authority() {
    use crate::analyzer::semantic::StoredSemanticIrRead;
    use crate::analyzer::semantic::classify;
    use crate::analyzer::semantic::read_ledger::StoredSemanticIrPublicationAnswer;

    let _rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);

    let (_temp, analyzer) = analyzer(&[("sample.py", "value = 1\n")]);
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "sample.py");
    assert!(analyzer.resolve_live_oid_for_file(&file).is_some());
    let cancellation = CancellationToken::default();
    let read = crate::analyzer::semantic::service::stored_semantic_ir_publication_read(
        &analyzer,
        &file,
        |store, key| {
            store
                .semantic_ir_head_observation(key)
                .map(|head| (head, None::<()>))
        },
        None,
        &cancellation,
    );
    assert!(
        matches!(read.unwrap().0, StoredSemanticIrRead::Observed(observation)
        if matches!(classify(&observation, [0; 32]), StoredSemanticIrPublicationAnswer::NoHead))
    );

    let overlay = Arc::new(crate::OverlayProject::new(Arc::clone(&analyzer.project)));
    assert!(overlay.set(file.abs_path(), "value = 2\n".to_owned()));
    let overlay_analyzer = analyzer.clone_with_project(Arc::new(overlay.snapshot()));
    let read = crate::analyzer::semantic::service::stored_semantic_ir_publication_read(
        &overlay_analyzer,
        &file,
        |store, key| {
            store
                .semantic_ir_head_observation(key)
                .map(|head| (head, None::<()>))
        },
        None,
        &cancellation,
    );
    assert!(matches!(read.unwrap().0, StoredSemanticIrRead::Refused));
}

#[test]
fn stored_publication_read_refuses_selection_drift() {
    use crate::analyzer::semantic::StoredSemanticIrRead;

    let _rules =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join("sample.py"), "value = 1\n").unwrap();
    let file = ProjectFile::new(&root, "sample.py");
    let calls = Arc::new(AtomicUsize::new(0));
    let enabled = Arc::new(AtomicBool::new(false));
    let adapter = PythonAdapter {
        storage_key_calls: Some(Arc::clone(&calls)),
        alternate_storage_key_on_call: Some(2),
        alternate_storage_key_enabled: Some(Arc::clone(&enabled)),
        ..PythonAdapter::default()
    };
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
    let analyzer = TreeSitterAnalyzer::new(project, adapter);
    assert!(analyzer.resolve_live_oid_for_file(&file).is_some());
    calls.store(0, Ordering::Relaxed);
    enabled.store(true, Ordering::Relaxed);
    let read = crate::analyzer::semantic::service::stored_semantic_ir_publication_read(
        &analyzer,
        &file,
        |store, key| {
            store
                .semantic_ir_head_observation(key)
                .map(|head| (head, None::<()>))
        },
        None,
        &CancellationToken::default(),
    );
    assert!(matches!(read.unwrap().0, StoredSemanticIrRead::Refused));
}

fn dirty_state(
    analyzer: &TreeSitterAnalyzer<PythonAdapter>,
    file: &ProjectFile,
    source: &str,
    state: FileState,
) {
    assert_eq!(state.source, source);
    let oid = analyzer
        .resolve_live_oid_for_file(file)
        .expect("fixture file is live");
    let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, file);
    let dirty = TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
        Arc::new(state),
        Arc::clone(&analyzer.store_context.generations),
        Vec::new(),
        1,
        "test state".to_string(),
        DirtyFileStateStatus::Retryable,
    );
    analyzer
        .state
        .dirty_file_states
        .lock()
        .expect("dirty state lock")
        .insert(key, dirty);
}

fn parsed_state(
    analyzer: &TreeSitterAnalyzer<PythonAdapter>,
    file: &ProjectFile,
    source: &str,
) -> FileState {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&analyzer.adapter.parser_language())
        .expect("Python grammar");
    TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
        &mut parser,
        &analyzer.adapter,
        file,
        source.to_string(),
    )
    .expect("parse fixture")
    .state
}

#[test]
#[hardwon("#8474: retained fill admitted a dirty parse-incomplete file state")]
fn retained_fill_must_refuse_dirty_parse_incomplete_state() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("main.py", "value = 1\n")]);
    let file = analyzer.analyzed_live_files().pop().expect("selected file");
    let source = file.read_to_string().expect("fixture source");
    let mut state = parsed_state(&analyzer, &file, &source);
    state.parse_complete = false;
    dirty_state(&analyzer, &file, &source, state);

    let fill = crate::analyzer::common::replayable_query_cache_fill(&analyzer, || {
        analyzer
            .cached_file_state_for_exact_source(&file, &source)
            .expect("dirty state is visible")
            .parse_complete
    });
    assert!(
        matches!(fill, Err(false)),
        "dirty incomplete state was retained: {fill:?}"
    );
}

fn unit(file: &ProjectFile, name: &str, kind: CodeUnitType) -> CodeUnit {
    CodeUnit::new(file.clone(), kind, "", name)
}

#[test]
fn workspace_import_budget_never_inspects_an_extra_file() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("a.py", "import os\na = 1\n"), ("b.py", "b = 2\n")]);
    let first = analyzer
        .project()
        .all_files()
        .expect("workspace files")
        .into_iter()
        .find(|file| file.rel_path() == std::path::Path::new("a.py"))
        .expect("first file");
    let source = first.read_to_string().expect("read fixture");
    let mut state = parsed_state(&analyzer, &first, &source);
    state.imports.push(crate::analyzer::ImportInfo {
        raw_snippet: "import os".to_string(),
        is_wildcard: false,
        is_global: false,
        identifier: Some("os".to_string()),
        alias: None,
        path: None,
        binder_span: None,
    });
    dirty_state(&analyzer, &first, &source, state);
    let result = analyzer.workspace_import_info_limited(
        crate::analyzer::AnalyzerQueryScope::new(&analyzer).token(),
        2,
        || true,
    );
    assert!(!result.complete);
    assert_eq!(result.inspected, 2);
    assert!(result.inspected <= 2);
}

#[test]
fn workspace_imports_use_dirty_selected_state_in_both_readers() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("A.py", "value = 1\n")]);
    let file = analyzer.analyzed_live_files().pop().expect("selected file");
    let source = file.read_to_string().expect("fixture source");
    let mut state = parsed_state(&analyzer, &file, &source);
    state.imports.push(crate::analyzer::ImportInfo {
        raw_snippet: "import dirty".to_owned(),
        is_wildcard: false,
        is_global: false,
        identifier: Some("dirty".to_owned()),
        alias: None,
        path: None,
        binder_span: None,
    });
    dirty_state(&analyzer, &file, &source, state);
    let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
    let limited = analyzer.workspace_import_info_limited(scope.token(), 10, || true);
    let full = analyzer.import_info_of(scope.token(), &file);
    assert!(limited.complete, "{limited:?}");
    assert_eq!(limited.rows, full);
}

#[test]
fn bulk_query_file_state_hydration_respects_its_file_cap() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let sources = (0..=BULK_FILE_STATE_QUERY_LIMIT)
        .map(|index| (format!("file_{index:04}.py"), "value = 1\n"))
        .collect::<Vec<_>>();
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace root");
    for (path, source) in &sources {
        std::fs::write(root.join(path), source).expect("write workspace source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
    let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
    // The byte budget would otherwise bind first whenever a FileState grows,
    // which says nothing about the file cap under test.
    analyzer.set_query_file_state_cache_budget_for_test(usize::MAX);
    let files = analyzer.project().all_files().expect("workspace files");
    let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
    // Isolate the file-count cap: FileState growth must not make the query's
    // separate byte budget decide how many entries this test retains.
    analyzer
        .active_query_cache_handle(|cache| &cache.file_states)
        .expect("active query file-state cache")
        .write()
        .expect("query file-state cache lock")
        .max_bytes = usize::MAX;
    analyzer.bulk_file_states_for_query(files.iter().cloned(), BulkFileStateSource::Omit);

    let snapshot = analyzer
        .query_file_state_snapshot
        .load_full()
        .expect("query state snapshot");
    // The byte budget can admit fewer states than the file cap as FileState grows.
    assert!(!snapshot.is_empty());
    assert!(snapshot.len() <= BULK_FILE_STATE_QUERY_LIMIT);
    let live = analyzer.live_snapshot();
    let beyond_cap = analyzer.bulk_live_file_entries(
        files.iter().skip(BULK_FILE_STATE_QUERY_LIMIT).cloned(),
        &live,
    );
    assert_eq!(beyond_cap.len(), 1);
    let (file, oid, _) = &beyond_cap[0];
    let beyond_cap_key = analyzer
        .variant_cache_key(*oid, file)
        .expect("live file has a variant key");
    assert!(!snapshot.contains_key(&beyond_cap_key));
}

#[test]
fn limited_children_reports_more_children_at_the_page_boundary() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("main.py", "value = 1\n")]);
    let file = analyzer
        .project()
        .all_files()
        .expect("workspace files")
        .into_iter()
        .next()
        .expect("one file");
    let owner = unit(&file, "Owner", CodeUnitType::Class);
    let limited = analyzer.direct_children_limited(&owner, 1);
    assert!(!limited.complete);
    assert_eq!(limited.rows.len(), 1);
    let unlimited = analyzer.direct_children_limited(&owner, 2);
    assert!(unlimited.complete);
    assert_eq!(unlimited.rows.len(), 1);
}

#[test]
fn limited_dirty_declaration_scan_never_inspects_past_its_budget() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("main.py", "value = 1\n")]);
    let file = analyzer
        .project()
        .all_files()
        .expect("workspace files")
        .into_iter()
        .next()
        .expect("one file");
    let source = file.read_to_string().expect("read fixture");
    let mut state = parsed_state(&analyzer, &file, &source);
    state
        .declarations
        .insert(unit(&file, "first", CodeUnitType::Function));
    state
        .declarations
        .insert(unit(&file, "second", CodeUnitType::Function));
    dirty_state(&analyzer, &file, &source, state);

    let (limited, _) = analyzer.authoritative_units_matching_limited(false, 2, |_| true, || true);
    assert!(!limited.complete);
    assert_eq!(limited.inspected, 2);
    assert!(limited.inspected <= 2);
}

#[test]
fn candidate_alias_walk_stops_at_the_caller_budget() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("a.py", "same = 1\n"), ("b.py", "same = 1\n")]);
    let files = analyzer.project().all_files().expect("workspace files");
    let first = files.iter().next().cloned().expect("first path");
    let oid = analyzer
        .resolve_live_oid_for_file(&first)
        .expect("live OID");
    let row = HydratedCandidateRow {
        variant: brokk_bifrost_core::gitblob::ParseVariant::Empty,
        blob_oid: oid,
        lang: "python".to_string(),
        unit_key: 1,
        kind: CodeUnitType::Class,
        short_name: "Thing".to_string(),
        content_qualifier: String::new(),
        signature: None,
        flags: CandidateFlags {
            is_type_alias: false,
            is_top_level: true,
            in_declarations: true,
            in_definition_lookup: false,
            synthetic: false,
        },
        fq: Some(RelationalUnitFq::new(
            None,
            0,
            1,
            5,
            vec![(
                crate::analyzer::fq_name::SegmentKind::Type,
                "Thing".to_string(),
            )],
        )),
    };

    let result = analyzer.resolve_candidate_rows_limited(vec![row], 1, || true);
    assert!(!result.complete);
    assert_eq!(result.inspected, 1);
    assert!(result.inspected <= 1);
}

#[test]
fn cancelled_reverse_identifier_lookup_does_not_return_workspace_fallback() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("a.py", "a = 1\n"), ("b.py", "b = 2\n")]);
    assert!(analyzer.store_context.generations.contains_key("python"));
    let token = CancellationToken::new();
    token.cancel();
    let candidates =
        analyzer.reverse_identifier_candidates(&HashSet::from_iter(["target".to_string()]), &token);
    assert!(candidates.is_empty());
}

#[test]
fn cancelled_reverse_reference_walk_discards_accumulated_candidates() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let sources = (0..4)
        .map(|index| (format!("file_{index:05}.py"), "value = 1\n"))
        .collect::<Vec<_>>();
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("absolute workspace root");
    for (path, source) in &sources {
        std::fs::write(root.join(path), source).expect("write fixture source");
    }
    let token = Arc::new(CancellationToken::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let enabled = Arc::new(AtomicBool::new(false));
    let adapter = PythonAdapter {
        cancellation_on_storage_key: Some(Arc::clone(&token)),
        storage_key_calls: Some(Arc::clone(&calls)),
        cancellation_enabled: Some(Arc::clone(&enabled)),
        cancel_after_storage_key_calls: 3,
        alternate_storage_key_on_call: None,
        alternate_storage_key_enabled: None,
    };
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
    let analyzer = TreeSitterAnalyzer::new(project, adapter);
    let files = analyzer.project().all_files().expect("workspace files");
    for file in &files {
        let source = file.read_to_string().expect("read fixture");
        let state = parsed_state(&analyzer, file, &source);
        dirty_state(&analyzer, file, &source, state);
    }

    calls.store(0, Ordering::Relaxed);
    let probe_token = CancellationToken::new();
    let complete_candidates = analyzer.reverse_reference_candidates(
        &HashSet::default(),
        &HashSet::default(),
        &HashSet::default(),
        &probe_token,
    );
    assert_eq!(complete_candidates.len(), files.len());
    calls.store(0, Ordering::Relaxed);
    enabled.store(true, Ordering::Relaxed);
    let candidates = analyzer.reverse_reference_candidates(
        &HashSet::default(),
        &HashSet::default(),
        &HashSet::default(),
        &token,
    );
    assert!(token.is_cancelled());
    assert!(candidates.is_empty());
}

#[test]
fn cancelled_symbol_search_is_incomplete_before_candidate_enumeration() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("main.py", "value = 1\n")]);
    let patterns = SearchSymbolPatternBatch::compile(vec!["value".to_string()], true, None);
    let token = CancellationToken::new();
    token.cancel();

    let candidates = analyzer
        .sql_search_symbol_candidates(&patterns, Some(&token), None)
        .expect("valid pattern batch");
    assert!(!candidates.complete);
    assert!(candidates.rows.is_empty());
    assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);
}

#[test]
fn incomplete_signature_metadata_does_not_record_a_complete_lookup_digest() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("main.py", "def value(): pass\n")]);
    let file = analyzer
        .project()
        .all_files()
        .expect("workspace files")
        .into_iter()
        .next()
        .expect("one file");
    let source = file.read_to_string().expect("read fixture");
    let code_unit = unit(&file, "value", CodeUnitType::Function);
    let mut state = parsed_state(&analyzer, &file, &source);
    state.signature_metadata.insert(
        code_unit.clone(),
        vec![
            SignatureMetadata::new("value()", Vec::new()),
            SignatureMetadata::new("value(x)", Vec::new()),
        ],
    );
    dirty_state(&analyzer, &file, &source, state);
    let ledger = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let _scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());

    let metadata = analyzer.signature_metadata_limited(&code_unit, 1);
    assert!(!metadata.complete);
    assert_eq!(metadata.rows.len(), 1);
    assert!(ledger.keys().iter().all(|key| {
        !matches!(key, crate::analyzer::read_ledger::ReadKey::Lookup { kind, .. }
            if *kind == crate::analyzer::read_ledger::LookupKind::SignatureMetadata)
    }));
}

#[test]
fn prepared_syntax_limit_matches_unlimited_at_the_byte_boundary() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("main.py", "value = 1\n")]);
    let files = analyzer.project().all_files().expect("workspace files");
    let file = files.iter().next().cloned().expect("one file");
    let source_len = file.read_to_string().expect("read fixture").len();
    let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);

    let unlimited = analyzer.prepared_syntax_limited(scope.token(), &file, usize::MAX);
    let at_limit = analyzer.prepared_syntax_limited(scope.token(), &file, source_len);
    let under_limit = analyzer.prepared_syntax_limited(scope.token(), &file, source_len - 1);

    assert!(matches!(unlimited, Ok(Some(_))));
    assert!(matches!(at_limit, Ok(Some(_))));
    assert!(under_limit.is_err());
}

#[test]
fn cancelled_fact_mount_collection_is_unavailable_and_retryable() {
    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("a.py", "a = 1\n"), ("b.py", "b = 2\n")]);
    assert_eq!(
        analyzer.live_file_mounts_for_fact_publication_while(&|| false),
        None
    );
    let checks = std::cell::Cell::new(0);
    assert_eq!(
        analyzer.live_file_mounts_for_fact_publication_while(&|| {
            checks.set(checks.get() + 1);
            checks.get() < 3
        }),
        None
    );
    let complete = analyzer
        .live_file_mounts_for_fact_publication_while(&|| true)
        .expect("uncancelled mount snapshot");
    assert_eq!(complete.len(), 2);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7876: a failed package-class index build was cached and served without its failure"
)]
fn failed_package_class_build_is_not_published_to_a_later_request() {
    use crate::analyzer::AnalyzerQueryScope;

    let _language_hooks =
        crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(&[
            Language::Python,
        ]);
    let (_temp, analyzer) = analyzer(&[("model.py", "class Model: pass\n")]);
    let keeper = AnalyzerQueryScope::new(&analyzer);
    analyzer
        .store_context
        .store
        .execute_selection_publication(|conn| {
            conn.execute(
                "UPDATE analysis_epochs SET generation = generation + 1 WHERE lang = 'python'",
                [],
            )
            .expect("make captured generation stale");
        });
    let failed = AnalyzerQueryScope::new(&analyzer);
    assert!(
        analyzer
            .persisted_top_level_classes_in_package("")
            .is_empty()
    );
    assert!(
        failed.read_completion().is_err(),
        "the failed store query ran"
    );
    assert!(
        analyzer
            .query_read_cache_lock()
            .top_level_class_units_by_package
            .get()
            .is_none()
    );
    drop(failed);
    analyzer
        .store_context
        .store
        .execute_selection_publication(|conn| {
            conn.execute(
                "UPDATE analysis_epochs SET generation = generation - 1 WHERE lang = 'python'",
                [],
            )
            .expect("restore captured generation");
        });
    // A new request has no enclosing context, while keeper keeps the same
    // request memo alive. It must rebuild rather than consume the failed fill.
    {
        let _independent = brokk_bifrost_core::analyzer::carried_context::push(None);
        let _independent_request =
            brokk_bifrost_core::analyzer::carried_context::push_request_state(None);
        let later = AnalyzerQueryScope::new(&analyzer);
        analyzer.persisted_top_level_classes_in_package("");
        assert!(
            later.read_completion().is_ok(),
            "{:?}",
            later.read_completion()
        );
        assert!(
            analyzer
                .query_read_cache_lock()
                .top_level_class_units_by_package
                .get()
                .is_some()
        );
    }
    assert_eq!(analyzer.package_declaration_scan_count_for_test(), 2);
    assert!(
        keeper.read_completion().is_err(),
        "nested failure stays with its parent"
    );
}
