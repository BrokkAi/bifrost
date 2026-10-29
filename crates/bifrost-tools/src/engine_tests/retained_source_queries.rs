use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerStreamingFileScope;
use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
use brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionRefusal;
use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, StoreLanguageAdapter};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    DirtyFileStateStatus, LanguageAdapter, ParsedFile, PreparedSyntaxPreparation,
    TreeSitterAnalyzer, prepare_exact_syntax_tree, store_context_from_store,
};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSourceOrigin, PreparedSyntaxSource};
use brokk_bifrost_core::analyzer::project::{Project, TestProject};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tree_sitter::Tree;

struct JavaRanges {
    reject: Arc<AtomicBool>,
    keys: Vec<&'static str>,
}

impl StoreLanguageAdapter for JavaRanges {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        JavaAdapter.source_fact_storage()
    }
    fn produces_canonical_source_facts(&self) -> bool {
        JavaAdapter.produces_canonical_source_facts()
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        JavaAdapter.requires_source_declaration_metadata_bridges()
    }
    fn declaration_visibility_facts_version(&self) -> Option<i64> {
        JavaAdapter.declaration_visibility_facts_version()
    }
    fn java_type_constructor_facts_version(&self) -> Option<i64> {
        JavaAdapter.java_type_constructor_facts_version()
    }
    fn java_source_facts_version(&self) -> Option<i64> {
        JavaAdapter.java_source_facts_version()
    }

    fn language(&self) -> Language {
        Language::Java
    }
}

impl LanguageAdapter for JavaRanges {
    fn query_directory(&self) -> &'static str {
        JavaAdapter.query_directory()
    }
    fn file_extension(&self) -> &'static str {
        "java"
    }
    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        JavaAdapter.extract_call_receiver(reference)
    }
    fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
        JavaAdapter.parse_file(file, source, tree)
    }
    fn storage_language_keys(&self) -> Vec<(String, tree_sitter::Language)> {
        self.keys
            .iter()
            .map(|key| (key.to_string(), self.parser_language()))
            .collect()
    }
    fn parser_included_ranges_from_tree(
        &self,
        _source: &str,
        tree: &Tree,
        _should_stop: &mut dyn FnMut() -> bool,
    ) -> std::ops::ControlFlow<(), Option<Vec<tree_sitter::Range>>> {
        std::ops::ControlFlow::Continue(
            self.reject
                .load(Ordering::SeqCst)
                .then(|| vec![tree.root_node().range(), tree.root_node().range()]),
        )
    }
}

#[test]
fn exact_preparation_distinguishes_rejection_cancellation_and_timeout() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("A.java", "class A {}\n")
        .build();
    let adapter = JavaRanges {
        reject: Arc::new(AtomicBool::new(true)),
        keys: vec!["java"],
    };
    let file = fixture.file("A.java");
    let prepare = |token: Option<&CancellationToken>, deadline| {
        prepare_exact_syntax_tree(
            &adapter,
            &file,
            PreparedSyntaxSource::Exact(Arc::from("class A {}\n")),
            PreparedSourceOrigin::Disk,
            None,
            token,
            deadline,
        )
    };
    assert!(matches!(
        prepare(None, Instant::now() + Duration::from_secs(10)),
        PreparedSyntaxPreparation::Refused(SourceAdmissionRefusal::ProofRejected)
    ));
    let token = CancellationToken::new();
    token.cancel();
    assert!(matches!(
        prepare(Some(&token), Instant::now() + Duration::from_secs(10)),
        PreparedSyntaxPreparation::Cancelled
    ));
    assert!(matches!(
        prepare(None, Instant::now()),
        PreparedSyntaxPreparation::TimedOut
    ));
}

#[test]
fn content_identity_tracks_storage_ownership_and_ignores_inventory_order() {
    let adapter = |keys| JavaRanges {
        reject: Arc::new(AtomicBool::new(false)),
        keys,
    };
    let config = AnalyzerConfig::default();
    let identity = |keys| TreeSitterAnalyzer::build_content_identity_base(&config, &adapter(keys));
    assert_eq!(
        identity(vec!["java", "other"]),
        identity(vec!["other", "java"])
    );
    assert_ne!(
        identity(vec!["java", "other"]),
        identity(vec!["java", "renamed"])
    );
}

#[test]
fn callable_metric_inventory_excludes_fields_and_containers() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Nested.java", "class Nested { int field; class Inner { void first() { if (true) {} } void second() {} } void last() {} }\n").build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let metrics = analyzer
        .callable_metrics_for_file(&fixture.file("Nested.java"))
        .unwrap();
    let mut names = metrics
        .into_iter()
        .map(|(unit, _)| unit.identifier().to_string())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["first", "last", "second"]);
}

#[test]
fn streaming_reads_preserve_empty_and_single_byte_generation_sources() {
    for source in ["", " ", "  "] {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Empty.java", source)
            .build();
        let file = fixture.file("Empty.java");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        assert!(analyzer.source_snapshot_file_state(&file).is_some());
        assert_eq!(analyzer.file_source(&file).as_deref(), Some(source));
        let _stream = AnalyzerStreamingFileScope::new(&analyzer, &file);
        std::fs::remove_file(file.abs_path()).unwrap();
        assert_eq!(analyzer.file_source(&file).as_deref(), Some(source));
    }
}

#[test]
fn overload_projection_does_not_answer_an_absent_signature() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file(
            "Overloads.java",
            "class Overloads { void run(int value) {} void run(String value) {} }\n",
        )
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let methods = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.identifier() == "run")
        .collect::<Vec<_>>();
    assert_eq!(methods.len(), 2);
    for unit in methods {
        assert!(!analyzer.signatures(&unit).is_empty());
        let absent = CodeUnit::with_signature(
            unit.source().clone(),
            unit.kind(),
            unit.package_name(),
            unit.short_name(),
            Some("(missing)".to_owned()),
            unit.is_synthetic(),
        );
        assert_eq!(absent.fq_name(), unit.fq_name());
        assert!(analyzer.signatures(&absent).is_empty());
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "b31f09c005a0: a refused reparse must back off rather than retry on every read"
)]
fn rejected_dirty_reparse_advances_backoff_and_preserves_declarations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), "Retry.java");
    file.write("class Retry {}\n").unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let store = AnalyzerStore::open_persistent(&root.join("analyzer.db")).unwrap();
    store.conn.execute(|conn| conn.execute_batch("CREATE TRIGGER reject_blob BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT, 'publication failure'); END;").unwrap());
    let reject = Arc::new(AtomicBool::new(false));
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaRanges {
            reject: Arc::clone(&reject),
            keys: vec!["java"],
        },
        AnalyzerConfig::default(),
        store_context_from_store(project.as_ref(), store, false),
        None,
    )
    .unwrap();
    let dirty = analyzer.state.dirty_snapshot();
    let (key, before) = dirty
        .iter()
        .find(|(key, _)| key.rel_path == file.rel_path())
        .unwrap();
    assert!(before.state.parse_complete);
    assert_eq!(before.status, DirtyFileStateStatus::Retryable);
    reject.store(true, Ordering::SeqCst);
    std::thread::sleep(
        before
            .next_retry_at
            .saturating_duration_since(Instant::now())
            + Duration::from_millis(5),
    );
    let retained = analyzer.retry_dirty_file_state(key, "java").unwrap();
    assert!(
        retained
            .declarations
            .iter()
            .any(|unit| unit.identifier() == "Retry")
    );
    let after = analyzer.state.dirty_snapshot();
    assert_eq!(after[key].attempts, before.attempts + 1);
    assert!(after[key].next_retry_at > Instant::now());
    assert_eq!(after[key].status, before.status);
    analyzer.retry_dirty_file_state(key, "java").unwrap();
    assert_eq!(
        analyzer.state.dirty_snapshot()[key].attempts,
        after[key].attempts
    );
}

#[test]
fn refusal_inventory_keeps_multiple_sources_per_storage_language() {
    let refused = format!("int {} = 0;\n", "x".repeat(17_000));
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file("a.cpp", &refused)
        .file("b.cpp", &refused)
        .file("a.c", &refused)
        .file("b.c", &refused)
        .file("ok.cpp", "int ok;\n")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
    let mut paths = analyzer
        .selected_source_admission_refusals()
        .unwrap()
        .into_iter()
        .map(|(file, reason)| {
            assert!(!reason.is_empty());
            file.rel_path().to_string_lossy().into_owned()
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(paths, ["a.c", "a.cpp", "b.c", "b.cpp"]);
}

#[test]
fn stale_generation_publication_retains_terminal_live_declarations() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Stale.java", "class Before {}\n")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let file = fixture.file("Stale.java");
    analyzer
        .analyzer_store()
        .ensure_language_epoch_value("java", "different-parser-generation")
        .unwrap();
    let source = "class After {}\n";
    file.write(source).unwrap();
    analyzer.prepare_canonical_source_facts(&file, source.to_owned());
    let dirty = analyzer.state.dirty_snapshot();
    let (key, retained) = dirty
        .iter()
        .find(|(key, _)| key.rel_path == file.rel_path())
        .unwrap();
    assert_eq!(retained.status, DirtyFileStateStatus::TerminalStale);
    assert!(
        retained
            .state
            .declarations
            .iter()
            .any(|unit| unit.identifier() == "After")
    );
    analyzer.retry_dirty_file_state(key, "java").unwrap();
    assert_eq!(
        analyzer.state.dirty_snapshot()[key].attempts,
        retained.attempts
    );
}

#[test]
fn failed_publication_keeps_identical_source_alias_declarations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for path in ["First.java", "Second.java"] {
        ProjectFile::new(root.clone(), path)
            .write("class Shared {}\n")
            .unwrap();
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let store = AnalyzerStore::open_persistent(&root.join("analyzer.db")).unwrap();
    store.conn.execute(|conn| conn.execute_batch("CREATE TRIGGER reject_blob BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT, 'publication failure'); END;").unwrap());
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig::default(),
        store_context_from_store(project.as_ref(), store, false),
        None,
    )
    .unwrap();
    let inventory = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        let mut rows = analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| {
                (
                    unit.source().rel_path().to_path_buf(),
                    unit.identifier().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    };
    let dirty = analyzer.state.dirty_snapshot();
    for path in ["First.java", "Second.java"] {
        assert!(
            dirty
                .keys()
                .any(|key| key.rel_path == std::path::Path::new(path)),
            "{dirty:?}"
        );
    }
    let retained = inventory(&analyzer);
    assert_eq!(
        retained,
        [
            (std::path::PathBuf::from("First.java"), "Shared".to_owned()),
            (std::path::PathBuf::from("Second.java"), "Shared".to_owned())
        ]
    );
    analyzer
        .analyzer_store()
        .conn
        .execute(|conn| conn.execute_batch("DROP TRIGGER reject_blob").unwrap());
    let fresh = TreeSitterAnalyzer::new(Arc::clone(&project), JavaAdapter);
    assert_eq!(retained, inventory(&fresh));
}

#[test]
fn dirty_identifier_candidates_include_matches_and_exclude_disjoint_files() {
    use brokk_bifrost_ruby_analysis::analyzer::ruby::adapter::RubyAdapter;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let matching = ProjectFile::new(root.clone(), "match.rb");
    let disjoint = ProjectFile::new(root.clone(), "other.rb");
    matching
        .write("class Match\n  def value\n    Needle.new\n  end\nend\n")
        .unwrap();
    disjoint
        .write("class Other\n  def value\n    Unrelated.new\n  end\nend\n")
        .unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Ruby));
    let store = AnalyzerStore::open_persistent(&root.join("analyzer.db")).unwrap();
    store.conn.execute(|conn| conn.execute_batch("CREATE TRIGGER reject_blob BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT, 'publication failure'); END;").unwrap());
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        RubyAdapter,
        AnalyzerConfig::default(),
        store_context_from_store(project.as_ref(), store, false),
        None,
    )
    .unwrap();
    assert_eq!(analyzer.state.dirty_snapshot().len(), 2);
    let identifiers = ["Needle".to_owned()].into_iter().collect();
    let expected = [matching].into_iter().collect();
    assert_eq!(
        analyzer.reverse_identifier_candidates(&identifiers, &CancellationToken::new()),
        expected
    );
    analyzer
        .analyzer_store()
        .conn
        .execute(|conn| conn.execute_batch("DROP TRIGGER reject_blob").unwrap());
    let fresh = TreeSitterAnalyzer::new(project, RubyAdapter);
    assert_eq!(
        fresh.reverse_identifier_candidates(&identifiers, &CancellationToken::new()),
        expected
    );
}

#[test]
fn indexed_filesystem_identity_revalidates_after_an_unannounced_edit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), "Changed.java");
    file.write("class Before {}\n").unwrap();
    let repo = git2::Repository::init(&root).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(file.rel_path()).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Test", "test@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let mut context = store_context_from_store(project.as_ref(), store, false);
    context.live_paths =
        Arc::new(brokk_bifrost_analysis::analyzer::store::liveness::LivePathMap::default());
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        project,
        JavaAdapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .unwrap();
    let original = analyzer.resolve_live_oid_for_file(&file).unwrap();
    let replacement = "class ChangedWithDifferentLength {}\n";
    file.write(replacement).unwrap();
    let expected = git2::Oid::hash_object(git2::ObjectType::Blob, replacement.as_bytes()).unwrap();
    assert_ne!(original, expected);
    assert_eq!(
        analyzer
            .store_context
            .live_paths
            .snapshot()
            .validated_oid_for_path(&file),
        None
    );
    assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(expected));
}

struct CancellablePython {
    delegate: brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter,
    token: CancellationToken,
    armed: Arc<AtomicBool>,
}
impl StoreLanguageAdapter for CancellablePython {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        self.delegate.source_fact_storage()
    }
    fn produces_canonical_source_facts(&self) -> bool {
        self.delegate.produces_canonical_source_facts()
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        self.delegate.requires_source_declaration_metadata_bridges()
    }
    fn python_source_facts_version(&self) -> Option<i64> {
        self.delegate.python_source_facts_version()
    }

    fn language(&self) -> Language {
        Language::Python
    }
}
impl LanguageAdapter for CancellablePython {
    fn for_project(&self, project: Arc<dyn Project>) -> Option<Self> {
        Some(Self {
            delegate: self.delegate.for_project(project).unwrap(),
            token: self.token.clone(),
            armed: Arc::clone(&self.armed),
        })
    }

    fn query_directory(&self) -> &'static str {
        self.delegate.query_directory()
    }
    fn file_extension(&self) -> &'static str {
        "py"
    }
    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.delegate.extract_call_receiver(reference)
    }
    fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
        self.delegate.parse_file(file, source, tree)
    }
    fn cognitive_complexity_config(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::cognitive_complexity::Config> {
        self.delegate.cognitive_complexity_config()
    }
    fn supports_structural_line_data(&self) -> bool {
        true
    }
    fn is_structural_line_data(
        &self,
        node: tree_sitter::Node<'_>,
        should_stop: &mut dyn FnMut() -> bool,
    ) -> std::ops::ControlFlow<(), bool> {
        self.delegate.is_structural_line_data(node, should_stop)
    }
    fn parser_included_ranges_from_tree(
        &self,
        _source: &str,
        _tree: &Tree,
        _should_stop: &mut dyn FnMut() -> bool,
    ) -> std::ops::ControlFlow<(), Option<Vec<tree_sitter::Range>>> {
        if self.armed.load(Ordering::SeqCst) {
            self.token.cancel();
        }
        std::ops::ControlFlow::Continue(None)
    }
}

#[test]
fn cancellation_during_metric_admission_records_incompleteness() {
    use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
    let source = format!("def measured():\n    return \"{}\"\n", "x".repeat(17_000));
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
        .file("sample.py", &source)
        .build();
    let token = CancellationToken::new();
    let armed = Arc::new(AtomicBool::new(false));
    let analyzer = TreeSitterAnalyzer::new(
        fixture.project_dyn(),
        CancellablePython {
            delegate: Default::default(),
            token: token.clone(),
            armed: Arc::clone(&armed),
        },
    );
    let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &token);
    armed.store(true, Ordering::SeqCst);
    assert!(!token.is_cancelled());
    assert!(
        analyzer
            .callable_metrics_for_file(&fixture.file("sample.py"))
            .is_none()
    );
    assert!(token.is_cancelled());
    assert!(matches!(
        scope.read_completion(),
        Err(QueryReadIncomplete::Cancelled)
    ));
    drop(scope);
    armed.store(false, Ordering::SeqCst);
    let _scope = AnalyzerQueryScope::new(&analyzer);
    assert!(
        analyzer
            .callable_metrics_for_file(&fixture.file("sample.py"))
            .unwrap()
            .iter()
            .any(|(unit, _)| unit.identifier() == "measured")
    );
}

#[test]
fn cancellation_during_parseability_check_stops_without_caching_refusal() {
    use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
        .file("sample.py", "def before():\n    pass\n")
        .build();
    let token = CancellationToken::new();
    let armed = Arc::new(AtomicBool::new(false));
    let analyzer = TreeSitterAnalyzer::new(
        fixture.project_dyn(),
        CancellablePython {
            delegate: Default::default(),
            token: token.clone(),
            armed: Arc::clone(&armed),
        },
    );
    let file = fixture.file("sample.py");
    let replacement = format!("def after():\n    return \"{}\"\n", "x".repeat(17_000));
    file.write(&replacement).unwrap();
    let oid = git2::Oid::hash_object(git2::ObjectType::Blob, replacement.as_bytes()).unwrap();
    let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &token);
    armed.store(true, Ordering::SeqCst);
    assert!(!token.is_cancelled());
    assert!(analyzer.record_structure_unavailable_if_unparseable(&file, oid));
    assert!(token.is_cancelled());
    assert!(matches!(
        scope.read_completion(),
        Err(QueryReadIncomplete::Cancelled)
    ));
    drop(scope);
    armed.store(false, Ordering::SeqCst);
    let _scope = AnalyzerQueryScope::new(&analyzer);
    assert!(!analyzer.record_structure_unavailable_if_unparseable(&file, oid));
    assert!(
        analyzer
            .selected_source_admission_refusals()
            .unwrap()
            .is_empty()
    );
}

struct CancellableStorage {
    token: CancellationToken,
    classifications: Arc<std::sync::atomic::AtomicUsize>,
    cancel_at: Arc<std::sync::atomic::AtomicUsize>,
}
impl StoreLanguageAdapter for CancellableStorage {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        JavaAdapter.source_fact_storage()
    }
    fn produces_canonical_source_facts(&self) -> bool {
        JavaAdapter.produces_canonical_source_facts()
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        JavaAdapter.requires_source_declaration_metadata_bridges()
    }
    fn declaration_visibility_facts_version(&self) -> Option<i64> {
        JavaAdapter.declaration_visibility_facts_version()
    }
    fn java_type_constructor_facts_version(&self) -> Option<i64> {
        JavaAdapter.java_type_constructor_facts_version()
    }
    fn java_source_facts_version(&self) -> Option<i64> {
        JavaAdapter.java_source_facts_version()
    }

    fn language(&self) -> Language {
        Language::Java
    }
    fn storage_language_key_for_file(&self, _file: &ProjectFile) -> &'static str {
        let count = self.classifications.fetch_add(1, Ordering::SeqCst) + 1;
        if count == self.cancel_at.load(Ordering::SeqCst) {
            self.token.cancel();
        }
        "java"
    }
}
impl LanguageAdapter for CancellableStorage {
    fn query_directory(&self) -> &'static str {
        JavaAdapter.query_directory()
    }
    fn file_extension(&self) -> &'static str {
        "java"
    }
    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        JavaAdapter.extract_call_receiver(reference)
    }
    fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
        JavaAdapter.parse_file(file, source, tree)
    }
}

#[test]
fn cancellation_after_path_classification_discards_dirty_reference_candidates() {
    use std::sync::atomic::AtomicUsize;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let clean = ProjectFile::new(root.clone(), "Clean.java");
    clean.write("class Clean { Needle value; }\n").unwrap();
    let dirty = ProjectFile::new(root.clone(), "Dirty.java");
    let source = "class Dirty { Needle value; }\n";
    dirty.write(source).unwrap();
    let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
    let store = AnalyzerStore::open_persistent(&root.join("analyzer.db")).unwrap();
    store.conn.execute(move |conn| conn.execute_batch(&format!("CREATE TRIGGER reject_blob BEFORE INSERT ON blobs WHEN NEW.blob_oid = '{oid}' BEGIN SELECT RAISE(ABORT, 'publication failure'); END;")).unwrap());
    let token = CancellationToken::new();
    let classifications = Arc::new(AtomicUsize::new(0));
    let cancel_at = Arc::new(AtomicUsize::new(usize::MAX));
    let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        CancellableStorage {
            token: token.clone(),
            classifications: Arc::clone(&classifications),
            cancel_at: Arc::clone(&cancel_at),
        },
        AnalyzerConfig::default(),
        store_context_from_store(project.as_ref(), store, false),
        None,
    )
    .unwrap();
    assert_eq!(analyzer.state.dirty_snapshot().len(), 1);
    let identifiers = ["Needle".to_owned()].into_iter().collect();
    let empty = Default::default();
    classifications.store(0, Ordering::SeqCst);
    assert_eq!(
        analyzer.reverse_reference_candidates(&empty, &empty, &identifiers, &token),
        [clean, dirty].into_iter().collect()
    );
    let total = classifications.load(Ordering::SeqCst);
    assert!(total >= 2);
    classifications.store(0, Ordering::SeqCst);
    cancel_at.store(total, Ordering::SeqCst);
    let candidates = analyzer.reverse_reference_candidates(&empty, &empty, &identifiers, &token);
    assert!(token.is_cancelled());
    assert!(candidates.is_empty(), "{candidates:?}");
}
