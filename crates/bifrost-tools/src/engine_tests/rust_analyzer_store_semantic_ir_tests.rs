#[cfg(test)]
pub(crate) mod rust_departing_root_tests {
    use crate::analyzer::semantic::SemanticWork;
    use brokk_bifrost_analysis::analyzer::LanguageAdapter;
    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
    use brokk_bifrost_semantic::analyzer::semantic::service::primary_declarations::lower_with_primary_declarations;

    use brokk_bifrost_analysis::analyzer::semantic::service::ProgramSemanticsLowerer;

    use git2::Oid;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::store::semantic_ir::PreparedSemanticIr;

    use brokk_bifrost_analysis::analyzer::store::semantic_ir::SemanticIrLoweringOutcome;

    use brokk_bifrost_analysis::analyzer::store::semantic_ir::SemanticIrMountScope;

    use brokk_bifrost_analysis::analyzer::store::semantic_ir::SemanticIrPublicationOutcome;

    use brokk_bifrost_analysis::analyzer::store::semantic_ir::insert_semantic_ir_tx;

    use brokk_bifrost_analysis::analyzer::store::prepare_parse_time_semantic_ir;
    use brokk_bifrost_analysis::analyzer::store::semantic_ir::semantic_ir_producer_epoch;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_rust_analysis::analyzer::rust::semantic::RustSemanticLowerer;

    use brokk_bifrost_semantic::analyzer::semantic::partial_flow::fixpoint::PartialFlowOutcome;
    use brokk_bifrost_semantic::analyzer::semantic::partial_flow::fixpoint::ProcedurePartialFlows;

    use brokk_bifrost_semantic::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_semantic::analyzer::semantic::partial_flow::fixpoint::parse_time_partial_flows;
    use brokk_bifrost_semantic::analyzer::semantic::partial_flow::fixpoint::parse_time_partial_flows_with_limits;

    use crate::analyzer::semantic::ContentIdentity;
    use crate::analyzer::semantic::ProcedureId;
    use crate::analyzer::semantic::ProcedureSemanticsParts;
    use crate::analyzer::semantic::SemanticArtifact;
    use brokk_bifrost_semantic::analyzer::semantic::service::semantic_artifact_key_from_content;

    use crate::analyzer::semantic::SemanticBudget;
    use crate::analyzer::semantic::SemanticCapability;
    use crate::analyzer::semantic::SemanticIrVersion;
    use crate::analyzer::semantic::SemanticOutcome;
    use crate::analyzer::semantic::SemanticRequest;
    use crate::analyzer::semantic::SourceRevision;
    use crate::analyzer::semantic::StableDigest;
    use crate::analyzer::semantic::WorkspaceMountId;
    use crate::analyzer::semantic::WorkspaceRelativePath;
    use brokk_bifrost_semantic::analyzer::semantic::ids::SemanticArtifactKey;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PreparedSyntaxPreparation;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::prepare_exact_syntax_tree;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::LanguageDialect;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::text_utils::compute_line_starts;
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11069: declaration_facts hits dropped their fill's reads"
    )]
    fn declaration_facts_fill_and_hit_receipts_agree() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"owner-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn emit(value: u32) { sink(value); }\npub fn sink(value: u32) {}\n",
            )
            .build();
        let filesystem =
            brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace = brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(filesystem),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let file = project.file("src/lib.rs");
        let rust = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer,
        >(workspace.analyzer())
        .unwrap();
        let queries = brokk_bifrost_rust::usage_queries::RustUsageQueries::new(rust);
        let (cold, reads) = brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(
            workspace.analyzer(),
            || queries.declaration_facts_of(&file).unwrap(),
        );
        let (warm, warm_reads) = brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(
            workspace.analyzer(),
            || queries.declaration_facts_of(&file).unwrap(),
        );
        assert!(Arc::ptr_eq(&cold, &warm));
        let keys = reads.unordered_keys();
        let rendered = format!("{keys:?}");
        for dependency in [
            "Cargo.toml",
            "src/lib.rs",
            "src/Cargo.toml",
            "PathAbsent",
            "DeclarationFacts",
            "WorkspaceOverlayMembership",
        ] {
            assert!(
                rendered.contains(dependency),
                "missing {dependency}: {keys:?}"
            );
        }

        assert_eq!(
            reads.digest(),
            warm_reads.digest(),
            "fill: {reads:?}; hit: {warm_reads:?}"
        );
    }

    const CANDIDATE_SOURCE: &str = r#"
fn sink(value: u32) -> u32 { value }
fn emit(mut target: u32, value: u32) {
    log::info!("captured={value} {}", sink(log::debug!("nested={value}", { target = value; value })));
}
"#;

    struct CandidatePublication {
        store: AnalyzerStore,
        blob_id: i64,
        key: crate::analyzer::store::BlobKey,
        scope: SemanticIrMountScope,
        artifact: Arc<SemanticArtifact>,
        syntax: PreparedSyntaxTree,
        /// The alternates' flows solved eagerly on the lowered artifact, the
        /// oracle that flows solved on demand must equal (#10379).
        candidate_flows:
            Vec<crate::analyzer::semantic::partial_flow::fixpoint::CandidateMacroPartialFlows>,
    }

    fn candidate_publication(source: &str) -> CandidatePublication {
        // Compare content mutations within the same workspace mount identity.
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-10972-candidate-publication"),
            std::path::PathBuf::from("lib.rs"),
        );
        candidate_publication_for_file(source, file)
    }

    fn candidate_publication_for_file(source: &str, file: ProjectFile) -> CandidatePublication {
        let source: Arc<str> = Arc::from(source);
        let prepared = prepare(&file, &source);
        let cancellation = CancellationToken::default();
        let parts = match RustSemanticLowerer.lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &cancellation,
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(64 * 1024 * 1024),
        ) {
            Ok(SemanticOutcome::Complete { value, .. }) => value,
            other => panic!("candidate source lowers completely: {other:?}"),
        };
        let content =
            ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
        let key = semantic_artifact_key_from_content(
            &file,
            prepared.dialect(),
            content,
            None,
            RustSemanticLowerer.identity(),
        )
        .expect("semantic artifact key");
        let artifact = Arc::new(
            SemanticArtifact::try_new(key, RustSemanticLowerer.capabilities(), parts.clone())
                .expect("candidate artifact validates"),
        );
        let flows = parse_time_partial_flows(&artifact, &prepared, &cancellation)
            .expect("base flows solve");
        let candidate_flows = brokk_bifrost_semantic::analyzer::semantic::partial_flow::fixpoint::candidate_macro_partial_flows_with_limits(
            &artifact, &prepared, &cancellation, OracleLimits::default(),
        )
        .expect("candidate flows solve");
        assert!(!candidate_flows.is_empty(), "fixture has candidate macros");
        let epoch = semantic_ir_producer_epoch(&RustSemanticLowerer.identity());
        let rows = PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Complete { parts },
            Some(&flows),
            &epoch,
            content,
            source.len(),
        );
        let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let scope = SemanticIrMountScope::new(
            WorkspaceMountId::from_root(file.root()),
            WorkspaceRelativePath::try_from_path(file.rel_path()).unwrap(),
            LanguageDialect::for_path(Language::Rust, file.rel_path()),
            content,
        );
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        assert!(
            store
                .ensure_semantic_ir_producer_epoch("rust", &epoch)
                .unwrap()
        );
        let blob_id = {
            let mut conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
                [oid.to_string()],
            )
            .unwrap();
            let blob_id = conn.last_insert_rowid();
            let tx = conn.transaction().unwrap();
            assert!(
                insert_semantic_ir_tx(&tx, blob_id, "rust", &rows, &CancellationToken::default())
                    .unwrap()
            );
            tx.commit().unwrap();
            blob_id
        };
        CandidatePublication {
            key: crate::analyzer::store::BlobKey {
                oid,
                lang: "rust".into(),
                variant: brokk_bifrost_core::gitblob::ParseVariant::Empty,
            },
            store,
            blob_id,
            scope,
            artifact,
            syntax: prepared,
            candidate_flows,
        }
    }

    /// Solve one decoded alternate's flows on demand, as a selecting query does.
    fn lazy_alternate_flows(
        publication: &CandidatePublication,
        artifact: &Arc<SemanticArtifact>,
        procedure: crate::analyzer::semantic::ProcedureId,
    ) -> ProcedurePartialFlows {
        crate::analyzer::semantic::partial_flow::fixpoint::candidate_alternate_partial_flows(
            &artifact
                .candidate_alternate_handle(procedure)
                .expect("decoded alternate"),
            &publication.syntax,
            &CancellationToken::default(),
        )
        .expect("alternate flows solve")
    }

    fn artifact_with_guarded_parts(
        publication: &CandidatePublication,
        guarded: &[brokk_bifrost_analysis::analyzer::store::semantic_ir::GuardedProcedure],
    ) -> SemanticArtifact {
        let mut parts = publication
            .store
            .read_semantic_ir(publication.blob_id, &publication.scope)
            .unwrap();
        for alternate in guarded {
            let base = parts
                .iter_mut()
                .find(|base| base.id == alternate.parts.id)
                .unwrap();
            base.attach_candidate_macro_alternate(
                alternate.parts.clone(),
                alternate.candidates.clone().into_boxed_slice(),
            );
        }
        SemanticArtifact::try_new(
            publication.artifact.key().clone(),
            publication.artifact.capabilities().clone(),
            parts,
        )
        .expect("decoded alternate rebuilds the complete artifact")
    }
    /// Every file with `extension` under `root`, sorted, found without recursion.
    pub(crate) fn source_files(root: &Path, extension: &str) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut directories = vec![root.to_path_buf()];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory).expect("read source directory") {
                let path = entry.expect("read source directory entry").path();
                if path.is_dir() {
                    directories.push(path);
                } else if path.extension().is_some_and(|suffix| suffix == extension) {
                    files.push(path);
                }
            }
        }
        files.sort();
        files
    }

    /// Parse one file the way the Rust adapter prepares exact syntax.
    pub(crate) fn prepare(file: &ProjectFile, source: &Arc<str>) -> PreparedSyntaxTree {
        let adapter = RustAdapter::for_tests();
        assert!(
            adapter.parser_included_ranges(file, source).is_none(),
            "the Rust adapter parses whole files"
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(file))
            .expect("Rust grammar loads");
        let tree = parser
            .parse(source.as_ref(), None)
            .expect("tree-sitter parses");
        let tree = adapter
            .reparse_grammar_gap(source, &tree, None)
            .unwrap_or(tree);
        PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::clone(source)),
            tree,
            compute_line_starts(source),
            LanguageDialect::for_path(Language::Rust, file.rel_path()),
            PreparedSourceOrigin::Disk,
            None,
        )
    }

    #[derive(Debug, Default)]
    pub(crate) struct RoundTripReport {
        files: usize,
        round_tripped: usize,
        /// Files whose lowering did not complete, with the outcome label.
        not_lowered: Vec<(PathBuf, String)>,
        duplicate_content: usize,
        /// Files whose lowering fails or whose lowered parts the artifact
        /// rejects, with the error. The write path stores these as an `Error`
        /// outcome, so they have no rows.
        invalid_lowering: Vec<(PathBuf, String)>,
        parse_failures: Vec<(PathBuf, String)>,
        publication_failures: Vec<(PathBuf, String)>,
        /// The largest round-tripped file: its source bytes, its rows and
        /// estimated payload bytes per table, and its total logical rows and
        /// payload bytes.
        largest: Option<LargestFile>,
    }

    #[derive(Debug)]
    pub(crate) struct LargestFile {
        path: PathBuf,
        source_bytes: usize,
        census: Vec<(&'static str, usize, usize)>,
        logical_rows: usize,
        payload_bytes: usize,
    }

    /// One nextest SLOW period for the round-trip override in
    /// `.config/nextest.toml`.
    const SLOW_FILE_REPORT_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

    /// Reports a file whose whole round trip took at least one nextest SLOW
    /// period. Nextest prints a timed-out test's captured output, but the walk
    /// itself reports only when it finishes. The queue is largest-first, so
    /// the files that did print show which slow files completed and, by
    /// omission, what was still in flight at the kill. This adds no assertion
    /// and does nothing for a healthy run except count completed files.
    struct SlowFile<'a> {
        path: &'a Path,
        source_bytes: usize,
        started: std::time::Instant,
        completed: &'a std::sync::atomic::AtomicUsize,
        total: usize,
    }

    impl Drop for SlowFile<'_> {
        fn drop(&mut self) {
            let completed = self
                .completed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            let elapsed = self.started.elapsed();
            if elapsed >= SLOW_FILE_REPORT_AFTER {
                eprintln!(
                    "[semantic-ir round trip] {} ({} source bytes) took {:.1}s; \
                     {} of {} files done",
                    self.path.display(),
                    self.source_bytes,
                    elapsed.as_secs_f64(),
                    completed,
                    self.total
                );
            }
        }
    }

    /// Lower, store, read and decode every matching file under `root` on
    /// `workers` threads, each with its own store. Compare the decoded IR and
    /// partial flows with the materialization path's results. Workers take the
    /// largest remaining file first, so the slowest lowerings start at once.
    pub(crate) fn round_trip_tree<A: LanguageAdapter + StoreLanguageAdapter>(
        root: &Path,
        workers: usize,
        adapter: &A,
        extension: &str,
    ) -> RoundTripReport {
        let root = root.canonicalize().expect("source root exists");
        let mut files = source_files(&root, extension)
            .into_iter()
            .map(|path| {
                let bytes = std::fs::metadata(&path).expect("source metadata").len();
                (bytes, path)
            })
            .collect::<Vec<_>>();
        files.sort_unstable_by(|left, right| right.cmp(left));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let completed = std::sync::atomic::AtomicUsize::new(0);
        let total = files.len();
        let reports = std::thread::scope(|scope| {
            let handles = (0..workers)
                .map(|_| {
                    let root = &root;
                    let files = &files;
                    let next = &next;
                    let completed = &completed;
                    scope.spawn(move || {
                        let queue = std::iter::from_fn(|| {
                            let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            files.get(index).map(|(_, path)| path)
                        });
                        round_trip_files(root, queue, adapter, completed, total)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                })
                .collect::<Vec<_>>()
        });
        let mut merged = RoundTripReport::default();
        for report in reports {
            merged.files += report.files;
            merged.round_tripped += report.round_tripped;
            merged.not_lowered.extend(report.not_lowered);
            merged.duplicate_content += report.duplicate_content;
            merged.invalid_lowering.extend(report.invalid_lowering);
            merged.parse_failures.extend(report.parse_failures);
            merged
                .publication_failures
                .extend(report.publication_failures);
            if let Some(largest) = report.largest
                && merged
                    .largest
                    .as_ref()
                    .is_none_or(|current| largest.source_bytes > current.source_bytes)
            {
                merged.largest = Some(largest);
            }
        }
        merged
    }

    pub(crate) fn round_trip_files<'a, A: LanguageAdapter + StoreLanguageAdapter>(
        root: &Path,
        files: impl Iterator<Item = &'a PathBuf>,
        adapter: &A,
        completed: &std::sync::atomic::AtomicUsize,
        total: usize,
    ) -> RoundTripReport {
        let root = root.to_path_buf();
        let lowerer = adapter
            .parse_time_semantic_lowerer()
            .expect("native lowerer");
        let lowerer = lowerer.lowerer();
        let identity = lowerer.identity();
        let capabilities = lowerer.capabilities();
        let epoch = semantic_ir_producer_epoch(&identity);
        let storage_language = adapter.language().config_label();
        // Each file's check reads only that file's rows, so each file gets its
        // own store, dropped before the next file. One store per worker for
        // the whole walk held gigabytes on the `crates/` corpus and ran the
        // Windows gate's disk out (#10813); emptying it per file with a
        // cascading delete cost more CPU than the rest of the test together.
        let open_store = || {
            let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
            assert!(
                store
                    .ensure_semantic_ir_producer_epoch(storage_language, &epoch)
                    .unwrap()
            );
            store
        };
        let first = open_store();
        assert!(
            !first
                .ensure_semantic_ir_producer_epoch(storage_language, &epoch)
                .unwrap()
        );
        drop(first);
        let mut seen = std::collections::HashSet::new();
        let mut report = RoundTripReport::default();
        for path in files {
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };
            report.files += 1;
            let _slow_file = SlowFile {
                path: path.as_path(),
                source_bytes: source.len(),
                started: std::time::Instant::now(),
                completed,
                total,
            };
            let source: Arc<str> = Arc::from(source);
            let rel_path = path.strip_prefix(&root).expect("file under root");
            let file = ProjectFile::new(root.clone(), rel_path);
            let prepared = match prepare_exact_syntax_tree(
                adapter,
                &file,
                PreparedSyntaxSource::Exact(Arc::clone(&source)),
                PreparedSourceOrigin::Disk,
                None,
                None,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            ) {
                PreparedSyntaxPreparation::Complete(Some(prepared)) => prepared,
                PreparedSyntaxPreparation::Complete(None) => {
                    report
                        .parse_failures
                        .push((path.clone(), "no syntax tree".into()));
                    continue;
                }
                PreparedSyntaxPreparation::Refused(reason) => {
                    report
                        .parse_failures
                        .push((path.clone(), format!("refused: {reason:?}")));
                    continue;
                }
                PreparedSyntaxPreparation::TimedOut => {
                    report
                        .parse_failures
                        .push((path.clone(), "timed out".into()));
                    continue;
                }
                PreparedSyntaxPreparation::Cancelled => {
                    report
                        .parse_failures
                        .push((path.clone(), "cancelled".into()));
                    continue;
                }
            };
            if prepared.tree().root_node().has_error() {
                report
                    .parse_failures
                    .push((path.clone(), "tree-sitter ERROR node".into()));
            }
            let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
            if !seen.insert(oid) {
                report.duplicate_content += 1;
                continue;
            }
            assert_eq!(
                ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256())),
                ContentIdentity::hash_bytes(source.as_bytes())
            );
            // C# content identity is scoped by the selected parse variant (#8147),
            // exactly as parse-time preparation derives it.
            let content = ContentIdentity::from_source_digest(
                StableDigest::from_array(prepared.source_sha256()),
                prepared.dialect().language(),
                prepared.parse_variant(),
            );
            let path_identity = WorkspaceRelativePath::try_from_path(file.rel_path()).unwrap();
            let language = LanguageDialect::for_path(adapter.language(), file.rel_path());
            let cancellation = CancellationToken::default();
            let blob_key = brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, storage_language);
            let produced = prepare_parse_time_semantic_ir(
                lowerer,
                &file,
                &prepared,
                &blob_key,
                &cancellation,
                &brokk_bifrost_core::retention_budget::RetentionBudget::new(64 * 1024 * 1024),
            )
            .unwrap()
            .expect("parse-time preparation completes");
            // A lowerer with a primary-declaration path (C#) materializes through
            // that path, so its lowering and partial flows are the oracle the
            // parse-time rows must equal. Any other lowerer materializes with the
            // same `lower` call the producer makes, so the producer's own artifact
            // and partial flows are the oracle. Lowering and solving partial flows
            // a second time would only repeat the most expensive work of the
            // full-corpus walk, which then exceeds its time limit (#8739).
            let comparison = if let Some(primary_lowerer) = lowerer.primary_declaration_lowerer() {
                let mut budget = SemanticBudget::default();
                budget
                    .admit(SemanticWork {
                        source_bytes: source.len(),
                        ..Default::default()
                    })
                    .unwrap();
                let outcome = lower_with_primary_declarations(
                    primary_lowerer,
                    &file,
                    &prepared,
                    &budget,
                    &cancellation,
                    || {
                        adapter
                            .parse_file_preprocessed(
                                &file,
                                prepared.source(),
                                prepared.tree(),
                                prepared.preprocessor().map(|p| p.as_ref()),
                            )
                            .0
                    },
                );
                let parts = match outcome {
                    Ok(SemanticOutcome::Complete { value, .. }) => value,
                    Err(error) => {
                        report
                            .invalid_lowering
                            .push((path.clone(), error.to_string()));
                        continue;
                    }
                    Ok(other) => {
                        report
                            .not_lowered
                            .push((path.clone(), other.label().to_owned()));
                        continue;
                    }
                };
                let key = SemanticArtifactKey::new(
                    WorkspaceMountId::from_root(file.root()),
                    path_identity.clone(),
                    language,
                    SourceRevision::Disk { content },
                    identity.adapter.clone(),
                    SemanticIrVersion::current(),
                    identity.configuration,
                    identity.dependencies,
                );
                let lowered =
                    match SemanticArtifact::try_new(key, capabilities.clone(), parts.clone()) {
                        Ok(lowered) => Arc::new(lowered),
                        Err(error) => {
                            report
                                .invalid_lowering
                                .push((path.clone(), error.to_string()));
                            continue;
                        }
                    };
                let flows = parse_time_partial_flows(&lowered, &prepared, &cancellation)
                    .expect("partial flows");
                let expected_rows = PreparedSemanticIr::prepare(
                    SemanticIrLoweringOutcome::Complete { parts },
                    Some(&flows),
                    &epoch,
                    content,
                    source.len(),
                );
                Some((lowered, flows, expected_rows))
            } else {
                None
            };
            let prepared_rows = produced.rows;
            let store = open_store();
            let blob_id = {
                let mut conn = store.conn.lock().unwrap();
                conn.execute(
                    "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, 1)",
                    rusqlite::params![oid.to_string(), storage_language],
                )
                .unwrap();
                let blob_id = conn.last_insert_rowid();
                let tx = conn.transaction().unwrap();
                assert!(
                    insert_semantic_ir_tx(
                        &tx,
                        blob_id,
                        storage_language,
                        &prepared_rows,
                        &CancellationToken::default()
                    )
                    .unwrap()
                );
                tx.commit().unwrap();
                blob_id
            };

            let publication = store
                .semantic_ir_publication(&blob_key)
                .unwrap()
                .unwrap_or_else(|| panic!("{}: no valid publication", path.display()));
            let (lowered, flows) = match (comparison, publication.outcome) {
                (Some((lowered, flows, expected_rows)), SemanticIrPublicationOutcome::Complete) => {
                    assert_eq!(
                        prepared_rows,
                        expected_rows,
                        "{}: parse-time and primary lowering differ",
                        path.display()
                    );
                    (lowered, flows)
                }
                (None, SemanticIrPublicationOutcome::Complete) => produced
                    .lowered
                    .expect("a complete publication has a lowered artifact"),
                (Some(_), outcome) => {
                    report
                        .publication_failures
                        .push((path.clone(), format!("{outcome:?}")));
                    continue;
                }
                (
                    None,
                    SemanticIrPublicationOutcome::Error(error)
                    | SemanticIrPublicationOutcome::Panicked(error),
                ) => {
                    report.invalid_lowering.push((path.clone(), error));
                    continue;
                }
                (None, outcome) => {
                    report
                        .not_lowered
                        .push((path.clone(), format!("{outcome:?}")));
                    continue;
                }
            };
            assert_eq!(publication.blob_id, blob_id);
            assert_eq!(publication.content, content);
            assert_eq!(publication.source_bytes, source.len());
            let scope = SemanticIrMountScope::new(
                WorkspaceMountId::from_root(file.root()),
                path_identity,
                language,
                content,
            );
            let decoded = store.read_semantic_ir(blob_id, &scope).unwrap();
            let rebuilt =
                SemanticArtifact::try_new(lowered.key().clone(), capabilities.clone(), decoded)
                    .unwrap_or_else(|error| {
                        panic!("{}: decoded parts are invalid: {error}", path.display())
                    });
            // Ordinary rows store the base projection; guarded alternates
            // have their own publication and round-trip test below.
            assert_eq!(
                rebuilt
                    .procedures()
                    .iter()
                    .map(|procedure| (procedure.id(), procedure.parts_materialization_id()))
                    .collect::<Vec<_>>(),
                lowered
                    .procedures()
                    .iter()
                    .map(|procedure| (procedure.id(), procedure.parts_materialization_id()))
                    .collect::<Vec<_>>(),
                "{}: decoded base rows differ from the lowered base rows",
                path.display()
            );
            assert_eq!(rebuilt.work(), lowered.base_work(), "{}", path.display());
            assert_eq!(
                flows.len(),
                rebuilt.procedures().len(),
                "{}",
                path.display()
            );
            // One read for the whole blob: a read per procedure decodes the
            // blob's identities each time, which is quadratic in the file.
            let stored = store.read_blob_partial_flows(blob_id, &scope).unwrap();
            assert_eq!(stored.len(), flows.len(), "{}", path.display());
            for ((stored_procedure, stored), (procedure, direct_flow)) in
                stored.iter().zip(rebuilt.procedures().iter().zip(&flows))
            {
                assert_eq!(*stored_procedure, procedure.id(), "{}", path.display());
                assert_eq!(stored, direct_flow, "{}", path.display());
            }
            if let Some((procedure, stored)) = stored.first() {
                assert_eq!(
                    store
                        .read_partial_flows(blob_id, *procedure, &scope)
                        .unwrap()
                        .as_ref(),
                    Some(stored),
                    "{}: the one-procedure read differs",
                    path.display()
                );
            }
            report.round_tripped += 1;
            if report
                .largest
                .as_ref()
                .is_none_or(|largest| source.len() > largest.source_bytes)
            {
                report.largest = Some(LargestFile {
                    path: path.clone(),
                    source_bytes: source.len(),
                    census: prepared_rows.table_census(),
                    logical_rows: prepared_rows.logical_rows(),
                    payload_bytes: prepared_rows.payload_bytes(),
                });
            }
        }
        report
    }

    pub(crate) fn print_report(report: &RoundTripReport) {
        println!(
            "{} files, {} round-tripped, {} duplicate contents, not lowered: {:?}, \
         invalid lowering: {:?}, parse failures: {:?}, publication failures: {:?}",
            report.files,
            report.round_tripped,
            report.duplicate_content,
            report.not_lowered,
            report.invalid_lowering,
            report.parse_failures,
            report.publication_failures
        );
        if let Some(largest) = &report.largest {
            println!(
                "largest file {} ({} source bytes, {} logical rows, {} estimated payload bytes):",
                largest.path.display(),
                largest.source_bytes,
                largest.logical_rows,
                largest.payload_bytes
            );
            for (table, rows, payload) in &largest.census {
                println!("  {table}: {rows} rows, {payload} estimated payload bytes");
            }
        }
    }

    /// Runs on every available CPU; `.config/nextest.toml` reserves them.
    #[test]
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    pub(crate) fn semantic_ir_rows_round_trip_every_workspace_crate_source() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let workers = std::thread::available_parallelism().map_or(1, usize::from);
        let report = round_trip_tree(&root, workers, &RustAdapter::for_tests(), "rs");
        print_report(&report);
        assert!(report.round_tripped > 0, "{report:?}");
    }

    /// A head written under another producer epoch is not a publication, and a
    /// head whose outcome is not complete reports that outcome.
    #[test]
    pub(crate) fn semantic_ir_publication_applies_the_validity_rule() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let source = "fn f() {}\n";
        let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let content = ContentIdentity::hash_bytes(source.as_bytes());
        let blob_id = {
            let mut conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
                [oid.to_string()],
            )
            .unwrap();
            let blob_id = conn.last_insert_rowid();
            let prepared = PreparedSemanticIr::prepare(
                SemanticIrLoweringOutcome::Unsupported(SemanticCapability::GuardFacts),
                None,
                "epoch-a",
                content,
                source.len(),
            );
            assert_eq!(prepared.logical_rows(), 1);
            let tx = conn.transaction().unwrap();
            assert!(
                insert_semantic_ir_tx(
                    &tx,
                    blob_id,
                    "rust",
                    &prepared,
                    &CancellationToken::default()
                )
                .unwrap()
            );
            tx.commit().unwrap();
            blob_id
        };
        assert_eq!(
            store
                .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    oid, "rust"
                ))
                .unwrap(),
            None
        );
        store
            .ensure_semantic_ir_producer_epoch("rust", "epoch-a")
            .unwrap();
        let publication = store
            .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "rust"))
            .unwrap()
            .unwrap();
        assert_eq!(publication.blob_id, blob_id);
        assert_eq!(
            publication.outcome,
            SemanticIrPublicationOutcome::Unsupported(SemanticCapability::GuardFacts)
        );
        assert!(
            store
                .ensure_semantic_ir_producer_epoch("rust", "epoch-b")
                .unwrap()
        );
        assert_eq!(
            store
                .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    oid, "rust"
                ))
                .unwrap(),
            None
        );
    }

    /// A Rust file served through the public provider comes from its semantic IR
    /// rows, and its artifact is the one that lowering the same source produces.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    pub(crate) fn rust_artifact_served_from_rows_matches_direct_lowering() {
        pub(crate) const LIB: &str = "pub fn first(value: i32) -> i32 { value + 1 }\n";
        pub(crate) const OTHER: &str = "pub struct Holder { pub item: String }\n\
        pub fn second(holder: &Holder) -> &str { &holder.item }\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", LIB)
            .file("src/other.rs", OTHER)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let store = workspace
            .store()
            .expect("the ephemeral workspace has a store");
        let conn = store.read_conn().expect("a read connection");
        let rust_blobs: i64 = conn
            .query_row(
                "SELECT count(*) FROM blobs WHERE lang = 'rust'",
                [],
                |row| row.get(0),
            )
            .expect("count Rust blobs");
        let published: i64 = conn
            .query_row(
                "SELECT count(*) FROM semantic_ir_publications WHERE outcome = 0",
                [],
                |row| row.get(0),
            )
            .expect("count complete semantic IR publications");
        drop(conn);
        assert_eq!(
            published, rust_blobs,
            "every Rust blob must publish complete semantic IR rows"
        );

        let file = project.file("src/lib.rs");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let served = workspace
            .materialize_program_semantics(
                &file,
                &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("materialize the Rust file through the provider")
            .available_value()
            .cloned()
            .expect("the Rust file yields a complete artifact");

        let prepared = match prepare_exact_syntax_tree(
            &RustAdapter::for_tests(),
            &file,
            PreparedSyntaxSource::Exact(Arc::from(LIB)),
            PreparedSourceOrigin::Disk,
            None,
            None,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        ) {
            PreparedSyntaxPreparation::Complete(Some(prepared)) => prepared,
            _ => panic!("the fixture parses"),
        };
        let lowered = match RustSemanticLowerer.lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &cancellation,
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(64 * 1024 * 1024),
        ) {
            Ok(SemanticOutcome::Complete { value, .. }) => value,
            Ok(other) => panic!("direct lowering must complete: {}", other.label()),
            Err(error) => panic!("direct lowering failed: {error}"),
        };
        let content =
            ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
        let key = semantic_artifact_key_from_content(
            &file,
            prepared.dialect(),
            content,
            None,
            RustSemanticLowerer.identity(),
        )
        .expect("the file has a semantic artifact key");
        let direct = SemanticArtifact::try_new_with_budget(
            key,
            RustSemanticLowerer.capabilities(),
            lowered,
            &mut SemanticBudget::default(),
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .expect("the directly lowered artifact validates");
        assert_eq!(served.materialization_id(), direct.materialization_id());
    }

    /// The partial flows of every procedure of one Rust source, projected the way
    /// the parse-time writer projects them, with the lowered procedures they belong
    /// to.
    pub(crate) fn partial_flows_of(
        source: &str,
    ) -> (
        ProjectFile,
        Vec<ProcedureSemanticsParts>,
        Vec<ProcedurePartialFlows>,
    ) {
        partial_flows_of_with_limits(source, OracleLimits::default())
    }

    /// [`partial_flows_of`] under explicit oracle limits.
    fn partial_flows_of_with_limits(
        source: &str,
        limits: OracleLimits,
    ) -> (
        ProjectFile,
        Vec<ProcedureSemanticsParts>,
        Vec<ProcedurePartialFlows>,
    ) {
        let (file, parts, mut flows) = partial_flows_under_each(source, &[limits]);
        (file, parts, flows.remove(0))
    }

    /// The partial flows of one source, projected once under each of `limits`
    /// from the same artifact, so the runs are comparable procedure by procedure.
    fn partial_flows_under_each(
        source: &str,
        limits: &[OracleLimits],
    ) -> (
        ProjectFile,
        Vec<ProcedureSemanticsParts>,
        Vec<Vec<ProcedurePartialFlows>>,
    ) {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", source)
            .build();
        let file = project.file("lib.rs");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Rust semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Rust semantic artifact is available");
        let source: Arc<str> = Arc::from(source);
        let prepared = prepare(&file, &source);
        let flows = limits
            .iter()
            .map(|limits| {
                parse_time_partial_flows_with_limits(&artifact, &prepared, &cancellation, *limits)
                    .expect("the projection is not cancelled")
            })
            .collect::<Vec<_>>();
        let parts = match RustSemanticLowerer.lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &CancellationToken::default(),
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(64 * 1024 * 1024),
        ) {
            Ok(SemanticOutcome::Complete { value, .. }) => value,
            other => panic!("the fixture lowers completely: {other:?}"),
        };
        for flows in &flows {
            assert_eq!(parts.len(), flows.len(), "one entry per procedure");
        }
        (file, parts, flows)
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6415: compound assignments lost operand dependence after overwriting the target"
    )]
    fn compound_assignment_preserves_both_operand_dependencies() {
        use brokk_bifrost_semantic::analyzer::semantic::partial_flow::ports::PartialFlowPort;

        let (_, parts, flows) = partial_flows_of("fn f(mut x: u8, t: u8) -> u8 { x |= t; x }");
        let index = parts
            .iter()
            .position(|part| part.locator.declaration().last_segment_name() == Some("f"))
            .expect("f procedure");
        let flow = &flows[index];
        for ordinal in [0, 1] {
            assert!(
                flow.flows.iter().any(|edge| {
                    flow.ports[edge.from.index()] == PartialFlowPort::Parameter { ordinal }
                        && flow.ports[edge.to.index()] == PartialFlowPort::NormalReturn
                }),
                "operand {ordinal} must reach the target's later read: {flow:#?}"
            );
        }
    }

    /// Write the heads of one Rust source through the semantic-IR writer, as
    /// the blob transaction does, and read each procedure's head back.
    fn store_and_read_heads(
        source: &str,
        file: &ProjectFile,
        parts: Vec<ProcedureSemanticsParts>,
        flows: &[ProcedurePartialFlows],
    ) -> Vec<ProcedurePartialFlows> {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let identity = RustSemanticLowerer.identity();
        let epoch = semantic_ir_producer_epoch(&identity);
        assert!(
            store
                .ensure_semantic_ir_producer_epoch("rust", &epoch)
                .unwrap()
        );
        let oid = Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let content = ContentIdentity::hash_bytes(source.as_bytes());
        let scope = SemanticIrMountScope::new(
            WorkspaceMountId::from_root(file.root()),
            WorkspaceRelativePath::try_from_path(file.rel_path()).unwrap(),
            LanguageDialect::for_path(Language::Rust, file.rel_path()),
            content,
        );
        let prepared = PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Complete { parts },
            Some(flows),
            &epoch,
            content,
            source.len(),
        );
        let blob_id = {
            let mut conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
                [oid.to_string()],
            )
            .unwrap();
            let blob_id = conn.last_insert_rowid();
            let tx = conn.transaction().unwrap();
            assert!(
                insert_semantic_ir_tx(
                    &tx,
                    blob_id,
                    "rust",
                    &prepared,
                    &CancellationToken::default()
                )
                .unwrap()
            );
            tx.commit().unwrap();
            blob_id
        };
        (0..flows.len())
            .map(|index| {
                let procedure = ProcedureId::new(u32::try_from(index).unwrap());
                store
                    .read_partial_flows(blob_id, procedure, &scope)
                    .unwrap()
                    .unwrap_or_else(|| panic!("procedure {index} has a head row"))
            })
            .collect()
    }

    /// Partial flows survive the write and the read: each procedure's ports,
    /// flows with their crossed calls, openness and discharged gaps read back
    /// equal to the computed value.
    #[test]
    pub(crate) fn partial_flows_round_trip_through_rows() {
        let source = "pub struct Holder {\n    field: u32,\n}\n\nimpl Holder {\n    pub fn store(&mut self, value: u32) {\n        self.field = value;\n    }\n}\n\npub fn identity(value: u32) -> u32 {\n    value\n}\n\npub fn forward(value: u32) {\n    sink(value);\n}\n\nfn sink(_value: u32) {}\n\npub fn capture(value: u32) -> impl Fn() -> u32 {\n    move || value\n}\n\npub fn around(value: u32) -> u32 {\n    sink(0);\n    value\n}\n\npub fn dynamic_index(values: &[u32], index: usize) -> u32 {\n    values[index]\n}\n\npub struct Pair { value: u32 }\npub fn mixed(flag: bool, value: u32, original: Pair) -> Pair {\n    if flag { return Pair { value }; }\n    original\n}\n";
        let (file, parts, flows) = partial_flows_of(source);
        let mixed = parts
            .iter()
            .position(|part| part.locator.declaration().last_segment_name() == Some("mixed"))
            .expect("mixed return procedure");
        assert!(
            !flows[mixed].relations_proven() && !flows[mixed].flows.is_empty(),
            "a positive member relation in one return arm cannot close another: {:#?}",
            flows[mixed]
        );
        assert!(
            flows.iter().any(|procedure| !procedure.flows.is_empty()),
            "the fixture has at least one partial flow to round-trip"
        );
        assert!(
            flows
                .iter()
                .flat_map(|procedure| &procedure.flows)
                .any(|flow| flow.crossed.iter().any(|class| !class.is_empty())),
            "the fixture has a flow that crosses a call: {flows:#?}"
        );
        // Both values of the head's relation-proof fact are stored and read back:
        // the dynamic element read names an index this procedure cannot prove
        // constant, so its relation stays partial.
        assert!(
            flows.iter().any(|procedure| procedure.relations_proven())
                && flows.iter().any(|procedure| !procedure.relations_proven()),
            "the fixture has procedures with and without an unproven relation: {flows:#?}"
        );
        let decoded = store_and_read_heads(source, &file, parts, &flows);
        for (index, (decoded, expected)) in decoded.iter().zip(&flows).enumerate() {
            assert_eq!(decoded, expected, "procedure {index}");
        }
    }

    /// The repository's own `from_reasons` shape: a return that joins a root that
    /// is not an exact allocation (a unit variant, a call result or a parameter)
    /// with a struct variant that stores a field. The projection does not
    /// transport the stored member (#9766).
    const REJECTED_MEMBER_SOURCE: &str = "pub fn small(x: u32) -> u32 { x }\n\
        pub enum Reasons { Complete, Incomplete { reasons: u32 } }\n\
        pub fn joined(empty: bool, reasons: u32) -> Reasons {\n    \
            if empty { Reasons::Complete } else { Reasons::Incomplete { reasons } }\n}\n\
        pub fn make() -> Reasons { Reasons::Complete }\n\
        pub fn from_call(empty: bool, reasons: u32) -> Reasons {\n    \
            if empty { make() } else { Reasons::Incomplete { reasons } }\n}\n\
        pub fn from_param(empty: bool, reasons: u32, base: Reasons) -> Reasons {\n    \
            if empty { base } else { Reasons::Incomplete { reasons } }\n}\n\
        pub struct Holder { pub text: Option<u32> }\n\
        pub fn holder() -> Holder { Holder { text: None } }\n\
        pub fn mutated(flag: bool, value: u32) -> Holder {\n    \
            match flag { true => holder(), false => { let mut result = holder(); result.text = Some(value); result } }\n}\n\
        pub enum Out { Text(String), Structured { structured: String, rendered: Option<String> } }\n\
        pub struct Res { pub content: Vec<String>, pub structured: Option<String> }\n\
        impl Res { pub fn success(content: Vec<String>) -> Res { Res { content, structured: None } } }\n\
        pub fn assigned_after_construction(output: Out) -> Res {\n    match output {\n        \
            Out::Text(text) => Res::success(vec![text]),\n        \
            Out::Structured { structured, rendered } => {\n            \
                let text = rendered.unwrap_or_else(|| structured.clone());\n            \
                let mut result = Res::success(vec![text]);\n            \
                result.structured = Some(structured);\n            result\n        }\n    }\n}\n\
        pub struct Outcome { pub complete: bool, pub diagnostics: Vec<u32> }\n\
        impl Outcome { pub fn complete(diagnostics: Vec<u32>) -> Outcome { Outcome { complete: true, diagnostics } } }\n\
        pub fn assigned_in_both_arms(r: Result<Outcome, u32>) -> Outcome {\n    match r {\n        \
            Ok(mut outcome) => { outcome.complete = true; outcome }\n        \
            Err(error) => {\n            let mut outcome = Outcome::complete(Vec::new());\n            \
                outcome.complete = false;\n            outcome.diagnostics.push(error);\n            outcome\n        }\n    }\n}\n";

    fn procedure_named(parts: &[ProcedureSemanticsParts], name: &str) -> usize {
        parts
            .iter()
            .position(|part| part.locator.declaration().last_segment_name() == Some(name))
            .unwrap_or_else(|| panic!("{name} procedure"))
    }

    /// A real capacity cap that cuts the candidate set leaves an incomplete
    /// projection that still yields flows, and the stored head must say
    /// Truncated, never Complete. A small provenance cap reaches that on a small
    /// fixture; the default cap needs more than 4,096 relations, which costs
    /// minutes in a debug build. The small function stays under the cap.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10461: a truncated parse-time head was stored as complete"
    )]
    fn truncated_parse_time_head_round_trips_as_truncated() {
        let mut values = OracleLimits::default().values();
        values.provenance_records = 8;
        let limits = OracleLimits::new(values).expect("eight provenance records is a valid limit");
        let mut source =
            String::from("pub fn small() {}\npub fn wide(x: u32) -> u32 {\n    let v0 = x;\n");
        for index in 1..24 {
            source.push_str(&format!("    let v{index} = v{};\n", index - 1));
        }
        source.push_str("    v23\n}\n");
        let source = source.as_str();
        let (file, parts, flows) = partial_flows_of_with_limits(source, limits);
        let wide = procedure_named(&parts, "wide");
        let small = procedure_named(&parts, "small");
        assert_eq!(
            flows[wide].outcome,
            PartialFlowOutcome::Truncated,
            "the provenance cap cuts the candidate set: {:?}",
            flows[wide].detail
        );
        assert!(
            flows[wide].has_undischarged_gap(),
            "a truncated incomplete projection is open"
        );
        assert_eq!(flows[small].outcome, PartialFlowOutcome::Complete);
        let decoded = store_and_read_heads(source, &file, parts, &flows);
        assert_eq!(decoded[wide], flows[wide]);
        assert_eq!(decoded[wide].outcome, PartialFlowOutcome::Truncated);
        assert_eq!(decoded[small], flows[small]);
    }

    /// The #9766 guard records a content gap: the stored member is not
    /// transported. That is not a capacity cut, so the stored head is Complete
    /// with `open` and without `relations_complete`, never Truncated. It reads
    /// back unchanged, and it is the same under a small but sufficient set of
    /// limits and under the defaults.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10466: a rejected return member was typed as a budget truncation"
    )]
    fn rejected_return_member_head_is_open_content_not_truncated() {
        let mut values = OracleLimits::default().values();
        values.provenance_records = 64;
        values.evidence_handles = 64;
        values.access_path_length = 4;
        let small = OracleLimits::new(values).expect("small limits are valid");
        let (file, parts, mut flows) =
            partial_flows_under_each(REJECTED_MEMBER_SOURCE, &[OracleLimits::default(), small]);
        let limited = flows.remove(1);
        let flows = flows.remove(0);
        for name in [
            "joined",
            "from_call",
            "from_param",
            "mutated",
            "assigned_after_construction",
            "assigned_in_both_arms",
        ] {
            let head = &flows[procedure_named(&parts, name)];
            assert_eq!(
                head.outcome,
                PartialFlowOutcome::Complete,
                "{name}: {head:#?}"
            );
            assert!(head.has_undischarged_gap(), "{name}: {head:#?}");
            assert!(
                !head.relations_proven(),
                "{name}: the rejected member is not covered: {head:#?}"
            );
        }
        let small = procedure_named(&parts, "small");
        assert_eq!(flows[small].outcome, PartialFlowOutcome::Complete);
        assert!(flows[small].relations_proven());
        // The guard reads only content: a small but sufficient set of limits
        // gives every procedure the same head.
        assert_eq!(limited, flows, "a sufficient limit must not change a head");

        let decoded = store_and_read_heads(REJECTED_MEMBER_SOURCE, &file, parts, &flows);
        assert_eq!(decoded, flows);
    }

    /// compute_partial_flows reports a cancellation as an ExceededBudget head.
    /// A preparation cancelled at any check must return no heads, not heads
    /// with a budget cause. The token trips after N checks; sweep N until the
    /// preparation finishes without tripping it.
    #[test]
    #[brokk_bifrost_test_macros::hardwon("#10461: a cancelled preparation held budget-stop heads")]
    fn cancelled_parse_time_preparation_holds_no_heads() {
        let source = "pub fn id(x: u32) -> u32 { x }\npub fn nothing() {}\n";
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", source)
            .build();
        let file = project.file("lib.rs");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let live = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &live),
            )
            .expect("Rust semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Rust semantic artifact is available");
        let source: Arc<str> = Arc::from(source);
        let prepared = prepare(&file, &source);
        let mut checks = 1;
        loop {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let flows = parse_time_partial_flows(&artifact, &prepared, &cancellation);
            if cancellation.cancel_after_checks_tripped_for_test() {
                assert!(
                    flows.is_none(),
                    "a preparation cancelled at check {checks} returned heads: {flows:#?}"
                );
            } else {
                assert!(flows.is_some(), "an uncancelled preparation has heads");
                break;
            }
            checks += 1;
            assert!(checks < 100_000, "the preparation never finished");
        }
        assert!(checks > 1, "the sweep cancelled at least once");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11910: two candidate alternates of one base shared a materialization id"
    )]
    fn candidate_alternate_materialization_identity_is_exact() {
        use crate::analyzer::semantic::ProcedureLocalLocatorError;
        let publication = candidate_publication("fn emit() { log::info!(\"hello\"); }");
        let (parts, guarded) = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        assert!(!guarded.is_empty());
        let build = |changed: bool| {
            Arc::new(
                SemanticArtifact::try_new_with_candidate_alternates(
                    publication.artifact.key().clone(),
                    publication.artifact.capabilities().clone(),
                    parts.clone(),
                    guarded.iter().map(|row| {
                        let mut alternate = row.parts.clone();
                        if changed {
                            alternate.properties.is_synthetic = !alternate.properties.is_synthetic;
                        }
                        (alternate, row.candidates.clone().into_boxed_slice())
                    }),
                )
                .unwrap(),
            )
        };
        let first = build(false);
        let second = build(true);
        let id = guarded[0].parts.id;
        let first_handle = first.candidate_alternate_handle(id).unwrap();
        let second_handle = second.candidate_alternate_handle(id).unwrap();
        assert_eq!(first_handle.durable_key(), second_handle.durable_key());
        let base = SemanticArtifact::try_new(
            publication.artifact.key().clone(),
            publication.artifact.capabilities().clone(),
            parts,
        )
        .unwrap();
        assert_ne!(base.materialization_id(), first.materialization_id());
        // This is the #11842 sweep memo key; a different alternate must miss.
        let mut memo = std::collections::HashMap::new();
        memo.insert(
            (first_handle.durable_key(), first.materialization_id()),
            "first sweep",
        );
        assert!(
            !memo.contains_key(&(second_handle.durable_key(), second.materialization_id())),
            "different alternate contents reused the first sweep entry"
        );
        assert_ne!(first.materialization_id(), second.materialization_id());
        let point = first_handle
            .point_handle(first_handle.semantics().entry_point())
            .unwrap();
        assert_eq!(
            point.durable_locator().validate_owner(&second_handle),
            Err(ProcedureLocalLocatorError::ArtifactMaterializationMismatch)
        );
    }

    #[test]
    fn composition_exact_identity_scopes_dense_calls() {
        use crate::analyzer::semantic::{CallSiteId, ExactCallSiteKey, ExactProcedureIdentity};
        let publication = candidate_publication(
            "fn emit(value:u32){log::info!(\"{}\", sink(value));} fn sink(value:u32)->u32{value}",
        );
        let (parts, guarded) = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        let build = |changed: bool| {
            Arc::new(
                SemanticArtifact::try_new_with_candidate_alternates(
                    publication.artifact.key().clone(),
                    publication.artifact.capabilities().clone(),
                    parts.clone(),
                    guarded.iter().map(|row| {
                        let mut alternate = row.parts.clone();
                        if changed {
                            alternate.properties.is_synthetic = !alternate.properties.is_synthetic;
                        }
                        (alternate, row.candidates.clone().into_boxed_slice())
                    }),
                )
                .unwrap(),
            )
        };
        let first = build(false);
        let second = build(true);
        let id = guarded[0].parts.id;
        let base = first.procedure_handle(id).unwrap();
        let alternate = first.candidate_alternate_handle(id).unwrap();
        let other = second.candidate_alternate_handle(id).unwrap();
        let c0 = CallSiteId::new(0);
        assert_ne!(
            base.semantics().call_site(c0),
            alternate.semantics().call_site(c0),
            "dense c0 must denote different calls in this fixture"
        );
        assert_eq!(alternate.durable_key(), other.durable_key());
        let handles = [&base, &alternate, &other];
        // Every composition answer map uses these two shared value-key types.
        // This exercises their Eq/Hash contract with real frozen rows, including
        // two same-key materializations and both executable interpretations.
        let procedures: std::collections::HashMap<ExactProcedureIdentity, usize> = handles
            .iter()
            .enumerate()
            .map(|(index, handle)| (handle.exact_identity(), index))
            .collect();
        let calls: std::collections::HashMap<ExactCallSiteKey, usize> = handles
            .iter()
            .enumerate()
            .map(|(index, handle)| (handle.call_site_handle(c0).unwrap().exact_key(), index))
            .collect();
        assert_eq!(procedures.len(), 3);
        assert_eq!(calls.len(), 3);
        for (index, handle) in handles.iter().enumerate() {
            assert_eq!(procedures[&handle.exact_identity()], index);
            assert_eq!(
                calls[&handle.call_site_handle(c0).unwrap().exact_key()],
                index
            );
        }
    }

    fn bare_candidate_admission_pin(prefix: &str, dependency: &str, expected: bool) {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::languages::{
            CandidateMacroAdmissionRequest, CandidateMacroDecision,
        };
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        let source = format!("{prefix}\nfn emit() {{ info!(\"hello\"); }}");
        let manifest = format!(
            "[package]\nname=\"bare-pin\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\n{dependency}\n"
        );
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", &manifest)
            .file("src/macros.rs", "macro_rules! info { ($($t:tt)*) => {} }")
            .file("src/lib.rs", &source)
            .build();
        let filesystem =
            brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace = brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(filesystem),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let file = project.file("src/lib.rs");
        let publication = candidate_publication_for_file(&source, file.clone());
        let (parts, guarded) = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        let artifact = SemanticArtifact::try_new_with_candidate_alternates(
            publication.artifact.key().clone(),
            publication.artifact.capabilities().clone(),
            parts,
            guarded
                .iter()
                .map(|row| (row.parts.clone(), row.candidates.clone().into_boxed_slice())),
        )
        .unwrap();
        let procedure = artifact.procedure(guarded[0].parts.id).unwrap();
        let (alternate, records) = procedure.candidate_macro_alternate().unwrap();
        let candidates = records
            .iter()
            .map(|record| {
                let crate::analyzer::semantic::CandidateRealization::RuntimeCall(id) =
                    record.realization
                else {
                    panic!("a logging candidate is a runtime call: {record:?}");
                };
                let call = alternate.call_site(id).unwrap();
                brokk_bifrost_analysis::analyzer::languages::CandidateMacroInvocation {
                    region: record.base_call,
                    realization:
                        brokk_bifrost_analysis::analyzer::languages::CandidateMacroRealization::RuntimeCall {
                            runtime_argument_count: call.arguments.len(),
                        },
                    anchor: record.anchor,
                }
            })
            .collect::<Vec<_>>();
        let syntax = prepare(&file, &Arc::from(source.as_str()));
        let live = CancellationToken::default();
        let scope = AnalyzerQueryScope::new(workspace.analyzer());
        let request = CandidateMacroAdmissionRequest {
            analyzer: workspace.analyzer(),
            token: scope.token(),
            file: &file,
            head: publication.artifact.key(),
            procedure: guarded[0].parts.id,
            syntax: &syntax,
            candidates: &candidates,
            cancellation: &live,
        };
        let answers = brokk_bifrost_analysis::analyzer::languages::language_support(Language::Rust)
            .unwrap()
            .admit_candidate_macros(request);
        assert_eq!(answers.len(), 1);
        assert_eq!(
            matches!(answers[0].decision, CandidateMacroDecision::Admitted { .. }),
            expected,
            "admission: {:?}",
            answers[0].decision
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: importing log macro must not shadow the crate root"
    )]
    fn candidate_macro_bare_full_group() {
        bare_candidate_admission_pin(
            "use log::{debug,error,info,log,trace,warn,Level};",
            "log=\"0.4\"",
            true,
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_direct() {
        bare_candidate_admission_pin("use log::info;", "log=\"0.4\"", true);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_grouped() {
        bare_candidate_admission_pin("use log::{info, warn};", "log=\"0.4\"", true);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_macro_use() {
        bare_candidate_admission_pin("#[macro_use] extern crate log;", "log=\"0.4\"", true);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_local_macro() {
        bare_candidate_admission_pin(
            "#[macro_use] mod macros; use log::info;",
            "log=\"0.4\"",
            false,
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_unknown_glob() {
        bare_candidate_admission_pin("use log::info; use unknown::*;", "log=\"0.4\"", false);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_renamed_package() {
        bare_candidate_admission_pin(
            "use log::info;",
            "log={package=\"not-log\",version=\"0.4\"}",
            false,
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10930: bare logging admission requires an unambiguous package binding"
    )]
    fn candidate_macro_bare_second_import() {
        bare_candidate_admission_pin("use log::info; use other::info;", "log=\"0.4\"", false);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: review: enclosing standard macro roots must prove their crate identity"
    )]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: review: budget-stopped flow selections poisoned later warm requests"
    )]
    fn candidate_macro_overlay_f10_query_scope_and_manifest_invalidation() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::languages::{
            CandidateMacroAdmissionRequest, CandidateMacroDecision,
        };
        use brokk_bifrost_analysis::analyzer::semantic::service::{
            CandidateProcedureOutcome, CandidateProcedureSide,
            procedure_semantics_and_partial_flows,
        };
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        const UNREALIZED: &str = r#"
fn emit(value: u32) {
    log::info!(unknown: "audit", "{}", value);
    log::debug!(unknown: "audit", "{}", value);
}
"#;
        for (source, registry_admitted) in [
            (CANDIDATE_SOURCE, 2),
            (UNREALIZED, 0),
            (
                r#"fn emit(value: u32) {
                    log::info!(target: "audit", "{}", value);
                    log::debug!(target: "audit", "{}", value);
                }"#,
                2,
            ),
            (
                r#"mod std { macro_rules! format { ($($t:tt)*) => { 1 } } pub(crate) use format; }
fn emit() { std::format!("{} {}", { log::info!("x"); 1 }, { log::debug!("y"); 2 }); }"#,
                0,
            ),
            (
                r#"fn emit() { std::format!("{} {}", { log::info!("x"); 1 }, { log::debug!("y"); 2 }); }"#,
                2,
            ),
            (
                r#"fn emit(value: u32) {
                log::log!(log::Level::Info, "{}", value);
                log::log!(log::Level::Debug, "{}", value);
            }"#,
                2,
            ),
            (
                r#"mod fake {} fn emit() { log::info!("{}", { use crate::fake as log; log::debug!("x"); 1 }); }"#,
                1,
            ),
            (
                r#"fn emit() { log::info!("{}", { mod log {} log::debug!("x"); 1 }); }"#,
                1,
            ),
            (
                r#"fn emit() { log::info!("{}", { macro_rules! debug { () => {} } log::debug!("x"); 1 }); }"#,
                2,
            ),
            (
                r#"fn emit() { log::info!("{}", { log::debug!("x"); 1 }); }"#,
                2,
            ),
            (
                r#"
mod fake {}
fn sink(value: u32) -> u32 { value }
fn emit(mut target: u32, value: u32) {
    log::info!("captured={value}");
    {
        use crate::fake as log;
        log::debug!("nested={value}", { target = value; value });
    }
}
"#,
                1,
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname=\"owner-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file("src/lib.rs", source)
                .build();
            let mut prior_head = None;
            for (dependency, expected_admitted) in [
                ("log=\"0.4\"", registry_admitted),
                ("log={package=\"not-log\",version=\"0.4\"}", 0),
                ("log=\"0.4\"", registry_admitted),
            ] {
                std::fs::write(project.root().join("Cargo.toml"), format!(
                    "[package]\nname=\"owner-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\n{dependency}\n"
                )).unwrap();
                let filesystem =
                    brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root())
                        .unwrap();
                let workspace = brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
                    Arc::new(filesystem),
                    AnalyzerConfig::default(),
                )
                .unwrap();
                let file = project.file("src/lib.rs");
                let publication = candidate_publication_for_file(source, file.clone());
                let (parts, guarded) = publication
                    .store
                    .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
                    .unwrap()
                    .1
                    .unwrap();
                let artifact = Arc::new(
                    SemanticArtifact::try_new_with_candidate_alternates(
                        publication.artifact.key().clone(),
                        publication.artifact.capabilities().clone(),
                        parts,
                        guarded.iter().map(|row| {
                            (row.parts.clone(), row.candidates.clone().into_boxed_slice())
                        }),
                    )
                    .unwrap(),
                );
                let id = guarded[0].parts.id;
                let prepared = crate::analyzer::semantic::StoredCandidateMacroArtifact {
                    artifact: artifact.clone(),
                };
                if let Some(head) = &prior_head {
                    assert_eq!(head, artifact.key());
                }
                prior_head = Some(artifact.key().clone());
                let base = artifact.procedure_handle(id).unwrap();
                let syntax = prepare(&file, &Arc::from(source));
                let live = CancellationToken::default();
                let base_flows = parse_time_partial_flows(&artifact, &syntax, &live).unwrap();
                let mut fresh_signature = None;
                for _ in 0..2 {
                    let scope = AnalyzerQueryScope::new(workspace.analyzer());
                    let rust =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer,
                        >(workspace.analyzer())
                        .expect("Rust analyzer");
                    let queries = brokk_bifrost_rust::usage_queries::RustUsageQueries::new(rust);
                    let (cold, cold_reads) =
                        brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(
                            workspace.analyzer(),
                            || queries.declaration_facts_of(&file).unwrap(),
                        );
                    let (warm, reads) =
                        brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(
                            workspace.analyzer(),
                            || queries.declaration_facts_of(&file).unwrap(),
                        );
                    assert!(Arc::ptr_eq(&cold, &warm));
                    assert!(!reads.is_empty());
                    assert_eq!(
                        cold_reads.digest(),
                        reads.digest(),
                        "declaration fill and hit reads agree"
                    );
                    use brokk_bifrost_analysis::analyzer::semantic::service::candidate_macro_overlay_receipt;
                    assert!(
                        candidate_macro_overlay_receipt().is_none(),
                        "new query cannot reuse prior entries"
                    );
                    let solve = |alternate: &crate::analyzer::semantic::ProcedureHandle| {
                        crate::analyzer::semantic::partial_flow::fixpoint::candidate_alternate_partial_flows(
                            alternate, &syntax, &live,
                        )
                    };
                    let mut limits = SemanticBudget::default().limits();
                    limits.nested_entries = 1;
                    let mut tight = SemanticBudget::new(limits).unwrap();
                    let stopped = procedure_semantics_and_partial_flows(
                        &prepared,
                        &base,
                        None,
                        solve,
                        CandidateMacroAdmissionRequest {
                            analyzer: workspace.analyzer(),
                            token: scope.token(),
                            file: &file,
                            head: artifact.key(),
                            procedure: id,
                            syntax: &syntax,
                            candidates: &[],
                            cancellation: &live,
                        },
                        &mut SemanticRequest::new(&mut tight, &live),
                    )
                    .unwrap();
                    if let CandidateProcedureOutcome::Selected(selected) = stopped {
                        assert_eq!(selected.flows.outcome, crate::analyzer::semantic::partial_flow::PartialFlowOutcome::ExceededBudget);
                    }
                    assert!(
                        candidate_macro_overlay_receipt().is_none(),
                        "a stopped projection must not be retained"
                    );
                    let mut selected_handle = None;
                    let mut selected_reads = None;
                    for _ in 0..2 {
                        let mut budget = SemanticBudget::default();
                        let (outcome, reads) =
                            brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(
                                workspace.analyzer(),
                                || {
                                    workspace
                                        .selected_procedure_handle(
                                            &base,
                                            &mut SemanticRequest::new(&mut budget, &live),
                                        )
                                        .unwrap()
                                },
                            );
                        let brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome::Complete {
                            value:
                                crate::analyzer::semantic::service::SelectedProcedureHandle {
                                    handle,
                                    ..
                                },
                            ..
                        } = outcome
                        else {
                            panic!("selected handle unavailable");
                        };
                        if let Some(previous) = &selected_handle {
                            assert_eq!(previous, &handle, "selected arena must be canonical");
                            assert_eq!(
                                selected_reads,
                                Some(reads.digest()),
                                "selected receipts agree"
                            );
                        }
                        selected_handle = Some(handle);
                        selected_reads = Some(reads.digest());
                    }
                    let mut budget = SemanticBudget::default();
                    let paired = workspace
                        .selected_procedure_and_flows(
                            &base,
                            &mut SemanticRequest::new(&mut budget, &live),
                        )
                        .unwrap();
                    let CandidateProcedureOutcome::Selected(paired) = paired else {
                        panic!("paired selection unavailable");
                    };
                    assert_eq!(
                        selected_handle.as_ref(),
                        Some(&paired.procedure),
                        "handle-only and paired acquisitions share arena"
                    );
                    let oracle = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle::new(&workspace);
                    let mut dispatch_budget = SemanticBudget::default();
                    let mut dispatch = oracle.prepare_source_dispatch_session_in_artifact(
                        SemanticOutcome::Complete {
                            value: Arc::clone(base.artifact()),
                            work: Default::default(),
                        },
                    );
                    for row in paired.procedure.semantics().call_sites() {
                        let call = paired.procedure.call_site_handle(row.id).unwrap();
                        let range = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(&call).unwrap();
                        dispatch
                            .resolve_at_source(
                                range,
                                &mut SemanticRequest::new(&mut dispatch_budget, &live),
                            )
                            .expect("selected source dispatch uses the selected arena");
                    }
                    let mut first = None;
                    let mut retained: Option<
                        brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt,
                    > = None;
                    for _ in 0..2 {
                        let mut budget = SemanticBudget::default();
                        let (outcome, reads) =
                            brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(
                                workspace.analyzer(),
                                || {
                                    procedure_semantics_and_partial_flows(
                                        &prepared,
                                        &base,
                                        Some(&base_flows[id.index()]),
                                        solve,
                                        CandidateMacroAdmissionRequest {
                                            analyzer: workspace.analyzer(),
                                            token: scope.token(),
                                            file: &file,
                                            head: artifact.key(),
                                            procedure: id,
                                            candidates: &[],
                                            syntax: &syntax,
                                            cancellation: &live,
                                        },
                                        &mut SemanticRequest::new(&mut budget, &live),
                                    )
                                    .unwrap()
                                },
                            );
                        let CandidateProcedureOutcome::Selected(selected) = outcome else {
                            panic!("selection stopped");
                        };
                        let receipt =
                            candidate_macro_overlay_receipt().expect("fill retained in this query");
                        if let Some(retained) = &retained {
                            assert_eq!(
                                retained.digest(),
                                receipt.digest(),
                                "complete receipt changed"
                            );
                            assert!(
                                receipt.shares_capture_with(retained),
                                "hit keeps original fill receipt"
                            );
                        }
                        retained = Some(receipt.clone());
                        let signature = (
                            selected.side,
                            format!("{:?}", selected.flows),
                            reads.digest(),
                            receipt.digest(),
                        );
                        if let Some(first) = &first {
                            assert_eq!(first, &signature, "fill and hit agree");
                        }
                        first = Some(signature);
                        assert_eq!(selected.admissions.len(), 2);
                        if source == UNREALIZED && dependency == "log=\"0.4\"" {
                            assert!(selected.admissions.iter().all(|answer| matches!(
                                answer.decision,
                                CandidateMacroDecision::Refused(
                                    brokk_bifrost_analysis::analyzer::languages::CandidateMacroRefusal::RealizationIncomplete
                                )
                            )));
                        }
                        assert_eq!(
                            selected
                                .admissions
                                .iter()
                                .filter(|answer| matches!(
                                    answer.decision,
                                    CandidateMacroDecision::Admitted { .. }
                                ))
                                .count(),
                            expected_admitted,
                            "admission answers: {:?}",
                            selected
                                .admissions
                                .iter()
                                .map(|answer| &answer.decision)
                                .collect::<Vec<_>>()
                        );
                        if dependency == "log=\"0.4\"" && registry_admitted == 1 {
                            assert!(selected.admissions.iter().any(|answer| matches!(
                                &answer.decision,
                                CandidateMacroDecision::Refused(reason) if format!("{reason:?}").contains("shadow")
                            )), "shadow refusal missing");
                        }
                        for answer in &selected.admissions {
                            assert_ne!(answer.reads.digest().as_bytes(), &[0; 32]);
                        }
                        assert_eq!(
                            selected.side,
                            if expected_admitted == 2 {
                                CandidateProcedureSide::Alternate
                            } else {
                                CandidateProcedureSide::Base
                            }
                        );
                    }
                    if let Some(fresh) = &fresh_signature {
                        assert_eq!(fresh, first.as_ref().expect("fresh selection"));
                    }
                    fresh_signature = first;
                }
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11612: dependent frame entry error retained unpaid prepared syntax"
    )]
    fn prepared_dispatch_frame_entry_error_discards_unpaid_source_and_recovers() {
        // Hard-won: #11595 8f32: frame-entry error skipped the source cleanup
        let fixture = brokk_bifrost_analysis::test_support::AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname=\"frame-cleanup\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                ),
                (
                    "src/lib.rs",
                    "pub struct Concrete;\nimpl Concrete { pub fn run(&self) {} }\npub fn invoke(worker: &Concrete) { worker.run(); }\n",
                ),
            ],
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &ProjectFile::new(fixture.project_root(), "src/lib.rs"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("materialize real Rust fixture")
            .available_value()
            .cloned()
            .expect("Rust artifact");
        let call = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::first_call_in_artifact(&artifact);
        brokk_bifrost_analysis::analyzer::usages::get_definition::assert_prepared_dispatch_recovers_from_frame_entry_error(
            &fixture.analyzer, artifact, &call,
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11479: retained Rust dispatch operation lost its dependent read frame"
    )]
    fn retained_rust_dispatch_operation_keeps_dependent_read_frame() {
        for (impl_source, required_receiver) in [
            (
                "use crate::api::Worker;\npub struct Concrete;\nimpl Worker for Concrete { fn run(&self) {} }\n",
                Some("Concrete"),
            ),
            (
                "use crate::api::Worker;\npub struct Concrete;\nimpl Worker for Concrete { fn run(&self) {} }\nimpl<T> Worker for &T { fn run(&self) {} }\n",
                None,
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname=\"retained-frame\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file(
                    "src/lib.rs",
                    "pub mod api;\npub mod impls;\npub fn invoke(worker: &dyn api::Worker) { worker.run(); }\n",
                )
                .file("src/api.rs", "pub trait Worker { fn run(&self); }\n")
                .file(
                    "src/impls.rs",
                    impl_source,
                )
                .build();
            let filesystem =
                brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root()).unwrap();
            let workspace = brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
                Arc::new(filesystem),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let caller_file = project.file("src/lib.rs");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let materialized = workspace
                .materialize_program_semantics(
                    &caller_file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("materialize caller semantics");
            assert!(
                materialized.is_complete(),
                "materialization: {materialized:?}"
            );
            let artifact = materialized
                .available_value()
                .cloned()
                .expect("caller artifact");
            let caller = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.locator().declaration().last_segment_name() == Some("invoke")
                })
                .expect("invoke procedure");
            assert_eq!(caller.call_sites().len(), 1, "one semantic call site");
            let call = artifact
                .procedure_handle(caller.id())
                .and_then(|procedure| procedure.call_site_handle(caller.call_sites()[0].id))
                .expect("semantic call-site handle");
            let call_range =
                brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(
                    &call,
                )
                .expect("call range comes from the semantic IR anchor");

            let oracle = workspace.semantic_oracle_provider();
            let mut session = oracle.prepare_source_dispatch_session_in_artifact(materialized);
            session.enable_definition_operation_reuse();
            let mut dispatch_budget = SemanticBudget::default();
            let mut request = SemanticRequest::new(&mut dispatch_budget, &cancellation);
            // The nominal impl has bound rows, but the reference blanket impl
            // needs structured header resolution during the hierarchy read. RQL
            // captures failures from that dependent lookup in this receipt.
            let (outcome, receipt) =
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(
                    workspace.analyzer(),
                    || session.resolve_at_source_recorded(call_range, &mut request),
                );
            assert!(
                receipt
                    .incomplete_reasons()
                    .iter()
                    .all(|reason| reason.execution_cause().is_none()),
                "recorded source dispatch read failures: {:?}",
                receipt.incomplete_reasons()
            );
            let outcome =
                outcome.expect("retained Rust definition operation keeps its dependent read frame");
            let quality = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::SourceOutcomeQuality::from_outcome(&outcome);
            let value = match outcome {
                SemanticOutcome::Complete { value, .. } => value,
                // The bodyless trait and generic impl can keep dispatch unproven.
                // The ordinary comparison below must retain that same openness.
                SemanticOutcome::Unproven { partial, .. } => partial,
                other => panic!("retained route became operationally incomplete: {other:?}"),
            };
            assert!(session.has_definition_operation());
            assert_eq!(value.observations().len(), 1);
            let dispatch = value.observations()[0].dispatch();
            if let Some(required_receiver) = required_receiver {
                assert!(
                    dispatch.candidates().iter().any(|candidate| {
                        let locator = candidate.target().semantics().locator();
                        locator.path().as_str() == "src/impls.rs"
                            && locator.declaration().last_segment_name() == Some("run")
                            && locator
                                .declaration()
                                .segments()
                                .iter()
                                .any(|segment| segment.name() == Some(required_receiver))
                    }),
                    "expected the concrete implementation target, got {dispatch:#?}"
                );
            }
            let retained_digest = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::procedure_dispatch_answer_digest(quality, Some(&value));
            drop(session);
            assert!(
                !brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_selected_operation_active(),
                "ordinary comparison starts after the retained operation is released"
            );
            // Compare the full semantic answer, including honest generic-family
            // incompleteness, with an ordinary lookup of the same selected artifact.
            // This runs second so it cannot prewarm the retained defect away.
            let mut ordinary =
                oracle.prepare_source_dispatch_session_in_artifact(SemanticOutcome::Complete {
                    value: Arc::clone(&artifact),
                    work: Default::default(),
                });
            let mut ordinary_budget = SemanticBudget::default();
            let (ordinary_outcome, ordinary_receipt) =
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(
                    workspace.analyzer(),
                    || {
                        ordinary.resolve_at_source_recorded(
                            call_range,
                            &mut SemanticRequest::new(&mut ordinary_budget, &cancellation),
                        )
                    },
                );
            assert!(
                ordinary_receipt
                    .incomplete_reasons()
                    .iter()
                    .all(|reason| reason.execution_cause().is_none()),
                "ordinary source dispatch read failures: {:?}",
                ordinary_receipt.incomplete_reasons()
            );
            let ordinary_outcome = ordinary_outcome.expect("ordinary dispatch comparison");
            assert!(!ordinary.has_definition_operation());
            assert_eq!(
                retained_digest,
                brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::procedure_dispatch_answer_digest(
                    brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::SourceOutcomeQuality::from_outcome(&ordinary_outcome),
                    ordinary_outcome.available_value(),
                ),
                "retained and ordinary dispatch must agree, including semantic incompleteness"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: review: an admitted caller inspected a shadowed callee's refused writes"
    )]
    fn candidate_macro_local_callee_refused_writes_do_not_change_caller_flows() {
        let source = r#"
struct Target { value: u32 }
fn hidden(target: &mut Target, value: u32) {
    mod log { macro_rules! info { ($($t:tt)*) => {} } pub(crate) use info; }
    log::info!("{}", { target.value = value; value });
}
fn emit(target: &mut Target, value: u32) -> u32 {
    log::info!("outer");
    hidden(target, value);
    target.value
}
"#;
        let without_write = source.replace("target.value = value; ", "");
        let mut caller_flows = None;
        for source in [source, without_write.as_str()] {
            let publication = candidate_publication(source);
            let (_, guarded) = publication
                .store
                .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
                .unwrap()
                .1
                .unwrap();
            // The caller is the last guarded procedure in source order.
            let caller = guarded.last().expect("caller alternate").parts.id;
            let reconstructed = Arc::new(artifact_with_guarded_parts(&publication, &guarded));
            let flows = &lazy_alternate_flows(&publication, &reconstructed, caller);
            assert_eq!(flows.outcome, PartialFlowOutcome::Complete);
            if let Some(previous) = &caller_flows {
                assert_eq!(
                    previous, flows,
                    "opaque callee token-tree writes cannot influence caller post-call inference"
                );
            }
            caller_flows = Some(flows.clone());
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: review: capture children inherited the admitted parent's interpretation"
    )]
    fn candidate_macro_local_capture_children_keep_base_identity() {
        use crate::analyzer::semantic::oracle::{OracleCallContext, ValueFlowEndpoint};
        use crate::analyzer::semantic::partial_flow::file_local_procedure_relations;
        let source = r#"fn emit(value: u32) {
            log::info!("outer");
            let child = || { mod log {} log::info!("{}", value); };
            child();
        }"#;
        let publication = candidate_publication(source);
        let (parts, guarded) = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        let artifact = Arc::new(
            SemanticArtifact::try_new_with_candidate_alternates(
                publication.artifact.key().clone(),
                publication.artifact.capabilities().clone(),
                parts,
                guarded
                    .iter()
                    .map(|row| (row.parts.clone(), row.candidates.clone().into_boxed_slice())),
            )
            .unwrap(),
        );
        let mut captures = 0;
        for row in &guarded {
            let parent = artifact.candidate_alternate_handle(row.parts.id).unwrap();
            if parent.semantics().captures().is_empty() {
                continue;
            }
            let mut budget = SemanticBudget::default();
            let live = CancellationToken::default();
            let outcome = file_local_procedure_relations(
                &parent,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &live),
            )
            .unwrap();
            let snapshot = outcome
                .available_value()
                .expect("open projection retains its relations");
            for relation in snapshot.relations() {
                if let ValueFlowEndpoint::Port(port) = &relation.target
                    && port.procedure().id() != parent.id()
                {
                    assert!(!port.procedure().is_candidate_alternate());
                    captures += 1;
                }
            }
        }
        assert!(captures > 0, "fixture must project a capture into a child");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: review: candidate selection turned budget exhaustion into Unknown"
    )]
    fn candidate_macro_conversion_preserves_budget_stop() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"budget\"\nversion=\"0.1.0\"\n[dependencies]\nlog=\"0.4\"\n",
            )
            .file("src/lib.rs", CANDIDATE_SOURCE)
            .build();
        let publication =
            candidate_publication_for_file(CANDIDATE_SOURCE, project.file("src/lib.rs"));
        let (parts, guarded) = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        let id = guarded[0].parts.id;
        let artifact = Arc::new(
            SemanticArtifact::try_new_with_candidate_alternates(
                publication.artifact.key().clone(),
                publication.artifact.capabilities().clone(),
                parts,
                guarded
                    .iter()
                    .map(|row| (row.parts.clone(), row.candidates.clone().into_boxed_slice())),
            )
            .unwrap(),
        );
        let base = artifact.procedure_handle(id).unwrap();
        let call = base
            .call_site_handle(base.semantics().call_sites()[0].id)
            .unwrap();
        let filesystem =
            brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace = brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(filesystem),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let oracle = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle::new(&workspace);
        let live = CancellationToken::default();
        let dispatch = SemanticOutcome::Complete {
            value: crate::analyzer::semantic::DispatchResult::new(
                &call,
                vec![],
                vec![],
                crate::analyzer::semantic::CandidateCoverage::Open,
                OracleLimits::default(),
            )
            .unwrap(),
            work: SemanticWork::default(),
        };
        let mut limits = SemanticBudget::default().limits();
        limits.nested_entries = 1;
        let mut tight = SemanticBudget::new(limits).unwrap();
        let stopped = oracle
            .call_conversion_may_run_user_code(
                &call,
                &dispatch,
                &mut SemanticRequest::new(&mut tight, &live),
            )
            .unwrap();
        assert!(
            matches!(stopped, SemanticOutcome::ExceededBudget { .. }),
            "{stopped:?}"
        );
        assert_eq!(stopped.work(), tight.used());
        let mut budget = SemanticBudget::default();
        let complete = oracle
            .call_conversion_may_run_user_code(
                &call,
                &dispatch,
                &mut SemanticRequest::new(&mut budget, &live),
            )
            .unwrap();
        assert!(
            matches!(complete, SemanticOutcome::Complete { .. }),
            "{complete:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: review: renewed refusal returned the retained alternate as Base"
    )]
    fn candidate_macro_retained_alternate_returns_true_base_after_manifest_change() {
        use brokk_bifrost_analysis::analyzer::semantic::service::{
            CandidateProcedureOutcome, CandidateProcedureSide,
        };
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"retained\"\nversion=\"0.1.0\"\n",
            )
            .file("src/lib.rs", CANDIDATE_SOURCE)
            .build();
        let file = project.file("src/lib.rs");
        let publication = candidate_publication_for_file(CANDIDATE_SOURCE, file.clone());
        let (parts, guarded) = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        let id = guarded[0].parts.id;
        let artifact = Arc::new(
            SemanticArtifact::try_new_with_candidate_alternates(
                publication.artifact.key().clone(),
                publication.artifact.capabilities().clone(),
                parts,
                guarded
                    .iter()
                    .map(|row| (row.parts.clone(), row.candidates.clone().into_boxed_slice())),
            )
            .unwrap(),
        );
        let base = artifact.procedure_handle(id).unwrap();
        let mut retained = None;
        let mut incremental_workspace = None;
        for dependency in ["log=\"0.4\"", "log={package=\"not-log\",version=\"0.4\"}"] {
            std::fs::write(project.root().join("Cargo.toml"), format!(
                "[package]\nname=\"retained\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\n{dependency}\n"
            )).unwrap();
            let build_workspace = || {
                let filesystem =
                    brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root())
                        .unwrap();
                brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
                    Arc::new(filesystem),
                    AnalyzerConfig::default(),
                )
                .unwrap()
            };
            let workspace = incremental_workspace.get_or_insert_with(build_workspace);
            if retained.is_some() {
                *workspace = workspace.update(&std::collections::BTreeSet::from([
                    project.file("Cargo.toml")
                ]));
            }
            let live = CancellationToken::default();
            let select = |handle: &crate::analyzer::semantic::ProcedureHandle| {
                let mut budget = SemanticBudget::default();
                let outcome = workspace
                    .selected_procedure_handle(
                        handle,
                        &mut SemanticRequest::new(&mut budget, &live),
                    )
                    .unwrap();
                outcome.available_value().unwrap().clone()
            };
            let pair = |handle: &crate::analyzer::semantic::ProcedureHandle| {
                let mut budget = SemanticBudget::default();
                let CandidateProcedureOutcome::Selected(selected) = workspace
                    .selected_procedure_and_flows(
                        handle,
                        &mut SemanticRequest::new(&mut budget, &live),
                    )
                    .unwrap()
                else {
                    panic!("selection stopped")
                };
                selected
            };
            if let Some(retained) = &retained {
                let crate::analyzer::semantic::service::SelectedProcedureHandle {
                    handle: selected,
                    side,
                    ..
                } = select(retained);
                assert_eq!(side, CandidateProcedureSide::Base);
                assert!(!selected.is_candidate_alternate());
                assert!(
                    selected
                        .semantics()
                        .call_sites()
                        .iter()
                        .all(|call| call.arguments.is_empty())
                );
                assert!(
                    selected
                        .validate_durable_locator(&retained.durable_key())
                        .is_err()
                );
                let selected_pair = pair(retained);
                let fresh_workspace = build_workspace();
                let mut fresh_budget = SemanticBudget::default();
                let CandidateProcedureOutcome::Selected(fresh_pair) = fresh_workspace
                    .selected_procedure_and_flows(
                        &base,
                        &mut SemanticRequest::new(&mut fresh_budget, &live),
                    )
                    .unwrap()
                else {
                    panic!("fresh selection stopped")
                };
                assert_eq!(selected_pair.side, CandidateProcedureSide::Base);
                assert!(!selected_pair.procedure.is_candidate_alternate());
                assert_eq!(selected_pair.flows, fresh_pair.flows);
                assert_eq!(selected.durable_key(), select(&base).handle.durable_key());
                assert!(Arc::ptr_eq(selected.artifact(), retained.artifact()));
            } else {
                let crate::analyzer::semantic::service::SelectedProcedureHandle {
                    handle: selected,
                    side,
                    ..
                } = select(&base);
                assert_eq!(side, CandidateProcedureSide::Alternate);
                assert!(selected.is_candidate_alternate());
                assert_eq!(pair(&selected).side, CandidateProcedureSide::Alternate);
                retained = Some(selected);
            }
        }
    }

    #[test]
    fn candidate_macro_owner_selects_whole_procedure_and_stops_atomically() {
        use crate::analyzer::semantic::{SemanticEffect, StoredCandidateMacroArtifact};
        use brokk_bifrost_semantic::analyzer::semantic::service::{
            CandidateProcedureOutcome, CandidateProcedureSelection, CandidateProcedureSide,
            select_candidate_procedure,
        };
        let source = format!(
            "struct Target {{ value: u32 }}\n{}",
            CANDIDATE_SOURCE
                .replace("mut target: u32", "target: &mut Target")
                .replace("target = value", "target.value = value")
        );
        let publication = candidate_publication(&source);
        let decoded = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap();
        let (base_parts, guarded) = decoded;
        let artifact = Arc::new(
            SemanticArtifact::try_new_with_candidate_alternates(
                publication.artifact.key().clone(),
                publication.artifact.capabilities().clone(),
                base_parts,
                guarded
                    .iter()
                    .map(|row| (row.parts.clone(), row.candidates.clone().into_boxed_slice())),
            )
            .unwrap(),
        );
        let id = guarded[0].parts.id;
        let prepared = StoredCandidateMacroArtifact {
            artifact: artifact.clone(),
        };
        let base = artifact.procedure_handle(id).unwrap();
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-10972-candidate-publication"),
            PathBuf::from("lib.rs"),
        );
        let syntax = prepare(&file, &Arc::from(source));
        let live = CancellationToken::default();
        let base_flows = parse_time_partial_flows(&artifact, &syntax, &live).unwrap();
        let expected_base = &base_flows[id.index()];
        let expected_alternate = &publication
            .candidate_flows
            .iter()
            .find(|flows| flows.procedure.id() == id)
            .expect("eager alternate flows")
            .partial;
        let solve = |alternate: &crate::analyzer::semantic::ProcedureHandle| {
            crate::analyzer::semantic::partial_flow::fixpoint::candidate_alternate_partial_flows(
                alternate, &syntax, &live,
            )
        };
        for admitted in [vec![true, true], vec![false, false], vec![true, false]] {
            let mut budget = SemanticBudget::default();
            let outcome = select_candidate_procedure(
                &prepared,
                &base,
                Some(expected_base),
                solve,
                |_, ids| {
                    assert_eq!(ids.len(), admitted.len());
                    if admitted.iter().all(|answer| *answer) {
                        CandidateProcedureSelection::Alternate(admitted)
                    } else {
                        CandidateProcedureSelection::Base(admitted)
                    }
                },
                &mut SemanticRequest::new(&mut budget, &live),
            )
            .unwrap();
            let CandidateProcedureOutcome::Selected(selected) = outcome else {
                panic!("selection stopped");
            };
            let alternate = selected.admissions.iter().all(|answer| *answer);
            assert_eq!(
                selected.side,
                if alternate {
                    CandidateProcedureSide::Alternate
                } else {
                    CandidateProcedureSide::Base
                }
            );
            if alternate {
                assert!(
                    selected.procedure.semantics().call_sites().len()
                        > base.semantics().call_sites().len()
                );
                assert!(
                    selected
                        .procedure
                        .semantics()
                        .points()
                        .iter()
                        .flat_map(|point| &point.events)
                        .any(|event| matches!(event.effect, SemanticEffect::Assignment { .. }))
                );
                assert_eq!(selected.flows, *expected_alternate);
                assert!(selected.flows.ports.len() > expected_base.ports.len());
                assert!(selected.flows.ports.iter().any(|port| matches!(
                    port,
                    crate::analyzer::semantic::partial_flow::PartialFlowPort::Heap { .. }
                )));
                assert!(selected.flows.ports.iter().any(|port| matches!(
                    port,
                    crate::analyzer::semantic::partial_flow::PartialFlowPort::CallResult { .. }
                )));
            } else {
                assert_eq!(selected.procedure, base);
                assert_eq!(selected.flows, *expected_base);
                assert!(
                    selected
                        .procedure
                        .semantics()
                        .call_sites()
                        .iter()
                        .all(|call| call.arguments.is_empty())
                );
            }
        }
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut budget = SemanticBudget::default();
        assert!(matches!(
            select_candidate_procedure(
                &prepared,
                &base,
                None,
                solve,
                |_, _| CandidateProcedureSelection::Alternate(()),
                &mut SemanticRequest::new(&mut budget, &cancelled)
            )
            .unwrap(),
            CandidateProcedureOutcome::Cancelled
        ));
        let mut tiny = SemanticBudget::uniform(1).unwrap();
        assert!(matches!(
            select_candidate_procedure(
                &prepared,
                &base,
                None,
                solve,
                |_, _| CandidateProcedureSelection::Alternate(()),
                &mut SemanticRequest::new(&mut tiny, &live)
            )
            .unwrap(),
            CandidateProcedureOutcome::ExceededBudget(_)
        ));
        // Missing matching flow rows use the same common fixpoint and caller budget.
        let mut budget = SemanticBudget::default();
        let CandidateProcedureOutcome::Selected(recomputed) = select_candidate_procedure(
            &prepared,
            &base,
            None,
            solve,
            |_, _| CandidateProcedureSelection::Base(()),
            &mut SemanticRequest::new(&mut budget, &live),
        )
        .unwrap() else {
            panic!("fallback stopped");
        };
        assert_eq!(recomputed.flows, *expected_base);

        let during_admission = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        assert!(matches!(
            select_candidate_procedure(
                &prepared,
                &base,
                Some(expected_base),
                solve,
                |_, _| {
                    during_admission.cancel();
                    CandidateProcedureSelection::Alternate(())
                },
                &mut SemanticRequest::new(&mut budget, &during_admission)
            )
            .unwrap(),
            CandidateProcedureOutcome::Cancelled
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972: guarded reconstruction must reject corrupt parts before freezing"
    )]
    fn candidate_macro_publication_guarded_round_trip_and_work_charge() {
        let publication = candidate_publication(CANDIDATE_SOURCE);
        let base = publication
            .store
            .read_semantic_ir(publication.blob_id, &publication.scope)
            .unwrap();
        assert_eq!(base.len(), publication.artifact.procedures().len());
        let decoded_base = SemanticArtifact::try_new(
            publication.artifact.key().clone(),
            publication.artifact.capabilities().clone(),
            base,
        )
        .expect("ordinary decoder returns the base artifact");
        assert_ne!(
            decoded_base.materialization_id(),
            publication.artifact.materialization_id(),
            "the decoded base omits the guarded alternate contents"
        );
        assert!(decoded_base.procedures().iter().all(|procedure| {
            procedure
                .candidate_macro_alternate_materialization_id()
                .is_none()
        }));
        let tiny = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(1);
        let transient = || {
            let mut arena = SemanticArtifact::try_new(
                publication.artifact.key().clone(),
                publication.artifact.capabilities().clone(),
                publication
                    .store
                    .read_semantic_ir(publication.blob_id, &publication.scope)
                    .unwrap(),
            )
            .unwrap();
            arena.charge_guarded_arena(&tiny);
            Arc::new(arena)
        };
        let first = decoded_base.canonical_candidate_arena(transient());
        let weak = Arc::downgrade(&first);
        let second = decoded_base.canonical_candidate_arena(transient());
        assert!(
            Arc::ptr_eq(&first, &second),
            "uncharged live arena is canonical"
        );
        drop((first, second));
        assert!(weak.upgrade().is_none(), "base cannot pin uncharged arena");
        assert_eq!(tiny.accounted_bytes(), 0);
        let guarded = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap()
            .1;
        let mut attach_budget = SemanticBudget::default();
        let reconstructed = SemanticArtifact::try_new_with_candidate_alternates_and_budget(
            publication.artifact.key().clone(),
            publication.artifact.capabilities().clone(),
            publication
                .store
                .read_semantic_ir(publication.blob_id, &publication.scope)
                .unwrap(),
            guarded.iter().map(|decoded| {
                (
                    decoded.parts.clone(),
                    decoded.candidates.clone().into_boxed_slice(),
                )
            }),
            &mut attach_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .expect("decoded alternates validate in their base artifact context");
        assert_eq!(attach_budget.used(), reconstructed.work());
        let reconstructed = Arc::new(reconstructed);
        let mut refused_budget = SemanticBudget::uniform(1).unwrap();
        let before = refused_budget.used();
        let refused = SemanticArtifact::try_new_with_candidate_alternates_and_budget(
            publication.artifact.key().clone(),
            publication.artifact.capabilities().clone(),
            publication
                .store
                .read_semantic_ir(publication.blob_id, &publication.scope)
                .unwrap(),
            guarded.iter().map(|decoded| {
                (
                    decoded.parts.clone(),
                    decoded.candidates.clone().into_boxed_slice(),
                )
            }),
            &mut refused_budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .expect_err("guarded attach must respect the caller's row limit");
        assert!(refused.budget_exceeded().is_some());
        assert_eq!(refused_budget.used(), before);
        assert_eq!(guarded.len(), publication.candidate_flows.len());
        for (decoded, expected) in guarded.iter().zip(&publication.candidate_flows) {
            let (alternate, candidate_ids) = publication
                .artifact
                .procedure(expected.procedure.id())
                .unwrap()
                .candidate_macro_alternate()
                .expect("candidate procedure has a full alternate");
            assert_eq!(&decoded.candidates, candidate_ids);
            // Flows solved on demand over the decoded alternate equal the
            // flows an eager solve of the lowered artifact returns (#10379).
            let lazy = lazy_alternate_flows(&publication, &reconstructed, decoded.parts.id);
            assert_eq!(&lazy, &expected.partial);
            assert_eq!(
                reconstructed
                    .procedure(decoded.parts.id)
                    .unwrap()
                    .candidate_macro_alternate_materialization_id()
                    .unwrap(),
                alternate.parts_materialization_id()
            );
            assert_eq!(crate::analyzer::semantic::partial_flow::fixpoint::CandidateMacroPartialFlows::materialization_id_for(reconstructed.procedure(decoded.parts.id).unwrap().candidate_macro_alternate_materialization_id().unwrap(), decoded.parts.id, &lazy), expected.materialization_id());
            assert_eq!(
                publication
                    .artifact
                    .procedure(expected.procedure.id())
                    .unwrap()
                    .candidate_macro_alternate_materialization_id(),
                Some(
                    reconstructed
                        .procedure(decoded.parts.id)
                        .unwrap()
                        .candidate_macro_alternate_materialization_id()
                        .unwrap()
                )
            );
        }
        let rebuild = |alternates: Vec<(
            crate::analyzer::semantic::ProcedureSemanticsParts,
            Box<[crate::analyzer::semantic::CandidateRecord]>,
        )>| {
            SemanticArtifact::try_new_with_candidate_alternates(
                publication.artifact.key().clone(),
                publication.artifact.capabilities().clone(),
                publication
                    .store
                    .read_semantic_ir(publication.blob_id, &publication.scope)
                    .unwrap(),
                alternates,
            )
        };
        let first = &guarded[0];
        let pair = || {
            (
                first.parts.clone(),
                first.candidates.clone().into_boxed_slice(),
            )
        };
        assert!(
            rebuild(vec![pair(), pair()]).is_err(),
            "duplicate alternate must be rejected"
        );
        let (mut unknown, ids) = pair();
        unknown.id = crate::analyzer::semantic::ProcedureId::new(u32::MAX);
        assert!(
            rebuild(vec![(unknown, ids)]).is_err(),
            "unknown alternate must be rejected"
        );
        let (mut invalid, ids) = pair();
        for point in &mut invalid.points {
            point.events = Box::new([]);
        }
        assert!(
            rebuild(vec![(invalid, ids)]).is_err(),
            "corrupt semantic parts must return an error before freezing"
        );
        {
            let conn = publication.store.conn.lock().unwrap();
            conn.execute(
                "UPDATE semantic_ir_publications SET row_digest = zeroblob(32) WHERE blob_id = ?1",
                [publication.blob_id],
            )
            .unwrap();
        }
        let corrupted = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope);
        assert!(
            matches!(corrupted, Err(error) if error.kind == crate::analyzer::store::StoreErrorKind::Corrupt)
        );
        assert_eq!(guarded.len(), publication.candidate_flows.len());
    }

    #[test]
    fn candidate_macro_decoded_alternate_work_is_charged_to_total() {
        let publication = candidate_publication(CANDIDATE_SOURCE);
        let guarded = publication
            .store
            .semantic_ir_candidate_macro_alternate(&publication.key, &publication.scope)
            .unwrap()
            .1
            .unwrap()
            .1;
        let reconstructed = artifact_with_guarded_parts(&publication, &guarded);
        let guarded_charge = reconstructed
            .work()
            .saturating_sub(publication.artifact.base_work());
        assert_eq!(
            publication.artifact.work(),
            publication
                .artifact
                .base_work()
                .conservative_add(guarded_charge)
        );
    }

    #[test]
    fn candidate_macro_alternate_identity_tracks_only_candidate_content() {
        let original = candidate_publication(CANDIDATE_SOURCE);
        let operand = "sink(log::debug!(\"nested={value}\", { target = value; value }))";
        let replacement = format!("1234{}", " ".repeat(operand.len() - 4));
        let changed_source = CANDIDATE_SOURCE.replace(operand, &replacement);
        assert_ne!(
            changed_source, CANDIDATE_SOURCE,
            "the fixture mutation is real"
        );
        let changed = candidate_publication(&changed_source);
        let original_base = original
            .store
            .read_semantic_ir(original.blob_id, &original.scope)
            .unwrap();
        let changed_base = changed
            .store
            .read_semantic_ir(changed.blob_id, &changed.scope)
            .unwrap();
        let mut changed_fields = Vec::new();
        macro_rules! compare_field {
            ($field:ident) => {
                if format!("{:?}", original_base[1].$field)
                    != format!("{:?}", changed_base[1].$field)
                {
                    changed_fields.push(stringify!($field));
                }
            };
        }
        compare_field!(declared_result_classes);
        compare_field!(id);
        compare_field!(locator);
        compare_field!(source_range_holes);
        compare_field!(lexical_parent);
        compare_field!(kind);
        compare_field!(properties);
        compare_field!(footprint_coverage);
        compare_field!(call_control_coverage);
        compare_field!(source);
        compare_field!(evidence);
        compare_field!(values);
        compare_field!(allocations);
        compare_field!(memory_locations);
        compare_field!(captures);
        compare_field!(call_sites);
        compare_field!(source_mappings);
        compare_field!(statement_entries);
        compare_field!(loop_sites);
        compare_field!(evidence_rows);
        compare_field!(gaps);
        compare_field!(blocks);
        compare_field!(points);
        compare_field!(control_edges);
        compare_field!(guard_facts);
        compare_field!(switch_facts);
        compare_field!(drops);
        compare_field!(move_outs);
        compare_field!(scope_ends);
        compare_field!(pointer_origins);
        compare_field!(pointer_aliases);
        compare_field!(pointer_accesses);
        compare_field!(pointer_invalidations);
        compare_field!(incomplete_facts);
        compare_field!(receiver_type_facts);
        compare_field!(guarded_pattern_projections);
        assert_eq!(
            original.artifact.procedures()[1].parts_materialization_id(),
            changed.artifact.procedures()[1].parts_materialization_id(),
            "the refused base should be stable; differing fields: {changed_fields:?}"
        );
        let original =
            original.artifact.procedures()[1].candidate_macro_alternate_materialization_id();
        let changed =
            changed.artifact.procedures()[1].candidate_macro_alternate_materialization_id();
        assert_ne!(original, changed);
    }

    #[test]
    fn candidate_macro_rows_cascade_on_blob_gc() {
        #[expect(
            clippy::disallowed_methods,
            reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
        )]
        fn guarded_counts(store: &AnalyzerStore) -> Vec<(String, i64)> {
            let conn = store.read_conn().unwrap();
            let tables = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'candidate_macro_%' ORDER BY name")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            tables
                .into_iter()
                .map(|table| {
                    let count = conn
                        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    (table, count)
                })
                .collect()
        }
        let collected = candidate_publication(CANDIDATE_SOURCE);
        let before_gc = guarded_counts(&collected.store);
        assert!(before_gc.iter().any(|(_, count)| *count > 0));
        assert_eq!(
            brokk_bifrost_analysis::analyzer::store::collect_ephemeral_candidates_for_test(
                &collected.store,
                |_| false
            )
            .unwrap(),
            1
        );
        let after_gc = guarded_counts(&collected.store);
        assert_eq!(before_gc.len(), after_gc.len());
        assert!(
            after_gc.iter().all(|(_, count)| *count == 0),
            "{after_gc:?}"
        );
    }
}
