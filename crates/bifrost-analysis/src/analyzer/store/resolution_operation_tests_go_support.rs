#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_11 {
    use crate::CancellationToken;

    use crate::analyzer::resolution::{
        LoweredResolutionFactsWithIdentityCatalog, LoweredSemanticRole, SelectedSemanticLocator,
    };

    use crate::analyzer::store::file_state::FileState;
    use crate::analyzer::store::resolution_operation::*;
    use crate::analyzer::store::resolution_selection::{
        SelectedResolutionContentMountRequest, SelectedResolutionLanguage,
        SelectedResolutionOverlayMask,
    };
    use crate::analyzer::store::{
        AnalyzerStore, GenerationId, Result, WorkspaceFileRow, WorkspaceId, WorkspaceSnapshotId,
        WorkspaceSnapshots,
    };
    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
    use crate::analyzer::tree_sitter_analyzer::ParsedFile;
    use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use crate::analyzer::{Language, Project, ProjectFile, TestProject};
    use brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionIdentifierRole, ResolutionNamespace, ResolutionSiteId,
    };

    use brokk_bifrost_rust::selected_context::{RustCallerTargetKind, RustCallerTargetProfile};

    use git2::Oid;
    use rusqlite::params;

    use std::collections::BTreeSet;
    use std::path::Path;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use tree_sitter::Parser;
    #[doc(hidden)]
    pub fn persist_test_workspace_snapshot(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        language: &str,
        generation: GenerationId,
        file_versions: Vec<(String, String, String)>,
    ) -> WorkspaceSnapshots {
        let writer_workspace_id = workspace_id.as_str().to_owned();
        let writer_language = language.to_owned();
        let generation_value = generation.get();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, ?2, ?3, 1)",
                params![writer_workspace_id, writer_language, generation_value],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
             VALUES(?1, ?2, ?3, 1)",
                params![writer_workspace_id, writer_language, generation_value],
            )
            .unwrap();
            for (path, blob_oid, projection_digest) in file_versions {
                tx.execute(
                    "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)",
                    params![
                        writer_workspace_id,
                        writer_language,
                        generation_value,
                        path,
                        blob_oid,
                        projection_digest,
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        });

        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            language.to_owned(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: language.to_owned(),
                generation,
                revision: 1,
            },
        );
        snapshots
    }
    #[doc(hidden)]
    pub fn selected_operation_input<'project, 'selection>(
        project: &'project dyn Project,
        workspace_id: &'selection WorkspaceId,
        snapshots: &'selection WorkspaceSnapshots,
        languages: &'selection [SelectedResolutionLanguage],
        overlay_masks: &'selection [SelectedResolutionOverlayMask],
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
    ) -> SelectedResolutionOperationInput<'project, 'selection> {
        SelectedResolutionOperationInput::new(
            project,
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
        )
        .with_content_mounts(content_mounts)
    }
    #[doc(hidden)]
    pub fn open_ready_operation<'store, 'project, 'selection>(
        store: &'store AnalyzerStore,
        input: SelectedResolutionOperationInput<'project, 'selection>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'store, 'project> {
        match store
            .open_selected_resolution_operation(input, cancellation)
            .expect("open selected resolution test operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            outcome => panic!("selected resolution test operation must be Ready: {outcome:?}"),
        }
    }
    #[doc(hidden)]
    pub fn content_mount_request(
        publication: crate::analyzer::store::resolution_publication::ResolutionContentWitness,
        path: &str,
        blob_oid: Oid,
    ) -> SelectedResolutionContentMountRequest {
        SelectedResolutionContentMountRequest::new(
            publication,
            WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
    #[derive(Clone)]
    #[doc(hidden)]
    pub struct MutableGenerationProject {
        delegate: TestProject,
        generation: Arc<AtomicU64>,
        overlay_content: Arc<Mutex<Option<Arc<WorkspaceOverlayContent>>>>,
    }
    impl MutableGenerationProject {
        #[doc(hidden)]
        pub fn new(root: &Path, language: Language) -> Self {
            Self {
                delegate: TestProject::new(root, language),
                generation: Arc::new(AtomicU64::new(0)),
                overlay_content: Arc::new(Mutex::new(None)),
            }
        }

        pub(crate) fn generation_handle(&self) -> Arc<AtomicU64> {
            Arc::clone(&self.generation)
        }

        pub(crate) fn advance(&self) {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }

        #[doc(hidden)]
        pub fn set_overlay_content(&self, file: ProjectFile, content: &str) {
            let digest =
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(content.as_bytes());
            let overlay = Arc::new(WorkspaceOverlayContent::new([(file, digest)]));
            *self
                .overlay_content
                .lock()
                .expect("operation test overlay lock") = Some(overlay);
        }
    }
    impl Project for MutableGenerationProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn analysis_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
            self.overlay_content
                .lock()
                .expect("operation test overlay lock")
                .clone()
        }
    }
    #[doc(hidden)]
    pub fn parsed_operation_state<A: LanguageAdapter>(
        project_root: &Path,
        relative_path: &str,
        source: &str,
        adapter: &A,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
        file.write(source).expect("write operation source");
        parsed_operation_source_state(project_root, relative_path, source, adapter)
    }
    /// Parse unsaved content without replacing the selected disk baseline.
    #[doc(hidden)]
    pub fn parsed_operation_source_state<A: LanguageAdapter>(
        project_root: &Path,
        relative_path: &str,
        source: &str,
        adapter: &A,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
        let source = source.to_owned();
        let mut parser = Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .expect("set Go grammar");
        let tree = parser
            .parse(&source, None)
            .expect("parse Go operation source");
        let mut parsed: ParsedFile = adapter.parse_file(&file, &source, &tree);
        parsed.add_file_scope(&file, &source);
        let contains_tests = adapter.contains_tests(&file, &source, &tree, &parsed);
        let state = Arc::new(TreeSitterAnalyzer::<A>::file_state_from_parsed(
            source,
            parsed,
            contains_tests,
            Some(Vec::new()),
            true,
        ));
        let facts = state.resolution_facts.clone();
        (state, facts)
    }
    #[doc(hidden)]
    pub fn site_for_identifier(
        facts: &FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        try_site_for_identifier(facts, spelling, role, namespace)
            .unwrap_or_else(|| panic!("fixture identifier {role:?} {namespace:?} {spelling:?}"))
    }
    pub(crate) fn try_site_for_identifier(
        facts: &FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> Option<ResolutionSiteId> {
        facts
            .identifiers_named(spelling, role, namespace)
            .into_iter()
            .next()
            .map(|identifier| identifier.site)
    }
    #[doc(hidden)]
    pub fn locator(
        path: &str,
        site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> SelectedSemanticLocator {
        SelectedSemanticLocator::new("java", path, site, role)
    }
    #[doc(hidden)]
    pub fn semantic_at(
        artifact: &LoweredResolutionFactsWithIdentityCatalog,
        site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> crate::analyzer::resolution::SemanticId {
        crate::analyzer::resolution::test_support::lowered_semantic_at(
            artifact.lexical().semantics(),
            site,
            role,
        )
    }
    /// The mount coverage lookup a test operation's context set is built against.
    #[doc(hidden)]
    pub fn mount_lookup(
        mounts: &[SelectedResolutionOperationMount],
    ) -> impl Fn(BindingFragmentId) -> Result<Option<(SelectedResolutionMountOrdinal, Language)>> + '_
    {
        |fragment| {
            Ok(mounts
                .iter()
                .find(|mount| mount.fragment() == fragment)
                .map(|mount| (mount.ordinal(), mount.semantic_language())))
        }
    }
    #[doc(hidden)]
    pub fn assert_store_error_contains<T>(result: Result<T>, needle: &str) {
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected store error containing {needle:?}"),
        };
        assert!(
            error.to_string().contains(needle),
            "unexpected store error: {error}"
        );
    }
    #[doc(hidden)]
    pub fn with_operation_lexical<T>(
        operation: &SelectedResolutionOperation<'_, '_>,
        inspect: impl FnOnce(
            &SelectedResolutionLexicalSource<'_, '_>,
            &SelectedResolutionLexicalSource<'_, '_>,
        ) -> T,
    ) -> T {
        let source = operation.ready.lexical_source();
        inspect(&source, &source)
    }
    impl SelectedResolutionOperation<'_, '_> {
        #[doc(hidden)]
        pub fn rust_test_crate_context(
            &self,
            profile: RustCallerTargetProfile,
            cancellation: &CancellationToken,
        ) -> Result<SelectedRustFileContextOutcome> {
            let root = if profile.target_kind == RustCallerTargetKind::Detached {
                profile.target_root.clone()
            } else {
                profile
                    .manifest_path
                    .parent()
                    .expect("manifest directory")
                    .join(&profile.target_root)
            };
            self.rust_context_for_file(&root, cancellation)
        }
    }
    #[doc(hidden)]
    pub fn assert_empty_context_metrics(metrics: &SelectedResolutionContextMetrics) {
        assert_eq!(metrics, &SelectedResolutionContextMetrics);
    }
}
