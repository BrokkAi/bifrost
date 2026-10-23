use crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;

use crate::analyzer::store::resolution_operation::*;

use crate::analyzer::store::AnalyzerStore;

use crate::analyzer::store::Result;

use crate::analyzer::store::WorkspaceFileRow;

use crate::analyzer::store::WorkspaceId;

use crate::analyzer::store::WorkspaceSnapshots;

use crate::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;

use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use crate::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

use crate::CancellationToken;

use crate::analyzer::Language;

use crate::analyzer::Project;

use crate::analyzer::ProjectFile;

use crate::analyzer::TestProject;

use crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog;

use crate::analyzer::resolution::LoweredSemanticRole;

use crate::analyzer::resolution::SelectedSemanticLocator;

use crate::analyzer::store::file_state::FileState;

use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

use crate::analyzer::tree_sitter_analyzer::ParsedFile;

use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent;

use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

use git2::Oid;

use std::collections::BTreeSet;

use std::path::Path;

use std::sync::Arc;

use std::sync::Mutex;

use std::sync::atomic::AtomicU64;

use std::sync::atomic::Ordering;

use tree_sitter::Parser;

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
#[doc(hidden)]
pub fn counterfactual_content_mount(
    content: SelectedResolutionContentMountRequest,
    original: &str,
) -> SelectedResolutionContentMountRequest {
    content.with_counterfactual_base_content_digest(
        brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes()),
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

    #[expect(
        dead_code,
        reason = "Retained with the shared generation fixture during the crate move."
    )]
    pub(super) fn generation_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }

    #[expect(
        dead_code,
        reason = "Retained with the shared generation fixture during the crate move."
    )]
    pub(super) fn advance(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    #[doc(hidden)]
    pub fn set_overlay_content(&self, file: ProjectFile, content: &str) {
        let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(content.as_bytes());
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
pub(super) fn try_site_for_identifier(
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
