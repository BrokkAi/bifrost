//! A [`CSharpSource`] view scoped to one reference file's compilation
//! membership.
//!
//! The C# usage resolver resolves references from one file at a time. Every
//! declaration it considers must be one that file's compilation can see: a
//! physical declaration that shares a fully qualified name with a visible one
//! is not the same identity when membership proves the reference cannot see
//! it. [`MembershipScopedSource`] wraps the analyzer source and applies that
//! rule to every candidate the resolver can obtain through it.
//!
//! The answer is three-valued, as [`CSharpCompilationVisibility`] is:
//!
//! - `Visible` keeps the declaration and adds no doubt.
//! - `NotVisible` drops it.
//! - `Unresolved`, or a failed membership read (`None`), keeps the declaration
//!   and counts it as doubt. An answer reached through doubt is not proven.
//!
//! A declaration whose source root differs from the reference's root is
//! outside the workspace and passes unchanged, with no doubt.

use brokk_bifrost_core::analyzer::memo_attribution::CaptureScopedMemo;

use brokk_bifrost_core::CancellationToken;
use brokk_bifrost_core::analyzer::capabilities::{
    AdditionalFileDependencies, DescendantIndexScope, FileDependencyFacts, ImportAnalysisProvider,
    ImportGraphBindingSurface, ImportGraphInputDigests, ImportReachability,
    ImportResolutionDependencies, ImportedFileEdgeFacts, ImportedFileEdgeTargets,
    TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, Language, ParseCompleteness, SignatureMetadata, SummaryFileProjection,
};
use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile, Range,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::graph_support::{CSharpCompilationVisibility, CSharpSource, identity_visibility};

/// A [`CSharpSource`] view for resolving references in one file. Every
/// candidate declaration it returns is filtered by the reference file's
/// compilation membership: a provably invisible declaration is dropped, a
/// declaration of unproven membership is kept and counted as doubt, and a
/// declaration outside the workspace (a different [`ProjectFile`] root) or a
/// visible one passes unchanged.
pub struct MembershipScopedSource<'a> {
    inner: &'a dyn CSharpSource,
    read_capability: brokk_bifrost_core::analyzer::project_reads::ReadCapability,
    reference: ProjectFile,
    /// Request-lifetime membership answers by declaring file.
    ///
    /// A `Mutex` rather than the request-local `RefCell` the analysis-side
    /// definition provider uses: this wrapper implements [`CSharpSource`],
    /// whose [`CodeUnitIndex`] supertrait requires `Send + Sync`.
    answers: Arc<CaptureScopedMemo<Mutex<VisibilityAnswers<ProjectFile>>>>,
    /// Request-lifetime visibility of type identities by fully qualified
    /// name: whether any physical part of the type is visible.
    type_identities: Arc<CaptureScopedMemo<Mutex<VisibilityAnswers<String>>>>,
    /// Request-lifetime direct ancestors derived through this view, with
    /// whether the derivation admitted doubt.
    direct_ancestors: Arc<CaptureScopedMemo<Mutex<HashMap<CodeUnit, DoubtedAncestors>>>>,
    /// Declarations admitted although their membership is unproven. An
    /// `AtomicUsize` for the same `Sync` reason as `answers`.
    doubt: Arc<AtomicUsize>,
    /// Query-owned filtered type lists shared by the source accessors.
    static_types: CaptureScopedMemo<OnceLock<std::sync::Arc<Vec<CodeUnit>>>>,
    usage_static_types: CaptureScopedMemo<OnceLock<std::sync::Arc<Vec<CodeUnit>>>>,
}

/// Direct ancestors and whether deriving them admitted doubt.
type DoubtedAncestors = (Vec<CodeUnit>, bool);

type VisibilityAnswers<K> = HashMap<K, Option<CSharpCompilationVisibility>>;

impl<'a> MembershipScopedSource<'a> {
    pub fn new(inner: &'a dyn CSharpSource, reference: &ProjectFile) -> Self {
        let read_capability = inner.read_capability();
        Self {
            inner,
            read_capability,
            reference: reference.clone(),
            answers: Arc::default(),
            type_identities: Arc::default(),
            direct_ancestors: Arc::default(),
            doubt: Arc::default(),
            static_types: CaptureScopedMemo::default(),
            usage_static_types: CaptureScopedMemo::default(),
        }
    }

    /// The analyzer source this view filters, for questions about every
    /// physical declaration of an identity rather than the visible ones.
    pub fn unscoped(&self) -> &dyn CSharpSource {
        self.inner
    }

    /// Number of unproven-membership declarations (and failed membership reads)
    /// admitted so far.
    pub fn doubt(&self) -> usize {
        self.doubt.load(Ordering::Relaxed)
    }

    /// Record doubt carried by a cached derivation.
    pub fn add_doubt(&self) {
        self.doubt.fetch_add(1, Ordering::Relaxed);
    }

    /// Run `derive` and report whether it admitted doubt, so a cache of its
    /// answer can carry the doubt to every later use.
    pub fn measured<T>(&self, derive: impl FnOnce() -> T) -> (T, bool) {
        let before = self.doubt();
        let value = derive();
        (value, self.doubt() > before)
    }

    /// Replay doubt a cached derivation recorded when it was computed.
    pub fn replay(&self, doubted: bool) {
        if doubted {
            self.add_doubt();
        }
    }

    /// The membership of `unit`'s file for the reference, `None` for a
    /// declaration outside the workspace (its own provenance applies).
    fn visibility(&self, unit: &CodeUnit) -> Option<Option<CSharpCompilationVisibility>> {
        self.answers
            .read(&self.read_capability.memo_attribution(), |answers_memo| {
                if unit.source().root() != self.reference.root() {
                    return None;
                }
                let cached = answers_memo
                    .lock()
                    .expect("membership answer cache poisoned")
                    .get(unit.source())
                    .copied();
                Some(match cached {
                    Some(answer) => answer,
                    None => {
                        let answer = self
                            .inner
                            .compilation_visibility(&self.reference, unit.source());
                        answers_memo
                            .lock()
                            .expect("membership answer cache poisoned")
                            .insert(unit.source().clone(), answer);
                        answer
                    }
                })
            })
    }

    /// Admit one declaration on its own. A type is a physical part: an
    /// invisible part is dropped and an unproven one is kept. The part adds
    /// doubt where it contributes (its base list, its members), and here
    /// only when no physical part of its type is visible, so the type itself
    /// is unproven. Any other declaration of unproven membership is kept as
    /// doubt.
    pub fn admit(&self, unit: &CodeUnit) -> bool {
        match self.visibility(unit) {
            None | Some(Some(CSharpCompilationVisibility::Visible)) => true,
            Some(Some(CSharpCompilationVisibility::NotVisible)) => false,
            Some(Some(CSharpCompilationVisibility::Unresolved) | None) => {
                if unit.is_class() {
                    self.admit_unproven_part(unit);
                } else {
                    self.add_doubt();
                }
                true
            }
        }
    }

    /// Doubt for an unproven type part unless its type identity has a
    /// visible (or external) physical part.
    fn admit_unproven_part(&self, part: &CodeUnit) {
        self.type_identities.read(
            &self.read_capability.memo_attribution(),
            |type_identities_memo| {
                let fqn = part.fq_name();
                let cached = type_identities_memo
                    .lock()
                    .expect("type identity cache poisoned")
                    .get(&fqn)
                    .copied();
                let answer = match cached {
                    Some(answer) => answer,
                    None => {
                        let answer = identity_visibility(
                            self.inner,
                            &self.reference,
                            &fqn,
                            Some(part),
                            CodeUnit::is_class,
                        );
                        type_identities_memo
                            .lock()
                            .expect("type identity cache poisoned")
                            .insert(fqn, answer);
                        answer
                    }
                };
                if answer != Some(CSharpCompilationVisibility::Visible) {
                    self.add_doubt();
                }
            },
        )
    }

    /// Admit a candidate set. Types follow [`Self::admit`]. Members are
    /// grouped by identity (fully qualified name, kind, signature): an
    /// identity with a visible declaration keeps only its visible ones,
    /// without doubt; one without keeps its unproven declarations as doubt;
    /// invisible declarations are dropped.
    pub fn admit_all(&self, units: impl IntoIterator<Item = CodeUnit>) -> Vec<CodeUnit> {
        let units = units
            .into_iter()
            .map(|unit| {
                let visibility = self.visibility(&unit);
                (unit, visibility)
            })
            .collect::<Vec<_>>();
        let identity = |unit: &CodeUnit| {
            (
                unit.fq_name(),
                unit.kind(),
                unit.signature().map(str::to_owned),
            )
        };
        let proven = units
            .iter()
            .filter(|(unit, visibility)| {
                !unit.is_class()
                    && matches!(
                        visibility,
                        None | Some(Some(CSharpCompilationVisibility::Visible))
                    )
            })
            .map(|(unit, _)| identity(unit))
            .collect::<HashSet<_>>();
        units
            .into_iter()
            .filter(|(unit, visibility)| match visibility {
                None | Some(Some(CSharpCompilationVisibility::Visible)) => true,
                Some(Some(CSharpCompilationVisibility::NotVisible)) => false,
                Some(Some(CSharpCompilationVisibility::Unresolved) | None) => {
                    if unit.is_class() {
                        self.admit_unproven_part(unit);
                        true
                    } else if proven.contains(&identity(unit)) {
                        false
                    } else {
                        self.add_doubt();
                        true
                    }
                }
            })
            .map(|(unit, _)| unit)
            .collect()
    }

    /// Every physical part of `code_unit`'s type, itself included. The
    /// analyzer's descendant index keys each subtype by the part its base
    /// resolved to, and a transitive walk visits one part per type, so a
    /// type's descendants are those of all its parts.
    fn physical_parts(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let mut parts = crate::graph_support::partial_type_parts(self.inner, code_unit);
        if !parts.contains(code_unit) {
            parts.push(code_unit.clone());
        }
        parts
    }

    /// The analyzer's direct descendants of `ancestor` whose derivation
    /// through this view names it.
    fn descendants_seen_here(
        &self,
        ancestor: &CodeUnit,
        descendants: HashSet<CodeUnit>,
    ) -> HashSet<CodeUnit> {
        let fqn = ancestor.fq_name();
        descendants
            .into_iter()
            .filter(|descendant| {
                self.admit(descendant)
                    && self
                        .get_direct_ancestors(descendant)
                        .iter()
                        .any(|candidate| candidate.fq_name() == fqn)
            })
            .collect()
    }

    fn admit_vec(&self, units: impl IntoIterator<Item = CodeUnit>) -> Vec<CodeUnit> {
        self.admit_all(units)
    }

    fn admit_set(&self, units: impl IntoIterator<Item = CodeUnit>) -> HashSet<CodeUnit> {
        self.admit_all(units).into_iter().collect()
    }

    fn admit_btree(&self, units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<CodeUnit> {
        self.admit_all(units).into_iter().collect()
    }

    /// A part's base list counts as doubt when the part's membership is
    /// unproven, and is empty when the part is provably invisible.
    pub fn admit_supertypes(&self, part: &CodeUnit, raw: &[String]) -> bool {
        match self.visibility(part) {
            None | Some(Some(CSharpCompilationVisibility::Visible)) => true,
            Some(Some(CSharpCompilationVisibility::NotVisible)) => false,
            Some(Some(CSharpCompilationVisibility::Unresolved) | None) => {
                if !raw.is_empty() {
                    self.add_doubt();
                }
                true
            }
        }
    }

    /// Filter rows only: the batch's inspected count and completeness describe
    /// the provider's work, not the admitted subset.
    fn admit_rows(&self, batch: LimitedQueryRows<CodeUnit>) -> LimitedQueryRows<CodeUnit> {
        LimitedQueryRows {
            rows: self.admit_vec(batch.rows),
            inspected: batch.inspected,
            complete: batch.complete,
        }
    }
}

impl CodeUnitIndex for MembershipScopedSource<'_> {
    fn project(&self) -> &dyn brokk_bifrost_core::analyzer::project::Project {
        self.inner.project()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn analyzed_files_for_language(&self, language: Language) -> Vec<ProjectFile> {
        self.inner.analyzed_files_for_language(language)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        self.inner.retain_analyzed(candidates)
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.top_level_declarations(file))
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.get_top_level_declarations(file))
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.declarations(file))
    }

    fn declares(&self, file: &ProjectFile, unit: &CodeUnit) -> bool {
        self.admit(unit) && self.inner.declares(file, unit)
    }

    fn declarations_named(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.declarations_named(file, identifier))
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.get_declarations(file))
    }

    fn declarations_of_files(
        &self,
        files: &[ProjectFile],
    ) -> HashMap<ProjectFile, BTreeSet<CodeUnit>> {
        self.inner
            .declarations_of_files(files)
            .into_iter()
            .map(|(file, units)| (file, self.admit_btree(units)))
            .collect()
    }

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.location_declarations(file))
    }

    fn parse_completeness(&self, file: &ProjectFile) -> ParseCompleteness {
        self.inner.parse_completeness(file)
    }

    fn materialization_records(&self, file: &ProjectFile) -> Vec<MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(
            self.inner
                .all_declarations()
                .filter(|unit| self.admit(unit)),
        )
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.get_all_declarations())
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.inner
            .all_declarations_with_primary_ranges()
            .into_iter()
            .filter(|(unit, _)| self.admit(unit))
            .collect()
    }

    fn summary_file_projection(&self, file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        self.inner.summary_file_projection(file)
    }

    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.declarations_sharing_name(unit))
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(
            self.inner
                .definitions(fq_name)
                .filter(|unit| self.admit(unit)),
        )
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        self.inner.prefetch_definitions(fq_names)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.get_definitions(fq_name))
    }

    fn definitions_by_structured_name(
        &self,
        fq_name: &FqName,
        language: Language,
    ) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.definitions_by_structured_name(fq_name, language))
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.lookup_candidates_by_short_name(symbol))
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.lookup_candidates_by_identifier(identifier))
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.search_definitions(pattern, auto_quote))
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.search_definitions_by_suffix_pattern(
            pattern,
            terminal_identifiers,
            language,
        ))
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.search_definitions_persisted(pattern))
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.direct_children(code_unit))
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.get_direct_children(code_unit))
    }

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.direct_children_in_file(code_unit))
    }

    fn get_members_in_class(&self, class_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.admit_vec(self.inner.get_members_in_class(class_unit))
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner
            .parent_of(code_unit)
            .filter(|parent| self.admit(parent))
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.inner.ranges(code_unit)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit(file, range)
            .filter(|unit| self.admit(unit))
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
            .filter(|unit| self.admit(unit))
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.inner.ranges_of(code_unit)
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.inner.location_ranges(code_unit)
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_skeletons(&self, file: &ProjectFile) -> std::collections::BTreeMap<CodeUnit, String> {
        self.inner
            .get_skeletons(file)
            .into_iter()
            .filter(|(unit, _)| self.admit(unit))
            .collect()
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata(code_unit)
    }

    fn signature_metadata_of(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata_of(code_unit)
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.indexed_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.inner.indexed_source_matches(file, source)
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        source: String,
        declaration_start: usize,
    ) -> String {
        self.inner
            .render_source_fragment(code_unit, source, declaration_start)
    }
}

impl ImportAnalysisProvider for MembershipScopedSource<'_> {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        Arc::new(self.admit_set(self.inner.imported_code_units_of(file).iter().cloned()))
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.inner.referencing_files_of(file)
    }

    fn referencing_files_of_targets(
        &self,
        targets: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> HashSet<ProjectFile> {
        self.inner
            .referencing_files_of_targets(targets, cancellation)
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        self.inner.import_infos_for_files(files)
    }

    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, FileDependencyFacts>> {
        self.inner.file_dependency_facts_for_files(files)
    }

    fn has_complete_import_resolution_dependencies(&self) -> bool {
        self.inner.has_complete_import_resolution_dependencies()
    }

    fn import_graph_module_path_keys_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<String>>> {
        self.inner.import_graph_module_path_keys_for_files(files)
    }

    fn import_graph_binding_surfaces_for_files(
        &self,
        files: &[ProjectFile],
        cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, Vec<ImportGraphBindingSurface>>> {
        self.inner
            .import_graph_binding_surfaces_for_files(files, cancellation)
    }

    fn import_graph_input_digests_for_files(
        &self,
        files: &[ProjectFile],
        cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, ImportGraphInputDigests>> {
        self.inner
            .import_graph_input_digests_for_files(files, cancellation)
    }

    fn import_resolution_dependencies_for_files(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, ImportResolutionDependencies>> {
        self.inner
            .import_resolution_dependencies_for_files(files, import_infos, cancellation)
    }

    fn for_each_import_edge_facts_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, Vec<ImportedFileEdgeFacts>) -> bool,
    ) -> Option<()> {
        self.inner.for_each_import_edge_facts_from_infos(
            files,
            import_infos,
            selected_ordinals,
            cancellation,
            visit,
        )
    }

    fn import_resolution_dependencies_for_ordinals(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, ImportResolutionDependencies>> {
        self.inner.import_resolution_dependencies_for_ordinals(
            files,
            import_infos,
            selected_ordinals,
            cancellation,
        )
    }

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Option<AdditionalFileDependencies> {
        self.inner
            .additional_direct_file_dependencies(files, cancellation)
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn import_info_of_checked(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Vec<ImportInfo>> {
        self.inner.import_info_of_checked(token, file)
    }

    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        self.inner
            .imported_code_units_from_infos(file, imports)
            .map(|units| Arc::new(self.admit_set(units.iter().cloned())))
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        self.inner.imported_files_from_infos(file, imports)
    }

    fn imported_file_edge_provenance_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<ImportedFileEdgeTargets> {
        self.inner
            .imported_file_edge_provenance_from_infos(file, imports)
    }

    fn for_each_imported_files_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, HashSet<ProjectFile>) -> bool,
    ) -> Option<()> {
        self.inner
            .for_each_imported_files_from_infos(files, import_infos, cancellation, visit)
    }

    fn for_each_imported_file_edges_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, ImportedFileEdgeTargets) -> bool,
    ) -> Option<()> {
        self.inner
            .for_each_imported_file_edges_from_infos(files, import_infos, cancellation, visit)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        self.inner.relevant_imports_for(code_unit)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        self.inner.could_import_file(source_file, imports, target)
    }

    fn prefetch_import_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &CancellationToken,
    ) {
        self.inner
            .prefetch_import_targets(files, import_infos, cancellation)
    }

    fn prefetch_file_dependency_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &CancellationToken,
    ) {
        self.inner
            .prefetch_file_dependency_targets(files, import_infos, cancellation)
    }

    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        self.inner.import_reachability(source_file, imports, target)
    }
}

/// The hierarchy as this view sees it. Ancestors are derived through the
/// view itself, so each part's base list counts by that part's membership
/// (an invisible part contributes nothing, an unproven one contributes
/// doubt), never from the analyzer's memo, which merges every physical part.
/// A descendant from the analyzer's index stays only when that derivation
/// names the ancestor. Transitive walks and scoped variants use the trait
/// defaults over these two.
impl TypeHierarchyProvider for MembershipScopedSource<'_> {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors.read(
            &self.read_capability.memo_attribution(),
            |direct_ancestors_memo| {
                let cached = direct_ancestors_memo
                    .lock()
                    .expect("direct ancestor cache poisoned")
                    .get(code_unit)
                    .cloned();
                if let Some((ancestors, doubted)) = cached {
                    self.replay(doubted);
                    return ancestors;
                }
                let (ancestors, doubted) =
                    self.measured(|| self.inner.direct_ancestors_through(self, code_unit));
                direct_ancestors_memo
                    .lock()
                    .expect("direct ancestor cache poisoned")
                    .insert(code_unit.clone(), (ancestors.clone(), doubted));
                ancestors
            },
        )
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let mut descendants = HashSet::default();
        for part in self.physical_parts(code_unit) {
            descendants.extend(self.inner.get_direct_descendants(&part));
        }
        self.descendants_seen_here(code_unit, descendants)
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.inner.supports_type_hierarchy(code_unit)
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let mut descendants = HashSet::default();
        for part in self.physical_parts(code_unit) {
            descendants.extend(self.inner.get_direct_descendants_within(&part, scope)?);
        }
        Some(self.descendants_seen_here(code_unit, descendants))
    }

    fn get_polymorphic_matches<T: CodeUnitIndex>(
        &self,
        target: &CodeUnit,
        analyzer: &T,
    ) -> Vec<CodeUnit> {
        if !target.is_function() {
            return Vec::new();
        }
        let Some(parent) = analyzer.parent_of(target) else {
            return Vec::new();
        };
        self.get_descendants(&parent)
    }
}

impl CSharpSource for MembershipScopedSource<'_> {
    fn read_capability(&self) -> brokk_bifrost_core::analyzer::project_reads::ReadCapability {
        self.read_capability.clone()
    }

    fn persisted_declaration_candidates_by_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit> {
        self.admit_btree(
            self.inner
                .persisted_declaration_candidates_by_fqn(fqn, normalized),
        )
    }

    fn persisted_declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.admit_rows(self.inner.persisted_declaration_candidates_by_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        ))
    }

    fn declaration_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.declaration_candidates_by_identifier(identifier))
    }

    fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.admit_rows(self.inner.declaration_candidates_by_identifier_limited(
            identifier,
            limit,
            continue_query,
        ))
    }

    fn member_candidates_for_owner(&self, owner_fqn: &str, name: &str) -> BTreeSet<CodeUnit> {
        self.admit_btree(self.inner.member_candidates_for_owner(owner_fqn, name))
    }

    fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.admit_rows(self.inner.member_candidates_for_owner_limited(
            owner_fqn,
            name,
            limit,
            continue_query,
        ))
    }

    fn workspace_namespace_exists(&self, namespace: &str) -> bool {
        self.inner.workspace_namespace_exists(namespace)
    }

    fn compilation_visibility(
        &self,
        reference: &ProjectFile,
        candidate: &ProjectFile,
    ) -> Option<CSharpCompilationVisibility> {
        self.inner.compilation_visibility(reference, candidate)
    }

    fn direct_children_where(
        &self,
        parent: &CodeUnit,
        keep: &dyn Fn(&CodeUnit) -> bool,
    ) -> Vec<CodeUnit> {
        self.admit_vec(
            self.inner
                .direct_children(parent)
                .into_iter()
                .filter(|child| keep(child)),
        )
    }

    fn direct_ancestors_through(
        &self,
        view: &dyn CSharpSource,
        code_unit: &CodeUnit,
    ) -> Vec<CodeUnit> {
        self.inner.direct_ancestors_through(view, code_unit)
    }

    fn with_usage_definitions(
        &self,
        token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
    ) {
        self.inner.with_usage_definitions(token, &mut |lookup| {
            let scoped = MembershipScopedLookup {
                inner: lookup,
                source: self,
            };
            read(&scoped);
        });
    }

    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.package_name_of(file)
    }

    fn file_namespace_hint_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.file_namespace_hint_limited(file, limit)
    }

    fn import_info_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<ImportInfo> {
        self.inner.import_info_of_limited(token, file, limit)
    }

    fn workspace_import_info_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<ImportInfo> {
        self.inner
            .workspace_import_info_limited(limit, continue_query)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        let raw = self.inner.raw_supertypes_of(code_unit);
        if self.admit_supertypes(code_unit, &raw) {
            raw
        } else {
            Vec::new()
        }
    }

    fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        let mut batch = self.inner.raw_supertypes_limited(code_unit, limit);
        if !self.admit_supertypes(code_unit, &batch.rows) {
            batch.rows.clear();
        }
        batch
    }

    fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    fn namespace_of_file(&self, file: &ProjectFile) -> String {
        self.inner.namespace_of_file(file)
    }

    fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.namespace_of_file_limited(file, limit)
    }

    fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.using_namespaces_of(file)
    }

    fn using_namespaces_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        self.inner
            .using_namespaces_of_limited(file, limit, continue_query)
    }

    fn using_aliases_of(&self, file: &ProjectFile) -> Arc<HashMap<String, String>> {
        self.inner.using_aliases_of(file)
    }

    fn using_aliases_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        self.inner
            .using_aliases_of_limited(file, limit, continue_query)
    }

    fn global_static_using_type_names(&self) -> std::sync::Arc<Vec<String>> {
        self.inner.global_static_using_type_names()
    }

    fn global_static_using_type_names_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        self.inner
            .global_static_using_type_names_limited(limit, continue_query)
    }

    fn global_static_using_types(&self) -> std::sync::Arc<Vec<CodeUnit>> {
        self.static_types.read(
            &self.read_capability.memo_attribution(),
            |static_types_memo| {
                static_types_memo
                    .get_or_init(|| {
                        std::sync::Arc::new(
                            self.admit_vec(self.inner.global_static_using_types().iter().cloned()),
                        )
                    })
                    .clone()
            },
        )
    }

    fn usage_global_static_using_types(&self) -> std::sync::Arc<Vec<CodeUnit>> {
        self.usage_static_types.read(
            &self.read_capability.memo_attribution(),
            |usage_static_types_memo| {
                usage_static_types_memo
                    .get_or_init(|| {
                        std::sync::Arc::new(self.admit_vec(
                            self.inner.usage_global_static_using_types().iter().cloned(),
                        ))
                    })
                    .clone()
            },
        )
    }

    fn global_using_namespaces(&self) -> std::sync::Arc<HashSet<String>> {
        self.inner.global_using_namespaces()
    }

    fn file_using_namespaces_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<String> {
        self.inner.file_using_namespaces_of(token, file)
    }

    fn sorted_global_using_namespaces(&self) -> Vec<String> {
        self.inner.sorted_global_using_namespaces()
    }

    fn global_using_namespaces_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        self.inner
            .global_using_namespaces_limited(limit, continue_query)
    }

    fn global_using_aliases(&self) -> std::sync::Arc<HashMap<String, String>> {
        self.inner.global_using_aliases()
    }

    fn global_using_aliases_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        self.inner
            .global_using_aliases_limited(limit, continue_query)
    }
}

/// A [`BoundedDefinitionLookup`] handed to a usage-resolution callback,
/// filtering every candidate it returns through the enclosing
/// [`MembershipScopedSource`].
struct MembershipScopedLookup<'l, 's> {
    inner: &'l dyn BoundedDefinitionLookup,
    source: &'s MembershipScopedSource<'s>,
}

impl BoundedDefinitionLookup for MembershipScopedLookup<'_, '_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.source.admit_vec(self.inner.fqn(fqn))
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        self.source
            .admit_vec(self.inner.fqn_in_language(fqn, language))
    }

    fn fqn_in_any_language(&self, fqn: &str) -> Vec<CodeUnit> {
        self.source.admit_vec(self.inner.fqn_in_any_language(fqn))
    }

    fn package_exists_in_any_language(&self, package: &str) -> bool {
        self.inner.package_exists_in_any_language(package)
    }

    fn types_in_package(&self, package: &str, simple: &str) -> Vec<CodeUnit> {
        self.source
            .admit_vec(self.inner.types_in_package(package, simple))
    }

    fn by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        self.source
            .admit_vec(self.inner.by_normalized_fqn(normalized))
    }

    fn identifier(&self, ident: &str) -> Vec<CodeUnit> {
        self.source.admit_vec(self.inner.identifier(ident))
    }

    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        self.source.admit_vec(self.inner.members_for_owner_name(
            owner_fqn,
            normalized_owner_fqn,
            name,
        ))
    }

    fn members_for_owner(&self, owner: &CodeUnit, name: &str) -> Vec<CodeUnit> {
        self.source
            .admit_vec(self.inner.members_for_owner(owner, name))
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.source
            .admit_vec(self.inner.file_identifier(file, ident))
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        self.source.admit_vec(self.inner.fqn_direct_children(fqn))
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        self.inner.fqn_exists(fqn)
    }

    fn package_exists(&self, package: &str) -> bool {
        self.inner.package_exists(package)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        self.inner.package_exists_in_language(package, language)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.inner.fqn_prefix_exists(prefix)
    }

    fn fqn_candidates(&self, fqns: Vec<String>) -> Vec<CodeUnit> {
        self.source.admit_vec(self.inner.fqn_candidates(fqns))
    }

    fn file_identifier_in_files(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
        self.source
            .admit_vec(self.inner.file_identifier_in_files(files, ident))
    }
}
