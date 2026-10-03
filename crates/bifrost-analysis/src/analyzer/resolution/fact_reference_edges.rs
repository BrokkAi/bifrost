//! Proof classification for projecting native fact answers into usage edges.
//!
//! Binding cardinality remains separate from unrelated typed projections, while
//! target-local callable receiver evidence decides external versus same-owner
//! inventory without collapsing positive routes into its incompleteness gap.

use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionCallableReceiverOrigin,
    ResolutionIdentifierRole, ResolutionMemberKind, ResolutionMemberOwnerFact, ResolutionNamespace,
    ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind, ResolutionTypeTransferKind,
};

use super::fact_lowering::{
    LoweredResolutionFragment, LoweredSemanticRole, lookup_routes, lookup_semantic,
    mounted_site_semantic,
};
use super::fact_resolution::{
    FactBatchedReferenceAnswer, FactCallableReceiverTargetDisposition, FactReferenceBatchAnswer,
    FactReferenceReceiverGap, FactResolutionBatchSummary, SelectedFactResolutionSnapshot,
};
use super::fact_source::FactResolutionSource;
use super::typed_fact_lowering::LoweredTypedFragment;
use super::{
    BindingFragmentId, FactReferenceSiteMetadata, MAX_REFERENCE_SEEDS_PER_BATCH, ResolutionAnswer,
    ResolutionBatchMetrics, ResolutionCompletion, ResolutionIncompleteReason, SemanticId,
};
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;

use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::common::{declaration_language_for_file, is_java_module_descriptor_file};
use crate::analyzer::store::{Result as StoreResult, StoreError};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::structural::reference_edges::EdgeDerivationResult;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeIncompleteReason, EdgeSite, OwnerRelationMemo, ReferenceEdgeRow,
    ReferenceSiteClassifier, is_same_owner_member_reference,
};
use crate::analyzer::structural::{EdgeAxis, EdgeProvenance, OwnerRelation, SiteClass};
use crate::analyzer::usages::{UsageHitKind, UsageProof};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
#[cfg(any(test, feature = "test-support"))]
use std::cmp::Ordering;
use std::collections::VecDeque;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

/// One selected file-local fact artifact whose semantic identities must be
/// crosswalked to the current analyzer snapshot.
///
/// `source`, `facts`, `lexical`, and `typed` must come from the same
/// parse/lowering pass for `file`. The catalog builder validates the source
/// bytes, positioned lexical semantics, and the typed receiver-dependency
/// join before it publishes any catalog.
pub struct FactReferenceEdgeSelectedFragment<'facts> {
    file: ProjectFile,
    source: &'facts str,
    facts: &'facts FileResolutionFacts,
    lexical: &'facts LoweredResolutionFragment,
    typed: &'facts LoweredTypedFragment,
    /// The interner these two artifacts were lowered with. A lookup this
    /// projection derives from a name has to be the same shared id the
    /// artifacts carry, so it cannot mint one of its own.
    names: &'facts dyn crate::analyzer::resolution::SharedNameInterner,
}

impl<'facts> FactReferenceEdgeSelectedFragment<'facts> {
    pub fn new(
        file: ProjectFile,
        source: &'facts str,
        facts: &'facts FileResolutionFacts,
        lexical: &'facts LoweredResolutionFragment,
        typed: &'facts LoweredTypedFragment,
        names: &'facts dyn crate::analyzer::resolution::SharedNameInterner,
    ) -> Self {
        Self {
            file,
            source,
            facts,
            lexical,
            typed,
            names,
        }
    }

    pub fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub const fn source(&self) -> &'facts str {
        self.source
    }

    pub const fn facts(&self) -> &'facts FileResolutionFacts {
        self.facts
    }

    pub const fn lexical(&self) -> &'facts LoweredResolutionFragment {
        self.lexical
    }

    pub const fn typed(&self) -> &'facts LoweredTypedFragment {
        self.typed
    }
}

#[derive(Debug, Clone, Copy)]
struct FactReferenceEdgeExpectedSemantic<'facts> {
    identifier: &'facts PositionedIdentifierFact,
    site: &'facts ResolutionSiteFact,
    name: &'facts str,
}

#[derive(Debug, Clone, Copy)]
struct FactReferenceEdgeSelectedDefinition<'facts> {
    semantic: SemanticId,
    lookup: SemanticId,
    lookup_domain: FactReferenceEdgeDeclarationDomain,
    site: &'facts ResolutionSiteFact,
    name: &'facts str,
    owner: Option<ResolutionMemberOwnerFact>,
}

/// One exact declaration-key family that an open reference lookup can still
/// select. This is derived from source-owned namespace and receiver structure,
/// never from the incomplete answer's retained targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FactReferenceEdgeLookupImpact {
    lookup: SemanticId,
    domain: FactReferenceEdgeDeclarationDomain,
}

#[derive(Debug)]
struct FactReferenceEdgeDeclarationCandidate {
    declaration: CodeUnit,
    ranges: Vec<Range>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactReferenceEdgeGraphKind {
    Type,
    Callable,
    Field,
}

impl FactReferenceEdgeGraphKind {
    fn matches(self, declaration: &CodeUnit) -> bool {
        match self {
            Self::Type => declaration.is_class(),
            Self::Callable => declaration.is_callable(),
            Self::Field => declaration.is_field(),
        }
    }
}

fn graph_definition_kind(
    kind: ResolutionSiteKind,
    member_owner: Option<ResolutionMemberOwnerFact>,
) -> Option<FactReferenceEdgeGraphKind> {
    match (kind, member_owner.map(|owner| owner.kind)) {
        (ResolutionSiteKind::TypeDeclaration, None | Some(ResolutionMemberKind::NestedType)) => {
            Some(FactReferenceEdgeGraphKind::Type)
        }
        (ResolutionSiteKind::CallableDeclaration, None | Some(ResolutionMemberKind::Method))
        | (
            ResolutionSiteKind::ConstructorDeclaration,
            None | Some(ResolutionMemberKind::Constructor),
        ) => Some(FactReferenceEdgeGraphKind::Callable),
        (ResolutionSiteKind::ValueDeclaration, Some(ResolutionMemberKind::Field)) => {
            Some(FactReferenceEdgeGraphKind::Field)
        }
        _ => None,
    }
}

fn reference_gap_domain(
    file: &FactReferenceEdgeFile<'_>,
    reference: SemanticId,
    namespace: ResolutionNamespace,
    site_kind: ResolutionSiteKind,
) -> Option<FactReferenceEdgeGapDomain> {
    reference_gap_domain_for_receiver_dependency(
        namespace,
        site_kind,
        file.receiver_dependency(reference),
    )
}

fn reference_gap_domain_for_receiver_dependency(
    namespace: ResolutionNamespace,
    site_kind: ResolutionSiteKind,
    receiver_dependency: Option<bool>,
) -> Option<FactReferenceEdgeGapDomain> {
    match namespace {
        ResolutionNamespace::Type
        | ResolutionNamespace::Callable
        | ResolutionNamespace::Constructor => Some(FactReferenceEdgeGapDomain::TypeOrCallable),
        // Rust calls use the value namespace, which contains both callable
        // declarations and values. An unresolved call cannot exclude either
        // graph domain solely from its lookup namespace.
        ResolutionNamespace::Value if site_kind == ResolutionSiteKind::CallableReference => {
            Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration)
        }
        ResolutionNamespace::Value => Some(FactReferenceEdgeGapDomain::Field),
        ResolutionNamespace::Constant => Some(FactReferenceEdgeGapDomain::Field),
        ResolutionNamespace::Macro | ResolutionNamespace::Package => None,
        ResolutionNamespace::TypeOrValue
            if matches!(site_kind, ResolutionSiteKind::ValueReference) =>
        {
            match receiver_dependency {
                Some(true) => None,
                Some(false) => Some(FactReferenceEdgeGapDomain::Field),
                None => Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
            }
        }
        ResolutionNamespace::TypeOrValue => Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
    }
}

fn lookup_declaration_domain(namespace: ResolutionNamespace) -> FactReferenceEdgeDeclarationDomain {
    match namespace {
        ResolutionNamespace::Type
        | ResolutionNamespace::Callable
        | ResolutionNamespace::Constructor => FactReferenceEdgeDeclarationDomain::TypeOrCallable,
        ResolutionNamespace::Value => FactReferenceEdgeDeclarationDomain::Field,
        ResolutionNamespace::Constant => FactReferenceEdgeDeclarationDomain::Field,
        ResolutionNamespace::Macro
        | ResolutionNamespace::TypeOrValue
        | ResolutionNamespace::Package => {
            unreachable!("effective lookup routes have exact namespaces")
        }
    }
}

fn declaration_domain(declaration: &CodeUnit) -> FactReferenceEdgeDeclarationDomain {
    if declaration.is_field() {
        FactReferenceEdgeDeclarationDomain::Field
    } else {
        FactReferenceEdgeDeclarationDomain::TypeOrCallable
    }
}

fn declaration_gap_domain(declaration: &CodeUnit) -> FactReferenceEdgeGapDomain {
    match declaration_domain(declaration) {
        FactReferenceEdgeDeclarationDomain::TypeOrCallable => {
            FactReferenceEdgeGapDomain::TypeOrCallable
        }
        FactReferenceEdgeDeclarationDomain::Field => FactReferenceEdgeGapDomain::Field,
    }
}

/// Whether `owner` occurs on `declaration`'s analyzer-owned parent chain.
///
/// A Java local type is structurally owned by its enclosing type in resolution
/// facts while its analyzer parent is the intervening callable. Walking the
/// exact `CodeUnit` chain preserves both truths without reconstructing a
/// rendered qualified name.
fn declaration_has_structured_owner(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    owner: &CodeUnit,
    cancellation: &CancellationToken,
) -> StoreResult<Option<bool>> {
    let mut seen = HashSet::default();
    let mut current = analyzer.parent_of(declaration);
    while let Some(candidate) = current {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if &candidate == owner {
            return Ok(Some(true));
        }
        if !seen.insert(candidate.clone()) {
            return Err(StoreError::new(format!(
                "current analyzer declaration parent chain is cyclic: declaration={declaration:?}, owner={owner:?}, seen={seen:?}"
            )));
        }
        current = analyzer.parent_of(&candidate);
    }
    Ok(Some(false))
}

fn select_graph_declaration(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    definition: FactReferenceEdgeSelectedDefinition<'_>,
    owner: Option<&CodeUnit>,
    current_graph_declarations: &[FactReferenceEdgeDeclarationCandidate],
    cancellation: &CancellationToken,
) -> StoreResult<Option<CodeUnit>> {
    let expected_graph_kind = graph_definition_kind(definition.site.kind, definition.owner)
        .expect("only graph definitions enter exact declaration selection");
    let mut candidates = Vec::new();
    for candidate in current_graph_declarations {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if candidate.declaration.terminal_name() != definition.name
            || !expected_graph_kind.matches(&candidate.declaration)
        {
            continue;
        }
        let Some(containing_span) = candidate
            .ranges
            .iter()
            .filter(|range| {
                range.start_byte <= definition.site.start_byte
                    && definition.site.end_byte <= range.end_byte
            })
            .map(|range| range.end_byte - range.start_byte)
            .min()
        else {
            continue;
        };
        if let Some(owner) = owner {
            let Some(has_owner) = declaration_has_structured_owner(
                analyzer,
                &candidate.declaration,
                owner,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if !has_owner {
                continue;
            }
        }
        candidates.push((candidate, containing_span));
    }
    if let Some(innermost_span) = candidates.iter().map(|(_, span)| *span).min() {
        candidates.retain(|(_, span)| *span == innermost_span);
    }
    if candidates.len() != 1 {
        return Err(StoreError::new(format!(
            "one current analyzer graph declaration must own selected native definition in {file:?}: definition={definition:?}, owner={owner:?}, candidates={candidates:?}, current_graph_declarations={current_graph_declarations:?}"
        )));
    }
    Ok(Some(candidates[0].0.declaration.clone()))
}

/// One selected source file needed to turn byte-addressed fact sites into
/// canonical workspace locations.
struct FactReferenceEdgeFile<'analyzer> {
    file: ProjectFile,
    source_len: usize,
    line_starts: Box<[usize]>,
    classifier: Option<ReferenceSiteClassifier<'analyzer>>,
    /// `Some` means selected source facts exhaustively classified this
    /// fragment. `None` keeps a manually assembled catalog conservative.
    receiver_dependencies: Option<HashSet<SemanticId>>,
}

impl<'analyzer> FactReferenceEdgeFile<'analyzer> {
    fn new(analyzer: &'analyzer dyn IAnalyzer, file: ProjectFile, source: &str) -> Self {
        let classifier = ReferenceSiteClassifier::new(analyzer, &file);
        Self {
            file,
            source_len: source.len(),
            line_starts: compute_line_starts(source).into_boxed_slice(),
            classifier,
            receiver_dependencies: None,
        }
    }

    const fn file(&self) -> &ProjectFile {
        &self.file
    }

    fn receiver_dependency(&self, reference: SemanticId) -> Option<bool> {
        self.receiver_dependencies
            .as_ref()
            .map(|dependencies| dependencies.contains(&reference))
    }

    fn install_receiver_dependencies(&mut self, dependencies: HashSet<SemanticId>) {
        assert!(
            self.receiver_dependencies.replace(dependencies).is_none(),
            "one selected receiver-dependency classification is required per fragment"
        );
    }

    fn range(&self, start_byte: usize, end_byte: usize) -> StoreResult<Range> {
        if start_byte > end_byte || end_byte > self.source_len {
            return Err(StoreError::new(format!(
                "native reference range {start_byte}..{end_byte} is outside selected file {:?} of {} bytes",
                self.file, self.source_len
            )));
        }
        Ok(Range {
            start_byte,
            end_byte,
            start_line: find_line_index_for_offset(&self.line_starts, start_byte) + 1,
            end_line: find_line_index_for_offset(&self.line_starts, end_byte.saturating_sub(1)) + 1,
        })
    }
}

/// Whether one selected definition belongs to the canonical declaration graph.
///
/// An explicit out-of-domain row is different from a missing crosswalk entry:
/// locals and parameters may be intentionally absent from usage graphs, while
/// a missing entry for a graph declaration is snapshot corruption.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FactReferenceEdgeDeclaration {
    Graph(CodeUnit),
    OutOfGraphDomain,
}

/// Immutable, generation-bound correspondence used by every native edge
/// consumer.
///
/// The catalog owns no resolution policy. It only binds fragment identities to
/// exact files and semantic declaration identities to the `CodeUnit` values
/// read from the same analyzer generation.
pub struct FactReferenceEdgeCatalog<'analyzer> {
    analyzer: &'analyzer dyn IAnalyzer,
    generation: u64,
    files_by_fragment: HashMap<BindingFragmentId, FactReferenceEdgeFile<'analyzer>>,
    current_declarations_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    declarations: HashMap<SemanticId, FactReferenceEdgeDeclaration>,
    lookup_impacts_by_reference: HashMap<SemanticId, Vec<FactReferenceEdgeLookupImpact>>,
    targets_by_lookup: HashMap<SemanticId, Vec<CodeUnit>>,
}

impl<'analyzer> FactReferenceEdgeCatalog<'analyzer> {
    /// Build one immutable crosswalk for an exact selected fragment set.
    ///
    /// `Ok(None)` means cancellation won before publication. Every structural
    /// mismatch is an error, and both outcomes discard the partially built
    /// catalog. Definition identities are classified exhaustively: types,
    /// callables, and member fields must map to one exact current analyzer
    /// declaration, while locals, parameters, and every other positioned
    /// non-`CodeUnit` definition are explicitly outside the canonical graph
    /// domain.
    pub fn from_selected_fragments<'facts>(
        analyzer: &'analyzer dyn IAnalyzer,
        selected_fragments: impl IntoIterator<Item = FactReferenceEdgeSelectedFragment<'facts>>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Self>> {
        let mut catalog = Self::new(analyzer);
        let mut selected_files = HashSet::default();
        let mut selected_semantics = HashSet::default();
        for selected in selected_fragments {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let fragment = selected.lexical.fragment();
            if catalog.files_by_fragment.contains_key(&fragment) {
                return Err(StoreError::new(format!(
                    "duplicate selected native reference-edge fragment {fragment:?}"
                )));
            }
            if !selected_files.insert(selected.file.clone()) {
                return Err(StoreError::new(format!(
                    "duplicate selected native reference-edge file {:?}",
                    selected.file
                )));
            }
            if !catalog.insert_selected_fragment(selected, &mut selected_semantics, cancellation)? {
                return Ok(None);
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if !catalog.canonicalize_lookup_indices(cancellation) {
            return Ok(None);
        }
        catalog.ensure_current()?;
        Ok(Some(catalog))
    }

    pub fn new(analyzer: &'analyzer dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            generation: analyzer.project().analysis_generation(),
            files_by_fragment: HashMap::default(),
            current_declarations_by_file: HashMap::default(),
            declarations: HashMap::default(),
            lookup_impacts_by_reference: HashMap::default(),
            targets_by_lookup: HashMap::default(),
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrow the exact fragment-to-file selection admitted by this catalog.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn selected_fragment_files(
        &self,
    ) -> impl Iterator<Item = (BindingFragmentId, &ProjectFile)> {
        self.files_by_fragment
            .iter()
            .map(|(&fragment, file)| (fragment, file.file()))
    }

    /// Return the exact current analyzer declaration for one selected semantic.
    ///
    /// `Ok(None)` is an explicit out-of-graph classification. An absent
    /// semantic remains an error rather than being conflated with that state.
    pub fn graph_declaration(&self, semantic: SemanticId) -> StoreResult<Option<&CodeUnit>> {
        self.ensure_current()?;
        Ok(match self.declaration(semantic)? {
            FactReferenceEdgeDeclaration::Graph(declaration) => Some(declaration),
            FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
        })
    }

    pub fn insert_file(
        &mut self,
        fragment: BindingFragmentId,
        file: ProjectFile,
    ) -> StoreResult<()> {
        let source = self.current_indexed_source(&file)?;
        self.insert_file_contents(fragment, file, &source)
    }

    fn current_indexed_source(&self, file: &ProjectFile) -> StoreResult<String> {
        self.ensure_current()?;
        if file.root() != self.analyzer.project().root() {
            return Err(StoreError::new(format!(
                "native reference-edge file {file:?} belongs to foreign workspace {:?}",
                file.root()
            )));
        }
        if !self.analyzer.is_analyzed(file) {
            return Err(StoreError::new(format!(
                "native reference-edge file {file:?} is absent from the current analyzer index"
            )));
        }
        let source = self.analyzer.indexed_source(file).ok_or_else(|| {
            StoreError::new(format!(
                "native reference-edge catalog has no indexed source for selected file {file:?}"
            ))
        })?;
        self.ensure_current()?;
        Ok(source)
    }

    fn insert_file_contents(
        &mut self,
        fragment: BindingFragmentId,
        file: ProjectFile,
        source: &str,
    ) -> StoreResult<()> {
        assert!(
            self.files_by_fragment
                .insert(
                    fragment,
                    FactReferenceEdgeFile::new(self.analyzer, file, source),
                )
                .is_none(),
            "one selected file must own each native fragment: {fragment:?}"
        );
        self.ensure_current()
    }

    pub fn insert_graph_declaration(
        &mut self,
        semantic: SemanticId,
        declaration: CodeUnit,
    ) -> StoreResult<()> {
        self.ensure_current()?;
        let file = declaration.source().clone();
        if file.root() != self.analyzer.project().root() {
            return Err(StoreError::new(format!(
                "native reference-edge declaration {declaration:?} belongs to foreign workspace {:?}",
                file.root()
            )));
        }
        if !self.current_declarations_by_file.contains_key(&file) {
            if !self.analyzer.is_analyzed(&file) {
                return Err(StoreError::new(format!(
                    "native reference-edge declaration source {file:?} is absent from the current analyzer index"
                )));
            }
            let mut declarations = self
                .analyzer
                .get_declarations(&file)
                .into_iter()
                .collect::<HashSet<_>>();
            let file_scope = CodeUnit::file_scope(file.clone());
            if is_java_module_descriptor_file(&file) {
                declarations.insert(file_scope);
            }
            self.ensure_current()?;
            assert!(
                self.current_declarations_by_file
                    .insert(file.clone(), declarations)
                    .is_none(),
                "one current declaration inventory is built per source file"
            );
        }
        let canonical = self.current_declarations_by_file[&file]
            .get(&declaration)
            .cloned()
            .ok_or_else(|| {
                StoreError::new(format!(
                    "native reference-edge declaration {declaration:?} is absent from the current analyzer index"
                ))
            })?;
        assert!(
            self.declarations
                .insert(semantic, FactReferenceEdgeDeclaration::Graph(canonical))
                .is_none(),
            "one selected declaration correspondence is required for {semantic:?}"
        );
        self.ensure_current()
    }

    pub fn insert_out_of_graph_declaration(&mut self, semantic: SemanticId) {
        assert!(
            self.declarations
                .insert(semantic, FactReferenceEdgeDeclaration::OutOfGraphDomain)
                .is_none(),
            "one selected declaration correspondence is required for {semantic:?}"
        );
    }

    fn insert_selected_graph_declarations(
        &mut self,
        file: &ProjectFile,
        definitions: &[FactReferenceEdgeSelectedDefinition<'_>],
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let declaration_candidates = self.analyzer.get_declarations(file);
        let mut current_graph_declarations = Vec::new();
        for declaration in declaration_candidates {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if declaration.is_synthetic()
                || (!declaration.is_class()
                    && !declaration.is_callable()
                    && !declaration.is_field())
            {
                continue;
            }
            let mut ranges = self.analyzer.ranges(&declaration);
            ranges.sort_unstable_by_key(|range| {
                (
                    range.start_byte,
                    range.end_byte,
                    range.start_line,
                    range.end_line,
                )
            });
            ranges.dedup();
            current_graph_declarations.push(FactReferenceEdgeDeclarationCandidate {
                declaration,
                ranges,
            });
        }
        self.ensure_current()?;

        let definitions_by_site = definitions
            .iter()
            .map(|definition| (definition.site.id, definition))
            .collect::<HashMap<_, _>>();
        let graph_definition_sites = definitions
            .iter()
            .filter(|definition| {
                graph_definition_kind(definition.site.kind, definition.owner).is_some()
            })
            .map(|definition| definition.site.id)
            .collect::<HashSet<_>>();
        let mut children_by_owner: HashMap<ResolutionSiteId, Vec<ResolutionSiteId>> =
            HashMap::default();
        let mut ready = VecDeque::new();
        for definition in definitions {
            if graph_definition_kind(definition.site.kind, definition.owner).is_none() {
                self.insert_out_of_graph_declaration(definition.semantic);
                continue;
            }
            match definition.owner {
                Some(owner) => {
                    if !graph_definition_sites.contains(&owner.owner) {
                        return Err(StoreError::new(format!(
                            "selected native reference-edge graph definition has a non-graph owner in {file:?}: definition={definition:?}, owner={owner:?}, definitions={definitions:?}"
                        )));
                    }
                    children_by_owner
                        .entry(owner.owner)
                        .or_default()
                        .push(definition.site.id);
                }
                None => ready.push_back(definition.site.id),
            }
        }

        let mut graph_declarations_by_site: HashMap<ResolutionSiteId, CodeUnit> =
            HashMap::default();
        while let Some(site_id) = ready.pop_front() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let definition = definitions_by_site[&site_id];
            let owner = definition
                .owner
                .map(|owner| graph_declarations_by_site[&owner.owner].clone());
            let Some(declaration) = select_graph_declaration(
                self.analyzer,
                file,
                *definition,
                owner.as_ref(),
                &current_graph_declarations,
                cancellation,
            )?
            else {
                return Ok(false);
            };
            self.insert_graph_declaration(definition.semantic, declaration.clone())?;
            let canonical = self
                .graph_declaration(definition.semantic)?
                .expect("a selected graph definition was inserted above")
                .clone();
            let target_domain = declaration_domain(&canonical);
            if target_domain != definition.lookup_domain {
                return Err(StoreError::new(format!(
                    "selected native reference-edge lookup namespace disagrees with its graph declaration domain in {file:?}: definition={definition:?}, declaration={canonical:?}, domain={target_domain:?}"
                )));
            }
            self.targets_by_lookup
                .entry(definition.lookup)
                .or_default()
                .push(canonical);
            if graph_declarations_by_site
                .insert(site_id, declaration)
                .is_some()
            {
                return Err(StoreError::new(format!(
                    "selected native reference-edge graph site was mapped twice in {file:?}: {site_id:?}"
                )));
            }
            if let Some(children) = children_by_owner.get(&site_id) {
                ready.extend(children.iter().copied());
            }
        }
        if graph_declarations_by_site.len() != graph_definition_sites.len() {
            let unresolved = graph_definition_sites
                .iter()
                .filter(|site| !graph_declarations_by_site.contains_key(site))
                .filter_map(|site| definitions_by_site.get(site).copied())
                .collect::<Vec<_>>();
            return Err(StoreError::new(format!(
                "selected native reference-edge graph ownership is cyclic or disconnected in {file:?}: {unresolved:?}"
            )));
        }
        self.ensure_current()?;
        Ok(!cancellation.is_cancelled())
    }

    fn insert_selected_fragment<'facts>(
        &mut self,
        selected: FactReferenceEdgeSelectedFragment<'facts>,
        selected_semantics: &mut HashSet<SemanticId>,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let FactReferenceEdgeSelectedFragment {
            file,
            source,
            facts,
            lexical,
            typed,
            names: shared_names,
        } = selected;
        let fragment = lexical.fragment();
        if typed.fragment() != fragment {
            return Err(StoreError::new(format!(
                "selected native reference-edge lexical and typed fragments disagree in {file:?}: lexical={fragment:?}, typed={:?}",
                typed.fragment()
            )));
        }
        if typed.language() != lexical.language() {
            return Err(StoreError::new(format!(
                "selected native reference-edge lexical and typed fragment languages disagree in {file:?}: lexical={:?}, typed={:?}",
                lexical.language(),
                typed.language()
            )));
        }
        let declaration_language = declaration_language_for_file(&file);
        if declaration_language == Language::None || lexical.language() != declaration_language {
            return Err(StoreError::new(format!(
                "selected native reference-edge fragment requires one non-None declaration language shared by the analyzer-owned file and artifacts: file={file:?}, declaration_language={declaration_language:?}, fragment_language={:?}",
                lexical.language()
            )));
        }
        let indexed_source = self.current_indexed_source(&file)?;
        if indexed_source != source {
            return Err(StoreError::new(format!(
                "selected native reference-edge source differs byte-for-byte from the current analyzer index for {file:?}: selected_len={}, indexed_len={}",
                source.len(),
                indexed_source.len()
            )));
        }
        self.insert_file_contents(fragment, file.clone(), source)?;
        let source_len = self.file(fragment)?.source_len;

        let mut names = HashMap::default();
        for name in &facts.names {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if names.insert(name.id, name.spelling.as_str()).is_some() {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate name ID {:?} in {file:?}",
                    name.id
                )));
            }
        }

        let mut sites = HashMap::default();
        for site in &facts.sites {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if site.start_byte > site.end_byte || site.end_byte > source_len {
                return Err(StoreError::new(format!(
                    "selected native reference-edge site {site:?} is outside {file:?} of {source_len} bytes"
                )));
            }
            if sites.insert(site.id, site).is_some() {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate site ID {:?} in {file:?}",
                    site.id
                )));
            }
        }

        let mut member_owners = HashMap::default();
        for owner in &facts.member_owners {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if member_owners.insert(owner.member, *owner).is_some() {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate member owner for {:?} in {file:?}: {:?}",
                    owner.member, facts.member_owners
                )));
            }
        }
        let mut reference_owners = HashMap::default();
        for owner in &facts.reference_owners {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if reference_owners
                .insert(owner.reference, owner.owner)
                .is_some()
            {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate reference owner for {:?} in {file:?}: {:?}",
                    owner.reference, facts.reference_owners
                )));
            }
        }
        let mut callable_receiver_origins = HashMap::default();
        for origin in &facts.callable_receiver_origins {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if callable_receiver_origins
                .insert(origin.reference, origin.origin)
                .is_some()
            {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate callable receiver origin for {:?} in {file:?}: {:?}",
                    origin.reference, facts.callable_receiver_origins
                )));
            }
        }

        let mut expected_semantics = HashMap::default();
        let mut definition_sites = HashSet::default();
        for identifier in &facts.identifiers {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let site = sites.get(&identifier.site).copied().ok_or_else(|| {
                StoreError::new(format!(
                    "selected native reference-edge identifier {identifier:?} names an unknown site in {file:?}"
                ))
            })?;
            let name = names.get(&identifier.name).copied().ok_or_else(|| {
                StoreError::new(format!(
                    "selected native reference-edge identifier {identifier:?} names an unknown spelling in {file:?}"
                ))
            })?;
            let role = match identifier.role {
                ResolutionIdentifierRole::Declaration => LoweredSemanticRole::Definition,
                ResolutionIdentifierRole::Reference => LoweredSemanticRole::Reference,
            };
            let expected = FactReferenceEdgeExpectedSemantic {
                identifier,
                site,
                name,
            };
            if expected_semantics
                .insert((identifier.site, role), expected)
                .is_some()
            {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate semantic role at {:?} in {file:?}: {:?}",
                    identifier.site, facts.identifiers
                )));
            }
            if role == LoweredSemanticRole::Definition && !definition_sites.insert(identifier.site)
            {
                return Err(StoreError::new(format!(
                    "selected native reference-edge facts contain duplicate definition at {:?} in {file:?}: {:?}",
                    identifier.site, facts.identifiers
                )));
            }
        }

        for (&member, owner) in &member_owners {
            let member_definition =
                expected_semantics.get(&(member, LoweredSemanticRole::Definition));
            let owner_definition =
                expected_semantics.get(&(owner.owner, LoweredSemanticRole::Definition));
            let (expected_site_kind, expected_namespace) = match owner.kind {
                ResolutionMemberKind::NestedType => (
                    ResolutionSiteKind::TypeDeclaration,
                    ResolutionNamespace::Type,
                ),
                ResolutionMemberKind::Method => (
                    ResolutionSiteKind::CallableDeclaration,
                    ResolutionNamespace::Callable,
                ),
                ResolutionMemberKind::Constructor => (
                    ResolutionSiteKind::ConstructorDeclaration,
                    ResolutionNamespace::Constructor,
                ),
                ResolutionMemberKind::Field => (
                    ResolutionSiteKind::ValueDeclaration,
                    ResolutionNamespace::Value,
                ),
                ResolutionMemberKind::AssociatedType => (
                    ResolutionSiteKind::TypeAliasDeclaration,
                    ResolutionNamespace::Type,
                ),
            };
            if member_definition.is_none_or(|definition| {
                definition.site.kind != expected_site_kind
                    || definition.identifier.namespace != expected_namespace
            }) || owner_definition.is_none_or(|definition| {
                definition.site.kind != ResolutionSiteKind::TypeDeclaration
                    || definition.identifier.namespace != ResolutionNamespace::Type
            }) {
                return Err(StoreError::new(format!(
                    "selected native reference-edge member ownership is misaligned in {file:?}: owner={owner:?}, member_definition={member_definition:?}, owner_definition={owner_definition:?}"
                )));
            }
        }
        for (&reference, &owner) in &reference_owners {
            if !expected_semantics.contains_key(&(reference, LoweredSemanticRole::Reference))
                || owner.is_some_and(|owner| !definition_sites.contains(&owner))
            {
                return Err(StoreError::new(format!(
                    "selected native reference-edge reference ownership is misaligned in {file:?}: reference={reference:?}, owner={owner:?}"
                )));
            }
        }
        for (&reference, &origin) in &callable_receiver_origins {
            let expected = expected_semantics.get(&(reference, LoweredSemanticRole::Reference));
            if expected.is_none_or(|expected| {
                expected.identifier.namespace != ResolutionNamespace::Callable
                    || !matches!(
                        expected.site.kind,
                        ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
                    )
                    || (expected.identifier.qualifier.is_none()
                        != (origin == ResolutionCallableReceiverOrigin::Implicit))
            }) {
                return Err(StoreError::new(format!(
                    "selected native reference-edge callable receiver origin is misaligned in {file:?}: reference={reference:?}, origin={origin:?}, expected={expected:?}"
                )));
            }
        }

        let mut root_references = HashSet::default();
        for reference in &facts.root_references {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            root_references.insert(reference.reference);
        }

        // A TypeOrValue ValueReference is only a dependency-only qualifier
        // when its projected value is structurally consumed as a receiver.
        // Keep this source-owned distinction beside the selected fragment:
        // the binding transport does not preserve the slot join, and
        // rebuilding it from source text would lose the producer's exact
        // semantics. MemberReference occurrences remain canonical even when
        // their values feed a later receiver.
        let mut lowered_receiver_inputs = HashSet::default();
        for transfer in typed.transfers() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if transfer.kind() == ResolutionTypeTransferKind::Receiver {
                lowered_receiver_inputs.insert(transfer.source_slot());
            }
        }
        let mut lowered_receiver_dependencies = HashSet::default();
        for projection in typed.projections() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if lowered_receiver_inputs.contains(&projection.output_slot()) {
                lowered_receiver_dependencies.insert(projection.reference());
            }
        }

        // The raw-fact side of the same set, in raw-fact space. It used to be
        // built in identity space, by computing each slot's semantic from
        // `(fragment, slot id)`; that was a pure function while a mounted id
        // was a digest of its identity, and a type-slot semantic is its
        // blob's catalog position now, which this projection cannot compute
        // because it holds the two lowered artifacts and not the catalog that
        // numbered them. It does not need to: a receiver input is a slot id
        // and a dependency is a reference site, and the comparison runs on
        // sites once the lexical artifact has said which semantic each site
        // owns. Raw facts stay part of the selected-artifact alignment
        // boundary, so a same-fragment typed artifact still cannot silently
        // drift from its source facts.
        drop(lowered_receiver_inputs);
        let mut expected_receiver_input_slots = HashSet::default();
        for transfer in &facts.type_transfers {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if transfer.kind == ResolutionTypeTransferKind::Receiver {
                expected_receiver_input_slots.insert(transfer.input);
            }
        }
        let mut expected_receiver_dependency_sites = HashSet::default();
        for projection in &facts.binding_projections {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if expected_receiver_input_slots.contains(&projection.output) {
                expected_receiver_dependency_sites.insert(projection.reference);
            }
        }
        drop(expected_receiver_input_slots);
        let mut lowered_receiver_dependency_sites = HashSet::default();

        let mut definitions = Vec::new();
        let mut receiver_dependencies = HashSet::default();
        for lowered in lexical.semantics() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let key = (lowered.site(), lowered.role());
            let expected = expected_semantics.remove(&key).ok_or_else(|| {
                StoreError::new(format!(
                    "selected native reference-edge lowering has no aligned fact semantic in {file:?}: {lowered:?}"
                ))
            })?;
            // The same property the batch projection asserts, at the point
            // where a lowered artifact is matched to its fact row. This used
            // to recompute `definition_semantic`/`reference_semantic` from
            // (fragment, site) and compare; that recipe is false for a
            // selected macro capsule, whose identities are specialized by
            // their invocation digest while their site ids stay capsule-local
            // and are copied through by `remount`. The site and the role are
            // the alignment key; what the identity has to satisfy is that it
            // is mounted on this fragment.
            assert_eq!(
                lowered.semantic().ordinal(),
                Some(fragment.ordinal()),
                "a lowered selected semantic is mounted on its own fragment: {:?} in {fragment:?} of {file:?}",
                lowered.semantic()
            );
            if !selected_semantics.insert(lowered.semantic()) {
                return Err(StoreError::new(format!(
                    "duplicate selected native reference-edge semantic {:?} in {file:?}",
                    lowered.semantic()
                )));
            }
            if lowered.namespace() != expected.identifier.namespace {
                return Err(StoreError::new(format!(
                    "selected native reference-edge lowering is misaligned in {file:?}: lowered={lowered:?}, expected={expected:?}"
                )));
            }
            match lowered.role() {
                LoweredSemanticRole::Definition => {
                    if lowered.site_metadata().is_some() {
                        return Err(StoreError::new(format!(
                            "selected native reference-edge definition unexpectedly carries reference metadata in {file:?}: {lowered:?}"
                        )));
                    }
                    definitions.push(FactReferenceEdgeSelectedDefinition {
                        semantic: lowered.semantic(),
                        lookup: lookup_semantic(
                            shared_names,
                            lexical.language(),
                            expected.identifier.namespace,
                            expected.name,
                        ),
                        lookup_domain: lookup_declaration_domain(expected.identifier.namespace),
                        site: expected.site,
                        name: expected.name,
                        owner: member_owners.get(&expected.site.id).copied(),
                    });
                }
                LoweredSemanticRole::Reference => {
                    let metadata = lowered.site_metadata().ok_or_else(|| {
                        StoreError::new(format!(
                            "selected native reference-edge reference lacks site metadata in {file:?}: {lowered:?}"
                        ))
                    })?;
                    let expected_owner = reference_owners
                        .get(&expected.site.id)
                        .copied()
                        .map(|owner| owner.map(|owner| mounted_site_semantic(fragment, owner)));
                    let expected_receiver_origin =
                        callable_receiver_origins.get(&expected.site.id).copied();
                    if metadata.namespace() != expected.identifier.namespace
                        || metadata.site_kind() != expected.site.kind
                        || metadata.start_byte() != expected.site.start_byte
                        || metadata.end_byte() != expected.site.end_byte
                        || metadata.unqualified()
                            != (expected.identifier.qualifier.is_none()
                                && !root_references.contains(&expected.site.id))
                        || metadata.reference_owner() != expected_owner
                        || metadata.callable_receiver_origin() != expected_receiver_origin
                    {
                        return Err(StoreError::new(format!(
                            "selected native reference-edge reference metadata is misaligned in {file:?}: lowered={lowered:?}, expected={expected:?}, reference_owner={expected_owner:?}, callable_receiver_origin={expected_receiver_origin:?}"
                        )));
                    }
                    if lowered_receiver_dependencies.contains(&lowered.semantic()) {
                        lowered_receiver_dependency_sites.insert(lowered.site());
                    }
                    let receiver_dependency = expected.identifier.namespace
                        == ResolutionNamespace::TypeOrValue
                        && expected.site.kind == ResolutionSiteKind::ValueReference
                        && lowered_receiver_dependencies.contains(&lowered.semantic());
                    if receiver_dependency {
                        receiver_dependencies.insert(lowered.semantic());
                    }
                    let gap_domain = reference_gap_domain_for_receiver_dependency(
                        expected.identifier.namespace,
                        expected.site.kind,
                        Some(receiver_dependency),
                    );
                    let mut impacts = Vec::new();
                    if let Some(gap_domain) = gap_domain {
                        for &(_, namespace) in lookup_routes(expected.identifier.namespace) {
                            let domain = lookup_declaration_domain(namespace);
                            if gap_domain.affects(domain) {
                                impacts.push(FactReferenceEdgeLookupImpact {
                                    lookup: lookup_semantic(
                                        shared_names,
                                        lexical.language(),
                                        namespace,
                                        expected.name,
                                    ),
                                    domain,
                                });
                            }
                        }
                    }
                    impacts.sort_unstable();
                    impacts.dedup();
                    if self
                        .lookup_impacts_by_reference
                        .insert(lowered.semantic(), impacts)
                        .is_some()
                    {
                        return Err(StoreError::new(format!(
                            "selected native reference-edge reference has duplicate lookup-impact ownership in {file:?}: {:?}",
                            lowered.semantic()
                        )));
                    }
                }
            }
        }
        if !expected_semantics.is_empty() {
            return Err(StoreError::new(format!(
                "selected native reference-edge facts have no aligned lowered semantics in {file:?}: {expected_semantics:?}"
            )));
        }
        // Every lowered receiver dependency belongs to a lexical semantic the
        // loop above visited, so the two counts agree unless the typed
        // artifact names a reference the lexical artifact does not have.
        if lowered_receiver_dependency_sites.len() != lowered_receiver_dependencies.len()
            || lowered_receiver_dependency_sites != expected_receiver_dependency_sites
        {
            return Err(StoreError::new(format!(
                "selected native reference-edge typed receiver dependencies are misaligned in {file:?}: lowered={lowered_receiver_dependency_sites:?}, expected={expected_receiver_dependency_sites:?}"
            )));
        }
        drop(expected_receiver_dependency_sites);
        self.files_by_fragment
            .get_mut(&fragment)
            .expect("the selected fragment file was inserted above")
            .install_receiver_dependencies(receiver_dependencies);
        drop(lowered_receiver_dependencies);

        self.insert_selected_graph_declarations(&file, &definitions, cancellation)
    }

    fn canonicalize_lookup_indices(&mut self, cancellation: &CancellationToken) -> bool {
        for impacts in self.lookup_impacts_by_reference.values_mut() {
            if cancellation.is_cancelled() {
                return false;
            }
            impacts.sort_unstable();
            impacts.dedup();
        }
        for targets in self.targets_by_lookup.values_mut() {
            if cancellation.is_cancelled() {
                return false;
            }
            targets.sort_unstable();
            targets.dedup();
        }
        !cancellation.is_cancelled()
    }

    fn reference_lookup_impacts(
        &self,
        reference: SemanticId,
    ) -> StoreResult<&[FactReferenceEdgeLookupImpact]> {
        self.ensure_current()?;
        self.lookup_impacts_by_reference
            .get(&reference)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                StoreError::new(format!(
                    "native reference-edge catalog is missing lookup impacts for selected reference {reference:?}"
                ))
            })
    }

    fn graph_targets_for_lookup(&self, lookup: SemanticId) -> StoreResult<&[CodeUnit]> {
        self.ensure_current()?;
        Ok(self
            .targets_by_lookup
            .get(&lookup)
            .map(Vec::as_slice)
            .unwrap_or(&[]))
    }

    fn ensure_current(&self) -> StoreResult<()> {
        let current = self.analyzer.project().analysis_generation();
        if current != self.generation {
            return Err(StoreError::new(format!(
                "native reference-edge catalog generation {} is stale against current generation {current}",
                self.generation
            )));
        }
        Ok(())
    }

    fn file(&self, fragment: BindingFragmentId) -> StoreResult<&FactReferenceEdgeFile<'_>> {
        self.files_by_fragment.get(&fragment).ok_or_else(|| {
            StoreError::new(format!(
                "native reference-edge catalog is missing selected fragment {fragment:?}"
            ))
        })
    }

    fn declaration(&self, semantic: SemanticId) -> StoreResult<&FactReferenceEdgeDeclaration> {
        self.declarations.get(&semantic).ok_or_else(|| {
            StoreError::new(format!(
                "native reference-edge catalog is missing declaration {semantic:?}"
            ))
        })
    }
}

/// A target-bearing edge projection gap that consumers may retain beside the
/// canonical rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactReferenceEdgeGap {
    IncompleteBinding {
        reference: SemanticId,
        domain: FactReferenceEdgeGapDomain,
    },
    ReceiverAdmission {
        reference: SemanticId,
        target: SemanticId,
        gap: FactReferenceReceiverGap,
        domain: FactReferenceEdgeGapDomain,
    },
    MissingSiteMetadata {
        reference: SemanticId,
        domain: FactReferenceEdgeGapDomain,
    },
    UnknownReferenceOwner {
        reference: SemanticId,
        domain: FactReferenceEdgeGapDomain,
    },
    /// The source owner is known, but has no canonical graph declaration
    /// (for example, a Rust block-local function represented lexically).
    OutOfGraphReferenceOwner {
        reference: SemanticId,
        owner: SemanticId,
        domain: FactReferenceEdgeGapDomain,
    },
    MissingReferenceKind {
        reference: SemanticId,
        target: SemanticId,
        domain: FactReferenceEdgeGapDomain,
    },
}

/// A disjoint canonical declaration target domain.
///
/// Fields remain valid canonical reference targets, but consumers whose node
/// model contains only types and callables can request completeness for that
/// narrower target domain without interpreting field-only uncertainty as a
/// missing type or callable edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactReferenceEdgeDeclarationDomain {
    TypeOrCallable,
    Field,
}

/// Which canonical declaration targets one projection gap may affect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactReferenceEdgeGapDomain {
    TypeOrCallable,
    Field,
    AnyGraphDeclaration,
}

impl FactReferenceEdgeGapDomain {
    pub const fn affects(self, domain: FactReferenceEdgeDeclarationDomain) -> bool {
        matches!(
            (self, domain),
            (
                Self::TypeOrCallable,
                FactReferenceEdgeDeclarationDomain::TypeOrCallable
            ) | (Self::Field, FactReferenceEdgeDeclarationDomain::Field)
                | (Self::AnyGraphDeclaration, _)
        )
    }

    fn union(self, other: Self) -> Self {
        if self == other {
            self
        } else {
            Self::AnyGraphDeclaration
        }
    }
}

impl FactReferenceEdgeGap {
    pub const fn domain(&self) -> FactReferenceEdgeGapDomain {
        match self {
            Self::IncompleteBinding { domain, .. }
            | Self::ReceiverAdmission { domain, .. }
            | Self::MissingSiteMetadata { domain, .. }
            | Self::UnknownReferenceOwner { domain, .. }
            | Self::OutOfGraphReferenceOwner { domain, .. }
            | Self::MissingReferenceKind { domain, .. } => *domain,
        }
    }

    fn incomplete_reason(&self) -> EdgeIncompleteReason {
        match self {
            Self::IncompleteBinding { .. } => EdgeIncompleteReason::ForwardResolutionIncomplete,
            Self::ReceiverAdmission { .. } => EdgeIncompleteReason::ForwardAdmissionIncomplete,
            Self::MissingSiteMetadata { .. } => EdgeIncompleteReason::ForwardMetadataIncomplete,
            Self::UnknownReferenceOwner { .. } | Self::OutOfGraphReferenceOwner { .. } => {
                EdgeIncompleteReason::AxisUnsupported(EdgeAxis::OwnerClassification)
            }
            Self::MissingReferenceKind { .. } => {
                EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification)
            }
        }
    }
}

/// Generation-bound completeness for one canonical declaration target domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactReferenceEdgeDomainStatus<'completeness> {
    domain: FactReferenceEdgeDeclarationDomain,
    generation: u64,
    completeness: &'completeness EdgeCompleteness,
}

impl FactReferenceEdgeDomainStatus<'_> {
    pub const fn domain(&self) -> FactReferenceEdgeDeclarationDomain {
        self.domain
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn completeness(&self) -> &EdgeCompleteness {
        self.completeness
    }

    pub fn covers(&self, axis: EdgeAxis) -> bool {
        axis != EdgeAxis::InverseProjection && self.completeness.covers(axis)
    }
}

/// One fragment-owned batch of canonical native reference edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactReferenceEdgeBatch {
    fragment: BindingFragmentId,
    generation: u64,
    reference_count: usize,
    edges: Box<[ReferenceEdgeRow]>,
    gaps: Box<[FactReferenceEdgeGap]>,
    unresolved_names: Option<Box<[String]>>,
    completeness: EdgeCompleteness,
    type_or_callable_completeness: EdgeCompleteness,
    field_completeness: EdgeCompleteness,
}

impl FactReferenceEdgeBatch {
    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn reference_count(&self) -> usize {
        self.reference_count
    }

    pub fn edges(&self) -> &[ReferenceEdgeRow] {
        &self.edges
    }

    pub fn gaps(&self) -> &[FactReferenceEdgeGap] {
        &self.gaps
    }

    /// The identifiers of this batch's unresolved references, normalized the
    /// way a declaration's short name is, or `None` when one of them has no
    /// identifier token this route can read.
    ///
    /// An `IncompleteBinding` gap says the resolver did not close one
    /// reference's target set. Such a reference can only *add* an inbound
    /// edge, never remove one, and the declarations it can add are the ones
    /// its own name reaches -- the reverse index's nomination relation read
    /// forward, where the reverse asks which sites name a target and this asks
    /// which declarations a site's name can reach.
    ///
    /// A consumer that proves a declaration unused reads this to abstain on
    /// the declarations one unresolved reference could still reach instead of
    /// on every candidate in the pass, and must abstain on the whole pass for
    /// `None`. It is names and not declarations because this route's catalog
    /// is deliberately lazy: it holds the declarations the answers named, not
    /// a workspace-wide name-to-declaration index, and building one here is
    /// the heap shape the architecture forbids.
    pub fn unresolved_names(&self) -> Option<&[String]> {
        self.unresolved_names.as_deref()
    }

    pub const fn completeness(&self) -> &EdgeCompleteness {
        &self.completeness
    }

    /// Return generation-bound completeness narrowed to one target domain.
    pub fn domain_status(
        &self,
        domain: FactReferenceEdgeDeclarationDomain,
    ) -> FactReferenceEdgeDomainStatus<'_> {
        FactReferenceEdgeDomainStatus {
            domain,
            generation: self.generation,
            completeness: self.domain_completeness(domain),
        }
    }

    fn domain_completeness(&self, domain: FactReferenceEdgeDeclarationDomain) -> &EdgeCompleteness {
        match domain {
            FactReferenceEdgeDeclarationDomain::TypeOrCallable => {
                &self.type_or_callable_completeness
            }
            FactReferenceEdgeDeclarationDomain::Field => &self.field_completeness,
        }
    }

    /// Whether this forward-only batch completely answers one edge axis.
    pub fn covers(&self, axis: EdgeAxis) -> bool {
        axis != EdgeAxis::InverseProjection && self.completeness.covers(axis)
    }
}

/// Final graph-specific status, exact cardinalities, and retained resolver
/// work of one broad native edge operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactReferenceEdgeSummary {
    generation: u64,
    completeness: EdgeCompleteness,
    type_or_callable_completeness: EdgeCompleteness,
    field_completeness: EdgeCompleteness,
    reference_count: usize,
    edge_count: usize,
    batch_count: usize,
    root_binding_metrics: ResolutionBatchMetrics,
}

impl FactReferenceEdgeSummary {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn completeness(&self) -> &EdgeCompleteness {
        &self.completeness
    }

    /// Return generation-bound completeness narrowed to one target domain.
    pub fn domain_status(
        &self,
        domain: FactReferenceEdgeDeclarationDomain,
    ) -> FactReferenceEdgeDomainStatus<'_> {
        let completeness = match domain {
            FactReferenceEdgeDeclarationDomain::TypeOrCallable => {
                &self.type_or_callable_completeness
            }
            FactReferenceEdgeDeclarationDomain::Field => &self.field_completeness,
        };
        FactReferenceEdgeDomainStatus {
            domain,
            generation: self.generation,
            completeness,
        }
    }

    pub const fn reference_count(&self) -> usize {
        self.reference_count
    }

    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }

    pub const fn batch_count(&self) -> usize {
        self.batch_count
    }

    /// Work performed by the shared unqualified lexical root batches.
    pub const fn root_binding_metrics(&self) -> ResolutionBatchMetrics {
        self.root_binding_metrics
    }

    /// Whether this forward-only operation completely answers one edge axis.
    pub fn covers(&self, axis: EdgeAxis) -> bool {
        axis != EdgeAxis::InverseProjection && self.completeness.covers(axis)
    }
}

/// Exact selected-fragment and selected-file coverage shared by every
/// canonical selected-Java edge consumer.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct SelectedReferenceEdgeCoverage {
    fragments: HashSet<BindingFragmentId>,
    files: HashSet<ProjectFile>,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedReferenceEdgeCoverage {
    pub(crate) fn fragments(&self) -> &HashSet<BindingFragmentId> {
        &self.fragments
    }

    pub(crate) fn files(&self) -> &HashSet<ProjectFile> {
        &self.files
    }

    pub(crate) fn into_fragments(self) -> HashSet<BindingFragmentId> {
        self.fragments
    }
}

struct SelectedReferenceEdgeMembership {
    fragments: HashSet<BindingFragmentId>,
}

impl SelectedReferenceEdgeMembership {
    fn fragments(&self) -> &HashSet<BindingFragmentId> {
        &self.fragments
    }
}

fn validate_selected_reference_edge_membership<S>(
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    catalog: &FactReferenceEdgeCatalog<'_>,
    cancellation: &CancellationToken,
) -> StoreResult<Option<SelectedReferenceEdgeMembership>>
where
    S: FactResolutionSource,
{
    let Some(snapshot_fragments) = selected.selected_fragments() else {
        return Ok(None);
    };
    let mut fragments = HashSet::default();
    for &fragment in snapshot_fragments {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if !fragments.insert(fragment) {
            return Err(StoreError::new(format!(
                "selected resolution snapshot contains duplicate fragment {fragment:?}: {snapshot_fragments:?}"
            )));
        }
    }

    let mut catalog_fragments = HashSet::default();
    for &fragment in catalog.files_by_fragment.keys() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assert!(catalog_fragments.insert(fragment));
    }
    if fragments != catalog_fragments {
        return Err(StoreError::new(format!(
            "selected resolution snapshot and native edge catalog cover different fragments: snapshot={fragments:?}, edge_catalog={catalog_fragments:?}"
        )));
    }
    Ok(Some(SelectedReferenceEdgeMembership { fragments }))
}

/// Validate the one canonical selected snapshot/catalog coverage
/// invariant. Consumer-specific graph or query checks belong at their call
/// sites, not in a second copy of this fragment/file authority.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn validate_selected_reference_edge_coverage<S>(
    analyzer: &dyn IAnalyzer,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    catalog: &FactReferenceEdgeCatalog<'_>,
    cancellation: &CancellationToken,
) -> StoreResult<Option<SelectedReferenceEdgeCoverage>>
where
    S: FactResolutionSource,
{
    let Some(membership) =
        validate_selected_reference_edge_membership(selected, catalog, cancellation)?
    else {
        return Ok(None);
    };

    let mut files = HashSet::default();
    for (_, file) in catalog.selected_fragment_files() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assert!(files.insert(file.clone()));
    }

    let mut analyzed_files = HashSet::default();
    for file in analyzer.analyzed_files() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        analyzed_files.insert(file);
    }
    if files != analyzed_files {
        return Err(StoreError::new(format!(
            "selected native edge catalog does not cover the complete analyzed workspace: analyzed={analyzed_files:?}, edge_catalog={files:?}"
        )));
    }
    Ok(Some(SelectedReferenceEdgeCoverage {
        fragments: membership.fragments,
        files,
    }))
}

/// One generation-bound inverse index built from the canonical selected
/// forward stream.
///
/// Every selected graph declaration has an entry, including declarations with
/// zero rows. Run-global status remains separate from those target-local
/// results: domain-global gaps apply only to declarations in that domain, and
/// receiver/kind gaps apply only to their exact target. A declaration outside
/// the covered universe receives an explicit incomplete result rather than a
/// manufactured complete empty answer.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct SelectedReferenceInverseIndex {
    generation: u64,
    run_completeness: EdgeCompleteness,
    covered_target_domains: HashMap<CodeUnit, FactReferenceEdgeDeclarationDomain>,
    results_by_target: HashMap<CodeUnit, Arc<EdgeDerivationResult>>,
    empty_type_or_callable_result: Arc<EdgeDerivationResult>,
    empty_field_result: Arc<EdgeDerivationResult>,
    uncovered_result: Arc<EdgeDerivationResult>,
    nonempty_target_count: usize,
    reference_count: usize,
    edge_count: usize,
    batch_count: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedReferenceInverseIndex {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Aggregate status of the full streamed operation. Individual target
    /// results can be complete when every open reason belongs elsewhere.
    pub const fn run_completeness(&self) -> &EdgeCompleteness {
        &self.run_completeness
    }

    pub fn target_count(&self) -> usize {
        self.covered_target_domains.len()
    }

    pub const fn nonempty_target_count(&self) -> usize {
        self.nonempty_target_count
    }

    pub const fn reference_count(&self) -> usize {
        self.reference_count
    }

    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }

    pub const fn batch_count(&self) -> usize {
        self.batch_count
    }

    pub fn covers_target(&self, target: &CodeUnit) -> bool {
        self.covered_target_domains.contains_key(target)
    }

    /// Return one exact target bucket, including a generation-bound complete
    /// empty bucket. Uncovered declarations share one explicit incomplete
    /// result and can never be mistaken for an absent selected edge.
    pub fn inverse_for(&self, target: &CodeUnit) -> Arc<EdgeDerivationResult> {
        if let Some(result) = self.results_by_target.get(target) {
            return Arc::clone(result);
        }
        match self.covered_target_domains.get(target) {
            Some(FactReferenceEdgeDeclarationDomain::TypeOrCallable) => {
                Arc::clone(&self.empty_type_or_callable_result)
            }
            Some(FactReferenceEdgeDeclarationDomain::Field) => Arc::clone(&self.empty_field_result),
            None => Arc::clone(&self.uncovered_result),
        }
    }

    /// Build a ready index without a selected source. This exists only
    /// for source-owned RQL adapter laws; the comparable facade always calls
    /// [`build_selected_reference_inverse_index`] instead.
    #[doc(hidden)]
    pub fn from_forward_rows_for_test_support(
        generation: u64,
        covered_targets: Vec<CodeUnit>,
        forward_completeness: EdgeCompleteness,
        reference_count: usize,
        rows: Vec<ReferenceEdgeRow>,
    ) -> Self {
        let edge_count = rows.len();
        let mut target_domains = HashMap::default();
        for target in covered_targets {
            let domain = declaration_domain(&target);
            assert!(target_domains.insert(target, domain).is_none());
        }
        let mut rows_by_target = HashMap::default();
        for row in rows {
            assert_eq!(row.generation, generation);
            assert_eq!(row.provenance, EdgeProvenance::Forward);
            assert!(target_domains.contains_key(&row.target));
            rows_by_target
                .entry(row.target.clone())
                .or_insert_with(Vec::new)
                .push(row);
        }
        let global = inverse_reasons(&forward_completeness);
        Self::finish_rows(
            generation,
            forward_completeness,
            target_domains,
            rows_by_target,
            global.clone(),
            global,
            HashMap::default(),
            reference_count,
            edge_count,
            usize::from(edge_count > 0),
            &CancellationToken::new(),
        )
        .expect("an uncancelled test-support index finalization must complete")
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_rows(
        generation: u64,
        forward_run_completeness: EdgeCompleteness,
        target_domains: HashMap<CodeUnit, FactReferenceEdgeDeclarationDomain>,
        mut rows_by_target: HashMap<CodeUnit, Vec<ReferenceEdgeRow>>,
        mut type_or_callable_reasons: Vec<EdgeIncompleteReason>,
        mut field_reasons: Vec<EdgeIncompleteReason>,
        mut target_reasons: HashMap<CodeUnit, Vec<EdgeIncompleteReason>>,
        reference_count: usize,
        edge_count: usize,
        batch_count: usize,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let run_completeness = inverse_index_completeness(&forward_run_completeness);
        type_or_callable_reasons.sort_by(canonical_inverse_reason_order);
        field_reasons.sort_by(canonical_inverse_reason_order);
        let empty_type_or_callable_result = Arc::new(EdgeDerivationResult {
            edges: Vec::new(),
            completeness: completeness_from_reasons(type_or_callable_reasons.clone()),
            provenance: EdgeProvenance::Inverse,
            generation,
        });
        let empty_field_result = Arc::new(EdgeDerivationResult {
            edges: Vec::new(),
            completeness: completeness_from_reasons(field_reasons.clone()),
            provenance: EdgeProvenance::Inverse,
            generation,
        });
        let mut nonempty_target_count = 0usize;
        let mut results_by_target = HashMap::default();
        for (target, domain) in &target_domains {
            if cancellation.is_cancelled() {
                return None;
            }
            let mut rows = rows_by_target.remove(target).unwrap_or_default();
            if !rows.is_empty() {
                nonempty_target_count += 1;
            }
            if !sort_inverse_rows_with_cancellation(&mut rows, cancellation) {
                return None;
            }
            for row in &mut rows {
                if cancellation.is_cancelled() {
                    return None;
                }
                assert_eq!(row.generation, generation);
                assert_eq!(&row.target, target);
                assert_eq!(row.provenance, EdgeProvenance::Forward);
                row.provenance = EdgeProvenance::Inverse;
            }
            let local_reasons = target_reasons.remove(target).unwrap_or_default();
            if rows.is_empty() && local_reasons.is_empty() {
                continue;
            }
            let mut reasons = match domain {
                FactReferenceEdgeDeclarationDomain::TypeOrCallable => {
                    type_or_callable_reasons.clone()
                }
                FactReferenceEdgeDeclarationDomain::Field => field_reasons.clone(),
            };
            for reason in local_reasons {
                if cancellation.is_cancelled() {
                    return None;
                }
                push_edge_reason(&mut reasons, reason);
            }
            reasons.sort_by(canonical_inverse_reason_order);
            let completeness = completeness_from_reasons(reasons);
            let result = Arc::new(EdgeDerivationResult {
                edges: rows,
                completeness,
                provenance: EdgeProvenance::Inverse,
                generation,
            });
            assert!(results_by_target.insert(target.clone(), result).is_none());
        }
        assert!(rows_by_target.is_empty());
        assert!(target_reasons.is_empty());
        let uncovered_result = Arc::new(EdgeDerivationResult {
            edges: Vec::new(),
            completeness: EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexTargetUncovered],
            },
            provenance: EdgeProvenance::Inverse,
            generation,
        });
        Some(Self {
            generation,
            run_completeness,
            covered_target_domains: target_domains,
            results_by_target,
            empty_type_or_callable_result,
            empty_field_result,
            uncovered_result,
            nonempty_target_count,
            reference_count,
            edge_count,
            batch_count,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
fn completeness_from_reasons(reasons: Vec<EdgeIncompleteReason>) -> EdgeCompleteness {
    if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    }
}

/// In-place heap sort with cancellation at every sift step. The index is still
/// provisional while this runs, so an interrupted partial permutation is
/// discarded with the accumulator instead of becoming an observable prefix.
#[cfg(any(test, feature = "test-support"))]
fn sort_inverse_rows_with_cancellation(
    rows: &mut [ReferenceEdgeRow],
    cancellation: &CancellationToken,
) -> bool {
    if cancellation.is_cancelled() {
        return false;
    }
    for root in (0..rows.len() / 2).rev() {
        if !sift_inverse_row_heap(rows, root, cancellation) {
            return false;
        }
    }
    for end in (1..rows.len()).rev() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.swap(0, end);
        if !sift_inverse_row_heap(&mut rows[..end], 0, cancellation) {
            return false;
        }
    }
    !cancellation.is_cancelled()
}

#[cfg(any(test, feature = "test-support"))]
fn sift_inverse_row_heap(
    rows: &mut [ReferenceEdgeRow],
    mut root: usize,
    cancellation: &CancellationToken,
) -> bool {
    loop {
        if cancellation.is_cancelled() {
            return false;
        }
        let Some(left) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return true;
        };
        if left >= rows.len() {
            return true;
        }
        let right = left + 1;
        let larger = if right < rows.len()
            && canonical_inverse_row_order(&rows[left], &rows[right]).is_lt()
        {
            right
        } else {
            left
        };
        if !canonical_inverse_row_order(&rows[root], &rows[larger]).is_lt() {
            return true;
        }
        rows.swap(root, larger);
        root = larger;
    }
}

#[cfg(any(test, feature = "test-support"))]
fn canonical_inverse_row_order(left: &ReferenceEdgeRow, right: &ReferenceEdgeRow) -> Ordering {
    left.site
        .file
        .cmp(&right.site.file)
        .then_with(|| left.site.range.start_byte.cmp(&right.site.range.start_byte))
        .then_with(|| left.site.range.end_byte.cmp(&right.site.range.end_byte))
        .then_with(|| left.site.range.start_line.cmp(&right.site.range.start_line))
        .then_with(|| left.site.range.end_line.cmp(&right.site.range.end_line))
        .then_with(|| left.site.ast_id.cmp(&right.site.ast_id))
        .then_with(|| left.site.enclosing.cmp(&right.site.enclosing))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| {
            left.reference_kind
                .map(|kind| kind as u8)
                .cmp(&right.reference_kind.map(|kind| kind as u8))
        })
        .then_with(|| (left.proof as u8).cmp(&(right.proof as u8)))
        .then_with(|| left.usage_kind.cmp(&right.usage_kind))
        .then_with(|| left.site_class.cmp(&right.site_class))
        .then_with(|| left.owner_relation.cmp(&right.owner_relation))
        .then_with(|| left.provenance.cmp(&right.provenance))
        .then_with(|| left.generation.cmp(&right.generation))
}

#[cfg(any(test, feature = "test-support"))]
fn canonical_inverse_reason_order(
    left: &EdgeIncompleteReason,
    right: &EdgeIncompleteReason,
) -> Ordering {
    inverse_reason_rank(left)
        .cmp(&inverse_reason_rank(right))
        .then_with(|| match (left, right) {
            (
                EdgeIncompleteReason::AxisUnsupported(left),
                EdgeIncompleteReason::AxisUnsupported(right),
            ) => left.cmp(right),
            (
                EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: left_kind,
                    reason: left_reason,
                },
                EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: right_kind,
                    reason: right_reason,
                },
            ) => left_kind
                .cmp(right_kind)
                .then_with(|| left_reason.cmp(right_reason)),
            (
                EdgeIncompleteReason::OccurrenceRowsIncomplete {
                    uncovered_roles: left,
                },
                EdgeIncompleteReason::OccurrenceRowsIncomplete {
                    uncovered_roles: right,
                },
            ) => left.cmp(right),
            _ => Ordering::Equal,
        })
}

#[cfg(any(test, feature = "test-support"))]
const fn inverse_reason_rank(reason: &EdgeIncompleteReason) -> u8 {
    match reason {
        EdgeIncompleteReason::AxisUnsupported(_) => 0,
        EdgeIncompleteReason::NoStructuralAdapter => 1,
        EdgeIncompleteReason::UsageListingTruncated => 2,
        EdgeIncompleteReason::UsageAnalysisFailed { .. } => 3,
        EdgeIncompleteReason::Cancelled => 4,
        EdgeIncompleteReason::OccurrenceRowsIncomplete { .. } => 5,
        EdgeIncompleteReason::ReferenceEnumerationIncomplete => 6,
        EdgeIncompleteReason::ForwardResolutionIncomplete => 7,
        EdgeIncompleteReason::ForwardAdmissionIncomplete => 8,
        EdgeIncompleteReason::ForwardMetadataIncomplete => 9,
        EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete => 10,
        EdgeIncompleteReason::InverseIndexResolutionIncomplete => 11,
        EdgeIncompleteReason::InverseIndexAdmissionIncomplete => 12,
        EdgeIncompleteReason::InverseIndexMetadataIncomplete => 13,
        EdgeIncompleteReason::InverseIndexTargetUncovered => 14,
        EdgeIncompleteReason::TimeBudgetExceeded => 15,
        EdgeIncompleteReason::SelectedInverseIndexUnavailable { .. } => 16,
    }
}

/// Atomic outcome of building one selected inverse index.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub enum SelectedReferenceInverseIndexBuildOutcome {
    Complete(SelectedReferenceInverseIndex),
    Incomplete(SelectedReferenceInverseIndex),
    Cancelled,
    Stale,
}

#[cfg(any(test, feature = "test-support"))]
fn inverse_reason(forward: &EdgeIncompleteReason) -> EdgeIncompleteReason {
    match forward {
        EdgeIncompleteReason::AxisUnsupported(EdgeAxis::ForwardProjection) => {
            EdgeIncompleteReason::AxisUnsupported(EdgeAxis::InverseProjection)
        }
        EdgeIncompleteReason::OccurrenceRowsIncomplete { .. }
        | EdgeIncompleteReason::ReferenceEnumerationIncomplete => {
            EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete
        }
        EdgeIncompleteReason::ForwardResolutionIncomplete => {
            EdgeIncompleteReason::InverseIndexResolutionIncomplete
        }
        EdgeIncompleteReason::ForwardAdmissionIncomplete => {
            EdgeIncompleteReason::InverseIndexAdmissionIncomplete
        }
        EdgeIncompleteReason::ForwardMetadataIncomplete => {
            EdgeIncompleteReason::InverseIndexMetadataIncomplete
        }
        reason => reason.clone(),
    }
}

#[cfg(any(test, feature = "test-support"))]
fn inverse_reasons(forward: &EdgeCompleteness) -> Vec<EdgeIncompleteReason> {
    let EdgeCompleteness::Incomplete { reasons } = forward else {
        return Vec::new();
    };
    let mut inverse = Vec::new();
    for reason in reasons {
        push_edge_reason(&mut inverse, inverse_reason(reason));
    }
    inverse.sort_by(canonical_inverse_reason_order);
    inverse
}

#[cfg(any(test, feature = "test-support"))]
fn inverse_index_completeness(forward: &EdgeCompleteness) -> EdgeCompleteness {
    let reasons = inverse_reasons(forward);
    if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    }
}

#[cfg(any(test, feature = "test-support"))]
struct SelectedReferenceInverseIndexAccumulator {
    generation: u64,
    target_domains: HashMap<CodeUnit, FactReferenceEdgeDeclarationDomain>,
    rows_by_target: HashMap<CodeUnit, Vec<ReferenceEdgeRow>>,
    type_or_callable_reasons: Vec<EdgeIncompleteReason>,
    field_reasons: Vec<EdgeIncompleteReason>,
    target_reasons: HashMap<CodeUnit, Vec<EdgeIncompleteReason>>,
    observed_batch_reasons: Vec<EdgeIncompleteReason>,
    edge_count: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedReferenceInverseIndexAccumulator {
    fn new(
        generation: u64,
        target_domains: HashMap<CodeUnit, FactReferenceEdgeDeclarationDomain>,
    ) -> Self {
        Self {
            generation,
            target_domains,
            rows_by_target: HashMap::default(),
            type_or_callable_reasons: Vec::new(),
            field_reasons: Vec::new(),
            target_reasons: HashMap::default(),
            observed_batch_reasons: Vec::new(),
            edge_count: 0,
        }
    }

    fn push_domain_reason(
        &mut self,
        domain: FactReferenceEdgeGapDomain,
        reason: EdgeIncompleteReason,
    ) {
        if domain.affects(FactReferenceEdgeDeclarationDomain::TypeOrCallable) {
            push_edge_reason(&mut self.type_or_callable_reasons, reason.clone());
        }
        if domain.affects(FactReferenceEdgeDeclarationDomain::Field) {
            push_edge_reason(&mut self.field_reasons, reason);
        }
    }

    fn push_target_reason(&mut self, target: CodeUnit, reason: EdgeIncompleteReason) {
        assert!(self.target_domains.contains_key(&target));
        push_edge_reason(self.target_reasons.entry(target).or_default(), reason);
    }

    fn push_lookup_impact_reasons(
        &mut self,
        catalog: &FactReferenceEdgeCatalog<'_>,
        reference: SemanticId,
        gap_domain: FactReferenceEdgeGapDomain,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        for impact in catalog.reference_lookup_impacts(reference)? {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if !gap_domain.affects(impact.domain) {
                continue;
            }
            for target in catalog.graph_targets_for_lookup(impact.lookup)? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let Some(&target_domain) = self.target_domains.get(target) else {
                    return Err(StoreError::new(format!(
                        "selected inverse-index lookup impact names uncovered declaration {target:?}: reference={reference:?}, impact={impact:?}"
                    )));
                };
                if target_domain != impact.domain {
                    return Err(StoreError::new(format!(
                        "selected inverse-index lookup impact domain {impact:?} disagrees with declaration domain {target_domain:?}: reference={reference:?}, target={target:?}"
                    )));
                }
                self.push_target_reason(
                    target.clone(),
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                );
            }
        }
        Ok(!cancellation.is_cancelled())
    }

    fn target_for_semantic(
        &self,
        catalog: &FactReferenceEdgeCatalog<'_>,
        semantic: SemanticId,
        gap_domain: FactReferenceEdgeGapDomain,
    ) -> StoreResult<CodeUnit> {
        let target = catalog.graph_declaration(semantic)?.cloned().ok_or_else(|| {
            StoreError::new(format!(
                "selected inverse-index target-local gap names out-of-graph semantic {semantic:?}"
            ))
        })?;
        let Some(&target_domain) = self.target_domains.get(&target) else {
            return Err(StoreError::new(format!(
                "selected inverse-index target-local gap names uncovered declaration {target:?}"
            )));
        };
        if !gap_domain.affects(target_domain) {
            return Err(StoreError::new(format!(
                "selected inverse-index target-local gap domain {gap_domain:?} does not cover declaration domain {target_domain:?}: target={target:?}"
            )));
        }
        Ok(target)
    }

    fn stage(
        &mut self,
        catalog: &FactReferenceEdgeCatalog<'_>,
        batch: &FactReferenceEdgeBatch,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        if batch.generation() != self.generation {
            return Err(StoreError::new(format!(
                "selected inverse-index batch generation {} differs from index generation {}",
                batch.generation(),
                self.generation
            )));
        }
        for gap in batch.gaps() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            match *gap {
                FactReferenceEdgeGap::IncompleteBinding { reference, domain } => {
                    if !self.push_lookup_impact_reasons(catalog, reference, domain, cancellation)? {
                        return Ok(false);
                    }
                }
                FactReferenceEdgeGap::ReceiverAdmission { target, domain, .. } => {
                    let target = self.target_for_semantic(catalog, target, domain)?;
                    self.push_target_reason(
                        target,
                        EdgeIncompleteReason::InverseIndexAdmissionIncomplete,
                    );
                }
                FactReferenceEdgeGap::MissingSiteMetadata { domain, .. } => self
                    .push_domain_reason(
                        domain,
                        EdgeIncompleteReason::InverseIndexMetadataIncomplete,
                    ),
                FactReferenceEdgeGap::UnknownReferenceOwner { domain, .. }
                | FactReferenceEdgeGap::OutOfGraphReferenceOwner { domain, .. } => self
                    .push_domain_reason(
                        domain,
                        EdgeIncompleteReason::AxisUnsupported(EdgeAxis::OwnerClassification),
                    ),
                FactReferenceEdgeGap::MissingReferenceKind { target, domain, .. } => {
                    let target = self.target_for_semantic(catalog, target, domain)?;
                    self.push_target_reason(
                        target,
                        EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification),
                    );
                }
            }
        }
        if let EdgeCompleteness::Incomplete { reasons } = batch.completeness() {
            for reason in reasons {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                push_edge_reason(&mut self.observed_batch_reasons, reason.clone());
                let accounted = batch
                    .gaps()
                    .iter()
                    .any(|gap| gap.incomplete_reason() == *reason);
                if accounted || *reason == EdgeIncompleteReason::Cancelled {
                    continue;
                }
                let inverse = inverse_reason(reason);
                for domain in [
                    FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                    FactReferenceEdgeDeclarationDomain::Field,
                ] {
                    if !batch.domain_completeness(domain).is_complete() {
                        let gap_domain = match domain {
                            FactReferenceEdgeDeclarationDomain::TypeOrCallable => {
                                FactReferenceEdgeGapDomain::TypeOrCallable
                            }
                            FactReferenceEdgeDeclarationDomain::Field => {
                                FactReferenceEdgeGapDomain::Field
                            }
                        };
                        self.push_domain_reason(gap_domain, inverse.clone());
                    }
                }
            }
        }
        for row in batch.edges() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if row.generation != self.generation || row.provenance != EdgeProvenance::Forward {
                return Err(StoreError::new(format!(
                    "selected inverse-index input row is not a coherent canonical forward-stage row: {row:?}"
                )));
            }
            if !self.target_domains.contains_key(&row.target) {
                return Err(StoreError::new(format!(
                    "selected inverse-index input row names uncovered target {:?}",
                    row.target
                )));
            }
            self.rows_by_target
                .entry(row.target.clone())
                .or_default()
                .push(row.clone());
            self.edge_count = self
                .edge_count
                .checked_add(1)
                .expect("selected inverse-index edge count must fit usize");
        }
        Ok(!cancellation.is_cancelled())
    }

    fn finish(
        mut self,
        summary: FactReferenceEdgeSummary,
        cancellation: &CancellationToken,
    ) -> SelectedReferenceInverseIndexBuildOutcome {
        assert_eq!(summary.generation(), self.generation);
        assert_eq!(summary.edge_count(), self.edge_count);
        if cancellation.is_cancelled() {
            return SelectedReferenceInverseIndexBuildOutcome::Cancelled;
        }
        if matches!(
            summary.completeness(),
            EdgeCompleteness::Incomplete { reasons }
                if reasons.contains(&EdgeIncompleteReason::Cancelled)
        ) {
            return SelectedReferenceInverseIndexBuildOutcome::Cancelled;
        }
        if let EdgeCompleteness::Incomplete { reasons } = summary.completeness() {
            for reason in reasons {
                if cancellation.is_cancelled() {
                    return SelectedReferenceInverseIndexBuildOutcome::Cancelled;
                }
                if self.observed_batch_reasons.contains(reason) {
                    continue;
                }
                let inverse = inverse_reason(reason);
                for domain in [
                    FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                    FactReferenceEdgeDeclarationDomain::Field,
                ] {
                    let domain_status = summary.domain_status(domain);
                    let EdgeCompleteness::Incomplete { reasons } = domain_status.completeness()
                    else {
                        continue;
                    };
                    if !reasons.contains(reason) {
                        continue;
                    }
                    let gap_domain = match domain {
                        FactReferenceEdgeDeclarationDomain::TypeOrCallable => {
                            FactReferenceEdgeGapDomain::TypeOrCallable
                        }
                        FactReferenceEdgeDeclarationDomain::Field => {
                            FactReferenceEdgeGapDomain::Field
                        }
                    };
                    self.push_domain_reason(gap_domain, inverse.clone());
                }
            }
        }
        let complete = summary.completeness().is_complete();
        let index = SelectedReferenceInverseIndex::finish_rows(
            self.generation,
            summary.completeness,
            self.target_domains,
            self.rows_by_target,
            self.type_or_callable_reasons,
            self.field_reasons,
            self.target_reasons,
            summary.reference_count,
            summary.edge_count,
            summary.batch_count,
            cancellation,
        );
        let Some(index) = index else {
            return SelectedReferenceInverseIndexBuildOutcome::Cancelled;
        };
        if complete {
            SelectedReferenceInverseIndexBuildOutcome::Complete(index)
        } else {
            SelectedReferenceInverseIndexBuildOutcome::Incomplete(index)
        }
    }
}

/// Stream the complete selected canonical edge operation once into a
/// generation-bound inverse target index.
#[cfg(any(test, feature = "test-support"))]
pub fn build_selected_reference_inverse_index<S>(
    analyzer: &dyn IAnalyzer,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    catalog: &FactReferenceEdgeCatalog<'_>,
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
) -> StoreResult<SelectedReferenceInverseIndexBuildOutcome>
where
    S: FactResolutionSource,
{
    if cancellation.is_cancelled() {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Cancelled);
    }
    let generation = catalog.generation();
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Stale);
    }
    let coverage =
        validate_selected_reference_edge_coverage(analyzer, selected, catalog, cancellation);
    if cancellation.is_cancelled() {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Stale);
    }
    let Some(coverage) = coverage? else {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Cancelled);
    };
    let mut target_domains = HashMap::default();
    for declaration in catalog.declarations.values() {
        if cancellation.is_cancelled() {
            return Ok(SelectedReferenceInverseIndexBuildOutcome::Cancelled);
        }
        let FactReferenceEdgeDeclaration::Graph(target) = declaration else {
            continue;
        };
        let domain = declaration_domain(target);
        if let Some(previous) = target_domains.insert(target.clone(), domain) {
            assert_eq!(previous, domain);
        }
    }
    let mut accumulator = SelectedReferenceInverseIndexAccumulator::new(generation, target_domains);
    let mut staging_cancelled = false;
    let staged = stage_selected_reference_edge_batches(
        selected,
        catalog,
        maximum_batch_size,
        cancellation,
        &mut |batch| {
            if !coverage.fragments().contains(&batch.fragment()) {
                return Err(StoreError::new(format!(
                    "selected inverse-index batch names an unselected fragment {:?}",
                    batch.fragment()
                )));
            }
            if !accumulator.stage(catalog, batch, cancellation)? {
                staging_cancelled = true;
            }
            Ok(())
        },
    );
    if staging_cancelled || cancellation.is_cancelled() {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Stale);
    }
    let summary = staged?;
    if summary.generation() != generation {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Stale);
    }
    let outcome = accumulator.finish(summary, cancellation);
    if cancellation.is_cancelled() {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedReferenceInverseIndexBuildOutcome::Stale);
    }
    Ok(outcome)
}

/// Whether one source occurrence belongs to the external usage-graph domain.
///
/// Admission is classified from source-owned occurrence and receiver metadata
/// before binding proof is projected. Resolution ambiguity or incompleteness
/// on an occurrence that can never contribute an external edge must not make
/// the external graph incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactReferenceGraphAdmission {
    /// The occurrence can contribute one or more canonical external edges.
    GraphCandidate,
    /// The occurrence is retained for same-owner/LSP inventory, not the
    /// external usage graph.
    SameOwnerInventory,
    /// Receiver evidence is not closed enough to choose between the external
    /// graph and same-owner inventory without guessing.
    Indeterminate(FactReferenceReceiverGap),
    /// The occurrence is a structured dependency of another terminal lookup.
    NonGraphDependency,
    /// The occurrence or target belongs to a declaration domain that the
    /// canonical usage graph intentionally does not represent.
    OutOfGraphDomain,
}

/// Orthogonal output channels and gap retained for one callable target.
///
/// A selected external route remains a graph candidate even when open evidence
/// may add another receiver route. The gap keeps strict graph admission
/// incomplete without erasing the positive route; incumbent `UsageProof`
/// remains an independent function of current binding cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactCallableReceiverTargetAdmission {
    external_candidate: bool,
    same_owner_inventory: bool,
    gap: Option<FactReferenceReceiverGap>,
}

impl FactCallableReceiverTargetAdmission {
    pub const fn external_candidate(self) -> bool {
        self.external_candidate
    }

    pub const fn same_owner_inventory(self) -> bool {
        self.same_owner_inventory
    }

    pub const fn gap(self) -> Option<FactReferenceReceiverGap> {
        self.gap
    }
}

/// Map one target-local callable receiver disposition to its output channels.
///
/// This deliberately accepts one target row instead of a whole answer. A
/// complete ambiguous binding may select self and external receiver routes at
/// once, and open evidence may accompany either positive channel. Consumers
/// must preserve those independent facts rather than collapse the occurrence
/// to one admission decision.
pub const fn fact_callable_receiver_target_admission(
    target: FactCallableReceiverTargetDisposition,
) -> FactCallableReceiverTargetAdmission {
    let disposition = target.disposition();
    let channels = disposition.channels();
    FactCallableReceiverTargetAdmission {
        external_candidate: channels.includes_external(),
        same_owner_inventory: channels.includes_self_receiver(),
        gap: disposition.gap(),
    }
}

/// Target-local callable inventory and proof after receiver admission.
///
/// This is separate from [`FactReferenceTargetProjection`], whose one
/// occurrence-wide admission cannot represent a binding that selects different
/// receiver channels for different targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactCallableReceiverTargetProjection<'answer> {
    target: SemanticId,
    binding_shape: FactReferenceBindingShape<'answer>,
    admission: FactCallableReceiverTargetAdmission,
    proof: UsageProof,
}

impl<'answer> FactCallableReceiverTargetProjection<'answer> {
    pub const fn target(self) -> SemanticId {
        self.target
    }

    pub const fn binding_shape(self) -> FactReferenceBindingShape<'answer> {
        self.binding_shape
    }

    pub const fn admission(self) -> FactCallableReceiverTargetAdmission {
        self.admission
    }

    pub const fn proof(self) -> UsageProof {
        self.proof
    }
}

fn current_target_usage_proof(targets: &[SemanticId]) -> Option<UsageProof> {
    match targets {
        [] => None,
        [_] => Some(UsageProof::Proven),
        _ => Some(UsageProof::Unproven),
    }
}

/// Project one callable target without collapsing sibling receiver channels.
///
/// `UsageProof` retains the incumbent current-world contract: one selected
/// target is proven and several selected alternatives are unproven. Binding
/// completion and receiver admission remain independently available through
/// `binding_shape` and `admission`; an open strict diagnostic does not rewrite
/// the cardinality of the targets already selected by the resolver.
pub fn project_fact_callable_receiver_target(
    binding: &ResolutionAnswer,
    target: FactCallableReceiverTargetDisposition,
) -> FactCallableReceiverTargetProjection<'_> {
    assert!(
        binding.targets().binary_search(&target.target()).is_ok(),
        "one callable receiver disposition must name a retained binding target"
    );
    let binding_shape = classify_fact_reference_binding(binding);
    let admission = fact_callable_receiver_target_admission(target);
    FactCallableReceiverTargetProjection {
        target: target.target(),
        binding_shape,
        admission,
        proof: current_target_usage_proof(binding.targets())
            .expect("a callable target disposition requires one retained binding target"),
    }
}

/// Closed-set status of one fully evaluated reference binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactReferenceBindingShape<'answer> {
    /// Exhaustive evaluation proved that the reference binds no declaration.
    CompleteNegative,
    /// Exhaustive evaluation selected one exact declaration.
    CompleteSingleton(SemanticId),
    /// Exhaustive evaluation selected several exact alternatives.
    ///
    /// Ambiguity is complete resolution evidence, but no individual
    /// alternative is a proven unique usage-graph edge.
    CompleteAmbiguity(&'answer [SemanticId]),
    /// Evaluation retained zero or more best-effort targets while an open
    /// semantic boundary prevented a closed-set result.
    Incomplete {
        retained_targets: &'answer [SemanticId],
        completion: &'answer ResolutionCompletion,
    },
}

/// Graph-level status of one proof-bearing target projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactReferenceProjectionStatus<'answer> {
    /// The occurrence is outside the external graph admission domain.
    Excluded(FactReferenceGraphAdmission),
    /// The admitted binding is a closed negative or closed singleton.
    Complete,
    /// The admitted binding is a closed set with more than one target.
    ///
    /// The target inventory remains exact, but a unique-edge consumer must
    /// record ambiguity instead of selecting an arbitrary alternative.
    Ambiguous,
    /// The admitted binding retained best-effort targets behind an open
    /// semantic boundary.
    Incomplete(&'answer ResolutionCompletion),
    /// Binding retained diagnostic targets, but receiver evidence cannot yet
    /// select their external or same-owner output channel.
    AdmissionIncomplete(FactReferenceReceiverGap),
}

/// Borrowed target/proof inventory for one source occurrence.
///
/// This is the stable resolution-owned seam before source/declaration metadata
/// is mapped into canonical `ReferenceEdgeRow` values. It allocates nothing:
/// all targets borrow the binding's already-canonical target slice and share
/// one proof value. Site ownership, receiver disposition, declaration-domain
/// mapping, and graph-row construction remain separate source-owned steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactReferenceTargetProjection<'answer> {
    binding_shape: FactReferenceBindingShape<'answer>,
    targets: &'answer [SemanticId],
    proof: Option<UsageProof>,
    status: FactReferenceProjectionStatus<'answer>,
}

impl<'answer> FactReferenceTargetProjection<'answer> {
    pub const fn binding_shape(self) -> FactReferenceBindingShape<'answer> {
        self.binding_shape
    }

    pub const fn targets(self) -> &'answer [SemanticId] {
        self.targets
    }

    /// Common proof for every retained target, or `None` when the binding is a
    /// closed negative or the occurrence is outside every target inventory.
    pub const fn proof(self) -> Option<UsageProof> {
        self.proof
    }

    pub const fn status(self) -> FactReferenceProjectionStatus<'answer> {
        self.status
    }
}

/// Classify one binding without consulting typed projection or witness
/// completions.
///
/// Target membership and the binding's aggregate completion are the semantic
/// authority. Witnesses are diagnostics for selected and rejected paths and
/// therefore cannot independently upgrade an incomplete target set.
pub fn classify_fact_reference_binding(
    binding: &ResolutionAnswer,
) -> FactReferenceBindingShape<'_> {
    match binding.completion() {
        ResolutionCompletion::Complete => match binding.targets() {
            [] => FactReferenceBindingShape::CompleteNegative,
            [target] => FactReferenceBindingShape::CompleteSingleton(*target),
            targets => FactReferenceBindingShape::CompleteAmbiguity(targets),
        },
        completion @ ResolutionCompletion::Incomplete(_) => FactReferenceBindingShape::Incomplete {
            retained_targets: binding.targets(),
            completion,
        },
    }
}

/// Project current binding cardinality and strict completion into orthogonal
/// graph fields.
///
/// One retained current target carries the incumbent `Proven` value even when
/// strict semantic completion remains open. Multiple retained alternatives
/// remain `Unproven`. The projection status continues to report complete,
/// ambiguous, binding-incomplete, and receiver-incomplete states without
/// suppressing or relabeling the current target inventory. Structured
/// dependencies and out-of-domain occurrences emit neither inventory nor a
/// graph gap.
pub fn project_fact_reference_targets<'answer>(
    binding: &'answer ResolutionAnswer,
    admission: FactReferenceGraphAdmission,
) -> FactReferenceTargetProjection<'answer> {
    let binding_shape = classify_fact_reference_binding(binding);
    if matches!(
        admission,
        FactReferenceGraphAdmission::NonGraphDependency
            | FactReferenceGraphAdmission::OutOfGraphDomain
    ) {
        return FactReferenceTargetProjection {
            binding_shape,
            targets: &[],
            proof: None,
            status: FactReferenceProjectionStatus::Excluded(admission),
        };
    }

    if admission == FactReferenceGraphAdmission::SameOwnerInventory {
        return FactReferenceTargetProjection {
            binding_shape,
            targets: binding.targets(),
            proof: current_target_usage_proof(binding.targets()),
            status: FactReferenceProjectionStatus::Excluded(admission),
        };
    }

    if let FactReferenceGraphAdmission::Indeterminate(gap) = admission
        && binding_shape != FactReferenceBindingShape::CompleteNegative
    {
        return FactReferenceTargetProjection {
            binding_shape,
            targets: binding.targets(),
            proof: current_target_usage_proof(binding.targets()),
            status: FactReferenceProjectionStatus::AdmissionIncomplete(gap),
        };
    }

    match binding_shape {
        FactReferenceBindingShape::CompleteNegative => FactReferenceTargetProjection {
            binding_shape,
            targets: &[],
            proof: None,
            status: FactReferenceProjectionStatus::Complete,
        },
        FactReferenceBindingShape::CompleteSingleton(_) => FactReferenceTargetProjection {
            binding_shape,
            targets: binding.targets(),
            proof: Some(UsageProof::Proven),
            status: FactReferenceProjectionStatus::Complete,
        },
        FactReferenceBindingShape::CompleteAmbiguity(targets) => FactReferenceTargetProjection {
            binding_shape,
            targets,
            proof: Some(UsageProof::Unproven),
            status: FactReferenceProjectionStatus::Ambiguous,
        },
        FactReferenceBindingShape::Incomplete {
            retained_targets,
            completion,
        } => FactReferenceTargetProjection {
            binding_shape,
            targets: retained_targets,
            proof: current_target_usage_proof(retained_targets),
            status: FactReferenceProjectionStatus::Incomplete(completion),
        },
    }
}

/// Whether a callable occurrence whose source supplied a receiver selected no
/// declaration at all.
///
/// The resolver reports that as a closed negative and the workspace graph then
/// publishes it as proof that this site calls nothing, which is how a
/// declaration with a structurally matching call site is reported dead. It is
/// not proof. A receiver's member set is closed only when the route resolved
/// the receiver to an exact type; a type bound, a bare generic parameter or an
/// inference failure leaves a universe the route never enumerated, and code
/// that compiles does not call a member its receiver lacks.
///
/// The reverse route keeps exactly these sites as unproven candidates for a
/// same-named member (`rust_reverse_rows::undecided_callable_receiver`), so
/// answering the same site here as a decided absence is the two routes
/// contradicting each other about one occurrence. This is the reverse's
/// predicate: a receiver that is an independent declared bound, or one whose
/// evaluation did not close, leaves a member universe the route never
/// enumerated. A receiver the route resolved to one exact type whose member
/// set it did close is a decided absence, and stays one.
///
/// A published receiver origin already asserts the callable namespace and a
/// terminal callable reference site; `FactReferenceSiteMetadata::new` refuses
/// any other combination, so the site shape is read from the origin alone.
fn undecided_callable_receiver_site(answer: &FactBatchedReferenceAnswer) -> bool {
    let binding = answer.answer().binding();
    binding.targets().is_empty()
        && answer.callable_receiver_origin().is_some()
        && (answer.answer().type_bound_receiver()
            || binding.completion() != &ResolutionCompletion::Complete)
}

fn push_edge_reason(reasons: &mut Vec<EdgeIncompleteReason>, reason: EdgeIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn push_edge_gap(gaps: &mut Vec<FactReferenceEdgeGap>, gap: FactReferenceEdgeGap) {
    if !gaps.contains(&gap) {
        gaps.push(gap);
    }
}

fn completeness_for_declaration_domain(
    completeness: &EdgeCompleteness,
    gaps: &[FactReferenceEdgeGap],
    domain: FactReferenceEdgeDeclarationDomain,
    cancellation: &CancellationToken,
) -> Option<EdgeCompleteness> {
    if cancellation.is_cancelled() {
        return None;
    }
    let EdgeCompleteness::Incomplete { reasons } = completeness else {
        return Some(EdgeCompleteness::Complete);
    };
    let mut filtered = Vec::new();
    for reason in reasons {
        if cancellation.is_cancelled() {
            return None;
        }
        let mut has_typed_gap = false;
        let mut affects_domain = false;
        for gap in gaps {
            if cancellation.is_cancelled() {
                return None;
            }
            if &gap.incomplete_reason() != reason {
                continue;
            }
            has_typed_gap = true;
            affects_domain |= gap.domain().affects(domain);
        }
        if !has_typed_gap || affects_domain {
            push_edge_reason(&mut filtered, reason.clone());
        }
    }
    if filtered.is_empty() {
        Some(EdgeCompleteness::Complete)
    } else {
        Some(EdgeCompleteness::Incomplete { reasons: filtered })
    }
}

fn cancelled_edge_batch(fragment: BindingFragmentId, generation: u64) -> FactReferenceEdgeBatch {
    let completeness = EdgeCompleteness::Incomplete {
        reasons: vec![EdgeIncompleteReason::Cancelled],
    };
    FactReferenceEdgeBatch {
        fragment,
        generation,
        reference_count: 0,
        edges: Box::new([]),
        gaps: Box::new([]),
        unresolved_names: None,
        type_or_callable_completeness: completeness.clone(),
        field_completeness: completeness.clone(),
        completeness,
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_fact_reference_edge_batch(
    catalog: &FactReferenceEdgeCatalog<'_>,
    fragment: BindingFragmentId,
    reference_count: usize,
    edges: Vec<ReferenceEdgeRow>,
    gaps: Vec<FactReferenceEdgeGap>,
    reasons: Vec<EdgeIncompleteReason>,
    unresolved_names: Option<Box<[String]>>,
    cancellation: &CancellationToken,
) -> StoreResult<FactReferenceEdgeBatch> {
    let completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    let Some(type_or_callable_completeness) = completeness_for_declaration_domain(
        &completeness,
        &gaps,
        FactReferenceEdgeDeclarationDomain::TypeOrCallable,
        cancellation,
    ) else {
        return Ok(cancelled_edge_batch(fragment, catalog.generation));
    };
    let Some(field_completeness) = completeness_for_declaration_domain(
        &completeness,
        &gaps,
        FactReferenceEdgeDeclarationDomain::Field,
        cancellation,
    ) else {
        return Ok(cancelled_edge_batch(fragment, catalog.generation));
    };
    let edges = edges.into_boxed_slice();
    let gaps = gaps.into_boxed_slice();

    // These are the publication gates. No source-sized work may occur after
    // them: cancellation or an analyzer generation change during either
    // domain scan must discard the fully materialized batch.
    if cancellation.is_cancelled() {
        return Ok(cancelled_edge_batch(fragment, catalog.generation));
    }
    catalog.ensure_current()?;
    if cancellation.is_cancelled() {
        return Ok(cancelled_edge_batch(fragment, catalog.generation));
    }
    Ok(FactReferenceEdgeBatch {
        fragment,
        generation: catalog.generation,
        reference_count,
        edges,
        gaps,
        unresolved_names,
        type_or_callable_completeness,
        field_completeness,
        completeness,
    })
}

fn graph_target(
    catalog: &FactReferenceEdgeCatalog<'_>,
    semantic: SemanticId,
) -> StoreResult<Option<CodeUnit>> {
    Ok(match catalog.declaration(semantic)? {
        FactReferenceEdgeDeclaration::Graph(declaration) => Some(declaration.clone()),
        FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
    })
}

fn binding_may_contribute_graph(
    catalog: &FactReferenceEdgeCatalog<'_>,
    binding: &ResolutionAnswer,
    cancellation: &CancellationToken,
) -> StoreResult<Option<bool>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    if matches!(
        classify_fact_reference_binding(binding),
        FactReferenceBindingShape::Incomplete { .. }
    ) {
        return Ok(Some(true));
    }
    for &target in binding.targets() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if matches!(
            catalog.declaration(target)?,
            FactReferenceEdgeDeclaration::Graph(_)
        ) {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

enum FactReferenceEdgeGapDomainResolution {
    Cancelled,
    Graph(FactReferenceEdgeGapDomain),
}

fn binding_gap_domain_without_metadata(
    catalog: &FactReferenceEdgeCatalog<'_>,
    binding: &ResolutionAnswer,
    cancellation: &CancellationToken,
) -> StoreResult<FactReferenceEdgeGapDomainResolution> {
    if cancellation.is_cancelled() {
        return Ok(FactReferenceEdgeGapDomainResolution::Cancelled);
    }
    if matches!(
        classify_fact_reference_binding(binding),
        FactReferenceBindingShape::Incomplete { .. }
    ) {
        return Ok(FactReferenceEdgeGapDomainResolution::Graph(
            FactReferenceEdgeGapDomain::AnyGraphDeclaration,
        ));
    }
    let mut domain: Option<FactReferenceEdgeGapDomain> = None;
    for &target in binding.targets() {
        if cancellation.is_cancelled() {
            return Ok(FactReferenceEdgeGapDomainResolution::Cancelled);
        }
        let FactReferenceEdgeDeclaration::Graph(declaration) = catalog.declaration(target)? else {
            continue;
        };
        let target_domain = declaration_gap_domain(declaration);
        domain = Some(match domain {
            Some(domain) => domain.union(target_domain),
            None => target_domain,
        });
    }
    Ok(FactReferenceEdgeGapDomainResolution::Graph(
        domain.unwrap_or(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
    ))
}

enum FactProjectedReferenceOwner {
    Unknown,
    Root,
    Declaration(CodeUnit),
}

impl FactProjectedReferenceOwner {
    const fn enclosing(&self) -> Option<&CodeUnit> {
        match self {
            Self::Unknown | Self::Root => None,
            Self::Declaration(owner) => Some(owner),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_reference_edges(
    catalog: &FactReferenceEdgeCatalog<'_>,
    file: &FactReferenceEdgeFile<'_>,
    reference: SemanticId,
    target_semantic: SemanticId,
    range: Range,
    enclosing: Option<&CodeUnit>,
    target: CodeUnit,
    owner_relation: OwnerRelation,
    proof: UsageProof,
    usage_kinds: &[UsageHitKind],
    emitted: &mut HashSet<(CodeUnit, UsageHitKind)>,
    missing_reference_kinds: &mut HashSet<(SemanticId, SemanticId)>,
    edges: &mut Vec<ReferenceEdgeRow>,
    gaps: &mut Vec<FactReferenceEdgeGap>,
    reasons: &mut Vec<EdgeIncompleteReason>,
) {
    let reference_kind = file.classifier.as_ref().and_then(|classifier| {
        classifier.classify_reference_kind(range.start_byte, range.end_byte, &target)
    });
    // Import bindings have an exact editor role but no runtime reference kind.
    // Preserve their rows without inventing a missing call/read classification.
    // A module target is the same shape: the `api` of `crate::api::helper()`
    // names a namespace the path travels through, and no `ReferenceKind` spells
    // a call, a read, a write, or a type use of a namespace. Demanding one made
    // every inventory holding a qualified path report an unsupported
    // kind-classification axis.
    let needs_reference_kind = !target.is_module()
        && usage_kinds
            .iter()
            .any(|kind| !matches!(kind, UsageHitKind::Import | UsageHitKind::Reexport));
    if needs_reference_kind
        && reference_kind.is_none()
        && missing_reference_kinds.insert((reference, target_semantic))
    {
        gaps.push(FactReferenceEdgeGap::MissingReferenceKind {
            reference,
            target: target_semantic,
            domain: declaration_gap_domain(&target),
        });
        push_edge_reason(
            reasons,
            EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification),
        );
    }
    let ast_id = file
        .classifier
        .as_ref()
        .and_then(|classifier| classifier.ast_id(range.start_byte, range.end_byte));
    for &usage_kind in usage_kinds {
        if !emitted.insert((target.clone(), usage_kind)) {
            continue;
        }
        edges.push(ReferenceEdgeRow {
            site: EdgeSite {
                file: file.file().clone(),
                range,
                ast_id: ast_id.clone(),
                enclosing: enclosing.cloned(),
            },
            owner_relation,
            target: target.clone(),
            reference_kind,
            proof,
            usage_kind,
            site_class: SiteClass::UseSite,
            provenance: EdgeProvenance::Forward,
            generation: catalog.generation,
        });
    }
}

fn reference_owner(
    catalog: &FactReferenceEdgeCatalog<'_>,
    file: &FactReferenceEdgeFile<'_>,
    answer: &FactBatchedReferenceAnswer,
    owner: Option<Option<SemanticId>>,
    domain: FactReferenceEdgeGapDomain,
    gaps: &mut Vec<FactReferenceEdgeGap>,
    reasons: &mut Vec<EdgeIncompleteReason>,
) -> StoreResult<FactProjectedReferenceOwner> {
    let Some(owner) = owner else {
        push_edge_gap(
            gaps,
            FactReferenceEdgeGap::UnknownReferenceOwner {
                reference: answer.reference(),
                domain,
            },
        );
        push_edge_reason(
            reasons,
            EdgeIncompleteReason::AxisUnsupported(EdgeAxis::OwnerClassification),
        );
        return Ok(FactProjectedReferenceOwner::Unknown);
    };
    let Some(owner) = owner else {
        return Ok(FactProjectedReferenceOwner::Root);
    };
    match catalog.declaration(owner).map_err(|error| {
        error.context(format!(
            "projecting owner {owner:?} of native reference {:?} in {:?} at {:?}",
            answer.reference(),
            file.file(),
            answer.site_metadata()
        ))
    })? {
        FactReferenceEdgeDeclaration::Graph(owner) => {
            Ok(FactProjectedReferenceOwner::Declaration(owner.clone()))
        }
        FactReferenceEdgeDeclaration::OutOfGraphDomain => {
            // Lexical definitions can contain references without being graph
            // nodes. Retain their exact identity as a projection gap, and do
            // not misattribute the reference to the file root or an outer item.
            push_edge_gap(
                gaps,
                FactReferenceEdgeGap::OutOfGraphReferenceOwner {
                    reference: answer.reference(),
                    owner,
                    domain,
                },
            );
            push_edge_reason(
                reasons,
                EdgeIncompleteReason::AxisUnsupported(EdgeAxis::OwnerClassification),
            );
            Ok(FactProjectedReferenceOwner::Unknown)
        }
    }
}

/// Project one fully evaluated native batch into canonical reference rows.
///
/// Binding proof comes only from the binding answer. Callable output channels
/// come only from the evaluator's target-local receiver disposition. Typed
/// frontier incompleteness that is unrelated to either axis is deliberately
/// absent from this graph-specific completion.
pub fn project_fact_reference_edge_batch(
    catalog: &FactReferenceEdgeCatalog<'_>,
    batch: &FactReferenceBatchAnswer,
    owner_relations: &mut OwnerRelationMemo,
    cancellation: &CancellationToken,
) -> StoreResult<FactReferenceEdgeBatch> {
    catalog.ensure_current()?;
    if cancellation.is_cancelled() {
        return Ok(cancelled_edge_batch(batch.fragment(), catalog.generation));
    }
    let file = catalog.file(batch.fragment())?;
    let mut edges = Vec::new();
    let mut gaps = Vec::new();
    let mut reasons = Vec::new();
    let mut unresolved_names = Some(std::collections::BTreeSet::new());
    let mut missing_reference_kinds = HashSet::default();

    for answer in batch.answers() {
        if cancellation.is_cancelled() {
            return Ok(cancelled_edge_batch(batch.fragment(), catalog.generation));
        }
        let binding = answer.answer().binding();
        let Some(metadata) = answer.site_metadata() else {
            let Some(may_contribute_graph) =
                binding_may_contribute_graph(catalog, binding, cancellation)?
            else {
                return Ok(cancelled_edge_batch(batch.fragment(), catalog.generation));
            };
            if may_contribute_graph {
                let domain =
                    match binding_gap_domain_without_metadata(catalog, binding, cancellation)? {
                        FactReferenceEdgeGapDomainResolution::Cancelled => {
                            return Ok(cancelled_edge_batch(batch.fragment(), catalog.generation));
                        }
                        FactReferenceEdgeGapDomainResolution::Graph(domain) => domain,
                    };
                push_edge_gap(
                    &mut gaps,
                    FactReferenceEdgeGap::MissingSiteMetadata {
                        reference: answer.reference(),
                        domain,
                    },
                );
                push_edge_reason(
                    &mut reasons,
                    EdgeIncompleteReason::ForwardMetadataIncomplete,
                );
            }
            continue;
        };
        // A site id is fragment-local only where nothing renames it. A
        // selected textual-macro capsule is lowered onto its host's fragment
        // and then specialized by its invocation digest, so that two capsules
        // in one host do not collide; `remount` rewrites the semantic and
        // copies the site id through. Recomputing the reference recipe from
        // (fragment, site) is false for every capsule reference, and it took
        // the whole request down when one file used a cross-file macro.
        //
        // The property this projection depends on is that the staged
        // reference belongs to this batch's fragment. What it reads from the
        // metadata is the byte range, which `FactReferenceEdgeFile::range`
        // validates against the file, and the owner, which `reference_owner`
        // resolves through the catalog; the site id has no other consumer
        // here. The pairing is already established upstream:
        // `FactEvaluation::from_seed` asserts the seed's reference is the
        // root it answers, and the demand path checks the query equality.
        assert_eq!(
            answer.reference().ordinal(),
            Some(batch.fragment().ordinal()),
            "a staged native reference is mounted on its own batch's fragment: {:?} in {:?}",
            answer.reference(),
            batch.fragment()
        );
        let range = file.range(metadata.start_byte(), metadata.end_byte())?;

        // Suppress only source-proven receiver dependencies. Bare Java value
        // expressions share the TypeOrValue namespace but remain canonical
        // field occurrences; a manual catalog has no proof and fails
        // conservative by retaining the occurrence in the broad graph domain.
        let Some(reference_domain) = reference_gap_domain(
            file,
            answer.reference(),
            metadata.namespace(),
            metadata.site_kind(),
        ) else {
            continue;
        };

        if matches!(
            classify_fact_reference_binding(binding),
            FactReferenceBindingShape::Incomplete { .. }
        ) || undecided_callable_receiver_site(answer)
        {
            push_edge_gap(
                &mut gaps,
                FactReferenceEdgeGap::IncompleteBinding {
                    reference: answer.reference(),
                    domain: reference_domain,
                },
            );
            push_edge_reason(
                &mut reasons,
                EdgeIncompleteReason::ForwardResolutionIncomplete,
            );
            // What this reference can still reach is bounded by the name it
            // spells. Read that name from the identifier node the parser
            // produced at the site's own range, and normalize it the way a
            // declaration's short name is. A file with no structural adapter
            // has no identifier node to read, and the batch then reports that
            // its unresolved references are unnamed rather than pretending
            // there are none.
            match file.classifier.as_ref().and_then(|classifier| {
                classifier.identifier_at(metadata.start_byte(), metadata.end_byte())
            }) {
                Some(identifier) => {
                    if let Some(names) = unresolved_names.as_mut() {
                        names.insert(strip_raw_identifier_prefix(identifier).to_owned());
                    }
                }
                None => unresolved_names = None,
            }
        }

        if metadata.namespace() == ResolutionNamespace::Callable
            && metadata.site_kind() != ResolutionSiteKind::ImportDeclaration
        {
            let dispositions = answer.callable_receiver_dispositions();
            if dispositions
                .iter()
                .copied()
                .map(FactCallableReceiverTargetDisposition::target)
                .ne(binding.targets().iter().copied())
            {
                return Err(StoreError::new(format!(
                    "callable receiver dispositions disagree with binding targets for {:?}",
                    answer.reference()
                )));
            }
            let mut graph_projections = Vec::new();
            for disposition in dispositions.iter().copied() {
                if cancellation.is_cancelled() {
                    return Ok(cancelled_edge_batch(batch.fragment(), catalog.generation));
                }
                let projection = project_fact_callable_receiver_target(binding, disposition);
                let admission = projection.admission();
                let Some(target) = graph_target(catalog, projection.target())? else {
                    continue;
                };
                if let Some(gap) = admission.gap() {
                    push_edge_gap(
                        &mut gaps,
                        FactReferenceEdgeGap::ReceiverAdmission {
                            reference: answer.reference(),
                            target: projection.target(),
                            gap,
                            domain: declaration_gap_domain(&target),
                        },
                    );
                    push_edge_reason(
                        &mut reasons,
                        EdgeIncompleteReason::ForwardAdmissionIncomplete,
                    );
                }
                if admission.external_candidate() || admission.same_owner_inventory() {
                    graph_projections.push((projection, target));
                }
            }
            if graph_projections.is_empty() {
                continue;
            }
            let projection_domain = graph_projections
                .iter()
                .map(|(_, target)| declaration_gap_domain(target))
                .reduce(FactReferenceEdgeGapDomain::union)
                .expect("one retained graph projection was checked above");
            let enclosing = reference_owner(
                catalog,
                file,
                answer,
                metadata.reference_owner(),
                projection_domain,
                &mut gaps,
                &mut reasons,
            )?;
            let mut emitted = HashSet::default();
            for (projection, target) in graph_projections {
                let admission = projection.admission();
                let usage_kinds: &[UsageHitKind] = match (
                    admission.external_candidate(),
                    admission.same_owner_inventory(),
                ) {
                    (true, true) => &[UsageHitKind::Reference, UsageHitKind::SelfReceiver],
                    (true, false) => &[UsageHitKind::Reference],
                    (false, true) => &[UsageHitKind::SelfReceiver],
                    (false, false) => unreachable!(
                        "a retained callable graph projection must own an output channel"
                    ),
                };
                let owner_relation =
                    owner_relations.classify(catalog.analyzer, enclosing.enclosing(), &target);
                push_reference_edges(
                    catalog,
                    file,
                    answer.reference(),
                    projection.target(),
                    range,
                    enclosing.enclosing(),
                    target,
                    owner_relation,
                    projection.proof(),
                    usage_kinds,
                    &mut emitted,
                    &mut missing_reference_kinds,
                    &mut edges,
                    &mut gaps,
                    &mut reasons,
                );
            }
            continue;
        }

        let projection =
            project_fact_reference_targets(binding, FactReferenceGraphAdmission::GraphCandidate);
        let Some(proof) = projection.proof() else {
            continue;
        };
        let mut graph_targets = Vec::new();
        for &target_semantic in projection.targets() {
            if cancellation.is_cancelled() {
                return Ok(cancelled_edge_batch(batch.fragment(), catalog.generation));
            }
            let Some(target) = graph_target(catalog, target_semantic)? else {
                continue;
            };
            graph_targets.push((target_semantic, target));
        }
        if graph_targets.is_empty() {
            continue;
        }
        let projection_domain = graph_targets
            .iter()
            .map(|(_, target)| declaration_gap_domain(target))
            .reduce(FactReferenceEdgeGapDomain::union)
            .expect("one retained graph target was checked above");
        let enclosing = reference_owner(
            catalog,
            file,
            answer,
            metadata.reference_owner(),
            projection_domain,
            &mut gaps,
            &mut reasons,
        )?;
        let mut emitted = HashSet::default();
        for (target_semantic, target) in graph_targets {
            let owner_relation =
                owner_relations.classify(catalog.analyzer, enclosing.enclosing(), &target);
            let value_like = metadata.namespace() == ResolutionNamespace::Value
                && matches!(
                    metadata.site_kind(),
                    ResolutionSiteKind::ValueReference | ResolutionSiteKind::MemberReference
                );
            let admission_unknown = match &enclosing {
                FactProjectedReferenceOwner::Unknown => true,
                FactProjectedReferenceOwner::Root => false,
                FactProjectedReferenceOwner::Declaration(_) => {
                    owner_relation == OwnerRelation::Unknown
                }
            };
            if value_like && admission_unknown {
                push_edge_gap(
                    &mut gaps,
                    FactReferenceEdgeGap::ReceiverAdmission {
                        reference: answer.reference(),
                        target: target_semantic,
                        gap: FactReferenceReceiverGap::UnresolvedReceiver,
                        domain: declaration_gap_domain(&target),
                    },
                );
                push_edge_reason(
                    &mut reasons,
                    EdgeIncompleteReason::ForwardAdmissionIncomplete,
                );
                continue;
            }
            let same_owner_inventory = value_like
                && (owner_relation == OwnerRelation::SelfReference
                    || (metadata.unqualified()
                        && is_same_owner_member_reference(owner_relation, &target)));
            push_reference_edges(
                catalog,
                file,
                answer.reference(),
                target_semantic,
                range,
                enclosing.enclosing(),
                target,
                owner_relation,
                proof,
                if metadata.site_kind() == ResolutionSiteKind::ImportDeclaration {
                    &[UsageHitKind::Import]
                } else if same_owner_inventory {
                    &[UsageHitKind::SelfReceiver]
                } else {
                    &[UsageHitKind::Reference]
                },
                &mut emitted,
                &mut missing_reference_kinds,
                &mut edges,
                &mut gaps,
                &mut reasons,
            );
        }
    }

    finish_fact_reference_edge_batch(
        catalog,
        batch.fragment(),
        batch.answers().len(),
        edges,
        gaps,
        reasons,
        unresolved_names.map(|names| names.into_iter().collect()),
        cancellation,
    )
}

fn completion_is_cancelled(completion: &ResolutionCompletion) -> bool {
    matches!(
        completion,
        ResolutionCompletion::Incomplete(reasons)
            if reasons.contains(&ResolutionIncompleteReason::Cancelled)
    )
}

fn include_batch_edge_reasons(
    reasons: &mut Vec<EdgeIncompleteReason>,
    completeness: &EdgeCompleteness,
) {
    if let EdgeCompleteness::Incomplete {
        reasons: batch_reasons,
    } = completeness
    {
        for reason in batch_reasons {
            push_edge_reason(reasons, reason.clone());
        }
    }
}

/// Stage every selected reference through the one canonical native edge
/// projector.
///
/// The callback inherits the resolver's rollback contract: its effects remain
/// provisional until this function returns a non-cancelled summary. A source,
/// catalog, or callback error returns `Err`; cancellation returns zero accepted
/// cardinalities plus `Cancelled`, invalidating every prior callback stage.
pub fn stage_selected_reference_edge_batches<S>(
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    catalog: &FactReferenceEdgeCatalog<'_>,
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    stager: &mut dyn FnMut(&FactReferenceEdgeBatch) -> StoreResult<()>,
) -> StoreResult<FactReferenceEdgeSummary>
where
    S: FactResolutionSource,
{
    assert!(
        (1..=MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size),
        "reference edge batch size must be in 1..={MAX_REFERENCE_SEEDS_PER_BATCH}"
    );
    catalog.ensure_current()?;
    let selected_coverage =
        validate_selected_reference_edge_membership(selected, catalog, cancellation)?;
    let mut reasons = Vec::new();
    let mut type_or_callable_reasons = Vec::new();
    let mut field_reasons = Vec::new();
    let mut reference_count = 0_usize;
    let mut edge_count = 0_usize;
    let mut batch_count = 0_usize;
    let mut owner_relations = OwnerRelationMemo::default();
    let summary: FactResolutionBatchSummary =
        selected.stage_all_reference_batches(maximum_batch_size, cancellation, &mut |batch| {
            let Some(coverage) = &selected_coverage else {
                return Err(StoreError::new(format!(
                    "cancelled selected resolution snapshot staged fragment {:?}",
                    batch.fragment()
                )));
            };
            if !coverage.fragments().contains(&batch.fragment()) {
                return Err(StoreError::new(format!(
                    "selected native edge batch names fragment outside snapshot membership: fragment={:?}, selected={:?}",
                    batch.fragment(),
                    coverage.fragments()
                )));
            }
            let projected =
                project_fact_reference_edge_batch(catalog, batch, &mut owner_relations, cancellation)?;
            include_batch_edge_reasons(&mut reasons, projected.completeness());
            include_batch_edge_reasons(
                &mut type_or_callable_reasons,
                projected.domain_completeness(FactReferenceEdgeDeclarationDomain::TypeOrCallable),
            );
            include_batch_edge_reasons(
                &mut field_reasons,
                projected.domain_completeness(FactReferenceEdgeDeclarationDomain::Field),
            );
            if completion_is_cancelled(batch.completion())
                || matches!(
                    projected.completeness(),
                    EdgeCompleteness::Incomplete { reasons }
                        if reasons.contains(&EdgeIncompleteReason::Cancelled)
                )
                || cancellation.is_cancelled()
            {
                return Ok(());
            }
            stager(&projected)?;
            reference_count = reference_count
                .checked_add(projected.reference_count())
                .expect("native edge reference count must fit usize");
            edge_count = edge_count
                .checked_add(projected.edges().len())
                .expect("native edge count must fit usize");
            batch_count = batch_count
                .checked_add(1)
                .expect("native edge batch count must fit usize");
            Ok(())
        })?;
    catalog.ensure_current()?;
    let cancelled = cancellation.is_cancelled()
        || completion_is_cancelled(summary.reference_enumeration_completion())
        || reasons.contains(&EdgeIncompleteReason::Cancelled);
    if cancelled {
        let completeness = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::Cancelled],
        };
        return Ok(FactReferenceEdgeSummary {
            generation: catalog.generation,
            type_or_callable_completeness: completeness.clone(),
            field_completeness: completeness.clone(),
            completeness,
            reference_count: 0,
            edge_count: 0,
            batch_count: 0,
            root_binding_metrics: ResolutionBatchMetrics::default(),
        });
    }
    if summary.reference_enumeration_completion() != &ResolutionCompletion::Complete {
        for domain_reasons in [
            &mut reasons,
            &mut type_or_callable_reasons,
            &mut field_reasons,
        ] {
            push_edge_reason(
                domain_reasons,
                EdgeIncompleteReason::ReferenceEnumerationIncomplete,
            );
        }
    }
    assert_eq!(
        reference_count,
        summary.reference_count(),
        "canonical edge projection must stage every selected reference exactly once"
    );
    assert_eq!(
        batch_count,
        summary.batch_count(),
        "canonical edge projection must preserve selected source batches"
    );
    Ok(FactReferenceEdgeSummary {
        generation: catalog.generation,
        type_or_callable_completeness: if type_or_callable_reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete {
                reasons: type_or_callable_reasons,
            }
        },
        field_completeness: if field_reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete {
                reasons: field_reasons,
            }
        },
        completeness: if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        },
        reference_count,
        edge_count,
        batch_count,
        root_binding_metrics: summary.root_binding_metrics(),
    })
}

#[cfg(test)]
mod tests {
    use crate::analyzer::resolution::fact_lowering::fixture_names::reference_semantic;

    use super::*;
    use crate::analyzer::java::JavaAnalyzer;
    use crate::analyzer::resolution::{
        FactCallableReceiverChannels, FactCallableReceiverDisposition, FactReferenceBatchAnswer,
        LoweredResolutionFragment, LoweredSemanticRole, LoweredTypedFragment, LoweringGapOrigin,
        PreloadedFactResolutionService, ResolutionIncompleteReason, ResolutionWitness,
        SelectedFactResolutionEngine, WitnessStep,
    };
    use crate::analyzer::{
        AnalyzerDelegate, CppAnalyzer, GoAnalyzer, KotlinAnalyzer, MultiAnalyzer,
    };
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionIdentifierRole,
    };
    use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};
    use std::collections::{BTreeMap, BTreeSet};

    const PROJECTOR_SOURCE: &str = "package demo;\n\nclass External {}\n\nclass Owner {\n    int value;\n    void write(External external) {\n        value = 1;\n    }\n}\n";

    struct NativeEdgeProjectionFixture {
        _project: BuiltInlineTestProject,
        analyzer: JavaAnalyzer,
        file: ProjectFile,
        fragment: BindingFragmentId,
        source: &'static str,
        facts: FileResolutionFacts,
        lexical: LoweredResolutionFragment,
        typed: LoweredTypedFragment,
        service: PreloadedFactResolutionService,
        batch: FactReferenceBatchAnswer,
    }

    fn native_edge_projection_fixture() -> NativeEdgeProjectionFixture {
        native_edge_projection_fixture_for(
            "Projector.java",
            PROJECTOR_SOURCE,
            b"native-edge-projector-laws",
            b"native-edge-projector-laws:demo",
        )
    }

    fn native_edge_projection_fixture_for(
        file_name: &str,
        source: &'static str,
        fragment_seed: &[u8],
        package_seed: &[u8],
    ) -> NativeEdgeProjectionFixture {
        let project = InlineTestProject::with_language(Language::Java)
            .file(file_name, source)
            .build();
        native_edge_projection_fixture_from_project(
            project,
            file_name,
            source,
            fragment_seed,
            package_seed,
        )
    }

    fn native_edge_selected_java_base_service(
        fixture: &NativeEdgeProjectionFixture,
    ) -> PreloadedFactResolutionService {
        PreloadedFactResolutionService::from_lowered_fragments(
            [fixture.lexical.clone()],
            [fixture.typed.clone()],
        )
    }

    fn native_edge_projection_fixture_from_project(
        project: BuiltInlineTestProject,
        file_name: &str,
        source: &'static str,
        fragment_seed: &[u8],
        _package_seed: &[u8],
    ) -> NativeEdgeProjectionFixture {
        let file = project.file(file_name);
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts =
            crate::native_resolution_test_support::parse_java_resolution_facts(&file, source);
        let fragment = BindingFragmentId::for_test(fragment_seed);
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let mut batches = Vec::new();
        let summary = service
            .stage_all_reference_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |batch| {
                    batches.push(batch.clone());
                    Ok(())
                },
            )
            .expect("the inline native edge fixture must stage");
        assert_eq!(
            summary.reference_enumeration_completion(),
            &ResolutionCompletion::Complete
        );
        assert_eq!(batches.len(), 1, "one file must produce one retained batch");
        let batch = batches.pop().expect("one retained batch was asserted");
        assert_eq!(batch.fragment(), fragment);

        NativeEdgeProjectionFixture {
            _project: project,
            analyzer,
            file,
            fragment,
            source,
            facts,
            lexical,
            typed,
            service,
            batch,
        }
    }

    fn native_edge_catalog(fixture: &NativeEdgeProjectionFixture) -> FactReferenceEdgeCatalog<'_> {
        FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                fixture.source,
                &fixture.facts,
                &fixture.lexical,
                &fixture.typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("the native edge catalog must match the inline analyzer snapshot")
        .expect("uncancelled native edge catalog construction must publish atomically")
    }

    fn exact_site_row(
        batch: &FactReferenceEdgeBatch,
        start_byte: usize,
        end_byte: usize,
    ) -> &ReferenceEdgeRow {
        let rows = batch
            .edges()
            .iter()
            .filter(|row| {
                row.site.range.start_byte == start_byte && row.site.range.end_byte == end_byte
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            1,
            "one exact canonical row must own site {start_byte}..{end_byte}: rows={rows:?}, all_edges={:?}, gaps={:?}, completeness={:?}",
            batch.edges(),
            batch.gaps(),
            batch.completeness(),
        );
        rows[0]
    }

    fn reference_semantic_at(
        fixture: &NativeEdgeProjectionFixture,
        start_byte: usize,
        end_byte: usize,
    ) -> (SemanticId, ResolutionNamespace, ResolutionSiteKind) {
        let sites = fixture
            .facts
            .sites
            .iter()
            .filter(|site| site.start_byte == start_byte && site.end_byte == end_byte)
            .collect::<Vec<_>>();
        assert_eq!(
            sites.len(),
            1,
            "one exact fact site must own {start_byte}..{end_byte}: {:?}",
            fixture.facts.sites
        );
        let site = sites[0];
        let identifiers = fixture
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.site == site.id && identifier.role == ResolutionIdentifierRole::Reference
            })
            .collect::<Vec<_>>();
        assert_eq!(
            identifiers.len(),
            1,
            "one exact reference identifier must own {site:?}: {:?}",
            fixture.facts.identifiers
        );
        (
            reference_semantic(fixture.fragment, site.id),
            identifiers[0].namespace,
            site.kind,
        )
    }

    #[test]
    fn native_edge_projection_retains_calls_with_out_of_graph_owners() {
        let fixture = native_edge_projection_fixture_for(
            "Projector.java",
            "class Target { static void hit() {} }\nclass Caller { static void run() { Target.hit(); } }\n",
            b"out-of-graph-owner",
            b"out-of-graph-owner-package",
        );
        let mut catalog = native_edge_catalog(&fixture);
        let cancellation = CancellationToken::new();
        let original = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .unwrap();
        let call = original
            .edges()
            .iter()
            .find(|edge| edge.target.identifier() == "hit")
            .expect("the source call has a canonical target");
        let owner = catalog
            .declarations
            .iter()
            .find_map(|(&semantic, declaration)| match declaration {
                FactReferenceEdgeDeclaration::Graph(unit)
                    if Some(unit) == call.site.enclosing.as_ref() =>
                {
                    Some(semantic)
                }
                _ => None,
            })
            .expect("the original call has a graph owner");
        // Model an explicitly lexical-only source owner. The real Rust
        // block-local construct is exercised by the native graph regression.
        catalog
            .declarations
            .insert(owner, FactReferenceEdgeDeclaration::OutOfGraphDomain);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .unwrap();
        let retained = projected
            .edges()
            .iter()
            .find(|edge| edge.target == call.target && edge.site.range == call.site.range)
            .expect("an unavailable owner must not erase the canonical reference");
        assert_eq!(retained.proof, call.proof);
        assert_eq!(retained.site.file, call.site.file);
        assert_eq!(retained.site.enclosing, None);
        assert!(projected.gaps().iter().any(|gap| {
            let FactReferenceEdgeGap::OutOfGraphReferenceOwner {
                reference,
                owner: gap_owner,
                domain: FactReferenceEdgeGapDomain::TypeOrCallable,
            } = gap
            else {
                return false;
            };
            *gap_owner == owner
                && fixture.batch.answers().iter().any(|answer| {
                    answer.reference() == *reference
                        && answer.site_metadata().is_some_and(|metadata| {
                            metadata.start_byte() == call.site.range.start_byte
                                && metadata.end_byte() == call.site.range.end_byte
                        })
                })
        }));
        assert!(
            !projected
                .completeness()
                .covers(EdgeAxis::OwnerClassification)
        );
        assert!(
            projected
                .field_completeness
                .covers(EdgeAxis::OwnerClassification)
        );

        catalog.declarations.remove(&owner);
        let error = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .expect_err("a missing declaration remains corruption, not lexical incompleteness");
        assert!(error.to_string().contains("Projector.java"), "{error}");
    }

    #[test]
    fn native_edge_catalog_rejects_foreign_and_unindexed_declarations() {
        use crate::analyzer::CodeUnitType;

        let fixture = native_edge_projection_fixture();
        let mut catalog = FactReferenceEdgeCatalog::new(&fixture.analyzer);
        let unindexed_file =
            ProjectFile::new(fixture.file.root().to_path_buf(), "unindexed/Missing.java");
        let error = catalog
            .insert_file(
                BindingFragmentId::for_test(b"unindexed-native-edge-file"),
                unindexed_file,
            )
            .expect_err("an unindexed source file must not enter the current catalog");
        assert!(
            error
                .to_string()
                .contains("is absent from the current analyzer index"),
            "unexpected unindexed-file error: {error}"
        );

        let missing = CodeUnit::new(fixture.file.clone(), CodeUnitType::Class, "demo", "Missing");
        let error = catalog
            .insert_graph_declaration(semantic(b"missing-current-declaration"), missing)
            .expect_err("a fabricated declaration must not enter the current catalog");
        assert!(
            error
                .to_string()
                .contains("is absent from the current analyzer index"),
            "unexpected fabricated-declaration error: {error}"
        );

        let foreign_file = ProjectFile::new(
            fixture.file.root().join("foreign-workspace"),
            "Foreign.java",
        );
        let foreign = CodeUnit::new(foreign_file, CodeUnitType::Class, "foreign", "Foreign");
        let error = catalog
            .insert_graph_declaration(semantic(b"foreign-declaration"), foreign)
            .expect_err("a foreign declaration must not enter the current catalog");
        assert!(
            error.to_string().contains("belongs to foreign workspace"),
            "unexpected foreign-declaration error: {error}"
        );
    }

    #[test]
    fn native_edge_catalog_accepts_java_module_descriptor_file_scope() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("module-info.java", "module demo {}\n")
            .build();
        let file = project.file("module-info.java");
        let root = file.root().to_path_buf();
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let mut catalog = FactReferenceEdgeCatalog::new(&analyzer);
        catalog
            .insert_graph_declaration(
                semantic(b"java-module-descriptor-file-scope"),
                CodeUnit::file_scope(file),
            )
            .expect("the canonical graph admits Java module descriptor file scope");

        let unindexed = ProjectFile::new(root, "unindexed/module-info.java");
        let error = catalog
            .insert_graph_declaration(
                semantic(b"unindexed-java-module-descriptor-file-scope"),
                CodeUnit::file_scope(unindexed),
            )
            .expect_err("an unindexed module descriptor must not enter the current catalog");
        assert!(
            error
                .to_string()
                .contains("is absent from the current analyzer index"),
            "unexpected unindexed module-descriptor error: {error}"
        );
    }

    #[test]
    fn selected_fragment_catalog_maps_fields_and_nested_overloads_but_excludes_locals() {
        const SOURCE: &str = "package demo;\nclass Outer {\n    int field;\n    class Nested {\n        Nested() {}\n        void run() {}\n        void run(int parameter) {}\n    }\n}\n";

        let project = InlineTestProject::with_language(Language::Java)
            .file("Outer.java", SOURCE)
            .build();
        let file = project.file("Outer.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts =
            crate::native_resolution_test_support::parse_java_resolution_facts(&file, SOURCE);
        let fragment = BindingFragmentId::for_test(b"selected-edge-catalog-overloads");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file.clone(),
                SOURCE,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("structured selected declarations must map exactly")
        .expect("uncancelled catalog construction must publish");

        let names = facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let sites = facts
            .sites
            .iter()
            .map(|site| (site.id, site))
            .collect::<HashMap<_, _>>();
        let identifiers = facts
            .identifiers
            .iter()
            .map(|identifier| (identifier.site, identifier))
            .collect::<HashMap<_, _>>();
        let mut run_declarations = HashSet::default();
        let mut saw_nested = false;
        let mut saw_field = false;
        let mut saw_out_of_graph_local = false;
        for semantic in lexical
            .semantics()
            .iter()
            .filter(|semantic| semantic.role() == LoweredSemanticRole::Definition)
        {
            let site = sites[&semantic.site()];
            let identifier = identifiers[&semantic.site()];
            assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
            let name = names[&identifier.name];
            let declaration = catalog
                .graph_declaration(semantic.semantic())
                .expect("every selected definition must be classified");
            let is_member_field = site.kind == ResolutionSiteKind::ValueDeclaration
                && facts
                    .member_owners
                    .iter()
                    .any(|owner| owner.member == site.id);
            let is_graph_definition = matches!(
                site.kind,
                ResolutionSiteKind::TypeDeclaration
                    | ResolutionSiteKind::CallableDeclaration
                    | ResolutionSiteKind::ConstructorDeclaration
            ) || is_member_field;
            if is_graph_definition {
                let declaration = declaration
                    .unwrap_or_else(|| panic!("graph definition was excluded: {semantic:?}"));
                assert_eq!(declaration.source(), &file);
                assert_eq!(declaration.terminal_name(), name);
                assert!(analyzer.ranges(declaration).iter().any(|range| {
                    range.start_byte <= site.start_byte && site.end_byte <= range.end_byte
                }));
                if name == "Nested" && site.kind == ResolutionSiteKind::TypeDeclaration {
                    saw_nested = true;
                }
                if name == "run" {
                    assert!(run_declarations.insert(declaration.declaration_id()));
                }
                if is_member_field {
                    assert!(declaration.is_field());
                    saw_field = true;
                }
            } else {
                assert!(declaration.is_none());
                if site.kind == ResolutionSiteKind::ValueDeclaration {
                    saw_out_of_graph_local = true;
                }
            }
        }
        assert!(
            saw_nested,
            "the law must exercise structured nested ownership"
        );
        assert!(
            saw_field,
            "the law must exercise an analyzer-owned canonical field"
        );
        assert!(
            saw_out_of_graph_local,
            "the law must exercise an explicit out-of-graph local or parameter"
        );
        assert_eq!(
            run_declarations.len(),
            2,
            "same-name overloads must retain distinct exact declaration identities"
        );
    }

    #[test]
    fn selected_fragment_catalog_indexes_graph_targets_with_withheld_binders() {
        let fixture = native_edge_projection_fixture();
        let names = fixture
            .facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let field_site = fixture
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Value
                    && names[&identifier.name] == "value"
            })
            .expect("the law source must retain its value field")
            .site;
        let reference_site = fixture
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && names[&identifier.name] == "value"
            })
            .expect("the law source must retain its value reference")
            .site;
        let mut facts = fixture.facts.clone();
        facts
            .binders
            .retain(|binder| binder.declaration != field_site);
        let lexical =
            crate::analyzer::resolution::lower_for_test(fixture.fragment, Language::Java, &facts)
                .lexical()
                .clone();
        assert!(lexical.gaps().iter().any(|gap| {
            gap.site() == field_site && gap.origin() == LoweringGapOrigin::MissingBinder
        }));
        let typed =
            crate::analyzer::resolution::lower_for_test(fixture.fragment, Language::Java, &facts)
                .typed()
                .clone();
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                fixture.source,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("the withheld-binder catalog must remain structurally valid")
        .expect("uncancelled withheld-binder catalog construction must publish");
        let target = catalog
            .graph_targets_for_lookup(lookup_semantic(
                crate::analyzer::resolution::test_shared_names(),
                Language::Java,
                ResolutionNamespace::Value,
                "value",
            ))
            .expect("the withheld field lookup bucket must be readable");
        let [target] = target else {
            panic!("one withheld field target must remain indexed: {target:?}");
        };
        assert!(target.is_field());

        let index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            reference_semantic(fixture.fragment, reference_site),
            FactReferenceEdgeGapDomain::Field,
        );
        assert_lookup_resolution_status(&index, target, true);
    }

    #[test]
    fn selected_fragment_catalog_is_atomic_for_mismatch_duplicate_and_cancellation() {
        let fixture = native_edge_projection_fixture();
        let stale_source = PROJECTOR_SOURCE.replacen("value", "other", 1);
        assert_eq!(
            stale_source.len(),
            PROJECTOR_SOURCE.len(),
            "the stale-source law must not rely on a length mismatch"
        );
        let stale = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                &stale_source,
                &fixture.facts,
                &fixture.lexical,
                &fixture.typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match stale {
            Ok(_) => panic!("same-length stale source and current analyzer bytes must not join"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("differs byte-for-byte"),
            "unexpected stale-source error: {error}"
        );

        let foreign_typed = crate::analyzer::resolution::lower_for_test(
            BindingFragmentId::for_test(b"foreign-selected-edge-typed-fragment"),
            Language::Java,
            &fixture.facts,
        )
        .typed()
        .clone();
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                PROJECTOR_SOURCE,
                &fixture.facts,
                &fixture.lexical,
                &foreign_typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("lexical and typed fragments with different identities must not join"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("lexical and typed fragments disagree"),
            "unexpected typed-fragment identity error: {error}"
        );

        let hostile_fragment = BindingFragmentId::for_test(b"hostile-edge-language-fragment");
        let empty_facts = FileResolutionFacts::default();
        let go_lexical = crate::analyzer::resolution::lower_for_test(
            hostile_fragment,
            Language::Go,
            &FileResolutionFacts::default(),
        )
        .lexical()
        .clone();
        let java_typed = crate::analyzer::resolution::lower_for_test(
            hostile_fragment,
            Language::Java,
            &FileResolutionFacts::default(),
        )
        .typed()
        .clone();
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                PROJECTOR_SOURCE,
                &empty_facts,
                &go_lexical,
                &java_typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("lexical and typed fragments with different languages must not join"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("fragment languages disagree"),
            "unexpected typed-fragment language error: {error}"
        );

        let go_typed = crate::analyzer::resolution::lower_for_test(
            hostile_fragment,
            Language::Go,
            &FileResolutionFacts::default(),
        )
        .typed()
        .clone();
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                PROJECTOR_SOURCE,
                &empty_facts,
                &go_lexical,
                &go_typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("Go artifacts must not join a Java source file"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("declaration language shared by the analyzer-owned file and artifacts"),
            "unexpected artifact/file language error: {error}"
        );

        let hostile_file = ProjectFile::new(
            fixture.file.root().to_path_buf(),
            "src/main/go/demo/Projector.go",
        );
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                hostile_file,
                PROJECTOR_SOURCE,
                &fixture.facts,
                &fixture.lexical,
                &fixture.typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("Java artifacts must not join a Go source file"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("declaration language shared by the analyzer-owned file and artifacts"),
            "unexpected source/artifact language error: {error}"
        );

        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                PROJECTOR_SOURCE,
                &empty_facts,
                &fixture.lexical,
                &fixture.typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("misaligned facts and lowering must fail atomically"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("has no aligned fact semantic"),
            "unexpected selected-fragment mismatch error: {error}"
        );

        let duplicate = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [
                FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &fixture.facts,
                    &fixture.lexical,
                    &fixture.typed,
                    crate::analyzer::resolution::test_shared_names(),
                ),
                FactReferenceEdgeSelectedFragment::new(
                    fixture.file.clone(),
                    PROJECTOR_SOURCE,
                    &fixture.facts,
                    &fixture.lexical,
                    &fixture.typed,
                    crate::analyzer::resolution::test_shared_names(),
                ),
            ],
            &CancellationToken::new(),
        );
        let error = match duplicate {
            Ok(_) => panic!("duplicate selected fragments must fail atomically"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("duplicate selected"),
            "unexpected duplicate selected-fragment error: {error}"
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                PROJECTOR_SOURCE,
                &fixture.facts,
                &fixture.lexical,
                &fixture.typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &cancellation,
        )
        .expect("cancellation is an explicit non-error outcome");
        assert!(cancelled.is_none(), "cancellation must publish no catalog");

        let retry = native_edge_catalog(&fixture);
        assert_eq!(
            retry.generation(),
            fixture.analyzer.project().analysis_generation()
        );
    }

    #[test]
    fn selected_go_type_references_stage_through_shared_edges_and_reject_file_mismatch() {
        const SOURCE: &str = "package demo\n\ntype Item struct{}\n\nfunc Echo(input *Item) *Item {\n    return input\n}\n";

        let project = InlineTestProject::with_language(Language::Go)
            .file("fixture.go", SOURCE)
            .build();
        let file = project.file("fixture.go");
        let analyzer = GoAnalyzer::new(project.project_dyn());
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar must match the shared tree-sitter runtime");
        let tree = parser
            .parse(SOURCE, None)
            .expect("Go edge fixture must produce a syntax tree");
        let facts =
            brokk_bifrost_go::declarations::parse_go_file(&file, SOURCE, &tree).resolution_facts;
        let fragment = BindingFragmentId::for_test(b"selected-go-edge-law");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Go, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Go, &facts)
            .typed()
            .clone();
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file.clone(),
                SOURCE,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("matching Go source and artifacts must form a catalog")
        .expect("uncancelled Go catalog construction must publish");
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let snapshot = SelectedFactResolutionEngine::new(&service)
            .snapshot(&CancellationToken::new())
            .expect("Go selected membership needs no Java placement context");
        let mut batches = Vec::new();
        let summary = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |batch| {
                batches.push(batch.clone());
                Ok(())
            },
        )
        .expect("Go references must stage through the canonical edge path");

        let item_targets = analyzer
            .get_declarations(&file)
            .into_iter()
            .filter(|declaration| declaration.terminal_name() == "Item")
            .collect::<Vec<_>>();
        let [item_target] = item_targets.as_slice() else {
            panic!("one indexed Go Item declaration is required: {item_targets:?}");
        };
        let actual_ranges = batches
            .iter()
            .flat_map(|batch| batch.edges())
            .filter(|edge| &edge.target == item_target)
            .map(|edge| (edge.site.range.start_byte, edge.site.range.end_byte))
            .collect::<BTreeSet<_>>();
        let expected_ranges = SOURCE
            .match_indices("Item")
            .skip(1)
            .map(|(start, spelling)| (start, start + spelling.len()))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_ranges, expected_ranges);
        assert_eq!(
            summary.edge_count(),
            batches
                .iter()
                .map(|batch| batch.edges().len())
                .sum::<usize>()
        );
        assert_eq!(summary.batch_count(), batches.len());

        let java_named_file = ProjectFile::new(file.root().to_path_buf(), "fixture.java");
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                java_named_file,
                SOURCE,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("Go artifacts must not join a Java-named source file"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("declaration language shared by the analyzer-owned file and artifacts"),
            "unexpected Go source/artifact mismatch error: {error}"
        );
    }

    #[test]
    fn include_claimed_extensionless_cpp_uses_declaration_language_authority() {
        const HEADER: &str = "struct Item {};\n";

        let project = InlineTestProject::with_language(Language::Cpp)
            .file("main.cc", "#include \"claimed_header\"\nItem item;\n")
            .file("claimed_header", HEADER)
            .build();
        let file = project.file("claimed_header");
        assert_eq!(file.language(), Language::None);
        assert_eq!(file.declaration_language(), Language::Cpp);
        let analyzer = CppAnalyzer::from_project(project.project().clone());
        assert!(
            analyzer.analyzed_files().contains(&file),
            "the include target must be adopted by the C++ analyzer"
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar must match the shared tree-sitter runtime");
        let tree = parser
            .parse(HEADER, None)
            .expect("extensionless C++ law source must parse");
        let facts =
            brokk_bifrost_cpp::adapter::parse_cpp_file(&file, HEADER, &tree).resolution_facts;
        let fragment = BindingFragmentId::for_test(b"include-claimed-cpp-edge-law");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Cpp, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Cpp, &facts)
            .typed()
            .clone();

        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file,
                HEADER,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("declaration-owned C++ facts must not be rejected by the path extension")
        .expect("a live extensionless C++ catalog must publish");
        assert_eq!(catalog.selected_fragment_files().count(), 1);
    }

    #[test]
    fn source_owned_membership_rejects_missing_and_extra_catalog_fragments_including_zero_rows() {
        let fixture = native_edge_projection_fixture();
        let zero_fragment = BindingFragmentId::for_test(b"selected-zero-row-membership-law");
        let zero_facts = FileResolutionFacts::default();
        let zero_lexical =
            crate::analyzer::resolution::lower_for_test(zero_fragment, Language::Go, &zero_facts)
                .lexical()
                .clone();
        let zero_typed =
            crate::analyzer::resolution::lower_for_test(zero_fragment, Language::Go, &zero_facts)
                .typed()
                .clone();
        assert!(
            zero_lexical
                .semantics()
                .iter()
                .all(|site| site.role() != LoweredSemanticRole::Reference),
            "the zero-row law must not infer membership from reference facts"
        );
        let zero_service =
            PreloadedFactResolutionService::from_lowered_fragments([zero_lexical], [zero_typed]);
        let zero_snapshot = SelectedFactResolutionEngine::new(&zero_service)
            .snapshot(&CancellationToken::new())
            .expect("a zero-reference source fragment still forms selected membership");
        assert_eq!(
            zero_snapshot.selected_fragments(),
            Some([zero_fragment].as_slice())
        );
        let empty_catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            std::iter::empty::<FactReferenceEdgeSelectedFragment<'_>>(),
            &CancellationToken::new(),
        )
        .expect("an empty selected catalog is structurally valid")
        .expect("a live empty catalog publishes");
        let missing = stage_selected_reference_edge_batches(
            &zero_snapshot,
            &empty_catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .expect_err("a catalog missing a zero-reference source fragment must fail closed");
        assert!(
            missing.to_string().contains("cover different fragments"),
            "unexpected missing-fragment error: {missing}"
        );

        let empty_service = PreloadedFactResolutionService::from_lowered_fragments(
            std::iter::empty::<LoweredResolutionFragment>(),
            std::iter::empty::<LoweredTypedFragment>(),
        );
        let empty_snapshot = SelectedFactResolutionEngine::new(&empty_service)
            .snapshot(&CancellationToken::new())
            .expect("an empty selected source forms an exact empty snapshot");
        assert_eq!(
            empty_snapshot.selected_fragments(),
            Some(&[] as &[BindingFragmentId])
        );
        let extra_catalog = native_edge_catalog(&fixture);
        let extra = stage_selected_reference_edge_batches(
            &empty_snapshot,
            &extra_catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .expect_err("a catalog fragment absent from the source inventory must fail closed");
        assert!(
            extra.to_string().contains("cover different fragments"),
            "unexpected extra-fragment error: {extra}"
        );
    }

    #[test]
    fn selected_fragment_catalog_rejects_misaligned_member_kinds_and_receiver_origins() {
        const SOURCE: &str = "package demo;\nclass Owner {\n    void target() {}\n    void caller() { target(); }\n}\n";

        let project = InlineTestProject::with_language(Language::Java)
            .file("Owner.java", SOURCE)
            .build();
        let file = project.file("Owner.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts =
            crate::native_resolution_test_support::parse_java_resolution_facts(&file, SOURCE);
        let fragment = BindingFragmentId::for_test(b"selected-edge-catalog-corruption");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();

        let mut wrong_member_kind = facts.clone();
        let method = wrong_member_kind
            .member_owners
            .iter_mut()
            .find(|owner| owner.kind == ResolutionMemberKind::Method)
            .expect("the law source must publish a method member-owner row");
        method.kind = ResolutionMemberKind::Field;
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file.clone(),
                SOURCE,
                &wrong_member_kind,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("a member kind that contradicts its positioned definition must fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("member ownership is misaligned"),
            "unexpected member-kind mismatch error: {error}"
        );

        let mut hostile_receiver_origin = facts.clone();
        let declaration_site = hostile_receiver_origin
            .identifiers
            .iter()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .expect("the law source must publish a positioned declaration")
            .site;
        hostile_receiver_origin
            .callable_receiver_origins
            .first_mut()
            .expect("the law source must publish an implicit callable receiver origin")
            .reference = declaration_site;
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file,
                SOURCE,
                &hostile_receiver_origin,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("a receiver-origin row that names a definition must fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("callable receiver origin is misaligned"),
            "unexpected receiver-origin mismatch error: {error}"
        );
    }

    #[test]
    fn exact_graph_declaration_selection_rejects_equal_innermost_candidates() {
        use crate::analyzer::CodeUnitType;

        let fixture = native_edge_projection_fixture();
        let semantic =
            fixture
                .lexical
                .semantics()
                .iter()
                .find(|semantic| {
                    semantic.role() == LoweredSemanticRole::Definition
                        && fixture.facts.identifiers.iter().any(|identifier| {
                            identifier.site == semantic.site()
                                && fixture.facts.names.iter().any(|name| {
                                    name.id == identifier.name && name.spelling == "write"
                                })
                        })
                })
                .expect("the fixture must retain its write declaration");
        let site = fixture
            .facts
            .sites
            .iter()
            .find(|site| site.id == semantic.site())
            .expect("the write definition must retain its exact site");
        let declaration = fixture
            .analyzer
            .get_declarations(&fixture.file)
            .into_iter()
            .find(|declaration| {
                declaration.kind() == CodeUnitType::Function
                    && declaration.terminal_name() == "write"
            })
            .expect("the analyzer must retain the write declaration");
        let competing = CodeUnit::with_signature_and_fq(
            fixture.file.clone(),
            declaration.kind(),
            declaration.package_name().to_owned(),
            declaration.short_name().to_owned(),
            Some("(competing)".to_owned()),
            false,
            declaration.fq().clone(),
        );
        let range = Range {
            start_byte: site.start_byte,
            end_byte: site.end_byte,
            start_line: 1,
            end_line: 1,
        };
        let candidates = vec![
            FactReferenceEdgeDeclarationCandidate {
                declaration,
                ranges: vec![range],
            },
            FactReferenceEdgeDeclarationCandidate {
                declaration: competing,
                ranges: vec![range],
            },
        ];
        let selected = select_graph_declaration(
            &fixture.analyzer,
            &fixture.file,
            FactReferenceEdgeSelectedDefinition {
                semantic: semantic.semantic(),
                lookup: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Java,
                    ResolutionNamespace::Callable,
                    "write",
                ),
                lookup_domain: FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                site,
                name: "write",
                owner: None,
            },
            None,
            &candidates,
            &CancellationToken::new(),
        );
        let error = selected.expect_err("equal innermost candidates must be ambiguous");
        assert!(
            error
                .to_string()
                .contains("one current analyzer graph declaration"),
            "unexpected graph ambiguity error: {error}"
        );
    }

    fn semantic(label: &[u8]) -> SemanticId {
        SemanticId::for_test(label)
    }

    #[test]
    fn fact_binding_shape_distinguishes_complete_negative_singleton_ambiguity_and_incomplete() {
        let first = semantic(b"fact-binding-shape-first");
        let second = semantic(b"fact-binding-shape-second");
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            b"fact-binding-shape-open-boundary",
        ));

        let negative = ResolutionAnswer::new([], [], ResolutionCompletion::Complete);
        assert_eq!(
            classify_fact_reference_binding(&negative),
            FactReferenceBindingShape::CompleteNegative
        );

        let singleton = ResolutionAnswer::new([first], [], ResolutionCompletion::Complete);
        assert_eq!(
            classify_fact_reference_binding(&singleton),
            FactReferenceBindingShape::CompleteSingleton(first)
        );

        let ambiguity = ResolutionAnswer::new([first, second], [], ResolutionCompletion::Complete);
        assert_eq!(
            classify_fact_reference_binding(&ambiguity),
            FactReferenceBindingShape::CompleteAmbiguity(&[first, second])
        );

        let completion = ResolutionCompletion::incomplete([reason]);
        let incomplete = ResolutionAnswer::new([first], [], completion.clone());
        assert_eq!(
            classify_fact_reference_binding(&incomplete),
            FactReferenceBindingShape::Incomplete {
                retained_targets: &[first],
                completion: &completion,
            }
        );
    }

    #[test]
    fn fact_binding_shape_uses_binding_completion_instead_of_witness_completion() {
        let reference = semantic(b"fact-binding-shape-reference");
        let target = semantic(b"fact-binding-shape-target");
        let witness_reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            b"fact-binding-shape-witness-only",
        ));
        let binding = ResolutionAnswer::new(
            [target],
            [ResolutionWitness::new(
                reference,
                target,
                [WitnessStep::Node(
                    crate::analyzer::resolution::BindingNodeId::for_test(
                        b"fact-binding-shape-witness-node",
                    ),
                )],
                ResolutionCompletion::incomplete([witness_reason]),
            )],
            ResolutionCompletion::Complete,
        );

        assert_eq!(
            classify_fact_reference_binding(&binding),
            FactReferenceBindingShape::CompleteSingleton(target)
        );
    }

    #[test]
    fn fact_target_projection_uses_current_cardinality_and_retains_strict_status() {
        let first = semantic(b"fact-target-projection-first");
        let second = semantic(b"fact-target-projection-second");
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            b"fact-target-projection-open-boundary",
        ));

        let singleton = ResolutionAnswer::new([first], [], ResolutionCompletion::Complete);
        let projected =
            project_fact_reference_targets(&singleton, FactReferenceGraphAdmission::GraphCandidate);
        assert_eq!(projected.targets(), &[first]);
        assert_eq!(projected.proof(), Some(UsageProof::Proven));
        assert_eq!(projected.status(), FactReferenceProjectionStatus::Complete);

        let ambiguity = ResolutionAnswer::new([first, second], [], ResolutionCompletion::Complete);
        let projected =
            project_fact_reference_targets(&ambiguity, FactReferenceGraphAdmission::GraphCandidate);
        assert_eq!(projected.targets(), &[first, second]);
        assert_eq!(projected.proof(), Some(UsageProof::Unproven));
        assert_eq!(projected.status(), FactReferenceProjectionStatus::Ambiguous);

        let completion = ResolutionCompletion::incomplete([reason]);
        let incomplete = ResolutionAnswer::new([first], [], completion.clone());
        let projected = project_fact_reference_targets(
            &incomplete,
            FactReferenceGraphAdmission::GraphCandidate,
        );
        assert_eq!(projected.targets(), &[first]);
        assert_eq!(projected.proof(), Some(UsageProof::Proven));
        assert_eq!(
            projected.status(),
            FactReferenceProjectionStatus::Incomplete(&completion)
        );

        let incomplete_ambiguity = ResolutionAnswer::new([first, second], [], completion.clone());
        let projected = project_fact_reference_targets(
            &incomplete_ambiguity,
            FactReferenceGraphAdmission::GraphCandidate,
        );
        assert_eq!(projected.targets(), &[first, second]);
        assert_eq!(projected.proof(), Some(UsageProof::Unproven));
        assert_eq!(
            projected.status(),
            FactReferenceProjectionStatus::Incomplete(&completion)
        );
    }

    #[test]
    fn fact_target_projection_preserves_same_owner_and_gates_non_graph_gaps() {
        let target = semantic(b"fact-target-projection-excluded-target");
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            b"fact-target-projection-excluded-reason",
        ));
        let binding =
            ResolutionAnswer::new([target], [], ResolutionCompletion::incomplete([reason]));

        let same_owner = project_fact_reference_targets(
            &binding,
            FactReferenceGraphAdmission::SameOwnerInventory,
        );
        assert_eq!(same_owner.targets(), &[target]);
        assert_eq!(same_owner.proof(), Some(UsageProof::Proven));
        assert_eq!(
            same_owner.status(),
            FactReferenceProjectionStatus::Excluded(
                FactReferenceGraphAdmission::SameOwnerInventory
            )
        );

        for admission in [
            FactReferenceGraphAdmission::NonGraphDependency,
            FactReferenceGraphAdmission::OutOfGraphDomain,
        ] {
            let projected = project_fact_reference_targets(&binding, admission);
            assert!(projected.targets().is_empty());
            assert_eq!(projected.proof(), None);
            assert_eq!(
                projected.status(),
                FactReferenceProjectionStatus::Excluded(admission)
            );
        }
    }

    #[test]
    fn fact_target_projection_marks_indeterminate_receiver_without_losing_targets() {
        let target = semantic(b"fact-target-projection-indeterminate-target");
        let binding = ResolutionAnswer::new([target], [], ResolutionCompletion::Complete);
        let gap = FactReferenceReceiverGap::MissingOrigin;
        let projected = project_fact_reference_targets(
            &binding,
            FactReferenceGraphAdmission::Indeterminate(gap),
        );
        assert_eq!(projected.targets(), &[target]);
        assert_eq!(projected.proof(), Some(UsageProof::Proven));
        assert_eq!(
            projected.status(),
            FactReferenceProjectionStatus::AdmissionIncomplete(gap)
        );

        let negative = ResolutionAnswer::new([], [], ResolutionCompletion::Complete);
        let projected = project_fact_reference_targets(
            &negative,
            FactReferenceGraphAdmission::Indeterminate(gap),
        );
        assert!(projected.targets().is_empty());
        assert_eq!(projected.proof(), None);
        assert_eq!(projected.status(), FactReferenceProjectionStatus::Complete);
    }

    #[test]
    fn callable_receiver_admission_preserves_positive_channels_beside_its_gap() {
        let target = semantic(b"fact-callable-receiver-admission-target");
        let external_open_disposition = FactCallableReceiverTargetDisposition::new(
            target,
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::External,
                Some(FactReferenceReceiverGap::UnresolvedReceiver),
            ),
        );
        let external_open = fact_callable_receiver_target_admission(external_open_disposition);
        assert!(external_open.external_candidate());
        assert!(!external_open.same_owner_inventory());
        assert_eq!(
            external_open.gap(),
            Some(FactReferenceReceiverGap::UnresolvedReceiver)
        );

        let mixed_disposition = FactCallableReceiverTargetDisposition::new(
            target,
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::SelfAndExternal,
                Some(FactReferenceReceiverGap::AmbiguousReceiver),
            ),
        );
        let mixed = fact_callable_receiver_target_admission(mixed_disposition);
        assert!(mixed.external_candidate());
        assert!(mixed.same_owner_inventory());
        assert_eq!(
            mixed.gap(),
            Some(FactReferenceReceiverGap::AmbiguousReceiver)
        );

        let binding = ResolutionAnswer::new([target], [], ResolutionCompletion::Complete);
        let projected = project_fact_callable_receiver_target(&binding, external_open_disposition);
        assert_eq!(projected.target(), target);
        assert_eq!(projected.proof(), UsageProof::Proven);
        assert_eq!(projected.admission(), external_open);

        let closed_external = FactCallableReceiverTargetDisposition::new(
            target,
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::External,
                None,
            ),
        );
        assert_eq!(
            project_fact_callable_receiver_target(&binding, closed_external).proof(),
            UsageProof::Proven
        );
        assert_eq!(
            project_fact_callable_receiver_target(&binding, mixed_disposition).proof(),
            UsageProof::Proven
        );
    }

    #[test]
    fn callable_receiver_projection_retains_gap_only_and_target_local_channels() {
        let first = semantic(b"fact-callable-receiver-target-local-first");
        let second = semantic(b"fact-callable-receiver-target-local-second");
        let mut targets = [first, second];
        targets.sort_unstable();
        let ambiguous_binding = ResolutionAnswer::new(targets, [], ResolutionCompletion::Complete);
        let first_projection = project_fact_callable_receiver_target(
            &ambiguous_binding,
            FactCallableReceiverTargetDisposition::new(
                first,
                FactCallableReceiverDisposition::from_parts(
                    FactCallableReceiverChannels::SelfReceiver,
                    None,
                ),
            ),
        );
        let second_projection = project_fact_callable_receiver_target(
            &ambiguous_binding,
            FactCallableReceiverTargetDisposition::new(
                second,
                FactCallableReceiverDisposition::from_parts(
                    FactCallableReceiverChannels::External,
                    None,
                ),
            ),
        );
        assert!(first_projection.admission().same_owner_inventory());
        assert!(!first_projection.admission().external_candidate());
        assert!(!second_projection.admission().same_owner_inventory());
        assert!(second_projection.admission().external_candidate());
        assert_eq!(first_projection.proof(), UsageProof::Unproven);
        assert_eq!(second_projection.proof(), UsageProof::Unproven);

        let gap_only_binding = ResolutionAnswer::new([first], [], ResolutionCompletion::Complete);
        let gap_only = project_fact_callable_receiver_target(
            &gap_only_binding,
            FactCallableReceiverTargetDisposition::new(
                first,
                FactCallableReceiverDisposition::from_parts(
                    FactCallableReceiverChannels::None,
                    Some(FactReferenceReceiverGap::UnresolvedReceiver),
                ),
            ),
        );
        assert!(!gap_only.admission().external_candidate());
        assert!(!gap_only.admission().same_owner_inventory());
        assert_eq!(
            gap_only.admission().gap(),
            Some(FactReferenceReceiverGap::UnresolvedReceiver)
        );
        assert_eq!(gap_only.proof(), UsageProof::Proven);
    }

    #[test]
    fn receiver_dependencies_suppress_only_type_or_value_value_qualifiers() {
        const SOURCE: &str = "package demo;\n\
class Leaf { int terminal; }\n\
class Owner {\n\
    int bareField;\n\
    Leaf valueQualifier;\n\
    static Leaf memberQualifier;\n\
    int bare() { return bareField; }\n\
    int viaValue() { return valueQualifier.terminal; }\n\
    int viaLocal(Leaf localQualifier) { return localQualifier.terminal; }\n\
    int viaType() { return Owner.memberQualifier.terminal; }\n\
}\n";

        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"native-edge-receiver-dependency-law",
            b"native-edge-receiver-dependency-law:demo",
        );
        let hostile_typed = crate::analyzer::resolution::lower_for_test(
            fixture.fragment,
            Language::Java,
            &FileResolutionFacts::default(),
        )
        .typed()
        .clone();
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                SOURCE,
                &fixture.facts,
                &fixture.lexical,
                &hostile_typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("same-fragment typed receiver drift must fail atomically"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("typed receiver dependencies are misaligned"),
            "unexpected typed receiver drift error: {error}"
        );

        let catalog = native_edge_catalog(&fixture);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("receiver-dependency law source must project");

        let bare_start =
            SOURCE.find("return bareField").expect("bare field read") + "return ".len();
        let value_start = SOURCE
            .find("return valueQualifier")
            .expect("field-valued qualifier")
            + "return ".len();
        let local_start = SOURCE
            .find("return localQualifier")
            .expect("local-valued qualifier")
            + "return ".len();
        let type_start = SOURCE
            .find("return Owner.memberQualifier")
            .expect("type qualifier")
            + "return ".len();
        let intermediate_member_start = type_start + "Owner.".len();
        let value_terminal_start = value_start + "valueQualifier.".len();
        let local_terminal_start = local_start + "localQualifier.".len();
        let type_terminal_start = intermediate_member_start + "memberQualifier.".len();

        let bare = exact_site_row(&projected, bare_start, bare_start + "bareField".len());
        assert!(bare.target.is_field());
        assert_eq!(bare.target.terminal_name(), "bareField");
        let intermediate_member = exact_site_row(
            &projected,
            intermediate_member_start,
            intermediate_member_start + "memberQualifier".len(),
        );
        assert!(intermediate_member.target.is_field());
        assert_eq!(
            intermediate_member.target.terminal_name(),
            "memberQualifier"
        );
        for terminal_start in [
            value_terminal_start,
            local_terminal_start,
            type_terminal_start,
        ] {
            let terminal = exact_site_row(
                &projected,
                terminal_start,
                terminal_start + "terminal".len(),
            );
            assert!(terminal.target.is_field());
            assert_eq!(terminal.target.terminal_name(), "terminal");
        }
        for (start, name) in [
            (value_start, "valueQualifier"),
            (local_start, "localQualifier"),
            (type_start, "Owner"),
        ] {
            assert!(
                projected.edges().iter().all(|row| {
                    row.site.range.start_byte != start
                        || row.site.range.end_byte != start + name.len()
                }),
                "a source-proven ValueReference receiver dependency must not publish a canonical row: start={start}, name={name:?}, edges={:?}",
                projected.edges()
            );
        }

        let file = catalog.file(fixture.fragment).expect("selected file");
        let (bare_reference, bare_namespace, bare_kind) =
            reference_semantic_at(&fixture, bare_start, bare_start + "bareField".len());
        assert_eq!(
            reference_gap_domain(file, bare_reference, bare_namespace, bare_kind),
            Some(FactReferenceEdgeGapDomain::Field),
            "a selected bare Java value expression is field-domain, not a qualifier"
        );
        for (start, name) in [
            (value_start, "valueQualifier"),
            (local_start, "localQualifier"),
            (type_start, "Owner"),
        ] {
            let (reference, namespace, kind) =
                reference_semantic_at(&fixture, start, start + name.len());
            assert_eq!(
                reference_gap_domain(file, reference, namespace, kind),
                None,
                "the exact projection-to-receiver join must suppress {name:?}"
            );
        }
        let (member_reference, member_namespace, member_kind) = reference_semantic_at(
            &fixture,
            intermediate_member_start,
            intermediate_member_start + "memberQualifier".len(),
        );
        assert_eq!(
            reference_gap_domain(file, member_reference, member_namespace, member_kind),
            Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
            "an intermediate MemberReference remains canonical even when its value feeds a receiver"
        );

        let mut manual = FactReferenceEdgeCatalog::new(&fixture.analyzer);
        manual
            .insert_file(fixture.fragment, fixture.file.clone())
            .expect("manual catalog file");
        let manual_file = manual.file(fixture.fragment).expect("manual file");
        let (type_reference, type_namespace, type_kind) =
            reference_semantic_at(&fixture, type_start, type_start + "Owner".len());
        assert_eq!(
            reference_gap_domain(manual_file, type_reference, type_namespace, type_kind),
            Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
            "a manual catalog without the structured join must fail conservative"
        );
    }

    #[test]
    fn field_only_uncertainty_preserves_type_or_callable_domain_completeness() {
        const SOURCE: &str =
            "package demo;\nclass Owner {\n    int value;\n    void write() { value = 1; }\n}\n";

        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"native-edge-field-domain-law",
            b"native-edge-field-domain-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("field-only native edges must project");
        assert!(
            projected.edges().iter().any(|row| row.target.is_field()),
            "fields must remain canonical edge declarations: {:?}",
            projected.edges()
        );
        assert!(
            !projected.completeness().is_complete(),
            "the broad canonical domain must retain field uncertainty: {:?}",
            projected.gaps()
        );
        let type_or_callable =
            projected.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
        assert_eq!(
            type_or_callable.domain(),
            FactReferenceEdgeDeclarationDomain::TypeOrCallable
        );
        assert_eq!(type_or_callable.generation(), catalog.generation());
        assert_eq!(type_or_callable.completeness(), &EdgeCompleteness::Complete);
        assert!(
            !projected
                .domain_status(FactReferenceEdgeDeclarationDomain::Field)
                .completeness()
                .is_complete(),
            "field-only gaps must still make the field domain incomplete"
        );
        assert!(
            projected.gaps().iter().all(|gap| {
                gap.domain()
                    .affects(FactReferenceEdgeDeclarationDomain::Field)
                    && !gap
                        .domain()
                        .affects(FactReferenceEdgeDeclarationDomain::TypeOrCallable)
            }),
            "the law source must retain only field-domain gaps: {:?}",
            projected.gaps()
        );

        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the field-domain selected snapshot must assemble");
        let summary = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .expect("field-domain canonical staging must finish");
        let type_or_callable =
            summary.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
        assert_eq!(
            type_or_callable.domain(),
            FactReferenceEdgeDeclarationDomain::TypeOrCallable
        );
        assert_eq!(type_or_callable.generation(), catalog.generation());
        assert_eq!(type_or_callable.completeness(), &EdgeCompleteness::Complete);
        assert!(
            !summary.completeness().is_complete(),
            "summary canonical completeness must retain field-only gaps"
        );
    }

    #[test]
    fn edge_summary_retains_root_batch_metrics_and_cancellation_resets_them() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected edge-metrics snapshot must assemble");

        let expected_metrics = snapshot
            .stage_all_reference_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |_| Ok(()),
            )
            .expect("the underlying selected batches must finish")
            .root_binding_metrics();
        assert_ne!(
            expected_metrics,
            ResolutionBatchMetrics::default(),
            "the law source must exercise shared lexical root batches"
        );
        let summary = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .expect("canonical edge staging must finish");
        assert_eq!(summary.root_binding_metrics(), expected_metrics);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
            &mut |_| panic!("a pre-cancelled edge operation must not stage a batch"),
        )
        .expect("cancellation is a semantic edge summary");
        assert_eq!(
            cancelled.root_binding_metrics(),
            ResolutionBatchMetrics::default()
        );
    }

    #[test]
    fn missing_metadata_domain_fails_closed() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let field = catalog
            .declarations
            .iter()
            .find_map(|(&semantic, declaration)| match declaration {
                FactReferenceEdgeDeclaration::Graph(declaration) if declaration.is_field() => {
                    Some(semantic)
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .expect("the fixture must map its field declaration");
        let complete_field = ResolutionAnswer::new([field], [], ResolutionCompletion::Complete);
        assert!(matches!(
            binding_gap_domain_without_metadata(
                &catalog,
                &complete_field,
                &CancellationToken::new(),
            )
            .expect("complete retained targets must classify"),
            FactReferenceEdgeGapDomainResolution::Graph(FactReferenceEdgeGapDomain::Field)
        ));

        let incomplete_field = ResolutionAnswer::new(
            [field],
            [],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                semantic(b"missing-metadata-open-binding"),
            )]),
        );
        assert!(matches!(
            binding_gap_domain_without_metadata(
                &catalog,
                &incomplete_field,
                &CancellationToken::new(),
            )
            .expect("an open binding without metadata must classify"),
            FactReferenceEdgeGapDomainResolution::Graph(
                FactReferenceEdgeGapDomain::AnyGraphDeclaration
            )
        ));
    }

    #[test]
    fn native_edge_projector_splits_non_callable_same_owner_and_external_targets() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("the inline native edge batch must project");
        assert_eq!(
            projected.completeness(),
            &EdgeCompleteness::Incomplete {
                reasons: vec![
                    EdgeIncompleteReason::ForwardResolutionIncomplete,
                    EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification),
                ],
            }
        );
        assert!(
            projected.completeness().covers(EdgeAxis::InverseProjection),
            "semantic completeness alone does not encode producer provenance"
        );
        assert!(
            !projected.covers(EdgeAxis::InverseProjection),
            "a forward-native batch must never vouch for inverse projection"
        );
        assert_eq!(projected.generation(), catalog.generation());
        assert_eq!(projected.reference_count(), fixture.batch.answers().len());

        let same_owner_start = PROJECTOR_SOURCE
            .find("value = 1")
            .expect("the fixture must retain its same-owner value location reference");
        let same_owner = exact_site_row(
            &projected,
            same_owner_start,
            same_owner_start + "value".len(),
        );
        assert_eq!(same_owner.target.terminal_name(), "value");
        assert_eq!(same_owner.owner_relation, OwnerRelation::SameOwner);
        assert_eq!(same_owner.usage_kind, UsageHitKind::SelfReceiver);
        assert_eq!(same_owner.proof, UsageProof::Proven);
        assert_eq!(
            same_owner.site.range,
            Range {
                start_byte: same_owner_start,
                end_byte: same_owner_start + "value".len(),
                start_line: 8,
                end_line: 8,
            }
        );
        assert!(same_owner.site.ast_id.is_some());
        assert_eq!(same_owner.provenance, EdgeProvenance::Forward);
        assert_eq!(same_owner.generation, catalog.generation());

        let external_start = PROJECTOR_SOURCE
            .find("External external")
            .expect("the fixture must retain its external type reference");
        let external = exact_site_row(
            &projected,
            external_start,
            external_start + "External".len(),
        );
        assert_eq!(external.target.terminal_name(), "External");
        assert_eq!(external.owner_relation, OwnerRelation::External);
        assert_eq!(external.usage_kind, UsageHitKind::Reference);
        assert_eq!(external.proof, UsageProof::Proven);
        assert_eq!(
            external.site.range,
            Range {
                start_byte: external_start,
                end_byte: external_start + "External".len(),
                start_line: 7,
                end_line: 7,
            }
        );
        assert!(external.site.ast_id.is_some());
        assert_eq!(external.provenance, EdgeProvenance::Forward);
        assert_eq!(external.generation, catalog.generation());
    }

    #[test]
    fn native_edge_projector_cancellation_discards_the_batch_and_retry_is_exact() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let baseline = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("the baseline native edge batch must project");

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .expect("cancellation is a semantic result");
        assert_eq!(cancelled.fragment(), fixture.fragment);
        assert_eq!(cancelled.generation(), catalog.generation());
        assert_eq!(cancelled.reference_count(), 0);
        assert!(cancelled.edges().is_empty());
        assert!(cancelled.gaps().is_empty());
        assert_eq!(
            cancelled.completeness(),
            &EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::Cancelled],
            }
        );
        assert!(!cancelled.covers(EdgeAxis::ForwardProjection));
        assert!(!cancelled.covers(EdgeAxis::InverseProjection));

        let retry = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("a fresh retry must project");
        assert_eq!(retry, baseline);
    }

    #[test]
    fn native_edge_publication_gates_domain_scan_cancellation_and_stale_generation() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let gaps = (0..128)
            .map(|ordinal| FactReferenceEdgeGap::MissingReferenceKind {
                reference: SemanticId::for_test(
                    format!("late-domain-reference-{ordinal}").as_bytes(),
                ),
                target: SemanticId::for_test(format!("late-domain-target-{ordinal}").as_bytes()),
                domain: FactReferenceEdgeGapDomain::Field,
            })
            .collect::<Vec<_>>();
        let cancellation = CancellationToken::cancel_after_checks_for_test(16);
        let cancelled = finish_fact_reference_edge_batch(
            &catalog,
            fixture.fragment,
            128,
            Vec::new(),
            gaps,
            vec![EdgeIncompleteReason::AxisUnsupported(
                EdgeAxis::KindClassification,
            )],
            None,
            &cancellation,
        )
        .expect("late domain-scan cancellation is semantic");
        assert_eq!(cancelled.reference_count(), 0);
        assert!(cancelled.edges().is_empty());
        assert!(cancelled.gaps().is_empty());
        assert_eq!(
            cancelled.completeness(),
            &EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::Cancelled],
            },
            "cancellation during the source-sized domain scan must discard the materialized batch"
        );

        let mut stale_catalog = native_edge_catalog(&fixture);
        stale_catalog.generation = stale_catalog
            .generation
            .checked_add(1)
            .expect("test generation must advance");
        let error = finish_fact_reference_edge_batch(
            &stale_catalog,
            fixture.fragment,
            0,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            &CancellationToken::new(),
        )
        .expect_err("a generation change before the final publication gate must reject the batch");
        assert!(
            error
                .to_string()
                .contains("is stale against current generation"),
            "unexpected stale-generation publication error: {error}"
        );
    }

    fn selected_inverse_index(
        outcome: SelectedReferenceInverseIndexBuildOutcome,
    ) -> SelectedReferenceInverseIndex {
        match outcome {
            SelectedReferenceInverseIndexBuildOutcome::Complete(index)
            | SelectedReferenceInverseIndexBuildOutcome::Incomplete(index) => index,
            SelectedReferenceInverseIndexBuildOutcome::Cancelled => {
                panic!("an uncancelled selected inverse-index law must not cancel")
            }
            SelectedReferenceInverseIndexBuildOutcome::Stale => {
                panic!("a current selected inverse-index law must not become stale")
            }
        }
    }

    fn graph_targets(catalog: &FactReferenceEdgeCatalog<'_>) -> Vec<CodeUnit> {
        let mut targets = catalog
            .declarations
            .values()
            .filter_map(|declaration| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) => Some(target.clone()),
                FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.dedup();
        targets
    }

    fn reference_semantic_named(
        fixture: &NativeEdgeProjectionFixture,
        spelling: &str,
        namespace: ResolutionNamespace,
        kind: ResolutionSiteKind,
    ) -> SemanticId {
        let names = fixture
            .facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let sites = fixture
            .facts
            .sites
            .iter()
            .map(|site| (site.id, site))
            .collect::<HashMap<_, _>>();
        let matches = fixture
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == namespace
                    && names[&identifier.name] == spelling
                    && sites[&identifier.site].kind == kind
            })
            .map(|identifier| reference_semantic(fixture.fragment, identifier.site))
            .collect::<Vec<_>>();
        let [reference] = matches.as_slice() else {
            panic!(
                "one exact reference must match spelling={spelling:?}, namespace={namespace:?}, kind={kind:?}: {matches:?}"
            );
        };
        *reference
    }

    fn inverse_index_for_binding_gap(
        catalog: &FactReferenceEdgeCatalog<'_>,
        fragment: BindingFragmentId,
        reference: SemanticId,
        domain: FactReferenceEdgeGapDomain,
    ) -> SelectedReferenceInverseIndex {
        let target_domains = graph_targets(catalog)
            .into_iter()
            .map(|target| {
                let domain = declaration_domain(&target);
                (target, domain)
            })
            .collect::<HashMap<_, _>>();
        let open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
        };
        let domain_completeness = |candidate| {
            if domain.affects(candidate) {
                open.clone()
            } else {
                EdgeCompleteness::Complete
            }
        };
        let batch = FactReferenceEdgeBatch {
            fragment,
            generation: catalog.generation(),
            reference_count: 1,
            edges: Box::new([]),
            gaps: vec![FactReferenceEdgeGap::IncompleteBinding { reference, domain }]
                .into_boxed_slice(),
            unresolved_names: None,
            completeness: open.clone(),
            type_or_callable_completeness: domain_completeness(
                FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            ),
            field_completeness: domain_completeness(FactReferenceEdgeDeclarationDomain::Field),
        };
        let mut accumulator =
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains);
        assert!(
            accumulator
                .stage(catalog, &batch, &CancellationToken::new())
                .expect("the structured lookup-impact gap must stage")
        );
        selected_inverse_index(accumulator.finish(
            FactReferenceEdgeSummary {
                generation: catalog.generation(),
                completeness: open,
                type_or_callable_completeness: batch.type_or_callable_completeness.clone(),
                field_completeness: batch.field_completeness.clone(),
                reference_count: 1,
                edge_count: 0,
                batch_count: 1,
                root_binding_metrics: ResolutionBatchMetrics::default(),
            },
            &CancellationToken::new(),
        ))
    }

    fn assert_lookup_resolution_status(
        index: &SelectedReferenceInverseIndex,
        target: &CodeUnit,
        incomplete: bool,
    ) {
        let expected = if incomplete {
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexResolutionIncomplete],
            }
        } else {
            EdgeCompleteness::Complete
        };
        assert_eq!(
            index.inverse_for(target).completeness,
            expected,
            "{target:?}"
        );
    }

    fn assert_same_inverse_index(
        left: &SelectedReferenceInverseIndex,
        right: &SelectedReferenceInverseIndex,
        targets: &[CodeUnit],
    ) {
        assert_eq!(left.generation(), right.generation());
        assert_eq!(left.run_completeness(), right.run_completeness());
        assert_eq!(left.target_count(), right.target_count());
        assert_eq!(left.nonempty_target_count(), right.nonempty_target_count());
        assert_eq!(left.reference_count(), right.reference_count());
        assert_eq!(left.edge_count(), right.edge_count());
        for target in targets {
            let left = left.inverse_for(target);
            let right = right.inverse_for(target);
            assert_eq!(left.edges, right.edges, "row order differs for {target:?}");
            assert_eq!(left.completeness, right.completeness);
            assert_eq!(left.provenance, right.provenance);
            assert_eq!(left.generation, right.generation);
        }
    }

    #[test]
    fn selected_inverse_index_preserves_multi_target_rows_and_batch_independent_order() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected inverse-index snapshot must assemble");
        let one_at_a_time = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("one-row selected inverse-index staging must succeed"),
        );
        let broad = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
            )
            .expect("broad selected inverse-index staging must succeed"),
        );
        assert_eq!(broad.batch_count(), 1);
        assert_eq!(one_at_a_time.batch_count(), one_at_a_time.reference_count());
        assert!(one_at_a_time.batch_count() > broad.batch_count());
        let targets = graph_targets(&catalog);
        assert_same_inverse_index(&one_at_a_time, &broad, &targets);
        assert_eq!(broad.target_count(), targets.len());
        assert!(
            broad.nonempty_target_count() > 1,
            "the law source must exercise multiple incoming target buckets"
        );

        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("the comparison forward batch must project");
        for target in targets {
            let mut expected = projected
                .edges()
                .iter()
                .filter(|row| row.target == target)
                .cloned()
                .collect::<Vec<_>>();
            assert!(sort_inverse_rows_with_cancellation(
                &mut expected,
                &CancellationToken::new()
            ));
            for row in &mut expected {
                row.provenance = EdgeProvenance::Inverse;
            }
            let indexed = broad.inverse_for(&target);
            assert_eq!(indexed.edges, expected);
            assert_eq!(indexed.provenance, EdgeProvenance::Inverse);
            assert!(
                indexed
                    .edges
                    .iter()
                    .all(|row| row.provenance == EdgeProvenance::Inverse)
            );
        }
    }

    #[test]
    fn selected_inverse_index_localizes_open_bindings_by_exact_lookup_impact() {
        const SOURCE: &str = "package demo;\nclass Owner {\n    class open {}\n    int open;\n    int closed;\n    void open() {}\n    void open(int value) {}\n    void closedCall() {}\n    void use(Owner receiver) {\n        int bare = open;\n        open();\n        Object member = receiver.open;\n        missing();\n    }\n}\n";
        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"selected-inverse-lookup-impact-law",
            b"selected-inverse-lookup-impact-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let targets = graph_targets(&catalog);
        let named_targets = |spelling: &str| {
            targets
                .iter()
                .filter(|target| target.terminal_name() == spelling)
                .cloned()
                .collect::<Vec<_>>()
        };
        let open_targets = named_targets("open");
        let open_field = open_targets
            .iter()
            .find(|target| target.is_field())
            .expect("the law source must retain the open field");
        let closed_field = named_targets("closed")
            .into_iter()
            .find(CodeUnit::is_field)
            .expect("the law source must retain the closed field");
        let open_type = open_targets
            .iter()
            .find(|target| target.is_class())
            .expect("the law source must retain the nested open type");
        let open_callables = open_targets
            .iter()
            .filter(|target| target.is_callable())
            .collect::<Vec<_>>();
        assert_eq!(open_callables.len(), 2, "both overloads must be indexed");

        let bare_open = reference_semantic_named(
            &fixture,
            "open",
            ResolutionNamespace::Value,
            ResolutionSiteKind::ValueReference,
        );
        assert_eq!(
            catalog
                .reference_lookup_impacts(bare_open)
                .expect("the bare reference must own lookup impacts"),
            &[FactReferenceEdgeLookupImpact {
                lookup: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Java,
                    ResolutionNamespace::Value,
                    "open"
                ),
                domain: FactReferenceEdgeDeclarationDomain::Field,
            }],
            "a Java value occurrence is admitted only as a field"
        );
        let bare_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            bare_open,
            FactReferenceEdgeGapDomain::Field,
        );
        assert!(!bare_index.run_completeness().is_complete());
        assert_lookup_resolution_status(&bare_index, open_field, true);
        assert_lookup_resolution_status(&bare_index, &closed_field, false);
        assert_lookup_resolution_status(&bare_index, open_type, false);
        for callable in &open_callables {
            assert_lookup_resolution_status(&bare_index, callable, false);
        }

        let callable_open = reference_semantic_named(
            &fixture,
            "open",
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
        );
        let callable_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            callable_open,
            FactReferenceEdgeGapDomain::TypeOrCallable,
        );
        for callable in &open_callables {
            assert_lookup_resolution_status(&callable_index, callable, true);
        }
        assert_lookup_resolution_status(&callable_index, open_field, false);
        assert_lookup_resolution_status(&callable_index, open_type, false);

        let member_open = reference_semantic_named(
            &fixture,
            "open",
            ResolutionNamespace::TypeOrValue,
            ResolutionSiteKind::MemberReference,
        );
        let mut expected_member_impacts = vec![
            FactReferenceEdgeLookupImpact {
                lookup: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Java,
                    ResolutionNamespace::Value,
                    "open",
                ),
                domain: FactReferenceEdgeDeclarationDomain::Field,
            },
            FactReferenceEdgeLookupImpact {
                lookup: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Java,
                    ResolutionNamespace::Type,
                    "open",
                ),
                domain: FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            },
        ];
        expected_member_impacts.sort_unstable();
        assert_eq!(
            catalog
                .reference_lookup_impacts(member_open)
                .expect("the member reference must own both exact routes"),
            expected_member_impacts,
        );
        let member_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            member_open,
            FactReferenceEdgeGapDomain::AnyGraphDeclaration,
        );
        assert_lookup_resolution_status(&member_index, open_field, true);
        assert_lookup_resolution_status(&member_index, open_type, true);
        for callable in &open_callables {
            assert_lookup_resolution_status(&member_index, callable, false);
        }
        assert_lookup_resolution_status(&member_index, &closed_field, false);

        let missing = reference_semantic_named(
            &fixture,
            "missing",
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
        );
        let missing_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            missing,
            FactReferenceEdgeGapDomain::TypeOrCallable,
        );
        assert!(!missing_index.run_completeness().is_complete());
        for target in targets {
            assert_lookup_resolution_status(&missing_index, &target, false);
        }
    }

    #[test]
    fn selected_inverse_lookup_join_discards_late_cancellation_and_retries_cleanly() {
        let mut source = String::from("package demo;\nclass Owner {\n");
        for arity in 0..32 {
            source.push_str("  void fanout(");
            for parameter in 0..arity {
                if parameter > 0 {
                    source.push_str(", ");
                }
                source.push_str(&format!("int p{parameter}"));
            }
            source.push_str(") {}\n");
        }
        source.push_str("  void unrelated() {}\n  void use() { fanout(); }\n}\n");
        let source = Box::leak(source.into_boxed_str());
        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            source,
            b"selected-inverse-late-lookup-cancellation-law",
            b"selected-inverse-late-lookup-cancellation-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let reference = reference_semantic_named(
            &fixture,
            "fanout",
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
        );
        let fanout_targets = catalog
            .graph_targets_for_lookup(lookup_semantic(
                crate::analyzer::resolution::test_shared_names(),
                Language::Java,
                ResolutionNamespace::Callable,
                "fanout",
            ))
            .expect("the fanout target bucket must be readable");
        assert_eq!(fanout_targets.len(), 32);
        let target_domains = graph_targets(&catalog)
            .into_iter()
            .map(|target| {
                let domain = declaration_domain(&target);
                (target, domain)
            })
            .collect::<HashMap<_, _>>();
        let open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
        };
        let batch = FactReferenceEdgeBatch {
            fragment: fixture.fragment,
            generation: catalog.generation(),
            reference_count: 1,
            edges: Box::new([]),
            gaps: vec![FactReferenceEdgeGap::IncompleteBinding {
                reference,
                domain: FactReferenceEdgeGapDomain::TypeOrCallable,
            }]
            .into_boxed_slice(),
            unresolved_names: None,
            completeness: open.clone(),
            type_or_callable_completeness: open,
            field_completeness: EdgeCompleteness::Complete,
        };
        let mut provisional =
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains);
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        assert!(
            !provisional
                .stage(&catalog, &batch, &cancellation)
                .expect("late lookup cancellation is a typed staging outcome")
        );
        assert!(cancellation.is_cancelled());
        assert!(
            !provisional.target_reasons.is_empty()
                && provisional.target_reasons.len() < fanout_targets.len(),
            "the token must cancel after a real target prefix but before the lookup bucket closes: staged={:?}",
            provisional.target_reasons
        );
        drop(provisional);

        let retry = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            reference,
            FactReferenceEdgeGapDomain::TypeOrCallable,
        );
        for target in fanout_targets {
            assert_lookup_resolution_status(&retry, target, true);
        }
        let unrelated = graph_targets(&catalog)
            .into_iter()
            .find(|target| target.is_callable() && target.terminal_name() == "unrelated")
            .expect("the law source must retain an unrelated callable target");
        assert_lookup_resolution_status(&retry, &unrelated, false);
    }

    #[test]
    fn selected_inverse_index_keeps_covered_empty_target_complete_across_field_only_gaps() {
        const SOURCE: &str =
            "package demo;\nclass Owner {\n    int value;\n    void write() { value = 1; }\n}\n";
        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"selected-inverse-empty-domain-law",
            b"selected-inverse-empty-domain-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected inverse-index snapshot must assemble");
        let index = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("the field-local selected inverse index must build"),
        );
        assert!(
            !index.run_completeness().covers(EdgeAxis::InverseProjection),
            "the aggregate run must retain the field gap"
        );
        let targets = graph_targets(&catalog);
        let empty_type_or_callable = targets
            .iter()
            .filter(|target| !target.is_field())
            .map(|target| (target, index.inverse_for(target)))
            .find(|(_, result)| result.edges.is_empty())
            .expect("the law source must contain one covered empty type/callable target");
        assert_eq!(
            empty_type_or_callable.1.completeness,
            EdgeCompleteness::Complete,
            "field-only gaps must not overtaint a covered empty type/callable"
        );
        assert!(
            targets
                .iter()
                .filter(|target| target.is_field())
                .any(|target| {
                    !index
                        .inverse_for(target)
                        .completeness
                        .covers(EdgeAxis::KindClassification)
                })
        );

        let uncovered = CodeUnit::new(
            fixture.file.clone(),
            crate::analyzer::CodeUnitType::Class,
            "demo",
            "NotSelected",
        );
        let uncovered = index.inverse_for(&uncovered);
        assert!(uncovered.edges.is_empty());
        assert_eq!(
            uncovered.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexTargetUncovered]
            }
        );
        assert!(!uncovered.covers(EdgeAxis::InverseProjection));
    }

    #[test]
    fn selected_inverse_index_localizes_receiver_gap_to_one_exact_sibling_target() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let mut siblings = catalog
            .declarations
            .iter()
            .filter_map(|(&semantic, declaration)| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) if !target.is_field() => {
                    Some((semantic, target.clone()))
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .collect::<Vec<_>>();
        siblings.sort_unstable_by(|left, right| left.1.cmp(&right.1));
        siblings.dedup_by(|left, right| left.1 == right.1);
        let [(open_semantic, open_target), (_, unaffected_target), ..] = siblings.as_slice() else {
            panic!("the law source must contain two type/callable sibling targets: {siblings:?}");
        };
        let mut target_domains = HashMap::default();
        assert!(
            target_domains
                .insert(
                    open_target.clone(),
                    FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                )
                .is_none()
        );
        assert!(
            target_domains
                .insert(
                    unaffected_target.clone(),
                    FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                )
                .is_none()
        );
        let open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardAdmissionIncomplete],
        };
        let batch = FactReferenceEdgeBatch {
            fragment: fixture.fragment,
            generation: catalog.generation(),
            reference_count: 1,
            edges: Box::new([]),
            gaps: vec![FactReferenceEdgeGap::ReceiverAdmission {
                reference: semantic(b"selected-inverse-local-receiver-gap"),
                target: *open_semantic,
                gap: FactReferenceReceiverGap::MissingOrigin,
                domain: FactReferenceEdgeGapDomain::TypeOrCallable,
            }]
            .into_boxed_slice(),
            unresolved_names: None,
            completeness: open.clone(),
            type_or_callable_completeness: open.clone(),
            field_completeness: EdgeCompleteness::Complete,
        };
        let mut accumulator =
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains);
        assert!(
            accumulator
                .stage(&catalog, &batch, &CancellationToken::new())
                .expect("the exact target-local gap must stage")
        );
        let index = selected_inverse_index(accumulator.finish(
            FactReferenceEdgeSummary {
                generation: catalog.generation(),
                completeness: open.clone(),
                type_or_callable_completeness: open,
                field_completeness: EdgeCompleteness::Complete,
                reference_count: 1,
                edge_count: 0,
                batch_count: 1,
                root_binding_metrics: ResolutionBatchMetrics::default(),
            },
            &CancellationToken::new(),
        ));
        assert_eq!(
            index.inverse_for(open_target).completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexAdmissionIncomplete]
            }
        );
        assert_eq!(
            index.inverse_for(unaffected_target).completeness,
            EdgeCompleteness::Complete,
            "a target-local receiver gap must not overtaint a same-domain sibling"
        );
    }

    #[test]
    fn selected_inverse_index_localizes_remaining_global_gap_axes() {
        struct GlobalGapCase {
            gap: FactReferenceEdgeGap,
            forward_reason: EdgeIncompleteReason,
            inverse_reason: EdgeIncompleteReason,
            covers_inverse: bool,
            covers_kind: bool,
            covers_owner: bool,
        }

        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let mut type_targets = catalog
            .declarations
            .values()
            .filter_map(|declaration| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) if !target.is_field() => {
                    Some(target.clone())
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .collect::<Vec<_>>();
        type_targets.sort_unstable();
        type_targets.dedup();
        let [first_type, second_type, ..] = type_targets.as_slice() else {
            panic!("the global-gap law requires two type/callable targets: {type_targets:?}");
        };
        let field = catalog
            .declarations
            .values()
            .find_map(|declaration| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) if target.is_field() => {
                    Some(target.clone())
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .expect("the global-gap law requires one field target");
        let target_domains = [
            (
                first_type.clone(),
                FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            ),
            (
                second_type.clone(),
                FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            ),
            (field.clone(), FactReferenceEdgeDeclarationDomain::Field),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();

        let cases = [
            GlobalGapCase {
                gap: FactReferenceEdgeGap::MissingSiteMetadata {
                    reference: semantic(b"selected-inverse-global-metadata-gap"),
                    domain: FactReferenceEdgeGapDomain::TypeOrCallable,
                },
                forward_reason: EdgeIncompleteReason::ForwardMetadataIncomplete,
                inverse_reason: EdgeIncompleteReason::InverseIndexMetadataIncomplete,
                covers_inverse: false,
                covers_kind: false,
                covers_owner: false,
            },
            GlobalGapCase {
                gap: FactReferenceEdgeGap::UnknownReferenceOwner {
                    reference: semantic(b"selected-inverse-global-owner-gap"),
                    domain: FactReferenceEdgeGapDomain::TypeOrCallable,
                },
                forward_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                inverse_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                covers_inverse: true,
                covers_kind: true,
                covers_owner: false,
            },
            GlobalGapCase {
                gap: FactReferenceEdgeGap::OutOfGraphReferenceOwner {
                    reference: semantic(b"selected-inverse-lexical-owner-reference"),
                    owner: semantic(b"selected-inverse-lexical-owner"),
                    domain: FactReferenceEdgeGapDomain::TypeOrCallable,
                },
                forward_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                inverse_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                covers_inverse: true,
                covers_kind: true,
                covers_owner: false,
            },
        ];
        for case in cases {
            let open = EdgeCompleteness::Incomplete {
                reasons: vec![case.forward_reason],
            };
            let batch = FactReferenceEdgeBatch {
                fragment: fixture.fragment,
                generation: catalog.generation(),
                reference_count: 1,
                edges: Box::new([]),
                gaps: vec![case.gap].into_boxed_slice(),
                unresolved_names: None,
                completeness: open.clone(),
                type_or_callable_completeness: open.clone(),
                field_completeness: EdgeCompleteness::Complete,
            };
            let mut accumulator = SelectedReferenceInverseIndexAccumulator::new(
                catalog.generation(),
                target_domains.clone(),
            );
            assert!(
                accumulator
                    .stage(&catalog, &batch, &CancellationToken::new())
                    .expect("the domain-global gap must stage")
            );
            let index = selected_inverse_index(accumulator.finish(
                FactReferenceEdgeSummary {
                    generation: catalog.generation(),
                    completeness: open.clone(),
                    type_or_callable_completeness: open,
                    field_completeness: EdgeCompleteness::Complete,
                    reference_count: 1,
                    edge_count: 0,
                    batch_count: 1,
                    root_binding_metrics: ResolutionBatchMetrics::default(),
                },
                &CancellationToken::new(),
            ));
            for target in [first_type, second_type] {
                let result = index.inverse_for(target);
                assert_eq!(
                    result.completeness,
                    EdgeCompleteness::Incomplete {
                        reasons: vec![case.inverse_reason.clone()]
                    }
                );
                assert_eq!(
                    result.covers(EdgeAxis::InverseProjection),
                    case.covers_inverse
                );
                assert_eq!(
                    result.covers(EdgeAxis::KindClassification),
                    case.covers_kind
                );
                assert_eq!(
                    result.covers(EdgeAxis::OwnerClassification),
                    case.covers_owner
                );
                assert!(result.covers(EdgeAxis::ProofAttribution));
            }
            let unaffected = index.inverse_for(&field);
            assert_eq!(unaffected.completeness, EdgeCompleteness::Complete);
            for axis in [
                EdgeAxis::InverseProjection,
                EdgeAxis::KindClassification,
                EdgeAxis::ProofAttribution,
                EdgeAxis::OwnerClassification,
            ] {
                assert!(unaffected.covers(axis));
            }
        }

        let enumeration_open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ReferenceEnumerationIncomplete],
        };
        let index = selected_inverse_index(
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains)
                .finish(
                    FactReferenceEdgeSummary {
                        generation: catalog.generation(),
                        completeness: enumeration_open.clone(),
                        type_or_callable_completeness: enumeration_open.clone(),
                        field_completeness: enumeration_open,
                        reference_count: 0,
                        edge_count: 0,
                        batch_count: 0,
                        root_binding_metrics: ResolutionBatchMetrics::default(),
                    },
                    &CancellationToken::new(),
                ),
        );
        for target in [first_type, second_type, &field] {
            let result = index.inverse_for(target);
            assert_eq!(
                result.completeness,
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete]
                }
            );
            assert!(!result.covers(EdgeAxis::InverseProjection));
            assert!(result.covers(EdgeAxis::KindClassification));
            assert!(result.covers(EdgeAxis::ProofAttribution));
            assert!(result.covers(EdgeAxis::OwnerClassification));
        }
    }

    #[test]
    fn selected_inverse_index_discards_cancelled_and_stale_builds_and_retries_exactly() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected inverse-index snapshot must assemble");
        let baseline = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("the baseline selected inverse index must build"),
        );

        let cancellation = CancellationToken::cancel_after_checks_for_test(8);
        assert!(matches!(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &cancellation,
            )
            .expect("cancellation is a typed selected inverse-index outcome"),
            SelectedReferenceInverseIndexBuildOutcome::Cancelled
        ));

        let retry = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("the selected inverse-index retry must build"),
        );
        let targets = graph_targets(&catalog);
        assert_same_inverse_index(&baseline, &retry, &targets);

        let mut stale_catalog = native_edge_catalog(&fixture);
        stale_catalog.generation = stale_catalog
            .generation
            .checked_add(1)
            .expect("the test generation must advance");
        assert!(matches!(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &stale_catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("generation mismatch is a typed selected inverse-index outcome"),
            SelectedReferenceInverseIndexBuildOutcome::Stale
        ));
    }

    #[test]
    fn selected_inverse_index_rejects_unselected_mixed_language_reference_sites_without_a_prefix() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("Projector.java", PROJECTOR_SOURCE)
            .file(
                "demo/Foreign.kt",
                "package demo\nclass Foreign { fun use(target: External) = target }\n",
            )
            .build();
        let fixture = native_edge_projection_fixture_from_project(
            project,
            "Projector.java",
            PROJECTOR_SOURCE,
            b"selected-inverse-mixed-language-law",
            b"selected-inverse-mixed-language-law:demo",
        );
        let analyzer = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::new(fixture._project.project_dyn())),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::Kotlin(KotlinAnalyzer::new(fixture._project.project_dyn())),
            ),
        ]));
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the Java selection itself must remain valid");
        let error = build_selected_reference_inverse_index(
            &analyzer,
            &snapshot,
            &catalog,
            1,
            &CancellationToken::new(),
        )
        .expect_err("a Java-only stream cannot certify Kotlin incoming sites");
        assert!(
            error
                .to_string()
                .contains("does not cover the complete analyzed workspace"),
            "unexpected mixed-language coverage error: {error}"
        );
    }
}
