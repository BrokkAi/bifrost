//! Language capability registry.
//!
//! Framework code (code that serves every language) reaches per-language behavior
//! through [`language_support`] instead of naming a language module or matching on
//! `Language` itself. The first lookup indexes the linked language table,
//! independently of which analyzers have been constructed.
//!
use crate::analyzer::common::language_for_target;
use crate::analyzer::structural::reference_edges::EdgeIncompleteReason;
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    DeclarationKinds, declaration_kind_index,
};
use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use crate::analyzer::loop_facts::LoopSyntax;

use crate::analyzer::semantic::ids::LengthDelimitedDigest;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::semantic::ids::WorkspaceRelativePath;

use crate::analyzer::semantic::BarrierObservation;
use crate::analyzer::semantic::FormalParameterPassingMode;
use crate::analyzer::semantic::ProcedureKind;
use crate::analyzer::semantic::SemanticLocator;
use crate::analyzer::semantic::SemanticProviderError;
use crate::analyzer::semantic::SemanticRequest;
use crate::analyzer::semantic::StablePackageValueScope;
use crate::analyzer::semantic::ValueTypeBarrierDecision;
use crate::analyzer::semantic::ValueTypeBarrierReason;
use crate::analyzer::semantic::ValueTypePredicate;

use crate::analyzer::store::LimitedQueryRows;

use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::get_definition::DefinitionLookupOutcome;
use crate::analyzer::usages::get_definition::ExactExternalCallProof;

use crate::analyzer::usages::get_type::TypeLookupOutcome;

use crate::analyzer::usages::inverted_edges::JsTsScopedUsageEdges;
use crate::analyzer::usages::inverted_edges::UsageEdgeBuildResult;
use crate::analyzer::usages::inverted_edges::UsageEdgeWeights;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::inverted_edges::UsageEdgesCache;
use crate::analyzer::usages::inverted_edges::UsageNodeKey;

use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::receiver_analysis::ReceiverFacts;
use crate::analyzer::usages::receiver_analysis::ReceiverFileCtx;
use crate::analyzer::usages::receiver_analysis::ReceiverFileFacts;
use crate::analyzer::usages::receiver_analysis::ReceiverFileSetup;

use crate::analyzer::usages::receiver_sites::ReceiverSiteInputMode;

use crate::analyzer::usages::reference_site::ResolvedReferenceSite;

use crate::analyzer::usages::workspace_graph::UsageEcosystem;

use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::UsageAnalyzer;
use crate::analyzer::usages::UsageHit;

use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::CodeUnit;
use crate::analyzer::ForwardQueryProvider;
use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;
use crate::analyzer::SignatureMetadata;
use crate::analyzer::resolve_analyzer;
use crate::analyzer::structural;

use crate::cancellation::CancellationToken;

use crate::hash::HashMap;
use crate::hash::HashSet;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::fq_name::SegmentKind;
use brokk_bifrost_core::analyzer::fq_name::joined_segments;
use brokk_bifrost_core::analyzer::fq_name::segment_interner;

use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

use std::any::Any;

use std::collections::BTreeSet;

use std::sync::Arc;

/// One callable whose saved defaults can no longer be treated as immutable.
/// The function declaration's source start is unique within its portable path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub struct SavedDefaultFunction {
    path: WorkspaceRelativePath,
    declaration_start_byte: u32,
}

impl SavedDefaultFunction {
    #[doc(hidden)]
    pub fn new(path: WorkspaceRelativePath, declaration_start_byte: u32) -> Self {
        Self {
            path,
            declaration_start_byte,
        }
    }

    fn from_locator(locator: &SemanticLocator) -> Self {
        let segment = locator
            .declaration()
            .segments()
            .last()
            .expect("semantic declaration locators contain a segment");
        Self::new(locator.path().clone(), segment.anchor().span().start_byte())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SavedDefaultKind {
    Positional,
    KeywordOnly,
}

/// Bounded evidence about which Python function defaults may have changed.
/// Exact receivers add only their function key to the affected set. Workspace
/// flags represent incomplete or exhausted evidence, including an incomplete
/// scan of functions that escape by value.
#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct SavedDefaultArgumentSafety {
    positional_workspace_open: bool,
    keyword_only_workspace_open: bool,
    positional_functions_open: HashSet<SavedDefaultFunction>,
    keyword_only_functions_open: HashSet<SavedDefaultFunction>,
}

impl SavedDefaultArgumentSafety {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn workspace_is_open(&self, kind: SavedDefaultKind) -> bool {
        match kind {
            SavedDefaultKind::Positional => self.positional_workspace_open,
            SavedDefaultKind::KeywordOnly => self.keyword_only_workspace_open,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn function_is_open(
        &self,
        function: &SavedDefaultFunction,
        kind: SavedDefaultKind,
    ) -> bool {
        match kind {
            SavedDefaultKind::Positional => self.positional_functions_open.contains(function),
            SavedDefaultKind::KeywordOnly => self.keyword_only_functions_open.contains(function),
        }
    }

    #[doc(hidden)]
    pub fn mark_workspace_open(&mut self, kind: SavedDefaultKind) {
        let (open, functions) = self.kind_evidence_mut(kind);
        *open = true;
        // Release the allocation, rather than retaining a redundant set.
        *functions = HashSet::default();
    }

    fn kind_evidence_mut(
        &mut self,
        kind: SavedDefaultKind,
    ) -> (&mut bool, &mut HashSet<SavedDefaultFunction>) {
        match kind {
            SavedDefaultKind::Positional => (
                &mut self.positional_workspace_open,
                &mut self.positional_functions_open,
            ),
            SavedDefaultKind::KeywordOnly => (
                &mut self.keyword_only_workspace_open,
                &mut self.keyword_only_functions_open,
            ),
        }
    }

    #[doc(hidden)]
    pub fn mark_function_open(
        &mut self,
        function: SavedDefaultFunction,
        kind: SavedDefaultKind,
        max_functions: usize,
    ) {
        let (open, functions) = self.kind_evidence_mut(kind);
        if *open || functions.contains(&function) {
            return;
        }
        if functions.len() == max_functions {
            // #5112: bounded residency per the architecture guidance. Collapse
            // conservatively: every default of this kind becomes unavailable.
            self.mark_workspace_open(kind);
        } else {
            functions.insert(function);
        }
    }

    pub(crate) fn default_is_available(
        &self,
        locator: &SemanticLocator,
        passing_mode: FormalParameterPassingMode,
    ) -> bool {
        let function = SavedDefaultFunction::from_locator(locator);
        match passing_mode {
            FormalParameterPassingMode::NamedOnly => {
                !self.keyword_only_workspace_open
                    && !self.keyword_only_functions_open.contains(&function)
            }
            FormalParameterPassingMode::PositionalOnly
            | FormalParameterPassingMode::PositionalOrNamed => {
                !self.positional_workspace_open
                    && !self.positional_functions_open.contains(&function)
            }
        }
    }

    pub(crate) fn fingerprint(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost-python-saved-default-safety/v1");
        digest.push(&[
            u8::from(self.positional_workspace_open),
            u8::from(self.keyword_only_workspace_open),
        ]);
        for (label, functions) in [
            (b"positional".as_slice(), &self.positional_functions_open),
            (
                b"keyword-only".as_slice(),
                &self.keyword_only_functions_open,
            ),
        ] {
            digest.push(label);
            let mut functions = functions.iter().collect::<Vec<_>>();
            functions.sort_unstable();
            for function in functions {
                digest.push(function.path.as_str().as_bytes());
                digest.push(&function.declaration_start_byte.to_le_bytes());
            }
        }
        digest.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum LocalDeclarationVisibility {
    Lexical,
    Hoisted,
}

#[doc(hidden)]
pub fn with_resolved_analyzer<T: Any, R>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce(&T) -> R,
) -> Option<R> {
    resolve_analyzer::<T>(analyzer).map(query)
}

#[doc(hidden)]
pub enum ExternalTypeBoundaryEvidence {
    Unresolved,
    Indexed(Option<String>),
}

#[doc(hidden)]
pub fn classify_jvm_external_boundary_evidence(
    type_evidence: ExternalTypeBoundaryEvidence,
    resolve_member: impl FnOnce() -> Option<String>,
    declared_unindexed: impl FnOnce() -> bool,
) -> (structural::BoundaryStatus, Option<String>) {
    if let ExternalTypeBoundaryEvidence::Indexed(fqn) = type_evidence {
        return (structural::BoundaryStatus::ExternalIndexed, fqn);
    }
    if let Some(fqn) = resolve_member() {
        return (structural::BoundaryStatus::ExternalIndexed, Some(fqn));
    }
    if declared_unindexed() {
        return (structural::BoundaryStatus::ExternalDeclaredUnindexed, None);
    }
    (structural::BoundaryStatus::ExternalUnknown, None)
}

/// Interpret one already-extracted package spelling through the registered
/// language separator and preserve path packages as path segments.
#[doc(hidden)]
pub fn package_fq_name(language: Language, package: &str) -> FqName {
    let separator = language_knowledge(language)
        .expect("every indexed language has registered support")
        .package_separator();
    let kind = if language == Language::Go {
        SegmentKind::Path
    } else {
        SegmentKind::Package
    };
    let interner = segment_interner();
    let mut name = FqName::new();
    for segment in joined_segments(package, separator) {
        name.push(interner.intern(segment, kind));
    }
    name
}

#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct LocalDeclarationBindingScope<'tree> {
    pub scope: tree_sitter::Node<'tree>,
    pub visibility: LocalDeclarationVisibility,
}

/// Language-owned proof that a package-scope callable value keeps its
/// function-literal initializer at every reference.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct StablePackageFunctionValueProof {
    pub initializer_start: usize,
    pub initializer_end: usize,
    pub references: Vec<UsageHit>,
    pub scope: StablePackageValueScope,
}

/// Work charged by a language-owned bounded declaration lookup.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub enum PredeclaredBuiltinQueryStep {
    BeginLookup,
    VisitCandidate,
}

/// Physical source roles used by navigation after language-owned interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum DeclarationNavigationRole {
    Declaration,
    Definition,
    Both,
    Unknown,
}

impl DeclarationNavigationRole {
    #[doc(hidden)]
    pub fn api_label(self) -> Option<&'static str> {
        match self {
            Self::Declaration => Some("declaration"),
            Self::Definition => Some("definition"),
            Self::Both | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct DeclarationNavigationOccurrence {
    pub range: Range,
    pub role: DeclarationNavigationRole,
}
/// AST-level helper that returns the identifier introduced by one pattern node.
#[doc(hidden)]
pub type PatternBindingNameProvider =
    for<'tree> fn(tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>>;

/// Pattern syntax admitted by query-local lexical lookup. This is separate
/// from pattern inventory: a language may inventory patterns while leaving
/// their lexical resolution incomplete.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct LexicalPatternBindings {
    /// Given a binder token, return its declaring pattern node.
    pub declaration_for_name:
        for<'tree> fn(tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>>,
    pub is_scope: fn(&str) -> bool,
    /// Prove visibility at this reference. `None` withholds identity,
    /// including fallback to an outer binding.
    pub visible_at:
        for<'tree> fn(tree_sitter::Node<'tree>, tree_sitter::Node<'tree>) -> Option<bool>,
    /// Whether bindings may be visible beyond this pattern scope. The
    /// reference-sensitive visibility proof still decides each candidate.
    pub bindings_may_escape_scope: fn(&str) -> bool,
}

/// Syntax roles one language supplies for procedure-local source proofs:
/// statement-entry assessment and loop repetition. Both enumerate syntax
/// independently of the producer, so a statement or loop classified here
/// without matching producer evidence stays open.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct ProcedureSyntaxRoles {
    /// Classify an executable statement node; `None` for any other node.
    pub statement_kind: fn(tree_sitter::Node<'_>) -> Option<&'static str>,
    /// Classify a conditional loop whose repetition the loop proof can join
    /// to control flow. Iteration loops (for-each) are not classified.
    pub loop_site: for<'tree> fn(tree_sitter::Node<'tree>) -> Option<LoopSyntax<'tree>>,
    /// Optional source-aware loop classification for grammars whose loop
    /// syntax is encoded in a value-bearing AST field rather than a node kind.
    /// The ordinary hook remains the fast path for languages with structural
    /// loop node kinds.
    pub loop_site_with_source:
        Option<for<'tree> fn(tree_sitter::Node<'tree>, &str) -> Option<LoopSyntax<'tree>>>,
    /// Whether `node` is the syntax of a procedure of this kind.
    pub procedure_matches: fn(ProcedureKind, tree_sitter::Node<'_>) -> bool,
    /// Whether `node` starts code that belongs to another procedure.
    pub nested_procedure: fn(tree_sitter::Node<'_>) -> bool,
}

/// Language interpretation of an already-proven native member route.
#[doc(hidden)]
pub struct NativeMemberAttribution {
    #[doc(hidden)]
    pub dispatch_tier: structural::MemberDispatchTier,
    #[doc(hidden)]
    pub relation: structural::HierarchyRelation,
    #[doc(hidden)]
    pub precedence_tier: structural::PrecedenceTier,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub type AssignmentValueTypeSpelling = fn(
    &str,
    crate::analyzer::resolution::ResolutionSlotValue,
    &mut Vec<crate::analyzer::usages::get_type::TypeLookupDiagnostic>,
) -> Option<String>;

#[doc(hidden)]
pub trait LanguageSupport: crate::analyzer::store::StoreLanguageSupport + Send + Sync {
    /// Whether shared lexical discovery may answer a local definition before
    /// the language's authoritative definition operation runs.
    fn lexical_definitions_are_authoritative(&self) -> bool {
        true
    }

    /// Whether this frontend can publish selected native content overlays.
    fn supports_selected_resolution_overlays(&self) -> bool {
        false
    }

    /// Workspace-aware imports; None keeps the delegate's own answer.
    fn workspace_imported_code_units(
        &self,
        _workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        None
    }

    /// Workspace-aware ancestors; None keeps the delegate's own answer.
    fn workspace_direct_ancestors(
        &self,
        _workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        _token: QueryToken<'_>,
        _unit: &CodeUnit,
    ) -> Option<Vec<CodeUnit>> {
        None
    }

    /// The outer option selects the override; the inner option preserves cancellation.
    fn workspace_direct_ancestors_within(
        &self,
        _workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        _token: QueryToken<'_>,
        _unit: &CodeUnit,
        _scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<Option<Vec<CodeUnit>>> {
        None
    }

    /// Additional descendants contributed by another language's realm-aware index.
    fn workspace_additional_direct_descendants(
        &self,
        _workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        _token: QueryToken<'_>,
        _unit: &CodeUnit,
        _scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        Some(HashSet::default())
    }

    /// Native definition route used without a rollout environment gate.
    fn default_definition_points(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        None
    }

    /// Optional bounded assignment-value probe owned by the language.
    #[cfg(any(test, feature = "test-support"))]
    fn probe_assignment_value(
        &self,
        _query: BoundedReceiverQuery<'_>,
        _request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
        _cancellation: &crate::CancellationToken,
    ) -> Result<
        Option<
            crate::analyzer::usages::get_definition::BoundedResolution<
                crate::analyzer::native_points::NativeAssignmentValueProbe,
            >,
        >,
        String,
    > {
        Ok(None)
    }

    /// Render assignment-value type evidence, when plain spelling is insufficient.
    #[cfg(any(test, feature = "test-support"))]
    fn assignment_value_type_spelling(&self) -> Option<AssignmentValueTypeSpelling> {
        None
    }

    /// Prove exact external receiver identities using this language's type flow.
    fn exact_external_receiver_identities(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _procedure: &crate::analyzer::semantic::ProcedureHandle,
        _call: &crate::analyzer::semantic::SemanticCallSite,
    ) -> Option<Vec<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>> {
        None
    }

    /// Select an effective external member under this language's inheritance rules.
    fn external_member_declaration(
        &self,
        _overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
        _owner_id: &str,
        _member: &str,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelSymbol>> {
        None
    }

    /// Prove the external class produced by a constructor call.
    fn external_class_call_identity(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _procedure: &crate::analyzer::semantic::ProcedureHandle,
        _call: &crate::analyzer::semantic::SemanticCallSite,
    ) -> Option<crate::analyzer::semantic::ClassIdentity> {
        None
    }

    /// A build ecosystem provider, registered even without source files of this language.
    fn build_model_provider(
        &self,
    ) -> Option<&'static dyn crate::analyzer::topology::BuildModelProvider> {
        None
    }

    fn workspace_external_member_family(
        &self,
        _workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        _identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        _max_visits: usize,
        _cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::ExternalMemberFamilyAnswer {
        crate::analyzer::usages::ExternalMemberFamilyAnswer::unsupported()
    }

    /// Collect with the dispatcher's overlay and discovery evidence. None
    /// leaves diagnostics to the file's delegate.
    fn workspace_semantic_diagnostics(
        &self,
        _workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _source: &str,
    ) -> Option<crate::analyzer::SemanticDiagnosticReport> {
        None
    }

    #[cfg(any(test, feature = "test-support"))]
    fn prepared_syntax_for_test(
        &self,
        _delegate: &crate::analyzer::multi_analyzer::AnalyzerDelegate,
        _file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        None
    }

    fn knowledge(&self) -> &'static dyn LanguageKnowledge;

    /// Select one grammar reference in a branch body. Shared code owns bounded
    /// traversal, lexical filtering, definition lookup and distinct-only proof.
    fn branch_body_reference_site(
        &self,
        _node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<structural::branch_relations::BranchReferenceSite> {
        None
    }

    /// Select one reference that can distinguish conditions. This never grants
    /// condition stability or equality from equal presentation targets.
    fn branch_condition_reference_site(
        &self,
        _node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<structural::branch_relations::BranchReferenceSite> {
        None
    }

    /// Current-object field grammar. Shared branch comparison admits equality
    /// only with an exact physical storage declaration for each reference.
    fn branch_current_object_fields(
        &self,
    ) -> Option<structural::branch_relations::BranchCurrentObjectFields> {
        None
    }

    /// Whether a resolved target at this reference site denotes a conversion
    /// rather than a callable edge.
    fn call_relation_target_is_conversion(
        &self,
        _site_kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind,
        _namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        _target: &CodeUnit,
    ) -> bool {
        false
    }

    fn build_analyzer(
        &self,
        project: Arc<dyn crate::analyzer::Project>,
        config: crate::analyzer::AnalyzerConfig,
        store_context: crate::analyzer::AnalyzerStoreContext,
        progress: Option<crate::analyzer::BuildProgress>,
    ) -> Result<crate::analyzer::multi_analyzer::AnalyzerDelegate, crate::analyzer::store::StoreError>;

    /// Inputs that cause a workspace delegate to receive an incremental update.
    fn is_configuration_input(&self, file: &ProjectFile) -> bool {
        self.is_configuration_input_path(file.rel_path())
    }

    fn workspace_member_family_capability(
        &self,
        workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        workspace
            .member_family_provider_for_code_unit(member)
            .map(|provider| provider.member_family_capability(member))
            .unwrap_or(crate::analyzer::structural::resolution::MemberFamilyCapability::Unsupported)
    }

    fn workspace_member_family(
        &self,
        workspace: &crate::analyzer::multi_analyzer::MultiAnalyzer,
        member: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        workspace
            .member_family_provider_for_code_unit(member)
            .map(|provider| provider.member_family(member, cancellation))
            .unwrap_or_else(crate::analyzer::usages::MemberFamilyAnswer::unsupported_answer)
    }

    /// Project a confirmed reverse site through the caller file's analyzer.
    /// Languages without a dedicated projection retain the supplied analyzer.
    #[cfg(any(test, feature = "test-support"))]
    fn selected_reverse_reference_file<'a>(
        &self,
        _analyzer: &'a dyn IAnalyzer,
        target_analyzer: &'a dyn IAnalyzer,
        file: &ProjectFile,
    ) -> crate::analyzer::store::Result<
        structural::reference_edges::SelectedReferenceFileProjection<'a>,
    > {
        structural::reference_edges::SelectedReferenceFileProjection::new(
            target_analyzer,
            target_analyzer,
            file,
            |source| target_analyzer.indexed_source_matches(file, source),
        )
    }

    /// Prove that workspace writes and escapes cannot replace a module member.
    /// None means the bounded query did not complete or has no language proof.
    fn workspace_module_member_mutation_free(
        &self,
        _analyzer: &dyn IAnalyzer,
        _module: &str,
        _member: &str,
        _max_nodes: usize,
        _keep_going: &dyn Fn() -> bool,
    ) -> Option<bool> {
        None
    }

    /// Interpret only the selected route; an absent route never acquires an owner.
    fn native_member_attribution(
        &self,
        _context: &crate::analyzer::store::resolution_operation::ProjectedNativeMemberContext,
        _outcome: structural::CandidateOutcome,
    ) -> Option<NativeMemberAttribution> {
        None
    }

    fn selected_graph_fallback_active(&self, _analyzer: &dyn IAnalyzer) -> bool {
        false
    }

    fn selected_graph_fallback_exclusion(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _modules: &[brokk_bifrost_go::packages::GoModuleRoot],
    ) -> Option<crate::analyzer::store::resolution_operation::graph_stage::GraphFileSkipReason>
    {
        None
    }

    /// Return the workspace-relative root of an unnamed module boundary that
    /// excludes this source file from language graph admission.
    fn unnamed_module_root_for_file(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
    ) -> Option<std::path::PathBuf> {
        None
    }

    /// Prove that an exact external field load has no unmodeled read behavior.
    fn external_field_read_discharges_gap(
        &self,
        _workspace: &super::WorkspaceAnalyzer,
        _procedure: &super::semantic::ProcedureHandle,
        _gap: &super::semantic::SemanticGap,
    ) -> bool {
        false
    }

    /// Whether a focused syntax node declares a name instead of referring to one.
    /// Native readers use this only when the producer has no reference at the point.
    fn native_non_reference_site(&self, _node: tree_sitter::Node<'_>) -> bool {
        false
    }

    /// Exact package identity published for an import by this language's
    /// activated semantic model. Framework callers supply the selected overlay
    /// so this lookup does not depend on a language delegate's local cache.
    fn modeled_external_package_identity(
        &self,
        _overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
        _import_path: &str,
    ) -> Option<ModeledExternalPackageIdentity> {
        None
    }

    /// Provider identities for external declaration inventories owned by this
    /// language's analyzer. Shared resolution gathers these through the
    /// registered language hooks instead of reaching into a language module.
    fn external_inventory_providers(&self, _analyzer: &dyn IAnalyzer) -> Vec<String> {
        Vec::new()
    }

    /// The qualified name that the one explicit, non-wildcard import visible
    /// at `reference` gives its spelling, so navigation can name the
    /// semantic-model symbol that import selects. `None` when the language has
    /// no such import rule or no single import applies.
    fn explicit_import_model_target(
        &self,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _reference: &ResolvedReferenceSite,
    ) -> Option<String> {
        None
    }

    /// The qualified name this language's own packs give a hierarchy edge whose
    /// recorded target is a bare, unqualified spelling.
    ///
    /// A producer that records a supertype by source spelling leaves the
    /// enclosing module implicit: a legacy Python pack records
    /// `class Child(Base)` as `Base`, where `Base` means the base in the
    /// declaring declaration's own module. The rule is the language's, so
    /// shared overlay code asks here instead of naming the language module.
    /// `None` leaves the recorded spelling as the only candidate.
    fn qualified_hierarchy_target(
        &self,
        _declaring_locator_path: Option<&str>,
        _declaring_qualified_name: &str,
        _target: &str,
    ) -> Option<String> {
        None
    }

    /// Whether each caller site's blob can be compiled in the selected
    /// configuration. Only positive inactivity evidence excludes a site;
    /// languages without placement information keep every site.
    fn caller_sites_compiled(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        sites: &[crate::analyzer::usages::CallSite],
        _cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<Vec<bool>> {
        Ok(vec![true; sites.len()])
    }

    /// Resolve only the callee ranges retained by a structural pipeline.
    /// Unsupported stores and languages leave the ordinary serial path in charge.
    fn prefetch_selected_call_targets(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _files: &[(crate::analyzer::ProjectFile, Vec<crate::analyzer::Range>)],
        _cancellation: &crate::CancellationToken,
        _snapshot: Option<
            std::sync::Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>,
        >,
    ) -> Option<
        crate::analyzer::store::Result<
            Vec<(
                crate::analyzer::ProjectFile,
                crate::analyzer::usages::call_relations::PrefetchedCallTargets,
            )>,
        >,
    > {
        None
    }

    /// Speculatively answer this language's own retained reverse call sites
    /// before the demanding walk asks for them. `sites` can hold several
    /// languages' sites, so an implementation answers only the ones its own
    /// language owns. `None` leaves the framework's ordinary demand path in
    /// charge, which is the only path a language without a selected native
    /// reverse operation has.
    fn prefetch_reverse_call_targets(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _sites: &[crate::analyzer::usages::CallSite],
        _cancellation: &crate::CancellationToken,
        _snapshot: Option<
            std::sync::Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>,
        >,
    ) -> Option<
        crate::analyzer::store::Result<
            crate::hash::HashMap<
                crate::analyzer::ProjectFile,
                crate::analyzer::usages::call_relations::PrefetchedCallFile,
            >,
        >,
    > {
        None
    }

    /// Demand an exact selected-artifact callable factory through the language
    /// adapter. Absence keeps ordinary external dispatch and its open boundary.
    fn materialize_callable_factory(
        &self,
        _oracle: &crate::analyzer::semantic::WorkspaceSemanticOracle<'_>,
        _call: &crate::analyzer::semantic::CallSiteHandle,
        _proof: &ExactExternalCallProof,
        _request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        Option<
            crate::analyzer::semantic::SemanticOutcome<crate::analyzer::semantic::DispatchResult>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        Ok(None)
    }

    /// The syntax roles procedure-local source proofs need for this language.
    /// `None` means the language's lowering does not author statement entries.
    fn procedure_syntax_roles(&self) -> Option<ProcedureSyntaxRoles> {
        None
    }

    /// The AST-level helper for extracting one pattern node's binding identifier.
    /// Shared analysis uses this for pattern bindings the generic lexical environment
    /// does not model.
    fn pattern_binding_name_provider(&self) -> Option<PatternBindingNameProvider> {
        None
    }

    /// Opt into pattern binding lookup, including expression-only scopes.
    fn lexical_pattern_bindings(&self) -> Option<LexicalPatternBindings> {
        None
    }

    /// The name universe this language's declarations belong to.
    ///
    /// The single owner of ecosystem knowledge: [`UsageEcosystem::of`] delegates here,
    /// and the edge-pass collector derives a pass's ecosystem from the supports that
    /// own it rather than asking the pass. A pass shared by several languages (JS/TS)
    /// requires those languages to agree here, which [`edge_passes`] asserts.
    fn ecosystem(&self) -> UsageEcosystem;

    /// Dependency pack discovery for the ecosystem's primary language.
    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn crate::analyzer::semantic_model::DependencyResolver> {
        None
    }

    /// Reader-side input classification for immutable dependency images.
    fn is_file_dependency_input(&self, path: &std::path::Path) -> bool {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        self.dependency_pack_resolver()
            .is_some_and(|resolver| resolver.dependency_inputs().contains(&name))
    }

    /// Apply project-owned dependency toolchain selection before construction.
    fn configure_dependency_workspace(
        &self,
        _config: &mut crate::analyzer::AnalyzerConfig,
        _project_root: &std::path::Path,
    ) -> Result<(), crate::analyzer::store::StoreError> {
        Ok(())
    }

    /// Reconcile source-owned build membership after a workspace revision changes.
    fn reconcile_workspace_build_context(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _changed: Option<&std::collections::BTreeSet<crate::analyzer::ProjectFile>>,
    ) -> Result<(), crate::analyzer::store::StoreError> {
        Ok(())
    }

    /// Republish tool-derived context after a live workspace snapshot update.
    /// Languages without external-tool context need no additional update step.
    fn refresh_updated_workspace_context(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _changed_files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
        _config: &crate::analyzer::AnalyzerConfig,
        _limits: &crate::analyzer::semantic_model::DependencyPackLimits,
        _cancellation: &crate::CancellationToken,
    ) -> Result<(), crate::analyzer::store::StoreError> {
        Ok(())
    }

    /// Discover dependencies using the selected workspace snapshot when required.
    fn resolve_workspace_dependencies(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        config: &crate::analyzer::AnalyzerConfig,
        limits: &crate::analyzer::semantic_model::DependencyPackLimits,
        cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::semantic_model::DependencyDiscoveryOutcome {
        self.dependency_pack_resolver()
            .expect("dependency ecosystem resolver")
            .resolve(
                config,
                workspace.analyzer().project(),
                limits,
                Some(cancellation),
            )
    }

    /// Bind prepared dependency artifacts to configured source toolchains.
    fn dependency_source_artifacts(
        &self,
        _config: &crate::analyzer::AnalyzerConfig,
        _project_root: &std::path::Path,
        _outcomes: &[crate::analyzer::workspace::DependencyPackEcosystemOutcome],
    ) -> Option<
        crate::hash::HashMap<
            std::path::PathBuf,
            crate::analyzer::semantic_model::SemanticModelActivationEvidence,
        >,
    > {
        None
    }

    /// Publish verified runtime dependency providers for this workspace.
    fn publish_dependency_runtime(
        &self,
        _workspace: &crate::analyzer::WorkspaceAnalyzer,
        _config: &crate::analyzer::AnalyzerConfig,
        _activation: &mut crate::analyzer::semantic_model::SemanticModelActivationRequest,
        _context: &crate::analyzer::workspace::DependencyPackWorkspaceContext<'_>,
    ) -> Result<
        Option<crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
        crate::analyzer::store::StoreError,
    > {
        Ok(None)
    }

    /// Repair this language's persisted usage facts before queries need them.
    fn warm_usage_facts(&self, _analyzer: &dyn IAnalyzer) {}

    /// Whether usage queries can proceed without waiting for fact catch-up.
    fn usage_facts_ready(&self, _analyzer: &dyn IAnalyzer) -> bool {
        true
    }

    /// Whether usage fact catch-up has completed for the selected generation.
    fn usage_facts_warm(&self, _analyzer: &dyn IAnalyzer) -> bool {
        true
    }

    /// Return this language's own answer to "which files can hold a reference
    /// to `target`", seeded from `seed_files`. `None` leaves the framework's
    /// generic importer walk in charge; `Some` is complete for this language
    /// and replaces that walk.
    ///
    /// A language may narrow its reverse-import closure by any admission test
    /// it can prove from structure -- a file the closure reaches but whose
    /// syntax cannot spell `target` holds no reference to it, proven or
    /// unproven -- so the answer stays complete while the framework's file
    /// budget sees a set it can admit whole.
    fn referencing_candidate_files(
        &self,
        _analyzer: &dyn IAnalyzer,
        _target: &CodeUnit,
        _seed_files: &BTreeSet<ProjectFile>,
        _cancellation: Option<&CancellationToken>,
    ) -> Option<HashSet<ProjectFile>> {
        None
    }

    /// The one reference-analysis plugin serving both target-directed and
    /// whole-workspace workloads for this language.
    fn reference_usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer;

    fn reference_graph_backend(&self) -> LanguageGraphBackend;

    #[allow(clippy::too_many_arguments)]
    fn definition_allocation_selector_method(
        &self,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _source: &str,
        _root: tree_sitter::Node<'_>,
        _allocation: tree_sitter::Node<'_>,
        _member: &str,
        _byte: usize,
        budget: crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::usages::get_definition::BoundedResolution<Option<CodeUnit>> {
        crate::analyzer::usages::get_definition::ResolutionSession::bounded(budget, cancellation)
            .finish(None)
    }

    fn definition_declared_import_route(
        &self,
        _analyzer: &dyn crate::analyzer::IAnalyzer,
        _token: crate::analyzer::QueryToken<'_>,
        _file: &crate::analyzer::ProjectFile,
        _leading: &str,
        _evidence: &crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
    ) -> bool {
        false
    }

    #[cfg(any(test, feature = "test-support"))]
    fn trial_definition(
        &self,
        _query: BoundedReceiverQuery<'_>,
    ) -> Option<crate::analyzer::usages::get_definition::DefinitionResolution> {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn definition_lexical_site<'a>(
        &self,
        _analyzer: &'a dyn crate::analyzer::IAnalyzer,
        _context: &mut crate::analyzer::usages::get_definition::DefinitionBatchContext<'a, '_>,
        _request: &crate::analyzer::usages::get_definition::DefinitionLookupRequest,
        _source: &str,
        _tree: Option<&tree_sitter::Tree>,
        site: crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    ) -> std::ops::ControlFlow<
        crate::analyzer::usages::get_definition::DefinitionResolution,
        crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    > {
        std::ops::ControlFlow::Continue(site)
    }

    #[allow(clippy::too_many_arguments)]
    fn definition_lexical_fallback(
        &self,
        _analyzer: &dyn crate::analyzer::IAnalyzer,
        _token: crate::analyzer::QueryToken<'_>,
        _file: &crate::analyzer::ProjectFile,
        _source: &str,
        _tree: &tree_sitter::Tree,
        _site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
        _identifier: &str,
    ) -> Option<crate::analyzer::lexical_definitions::LexicalBindingResolution> {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_call_target_batch(
        &self,
        analyzer: &dyn crate::analyzer::IAnalyzer,
        token: crate::analyzer::QueryToken<'_>,
        requests: Vec<crate::analyzer::usages::get_definition::DefinitionLookupRequest>,
        file: crate::analyzer::ProjectFile,
        source: std::sync::Arc<str>,
        primary_tree: Option<tree_sitter::Tree>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Vec<crate::analyzer::usages::get_definition::CallTargetLookupOutcome> {
        crate::analyzer::usages::get_definition::resolve_generic_call_target_batch(
            analyzer,
            token,
            requests,
            file,
            source,
            primary_tree,
            cancellation,
        )
    }

    fn definition_site_for_focus(
        &self,
        site: crate::analyzer::usages::get_definition::ResolvedReferenceSite,
        _tree: &tree_sitter::Tree,
        _source: &str,
        _start: Option<usize>,
        _end: Option<usize>,
    ) -> crate::analyzer::usages::get_definition::ResolvedReferenceSite {
        site
    }

    fn definition_navigation_selection(
        &self,
        _context: &mut crate::analyzer::usages::get_definition::DefinitionBatchContext<'_, '_>,
        _token: crate::analyzer::QueryToken<'_>,
        _file: &crate::analyzer::ProjectFile,
        _definitions: &[crate::analyzer::CodeUnit],
        _operation: crate::navigation::NavigationOperation,
    ) -> Option<crate::analyzer::usages::get_definition::DefinitionNavigationSelection> {
        None
    }

    fn definition_declaration_site_targets(
        &self,
        analyzer: &dyn crate::analyzer::IAnalyzer,
        token: crate::analyzer::QueryToken<'_>,
        candidate: crate::analyzer::CodeUnit,
        operation: crate::navigation::NavigationOperation,
    ) -> Vec<crate::analyzer::usages::get_definition::NavigationTarget> {
        self.definition_associated_navigation_targets(analyzer, token, candidate, operation)
    }

    fn definition_associated_navigation_targets(
        &self,
        _analyzer: &dyn crate::analyzer::IAnalyzer,
        _token: crate::analyzer::QueryToken<'_>,
        candidate: crate::analyzer::CodeUnit,
        _operation: crate::navigation::NavigationOperation,
    ) -> Vec<crate::analyzer::usages::get_definition::NavigationTarget> {
        vec![crate::analyzer::usages::get_definition::NavigationTarget {
            code_unit: candidate,
            declaration_range: None,
        }]
    }

    fn definition_value_identity(
        &self,
        _analyzer: &dyn crate::analyzer::IAnalyzer,
        _request: &crate::analyzer::usages::get_definition::DefinitionLookupRequest,
        _file: &crate::analyzer::ProjectFile,
        _source: &str,
        _cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<crate::analyzer::usages::get_definition::ResolvedValueIdentity> {
        None
    }

    fn release_definition_file(
        &self,
        _context: &mut crate::analyzer::usages::get_definition::DefinitionBatchContext<'_, '_>,
        _file: &crate::analyzer::ProjectFile,
    ) {
    }

    /// `primary_tree`, when supplied, was parsed for this exact source using
    /// the ordinary file parser. Overrides that transform source must select
    /// their own tree rather than accepting it as their definition tree.
    #[allow(clippy::too_many_arguments)]
    fn definition_tree(
        &self,
        _analyzer: &dyn crate::analyzer::IAnalyzer,
        _token: crate::analyzer::QueryToken<'_>,
        file: &crate::analyzer::ProjectFile,
        language: crate::analyzer::Language,
        source: &str,
        primary_tree: Option<&tree_sitter::Tree>,
    ) -> Option<tree_sitter::Tree> {
        primary_tree.cloned().or_else(|| {
            crate::analyzer::usages::get_definition::parse_tree_for_language(file, language, source)
        })
    }

    fn definition_batch_resolver<'a>(
        &self,
        _analyzer: &'a dyn crate::analyzer::IAnalyzer,
        _cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<Box<dyn crate::analyzer::usages::get_definition::DefinitionBatchResolver<'a> + 'a>>
    {
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_dispatch<'a>(
        &self,
        _analyzer: &'a dyn crate::analyzer::IAnalyzer,
        _token: crate::analyzer::QueryToken<'_>,
        _context: &mut crate::analyzer::usages::get_definition::DefinitionBatchContext<'a, '_>,
        _request: &crate::analyzer::usages::get_definition::DefinitionLookupRequest,
        _source: &std::sync::Arc<str>,
        _tree: &Option<tree_sitter::Tree>,
        _site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
        _operation: Option<crate::navigation::NavigationOperation>,
        _cancellation: Option<&crate::cancellation::CancellationToken>,
        _go_session: Option<&crate::analyzer::usages::get_definition::ResolutionSession>,
    ) -> std::ops::ControlFlow<
        crate::analyzer::usages::get_definition::DefinitionResolution,
        crate::analyzer::usages::get_definition::DefinitionResolution,
    > {
        unreachable!("unsupported language handled before definition dispatch")
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_receiver_query(
        &self,
        _service: &crate::analyzer::usages::receiver_query::ReceiverQueryService<'_>,
        _operation: crate::analyzer::usages::receiver_query::ReceiverQueryOperation,
        _file: &ProjectFile,
        _range: crate::analyzer::Range,
        _input: crate::analyzer::usages::receiver_query::ReceiverQueryInput,
        _budget: crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
        _cancellation: Option<&crate::CancellationToken>,
        _indexed_source: Option<String>,
    ) -> Option<
        Result<
            crate::analyzer::usages::receiver_query::ReceiverQueryReport,
            crate::analyzer::usages::receiver_query::ReceiverQueryError,
        >,
    > {
        None
    }

    fn call_reference_candidate_override(&self, _node: tree_sitter::Node<'_>) -> Option<bool> {
        None
    }

    fn definition_call_reference_candidate(&self, _node: tree_sitter::Node<'_>) -> bool {
        false
    }

    fn definition_call_callee<'tree>(
        &self,
        _node: tree_sitter::Node<'tree>,
    ) -> Option<tree_sitter::Node<'tree>> {
        None
    }

    fn definition_call_signature_context(
        &self,
        _node: tree_sitter::Node<'_>,
        _byte_offset: usize,
    ) -> Option<crate::analyzer::usages::get_definition::call_sites::CallSignatureContext> {
        None
    }

    fn definition_nested_callable(&self, _node: tree_sitter::Node<'_>) -> bool {
        false
    }

    fn definition_boundary_evidence(
        &self,
        _analyzer: &dyn crate::analyzer::IAnalyzer,
        _token: crate::analyzer::QueryToken<'_>,
        _file: &crate::analyzer::ProjectFile,
        _name: &str,
    ) -> Option<(
        crate::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        None
    }

    fn allocation_binds_by_reference_at_offset(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _offset: usize,
    ) -> Option<bool> {
        None
    }

    fn allocation_boxes_reference_payload_at_offset(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _offset: usize,
    ) -> Option<bool> {
        None
    }

    fn result_binds_by_reference_at_ordinal(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &str,
        _declaration: &CodeUnit,
        _ordinal: usize,
    ) -> Option<bool> {
        None
    }

    fn parameter_binds_by_reference_at_span(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _start: usize,
        _end: usize,
        _ordinal: usize,
    ) -> Option<bool> {
        None
    }

    fn parameter_preserves_backing_at_span(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _start: usize,
        _end: usize,
        _ordinal: usize,
    ) -> Option<bool> {
        None
    }

    fn parameter_boxes_reference_payload_at_span(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _start: usize,
        _end: usize,
        _ordinal: usize,
    ) -> Option<bool> {
        None
    }

    fn parameter_is_reference_free_at_ordinal(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &str,
        _declaration: &CodeUnit,
        _ordinal: usize,
    ) -> Option<bool> {
        None
    }

    fn modeled_method_selection_at_offset(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &str,
        _offset: usize,
    ) -> Option<String> {
        None
    }

    fn lexical_binding_repeats_at_offset(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _offset: usize,
    ) -> Option<bool> {
        None
    }

    fn declaration_site_at_offset(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &str,
        _offset: usize,
    ) -> Option<CodeUnit> {
        None
    }

    fn navigation_declaration_site_at_offset(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &str,
        _offset: usize,
    ) -> Option<CodeUnit> {
        None
    }

    fn reference_plugin(&self) -> ReferenceLanguagePlugin {
        ReferenceLanguagePlugin {
            strategy: self.reference_usage_strategy(),
            graph: self.reference_graph_backend(),
        }
    }

    fn call_relation_provider(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_relations::CallRelationProvider> {
        None
    }

    /// Refine legacy incoming hits whose graph does placement by owner, name
    /// and call shape without argument types, so a hit can sit under the
    /// wrong overload. C# matches
    /// ordinary/generic arity before bucketing hits under the requested target.
    /// Java's legacy graph also matches owner and arity; Kotlin uses FQN and
    /// accepted arities; Scala adds call-list, named-argument and literal checks
    /// but does not fully type non-literal arguments. Their opt-ins remain
    /// separate changes requiring language-specific proof, cache and CPU checks.
    /// A false default preserves existing authority, not a claim of exactness.
    /// External static-owner normalization (`csharp_normalized_static_owner`)
    /// is separate from source overload selection. Native call-relation
    /// providers bypass this legacy projection.
    fn refine_legacy_incoming_overload_families(&self) -> bool {
        false
    }

    /// Refine proof for resolved source-call targets using language-owned
    /// receiver evidence. The default keeps the resolver's proof unchanged.
    fn refine_resolved_call_targets(
        &self,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _site: &ExternalCalleeSite<'_>,
        _targets: &mut [crate::analyzer::usages::call_relations::CallDispatchTarget],
    ) {
    }

    fn rename_provider(&self) -> Option<&'static dyn crate::analyzer::rename::RenameProvider> {
        None
    }

    /// The builder of this language's whole-workspace selected inverse
    /// reference index, or `None` when the language has no selected resolution
    /// engine and its inverse edges are derived one declaration at a time.
    ///
    /// Registering a provider makes the selected index this language's only
    /// inverse-edge authority for RQL `edges_of` and the policy edge asserts,
    /// so those consumers report a build refusal as an incomplete inverse
    /// axis rather than deriving the same question by the other route.
    fn selected_inverse_reference_provider(
        &self,
    ) -> Option<
        &'static dyn crate::analyzer::structural::reference_edges::SelectedInverseReferenceProvider,
    > {
        None
    }

    /// This language's analyzer inside `analyzer`, viewed as a forward-query provider.
    /// Each support owns the downcast to its own concrete analyzer; `None` means the
    /// workspace does not analyze this language, which callers treat as an empty result
    /// rather than a failure.
    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider>;

    /// Whether written call arguments enumerate the values that will bind.
    /// Languages with implicit argument expansion withhold completeness until
    /// the query has proved that no unrepresented values are being passed.
    fn call_argument_partition_is_complete(
        &self,
        _analyzer: &dyn IAnalyzer,
        _shape: &crate::analyzer::usages::call_shape::CallShapeReport,
        _cancellation: Option<&crate::analyzer::semantic::CancellationToken>,
    ) -> bool {
        true
    }

    /// Language-owned producer for resolver-proven actual-to-formal call
    /// conversion facts. The shared call-conversion relation supplies the
    /// exact call/signature/actual/formal join and invokes this capability for
    /// owner applicability and AST-backed type proof.
    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_conversion::CallArgumentConversionProver>
    {
        None
    }

    /// Bounded evidence about saved callable defaults. `None`
    /// leaves default-argument binding unproven because the language has no
    /// such capability or the analyzer is absent. Incomplete scans leave all
    /// defaults open.
    fn saved_default_argument_safety(
        &self,
        _analyzer: &dyn IAnalyzer,
    ) -> Option<Arc<SavedDefaultArgumentSafety>> {
        None
    }

    /// Prove the initializer and reference census for a package-scope
    /// callable value. `None` means the rule does not apply or its language
    /// analyzer is unavailable; `Some(Err(_))` preserves a structured reason
    /// why the proof could not be completed.
    fn stable_package_function_value_proof(
        &self,
        _analyzer: &dyn IAnalyzer,
        _variable: &CodeUnit,
        _declaring_source: &str,
    ) -> Option<Result<StablePackageFunctionValueProof, String>> {
        None
    }

    /// Whether a member-family edge can be a virtual-dispatch target for this
    /// language. The default keeps every proven edge; languages with narrower
    /// dispatch domains may reject it using their analyzer's structured facts.
    fn virtual_dispatch_target_is_applicable(
        &self,
        _analyzer: &dyn IAnalyzer,
        _declaration: &CodeUnit,
        _target_file: &ProjectFile,
    ) -> bool {
        true
    }

    /// Whether the bounded package declaration lookup proves that a
    /// predeclared builtin is or is not shadowed. `BeginLookup` is called only
    /// after the language analyzer is available; each candidate visit is
    /// separately budgeted and may be cancelled by the caller.
    fn predeclared_builtin_shadow_status_limited(
        &self,
        _analyzer: &dyn IAnalyzer,
        _relative_path: &str,
        _name: &str,
        _limit: usize,
        _query_step: &mut dyn FnMut(PredeclaredBuiltinQueryStep) -> bool,
    ) -> Option<bool> {
        None
    }

    /// Signature metadata this language's analyzer holds for `unit`, visiting at most
    /// `limit` rows. `None` means the workspace does not analyze this language, or the
    /// language keeps no signature metadata at all: Java, JavaScript and TypeScript
    /// answer `None` because their analyzers expose no such projection, and the receiver
    /// query charges both cases to the same budget limit.
    fn signature_metadata_limited(
        &self,
        _analyzer: &dyn IAnalyzer,
        _unit: &CodeUnit,
        _limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        None
    }

    /// Whether `spelling`, read in `file`, resolves through this language's
    /// external declaration surface to a member proven both static and a
    /// compile-time constant (#2538).
    ///
    /// The workspace oracle uses this to discharge a `FieldMemory` gap for a
    /// read of an external constant: such a read cannot observe or produce a
    /// heap effect the gap would otherwise have to keep open. The default is
    /// `false` -- a language without a modeled external declaration surface,
    /// or whose analyzer is absent from this workspace, leaves the gap
    /// standing. An implementation must answer `true` only from proven
    /// declaration evidence, never from the spelling's shape.
    fn external_compile_time_constant_member(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _spelling: &str,
    ) -> bool {
        false
    }

    /// Whether an exact closed nominal receiver proof and a unique complete
    /// summary can close an external method body. Languages opt in only when
    /// the proven method set cannot acquire overrides.
    fn closed_receiver_summary_closes_external_body(&self) -> bool {
        false
    }

    /// Whether the external declaration surface proves `owner.member` is static.
    /// `None` means this language has no such proof or the analyzer is absent.
    fn external_member_is_static(
        &self,
        _analyzer: &dyn IAnalyzer,
        _packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        _owner: &str,
        _member: &str,
    ) -> Option<bool> {
        None
    }

    /// Whether the external declaration surface proves `owner` is sealed.
    /// `None` means this language has no such proof or the analyzer is absent.
    fn external_type_is_sealed(
        &self,
        _analyzer: &dyn IAnalyzer,
        _packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        _owner: &str,
    ) -> Option<bool> {
        None
    }

    /// Whether the call whose source mapping spans `call` in `source` provably
    /// cannot throw an exception the catch parameter whose name spans
    /// `catch_parameter` catches.
    ///
    /// The workspace oracle uses this to drop a lowered catch binding from
    /// that call's thrown value, so the parameter keeps the origins of the
    /// throws that can reach it. The default is `false`, which keeps every
    /// binding. An implementation must answer `true` only from the language's
    /// own exception typing rules, never from spelling.
    fn call_cannot_reach_catch_parameter(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &Arc<str>,
        _call: std::ops::Range<usize>,
        _catch_parameter: std::ops::Range<usize>,
    ) -> bool {
        false
    }

    /// Whether dropping every parameter and every `let` binding of the
    /// procedure whose callable spans `callable` in `source` provably runs no
    /// user code (#3757).
    ///
    /// The workspace oracle uses this to discharge a gap whose declared
    /// obligation is `SemanticGapDischarge::InertDropGlue`. The default is
    /// `false`, which keeps every such gap. An implementation must answer
    /// `true` only from structured type evidence and resolver proof, never
    /// from spelling.
    fn procedure_drops_run_no_user_code(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &Arc<str>,
        _callable: std::ops::Range<usize>,
    ) -> bool {
        false
    }

    /// Whether the residual conversion spanned by `conversion` in `source`
    /// provably runs no user code (#4967).
    ///
    /// The workspace oracle uses this to discharge a gap whose declared
    /// obligation is `SemanticGapDischarge::ResidualConversion`, the `?`
    /// operator's `From` conversion on the error path. The default is `false`,
    /// which keeps every such gap. An implementation must answer `true` only
    /// from structured resolver proof, never from spelling.
    fn residual_conversion_runs_no_user_code(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &Arc<str>,
        _conversion: std::ops::Range<usize>,
    ) -> bool {
        false
    }

    /// Rendered signatures this language's analyzer holds for `unit`, visiting at most
    /// `limit` rows. `None` means the workspace does not analyze this language, or the
    /// language keeps no direct signature projection.
    fn signatures_limited(
        &self,
        _analyzer: &dyn IAnalyzer,
        _unit: &CodeUnit,
        _limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        None
    }

    /// Declaration ranges this language's analyzer holds for `unit`, visiting at most
    /// `limit` rows. No default: every registered language answers this, and a silent
    /// `None` would report every receiver in that language as budget-exceeded.
    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>>;

    /// Canonical physical occurrences for navigation. Missing required evidence is
    /// `None`; languages without distinct physical roles expose unknown roles.
    fn declaration_navigation_occurrences(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<Vec<DeclarationNavigationOccurrence>> {
        Some(
            analyzer
                .ranges(unit)
                .into_iter()
                .map(|range| DeclarationNavigationOccurrence {
                    range,
                    role: DeclarationNavigationRole::Unknown,
                })
                .collect(),
        )
    }

    /// How dead-code analysis proves this language's candidates.
    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport::default()
    }

    /// Report-local coverage, including language-owned exclusions from authoritative absence.
    /// The returned collections must not survive this report.
    fn dead_code_coverage(
        &self,
        _analyzer: &dyn IAnalyzer,
        _candidates: &[CodeUnit],
    ) -> crate::analyzer::store::Result<DeadCodeCoverage> {
        Ok(DeadCodeCoverage::default())
    }

    /// Whether this reason describes the report's stated certainty boundary rather
    /// than a missing reference. Reference-attributable losses must return false.
    fn dead_code_reason_is_scope(&self, _reason: &EdgeIncompleteReason) -> bool {
        false
    }

    /// Whether a semantic gap is already fully attributed by the graph's
    /// unresolved-name set. The consumer still vetoes every matching candidate.
    fn dead_code_reason_is_attributed(&self, _reason: &EdgeIncompleteReason) -> bool {
        false
    }

    /// Explicit caller inventory for precise dead-code proof when generic import
    /// discovery is not this language's native authority. A missing file budget
    /// still makes the proof inconclusive; this is never a fallback resolver.
    fn dead_code_reference_scope(&self, _analyzer: &dyn IAnalyzer) -> Option<HashSet<ProjectFile>> {
        None
    }

    /// Interpret precise-query coverage for this consumer without changing usages.
    fn dead_code_usage_result(&self, result: FuzzyResult) -> FuzzyResult {
        result
    }

    /// Source files in no selected build context; their references still veto dead code.
    fn dead_code_outside_build_files(
        &self,
        _analyzer: &dyn IAnalyzer,
    ) -> crate::analyzer::store::Result<HashSet<ProjectFile>> {
        Ok(HashSet::default())
    }

    /// Whether a candidate requires the language's precise dead-code strategy.
    fn dead_code_needs_precise_scan(
        &self,
        _analyzer: &dyn IAnalyzer,
        _candidate: &CodeUnit,
    ) -> bool {
        false
    }

    /// Bounded structural receiver resolution, or `None` when receiver queries for this
    /// language take another route (Java runs a resolution session, JS/TS runs its own
    /// syntax-index path) or are unsupported entirely.
    ///
    /// This is the single owner of the structural-receiver capability: the receiver query
    /// gate admits exactly the languages that answer `Some` here, so an absent resolver
    /// yields the `receiver_analysis_language_unsupported` report rather than reaching a
    /// dispatch that cannot serve it.
    ///
    /// `get_type_by_location` dispatches through the same resolver (with its own, more
    /// generous budget), so one bounded core answers both the receiver query and the
    /// interactive type lookup; Java and JS/TS take their other routes there too.
    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        None
    }

    /// Resolve an expression that denotes an imported package namespace.
    fn imported_package_at_range(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &str,
        _start_byte: usize,
        _end_byte: usize,
    ) -> Option<String> {
        None
    }

    /// Refine a selector call with the language's receiver method-set evidence.
    #[allow(clippy::too_many_arguments)]
    fn refine_selector_call_target(
        &self,
        _lookup: &mut crate::analyzer::usages::call_relations::CallDispatchLookup,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _source: &str,
        _tree: &tree_sitter::Tree,
        _callee_range: &Range,
        _cancellation: Option<&CancellationToken>,
    ) {
    }

    /// Resolve an interactive type lookup through the language's existing bounded route.
    fn bounded_type_resolution(
        &self,
        _definitions: &crate::analyzer::AnalyzerDefinitionLookup<'_>,
        _language: Language,
        query: BoundedReceiverQuery<'_>,
    ) -> Option<BoundedResolution<TypeLookupOutcome>> {
        Some(self.structural_receiver()?.resolve_type_bounded(query))
    }

    /// Prepare syntax for interactive type lookup.
    fn parse_tree_for_type_lookup(
        &self,
        file: &ProjectFile,
        language: Language,
        source: &str,
    ) -> Option<tree_sitter::Tree> {
        crate::analyzer::usages::get_definition::parse_tree_for_language(file, language, source)
    }

    /// Open the optional state shared by structural receiver queries in one request.
    fn open_receiver_request<'a>(
        &self,
        _analyzer: &'a dyn IAnalyzer,
        _cancellation: &CancellationToken,
    ) -> Option<Box<dyn ReceiverRequest + 'a>> {
        None
    }

    /// Whether two callable declarations share this language's identity evidence.
    fn callable_definitions_share_identity_evidence(
        &self,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _target: &CodeUnit,
        _candidate: &CodeUnit,
    ) -> bool {
        false
    }

    /// Derive the rewrite domains this language declares for one file.
    fn rewrite_paths(
        &self,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        generation: u64,
        _request: &mut crate::analyzer::structural::rewrite_paths::RewritePathRequest<'_>,
    ) -> crate::analyzer::structural::rewrite_paths::FileRewritePaths {
        crate::analyzer::structural::rewrite_paths::FileRewritePaths::complete(
            Vec::new(),
            generation,
        )
    }

    /// Open one request-owned native operation and memo context, on demand.
    fn value_type_barrier_context<'a>(
        &self,
        _analyzer: &'a dyn IAnalyzer,
        _cancellation: &crate::CancellationToken,
    ) -> Result<
        Option<Box<dyn crate::analyzer::semantic::ValueTypeBarrierContext + 'a>>,
        SemanticProviderError,
    > {
        Ok(None)
    }

    /// Classify one value-type predicate using this language's type proofs.
    ///
    /// The caller owns the query budget, cancellation, and any memoization.
    /// Unsupported languages must remain undecided rather than silently
    /// claiming that their values cannot match a barrier.
    fn value_type_barrier(
        &self,
        _analyzer: &dyn IAnalyzer,
        _observation: &BarrierObservation,
        _predicate: ValueTypePredicate,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, SemanticProviderError> {
        Ok(ValueTypeBarrierDecision::Undecided(
            ValueTypeBarrierReason::UnsupportedLanguage,
        ))
    }

    /// Resolve a declared carrier shape using the request-owned native context.
    /// Canonical names exclude generic arguments and come from structured identities.
    fn observed_value_type(
        &self,
        _analyzer: &dyn IAnalyzer,
        _observation: &BarrierObservation,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<crate::analyzer::semantic::ObservedValueType, SemanticProviderError> {
        Ok(crate::analyzer::semantic::ObservedValueType::Undecided(
            ValueTypeBarrierReason::UnsupportedLanguage,
        ))
    }

    /// The native row-backed point resolver of a language whose production
    /// routing has not flipped yet, reached only by the rollout probes. At the
    /// flip it becomes the language's `structural_receiver` and this returns
    /// `None` again.
    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        None
    }

    /// Class-set type-propagation adapter for this language, or `None` when the
    /// engine has no per-language facts for it. The default means class-set
    /// propagation reports `Unsupported` for this language: an absent adapter
    /// is an honest capability statement, never an empty class set.
    fn type_flow_adapter(&self) -> Option<&'static dyn crate::analyzer::semantic::TypeFlowAdapter> {
        None
    }

    /// Per-file setup and per-query factory for languages whose receiver analysis runs on
    /// their own syntax index instead of through [`StructuralReceiverResolver`].
    ///
    /// One accessor to a two-method trait rather than two capabilities, for the reason
    /// [`StructuralReceiverResolver`] is one trait: a language answering only half of it
    /// would strand the query between preparing a file and querying it.
    fn receiver_facts(&self) -> Option<&'static dyn ReceiverFactsFactory> {
        None
    }

    /// Candidate files this language contributes to a usage query beyond the generic
    /// import-graph and text-search routes. Consulted for default discovery and incomplete
    /// seed providers; a complete execution-scope provider is never augmented.
    fn candidate_augmentation(&self, _ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        None
    }

    /// Expand a source-level callee spelling to the external identity that semantic
    /// models publish, when this language can prove the expansion from structured
    /// language evidence. The default offers no expansion.
    ///
    /// The call site's parsed file and exact source are handed over for the same
    /// reason [`Self::single_segment_external_owner`] receives them: a language
    /// may have to ask a scope question about the evidence it expands from --
    /// Rust's import binder expands only while the path it binds has a root the
    /// workspace does not claim (#3484).
    fn expand_imported_external_callee(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _callee_text: &str,
        _site: Option<&ExternalCalleeSite<'_>>,
    ) -> Option<ImportedExternalCallee> {
        None
    }

    /// The canonical owner a single-segment external callee publishes, or
    /// `None` when this owner names no external identity at all (#2598).
    ///
    /// Called only when [`Self::publishes_single_segment_external_owners`] is
    /// true and only after the callee has already failed to resolve, so the
    /// question is never "what does this name mean" but "does anything in this
    /// file already answer that". A language answers it from its own binding
    /// structure; there is no shared rule, because what may legally shadow a
    /// runtime global differs by language.
    ///
    /// Returning a *different* owner than `owner` is how a module binding
    /// publishes its module's identity rather than the local name a file
    /// happened to give it.
    ///
    /// `member` is the callee's own member name. An owner that is a shared
    /// mutable object publishes an identity for one member at a time, because
    /// the file may have replaced exactly that member (#3427).
    fn single_segment_external_owner(
        &self,
        _owner: &str,
        _member: &str,
        _site: &ExternalCalleeSite<'_>,
    ) -> Option<String> {
        None
    }

    /// Grammar nodes that own ordinary formal parameters. None retains the
    /// shared legacy grammar table for languages not yet providing this hook.
    fn formal_parameter_owner_kinds(&self) -> Option<&'static [&'static str]> {
        None
    }

    /// The syntax declaration supplying a callable's parameters. Most
    /// callables write their own list; compact forms may inherit an owner's.
    fn formal_parameter_source_owner<'tree>(
        &self,
        owner: tree_sitter::Node<'tree>,
        _scope_step: &mut dyn FnMut() -> bool,
    ) -> Option<tree_sitter::Node<'tree>> {
        Some(owner)
    }

    /// A type header can supply constructor formals without making them
    /// lexical parameters throughout the type's body.
    fn parameter_owner_has_lexical_bindings(&self, _owner: tree_sitter::Node<'_>) -> bool {
        true
    }

    /// A compiler-supplied callable may have exact formals without a written
    /// callable AST node. A language must prove its source member shape here.
    fn implicit_callable_parameter_layout(
        &self,
        _unit: &CodeUnit,
        _root: tree_sitter::Node<'_>,
        _source: &str,
        _range: &Range,
    ) -> Option<crate::analyzer::lexical_definitions::FormalParameterLayout> {
        None
    }

    /// Whether a lexical definition may be resolved from the focused node at all. Rust
    /// says no for struct-field names, whose owning type -- not the enclosing scope --
    /// decides what they denote, so resolving them lexically would answer with the wrong
    /// binding rather than with none.
    fn focus_resolves_lexically(&self, _focus: tree_sitter::Node<'_>) -> bool {
        true
    }

    /// The syntax scope that owns a local declaration whose binding rules differ from
    /// ordinary source-order visibility. `None` keeps the framework's default rule that
    /// a local declaration is visible only after its declaration. JavaScript and
    /// TypeScript return their structured variable-binding scope and state whether the
    /// binding is lexical or hoisted.
    fn local_declaration_binding_scope<'tree>(
        &self,
        _node: tree_sitter::Node<'tree>,
    ) -> Option<LocalDeclarationBindingScope<'tree>> {
        None
    }

    /// Attach language-owned source scope to declarations emitted by semantic-model rules.
    /// The default leaves generated symbols unchanged.
    fn bind_generated_symbols(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _symbols: &mut [crate::analyzer::semantic_model::SemanticModelSymbol],
    ) {
    }
}

/// Identity of one whole-workspace edge resolver family.
///
/// Not one per `Language`: JavaScript and TypeScript are served by a single resolver and
/// report the same id, while Java, Scala and Kotlin run three distinct resolvers over one
/// shared candidate space. Framework collectors deduplicate by this id, so neither fact
/// has to be re-encoded at a consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub enum EdgePassId {
    Rust,
    Python,
    JsTs,
    Java,
    Scala,
    Kotlin,
    Go,
    CSharp,
    Cpp,
    Php,
    Ruby,
}

impl EdgePassId {
    /// Every pass, in the order framework collectors run them.
    ///
    /// Passes sharing an ecosystem are adjacent, which is load-bearing: the workspace
    /// graph reports the ecosystems it resolved by pushing one entry per pass and
    /// collapsing *consecutive* duplicates, so splitting the JVM trio apart would report
    /// `Jvm` three times.
    #[doc(hidden)]
    pub const ALL: [Self; 11] = [
        Self::Rust,
        Self::Python,
        Self::JsTs,
        Self::Java,
        Self::Scala,
        Self::Kotlin,
        Self::Go,
        Self::CSharp,
        Self::Cpp,
        Self::Php,
        Self::Ruby,
    ];

    /// Profiling-scope suffix naming this pass.
    #[doc(hidden)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Python => "python",
            Self::JsTs => "jsts",
            Self::Java => "java",
            Self::Scala => "scala",
            Self::Kotlin => "kotlin",
            Self::Go => "go",
            Self::CSharp => "csharp",
            Self::Cpp => "cpp",
            Self::Php => "php",
            Self::Ruby => "ruby",
        }
    }
}

/// One language family's whole-workspace `caller -> callee` scan.
///
/// Replaces the per-language `UsageEdgeResolver` uniformity contract, which had eleven
/// monomorphic implementations and no polymorphic use. What that trait documented and
/// this one enforces: every graph language builds its edges in a single inverted pass
/// over the workspace, borrowing its concrete analyzer once, rather than scanning each
/// symbol's candidate files.
///
/// The two methods are two *finalizations* of the same underlying scan, not two scans.
/// `edge_sites` keeps every call site's path and line; `edge_weights` keeps reference-kind
/// counts. Neither is reconstructible from the other, and each consumer calls only the one
/// it needs, so a language still scans exactly once per consumer.
#[doc(hidden)]
pub trait LanguageEdgePass: Send + Sync {
    fn id(&self) -> EdgePassId;

    /// Check input authority even when unavailable declarations leave no roots.
    /// None means no known failure (including an inapplicable language).
    ///
    /// `request_files` is the file set this request will resolve: the files a
    /// rooted request named, or every analyzable file when it named none. A
    /// pass whose authority is per file must answer about those files only, so
    /// a rooted request is never made unavailable by a file it never named and
    /// never pays a workspace-sized read for one.
    fn input_failure(
        &self,
        _analyzer: &dyn IAnalyzer,
        _request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        None
    }

    /// Sources this pass omits as explained exclusions while its input stays
    /// available: files that source admission refused, each with the recorded
    /// reason object as JSON text. A consumer names each one as partial
    /// coverage and never treats the missing references as proof of absence.
    fn excluded_sources(
        &self,
        _analyzer: &dyn IAnalyzer,
    ) -> crate::analyzer::store::Result<Vec<(ProjectFile, String)>> {
        Ok(Vec::new())
    }

    /// Whether an FQN-only edge can be a proven relation to a logical callable
    /// family even when no single physical overload is selected. Consumers
    /// retain every candidate endpoint and report the non-exact relation.
    fn permits_logical_family_targets(&self) -> bool {
        false
    }

    /// Location-bearing edges for the `usage_graph` consumer. `None` when the workspace
    /// does not analyze this pass's languages; the consumer records nothing and reports
    /// no diagnostic. An applicable pass that could not build reports `Unavailable`.
    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites>;

    /// Reference-kind counts for the workspace-graph consumer, in whichever node
    /// identity this pass keys by.
    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights>;
}

/// One language family's semantic hooks behind [`ReferenceEngine`](crate::analyzer::usages::ReferenceEngine).
///
/// Planning, admission, traversal, cancellation, completeness and canonical
/// row formatting belong to the engine. This descriptor is deliberately only
/// the semantic plug point. Keeping the target resolver and file scanner in
/// one registered value prevents the two workloads from being wired through
/// unrelated registry paths again.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct ReferenceLanguagePlugin {
    strategy: &'static dyn GraphUsageAnalyzer,
    #[doc(hidden)]
    pub graph: LanguageGraphBackend,
}

impl ReferenceLanguagePlugin {
    pub(crate) const fn target_strategy(self) -> &'static dyn GraphUsageAnalyzer {
        self.strategy
    }
}

/// A pass has exactly one graph authority. Native endpoints retain declaration
/// identity instead of being converted back into legacy name-based edges.
#[derive(Clone, Copy)]
#[doc(hidden)]
pub enum LanguageGraphBackend {
    Legacy(&'static dyn LanguageEdgePass),
    Native(&'static dyn NativeWorkspaceGraphProvider),
}

impl LanguageGraphBackend {
    #[doc(hidden)]
    pub fn id(self) -> EdgePassId {
        match self {
            Self::Legacy(pass) => pass.id(),
            Self::Native(provider) => provider.id(),
        }
    }

    /// The input-authority preflight of whichever backend holds this pass.
    ///
    /// Both graph consumers run this before building a catalog, because an
    /// unavailable declaration catalog is empty rather than absent: without the
    /// preflight a pass whose canonical facts could not be read reports a
    /// complete graph with no edges. The question is the backend's, not the
    /// legacy implementation's, so it is asked through the authority the
    /// language actually registered.
    #[doc(hidden)]
    pub fn input_failure(
        self,
        analyzer: &dyn IAnalyzer,
        request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        match self {
            Self::Legacy(pass) => pass.input_failure(analyzer, request_files),
            Self::Native(provider) => provider.input_failure(analyzer, request_files),
        }
    }

    /// The explained exclusions of whichever backend holds this pass. Every
    /// consumer that passes [`Self::input_failure`] and claims completeness
    /// must account for them.
    #[doc(hidden)]
    pub fn excluded_sources(
        self,
        analyzer: &dyn IAnalyzer,
    ) -> crate::analyzer::store::Result<Vec<(ProjectFile, String)>> {
        match self {
            Self::Legacy(pass) => pass.excluded_sources(analyzer),
            Self::Native(provider) => provider.excluded_sources(analyzer),
        }
    }
}

#[doc(hidden)]
pub trait NativeWorkspaceGraphProvider: Send + Sync {
    fn id(&self) -> EdgePassId;

    /// Check input authority even when unavailable declarations leave no roots.
    /// None means no known failure (including an inapplicable language).
    ///
    /// `request_files` carries the same contract as
    /// [`LanguageEdgePass::input_failure`]: it is the request's own file set,
    /// and a per-file authority answers about those files alone.
    fn input_failure(
        &self,
        _analyzer: &dyn IAnalyzer,
        _request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        None
    }

    /// Sources this provider omits as explained exclusions while its input stays
    /// available: files that source admission refused, each with the recorded
    /// reason object as JSON text. A consumer names each one as partial
    /// coverage and never treats the missing references as proof of absence.
    fn excluded_sources(
        &self,
        _analyzer: &dyn IAnalyzer,
    ) -> crate::analyzer::store::Result<Vec<(ProjectFile, String)>> {
        Ok(Vec::new())
    }

    /// The `callers` whose references this provider could resolve to a
    /// declaration in one of `targets`, in `callers` order.
    ///
    /// A consumer that only reads the edges into declarations of `targets`
    /// projects these callers instead of all of them: every caller left out
    /// is one whose edges it would discard. The default keeps every caller.
    fn callers_reaching(
        &self,
        _analyzer: &dyn IAnalyzer,
        callers: &[ProjectFile],
        _targets: &[ProjectFile],
        _cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<Vec<ProjectFile>> {
        Ok(callers.to_vec())
    }

    /// An empty caller slice admits no sources. Dependency definitions remain
    /// available, but only admitted callers may contribute outgoing edges.
    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        admitted_callers: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<
        crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome,
    >;
}

/// Location-bearing edges in the node identity native to the language family.
/// Package-scoped languages use an FQN; module-scoped JS/TS retains the source
/// file so same-named exports never collapse at the plugin boundary.
#[doc(hidden)]
pub enum LanguageEdgeSites {
    Fqn(UsageEdges),
    Scoped(UsageEdges<UsageNodeKey>),
    // Preserved for edge passes that cannot build complete input; Go's retained legacy
    // test pass exercises it while production Go uses the typed native provider outcome.
    #[allow(dead_code)]
    Unavailable(LanguageEdgeFailure),
}

/// An applicable language pass could not obtain complete input facts. This is
/// different from an inapplicable pass or a complete graph with no edges.
#[derive(Debug)]
#[doc(hidden)]
pub struct LanguageEdgeFailure {
    pub reason: &'static str,
    pub files: Vec<ProjectFile>,
}

/// Reference-kind counts in this pass's node identity. JS/TS keys by `{file, fqn}` because
/// same-named exports in different modules are different declarations; every other pass
/// keys by fqn within its ecosystem.
#[doc(hidden)]
pub enum LanguageEdgeWeights {
    Fqn(UsageEdgeWeights),
    Scoped(JsTsScopedUsageEdges),
    // See `LanguageEdgeSites::Unavailable`.
    #[allow(dead_code)]
    Unavailable(LanguageEdgeFailure),
}

/// Inputs to a sites scan. `keep_file` drops out-of-scope caller files before parsing and
/// is called once per file, never per reference.
#[doc(hidden)]
pub struct EdgeSiteScanCtx<'a> {
    #[doc(hidden)]
    pub cancellation: &'a CancellationToken,
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub fqns: &'a HashSet<String>,
    #[doc(hidden)]
    pub scoped_callers: &'a HashSet<UsageNodeKey>,
    #[doc(hidden)]
    pub keep_file: &'a (dyn Fn(&ProjectFile) -> bool + Sync),
}

/// Inputs to a weights scan. Both node sets are supplied because the collector cannot know
/// which identity a pass keys by; a pass reads exactly one of them.
#[doc(hidden)]
pub struct EdgeWeightScanCtx<'a> {
    /// Kinds retained from the graph's indexed declaration inventory.
    pub declaration_kinds: &'a DeclarationKinds,
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub fqns: &'a HashSet<String>,
    #[doc(hidden)]
    pub scoped_nodes: &'a HashSet<UsageNodeKey>,
    #[doc(hidden)]
    pub keep_file: &'a (dyn Fn(&ProjectFile) -> bool + Sync),
}

#[doc(hidden)]
pub fn fqn_edge_sites(
    ctx: &EdgeSiteScanCtx<'_>,
    build: impl FnOnce(QueryToken<'_>) -> Option<UsageEdges>,
) -> Option<LanguageEdgeSites> {
    let scope = crate::analyzer::AnalyzerQueryScope::new(ctx.analyzer);
    build(scope.token()).map(LanguageEdgeSites::Fqn)
}

#[doc(hidden)]
pub fn fqn_edge_weights(
    ctx: &EdgeWeightScanCtx<'_>,
    build: impl FnOnce(QueryToken<'_>) -> Option<UsageEdgeWeights>,
) -> Option<LanguageEdgeWeights> {
    let scope = crate::analyzer::AnalyzerQueryScope::new(ctx.analyzer);
    build(scope.token()).map(LanguageEdgeWeights::Fqn)
}

/// One pass together with the ecosystem its owning supports agree on.
#[doc(hidden)]
pub struct EdgePassEntry {
    #[doc(hidden)]
    pub id: EdgePassId,
    #[doc(hidden)]
    pub ecosystem: UsageEcosystem,
    #[doc(hidden)]
    pub languages: Vec<Language>,
    #[doc(hidden)]
    pub backend: LanguageGraphBackend,
}

/// The graph authority every edge pass is registered with, as one digest.
///
/// Which implementation answers a language's reference, call, graph and
/// dead-code questions is an engine input exactly like the grammar it parses
/// with: two engines that disagree about it derive different answers from
/// identical bytes. Every identity that must not survive a per-language flip --
/// the workspace usage-graph cache key and the analysis epoch a recorded read
/// set carries -- folds this value, so a flip rotates them all and there is no
/// separate hand-bumped version to remember on the next one.
///
/// Derived from the live registry rather than from a constant, which is why
/// [`graph_authority_digest_of`] takes the passes: the production digest reads
/// [`edge_passes`], and a test can ask what the same registry would digest with
/// one language on the other authority.
#[doc(hidden)]
pub fn graph_authority_digest() -> StableDigest {
    static PRODUCTION: std::sync::OnceLock<StableDigest> = std::sync::OnceLock::new();
    *PRODUCTION.get_or_init(|| graph_authority_digest_of(&edge_passes()))
}

#[doc(hidden)]
pub fn graph_authority_digest_of(passes: &[EdgePassEntry]) -> StableDigest {
    let mut hasher = CanonicalHasher::new(GRAPH_AUTHORITY_DOMAIN);
    for entry in passes {
        hasher.field(
            entry.id.as_str(),
            match entry.backend {
                LanguageGraphBackend::Legacy(_) => b"legacy".as_slice(),
                LanguageGraphBackend::Native(_) => b"native".as_slice(),
            },
        );
    }
    StableDigest::from_array(hasher.finish())
}

/// Domain for [`graph_authority_digest`].
const GRAPH_AUTHORITY_DOMAIN: &[u8] = b"bifrost-language-graph-authority:v1";

/// Every active edge pass, deduplicated by [`EdgePassId`] and ordered by
/// [`EdgePassId::ALL`].
///
/// The shared half of both edge consumers: iterating supports directly would run the
/// JS/TS pass twice, and deduplicating by ecosystem would collapse the three JVM passes
/// into one even while they use distinct legacy authorities. Ecosystem selection,
/// node-set choice and result conversion stay with each
/// consumer, because those are where the two genuinely differ.
#[doc(hidden)]
pub fn edge_passes() -> Vec<EdgePassEntry> {
    let mut entries = Vec::with_capacity(EdgePassId::ALL.len());
    for id in EdgePassId::ALL {
        let mut entry: Option<EdgePassEntry> = None;
        for language in Language::ANALYZABLE {
            let support = language_support_for_hook(language, "reference_plugin")
                .expect("analyzable languages are registered");
            let backend = support.reference_plugin().graph;
            if backend.id() != id {
                continue;
            }
            match &mut entry {
                None => {
                    entry = Some(EdgePassEntry {
                        id,
                        ecosystem: support.ecosystem(),
                        languages: vec![language],
                        backend,
                    });
                }
                Some(entry) => {
                    assert_eq!(
                        entry.ecosystem,
                        support.ecosystem(),
                        "{language:?} shares edge pass {id:?} but disagrees on its ecosystem"
                    );
                    assert!(
                        matches!(
                            (entry.backend, backend),
                            (
                                LanguageGraphBackend::Legacy(_),
                                LanguageGraphBackend::Legacy(_)
                            ) | (
                                LanguageGraphBackend::Native(_),
                                LanguageGraphBackend::Native(_)
                            )
                        ),
                        "languages sharing a pass must share its graph authority"
                    );
                    entry.languages.push(language);
                }
            }
        }
        // A shared native provider can replace several legacy pass IDs.
        // Every language was checked above; an unused ordering slot needs no pass.
        if let Some(entry) = entry {
            entries.push(entry);
        }
    }
    entries
}

/// How dead-code analysis proves one language's candidates.
///
/// Two proofs, and a language may offer either, both, or neither. `strategy` is the
/// precise per-symbol scan; `bulk` is a whole-workspace edge build a bucket of candidates
/// is proven against at once. Absence is not "unimplemented" and is deliberately silent:
/// Python and C++ have no per-symbol strategy because their candidates are always proven
/// in bulk, and a candidate that reaches a path its language does not serve is skipped as
/// inconclusive.
#[derive(Clone, Copy, Default)]
#[doc(hidden)]
pub struct DeadCodeSupport {
    #[doc(hidden)]
    pub strategy: Option<&'static dyn UsageAnalyzer>,
    #[doc(hidden)]
    pub bulk: Option<&'static dyn DeadCodeBulkProof>,
}

/// Coverage retained for one dead-code report only.
#[derive(Default)]
pub struct DeadCodeCoverage {
    pub note: Option<String>,
    pub vetoes: HashMap<brokk_bifrost_core::analyzer::model::DeclarationId, String>,
}

/// One language family's whole-workspace dead-code proof.
///
/// Deliberately not [`LanguageEdgePass`]. The dead-code builds diverge from the general
/// passes in ways a shared contract could only express as mode flags: Python resolves a
/// bounded target set through its cached builder, Scala uses its full builder with no file
/// predicate, Rust checks analyzer availability and measures its file cap off the
/// analyzer's own file list, and JS/TS needs per-node seed statuses the general weights
/// product does not carry. Each divergence stays inside the implementation that owns it.
#[doc(hidden)]
pub trait DeadCodeBulkProof: Send + Sync {
    /// Resolver-family identity, the same partition the edge passes use: candidates of
    /// languages served by one proof (JavaScript and TypeScript) share a bucket, while
    /// the JVM trio keep three.
    fn id(&self) -> EdgePassId;

    /// Whether `candidate` must take the per-symbol precise path instead of this proof.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool;

    /// Whether a precise candidate may take the conservative report-local inbound
    /// preflight. This is restricted to a language whose precise overload scan
    /// cannot complete within the report budget and whose inbound graph is used
    /// only to establish inconclusive evidence. Other precise-path reasons and
    /// languages stay on their precise route.
    fn supports_precise_inbound_preflight(&self, _routing: DeadCodeRouting<'_>) -> bool {
        false
    }

    /// Whole-workspace facts this proof memoizes across the candidates of one report.
    /// The default serves proofs whose routing decision needs none.
    fn new_memo(&self) -> Box<dyn Any + Send> {
        Box::new(())
    }

    /// The file count and label this proof's cap diagnostics report, or the reason the
    /// proof cannot run at all.
    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight;

    /// Resolve inbound edges for `candidates` over every declaration of this proof's
    /// languages as a possible caller.
    fn build(&self, analyzer: &dyn IAnalyzer, candidates: &[CodeUnit])
    -> Option<DeadCodeBulkEdges>;
}

#[doc(hidden)]
pub struct DeadCodeRouting<'a> {
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub candidate: &'a CodeUnit,
    #[doc(hidden)]
    pub file_cap: usize,
    /// The value [`DeadCodeBulkProof::new_memo`] produced for this bucket.
    #[doc(hidden)]
    pub memo: &'a mut dyn Any,
}

#[doc(hidden)]
pub enum DeadCodeBulkPreflight {
    /// Ready to build. `label` names the language family in cap diagnostics ("C++",
    /// "JS/TS"), and `files` is the count the cap is measured against, which is not
    /// always the project's analyzable-file count for one `Language`.
    Ready { label: &'static str, files: usize },
    /// The proof cannot run; every bucketed candidate is skipped with this reason.
    Unavailable(&'static str),
}

#[doc(hidden)]
pub enum DeadCodeBulkEdges {
    /// `Arc` rather than a bare value because Python's and Scala's builders hand back
    /// analyzer-cached graphs that outlive one report.
    Fqn(Arc<UsageEdges>),
    Scoped(JsTsScopedUsageEdges),
}

#[doc(hidden)]
pub fn build_fqn_dead_code_edges(
    analyzer: &dyn IAnalyzer,
    cache: &UsageEdgesCache,
    candidates: &[CodeUnit],
    build: impl FnOnce(QueryToken<'_>, &HashSet<String>) -> Option<UsageEdgeBuildResult<UsageEdges>>,
) -> Option<DeadCodeBulkEdges> {
    let callees = candidate_fqns(candidates);
    crate::analyzer::usages::inverted_edges::cached_dead_code_usage_edges(
        analyzer,
        cache,
        &callees,
        |token| build(token, &callees),
    )
    .map(DeadCodeBulkEdges::Fqn)
}

/// Every non-synthetic declaration of `language` that `is_caller` admits, plus the
/// candidates themselves. Bulk proofs need the whole workspace as possible callers while
/// resolving only their bounded candidate set, so the two sets differ.
#[doc(hidden)]
pub fn fqn_bulk_nodes(
    analyzer: &dyn IAnalyzer,
    language: Language,
    is_caller: impl Fn(&CodeUnit) -> bool,
    candidates: &[CodeUnit],
) -> HashSet<String> {
    fqn_bulk_declarations(analyzer, language, is_caller, candidates)
        .iter()
        .map(CodeUnit::fq_name)
        .collect()
}

fn fqn_bulk_declarations(
    analyzer: &dyn IAnalyzer,
    language: Language,
    is_caller: impl Fn(&CodeUnit) -> bool,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    analyzer
        .all_declarations()
        .filter(|unit| {
            language_for_target(unit) == language && !unit.is_synthetic() && is_caller(unit)
        })
        .chain(candidates.iter().cloned())
        .collect()
}

#[doc(hidden)]
pub fn build_fqn_bulk_edges(
    analyzer: &dyn IAnalyzer,
    language: Language,
    candidates: &[CodeUnit],
    build_edges: impl FnOnce(&dyn IAnalyzer, &HashSet<String>, &DeclarationKinds) -> Option<UsageEdges>,
) -> Option<DeadCodeBulkEdges> {
    let declarations = fqn_bulk_declarations(
        analyzer,
        language,
        |unit| unit.is_function() || unit.is_class(),
        candidates,
    );
    let nodes = declarations.iter().map(CodeUnit::fq_name).collect();
    let kinds = declaration_kind_index(&declarations);
    build_edges(analyzer, &nodes, &kinds).map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
}

#[doc(hidden)]
pub fn candidate_fqns(candidates: &[CodeUnit]) -> HashSet<String> {
    candidates.iter().map(CodeUnit::fq_name).collect()
}

#[doc(hidden)]
pub fn analyzable_file_count(analyzer: &dyn IAnalyzer, language: Language) -> usize {
    analyzer
        .project()
        .analyzable_files(language)
        .map_or(0, |files| files.len())
}

#[doc(hidden)]
pub fn ready_preflight(
    analyzer: &dyn IAnalyzer,
    language: Language,
    label: &'static str,
) -> DeadCodeBulkPreflight {
    DeadCodeBulkPreflight::Ready {
        label,
        files: analyzable_file_count(analyzer, language),
    }
}

/// Fq names declared more than once as a function in `language`. An overloaded name is
/// ambiguous to an fqn-keyed bulk proof, so the languages that can overload consult this
/// before admitting a candidate.
#[doc(hidden)]
pub fn overloaded_function_fqns(analyzer: &dyn IAnalyzer, language: Language) -> HashSet<String> {
    let mut counts: HashMap<String, usize> = HashMap::default();
    for declaration in analyzer.all_declarations().filter(|unit| {
        language_for_target(unit) == language && !unit.is_synthetic() && unit.is_function()
    }) {
        *counts.entry(declaration.fq_name()).or_default() += 1;
    }
    counts
        .into_iter()
        .filter_map(|(fqn, count)| (count > 1).then_some(fqn))
        .collect()
}

/// Whether one exact FQN has multiple non-synthetic function definitions in `language`.
///
/// Unlike [`overloaded_function_fqns`], this is candidate-local: the definition index is
/// queried for the requested name instead of scanning every declaration in the workspace.
/// That distinction matters when an FQN-keyed bulk graph is used to decide whether a
/// precise overload scan is required.
#[doc(hidden)]
pub fn fqn_has_multiple_function_definitions(
    analyzer: &dyn IAnalyzer,
    language: Language,
    fqn: &str,
) -> bool {
    analyzer
        .get_definitions(fqn)
        .into_iter()
        .filter(|definition| {
            language_for_target(definition) == language
                && !definition.is_synthetic()
                && definition.is_function()
        })
        .take(2)
        .count()
        > 1
}

/// Language-owned mutable state whose lifetime is one receiver-query request.
#[doc(hidden)]
pub trait ReceiverRequest {
    fn resolve_type(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome>;
    fn resolve_definition(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome>;
}

/// The pair of bounded resolvers a structural receiver query needs. One trait rather than
/// two independent capabilities: a language that can answer one and not the other would
/// leave the receiver query with half an implementation part-way through a report.
#[doc(hidden)]
pub trait StructuralReceiverResolver: Send + Sync {
    /// Whether this resolver consumes caller-owned selected-operation state
    /// shared by the bounded queries in one receiver request.
    fn reuses_request_scoped_native_points(&self) -> bool {
        false
    }

    /// Select the site for a captured member-target range. Most languages capture the
    /// receiver expression itself, while C# field/indexer matches capture the complete
    /// member-access expression and therefore need containing-site selection.
    fn member_target_input_mode(&self) -> ReceiverSiteInputMode {
        ReceiverSiteInputMode::Expression
    }

    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome>;

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome>;

    fn resolve_definition_with_call_evidence_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(
        DefinitionLookupOutcome,
        crate::analyzer::usages::get_definition::CallEvidence,
    )> {
        match self.resolve_definition_bounded(query) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: (value, Default::default()),
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn resolve_definition_with_evidence_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(DefinitionLookupOutcome, Option<ExactExternalCallProof>)> {
        match self.resolve_definition_bounded(query) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: (value, None),
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }
}

#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct BoundedReceiverQuery<'a> {
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub file: &'a ProjectFile,
    #[doc(hidden)]
    pub source: &'a str,
    #[doc(hidden)]
    pub tree: Option<&'a tree_sitter::Tree>,
    #[doc(hidden)]
    pub site: &'a ResolvedReferenceSite,
    #[doc(hidden)]
    pub budget: ReceiverAnalysisBudget,
    #[doc(hidden)]
    pub cancellation: Option<&'a CancellationToken>,
}

#[doc(hidden)]
pub fn with_bounded_receiver_query<R>(
    query: BoundedReceiverQuery<'_>,
    resolve: impl FnOnce(BoundedReceiverQuery<'_>, QueryToken<'_>) -> R,
) -> R {
    let scope = crate::analyzer::AnalyzerQueryScope::new(query.analyzer);
    resolve(query, scope.token())
}

/// Everything a per-query receiver-facts provider borrows. `'tree` is the prepared tree's
/// lifetime and `'a` the query's; both outlive the boxed provider.
///
/// This context and [`ReceiverFactsFactory`] stayed behind when the rest of the
/// receiver-facts vocabulary lowered to `brokk-bifrost-core`: `analyzer` is a full
/// `IAnalyzer` because the only implementer's provider hands it to
/// `get_definition::js_ts`'s candidate resolvers, which downcast through
/// `resolve_analyzer` (`cached_jsts_index`) and read `IAnalyzer::type_alias_provider`.
/// Narrowing it to `CodeUnitIndex` needs those resolvers relocated first.
#[doc(hidden)]
pub struct ReceiverFactContext<'a, 'tree> {
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub definitions: &'a dyn BoundedDefinitionLookup,
    #[doc(hidden)]
    pub language: Language,
    #[doc(hidden)]
    pub file: &'a ProjectFile,
    #[doc(hidden)]
    pub source: &'a str,
    #[doc(hidden)]
    pub root: tree_sitter::Node<'tree>,
    #[doc(hidden)]
    pub facts: &'a ReceiverFileFacts,
}

/// A language's own receiver analysis, resolving against a syntax index it builds rather
/// than against structural facts. JS/TS is the only implementer today.
#[doc(hidden)]
pub trait ReceiverFactsFactory: Send + Sync {
    fn prepare_file(&self, ctx: &ReceiverFileCtx<'_>) -> ReceiverFileSetup;

    /// One provider per bounded resolution query, never per node: it owns query-local
    /// caches, so its allocation is amortized over every node the query resolves.
    fn make_receiver_facts<'a, 'tree: 'a>(
        &self,
        ctx: ReceiverFactContext<'a, 'tree>,
    ) -> Box<dyn ReceiverFacts<'tree> + 'a>;
}

#[doc(hidden)]
pub struct CandidateCtx<'a> {
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    #[doc(hidden)]
    pub target: &'a CodeUnit,
    #[doc(hidden)]
    pub cancellation: &'a CancellationToken,
}

/// The file-scoped evidence [`LanguageSupport::single_segment_external_owner`]
/// may consult about one call site (#2598).
///
/// The classification stage already parsed the file to find the call, so the
/// tree and the exact source it was parsed from are handed over rather than
/// re-derived. `callee_start_byte` is the offset of the callee reference
/// itself, which is what a lexically scoped binding question has to be asked
/// at: the same name can be a parameter in one body and a free global three
/// lines later.
#[doc(hidden)]
pub struct ExternalCalleeSite<'a> {
    #[doc(hidden)]
    pub source: &'a str,
    #[doc(hidden)]
    pub tree: &'a tree_sitter::Tree,
    #[doc(hidden)]
    pub callee_start_byte: usize,
    /// File-wide evidence shared by every callee site classified in this file.
    #[doc(hidden)]
    pub file_evidence: &'a ExternalCalleeFileEvidence,
}

/// What [`LanguageSupport::expand_imported_external_callee`] proved about one
/// imported callee spelling.
///
/// The published text and the structured evidence are two spellings of one
/// callee, not two independent facts. A language that only expanded a spelling
/// publishes [`Self::text`]. A language whose resolver selected the callable
/// itself publishes [`Self::proven`], and the exact call proof and the
/// owner/member identity then travel together to the call boundary: a summary
/// is behavior attached to a callable, so text alone must not stand for the
/// declaration the summary describes (#3484).
#[doc(hidden)]
pub struct ImportedExternalCallee {
    /// The canonical callee text the boundary publishes, written with the
    /// language's own separator.
    pub(crate) canonical_callee: String,
    /// The exact declaration-side proof of the selected callable and its
    /// written call shape.
    #[doc(hidden)]
    pub exact_external_call: Option<ExactExternalCallProof>,
    /// The resolver-owned owner/member identity that exact proof names.
    #[doc(hidden)]
    pub external_callee_identity:
        Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>,
}

impl ImportedExternalCallee {
    #[doc(hidden)]
    /// An expansion whose language proved the callee text but no exact
    /// declaration-side call shape.
    pub fn text(canonical_callee: impl Into<String>) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            exact_external_call: None,
            external_callee_identity: None,
        }
    }

    /// An expansion whose language selected the callable itself. The proof and
    /// the identity are two spellings of what it selected, so they are stored
    /// and published together.
    #[doc(hidden)]
    pub fn proven(
        proof: ExactExternalCallProof,
        identity: crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity,
    ) -> Self {
        Self {
            canonical_callee: proof.canonical_callee().to_owned(),
            exact_external_call: Some(proof),
            external_callee_identity: Some(identity),
        }
    }
}

/// The file-wide proofs [`LanguageSupport::single_segment_external_owner`]
/// reuses across one file's callee sites.
///
/// An owner rule can need evidence that walks the whole file: JavaScript must
/// prove the file writes nothing to the member it is about to publish (#3427).
/// Classification runs once per unresolved callee, so a file with many external
/// member calls would otherwise rewalk itself once per call. One value is built
/// per file and handed to each of its sites.
#[derive(Default)]
#[doc(hidden)]
pub struct ExternalCalleeFileEvidence {
    #[doc(hidden)]
    pub js_ts_module_member_writes: brokk_bifrost_js_ts::syntax::JsTsModuleMemberWriteMemo,
}

/// Extra candidate files for one query target, split by how the query's budgets treat them.
///
/// The split is behavior, not bookkeeping. `protected` joins the candidate set before the
/// finder takes its protected snapshot, so both the file-count and the source-byte budget
/// admit those files ahead of everything else. `supplemental` joins after the snapshot and
/// is therefore what either budget drops first -- which is what PHP's composer expansion
/// needs, since a single autoload-visible target pulls in every analyzed PHP file and would
/// otherwise displace the import-graph candidates that are far likelier to hold a usage.
#[derive(Default)]
#[doc(hidden)]
pub struct CandidateAugmentation {
    #[doc(hidden)]
    pub protected: HashSet<ProjectFile>,
    #[doc(hidden)]
    pub supplemental: HashSet<ProjectFile>,
}

impl CandidateAugmentation {
    #[doc(hidden)]
    pub fn protected(files: HashSet<ProjectFile>) -> Self {
        Self {
            protected: files,
            supplemental: HashSet::default(),
        }
    }

    #[doc(hidden)]
    pub fn supplemental(files: HashSet<ProjectFile>) -> Self {
        Self {
            protected: HashSet::default(),
            supplemental: files,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.protected.is_empty() && self.supplemental.is_empty()
    }
}

/// What `target`'s language adds to the default candidate route, or `None` when it adds
/// nothing.
///
/// A cancelled token skips the augmentation and leaves the query holding what it has
/// already accumulated: whether to abandon the query is the caller's decision, taken at the
/// cancellation check it runs next, and the two callers differ on it.
pub(crate) fn candidate_augmentation(ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
    if ctx.cancellation.is_cancelled() {
        return None;
    }
    let augmentation =
        language_support_for_hook(language_for_target(ctx.target), "candidate_augmentation")?
            .candidate_augmentation(ctx)?;
    (!augmentation.is_empty()).then_some(augmentation)
}

/// The languages whose adapters adopt workspace files that no extension list
/// claims, by resolving their own sources' imports (#1837).
///
/// CLAIMS SEAM. This registry is the single-claimant premise every other part
/// of include-driven inference rests on: `storage_language_key_for_file` hands
/// the unclaimed-extension storage-key namespace to the asking adapter, and
/// `MultiAnalyzer::dispatch_language` routes an unclaimed-extension file to the
/// one language named here. Both are sound only while this list holds at most
/// one entry. Adding a second language means implementing the drop-and-report
/// rule stated on [`crate::analyzer::LanguageAdapter::infer_claimed_files`]:
/// a file two languages claim belongs to neither, and a diagnostic must name
/// both claimants.
#[doc(hidden)]
pub fn claim_inferring_languages() -> &'static [Language] {
    const LANGUAGES: &[Language] = &[Language::Cpp];
    debug_assert!(
        LANGUAGES.len() <= 1,
        "include-driven claim inference has no multi-claimant resolution yet, but the registry \
         lists {LANGUAGES:?}"
    );
    LANGUAGES
}

/// The language implementations linked into this binary.
#[doc(hidden)]
pub struct LanguageTable {
    supports: Box<[&'static dyn LanguageSupport]>,
}

impl LanguageTable {
    /// Construct the complete table for a production binary.
    pub fn complete(supports: Vec<&'static dyn LanguageSupport>) -> Self {
        let table = Self::partial_for_tests(supports);
        let installed: Vec<_> = table
            .supports
            .iter()
            .map(|support| support.knowledge().language())
            .collect();
        let missing: Vec<_> = Language::ANALYZABLE
            .iter()
            .copied()
            .filter(|language| !installed.contains(language))
            .collect();
        assert!(
            missing.is_empty(),
            "invalid language support table: missing {missing:?}, installed {installed:?}"
        );
        table
    }

    /// Construct a test table containing only the implementations available here.
    pub fn partial_for_tests(supports: Vec<&'static dyn LanguageSupport>) -> Self {
        let mut installed = Vec::new();
        let mut duplicates = Vec::new();
        for support in &supports {
            let language = support.knowledge().language();
            assert!(
                language_index(language).is_some(),
                "invalid language support table: unsupported {language:?}"
            );
            if installed.contains(&language) {
                duplicates.push(language);
            }
            installed.push(language);
        }
        assert!(
            duplicates.is_empty(),
            "invalid language support table: duplicates {duplicates:?}, installed {installed:?}"
        );
        Self {
            supports: supports.into_boxed_slice(),
        }
    }

    /// Upcast the same validated implementations for the lower store boundary.
    #[doc(hidden)]
    pub fn store_supports(&self) -> crate::analyzer::store::StoreLanguageTable {
        let mut table: crate::analyzer::store::StoreLanguageTable =
            [None; Language::ANALYZABLE.len()];
        for &support in &self.supports {
            let language = support.knowledge().language();
            let index = language_index(language).expect("validated language support");
            table[index] = Some(support as &dyn crate::analyzer::store::StoreLanguageSupport);
        }
        table
    }
}

// Production binaries link only the tools definition, complete by construction;
// cfg(test) stubs cannot reach a production binary.
unsafe extern "Rust" {
    safe fn __brokk_bifrost_language_supports_v1() -> &'static LanguageTable;
}

static LANGUAGE_SUPPORT: std::sync::OnceLock<
    [Option<&'static dyn LanguageSupport>; Language::ANALYZABLE.len()],
> = std::sync::OnceLock::new();

use crate::analyzer::store::language_support::language_index;

#[doc(hidden)]
pub fn language_support(language: Language) -> Option<&'static dyn LanguageSupport> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(support) = neutral_fixture::support(language) {
        return Some(support);
    }
    let index = language_index(language)?;
    let table = LANGUAGE_SUPPORT.get_or_init(|| {
        let mut table = [None; Language::ANALYZABLE.len()];
        for &support in &__brokk_bifrost_language_supports_v1().supports {
            let language = support.knowledge().language();
            let index = language_index(language).expect("validated language support");
            table[index] = Some(support);
        }
        table
    });
    table[index]
}

/// Resolve hook support, distinguishing an absent language from default hooks.
#[doc(hidden)]
pub fn language_support_for_hook(
    language: crate::analyzer::Language,
    hook: &str,
) -> Option<&'static dyn LanguageSupport> {
    if language == crate::analyzer::Language::None {
        return None;
    }
    Some(
        language_support(language)
            .unwrap_or_else(|| panic!("unregistered language {language:?} for hook {hook}")),
    )
}

#[doc(hidden)]
pub use crate::analyzer::semantic::languages::language_knowledge;

const ANALYZABLE_LANGUAGES: &[Language] = &[
    Language::Java,
    Language::Go,
    Language::Cpp,
    Language::JavaScript,
    Language::TypeScript,
    Language::Python,
    Language::Rust,
    Language::Php,
    Language::Scala,
    Language::CSharp,
    Language::Ruby,
    Language::Kotlin,
];

pub(crate) fn selected_external_inventory_providers(analyzer: &dyn IAnalyzer) -> Vec<String> {
    let mut providers = ANALYZABLE_LANGUAGES
        .iter()
        .filter_map(|&language| language_support(language))
        .flat_map(|support| support.external_inventory_providers(analyzer))
        .collect::<Vec<_>>();
    providers.sort_unstable();
    providers.dedup();
    providers
}

/// Every build ecosystem that can derive project topology (#2448), in a stable
/// order.
///
/// Assembly, like `language_support` above: a provider knows one build model
/// and nothing outside its own module dispatches over build ecosystems. The
/// registry is keyed by ecosystem rather than by [`Language`] because one
/// build model serves several languages -- Java, Kotlin, and Scala share the
/// Maven reactor -- and because a workspace can carry build metadata for a
/// language it has no sources in yet.
pub(crate) fn build_model_providers()
-> impl Iterator<Item = &'static dyn crate::analyzer::topology::BuildModelProvider> {
    // Java support registers the shared JVM model once for all JVM languages.
    ANALYZABLE_LANGUAGES
        .iter()
        .filter_map(|&language| language_support(language))
        .filter_map(|support| support.build_model_provider())
}

pub use crate::analyzer::resolution::registry_vocabulary::{
    ModeledExternalPackageIdentity, TypeComponentProjection, TypeComponentSelection,
};

/// Implementations actually linked into this binary, including partial test tables.
#[doc(hidden)]
pub fn registered_language_supports() -> impl Iterator<Item = &'static dyn LanguageSupport> {
    __brokk_bifrost_language_supports_v1()
        .supports
        .iter()
        .copied()
}

/// Neutral hook support scoped to a shared-algorithm test's fixture.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod neutral_fixture {
    use super::*;
    use std::cell::RefCell;
    thread_local! {
        static OVERLAYS: RefCell<Vec<Vec<Language>>> = const { RefCell::new(Vec::new()) };
    }
    struct NeutralFakeLanguageSupport;
    impl crate::analyzer::store::StoreLanguageSupport for NeutralFakeLanguageSupport {}
    impl LanguageSupport for NeutralFakeLanguageSupport {
        fn build_analyzer(
            &self,
            _project: Arc<dyn crate::analyzer::Project>,
            _config: crate::analyzer::AnalyzerConfig,
            _store_context: crate::analyzer::AnalyzerStoreContext,
            _progress: Option<crate::analyzer::BuildProgress>,
        ) -> Result<
            crate::analyzer::multi_analyzer::AnalyzerDelegate,
            crate::analyzer::store::StoreError,
        > {
            unimplemented!("neutral rules fixtures do not build analyzers")
        }
        fn forward_query_provider<'a>(
            &self,
            _analyzer: &'a dyn IAnalyzer,
        ) -> Option<&'a dyn ForwardQueryProvider> {
            None
        }
        fn declaration_ranges_limited(
            &self,
            _analyzer: &dyn IAnalyzer,
            _unit: &CodeUnit,
            _limit: usize,
        ) -> Option<LimitedQueryRows<Range>> {
            None
        }
        fn knowledge(&self) -> &'static dyn LanguageKnowledge {
            unimplemented!("neutral rules fixtures do not supply language knowledge")
        }
        fn ecosystem(&self) -> UsageEcosystem {
            UsageEcosystem::Unknown
        }
        fn reference_usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
            unimplemented!("neutral rules fixtures do not supply usage strategies")
        }
        fn reference_graph_backend(&self) -> LanguageGraphBackend {
            unimplemented!("neutral rules fixtures do not supply graph backends")
        }
    }
    pub struct NeutralRulesFixture {
        depth: usize,
        _store: crate::analyzer::store::language_support::neutral_fixture::NeutralRulesFixture,
    }
    pub fn neutral_rules_fixture(languages: &[Language]) -> NeutralRulesFixture {
        let store =
            crate::analyzer::store::language_support::neutral_fixture::neutral_rules_fixture(
                languages,
            );
        let depth = OVERLAYS.with(|overlays| {
            let mut overlays = overlays.borrow_mut();
            overlays.push(languages.to_vec());
            overlays.len()
        });
        NeutralRulesFixture {
            depth,
            _store: store,
        }
    }
    impl Drop for NeutralRulesFixture {
        fn drop(&mut self) {
            OVERLAYS.with(|overlays| {
                let mut overlays = overlays.borrow_mut();
                assert_eq!(
                    overlays.len(),
                    self.depth,
                    "neutral fixture guards must drop in nesting order"
                );
                overlays.pop().expect("live neutral fixture overlay");
            });
        }
    }
    pub(super) fn support(language: Language) -> Option<&'static dyn LanguageSupport> {
        OVERLAYS
            .with(|overlays| {
                overlays
                    .borrow()
                    .iter()
                    .rev()
                    .any(|languages| languages.contains(&language))
            })
            .then_some(&NeutralFakeLanguageSupport as &dyn LanguageSupport)
    }
}
