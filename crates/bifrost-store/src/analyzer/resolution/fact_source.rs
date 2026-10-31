//! Storage-neutral reads over selected immutable resolution facts.
//!
//! The source contracts deliberately expose bounded, selected-context reads
//! instead of fragment hydrators: a persistent implementation must join every
//! query through one sealed selection, while preload implementations present
//! the same normalized rows from immutable in-memory artifacts.

use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use brokk_bifrost_core::analyzer::resolution_facts::{
    DeclarationTypeRole, IntrinsicTypeKind, ResolutionConstructionRequirementKind,
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberQualifierCompatibility,
    ResolutionNamespace, ResolutionSiteId, ResolutionSupertypeKind, ResolutionTypeComponentKind,
};
use brokk_bifrost_core::analyzer::rust_facts::RustVisibility;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::hash::HashSet;

use super::batch::{BatchResolutionFragmentSource, CancellationEvidenceLedger};
use super::common_fact_lowering::LoweredDeferredMemberOwner;
use super::fact_lowering::{LoweredResolutionFragment, LoweringGapOrigin};
use super::model::{
    BindingFragmentId, BindingNodeId, ResolutionCompletion, ResolutionIncompleteReason, SemanticId,
};
use super::seam_profile::{self, SeamMethod};
use super::typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDeclaredTypeArgument,
    LoweredDefinitionPropertyGap, LoweredGenericFormal, LoweredGenericFormalDefault,
    LoweredGenericTypeAliasParameter, LoweredIntrinsicSeed, LoweredMemberOwnerProperty,
    LoweredMemberScopeProperty, LoweredQualifiedSeededRoute, LoweredSupertypeProperty,
    LoweredTypeArgument, LoweredTypeComponent, LoweredTypeProduction, LoweredTypeTransfer,
    LoweredTypedFrontier, LoweredUnderlyingType,
};

/// Hard upper bound on identities in one typed-fact source request.
///
/// This keeps a plural read below SQLite's ordinary bound-variable limit even
/// when an implementation expands each identity into a small request tuple.
pub const MAX_TYPED_FACT_REQUESTS_PER_BATCH: usize = 256;

/// Hard upper bound on fully hydrated parent rows in one visitor page.
pub const MAX_TYPED_FACT_ROWS_PER_PAGE: usize = 256;

/// Shared request bound for every selected fact source family.
///
/// The older typed name remains public for compatibility; Java placement uses
/// the same boundary rather than defining a second paging protocol.
pub const MAX_FACT_REQUESTS_PER_BATCH: usize = MAX_TYPED_FACT_REQUESTS_PER_BATCH;

/// Shared row-page bound for every selected fact source family.
pub const MAX_FACT_ROWS_PER_PAGE: usize = MAX_TYPED_FACT_ROWS_PER_PAGE;

/// Exact already-selected endpoints whose declaration access needs context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub struct DeclarationAccessRequest {
    pub reference: SemanticId,
    pub definition: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationAccessDecision {
    Allowed,
    Denied,
    Unknown,
    UnknownActivation,
    InactiveActivation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct DeclarationAccessRow {
    pub request: DeclarationAccessRequest,
    pub decision: DeclarationAccessDecision,
    pub activation_reason: Option<SemanticId>,
    /// The policy supplies visibility for this declaration even when its
    /// producer has no visibility gap to refine.
    pub visibility_applies: bool,
    /// Some JVM access rules require an enclosing type to inherit the
    /// declaration's owner.
    pub subclass_access: Option<SubclassAccessContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SubclassAccessContext {
    pub enclosing_templates: Vec<SemanticId>,
    pub declaration_template: SemanticId,
}

/// A selected lowering-gap reason and the Rust declaration whose declaration
/// site produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct ReasonOwnerRow {
    pub reason: SemanticId,
    pub definition: SemanticId,
}

/// Selected lexical ownership used by Java declaration access. Values live for
/// one query and come from exact mounted source rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAccessEndpoint {
    pub semantic: SemanticId,
    pub package: Option<String>,
    pub outermost_type: Option<SemanticId>,
}

/// Selected lexical templates and package for visibility decisions over JVM
/// declarations. The ordered owners are the exact enclosing type scopes from
/// the declaration/reference up to its outermost type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmAccessEndpoint {
    pub semantic: SemanticId,
    pub language: Language,
    pub package: Option<String>,
    pub enclosing_templates: Vec<SemanticId>,
    pub outermost_type: Option<SemanticId>,
}

/// Candidate admission evidence, never a binding or applicability answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredMemberOwnerProof {
    Matches,
    DoesNotMatch,
    Unknown,
}

/// Exact selected Go member metadata, retained only for the current query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoMemberDeclaration {
    pub definition: SemanticId,
    pub kind: GoMemberDeclarationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoMemberDeclarationKind {
    Defined,
    Interface { methods: Vec<GoInterfaceMethod> },
    Struct { fields: Vec<GoStructField> },
    Method { pointer_receiver: Option<bool> },
}

/// One declared Go interface method, projected from selected source facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoInterfaceMethod {
    pub callable_lookup: SemanticId,
    pub definition: Option<SemanticId>,
}

/// Reached composed declarations and type slots; retained only by this request.
#[derive(Debug, Clone)]
pub struct GoModelOwnerDeclarations {
    pub owner: crate::analyzer::semantic_model::overlay::ModelSymbolRef,
    pub declaration: GoMemberDeclaration,
    pub members_state: crate::analyzer::semantic_model::overlay::ModelMembersState,
    pub embedded: Vec<super::ResolutionTypeRef>,
    pub methods: Vec<GoModelMemberDeclaration>,
    pub completion: ResolutionCompletion,
}

#[derive(Debug, Clone)]
pub struct GoModelMemberDeclaration {
    pub member: crate::analyzer::semantic_model::overlay::ModelSymbolRef,
    pub owner: SemanticId,
    pub definition: SemanticId,
    pub callable_lookup: SemanticId,
    pub declaration: crate::analyzer::semantic_model::overlay::SemanticModelSymbol,
}

/// A reached callable and its native signature, retained only for this query.
#[derive(Debug, Clone)]
pub struct ModelCallableResultDeclaration {
    pub member: crate::analyzer::semantic_model::overlay::ModelSymbolRef,
    pub selection: crate::analyzer::semantic_model::overlay::ModelProviderSelection,
    pub declaration: crate::analyzer::semantic_model::overlay::SemanticModelSymbol,
    pub signature: Option<super::LoweredCallableSignatureProperty>,
}

/// One reached modeled receiver candidate. This is query-only provenance,
/// never a source declaration, inventory ordinal, snapshot, or persisted row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactModelMember {
    pub target: SemanticId,
    pub member: crate::analyzer::semantic_model::overlay::ModelSymbolRef,
    pub declaration: crate::analyzer::semantic_model::overlay::SemanticModelSymbol,
    pub owner: super::ExternalOwnerIdentity,
    pub owners: Box<[SemanticId]>,
    pub owner_coordinates: Box<[Option<super::ExternalOwnerIdentity>]>,
    pub receiver_owner: Option<super::ExternalOwnerIdentity>,
    pub receiver_proven: bool,
    pub selected: bool,
    pub selection_complete: bool,
    pub incomplete_reasons: Vec<String>,
    pub receiver: super::ResolutionSlotValue,
    pub interface: bool,
    pub route_exact: bool,
    pub receiver_route_proven: bool,
    pub completion: ResolutionCompletion,
    pub rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactModelMemberSelection {
    pub native_target_count: usize,
    pub candidates: Vec<FactModelMember>,
    pub completion: ResolutionCompletion,
}

/// All source fields participate in selector shadowing, including ordinary
/// fields. Missing native bridges or value slots keep promotion incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoStructField {
    /// Callable-namespace identity for shadowing a same-spelled method.
    pub callable_lookup: SemanticId,
    pub embedded: bool,
    pub field: Option<SemanticId>,
    pub value_type: Option<SemanticId>,
}

/// The selected descriptor shared by every intrinsic seed that names one
/// semantic type identity. This projection avoids returning each seed's
/// unrelated source value when the caller only needs the type descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredIntrinsicTypeDescriptor {
    identity: SemanticId,
    kind: IntrinsicTypeKind,
    spelling: Box<str>,
}

impl LoweredIntrinsicTypeDescriptor {
    pub fn new(
        identity: SemanticId,
        kind: IntrinsicTypeKind,
        spelling: impl Into<Box<str>>,
    ) -> Self {
        let spelling = spelling.into();
        Self {
            identity,
            kind,
            spelling,
        }
    }

    pub const fn identity(&self) -> SemanticId {
        self.identity
    }

    pub const fn kind(&self) -> IntrinsicTypeKind {
        self.kind
    }

    pub fn spelling(&self) -> &str {
        &self.spelling
    }
}

/// Package knowledge is independent of the existence of a declaration.
/// Known(None) denotes the unnamed package; Unknown carries no package proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmDeclarationPackage {
    Known(Option<String>),
    Unknown,
}

impl JvmDeclarationPackage {
    pub fn named(&self) -> Option<&str> {
        match self {
            Self::Known(package) => package.as_deref(),
            Self::Unknown => None,
        }
    }

    pub fn same_known_package(&self, other: &Self) -> Option<bool> {
        match (self, other) {
            (Self::Known(left), Self::Known(right)) => Some(left == right),
            _ => None,
        }
    }
}

/// Selected Java declaration properties needed before inheriting a method.
/// Missing properties remain unknown; they are never inferred from a signature label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaInheritanceDeclaration {
    pub definition: SemanticId,
    pub name: String,
    pub package: JvmDeclarationPackage,
    pub kind: JavaInheritanceDeclarationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaInheritanceDeclarationKind {
    Type {
        is_interface: bool,
        /// A Scala `object`: the declaration's last identity segment is a
        /// companion segment.
        is_singleton: bool,
    },
    Method {
        is_abstract: Option<bool>,
        is_static: bool,
        visibility: brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility,
    },
}

/// What the crate rows say about the traits one Rust type implements where one
/// reference is written. See
/// [`SelectedTypedFactSource::rust_implemented_traits_nameable_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustImplementedTraits {
    /// The trait definitions, sorted and without duplicates. Empty is a
    /// decided answer: the crate rows bind no nameable trait to the owner.
    Traits(Vec<SemanticId>),
    /// The owner or the reference has no persisted crate placement: it is
    /// staged content, or its file is placed in no crate. The crate rows cannot
    /// answer, so an empty answer here would be a guess.
    Unplaced,
    Cancelled,
}

/// Exact positioned label fact read from the selected source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamedArgumentLabelRead {
    Found(NamedArgumentLabel),
    Missing,
    Cancelled,
}

/// A named argument label and the call obligation that owns its reference site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedArgumentLabel {
    pub call: SemanticId,
    pub callee_reference: Option<SemanticId>,
    pub spelling: String,
}

/// Immutable selected-context access policy, not a name resolver. Implementors
/// authorize only supplied endpoint pairs using canonical selected source facts.
#[doc(hidden)]
pub trait SelectedDeclarationAccessSource: Send + Sync {
    /// Languages without activation premises leave precedence unchanged.
    fn qualify_selection_path(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _reference: SemanticId,
        _path: &mut super::PartialPath,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<bool>> {
        Ok((!cancellation.is_cancelled()).then_some(true))
    }

    fn identity(&self) -> SemanticId;

    /// Activation of an inverse target before any reference exists. Only
    /// Allowed, InactiveActivation, or UnknownActivation are returned; None
    /// means cancellation. The optional semantic is its retained obligation.
    fn declaration_activation(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _definition: SemanticId,
        cancellation: &CancellationToken,
        _session: Option<&ResolutionSession>,
    ) -> StoreResult<Option<(DeclarationAccessDecision, Option<SemanticId>)>> {
        Ok((!cancellation.is_cancelled()).then_some((DeclarationAccessDecision::Allowed, None)))
    }

    fn visit_access_pages(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: TypedFactRequest<DeclarationAccessRequest>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<DeclarationAccessRow>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Visit the declaration authority at the source site of each selected
    /// reason. Languages without declaration activation leave ownership empty.
    fn visit_reason_owners(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _reasons: TypedFactRequest<SemanticId>,
        cancellation: &CancellationToken,
        _visitor: &mut FactPageVisitor<ReasonOwnerRow>,
    ) -> StoreResult<TypedFactReadOutcome> {
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }
}

/// A unique, bounded set of lookup identities for one source read.
///
/// The private field makes the request limit and uniqueness law part of the
/// call boundary rather than an implementation convention. Empty requests are
/// valid and have the same terminal semantics as every other request.
#[derive(Debug, Clone, Copy)]
pub struct TypedFactRequest<'a, T> {
    identities: &'a [T],
}

/// Storage-neutral request shared by typed and Java placement sources.
pub type FactRequest<'a, T> = TypedFactRequest<'a, T>;

impl<'a, T> TypedFactRequest<'a, T>
where
    T: Eq + Hash,
{
    pub fn new(identities: &'a [T]) -> Self {
        assert!(
            identities.len() <= MAX_TYPED_FACT_REQUESTS_PER_BATCH,
            "typed-fact request has {} identities; maximum is {MAX_TYPED_FACT_REQUESTS_PER_BATCH}",
            identities.len()
        );
        let mut unique = HashSet::default();
        for identity in identities {
            assert!(
                unique.insert(identity),
                "typed-fact request identities must be unique"
            );
        }
        Self { identities }
    }

    pub const fn as_slice(&self) -> &'a [T] {
        self.identities
    }

    pub const fn len(&self) -> usize {
        self.identities.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

/// The only callback boundary through which a typed source emits row pages.
///
/// A source calls [`Self::visit_page`] with fully hydrated parent rows. The
/// wrapper enforces nonempty bounded pages and remembers a live visitor stop,
/// so an implementation cannot accidentally resume emission after `false`.
pub struct TypedFactPageVisitor<'a, T> {
    callback: &'a mut dyn FnMut(&[T]) -> StoreResult<bool>,
    resolution_session: Option<&'a ResolutionSession>,
    maximum_rows: usize,
    stopped: bool,
    /// Set by the seam profile's decorator for the length of one read, so the
    /// rows a paged method hands back are counted where they are produced.
    ///
    /// A second, wrapping visitor cannot do this job: a visitor carries the
    /// resolution session's scope-step charge, so wrapping one would charge the
    /// budget twice and change what a request answers.
    counted: Option<SeamMethod>,
}

/// Storage-neutral page visitor shared by typed and Java placement sources.
pub type FactPageVisitor<'a, T> = TypedFactPageVisitor<'a, T>;

fn empty_rust_traits_or_cancelled(cancellation: &CancellationToken) -> RustImplementedTraits {
    if cancellation.is_cancelled() {
        RustImplementedTraits::Cancelled
    } else {
        RustImplementedTraits::Traits(Vec::new())
    }
}

impl<'a, T> TypedFactPageVisitor<'a, T> {
    pub fn new(callback: &'a mut dyn FnMut(&[T]) -> StoreResult<bool>) -> Self {
        Self {
            callback,
            resolution_session: None,
            maximum_rows: MAX_TYPED_FACT_ROWS_PER_PAGE,
            stopped: false,
            counted: None,
        }
    }

    #[doc(hidden)]
    pub fn with_maximum_rows(
        callback: &'a mut dyn FnMut(&[T]) -> StoreResult<bool>,
        maximum_rows: usize,
    ) -> Self {
        assert!((1..=MAX_TYPED_FACT_ROWS_PER_PAGE).contains(&maximum_rows));
        Self {
            callback,
            resolution_session: None,
            maximum_rows,
            stopped: false,
            counted: None,
        }
    }

    pub(crate) fn with_maximum_rows_in_session(
        callback: &'a mut dyn FnMut(&[T]) -> StoreResult<bool>,
        maximum_rows: usize,
        resolution_session: &'a ResolutionSession,
    ) -> Self {
        let mut visitor = Self::with_maximum_rows(callback, maximum_rows);
        visitor.resolution_session = Some(resolution_session);
        visitor
    }

    /// Attribute the rows this visitor sees to one seam method, or to none.
    pub(crate) fn count_rows_as(&mut self, method: Option<SeamMethod>) {
        self.counted = method;
    }

    pub fn visit_page(&mut self, rows: &[T]) -> StoreResult<bool> {
        assert!(!self.stopped, "typed-fact visitation already stopped");
        assert!(!rows.is_empty(), "typed-fact pages must not be empty");
        assert!(
            rows.len() <= self.maximum_rows,
            "typed-fact page has {} rows; operation maximum is {}",
            rows.len(),
            self.maximum_rows
        );
        if !self.charge_source_rows(rows.len()) {
            self.stopped = true;
            return Ok(false);
        }
        // After the charge: a page the budget refused was never handed over,
        // so it is not a row the reader seam produced.
        if let Some(method) = self.counted {
            seam_profile::record_rows(method, rows.len());
        }
        let keep_going = (self.callback)(rows)?;
        self.stopped = !keep_going;
        Ok(keep_going)
    }

    pub const fn stopped(&self) -> bool {
        self.stopped
    }

    pub(crate) const fn maximum_rows(&self) -> usize {
        self.maximum_rows
    }

    pub(crate) const fn resolution_session(&self) -> Option<&'a ResolutionSession> {
        self.resolution_session
    }

    pub(crate) fn charge_source_rows(&self, count: usize) -> bool {
        self.resolution_session
            .is_none_or(|session| session.scope_steps(count))
    }

    pub(crate) fn source_lookahead_limit(&self) -> usize {
        self.resolution_session
            .map_or(usize::MAX, |session| session.scope_lookahead_limit())
    }
}

/// Why a typed-fact source stopped producing pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedFactReadTerminal {
    /// The complete selected relation for this read was consumed.
    Exhausted,
    /// A live visitor returned `false`; unread rows may still exist.
    ///
    /// This terminal is valid only while the source and cancellation token
    /// remain live. If the callback both returns `false` and causes
    /// cancellation, [`Self::Cancelled`] takes precedence.
    Stopped,
    /// The source observed cancellation; unread rows may still exist.
    Cancelled,
}

/// Storage-neutral terminal shared by typed and Java placement sources.
pub type FactReadTerminal = TypedFactReadTerminal;

/// Exact terminal state and semantic evidence returned by one typed read.
///
/// Only [`TypedFactReadTerminal::Exhausted`] can prove that an absent row does
/// not exist in the selected relation. `Stopped` remains distinct from
/// cancellation, and the `Cancelled` terminal is explicit operational
/// cancellation evidence even when the caller's token is still live by the
/// time it inspects the result. The accompanying semantic evidence is moved
/// unchanged; downstream publication adds its ordinary `Cancelled` completion
/// reason through its cancellation-polled completion path. Cancellation wins
/// over a simultaneous visitor stop: `Stopped` always means that the callback
/// returned `false` while the source and token were still live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedFactReadOutcome {
    terminal: TypedFactReadTerminal,
    evidence: ResolutionCompletion,
}

/// Storage-neutral read outcome shared by typed and Java placement sources.
pub type FactReadOutcome = TypedFactReadOutcome;

impl TypedFactReadOutcome {
    pub fn exhausted(evidence: ResolutionCompletion) -> Self {
        Self {
            terminal: TypedFactReadTerminal::Exhausted,
            evidence,
        }
    }

    pub fn stopped(evidence: ResolutionCompletion) -> Self {
        Self {
            terminal: TypedFactReadTerminal::Stopped,
            evidence,
        }
    }

    pub fn cancelled(evidence: ResolutionCompletion) -> Self {
        Self {
            terminal: TypedFactReadTerminal::Cancelled,
            evidence,
        }
    }

    pub const fn terminal(&self) -> TypedFactReadTerminal {
        self.terminal
    }

    pub const fn evidence(&self) -> &ResolutionCompletion {
        &self.evidence
    }

    pub fn into_parts(self) -> (TypedFactReadTerminal, ResolutionCompletion) {
        (self.terminal, self.evidence)
    }

    pub const fn is_exhausted(&self) -> bool {
        matches!(self.terminal, TypedFactReadTerminal::Exhausted)
    }

    pub const fn is_cancelled(&self) -> bool {
        matches!(self.terminal, TypedFactReadTerminal::Cancelled)
    }
}

pub(crate) fn visit_mapped_typed_pages<T, U: Copy>(
    rows: &[T],
    page_rows: usize,
    cancellation: &CancellationToken,
    mut project: impl FnMut(&T) -> U,
    visitor: &mut TypedFactPageVisitor<'_, U>,
) -> StoreResult<TypedFactReadOutcome> {
    assert!((1..=visitor.maximum_rows()).contains(&page_rows));
    if cancellation.is_cancelled() {
        return Ok(TypedFactReadOutcome::cancelled(
            ResolutionCompletion::Complete,
        ));
    }
    for chunk in rows.chunks(page_rows) {
        let mut page = Vec::with_capacity(chunk.len());
        for row in chunk {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            page.push(project(row));
        }
        let keep_going = visitor.visit_page(&page)?;
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        if !keep_going {
            return Ok(TypedFactReadOutcome::stopped(
                ResolutionCompletion::Complete,
            ));
        }
    }
    Ok(if cancellation.is_cancelled() {
        TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
    } else {
        TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
    })
}

/// Inventory coordinates of one externally enumerated type. These are
/// provider content and declaration names, not workspace source locators.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalOwnerIdentity {
    pub provider_id: std::sync::Arc<str>,
    pub owner_fqn: std::sync::Arc<str>,
}

impl ExternalOwnerIdentity {
    /// Provider id of an implicit-package name that no selected provider
    /// declares. Such an owner names a type, but supplies no declaration,
    /// hierarchy or member inventory, so it does not prove the type exists.
    pub const UNINDEXED_IMPORT_PROVIDER: &'static str = "jvm-unindexed-import";

    /// Whether a selected provider declares this owner.
    pub fn is_provider_declared(&self) -> bool {
        &*self.provider_id != Self::UNINDEXED_IMPORT_PROVIDER
    }
}

/// Query-local member coordinates; model members have no JVM inventory ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExternalMemberCoordinate {
    InventoryOrdinal(u32),
    ModelMember(crate::analyzer::semantic_model::ModelSymbolRef),
}

/// One member row in its provider's durable owner inventory. A callable
/// family locator is dispatch evidence, not this per-overload identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalMemberIdentity {
    pub owner: ExternalOwnerIdentity,
    pub ordinal: u32,
}

/// The identity carried by a selected typed row. Its payload supplies the
/// selected declaration semantic for a source row. External rows never carry
/// a fabricated source fragment, locator, or producer declaration ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SelectedTypedRowIdentity {
    SelectedSource {
        fragment: BindingFragmentId,
    },
    External {
        owner: ExternalOwnerIdentity,
    },
    ExternalMember {
        owner: ExternalOwnerIdentity,
        ordinal: u32,
    },
}

/// Compact query-local interner key. External declaration semantics are
/// interned from their provider/owner/member coordinates, so they remain
/// distinct without copying strings into the row-family membership indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectedTypedRowKey {
    SelectedSource(BindingFragmentId),
    External,
}

/// One typed parent row and its honest selected-source or external identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedTypedRow<T> {
    identity: SelectedTypedRowIdentity,
    row: T,
}

/// The exact source authority needed to evaluate Rust declaration visibility
/// for one selected reference.
///
/// The resolution owner field is deliberately absent here. Rust's native
/// producer records the nearest callable in that field, so `Some(None)` is
/// also emitted for module-level const initializers and type references. The
/// source occurrence and canonical Rust module context are the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredRustReferenceContext {
    reference: SemanticId,
    source_site: ResolutionSiteId,
    source_occurrence: SourceOccurrenceId,
    module_context: SourceOccurrenceId,
    module_declaration: Option<SourceDeclarationId>,
    cfg_condition: RustCfgCondition,
}

/// Exact source-owned authority for one selected Rust definition semantic.
/// Item definitions carry a visibility; local and pattern definitions retain
/// their source identity but intentionally have no item-property row and are
/// therefore an Unknown access decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredRustDeclarationAuthority {
    definition: SemanticId,
    source_site: ResolutionSiteId,
    declaration: SourceDeclarationId,
    visibility: Option<RustVisibility>,
    module_context: SourceOccurrenceId,
    module_declaration: Option<SourceDeclarationId>,
    cfg_condition: RustCfgCondition,
    activation_reason: Option<SemanticId>,
}

impl LoweredRustDeclarationAuthority {
    pub const fn new(
        definition: SemanticId,
        source_site: ResolutionSiteId,
        declaration: SourceDeclarationId,
        visibility: Option<RustVisibility>,
        module_context: SourceOccurrenceId,
        module_declaration: Option<SourceDeclarationId>,
    ) -> Self {
        Self {
            definition,
            source_site,
            declaration,
            visibility,
            module_context,
            module_declaration,
            cfg_condition: RustCfgCondition::Always,
            activation_reason: None,
        }
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn source_site(&self) -> ResolutionSiteId {
        self.source_site
    }

    pub const fn declaration(&self) -> SourceDeclarationId {
        self.declaration
    }

    pub const fn visibility(&self) -> Option<&RustVisibility> {
        self.visibility.as_ref()
    }

    pub const fn module_context(&self) -> SourceOccurrenceId {
        self.module_context
    }

    pub const fn module_declaration(&self) -> Option<SourceDeclarationId> {
        self.module_declaration
    }
    pub fn with_cfg_condition(mut self, condition: RustCfgCondition) -> Self {
        self.cfg_condition = condition;
        self
    }

    pub fn cfg_condition(&self) -> &RustCfgCondition {
        &self.cfg_condition
    }

    pub fn with_activation_reason(mut self, reason: Option<SemanticId>) -> Self {
        self.activation_reason = reason;
        self
    }
    pub fn activation_reason(&self) -> Option<SemanticId> {
        self.activation_reason
    }
}

/// Compact transient input produced from the canonical parsed source facts
/// before resolution identities are lowered. It intentionally contains only
/// source identities; the selected semantic is attached later by the
/// operation's final lowered artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RustReferenceContextSource {
    source_site: ResolutionSiteId,
    source_occurrence: SourceOccurrenceId,
    module_context: SourceOccurrenceId,
    module_declaration: Option<SourceDeclarationId>,
    cfg_condition: RustCfgCondition,
}

const fn rust_reference_context_fields(
    source_site: ResolutionSiteId,
    source_occurrence: SourceOccurrenceId,
    module_context: SourceOccurrenceId,
    module_declaration: Option<SourceDeclarationId>,
) -> (
    ResolutionSiteId,
    SourceOccurrenceId,
    SourceOccurrenceId,
    Option<SourceDeclarationId>,
) {
    (
        source_site,
        source_occurrence,
        module_context,
        module_declaration,
    )
}

/// Compact transient source identity for a native Rust declaration bridge.
/// The declaration is retained alongside the source site so a later lowered
/// semantic cannot silently join through a name or parser-unit key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RustDeclarationContextSource {
    source_site: ResolutionSiteId,
    declaration: SourceDeclarationId,
    module_context: SourceOccurrenceId,
    module_declaration: Option<SourceDeclarationId>,
}

impl RustDeclarationContextSource {
    pub(crate) const fn new(
        source_site: ResolutionSiteId,
        declaration: SourceDeclarationId,
        module_context: SourceOccurrenceId,
        module_declaration: Option<SourceDeclarationId>,
    ) -> Self {
        Self {
            source_site,
            declaration,
            module_context,
            module_declaration,
        }
    }

    pub(crate) const fn source_site(self) -> ResolutionSiteId {
        self.source_site
    }

    pub(crate) const fn declaration(self) -> SourceDeclarationId {
        self.declaration
    }

    pub(crate) const fn module_context(self) -> SourceOccurrenceId {
        self.module_context
    }

    pub(crate) const fn module_declaration(self) -> Option<SourceDeclarationId> {
        self.module_declaration
    }
}

impl RustReferenceContextSource {
    pub(crate) const fn new(
        source_site: ResolutionSiteId,
        source_occurrence: SourceOccurrenceId,
        module_context: SourceOccurrenceId,
        module_declaration: Option<SourceDeclarationId>,
    ) -> Self {
        let (source_site, source_occurrence, module_context, module_declaration) =
            rust_reference_context_fields(
                source_site,
                source_occurrence,
                module_context,
                module_declaration,
            );
        Self {
            source_site,
            source_occurrence,
            module_context,
            module_declaration,
            cfg_condition: RustCfgCondition::Always,
        }
    }

    pub(crate) const fn source_site(&self) -> ResolutionSiteId {
        self.source_site
    }

    pub(crate) const fn source_occurrence(&self) -> SourceOccurrenceId {
        self.source_occurrence
    }

    pub(crate) const fn module_context(&self) -> SourceOccurrenceId {
        self.module_context
    }

    pub(crate) const fn module_declaration(&self) -> Option<SourceDeclarationId> {
        self.module_declaration
    }
    pub fn with_cfg_condition(mut self, condition: RustCfgCondition) -> Self {
        self.cfg_condition = condition;
        self
    }

    pub fn cfg_condition(&self) -> &RustCfgCondition {
        &self.cfg_condition
    }
}

impl LoweredRustReferenceContext {
    pub const fn new(
        reference: SemanticId,
        source_site: ResolutionSiteId,
        source_occurrence: SourceOccurrenceId,
        module_context: SourceOccurrenceId,
        module_declaration: Option<SourceDeclarationId>,
    ) -> Self {
        let (source_site, source_occurrence, module_context, module_declaration) =
            rust_reference_context_fields(
                source_site,
                source_occurrence,
                module_context,
                module_declaration,
            );
        Self {
            reference,
            source_site,
            source_occurrence,
            module_context,
            module_declaration,
            cfg_condition: RustCfgCondition::Always,
        }
    }

    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn source_site(&self) -> ResolutionSiteId {
        self.source_site
    }

    pub const fn source_occurrence(&self) -> SourceOccurrenceId {
        self.source_occurrence
    }

    pub const fn module_context(&self) -> SourceOccurrenceId {
        self.module_context
    }

    pub const fn module_declaration(&self) -> Option<SourceDeclarationId> {
        self.module_declaration
    }
    pub fn with_cfg_condition(mut self, condition: RustCfgCondition) -> Self {
        self.cfg_condition = condition;
        self
    }

    pub fn cfg_condition(&self) -> &RustCfgCondition {
        &self.cfg_condition
    }
}

impl SelectedTypedRow<LoweredRustReferenceContext> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        selected_row_natural_identity(self.fragment(), self.row.reference())
    }
}

/// One selected fact row together with its exact fragment owner.
///
/// Typed callers retain the historical [`SelectedTypedRow`] spelling. New
/// source families use this alias to make the shared ownership boundary
/// explicit without creating another wrapper protocol.
pub type SelectedFactRow<T> = SelectedTypedRow<T>;

impl<T> SelectedTypedRow<T> {
    pub const fn new(fragment: BindingFragmentId, row: T) -> Self {
        Self {
            identity: SelectedTypedRowIdentity::SelectedSource { fragment },
            row,
        }
    }

    pub fn external_owner(owner: ExternalOwnerIdentity, row: T) -> Self {
        Self {
            identity: SelectedTypedRowIdentity::External { owner },
            row,
        }
    }

    pub fn external_member(owner: ExternalOwnerIdentity, ordinal: u32, row: T) -> Self {
        Self {
            identity: SelectedTypedRowIdentity::ExternalMember { owner, ordinal },
            row,
        }
    }

    pub const fn identity(&self) -> &SelectedTypedRowIdentity {
        &self.identity
    }

    pub const fn identity_key(&self) -> SelectedTypedRowKey {
        match self.identity {
            SelectedTypedRowIdentity::SelectedSource { fragment } => {
                SelectedTypedRowKey::SelectedSource(fragment)
            }
            SelectedTypedRowIdentity::External { .. }
            | SelectedTypedRowIdentity::ExternalMember { .. } => SelectedTypedRowKey::External,
        }
    }

    pub const fn fragment(&self) -> BindingFragmentId {
        match self.identity {
            SelectedTypedRowIdentity::SelectedSource { fragment } => fragment,
            _ => panic!("external typed rows have inventory coordinates, not source fragments"),
        }
    }

    pub const fn row(&self) -> &T {
        &self.row
    }

    pub fn with_row<U>(&self, row: U) -> SelectedTypedRow<U> {
        SelectedTypedRow {
            identity: self.identity.clone(),
            row,
        }
    }

    pub fn into_parts(self) -> (BindingFragmentId, T) {
        (self.fragment(), self.row)
    }
}

impl SelectedTypedRow<LoweredTypedFrontier> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        selected_row_natural_identity(self.fragment(), self.row.slot())
    }
}

const fn selected_row_natural_identity(
    fragment: BindingFragmentId,
    semantic: SemanticId,
) -> (BindingFragmentId, SemanticId) {
    (fragment, semantic)
}

impl SelectedTypedRow<LoweredTypeTransfer> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.rule().semantic())
    }

    /// Query-planning key for source-slot access.
    ///
    /// This is not a page-order contract: a selected source may use any
    /// deterministic duplicate-free storage cursor.
    pub const fn source_access_order(&self) -> (BindingFragmentId, SemanticId, SemanticId) {
        (
            self.fragment(),
            self.row.source_slot(),
            self.row.rule().semantic(),
        )
    }

    /// Query-planning key for target-slot access.
    ///
    /// This is not a page-order contract: a selected source may use any
    /// deterministic duplicate-free storage cursor.
    pub const fn target_access_order(&self) -> (BindingFragmentId, SemanticId, SemanticId) {
        (
            self.fragment(),
            self.row.rule().target_slot(),
            self.row.rule().semantic(),
        )
    }
}

impl SelectedTypedRow<LoweredTypeProduction> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.output)
    }
}

impl SelectedTypedRow<LoweredTypeComponent> {
    pub const fn natural_identity(
        &self,
    ) -> (BindingFragmentId, SemanticId, ResolutionTypeComponentKind) {
        (self.fragment(), self.row.container(), self.row.kind())
    }
}

impl SelectedTypedRow<LoweredDeclaredTypeArgument> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, u32) {
        (self.fragment(), self.row.owner(), self.row.position())
    }
}

impl SelectedTypedRow<LoweredTypeArgument> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, u32, SemanticId) {
        (
            self.fragment(),
            self.row.application(),
            self.row.ordinal(),
            self.row.argument(),
        )
    }
}

impl SelectedTypedRow<LoweredGenericTypeAliasParameter> {
    pub const fn natural_identity(
        &self,
    ) -> (BindingFragmentId, SemanticId, u32, SemanticId, SemanticId) {
        (
            self.fragment(),
            self.row.alias(),
            self.row.ordinal(),
            self.row.parameter(),
            self.row.target(),
        )
    }
}

impl SelectedTypedRow<LoweredGenericFormal> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, u32, SemanticId) {
        (
            self.fragment(),
            self.row.owner(),
            self.row.ordinal(),
            self.row.parameter(),
        )
    }
}

impl SelectedTypedRow<LoweredGenericFormalDefault> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, u32, SemanticId) {
        (
            self.fragment(),
            self.row.owner(),
            self.row.ordinal(),
            self.row.default(),
        )
    }
}

impl SelectedTypedRow<LoweredUnderlyingType> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.definition())
    }
}

impl SelectedTypedRow<LoweredIntrinsicSeed> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.frontier().slot())
    }
}

impl SelectedTypedRow<LoweredBindingProjection> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.reference())
    }
}

impl SelectedTypedRow<LoweredDeclarationTypeProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, DeclarationTypeRole) {
        (self.fragment(), self.row.definition(), self.row.role())
    }
}

impl SelectedTypedRow<LoweredDeclarationVisibilityProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.definition())
    }
}

impl SelectedTypedRow<LoweredMemberScopeProperty> {
    pub const fn natural_identity(
        &self,
    ) -> (SelectedTypedRowKey, SemanticId, Option<BindingNodeId>) {
        (
            self.identity_key(),
            self.row.definition(),
            self.row.source_scope_head(),
        )
    }
}

impl SelectedTypedRow<CompanionTypeRelation> {
    pub(crate) const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, SemanticId) {
        (
            self.fragment(),
            self.row.enclosing_type(),
            self.row.companion_type(),
        )
    }
}

impl SelectedTypedRow<LoweredMemberOwnerProperty> {
    pub fn natural_identity(
        &self,
    ) -> (
        SelectedTypedRowKey,
        SemanticId,
        SemanticId,
        Option<BindingNodeId>,
        ResolutionMemberKind,
        ResolutionMemberAccess,
        ResolutionMemberQualifierCompatibility,
    ) {
        (
            self.identity_key(),
            self.row.definition(),
            self.row.owner_definition(),
            self.row.source_owner_scope_head(),
            self.row.kind(),
            self.row.access(),
            self.row.qualifier_compatibility(),
        )
    }
}

impl SelectedTypedRow<LoweredDeferredMemberOwner> {
    pub const fn natural_identity(
        &self,
    ) -> (
        BindingFragmentId,
        SemanticId,
        SemanticId,
        SemanticId,
        ResolutionMemberKind,
        ResolutionMemberAccess,
        ResolutionMemberQualifierCompatibility,
    ) {
        (
            self.fragment(),
            self.row.definition(),
            self.row.owner_frontier(),
            self.row.lookup(),
            self.row.kind(),
            self.row.access(),
            self.row.qualifier_compatibility(),
        )
    }
}

impl SelectedTypedRow<LoweredConstructionRequirementProperty> {
    pub const fn natural_identity(
        &self,
    ) -> (
        BindingFragmentId,
        SemanticId,
        ResolutionConstructionRequirementKind,
        SemanticId,
    ) {
        (
            self.fragment(),
            self.row.definition(),
            self.row.kind(),
            self.row.required_owner_definition(),
        )
    }
}

impl SelectedTypedRow<LoweredSupertypeProperty> {
    pub const fn natural_identity(
        &self,
    ) -> (
        SelectedTypedRowKey,
        SemanticId,
        Option<ResolutionSupertypeKind>,
        SemanticId,
        SemanticId,
    ) {
        (
            self.identity_key(),
            self.row.definition(),
            self.row.source_kind(),
            self.row.reference(),
            self.row.frontier(),
        )
    }
}

impl SelectedTypedRow<LoweredDefinitionPropertyGap> {
    pub const fn natural_identity(
        &self,
    ) -> (BindingFragmentId, SemanticId, SemanticId, SemanticId) {
        (
            self.fragment(),
            self.row.definition(),
            self.row.reason_semantic(),
            self.row.frontier(),
        )
    }
}

impl SelectedTypedRow<LoweredCallApplicabilityObligation> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.call())
    }
}

impl SelectedTypedRow<LoweredCallableSignatureProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.row.definition())
    }
}

/// One qualified route joined to its selected lexical reference node.
///
/// The persisted route alone is insufficient for seeded evaluation. Joining
/// the node here also proves that lexical and typed ownership came from the
/// same selected sealed fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedQualifiedRoute {
    fragment: BindingFragmentId,
    reference_node: BindingNodeId,
    row: LoweredQualifiedSeededRoute,
    language: Language,
}

impl SelectedQualifiedRoute {
    pub const fn new(
        fragment: BindingFragmentId,
        reference_node: BindingNodeId,
        row: LoweredQualifiedSeededRoute,
    ) -> Self {
        Self {
            fragment,
            reference_node,
            row,
            language: Language::None,
        }
    }

    /// Retain selected mount metadata without a later source read. This is not
    /// part of the persisted route identity or any lookup key.
    pub const fn with_language(mut self, language: Language) -> Self {
        self.language = language;
        self
    }

    pub const fn language(self) -> Language {
        self.language
    }

    pub const fn fragment(self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn reference_node(self) -> BindingNodeId {
        self.reference_node
    }

    pub const fn row(self) -> LoweredQualifiedSeededRoute {
        self.row
    }

    /// The exact persisted route key includes the independently produced output.
    pub const fn natural_identity(self) -> (BindingFragmentId, SemanticId, u32, SemanticId) {
        (
            self.fragment(),
            self.row.reference(),
            self.row.precedence_ordinal(),
            self.row.projection_output_slot(),
        )
    }

    pub const fn into_parts(
        self,
    ) -> (
        BindingFragmentId,
        BindingNodeId,
        LoweredQualifiedSeededRoute,
    ) {
        (self.fragment(), self.reference_node, self.row)
    }
}

/// One selected entry in the canonical lowered gap-reason catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedGapReasonProvenance {
    fragment: BindingFragmentId,
    reason: SemanticId,
    source_site: ResolutionSiteId,
    origin: LoweringGapOrigin,
}

impl SelectedGapReasonProvenance {
    pub const fn new(
        fragment: BindingFragmentId,
        reason: SemanticId,
        source_site: ResolutionSiteId,
        origin: LoweringGapOrigin,
    ) -> Self {
        Self {
            fragment,
            reason,
            source_site,
            origin,
        }
    }

    pub const fn fragment(self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn reason(self) -> SemanticId {
        self.reason
    }

    pub const fn source_site(self) -> ResolutionSiteId {
        self.source_site
    }

    pub const fn origin(self) -> LoweringGapOrigin {
        self.origin
    }

    pub const fn natural_identity(self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.reason)
    }
}

/// The persisted semantic completion attached to one selected typed frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedTypeFrontierCompletion {
    fragment: BindingFragmentId,
    frontier: SemanticId,
    completion: ResolutionCompletion,
}

impl SelectedTypeFrontierCompletion {
    pub fn new(
        fragment: BindingFragmentId,
        frontier: SemanticId,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            fragment,
            frontier,
            completion,
        }
    }

    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn frontier(&self) -> SemanticId {
        self.frontier
    }

    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment(), self.frontier)
    }

    pub fn into_parts(self) -> (BindingFragmentId, SemanticId, ResolutionCompletion) {
        (self.fragment(), self.frontier, self.completion)
    }
}

/// An invocation role carried by an exact selected head reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedInvocationRole {
    pub reference: SemanticId,
    pub language: Language,
    pub role: brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole,
}

/// Composite key used by exact qualified-route candidate discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualifiedRouteSlotLookup {
    qualifier_slot: SemanticId,
    lookup: SemanticId,
}

/// A JVM alias of an authored declaration, read only for this query.
/// Owner components and member spelling nominate candidates; the declaration
/// remains the identity that forward confirmation must prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmAliasProperty {
    pub definition: SemanticId,
    pub alias: u32,
    pub member_name: String,
    pub owner_segments: Vec<String>,
    pub kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionJvmAliasKind,
    pub status: brokk_bifrost_core::analyzer::resolution_facts::ResolutionJvmAliasStatus,
}

impl SelectedTypedRow<JvmAliasProperty> {
    pub fn natural_identity(&self) -> (BindingFragmentId, SemanticId, u32) {
        (self.fragment(), self.row.definition, self.row.alias)
    }
}

/// A persisted companion declaration paired with the type that encloses it.
///
/// The storage table is site keyed; the selected reader joins those sites to
/// their semantic definitions so the shared resolver can add the companion's
/// actual member scope to an enclosing type lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompanionTypeRelation {
    enclosing_type: SemanticId,
    companion_type: SemanticId,
}

impl CompanionTypeRelation {
    pub(crate) const fn new(enclosing_type: SemanticId, companion_type: SemanticId) -> Self {
        Self {
            enclosing_type,
            companion_type,
        }
    }

    pub(crate) const fn enclosing_type(self) -> SemanticId {
        self.enclosing_type
    }

    pub(crate) const fn companion_type(self) -> SemanticId {
        self.companion_type
    }
}

/// Shared member-name key used to enumerate candidate impl subjects before
/// exact owner-frontier validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeferredMemberOwnerLookupName {
    lookup: SemanticId,
}

impl DeferredMemberOwnerLookupName {
    pub const fn new(lookup: SemanticId) -> Self {
        Self { lookup }
    }

    pub const fn lookup(self) -> SemanticId {
        self.lookup
    }
}

impl QualifiedRouteSlotLookup {
    pub const fn new(qualifier_slot: SemanticId, lookup: SemanticId) -> Self {
        Self {
            qualifier_slot,
            lookup,
        }
    }

    pub const fn qualifier_slot(self) -> SemanticId {
        self.qualifier_slot
    }

    pub const fn lookup(self) -> SemanticId {
        self.lookup
    }

    pub const fn into_parts(self) -> (SemanticId, SemanticId) {
        (self.qualifier_slot, self.lookup)
    }
}

/// Bounded read side for immutable typed facts in one exact selected context.
///
/// Every implementation is a closed-world authority for one selected context.
/// A returned row must belong to a selected, fully published fragment; no
/// method may bypass membership and sealing through a raw fragment lookup.
/// Each parent row is atomic: all ordered children, row-local completion
/// reasons, and values needed to reconstruct the lowered value must be decoded
/// before the row enters a page. Operational SQL/decode failures are
/// `StoreResult` errors and never empty semantic answers.
///
/// Concatenated pages use one deterministic, duplicate-free source cursor
/// order. That order may use storage-local keys and is deliberately unrelated
/// to opaque mounted runtime IDs. Each row's `natural_identity` is the stable
/// duplicate/conflict key; type-transfer source and target access keys remain
/// query-planning details, not stream-order requirements. Therefore preload
/// and SQL implementations are equal exactly when their rows, child order,
/// evidence, terminal, and selected ownership are equal; page boundaries and
/// source cursor order are immaterial. Consumers validate uniqueness while
/// staging and restore canonical runtime order only after `Exhausted`, the
/// sole terminal that proves a missing requested identity is absent. A stopped
/// read must retain the full source-known evidence for the request, while a
/// cancelled read retains every decoded semantic evidence item unchanged; its
/// terminal supplies the operational cancellation proof and makes no claim
/// about an unread suffix.
///
/// The separate directions and inventories below are intentional indexed
/// access shapes. Implementations must not satisfy them with per-identity
/// point reads or by hydrating every selected fragment first.
/// Selected creation authority, independent of a language's surface syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassCreationKind {
    Ordinary,
    Custom,
    Unknown,
}

/// Authority for an implicit base inventory or its language-defined root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImplicitBaseAuthority {
    Selected(SelectedTypedRowIdentity),
    Intrinsic { descriptor: SemanticId },
}

/// Exact selected root identity; its authority must survive remounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImplicitRootObject {
    pub identity: SemanticId,
    pub authority: ImplicitBaseAuthority,
    pub occurrence: SemanticId,
}

/// Inputs for one owner's implicit base. Empty written inventory is distinct
/// from missing metadata and does not by itself prove ordinary creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImplicitBaseInputs {
    pub written_inventory_complete: bool,
    pub written_base_count: u32,
    pub creation: ClassCreationKind,
    pub root_object: Option<ImplicitRootObject>,
    pub authority: ImplicitBaseAuthority,
    pub completion: ResolutionCompletion,
}

/// Static qualified-member rules available in one selected source. This table
/// contains no selected owners, provider rows or workspace-sized state.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct QualifiedMemberRegistration {
    pub language: Language,
    pub hierarchy_identity: u64,
    pub member_access: bool,
}

/// Query-local seed whose prerequisites must all select one proven identity.
/// Language hooks supply the rules; the shared evaluator owns dependency demand
/// and activation. These values are never persisted.
#[derive(Clone, Debug)]
pub struct ConditionalTypeSeed {
    pub slot: SemanticId,
    pub value: super::ResolutionSlotValue,
    pub prerequisites: Vec<(SemanticId, SemanticId)>,
}

pub trait SelectedTypedFactSource {
    /// Fixed selected capability. Default languages incur no seed reader call.
    fn supports_conditional_type_seeds(&self) -> bool {
        false
    }

    /// Default languages add no facts and perform no reads.
    fn conditional_type_seeds(
        &self,
        _slots: &[SemanticId],
        _cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ConditionalTypeSeed>> {
        Ok(Vec::new())
    }

    /// An empty default preserves ordinary qualified replay without extra reads.
    fn qualified_member_registrations(&self) -> &'static [QualifiedMemberRegistration] {
        &[]
    }

    /// Bounded selected inputs for one owner. None exposes no authority; a
    /// cancelled read also returns None with cancellation set. The default
    /// performs no reads, preserving existing language work and lifecycles.
    fn implicit_base_inputs(
        &self,
        _owner: SemanticId,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBaseInputs>> {
        Ok(None)
    }

    /// Selected versioned inventory inputs, requested only for a language that
    /// opts into selected universe authority. Shared registry data determines
    /// presence. The default has no inventory and performs no work.
    fn intrinsic_member_inventory(
        &self,
        _owner: SemanticId,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<super::universe::IntrinsicMemberInventory>> {
        Ok(None)
    }

    /// Whether no selected declaration provider owns this JVM type. Intrinsic
    /// absence proofs yield to both unique and ambiguous authority.
    /// Sources without external declarations have no provider to shadow it.
    fn jvm_intrinsic_owner_is_unshadowed(
        &self,
        _owner_fqn: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        Ok(!cancellation.is_cancelled())
    }

    /// Selected source language capability for one positioned reference.
    fn generated_items_cannot_shadow_bindings(
        &self,
        _reference: SemanticId,
        _cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        Ok(false)
    }

    /// Read the exact positioned named-argument label at `reference`.
    fn named_argument_label_for_reference(
        &self,
        _reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<NamedArgumentLabelRead> {
        Ok(if cancellation.is_cancelled() {
            NamedArgumentLabelRead::Cancelled
        } else {
            NamedArgumentLabelRead::Missing
        })
    }

    /// Find the unique parameter of the selected callable with this label.
    fn callable_parameter_for_label(
        &self,
        _callable: SemanticId,
        _label: &str,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        Ok(None)
    }

    /// Qualify path precedence under the reference's activation premise.
    /// False excludes this route; None means cancellation. Languages without
    /// activation premises preserve their paths unchanged.
    fn qualify_selection_path(
        &self,
        _reference: SemanticId,
        _path: &mut super::PartialPath,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<bool>> {
        Ok((!cancellation.is_cancelled()).then_some(true))
    }

    /// Evaluate exact source authority against one persisted crate selection.
    fn rust_crate_access(
        &self,
        _crate_key: [u8; 32],
        _base_blobs: &[(BindingFragmentId, i64)],
        _reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        _definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<DeclarationAccessDecision>> {
        Ok(None)
    }

    fn rust_crate_set_access(
        &self,
        _crate_key: [u8; 32],
        _base_blobs: &[(BindingFragmentId, i64)],
        _reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        _definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<DeclarationAccessDecision>> {
        Ok(None)
    }

    /// Associated Target declarations of impls for one selected nominal owner.
    /// The selected subject index is the driver even when the trait is external.
    fn rust_receiver_impl_targets(
        &self,
        _owner: SemanticId,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        Ok(Vec::new())
    }

    /// The traits the type declared at `owner` implements that the module
    /// `reference` is written in can name, as those traits' definitions.
    ///
    /// This is Rust's method-call rule for a member no implementation of the
    /// type declares: `value.member()` reaches a trait's own member only when
    /// the type implements the trait and the trait is in scope where the call
    /// is written. Crate derivation binds both ends of every `impl Trait for
    /// Type` it reaches, so the question is asked of the tier-1 crate rows,
    /// keyed by the owner's declaration and the reference's module placement.
    ///
    /// A source that holds no Rust crate rows answers an empty set, as does a
    /// reference in another language: no Rust implementation applies there.
    fn rust_implemented_traits_nameable_at(
        &self,
        _owner: SemanticId,
        _reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        Ok(empty_rust_traits_or_cancelled(cancellation))
    }

    /// Whether the reference can name this specific Rust trait, independent of its implementor.
    fn rust_trait_nameable_at(
        &self,
        _owner: SemanticId,
        _reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        Ok(if cancellation.is_cancelled() {
            RustImplementedTraits::Cancelled
        } else {
            RustImplementedTraits::Unplaced
        })
    }

    /// The traits the crate rows say the impl declaring the Rust item
    /// `member` states, as those traits' definitions.
    ///
    /// An impl's trait is a crate-level fact that crate derivation decided in
    /// the impl's own crate, so the answer does not depend on where the item
    /// is asked from. An empty set means the rows bind no trait to that impl,
    /// and the caller resolves the impl's header instead. A source that holds
    /// no Rust crate rows answers an empty set.
    fn rust_impl_item_traits(
        &self,
        _member: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        Ok(empty_rust_traits_or_cancelled(cancellation))
    }

    /// The persisted namespace of a shared lookup recipe. An absent recipe
    /// cannot authorize splitting a widened lexical head into namespaces.
    fn lookup_namespace(
        &self,
        _lookup: SemanticId,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionNamespace>> {
        Ok(None)
    }

    /// Whether the selection can contain Java semantics at all. A source
    /// without selection metadata (a preloaded fixture) answers `true`, which
    /// only permits Java-specific work; it never skips any.
    fn selection_has_java_semantics(&self) -> bool {
        true
    }

    /// Whether the selection can contain JVM semantics at all. Without its
    /// own selection metadata, a source follows the Java selection answer.
    fn selection_has_jvm_semantics(&self) -> bool {
        self.selection_has_java_semantics()
    }

    /// Exact selected external callable result types keyed by their external
    /// member identities. Results are present only for named types whose owner
    /// has one identity in the selected provider set; unresolved and
    /// non-nominal signatures remain absent.
    fn external_callable_result_type_identities(
        &self,
        _definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Selection rank of one independently identified callee route. Stored
    /// ordinals stay unique even when a language joins namespaces in one family.
    fn fragment_call_target_precedence(
        &self,
        _fragment: BindingFragmentId,
        _namespace: ResolutionNamespace,
        ordinal: u32,
    ) -> StoreResult<u32> {
        Ok(ordinal)
    }

    /// Source language of one selected fragment, read from immutable mount
    /// metadata. Unknown metadata cannot authorize language-specific member
    /// inheritance refinement.
    fn fragment_language(&self, _fragment: BindingFragmentId) -> StoreResult<Language> {
        Ok(Language::None)
    }

    /// Whether a type-object qualifier written in `fragment` also searches its
    /// companion object's members. Only a source that knows each fragment's
    /// language can answer `true`, so a source without that metadata answers
    /// `false`. A workspace-wide answer would charge every fragment with the
    /// companion read, including fragments of languages without companions.
    fn fragment_type_qualifiers_search_companion_members(
        &self,
        _fragment: BindingFragmentId,
    ) -> StoreResult<bool> {
        Ok(false)
    }

    /// Whether reverse intrinsic lookups are keyed only by shared type names.
    /// Sources with that index shape cannot answer fragment-local identities;
    /// source-backed implementations may support both kinds.
    fn intrinsic_reverse_index_uses_shared_type_names(&self) -> bool {
        false
    }

    /// Exact selected Java source properties for the requested declarations.
    /// An omitted declaration has no available Java metadata; None is cancellation.
    fn java_access_endpoints(
        &self,
        _semantics: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<JavaAccessEndpoint>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Exact selected JVM endpoints for language visibility rules. An omitted
    /// declaration has no selected JVM metadata; None is cancellation.
    fn jvm_access_endpoints(
        &self,
        _semantics: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<JvmAccessEndpoint>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Translate selected Go value/callable lookup recipes into the shared
    /// callable spelling space used for field/method shadowing. Omitted names
    /// have no available Go recipe; None reports cancellation.
    fn go_callable_lookups(
        &self,
        _lookups: &[(BindingFragmentId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Invocation roles keyed on the requested positioned reference sites.
    /// References without a role are omitted; None reports cancellation.
    fn invocation_roles_for_references(
        &self,
        _references: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SelectedInvocationRole>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// The subset of `lookups` whose recipe spells no member name of the
    /// implicit root supertype of the recipe's own JVM language
    /// ([`language_implicit_root_member_names`]). Such a lookup cannot reach a
    /// member the implicit root declares, so an inherited walk that is sealed
    /// apart from that root has an exhaustive negative answer for it. A lookup
    /// with no recipe, or of a language with no modelled implicit root, is
    /// omitted, never reported as outside the root. None reports cancellation.
    fn lookups_outside_implicit_root(
        &self,
        _lookups: &[(BindingFragmentId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Requested identities proven to denote lexical type parameters by
    /// existing source declarations. Missing source metadata proves nothing.
    fn generic_parameter_declarations(
        &self,
        _definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Whether each declaration participates in the selected language build.
    /// Missing build metadata preserves participation; None means cancellation.
    /// Apply this before demanding a deferred candidate's owner frontier.
    fn deferred_member_participation(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<bool>>> {
        Ok((!cancellation.is_cancelled()).then(|| vec![true; definitions.len()]))
    }

    /// All member-file sources of each declaration's selected Go package.
    /// Missing package membership or an unmounted member returns None for that
    /// declaration; an incomplete inventory cannot certify placement.
    fn go_package_member_sources(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<Option<Vec<SemanticId>>>>> {
        Ok((!cancellation.is_cancelled()).then(|| vec![None; definitions.len()]))
    }

    /// Whether each source has selected Go placement or authoritative exclusion.
    /// Source identities come from gap provenance; absent membership proves nothing.
    fn go_source_placement_proofs(
        &self,
        sources: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<bool>>> {
        Ok((!cancellation.is_cancelled()).then(|| vec![false; sources.len()]))
    }

    /// Admission proof for exact deferred members against a complete receiver
    /// promotion set. Unknown preserves the ordinary name-based demand path.
    /// Each candidate is (definition, owner frontier); preserve input order.
    /// Implementations and their immutable read reuse live for one request.
    fn deferred_member_owner_proofs(
        &self,
        _owners: &[SemanticId],
        candidates: &[(SemanticId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<DeferredMemberOwnerProof>>> {
        Ok((!cancellation.is_cancelled())
            .then(|| vec![DeferredMemberOwnerProof::Unknown; candidates.len()]))
    }

    /// Missing declarations have unavailable Go metadata. A returned struct
    /// with no embedded fields has a known empty embedding inventory.
    fn go_member_declarations(
        &self,
        _definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<GoMemberDeclaration>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Selected model declaration behind an unindexed callable-result frontier.
    /// Outer None denotes cancellation; inner None means no unique result declaration.
    fn unindexed_model_callable_result(
        &self,
        _frontier: &super::UnindexedExternalFrontier,
        cancellation: &CancellationToken,
        _session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> StoreResult<Option<Option<ModelCallableResultDeclaration>>> {
        Ok((!cancellation.is_cancelled()).then_some(None))
    }

    /// A reached selected model member callable. No source or durable inventory is minted.
    fn model_member_callable_result(
        &self,
        _member: &crate::analyzer::semantic_model::overlay::ModelSymbolRef,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<ModelCallableResultDeclaration>>> {
        Ok((!cancellation.is_cancelled()).then_some(None))
    }

    /// A model owner has no source SQL inventory. The outer None denotes
    /// cancellation; an inner None means unavailable selected model metadata.
    fn go_model_owner_declarations(
        &self,
        _definition: SemanticId,
        _owner: &super::ExternalOwnerIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<GoModelOwnerDeclarations>>> {
        Ok((!cancellation.is_cancelled()).then_some(None))
    }

    /// Exact source-owned lexical hierarchy terminals. Missing terminals are
    /// legitimate for abstract type frontiers and declarations without bodies.
    /// None reports cancellation; requests come from selected gap provenance.
    fn hierarchy_terminal_nodes(
        &self,
        gaps: &[SelectedGapReasonProvenance],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, BindingNodeId)>>>;

    /// Selected JVM type and callable properties for lexical hierarchy replay.
    /// Omitted declarations have no available metadata; None is cancellation.
    fn java_inheritance_declarations(
        &self,
        _definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<JavaInheritanceDeclaration>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Selected Rust owners whose supertype rows describe trait bounds.
    /// None reports cancellation. Other languages keep their existing member rules.
    fn rust_supertrait_owners(
        &self,
        _owners: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Import-binding identities usable as opaque external type-flow values.
    /// These are not definition targets and do not close the external boundary.
    /// Sources without Rust import rows answer an empty set; None is cancellation.
    fn rust_external_type_identities(
        &self,
        _boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// The structured Rust import path behind an external type boundary, if
    /// the boundary is an imported type name. The path contains module
    /// segments followed by the imported item name; it is empty for sources
    /// without a persisted Rust import row. `None` reports cancellation.
    fn rust_external_type_import_path(
        &self,
        _boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<String>>> {
        Ok((!cancellation.is_cancelled()).then(Vec::new))
    }

    /// Namespace-valued bindings contribute no missing declared value type.
    fn namespace_definitions(
        &self,
        _definitions: &[SemanticId],
        _cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        Ok(Vec::new())
    }

    /// Module declarations classified by the selected languages' providers.
    /// Sources without a provider perform no reads. Cancellation is observed by the caller.
    fn module_definitions(
        &self,
        _definitions: &[SemanticId],
        _cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        Ok(Vec::new())
    }

    /// The Rust module declarations among `definitions`.
    ///
    /// A module lives in the type namespace but is not a type, so a path
    /// prefix that names one gives its terminal no receiver type. The source
    /// module rows say which declarations are modules; a source that holds no
    /// Rust rows answers none. A cancelled read answers none as well, and the
    /// caller observes the cancellation itself.
    fn rust_module_definitions(
        &self,
        _definitions: &[SemanticId],
        _cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        Ok(Vec::new())
    }

    /// Visit the exact fragment membership of this selected source.
    ///
    /// This inventory is independent of fact-row cardinality and therefore
    /// includes selected fragments whose lexical and typed relations are all
    /// empty. Only a live `Exhausted` terminal with complete evidence
    /// certifies the closed-world membership; stopped and cancelled prefixes
    /// must never be published as a selected snapshot.
    fn visit_selected_fragment_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, BindingFragmentId>,
    ) -> StoreResult<FactReadOutcome>;

    /// Read completion for the selected reverse-reference inventory.
    ///
    /// This is selection-wide evidence assembled by placement and publication,
    /// not a completion synthesized from whichever typed rows a caller happens
    /// to demand. A live exhausted read returns the exact completion even for
    /// an empty selected context. A source-observed cancellation returns a
    /// `Cancelled` terminal and only semantic evidence decoded before it.
    fn read_selected_reverse_inventory_completion(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Visit exact Rust source authority for selected reference semantics.
    ///
    /// A row is present only when the semantic site has a canonical source
    /// occurrence and a containing Rust module/file context. Missing source
    /// authority is an operationally unavailable read, never a file-root
    /// fallback.
    fn visit_rust_reference_context_pages(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustReferenceContext>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Visit exact source authority for selected Rust definition semantics.
    /// Missing bridge/context rows are operationally unavailable; a row with
    /// no item visibility is a legitimate local definition and remains
    /// available to the policy as an Unknown case.
    fn visit_rust_declaration_authority_pages(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_typed_frontier_pages(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Reference observations of transfer-owned type identities, indexed by occurrence.
    fn visit_type_identity_observation_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_type_frontier_completion_pages(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypeFrontierCompletion>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_type_transfer_pages_from_sources(
        &self,
        source_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_type_transfer_pages_to_targets(
        &self,
        target_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_type_production_pages_for_outputs(
        &self,
        outputs: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeProduction>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_type_component_pages_for_containers(
        &self,
        containers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeComponent>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_declared_type_argument_pages_for_owners(
        &self,
        owners: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclaredTypeArgument>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_type_argument_pages_for_applications(
        &self,
        applications: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeArgument>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_generic_type_alias_parameter_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericTypeAliasParameter>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_generic_formal_pages_for_owners(
        &self,
        owners: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericFormal>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_generic_formal_default_pages_for_owners(
        &self,
        owners: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericFormalDefault>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_underlying_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredUnderlyingType>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_intrinsic_seed_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_intrinsic_seed_pages_for_type_identities(
        &self,
        type_identities: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Visit distinct selected `(identity, kind, spelling)` rows for the
    /// requested intrinsic type identities. Conflicting descriptor tuples
    /// remain separate rows so the caller can reject inconsistent facts.
    fn visit_intrinsic_type_descriptor_pages_for_type_identities(
        &self,
        type_identities: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicTypeDescriptor>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_binding_projection_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_binding_projection_pages_for_outputs(
        &self,
        output_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_qualified_route_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Select exact qualifier slots paired with either the source lookup or
    /// the typed member lookup. Publish each natural route identity once even
    /// when both coordinates, or multiple requests, select it.
    fn visit_qualified_route_pages_for_slot_lookups(
        &self,
        requests: TypedFactRequest<'_, QualifiedRouteSlotLookup>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_qualified_route_pages_for_qualifier_slots(
        &self,
        qualifier_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Select either exact source or typed member lookup coordinates, with
    /// each natural route identity published once across the requested union.
    fn visit_qualified_route_pages_for_lookups(
        &self,
        lookups: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_qualified_route_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_qualified_route_inventory_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_declaration_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_declaration_type_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_declaration_visibility_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_member_scope_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Enumerate existing JVM alias spellings and owner routes for exact
    /// authored definitions. Sources without alias facts must stay open.
    fn visit_jvm_alias_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        _visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<JvmAliasProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let completion = if definitions.as_slice().is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(
                definitions
                    .as_slice()
                    .iter()
                    .copied()
                    .map(ResolutionIncompleteReason::UnsupportedSemantic),
            )
        };
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(completion)
        } else {
            TypedFactReadOutcome::exhausted(completion)
        })
    }

    /// Visit companion declarations enclosed by selected type definitions.
    ///
    /// A companion relation is consumed beside member-scope reads, where the
    /// shared lookup can select the companion's own persisted scope.
    fn visit_companion_relation_pages_for_enclosing_types(
        &self,
        _enclosing_types: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        _visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<CompanionTypeRelation>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn visit_member_scope_pages_for_heads(
        &self,
        heads: TypedFactRequest<'_, BindingNodeId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_member_owner_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_member_owner_pages_for_owners(
        &self,
        owner_definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Read deferred member owners by their exact definition identity.
    ///
    /// Sources that do not retain this direction may use the closed-world
    /// empty default; persisted selected sources override it with the
    /// definition primary-key read.
    fn visit_deferred_member_owner_pages_for_definitions(
        &self,
        _definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        _visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn visit_deferred_member_owner_pages_for_lookup_names(
        &self,
        lookups: TypedFactRequest<'_, DeferredMemberOwnerLookupName>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_construction_requirement_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredConstructionRequirementProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_supertype_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_supertype_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_supertype_pages_for_frontiers(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_definition_property_gap_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_definition_property_gap_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_call_applicability_pages_for_callee_references(
        &self,
        callee_references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Read exact callee-owned applicability obligations for raw gap reasons.
    /// A same-origin gap on a call site or declaration is not an obligation
    /// match. Sources must establish the callee provenance and exact reason
    /// equality without requiring a speculative reference identity to exist.
    fn visit_call_applicability_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_callable_signature_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Read persisted gap provenance from a possibly mixed completion-reason
    /// set. Semantic reasons without a persisted gap row contribute no rows;
    /// absence of provenance does not discharge their completion obligation.
    fn visit_gap_reason_provenance_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
    ) -> StoreResult<TypedFactReadOutcome>;

    /// Visit persisted Rust declaration ownership for lowering-gap reasons.
    /// Other sources have no Rust declaration-authority join and return empty.
    fn visit_rust_reason_owners(
        &self,
        _reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        _visitor: &mut TypedFactPageVisitor<'_, (SemanticId, SemanticId)>,
    ) -> StoreResult<TypedFactReadOutcome> {
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }
}

/// Whether one selected semantic language uses the JVM resolution rules.
pub(crate) const fn language_has_jvm_semantics(language: Language) -> bool {
    matches!(
        language,
        Language::Java | Language::Kotlin | Language::Scala
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JvmDeclarationAccessRules {
    Java,
    Kotlin,
    Scala,
}

impl JvmDeclarationAccessRules {
    pub(crate) const fn contextual_visibility_without_gap(self) -> bool {
        matches!(self, Self::Scala)
    }

    /// Namespace of a source owner whose authored members have JVM static
    /// access. Kotlin requires its explicit JVM aliases: singleton instance
    /// members alone do not establish a Java static entry point.
    pub(crate) const fn java_static_import_owner_namespace(self) -> Option<ResolutionNamespace> {
        match self {
            Self::Java => Some(ResolutionNamespace::Type),
            Self::Scala => Some(ResolutionNamespace::Value),
            Self::Kotlin => None,
        }
    }

    /// Java public members remain inherited through a superclass the caller
    /// cannot name. Direct type references and final members keep access checks.
    pub(crate) const fn inherited_member_requires_accessible_owner(self) -> bool {
        !matches!(self, Self::Java)
    }

    /// A Java superclass or superinterface name denotes a nominal type
    /// declaration, so a hierarchy edge's unique selected target is the
    /// parent itself. Kotlin and Scala supertypes may name type aliases,
    /// which their type-frontier projection expands first.
    pub(crate) const fn supertype_references_are_nominal(self) -> bool {
        matches!(self, Self::Java)
    }

    /// JLS 6.6.2.1: outside its package, a protected instance field or
    /// method is accessible through a qualifier only when the qualifier's
    /// type is the accessing subclass or one of its subtypes. Kotlin and
    /// Scala keep their existing subclass access rules.
    pub(crate) const fn protected_access_requires_qualifier_subtype(self) -> bool {
        matches!(self, Self::Java)
    }
}

/// JVM source imports spell nested types canonically (Outer.Inner). After
/// package selection proves that prefix, the binary type is Outer$Inner.
/// This converts the caller's type route; it never guesses a target
/// language's facade, singleton, companion, or local-class projection.
pub(crate) fn language_jvm_import_binary_owner(
    language: Language,
    package_segments: usize,
    owner: &[&str],
) -> Vec<String> {
    if matches!(
        language,
        Language::Java | Language::Kotlin | Language::Scala
    ) && package_segments < owner.len()
    {
        let mut result = owner[..package_segments]
            .iter()
            .map(|segment| (*segment).to_owned())
            .collect::<Vec<_>>();
        result.push(owner[package_segments..].join("$"));
        result
    } else {
        owner.iter().map(|segment| (*segment).to_owned()).collect()
    }
}

/// The declared-visibility rules selected for one JVM declaration language.
pub(crate) fn language_jvm_declaration_access_rules(
    language: Language,
) -> Option<JvmDeclarationAccessRules> {
    crate::analyzer::store::resolution_operation::nominal_rules::nominal_language_rules(language)
        .map(|rules| rules.declaration_access_rules())
}

#[doc(hidden)]
/// An implicit provider that can make a bare JVM name visible without an
/// explicit import in the source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum JvmImplicitRootProvider {
    Package(&'static str),
    ScalaPredef,
}

const JAVA_IMPLICIT_ROOT_PROVIDERS: &[JvmImplicitRootProvider] =
    &[JvmImplicitRootProvider::Package("java.lang")];
const KOTLIN_IMPLICIT_ROOT_PROVIDERS: &[JvmImplicitRootProvider] = &[
    JvmImplicitRootProvider::Package("kotlin"),
    JvmImplicitRootProvider::Package("kotlin.annotation"),
    JvmImplicitRootProvider::Package("kotlin.collections"),
    JvmImplicitRootProvider::Package("kotlin.comparisons"),
    JvmImplicitRootProvider::Package("kotlin.io"),
    JvmImplicitRootProvider::Package("kotlin.ranges"),
    JvmImplicitRootProvider::Package("kotlin.sequences"),
    JvmImplicitRootProvider::Package("kotlin.text"),
    JvmImplicitRootProvider::Package("kotlin.jvm"),
    JvmImplicitRootProvider::Package("java.lang"),
];
const SCALA_IMPLICIT_ROOT_PROVIDERS: &[JvmImplicitRootProvider] = &[
    JvmImplicitRootProvider::Package("java.lang"),
    JvmImplicitRootProvider::Package("scala"),
    JvmImplicitRootProvider::ScalaPredef,
];

/// The implicit package and singleton providers whose missing inventory keeps
/// a bare-name lookup open for one JVM language.
#[doc(hidden)]
pub const fn language_implicit_root_providers(
    language: Language,
) -> &'static [JvmImplicitRootProvider] {
    match language {
        Language::Java => JAVA_IMPLICIT_ROOT_PROVIDERS,
        Language::Kotlin => KOTLIN_IMPLICIT_ROOT_PROVIDERS,
        Language::Scala => SCALA_IMPLICIT_ROOT_PROVIDERS,
        _ => &[],
    }
}

/// Java package imports supply types, whereas Kotlin and Scala also import
/// terms. A widened type/value reference must not invent a value provider.
pub(crate) const fn language_implicit_root_providers_in_namespace(
    language: Language,
    namespace: ResolutionNamespace,
) -> &'static [JvmImplicitRootProvider] {
    if matches!(language, Language::Java)
        && !matches!(
            namespace,
            ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
        )
    {
        &[]
    } else {
        language_implicit_root_providers(language)
    }
}

/// Whether call applicability may close an interface's implicit Object frontier.
///
/// An interface with no superinterface implicitly declares the public methods
/// of `java.lang.Object` (JLS 9.2), so a directly declared interface method is
/// a complete candidate when the only possible inherited names are Object
/// methods. Java states that rule itself and Kotlin follows it through Java
/// interop. Scala's interop remains conservative.
pub(crate) const fn language_can_close_interface_object_frontier(language: Language) -> bool {
    matches!(language, Language::Java | Language::Kotlin)
}

/// Whether selected nominal metadata can denote an implicit root or an ancestor
/// of one. This only excludes impossible targets; it never proves a subtype.
/// Scala's root ancestry remains conservative for its entire root package.
pub(crate) fn language_implicit_superclass_may_reach_type(
    language: Language,
    package: Option<&str>,
    name: &str,
) -> bool {
    match language {
        Language::Java => package == Some("java.lang") && name == "Object",
        Language::Kotlin => package == Some("kotlin") && name == "Any",
        Language::Scala => package == Some("scala"),
        _ => false,
    }
}

/// The identity namespace shared by declarations visible to one language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ResolutionIdentityDomain {
    Jvm,
    Language(Language),
}

impl ResolutionIdentityDomain {
    pub(crate) fn identity_label(self) -> &'static str {
        match self {
            Self::Jvm => "jvm",
            Self::Language(language) => language.config_label(),
        }
    }
}

/// Map a selected language to the namespace used for declaration lookup keys.
pub(crate) const fn language_identity_domain(language: Language) -> ResolutionIdentityDomain {
    if language_has_jvm_semantics(language) {
        ResolutionIdentityDomain::Jvm
    } else {
        ResolutionIdentityDomain::Language(language)
    }
}

/// The origin rank carried by a proven lexical declaration. Scala orders its
/// local declarations before imported and package alternatives. An unresolved
/// lexical continuation has no such proof and therefore keeps no origin rank.
/// Other languages retain their existing scope-choice ordering.
pub(crate) const fn language_lexical_binder_origin(
    language: Language,
) -> Option<super::model::BindingOrigin> {
    match language {
        Language::Scala => Some(super::model::BindingOrigin::LocalOrInherited),
        _ => None,
    }
}

/// Whether qualified callable routes search inherited overloads past the nearest owner.
///
/// Java deliberately keeps nearest-owner replay: renaming `Base.oldName` to a
/// name declared on `Child` must see `child.oldName()` rebind to `Child`'s
/// method, so native rename refuses at its counterfactual capture check.
pub(crate) const fn language_uses_qualified_callable_hierarchy_replay(language: Language) -> bool {
    matches!(language, Language::Kotlin)
}

/// Whether an explicit import outranks a package-scope declaration of the same name.
///
/// Kotlin ranks an explicit import above every declaration in the current
/// package, including a declaration in the same file. Those declarations are
/// package members, so their package-scope binders take the package tier. Scala
/// ranks same-unit definitions above explicit imports, and Java rejects a
/// single-type import that clashes with a same-unit top-level type, so both keep
/// the lexical rank.
pub(crate) const fn language_explicit_imports_outrank_package_binders(language: Language) -> bool {
    matches!(language, Language::Kotlin)
}

/// Whether an unqualified call in a class body can select a companion member.
pub(crate) const fn language_uses_enclosing_companion_members(language: Language) -> bool {
    matches!(language, Language::Kotlin)
}

/// Whether a type-object qualifier also searches its companion object's
/// members, as in `Host.respond()` for `class Host { companion object { fun
/// respond() } }`. The qualifier's own hierarchy does not contain that member,
/// so the companion joins the hierarchy roots. Only Kotlin is wired.
pub(crate) const fn language_type_qualifiers_search_companion_members(language: Language) -> bool {
    matches!(language, Language::Kotlin)
}

/// Whether a Callable declaration also occupies the Value namespace.
///
/// Scala's term namespace holds vals, vars, objects and defs, so a bare
/// `ready` that names a `def ready: Boolean` is a term reference, while the
/// def itself is a Callable declaration that a Value lookup never meets.
/// Publishing the def in both namespaces keeps one lookup symbol per
/// reference, which the hierarchy replay requires, and lets the scope
/// precedence of the nearer declaration decide between a def and a val of the
/// same name. Java, Kotlin and Go keep fields and methods in separate
/// namespaces, and Rust files its functions under Value already.
#[doc(hidden)]
pub const fn language_callables_occupy_value_namespace(language: Language) -> bool {
    matches!(language, Language::Scala)
}

/// Additional member kinds which can carry a value-namespace binding. The
/// hierarchy still requires a balanced lexical path in that namespace;
/// admitting a kind never invents an alias for a class declaration.
pub(crate) const fn language_value_member_aliases(
    language: Language,
) -> &'static [ResolutionMemberKind] {
    match language {
        Language::Scala => &[ResolutionMemberKind::NestedType],
        _ => &[],
    }
}

/// Scala import owner steps can bind a singleton term and continue in its
/// proven module type. Other JVM languages keep type-only owner steps.
pub(crate) const fn language_import_owner_steps_bind_singletons(language: Language) -> bool {
    matches!(language, Language::Scala)
}

/// Instance-method proof for override selection. Scala's module methods use
/// type-access metadata for singleton access but belong to the module instance.
/// Java static hiding is supplied separately by its language hook.
pub(crate) fn language_method_is_instance_for_override(
    language: Language,
    access: Option<ResolutionMemberAccess>,
    owner: Option<&JavaInheritanceDeclarationKind>,
) -> Option<bool> {
    match access {
        Some(ResolutionMemberAccess::Instance) => Some(true),
        Some(ResolutionMemberAccess::Type) if language == Language::Scala => match owner {
            Some(JavaInheritanceDeclarationKind::Type { is_singleton, .. }) => Some(*is_singleton),
            _ => None,
        },
        Some(_) => Some(false),
        None => None,
    }
}

/// Exact selection alone does not close Scala ancestors. Its bounded hierarchy
/// must already be sealed before a resolved edge placeholder can be discharged.
/// Other languages retain their existing exact-call dominance theorem.
pub(crate) const fn language_exact_call_closes_ancestor_frontier(language: Language) -> bool {
    !matches!(language, Language::Scala)
}

/// Applied singleton members include indexed parents in Scala. Kotlin's
/// result `invoke` lookup retains its declared-member contract.
pub(crate) const fn language_applied_members_search_hierarchy(language: Language) -> bool {
    matches!(language, Language::Scala)
}

/// Whether a JVM query requires the selected source package to match the file's
/// directory in a manifest-free project. Scala packages are declared by package
/// clauses (SLS 9.2), including package objects and successive package clauses.
/// Kotlin likewise takes membership from its package declaration rather than its
/// source directory. Keep Java and foreign-language admission rules unchanged.
pub(crate) fn language_jvm_package_requires_directory_agreement(
    query_language: Language,
    source_language: Language,
) -> bool {
    !crate::analyzer::store::resolution_operation::nominal_rules::nominal_language_rules(
        query_language,
    )
    .is_some_and(|rules| rules.lexical_package_languages().contains(&source_language))
}

/// The declared extractor members a language uses for this pattern-head role.
pub(crate) const fn language_extractor_member_names(
    language: Language,
    role: brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole,
) -> &'static [&'static str] {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole;
    match (language, role) {
        (Language::Scala, ResolutionInvocationRole::Unapply) => &["unapply", "unapplySeq"],
        (Language::Scala, ResolutionInvocationRole::UnapplySeq) => &["unapplySeq"],
        _ => &[],
    }
}

/// The member names that every type of a JVM language has through its implicit
/// root supertype, whether or not the type declares a supertype.
///
/// A type with no declared supertype still answers these names: Java's
/// `Object` members, Scala's `Any` and `AnyRef` members (`==`, `##`, `eq`,
/// `synchronized` and the like), and Kotlin's `Any` members. An import owner
/// that declares no supertype has a complete member set for every other name.
#[doc(hidden)]
pub const fn language_implicit_root_member_names(language: Language) -> &'static [&'static str] {
    match language {
        Language::Java => &[
            "getClass",
            "hashCode",
            "equals",
            "clone",
            "toString",
            "notify",
            "notifyAll",
            "wait",
            "finalize",
        ],
        Language::Kotlin => &["equals", "hashCode", "toString"],
        Language::Scala => &[
            "==",
            "!=",
            "equals",
            "hashCode",
            "toString",
            "##",
            "isInstanceOf",
            "asInstanceOf",
            "getClass",
            "eq",
            "ne",
            "synchronized",
            "wait",
            "notify",
            "notifyAll",
            "clone",
            "finalize",
        ],
        _ => &[],
    }
}

/// One source that supplies both lexical stitching and selected typed facts.
pub trait FactResolutionSource: BatchResolutionFragmentSource + SelectedTypedFactSource {}

impl<T> FactResolutionSource for T where
    T: BatchResolutionFragmentSource + SelectedTypedFactSource + ?Sized
{
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionFact, BindingProjectionKind, FileResolutionFacts,
        PositionedIdentifierFact, ResolutionBinderFact, ResolutionBinderKind,
        ResolutionConstructionRequirementFact, ResolutionDeclarationVisibilityFact,
        ResolutionGapFact, ResolutionGapKind, ResolutionIdentifierRole, ResolutionImportRouteFact,
        ResolutionImportRouteKind, ResolutionImportRouteSegmentFact, ResolutionMemberAccess,
        ResolutionMemberKind, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
        ResolutionNameFact, ResolutionNameId, ResolutionNamespace, ResolutionPackageFact,
        ResolutionPackageSegmentFact, ResolutionScopeFact, ResolutionScopeId, ResolutionScopeKind,
        ResolutionSiteFact, ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
        ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
        ResolutionTypeTransferKind,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};

    use super::*;
    use crate::analyzer::resolution::model::{
        ResolutionIncompleteReason, TypeTransferRule, TypeTransferValueTransform,
    };
    use crate::analyzer::resolution::test_support::{fragment, selected_transfer, semantic};

    #[test]
    fn transfer_stable_identity_is_distinct_from_directional_stream_order() {
        let owner = fragment("transfer-order-fragment");
        let mut rule_semantics = [semantic("transfer-rule-a"), semantic("transfer-rule-b")];
        rule_semantics.sort_unstable();
        let mut sources = [semantic("transfer-source-a"), semantic("transfer-source-b")];
        sources.sort_unstable();
        let mut targets = [semantic("transfer-target-a"), semantic("transfer-target-b")];
        targets.sort_unstable();
        assert_ne!(sources[0], targets[0]);
        assert_ne!(sources[1], targets[1]);

        let low_rule_high_access =
            selected_transfer(owner, rule_semantics[0], sources[1], targets[1]);
        let high_rule_low_access =
            selected_transfer(owner, rule_semantics[1], sources[0], targets[0]);

        let mut stable = vec![high_rule_low_access.clone(), low_rule_high_access.clone()];
        stable.sort_unstable_by_key(SelectedTypedRow::<LoweredTypeTransfer>::natural_identity);
        assert_eq!(
            stable
                .iter()
                .map(|row| row.row().rule().semantic())
                .collect::<Vec<_>>(),
            rule_semantics
        );

        let mut from_sources = vec![low_rule_high_access.clone(), high_rule_low_access.clone()];
        from_sources
            .sort_unstable_by_key(SelectedTypedRow::<LoweredTypeTransfer>::source_access_order);
        assert_eq!(
            from_sources
                .iter()
                .map(SelectedTypedRow::<LoweredTypeTransfer>::source_access_order)
                .collect::<Vec<_>>(),
            vec![
                (owner, sources[0], rule_semantics[1]),
                (owner, sources[1], rule_semantics[0]),
            ]
        );

        let mut to_targets = vec![low_rule_high_access, high_rule_low_access];
        to_targets
            .sort_unstable_by_key(SelectedTypedRow::<LoweredTypeTransfer>::target_access_order);
        assert_eq!(
            to_targets
                .iter()
                .map(SelectedTypedRow::<LoweredTypeTransfer>::target_access_order)
                .collect::<Vec<_>>(),
            vec![
                (owner, targets[0], rule_semantics[1]),
                (owner, targets[1], rule_semantics[0]),
            ]
        );
        assert_ne!(stable, from_sources);
        assert_ne!(stable, to_targets);
        assert_eq!(
            from_sources
                .iter()
                .map(SelectedTypedRow::<LoweredTypeTransfer>::natural_identity)
                .collect::<BTreeSet<_>>(),
            to_targets
                .iter()
                .map(SelectedTypedRow::<LoweredTypeTransfer>::natural_identity)
                .collect::<BTreeSet<_>>()
        );
    }
}

/// Array operand rules are selected only for producers that emit gate rows.
#[derive(Debug, Clone, Copy)]
pub(crate) enum JvmArrayOperandRules {
    Java,
}

impl JvmArrayOperandRules {
    pub(crate) fn index_type(self, kind: IntrinsicTypeKind, spelling: &str) -> bool {
        match self {
            Self::Java => {
                kind == IntrinsicTypeKind::Primitive
                    && matches!(spelling, "byte" | "short" | "char" | "int")
            }
        }
    }
    pub(crate) fn element<T: brokk_bifrost_jvm::java::conversion::JavaConversionTypes>(
        self,
        types: &mut T,
        source: T::Type,
        target: T::Type,
    ) -> std::result::Result<brokk_bifrost_jvm::java::conversion::JavaConversion, T::Error> {
        match self {
            Self::Java => brokk_bifrost_jvm::java::conversion::classify(types, source, target),
        }
    }
}

pub(crate) fn language_jvm_array_operand_rules(language: Language) -> Option<JvmArrayOperandRules> {
    match language {
        Language::Java => Some(JvmArrayOperandRules::Java),
        _ => None,
    }
}
