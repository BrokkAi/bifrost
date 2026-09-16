//! Storage-neutral reads over selected immutable resolution facts.
//!
//! The source contracts deliberately expose bounded, selected-context reads
//! instead of fragment hydrators: a persistent implementation must join every
//! query through one sealed selection, while preload implementations present
//! the same normalized rows from immutable in-memory artifacts.

use std::hash::Hash;

use brokk_bifrost_core::analyzer::resolution_facts::{
    DeclarationTypeRole, ResolutionConstructionRequirementKind, ResolutionMemberAccess,
    ResolutionMemberKind, ResolutionMemberQualifierCompatibility, ResolutionSiteId,
    ResolutionSupertypeKind,
};

use crate::CancellationToken;
use crate::analyzer::store::Result as StoreResult;
use crate::hash::HashSet;

use super::batch::BatchResolutionFragmentSource;
use super::coverage::LoweringGapOrigin;
use super::model::{BindingFragmentId, BindingNodeId, ResolutionCompletion, SemanticId};
use super::typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDefinitionPropertyGap, LoweredIntrinsicSeed,
    LoweredMemberOwnerProperty, LoweredMemberScopeProperty, LoweredQualifiedSeededRoute,
    LoweredSupertypeProperty, LoweredTypeTransfer, LoweredTypedFrontier,
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
    maximum_rows: usize,
    stopped: bool,
}

/// Storage-neutral page visitor shared by typed and Java placement sources.
pub type FactPageVisitor<'a, T> = TypedFactPageVisitor<'a, T>;

impl<'a, T> TypedFactPageVisitor<'a, T> {
    pub fn new(callback: &'a mut dyn FnMut(&[T]) -> StoreResult<bool>) -> Self {
        Self::with_maximum_rows(callback, MAX_TYPED_FACT_ROWS_PER_PAGE)
    }

    pub(crate) fn with_maximum_rows(
        callback: &'a mut dyn FnMut(&[T]) -> StoreResult<bool>,
        maximum_rows: usize,
    ) -> Self {
        assert!((1..=MAX_TYPED_FACT_ROWS_PER_PAGE).contains(&maximum_rows));
        Self {
            callback,
            maximum_rows,
            stopped: false,
        }
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

/// One typed parent row together with its exact selected fragment owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedTypedRow<T> {
    fragment: BindingFragmentId,
    row: T,
}

/// One selected fact row together with its exact fragment owner.
///
/// Typed callers retain the historical [`SelectedTypedRow`] spelling. New
/// source families use this alias to make the shared ownership boundary
/// explicit without creating another wrapper protocol.
pub type SelectedFactRow<T> = SelectedTypedRow<T>;

impl<T> SelectedTypedRow<T> {
    pub const fn new(fragment: BindingFragmentId, row: T) -> Self {
        Self { fragment, row }
    }

    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn row(&self) -> &T {
        &self.row
    }

    pub fn into_parts(self) -> (BindingFragmentId, T) {
        (self.fragment, self.row)
    }
}

impl SelectedTypedRow<LoweredTypedFrontier> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.slot())
    }
}

impl SelectedTypedRow<LoweredTypeTransfer> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.rule().semantic())
    }

    /// Query-planning key for source-slot access.
    ///
    /// This is not a page-order contract: a selected source may use any
    /// deterministic duplicate-free storage cursor.
    pub const fn source_access_order(&self) -> (BindingFragmentId, SemanticId, SemanticId) {
        (
            self.fragment,
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
            self.fragment,
            self.row.rule().target_slot(),
            self.row.rule().semantic(),
        )
    }
}

impl SelectedTypedRow<LoweredIntrinsicSeed> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.frontier().slot())
    }
}

impl SelectedTypedRow<LoweredBindingProjection> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.reference())
    }
}

impl SelectedTypedRow<LoweredDeclarationTypeProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId, DeclarationTypeRole) {
        (self.fragment, self.row.definition(), self.row.role())
    }
}

impl SelectedTypedRow<LoweredDeclarationVisibilityProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.definition())
    }
}

impl SelectedTypedRow<LoweredMemberScopeProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.definition())
    }
}

impl SelectedTypedRow<LoweredMemberOwnerProperty> {
    pub const fn natural_identity(
        &self,
    ) -> (
        BindingFragmentId,
        SemanticId,
        SemanticId,
        BindingNodeId,
        ResolutionMemberKind,
        ResolutionMemberAccess,
        ResolutionMemberQualifierCompatibility,
    ) {
        (
            self.fragment,
            self.row.definition(),
            self.row.owner_definition(),
            self.row.owner_scope_head(),
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
            self.fragment,
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
        BindingFragmentId,
        SemanticId,
        ResolutionSupertypeKind,
        SemanticId,
        SemanticId,
    ) {
        (
            self.fragment,
            self.row.definition(),
            self.row.kind(),
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
            self.fragment,
            self.row.definition(),
            self.row.reason_semantic(),
            self.row.frontier(),
        )
    }
}

impl SelectedTypedRow<LoweredCallApplicabilityObligation> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.call())
    }
}

impl SelectedTypedRow<LoweredCallableSignatureProperty> {
    pub const fn natural_identity(&self) -> (BindingFragmentId, SemanticId) {
        (self.fragment, self.row.definition())
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
        }
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

    /// The exact persisted route key: `(fragment, reference, precedence)`.
    pub const fn natural_identity(self) -> (BindingFragmentId, SemanticId, u32) {
        (
            self.fragment,
            self.row.reference(),
            self.row.precedence_ordinal(),
        )
    }

    pub const fn into_parts(
        self,
    ) -> (
        BindingFragmentId,
        BindingNodeId,
        LoweredQualifiedSeededRoute,
    ) {
        (self.fragment, self.reference_node, self.row)
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
        (self.fragment, self.reason)
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
        (self.fragment, self.frontier)
    }

    pub fn into_parts(self) -> (BindingFragmentId, SemanticId, ResolutionCompletion) {
        (self.fragment, self.frontier, self.completion)
    }
}

/// Composite key used by exact qualified-route candidate discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualifiedRouteSlotLookup {
    qualifier_slot: SemanticId,
    lookup: SemanticId,
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
/// read retains the semantic evidence decoded or accumulated before stopping;
/// a cancelled read retains that evidence unchanged and wins over a simultaneous
/// visitor stop. Decoded or buffered rows can precede callback delivery, so
/// evidence is not necessarily limited to callback-emitted rows. Neither
/// terminal establishes absence in an unread suffix, even with Complete
/// evidence. Exhausted establishes enumeration absence, while row-local
/// completions still participate in semantic answers. The separate reverse
/// inventory read returns its exact selection-wide completion on Exhausted.
///
/// The separate directions and inventories below are intentional indexed
/// access shapes. Implementations must not satisfy them with per-identity
/// point reads or by hydrating every selected fragment first.
pub trait SelectedTypedFactSource {
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

    fn visit_typed_frontier_pages(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
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

    fn visit_member_scope_pages_for_heads(
        &self,
        heads: TypedFactRequest<'_, BindingNodeId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_member_scope_inventory_pages(
        &self,
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

    fn visit_callable_signature_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome>;

    fn visit_gap_reason_provenance_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
    ) -> StoreResult<TypedFactReadOutcome>;
}

/// One source that supplies both lexical stitching and selected typed facts.
pub trait FactResolutionSource: BatchResolutionFragmentSource + SelectedTypedFactSource {}

impl<T> FactResolutionSource for T where
    T: BatchResolutionFragmentSource + SelectedTypedFactSource + ?Sized
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::model::{
        ResolutionIncompleteReason, TypeTransferRule, TypeTransferValueTransform,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionKind, ResolutionNamespace, ResolutionTypeTransferKind,
    };
    use std::collections::BTreeSet;

    fn fragment(name: &str) -> BindingFragmentId {
        BindingFragmentId::hash_bytes(name)
    }

    fn semantic(name: &str) -> SemanticId {
        SemanticId::hash_bytes(name)
    }

    fn selected_transfer(
        owner: BindingFragmentId,
        rule_semantic: SemanticId,
        source_slot: SemanticId,
        target_slot: SemanticId,
    ) -> SelectedTypedRow<LoweredTypeTransfer> {
        SelectedTypedRow::new(
            owner,
            LoweredTypeTransfer::new(
                source_slot,
                ResolutionTypeTransferKind::Assignment,
                TypeTransferRule::new(
                    rule_semantic,
                    target_slot,
                    0,
                    TypeTransferValueTransform::Preserve,
                    ResolutionCompletion::Complete,
                ),
            ),
        )
    }

    #[test]
    fn request_and_page_boundaries_accept_the_general_empty_and_maximum_cases() {
        let empty = TypedFactRequest::<u16>::new(&[]);
        assert!(empty.is_empty());

        let identities = (0..MAX_TYPED_FACT_REQUESTS_PER_BATCH)
            .map(|identity| u16::try_from(identity).expect("request bound fits u16"))
            .collect::<Vec<_>>();
        let maximum = TypedFactRequest::new(&identities);
        assert_eq!(maximum.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH);

        let rows = vec![0_u8; MAX_TYPED_FACT_ROWS_PER_PAGE];
        let mut visited = 0_usize;
        let mut callback = |page: &[u8]| {
            visited += page.len();
            Ok(true)
        };
        {
            let mut visitor = TypedFactPageVisitor::new(&mut callback);
            assert!(
                visitor
                    .visit_page(&rows)
                    .expect("test visitor is infallible")
            );
            assert!(!visitor.stopped());
        }
        assert_eq!(visited, MAX_TYPED_FACT_ROWS_PER_PAGE);
    }

    #[test]
    #[should_panic(expected = "typed-fact request identities must be unique")]
    fn request_boundary_rejects_duplicate_identities() {
        let _ = TypedFactRequest::new(&[1_u8, 1_u8]);
    }

    #[test]
    #[should_panic(expected = "typed-fact pages must not be empty")]
    fn page_boundary_rejects_empty_pages() {
        let mut callback = |_page: &[u8]| Ok(true);
        let mut visitor = TypedFactPageVisitor::new(&mut callback);
        let _ = visitor.visit_page(&[]);
    }

    #[test]
    fn source_returned_cancellation_is_exact_and_moves_prior_evidence_unchanged() {
        let prior = ResolutionIncompleteReason::UnsupportedSemantic(semantic("prior-gap"));
        let evidence = ResolutionCompletion::incomplete([prior]);
        let outcome = TypedFactReadOutcome::cancelled(evidence.clone());

        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Cancelled);
        assert!(outcome.is_cancelled());
        assert_eq!(outcome.evidence(), &evidence);
    }

    #[test]
    fn every_terminal_moves_semantic_evidence_unchanged() {
        let evidence =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                semantic("terminal-gap"),
            )]);
        for outcome in [
            TypedFactReadOutcome::exhausted(evidence.clone()),
            TypedFactReadOutcome::stopped(evidence.clone()),
            TypedFactReadOutcome::cancelled(evidence.clone()),
        ] {
            assert_eq!(outcome.evidence(), &evidence);
        }
    }

    #[test]
    fn qualified_route_identity_and_selected_reference_node_are_exact() {
        let fragment = fragment("qualified-route-fragment");
        let reference = semantic("qualified-route-reference");
        let reference_node = BindingNodeId::in_fragment(fragment, b"reference-node");
        let row = LoweredQualifiedSeededRoute::new(
            reference,
            semantic("qualifier-slot"),
            semantic("lookup"),
            ResolutionNamespace::Value,
            7,
            semantic("projection-output"),
            BindingProjectionKind::TargetDeclaredValueType,
            semantic("coarse-gap"),
        );
        let selected = SelectedQualifiedRoute::new(fragment, reference_node, row);

        assert_eq!(selected.natural_identity(), (fragment, reference, 7));
        assert_eq!(selected.reference_node(), reference_node);
    }

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

    #[test]
    fn selected_source_traits_are_object_safe() {
        let typed: Option<&dyn SelectedTypedFactSource> = None;
        let composite: Option<&dyn FactResolutionSource> = None;
        assert!(typed.is_none());
        assert!(composite.is_none());
    }
    #[test]
    fn stopped_complete_evidence_does_not_prove_exhaustion() {
        let outcome = TypedFactReadOutcome::stopped(ResolutionCompletion::Complete);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);
        assert!(!outcome.is_exhausted());
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Stopped);
    }
}
