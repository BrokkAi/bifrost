//! Operation-local context shared by language-specific selected placement.
//!
//! Content lowering owns the two fragment-local halves of a root route. This
//! module owns only the exact selected-context bridge between them. Keeping
//! the canonical route in the symbol stack makes a bridge self-describing to
//! forward and reverse stitching; no caller provenance is attached to a batch
//! candidate request.

mod go_import;
mod package;
pub(crate) use go_import::SelectedGoImportBindingDescriptor;
pub(crate) use package::SelectedPackageBridgeDescriptor;

use std::collections::BTreeSet;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionNamespace, ResolutionRootImportAnchor, ResolutionScopeId, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::hash::HashMap;

use super::batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateRequest,
    BatchResolutionFragmentSource, CandidatePathIdentity, ReverseCandidateGapIdentity,
};
#[cfg(test)]
use super::fact_lowering::root_reference_token;
use super::fact_lowering::{
    root_export_token, root_import_anchor_semantic, root_import_anchor_semantic_identity,
    root_import_token, scope_head_node,
};
use super::fact_source::{FactPageVisitor, FactReadOutcome, SelectedDeclarationAccessSource};
use super::local_identity::{
    ResolutionLookupSemanticRecipe, ResolutionSemanticIdentity, SelectedResolutionMountOrdinal,
    SharedNameInterner,
};
use super::model::{
    BindingFragmentId, BindingNodeId, EndpointSignature, PartialPath, PartialPathId,
    PartialScopedSymbol, PrecedenceStep, ResolutionCompletion, ResolutionIncompleteReason,
    SemanticId, StackPattern, StackVariableId, WitnessStep,
};

/// An immutable context owned by one selected request's private SQL rows.
/// Only the store allocator creates tokens; they never enter cached answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SelectedContextPathToken(i64);

impl SelectedContextPathToken {
    pub(crate) fn new(value: i64) -> Self {
        assert!(
            value > 0,
            "context token comes from a positive SQL row identity"
        );
        Self(value)
    }

    pub(crate) const fn get(self) -> i64 {
        self.0
    }
}

/// Read one explicitly selected context's paths without reopening base facts.
/// Context rows live until request teardown and never imply global visibility.
pub(crate) trait SelectedContextPathSource {
    /// Preserve supplied base coverage, extending it with Cancelled only when
    /// cancellation or the existing per-offered-row session budget stops work.
    /// A budget stop drops a pending page, matching the context adapter contract.
    /// Path-specific completion remains in the hydrated path body. Pages are
    /// ordered by request ordinal and candidate identity and contain no repeats.
    #[allow(clippy::too_many_arguments)]
    fn visit_context_forward_additions(
        &self,
        context: SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome>;

    /// Reverse additions obey the same coverage, page and stop contract.
    #[allow(clippy::too_many_arguments)]
    fn visit_context_reverse_additions(
        &self,
        context: SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome>;

    /// One query-owned relation for closure validation and publication. None
    /// means cancellation, so no partial relation reaches ClosedRelations.
    fn context_paths(
        &self,
        context: SelectedContextPathToken,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(CandidatePathIdentity, PartialPath)>>>;

    /// Seek only requested identities within this token. Missing keys are
    /// omitted; returned identities are unique and belong to the request.
    /// None means cancellation. A base/context collision is an error at the
    /// caller, never permission to suppress a base candidate.
    fn hydrate_context_paths(
        &self,
        context: SelectedContextPathToken,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(CandidatePathIdentity, PartialPath)>>>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SelectedRootPathHalf {
    Import {
        identity: CandidatePathIdentity,
        source_scope_head: BindingNodeId,
        route: Box<[SemanticId]>,
        /// Structural anchor from the source-owned root import.
        /// The common lowerer supplies this typed fact; keeping it in the
        /// selected half prevents bare and absolute routes from colliding.
        anchor: ResolutionRootImportAnchor,
        /// The route's first symbol, which is the anchor as its own blob
        /// mounted it. A bridge compiled out of this half starts with exactly
        /// this symbol, so the two meet without either recomputing it.
        anchor_semantic: SemanticId,
        token: SemanticId,
        demand: SemanticId,
    },
    Export {
        identity: CandidatePathIdentity,
        demand: SemanticId,
        token: SemanticId,
        definition: BindingNodeId,
        /// Canonical source-owned evidence retained by exact export bridges.
        incomplete_reasons: Box<[ResolutionIncompleteReason]>,
    },
    Reference {
        identity: CandidatePathIdentity,
        source_reference: BindingNodeId,
        source_scope_head: BindingNodeId,
        /// Bare Rust routes carry the lexical scope in which their first Type
        /// segment must be resolved before selected continuation.
        lexical_scope_head: Option<BindingNodeId>,
        /// Canonical semantic of the positioned first-segment reference.
        /// Explicit anchored routes have no lexical prefix reference.
        prefix_reference: Option<SemanticId>,
        route: Box<[SemanticId]>,
        anchor: ResolutionRootImportAnchor,
        /// See [`SelectedRootPathHalf::Import::anchor_semantic`].
        anchor_semantic: SemanticId,
        token: SemanticId,
        demand: SemanticId,
    },
}

/// Which root-import anchor one selected semantic is, if it is one.
///
/// A root route's first symbol is its anchor: `lexical` or `absolute`. It is
/// a fragment-local identity of the blob that published the route, so it used
/// to be recomputable -- `root_import_anchor_semantic(fragment, anchor)` was a
/// pure function of the two. A fragment-local id is that blob's catalog
/// position now, so only the blob can say which of the two its first symbol
/// is, and this is the one question
/// [`classify_selected_root_path_half`] asks of its caller.
pub(crate) trait SelectedRootImportAnchors {
    fn anchor_of(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionRootImportAnchor>>;
}

/// The root-import anchors of one lowered artifact, answered from its own
/// identity catalog.
///
/// A lowered artifact's ids are its catalog's positions, so the catalog says
/// directly which identity a semantic is, and this compares that against the
/// two anchor identities. It is what a caller holding an artifact uses where
/// the store's caller uses the selected source.
pub(crate) struct CatalogRootImportAnchors<'catalog> {
    catalog: &'catalog super::local_identity::ResolutionIdentityCatalog,
}

impl<'catalog> CatalogRootImportAnchors<'catalog> {
    pub(crate) const fn new(
        catalog: &'catalog super::local_identity::ResolutionIdentityCatalog,
    ) -> Self {
        Self { catalog }
    }
}

impl SelectedRootImportAnchors for CatalogRootImportAnchors<'_> {
    fn anchor_of(
        &self,
        semantic: SemanticId,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionRootImportAnchor>> {
        let Some((_, identity)) = self.catalog.semantic_coordinate(semantic) else {
            return Ok(None);
        };
        Ok([
            ResolutionRootImportAnchor::Lexical,
            ResolutionRootImportAnchor::Absolute,
        ]
        .into_iter()
        .find(|anchor| root_import_anchor_semantic_identity(*anchor) == identity))
    }
}

pub(crate) fn classify_selected_root_path_half(
    anchors: &dyn SelectedRootImportAnchors,
    identity: CandidatePathIdentity,
    path: &PartialPath,
    cancellation: &CancellationToken,
) -> StoreResult<Option<SelectedRootPathHalf>> {
    // A reference half is the source-side evidence needed to continue a
    // native bare prefix.  It can remain structurally useful when the
    // callee has an unrelated source gap (for example unsupported call
    // applicability), so do not discard it solely because its completion is
    // incomplete.  Cancellation is different: it means that this path was
    // not actually evaluated and must never be published as evidence.
    if path
        .completion()
        .contains_reason(ResolutionIncompleteReason::Cancelled)
        || !endpoint_has_empty_scopes(path.start())
        || !endpoint_has_empty_scopes(path.end())
        || path.start().symbols().tail() != path.end().symbols().tail()
        || path
            .start()
            .symbols()
            .fixed()
            .iter()
            .chain(path.end().symbols().fixed())
            .any(|symbol| symbol.scopes().is_some())
    {
        return Ok(None);
    }
    let root = BindingNodeId::universal_root();
    if path.end().node() == root && path.start().symbols().tail().is_some() {
        let start = path.start().symbols().fixed();
        let end = path.end().symbols().fixed();
        if path.completion() != &ResolutionCompletion::Complete
            || path.start().node() == root
            || start.len() != 1
            // An Import half spells anchor, route segments, target token and
            // demand. A single-segment `use serde as s;` names the path root
            // itself, so its route is empty and three symbols are the whole
            // stack; four was the shortest stack a route segment allowed.
            || end.len() < 3
            || start[0].symbol() != end[end.len() - 1].symbol()
            // A Rust import ranks on its scope choice with the outward
            // continuation and then on its scope's import choice
            // (`root_import_precedence`); Java single imports use the explicit
            // tier and on-demand imports use the wildcard tier. Go file
            // imports share rank zero with file spelling binders; the catalog
            // anchor and exact stack/witness shape still establish an import.
            || !matches!(path.precedence(), [step, ..]
                if (step.tier, step.ordinal) == (PrecedenceTier::WildcardImport, 0)
                    || (step.tier, step.ordinal) == (PrecedenceTier::ExplicitImport, 0)
                    || (step.tier == PrecedenceTier::LexicalBinding && step.ordinal <= 1))
            || path.witness() != [WitnessStep::Node(root)]
        {
            return Ok(None);
        }
        let anchor_semantic = end[0].symbol();
        let Some(anchor) = anchors.anchor_of(anchor_semantic, cancellation)? else {
            return Ok(None);
        };
        return Ok(Some(SelectedRootPathHalf::Import {
            identity,
            source_scope_head: path.start().node(),
            route: end[1..end.len() - 2]
                .iter()
                .map(PartialScopedSymbol::symbol)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            anchor,
            anchor_semantic,
            token: end[end.len() - 2].symbol(),
            demand: end[end.len() - 1].symbol(),
        }));
    }
    if path.end().node() == root {
        let start = path.start().symbols().fixed();
        let end = path.end().symbols().fixed();
        let (lexical_scope_head, source_scope_head) = match path.witness() {
            [
                WitnessStep::Node(source_scope_head),
                WitnessStep::Node(witness_root),
            ] if *witness_root == root => (None, *source_scope_head),
            [
                WitnessStep::Node(lexical_scope_head),
                WitnessStep::Node(source_scope_head),
                WitnessStep::Node(witness_root),
            ] if *witness_root == root => (Some(*lexical_scope_head), *source_scope_head),
            _ => return Ok(None),
        };
        if path.start().node() == root
            || path.start().symbols().tail().is_some()
            || !start.is_empty()
            || end.len() < 3
            || !matches!(path.precedence(), [step]
                if step.tier == PrecedenceTier::PackageOrModule && step.ordinal <= 1)
        {
            return Ok(None);
        }
        let anchor_semantic = end[0].symbol();
        let Some(anchor) = anchors.anchor_of(anchor_semantic, cancellation)? else {
            return Ok(None);
        };
        let (prefix_reference, route_start) = if lexical_scope_head.is_some() {
            if end.len() < 4 {
                return Ok(None);
            }
            (Some(end[1].symbol()), 2)
        } else {
            (None, 1)
        };
        return Ok(Some(SelectedRootPathHalf::Reference {
            identity,
            source_reference: path.start().node(),
            source_scope_head,
            lexical_scope_head,
            prefix_reference,
            route: end[route_start..end.len() - 2]
                .iter()
                .map(PartialScopedSymbol::symbol)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            anchor,
            anchor_semantic,
            token: end[end.len() - 2].symbol(),
            demand: end[end.len() - 1].symbol(),
        }));
    }
    if path.start().node() == root {
        let start = path.start().symbols().fixed();
        if start.len() != 2
            || path.start().symbols().tail().is_none()
            || !path.end().symbols().fixed().is_empty()
            || !matches!(path.precedence(), [step]
                if step.tier == PrecedenceTier::PackageOrModule && step.ordinal == 0)
            || path.witness() != [WitnessStep::Node(path.end().node())]
        {
            return Ok(None);
        }
        return Ok(Some(SelectedRootPathHalf::Export {
            identity,
            demand: start[0].symbol(),
            token: start[1].symbol(),
            definition: path.end().node(),
            incomplete_reasons: match path.completion() {
                ResolutionCompletion::Complete => Box::new([]),
                ResolutionCompletion::Incomplete(reasons) => reasons.iter().copied().collect(),
            },
        }));
    }
    Ok(None)
}

fn endpoint_has_empty_scopes(endpoint: &EndpointSignature) -> bool {
    endpoint.scopes().fixed().is_empty() && endpoint.scopes().tail().is_none()
}

/// Read the root import and reference halves owned by `mounts`, or by the
/// whole selection when `mounts` is `None`.
///
/// A root half belongs to exactly one mount, and a caller always knows which
/// mounts its request can use: an import or reference half only ever compiles
/// a bridge out of the file that owns it. Naming those mounts turns the root
/// inventory from a scan of the whole selection into one probe per named
/// mount, which is what keeps a point request's rows bounded by its endpoint
/// instead of by the workspace. A source that keeps its fragments in memory
/// has nothing to seek and returns all of them; such a caller keeps the halves
/// its own scope admits, and says so with `None` rather than by building a
/// vector of every selected ordinal.
pub(crate) fn visit_selected_root_import_half_pages<S>(
    context_identities: &SelectedContextIdentities,
    anchors: &dyn SelectedRootImportAnchors,
    source: &S,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    cancellation: &CancellationToken,
    visitor: &mut FactPageVisitor<'_, SelectedRootPathHalf>,
) -> StoreResult<FactReadOutcome>
where
    S: BatchResolutionFragmentSource + ?Sized,
{
    let request =
        selected_root_inventory_request(context_identities, b"selected-root-import-inventory");
    visit_selected_root_path_half_pages(
        anchors,
        source,
        request,
        mounts,
        cancellation,
        visitor,
        |source, requests, mounts, cancellation, callback| {
            source.visit_reverse_root_candidate_match_pages(
                requests,
                mounts,
                cancellation,
                callback,
            )
        },
        |half| {
            matches!(
                half,
                SelectedRootPathHalf::Import { .. } | SelectedRootPathHalf::Reference { .. }
            )
        },
    )
}

/// Read the root export halves owned by `mounts`, bounded exactly as
/// [`visit_selected_root_import_half_pages`] is, and reading the whole
/// selection on the same `None`.
pub(crate) fn visit_selected_root_export_half_pages<S>(
    context_identities: &SelectedContextIdentities,
    anchors: &dyn SelectedRootImportAnchors,
    source: &S,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    cancellation: &CancellationToken,
    visitor: &mut FactPageVisitor<'_, SelectedRootPathHalf>,
) -> StoreResult<FactReadOutcome>
where
    S: BatchResolutionFragmentSource + ?Sized,
{
    let request =
        selected_root_inventory_request(context_identities, b"selected-root-export-inventory");
    visit_selected_root_path_half_pages(
        anchors,
        source,
        request,
        mounts,
        cancellation,
        visitor,
        |source, requests, mounts, cancellation, callback| {
            source.visit_forward_root_candidate_match_pages(
                requests,
                mounts,
                cancellation,
                callback,
            )
        },
        |half| matches!(half, SelectedRootPathHalf::Export { .. }),
    )
}

fn selected_root_inventory_request(
    identities: &SelectedContextIdentities,
    domain: &[u8],
) -> BatchCandidateRequest {
    let mut hasher = CanonicalHasher::new(b"bifrost-selected-root-inventory-domain:v1");
    hasher.field("domain", domain);
    BatchCandidateRequest::new(
        0,
        EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::open(Vec::new(), identities.stack_variable(hasher.finish())),
            StackPattern::closed(Vec::new()),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn visit_selected_root_path_half_pages<S, M, F>(
    anchors: &dyn SelectedRootImportAnchors,
    source: &S,
    request: BatchCandidateRequest,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    cancellation: &CancellationToken,
    visitor: &mut FactPageVisitor<'_, SelectedRootPathHalf>,
    visit_matches: M,
    accepts: F,
) -> StoreResult<FactReadOutcome>
where
    S: BatchResolutionFragmentSource + ?Sized,
    M: FnOnce(
        &S,
        &[BatchCandidateRequest],
        Option<&[SelectedResolutionMountOrdinal]>,
        &CancellationToken,
        &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<super::batch::BatchCandidateCompletionOutcome>,
    F: Fn(&SelectedRootPathHalf) -> bool,
{
    let mut stopped = false;
    let mut callback = |matches: &[BatchCandidateMatch]| {
        let identities = matches
            .iter()
            .map(|matched| matched.candidate())
            .collect::<Vec<_>>();
        let hydrated = source.hydrate_candidate_paths(&identities, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        if hydrated.len() != identities.len() {
            return Err(StoreError::new(format!(
                "selected root inventory hydration mismatch: requested {identities:?}, returned {:?}",
                hydrated
                    .iter()
                    .map(|(identity, _)| *identity)
                    .collect::<Vec<_>>()
            )));
        }
        let mut halves = Vec::with_capacity(hydrated.len());
        for (identity, path) in hydrated {
            let Some(half) =
                classify_selected_root_path_half(anchors, identity, &path, cancellation)?
            else {
                continue;
            };
            if accepts(&half) {
                halves.push(half);
            }
        }
        if halves.is_empty() {
            return Ok(true);
        }
        let keep_going = visitor.visit_page(&halves)?;
        stopped = !keep_going;
        Ok(keep_going)
    };
    let completion = visit_matches(
        source,
        std::slice::from_ref(&request),
        mounts,
        cancellation,
        &mut callback,
    )?;
    let evidence = completion
        .unconditional_completion()
        .combine(&completion.branch_completions()[0]);
    if cancellation.is_cancelled()
        || evidence.contains_reason(ResolutionIncompleteReason::Cancelled)
    {
        Ok(FactReadOutcome::cancelled(evidence))
    } else if stopped || visitor.stopped() {
        Ok(FactReadOutcome::stopped(evidence))
    } else {
        Ok(FactReadOutcome::exhausted(evidence))
    }
}

/// Context supplied for one exact post-open selected mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedResolutionMountContext {
    ordinal: SelectedResolutionMountOrdinal,
    fragment: BindingFragmentId,
    semantic_language: Language,
    root_bridges: Box<[SelectedRootBridgeDescriptor]>,
    package_bridges: Box<[SelectedPackageBridgeDescriptor]>,
    go_import_bindings: Box<[SelectedGoImportBindingDescriptor]>,
    root_reverse_inventory_completion: ResolutionCompletion,
}

impl SelectedResolutionMountContext {
    pub(crate) fn new(
        ordinal: SelectedResolutionMountOrdinal,
        fragment: BindingFragmentId,
        semantic_language: Language,
        root_bridges: impl Into<Box<[SelectedRootBridgeDescriptor]>>,
        root_reverse_inventory_completion: ResolutionCompletion,
    ) -> StoreResult<Self> {
        if semantic_language == Language::None {
            return Err(StoreError::new(
                "a selected resolution mount context needs a semantic language",
            ));
        }
        if root_reverse_inventory_completion.contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Err(StoreError::new(
                "selected root inventory completion contains operation cancellation",
            ));
        }
        let root_bridges = root_bridges.into();
        for bridge in &root_bridges {
            if bridge.source_fragment() != fragment || bridge.source_language() != semantic_language
            {
                return Err(StoreError::new(
                    "selected root bridge is not owned by its source mount context",
                ));
            }
        }
        Ok(Self {
            ordinal,
            fragment,
            semantic_language,
            root_bridges,
            package_bridges: Box::new([]),
            go_import_bindings: Box::new([]),
            root_reverse_inventory_completion,
        })
    }

    pub(crate) fn with_package_bridges(
        mut self,
        bridges: Vec<SelectedPackageBridgeDescriptor>,
    ) -> StoreResult<Self> {
        for bridge in &bridges {
            if bridge.source_fragment != self.fragment || bridge.language != self.semantic_language
            {
                return Err(StoreError::new(
                    "selected package bridge is not owned by its source mount context",
                ));
            }
        }
        assert!(
            self.package_bridges.is_empty(),
            "package bridges installed once"
        );
        self.package_bridges = bridges.into_boxed_slice();
        Ok(self)
    }

    pub(crate) fn with_go_import_bindings(
        mut self,
        bindings: Vec<SelectedGoImportBindingDescriptor>,
    ) -> StoreResult<Self> {
        if bindings
            .iter()
            .any(|binding| binding.source_fragment != self.fragment)
            || (!bindings.is_empty() && self.semantic_language != Language::Go)
        {
            return Err(StoreError::new(
                "Go import binding is not owned by its selected Go mount",
            ));
        }
        assert!(
            self.go_import_bindings.is_empty(),
            "Go import bindings installed once"
        );
        self.go_import_bindings = bindings.into_boxed_slice();
        Ok(self)
    }

    pub(crate) const fn ordinal(&self) -> SelectedResolutionMountOrdinal {
        self.ordinal
    }

    pub(crate) const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub(crate) const fn semantic_language(&self) -> Language {
        self.semantic_language
    }
}

/// One selected operation's mount table, asked by fragment.
///
/// The context set is sparse, so it does not materialize the operation's mount
/// table. Coverage questions come here instead: the lookup answers with the
/// mount's ordinal and language for a selected fragment, and with `None` for a
/// fragment the operation did not select.
pub(crate) type SelectedMountLookup<'a> = dyn Fn(BindingFragmentId) -> StoreResult<Option<(SelectedResolutionMountOrdinal, Language)>>
    + 'a;

/// One number per distinct identity a selected context mints.
///
/// The context invents identities of its own: a root bridge's path and its
/// open tail, and the import anchor a bridge's route starts from. They belong
/// to no file, so they are the `Operation` kind, and they are content keys --
/// two compilations of one bridge have to agree, and
/// `classify_selected_root_path_half` recomputes an anchor to compare it --
/// so a counter alone will not do and this maps the structure's digest to its
/// number, the same shape `HierarchyOperationArena` uses for the operation's
/// own.
///
/// **It cannot share the operation's numbering.** A context is built before
/// any operation exists and a retained selection may attach one context to
/// several operations, so both counters start at zero and would give one
/// number to two different structures. The numbers here are offset by
/// [`CONTEXT_OPERATION_BASE`], which is bit 60 of the 61-bit payload, and
/// `SelectedResolutionContextSet::assert_identities_are_context_local` checks
/// at attachment that everything the context carries is in that half.
///
/// It lives as long as the context and is dropped with it, and it is bounded
/// by the bridges one context compiles.
///
/// The table is shared rather than copied. A context set is cloned by the
/// operations that narrow it, the overlay compilation and the blueprint hold
/// it too, and every holder has to hand out the *same* number for the same
/// structure or two compilations of one bridge stop meeting. That is one
/// value with several holders whose lifetimes are not nested, which is what
/// an `Arc` is for; the lock is taken once per identity minted, at context
/// compile time.
#[derive(Clone, Debug, Default)]
pub(crate) struct SelectedContextIdentities {
    numbers: Arc<std::sync::Mutex<crate::hash::HashMap<[u8; 32], u64>>>,
    /// The stable name and evidence of each named incompleteness reason this
    /// context minted, by identity number, so an answer carrying the reason
    /// can say what it is. Bounded like `numbers`: one entry per reason the
    /// context's routes minted.
    named_reasons: Arc<std::sync::Mutex<crate::hash::HashMap<u64, NamedReason>>>,
    /// Exact unqualified references whose selected crate routes fell through
    /// to a standard prelude item. A reference may be compiled by more than
    /// one selected Cargo target, so retain each selected prelude identity.
    rust_prelude_references:
        Arc<std::sync::Mutex<crate::hash::HashMap<SemanticId, Vec<SemanticId>>>>,
    /// Exact structured import paths that leave the workspace through an
    /// unindexed external type. Paths remain separate across cfg alternatives.
    rust_external_type_import_paths:
        Arc<std::sync::Mutex<crate::hash::HashMap<SemanticId, Vec<Vec<String>>>>>,
}

/// A named incompleteness reason's stable name and its evidence.
type NamedReason = (&'static str, Arc<str>);

impl SelectedContextIdentities {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn shares_identity_space(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.numbers, &other.numbers)
            && Arc::ptr_eq(&self.named_reasons, &other.named_reasons)
            && Arc::ptr_eq(
                &self.rust_prelude_references,
                &other.rust_prelude_references,
            )
            && Arc::ptr_eq(
                &self.rust_external_type_import_paths,
                &other.rust_external_type_import_paths,
            )
    }

    fn number(&self, digest: [u8; 32]) -> u64 {
        let mut numbers = self
            .numbers
            .lock()
            .expect("the selected context's identity table is not poisoned");
        let next = u64::try_from(numbers.len()).expect("a context's identity count fits u64");
        *numbers.entry(digest).or_insert(next)
    }

    pub(crate) fn semantic(&self, digest: [u8; 32]) -> SemanticId {
        SemanticId::context_local(self.number(digest))
    }

    pub(crate) fn path(&self, digest: [u8; 32]) -> PartialPathId {
        PartialPathId::context_local(self.number(digest))
    }

    /// Mint the identity of a named incompleteness reason and remember its
    /// name and evidence for [`Self::named_reason`].
    pub(crate) fn named_semantic(
        &self,
        digest: [u8; 32],
        name: &'static str,
        evidence: &str,
    ) -> SemanticId {
        let number = self.number(digest);
        self.named_reasons
            .lock()
            .expect("the selected context's named reasons are not poisoned")
            .entry(number)
            .or_insert_with(|| (name, Arc::from(evidence)));
        SemanticId::context_local(number)
    }

    /// The stable name and evidence of a reason this context minted with
    /// [`Self::named_semantic`], or `None` for any other identity.
    pub(crate) fn named_reason(&self, semantic: SemanticId) -> Option<NamedReason> {
        if !semantic.is_context_local() {
            return None;
        }
        let number = semantic.operation_local_number()? & !super::model::CONTEXT_OPERATION_BASE;
        self.named_reasons
            .lock()
            .expect("the selected context's named reasons are not poisoned")
            .get(&number)
            .cloned()
    }

    pub(crate) fn record_rust_prelude_reference(
        &self,
        reference: SemanticId,
        boundary: SemanticId,
    ) {
        let mut references = self
            .rust_prelude_references
            .lock()
            .expect("the selected context's prelude references are not poisoned");
        let boundaries = references.entry(reference).or_default();
        if !boundaries.contains(&boundary) {
            boundaries.push(boundary);
        }
    }

    pub(crate) fn rust_prelude_reference_boundaries(
        &self,
        reference: SemanticId,
    ) -> Vec<SemanticId> {
        self.rust_prelude_references
            .lock()
            .expect("the selected context's prelude references are not poisoned")
            .get(&reference)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn record_rust_external_type_import_paths(
        &self,
        boundary: SemanticId,
        paths: impl IntoIterator<Item = Vec<String>>,
    ) {
        let mut selected_paths = self
            .rust_external_type_import_paths
            .lock()
            .expect("the selected context's external type paths are not poisoned");
        let recorded = selected_paths.entry(boundary).or_default();
        for path in paths {
            if !recorded.contains(&path) {
                recorded.push(path);
            }
        }
    }

    pub(crate) fn rust_external_type_import_paths(&self, boundary: SemanticId) -> Vec<Vec<String>> {
        self.rust_external_type_import_paths
            .lock()
            .expect("the selected context's external type paths are not poisoned")
            .get(&boundary)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn stack_variable(&self, digest: [u8; 32]) -> StackVariableId {
        StackVariableId::context_local(self.number(digest))
    }
}

/// Exact context coverage for one selected operation.
///
/// The set is sparse: a mount appears in `mounts` only when it has at least one
/// root bridge or a root reverse inventory that was not `Complete`. Every
/// selected mount with neither is covered by `selected_mount_count` and
/// answered by [`SelectedMountLookup`], the operation's own mount table. An
/// entry per selected mount made a point request charge work proportional to
/// unrelated inventory instead of to its own relations.
#[derive(Clone)]
pub(crate) struct SelectedResolutionContextSet {
    /// The mounts that carry something, in strict ordinal order.
    mounts: Box<[SelectedResolutionMountContext]>,
    /// How many mounts the operation selected. Validation compares this with
    /// the operation's own mount count.
    selected_mount_count: usize,
    /// Every carried mount's root bridges, in mount order, flattened once at
    /// construction.
    root_bridges: Box<[SelectedRootBridgeDescriptor]>,
    package_bridges: Box<[SelectedPackageBridgeDescriptor]>,
    go_import_bindings: Box<[SelectedGoImportBindingDescriptor]>,
    /// Every carried mount's root reverse inventory evidence, combined once at
    /// construction for the same reason.
    root_reverse_inventory_completion: ResolutionCompletion,
    context_owned_gap_identities: BTreeSet<SemanticId>,
    /// The numbers this context minted for the identities it invents. It is
    /// carried with the context because everything built from the context --
    /// the overlay, the blueprint, the halves it classifies -- has to agree
    /// with what the context already minted.
    identities: SelectedContextIdentities,
    // Preliminary and completed contexts share this immutable selected policy;
    // it owns no database handles or evaluated answers.
    declaration_access_source: Option<Arc<dyn SelectedDeclarationAccessSource>>,
}

pub(crate) struct SelectedResolutionContextInputs {
    root_bridges: Box<[SelectedRootBridgeDescriptor]>,
    package_bridges: Box<[SelectedPackageBridgeDescriptor]>,
    go_import_bindings: Box<[SelectedGoImportBindingDescriptor]>,
    root_reverse_inventory_completion: ResolutionCompletion,
    declaration_access_source: Option<Arc<dyn SelectedDeclarationAccessSource>>,
    context_owned_gap_identities: BTreeSet<SemanticId>,
    identities: SelectedContextIdentities,
}

/// Request-owned metadata for paths already published under one explicit token.
/// Candidate bodies and indexes remain in the selected request's SQL rows.
pub(crate) struct SelectedContextPathPublication {
    pub(crate) token: SelectedContextPathToken,
    pub(crate) contextual_reverse_inventory_completion: ResolutionCompletion,
    pub(crate) declaration_access_source: Option<Arc<dyn SelectedDeclarationAccessSource>>,
    pub(crate) context_owned_gap_identities: BTreeSet<SemanticId>,
    pub(crate) identities: SelectedContextIdentities,
    pub(crate) shared_semantic_identities: Box<[ResolutionSemanticIdentity]>,
    pub(crate) fragment_local_semantic_identities:
        Box<[(BindingFragmentId, ResolutionSemanticIdentity)]>,
}

pub(crate) enum SelectedContextPathPublicationOutcome {
    Ready(SelectedContextPathPublication),
    Cancelled {
        contextual_reverse_inventory_completion: ResolutionCompletion,
    },
}

pub(crate) enum SelectedResolutionContextValidationOutcome {
    Ready(SelectedResolutionContextInputs),
    Cancelled,
}

/// Context authority in consumption order: root bridges, reverse inventory
/// evidence, declaration access, context-owned gaps, minted identities, and
/// protected package bridges.
pub(crate) type SelectedResolutionContextParts = (
    Box<[SelectedRootBridgeDescriptor]>,
    ResolutionCompletion,
    Option<Arc<dyn SelectedDeclarationAccessSource>>,
    BTreeSet<SemanticId>,
    SelectedContextIdentities,
    Box<[SelectedPackageBridgeDescriptor]>,
    Box<[SelectedGoImportBindingDescriptor]>,
);

impl SelectedResolutionContextInputs {
    pub(crate) fn into_parts(self) -> SelectedResolutionContextParts {
        (
            self.root_bridges,
            self.root_reverse_inventory_completion,
            self.declaration_access_source,
            self.context_owned_gap_identities,
            self.identities,
            self.package_bridges,
            self.go_import_bindings,
        )
    }
}

impl SelectedResolutionContextSet {
    /// Retain mount inventory evidence and its provenance while leaving every
    /// bridge to be installed by the demand that justifies it.
    ///
    /// A mount that only ever carried bridges carries no evidence to retain, so
    /// it leaves the sparse set rather than staying behind as an empty entry.
    /// The carried evidence is unchanged either way, because a dropped mount's
    /// own completion was `Complete`.
    pub(crate) fn without_root_bridges(&self) -> Self {
        Self {
            mounts: self
                .mounts
                .iter()
                .filter(|mount| {
                    !matches!(
                        mount.root_reverse_inventory_completion,
                        ResolutionCompletion::Complete
                    )
                })
                .map(|mount| SelectedResolutionMountContext {
                    ordinal: mount.ordinal,
                    fragment: mount.fragment,
                    semantic_language: mount.semantic_language,
                    root_bridges: Box::new([]),
                    package_bridges: Box::new([]),
                    go_import_bindings: Box::new([]),
                    root_reverse_inventory_completion: mount
                        .root_reverse_inventory_completion
                        .clone(),
                })
                .collect(),
            selected_mount_count: self.selected_mount_count,
            root_bridges: Box::new([]),
            package_bridges: Box::new([]),
            go_import_bindings: Box::new([]),
            root_reverse_inventory_completion: self.root_reverse_inventory_completion.clone(),
            context_owned_gap_identities: self.context_owned_gap_identities.clone(),
            identities: self.identities.clone(),
            declaration_access_source: self.declaration_access_source.clone(),
        }
    }

    /// Add continuations established by an earlier native binding phase.
    /// Existing mount coverage and authority remain unchanged; callers cannot
    /// introduce an unselected source or destination through this operation.
    ///
    /// Only the mounts these continuations name are touched, and the extension
    /// charges one step per added bridge rather than one per selected mount.
    pub(crate) fn extend_root_bridges(
        self,
        bridges: Vec<SelectedRootBridgeDescriptor>,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        selected_mount_of: &SelectedMountLookup<'_>,
    ) -> StoreResult<Option<Self>> {
        let Self {
            mounts,
            selected_mount_count,
            declaration_access_source,
            context_owned_gap_identities,
            identities,
            // Both are recomputed by `Self::new` below from the extended
            // mounts, so the extension cannot keep a stale flattening.
            root_bridges: _,
            package_bridges: _,
            go_import_bindings: _,
            root_reverse_inventory_completion: _,
        } = self;
        let mut additions = HashMap::<_, Vec<_>>::default();
        for bridge in bridges {
            assert!(
                selected_mount_of(bridge.source_fragment())?.is_some(),
                "native continuations require selected source mounts: {}",
                bridge.source_fragment()
            );
            if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            additions
                .entry(bridge.source_fragment())
                .or_default()
                .push(bridge);
        }
        let mut extended_mounts = mounts.into_vec();
        for (fragment, extra) in additions {
            let (ordinal, language) = selected_mount_of(fragment)?
                .expect("an addition's source fragment was checked as a selected mount");
            match extended_mounts.binary_search_by_key(&ordinal, |mount| mount.ordinal()) {
                Ok(index) => {
                    assert_eq!(
                        extended_mounts[index].fragment(),
                        fragment,
                        "a selected mount ordinal names one fragment"
                    );
                    // Appended relations retain their own evidence. Their
                    // uncertainty does not mean the selected relation
                    // inventory omitted entries.
                    let mut bridges = extended_mounts[index].root_bridges.to_vec();
                    bridges.extend(extra);
                    let completion = extended_mounts[index]
                        .root_reverse_inventory_completion
                        .clone();
                    let packages = std::mem::take(&mut extended_mounts[index].package_bridges);
                    let imports = std::mem::take(&mut extended_mounts[index].go_import_bindings);
                    extended_mounts[index] = SelectedResolutionMountContext::new(
                        ordinal, fragment, language, bridges, completion,
                    )?
                    .with_package_bridges(packages.into_vec())?
                    .with_go_import_bindings(imports.into_vec())?;
                }
                Err(index) => extended_mounts.insert(
                    index,
                    SelectedResolutionMountContext::new(
                        ordinal,
                        fragment,
                        language,
                        extra,
                        ResolutionCompletion::Complete,
                    )?,
                ),
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Self::new(
            identities,
            extended_mounts,
            selected_mount_count,
            selected_mount_of,
        )
        .map(|mut context| {
            context.declaration_access_source = declaration_access_source;
            context.context_owned_gap_identities = context_owned_gap_identities;
            Some(context)
        })
    }

    pub(crate) fn inventory_completion(&self) -> &ResolutionCompletion {
        &self.root_reverse_inventory_completion
    }

    /// Add package relations proven by the selected language context. Source
    /// and destination membership are checked by the same constructor used for
    /// the initial context, and cancellation discards the whole extension.
    pub(crate) fn extend_package_bridges(
        self,
        bridges: Vec<SelectedPackageBridgeDescriptor>,
        cancellation: &CancellationToken,
        selected_mount_of: &SelectedMountLookup<'_>,
    ) -> StoreResult<Option<Self>> {
        let Self {
            mounts,
            selected_mount_count,
            declaration_access_source,
            context_owned_gap_identities,
            identities,
            ..
        } = self;
        let mut additions = HashMap::<_, Vec<_>>::default();
        for bridge in bridges {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            additions
                .entry(bridge.source_fragment)
                .or_default()
                .push(bridge);
        }
        let mut mounts = mounts.into_vec();
        for (fragment, extra) in additions {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some((ordinal, language)) = selected_mount_of(fragment)? else {
                return Err(StoreError::new(
                    "package bridge source is not a selected mount",
                ));
            };
            match mounts.binary_search_by_key(&ordinal, |mount| mount.ordinal()) {
                Ok(index) => {
                    assert_eq!(mounts[index].fragment(), fragment);
                    if extra.iter().any(|bridge| bridge.language != language) {
                        return Err(StoreError::new(
                            "package bridge language differs from its source mount",
                        ));
                    }
                    let mut packages =
                        std::mem::take(&mut mounts[index].package_bridges).into_vec();
                    packages.extend(extra);
                    mounts[index].package_bridges = packages.into_boxed_slice();
                }
                Err(index) => mounts.insert(
                    index,
                    SelectedResolutionMountContext::new(
                        ordinal,
                        fragment,
                        language,
                        Vec::new(),
                        ResolutionCompletion::Complete,
                    )?
                    .with_package_bridges(extra)?,
                ),
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Self::new(identities, mounts, selected_mount_count, selected_mount_of).map(|mut context| {
            context.declaration_access_source = declaration_access_source;
            context.context_owned_gap_identities = context_owned_gap_identities;
            Some(context)
        })
    }

    pub(crate) fn extend_go_import_bindings(
        self,
        bridges: Vec<SelectedGoImportBindingDescriptor>,
        cancellation: &CancellationToken,
        selected_mount_of: &SelectedMountLookup<'_>,
    ) -> StoreResult<Option<Self>> {
        let Self {
            mounts,
            selected_mount_count,
            declaration_access_source,
            context_owned_gap_identities,
            identities,
            ..
        } = self;
        let mut additions = HashMap::<_, Vec<_>>::default();
        for bridge in bridges {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            additions
                .entry(bridge.source_fragment)
                .or_default()
                .push(bridge);
        }
        let mut mounts = mounts.into_vec();
        for (fragment, extra) in additions {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some((ordinal, language)) = selected_mount_of(fragment)? else {
                return Err(StoreError::new(
                    "Go import binding source is not a selected mount",
                ));
            };
            match mounts.binary_search_by_key(&ordinal, |mount| mount.ordinal()) {
                Ok(index) => {
                    assert_eq!(mounts[index].fragment(), fragment);
                    if language != Language::Go {
                        return Err(StoreError::new(
                            "Go import binding language differs from its source mount",
                        ));
                    }
                    let mut packages =
                        std::mem::take(&mut mounts[index].go_import_bindings).into_vec();
                    packages.extend(extra);
                    mounts[index].go_import_bindings = packages.into_boxed_slice();
                }
                Err(index) => mounts.insert(
                    index,
                    SelectedResolutionMountContext::new(
                        ordinal,
                        fragment,
                        language,
                        Vec::new(),
                        ResolutionCompletion::Complete,
                    )?
                    .with_go_import_bindings(extra)?,
                ),
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Self::new(identities, mounts, selected_mount_count, selected_mount_of).map(|mut context| {
            context.declaration_access_source = declaration_access_source;
            context.context_owned_gap_identities = context_owned_gap_identities;
            Some(context)
        })
    }

    /// Combine contexts built for files in one selected operation. Go's
    /// selected import closure can contain several source packages, each of
    /// which needs its own file-local import and same-package authority.
    pub(crate) fn merge(
        self,
        other: Self,
        cancellation: &CancellationToken,
        selected_mount_of: &SelectedMountLookup<'_>,
    ) -> StoreResult<Option<Self>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if self.selected_mount_count != other.selected_mount_count {
            return Err(StoreError::new(
                "selected resolution contexts belong to different mount sets",
            ));
        }
        assert!(
            self.identities.shares_identity_space(&other.identities),
            "selected resolution contexts in one operation share identity space"
        );
        let declaration_access_source = match (
            self.declaration_access_source,
            other.declaration_access_source,
        ) {
            (Some(left), Some(right)) if !Arc::ptr_eq(&left, &right) => {
                return Err(StoreError::new(
                    "selected resolution contexts have different declaration access sources",
                ));
            }
            (Some(source), _) | (_, Some(source)) => Some(source),
            (None, None) => None,
        };
        let mut context_owned_gap_identities = self.context_owned_gap_identities;
        context_owned_gap_identities.extend(other.context_owned_gap_identities);
        let mut mounts = self.mounts.into_vec();
        for incoming in other.mounts.into_vec() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            match mounts.binary_search_by_key(&incoming.ordinal(), |mount| mount.ordinal()) {
                Ok(index) => {
                    let current = &mut mounts[index];
                    if current.fragment() != incoming.fragment()
                        || current.semantic_language() != incoming.semantic_language()
                    {
                        return Err(StoreError::new(
                            "selected resolution contexts disagree on a mount identity",
                        ));
                    }
                    let mut roots = current.root_bridges.to_vec();
                    roots.extend(incoming.root_bridges.iter().cloned());
                    let mut packages = current.package_bridges.to_vec();
                    packages.extend(incoming.package_bridges.iter().cloned());
                    let mut imports = current.go_import_bindings.to_vec();
                    imports.extend(incoming.go_import_bindings.iter().cloned());
                    let completion = current
                        .root_reverse_inventory_completion
                        .combine(&incoming.root_reverse_inventory_completion);
                    *current = SelectedResolutionMountContext::new(
                        incoming.ordinal(),
                        incoming.fragment(),
                        incoming.semantic_language(),
                        roots,
                        completion,
                    )?
                    .with_package_bridges(packages)?
                    .with_go_import_bindings(imports)?;
                }
                Err(index) => mounts.insert(index, incoming),
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut merged = Self::new(
            self.identities,
            mounts,
            self.selected_mount_count,
            selected_mount_of,
        )?;
        merged.declaration_access_source = declaration_access_source;
        merged.context_owned_gap_identities = context_owned_gap_identities;
        Ok(Some(merged))
    }

    /// Register only a reason created by this context's producer. Persisted
    /// reasons already have mounted provenance and must not be reclassified.
    pub(crate) fn with_context_owned_inventory_reason(mut self, reason: SemanticId) -> Self {
        assert!(
            self.mounts.iter().any(|mount| mount
                .root_reverse_inventory_completion
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))),
            "context-owned reason registration requires retained inventory evidence"
        );
        self.context_owned_gap_identities.insert(reason);
        self
    }

    pub(crate) fn with_additional_context_owned_inventory_reason(
        mut self,
        reason: SemanticId,
    ) -> Self {
        assert!(
            !self.context_owned_gap_identities.contains(&reason),
            "additional context-owned reason must be new to this context"
        );
        let completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )]);
        for mount in &mut self.mounts {
            mount.root_reverse_inventory_completion =
                mount.root_reverse_inventory_completion.combine(&completion);
        }
        self.root_reverse_inventory_completion =
            self.root_reverse_inventory_completion.combine(&completion);
        self.context_owned_gap_identities.insert(reason);
        self
    }

    pub(crate) fn with_declaration_access_source(
        mut self,
        declaration_access_source: Arc<dyn SelectedDeclarationAccessSource>,
    ) -> Self {
        assert!(
            self.declaration_access_source.is_none(),
            "selected declaration access source may only be installed once"
        );
        self.declaration_access_source = Some(declaration_access_source);
        self
    }

    /// Build a context set from the sparse mounts that carry something.
    ///
    /// `selected_mount_count` is how many mounts the operation selected, and
    /// `selected_mount_of` is the operation's own mount table. The lookup is
    /// what lets a sparse entry name a mount, a bridge land on one, and a
    /// repeated fragment be rejected without the set holding an entry per
    /// selected mount.
    pub(crate) fn new(
        identities: SelectedContextIdentities,
        mounts: impl Into<Box<[SelectedResolutionMountContext]>>,
        selected_mount_count: usize,
        selected_mount_of: &SelectedMountLookup<'_>,
    ) -> StoreResult<Self> {
        let mounts = mounts.into();
        let mut prior_ordinal = None;
        for mount in &mounts {
            if prior_ordinal.is_some_and(|prior| prior >= mount.ordinal()) {
                return Err(StoreError::new(format!(
                    "selected resolution mount contexts are not in strict ordinal order at {}",
                    mount.ordinal().get()
                )));
            }
            prior_ordinal = Some(mount.ordinal());
            // The operation's mount table is the authority for a carried
            // mount's identity. Asking it also rules out a repeated fragment,
            // because one fragment has one ordinal and the order is strict.
            if selected_mount_of(mount.fragment())?
                != Some((mount.ordinal(), mount.semantic_language()))
            {
                return Err(StoreError::new(format!(
                    "selected resolution mount context {} is not the mount the operation selected for fragment {}",
                    mount.ordinal().get(),
                    mount.fragment(),
                )));
            }
        }
        let mut root_bridges = Vec::new();
        let mut package_bridges = Vec::new();
        let mut go_import_bindings = Vec::new();
        let mut root_reverse_inventory_completion = ResolutionCompletion::Complete;
        for mount in &mounts {
            for bridge in &mount.root_bridges {
                if selected_mount_of(bridge.target_fragment())?
                    .is_none_or(|(_, language)| language != bridge.target_language())
                {
                    return Err(StoreError::new(format!(
                        "selected root bridge target fragment {} is not a selected mount for language {:?}",
                        bridge.target_fragment(),
                        bridge.target_language(),
                    )));
                }
                root_bridges.push(bridge.clone());
            }
            for bridge in &mount.package_bridges {
                if selected_mount_of(bridge.target_fragment)?
                    .is_none_or(|(_, language)| language != bridge.language)
                {
                    return Err(StoreError::new(
                        "selected package bridge target is not a selected mount for its language",
                    ));
                }
                package_bridges.push(bridge.clone());
            }
            go_import_bindings.extend(mount.go_import_bindings.iter().cloned());
            // Complete is the identity operand. Combining it would clone the
            // accumulated inventory once for every otherwise complete mount.
            if !matches!(
                mount.root_reverse_inventory_completion,
                ResolutionCompletion::Complete
            ) {
                root_reverse_inventory_completion = root_reverse_inventory_completion
                    .combine(&mount.root_reverse_inventory_completion);
            }
        }
        Ok(Self {
            mounts,
            selected_mount_count,
            root_bridges: root_bridges.into_boxed_slice(),
            package_bridges: package_bridges.into_boxed_slice(),
            go_import_bindings: go_import_bindings.into_boxed_slice(),
            root_reverse_inventory_completion,
            context_owned_gap_identities: BTreeSet::new(),
            identities,
            declaration_access_source: None,
        })
    }

    pub(crate) fn validate_exact_mounts(
        self,
        expected_mounts: usize,
        selected_mount_of: &SelectedMountLookup<'_>,
        cancellation: &CancellationToken,
    ) -> StoreResult<SelectedResolutionContextValidationOutcome> {
        self.validate_exact_mounts_with_session(
            expected_mounts,
            selected_mount_of,
            cancellation,
            None,
        )
    }

    pub(crate) fn validate_exact_mounts_in_session(
        self,
        expected_mounts: usize,
        selected_mount_of: &SelectedMountLookup<'_>,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> StoreResult<SelectedResolutionContextValidationOutcome> {
        self.validate_exact_mounts_with_session(
            expected_mounts,
            selected_mount_of,
            cancellation,
            Some(session),
        )
    }

    /// Check that this context was built for the operation about to use it and
    /// hand over the relations it carries.
    ///
    /// The context's flattened root bridges and combined reverse inventory
    /// evidence are computed once in [`Self::new`], so this is constant work.
    /// Coverage is a construction-time invariant of the producer, so
    /// element-wise correspondence is a debug assertion over the sparse
    /// entries, and the release check is the one thing a caller can still get
    /// wrong: handing over a context built for a different operation, whose
    /// mount count differs.
    fn validate_exact_mounts_with_session(
        self,
        expected_mounts: usize,
        _selected_mount_of: &SelectedMountLookup<'_>,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> StoreResult<SelectedResolutionContextValidationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionContextValidationOutcome::Cancelled);
        }
        let Self {
            mounts: _mounts,
            selected_mount_count,
            root_bridges,
            package_bridges,
            go_import_bindings,
            root_reverse_inventory_completion,
            declaration_access_source,
            context_owned_gap_identities,
            identities,
        } = self;

        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(SelectedResolutionContextValidationOutcome::Cancelled);
        }
        if selected_mount_count > expected_mounts {
            return Err(StoreError::new(
                "selected resolution context has more entries than the operation",
            ));
        }
        if selected_mount_count < expected_mounts {
            return Err(StoreError::new(
                "selected resolution context omits operation mounts",
            ));
        }
        #[cfg(debug_assertions)]
        for mount in &_mounts {
            debug_assert_eq!(
                _selected_mount_of(mount.fragment())?,
                Some((mount.ordinal(), mount.semantic_language())),
                "selected resolution context carries a mount the operation did not select"
            );
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionContextValidationOutcome::Cancelled);
        }
        Ok(SelectedResolutionContextValidationOutcome::Ready(
            SelectedResolutionContextInputs {
                root_bridges,
                package_bridges,
                go_import_bindings,
                root_reverse_inventory_completion,
                declaration_access_source,
                context_owned_gap_identities,
                identities,
            },
        ))
    }
}

/// One exact selected route from a content-owned import ingress to a
/// content-owned root export.
///
/// The descriptor retains the exact mounted opaque tokens from both canonical
/// path halves. Its caller must derive them from the exact post-open mount
/// context and selected workspace topology. The constructor enforces local
/// shape, while the store operation verifies exact mount coverage. The trusted
/// selected-context builder remains the authority for route-to-target topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRootBridgeDescriptor {
    source_fragment: BindingFragmentId,
    source_language: Language,
    source_import_token: SemanticId,
    anchor: ResolutionRootImportAnchor,
    /// The anchor symbol the source half's route starts with, as the source
    /// blob mounted it.
    ///
    /// The bridge's own route starts with exactly this symbol, so the two
    /// halves meet without either recomputing it. It used to be recomputed:
    /// `root_import_anchor_semantic(source_fragment, anchor)` was a pure
    /// function while a mounted id was a digest of its identity, and a
    /// fragment-local id is that blob's catalog position now.
    source_import_anchor: SemanticId,
    target_fragment: BindingFragmentId,
    target_language: Language,
    target_export_token: SemanticId,
    /// Exact authorized endpoint, when selection owns declaration-level access.
    /// A token-only destination remains useful for open/unsupported routes.
    target_definition: Option<BindingNodeId>,
    /// A member scope the route lands in instead of a root export.
    ///
    /// The Rust crate route publishes this for `Foo::frobnicate()` where `Foo`
    /// implements a trait that declares `frobnicate`. The qualified route
    /// already carries the member lookup, so the bridge hands that lookup to
    /// the trait's own member scope and the member paths the trait's blob
    /// holds answer it. The destination is a scope, not a declaration, so the
    /// bridge never names a member and cannot disagree with what the trait
    /// declares.
    target_member_scope: Option<BindingNodeId>,
    /// Canonical first Type segment for a bare Rust qualified route.  It is
    /// kept separate from `route`: the prefix is resolved lexically first,
    /// then the remaining Type route is selected from that result.
    prefix_reference: Option<SemanticId>,
    route: Box<[ResolutionLookupSemanticRecipe]>,
    source_demand: ResolutionLookupSemanticRecipe,
    target_demand: ResolutionLookupSemanticRecipe,
    completion: ResolutionCompletion,
}

impl SelectedRootBridgeDescriptor {
    // `new` is gone. It took a site and a scope and computed the two root
    // tokens from them, which a mounted id being a pure function of its
    // identity allowed. A token is a catalog position now and only the mount's
    // catalog knows it, so a caller that wants a bridge brings the tokens it
    // read: `from_selected_path_tokens` is the only constructor, and every
    // production caller already used it.
    /// One bridge for a fixture, from the site and scope its tokens used to
    /// be computed from.
    ///
    /// `new` took those two and computed the import and export tokens, which
    /// only worked while a mounted id was a pure function of its identity. A
    /// token is a catalog position now and only the mount's catalog knows it,
    /// which is why production callers bring the tokens they read. A fixture
    /// reads no tokens: it checks the bridge's shape, and needs only that two
    /// bridges built from two sites differ. So the three identities come from
    /// the fixture label table, and nothing here claims they are the tokens
    /// any blob would publish.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        source_fragment: BindingFragmentId,
        source_language: Language,
        import_site: ResolutionSiteId,
        anchor: ResolutionRootImportAnchor,
        target_fragment: BindingFragmentId,
        target_language: Language,
        root_scope: ResolutionScopeId,
        route: impl Into<Box<[ResolutionLookupSemanticRecipe]>>,
        source_demand: ResolutionLookupSemanticRecipe,
        target_demand: ResolutionLookupSemanticRecipe,
        completion: ResolutionCompletion,
    ) -> Self {
        let label = |what: &str, ordinal: u32| {
            let mut bytes = what.as_bytes().to_vec();
            bytes.extend_from_slice(&source_fragment.ordinal().to_be_bytes());
            bytes.extend_from_slice(&target_fragment.ordinal().to_be_bytes());
            bytes.extend_from_slice(&ordinal.to_be_bytes());
            bytes
        };
        Self::from_selected_path_tokens(
            source_fragment,
            source_language,
            SemanticId::for_test(label("import-token", import_site.get())),
            anchor,
            SemanticId::for_test(label(
                "import-anchor",
                u32::from(anchor == ResolutionRootImportAnchor::Absolute),
            )),
            target_fragment,
            target_language,
            SemanticId::for_test(label("export-token", root_scope.get())),
            route,
            source_demand,
            target_demand,
            completion,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_selected_path_tokens(
        source_fragment: BindingFragmentId,
        source_language: Language,
        source_import_token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        source_import_anchor: SemanticId,
        target_fragment: BindingFragmentId,
        target_language: Language,
        target_export_token: SemanticId,
        route: impl Into<Box<[ResolutionLookupSemanticRecipe]>>,
        source_demand: ResolutionLookupSemanticRecipe,
        target_demand: ResolutionLookupSemanticRecipe,
        completion: ResolutionCompletion,
    ) -> Self {
        Self::from_selected_path_tokens_inner(
            source_fragment,
            source_language,
            source_import_token,
            anchor,
            source_import_anchor,
            target_fragment,
            target_language,
            target_export_token,
            None,
            route,
            source_demand,
            target_demand,
            completion,
        )
    }

    /// Construct a selected bridge whose first segment is a separately
    /// resolved Rust Type prefix, Go package-import definition, or Java Type
    /// shadowing guard. The caller proves the language-specific prefix result
    /// before constructing a continuation. This is
    /// intentionally distinct from the
    /// ordinary constructor so a namespace mismatch cannot be accepted by a
    /// blanket relaxation of route validation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_selected_path_tokens_with_prefix(
        source_fragment: BindingFragmentId,
        source_language: Language,
        source_import_token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        source_import_anchor: SemanticId,
        target_fragment: BindingFragmentId,
        target_language: Language,
        target_export_token: SemanticId,
        prefix_reference: SemanticId,
        route: impl Into<Box<[ResolutionLookupSemanticRecipe]>>,
        source_demand: ResolutionLookupSemanticRecipe,
        target_demand: ResolutionLookupSemanticRecipe,
        completion: ResolutionCompletion,
    ) -> Self {
        Self::from_selected_path_tokens_inner(
            source_fragment,
            source_language,
            source_import_token,
            anchor,
            source_import_anchor,
            target_fragment,
            target_language,
            target_export_token,
            Some(prefix_reference),
            route,
            source_demand,
            target_demand,
            completion,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_selected_path_tokens_inner(
        source_fragment: BindingFragmentId,
        source_language: Language,
        source_import_token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        source_import_anchor: SemanticId,
        target_fragment: BindingFragmentId,
        target_language: Language,
        target_export_token: SemanticId,
        prefix_reference: Option<SemanticId>,
        route: impl Into<Box<[ResolutionLookupSemanticRecipe]>>,
        source_demand: ResolutionLookupSemanticRecipe,
        target_demand: ResolutionLookupSemanticRecipe,
        completion: ResolutionCompletion,
    ) -> Self {
        assert_ne!(
            source_language,
            Language::None,
            "a selected root bridge needs a source semantic language"
        );
        assert_eq!(
            source_language, target_language,
            "a selected root bridge needs one semantic language"
        );
        assert_eq!(
            source_demand.semantic_language(),
            source_language.config_label(),
            "selected root bridge source demand language differs from its mounts"
        );
        assert_eq!(
            target_demand.semantic_language(),
            target_language.config_label(),
            "selected root bridge target demand language differs from its mounts"
        );
        assert_eq!(
            source_demand.namespace(),
            target_demand.namespace(),
            "selected root bridge source and target demands need one namespace"
        );
        let route = route.into();
        for segment in &route {
            assert_eq!(
                segment.semantic_language(),
                source_language.config_label(),
                "selected root bridge route language differs from its mounts"
            );
            assert_eq!(
                segment.namespace(),
                if prefix_reference.is_some() {
                    ResolutionNamespace::Type
                } else {
                    source_demand.namespace()
                },
                "selected root bridge route namespace differs from its demand or Type prefix"
            );
        }
        assert!(
            !completion.contains_reason(ResolutionIncompleteReason::Cancelled),
            "selected root bridge completion cannot persist operation cancellation"
        );
        Self {
            source_fragment,
            source_language,
            source_import_token,
            anchor,
            source_import_anchor,
            target_fragment,
            target_language,
            target_export_token,
            target_definition: None,
            target_member_scope: None,
            prefix_reference,
            route,
            source_demand,
            target_demand,
            completion,
        }
    }

    pub(crate) const fn source_fragment(&self) -> BindingFragmentId {
        self.source_fragment
    }

    pub(crate) const fn source_language(&self) -> Language {
        self.source_language
    }

    pub(crate) const fn source_import_token(&self) -> SemanticId {
        self.source_import_token
    }

    pub(crate) const fn source_import_anchor(&self) -> SemanticId {
        self.source_import_anchor
    }

    pub(crate) const fn anchor(&self) -> ResolutionRootImportAnchor {
        self.anchor
    }

    pub(crate) const fn target_fragment(&self) -> BindingFragmentId {
        self.target_fragment
    }

    pub(crate) const fn target_language(&self) -> Language {
        self.target_language
    }

    pub(crate) const fn target_definition(&self) -> Option<BindingNodeId> {
        self.target_definition
    }

    pub(crate) const fn target_export_token(&self) -> SemanticId {
        self.target_export_token
    }

    pub(crate) const fn prefix_reference(&self) -> Option<SemanticId> {
        self.prefix_reference
    }

    /// Join the authorized canonical export now, before the shared token could
    /// branch to another declaration with the same lookup name.
    pub(crate) fn with_selected_export(
        mut self,
        names: &dyn SharedNameInterner,
        export: &SelectedRootPathHalf,
    ) -> Self {
        let SelectedRootPathHalf::Export {
            identity,
            demand,
            token,
            definition,
            incomplete_reasons,
        } = export
        else {
            panic!("a selected export endpoint requires an export half: {export:?}");
        };
        assert_eq!(identity.fragment(), self.target_fragment);
        assert_eq!(*demand, self.target_demand.semantic(names));
        assert_eq!(*token, self.target_export_token);
        assert_ne!(*definition, BindingNodeId::universal_root());
        self.target_definition = Some(*definition);
        if !incomplete_reasons.is_empty() {
            self.completion = self.completion.combine(&ResolutionCompletion::incomplete(
                incomplete_reasons.iter().copied(),
            ));
        }
        self
    }

    /// Finish a route whose owner/member walk already proved this selected
    /// declaration. The caller retains name, ownership and access evidence in
    /// the bridge completion; no universal-root name search is performed.
    pub(crate) fn with_selected_member_definition(mut self, definition: BindingNodeId) -> Self {
        assert_eq!(
            definition.ordinal(),
            Some(self.target_fragment.ordinal()),
            "a selected member definition belongs to its target mount"
        );
        assert!(self.target_member_scope.is_none());
        self.target_definition = Some(definition);
        self
    }

    /// Land this route in a member scope instead of at a root export.
    ///
    /// The scope head is the destination blob's own, so it cannot be the
    /// universal root, and a bridge that already names an authorized export
    /// declaration is a different route: the two destinations are exclusive.
    pub(crate) fn with_trait_member_scope(mut self, scope_head: BindingNodeId) -> Self {
        assert_ne!(
            scope_head,
            BindingNodeId::universal_root(),
            "a trait member scope is owned by the blob that declares the trait"
        );
        assert!(
            self.target_definition.is_none(),
            "a selected bridge lands either at an export declaration or in a member scope"
        );
        self.target_member_scope = Some(scope_head);
        self
    }

    pub(crate) fn route(&self) -> &[ResolutionLookupSemanticRecipe] {
        &self.route
    }

    pub(crate) const fn source_demand(&self) -> &ResolutionLookupSemanticRecipe {
        &self.source_demand
    }

    pub(crate) const fn target_demand(&self) -> &ResolutionLookupSemanticRecipe {
        &self.target_demand
    }

    pub(crate) const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

/// Atomic result of compiling selected context into one lexical overlay.
pub(crate) enum SelectedContextOverlayCompilation {
    Ready(SelectedContextOverlay),
    Cancelled {
        contextual_reverse_inventory_completion: ResolutionCompletion,
    },
}

/// One language-neutral, operation-local graph delta.
///
pub(crate) struct SelectedContextOverlay {
    removed_candidate_paths: Box<[CandidatePathIdentity]>,
    removed_reverse_candidate_gaps: Box<[ReverseCandidateGapIdentity]>,
    added_candidate_paths: Box<[(CandidatePathIdentity, PartialPath)]>,
    boundary_nodes: Box<[BindingNodeId]>,
    callable_static_import_boundaries: Box<[BindingNodeId]>,
    shared_semantic_identities: Box<[ResolutionSemanticIdentity]>,
    fragment_local_semantic_identities: Box<[(BindingFragmentId, ResolutionSemanticIdentity)]>,
    contextual_reverse_inventory_completion: ResolutionCompletion,
}

pub(super) type SelectedContextOverlayParts = (
    Box<[CandidatePathIdentity]>,
    Box<[ReverseCandidateGapIdentity]>,
    Box<[(CandidatePathIdentity, PartialPath)]>,
    Box<[BindingNodeId]>,
    Box<[BindingNodeId]>,
    Box<[ResolutionSemanticIdentity]>,
    ResolutionCompletion,
);

impl SelectedContextOverlay {
    #[cfg(test)]
    pub(crate) fn add_package_bridges(
        &mut self,
        identities: &SelectedContextIdentities,
        bridges: &[SelectedPackageBridgeDescriptor],
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let session = ResolutionSession::unbounded();
        let mut additions = self.added_candidate_paths.to_vec();
        let mut shared = self.shared_semantic_identities.to_vec();
        for bridge in bridges {
            let Some(path) = bridge.compile(identities, cancellation, &session) else {
                return Ok(false);
            };
            additions.push(path);
            shared.extend(bridge.shared_identities());
        }
        additions.sort_unstable_by_key(|entry| entry.0);
        for pair in additions.windows(2) {
            if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
                return Err(StoreError::new("conflicting selected package oracle paths"));
            }
        }
        additions.dedup_by_key(|entry| entry.0);
        shared.sort_unstable();
        shared.dedup();
        self.added_candidate_paths = additions.into_boxed_slice();
        self.shared_semantic_identities = shared.into_boxed_slice();
        Ok(!cancellation.is_cancelled())
    }

    #[cfg(test)]
    pub(crate) fn add_go_import_bindings(
        &mut self,
        identities: &SelectedContextIdentities,
        bridges: &[SelectedGoImportBindingDescriptor],
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let session = ResolutionSession::unbounded();
        let mut additions = self.added_candidate_paths.to_vec();
        let mut shared = self.shared_semantic_identities.to_vec();
        for bridge in bridges {
            let Some(path) = bridge.compile(identities, cancellation, &session) else {
                return Ok(false);
            };
            additions.push(path);
            shared.extend(bridge.shared_identities());
        }
        additions.sort_unstable_by_key(|entry| entry.0);
        for pair in additions.windows(2) {
            if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
                return Err(StoreError::new(
                    "conflicting selected Go import oracle paths",
                ));
            }
        }
        additions.dedup_by_key(|entry| entry.0);
        shared.sort_unstable();
        shared.dedup();
        self.added_candidate_paths = additions.into_boxed_slice();
        self.shared_semantic_identities = shared.into_boxed_slice();
        Ok(!cancellation.is_cancelled())
    }

    pub(crate) fn shared_semantic_identities(&self) -> &[ResolutionSemanticIdentity] {
        &self.shared_semantic_identities
    }

    pub(crate) fn fragment_local_semantic_identities(
        &self,
    ) -> &[(BindingFragmentId, ResolutionSemanticIdentity)] {
        &self.fragment_local_semantic_identities
    }

    pub(super) fn into_parts(self) -> SelectedContextOverlayParts {
        (
            self.removed_candidate_paths,
            self.removed_reverse_candidate_gaps,
            self.added_candidate_paths,
            self.boundary_nodes,
            self.callable_static_import_boundaries,
            self.shared_semantic_identities,
            self.contextual_reverse_inventory_completion,
        )
    }
}

/// Compile exact selected root bridges. Cancellation publishes no partial overlay.
pub(crate) fn compile_selected_context_overlay(
    identities: &SelectedContextIdentities,
    bridges: &[SelectedRootBridgeDescriptor],
    names: &dyn SharedNameInterner,
    root_reverse_inventory_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
) -> StoreResult<SelectedContextOverlayCompilation> {
    compile_selected_context_overlay_with_session(
        identities,
        bridges,
        names,
        root_reverse_inventory_completion,
        cancellation,
        None,
    )
}

pub(crate) fn compile_selected_context_overlay_in_session(
    identities: &SelectedContextIdentities,
    bridges: &[SelectedRootBridgeDescriptor],
    names: &dyn SharedNameInterner,
    root_reverse_inventory_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> StoreResult<SelectedContextOverlayCompilation> {
    compile_selected_context_overlay_with_session(
        identities,
        bridges,
        names,
        root_reverse_inventory_completion,
        cancellation,
        Some(session),
    )
}

fn compile_selected_context_overlay_with_session(
    identities: &SelectedContextIdentities,
    bridges: &[SelectedRootBridgeDescriptor],
    names: &dyn SharedNameInterner,
    root_reverse_inventory_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    session: Option<&ResolutionSession>,
) -> StoreResult<SelectedContextOverlayCompilation> {
    if root_reverse_inventory_completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
        return Err(StoreError::new(
            "selected root inventory completion contains operation cancellation",
        ));
    }

    let mut overlay = SelectedContextOverlay {
        removed_candidate_paths: Box::new([]),
        removed_reverse_candidate_gaps: Box::new([]),
        added_candidate_paths: Box::new([]),
        boundary_nodes: Box::new([]),
        callable_static_import_boundaries: Box::new([]),
        shared_semantic_identities: Box::new([]),
        fragment_local_semantic_identities: Box::new([]),
        contextual_reverse_inventory_completion: ResolutionCompletion::Complete,
    };
    overlay.contextual_reverse_inventory_completion = overlay
        .contextual_reverse_inventory_completion
        .combine(root_reverse_inventory_completion);
    if cancellation.is_cancelled() {
        return Ok(SelectedContextOverlayCompilation::Cancelled {
            contextual_reverse_inventory_completion: overlay
                .contextual_reverse_inventory_completion,
        });
    }

    let mut added = overlay.added_candidate_paths.into_vec();
    added.reserve(bridges.len());
    let mut compiled_bridges = HashMap::default();
    let mut shared = BTreeSet::new();
    let mut fragment_local = BTreeSet::new();
    let mut work = 0_usize;
    for bridge in bridges {
        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(SelectedContextOverlayCompilation::Cancelled {
                contextual_reverse_inventory_completion: overlay
                    .contextual_reverse_inventory_completion,
            });
        }
        if poll_context_work(cancellation, &mut work) {
            return Ok(SelectedContextOverlayCompilation::Cancelled {
                contextual_reverse_inventory_completion: overlay
                    .contextual_reverse_inventory_completion,
            });
        }
        validate_bridge(bridge)?;
        fragment_local.insert((
            bridge.source_fragment(),
            root_import_anchor_semantic_identity(bridge.anchor()),
        ));
        for recipe in bridge
            .route()
            .iter()
            .chain([bridge.source_demand(), bridge.target_demand()])
        {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(SelectedContextOverlayCompilation::Cancelled {
                    contextual_reverse_inventory_completion: overlay
                        .contextual_reverse_inventory_completion,
                });
            }
            if poll_context_work(cancellation, &mut work) {
                return Ok(SelectedContextOverlayCompilation::Cancelled {
                    contextual_reverse_inventory_completion: overlay
                        .contextual_reverse_inventory_completion,
                });
            }
            shared.insert(recipe.identity(names));
        }
        let candidate = compile_bridge(identities, bridge, names);
        // Topology retains every import/profile justification. Compilation
        // projects those records onto executable relations: the same exact
        // source token, route and authorized endpoint need execute only once.
        // Charge and validate every derivation above before this projection.
        // Completion is part of descriptor equality even though it is not
        // part of path identity; conflicting evidence is never first-wins.
        if let Some(previous) = compiled_bridges.insert(candidate.0, bridge) {
            if previous != bridge {
                return Err(StoreError::new(format!(
                    "selected context has conflicting derivations for candidate path {:?}: previous={previous:?}, current={bridge:?}",
                    candidate.0
                )));
            }
        } else {
            added.push(candidate);
        }
    }
    if cancellation.is_cancelled() {
        return Ok(SelectedContextOverlayCompilation::Cancelled {
            contextual_reverse_inventory_completion: overlay
                .contextual_reverse_inventory_completion,
        });
    }
    added.sort_unstable_by_key(|(identity, _)| *identity);
    for rows in added.windows(2) {
        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(SelectedContextOverlayCompilation::Cancelled {
                contextual_reverse_inventory_completion: overlay
                    .contextual_reverse_inventory_completion,
            });
        }
        if poll_context_work(cancellation, &mut work) {
            return Ok(SelectedContextOverlayCompilation::Cancelled {
                contextual_reverse_inventory_completion: overlay
                    .contextual_reverse_inventory_completion,
            });
        }
        if rows[0].0 == rows[1].0 {
            return Err(StoreError::new(format!(
                "selected context repeats added candidate path {:?}",
                rows[1].0
            )));
        }
    }
    for candidate in &added {
        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(SelectedContextOverlayCompilation::Cancelled {
                contextual_reverse_inventory_completion: overlay
                    .contextual_reverse_inventory_completion,
            });
        }
        if poll_context_work(cancellation, &mut work) {
            return Ok(SelectedContextOverlayCompilation::Cancelled {
                contextual_reverse_inventory_completion: overlay
                    .contextual_reverse_inventory_completion,
            });
        }
        if overlay
            .removed_candidate_paths
            .binary_search(&candidate.0)
            .is_ok()
        {
            return Err(StoreError::new(format!(
                "selected context both removes and adds candidate path {:?}",
                candidate.0
            )));
        }
    }
    overlay.added_candidate_paths = added.into_boxed_slice();
    overlay.shared_semantic_identities = shared.into_iter().collect();
    overlay.fragment_local_semantic_identities = fragment_local.into_iter().collect();
    if cancellation.is_cancelled() {
        return Ok(SelectedContextOverlayCompilation::Cancelled {
            contextual_reverse_inventory_completion: overlay
                .contextual_reverse_inventory_completion,
        });
    }
    Ok(SelectedContextOverlayCompilation::Ready(overlay))
}

fn validate_bridge(bridge: &SelectedRootBridgeDescriptor) -> StoreResult<()> {
    if bridge.source_language() != bridge.target_language() {
        return Err(StoreError::new(
            "selected root bridge crosses semantic languages",
        ));
    }
    let language = bridge.source_language().config_label();
    if bridge.source_demand().semantic_language() != language
        || bridge.target_demand().semantic_language() != language
        || bridge.source_demand().namespace() != bridge.target_demand().namespace()
        || bridge.route().iter().any(|segment| {
            segment.semantic_language() != language
                || segment.namespace()
                    != bridge
                        .prefix_reference()
                        .map_or(bridge.source_demand().namespace(), |_| {
                            ResolutionNamespace::Type
                        })
        })
    {
        return Err(StoreError::new(
            "selected root bridge lookup recipe language differs from its mounts",
        ));
    }
    if bridge
        .completion()
        .contains_reason(ResolutionIncompleteReason::Cancelled)
    {
        return Err(StoreError::new(
            "selected root bridge completion contains operation cancellation",
        ));
    }
    Ok(())
}

/// The complete graph contribution of one validated context derivation.
/// Borrow it only while publishing that producer into the active SQL context.
pub(crate) struct SelectedRootBridgeProjection {
    pub(crate) identity: [u8; 32],
    pub(crate) lexical: super::fact_lowering::LoweredResolutionFragment,
    pub(crate) typed: super::typed_fact_lowering::LoweredTypedFragment,
    pub(crate) recipes: Vec<(SemanticId, ResolutionLookupSemanticRecipe)>,
    pub(crate) local_anchor: (BindingFragmentId, ResolutionSemanticIdentity),
}

/// Validate and charge every derivation before its publication can deduplicate
/// an already admitted producer. Completion remains part of the path body even
/// though the stable derivation identity deliberately does not hash it.
pub(crate) fn compile_selected_root_bridge(
    identities: &SelectedContextIdentities,
    bridge: &SelectedRootBridgeDescriptor,
    names: &dyn SharedNameInterner,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> StoreResult<Option<SelectedRootBridgeProjection>> {
    if !session.scope_step() || cancellation.is_cancelled() {
        return Ok(None);
    }
    validate_bridge(bridge)?;
    let mut recipes = Vec::with_capacity(bridge.route().len() + 2);
    for recipe in bridge
        .route()
        .iter()
        .chain([bridge.source_demand(), bridge.target_demand()])
    {
        if !session.scope_step() || cancellation.is_cancelled() {
            return Ok(None);
        }
        recipes.push((recipe.semantic(names), recipe.clone()));
    }
    let (candidate, path) = compile_bridge(identities, bridge, names);
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(SelectedRootBridgeProjection {
        identity: bridge_digest(b"bifrost-selected-root-bridge-path:v1", bridge),
        lexical: super::fact_lowering::LoweredResolutionFragment::new(
            bridge.source_fragment(),
            bridge.source_language(),
            Vec::new(),
            vec![(candidate.path(), path)],
            Vec::new(),
            Vec::new(),
        ),
        typed: super::typed_fact_lowering::LoweredTypedFragment::empty(
            bridge.source_fragment(),
            bridge.source_language(),
        ),
        recipes,
        local_anchor: (
            bridge.source_fragment(),
            root_import_anchor_semantic_identity(bridge.anchor()),
        ),
    }))
}

fn compile_bridge(
    identities: &SelectedContextIdentities,
    bridge: &SelectedRootBridgeDescriptor,
    names: &dyn SharedNameInterner,
) -> (CandidatePathIdentity, PartialPath) {
    let path_digest = bridge_digest(b"bifrost-selected-root-bridge-path:v1", bridge);
    let path = identities.path(path_digest);
    let tail = identities.stack_variable(bridge_digest(
        b"bifrost-selected-root-bridge-tail:v1",
        bridge,
    ));
    let route = std::iter::once(bridge.source_import_anchor())
        .chain(bridge.prefix_reference())
        .chain(bridge.route().iter().map(|recipe| recipe.semantic(names)))
        .chain([
            bridge.source_import_token(),
            bridge.source_demand().semantic(names),
        ])
        .collect::<Vec<_>>();
    let (end_node, export, precedence, witness) =
        match (bridge.target_definition, bridge.target_member_scope) {
            // The trait's member scope answers the lookup the route already
            // carries, so the bridge ends holding that one symbol and the
            // destination blob's own member paths continue from there. It claims
            // no declaration and no precedence: which member the scope binds, and
            // whether it binds one at all, stays the trait's answer.
            (_, Some(scope_head)) => (
                scope_head,
                vec![bridge.target_demand().semantic(names)],
                Vec::new(),
                Vec::new(),
            ),
            (Some(definition), None) => (
                definition,
                Vec::new(),
                vec![PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic: bridge.target_export_token(),
                }],
                vec![WitnessStep::Node(definition)],
            ),
            (None, None) => (
                BindingNodeId::universal_root(),
                vec![
                    bridge.target_demand().semantic(names),
                    bridge.target_export_token(),
                ],
                Vec::new(),
                Vec::new(),
            ),
        };
    (
        CandidatePathIdentity::new(bridge.source_fragment(), path),
        PartialPath::new(
            EndpointSignature::new(
                BindingNodeId::universal_root(),
                StackPattern::open(route, tail),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                end_node,
                StackPattern::open(export, tail),
                StackPattern::closed(Vec::new()),
            ),
            precedence,
            witness,
            bridge.completion().clone(),
        ),
    )
}

fn bridge_digest(domain: &[u8], bridge: &SelectedRootBridgeDescriptor) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    hasher.field("source_fragment", &bridge.source_fragment().as_bytes());
    hasher.field(
        "source_language",
        bridge.source_language().config_label().as_bytes(),
    );
    hasher.field(
        "source_import_token",
        &bridge.source_import_token().as_bytes(),
    );
    hasher.field(
        "anchor",
        match bridge.anchor() {
            ResolutionRootImportAnchor::Lexical => b"lexical",
            ResolutionRootImportAnchor::Absolute => b"absolute",
        },
    );
    hasher.field("target_fragment", &bridge.target_fragment().as_bytes());
    hasher.field(
        "target_language",
        bridge.target_language().config_label().as_bytes(),
    );
    hasher.field(
        "target_export_token",
        &bridge.target_export_token().as_bytes(),
    );
    if let Some(definition) = bridge.target_definition {
        hasher.field("target_definition", &definition.as_bytes());
    }
    if let Some(scope_head) = bridge.target_member_scope {
        hasher.field("target_member_scope", &scope_head.as_bytes());
    }
    if let Some(prefix) = bridge.prefix_reference() {
        hasher.field("prefix_reference", &prefix.as_bytes());
    }
    hasher.field(
        "namespace",
        bridge
            .source_demand()
            .namespace()
            .identity_label()
            .as_bytes(),
    );
    for segment in bridge.route() {
        hasher.field("route", &segment.name_digest());
    }
    hasher.field("source_demand", &bridge.source_demand().name_digest());
    hasher.field("target_demand", &bridge.target_demand().name_digest());
    hasher.finish()
}

fn poll_context_work(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work = work
        .checked_add(1)
        .expect("selected context work must fit usize");
    (*work).is_multiple_of(super::engine::CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

#[cfg(test)]
mod tests {
    use crate::analyzer::resolution::fact_lowering::fixture_names::{
        definition_node, reference_node, root_export_token, root_import_anchor_semantic,
        root_import_token, root_reference_token, scope_head_node,
    };

    use std::cell::Cell;

    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, PositionedIdentifierFact, ResolutionBinderFact, ResolutionBinderKind,
        ResolutionIdentifierRole, ResolutionNameFact, ResolutionNameId, ResolutionNamespace,
        ResolutionRootExportFact, ResolutionRootImportAnchor, ResolutionRootImportDemandFact,
        ResolutionRootImportFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
        ResolutionScopeFact, ResolutionScopeId, ResolutionScopeInheritance, ResolutionScopeKind,
        ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use super::super::engine::PreloadedFragmentSource;
    use super::super::fact_lowering::{
        lookup_semantic, root_export_token_identity, root_import_token_identity,
    };
    use super::*;

    fn go_mount_context(ordinal: u32) -> SelectedResolutionMountContext {
        SelectedResolutionMountContext::new(
            SelectedResolutionMountOrdinal::new(ordinal),
            BindingFragmentId::for_test(ordinal.to_be_bytes()),
            Language::Go,
            Vec::new(),
            ResolutionCompletion::Complete,
        )
        .expect("a Go mount needs no Java placement")
    }

    /// The mount table one test operation selected.
    ///
    /// A context set is sparse, so a test hands the table it built over and
    /// asks for the count, the lookup, and the entries the set carries, rather
    /// than materializing one entry per selected mount.
    struct GoMountTable {
        mounts: Vec<SelectedResolutionMountContext>,
    }

    impl From<Vec<SelectedResolutionMountContext>> for GoMountTable {
        fn from(mounts: Vec<SelectedResolutionMountContext>) -> Self {
            Self { mounts }
        }
    }

    impl GoMountTable {
        fn lookup(
            &self,
        ) -> impl Fn(
            BindingFragmentId,
        ) -> StoreResult<Option<(SelectedResolutionMountOrdinal, Language)>>
        + '_ {
            |fragment| {
                Ok(self
                    .mounts
                    .iter()
                    .find(|mount| mount.fragment() == fragment)
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            }
        }

        /// The entries a sparse context set keeps: a mount carries either a
        /// relation or inventory evidence, and nothing else earns an entry.
        fn carried(&self) -> Vec<SelectedResolutionMountContext> {
            self.mounts
                .iter()
                .filter(|mount| {
                    !mount.root_bridges.is_empty()
                        || !matches!(
                            mount.root_reverse_inventory_completion,
                            ResolutionCompletion::Complete
                        )
                })
                .cloned()
                .collect()
        }

        fn context(
            &self,
            sparse: Vec<SelectedResolutionMountContext>,
        ) -> StoreResult<SelectedResolutionContextSet> {
            SelectedResolutionContextSet::new(
                SelectedContextIdentities::new(),
                sparse,
                self.mounts.len(),
                &self.lookup(),
            )
        }
    }

    #[test]
    fn explicitly_owned_context_gap_survives_extension_validation_and_blueprint() {
        use super::super::fact_resolution::SelectedFactOperationBlueprint;
        use super::super::local_identity::{MountRebaser, SelectedSemanticProvenance};
        let generated = SemanticId::for_test(b"selected-context-generated-coverage");
        let source = SemanticId::for_test(b"selected-source-owned-coverage");
        let mut mount = go_mount_context(0);
        mount.root_reverse_inventory_completion = ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(generated),
            ResolutionIncompleteReason::UnsupportedSemantic(source),
        ]);
        let expected = [(mount.ordinal(), mount.fragment(), mount.semantic_language())];
        let completion = mount.root_reverse_inventory_completion.clone();
        let table = GoMountTable::from(vec![mount.clone()]);
        let lookup = table.lookup();
        let context = table
            .context(vec![mount])
            .unwrap()
            .with_context_owned_inventory_reason(generated);
        let cancellation = CancellationToken::new();
        let context = context
            .extend_root_bridges(Vec::new(), &cancellation, None, &lookup)
            .unwrap()
            .expect("live extension preserves context evidence ownership");
        for (in_session, context) in [(false, context.clone()), (true, context)] {
            let session = ResolutionSession::unbounded();
            let validated = if in_session {
                context.validate_exact_mounts_in_session(
                    expected.len(),
                    &table.lookup(),
                    &cancellation,
                    &session,
                )
            } else {
                context.validate_exact_mounts(expected.len(), &table.lookup(), &cancellation)
            }
            .unwrap();
            let SelectedResolutionContextValidationOutcome::Ready(inputs) = validated else {
                panic!("live context validation must complete")
            };
            assert_eq!(inputs.root_reverse_inventory_completion, completion);
            // This test isolates metadata ownership; SQL path publication and
            // token liveness are covered by the actual operation adapter tests.
            let (_, inventory, access, reasons, _, packages, imports) = inputs.into_parts();
            assert!(imports.is_empty());
            assert!(packages.is_empty());
            let blueprint =
                SelectedFactOperationBlueprint::from_publication(SelectedContextPathPublication {
                    token: SelectedContextPathToken::new(1),
                    contextual_reverse_inventory_completion: inventory,
                    declaration_access_source: access,
                    context_owned_gap_identities: reasons,
                    identities: SelectedContextIdentities::new(),
                    shared_semantic_identities: Box::new([]),
                    fragment_local_semantic_identities: Box::new([]),
                });
            assert_eq!(
                blueprint.context_owned_gap_identities(),
                &BTreeSet::from([generated])
            );
            assert_eq!(
                blueprint.contextual_reverse_inventory_completion(),
                &completion
            );
            let names = crate::analyzer::resolution::test_shared_names();
            let mut rebaser = MountRebaser::new();
            for &identity in blueprint.shared_semantic_identities() {
                rebaser.register_shared_semantic(identity);
            }
            for &reason in blueprint.context_owned_gap_identities() {
                rebaser.register_context_owned_semantic(reason, names);
            }
            // The reason keeps the runtime value the completion carries and
            // takes an id no blob published, so a keyed read it reaches
            // matches nothing.
            let Some(SelectedSemanticProvenance::Shared(identity)) =
                rebaser.registered_semantic_provenance(generated)
            else {
                panic!("a context-owned reason registers a shared provenance")
            };
            assert!(
                !identity
                    .shared_name()
                    .expect("a shared provenance names a shared name")
                    .is_interned()
            );
            assert_eq!(
                rebaser.registered_semantic_provenance(source),
                None,
                "raw source evidence must not be guessed into context-owned shared identity"
            );
        }
    }

    #[test]
    #[should_panic(expected = "requires retained inventory evidence")]
    fn context_gap_registration_requires_its_explicit_evidence() {
        // The operation selected one mount, but a mount with a complete
        // inventory and no bridge takes no entry, so no evidence is retained.
        let table = GoMountTable::from(vec![go_mount_context(0)]);
        let context = table.context(Vec::new()).unwrap();
        context.with_context_owned_inventory_reason(SemanticId::for_test(b"absent-context-reason"));
    }

    #[test]
    fn exact_mount_inventory_accumulation_matches_sequential_raw_and_shared_fold() {
        let first = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(b"first"));
        let second =
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(b"second"));
        let empty = ResolutionCompletion::Incomplete(Vec::new().into());
        let raw = ResolutionCompletion::Incomplete(vec![second, first, second].into());
        let shared = ResolutionCompletion::Incomplete(vec![first].into());
        let ResolutionCompletion::Incomplete(shared) = shared else {
            unreachable!()
        };
        let shared =
            ResolutionCompletion::Incomplete(shared.to_shared_with_poll(&mut || false).unwrap());
        for operands in [
            vec![],
            vec![empty.clone()],
            vec![raw.clone()],
            vec![
                ResolutionCompletion::Complete,
                raw.clone(),
                ResolutionCompletion::Complete,
            ],
            vec![empty, raw.clone()],
            vec![shared.clone(), raw.clone(), shared],
        ] {
            let oracle = operands
                .iter()
                .fold(ResolutionCompletion::Complete, |completion, operand| {
                    completion.combine(operand)
                });
            let mounts = operands
                .into_iter()
                .enumerate()
                .map(|(ordinal, completion)| {
                    let mut mount = go_mount_context(ordinal as u32);
                    mount.root_reverse_inventory_completion = completion;
                    mount
                })
                .collect::<Vec<_>>();
            let expected = mounts
                .iter()
                .map(|mount| (mount.ordinal(), mount.fragment(), mount.semantic_language()))
                .collect::<Vec<_>>();
            let table = GoMountTable::from(mounts);
            let context = table.context(table.carried()).unwrap();
            let SelectedResolutionContextValidationOutcome::Ready(inputs) = context
                .validate_exact_mounts(
                    expected.len(),
                    &table.lookup(),
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("uncancelled exact context must publish")
            };
            assert_eq!(inputs.root_reverse_inventory_completion, oracle);
        }
    }

    /// Validating a context against the operation it was built for is
    /// constant work, whatever the inventory size, and it still publishes the
    /// combined reverse inventory evidence of every mount.
    #[test]
    fn exact_mount_validation_charges_constant_work_at_every_inventory_size() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        for count in [1_u32, 32, 256] {
            for limit in [0_usize, 1] {
                let mounts = (0..count)
                    .map(|ordinal| {
                        let mut mount = go_mount_context(ordinal);
                        mount.root_reverse_inventory_completion =
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(
                                    SemanticId::for_test(ordinal.to_be_bytes()),
                                ),
                                ResolutionIncompleteReason::UnsupportedSemantic(
                                    SemanticId::for_test(b"shared"),
                                ),
                            ]);
                        mount
                    })
                    .collect::<Vec<_>>();
                let oracle =
                    mounts
                        .iter()
                        .fold(ResolutionCompletion::Complete, |completion, mount| {
                            completion.combine(&mount.root_reverse_inventory_completion)
                        });
                let expected = mounts
                    .iter()
                    .map(|mount| (mount.ordinal(), mount.fragment(), mount.semantic_language()))
                    .collect::<Vec<_>>();
                let session = ResolutionSession::bounded(
                    ReceiverAnalysisBudget {
                        max_scope_nodes: limit,
                        ..ReceiverAnalysisBudget::default()
                    },
                    None,
                );
                let table = GoMountTable::from(mounts);
                let outcome = table
                    .context(table.carried())
                    .unwrap()
                    .validate_exact_mounts_in_session(
                        expected.len(),
                        &table.lookup(),
                        &CancellationToken::default(),
                        &session,
                    )
                    .unwrap();
                match outcome {
                    SelectedResolutionContextValidationOutcome::Ready(inputs) => {
                        assert_eq!(limit, 1);
                        assert_eq!(inputs.root_reverse_inventory_completion, oracle);
                    }
                    SelectedResolutionContextValidationOutcome::Cancelled => {
                        assert_eq!(limit, 0);
                    }
                }
                assert_eq!(session.finish(()).work().scope_nodes, limit);
            }
        }
    }

    #[test]
    fn exact_mount_inventory_reason_cancellation_publishes_no_context() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        let mut mount = go_mount_context(0);
        mount.root_reverse_inventory_completion =
            ResolutionCompletion::incomplete((0_u32..8192).map(|index| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                    index.to_be_bytes(),
                ))
            }));
        let expected = [(mount.ordinal(), mount.fragment(), mount.semantic_language())];
        let table = GoMountTable::from(vec![mount.clone()]);
        let context = table.context(vec![mount]).unwrap();
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        // Validation checks cancellation on entry and again before it
        // publishes. A token that trips on the second check must publish
        // nothing, however large the retained completion operand is.
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        assert!(matches!(
            context
                .validate_exact_mounts_in_session(
                    expected.len(),
                    &table.lookup(),
                    &cancellation,
                    &session
                )
                .unwrap(),
            SelectedResolutionContextValidationOutcome::Cancelled
        ));
        assert_eq!(
            session.finish(()).work().scope_nodes,
            1,
            "validation charges one step whatever the retained evidence holds"
        );
    }

    #[test]
    fn root_bridge_extension_preserves_inventory_and_relation_evidence_at_exact_work_boundary() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        for count in [0_u32, 1, 128] {
            // One step per added bridge, so a budget of the bridge count is
            // exactly enough and the boundary sits there.
            for limit in [count as usize, count as usize + 1] {
                let mut source = go_mount_context(0);
                let target = go_mount_context(1);
                let reason = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                    b"inventory-gap",
                ));
                source.root_reverse_inventory_completion = ResolutionCompletion::Incomplete(
                    if count == 1 {
                        vec![reason, reason]
                    } else {
                        Vec::new()
                    }
                    .into(),
                );
                let demand = ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Value,
                    "Item",
                );
                let bridges = (0..count)
                    .map(|ordinal| {
                        SelectedRootBridgeDescriptor::for_test(
                            source.fragment(),
                            Language::Go,
                            ResolutionSiteId::new(ordinal),
                            ResolutionRootImportAnchor::Lexical,
                            target.fragment(),
                            Language::Go,
                            ResolutionScopeId::new(0),
                            vec![demand.clone()],
                            demand.clone(),
                            demand.clone(),
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(
                                    SemanticId::for_test(ordinal.to_be_bytes()),
                                ),
                            ]),
                        )
                    })
                    .collect::<Vec<_>>();
                let oracle = source.root_reverse_inventory_completion.clone();
                let source_fragment = source.fragment();
                let table = GoMountTable::from(vec![source.clone(), target]);
                let lookup = table.lookup();
                let session = ResolutionSession::bounded(
                    ReceiverAnalysisBudget {
                        max_scope_nodes: limit,
                        ..ReceiverAnalysisBudget::default()
                    },
                    None,
                );
                let result = table
                    .context(vec![source])
                    .unwrap()
                    .extend_root_bridges(
                        bridges.clone(),
                        &CancellationToken::default(),
                        Some(&session),
                        &lookup,
                    )
                    .unwrap();
                let context = result.expect("a budget of one step per added bridge is enough");
                // The target mount carries neither a relation nor evidence of
                // its own, so the sparse set keeps only the source.
                assert_eq!(context.mounts.len(), 1);
                assert_eq!(context.mounts[0].fragment(), source_fragment);
                assert_eq!(context.mounts[0].root_reverse_inventory_completion, oracle);
                assert_eq!(context.mounts[0].root_bridges.as_ref(), bridges.as_slice());
                assert_eq!(session.finish(()).work().scope_nodes, count as usize);
            }
        }
    }

    /// Extending the context set is charged per added bridge, never per
    /// selected mount: two thousand unrelated mounts cost nothing.
    #[test]
    fn root_bridge_extension_charges_per_bridge_over_a_large_mount_inventory() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        let mount_count = 2_048_u32;
        let demand =
            ResolutionLookupSemanticRecipe::new(Language::Go, ResolutionNamespace::Value, "Item");
        let mounts = (0..mount_count).map(go_mount_context).collect::<Vec<_>>();
        // Two selected mounts carry one bridge each; a third is the target of
        // every bridge; the remaining two thousand and forty-five carry
        // nothing at all.
        let target = mounts[3].fragment();
        let sources = [mounts[0].clone(), mounts[1].clone()];
        let bridge = |source: BindingFragmentId, site: u32| {
            SelectedRootBridgeDescriptor::for_test(
                source,
                Language::Go,
                ResolutionSiteId::new(site),
                ResolutionRootImportAnchor::Lexical,
                target,
                Language::Go,
                ResolutionScopeId::new(0),
                vec![demand.clone()],
                demand.clone(),
                demand.clone(),
                ResolutionCompletion::Complete,
            )
        };
        let table = GoMountTable::from(mounts);
        let lookup = table.lookup();
        let context = table
            .context(
                sources
                    .iter()
                    .enumerate()
                    .map(|(index, mount)| {
                        SelectedResolutionMountContext::new(
                            mount.ordinal(),
                            mount.fragment(),
                            mount.semantic_language(),
                            vec![bridge(mount.fragment(), index as u32)],
                            ResolutionCompletion::Complete,
                        )
                        .expect("a bridge is owned by the mount it starts from")
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("two sparse mounts over a large mount table form one context set");
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 20,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        );
        let extended = context
            .extend_root_bridges(
                vec![
                    bridge(sources[0].fragment(), 2),
                    bridge(sources[0].fragment(), 3),
                    bridge(sources[1].fragment(), 4),
                ],
                &CancellationToken::default(),
                Some(&session),
                &lookup,
            )
            .expect("a sparse extension of a large mount table is not a structural error")
            .expect("three added bridges fit a twenty step budget");
        let steps = session.finish(()).work().scope_nodes;
        assert!(
            steps < 20,
            "adding three bridges cost {steps} steps over {mount_count} selected mounts"
        );
        assert_eq!(steps, 3, "one charged step per added bridge");
        assert_eq!(extended.selected_mount_count, mount_count as usize);
        assert_eq!(extended.mounts.len(), 2);
        assert_eq!(
            extended
                .mounts
                .iter()
                .map(SelectedResolutionMountContext::fragment)
                .collect::<Vec<_>>(),
            vec![sources[0].fragment(), sources[1].fragment()]
        );
    }

    #[test]
    fn exact_mount_validation_observes_pre_cancellation_before_the_expected_source() {
        let table = GoMountTable::from(Vec::new());
        let context = table
            .context(Vec::new())
            .expect("an empty selected context is structurally valid");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let must_not_read = |_| -> StoreResult<Option<(SelectedResolutionMountOrdinal, Language)>> {
            panic!("pre-cancelled context validation cannot query its expected source")
        };

        assert!(matches!(
            context
                .validate_exact_mounts(0, &must_not_read, &cancellation)
                .expect("context cancellation is semantic"),
            SelectedResolutionContextValidationOutcome::Cancelled
        ));
    }

    /// A context whose mount count differs from the operation's is the one
    /// mistake a caller can still make, and it is rejected before any work.
    #[test]
    fn exact_mount_validation_rejects_a_context_built_for_another_operation() {
        let mount_count = 300_u32;
        // Every mount is complete and carries no bridge, so the context set is
        // empty over three hundred selected mounts.
        let table = GoMountTable::from((0..mount_count).map(go_mount_context).collect::<Vec<_>>());
        let context = table
            .context(table.carried())
            .expect("ordered Go mounts form one exact selected context");
        let cancellation = CancellationToken::new();
        let expected = (0..mount_count - 1).map(|ordinal| {
            (
                SelectedResolutionMountOrdinal::new(ordinal),
                BindingFragmentId::for_test(ordinal.to_be_bytes()),
                Language::Go,
            )
        });

        let Err(error) =
            context.validate_exact_mounts(expected.len(), &table.lookup(), &cancellation)
        else {
            panic!("a context wider than the operation is a structural error")
        };
        assert!(
            error
                .to_string()
                .contains("more entries than the operation"),
            "{error}"
        );
    }

    #[test]
    fn bridge_compilation_preserves_exact_shared_route_and_mounted_tokens() {
        let source = BindingFragmentId::for_test(b"selected-root-source");
        let target = BindingFragmentId::for_test(b"selected-root-target");
        let route = ResolutionLookupSemanticRecipe::new(
            Language::Go,
            ResolutionNamespace::Value,
            "example.com/dep",
        );
        let source_demand = ResolutionLookupSemanticRecipe::new(
            Language::Go,
            ResolutionNamespace::Value,
            "LocalItem",
        );
        let target_demand =
            ResolutionLookupSemanticRecipe::new(Language::Go, ResolutionNamespace::Value, "Item");
        let bridge = SelectedRootBridgeDescriptor::for_test(
            source,
            Language::Go,
            ResolutionSiteId::new(7),
            ResolutionRootImportAnchor::Lexical,
            target,
            Language::Go,
            ResolutionScopeId::new(0),
            vec![route.clone()],
            source_demand.clone(),
            target_demand.clone(),
            ResolutionCompletion::Complete,
        );
        let identities = SelectedContextIdentities::new();
        let compiled = compile_selected_context_overlay(
            &identities,
            std::slice::from_ref(&bridge),
            crate::analyzer::resolution::test_shared_names(),
            &ResolutionCompletion::Complete,
            &CancellationToken::default(),
        )
        .expect("bridge compilation");
        let SelectedContextOverlayCompilation::Ready(compiled) = compiled else {
            panic!("live bridge compilation cannot cancel");
        };
        assert_eq!(compiled.added_candidate_paths.len(), 1);
        let path = &compiled.added_candidate_paths[0].1;
        assert_eq!(
            path.start()
                .symbols()
                .fixed()
                .iter()
                .map(|symbol| symbol.symbol())
                .collect::<Vec<_>>(),
            vec![
                bridge.source_import_anchor,
                route.semantic(crate::analyzer::resolution::test_shared_names()),
                bridge.source_import_token,
                source_demand.semantic(crate::analyzer::resolution::test_shared_names()),
            ]
        );
        assert_eq!(
            path.end()
                .symbols()
                .fixed()
                .iter()
                .map(|symbol| symbol.symbol())
                .collect::<Vec<_>>(),
            vec![
                target_demand.semantic(crate::analyzer::resolution::test_shared_names()),
                bridge.target_export_token,
            ]
        );
        assert!(path.start().scopes().fixed().is_empty());
        assert!(path.end().scopes().fixed().is_empty());
        let mut expected_shared = vec![
            route.identity(crate::analyzer::resolution::test_shared_names()),
            source_demand.identity(crate::analyzer::resolution::test_shared_names()),
            target_demand.identity(crate::analyzer::resolution::test_shared_names()),
        ];
        expected_shared.sort_unstable();
        expected_shared.dedup();
        assert_eq!(compiled.shared_semantic_identities(), expected_shared);
        assert_eq!(
            compiled.fragment_local_semantic_identities(),
            &[(
                source,
                root_import_anchor_semantic_identity(ResolutionRootImportAnchor::Lexical),
            )]
        );

        let projection_session = ResolutionSession::bounded(Default::default(), None);
        let projection = compile_selected_root_bridge(
            &identities,
            &bridge,
            crate::analyzer::resolution::test_shared_names(),
            &CancellationToken::default(),
            &projection_session,
        )
        .expect("one descriptor compiles for stage publication")
        .expect("live descriptor cannot cancel");
        assert_eq!(projection.lexical.fragment(), source);
        assert_eq!(projection.typed.fragment(), source);
        assert_eq!(
            projection.lexical.paths(),
            &[(compiled.added_candidate_paths[0].0.path(), path.clone())],
            "per-producer publication preserves the existing executable relation"
        );
        assert_eq!(
            projection.local_anchor,
            compiled.fragment_local_semantic_identities()[0]
        );
        assert_eq!(
            projection.recipes,
            [route, source_demand, target_demand]
                .into_iter()
                .map(|recipe| (
                    recipe.semantic(crate::analyzer::resolution::test_shared_names()),
                    recipe
                ))
                .collect::<Vec<_>>()
        );
        let repeated_session = ResolutionSession::bounded(Default::default(), None);
        for _ in 0..2 {
            let repeated = compile_selected_root_bridge(
                &identities,
                &bridge,
                crate::analyzer::resolution::test_shared_names(),
                &CancellationToken::default(),
                &repeated_session,
            )
            .unwrap()
            .unwrap();
            assert_eq!(repeated.identity, projection.identity);
            assert_eq!(repeated.lexical.paths(), projection.lexical.paths());
        }
        assert_eq!(
            repeated_session.finish(()).work().scope_nodes,
            2 * projection_session.finish(()).work().scope_nodes,
            "every derivation is charged before stage admission deduplicates it"
        );
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(
            compile_selected_root_bridge(
                &identities,
                &bridge,
                crate::analyzer::resolution::test_shared_names(),
                &cancelled,
                &ResolutionSession::bounded(Default::default(), None),
            )
            .unwrap()
            .is_none()
        );

        let mut other_target = bridge.clone();
        other_target.target_definition = Some(BindingNodeId::for_test(b"other-target-definition"));
        let compile_set = |bridges: &[SelectedRootBridgeDescriptor]| {
            let SelectedContextOverlayCompilation::Ready(overlay) =
                compile_selected_context_overlay(
                    &SelectedContextIdentities::new(),
                    bridges,
                    crate::analyzer::resolution::test_shared_names(),
                    &ResolutionCompletion::Complete,
                    &CancellationToken::default(),
                )
                .expect("equal derivations form a canonical relation set")
            else {
                panic!("uncancelled relation projection must finish");
            };
            overlay.added_candidate_paths
        };
        // Two compilations are two operations. A path id and a stack variable
        // id are `Operation` identities: the number is the minting
        // operation's own and orders by the order the bridges arrived in, so
        // it says nothing about the relation set. The set therefore compares
        // blind to those numbers, and as a set: sorted, with every other
        // identity -- the fragment-local tokens and the shared route --
        // compared exactly.
        let as_a_set = |paths: &[(CandidatePathIdentity, PartialPath)]| {
            use crate::analyzer::resolution::{OperationBlind, SpliceMount};
            let mut blinded = paths
                .iter()
                .map(|(identity, path)| {
                    format!(
                        "{:?}",
                        (
                            identity.splice(&OperationBlind),
                            path.splice(&OperationBlind)
                        )
                    )
                })
                .collect::<Vec<_>>();
            blinded.sort();
            blinded
        };
        let expected = compile_set(&[bridge.clone(), other_target.clone()]);
        assert_eq!(expected.len(), 2, "different targets must remain distinct");
        assert_eq!(
            as_a_set(&compile_set(&[
                other_target.clone(),
                bridge.clone(),
                other_target,
                bridge.clone(),
            ])),
            as_a_set(&expected),
            "set union must be idempotent and independent of derivation order"
        );
        let single_session = ResolutionSession::bounded(Default::default(), None);
        let duplicate_session = ResolutionSession::bounded(Default::default(), None);
        for (derivations, session) in [
            (vec![bridge.clone()], &single_session),
            (vec![bridge.clone(), bridge.clone()], &duplicate_session),
        ] {
            assert!(matches!(
                compile_selected_context_overlay_in_session(
                    &SelectedContextIdentities::new(),
                    &derivations,
                    crate::analyzer::resolution::test_shared_names(),
                    &ResolutionCompletion::Complete,
                    &CancellationToken::default(),
                    session,
                )
                .expect("charge every input derivation"),
                SelectedContextOverlayCompilation::Ready(_)
            ));
        }
        assert!(
            duplicate_session.finish(()).work().scope_nodes
                > single_session.finish(()).work().scope_nodes
        );

        let mut incomplete = bridge.clone();
        incomplete.completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::for_test(b"different-bridge-evidence"),
            )]);
        assert_eq!(
            compile_bridge(
                &SelectedContextIdentities::new(),
                &bridge,
                crate::analyzer::resolution::test_shared_names()
            )
            .0,
            compile_bridge(
                &SelectedContextIdentities::new(),
                &incomplete,
                crate::analyzer::resolution::test_shared_names()
            )
            .0
        );
        for derivations in [[bridge.clone(), incomplete.clone()], [incomplete, bridge]] {
            let error = compile_selected_context_overlay(
                &SelectedContextIdentities::new(),
                &derivations,
                crate::analyzer::resolution::test_shared_names(),
                &ResolutionCompletion::Complete,
                &CancellationToken::default(),
            )
            .err()
            .expect("different completion cannot collapse under one path identity");
            assert!(error.to_string().contains("conflicting derivations"));
        }
    }

    #[test]
    fn mounted_root_tokens_isolate_duplicate_content_remounts() {
        // Two mounts of one content give one catalog position two runtime
        // ids, which is what keeps two remounts of the same file apart. The
        // pin used to compare a recomputation, `identity.mount(fragment)`,
        // against the helper; a token is a catalog position now, so what it
        // compares is the two mounts.
        let first = 1_u32;
        let second = 2_u32;
        assert_ne!(SemanticId::local(first, 4), SemanticId::local(second, 4));
        assert_eq!(
            SemanticId::local(first, 4).local_key(),
            SemanticId::local(second, 4).local_key(),
            "one content position, two mounts"
        );
    }

    #[test]
    fn canonical_lowered_root_paths_expose_exact_selected_halves() {
        let fragment = BindingFragmentId::for_test(b"selected-root-half-classification");
        let root_scope = ResolutionScopeId::new(0);
        let import_site = ResolutionSiteId::new(0);
        let declaration_site = ResolutionSiteId::new(1);
        let reference_site = ResolutionSiteId::new(2);
        let route_name = ResolutionNameId::new(0);
        let demand_name = ResolutionNameId::new(1);
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: route_name,
                    spelling: "dep".to_owned(),
                },
                ResolutionNameFact {
                    id: demand_name,
                    spelling: "Item".to_owned(),
                },
            ],
            scopes: vec![ResolutionScopeFact {
                id: root_scope,
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                inheritance: ResolutionScopeInheritance::Lexical,
                start_byte: 0,
                end_byte: 20,
            }],
            sites: vec![
                ResolutionSiteFact {
                    id: import_site,
                    scope: root_scope,
                    kind: ResolutionSiteKind::ImportDeclaration,
                    start_byte: 0,
                    end_byte: 8,
                },
                ResolutionSiteFact {
                    id: declaration_site,
                    scope: root_scope,
                    kind: ResolutionSiteKind::TypeDeclaration,
                    start_byte: 9,
                    end_byte: 20,
                },
                ResolutionSiteFact {
                    id: reference_site,
                    scope: root_scope,
                    kind: ResolutionSiteKind::TypeReference,
                    start_byte: 12,
                    end_byte: 16,
                },
            ],
            root_imports: vec![ResolutionRootImportFact {
                site: import_site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
            }],
            root_import_segments: vec![ResolutionRootImportSegmentFact {
                import_site,
                position: 0,
                name: route_name,
            }],
            root_import_demands: vec![ResolutionRootImportDemandFact {
                import_site,
                namespace: ResolutionNamespace::Type,
                name: demand_name,
            }],
            root_references: vec![ResolutionRootReferenceFact {
                reference: reference_site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Absolute,
                prefix_reference: None,
            }],
            root_reference_segments: Vec::new(),
            root_exports: vec![ResolutionRootExportFact {
                root_scope,
                declaration: declaration_site,
                namespace: ResolutionNamespace::Type,
            }],
            identifiers: vec![
                PositionedIdentifierFact {
                    site: declaration_site,
                    name: demand_name,
                    role: ResolutionIdentifierRole::Declaration,
                    namespace: ResolutionNamespace::Type,
                    qualifier: None,
                },
                PositionedIdentifierFact {
                    site: reference_site,
                    name: demand_name,
                    role: ResolutionIdentifierRole::Reference,
                    namespace: ResolutionNamespace::Type,
                    qualifier: None,
                },
            ],
            binders: vec![ResolutionBinderFact {
                declaration: declaration_site,
                scope: root_scope,
                kind: ResolutionBinderKind::Type,
                hoisting: HoistingClass::ScopeWide,
                activation_start: 0,
                activation_end: 20,
            }],
            ..FileResolutionFacts::default()
        };

        let artifact =
            crate::analyzer::resolution::lower_for_test(fragment, Language::Rust, &facts);
        let lowered = artifact.lexical().clone();
        let halves = lowered
            .paths()
            .iter()
            .filter_map(|&(path_id, ref path)| {
                classify_selected_root_path_half(
                    &CatalogRootImportAnchors::new(artifact.identities()),
                    CandidatePathIdentity::new(fragment, path_id),
                    path,
                    &CancellationToken::default(),
                )
                .expect("a fixture's catalog answers its own anchors")
            })
            .collect::<Vec<_>>();

        assert_eq!(halves.len(), 3);
        let source_gap =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Rust,
                    ResolutionNamespace::Type,
                    "source-gap",
                ),
            )]);
        let mut incomplete_reference_count = 0;
        for &(path_id, ref path) in lowered.paths() {
            let Some(half) = classify_selected_root_path_half(
                &CatalogRootImportAnchors::new(artifact.identities()),
                CandidatePathIdentity::new(fragment, path_id),
                path,
                &CancellationToken::default(),
            )
            .expect("a fixture's catalog answers its own anchors") else {
                continue;
            };
            let incomplete_path = path.clone().with_additional_completion(&source_gap);
            let incomplete_half = classify_selected_root_path_half(
                &CatalogRootImportAnchors::new(artifact.identities()),
                CandidatePathIdentity::new(fragment, path_id),
                &incomplete_path,
                &CancellationToken::default(),
            )
            .expect("a fixture's catalog answers its own anchors");
            match half {
                SelectedRootPathHalf::Reference { .. } => {
                    incomplete_reference_count += 1;
                    assert!(
                        matches!(
                            incomplete_half,
                            Some(SelectedRootPathHalf::Reference { .. })
                        ),
                        "incomplete reference evidence must remain selectable"
                    );
                }
                SelectedRootPathHalf::Export { .. } => {
                    let Some(SelectedRootPathHalf::Export {
                        incomplete_reasons, ..
                    }) = incomplete_half
                    else {
                        panic!("incomplete export evidence must remain selectable");
                    };
                    assert!(!incomplete_reasons.is_empty());
                }
                SelectedRootPathHalf::Import { .. } => {
                    assert!(
                        incomplete_half.is_none(),
                        "incomplete import evidence must remain rejected"
                    );
                }
            }
        }
        assert_eq!(incomplete_reference_count, 1);
        let (export_id, export_path) = lowered
            .paths()
            .iter()
            .find(|(_, path)| {
                path.start().node() == BindingNodeId::universal_root()
                    && path.end().node() == definition_node(fragment, declaration_site)
            })
            .expect("canonical export path");
        let export_half = classify_selected_root_path_half(
            &CatalogRootImportAnchors::new(artifact.identities()),
            CandidatePathIdentity::new(fragment, *export_id),
            export_path,
            &CancellationToken::default(),
        )
        .expect("a fixture's catalog answers its own anchors")
        .expect("canonical export half");
        let demand =
            ResolutionLookupSemanticRecipe::new(Language::Rust, ResolutionNamespace::Type, "Item");
        // This bridge composes against a real export half, so it brings the
        // tokens that half carries rather than minting fixture ones: an
        // export token is the blob's catalog position and only the blob can
        // state it.
        let SelectedRootPathHalf::Export {
            token: export_token,
            ..
        } = export_half
        else {
            panic!("the canonical export half is an export");
        };
        let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens(
            fragment,
            Language::Rust,
            root_import_token(fragment, import_site, ResolutionNamespace::Type),
            ResolutionRootImportAnchor::Lexical,
            root_import_anchor_semantic(fragment, ResolutionRootImportAnchor::Lexical),
            fragment,
            Language::Rust,
            export_token,
            vec![ResolutionLookupSemanticRecipe::new(
                Language::Rust,
                ResolutionNamespace::Type,
                "dep",
            )],
            demand.clone(),
            demand,
            ResolutionCompletion::Complete,
        );
        let (_, token_path) = compile_bridge(
            &SelectedContextIdentities::new(),
            &bridge,
            crate::analyzer::resolution::test_shared_names(),
        );
        let composed = token_path
            .concatenate(export_path)
            .expect("canonical bridge and export compose");
        let (_, exact_path) = compile_bridge(
            &SelectedContextIdentities::new(),
            &bridge.clone().with_selected_export(
                crate::analyzer::resolution::test_shared_names(),
                &export_half,
            ),
            crate::analyzer::resolution::test_shared_names(),
        );
        assert_eq!(exact_path.start().node(), composed.start().node());
        assert_eq!(
            exact_path.start().symbols().fixed(),
            composed.start().symbols().fixed()
        );
        assert_eq!(exact_path.end().node(), composed.end().node());
        assert_eq!(
            exact_path.end().symbols().fixed(),
            composed.end().symbols().fixed()
        );
        assert_eq!(exact_path.precedence(), composed.precedence());
        assert_eq!(exact_path.witness(), composed.witness());
        assert_eq!(exact_path.completion(), composed.completion());
        let incomplete_export = export_path.clone().with_additional_completion(&source_gap);
        let incomplete_export_half = classify_selected_root_path_half(
            &CatalogRootImportAnchors::new(artifact.identities()),
            CandidatePathIdentity::new(fragment, *export_id),
            &incomplete_export,
            &CancellationToken::default(),
        )
        .expect("a fixture's catalog answers its own anchors")
        .expect("incomplete export retains its exact authority");
        let incomplete_composed = token_path
            .concatenate(&incomplete_export)
            .expect("bridge and incomplete export compose");
        let (_, incomplete_exact) = compile_bridge(
            &SelectedContextIdentities::new(),
            &bridge.with_selected_export(
                crate::analyzer::resolution::test_shared_names(),
                &incomplete_export_half,
            ),
            crate::analyzer::resolution::test_shared_names(),
        );
        assert_eq!(
            incomplete_exact.completion(),
            incomplete_composed.completion()
        );
        assert_ne!(
            incomplete_exact.completion(),
            &ResolutionCompletion::Complete
        );
        assert!(
            exact_path.concatenate(export_path,).is_err(),
            "an exact endpoint cannot branch through the shared export token again"
        );
        assert!(
            halves.contains(&SelectedRootPathHalf::Import {
                identity: halves
                    .iter()
                    .find_map(|half| match half {
                        SelectedRootPathHalf::Import { identity, .. } => Some(*identity),
                        SelectedRootPathHalf::Reference { .. } => None,
                        SelectedRootPathHalf::Export { .. } => None,
                    })
                    .expect("lowered root import half"),
                route: vec![lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Rust,
                    ResolutionNamespace::Type,
                    "dep"
                )]
                .into_boxed_slice(),
                source_scope_head: scope_head_node(fragment, root_scope),
                anchor: ResolutionRootImportAnchor::Lexical,
                anchor_semantic: root_import_anchor_semantic(
                    fragment,
                    ResolutionRootImportAnchor::Lexical,
                ),
                token: root_import_token(fragment, import_site, ResolutionNamespace::Type),
                demand: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Rust,
                    ResolutionNamespace::Type,
                    "Item"
                ),
            })
        );
        assert!(
            halves.contains(&SelectedRootPathHalf::Export {
                identity: halves
                    .iter()
                    .find_map(|half| match half {
                        SelectedRootPathHalf::Export { identity, .. } => Some(*identity),
                        SelectedRootPathHalf::Import { .. } => None,
                        SelectedRootPathHalf::Reference { .. } => None,
                    })
                    .expect("lowered root export half"),
                demand: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Rust,
                    ResolutionNamespace::Type,
                    "Item"
                ),
                token: root_export_token(fragment, root_scope, ResolutionNamespace::Type),
                definition: definition_node(fragment, declaration_site),
                incomplete_reasons: Box::new([]),
            })
        );
        assert!(
            halves.contains(&SelectedRootPathHalf::Reference {
                identity: halves
                    .iter()
                    .find_map(|half| match half {
                        SelectedRootPathHalf::Reference { identity, .. } => Some(*identity),
                        SelectedRootPathHalf::Import { .. }
                        | SelectedRootPathHalf::Export { .. } => {
                            None
                        }
                    })
                    .expect("lowered direct root reference half"),
                source_reference: reference_node(fragment, reference_site),
                source_scope_head: scope_head_node(fragment, root_scope),
                anchor_semantic: root_import_anchor_semantic(
                    fragment,
                    ResolutionRootImportAnchor::Absolute,
                ),
                lexical_scope_head: None,
                prefix_reference: None,
                route: Vec::new().into_boxed_slice(),
                anchor: ResolutionRootImportAnchor::Absolute,
                token: root_reference_token(fragment, reference_site, ResolutionNamespace::Type),
                demand: lookup_semantic(
                    crate::analyzer::resolution::test_shared_names(),
                    Language::Rust,
                    ResolutionNamespace::Type,
                    "Item"
                ),
            })
        );

        let source = PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let mut visited_imports = Vec::new();
        let every_mount = [SelectedResolutionMountOrdinal::new(0)];
        let import_outcome = visit_selected_root_import_half_pages(
            &SelectedContextIdentities::new(),
            &CatalogRootImportAnchors::new(artifact.identities()),
            &source,
            Some(&every_mount),
            &CancellationToken::new(),
            &mut FactPageVisitor::new(&mut |page| {
                visited_imports.extend_from_slice(page);
                Ok(true)
            }),
        )
        .expect("preloaded root import inventory");
        assert!(import_outcome.is_exhausted());
        assert_eq!(
            visited_imports,
            halves
                .iter()
                .filter(|half| {
                    matches!(
                        half,
                        SelectedRootPathHalf::Import { .. }
                            | SelectedRootPathHalf::Reference { .. }
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        );

        let mut visited_exports = Vec::new();
        let export_outcome = visit_selected_root_export_half_pages(
            &SelectedContextIdentities::new(),
            &CatalogRootImportAnchors::new(artifact.identities()),
            &source,
            Some(&every_mount),
            &CancellationToken::new(),
            &mut FactPageVisitor::new(&mut |page| {
                visited_exports.extend_from_slice(page);
                Ok(true)
            }),
        )
        .expect("preloaded root export inventory");
        assert!(export_outcome.is_exhausted());
        assert_eq!(
            visited_exports,
            halves
                .iter()
                .filter(|half| matches!(half, SelectedRootPathHalf::Export { .. }))
                .cloned()
                .collect::<Vec<_>>()
        );
    }
}
