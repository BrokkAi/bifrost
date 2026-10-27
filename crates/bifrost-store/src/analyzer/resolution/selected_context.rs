//! Operation-local context shared by language-specific selected placement.
//!
//! Content lowering owns the two fragment-local halves of a root route. This
//! module owns only the exact selected-context bridge between them. Keeping
//! the canonical route in the symbol stack makes a bridge self-describing to
//! forward and reverse stitching; no caller provenance is attached to a batch
//! candidate request.

#[doc(hidden)]
pub mod go_import;
#[doc(hidden)]
pub mod package;
pub(crate) use go_import::SelectedGoImportBindingDescriptor;

pub(crate) use package::SelectedPackageBridgeDescriptor;

use super::canonical_identity::CanonicalIdentityDescriptor;
use super::canonical_identity::CanonicalIdentityPart;

use std::collections::BTreeSet;

use std::sync::Arc;

use brokk_bifrost_core::analyzer::Language;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;

use crate::analyzer::store::Result as StoreResult;
use crate::analyzer::store::StoreError;

use crate::hash::HashMap;

use super::batch::BatchCandidateCompletionOutcome;
use super::batch::BatchCandidateMatch;
use super::batch::BatchCandidateRequest;
use super::batch::BatchResolutionFragmentSource;
use super::batch::CandidatePathIdentity;
use super::batch::ReverseCandidateGapIdentity;

#[cfg(test)]
use super::fact_lowering::root_reference_token;

use super::fact_lowering::root_export_token;
use super::fact_lowering::root_import_anchor_semantic;
use super::fact_lowering::root_import_anchor_semantic_identity;
use super::fact_lowering::root_import_token;
use super::fact_lowering::scope_head_node;

use super::fact_source::FactPageVisitor;
use super::fact_source::FactReadOutcome;
use super::fact_source::SelectedDeclarationAccessSource;
use super::fact_source::language_identity_domain;

use super::local_identity::ResolutionLookupSemanticRecipe;
use super::local_identity::ResolutionSemanticIdentity;
use super::local_identity::SelectedResolutionMountOrdinal;
use super::local_identity::SharedNameInterner;

use super::model::BindingFragmentId;
use super::model::BindingNodeId;
use super::model::EndpointSignature;
use super::model::PartialPath;
use super::model::PartialPathId;
use super::model::PartialScopedSymbol;
use super::model::PrecedenceStep;
use super::model::ResolutionCompletion;
use super::model::ResolutionIncompleteReason;
use super::model::SemanticId;
use super::model::SharedNameId;
use super::model::StackPattern;
use super::model::StackVariableId;
use super::model::WitnessStep;

/// An immutable context owned by one selected request's private SQL rows.
/// Only the store allocator creates tokens; they never enter cached answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct SelectedContextPathToken(#[doc(hidden)] pub i64);

impl SelectedContextPathToken {
    pub(crate) fn new(value: i64) -> Self {
        assert!(
            value > 0,
            "context token comes from a positive SQL row identity"
        );
        Self(value)
    }

    #[doc(hidden)]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Read one explicitly selected context's paths without reopening base facts.
/// Context rows live until request teardown and never imply global visibility.
#[doc(hidden)]
pub trait SelectedContextPathSource {
    /// Preserve supplied base coverage, extending it with Cancelled only when
    /// cancellation stops work. Engine consumers own candidate budget charges;
    /// readers preserve page boundaries without charging the supplied session.
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
#[doc(hidden)]
pub enum SelectedRootPathHalf {
    Import {
        identity: CandidatePathIdentity,
        source_scope_head: BindingNodeId,
        route: Box<[SemanticId]>,
        /// The source position at which a positional import takes effect
        /// (Scala). Within one blob, imports are consumed in this order.
        activation: Option<u32>,
        /// The root import's choice point and rank, reused by selected member bridges.
        precedence: Box<[PrecedenceStep]>,
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
        /// The route head owns a continuation without a positioned prefix
        /// reference of its own.
        owner_continued: bool,
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
#[doc(hidden)]
pub trait SelectedRootImportAnchors {
    fn anchor_of(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionRootImportAnchor>>;
}

/// Read root anchors through the existing canonical content authority when a
/// caller has a selected source rather than an artifact catalog. This preserves
/// the same root-path classifier without exposing catalog ordinals as meaning.
pub(crate) struct SourceRootImportAnchors<'source> {
    pub(crate) source: &'source dyn super::batch::BatchResolutionFragmentSource,
}

impl SelectedRootImportAnchors for SourceRootImportAnchors<'_> {
    fn anchor_of(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionRootImportAnchor>> {
        let Some(ordinal) = semantic.ordinal() else {
            return Ok(None);
        };
        let Some(content) = self
            .source
            .identity_content_digest(semantic.into(), cancellation)?
        else {
            return Ok(None);
        };
        let fragment = super::model::BindingFragmentId::at_ordinal(ordinal);
        let Some(mount) = self
            .source
            .identity_content_digest(fragment.into(), cancellation)?
        else {
            return Ok(None);
        };
        Ok([
            ResolutionRootImportAnchor::Lexical,
            ResolutionRootImportAnchor::Absolute,
        ]
        .into_iter()
        .find(|anchor| {
            super::canonical_identity::mounted_identity_digest(
                b"semantic",
                mount,
                root_import_anchor_semantic_identity(*anchor).fragment_local_digest(),
            ) == content
        }))
    }
}

/// The root-import anchors of one lowered artifact, answered from its own
/// identity catalog.
///
/// A lowered artifact's ids are its catalog's positions, so the catalog says
/// directly which identity a semantic is, and this compares that against the
/// two anchor identities. It is what a caller holding an artifact uses where
/// the store's caller uses the selected source.
#[doc(hidden)]
pub struct CatalogRootImportAnchors<'catalog> {
    catalog: &'catalog super::local_identity::ResolutionIdentityCatalog,
}

impl<'catalog> CatalogRootImportAnchors<'catalog> {
    #[doc(hidden)]
    pub const fn new(catalog: &'catalog super::local_identity::ResolutionIdentityCatalog) -> Self {
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
        Ok(super::root_import_anchor_for_identity(&identity))
    }
}

/// Both source-half forms require the endpoint's first symbol to be a
/// published import anchor. Discovery uses this same guard to prove that an
/// eligible shared domain cannot match either source-half form.
pub(crate) fn selected_root_source_anchor(
    anchors: &dyn SelectedRootImportAnchors,
    endpoint: &EndpointSignature,
    cancellation: &CancellationToken,
) -> StoreResult<Option<ResolutionRootImportAnchor>> {
    let Some(first) = endpoint.symbols().fixed().first() else {
        return Ok(None);
    };
    anchors.anchor_of(first.symbol(), cancellation)
}

#[doc(hidden)]
pub fn classify_selected_root_path_half(
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
        || !super::endpoint_has_empty_scopes(path.start())
        || !super::endpoint_has_empty_scopes(path.end())
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
        // Activation incompleteness is not route incompleteness. Keep a
        // noncancelled import when its anchor, target and route stack retain
        // the structural authority checked below, regardless of its reasons.
        if path.start().node() == root
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
        {
            return Ok(None);
        }
        let source_scope_head = match path.witness() {
            [WitnessStep::Node(witness_root)] if *witness_root == root => path.start().node(),
            [
                WitnessStep::Node(source_scope_head),
                WitnessStep::Node(witness_root),
            ] if *witness_root == root => *source_scope_head,
            _ => return Ok(None),
        };
        let anchor_semantic = end[0].symbol();
        let Some(anchor) = selected_root_source_anchor(anchors, path.end(), cancellation)? else {
            return Ok(None);
        };
        return Ok(Some(SelectedRootPathHalf::Import {
            identity,
            source_scope_head,
            route: end[1..end.len() - 2]
                .iter()
                .map(PartialScopedSymbol::symbol)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            activation: path.root_import_activation(),
            precedence: path.precedence().to_vec().into_boxed_slice(),
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
        let Some(anchor) = selected_root_source_anchor(anchors, path.end(), cancellation)? else {
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
            owner_continued: path.owner_continued(),
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
#[doc(hidden)]
pub fn visit_selected_root_import_half_pages<S>(
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
    visit_selected_root_import_half_pages_for_request(
        anchors,
        source,
        request,
        mounts,
        cancellation,
        visitor,
    )
}

/// Read Go root import halves by the exact terminal targets persisted on that
/// source blob's root-import paths. Qualified references share those terminal
/// names, but this context preparation only consumes import declarations.
pub(crate) fn visit_selected_root_import_half_pages_with_targets<S>(
    context_identities: &SelectedContextIdentities,
    anchors: &dyn SelectedRootImportAnchors,
    source: &S,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    root_terminals: &[SharedNameId],
    cancellation: &CancellationToken,
    visitor: &mut FactPageVisitor<'_, SelectedRootPathHalf>,
) -> StoreResult<FactReadOutcome>
where
    S: BatchResolutionFragmentSource + ?Sized,
{
    let request =
        selected_root_inventory_request(context_identities, b"selected-root-import-inventory");
    visit_selected_root_import_half_pages_for_request(
        anchors,
        source,
        BatchCandidateRequest::with_root_import_terminal_targets(
            request.request_ordinal(),
            request.endpoint().clone(),
            root_terminals.to_vec(),
        ),
        mounts,
        cancellation,
        visitor,
    )
}

fn visit_selected_root_import_half_pages_for_request<S>(
    anchors: &dyn SelectedRootImportAnchors,
    source: &S,
    request: BatchCandidateRequest,
    mounts: Option<&[SelectedResolutionMountOrdinal]>,
    cancellation: &CancellationToken,
    visitor: &mut FactPageVisitor<'_, SelectedRootPathHalf>,
) -> StoreResult<FactReadOutcome>
where
    S: BatchResolutionFragmentSource + ?Sized,
{
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
        PartialPath::end,
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
#[doc(hidden)]
pub fn visit_selected_root_export_half_pages<S>(
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
        PartialPath::start,
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
    offered_endpoint: fn(&PartialPath) -> &EndpointSignature,
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
    let session = visitor
        .resolution_session()
        .or_else(|| source.candidate_admission_session());
    if !super::engine::charge_candidate_requests(session, 1) {
        return Ok(FactReadOutcome::cancelled(super::cancelled_completion()));
    }
    let mut admission_work = 0;
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
            if super::poll_resolution_work(cancellation, &mut admission_work) {
                return Ok(false);
            }
            match super::engine::admit_candidate_pair(
                session,
                request.endpoint(),
                offered_endpoint(&path),
            ) {
                Some(true) => {}
                Some(false) => continue,
                None => {
                    stopped = true;
                    return Ok(false);
                }
            }
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
#[doc(hidden)]
pub struct SelectedResolutionMountContext {
    ordinal: SelectedResolutionMountOrdinal,
    #[doc(hidden)]
    pub fragment: BindingFragmentId,
    semantic_language: Language,
    #[doc(hidden)]
    pub root_bridges: Box<[SelectedRootBridgeDescriptor]>,
    package_bridges: Box<[SelectedPackageBridgeDescriptor]>,
    go_import_bindings: Box<[SelectedGoImportBindingDescriptor]>,
    #[doc(hidden)]
    pub root_reverse_inventory_completion: ResolutionCompletion,
}

fn has_incomplete_root_inventory(mount: &SelectedResolutionMountContext) -> bool {
    !matches!(
        mount.root_reverse_inventory_completion,
        ResolutionCompletion::Complete
    )
}

impl SelectedResolutionMountContext {
    #[doc(hidden)]
    pub fn new(
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
            if bridge.source_fragment != self.fragment
                || bridge.source_language() != self.semantic_language
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

    #[doc(hidden)]
    pub const fn fragment(&self) -> BindingFragmentId {
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

fn is_jvm_language(language: Language) -> bool {
    matches!(
        language,
        Language::Java | Language::Kotlin | Language::Scala
    )
}

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
#[doc(hidden)]
pub struct SelectedContextIdentities {
    presumed_go_imports:
        Arc<std::sync::Mutex<HashMap<SemanticId, super::UnindexedExternalFrontier>>>,
    numbers: Arc<std::sync::Mutex<super::CanonicalIdentityNumbers>>,
    /// The stable name and evidence of each named incompleteness reason this
    /// context minted, by identity number, so an answer carrying the reason
    /// can say what it is. Bounded like `numbers`: one entry per reason the
    /// context's routes minted.
    named_reasons: Arc<std::sync::Mutex<crate::hash::HashMap<u64, NamedReasonEntry>>>,
    /// Exact unqualified references whose selected crate routes fell through
    /// to a standard prelude item. A reference may be compiled by more than
    /// one selected Cargo target, so retain each selected prelude identity.
    rust_prelude_references:
        Arc<std::sync::Mutex<crate::hash::HashMap<SemanticId, Vec<SemanticId>>>>,
    /// Exact structured import paths that leave the workspace through an
    /// unindexed external type. Paths remain separate across cfg alternatives.
    rust_external_type_import_paths:
        Arc<std::sync::Mutex<crate::hash::HashMap<SemanticId, Vec<Vec<String>>>>>,
    /// Persisted source gap identities whose Java single-type import route was
    /// closed by complete selected package/type rows. This set is request-local
    /// and each entry names one exact source import site.
    java_import_route_gap_reasons: Arc<std::sync::Mutex<BTreeSet<SemanticId>>>,
    jvm: Box<SelectedJvmContextIdentities>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JvmExternalTypeIdentityClaim {
    Provider(SemanticId),
    ImplicitFallback(SemanticId),
}

/// Request-local JVM metadata is grouped to keep ordinary context outcomes
/// compact. Clones share the existing inner identity maps; isolated snapshots
/// still copy their contents.
#[derive(Clone, Debug, Default)]
struct SelectedJvmContextIdentities {
    /// Exact unindexed JVM implicit-provider boundaries and the external type
    /// identity they establish for one spelling. These maps are bounded by the
    /// implicit-root gaps compiled into this selected context.
    jvm_external_type_identities: Arc<std::sync::Mutex<HashMap<SemanticId, SemanticId>>>,
    /// Bare TypeIdentity references whose unindexed implicit roots establish
    /// the same external type identity despite a complete-empty name answer.
    jvm_external_type_identities_by_reference:
        Arc<std::sync::Mutex<HashMap<SemanticId, JvmExternalTypeIdentityClaim>>>,
    /// The boundary to restore when an external-provider type is used for
    /// member enumeration, which remains open even though type equality is
    /// exact.
    jvm_external_type_boundaries: Arc<std::sync::Mutex<HashMap<SemanticId, Vec<SemanticId>>>>,
    /// Provider coordinates retained only for this resolution request and its
    /// demanded external hierarchy. Durable inventory remains in SQLite.
    jvm_external_owners: Arc<std::sync::Mutex<HashMap<SemanticId, super::ExternalOwnerIdentity>>>,
    jvm_supertype_names: Arc<std::sync::Mutex<HashMap<SemanticId, Arc<str>>>>,
    jvm_external_members:
        Arc<std::sync::Mutex<HashMap<SemanticId, (super::ExternalOwnerIdentity, u32)>>>,
}

/// A named incompleteness reason's stable name and its evidence.
type NamedReason = (&'static str, Arc<str>);

/// Immutable lookup provenance belongs to the reason, not to any later proof
/// that a selected binding can discharge it.
#[derive(Clone, Debug)]
struct NamedReasonEntry {
    reason: NamedReason,
    lookup: Option<(BindingFragmentId, SemanticId)>,
}

impl SelectedContextIdentities {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_presumed_go_import(
        &self,
        definition: SemanticId,
        provider: super::UnindexedExternalFrontier,
    ) {
        assert!(
            provider.member.is_none(),
            "an import frontier has no member yet"
        );
        let previous = self
            .presumed_go_imports
            .lock()
            .expect("presumed Go imports are not poisoned")
            .insert(definition, provider.clone());
        assert!(previous.is_none_or(|previous| previous == provider));
    }

    pub(crate) fn has_presumed_go_imports(&self) -> bool {
        !self
            .presumed_go_imports
            .lock()
            .expect("presumed Go imports are not poisoned")
            .is_empty()
    }

    pub(crate) fn presumed_go_import(
        &self,
        definition: SemanticId,
    ) -> Option<super::UnindexedExternalFrontier> {
        self.presumed_go_imports
            .lock()
            .expect("presumed Go imports are not poisoned")
            .get(&definition)
            .cloned()
    }

    /// Whether this request has minted any selected-context identities yet.
    /// A cached context can be restored only into an unused identity space so
    /// its stable numbers cannot collide with values minted by this request.
    pub(crate) fn is_empty(&self) -> bool {
        self.presumed_go_imports
            .lock()
            .expect("presumed Go imports are not poisoned")
            .is_empty()
            && self
                .numbers
                .lock()
                .expect("the selected context's identity table is not poisoned")
                .is_empty()
            && self
                .named_reasons
                .lock()
                .expect("the selected context's named reasons are not poisoned")
                .is_empty()
            && self
                .rust_prelude_references
                .lock()
                .expect("the selected context's Rust prelude table is not poisoned")
                .is_empty()
            && self
                .rust_external_type_import_paths
                .lock()
                .expect("the selected context's Rust external path table is not poisoned")
                .is_empty()
            && self
                .java_import_route_gap_reasons
                .lock()
                .expect("the selected context's Java import reason set is not poisoned")
                .is_empty()
            && self
                .jvm
                .jvm_external_type_identities
                .lock()
                .expect("the selected context's JVM external type identities are not poisoned")
                .is_empty()
            && self
                .jvm
                .jvm_external_type_identities_by_reference
                .lock()
                .expect("the selected context's JVM external reference identities are not poisoned")
                .is_empty()
            && self
                .jvm
                .jvm_external_type_boundaries
                .lock()
                .expect("the selected context's JVM external type boundaries are not poisoned")
                .is_empty()
            && self
                .jvm
                .jvm_supertype_names
                .lock()
                .expect("supertype names are not poisoned")
                .is_empty()
            && self
                .jvm
                .jvm_external_owners
                .lock()
                .expect("external owner coordinates are not poisoned")
                .is_empty()
            && self
                .jvm
                .jvm_external_members
                .lock()
                .expect("external member coordinates are not poisoned")
                .is_empty()
    }

    /// Make an isolated snapshot, preserving every context-local number and
    /// its supporting metadata while allowing later requests to mutate their
    /// own identity table independently.
    pub(crate) fn isolated_clone(&self) -> Self {
        Self {
            presumed_go_imports: Arc::new(std::sync::Mutex::new(self.presumed_go_imports.lock().expect("presumed Go imports are not poisoned").clone())),
            numbers: Arc::new(std::sync::Mutex::new(
                self.numbers
                    .lock()
                    .expect("the selected context's identity table is not poisoned")
                    .clone(),
            )),
            named_reasons: Arc::new(std::sync::Mutex::new(
                self.named_reasons
                    .lock()
                    .expect("the selected context's named reasons are not poisoned")
                    .clone(),
            )),
            rust_prelude_references: Arc::new(std::sync::Mutex::new(
                self.rust_prelude_references
                    .lock()
                    .expect("the selected context's Rust prelude table is not poisoned")
                    .clone(),
            )),
            rust_external_type_import_paths: Arc::new(std::sync::Mutex::new(
                self.rust_external_type_import_paths
                    .lock()
                    .expect("the selected context's Rust external path table is not poisoned")
                    .clone(),
            )),
            java_import_route_gap_reasons: Arc::new(std::sync::Mutex::new(
                self.java_import_route_gap_reasons
                    .lock()
                    .expect("the selected context's Java import reason set is not poisoned")
                    .clone(),
            )),
            jvm: Box::new(SelectedJvmContextIdentities {
            jvm_external_type_identities: Arc::new(std::sync::Mutex::new(
                self.jvm.jvm_external_type_identities
                    .lock()
                    .expect("the selected context's JVM external type identities are not poisoned")
                    .clone(),
            )),
            jvm_external_type_identities_by_reference: Arc::new(std::sync::Mutex::new(
                self.jvm.jvm_external_type_identities_by_reference
                    .lock()
                    .expect(
                        "the selected context's JVM external reference identities are not poisoned",
                    )
                    .clone(),
            )),
            jvm_external_type_boundaries: Arc::new(std::sync::Mutex::new(
                self.jvm.jvm_external_type_boundaries
                    .lock()
                    .expect("the selected context's JVM external type boundaries are not poisoned")
                    .clone(),
            )),
            jvm_supertype_names: Arc::new(std::sync::Mutex::new(
                self.jvm.jvm_supertype_names
                    .lock()
                    .expect("supertype names are not poisoned")
                    .clone(),
            )),
            jvm_external_owners: Arc::new(std::sync::Mutex::new(
                self.jvm.jvm_external_owners
                    .lock()
                    .expect("external owner coordinates are not poisoned")
                    .clone(),
            )),
            jvm_external_members: Arc::new(std::sync::Mutex::new(
                self.jvm.jvm_external_members
                    .lock()
                    .expect("external member coordinates are not poisoned")
                    .clone(),
            )),
            }),
        }
    }

    /// Restore an isolated snapshot into this request's still-empty table.
    /// The caller must rebind the prepared context to this identity space.
    pub(crate) fn copy_from_empty(&self, other: &Self) {
        assert!(
            self.is_empty(),
            "cached context identities restore only into an unused request"
        );
        let other = other.isolated_clone();
        *self
            .presumed_go_imports
            .lock()
            .expect("presumed Go imports are not poisoned") = other
            .presumed_go_imports
            .lock()
            .expect("presumed Go imports are not poisoned")
            .clone();
        *self
            .numbers
            .lock()
            .expect("the selected context's identity table is not poisoned") = other
            .numbers
            .lock()
            .expect("the cached context's identity table is not poisoned")
            .clone();
        *self
            .named_reasons
            .lock()
            .expect("the selected context's named reasons are not poisoned") = other
            .named_reasons
            .lock()
            .expect("the cached context's named reasons are not poisoned")
            .clone();
        *self
            .rust_prelude_references
            .lock()
            .expect("the selected context's Rust prelude table is not poisoned") = other
            .rust_prelude_references
            .lock()
            .expect("the cached context's Rust prelude table is not poisoned")
            .clone();
        *self
            .rust_external_type_import_paths
            .lock()
            .expect("the selected context's Rust external path table is not poisoned") = other
            .rust_external_type_import_paths
            .lock()
            .expect("the cached context's Rust external path table is not poisoned")
            .clone();
        *self
            .java_import_route_gap_reasons
            .lock()
            .expect("the selected context's Java import reason set is not poisoned") = other
            .java_import_route_gap_reasons
            .lock()
            .expect("the cached context's Java import reason set is not poisoned")
            .clone();
        *self
            .jvm
            .jvm_external_type_identities
            .lock()
            .expect("the selected JVM external type identities are not poisoned") = other
            .jvm
            .jvm_external_type_identities
            .lock()
            .expect("the cached JVM external type identities are not poisoned")
            .clone();
        *self
            .jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("the selected JVM external reference identities are not poisoned") = other
            .jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("the cached JVM external reference identities are not poisoned")
            .clone();
        *self
            .jvm
            .jvm_external_type_boundaries
            .lock()
            .expect("the selected JVM external type boundaries are not poisoned") = other
            .jvm
            .jvm_external_type_boundaries
            .lock()
            .expect("the cached JVM external type boundaries are not poisoned")
            .clone();
        *self
            .jvm
            .jvm_supertype_names
            .lock()
            .expect("supertype names are not poisoned") = other
            .jvm
            .jvm_supertype_names
            .lock()
            .expect("cached supertype names are not poisoned")
            .clone();
        *self
            .jvm
            .jvm_external_owners
            .lock()
            .expect("external owner coordinates are not poisoned") = other
            .jvm
            .jvm_external_owners
            .lock()
            .expect("cached external owner coordinates are not poisoned")
            .clone();
        *self
            .jvm
            .jvm_external_members
            .lock()
            .expect("external member coordinates are not poisoned") = other
            .jvm
            .jvm_external_members
            .lock()
            .expect("cached external member coordinates are not poisoned")
            .clone();
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
            && Arc::ptr_eq(
                &self.java_import_route_gap_reasons,
                &other.java_import_route_gap_reasons,
            )
            && Arc::ptr_eq(
                &self.jvm.jvm_external_type_identities,
                &other.jvm.jvm_external_type_identities,
            )
            && Arc::ptr_eq(
                &self.jvm.jvm_external_type_identities_by_reference,
                &other.jvm.jvm_external_type_identities_by_reference,
            )
            && Arc::ptr_eq(
                &self.jvm.jvm_external_type_boundaries,
                &other.jvm.jvm_external_type_boundaries,
            )
            && Arc::ptr_eq(
                &self.jvm.jvm_supertype_names,
                &other.jvm.jvm_supertype_names,
            )
            && Arc::ptr_eq(
                &self.jvm.jvm_external_owners,
                &other.jvm.jvm_external_owners,
            )
            && Arc::ptr_eq(
                &self.jvm.jvm_external_members,
                &other.jvm.jvm_external_members,
            )
    }

    pub(crate) fn contains_operation_number(&self, number: u64) -> bool {
        number
            .checked_sub(super::model::CONTEXT_OPERATION_BASE)
            .and_then(|number| self.content_digest(number))
            .is_some()
    }

    fn number(&self, digest: [u8; 32]) -> u64 {
        let mut numbers = self
            .numbers
            .lock()
            .expect("the selected context's identity table is not poisoned");
        numbers.number(digest)
    }

    pub(crate) fn content_digest(&self, number: u64) -> Option<[u8; 32]> {
        self.numbers
            .lock()
            .expect("the selected context's identity table is not poisoned")
            .digest(number)
    }

    pub(crate) fn semantic(&self, digest: [u8; 32]) -> SemanticId {
        SemanticId::context_local(self.number(digest))
    }

    pub(crate) fn node(&self, digest: [u8; 32]) -> BindingNodeId {
        BindingNodeId::context_local(self.number(digest))
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
            .or_insert_with(|| NamedReasonEntry {
                reason: (name, Arc::from(evidence)),
                lookup: None,
            });
        SemanticId::context_local(number)
    }

    /// The stable name and evidence of a reason this context minted with
    /// [`Self::named_semantic`], or `None` for any other identity.
    pub(crate) fn named_reason(&self, semantic: SemanticId) -> Option<NamedReason> {
        if let Some(name) = self.jvm_supertype_name(semantic) {
            return Some(("UnsupportedHierarchyTraversal", name));
        }
        if !semantic.is_context_local() {
            return None;
        }
        let number = semantic.operation_local_number()? & !super::model::CONTEXT_OPERATION_BASE;
        self.named_reasons
            .lock()
            .expect("the selected context's named reasons are not poisoned")
            .get(&number)
            .map(|entry| entry.reason.clone())
    }

    pub(crate) fn record_named_reason_lookup(
        &self,
        reason: SemanticId,
        source: BindingFragmentId,
        lookup: SemanticId,
    ) {
        assert!(
            reason.is_context_local(),
            "a named reason belongs to its context"
        );
        let number = reason
            .operation_local_number()
            .expect("a context-local reason has a local number")
            & !super::model::CONTEXT_OPERATION_BASE;
        let mut reasons = self
            .named_reasons
            .lock()
            .expect("the selected context's named reasons are not poisoned");
        let entry = reasons
            .get_mut(&number)
            .expect("lookup provenance belongs to an already named reason");
        if let Some(previous) = entry.lookup.replace((source, lookup)) {
            assert_eq!(
                previous,
                (source, lookup),
                "one named reason has one source lookup"
            );
        }
    }

    pub(crate) fn named_reason_lookup(
        &self,
        reason: SemanticId,
    ) -> Option<(BindingFragmentId, SemanticId)> {
        if !reason.is_context_local() {
            return None;
        }
        let number = reason.operation_local_number()? & !super::model::CONTEXT_OPERATION_BASE;
        self.named_reasons
            .lock()
            .expect("the selected context's named reasons are not poisoned")
            .get(&number)
            .and_then(|entry| entry.lookup)
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

    pub(crate) fn record_java_import_route_gap_reason(&self, reason: SemanticId) {
        assert!(
            reason.ordinal().is_some() && reason.local_key().is_some(),
            "a Java import route proof closes a selected source gap reason"
        );
        self.java_import_route_gap_reasons
            .lock()
            .expect("the selected Java import route proofs are not poisoned")
            .insert(reason);
    }

    pub(crate) fn java_import_route_gap_reasons(&self) -> BTreeSet<SemanticId> {
        self.java_import_route_gap_reasons
            .lock()
            .expect("the selected Java import route proofs are not poisoned")
            .clone()
    }

    pub(crate) fn record_jvm_supertype_name(&self, reference: SemanticId, name: &str) {
        let mut names = self
            .jvm
            .jvm_supertype_names
            .lock()
            .expect("supertype names are not poisoned");
        if let Some(previous) = names.insert(reference, Arc::from(name)) {
            assert_eq!(
                previous.as_ref(),
                name,
                "one supertype reference or source gap has one structured name"
            );
        }
    }

    pub(crate) fn jvm_supertype_name(&self, reference: SemanticId) -> Option<Arc<str>> {
        self.jvm
            .jvm_supertype_names
            .lock()
            .expect("supertype names are not poisoned")
            .get(&reference)
            .cloned()
    }

    pub(crate) fn external_owner_semantic(
        &self,
        owner: &super::ExternalOwnerIdentity,
        names: &dyn super::SharedNameInterner,
    ) -> SemanticId {
        let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-owner:v1");
        hash.field("provider-id", owner.provider_id.as_bytes());
        hash.field("owner-fqn", owner.owner_fqn.as_bytes());
        let semantic = SemanticId::shared_name(names.intern(hash.finish()));
        let previous = self
            .jvm
            .jvm_external_owners
            .lock()
            .expect("external owner coordinates are not poisoned")
            .insert(semantic, owner.clone());
        assert!(
            previous.is_none_or(|previous| previous == *owner),
            "one external owner semantic has one provider coordinate"
        );
        semantic
    }

    pub(crate) fn external_owner_identity(
        &self,
        semantic: SemanticId,
    ) -> Option<super::ExternalOwnerIdentity> {
        self.jvm
            .jvm_external_owners
            .lock()
            .expect("external owner coordinates are not poisoned")
            .get(&semantic)
            .cloned()
    }

    pub(crate) fn record_external_hierarchy_reference(
        &self,
        reference: SemanticId,
        target: SemanticId,
    ) {
        let old = self
            .jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("external reference identities are not poisoned")
            .insert(reference, JvmExternalTypeIdentityClaim::Provider(target));
        assert!(
            old.is_none_or(|old| old == JvmExternalTypeIdentityClaim::Provider(target)
                || matches!(old, JvmExternalTypeIdentityClaim::ImplicitFallback(_))),
            "one external hierarchy edge identifies one owner"
        );
    }

    pub(crate) fn external_supertype_reference(
        &self,
        owner: &super::ExternalOwnerIdentity,
        ordinal: u32,
        names: &dyn super::SharedNameInterner,
    ) -> SemanticId {
        let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-supertype-edge:v1");
        hash.field("provider-id", owner.provider_id.as_bytes());
        hash.field("owner-fqn", owner.owner_fqn.as_bytes());
        hash.field("parent-ordinal", &ordinal.to_be_bytes());
        SemanticId::shared_name(names.intern(hash.finish()))
    }

    pub(crate) fn external_member_semantic(
        &self,
        owner: &super::ExternalOwnerIdentity,
        ordinal: u32,
        names: &dyn super::SharedNameInterner,
    ) -> SemanticId {
        let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-member:v1");
        hash.field("provider-id", owner.provider_id.as_bytes());
        hash.field("owner-fqn", owner.owner_fqn.as_bytes());
        hash.field("member-ordinal", &ordinal.to_be_bytes());
        let semantic = SemanticId::shared_name(names.intern(hash.finish()));
        let coordinates = (owner.clone(), ordinal);
        let previous = self
            .jvm
            .jvm_external_members
            .lock()
            .expect("external member coordinates are not poisoned")
            .insert(semantic, coordinates.clone());
        assert!(
            previous.is_none_or(|previous| previous == coordinates),
            "one external member semantic has one inventory row"
        );
        semantic
    }

    pub(crate) fn external_member_identity(
        &self,
        semantic: SemanticId,
    ) -> Option<(super::ExternalOwnerIdentity, u32)> {
        self.jvm
            .jvm_external_members
            .lock()
            .expect("external member coordinates are not poisoned")
            .get(&semantic)
            .cloned()
    }

    pub(crate) fn record_jvm_external_provider_type_identity(
        &self,
        source_reference: SemanticId,
        source_boundary: SemanticId,
        identity: SemanticId,
        enumeration_boundary: SemanticId,
    ) {
        assert!(
            identity.shared_name_id().is_some(),
            "an external provider type has one request-shared identity"
        );
        let previous = self
            .jvm
            .jvm_external_type_identities
            .lock()
            .expect("the selected JVM external type identities are not poisoned")
            .insert(source_boundary, identity);
        assert!(
            previous.is_none_or(|previous| previous == identity),
            "one implicit-provider boundary names one external type identity"
        );
        let previous = self
            .jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("the selected JVM external reference identities are not poisoned")
            .insert(
                source_reference,
                JvmExternalTypeIdentityClaim::Provider(identity),
            );
        assert!(
            previous.is_none_or(|previous| previous
                == JvmExternalTypeIdentityClaim::Provider(identity)
                || matches!(previous, JvmExternalTypeIdentityClaim::ImplicitFallback(_))),
            "one TypeIdentity reference names one external provider type"
        );
        self.record_jvm_external_provider_type_boundary(identity, enumeration_boundary);
    }

    /// A complete-empty scope answer may use this provider name as its nominal
    /// type. It is not a declaration and must not redirect hierarchy lookup
    /// when structured resolution has already selected a source declaration.
    pub(crate) fn record_jvm_implicit_nominal_fallback(
        &self,
        source_reference: SemanticId,
        identity: SemanticId,
        enumeration_boundary: SemanticId,
    ) {
        self.jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("the selected JVM external reference identities are not poisoned")
            .entry(source_reference)
            .or_insert(JvmExternalTypeIdentityClaim::ImplicitFallback(identity));
        self.record_jvm_external_provider_type_boundary(identity, enumeration_boundary);
    }

    fn record_jvm_external_provider_type_boundary(
        &self,
        identity: SemanticId,
        enumeration_boundary: SemanticId,
    ) {
        let mut boundaries = self
            .jvm
            .jvm_external_type_boundaries
            .lock()
            .expect("the selected JVM external type boundaries are not poisoned");
        let recorded = boundaries.entry(identity).or_default();
        if !recorded.contains(&enumeration_boundary) {
            recorded.push(enumeration_boundary);
        }
    }

    pub(crate) fn record_jvm_unindexed_import_owner(&self, identity: SemanticId, owner_fqn: &str) {
        assert!(
            identity.shared_name_id().is_some(),
            "an unindexed import type has one request-shared identity"
        );
        let owner = super::ExternalOwnerIdentity {
            provider_id: Arc::from("jvm-unindexed-import"),
            owner_fqn: Arc::from(owner_fqn),
        };
        let previous = self
            .jvm
            .jvm_external_owners
            .lock()
            .expect("external owner coordinates are not poisoned")
            .insert(identity, owner.clone());
        assert!(
            previous.is_none_or(|previous| previous == owner),
            "one unindexed JVM import identity has one owner FQN"
        );
    }

    pub(crate) fn jvm_external_provider_type_identity(
        &self,
        source_boundary: SemanticId,
    ) -> Option<SemanticId> {
        self.jvm
            .jvm_external_type_identities
            .lock()
            .expect("the selected JVM external type identities are not poisoned")
            .get(&source_boundary)
            .copied()
    }

    pub(crate) fn jvm_external_provider_type_identity_for_reference(
        &self,
        source_reference: SemanticId,
    ) -> Option<SemanticId> {
        self.jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("the selected JVM external reference identities are not poisoned")
            .get(&source_reference)
            .and_then(|claim| match claim {
                JvmExternalTypeIdentityClaim::Provider(identity) => Some(*identity),
                JvmExternalTypeIdentityClaim::ImplicitFallback(_) => None,
            })
    }

    pub(crate) fn jvm_implicit_nominal_fallback(
        &self,
        source_reference: SemanticId,
    ) -> Option<SemanticId> {
        self.jvm
            .jvm_external_type_identities_by_reference
            .lock()
            .expect("the selected JVM external reference identities are not poisoned")
            .get(&source_reference)
            .and_then(|claim| match claim {
                JvmExternalTypeIdentityClaim::ImplicitFallback(identity) => Some(*identity),
                JvmExternalTypeIdentityClaim::Provider(_) => None,
            })
    }

    /// Selected provider coordinates or a nominal fallback's enumeration
    /// boundary prove external identity, without claiming a member inventory.
    pub(crate) fn is_jvm_external_type_identity(&self, identity: SemanticId) -> bool {
        self.jvm
            .jvm_external_owners
            .lock()
            .expect("external owner coordinates are not poisoned")
            .contains_key(&identity)
            || self
                .jvm
                .jvm_external_type_boundaries
                .lock()
                .expect("the selected JVM external type boundaries are not poisoned")
                .contains_key(&identity)
    }

    pub(crate) fn jvm_external_provider_type_boundaries(
        &self,
        identity: SemanticId,
    ) -> Vec<SemanticId> {
        self.jvm
            .jvm_external_type_boundaries
            .lock()
            .expect("the selected JVM external type boundaries are not poisoned")
            .get(&identity)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn stack_variable(&self, digest: [u8; 32]) -> StackVariableId {
        StackVariableId::context_local(self.number(digest))
    }
}

#[doc(hidden)]
/// Exact context coverage for one selected operation.
///
/// The set is sparse: a mount appears in `mounts` only when it has at least one
/// root bridge or a root reverse inventory that was not `Complete`. Every
/// selected mount with neither is covered by `selected_mount_count` and
/// answered by [`SelectedMountLookup`], the operation's own mount table. An
/// entry per selected mount made a point request charge work proportional to
/// unrelated inventory instead of to its own relations.
#[derive(Clone)]
#[doc(hidden)]
pub struct SelectedResolutionContextSet {
    /// The mounts that carry something, in strict ordinal order.
    #[doc(hidden)]
    pub mounts: Box<[SelectedResolutionMountContext]>,
    /// How many mounts the operation selected. Validation compares this with
    /// the operation's own mount count.
    selected_mount_count: usize,
    /// Every carried mount's root bridges, in mount order, flattened once at
    /// construction.
    root_bridges: Box<[SelectedRootBridgeDescriptor]>,
    callable_import_boundaries: BTreeSet<BindingNodeId>,
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

#[doc(hidden)]
pub struct SelectedResolutionContextInputs {
    root_bridges: Box<[SelectedRootBridgeDescriptor]>,
    callable_import_boundaries: BTreeSet<BindingNodeId>,
    package_bridges: Box<[SelectedPackageBridgeDescriptor]>,
    go_import_bindings: Box<[SelectedGoImportBindingDescriptor]>,
    root_reverse_inventory_completion: ResolutionCompletion,
    declaration_access_source: Option<Arc<dyn SelectedDeclarationAccessSource>>,
    context_owned_gap_identities: BTreeSet<SemanticId>,
    identities: SelectedContextIdentities,
}

/// Request-owned metadata for paths already published under one explicit token.
/// Candidate bodies and indexes remain in the selected request's SQL rows.
#[derive(Clone)]
#[doc(hidden)]
pub struct SelectedContextPathPublication {
    #[doc(hidden)]
    pub token: SelectedContextPathToken,
    pub(crate) context_digest: [u8; 32],
    pub(crate) callable_static_import_boundaries: Box<[BindingNodeId]>,
    pub(crate) contextual_reverse_inventory_completion: ResolutionCompletion,
    pub(crate) go_package_inventory_complete: Option<bool>,
    pub(crate) go_package_inventory_fragments: HashMap<BindingFragmentId, bool>,
    pub(crate) declaration_access_source: Option<Arc<dyn SelectedDeclarationAccessSource>>,
    pub(crate) context_owned_gap_identities: BTreeSet<SemanticId>,
    pub(crate) identities: SelectedContextIdentities,
    pub(crate) shared_semantic_identities: Box<[ResolutionSemanticIdentity]>,
    pub(crate) fragment_local_semantic_identities:
        Box<[(BindingFragmentId, ResolutionSemanticIdentity)]>,
}

// A transient return value: the ready payload is moved out immediately during
// blueprint construction, so boxing it would add an allocation to every
// publication. The larger variant carries the publication's digest and
// identities inline, which is cheaper here than an indirection.
#[allow(clippy::large_enum_variant)]
#[doc(hidden)]
pub enum SelectedContextPathPublicationOutcome {
    Ready(SelectedContextPathPublication),
    Cancelled {
        contextual_reverse_inventory_completion: ResolutionCompletion,
    },
}

// Validation moves the ready inputs directly into publication; keep them inline.
#[allow(clippy::large_enum_variant)]
#[doc(hidden)]
pub enum SelectedResolutionContextValidationOutcome {
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
    BTreeSet<BindingNodeId>,
);

impl SelectedResolutionContextInputs {
    #[cfg(test)]
    pub(crate) fn root_bridges_for_test(&self) -> &[SelectedRootBridgeDescriptor] {
        &self.root_bridges
    }

    #[doc(hidden)]
    pub fn into_parts(self) -> SelectedResolutionContextParts {
        (
            self.root_bridges,
            self.root_reverse_inventory_completion,
            self.declaration_access_source,
            self.context_owned_gap_identities,
            self.identities,
            self.package_bridges,
            self.go_import_bindings,
            self.callable_import_boundaries,
        )
    }
}

impl SelectedResolutionContextSet {
    /// Publish all authored import binders before lazy member closure begins.
    pub(crate) fn with_callable_imports<'a>(
        mut self,
        language: Language,
        halves: impl IntoIterator<Item = &'a SelectedRootPathHalf>,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<Self> {
        assert!(is_jvm_language(language));
        for half in halves {
            if let SelectedRootPathHalf::Import {
                identity, token, ..
            } = half
            {
                self.callable_import_boundaries
                    .insert(callable_import_boundary(
                        identity.fragment(),
                        language,
                        *token,
                        &self.identities,
                        source,
                        cancellation,
                    )?);
            }
        }
        Ok(self)
    }

    /// Borrow the already prepared descriptor material without another read.
    pub(crate) fn root_bridges(&self) -> &[SelectedRootBridgeDescriptor] {
        &self.root_bridges
    }

    /// Return the identity handle retained by this immutable context.
    pub(crate) fn identity_space(&self) -> SelectedContextIdentities {
        self.identities.clone()
    }

    /// Rebind a cached immutable context to one request's restored identity
    /// table. Cached snapshots preserve the original numeric assignments.
    pub(crate) fn with_identity_space(mut self, identities: SelectedContextIdentities) -> Self {
        self.identities = identities;
        self
    }

    /// Rebind shared symbols in both the sparse mount descriptors and their
    /// flattened compilation inputs. Cached contexts must use the receiving
    /// request's shared-name table, even when it has already minted names.
    pub(crate) fn remap_shared_names(
        &mut self,
        mut remap: impl FnMut(SemanticId) -> StoreResult<SemanticId>,
    ) -> StoreResult<()> {
        for mount in &mut self.mounts {
            for bridge in &mut mount.package_bridges {
                bridge.remap_shared_names(&mut remap)?;
            }
            for binding in &mut mount.go_import_bindings {
                binding.remap_shared_names(&mut remap)?;
            }
        }
        for bridge in &mut self.package_bridges {
            bridge.remap_shared_names(&mut remap)?;
        }
        for binding in &mut self.go_import_bindings {
            binding.remap_shared_names(&mut remap)?;
        }
        Ok(())
    }

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
                .filter(|mount| has_incomplete_root_inventory(mount))
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
            callable_import_boundaries: self.callable_import_boundaries.clone(),
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
    #[doc(hidden)]
    pub fn extend_root_bridges(
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
            callable_import_boundaries,
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
            context.callable_import_boundaries = callable_import_boundaries;
            Some(context)
        })
    }

    #[doc(hidden)]
    pub fn inventory_completion(&self) -> &ResolutionCompletion {
        &self.root_reverse_inventory_completion
    }

    pub(crate) fn qualified_reference_bridges(
        &self,
        source_fragment: BindingFragmentId,
        source_tokens: &[SemanticId],
        source_demands: &[ResolutionLookupSemanticRecipe],
        names: &dyn SharedNameInterner,
    ) -> (
        Vec<SelectedRootBridgeDescriptor>,
        Vec<SelectedPackageBridgeDescriptor>,
    ) {
        let root_bridges = self
            .root_bridges
            .iter()
            .filter(|bridge| {
                bridge.source_fragment() == source_fragment
                    && source_demands.iter().any(|demand| {
                        bridge.source_demand().identity_domain() == demand.identity_domain()
                            && bridge.source_demand().namespace() == demand.namespace()
                            && bridge.source_demand().spelling() == demand.spelling()
                    })
            })
            .cloned()
            .collect();
        let source_lookups = source_demands
            .iter()
            .map(|demand| demand.semantic(names))
            .collect::<Vec<_>>();
        let package_bridges = self
            .package_bridges
            .iter()
            .filter(|bridge| {
                source_tokens.iter().any(|source_token| {
                    bridge.matches_qualified_reference(
                        source_fragment,
                        *source_token,
                        &source_lookups,
                    )
                })
            })
            .cloned()
            .collect();
        (root_bridges, package_bridges)
    }

    /// Add package relations proven by the selected language context. Source
    /// and destination membership are checked by the same constructor used for
    /// the initial context, and cancellation discards the whole extension.
    #[doc(hidden)]
    pub fn extend_package_bridges(
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
            callable_import_boundaries,
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
                    if extra
                        .iter()
                        .any(|bridge| bridge.source_language() != language)
                    {
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
            context.callable_import_boundaries = callable_import_boundaries;
            Some(context)
        })
    }

    #[doc(hidden)]
    pub fn extend_go_import_bindings(
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
            callable_import_boundaries,
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
            context.callable_import_boundaries = callable_import_boundaries;
            Some(context)
        })
    }

    /// Combine contexts built for files in one selected operation. Go's
    /// selected import closure can contain several source packages, each of
    /// which needs its own file-local import and same-package authority.
    #[doc(hidden)]
    pub fn merge(
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
        let mut callable_import_boundaries = self.callable_import_boundaries;
        callable_import_boundaries.extend(other.callable_import_boundaries);
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
        merged.callable_import_boundaries = callable_import_boundaries;
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

    /// Register a context-owned reason that a demand adapter will attach only
    /// to roots matching the reason's structured lookup.
    pub(crate) fn with_context_owned_gap_identity(mut self, reason: SemanticId) -> Self {
        assert!(
            !self.context_owned_gap_identities.contains(&reason),
            "context-owned gap identity must be new to this context"
        );
        self.context_owned_gap_identities.insert(reason);
        self
    }

    #[doc(hidden)]
    pub fn with_additional_context_owned_inventory_reason(mut self, reason: SemanticId) -> Self {
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
    #[doc(hidden)]
    pub fn new(
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
                    .is_none_or(|(_, language)| language != bridge.target_language())
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
            callable_import_boundaries: BTreeSet::new(),
            package_bridges: package_bridges.into_boxed_slice(),
            go_import_bindings: go_import_bindings.into_boxed_slice(),
            root_reverse_inventory_completion,
            context_owned_gap_identities: BTreeSet::new(),
            identities,
            declaration_access_source: None,
        })
    }

    #[doc(hidden)]
    pub fn validate_exact_mounts(
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
            callable_import_boundaries,
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
                callable_import_boundaries,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SelectedJvmBridgeVisibility {
    Public,
    Protected,
    Package,
    /// The selected lexical access region was checked for this caller.
    Scoped,
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SelectedJvmBridgeProvenance {
    StructuredPackageType {
        source_package: SemanticId,
        target_package: SemanticId,
    },
    AliasFact {
        alias: SemanticId,
    },
}

/// Proof carried by an inter-language JVM route. The package and alias
/// identities come from selected structured rows; the dependency digest is
/// minted from the selected source-root/dependency relation that admitted the
/// target. The target is always the authored declaration endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct SelectedJvmBridgeEvidence {
    pub(crate) provenance: SelectedJvmBridgeProvenance,
    pub(crate) source_namespace: ResolutionNamespace,
    pub(crate) target_namespace: ResolutionNamespace,
    pub(crate) visibility: SelectedJvmBridgeVisibility,
    pub(crate) dependency_identity: [u8; 32],
    pub(crate) target_declaration: SemanticId,
    pub(crate) target_definition: BindingNodeId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedBridgeTargetKind {
    Export,
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedRootBridgeDescriptor {
    #[doc(hidden)]
    pub source_fragment: BindingFragmentId,
    #[doc(hidden)]
    pub source_language: Language,
    #[doc(hidden)]
    pub source_import_token: SemanticId,
    #[doc(hidden)]
    pub anchor: ResolutionRootImportAnchor,
    /// The anchor symbol the source half's route starts with, as the source
    /// blob mounted it.
    ///
    /// The bridge's own route starts with exactly this symbol, so the two
    /// halves meet without either recomputing it. It used to be recomputed:
    /// `root_import_anchor_semantic(source_fragment, anchor)` was a pure
    /// function while a mounted id was a digest of its identity, and a
    /// fragment-local id is that blob's catalog position now.
    #[doc(hidden)]
    pub source_import_anchor: SemanticId,
    #[doc(hidden)]
    pub target_fragment: BindingFragmentId,
    #[doc(hidden)]
    pub target_language: Language,
    #[doc(hidden)]
    pub target_export_token: SemanticId,
    /// Exact authorized endpoint, when selection owns declaration-level access.
    /// A token-only destination remains useful for open/unsupported routes.
    #[doc(hidden)]
    pub target_definition: Option<BindingNodeId>,
    target_kind: SelectedBridgeTargetKind,
    precedence: Option<PrecedenceStep>,
    candidate_origin_rank: Option<u32>,
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
    #[doc(hidden)]
    pub prefix_reference: Option<SemanticId>,
    #[doc(hidden)]
    pub route: Box<[ResolutionLookupSemanticRecipe]>,
    #[doc(hidden)]
    pub source_demand: ResolutionLookupSemanticRecipe,
    #[doc(hidden)]
    pub target_demand: ResolutionLookupSemanticRecipe,
    jvm_evidence: Option<SelectedJvmBridgeEvidence>,
    callable_import: Option<SemanticId>,
    #[doc(hidden)]
    pub completion: ResolutionCompletion,
}

impl std::hash::Hash for SelectedRootBridgeDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Preserve the existing export descriptor hash sequence.
        std::hash::Hash::hash(&self.source_fragment, state);
        std::hash::Hash::hash(&self.source_language, state);
        std::hash::Hash::hash(&self.source_import_token, state);
        std::hash::Hash::hash(&self.anchor, state);
        std::hash::Hash::hash(&self.source_import_anchor, state);
        std::hash::Hash::hash(&self.target_fragment, state);
        std::hash::Hash::hash(&self.target_language, state);
        std::hash::Hash::hash(&self.target_export_token, state);
        std::hash::Hash::hash(&self.target_definition, state);
        std::hash::Hash::hash(&self.precedence, state);
        std::hash::Hash::hash(&self.candidate_origin_rank, state);
        std::hash::Hash::hash(&self.target_member_scope, state);
        std::hash::Hash::hash(&self.prefix_reference, state);
        std::hash::Hash::hash(&self.route, state);
        std::hash::Hash::hash(&self.source_demand, state);
        std::hash::Hash::hash(&self.target_demand, state);
        std::hash::Hash::hash(&self.jvm_evidence, state);
        std::hash::Hash::hash(&self.completion, state);
        if let Some(import) = self.callable_import {
            std::hash::Hash::hash(&"callable-import", state);
            std::hash::Hash::hash(&import, state);
        }
        if self.target_kind == SelectedBridgeTargetKind::Member {
            std::hash::Hash::hash(&"selected-member", state);
        }
    }
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
    #[doc(hidden)]
    pub fn for_test(
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
            bytes.extend_from_slice(
                &super::fact_lowering::fixture_names::identity_content_digest(
                    source_fragment.into(),
                )
                .expect("source fixture fragment has canonical content"),
            );
            bytes.extend_from_slice(
                &super::fact_lowering::fixture_names::identity_content_digest(
                    target_fragment.into(),
                )
                .expect("target fixture fragment has canonical content"),
            );
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
    #[doc(hidden)]
    pub fn from_selected_path_tokens(
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
            None,
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
            None,
            completion,
        )
    }

    /// Construct an explicitly proven JVM bridge. Cross-language callers must
    /// supply the selected package/type or JVM-alias identity, dependency
    /// identity, namespace mapping, and visibility result. Matching spelling
    /// alone cannot construct this descriptor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_selected_path_tokens_with_jvm_evidence(
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
        jvm_evidence: SelectedJvmBridgeEvidence,
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
            prefix_reference,
            route,
            source_demand,
            target_demand,
            Some(jvm_evidence),
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
        jvm_evidence: Option<SelectedJvmBridgeEvidence>,
        completion: ResolutionCompletion,
    ) -> Self {
        assert_ne!(
            source_language,
            Language::None,
            "a selected root bridge needs a source semantic language"
        );
        if source_language == target_language {
            assert!(
                jvm_evidence.is_none(),
                "same-language selected root bridges use their language resolver"
            );
        } else {
            let evidence = jvm_evidence.expect(
                "a cross-language selected root bridge needs explicit JVM identity and access evidence",
            );
            assert!(
                is_jvm_language(source_language) && is_jvm_language(target_language),
                "cross-language selected root bridges are limited to the JVM ecosystem"
            );
            assert_eq!(
                evidence.source_namespace,
                source_demand.namespace(),
                "JVM bridge source namespace matches its import demand"
            );
            assert_eq!(
                evidence.target_namespace,
                target_demand.namespace(),
                "JVM bridge target namespace matches its selected declaration"
            );
            assert_eq!(
                evidence.source_namespace, evidence.target_namespace,
                "only identity namespace conversion is admitted by root bridges"
            );
            if evidence.visibility == SelectedJvmBridgeVisibility::Open {
                assert!(
                    matches!(&completion, ResolutionCompletion::Incomplete(_)),
                    "an open JVM visibility result keeps bridge completion incomplete"
                );
            }
        }
        assert_eq!(
            source_demand.identity_domain(),
            language_identity_domain(source_language),
            "selected root bridge source demand identity differs from its language"
        );
        assert_eq!(
            target_demand.identity_domain(),
            language_identity_domain(target_language),
            "selected root bridge target demand identity differs from its language"
        );
        if jvm_evidence.is_none() {
            assert_eq!(
                source_demand.namespace(),
                target_demand.namespace(),
                "same-language selected root bridge demands need one namespace"
            );
        }
        let route = route.into();
        for segment in &route {
            assert_eq!(
                segment.identity_domain(),
                language_identity_domain(source_language),
                "selected root bridge route identity differs from its source language"
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
            target_kind: SelectedBridgeTargetKind::Export,
            precedence: None,
            candidate_origin_rank: None,
            target_member_scope: None,
            prefix_reference,
            route,
            source_demand,
            target_demand,
            jvm_evidence,
            callable_import: None,
            completion,
        }
    }

    /// Only authored JVM import halves grant external callable authority.
    /// Qualified references and lexical receiver paths carry no such premise.
    pub(crate) fn with_callable_import_half(self, half: &SelectedRootPathHalf) -> Self {
        self.with_callable_import_token(match half {
            SelectedRootPathHalf::Import { token, .. } => Some(*token),
            _ => None,
        })
    }

    pub(crate) fn with_callable_import_token(mut self, token: Option<SemanticId>) -> Self {
        if let Some(token) = token {
            assert!(is_jvm_language(self.source_language));
            assert_eq!(token, self.source_import_token);
        }
        self.callable_import = token;
        self
    }

    pub(crate) fn callable_import_boundary(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        self.callable_import
            .map(|token| {
                callable_import_boundary(
                    self.source_fragment(),
                    self.source_language(),
                    token,
                    identities,
                    source,
                    cancellation,
                )
            })
            .transpose()
    }

    #[doc(hidden)]
    pub const fn source_fragment(&self) -> BindingFragmentId {
        self.source_fragment
    }

    #[cfg(test)]
    pub(crate) fn assert_distinct_target_kinds_for_test(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) {
        assert_eq!(self.target_kind, SelectedBridgeTargetKind::Member);
        let mut export = self.clone();
        export.target_kind = SelectedBridgeTargetKind::Export;
        assert_ne!(&export, self, "target proof kind is descriptor data");
        assert_ne!(
            export
                .candidate_identity(identities, source, cancellation)
                .unwrap(),
            self.candidate_identity(identities, source, cancellation)
                .unwrap(),
            "equal fields with different proof kinds cannot share publication/reverse/registration identity"
        );
    }

    pub(crate) fn validate_content_authority(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        bridge_digest(
            b"bifrost-selected-root-bridge-path:v1",
            self,
            identities,
            source,
            cancellation,
        )?;
        Ok(())
    }

    pub(crate) fn candidate_identity(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<CandidatePathIdentity> {
        Ok(CandidatePathIdentity::new(
            self.source_fragment,
            identities.path(bridge_digest(
                b"bifrost-selected-root-bridge-path:v1",
                self,
                identities,
                source,
                cancellation,
            )?),
        ))
    }

    #[doc(hidden)]
    pub const fn source_language(&self) -> Language {
        self.source_language
    }

    #[doc(hidden)]
    pub const fn source_import_token(&self) -> SemanticId {
        self.source_import_token
    }

    #[doc(hidden)]
    pub const fn source_import_anchor(&self) -> SemanticId {
        self.source_import_anchor
    }

    #[doc(hidden)]
    pub const fn anchor(&self) -> ResolutionRootImportAnchor {
        self.anchor
    }

    #[doc(hidden)]
    pub const fn target_fragment(&self) -> BindingFragmentId {
        self.target_fragment
    }

    #[doc(hidden)]
    pub const fn target_language(&self) -> Language {
        self.target_language
    }

    pub(crate) const fn is_member_target(&self) -> bool {
        matches!(self.target_kind, SelectedBridgeTargetKind::Member)
    }

    #[doc(hidden)]
    pub const fn target_definition(&self) -> Option<BindingNodeId> {
        self.target_definition
    }

    pub(crate) const fn precedence(&self) -> Option<PrecedenceStep> {
        self.precedence
    }
    pub(crate) const fn candidate_origin_rank(&self) -> Option<u32> {
        self.candidate_origin_rank
    }

    pub(crate) fn with_precedence(mut self, precedence: Option<PrecedenceStep>) -> Self {
        self.precedence = precedence;
        self
    }

    pub(crate) fn with_candidate_origin_rank(mut self, rank: Option<u32>) -> Self {
        self.candidate_origin_rank = rank;
        self
    }

    /// A selected declaration proves this provider's name binding even when
    /// independent source-access or applicability evidence remains incomplete.
    pub(crate) fn binding_origin_rank(&self) -> Option<u32> {
        let type_name = matches!(
            self.source_demand.namespace(),
            ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
        );
        (type_name || self.completion == ResolutionCompletion::Complete)
            .then_some(self.target_definition.and(self.candidate_origin_rank))
            .flatten()
    }

    pub(crate) const fn jvm_evidence(&self) -> Option<SelectedJvmBridgeEvidence> {
        self.jvm_evidence
    }

    #[doc(hidden)]
    pub const fn target_export_token(&self) -> SemanticId {
        self.target_export_token
    }

    #[doc(hidden)]
    pub const fn prefix_reference(&self) -> Option<SemanticId> {
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
        assert_eq!(
            definition.ordinal(),
            Some(self.target_fragment.ordinal()),
            "a selected export target requires source content authority; intrinsic inventory roots cannot be bridge targets"
        );
        if let Some(evidence) = self.jvm_evidence {
            assert_eq!(
                *definition, evidence.target_definition,
                "JVM bridge evidence names the exact selected authored declaration"
            );
        }
        self.target_definition = Some(*definition);
        self.target_kind = SelectedBridgeTargetKind::Export;
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
        if let Some(evidence) = self.jvm_evidence {
            assert_eq!(
                definition, evidence.target_definition,
                "JVM bridge evidence names the exact selected authored declaration"
            );
        }
        self.target_definition = Some(definition);
        self.target_kind = SelectedBridgeTargetKind::Member;
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

    #[doc(hidden)]
    pub fn route(&self) -> &[ResolutionLookupSemanticRecipe] {
        &self.route
    }

    #[doc(hidden)]
    pub const fn source_demand(&self) -> &ResolutionLookupSemanticRecipe {
        &self.source_demand
    }

    #[doc(hidden)]
    pub const fn target_demand(&self) -> &ResolutionLookupSemanticRecipe {
        &self.target_demand
    }

    #[doc(hidden)]
    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

/// Atomic result of compiling selected context into one lexical overlay.
#[doc(hidden)]
pub enum SelectedContextOverlayCompilation {
    Ready(SelectedContextOverlay),
    Cancelled {
        contextual_reverse_inventory_completion: ResolutionCompletion,
    },
}

/// One language-neutral, operation-local graph delta.
///
#[doc(hidden)]
pub struct SelectedContextOverlay {
    removed_candidate_paths: Box<[CandidatePathIdentity]>,
    removed_reverse_candidate_gaps: Box<[ReverseCandidateGapIdentity]>,
    #[doc(hidden)]
    pub added_candidate_paths: Box<[(CandidatePathIdentity, PartialPath)]>,
    boundary_nodes: Box<[BindingNodeId]>,
    callable_static_import_boundaries: Box<[BindingNodeId]>,
    #[doc(hidden)]
    pub shared_semantic_identities: Box<[ResolutionSemanticIdentity]>,
    #[doc(hidden)]
    pub fragment_local_semantic_identities: Box<[(BindingFragmentId, ResolutionSemanticIdentity)]>,
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
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn add_callable_import_boundaries(&mut self, boundaries: BTreeSet<BindingNodeId>) {
        let mut nodes = self.boundary_nodes.iter().copied().collect::<BTreeSet<_>>();
        nodes.extend(boundaries.iter().copied());
        self.boundary_nodes = nodes.into_iter().collect();
        let mut callable = self
            .callable_static_import_boundaries
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        callable.extend(boundaries);
        self.callable_static_import_boundaries = callable.into_iter().collect();
    }

    #[cfg(any(test, feature = "test-support"))]
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
            let Some(path) = bridge.compile(
                identities,
                &super::engine::PreloadedFragmentSource::new([], []),
                cancellation,
                &session,
            )?
            else {
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

    #[cfg(any(test, feature = "test-support"))]
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
            let Some(path) = bridge.compile(
                identities,
                &super::engine::PreloadedFragmentSource::new([], []),
                cancellation,
                &session,
            )?
            else {
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

    #[doc(hidden)]
    pub fn shared_semantic_identities(&self) -> &[ResolutionSemanticIdentity] {
        &self.shared_semantic_identities
    }

    #[doc(hidden)]
    pub fn fragment_local_semantic_identities(
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
#[doc(hidden)]
pub fn compile_selected_context_overlay(
    source: &dyn BatchResolutionFragmentSource,
    identities: &SelectedContextIdentities,
    bridges: &[SelectedRootBridgeDescriptor],
    names: &dyn SharedNameInterner,
    root_reverse_inventory_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
) -> StoreResult<SelectedContextOverlayCompilation> {
    compile_selected_context_overlay_with_session(
        source,
        identities,
        bridges,
        names,
        root_reverse_inventory_completion,
        cancellation,
        None,
    )
}

#[doc(hidden)]
pub fn compile_selected_context_overlay_in_session(
    source: &dyn BatchResolutionFragmentSource,
    identities: &SelectedContextIdentities,
    bridges: &[SelectedRootBridgeDescriptor],
    names: &dyn SharedNameInterner,
    root_reverse_inventory_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> StoreResult<SelectedContextOverlayCompilation> {
    compile_selected_context_overlay_with_session(
        source,
        identities,
        bridges,
        names,
        root_reverse_inventory_completion,
        cancellation,
        Some(session),
    )
}

fn compile_selected_context_overlay_with_session(
    source: &dyn BatchResolutionFragmentSource,
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
    let mut callable_boundaries = BTreeSet::new();
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
        let candidate = compile_bridge(source, identities, bridge, names, cancellation)?;
        if let Some(boundary) = bridge.callable_import_boundary(identities, source, cancellation)? {
            callable_boundaries.insert(boundary);
        }
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
    overlay.boundary_nodes = callable_boundaries.iter().copied().collect();
    overlay.callable_static_import_boundaries = callable_boundaries.into_iter().collect();
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
    let same_language = bridge.source_language() == bridge.target_language();
    let evidence = bridge.jvm_evidence();
    if same_language && evidence.is_some() {
        return Err(StoreError::new(
            "same-language selected root bridge carries cross-language JVM evidence",
        ));
    }
    if !same_language {
        let Some(evidence) = evidence else {
            return Err(StoreError::new(
                "cross-language selected root bridge lacks structured JVM evidence",
            ));
        };
        if !is_jvm_language(bridge.source_language()) || !is_jvm_language(bridge.target_language())
        {
            return Err(StoreError::new(
                "cross-language selected root bridge leaves the JVM ecosystem",
            ));
        }
        if bridge.target_definition() != Some(evidence.target_definition)
            || bridge.target_member_scope.is_some()
        {
            return Err(StoreError::new(
                "cross-language JVM bridge does not name its exact authored target",
            ));
        }
        if evidence.source_namespace != bridge.source_demand().namespace()
            || evidence.target_namespace != bridge.target_demand().namespace()
            || evidence.source_namespace != evidence.target_namespace
        {
            return Err(StoreError::new(
                "selected JVM bridge namespace conversion disagrees with its demands",
            ));
        }
        if evidence.visibility == SelectedJvmBridgeVisibility::Open
            && matches!(bridge.completion(), ResolutionCompletion::Complete)
        {
            return Err(StoreError::new(
                "open JVM bridge visibility cannot have complete completion",
            ));
        }
    }
    let source_identity_domain = language_identity_domain(bridge.source_language());
    let target_identity_domain = language_identity_domain(bridge.target_language());
    if bridge.source_demand().identity_domain() != source_identity_domain
        || bridge.target_demand().identity_domain() != target_identity_domain
        || (same_language
            && bridge.source_demand().namespace() != bridge.target_demand().namespace())
        || bridge.route().iter().any(|segment| {
            segment.identity_domain() != source_identity_domain
                || segment.namespace()
                    != bridge
                        .prefix_reference()
                        .map_or(bridge.source_demand().namespace(), |_| {
                            ResolutionNamespace::Type
                        })
        })
    {
        return Err(StoreError::new(
            "selected root bridge identity domain differs from its source or target language",
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
#[doc(hidden)]
pub struct SelectedRootBridgeProjection {
    #[doc(hidden)]
    pub identity: [u8; 32],
    #[doc(hidden)]
    pub lexical: super::fact_lowering::LoweredResolutionFragment,
    #[doc(hidden)]
    pub typed: super::typed_fact_lowering::LoweredTypedFragment,
    #[doc(hidden)]
    pub recipes: Vec<(SemanticId, ResolutionLookupSemanticRecipe)>,
    #[doc(hidden)]
    pub local_anchor: (BindingFragmentId, ResolutionSemanticIdentity),
    #[doc(hidden)]
    pub callable_import_boundary: Option<BindingNodeId>,
}

/// Validate and charge every derivation before its publication can deduplicate
/// an already admitted producer. Completion remains part of the path body even
/// though the stable derivation identity deliberately does not hash it.
#[doc(hidden)]
pub fn compile_selected_root_bridge(
    source: &dyn BatchResolutionFragmentSource,
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
    let (candidate, path) = compile_bridge(source, identities, bridge, names, cancellation)?;
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(SelectedRootBridgeProjection {
        callable_import_boundary: bridge.callable_import_boundary(
            identities,
            source,
            cancellation,
        )?,
        identity: bridge_digest(
            b"bifrost-selected-root-bridge-path:v1",
            bridge,
            identities,
            source,
            cancellation,
        )?,
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

#[doc(hidden)]
pub fn compile_bridge(
    source: &dyn BatchResolutionFragmentSource,
    identities: &SelectedContextIdentities,
    bridge: &SelectedRootBridgeDescriptor,
    names: &dyn SharedNameInterner,
    cancellation: &CancellationToken,
) -> StoreResult<(CandidatePathIdentity, PartialPath)> {
    let path_digest = bridge_digest(
        b"bifrost-selected-root-bridge-path:v1",
        bridge,
        identities,
        source,
        cancellation,
    )?;
    let path = identities.path(path_digest);
    let tail = identities.stack_variable(bridge_digest(
        b"bifrost-selected-root-bridge-tail:v1",
        bridge,
        identities,
        source,
        cancellation,
    )?);
    let route = std::iter::once(bridge.source_import_anchor())
        .chain(bridge.prefix_reference())
        .chain(bridge.route().iter().map(|recipe| recipe.semantic(names)))
        .chain([
            bridge.source_import_token(),
            bridge.source_demand().semantic(names),
        ])
        .collect::<Vec<_>>();
    let (end_node, export, mut precedence, mut witness) =
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
                vec![bridge.precedence.unwrap_or(PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic: bridge.target_export_token(),
                })],
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
    if let Some(boundary) = bridge.callable_import_boundary(identities, source, cancellation)? {
        witness.insert(0, WitnessStep::Node(boundary));
    }
    if let Some(rank) = bridge.candidate_origin_rank {
        let semantic = precedence
            .first()
            .map_or(bridge.source_import_token(), |step| step.semantic);
        precedence.push(PrecedenceStep {
            tier: PrecedenceTier::CandidateOriginRank,
            ordinal: rank,
            semantic,
        });
    }
    Ok((
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
        )
        .with_native_import(
            crate::analyzer::resolution::resolution_diagnostics()
                .native_rejection_projection_active()
                .then(|| {
                    Box::new((
                        bridge.source_import_token(),
                        bridge
                            .route()
                            .iter()
                            .map(|recipe| recipe.semantic(names))
                            .chain([bridge.source_demand().semantic(names)])
                            .collect::<Vec<_>>()
                            .into_boxed_slice(),
                    ))
                }),
        ),
    ))
}

fn callable_import_boundary(
    fragment: BindingFragmentId,
    language: Language,
    token: SemanticId,
    identities: &SelectedContextIdentities,
    source: &dyn BatchResolutionFragmentSource,
    cancellation: &CancellationToken,
) -> StoreResult<BindingNodeId> {
    let digest = |key| {
        super::canonical_identity::selected_identity_content_digest(
            identities,
            source,
            key,
            cancellation,
        )
    };
    let mut hasher =
        CanonicalIdentityDescriptor::new(b"bifrost-selected-callable-import-boundary:v1", digest);
    hasher.field("source_fragment", CanonicalIdentityPart::identity(fragment))?;
    hasher.field(
        "source_language",
        CanonicalIdentityPart::Label(language.config_label()),
    )?;
    hasher.field(
        "source_import_token",
        CanonicalIdentityPart::identity(token),
    )?;
    Ok(identities.node(hasher.finish()))
}

fn bridge_digest(
    domain: &[u8],
    bridge: &SelectedRootBridgeDescriptor,
    identities: &SelectedContextIdentities,
    source: &dyn BatchResolutionFragmentSource,
    cancellation: &CancellationToken,
) -> StoreResult<[u8; 32]> {
    let digest = |key| {
        super::canonical_identity::selected_identity_content_digest(
            identities,
            source,
            key,
            cancellation,
        )
    };
    let mut hasher = CanonicalIdentityDescriptor::new(domain, digest);
    hasher.field(
        "source_fragment",
        CanonicalIdentityPart::identity(bridge.source_fragment()),
    )?;
    hasher.field(
        "source_language",
        CanonicalIdentityPart::Label(bridge.source_language().config_label()),
    )?;
    hasher.field(
        "source_import_token",
        CanonicalIdentityPart::identity(bridge.source_import_token()),
    )?;
    hasher.field(
        "anchor",
        CanonicalIdentityPart::Content(match bridge.anchor() {
            ResolutionRootImportAnchor::Lexical => b"lexical",
            ResolutionRootImportAnchor::Absolute => b"absolute",
        }),
    )?;
    hasher.field(
        "target_fragment",
        CanonicalIdentityPart::identity(bridge.target_fragment()),
    )?;
    hasher.field(
        "target_language",
        CanonicalIdentityPart::Label(bridge.target_language().config_label()),
    )?;
    hasher.field(
        "target_export_token",
        CanonicalIdentityPart::identity(bridge.target_export_token()),
    )?;
    if let Some(import) = bridge.callable_import {
        hasher.field("callable_import", CanonicalIdentityPart::identity(import))?;
    }
    if bridge.target_kind == SelectedBridgeTargetKind::Member {
        hasher.field(
            "target_authority",
            CanonicalIdentityPart::Content(b"selected-member"),
        )?;
    }
    if let Some(definition) = bridge.target_definition {
        hasher.field(
            "target_definition",
            CanonicalIdentityPart::identity(definition),
        )?;
    }
    if let Some(rank) = bridge.candidate_origin_rank {
        hasher.field(
            "candidate_origin_rank",
            CanonicalIdentityPart::Content(&rank.to_le_bytes()),
        )?;
    }
    if let Some(precedence) = bridge.precedence {
        hasher.field(
            "precedence_tier",
            CanonicalIdentityPart::Label(precedence.tier.label()),
        )?;
        hasher.field(
            "precedence_ordinal",
            CanonicalIdentityPart::Content(&precedence.ordinal.to_le_bytes()),
        )?;
        hasher.field(
            "precedence_semantic",
            CanonicalIdentityPart::identity(precedence.semantic),
        )?;
    }
    if let Some(scope_head) = bridge.target_member_scope {
        hasher.field(
            "target_member_scope",
            CanonicalIdentityPart::identity(scope_head),
        )?;
    }
    if let Some(prefix) = bridge.prefix_reference() {
        hasher.field("prefix_reference", CanonicalIdentityPart::identity(prefix))?;
    }
    hasher.field(
        "namespace",
        CanonicalIdentityPart::Label(bridge.source_demand().namespace().identity_label()),
    )?;
    for segment in bridge.route() {
        hasher.field(
            "route",
            CanonicalIdentityPart::Content(&segment.name_digest()),
        )?;
    }
    hasher.field(
        "source_demand",
        CanonicalIdentityPart::Content(&bridge.source_demand().name_digest()),
    )?;
    hasher.field(
        "target_demand",
        CanonicalIdentityPart::Content(&bridge.target_demand().name_digest()),
    )?;
    if let Some(evidence) = bridge.jvm_evidence() {
        hasher.field(
            "jvm_source_namespace",
            CanonicalIdentityPart::Label(evidence.source_namespace.identity_label()),
        )?;
        hasher.field(
            "jvm_target_namespace",
            CanonicalIdentityPart::Label(evidence.target_namespace.identity_label()),
        )?;
        hasher.field(
            "jvm_dependency_identity",
            CanonicalIdentityPart::Content(&evidence.dependency_identity),
        )?;
        hasher.field(
            "jvm_target_declaration",
            CanonicalIdentityPart::identity(evidence.target_declaration),
        )?;
        hasher.field(
            "jvm_target_definition",
            CanonicalIdentityPart::identity(evidence.target_definition),
        )?;
        hasher.field(
            "jvm_visibility",
            CanonicalIdentityPart::Content(match evidence.visibility {
                SelectedJvmBridgeVisibility::Public => b"public".as_slice(),
                SelectedJvmBridgeVisibility::Protected => b"protected".as_slice(),
                SelectedJvmBridgeVisibility::Package => b"package".as_slice(),
                SelectedJvmBridgeVisibility::Scoped => b"scoped".as_slice(),
                SelectedJvmBridgeVisibility::Open => b"open".as_slice(),
            }),
        )?;
        match evidence.provenance {
            SelectedJvmBridgeProvenance::StructuredPackageType {
                source_package,
                target_package,
            } => {
                hasher.field(
                    "jvm_provenance",
                    CanonicalIdentityPart::Content(b"structured_package_type"),
                )?;
                hasher.field(
                    "jvm_source_package",
                    CanonicalIdentityPart::identity(source_package),
                )?;
                hasher.field(
                    "jvm_target_package",
                    CanonicalIdentityPart::identity(target_package),
                )?;
            }
            SelectedJvmBridgeProvenance::AliasFact { alias } => {
                hasher.field(
                    "jvm_provenance",
                    CanonicalIdentityPart::Content(b"alias_fact"),
                )?;
                hasher.field("jvm_alias", CanonicalIdentityPart::identity(alias))?;
            }
        }
    }
    Ok(hasher.finish())
}

fn poll_context_work(cancellation: &CancellationToken, work: &mut usize) -> bool {
    super::poll_resolution_work(cancellation, work)
}

#[cfg(test)]
mod tests {
    use crate::analyzer::resolution::selected_context::go_global_support_1::*;

    use crate::analyzer::resolution::fact_lowering::fixture_names::definition_node;
    use crate::analyzer::resolution::fact_lowering::fixture_names::reference_node;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_export_token;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_import_anchor_semantic;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_import_token;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_reference_token;
    use crate::analyzer::resolution::fact_lowering::fixture_names::scope_head_node;

    use std::cell::Cell;

    use brokk_bifrost_core::analyzer::Language;

    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
    use brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootExportFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportDemandFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportKindFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportSegmentFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootReferenceFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeInheritance;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;

    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use super::super::engine::PreloadedFragmentSource;

    use super::super::fact_lowering::lookup_semantic;
    use super::super::fact_lowering::root_export_token_identity;
    use super::super::fact_lowering::root_import_token_identity;

    use super::*;

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "6c35203a7760: context-owned gap identity was lost during validation and blueprint creation"
    )]
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
            let (_, inventory, access, reasons, _, packages, imports, boundaries) =
                inputs.into_parts();
            assert!(boundaries.is_empty());
            assert!(imports.is_empty());
            assert!(packages.is_empty());
            let blueprint =
                SelectedFactOperationBlueprint::from_publication(SelectedContextPathPublication {
                    token: SelectedContextPathToken::new(1),
                    context_digest: [0; 32],
                    callable_static_import_boundaries: Box::new([]),
                    contextual_reverse_inventory_completion: inventory,
                    go_package_inventory_complete: None,
                    go_package_inventory_fragments: HashMap::default(),
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
                rebaser.register_context_owned_semantic(
                    reason,
                    blueprint
                        .context_owned_semantic_digest(reason)
                        .expect("fixture reason content"),
                    names,
                );
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

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "6c35203a7760: context gap registration accepted a reason absent from inventory evidence"
    )]
    #[test]
    #[should_panic(expected = "requires retained inventory evidence")]
    fn context_gap_registration_requires_its_explicit_evidence() {
        // The operation selected one mount, but a mount with a complete
        // inventory and no bridge takes no entry, so no evidence is retained.
        let table = GoMountTable::from(vec![go_mount_context(0)]);
        let context = table.context(Vec::new()).unwrap();
        context.with_context_owned_inventory_reason(SemanticId::for_test(b"absent-context-reason"));
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
    #[test]
    fn jvm_bridge_requires_structured_identity_and_composes_peer_inventory() {
        let source = BindingFragmentId::at_ordinal(0);
        let target = BindingFragmentId::at_ordinal(1);
        let source_demand = ResolutionLookupSemanticRecipe::new(
            Language::Java,
            ResolutionNamespace::Type,
            "Target",
        );
        let target_demand = ResolutionLookupSemanticRecipe::new(
            Language::Kotlin,
            ResolutionNamespace::Type,
            "Target",
        );
        let route =
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "demo");
        let target_definition = definition_node(target, ResolutionSiteId::new(7));
        let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
            source,
            Language::Java,
            SemanticId::for_test(b"java-kotlin-import"),
            ResolutionRootImportAnchor::Absolute,
            SemanticId::for_test(b"java-kotlin-anchor"),
            target,
            Language::Kotlin,
            SemanticId::for_test(b"kotlin-export"),
            None,
            vec![route],
            source_demand,
            target_demand,
            SelectedJvmBridgeEvidence {
                provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package: SemanticId::for_test(b"java-demo-package"),
                    target_package: SemanticId::for_test(b"kotlin-demo-package"),
                },
                source_namespace: ResolutionNamespace::Type,
                target_namespace: ResolutionNamespace::Type,
                visibility: SelectedJvmBridgeVisibility::Public,
                dependency_identity: [7; 32],
                target_declaration: SemanticId::for_test(b"kotlin-target-declaration"),
                target_definition,
            },
            ResolutionCompletion::Complete,
        )
        .with_selected_member_definition(target_definition);
        validate_bridge(&bridge).expect("selected structured JVM route is valid");

        let inventory_gap = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
            b"kotlin-peer-inventory-gap",
        ));
        let mounts = [
            SelectedResolutionMountContext::new(
                SelectedResolutionMountOrdinal::new(0),
                source,
                Language::Java,
                vec![bridge.clone()],
                ResolutionCompletion::Complete,
            )
            .unwrap(),
            SelectedResolutionMountContext::new(
                SelectedResolutionMountOrdinal::new(1),
                target,
                Language::Kotlin,
                Vec::new(),
                ResolutionCompletion::incomplete([inventory_gap]),
            )
            .unwrap(),
        ];
        let context = SelectedResolutionContextSet::new(
            SelectedContextIdentities::new(),
            mounts,
            2,
            &|fragment| match fragment {
                fragment if fragment == source => Ok(Some((
                    SelectedResolutionMountOrdinal::new(0),
                    Language::Java,
                ))),
                fragment if fragment == target => Ok(Some((
                    SelectedResolutionMountOrdinal::new(1),
                    Language::Kotlin,
                ))),
                _ => Ok(None),
            },
        )
        .expect("source and target are both selected mounts");
        assert!(
            context
                .inventory_completion()
                .contains_reason(inventory_gap),
            "a selected peer-language inventory gap remains part of completion"
        );
    }

    #[cfg(test)]
    #[test]
    #[should_panic(
        expected = "a cross-language selected root bridge needs explicit JVM identity and access evidence"
    )]
    fn matching_spelling_cannot_construct_a_cross_language_bridge() {
        let fragment = BindingFragmentId::for_test(b"cross-language-matching-spelling-source");
        let source =
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Same");
        let target = ResolutionLookupSemanticRecipe::new(
            Language::Kotlin,
            ResolutionNamespace::Type,
            "Same",
        );
        let _ = SelectedRootBridgeDescriptor::for_test(
            fragment,
            Language::Java,
            ResolutionSiteId::new(1),
            ResolutionRootImportAnchor::Absolute,
            BindingFragmentId::for_test(b"cross-language-matching-spelling-target"),
            Language::Kotlin,
            ResolutionScopeId::new(0),
            Vec::new(),
            source,
            target,
            ResolutionCompletion::Complete,
        );
    }

    #[cfg(test)]
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

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: activation gaps hid structurally valid Python import routes"
    )]
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
                position: None,
            }],
            root_import_kinds: vec![ResolutionRootImportKindFact {
                import_site,
                kind: ResolutionRootImportKind::Glob,
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
                owner_continued: false,
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
                        matches!(incomplete_half, Some(SelectedRootPathHalf::Import { .. })),
                        "activation incompleteness must retain a structural import route"
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
            &super::super::PreloadedFragmentSource::from_lowered_fragments([]),
            &SelectedContextIdentities::new(),
            &bridge,
            crate::analyzer::resolution::test_shared_names(),
            &CancellationToken::default(),
        )
        .unwrap();
        let composed = token_path
            .concatenate(export_path)
            .expect("canonical bridge and export compose");
        let (_, exact_path) = compile_bridge(
            &super::super::PreloadedFragmentSource::from_lowered_fragments([]),
            &SelectedContextIdentities::new(),
            &bridge.clone().with_selected_export(
                crate::analyzer::resolution::test_shared_names(),
                &export_half,
            ),
            crate::analyzer::resolution::test_shared_names(),
            &CancellationToken::default(),
        )
        .unwrap();
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
            &super::super::PreloadedFragmentSource::from_lowered_fragments([]),
            &SelectedContextIdentities::new(),
            &bridge.with_selected_export(
                crate::analyzer::resolution::test_shared_names(),
                &incomplete_export_half,
            ),
            crate::analyzer::resolution::test_shared_names(),
            &CancellationToken::default(),
        )
        .unwrap();
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
        let import_half = halves
            .iter()
            .find(|half| matches!(half, SelectedRootPathHalf::Import { .. }))
            .expect("lowered root import half");
        let SelectedRootPathHalf::Import {
            activation,
            route,
            source_scope_head,
            anchor,
            precedence,
            anchor_semantic,
            token,
            demand,
            ..
        } = import_half
        else {
            unreachable!();
        };
        assert_eq!(*activation, None);
        assert_eq!(
            route.as_ref(),
            &[lookup_semantic(
                crate::analyzer::resolution::test_shared_names(),
                Language::Rust,
                ResolutionNamespace::Type,
                "dep"
            )]
        );
        assert_eq!(*source_scope_head, scope_head_node(fragment, root_scope));
        assert_eq!(*anchor, ResolutionRootImportAnchor::Lexical);
        assert_eq!(
            precedence
                .iter()
                .map(|step| (step.tier, step.ordinal))
                .collect::<Vec<_>>(),
            [
                (PrecedenceTier::LexicalBinding, 1),
                (PrecedenceTier::LexicalBinding, 0),
                (PrecedenceTier::LexicalBinding, 1),
            ]
        );
        assert_eq!(
            *anchor_semantic,
            root_import_anchor_semantic(fragment, ResolutionRootImportAnchor::Lexical)
        );
        assert_eq!(
            *token,
            root_import_token(fragment, import_site, ResolutionNamespace::Type)
        );
        assert_eq!(
            *demand,
            lookup_semantic(
                crate::analyzer::resolution::test_shared_names(),
                Language::Rust,
                ResolutionNamespace::Type,
                "Item"
            )
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
                owner_continued: false,
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_global_support_1 {
    use crate::analyzer::resolution::engine::PreloadedFragmentSource;

    use crate::analyzer::resolution::fact_lowering::fixture_names::definition_node;
    use crate::analyzer::resolution::fact_lowering::fixture_names::reference_node;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_export_token;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_import_anchor_semantic;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_import_token;
    use crate::analyzer::resolution::fact_lowering::fixture_names::root_reference_token;
    use crate::analyzer::resolution::fact_lowering::fixture_names::scope_head_node;

    use crate::analyzer::resolution::fact_lowering::lookup_semantic;
    use crate::analyzer::resolution::fact_lowering::root_export_token_identity;
    use crate::analyzer::resolution::fact_lowering::root_import_token_identity;

    use crate::analyzer::resolution::selected_context::*;

    use brokk_bifrost_core::analyzer::Language;

    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
    use brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootExportFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportDemandFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportKindFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportSegmentFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootReferenceFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeInheritance;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;

    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use std::cell::Cell;

    #[doc(hidden)]
    pub fn go_mount_context(ordinal: u32) -> SelectedResolutionMountContext {
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
    #[doc(hidden)]
    pub struct GoMountTable {
        mounts: Vec<SelectedResolutionMountContext>,
    }
    impl From<Vec<SelectedResolutionMountContext>> for GoMountTable {
        fn from(mounts: Vec<SelectedResolutionMountContext>) -> Self {
            Self { mounts }
        }
    }
    impl GoMountTable {
        #[doc(hidden)]
        pub fn lookup(
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
        #[doc(hidden)]
        pub fn carried(&self) -> Vec<SelectedResolutionMountContext> {
            self.mounts
                .iter()
                .filter(|mount| {
                    !mount.root_bridges.is_empty() || has_incomplete_root_inventory(mount)
                })
                .cloned()
                .collect()
        }

        #[doc(hidden)]
        pub fn context(
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
}

impl SelectedRootBridgeDescriptor {
    fn charge_retained(&self, heap: &mut crate::analyzer::store::cache_budget::RetainedHeap) {
        heap.slice(&self.route);
        for recipe in &self.route {
            heap.add(recipe.owned_bytes());
        }
        heap.add(self.source_demand.owned_bytes() + self.target_demand.owned_bytes());
        self.completion.charge_retained(heap);
    }
}

impl SelectedResolutionContextSet {
    pub(crate) fn charge_retained(
        &self,
        heap: &mut crate::analyzer::store::cache_budget::RetainedHeap,
    ) {
        // Only Go snapshots currently call this census. They have no retained
        // declaration-access policy; a new consumer must weigh its policy.
        assert!(self.declaration_access_source.is_none());
        heap.slice(&self.mounts);
        for mount in &self.mounts {
            heap.slice(&mount.root_bridges);
            for bridge in &mount.root_bridges {
                bridge.charge_retained(heap);
            }
            heap.slice(&mount.package_bridges);
            for bridge in &mount.package_bridges {
                bridge.charge_retained(heap);
            }
            heap.slice(&mount.go_import_bindings);
            for binding in &mount.go_import_bindings {
                binding.charge_retained(heap);
            }
            mount
                .root_reverse_inventory_completion
                .charge_retained(heap);
        }
        heap.slice(&self.root_bridges);
        for bridge in &self.root_bridges {
            bridge.charge_retained(heap);
        }
        heap.slice(&self.package_bridges);
        for bridge in &self.package_bridges {
            bridge.charge_retained(heap);
        }
        heap.slice(&self.go_import_bindings);
        for binding in &self.go_import_bindings {
            binding.charge_retained(heap);
        }
        self.root_reverse_inventory_completion.charge_retained(heap);
        heap.btree_set(&self.context_owned_gap_identities);
        self.identities.charge_retained(heap);
    }
}

impl SelectedContextIdentities {
    fn charge_retained(&self, heap: &mut crate::analyzer::store::cache_budget::RetainedHeap) {
        heap.arc(&self.numbers, |numbers, heap| {
            numbers
                .lock()
                .expect("identity numbers are not poisoned")
                .charge_retained(heap)
        });
        heap.arc(&self.presumed_go_imports, |imports, heap| {
            let imports = imports.lock().expect("presumed imports are not poisoned");
            heap.map(&imports);
            for provider in imports.values() {
                provider.charge_retained(heap);
            }
        });
        heap.arc(&self.named_reasons, |reasons, heap| {
            let reasons = reasons.lock().expect("named reasons are not poisoned");
            heap.map(&reasons);
            for entry in reasons.values() {
                heap.arc(&entry.reason.1, |_, _| {});
            }
        });
        heap.arc(&self.rust_prelude_references, |references, heap| {
            let references = references
                .lock()
                .expect("prelude references are not poisoned");
            heap.map(&references);
            for values in references.values() {
                heap.vec(values);
            }
        });
        heap.arc(&self.rust_external_type_import_paths, |paths, heap| {
            let paths = paths.lock().expect("external paths are not poisoned");
            heap.map(&paths);
            for paths in paths.values() {
                heap.vec(paths);
                for path in paths {
                    heap.vec(path);
                    for part in path {
                        heap.add(part.capacity());
                    }
                }
            }
        });
        heap.arc(&self.java_import_route_gap_reasons, |reasons, heap| {
            heap.btree_set(&reasons.lock().expect("Java reasons are not poisoned"));
        });
        let jvm = &self.jvm;
        heap.add(std::mem::size_of_val(&**jvm));
        heap.arc(&jvm.jvm_external_type_identities, |values, heap| {
            heap.map(&values.lock().expect("external types are not poisoned"))
        });
        heap.arc(
            &jvm.jvm_external_type_identities_by_reference,
            |values, heap| {
                heap.map(
                    &values
                        .lock()
                        .expect("external type references are not poisoned"),
                )
            },
        );
        heap.arc(&jvm.jvm_external_type_boundaries, |values, heap| {
            let values = values.lock().expect("external boundaries are not poisoned");
            heap.map(&values);
            for value in values.values() {
                heap.vec(value);
            }
        });
        heap.arc(&jvm.jvm_supertype_names, |values, heap| {
            let values = values.lock().expect("supertype names are not poisoned");
            heap.map(&values);
            for value in values.values() {
                heap.arc(value, |_, _| {});
            }
        });
        heap.arc(&jvm.jvm_external_owners, |values, heap| {
            let values = values.lock().expect("external owners are not poisoned");
            heap.map(&values);
            for value in values.values() {
                heap.arc(&value.provider_id, |_, _| {});
                heap.arc(&value.owner_fqn, |_, _| {});
            }
        });
        heap.arc(&jvm.jvm_external_members, |values, heap| {
            let values = values.lock().expect("external members are not poisoned");
            heap.map(&values);
            for (value, _) in values.values() {
                heap.arc(&value.provider_id, |_, _| {});
                heap.arc(&value.owner_fqn, |_, _| {});
            }
        });
    }
}
