//! Native Rust qualified-route prefix evidence.
//!
//! A bare `prefix::member` route is admitted to selected continuation only
//! after the positioned prefix reference has gone through the common lexical
//! Type graph. This module keeps the small operation-local contract shared by
//! the selected Rust operation and its topology adapter; it does not inspect
//! source text or choose a module by spelling.

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;
use crate::analyzer::resolution::{
    BatchResolutionFragmentSource, BindingNodeId, FactResolutionAnswer,
    MAX_REFERENCE_SEEDS_PER_BATCH, ResolutionBatchMetrics, ResolutionCompletion,
    ResolutionIncompleteReason, SelectedFactOperationBlueprint, SelectedRootPathHalf,
    SelectedTypedFactSource, SemanticId,
};
use crate::analyzer::store::Result as StoreResult;

/// The structured prefix metadata attached to one selected root reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RustQualifiedPrefix {
    pub(crate) reference: SemanticId,
    pub(crate) lexical_scope_head: BindingNodeId,
    pub(crate) route: Box<[SemanticId]>,
}

/// Prefix binding evidence retained independently of selected continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RustQualifiedPrefixResolution {
    pub(crate) targets: Box<[SemanticId]>,
    pub(crate) completion: ResolutionCompletion,
}

pub(crate) fn rust_qualified_prefix(half: &SelectedRootPathHalf) -> Option<RustQualifiedPrefix> {
    let SelectedRootPathHalf::Reference {
        prefix_reference: Some(reference),
        lexical_scope_head: Some(lexical_scope_head),
        route,
        ..
    } = half
    else {
        return None;
    };
    Some(RustQualifiedPrefix {
        reference: *reference,
        lexical_scope_head: *lexical_scope_head,
        route: route.clone(),
    })
}

/// Classify the answer for a positioned Rust route prefix.
///
/// The caller obtains `answer` by resolving the canonical prefix semantic in
/// the selected native graph. A Type namespace is an invariant of the Rust
/// producer/fact lowerer; assert it here so a topology adapter cannot silently
/// reinterpret a value or const-generic binding as a module route.
pub(crate) fn resolve_rust_type_prefix(
    answer: &FactResolutionAnswer,
) -> RustQualifiedPrefixResolution {
    let metadata = answer
        .site_metadata()
        .expect("native Rust prefix resolution retains site metadata");
    assert_eq!(
        metadata.namespace(),
        ResolutionNamespace::Type,
        "native Rust bare-route prefix must resolve in the Type namespace"
    );
    RustQualifiedPrefixResolution {
        targets: answer.binding().targets().to_vec().into_boxed_slice(),
        // Module continuation consumes declaration identity, not a nominal
        // runtime type projection. The canonical module-edge join below
        // separately rejects type parameters and other nonmodule targets.
        completion: answer.binding().completion().clone(),
    }
}

/// Whether a resolved route prefix left the indexed workspace.
///
/// The prefix named no target, and the only thing it did answer is either a
/// finished selection or the external boundary itself. Both mean the same
/// thing to the terminal below it: the module this path passes through is not
/// in the index, so the terminal is beyond a boundary rather than absent from
/// a world the route proved.
///
/// The second arm is the one that was missing. `use std::path::Path;` claims
/// `ExternalDeclaredUnindexed` on the import, so the `Path` prefix of
/// `Path::new` answers that boundary rather than `Complete`; the terminal then
/// restated the same question as two coarse `UnsupportedSemantic` reasons,
/// which is what defeated the all-boundary predicate in
/// `rust/native_points.rs` and made an import-bound external callee answer
/// `incomplete` instead of `unresolvable_import_boundary` (#2596). A boundary
/// is the whole answer wherever the route establishes it, not only where this
/// half is the one that claims it.
pub(crate) fn rust_prefix_left_the_workspace(resolved: &RustQualifiedPrefixResolution) -> bool {
    resolved.targets.is_empty()
        && match &resolved.completion {
            ResolutionCompletion::Complete => true,
            ResolutionCompletion::Incomplete(reasons) => reasons.iter().all(|reason| {
                matches!(
                    reason,
                    ResolutionIncompleteReason::OpenBoundary {
                        status:
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                        ..
                    }
                )
            }),
        }
}

/// One evaluation's Rust prefix resolutions, keyed by the reference site each
/// was evaluated for. The session and non-session entry points return the same
/// shape, so it is named once here.
pub(crate) type RustPrefixResolutionBatch = Box<[(SemanticId, RustQualifiedPrefixResolution)]>;

/// Resolve every demanded bare-route prefix against one immutable selected
/// blueprint. The source and typed adapters are shared for the whole batch;
/// no route spelling is consulted while deciding whether a prefix is a Type.
pub(crate) fn resolve_rust_type_prefixes(
    blueprint: &SelectedFactOperationBlueprint,
    source: &dyn BatchResolutionFragmentSource,
    paths: &dyn crate::analyzer::resolution::SelectedContextPathSource,
    typed: &dyn SelectedTypedFactSource,
    prefixes: &[RustQualifiedPrefix],
    cancellation: &CancellationToken,
) -> StoreResult<Option<RustPrefixResolutionBatch>> {
    let mut references = prefixes
        .iter()
        .map(|prefix| prefix.reference)
        .collect::<Vec<_>>();
    references.sort_unstable();
    references.dedup();
    let trace = crate::profiling::enabled();
    if trace {
        crate::profiling::note(format!(
            "selected Rust prefix root count={}",
            references.len()
        ));
    }
    let session = ResolutionSession::unbounded();
    blueprint.with_forward_operation_in_session(
        source,
        paths,
        typed,
        cancellation,
        &session,
        |operation| {
            let mut resolutions = Vec::with_capacity(references.len());
            for (ordinal, references) in
                references.chunks(MAX_REFERENCE_SEEDS_PER_BATCH).enumerate()
            {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                // Keep startup samples and bounded progress intervals even
                // when a workspace contains hundreds of thousands of roots.
                let sample = trace && (ordinal.is_power_of_two() || ordinal % 16 == 0);
                let timing = sample.then(|| {
                    crate::profiling::scope(format!("rust_selected::prefix_batch::{ordinal}"))
                });
                let mut metrics = ResolutionBatchMetrics::default();
                let batch = operation.resolve_references_with_metrics(references, &mut metrics)?;
                if sample {
                    crate::profiling::note(format!("prefix batch {ordinal}: {metrics:?}"));
                }
                drop(timing);
                if batch
                    .completion()
                    .contains_reason(ResolutionIncompleteReason::Cancelled)
                {
                    return Ok(None);
                }
                for answer in batch.answers() {
                    resolutions.push((
                        answer.reference(),
                        resolve_rust_type_prefix(answer.answer()),
                    ));
                }
            }
            Ok(Some(resolutions.into_boxed_slice()))
        },
    )
}
