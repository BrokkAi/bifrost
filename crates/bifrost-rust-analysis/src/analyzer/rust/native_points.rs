//! Rust point and type consumers of the selected native operation.
//!
//! Source authority, canonical binding identity, and typed completion are
//! established inside the selected operation before public result projection.

use crate::analyzer::rust::RustAnalyzer;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalDefinition;

use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactResolutionAnswer;

use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionSlotValue;

use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustCallerReferenceOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustReferenceAnswer;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustSourceDefinition;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustSourceDefinitionProjection;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustTypeProjection;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ClaimSubjectRole;
use brokk_bifrost_analysis::analyzer::usages::get_definition::{CallApplicationKind, CallEvidence};

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaim;

use brokk_bifrost_analysis::analyzer::usages::get_type::projection_target_kind;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupType;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionNamespace, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use brokk_bifrost_core::path_utils::rel_path_string;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// Query-only native result and the call proof derived during its selection.
pub(crate) type RustDefinitionLookup = (BoundedResolution<DefinitionLookupOutcome>, CallEvidence);

/// Inputs for selected Rust point operations in one source-definition batch.
/// The factory retains overlay masks and content mounts across that batch's
/// selected operations.
pub(crate) struct RustDefinitionOperationFactory<'analyzer> {
    rust: &'analyzer RustAnalyzer,
    snapshots: Arc<brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots>,
    languages: [SelectedResolutionLanguage; 1],
    overlay_inputs: OnceLock<RustDefinitionOverlayInputs>,
}

struct RustDefinitionOverlayInputs {
    masks: Vec<SelectedResolutionOverlayMask>,
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
}

fn diagnostic_json(mut value: serde_json::Value) -> String {
    value.sort_all_objects();
    value.to_string()
}

pub(crate) enum RustDefinitionOperationOpenFailure {
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

impl<'analyzer> RustDefinitionOperationFactory<'analyzer> {
    pub(crate) fn new(
        analyzer: &'analyzer dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        if cancellation.is_cancelled()
            || !rust.inner.workspace_declaration_identities_authoritative()
        {
            return None;
        }
        let snapshots = rust.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        Some(Self {
            rust,
            snapshots,
            languages,
            overlay_inputs: OnceLock::new(),
        })
    }

    pub(crate) fn retain_exclusive_reader(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::store::writer::RetainedExclusiveReader {
        self.rust
            .inner
            .analyzer_store()
            .conn
            .retain_exclusive_reader()
    }

    pub(crate) fn open(
        &self,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        SelectedResolutionOperationOpenOutcome<'analyzer, 'analyzer>,
    > {
        let _perf_open = brokk_bifrost_core::profiling::scope("perf_dispatch::factory_open");
        if self.overlay_inputs.get().is_none() {
            note_rust_definition_overlay_preparation();
            let inputs = match self
                .rust
                .inner
                .selected_rust_resolution_overlay_inputs(self.snapshots.as_ref(), cancellation)?
            {
                SelectedResolutionOverlayInputsOutcome::Ready {
                    masks,
                    content_mounts,
                } => RustDefinitionOverlayInputs {
                    masks,
                    content_mounts,
                },
                SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                    return Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason));
                }
                SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                    return Ok(SelectedResolutionOperationOpenOutcome::Stale(reason));
                }
                SelectedResolutionOverlayInputsOutcome::Cancelled => {
                    return Ok(SelectedResolutionOperationOpenOutcome::Cancelled);
                }
            };
            assert!(
                self.overlay_inputs.set(inputs).is_ok(),
                "selected Rust batch overlay inputs initialize once"
            );
        }
        let overlay_inputs = self
            .overlay_inputs
            .get()
            .expect("selected Rust batch overlay inputs were initialized");
        note_rust_definition_operation_open();
        self.rust
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    self.rust.inner.project(),
                    self.rust.inner.workspace_id(),
                    self.snapshots.as_ref(),
                    &self.languages,
                    &overlay_inputs.masks,
                )
                .with_content_mounts(overlay_inputs.content_mounts.clone()),
                cancellation,
            )
    }

    pub(crate) fn resolve(
        &self,
        operation: &mut SelectedResolutionOperation<'_, '_>,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_rust_definition_in_operation(query, operation)
    }

    pub(crate) fn resolve_with_evidence(
        &self,
        operation: &mut SelectedResolutionOperation<'_, '_>,
        query: BoundedReceiverQuery<'_>,
    ) -> RustDefinitionLookup {
        let mut evidence = CallEvidence::default();
        let outcome =
            resolve_rust_definition_in_operation_with_evidence(query, operation, &mut evidence);
        (outcome, evidence)
    }

    pub(crate) fn resolve_many(
        &self,
        operation: &mut SelectedResolutionOperation<'_, '_>,
        queries: &[BoundedReceiverQuery<'_>],
        cancellation: &CancellationToken,
    ) -> Vec<Option<RustDefinitionLookup>> {
        let mut evidence = vec![CallEvidence::default(); queries.len()];
        resolve_rust_definitions_in_operation(
            self.rust,
            operation,
            queries,
            cancellation,
            &mut evidence,
        )
        .into_iter()
        .zip(evidence)
        .map(|(outcome, evidence)| outcome.map(|outcome| (outcome, evidence)))
        .collect()
    }

    pub(crate) fn resolve_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        match self.open(&cancellation) {
            Ok(SelectedResolutionOperationOpenOutcome::Ready(mut operation)) => {
                self.resolve(&mut operation, query)
            }
            outcome => resolve_rust_definition_open_failure(query, outcome),
        }
    }
}

pub(crate) fn resolve_rust_definition_open_failure(
    query: BoundedReceiverQuery<'_>,
    outcome: brokk_bifrost_analysis::analyzer::store::Result<
        SelectedResolutionOperationOpenOutcome<'_, '_>,
    >,
) -> BoundedResolution<DefinitionLookupOutcome> {
    match outcome {
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            resolve_rust_definition_open_failure_for_batch(
                query,
                &RustDefinitionOperationOpenFailure::Unavailable(format!("{reason:?}")),
            )
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            resolve_rust_definition_open_failure_for_batch(
                query,
                &RustDefinitionOperationOpenFailure::Stale(format!("{reason:?}")),
            )
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            resolve_rust_definition_open_failure_for_batch(
                query,
                &RustDefinitionOperationOpenFailure::Cancelled,
            )
        }
        Ok(SelectedResolutionOperationOpenOutcome::Ready(_)) => {
            unreachable!("ready selected Rust operation is not an open failure")
        }
        Err(error) => resolve_rust_definition_open_failure_for_batch(
            query,
            &RustDefinitionOperationOpenFailure::StoreError(error.to_string()),
        ),
    }
}

pub(crate) fn resolve_rust_definition_open_failure_for_batch(
    query: BoundedReceiverQuery<'_>,
    failure: &RustDefinitionOperationOpenFailure,
) -> BoundedResolution<DefinitionLookupOutcome> {
    match failure {
        RustDefinitionOperationOpenFailure::Unavailable(reason) => complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_unavailable",
            format!("selected Rust point operation is unavailable: {reason}"),
        )
        .into_complete_resolution(),
        RustDefinitionOperationOpenFailure::Stale(reason) => complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_stale",
            format!("selected Rust point operation is stale: {reason}"),
        )
        .into_complete_resolution(),
        RustDefinitionOperationOpenFailure::Cancelled => BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        },
        RustDefinitionOperationOpenFailure::StoreError(error) => complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_store_error",
            format!("selected Rust point operation failed to open: {error}"),
        )
        .into_complete_resolution(),
    }
}

pub(crate) fn resolve_rust_definition_in_operation(
    query: BoundedReceiverQuery<'_>,
    operation: &mut SelectedResolutionOperation<'_, '_>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_rust_definition_in_operation_with_evidence(
        query,
        operation,
        &mut CallEvidence::default(),
    )
}

fn resolve_rust_definition_in_operation_with_evidence(
    query: BoundedReceiverQuery<'_>,
    operation: &mut SelectedResolutionOperation<'_, '_>,
    evidence: &mut CallEvidence,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(query.analyzer) else {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable for the selected native point operation",
        )
        .into_complete_resolution();
    };
    resolve_rust_definition_with_operation(query, rust, operation, &cancellation, evidence)
}

#[cfg(test)]
thread_local! {
    static RUST_DEFINITION_OPERATION_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RUST_DEFINITION_OVERLAY_PREPARATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn note_rust_definition_operation_open() {
    #[cfg(test)]
    RUST_DEFINITION_OPERATION_OPENS.with(|count| count.set(count.get() + 1));
}

fn note_rust_definition_overlay_preparation() {
    #[cfg(test)]
    RUST_DEFINITION_OVERLAY_PREPARATIONS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(crate) fn reset_rust_definition_operation_open_count_for_test() {
    RUST_DEFINITION_OPERATION_OPENS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn rust_definition_operation_open_count_for_test() -> usize {
    RUST_DEFINITION_OPERATION_OPENS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_rust_definition_overlay_preparation_count_for_test() {
    RUST_DEFINITION_OVERLAY_PREPARATIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn rust_definition_overlay_preparation_count_for_test() -> usize {
    RUST_DEFINITION_OVERLAY_PREPARATIONS.with(std::cell::Cell::get)
}

/// Adapt one selected native Rust reference into the definition lookup
/// vocabulary without consulting a legacy candidate or lexical resolver.
#[doc(hidden)]
pub fn resolve_rust_definition_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_rust_definition_bounded_with_after_open(query, || {})
}

/// Variant used by stale/cancellation fixtures to observe the operation after
/// opening the selected snapshot but before reading the focused reference.
pub(crate) fn resolve_rust_definition_bounded_with_after_open(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_rust_definition_bounded_with_after_open_and_evidence(
        query,
        after_open,
        &mut CallEvidence::default(),
    )
}

pub(crate) fn resolve_rust_definition_bounded_with_evidence(
    query: BoundedReceiverQuery<'_>,
) -> RustDefinitionLookup {
    let mut evidence = CallEvidence::default();
    let outcome =
        resolve_rust_definition_bounded_with_after_open_and_evidence(query, || {}, &mut evidence);
    (outcome, evidence)
}

fn resolve_rust_definition_bounded_with_after_open_and_evidence(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
    evidence: &mut CallEvidence,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(query.analyzer) else {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable for the selected native point operation",
        )
        .into_complete_resolution();
    };
    if !cancellation.is_cancelled() && !rust.inner.workspace_declaration_identities_authoritative()
    {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_identity_authority_unavailable",
            "selected Rust declaration identity inputs are not authoritative",
        )
        .into_complete_resolution();
    }

    let report = rust.open_selected_rust_operation(&cancellation);
    // Existing counter readers observe completed calls. Record returned attempt
    // progress before projecting failures or invoking the after-open callback.
    note_rust_definition_overlay_preparation();
    if report.store_open_attempted {
        note_rust_definition_operation_open();
    }
    let mut operation = match report.outcome {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust point operation is unavailable: {reason:?}"),
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust point operation is stale: {reason:?}"),
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust point operation failed to open: {error}"),
            )
            .into_complete_resolution();
        }
    };
    after_open();

    resolve_rust_definition_with_operation(query, rust, &mut operation, &cancellation, evidence)
}

/// Rust's projection for the shared declaration-at-range lookup.
fn project_rust_declarations(
    ready: &brokk_bifrost_analysis::analyzer::store::resolution_operation::ReadySelectedResolution<
        '_,
        '_,
    >,
    definitions: &[brokk_bifrost_analysis::analyzer::resolution::model::SemanticId],
    cancellation: &CancellationToken,
    session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedRustSourceDefinitionProjection> {
    brokk_bifrost_analysis::analyzer::store::resolution_operation::project_rust_source_definitions(
        ready,
        brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedMountTable::new(
            &ready.inventory,
        ),
        definitions,
        cancellation,
        session,
    )
}

fn resolve_rust_definition_with_operation(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    operation: &mut SelectedResolutionOperation<'_, '_>,
    cancellation: &CancellationToken,
    evidence: &mut CallEvidence,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let source_matches = rust
        .inner
        .source_matches_selected_native_content(query.file, query.source);
    if cancellation.is_cancelled() {
        return BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if !source_matches {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Unavailable,
            "native_source_mismatch",
            "supplied Rust reference text is not backed by the admitted selected source",
        )
        .into_complete_resolution();
    }

    // Rust's wildcard token, inferred type, and unnamed import alias have no
    // declaration. The grammar represents the latter two as identifiers, so
    // inspect the focused AST token rather than asking the reference locator
    // for a fact the producer deliberately does not emit.
    if query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .is_some_and(|node| {
                node.kind() == "_"
                    || (matches!(node.kind(), "identifier" | "type_identifier")
                        && node.utf8_text(query.source.as_bytes()) == Ok("_"))
            })
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::NoDefinition,
            "rust_non_reference_syntax",
            "the focused Rust wildcard, inferred type, or unnamed alias has no declaration",
        )
        .into_complete_resolution();
    }

    // An explicit crate anchor is syntax, not a reference to a declaration.
    // The producer deliberately omits its binder demand: no scope exports a
    // declaration named by this keyword. Preserve the focused token instead
    // of looking up the terminal of the containing path or reporting a
    // missing fact. This also applies inside macro token trees.
    if query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .is_some_and(|node| node.kind() == "crate")
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::NoDefinition,
            "crate_anchor",
            "the focused crate anchor has no source declaration",
        )
        .into_complete_resolution();
    }

    // Relative module anchors in a macro transcriber belong to the invocation
    // module. The definition-site token alone does not select an expansion,
    // so resolving it against the containing source module would invent a
    // target. Inspect the original AST, before any template-path projection.
    if query.tree.is_some_and(|tree| {
        let Some(node) = tree
            .root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
        else {
            return false;
        };
        if !matches!(node.kind(), "self" | "super") {
            return false;
        }
        let mut ancestor = node.parent();
        while let Some(parent) = ancestor {
            if parent.kind() == "macro_rule" {
                return parent.child_by_field_name("right").is_some_and(|body| {
                    body.start_byte() <= node.start_byte() && node.end_byte() <= body.end_byte()
                });
            }
            ancestor = parent.parent();
        }
        false
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::Incomplete,
            "macro_expansion_context_required",
            "the relative module anchor in this macro template requires an invocation context",
        )
        .into_complete_resolution();
    }

    // A Rust lifetime names a binder introduced by a generic parameter list, a
    // `for<..>` clause or an impl header, and no analyzer publishes such a
    // binder as a CodeUnit. The producer emits neither a name nor a reference
    // site for one on purpose (`brokk_bifrost_rust::resolution`,
    // `lifetimes_do_not_hide_classified_value_and_type_references`), so the
    // point route has to decide this token instead of reporting the absent
    // fact: every lifetime was answering `unavailable`, which the census
    // grades as inconclusive rather than as the local binding it is. The
    // grammar keeps the tick and the name inside one `lifetime` node, so read
    // the retained AST rather than the source text.
    if query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .is_some_and(|node| {
                node.kind() == "lifetime"
                    || node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "lifetime")
            })
    }) {
        return complete_definition(
            query.site,
            DefinitionLookupStatus::NoDefinition,
            brokk_bifrost_analysis::analyzer::usages::get_definition::LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            "the focused Rust lifetime is a local binder, not a reference to a declaration",
        )
        .into_complete_resolution();
    }

    let conditional_site_cfg = match crate::analyzer::rust::site_activation::rust_site_activation(
        query.tree,
        query.source,
        query.site.focus_start_byte..query.site.focus_end_byte,
        |condition| {
            operation.rust_cfg_activation_for_caller_under_site_cfg(
                query.file.rel_path(),
                condition,
                cancellation,
            )
        },
    ) {
        Ok(Some(crate::analyzer::rust::site_activation::RustSiteActivation::Active)) => None,
        Ok(Some(crate::analyzer::rust::site_activation::RustSiteActivation::Unknown {
            conditional_site_cfg: Some(condition),
        })) => Some(condition),
        Ok(Some(crate::analyzer::rust::site_activation::RustSiteActivation::NoNode)) => None,
        Ok(Some(crate::analyzer::rust::site_activation::RustSiteActivation::Inactive)) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::NoDefinition,
                "inactive_cfg",
                "the selected Rust cfg predicate is refuted",
            )
            .into_complete_resolution();
        }
        Ok(Some(crate::analyzer::rust::site_activation::RustSiteActivation::Unknown {
            conditional_site_cfg: None,
        })) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Incomplete,
                "unknown_activation",
                "the selected Rust cfg predicate contains an undecidable atom",
            )
            .into_complete_resolution();
        }
        Ok(None) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust cfg lookup failed: {error}"),
            )
            .into_complete_resolution();
        }
    };

    let macro_invocation = query.tree.and_then(|tree| {
        let token = tree
            .root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)?;
        brokk_bifrost_rust::macro_matcher::enclosing_macro_invocation_for_argument(token)
    });
    let macro_binding = if let Some(invocation) = macro_invocation {
        let local = brokk_bifrost_rust::macro_matcher::match_local_macro_invocation(
            invocation,
            query.source,
        );
        let matched = if local.is_some() {
            local
        } else if let Some(head) = invocation.child_by_field_name("macro")
            && head.kind() == "identifier"
            && let Some(arguments) = invocation.child_by_field_name("token_tree").or_else(|| {
                let mut cursor = invocation.walk();
                invocation
                    .named_children(&mut cursor)
                    .find(|node| node.kind() == "token_tree")
            })
        {
            match operation.match_selected_textual_macro(
                query.file.rel_path(),
                invocation.start_byte(),
                arguments.start_byte(),
                &query.source[head.byte_range()],
                cancellation,
            ) {
                Ok(matched) => matched,
                Err(error) => {
                    return complete_definition(
                        query.site,
                        DefinitionLookupStatus::Unavailable,
                        "native_store_error",
                        format!("selected macro replay failed: {error}"),
                    )
                    .into_complete_resolution();
                }
            }
        } else {
            None
        };
        Some(matched)
    } else {
        None
    };
    let mut matcher_diagnostic = None;
    let mut matcher_namespace_undecided = false;
    if let Some(matched) = macro_binding {
        use brokk_bifrost_rust::macro_matcher::{
            MacroMatchError, MacroNamespaceEvidence, classify_fragment_interior,
            token_namespace_evidence,
        };
        match matched {
            Some(Err(MacroMatchError::NoArmMatched)) => {
                return complete_definition(
                    query.site,
                    DefinitionLookupStatus::NoDefinition,
                    "macro_matcher_failed",
                    "no arm in the visible macro definition matches the invocation",
                )
                .into_complete_resolution();
            }
            Some(Ok(arm)) => {
                let start = query.site.focus_start_byte;
                let end = query.site.focus_end_byte;
                match token_namespace_evidence(&arm, start, end) {
                    // The matcher bound the focused token to a declaration
                    // position. The token denotes itself; that is an answer,
                    // and the whole selection is irrelevant to it.
                    Some(MacroNamespaceEvidence::Declaration) => {
                        return complete_definition(
                            query.site,
                            DefinitionLookupStatus::NoDefinition,
                            brokk_bifrost_analysis::analyzer::usages::get_definition::MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND,
                            "the matched token binds a declaration position, so it denotes itself",
                        )
                        .into_complete_resolution();
                    }
                    // A fragment specifier alone may not carry a namespace,
                    // but structured transcriber replay can have already
                    // published an ordinary reference at this input span.
                    // Let that producer authority answer before abstaining.
                    Some(MacroNamespaceEvidence::NoNamespace) => {
                        matcher_namespace_undecided = true;
                    }
                    // The matcher bound the token inside a parsed fragment.
                    // Which namespace it is in is the fragment's own syntax to
                    // answer, so classify it there rather than treating the
                    // whole interior as undecided: a declaration name inside an
                    // `item` fragment denotes itself and is not a forward
                    // reference to anything.
                    Some(MacroNamespaceEvidence::Interior(fragment)) => {
                        let binding = arm
                            .binding_containing(start, end)
                            .expect("interior evidence comes from a containing binding");
                        let interior = classify_fragment_interior(
                            fragment,
                            &query.source[binding.start_byte..binding.end_byte],
                            start - binding.start_byte,
                            end - binding.start_byte,
                        );
                        if interior == Some(MacroNamespaceEvidence::Declaration) {
                            return complete_definition(
                                query.site,
                                DefinitionLookupStatus::NoDefinition,
                                brokk_bifrost_analysis::analyzer::usages::get_definition::MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND,
                                "the matched token binds a declaration position, so it denotes itself",
                            )
                            .into_complete_resolution();
                        }
                    }
                    _ => {}
                }
                matcher_diagnostic =
                    arm.binding_containing(start, end)
                        .map(|binding| DefinitionLookupDiagnostic {
                            claim: None,
                            kind: "macro_matcher_binding".to_owned(),
                            message: format!(
                                "arm={} fragment={}",
                                arm.arm_index,
                                binding.fragment.as_str()
                            ),
                        });
            }
            // No visible `macro_rules!` matches this invocation's head. That
            // is a fact about the macro, not about the focused token: a
            // definition-less macro's token tree is enumerated as expression
            // fragments and lowered by the ordinary walk, so the token has
            // ordinary reference sites. Fall through to them. Only a group
            // the enumeration could not lower keeps a macro gap, and it keeps
            // it as the producer's own gap rather than as an early return
            // that claims the whole workspace does not contain the name.
            None => {}
            Some(Err(_)) => {}
        }
    }

    // Declaration identifiers denote themselves, even when there is no
    // reference row at the focused range. The selected lookup serves both
    // persisted source bridges and transient native declaration facts.
    let declaration = operation.declaration_at_range_bounded(
        &SelectedSemanticLocator::for_declaration_range(
            "rust",
            rel_path_string(query.file),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        ),
        query.budget,
        cancellation,
        project_rust_declarations,
        SelectedRustSourceDefinitionProjection::Cancelled,
    );
    match declaration {
        Ok(None) => {}
        Ok(Some(result)) => {
            return match result {
                BoundedResolution::Exceeded { limit, work } => {
                    BoundedResolution::Exceeded { limit, work }
                }
                BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
                BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                    value: {
                        let mut value = adapt_declaration_value(query.site, value);
                        if let Some(condition) = &conditional_site_cfg {
                            value
                                .diagnostics
                                .push(conditional_cfg_diagnostic(condition));
                        }
                        value
                    },
                    work,
                },
            };
        }
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust declaration lookup failed: {error}"),
            )
            .into_complete_resolution();
        }
    }

    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        rel_path_string(query.file),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    );
    // Asked before the operation is consumed, and only for a path head, the
    // one shape `claim_external_route_head` reads it for.
    let (head_names_macro_module, head_workspace_crate) = if focused_route_head(&query) {
        match operation
            .rust_reference_names_macro_module(&locator, cancellation)
            .and_then(|macro_module| {
                Ok((
                    macro_module,
                    operation.rust_reference_names_workspace_crate(&locator, cancellation)?,
                ))
            }) {
            Ok(names) => names,
            Err(error) => {
                return complete_definition(
                    query.site,
                    DefinitionLookupStatus::Unavailable,
                    "native_store_error",
                    format!("selected Rust route head read failed: {error}"),
                )
                .into_complete_resolution();
            }
        }
    } else {
        (false, None)
    };
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation.resolve_rust_reference_for_caller_bounded(
        query.file.rel_path(),
        &locator,
        query.budget,
        cancellation,
        &mut context_metrics,
        &mut point_metrics,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            return complete_definition(
                query.site,
                DefinitionLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust point operation failed: {error}"),
            )
            .into_complete_resolution();
        }
    };

    match result {
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        BoundedResolution::Complete { value, work } => {
            let mut outcome = adapt_definition_value(&query, value, evidence, cancellation);
            if matcher_namespace_undecided
                && outcome
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.kind == "native_reference_missing")
            {
                outcome = complete_definition(
                    query.site,
                    DefinitionLookupStatus::Incomplete,
                    brokk_bifrost_analysis::analyzer::usages::get_definition::MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND,
                    "the matched macro fragment carries no namespace and has no replayed reference site",
                )
                .into_complete_value();
            }

            if let Some(condition) = &conditional_site_cfg {
                outcome
                    .diagnostics
                    .push(conditional_cfg_diagnostic(condition));
            }
            outcome.diagnostics.extend(matcher_diagnostic);
            name_unresolved_receiver_owner(query.tree, query.source, query.site, &mut outcome);
            claim_external_route_head(
                &mut outcome,
                &query,
                head_names_macro_module,
                head_workspace_crate.as_deref(),
            );
            if cancellation.is_cancelled() {
                BoundedResolution::Cancelled { work }
            } else {
                BoundedResolution::Complete {
                    value: outcome,
                    work,
                }
            }
        }
    }
}

fn resolve_rust_definitions_in_operation(
    rust: &RustAnalyzer,
    operation: &mut SelectedResolutionOperation<'_, '_>,
    queries: &[BoundedReceiverQuery<'_>],
    cancellation: &CancellationToken,
    evidence: &mut [CallEvidence],
) -> Vec<Option<BoundedResolution<DefinitionLookupOutcome>>> {
    let mut results = std::iter::repeat_with(|| None)
        .take(queries.len())
        .collect::<Vec<_>>();
    if queries.len() < 2 || cancellation.is_cancelled() {
        return results;
    }
    let first = &queries[0];
    if queries.iter().any(|query| {
        query.file != first.file
            || query.source.as_ptr() != first.source.as_ptr()
            || query.source.len() != first.source.len()
    }) || !rust
        .inner
        .source_matches_selected_native_content(first.file, first.source)
    {
        return results;
    }

    let mut positions = Vec::new();
    let mut locators = Vec::new();
    let mut conditional_cfgs = Vec::new();
    for (index, query) in queries.iter().enumerate() {
        if cancellation.is_cancelled() {
            return results;
        }
        let Some(tree) = query.tree else {
            continue;
        };
        let Some(token) = tree
            .root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
        else {
            continue;
        };
        if brokk_bifrost_rust::macro_matcher::enclosing_macro_invocation_for_argument(token)
            .is_some()
        {
            continue;
        }
        let condition =
            brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(token, query.source);
        let conditional_cfg =
            if condition != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
                use brokk_bifrost_rust::selected_context::RustSelectedActivation;
                match operation.rust_cfg_activation_for_caller_under_site_cfg(
                    query.file.rel_path(),
                    &condition,
                    cancellation,
                ) {
                    Ok(Some((RustSelectedActivation::Active, conditional))) => {
                        conditional.then_some(condition)
                    }
                    Ok(Some((RustSelectedActivation::Inactive, _))) => {
                        results[index] = Some(
                            complete_definition(
                                query.site,
                                DefinitionLookupStatus::NoDefinition,
                                "inactive_cfg",
                                "the selected Rust cfg predicate is refuted",
                            )
                            .into_complete_resolution(),
                        );
                        continue;
                    }
                    Ok(Some((RustSelectedActivation::Unknown, _))) => {
                        results[index] = Some(
                            complete_definition(
                                query.site,
                                DefinitionLookupStatus::Incomplete,
                                "unknown_activation",
                                "the selected Rust cfg predicate contains an undecidable atom",
                            )
                            .into_complete_resolution(),
                        );
                        continue;
                    }
                    Ok(None) => {
                        results[index] = Some(BoundedResolution::Cancelled {
                            work: ReceiverAnalysisWork::default(),
                        });
                        continue;
                    }
                    Err(error) => {
                        results[index] = Some(
                            complete_definition(
                                query.site,
                                DefinitionLookupStatus::Unavailable,
                                "native_store_error",
                                format!("selected Rust cfg lookup failed: {error}"),
                            )
                            .into_complete_resolution(),
                        );
                        continue;
                    }
                }
            } else {
                None
            };
        if focused_route_head(query) {
            continue;
        }
        if crate::analyzer::rust::external_calls::call_path_for_site(tree, query.site).is_none() {
            continue;
        }
        let declaration_locator = SelectedSemanticLocator::for_declaration_range(
            "rust",
            rel_path_string(query.file),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        );
        match operation.declaration_at_range_bounded(
            &declaration_locator,
            query.budget,
            cancellation,
            project_rust_declarations,
            SelectedRustSourceDefinitionProjection::Cancelled,
        ) {
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => continue,
        }
        positions.push(index);
        conditional_cfgs.push(conditional_cfg);
        locators.push(SelectedSemanticLocator::for_reference_range(
            "rust",
            rel_path_string(query.file),
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        ));
    }
    if locators.len() < 2 {
        return results;
    }
    let budget = queries[positions[0]].budget;
    assert!(
        positions
            .iter()
            .all(|&index| queries[index].budget == budget)
    );
    let locator_refs = locators.iter().collect::<Vec<_>>();
    let references = match operation.resolve_rust_references_for_caller_bounded_per_locator(
        first.file.rel_path(),
        &locator_refs,
        budget,
        cancellation,
    ) {
        Ok(references) => references,
        Err(error) => {
            for &index in &positions {
                results[index] = Some(
                    complete_definition(
                        queries[index].site,
                        DefinitionLookupStatus::Unavailable,
                        "native_store_error",
                        format!("selected Rust point operation failed: {error}"),
                    )
                    .into_complete_resolution(),
                );
            }
            return results;
        }
    };
    assert_eq!(references.len(), positions.len());
    for ((index, conditional_cfg), query_result) in
        positions.into_iter().zip(conditional_cfgs).zip(references)
    {
        let query = &queries[index];
        results[index] = Some(match query_result {
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
            BoundedResolution::Complete { value, work } => {
                let mut outcome =
                    adapt_definition_value(query, value, &mut evidence[index], cancellation);
                if let Some(condition) = &conditional_cfg {
                    outcome
                        .diagnostics
                        .push(conditional_cfg_diagnostic(condition));
                }
                name_unresolved_receiver_owner(query.tree, query.source, query.site, &mut outcome);
                if cancellation.is_cancelled() {
                    BoundedResolution::Cancelled { work }
                } else {
                    BoundedResolution::Complete {
                        value: outcome,
                        work,
                    }
                }
            }
        });
    }
    results
}

fn conditional_cfg_diagnostic(
    condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
) -> DefinitionLookupDiagnostic {
    DefinitionLookupDiagnostic {
        claim: None,
        kind: "conditional_cfg".to_owned(),
        message: format!("the answer is conditional on Rust cfg {condition:?}"),
    }
}

/// Name the owner type a `self.member` read reached when the member did not
/// resolve to any indexed declaration.
///
/// `impl Mystery { fn poll(&self) { self.inner ... } }`, where `Mystery` is
/// declared nowhere the workspace indexes, leaves the receiver's type
/// unresolved. The generic "no source-backed definition" wording then names
/// neither the owner the read tried nor a next query, which is the dead end
/// #1019 reported. The enclosing `impl` still writes its self type, so the
/// diagnostic reads it from that `impl_item`'s own `type` field and names a
/// concrete retry. The answer itself does not change: the member really has no
/// indexed definition.
fn name_unresolved_receiver_owner(
    tree: Option<&tree_sitter::Tree>,
    source: &str,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    outcome: &mut DefinitionLookupOutcome,
) {
    if outcome.status != DefinitionLookupStatus::NoDefinition {
        return;
    }
    let Some(node) = tree.and_then(|tree| {
        tree.root_node()
            .descendant_for_byte_range(site.focus_start_byte, site.focus_end_byte)
    }) else {
        return;
    };
    let member_of_self_receiver = node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(node)
            && parent
                .child_by_field_name("value")
                .is_some_and(|receiver| receiver.kind() == "self")
    });
    if !member_of_self_receiver {
        return;
    }
    let Some(owner) = enclosing_impl_self_type_name(node, source) else {
        return;
    };
    let member = &source[node.byte_range()];
    for diagnostic in &mut outcome.diagnostics {
        if diagnostic.kind == "no_indexed_definition" {
            diagnostic.message = format!(
                "`{member}` looks like a member of `{owner}`, but `{owner}` has no indexed Rust \
                 declaration; try get_symbol_sources with \"{owner}.{member}\" or search_symbols \
                 for \"{member}\""
            );
        }
    }
}

/// The name the nearest enclosing `impl` writes for its self type, read from
/// the `impl_item`'s `type` field and its own structured children. An `impl`
/// whose self type is not a named path (a reference, a tuple, `dyn Trait`)
/// names no owner and yields `None`.
fn enclosing_impl_self_type_name<'source>(
    node: tree_sitter::Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let mut current = node.parent()?;
    let mut self_type = loop {
        if current.kind() == "impl_item" {
            break current.child_by_field_name("type")?;
        }
        current = current.parent()?;
    };
    loop {
        match self_type.kind() {
            "generic_type" => self_type = self_type.child_by_field_name("type")?,
            "scoped_type_identifier" => self_type = self_type.child_by_field_name("name")?,
            "type_identifier" => return Some(&source[self_type.byte_range()]),
            _ => return None,
        }
    }
}

/// A path's first segment that names no module this workspace compiles has
/// left the workspace, and that is a boundary rather than a decided negative
/// (owner decision, 2026-09-17).
///
/// The crate route already says this for the demand it resolves: both copies
/// of the guard, in `rust_crate_context` and in `rust_demand/rows`, claim
/// `ExternalDeclaredUnindexed` when a route head matches no module. A caret on
/// the head itself never reaches them. That segment has its own lexical Type
/// reference, issued by `brokk_bifrost_rust::resolution`'s
/// `add_root_reference_route` for exactly this shape, and resolving it asks a
/// lexical question only, so the demand provider is never entered, nothing
/// claims the boundary, and the empty selection answers `no_definition`.
/// Navigating to `serde_json` in `serde_json::to_string_pretty`, and to the
/// original spelling of a Cargo-renamed dependency, both landed there.
///
/// The claim is made only where the route itself would make it: the focused
/// token is the first segment of a multi-segment path, it is not one of the
/// explicit module anchors, and the selection finished having found no
/// definition at all. A head the workspace does compile resolves and never
/// reaches here.
///
/// A head that names a module the crate declares for an item macro in the
/// reference's own module is not such a boundary: the module is compiled, and
/// the head finds nothing only because a crate-declared module has no lexical
/// binder. That answer is incomplete, not a boundary.
///
/// A head that names a workspace crate, by its extern name or through an alias
/// of its root (`use forc_pkg::{self as pkg};`), is not one either: the crate
/// is compiled, and the head finds nothing only because a crate root has no
/// declaration. The answer stays `no_definition` and says the head is a crate
/// namespace in this workspace (#1089).
fn claim_external_route_head(
    outcome: &mut DefinitionLookupOutcome,
    query: &BoundedReceiverQuery<'_>,
    head_names_macro_module: bool,
    head_workspace_crate: Option<&str>,
) {
    if outcome.status != DefinitionLookupStatus::NoDefinition
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
        || !focused_route_head(query)
    {
        return;
    }
    outcome.diagnostics.retain(|diagnostic| {
        diagnostic.kind
            != brokk_bifrost_analysis::analyzer::usages::get_definition::RUST_NO_INDEXED_DEFINITION_DIAGNOSTIC_KIND
    });
    if let Some(crate_name) = head_workspace_crate {
        let head = &query.source[query.site.focus_start_byte..query.site.focus_end_byte];
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: brokk_bifrost_analysis::analyzer::usages::get_definition::RUST_WORKSPACE_CRATE_NAMESPACE_DIAGNOSTIC_KIND
                .to_owned(),
            message: format!(
                "`{head}` names the Rust crate `{crate_name}` in this workspace; a crate root is a \
                 namespace, not a single indexed declaration"
            ),
        });
        return;
    }
    if head_names_macro_module {
        outcome.status = DefinitionLookupStatus::Incomplete;
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "incomplete_binding".to_owned(),
            message: "the focused Rust path head names a module an item macro declares in this \
                      module; a path head is bound lexically, and a macro-declared module has no \
                      lexical binder"
                .to_owned(),
        });
        return;
    }
    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        claim: None,
        kind:
            brokk_bifrost_analysis::analyzer::usages::get_definition::RUST_UNINDEXED_IMPORT_BOUNDARY_DIAGNOSTIC_KIND
                .to_owned(),
        message: "the focused Rust path head names no module this workspace compiles".to_owned(),
    });
}

/// Whether the focused token is the first segment of a multi-segment path and
/// not one of the explicit module anchors. The head of a grouped `use`
/// (`pkg` in `use pkg::{A, B};`) is the `path` of its `scoped_use_list`.
fn focused_route_head(query: &BoundedReceiverQuery<'_>) -> bool {
    query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .and_then(|token| Some((token, token.parent()?)))
            .is_some_and(|(token, path)| {
                matches!(
                    path.kind(),
                    "scoped_identifier" | "scoped_type_identifier" | "scoped_use_list"
                ) && path.child_by_field_name("path").map(|head| head.id()) == Some(token.id())
                    && !matches!(token.kind(), "crate" | "self" | "super" | "metavariable")
            })
    })
}

fn focused_qualified_type_route(query: &BoundedReceiverQuery<'_>) -> bool {
    if focused_route_head(query) {
        return true;
    }
    query.tree.is_some_and(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
            .and_then(|token| Some((token, token.parent()?)))
            .is_some_and(|(token, path)| {
                matches!(path.kind(), "scoped_identifier" | "scoped_type_identifier")
                    && path
                        .child_by_field_name("name")
                        .is_some_and(|name| name.id() == token.id())
            })
    })
}

fn adapt_declaration_value(
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    value: SelectedResolutionOperationOutcome<SelectedRustSourceDefinitionProjection>,
) -> DefinitionLookupOutcome {
    let rows = match value {
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Complete(rows),
        ) => rows,
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Cancelled,
        )
        | SelectedResolutionOperationOutcome::Cancelled(_) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Incomplete,
                "native_cancelled",
                "selected Rust declaration lookup was cancelled",
            )
            .0;
        }
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Unavailable,
        ) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_definition_projection_unavailable",
                "selected Rust declaration has no source projection",
            )
            .0;
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust declaration lookup is unavailable: {reason:?}"),
            )
            .0;
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust declaration lookup is stale: {reason:?}"),
            )
            .0;
        }
    };
    let mut definitions = Vec::new();
    let mut lexical = Vec::new();
    let mut withdrawn = 0usize;
    for (_, definition) in rows {
        match definition {
            SelectedRustSourceDefinition::Unit(unit) => definitions.push(unit),
            SelectedRustSourceDefinition::Lexical(row) => lexical.push(row),
            // The parser published neither a `CodeUnit` nor a lexical binder
            // for this declaration, so neither vocabulary has a row to carry
            // it. `WithoutUnit` is one alternative's own answer, so it
            // withdraws that alternative and the point answers from the rest.
            // Refusing the whole point for it threw away the alternatives that
            // did project, which is what the reverse batch used to do too.
            SelectedRustSourceDefinition::WithoutUnit { .. } => withdrawn += 1,
            // A language universe entry (`i64`) declares no `CodeUnit` and
            // binds no lexical name, so no vocabulary here carries it either;
            // the alternative withdraws itself exactly as `WithoutUnit` does.
            SelectedRustSourceDefinition::UniverseEntry => withdrawn += 1,
        }
    }
    definitions.sort_unstable();
    definitions.dedup();
    lexical.dedup();
    // Every alternative withdrew itself, so the point has no source-backed
    // answer to publish and says so once, for the whole point.
    if definitions.is_empty() && lexical.is_empty() {
        assert!(
            withdrawn > 0,
            "a complete Rust declaration projection publishes at least one alternative"
        );
        return complete_definition(
            site,
            DefinitionLookupStatus::Unavailable,
            "native_definition_projection_unavailable",
            "selected Rust declaration has no source projection",
        )
        .0;
    }
    let status = if definitions.len() + lexical.len() == 1 {
        DefinitionLookupStatus::Resolved
    } else {
        DefinitionLookupStatus::Ambiguous
    };
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: None,
        definitions,
        lexical_definition: (lexical.len() == 1).then(|| lexical.remove(0)),
        diagnostics: Vec::new(),
    };
    brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_units(
        &outcome,
    );
    brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_lexical(
        &outcome,
    );
    outcome
}

/// Adapt one selected native Rust type projection into the type lookup
/// vocabulary. Type exactness is decided by the selected typed frontiers, not
/// by binding completion or by the order in which slots happen to be stored.
pub(crate) fn resolve_rust_type_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<TypeLookupOutcome> {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(query.analyzer) else {
        return complete_type(
            query.site,
            TypeLookupStatus::Unavailable,
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable for the selected native type operation",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_resolution();
    };
    if !cancellation.is_cancelled() && !rust.inner.workspace_declaration_identities_authoritative()
    {
        return complete_type(
            query.site,
            TypeLookupStatus::Unavailable,
            "native_identity_authority_unavailable",
            "selected Rust declaration identity inputs are not authoritative",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_resolution();
    }

    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust type operation is unavailable: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust type operation is stale: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust type operation failed to open: {error}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let mut operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust type operation is unavailable: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust type operation is stale: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust type operation failed to open: {error}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
    };

    let source_matches = rust
        .inner
        .source_matches_selected_native_content(query.file, query.source);
    if cancellation.is_cancelled() {
        return BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if !source_matches {
        return complete_type(
            query.site,
            TypeLookupStatus::Unavailable,
            "native_source_mismatch",
            "supplied Rust reference text is not backed by the admitted selected source",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_resolution();
    }

    let mut conditional_site_cfg = None;

    // A type answer cannot escape the activation of its enclosing source body.
    if let Some(node) = query.tree.and_then(|tree| {
        tree.root_node()
            .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
    }) {
        let condition =
            brokk_bifrost_rust::lexical_scope::rust_effective_cfg_condition(node, query.source);
        if condition != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
            use brokk_bifrost_rust::selected_context::RustSelectedActivation;
            match operation.rust_cfg_activation_for_caller_under_site_cfg(
                query.file.rel_path(),
                &condition,
                &cancellation,
            ) {
                Ok(Some((RustSelectedActivation::Active, conditional))) => {
                    if conditional {
                        conditional_site_cfg = Some(condition.clone());
                    }
                }
                Ok(Some((RustSelectedActivation::Inactive, _))) => {
                    return complete_type(
                        query.site,
                        TypeLookupStatus::NoType,
                        "inactive_cfg",
                        "the selected Rust cfg predicate is refuted",
                        TypeLookupTargetKind::ValueExpression,
                    )
                    .into_complete_resolution();
                }
                Ok(Some((RustSelectedActivation::Unknown, _))) => {
                    return complete_type(
                        query.site,
                        TypeLookupStatus::Incomplete,
                        "unknown_activation",
                        "the selected Rust cfg predicate contains an undecidable atom",
                        TypeLookupTargetKind::ValueExpression,
                    )
                    .into_complete_resolution();
                }
                Ok(None) => {
                    return BoundedResolution::Cancelled {
                        work: ReceiverAnalysisWork::default(),
                    };
                }
                Err(error) => {
                    return complete_type(
                        query.site,
                        TypeLookupStatus::Unavailable,
                        "native_store_error",
                        format!("selected Rust cfg lookup failed: {error}"),
                        TypeLookupTargetKind::ValueExpression,
                    )
                    .into_complete_resolution();
                }
            }
        }
    }

    let expression = query
        .tree
        .and_then(|tree| {
            tree.root_node()
                .descendant_for_byte_range(query.site.focus_start_byte, query.site.focus_end_byte)
        })
        .map(brokk_bifrost_rust::structural::rust_receiver_operand);
    let name = expression.and_then(brokk_bifrost_rust::structural::expression_name_node);
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        rel_path_string(query.file),
        name.map_or(query.site.focus_start_byte, |name| name.start_byte()),
        name.map_or(query.site.focus_end_byte, |name| name.end_byte()),
    );
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation.resolve_rust_type_for_caller_bounded(
        query.file.rel_path(),
        &locator,
        query.budget,
        &cancellation,
        &mut context_metrics,
        &mut point_metrics,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            return complete_type(
                query.site,
                TypeLookupStatus::Unavailable,
                "native_store_error",
                format!("selected Rust type operation failed: {error}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_resolution();
        }
    };

    match result {
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        BoundedResolution::Complete { value, work } => {
            let mut value = adapt_type_value(query, rust, value);
            if expression
                .is_some_and(|node| matches!(node.kind(), "call_expression" | "struct_expression"))
            {
                value.target_kind = TypeLookupTargetKind::ValueExpression;
            }
            if let Some(condition) = &conditional_site_cfg {
                value.diagnostics.push(TypeLookupDiagnostic {
                    kind: "conditional_cfg".to_owned(),
                    message: format!("the answer is conditional on Rust cfg {condition:?}"),
                });
            }
            BoundedResolution::Complete { value, work }
        }
    }
}

/// Read the category of the receiver selected by native member lookup.
/// This consumes selection evidence; it never re-infers a receiver expression.
fn selected_member_call_evidence(
    query: &BoundedReceiverQuery<'_>,
    answers: &[SelectedRustReferenceAnswer],
) -> CallEvidence {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind;
    use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind;

    let Some(_) = query
        .tree
        .and_then(|tree| {
            crate::analyzer::rust::external_calls::call_path_for_site(tree, query.site)
        })
        .and_then(brokk_bifrost_rust::structural::rust_method_call_parts)
    else {
        return CallEvidence::default();
    };
    if answers.is_empty() {
        return CallEvidence::default();
    }
    let mut extensibility = None;
    for answer in answers {
        let [target] = answer.resolution.binding().targets() else {
            return CallEvidence::default();
        };
        let Some(selected) = answer
            .member_attributions
            .iter()
            .find(|member| member.target == *target)
        else {
            return CallEvidence::default();
        };
        let kind = if selected.receiver_is_intrinsic {
            SemanticModelSymbolKind::Class
        } else {
            match selected.receiver_kind {
                Some(RustDeclarationKind::Struct) => SemanticModelSymbolKind::Struct,
                Some(RustDeclarationKind::Enum) => SemanticModelSymbolKind::Enum,
                Some(RustDeclarationKind::Union) => SemanticModelSymbolKind::Union,
                Some(RustDeclarationKind::Trait) => SemanticModelSymbolKind::Trait,
                _ => return CallEvidence::default(),
            }
        };
        extensibility = super::modeled_members::receiver_dispatch_extensibility(kind, None);
        if extensibility.is_none() {
            return CallEvidence::default();
        }
    }
    CallEvidence {
        call_application: CallApplicationKind::BoundReceiver,
        dispatch_extensibility: extensibility,
        ..CallEvidence::default()
    }
}

fn adapt_definition_value(
    query: &BoundedReceiverQuery<'_>,
    value: SelectedRustCallerReferenceOutcome,
    evidence: &mut CallEvidence,
    cancellation: &CancellationToken,
) -> DefinitionLookupOutcome {
    let site = query.site;
    match value {
        SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile => complete_definition(
            site,
            DefinitionLookupStatus::Unavailable,
            "unsupported_caller_profile",
            "the selected Rust caller profile is not supported by native resolution",
        )
        .into_complete_value(),
        SelectedRustCallerReferenceOutcome::Operation(outcome) => match outcome {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                complete_definition(
                    site,
                    DefinitionLookupStatus::Unavailable,
                    "native_reference_missing",
                    "the structured Rust reference site is absent from selected native facts",
                )
                .into_complete_value()
            }
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) => {
                *evidence = selected_member_call_evidence(query, &answer);
                let Some(completion) = ResolutionCompletion::combine_all_with_poll(
                    answer
                        .iter()
                        .map(|answer| answer.resolution.binding().completion()),
                    &mut || cancellation.is_cancelled(),
                ) else {
                    return complete_definition(
                        site,
                        DefinitionLookupStatus::Cancelled,
                        "cancelled",
                        "selected Rust point operation was cancelled",
                    )
                    .into_complete_value();
                };
                let modeled = modeled_macro_definitions(query, &answer);
                let mut outcome = adapt_definition_answer(
                    site,
                    answer,
                    completion,
                    focused_qualified_type_route(query),
                );
                match modeled {
                    Ok(definitions) if !definitions.is_empty() => {
                        outcome.status =
                            if definitions.len() == 1 && !definitions[0].provenance.ambiguous {
                                DefinitionLookupStatus::Resolved
                            } else {
                                DefinitionLookupStatus::Ambiguous
                            };
                        outcome
                            .diagnostics
                            .retain(|diagnostic| diagnostic.kind != "incomplete_binding");
                        outcome.modeled_definitions = definitions;
                        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_modeled(
                            &outcome,
                        );
                    }
                    Ok(_) => {}
                    Err(error) => outcome.diagnostics.push(DefinitionLookupDiagnostic {
                        claim: None,
                        kind: "rust_generated_route_unavailable".to_owned(),
                        message: format!("Rust generated declaration route failed: {error:?}"),
                    }),
                }
                outcome
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust point operation is unavailable: {reason:?}"),
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Stale(reason) => complete_definition(
                site,
                DefinitionLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust point operation is stale: {reason:?}"),
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Cancelled(_) => complete_definition(
                site,
                DefinitionLookupStatus::Cancelled,
                "cancelled",
                "selected Rust point operation was cancelled",
            )
            .into_complete_value(),
        },
    }
}

/// No binding, producer projection, or transfer-owned identity was examined.
/// A lexical negative can legitimately have this shape; an observed type
/// frontier, including an abstract one, cannot.
fn reference_answer_has_no_candidate(resolution: &FactResolutionAnswer) -> bool {
    resolution.binding().targets().is_empty()
        && matches!(
            resolution.binding().completion(),
            ResolutionCompletion::Complete
        )
        && resolution.projections().is_empty()
        && resolution.observed_type_identity().is_none()
}

/// An unqualified type occurrence without any observed identity is not a
/// proved lexical absence. Complete transfer observations are exposed separately
/// from binding projections and do not take this abstention path.
fn definition_answer_abstains(resolution: &FactResolutionAnswer) -> bool {
    reference_answer_has_no_candidate(resolution)
        && resolution.site_metadata().is_some_and(|metadata| {
            metadata.site_kind() == ResolutionSiteKind::TypeReference && metadata.unqualified()
        })
}

/// Name every reason one selected binding is incomplete, for a public
/// diagnostic.
///
/// The site used to format `{completion:?}`, so each reason printed a
/// `SemanticId` as a 32-byte array and the message named no gap at all. Each
/// reason retains its kind and the boundary status for an open boundary.
/// `ResolutionIncompleteReason::kind` covers only persistable reason kinds,
/// so operation-specific cancellation and budget reasons are matched here too.
///
/// A semantic that is one of the binding's own targets keeps the name from
/// the `(SemanticId, definition)` pairing the answer carries. Local and
/// shared semantics use the store's portable projection. Operation and
/// selected-context semantics keep their runtime marker without an ordinal.
/// The reason and any target name remain available to the caller.
fn describe_incomplete_binding(
    completion: &ResolutionCompletion,
    names: &std::collections::BTreeMap<SemanticId, String>,
    identities: &std::collections::BTreeMap<SemanticId, String>,
) -> String {
    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason as Reason;
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        unreachable!("an incomplete binding diagnostic requires an incomplete completion")
    };
    let named = |semantic: &SemanticId| {
        let identity = if semantic.operation_local_number().is_some() {
            "runtime semantic".to_owned()
        } else {
            identities.get(semantic).cloned().unwrap_or_else(|| brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_diagnostic_identity("semantic", None, None, None))
        };
        match names.get(semantic) {
            Some(name) => format!("{identity}, {name}"),
            None => identity,
        }
    };
    let mut described = Vec::with_capacity(reasons.len());
    for reason in reasons.iter() {
        described.push(match reason {
            Reason::Cancelled => "cancelled".to_owned(),
            Reason::CyclicExpansion(path) => format!("cyclic_expansion({path})"),
            Reason::CyclicPrefixDependency(semantic) => {
                format!("cyclic_prefix_dependency({})", named(semantic))
            }
            Reason::InconsistentPrecedence(semantic) => {
                format!("inconsistent_precedence({})", named(semantic))
            }
            Reason::OpenBoundary { semantic, status } => {
                format!("open_boundary({}, {})", status.label(), named(semantic))
            }
            Reason::UnsupportedSemantic(semantic) => {
                format!("unsupported_semantic({})", named(semantic))
            }
            Reason::ReceiverBudgetExhausted(semantic) => {
                format!("receiver_budget_exhausted({})", named(semantic))
            }
            Reason::TimeBudgetExceeded(semantic) => {
                format!("time_budget_exceeded({})", named(semantic))
            }
            Reason::UnmountedFile { fragment } => format!("unmounted_file({fragment})"),
        });
    }
    // Every identity space can change encounter order across fresh stores.
    described.sort_unstable();
    described.join(", ")
}

/// Stage the member attribution the selected operation recorded, so the
/// candidate rows the trace publishes carry the owner the resolver found the
/// member on instead of no attribution at all.
///
/// Only targets the member lookup itself selected have a row. An associated
/// call that resolves through the scoped-owner path names no owner and is
/// deliberately left unattributed: absence is the correct report, and a depth
/// of zero would be a claim the resolver never made.
fn stage_rust_member_attribution(answers: &[SelectedRustReferenceAnswer]) {
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustMemberReach;

    use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

    use brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::HierarchyHopRecord;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::MemberEnrichment;
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    let staged = answers
        .iter()
        .flat_map(|answer| {
            answer.member_attributions.iter().filter_map(|attribution| {
                let name = answer
                    .definition_names
                    .iter()
                    .find(|(semantic, _)| *semantic == attribution.target)
                    .map(|(_, name)| name.clone())?;
                let (hierarchy_depth, dispatch_tier, route) = match &attribution.reach {
                    SelectedRustMemberReach::Direct {
                        declared_by_trait_implementation,
                    } => (
                        0,
                        if *declared_by_trait_implementation {
                            MemberDispatchTier::TraitOrInterface
                        } else {
                            MemberDispatchTier::InherentOrDirect
                        },
                        Vec::new(),
                    ),
                    SelectedRustMemberReach::Hierarchy {
                        owner_path,
                        implementation_hop,
                    } => (
                        owner_path.len() - 1,
                        MemberDispatchTier::TraitOrInterface,
                        owner_path
                            .windows(2)
                            .enumerate()
                            .map(|(hop, pair)| HierarchyHopRecord {
                                hop,
                                from: pair[0].clone(),
                                to: pair[1].clone(),
                                relation: if hop == 0 && *implementation_hop {
                                    HierarchyRelation::TraitImpl
                                } else {
                                    HierarchyRelation::Supertype
                                },
                            })
                            .collect(),
                    ),
                };
                Some((
                    name,
                    MemberEnrichment {
                        owner: attribution.owner.clone(),
                        hierarchy_depth,
                        dispatch_tier,
                        // The Rust member seam checks the member's namespace
                        // and nothing about the call shape, so the
                        // applicability axis is untested here.
                        applicability: ApplicabilityVerdict::Unknown,
                        route,
                    },
                ))
            })
        })
        .collect::<Vec<_>>();
    if staged.is_empty() {
        return;
    }
    brokk_bifrost_analysis::analyzer::usages::get_definition::trace::stage_member_context(staged);
}

/// An explicit modeled declaration can account for the exact invocation
/// that blocked binding, including an import boundary carrying that exact
/// inventory identity. Every remaining reason and every selected Cargo view
/// must be covered; an unrelated macro or native candidate remains incomplete.
fn modeled_macro_definitions(
    query: &BoundedReceiverQuery<'_>,
    answers: &[SelectedRustReferenceAnswer],
) -> Result<
    Vec<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelSymbol>>,
    brokk_bifrost_rust::graph_support::RustCargoRouteError,
> {
    use crate::analyzer::semantic_model::SemanticModelLocation;
    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;
    if answers.is_empty()
        || answers.iter().any(|answer| {
            !answer.resolution.binding().targets().is_empty()
                || !answer.definitions.is_empty()
                || !answer.lexical_definitions.is_empty()
                || !matches!(answer.resolution.binding().completion(),
                ResolutionCompletion::Incomplete(reasons) if reasons.iter().all(|reason| {
                    matches!(reason,
                        ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                        | ResolutionIncompleteReason::OpenBoundary {
                            semantic,
                            status: crate::analyzer::structural::BoundaryStatus::WorkspaceLocal,
                        }
                        if answer.macro_expansion_gaps.iter().any(|gap| gap.semantic == *semantic))
                }))
        })
    {
        return Ok(Vec::new());
    }
    let Some(overlay) = query.analyzer.semantic_model_overlay() else {
        return Ok(Vec::new());
    };
    let records = crate::analyzer::rust::generated_model::resolve_generated_functions(
        query.analyzer,
        &overlay,
        query.file,
        query.site,
    )?;
    let gaps = answers
        .iter()
        .flat_map(|answer| &answer.macro_expansion_gaps)
        .collect::<Vec<_>>();
    let covers = |symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
                  gap: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustMacroExpansionGap| {
        matches!(&symbol.location, SemanticModelLocation::Authored(anchor)
            if anchor.path == gap.relative_path
                && gap.start_byte <= anchor.range.start_byte
                && anchor.range.end_byte <= gap.end_byte)
    };
    if gaps.is_empty()
        || gaps
            .iter()
            .any(|gap| !records.iter().any(|symbol| covers(symbol, gap)))
        || records
            .iter()
            .any(|symbol| !gaps.iter().any(|gap| covers(symbol, gap)))
    {
        return Ok(Vec::new());
    }
    Ok(records)
}

/// The attribute-macro frontiers that cannot change which declaration one Rust
/// callable reference binds to, and the shape that closes them.
enum AttributeFrontierClosure {
    /// The reference binds a written inherent method.
    WrittenInherentMethod(
        Vec<brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustGapFrontier>,
    ),
    /// The reference is an unqualified macro invocation that no workspace
    /// declaration answers and that names a standard prelude macro.
    ExternalMacro(
        Vec<brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustGapFrontier>,
    ),
}

/// Decide whether the attribute-macro frontiers a lookup retained can be
/// ignored for the binding of one callable reference.
///
/// An attribute macro can add items, so a frontier is a gap in what the
/// module may declare. It cannot change the binding in these two shapes:
///
/// - A written inherent method. A duplicate inherent method would be a
///   compile error, and inherent methods take precedence over trait methods.
/// - An unqualified standard prelude macro (`println!`, `format!`, ...) that
///   no workspace declaration answers. An attribute expansion could change
///   this binding only by defining a `macro_rules!` with the same name earlier
///   in the module. This is an accepted assumption: Bifrost assumes no
///   attribute expansion does that, which matches what an expanding analyzer
///   sees for this binding. Owner decision, 2026-10-09, for the Rust
///   cleartext-logging parity work.
///
/// The native lookup has no prelude model for the macro namespace, so the
/// prelude macro has no canonical target or definition. Its name is decided
/// by the same standard-macro table the dispatch side uses.
fn rust_attribute_frontier_cannot_change_binding(
    answers: &[SelectedRustReferenceAnswer],
    completion: &ResolutionCompletion,
    canonical_targets: &std::collections::BTreeSet<SemanticId>,
    definitions: &[CodeUnit],
    lexical: &[LexicalDefinition],
    callee_name: &str,
) -> Option<AttributeFrontierClosure> {
    rust_written_inherent_method_frontiers(
        answers,
        completion,
        canonical_targets,
        definitions,
        lexical,
    )
    .map(AttributeFrontierClosure::WrittenInherentMethod)
    .or_else(|| {
        rust_external_macro_frontiers(
            answers,
            completion,
            canonical_targets,
            definitions,
            lexical,
            callee_name,
        )
        .map(AttributeFrontierClosure::ExternalMacro)
    })
}

/// The written inherent method shape. Its gate is the one on master: every
/// retained frontier must be an attribute-macro frontier, and the reference
/// must bind exactly one written inherent method.
fn rust_written_inherent_method_frontiers(
    answers: &[SelectedRustReferenceAnswer],
    completion: &ResolutionCompletion,
    canonical_targets: &std::collections::BTreeSet<SemanticId>,
    definitions: &[CodeUnit],
    lexical: &[LexicalDefinition],
) -> Option<
    Vec<brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustGapFrontier>,
> {
    let target = canonical_targets.iter().next()?;
    let [definition] = definitions else {
        return None;
    };
    if canonical_targets.len() != 1
        || !lexical.is_empty()
        || definition.is_synthetic()
        || !definition.is_callable()
    {
        return None;
    }
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return None;
    };
    if reasons.is_empty() {
        return None;
    }
    let retained_gap_frontiers = answers
        .iter()
        .flat_map(|answer| answer.retained_gap_frontiers.iter().copied())
        .collect::<Vec<_>>();
    let retained_semantics = retained_gap_frontiers
        .iter()
        .map(|frontier| frontier.semantic)
        .collect::<std::collections::BTreeSet<_>>();
    if !reasons.iter().all(|reason| {
        matches!(
            reason,
            crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                if retained_semantics.contains(semantic)
        )
    }) || retained_gap_frontiers.is_empty()
        || retained_gap_frontiers
            .iter()
            .any(|frontier| !frontier.kind.is_attribute_macro_frontier())
    {
        return None;
    }
    let callable_member_reference = answers.iter().any(|answer| {
        answer.resolution.site_metadata().is_some_and(|metadata| {
            metadata.namespace() == ResolutionNamespace::Callable
                && matches!(
                    metadata.site_kind(),
                    ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
                )
        })
    });
    if !callable_member_reference {
        return None;
    }
    let mut matching_inherent_members = answers
        .iter()
        .flat_map(|answer| answer.member_attributions.iter())
        .filter(|attribution| attribution.target == *target)
        .filter(|attribution| {
            matches!(
                &attribution.reach,
                brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustMemberReach::Direct {
                    declared_by_trait_implementation: false
                }
            ) && attribution.owner.is_class()
                && !attribution.owner.is_synthetic()
        });
    let _written_method = matching_inherent_members.next()?;
    if matching_inherent_members.next().is_some() {
        return None;
    }
    Some(retained_gap_frontiers)
}

/// The unqualified standard prelude macro shape. The reference must be an
/// unqualified macro reference whose name the standard-macro table owns, and
/// the lookup must have no workspace answer. Every incomplete reason must be
/// an operation-minted reason, or an unsupported semantic that names a
/// retained attribute-macro frontier.
fn rust_external_macro_frontiers(
    answers: &[SelectedRustReferenceAnswer],
    completion: &ResolutionCompletion,
    canonical_targets: &std::collections::BTreeSet<SemanticId>,
    definitions: &[CodeUnit],
    lexical: &[LexicalDefinition],
    callee_name: &str,
) -> Option<
    Vec<brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustGapFrontier>,
> {
    if !canonical_targets.is_empty()
        || !definitions.is_empty()
        || !lexical.is_empty()
        || crate::analyzer::rust::format_macro_dispatch::rust_standard_macro_prelude_owner(
            callee_name,
        )
        .is_none()
    {
        return None;
    }
    let unqualified_macro_reference = answers.iter().any(|answer| {
        answer.resolution.site_metadata().is_some_and(|metadata| {
            metadata.namespace() == ResolutionNamespace::Macro
                && metadata.site_kind() == ResolutionSiteKind::MacroReference
                && metadata.unqualified()
        })
    });
    if !unqualified_macro_reference {
        return None;
    }
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return None;
    };
    let retained_gap_frontiers = answers
        .iter()
        .flat_map(|answer| answer.retained_gap_frontiers.iter().copied())
        .collect::<Vec<_>>();
    let mut frontiers = Vec::new();
    for reason in reasons.iter() {
        let brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason::UnsupportedSemantic(semantic) =
            reason
        else {
            return None;
        };
        // An operation-minted reason is generated-surface noise to the same
        // gate in `generated_surface_only_completion`. Only this shape admits it.
        if semantic.operation_local_number().is_some() {
            continue;
        }
        let frontier = retained_gap_frontiers
            .iter()
            .find(|frontier| frontier.semantic == *semantic)?;
        if !frontier.kind.is_attribute_macro_frontier() {
            return None;
        }
        frontiers.push(*frontier);
    }
    // A completion of operation-minted reasons alone names no attribute
    // frontier, so it does not close on the frontier this rule is about.
    if frontiers.is_empty() {
        return None;
    }
    frontiers.sort_unstable_by_key(|frontier| (frontier.semantic, frontier.kind.evidence_name()));
    frontiers.dedup();
    Some(frontiers)
}

fn adapt_definition_answer(
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    answers: Vec<SelectedRustReferenceAnswer>,
    completion: ResolutionCompletion,
    qualified_route_head: bool,
) -> DefinitionLookupOutcome {
    let canonical_targets = answers
        .iter()
        .flat_map(|answer| answer.resolution.binding().targets().iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    let authored_member_candidate = answers
        .iter()
        .any(|answer| !answer.member_attributions.is_empty());

    let diagnostic_identities = answers
        .iter()
        .flat_map(|answer| answer.diagnostic_identities.iter().cloned())
        .collect::<BTreeMap<_, _>>();
    let project_identity = |semantic: &SemanticId| {
        diagnostic_identities.get(semantic).cloned().unwrap_or_else(|| brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_diagnostic_identity("semantic", None, None, None))
    };
    let definition_names = answers
        .iter()
        .flat_map(|answer| answer.definition_names.iter().cloned())
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut inventory_details = answers
        .iter()
        .flat_map(|answer| answer.inventory_details.iter().cloned())
        .collect::<Vec<_>>();
    inventory_details.sort_unstable();
    inventory_details.dedup();
    let undecided_macro_module = inventory_details
        .iter()
        .map(String::as_str)
        .chain(
            answers
                .iter()
                .flat_map(|answer| answer.named_reasons.iter())
                .filter_map(|(kind, evidence)| {
                    (*kind == "UnsupportedMacroGeneratedModule").then_some(evidence.as_str())
                }),
        )
        .any(|detail| {
            let parsed: serde_json::Value =
                serde_json::from_str(detail).expect("an open inventory detail is JSON");
            parsed["evidence"].as_array().is_some_and(|evidence| {
                evidence.iter().any(|item| {
                    item["reason"] == "UnsupportedMacroGeneratedModule"
                        && item["decided"].as_bool() == Some(false)
                })
            })
        });
    let macro_expansion_gaps = answers
        .iter()
        .flat_map(|answer| answer.macro_expansion_gaps.iter().cloned())
        .collect::<Vec<_>>();
    let generated_surface_gaps = answers
        .iter()
        .flat_map(|answer| answer.generated_surface_gaps.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    let generated_item_surface = answers.iter().any(|answer| {
        answer
            .named_reasons
            .iter()
            .any(|(kind, _)| *kind == "GeneratedItemSurface")
    }) || inventory_details.iter().any(|detail| {
        let parsed: serde_json::Value =
            serde_json::from_str(detail).expect("an open inventory detail is JSON");
        parsed["evidence"].as_array().is_some_and(|evidence| {
            evidence
                .iter()
                .any(|item| item["reason"] == "GeneratedItemSurface")
        })
    });
    let macro_generated_surface = macro_expansion_gaps
        .iter()
        .any(|gap| gap.macro_name != "include")
        || answers.iter().any(|answer| {
            answer.named_reasons.iter().any(|(kind, evidence)| {
                *kind == "UnsupportedMacroGeneratedModule"
                    && !evidence.contains("\"macro\":\"include\"")
            })
        });
    let callable_generated_surface = answers.iter().any(|answer| {
        answer.resolution.site_metadata().is_some_and(|metadata| {
            metadata.namespace() == ResolutionNamespace::Value
                && metadata.site_kind() == ResolutionSiteKind::CallableReference
        })
    }) && (generated_item_surface || macro_generated_surface);
    let member_generated_surface = macro_generated_surface
        && answers.iter().any(|answer| {
            answer
                .resolution
                .site_metadata()
                .is_some_and(|metadata| metadata.site_kind() == ResolutionSiteKind::MemberReference)
        });
    let qualified_type_generated_surface = generated_item_surface
        && qualified_route_head
        && answers.iter().any(|answer| {
            answer.resolution.site_metadata().is_some_and(|metadata| {
                metadata.namespace() == ResolutionNamespace::Type
                    && metadata.site_kind() == ResolutionSiteKind::TypeReference
            })
        });
    let mut named_reasons = answers
        .iter()
        .flat_map(|answer| answer.named_reasons.iter().cloned())
        .collect::<Vec<_>>();
    named_reasons.sort_unstable();
    named_reasons.dedup();
    let mut boundary_import_names = answers
        .iter()
        .flat_map(|answer| answer.boundary_import_names.iter().cloned())
        .collect::<Vec<_>>();
    boundary_import_names.sort_unstable();
    boundary_import_names.dedup();
    let prelude_value_member_reference = named_reasons
        .iter()
        .any(|(name, _)| *name == "rust_prelude_item")
        && answers.iter().any(|answer| {
            answer.resolution.site_metadata().is_some_and(|metadata| {
                metadata.site_kind() == ResolutionSiteKind::MemberReference
                    && metadata.namespace() == ResolutionNamespace::Value
            })
        });
    stage_rust_member_attribution(&answers);
    let mut definitions = Vec::new();
    let mut lexical = Vec::new();
    let mut examined_answers = 0usize;
    for answer in &answers {
        if !definition_answer_abstains(&answer.resolution) {
            examined_answers += 1;
        }
        definitions.extend(answer.definitions.iter().cloned());
        lexical.extend(answer.lexical_definitions.iter().cloned());
    }
    definitions.sort_unstable();
    definitions.dedup();
    lexical.sort_by(|left, right| {
        left.identifier
            .cmp(&right.identifier)
            .then_with(|| {
                left.declaration_range
                    .start_byte
                    .cmp(&right.declaration_range.start_byte)
            })
            .then_with(|| {
                left.declaration_range
                    .end_byte
                    .cmp(&right.declaration_range.end_byte)
            })
    });
    lexical.dedup();
    // One open inventory can be open for more than one reason (an undecided
    // item macro, a withheld declaration); each reason its evidence names is
    // one diagnostic kind, carrying the whole detail.
    let mut diagnostics = inventory_details
        .into_iter()
        .flat_map(|detail| {
            let parsed: serde_json::Value =
                serde_json::from_str(&detail).expect("an open inventory detail is JSON");
            let mut reasons = parsed["evidence"]
                .as_array()
                .expect("an open inventory detail lists its evidence")
                .iter()
                .map(|evidence| {
                    evidence["reason"]
                        .as_str()
                        .expect("open inventory evidence names its reason")
                        .to_owned()
                })
                .collect::<Vec<_>>();
            reasons.sort_unstable();
            reasons.dedup();
            reasons
                .into_iter()
                .map(move |kind| DefinitionLookupDiagnostic {
                    claim: None,
                    kind,
                    message: detail.clone(),
                })
        })
        .chain(
            named_reasons
                .into_iter()
                .map(|(name, evidence)| DefinitionLookupDiagnostic {
                    claim: None,
                    kind: name.to_owned(),
                    message: evidence,
                }),
        )
        .collect::<Vec<_>>();
    for gap in &macro_expansion_gaps {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "UnsupportedMacroGeneratedSurface".to_owned(),
            message: diagnostic_json(serde_json::json!({
                "evidence": [{
                    "reason": "UnexpandedMacroBoundary",
                    "macro": gap.macro_name,
                    "rel_path": gap.relative_path,
                    "start_byte": gap.start_byte,
                    "end_byte": gap.end_byte,
                }]
            })),
        });
    }
    let mut public_generated_surface_gaps = generated_surface_gaps
        .iter()
        .map(project_identity)
        .collect::<Vec<_>>();
    public_generated_surface_gaps.sort_unstable();
    for semantic in public_generated_surface_gaps {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "GeneratedItemSurface".to_owned(),
            message: diagnostic_json(serde_json::json!({
                "evidence": [{
                    "reason": "GeneratedItemSurface",
                    "semantic": semantic,
                }]
            })),
        });
    }
    if lexical.len() > 1 {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_lexical_definition".to_owned(),
            message: format!(
                "selected Rust binding has multiple lexical definitions; no winner was selected: {lexical:?}"
            ),
        });
    }
    // The shape and its reasons are decided by
    // `rust_attribute_frontier_cannot_change_binding`, which documents why an
    // attribute frontier cannot change this binding.
    let attribute_frontier_closure = rust_attribute_frontier_cannot_change_binding(
        &answers,
        &completion,
        &canonical_targets,
        &definitions,
        &lexical,
        &site.text,
    );
    // A reference that reached a block-local item names it, although the item
    // has no parser unit; see `rust_block_local_binding_is_decided`.
    let binding_complete = matches!(completion, ResolutionCompletion::Complete)
        || brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_block_local_binding_is_decided(
            &definitions,
            &lexical,
            &completion,
        )
        || attribute_frontier_closure.is_some();
    let lexical_count = lexical.len();
    let lexical_definition = (lexical_count == 1).then(|| lexical.remove(0));
    // Display CodeUnits can compare equal for distinct source declarations.
    // Deduplicate aliases by canonical target identity, before projecting that
    // identity into the public presentation vocabulary.
    let canonical_target_count = canonical_targets.len();
    // A conflicting intermediate binding remains ambiguous after its routes
    // converge on one endpoint. The completion, not the displayed target
    // count, records whether the language orders the alternatives.
    let unordered_candidates =
        brokk_bifrost_analysis::analyzer::native_points::is_precedence_ambiguity(&completion);
    // A value member reached through a named Rust prelude item is still an
    // open member lookup. The prelude boundary does not establish that the
    // selected member belongs to std.
    let external_boundary = !prelude_value_member_reference
        && canonical_target_count == 0
        && lexical_definition.is_none()
        && matches!(&completion, ResolutionCompletion::Incomplete(reasons)
        if reasons.iter().all(|reason| matches!(reason,
            crate::analyzer::resolution::ResolutionIncompleteReason::OpenBoundary {
                status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                ..
            }
        )));
    // A selected source or lexical candidate can be only the authored side of
    // an unexpanded generated surface. When the completion contains no other
    // kind of gap and no displayable definition, preserve the partial local
    // binding while grading the missing generated member as a boundary.
    let macro_module_boundary = diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == "UnsupportedMacroGeneratedModule"
            && !diagnostic.message.contains("\"macro\":\"include\"")
    });
    let private_macro_module_boundary = macro_expansion_gaps
        .iter()
        .any(|gap| gap.private_module_route);
    let generated_surface_completion = macro_module_boundary
        || callable_generated_surface
        || member_generated_surface
        || qualified_type_generated_surface
        || diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "UnplacedRoutePrefix")
        || !generated_surface_gaps.is_empty();
    let generated_surface_only_completion = generated_surface_completion
        && matches!(&completion, ResolutionCompletion::Incomplete(reasons)
        if !reasons.is_empty() && reasons.iter().all(|reason| match reason {
            crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                generated_surface_gaps.contains(semantic)
                    || semantic.operation_local_number().is_some()
                    || callable_generated_surface
                    || member_generated_surface
                    || qualified_type_generated_surface
            }
            crate::analyzer::resolution::ResolutionIncompleteReason::OpenBoundary { .. } => {
                callable_generated_surface
                    || (member_generated_surface && diagnostics.iter().any(|diagnostic| {
                        diagnostic.kind == "UnsupportedMacroGeneratedSurface"
                    }))
            }
            _ => false,
        }));
    // Keep the specific structured reason beside the boundary status so
    // census consumers distinguish unsupported macro/attribute surfaces from
    // external crates.
    let generated_surface_evidence = generated_surface_only_completion
        && ((callable_generated_surface && (generated_item_surface || macro_module_boundary))
            || (macro_module_boundary && private_macro_module_boundary)
            || member_generated_surface
            || qualified_type_generated_surface
            || !generated_surface_gaps.is_empty())
        && diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic.kind.as_str(),
                "UnsupportedMacroGeneratedModule"
                    | "UnsupportedMacroGeneratedSurface"
                    | "UnloweredDeclaration"
                    | "GeneratedItemSurface"
            )
        });
    // A macro boundary on an ordinary member lookup leaves the authored
    // member candidate undecided. An explicit generated-item or generated
    // module fact is required before that surface closes the lookup.
    let member_generated_surface_boundary = member_generated_surface
        && (generated_item_surface || !generated_surface_gaps.is_empty() || macro_module_boundary);
    // A macro gate in a different module file is a concrete selected route
    // from this reference to that generated surface. A direct lookup in the
    // file with the undecided module declaration stays open.
    let explicit_macro_gated_import_route = macro_module_boundary
        && macro_expansion_gaps
            .iter()
            .any(|gap| gap.relative_path != site.path);
    let has_external_declared_unindexed_boundary = matches!(
        &completion,
        ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(
                reason,
                crate::analyzer::resolution::ResolutionIncompleteReason::OpenBoundary {
                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    ..
                }
            ))
    );
    let generated_surface_boundary = generated_surface_evidence
        && !authored_member_candidate
        && definitions.is_empty()
        && lexical_count == 0
        && (!undecided_macro_module
            || explicit_macro_gated_import_route
            || (member_generated_surface_boundary && !has_external_declared_unindexed_boundary))
        && (!member_generated_surface || member_generated_surface_boundary);
    // An undecided macro module accounts for the unresolved name, so its
    // generic route gap adds nothing. An unrelated generated surface must not
    // erase the evidence for a genuine unplaced prefix.
    let generated_surface_replaces_route_gap =
        generated_surface_boundary || (macro_module_boundary && undecided_macro_module);
    if generated_surface_replaces_route_gap {
        diagnostics.retain(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix");
    }
    if generated_surface_boundary {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: brokk_bifrost_analysis::analyzer::usages::get_definition::RUST_UNSUPPORTED_GENERATED_SURFACE_BOUNDARY_DIAGNOSTIC_KIND
                .to_owned(),
            message: "selected Rust binding stops at a structured macro or attribute surface"
                .to_owned(),
        });
    }
    let inactive_cfg_boundary = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "InactiveCfgPlacement");
    if inactive_cfg_boundary {
        diagnostics.retain(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix");
    }
    let status = if external_boundary {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: (!boundary_import_names.is_empty()).then(|| {
                UnindexedClaim::external_boundary_many(boundary_import_names, ClaimSubjectRole::Any)
            }),
            kind: "unindexed_import_boundary".to_owned(),
            message: format!("selected Rust binding reaches an unindexed import: {}", brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_completion_details(&completion, |id| project_identity(&id))),
        });
        DefinitionLookupStatus::UnresolvableImportBoundary
    } else if generated_surface_boundary || inactive_cfg_boundary {
        DefinitionLookupStatus::UnresolvableImportBoundary
    } else if unordered_candidates {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "unordered_candidates".to_owned(),
            message: format!(
                "the language orders none of these candidates over the others (for Rust trait items, rustc E0034: multiple applicable items in scope): {:?}; {}",
                definitions.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                describe_incomplete_binding(&completion, &definition_names, &diagnostic_identities)
            ),
        });
        DefinitionLookupStatus::Ambiguous
    } else if !binding_complete {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "incomplete_binding".to_owned(),
            message: format!(
                "selected Rust binding is incomplete: {}",
                describe_incomplete_binding(&completion, &definition_names, &diagnostic_identities)
            ),
        });
        DefinitionLookupStatus::Incomplete
    } else if canonical_target_count > 1 {
        DefinitionLookupStatus::Ambiguous
    } else if definitions.is_empty() {
        if lexical_definition.is_some() {
            DefinitionLookupStatus::Resolved
        } else if examined_answers == 0 {
            // No selected alternative exposed a binding or type observation.
            // Do not turn unexamined type syntax into a proved absence.
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: "unprojected_type_frontier".to_owned(),
                message: "selected Rust reference carries no binding candidate, so its definition frontier was not examined".to_owned(),
            });
            DefinitionLookupStatus::Incomplete
        } else {
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: "no_indexed_definition".to_owned(),
                message: "the selected Rust binding has no source-backed definition".to_owned(),
            });
            DefinitionLookupStatus::NoDefinition
        }
    } else if definitions.len() == 1 && lexical_definition.is_none() {
        DefinitionLookupStatus::Resolved
    } else if definitions.len() == 1 && lexical_definition.is_some() {
        DefinitionLookupStatus::Ambiguous
    } else {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_definition".to_owned(),
            message: "selected Rust binding resolved to multiple workspace definitions".to_owned(),
        });
        DefinitionLookupStatus::Ambiguous
    };
    let mut attribute_frontier_evidence = answers
        .iter()
        .flat_map(|answer| answer.retained_gap_frontiers.iter().copied())
        .filter(|frontier| frontier.kind.is_attribute_macro_frontier())
        .collect::<Vec<_>>();
    attribute_frontier_evidence
        .sort_unstable_by_key(|frontier| (frontier.semantic, frontier.kind.evidence_name()));
    attribute_frontier_evidence.dedup();
    attribute_frontier_evidence.sort_unstable_by_key(|frontier| {
        (
            project_identity(&frontier.semantic),
            frontier.kind.evidence_name(),
        )
    });
    if attribute_frontier_closure.is_none() {
        for frontier in attribute_frontier_evidence {
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: "GeneratedItemSurface".to_owned(),
                // #6112: diagnostic JSON keys stay stable across feature unification.
                message: diagnostic_json(serde_json::json!({
                    "evidence": [{
                        "gap_kind": frontier.kind.evidence_name(),
                        "native_macro_invocation": false,
                        "reason": "GeneratedItemSurface",
                        "semantic": project_identity(&frontier.semantic),
                    }]
                })),
            });
        }
    }
    if let Some(closure) = attribute_frontier_closure {
        let (kind, reason, mut frontiers) = match closure {
            AttributeFrontierClosure::WrittenInherentMethod(frontiers) => (
                "attribute_macro_frontier_cannot_change_inherent_dispatch",
                "attribute macro frontier cannot change inherent dispatch",
                frontiers,
            ),
            AttributeFrontierClosure::ExternalMacro(frontiers) => (
                "attribute_macro_frontier_cannot_change_external_macro_binding",
                "attribute macro frontier cannot change external macro binding",
                frontiers,
            ),
        };
        frontiers.sort_unstable_by_key(|frontier| {
            (
                project_identity(&frontier.semantic),
                frontier.kind.evidence_name(),
            )
        });
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.to_owned(),
            message: diagnostic_json(serde_json::json!({
                "evidence": frontiers.iter().map(|frontier| serde_json::json!({
                    "gap_kind": frontier.kind.evidence_name(),
                    "semantic": project_identity(&frontier.semantic),
                })).collect::<Vec<_>>(),
                "reason": reason,
            })),
        });
    }
    if generated_surface_evidence && status == DefinitionLookupStatus::Incomplete {
        let incomplete = diagnostics
            .iter()
            .position(|diagnostic| diagnostic.kind == "incomplete_binding")
            .expect("an incomplete generated surface has an incomplete-binding diagnostic");
        let diagnostic = diagnostics.remove(incomplete);
        diagnostics.insert(0, diagnostic);
    }
    if status == DefinitionLookupStatus::Ambiguous
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "ambiguous_definition")
        && definitions.len() > 1
    {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_definition".to_owned(),
            message: "selected Rust binding resolved to multiple workspace definitions".to_owned(),
        });
    }
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: Some(site.clone()),
        definitions,
        lexical_definition,
        diagnostics,
    };
    brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_units(
        &outcome,
    );
    // A lexical binding is the answer, so the trace has to carry it as the
    // selection. The shared lexical constructor records this row for every
    // other language; the selected Rust operation builds its own outcome and
    // reached the trace with no selected candidate at all, which let a
    // consumer read a complete trace whose only row was a rejected peer.
    if outcome.status == DefinitionLookupStatus::Resolved {
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_lexical(
            &outcome,
        );
    }
    outcome
}

fn adapt_type_value(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    value: SelectedRustCallerReferenceOutcome<SelectedRustTypeProjection>,
) -> TypeLookupOutcome {
    let site = query.site;
    match value {
        SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile => complete_type(
            site,
            TypeLookupStatus::Unavailable,
            "unsupported_caller_profile",
            "the selected Rust caller profile is not supported by native resolution",
            TypeLookupTargetKind::ValueExpression,
        )
        .into_complete_value(),
        SelectedRustCallerReferenceOutcome::Operation(outcome) => match outcome {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                complete_type(
                    site,
                    TypeLookupStatus::Unavailable,
                    "native_reference_missing",
                    "the structured Rust reference site is absent from selected native facts",
                    TypeLookupTargetKind::ValueExpression,
                )
                .into_complete_value()
            }
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) => adapt_type_answer(query, rust, answer),
            SelectedResolutionOperationOutcome::Unavailable(reason) => complete_type(
                site,
                TypeLookupStatus::Unavailable,
                "native_unavailable",
                format!("selected Rust type operation is unavailable: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Stale(reason) => complete_type(
                site,
                TypeLookupStatus::Unavailable,
                "native_stale",
                format!("selected Rust type operation is stale: {reason:?}"),
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_value(),
            SelectedResolutionOperationOutcome::Cancelled(_) => complete_type(
                site,
                TypeLookupStatus::Cancelled,
                "cancelled",
                "selected Rust type operation was cancelled",
                TypeLookupTargetKind::ValueExpression,
            )
            .into_complete_value(),
        },
    }
}

fn adapt_type_answer(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    answers: Vec<SelectedRustReferenceAnswer<SelectedRustTypeProjection>>,
) -> TypeLookupOutcome {
    let site = query.site;
    let diagnostic_identities = answers
        .iter()
        .flat_map(|answer| {
            answer
                .projection
                .diagnostic_identities
                .iter()
                .chain(answer.diagnostic_identities.iter())
        })
        .cloned()
        .collect::<BTreeMap<_, _>>();
    let project_identity = |semantic: SemanticId| {
        diagnostic_identities.get(&semantic).cloned().unwrap_or_else(|| brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_diagnostic_identity("semantic", None, None, None))
    };

    let local_declaration = match answers.as_slice() {
        [answer] if answer.definitions.is_empty() => match answer.lexical_definitions.as_slice() {
            [definition] => Some(definition.clone()),
            _ => None,
        },
        _ => None,
    };
    let mut diagnostics = Vec::new();
    let mut canonical_types = BTreeMap::<(SemanticId, u32), (String, Vec<CodeUnit>)>::new();
    let mut typed_complete = true;
    let mut target_kind = None;
    let mut projected_answers = 0usize;
    for answer in &answers {
        diagnostics.extend(
            answer
                .projection
                .named_reasons
                .iter()
                .map(|(kind, message)| TypeLookupDiagnostic {
                    kind: (*kind).to_owned(),
                    message: message.clone(),
                }),
        );
        if reference_answer_has_no_candidate(&answer.resolution) {
            continue;
        }
        // A member-owner projection names the declaration whose members a
        // literal writes, not the type of the expression that writes them:
        // `Enum::Variant { .. }` has type `Enum` and writes `Variant`'s
        // fields. The owner path carries distinct projection outputs on one
        // occurrence, so a type query reads the type frontier and leaves the
        // member-owner frontier to the field lookup that asked for it.
        if answer.resolution.observed_type_identity().is_none()
            && !answer.resolution.projections().is_empty()
            && answer
                .resolution
                .projections()
                .iter()
                .all(|projection| projection.kind() == BindingProjectionKind::TargetMemberOwnerType)
        {
            continue;
        }
        projected_answers += 1;
        let observed_identity = answer.resolution.observed_type_identity();
        let (alternative_kind, selected_projection_kind, projection_kinds) =
            if observed_identity.is_some() {
                (
                    TypeLookupTargetKind::TypeReference,
                    Some(BindingProjectionKind::TargetTypeIdentity),
                    vec![BindingProjectionKind::TargetTypeIdentity],
                )
            } else {
                projection_target_kind(answer.resolution.projections())
            };
        target_kind = Some(match target_kind {
            Some(existing) if existing != alternative_kind => TypeLookupTargetKind::ValueExpression,
            _ => alternative_kind,
        });
        let mut selected_frontier_count = 0usize;
        if answer.resolution.projections().is_empty() && observed_identity.is_none() {
            typed_complete = false;
            diagnostics.push(TypeLookupDiagnostic {
                kind: "missing_type_projection".to_owned(),
                message: "selected Rust reference has no typed projection metadata".to_owned(),
            });
        }
        if !matches!(
            answer.resolution.binding().completion(),
            ResolutionCompletion::Complete
        ) {
            typed_complete = false;
            diagnostics.push(TypeLookupDiagnostic {
                kind: "incomplete_binding".to_owned(),
                message: "selected Rust binding is incomplete; its type is not exact".to_owned(),
            });
        }
        let output_slots = answer
            .resolution
            .projections()
            .iter()
            .filter(|projection| Some(projection.kind()) == selected_projection_kind)
            .map(|projection| projection.output_slot())
            .chain(observed_identity);
        for output_slot in output_slots {
            let Some(frontier) = answer
                .resolution
                .projected_frontiers()
                .iter()
                .find(|frontier| frontier.slot() == output_slot)
            else {
                typed_complete = false;
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "missing_typed_frontier".to_owned(),
                    message: format!(
                        "selected Rust projection {:?} has no output frontier",
                        selected_projection_kind
                    ),
                });
                continue;
            };
            selected_frontier_count += 1;
            if !matches!(frontier.completion(), ResolutionCompletion::Complete) {
                typed_complete = false;
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "incomplete_typed_frontier".to_owned(),
                    message: format!(
                        "selected Rust type frontier is incomplete: {}",
                        brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_completion_details(frontier.completion(), project_identity)
                    ),
                });
            }
            for value in frontier.possible_values() {
                let identity = value.ty().identity();
                if let Some(descriptor) = answer
                    .projection
                    .intrinsic_types
                    .iter()
                    .find(|descriptor| descriptor.identity() == identity)
                {
                    let fqn = render_type_spelling(descriptor.spelling(), *value, &mut diagnostics);
                    canonical_types
                        .entry((identity, value.ty().indirection()))
                        .or_insert((fqn, Vec::new()));
                    continue;
                }
                let Some(source_definition) = answer
                    .projection
                    .nominal_types
                    .iter()
                    .find(|(candidate, _)| *candidate == identity)
                    .map(|(_, definition)| definition)
                else {
                    typed_complete = false;
                    diagnostics.push(TypeLookupDiagnostic {
                        kind: "missing_nominal_type_definition".to_owned(),
                        message: format!(
                            "selected Rust type identity {} has no source definition",
                            project_identity(identity)
                        ),
                    });
                    continue;
                };
                match source_definition {
                    SelectedRustSourceDefinition::Unit(unit) => {
                        let fqn = render_type_spelling(&unit.fq_name(), *value, &mut diagnostics);
                        canonical_types
                            .entry((identity, value.ty().indirection()))
                            .or_insert_with(|| (fqn, Vec::new()))
                            .1
                            .push(unit.clone());
                    }
                    SelectedRustSourceDefinition::Lexical(definition) => {
                        typed_complete = false;
                        diagnostics.push(TypeLookupDiagnostic {
                        kind: "unsupported_lexical_type_definition".to_owned(),
                        message: format!(
                            "selected Rust type identity has lexical source evidence but no nominal CodeUnit: {definition:?}"
                        ),
                    });
                    }
                    SelectedRustSourceDefinition::WithoutUnit {
                        source_file,
                        declaration_range,
                    } => {
                        typed_complete = false;
                        diagnostics.push(TypeLookupDiagnostic {
                            kind: "unsupported_unit_less_type_definition".to_owned(),
                            message: format!(
                                "selected Rust type identity is declared where the parser published no CodeUnit: {source_file:?} {declaration_range:?}"
                            ),
                        });
                    }
                    // A language universe entry (`i64`) is a type with no
                    // source declaration at all.
                    SelectedRustSourceDefinition::UniverseEntry => {
                        typed_complete = false;
                        diagnostics.push(TypeLookupDiagnostic {
                            kind: "unsupported_unit_less_type_definition".to_owned(),
                            message: format!(
                                "selected Rust type identity {} is a language universe entry with no source declaration", project_identity(identity)
                            ),
                        });
                    }
                }
            }
        }
        if selected_frontier_count == 0 && !answer.resolution.projections().is_empty() {
            typed_complete = false;
        }
        if projection_kinds.len() > 1 {
            diagnostics.push(TypeLookupDiagnostic {
            kind: "ambiguous_type_projection_kind".to_owned(),
            message: format!(
                "selected Rust reference has projection kinds {projection_kinds:?}; only {selected_projection_kind:?} was projected"
            ),
        });
        }
    }
    let canonical_type_count = canonical_types.len();
    let mut canonical_keys = canonical_types
        .keys()
        .map(|(identity, depth)| (project_identity(*identity), *depth))
        .collect::<Vec<_>>();
    canonical_keys.sort_unstable();
    let mut types = BTreeMap::<String, Vec<CodeUnit>>::new();
    for (fqn, definitions) in canonical_types.into_values() {
        types.entry(fqn).or_default().extend(definitions);
    }
    for definitions in types.values_mut() {
        definitions.sort_unstable();
        definitions.dedup();
    }
    let mut types = types
        .into_iter()
        .map(|(fqn, definitions)| TypeLookupType {
            fqn,
            definitions,
            semantic_model_id: None,
        })
        .collect::<Vec<_>>();
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_mut_reference_qualifier")
    {
        typed_complete = false;
    }
    let status = if !typed_complete {
        TypeLookupStatus::Incomplete
    } else if projected_answers == 0 {
        // No selected alternative exposed a type producer or observation.
        diagnostics.push(TypeLookupDiagnostic {
            kind: "unprojected_type_frontier".to_owned(),
            message: "selected Rust reference carries no typed projection, so its type frontier was not examined".to_owned(),
        });
        TypeLookupStatus::Incomplete
    } else if types.is_empty() {
        // The type frontier was examined and named nothing. Say so: the status
        // alone cannot tell a proved absence from a route that never looked,
        // and the decided-negative guard reads the kind, not the status.
        diagnostics.push(TypeLookupDiagnostic {
            kind: brokk_bifrost_analysis::analyzer::usages::get_definition::RUST_NO_TYPED_PROJECTION_DIAGNOSTIC_KIND
                .to_owned(),
            message: "the selected Rust type frontier was complete and named no type".to_owned(),
        });
        TypeLookupStatus::NoType
    } else if canonical_type_count == 1 {
        TypeLookupStatus::Resolved
    } else {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "ambiguous_type".to_owned(),
            message: format!(
                "selected Rust typed projections retain multiple canonical types: keys={canonical_keys:?}, displayed={:?}",
                types.iter().map(|ty| &ty.fqn).collect::<Vec<_>>()
            ),
        });
        TypeLookupStatus::Ambiguous
    };
    if status == TypeLookupStatus::Resolved
        && let [candidate] = types.as_mut_slice()
        && let Some(definition) = local_declaration.as_ref()
        && let Some(alias_fqn) = rust_local_type_alias_display_fqn(query, rust, definition)
    {
        // Keep the written local alias as the type's display name while the
        // candidate definitions retain the canonical target used by member
        // resolution.
        candidate.fqn = alias_fqn;
    }
    TypeLookupOutcome {
        status,
        reference: Some(site.clone()),
        types,
        diagnostics,
        target_kind: target_kind.unwrap_or(TypeLookupTargetKind::ValueExpression),
    }
}

fn rust_local_type_alias_display_fqn(
    query: BoundedReceiverQuery<'_>,
    rust: &RustAnalyzer,
    definition: &brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalDefinition,
) -> Option<String> {
    assert!(
        definition
            .source_file
            .as_ref()
            .is_none_or(|file| file == query.file),
        "local Rust binding belongs to another source file: {:?}",
        definition.source_file
    );
    let tree = query.tree?;
    let range = &definition.declaration_range;
    let mut declaration = tree
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while !matches!(
        declaration.kind(),
        "let_declaration" | "parameter" | "closure_parameter"
    ) {
        declaration = declaration.parent()?;
    }
    let alias_type = declaration.child_by_field_name("type")?;
    if !matches!(
        alias_type.kind(),
        "type_identifier" | "scoped_type_identifier" | "scoped_identifier"
    ) {
        return None;
    }
    let site = brokk_bifrost_core::analyzer::usages::reference_site::resolve_reference_site(
        &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest {
            file: query.file.clone(),
            line: None,
            column: None,
            start_byte: Some(alias_type.start_byte()),
            end_byte: Some(alias_type.end_byte()),
        },
        query.source,
        Some(tree.root_node()),
    )
    .ok()?;
    let resolution = resolve_rust_definition_bounded(BoundedReceiverQuery {
        site: &site,
        ..query
    });
    let BoundedResolution::Complete { value, .. } = resolution else {
        return None;
    };
    let [alias] = value.definitions.as_slice() else {
        return None;
    };
    (value.status == DefinitionLookupStatus::Resolved && rust.is_type_alias(alias))
        .then(|| alias.fq_name().to_owned())
}

pub(crate) fn render_type_spelling(
    spelling: &str,
    value: ResolutionSlotValue,
    diagnostics: &mut Vec<TypeLookupDiagnostic>,
) -> String {
    let indirection = value.ty().indirection() as usize;
    if matches!(
        value,
        ResolutionSlotValue::Runtime {
            addressable: true,
            ..
        }
    ) && indirection > 0
    {
        diagnostics.push(TypeLookupDiagnostic {
            kind: "unsupported_mut_reference_qualifier".to_owned(),
            message: format!(
                "selected Rust typed value retains mutable reference evidence for `{spelling}`; the public type projection cannot encode `&mut` exactly"
            ),
        });
    }
    format!("{}{}", "&".repeat(indirection), spelling)
}

struct CompleteOutcome<T>(T);

impl<T> CompleteOutcome<T> {
    fn into_complete_value(self) -> T {
        self.0
    }

    fn into_complete_resolution(self) -> BoundedResolution<T> {
        BoundedResolution::Complete {
            value: self.0,
            work: ReceiverAnalysisWork::default(),
        }
    }
}

fn complete_definition(
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    status: DefinitionLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> CompleteOutcome<DefinitionLookupOutcome> {
    CompleteOutcome(DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: Some(site.clone()),
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.into(),
            message: message.into(),
        }],
    })
}

fn complete_type(
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    status: TypeLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
    target_kind: TypeLookupTargetKind,
) -> CompleteOutcome<TypeLookupOutcome> {
    CompleteOutcome(TypeLookupOutcome {
        status,
        reference: Some(site.clone()),
        types: Vec::new(),
        diagnostics: vec![TypeLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
        }],
        target_kind,
    })
}
