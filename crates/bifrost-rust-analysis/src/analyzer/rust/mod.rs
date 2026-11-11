use brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::delegate_inner_test_hook_methods;
use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};

use crate::analyzer::rust::source_storage::RustSourceStorage;
#[doc(hidden)]
pub mod adapter;
mod call_conversion;
mod cargo_routes;
mod clones;
#[doc(hidden)]
pub mod crate_identity;
mod dependency_discovery;
pub(crate) mod diagnostics;
mod external;
pub(crate) mod external_calls;
#[doc(hidden)]
pub mod fact_catch_up;
pub mod failure_handlers;
mod file_dependency_evidence;
mod format_macro_dispatch;
#[doc(hidden)]
pub mod generated_model;
mod graph_support;
mod hierarchy;
mod imports;
mod modeled_members;
pub(crate) mod native_call_projection;
#[doc(hidden)]
pub mod native_graph;
mod native_outgoing;
#[doc(hidden)]
pub mod native_points;
#[doc(hidden)]
pub mod native_rename;
#[doc(hidden)]
pub mod native_usages;
mod pattern_admission;
#[doc(hidden)]
pub mod route_kinds;
mod toolchain_evidence;
mod trait_applicability;
mod value_type_barriers;

pub use crate::analyzer::rust::native_usages::RustNativeUsageStrategy;
pub(crate) mod prefetch;
mod rustdoc_artifact;
pub(crate) mod selected_projection;
#[doc(hidden)]
pub mod selected_reverse;
#[doc(hidden)]
pub mod selected_shadow;
#[doc(hidden)]
pub mod semantic;
mod site_activation;
mod topology;

pub(crate) use crate::analyzer::rust::semantic::RustReceiverTypeFacts;

pub(crate) fn rust_call_reference_candidate(node: tree_sitter::Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "macro_invocation" if parent.child_by_field_name("macro") == Some(current) => {
                return true;
            }
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "scoped_identifier" | "field_expression" => current = parent,
            "generic_function" if parent.child_by_field_name("function") == Some(current) => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

/// One identity predicate for selected evaluation and analysis owner proofs.
pub(crate) struct SelectedTypeHeadEvidence<'a> {
    prelude_item: Option<(&'a str, &'a str, &'a str)>,
    external_path: &'a [String],
}

/// Owned selected inputs, so the bounded source is free for subsequent reads.
struct SelectedTypeHeadInputs {
    prelude_item: Option<(String, String, String)>,
    import_paths: Vec<Vec<String>>,
    // Only cached routes can supply a proven wrapper path. A fallback route
    // remains evidence to classify, not a new canonical proof.
    cached_path_count: usize,
}

fn read_selected_type_head(
    semantic: brokk_bifrost_analysis::analyzer::resolution::SemanticId,
    source: &mut dyn brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeHeadSource,
) -> brokk_bifrost_analysis::analyzer::store::Result<Option<SelectedTypeHeadInputs>> {
    let named = source.named_reason(semantic);
    let prelude = named
        .as_ref()
        .filter(|(name, _)| *name == "rust_prelude_item")
        .map(|(_, json)| {
            serde_json::from_str::<serde_json::Value>(json)
                .expect("selected prelude evidence is JSON")
        });
    let prelude_item = prelude.as_ref().and_then(|item| {
        Some((
            item["crate"].as_str()?.to_owned(),
            item["name"].as_str()?.to_owned(),
            item["namespace"].as_str()?.to_owned(),
        ))
    });
    let mut import_paths = source.cached_external_type_import_paths(semantic);
    let cached_path_count = import_paths.len();
    if import_paths.is_empty() {
        let Some(path) = source.external_type_import_path(semantic)? else {
            return Ok(None);
        };
        if !path.is_empty() {
            import_paths.push(path);
        }
    }
    Ok(Some(SelectedTypeHeadInputs {
        prelude_item,
        import_paths,
        cached_path_count,
    }))
}

pub(crate) fn standard_unwrap_payload_name(name: &str) -> bool {
    matches!(
        name,
        "std.option.Option"
            | "core.option.Option"
            | "alloc.option.Option"
            | "std.result.Result"
            | "core.result.Result"
            | "alloc.result.Result"
            | "std.io.Result"
            | "std.thread.Result"
    )
}

fn standard_wrapper_payload(
    evidence: &SelectedTypeHeadEvidence<'_>,
) -> Option<brokk_bifrost_analysis::analyzer::store::language_support::WrapperPayloadProjection> {
    use brokk_bifrost_analysis::analyzer::store::language_support::WrapperPayloadProjection;
    let delta = if let Some((root, name, namespace)) = evidence.prelude_item {
        if !matches!(root, "std" | "core" | "alloc") || namespace != "type" {
            return None;
        }
        match name {
            "Box" | "Arc" | "Rc" => 0,
            "Option" | "Result"
                if standard_unwrap_payload_name(&format!(
                    "{root}.{}.{}",
                    if name == "Option" { "option" } else { "result" },
                    name
                )) =>
            {
                1
            }
            _ => return None,
        }
    } else {
        let [root, module, name] = evidence.external_path else {
            return None;
        };
        if !matches!(root.as_str(), "std" | "core" | "alloc") {
            return None;
        }
        match (module.as_str(), name.as_str()) {
            ("boxed", "Box") | ("sync", "Arc") | ("rc", "Rc") => 0,
            _ if standard_unwrap_payload_name(&format!("{root}.{module}.{name}")) => 1,
            _ => return None,
        }
    };
    Some(WrapperPayloadProjection {
        ordinal: 0,
        indirection_delta: delta,
    })
}

/// Classify selected identity evidence, never the impl header's spelling.
fn standard_deref_trait(evidence: &SelectedTypeHeadEvidence<'_>) -> bool {
    if let Some((root, name, namespace)) = evidence.prelude_item {
        return matches!(root, "core" | "std") && name == "Deref" && namespace == "type";
    }
    matches!(evidence.external_path, [root, module, name]
        if matches!(root.as_str(), "core" | "std") && module == "ops" && name == "Deref")
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for RustSupport {
    fn demand_installer(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::store::resolution_operation::NativeDemandInstaller>
    {
        Some(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_demand::RUST_DEMAND_INSTALLER)
    }

    fn precedence_rules(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::resolution::precedence::PrecedenceRules
    {
        use brokk_bifrost_analysis::analyzer::resolution::precedence;
        &precedence::RustPrecedenceRules
    }

    fn selected_receiver_step(
        &self,
        request: brokk_bifrost_analysis::analyzer::store::language_support::SelectedReceiverStepRequest<'_>,
        source: &mut dyn brokk_bifrost_analysis::analyzer::store::language_support::SelectedReceiverStepSource,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::store::language_support::SelectedReceiverStepRead,
    > {
        use brokk_bifrost_analysis::analyzer::resolution::fact_source::DeclarationAccessDecision;
        use brokk_bifrost_analysis::analyzer::resolution::{
            LoweringGapOrigin, ResolutionCompletion, ResolutionIncompleteReason,
            ResolutionSlotValue,
        };
        use brokk_bifrost_analysis::analyzer::store::language_support::{
            SelectedReceiverSlotRead, SelectedReceiverStep, SelectedReceiverStepRead,
        };
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
        if source.poll_cancelled() {
            return Ok(SelectedReceiverStepRead::Cancelled);
        }
        // Rust autoderef applies to value receivers with ordinary references.
        let ty = request.value.ty();
        if !matches!(request.value, ResolutionSlotValue::Runtime { .. })
            || ty.indirection() != ty.reference_indirection()
        {
            return Ok(SelectedReceiverStepRead::ReadyNone);
        }
        let mut active = Vec::new();
        let mut unknown = Vec::new();
        for target in source.rust_impl_targets(request.value.ty().identity())? {
            let activation = source.activation(request.reference, target)?;
            if activation == DeclarationAccessDecision::InactiveActivation {
                continue;
            }
            let Some(owner) = source.impl_owner(target)? else {
                continue;
            };
            let Some(applicability) = source.applicability(owner, &request)? else {
                continue;
            };
            let Some(trait_slot) = owner.hierarchy_frontier() else {
                continue;
            };
            let state = match source.slot(trait_slot)? {
                SelectedReceiverSlotRead::Ready(state) => state,
                SelectedReceiverSlotRead::Pending => return Ok(SelectedReceiverStepRead::Pending),
                SelectedReceiverSlotRead::Cancelled => {
                    return Ok(SelectedReceiverStepRead::Cancelled);
                }
            };
            let mut identities = state
                .possible_values()
                .iter()
                .map(|value| value.ty().identity())
                .collect::<Vec<_>>();
            if let ResolutionCompletion::Incomplete(reasons) = state.completion() {
                identities.extend(reasons.iter().filter_map(|reason| match reason {
                    ResolutionIncompleteReason::OpenBoundary { semantic, .. } => Some(*semantic),
                    _ => None,
                }));
            }
            identities.sort_unstable();
            identities.dedup();
            let mut paths = Vec::new();
            let mut missing = identities.is_empty();
            for identity in identities {
                let Some(head) = read_selected_type_head(identity, source.type_head_source())?
                else {
                    return Ok(SelectedReceiverStepRead::Cancelled);
                };
                let prelude_item = head.prelude_item.as_ref().map(|(root, name, namespace)| {
                    (root.as_str(), name.as_str(), namespace.as_str())
                });
                let mut identity_paths = head.import_paths;
                if standard_deref_trait(&SelectedTypeHeadEvidence {
                    prelude_item,
                    external_path: &[],
                }) {
                    identity_paths.push(vec![
                        prelude_item.unwrap().0.to_owned(),
                        "ops".to_owned(),
                        "Deref".to_owned(),
                    ]);
                }
                missing |= identity_paths.is_empty()
                    || (prelude_item.is_some()
                        && !standard_deref_trait(&SelectedTypeHeadEvidence {
                            prelude_item,
                            external_path: &[],
                        }));
                paths.extend(identity_paths);
            }
            // A qualified route can retain both its prefix boundary and its
            // terminal boundary. Only a proved canonical terminal discharges
            // those prefixes; an unrelated external route remains uncertain.
            let canonical = paths
                .iter()
                .filter(|path| {
                    standard_deref_trait(&SelectedTypeHeadEvidence {
                        prelude_item: None,
                        external_path: path,
                    })
                })
                .collect::<Vec<_>>();
            let mut proved = applicability == ResolutionCompletion::Complete
                && !missing
                && !canonical.is_empty()
                && paths
                    .iter()
                    .all(|path| canonical.iter().any(|terminal| terminal.starts_with(path)));
            if proved && let ResolutionCompletion::Incomplete(reasons) = state.completion() {
                proved &= reasons.iter().all(|reason| {
                    matches!(
                        reason,
                        ResolutionIncompleteReason::OpenBoundary { .. }
                            | ResolutionIncompleteReason::UnsupportedSemantic(_)
                    )
                });
                let unsupported = reasons
                    .iter()
                    .filter_map(|reason| match reason {
                        ResolutionIncompleteReason::UnsupportedSemantic(reason) => Some(*reason),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if proved && !unsupported.is_empty() {
                    let Some(origins) = source.gap_origins(&unsupported)? else {
                        return Ok(SelectedReceiverStepRead::Cancelled);
                    };
                    // The producer leaves trait inventory open even when its
                    // standard identity is known. Other unresolved obligations
                    // cannot be discharged by the canonical spelling route.
                    proved &= unsupported.iter().all(|reason| {
                        origins.iter().any(|origin| {
                            origin.reason() == *reason
                                && origin.origin()
                                    == LoweringGapOrigin::Extracted(
                                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                                    )
                        })
                    });
                }
            }
            let candidate = (target, proved, state.completion().clone());
            if matches!(
                activation,
                DeclarationAccessDecision::Allowed | DeclarationAccessDecision::Denied
            ) {
                active.push(candidate);
            } else {
                unknown.push(candidate);
            }
        }
        // Coherence permits at most one Deref impl in a valid configuration.
        // An impl known active under this call's premise therefore wins over
        // unknown alternatives, which only add incompleteness. Target equality
        // and generic ambiguity checks apply to the alternatives that remain.
        let uncertain = !unknown.is_empty() || active.len() > 1;
        let candidates = if active.is_empty() { &unknown } else { &active };
        if candidates.is_empty() {
            return Ok(SelectedReceiverStepRead::ReadyNone);
        }
        let mut values = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        let mut instantiation = request.instantiation.clone();
        let mut generic_target = false;
        for (target, proved, trait_completion) in candidates {
            let target = *target;
            let proved = *proved;
            let state = match source.target(target, &request)? {
                SelectedReceiverSlotRead::Ready(state) => state,
                SelectedReceiverSlotRead::Pending => return Ok(SelectedReceiverStepRead::Pending),
                SelectedReceiverSlotRead::Cancelled => {
                    return Ok(SelectedReceiverStepRead::Cancelled);
                }
            };
            if candidates.len() > 1
                && let [value] = state.possible_values()
            {
                let Some(has_arguments) =
                    source.has_type_arguments(state.slot(), value.ty().identity())?
                else {
                    return Ok(SelectedReceiverStepRead::Cancelled);
                };
                generic_target |= has_arguments;
            }
            instantiation.application_slot = state.slot();
            completion = completion.combine(state.completion());
            if !proved {
                completion = completion.combine(trait_completion);
            }
            if uncertain || !proved {
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target),
                ]));
            }
            values.extend(
                state
                    .possible_values()
                    .iter()
                    .map(|value| ResolutionSlotValue::runtime(value.ty(), true)),
            );
        }
        values.sort_unstable();
        values.dedup();
        // Nominal dedup cannot prove equality between generic applications.
        // Even identical written arguments must not silently select one slot.
        let stop_reason = (values.len() == 1 && generic_target)
            .then_some("receiver-step-ambiguous-generic-target");
        Ok(SelectedReceiverStepRead::ReadyStep(SelectedReceiverStep {
            values,
            instantiation,
            completion,
            stop_reason,
        }))
    }

    fn callable_results_instantiate_nested_generic_projections(&self) -> bool {
        true
    }

    fn selected_wrapper_payload(
        &self,
        boundaries: &[brokk_bifrost_analysis::analyzer::resolution::SemanticId],
        source: &mut dyn brokk_bifrost_analysis::analyzer::store::language_support::SelectedTypeHeadSource,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<
            Vec<brokk_bifrost_analysis::analyzer::store::language_support::SelectedWrapperBoundary>,
        >,
    > {
        use brokk_bifrost_analysis::analyzer::store::language_support::{
            SelectedWrapperBoundary, SelectedWrapperPath,
        };
        let mut evidence = Vec::new();
        for &semantic in boundaries {
            let Some(head) = read_selected_type_head(semantic, source)? else {
                return Ok(None);
            };
            let prelude_item = head
                .prelude_item
                .as_ref()
                .map(|(root, name, namespace)| (root.as_str(), name.as_str(), namespace.as_str()));
            let mut paths = head.import_paths;
            let canonical_proven_paths = paths
                .iter()
                .take(head.cached_path_count)
                .filter(|path| {
                    standard_wrapper_payload(&SelectedTypeHeadEvidence {
                        prelude_item: None,
                        external_path: path,
                    })
                    .is_some()
                })
                .cloned()
                .collect();
            if paths.is_empty() {
                paths.push(Vec::new());
            }
            let paths = paths
                .into_iter()
                .map(|path| {
                    let projection = standard_wrapper_payload(&SelectedTypeHeadEvidence {
                        prelude_item,
                        external_path: &path,
                    });
                    SelectedWrapperPath { path, projection }
                })
                .collect();
            evidence.push(SelectedWrapperBoundary {
                semantic,
                canonical_proven_paths,
                paths,
            });
        }
        Ok(Some(evidence))
    }

    fn module_definition_provider(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::store::language_support::ModuleDefinitionProvider>
    {
        Some(|source, definitions, cancellation| {
            source.rust_module_definitions(definitions, cancellation)
        })
    }

    fn is_configuration_input_path(&self, path: &Path) -> bool {
        file_dependency_evidence::cargo_input(path)
            || toolchain_evidence::rust_toolchain_input(path)
    }
    fn selected_macro_source_rows(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedMacroSourceRows>
{
        Some(&source_storage::RustMacroSourceRows)
    }
    fn intrinsic_sequence_type(
        &self,
        element: brokk_bifrost_analysis::analyzer::resolution::universe::UniverseEntry,
        constructor: brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeConstructorKind,
        length: Option<&str>,
    ) -> Option<(
        brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind,
        String,
    )> {
        use brokk_bifrost_analysis::analyzer::resolution::universe::UniverseIdentityKind;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            IntrinsicTypeKind, ResolutionTypeConstructorKind,
        };
        if element.language != Language::Rust
            || element.identity_kind != UniverseIdentityKind::Type(IntrinsicTypeKind::Primitive)
        {
            return None;
        }
        let name = element.identity_spelling;
        match (constructor, length) {
            (ResolutionTypeConstructorKind::Slice, None) => {
                Some((IntrinsicTypeKind::Slice, format!("[{name}]")))
            }
            (ResolutionTypeConstructorKind::Array, Some(length)) => {
                Some((IntrinsicTypeKind::Array, format!("[{name}; {length}]")))
            }
            _ => None,
        }
    }
    fn selected_dependency_file_evidence(
        &self,
        root: &std::path::Path,
        selected: &[(
            ProjectFile,
            brokk_bifrost_analysis::analyzer::ProjectSourceSnapshot,
            Option<bool>,
        )],
        limits: &brokk_bifrost_analysis::analyzer::semantic_model::DependencyFileEvidenceLimits,
    ) -> brokk_bifrost_analysis::analyzer::semantic_model::DependencyFileEvidence {
        let selected = selected
            .iter()
            .map(|(file, source, _)| (file.clone(), source.clone()))
            .collect::<Vec<_>>();
        rust_file_dependency_evidence(root, &selected, limits, None)
    }
}

#[cfg(test)]
mod enum_variant_tests;
#[cfg(test)]
mod hit_path_read_parity_tests;
#[doc(hidden)]
pub mod source_publication;
#[doc(hidden)]
pub mod source_storage;
pub(crate) mod std_types;

pub use crate::analyzer::rust::std_types::RustNativeObligationProof;

pub use crate::analyzer::rust::std_types::rust_call_is_standard_drop;

pub use crate::analyzer::rust::std_types::rust_native_result_obligation;
#[cfg(any(test, feature = "test-support"))]
pub use crate::analyzer::rust::std_types::with_rust_native_result_obligation_limits_for_test;

#[cfg(test)]
mod module_export_resolution_tests;
mod structural;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod usage_queries_tests;
#[cfg(test)]
mod usage_tests;
#[cfg(test)]
mod usage_walks_tests;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeSupport;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite;

use brokk_bifrost_analysis::analyzer::languages::ImportedExternalCallee;

use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::CodeUnitType;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::StructuredImportPath;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::hash::HashSet;

use crate::analyzer::rust::external_calls::rust_import_binder_external_callee;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_core::retention_budget::BudgetRegion;

use brokk_bifrost_core::retention_budget::{Accounted, SharedAllocation};

pub(crate) use crate::analyzer::rust::adapter::RustAdapter;
use brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts;
use brokk_bifrost_rust::cache::{
    weight_declaration_facts, weight_declaration_source_properties, weight_rust_usage_facts,
};
use brokk_bifrost_rust::graph_support::{
    RustCargoRouteError, RustDeclarationSourceProperties, RustFactSource, RustLiveBlobs,
    RustPlacedDeclaration, RustTraitImplRow, RustUnresolvedImpl,
};
use brokk_bifrost_rust::hierarchy::RustHierarchySourceFacts;
pub use brokk_bifrost_rust::structural::{RustCallResultUseIndex, rust_call_result_use};
use brokk_bifrost_rust::usage_queries::RustDeclarationFacts;
use brokk_bifrost_rust::usage_walks::RustWalkCaches;

/// The key of the per-blob fact cache: the rows are content-addressed, and the
/// generation component retires the whole cache when extraction semantics move.
type RustFactCacheKey = (
    Option<brokk_bifrost_analysis::analyzer::store::GenerationId>,
    git2::Oid,
);
type RustHierarchySourceFactsCacheKey = (
    brokk_bifrost_analysis::analyzer::store::GenerationId,
    brokk_bifrost_core::gitblob::BlobKey,
    ProjectFile,
);

#[cfg(test)]
thread_local! {
    static DECLARATION_FACT_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The route and package-file indexes built from the live summary rows, held
/// for one query. They scale with the workspace, so they live in the query
/// scope's request memos and are dropped with the outermost scope; no analyzer
/// field holds them.
#[derive(Default)]
struct RustRouteRequestMemo {
    package_files: brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo<
        RustRouteMemoEntry<RustWholePackageIndex>,
    >,
    /// The per-question route answers that replace the two whole-index memos
    /// above. A file's `RustFileRoutes`, by workspace-relative path.
    ///
    /// Each entry holds the answer and the whole receipt of the demand that
    /// built it, so a hit replays the reads and the stable incompleteness
    /// reasons the demand recorded. The map lives in `QueryRequestMemos`, which
    /// `reset_request_caches` replaces at each outermost scope transition: an
    /// answer is never served to another request. An entry holds no read frame,
    /// no inventory and no revision; the frame that built it is closed when the
    /// build returns, and a later consumer opens its own.
    file_routes: KeyedPoolSafeMemo<String, RustRouteMemoEntry<RustFileRoutes>>,
    /// Declaration facts by workspace-relative path, including incomplete fills.
    /// The whole receipt replays reads and stable gaps on hits, and entries die
    /// with the request just like `file_routes`.
    declaration_facts: KeyedPoolSafeMemo<String, RustRouteMemoEntry<Arc<RustDeclarationFacts>>>,
    /// The package questions of [`RustPackageView`], by package name.
    package_files_of:
        KeyedPoolSafeMemo<String, RustRouteMemoEntry<RustRoutedAnswer<Vec<ProjectFile>>>>,
    /// Whether a file is a member of any package, by workspace-relative path.
    package_membership: KeyedPoolSafeMemo<String, RustRouteMemoEntry<RustRoutedAnswer<bool>>>,
    /// The packages a crate name's library and binary roots sit in, by
    /// normalized crate name.
    crate_package_names:
        KeyedPoolSafeMemo<String, RustRouteMemoEntry<RustRoutedAnswer<Vec<String>>>>,
    /// The library roots under a normalized crate name, for a file in no
    /// target (the whole index's unscoped-library fallback).
    unscoped_libraries:
        KeyedPoolSafeMemo<String, RustRouteMemoEntry<RustRoutedAnswer<Vec<RustLibraryRoot>>>>,
    /// The files that can reference the target roots of one file, by
    /// workspace-relative path.
    reaching_files:
        KeyedPoolSafeMemo<String, RustRouteMemoEntry<RustRoutedAnswer<Vec<ProjectFile>>>>,
}

/// The package questions of the workspace over the per-unit kinds
/// `RustFileUnits`, `RustPackageUnits`, `RustCrateNameUnits` and
/// `RustUnitPackageRows`, composed as the whole `RustPackageFileIndex` answers
/// them. Each question demands only the units it names, and a request scope
/// memoizes the answer by package, path or crate name. Values are owned.
///
/// The view borrows its analyzer. `RustAnalyzer::clone` opens a fresh
/// `QueryReadCache`, so an owned clone would not see the open request scope,
/// its request memos or its cancellation token; an owner that must outlive the
/// borrow holds the analyzer it was given the borrow of.
///
/// An incomplete answer may omit members: the view records one
/// `SemanticEvidenceGap` for it (inside the memoized build, so a hit replays
/// it), and the caller must treat a negative or universal claim from it as
/// unknown.
pub struct RustPackageView<'a> {
    source: &'a RustAnalyzer,
}

impl RustPackageView<'_> {
    /// The member files whose package is `package`.
    pub fn files_in_package(
        &self,
        package: &str,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<ProjectFile>>, RustCargoRouteError> {
        let source = self.source;
        source.package_question(
            |memo| &memo.package_files_of,
            package.to_owned(),
            progress,
            |derivations, inventory, incomplete| {
                let (units, mut complete) = source.demanded::<route_kinds::RustPackageUnits>(
                    derivations,
                    inventory,
                    &package.to_owned(),
                )?;
                let root = source.inner.project().root().to_path_buf();
                let mut files = Vec::new();
                for (unit, _) in units.iter() {
                    let (rows, rows_complete) = source
                        .demanded::<route_kinds::RustUnitPackageRows>(
                            derivations,
                            inventory,
                            unit,
                        )?;
                    complete &= source.note_incomplete_unit(unit, rows_complete, incomplete);
                    files.extend(
                        rows.iter()
                            .filter(|row| row.package_components.join(".") == package)
                            .map(|row| ProjectFile::new(root.clone(), &row.rel_path)),
                    );
                }
                files.sort();
                files.dedup();
                Ok(RustRoutedAnswer {
                    value: files,
                    complete,
                })
            },
        )
    }

    /// Whether `file` is a member of some unit's package listing. `false` is
    /// only a proof of absence when the answer is complete.
    pub fn contains(
        &self,
        file: &ProjectFile,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<bool>, RustCargoRouteError> {
        let source = self.source;
        let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(file.rel_path());
        source.package_question(
            |memo| &memo.package_membership,
            path.clone(),
            progress,
            |derivations, inventory, incomplete| {
                let (units, mut complete) =
                    source.demanded::<route_kinds::RustFileUnits>(derivations, inventory, &path)?;
                let mut found = false;
                for unit in units.iter() {
                    let (rows, rows_complete) = source
                        .demanded::<route_kinds::RustUnitPackageRows>(
                            derivations,
                            inventory,
                            unit,
                        )?;
                    complete &= source.note_incomplete_unit(unit, rows_complete, incomplete);
                    found |= rows.iter().any(|row| row.rel_path == path);
                }
                Ok(RustRoutedAnswer {
                    value: found,
                    complete,
                })
            },
        )
    }

    /// The packages that hold the library and binary roots named `import_name`.
    /// The name is normalized, so `dep-crate` and `dep_crate` are one question.
    pub fn crate_packages(
        &self,
        import_name: &str,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<String>>, RustCargoRouteError> {
        let source = self.source;
        let name = brokk_bifrost_rust::cargo_manifest::normalize_crate_name(import_name);
        source.package_question(
            |memo| &memo.crate_package_names,
            name.clone(),
            progress,
            |derivations, inventory, incomplete| {
                let (roots, mut complete) = source.demanded::<route_kinds::RustCrateNameUnits>(
                    derivations,
                    inventory,
                    &name,
                )?;
                let mut packages = Vec::new();
                for (unit, _, root) in roots.iter() {
                    let (rows, rows_complete) = source
                        .demanded::<route_kinds::RustUnitPackageRows>(
                            derivations,
                            inventory,
                            unit,
                        )?;
                    complete &= source.note_incomplete_unit(unit, rows_complete, incomplete);
                    packages.extend(
                        rows.iter()
                            .filter(|row| &row.rel_path == root && row.is_root_member)
                            .map(|row| row.package_components.join(".")),
                    );
                }
                packages.sort();
                packages.dedup();
                Ok(RustRoutedAnswer {
                    value: packages,
                    complete,
                })
            },
        )
    }
}

/// An index with the whole receipt of the build that filled it. A later
/// consumer in the same outer scope (another policy unit) replays the receipt,
/// so its ledger holds every read the fill recorded, such as the file key of a
/// refused member, and not only the stable incompleteness reasons.
struct RustRouteMemoEntry<T> {
    value: Arc<T>,
    receipt: brokk_bifrost_analysis::analyzer::common::QueryCacheBuildReceipt,
}

/// Query occurrences and their immutable fact product share one selected blob.
#[cfg(test)]
pub(crate) struct RustPrimarySourceAt {
    pub(crate) occurrences: Vec<brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId>,
    pub(crate) facts:
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustHierarchySourceFacts>>,
}

fn weight_rust_hierarchy_source_facts<K>(_key: &K, value: &Arc<RustHierarchySourceFacts>) -> u32 {
    let bytes = value.estimated_retained_bytes();
    bytes.clamp(1, u32::MAX as usize) as u32
}
use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;
use brokk_bifrost_rust::cargo_routes::{RustFileRoutes, RustLibraryRoot, RustUnscopedLibraries};
use brokk_bifrost_rust::crate_naming;
use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;

pub use brokk_bifrost_rust::cargo_config::{builtin_target_platform, host_target_triple};
pub(crate) use brokk_bifrost_rust::declarations::rust_type_identifiers;
pub use brokk_bifrost_rust::field_roles::rust_is_field_declaration_name;
pub use brokk_bifrost_rust::graph_support::{rust_path_segments, rust_reference_namespace};
pub(crate) use brokk_bifrost_rust::imports::rust_import_binding_name;
use brokk_bifrost_rust::test_detection::detect_rust_test_assertion_smells;

use crate::analyzer::rust::clones::build_rust_clone_candidate_data;

pub use crate::analyzer::rust::dependency_discovery::build_disjoint_rustdoc_activation_ranges;
pub use crate::analyzer::rust::dependency_discovery::choose_nearest_compatible_rustdoc_version;
pub use crate::analyzer::rust::dependency_discovery::resolve_rust_semantic_pack_dependencies;
pub use crate::analyzer::rust::dependency_discovery::{
    DocsRsArtifactInput, DocsRsAuthority, DocsRsBindingOutcome, DocsRsBindingRow,
    bind_docsrs_artifacts,
};

pub use crate::analyzer::rust::external::RustDependencyPackAdapter;

pub use crate::analyzer::rust::file_dependency_evidence::CARGO_LOCK_ASSOCIATIONS;
pub use crate::analyzer::rust::file_dependency_evidence::acquire_rust_file_dependency_evidence;

pub use crate::analyzer::rust::file_dependency_evidence::rust_file_dependency_evidence;

pub use crate::analyzer::rust::toolchain_evidence::RUST_TOOLCHAIN_ECOSYSTEM;

pub use crate::analyzer::rust::rustdoc_artifact::RustdocJsonPackProducer;

pub use brokk_bifrost_rust::graph_support::RustReferenceContext;
use brokk_bifrost_rust::graph_support::is_rust_enum_variant_declaration;
use brokk_bifrost_rust::graph_support::{
    ReferenceContextError, ReferenceContextResult, RustPackageFileRow, RustRoutedAnswer,
    RustWholePackageIndex,
};
pub use brokk_bifrost_rust::lexical_scope::{RustPatternName, rust_pattern_name_bounded};
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_rust::lexical_scope::{
    reset_rust_tree_parse_counters_for_test, rust_scope_index_build_count_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use brokk_bifrost_rust::usage::RustReferenceNamespace;
use brokk_bifrost_rust::usage::RustSymbolNamespace;

pub fn rust_declaration_matches_reference_namespace(
    declaration: &CodeUnit,
    reference: RustReferenceNamespace,
) -> bool {
    RustSymbolNamespace::of(declaration)
        .is_some_and(|symbol_namespace| symbol_namespace.accepts(reference))
}

pub fn rust_declaration_is_enum_variant(
    rust: &RustAnalyzer,
    declaration: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
    if declaration.kind() != CodeUnitType::Field {
        return Ok(false);
    }
    // Enum variants are distinguished on their own canonical source property;
    // their class owner need not be present in that property's unit map.
    is_rust_enum_variant_declaration(rust, declaration)
}

struct RustDeclarationFactsEntry {
    value: brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
        Result<SharedAllocation<RustDeclarationFacts>, RustCargoRouteError>,
    >,
}

// The facts allocation keeps its own accounting: an allocation the budget could
// not charge reports `usize::MAX`, which keeps it out of cross-request
// retention, and a charged one weighs its bytes for eviction. An error is not
// retained across requests, as before receipts were cached with the facts.
impl brokk_bifrost_core::retention_budget::RetainedBytes for RustDeclarationFactsEntry {
    fn retained_bytes(&self) -> usize {
        let facts = match self.value.value() {
            Ok(facts) => facts.retained_bytes(),
            Err(_) => usize::MAX,
        };
        std::mem::size_of::<Self>()
            .saturating_add(facts)
            .saturating_add(self.value.retained_receipt_bytes())
    }

    fn eviction_bytes(&self) -> usize {
        let facts = match self.value.value() {
            Ok(facts) => facts.eviction_bytes(),
            Err(_) => usize::MAX,
        };
        std::mem::size_of::<Self>()
            .saturating_add(facts)
            .saturating_add(self.value.retained_receipt_bytes())
    }
}

#[derive(Clone)]
pub struct RustAnalyzer {
    #[doc(hidden)]
    pub inner: TreeSitterAnalyzer<RustAdapter>,
    _retention_budget: brokk_bifrost_core::retention_budget::RetentionBudget,
    dependency_evidence_overlay: brokk_bifrost_analysis::analyzer::store::Result<
        Option<Arc<brokk_bifrost_analysis::analyzer::store::dependency_file_evidence::ScopedDependencyEvidence>>,
    >,
    imported_code_units: BudgetRegion<ProjectFile, SharedAllocation<Accounted<HashSet<CodeUnit>>>>,
    referencing_files: BudgetRegion<ProjectFile, HashSet<ProjectFile>>,
    export_indexes: BudgetRegion<ProjectFile, SharedAllocation<Accounted<brokk_bifrost_core::analyzer::usages::model::ExportIndex>>>,
    /// `resolve_module_files` calls. A use-path's module files are invariant in
    /// the export name being resolved, so this count is what proves the
    /// per-export-name recomputation is gone (#1230 item 4).
    module_file_resolution_count: Arc<AtomicUsize>,
    export_name_canonicalization_count: Arc<AtomicUsize>,
    /// Files the Cargo-route build had to parse because their blob carried no
    /// persisted module-route rows (#1793).
    module_route_fact_fallback_count: Arc<AtomicUsize>,
    /// One blob's persisted per-file Rust usage facts. Keyed by
    /// `(generation, blob)` rather than by file, because the rows are
    /// content-addressed and two byte-identical files share them; the
    /// generation component retires the whole cache when extraction semantics
    /// move. Retained on the analyzer store's budget, never by workspace size.
    rust_usage_facts: BudgetRegion<RustFactCacheKey, SharedAllocation<Accounted<RustUsageFacts>>>,
    /// One file's declaration identities and their visibility domains. Keyed by
    /// file rather than by blob because the derivation consults analyzer state
    /// (structural parents, visibility) and not only the file's bytes; the
    /// analyzer is replaced wholesale on `update`, so the cache retires with it.
    declaration_facts: BudgetRegion<ProjectFile, RustDeclarationFactsEntry>,
    declaration_source_properties: BudgetRegion<
        (brokk_bifrost_analysis::analyzer::store::GenerationId, brokk_bifrost_core::gitblob::BlobKey, ProjectFile),
        SharedAllocation<Accounted<RustDeclarationSourceProperties>>>,
    /// One mounted file's canonical hierarchy inputs. The generation, blob,
    /// and mounted file all participate in the key: source rows are
    /// content-owned, while CodeUnit links are placement-dependent.
    rust_hierarchy_source_facts:
        BudgetRegion<RustHierarchySourceFactsCacheKey, SharedAllocation<Accounted<RustHierarchySourceFacts>>>,
    /// The fact catch-up state for this generation: whether the live blobs
    /// without persisted Rust facts have been found and repaired.
    fact_catch_up: Arc<fact_catch_up::RustFactCatchUp>,
    /// The cross-file usage walks' bounded memos. Behind one `Arc` so the
    /// analyzer stays small: nine `Cache` handles inline would make this struct
    /// the outsized variant of `AnalyzerDelegate`.
    walk_caches: Arc<RustWalkCaches>,
}

impl_forward_query_provider!(RustAnalyzer);

/// One-shot selected opening plus attempt progress, including failed store opens.
pub(crate) struct RustSelectedOperationOpenReport<'analyzer> {
    pub(crate) outcome: brokk_bifrost_analysis::analyzer::store::Result<
        SelectedResolutionOperationOpenOutcome<'analyzer, 'analyzer>,
    >,
    pub(crate) store_open_attempted: bool,
}

impl RustAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let inner = self.inner.update_all_with_progress(progress);
            Self::from_inner(inner)
        })
    }

    fn capture_dependency_overlay(
        inner: &TreeSitterAnalyzer<RustAdapter>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<Arc<brokk_bifrost_analysis::analyzer::store::dependency_file_evidence::ScopedDependencyEvidence>>,
    >{
        brokk_bifrost_analysis::analyzer::store::dependency_file_evidence::publish_overlay(
            inner.analyzer_store(),
            &inner.selected_workspace_snapshots(),
            inner.project(),
            Language::Rust,
        )
    }

    fn from_inner(inner: TreeSitterAnalyzer<RustAdapter>) -> Self {
        let budget = inner.analyzer_store().retention_budget().clone();
        Self {
            dependency_evidence_overlay: Self::capture_dependency_overlay(&inner),
            _retention_budget: budget.clone(),
            inner,
            imported_code_units: budget.region("rust.imported_code_units", None),
            referencing_files: budget.region("rust.referencing_files", None),
            export_indexes: budget.region("rust.export_indexes", None),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            export_name_canonicalization_count: Arc::new(AtomicUsize::new(0)),
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: budget.region("rust.usage_facts", None),
            declaration_facts: budget.region("rust.declaration_facts", None),
            declaration_source_properties: budget
                .region("rust.declaration_source_properties", None),
            rust_hierarchy_source_facts: budget.region("rust.hierarchy_source_facts", None),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(&budget)),
        }
    }

    fn store_result_or_unavailable<T>(
        &self,
        result: brokk_bifrost_analysis::analyzer::store::Result<T>,
        context: impl FnOnce() -> String,
    ) -> Result<T, RustCargoRouteError> {
        result.map_err(|error| {
            self.inner.record_store_error(error.context(context()));
            RustCargoRouteError::Unavailable
        })
    }

    pub(crate) fn open_selected_rust_inventory(
        &self,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome<'_>,
    >{
        use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        let snapshots = self.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        match self
            .inner
            .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
        {
            SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } => {
                let outcome = self
                    .analyzer_store()
                    .open_selected_resolution_mount_inventory_with_content_mounts(
                        self.inner.workspace_id(),
                        snapshots.as_ref(),
                        &languages,
                        &masks,
                        &content_mounts,
                        cancellation,
                    )?;
                if let SelectedResolutionMountInventoryOutcome::Ready(inventory) = &outcome {
                    inventory.stamp_declared_rust_route_recipe();
                }
                Ok(outcome)
            }
            SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                Ok(SelectedResolutionMountInventoryOutcome::Unavailable(reason))
            }
            SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                Ok(SelectedResolutionMountInventoryOutcome::Stale(reason))
            }
            SelectedResolutionOverlayInputsOutcome::Cancelled => {
                Ok(SelectedResolutionMountInventoryOutcome::Cancelled)
            }
        }
    }

    /// The read frame a route question needs while this thread owns `operation`.
    ///
    /// A route question asked inside a selected operation must borrow that
    /// operation's selection (`with_read_frame` answers `ValidationFailed`
    /// otherwise, and nothing falls back to opening another one). Every site
    /// that opens a Rust selected operation and runs analyzer code under it holds
    /// this frame while it does. The frame owns a clone of the operation's
    /// inventory handle and no borrow of `operation`, so the operation stays
    /// mutable; drop the frame before the operation.
    pub(crate) fn operation_read_frame<'store>(
        &self,
        operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'store, '_>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::derivation_host::read_frame::OperationReadFrame<'store>,
    > {
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            read_frame::OperationReadFrame, rust_route_question_identity, selected_rust_snapshot,
        };
        let snapshot = selected_rust_snapshot(&operation.ready.inventory)
            .map_err(brokk_bifrost_analysis::analyzer::store::StoreError::new)?;
        let mut identity = rust_route_question_identity(self, self.analyzer_store(), snapshot);
        identity.selection = Some(operation.ready.inventory.fingerprint());
        identity.operation = Some(operation as *const _ as usize);
        OperationReadFrame::enter(identity, operation).map_err(|cause| {
            brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                "Rust operation read frame unavailable: {cause:?}"
            ))
        })
    }

    pub(crate) fn selected_dependency_package(
        &self,
        file: &ProjectFile,
        exposed: &str,
    ) -> Option<String> {
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
        let derivations = self.inner.derivations()?;
        let snapshot = self
            .inner
            .selected_workspace_snapshots()
            .get("rust")?
            .clone();
        self.with_rust_route_inventory(snapshot, |inventory| {
            Ok((|| {
                let path =
                    brokk_bifrost_core::path_utils::workspace_relative_slash_path(file.rel_path());
                let unit_answer =
                    derivations.demand::<route_kinds::RustFileUnits>(self, inventory, &path);
                let Demanded::Available {
                    value: units,
                    complete: true,
                    ..
                } = unit_answer
                else {
                    return None;
                };
                let mut selected = None;
                for unit in units.iter() {
                    let Demanded::Available {
                        value: identities,
                        complete: true,
                        ..
                    } = derivations.demand::<route_kinds::RustUnitDependencyIdentities>(
                        self,
                        inventory,
                        unit.key(),
                    )
                    else {
                        return None;
                    };
                    let nearest = identities
                        .iter()
                        .filter(|(_, name, _)| name == exposed)
                        .collect::<Vec<_>>();
                    if nearest.is_empty() {
                        return None;
                    }
                    for (_, _, package) in nearest {
                        if package.is_empty() {
                            return None;
                        }
                        if selected
                            .as_ref()
                            .is_some_and(|previous| previous != package)
                        {
                            return None;
                        }
                        selected = Some(package.clone());
                    }
                }
                selected
            })())
        })
        .ok()
        .flatten()
    }

    /// Run `f` on the selected Rust inventory of `snapshot`: the active read
    /// frame's inventory when one matches, otherwise a freshly opened one.
    fn with_rust_route_inventory<T>(
        &self,
        snapshot: brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
        f: impl FnOnce(
            &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        ) -> Result<T, brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause>,
    ) -> Result<T, brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause> {
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            read_frame, rust_route_question_identity,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;
        let identity = rust_route_question_identity(self, self.analyzer_store(), snapshot);
        let cancellation = CancellationToken::default();
        read_frame::with_read_frame(
            &identity,
            || match self.open_selected_rust_inventory(&cancellation) {
                Ok(SelectedResolutionMountInventoryOutcome::Ready(inventory)) => Ok(*inventory),
                Ok(SelectedResolutionMountInventoryOutcome::Cancelled) => {
                    Err(UnavailableCause::Cancelled)
                }
                Ok(SelectedResolutionMountInventoryOutcome::Unavailable(reason)) => {
                    Err(UnavailableCause::Failed(
                        format!("Rust selected inventory unavailable: {reason:?}").into(),
                    ))
                }
                Ok(SelectedResolutionMountInventoryOutcome::Stale(reason)) => {
                    Err(UnavailableCause::Failed(
                        format!("Rust selected inventory stale: {reason:?}").into(),
                    ))
                }
                Err(error) => Err(UnavailableCause::Failed(error.to_string().into())),
            },
            f,
        )
        .and_then(|answer| answer)
    }

    /// Record, as read keys, the unit summaries a forward resolution of the
    /// references in `file` can consult.
    ///
    /// A reference in a crate binds only inside that crate's workspace
    /// dependency closure, and a re-export or glob hop through a module of the
    /// closure is resolved from its unit's summary rows, so no file key names
    /// the module that carries the `pub use`. Each closure unit's summary
    /// output digest covers what a dependent reads of it (exports with their
    /// origin and alias target, route provenance, completeness) and nothing of
    /// member blobs, bodies or comments, so an edit that keeps a unit's
    /// surface keeps its key. The set is the whole closure, not the units the
    /// resolver actually read: the summary joins do not report which rows they
    /// met.
    ///
    /// A closure that cannot be read leaves the answer unattributed, so no
    /// consumer reuses it.
    pub(crate) fn record_forward_scope_reads(&self, file: &ProjectFile) {
        use brokk_bifrost_analysis::analyzer::derivation_host::UnitSummaryKind;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{Demanded, UnavailableCause};
        if !brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
            self.read_ledger_attached()
        }) {
            return;
        }
        let read = || {
            let derivations = self
                .inner
                .derivations()
                .ok_or(UnavailableCause::ValidationFailed)?;
            let snapshot = self
                .inner
                .selected_workspace_snapshots()
                .get("rust")
                .cloned()
                .ok_or(UnavailableCause::ValidationFailed)?;
            self.with_rust_route_inventory(snapshot, |inventory| {
                let path = file.rel_path().to_string_lossy().replace('\\', "/");
                let roots = match derivations
                    .demand::<route_kinds::RustBroadFileUnits>(self, inventory, &path)
                {
                    Demanded::Available { value, .. } => value,
                    Demanded::Unavailable(cause) => return Err(cause),
                };
                let closure = inventory
                    .rust_unit_closure_keys(
                        &roots.iter().map(|unit| *unit.key()).collect::<Vec<_>>(),
                    )
                    .map_err(|error| UnavailableCause::Failed(error.to_string().into()))?;
                for unit in &closure {
                    if let Demanded::Unavailable(cause) =
                        derivations.demand::<UnitSummaryKind>(self, inventory, unit)
                    {
                        return Err(cause);
                    }
                }
                Ok(())
            })
        };
        if read().is_err() {
            self.record_unattributed_read();
        }
    }

    pub(crate) fn open_selected_rust_operation(
        &self,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> RustSelectedOperationOpenReport<'_> {
        use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

        let snapshots = self.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        // Every returned report follows an overlay attempt. Identity admission
        // belongs to callers; cancellation is handled by overlay preparation.
        let (outcome, store_open_attempted) = match self
            .inner
            .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)
        {
            Ok(SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            }) => {
                let input = SelectedResolutionOperationInput::new(
                    self.inner.project(),
                    self.inner.workspace_id(),
                    snapshots.as_ref(),
                    &languages,
                    &masks,
                )
                .with_content_mounts(content_mounts);
                (
                    self.inner
                        .analyzer_store()
                        .open_selected_resolution_operation(input, cancellation),
                    true,
                )
            }
            Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => (
                Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)),
                false,
            ),
            Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => (
                Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)),
                false,
            ),
            Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
                (Ok(SelectedResolutionOperationOpenOutcome::Cancelled), false)
            }
            Err(error) => (Err(error), false),
        };
        RustSelectedOperationOpenReport {
            outcome,
            store_open_attempted,
        }
    }

    pub(crate) fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    pub(crate) fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(token, file)
    }

    #[doc(hidden)]
    pub fn analyzer_store(&self) -> &Arc<brokk_bifrost_analysis::analyzer::store::AnalyzerStore> {
        self.inner.analyzer_store()
    }

    #[doc(hidden)]
    pub fn live_path_snapshot(
        &self,
    ) -> Arc<brokk_bifrost_analysis::analyzer::store::liveness::LiveSnapshot> {
        self.inner.live_path_snapshot()
    }

    /// One blob's persisted per-file usage facts, read once per
    /// `(generation, blob)` and then served from the bounded cache.
    fn rust_usage_facts_of_blob(
        &self,
        oid: git2::Oid,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustUsageFacts>>,
        RustCargoRouteError,
    > {
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let key: RustFactCacheKey = (self.inner.language_generation("rust"), oid);
        if let Some(cached) = self.rust_usage_facts.get(&key) {
            return Ok(Arc::clone(cached.arc()));
        }
        let facts = self
            .analyzer_store()
            .rust_usage_facts(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "rust"))
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading canonical Rust usage facts for blob {oid}")),
                );
                RustCargoRouteError::Unavailable
            })?;
        if !facts
            .modules
            .first()
            .is_some_and(|root| root.module_name.is_empty() && root.is_inline)
        {
            self.inner.record_store_error(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "canonical Rust usage publication has no root module for blob {oid}: {:?}",
                    facts.modules
                )),
            );
            return Err(RustCargoRouteError::Unavailable);
        }
        let facts = Arc::new(facts);
        let bytes = weight_rust_usage_facts(&key, &facts) as usize;
        let facts = Arc::try_unwrap(facts).expect("new Rust usage facts have no other holder");
        let facts = Arc::new(if cache_fill.is_complete() {
            Accounted::charged_with_bytes(&self._retention_budget, facts, bytes)
        } else {
            Accounted::uncharged(facts)
        });
        if cache_fill.is_complete() {
            drop(
                self.rust_usage_facts
                    .insert(key, SharedAllocation::new(Arc::clone(&facts))),
            );
        }
        Ok(facts)
    }

    /// One file's declaration identities and their visibility domains, derived
    /// once per file and then served from the bounded cache when complete.
    /// Incomplete fills live only in the request memo, whose hits replay their
    /// reads and stable gaps so enclosing fills remain incomplete.
    fn rust_declaration_facts_of(
        &self,
        file: &ProjectFile,
    ) -> Result<Arc<RustDeclarationFacts>, RustCargoRouteError> {
        if let Some(cached) = self.declaration_facts.get(file) {
            return Ok(Arc::clone(
                cached.value.replay().as_ref().map_err(Clone::clone)?.arc(),
            ));
        }
        let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(file.rel_path());
        self.request_memoized(
            |memo| &memo.declaration_facts,
            path,
            &|| true,
            || {
                let mut complete = false;
                let entry =
                    brokk_bifrost_analysis::analyzer::common::complete_replayable_query_cache_value(
                        self,
                        || {
                            #[cfg(test)]
                            DECLARATION_FACT_DERIVATIONS.with(|count| count.set(count.get() + 1));
                            let cache_fill =
                                brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
                            let mut facts = Arc::new(
                                brokk_bifrost_rust::usage_queries::rust_declaration_facts(
                                    self,
                                    file,
                                    &self.declarations(file),
                                    &|| true,
                                )?
                                .expect("uninterrupted Rust declaration-fact derivation"),
                            );
                            complete = cache_fill.is_complete();
                            let bytes = weight_declaration_facts(file, &facts) as usize;
                            Arc::get_mut(&mut facts)
                                .expect("new Rust declaration facts have no other holder")
                                .charge =
                                brokk_bifrost_core::retention_budget::AllocationCharge::acquire(
                                    &self._retention_budget,
                                    bytes,
                                );
                            Ok::<_, RustCargoRouteError>(SharedAllocation::new(facts))
                        },
                    );
                match entry {
                    Ok(value) if complete => {
                        let facts =
                            Arc::clone(value.replay().as_ref().map_err(Clone::clone)?.arc());
                        drop(
                            self.declaration_facts
                                .insert(file.clone(), RustDeclarationFactsEntry { value }),
                        );
                        Ok(facts)
                    }
                    Ok(value) | Err(value) => Ok(Arc::clone(
                        value.replay().as_ref().map_err(Clone::clone)?.arc(),
                    )),
                }
            },
        )
    }

    fn selected_rust_source(
        &self,
        file: &ProjectFile,
    ) -> Result<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            brokk_bifrost_core::gitblob::BlobKey,
        ),
        RustCargoRouteError,
    > {
        let generation = self
            .inner
            .language_generation("rust")
            .expect("Rust analyzer has a Rust storage generation");
        let Some(oid) = self.live_path_snapshot().oid_for_path(file) else {
            // A file this adapter does not own has no canonical Rust source
            // and never will, so asking about one is not a store failure. It
            // used to record one, and a recorded store error fails the whole
            // request: a mixed-language `usage_graph` naming only Rust paths
            // exited 1 on a C++ header. Only a missing *Rust* source is a
            // store problem.
            if brokk_bifrost_core::analyzer::common::language_for_file(file) == Language::Rust {
                self.inner.record_store_error(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                        "canonical Rust source is absent from the live snapshot: {file:?}"
                    )),
                );
            }
            return Err(RustCargoRouteError::Unavailable);
        };
        Ok((
            generation,
            brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "rust"),
        ))
    }

    fn selected_rust_source_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            brokk_bifrost_core::gitblob::BlobKey,
        ),
        RustCargoRouteError,
    > {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        self.selected_rust_source(file)
    }

    fn declaration_source_properties(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustDeclarationSourceProperties>>,
        RustCargoRouteError,
    > {
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let (generation, oid) = self.selected_rust_source_while(file, keep_going)?;
        let key = (generation, oid.clone(), file.clone());
        if let Some(cached) = self.declaration_source_properties.get(&key) {
            return Ok(Arc::clone(cached.arc()));
        }
        let load = || {
            self.analyzer_store().rust_declaration_properties(
                &oid,
                generation,
                self.inner.adapter(),
                file,
                keep_going,
            )
        };
        let rows = match load() {
            Ok(rows) => rows,
            Err(error) if error.is_missing_required_source_facts() => {
                self.ensure_rust_declaration_facts_published(file, generation, &oid)?;
                load().map_err(|error| {
                    self.inner.record_store_error(error.context(format!(
                        "reading canonical Rust declaration properties after catch-up for {file:?} ({oid:?})"
                    )));
                    RustCargoRouteError::Unavailable
                })?
            }
            Err(error) => {
                self.inner.record_store_error(error.context(format!(
                    "reading canonical Rust declaration properties for {file:?} ({oid:?})"
                )));
                return Err(RustCargoRouteError::Unavailable);
            }
        }
        .ok_or(RustCargoRouteError::Cancelled)?;
        let mut properties = RustDeclarationSourceProperties::default();
        for (unit, property) in rows {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            properties.entry(unit).or_default().push(property);
        }
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let properties = Arc::new(properties);
        let bytes = weight_declaration_source_properties(&key, &properties) as usize;
        let properties = Arc::try_unwrap(properties)
            .expect("new Rust declaration properties have no other holder");
        let properties = Arc::new(if cache_fill.is_complete() {
            Accounted::charged_with_bytes(&self._retention_budget, properties, bytes)
        } else {
            Accounted::uncharged(properties)
        });
        if cache_fill.is_complete() {
            drop(
                self.declaration_source_properties
                    .insert(key, SharedAllocation::new(Arc::clone(&properties))),
            );
        }
        Ok(properties)
    }

    /// One mounted file's complete canonical hierarchy input. Publication is
    /// read from the current generation and failures are never inserted into
    /// the budget region; the store's `None` result is cancellation.
    pub(crate) fn canonical_rust_hierarchy_source_facts(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustHierarchySourceFacts>>,
        RustCargoRouteError,
    > {
        let (generation, oid) = self.selected_rust_source_while(file, keep_going)?;
        self.rust_hierarchy_source_facts_for_key((generation, oid, file.clone()), keep_going)
    }

    fn rust_hierarchy_source_facts_for_key(
        &self,
        key: RustHierarchySourceFactsCacheKey,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustHierarchySourceFacts>>,
        RustCargoRouteError,
    > {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let (generation, oid, file) = &key;
        if let Some(cached) = self.rust_hierarchy_source_facts.get(&key) {
            return Ok(Arc::clone(cached.arc()));
        }
        let facts = self
            .analyzer_store()
            .rust_hierarchy_source_facts(
                oid.oid,
                *generation,
                self.inner.adapter(),
                file,
                keep_going,
            )
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading canonical Rust hierarchy source facts for {file:?} ({oid:?})"
                )));
                RustCargoRouteError::Unavailable
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let facts = Arc::new(facts);
        let bytes = weight_rust_hierarchy_source_facts(&key, &facts) as usize;
        let facts = Arc::try_unwrap(facts).expect("new Rust hierarchy facts have no other holder");
        let facts = Arc::new(Accounted::charged_with_bytes(
            &self._retention_budget,
            facts,
            bytes,
        ));
        drop(
            self.rust_hierarchy_source_facts
                .insert(key, SharedAllocation::new(Arc::clone(&facts))),
        );
        Ok(facts)
    }

    #[cfg(test)]
    pub(crate) fn canonical_rust_primary_source_at(
        &self,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<RustPrimarySourceAt, RustCargoRouteError> {
        let (generation, oid) = self.selected_rust_source_while(file, keep_going)?;
        let occurrences = self
            .analyzer_store()
            .rust_primary_occurrences_at(&oid, generation, range, keep_going)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading canonical Rust primary query occurrences for {file:?} ({oid:?})"
                )));
                RustCargoRouteError::Unavailable
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        // Occurrence IDs are blob-local. Never recapture live identity between
        // point selection and hierarchy loading if a mount changes during I/O.
        let facts =
            self.rust_hierarchy_source_facts_for_key((generation, oid, file.clone()), keep_going)?;
        Ok(RustPrimarySourceAt { occurrences, facts })
    }

    #[track_caller]
    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_fqn_limited(fqn, limit, continue_query)
    }

    delegate_inner_methods! {
        pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata>;
    }

    delegate_inner_methods! {
        pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String>;
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    /// Per-instance counters behind the #1230 complexity pins. Each is shared by
    /// `Clone` (so a cloned analyzer keeps counting into the same cell) and
    /// reset by the analyzer that owns it, never process-globally, so suites
    /// running in parallel cannot bleed into one another.
    pub(crate) fn note_module_file_resolution(&self) {
        self.module_file_resolution_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn reset_module_file_resolution_count_for_test(&self) {
        self.module_file_resolution_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn module_file_resolution_count_for_test(&self) -> usize {
        self.module_file_resolution_count.load(Ordering::Relaxed)
    }

    pub(crate) fn note_export_name_canonicalization(&self) {
        self.export_name_canonicalization_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn reset_export_name_canonicalization_count_for_test(&self) {
        self.export_name_canonicalization_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn export_name_canonicalization_count_for_test(&self) -> usize {
        self.export_name_canonicalization_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_analyzed_file_listing_count_for_test(&self) {
        self.inner.reset_analyzed_file_listing_count_for_test();
    }

    #[doc(hidden)]
    pub fn analyzed_file_listing_count_for_test(&self) -> usize {
        self.inner.analyzed_file_listing_count_for_test()
    }

    #[doc(hidden)]
    pub fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.dependency_evidence_overlay = Self::capture_dependency_overlay(&clone.inner);
        clone.imported_code_units = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.imported_code_units", None);
        clone.referencing_files = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.referencing_files", None);
        clone.export_indexes = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.export_indexes", None);
        clone.declaration_facts = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.declaration_facts", None);
        clone.rust_usage_facts = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.usage_facts", None);
        clone.declaration_source_properties = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.declaration_source_properties", None);
        clone.rust_hierarchy_source_facts = clone
            .inner
            .analyzer_store()
            .retention_budget()
            .region("rust.hierarchy_source_facts", None);
        clone.fact_catch_up = Arc::new(fact_catch_up::RustFactCatchUp::new());
        clone.walk_caches = Arc::new(RustWalkCaches::new(&self._retention_budget));
        clone
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.dependency_evidence_overlay = Self::capture_dependency_overlay(&clone.inner);
        clone
    }

    /// Fill or hit one request memo. A fill captures its whole receipt and
    /// stores it with the index; any other consumer replays it: the read keys,
    /// the stable gaps, the unattributed-read count and any reuse refusal, so a
    /// hit leaves the same evidence as rebuilding would within the request. A
    /// fill with execution dependences depends on this execution, not on the
    /// snapshot, so it returns its index to its own caller and publishes
    /// nothing.
    fn memoized_route_index<T>(
        &self,
        memo: &brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo<RustRouteMemoEntry<T>>,
        keep_going: &dyn Fn() -> bool,
        build: impl FnOnce() -> Result<T, RustCargoRouteError>,
    ) -> Result<Arc<T>, RustCargoRouteError> {
        let uncached = std::sync::Mutex::new(None);
        let built_here = std::sync::atomic::AtomicBool::new(false);
        let entry = memo.get_or_try_build_pool_independent_while(&|| keep_going(), || {
            built_here.store(true, std::sync::atomic::Ordering::Relaxed);
            let (built, receipt) =
                brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(self, build);
            match built {
                Ok(value) => {
                    let value = Arc::new(value);
                    if receipt.has_execution_dependences() {
                        *uncached.lock().expect("Rust route result mutex poisoned") =
                            Some(Arc::clone(&value));
                        return Ok(None);
                    }
                    Ok(Some(RustRouteMemoEntry { value, receipt }))
                }
                Err(RustCargoRouteError::Cancelled) => Ok(None),
                Err(error) => Err(error),
            }
        })?;
        match entry {
            Some(entry) => {
                if !built_here.load(std::sync::atomic::Ordering::Relaxed) {
                    self.walk_caches.note_route_memo_hit();
                    entry.receipt.replay();
                }
                Ok(Arc::clone(&entry.value))
            }
            None => uncached
                .into_inner()
                .expect("Rust route result mutex poisoned")
                .ok_or(RustCargoRouteError::Cancelled),
        }
    }

    /// Fill or hit one keyed request memo. Outside a query scope nothing is
    /// retained and every call builds. [`Self::memoized_route_index`] explains
    /// the fill and the replay.
    fn request_memoized<K, T>(
        &self,
        memo_of: fn(&RustRouteRequestMemo) -> &KeyedPoolSafeMemo<K, RustRouteMemoEntry<T>>,
        key: K,
        keep_going: &dyn Fn() -> bool,
        build: impl FnOnce() -> Result<T, RustCargoRouteError>,
    ) -> Result<T, RustCargoRouteError>
    where
        K: Eq + std::hash::Hash + Clone,
        T: Clone,
    {
        match self
            .inner
            .active_query_request_memo::<RustRouteRequestMemo>()
        {
            Some(memo) => {
                let cell = memo_of(&memo).cell(&key);
                let value = self.memoized_route_index(&cell, keep_going, build)?;
                Ok(T::clone(&value))
            }
            None => build(),
        }
    }

    /// The routes of the units that hold `file`: one `RustFileRoutes` composed
    /// from the per-unit kinds, memoized per file for the open query scope.
    fn file_routes(
        &self,
        file: &ProjectFile,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustFileRoutes, RustCargoRouteError> {
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
        let derivations = self
            .inner
            .derivations()
            .expect("the tree-sitter analyzer owns a derivation host");
        let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(file.rel_path());
        self.request_memoized(
            |memo| &memo.file_routes,
            path.clone(),
            progress.unwrap_or(&|| true),
            || {
                self.with_selected_route_demands(progress, |inventory| {
                    let (units, mut complete) = match derivations
                        .demand::<route_kinds::RustBroadFileUnits>(self, inventory, &path)
                    {
                        Demanded::Available {
                            value, complete, ..
                        } => (value, complete),
                        Demanded::Unavailable(cause) => return Err(cause),
                    };
                    let mut indexes = Vec::with_capacity(units.len());
                    let mut incomplete = Vec::new();
                    for unit in units.iter() {
                        if progress.is_some_and(|p| !p()) {
                            return Err(UnavailableCause::Cancelled);
                        }
                        match derivations
                            .demand::<route_kinds::RustUnitRoutes>(self, inventory, unit)
                        {
                            Demanded::Available {
                                value,
                                complete: unit_complete,
                                ..
                            } => {
                                complete &=
                                    self.note_incomplete_unit(unit, unit_complete, &mut incomplete);
                                indexes.push(Arc::clone(&value.index));
                            }
                            Demanded::Unavailable(cause) => return Err(cause),
                        }
                    }
                    // Recorded inside the memoized build, so a hit replays it
                    // and every consumer of a partial answer marks its result
                    // incomplete. An incomplete listing makes every unit it
                    // names incomplete, so they are all named here.
                    if !complete {
                        route_kinds::record_route_evidence_gap(self, &incomplete);
                    }
                    Ok(RustFileRoutes::with_completeness(indexes, complete))
                })
            },
        )
    }

    /// An inverse query may find no sites in a detached file without asking
    /// any forward route question. That negative still depends on knowing
    /// every selected unit's membership, including units with partial routes.
    fn check_route_membership_completeness(
        &self,
        progress: &dyn Fn() -> bool,
    ) -> Result<(), RustCargoRouteError> {
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
        // Without derivations the whole index answers routes, as file_routes
        // does, until step d removes it.
        let Some(derivations) = self.inner.derivations() else {
            return Ok(());
        };
        self.with_selected_route_demands(Some(progress), |inventory| {
            match derivations.demand::<route_kinds::RustSelectedUnitsKnown>(self, inventory, &0) {
                Demanded::Available { complete, .. } => {
                    if !complete {
                        route_kinds::record_route_evidence_gap(self, &[]);
                    }
                    Ok(())
                }
                Demanded::Unavailable(cause) => Err(cause),
            }
        })
    }

    /// Run `demands` in the read frame of this request's selected Rust
    /// snapshot, opening the selection when no frame is open, and map an
    /// unavailable demand to the route error the consumers know.
    fn with_selected_route_demands<T>(
        &self,
        progress: Option<&dyn Fn() -> bool>,
        demands: impl FnOnce(
            &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        ) -> Result<T, UnavailableCause>,
    ) -> Result<T, RustCargoRouteError> {
        if progress.is_some_and(|p| !p()) {
            return Err(RustCargoRouteError::Cancelled);
        }
        let snapshots = self.inner.selected_workspace_snapshots();
        let Some(snapshot) = snapshots.get("rust").cloned() else {
            self.inner.record_store_error(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(
                    "Rust file routes unavailable: no selected Rust snapshot",
                ),
            );
            return Err(RustCargoRouteError::Unavailable);
        };
        let result = self.with_rust_route_inventory(snapshot, demands);
        if result.is_ok() {
            // A route reader
            // answered from the selected live publication, which verifies an
            // initially unverified generation without starting repair.
            self.note_rust_publication_verified();
        }
        result.map_err(|cause| match cause {
            UnavailableCause::Cancelled => RustCargoRouteError::Cancelled,
            other => {
                self.inner.record_store_error(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                        "Rust file routes unavailable: {other:?}"
                    )),
                );
                RustCargoRouteError::Unavailable
            }
        })
    }

    /// The package and member-file questions, answered lazily from the per-unit
    /// kinds instead of from the whole package index.
    pub fn package_view(&self) -> RustPackageView<'_> {
        RustPackageView { source: self }
    }

    /// The library roots named `normalized_name`, for a file that no unit's
    /// target holds: the crate-name question, with each library's package from
    /// its unit's package rows. The whole index's unscoped-library fallback.
    fn unscoped_libraries_of(
        &self,
        normalized_name: &str,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<RustLibraryRoot>>, RustCargoRouteError> {
        let name = brokk_bifrost_rust::cargo_manifest::normalize_crate_name(normalized_name);
        self.package_question(
            |memo| &memo.unscoped_libraries,
            name.clone(),
            progress,
            |derivations, inventory, incomplete| {
                let (roots, mut complete) = self.demanded::<route_kinds::RustCrateNameUnits>(
                    derivations,
                    inventory,
                    &name,
                )?;
                let project_root = self.inner.project().root().to_path_buf();
                let mut libraries = Vec::new();
                for (unit, _, root) in roots.iter().filter(|(_, kind, _)| kind == "lib") {
                    let (rows, rows_complete) = self.demanded::<route_kinds::RustUnitPackageRows>(
                        derivations,
                        inventory,
                        unit,
                    )?;
                    complete &= self.note_incomplete_unit(unit, rows_complete, incomplete);
                    libraries.extend(
                        rows.iter()
                            .filter(|row| &row.rel_path == root && row.is_root_member)
                            .map(|row| RustLibraryRoot {
                                root_file: ProjectFile::new(project_root.clone(), &row.rel_path),
                                package: row.package_components.join("."),
                            }),
                    );
                }
                libraries.sort_by(|left, right| {
                    left.root_file
                        .cmp(&right.root_file)
                        .then_with(|| left.package.cmp(&right.package))
                });
                libraries.dedup();
                Ok(RustRoutedAnswer {
                    value: libraries,
                    complete,
                })
            },
        )
    }

    /// The files that can name something in the target roots of `file`: for
    /// each root of `file`, the union of that root's entry in the reachability
    /// of every unit that holds the root. A root's reachability through one
    /// unit can be a strict subset of the whole index's answer, because
    /// targets of different units can share a root file.
    fn reaching_files_of(
        &self,
        file: &ProjectFile,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<ProjectFile>>, RustCargoRouteError> {
        let routes = self.file_routes(file, progress)?;
        let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(file.rel_path());
        let roots = routes.target_roots(file);
        let routes_complete = routes.is_complete();
        self.package_question(
            |memo| &memo.reaching_files,
            path,
            progress,
            |derivations, inventory, incomplete| {
                let project_root = self.inner.project().root().to_path_buf();
                let mut complete = routes_complete;
                let mut files = Vec::new();
                for root in &roots {
                    let root_path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(
                        root.rel_path(),
                    );
                    let (units, units_complete) = self
                        .demanded::<route_kinds::RustBroadFileUnits>(
                            derivations,
                            inventory,
                            &root_path,
                        )?;
                    complete &= units_complete;
                    for unit in units.iter() {
                        let (reachable, reachable_complete) = self
                            .demanded::<route_kinds::RustTargetReachability>(
                            derivations,
                            inventory,
                            unit,
                        )?;
                        complete &= self.note_incomplete_unit(unit, reachable_complete, incomplete);
                        files.extend(
                            reachable
                                .roots
                                .iter()
                                .filter(|entry| entry.root == root_path)
                                .flat_map(|entry| &entry.files)
                                .map(|path| ProjectFile::new(project_root.clone(), path)),
                        );
                    }
                }
                files.sort();
                files.dedup();
                Ok(RustRoutedAnswer {
                    value: files,
                    complete,
                })
            },
        )
    }

    /// One package question: demand the units it names in the read frame,
    /// record the route evidence gap when the answer is incomplete, and
    /// memoize the answer for the open query scope. Recording happens inside
    /// the build, so a memo hit replays it with the rest of the receipt.
    fn package_question<K, T>(
        &self,
        memo_of: fn(
            &RustRouteRequestMemo,
        ) -> &KeyedPoolSafeMemo<K, RustRouteMemoEntry<RustRoutedAnswer<T>>>,
        key: K,
        progress: Option<&dyn Fn() -> bool>,
        compose: impl FnOnce(
            &brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations,
            &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
            &mut Vec<[u8; 32]>,
        ) -> Result<RustRoutedAnswer<T>, UnavailableCause>,
    ) -> Result<RustRoutedAnswer<T>, RustCargoRouteError>
    where
        K: Eq + std::hash::Hash + Clone,
        T: Clone,
    {
        let Some(derivations) = self.inner.derivations() else {
            self.inner.record_store_error(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(
                    "Rust package questions unavailable: no derivation host",
                ),
            );
            return Err(RustCargoRouteError::Unavailable);
        };
        self.request_memoized(memo_of, key, progress.unwrap_or(&|| true), || {
            self.with_selected_route_demands(progress, |inventory| {
                let mut incomplete = Vec::new();
                let answer = compose(derivations, inventory, &mut incomplete)?;
                if !answer.complete {
                    route_kinds::record_route_evidence_gap(self, &incomplete);
                }
                Ok(answer)
            })
        })
    }

    fn demanded<K: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind>(
        &self,
        derivations: &brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations,
        inventory: &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        key: &K::Key,
    ) -> Result<
        (
            brokk_bifrost_semantic::analyzer::semantic::derivation::Handle<K::Output>,
            bool,
        ),
        UnavailableCause,
    > {
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
        match derivations.demand::<K>(self, inventory, key) {
            Demanded::Available {
                value, complete, ..
            } => Ok((value, complete)),
            Demanded::Unavailable(cause) => Err(cause),
        }
    }

    /// The completeness of an answer about `unit`, remembering the unit when
    /// the answer is not complete.
    fn note_incomplete_unit(
        &self,
        unit: &route_kinds::SelectedRustUnit,
        answer_complete: bool,
        incomplete: &mut Vec<[u8; 32]>,
    ) -> bool {
        let complete = unit.and_complete(answer_complete);
        if !complete {
            incomplete.push(*unit.key());
        }
        complete
    }

    /// The package and member file index, memoized for the open query scope
    /// with the same receipt replay as the per-question route memos.
    pub(crate) fn package_file_index_while(
        &self,
        _token: QueryToken<'_>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustWholePackageIndex>, RustCargoRouteError> {
        match self
            .inner
            .active_query_request_memo::<RustRouteRequestMemo>()
        {
            Some(memo) => self.memoized_route_index(&memo.package_files, keep_going, || {
                self.build_package_file_index_while(keep_going)
            }),
            None => self
                .build_package_file_index_while(keep_going)
                .map(Arc::new),
        }
    }

    fn build_package_file_index_while(
        &self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<RustWholePackageIndex, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let snapshots = self.inner.selected_workspace_snapshots();
        let rows = self
            .analyzer_store()
            .rust_summary_package_rows(snapshots.as_ref())
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context("reading live Rust summary package and member rows"),
                );
                RustCargoRouteError::Unavailable
            })?;
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let root = self.inner.project().root().to_path_buf();
        let rows = rows
            .into_iter()
            .map(|row| RustPackageFileRow {
                file: ProjectFile::new(root.clone(), row.rel_path),
                package_components: row.package_components,
                crate_name: row.crate_name,
                target_kind: row.target_kind,
                is_root_member: row.is_root_member,
            })
            .collect();
        Ok(RustWholePackageIndex::from_summary_rows(rows))
    }

    #[cfg(test)]
    /// Files the Cargo-route build recovered by parsing. The structural claim of
    /// #1793 is that this reads zero on a warm workspace: the index composes
    /// from rows and never from a workspace parse.
    #[doc(hidden)]
    pub fn module_route_fact_fallback_count_for_test(&self) -> usize {
        self.module_route_fact_fallback_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_module_route_fact_fallback_count_for_test(&self) {
        self.module_route_fact_fallback_count
            .store(0, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let adapter = RustAdapter::for_tests();
        let inner = TreeSitterAnalyzer::new_with_config(project, adapter, config);
        Self::from_inner(inner)
    }

    #[doc(hidden)]
    pub fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
        let budget = store_context.store.retention_budget();
        // Content-keyed lexical caches can move to the owner's snapshot caches later.
        let adapter = RustAdapter::new(
            Arc::new(crate_naming::RustCrateNamingCaches::new(budget)),
            Arc::new(brokk_bifrost_rust::lexical_scope::RustLexicalCaches::new(
                budget,
            )),
        );
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            adapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        rust_type_identifiers(source)
    }
}

/// Whether `file` is a Cargo input the workspace analyzer routes to the Rust
/// delegate by name, because none maps to a language: a manifest, a lockfile
/// or a configuration file (`RustSupport::is_configuration_input_path`). Cargo
/// file changes refresh static file evidence independently of packs; crate
/// rows read the subset `is_cargo_topology_input` names.
pub(crate) fn is_cargo_evidence_input(file: &ProjectFile) -> bool {
    RustSupport.is_configuration_input_path(file.rel_path())
}

/// Whether `file` is a Cargo input that crate rows read, and so a workspace
/// package identity input with a topology digest
/// (`RustAdapter::workspace_package_identity_digest`):
/// - a manifest, `Cargo.toml`, which names crates, their targets and their
///   dependency routes;
/// - a Cargo configuration file, `.cargo/config.toml` or the legacy
///   `.cargo/config`, whose `[patch]`, `build.target` and `--cfg` rustflags
///   change crate cfg sets and routes (#3768,
///   `brokk_bifrost_rust::cargo_config`).
///
/// `Cargo.lock` is routed but crate rows do not read it, so it has no digest
/// and an edit to it rebuilds.
pub(crate) fn is_cargo_topology_input(path: &std::path::Path) -> bool {
    path.file_name().is_some_and(|name| name == "Cargo.toml")
        || brokk_bifrost_rust::cargo_config::is_cargo_configuration_path(path)
}

/// Whether every changed file the Rust analyzer would reindex still hashes to
/// what the store holds, so `update` can hand back a clone instead of
/// rebuilding.
///
/// A changed Cargo input is never "unchanged": a manifest or configuration
/// file moves crate membership, cfg sets and dependency routes, and any of
/// them moves dependency evidence, without touching a Rust source. Only the
/// underlying analyzer's update re-derives those rows.
fn rust_indexed_sources_unchanged(
    index: &dyn CodeUnitIndex,
    changed_files: &BTreeSet<ProjectFile>,
) -> bool {
    if changed_files.iter().any(is_cargo_evidence_input) {
        return false;
    }
    changed_files
        .iter()
        .filter(|file| file_language(file) == Language::Rust || index.is_analyzed(file))
        .all(|file| {
            index
                .project()
                .read_source(file)
                .ok()
                .is_some_and(|source| index.indexed_source_matches(file, &source))
        })
}

fn reference_context_with_progress<'a>(
    progress: &'a dyn Fn() -> bool,
    build: impl FnOnce() -> brokk_bifrost_rust::graph_support::RustReferenceContext<'a>,
) -> Option<brokk_bifrost_rust::graph_support::RustReferenceContext<'a>> {
    progress().then(build)
}

impl TypeAliasProvider for RustAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

/// The analyzer owns the retained bounded indexes, so it is the only implementor
/// of the source traits the Rust language logic is written against. Reference
/// contexts themselves are query-scoped views over these indexes.
/// Every method here forwards to an inherent accessor; inherent methods win
/// name resolution, so these bodies do not recurse.
impl brokk_bifrost_rust::graph_support::RustSource for RustAnalyzer {
    fn is_selected_source(&self, file: &ProjectFile) -> bool {
        self.inner.resolve_live_oid_for_file(file).is_some()
    }

    fn with_usage_read_frame(&self, f: &mut dyn FnMut()) {
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            read_frame, rust_route_question_identity, selected_rust_snapshot,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;

        let snapshots = self.inner.selected_workspace_snapshots();
        let Some(snapshot) = snapshots.get("rust").cloned() else {
            f();
            return;
        };
        let identity = rust_route_question_identity(self, self.analyzer_store(), snapshot.clone());
        read_frame::with_query_read_frame(
            identity,
            || match self.open_selected_rust_inventory(&CancellationToken::default()) {
                // The frame answers for the snapshot its identity names. If the
                // analyzer's selection moved before the first question opened
                // it, refuse instead of answering from a newer snapshot, so one
                // request never mixes two.
                Ok(SelectedResolutionMountInventoryOutcome::Ready(inventory)) => {
                    match selected_rust_snapshot(&inventory) {
                        Ok(opened) if opened == snapshot => Ok(*inventory),
                        opened => Err(UnavailableCause::Failed(
                            format!("Rust usage inventory moved: {snapshot:?} to {opened:?}")
                                .into(),
                        )),
                    }
                }
                Ok(SelectedResolutionMountInventoryOutcome::Cancelled) => {
                    Err(UnavailableCause::Cancelled)
                }
                Ok(SelectedResolutionMountInventoryOutcome::Unavailable(reason)) => {
                    Err(UnavailableCause::Failed(
                        format!("Rust usage inventory unavailable: {reason:?}").into(),
                    ))
                }
                Ok(SelectedResolutionMountInventoryOutcome::Stale(reason)) => {
                    Err(UnavailableCause::Failed(
                        format!("Rust usage inventory stale: {reason:?}").into(),
                    ))
                }
                Err(error) => Err(UnavailableCause::Failed(error.to_string().into())),
            },
            f,
        );
    }
    fn crate_naming_caches(&self) -> &crate_naming::RustCrateNamingCaches {
        &self.inner.adapter().naming
    }

    fn lexical_caches(&self) -> &brokk_bifrost_rust::lexical_scope::RustLexicalCaches {
        self.inner.adapter().lexical_caches()
    }

    fn code_units(&self) -> &dyn CodeUnitIndex {
        self
    }

    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.structural_parent_of(code_unit)
    }

    #[track_caller]
    fn declaration_candidates_by_fqn_while(
        &self,
        fq_name: &str,
        keep_going: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Vec<CodeUnit>> {
        if !keep_going() {
            return Err(ReferenceContextError::Interrupted);
        }
        if !self.inner.workspace_declaration_identities_authoritative() {
            return Err(RustCargoRouteError::Unavailable.into());
        }
        let mut interrupted = false;
        let candidates = self.declaration_candidates_by_fqn_limited(fq_name, usize::MAX, || {
            let proceed = keep_going();
            interrupted |= !proceed;
            proceed
        });
        if interrupted || !keep_going() {
            return Err(ReferenceContextError::Interrupted);
        }
        if !candidates.complete {
            return Err(RustCargoRouteError::Unavailable.into());
        }
        Ok(candidates.rows)
    }

    fn declaration_source_properties(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustDeclarationSourceProperties>>,
        RustCargoRouteError,
    > {
        self.declaration_source_properties(file, keep_going)
    }

    fn direct_ancestors(&self, code_unit: &CodeUnit) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
        self.direct_ancestors(code_unit)
    }

    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        self.prepared_syntax(token, file)
    }

    fn file_routes(
        &self,
        file: &ProjectFile,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustFileRoutes, RustCargoRouteError> {
        self.file_routes(file, progress)
    }

    fn unscoped_libraries(
        &self,
        normalized_name: &str,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustUnscopedLibraries, RustCargoRouteError> {
        self.unscoped_libraries_of(normalized_name, progress)
    }

    fn files_that_can_reference_target_of(
        &self,
        file: &ProjectFile,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<ProjectFile>>, RustCargoRouteError> {
        self.reaching_files_of(file, progress)
    }

    fn package_file_index_while(
        &self,
        token: QueryToken<'_>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustWholePackageIndex>, RustCargoRouteError> {
        self.package_file_index_while(token, keep_going)
    }

    // The package questions are answered by the per-unit kinds. A tree-sitter
    // analyzer always has a derivation host; the view reports Unavailable if
    // it did not.

    fn package_files_of(
        &self,
        _token: QueryToken<'_>,
        package: &str,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<ProjectFile>>, RustCargoRouteError> {
        self.package_view().files_in_package(package, progress)
    }

    fn package_contains(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<bool>, RustCargoRouteError> {
        self.package_view().contains(file, progress)
    }

    fn crate_package_names(
        &self,
        _token: QueryToken<'_>,
        import_name: &str,
        progress: Option<&dyn Fn() -> bool>,
    ) -> Result<RustRoutedAnswer<Vec<String>>, RustCargoRouteError> {
        self.package_view().crate_packages(import_name, progress)
    }

    fn import_binder_of(
        &self,
        file: &ProjectFile,
    ) -> brokk_bifrost_core::analyzer::usages::model::ImportBinder {
        brokk_bifrost_analysis::analyzer::i_analyzer::with_query_scope(self, |token| {
            self.import_binder_of(token, file)
        })
    }

    fn export_index_of(
        &self,
        file: &ProjectFile,
    ) -> brokk_bifrost_rust::graph_support::ReferenceContextResult<
        Arc<Accounted<brokk_bifrost_core::analyzer::usages::model::ExportIndex>>,
    > {
        self.export_index_of(file)
    }

    fn export_index_of_while(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> brokk_bifrost_rust::graph_support::ReferenceContextResult<
        Arc<Accounted<brokk_bifrost_core::analyzer::usages::model::ExportIndex>>,
    > {
        self.export_index_of_while(file, progress)
    }

    fn note_module_file_resolution(&self) {
        self.note_module_file_resolution();
    }

    fn note_export_name_canonicalization(&self) {
        self.note_export_name_canonicalization();
    }
}

/// The live file-to-blob mapping, handed to `brokk-bifrost-rust` as an
/// object-safe view because `LiveSnapshot` is an analysis-side type.
struct LiveSnapshotBlobs(Arc<brokk_bifrost_analysis::analyzer::store::liveness::LiveSnapshot>);

impl RustLiveBlobs for LiveSnapshotBlobs {
    fn oid_for_path(&self, file: &ProjectFile) -> Option<git2::Oid> {
        self.0.oid_for_path(file)
    }

    fn paths_for_oid(&self, oid: git2::Oid) -> Vec<ProjectFile> {
        self.0.paths_for_oid(oid).to_vec()
    }
}

fn placed_declarations(rows: Vec<(git2::Oid, u32, String)>) -> Vec<RustPlacedDeclaration> {
    rows.into_iter()
        .map(|(blob, declaration, rel_path)| RustPlacedDeclaration {
            rel_path,
            blob,
            declaration,
        })
        .collect()
}

/// The store-backed half of the Rust usage substrate. Everything here is
/// something only the analyzer can answer: the store handle behind the six
/// inverted lookups, the live blob mapping, and the caches it owns.
/// Publication preparation is deliberately not part of this query interface.
impl RustFactSource for RustAnalyzer {
    fn read_capability(&self) -> brokk_bifrost_core::analyzer::project_reads::ReadCapability {
        self.inner.read_capability()
    }

    fn rust_usage_facts_of_blob(
        &self,
        oid: git2::Oid,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustUsageFacts>>,
        RustCargoRouteError,
    > {
        self.rust_usage_facts_of_blob(oid)
    }

    fn rust_import_target_blobs(
        &self,
        module_path: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.store_result_or_unavailable(
            self.analyzer_store()
                .rust_import_target_blobs("rust", module_path),
            || format!("reading Rust import targets for {module_path:?}"),
        )
    }

    fn rust_module_import_candidate_blobs(
        &self,
        component: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupKind;
        use brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows;
        match self
            .recorded_rust_inventory(LookupKind::RustModuleImportCandidateInventory, component)?
        {
            RustInventoryRows::Imports(rows) => Ok(rows),
            _ => unreachable!("import inventory returned another shape"),
        }
    }

    fn rust_export_blobs(
        &self,
        exported_name: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.store_result_or_unavailable(
            self.analyzer_store()
                .rust_export_blobs("rust", exported_name),
            || format!("reading Rust exports for {exported_name:?}"),
        )
    }

    fn rust_traits_implemented_by(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion};
        let rows = self.recorded_rust_inventory_question(
            LookupKind::RustTraitsImplementedByInventory,
            LookupQuestion::RustPlacedDeclaration {
                blob: declaration.blob.as_bytes().try_into().expect("git OID"),
                declaration: declaration.declaration,
                rel_path: declaration.rel_path.clone().into(),
            },
        )?;
        let brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows::Bound(rows) =
            rows
        else {
            unreachable!()
        };
        let mut declarations = rows
            .into_iter()
            .filter_map(|(_, _, _, endpoint)| endpoint)
            .map(|(blob, declaration, rel_path)| RustPlacedDeclaration {
                blob,
                declaration,
                rel_path,
            })
            .collect::<Vec<_>>();
        declarations.sort();
        declarations.dedup();
        Ok(declarations)
    }

    fn rust_types_implementing(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
        let result = self
            .analyzer_store()
            .rust_types_implementing(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(declaration.blob, "rust"),
                declaration.declaration,
                &declaration.rel_path,
            )
            .map(placed_declarations);
        self.store_result_or_unavailable(result, || {
            format!("reading Rust types implementing {declaration:?}")
        })
    }

    fn rust_trait_impl_rows(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustTraitImplRow>, RustCargoRouteError> {
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, LookupQuestion};
        let rows = self.recorded_rust_inventory_question(
            LookupKind::RustBoundTraitImplInventory,
            LookupQuestion::RustPlacedDeclaration {
                blob: declaration.blob.as_bytes().try_into().expect("git OID"),
                declaration: declaration.declaration,
                rel_path: declaration.rel_path.clone().into(),
            },
        )?;
        let brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows::Bound(rows) =
            rows
        else {
            unreachable!()
        };
        Ok(rows
            .into_iter()
            .map(
                |(impl_blob, impl_rel_path, impl_declaration, subject)| RustTraitImplRow {
                    impl_blob,
                    impl_rel_path,
                    impl_declaration,
                    subject: subject.map(|(blob, declaration, rel_path)| RustPlacedDeclaration {
                        blob,
                        declaration,
                        rel_path,
                    }),
                },
            )
            .collect())
    }

    fn rust_traits_of_impl(
        &self,
        impl_item: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
        let result = self
            .analyzer_store()
            .rust_traits_of_impl(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(impl_item.blob, "rust"),
                impl_item.declaration,
                &impl_item.rel_path,
            )
            .map(placed_declarations);
        self.store_result_or_unavailable(result, || {
            format!("reading the Rust traits stated by impl {impl_item:?}")
        })
    }

    fn rust_item_macro_decisions(
        &self,
        file: &ProjectFile,
    ) -> Result<Vec<brokk_bifrost_rust::graph_support::RustItemMacroDecision>, RustCargoRouteError>
    {
        let blob = self
            .live_blobs()
            .oid_for_path(file)
            .ok_or(RustCargoRouteError::Unavailable)?;
        let rel_path = brokk_bifrost_core::path_utils::rel_path_string(file);
        let snapshots = self.inner.selected_workspace_snapshots();
        self.analyzer_store()
            .rust_item_macro_decisions(
                snapshots.as_ref(),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(blob, "rust"),
                &rel_path,
            )
            .map(|rows| {
                rows.into_iter()
                    .map(
                        |row| brokk_bifrost_rust::graph_support::RustItemMacroDecision {
                            invocation:
                                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new(
                                    row.invocation,
                                ),
                            name: row.name,
                            decided: row.decided,
                        },
                    )
                    .collect()
            })
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading the Rust item macro decisions of {file:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_macro_expansion_blobs(
        &self,
        names: &[String],
    ) -> Result<Vec<brokk_bifrost_rust::graph_support::RustMacroExpansionBlob>, RustCargoRouteError>
    {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupKind;
        use brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows;
        let mut combined = Vec::new();
        for name in names {
            let RustInventoryRows::Macros(rows) =
                self.recorded_rust_inventory(LookupKind::RustMacroExpansionInventory, name)?
            else {
                unreachable!("macro inventory returns macro rows")
            };
            combined.extend(rows.into_iter().map(|row| {
                brokk_bifrost_rust::graph_support::RustMacroExpansionBlob {
                    blob: row.blob,
                    via: row.via,
                }
            }));
        }
        combined.sort();
        combined.dedup();
        Ok(combined)
    }

    fn rust_trait_impl_spellings(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<String>, RustCargoRouteError> {
        let result = self.analyzer_store().rust_trait_impl_spellings(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(declaration.blob, "rust"),
            declaration.declaration,
            &declaration.rel_path,
        );
        self.store_result_or_unavailable(result, || {
            format!("reading Rust trait impl spellings for {declaration:?}")
        })
    }

    fn rust_alias_blobs_mentioning(
        &self,
        identifier: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupKind;
        let rows = self.recorded_rust_inventory(LookupKind::RustAliasBlobInventory, identifier)?;
        let brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows::Imports(
            rows,
        ) = rows
        else {
            unreachable!()
        };
        Ok(rows)
    }

    fn rust_unresolved_trait_impl_files(
        &self,
        spelling: &str,
    ) -> Result<Vec<RustUnresolvedImpl>, RustCargoRouteError> {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupKind;
        use brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows;
        match self
            .recorded_rust_inventory(LookupKind::RustUnresolvedTraitImplInventory, spelling)?
        {
            RustInventoryRows::Unresolved(rows) => Ok(rows
                .into_iter()
                .map(
                    |(impl_blob, impl_rel_path, impl_declaration)| RustUnresolvedImpl {
                        impl_blob,
                        impl_rel_path,
                        impl_declaration,
                    },
                )
                .collect()),
            _ => unreachable!("impl inventory returned another shape"),
        }
    }

    fn rust_identifier_occurrence_blobs(
        &self,
        identifier: &str,
    ) -> Result<Vec<(git2::Oid, u32)>, RustCargoRouteError> {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupKind;
        use brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows;
        match self
            .recorded_rust_inventory(LookupKind::RustIdentifierOccurrenceInventory, identifier)?
        {
            RustInventoryRows::Occurrences(rows) => Ok(rows),
            _ => unreachable!("occurrence inventory returned another shape"),
        }
    }

    fn rust_include_blobs(&self, file_name: &str) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.store_result_or_unavailable(
            self.analyzer_store().rust_include_blobs("rust", file_name),
            || format!("reading Rust include candidates for {file_name:?}"),
        )
    }

    fn rust_include_host_blobs(&self) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.store_result_or_unavailable(
            self.analyzer_store().rust_include_host_blobs("rust"),
            || "reading Rust include hosts".to_owned(),
        )
    }

    fn rust_declaration_facts_of(
        &self,
        file: &ProjectFile,
    ) -> Result<Arc<RustDeclarationFacts>, RustCargoRouteError> {
        self.rust_declaration_facts_of(file)
    }

    fn canonical_rust_hierarchy_source_facts(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<RustHierarchySourceFacts>>,
        RustCargoRouteError,
    > {
        self.canonical_rust_hierarchy_source_facts(file, keep_going)
    }

    fn live_blobs(&self) -> Arc<dyn RustLiveBlobs> {
        Arc::new(LiveSnapshotBlobs(self.live_path_snapshot()))
    }

    fn walk_caches(&self) -> &Arc<RustWalkCaches> {
        &self.walk_caches
    }

    fn reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        self.reference_context_of(token, file)
    }

    fn reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>> {
        reference_context_with_progress(progress, || {
            self.reference_context_of_while(token, file, progress)
        })
    }

    fn forward_reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        self.forward_reference_context_of(token, file)
    }

    fn forward_reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>> {
        reference_context_with_progress(progress, || {
            self.forward_reference_context_of_while(token, file, progress)
        })
    }
}

impl TestDetectionProvider for RustAnalyzer {}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for RustAnalyzer {
    delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    delegate_inner_methods! {
        fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit>;
    }

    delegate_inner_methods! {
        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit>;
    }

    delegate_inner_methods! {
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit>;
    }

    delegate_inner_methods! {
        fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>>;
    }

    delegate_inner_methods! {
        fn analyzed_files(&self) -> Vec<ProjectFile>;
    }

    delegate_inner_methods! {
        fn indexed_source(&self, file: &ProjectFile) -> Option<String>;
    }

    delegate_inner_methods! {
        fn indexed_blob_oid(&self, file: &ProjectFile) -> Option<brokk_bifrost_analysis::analyzer::Oid>;
    }

    delegate_inner_methods! {
        fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range>;
    }

    delegate_inner_methods! {
        fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool;
    }

    delegate_inner_methods! {
        fn is_analyzed(&self, file: &ProjectFile) -> bool;
    }

    delegate_inner_methods! {
        fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile>;
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    delegate_inner_methods! {
        fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    delegate_inner_methods! {
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    fn declares(&self, file: &ProjectFile, unit: &CodeUnit) -> bool {
        self.inner.declares(file, unit)
    }

    fn declarations_named(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.inner.declarations_named(file, identifier)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    delegate_inner_methods! {
        fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    /// The same owner lookup as the [`CodeUnitIndex::parent_of`] default plus Rust's
    /// structural fallback, routed through the request-scoped owner memo so a
    /// file of N declarations asking for the same owner name costs one store
    /// query rather than N (#1230 item 6).
    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner
            .definition_parent_unit(code_unit)
            .or_else(|| self.inner.structural_parent_of(code_unit))
    }

    delegate_inner_methods! {
        fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range>;
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> (Vec<brokk_bifrost_core::analyzer::model::Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    delegate_inner_methods! {
        fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata>;
    }

    delegate_inner_methods! {
        fn languages(&self) -> BTreeSet<Language>;
    }

    delegate_inner_methods! {
        fn project(&self) -> &dyn Project;
    }

    delegate_inner_methods! {
        fn get_all_declarations(&self) -> Vec<CodeUnit>;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    delegate_inner_methods! {
        fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    }

    delegate_inner_methods! {
        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    }

    delegate_inner_methods! {
        fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    }

    delegate_inner_methods! {
        fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn has_complete_symbol_lookup_index(&self) -> bool;
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for RustAnalyzer {
    delegate_inner_procedure_fact_methods!();

    fn dependency_file_locations(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Vec<(
            String,
            crate::analyzer::semantic_model::DependencyEvidenceLocation,
        )>,
    > {
        match &self.dependency_evidence_overlay {
            Ok(Some(publication)) => publication.locations(),
            Ok(None) => self.inner.dependency_file_locations(),
            Err(error) => Err(error.clone()),
        }
    }

    fn dependency_file_evidence(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        crate::analyzer::semantic_model::DependencyFileEvidence,
    > {
        if let Some(error) = self.inner.workspace_input_publication_error() {
            return Err(error);
        }
        match &self.dependency_evidence_overlay {
            Ok(Some(publication)) => publication.read(),
            Ok(None) => self.inner.dependency_file_evidence(),
            Err(error) => Err(error.clone()),
        }
    }

    forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
    }

    forward_file_identity_invalidation!();

    fn working_tree_identity(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        match self.rust_trait_member_implementations(code_unit) {
            Ok(value) => value,
            Err(error) => {
                self.record_hierarchy_error(error);
                None
            }
        }
    }

    brokk_bifrost_analysis::forward_query_read_ledger!();

    fn begin_query(
        &self,
        context: &Arc<brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext>,
    ) {
        self.inner.begin_query(context);
    }

    fn end_query(
        &self,
        context: &Arc<brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext>,
    ) {
        self.inner.end_query(context);
    }

    delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
    }

    delegate_inner_methods! {
        fn record_query_failure(&self, error: crate::analyzer::store::StoreError);
    }

    delegate_inner_methods! {
        fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell>;
    }

    delegate_inner_methods! {
        fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<crate::analyzer::DefinitionLookupMemo>>;
    }

    delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    /// The hierarchy index still takes double-digit seconds to build on a large
    /// workspace; the Rust usage side no longer builds anything, so its warm is
    /// the fact catch-up, which finds nothing to do on a workspace analysis
    /// already persisted. The two run on separate threads because neither may
    /// wait on the other: on a 401k-file workspace the hierarchy build had not
    /// returned sixteen minutes in (#1757), and a usage query must not inherit
    /// that wait.
    ///
    /// The hierarchy half builds on the dedicated build pool (#1772), so this
    /// scope's own thread only parks on it: neither the warm nor a request
    /// that reaches the same memo spends a global-pool worker on the build's
    /// parallelism.
    fn warm_query_indexes(&self) {
        self.warm_usage_facts();
    }

    fn query_indexes_warm(&self) -> bool {
        self.rust_usage_facts_warm()
    }

    fn update_with_listing(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
    ) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            // A failed listing read counts as a change, so the delegate's
            // update meets the same read and records the error.
            if !self.inner.rust_listing_changed(listing).unwrap_or(true)
                && rust_indexed_sources_unchanged(self, changed_files)
            {
                return self.clone();
            }

            let inner = self.inner.update_with_listing(changed_files, listing);
            Self::from_inner(inner)
        })
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
    }

    fn parse_errors(
        &self,
        file: &ProjectFile,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
        diagnostics::collect_rust_semantic_diagnostics(self, file, source)
    }

    delegate_inner_methods! {
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    }

    delegate_inner_methods! {
        fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    }

    delegate_inner_methods! {
        fn find_nearest_declaration(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
            ident: &str,
        ) -> Option<crate::analyzer::DeclarationInfo>;
    }

    fn search_symbol_candidates(
        &self,
        patterns: &brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn member_family_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider>
    {
        Some(self)
    }

    delegate_inner_methods! {
        fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider>;
    }

    fn snapshot_caches(
        &self,
    ) -> Option<&brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    delegate_inner_methods! {
        fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities>;
    }

    delegate_inner_methods! {
        fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex>;
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    /// Per-declaration taint, widened by the file-level verdict: every
    /// declaration in a `#[cfg(test)]`-only module is in a test region, even
    /// the plain helper functions that carry no attribute of their own (#1546).
    fn in_test_region(&self, code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit) || self.file_is_test_only(code_unit.source())
    }

    /// `false` is not a proof of "not test-only" when the answer is partial:
    /// `RustFileRoutes::file_is_test_only` is a universal claim over the file's
    /// units. A partial answer records its route evidence gap on the query
    /// scope, which marks the enclosing result incomplete.
    fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        match self.file_routes(file, None) {
            Ok(routes) => routes.file_is_test_only(file),
            // This legacy boolean capability cannot carry availability. The
            // route producer records the structured store failure on the query
            // scope, which must reject the enclosing result; do not cache it.
            Err(RustCargoRouteError::Unavailable) => false,
            Err(RustCargoRouteError::Cancelled) => {
                unreachable!("unbounded Cargo-route lookup cannot cancel")
            }
        }
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        detect_language_structural_clone_smells(self, files, weights, Language::Rust, |code_unit| {
            build_rust_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        brokk_bifrost_analysis::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::Rust,
            |source| detect_rust_test_assertion_smells(file, source, &weights),
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for RustAnalyzer {
    delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    fn reset_definition_candidate_row_read_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_definition_candidate_row_read_count_for_test();
    }

    fn definition_candidate_row_read_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .definition_candidate_row_read_count_for_test()
    }

    delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_search_candidate_hydration_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_search_candidate_hydration_count_for_test();
    }

    fn search_candidate_hydration_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .search_candidate_hydration_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }
}

static RUST_USAGE_STRATEGY: RustNativeUsageStrategy = RustNativeUsageStrategy;

#[doc(hidden)]
pub struct RustSupport;

/// Expand `Path::new` to `std::path::Path::new` when the file's `use`
/// declarations bind `Path` (#2596, the Rust analog of Java's #2364).
///
/// The expansion reads the parser-derived import binders the store already
/// holds: a binder's `local_name` is the name written at the call site
/// (`alias ?? identifier`), and its structured segments are the path it binds
/// to. Nothing here parses source text or reconstructs a path from the raw
/// `use` snippet.
///
/// The binder has to be a proof, not a spelling. Its leading segment must name
/// no workspace declaration in the scope that holds the `use`, which is the
/// question the Rust resolver answers for a written-out scoped path (see
/// [`rust_import_binder_external_callee`]). A workspace `std` module therefore
/// leaves the call it shadows unresolved instead of letting the binder's text
/// borrow a sysroot summary (#3484). The check needs the parsed file and the
/// exact source snapshot the call site was classified against; without them no
/// binder expands.
///
/// A multi-segment callee binds through its leading segment. In
/// `net::TcpStream::connect` with `use std::net as net;`, the binder `net` names
/// the target path `std::net`, and the middle written segments (`TcpStream`)
/// append after it, so the owner is `std::net::TcpStream` (#3491). A
/// single-segment import (`use foo;`, `extern crate foo;`) adds no qualification
/// and is skipped. Every other binder of that local name
/// has to prove this one identity: a binder that proves a different owner
/// answers nothing rather than picking one, and so does a binder that proves
/// nothing at all, whether because a workspace declaration or boundary owns the
/// path or because it is one of two mutually exclusive `#[cfg]` alternatives
/// (see `a_rust_cfg_disjoint_owner_binding_proves_no_external_identity`).
/// Nothing is published from an owner name the file itself leaves open.
///
/// A binder is read where its `use` declaration is in scope, not wherever the
/// file happens to spell the name: see
/// [`rust_import_binder_visible_at_byte`].
fn expand_rust_imported_external_callee(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    _callee_text: &str,
    site: Option<&ExternalCalleeSite<'_>>,
) -> Option<ImportedExternalCallee> {
    let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
    let factory = native_points::RustDefinitionOperationFactory::new(analyzer, &cancellation)?;
    let mut operation = match factory.open(&cancellation).ok()? {
        brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        _ => return None,
    };
    expand_rust_imported_external_callee_with_operation(
        analyzer,
        file,
        _callee_text,
        site,
        &factory,
        &mut operation,
    )
}

pub(crate) fn expand_rust_imported_external_callee_with_operation<
    'analyzer,
    'factory,
    'selection,
>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    _callee_text: &str,
    site: Option<&ExternalCalleeSite<'_>>,
    operation_factory: &'factory native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
) -> Option<ImportedExternalCallee> {
    expand_rust_imported_external_callee_attempt_with_operation(
        analyzer,
        file,
        _callee_text,
        site,
        operation_factory,
        operation,
    )
    .into_value()
}

pub(crate) fn expand_rust_imported_external_callee_attempt_with_operation<
    'analyzer,
    'factory,
    'selection,
>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    _callee_text: &str,
    site: Option<&ExternalCalleeSite<'_>>,
    operation_factory: &'factory native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
) -> std_types::RustProofAttempt<ImportedExternalCallee> {
    let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
    std_types::completed_proof(Some(&cancellation), || {
        let site = site?;
        let callee = external_calls::call_path(site.tree, site.callee_start_byte)?;
        // The definition resolver owns receiver-call proofs.
        if callee.kind() == "field_expression" {
            return None;
        }
        let call_site = ResolvedReferenceSite {
            path: String::new(),
            text: String::new(),
            range: Range {
                start_byte: callee.start_byte(),
                end_byte: callee.end_byte(),
                start_line: callee.start_position().row + 1,
                end_line: callee.end_position().row + 1,
            },
            focus_start_byte: callee.start_byte(),
            focus_end_byte: callee.end_byte(),
        };
        if let Some((proof, identity)) =
            external_calls::exact_rust_external_type_call_with_operation(
                analyzer,
                file,
                site.source,
                site.tree,
                &call_site,
                operation_factory,
                &mut *operation,
                Some(&cancellation),
            )
        {
            return Some(ImportedExternalCallee::proven(proof, identity));
        }
        let mut expanded: Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> =
            None;
        if let Some(segments) = brokk_bifrost_rust::graph_support::rust_path_segments(callee) {
            // The leading written segment names the binder. A single-segment callee
            // is its own binder (`use foo::bar; bar()`).
            let (written_member, written_owner) = segments.split_last()?;
            let binding_node = written_owner.first().unwrap_or(written_member);
            let binding =
                brokk_bifrost_rust::declarations::rust_node_text(*binding_node, site.source);
            let written_member =
                brokk_bifrost_rust::declarations::rust_node_text(*written_member, site.source);
            if analyzer.import_analysis_provider_for_file(file).is_some() {
                let scope = AnalyzerQueryScope::new(analyzer);
                let imports =
                    std_types::selected_import_infos(analyzer, operation, file, &cancellation)?;
                for import in &imports {
                    let binding_name = rust_import_binding_name(import);
                    if binding_name.is_glob()
                        || !binding_name.named().is_some_and(|name| {
                            brokk_bifrost_rust::imports::rust_binding_name_matches(name, binding)
                        })
                    {
                        continue;
                    }
                    // Only an owner path can carry the qualification; a `use foo;`
                    // binder has nothing to expand, exactly as before.
                    let path = match import.path.as_ref() {
                        Some(path) if path.segments.len() >= 2 => path,
                        _ => continue,
                    };
                    // The binder is evidence only where the `use` declaration is in
                    // scope. A module-owned `use` binds its name inside that module's
                    // lexical extent -- which is exactly what `lexical_scopes` records --
                    // so a binder written in a sibling module names nothing at this call,
                    // and letting it answer would either veto a real identity or, when it
                    // binds the same path, prove an identity the call never wrote.
                    if !rust_import_binder_visible_at_byte(path, site.callee_start_byte) {
                        continue;
                    }
                    // A single-segment callee takes the member from the binder's own
                    // path. A longer callee appends its middle segments after the
                    // binder's target: `net::TcpStream::connect` with `net` bound to
                    // `std::net` owns `std::net::TcpStream`.
                    let (owner_components, member): (Vec<String>, &str) =
                        if written_owner.is_empty() {
                            let (member, owner_components) = path.segments.split_last()?;
                            (owner_components.to_vec(), member.as_str())
                        } else {
                            let appended = written_owner.iter().skip(1).map(|node| {
                                brokk_bifrost_rust::declarations::rust_node_text(*node, site.source)
                                    .to_owned()
                            });
                            (
                                path.segments.iter().cloned().chain(appended).collect(),
                                written_member,
                            )
                        };
                    // A binder that names the local owner but proves no external identity
                    // is evidence against the expansion, so it ends the whole answer
                    // rather than extending the loop.
                    let proof = rust_import_binder_external_callee(
                        analyzer,
                        scope.token(),
                        file,
                        site,
                        import,
                        &imports,
                        member,
                        &owner_components,
                        operation_factory,
                        &mut *operation,
                        Some(&cancellation),
                    )?;
                    match &expanded {
                        Some(existing) if *existing == proof => {}
                        Some(_) => return None,
                        None => expanded = Some(proof),
                    }
                }
            }
        }
        // The binder selected one callable in the activated model, so the call
        // carries that callable's exact proof and owner/member identity into the
        // common dispatch path rather than a spelling a later stage has to
        // re-interpret (#3484).
        expanded.map(|(proof, identity)| ImportedExternalCallee::proven(proof, identity))
    })
}

/// Whether the parser-derived `use` declaration behind `path` binds a name
/// that is in scope at `call_start_byte`.
///
/// `lexical_scopes` records the containers the parser found around the
/// declaration, outermost first, so a binder is in scope exactly where the
/// innermost recorded container reaches. A module-owned `use` therefore names
/// something only inside that module's body (and the modules nested in it,
/// which is why containment, not equality, is the test). A top-level `use`
/// records no container to constrain it and is visible anywhere in the file.
///
/// Without this filter a `use` written inside a sibling inline module answers
/// for calls in other modules, where the name it binds is not in scope: the
/// binder can then veto a real identity or, when it binds the same path, hand
/// a call an identity it never wrote (#3484).
fn rust_import_binder_visible_at_byte(path: &StructuredImportPath, call_start_byte: usize) -> bool {
    path.lexical_scopes
        .iter()
        .all(|scope| scope.start_byte <= call_start_byte && call_start_byte < scope.end_byte)
}

fn open_declared_rust_route_recipe(
    analyzer: &dyn IAnalyzer,
    use_inventory: &mut dyn FnMut(&brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>),
) -> Result<(), brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause> {
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;
    let rust = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
        analyzer,
    )
    .ok_or(UnavailableCause::ValidationFailed)?;
    let cancellation = CancellationToken::default();
    match rust.open_selected_rust_inventory(&cancellation) {
        Ok(SelectedResolutionMountInventoryOutcome::Ready(inventory)) => {
            use_inventory(&inventory);
            Ok(())
        }
        Ok(SelectedResolutionMountInventoryOutcome::Cancelled) => Err(UnavailableCause::Cancelled),
        Ok(SelectedResolutionMountInventoryOutcome::Unavailable(reason)) => {
            Err(UnavailableCause::Failed(format!("{reason:?}").into()))
        }
        Ok(SelectedResolutionMountInventoryOutcome::Stale(reason)) => {
            Err(UnavailableCause::Failed(format!("{reason:?}").into()))
        }
        Err(error) => Err(UnavailableCause::Failed(error.to_string().into())),
    }
}

impl LanguageSupport for RustSupport {
    fn receiver_type_parameter_dependency(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        receiver: Range,
    ) -> brokk_bifrost_analysis::analyzer::languages::ReceiverTypeParameterDependency {
        std_types::receiver_type_parameter_dependency(analyzer, file, receiver)
    }

    fn identity_receiver_lookup(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::structural::identity::ReceiverLookupPolicy {
        brokk_bifrost_analysis::analyzer::structural::identity::ReceiverLookupPolicy::RustUsesTraits
    }

    fn policy_lowering_identity(
        &self,
        _models: Option<
            &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot,
        >,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::service::SemanticAdapterIdentity> {
        Some(
            brokk_bifrost_analysis::analyzer::semantic::service::ProgramSemanticsLowerer::identity(
                &semantic::RustSemanticLowerer,
            ),
        )
    }

    fn register_derivation_kinds(
        &self,
        derivations: &brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations,
    ) {
        route_kinds::register(derivations);
        derivations
            .register_declared_route_recipe_opener(Language::Rust, open_declared_rust_route_recipe);
    }
    fn admit_selected_tuple_binding(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        candidate: &brokk_bifrost_analysis::analyzer::semantic::GuardedPatternProjection,
        snapshot: Option<
            &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot,
        >,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::languages::SelectedTupleBinding,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        pattern_admission::admit_selected_tuple_binding(
            workspace, procedure, candidate, snapshot, request,
        )
    }
    fn fresh_logical_instance(
        &self,
        node: tree_sitter::Node<'_>,
        _allocation: &brokk_bifrost_analysis::analyzer::semantic::AllocationSite,
        _artifact: &brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact,
        _source: &str,
    ) -> brokk_bifrost_analysis::analyzer::languages::FreshEndpoint {
        use brokk_bifrost_analysis::analyzer::languages::FreshEndpoint;
        if node.kind() != "struct_expression" || node.has_error() {
            return FreshEndpoint::Unknown("not an exact Rust struct construction");
        }
        let Some(body) = node.child_by_field_name("body") else {
            return FreshEndpoint::Unknown("Rust struct body unavailable");
        };
        let mut cursor = body.walk();
        if body
            .named_children(&mut cursor)
            .any(|child| child.kind() == "base_field_initializer")
        {
            return FreshEndpoint::Unknown("Rust struct update may retain another referent");
        }
        FreshEndpoint::Proven
    }

    fn direct_formal_referent_at_call(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        caller: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        call: &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
        argument_ordinal: u32,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Option<u32>, brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError>
    {
        semantic::direct_formal_referent_at_call(workspace, caller, call, argument_ordinal, request)
    }

    fn source_callable_application(
        &self,
        owner: tree_sitter::Node<'_>,
        scope_step: &mut dyn FnMut() -> bool,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::SourceCallableApplication> {
        (scope_step() && owner.kind() == "closure_expression").then_some(
            brokk_bifrost_analysis::analyzer::languages::SourceCallableApplication::NoReceiver,
        )
    }

    fn source_callable_initializer_matches(
        &self,
        declaration: tree_sitter::Node<'_>,
        name: &Range,
        callable: &Range,
        scope_step: &mut dyn FnMut() -> bool,
    ) -> bool {
        scope_step()
            && declaration.kind() == "let_declaration"
            && declaration
                .child_by_field_name("pattern")
                .is_some_and(|node| {
                    scope_step()
                        && node.start_byte() == name.start_byte
                        && node.end_byte() == name.end_byte
                })
            && declaration
                .child_by_field_name("value")
                .is_some_and(|node| {
                    scope_step()
                        && node.start_byte() == callable.start_byte
                        && node.end_byte() == callable.end_byte
                })
    }

    fn requires_selected_receiver_witness(&self) -> bool {
        true
    }

    fn replay_owned_lookup(
        &self,
        head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        kind: brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupKind,
        question: &brokk_bifrost_analysis::analyzer::LookupQuestion,
        row_budget: usize,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest> {
        use brokk_bifrost_analysis::analyzer::store::rust_copy_absence::RustCopyAbsence;

        let analyzer = head.analyzer();
        let store = head.store()?;
        let snapshots = analyzer.selected_workspace_snapshots_for_reads()?;
        let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
        if kind
            != brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupKind::RustCopyAbsence
        {
            let before = analyzer.workspace_content_identity()?;
            let readiness = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(analyzer)?
                .inner
                .active_query_request_memo::<brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryReadinessMemo>()
                .unwrap_or_default();
            let answer = store
                .rust_inventory_answer(
                    snapshots.as_ref(),
                    kind,
                    question,
                    &cancellation,
                    row_budget,
                    &readiness,
                )
                .ok()
                .flatten()?;
            if cancellation.is_cancelled() || analyzer.workspace_content_identity()? != before {
                return None;
            }
            return Some(answer.digest);
        }
        let mut cut = false;
        match store
            .rust_copy_absence_answer(
                snapshots.as_ref(),
                question,
                &cancellation,
                row_budget,
                &mut cut,
                || {},
            )
            .ok()??
            .0
        {
            RustCopyAbsence::Absent { digest } => Some(digest),
            RustCopyAbsence::Unknown(_) => None,
        }
    }

    fn ownership_class_of_call_result(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        callee: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::languages::SelectedCallResultOwnership,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        semantic::selected_call_result_ownership(workspace, callee, request)
    }

    fn ownership_class_of_formal(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        callee: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        ordinal: u32,
        actual: brokk_bifrost_analysis::analyzer::semantic::ValueId,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::languages::SelectedCallResultOwnership,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        semantic::selected_formal_ownership(workspace, callee, ordinal, actual, request)
    }

    fn identity_conversion_between_formals(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        source: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        source_ordinal: u32,
        target: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        target_ordinal: u32,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::languages::SelectedIdentityConversion,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        semantic::selected_formal_identity_conversion(
            workspace,
            source,
            source_ordinal,
            target,
            target_ordinal,
            request,
        )
    }

    fn local_callable_dispatch(&self) -> bool {
        true
    }

    fn build_model_provider(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::languages::BuildModelProvider> {
        Some(&topology::CARGO_BUILD_MODEL)
    }

    fn certifies_caller_inventory(&self) -> bool {
        true
    }

    fn intrinsic_call(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        call: &brokk_bifrost_analysis::analyzer::semantic::ir::CallSiteHandle,
    ) -> Result<
        Option<brokk_bifrost_analysis::analyzer::semantic::IntrinsicCall>,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        use self::std_types::RustStdBuiltinTransfer;
        use brokk_bifrost_analysis::analyzer::semantic::{IntrinsicCall, IntrinsicTransfer};
        Ok(
            crate::analyzer::semantic::workspace_oracle::rust::rust_std_builtin_call(
                workspace, call,
            )?
            .map(|builtin| IntrinsicCall {
                operation: builtin.operation,
                transfer: match builtin.transfer {
                    RustStdBuiltinTransfer::ReceiverToResult => IntrinsicTransfer::ReceiverToResult,
                    RustStdBuiltinTransfer::ArgumentToResult => IntrinsicTransfer::ArgumentToResult,
                    RustStdBuiltinTransfer::FreshResult => IntrinsicTransfer::FreshResult,
                },
                model_namespace: "bifrost.rust-std",
                content_domain: b"bifrost-rust-std-builtin/v1\0",
            }),
        )
    }

    fn intrinsic_call_has_direct_receiver(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        call: &brokk_bifrost_analysis::analyzer::semantic::ir::CallSiteHandle,
    ) -> Result<bool, brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError> {
        crate::analyzer::semantic::workspace_oracle::rust::rust_std_direct_string_receiver(
            workspace, call,
        )
    }

    fn intrinsic_format_result(
        &self,
        identity: &brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity,
    ) -> bool {
        matches!(
            (identity.owner_fqn(), identity.member()),
            ("std" | "core" | "alloc", "format" | "format_args") | ("alloc.fmt", "format")
        )
    }

    fn intrinsic_complete_target(
        &self,
        identity: &brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity,
    ) -> bool {
        matches!(
            (identity.owner_fqn(), identity.member()),
            (
                "std" | "core" | "alloc",
                "format"
                    | "format_args"
                    | "print"
                    | "println"
                    | "eprint"
                    | "eprintln"
                    | "write"
                    | "writeln"
                    | "panic"
            ) | ("alloc.fmt", "format")
                | ("core.panicking", "panic_fmt" | "assert_failed")
                | ("std.io.stdio", "_print" | "_eprint")
                | ("core", "matches")
                | ("alloc", "vec")
        )
    }

    fn taint_uses_call_site_evidence(&self) -> bool {
        true
    }

    fn lexical_definitions_are_authoritative(&self) -> bool {
        false
    }

    fn branch_body_reference_site(
        &self,
        node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::ReferenceSite> {
        use brokk_bifrost_analysis::analyzer::structural::branch_relations::{
            ReferenceKind, ReferenceSite,
        };
        if node.kind() != "identifier"
            || node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "scoped_identifier" | "scoped_type_identifier"
                )
            })
        {
            return None;
        }
        let (focus, kind) = (node, ReferenceKind::Field);
        Some(ReferenceSite {
            range: (focus.start_byte(), focus.end_byte()),
            kind,
        })
    }

    fn supports_selected_resolution_overlays(&self) -> bool {
        true
    }

    fn closed_receiver_summary_closes_external_body(&self) -> bool {
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    fn probe_assignment_value(
        &self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
        request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Option<
            brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
                brokk_bifrost_analysis::analyzer::native_points::NativeAssignmentValueProbe,
            >,
        >,
        String,
    > {
        use brokk_bifrost_analysis::analyzer::native_points::adapt_assignment_value_probe;

        use brokk_bifrost_analysis::analyzer::native_points::map_bounded;

        use brokk_bifrost_analysis::analyzer::native_points::unavailable_assignment_value_probe;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
        use brokk_bifrost_core::path_utils::rel_path_string;
        let analyzer = query.analyzer;
        let site = query.site;
        let budget = query.budget;
        let language = Language::Rust;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

        let factory = crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
            analyzer,
            cancellation,
        )
        .ok_or("assignment-value probe has no authoritative Rust operation factory")?;
        let mut operation = match factory
            .open(cancellation)
            .map_err(|error| error.to_string())?
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return Ok(Some(BoundedResolution::Cancelled {
                    work: ReceiverAnalysisWork::default(),
                }));
            }
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Err(format!(
                    "assignment-value operation unavailable: {reason:?}"
                ));
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Err(format!("assignment-value operation stale: {reason:?}"));
            }
        };
        let locator = SelectedSemanticLocator::for_reference_range_in_namespace(
            "rust",
            rel_path_string(&request.file),
            site.focus_start_byte,
            site.focus_end_byte,
            ResolutionNamespace::Value,
        );
        let answer = operation
            .resolve_rust_assignment_value_bounded(
                request.file.rel_path(),
                &locator,
                budget,
                cancellation,
            )
            .map_err(|error| error.to_string())?;
        Ok(Some(map_bounded(answer, |outcome| {
            match outcome {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) => adapt_assignment_value_probe(site, language, answer),
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                unavailable_assignment_value_probe(
                    site,
                    "native_reference_unavailable",
                    "assignment-value probe has no exact selected reference".into(),
                )
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                unavailable_assignment_value_probe(
                    site,
                    "native_unavailable",
                    format!("{reason:?}"),
                )
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                unavailable_assignment_value_probe(site, "native_stale", format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                unavailable_assignment_value_probe(
                    site,
                    "native_cancelled",
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_completion_details(&completion, |_| brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::public_diagnostic_identity("semantic", None, None, None)),
                )
            }
        }
        })))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn assignment_value_type_spelling(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::AssignmentValueTypeSpelling> {
        use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupDiagnostic;
        Some(|spelling, value, diagnostics| {
            let ty = value.ty();
            // The Rust renderer spells total depth as references. Do not turn
            // raw-pointer or mixed indirection into reference evidence.
            if ty.indirection() != ty.reference_indirection() {
                diagnostics.push(TypeLookupDiagnostic {
                    kind: "unsupported_type_indirection".into(),
                    message: format!(
                        "unsupported Rust assignment-value indirection for {spelling:?}: {value:?}"
                    ),
                });
                return None;
            }
            Some(native_points::render_type_spelling(
                spelling,
                value,
                diagnostics,
            ))
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    fn prepared_syntax_for_test(
        &self,
        delegate: &brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(
            delegate.analyzer(),
        );
        delegate
            .as_any()
            .downcast_ref::<RustAnalyzer>()?
            .prepared_syntax(scope.token(), file)
    }

    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // Rust classifies paths that leave the workspace against the activated
        // exact Cargo API packs (#1625), and the semantic-model overlay and the
        // retained Cargo dependency evidence belong to the dispatching
        // analyzer, not to the delegate. Passing `workspace` is what lets a path
        // into an indexed dependency resolve instead of reporting nothing
        // known.
        Some(diagnostics::collect_rust_semantic_diagnostics(
            workspace, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_rust::RustKnowledge
    }

    fn build_analyzer(
        &self,
        project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
        config: brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        store_context: brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate,
        brokk_bifrost_analysis::analyzer::store::StoreError,
    > {
        Ok(
            brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate::new(
                RustAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn caller_sites_compiled(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        sites: &[brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Vec<bool>> {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_access::RustBlobActivity;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;
        let mut compiled = vec![true; sites.len()];
        let Some(factory) =
            native_points::RustDefinitionOperationFactory::new(workspace.analyzer(), cancellation)
        else {
            return Ok(compiled);
        };
        let SelectedResolutionOperationOpenOutcome::Ready(operation) =
            factory.open(cancellation)?
        else {
            return Ok(compiled);
        };
        // Resolve only the retained inventory files. This map dies with the
        // caller query; it never indexes or retains the whole workspace.
        let mut files = brokk_bifrost_core::hash::HashMap::default();
        let mut blobs = Vec::with_capacity(sites.len());
        for site in sites {
            let blob = if site.file.language() != Language::Rust
                || site.file.root() != workspace.analyzer().project().root()
            {
                -1
            } else if let Some(blob) = files.get(&site.file) {
                *blob
            } else {
                let path = brokk_bifrost_core::path_utils::rel_path_string(&site.file);
                let blob = operation
                    .mount_table()
                    .blob_for_path("rust", &path)?
                    .unwrap_or(-1);
                files.insert(&site.file, blob);
                blob
            };
            blobs.push(blob);
        }
        // One statement for this caller request, including duplicate blobs.
        let activity = operation.rust_blob_placement_activity(&blobs)?;
        assert_eq!(activity.len(), sites.len());
        for ((expected, (actual, activity)), compiled) in
            blobs.iter().zip(activity).zip(&mut compiled)
        {
            debug_assert_eq!(*expected, actual);
            *compiled = activity != RustBlobActivity::Inactive;
        }
        Ok(compiled)
    }

    fn prefetch_selected_call_targets(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        files: &[(
            brokk_bifrost_core::analyzer::model::ProjectFile,
            Vec<brokk_bifrost_core::analyzer::model::Range>,
        )],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        snapshot: Option<
            std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot>,
        >,
    ) -> Option<
        brokk_bifrost_analysis::analyzer::store::Result<
            Vec<(
                brokk_bifrost_core::analyzer::model::ProjectFile,
                brokk_bifrost_analysis::analyzer::usages::call_relations::PrefetchedCallTargets,
            )>,
        >,
    > {
        Some(prefetch::prefetch_selected_files(
            workspace,
            files,
            cancellation,
            snapshot,
        ))
    }

    fn prefetch_reverse_call_targets(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        sites: &[brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
        snapshot: Option<
            std::sync::Arc<brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot>,
        >,
    ) -> Option<
        brokk_bifrost_analysis::analyzer::store::Result<
            brokk_bifrost_core::hash::HashMap<
                brokk_bifrost_core::analyzer::model::ProjectFile,
                brokk_bifrost_analysis::analyzer::usages::call_relations::PrefetchedCallFile,
            >,
        >,
    > {
        Some(prefetch::prefetch_caller_files(
            workspace,
            sites,
            cancellation,
            snapshot,
        ))
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn bind_generated_symbols(
        &self,
        file: &ProjectFile,
        source: &str,
        symbols: &mut [crate::analyzer::semantic_model::SemanticModelSymbol],
    ) {
        // LanguageSupport has no analyzer owner here; keep this call uncached.
        let caches = brokk_bifrost_rust::crate_naming::RustCrateNamingCaches::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::retain_nothing(),
        );
        generated_model::bind_generated_functions(&caches, file, source, symbols);
    }

    fn call_qualifying_type(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        sources: &brokk_bifrost_analysis::analyzer::usages::call_conversion::CallConversionCache,
        file: &ProjectFile,
        source: &str,
        call: tree_sitter::Node<'_>,
    ) -> Result<
        Option<brokk_bifrost_analysis::analyzer::usages::call_conversion::RustQualifyingTypeProof>,
        brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionUnknown,
    > {
        call_conversion::call_qualifying_type(analyzer, sources, file, source, call)
    }

    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver>
{
        Some(&call_conversion::CALL_ARGUMENT_CONVERSION_PROVER)
    }

    fn focus_resolves_lexically(&self, focus: tree_sitter::Node<'_>) -> bool {
        matches!(
            brokk_bifrost_rust::field_roles::classify_rust_field_name(focus),
            brokk_bifrost_rust::field_roles::RustFieldNameRole::Other
        )
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<RustAnalyzer>(analyzer)
            .map(|rust| rust.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<RustAnalyzer, _>(
            analyzer,
            |rust| rust.signatures_limited(unit, limit),
        )
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<RustAnalyzer>(analyzer).map(|rust| rust.ranges_limited(unit, limit))
    }

    fn procedure_drops_run_no_user_code(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &Arc<str>,
        callable: std::ops::Range<usize>,
    ) -> bool {
        std_types::procedure_drops_run_no_user_code(analyzer, file, source, callable)
    }

    fn residual_conversion_runs_no_user_code(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &Arc<str>,
        conversion: std::ops::Range<usize>,
    ) -> bool {
        std_types::residual_conversion_runs_no_user_code(analyzer, file, source, conversion)
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<RustAnalyzer>(
            analyzer,
        )
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Rust
    }

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&dependency_packs::CargoDependencyResolver)
    }

    fn warm_usage_facts(&self, analyzer: &dyn IAnalyzer) {
        if let Some(rust) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            crate::analyzer::RustAnalyzer,
        >(analyzer)
        {
            // The catch-up issues per-file store queries that are only cheap
            // under request-scoped memoization; without a scope each lookup
            // re-hydrates (observed ~65s instead of ~3.5s on the Bifrost
            // workspace).
            let _scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
            rust.warm_usage_facts();
        }
    }

    fn usage_facts_ready(&self, analyzer: &dyn IAnalyzer) -> bool {
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(analyzer)
            .is_none_or(|rust| rust.rust_usage_facts_ready())
    }

    fn usage_facts_warm(&self, analyzer: &dyn IAnalyzer) -> bool {
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(analyzer)
            .is_none_or(|rust| rust.rust_usage_facts_warm())
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &RUST_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Native(
            &native_graph::RustNativeWorkspaceGraphProvider,
        )
    }

    fn definition_associated_navigation_targets(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        candidate: brokk_bifrost_core::analyzer::model::CodeUnit,
        operation: brokk_bifrost_analysis::navigation::NavigationOperation,
    ) -> Vec<brokk_bifrost_analysis::analyzer::usages::get_definition::NavigationTarget> {
        crate::analyzer::usages::get_definition::rust::associated_navigation_targets(
            analyzer, candidate, operation,
        )
    }

    fn definition_batch_resolver<'a>(
        &self,
        analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<
        Box<
            dyn brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchResolver<
                    'a,
                > + 'a,
        >,
    > {
        crate::analyzer::usages::get_definition::rust::definition_batch_resolver(
            analyzer,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_dispatch<'a>(
        &self,
        analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<'a, '_>,
        request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
        source: &std::sync::Arc<str>,
        tree: &Option<tree_sitter::Tree>,
        site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        go_session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> std::ops::ControlFlow<
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    > {
        crate::analyzer::usages::get_definition::rust::resolve_definition_dispatch_entry(
            analyzer,
            token,
            context,
            request,
            source,
            tree,
            site,
            operation,
            cancellation,
            go_session,
        )
    }

    fn definition_call_reference_candidate(&self, node: tree_sitter::Node<'_>) -> bool {
        crate::analyzer::rust::rust_call_reference_candidate(node)
    }

    fn definition_boundary_evidence(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        _file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        name: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
        Some((|| {
            // Rust reads the same pair, resolved through the shared crate
            // identity so a trace, a definition, and a diagnostic classify one
            // crate path identically. A path is spelled with `::` and a pack
            // records it dotted, and a Cargo rename is published as an alias,
            // so the written spelling is the lookup key either way. The lookup
            // is gated on its crate root, so a name reaching a crate the
            // workspace renamed away is unindexed here exactly as it is in
            // diagnostics (#1795).
            let overlay = analyzer.semantic_model_overlay();
            let crates =
                crate::analyzer::rust::crate_identity::RustOverlayCrates::new(overlay.as_deref());
            if let Some(symbol) = crates.referenceable_symbol(name) {
                return (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone()));
            }
            let declared = analyzer
                .dependency_discovery_evidence(Language::Rust)
                .is_some_and(|evidence| {
                    evidence.truncated() || evidence.declares_module_path(name)
                });
            if declared {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        })())
    }

    fn call_relation_provider(
        &self,
    ) -> Option<
        &'static dyn brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider,
    > {
        Some(&native_call_projection::RustNativeCallRelations)
    }

    fn rename_provider(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::rename::RenameProvider> {
        Some(&native_rename::RustNativeRenameProvider)
    }

    fn selected_inverse_reference_provider(
        &self,
    ) -> Option<
        &'static dyn brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedInverseReferenceProvider,
    >{
        Some(&selected_shadow::RustNativeSelectedInverseProvider)
    }

    fn expand_imported_external_callee(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_text: &str,
        site: Option<&ExternalCalleeSite<'_>>,
    ) -> Result<
        Option<ImportedExternalCallee>,
        brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause,
    > {
        Ok(expand_rust_imported_external_callee(
            analyzer,
            file,
            callee_text,
            site,
        ))
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&RUST_USAGE_STRATEGY),
            bulk: None,
        }
    }

    fn dead_code_needs_precise_scan(&self, analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
        resolve_analyzer::<RustAnalyzer>(analyzer).is_some_and(|rust| {
            (candidate.is_function() || candidate.is_field() || rust.is_type_alias(candidate))
                && rust.parent_of(candidate).is_some()
        })
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&RustSupport)
    }

    fn refine_selector_call_target(
        &self,
        lookup: &mut brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _source: &str,
        _tree: &tree_sitter::Tree,
        _callee_range: &Range,
        _cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        _member_selection: Option<
            &brokk_bifrost_analysis::analyzer::semantic::DeferredMemberSelection,
        >,
    ) {
        use brokk_bifrost_analysis::analyzer::semantic::ReceiverOwnerRelation;
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
        let Some(evidence) = lookup.source_member_evidence.as_deref() else {
            return;
        };
        if lookup.status != Some(DefinitionLookupStatus::Resolved) || lookup.targets.len() != 1 {
            return;
        }
        let associated: Vec<_> = evidence
            .iter()
            .filter(|row| row.definition == lookup.targets[0].definition)
            .collect();
        let [first, rest @ ..] = associated.as_slice() else {
            return;
        };
        if rest.iter().all(|row| {
            row.receiver_owner_relation == first.receiver_owner_relation
                && row.receiver_preparation == first.receiver_preparation
        }) {
            lookup.receiver_owner_relation = first.receiver_owner_relation;
            if first.receiver_owner_relation == ReceiverOwnerRelation::Direct {
                lookup.member_receiver_preparation = first.receiver_preparation;
            }
        }
    }

    fn rewrite_paths(
        &self,
        analyzer: &dyn IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        generation: u64,
        request: &mut brokk_bifrost_analysis::analyzer::structural::rewrite_paths::RewritePathRequest<'_>,
    ) -> brokk_bifrost_analysis::analyzer::structural::rewrite_paths::FileRewritePaths {
        rust_import_alias_paths(analyzer, token, file, generation, request)
    }

    fn value_type_barrier_context<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Option<Box<dyn crate::analyzer::semantic::ValueTypeBarrierContext + 'a>>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        value_type_barriers::open(analyzer, cancellation).map(Some)
    }

    fn value_type_barrier(
        &self,
        _analyzer: &dyn IAnalyzer,
        observation: &crate::analyzer::semantic::BarrierObservation,
        predicate: crate::analyzer::semantic::ValueTypePredicate,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::ValueTypeBarrierDecision,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        request.classify_value_type_barrier(observation, predicate)
    }

    fn observed_value_type(
        &self,
        _analyzer: &dyn IAnalyzer,
        observation: &brokk_bifrost_analysis::analyzer::semantic::BarrierObservation,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::semantic::ObservedValueType,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        use brokk_bifrost_analysis::analyzer::semantic::{
            ObservedValueType, ValueTypeBarrierReason,
        };
        let Some(context) = request.value_type_barrier_context() else {
            return Ok(ObservedValueType::Undecided(
                ValueTypeBarrierReason::UnavailableObservation,
            ));
        };
        context.observed_type(observation, request)
    }
}

impl StructuralReceiverResolver for RustSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        native_points::resolve_rust_type_bounded(query)
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        native_points::resolve_rust_definition_bounded(query)
    }
}

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for RustAnalyzer {
    fn analyzer(&self) -> &dyn IAnalyzer {
        self
    }

    fn program_semantics_provider(
        &self,
    ) -> &dyn crate::analyzer::semantic::ProgramSemanticsProvider {
        self
    }

    fn clone_with_project(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(RustAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(RustAnalyzer::clone_for_index_warm(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        IAnalyzer::type_hierarchy_provider(self)
    }

    fn type_alias_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider> {
        IAnalyzer::type_alias_provider(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn update(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(IAnalyzer::update_with_listing(self, changed_files, listing))
    }

    fn listing_changed(
        &self,
        listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
    ) -> bool {
        self.inner.rust_listing_changed(listing).unwrap_or(true)
    }

    fn update_all_with_progress(
        &self,
        progress: Option<BuildProgress>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(RustAnalyzer::update_all_with_progress(self, progress))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(
        &self,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(Clone::clone(self))
    }
}

pub(super) mod dependency_packs {

    use crate::analyzer::semantic_model::DependencyDiscoveryOutcome;

    use crate::analyzer::semantic_model::DependencyPackAdapter;

    use crate::analyzer::semantic_model::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver;

    use crate::analyzer::semantic_model::DependencyResolverBounds;

    use brokk_bifrost_analysis::analyzer::workspace::READS_FILES_ONLY;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;

    use crate::analyzer::RustDependencyPackAdapter;

    use crate::analyzer::resolve_rust_semantic_pack_dependencies;

    pub(crate) struct CargoDependencyResolver;

    impl DependencyResolver for CargoDependencyResolver {
        fn is_discovery_candidate(&self, rel_path: &std::path::Path) -> bool {
            super::file_dependency_evidence::cargo_input(rel_path)
                || super::toolchain_evidence::rust_toolchain_input(rel_path)
        }

        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &RustDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            &["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
        }

        fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
            READS_FILES_ONLY
        }

        fn resolve(
            &self,
            config: &AnalyzerConfig,
            project: &dyn Project,
            _digests: &brokk_bifrost_core::content_digest::ContentDigestCache,
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            resolve_rust_semantic_pack_dependencies(&config.rust, project, limits, cancellation)
        }
    }

    #[cfg(test)]
    #[test]
    fn cargo_discovery_membership_tracks_only_candidate_paths() {
        use std::path::PathBuf;
        let resolver = CargoDependencyResolver;
        let same = [0u8; 32];
        let check = |path: &str| {
            brokk_bifrost_analysis::analyzer::semantic_model::discovery_membership_unchanged(
                &resolver,
                &[PathBuf::from(path)],
                &[],
                &same,
                &same,
            )
        };
        assert!(check("src/new.rs"));
        assert!(!check("crates/x/Cargo.toml"));
        assert!(!check("rust-toolchain.toml"));
    }
}

/// The `rust_import_alias` domain over one Rust file.
fn rust_import_alias_paths(
    analyzer: &dyn IAnalyzer,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    file: &ProjectFile,
    generation: u64,
    request: &mut brokk_bifrost_analysis::analyzer::structural::rewrite_paths::RewritePathRequest<
        '_,
    >,
) -> brokk_bifrost_analysis::analyzer::structural::rewrite_paths::FileRewritePaths {
    use brokk_bifrost_analysis::analyzer::structural::rewrite_paths::FileRewritePaths;

    use brokk_bifrost_analysis::analyzer::structural::rewrite_paths::LineIndex;

    use brokk_bifrost_analysis::analyzer::structural::rewrite_paths::RewritePathCompleteness;

    use brokk_bifrost_analysis::analyzer::structural::rewrite_paths::RewritePathIncompleteReason;
    use brokk_bifrost_core::analyzer::structural::rewrite_path::{
        RewriteDomainKind, RewriteOrigin, RewriteOutcome, RewritePath, RewriteTrace,
    };
    use brokk_bifrost_rust::graph_support::resolve_module_package_traced_while;
    let domain = RewriteDomainKind::RustImportAlias;
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
    let Some(rust) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::RustAnalyzer,
    >(analyzer) else {
        return FileRewritePaths::incomplete(
            vec![RewritePathIncompleteReason::NoDomainAnalyzer(domain)],
            generation,
        );
    };
    let Some(source) = analyzer.indexed_source(file) else {
        return FileRewritePaths::incomplete(
            vec![RewritePathIncompleteReason::NoIndexedSource],
            generation,
        );
    };
    let lines = LineIndex::build(&source);

    let mut reasons = Vec::new();
    let mut paths = Vec::new();
    let mut seen_origins: HashSet<String> = HashSet::default();
    for import in brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider::import_info_of(
        rust, token, file,
    ) {
        if request.cancellation.is_cancelled() {
            reasons.push(RewritePathIncompleteReason::Cancelled);
            break;
        }
        // A wildcard binds no single name, so it has no root the alias rule
        // can rewrite, and the binder records no rewritable root for it.
        if import.is_wildcard {
            continue;
        }
        let (Some(local_name), Some(span)) = (import.local_name(), import.binder_span) else {
            continue;
        };
        if !seen_origins.insert(local_name.to_string()) {
            continue;
        }
        let mut trace = RewriteTrace::default();
        // The resolved name is not this consumer's output, but failure still
        // prevents a complete account of how the instrumented chase terminated.
        if let Err(error) = resolve_module_package_traced_while(
            rust,
            scope.token(),
            file,
            local_name,
            Some(&mut trace),
            &|| !request.cancellation.is_cancelled(),
        ) {
            use brokk_bifrost_rust::graph_support::{ReferenceContextError, RustCargoRouteError};
            reasons.push(match error {
                ReferenceContextError::CargoRoutes(RustCargoRouteError::Unavailable) => {
                    RewritePathIncompleteReason::CanonicalFactsUnavailable
                }
                ReferenceContextError::Interrupted
                | ReferenceContextError::CargoRoutes(RustCargoRouteError::Cancelled) => {
                    RewritePathIncompleteReason::Cancelled
                }
            });
            break;
        }
        let (declared_bound, steps, outcome) = trace.into_parts();
        // A specifier whose root no alias rewrites never engaged the domain,
        // so it is not a path through it.
        if steps.is_empty() {
            continue;
        }
        let outcome = outcome.unwrap_or(RewriteOutcome::ExceededBudget {
            explored: steps.len(),
        });
        paths.push(RewritePath {
            domain,
            origin: RewriteOrigin {
                file: file.clone(),
                specifier: local_name.to_string(),
                range: lines.range(span.start_byte, span.end_byte),
            },
            declared_bound,
            steps,
            outcome,
            generation,
        });
    }
    paths.sort_by_key(|path| {
        (
            path.origin.range.start_byte,
            path.origin.range.end_byte,
            path.origin.specifier.clone(),
        )
    });
    FileRewritePaths {
        paths,
        completeness: RewritePathCompleteness::from_reasons(reasons),
        generation,
    }
}

impl RustAnalyzer {
    fn recorded_rust_inventory(
        &self,
        kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind,
        name: &str,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows,
        RustCargoRouteError,
    > {
        use brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion;
        let question = LookupQuestion::Name {
            language: Some(Language::Rust),
            name: name.into(),
        };
        self.recorded_rust_inventory_question(kind, question)
    }

    fn recorded_rust_inventory_question(
        &self,
        kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind,
        question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryRows,
        RustCargoRouteError,
    > {
        use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
        use brokk_bifrost_analysis::analyzer::store::rust_inventory::RustInventoryReadinessMemo;
        let snapshots = self.inner.selected_workspace_snapshots();
        let cancellation = self.active_query_cancellation().unwrap_or_default();
        let readiness = self
            .inner
            .active_query_request_memo::<RustInventoryReadinessMemo>()
            .unwrap_or_default();
        let answer = self
            .store_result_or_unavailable(
                self.analyzer_store().rust_inventory_answer(
                    snapshots.as_ref(),
                    kind,
                    &question,
                    &cancellation,
                    usize::MAX,
                    &readiness,
                ),
                || format!("reading Rust inventory {kind:?} for {question:?}"),
            )?
            .ok_or(RustCargoRouteError::Unavailable)?;
        self.inner
            .record_read(ReadKey::lookup(kind, question, answer.digest));
        for reason in &answer.incomplete {
            self.inner.record_query_incomplete(
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(
                    format!("Rust inventory {kind:?} is incomplete: {reason:?}").into(),
                ),
            );
        }
        Ok(answer.rows)
    }
}

#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_rust::declarations::rust_package_name_with;
    use brokk_bifrost_rust::hierarchy::RustHierarchySourceFacts;
    use brokk_bifrost_rust::test_helpers::write_fixture_file as write;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11089: an unready Rust inventory surfaced as an Internal store error"
    )]
    fn recorded_inventory_readiness_replays_after_repair() {
        use brokk_bifrost_analysis::analyzer::store::rust_inventory::{
            RustInventoryIncomplete, RustInventoryReadinessMemo,
        };
        use brokk_bifrost_analysis::analyzer::{
            QueryReadIncomplete,
            read_ledger::{LookupKind, LookupQuestion},
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"partial\"\nversion = \"0.1.0\"\n",
        );
        write(&root, "src/lib.rs", "mod missing;\npub struct Local;\n");
        let analyzer = crate::test_support::rust_analyzer(&root);
        let kind = LookupKind::RustUnresolvedTraitImplInventory;
        let question = LookupQuestion::Name {
            language: Some(Language::Rust),
            name: "Marker".into(),
        };
        let memo = RustInventoryReadinessMemo::default();
        let read = |analyzer: &crate::RustAnalyzer| {
            analyzer
                .analyzer_store()
                .rust_inventory_answer(
                    &analyzer.inner.selected_workspace_snapshots(),
                    kind,
                    &question,
                    &Default::default(),
                    usize::MAX,
                    &memo,
                )
                .unwrap()
                .unwrap()
        };
        let before = read(&analyzer);
        assert!(
            before
                .incomplete
                .contains(&RustInventoryIncomplete::TopologyInventoryIncomplete),
            "{:?}",
            before.incomplete
        );
        {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            analyzer
                .recorded_rust_inventory_question(kind, question.clone())
                .unwrap();
            analyzer
                .recorded_rust_inventory_question(kind, question.clone())
                .unwrap();
            assert!(
                scope
                    .captured_read_incompleteness()
                    .iter()
                    .any(|reason| matches!(reason, QueryReadIncomplete::SemanticEvidenceGap(_)))
            );
            assert_eq!(read(&analyzer).digest, before.digest);
        }
        write(&root, "src/missing.rs", "pub struct Added;\n");
        let updated = analyzer.update(&BTreeSet::from([ProjectFile::new(root, "src/missing.rs")]));
        let after = read(&updated);
        assert!(after.incomplete.is_empty(), "{:?}", after.incomplete);
        assert_ne!(
            after.digest, before.digest,
            "repair must invalidate the recorded lookup"
        );
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(&updated);
        updated
            .recorded_rust_inventory_question(kind, question)
            .unwrap();
        assert!(scope.captured_read_incompleteness().is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10774: target-layout classification probed the live disk, not the generation's listing"
    )]
    fn target_layout_uses_the_generation_listing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"layout\"\nversion = \"0.1.0\"\n",
        );
        write(&root, "src/lib.rs", "pub struct Marker;\n");
        write(&root, "tests/check/helper.rs", "pub fn helper() {}\n");
        let helper = ProjectFile::new(root.clone(), "tests/check/helper.rs");
        let main = ProjectFile::new(root.clone(), "tests/check/main.rs");
        let analyzer = crate::test_support::rust_analyzer(&root);
        let before = brokk_bifrost_rust::imports::rust_crate_root_package_with(
            &analyzer.inner.adapter().naming,
            &helper,
        );
        write(&root, "tests/check/main.rs", "fn main() {}\n");
        analyzer.inner.adapter().naming.invalidate_all();
        assert_eq!(
            brokk_bifrost_rust::imports::rust_crate_root_package_with(
                &analyzer.inner.adapter().naming,
                &helper
            ),
            before
        );
        let updated = analyzer.update(&BTreeSet::from([main.clone()]));
        let after = brokk_bifrost_rust::imports::rust_crate_root_package_with(
            &updated.inner.adapter().naming,
            &helper,
        );
        assert_ne!(after, before);
        std::fs::remove_file(root.join(main.rel_path())).expect("remove target");
        updated.inner.adapter().naming.invalidate_all();
        assert_eq!(
            brokk_bifrost_rust::imports::rust_crate_root_package_with(
                &updated.inner.adapter().naming,
                &helper
            ),
            after
        );
        let removed = updated.update(&BTreeSet::from([main]));
        assert_eq!(
            brokk_bifrost_rust::imports::rust_crate_root_package_with(
                &removed.inner.adapter().naming,
                &helper
            ),
            before
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10774: ignored Cargo target main files were absent from naming authority"
    )]
    fn ignored_target_layout_is_captured() {
        for ignore in [".gitignore", ".bifrostignore"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            if ignore == ".gitignore" {
                git2::Repository::init(&root).unwrap();
            }
            write(
                &root,
                "Cargo.toml",
                "[package]\nname = \"layout\"\nversion = \"0.1.0\"\n",
            );
            write(&root, "src/lib.rs", "pub struct Marker;\n");
            write(&root, ignore, "main.rs\n");
            for kind in ["tests", "src/bin"] {
                write(&root, &format!("{kind}/check/main.rs"), "fn main() {}\n");
                write(
                    &root,
                    &format!("{kind}/check/helper.rs"),
                    "pub fn helper() {}\n",
                );
            }
            let analyzer = crate::RustAnalyzer::from_project(
                brokk_bifrost_core::analyzer::project::FilesystemProject::new(root.clone())
                    .unwrap(),
            );
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let roots = analyzer
                .analyzer_store()
                .selected_rust_target_roots(snapshots.get("rust").unwrap())
                .unwrap();
            assert!(roots.contains("tests/check/main.rs"), "{ignore}: {roots:?}");
            assert!(
                roots.contains("src/bin/check/main.rs"),
                "{ignore}: {roots:?}"
            );
            for (kind, name) in [("tests", "tests"), ("src/bin", "bin")] {
                let helper = ProjectFile::new(root.clone(), format!("{kind}/check/helper.rs"));
                assert_eq!(
                    brokk_bifrost_rust::imports::rust_crate_root_package_with(
                        &analyzer.inner.adapter().naming,
                        &helper
                    ),
                    format!("layout.{name}.check"),
                    "{ignore}: {kind}"
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10596: an incremental update kept the old configuration capture and named a newly added file under an ancestor crate"
    )]
    fn added_source_captures_an_unlisted_ancestor_manifest() {
        use brokk_bifrost_core::analyzer::project::Project;
        use brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot;
        use std::{io, path::Path};
        struct FilteredProject(TestProject);
        impl Project for FilteredProject {
            fn install_read_recorder(
                &self,
                capability: brokk_bifrost_core::analyzer::project_reads::ReadCapability,
            ) -> bool {
                self.0.install_read_recorder(capability)
            }
            fn root(&self) -> &Path {
                self.0.root()
            }
            fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
                self.0.project_read_slot()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.0.analyzer_languages()
            }
            fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
                Ok(self
                    .0
                    .all_files()?
                    .into_iter()
                    .filter(|file| file.rel_path() != Path::new("crates/inner/Cargo.toml"))
                    .collect())
            }
            fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
                self.0.analyzable_files(language)
            }
            fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
                self.0.file_by_rel_path(path)
            }
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"root_pkg\"\nversion = \"0.1.0\"\n",
        );
        write(&root, "src/lib.rs", "pub struct Root;\n");
        write(
            &root,
            "crates/inner/Cargo.toml",
            "[package]\nname = \"inner_pkg\"\nversion = \"0.1.0\"\n",
        );
        let project = || FilteredProject(TestProject::new(root.clone(), Language::Rust));
        let analyzer = super::RustAnalyzer::from_project(project());
        write(&root, "crates/inner/src/lib.rs", "pub struct Inner;\n");
        let added = ProjectFile::new(root.clone(), "crates/inner/src/lib.rs");
        let listing = project().all_files_with_omissions().expect("listing");
        let updated =
            analyzer.update_with_listing(&BTreeSet::from([added.clone()]), Some(&listing));
        let fresh = super::RustAnalyzer::from_project(project());
        let name = rust_package_name_with(&updated.inner.adapter().naming, &added);
        assert_eq!(name, "inner_pkg");
        assert_eq!(
            name,
            rust_package_name_with(&fresh.inner.adapter().naming, &added)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4502: a generated Rust hierarchy result above 16 MiB was hydrated for each inverse target"
    )]
    fn generated_hierarchy_facts_over_sixteen_mib_stay_cached() {
        const GENERATED_UNITS: usize = 15_059;
        let cache_budget = 256 * 1024 * 1024;
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root, "generated.rs");
        let long_name = "x".repeat(1_500);
        let unit = brokk_bifrost_core::analyzer::model::CodeUnit::new(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
            "generated",
            long_name,
        );
        let declaration_units = (0..GENERATED_UNITS)
            .map(|index| {
                (
                    brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId::new(
                        index as u32,
                    ),
                    unit.clone(),
                )
            })
            .collect();
        let facts = Arc::new(RustHierarchySourceFacts {
            items: Default::default(),
            types: Vec::new(),
            declarations: Vec::new(),
            declaration_units,
            module_names: Default::default(),
            imports: Vec::new(),
        });
        let retained_bytes = facts.estimated_retained_bytes();
        assert!(retained_bytes > (16 * 1024 * 1024));
        assert!(retained_bytes <= cache_budget as usize);

        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(cache_budget);
        let cache = budget.region::<
            super::RustHierarchySourceFactsCacheKey,
            brokk_bifrost_core::retention_budget::SharedAllocation<
                brokk_bifrost_core::retention_budget::Accounted<RustHierarchySourceFacts>,
            >,
        >("rust.hierarchy_source_facts", None);
        let key = (
            brokk_bifrost_analysis::analyzer::store::GenerationId::BOOTSTRAP,
            brokk_bifrost_core::gitblob::BlobKey::unvaried(git2::Oid::zero(), "rust"),
            file,
        );
        let bytes = super::weight_rust_hierarchy_source_facts(&key, &facts) as usize;
        let facts = Arc::try_unwrap(facts).expect("new hierarchy facts have no other holder");
        let facts = Arc::new(
            brokk_bifrost_core::retention_budget::Accounted::charged_with_bytes(
                &budget, facts, bytes,
            ),
        );
        drop(cache.insert(
            key.clone(),
            brokk_bifrost_core::retention_budget::SharedAllocation::new(Arc::clone(&facts)),
        ));
        for _target in 0..2 {
            let cached = cache.get(&key).expect("large hierarchy entry is retained");
            assert_eq!(cached.arc().declaration_units.len(), GENERATED_UNITS);
            assert!(Arc::ptr_eq(cached.arc(), &facts));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10596: crate naming read new Cargo.toml bytes for an older generation"
    )]
    fn a_manifest_rename_reaches_naming_at_the_next_generation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"before\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", "pub struct Marker;\n");
        let library = ProjectFile::new(root.clone(), "src/lib.rs");

        let analyzer = crate::test_support::rust_analyzer(&root);
        assert_eq!(
            rust_package_name_with(&analyzer.inner.adapter().naming, &library),
            "before"
        );

        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"after\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        // Force an old-generation miss, as eviction would, after the disk edit.
        analyzer.inner.adapter().naming.invalidate_all();
        let unseen = ProjectFile::new(root.clone(), "src/unseen/new.rs");
        assert!(
            rust_package_name_with(&analyzer.inner.adapter().naming, &unseen).starts_with("before")
        );
        // A newly created nearer manifest is absent for the old generation.
        write(
            &root,
            "src/unseen/Cargo.toml",
            "[package]\nname = \"nearer\"\n",
        );
        analyzer.inner.adapter().naming.invalidate_all();
        assert!(
            rust_package_name_with(&analyzer.inner.adapter().naming, &unseen).starts_with("before")
        );
        let updated = analyzer.update(&BTreeSet::from([ProjectFile::new(
            root.clone(),
            "Cargo.toml",
        )]));
        assert_eq!(
            rust_package_name_with(&updated.inner.adapter().naming, &library),
            "after",
            "update selects the newly captured manifest",
        );
        analyzer.inner.adapter().naming.invalidate_all();
        assert_eq!(
            rust_package_name_with(&analyzer.inner.adapter().naming, &library),
            "before",
            "publishing the next generation cannot mutate the old generation"
        );
        drop(updated);

        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"renamed-again\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let rebuilt = crate::test_support::rust_analyzer(&root);
        assert_eq!(
            rust_package_name_with(&rebuilt.inner.adapter().naming, &library),
            "renamed_again",
            "constructing an analyzer starts a generation too",
        );
        drop(rebuilt);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "a6d14cf6a78a: a foreign-language file poisoned an otherwise valid Rust request"
    )]
    fn a_foreign_file_is_unavailable_to_rust_without_failing_the_request() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"foreign\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("write Rust");
        std::fs::write(root.join("src/widget.h"), "struct Widget { int v; };\n")
            .expect("write header");
        let analyzer = crate::analyzer::rust::RustAnalyzer::from_project(TestProject::new(
            root.clone(),
            Language::Rust,
        ));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let header = ProjectFile::new(root.clone(), "src/widget.h");
        let outcome = analyzer.canonical_rust_hierarchy_source_facts(&header, &|| true);
        assert!(
            matches!(
                outcome,
                Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
            ),
            "a foreign file has no canonical Rust source"
        );
        assert!(
            scope.store_error().is_none(),
            "a foreign file must not poison the request: {:?}",
            scope.store_error()
        );

        // A Rust file the snapshot does know still answers, so the guard did
        // not silence the ownership test itself.
        let library = ProjectFile::new(root, "src/lib.rs");
        assert!(
            analyzer
                .canonical_rust_hierarchy_source_facts(&library, &|| true)
                .is_ok()
        );
    }
}
