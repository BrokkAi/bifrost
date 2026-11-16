//! Query-time Rust type facts from structure, the resolver, and the reviewed
//! std fact table (#3757).
//!
//! Three consumers read them: the inert-drop proof below, the receiver type a
//! Rust method call's external identity is minted from
//! ([`rust_method_receiver_owner`]), and the std operations the taint compiler
//! installs as built-in call models ([`rust_std_builtin_call`]).
//!
//! The Rust semantic adapter lowers one file at a time without the resolver.
//! When an implicit `Drop` it cannot type destroys only parameters and `let`
//! bindings, it publishes the omission with the `InertDropGlue` obligation, and
//! the workspace oracle answers that obligation here with
//! [`procedure_drops_run_no_user_code`].
//!
//! A type is proven inert -- its drop glue runs no user code -- only from:
//!
//! - structure: a reference, raw pointer, primitive, `()`, `!`, or a tuple or
//!   array of inert types;
//! - a reviewed std prelude type (`RUST_STD_TYPE_FACTS`) whose written name
//!   the resolver proves is the `std` or `core` prelude item, with inert type
//!   arguments;
//! - a workspace struct or enum the resolver names, with no type parameters
//!   and only resolver-certified built-in derives (other macros may add `Drop`),
//!   whose fields are inert and whose selected crate inventory certifies
//!   absence of a Drop implementation.
//! - an activated model's Rust struct, enum, or union whose declaration
//!   reviews its drop glue as inert (#9057), with inert type arguments,
//!   including the defaults an application omits.
//!
//! An expression's type comes from literals, the declared type of the
//! parameter or `let` a name resolves to, the declared return type of the
//! workspace function a call resolves to, an activated model's exact
//! per-call return signature, and the reviewed std method, operator, and
//! constructor facts. Anything else leaves the proof open and the gap stands;
//! nothing here is inferred from spelling alone.
//!
//! Existing standard owned-memory admission shares the documented environment
//! assumption in
//! [`crate::analyzer::semantic_model::GLOBAL_ALLOCATOR_RELEASE_ASSUMPTION`].
//! The consumer-relative release proof must preserve that assumption in its
//! provenance; a complete allocator census will tighten both paths (#10969).
//!
//! Expression classes and modeled call shapes are memoized only while one
//! query proves one prepared source. Those memos and every answer are dropped
//! with the query; all other facts come from the prepared trees and point
//! resolver lookups.

use brokk_bifrost_analysis::analyzer::semantic_model::alias_resolution::{
    AliasCursorContext, AliasExpansionFailure, AliasTypeCursor, normalize_alias_cursor,
};
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelNamespace;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ResolvedActiveSemanticModels, SemanticModelOverlay, SemanticModelOverlayBuildError,
};

use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustPrimitive;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::cancellation::CancellationToken;
#[cfg(test)]
use std::cell::Cell;
use std::ops::Range as ByteRange;
use std::sync::Arc;
#[cfg(all(test, debug_assertions))]
use std::time::Instant;
use std::{cell::RefCell, collections::HashMap};

use brokk_bifrost_rust::graph_support::rust_path_segments;
use brokk_bifrost_rust::prelude::{
    RUST_STD_ASSOCIATED_FACTS, RUST_STD_METHOD_FACTS, RUST_STD_SELF_CONSTRUCTOR_FACTS,
    RUST_STD_STRING_ADD_STR, RustStdAssociatedFact, RustStdReceiver, RustStdValue,
    rust_std_associated_fact, rust_std_constructor_fact, rust_std_method_fact,
    rust_std_self_constructor_fact, rust_std_type_fact,
};
use brokk_bifrost_rust::rust_unwrap_operand;
use brokk_bifrost_rust::structural::{call_function_target, rust_method_call_parts};
use brokk_bifrost_rust::syntax::{item_has_path_attribute, outer_attributes};
use tree_sitter::{Node, Tree};

use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::structural::native_obligation::{
    NativeResultObligation, NativeResultObligationBasis,
};

use crate::analyzer::rust::RustAnalyzer;

use crate::analyzer::rust::semantic::named_children;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeFileEvidence;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite;

use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalBindingResolution;

use crate::analyzer::semantic_model::{
    GenericParameterDefault, SemanticModelCallApplication, SemanticModelCallableKey,
    SemanticModelSymbol, TypeDropGlue, TypeFact, TypeRef,
};
use brokk_bifrost_analysis::analyzer::lexical_definitions::{
    LexicalBindingUnproven, resolve_lexical_binding, resolve_lexical_binding_with_visibility,
};

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaimKind;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

/// How many nested type or binding hops one proof follows. The proof fails
/// closed past it, which bounds the otherwise recursive descent.
pub(crate) const PROOF_DEPTH: usize = 8;

/// An incomplete attempt retains its ordinary value and records completion in
/// the enclosing query receipt so callers and replay observe the same stop.
#[derive(Debug, Clone)]
pub(crate) enum RustProofAttempt<T> {
    Complete(Option<T>),
    Incomplete {
        value: Option<T>,
        reason: &'static str,
        cause: Option<DerivationExecutionCause>,
    },
}

impl<T> RustProofAttempt<T> {
    pub(crate) fn into_value(self) -> Option<T> {
        match self {
            Self::Complete(value) | Self::Incomplete { value, .. } => value,
        }
    }
}

pub(crate) fn incomplete_proof(reason: &'static str) {
    debug_assert!(
        brokk_bifrost_analysis::analyzer::i_analyzer::DETERMINISTIC_PROOF_STOP_LABELS
            .contains(&reason),
        "unregistered deterministic proof stop {reason:?}"
    );
    record_proof_stop(reason, None);
}

pub(crate) fn operational_proof_stop(reason: &'static str, cause: DerivationExecutionCause) {
    record_proof_stop(reason, Some(cause));
}

pub(crate) fn selected_import_infos(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    cancellation: &CancellationToken,
) -> Option<Vec<brokk_bifrost_core::analyzer::model::ImportInfo>> {
    selected_import_infos_from_read(analyzer, file, cancellation, || {
        if !operation.selected_rust_imports_have_cfg(file, cancellation)? {
            return operation.selected_rust_import_infos(file, None, cancellation);
        }
        use super::route_kinds::{RustUnitConfiguration, RustUnitConfigurationKey};
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::RustCfgAuthority;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
        let rust = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            super::RustAnalyzer,
        >(analyzer)
        .expect("Rust import proof requires Rust analyzer");
        // Admit routes against this operation's content; a cold miss certifies
        // membership through the distinct Main reader before replaying here.
        let _frame = rust.operation_read_frame(operation)?;
        let routes = rust
            .file_routes(file, Some(&|| !cancellation.is_cancelled()))
            .map_err(|error| {
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "Rust import membership unavailable: {error:?}"
                ))
            })?;
        let host = rust
            .inner
            .derivations()
            .expect("Rust analyzer owns derivations");
        let targets = operation.rust_file_configuration_targets(file.rel_path(), cancellation)?;
        let mut contexts = Vec::new();
        let mut complete = routes.is_complete() && !targets.targets.is_empty();
        for target in targets.targets {
            if target.cfg_authority == RustCfgAuthority::IncompleteBuildScript {
                // Build output is outside configuration authority. Keep every
                // binder rather than proving inactivity from Cargo alone.
                complete = false;
            }
            let key = RustUnitConfigurationKey {
                manifest_path: target.manifest_path,
                target_kind: target.target_kind,
                target_name: target.target_name,
            };
            match host.demand_in_operation::<RustUnitConfiguration>(analyzer, operation, &key) {
                Demanded::Available {
                    value,
                    complete: configuration_complete,
                    ..
                } => {
                    complete &= configuration_complete;
                    contexts.push(
                        brokk_bifrost_rust::selected_context::merge_rust_configuration_atoms(
                            &value.0.cfg_atoms,
                            &value.0.features,
                        ),
                    );
                }
                Demanded::Unavailable(_) => complete = false,
            }
        }
        if !complete {
            super::route_kinds::record_route_evidence_gap(analyzer, &[]);
        }
        let imports = operation.selected_rust_import_infos(
            file,
            complete.then_some(contexts.as_slice()),
            cancellation,
        )?;
        Ok(imports)
    })
}

fn selected_import_infos_from_read(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: &CancellationToken,
    read: impl FnOnce() -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<(
            git2::Oid,
            Vec<brokk_bifrost_core::analyzer::model::ImportInfo>,
        )>,
    >,
) -> Option<Vec<brokk_bifrost_core::analyzer::model::ImportInfo>> {
    match read() {
        Ok(Some((oid, imports))) => {
            analyzer.record_read(
                brokk_bifrost_analysis::analyzer::read_ledger::ReadKey::file(
                    brokk_bifrost_core::analyzer::Language::Rust,
                    brokk_bifrost_core::path_utils::rel_path_string(file),
                    oid,
                    brokk_bifrost_core::gitblob::ParseVariant::Empty,
                ),
            );
            Some(imports)
        }
        Ok(None) => {
            if cancellation.is_cancelled() {
                operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
            } else {
                operational_proof_stop(
                    "selected_imports_unavailable",
                    DerivationExecutionCause::Provider,
                );
            }
            None
        }
        Err(_) => {
            operational_proof_stop("store_error", DerivationExecutionCause::Provider);
            None
        }
    }
}

fn record_proof_stop(reason: &'static str, cause: Option<DerivationExecutionCause>) {
    brokk_bifrost_analysis::analyzer::i_analyzer::record_proof_incomplete_on_current_contexts(
        brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped { reason, cause },
    );
}

pub(crate) fn cargo_route_execution_cause(
    error: &brokk_bifrost_rust::graph_support::RustCargoRouteError,
) -> DerivationExecutionCause {
    use brokk_bifrost_rust::graph_support::RustCargoRouteError;
    match error {
        RustCargoRouteError::Cancelled => DerivationExecutionCause::Cancelled,
        RustCargoRouteError::Unavailable => DerivationExecutionCause::Provider,
    }
}

/// Normalize a modeled Rust type through the shared endpoint cursor core.
/// This adaptor intentionally does not change production type_ref_class drop
/// decisions; wiring that consumer belongs to the separate #12054 follow-up.
#[doc(hidden)]
pub fn normalize_std_model_type(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    current: &mut AliasTypeCursor<TypeRef>,
    context: &mut AliasCursorContext<TypeRef>,
    cancellation: &CancellationToken,
) -> Result<Option<AliasExpansionFailure>, SemanticModelOverlayBuildError> {
    context.begin_normalization();
    normalize_alias_cursor(
        overlay,
        active,
        "rust",
        &active.model_provider_selection(),
        current,
        context,
        cancellation,
        |ty| is_intrinsic_primitive_type(overlay, ty),
    )
}

fn is_intrinsic_primitive_type(overlay: &SemanticModelOverlay, ty: &TypeRef) -> bool {
    match ty {
        TypeRef::Named {
            name, arguments, ..
        } => {
            arguments.is_empty()
                && (super::call_conversion::modeled_primitive(name).is_some()
                    || super::call_conversion::primitive_for_spelling(name).is_some())
        }
        TypeRef::Declared { id, arguments, .. } => {
            arguments.is_empty()
                && overlay
                    .symbols_with_id_in_family(id, "rust")
                    .unique()
                    .is_some_and(|symbol| {
                        super::call_conversion::modeled_primitive(&symbol.qualified_name).is_some()
                    })
        }
        _ => false,
    }
}

/// Preserve owner-local open member evidence for target-less model aliases.
/// This does not expand the alias or establish authority for a payload/target.
pub(crate) fn targetless_alias_own_owner(
    analyzer: &dyn IAnalyzer,
    mut ty: &TypeRef,
) -> Option<String> {
    while let TypeRef::ByRef { element, .. } = ty {
        ty = element;
    }
    let overlay = analyzer.semantic_model_overlay()?;
    let symbol = match ty {
        TypeRef::Named { name, .. } => overlay
            .symbols_named_in_family(name, "rust", SemanticModelNamespace::TypeOrModule)
            .unique()?,
        TypeRef::Declared { id, .. } => overlay.symbols_with_id_in_family(id, "rust").unique()?,
        _ => return None,
    };
    if symbol.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::TypeAlias
        || super::call_conversion::modeled_primitive(&symbol.qualified_name).is_some()
        || overlay
            .members_of_in_family(&symbol.id, "rust")
            .records
            .is_empty()
    {
        return None;
    }
    let active = analyzer.active_semantic_models()?;
    let declaration = brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
        &active, &symbol,
    )?;
    declaration
        .alias_target
        .is_none()
        .then(|| symbol.qualified_name.clone())
}

/// Canonicalize a selected modeled receiver application before deriving its
/// owner or binding payload parameters. The shared cursor retains argument
/// environments until every child has been rebuilt; a raw target's T must not
/// escape without its binding. Refusals select nothing, and references remain.
pub(crate) fn normalized_receiver_application(
    analyzer: &dyn IAnalyzer,
    ty: TypeRef,
) -> Option<TypeRef> {
    use brokk_bifrost_analysis::analyzer::semantic_model::alias_resolution::{
        AliasExpansionRefusal, materialize_alias_application,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::overlay::ModelProvider;
    let head_of = |mut ty: &TypeRef| {
        while let TypeRef::ByRef { element, .. } = ty {
            ty = element;
        }
        ty.clone()
    };
    let head = head_of(&ty);
    // Intrinsic primitive records may use a type_alias encoding without a
    // language alias target. Their authority comes from the shared classifier.
    if matches!(&head, TypeRef::Named { name, arguments, .. }
        if arguments.is_empty() && super::call_conversion::modeled_primitive(name).is_some())
    {
        return Some(ty);
    }
    // A source binder is not an alias expansion failure. The existing trait
    // selector still needs T (and &T) to consult its lexical trait bounds.
    if matches!(head, TypeRef::TypeParameter { .. }) {
        return Some(ty);
    }
    if matches!(head, TypeRef::Unknown) {
        return None;
    }
    let overlay = analyzer.semantic_model_overlay()?;
    let symbol_for = |head: &TypeRef| match head {
        TypeRef::Named { name, .. } => overlay
            .symbols_named_in_family(name, "rust", SemanticModelNamespace::TypeOrModule)
            .unique(),
        TypeRef::Declared { id, .. } => overlay.symbols_with_id_in_family(id, "rust").unique(),
        _ => None,
    };
    if !matches!(head, TypeRef::Named { .. } | TypeRef::Declared { .. }) {
        return Some(ty);
    }
    // A workspace nominal is not a modeled alias. Preserve it for native
    // ownership and external trait selection. Competing modeled declarations
    // still cannot establish a unique alias or member owner.
    let Some(symbol) = symbol_for(&head) else {
        let absent = match &head {
            TypeRef::Named { name, .. } => overlay
                .symbols_named_in_family(name, "rust", SemanticModelNamespace::TypeOrModule)
                .records
                .is_empty(),
            TypeRef::Declared { id, .. } => overlay
                .symbols_with_id_in_family(id, "rust")
                .records
                .is_empty(),
            _ => unreachable!(),
        };
        if !absent {
            incomplete_proof("model_alias_unresolvable_target");
        }
        return absent.then_some(ty);
    };
    // Declared primitive identities have the same intrinsic authority as
    // their named spelling; pack encoding does not create a language alias.
    if super::call_conversion::modeled_primitive(&symbol.qualified_name).is_some()
        && matches!(&head, TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } if arguments.is_empty())
    {
        return Some(ty);
    }
    let active = analyzer.active_semantic_models()?;
    let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
    let result = match materialize_alias_application(
        &overlay,
        &active,
        "rust",
        AliasTypeCursor::new(ty, ModelProvider::from(&symbol.provenance)),
        |ty| is_intrinsic_primitive_type(&overlay, ty),
        &cancellation,
    ) {
        Ok(Ok(result)) => result,
        Ok(Err(refusal)) => {
            incomplete_proof(match refusal.reason {
                AliasExpansionRefusal::AliasMissingTarget => "model_alias_missing_target",
                AliasExpansionRefusal::AliasUnresolvableTarget => "model_alias_unresolvable_target",
                AliasExpansionRefusal::AliasCycle => "model_alias_cycle",
                AliasExpansionRefusal::AliasArityMismatch => "model_alias_arity_mismatch",
            });
            return None;
        }
        Err(SemanticModelOverlayBuildError::Cancelled) => {
            operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
            return None;
        }
        Err(
            SemanticModelOverlayBuildError::RetainedBytesExceeded(_)
            | SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded,
        ) => {
            operational_proof_stop(
                "alias_receiver_model_budget",
                DerivationExecutionCause::Budget,
            );
            return None;
        }
        Err(SemanticModelOverlayBuildError::Open(open)) => {
            if open.is_cancellation() {
                operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
            } else {
                operational_proof_stop(
                    "alias_receiver_model_unavailable",
                    DerivationExecutionCause::Provider,
                );
            }
            return None;
        }
    };
    let head = head_of(&result);
    // Definition-owned nominals were validated while their cursor context
    // was available. A substituted source nominal may instead be owned by
    // the workspace, just like an unaliased receiver; retain that authority.
    // Restored lexical parameters likewise retain their source trait bounds.
    if matches!(head, TypeRef::Unknown) {
        incomplete_proof("model_alias_unresolvable_target");
        return None;
    }
    Some(result)
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static NATIVE_PROOF_LIMITS: RefCell<Option<(ReceiverAnalysisBudget, Option<CancellationToken>)>> = const { RefCell::new(None) };
}

/// Restrict only native declaration proofs, leaving dispatch able to finish.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_rust_native_result_obligation_limits_for_test<T>(
    budget: ReceiverAnalysisBudget,
    cancellation: Option<CancellationToken>,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            NATIVE_PROOF_LIMITS.with(|limits| *limits.borrow_mut() = None);
        }
    }
    NATIVE_PROOF_LIMITS.with(|limits| {
        assert!(
            limits
                .borrow_mut()
                .replace((budget, cancellation))
                .is_none(),
            "nested native proof limits"
        );
    });
    let _reset = Reset;
    run()
}

fn native_proof_limits(
    analyzer: &dyn IAnalyzer,
) -> (ReceiverAnalysisBudget, Option<CancellationToken>) {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(limits) = NATIVE_PROOF_LIMITS.with(|limits| limits.borrow().clone()) {
        return limits;
    }
    (
        INTERACTIVE_TYPE_LOOKUP_BUDGET,
        analyzer.active_query_cancellation(),
    )
}

fn completed_native_proof<T>(
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
    proof: impl FnOnce() -> T,
) -> (T, Option<DerivationExecutionCause>) {
    let (attempt, read_cause) =
        brokk_bifrost_analysis::analyzer::i_analyzer::capture_read_execution_cause(
            analyzer,
            || completed_proof(analyzer, cancellation, || Some(proof())),
        );
    let (value, cause) = match attempt {
        RustProofAttempt::Complete(value) => (value, read_cause),
        RustProofAttempt::Incomplete { value, cause, .. } => (value, cause.or(read_cause)),
    };
    if cause.is_some() {
        analyzer.mark_execution_dependent();
    }
    (
        value.expect("a native proof always returns its value"),
        cause,
    )
}

pub(crate) fn observe_proof_resolution(resolution: &BoundedResolution<DefinitionLookupOutcome>) {
    match resolution {
        BoundedResolution::Exceeded { .. } => {
            operational_proof_stop("exceeded", DerivationExecutionCause::Budget)
        }
        BoundedResolution::Unavailable { .. } => {
            operational_proof_stop("input unavailable", DerivationExecutionCause::Provider)
        }
        BoundedResolution::Cancelled { .. } => {
            operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled)
        }
        BoundedResolution::Complete { value, .. } => match value.status {
            DefinitionLookupStatus::Resolved
            | DefinitionLookupStatus::NotAReference
            | DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::UnresolvableImportBoundary
            | DefinitionLookupStatus::Ambiguous => {}
            DefinitionLookupStatus::Unavailable => {
                operational_proof_stop("unavailable", DerivationExecutionCause::Provider)
            }
            DefinitionLookupStatus::Cancelled => {
                operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled)
            }
            DefinitionLookupStatus::ExceededBudget(_) => {
                operational_proof_stop("exceeded_budget", DerivationExecutionCause::Budget)
            }
            // The aggregate status does not certify why resolution was incomplete (#11408).
            DefinitionLookupStatus::Incomplete => observe_incomplete_lookup(value),
            DefinitionLookupStatus::UnsupportedLanguage => incomplete_proof("unsupported_language"),
            DefinitionLookupStatus::InvalidLocation => incomplete_proof("invalid_location"),
            DefinitionLookupStatus::NotFound => incomplete_proof("not_found"),
        },
    }
}

fn observe_incomplete_lookup(value: &DefinitionLookupOutcome) {
    use brokk_bifrost_analysis::analyzer::resolution::{
        ResolutionCompletion, model::ResolutionIncompleteReason as Native,
    };
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupReason as Adapter;
    let mut observed = false;
    if let Some(evidence) = &value.incomplete_evidence {
        if let ResolutionCompletion::Incomplete(reasons) = &evidence.completion {
            for reason in reasons {
                observed = true;
                match reason {
                    Native::Cancelled => {
                        operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled)
                    }
                    Native::CyclicPrefixDependency(_) => operational_proof_stop(
                        "resolution_cyclic_prefix_dependency",
                        DerivationExecutionCause::Provider,
                    ),
                    Native::ReceiverBudgetExhausted(_) => operational_proof_stop(
                        "resolution_receiver_budget_exhausted",
                        DerivationExecutionCause::Budget,
                    ),
                    Native::TimeBudgetExceeded(_) => operational_proof_stop(
                        "resolution_time_budget_exceeded",
                        DerivationExecutionCause::Budget,
                    ),
                    // The selected boundary catalog's complete read closure is not certified here.
                    Native::OpenBoundary { .. } => operational_proof_stop(
                        "resolution_open_boundary",
                        DerivationExecutionCause::Provider,
                    ),
                    // Saturation can choose a different conservative stop from branch
                    // history; that history is not part of the lookup key.
                    Native::CyclicExpansion(_) => operational_proof_stop(
                        "resolution_cyclic_expansion",
                        DerivationExecutionCause::Provider,
                    ),
                    Native::InconsistentPrecedence(_) => {
                        // Provider until certified (#11510).
                        operational_proof_stop(
                            "resolution_inconsistent_precedence",
                            DerivationExecutionCause::Provider,
                        )
                    }
                    // No UnsupportedSemantic origin is certified (#11510).
                    // The per-origin experiment published 0/42 Bat units; keep
                    // the provenance machinery for separately reviewed stops.
                    Native::UnsupportedSemantic(_) => operational_proof_stop(
                        "resolution_unsupported_semantic",
                        DerivationExecutionCause::Provider,
                    ),
                    Native::OverlayFrontierUnknown(_) => operational_proof_stop(
                        "resolution_overlay_frontier_unknown",
                        DerivationExecutionCause::Provider,
                    ),
                    Native::Unclassified(_) => operational_proof_stop(
                        "resolution_unclassified",
                        DerivationExecutionCause::Provider,
                    ),
                    Native::UnmountedFile { .. } => {
                        // Provider until certified (#11510).
                        operational_proof_stop(
                            "resolution_unmounted_file",
                            DerivationExecutionCause::Provider,
                        )
                    }
                    Native::ReceiverSubclassObligation(_) => {
                        // Provider until certified (#11510).
                        operational_proof_stop(
                            "resolution_receiver_subclass_obligation",
                            DerivationExecutionCause::Provider,
                        )
                    }
                }
            }
        }
        for reason in &evidence.reasons {
            observed = true;
            match reason {
                Adapter::UnprojectedDefinition { .. } => {
                    incomplete_proof("resolution_unprojected_definition")
                }
                Adapter::UnplacedDefinition => {
                    operational_proof_stop("incomplete", DerivationExecutionCause::Provider)
                }
                Adapter::Execution(cause) => operational_proof_stop("incomplete", *cause),
                Adapter::MacroExpansionContextRequired => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_macro_expansion_context_required",
                        DerivationExecutionCause::Provider,
                    )
                }
                Adapter::UnknownActivation => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_unknown_activation",
                        DerivationExecutionCause::Provider,
                    )
                }
                Adapter::MacroFragmentNoNamespace => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_macro_fragment_no_namespace",
                        DerivationExecutionCause::Provider,
                    )
                }
                Adapter::MacroModuleHeadUnbound => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_macro_module_head_unbound",
                        DerivationExecutionCause::Provider,
                    )
                }
                Adapter::UnprojectedTypeFrontier => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_unprojected_type_frontier",
                        DerivationExecutionCause::Provider,
                    )
                }
                Adapter::UnprovedClosedWorld => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_unproved_closed_world",
                        DerivationExecutionCause::Provider,
                    )
                }
                Adapter::LexicalBindingUnproven => {
                    // Provider until certified (#11510).
                    operational_proof_stop(
                        "resolution_lexical_binding_unproven",
                        DerivationExecutionCause::Provider,
                    )
                }
            }
        }
    }
    if !observed {
        operational_proof_stop("incomplete", DerivationExecutionCause::Provider);
    }
}

/// Complete one proof from its consumed evidence (#11970). The closure must
/// read its own semantic inputs or replay their `QueryReadReceipt`; a bare
/// value from an incomplete parent proof is not a certified input. Ambient
/// stops from unrelated work do not belong to this proof, while its reads
/// still propagate outward and prevent reuse of the enclosing request.
pub(crate) fn completed_proof<T>(
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    proof: impl FnOnce() -> Option<T>,
) -> RustProofAttempt<T> {
    let active = analyzer.active_query_cancellation();
    let combined = cancellation
        .zip(active.as_ref())
        .map(|(operation, request)| request.combined_with(operation));
    let cancellation = combined.as_ref().or(cancellation).or(active.as_ref());
    let _completion = AnalyzerQueryScope::independent_answer(analyzer, cancellation);
    let scope = AnalyzerQueryScope::capturing_proof_completion(analyzer);
    // Type evidence is an auxiliary lookup, not another candidate for the
    // reference whose definition trace encloses this proof. Its read and stop
    // receipts still belong to the enclosing query.
    let value =
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::without_recording(proof);
    // A soft deadline is a time budget; explicit cancellation is its own cause.
    if let Some(token) = cancellation {
        if token.is_cancelled() {
            operational_proof_stop("cancelled_or_deadline", DerivationExecutionCause::Cancelled);
        } else if token.soft_deadline_passed() {
            operational_proof_stop("cancelled_or_deadline", DerivationExecutionCause::Budget);
        }
    }
    // Store adapters can report a failed read without a language-specific
    // stop. Consuming that receipt must still refuse a complete proof; keep
    // the original attributed failure in the ledger and receipt (#11970).
    if scope.captured_read_incompleteness().iter().any(|reason| {
        matches!(
            reason.base_cause(),
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::StoreFailure(_)
        )
    }) {
        operational_proof_stop("store_error", DerivationExecutionCause::Provider);
    }
    let stop = scope
        .captured_read_incompleteness()
        .into_iter()
        .filter(|reason| {
            matches!(
                reason,
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped { .. }
            )
        })
        .reduce(|first, next| {
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::merge_optional(
                Some(first),
                Some(next),
            )
            .unwrap()
        });
    match stop {
        Some(brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
            reason,
            cause,
        }) => RustProofAttempt::Incomplete {
            value,
            reason,
            cause,
        },
        None => RustProofAttempt::Complete(value),
        _ => unreachable!("only proof stops were selected"),
    }
}

/// Where a `.clone()` call's member selection landed (see `clone_selection`).
enum CloneSelection {
    /// Not a zero-argument method call named `clone` on a receiver.
    NotCloneCall,
    /// std::clone::Clone's own declaration was selected.
    Trait {
        clone_trait: Arc<SemanticModelSymbol>,
        receiver_steps: usize,
    },
    /// Another declaration was selected: the receiver type's own record, or
    /// another trait's.
    Other {
        selected: Arc<SemanticModelSymbol>,
        clone_trait: Arc<SemanticModelSymbol>,
    },
}

/// A semantic-model declaration, by record identity and supplying pack. Two
/// packs that declare the same name are different declarations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct RustModelDeclaration {
    pub id: String,
    pub pack_digest: String,
}

impl RustModelDeclaration {
    fn of(symbol: &SemanticModelSymbol) -> Self {
        Self {
            id: symbol.id.clone(),
            pack_digest: symbol.provenance.pack_digest.clone(),
        }
    }
}

/// How the receiver type's model implements std::clone::Clone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustCloneImplementation {
    /// The model gives the receiver type an `implements std.clone.Clone`
    /// hierarchy path and no `clone` record of its own. The model does not say
    /// whether the implementation is derived or written by hand, so this
    /// proves which implementation was selected, not what its body does.
    Declared { receiver: RustModelDeclaration },
    /// The receiver type's model declares a `clone` record whose implemented
    /// trait is std.clone.Clone: an `impl Clone for T` item.
    Explicit {
        receiver: RustModelDeclaration,
        method: RustModelDeclaration,
    },
}

/// A modeled `.clone()` call selects std::clone::Clone on its receiver type,
/// written with at most one reference layer and no dereference. This names the
/// selected implementation; it does not prove that the implementation copies
/// its receiver's state, which a consumer must establish separately.
#[derive(Debug, Clone, PartialEq)]
#[doc(hidden)]
pub struct RustCloneCertificate {
    /// The selected implementation, on the type the member was selected on.
    pub implementation: RustCloneImplementation,
    /// The trait the selected implementation was checked against.
    pub clone_trait: RustModelDeclaration,
    /// Type-level dereferences selection followed from the written receiver.
    pub receiver_steps: usize,
    /// The call's modeled result type.
    pub result: TypeRef,
}

/// Why a clone proof could not decide.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustCloneIncomplete {
    /// A `.clone()` call whose receiver or member selection has no proven
    /// modeled identity, and no proof stop explains it. Deterministic given
    /// the receipt's reads.
    ReceiverUnresolved,
    /// A proof stop recorded while deciding. A stop without a cause is a
    /// registered deterministic gap; one with a cause is operational.
    ProofStopped {
        reason: &'static str,
        cause: Option<DerivationExecutionCause>,
    },
}

#[derive(Debug, Clone, PartialEq)]
#[doc(hidden)]
pub enum RustCloneVerdict {
    Certified(RustCloneCertificate),
    /// Clone's declaration was selected, but the receiver type's model has no
    /// positive implementation path. Not a certificate.
    Unproven {
        result: TypeRef,
    },
    /// Decided: the call is not a method-call `clone` that selects
    /// std::clone::Clone (an inherent method, another trait's method, or a
    /// call that is not written `receiver.clone()`; a UFCS `Clone::clone(&x)`
    /// is not certified here).
    NotClone,
    Incomplete(RustCloneIncomplete),
}

/// A clone verdict with the reads it depended on.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct RustCloneProof {
    pub verdict: RustCloneVerdict,
    pub receipt: QueryReadReceipt,
}

/// The verdict when a call's exact source cannot be read. The operational
/// stop is recorded in the returned receipt, so a consumer that replays the
/// receipt does not cache its answer as complete.
pub(crate) fn rust_clone_source_unavailable(analyzer: &dyn IAnalyzer) -> RustCloneProof {
    let (verdict, receipt) = QueryReadReceipt::capture(analyzer, || {
        match completed_proof(analyzer, None, || {
            operational_proof_stop("source_unavailable", DerivationExecutionCause::Provider);
            None::<()>
        }) {
            RustProofAttempt::Incomplete { reason, cause, .. } => {
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ProofStopped { reason, cause })
            }
            RustProofAttempt::Complete(_) => unreachable!("the stop was just recorded"),
        }
    });
    RustCloneProof { verdict, receipt }
}

/// Certify a modeled `.clone()` call at `range` of `file` (#11547). `source`
/// is the exact text `range` was taken from; the proof declines, with an
/// operational stop, when the file's prepared syntax is not that text. Opens
/// its own bounded proof with the full remaining allowance, as `call_conversion`
/// does for the bare clone result.
pub(crate) fn rust_modeled_clone_certificate(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    range: ByteRange<usize>,
) -> RustCloneProof {
    // One capture covers opening the proof (its resolution operation and
    // workspace snapshots) and deciding, so the receipt holds every read.
    let (verdict, receipt) = QueryReadReceipt::capture(analyzer, || {
        match completed_proof(analyzer, None, || RustTypeProof::new(analyzer)) {
            RustProofAttempt::Complete(Some(proof)) => {
                proof.clone_proof_verdict(file, source, range, PROOF_DEPTH)
            }
            RustProofAttempt::Incomplete { reason, cause, .. } => {
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ProofStopped { reason, cause })
            }
            // `RustTypeProof::new` records its own stop when it declines.
            RustProofAttempt::Complete(None) => {
                unreachable!("an absent proof records its stop")
            }
        }
    });
    RustCloneProof { verdict, receipt }
}

/// What the proof knows about one value's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustValueClass {
    /// A `&str`: a string literal, or a binding declared `&str` or
    /// `&mut str`.
    Str,
    /// A `String`, proven through the reviewed std facts.
    String,
    /// The `Result<String, _>` returned by the reviewed `std::env::var`
    /// declaration. The semantic model records the outer `Result` return but
    /// intentionally does not encode its generic payload, so this class keeps
    /// that structured std fact available to the following `unwrap` call.
    EnvVarResult,
    /// Some other type whose drop glue runs no user code.
    Inert,
    /// This value is inert, but other values of its inferred type may not be.
    InertValue,
    /// Not proven.
    Unknown,
}

impl RustValueClass {
    fn is_inert(self) -> bool {
        self != Self::Unknown
    }

    fn from_std(value: RustStdValue) -> Self {
        match value {
            RustStdValue::StdType("String") => Self::String,
            RustStdValue::StdType(name) => {
                // Every other reviewed std type carries type arguments, which
                // a bare std value does not name.
                debug_assert!(rust_std_type_fact(name).is_some());
                Self::Unknown
            }
            RustStdValue::Primitive(_) => Self::Inert,
        }
    }
}

// The final scalar replays only the selected type-level dereferences; no receiver
// type tree is retained in the operation-owned call-shape memo.
type RustModeledCallShape = (String, String, bool, usize, usize);
type RustProofMemo<T> = RefCell<HashMap<(usize, usize), (T, QueryReadReceipt)>>;

// Query-local evidence. Keep every agreeing callable's defining providers;
// type-only consumers need no additional provenance restriction.
struct RustModeledCallReturn {
    returned: TypeRef,
    providers: Vec<Arc<SemanticModelSymbol>>,
}

/// One file's exact prepared source, as the proof reads it.
struct RustSource {
    file: ProjectFile,
    prepared: Arc<PreparedSyntaxTree>,
    macro_inventory: brokk_bifrost_rust::macro_matcher::MacroDefinitionInventory,
    expression_classes: RustProofMemo<RustValueClass>,
    modeled_call_shapes: RustProofMemo<Option<RustModeledCallShape>>,
    #[cfg(test)]
    expression_class_evaluations: Cell<usize>,
    #[cfg(test)]
    expression_class_evaluation_limit: Cell<Option<usize>>,
    #[cfg(test)]
    modeled_call_shape_evaluations: Cell<usize>,
    #[cfg(test)]
    modeled_call_shape_evaluation_limit: Cell<Option<usize>>,
}

impl RustSource {
    fn text(&self) -> &str {
        self.prepared.source()
    }

    fn tree(&self) -> &Tree {
        self.prepared.tree()
    }

    // Only the retained source tree can supply stable IDs to these memos.
    // Macro operand reparses have original byte coordinates but temporary IDs.
    fn owns_node(&self, mut node: Node<'_>) -> bool {
        while let Some(parent) = node.parent() {
            node = parent;
        }
        node == self.tree().root_node()
    }

    fn node_text(&self, node: Node<'_>) -> Option<&str> {
        self.text().get(node.byte_range())
    }
}

/// The resolver and analyzer access one query's proofs share.
type DropInventoryProof<'a> = dyn Fn(&CodeUnit, &str, ByteRange<usize>) -> bool + 'a;

pub(crate) struct RustTypeProof<'a, R: RustTypeProofResolver = FactoryRustTypeProofResolver<'a>> {
    analyzer: &'a dyn IAnalyzer,
    rust: &'a RustAnalyzer,
    resolver: R,
    drop_inventory: Option<&'a DropInventoryProof<'a>>,
}

pub(crate) trait RustTypeProofResolver {
    fn absolute_external_components(
        &self,
        _file: &ProjectFile,
        _name: &str,
    ) -> Option<Vec<String>> {
        None
    }

    fn glob_name_absent(
        &self,
        _file: &ProjectFile,
        _import: &brokk_bifrost_core::analyzer::model::ImportInfo,
        _namespace: brokk_bifrost_rust::graph_support::RustGlobNamespace,
        _name: &str,
    ) -> bool {
        false
    }

    fn nominal_type_owner<'tree>(
        &self,
        file: &ProjectFile,
        source: &str,
        ty: Node<'tree>,
    ) -> Option<(String, Vec<Node<'tree>>)>;
    fn modeled_receiver_type(&self, file: &ProjectFile, expression: Node<'_>) -> Option<TypeRef>;
    #[allow(clippy::too_many_arguments)]
    fn select_member(
        &self,
        _analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        site: &ResolvedReferenceSite,
        owner: &str,
        has_receiver: bool,
        parameter_count: u32,
        receiver_application: Option<&TypeRef>,
    ) -> Option<super::modeled_members::SelectedMember>;
    fn import_infos(
        &self,
        file: &ProjectFile,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ImportInfo>>;

    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome>;

    fn external_call_identity(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
        callee_start_byte: usize,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity>;

    fn cancellation(&self) -> Option<&brokk_bifrost_core::cancellation::CancellationToken>;

    fn budget(&self) -> ReceiverAnalysisBudget {
        INTERACTIVE_TYPE_LOOKUP_BUDGET
    }
}

impl<T: RustTypeProofResolver + ?Sized> RustTypeProofResolver for &T {
    fn glob_name_absent(
        &self,
        file: &ProjectFile,
        import: &brokk_bifrost_core::analyzer::model::ImportInfo,
        namespace: brokk_bifrost_rust::graph_support::RustGlobNamespace,
        name: &str,
    ) -> bool {
        (**self).glob_name_absent(file, import, namespace, name)
    }

    fn absolute_external_components(&self, file: &ProjectFile, name: &str) -> Option<Vec<String>> {
        (**self).absolute_external_components(file, name)
    }

    fn nominal_type_owner<'tree>(
        &self,
        file: &ProjectFile,
        source: &str,
        ty: Node<'tree>,
    ) -> Option<(String, Vec<Node<'tree>>)> {
        (**self).nominal_type_owner(file, source, ty)
    }

    fn modeled_receiver_type(&self, file: &ProjectFile, expression: Node<'_>) -> Option<TypeRef> {
        (**self).modeled_receiver_type(file, expression)
    }

    fn select_member(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        site: &ResolvedReferenceSite,
        owner: &str,
        has_receiver: bool,
        parameter_count: u32,
        receiver_application: Option<&TypeRef>,
    ) -> Option<super::modeled_members::SelectedMember> {
        (**self).select_member(
            analyzer,
            file,
            source,
            site,
            owner,
            has_receiver,
            parameter_count,
            receiver_application,
        )
    }

    fn import_infos(
        &self,
        file: &ProjectFile,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ImportInfo>> {
        (**self).import_infos(file, token)
    }

    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        (**self).resolve(query)
    }

    fn external_call_identity(&self, file: &ProjectFile, source: &str, tree: &Tree, site: &ResolvedReferenceSite, callee_start_byte: usize) -> Option<brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity>{
        (**self).external_call_identity(file, source, tree, site, callee_start_byte)
    }

    fn cancellation(&self) -> Option<&brokk_bifrost_core::cancellation::CancellationToken> {
        (**self).cancellation()
    }

    fn budget(&self) -> ReceiverAnalysisBudget {
        (**self).budget()
    }
}

type RustProofOperation<'a> =
    brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
        'a,
        'a,
    >;

fn selected_glob_name_absent(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    import: &brokk_bifrost_core::analyzer::model::ImportInfo,
    namespace: brokk_bifrost_rust::graph_support::RustGlobNamespace,
    name: &str,
) -> bool {
    use brokk_bifrost_rust::graph_support::{RustFactSource, RustGlobNameAbsence};
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer).expect("Rust proof requires Rust");
    let Ok(_frame) = rust
        .operation_read_frame(operation)
        .map_err(|error| rust.inner.record_store_error(error))
    else {
        return false;
    };
    rust.local_glob_name_absence(file, import, namespace, name) == RustGlobNameAbsence::ClosedAbsent
}

pub(crate) struct FactoryRustTypeProofResolver<'a> {
    analyzer: &'a dyn IAnalyzer,
    definition_operation_factory:
        crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'a>,
    // Structural facts do not need a selected declaration reader.
    operation: RefCell<Option<RustProofOperation<'a>>>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<CancellationToken>,
}

impl<'a> FactoryRustTypeProofResolver<'a> {
    fn operation(
        &self,
    ) -> Result<
        std::cell::RefMut<'_, RustProofOperation<'a>>,
        crate::analyzer::rust::native_points::RustDefinitionOperationOpenFailure,
    > {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;
        let mut operation = self.operation.borrow_mut();
        if operation.is_none() {
            let cancellation = self.cancellation.clone().unwrap_or_default();
            let cpu = crate::profiling::enabled().then(crate::profiling::thread_cpu_time);
            let opened = self.factory().open(&cancellation);
            if let Some(cpu) = cpu {
                crate::profiling::note(format!(
                    "inert_drop.factory_open calls=1 cpu_ns={}",
                    crate::profiling::thread_cpu_time()
                        .saturating_sub(cpu)
                        .as_nanos()
                ));
            }
            match opened {
                Ok(SelectedResolutionOperationOpenOutcome::Ready(opened)) => {
                    *operation = Some(*opened)
                }
                outcome => {
                    // The eager open this replaced recorded the same stop when
                    // the operation could not open, so a caller that maps the
                    // failure to None still leaves the proof incomplete.
                    operational_proof_stop(
                        "analyzer_unavailable",
                        DerivationExecutionCause::Provider,
                    );
                    return Err(crate::analyzer::rust::native_points::RustDefinitionOperationOpenFailure::from_open_outcome(outcome));
                }
            }
        }
        Ok(std::cell::RefMut::map(operation, |operation| {
            operation
                .as_mut()
                .expect("selected proof operation was opened")
        }))
    }

    fn factory(&self) -> &crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'a> {
        &self.definition_operation_factory
    }
}

impl RustTypeProofResolver for FactoryRustTypeProofResolver<'_> {
    fn glob_name_absent(
        &self,
        file: &ProjectFile,
        import: &brokk_bifrost_core::analyzer::model::ImportInfo,
        namespace: brokk_bifrost_rust::graph_support::RustGlobNamespace,
        name: &str,
    ) -> bool {
        let Ok(operation) = self.operation() else {
            return false;
        };
        selected_glob_name_absent(self.analyzer, &operation, file, import, namespace, name)
    }

    fn absolute_external_components(&self, file: &ProjectFile, name: &str) -> Option<Vec<String>> {
        // The operation opens lazily; a failed open has already recorded its
        // operational proof stop, so the root stays unproven.
        crate::analyzer::rust::external_calls::absolute_external_components(
            self.analyzer,
            &*self.operation().ok()?,
            file,
            name,
            self.cancellation(),
        )
    }

    fn nominal_type_owner<'tree>(
        &self,
        file: &ProjectFile,
        source: &str,
        ty: Node<'tree>,
    ) -> Option<(String, Vec<Node<'tree>>)> {
        rust_nominal_receiver_application_with_operation(
            self.analyzer,
            file,
            source,
            ty,
            self.factory(),
            &mut *self.operation().ok()?,
            self.cancellation(),
        )
    }

    fn modeled_receiver_type(&self, file: &ProjectFile, expression: Node<'_>) -> Option<TypeRef> {
        let proof = RustTypeProof {
            drop_inventory: None,
            analyzer: self.analyzer,
            rust: resolve_analyzer::<RustAnalyzer>(self.analyzer)?,
            resolver: self,
        };
        proof.modeled_receiver_type(file, expression)
    }
    fn select_member(
        &self,
        _analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        site: &ResolvedReferenceSite,
        owner: &str,
        has_receiver: bool,
        parameter_count: u32,
        receiver_application: Option<&TypeRef>,
    ) -> Option<super::modeled_members::SelectedMember> {
        super::modeled_members::select(
            self.analyzer,
            file,
            source,
            site,
            owner,
            has_receiver,
            parameter_count,
            self.factory(),
            &mut *self.operation().ok()?,
            None,
            receiver_application,
            self.cancellation.as_ref(),
        )
    }
    fn import_infos(
        &self,
        file: &ProjectFile,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ImportInfo>> {
        Some(
            self.analyzer
                .import_analysis_provider_for_file(file)
                .map(|provider| provider.import_info_of(token, file))
                .unwrap_or_default(),
        )
    }

    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        let mut operation = match self.operation() {
            Ok(operation) => operation,
            Err(failure) => {
                return crate::analyzer::rust::native_points::resolve_rust_definition_open_failure_for_batch(query, &failure);
            }
        };
        self.factory().resolve(&mut operation, query)
    }

    fn external_call_identity(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
        callee_start_byte: usize,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity>{
        resolve_external_call_identity(
            self.analyzer,
            file,
            source,
            tree,
            site,
            callee_start_byte,
            self.factory(),
            &mut *self.operation().ok()?,
            None,
        )
    }

    fn cancellation(&self) -> Option<&brokk_bifrost_core::cancellation::CancellationToken> {
        self.cancellation.as_ref()
    }

    fn budget(&self) -> ReceiverAnalysisBudget {
        self.budget
    }
}

struct SelectedRustTypeProofResolver<'analyzer, 'factory, 'selection, 'operation, 'cancellation> {
    analyzer: &'analyzer dyn IAnalyzer,
    factory: &'factory crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: RefCell<
        &'operation mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
    cancellation: Option<&'cancellation brokk_bifrost_core::cancellation::CancellationToken>,
}

impl RustTypeProofResolver for SelectedRustTypeProofResolver<'_, '_, '_, '_, '_> {
    fn glob_name_absent(
        &self,
        file: &ProjectFile,
        import: &brokk_bifrost_core::analyzer::model::ImportInfo,
        namespace: brokk_bifrost_rust::graph_support::RustGlobNamespace,
        name: &str,
    ) -> bool {
        selected_glob_name_absent(
            self.analyzer,
            &self.operation.borrow(),
            file,
            import,
            namespace,
            name,
        )
    }

    fn absolute_external_components(&self, file: &ProjectFile, name: &str) -> Option<Vec<String>> {
        crate::analyzer::rust::external_calls::absolute_external_components(
            self.analyzer,
            &self.operation.borrow(),
            file,
            name,
            self.cancellation,
        )
    }

    fn nominal_type_owner<'tree>(
        &self,
        file: &ProjectFile,
        source: &str,
        ty: Node<'tree>,
    ) -> Option<(String, Vec<Node<'tree>>)> {
        let mut operation = self.operation.borrow_mut();
        rust_nominal_receiver_application_with_operation(
            self.analyzer,
            file,
            source,
            ty,
            self.factory,
            &mut operation,
            self.cancellation,
        )
    }

    fn modeled_receiver_type(&self, file: &ProjectFile, expression: Node<'_>) -> Option<TypeRef> {
        let mut operation = self.operation.borrow_mut();
        rust_modeled_receiver_type_with_operation(
            self.analyzer,
            file,
            expression,
            self.factory,
            &mut operation,
        )
    }
    fn select_member(
        &self,
        _analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        site: &ResolvedReferenceSite,
        owner: &str,
        has_receiver: bool,
        parameter_count: u32,
        receiver_application: Option<&TypeRef>,
    ) -> Option<super::modeled_members::SelectedMember> {
        let mut operation = self.operation.borrow_mut();
        super::modeled_members::select(
            self.analyzer,
            file,
            source,
            site,
            owner,
            has_receiver,
            parameter_count,
            self.factory,
            &mut operation,
            None,
            receiver_application,
            self.cancellation,
        )
    }
    fn import_infos(
        &self,
        file: &ProjectFile,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ImportInfo>> {
        let cancellation = self.cancellation.cloned().unwrap_or_default();
        selected_import_infos(self.analyzer, &self.operation.borrow(), file, &cancellation)
    }

    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        let mut operation = self.operation.borrow_mut();
        self.factory.resolve(&mut operation, query)
    }

    fn external_call_identity(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
        callee_start_byte: usize,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity>{
        let mut operation = self.operation.borrow_mut();
        resolve_external_call_identity(
            self.analyzer,
            file,
            source,
            tree,
            site,
            callee_start_byte,
            self.factory,
            &mut operation,
            self.cancellation,
        )
    }

    fn cancellation(&self) -> Option<&brokk_bifrost_core::cancellation::CancellationToken> {
        self.cancellation
    }
}

pub(crate) fn model_proof_resolver<
    'analyzer: 'operation,
    'factory: 'operation,
    'selection,
    'operation,
>(
    analyzer: &'analyzer dyn IAnalyzer,
    factory: &'factory crate::analyzer::rust::native_points::RustDefinitionOperationFactory<
        'analyzer,
    >,
    operation: &'operation mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
) -> Option<Box<dyn RustTypeProofResolver + 'operation>> {
    Some(Box::new(SelectedRustTypeProofResolver {
        analyzer,
        factory,
        operation: RefCell::new(operation),
        cancellation: None,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_external_call_identity<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    callee_start_byte: usize,
    factory: &'factory crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity>{
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    crate::analyzer::rust::external_calls::resolve_exact_rust_external_call_with_operation(
        analyzer,
        token,
        file,
        source,
        tree,
        site,
        || None,
        cancellation,
        factory,
        &mut *operation,
    )
    .map(|(_, identity)| identity)
    .or_else(|| {
        let file_evidence = ExternalCalleeFileEvidence::default();
        let external_site = ExternalCalleeSite {
            source,
            tree,
            callee_start_byte,
            file_evidence: &file_evidence,
        };
        crate::analyzer::rust::expand_rust_imported_external_callee_with_operation(
            analyzer,
            file,
            "",
            Some(&external_site),
            factory,
            operation,
        )
        .and_then(|callee| callee.external_callee_identity)
    })
}

/// The standard `Result` variant named by a pattern constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustResultVariant {
    Ok,
    Err,
}

/// The language-native result obligation proof for one resolved Rust call
/// target. `Open` deliberately carries a stable transport reason rather than
/// collapsing an unresolved declaration into a clean result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustNativeObligationProof {
    Obligation(NativeResultObligation),
    NoObligation,
    Open(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustNativeReturnKind {
    FallibleResult,
    MustUseValue,
    OrdinaryValue,
    Open(&'static str),
}

/// Resolve a Rust pattern constructor to the standard-library `Result`
/// variant it names. Bare constructors require the resolver's prelude proof;
/// qualified constructors require the owner type to resolve to the standard
/// `Result` prelude item. A workspace declaration, import route, lexical
/// shadow, or unresolved lookup therefore stays open.
/// Proves which standard `Result` variant the pattern constructors of one
/// file name.
///
/// One selected resolution operation answers every constructor of the file.
/// The operation owns its derive-helper decisions, macro frontiers and typed
/// root memo, so opening one operation per constructor repeated that setup at
/// every site; on a 9,000-line file that cost hundreds of milliseconds per
/// constructor (#8853).
pub(crate) struct RustResultVariantProver<'a> {
    proof: RustTypeProof<'a>,
    source: RustSource,
}

impl<'a> RustResultVariantProver<'a> {
    /// `None` when no proof can run against `file`; a stale or unavailable
    /// source also stops the active proof attempt.
    pub(crate) fn new(
        analyzer: &'a dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Option<Self> {
        let proof = RustTypeProof::new(analyzer)?;
        let rust_source = proof.source(file)?;
        if rust_source.text() != source {
            // Within one snapshot the caller's text equals the prepared text, so a
            // mismatch means one side is stale: an operational state, not content.
            operational_proof_stop("source_mismatch", DerivationExecutionCause::Provider);
            return None;
        }
        Some(Self {
            proof,
            source: rust_source,
        })
    }

    /// The standard `Result` variant the constructor at `constructor` names.
    pub(crate) fn variant(&self, constructor: ByteRange<usize>) -> Option<RustResultVariant> {
        let rust_source = &self.source;
        let node = rust_source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(constructor.start, constructor.end)
            .filter(|node| node.byte_range() == constructor)?;
        let fact = self.proof.standard_constructor_fact(rust_source, node)?;
        if fact.constructs != "Result" || fact.arity != 1 {
            return None;
        }
        match fact.name {
            "Ok" => Some(RustResultVariant::Ok),
            "Err" => Some(RustResultVariant::Err),
            _ => None,
        }
    }
}

fn standard_result_prelude_name<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    source: &RustSource,
    node: Node<'_>,
    namespace: &str,
    expected: &str,
) -> Option<String> {
    let outcome = proof.resolve(source, node)?;
    if prelude_item_of(&outcome, namespace).as_deref() == Some(expected) {
        return Some(expected.to_owned());
    }
    // A pattern constructor has a Pattern resolution site rather than the
    // ordinary value-reference site used by calls. The selected resolver
    // still proves the important negative facts at that site: no workspace
    // definition, lexical binding, or import claim. With the reviewed Result
    // constructor table, that boundary is the implicit core/std prelude.
    (outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
        && source.node_text(node) == Some(expected)
        && outcome.definitions.is_empty()
        && outcome.lexical_definition.is_none()
        && outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.claim.is_none()))
    .then(|| expected.to_owned())
}

fn standard_result_type_path<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    source: &RustSource,
    path: Node<'_>,
) -> Option<()> {
    let segments = rust_path_segments(path)?;
    let names = segments
        .iter()
        .map(|segment| source.node_text(*segment))
        .collect::<Option<Vec<_>>>()?;
    // `path` names the `Result` type itself: the owner of a variant path
    // (`std::result::Result` in `std::result::Result::Err`) or a whole type
    // path (`std::result::Result` in a return type).
    match names.as_slice() {
        ["Result"] => {
            standard_result_prelude_name(proof, source, segments[0], "type", "Result")?;
            Some(())
        }
        [root @ ("std" | "core"), "result", "Result"] => {
            let root_outcome = proof.resolve(source, segments[0])?;
            (root_outcome.definitions.is_empty()
                && root_outcome.lexical_definition.is_none()
                && !root_outcome
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.claim.is_some())
                && matches!(
                    root_outcome.status,
                    DefinitionLookupStatus::Incomplete
                        | DefinitionLookupStatus::UnresolvableImportBoundary
                )
                && source.node_text(segments[0]) == Some(root))
            .then_some(())
        }
        _ => None,
    }
}

impl<'a> RustTypeProof<'a, FactoryRustTypeProofResolver<'a>> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let initialized = (|| {
            let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
            let cancellation = CancellationToken::default();
            let factory =
                crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
                    analyzer,
                    &cancellation,
                )?;
            Some((rust, factory))
        })();
        let Some((rust, factory)) = initialized else {
            operational_proof_stop("analyzer_unavailable", DerivationExecutionCause::Provider);
            return None;
        };
        Some(Self {
            drop_inventory: None,
            analyzer,
            rust,
            resolver: FactoryRustTypeProofResolver {
                analyzer,
                definition_operation_factory: factory,
                operation: RefCell::new(None),
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: None,
            },
        })
    }
}

impl<'a, R: RustTypeProofResolver> RustTypeProof<'a, R> {
    /// One structured constructor proof shared by patterns and selected payloads.
    fn standard_constructor_fact(
        &self,
        source: &RustSource,
        node: Node<'_>,
    ) -> Option<&'static brokk_bifrost_rust::prelude::RustStdConstructorFact> {
        let name_node = match node.kind() {
            "identifier" | "type_identifier" => node,
            "scoped_identifier" | "scoped_type_identifier" => node.child_by_field_name("name")?,
            _ => return None,
        };
        let fact = rust_std_constructor_fact(source.node_text(name_node)?)?;
        match node.kind() {
            "identifier" | "type_identifier" => {
                standard_result_prelude_name(self, source, node, "value", fact.name)?;
            }
            _ => {
                let owner = node.child_by_field_name("path")?;
                if fact.constructs == "Result" {
                    standard_result_type_path(self, source, owner)?;
                } else {
                    let RustReceiverOwner::Path(owner) =
                        self.declared_receiver_owner(source, owner)?
                    else {
                        return None;
                    };
                    if !matches!(owner.as_str(), "core.option.Option" | "std.option.Option") {
                        return None;
                    }
                }
            }
        }
        Some(fact)
    }

    fn completed_attempt<T>(&self, proof: impl FnOnce() -> Option<T>) -> RustProofAttempt<T> {
        completed_proof(self.analyzer, self.resolver.cancellation(), proof)
    }

    fn source(&self, file: &ProjectFile) -> Option<RustSource> {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let Some(prepared) = self.rust.prepared_syntax(scope.token(), file) else {
            // Missing prepared syntax can be transient (#11408).
            operational_proof_stop("source_unavailable", DerivationExecutionCause::Provider);
            return None;
        };
        let macro_inventory = brokk_bifrost_rust::macro_matcher::MacroDefinitionInventory::build(
            prepared.tree(),
            prepared.source(),
            &|| {
                !self
                    .resolver
                    .cancellation()
                    .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
            },
        );
        let macro_inventory = match macro_inventory {
            Ok(inventory) => inventory,
            Err(error) => {
                debug_assert!(matches!(
                    error,
                    brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled
                ));
                operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
                return None;
            }
        };
        Some(RustSource {
            macro_inventory,
            file: file.clone(),
            prepared,
            expression_classes: RefCell::new(HashMap::new()),
            modeled_call_shapes: RefCell::new(HashMap::new()),
            #[cfg(test)]
            expression_class_evaluations: Cell::new(0),
            #[cfg(test)]
            expression_class_evaluation_limit: Cell::new(None),
            #[cfg(test)]
            modeled_call_shape_evaluations: Cell::new(0),
            #[cfg(test)]
            modeled_call_shape_evaluation_limit: Cell::new(None),
        })
    }

    /// The resolver's complete answer for the name `node` spells.
    fn resolve(&self, source: &RustSource, node: Node<'_>) -> Option<DefinitionLookupOutcome> {
        // The resolver records a scoped path's reference at its last segment.
        let node = match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => node.child_by_field_name("name")?,
            _ => node,
        };
        let text = source.node_text(node)?.to_owned();
        let site = ResolvedReferenceSite {
            path: text.clone(),
            text,
            range: node_range(node),
            focus_start_byte: node.start_byte(),
            focus_end_byte: node.end_byte(),
        };
        let query = BoundedReceiverQuery {
            analyzer: self.analyzer,
            file: &source.file,
            source: source.text(),
            tree: Some(source.tree()),
            site: &site,
            budget: self.resolver.budget(),
            cancellation: None,
        };
        let resolution = self.resolver.resolve(BoundedReceiverQuery {
            cancellation: self.resolver.cancellation(),
            ..query
        });
        observe_proof_resolution(&resolution);
        match resolution {
            BoundedResolution::Complete { value, .. } => Some(value),
            BoundedResolution::Exceeded { .. }
            | BoundedResolution::Unavailable { .. }
            | BoundedResolution::Cancelled { .. } => None,
        }
    }

    /// The `std` or `core` prelude item the name at `node` resolves to, when
    /// the resolver proves that and nothing else: no workspace declaration,
    /// no lexical binding, no `use` route, and exactly one prelude reason in
    /// `namespace` (`"type"` or `"value"`).
    fn prelude_item(&self, source: &RustSource, node: Node<'_>, namespace: &str) -> Option<String> {
        let item = prelude_item_of(&self.resolve(source, node)?, namespace)?;
        if matches!(node.kind(), "identifier" | "type_identifier")
            && !self.prelude_name_is_unbound(source, node.start_byte(), &item, namespace)
        {
            return None;
        }
        Some(item)
    }

    /// Exclude lexical and import competitors for a prelude name at a site,
    /// including an implicit trait name that has no written reference node.
    fn prelude_name_is_unbound(
        &self,
        source: &RustSource,
        reference_byte: usize,
        name: &str,
        namespace: &str,
    ) -> bool {
        use brokk_bifrost_rust::graph_support::RustGlobNamespace;
        let glob_namespace = match namespace {
            "type" => Some(RustGlobNamespace::Type),
            // The store has no value-namespace glob absence proof.
            "value" => None,
            "macro" => Some(RustGlobNamespace::Macro),
            _ => unreachable!("prelude namespace must be type, value or macro"),
        };
        brokk_bifrost_rust::lexical_scope::prelude_name_is_unbound_with(
            self.rust.inner.adapter().lexical_caches(),
            source.tree().root_node(),
            source.text(),
            reference_byte,
            name,
            |import| {
                glob_namespace.is_some_and(|namespace| {
                    self.resolver
                        .glob_name_absent(&source.file, import, namespace, name)
                })
            },
        )
    }

    /// The one workspace declaration the name at `node` resolves to.
    fn workspace_definition(&self, source: &RustSource, node: Node<'_>) -> Option<CodeUnit> {
        let outcome = self.resolve(source, node)?;
        match (
            outcome.status,
            outcome.definitions.as_slice(),
            outcome.lexical_definition,
        ) {
            (DefinitionLookupStatus::Resolved, [definition], None) => Some(definition.clone()),
            _ => None,
        }
    }

    /// The declaration node of a workspace unit in its own file.
    fn declaration<'s>(&self, source: &'s RustSource, unit: &CodeUnit) -> Option<Node<'s>> {
        let ranges = self.rust.ranges_limited(unit, 2);
        let [range] = ranges.rows.as_slice() else {
            return None;
        };
        if !ranges.complete {
            return None;
        }
        let node = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        (node.byte_range() == (range.start_byte..range.end_byte)).then_some(node)
    }

    /// Return the trait method whose signature governs an implementation
    /// member, when the hierarchy index proves that relationship. Trait
    /// attributes are not inherited by the implementation AST, so native
    /// obligation proof must read the trait declaration itself.
    fn trait_signature_target(&self, target: &CodeUnit) -> Result<Option<CodeUnit>, &'static str> {
        if !target.is_function() {
            return Ok(None);
        }
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let trait_owner = brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
            self.rust,
            scope.token(),
            target,
        )
        .map_err(|error| {
            use brokk_bifrost_rust::graph_support::RustCargoRouteError;
            operational_proof_stop(
                match error {
                    RustCargoRouteError::Cancelled => "Cancelled",
                    RustCargoRouteError::Unavailable => "Unavailable",
                },
                cargo_route_execution_cause(&error),
            );
            "native_trait_signature_unknown"
        })?;
        let Some(trait_owner) = trait_owner else {
            return Ok(None);
        };
        let candidates = self
            .rust
            .get_direct_children(&trait_owner)
            .into_iter()
            .filter(|child| child.is_function() && child.identifier() == target.identifier())
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [candidate] => Ok(Some(candidate.clone())),
            _ => Err("native_trait_signature_unknown"),
        }
    }

    /// Classify the declared result type of one Rust callable. The returned
    /// type is intentionally structural: aliases are followed only through
    /// workspace declarations, and an unresolved or generic type stays open.
    fn native_return_kind(
        &self,
        source: &RustSource,
        ty: Option<Node<'_>>,
        depth: usize,
    ) -> RustNativeReturnKind {
        let Some(ty) = ty else {
            return RustNativeReturnKind::OrdinaryValue;
        };
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustNativeReturnKind::Open("native_return_type_depth");
        }
        match ty.kind() {
            // These types carry no language-level `must_use` obligation of
            // their own. A declaration-level attribute is checked by the
            // caller after this classification.
            "primitive_type" | "unit_type" | "never_type" | "reference_type" | "pointer_type"
            | "tuple_type" | "array_type" | "function_type" | "raw_string_literal" => {
                RustNativeReturnKind::OrdinaryValue
            }
            "type_identifier" | "scoped_type_identifier" => {
                self.native_nominal_return_kind(source, ty, depth)
            }
            "generic_type" => {
                let Some(name) = ty.child_by_field_name("type") else {
                    return RustNativeReturnKind::Open("native_return_type_unknown");
                };
                self.native_nominal_return_kind(source, name, depth)
            }
            // `impl Trait`, `dyn Trait`, higher-ranked types, and any syntax
            // the grammar does not expose as a nominal declaration require a
            // reviewed model before a discarded value can be classified.
            _ => RustNativeReturnKind::Open("native_return_type_unknown"),
        }
    }

    fn native_nominal_return_kind(
        &self,
        source: &RustSource,
        name: Node<'_>,
        depth: usize,
    ) -> RustNativeReturnKind {
        if self.standard_result_type(source, name) {
            return RustNativeReturnKind::FallibleResult;
        }
        if let Some(unit) = self.workspace_definition(source, name) {
            return self.workspace_return_kind(&unit, depth - 1);
        }
        if self.external_result_alias(source, name) {
            return RustNativeReturnKind::FallibleResult;
        }
        if name.kind() == "type_identifier" && self.prelude_item(source, name, "type").is_some() {
            // The standard-library types which carry `#[must_use]` need a
            // reviewed model of their semantics. The Rust B4 lane claims no
            // such external type merely from its spelling.
            return RustNativeReturnKind::Open("native_std_type_unmodeled");
        }
        RustNativeReturnKind::Open("native_return_type_unresolved")
    }

    /// For an unqualified identifier, the unresolved-prelude fallback assumes
    /// the caller already checked that its spelling is Result. Callers that
    /// classify more than one standard family must check that precondition;
    /// scoped paths are checked structurally by standard_result_type_path.
    fn standard_result_type(&self, source: &RustSource, name: Node<'_>) -> bool {
        match name.kind() {
            "type_identifier" => {
                standard_result_prelude_name(self, source, name, "type", "Result").is_some()
            }
            "scoped_type_identifier" => standard_result_type_path(self, source, name).is_some(),
            _ => false,
        }
    }

    /// The resolver may expose an external alias without a materialized
    /// declaration. Accept only the exact standard Result aliases that the
    /// resolver names; an arbitrary `io::Result` remains open.
    fn external_result_alias(&self, source: &RustSource, name: Node<'_>) -> bool {
        self.resolve(source, name)
            .as_ref()
            .and_then(standard_wrapper_owner)
            .is_some_and(|path| path.last().is_some_and(|name| name == "Result"))
    }

    fn workspace_return_kind(&self, unit: &CodeUnit, depth: usize) -> RustNativeReturnKind {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustNativeReturnKind::Open("native_return_type_depth");
        }
        let Some(source) = self.source(unit.source()) else {
            return RustNativeReturnKind::Open("native_return_type_source");
        };
        let Some(item) = self.declaration(&source, unit) else {
            return RustNativeReturnKind::Open("native_return_type_declaration");
        };
        if item.kind() == "type_item" {
            let kind =
                self.native_return_kind(&source, item.child_by_field_name("type"), depth - 1);
            return match kind {
                RustNativeReturnKind::FallibleResult => kind,
                RustNativeReturnKind::Open(reason) => RustNativeReturnKind::Open(reason),
                RustNativeReturnKind::MustUseValue | RustNativeReturnKind::OrdinaryValue
                    if item_has_path_attribute(item, source.text(), "must_use") =>
                {
                    RustNativeReturnKind::MustUseValue
                }
                _ => kind,
            };
        }
        if matches!(item.kind(), "struct_item" | "enum_item" | "union_item") {
            return if item_has_path_attribute(item, source.text(), "must_use") {
                RustNativeReturnKind::MustUseValue
            } else {
                RustNativeReturnKind::OrdinaryValue
            };
        }
        RustNativeReturnKind::Open("native_return_type_declaration")
    }

    fn native_obligation_for_target(
        &self,
        target: &CodeUnit,
        result_ordinal: u32,
    ) -> RustNativeObligationProof {
        if target.source().declaration_language() != Language::Rust {
            return RustNativeObligationProof::Open("native_target_language");
        }
        if result_ordinal != 0 {
            return RustNativeObligationProof::NoObligation;
        }
        let Some(source) = self.source(target.source()) else {
            return RustNativeObligationProof::Open("native_target_source");
        };
        let Some(item) = self.declaration(&source, target) else {
            return RustNativeObligationProof::Open("native_target_declaration");
        };
        let signature_target = match self.trait_signature_target(target) {
            Ok(signature_target) => signature_target,
            Err(reason) => return RustNativeObligationProof::Open(reason),
        };
        if let Some(signature_target) = signature_target {
            let Some(signature_source) = self.source(signature_target.source()) else {
                return RustNativeObligationProof::Open("native_trait_signature_source");
            };
            let Some(signature_item) = self.declaration(&signature_source, &signature_target)
            else {
                return RustNativeObligationProof::Open("native_trait_signature_declaration");
            };
            return self.native_obligation_for_declaration(
                &signature_source,
                signature_item,
                result_ordinal,
            );
        }
        self.native_obligation_for_declaration(&source, item, result_ordinal)
    }

    fn native_obligation_for_declaration(
        &self,
        source: &RustSource,
        item: Node<'_>,
        result_ordinal: u32,
    ) -> RustNativeObligationProof {
        let return_kind =
            self.native_return_kind(source, item.child_by_field_name("return_type"), PROOF_DEPTH);
        match return_kind {
            // Result is always B5, even if the callable or alias also carries
            // `#[must_use]`; the two policies must never double-report.
            RustNativeReturnKind::FallibleResult => {
                RustNativeObligationProof::Obligation(NativeResultObligation::fallible_status(
                    result_ordinal,
                    NativeResultObligationBasis::StaticSignature,
                ))
            }
            RustNativeReturnKind::Open(reason) => RustNativeObligationProof::Open(reason),
            RustNativeReturnKind::MustUseValue => {
                RustNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                    result_ordinal,
                    NativeResultObligationBasis::StaticSignature,
                ))
            }
            RustNativeReturnKind::OrdinaryValue => {
                if item_has_path_attribute(item, source.text(), "must_use") {
                    RustNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                        result_ordinal,
                        NativeResultObligationBasis::StaticSignature,
                    ))
                } else {
                    RustNativeObligationProof::NoObligation
                }
            }
        }
    }

    /// The class of the declared type `ty`, written in `source`.
    fn type_class(&self, source: &RustSource, ty: Node<'_>, depth: usize) -> RustValueClass {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustValueClass::Unknown;
        }
        match ty.kind() {
            "reference_type" => {
                let referent = ty.child_by_field_name("type");
                if referent.is_some_and(|referent| {
                    referent.kind() == "primitive_type" && source.node_text(referent) == Some("str")
                }) {
                    RustValueClass::Str
                } else {
                    RustValueClass::Inert
                }
            }
            "pointer_type" | "primitive_type" | "unit_type" | "never_type" | "function_type" => {
                RustValueClass::Inert
            }
            "tuple_type" | "array_type" => {
                let elements = if ty.kind() == "array_type" {
                    ty.child_by_field_name("element").into_iter().collect()
                } else {
                    named_children(ty)
                };
                if elements
                    .into_iter()
                    .all(|element| self.type_class(source, element, depth - 1).is_inert())
                {
                    RustValueClass::Inert
                } else {
                    RustValueClass::Unknown
                }
            }
            "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                self.nominal_type_class(source, ty, depth)
            }
            _ => RustValueClass::Unknown,
        }
    }

    fn nominal_type_class(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let (name, arguments) = if ty.kind() == "generic_type" {
            let Some(name) = ty.child_by_field_name("type") else {
                return RustValueClass::Unknown;
            };
            let arguments = ty
                .child_by_field_name("type_arguments")
                .map(named_children)
                .unwrap_or_default();
            (name, arguments)
        } else {
            (ty, Vec::new())
        };
        // A lifetime argument names no value and drops nothing.
        let arguments = arguments
            .into_iter()
            .filter(|argument| argument.kind() != "lifetime")
            .collect::<Vec<_>>();
        if name.kind() == "type_identifier"
            && let Some(prelude) = self.prelude_item(source, name, "type")
            && let Some(fact) = rust_std_type_fact(&prelude)
        {
            if arguments.len() != fact.type_arguments
                || !arguments
                    .iter()
                    .all(|argument| self.type_class(source, *argument, depth - 1).is_inert())
            {
                return RustValueClass::Unknown;
            }
            return if fact.name == "String" {
                RustValueClass::String
            } else {
                RustValueClass::Inert
            };
        }
        if self.standard_result_type(source, name) {
            return if arguments.len() == 2
                && arguments
                    .iter()
                    .all(|argument| self.type_class(source, *argument, depth - 1).is_inert())
            {
                RustValueClass::Inert
            } else {
                RustValueClass::Unknown
            };
        }
        if arguments.is_empty()
            && let Some(unit) = self.workspace_definition(source, name)
        {
            return if self.workspace_type_is_inert(&unit, depth - 1) {
                RustValueClass::Inert
            } else {
                RustValueClass::Unknown
            };
        }
        self.modeled_nominal_type_class(source, ty, depth)
    }

    /// The class of a written application of an activated model type, from
    /// the model's reviewed drop glue (#9057). Every written argument and
    /// every defaulted one the application omits must be inert too.
    fn modeled_nominal_type_class(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let Some((owner, arguments)) = self.nominal_type_owner(source, ty) else {
            return RustValueClass::Unknown;
        };
        let Some(declaration) = self
            .analyzer
            .semantic_model_overlay_read()
            .published()
            .and_then(|overlay| {
                overlay
                    .symbols_named_in_family(&owner, "rust", SemanticModelNamespace::TypeOrModule)
                    .unique()
            })
            .and_then(|symbol| self.modeled_inert_drop_glue_owner(&symbol))
        else {
            return RustValueClass::Unknown;
        };
        let written_inert = arguments
            .iter()
            .all(|argument| self.type_class(source, *argument, depth - 1).is_inert());
        // Owner identity permits inferred arguments, but an inert-drop proof
        // needs each argument's class. Missing arguments remain unknown here.
        let defaults_inert = (arguments.len()..declaration.type_parameters.len()).all(|index| {
            match declaration
                .type_parameter_defaults
                .get(index)
                .and_then(Option::as_ref)
            {
                Some(GenericParameterDefault::Type { r#type }) => self
                    .type_ref_class(r#type, depth - 1)
                    .is_some_and(RustValueClass::is_inert),
                _ => {
                    incomplete_proof("external_receiver_type_arguments_unknown");
                    false
                }
            }
        });
        if written_inert && defaults_inert {
            RustValueClass::Inert
        } else {
            RustValueClass::Unknown
        }
    }

    /// The selected declaration of the activated Rust model type `symbol`
    /// when that model reviews the type's own drop glue as inert (#9057). A
    /// generic application's type arguments are the caller's to prove.
    fn modeled_inert_drop_glue_owner(&self, symbol: &SemanticModelSymbol) -> Option<Arc<TypeFact>> {
        if symbol.provenance.ambiguous || symbol.language != Language::Rust.config_label() {
            return None;
        }
        let active = self.analyzer.active_semantic_models()?;
        brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
            &active, symbol,
        )
        .filter(|declaration| {
            let Some(semantics) = declaration.value_semantics.as_ref() else {
                return false;
            };
            if semantics.drop_review.is_some() {
                // Scope selection is integrated in checkpoint 1 slice B. The
                // legacy reader must never ignore a new review's restrictions.
                incomplete_proof("drop_review_scope_admission_pending");
                return false;
            }
            semantics.drop_glue == Some(TypeDropGlue::Inert)
        })
    }

    /// Admit only unconditional bare derives with certified macro-prelude authority.
    fn workspace_attributes_preserve_drop(&self, source: &RustSource, item: Node<'_>) -> bool {
        outer_attributes(item).all(|outer| {
            if !brokk_bifrost_rust::syntax::attribute_item_has_path(outer, source.text(), "derive")
            {
                return false;
            }
            let Some(arguments) = outer
                .named_child(0)
                .and_then(|attribute| attribute.child_by_field_name("arguments"))
                .filter(|arguments| arguments.kind() == "token_tree" && !arguments.has_error())
            else {
                return false;
            };
            let mut cursor = arguments.walk();
            let tokens = arguments
                .children(&mut cursor)
                .filter(|token| {
                    !matches!(token.kind(), "(" | ")" | "line_comment" | "block_comment")
                })
                .collect::<Vec<_>>();
            let mut paths = tokens.split(|token| token.kind() == ",").peekable();
            while let Some(path) = paths.next() {
                if path.is_empty() && paths.peek().is_none() {
                    continue;
                }
                // Qualified and imported derives remain blocking until their
                // selected external macro identity can be certified here.
                let [name] = path else {
                    return false;
                };
                if name.kind() != "identifier" {
                    return false;
                }
                // Selected prelude resolution does not inventory textual
                // macro_rules definitions. The existing local macro lookup
                // requires a macro_invocation node, while derive arguments
                // are tokens. Conservatively block a same-named definition
                // anywhere in this file, including conditional definitions.
                let Some(spelling) = source
                    .node_text(*name)
                    .map(brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix)
                else {
                    return false;
                };
                // A selected prelude answer alone does not exclude lexical
                // imports at derive tokens. Reuse the structured lexical use
                // projection: named imports (including aliases) and any glob
                // which may bind this name leave prelude authority unproven.
                if brokk_bifrost_rust::lexical_scope::visible_use_for_name_with(
                    self.rust.inner.adapter().lexical_caches(),
                    source.tree().root_node(),
                    source.text(),
                    name.start_byte(),
                    spelling,
                ) != brokk_bifrost_rust::lexical_scope::RustVisibleUse::Unbound
                {
                    return false;
                }
                // The file's macro inventory (built once per source) holds
                // every textual macro_rules definition, in any scope.
                if source
                    .macro_inventory
                    .defines_textual_macro_anywhere(spelling)
                {
                    return false;
                }
                let Some(identity) = self.prelude_item(source, *name, "macro") else {
                    return false;
                };
                if brokk_bifrost_rust::prelude::rust_builtin_derive(&[identity.as_str()]).is_none()
                {
                    return false;
                }
                // Drop cannot be derived. A resolved built-in derive never
                // adds drop glue; typed Drop absence and fields still decide
                // inertness after this attribute check.
            }
            true
        })
    }

    /// Whether a workspace struct or enum's drop glue runs no user code.
    fn workspace_type_is_inert(&self, unit: &CodeUnit, depth: usize) -> bool {
        if depth == 0 {
            incomplete_proof("depth_limit");
        }
        if depth == 0 || !unit.is_class() {
            return false;
        }
        let Some(source) = self.source(unit.source()) else {
            return false;
        };
        let Some(item) = self.declaration(&source, unit) else {
            return false;
        };
        if !matches!(item.kind(), "struct_item" | "enum_item")
            || brokk_bifrost_rust::syntax::rust_item_has_type_or_const_parameters(item)
            || !self.workspace_attributes_preserve_drop(&source, item)
        {
            return false;
        }
        let Some(inventory) = self.drop_inventory else {
            incomplete_proof("drop_inventory_unavailable");
            return false;
        };
        if !inventory(unit, source.text(), item.byte_range()) {
            return false;
        }
        let Some(body) = item.child_by_field_name("body") else {
            // A unit struct owns nothing.
            return item.kind() == "struct_item";
        };
        let mut field_types = Vec::new();
        let mut pending = vec![body];
        while let Some(node) = pending.pop() {
            match node.kind() {
                "field_declaration" => field_types.extend(node.child_by_field_name("type")),
                "ordered_field_declaration_list" => {
                    field_types.extend(named_children(node).into_iter().filter(|child| {
                        child.kind() != "attribute_item" && child.kind() != "visibility_modifier"
                    }))
                }
                "field_declaration_list" | "enum_variant_list" | "enum_variant" => {
                    pending.extend(named_children(node));
                }
                _ => {}
            }
        }
        field_types
            .into_iter()
            .all(|ty| self.type_class(&source, ty, depth).is_inert())
    }

    /// Type a resolved value declaration without treating its spelling as a type.
    fn workspace_value_class(&self, unit: &CodeUnit, depth: usize) -> RustValueClass {
        if self.workspace_type_is_inert(unit, depth) {
            return RustValueClass::Inert;
        }
        let Some(source) = self.source(unit.source()) else {
            return RustValueClass::Unknown;
        };
        let Some(declaration) = self.declaration(&source, unit) else {
            return RustValueClass::Unknown;
        };
        match declaration.kind() {
            "const_item" | "static_item" => declaration
                .child_by_field_name("type")
                .map_or(RustValueClass::Unknown, |ty| {
                    self.type_class(&source, ty, depth)
                }),
            "enum_variant" => {
                let mut owner = declaration.parent();
                while let Some(node) = owner {
                    if node.kind() == "enum_item" {
                        return node
                            .child_by_field_name("name")
                            .and_then(|name| self.workspace_definition(&source, name))
                            .filter(|owner| self.workspace_type_is_inert(owner, depth))
                            .map_or(RustValueClass::Unknown, |_| RustValueClass::Inert);
                    }
                    owner = node.parent();
                }
                RustValueClass::Unknown
            }
            _ => RustValueClass::Unknown,
        }
    }

    /// The class of the value `expression` evaluates to.
    fn expression_class(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let key = (expression.id(), depth);
        if let Some((class, receipt)) = source
            .expression_classes
            .borrow()
            .get(&key)
            .filter(|_| source.owns_node(expression))
        {
            receipt.replay(self.analyzer);
            return *class;
        }
        #[cfg(test)]
        {
            let evaluations = source.expression_class_evaluations.get() + 1;
            source.expression_class_evaluations.set(evaluations);
            if let Some(limit) = source.expression_class_evaluation_limit.get() {
                assert!(
                    evaluations <= limit,
                    "uncached expression proof count {evaluations} exceeded limit {limit}"
                );
            }
        }
        // Remaining depth is part of the key: never restart a nested proof's allowance.
        let (attempt, receipt) = QueryReadReceipt::capture(self.analyzer, || {
            self.completed_attempt(|| {
                Some(self.expression_class_uncached(source, expression, depth))
            })
        });
        let class = match attempt {
            RustProofAttempt::Complete(Some(class)) => class,
            RustProofAttempt::Incomplete { .. } => RustValueClass::Unknown,
            RustProofAttempt::Complete(None) => {
                unreachable!("classification always returns a class")
            }
        };
        if source.owns_node(expression)
            && !receipt
                .incomplete_reasons()
                .iter()
                .any(|reason| reason.is_execution_dependent())
        {
            source
                .expression_classes
                .borrow_mut()
                .insert(key, (class, receipt));
        }
        class
    }

    fn expression_class_uncached(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustValueClass::Unknown;
        }
        match expression.kind() {
            "string_literal" | "raw_string_literal" => RustValueClass::Str,
            "char_literal" | "integer_literal" | "float_literal" | "boolean_literal"
            | "unit_expression" => RustValueClass::Inert,
            "parenthesized_expression" => named_children(expression)
                .first()
                .map_or(RustValueClass::Unknown, |inner| {
                    self.expression_class(source, *inner, depth - 1)
                }),
            "reference_expression" => {
                // A borrow of a place drops nothing. A borrow of any other
                // expression borrows a temporary, which a `let` extends to
                // the end of its block, so that temporary must be inert. A
                // borrow of a `String` coerces to `&str` where an argument
                // expects one.
                let Some(value) = expression.child_by_field_name("value") else {
                    return RustValueClass::Unknown;
                };
                let referent = self.expression_class(source, value, depth - 1);
                if referent == RustValueClass::String {
                    RustValueClass::Str
                } else if referent.is_inert() || is_place(source, value) {
                    RustValueClass::Inert
                } else {
                    RustValueClass::Unknown
                }
            }
            "array_expression" | "tuple_expression" => {
                let mut class = RustValueClass::Inert;
                for element in named_children(expression) {
                    match self.expression_class(source, element, depth - 1) {
                        RustValueClass::Unknown => return RustValueClass::Unknown,
                        RustValueClass::InertValue => class = RustValueClass::InertValue,
                        _ => {}
                    }
                }
                class
            }
            "macro_invocation" => self.vec_macro_class(source, expression, depth),
            "closure_expression" => self.closure_environment_class(source, expression, depth),
            "binary_expression" => self.binary_class(source, expression, depth),
            "identifier"
                if self.prelude_item(source, expression, "value").as_deref() == Some("None") =>
            {
                RustValueClass::InertValue
            }
            "identifier" => self.binding_class(source, expression, depth),
            "scoped_identifier" => match self.workspace_definition(source, expression) {
                Some(unit) => self.workspace_value_class(&unit, depth - 1),
                _ => RustValueClass::Unknown,
            },
            "struct_expression" => expression
                .child_by_field_name("name")
                .and_then(|name| self.workspace_definition(source, name))
                .filter(|unit| self.workspace_type_is_inert(unit, depth - 1))
                .map_or(RustValueClass::Unknown, |_| RustValueClass::Inert),
            "call_expression" => self.call_class(source, expression, depth),
            "try_expression" => self
                .modeled_receiver_type_bounded(source, expression, depth)
                .and_then(|ty| self.type_ref_class(&ty, depth - 1))
                .unwrap_or(RustValueClass::Unknown),
            _ => RustValueClass::Unknown,
        }
    }

    /// The class of `Owner::function(..)` for a reviewed std `Self`
    /// constructor (`String::from`, `Vec::<u8>::with_capacity`), proven
    /// without an activated model. `None` leaves the call to the other
    /// routes, which stay open without authority.
    ///
    /// Two resolver routes certify the owner. A bare prelude owner needs the
    /// selected prelude reason, which a local declaration, an import, or
    /// `no_implicit_prelude` removes. Any other owner, qualified or aliased,
    /// needs the resolver's external call identity and an inherent fact.
    /// External identity alone cannot prove the module has the standard
    /// prelude traits: disabling attributes may live in another file.
    /// The result is the owner type applied to its written type
    /// arguments: a `Vec` needs exactly one, inert, so a custom allocator
    /// argument or an inferred element type stays unproven. The call's own
    /// arguments are consumed by the call and never reach the result.
    fn std_self_constructor_class(
        &self,
        source: &RustSource,
        call: Node<'_>,
        function: Node<'_>,
        depth: usize,
    ) -> Option<RustValueClass> {
        if function.kind() != "scoped_identifier" {
            return None;
        }
        let name = function.child_by_field_name("name")?;
        let function_name = source.node_text(name)?;
        let arity = named_children(call.child_by_field_name("arguments")?).len();
        if !RUST_STD_SELF_CONSTRUCTOR_FACTS
            .iter()
            .any(|fact| fact.function == function_name && fact.arity == arity)
        {
            return None;
        }
        let owner = function.child_by_field_name("path")?;
        let (head, arguments) =
            if matches!(owner.kind(), "generic_type" | "generic_type_with_turbofish") {
                let arguments = owner
                    .child_by_field_name("type_arguments")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|argument| argument.kind() != "lifetime")
                    .collect::<Vec<_>>();
                (owner.child_by_field_name("type")?, arguments)
            } else {
                (owner, Vec::new())
            };
        // The resolver's external identity comes first: a prelude reason
        // survives next to an explicit unindexed `use other::String`, which
        // shadows the prelude, so the prelude route runs only when no
        // external identity claims the call.
        let site = ResolvedReferenceSite {
            path: function_name.to_owned(),
            text: function_name.to_owned(),
            range: node_range(name),
            focus_start_byte: name.start_byte(),
            focus_end_byte: name.end_byte(),
        };
        let identity = self.resolver.external_call_identity(
            &source.file,
            source.text(),
            source.tree(),
            &site,
            call.start_byte(),
        );
        let external_owner = identity.is_some();
        let type_name = if let Some(identity) = identity {
            if identity.member() != function_name {
                return None;
            }
            // `alloc` publishes the types `std` re-exports.
            let owner_path = identity.owner_fqn().split('.').collect::<Vec<_>>();
            let ["std" | "alloc", module, type_name] = owner_path.as_slice() else {
                return None;
            };
            let fact = rust_std_type_fact(type_name)?;
            (fact.path[1] == *module).then(|| (*type_name).to_owned())?
        } else if matches!(head.kind(), "identifier" | "type_identifier") {
            // The prelude reason does not exclude an import of the same name
            // (see above), so no import of this file may bind it.
            if self.imports_may_bind(source, source.node_text(head)?) {
                return None;
            }
            self.prelude_item(source, head, "type")?
        } else {
            return None;
        };
        let fact = rust_std_self_constructor_fact(&type_name, function_name, arity)?;
        if !fact.inherent {
            debug_assert_eq!((fact.owner, fact.function), ("String", "from"));
            // String has no inherent `from`. Its result is String only when
            // the enabled prelude supplies From, with no lexical or imported
            // trait of that name displacing it.
            if external_owner
                || self.implicit_prelude_disabled_at(source, call)
                || !self.prelude_name_is_unbound(source, call.start_byte(), "From", "type")
            {
                return None;
            }
        }
        let type_fact = rust_std_type_fact(fact.owner)?;
        if arguments.len() != type_fact.type_arguments {
            return None;
        }
        if !arguments
            .iter()
            .all(|argument| self.type_class(source, *argument, depth - 1).is_inert())
        {
            return Some(RustValueClass::Unknown);
        }
        // Dropping the result drops the elements it will hold, so an inferred
        // element type proves nothing (`let mut v = Vec::new(); v.push(guard)`).
        Some(if type_fact.name == "String" {
            RustValueClass::String
        } else {
            RustValueClass::Inert
        })
    }

    /// Whether an import of this file can bind `name` ahead of the prelude:
    /// one that names it (or renames to it), or a wildcard whose selected
    /// export inventory does not prove absence. The answer is file-wide, so
    /// it over-refuses; an unavailable import list refuses too.
    fn imports_may_bind(&self, source: &RustSource, name: &str) -> bool {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let Some(imports) = self.resolver.import_infos(&source.file, scope.token()) else {
            return true;
        };
        use brokk_bifrost_rust::graph_support::RustGlobNamespace;
        imports.iter().any(|import| {
            if import.is_wildcard {
                // Reuse the resolver's selected operation and read frame,
                // as the prelude proof does for this same absence question.
                !self
                    .resolver
                    .glob_name_absent(&source.file, import, RustGlobNamespace::Type, name)
            } else {
                import.alias.as_deref().or(import.identifier.as_deref()) == Some(name)
            }
        })
    }

    /// Whether `#![no_implicit_prelude]` or `#![no_core]` on the crate root,
    /// or `no_implicit_prelude` on an enclosing module, can remove the
    /// standard prelude traits at `site`. Anything the attribute reader
    /// cannot evaluate counts as disabled.
    fn implicit_prelude_disabled_at(&self, source: &RustSource, site: Node<'_>) -> bool {
        let mentions = |attribute: Node<'_>| {
            source.node_text(attribute).is_some_and(|text| {
                text.contains("no_implicit_prelude") || text.contains("no_core")
            })
        };
        if !brokk_bifrost_rust::syntax::rust_implicit_prelude_contains_type(
            source.tree().root_node(),
            source.text(),
            "Option",
        ) {
            return true;
        }
        std::iter::successors(site.parent(), |node| node.parent()).any(|scope| match scope.kind() {
            "mod_item" => outer_attributes(scope).any(mentions),
            "declaration_list" => named_children(scope)
                .into_iter()
                .any(|child| child.kind() == "inner_attribute_item" && mentions(child)),
            _ => false,
        })
    }

    /// The class of a closure value, which is the class of its environment.
    ///
    /// Dropping a closure drops its by-value captures, and a by-reference
    /// capture drops nothing. A captured binding with an inert class is inert
    /// whichever way it is captured, so the proof does not read the capture
    /// mode: the lowering label `rust_shared_borrow` only means that no
    /// assignment, `&mut` or call was seen, and it also marks consuming uses
    /// such as `|| x`. The class does not describe what the closure returns.
    /// A nested closure, `async` block or `gen` block contributes the captures
    /// of the enclosing scopes it reaches, because it lives in this
    /// environment.
    fn closure_environment_class(
        &self,
        source: &RustSource,
        closure: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        use super::closure_captures::rust_callable_free_variables;
        use super::semantic::{rust_closure_is_async, rust_closure_like_body};
        // An async closure returns a future that owns its state.
        if rust_closure_is_async(closure) {
            return RustValueClass::Unknown;
        }
        if !source.owns_node(closure) {
            // Captures resolve against the retained tree, not a macro reparse.
            incomplete_proof("closure_outside_source_tree");
            return RustValueClass::Unknown;
        }
        let Some(body) = rust_closure_like_body(closure) else {
            return RustValueClass::Unknown;
        };
        let mut remaining = self.resolver.budget().max_scope_nodes;
        let mut charge = |steps| {
            if self
                .resolver
                .cancellation()
                .is_some_and(CancellationToken::is_cancelled)
            {
                operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
                return Err(());
            }
            let Some(next) = remaining.checked_sub(steps) else {
                operational_proof_stop(
                    "closure_capture_scan_limit",
                    DerivationExecutionCause::Budget,
                );
                return Err(());
            };
            remaining = next;
            Ok(())
        };
        let mut class = RustValueClass::Inert;
        let mut callables = vec![(closure, body)];
        while let Some((callable, body)) = callables.pop() {
            let Ok(free) =
                rust_callable_free_variables(callable, body, &source.prepared, None, &mut charge)
            else {
                return RustValueClass::Unknown;
            };
            if free.unresolved {
                incomplete_proof("closure_capture_unresolved");
                return RustValueClass::Unknown;
            }
            if free.saw_macro_invocation {
                // Without parsed operands, `format!("{x}")` captures invisibly.
                incomplete_proof("closure_macro_environment");
                return RustValueClass::Unknown;
            }
            for nested in free.nested_callables {
                let Some(nested_body) = rust_closure_like_body(nested) else {
                    return RustValueClass::Unknown;
                };
                callables.push((nested, nested_body));
            }
            for variable in free.references {
                // A binding declared inside this closure is not in its environment.
                if closure.start_byte() <= variable.declaration_range.start
                    && variable.declaration_range.end <= closure.end_byte()
                {
                    continue;
                }
                match self.expression_class(source, variable.reference, depth - 1) {
                    RustValueClass::Unknown => return RustValueClass::Unknown,
                    RustValueClass::InertValue => class = RustValueClass::InertValue,
                    _ => {}
                }
            }
        }
        class
    }

    fn vec_macro_class(
        &self,
        source: &RustSource,
        invocation: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        use brokk_bifrost_rust::format_args::{RustVecMacroArguments, rust_vec_macro_arguments};
        if !self.standard_macro_matches(source, invocation, "alloc", "vec") {
            return RustValueClass::Unknown;
        }
        let Ok(arguments) = rust_vec_macro_arguments(invocation, source.text()) else {
            return RustValueClass::Unknown;
        };
        let elements = match arguments {
            RustVecMacroArguments::Elements(elements) => elements,
            RustVecMacroArguments::Repeated(repeated) => vec![repeated.element],
        };
        if elements.is_empty() {
            return RustValueClass::Unknown;
        }
        let Some(operands) =
            brokk_bifrost_rust::macro_matcher::parse_macro_operands(invocation, source.text())
        else {
            return RustValueClass::Unknown;
        };
        let mut agreed = None;
        for element in elements {
            let Some(operand) = operands.iter().find(|operand| {
                operand.node().byte_range()
                    == (element.value_range.start_byte..element.value_range.end_byte)
            }) else {
                return RustValueClass::Unknown;
            };
            let Some(ty) = self.exact_model_argument_type(source, operand.node(), depth - 1) else {
                return RustValueClass::Unknown;
            };
            // A variant's value-level inertness cannot certify its whole type.
            if !matches!(
                self.type_ref_class(&ty, depth - 1),
                Some(RustValueClass::Inert | RustValueClass::Str | RustValueClass::String)
            ) || agreed.as_ref().is_some_and(|previous| previous != &ty)
            {
                return RustValueClass::Unknown;
            }
            agreed = Some(ty);
        }
        RustValueClass::Inert
    }

    fn binary_class(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let (Some(left), Some(operator), Some(right)) = (
            expression.child_by_field_name("left"),
            expression.child_by_field_name("operator"),
            expression.child_by_field_name("right"),
        ) else {
            return RustValueClass::Unknown;
        };
        match operator.kind() {
            // Comparison and logical operators always produce `bool`.
            "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" => RustValueClass::Inert,
            "+" if self.expression_class(source, left, depth - 1) == RustValueClass::String
                && self.expression_class(source, right, depth - 1) == RustValueClass::Str =>
            {
                RustValueClass::from_std(RUST_STD_STRING_ADD_STR)
            }
            _ => RustValueClass::Unknown,
        }
    }

    /// The class of the parameter or `let` binding `name` resolves to.
    fn binding_class(&self, source: &RustSource, name: Node<'_>, depth: usize) -> RustValueClass {
        let Some(identifier) = source.node_text(name) else {
            return RustValueClass::Unknown;
        };
        let binding = match resolve_lexical_binding_with_visibility(
            Language::Rust,
            source.tree().root_node(),
            source.text(),
            name.start_byte(),
            name.end_byte(),
            identifier,
        ) {
            Ok(Some(binding)) => binding,
            Ok(None) | Err(LexicalBindingUnproven::NonLexicalFocus) => {
                // A path to a unit struct is a value too.
                return match self.workspace_definition(source, name) {
                    Some(unit) => self.workspace_value_class(&unit, depth - 1),
                    _ => RustValueClass::Unknown,
                };
            }
            Err(_) => return RustValueClass::Unknown,
        };
        let (LexicalBindingResolution::Parameter(definition)
        | LexicalBindingResolution::OtherLocal(definition)) = binding;
        let Some(declaration) = source.tree().root_node().named_descendant_for_byte_range(
            definition.declaration_range.start_byte,
            definition.declaration_range.end_byte,
        ) else {
            return RustValueClass::Unknown;
        };
        match binding_pattern_owner(
            declaration,
            definition.name_range.start_byte..definition.name_range.end_byte,
        ) {
            Some(owner) if owner.kind() == "parameter" => owner
                .child_by_field_name("type")
                .map_or(RustValueClass::Unknown, |ty| {
                    self.type_class(source, ty, depth - 1)
                }),
            Some(owner) => self.let_class(source, owner, depth - 1),
            None => RustValueClass::Unknown,
        }
    }

    /// The class of the value one `let` binds or discards.
    fn let_class(&self, source: &RustSource, binding: Node<'_>, depth: usize) -> RustValueClass {
        if let Some(ty) = binding.child_by_field_name("type") {
            return self.type_class(source, ty, depth);
        }
        // A `let ... else` diverges when the pattern is refutable, which the
        // proof does not type.
        if binding.child_by_field_name("alternative").is_some() {
            return RustValueClass::Unknown;
        }
        let class = binding
            .child_by_field_name("value")
            .map_or(RustValueClass::Unknown, |value| {
                self.expression_class(source, value, depth)
            });
        if class == RustValueClass::InertValue {
            let Some(pattern) = binding.child_by_field_name("pattern") else {
                return RustValueClass::Unknown;
            };
            let mut remaining = self.resolver.budget().max_scope_nodes;
            let mut charge = |steps| {
                if self
                    .resolver
                    .cancellation()
                    .is_some_and(CancellationToken::is_cancelled)
                {
                    operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
                    return Err(());
                }
                let Some(next) = remaining.checked_sub(steps) else {
                    operational_proof_stop(
                        "binding_write_scan_limit",
                        DerivationExecutionCause::Budget,
                    );
                    return Err(());
                };
                remaining = next;
                Ok(())
            };
            for name in brokk_bifrost_rust::lexical_scope::rust_pattern_binding_identifiers(pattern)
            {
                match brokk_bifrost_rust::structural::rust_binding_may_be_written(
                    binding,
                    name,
                    source.text(),
                    &mut charge,
                ) {
                    Ok(false) => {}
                    Ok(true) => {
                        incomplete_proof("binding_value_may_be_replaced");
                        return RustValueClass::Unknown;
                    }
                    Err(()) => return RustValueClass::Unknown,
                }
            }
        }
        class
    }

    // A dyn receiver's selected trait declaration fixes the result type even
    // when the runtime implementation set remains open. Do not confuse that
    // dispatch completeness with the signature's structural authority.
    fn trait_object_call_result_class(
        &self,
        source: &RustSource,
        function: Node<'_>,
        depth: usize,
    ) -> Option<RustValueClass> {
        if function.kind() != "field_expression" {
            return None;
        }
        let receiver = function.child_by_field_name("value")?;
        let mut ty = self.declared_binding_type(source, receiver)?;
        while ty.kind() == "reference_type" {
            ty = ty.child_by_field_name("type")?;
        }
        if ty.kind() != "dynamic_type" {
            return None;
        }
        let mut bound = ty.child_by_field_name("trait")?;
        if bound.kind() == "generic_type" {
            bound = bound.child_by_field_name("type")?;
        }
        let owner = self.workspace_definition(source, bound)?;
        let owner_source = self.source(owner.source())?;
        let owner_decl = self.declaration(&owner_source, &owner)?;
        if owner_decl.kind() != "trait_item" || outer_attributes(owner_decl).next().is_some() {
            return None;
        }
        let outcome = self.resolve(source, function.child_by_field_name("field")?)?;
        let [target] = outcome.definitions.as_slice() else {
            return None;
        };
        if outcome.lexical_definition.is_some() || !target.is_function() {
            return None;
        }
        let target_source = self.source(target.source())?;
        if target_source.file != owner_source.file || target_source.text() != owner_source.text() {
            return None;
        }
        let declaration = self.declaration(&target_source, target)?;
        if !matches!(
            declaration.kind(),
            "function_item" | "function_signature_item"
        ) || outer_attributes(declaration).next().is_some()
            || super::semantic::function_is_async(declaration)
        {
            return None;
        }
        let parent =
            std::iter::successors(declaration.parent(), |node| node.parent()).find(|node| {
                matches!(
                    node.kind(),
                    "trait_item" | "impl_item" | "function_item" | "source_file"
                )
            })?;
        if parent.kind() != "trait_item" || parent.byte_range() != owner_decl.byte_range() {
            return None;
        }
        Some(
            declaration
                .child_by_field_name("return_type")
                .map_or(RustValueClass::Inert, |result| {
                    self.type_class(&target_source, result, depth - 1)
                }),
        )
    }

    fn call_class(&self, source: &RustSource, call: Node<'_>, depth: usize) -> RustValueClass {
        let Some(function) = call
            .child_by_field_name("function")
            .map(call_function_target)
        else {
            return RustValueClass::Unknown;
        };
        if let Some(signature) = self
            .declared_binding_type(source, function)
            .filter(|ty| ty.kind() == "function_type")
        {
            // The result's drop class does not resolve the indirect target.
            return signature
                .child_by_field_name("return_type")
                .map_or(RustValueClass::Inert, |result| {
                    self.type_class(source, result, depth - 1)
                });
        }
        if let Some(fact) = self.standard_constructor_fact(source, function) {
            let arguments = named_children(
                call.child_by_field_name("arguments")
                    .expect("call arguments"),
            );
            if arguments.len() != fact.arity {
                return RustValueClass::Unknown;
            }
            return if arguments.iter().all(|argument| {
                self.expression_class(source, *argument, depth - 1)
                    .is_inert()
            }) {
                RustValueClass::Inert
            } else {
                RustValueClass::Unknown
            };
        }
        if let Some(class) = self.std_self_constructor_class(source, call, function, depth) {
            return class;
        }
        if self.is_modeled_env_var_call(source, call) {
            return RustValueClass::EnvVarResult;
        }
        if let Some(class) = self.modeled_call_result_class(source, call, depth) {
            return class;
        }
        let arity = call
            .child_by_field_name("arguments")
            .map_or(0, |arguments| named_children(arguments).len());
        let callee_name = match function.kind() {
            "field_expression" => {
                let Some((receiver, method)) = rust_method_call_parts(function) else {
                    return RustValueClass::Unknown;
                };
                let receiver_class = self.expression_class(source, receiver, depth - 1);
                if receiver_class == RustValueClass::EnvVarResult
                    && source.node_text(method) == Some("unwrap")
                    && arity == 0
                {
                    return RustValueClass::String;
                }
                if let Some(receiver) = match receiver_class {
                    RustValueClass::Str => Some(RustStdReceiver::Str),
                    RustValueClass::String => Some(RustStdReceiver::String),
                    _ => None,
                } {
                    return source
                        .node_text(method)
                        .and_then(|method| rust_std_method_fact(receiver, method, arity))
                        .map_or(RustValueClass::Unknown, |fact| {
                            RustValueClass::from_std(fact.result)
                        });
                }
                method
            }
            "scoped_identifier" => {
                if let Some(fact) = self.prelude_type_associated_fact(source, function, arity) {
                    return RustValueClass::from_std(fact.result);
                }
                function
            }
            "identifier" => function,
            _ => return RustValueClass::Unknown,
        };
        if let Some(class) = self.trait_object_call_result_class(source, function, depth) {
            return class;
        }
        let Some((callee_source, unit)) = self.selected_source_declaration(source, callee_name)
        else {
            return RustValueClass::Unknown;
        };
        if unit.is_class() && self.workspace_type_is_inert(&unit, depth - 1) {
            return RustValueClass::Inert;
        }
        if !unit.is_function() {
            return RustValueClass::Unknown;
        }
        let Some(callee) = self.declaration(&callee_source, &unit) else {
            return RustValueClass::Unknown;
        };
        if callee.kind() != "function_item" {
            return RustValueClass::Unknown;
        }
        if super::semantic::function_is_async(callee) {
            // An unpolled async fn owns its captures, not its written Output.
            // Polling may initialize other fields, so this is a value proof.
            if outer_attributes(callee).next().is_some() {
                return RustValueClass::Unknown;
            }
            let Some(arguments) = call.child_by_field_name("arguments") else {
                return RustValueClass::Unknown;
            };
            let receiver_inert = if function.kind() == "field_expression" {
                let borrowed = callee
                    .child_by_field_name("parameters")
                    .is_some_and(|parameters| {
                        named_children(parameters)
                            .into_iter()
                            .any(super::semantic::rust_self_parameter_is_borrowed)
                    });
                borrowed
                    || function
                        .child_by_field_name("value")
                        .is_some_and(|receiver| {
                            self.expression_class(source, receiver, depth - 1)
                                .is_inert()
                        })
            } else {
                true
            };
            if receiver_inert
                && named_children(arguments).into_iter().all(|argument| {
                    self.expression_class(source, argument, depth - 1)
                        .is_inert()
                })
            {
                return RustValueClass::InertValue;
            }
            // The boolean sub-proof also returns false on operational stops.
            operational_proof_stop(
                "async_capture_cleanup_unknown",
                DerivationExecutionCause::Provider,
            );
            return RustValueClass::Unknown;
        }
        match callee.child_by_field_name("return_type") {
            // A function without a written return type returns `()`.
            None => RustValueClass::Inert,
            Some(ty) => self.type_class(&callee_source, ty, depth - 1),
        }
    }

    /// The selected source declaration shared by class and application proofs.
    /// Selection remains exactly the workspace definition read used by call_class.
    fn selected_source_declaration(
        &self,
        source: &RustSource,
        callee_name: Node<'_>,
    ) -> Option<(RustSource, CodeUnit)> {
        let unit = self.workspace_definition(source, callee_name)?;
        let selected_source = self.source(unit.source())?;
        Some((selected_source, unit))
    }

    /// Retain a selected local call's written concrete application, instead of
    /// erasing its arguments to the abstract receiver used for owner probing.
    fn selected_call_receiver_type(&self, source: &RustSource, call: Node<'_>) -> Option<TypeRef> {
        let function = call.child_by_field_name("function")?;
        // A nongeneric declaration accepts no supplied type arguments; an
        // empty turbofish still supplies zero and preserves the same call.
        if function.kind() == "generic_function" {
            let types = function.child_by_field_name("type_arguments")?;
            if types.has_error() || types.is_missing() || !named_children(types).is_empty() {
                return None;
            }
        }
        if call.has_error() || call.is_missing() {
            return None;
        }
        let callee = call_function_target(function);
        if !matches!(callee.kind(), "identifier" | "scoped_identifier") {
            return None;
        }
        let (selected_source, unit) = self.selected_source_declaration(source, callee)?;
        if !unit.is_function() {
            return None;
        }
        let declaration = self.declaration(&selected_source, &unit)?;
        if declaration.kind() != "function_item"
            || super::semantic::function_is_async(declaration)
            || declaration.child_by_field_name("type_parameters").is_some()
            || item_or_enclosing_item_attributed(declaration)
        {
            return None;
        }
        let parameters = declaration.child_by_field_name("parameters")?;
        let arguments = call.child_by_field_name("arguments")?;
        let formals = named_children(parameters);
        let actuals = named_children(arguments);
        if parameters.has_error()
            || parameters.is_missing()
            || arguments.has_error()
            || arguments.is_missing()
            || formals.iter().any(|parameter| {
                !matches!(parameter.kind(), "parameter" | "self_parameter")
                    || parameter.has_error()
                    || parameter.is_missing()
                    || outer_attributes(*parameter).next().is_some()
            })
            || actuals.iter().any(|argument| {
                argument.has_error()
                    || argument.is_missing()
                    || outer_attributes(*argument).next().is_some()
            })
            || formals.len() != actuals.len()
        {
            return None;
        }
        let mut ancestor = declaration.parent();
        while let Some(node) = ancestor {
            // A uniquely selected nongeneric associated function has the
            // same concrete signature authority as a free function. Generic
            // enclosing owners still require substitution we do not prove.
            if node.child_by_field_name("type_parameters").is_some() {
                return None;
            }
            ancestor = node.parent();
        }
        for (index, (formal, actual)) in formals.iter().zip(&actuals).enumerate() {
            if formal.kind() == "self_parameter"
                && (index != 0
                    || !self.explicit_self_matches(
                        source,
                        *actual,
                        &selected_source,
                        declaration,
                        *formal,
                    ))
            {
                return None;
            }
        }
        let Some(written) = declaration.child_by_field_name("return_type") else {
            return Some(TypeRef::Tuple {
                elements: Vec::new(),
            });
        };
        let overlay = self.analyzer.semantic_model_overlay()?;
        let active = self.analyzer.active_semantic_models()?;
        let mut applicability = super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            &overlay,
            &active,
            &self.resolver,
        );

        let mut returned =
            applicability.receiver_type(&selected_source.file, selected_source.text(), written)?;
        // Keep only direct, non-generic workspace nominals from this SAME
        // written return. The existing residual proof owns resolution; this
        // reader does not infer a name, descend into a generic, or relax the
        // unknown-argument member gate.
        if written.kind() == "generic_type"
            && let Some(arguments) = written.child_by_field_name("type_arguments")
            && let TypeRef::Named {
                arguments: actual, ..
            }
            | TypeRef::Declared {
                arguments: actual, ..
            } = &mut returned
        {
            let arguments = super::trait_applicability::source_type_arguments(arguments);
            if arguments.len() == actual.len() {
                for (argument, actual) in arguments.into_iter().zip(actual) {
                    if matches!(actual, TypeRef::Unknown)
                        && matches!(
                            argument.kind(),
                            "type_identifier" | "scoped_type_identifier"
                        )
                        && let Some(expression) =
                            self.expand_written_type(&selected_source, argument)
                        && let Some(RustResidualError::Declaration(unit)) =
                            self.residual_error(expression)
                    {
                        *actual = TypeRef::Named {
                            name: unit.fq_name(),
                            arguments: Vec::new(),
                            nullable: false,
                        };
                    }
                }
            }
        }
        (!returned.contains_unknown() && !type_ref_mentions_type_parameter(&returned))
            .then_some(returned)
    }

    /// A qualified instance call supplies its receiver as an ordinary argument.
    /// Compare selected nominal declarations, never the spelling of `Self` or
    /// the argument. This deliberately proves only concrete workspace owners.
    fn explicit_self_matches(
        &self,
        source: &RustSource,
        actual: Node<'_>,
        selected_source: &RustSource,
        declaration: Node<'_>,
        formal: Node<'_>,
    ) -> bool {
        use brokk_bifrost_analysis::analyzer::semantic::ReceiverMode;
        use brokk_bifrost_rust::ownership::{
            rust_reference_expression_value, rust_reference_is_mutable,
            rust_reference_type_referent,
        };
        let expected_mode = super::semantic::rust_declared_receiver_mode(formal);
        if expected_mode == ReceiverMode::Unknown {
            return false;
        }
        let mut parent = declaration.parent();
        let owner_type = loop {
            let Some(node) = parent else { return false };
            if node.kind() == "impl_item" {
                break node.child_by_field_name("type");
            }
            parent = node.parent();
        };
        let Some(owner) = owner_type
            .filter(|node| matches!(node.kind(), "type_identifier" | "scoped_type_identifier"))
            .and_then(|node| self.workspace_definition(selected_source, node))
        else {
            return false;
        };
        let mut actual = actual;
        while actual.kind() == "parenthesized_expression" {
            let children = named_children(actual);
            let [inner] = children.as_slice() else {
                return false;
            };
            actual = *inner;
        }
        let written = self.declared_binding_type(source, actual);
        let (mode, head, written) = if actual.kind() == "reference_expression" {
            let Some(value) = rust_reference_expression_value(actual) else {
                return false;
            };
            (
                if rust_reference_is_mutable(actual) {
                    ReceiverMode::MutableBorrow
                } else {
                    ReceiverMode::SharedBorrow
                },
                value,
                self.declared_binding_type(source, value),
            )
        } else if let Some(ty) = written.filter(|ty| ty.kind() == "reference_type") {
            let Some(referent) = rust_reference_type_referent(ty) else {
                return false;
            };
            (
                if rust_reference_is_mutable(ty) {
                    ReceiverMode::MutableBorrow
                } else {
                    ReceiverMode::SharedBorrow
                },
                actual,
                Some(referent),
            )
        } else {
            (ReceiverMode::Owned, actual, written)
        };
        if mode != expected_mode
            && !(mode == ReceiverMode::MutableBorrow && expected_mode == ReceiverMode::SharedBorrow)
        {
            return false;
        }
        let head = written.unwrap_or_else(|| {
            if head.kind() == "struct_expression" {
                head.child_by_field_name("name").unwrap_or(head)
            } else {
                head
            }
        });
        matches!(
            head.kind(),
            "identifier" | "scoped_identifier" | "type_identifier" | "scoped_type_identifier"
        ) && self
            .workspace_definition(source, head)
            .is_some_and(|unit| unit == owner)
    }

    /// The reviewed model's declaration for `std::env::var` names its outer
    /// `Result` type but leaves generic arguments untyped. Its Rust API
    /// contract fixes the success payload as `String`, which lets a following
    /// structured `Result::unwrap()` reach the existing `String::len` fact.
    fn is_modeled_env_var_call(&self, source: &RustSource, call: Node<'_>) -> bool {
        let Some(function) = call
            .child_by_field_name("function")
            .map(call_function_target)
        else {
            return false;
        };
        if function.kind() != "scoped_identifier" {
            return false;
        }
        let Some(name) = function.child_by_field_name("name") else {
            return false;
        };
        let Some(text) = source.node_text(name) else {
            return false;
        };
        let site = ResolvedReferenceSite {
            path: text.to_owned(),
            text: text.to_owned(),
            range: node_range(name),
            focus_start_byte: name.start_byte(),
            focus_end_byte: name.end_byte(),
        };
        let Some(identity) = self.resolver.external_call_identity(
            &source.file,
            source.text(),
            source.tree(),
            &site,
            call.start_byte(),
        ) else {
            return false;
        };
        identity.owner_fqn() == "std.env"
            && identity.member() == "var"
            && call
                .child_by_field_name("arguments")
                .is_some_and(|arguments| named_children(arguments).len() == 1)
    }

    /// The reviewed fact for `Owner::function(..)` written with `arity`
    /// arguments, when `Owner` is one segment the resolver proves is a std
    /// prelude type.
    fn prelude_type_associated_fact(
        &self,
        source: &RustSource,
        path: Node<'_>,
        arity: usize,
    ) -> Option<&'static RustStdAssociatedFact> {
        if path.kind() != "scoped_identifier" {
            return None;
        }
        let owner = path.child_by_field_name("path")?;
        let function = source.node_text(path.child_by_field_name("name")?)?;
        if !matches!(owner.kind(), "identifier" | "type_identifier")
            || !RUST_STD_ASSOCIATED_FACTS
                .iter()
                .any(|fact| fact.function == function && fact.arity == arity)
        {
            return None;
        }
        let prelude = self.prelude_item(source, owner, "type")?;
        rust_std_associated_fact(&prelude, function, arity)
    }

    /// The activated model's exact callable shape for one call (#3757). The
    /// identity comes from the same structure the dispatch route proves: a
    /// receiver typed through built-in reference dereferences, or a written
    /// path rooted at an external crate. The answer is per call site; no
    /// symbol-level candidate is shared across calls with different owners or
    /// receiver shapes.
    fn modeled_call_shape(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustModeledCallShape> {
        let key = (call.id(), depth);
        if let Some((shape, receipt)) = source
            .modeled_call_shapes
            .borrow()
            .get(&key)
            .filter(|_| source.owns_node(call))
        {
            receipt.replay(self.analyzer);
            return shape.clone();
        }
        #[cfg(test)]
        {
            let evaluations = source.modeled_call_shape_evaluations.get() + 1;
            source.modeled_call_shape_evaluations.set(evaluations);
            if let Some(limit) = source.modeled_call_shape_evaluation_limit.get() {
                assert!(
                    evaluations <= limit,
                    "uncached modeled call shape count {evaluations} exceeded limit {limit}"
                );
            }
        }
        let (attempt, receipt) = QueryReadReceipt::capture(self.analyzer, || {
            self.completed_attempt(|| self.modeled_call_shape_uncached(source, call, depth))
        });
        let shape = attempt.into_value();
        if source.owns_node(call)
            && !receipt
                .incomplete_reasons()
                .iter()
                .any(|reason| reason.is_execution_dependent())
        {
            source
                .modeled_call_shapes
                .borrow_mut()
                .insert(key, (shape.clone(), receipt));
        }
        shape
    }

    fn modeled_call_shape_uncached(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustModeledCallShape> {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return None;
        }
        let function = call_function_target(call.child_by_field_name("function")?);
        let arity = named_children(call.child_by_field_name("arguments")?).len();
        let (owner, member, has_receiver, receiver_steps) = match function.kind() {
            "field_expression" => {
                let (receiver, name) = rust_method_call_parts(function)?;
                let owner = self.receiver_owner_bounded(source, receiver, depth - 1)?;
                let member = source.node_text(name)?;
                let overlay = self.analyzer.semantic_model_overlay_read().published()?;
                let active = self.analyzer.active_semantic_models()?;
                let mut applicability = super::trait_applicability::ModelApplicability::new(
                    self.analyzer,
                    self.rust,
                    &overlay,
                    &active,
                    &self.resolver,
                );
                let application =
                    super::semantic::RustReceiverTypeFacts::from_tree(source.text(), source.tree())
                        .declared_receiver_type(source.text(), source.tree(), receiver)
                        .and_then(|ty| applicability.receiver_type(&source.file, source.text(), ty))
                        .or_else(|| self.modeled_receiver_type_bounded(source, receiver, depth - 1))
                        .or_else(|| {
                            overlay
                                .symbols_named_in_family(
                                    &owner.key(),
                                    "rust",
                                    SemanticModelNamespace::TypeOrModule,
                                )
                                .unique()
                                .as_ref()
                                .map(|owner| applicability.abstract_receiver(owner))
                        })?;
                let site = ResolvedReferenceSite {
                    path: member.to_owned(),
                    text: member.to_owned(),
                    range: node_range(name),
                    focus_start_byte: name.start_byte(),
                    focus_end_byte: name.end_byte(),
                };
                let owner = self.resolver.select_member(
                    self.analyzer,
                    &source.file,
                    source.text(),
                    &site,
                    &owner.key(),
                    true,
                    u32::try_from(arity).ok()?,
                    Some(&application),
                )?;
                (owner.owner, member.to_owned(), true, owner.receiver_steps)
            }
            "identifier" | "scoped_identifier" => {
                let name = function.child_by_field_name("name").unwrap_or(function);
                let text = source.node_text(name)?.to_owned();
                let site = ResolvedReferenceSite {
                    path: text.clone(),
                    text,
                    range: node_range(name),
                    focus_start_byte: name.start_byte(),
                    focus_end_byte: name.end_byte(),
                };
                let identity = self.resolver.external_call_identity(
                    &source.file,
                    source.text(),
                    source.tree(),
                    &site,
                    call.start_byte(),
                )?;
                (
                    identity.owner_fqn().to_owned(),
                    identity.member().to_owned(),
                    false,
                    0,
                )
            }
            _ => return None,
        };
        Some((owner, member, has_receiver, arity, receiver_steps))
    }

    /// The result of a modeled `.clone()` call whose member selection landed on
    /// std::clone::Clone's own declaration. Selection on a receiver type's own
    /// explicit `clone` record has never been accepted here; only the
    /// certificate API below admits it.
    pub(crate) fn modeled_clone_result(
        &self,
        file: &ProjectFile,
        range: ByteRange<usize>,
        depth: usize,
    ) -> Option<TypeRef> {
        let source = self.source(file)?;
        let call = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start, range.end)?;
        if call.byte_range() != range {
            return None;
        }
        match self.clone_selection(&source, call, depth)? {
            CloneSelection::Trait { .. } => self.modeled_call_return_type(&source, call, depth),
            CloneSelection::NotCloneCall | CloneSelection::Other { .. } => None,
        }
    }

    /// Which declaration the member selection of one `.clone()` call landed on.
    /// `None` means the shape could not be decided. This is the proof every
    /// clone answer starts from; it reads exactly what the earlier bare-result
    /// proof read.
    fn clone_selection(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<CloneSelection> {
        let (owner, member, receiver, arity, receiver_steps) =
            self.modeled_call_shape(source, call, depth)?;
        if member != "clone" || !receiver || arity != 0 {
            return Some(CloneSelection::NotCloneCall);
        }
        let snapshot = self.analyzer.active_semantic_model_snapshot()?;
        let overlay = snapshot.semantic_model_overlay()?;
        let selected = overlay
            .symbols_named_in_family(&owner, "rust", SemanticModelNamespace::TypeOrModule)
            .unique()?;
        let clone_trait = crate::analyzer::RustOverlayCrates::new(Some(overlay))
            .referenceable_owner("std.clone.Clone")?;
        Some(if selected.id == clone_trait.id {
            CloneSelection::Trait {
                clone_trait,
                receiver_steps,
            }
        } else {
            CloneSelection::Other {
                selected,
                clone_trait,
            }
        })
    }

    /// Certify that a modeled `.clone()` call selects std::clone::Clone on its
    /// receiver type (#11547). The certificate names the selected
    /// implementation by model declaration identity; a name alone never
    /// certifies. `depth` is the remaining proof allowance, as for the other
    /// bounded proofs.
    ///
    /// Any proof stop recorded while deciding makes the verdict `Incomplete`,
    /// so a certificate is never built on a partial proof. A deterministic
    /// stop carries no cause; provider and cancellation stops keep theirs.
    /// The stop still reaches enclosing proof attempts, as for every other
    /// bounded proof. The bare `modeled_clone_result` opens no attempt of its
    /// own and so reports exactly what it did before.
    #[cfg(test)]
    pub(crate) fn modeled_clone_certificate(
        &self,
        file: &ProjectFile,
        exact_source: &str,
        range: ByteRange<usize>,
        depth: usize,
    ) -> RustCloneProof {
        let (verdict, receipt) = QueryReadReceipt::capture(self.analyzer, || {
            self.clone_proof_verdict(file, exact_source, range, depth)
        });
        RustCloneProof { verdict, receipt }
    }

    /// The verdict alone, for a caller that holds the enclosing capture.
    fn clone_proof_verdict(
        &self,
        file: &ProjectFile,
        exact_source: &str,
        range: ByteRange<usize>,
        depth: usize,
    ) -> RustCloneVerdict {
        match self.completed_attempt(|| self.clone_verdict(file, exact_source, range, depth)) {
            RustProofAttempt::Complete(Some(verdict)) => verdict,
            RustProofAttempt::Complete(None) => {
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ReceiverUnresolved)
            }
            RustProofAttempt::Incomplete { reason, cause, .. } => {
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ProofStopped { reason, cause })
            }
        }
    }

    fn clone_verdict(
        &self,
        file: &ProjectFile,
        exact_source: &str,
        range: ByteRange<usize>,
        depth: usize,
    ) -> Option<RustCloneVerdict> {
        let source = self.source(file)?;
        if source.text() != exact_source {
            // The range belongs to other bytes; it would name another call.
            operational_proof_stop("source_mismatch", DerivationExecutionCause::Provider);
            return None;
        }
        let call = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start, range.end)?;
        if call.byte_range() != range || call.kind() != "call_expression" {
            return Some(RustCloneVerdict::NotClone);
        }
        let selection = match self.clone_selection(&source, call, depth) {
            Some(selection) => selection,
            // An undecided shape is a gap only for a call written as a
            // zero-argument method call named `clone`.
            None => {
                let written_clone = call
                    .child_by_field_name("function")
                    .and_then(rust_method_call_parts)
                    .zip(call.child_by_field_name("arguments"))
                    .is_some_and(|((_, name), arguments)| {
                        source.node_text(name) == Some("clone")
                            && named_children(arguments).is_empty()
                    });
                return (!written_clone).then_some(RustCloneVerdict::NotClone);
            }
        };
        let snapshot = self.analyzer.active_semantic_model_snapshot()?;
        let overlay = snapshot.semantic_model_overlay()?;
        let active = snapshot.active_models();
        let mut applicability = super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            overlay,
            active,
            &self.resolver,
        );
        // A hierarchy path or an impl record proves Clone is a candidate, not
        // that no inherent `clone` shadows it: a pack that lists only part of
        // the receiver's surface may omit one. Only a surface the pack
        // reports whole lets the selected implementation stand.
        let surface_closed = |receiver: &Arc<SemanticModelSymbol>| {
            !overlay.owner_surface(receiver).gaps.iter().any(|gap| {
                matches!(gap, crate::analyzer::semantic_model::SemanticModelSurfaceGap::PartialType { qualified_name }
                    if *qualified_name == receiver.qualified_name)
            })
        };
        let (implementation, clone_trait, receiver_steps) = match selection {
            CloneSelection::NotCloneCall => return Some(RustCloneVerdict::NotClone),
            CloneSelection::Trait {
                clone_trait,
                receiver_steps,
            } => {
                let result = self.modeled_call_return_type(&source, call, depth)?;
                // The trait declaration was selected. It certifies only when
                // the receiver type's own model has a positive implementation
                // path to Clone. A hierarchy edge without a `clone` record is
                // all the model records for an implementation it does not
                // enumerate; it does not say how the implementation is written.
                let receiver = self
                    .selected_receiver_type(
                        &source,
                        call,
                        &clone_trait,
                        true,
                        receiver_steps,
                        depth,
                        &mut applicability,
                    )
                    // Clone is selected on the receiver as written only for at
                    // most one reference layer and no dereference: `&&T` selects
                    // `<&T as Clone>::clone`, and a dereferenced receiver is a
                    // different type than the one written.
                    .filter(|(_, layers)| receiver_steps == 0 && *layers <= 1)
                    .and_then(|(actual, _)| applicability.owner(&actual));
                let path = receiver.filter(surface_closed).and_then(|receiver| {
                    overlay
                        .callable_owners_on_surface(active, &receiver, "clone")?
                        .into_iter()
                        .any(|candidate| {
                            candidate.owner.id == clone_trait.id && !candidate.hierarchy.is_empty()
                        })
                        .then_some(receiver)
                });
                return Some(match path {
                    Some(receiver) => RustCloneVerdict::Certified(RustCloneCertificate {
                        implementation: RustCloneImplementation::Declared {
                            receiver: RustModelDeclaration::of(&receiver),
                        },
                        clone_trait: RustModelDeclaration::of(&clone_trait),
                        receiver_steps,
                        result,
                    }),
                    None => RustCloneVerdict::Unproven { result },
                });
            }
            CloneSelection::Other {
                selected,
                clone_trait,
            } => {
                // A member selected on a type or on another trait. It is
                // Clone's only when that declaration is an impl item of Clone.
                let method = overlay
                    .callable_for_application(
                        SemanticModelCallableKey::new(
                            Language::Rust.config_label(),
                            &selected.qualified_name,
                            "clone",
                            true,
                            0,
                        ),
                        &SemanticModelCallApplication::positional(0),
                    )
                    .unique()?;
                let Some(implemented) = applicability.member(&method)?.implemented_trait.clone()
                else {
                    return Some(RustCloneVerdict::NotClone);
                };
                if applicability.owner(&implemented)?.id != clone_trait.id {
                    return Some(RustCloneVerdict::NotClone);
                }
                let receiver_steps = self
                    .modeled_call_shape(&source, call, depth)
                    .map(|shape| shape.4)?;
                let as_written = receiver_steps == 0
                    && self
                        .selected_receiver_type(
                            &source,
                            call,
                            &selected,
                            true,
                            receiver_steps,
                            depth,
                            &mut applicability,
                        )
                        .is_some_and(|(_, layers)| layers <= 1);
                if !as_written || !surface_closed(&selected) {
                    let result = self.modeled_call_return_type(&source, call, depth)?;
                    return Some(RustCloneVerdict::Unproven { result });
                }
                (
                    RustCloneImplementation::Explicit {
                        receiver: RustModelDeclaration::of(&selected),
                        method: RustModelDeclaration::of(&method),
                    },
                    clone_trait,
                    receiver_steps,
                )
            }
        };
        let result = self.modeled_call_return_type(&source, call, depth)?;
        Some(RustCloneVerdict::Certified(RustCloneCertificate {
            implementation,
            clone_trait: RustModelDeclaration::of(&clone_trait),
            receiver_steps,
            result,
        }))
    }

    pub(crate) fn modeled_operator_result(
        &self,
        left: &brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType,
        right: &brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType,
        trait_name: &str,
    ) -> Option<TypeRef> {
        let outputs = self.modeled_operator_outputs(left, right, trait_name)?;
        match outputs.as_slice() {
            [output] => Some(output.clone()),
            _ => None,
        }
    }

    pub(crate) fn modeled_operator_outputs(
        &self,
        left: &brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType,
        right: &brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType,
        trait_name: &str,
    ) -> Option<Vec<TypeRef>> {
        use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType;
        // StdIntrinsic has no declaration; it cannot select a modeled member.
        let RustConversionType::Model { symbol, .. } = left else {
            return None;
        };
        let snapshot = self.analyzer.active_semantic_model_snapshot()?;
        let overlay = snapshot.semantic_model_overlay()?;
        let active = snapshot.active_models();
        let receiver = overlay.symbols_with_id_in_family(symbol, "rust").unique()?;
        let declaration =
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                active, &receiver,
            )?;
        let trait_ = overlay
            .symbols_named_in_family(
                &format!("std.ops.{trait_name}"),
                "rust",
                SemanticModelNamespace::TypeOrModule,
            )
            .unique()
            .or_else(|| {
                overlay
                    .symbols_named_in_family(
                        &format!("core.ops.{trait_name}"),
                        "rust",
                        SemanticModelNamespace::TypeOrModule,
                    )
                    .unique()
            })?;
        let applicability = super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            overlay,
            active,
            &self.resolver,
        );
        applicability.operator_outputs(&receiver, &trait_, left, right, &declaration)
    }

    pub(crate) fn modeled_result(
        &self,
        file: &ProjectFile,
        range: ByteRange<usize>,
        depth: usize,
    ) -> Option<TypeRef> {
        let source = self.source(file)?;
        let call = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start, range.end)?;
        if call.byte_range() != range {
            return None;
        }
        self.modeled_call_return_type(&source, call, depth)
    }

    fn modeled_call_return_type(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<TypeRef> {
        self.modeled_call_return(source, call, depth)
            .map(|proof| proof.returned)
    }

    fn modeled_call_return(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustModeledCallReturn> {
        match self.completed_attempt(|| self.modeled_call_return_type_inner(source, call, depth)) {
            RustProofAttempt::Complete(returned) => returned,
            RustProofAttempt::Incomplete { .. } => None,
        }
    }

    /// The receiver type on which a call's member was selected: the written or
    /// inferred receiver, followed through the `receiver_steps` type-level
    /// dereferences that selection proved. The count is how many reference
    /// layers the written receiver type had before any dereference.
    #[allow(clippy::too_many_arguments)]
    fn selected_receiver_type(
        &self,
        source: &RustSource,
        call: Node<'_>,
        owner_symbol: &SemanticModelSymbol,
        has_receiver: bool,
        receiver_steps: usize,
        depth: usize,
        applicability: &mut super::trait_applicability::ModelApplicability<'_, '_>,
    ) -> Option<(TypeRef, usize)> {
        let function = call.child_by_field_name("function")?;
        let function = call_function_target(function);
        let mut actual = if has_receiver {
            let (receiver, _) = rust_method_call_parts(function)?;
            super::semantic::RustReceiverTypeFacts::from_tree(source.text(), source.tree())
                .declared_receiver_type(source.text(), source.tree(), receiver)
                .and_then(|ty| applicability.receiver_type(&source.file, source.text(), ty))
                .or_else(|| self.modeled_receiver_type_bounded(source, receiver, depth - 1))
                .unwrap_or(TypeRef::Unknown)
        } else {
            function
                .child_by_field_name("path")
                .and_then(|ty| applicability.receiver_type(&source.file, source.text(), ty))
                .unwrap_or_else(|| applicability.abstract_receiver(owner_symbol))
        };
        actual = normalized_receiver_application(self.analyzer, actual)?;
        debug_assert!(
            receiver_steps <= brokk_bifrost_analysis::analyzer::store::language_support::MAX_EXPLICIT_RECEIVER_STEPS
        );
        // The type node comes from the binding's declaration or initializer
        // with borrows, dereferences and casts looked through, so its layers
        // are the receiver's only for a plain binding with a written type, a
        // call whose result type the model states, or a `let` binding
        // assigned once whose initializer is one of those. Any other receiver
        // expression, including `self` with its implicit borrow, is not
        // followed.
        let mut written_reference_layers = 0;
        if has_receiver {
            let (mut receiver, _) = rust_method_call_parts(function)?;
            while receiver.kind() == "parenthesized_expression" {
                receiver = receiver.named_child(0)?;
            }
            let facts =
                super::semantic::RustReceiverTypeFacts::from_tree(source.text(), source.tree());
            let (text, tree) = (source.text(), source.tree());
            let direct = |node: Node<'_>| {
                node.kind() == "call_expression" || facts.binding_has_written_type(text, tree, node)
            };
            let exact = direct(receiver)
                || facts
                    .single_assignment_let_initializer(text, tree, receiver)
                    .is_some_and(|mut initializer| {
                        while initializer.kind() == "parenthesized_expression" {
                            let Some(inner) = initializer.named_child(0) else {
                                return false;
                            };
                            initializer = inner;
                        }
                        direct(initializer)
                    });
            if !exact {
                written_reference_layers = usize::MAX / 2;
            }
        }
        for step in 0..=receiver_steps {
            while let TypeRef::ByRef { element, .. } = actual {
                actual = *element;
                if step == 0 {
                    written_reference_layers += 1;
                }
            }
            if step < receiver_steps {
                // Replay selection's exact type evidence. Flow adjustments can
                // be absent when their separate summary was not admitted.
                let receiver = applicability.owner(&actual)?;
                actual = applicability.deref_target(&receiver, &actual)?;
            }
        }
        Some((actual, written_reference_layers))
    }

    fn modeled_call_return_type_inner(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustModeledCallReturn> {
        let (owner, member, has_receiver, arity, receiver_steps) =
            self.modeled_call_shape(source, call, depth)?;
        let overlay = self.analyzer.semantic_model_overlay_read().published()?;
        let parameter_count = u32::try_from(arity).ok()?;
        let candidates = overlay.callable_for_application(
            SemanticModelCallableKey::new(
                Language::Rust.config_label(),
                &owner,
                &member,
                has_receiver,
                parameter_count,
            ),
            &SemanticModelCallApplication::positional(parameter_count),
        );
        if let Some(callable) = candidates.unique() {
            let returned = self.modeled_callable_return_type(
                source,
                call,
                depth,
                &owner,
                has_receiver,
                receiver_steps,
                &callable,
            )?;
            return Some(RustModeledCallReturn {
                returned,
                providers: candidates.records,
            });
        }
        if candidates.disposition
            != crate::analyzer::semantic_model::SemanticModelCallableDisposition::CompatibleLayout
        {
            return None;
        }
        let active = self.analyzer.active_semantic_models()?;
        let applicability = super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            &overlay,
            &active,
            &self.resolver,
        );
        let arguments = named_children(call.child_by_field_name("arguments")?);
        let actual = if let [argument] = arguments.as_slice() {
            self.exact_model_argument_type(source, *argument, depth.saturating_sub(1))
        } else {
            None
        };
        let from = overlay
            .symbols_named_in_family(
                "core.convert.From",
                "rust",
                SemanticModelNamespace::TypeOrModule,
            )
            .unique();
        let mut agreed = None;
        let mut providers = Vec::new();
        for callable in &candidates.records {
            // From's trait parameter fixes the input type exactly. Ordinary
            // overload parameters may admit coercions, so do not exclude them
            // by a structural inequality. Unknown input evidence retains every
            // candidate, including the two erased &str reference contracts.
            if let Some(actual) = &actual
                && let Some(implemented) =
                    applicability.member(callable)?.implemented_trait.as_ref()
                && from.as_ref().is_some_and(|from| {
                    applicability
                        .owner(implemented)
                        .is_some_and(|owner| owner.id == from.id)
                })
                && let TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } =
                    implemented
                && let [expected] = arguments.as_slice()
                && model_argument_definitely_differs(actual, expected, &applicability)
            {
                continue;
            }
            let returned = self.modeled_callable_return_type(
                source,
                call,
                depth,
                &owner,
                has_receiver,
                receiver_steps,
                callable,
            )?;
            let returned = resolved_model_result(returned, &applicability, &active)?;
            if agreed
                .as_ref()
                .is_some_and(|previous| previous != &returned)
            {
                return None;
            }
            providers.push(Arc::clone(callable));
            agreed = Some(returned);
        }
        // This proof carries only a type. It never changes the overlay's
        // ambiguous callable match or admits an implementation's flow summary.
        Some(RustModeledCallReturn {
            returned: agreed?,
            providers,
        })
    }

    fn exact_model_argument_type(
        &self,
        source: &RustSource,
        argument: Node<'_>,
        depth: usize,
    ) -> Option<TypeRef> {
        use brokk_bifrost_rust::syntax::{RustLiteralType, rust_literal_type};
        if argument.kind() == "unit_expression" {
            return Some(TypeRef::Tuple {
                elements: Vec::new(),
            });
        }
        if let Some(literal) = rust_literal_type(argument, source.text()) {
            let RustLiteralType::Exact {
                primitive,
                reference_layers,
            } = literal
            else {
                return None;
            };
            let mut ty = TypeRef::named(format!("core.primitive.{primitive}"));
            for _ in 0..reference_layers {
                ty = TypeRef::ByRef {
                    element: Box::new(ty),
                    reference_kind: crate::analyzer::semantic_model::TypeRefReferenceKind::Lvalue,
                };
            }
            return Some(ty);
        }
        self.modeled_receiver_type_bounded(source, argument, depth)
    }

    #[allow(clippy::too_many_arguments)]
    fn modeled_callable_return_type(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
        owner: &str,
        has_receiver: bool,
        receiver_steps: usize,
        callable: &SemanticModelSymbol,
    ) -> Option<TypeRef> {
        let overlay = self.analyzer.semantic_model_overlay_read().published()?;
        let signature = callable.structured_signature.as_ref()?;
        let Some(returned) = signature.returns.clone() else {
            // Signature::returns None declares no results (#7570).
            // Missing signatures and explicit Unknown results stay unknown.
            return Some(TypeRef::Tuple {
                elements: Vec::new(),
            });
        };
        let owner_symbol = overlay
            .symbols_named_in_family(owner, "rust", SemanticModelNamespace::TypeOrModule)
            .unique()?;
        // The producer projects an impl's Self return onto its declared owner.
        // Retain the call's explicit generic application, rather than treating
        // Vec::<u8>::new() as an untyped Vec when probing its result (#6542).
        let depends_on_type_parameters = type_ref_mentions_type_parameter(&returned);
        if depends_on_type_parameters
            || matches!(&returned, TypeRef::Declared { id, .. } if id == &owner_symbol.id)
            || matches!(&returned, TypeRef::TypeParameter { name } if name == "Self")
            || type_ref_has_self_projection(&returned)
        {
            let active = self.analyzer.active_semantic_models()?;
            let mut applicability = super::trait_applicability::ModelApplicability::new(
                self.analyzer,
                self.rust,
                &overlay,
                &active,
                &self.resolver,
            );
            let (mut actual, _) = self.selected_receiver_type(
                source,
                call,
                &owner_symbol,
                has_receiver,
                receiver_steps,
                depth,
                &mut applicability,
            )?;
            if let TypeRef::Named {
                arguments,
                nullable,
                ..
            } = &actual
            {
                let receiver = applicability.owner(&actual)?;
                actual = TypeRef::Declared {
                    id: receiver.id.clone(),
                    arguments: arguments.clone(),
                    nullable: *nullable,
                };
            }
            let declaration =
                brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                    &active,
                    &owner_symbol,
                )?;
            // The owner's type parameters bind from the receiver's arguments
            // only when the owner IS the receiver's declaration. A trait
            // method selected on another type takes its trait arguments from
            // the selected impl (impl Get<i32> for Wrapper<String>), not from
            // the receiver, so only Self binds there, and a return that still
            // names a parameter is Unknown.
            let receiver_is_owner =
                matches!(&actual, TypeRef::Declared { id, .. } if id == &owner_symbol.id);
            let mut bindings = HashMap::new();
            if receiver_is_owner {
                let TypeRef::Declared { arguments, .. } = &mut actual else {
                    unreachable!("checked above");
                };
                super::trait_applicability::complete_type_arguments(&declaration, arguments)?;
                if arguments.len() != declaration.type_parameters.len() {
                    return None;
                }
                bindings.extend(
                    declaration
                        .type_parameters
                        .iter()
                        .cloned()
                        .zip(arguments.iter().cloned()),
                );
            }
            // Explicit callable parameters are independent of owner parameters.
            // Keep the wrapper to read its arguments, then normalize only the
            // target. Missing, unresolved and placeholder arguments stay open.
            let function = call.child_by_field_name("function")?;
            let parameters = &callable.structured_signature.as_ref()?.type_parameters;
            if let Some(arguments) = function.child_by_field_name("type_arguments") {
                // Signature parameters omit lifetimes, as do stored argument facts.
                let arguments = super::trait_applicability::source_type_arguments(arguments);
                if arguments.len() == parameters.len() {
                    bindings.extend(parameters.iter().cloned().zip(arguments.into_iter().map(
                        |argument| {
                            applicability
                                .receiver_type(&source.file, source.text(), argument)
                                .unwrap_or(TypeRef::Unknown)
                        },
                    )));
                }
            }
            // A trait method's `Self::Item` return names its associated type at
            // the receiver. Resolve it only from the receiver's implemented-trait
            // facts (the same selection Deref uses); otherwise it stays a
            // projection, which every consumer treats as unknown.
            //
            // The producer erases every generic it cannot name to the same
            // wildcard, so an erased owner stands for `Self` only when the method
            // has no generic of its own. The receiver must list all its impls.
            let mut returned = returned;
            if owner_symbol.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::Trait
                && signature.type_parameters.is_empty()
                && type_ref_has_self_projection(&returned)
                && let Some(receiver) = applicability.owner(&actual)
                && applicability.implemented_traits_complete(&receiver)
            {
                bind_self_projections(
                    &mut returned,
                    &receiver,
                    &actual,
                    &owner_symbol,
                    &applicability,
                );
            }
            bindings.insert("Self".into(), actual);
            let mut returned = super::trait_applicability::substitute(&returned, &bindings, 16)?;
            if type_ref_mentions_type_parameter(&returned) {
                return None;
            }
            if let TypeRef::Declared { id, arguments, .. } = &mut returned {
                // Complete the returned declaration, which can differ from
                // the receiver (for example Result<String, E>::unwrap).
                let symbol = overlay.symbols_with_id_in_family(id, "rust").unique()?;
                let returned_declaration =
                    brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                        &active, &symbol,
                    )?;
                super::trait_applicability::complete_type_arguments(
                    &returned_declaration,
                    arguments,
                )?;
            }
            return Some(returned);
        }
        Some(returned)
    }

    /// The owner a modeled external call's result is declared as, read from
    /// a closed activated callable family for the call's exact identity.
    /// Ambiguous callable identities can prove only an agreed result type.
    fn modeled_call_result_owner(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustReceiverOwner> {
        self.receiver_owner_from_type(self.modeled_call_return_type(source, call, depth)?)
    }

    /// A modeled call result, including one carried by an unannotated local.
    /// This supplies its structured application to the same query's Deref and
    /// coherence checks; it is not general source result-type inference.
    pub(crate) fn modeled_receiver_type(
        &self,
        file: &ProjectFile,
        expression: Node<'_>,
    ) -> Option<TypeRef> {
        let source = self.source(file)?;
        let expression = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(expression.start_byte(), expression.end_byte())?;
        self.modeled_receiver_type_bounded(&source, expression, PROOF_DEPTH)
    }

    fn modeled_receiver_type_bounded<'tree>(
        &self,
        source: &'tree RustSource,
        mut expression: Node<'tree>,
        depth: usize,
    ) -> Option<TypeRef> {
        for depth in (1..=depth).rev() {
            if let Some(operand) = rust_unwrap_operand(expression, source.text()) {
                // Preserve the language's existing standard payload projection.
                // A nonstandard carrier instead needs its exact modeled return.
                let payload = (|| {
                    let mut wrapped = normalized_receiver_application(
                        self.analyzer,
                        self.modeled_receiver_type_bounded(source, operand, depth - 1)?,
                    )?;
                    if brokk_bifrost_analysis::analyzer::i_analyzer::current_captured_proof_stop()
                        .is_some()
                    {
                        return None;
                    }
                    while let TypeRef::ByRef { element, .. } = wrapped {
                        wrapped = *element;
                    }
                    let overlay = self.analyzer.semantic_model_overlay()?;
                    let (name, arguments) = match wrapped {
                        TypeRef::Named {
                            name, arguments, ..
                        } => (
                            overlay
                                .symbols_named_in_family(
                                    &name,
                                    "rust",
                                    SemanticModelNamespace::TypeOrModule,
                                )
                                .unique()?
                                .qualified_name
                                .clone(),
                            arguments,
                        ),
                        TypeRef::Declared { id, arguments, .. } => (
                            overlay
                                .symbols_with_id_in_family(&id, "rust")
                                .unique()?
                                .qualified_name
                                .clone(),
                            arguments,
                        ),
                        _ => return None,
                    };
                    if !super::standard_unwrap_payload_name(&name) {
                        return None;
                    }
                    if expression.kind() == "call_expression" {
                        // A canonical carrier does not select its method: an
                        // earlier trait on a reference or smart pointer may
                        // own unwrap/expect and return a different type.
                        let (selected_owner, selected_member, has_receiver, _, _) =
                            self.modeled_call_shape(source, expression, depth)?;
                        if !has_receiver
                            || selected_owner != name
                            || !matches!(selected_member.as_str(), "unwrap" | "expect")
                        {
                            return None;
                        }
                    }
                    arguments.into_iter().next()
                })();
                if brokk_bifrost_analysis::analyzer::i_analyzer::current_captured_proof_stop()
                    .is_some()
                {
                    return None;
                }
                if payload.is_some() || expression.kind() == "try_expression" {
                    return payload;
                }
            }
            match expression.kind() {
                "call_expression" => {
                    let returned = self.selected_call_result_type(source, expression, depth)?;
                    if targetless_alias_own_owner(self.analyzer, &returned).is_some() {
                        // Only the alias owner's open dispatch surface can use
                        // this nominal. Payload readers still normalize/refuse.
                        return Some(returned);
                    }
                    return normalized_receiver_application(self.analyzer, returned);
                }
                "identifier" => {
                    if let Some(ty) = self.declared_binding_type(source, expression) {
                        let overlay = self.analyzer.semantic_model_overlay_read().published()?;
                        let active = self.analyzer.active_semantic_models()?;
                        let mut applicability = super::trait_applicability::ModelApplicability::new(
                            self.analyzer,
                            self.rust,
                            &overlay,
                            &active,
                            &self.resolver,
                        );
                        let typed = applicability.receiver_type(&source.file, source.text(), ty);
                        return if brokk_bifrost_analysis::analyzer::i_analyzer::current_captured_proof_stop().is_some() { None } else { typed };
                    }
                    expression = self.binding_initializer(source, expression)?;
                }
                _ => return None,
            }
        }
        incomplete_proof("depth_limit");
        None
    }

    /// Structured result types for standard variants, activated models and
    /// uniquely resolved, nongeneric workspace signatures. These same facts
    /// feed receiver/payload selection and both Drop proof roles.
    fn selected_call_result_type(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<TypeRef> {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return None;
        }
        let function = call_function_target(call.child_by_field_name("function")?);
        if let Some(fact) = self.standard_constructor_fact(source, function) {
            let arguments = named_children(call.child_by_field_name("arguments")?);
            if arguments.len() != fact.arity {
                return None;
            }
            let [argument] = arguments.as_slice() else {
                return None;
            };
            let payload = self
                .exact_model_argument_type(source, *argument, depth - 1)
                .unwrap_or(TypeRef::Unknown);
            let (name, arguments) = match fact.name {
                "Some" => ("core.option.Option", vec![payload]),
                "Ok" => ("core.result.Result", vec![payload, TypeRef::Unknown]),
                "Err" => ("core.result.Result", vec![TypeRef::Unknown, payload]),
                _ => return None,
            };
            return Some(TypeRef::Named {
                name: name.into(),
                arguments,
                nullable: false,
            });
        }
        if let Some(ty) = self.modeled_call_return_type(source, call, depth) {
            return Some(ty);
        }
        if matches!(function.kind(), "identifier" | "scoped_identifier") {
            // Keep concrete free and associated source applications only after the same complete
            // syntax, positional arity and nongeneric declaration proof used
            // by receiver selection. A refusal cannot fall through to the
            // written return type without those proofs.
            return self.selected_call_receiver_type(source, call);
        }
        let unit = self.callee_definition(source, call)?;
        if !unit.is_function() {
            return None;
        }
        let declaration_source = self.source(unit.source())?;
        let declaration = self.declaration(&declaration_source, &unit)?;
        if declaration.kind() != "function_item"
            || super::semantic::function_is_async(declaration)
            || item_or_enclosing_item_attributed(declaration)
        {
            return None;
        }
        let mut parent = Some(declaration);
        while let Some(node) = parent {
            if node.child_by_field_name("type_parameters").is_some() {
                return None;
            }
            parent = node.parent();
        }
        let Some(returned) = declaration.child_by_field_name("return_type") else {
            return Some(TypeRef::Tuple {
                elements: Vec::new(),
            });
        };
        let overlay = self.analyzer.semantic_model_overlay()?;
        let active = self.analyzer.active_semantic_models()?;
        let mut applicability = super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            &overlay,
            &active,
            &self.resolver,
        );
        let ty = applicability.receiver_type(
            &declaration_source.file,
            declaration_source.text(),
            returned,
        )?;
        (!type_ref_mentions_type_parameter(&ty)).then_some(ty)
    }

    /// The drop class of the model's structured return type.
    fn modeled_call_result_class(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustValueClass> {
        self.type_ref_class(&self.modeled_call_return_type(source, call, depth)?, depth)
    }

    /// The drop class of a model's structured type. References, pointers,
    /// and primitive scalars cannot run user drop glue. A nominal type needs
    /// a reviewed drop fact: one of the standard owned-memory types known
    /// here, or the model's own drop glue with inert type arguments (#9057).
    fn type_ref_class(&self, ty: &TypeRef, depth: usize) -> Option<RustValueClass> {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return None;
        }
        match ty {
            TypeRef::ByRef { element, .. } => Some(match element.as_ref() {
                TypeRef::Named { name, .. }
                    if matches!(
                        name.as_str(),
                        "str" | "std.primitive.str" | "core.primitive.str"
                    ) =>
                {
                    RustValueClass::Str
                }
                _ => RustValueClass::Inert,
            }),
            TypeRef::Pointer { .. } => Some(RustValueClass::Inert),
            TypeRef::Tuple { elements } => elements
                .iter()
                .all(|element| {
                    self.type_ref_class(element, depth - 1)
                        .is_some_and(RustValueClass::is_inert)
                })
                .then_some(RustValueClass::Inert),
            TypeRef::Named {
                name, arguments, ..
            } if arguments.is_empty() => {
                match name.as_str() {
                    "std.string.String" => Some(RustValueClass::String),
                    "std.path.Path" | "std.path.PathBuf" => Some(RustValueClass::Inert),
                    _ => {
                        // These are model type identities, not source type syntax.
                        let primitive = name
                            .strip_prefix("std.primitive.")
                            .or_else(|| name.strip_prefix("core.primitive."))
                            .unwrap_or(name);
                        matches!(
                            primitive,
                            "bool"
                                | "char"
                                | "i8"
                                | "i16"
                                | "i32"
                                | "i64"
                                | "i128"
                                | "isize"
                                | "u8"
                                | "u16"
                                | "u32"
                                | "u64"
                                | "u128"
                                | "usize"
                                | "f16"
                                | "f32"
                                | "f64"
                                | "f128"
                        )
                        .then_some(RustValueClass::Inert)
                        .or_else(|| {
                            let symbol = self
                                .analyzer
                                .semantic_model_overlay_read()
                                .published()?
                                .symbols_named_in_family(
                                    name,
                                    "rust",
                                    SemanticModelNamespace::TypeOrModule,
                                )
                                .unique()?;
                            self.modeled_type_ref_class(&symbol, &[], depth)
                        })
                    }
                }
            }
            TypeRef::Named {
                name, arguments, ..
            } => {
                let symbol = self
                    .analyzer
                    .semantic_model_overlay_read()
                    .published()?
                    .symbols_named_in_family(name, "rust", SemanticModelNamespace::TypeOrModule)
                    .unique()?;
                self.modeled_type_ref_class(&symbol, arguments, depth)
            }
            TypeRef::Declared { id, arguments, .. } => {
                let symbol = self
                    .analyzer
                    .semantic_model_overlay_read()
                    .published()?
                    .symbols_with_id_in_family(id, "rust")
                    .unique()?;
                self.modeled_type_ref_class(&symbol, arguments, depth)
            }
            _ => None,
        }
    }

    /// The class of an application of the activated model type `symbol`,
    /// from the model's reviewed drop glue.
    fn modeled_type_ref_class(
        &self,
        symbol: &SemanticModelSymbol,
        arguments: &[TypeRef],
        depth: usize,
    ) -> Option<RustValueClass> {
        // The standard carrier itself has no user destructor; only its
        // contained type arguments contribute drop glue. This is the same
        // intrinsic fact used for written Option/Result types.
        let carrier = match symbol.qualified_name.as_str() {
            "core.option.Option" | "std.option.Option" => rust_std_type_fact("Option"),
            "core.result.Result" | "std.result.Result" => rust_std_type_fact("Result"),
            _ => None,
        };
        if let Some(fact) = carrier {
            return (arguments.len() == fact.type_arguments
                && arguments.iter().all(|argument| {
                    self.type_ref_class(argument, depth - 1)
                        .is_some_and(RustValueClass::is_inert)
                }))
            .then_some(RustValueClass::Inert);
        }
        let declaration = self.modeled_inert_drop_glue_owner(symbol)?;
        let mut arguments = arguments.to_vec();
        super::trait_applicability::complete_type_arguments(&declaration, &mut arguments)?;
        arguments
            .iter()
            .all(|argument| {
                self.type_ref_class(argument, depth - 1)
                    .is_some_and(RustValueClass::is_inert)
            })
            .then_some(RustValueClass::Inert)
    }

    /// The declared type of the parameter or annotated `let` that the name
    /// `receiver` resolves to.
    fn declared_binding_type<'s>(
        &self,
        source: &'s RustSource,
        receiver: Node<'s>,
    ) -> Option<Node<'s>> {
        if receiver.kind() == "self" {
            return super::semantic::RustReceiverTypeFacts::from_tree(source.text(), source.tree())
                .declared_receiver_type(source.text(), source.tree(), receiver);
        }
        if receiver.kind() != "identifier" {
            return None;
        }
        let identifier = source.node_text(receiver)?;
        let binding = resolve_lexical_binding(
            Language::Rust,
            source.tree().root_node(),
            source.text(),
            receiver.start_byte(),
            receiver.end_byte(),
            identifier,
        )?;
        let (LexicalBindingResolution::Parameter(definition)
        | LexicalBindingResolution::OtherLocal(definition)) = binding;
        let declaration = source.tree().root_node().named_descendant_for_byte_range(
            definition.declaration_range.start_byte,
            definition.declaration_range.end_byte,
        )?;
        binding_pattern_owner(
            declaration,
            definition.name_range.start_byte..definition.name_range.end_byte,
        )?
        .child_by_field_name("type")
    }

    /// The initializer of a local binding, when the receiver is that binding.
    /// This preserves the modeled return owner of an imported associated call
    /// through an unannotated `let` instead of requiring a type annotation.
    fn binding_initializer<'s>(
        &self,
        source: &'s RustSource,
        receiver: Node<'s>,
    ) -> Option<Node<'s>> {
        if receiver.kind() != "identifier" {
            return None;
        }
        let identifier = source.node_text(receiver)?;
        let LexicalBindingResolution::OtherLocal(definition) = resolve_lexical_binding(
            Language::Rust,
            source.tree().root_node(),
            source.text(),
            receiver.start_byte(),
            receiver.end_byte(),
            identifier,
        )?
        else {
            return None;
        };
        let declaration = source.tree().root_node().named_descendant_for_byte_range(
            definition.declaration_range.start_byte,
            definition.declaration_range.end_byte,
        )?;
        binding_pattern_owner(
            declaration,
            definition.name_range.start_byte..definition.name_range.end_byte,
        )
        .filter(|owner| owner.kind() == "let_declaration")?
        .child_by_field_name("value")
    }

    /// The canonical owner path, dot-joined, of the type a method receiver
    /// evaluates to after built-in reference dereferences, when the receiver
    /// is a `&str`, a binding or field whose nominal type the resolver proves belongs
    /// to an external crate (through the prelude, an import, or a qualified
    /// path), or the result of a modeled external call whose model declares
    /// its return type. A workspace type resolves through the workspace
    /// instead.
    fn receiver_owner(&self, source: &RustSource, receiver: Node<'_>) -> Option<RustReceiverOwner> {
        self.receiver_owner_bounded(source, receiver, PROOF_DEPTH)
    }

    /// Share the resolver-backed standard identity check with macro value proofs.
    fn standard_macro_matches(
        &self,
        source: &RustSource,
        invocation: Node<'_>,
        owner: &str,
        member: &str,
    ) -> bool {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let span = node_range(invocation);
        let dispatch = crate::analyzer::rust::format_macro_dispatch::dispatch(
            brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLanguageRequest {
                analyzer: self.analyzer,
                token: scope.token(),
                file: &source.file,
                source: source.text(),
                tree: source.tree(),
                macro_inventory: Some(&source.macro_inventory),
                call_span: &span,
                member_selection: None,
                cancellation: self.resolver.cancellation(),
                work: Default::default(),
            },
            None,
        );
        let Some(dispatch) = dispatch else {
            return false;
        };
        let [
                brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind::External {
                    external_callee_identity: Some(identity),
                    ..
                },
            ] = dispatch.boundaries.as_slice()
            else {
                return false;
            };
        identity.owner_fqn() == owner && identity.member() == member
    }

    fn receiver_owner_bounded(
        &self,
        source: &RustSource,
        receiver: Node<'_>,
        depth: usize,
    ) -> Option<RustReceiverOwner> {
        // Resolve declared owners and lexical bounds before drop classification.
        // Inferred applications then use the same selected-owner proof without
        // spending their depth on a second receiver walk.
        if depth == 0 {
            incomplete_proof("depth_limit");
            return None;
        }
        let declared = self.declared_binding_type(source, receiver);
        if let Some(ty) = declared
            && let Some(owner) = self.declared_receiver_owner(source, ty)
        {
            return Some(owner);
        }
        if declared.is_none()
            && matches!(receiver.kind(), "call_expression" | "identifier" | "self")
        {
            match self
                .completed_attempt(|| self.modeled_receiver_type_bounded(source, receiver, depth))
            {
                RustProofAttempt::Complete(Some(ty)) => {
                    if let Some(owner) = self.receiver_owner_from_type(ty) {
                        return Some(owner);
                    }
                }
                RustProofAttempt::Incomplete { .. } => return None,
                RustProofAttempt::Complete(None) => {}
            }
        }
        if self.expression_class(source, receiver, depth) == RustValueClass::Str {
            return Some(RustReceiverOwner::Std(RustStdReceiver::Str));
        }
        // A written type without a nominal/lexical anchor keeps the existing
        // initializer proof below; the substitution reader still uses the
        // written application's arguments before considering inferred ones.
        if receiver.kind() == "field_expression" {
            return self.field_receiver_owner(source, receiver);
        }
        if receiver.kind() == "try_expression" {
            let ty = self.modeled_receiver_type_bounded(source, receiver, depth)?;
            return self.receiver_owner_from_type(ty);
        }
        if receiver.kind() == "call_expression" {
            return self.modeled_call_result_owner(source, receiver, depth);
        }
        if receiver.kind() == "macro_invocation" {
            let layout = brokk_bifrost_rust::format_args::rust_macro_runtime_layout_for_path(
                receiver.child_by_field_name("macro")?,
                source.text(),
            )?;
            let result_owner = layout.result_owner?;
            return self
                .standard_macro_matches(source, receiver, layout.owner, layout.member)
                .then(|| RustReceiverOwner::Path(result_owner.into()));
        }
        if depth <= 1 {
            incomplete_proof("depth_limit");
        }
        if depth > 1
            && let Some(initializer) = self.binding_initializer(source, receiver)
            && let Some(owner) = self.receiver_owner_bounded(source, initializer, depth - 1)
        {
            return Some(owner);
        }
        None
    }

    /// Resolve a written owner or lexical trait anchor without following an initializer.
    fn declared_receiver_owner(
        &self,
        source: &RustSource,
        ty: Node<'_>,
    ) -> Option<RustReceiverOwner> {
        if let Some((owner, _arguments)) = self.nominal_type_owner(source, ty) {
            return Some(RustReceiverOwner::Path(owner));
        }
        let overlay = self.analyzer.semantic_model_overlay_read().published()?;
        let active = self.analyzer.active_semantic_models()?;
        let model = super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            &overlay,
            &active,
            &self.resolver,
        );
        let bounds = super::trait_applicability::lexical_receiver_traits(
            self.analyzer,
            &source.file,
            source.text(),
            source.tree(),
            ty,
            &model,
        )?;
        // This is an anchor for the bounded surface, not a nominal type claim.
        // Selection independently reads every bound and retains rivals.
        Some(RustReceiverOwner::Path(
            bounds.first()?.qualified_name.clone(),
        ))
    }

    fn receiver_owner_from_type(&self, ty: TypeRef) -> Option<RustReceiverOwner> {
        if let Some(owner) = targetless_alias_own_owner(self.analyzer, &ty) {
            return Some(RustReceiverOwner::Path(owner));
        }
        let mut ty = normalized_receiver_application(self.analyzer, ty)?;
        while let TypeRef::ByRef { element, .. } = ty {
            ty = *element;
        }
        match ty {
            TypeRef::Named { name, .. } => {
                let primitive = super::call_conversion::modeled_primitive(&name)
                    .or_else(|| super::call_conversion::primitive_for_spelling(&name));
                if primitive == Some(RustPrimitive::Str) {
                    Some(RustReceiverOwner::Std(RustStdReceiver::Str))
                } else {
                    Some(RustReceiverOwner::Path(name))
                }
            }
            TypeRef::Declared { id, .. } => {
                let overlay = self.analyzer.semantic_model_overlay_read().published()?;
                Some(RustReceiverOwner::Path(
                    overlay
                        .symbols_with_id_in_family(&id, "rust")
                        .unique()?
                        .qualified_name
                        .clone(),
                ))
            }
            _ => None,
        }
    }

    /// A field's declared type, after the resolver has selected its actual
    /// declaration through built-in reference projection. Positional fields
    /// have a lexical source declaration instead of a display CodeUnit.
    fn field_receiver_owner(
        &self,
        source: &RustSource,
        receiver: Node<'_>,
    ) -> Option<RustReceiverOwner> {
        let outcome = self.resolve(source, receiver.child_by_field_name("field")?)?;
        if outcome.status != DefinitionLookupStatus::Resolved {
            return None;
        }
        let prove = |field_source: &RustSource, declaration: Node<'_>| {
            let ty = match declaration.kind() {
                "field_declaration" => declaration.child_by_field_name("type")?,
                _ if declaration
                    .parent()
                    .is_some_and(|parent| parent.kind() == "ordered_field_declaration_list") =>
                {
                    declaration
                }
                _ => return None,
            };
            self.nominal_type_owner(field_source, ty)
                .map(|(owner, _arguments)| RustReceiverOwner::Path(owner))
        };
        match (
            outcome.definitions.as_slice(),
            outcome.lexical_definition.as_ref(),
        ) {
            ([unit], None) if unit.is_field() => {
                let field_source = self.source(unit.source())?;
                prove(&field_source, self.declaration(&field_source, unit)?)
            }
            ([], Some(definition))
                if definition.kind
                    == brokk_bifrost_core::analyzer::model::DeclarationKind::Field =>
            {
                let field_source =
                    self.source(definition.source_file.as_ref().unwrap_or(&source.file))?;
                let range = &definition.declaration_range;
                let declaration = field_source
                    .tree()
                    .root_node()
                    .named_descendant_for_byte_range(range.start_byte, range.end_byte)
                    .filter(|node| node.byte_range() == (range.start_byte..range.end_byte))?;
                prove(&field_source, declaration)
            }
            _ => None,
        }
    }

    /// Prove a nominal application from the resolver's head identity. A public
    /// declaration in a partial pack proves identity, not a closed member list.
    fn nominal_type_owner<'tree>(
        &self,
        source: &RustSource,
        mut ty: Node<'tree>,
    ) -> Option<(String, Vec<Node<'tree>>)> {
        let mut arguments = Vec::new();
        let primitive_identity = loop {
            match ty.kind() {
                "reference_type" => ty = ty.child_by_field_name("type")?,
                "generic_type" => {
                    arguments = super::trait_applicability::source_type_arguments(
                        ty.child_by_field_name("type_arguments")?,
                    );
                    ty = ty.child_by_field_name("type")?;
                }
                "primitive_type" => {
                    break Some(format!("std.primitive.{}", source.node_text(ty)?));
                }
                "array_type" => {
                    arguments.push(ty.child_by_field_name("element")?);
                    let primitive = if let Some(length) = ty.child_by_field_name("length") {
                        arguments.push(length);
                        "array"
                    } else {
                        "slice"
                    };
                    break Some(format!("std.primitive.{primitive}"));
                }
                "identifier"
                | "scoped_identifier"
                | "type_identifier"
                | "scoped_type_identifier" => break None,
                _ => return None,
            }
        };
        let identity = if let Some(identity) = primitive_identity {
            identity
        } else {
            let outcome = self.resolve(source, ty)?;
            if !outcome.definitions.is_empty() || outcome.lexical_definition.is_some() {
                return None;
            }
            // The terminal's boundary claim names the binder its route stopped
            // at, which for `use widget::sync;` then `sync::Lock` is the module
            // `widget.sync`, not the type. A root that the selected resolver
            // proves external carries the rest of the written path into that
            // crate, as static calls through the same path do (#11324).
            let canonical_root_path = matches!(ty.kind(), "scoped_type_identifier" | "scoped_identifier")
                .then(|| rust_path_segments(ty))
                .flatten()
                .and_then(|segments| {
                    let components = crate::analyzer::rust::external_calls::canonical_rust_external_owner_components_with_resolver(
                        self.analyzer,
                        &source.file,
                        source.text(),
                        source.tree(),
                        &segments,
                        self.resolver.cancellation(),
                        |query| self.resolver.resolve(query),
                    );
                    let written = segments
                        .iter()
                        .map(|segment| source.node_text(*segment))
                        .collect::<Option<Vec<_>>>()?;
                    (!components.iter().map(String::as_str).eq(written))
                        .then(|| components.join("."))
                });
            if let Some(path) = canonical_root_path {
                path
            } else if let Some(path) = standard_wrapper_owner(&outcome) {
                path.join(".")
            } else if let Some(prelude) = prelude_item_of(&outcome, "type") {
                rust_std_type_fact(&prelude)?.path.join(".")
            } else {
                let subjects = outcome
                    .diagnostics
                    .iter()
                    .filter_map(|diagnostic| diagnostic.claim.as_ref())
                    .filter(|claim| claim.kind == UnindexedClaimKind::ExternalBoundary)
                    .flat_map(|claim| claim.subjects.iter())
                    .collect::<Vec<_>>();
                match subjects.as_slice() {
                    [subject]
                        if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary =>
                    {
                        (*subject).clone()
                    }
                    [] if matches!(ty.kind(), "scoped_type_identifier" | "scoped_identifier") => {
                        // A qualified type may have no terminal reference row. Prove
                        // its root through the selected resolver instead; the model
                        // below must still publish the complete nominal identity.
                        let segments = rust_path_segments(ty)?;
                        let root = *segments.first()?;
                        if brokk_bifrost_rust::graph_support::rust_path_is_leading_absolute(root) {
                            self.resolver
                                .absolute_external_components(
                                    &source.file,
                                    source.node_text(root)?,
                                )?
                                .into_iter()
                                .chain(segments.iter().skip(1).map(|segment| {
                                    source
                                        .node_text(*segment)
                                        .expect("path segment has text")
                                        .to_owned()
                                }))
                                .collect::<Vec<_>>()
                                .join(".")
                        } else {
                            let scope = AnalyzerQueryScope::new(self.analyzer);
                            let imports =
                                self.resolver.import_infos(&source.file, scope.token())?;
                            if !crate::analyzer::rust::external_calls::native_external_root_with_resolver(
                        self.analyzer,
                        &source.file,
                        source.text(),
                        source.tree(),
                        root,
                        self.resolver.cancellation(),
                        &imports,
                        |query| self.resolver.resolve(query),
                    ) {
                        return None;
                    }
                            segments
                                .iter()
                                .map(|segment| source.node_text(*segment))
                                .collect::<Option<Vec<_>>>()?
                                .join(".")
                        }
                    }
                    [] if matches!(ty.kind(), "type_identifier" | "identifier") => {
                        // A bare imported type has no terminal boundary subject.
                        // Its structured `use` path still names the external
                        // owner, and the model overlay must publish it.
                        let name = source.node_text(ty)?;
                        let scope = AnalyzerQueryScope::new(self.analyzer);
                        let imports = self.resolver.import_infos(&source.file, scope.token())?;
                        let mut paths = imports.iter().filter_map(|import| {
                            if import.local_name() == Some(name) {
                                import.path.as_ref()
                            } else {
                                None
                            }
                        });
                        let path = paths.next()?.render_segments(".");
                        if paths.next().is_some() {
                            return None;
                        }
                        path
                    }
                    _ => return None,
                }
            }
        };
        let overlay = self.analyzer.semantic_model_overlay_read().published()?;
        let symbol = crate::analyzer::rust::crate_identity::RustOverlayCrates::new(Some(&overlay))
            .unique_symbol(&identity, brokk_bifrost_analysis::analyzer::semantic_model::overlay::RustReexportNamespace::TypeOrModule)?;
        if symbol.provenance.ambiguous
            || !symbol.externally_visible()
            || symbol.language != Language::Rust.config_label()
            || !matches!(
                symbol.kind,
                crate::analyzer::semantic_model::SemanticModelSymbolKind::Struct
                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Enum
                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Union
            )
        {
            return None;
        }
        let active = self.analyzer.active_semantic_models()?;
        let Some(record) =
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                &active, &symbol,
            )
        else {
            incomplete_proof("external_receiver_generic_arity_mismatch");
            return None;
        };
        let written = arguments.len();
        // An omitted application in a value path leaves inference variables.
        // Identity does not require their values; consumers prove arguments
        // separately when a member obligation or drop proof needs them.
        let inferred = written == 0 && matches!(ty.kind(), "identifier" | "scoped_identifier");
        if !inferred
            && (written > record.type_parameters.len()
                || (written < record.type_parameters.len()
                    && (record.type_parameter_defaults.len() != record.type_parameters.len()
                        || record.type_parameter_defaults[written..]
                            .iter()
                            .any(Option::is_none))))
        {
            incomplete_proof("external_receiver_generic_arity_mismatch");
            return None;
        }
        Some((symbol.qualified_name.clone(), arguments))
    }

    /// Prove only the exact value selected by the cleanup gap's source mapping.
    fn procedure_drops_are_inert(
        &self,
        file: &ProjectFile,
        source: &Arc<str>,
        value: ByteRange<usize>,
    ) -> bool {
        let Some(rust_source) = self.source(file) else {
            return false;
        };
        if rust_source.text() != source.as_ref() {
            return false;
        }
        let Some(node) = rust_source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(value.start, value.end)
            .filter(|node| node.byte_range() == value)
        else {
            return false;
        };
        // A declaration token is not yet visible to lexical use-site lookup.
        let node = if node.kind() == "self" {
            node.parent()
                .filter(|parent| parent.kind() == "self_parameter")
                .unwrap_or(node)
        } else {
            node
        };
        if node.kind() == "function_item" {
            let callable = node;
            let parameters = callable
                .child_by_field_name("parameters")
                .map(named_children)
                .unwrap_or_default();
            for parameter in parameters {
                let inert = match parameter.kind() {
                    "self_parameter" => {
                        // A borrowed receiver drops nothing; the remaining
                        // parameters and bindings still need their own proof.
                        if crate::analyzer::rust::semantic::rust_self_parameter_is_borrowed(
                            parameter,
                        ) {
                            true
                        } else {
                            let mut owner = callable.parent();
                            while let Some(node) = owner {
                                if node.kind() == "impl_item" {
                                    break;
                                }
                                owner = node.parent();
                            }
                            owner
                                .and_then(|node| node.child_by_field_name("type"))
                                .is_some_and(|ty| {
                                    self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert()
                                })
                        }
                    }
                    "parameter" => parameter.child_by_field_name("type").is_some_and(|ty| {
                        self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert()
                    }),
                    "attribute_item" => true,
                    _ => false,
                };
                if !inert {
                    return false;
                }
            }
            let Some(body) = callable.child_by_field_name("body") else {
                return true;
            };
            let mut pending = vec![body];
            while let Some(node) = pending.pop() {
                if node != body && is_procedure_boundary(node.kind()) {
                    continue;
                }
                if (node.kind() == "let_declaration"
                    && !self.let_class(&rust_source, node, PROOF_DEPTH).is_inert())
                    || (node.kind() == "struct_expression"
                        && !self
                            .expression_class(&rust_source, node, PROOF_DEPTH)
                            .is_inert())
                {
                    return false;
                }
                pending.extend(named_children(node));
            }
            return true;
        }
        if node.kind() == "parameter" {
            return node
                .child_by_field_name("type")
                .is_some_and(|ty| self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert());
        }
        if node.kind() == "self_parameter" {
            if crate::analyzer::rust::semantic::rust_self_parameter_is_borrowed(node) {
                return true;
            }
            let mut owner = node.parent();
            while let Some(item) = owner {
                if item.kind() == "impl_item" {
                    return item.child_by_field_name("type").is_some_and(|ty| {
                        self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert()
                    });
                }
                owner = item.parent();
            }
            return false;
        }
        if node.kind() == "self" {
            return self
                .declared_binding_type(&rust_source, node)
                .is_some_and(|ty| self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert());
        }
        // Binding mappings name the declaration, where lexical lookup need not
        // yet consider that binding visible. Read its structured owner directly.
        if let Some(owner) = node
            .parent()
            .and_then(|parent| binding_pattern_owner(parent, node.byte_range()))
        {
            return if owner.kind() == "let_declaration" {
                self.let_class(&rust_source, owner, PROOF_DEPTH).is_inert()
            } else {
                owner
                    .child_by_field_name("type")
                    .is_some_and(|ty| self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert())
            };
        }
        match node.kind() {
            "type_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "reference_type"
            | "pointer_type"
            | "tuple_type"
            | "array_type"
            | "primitive_type" => self.type_class(&rust_source, node, PROOF_DEPTH).is_inert(),
            _ => self
                .expression_class(&rust_source, node, PROOF_DEPTH)
                .is_inert(),
        }
    }
}

/// Prove the native B4/B5 obligation for one resolved Rust callable and one
/// result port. The caller owns dispatch completeness; this function answers
/// only the selected declaration's static signature and attributes.
pub fn rust_native_result_obligation(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    result_ordinal: u32,
) -> (RustNativeObligationProof, Option<DerivationExecutionCause>) {
    let (budget, cancellation) = native_proof_limits(analyzer);
    completed_native_proof(analyzer, cancellation.as_ref(), || {
        let Some(mut proof) = RustTypeProof::new(analyzer) else {
            return RustNativeObligationProof::Open("native_rust_analyzer");
        };
        proof.resolver.budget = budget;
        proof.resolver.cancellation = cancellation.clone();
        proof.native_obligation_for_target(target, result_ordinal)
    })
}

/// Whether `call` is the resolver-proven prelude `drop` wrapper. The wrapper
/// itself returns unit and contributes no discarded-result obligation, while
/// its argument call remains a separate result-use observation.
pub fn rust_call_is_standard_drop(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    range: Range,
) -> (bool, Option<DerivationExecutionCause>) {
    let (budget, cancellation) = native_proof_limits(analyzer);
    completed_native_proof(analyzer, cancellation.as_ref(), || {
        let Some(mut proof) = RustTypeProof::new(analyzer) else {
            return false;
        };
        proof.resolver.budget = budget;
        proof.resolver.cancellation = cancellation.clone();
        standard_drop_with_proof(&proof, file, source, range)
    })
}

fn standard_drop_with_proof(
    proof: &RustTypeProof<'_>,
    file: &ProjectFile,
    source: &str,
    range: Range,
) -> bool {
    let Some(rust_source) = proof.source(file) else {
        return false;
    };
    if rust_source.text() != source {
        return false;
    }
    let Some(call) = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        .filter(|node| {
            node.kind() == "call_expression"
                && node.byte_range() == (range.start_byte..range.end_byte)
        })
    else {
        return false;
    };
    let Some(function) = call
        .child_by_field_name("function")
        .map(call_function_target)
    else {
        return false;
    };
    function.kind() == "identifier"
        && rust_source.node_text(function) == Some("drop")
        && proof
            .prelude_item(&rust_source, function, "value")
            .as_deref()
            == Some("drop")
}

/// Whether the exact value mapped to `callable` in `source` has inert drop glue.
pub(crate) fn procedure_drops_run_no_user_code(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    callable: ByteRange<usize>,
    inventory: Option<&DropInventoryProof<'_>>,
) -> bool {
    RustTypeProof::new(analyzer).is_some_and(|mut proof| {
        proof.drop_inventory = inventory;
        proof.procedure_drops_are_inert(file, source, callable)
    })
}

/// The drop class of a try residual, distinct from the success value at
/// the same AST range. Unknown or custom Try carriers keep their obligation.
pub(crate) fn try_residual_drop_runs_no_user_code(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    expression: ByteRange<usize>,
    inventory: &DropInventoryProof<'_>,
) -> bool {
    let Some(mut proof) = RustTypeProof::new(analyzer) else {
        return false;
    };
    proof.drop_inventory = Some(inventory);
    let Some(rust_source) = proof.source(file) else {
        return false;
    };
    if rust_source.text() != source.as_ref() {
        return false;
    }
    let Some(node) = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(expression.start, expression.end)
        .filter(|node| node.byte_range() == expression && node.kind() == "try_expression")
    else {
        return false;
    };
    let Some(operand) = rust_unwrap_operand(node, rust_source.text()) else {
        return false;
    };
    let Some(carrier) = proof.modeled_receiver_type_bounded(&rust_source, operand, PROOF_DEPTH - 1)
    else {
        return false;
    };
    let (name, arguments) = match carrier {
        TypeRef::Named {
            name, arguments, ..
        } => (name, arguments),
        TypeRef::Declared { id, arguments, .. } => {
            let Some(overlay) = analyzer.semantic_model_overlay() else {
                return false;
            };
            let Some(owner) = overlay.symbols_with_id_in_family(&id, "rust").unique() else {
                return false;
            };
            (owner.qualified_name.clone(), arguments)
        }
        _ => return false,
    };
    match (name.as_str(), arguments.as_slice()) {
        ("core.option.Option" | "std.option.Option", [_]) => true,
        ("core.result.Result" | "std.result.Result", [_, error]) => proof
            .type_ref_class(error, PROOF_DEPTH - 1)
            .is_some_and(RustValueClass::is_inert),
        _ => false,
    }
}

/// The owner a method receiver's type is published under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RustReceiverOwner {
    /// A receiver type the reviewed std facts describe.
    Std(RustStdReceiver),
    /// The dot-joined canonical path of a std prelude type or a
    /// `use`-imported external type.
    Path(String),
}

impl RustReceiverOwner {
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Std(receiver) => receiver.owner_path().join("."),
            Self::Path(path) => path.clone(),
        }
    }
}

/// The owner of the receiver type of the Rust method call whose method name
/// spans `method` in `source`, with the call's written argument count. See
/// [`RustTypeProof::receiver_owner`].
#[cfg(test)]
pub(crate) fn rust_method_receiver_owner(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
) -> Option<(RustReceiverOwner, usize)> {
    completed_proof(analyzer, None, || {
        let proof = RustTypeProof::new(analyzer)?;
        rust_method_receiver_owner_with_proof(&proof, file, source, method)
    })
    .into_value()
}

pub(crate) fn rust_expression_receiver_owner_with_operation<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    expression: ByteRange<usize>,
    factory: &crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> Option<RustReceiverOwner> {
    completed_proof(analyzer, cancellation, || {
        let proof = RustTypeProof {
            drop_inventory: None,
            analyzer,
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
            resolver: SelectedRustTypeProofResolver {
                analyzer,
                factory,
                operation: RefCell::new(operation),
                cancellation,
            },
        };
        rust_expression_receiver_owner_with_proof(&proof, file, source, expression)
    })
    .into_value()
}

fn rust_expression_receiver_owner_with_proof<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    file: &ProjectFile,
    source: &str,
    expression: ByteRange<usize>,
) -> Option<RustReceiverOwner> {
    let rust_source = proof.source(file)?;
    if rust_source.text() != source {
        operational_proof_stop("source_mismatch", DerivationExecutionCause::Provider);
        return None;
    }
    let receiver = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(expression.start, expression.end)
        .filter(|node| node.byte_range() == expression)?;
    proof.receiver_owner(&rust_source, receiver)
}

pub(crate) fn rust_method_receiver_owner_with_operation<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
    factory: &'factory crate::analyzer::rust::native_points::RustDefinitionOperationFactory<
        'analyzer,
    >,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
        'analyzer,
        'selection,
    >,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> Option<(RustReceiverOwner, usize)> {
    rust_method_receiver_owner_attempt_with_operation(
        analyzer,
        file,
        source,
        method,
        factory,
        operation,
        cancellation,
    )
    .into_value()
}

pub(crate) fn rust_method_receiver_owner_attempt_with_operation<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
    factory: &'factory crate::analyzer::rust::native_points::RustDefinitionOperationFactory<
        'analyzer,
    >,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
        'analyzer,
        'selection,
    >,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> RustProofAttempt<(RustReceiverOwner, usize)> {
    completed_proof(analyzer, cancellation, || {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            operational_proof_stop("analyzer_unavailable", DerivationExecutionCause::Provider);
            return None;
        };
        let proof = RustTypeProof {
            drop_inventory: None,
            analyzer,
            rust,
            resolver: SelectedRustTypeProofResolver {
                analyzer,
                factory,
                operation: RefCell::new(operation),
                cancellation,
            },
        };
        rust_method_receiver_owner_with_proof(&proof, file, source, method)
    })
}

pub(crate) fn rust_modeled_receiver_type_with_operation<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    expression: Node<'_>,
    factory: &crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>,
) -> Option<TypeRef> {
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    let proof = RustTypeProof {
        drop_inventory: None,
        analyzer,
        rust,
        resolver: SelectedRustTypeProofResolver {
            analyzer,
            factory,
            operation: RefCell::new(operation),
            cancellation: None,
        },
    };
    proof.modeled_receiver_type(file, expression)
}

/// Resolve a declared type reached by the receiver-facts traversal with the
/// same nominal proof used by the direct receiver route.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_nominal_receiver_owner_with_operation<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    ty: Node<'_>,
    factory: &crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> Option<String> {
    rust_nominal_receiver_application_with_operation(
        analyzer,
        file,
        source,
        ty,
        factory,
        operation,
        cancellation,
    )
    .map(|(owner, _arguments)| owner)
}

/// Preserve the explicit generic application for query-local impl obligations.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_nominal_receiver_application_with_operation<'analyzer, 'tree>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    ty: Node<'tree>,
    factory: &crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> Option<(String, Vec<Node<'tree>>)> {
    completed_proof(analyzer, cancellation, || {
        let prove = |proof: &RustTypeProof<'_, _>| {
            let rust_source = proof.source(file)?;
            if rust_source.text() != source {
                operational_proof_stop("source_mismatch", DerivationExecutionCause::Provider);
                return None;
            }
            proof.nominal_type_owner(&rust_source, ty)
        };
        let proof = RustTypeProof {
            drop_inventory: None,
            analyzer,
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
            resolver: SelectedRustTypeProofResolver {
                analyzer,
                factory,
                operation: RefCell::new(operation),
                cancellation,
            },
        };
        prove(&proof)
    })
    .into_value()
}

fn rust_method_receiver_owner_with_proof<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
) -> Option<(RustReceiverOwner, usize)> {
    let rust_source = proof.source(file)?;
    if rust_source.text() != source {
        operational_proof_stop("source_mismatch", DerivationExecutionCause::Provider);
        return None;
    }
    let name = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(method.start, method.end)
        .filter(|node| node.byte_range() == method)?;
    let function = name.parent().filter(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(name)
    })?;
    let (receiver, _) = rust_method_call_parts(function)?;
    let call = std::iter::successors(function.parent(), |node| node.parent()).find(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .map(call_function_target)
                == Some(function)
    })?;
    let arity = named_children(call.child_by_field_name("arguments")?).len();
    let owner = proof.receiver_owner(&rust_source, receiver)?;
    Some((owner, arity))
}

/// The `std` or `core` prelude item `outcome` proves its reference names in
/// `namespace` (`"type"` or `"value"`): no workspace declaration, lexical
/// binding, or `use` route, and exactly one prelude reason.
pub(crate) fn prelude_item_of(
    outcome: &DefinitionLookupOutcome,
    namespace: &str,
) -> Option<String> {
    prelude_item_identity_of(outcome, namespace).map(|(_, name)| name)
}

/// Translate public selected evidence into the same wrapper identity proof the
/// store evaluator uses. Splitting resolver identities here inspects values,
/// never source syntax.
pub(crate) fn standard_wrapper_owner(outcome: &DefinitionLookupOutcome) -> Option<Vec<String>> {
    use super::SelectedTypeHeadEvidence;
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
    {
        return None;
    }
    if let Some((root, name)) = prelude_item_identity_of(outcome, "type") {
        let evidence = SelectedTypeHeadEvidence {
            prelude_item: Some((&root, &name, "type")),
            external_path: &[],
        };
        if crate::analyzer::rust::standard_wrapper_payload(&evidence).is_some() {
            let fact = rust_std_type_fact(&name)?;
            let mut path = fact
                .path
                .iter()
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>();
            path[0] = root;
            return Some(path);
        }
    }
    let mut subjects = outcome
        .diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.claim.as_ref())
        .filter(|claim| {
            matches!(
                claim.kind,
                UnindexedClaimKind::ResolvedExternal | UnindexedClaimKind::ExternalBoundary
            )
        })
        .flat_map(|claim| claim.subjects.iter())
        .collect::<Vec<_>>();
    subjects.sort_unstable();
    subjects.dedup();
    let mut owner = None;
    for subject in subjects {
        let path = if subject.contains("::") {
            subject.split("::").map(str::to_owned).collect::<Vec<_>>()
        } else {
            subject.split('.').map(str::to_owned).collect::<Vec<_>>()
        };
        let evidence = SelectedTypeHeadEvidence {
            prelude_item: None,
            external_path: &path,
        };
        crate::analyzer::rust::standard_wrapper_payload(&evidence)?;
        if let Some(selected) = &owner {
            if selected != &path {
                return None;
            }
        } else {
            owner = Some(path);
        }
    }
    owner
}

/// The selected prelude crate and item, preserving core/std route authority.
pub(crate) fn prelude_item_identity_of(
    outcome: &DefinitionLookupOutcome,
    namespace: &str,
) -> Option<(String, String)> {
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
        || outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.claim.is_some())
    {
        return None;
    }
    let mut prelude = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "rust_prelude_item");
    let reason = prelude.next()?;
    if prelude.next().is_some() {
        return None;
    }
    let evidence: serde_json::Value =
        serde_json::from_str(&reason.message).expect("a Rust prelude reason carries JSON evidence");
    let standard = matches!(evidence["crate"].as_str(), Some("std" | "core"));
    (standard && evidence["namespace"].as_str() == Some(namespace))
        .then(|| {
            Some((
                evidence["crate"].as_str()?.to_owned(),
                evidence["name"].as_str()?.to_owned(),
            ))
        })
        .flatten()
}

/// What one reviewed std operation transfers at its call (#3757).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustStdBuiltinTransfer {
    /// The receiver's value reaches the normal result: `str::to_owned`,
    /// `str::len`.
    ReceiverToResult,
    /// The one argument's value reaches the normal result: `Ok(x)`,
    /// `Err(x)`, `Some(x)`.
    ArgumentToResult,
    /// The normal result is fresh and no input reaches it: `String::new()`.
    FreshResult,
}

/// One call of a reviewed std operation of the in-code fact table, and what
/// it transfers (#3757). These are Bifrost-authored language-library facts,
/// not reviewed pack summaries, so they model the call at the derived tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustStdBuiltinCall {
    /// The operation's canonical dot-joined std path, such as
    /// `std.primitive.str.to_owned`.
    pub operation: String,
    pub transfer: RustStdBuiltinTransfer,
}

impl<'a, R: RustTypeProofResolver> RustTypeProof<'a, R> {
    /// The reviewed std operation `call` invokes, when its identity is
    /// proven: the receiver is a `&str` by structure and the resolver finds
    /// no workspace candidate for the method (a same-named workspace trait
    /// method on `str` would make the call ambiguous with the std method,
    /// rustc E0034), or the resolver proves the callee or its owner is the
    /// `std` or `core` prelude item.
    ///
    /// Each branch first checks the written name and arity against the
    /// reviewed fact tables, which are keyed by them, and resolves names
    /// only for a call some fact could describe: the resolution is the
    /// expensive part, and most calls name no reviewed operation.
    fn builtin_call(&self, source: &RustSource, call: Node<'_>) -> Option<RustStdBuiltinCall> {
        let function = call_function_target(call.child_by_field_name("function")?);
        let arity = named_children(call.child_by_field_name("arguments")?).len();
        match function.kind() {
            "field_expression" => {
                let (receiver, method) = rust_method_call_parts(function)?;
                let name = source.node_text(method)?;
                if !RUST_STD_METHOD_FACTS
                    .iter()
                    .any(|fact| fact.method == name && fact.arity == arity)
                {
                    return None;
                }
                let receiver = match self.expression_class(source, receiver, PROOF_DEPTH) {
                    RustValueClass::Str => RustStdReceiver::Str,
                    RustValueClass::String => RustStdReceiver::String,
                    _ => return None,
                };
                let fact = rust_std_method_fact(receiver, name, arity)?;
                let outcome = self.resolve(source, method)?;
                if !outcome.definitions.is_empty() || outcome.lexical_definition.is_some() {
                    return None;
                }
                Some(RustStdBuiltinCall {
                    operation: format!("{}.{}", fact.receiver.owner_path().join("."), fact.method),
                    transfer: RustStdBuiltinTransfer::ReceiverToResult,
                })
            }
            "identifier" => {
                // A prelude reason names the spelling it resolved, so the
                // written name is the prelude name the fact must match.
                rust_std_constructor_fact(source.node_text(function)?)?;
                let name = self.prelude_item(source, function, "value")?;
                let fact = rust_std_constructor_fact(&name)?;
                (fact.arity == arity).then(|| RustStdBuiltinCall {
                    operation: format!(
                        "{}.{}",
                        rust_std_type_fact(fact.constructs)
                            .expect("a reviewed constructor names a reviewed std type")
                            .path
                            .join("."),
                        fact.name
                    ),
                    transfer: RustStdBuiltinTransfer::ArgumentToResult,
                })
            }
            "scoped_identifier" => {
                let fact = self.prelude_type_associated_fact(source, function, arity)?;
                Some(RustStdBuiltinCall {
                    operation: format!(
                        "{}.{}",
                        rust_std_type_fact(fact.owner)?.path.join("."),
                        fact.function
                    ),
                    transfer: RustStdBuiltinTransfer::FreshResult,
                })
            }
            _ => None,
        }
    }
}

/// The reviewed std operation the Rust call spanning `call` in `source`
/// invokes, if its identity is proven. See [`RustTypeProof::builtin_call`].
pub(crate) fn rust_std_builtin_call(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    call: ByteRange<usize>,
) -> Option<RustStdBuiltinCall> {
    let proof = RustTypeProof::new(analyzer)?;
    let rust_source = proof.source(file)?;
    if rust_source.text() != source.as_ref() {
        return None;
    }
    let node = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(call.start, call.end)
        .filter(|node| node.byte_range() == call && node.kind() == "call_expression")?;
    proof.builtin_call(&rust_source, node)
}

/// Direct receiver proof for the conversion-effect exception. Inferred values,
/// including intermediate calls, remain open until #10976 supplies exact types.
/// The existing classifier remains unchanged for its other consumers.
pub(crate) fn rust_std_direct_string_receiver(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    call: ByteRange<usize>,
) -> bool {
    let prove = || -> Option<bool> {
        let proof = RustTypeProof::new(analyzer)?;
        let rust_source = proof.source(file)?;
        if rust_source.text() != source.as_ref() {
            return None;
        }
        let node = rust_source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(call.start, call.end)
            .filter(|node| node.byte_range() == call && node.kind() == "call_expression")?;
        let (receiver, _) = rust_method_call_parts(node.child_by_field_name("function")?)?;
        if receiver.kind() != "identifier" {
            return None;
        }
        let binding = resolve_lexical_binding_with_visibility(
            Language::Rust,
            rust_source.tree().root_node(),
            rust_source.text(),
            receiver.start_byte(),
            receiver.end_byte(),
            rust_source.node_text(receiver)?,
        )
        .ok()??;
        let (LexicalBindingResolution::Parameter(definition)
        | LexicalBindingResolution::OtherLocal(definition)) = binding;
        let declaration = rust_source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(
                definition.declaration_range.start_byte,
                definition.declaration_range.end_byte,
            )?;
        let ty = binding_pattern_owner(
            declaration,
            definition.name_range.start_byte..definition.name_range.end_byte,
        )?
        .child_by_field_name("type")?;
        Some(proof.type_class(&rust_source, ty, PROOF_DEPTH) == RustValueClass::String)
    };
    prove().unwrap_or(false)
}

/// Identity conversions proven from structured declared error types.
/// Boxing needs source-side trait bounds and is not discharged here.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RustResidualError {
    Unit,
    Primitive(String),
    ReferenceStr(bool),
    Declaration(CodeUnit),
    /// An external error type, as the shared selected-type resolver's
    /// canonical identity: only `Model { arguments: [] }`. Both sides build it
    /// through that resolver, so equal values name one unambiguous model
    /// symbol in one active model set. The destination also proves its source
    /// spelling through the Cargo-selected route.
    Model(brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType),
}

impl RustResidualError {
    fn model(
        ty: brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType,
    ) -> Option<Self> {
        use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType;
        matches!(&ty, RustConversionType::Model { arguments, .. } if arguments.is_empty())
            .then_some(Self::Model(ty))
    }
}

impl<R: RustTypeProofResolver> RustTypeProof<'_, R> {
    /// Expand a written type's head through the shared selected-type alias
    /// expansion (#10770). Supplied arguments keep their caller context;
    /// defaults use the alias's declaration context and earlier bindings.
    /// An unsupported or unresolvable alias stays unproven.
    fn expand_written_type(
        &self,
        source: &RustSource,
        ty: Node<'_>,
    ) -> Option<crate::analyzer::rust::call_conversion::selected_type::AliasTypeExpr> {
        use crate::analyzer::rust::call_conversion::selected_type::{
            AliasTypeExpr, alias_type_expr, expand_alias_head,
        };
        let mut remaining = 256;
        let written = alias_type_expr(
            ty,
            &source.file,
            &Arc::<str>::from(source.text()),
            &mut remaining,
        )?;
        match written {
            AliasTypeExpr::Constructor { ref site, .. } if site.kind != "primitive_type" => {
                expand_alias_head(
                    self.analyzer,
                    written,
                    &CancellationToken::default(),
                    0,
                    false,
                )
                .ok()
            }
            other => Some(other),
        }
    }

    /// The head node an expanded constructor names, in its own file.
    fn constructor_head<'s>(
        &self,
        site: &crate::analyzer::rust::call_conversion::selected_type::TypeSite,
        site_source: &'s RustSource,
    ) -> Option<Node<'s>> {
        if site_source.text() != site.source.as_ref() {
            return None;
        }
        crate::analyzer::rust::call_conversion::selected_type::exact_node(
            site_source.tree().root_node(),
            &site.kind,
            site.start,
            site.end,
        )
        .ok()
        .flatten()
    }

    fn residual_error(
        &self,
        expression: crate::analyzer::rust::call_conversion::selected_type::AliasTypeExpr,
    ) -> Option<RustResidualError> {
        use crate::analyzer::rust::call_conversion::selected_type::{
            AliasTypeExpr, expand_alias_head,
        };
        let expression = match expression {
            AliasTypeExpr::Constructor { ref site, .. } if site.kind != "primitive_type" => {
                expand_alias_head(
                    self.analyzer,
                    expression,
                    &CancellationToken::default(),
                    0,
                    false,
                )
                .ok()?
            }
            other => other,
        };
        match expression {
            AliasTypeExpr::Shape { site, arguments }
                if site.kind == "unit_type" && arguments.is_empty() =>
            {
                Some(RustResidualError::Unit)
            }
            AliasTypeExpr::Reference { mutable, referent } => match *referent {
                AliasTypeExpr::Constructor { site, arguments }
                    if arguments.is_empty()
                        && site.kind == "primitive_type"
                        && site.source.get(site.start..site.end) == Some("str") =>
                {
                    Some(RustResidualError::ReferenceStr(mutable))
                }
                _ => None,
            },
            AliasTypeExpr::Constructor { site, arguments } if site.kind == "primitive_type" => {
                arguments.is_empty().then_some(())?;
                Some(RustResidualError::Primitive(
                    site.source.get(site.start..site.end)?.to_owned(),
                ))
            }
            AliasTypeExpr::Constructor { site, arguments } if arguments.is_empty() => {
                let site_source = self.source(&site.file)?;
                let head = self.constructor_head(&site, &site_source)?;
                let Some(unit) = self.workspace_definition(&site_source, head) else {
                    // Not a workspace item: an external type resolves through
                    // the shared resolver's Cargo-selected model route.
                    return RustResidualError::model(
                        crate::analyzer::rust::call_conversion::type_conversion_type(
                            self.analyzer,
                            &site.file,
                            site_source.text(),
                            head,
                        )
                        .ok()?,
                    );
                };
                let declaration_source = self.source(unit.source())?;
                let declaration = self.declaration(&declaration_source, &unit)?;
                (matches!(declaration.kind(), "struct_item" | "enum_item")
                    && declaration.child_by_field_name("type_parameters").is_none())
                .then_some(RustResidualError::Declaration(unit))
            }
            _ => None,
        }
    }

    /// The error type of a written `Result` type, after the shared alias
    /// expansion: `core::result::Result<T, E>`'s second type argument.
    fn result_error_type(&self, source: &RustSource, ty: Node<'_>) -> Option<RustResidualError> {
        use crate::analyzer::rust::call_conversion::selected_type::AliasTypeExpr;
        let AliasTypeExpr::Constructor { site, arguments } =
            self.expand_written_type(source, ty)?
        else {
            return None;
        };
        let site_source = self.source(&site.file)?;
        let head = self.constructor_head(&site, &site_source)?;
        if !self.standard_result_type(&site_source, head) {
            return None;
        }
        let mut types = arguments
            .into_iter()
            .filter(|argument| !matches!(argument, AliasTypeExpr::Lifetime));
        let (Some(_), Some(error), None) = (types.next(), types.next(), types.next()) else {
            return None;
        };
        self.residual_error(error)
    }

    fn operand_error_type(
        &self,
        source: &RustSource,
        operand: Node<'_>,
        depth: usize,
    ) -> Option<RustResidualError> {
        if depth == 0 {
            return None;
        }
        match operand.kind() {
            "identifier" => {
                if let Some(ty) = self.declared_binding_type(source, operand) {
                    self.result_error_type(source, ty)
                } else {
                    self.operand_error_type(
                        source,
                        self.binding_initializer(source, operand)?,
                        depth - 1,
                    )
                }
            }
            "parenthesized_expression" => {
                self.operand_error_type(source, *named_children(operand).first()?, depth - 1)
            }
            "call_expression" => {
                let function = call_function_target(operand.child_by_field_name("function")?);
                if function.kind() == "identifier"
                    && self.prelude_item(source, function, "value").as_deref() == Some("Err")
                {
                    let arguments = named_children(operand.child_by_field_name("arguments")?);
                    let [argument] = arguments.as_slice() else {
                        return None;
                    };
                    return (argument.kind() == "unit_expression")
                        .then_some(RustResidualError::Unit);
                }
                let Some(unit) = self.callee_definition(source, operand) else {
                    return self.modeled_result_error(source, operand);
                };
                let callee_source = self.source(unit.source())?;
                let declaration = self.declaration(&callee_source, &unit)?;
                // Calling an `async fn` yields a future, not its written return.
                if super::semantic::function_is_async(declaration) {
                    return None;
                }
                self.result_error_type(
                    &callee_source,
                    declaration.child_by_field_name("return_type")?,
                )
            }
            // `path().await` on a direct path call to one selected `async fn`
            // item with a written return type yields that return type. This
            // is the only place an await is typed: replace this arm if the
            // shared selected-type resolver gains await typing. It says nothing
            // about the async body or cancellation. Method calls, closures,
            // async blocks, fn pointers, awaited bindings and a non-async fn
            // returning a future stay open, and so does a callee that, or whose enclosing
            // module, impl, trait or function, carries an outer attribute, since an
            // attribute macro can rewrite the signature.
            "await_expression" => {
                let call = *named_children(operand).first()?;
                if call.kind() != "call_expression"
                    || !matches!(
                        call_function_target(call.child_by_field_name("function")?).kind(),
                        "identifier" | "scoped_identifier"
                    )
                {
                    return None;
                }
                let unit = self.callee_definition(source, call)?;
                let callee_source = self.source(unit.source())?;
                let declaration = self.declaration(&callee_source, &unit)?;
                if declaration.kind() != "function_item"
                    || !super::semantic::function_is_async(declaration)
                    || item_or_enclosing_item_attributed(declaration)
                {
                    return None;
                }
                self.result_error_type(
                    &callee_source,
                    declaration.child_by_field_name("return_type")?,
                )
            }
            _ => None,
        }
    }

    /// The error type of an external callee's declared `Result` return, read
    /// from the active model the same way every other `modeled_call_return_type`
    /// consumer reads it, then converted by the shared selected-type resolver.
    /// A type parameter, a projection (`F::Err`) or an error with arguments
    /// stays open.
    fn modeled_result_error(
        &self,
        source: &RustSource,
        call: Node<'_>,
    ) -> Option<RustResidualError> {
        use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustProjectedType;
        let returned = self.modeled_call_return(source, call, PROOF_DEPTH)?;
        let projected = crate::analyzer::rust::call_conversion::modeled_type_projection(
            self.analyzer,
            &source.file,
            source.text(),
            call,
            &returned.returned,
        )
        .ok()?;
        // Result's constructor and its error argument are sufficient; an
        // unsupported success type cannot affect FromResidual's identity.
        projected.replay(self.analyzer, &[vec![1]]);
        let RustProjectedType::Model {
            symbol,
            mut arguments,
            ..
        } = projected.ty
        else {
            return None;
        };
        let snapshot = self.analyzer.active_semantic_model_snapshot()?;
        let overlay = snapshot.semantic_model_overlay()?;
        let result = crate::analyzer::RustOverlayCrates::new(Some(overlay))
            .referenceable_symbol("std.result.Result")?;
        if symbol != result.id || arguments.len() != 2 {
            return None;
        }
        let error = arguments.pop()?.into_complete().ok()?;
        let brokk_bifrost_analysis::analyzer::usages::call_conversion::RustConversionType::Model {
            ref symbol,
            ..
        } = error
        else {
            return None;
        };
        let errors = overlay.symbols_with_id_in_family(symbol, "rust");
        errors.unique()?;
        // Recorded cross-pack names do not identify a dependency version.
        // Until that provenance is represented, every agreeing callable's
        // defining provider must also declare the error. Curated annotation
        // contributors do not supply its retained structured signature.
        // Equivalent defining records may cover more than one provider.
        // Annotation contributors can disagree with the retained declaration,
        // so their provenance cannot certify the error identity either.
        let error_providers = errors.records.iter().map(|symbol| &symbol.provenance);
        if !returned
            .providers
            .iter()
            .map(|symbol| &symbol.provenance)
            .all(|provider| {
                error_providers.clone().any(|error| {
                    provider.pack_id == error.pack_id
                        && provider.pack_version == error.pack_version
                        && provider.pack_digest == error.pack_digest
                })
            })
        {
            return None;
        }
        RustResidualError::model(error)
    }

    /// The workspace function a call's written callee selects.
    fn callee_definition(&self, source: &RustSource, call: Node<'_>) -> Option<CodeUnit> {
        let function = call_function_target(call.child_by_field_name("function")?);
        let name = match function.kind() {
            "field_expression" => function.child_by_field_name("field")?,
            "identifier" | "scoped_identifier" => function,
            _ => return None,
        };
        self.workspace_definition(source, name)
    }
}

pub(crate) fn residual_conversion_runs_no_user_code(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    exact_source: &Arc<str>,
    question: ByteRange<usize>,
) -> bool {
    let Some(proof) = RustTypeProof::new(analyzer) else {
        return false;
    };
    let Some(source) = proof.source(file) else {
        return false;
    };
    if source.text() != exact_source.as_ref() {
        return false;
    }
    let Some(node) = source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(question.start, question.end)
        .filter(|node| node.byte_range() == question && node.kind() == "try_expression")
    else {
        return false;
    };
    let mut callable = node.parent();
    while let Some(parent) = callable {
        if is_procedure_boundary(parent.kind()) {
            break;
        }
        callable = parent.parent();
    }
    let Some(return_type) = callable.and_then(|node| node.child_by_field_name("return_type"))
    else {
        return false;
    };
    let Some(error) = proof.result_error_type(&source, return_type) else {
        return false;
    };
    named_children(node)
        .first()
        .and_then(|operand| proof.operand_error_type(&source, *operand, PROOF_DEPTH))
        .is_some_and(|operand_error| operand_error == error)
}

/// Whether `item` or any item enclosing it carries an outer attribute. An
/// attribute macro on an enclosing module, impl, trait or function can rewrite
/// the signatures of the items inside it. Custom inner attributes are unstable,
/// so outer attributes are the macro entry points to refuse.
fn item_or_enclosing_item_attributed(item: Node<'_>) -> bool {
    let mut current = Some(item);
    while let Some(node) = current {
        if matches!(
            node.kind(),
            "function_item" | "mod_item" | "impl_item" | "trait_item"
        ) && outer_attributes(node).next().is_some()
        {
            return true;
        }
        current = node.parent();
    }
    false
}

/// A callable whose body is a separate procedure.
/// Whether `expression` is a place rooted at `self` or a local binding, so
/// borrowing it creates no temporary.
fn is_place(source: &RustSource, expression: Node<'_>) -> bool {
    let mut current = expression;
    loop {
        match current.kind() {
            "self" => return true,
            "identifier" => {
                return source.node_text(current).is_some_and(|identifier| {
                    resolve_lexical_binding(
                        Language::Rust,
                        source.tree().root_node(),
                        source.text(),
                        current.start_byte(),
                        current.end_byte(),
                        identifier,
                    )
                    .is_some()
                });
            }
            "field_expression" => match current.child_by_field_name("value") {
                Some(value) => current = value,
                None => return false,
            },
            _ => return false,
        }
    }
}

/// The `parameter` or `let_declaration` whose `pattern` field contains the
/// binding name at `name`, climbing from `start`. The nearest such node decides:
/// a binding declared in a match arm, `if let`, `while let` or `for` pattern
/// inside a `let` initializer lies in that `let`'s value, not its pattern, so
/// the enclosing `let` and its type do not describe the binding (#12652).
/// A procedure boundary ends the climb because an enclosing function or closure
/// does not own its inner bindings.
pub(super) fn binding_pattern_owner<'t>(
    start: Node<'t>,
    name: std::ops::Range<usize>,
) -> Option<Node<'t>> {
    let mut current = Some(start);
    while let Some(node) = current {
        if matches!(node.kind(), "parameter" | "let_declaration") {
            return node
                .child_by_field_name("pattern")
                .filter(|pattern| {
                    pattern.start_byte() <= name.start && name.end <= pattern.end_byte()
                })
                .map(|_| node);
        }
        if is_procedure_boundary(node.kind()) {
            return None;
        }
        current = node.parent();
    }
    None
}

fn is_procedure_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_item" | "closure_expression" | "async_block" | "gen_block"
    )
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

/// Alias identities are not nominal constructors. Until their targets are
/// normalized, neither an input mismatch nor result agreement may use them.
fn model_type_contains_alias(
    ty: &TypeRef,
    model: &super::trait_applicability::ModelApplicability<'_, '_>,
) -> bool {
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                if model.owner(ty).is_some_and(|symbol| {
                    symbol.kind
                        == crate::analyzer::semantic_model::SemanticModelSymbolKind::TypeAlias
                }) {
                    return true;
                }
                pending.extend(arguments);
            }
            TypeRef::Projection {
                owner,
                trait_type,
                arguments,
                ..
            } => {
                pending.push(owner);
                pending.extend(trait_type.as_deref());
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => pending.extend([key.as_ref(), value.as_ref()]),
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref()),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                pending.extend(result.as_deref());
            }
            TypeRef::Unknown | TypeRef::TypeParameter { .. } => {}
        }
    }
    false
}

/// Only a proven structural mismatch may remove a From input candidate.
/// Reference mutability is erased by TypeRef, so both reference contracts
/// remain possible. Unknowns and generic parameters never prove inequality.
fn model_argument_definitely_differs(
    actual: &TypeRef,
    expected: &TypeRef,
    model: &super::trait_applicability::ModelApplicability<'_, '_>,
) -> bool {
    if model_type_contains_alias(actual, model) || model_type_contains_alias(expected, model) {
        return false;
    }
    let mut pending = vec![(actual, expected)];
    while let Some((actual, expected)) = pending.pop() {
        match (actual, expected) {
            (
                TypeRef::ByRef {
                    element: actual, ..
                },
                TypeRef::ByRef {
                    element: expected, ..
                },
            ) => {
                pending.push((actual, expected));
            }
            (TypeRef::ByRef { .. }, other) | (other, TypeRef::ByRef { .. }) => {
                if model.owner(other).is_some() {
                    return true;
                }
            }
            _ => {
                let (Some(actual_owner), Some(expected_owner)) =
                    (model.owner(actual), model.owner(expected))
                else {
                    continue;
                };
                if actual_owner.id != expected_owner.id {
                    return true;
                }
                if let (
                    TypeRef::Named {
                        arguments: actual, ..
                    }
                    | TypeRef::Declared {
                        arguments: actual, ..
                    },
                    TypeRef::Named {
                        arguments: expected,
                        ..
                    }
                    | TypeRef::Declared {
                        arguments: expected,
                        ..
                    },
                ) = (actual, expected)
                {
                    // An omitted/default argument is not an incompatible one.
                    if actual.len() == expected.len() {
                        pending.extend(actual.iter().zip(expected));
                    }
                }
            }
        }
    }
    false
}

/// Canonicalize a fully resolved result before comparing candidate contracts.
/// Transport equality of Unknown, projections, or free binders proves nothing.
fn resolved_model_result(
    mut result: TypeRef,
    model: &super::trait_applicability::ModelApplicability<'_, '_>,
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
) -> Option<TypeRef> {
    let mut pending = vec![&mut result];
    while let Some(ty) = pending.pop() {
        if matches!(ty, TypeRef::Named { .. } | TypeRef::Declared { .. }) {
            let symbol = model.owner(ty)?;
            if symbol.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::TypeAlias {
                return None;
            }
            let (TypeRef::Named {
                arguments,
                nullable,
                ..
            }
            | TypeRef::Declared {
                arguments,
                nullable,
                ..
            }) = ty
            else {
                unreachable!()
            };
            let declaration =
                brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                    active, &symbol,
                )?;
            if arguments.len() != declaration.type_parameters.len() {
                return None;
            }
            *ty = TypeRef::Declared {
                id: symbol.id.clone(),
                arguments: std::mem::take(arguments),
                nullable: *nullable,
            };
        }
        match ty {
            TypeRef::Unknown
            | TypeRef::TypeParameter { .. }
            | TypeRef::Projection { .. }
            | TypeRef::Wildcard { .. } => return None,
            TypeRef::Named { .. } => unreachable!("canonicalized above"),
            TypeRef::Declared { arguments, .. } => pending.extend(arguments),
            TypeRef::ByRef { element, .. }
            | TypeRef::Array { element }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::FixedArray { element, length } => {
                length.parse::<u64>().ok()?;
                pending.push(element);
            }
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Map { key, value } => pending.extend([key.as_mut(), value.as_mut()]),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter_mut().map(|parameter| &mut parameter.r#type));
                pending.push(result.as_deref_mut()?);
            }
        }
    }
    Some(result)
}

/// Whether `ty` holds an associated-type projection on the method's own `Self`:
/// an erased wildcard owner or the `Self` parameter, with no extra arguments.
fn type_ref_has_self_projection(ty: &TypeRef) -> bool {
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty {
            TypeRef::Projection {
                owner, arguments, ..
            } if arguments.is_empty() && is_self_projection_owner(owner) => return true,
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments);
            }
            TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::Array { element } => pending.push(element),
            TypeRef::Tuple { elements } => pending.extend(elements),
            _ => {}
        }
    }
    false
}

fn is_self_projection_owner(owner: &TypeRef) -> bool {
    match owner {
        TypeRef::Wildcard {
            variance: crate::analyzer::semantic_model::WildcardVariance::Any,
            bound: None,
        } => true,
        TypeRef::TypeParameter { name } => name == "Self",
        _ => false,
    }
}

/// Replace each projection on the method's own `Self` by the associated type
/// `receiver` binds for the method's trait at `actual`. A projection with no
/// single concrete binding is left as it was.
fn bind_self_projections(
    returned: &mut TypeRef,
    receiver: &SemanticModelSymbol,
    actual: &TypeRef,
    trait_: &SemanticModelSymbol,
    model: &super::trait_applicability::ModelApplicability<'_, '_>,
) {
    let mut pending = vec![returned];
    while let Some(ty) = pending.pop() {
        let bound = match &*ty {
            TypeRef::Projection {
                owner,
                trait_type: Some(projected_trait),
                name,
                arguments,
            } if arguments.is_empty()
                && is_self_projection_owner(owner)
                && model
                    .owner(projected_trait)
                    .is_some_and(|projected| projected.id == trait_.id) =>
            {
                model.selected_associated_type(receiver, actual, trait_, name)
            }
            _ => None,
        };
        if let Some(bound) = bound {
            *ty = bound;
            continue;
        }
        match ty {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments.iter_mut());
            }
            TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::Array { element } => pending.push(element),
            TypeRef::Tuple { elements } => pending.extend(elements.iter_mut()),
            _ => {}
        }
    }
}

/// Whether `ty` still names a type parameter anywhere inside it.
pub(super) fn type_ref_mentions_type_parameter(ty: &TypeRef) -> bool {
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty {
            TypeRef::TypeParameter { .. } => return true,
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments);
            }
            TypeRef::Projection {
                owner,
                trait_type,
                arguments,
                ..
            } => {
                pending.push(owner);
                pending.extend(trait_type.as_deref());
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => pending.extend([key.as_ref(), value.as_ref()]),
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref()),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                pending.extend(result.as_deref());
            }
            TypeRef::Unknown => {}
        }
    }
    false
}

/// A query-time guard for provenance refinement; absent type proof stays unknown.
pub(super) fn receiver_type_parameter_dependency(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    receiver: brokk_bifrost_core::analyzer::model::Range,
) -> brokk_bifrost_analysis::analyzer::languages::ReceiverTypeParameterDependency {
    use brokk_bifrost_analysis::analyzer::languages::ReceiverTypeParameterDependency;
    let dependency = completed_proof(analyzer, None, || {
        let proof = RustTypeProof::new(analyzer)?;
        let source = proof.source(file)?;
        let expression = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(receiver.start_byte, receiver.end_byte)?;
        // Source struct literals need no model result-type inference. Keep this
        // extension local to provenance so resolver answers do not change.
        let ty = proof.modeled_receiver_type(file, expression).or_else(|| {
            let mut expression = expression;
            for _ in 0..PROOF_DEPTH {
                if expression.kind() == "struct_expression" {
                    let ty = expression.child_by_field_name("name")?;
                    let (name, arguments) = if ty.kind() == "generic_type" {
                        (
                            ty.child_by_field_name("type")?,
                            named_children(ty.child_by_field_name("type_arguments")?),
                        )
                    } else {
                        (ty, Vec::new())
                    };
                    let unit = proof.workspace_definition(&source, name)?;
                    let declaration_source = proof.source(unit.source())?;
                    let declaration = proof.declaration(&declaration_source, &unit)?;
                    if !matches!(declaration.kind(), "struct_item" | "enum_item") {
                        return None;
                    }
                    let parameters = declaration
                        .child_by_field_name("type_parameters")
                        .map(named_children)
                        .unwrap_or_default();
                    if parameters.len() != arguments.len() {
                        return None;
                    }
                    let arguments = arguments
                        .into_iter()
                        .map(|argument| {
                            let overlay = analyzer.semantic_model_overlay_read().published()?;
                            let active = analyzer.active_semantic_models()?;
                            let mut applicability =
                                super::trait_applicability::ModelApplicability::new(
                                    analyzer,
                                    proof.rust,
                                    &overlay,
                                    &active,
                                    &proof.resolver,
                                );
                            applicability.receiver_type(file, source.text(), argument)
                        })
                        .collect::<Option<Vec<_>>>()?;
                    return Some(TypeRef::Named {
                        name: unit.fq_name(),
                        arguments,
                        nullable: false,
                    });
                }
                expression = proof.binding_initializer(&source, expression)?;
            }
            None
        })?;
        if ty.contains_unknown() {
            return None;
        }
        Some(type_ref_mentions_type_parameter(&ty))
    })
    .into_value();
    match dependency {
        Some(true) => ReceiverTypeParameterDependency::Yes,
        Some(false) => ReceiverTypeParameterDependency::No,
        None => ReceiverTypeParameterDependency::Unknown,
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::std_types::*;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

    #[test]
    #[hardwon("#12755: unindexed imports certified String parameters and constructors as inert")]
    fn imported_string_is_not_inert() {
        let mut failures = Vec::new();
        for (module, import, spelling) in [
            (
                "mod other { pub struct String; impl Drop for String { fn drop(&mut self) {} } impl String { pub fn new() -> Self { Self } pub fn from(_: &str) -> Self { Self } } }",
                "use other::String;",
                "String",
            ),
            (
                "mod other { pub struct String; impl Drop for String { fn drop(&mut self) {} } impl String { pub fn new() -> Self { Self } pub fn from(_: &str) -> Self { Self } } }",
                "use other::*;",
                "String",
            ),
            ("", "use some_dependency::String;", "String"),
            ("", "use some_dependency::*;", "String"),
            // A raw spelling names the same binding as the import.
            ("", "use some_dependency::String;", "r#String"),
        ] {
            let text = format!(
                "{module} {import} fn run(v: {spelling}) {{ let y = v; let s = {spelling}::new(); let t = {spelling}::from(\"x\"); }}"
            );
            let fixture = AnalyzerFixture::new_for_language(
                Language::Rust,
                &[
                    (
                        "Cargo.toml",
                        "[package]\nname='prelude_shadow'\nversion='0.1.0'\nedition='2021'\n",
                    ),
                    ("src/lib.rs", &text),
                ],
            );
            let analyzer = fixture.analyzer.analyzer();
            let _scope = AnalyzerQueryScope::new(analyzer);
            let proof = RustTypeProof::new(analyzer).unwrap();
            let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
            let source = proof.source(&file).unwrap();
            let function = named_children(source.tree().root_node())
                .into_iter()
                .find(|node| node.kind() == "function_item")
                .unwrap();
            let parameters = function.child_by_field_name("parameters").unwrap();
            let parameter = named_children(parameters)
                .into_iter()
                .find(|node| node.kind() == "parameter")
                .unwrap();
            let ty = parameter.child_by_field_name("type").unwrap();
            if proof.type_class(&source, ty, PROOF_DEPTH).is_inert() {
                failures.push(format!("{import} {spelling} parameter"));
            }
            let body = function.child_by_field_name("body").unwrap();
            for declaration in named_children(body)
                .into_iter()
                .filter(|node| node.kind() == "let_declaration")
            {
                let value = declaration.child_by_field_name("value").unwrap();
                if value.kind() == "call_expression"
                    && proof
                        .expression_class(&source, value, PROOF_DEPTH)
                        .is_inert()
                {
                    failures.push(format!("{import} {}", source.node_text(value).unwrap()));
                }
            }
        }
        assert!(failures.is_empty(), "inert imported String: {failures:?}");
    }

    fn selected_external_call(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
    ) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
        let cancellation = CancellationToken::default();
        let factory = crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
            analyzer,
            &cancellation,
        )?;
        let mut operation = match factory.open(&cancellation).ok()? {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => return None,
        };
        let scope = AnalyzerQueryScope::new(analyzer);
        crate::analyzer::rust::external_calls::resolve_exact_rust_external_call_with_operation(
            analyzer,
            scope.token(),
            file,
            source,
            tree,
            site,
            || None,
            Some(&cancellation),
            &factory,
            &mut operation,
        )
    }

    #[test]
    #[hardwon("#11834: a decided-false cfg mod kept unrelated crate-root lookups incomplete")]
    fn selected_cfg_placement_alias_proof_tracks_edits_and_configuration() {
        use std::collections::BTreeSet;
        const MANIFEST: &str = "[package]\nname='placement'\nversion='0.1.0'\nedition='2021'\n[workspace]\nmembers=[]\n";
        const LINUX: &str = "[build]\ntarget='x86_64-unknown-linux-gnu'\n";
        const WINDOWS: &str = "[build]\ntarget='x86_64-pc-windows-msvc'\n";
        fn fixture(source: &str, configuration: &str, extras: &[(&str, &str)]) -> AnalyzerFixture {
            let mut files = vec![
                ("Cargo.toml", MANIFEST),
                (".cargo/config.toml", configuration),
                ("src/lib.rs", source),
                ("src/facade.rs", "pub use crate::types::R;"),
                ("src/types.rs", "pub type R<T> = Result<T, ()>;"),
                ("src/gated.rs", "pub struct Gated;"),
            ];
            files.extend_from_slice(extras);
            AnalyzerFixture::new(&files)
        }
        fn answer(fixture: &AnalyzerFixture) -> bool {
            let analyzer = fixture.analyzer.analyzer();
            let _scope = AnalyzerQueryScope::new(analyzer);
            let proof = RustTypeProof::new(analyzer).expect("proof");
            let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
            let prepared = proof.source(&file).expect("source");
            let root = prepared.tree().root_node();
            let function = root
                .named_children(&mut root.walk())
                .find(|node| node.kind() == "function_item")
                .unwrap();
            proof
                .result_error_type(
                    &prepared,
                    function.child_by_field_name("return_type").unwrap(),
                )
                .is_some()
        }
        let source = |gate: &str, frontier: &str| {
            format!(
                "mod facade; mod types; #[cfg({gate})] {frontier} use facade::R; fn run(v: Result<(), ()>) -> R<()> {{ v?; Ok(()) }}"
            )
        };
        let initial = source("windows", "mod gated;");
        let mut warm = fixture(&initial, LINUX, &[]);
        assert!(
            answer(&warm),
            "a false selected gate discharges the placement gap"
        );
        for (gate, expected) in [
            ("my_flag", false),
            ("feature = \"x\"", true),
            ("unix", false),
            ("any()", true),
        ] {
            let edited = source(gate, "mod gated;");
            let host = ProjectFile::new(warm.project_root(), "src/lib.rs");
            host.write(&edited).unwrap();
            warm.analyzer = warm.analyzer.update(&BTreeSet::from([host]));
            let fresh = fixture(&edited, LINUX, &[]);
            assert_eq!(answer(&warm), answer(&fresh), "gate={gate}");
            assert_eq!(answer(&warm), expected, "gate={gate}");
        }
        // These edits leave the host blob untouched. This alias-proof surface
        // cannot observe macro closure, and root TEMP is not the worker reader.
        // The tools SQL guard covers the existing inactive-macro arm separately.
        let host = source("windows", "mod gated;");
        let mut warm = fixture(&host, LINUX, &[]);
        assert!(answer(&warm), "inactive module");
        let configuration = ProjectFile::new(warm.project_root(), ".cargo/config.toml");
        configuration.write(WINDOWS).unwrap();
        warm.analyzer = warm.analyzer.update(&BTreeSet::from([configuration]));
        let fresh = fixture(&host, WINDOWS, &[]);
        assert_eq!(answer(&warm), answer(&fresh), "configuration-only edit");
        assert!(!answer(&warm), "active module retains its placement gap");

        // Start with Linux again, then add only a second workspace and its
        // custom-target configuration. The first unit's configuration is fixed.
        let mut warm = fixture(&host, LINUX, &[]);
        assert!(answer(&warm), "inactive module before membership change");
        let extras = [
            (
                "other/Cargo.toml",
                "[package]\nname='other'\nversion='0.1.0'\nedition='2021'\n[workspace]\n",
            ),
            (
                "other/src/lib.rs",
                "#[path=\"../../src/lib.rs\"] mod shared;",
            ),
            (
                "other/.cargo/config.toml",
                "[build]\ntarget='custom-target.json'\n",
            ),
        ];
        let mut changed = BTreeSet::new();
        for (path, contents) in extras {
            let file = ProjectFile::new(warm.project_root(), path);
            file.write(contents).unwrap();
            changed.insert(file);
        }
        warm.analyzer = warm.analyzer.update(&changed);
        let fresh = fixture(&host, LINUX, &extras);
        assert_eq!(answer(&warm), answer(&fresh), "membership-only edit");
        assert!(
            !answer(&warm),
            "unknown membership retains the placement gap"
        );
    }

    /// Control for #11786: a `mod name;` gated on a predicate some atom
    /// assignment satisfies keeps its placement boundary, so the same alias
    /// lookup stays incomplete and the residual proof makes no claim. Use an
    /// unknown custom cfg: the fully read fixture's absent feature is proven
    /// false by its complete Cargo feature inventory (#11834).
    #[test]
    #[hardwon("#11786: an inactive cfg(any()) module made an unrelated alias lookup incomplete")]
    fn satisfiable_cfg_module_keeps_alias_lookup_incomplete() {
        let fixture = AnalyzerFixture::new(&[
            (
                "Cargo.toml",
                "[package]\nname='staged_receipt'\nversion='0.1.0'\nedition='2021'\n",
            ),
            (
                "src/lib.rs",
                "mod facade; mod types; #[cfg(my_flag)] mod gated; use facade::R; fn run(v: Result<(), ()>) -> R<()> { v?; Ok(()) }",
            ),
            ("src/types.rs", "pub type R<T> = Result<T, ()>;"),
            ("src/gated.rs", "pub struct Gated;"),
            ("src/facade.rs", "pub use crate::types::R;"),
        ]);
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).expect("proof");
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let source = proof.source(&file).expect("source");
        let function = source
            .tree()
            .root_node()
            .named_children(&mut source.tree().root_node().walk())
            .find(|node| node.kind() == "function_item")
            .unwrap();
        assert_eq!(
            proof.result_error_type(
                &source,
                function.child_by_field_name("return_type").unwrap()
            ),
            None
        );
    }

    #[test]
    #[hardwon("#11786: an inactive cfg(any()) module made an unrelated alias lookup incomplete")]
    fn inactive_alias_portable_diagnostic() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
        use brokk_bifrost_analysis::analyzer::store::advance_selected_rust_unit_summaries_generation_for_test;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_broad_file_units;
        let fixture = AnalyzerFixture::new(&[
            (
                "Cargo.toml",
                "[package]\nname='staged_receipt'\nversion='0.1.0'\nedition='2021'\n[workspace]\nmembers=['other']\n",
            ),
            (
                "src/lib.rs",
                "mod facade; mod types; #[cfg(any())] mod inactive; use facade::R; fn run(v: Result<(), ()>) -> R<()> { println!(\"marker\"); v?; Ok(()) }",
            ),
            ("src/types.rs", "pub type R<T> = Result<T, ()>;"),
            ("src/inactive.rs", "pub struct Inactive;"),
            ("src/facade.rs", "pub use crate::types::R;"),
            (
                "other/Cargo.toml",
                "[package]\nname='competitor'\nversion='0.1.0'\nedition='2021'\n",
            ),
            ("other/src/lib.rs", "pub type R<T> = Result<T, u8>;"),
        ]);
        let analyzer = fixture.analyzer.analyzer();
        let rust =
            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
                analyzer,
            )
            .unwrap();
        let token = CancellationToken::default();
        let operation = match rust.open_selected_rust_operation(&token).outcome.unwrap() {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
            _ => panic!("ready operation"),
        };
        let inventory = &operation.ready.inventory;
        let _lease = inventory.derivation_read().unwrap();
        let snapshot = rust.inner.selected_workspace_snapshots()["rust"].clone();
        inventory
            .with_owned_temp_write(advance_selected_rust_unit_summaries_generation_for_test)
            .unwrap();
        let roots = rust_broad_file_units(inventory.connection(), &snapshot, "src/lib.rs").unwrap();
        assert_eq!(roots.len(), 1);
        let other =
            rust_broad_file_units(inventory.connection(), &snapshot, "other/src/lib.rs").unwrap();
        assert_eq!(other.len(), 1);
        inventory.with_owned_temp_write(|c| Ok(c.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent) VALUES('rust','src/inactive.rs','removal')", [])?)).unwrap();
        inventory.with_owned_temp_write(|c| Ok(c.execute("DELETE FROM temp.selected_resolution_overlay_masks WHERE storage_language='rust' AND persisted_relative_path='src/inactive.rs'", [])?)).unwrap();
        inventory.with_owned_temp_write(|c| Ok(c.execute("INSERT INTO temp.selected_rust_unplaced_placements(summary_id,container_path,member_ordinal,module_path,rel_path) SELECT p.summary_id,p.container_path,p.member_ordinal,a.module_path,m.rel_path FROM main.resolution_unit_summary_placements p JOIN main.rust_resolution_unit_summary_placement_attributes a USING(summary_id,container_path,member_ordinal) JOIN main.resolution_unit_summary_members m USING(summary_id,member_ordinal) JOIN temp.selected_rust_unit_summaries u ON u.summary_id=p.summary_id WHERE u.unit_key=?1 AND a.module_path='crate'", [roots[0].as_slice()])?)).unwrap();
        inventory.with_owned_temp_write(|c| Ok(c.execute("DELETE FROM temp.selected_rust_unplaced_placements WHERE summary_id IN (SELECT summary_id FROM temp.selected_rust_unit_summaries WHERE unit_key=?1)", [roots[0].as_slice()])?)).unwrap();
        let answer = |phase: &str, analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer| {
            eprintln!("DIAG_PHASE_BEGIN portable {phase}");
            let proof = RustTypeProof::new(analyzer).expect("proof");
            let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
            let source = proof.source(&file).expect("source");
            let function = source
                .tree()
                .root_node()
                .named_children(&mut source.tree().root_node().walk())
                .find(|node| node.kind() == "function_item")
                .unwrap();
            let result = proof.result_error_type(
                &source,
                function.child_by_field_name("return_type").unwrap(),
            );
            eprintln!("DIAG_PHASE_END portable {phase} result={result:?}");
            format!("{result:?}")
        };
        let (selected_before_edge, _) = capture_query_reads(analyzer, || {
            let _frame = rust.operation_read_frame(&operation).unwrap();
            answer("selected-before-edge", analyzer)
        });
        inventory.with_owned_temp_write(|c| Ok(c.execute("INSERT INTO temp.selected_rust_unit_closure SELECT ?1,unit_key,summary_id,topology_id,workspace_id,generation FROM temp.selected_rust_unit_closure WHERE root_unit_key=?2 AND unit_key=?2", rusqlite::params![roots[0].as_slice(), other[0].as_slice()])?)).unwrap();
        let (selected, _) = capture_query_reads(analyzer, || {
            let _frame = rust.operation_read_frame(&operation).unwrap();
            answer("selected-after-edge", analyzer)
        });
        let fresh = brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun(Arc::new(brokk_bifrost_analysis::analyzer::FilesystemProject::new(fixture.project_root()).unwrap()), Default::default()).unwrap();
        let fresh_answer = answer("fresh", fresh.analyzer());
        assert_eq!(
            selected_before_edge, fresh_answer,
            "restored selected inputs before the artificial edge equal fresh"
        );
        assert_eq!(
            selected, fresh_answer,
            "same selected/fresh answer with the same fixture and staged sequence"
        );
        assert_eq!(selected, "Some(Unit)");
    }

    #[test]
    #[hardwon(
        "#8866: unwrapping Option<&T> dropped the payload's reference in the typed receiver (review of #8899)"
    )]
    fn modeled_unwrap_keeps_payload_reference_but_not_wrapper_reference() {
        let source = "fn receivers(by_ref: std::option::Option<&std::fs::File>, owned: std::option::Option<std::fs::File>, wrapper_ref: &std::option::Option<std::fs::File>) { let _ = by_ref.unwrap(); let _ = owned.unwrap(); let _ = wrapper_ref.unwrap(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let mut option = rust_type("std.option.Option", "enum");
        option["type_parameters"] = serde_json::json!(["T"]);
        let model = serde_json::json!({
            "schema_version": 32,
            "pack_id": "fixture.rust-wrapper-reference",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust", "ecosystem": "cargo",
            "compatibility": { "toolchains": [] },
            "provenance": { "source": "test-only #8866 typed receiver regression" },
            "license": "NOASSERTION", "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-wrapper-reference",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": { "kind": "declaration_facts", "types": [
                    rust_type("std", "module"), rust_type("std.option", "module"),
                    option, rust_type("std.fs", "module"), rust_type("std.fs.File", "struct")
                ], "members": [{
                    "id":"member.fixture.option-unwrap", "owner":"type.fixture.std-option-option",
                    "name":"unwrap", "member_kind":"method", "visibility":"public",
                    "callable_family_complete":true, "receiver":{"pointer":false},
                    "self_form":{"kind":"value"},
                    "signature":{"parameters":[],"returns":{"kind":"type_parameter","name":"T"}},
                    "locator":{"kind":"artifact","path":"library/core/src/option.rs","symbol":"std.option.Option.unwrap"}
                }], "relations": [] }
            }]
        });
        activate_model_pack(&fixture, model, "fixture.rust-wrapper-reference", "std");
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).expect("Rust proof");
        let prepared = proof.source(&file).expect("prepared source");
        for (expression, borrowed) in [
            ("by_ref.unwrap()", true),
            ("owned.unwrap()", false),
            ("wrapper_ref.unwrap()", false),
        ] {
            let start = source.find(expression).expect("receiver expression");
            let node = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + expression.len())
                .expect("call expression");
            assert_eq!(node.kind(), "call_expression");
            let ty = proof
                .modeled_receiver_type(&file, node)
                .unwrap_or_else(|| panic!("modeled receiver type for {expression}"));
            let expected = TypeRef::Declared {
                id: "type.fixture.std-fs-file".into(),
                arguments: vec![],
                nullable: false,
            };
            let expected = if borrowed {
                TypeRef::ByRef {
                    element: Box::new(expected),
                    reference_kind: crate::analyzer::semantic_model::TypeRefReferenceKind::Lvalue,
                }
            } else {
                expected
            };
            assert_eq!(
                ty, expected,
                "{expression} has the wrong modeled receiver type"
            );
        }
    }

    #[test]
    fn standard_wrapper_owner_accepts_agreeing_external_claims() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::{
            ClaimSubjectRole, DefinitionLookupDiagnostic, UnindexedClaim,
        };
        let source =
            "use std::io::Result as IoResult;\nfn fallible() -> IoResult<()> { todo!() }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).expect("Rust proof");
        let source = proof.source(&file).expect("prepared source");
        let callable = named_children(source.tree().root_node())
            .into_iter()
            .find(|node| node.kind() == "function_item")
            .expect("fixture callable");
        let head = callable
            .child_by_field_name("return_type")
            .expect("return type")
            .child_by_field_name("type")
            .expect("generic head");
        let mut outcome = proof
            .resolve(&source, head)
            .expect("selected type-head lookup");
        let expected = Some(vec!["std".into(), "io".into(), "Result".into()]);
        assert_eq!(standard_wrapper_owner(&outcome), expected);
        // The public lookup contract permits a resolved-external claim beside
        // the native boundary claim, with either qualified-path rendering.
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "resolved_external".into(),
            message: "selected external type".into(),
            claim: Some(UnindexedClaim::resolved_external(
                "std::io::Result",
                ClaimSubjectRole::Type,
            )),
        });
        assert_eq!(standard_wrapper_owner(&outcome), expected);
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "unindexed_import_boundary".into(),
            message: "selected routes".into(),
            claim: Some(UnindexedClaim::external_boundary_many(
                ["std.io.Result", "std::io::Result"],
                ClaimSubjectRole::Any,
            )),
        });
        assert_eq!(standard_wrapper_owner(&outcome), expected);
        outcome
            .diagnostics
            .last_mut()
            .unwrap()
            .claim
            .as_mut()
            .unwrap()
            .subjects
            .push("std.thread.Result".into());
        assert_eq!(standard_wrapper_owner(&outcome), None);
    }

    #[test]
    #[hardwon(
        "#11145: a transient analyzer-open failure was retained as a deterministic proof stop"
    )]
    fn analyzer_unavailable_initialization_recovers() {
        use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
        use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "pub struct Known;")]);
        let analyzer = fixture.analyzer.analyzer();
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer).unwrap();
        let store = rust.inner.analyzer_store();
        store.execute_selection_publication(|conn| {
            conn.execute_batch("PRAGMA legacy_alter_table=ON; ALTER TABLE blobs RENAME TO unavailable_blobs; PRAGMA legacy_alter_table=OFF;")
                .unwrap();
        });
        let (failed, receipt) = QueryReadReceipt::capture(analyzer, || {
            completed_proof(analyzer, None, || {
                let proof = RustTypeProof::new(analyzer)?;
                // The proof opens its selected-declaration operation lazily;
                // that open is the first store read and must report the stop.
                proof.resolver.operation().ok().map(|_| ())
            })
        });
        assert!(
            matches!(
                failed,
                RustProofAttempt::Incomplete {
                    value: None,
                    reason: "analyzer_unavailable",
                    cause: Some(DerivationExecutionCause::Provider),
                }
            ),
            "{failed:?}"
        );
        assert!(
            receipt
                .incomplete_reasons()
                .contains(&QueryReadIncomplete::ProofStopped {
                    reason: "analyzer_unavailable",
                    cause: Some(DerivationExecutionCause::Provider),
                })
        );
        store.execute_selection_publication(|conn| {
            conn.execute_batch("PRAGMA legacy_alter_table=ON; ALTER TABLE unavailable_blobs RENAME TO blobs; PRAGMA legacy_alter_table=OFF;")
                .unwrap();
        });
        let (answer, receipt) = QueryReadReceipt::capture(analyzer, || {
            completed_proof(analyzer, None, || {
                let proof = RustTypeProof::new(analyzer)?;
                proof.resolver.operation().ok().map(|_| ())
            })
        });
        assert!(
            matches!(answer, RustProofAttempt::Complete(Some(()))),
            "{answer:?}"
        );
        assert!(
            receipt.incomplete_reasons().is_empty(),
            "{:?}",
            receipt.incomplete_reasons()
        );
    }

    #[test]
    #[hardwon("#11970: a drop-sweep stop erased an unrelated valid receiver proof")]
    fn independent_receiver_proof_ignores_ambient_stop() {
        use brokk_bifrost_analysis::analyzer::{MultiAnalyzer, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        let _request = AnalyzerQueryScope::new(&analyzer);
        analyzer.record_query_incomplete(QueryReadIncomplete::ProofStopped {
            reason: "resolution_unsupported_semantic",
            cause: Some(DerivationExecutionCause::Provider),
        });
        let receiver = completed_proof(&analyzer, None, || {
            Some(TypeRef::Named {
                name: "alloc.string.String".into(),
                arguments: Vec::new(),
                nullable: false,
            })
        });
        assert!(
            matches!(receiver, RustProofAttempt::Complete(Some(_))),
            "{receiver:?}"
        );
    }

    #[test]
    #[hardwon(
        "#11970: independent completion must retain UnsupportedSemantic consumed by the proof"
    )]
    fn independent_proof_consumes_native_unsupported_await_receiver() {
        let text = "struct Response; impl Response { fn inspect(self) {} } async fn output() -> Response { Response } async fn run() { output().await.inspect(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", text)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let (attempt, receipt) = QueryReadReceipt::capture(analyzer, || {
            completed_proof(analyzer, None, || {
                let proof = RustTypeProof::new(analyzer)?;
                let source = proof.source(&file)?;
                let start = text.rfind("inspect()").unwrap();
                let method = source
                    .tree()
                    .root_node()
                    .named_descendant_for_byte_range(start, start + "inspect".len())
                    .unwrap();
                assert_eq!(source.node_text(method), Some("inspect"));
                // Native resolution currently cannot type an awaited receiver
                // (#11962). Read that actual method site inside this proof.
                proof.workspace_definition(&source, method)
            })
        });
        assert!(
            matches!(
                attempt,
                RustProofAttempt::Incomplete {
                    value: None,
                    reason: "resolution_unsupported_semantic",
                    cause: Some(DerivationExecutionCause::Provider)
                }
            ),
            "{attempt:?}"
        );
        assert!(
            receipt.incomplete_reasons().iter().any(|reason| matches!(
                reason,
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                    reason: "resolution_unsupported_semantic",
                    cause: Some(DerivationExecutionCause::Provider)
                }
            )),
            "{:?}",
            receipt.incomplete_reasons()
        );
    }

    #[test]
    #[hardwon("#11970: independent receiver proofs must consume parent input completeness")]
    fn independent_receiver_proof_replays_incomplete_input() {
        use brokk_bifrost_analysis::analyzer::{MultiAnalyzer, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        let _request = AnalyzerQueryScope::new(&analyzer);
        let (receiver, input_receipt) = QueryReadReceipt::capture(&analyzer, || {
            completed_proof(&analyzer, None, || {
                operational_proof_stop("source_unavailable", DerivationExecutionCause::Provider);
                Some(TypeRef::Named {
                    name: "alloc.string.String".into(),
                    arguments: Vec::new(),
                    nullable: false,
                })
            })
        });
        assert!(matches!(
            &receiver,
            RustProofAttempt::Incomplete { value: Some(_), .. }
        ));
        let (consumer, receipt) = QueryReadReceipt::capture(&analyzer, || {
            completed_proof(&analyzer, None, || {
                // The type is an input, so its receipt is consumed with it.
                input_receipt.replay(&analyzer);
                receiver.into_value()
            })
        });
        assert!(
            matches!(
                consumer,
                RustProofAttempt::Incomplete {
                    value: Some(_),
                    reason: "source_unavailable",
                    cause: Some(DerivationExecutionCause::Provider)
                }
            ),
            "{consumer:?}"
        );
        assert!(
            receipt
                .incomplete_reasons()
                .contains(&QueryReadIncomplete::ProofStopped {
                    reason: "source_unavailable",
                    cause: Some(DerivationExecutionCause::Provider)
                })
        );
    }

    #[test]
    #[hardwon("#11970: independent receiver proof inputs must retain attributed store failures")]
    fn independent_receiver_proof_preserves_store_provenance() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::QueryLookupProvenance;
        use brokk_bifrost_analysis::analyzer::store::StoreError;
        use brokk_bifrost_analysis::analyzer::{MultiAnalyzer, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        let _request = AnalyzerQueryScope::new(&analyzer);
        let error = StoreError::new("receiver input read failed");
        let failure =
            QueryReadIncomplete::StoreFailure(error.clone()).attributed(QueryLookupProvenance {
                file: ProjectFile::new(std::env::current_dir().unwrap(), "receiver.rs"),
                byte_span: 12..20,
                name: "receiver".into(),
                tier: "type-input",
            });
        let (_, input_receipt) = QueryReadReceipt::capture_deferred(&analyzer, || {
            completed_proof(&analyzer, None, || {
                // A store receipt alone must refuse completion; no language
                // helper has translated it into a ProofStopped reason.
                analyzer.record_query_incomplete(failure.clone());
                Some(TypeRef::Unknown)
            })
        });
        let capture = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let (consumer, receipt) = QueryReadReceipt::capture(&analyzer, || {
            completed_proof(&analyzer, None, || {
                input_receipt.replay(&analyzer);
                Some(TypeRef::Unknown)
            })
        });
        assert!(
            matches!(
                consumer,
                RustProofAttempt::Incomplete {
                    cause: Some(DerivationExecutionCause::Provider),
                    ..
                }
            ),
            "{consumer:?}"
        );
        assert_eq!(capture.store_error(), Some(error));
        let QueryReadIncomplete::Attributed(original) = &failure else {
            unreachable!()
        };
        assert!(receipt.incomplete_reasons().iter().any(|reason| matches!(reason, QueryReadIncomplete::Attributed(replayed) if std::sync::Arc::ptr_eq(original, replayed))));
    }

    #[test]
    #[hardwon("#11970: independent proofs lost active cancellation when passed no token")]
    fn independent_proof_observes_active_cancellation_and_deadline() {
        use brokk_bifrost_analysis::analyzer::MultiAnalyzer;
        use std::time::Instant;
        for (token, cause) in [
            (
                {
                    let token = CancellationToken::default();
                    token.cancel();
                    token
                },
                DerivationExecutionCause::Cancelled,
            ),
            (
                CancellationToken::default().with_soft_deadline(Instant::now()),
                DerivationExecutionCause::Budget,
            ),
        ] {
            let analyzer = MultiAnalyzer::default();
            let _request = AnalyzerQueryScope::independent_answer(&analyzer, Some(&token));
            for supplied in [None, Some(&token), Some(&CancellationToken::default())] {
                let proof = completed_proof(&analyzer, supplied, || Some(7));
                assert!(
                    matches!(proof, RustProofAttempt::Incomplete { value: Some(7), cause: Some(found), .. } if found == cause),
                    "{proof:?}"
                );
            }
        }
        let analyzer = MultiAnalyzer::default();
        let token = CancellationToken::default();
        let proof = completed_proof(&analyzer, Some(&token), || {
            token.cancel();
            Some(7)
        });
        assert!(
            matches!(
                proof,
                RustProofAttempt::Incomplete {
                    cause: Some(DerivationExecutionCause::Cancelled),
                    ..
                }
            ),
            "{proof:?}"
        );
    }

    #[test]
    #[hardwon("#11970: nested proofs must reuse active cancellation without growing its chain")]
    fn independent_proof_reuses_active_token_without_chain_growth() {
        use brokk_bifrost_analysis::analyzer::MultiAnalyzer;
        fn nested(analyzer: &dyn IAnalyzer, expected: &str, remaining: usize) {
            let attempt = completed_proof(analyzer, None, || {
                assert_eq!(
                    format!("{:?}", analyzer.active_query_cancellation().unwrap()),
                    expected
                );
                if remaining != 0 {
                    nested(analyzer, expected, remaining - 1);
                }
                Some(())
            });
            assert!(matches!(attempt, RustProofAttempt::Complete(Some(()))));
        }
        let analyzer = MultiAnalyzer::default();
        let token = CancellationToken::default();
        let _request = AnalyzerQueryScope::independent_answer(&analyzer, Some(&token));
        nested(&analyzer, &format!("{token:?}"), 32);
    }

    #[test]
    #[hardwon("#11970: an operation token hid request cancellation inside a proof")]
    fn independent_proof_nested_reads_observe_both_tokens() {
        use brokk_bifrost_analysis::analyzer::MultiAnalyzer;
        use std::time::Instant;
        for cancel_request in [true, false] {
            let analyzer = MultiAnalyzer::default();
            let request = CancellationToken::default();
            let operation = CancellationToken::default();
            let _request = AnalyzerQueryScope::independent_answer(&analyzer, Some(&request));
            let proof = completed_proof(&analyzer, Some(&operation), || {
                let nested = analyzer.active_query_cancellation().expect("proof token");
                assert!(!nested.is_cancelled());
                if cancel_request {
                    request.cancel();
                } else {
                    operation.cancel();
                }
                assert!(
                    nested.is_cancelled(),
                    "nested reads must stop during the proof"
                );
                Some(7)
            });
            assert!(matches!(
                proof,
                RustProofAttempt::Incomplete {
                    cause: Some(DerivationExecutionCause::Cancelled),
                    ..
                }
            ));
        }
        for request in [
            CancellationToken::default().with_deadline(Instant::now()),
            CancellationToken::default().with_soft_deadline(Instant::now()),
        ] {
            let analyzer = MultiAnalyzer::default();
            let operation = CancellationToken::default();
            let _request = AnalyzerQueryScope::independent_answer(&analyzer, Some(&request));
            let proof = completed_proof(&analyzer, Some(&operation), || {
                let nested = analyzer.active_query_cancellation().expect("proof token");
                assert!(
                    nested.is_cancelled() || nested.soft_deadline_passed(),
                    "nested reads must observe the request deadline during the proof"
                );
                Some(7)
            });
            assert!(matches!(proof, RustProofAttempt::Incomplete { .. }));
        }
    }

    #[test]
    #[hardwon("#11145: a Rust proof stop lived outside the query receipt")]
    fn proof_stop_receipt_replays_completion() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
        use brokk_bifrost_analysis::analyzer::{MultiAnalyzer, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::new(&analyzer);
        let reason = QueryReadIncomplete::ProofStopped {
            reason: "depth_limit",
            cause: None,
        };
        let receipt = {
            let candidate = AnalyzerQueryScope::capturing_candidate_classification(&analyzer);
            let (attempt, receipt) = QueryReadReceipt::capture(&analyzer, || {
                completed_proof(&analyzer, None, || {
                    incomplete_proof("depth_limit");
                    Some(7)
                })
            });
            assert_eq!(attempt.into_value(), Some(7));
            assert_eq!(candidate.read_completion(), Err(reason.clone()));
            assert_eq!(receipt.incomplete_reasons(), std::slice::from_ref(&reason));
            receipt
        };
        assert_eq!(outer.read_completion(), Ok(()));
        {
            let advisory = AnalyzerQueryScope::for_advisory_read(&analyzer);
            let attempt = completed_proof(&analyzer, None, || {
                receipt.replay(&analyzer);
                Some(7)
            });
            assert!(matches!(
                attempt,
                RustProofAttempt::Incomplete { value: Some(7), .. }
            ));
            assert_eq!(advisory.read_completion(), Err(reason.clone()));
        }
        assert_eq!(outer.read_completion(), Ok(()));
        receipt.replay(&analyzer);
        assert_eq!(outer.read_completion(), Err(reason));
    }

    #[test]
    #[hardwon(
        "#11510: Unclassified and UnsupportedSemantic must have distinct Provider stop labels"
    )]
    fn unclassified_lookup_has_a_distinct_provider_label() {
        use brokk_bifrost_analysis::analyzer::resolution::{
            ResolutionCompletion, ResolutionIncompleteReason as Native, SemanticId,
        };
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupEvidence;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        let analyzer = &brokk_bifrost_analysis::analyzer::MultiAnalyzer::default();
        let resolution = BoundedResolution::Complete {
            value: DefinitionLookupOutcome {
                selected_sites: Vec::new(),
                inventory_evidence: None,
                incomplete_evidence: Some(DefinitionLookupEvidence {
                    completion: ResolutionCompletion::incomplete([
                        Native::Unclassified(SemanticId::for_test("unknown stored reason")),
                        Native::UnsupportedSemantic(SemanticId::for_test(
                            "known unsupported reason",
                        )),
                    ]),
                    reasons: Vec::new(),
                    snapshot_stops: Vec::new(),
                }),
                status: DefinitionLookupStatus::Incomplete,
                modeled_definitions: Vec::new(),
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            work: Default::default(),
        };
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        let proof = AnalyzerQueryScope::capturing_proof_completion(analyzer);
        observe_proof_resolution(&resolution);
        drop(proof);
        let observed = scope.captured_read_incompleteness();
        for reason in ["resolution_unclassified", "resolution_unsupported_semantic"] {
            assert!(
                observed.contains(&QueryReadIncomplete::ProofStopped {
                    reason,
                    cause: Some(DerivationExecutionCause::Provider)
                }),
                "{observed:?}"
            );
        }
        assert_eq!(observed.len(), 2, "distinct reasons must not coalesce");
    }

    #[test]
    #[hardwon("#11510: unsupported-semantic stops remain Provider even beside snapshot provenance")]
    fn unsupported_semantic_stays_provider_even_with_snapshot_provenance() {
        use brokk_bifrost_analysis::analyzer::resolution::{
            ResolutionCompletion, ResolutionIncompleteReason as Native, SemanticId,
        };
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupEvidence;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        let analyzer = &brokk_bifrost_analysis::analyzer::MultiAnalyzer::default();
        let declared = SemanticId::for_test("declared snapshot stop");
        let undeclared = SemanticId::for_test("request or unaudited stop");
        let resolution = |stops: Vec<SemanticId>| BoundedResolution::Complete {
            value: DefinitionLookupOutcome {
                selected_sites: Vec::new(),
                inventory_evidence: None,
                incomplete_evidence: Some(DefinitionLookupEvidence {
                    completion: ResolutionCompletion::incomplete([
                        Native::UnsupportedSemantic(declared),
                        Native::UnsupportedSemantic(undeclared),
                    ]),
                    reasons: Vec::new(),
                    snapshot_stops: stops,
                }),
                status: DefinitionLookupStatus::Incomplete,
                modeled_definitions: Vec::new(),
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            work: Default::default(),
        };
        let observe = |stops: Vec<SemanticId>| {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            let proof = AnalyzerQueryScope::capturing_proof_completion(analyzer);
            observe_proof_resolution(&resolution(stops));
            drop(proof);
            scope.captured_read_incompleteness()
        };
        let stop = |cause| QueryReadIncomplete::ProofStopped {
            reason: "resolution_unsupported_semantic",
            cause,
        };
        // Provenance alone never certifies the UnsupportedSemantic label.
        let mixed = observe(vec![declared]);
        assert!(!mixed.contains(&stop(None)), "{mixed:?}");
        assert!(
            mixed.contains(&stop(Some(DerivationExecutionCause::Provider))),
            "{mixed:?}"
        );
        // With no declaration, nothing is deterministic.
        assert_eq!(
            observe(Vec::new()),
            [stop(Some(DerivationExecutionCause::Provider))]
        );
    }

    #[test]
    #[hardwon("#8411: an earlier static gap hid a later operational proof stop")]
    fn nested_receiver_completion_preserves_values_and_unwinds() {
        let analyzer = &brokk_bifrost_analysis::analyzer::MultiAnalyzer::default();
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
        for (status, expected) in [
            (
                DefinitionLookupStatus::Unavailable,
                DerivationExecutionCause::Provider,
            ),
            (
                DefinitionLookupStatus::Cancelled,
                DerivationExecutionCause::Cancelled,
            ),
            (
                DefinitionLookupStatus::ExceededBudget(ReceiverBudgetLimit::ScopeNodes),
                DerivationExecutionCause::Budget,
            ),
        ] {
            let attempt = completed_proof(analyzer, None, || {
                incomplete_proof("depth_limit");
                let nested = completed_proof(analyzer, None, || {
                    observe_proof_resolution(&BoundedResolution::Complete {
                        value: DefinitionLookupOutcome {
                            selected_sites: Vec::new(),
                            inventory_evidence: None,
                            incomplete_evidence: None,
                            status,
                            modeled_definitions: Vec::new(),
                            reference: None,
                            definitions: Vec::new(),
                            lexical_definition: None,
                            diagnostics: Vec::new(),
                        },
                        work: Default::default(),
                    });
                    Some(7)
                });
                assert_eq!(nested.into_value(), Some(7));
                Some(9)
            });
            let RustProofAttempt::Incomplete {
                value: Some(9),
                reason,
                cause,
            } = attempt
            else {
                panic!("an operational stop must preserve the retained value");
            };
            assert_eq!(cause, Some(expected), "{reason}");
        }
        let panic = std::panic::catch_unwind(|| {
            let analyzer = &brokk_bifrost_analysis::analyzer::MultiAnalyzer::default();
            completed_proof::<()>(analyzer, None, || {
                operational_proof_stop("cancelled", DerivationExecutionCause::Cancelled);
                panic!("proof interrupted");
            })
        });
        assert!(panic.is_err());
        assert!(matches!(
            completed_proof::<()>(analyzer, None, || None),
            RustProofAttempt::Complete(None)
        ));
    }

    use brokk_bifrost_core::analyzer::model::Language;

    use crate::analyzer::semantic_model::CatalogCoordinate;

    use crate::analyzer::semantic_model::CompilerOptions;

    use crate::analyzer::semantic_model::SemanticModelActivationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome;

    use crate::analyzer::semantic_model::SessionPackSource;

    use crate::analyzer::semantic_model::SessionPackSourceKind;

    use crate::analyzer::semantic_model::SourceFormat;

    use crate::analyzer::semantic_model::compile_source;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#11259: intrinsic classification without an outer proof cached an unreported cutoff"
    )]
    fn standalone_memos_capture_and_replay_proof_stops() {
        let text = "fn f() { let s = \"x\"; s.clone(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", text)]);
        let analyzer = fixture.analyzer.analyzer();
        let proof = RustTypeProof::new(analyzer).expect("Rust proof");
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let source = proof.source(&file).expect("prepared source");
        let start = text.find("s.clone()").unwrap();
        let call = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + "s.clone()".len())
            .unwrap();
        for _ in 0..2 {
            // Deliberately no enclosing completed_proof: intrinsic readers only
            // capture reads, so each memo must create its own proof attempt.
            let (class, receipt) =
                QueryReadReceipt::capture(analyzer, || proof.expression_class(&source, call, 0));
            assert_eq!(class, RustValueClass::Unknown);
            assert!(receipt.incomplete_reasons().iter().any(|reason| matches!(
                reason,
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                    reason: "depth_limit",
                    cause: None
                }
            )));
            let (shape, receipt) =
                QueryReadReceipt::capture(analyzer, || proof.modeled_call_shape(&source, call, 0));
            assert!(shape.is_none());
            assert!(receipt.incomplete_reasons().iter().any(|reason| matches!(
                reason,
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                    reason: "depth_limit",
                    cause: None
                }
            )));
        }
        assert_eq!(source.expression_class_evaluations.get(), 1);
        assert_eq!(source.modeled_call_shape_evaluations.get(), 1);
    }

    #[test]
    #[hardwon("#11145: Bat cold SQL rose 8,138,866 -> 12,489,418 on b83601a4b6")]
    fn depth_keyed_expression_memo_replays_stop_without_refill() {
        let text = "fn f() { let s0 = 1; let s1 = s0; let s2 = s1; let s3 = s2; let s4 = s3; let s5 = s4; let s6 = s5; let s7 = s6; let s8 = s7; let s9 = s8; let s10 = s9; let s11 = s10; let s12 = s11; s12; }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", text)]);
        let analyzer = fixture.analyzer.analyzer();
        let proof = RustTypeProof::new(analyzer).expect("Rust proof");
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let source = proof.source(&file).expect("prepared source");
        let start = text.rfind("s12;").unwrap();
        let node = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + 3)
            .unwrap();
        let mut fills = Vec::new();
        let mut answers = Vec::new();
        for depth in [0, PROOF_DEPTH, 0, PROOF_DEPTH] {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            let attempt = completed_proof(analyzer, None, || {
                Some(proof.expression_class(&source, node, depth))
            });
            assert!(
                matches!(
                    attempt,
                    RustProofAttempt::Incomplete {
                        value: Some(RustValueClass::Unknown),
                        reason: "depth_limit",
                        cause: None,
                    }
                ),
                "{attempt:?}"
            );
            answers.push((format!("{attempt:?}"), scope.captured_read_incompleteness()));
            fills.push(source.expression_class_evaluations.get());
        }
        assert_eq!(answers[0], answers[2], "cold fill and warm hit differ");
        assert_eq!(answers[1], answers[3], "cold fill and warm hit differ");
        assert!(fills[1] > fills[0]);
        assert_eq!(fills[1], fills[2]);
        assert_eq!(fills[2], fills[3]);
    }

    #[test]
    #[hardwon("#11825: scoped import consumers refused reusable configuration receipts")]
    fn selected_import_cfg_read_reuses_cold_narrowed_routes_and_refuses_removal() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;
        let fixture = AnalyzerFixture::new(&[
            (
                "Cargo.toml",
                "[package]\nname='cfg_receipt'\nversion='0.1.0'\nedition='2021'\n[features]\ndefault=['fast']\nfast=[]\n",
            ),
            (
                "src/lib.rs",
                "#[cfg(feature=\"fast\")] use std::str::from_utf8 as parse; pub fn f() {}",
            ),
            ("src/other.rs", "pub fn other() {}"),
        ]);
        let analyzer = fixture.analyzer.analyzer();
        let rust =
            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
                analyzer,
            )
            .unwrap();
        let cancellation = CancellationToken::default();
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let _scope = AnalyzerQueryScope::new(analyzer);
        let operation = match rust
            .open_selected_rust_operation(&cancellation)
            .outcome
            .unwrap()
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
            _ => panic!("ready operation"),
        };
        let keys = operation
            .rust_crate_keys_for_file(file.rel_path(), &cancellation)
            .unwrap();
        // `selected_import_infos` opens the operation read frame around its own
        // route question, so this scope deliberately enters none.
        operation.with_rust_forward_crate_scope(&keys, &cancellation, |_| Ok(()), || {
            let (imports, reads) = capture_query_reads(analyzer, || selected_import_infos(analyzer, &operation, &file, &cancellation));
            assert_eq!(imports.unwrap().len(), 1);
            assert!(!reads.reuse_refused(), "{:?}", reads.first_refusal());
            assert_eq!(reads.execution_dependences(), 0);
            assert!(format!("{:?}", reads.keys()).contains("rust_unit_configuration"));

            // A Main memo now exists. Removing Rust content must refuse its replay.
            let inventory = &operation.ready.inventory;
            inventory.with_owned_temp_write(|conn| {
                conn.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent) VALUES('rust','src/other.rs','removal')", [])?;
                Ok(())
            })?;
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            let (imports, _) = capture_query_reads(analyzer, || selected_import_infos(analyzer, &operation, &file, &cancellation));
            assert!(imports.is_none());
            assert!(scope.captured_read_incompleteness().iter().any(|reason| matches!(
                reason,
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                    reason: "RustMembershipOverlaid",
                    cause: Some(DerivationExecutionCause::Provider),
                }
            )), "{:?}", scope.captured_read_incompleteness());
            Ok(())
        }).unwrap();
    }
    #[test]
    #[hardwon("#8884: the selected import read recorded no file dependency (review of #8900)")]
    fn selected_import_read_records_the_selected_file_oid() {
        use brokk_bifrost_analysis::analyzer::read_ledger::{ReadKey, ReadLedger};
        use brokk_bifrost_core::gitblob::ParseVariant;

        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[("lib.rs", "use std::fs::File;\n")],
        );
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let selected_oid =
            git2::Oid::hash_object(git2::ObjectType::Blob, b"selected import source").unwrap();
        let ledger = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
        assert!(
            selected_import_infos_from_read(analyzer, &file, &CancellationToken::new(), || {
                Ok(Some((selected_oid, Vec::new())))
            })
            .is_some()
        );
        assert!(ledger.keys().contains(&ReadKey::file(
            Language::Rust,
            brokk_bifrost_core::path_utils::rel_path_string(&file),
            selected_oid,
            ParseVariant::Empty,
        )));
    }

    #[hardwon("#4626: same-file type-proof leaves reused query-local macro frontier state")]
    #[test]
    fn type_proof_shares_one_selected_operation_across_leaves() {
        let source = r#"
macro_rules! checkpointed {
    ($(($name:ident, $value:path),)*) => { $(fn $name() -> Known { $value })* };
}
enum Known { First, Second }
struct Container;
impl Container {
    checkpointed!((first, Known::First), (second, Known::Second),);
}
pub struct Item;
pub fn run() { let first = Item; let second = Item; }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        crate::analyzer::rust::native_points::reset_rust_definition_operation_open_count_for_test();
        crate::analyzer::rust::native_points::reset_rust_definition_overlay_preparation_count_for_test();
        let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
        let rust_source = proof.source(&file).expect("prepared Rust source");
        let mut pending = vec![rust_source.tree().root_node()];
        let mut references = Vec::new();
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "identifier" | "type_identifier")
                && rust_source.node_text(node) == Some("Item")
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() != "struct_item")
            {
                references.push(node);
            }
            pending.extend(named_children(node));
        }
        references.reverse();
        assert_eq!(references.len(), 2);

        let proof_outcomes = references
            .iter()
            .copied()
            .map(|node| {
                proof
                    .resolve(&rust_source, node)
                    .expect("complete proof lookup")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            crate::analyzer::rust::native_points::rust_definition_overlay_preparation_count_for_test(),
            1,
            "one type proof prepares its selected overlay inputs once across leaf lookups"
        );
        assert_eq!(
            crate::analyzer::rust::native_points::rust_definition_operation_open_count_for_test(),
            1,
            "one type proof owns one selected operation across its leaf lookups"
        );

        crate::analyzer::rust::native_points::reset_rust_definition_operation_open_count_for_test();
        crate::analyzer::rust::native_points::reset_rust_definition_overlay_preparation_count_for_test();
        let direct_outcomes = references
            .iter()
            .copied()
            .map(|node| {
                let text = rust_source
                    .node_text(node)
                    .expect("reference name")
                    .to_owned();
                let site = ResolvedReferenceSite {
                    path: text.clone(),
                    text,
                    range: node_range(node),
                    focus_start_byte: node.start_byte(),
                    focus_end_byte: node.end_byte(),
                };
                match crate::analyzer::rust::native_points::resolve_rust_definition_bounded(
                    BoundedReceiverQuery {
                        analyzer,
                        file: &file,
                        source: rust_source.text(),
                        tree: Some(rust_source.tree()),
                        site: &site,
                        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                        cancellation: None,
                    },
                ) {
                    BoundedResolution::Complete { value, .. } => value,
                    BoundedResolution::Exceeded { .. }
                    | BoundedResolution::Unavailable { .. }
                    | BoundedResolution::Cancelled { .. } => {
                        panic!("direct definition lookup did not complete")
                    }
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            crate::analyzer::rust::native_points::rust_definition_overlay_preparation_count_for_test(),
            2,
            "independent leaf lookups prepare the overlay inputs independently"
        );
        assert_eq!(
            crate::analyzer::rust::native_points::rust_definition_operation_open_count_for_test(),
            2,
            "independent leaf queries each open their own selected operation"
        );
        for (proof, direct) in proof_outcomes.iter().zip(direct_outcomes) {
            assert_eq!(proof.status, direct.status);
            assert_eq!(
                proof
                    .definitions
                    .iter()
                    .map(CodeUnit::declaration_id)
                    .collect::<Vec<_>>(),
                direct
                    .definitions
                    .iter()
                    .map(CodeUnit::declaration_id)
                    .collect::<Vec<_>>(),
            );
        }
    }

    mod deref_models {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/deref_models.rs"
        ));
    }

    fn activate_deref_fixture(fixture: &AnalyzerFixture, summary: Option<bool>, certified: bool) {
        deref_models::activate(fixture.analyzer.analyzer(), summary, certified);
    }

    fn deref_fixture_call(
        fixture: &AnalyzerFixture,
        source: &str,
        method: &str,
    ) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let rust_source = proof.source(&file).unwrap();
        let start = source.find(method).unwrap();
        let site = ResolvedReferenceSite {
            path: method.into(),
            text: method.into(),
            range: Range {
                start_byte: start,
                end_byte: start + method.len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: start + method.len(),
        };
        selected_external_call(
            fixture.analyzer.analyzer(),
            &file,
            source,
            rust_source.tree(),
            &site,
        )
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11114: unpinned stdlib activation rejected its toolchain-keyed Deref companion"
    )]
    fn unpinned_stdlib_shares_one_toolchain_with_deref_companions() {
        use brokk_bifrost_analysis::analyzer::semantic_model::*;
        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
        const VERSION: &str = "1.100.0-nightly";
        let source = r#"fn f(s: std::string::String) { let _ = s.contains(".."); }"#;
        // The stdlib authoring version deliberately differs from Rust's version.
        for (
            case,
            requirements,
            companion_requirement,
            pinned,
            include_stdlib,
            expected,
            diagnostic,
        ) in [
            (
                "shared",
                vec!["=1.100.0-nightly"],
                "=1.100.0-nightly",
                false,
                true,
                true,
                "",
            ),
            (
                "versionless",
                vec!["=1.100.0-nightly"],
                "=1.100.0-nightly",
                false,
                true,
                true,
                "",
            ),
            (
                "excluded",
                vec!["=1.100.0-nightly"],
                "=1.99.0",
                false,
                true,
                false,
                "assumed Rust toolchain 1.100.0-nightly",
            ),
            (
                "missing",
                vec!["=1.100.0-nightly"],
                "=1.100.0-nightly",
                false,
                false,
                false,
                "no assumed Rust toolchain",
            ),
            (
                "pinned",
                vec!["=1.100.0-nightly"],
                "=1.100.0-nightly",
                true,
                true,
                true,
                "",
            ),
            (
                "several",
                vec!["=1.100.0-nightly", "=1.99.0"],
                "=1.100.0-nightly",
                false,
                true,
                false,
                "several Rust toolchain versions",
            ),
            (
                "range",
                vec![">=1.99.0"],
                "=1.100.0-nightly",
                false,
                true,
                false,
                "non-exact Rust selector range",
            ),
            (
                "unconstrained-alternative",
                vec!["=1.100.0-nightly", "unconstrained"],
                "=1.100.0-nightly",
                false,
                true,
                false,
                "names no exact Rust toolchain version",
            ),
            (
                "no-version",
                vec![""],
                "=1.100.0-nightly",
                false,
                true,
                false,
                "names no exact Rust toolchain version",
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
            let catalog = SemanticPackCatalog::open(
                &fixture.project_root().join("test-catalog"),
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap();
            let store =
                AnalyzerStore::open_persistent(&fixture.project_root().join("activation.sqlite"))
                    .unwrap();
            let mut companion_digest = String::new();
            for mut model in deref_models::models(Some(true), true) {
                let stdlib = model["pack_id"] == "bifrost.rust-stdlib";
                if stdlib && !include_stdlib {
                    continue;
                }
                model["version"] = "9.8.7".into();
                model["compatibility"]["toolchains"] = serde_json::json!([{
                    "name":"rust", "requirement": if stdlib { "=1.100.0-nightly" } else { companion_requirement }
                }]);
                let selectors = if stdlib {
                    requirements.clone()
                } else {
                    vec![companion_requirement]
                };
                model["shards"][0]["activation"] = serde_json::Value::Array(selectors.into_iter().map(|requirement| {
                    if requirement == "unconstrained" { serde_json::json!({}) }
                    else if requirement.is_empty() { serde_json::json!({"toolchain":{"name":"rust"}}) }
                    else { serde_json::json!({"toolchain":{"name":"rust","version":requirement}}) }
                }).collect());
                let mut authored: AuthoredSemanticModelPack =
                    serde_json::from_value(model).unwrap();
                if stdlib {
                    authored.extraction = Some(ArtifactExtraction::source_set(
                        ArtifactExtractionKind::RustdocJsonSet,
                        &"a".repeat(64),
                    ));
                }
                let pack = compile_pack(&authored, &CompilerOptions::default()).unwrap();
                if !stdlib {
                    companion_digest = pack.manifest.content_sha256.clone();
                }
                catalog
                    .install(
                        &pack,
                        &DurablePackSource {
                            kind: DurablePackSourceKind::Installed,
                            source_id: authored.pack_id.clone(),
                        },
                    )
                    .unwrap();
            }
            let request = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                approximate_standard_libraries: if pinned {
                    vec![]
                } else {
                    vec![ApproximateSemanticModelExpectation {
                        language: "rust".into(),
                        ecosystem: "cargo".into(),
                        selection: ApproximateStandardLibrarySelection::Pack(
                            "bifrost.rust-stdlib".into(),
                        ),
                        toolchain: Some("rust".into()),
                    }]
                },
                evidence: vec![SemanticModelActivationEvidence {
                    language: "rust".into(),
                    ecosystem: "cargo".into(),
                    package: None,
                    module: None,
                    toolchain: (pinned || case == "versionless").then(|| CatalogCoordinate {
                        name: "rust".into(),
                        version: pinned.then(|| semver::Version::parse(VERSION).unwrap()),
                    }),
                    target: None,
                    configuration: None,
                    artifact_sha256: Some("a".repeat(64)),
                }],
                controls: ["bifrost.rust-stdlib", "test.std-deref-companion"]
                    .into_iter()
                    .map(|pack_id| SemanticModelActivationControl {
                        scope: SemanticModelControlScope::Workspace,
                        action: SemanticModelControlAction::Enable,
                        selector: SemanticModelPackSelector {
                            pack_id: pack_id.into(),
                            version: None,
                            manifest_digest: None,
                        },
                    })
                    .collect(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let outcome = acquire_active_semantic_models(
                fixture.analyzer.analyzer(),
                &catalog,
                Some(SemanticModelActivationPersistence {
                    scope_id: "shared-toolchain",
                    store: &store,
                }),
                &request,
                &CancellationToken::default(),
            );
            let SemanticModelRuntimeOutcome::Ready { active, .. } = outcome else {
                panic!("{case}: {outcome:#?}")
            };
            let shards = active.shards();
            let companion = shards
                .iter()
                .find(|shard| shard.manifest.pack_id == "test.std-deref-companion");
            assert_eq!(companion.is_some(), expected, "{case}: {active:#?}");
            let stdlib = shards
                .iter()
                .find(|shard| shard.manifest.pack_id == "bifrost.rust-stdlib");
            assert_eq!(stdlib.is_some(), include_stdlib, "{case}");
            if let Some(stdlib) = stdlib {
                assert_eq!(stdlib.approximate, !pinned, "{case}");
            }
            if let Some(companion) = companion {
                assert_eq!(companion.approximate, !pinned, "{case}");
                assert_eq!(
                    companion
                        .matched_evidence
                        .toolchain
                        .as_ref()
                        .unwrap()
                        .version
                        .as_ref()
                        .unwrap()
                        .to_string(),
                    VERSION
                );
                if !pinned {
                    assert!(stdlib.unwrap().selectors.iter().all(|selector| {
                        selector.toolchain.as_ref().unwrap().version.as_deref()
                            == Some("=1.100.0-nightly")
                    }));
                }
            }
            if !diagnostic.is_empty() {
                assert!(
                    active
                        .activation_report()
                        .explanations
                        .iter()
                        .any(|explanation| explanation.pack_id.as_deref()
                            == Some("test.std-deref-companion")
                            && explanation.status == SemanticModelActivationStatus::Incompatible
                            && explanation.reason.contains(diagnostic)
                            && (!include_stdlib
                                || case == "excluded"
                                || explanation.reason.contains("9.8.7"))),
                    "{case}: {:?}",
                    active.activation_report()
                );
            }
            let persisted = store.semantic_pack_active_set().unwrap().unwrap();
            assert_eq!(
                persisted
                    .members
                    .iter()
                    .any(|member| member.manifest_digest == companion_digest),
                expected,
                "{case}: {persisted:?}"
            );
            let result = deref_fixture_call(&fixture, source, "contains");
            assert_eq!(
                result
                    .as_ref()
                    .is_some_and(|(proof, _)| !proof.unadmitted_receiver_deref
                        && proof.receiver_adjustments.len() == 1),
                expected,
                "{case}: {result:?}"
            );
        }
    }

    #[test]
    fn std_deref_requires_the_exact_complete_companion_and_certified_family() {
        let source = r#"fn f(s: std::string::String, p: std::path::PathBuf) { let _ = s.contains(".."); let _ = p.starts_with("/srv/public"); }"#;
        for (summary, certified, expected) in [
            (Some(true), true, true),
            (None, true, false),
            (Some(false), true, false),
            (Some(true), false, false),
        ] {
            let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
            activate_deref_fixture(&fixture, summary, certified);
            let result = deref_fixture_call(&fixture, source, "contains");
            assert_eq!(
                result
                    .as_ref()
                    .is_some_and(|(proof, _)| !proof.unadmitted_receiver_deref),
                expected,
                "summary={summary:?}, certified={certified}"
            );
            if let Some((proof, target)) = result {
                assert_eq!(target.owner_fqn(), "core.primitive.str");
                assert_eq!(proof.receiver_adjustments.len(), usize::from(expected));
            }
            let path = deref_fixture_call(&fixture, source, "starts_with");
            assert_eq!(
                path.as_ref()
                    .is_some_and(|(proof, _)| !proof.unadmitted_receiver_deref),
                summary == Some(true),
                "PathBuf has its own certified family"
            );
            if let Some((proof, target)) = path {
                assert_eq!(target.owner_fqn(), "std.path.Path");
                assert_eq!(
                    proof.receiver_adjustments.len(),
                    usize::from(summary == Some(true))
                );
            }
        }
    }

    #[test]
    fn std_deref_pack_swap_on_unchanged_source_declines_missing_and_partial_summaries() {
        let source = r#"fn f(s: std::string::String) { let _ = s.contains(".."); }"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        use brokk_bifrost_analysis::analyzer::read_ledger::{ReadKey, ReadLedger};
        use brokk_bifrost_analysis::analyzer::{
            ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
            verify_read_set,
        };
        let mut identities = Vec::new();
        let mut original_model_reads = None;

        for summary in [Some(true), None, Some(false), Some(true)] {
            activate_deref_fixture(&fixture, summary, true);
            identities.push(
                fixture
                    .analyzer
                    .analyzer()
                    .active_semantic_models()
                    .unwrap()
                    .active_model_set_hash
                    .clone(),
            );
            let ledger = Arc::new(ReadLedger::new());
            let selected = {
                let _scope = AnalyzerQueryScope::with_read_ledger(
                    fixture.analyzer.analyzer(),
                    Arc::clone(&ledger),
                );
                deref_fixture_call(&fixture, source, "contains")
            };
            assert_eq!(
                selected
                    .as_ref()
                    .is_some_and(|(proof, _)| !proof.unadmitted_receiver_deref),
                summary == Some(true)
            );
            let model_reads = ledger
                .keys()
                .into_iter()
                .filter(|key| matches!(key, ReadKey::Models(_)))
                .collect::<Vec<_>>();
            assert!(
                !model_reads.is_empty(),
                "Deref selection must record model reads"
            );
            let original = original_model_reads.get_or_insert(model_reads);
            let mut inputs = brokk_bifrost_analysis::test_support::read_ledger_test_inputs();
            inputs.models = brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
                Some(identities.last().unwrap()),
            );
            let verdict = verify_read_set(
                &fixture.analyzer,
                &ChangedFacts::between(&fixture.analyzer, &fixture.analyzer),
                &inputs,
                original,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            );
            if summary == Some(true) {
                assert_eq!(verdict, ReadVerdict::Unchanged);
            } else {
                assert!(
                    verdict.changed().is_some(),
                    "a pack swap must miss read-receipt reuse, never hit: {verdict:?}"
                );
            }
        }
        assert_ne!(identities[0], identities[1]);
        assert_ne!(identities[0], identities[2]);
        assert_eq!(identities[0], identities[3]);
    }

    #[test]
    fn shared_std_deref_summary_does_not_authorize_a_mutable_target() {
        let source = "fn f(mut s: std::string::String) { s.mutate(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_deref_fixture(&fixture, Some(true), true);
        assert!(
            deref_fixture_call(&fixture, source, "mutate")
                .is_some_and(|(proof, _)| proof.unadmitted_receiver_deref
                    && proof.receiver_adjustments.is_empty()),
            "DerefMut needs its own complete summary"
        );
    }

    #[test]
    fn user_deref_target_is_not_a_trusted_std_receiver_adjustment() {
        let source = r#"struct W(std::string::String); impl std::ops::Deref for W { type Target = str; fn deref(&self) -> &str { &self.0 } } fn f(w: W) { let _ = w.contains(".."); }"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_deref_fixture(&fixture, Some(true), true);
        assert!(
            deref_fixture_call(&fixture, source, "contains").is_none(),
            "a source impl has no admitted implicit call summary"
        );
    }

    #[test]
    fn imported_external_constructor_proves_modeled_receiver_owner() {
        let source = "use std::process::Command;\n\nfn chained() {\n    Command::new(\"sh\").arg(\"-c\");\n}\n\nfn bound() {\n    let mut command = Command::new(\"sh\");\n    command.arg(\"-c\");\n}\n\nfn typed() {\n    let mut command: Command = Command::new(\"sh\");\n    command.arg(\"-c\");\n}\n\nfn direct() {\n    Command::new(\"sh\");\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_imported_constructor_model(&fixture);

        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let constructor_start = source.find("new(").expect("fixture contains new");
        let rust_source = RustTypeProof::new(fixture.analyzer.analyzer())
            .expect("Rust type proof")
            .source(&file)
            .expect("prepared Rust source");
        let site = ResolvedReferenceSite {
            path: "new".to_owned(),
            text: "new".to_owned(),
            range: Range {
                start_byte: constructor_start,
                end_byte: constructor_start + 3,
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: constructor_start,
            focus_end_byte: constructor_start + 3,
        };
        let (_, identity) = selected_external_call(
            fixture.analyzer.analyzer(),
            &file,
            rust_source.text(),
            rust_source.tree(),
            &site,
        )
        .expect("imported constructor resolves through the activated model");
        assert_eq!(identity.owner_fqn(), "std.process.Command");
        assert_eq!(identity.member(), "new");

        let owners = source
            .match_indices("arg(")
            .map(|(method_start, _)| {
                rust_method_receiver_owner(
                    fixture.analyzer.analyzer(),
                    &file,
                    source,
                    method_start..method_start + 3,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owners,
            vec![
                Some((RustReceiverOwner::Path("std.process.Command".to_owned()), 1)),
                Some((RustReceiverOwner::Path("std.process.Command".to_owned()), 1)),
                Some((RustReceiverOwner::Path("std.process.Command".to_owned()), 1)),
            ]
        );

        use brokk_bifrost_analysis::analyzer::usages::get_definition::{
            DefinitionLookupRequest, resolve_call_target_batch_with_source,
        };

        let requests = source
            .match_indices("arg(")
            .map(|(method_start, _)| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(method_start),
                end_byte: Some(method_start + 3),
            })
            .collect();
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let outcomes = resolve_call_target_batch_with_source(
            fixture.analyzer.analyzer(),
            scope.token(),
            requests,
            file,
            Arc::from(source),
            None,
        );
        assert_eq!(outcomes.len(), 3);
        for outcome in outcomes {
            assert!(
                outcome.exact_external_call.is_some(),
                "imported receiver method carries its resolver proof: {outcome:#?}"
            );
            let identity = outcome
                .external_callee_identity
                .as_ref()
                .unwrap_or_else(|| {
                    panic!("receiver resolver publishes the selected identity: {outcome:#?}")
                });
            assert_eq!(identity.owner_fqn(), "std.process.Command");
            assert_eq!(identity.member(), "arg");
        }
    }

    #[test]
    #[hardwon("#12987: any glob import blocked String constructor certification")]
    fn std_self_constructor_globs_use_selected_export_absence() {
        let absent = "mod exports { pub struct Other; }\nuse exports::*;\npub fn probe() { let unused = String::from(\"a\"); }\n";
        let present = "mod exports { pub struct String; impl String { pub fn from(_: &str) -> Self { Self } } impl Drop for String { fn drop(&mut self) {} } }\nuse exports::*;\npub fn probe() { let unused = String::from(\"a\"); }\n";
        let external =
            "use unknown_external::*;\npub fn probe() { let unused = String::from(\"a\"); }\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"glob_constructor\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "mod absent; mod present; mod external;")
            .file("src/absent.rs", absent)
            .file("src/present.rs", present)
            .file("src/external.rs", external)
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        for (path, source, expected) in [
            ("src/absent.rs", absent, RustValueClass::String),
            ("src/present.rs", present, RustValueClass::Unknown),
            ("src/external.rs", external, RustValueClass::Unknown),
        ] {
            let proof = RustTypeProof::new(workspace.analyzer()).expect("Rust type proof");
            let prepared = proof
                .source(&ProjectFile::new(project.root(), path))
                .unwrap();
            let start = source.rfind("String::from(\"a\")").unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + "String::from(\"a\")".len())
                .unwrap();
            assert_eq!(call.kind(), "call_expression");
            assert_eq!(
                proof.call_class(&prepared, call, PROOF_DEPTH),
                expected,
                "{path}"
            );
        }
    }

    #[test]
    #[hardwon("#12987: a shadowing From trait made a Drop-carrying result look like String")]
    fn std_self_constructor_rejects_shadowed_from_traits() {
        let guard = "pub struct Guard; impl Drop for Guard { fn drop(&mut self) {} }";
        let local = format!(
            "{guard} trait From {{ fn from(_: &str) -> Guard; }} impl From for String {{ fn from(_: &str) -> Guard {{ Guard }} }} pub fn probe() {{ let unused = String::from(\"a\"); }}"
        );
        let imported = format!(
            "{guard} mod traits {{ pub trait From {{ fn from(_: &str) -> super::Guard; }} impl From for String {{ fn from(_: &str) -> super::Guard {{ super::Guard }} }} }} use traits::From; pub fn probe() {{ let unused = String::from(\"a\"); }}"
        );
        let glob = imported.replace("use traits::From;", "use traits::*;");
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"shadow_from\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "mod local; mod imported; mod glob;")
            .file("src/local.rs", &local)
            .file("src/imported.rs", &imported)
            .file("src/glob.rs", &glob)
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let actual = [
            ("src/local.rs", local),
            ("src/imported.rs", imported),
            ("src/glob.rs", glob),
        ]
        .into_iter()
        .map(|(path, source)| {
            let proof = RustTypeProof::new(workspace.analyzer()).expect("Rust type proof");
            let prepared = proof
                .source(&ProjectFile::new(project.root(), path))
                .unwrap();
            let start = source.rfind("String::from(\"a\")").unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + "String::from(\"a\")".len())
                .unwrap();
            assert_eq!(call.kind(), "call_expression");
            (path, proof.call_class(&prepared, call, PROOF_DEPTH))
        })
        .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                ("src/local.rs", RustValueClass::Unknown),
                ("src/imported.rs", RustValueClass::Unknown),
                ("src/glob.rs", RustValueClass::Unknown)
            ]
        );
    }

    #[test]
    fn std_self_constructors_classify_without_a_model_pack() {
        use RustValueClass::{Inert, String as Owned, Unknown};
        const GUARD: &str = "struct Guard; impl Drop for Guard { fn drop(&mut self) {} }\n";
        const LOCAL_STRING: &str = "struct String; impl Drop for String { fn drop(&mut self) {} }\nimpl String { fn from(_: &str) -> String { String } }\n";
        // (case, source, the call to classify, expected class)
        let cases: &[(&str, &str, &str, RustValueClass)] = &[
            (
                "prelude String::from",
                "fn probe() { let s = String::from(\"x\"); }",
                "String::from(\"x\")",
                Owned,
            ),
            (
                "prelude String::new",
                "fn probe() { let s = String::new(); }",
                "String::new()",
                Owned,
            ),
            (
                "qualified String::from cannot prove the module prelude is enabled",
                "fn probe() { let s = std::string::String::from(\"x\"); }",
                "std::string::String::from(\"x\")",
                Unknown,
            ),
            (
                "aliased String::from cannot prove the module prelude is enabled",
                "use std::string::String as S;\nfn probe() { let s = S::from(\"x\"); }",
                "S::from(\"x\")",
                Unknown,
            ),
            (
                "a non-literal argument never reaches the result",
                "fn probe(g: i32) { let s = String::from(g); }",
                "String::from(g)",
                Owned,
            ),
            (
                "turbofish Vec::new",
                "fn probe() { let v = Vec::<u8>::new(); }",
                "Vec::<u8>::new()",
                Inert,
            ),
            (
                "turbofish Vec::with_capacity",
                "fn probe() { let v = Vec::<u8>::with_capacity(3); }",
                "Vec::<u8>::with_capacity(3)",
                Inert,
            ),
            (
                "qualified Vec::new",
                "fn probe() { let v = std::vec::Vec::<String>::new(); }",
                "std::vec::Vec::<String>::new()",
                Inert,
            ),
            (
                "aliased Vec::with_capacity",
                "use std::vec::Vec as V;\nfn probe() { let v = V::<u8>::with_capacity(3); }",
                "V::<u8>::with_capacity(3)",
                Inert,
            ),
            (
                "inherent constructors survive no_implicit_prelude on a qualified path",
                "#![no_implicit_prelude]\nfn probe() { let s = ::std::string::String::new(); }",
                "::std::string::String::new()",
                Owned,
            ),
            (
                "an inherent constructor inside a no_implicit_prelude module",
                "#[no_implicit_prelude]\nmod m { pub fn probe() { let s = ::std::string::String::new(); } }",
                "::std::string::String::new()",
                Owned,
            ),
            (
                "an inferred element type proves nothing",
                "fn probe() { let v = Vec::new(); }",
                "Vec::new()",
                Unknown,
            ),
            (
                "an inferred element type proves nothing with a capacity",
                "fn probe() { let v = Vec::with_capacity(3); }",
                "Vec::with_capacity(3)",
                Unknown,
            ),
            (
                "an element whose drop runs user code",
                &format!("{GUARD}fn probe() {{ let v = Vec::<Guard>::new(); }}"),
                "Vec::<Guard>::new()",
                Unknown,
            ),
            (
                "a custom allocator runs user code on drop",
                &format!("{GUARD}fn probe() {{ let v = Vec::<u8, Guard>::new(); }}"),
                "Vec::<u8, Guard>::new()",
                Unknown,
            ),
            (
                "a generic element type is unproven",
                "fn probe<T>() { let v = Vec::<T>::new(); }",
                "Vec::<T>::new()",
                Unknown,
            ),
            (
                "a local String shadows the prelude",
                &format!("{LOCAL_STRING}fn probe() {{ let s = String::from(\"x\"); }}"),
                "String::from(\"x\")",
                Unknown,
            ),
            (
                "an import named String is another type",
                "use other::String;\nfn probe() { let s = String::from(\"x\"); }",
                "String::from(\"x\")",
                Unknown,
            ),
            (
                "an unindexed named import shadows the turbofish String",
                "use other::String;\nfn probe() { let v = Vec::<String>::new(); }",
                "Vec::<String>::new()",
                Unknown,
            ),
            (
                "an unindexed glob may shadow the turbofish String",
                "use other::*;\nfn probe() { let v = Vec::<String>::new(); }",
                "Vec::<String>::new()",
                Unknown,
            ),
            (
                "an alias of a foreign String is another type",
                "use other::String as S;\nfn probe() { let s = S::from(\"x\"); }",
                "S::from(\"x\")",
                Unknown,
            ),
            (
                "a local std module shadows the standard crate",
                "mod std { pub mod string { pub struct String; impl Drop for String { fn drop(&mut self) {} } impl String { pub fn from(_: &str) -> String { String } } } }\nfn probe() { let s = std::string::String::from(\"x\"); }",
                "std::string::String::from(\"x\")",
                Unknown,
            ),
            (
                "no_implicit_prelude removes the prelude String",
                "#![no_implicit_prelude]\nfn probe() { let s = String::from(\"x\"); }",
                "String::from(\"x\")",
                Unknown,
            ),
            (
                "no_implicit_prelude removes the From trait from a qualified path",
                "#![no_implicit_prelude]\nfn probe() { let s = ::std::string::String::from(\"x\"); }",
                "::std::string::String::from(\"x\")",
                Unknown,
            ),
            (
                "no_implicit_prelude on an enclosing module",
                "#[no_implicit_prelude]\nmod m { pub fn probe() { let s = ::std::string::String::from(\"x\"); } }",
                "::std::string::String::from(\"x\")",
                Unknown,
            ),
            (
                "an unreviewed constructor",
                "fn probe() { let s = String::from_utf8_lossy(b\"x\"); }",
                "String::from_utf8_lossy(b\"x\")",
                Unknown,
            ),
        ];
        for (case, source, call, expected) in cases {
            let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
            let proof = RustTypeProof::new(fixture.analyzer.analyzer()).expect("Rust type proof");
            let prepared = proof
                .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
                .expect("prepared Rust source");
            let start = source.rfind(call).expect(case);
            let node = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + call.len())
                .expect(case);
            assert_eq!(node.kind(), "call_expression", "{case}");
            assert_eq!(
                proof.call_class(&prepared, node, PROOF_DEPTH),
                *expected,
                "{case}"
            );
        }
    }

    #[test]
    #[hardwon("#12074: reparsed vec! operand node ids collided in a node-keyed proof cache")]
    fn vec_operand_reparses_do_not_enter_source_memos() {
        let source = "struct Guard; impl Drop for Guard { fn drop(&mut self) {} } fn guard() -> Guard { Guard } fn run() { vec![Vec::<u8>::new()]; vec![guard()]; }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let source = proof.source(&file).expect("prepared Rust source");
        let mut pending = vec![source.tree().root_node()];
        let mut invocations = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "macro_invocation" {
                invocations.push(node);
            }
            pending.extend(named_children(node));
        }
        assert_eq!(invocations.len(), 2);
        for order in [invocations.clone(), invocations.into_iter().rev().collect()] {
            for invocation in order {
                let operands = brokk_bifrost_rust::macro_matcher::parse_macro_operands(
                    invocation,
                    source.text(),
                )
                .unwrap();
                for operand in operands {
                    assert!(!source.owns_node(operand.node()));
                    let _ty = proof.exact_model_argument_type(&source, operand.node(), PROOF_DEPTH);
                    proof.expression_class(&source, operand.node(), PROOF_DEPTH);
                }
                // Deterministically pin the lifetime boundary rather than relying
                // on the allocator to reuse a freed tree's IDs in this run.
                assert!(source.expression_classes.borrow().is_empty());
                assert!(source.modeled_call_shapes.borrow().is_empty());
            }
        }
    }

    #[test]
    fn prelude_and_std_root_constructors_use_pack_identity_when_unreviewed() {
        let source = "fn run(size: usize) {\n    Vec::<u8>::with_capacity(size);\n    let typed: Vec<u8> = Vec::with_capacity(size);\n    std::vec::Vec::with_capacity(size);\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_imported_constructor_model(&fixture);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let identities = source
            .match_indices("with_capacity")
            .map(|(start, _)| {
                let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
                let rust_source = proof.source(&file).expect("prepared Rust source");
                let site = ResolvedReferenceSite {
                    path: "with_capacity".to_owned(),
                    text: "with_capacity".to_owned(),
                    range: Range {
                        start_byte: start,
                        end_byte: start + "with_capacity".len(),
                        start_line: 0,
                        end_line: 0,
                    },
                    focus_start_byte: start,
                    focus_end_byte: start + "with_capacity".len(),
                };
                selected_external_call(
                    analyzer,
                    &file,
                    rust_source.text(),
                    rust_source.tree(),
                    &site,
                )
                .map(|(_, identity)| {
                    (
                        identity.owner_fqn().to_owned(),
                        identity.member().to_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            identities,
            vec![
                Some(("std.vec.Vec".to_owned(), "with_capacity".to_owned())),
                Some(("std.vec.Vec".to_owned(), "with_capacity".to_owned())),
                Some(("std.vec.Vec".to_owned(), "with_capacity".to_owned())),
            ]
        );
    }

    #[test]
    #[hardwon(
        "#6542: std receivers rejected defaults and primitives; #11145: omitted arguments were mistaken for arity mismatch"
    )]
    fn std_receiver_type_contract_accepts_defaults_and_structural_primitives() {
        // Synthetic declarations exercise the schema/structured-resolver boundary;
        // these are test-only shapes, not a product standard-library catalog.
        let source = "fn probe(a: Vec<u8>, b: Vec<u8, u16>, c: Vec, d: Vec<u8, u16, u32>, e: &str, f: &[u8], g: u32, h: &[u8; 4], i: std::slice::Iter<'_, u8>) { let inferred = Vec::new(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let mut vector = rust_type("std.vec.Vec", "struct");
        vector["type_parameters"] = serde_json::json!(["T", "A"]);
        vector["type_parameter_defaults"] = serde_json::json!([
            null, { "kind": "type", "type": { "kind": "named", "name": "u8" } }
        ]);
        let primitive = |name: &str, parameters: &[&str]| {
            let mut fact = rust_type(&format!("core.primitive.{name}"), "struct");
            fact["aliases"] = serde_json::json!([format!("std.primitive.{name}")]);
            fact["type_parameters"] = serde_json::json!(parameters);
            fact
        };
        let mut iterator = rust_type("std.slice.Iter", "struct");
        iterator["type_parameters"] = serde_json::json!(["T"]);
        let pack = serde_json::json!({
            "schema_version": 18,
            "pack_id": "fixture.rust-std-receiver-contract",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "toolchains": [] },
            "provenance": { "source": "synthetic test-only receiver contract for #6542" },
            "license": "NOASSERTION",
            "completeness": "partial",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.receiver-contract",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"), vector, iterator,
                        primitive("str", &[]), primitive("slice", &["T"]),
                        primitive("u32", &[]), primitive("array", &["T", "N"])
                    ],
                    "members": [], "relations": []
                }
            }]
        });
        activate_model_pack(&fixture, pack, "fixture.rust-std-receiver-contract", "std");
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
        let prepared = proof.source(&file).expect("prepared source");
        let function = named_children(prepared.tree().root_node())[0];
        let initializer = function
            .child_by_field_name("body")
            .unwrap()
            .named_child(0)
            .unwrap()
            .child_by_field_name("value")
            .unwrap();
        let owner_node = initializer
            .child_by_field_name("function")
            .unwrap()
            .child_by_field_name("path")
            .unwrap();
        let inferred = completed_proof(analyzer, None, || {
            proof.nominal_type_owner(&prepared, owner_node)
        });
        assert!(
            matches!(inferred, RustProofAttempt::Complete(Some((owner, arguments))) if owner == "std.vec.Vec" && arguments.is_empty())
        );
        let parameters = named_children(function.child_by_field_name("parameters").unwrap());
        let attempts = parameters
            .into_iter()
            .map(|parameter| {
                completed_proof(analyzer, None, || {
                    proof
                        .nominal_type_owner(
                            &prepared,
                            parameter.child_by_field_name("type").unwrap(),
                        )
                        .map(|(owner, _)| owner)
                })
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            &attempts[2],
            RustProofAttempt::Incomplete {
                value: None,
                reason: "external_receiver_generic_arity_mismatch",
                cause: None
            }
        ));
        assert!(matches!(
            &attempts[3],
            RustProofAttempt::Incomplete {
                value: None,
                reason: "external_receiver_generic_arity_mismatch",
                cause: None
            }
        ));
        let owners = attempts
            .into_iter()
            .map(RustProofAttempt::into_value)
            .collect::<Vec<_>>();
        assert_eq!(
            owners,
            [
                Some("std.vec.Vec".into()),
                Some("std.vec.Vec".into()),
                None,
                None,
                Some("core.primitive.str".into()),
                Some("core.primitive.slice".into()),
                Some("core.primitive.u32".into()),
                Some("core.primitive.array".into()),
                Some("std.slice.Iter".into())
            ]
        );
    }

    #[test]
    #[hardwon("#11952: duplicate String::from impl layouts suppressed an agreed result type")]
    fn modeled_from_result_agreement_does_not_select_an_ambiguous_callable() {
        use crate::analyzer::semantic_model::SemanticModelCallableDisposition;

        // Two erased reference contracts reproduce the published stdlib family.
        // A distinct char return makes argument filtering observable; a second
        // reference return disagreement must suppress the result proof.
        for trait_input_contract in [true, false] {
            for mode in 0..6 {
                let method = if trait_input_contract {
                    "from"
                } else {
                    "build"
                };
                let source = r##"fn probe(unknown: Unknown, mutable: &mut str) {
                std::string::String::from("echo hello").as_str();
                std::string::String::from(r#"raw"#);
                std::string::String::from('x');
                std::string::String::from(unknown);
                std::string::String::from(mutable);
                std::string::String::from(42);
                std::string::String::from(42u8);
                std::string::String::from(1.0f32);
                std::string::String::from(b"bytes");
            }"##;
                let source = source.replace("::from", &format!("::{method}"));
                let fixture =
                    AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
                let named = |name: &str| serde_json::json!({"kind":"named", "name":name});
                let str_ref =
                    serde_json::json!({"kind":"by_ref", "element":named("core.primitive.str")});
                let member = |id: &str, argument: serde_json::Value, returns: &str| {
                    serde_json::json!({
                        "id":format!("member.fixture.{id}"), "owner":"type.fixture.std-string-string",
                        "name":method, "member_kind":"method", "visibility":"public",
                        "is_static":true, "callable_family_complete":true,
                        "implemented_trait":{"kind":"named", "name":"core.convert.From", "arguments":[argument.clone()]},
                        "signature":{"parameters":[{"name":"value", "type":argument}], "returns":named(returns)},
                        "locator":{"kind":"artifact", "path":"fixture.rs", "symbol":format!("String.from.{id}")}
                    })
                };
                let pack = serde_json::json!({
                    "schema_version":31, "pack_id":"fixture.rust-from-agreement", "version":"1.0.0",
                    "producer":{"name":"rust-type-proof-test", "version":"1.0.0"},
                    "language":"rust", "ecosystem":"cargo", "compatibility":{"toolchains":[]},
                    "provenance":{"source":"test-only erased Rust reference contracts"}, "license":"NOASSERTION",
                    "completeness":"complete", "safety":{"generated_code_only":false,"review_required":false},
                    "shards":[{"id":"declarations.from", "activation":[{}], "payload":{
                        "kind":"declaration_facts", "types":[
                            rust_type("std", "module"), rust_type("std.string", "module"),
                            rust_type("std.string.String", "struct"),
                            rust_type("core", "module"), rust_type("core.primitive", "module"),
                            rust_type("core.primitive.str", "struct"), rust_type("core.primitive.char", "struct"),
                            rust_type("core.primitive.u8", "struct"), rust_type("core.primitive.f32", "struct"),
                            rust_type("core.convert", "module"), rust_type("core.convert.From", "trait")
                        ], "members":[
                            member("shared", str_ref.clone(), "std.string.String"),
                            member("erased-mutable", str_ref, if mode >= 2 {"core.primitive.char"} else {"std.string.String"}),
                            member("char", named("core.primitive.char"), if mode == 0 { "std.string.String" } else { "core.primitive.char" })
                        ], "relations":[]
                    }}]
                });
                let mut pack = pack;
                if mode >= 3 {
                    pack["shards"][0]["payload"]["members"][1]["signature"]["returns"] =
                        if mode == 3 {
                            serde_json::json!({"kind":"unknown"})
                        } else {
                            serde_json::json!({"kind":"type_parameter", "name":"Unbound"})
                        };
                }
                if mode == 4 {
                    pack["shards"][0]["payload"]["members"][1]["signature"]["type_parameters"] =
                        serde_json::json!(["Unbound"]);
                }
                if mode == 5 {
                    pack["shards"][0]["payload"]["members"][1]["signature"]["returns"] = serde_json::json!({"kind":"projection", "owner":named("std.string.String"), "name":"Associated"});
                }
                if !trait_input_contract {
                    for member in pack["shards"][0]["payload"]["members"]
                        .as_array_mut()
                        .unwrap()
                    {
                        member.as_object_mut().unwrap().remove("implemented_trait");
                    }
                }
                activate_model_pack(&fixture, pack, "fixture.rust-from-agreement", "std");
                let analyzer = fixture.analyzer.analyzer();
                let overlay = analyzer
                    .semantic_model_overlay_read()
                    .published()
                    .expect("overlay");
                let candidates = overlay.callable_for_application(
                    SemanticModelCallableKey::new("rust", "std.string.String", method, false, 1),
                    &SemanticModelCallApplication::positional(1),
                );
                assert_eq!(
                    candidates.disposition,
                    SemanticModelCallableDisposition::CompatibleLayout
                );
                assert!(
                    candidates.unique().is_none(),
                    "result agreement cannot select an impl"
                );
                let file = ProjectFile::new(fixture.project_root(), "lib.rs");
                for _ in 0..2 {
                    let proof = RustTypeProof::new(analyzer).expect("Rust proof");
                    for (argument, expected) in [
                        ("\"echo hello\"", (mode < 2).then_some("std.string.String")),
                        ("r#\"raw\"#", (mode < 2).then_some("std.string.String")),
                        (
                            "'x'",
                            Some(if mode == 0 {
                                "std.string.String"
                            } else {
                                "core.primitive.char"
                            }),
                        ),
                        ("mutable", (mode < 2).then_some("std.string.String")),
                        ("unknown", (mode == 0).then_some("std.string.String")),
                        ("42", (mode == 0).then_some("std.string.String")),
                        ("42u8", None),
                        ("1.0f32", None),
                        ("b\"bytes\"", (mode == 0).then_some("std.string.String")),
                    ] {
                        let expected = if trait_input_contract {
                            expected
                        } else {
                            (mode == 0).then_some("std.string.String")
                        };
                        let expression = format!("std::string::String::{method}({argument})");
                        let start = source.find(&expression).expect("fixture call");
                        let result = proof.modeled_result(
                            &file,
                            start..start + expression.len(),
                            PROOF_DEPTH,
                        );
                        let owner = result.as_ref().and_then(|ty| match ty {
                            TypeRef::Named { name, .. } => Some(name.as_str()),
                            TypeRef::Declared { id, .. } => expected.filter(|name| {
                                overlay
                                    .symbols_named_in_family(
                                        name,
                                        "rust",
                                        SemanticModelNamespace::TypeOrModule,
                                    )
                                    .unique()
                                    .is_some_and(|symbol| symbol.id == *id)
                            }),
                            _ => None,
                        });
                        assert_eq!(
                            owner, expected,
                            "{expression}, mode={mode}, result={result:?}"
                        );
                        if expected.is_none() {
                            assert!(
                                result.is_none(),
                                "unknown or conflicting evidence must refuse"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[hardwon(
        "#11952: a transparent alias identity was treated as an incompatible From input and a resolved result"
    )]
    fn modeled_result_agreement_keeps_alias_candidates_and_refuses_alias_results() {
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "fn probe() {}")]);
        let mut alias = rust_type("core.primitive.CharAlias", "type_alias");
        alias["alias_target"] = serde_json::json!({"kind":"named", "name":"core.primitive.char"});
        let mut wrapper = rust_type("core.primitive.Wrapper", "struct");
        wrapper["type_parameters"] = serde_json::json!(["T"]);
        let pack = serde_json::json!({
            "schema_version":32, "pack_id":"fixture.rust-alias-agreement", "version":"1.0.0",
            "producer":{"name":"rust-type-proof-test", "version":"1.0.0"},
            "language":"rust", "ecosystem":"cargo", "compatibility":{"toolchains":[]},
            "provenance":{"source":"test-only transparent alias contracts"}, "license":"NOASSERTION",
            "completeness":"complete", "safety":{"generated_code_only":false,"review_required":false},
            "shards":[{"id":"declarations.aliases", "activation":[{}], "payload":{
                "kind":"declaration_facts", "types":[
                    rust_type("core", "module"), rust_type("core.primitive", "module"),
                    rust_type("core.primitive.char", "struct"), alias, wrapper
                ], "members":[], "relations":[]
            }}]
        });
        activate_model_pack(&fixture, pack, "fixture.rust-alias-agreement", "core");
        let analyzer = fixture.analyzer.analyzer();
        let proof = RustTypeProof::new(analyzer).expect("Rust proof");
        let overlay = analyzer
            .semantic_model_overlay_read()
            .published()
            .expect("overlay");
        let active = analyzer.active_semantic_models().expect("models");
        let model = super::super::trait_applicability::ModelApplicability::new(
            analyzer,
            proof.rust,
            &overlay,
            &active,
            &proof.resolver,
        );
        let character = TypeRef::named("core.primitive.char");
        let alias = TypeRef::named("core.primitive.CharAlias");
        let nested = |argument| TypeRef::Named {
            name: "core.primitive.Wrapper".into(),
            arguments: vec![argument],
            nullable: false,
        };
        let observations = (
            model_argument_definitely_differs(&character, &alias, &model),
            model_argument_definitely_differs(&alias, &character, &model),
            model_argument_definitely_differs(
                &nested(character.clone()),
                &nested(alias.clone()),
                &model,
            ),
            resolved_model_result(alias.clone(), &model, &active).is_some(),
            resolved_model_result(nested(alias), &model, &active).is_some(),
        );
        assert_eq!(
            observations,
            (false, false, false, false, false),
            "an alias is not a proven mismatch or a normalized result constructor"
        );
    }

    #[test]
    #[hardwon(
        "#12038: alias normalization erased unexpanded T and &T before lexical trait selection"
    )]
    fn alias_receiver_normalization_preserves_lexical_generic_traits() {
        let source = "use std::clone::Clone;\nfn direct<T: Clone>(x: T) { x.clone(); }\nfn borrowed<T: Clone>(x: &T) { x.clone(); }\nfn unbound<T>(x: T) { x.clone(); }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let mut pack = clone_certificate_pack();
        let method = &mut pack["shards"][0]["payload"]["members"][0];
        method["receiver"] = serde_json::json!({"pointer":false});
        method["self_form"] = serde_json::json!({"kind":"shared"});
        activate_model_pack(&fixture, pack, "fixture.rust-clone-certificate", "std");
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(analyzer).unwrap();
        let prepared = proof.source(&file).unwrap();
        for (index, (start, _)) in source.match_indices("clone()").enumerate() {
            let site = ResolvedReferenceSite {
                path: "clone".into(),
                text: "clone".into(),
                range: Range {
                    start_byte: start,
                    end_byte: start + 5,
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: start,
                focus_end_byte: start + 5,
            };
            let selected = selected_external_call(analyzer, &file, source, prepared.tree(), &site);
            if index < 2 {
                let (_, identity) = selected
                    .unwrap_or_else(|| panic!("generic receiver {index} lost its trait selection"));
                assert_eq!(identity.owner_fqn(), "std.clone.Clone");
                assert_eq!(identity.member(), "clone");
            } else {
                assert!(selected.is_none(), "an unbound T acquired trait authority");
            }
        }
    }

    #[test]
    #[hardwon("#12038: workspace nominals need no overlay owner before external trait selection")]
    fn alias_receiver_normalization_preserves_workspace_trait_receivers() {
        let source = "use std::clone::Clone; struct Local; fn probe<T: Clone>(x: T, y: &T) { x.clone(); y.clone(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let mut pack = clone_certificate_pack();
        let method = &mut pack["shards"][0]["payload"]["members"][0];
        method["receiver"] = serde_json::json!({"pointer":false});
        method["self_form"] = serde_json::json!({"kind":"shared"});
        pack["schema_version"] = serde_json::json!(32);
        for (name, target) in [
            (
                "std.clone.Identity",
                serde_json::json!({"kind":"type_parameter","name":"T"}),
            ),
            (
                "std.clone.Borrowed",
                serde_json::json!({"kind":"by_ref","element":{"kind":"type_parameter","name":"T"}}),
            ),
        ] {
            let mut alias = rust_type(name, "type_alias");
            alias["type_parameters"] = serde_json::json!(["T"]);
            alias["alias_target"] = target;
            pack["shards"][0]["payload"]["types"]
                .as_array_mut()
                .unwrap()
                .push(alias);
        }
        activate_model_pack(&fixture, pack, "fixture.rust-clone-certificate", "std");
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        // Selected applications can carry a workspace instantiation of the
        // lexical receiver. Neither its spelling nor its native ID is a
        // semantic-model declaration; both must survive this adapter.
        for local in [
            TypeRef::named("Local"),
            TypeRef::TypeParameter { name: "T".into() },
            TypeRef::Declared {
                id: "workspace.local".into(),
                arguments: vec![],
                nullable: false,
            },
        ] {
            let borrowed = TypeRef::ByRef {
                element: Box::new(local.clone()),
                reference_kind: crate::analyzer::semantic_model::TypeRefReferenceKind::Lvalue,
            };
            for (spelling, application) in [("x.clone", local), ("y.clone", borrowed)] {
                let alias = |name: &str, argument| TypeRef::Named {
                    name: name.into(),
                    arguments: vec![argument],
                    nullable: false,
                };
                let identity = alias("std.clone.Identity", application.clone());
                let nested = alias("std.clone.Identity", identity.clone());
                let borrowed_alias = alias("std.clone.Borrowed", application.clone());
                let borrowed_result = TypeRef::ByRef {
                    element: Box::new(application.clone()),
                    reference_kind: crate::analyzer::semantic_model::TypeRefReferenceKind::Lvalue,
                };
                for (input, expected) in [
                    (application.clone(), application.clone()),
                    (identity, application.clone()),
                    (nested, application),
                    (borrowed_alias, borrowed_result),
                ] {
                    let attempt = completed_proof(analyzer, None, || {
                        normalized_receiver_application(analyzer, input.clone())
                    });
                    assert!(
                        matches!(attempt, RustProofAttempt::Complete(Some(ref actual)) if actual == &expected),
                        "a bound source type retains its workspace authority without a refusal: {attempt:?}"
                    );
                    let selected = select_opaque_application(
                        analyzer,
                        &file,
                        source,
                        spelling,
                        "clone",
                        "std.clone.Clone",
                        &input,
                    )
                    .expect("workspace application retains the lexical trait route");
                    assert_eq!(selected.owner, "std.clone.Clone");
                }
            }
        }
        for name in ["std.clone.Identity", "std.clone.Borrowed"] {
            let attempt = completed_proof(analyzer, None, || {
                normalized_receiver_application(
                    analyzer,
                    TypeRef::Named {
                        name: name.into(),
                        arguments: vec![TypeRef::Unknown],
                        nullable: false,
                    },
                )
            });
            assert!(
                matches!(
                    attempt,
                    RustProofAttempt::Incomplete {
                        value: None,
                        reason: "model_alias_unresolvable_target",
                        cause: None
                    }
                ),
                "an opaque root still supplies no receiver facts: {attempt:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#12038: cancellation in the shared alias worklist became a complete missing receiver"
    )]
    fn alias_receiver_materialization_records_cancellation() {
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "fn run() {}")]);
        let mut pack = clone_certificate_pack();
        pack["schema_version"] = serde_json::json!(32);
        let mut alias = rust_type("std.clone.CancelAlias", "type_alias");
        alias["alias_target"] = serde_json::json!({"kind":"named","name":"std.clone.Clone"});
        pack["shards"][0]["payload"]["types"]
            .as_array_mut()
            .unwrap()
            .push(alias);
        activate_model_pack(&fixture, pack, "fixture.rust-clone-certificate", "std");
        let analyzer = fixture.analyzer.analyzer();
        assert_eq!(
            normalized_receiver_application(analyzer, TypeRef::named("std.clone.CancelAlias")),
            Some(TypeRef::named("std.clone.Clone"))
        );
        let cancellation = CancellationToken::new();
        let _request = AnalyzerQueryScope::with_cancellation(analyzer, &cancellation);
        cancellation.cancel();
        // Do not pass the token to completed_proof: the alias adapter itself
        // must report its worklist's cancellation, rather than a later poll.
        let (attempt, receipt) = QueryReadReceipt::capture(analyzer, || {
            completed_proof(analyzer, None, || {
                normalized_receiver_application(analyzer, TypeRef::named("std.clone.CancelAlias"))
            })
        });
        assert!(
            matches!(
                attempt,
                RustProofAttempt::Incomplete {
                    value: None,
                    cause: Some(DerivationExecutionCause::Cancelled),
                    ..
                }
            ),
            "{attempt:?}"
        );
        assert!(receipt.incomplete_reasons().contains(
            &brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                reason: "cancelled",
                cause: Some(DerivationExecutionCause::Cancelled)
            }
        ));
    }

    #[test]
    #[hardwon(
        "#12038: primitive alias targets lost intrinsic authority without model declarations"
    )]
    fn alias_receiver_primitive_targets_need_no_model_declaration() {
        use serde_json::json;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "fn run() {}")]);
        let mut pack = opaque_receiver_pack();
        for (index, primitive) in [
            "u8",
            "usize",
            "bool",
            "core.primitive.i32",
            "std.primitive.f64",
        ]
        .into_iter()
        .enumerate()
        {
            for nested in [false, true] {
                let name = format!(
                    "std.fs.Intrinsic{index}{}",
                    if nested { "Result" } else { "Root" }
                );
                let mut alias = rust_type(&name, "type_alias");
                alias["alias_target"] = if nested {
                    json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"named","name":primitive},{"kind":"named","name":"std.io.Error"}]})
                } else {
                    json!({"kind":"named","name":primitive})
                };
                pack["shards"][0]["payload"]["types"]
                    .as_array_mut()
                    .unwrap()
                    .push(alias);
            }
        }
        activate_model_pack(&fixture, pack, "fixture.rust-opaque-receiver", "std");
        let analyzer = fixture.analyzer.analyzer();
        for (index, primitive) in [
            "u8",
            "usize",
            "bool",
            "core.primitive.i32",
            "std.primitive.f64",
        ]
        .into_iter()
        .enumerate()
        {
            for nested in [false, true] {
                let name = format!(
                    "std.fs.Intrinsic{index}{}",
                    if nested { "Result" } else { "Root" }
                );
                let expected = if nested {
                    TypeRef::Named {
                        name: "core.result.Result".into(),
                        arguments: vec![TypeRef::named(primitive), TypeRef::named("std.io.Error")],
                        nullable: false,
                    }
                } else {
                    TypeRef::named(primitive)
                };
                assert_eq!(
                    normalized_receiver_application(analyzer, TypeRef::named(&name)),
                    Some(expected),
                    "{name}"
                );
            }
        }
    }

    const MERGED_RECEIVER_SOURCE: &str = r#"
trait Returns { fn number(&self) -> u64; }
struct Trivial(u64);
struct Guard;
impl Drop for Guard { fn drop(&mut self) {} }
async fn capture_inert(_: u64) -> Guard { Guard }
async fn capture_drop(_: Guard) -> u64 { 0 }
fn local(_: u64) -> core::result::Result<bool, u64> { unimplemented!() }
fn unit() {}
fn probe(x: &dyn Returns) {
    x.number(); Trivial(1); capture_inert(1); capture_drop(Guard);
    local(1); local(); unit();
}
"#;

    fn merged_receiver_fixture(source: &str) -> AnalyzerFixture {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("lib.rs", source),
                (
                    "Cargo.toml",
                    "[package]\nname=\"merged-receiver\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[lib]\npath=\"lib.rs\"\n",
                ),
            ],
        );
        activate_model_pack(
            &fixture,
            opaque_receiver_pack(),
            "fixture.rust-opaque-receiver",
            "std",
        );
        fixture
    }

    #[test]
    #[hardwon("#12038: receiver merge must retain a dyn trait signature's result authority")]
    fn merged_trait_object_result_keeps_signature_authority() {
        let fixture = merged_receiver_fixture(MERGED_RECEIVER_SOURCE);
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let prepared = proof
            .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
            .unwrap();
        let start = MERGED_RECEIVER_SOURCE.rfind("x.number()").unwrap();
        let call = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + "x.number()".len())
            .unwrap();
        assert_eq!(
            proof.call_class(&prepared, call, PROOF_DEPTH),
            RustValueClass::Inert
        );
    }

    #[test]
    #[hardwon("#12038: receiver merge must retain an inert constructor's selected Drop inventory")]
    fn merged_inert_constructor_keeps_inventory_authority() {
        use crate::analyzer::semantic::{SemanticBudget, SemanticRequest};
        let source = "struct Trivial(u64); fn probe() { Trivial(1); }";
        let fixture = merged_receiver_fixture(source);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        crate::analyzer::rust::with_drop_inventory(&fixture.analyzer, &mut request, |inventory| {
            let mut proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
            proof.drop_inventory = Some(inventory);
            let prepared = proof
                .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
                .unwrap();
            let start = source.rfind("Trivial(1)").unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + "Trivial(1)".len())
                .unwrap();
            let actual =
                proof.completed_attempt(|| Some(proof.call_class(&prepared, call, PROOF_DEPTH)));
            assert_eq!(actual.into_value(), Some(RustValueClass::Inert));
        });
    }

    #[test]
    #[hardwon(
        "#12038: receiver merge must classify unpolled captures, never an async written Output"
    )]
    fn merged_async_capture_keeps_value_authority() {
        let fixture = merged_receiver_fixture(MERGED_RECEIVER_SOURCE);
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let prepared = proof
            .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
            .unwrap();
        for (spelling, expected) in [
            ("capture_inert(1)", RustValueClass::InertValue),
            ("capture_drop(Guard)", RustValueClass::Unknown),
        ] {
            let start = MERGED_RECEIVER_SOURCE.rfind(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            assert_eq!(
                proof.call_class(&prepared, call, PROOF_DEPTH),
                expected,
                "{spelling}"
            );
            assert!(
                proof
                    .modeled_receiver_type_bounded(&prepared, call, PROOF_DEPTH)
                    .is_none(),
                "unpolled async call has no Output receiver: {spelling}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#12038: the shared call-result route must check local arity before canonical receiver projection"
    )]
    fn merged_local_return_uses_checked_canonical_application() {
        let fixture = merged_receiver_fixture(MERGED_RECEIVER_SOURCE);
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let prepared = proof
            .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
            .unwrap();
        for (spelling, expected) in [
            (
                "local(1)",
                Some(TypeRef::Declared {
                    id: "type.fixture.core-result-result".into(),
                    arguments: vec![
                        TypeRef::named("core.primitive.bool"),
                        TypeRef::named("core.primitive.u64"),
                    ],
                    nullable: false,
                }),
            ),
            ("local()", None),
            (
                "unit()",
                Some(TypeRef::Tuple {
                    elements: Vec::new(),
                }),
            ),
        ] {
            let start = MERGED_RECEIVER_SOURCE.rfind(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            let actual = proof
                .completed_attempt(|| {
                    proof.modeled_receiver_type_bounded(&prepared, call, PROOF_DEPTH)
                })
                .into_value();
            assert_eq!(actual, expected, "{spelling}");
        }
    }

    #[test]
    #[hardwon("#12038: shared result typing rejected every nongeneric associated function owner")]
    fn selected_associated_return_preserves_concrete_owners_and_checks_arity() {
        let source = r#"
struct Factory;
impl Factory {
    fn make(_: u64) -> core::result::Result<bool, u64> { unimplemented!() }
    fn zero() -> core::result::Result<bool, u64> { unimplemented!() }
    async fn asynchronous() -> core::result::Result<bool, u64> { unimplemented!() }
}
struct Generic<T>(T);
impl<T> Generic<T> {
    fn make() -> core::result::Result<bool, u64> { unimplemented!() }
}
fn probe() { Factory::make(1); Factory::make(); Factory::make(1,2); Factory::zero(); Factory::asynchronous(); Generic::<u8>::make(); }
fn question() -> core::result::Result<(), u64> { let _ = Factory::zero()?; Ok(()) }
"#;
        let fixture = merged_receiver_fixture(source);
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let prepared = proof
            .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
            .unwrap();
        for (spelling, known) in [
            ("Factory::make(1)", true),
            ("Factory::make()", false),
            ("Factory::make(1,2)", false),
            ("Factory::zero()", true),
            ("Factory::asynchronous()", false),
            ("Generic::<u8>::make()", false),
        ] {
            let start = source.rfind(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            let attempt = proof.completed_attempt(|| {
                proof.selected_call_result_type(&prepared, call, PROOF_DEPTH)
            });
            let result = attempt.into_value();
            assert_eq!(result.is_some(), known, "{spelling}: {result:?}");
            if let Some(result) = result {
                assert_eq!(
                    result,
                    TypeRef::Declared {
                        id: "type.fixture.core-result-result".into(),
                        arguments: vec![
                            TypeRef::named("core.primitive.bool"),
                            TypeRef::named("core.primitive.u64")
                        ],
                        nullable: false,
                    },
                    "{spelling}"
                );
            }
        }
        let spelling = "Factory::zero()?";
        let start = source.rfind(spelling).unwrap();
        let question = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + spelling.len())
            .unwrap();
        assert_eq!(
            proof
                .completed_attempt(|| proof.modeled_receiver_type_bounded(
                    &prepared,
                    question,
                    PROOF_DEPTH
                ))
                .into_value(),
            Some(TypeRef::named("core.primitive.bool")),
            "the associated Result remains a recognized ? operand"
        );
    }

    #[test]
    #[hardwon("#12038: qualified instance calls lost their concrete return application")]
    fn selected_ufcs_self_preserves_result_and_refuses_wrong_owner() {
        let source = r#"
struct Factory;
struct Other;
impl Factory {
    fn borrowed(&self) -> core::result::Result<bool, u64> { unimplemented!() }
}
fn probe() { Factory::borrowed(&Factory); Factory::borrowed(&Other); }
"#;
        let fixture = merged_receiver_fixture(source);
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let prepared = proof
            .source(&ProjectFile::new(fixture.project_root(), "lib.rs"))
            .unwrap();
        let spelling = "Factory::borrowed(&Factory)";
        let start = source.rfind(spelling).unwrap();
        let call = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + spelling.len())
            .unwrap();
        let unit = proof
            .callee_definition(&prepared, call)
            .expect("BASE callee_definition must resolve the UFCS instance method");
        assert!(unit.is_function());
        let declared_source = proof.source(unit.source()).unwrap();
        let declaration = proof.declaration(&declared_source, &unit).unwrap();
        assert_eq!(declaration.kind(), "function_item");
        assert!(!super::super::semantic::function_is_async(declaration));
        assert!(!item_or_enclosing_item_attributed(declaration));
        let mut parent = Some(declaration);
        while let Some(node) = parent {
            assert!(node.child_by_field_name("type_parameters").is_none());
            parent = node.parent();
        }
        let overlay = proof.analyzer.semantic_model_overlay().unwrap();
        let active = proof.analyzer.active_semantic_models().unwrap();
        let mut applicability = super::super::trait_applicability::ModelApplicability::new(
            proof.analyzer,
            proof.rust,
            &overlay,
            &active,
            &proof.resolver,
        );
        let returned = applicability
            .receiver_type(
                &declared_source.file,
                declared_source.text(),
                declaration.child_by_field_name("return_type").unwrap(),
            )
            .expect("BASE shared signature path must retain the result application");
        assert!(!type_ref_mentions_type_parameter(&returned));

        let actual = proof
            .completed_attempt(|| proof.selected_call_result_type(&prepared, call, PROOF_DEPTH))
            .into_value();
        assert_eq!(
            actual,
            Some(returned),
            "nongeneric UFCS must retain master's result signature"
        );
        let spelling = "Factory::borrowed(&Other)";
        let start = source.rfind(spelling).unwrap();
        let call = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + spelling.len())
            .unwrap();
        assert_eq!(
            proof
                .completed_attempt(|| proof.selected_call_result_type(&prepared, call, PROOF_DEPTH))
                .into_value(),
            None,
            "the explicit self argument must match the selected impl owner"
        );
    }

    #[test]
    fn selected_local_call_receiver_keeps_concrete_return_and_refuses_generic_async() {
        let source = r#"
fn concrete() -> core::result::Result<bool, u64> { unimplemented!() }
fn unit_error() -> core::result::Result<bool, ()> { unimplemented!() }
fn generic<T>() -> core::result::Result<bool, u64> { unimplemented!() }
async fn asynchronous() -> core::result::Result<bool, u64> { unimplemented!() }
fn probe() { concrete(); unit_error(); generic::<u8>(); asynchronous(); }
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("lib.rs", source),
                (
                    "Cargo.toml",
                    "[package]\nname=\"receiver-proof\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[lib]\npath=\"lib.rs\"\n",
                ),
            ],
        );
        activate_model_pack(
            &fixture,
            opaque_receiver_pack(),
            "fixture.rust-opaque-receiver",
            "std",
        );
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let prepared = proof.source(&file).unwrap();
        for (spelling, known) in [
            ("concrete()", true),
            ("unit_error()", true),
            ("generic::<u8>()", false),
            ("asynchronous()", false),
        ] {
            let start = source.rfind(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            let result = proof.selected_call_receiver_type(&prepared, call);
            assert_eq!(result.is_some(), known, "{spelling}: {result:?}");
            if let Some(result) = result {
                let normalized =
                    normalized_receiver_application(fixture.analyzer.analyzer(), result).unwrap();
                let arguments = match normalized {
                    TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                        arguments
                    }
                    other => panic!("expected a normalized Result application: {other:?}"),
                };
                assert_eq!(arguments.len(), 2);
                if spelling == "unit_error()" {
                    assert_eq!(
                        arguments[1],
                        TypeRef::Tuple {
                            elements: Vec::new()
                        }
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon("#12038: malformed local calls supplied unproven concrete Result applications")]
    fn selected_local_return_requires_matching_complete_call_arity() {
        let source = r#"
fn one(_: i32) -> core::result::Result<bool, u64> { unimplemented!() }
fn zero() -> core::result::Result<bool, u64> { unimplemented!() }
fn attributed(#[cfg(feature="optional")] _: i32) -> core::result::Result<bool, u64> { unimplemented!() }
fn probe() { one(1); one(/* comment */1); one(1,); one(); one(1,2); zero(); zero(1); one::<u8>(1); attributed(1); one(#[cfg(feature="optional")] 1); }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_model_pack(
            &fixture,
            opaque_receiver_pack(),
            "fixture.rust-opaque-receiver",
            "std",
        );
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let prepared = proof.source(&file).unwrap();
        for (spelling, known) in [
            ("one(1)", true),
            ("one(/* comment */1)", true),
            ("one(1,)", true),
            ("one()", false),
            ("one(1,2)", false),
            ("zero()", true),
            ("zero(1)", false),
            ("one::<u8>(1)", false),
            ("attributed(1)", false),
            ("one(#[cfg(feature=\"optional\")] 1)", false),
        ] {
            let start = source.rfind(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            let actual = proof
                .completed_attempt(|| proof.selected_call_receiver_type(&prepared, call))
                .into_value();
            assert_eq!(actual.is_some(), known, "{spelling}: {actual:?}");
            if !known {
                assert!(
                    proof
                        .completed_attempt(|| proof.modeled_receiver_type_bounded(
                            &prepared,
                            call,
                            PROOF_DEPTH
                        ))
                        .into_value()
                        .is_none(),
                    "invalid call must not gain a concrete application through another route: {spelling}"
                );
            }
        }
    }

    #[test]
    fn selected_return_workspace_argument_requires_unique_direct_nongeneric_nominal() {
        let source = r#"
struct Converted;
mod one { pub struct Ambiguous; }
mod two { pub struct Ambiguous; }
use one::Ambiguous;
use two::Ambiguous;
fn concrete() -> core::result::Result<bool, Converted> { unimplemented!() }
fn unresolved() -> core::result::Result<bool, Missing> { unimplemented!() }
fn ambiguous() -> core::result::Result<bool, Ambiguous> { unimplemented!() }
fn generic<T>() -> core::result::Result<T, Converted> { unimplemented!() }
fn nested() -> core::result::Result<std::vec::Vec<Converted>, Converted> { unimplemented!() }
fn probe() { concrete(); unresolved(); ambiguous(); generic::<bool>(); nested(); }
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("lib.rs", source),
                (
                    "Cargo.toml",
                    "[package]\nname=\"receiver-proof\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[lib]\npath=\"lib.rs\"\n",
                ),
            ],
        );
        activate_model_pack(
            &fixture,
            opaque_receiver_pack(),
            "fixture.rust-opaque-receiver",
            "std",
        );
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let prepared = proof.source(&file).unwrap();
        for (spelling, known) in [
            ("concrete()", true),
            ("unresolved()", false),
            ("ambiguous()", false),
            ("generic::<bool>()", false),
            ("nested()", false),
        ] {
            let start = source.rfind(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            let result = proof
                .completed_attempt(|| proof.selected_call_receiver_type(&prepared, call))
                .into_value();
            assert_eq!(result.is_some(), known, "{spelling}: {result:?}");
        }
    }

    #[test]
    fn alias_chain_primitives_keep_intrinsic_authority_before_targetless_encoding() {
        use serde_json::json;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "fn probe() {}")]);
        let mut pack = opaque_receiver_pack();
        let types = pack["shards"][0]["payload"]["types"]
            .as_array_mut()
            .unwrap();
        types.push(rust_type("std.primitive", "module"));
        types.push(rust_type("core.primitive", "module"));
        let primitive = rust_type("std.primitive.str", "type_alias");
        let primitive_id = primitive["id"].as_str().unwrap().to_owned();
        types.push(primitive);
        types.push(rust_type("core.primitive.bool", "type_alias"));
        for (name, target) in [
            (
                "std.fs.TextAlias",
                json!({"kind":"named","name":"std.primitive.str"}),
            ),
            (
                "std.fs.DeclaredTextAlias",
                json!({"kind":"declared","id":primitive_id}),
            ),
            (
                "std.fs.MissingChain",
                json!({"kind":"named","name":"std.fs.MissingPayload"}),
            ),
        ] {
            let mut alias = rust_type(name, "type_alias");
            alias["alias_target"] = target;
            types.push(alias);
        }
        activate_model_pack(&fixture, pack, "fixture.rust-opaque-receiver", "std");
        let analyzer = fixture.analyzer.analyzer();
        assert_eq!(
            normalized_receiver_application(analyzer, TypeRef::named("std.fs.TextAlias")),
            Some(TypeRef::named("std.primitive.str"))
        );
        assert_eq!(
            normalized_receiver_application(analyzer, TypeRef::named("std.fs.DeclaredTextAlias")),
            Some(TypeRef::Declared {
                id: primitive_id,
                arguments: Vec::new(),
                nullable: false
            })
        );
        let application: TypeRef = serde_json::from_value(json!({"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"named","name":"core.primitive.bool"}]})).unwrap();
        let expected: TypeRef = serde_json::from_value(json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"named","name":"core.primitive.bool"},{"kind":"named","name":"std.io.Error"}]})).unwrap();
        assert_eq!(
            normalized_receiver_application(analyzer, application),
            Some(expected)
        );
        let overlay = analyzer.semantic_model_overlay().unwrap();
        let active = analyzer.active_semantic_models().unwrap();
        let symbol = overlay
            .symbols_named_in_family(
                "std.fs.MissingChain",
                "rust",
                SemanticModelNamespace::TypeOrModule,
            )
            .unique()
            .unwrap();
        let mut cursor = AliasTypeCursor::new(
            TypeRef::named("std.fs.MissingChain"),
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::ModelProvider::from(
                &symbol.provenance,
            ),
        );
        let failure = normalize_std_model_type(
            &overlay,
            &active,
            &mut cursor,
            &mut AliasCursorContext::default(),
            &CancellationToken::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(failure.reason, brokk_bifrost_analysis::analyzer::semantic_model::alias_resolution::AliasExpansionRefusal::AliasMissingTarget);
    }

    fn opaque_receiver_pack() -> serde_json::Value {
        use serde_json::json;
        let mut types = [
            "std",
            "std.fs",
            "std.io",
            "std.vec",
            "core",
            "core.io",
            "core.io.error",
            "core.result",
        ]
        .into_iter()
        .map(|n| rust_type(n, "module"))
        .collect::<Vec<_>>();
        let mut result = rust_type("core.result.Result", "enum");
        result["type_parameters"] = json!(["T", "E"]);
        types.push(result);
        for name in ["std.vec.Vec", "std.fs.Partial"] {
            let mut fact = rust_type(name, "struct");
            fact["type_parameters"] = json!(["T"]);
            types.push(fact);
        }
        types.push(rust_type("std.io.Error", "struct"));
        let mut io = rust_type("core.io.error.Result", "type_alias");
        io["aliases"] = json!(["std.io.Result"]);
        io["type_parameters"] = json!(["T"]);
        io["alias_target"] = json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"type_parameter","name":"T"},{"kind":"named","name":"std.io.Error"}]});
        types.push(io);
        let mut root = rust_type("std.fs.UnknownHead", "type_alias");
        root["alias_target"] = json!({"kind":"unknown"});
        types.push(root);
        types.push(rust_type("std.fs.MissingPayload", "type_alias"));
        let mut nested = rust_type("std.fs.BrokenNested", "type_alias");
        nested["alias_target"] = json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"named","name":"std.fs.MissingPayload"},{"kind":"named","name":"std.io.Error"}]});
        types.push(nested);
        let method = |owner: &str, name: &str, returned: serde_json::Value| json!({"id":format!("member.{name}"),"owner":format!("type.fixture.{}",owner.replace('.',"-").to_ascii_lowercase()),"name":name,"member_kind":"method","visibility":"public","callable_family_complete":true,"receiver":{"pointer":false},"self_form":{"kind":"value"},"signature":{"parameters":[],"returns":returned},"locator":{"kind":"artifact","path":"library/std/src/lib.rs","symbol":format!("{owner}.{name}")}});
        // Partial::only is the erased declaration of a specialized inherent
        // impl (for example Partial<u8>); the current pack cannot retain its
        // self pattern. A unique erased family must not be a blanket proof.
        json!({"schema_version":32,"pack_id":"fixture.rust-opaque-receiver","version":"1.0.0","producer":{"name":"rust-type-proof-test","version":"1.0.0"},"language":"rust","ecosystem":"cargo","compatibility":{"toolchains":[]},"provenance":{"source":"synthetic opaque receiver and erased specialized impl"},"license":"NOASSERTION","completeness":"complete","safety":{"generated_code_only":false,"review_required":false},"shards":[{"id":"declarations.opaque","activation":[{}],"payload":{"kind":"declaration_facts","types":types,"members":[method("core.result.Result","unwrap",json!({"kind":"type_parameter","name":"T"})),method("std.vec.Vec","len",json!({"kind":"named","name":"usize"})),method("std.fs.Partial","only",json!({"kind":"named","name":"usize"}))],"relations":[]}}]})
    }

    #[test]
    #[hardwon("#12038: a targetless alias own-member shortcut ignored the explicit UFCS trait")]
    fn targetless_alias_ufcs_respects_named_trait_with_or_without_own_member() {
        use crate::analyzer::rust::modeled_members::{UfcsTrait, select};
        use serde_json::json;
        let source =
            "fn probe(x: std::fs::Alias) { <std::fs::Alias as std::fs::Picked>::only(x); }";
        for own_member in [false, true] {
            let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
            let mut pack = opaque_receiver_pack();
            let declarations = &mut pack["shards"][0]["payload"];
            let types = declarations["types"].as_array_mut().unwrap();
            let mut alias = rust_type("std.fs.Alias", "type_alias");
            alias["hierarchy"] = json!([{"hierarchy_kind":"implements", "target":{"kind":"named","name":"std.fs.Picked"}}]);
            let alias_id = alias["id"].as_str().unwrap().to_owned();
            let trait_type = rust_type("std.fs.Picked", "trait");
            let trait_id = trait_type["id"].as_str().unwrap().to_owned();
            types.extend([alias, trait_type]);
            let members = declarations["members"].as_array_mut().unwrap();
            let member = |id: &str, owner: &str| json!({"id":id,"owner":owner,"name":"only","member_kind":"method","visibility":"public","callable_family_complete":true,"receiver":{"pointer":false},"self_form":{"kind":"value"},"signature":{"parameters":[]},"locator":{"kind":"artifact","path":"test-only/alias.rs","symbol":id}});
            members.push(member("test.member.picked.only", &trait_id));
            if own_member {
                members.push(member("test.member.alias.only", &alias_id));
            }
            activate_model_pack(&fixture, pack, "fixture.rust-opaque-receiver", "std");
            let analyzer = fixture.analyzer.analyzer();
            let file = ProjectFile::new(fixture.project_root(), "lib.rs");
            let cancellation = CancellationToken::default();
            let factory =
                crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
                    analyzer,
                    &cancellation,
                )
                .unwrap();
            let mut operation = match factory.open(&cancellation).unwrap() {
                brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
                _ => panic!("selected fixture operation must open"),
            };
            let start = source.find("::only").unwrap() + 2;
            let site = ResolvedReferenceSite {
                path: "only".into(),
                text: "only".into(),
                range: Range {
                    start_byte: start,
                    end_byte: start + 4,
                    start_line: 1,
                    end_line: 1,
                },
                focus_start_byte: start,
                focus_end_byte: start + 4,
            };
            for (named, expected) in [
                ("std.fs.Picked", Some("std.fs.Picked")),
                ("std.fs.Other", None),
            ] {
                let named_trait = UfcsTrait {
                    owner: named.into(),
                    arguments: None,
                };
                let selected = select(
                    analyzer,
                    &file,
                    source,
                    &site,
                    "std.fs.Alias",
                    true,
                    0,
                    &factory,
                    &mut operation,
                    Some(&named_trait),
                    None,
                    Some(&cancellation),
                );
                assert_eq!(
                    selected.as_ref().map(|member| member.owner.as_str()),
                    expected,
                    "own member={own_member}, named trait={named}"
                );
            }
        }
    }

    fn select_opaque_application(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        call_spelling: &str,
        member: &str,
        owner: &str,
        application: &TypeRef,
    ) -> Option<crate::analyzer::rust::modeled_members::SelectedMember> {
        let cancellation = CancellationToken::default();
        let factory = crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
            analyzer,
            &cancellation,
        )?;
        let mut operation=match factory.open(&cancellation).ok()? {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(operation)=>*operation,
            _=>return None,
        };
        let start = source.find(call_spelling).unwrap() + call_spelling.len() - member.len();
        let site = ResolvedReferenceSite {
            path: member.into(),
            text: member.into(),
            range: Range {
                start_byte: start,
                end_byte: start + member.len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start,
            focus_end_byte: start + member.len(),
        };
        crate::analyzer::rust::modeled_members::select(
            analyzer,
            file,
            source,
            &site,
            owner,
            true,
            0,
            &factory,
            &mut operation,
            None,
            Some(application),
            Some(&cancellation),
        )
    }

    #[test]
    #[hardwon("#12038: strict alias-head refusal erased opaque payloads and nested source binders")]
    fn alias_receiver_opaque_arguments_preserve_shape_without_impl_authority() {
        use serde_json::json;
        let source = "struct MyStruct; fn probe<T>(x: std::io::Result<MyStruct>, b: std::io::Result<bool>, v: std::vec::Vec<std::io::Result<T>>, p: std::fs::Partial<MyStruct>) { x.unwrap(); b.unwrap(); v.len(); p.only(); }";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_model_pack(
            &fixture,
            opaque_receiver_pack(),
            "fixture.rust-opaque-receiver",
            "std",
        );
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let typed = |v| serde_json::from_value::<TypeRef>(v).unwrap();
        let io = typed(
            json!({"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"unknown"}]}),
        );
        let canonical = typed(
            json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"unknown"},{"kind":"named","name":"std.io.Error"}]}),
        );
        assert_eq!(
            normalized_receiver_application(analyzer, io.clone()),
            Some(canonical)
        );
        assert!(
            normalized_receiver_application(analyzer, TypeRef::Unknown).is_none(),
            "opaque payload supplies no type facts"
        );
        assert!(
            select_opaque_application(
                analyzer,
                &file,
                source,
                "x.unwrap",
                "unwrap",
                "core.io.error.Result",
                &io
            )
            .is_none(),
            "missing impl facts cannot select an opaque instantiation"
        );
        let known = typed(
            json!({"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"named","name":"bool"}]}),
        );
        assert_eq!(
            select_opaque_application(
                analyzer,
                &file,
                source,
                "b.unwrap",
                "unwrap",
                "core.io.error.Result",
                &known
            )
            .expect("known arguments retain their existing selection")
            .owner,
            "core.result.Result"
        );
        let nested = typed(
            json!({"kind":"named","name":"std.vec.Vec","arguments":[{"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"type_parameter","name":"T"}]}]}),
        );
        let expected = typed(
            json!({"kind":"named","name":"std.vec.Vec","arguments":[{"kind":"named","name":"core.result.Result","arguments":[{"kind":"type_parameter","name":"T"},{"kind":"named","name":"std.io.Error"}]}]}),
        );
        assert_eq!(
            normalized_receiver_application(analyzer, nested.clone()),
            Some(expected),
            "nested lexical T survives normalization"
        );
        assert!(
            select_opaque_application(
                analyzer,
                &file,
                source,
                "v.len",
                "len",
                "std.vec.Vec",
                &nested
            )
            .is_none()
        );
        let partial =
            typed(json!({"kind":"named","name":"std.fs.Partial","arguments":[{"kind":"unknown"}]}));
        assert!(
            select_opaque_application(
                analyzer,
                &file,
                source,
                "p.only",
                "only",
                "std.fs.Partial",
                &partial
            )
            .is_none(),
            "an erased partial-instantiation impl is not argument independent"
        );
        let attempt = completed_proof(analyzer, None, || {
            select_opaque_application(
                analyzer,
                &file,
                source,
                "p.only",
                "only",
                "std.fs.Partial",
                &partial,
            )
        });
        assert!(
            matches!(
                attempt,
                RustProofAttempt::Incomplete {
                    value: None,
                    reason: "external_receiver_type_arguments_unknown",
                    cause: None
                }
            ),
            "missing impl evidence is an incomplete selection, not a proven absence"
        );
        assert!(
            normalized_receiver_application(analyzer, TypeRef::named("std.fs.UnknownHead"))
                .is_none()
        );
        assert!(
            normalized_receiver_application(analyzer, TypeRef::named("std.fs.BrokenNested"))
                .is_none(),
            "a refused nested alias stays fatal"
        );
    }

    #[test]
    #[hardwon("#12038: an earlier reference trait must not become a later inherent member proof")]
    fn alias_receiver_reference_rival_refuses_inherent_selection() {
        use serde_json::json;
        let source = r#"trait Rival { fn unwrap(self) -> u8; fn expect(self, message: &str) -> u8; } impl<T> Rival for &std::io::Result<T> { fn unwrap(self) -> u8 { 0 } fn expect(self, message: &str) -> u8 { 0 } } fn probe(x: &std::io::Result<bool>) { x.unwrap(); x.expect("message"); }"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_model_pack(
            &fixture,
            opaque_receiver_pack(),
            "fixture.rust-opaque-receiver",
            "std",
        );
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let reference:TypeRef=serde_json::from_value(json!({"kind":"by_ref","element":{"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"named","name":"bool"}]}})).unwrap();
        assert!(matches!(
            normalized_receiver_application(analyzer, reference.clone()),
            Some(TypeRef::ByRef { .. })
        ));
        assert!(
            select_opaque_application(
                analyzer,
                &file,
                source,
                "x.unwrap",
                "unwrap",
                "core.io.error.Result",
                &reference
            )
            .is_none()
        );
        let proof = RustTypeProof::new(analyzer).unwrap();
        let prepared = proof.source(&file).unwrap();
        for spelling in ["x.unwrap()", "x.expect(\"message\")"] {
            let start = source.find(spelling).unwrap();
            let call = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            assert_eq!(
                proof.modeled_receiver_type(&file, call),
                None,
                "the rival returns u8, so the wrapper's bool payload is not the call result: {spelling}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#12038: io Result alias receivers queried the alias's empty member set and lost their payload binding"
    )]
    fn modeled_alias_receiver_selects_canonical_unwrap_and_payload() {
        use serde_json::json;
        for (case, target, parameters, nested, accepted) in [
            (
                "io",
                Some(
                    json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"type_parameter","name":"T"},{"kind":"named","name":"std.io.Error"}]}),
                ),
                json!(["T"]),
                false,
                true,
            ),
            (
                "nested",
                Some(
                    json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"type_parameter","name":"T"},{"kind":"named","name":"std.io.Error"}]}),
                ),
                json!(["T"]),
                true,
                true,
            ),
            (
                "intrinsic-child",
                Some(
                    json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"named","name":"bool"},{"kind":"type_parameter","name":"T"}]}),
                ),
                json!(["T"]),
                false,
                true,
            ),
            ("missing", None, json!(["T"]), false, false),
            (
                "cycle",
                Some(
                    json!({"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"type_parameter","name":"T"}]}),
                ),
                json!(["T"]),
                false,
                false,
            ),
            (
                "arity",
                Some(json!({"kind":"named","name":"bool"})),
                json!(["T", "E"]),
                false,
                false,
            ),
            (
                "unresolvable",
                Some(json!({"kind":"named","name":"missing.Target"})),
                json!(["T"]),
                false,
                false,
            ),
            (
                "unresolvable-child",
                Some(
                    json!({"kind":"named","name":"core.result.Result","arguments":[{"kind":"named","name":"missing.Target"},{"kind":"named","name":"std.io.Error"}]}),
                ),
                json!(["T"]),
                false,
                false,
            ),
        ] {
            let source = "fn run() { std::fs::exists(\"file\").unwrap(); }";
            let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
            let mut result = rust_type("core.result.Result", "enum");
            result["type_parameters"] = json!(["T", "E"]);
            let mut alias = rust_type("core.io.error.Result", "type_alias");
            alias["type_parameters"] = parameters;
            if let Some(target) = target {
                alias["alias_target"] = target;
            }
            let mut outer = rust_type("std.fs.Outer", "type_alias");
            outer["type_parameters"] = json!(["V"]);
            outer["alias_target"] = json!({"kind":"named","name":"core.io.error.Result","arguments":[{"kind":"type_parameter","name":"V"}]});
            let shape_target = json!({"kind":"tuple","elements":[{"kind":"function","parameters":[{"name":"input","type":{"kind":"type_parameter","name":"T"}}],"result":{"kind":"type_parameter","name":"T"}},{"kind":"by_ref","element":{"kind":"type_parameter","name":"T"}}]});
            let mut shape = rust_type("std.fs.Shape", "type_alias");
            shape["type_parameters"] = json!(["T"]);
            shape["alias_target"] = shape_target;
            let pack = json!({
                "schema_version":32,"pack_id":"fixture.rust-alias-receiver","version":"1.0.0",
                "producer":{"name":"rust-type-proof-test","version":"1.0.0"},"language":"rust","ecosystem":"cargo",
                "compatibility":{"toolchains":[]},"provenance":{"source":"synthetic alias receiver regression"},"license":"NOASSERTION","completeness":"complete",
                "safety":{"generated_code_only":false,"review_required":false},
                "shards":[{"id":"declarations.alias-receiver","activation":[{}],"payload":{
                    "kind":"declaration_facts","types":[rust_type("std","module"),rust_type("std.fs","module"),rust_type("std.io","module"),rust_type("std.io.Error","struct"),rust_type("core","module"),rust_type("core.io","module"),rust_type("core.io.error","module"),rust_type("core.result","module"),result,alias,outer,shape],
                    "members":[
                        {"id":"member.fixture.exists","owner":"type.fixture.std-fs","name":"exists","member_kind":"function","visibility":"public","is_static":true,"callable_family_complete":true,
                         "signature":{"parameters":[{"name":"path","type":{"kind":"named","name":"str"}}],"returns":{"kind":"named","name":if nested {"std.fs.Outer"} else {"core.io.error.Result"},"arguments":[{"kind":"named","name":"bool"}]}},
                         "locator":{"kind":"artifact","path":"library/std/src/lib.rs","symbol":"std.fs.exists"}},
                        {"id":"member.fixture.unwrap","owner":"type.fixture.core-result-result","name":"unwrap","member_kind":"method","visibility":"public","callable_family_complete":true,"receiver":{"pointer":false},"self_form":{"kind":"value"},
                         "signature":{"parameters":[],"returns":{"kind":"type_parameter","name":"T"}},
                         "locator":{"kind":"artifact","path":"library/core/src/result.rs","symbol":"core.result.Result.unwrap"}}
                    ],"relations":[]
                }}]
            });
            activate_model_pack(&fixture, pack, "fixture.rust-alias-receiver", "std");
            let analyzer = fixture.analyzer.analyzer();
            let file = ProjectFile::new(fixture.project_root(), "lib.rs");
            let proof = RustTypeProof::new(analyzer).unwrap();
            let prepared = proof.source(&file).unwrap();
            let start = source.find("unwrap").unwrap();
            let site = ResolvedReferenceSite {
                path: "unwrap".into(),
                text: "unwrap".into(),
                range: Range {
                    start_byte: start,
                    end_byte: start + 6,
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: start,
                focus_end_byte: start + 6,
            };
            let selected = selected_external_call(analyzer, &file, source, prepared.tree(), &site);
            if case == "unresolvable-child" {
                use brokk_bifrost_analysis::analyzer::semantic_model::alias_resolution::{
                    AliasExpansionRefusal, materialize_alias_application,
                };
                use brokk_bifrost_analysis::analyzer::semantic_model::overlay::ModelProvider;
                let overlay = analyzer.semantic_model_overlay().unwrap();
                let active = analyzer.active_semantic_models().unwrap();
                let symbol = overlay
                    .symbols_named_in_family(
                        "core.io.error.Result",
                        "rust",
                        SemanticModelNamespace::TypeOrModule,
                    )
                    .unique()
                    .unwrap();
                let result = materialize_alias_application(
                    &overlay,
                    &active,
                    "rust",
                    AliasTypeCursor::new(
                        TypeRef::Named {
                            name: "core.io.error.Result".into(),
                            arguments: vec![TypeRef::named("bool")],
                            nullable: false,
                        },
                        ModelProvider::from(&symbol.provenance),
                    ),
                    |ty| is_intrinsic_primitive_type(&overlay, ty),
                    &CancellationToken::default(),
                )
                .unwrap();
                assert_eq!(
                    result.unwrap_err().reason,
                    AliasExpansionRefusal::AliasUnresolvableTarget
                );
            }
            if accepted {
                let (_, identity) =
                    selected.unwrap_or_else(|| panic!("canonical selected unwrap: {case}"));
                assert_eq!(identity.owner_fqn(), "core.result.Result", "{case}");
                assert_eq!(identity.member(), "unwrap");
                let shape = TypeRef::Named {
                    name: "std.fs.Shape".into(),
                    arguments: vec![TypeRef::named("bool")],
                    nullable: false,
                };
                let expected: TypeRef = serde_json::from_value(json!({"kind":"tuple","elements":[{"kind":"function","parameters":[{"name":"input","type":{"kind":"named","name":"bool"}}],"result":{"kind":"named","name":"bool"}},{"kind":"by_ref","element":{"kind":"named","name":"bool"}}]})).unwrap();
                assert_eq!(
                    normalized_receiver_application(analyzer, shape),
                    Some(expected),
                    "scoped tuple/function/reference target: {case}"
                );

                let call = prepared
                    .tree()
                    .root_node()
                    .named_descendant_for_byte_range(start, start + 6)
                    .unwrap();
                let call = std::iter::successors(Some(call), |n| n.parent())
                    .find(|n| n.kind() == "call_expression")
                    .unwrap();
                assert_eq!(
                    proof.modeled_receiver_type(&file, call),
                    Some(TypeRef::named("bool")),
                    "canonical payload: {case}"
                );
            } else {
                assert!(
                    selected.is_none(),
                    "refused alias selected a member: {case}"
                );
                let expected = match case {
                    "missing" => "model_alias_missing_target",
                    "cycle" => "model_alias_cycle",
                    "arity" => "model_alias_arity_mismatch",
                    "unresolvable" | "unresolvable-child" => "model_alias_unresolvable_target",
                    _ => unreachable!(),
                };
                let (attempt, receipt) = QueryReadReceipt::capture(analyzer, || {
                    completed_proof(analyzer, None, || {
                        normalized_receiver_application(
                            analyzer,
                            TypeRef::Named {
                                name: "core.io.error.Result".into(),
                                arguments: vec![TypeRef::named("bool")],
                                nullable: false,
                            },
                        )
                    })
                });
                assert!(
                    matches!(attempt, RustProofAttempt::Incomplete { value: None, reason, cause: None } if reason == expected),
                    "{case}: {attempt:?}"
                );
                assert!(
                    receipt.incomplete_reasons().contains(
                        &brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                            reason: expected,
                            cause: None
                        }
                    ),
                    "{case}: refused expansion must remain in the receipt"
                );
            }
        }
    }

    #[test]
    fn modeled_path_constructor_proves_join_receiver_owner() {
        let source = "use std::path::Path;\n\nfn run(value: &str) {\n    Path::new(\"/srv\").join(value);\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let pack = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-path-owner",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-path-owner",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.path", "module"),
                        rust_type("std.path.Path", "struct"),
                        rust_type("std.path.PathBuf", "struct")
                    ],
                    "members": [rust_path_constructor(), rust_path_method()],
                    "relations": []
                }
            }]
        });
        activate_model_pack(&fixture, pack, "fixture.rust-path-owner", "std");
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let method_start = source.find("join").expect("fixture contains join");
        let (owner, arity) = rust_method_receiver_owner(
            analyzer,
            &file,
            source,
            method_start..method_start + "join".len(),
        )
        .expect("modeled Path::new return proves the join receiver owner");
        assert_eq!(owner.key(), "std.path.Path");
        assert_eq!(arity, 1);
    }

    #[test]
    fn reviewed_inert_fact_is_refused_until_scope_admission_is_integrated() {
        let source = Arc::<str>::from("fn run() {}\n");
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
        let mut widget = rust_type("widget.Widget", "struct");
        widget["value_semantics"] = serde_json::json!({
            "drop_glue":"inert",
            "drop_review": {
                "scope": {"kind":"cargo", "package":"widget", "version":"1.0.0", "source_sha256":"a".repeat(64), "enabled_features":[], "target":"x86_64-unknown-linux-gnu", "cfgs":[]},
                "review": {"source":"test-only scope fixture", "revision":"fixture-v1", "source_digests":["a".repeat(64)]}
            }
        });
        let pack = serde_json::json!({
            "schema_version":31, "pack_id":"fixture.reviewed-inert", "version":"1.0.0",
            "producer":{"name":"test", "version":"1.0.0"}, "language":"rust", "ecosystem":"cargo",
            "compatibility":{"toolchains":[]}, "provenance":{"source":"test-only review scope"},
            "license":"NOASSERTION", "completeness":"complete",
            "safety":{"generated_code_only":false,"review_required":false},
            "shards":[{"id":"fixture.declarations", "activation":[{}], "payload":{"kind":"declaration_facts", "types":[rust_type("widget","module"),widget], "members":[], "relations":[]}}]
        });
        activate_model_pack(&fixture, pack, "fixture.reviewed-inert", "widget");
        let analyzer = fixture.analyzer.analyzer();
        let symbol = analyzer
            .semantic_model_overlay_read()
            .published()
            .unwrap()
            .symbols_named_in_family(
                "widget.Widget",
                "rust",
                SemanticModelNamespace::TypeOrModule,
            )
            .unique()
            .unwrap();
        let proof = RustTypeProof::new(analyzer).unwrap();
        let attempt = completed_proof(analyzer, None, || {
            proof.modeled_inert_drop_glue_owner(&symbol)
        });
        assert!(
            matches!(
                attempt,
                RustProofAttempt::Incomplete {
                    value: None,
                    reason: "drop_review_scope_admission_pending",
                    ..
                }
            ),
            "review restrictions must not be ignored: {attempt:?}"
        );
    }

    #[test]
    #[hardwon(
        "#10879: step 0b merge found inventory Ok(None) mapped to a deterministic not_absent"
    )]
    fn cancelled_drop_inventory_records_an_operational_stop() {
        use crate::analyzer::semantic::{SemanticBudget, SemanticRequest, StableDigest};
        use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
        use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
        use brokk_bifrost_analysis::analyzer::store::rust_drop_inventory::RustDropInventorySubject;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "struct Local;")]);
        let store =
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let memo =
            crate::analyzer::rust::semantic::drop_inventory::RustDropInventoryMemo::default();
        let subject = RustDropInventorySubject {
            owning_unit: StableDigest::from_array([1; 32]),
            module_path: "crate".into(),
            identity_digest: StableDigest::from_array([2; 32]),
            config_digest: StableDigest::from_array([3; 32]),
        };
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut budget = SemanticBudget::default();
        let (attempt, receipt) = QueryReadReceipt::capture(fixture.analyzer.analyzer(), || {
            completed_proof(fixture.analyzer.analyzer(), None, || {
                let answer = memo
                    .retained_answer(&store, &Default::default(), &subject, &cancellation, || {
                        panic!("cancelled scan must not read a row")
                    })
                    .unwrap();
                let cause = answer.expect_err("cancelled inventory carries its stop cause");
                assert_eq!(cause, DerivationExecutionCause::Cancelled);
                Some(crate::analyzer::rust::drop_inventory_answer_is_absent(
                    &fixture.analyzer,
                    Ok(crate::analyzer::rust::semantic::RustDropInventoryProof::Stopped(cause)),
                    &SemanticRequest::new(&mut budget, &cancellation),
                ))
            })
        });
        assert_eq!(attempt.into_value(), Some(false));
        assert!(
            receipt
                .incomplete_reasons()
                .contains(&QueryReadIncomplete::ProofStopped {
                    reason: "drop_inventory_unavailable",
                    cause: Some(DerivationExecutionCause::Cancelled),
                }),
            "{:?}",
            receipt.incomplete_reasons()
        );
        assert!(
            !receipt
                .incomplete_reasons()
                .contains(&QueryReadIncomplete::ProofStopped {
                    reason: "drop_inventory_not_absent",
                    cause: None,
                })
        );
    }

    #[test]
    #[hardwon("#12450: a built-in derive(Debug) blocked the inertness proof of a no-Drop struct")]
    fn builtin_derive_inertness_requires_macro_authority_and_drop_absence() {
        for (prefix, attributes, drop_impl, inventory_absent, expected) in [
            ("", "#[derive(Debug)]", "", true, true),
            ("", "#[derive(Debug, Clone, Copy)]", "", true, true),
            (
                "macro_rules! Debug { () => {} }",
                "#[derive(Debug)]",
                "",
                true,
                false,
            ),
            (
                "use external_proc_macros::Debug;",
                "#[derive(Debug)]",
                "",
                true,
                false,
            ),
            (
                "use external_proc_macros::Custom as Debug;",
                "#[derive(Debug)]",
                "",
                true,
                false,
            ),
            (
                "use external_proc_macros::*;",
                "#[derive(Debug)]",
                "",
                true,
                false,
            ),
            ("", "#[unknown]", "", true, false),
            (
                "",
                "#[derive(Debug)]",
                "impl Drop for Local { fn drop(&mut self) {} }",
                false,
                false,
            ),
            ("", "#[derive(Debug)]", "", false, false),
        ] {
            let text = format!(
                "{prefix} {attributes} struct Local {{ val: i64 }} {drop_impl} fn run(v: Local) {{}}"
            );
            let fixture = AnalyzerFixture::new_for_language(
                Language::Rust,
                &[
                    (
                        "Cargo.toml",
                        "[package]\nname='derive_inertness'\nversion='0.1.0'\nedition='2021'\n",
                    ),
                    ("src/lib.rs", &text),
                ],
            );
            let analyzer = fixture.analyzer.analyzer();
            let _scope = AnalyzerQueryScope::new(analyzer);
            // Supply the typed inventory contract independently of attribute
            // admission: a negative/unknown absence proof must still block.
            let inventory = |_: &CodeUnit, _: &str, _: ByteRange<usize>| inventory_absent;
            let mut proof = RustTypeProof::new(analyzer).unwrap();
            proof.drop_inventory = Some(&inventory);
            let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
            let source = proof.source(&file).unwrap();
            let root = source.tree().root_node();
            let function = named_children(root)
                .into_iter()
                .find(|node| node.kind() == "function_item")
                .unwrap();
            let parameters = function.child_by_field_name("parameters").unwrap();
            let parameter = named_children(parameters)
                .into_iter()
                .find(|node| node.kind() == "parameter")
                .unwrap();
            let ty = parameter.child_by_field_name("type").unwrap();
            assert_eq!(
                proof.type_class(&source, ty, PROOF_DEPTH).is_inert(),
                expected,
                "{text}"
            );
        }
    }

    /// The class of the first closure in `text` whose source starts with
    /// `closure`, with the typed Drop inventory answering `inventory_absent`.
    fn closure_environment_class_of(
        text: &str,
        closure: &str,
        inventory_absent: bool,
    ) -> (
        RustValueClass,
        Vec<brokk_bifrost_analysis::analyzer::QueryReadIncomplete>,
    ) {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname='closure_env'\nversion='0.1.0'\nedition='2021'\n",
                ),
                ("src/lib.rs", text),
            ],
        );
        let analyzer = fixture.analyzer.analyzer();
        let _scope = AnalyzerQueryScope::new(analyzer);
        let inventory = |_: &CodeUnit, _: &str, _: ByteRange<usize>| inventory_absent;
        let mut proof = RustTypeProof::new(analyzer).unwrap();
        proof.drop_inventory = Some(&inventory);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let source = proof.source(&file).unwrap();
        let start = text.find(closure).unwrap();
        let node = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(start, start + closure.len())
            .unwrap();
        assert_eq!(node.kind(), "closure_expression", "{closure} in {text}");
        let (class, receipt) = QueryReadReceipt::capture(analyzer, || {
            proof.expression_class(&source, node, PROOF_DEPTH)
        });
        (class, receipt.incomplete_reasons().to_vec())
    }

    #[test]
    fn closure_class_is_the_class_of_its_environment() {
        let guard = "struct G; impl Drop for G { fn drop(&mut self) {} } ";
        for (text, closure, expected) in [
            // The class describes the environment, not the result or the body.
            ("fn f() { let c = || 1; }", "|| 1", RustValueClass::Inert),
            (
                "fn f() { let c = |x: i32| { let y = x; }; }",
                "|x: i32| { let y = x; }",
                RustValueClass::Inert,
            ),
            // An inert binding is inert whether it is captured by reference or by move.
            (
                "fn f() { let n = 1; let c = || n; }",
                "|| n",
                RustValueClass::Inert,
            ),
            (
                "fn f(s: String) { let c = move || s; }",
                "move || s",
                RustValueClass::Inert,
            ),
            (
                "fn f() { let a = || 1; let c = move || a; }",
                "move || a",
                RustValueClass::Inert,
            ),
            (
                "fn f() { let n = 1; let c = || { let inner = || n; }; }",
                "|| { let inner = || n; }",
                RustValueClass::Inert,
            ),
            // An inert-valued binding makes the environment inert-valued.
            (
                "fn f() { let o = None; let c = move || o; }",
                "move || o",
                RustValueClass::InertValue,
            ),
        ] {
            let (class, reasons) = closure_environment_class_of(text, closure, false);
            assert_eq!((class, &reasons[..]), (expected, &[][..]), "{text}");
        }
        for (text, closure) in [
            // A consuming use is by value even without `move`.
            ("fn f(g: G) { let c = || g; }", "|| g"),
            ("fn f(g: G) { let c = move || g; }", "move || g"),
            ("fn f<T>(t: T) { let c = move || t; }", "move || t"),
            // A nested closure adds its captures to the outer environment.
            (
                "fn f(g: G) { let c = || { let inner = || g; }; }",
                "|| { let inner = || g; }",
            ),
            ("fn f() { let c = async || 1; }", "async || 1"),
        ] {
            let text = format!("{guard}{text}");
            let (class, _) = closure_environment_class_of(&text, closure, false);
            assert_eq!(class, RustValueClass::Unknown, "{text}");
        }
    }

    #[test]
    fn closure_with_an_incomplete_capture_set_records_a_proof_stop() {
        use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
        for (text, closure, reason) in [
            (
                "fn f() { let n = 1; let c = || println!(\"{n}\"); }",
                "|| println!(\"{n}\")",
                "closure_macro_environment",
            ),
            (
                "fn f() { let c = || __bifrost_refused_capture_11830; }",
                "|| __bifrost_refused_capture_11830",
                "closure_capture_unresolved",
            ),
        ] {
            let (class, reasons) = closure_environment_class_of(text, closure, true);
            assert_eq!(class, RustValueClass::Unknown, "{text}");
            assert!(
                reasons.contains(&QueryReadIncomplete::ProofStopped {
                    reason,
                    cause: None
                }),
                "{text}: {reasons:?}"
            );
        }
    }

    #[test]
    fn borrowed_receiver_does_not_certify_other_parameters_inert() {
        let source = Arc::<str>::from(
            "struct Guard; impl Drop for Guard { fn drop(&mut self) {} } struct S; impl S { fn run(&self, guard: Guard) { may_panic(); } fn run2(&self, n: u32) { may_panic(); } }",
        );
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"borrowed_receiver\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                ("lib.rs", &source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let rust_source = proof.source(&file).unwrap();
        for (name, expected) in [("run", false), ("run2", true)] {
            let mut pending = vec![rust_source.tree().root_node()];
            let callable = loop {
                let Some(node) = pending.pop() else {
                    panic!("fixture method {name} not found");
                };
                if node.kind() == "function_item"
                    && node
                        .child_by_field_name("name")
                        .and_then(|name| rust_source.node_text(name))
                        == Some(name)
                {
                    break node;
                }
                pending.extend(named_children(node));
            };
            assert_eq!(
                proof.procedure_drops_are_inert(&file, &source, callable.byte_range()),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    #[hardwon("#12652: nested pattern binding took the outer let's class")]
    fn nested_pattern_bindings_do_not_take_the_enclosing_let_class() {
        // Each loop binder is out of scope at the following read, so the
        // reads resolve to their parameters. Guard owns user Drop code and
        // must stay non-inert; String is inert from the reviewed std facts
        // because this proof asks whether drop glue runs user code. Guard
        // still guards #12652: a climb to the enclosing let must not borrow
        // its inert u8 annotation to classify the parameter read.
        let source = Arc::<str>::from(
            "struct Guard; impl Drop for Guard { fn drop(&mut self) {} }\n\
             fn consume<T>(_: T) {}\n\
             fn run(loop_guard: Guard, loop_string: String, v: Vec<u8>, w: Vec<u8>) {\n\
                 let r1: u8 = { for loop_guard in v {} consume(loop_guard); 1 };\n\
                 let r2: u8 = { for loop_string in w {} consume(loop_string); 1 };\n\
             }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"nested_bindings\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                ("lib.rs", &source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let rust_source = proof.source(&file).unwrap();
        let mut pending = vec![rust_source.tree().root_node()];
        let mut uses = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "identifier"
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "arguments")
                && let Some(name) = rust_source.node_text(node)
                && name.starts_with("loop_")
            {
                uses.push((
                    name,
                    proof
                        .expression_class(&rust_source, node, PROOF_DEPTH)
                        .is_inert(),
                ));
            }
            pending.extend(named_children(node));
        }
        uses.sort();
        assert_eq!(uses, [("loop_guard", false), ("loop_string", true)]);
    }

    #[test]
    #[hardwon(
        "#10879: discarded function-pointer call results ignored their declared return types"
    )]
    fn function_pointer_results_use_the_structured_signature_without_resolving_dispatch() {
        let source = Arc::<str>::from(
            "fn run<T>(unit: fn(), text: fn() -> String, unknown: fn() -> T) { unit(); text(); unknown(); }",
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        crate::analyzer::rust::native_points::reset_rust_definition_operation_open_count_for_test();
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let parsed = proof.source(&file).unwrap();
        let mut pending = vec![parsed.tree().root_node()];
        let mut actual = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "call_expression" {
                let name = parsed
                    .node_text(node.child_by_field_name("function").unwrap())
                    .unwrap();
                actual.push((name, proof.expression_class(&parsed, node, 64).is_inert()));
                if name == "unit" {
                    assert_eq!(crate::analyzer::rust::native_points::rust_definition_operation_open_count_for_test(), 0);
                }
            }
            pending.extend(named_children(node).into_iter().rev());
        }
        assert_eq!(actual, [("unit", true), ("text", true), ("unknown", false)]);
    }

    #[test]
    fn modeled_path_return_proves_local_drop_glue_is_inert() {
        let source = Arc::<str>::from(
            "use std::path::Path;\n\nfn run(value: &str) {\n    let joined = Path::new(\"/srv\").join(value);\n    std::fs::read(joined);\n}\n",
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
        let pack = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-path-owner",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-path-owner",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.path", "module"),
                        rust_type("std.path.Path", "struct"),
                        rust_type("std.path.PathBuf", "struct")
                    ],
                    "members": [rust_path_constructor(), rust_path_method()],
                    "relations": []
                }
            }]
        });
        activate_model_pack(&fixture, pack, "fixture.rust-path-owner", "std");
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).unwrap();
        let parsed = proof.source(&file).unwrap();
        let function = named_children(parsed.tree().root_node())
            .into_iter()
            .find(|node| node.kind() == "function_item")
            .unwrap();
        let binding = named_children(function.child_by_field_name("body").unwrap())
            .into_iter()
            .find(|node| node.kind() == "let_declaration")
            .unwrap();
        let value = binding.child_by_field_name("value").unwrap();
        assert_eq!(value.kind(), "call_expression");
        let callable = value.byte_range();
        assert!(procedure_drops_run_no_user_code(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            callable,
            None,
        ));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[hardwon("#8893+#11259: nested receiver proofs repeated work and lost cutoff completion")]
    fn modeled_builder_chain_proof_growth() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::take_nested_rust_selected_operation_opens_for_test;

        let length = PROOF_DEPTH + 4;
        let source = format!(
            "use std::path::Path;\nfn resolved() {{ let _ = Path::new(\"root\").join(\"part\"); }}\nfn chain_{length}() {{ let _ = Path::new(\"root\"){}; }}\nfn untouched() {{ let _ = \"cancelled\"; }}\n",
            ".join(\"part\")".repeat(length)
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
        activate_path_chain_model(&fixture);
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let analyzer = fixture.analyzer.analyzer();
        let cancellation = CancellationToken::new();
        let factory = crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
            analyzer,
            &cancellation,
        )
        .expect("Rust definition factory");
        let mut operation = match factory.open(&cancellation).expect("selected Rust opening") {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
            _ => panic!("selected Rust operation unavailable"),
        };
        let proof = RustTypeProof {
            drop_inventory: None,
            analyzer,
            rust: resolve_analyzer::<RustAnalyzer>(analyzer).expect("Rust analyzer"),
            resolver: SelectedRustTypeProofResolver {
                analyzer,
                factory: &factory,
                operation: RefCell::new(&mut operation),
                cancellation: Some(&cancellation),
            },
        };
        let rust_source = proof.source(&file).expect("prepared Rust source");
        let resolved_text = "Path::new(\"root\").join(\"part\")";
        let resolved_call = rust_source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(
                source.find(resolved_text).expect("resolved call"),
                source.find(resolved_text).expect("resolved call") + resolved_text.len(),
            )
            .expect("resolved call node");
        assert_eq!(resolved_call.kind(), "call_expression");
        take_nested_rust_selected_operation_opens_for_test();
        let resolved_owner =
            proof.modeled_call_result_owner(&rust_source, resolved_call, PROOF_DEPTH);
        let resolved_opens = take_nested_rust_selected_operation_opens_for_test();
        eprintln!("resolved_nested_opens={resolved_opens}");
        assert_eq!(resolved_opens, 0);
        assert_eq!(
            resolved_owner,
            Some(RustReceiverOwner::Path("std.path.PathBuf".into()))
        );
        let mut pending = vec![rust_source.tree().root_node()];
        let mut functions = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "function_item" {
                functions.push(node);
            }
            pending.extend(named_children(node));
        }

        let function_name = format!("chain_{length}");
        let function = functions
            .iter()
            .copied()
            .find(|function| {
                function
                    .child_by_field_name("name")
                    .and_then(|name| rust_source.node_text(name))
                    == Some(function_name.as_str())
            })
            .expect("generated chain function exists");
        let mut pending = vec![function];
        let mut outer_call = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "call_expression"
                && outer_call.is_none_or(|current: Node<'_>| {
                    node.end_byte() - node.start_byte() > current.end_byte() - current.start_byte()
                })
            {
                outer_call = Some(node);
            }
            pending.extend(named_children(node));
        }
        let call = outer_call.expect("generated chain has a call");
        let function = call.child_by_field_name("function").expect("call function");
        let receiver = function
            .child_by_field_name("value")
            .expect("modeled method has a receiver");
        let before = rust_source.expression_class_evaluations.get();
        let shapes_before = rust_source.modeled_call_shape_evaluations.get();
        take_nested_rust_selected_operation_opens_for_test();
        let operation_limit = length * 8;
        rust_source
            .expression_class_evaluation_limit
            .set(Some(before + operation_limit));
        rust_source
            .modeled_call_shape_evaluation_limit
            .set(Some(shapes_before + operation_limit));
        let started = Instant::now();
        let attempt = completed_proof(analyzer, None, || {
            proof.receiver_owner(&rust_source, receiver)
        });
        assert!(matches!(&attempt, RustProofAttempt::Incomplete { .. }));
        let owner = attempt.into_value();
        assert!(
            rust_source
                .modeled_call_shapes
                .borrow()
                .get(&(receiver.id(), PROOF_DEPTH))
                .is_none_or(|(_, receipt)| receipt.incomplete_reasons().iter().any(
                    |reason| matches!(
                        reason,
                        brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                            reason: "depth_limit",
                            cause: None
                        }
                    )
                ))
        );
        let chain_opens = take_nested_rust_selected_operation_opens_for_test();
        eprintln!("chain_nested_opens={chain_opens}");
        assert_eq!(chain_opens, 0);
        let elapsed = started.elapsed();
        let evaluations = rust_source.expression_class_evaluations.get() - before;
        let shape_evaluations = rust_source.modeled_call_shape_evaluations.get() - shapes_before;
        eprintln!(
            "chain_length={length} elapsed={elapsed:?} expression_class_evaluations={evaluations} modeled_call_shape_evaluations={shape_evaluations}"
        );
        assert_eq!(owner, None);
        assert!(
            evaluations <= operation_limit,
            "chain of {length} modeled calls evaluated {evaluations} uncached expressions"
        );
        assert!(
            shape_evaluations <= operation_limit,
            "chain of {length} modeled calls evaluated {shape_evaluations} uncached call shapes"
        );
        for _ in 0..2 {
            let attempt = completed_proof(analyzer, None, || {
                Some(proof.expression_class(&rust_source, receiver, 1))
            });
            assert!(matches!(attempt, RustProofAttempt::Incomplete { .. }));
            assert!(
                rust_source
                    .expression_classes
                    .borrow()
                    .get(&(receiver.id(), 1))
                    .is_none_or(|(_, receipt)| receipt.incomplete_reasons().iter().any(
                        |reason| matches!(
                            reason,
                            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                                reason: "depth_limit",
                                cause: None
                            }
                        )
                    ))
            );
        }
        let mut pending = vec![rust_source.tree().root_node()];
        let mut literal = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "string_literal"
                && rust_source.node_text(node) == Some("\"cancelled\"")
            {
                literal = Some(node);
                break;
            }
            pending.extend(named_children(node));
        }
        let literal = literal.expect("untouched cancellation literal");
        let key = (literal.id(), PROOF_DEPTH);
        assert!(!rust_source.expression_classes.borrow().contains_key(&key));
        cancellation.cancel();
        let attempt = completed_proof(analyzer, None, || {
            Some(proof.expression_class(&rust_source, literal, PROOF_DEPTH))
        });
        assert!(matches!(
            attempt,
            RustProofAttempt::Incomplete {
                value: Some(RustValueClass::Unknown),
                cause: Some(DerivationExecutionCause::Cancelled),
                ..
            }
        ));
        assert!(!rust_source.expression_classes.borrow().contains_key(&key));
    }

    fn activate_imported_constructor_model(fixture: &AnalyzerFixture) {
        let source = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-imported-constructor",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-imported-constructor",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.process", "module"),
                        rust_type("std.process.Command", "struct"),
                        rust_type("std.vec", "module"),
                        rust_type("std.vec.Vec", "struct")
                    ],
                    "members": [rust_constructor(), rust_vec_constructor(), rust_method()],
                    "relations": []
                }
            }]
        });
        activate_model_pack(fixture, source, "fixture.rust-imported-constructor", "std");
    }

    #[track_caller]
    fn activate_model_pack(
        fixture: &AnalyzerFixture,
        source: serde_json::Value,
        pack_id: &str,
        package: &str,
    ) {
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).expect("serialize Rust model fixture"),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("Rust model fixture must compile: {diagnostics:#?}"));
        activate_compiled_model_pack(fixture, &pack, pack_id, package);
    }

    fn activate_compiled_model_pack(
        fixture: &AnalyzerFixture,
        pack: &crate::analyzer::semantic_model::CompiledSemanticModelPack,
        pack_id: &str,
        package: &str,
    ) {
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default())
            .expect("open semantic-pack catalog");
        catalog
            .register_session_pack(
                pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: pack_id.to_owned(),
                },
            )
            .expect("register Rust model fixture");
        assert!(matches!(
            brokk_bifrost_analysis::test_support::activate_semantic_model_fixture(
                fixture.analyzer.analyzer(),
                &catalog,
                pack_id,
                SemanticModelActivationEvidence {
                    language: "rust".to_owned(),
                    ecosystem: "cargo".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: package.to_owned(),
                        version: None,
                    }),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
            ),
            SemanticModelRuntimeOutcome::Ready { .. }
        ));
    }

    /// A self-contained clone-certificate pack: the `std` and `std.clone`
    /// modules, the Clone trait declaration and its abstract method, plus one
    /// type per Clone shape: a derive-style hierarchy edge, an `impl Clone`
    /// record, an inherent `clone`, and a type whose `clone` comes from another
    /// trait. Keeping the model in code avoids a public unit test reaching
    /// into the private semantic-model fixture tree.
    fn clone_certificate_pack() -> serde_json::Value {
        let mut pack = serde_json::json!({
            "schema_version": 19,
            "pack_id": "fixture.rust-clone-certificate",
            "version": "1.0.0",
            "producer": {
                "name": "bifrost-test-fixtures",
                "version": "0.1.0"
            },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "toolchains": [] },
            "provenance": {
                "source": "Test-only clone certificate fixture; never registered in production.",
                "revision": "test-only-clone-certificate"
            },
            "license": "Apache-2.0 AND MIT",
            "completeness": "complete",
            "safety": {
                "generated_code_only": false,
                "review_required": false
            },
            "shards": [{
                "id": "test.declarations.clone-certificate",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        {
                            "id": "type.fixture.std",
                            "name": "std",
                            "type_kind": "module",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/lib.rs",
                                "symbol": "std"
                            },
                            "hierarchy": []
                        },
                        {
                            "id": "type.fixture.std-clone",
                            "name": "std.clone",
                            "type_kind": "module",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/core/src/clone.rs",
                                "symbol": "std.clone"
                            },
                            "hierarchy": []
                        },
                        {
                            "id": "type.fixture.std-clone-clone",
                            "name": "std.clone.Clone",
                            "type_kind": "trait",
                            "visibility": "public",
                            "is_abstract": true,
                            "callable_surface_complete": false,
                            "locator": {
                                "kind": "artifact",
                                "path": "library/core/src/clone.rs",
                                "symbol": "std.clone.Clone"
                            },
                            "hierarchy": []
                        }
                    ],
                    "members": [{
                        "id": "member.fixture.clone-clone",
                        "owner": "type.fixture.std-clone-clone",
                        "name": "clone",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "is_abstract": true,
                        "callable_family_complete": true,
                        "signature": {
                            "parameters": [],
                            "returns": { "kind": "type_parameter", "name": "Self" },
                            "type_parameters": ["Self"]
                        },
                        "locator": {
                            "kind": "artifact",
                            "path": "library/core/src/clone.rs",
                            "symbol": "std.clone.Clone.clone"
                        }
                    }],
                    "relations": []
                }
            }]
        });
        let shard = &mut pack["shards"][0];
        let payload = &mut shard["payload"];
        let implements = |target: &str| {
            serde_json::json!([{
                "hierarchy_kind": "implements",
                "target": { "kind": "named", "name": target, "arguments": [] }
            }])
        };
        let types = payload["types"].as_array_mut().unwrap();
        // Absence of Clone needs both inventories closed (the trait's blanket
        // rules and the type's concrete impls) in one pack.
        for ty in types
            .iter_mut()
            .filter(|ty| ty["name"] == "std.clone.Clone")
        {
            ty["generic_trait_impls_complete"] = serde_json::json!(true);
            ty["generic_trait_impls"] = serde_json::json!([]);
        }
        for (name, kind, hierarchy) in [
            ("std.derived", "module", serde_json::json!([])),
            (
                "std.derived.Cookie",
                "struct",
                implements("std.clone.Clone"),
            ),
            ("std.explicit", "module", serde_json::json!([])),
            ("std.explicit.Handle", "struct", serde_json::json!([])),
            ("std.inherent", "module", serde_json::json!([])),
            ("std.inherent.Thing", "struct", serde_json::json!([])),
            ("std.other", "module", serde_json::json!([])),
            ("std.other.Dup", "trait", serde_json::json!([])),
            ("std.other.Widget", "struct", implements("std.other.Dup")),
        ] {
            let mut ty = rust_type(name, kind);
            ty["hierarchy"] = hierarchy;
            // Without a complete inventory, selection cannot rule Clone out of
            // a type, so its other `clone` would stay ambiguous.
            if matches!(name, "std.inherent.Thing" | "std.other.Widget") {
                ty["implemented_traits_complete"] = serde_json::json!(true);
                ty["implemented_traits"] = serde_json::json!([]);
            }
            types.push(ty);
        }
        let method = |id: &str, owner: &str, symbol: &str, returns: &str| {
            serde_json::json!({
                "id": id,
                "owner": owner,
                "name": "clone",
                "member_kind": "method",
                "visibility": "public",
                "is_static": false,
                "callable_family_complete": true,
                "self_form": { "kind": "shared" },
                "signature": {
                    "parameters": [],
                    "returns": { "kind": "named", "name": returns }
                },
                "locator": {
                    "kind": "artifact",
                    "path": "library/std/src/lib.rs",
                    "symbol": symbol
                }
            })
        };
        let members = payload["members"].as_array_mut().unwrap();
        let mut explicit = method(
            "member.fixture.handle-clone",
            "type.fixture.std-explicit-handle",
            "std.explicit.Handle.clone",
            "std.explicit.Handle",
        );
        explicit["implemented_trait"] =
            serde_json::json!({ "kind": "named", "name": "std.clone.Clone", "arguments": [] });
        members.push(explicit);
        members.push(method(
            "member.fixture.thing-clone",
            "type.fixture.std-inherent-thing",
            "std.inherent.Thing.clone",
            "std.inherent.Thing",
        ));
        let mut dup = method(
            "member.fixture.dup-clone",
            "type.fixture.std-other-dup",
            "std.other.Dup.clone",
            "std.other.Widget",
        );
        dup["is_abstract"] = serde_json::json!(true);
        members.push(dup);
        for (id, name, is_static, parameter, self_form) in [
            ("member.fixture.cookie-new", "new", true, "name", None),
            (
                "member.fixture.cookie-set-secure",
                "set_secure",
                false,
                "secure",
                Some(serde_json::json!({ "kind": "mutable" })),
            ),
        ] {
            let mut member = serde_json::json!({
                "id": id,
                "owner": "type.fixture.std-derived-cookie",
                "name": name,
                "member_kind": "method",
                "visibility": "public",
                "is_static": is_static,
                "callable_family_complete": true,
                "signature": {
                    "parameters": [{ "name": parameter, "type": { "kind": "named", "name": "untyped" } }],
                    "returns": { "kind": "named", "name": "std.derived.Cookie" }
                },
                "locator": {
                    "kind": "artifact",
                    "path": "library/std/src/lib.rs",
                    "symbol": format!("std.derived.Cookie.{name}")
                }
            });
            if let Some(self_form) = self_form {
                member["self_form"] = self_form;
            }
            members.push(member);
        }
        pack
    }

    // Another trait's `clone` in scope makes every receiver's `clone` ambiguous,
    // so that case needs a file of its own.
    const CLONE_CERTIFICATE_SOURCE: &str = "use std::derived::Cookie;\nuse std::explicit::Handle;\nuse std::inherent::Thing;\nfn run(a: Cookie, b: Handle, c: Thing, e: Unresolved, f: &&Cookie, g: &Cookie) {\n    let r = &&a;\n    let _ = (a.clone(), b.clone(), c.clone(), e.clone(), f.clone(), g.clone(), (&g).clone(), (*f).clone(), (&a).clone(), r.clone());\n}\n";
    // `let` receivers: the first function holds the allowed forms and the second
    // each excluded form, so a certificate in the second is a regression.
    const CLONE_LET_SOURCE: &str = "use std::derived::Cookie;\nfn allowed(typed_param: Cookie) {\n    let mut mutated = Cookie::new(\"n\");\n    mutated.set_secure(true);\n    let _ = mutated.clone();\n    let plain = Cookie::new(\"n\");\n    let _ = plain.clone();\n    for _ in 0..2 {\n        let mut looped = Cookie::new(\"n\");\n        looped.set_secure(false);\n        let _ = looped.clone();\n    }\n    let moved = typed_param;\n    let _ = moved.clone();\n}\nfn excluded(typed_loop: Cookie) {\n    let mut reassigned = Cookie::new(\"n\");\n    reassigned = Cookie::new(\"m\");\n    let _ = reassigned.clone();\n    let mut borrowed_mut = Cookie::new(\"n\");\n    let _handle = &mut borrowed_mut;\n    let _ = borrowed_mut.clone();\n    let shadowed = Cookie::new(\"n\");\n    let _ = shadowed.clone();\n    let shadowed = 1;\n    let mut closure_rebound = Cookie::new(\"n\");\n    let mut rebind = || {\n        closure_rebound = Cookie::new(\"m\");\n    };\n    rebind();\n    let _ = closure_rebound.clone();\n    let macro_read = Cookie::new(\"n\");\n    println!(\"{}\", macro_read);\n    let _ = macro_read.clone();\n    let ref_init = &Cookie::new(\"n\");\n    let _ = ref_init.clone();\n    let loop_shadow = Cookie::new(\"n\");\n    for loop_shadow in 0..1 {\n        let _ = loop_shadow.clone();\n    }\n    for typed_loop in 0..1 {\n        let _ = typed_loop.clone();\n    }\n}\n";
    const CLONE_OTHER_TRAIT_SOURCE: &str =
        "use std::other::{Dup, Widget};\nfn run(d: Widget) {\n    let _ = d.clone();\n}\n";

    /// Runs `run` with a proof over both fixture files; `range` locates a call
    /// by its text in either.
    fn with_clone_certificate_proof<R>(
        run: impl FnOnce(&RustTypeProof<'_>, &dyn Fn(&str) -> (ProjectFile, ByteRange<usize>)) -> R,
    ) -> R {
        with_clone_certificate_pack(clone_certificate_pack(), run)
    }

    fn with_clone_certificate_pack<R>(
        pack: serde_json::Value,
        run: impl FnOnce(&RustTypeProof<'_>, &dyn Fn(&str) -> (ProjectFile, ByteRange<usize>)) -> R,
    ) -> R {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("lib.rs", CLONE_CERTIFICATE_SOURCE),
                ("other.rs", CLONE_OTHER_TRAIT_SOURCE),
                ("let.rs", CLONE_LET_SOURCE),
            ],
        );
        activate_model_pack(&fixture, pack, "fixture.rust-clone-certificate", "std");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).expect("Rust proof");
        let locate = |call: &str| {
            let (name, text) = if CLONE_CERTIFICATE_SOURCE.contains(call) {
                ("lib.rs", CLONE_CERTIFICATE_SOURCE)
            } else if CLONE_LET_SOURCE.contains(call) {
                ("let.rs", CLONE_LET_SOURCE)
            } else {
                ("other.rs", CLONE_OTHER_TRAIT_SOURCE)
            };
            let start = text.find(call).expect("fixture call");
            (
                ProjectFile::new(fixture.project_root(), name),
                start..start + call.len(),
            )
        };
        run(&proof, &locate)
    }

    fn model_declaration(analyzer: &dyn IAnalyzer, name: &str) -> RustModelDeclaration {
        let overlay = analyzer
            .semantic_model_overlay_read()
            .published()
            .expect("overlay");
        RustModelDeclaration::of(
            &overlay
                .symbols_named_in_family(name, "rust", SemanticModelNamespace::TypeOrModule)
                .unique()
                .unwrap_or_else(|| panic!("unique model symbol {name}")),
        )
    }

    fn clone_fixture_text(file: &ProjectFile) -> &'static str {
        match file.rel_path().to_string_lossy().as_ref() {
            "lib.rs" => CLONE_CERTIFICATE_SOURCE,
            "let.rs" => CLONE_LET_SOURCE,
            _ => CLONE_OTHER_TRAIT_SOURCE,
        }
    }

    fn certify(
        proof: &RustTypeProof<'_>,
        locate: &dyn Fn(&str) -> (ProjectFile, ByteRange<usize>),
        call: &str,
        depth: usize,
    ) -> RustCloneProof {
        let (file, range) = locate(call);
        proof.modeled_clone_certificate(&file, clone_fixture_text(&file), range, depth)
    }

    fn bare_clone_result(
        proof: &RustTypeProof<'_>,
        locate: &dyn Fn(&str) -> (ProjectFile, ByteRange<usize>),
        call: &str,
    ) -> Option<TypeRef> {
        let (file, range) = locate(call);
        proof.modeled_clone_result(&file, range, PROOF_DEPTH)
    }

    #[test]
    fn clone_certificate_names_the_selected_implementation() {
        with_clone_certificate_proof(|proof, locate| {
            let analyzer = proof.analyzer;
            let clone_trait = model_declaration(analyzer, "std.clone.Clone");
            let derived = certify(proof, locate, "a.clone()", PROOF_DEPTH);
            let RustCloneVerdict::Certified(derived_certificate) = &derived.verdict else {
                panic!("a hierarchy edge to Clone certifies: {:?}", derived.verdict);
            };
            assert_eq!(
                derived_certificate.implementation,
                RustCloneImplementation::Declared {
                    receiver: model_declaration(analyzer, "std.derived.Cookie")
                }
            );
            assert_eq!(derived_certificate.clone_trait, clone_trait);
            assert_eq!(derived_certificate.receiver_steps, 0);
            assert!(derived.receipt.incomplete_reasons().is_empty());

            let explicit = certify(proof, locate, "b.clone()", PROOF_DEPTH);
            let RustCloneVerdict::Certified(explicit_certificate) = &explicit.verdict else {
                panic!("an impl Clone record certifies: {:?}", explicit.verdict);
            };
            let RustCloneImplementation::Explicit { receiver, method } =
                &explicit_certificate.implementation
            else {
                panic!("explicit impl: {:?}", explicit_certificate.implementation);
            };
            assert_eq!(
                receiver,
                &model_declaration(analyzer, "std.explicit.Handle")
            );
            assert_eq!(method.id, "member.fixture.handle-clone");
            assert_eq!(explicit_certificate.clone_trait, clone_trait);
        });
    }

    #[test]
    fn clone_certificate_refuses_other_clone_methods_and_reports_gaps() {
        with_clone_certificate_proof(|proof, locate| {
            for call in ["c.clone()", "d.clone()"] {
                let answer = certify(proof, locate, call, PROOF_DEPTH);
                assert_eq!(answer.verdict, RustCloneVerdict::NotClone, "{call}");
                assert_eq!(bare_clone_result(proof, locate, call), None, "{call}");
            }
            let unresolved = certify(proof, locate, "e.clone()", PROOF_DEPTH);
            assert_eq!(
                unresolved.verdict,
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ReceiverUnresolved)
            );
            // Too little depth is a registered deterministic stop: no cause.
            let shallow = certify(proof, locate, "a.clone()", 0);
            assert_eq!(
                shallow.verdict,
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ProofStopped {
                    reason: "depth_limit",
                    cause: None,
                })
            );
            let (file, range) = locate("a.clone()");
            // A range taken from other bytes declines instead of naming another call.
            let stale =
                proof.modeled_clone_certificate(&file, "// edited\n", range.clone(), PROOF_DEPTH);
            assert_eq!(
                stale.verdict,
                RustCloneVerdict::Incomplete(RustCloneIncomplete::ProofStopped {
                    reason: "source_mismatch",
                    cause: Some(DerivationExecutionCause::Provider),
                })
            );
            let by_function = rust_modeled_clone_certificate(
                proof.analyzer,
                &file,
                clone_fixture_text(&file),
                range,
            );
            assert!(matches!(
                by_function.verdict,
                RustCloneVerdict::Certified(_)
            ));
        });
    }

    #[test]
    fn clone_certificate_selects_on_the_receiver_as_written() {
        with_clone_certificate_proof(|proof, locate| {
            // `&Cookie` selects `<Cookie as Clone>::clone`.
            let single = certify(proof, locate, "g.clone()", PROOF_DEPTH);
            assert!(
                matches!(single.verdict, RustCloneVerdict::Certified(_)),
                "{:?}",
                single.verdict
            );
            // `&&Cookie` selects `<&Cookie as Clone>::clone`: Cookie's own
            // implementation is not the one called.
            let double = certify(proof, locate, "f.clone()", PROOF_DEPTH);
            assert!(
                matches!(double.verdict, RustCloneVerdict::Unproven { .. }),
                "{:?}",
                double.verdict
            );
            // The replay looks through borrows, dereferences and initializers
            // to a declared type, so it cannot count their layers. Only a
            // plain binding with a written type is certified. Member
            // selection already declines most of these receivers; the check
            // is a second guard if it ever resolves them.
            for call in ["(&g).clone()", "(*f).clone()", "(&a).clone()", "r.clone()"] {
                let answer = certify(proof, locate, call, PROOF_DEPTH);
                assert!(
                    !matches!(answer.verdict, RustCloneVerdict::Certified(_)),
                    "{call}: {:?}",
                    answer.verdict
                );
            }
        });
    }

    #[test]
    fn written_binding_type_excludes_self_and_inferred_bindings() {
        let source = "struct S;\nimpl S {\n    fn f(&self, x: S) {\n        let y = &&x;\n        let _ = (self.clone(), x.clone(), y.clone());\n    }\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = super::super::semantic::RustReceiverTypeFacts::from_tree(source, &tree);
        let receiver = |call: &str| {
            let start = source.find(call).unwrap();
            let call = tree
                .root_node()
                .named_descendant_for_byte_range(start, start + call.len())
                .unwrap();
            rust_method_call_parts(call.child_by_field_name("function").unwrap())
                .unwrap()
                .0
        };
        assert!(facts.binding_has_written_type(source, &tree, receiver("x.clone()")));
        assert!(!facts.binding_has_written_type(source, &tree, receiver("self.clone()")));
        assert!(!facts.binding_has_written_type(source, &tree, receiver("y.clone()")));
    }

    #[test]
    fn clone_certificate_follows_a_single_assignment_let_binding() {
        with_clone_certificate_proof(|proof, locate| {
            // A binding assigned once, with a certifiable initializer, whether
            // or not the object is mutated through `&mut self` between its
            // initialization and the clone, and whether it is declared in a
            // loop body or holds a moved typed parameter.
            for call in [
                "mutated.clone()",
                "plain.clone()",
                "looped.clone()",
                "moved.clone()",
            ] {
                let answer = certify(proof, locate, call, PROOF_DEPTH);
                assert!(
                    matches!(answer.verdict, RustCloneVerdict::Certified(_)),
                    "{call}: {:?}",
                    answer.verdict
                );
            }
            // Each excluded form stays uncertified.
            for call in [
                "reassigned.clone()",
                "borrowed_mut.clone()",
                "shadowed.clone()",
                "closure_rebound.clone()",
                "macro_read.clone()",
                "ref_init.clone()",
                "loop_shadow.clone()",
                "typed_loop.clone()",
            ] {
                let answer = certify(proof, locate, call, PROOF_DEPTH);
                assert!(
                    !matches!(answer.verdict, RustCloneVerdict::Certified(_)),
                    "{call}: {:?}",
                    answer.verdict
                );
            }
        });
    }

    #[test]
    fn unavailable_clone_source_stops_the_receipt() {
        let fixture =
            AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "fn run() {}")]);
        let answer = rust_clone_source_unavailable(fixture.analyzer.analyzer());
        let stop = RustCloneIncomplete::ProofStopped {
            reason: "source_unavailable",
            cause: Some(DerivationExecutionCause::Provider),
        };
        assert_eq!(answer.verdict, RustCloneVerdict::Incomplete(stop));
        assert!(
            answer
                .receipt
                .incomplete_reasons()
                .iter()
                .any(|reason| reason.is_execution_dependent()),
            "{:?}",
            answer.receipt
        );
    }

    #[test]
    fn clone_certificate_needs_a_closed_receiver_surface() {
        // A pack that reports only part of a type's surface may omit an
        // inherent `clone` that would shadow the trait method.
        let mut pack = clone_certificate_pack();
        pack["completeness"] = serde_json::json!("partial");
        with_clone_certificate_pack(pack, |proof, locate| {
            for call in ["a.clone()", "b.clone()"] {
                let answer = certify(proof, locate, call, PROOF_DEPTH);
                assert!(
                    !matches!(answer.verdict, RustCloneVerdict::Certified(_)),
                    "{call}: {:?}",
                    answer.verdict
                );
            }
            assert!(matches!(
                certify(proof, locate, "a.clone()", PROOF_DEPTH).verdict,
                RustCloneVerdict::Unproven { .. }
            ));
            // The bare result keeps its earlier trait-selected answer.
            assert!(bare_clone_result(proof, locate, "a.clone()").is_some());
        });
    }

    #[test]
    fn bare_clone_result_is_unchanged_by_the_certificate() {
        with_clone_certificate_proof(|proof, locate| {
            let RustCloneVerdict::Certified(derived) =
                certify(proof, locate, "a.clone()", PROOF_DEPTH).verdict
            else {
                panic!("derived certificate");
            };
            assert_eq!(
                bare_clone_result(proof, locate, "a.clone()"),
                Some(derived.result)
            );
            // An explicit `impl Clone` record has never produced a bare result.
            assert_eq!(bare_clone_result(proof, locate, "b.clone()"), None);
        });
    }

    #[test]
    #[hardwon(
        "#12054: partial Rust packs rejected unique inherent declarations before method resolution"
    )]
    fn partial_inherent_declarations_preserve_trait_competition() {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            SemanticModelCallApplication, SemanticModelCallableDisposition,
            SemanticModelCallableIncompleteReason, SemanticModelCallableKey,
        };
        use brokk_bifrost_analysis::analyzer::usages::get_definition::{
            DefinitionLookupRequest, resolve_call_target_batch_with_source,
        };
        let source = "use std::string::String;\nfn plain(s: String) { s.as_str(); s.as_bytes(); }\nmod local { use std::string::String; trait X { fn as_str(self); } impl X for String { fn as_str(self) {} } fn check(s: String) { s.as_str(); } }\nmod external { use std::string::String; use std::shadow::X; fn check(s: String) { s.as_str(); } }\nfn prelude(s: String) { s.clone(); }\nfn cookie<'c>(c: std::fixture::Cookie<'c>) { c.method(); }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let mut generic = rust_type("std.fixture.Generic", "struct");
        generic["type_parameters"] = serde_json::json!(["T"]);
        let types = vec![
            rust_type("std", "module"),
            rust_type("std.string", "module"),
            rust_type("std.string.String", "struct"),
            rust_type("std.fixture", "module"),
            generic,
            // rustdoc's generic_names excludes lifetime parameters: Cookie<'c>
            // has an empty type_parameters list, just like String.
            rust_type("std.fixture.Cookie", "struct"),
            rust_type("std.shadow", "module"),
            rust_type("std.shadow.X", "trait"),
            rust_type("std.clone", "module"),
            rust_type("std.clone.Clone", "trait"),
        ];
        let member = |owner: &str, name: &str| {
            serde_json::json!({
                "id": format!("member.{owner}.{name}").to_ascii_lowercase(),
                "owner": format!("type.fixture.{}", owner.replace('.', "-").to_ascii_lowercase()),
                "name": name, "member_kind": "method", "visibility": "public",
                "self_form": { "kind": "shared" },
                "signature": { "parameters": [], "returns": { "kind": "named", "name": "str" } },
                "locator": { "kind": "artifact", "path": "std.json", "symbol": format!("{owner}.{name}") }
            })
        };
        let mut external = member("std.shadow.X", "as_str");
        external["self_form"] = serde_json::json!({"kind": "value"});
        let mut trait_impl = member("std.fixture.Cookie", "trait_method");
        trait_impl["implemented_trait"] =
            serde_json::json!({"kind": "named", "name": "std.shadow.X"});
        let mut prelude = member("std.clone.Clone", "clone");
        prelude["self_form"] = serde_json::json!({"kind": "value"});
        let pack = serde_json::json!({
            "schema_version": 32, "pack_id": "fixture.rust-inherent-partial", "version": "1.0.0",
            "producer": {"name": "test", "version": "1.0.0"}, "language": "rust", "ecosystem": "cargo",
            "compatibility": {"toolchains": []}, "provenance": {"source": "test"},
            "license": "NOASSERTION", "completeness": "partial",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "declarations", "activation": [{"targets": [], "configurations": []}],
                "payload": {"kind": "declaration_facts", "types": types,
                    "members": [member("std.string.String", "as_str"), member("std.string.String", "as_bytes"),
                        member("std.string.String", "clone"), member("std.fixture.Generic", "method"),
                        member("std.fixture.Cookie", "method"), external, prelude, trait_impl], "relations": []}}]
        });
        // Artifact authority is carried by the producer, never authored JSON.
        let mut extracted: crate::analyzer::semantic_model::AuthoredSemanticModelPack =
            serde_json::from_value(pack.clone()).expect("fixture pack");
        extracted.extraction = Some(
            crate::analyzer::semantic_model::ArtifactExtraction::source_set(
                crate::analyzer::semantic_model::ArtifactExtractionKind::RustdocJsonSet,
                &"ab".repeat(32),
            ),
        );
        let compiled =
            crate::analyzer::semantic_model::compile_pack(&extracted, &CompilerOptions::default())
                .expect("extracted fixture compiles");
        activate_compiled_model_pack(&fixture, &compiled, "fixture.rust-inherent-partial", "std");
        let analyzer = fixture.analyzer.analyzer();
        let overlay = analyzer
            .semantic_model_overlay_read()
            .published()
            .expect("active overlay");
        for (owner, name, expected) in [
            (
                "std.string.String",
                "as_str",
                SemanticModelCallableDisposition::Unique,
            ),
            (
                "std.string.String",
                "as_bytes",
                SemanticModelCallableDisposition::Unique,
            ),
            (
                "std.fixture.Cookie",
                "method",
                SemanticModelCallableDisposition::Unique,
            ),
            (
                "std.fixture.Generic",
                "method",
                SemanticModelCallableDisposition::Incomplete(
                    SemanticModelCallableIncompleteReason::PartialModel,
                ),
            ),
            (
                "std.fixture.Cookie",
                "trait_method",
                SemanticModelCallableDisposition::Incomplete(
                    SemanticModelCallableIncompleteReason::PartialModel,
                ),
            ),
        ] {
            assert_eq!(
                overlay
                    .callable_for_application(
                        SemanticModelCallableKey::new("rust", owner, name, true, 0),
                        &SemanticModelCallApplication::positional(0),
                    )
                    .disposition,
                expected,
                "{owner}.{name}"
            );
            let declaration = overlay
                .symbols_named(owner)
                .unique()
                .expect("selected owner");
            assert_eq!(
                overlay
                    .callable_for_rust_reexported_owner_application(
                        SemanticModelCallableKey::new("rust", owner, name, true, 0),
                        &SemanticModelCallApplication::positional(0),
                        declaration,
                    )
                    .disposition,
                expected,
                "selected facade owner {owner}.{name}"
            );
        }
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let mut call_starts = source
            .match_indices("s.")
            .map(|(start, _)| start)
            .collect::<Vec<_>>();
        call_starts.push(source.find("c.method").expect("lifetime-only receiver"));
        let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
        let prepared = proof.source(&file).expect("prepared source");
        for (index, start) in call_starts.iter().copied().enumerate() {
            let mut node = prepared
                .tree()
                .root_node()
                .descendant_for_byte_range(start, start + 1)
                .unwrap();
            while node.kind() != "call_expression" {
                node = node.parent().expect("method call parent");
            }
            let returned = proof.modeled_call_return_type(&prepared, node, 16);
            assert_eq!(
                returned.is_some(),
                index < 2 || index == 5,
                "return inference must honor the same trait competition at call {index}: {returned:?}"
            );
        }
        let requests = call_starts
            .into_iter()
            .map(|start| {
                let start = start + 2;
                let end = start + source[start..].find('(').unwrap();
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start),
                    end_byte: Some(end),
                }
            })
            .collect();
        let scope = AnalyzerQueryScope::new(analyzer);
        let outcomes = resolve_call_target_batch_with_source(
            analyzer,
            scope.token(),
            requests,
            file,
            Arc::from(source),
            None,
        );
        assert_eq!(outcomes.len(), 6);
        for (index, outcome) in outcomes.iter().enumerate() {
            if index < 2 || index == 5 {
                assert_eq!(
                    outcome
                        .exact_external_call
                        .as_ref()
                        .and_then(|proof| proof.dispatch_extensibility),
                    Some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed),
                    "plain inherent: {outcome:#?}"
                );
            } else {
                assert_ne!(
                    outcome
                        .exact_external_call
                        .as_ref()
                        .and_then(|proof| proof.dispatch_extensibility),
                    Some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed),
                    "trait rival must block closed inherent: {outcome:#?}"
                );
            }
        }
        // Neither omitted nor explicitly empty parameters in a manual partial
        // pack certify a nongeneric owner. Only extraction reviews that fact.
        for explicit_empty in [false, true] {
            let manual_fixture =
                AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "fn f() {}")]);
            let mut manual = pack.clone();
            manual.as_object_mut().unwrap().remove("extraction");
            for ty in manual["shards"][0]["payload"]["types"]
                .as_array_mut()
                .unwrap()
            {
                if explicit_empty {
                    ty["type_parameters"] = serde_json::json!([]);
                } else {
                    ty.as_object_mut().unwrap().remove("type_parameters");
                }
            }
            activate_model_pack(
                &manual_fixture,
                manual,
                "fixture.rust-inherent-partial",
                "std",
            );
            let manual_overlay = manual_fixture
                .analyzer
                .analyzer()
                .semantic_model_overlay_read()
                .published()
                .unwrap();
            assert_eq!(
                manual_overlay
                    .callable_for_application(
                        SemanticModelCallableKey::new(
                            "rust",
                            "std.string.String",
                            "as_str",
                            true,
                            0
                        ),
                        &SemanticModelCallApplication::positional(0),
                    )
                    .disposition,
                SemanticModelCallableDisposition::Incomplete(
                    SemanticModelCallableIncompleteReason::PartialModel
                ),
                "manual type parameters explicitly empty: {explicit_empty}"
            );
        }
    }

    fn rust_type(name: &str, type_kind: &str) -> serde_json::Value {
        serde_json::json!({
            "id": format!(
                "type.fixture.{}",
                name.replace('.', "-").to_ascii_lowercase()
            ),
            "name": name,
            "type_kind": type_kind,
            "visibility": "public",
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/lib.rs",
                "symbol": name
            }
        })
    }

    fn rust_constructor() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-process-command-new",
            "owner": "type.fixture.std-process-command",
            "name": "new",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "program",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.process.Command" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/lib.rs",
                "symbol": "std.process.Command.new"
            }
        })
    }

    fn rust_path_constructor() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-path-path-new",
            "owner": "type.fixture.std-path-path",
            "name": "new",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "path",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.path.Path" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/path.rs",
                "symbol": "std.path.Path.new"
            }
        })
    }

    fn rust_path_method() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-path-path-join",
            "owner": "type.fixture.std-path-path",
            "name": "join",
            "member_kind": "method",
            "visibility": "public",
            "is_static": false,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "path",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.path.PathBuf" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/path.rs",
                "symbol": "std.path.Path.join"
            }
        })
    }

    #[cfg(debug_assertions)]
    fn rust_pathbuf_method() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-path-pathbuf-join",
            "owner": "type.fixture.std-path-pathbuf",
            "name": "join",
            "member_kind": "method",
            "visibility": "public",
            "is_static": false,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "path",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.path.PathBuf" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/path.rs",
                "symbol": "std.path.PathBuf.join"
            }
        })
    }

    #[cfg(debug_assertions)]
    fn activate_path_chain_model(fixture: &AnalyzerFixture) {
        let pack = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-path-chain",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-path-chain",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.path", "module"),
                        rust_type("std.path.Path", "struct"),
                        rust_type("std.path.PathBuf", "struct")
                    ],
                    "members": [
                        rust_path_constructor(),
                        rust_path_method(),
                        rust_pathbuf_method()
                    ],
                    "relations": []
                }
            }]
        });
        activate_model_pack(fixture, pack, "fixture.rust-path-chain", "std");
    }

    fn rust_vec_constructor() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-vec-vec-with-capacity",
            "owner": "type.fixture.std-vec-vec",
            "name": "with_capacity",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "capacity",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.vec.Vec" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/alloc/src/vec/mod.rs",
                "symbol": "std.vec.Vec.with_capacity"
            }
        })
    }

    fn rust_method() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-process-command-arg",
            "owner": "type.fixture.std-process-command",
            "name": "arg",
            "member_kind": "method",
            "visibility": "public",
            "is_static": false,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "arg",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.process.Command" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/process.rs",
                "symbol": "std.process.Command.arg"
            }
        })
    }
}

mod payload_projection;
pub(super) use payload_projection::select as selected_payload_projection;
