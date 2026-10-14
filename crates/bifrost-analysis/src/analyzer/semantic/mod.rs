//! Language-neutral executable semantics and adapter contracts.

macro_rules! count_idents {
    ($($value:ident),* $(,)?) => {
        <[()]>::len(&[$(count_idents!(@unit $value)),*])
    };
    (@unit $value:ident) => { () };
}

/// Implement the public semantic-provider lifecycle by forwarding to one
/// stateless language lowerer through the analyzer's shared tree-sitter core.
/// Keeping this pair together prevents each lifecycle addition from requiring
/// another copy in every language adapter.
macro_rules! impl_program_semantics_provider {
    ($analyzer:ty, |$context:ident| $lowerer:expr) => {
        impl $crate::analyzer::semantic::ProgramSemanticsProvider for $analyzer {
            fn capabilities(&self) -> $crate::analyzer::semantic::SemanticCapabilities {
                let $context = self;
                let lowerer = $lowerer;
                $crate::analyzer::semantic::service::ProgramSemanticsLowerer::capabilities(&lowerer)
            }

            fn current_artifact_source(
                &self,
                file: &$crate::analyzer::ProjectFile,
                max_source_bytes: usize,
            ) -> Result<
                Option<$crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                let $context = self;
                let lowerer = $lowerer;
                self.inner.current_semantic_artifact_source_with_lowerer(
                    &lowerer,
                    file,
                    max_source_bytes,
                )
            }

            fn storage_language_key_for_file(
                &self,
                file: &$crate::analyzer::ProjectFile,
            ) -> Option<$crate::analyzer::semantic::StorageLanguageKey> {
                Some(
                    $crate::analyzer::semantic::StorageLanguageKey::from_adapter(
                        $crate::analyzer::tree_sitter_analyzer::LanguageAdapter::storage_language_key_for_file(
                            self.inner.adapter(),
                            file,
                        ),
                    ),
                )
            }

            fn materialize(
                &self,
                file: &$crate::analyzer::ProjectFile,
                request: &mut $crate::analyzer::semantic::SemanticRequest<'_>,
            ) -> Result<
                $crate::analyzer::semantic::SemanticOutcome<
                    std::sync::Arc<$crate::analyzer::semantic::SemanticArtifact>,
                >,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                let $context = self;
                let lowerer = $lowerer;
                self.inner
                    .materialize_semantics_with_lowerer(&lowerer, file, request)
            }

            fn stored_partial_flows(
                &self,
                file: &$crate::analyzer::ProjectFile,
                key: &$crate::analyzer::semantic::SemanticArtifactKey,
                procedure: $crate::analyzer::semantic::ProcedureId,
            ) -> Result<
                Option<$crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                self.inner.stored_partial_flows(file, key, procedure)
            }

            fn has_complete_semantic_ir_rows(
                &self,
                file: &$crate::analyzer::ProjectFile,
                key: &$crate::analyzer::semantic::SemanticArtifactKey,
            ) -> Result<bool, $crate::analyzer::semantic::SemanticProviderError> {
                self.inner.has_complete_semantic_ir_rows(file, key)
            }
        }
    };
    ($analyzer:ty, $lowerer:expr) => {
        impl $crate::analyzer::semantic::ProgramSemanticsProvider for $analyzer {
            fn capabilities(&self) -> $crate::analyzer::semantic::SemanticCapabilities {
                let lowerer = $lowerer;
                $crate::analyzer::semantic::service::ProgramSemanticsLowerer::capabilities(&lowerer)
            }

            fn current_artifact_source(
                &self,
                file: &$crate::analyzer::ProjectFile,
                max_source_bytes: usize,
            ) -> Result<
                Option<$crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                let lowerer = $lowerer;
                self.inner.current_semantic_artifact_source_with_lowerer(
                    &lowerer,
                    file,
                    max_source_bytes,
                )
            }

            fn storage_language_key_for_file(
                &self,
                file: &$crate::analyzer::ProjectFile,
            ) -> Option<$crate::analyzer::semantic::StorageLanguageKey> {
                Some(
                    $crate::analyzer::semantic::StorageLanguageKey::from_adapter(
                        $crate::analyzer::tree_sitter_analyzer::LanguageAdapter::storage_language_key_for_file(
                            self.inner.adapter(),
                            file,
                        ),
                    ),
                )
            }

            fn materialize(
                &self,
                file: &$crate::analyzer::ProjectFile,
                request: &mut $crate::analyzer::semantic::SemanticRequest<'_>,
            ) -> Result<
                $crate::analyzer::semantic::SemanticOutcome<
                    std::sync::Arc<$crate::analyzer::semantic::SemanticArtifact>,
                >,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                let lowerer = $lowerer;
                self.inner
                    .materialize_semantics_with_lowerer(&lowerer, file, request)
            }

            fn stored_partial_flows(
                &self,
                file: &$crate::analyzer::ProjectFile,
                key: &$crate::analyzer::semantic::SemanticArtifactKey,
                procedure: $crate::analyzer::semantic::ProcedureId,
            ) -> Result<
                Option<$crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                self.inner.stored_partial_flows(file, key, procedure)
            }

            fn has_complete_semantic_ir_rows(
                &self,
                file: &$crate::analyzer::ProjectFile,
                key: &$crate::analyzer::semantic::SemanticArtifactKey,
            ) -> Result<bool, $crate::analyzer::semantic::SemanticProviderError> {
                self.inner.has_complete_semantic_ir_rows(file, key)
            }
        }
    };
}

pub(crate) use impl_program_semantics_provider;

pub(crate) fn hash_arc_key<T: ?Sized, K: std::hash::Hash, H: std::hash::Hasher>(
    owner: &std::sync::Arc<T>,
    key: &K,
    state: &mut H,
) {
    std::hash::Hash::hash(&std::sync::Arc::as_ptr(owner), state);
    std::hash::Hash::hash(key, state);
}

pub(crate) fn completeness_reason_bytes(completeness: &EvidenceCompleteness) -> usize {
    completeness.retained_heap_bytes()
}

pub(crate) const fn procedure_relays_receiver_capture(kind: ProcedureKind) -> bool {
    matches!(kind, ProcedureKind::Lambda)
}

pub mod binding_origins;
pub mod capabilities;
pub(crate) mod cfg;
pub mod cfg_algorithms;
pub mod icfg;
pub mod ids;
pub(crate) mod inventory;
pub mod ir;
pub mod leases;
pub(crate) mod lowering;
pub mod oracle;
pub mod partial_flow;
pub mod property_reaching;
pub mod provider;
pub mod render;
pub mod service;
pub mod statement_entries;
pub(crate) mod structural_identity;
pub mod type_flow;
pub mod workspace_oracle;

#[cfg(test)]
pub(crate) fn floating_value_for_test(value: f64) -> SemanticValueKind {
    SemanticValueKind::FloatingPoint {
        bits: value.to_bits(),
    }
}

pub use crate::cancellation::CancellationToken;
pub use binding_origins::*;
pub use capabilities::*;
pub use icfg::*;
pub use ids::*;
pub(crate) use inventory::*;
pub use ir::*;
pub use leases::*;
pub(crate) use lowering::*;
pub use oracle::*;
pub use property_reaching::*;
pub use provider::*;
pub use render::*;
pub use service::semantic_artifact_retained_bytes;
#[cfg(any(test, feature = "test-support"))]
pub use service::{SemanticCacheRevivalCensus, SemanticMaterializationCensus};
pub use statement_entries::*;
pub use type_flow::{
    CallGuardOutcome, ClassAtom, ClassBodyMemberBinding, ClassHierarchy, ClassIdentity, ClassSeed,
    ConstructorResultEvidence, ConstructorResultOrigin, DispatchHint, DispatchHintCallSiteKey,
    DispatchHintSet, DispatchHints, DynamicFieldNameSet, DynamicFieldWrite, ExactResultProducer,
    ExternalMemberDeclaration, MemberAccessKind, MemberAccessQuery, MemberDeclaration,
    MemberLookup, MemberLookupHit, MemberReceiverQuery, NarrowingVerdict,
    NormalReturnTypeConstraint, SourceSite, SourceSiteKind, TypeFlowAdapter, UnknownReason,
    source_site_kind_tag, type_flow_adapter, validate_prepared_syntax_for_procedure,
};
pub use workspace_oracle::*;

pub mod local_value_origins;
pub use local_value_origins::*;
