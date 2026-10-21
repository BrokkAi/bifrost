// Preserve explicit engine visibility when an overlay shadows a public glob.
#![allow(hidden_glob_reexports)]
// Boundary-visible child modules keep their qualified paths when short names collide.
#![allow(ambiguous_glob_reexports)]

//! Language-neutral executable semantics and adapter contracts.

pub use brokk_bifrost_semantic::analyzer::semantic::common;
pub use brokk_bifrost_semantic::analyzer::semantic::*;
/// Implement the public semantic-provider lifecycle by forwarding to one
/// stateless language lowerer through the analyzer's shared tree-sitter core.
/// Keeping this pair together prevents each lifecycle addition from requiring
/// another copy in every language adapter.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_program_semantics_provider {
    ($analyzer:ty, |$context:ident| $lowerer:expr) => {
        impl $crate::analyzer::semantic::ProgramSemanticsProvider for $analyzer {
            fn capabilities(&self) -> $crate::analyzer::semantic::SemanticCapabilities {
                let $context = self;
                let lowerer = $lowerer;
                $crate::analyzer::semantic::service::ProgramSemanticsLowerer::capabilities(&lowerer)
            }

            fn procedure_inventory(
                &self,
                file: &$crate::analyzer::ProjectFile,
                request: &mut $crate::analyzer::semantic::SemanticRequest<'_>,
            ) -> Result<
                Option<$crate::analyzer::semantic::SemanticProcedureInventory>,
                $crate::analyzer::semantic::SemanticProviderError,
            > {
                let $context = self;
                let lowerer = $lowerer;
                let scope = $crate::analyzer::AnalyzerQueryScope::new(self);
                let Some(prepared) = self.inner.prepared_syntax(
                    brokk_bifrost_core::analyzer::query_token::QueryScope::token(&scope),
                    file,
                ) else {
                    return Err($crate::analyzer::semantic::SemanticProviderError::internal(
                        "procedure inventory source is unavailable".to_owned(),
                    ));
                };
                $crate::analyzer::semantic::service::ProgramSemanticsLowerer::procedure_inventory(
                    &lowerer,
                    file,
                    &prepared,
                    request.budget,
                    request.cancellation,
                )
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

#[doc(hidden)]
pub use crate::impl_program_semantics_provider;
pub mod cfg_algorithms;
pub mod icfg;
pub mod ids;
pub mod ir;
pub mod leases;
#[doc(hidden)]
pub mod lowering;
pub mod oracle;
pub mod partial_flow;
pub mod property_reaching;
pub mod render;
pub mod service;
pub mod statement_entries;
#[doc(hidden)]
pub mod structural_identity;
pub mod type_flow;
pub mod value_type_barriers;
pub mod workspace_oracle;
pub use crate::cancellation::CancellationToken;
pub use icfg::*;
pub(crate) use inventory::*;
pub(crate) use lowering::*;
pub use oracle::*;
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
pub use value_type_barriers::*;
pub use workspace_oracle::*;
pub mod local_value_origins;
pub use local_value_origins::*;

// Keep the oracle module distinct from the workspace implementation overlay.
pub use oracle::{dispatch, heap};
