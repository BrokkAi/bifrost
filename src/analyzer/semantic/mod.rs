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
    ($analyzer:ty, $lowerer:expr) => {
        impl $crate::analyzer::semantic::ProgramSemanticsProvider for $analyzer {
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
        }
    };
}

pub(crate) use impl_program_semantics_provider;

pub mod capabilities;
pub(crate) mod cfg;
pub mod icfg;
pub mod ids;
pub mod ir;
pub(crate) mod lowering;
pub mod oracle;
pub mod provider;
pub mod render;
pub(crate) mod service;
pub(crate) mod workspace_oracle;

pub use crate::cancellation::CancellationToken;
pub use capabilities::*;
pub use icfg::*;
pub use ids::*;
pub use ir::*;
pub(crate) use lowering::*;
pub use oracle::*;
pub use provider::*;
pub use render::*;
pub use workspace_oracle::*;
