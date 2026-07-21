//! TypeScript and TSX provider entry point for the shared JS/TS lowerer.

use std::sync::Arc;

use crate::analyzer::js_ts::semantic::JsTsSemanticLowerer;
use crate::analyzer::semantic::{
    ProgramSemanticsProvider, SemanticArtifact, SemanticArtifactKey, SemanticOutcome,
    SemanticProviderError, SemanticRequest,
};
use crate::analyzer::{ProjectFile, TypescriptAnalyzer};

impl ProgramSemanticsProvider for TypescriptAnalyzer {
    fn current_artifact_key(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        self.inner.current_semantic_artifact_key_with_lowerer(
            &JsTsSemanticLowerer::typescript(),
            file,
            max_source_bytes,
        )
    }

    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        self.inner.materialize_semantics_with_lowerer(
            &JsTsSemanticLowerer::typescript(),
            file,
            request,
        )
    }
}
