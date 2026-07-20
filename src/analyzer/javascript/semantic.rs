//! JavaScript and JSX provider entry point for the shared JS/TS lowerer.

use std::sync::Arc;

use crate::analyzer::js_ts::semantic::JsTsSemanticLowerer;
use crate::analyzer::semantic::{
    ProgramSemanticsProvider, SemanticArtifact, SemanticOutcome, SemanticProviderError,
    SemanticRequest,
};
use crate::analyzer::{JavascriptAnalyzer, ProjectFile};

impl ProgramSemanticsProvider for JavascriptAnalyzer {
    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        self.inner.materialize_semantics_with_lowerer(
            &JsTsSemanticLowerer::javascript(),
            file,
            request,
        )
    }
}
