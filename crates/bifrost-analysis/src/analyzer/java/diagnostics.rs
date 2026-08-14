//! The downcast that produces the arguments of
//! [`brokk_bifrost_jvm::java::diagnostics::collect_java_semantic_diagnostics`].
//!
//! Both call sites -- `JavaAnalyzer`'s own `semantic_diagnostics` and
//! `MultiAnalyzer`'s Java arm -- pass the *dispatching* analyzer, because the
//! declaration index and the semantic-model overlay a Java file is judged
//! against are the dispatcher's, not the Java analyzer's: that is what lets a
//! Java file name a Kotlin or Scala sibling's type without being reported as
//! unrecognized.

use crate::analyzer::jvm::JvmOverlayModel;
use crate::analyzer::{IAnalyzer, JavaAnalyzer, ProjectFile, SemanticDiagnosticReport};

pub(crate) fn collect_java_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(java) = crate::analyzer::resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    brokk_bifrost_jvm::java::diagnostics::collect_java_semantic_diagnostics(
        java,
        &analyzer.global_usage_definition_index(),
        &JvmOverlayModel(analyzer.semantic_model_overlay()),
        file,
        source,
    )
}
