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

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use crate::analyzer::JavaAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

pub(crate) fn collect_java_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(java) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        JavaAnalyzer,
    >(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    let report = brokk_bifrost_jvm::java::diagnostics::collect_java_semantic_diagnostics(
        java,
        token,
        &brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(analyzer, Language::None),
        &JvmOverlayModel::new(analyzer),
        file,
        source,
    );
    brokk_bifrost_analysis::analyzer::semantic_model::runtime::degrade_pack_gap_absences(
        analyzer, report,
    )
}
