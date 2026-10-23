//! The downcast that produces the arguments of
//! [`brokk_bifrost_jvm::scala::diagnostics::collect_scala_semantic_diagnostics`].
//!
//! Both call sites -- `ScalaAnalyzer`'s own `semantic_diagnostics` and
//! `MultiAnalyzer`'s Scala arm -- pass the *dispatching* analyzer, because the
//! active dependency model a Scala file is judged against is the dispatcher's,
//! not the Scala analyzer's. `acquire_active_semantic_models` publishes onto the
//! analyzer a host holds, which in a mixed workspace is the `MultiAnalyzer`;
//! a delegate's own overlay cell stays empty. Reading the delegate's would make
//! every externally-modelled Scala type look absent, which is exactly the false
//! positive #1619 exists to prevent.

use crate::analyzer::jvm::JvmOverlayModel;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::ScalaAnalyzer;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

pub(crate) fn collect_scala_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    let report = brokk_bifrost_jvm::scala::diagnostics::collect_scala_semantic_diagnostics(
        scala,
        file,
        source,
        &JvmOverlayModel::new(analyzer),
    );
    brokk_bifrost_analysis::analyzer::semantic_model::runtime::degrade_pack_gap_absences(
        analyzer, report,
    )
}
