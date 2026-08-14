//! The analysis-side entry point for Kotlin's semantic diagnostics.
//!
//! The collector and the proof contract it implements live in
//! [`brokk_bifrost_jvm::kotlin::diagnostics`]. What stays is the downcast that
//! produces the Kotlin resolution surface, and the narrowing of the dispatching
//! analyzer's active overlay into the view that crate can see.
//!
//! Both the enclosing-declaration lookup and the overlay come from the
//! *dispatching* analyzer, not the Kotlin one: in a mixed workspace that is
//! what lets a Kotlin file name a Java or Scala sibling's type, and be judged
//! against the dependency models the whole workspace activated.

use crate::analyzer::jvm::JvmOverlayModel;
use crate::analyzer::{
    IAnalyzer, KotlinAnalyzer, ProjectFile, SemanticDiagnosticReport, resolve_analyzer,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;

/// Collect proof-gated Kotlin unresolved-type diagnostics for `file`.
///
/// `realm` widens resolution across the whole JVM source realm (Java/Scala
/// siblings in the same workspace) when supplied by `MultiAnalyzer`; a bare
/// `KotlinAnalyzer` passes `None`.
pub(crate) fn collect_kotlin_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> SemanticDiagnosticReport {
    let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    brokk_bifrost_jvm::kotlin::diagnostics::collect_kotlin_semantic_diagnostics(
        analyzer,
        kotlin,
        file,
        source,
        realm,
        &JvmOverlayModel(analyzer.semantic_model_overlay()),
    )
}
