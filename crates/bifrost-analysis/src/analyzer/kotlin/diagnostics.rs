//! The analysis-side entry point for Kotlin's semantic diagnostics.
//!
//! The collector and the suppression contract it implements moved to
//! [`brokk_bifrost_jvm::kotlin::diagnostics`]. What stays is the downcast that
//! produces the Kotlin resolution surface and the lowering into the framework's
//! own [`SemanticDiagnostic`].

use crate::analyzer::{IAnalyzer, KotlinAnalyzer, ProjectFile, resolve_analyzer};
use brokk_bifrost_jvm::kotlin::diagnostics::KotlinSemanticDiagnostic;
use brokk_bifrost_jvm::realm::JvmSourceRealm;

/// Collect high-confidence Kotlin unresolved-type diagnostics for `file`.
///
/// `realm` widens resolution across the whole JVM source realm (Java/Scala
/// siblings in the same workspace) when supplied by `MultiAnalyzer`; a bare
/// `KotlinAnalyzer` passes `None` and resolves against its own declarations
/// and the external dependency index only.
pub(crate) fn collect_kotlin_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> Vec<KotlinSemanticDiagnostic> {
    let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) else {
        return Vec::new();
    };
    brokk_bifrost_jvm::kotlin::diagnostics::collect_kotlin_semantic_diagnostics(
        analyzer, kotlin, file, source, realm,
    )
}
