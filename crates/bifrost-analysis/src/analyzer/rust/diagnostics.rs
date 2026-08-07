//! The analysis-side entry point for Rust's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_rust::diagnostics`]. What stays
//! here is what that crate cannot name: the downcast that produces the Rust
//! usage source, and the retained dependency surface -- the published
//! semantic-model overlay plus the Cargo discovery evidence -- that answers
//! what the activated API packs prove about a crate a path enters.
//!
//! Both call sites pass the *dispatching* analyzer, because the overlay and the
//! discovery evidence are published on the analyzer a host activated packs
//! against, which in a workspace is the composite one, not the Rust delegate.
//!
//! Nothing on this path runs `cargo` or `rustdoc`, reads `target/doc`, or
//! triggers pack production. Both accessors below read snapshot state a host
//! filled earlier; an empty one is an unknown boundary, never a reason to go
//! and build it.

use std::sync::Arc;

use crate::analyzer::rust::crate_identity::RustOverlayCrates;
use crate::analyzer::semantic_model::{DependencyDiscoveryEvidence, SemanticModelOverlay};
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::{
    IAnalyzer, Language, ProjectFile, RustAnalyzer, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport, resolve_analyzer,
};
use brokk_bifrost_rust::diagnostics::{RustCrateSurface, RustExternalEvidence};

pub(crate) fn collect_rust_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "no Rust analyzer serves this file".to_string(),
            }],
        );
        return report;
    };
    let support = analyzer.global_usage_definition_index();
    let external = RetainedRustDependencies {
        overlay: analyzer.semantic_model_overlay(),
        discovery: analyzer.dependency_discovery_evidence(Language::Rust),
    };
    brokk_bifrost_rust::diagnostics::collect_rust_semantic_diagnostics(
        rust, &support, &external, file, source,
    )
}

/// The external Rust facts a diagnostic request is allowed to read: what an
/// activation published, and what a Cargo discovery run retained.
struct RetainedRustDependencies {
    overlay: Option<Arc<SemanticModelOverlay>>,
    discovery: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl RetainedRustDependencies {
    fn crates(&self) -> RustOverlayCrates<'_> {
        RustOverlayCrates::new(self.overlay.as_deref())
    }
}

impl RustExternalEvidence for RetainedRustDependencies {
    fn crate_surface(&self, crate_name: &str) -> RustCrateSurface {
        self.crates().crate_surface(crate_name)
    }

    fn publishes_path(&self, segments: &[String]) -> bool {
        self.crates().publishes_path(segments)
    }

    fn unindexed_boundary(&self, crate_name: &str) -> BoundaryStatus {
        // Retained discovery evidence (#1601): the Cargo dependency graph
        // declares this crate and nothing indexed it, or discovery could not
        // read everything the build declared, so the item may well be there.
        // Where no discovery has run, nothing is retained and
        // `ExternalUnknown` is the honest answer.
        //
        // A Rust crate name carries no dots, so `declares_module_path` is an
        // exact match against the package and crate identities discovery
        // recorded. A dependency Cargo renames is declared under its real
        // package name rather than the source spelling, so a renamed crate no
        // pack indexed reads as unknown rather than declared. That errs toward
        // less evidence, which can only suppress, never accuse.
        let declared = self.discovery.as_ref().is_some_and(|evidence| {
            evidence.truncated() || evidence.declares_module_path(crate_name)
        });
        if declared {
            BoundaryStatus::ExternalDeclaredUnindexed
        } else {
            BoundaryStatus::ExternalUnknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::collect_rust_semantic_diagnostics;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::{
        Language, ProjectFile, RustAnalyzer, SemanticDiagnostic, SemanticDiagnosticOutcome,
        SemanticDiagnosticReportStatus, TestProject,
    };
    use brokk_bifrost_rust::diagnostics::RUST_UNRECOGNIZED_SYMBOL;
    use tempfile::tempdir;

    fn rust_project(files: &[(&str, &str)]) -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempdir().unwrap();
        for (path, contents) in files {
            ProjectFile::new(temp.path().to_path_buf(), path)
                .write(*contents)
                .unwrap();
        }
        let project = TestProject::new(temp.path().to_path_buf(), Language::Rust);
        let analyzer = RustAnalyzer::from_project(project);
        (temp, analyzer)
    }

    fn report_for(
        analyzer: &RustAnalyzer,
        rel_path: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let file = ProjectFile::new(analyzer.project().root().to_path_buf(), rel_path);
        let source = analyzer.project().read_source(&file).unwrap();
        collect_rust_semantic_diagnostics(analyzer, &file, &source)
    }

    fn diagnostics_for(analyzer: &RustAnalyzer, rel_path: &str) -> Vec<SemanticDiagnostic> {
        report_for(analyzer, rel_path).into_diagnostics()
    }

    #[test]
    fn rust_semantic_diagnostics_report_unknown_type_and_value_references() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            r#"
fn run(input: MissingType) {
    missing_value;
    missing_function();
}
"#,
        )]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert_eq!(3, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == RUST_UNRECOGNIZED_SYMBOL)
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_value"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_function"))
        );
    }

    /// Every error carries a complete absence proof, and a resolved reference
    /// is recorded rather than passed over in silence.
    #[test]
    fn rust_semantic_diagnostics_record_proof_for_every_lookup() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            "fn run() {\n    let bound = 1;\n    bound;\n    missing_value;\n}\n",
        )]);

        let report = report_for(&analyzer, "src/main.rs");
        assert!(
            report
                .outcomes()
                .iter()
                .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Resolved { .. })),
            "{:#?}",
            report.outcomes()
        );
        assert_eq!(
            1,
            report
                .outcomes()
                .iter()
                .filter(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Absent(_)))
                .count(),
            "{:#?}",
            report.outcomes()
        );
    }

    #[test]
    fn rust_semantic_diagnostics_suppress_locals_declarations_imports_and_module_paths() {
        let (_temp, analyzer) = rust_project(&[
            (
                "src/models.rs",
                "pub struct Service;\npub type Handler = fn();\npub fn build_service() -> Service { Service }\n",
            ),
            (
                "src/main.rs",
                r#"
mod models;
use crate::models::{Service as RenamedService, Handler, build_service};

struct LocalType;
type LocalHandler = fn();
fn local_function() {}

fn run(param: RenamedService, handler: Handler, local_handler: LocalHandler) {
    let local = build_service();
    let typed: LocalType = LocalType;
    local_function();
    crate::models::build_service();
    param;
    handler;
    local_handler;
    local;
    typed;
}
"#,
            ),
        ]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn rust_semantic_diagnostics_handle_rust_item_scope_edges() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            r#"
fn nested_item_does_not_capture_local() {
    let captured = 1;
    fn inner() {
        captured;
    }
}

fn block_item_is_visible_before_declaration() {
    helper();
    fn helper() {}
}

trait Service {
    fn get<T>(input: T) -> T;
}

struct Boxed<T> {
    value: T,
}

fn leaked_generic(value: T) {}
"#,
        )]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("captured")),
            "{diagnostics:#?}"
        );
        assert_eq!(
            1,
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("`T`"))
                .count(),
            "{diagnostics:#?}"
        );
    }

    /// None of these becomes an error, and each states the typed reason it was
    /// not judged instead of vanishing.
    #[test]
    fn rust_semantic_diagnostics_suppress_builtin_macro_cfg_external_and_glob_uncertainty() {
        let (_temp, analyzer) = rust_project(&[(
            "src/main.rs",
            r#"
use external_crate::ExternalType;
use crate::missing::*;

#[cfg(feature = "generated")]
fn generated(value: CfgType) {
    cfg_value;
}

fn run(value: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{:?}", value);
    external_crate::call();
    let _: ExternalType = external_crate::make();
    macro_rules! local_macro { () => { generated_name } }
    local_macro!();
    Ok(())
}
"#,
        )]);

        let report = report_for(&analyzer, "src/main.rs");
        assert!(
            report.diagnostics().is_empty(),
            "{:#?}",
            report.diagnostics()
        );
        assert_eq!(
            SemanticDiagnosticReportStatus::Incomplete,
            report.status(),
            "{:#?}",
            report.outcomes()
        );
    }

    /// A file the parser could not read states that it judged nothing, rather
    /// than reporting an empty complete result that looks like a clean file.
    #[test]
    fn rust_semantic_diagnostics_state_malformed_files() {
        let (_temp, analyzer) =
            rust_project(&[("src/main.rs", "fn run( {\n    missing_value;\n}\n")]);

        let report = report_for(&analyzer, "src/main.rs");
        assert!(
            report.diagnostics().is_empty(),
            "{:#?}",
            report.diagnostics()
        );
        assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                    if reasons.iter().any(|reason| format!("{reason:?}").contains("parse errors"))
            )),
            "{:#?}",
            report.outcomes()
        );
    }

    #[test]
    fn rust_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("fn run() {\n");
        for index in 0..250 {
            source.push_str(&format!("    missing_{index};\n"));
        }
        source.push_str("}\n");
        let (_temp, analyzer) = rust_project(&[("src/main.rs", &source)]);

        let diagnostics = diagnostics_for(&analyzer, "src/main.rs");
        assert_eq!(
            brokk_bifrost_rust::diagnostics::MAX_RUST_SEMANTIC_DIAGNOSTICS,
            diagnostics.len()
        );
    }
}
