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

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use std::sync::Arc;

use crate::analyzer::rust::crate_identity::RustOverlayCrates;

use crate::analyzer::semantic_model::DependencyDiscoveryEvidence;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::RustAnalyzer;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
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
    let support =
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            analyzer,
            Language::None,
        );
    let external = RetainedRustDependencies {
        overlay: analyzer.semantic_model_overlay(),
        discovery: analyzer.dependency_discovery_evidence(Language::Rust),
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let report = brokk_bifrost_rust::diagnostics::collect_rust_semantic_diagnostics(
        rust,
        scope.token(),
        &support,
        &external,
        file,
        source,
    );
    brokk_bifrost_analysis::analyzer::semantic_model::runtime::degrade_pack_gap_absences(
        analyzer, report,
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

    fn is_module_surface(&self, segments: &[String]) -> bool {
        self.crates().is_module_surface(segments)
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

    use crate::analyzer::rust::diagnostics::collect_rust_semantic_diagnostics;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use crate::analyzer::RustAnalyzer;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnostic;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnosticOutcome;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReportStatus;

    #[track_caller]
    fn rust_project(files: &[(&str, &str)]) -> (tempfile::TempDir, RustAnalyzer) {
        crate::analyzer::rust::test_support::lazy_project(files)
    }

    fn report_for(
        analyzer: &RustAnalyzer,
        rel_path: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
        let file = ProjectFile::new(analyzer.project().root().to_path_buf(), rel_path);
        let source = analyzer.project().read_source(&file).unwrap();
        collect_rust_semantic_diagnostics(analyzer, &file, &source)
    }

    fn diagnostics_for(analyzer: &RustAnalyzer, rel_path: &str) -> Vec<SemanticDiagnostic> {
        report_for(analyzer, rel_path).into_diagnostics()
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

    #[test]
    fn unavailable_canonical_routes_do_not_prove_a_symbol_absent() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"diagnostics\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod part;\nfn run() { crate::part::missing(); }\n",
            )
            .file("src/part.rs", "pub fn target() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let report = report_for(&analyzer, "src/lib.rs");
        assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
        assert!(report.outcomes().iter().any(|outcome| matches!(outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(reason,
                    crate::analyzer::SemanticDiagnosticIncompleteReason::CanonicalFactsUnavailable { .. }
                ))
        )), "{:?}", report.outcomes());
        assert!(report.into_diagnostics().is_empty());
        assert!(scope.store_error().is_some());
    }

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
}
