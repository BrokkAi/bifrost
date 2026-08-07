//! The analysis-side entry point for Python's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_python::diagnostics`]. What
//! stays here is what that crate cannot name: the downcast that produces the
//! Python analysis source, and the retained environment surface -- the
//! published semantic-model overlay plus the dependency-discovery evidence --
//! that answers what the activated environment packs prove about an imported
//! module.
//!
//! Both call sites pass the *dispatching* analyzer, because the overlay and
//! the discovery evidence are published on the analyzer a host activated packs
//! against, which in a workspace is the composite one, not the Python
//! delegate.

use std::sync::Arc;

use crate::analyzer::python::external::PYTHON_UNENUMERATED_BINDING;
use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, RetainedDiscoveryVerdict, SemanticModelCompleteness,
    SemanticModelOverlay, SemanticModelOverlayDisposition, SemanticModelSymbol,
    SemanticModelSymbolKind, TypeIdentity, retained_discovery_verdict, type_declaration_id,
};
use crate::analyzer::structural::BoundaryStatus;
use crate::analyzer::{
    IAnalyzer, Language, ProjectFile, PythonAnalyzer, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport, resolve_analyzer,
};
use brokk_bifrost_python::diagnostics::{PythonEnvironmentBoundary, PythonEnvironmentSurface};

/// The ecosystem every Python declaration identity is minted under, in the
/// environment pack producer and here.
const PYTHON_ECOSYSTEM: &str = "python";

/// PEP 562's module-level attribute hook.
const PYTHON_MODULE_GETATTR: &str = "__getattr__";

pub(crate) fn collect_python_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "no Python analyzer serves this file".to_string(),
            }],
        );
        return report;
    };
    let support = analyzer.global_usage_definition_index();
    let environment = RetainedPythonEnvironment {
        overlay: analyzer.semantic_model_overlay(),
        evidence: analyzer.dependency_discovery_evidence(Language::Python),
    };
    brokk_bifrost_python::diagnostics::collect_python_semantic_diagnostics(
        py,
        &support,
        &environment,
        file,
        source,
    )
}

/// The environment facts a diagnostic request is allowed to read: what an
/// activation published, and what a discovery run retained. Both are analyzer
/// state a host produced earlier. Nothing here starts discovery, reads a
/// distribution, or executes Python.
struct RetainedPythonEnvironment {
    overlay: Option<Arc<SemanticModelOverlay>>,
    evidence: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl RetainedPythonEnvironment {
    /// Why a module no active pack publishes cannot be judged.
    fn missing_evidence(&self, module_path: &str) -> PythonEnvironmentBoundary {
        let reason = match retained_discovery_verdict(self.evidence.as_deref(), module_path) {
            RetainedDiscoveryVerdict::NoDiscovery | RetainedDiscoveryVerdict::Undeclared => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                }
            }
            RetainedDiscoveryVerdict::Truncated => SemanticDiagnosticIncompleteReason::Truncated,
            RetainedDiscoveryVerdict::Declared => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                }
            }
        };
        PythonEnvironmentBoundary::Incomplete(reason)
    }

    /// The module surface an active pack publishes for `module_path`, or the
    /// verdict that stands in for it.
    ///
    /// The lookup is by declaration identity rather than by name, so it cannot
    /// be satisfied by a same-named symbol from another module.
    fn module_surface<'a>(
        &self,
        overlay: &'a SemanticModelOverlay,
        module_path: &str,
    ) -> Result<&'a SemanticModelSymbol, PythonEnvironmentBoundary> {
        let matched = overlay.symbols_with_id(&python_declaration_id(module_path));
        match matched.disposition {
            SemanticModelOverlayDisposition::Empty => Err(self.missing_evidence(module_path)),
            SemanticModelOverlayDisposition::Conflict => {
                Err(PythonEnvironmentBoundary::Incomplete(
                    SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!(
                            "more than one active semantic pack declares Python module `{module_path}`"
                        ),
                    },
                ))
            }
            SemanticModelOverlayDisposition::Unique => {
                let symbol = matched
                    .records
                    .first()
                    .expect("a unique overlay match has one record");
                if symbol.kind != SemanticModelSymbolKind::Module {
                    // The owner is published, but as a type rather than a
                    // module surface. Proving a type's member absent needs the
                    // owner's whole inherited surface, which this pass does
                    // not resolve (#1622).
                    return Err(PythonEnvironmentBoundary::Incomplete(
                        SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                            detail: format!(
                                "`{module_path}` is an indexed Python type, not a module surface"
                            ),
                        },
                    ));
                }
                Ok(symbol)
            }
        }
    }
}

impl PythonEnvironmentSurface for RetainedPythonEnvironment {
    fn module_boundary(&self, module_path: &str) -> PythonEnvironmentBoundary {
        let Some(overlay) = self.overlay.as_deref() else {
            return self.missing_evidence(module_path);
        };
        match self.module_surface(overlay, module_path) {
            Ok(_) => PythonEnvironmentBoundary::Indexed,
            Err(boundary) => boundary,
        }
    }

    fn module_member_boundary(&self, module_path: &str, member: &str) -> PythonEnvironmentBoundary {
        let Some(overlay) = self.overlay.as_deref() else {
            return self.missing_evidence(module_path);
        };
        let module = match self.module_surface(overlay, module_path) {
            Ok(module) => module,
            Err(boundary) => return boundary,
        };
        // A submodule, class, or type alias the module declares is published
        // as its own qualified declaration.
        if !overlay
            .symbols_with_id(&python_declaration_id(&format!("{module_path}.{member}")))
            .records
            .is_empty()
        {
            return PythonEnvironmentBoundary::Indexed;
        }
        let members = overlay.members_of(&module.id);
        if members.records.iter().any(|record| record.name == member) {
            return PythonEnvironmentBoundary::Indexed;
        }
        // PEP 562: a module `__getattr__` answers any name at run time, so a
        // miss against the published surface proves nothing.
        if members
            .records
            .iter()
            .any(|record| record.name == PYTHON_MODULE_GETATTR)
        {
            return PythonEnvironmentBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::DynamicBehavior {
                    detail: format!("Python module `{module_path}` defines `__getattr__`"),
                },
            );
        }
        // The producer recorded that this surface binds names it could not
        // enumerate, e.g. a wildcard re-export in the package's `__init__`.
        if members
            .records
            .iter()
            .any(|record| record.name == PYTHON_UNENUMERATED_BINDING)
        {
            return PythonEnvironmentBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::DynamicBehavior {
                    detail: format!(
                        "Python module `{module_path}` re-exports names its semantic pack could not enumerate"
                    ),
                },
            );
        }
        // A member identity duplicated inside one module says nothing about a
        // name that is not there; two packs declaring the whole module is the
        // conflict that matters, and `module_surface` already reported it.
        if module.provenance.completeness != SemanticModelCompleteness::Complete {
            // A partial surface is exactly the missing or dynamic-only stub
            // case: what it does publish is true, what it omits is unknown.
            return PythonEnvironmentBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: format!(
                        "the active semantic pack for Python module `{module_path}` is partial"
                    ),
                },
            );
        }
        PythonEnvironmentBoundary::Absent
    }
}

fn python_declaration_id(name: &str) -> String {
    type_declaration_id(TypeIdentity {
        ecosystem: PYTHON_ECOSYSTEM,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::collect_python_semantic_diagnostics;
    use crate::analyzer::structural::BoundaryStatus;
    use crate::analyzer::{
        Language, ProjectFile, PythonAnalyzer, SemanticDiagnostic, SemanticDiagnosticDomain,
        SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
        SemanticDiagnosticReportStatus, TestProject,
    };
    use brokk_bifrost_python::diagnostics::{
        MAX_PYTHON_SEMANTIC_DIAGNOSTICS, PYTHON_UNRECOGNIZED_SYMBOL,
    };
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: PythonAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn report_for(&self, rel_path: &str) -> SemanticDiagnosticReport {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_python_semantic_diagnostics(&self.analyzer, &file, &source)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<SemanticDiagnostic> {
            self.report_for(rel_path).into_diagnostics()
        }

        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().to_path_buf();
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(*source)
                .unwrap_or_else(|err| panic!("write {path}: {err}"));
        }
        let project = TestProject::new(root.clone(), Language::Python);
        let analyzer = PythonAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    fn incomplete_details(report: &SemanticDiagnosticReport) -> Vec<String> {
        report
            .outcomes()
            .iter()
            .filter_map(|outcome| match outcome {
                SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
                _ => None,
            })
            .flatten()
            .map(|reason| format!("{reason:?}"))
            .collect()
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_local_identifier() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    missing_value
"#,
        )]);

        let report = fixture.report_for("app.py");
        assert_eq!(1, report.diagnostics().len(), "{report:#?}");
        assert_eq!(PYTHON_UNRECOGNIZED_SYMBOL, report.diagnostics()[0].kind);
        assert!(report.diagnostics()[0].message.contains("missing_value"));
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Absent(proof)
                    if proof.boundary == BoundaryStatus::WorkspaceLocal
                        && matches!(proof.domain, SemanticDiagnosticDomain::LexicalScope { .. })
            )),
            "{report:#?}"
        );
    }

    #[test]
    fn python_semantic_diagnostics_suppress_known_names_and_imports() {
        let fixture = fixture(&[
            (
                "pkg/service.py",
                r#"
class Service:
    pass

def build():
    return Service()
"#,
            ),
            (
                "app.py",
                r#"
from pkg.service import Service, build

LOCAL = 1

class Runner:
    pass

def run(param):
    value = LOCAL
    for item in range(1):
        alias = item
    with open(__file__) as handle:
        data = handle
    try:
        build()
    except Exception as exc:
        print(exc)
    return Service(), Runner(), value, alias, data, param, True, None
"#,
            ),
        ]);

        let report = fixture.report_for("app.py");
        assert!(report.diagnostics().is_empty(), "{report:#?}");
        assert_eq!(SemanticDiagnosticReportStatus::Complete, report.status());
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Resolved {
                    boundary: BoundaryStatus::WorkspaceLocal,
                    ..
                }
            )),
            "{report:#?}"
        );
    }

    #[test]
    fn python_semantic_diagnostics_suppress_relative_imports_and_reexports() {
        let fixture = fixture(&[
            (
                "pkg/core.py",
                r#"
class Service:
    pass
"#,
            ),
            (
                "pkg/__init__.py",
                r#"
from .core import Service
"#,
            ),
            (
                "app.py",
                r#"
from pkg import Service

def run():
    return Service()
"#,
            ),
        ]);

        let report = fixture.report_for("app.py");
        assert!(report.diagnostics().is_empty(), "{report:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_type_references() {
        let fixture = fixture(&[(
            "app.py",
            r#"
class Known:
    pass

def run(value: Known) -> MissingType:
    return value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PYTHON_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingType"));
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_parameter_annotations_and_defaults() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(value: MissingType = missing_default):
    return value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_default"))
        );
    }

    #[test]
    fn python_semantic_diagnostics_check_attribute_receiver_but_not_unproven_member() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    return missing_client.fetch()
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].message.contains("missing_client"));
        assert!(!diagnostics[0].message.contains("fetch"));
    }

    #[test]
    fn python_semantic_diagnostics_handle_comprehension_scopes() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(rows):
    values = [item for item in rows if item]
    return item
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].message.contains("item"));
    }

    #[test]
    fn python_semantic_diagnostics_state_match_pattern_uncertainty() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(value):
    match value:
        case {"id": ident}:
            return ident
"#,
        )]);

        let report = fixture.report_for("app.py");
        assert!(report.diagnostics().is_empty(), "{report:#?}");
        assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
        assert!(
            incomplete_details(&report)
                .iter()
                .any(|detail| detail.contains("match statement")),
            "{report:#?}"
        );
    }

    #[test]
    fn python_semantic_diagnostics_resolve_builtins() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    try:
        raise RuntimeError("boom")
    except ValueError as exc:
        return exc
"#,
        )]);

        let report = fixture.report_for("app.py");
        assert!(report.diagnostics().is_empty(), "{report:#?}");
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Resolved {
                    boundary: BoundaryStatus::ExternalIndexed,
                    ..
                }
            )),
            "{report:#?}"
        );
    }

    #[test]
    fn python_semantic_diagnostics_state_unresolved_import_boundaries() {
        let fixture = fixture(&[
            (
                "external.py",
                r#"
from missing_package import *

def run():
    missing_name
"#,
            ),
            (
                "named.py",
                r#"
from missing_package import maybe

def run():
    maybe
"#,
            ),
        ]);

        let wildcard = fixture.report_for("external.py");
        assert!(wildcard.diagnostics().is_empty(), "{wildcard:#?}");
        assert!(
            incomplete_details(&wildcard)
                .iter()
                .any(|detail| detail.contains("DynamicBehavior")),
            "{wildcard:#?}"
        );

        let named = fixture.report_for("named.py");
        assert!(named.diagnostics().is_empty(), "{named:#?}");
        assert!(
            named.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                            boundary: BoundaryStatus::ExternalUnknown,
                        }
                    ))
            )),
            "{named:#?}"
        );
    }

    #[test]
    fn python_semantic_diagnostics_state_dynamic_constructs() {
        let fixture = fixture(&[
            (
                "dynamic.py",
                r#"
def run():
    globals()
    missing_name
"#,
            ),
            (
                "module_getattr.py",
                r#"
def __getattr__(name):
    return 1

def run():
    missing_name
"#,
            ),
            (
                "attribute.py",
                r#"
def run(obj):
    obj.missing_name
"#,
            ),
        ]);

        let dynamic = fixture.report_for("dynamic.py");
        assert!(dynamic.diagnostics().is_empty(), "{dynamic:#?}");
        assert!(
            incomplete_details(&dynamic)
                .iter()
                .any(|detail| detail.contains("globals")),
            "{dynamic:#?}"
        );

        let getattr = fixture.report_for("module_getattr.py");
        assert!(getattr.diagnostics().is_empty(), "{getattr:#?}");
        assert!(
            incomplete_details(&getattr)
                .iter()
                .any(|detail| detail.contains("__getattr__")),
            "{getattr:#?}"
        );

        // An attribute on an unproven receiver is not a candidate here: the
        // receiver's own binding resolves, the member is not judged.
        let attribute = fixture.report_for("attribute.py");
        assert!(attribute.diagnostics().is_empty(), "{attribute:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_state_malformed_files() {
        let fixture = fixture(&[(
            "broken.py",
            r#"
def run(
    missing_name
"#,
        )]);

        let report = fixture.report_for("broken.py");
        assert!(report.diagnostics().is_empty(), "{report:#?}");
        assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
        assert!(
            incomplete_details(&report)
                .iter()
                .any(|detail| detail.contains("parse errors")),
            "{report:#?}"
        );
    }

    #[test]
    fn python_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("def run():\n");
        for index in 0..(MAX_PYTHON_SEMANTIC_DIAGNOSTICS + 25) {
            source.push_str(&format!("    missing_{index}\n"));
        }
        let fixture = fixture(&[("app.py", &source)]);

        let report = fixture.report_for("app.py");
        assert_eq!(MAX_PYTHON_SEMANTIC_DIAGNOSTICS, report.diagnostics().len());
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                    if reasons.contains(&SemanticDiagnosticIncompleteReason::Truncated)
            )),
            "truncation must be stated"
        );
    }
}
