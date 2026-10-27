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

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence;

use brokk_bifrost_analysis::analyzer::semantic_model::RetainedDiscoveryVerdict;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind;

use brokk_bifrost_semantic::analyzer::semantic_model::identity::TypeIdentity;

use brokk_bifrost_analysis::analyzer::semantic_model::retained_discovery_verdict;

use brokk_bifrost_semantic::analyzer::semantic_model::identity::type_declaration_id;

use brokk_bifrost_analysis::analyzer::semantic_model::universal_root_name_for_language;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::PythonAnalyzer;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_python::diagnostics::{PythonEnvironmentBoundary, PythonEnvironmentSurface};

/// The ecosystem every Python declaration identity is minted under, in the
/// environment pack producer and here.
const PYTHON_ECOSYSTEM: &str = "python";

/// PEP 562's module-level attribute hook, which a class also uses to answer
/// names its own surface does not list.
const PYTHON_MODULE_GETATTR: &str = "__getattr__";

/// The class hook that replaces attribute lookup outright.
const PYTHON_CLASS_GETATTRIBUTE: &str = "__getattribute__";

pub(crate) fn collect_python_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
    let support =
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            analyzer,
            Language::None,
        );
    let environment = RetainedPythonEnvironment {
        overlay: analyzer.semantic_model_overlay(),
        evidence: analyzer.dependency_discovery_evidence(Language::Python),
    };
    let report = brokk_bifrost_python::diagnostics::collect_python_semantic_diagnostics(
        py,
        token,
        &support,
        &environment,
        file,
        source,
    );
    brokk_bifrost_analysis::analyzer::semantic_model::runtime::degrade_pack_gap_absences(
        analyzer, report,
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
                    boundary: brokk_bifrost_semantic::analyzer::semantic_model::dependency::missing_dependency_boundary(false),
                }
            }
            RetainedDiscoveryVerdict::Truncated => SemanticDiagnosticIncompleteReason::Truncated,
            RetainedDiscoveryVerdict::Declared => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: brokk_bifrost_semantic::analyzer::semantic_model::dependency::missing_dependency_boundary(true),
                }
            }
        };
        PythonEnvironmentBoundary::Incomplete(reason)
    }

    /// The declaration an active pack publishes for `path`, or the verdict that
    /// stands in for it.
    ///
    /// The lookup is by declaration identity rather than by name, so it cannot
    /// be satisfied by a same-named symbol from another module.
    fn published_declaration(
        &self,
        overlay: &SemanticModelOverlay,
        path: &str,
    ) -> Result<Arc<SemanticModelSymbol>, PythonEnvironmentBoundary> {
        let matched = overlay.symbols_with_id(&python_declaration_id(path));
        match matched.disposition {
            SemanticModelOverlayDisposition::Empty => Err(self.missing_evidence(path)),
            SemanticModelOverlayDisposition::Conflict => {
                Err(PythonEnvironmentBoundary::Incomplete(
                    SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!(
                            "more than one active semantic pack declares Python `{path}`"
                        ),
                    },
                ))
            }
            SemanticModelOverlayDisposition::Unique => Ok(matched
                .records
                .first()
                .expect("a unique overlay match has one record")
                .clone()),
        }
    }

    /// The module surface an active pack publishes for `module_path`.
    fn module_surface(
        &self,
        overlay: &SemanticModelOverlay,
        module_path: &str,
    ) -> Result<Arc<SemanticModelSymbol>, PythonEnvironmentBoundary> {
        let symbol = self.published_declaration(overlay, module_path)?;
        if symbol.kind != SemanticModelSymbolKind::Module {
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

    /// Judge `member` against a published module's surface.
    fn module_member(
        &self,
        overlay: &SemanticModelOverlay,
        module: &SemanticModelSymbol,
        module_path: &str,
        member: &str,
    ) -> PythonEnvironmentBoundary {
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
        // conflict that matters, and `published_declaration` already reported
        // it.
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

    /// Judge `member` against a published type's whole inherited surface.
    ///
    /// This is the #1622 remainder. It answers `Absent` only behind the
    /// overlay's three-layer owner-surface gate, so a type whose base no pack
    /// published, or whose closure comes from a partial pack, suppresses with a
    /// reason that names the gap instead of claiming a member is missing from a
    /// surface Bifrost has not seen.
    fn type_member(
        &self,
        overlay: &SemanticModelOverlay,
        owner: &Arc<SemanticModelSymbol>,
        owner_path: &str,
        member: &str,
    ) -> PythonEnvironmentBoundary {
        let surface = overlay.owner_surface(owner);
        if let Some(gap) = surface.gaps.first() {
            return PythonEnvironmentBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: format!(
                        "the inherited surface of Python type `{owner_path}` is incomplete: {gap}"
                    ),
                },
            );
        }
        // A hook found on one class still does not matter if another class in
        // the closure declares the member, so the whole closure is scanned
        // before a dynamic verdict is returned.
        let mut dynamic = None;
        for record in &surface.closure {
            // A nested class or type alias is published as its own qualified
            // declaration rather than as a member of its owner.
            if !overlay
                .symbols_with_id(&python_declaration_id(&format!(
                    "{}.{member}",
                    record.qualified_name
                )))
                .records
                .is_empty()
            {
                return PythonEnvironmentBoundary::Indexed;
            }
            for published in overlay.members_of(&record.id).records {
                if published.name == member {
                    return PythonEnvironmentBoundary::Indexed;
                }
                if dynamic.is_none() {
                    dynamic = dynamic_surface_detail(record, &published.name);
                }
            }
        }
        match dynamic {
            Some(detail) => PythonEnvironmentBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::DynamicBehavior { detail },
            ),
            None => PythonEnvironmentBoundary::Absent,
        }
    }
}

/// Why one published member name makes its owner's attribute lookup dynamic,
/// or `None` when it does not.
///
/// `object` supplies the default attribute lookup, so its own
/// `__getattribute__` is not an override and does not make every Python class
/// unprovable. An override on any other class does.
fn dynamic_surface_detail(owner: &SemanticModelSymbol, member_name: &str) -> Option<String> {
    let owner_name = &owner.qualified_name;
    let is_universal_root =
        universal_root_name_for_language(&owner.language) == Some(owner_name.as_str());
    match member_name {
        PYTHON_MODULE_GETATTR => Some(format!(
            "Python type `{owner_name}` defines `{PYTHON_MODULE_GETATTR}`"
        )),
        PYTHON_CLASS_GETATTRIBUTE if !is_universal_root => Some(format!(
            "Python type `{owner_name}` overrides `{PYTHON_CLASS_GETATTRIBUTE}`"
        )),
        PYTHON_UNENUMERATED_BINDING => Some(format!(
            "Python type `{owner_name}` binds names its semantic pack could not enumerate"
        )),
        _ => None,
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

    fn attribute_boundary(&self, owner_path: &str, member: &str) -> PythonEnvironmentBoundary {
        let Some(overlay) = self.overlay.as_deref() else {
            return self.missing_evidence(owner_path);
        };
        let owner = match self.published_declaration(overlay, owner_path) {
            Ok(owner) => owner,
            Err(boundary) => return boundary,
        };
        if owner.kind == SemanticModelSymbolKind::Module {
            self.module_member(overlay, &owner, owner_path, member)
        } else {
            self.type_member(overlay, &owner, owner_path, member)
        }
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

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use crate::analyzer::PythonAnalyzer;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnostic;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;

    use brokk_bifrost_core::analyzer::project::TestProject;
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
            self.analyzer.semantic_diagnostics(&file, &source)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<SemanticDiagnostic> {
            self.report_for(rel_path).into_diagnostics()
        }

        fn file(&self, rel_path: &str) -> ProjectFile {
            brokk_bifrost_analysis::analyzer::common::project_file_for_test(&self.root, rel_path)
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: with context expression was suppressed as an alias binder"
    )]
    fn qs6_python_lexical_diagnostic_corpus() {
        // A single lexical corpus, with deliberately absent reads as controls.
        // Expected rows are the CPython lexical-scope oracle, in byte order.
        let source = "def run(self):\n def helper():\n  return self\n helper()\n return missing\nidentity = lambda value: value\nwith manager() as alias:\n print(alias)\nraise AssertionError('failure')\nAssertionError_\n";
        let fixture = fixture(&[("app.py", source)]);
        let report = fixture.report_for("app.py");
        let actual = report
            .diagnostics()
            .iter()
            .map(|d| {
                (
                    &source[d.range.start_byte..d.range.end_byte],
                    d.range.start_line,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [("missing", 5), ("manager", 7), ("AssertionError_", 10)],
            "{report:#?}"
        );
        // Declaration and with-alias nodes are binders, not read candidates.
        use brokk_bifrost_core::analyzer::model::SemanticDiagnosticOutcome;
        let lambda_reads = report.outcomes().iter().filter(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Resolved { range, .. } if range.start_line == 6)).count();
        assert_eq!(
            lambda_reads, 1,
            "only the lambda body is a read: {report:?}"
        );
        for outcome in report.outcomes() {
            let range = match outcome {
                SemanticDiagnosticOutcome::Resolved { range, .. }
                | SemanticDiagnosticOutcome::Ambiguous { range, .. }
                | SemanticDiagnosticOutcome::Absent(
                    brokk_bifrost_core::analyzer::model::SemanticAbsenceProof { range, .. },
                ) => range,
                SemanticDiagnosticOutcome::Incomplete { .. } => continue,
            };
            assert_ne!(
                range.start_line, 1,
                "parameter declaration was judged: {outcome:?}"
            );
            assert!(
                range.start_line != 7 || &source[range.start_byte..range.end_byte] == "manager",
                "with alias was judged: {outcome:?}"
            );
        }
    }

    #[test]
    fn qs6_python_diagnostic_limits() {
        use brokk_bifrost_core::analyzer::model::{
            SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
        };
        let truncated = |report: &SemanticDiagnosticReport| {
            report.outcomes().iter().any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Incomplete { reasons, .. } if reasons.contains(&SemanticDiagnosticIncompleteReason::Truncated)))
        };
        for bytes in [524287, 524288, 524289] {
            let mut source = "missing\n#".to_owned();
            source.extend(std::iter::repeat_n(' ', bytes - source.len()));
            let fixture = fixture(&[("app.py", &source)]);
            let report = fixture.report_for("app.py");
            assert_eq!(
                report.diagnostics().len(),
                usize::from(bytes <= 524288),
                "{bytes}: {report:?}"
            );
            assert_eq!(truncated(&report), bytes > 524288, "{bytes}: {report:?}");
        }
        for count in [199, 200, 201] {
            let source = (0..count)
                .map(|i| format!("missing_{i}\n"))
                .collect::<String>();
            let fixture = fixture(&[("app.py", &source)]);
            let report = fixture.report_for("app.py");
            assert_eq!(report.diagnostics().len(), count.min(200), "{report:?}");
            assert_eq!(truncated(&report), count > 200, "{report:?}");
            for (i, diagnostic) in report.diagnostics().iter().enumerate() {
                assert_eq!(
                    &source[diagnostic.range.start_byte..diagnostic.range.end_byte],
                    format!("missing_{i}")
                );
            }
        }
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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
}
