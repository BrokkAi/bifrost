//! The analysis-side entry point for Go's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_go::diagnostics`]. What stays
//! here is the downcast that turns an `&dyn IAnalyzer` into the arguments that
//! function takes: the file's resolved import bindings, the bounded definition
//! lookup, and the external evidence view of the activated exact API packs and
//! the retained Go module graph.
//!
//! `brokk-bifrost-go` cannot name `SemanticModelOverlay`, so the overlay
//! crosses the crate boundary as the [`GoExternalEvidence`] trait, the same
//! shape Java's `JavaSource::external_boundary_evidence` uses.
//!
//! Every fact this reads is state the analyzer already retains. A diagnostic
//! request must never run `go`, walk a module cache, or start dependency
//! discovery: state it cannot see becomes a typed incomplete reason.

use crate::analyzer::go::package_identity::GoOverlayPackages;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

use crate::analyzer::GoAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason;

use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
use brokk_bifrost_core::analyzer::model::SemanticDiagnosticDomain;
use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;

use crate::analyzer::go::native_points::{GoNativePointRequest, GoNativePointRequestOpen};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_go::diagnostics::{GoExternalEvidence, GoPackageSurface};
use brokk_bifrost_go::graph::resolver::GoImportBindings;
use std::sync::Arc;

pub(crate) fn collect_go_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    _token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    let external = AnalyzerGoExternalEvidence {
        overlay: analyzer.semantic_model_overlay(),
        discovery: analyzer.dependency_discovery_evidence(Language::Go),
    };
    let cancellation = CancellationToken::new();
    // One file's partial imports, alive only while rendering its report.
    struct IncompleteImport {
        owner: String,
        is_dot: bool,
        detail: String,
    }
    let bindings = (|| -> Result<(GoImportBindings, Vec<IncompleteImport>), String> {
        let opened = GoNativePointRequest::open(go, external.overlay.clone(), &cancellation)
            .map_err(|error| format!("Go canonical import binding read failed: {error}"))?;
        let request = match opened {
            GoNativePointRequestOpen::Ready(request) => request,
            GoNativePointRequestOpen::Unavailable { message, .. } => return Err(message),
            GoNativePointRequestOpen::Cancelled => {
                return Err("Go import preparation cancelled".into());
            }
        };
        let view = request
            .import_diagnostic_view(file, &cancellation)
            .map_err(|error| format!("Go canonical import binding read failed: {error}"))?
            .ok_or_else(|| "Go selected import context unavailable".to_string())?;
        if !view.source_authority_gaps.is_empty() {
            return Err(format!(
                "Go package clauses unavailable: {:?}",
                view.source_authority_gaps
            ));
        }
        let mut bindings = GoImportBindings::default();
        let mut incomplete = Vec::new();
        for binding in &view.bindings {
            if binding.local_name == "_" {
                continue;
            }
            // Workspace declarations use their selected canonical source
            // anchor. External evidence is keyed by the import spelling,
            // independent of GoTool's opaque provider instance identity.
            let path = if binding.has_source_declarations {
                binding.provider_path.as_deref().ok_or_else(|| {
                    "selected Go source provider has no canonical package anchor".to_string()
                })?
            } else {
                &binding.source_spelling
            };
            if let ResolutionCompletion::Incomplete(_) = &binding.completion {
                incomplete.push(IncompleteImport {
                    owner: path.into(),
                    is_dot: binding.local_name == ".",
                    detail: format!(
                        "Go import {:?} is incomplete: {:?}; named reasons: {:?}",
                        binding.source_spelling, binding.completion, binding.named_reasons
                    ),
                });
            }
            match (binding.has_source_declarations, binding.local_name.as_str()) {
                (true, ".") => bindings.dot_workspace.push(path.into()),
                (false, ".") => bindings.dot_external.push(path.into()),
                (true, name) => bindings
                    .workspace
                    .entry(name.into())
                    .or_default()
                    .push(path.into()),
                (false, name) => bindings
                    .external
                    .entry(name.into())
                    .or_default()
                    .push(path.into()),
            }
        }
        for paths in bindings
            .workspace
            .values_mut()
            .chain(bindings.external.values_mut())
        {
            paths.sort();
            paths.dedup();
        }
        bindings.dot_workspace.sort();
        bindings.dot_workspace.dedup();
        bindings.dot_external.sort();
        bindings.dot_external.dedup();
        Ok((bindings, incomplete))
    })();
    let (bindings, incomplete) = match bindings {
        Ok(bindings) => bindings,
        Err(detail) => {
            let mut report = SemanticDiagnosticReport::new();
            report.push_incomplete(
                None,
                vec![SemanticDiagnosticIncompleteReason::CanonicalFactsUnavailable { detail }],
            );
            return report;
        }
    };
    let support =
        brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(
            analyzer,
            Language::None,
        );
    let mut report = brokk_bifrost_go::diagnostics::collect_go_semantic_diagnostics(
        &bindings, &support, &external, file, source,
    );
    report.degrade_absences(|domain| {
        incomplete
            .iter()
            .find(|import| match domain {
                SemanticDiagnosticDomain::MemberSurface { owner, .. } => owner == &import.owner,
                SemanticDiagnosticDomain::LexicalScope { .. } => import.is_dot,
                _ => false,
            })
            .map(
                |import| SemanticDiagnosticIncompleteReason::CanonicalFactsUnavailable {
                    detail: import.detail.clone(),
                },
            )
    });
    if !incomplete.is_empty() {
        report.push_incomplete(
            None,
            incomplete
                .into_iter()
                .map(
                    |import| SemanticDiagnosticIncompleteReason::CanonicalFactsUnavailable {
                        detail: import.detail,
                    },
                )
                .collect(),
        );
    }
    brokk_bifrost_analysis::analyzer::semantic_model::runtime::degrade_pack_gap_absences(
        analyzer, report,
    )
}

/// The retained external Go state one diagnostic request may read.
struct AnalyzerGoExternalEvidence {
    overlay: Option<Arc<SemanticModelOverlay>>,
    discovery: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl AnalyzerGoExternalEvidence {
    fn packages(&self) -> GoOverlayPackages<'_> {
        GoOverlayPackages::new(self.overlay.as_deref())
    }
}

impl GoExternalEvidence for AnalyzerGoExternalEvidence {
    fn package_surface(&self, import_path: &str) -> GoPackageSurface {
        self.packages().package_surface(import_path)
    }

    fn publishes_member(&self, import_path: &str, member: &str) -> bool {
        self.packages().publishes_member(import_path, member)
    }

    fn unindexed_boundary(&self, import_path: &str) -> BoundaryStatus {
        // Retained discovery evidence (#1601): the module graph declares the
        // module this import routes through and nothing indexed it, or
        // discovery could not read everything the build declared, so the
        // package may well be there. Where no discovery has run, nothing is
        // retained and `ExternalUnknown` is the honest answer.
        let declared = self.discovery.as_ref().is_some_and(|evidence| {
            evidence.truncated() || evidence.declares_go_import_path(import_path)
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

    use crate::analyzer::GoAnalyzer;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnostic;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_go::diagnostics::{GO_UNRECOGNIZED_PACKAGE_MEMBER, GO_UNRECOGNIZED_SYMBOL};
    use brokk_bifrost_test_macros::hardwon;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: GoAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn file(&self, rel_path: &str) -> ProjectFile {
            brokk_bifrost_analysis::analyzer::common::project_file_for_test(&self.root, rel_path)
        }

        fn report_for(&self, rel_path: &str) -> SemanticDiagnosticReport {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            self.analyzer.semantic_diagnostics(&file, &source)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<SemanticDiagnostic> {
            self.report_for(rel_path).into_diagnostics()
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        fixture_with_go_mod(files, true)
    }

    fn assert_single_unknown_package_member(diagnostics: &[SemanticDiagnostic]) {
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
    }

    fn fixture_without_go_mod(files: &[(&str, &str)]) -> Fixture {
        fixture_with_go_mod(files, false)
    }

    fn fixture_with_go_mod(files: &[(&str, &str)], write_go_mod: bool) -> Fixture {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().to_path_buf();
        if write_go_mod {
            ProjectFile::new(root.clone(), "go.mod")
                .write("module example.com/app\n\ngo 1.22\n")
                .expect("write go.mod");
        }
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(*source)
                .unwrap_or_else(|err| panic!("write {path}: {err}"));
        }
        let project = TestProject::new(root.clone(), Language::Go);
        let analyzer = GoAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    #[test]
    fn go_semantic_diagnostics_resolve_relative_workspace_imports() {
        let fixture = fixture_without_go_mod(&[
            (
                "store/store.go",
                r#"
package store

func Present() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "./store"

func Run() {
    store.Missing()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_single_unknown_package_member(&diagnostics);
    }

    #[test]
    fn go_semantic_diagnostics_bound_range_names_stay_inside_the_loop() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func Run(values []int) {
    for _, item := range values {
        _ = item
    }
    _ = item
    for missing = range values {}
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == GO_UNRECOGNIZED_SYMBOL)
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("item"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing"))
        );
    }

    #[test]
    fn go_semantic_diagnostics_report_unavailable_workspace_package_clause() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason;

        use brokk_bifrost_core::analyzer::model::SemanticDiagnosticOutcome;

        use brokk_bifrost_core::analyzer::model::SemanticDiagnosticReportStatus;

        let source =
            "package main\nimport \"example.com/app/broken\"\nfunc Run() { broken.Missing() }\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n")
            .file(
                "broken/broken.go",
                "// Missing the required package clause.\n",
            )
            .file("main.go", source)
            .build();
        let analyzer = GoAnalyzer::from_project(project.project().clone());
        let report = analyzer.semantic_diagnostics(&project.file("main.go"), source);
        assert_eq!(
            report.status(),
            SemanticDiagnosticReportStatus::Incomplete,
            "{report:#?}"
        );
        assert!(report.diagnostics().is_empty(), "{report:#?}");
        assert!(
            report.outcomes().iter().any(|outcome| {
                matches!(outcome, SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(reason,
                    SemanticDiagnosticIncompleteReason::CanonicalFactsUnavailable { detail }
                        if detail.contains("broken.go"))))
            }),
            "{report:#?}"
        );
    }

    #[test]
    fn go_semantic_diagnostics_respect_function_local_scopes() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func A() {
    ctx := 1
    _ = ctx
}

func B() {
    _ = ctx
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("ctx"));
    }

    #[test]
    fn go_semantic_diagnostics_suppress_external_and_malformed_files() {
        let fixture = fixture(&[
            (
                "external.go",
                r#"
package main

import "fmt"

func Run() {
    fmt.Println("ok")
}
"#,
            ),
            (
                "broken.go",
                r#"
package main

func Run( {
    missingValue
}
"#,
            ),
        ]);

        assert!(
            fixture.diagnostics_for("external.go").is_empty(),
            "external package selectors should not be diagnosed"
        );
        assert!(
            fixture.diagnostics_for("broken.go").is_empty(),
            "semantic diagnostics should suppress malformed files"
        );
    }

    #[test]
    fn go_semantic_diagnostics_suppress_keyed_literal_keys_but_scan_values() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Client struct {
    Name string
}

func Run() {
    _ = Client{Name: missingValue}
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missingValue"));
    }

    #[test]
    #[hardwon(
        "94224b15a07d: canonical Go package facts did not preserve comments and missing clauses"
    )]
    fn go_canonical_package_clause_preserves_structured_package_cases() {
        for (source, expected) in [
            ("package main\n\nfunc main() {}", Some("main")),
            (
                "package mypkg\nimport \"fmt\"\nfunc Hello() { fmt.Println(\"Hello\") }",
                Some("mypkg"),
            ),
            (
                "// comment\npackage main /* another comment */",
                Some("main"),
            ),
            ("func main() {}", None),
            ("", None),
        ] {
            let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
                .file("source.go", source)
                .build();
            let analyzer = GoAnalyzer::from_project(project.project().clone());
            let clause = analyzer.package_clause_of(&project.file("source.go"));
            assert_eq!(
                clause.as_deref().filter(|clause| !clause.is_empty()),
                expected,
                "{source:?}"
            );
        }
    }

    #[test]
    #[hardwon("94224b15a07d: Go diagnostics read stale package identity after an overlay edit")]
    fn go_semantic_diagnostics_read_canonical_overlay_package_clauses() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::project::OverlayProject;

        use brokk_bifrost_core::analyzer::project::Project;
        use std::sync::Arc;

        let source = "package main\nimport \"example.com/app/postgres\"\nfunc Run() { fresh.Present(); fresh.Missing() }\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n")
            .file("postgres/postgres.go", "package old\nfunc Present() {}\n")
            .file("main.go", source)
            .build();
        let overlay = Arc::new(OverlayProject::new(project.project_dyn()));
        assert!(overlay.set(
            project.file("postgres/postgres.go").abs_path(),
            "package fresh /* canonical clause */\nfunc Present() {}\n".to_owned(),
        ));
        let analyzer = GoAnalyzer::new(overlay as Arc<dyn Project>);
        let report = analyzer.semantic_diagnostics(&project.file("main.go"), source);
        assert_eq!(report.diagnostics().len(), 1, "{report:#?}");
        assert_eq!(report.diagnostics()[0].kind, GO_UNRECOGNIZED_PACKAGE_MEMBER);
        assert!(
            report.diagnostics()[0].message.contains("Missing"),
            "{report:#?}"
        );
    }

    #[test]
    fn go_semantic_diagnostics_report_nested_unknown_workspace_package_member() {
        let fixture = fixture(&[
            (
                "store/store.go",
                r#"
package store

func Present() {}
"#,
            ),
            (
                "external_test.go",
                r#"package main_test
import "example.com/app/store"
func Check() {
    store.Present()
    store.Missing.Nested()
}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "example.com/app/store"

func Run() {
    store.Missing.Nested()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_single_unknown_package_member(&diagnostics);

        // A test provider's opaque GoTool path is not the canonical FQN
        // prefix. Exercise real selected publication and diagnostic lookup.
        use brokk_bifrost_analysis::analyzer::store::go_package_context::{
            GoContextPublicationOutcome, GoInputObservationOutcome, profile_digest,
        };
        use brokk_bifrost_core::cancellation::CancellationToken;
        use brokk_bifrost_go::package_discovery::{
            GoDiscoveryDomain, GoPackageDiscovery, host_build_configuration,
        };
        use serde_json::json;

        let analyzer = &fixture.analyzer;
        let snapshot = analyzer.selected_snapshot_for_test().unwrap();
        let store = analyzer.inner.analyzer_store();
        let cancellation = CancellationToken::new();
        let GoInputObservationOutcome::Ready(observation) = store
            .observe_go_context_inputs(&snapshot, analyzer.inner.project(), &cancellation)
            .unwrap()
        else {
            panic!("fixture inputs must be selected")
        };
        let config =
            host_build_configuration(&analyzer.inner.analyzer_config().go.dependency_discovery);
        let module = json!({"Path":"example.com/app", "Main":true, "Dir":fixture.root});
        let variant = "example.com/app/store [example.com/app.test]";
        let discovery = GoPackageDiscovery {
            domain: GoDiscoveryDomain {
                directory: String::new(), gowork_path: String::new(),
                modules: vec![(String::new(), "example.com/app".into())],
            },
            input_digest: None, failure: None,
            packages: [
                json!({"ImportPath":"example.com/app", "Name":"main", "Dir":fixture.root,
                    "GoFiles":["main.go"], "Imports":["example.com/app/store"], "Module":module}),
                json!({"ImportPath":"example.com/app/store", "Name":"store", "Dir":fixture.root.join("store"),
                    "GoFiles":["store.go"], "Module":module}),
                json!({"ImportPath":variant, "ForTest":"example.com/app", "Name":"store", "Dir":fixture.root.join("store"),
                    "GoFiles":["store.go"], "Module":module}),
                json!({"ImportPath":"example.com/app_test [example.com/app.test]", "ForTest":"example.com/app",
                    "Name":"main_test", "Dir":fixture.root, "GoFiles":["external_test.go"],
                    "Imports":[variant], "ImportMap":{"example.com/app/store":variant}, "Module":module}),
            ].into_iter().map(|record| serde_json::from_value(record).unwrap()).collect(),
            environment: serde_json::from_value(json!({
                "GOROOT":fixture.root, "GOPATH":fixture.root, "GOMODCACHE":fixture.root,
                "GOVERSION":"go1.22", "GOWORK":"off", "GOOS":config.goos, "GOARCH":config.goarch,
            })).unwrap(),
            build_configuration: config, workspace_patterns: vec!["./...".into()], vendor: false,
        };
        let profile = profile_digest(&discovery);
        let GoContextPublicationOutcome::Published(_) = store
            .publish_go_package_context(
                snapshot.clone(),
                fixture.root.clone(),
                None,
                &observation,
                &observation,
                discovery,
                &cancellation,
            )
            .unwrap()
        else {
            panic!("test-variant publication must succeed")
        };
        assert!(analyzer.activate_native_context_profile(&snapshot, profile));
        let diagnostics = fixture.diagnostics_for("external_test.go");
        assert_single_unknown_package_member(&diagnostics);
        assert_eq!(
            "Go package `example.com/app/store` has no indexed member `Missing`",
            diagnostics[0].message
        );
    }

    #[test]
    fn go_semantic_diagnostics_do_not_treat_struct_fields_as_bare_names() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Client struct {
    Name string
}

func Run() {
    _ = Name
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Name"));
    }
}
