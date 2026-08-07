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
use crate::analyzer::semantic_model::{DependencyDiscoveryEvidence, SemanticModelOverlay};
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::usages::go_graph::go_graph_source;
use crate::analyzer::{
    GoAnalyzer, IAnalyzer, Language, ProjectFile, SemanticDiagnosticReport, resolve_analyzer,
};
use brokk_bifrost_go::diagnostics::{GoExternalEvidence, GoPackageSurface};
use brokk_bifrost_go::graph::resolver::resolve_go_import_bindings;
use std::sync::Arc;

pub(crate) fn collect_go_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
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
    let bindings = resolve_go_import_bindings(
        go_graph_source(go),
        file,
        go.package_clause_names(),
        |import_path| external.packages().declared_package_name(import_path),
    );
    let support = analyzer.global_usage_definition_index();
    brokk_bifrost_go::diagnostics::collect_go_semantic_diagnostics(
        &bindings, &support, &external, file, source,
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
    use super::collect_go_semantic_diagnostics;
    use crate::analyzer::{
        GoAnalyzer, Language, ProjectFile, SemanticDiagnostic, SemanticDiagnosticReport,
        TestProject,
    };
    use brokk_bifrost_go::diagnostics::{
        GO_UNRECOGNIZED_PACKAGE_MEMBER, GO_UNRECOGNIZED_SYMBOL, MAX_GO_SEMANTIC_DIAGNOSTICS,
    };
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: GoAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
        }

        fn report_for(&self, rel_path: &str) -> SemanticDiagnosticReport {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_go_semantic_diagnostics(&self.analyzer, &file, &source)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<SemanticDiagnostic> {
            self.report_for(rel_path).into_diagnostics()
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        fixture_with_go_mod(files, true)
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
    fn go_semantic_diagnostics_report_unknown_local_identifier() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func Run() {
    missingValue
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missingValue"));
    }

    #[test]
    fn go_semantic_diagnostics_report_unknown_workspace_package_member() {
        let fixture = fixture(&[
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

import "example.com/app/store"

func Run() {
    store.Missing()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
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
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
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
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
    }

    #[test]
    fn go_semantic_diagnostics_suppress_known_names_and_import_forms() {
        let fixture = fixture(&[
            (
                "store/store.go",
                r#"
package store

type Client struct {
    Name string
}

func Present() {}
func (Client) Run() {}
"#,
            ),
            (
                "dot/dot.go",
                r#"
package dot

func DotFunc() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import (
    s "example.com/app/store"
    . "example.com/app/dot"
    _ "example.com/app/store"
)

type Local struct{}

func Present() {}

func Run(client s.Client) {
Start:
    local := Local{}
    _ = local
    _ = client.Name
    client.Run()
    Present()
    s.Present()
    DotFunc()
    println(len([]int{1}))
    goto Start
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn go_semantic_diagnostics_suppress_generic_and_variadic_declarations() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Box[T any] struct {
    value T
}

func Identity[T any](x T) T {
    var y T = x
    return y
}

func Log(xs ...string) {
    println(xs)
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
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
    fn go_semantic_diagnostics_scan_assignment_lhs_references() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func Run() {
    missingValue = 1
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missingValue"));
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

    #[test]
    fn go_semantic_diagnostics_scan_struct_field_types() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Client struct {
    Store MissingType
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingType"));
    }

    #[test]
    fn go_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("package main\n\nfunc Run() {\n");
        for index in 0..(MAX_GO_SEMANTIC_DIAGNOSTICS + 25) {
            source.push_str(&format!("    missing{index}\n"));
        }
        source.push_str("}\n");
        let fixture = fixture(&[("main.go", &source)]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(MAX_GO_SEMANTIC_DIAGNOSTICS, diagnostics.len());
    }

    #[test]
    fn go_semantic_diagnostics_use_imported_package_clause_for_unaliased_imports() {
        let fixture = fixture(&[
            (
                "postgres/postgres.go",
                r#"
package pg

func Present() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "example.com/app/postgres"

func Run() {
    pg.Present()
    pg.Missing()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
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
}
