//! C#'s proof-gated semantic diagnostics (#1621).
//!
//! Every assertion is outcome-level: what a report *claims* matters more than
//! how many diagnostics it printed, because the contract is that a diagnostic
//! exists only where a complete surface proved absence.
//!
//! No test here writes an assembly, a `project.assets.json` or a NuGet cache,
//! and none runs `dotnet`. Where a test needs the assembly index to exist it
//! calls `warm_query_indexes`, which is the same off-request hook a host uses;
//! over a workspace with no dependency inputs that builds an empty index
//! without touching anything outside the temporary project root.

use brokk_bifrost::analyzer::AnalyzerConfig;
use brokk_bifrost::{Language, WorkspaceAnalyzer};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport, SemanticDiagnosticReportStatus,
};

use crate::common::{BuiltInlineTestProject, InlineTestProject};

const APP: &str = "App.cs";

struct CSharpFixture {
    project: BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
}

impl CSharpFixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let mut builder = InlineTestProject::with_language(Language::CSharp);
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let project = builder.build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        Self { project, analyzer }
    }

    /// Build the assembly index off the request path, the way a host's index
    /// warmer does. A diagnostic request must never do this itself.
    fn warmed(files: &[(&str, &str)]) -> Self {
        let fixture = Self::new(files);
        fixture.analyzer.analyzer().warm_query_indexes();
        assert!(
            fixture.analyzer.analyzer().query_indexes_warm(),
            "warming must build the C# assembly index"
        );
        fixture
    }

    fn report(&self, rel_path: &str) -> SemanticDiagnosticReport {
        let file = self.project.file(rel_path);
        let source = file.read_to_string().expect("read fixture source");
        self.analyzer
            .analyzer()
            .semantic_diagnostics(&file, &source)
    }
}

fn resolved_at(report: &SemanticDiagnosticReport, boundary: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Resolved { boundary: found, .. }
            if *found == boundary)
    })
}

fn absence_domains(report: &SemanticDiagnosticReport) -> Vec<&SemanticDiagnosticDomain> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Absent(proof) => Some(&proof.domain),
            _ => None,
        })
        .collect()
}

fn absence_boundaries(report: &SemanticDiagnosticReport) -> Vec<BoundaryStatus> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Absent(proof) => Some(proof.boundary),
            _ => None,
        })
        .collect()
}

fn incomplete_reasons(
    report: &SemanticDiagnosticReport,
) -> Vec<&SemanticDiagnosticIncompleteReason> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
            _ => None,
        })
        .flatten()
        .collect()
}

fn ambiguity_widths(report: &SemanticDiagnosticReport) -> Vec<usize> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Ambiguous { boundaries, .. } => Some(boundaries.len()),
            _ => None,
        })
        .collect()
}

fn absent_type(report: &SemanticDiagnosticReport, name: &str) -> bool {
    absence_domains(report).into_iter().any(|domain| {
        *domain
            == SemanticDiagnosticDomain::Type {
                name: name.to_owned(),
            }
    })
}

fn absent_member(report: &SemanticDiagnosticReport, owner: &str, member: &str) -> bool {
    absence_domains(report).into_iter().any(|domain| {
        *domain
            == SemanticDiagnosticDomain::MemberSurface {
                owner: owner.to_owned(),
                member: member.to_owned(),
            }
    })
}

// ---------------------------------------------------------------------------
// Workspace resolution
// ---------------------------------------------------------------------------

#[test]
fn a_workspace_type_reference_resolves_without_erroring() {
    let fixture = CSharpFixture::warmed(&[
        (
            "Widget.cs",
            "namespace App { public class Widget { public int Size; } }\n",
        ),
        (
            APP,
            "namespace App { public class Host { Widget MakeOne() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{report:#?}"
    );
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert_eq!(report.status(), SemanticDiagnosticReportStatus::Complete);
}

#[test]
fn a_missing_local_type_errors_after_complete_resolution() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "namespace App { public class Host { Missing MakeOne() { return null; } } }\n",
    )]);
    let report = fixture.report(APP);
    assert!(absent_type(&report, "Missing"), "{report:#?}");
    assert_eq!(
        absence_boundaries(&report),
        vec![BoundaryStatus::WorkspaceLocal],
        "{report:#?}"
    );
    assert_eq!(report.diagnostics().len(), 1, "{report:#?}");
    assert_eq!(report.diagnostics()[0].kind, "csharp_unrecognized_symbol");
}

// ---------------------------------------------------------------------------
// The read-only rule
// ---------------------------------------------------------------------------

#[test]
fn an_unbuilt_assembly_index_never_proves_absence_and_is_not_built_by_the_request() {
    let fixture = CSharpFixture::new(&[(
        APP,
        "namespace App { public class Host { Missing MakeOne() { return null; } } }\n",
    )]);
    assert!(
        !fixture.analyzer.analyzer().query_indexes_warm(),
        "the fixture must start with an unbuilt index"
    );
    let report = fixture.report(APP);
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalUnknown
            }
        )),
        "{report:#?}"
    );
    assert!(
        !fixture.analyzer.analyzer().query_indexes_warm(),
        "a diagnostic request must not build the assembly index"
    );
}

#[test]
fn a_using_of_a_namespace_no_dependency_input_declares_suppresses_every_claim() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "using System.Text;\nnamespace App { public class Host { Missing MakeOne() { return null; } } }\n",
    )]);
    let report = fixture.report(APP);
    assert!(
        report.diagnostics().is_empty(),
        "a file that opens an unseen namespace proves nothing: {report:#?}"
    );
    assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalUnknown
            }
        )),
        "{report:#?}"
    );
}

#[test]
fn a_using_of_a_workspace_namespace_resolves() {
    let fixture = CSharpFixture::warmed(&[
        (
            "Widget.cs",
            "namespace App.Models { public class Widget { } }\n",
        ),
        (
            APP,
            "using App.Models;\nnamespace App { public class Host { Widget MakeOne() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{report:#?}"
    );
}

// ---------------------------------------------------------------------------
// Near misses
// ---------------------------------------------------------------------------

#[test]
fn the_same_type_name_under_two_usings_is_ambiguous_not_absent() {
    let fixture = CSharpFixture::warmed(&[
        (
            "Left.cs",
            "namespace App.Left { public class Widget { } }\n",
        ),
        (
            "Right.cs",
            "namespace App.Right { public class Widget { } }\n",
        ),
        (
            APP,
            "using App.Left;\nusing App.Right;\nnamespace App { public class Host { Widget MakeOne() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(
        report.diagnostics().is_empty(),
        "an ambiguous name is not an absence: {report:#?}"
    );
    assert!(ambiguity_widths(&report).contains(&2), "{report:#?}");
}

#[test]
fn a_using_alias_resolves_the_name_it_binds() {
    let fixture = CSharpFixture::warmed(&[
        (
            "Widget.cs",
            "namespace App.Models { public class Widget { } }\n",
        ),
        (
            APP,
            "using Gadget = App.Models.Widget;\nnamespace App { public class Host { Gadget MakeOne() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{report:#?}"
    );
}

#[test]
fn a_partial_class_declared_twice_is_one_logical_type() {
    let fixture = CSharpFixture::warmed(&[
        (
            "WidgetA.cs",
            "namespace App { public partial class Widget { public int Left; } }\n",
        ),
        (
            "WidgetB.cs",
            "namespace App { public partial class Widget { public int Right; } }\n",
        ),
        (
            APP,
            "namespace App { public class Host { Widget MakeOne() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(
        ambiguity_widths(&report).is_empty(),
        "a partial type's parts are one type: {report:#?}"
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{report:#?}"
    );
}

#[test]
fn a_generic_type_reference_is_matched_on_arity() {
    let fixture = CSharpFixture::warmed(&[
        ("Box.cs", "namespace App { public class Box<T> { } }\n"),
        (
            APP,
            "namespace App { public class Host { Box<int> One() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{report:#?}"
    );
}

#[test]
fn a_generic_arity_mismatch_does_not_resolve_to_the_other_arity() {
    let fixture = CSharpFixture::warmed(&[
        ("Box.cs", "namespace App { public class Box<T> { } }\n"),
        (
            APP,
            "namespace App { public class Host { Box<int, string> One() { return null; } } }\n",
        ),
    ]);
    let report = fixture.report(APP);
    assert!(
        absent_type(&report, "Box`2"),
        "a two-argument reference must not match the one-parameter type: {report:#?}"
    );
}

#[test]
fn a_generic_parameter_is_not_looked_up_as_a_type() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "namespace App { public class Host<T> { T Keep(T value) { return value; } } }\n",
    )]);
    let report = fixture.report(APP);
    assert!(
        report.diagnostics().is_empty(),
        "`T` names a generic parameter, not a declaration: {report:#?}"
    );
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

#[test]
fn a_missing_member_on_a_complete_workspace_owner_errors() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "namespace App {\n  public class Widget { public int Size; }\n  public class Host { void Use() { Widget w = new Widget(); int n = w.Missing; } }\n}\n",
    )]);
    let report = fixture.report(APP);
    assert!(
        absent_member(&report, "App.Widget", "Missing"),
        "{report:#?}"
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.kind == "csharp_unrecognized_member"),
        "{report:#?}"
    );
}

#[test]
fn a_member_inherited_from_a_workspace_base_resolves() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "namespace App {\n  public class Base { public int Size; }\n  public class Widget : Base { }\n  public class Host { void Use() { Widget w = new Widget(); int n = w.Size; } }\n}\n",
    )]);
    let report = fixture.report(APP);
    assert!(
        report.diagnostics().is_empty(),
        "an inherited member is present: {report:#?}"
    );
}

#[test]
fn an_unresolvable_ancestor_suppresses_the_member_absence() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "using App.Unknown;\nnamespace App {\n  public class Widget : SomeUnknownBase { }\n  public class Host { void Use() { Widget w = new Widget(); int n = w.Missing; } }\n}\n",
    )]);
    let report = fixture.report(APP);
    assert!(
        report.diagnostics().is_empty(),
        "an owner whose base chain leaves the workspace has no complete surface: {report:#?}"
    );
    assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
}

#[test]
fn an_extension_method_lookalike_suppresses_the_member_absence() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "namespace App {\n  public class Widget { }\n  public static class Extras { public static int Frob(this Widget widget) { return 1; } }\n  public class Host { void Use() { Widget w = new Widget(); int n = w.Frob(); } }\n}\n",
    )]);
    let report = fixture.report(APP);
    assert!(
        !absent_member(&report, "App.Widget", "Frob"),
        "an extension method in scope explains the miss: {report:#?}"
    );
}

// ---------------------------------------------------------------------------
// Parse errors
// ---------------------------------------------------------------------------

#[test]
fn parse_errors_report_a_typed_incomplete_rather_than_an_empty_report() {
    let fixture = CSharpFixture::warmed(&[(
        APP,
        "namespace App { public class Host { Missing MakeOne() { return\n",
    )]);
    let report = fixture.report(APP);
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                if detail.contains("parse errors")
        )),
        "{report:#?}"
    );
}
