//! C/C++'s semantic-diagnostic ladder over a `compile_commands.json` database.
//!
//! The collector may only call a type absent when it can reproduce the whole
//! translation unit the compiler would see. Every way of failing that says so
//! with a typed reason, so an empty diagnostic list means "nothing unknown
//! here" only when the report is also `Complete`. These tests assert the
//! outcomes, because the diagnostic list alone cannot tell the two apart.
//!
//! No test here runs a compiler or a build tool: the compile database is
//! written as an ordinary fixture file and read as data.

use crate::common::InlineTestProject;
use brokk_bifrost::{CppAnalyzer, IAnalyzer, Language, Project, ProjectFile};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport, SemanticDiagnosticReportStatus,
};

const MAIN: &str = "src/main.cpp";

/// One compile-database entry for `src/main.cpp` with the given extra flags.
fn database(flags: &[&str]) -> String {
    let flags = flags
        .iter()
        .map(|flag| format!("\"{flag}\","))
        .collect::<String>();
    format!(
        r#"[{{"directory":".","file":"src/main.cpp","arguments":["clang++",{flags}"-c","src/main.cpp"]}}]"#
    )
}

struct Fixture {
    project: crate::common::BuiltInlineTestProject,
    analyzer: CppAnalyzer,
}

impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let mut project = InlineTestProject::with_language(Language::Cpp);
        for (path, contents) in files {
            project = project.file(*path, *contents);
        }
        let project = project.build();
        let analyzer = CppAnalyzer::new(project.project_dyn());
        Self { project, analyzer }
    }

    fn report(&self) -> SemanticDiagnosticReport {
        let file = self.project.file(MAIN);
        let source = self
            .project
            .project()
            .read_source(&file)
            .expect("read target source");
        self.analyzer.semantic_diagnostics(&file, &source)
    }

    /// Rewrite a fixture file on disk after the analyzer already exists.
    fn rewrite(&self, path: &str, contents: &str) {
        ProjectFile::new(self.project.root().to_path_buf(), path)
            .write(contents)
            .expect("rewrite fixture file");
    }
}

/// The report for a project whose only interesting file is `src/main.cpp`.
fn report(files: &[(&str, &str)]) -> SemanticDiagnosticReport {
    Fixture::new(files).report()
}

fn has_incomplete_reason(
    report: &SemanticDiagnosticReport,
    matcher: fn(&SemanticDiagnosticIncompleteReason) -> bool,
) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(matcher)
        )
    })
}

/// The detail text of the first incomplete reason that carries one.
fn incomplete_details(report: &SemanticDiagnosticReport) -> Vec<String> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
            _ => None,
        })
        .flatten()
        .filter_map(|reason| match reason {
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
            | SemanticDiagnosticIncompleteReason::DynamicBehavior { detail }
            | SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { detail }
            | SemanticDiagnosticIncompleteReason::RuntimeUnavailable { detail }
            | SemanticDiagnosticIncompleteReason::CorruptSemanticPack { detail } => {
                Some(detail.clone())
            }
            _ => None,
        })
        .collect()
}

fn absent_type_names(report: &SemanticDiagnosticReport) -> Vec<String> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Absent(proof) => match &proof.domain {
                SemanticDiagnosticDomain::Type { name } => Some(name.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn resolved_count(report: &SemanticDiagnosticReport) -> usize {
    report
        .outcomes()
        .iter()
        .filter(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Resolved { .. }))
        .count()
}

fn missing_discovery_at(report: &SemanticDiagnosticReport, expected: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary }
                        if *boundary == expected
                ))
        )
    })
}

// --- the proving path ------------------------------------------------------

#[test]
fn a_complete_project_closure_proves_a_missing_type() {
    let report = report(&[
        ("include/known.hpp", "struct Known {};"),
        (
            MAIN,
            "#include \"known.hpp\"\nKnown present;\nMissing absent;",
        ),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert_eq!(
        SemanticDiagnosticReportStatus::Complete,
        report.status(),
        "{:#?}",
        report.outcomes()
    );
    assert_eq!(
        vec!["Missing".to_string()],
        absent_type_names(&report),
        "{:#?}",
        report.outcomes()
    );
    assert_eq!(1, report.diagnostics().len(), "{:#?}", report.outcomes());
    // The proven closure is entirely project-local, so that is the boundary the
    // absence proof may claim.
    let SemanticDiagnosticOutcome::Absent(proof) = report
        .outcomes()
        .iter()
        .find(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Absent(_)))
        .expect("an absence proof")
    else {
        unreachable!("filtered to absences")
    };
    assert_eq!(BoundaryStatus::WorkspaceLocal, proof.boundary);
}

#[test]
fn a_type_from_an_included_project_header_resolves_locally() {
    let report = report(&[
        ("include/known.hpp", "struct Known {};"),
        (MAIN, "#include \"known.hpp\"\nKnown present;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Resolved {
                boundary: BoundaryStatus::WorkspaceLocal,
                ..
            }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_forward_declaration_alone_still_makes_the_name_known() {
    let report = report(&[
        ("include/known.hpp", "struct Known;"),
        (MAIN, "#include \"known.hpp\"\nKnown *present;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert_eq!(SemanticDiagnosticReportStatus::Complete, report.status());
    assert_eq!(1, resolved_count(&report), "{:#?}", report.outcomes());
}

#[test]
fn a_name_two_namespaces_define_is_ambiguous_not_absent() {
    let report = report(&[
        (
            "include/shapes.hpp",
            "namespace alpha { struct Shape {}; }\nnamespace beta { struct Shape {}; }",
        ),
        (MAIN, "#include \"shapes.hpp\"\nShape value;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    // This pass matches bare names, so it genuinely cannot pick between the two
    // definitions. Saying so beats both a false error and a false resolution.
    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Ambiguous { boundaries, .. }
                if boundaries.len() == 2
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn an_alias_declaration_is_a_known_type_name() {
    // Before #1627 the closure collected only class, struct and enum names, so
    // every typedef and using alias was reported as an unrecognized type.
    let report = report(&[
        (
            "include/aliases.hpp",
            "typedef int Meters;\nusing Seconds = int;\nunion Payload {};",
        ),
        (
            MAIN,
            "#include \"aliases.hpp\"\nMeters distance;\nSeconds elapsed;\nPayload payload;",
        ),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert_eq!(SemanticDiagnosticReportStatus::Complete, report.status());
    // All three uses must actually be judged, or this test would pass for a
    // collector that stopped looking at type references altogether.
    assert_eq!(3, resolved_count(&report), "{:#?}", report.outcomes());
}

// --- typed suppressions ----------------------------------------------------

#[test]
fn a_file_the_compile_database_omits_is_unjudged() {
    let report = report(&[(MAIN, "Missing absent;")]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
    assert!(
        missing_discovery_at(&report, BoundaryStatus::ExternalUnknown),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_forced_include_suppresses_with_the_flag_named() {
    let report = report(&[
        ("include/prelude.hpp", "struct Prelude {};"),
        (MAIN, "Missing absent;"),
        (
            "compile_commands.json",
            &database(&["-include", "include/prelude.hpp"]),
        ),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("-include") && detail.contains("prelude.hpp")),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_system_include_root_suppresses_with_the_root_named() {
    let report = report(&[
        (MAIN, "Missing absent;"),
        (
            "compile_commands.json",
            &database(&["-isystem", "vendor/include"]),
        ),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("system include root")),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn an_angle_bracket_include_is_a_declared_but_unindexed_dependency() {
    let report = report(&[
        (MAIN, "#include <vector>\nMissing absent;"),
        ("compile_commands.json", &database(&[])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        missing_discovery_at(&report, BoundaryStatus::ExternalDeclaredUnindexed),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_quoted_include_that_resolves_to_nothing_is_declared_but_unindexed() {
    let report = report(&[
        (MAIN, "#include \"absent_header.hpp\"\nMissing absent;"),
        ("compile_commands.json", &database(&[])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        missing_discovery_at(&report, BoundaryStatus::ExternalDeclaredUnindexed),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_header_that_does_not_parse_suppresses_with_the_header_named() {
    let report = report(&[
        ("include/broken.hpp", "struct Broken { ; ) }"),
        (MAIN, "#include \"broken.hpp\"\nMissing absent;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("broken.hpp") && detail.contains("parse errors")),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_macro_definition_in_the_closure_is_a_generated_surface() {
    let report = report(&[
        (
            "include/macros.hpp",
            "#define WRAPPED(name) struct name {};",
        ),
        (MAIN, "#include \"macros.hpp\"\nMissing absent;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("WRAPPED")),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn conditional_compilation_in_the_closure_is_dynamic_behavior() {
    let report = report(&[
        (
            "include/conditional.hpp",
            "#ifdef FEATURE\nstruct Gated {};\n#endif",
        ),
        (MAIN, "#include \"conditional.hpp\"\nGated absent;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    // `Gated` exists in exactly one preprocessor state. Reporting it as unknown
    // would be a false error in the other.
    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_command_line_macro_type_name_is_a_generated_surface() {
    let report = report(&[
        (MAIN, "FEATURE value;"),
        ("compile_commands.json", &database(&["-D", "FEATURE"])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_pragma_in_the_closure_is_refused_rather_than_walked_past() {
    let report = report(&[
        ("include/guarded.hpp", "#pragma once\nstruct Guarded {};"),
        (MAIN, "#include \"guarded.hpp\"\nMissing absent;"),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    // The gate is closed by default: an unclassified directive suppresses.
    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("preprocessor directive")),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_file_with_parse_errors_is_incomplete_not_empty() {
    let report = report(&[
        (MAIN, "struct Broken { ; ) }"),
        ("compile_commands.json", &database(&[])),
    ]);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("parse errors")),
        "{:#?}",
        report.outcomes()
    );
}

// --- compile-command selection ---------------------------------------------

#[test]
fn two_configurations_that_agree_still_prove_the_absence() {
    let report = report(&[
        ("include/known.hpp", "struct Known {};"),
        (MAIN, "#include \"known.hpp\"\nMissing absent;"),
        (
            "compile_commands.json",
            r#"[
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-c","src/main.cpp"]},
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-DRELEASE","-c","src/main.cpp"]}
            ]"#,
        ),
    ]);

    // Neither configuration's closure has `Missing`, so the file is judged.
    assert_eq!(
        vec!["Missing".to_string()],
        absent_type_names(&report),
        "{:#?}",
        report.outcomes()
    );
    assert_eq!(SemanticDiagnosticReportStatus::Complete, report.status());
}

#[test]
fn two_configurations_that_disagree_leave_the_type_unjudged() {
    let report = report(&[
        ("debug/gated.hpp", "struct Gated {};"),
        ("release/other.hpp", "struct Other {};"),
        (
            MAIN,
            "#include \"gated.hpp\"\n#include \"other.hpp\"\nGated value;",
        ),
        (
            "compile_commands.json",
            r#"[
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","debug","-I","release","-c","src/main.cpp"]},
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","debug","-I","release","-DGated","-c","src/main.cpp"]}
            ]"#,
        ),
    ]);

    // The second configuration defines `Gated` as a command-line macro, so the
    // two configurations do not agree on what the name means.
    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        incomplete_details(&report)
            .iter()
            .any(|detail| detail.contains("disagree") && detail.contains("Gated")),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn one_unprovable_configuration_sinks_the_whole_file() {
    let report = report(&[
        ("include/known.hpp", "struct Known {};"),
        (MAIN, "#include \"known.hpp\"\nMissing absent;"),
        (
            "compile_commands.json",
            r#"[
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-c","src/main.cpp"]},
                {"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-isystem","vendor","-c","src/main.cpp"]}
            ]"#,
        ),
    ]);

    // A name missing from the closure that did prove out may well exist in the
    // configuration whose closure could not be reproduced.
    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert_eq!(SemanticDiagnosticReportStatus::Incomplete, report.status());
}

// --- header-change invalidation --------------------------------------------

#[test]
fn editing_a_header_withdraws_a_previously_proven_absence() {
    let fixture = Fixture::new(&[
        ("include/known.hpp", "struct Known {};"),
        (
            MAIN,
            "#include \"known.hpp\"\nKnown present;\nLater absent;",
        ),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    let before = fixture.report();
    assert_eq!(
        vec!["Later".to_string()],
        absent_type_names(&before),
        "{:#?}",
        before.outcomes()
    );

    // Adding the type to the header must retire the proof, not survive it in a
    // memo. The closure is re-read from disk on every request, so the same
    // analyzer generation already sees the edit.
    fixture.rewrite("include/known.hpp", "struct Known {};\nstruct Later {};");

    let after = fixture.report();
    assert!(
        after.diagnostics().is_empty(),
        "the absence proof outlived the header edit: {:#?}",
        after.outcomes()
    );
    assert_eq!(SemanticDiagnosticReportStatus::Complete, after.status());
}

#[test]
fn removing_a_type_from_a_header_produces_a_new_proof() {
    let fixture = Fixture::new(&[
        ("include/known.hpp", "struct Known {};\nstruct Later {};"),
        (
            MAIN,
            "#include \"known.hpp\"\nKnown present;\nLater absent;",
        ),
        ("compile_commands.json", &database(&["-I", "include"])),
    ]);

    assert!(fixture.report().diagnostics().is_empty());

    fixture.rewrite("include/known.hpp", "struct Known {};");

    let after = fixture.report();
    assert_eq!(
        vec!["Later".to_string()],
        absent_type_names(&after),
        "{:#?}",
        after.outcomes()
    );
}
