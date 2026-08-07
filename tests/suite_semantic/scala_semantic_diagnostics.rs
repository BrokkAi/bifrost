//! Scala semantic diagnostics, proof-gated by #1619.
//!
//! A name is reported only when every retained surface was able to miss it.
//! What used to be silent suppression is now a typed outcome: an import this
//! analyzer cannot follow records `UnsupportedSemantics` naming that import,
//! and an unbuilt or unreadable classpath records `MissingDependencyDiscovery`
//! naming the boundary.
//!
//! The error-producing half of the contract needs a published dependency model,
//! so it lives in `jvm_diagnostic_proof.rs` alongside Java's and Kotlin's.

use crate::common::InlineTestProject;
use crate::jvm_diagnostic_proof::{resolved_at, suppressed_for_missing_dependency};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::analyzer::structural::BoundaryStatus;
use brokk_bifrost::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
};
use brokk_bifrost::{
    AnalyzerConfig, IAnalyzer, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
    Language, ScalaAnalyzer,
};
use std::fs::File;
use std::io::Write;

fn report(files: &[(&str, &str)], target: &str) -> SemanticDiagnosticReport {
    let mut builder = InlineTestProject::with_language(Language::Scala);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let file = project.file(target);
    let source = analyzer.project().read_source(&file).unwrap();
    analyzer.semantic_diagnostics(&file, &source)
}

/// Whether `report` suppressed something because a construct is outside what
/// the resolver models -- an import it cannot follow, in this file's cases.
fn suppressed_as_unsupported(report: &SemanticDiagnosticReport) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Incomplete { reasons, .. }
        if reasons.iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics { .. }
        )))
    })
}

/// With no classpath configured and no dependency model published, nothing past
/// the workspace has been read, so an unknown type is suppressed with the
/// boundary named rather than reported.
#[test]
fn scala_semantic_diagnostics_suppress_unproved_simple_type() {
    let report = report(
        &[(
            "app/Consumer.scala",
            "package app\nclass Consumer(value: MissingType)\n",
        )],
        "app/Consumer.scala",
    );

    assert!(
        report.diagnostics().is_empty(),
        "an unproved name must not be reported: {:#?}",
        report.diagnostics()
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                        boundary: BoundaryStatus::ExternalUnknown,
                    }
                ))
        )),
        "the suppression must name the boundary it could not see past: {:#?}",
        report.outcomes()
    );
}

/// The same for a bare term reference.
#[test]
fn scala_semantic_diagnostics_suppress_unproved_bare_local_reference() {
    let report = report(
        &[(
            "app/Consumer.scala",
            "package app\ndef run(): Unit = { missingValue }\n",
        )],
        "app/Consumer.scala",
    );

    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        suppressed_for_missing_dependency(&report),
        "a bare term over an unread classpath is suppressed with a reason: {:#?}",
        report.outcomes()
    );
}

/// The mixed fixture that used to assert only "nothing was reported". Each of
/// its references now records which surface answered it: the workspace for the
/// declared types, and an unfollowable import for `DependencyType`.
#[test]
fn scala_semantic_diagnostics_separate_resolved_types_from_unfollowable_imports() {
    let report = report(
        &[
            ("model/Widget.scala", "package model\nclass Widget\n"),
            ("app/Local.scala", "package app\nclass Local\n"),
            (
                "app/Consumer.scala",
                r#"package app
import model.Widget
import model.*
import missing.DependencyType

class Consumer[T](local: Local, widget: Widget, inferred: T, text: String, values: List[Int], dependency: DependencyType)
class StandardLibraryDefaults(tuple: Tuple2[Int, String], callback: Function1[Int, String], partial: PartialFunction[Int, String], matching: Matchable, failure: RuntimeException)
"#,
            ),
        ],
        "app/Consumer.scala",
    );

    assert!(
        report.diagnostics().is_empty(),
        "nothing here is provably absent: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "`Local` and `Widget` are workspace declarations: {:#?}",
        report.outcomes()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "Scala's built-in type names are known by construction: {:#?}",
        report.outcomes()
    );
    assert!(
        suppressed_as_unsupported(&report),
        "the wildcard and `missing.DependencyType` imports cannot be followed, \
         and that is now a stated reason rather than silence: {:#?}",
        report.outcomes()
    );
}

#[test]
fn scala_semantic_diagnostics_resolve_same_package_singleton_term() {
    let report = report(
        &[(
            "app/Consumer.scala",
            "package app\nobject Service\ndef run(): Unit = { Service }\n",
        )],
        "app/Consumer.scala",
    );

    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "`Service` is declared in this very file: {:#?}",
        report.outcomes()
    );
}

/// A file the parser could not read has no reliable reference sites, so no name
/// in it can be proved absent.
#[test]
fn scala_semantic_diagnostics_suppress_malformed_source() {
    let report = report(
        &[(
            "app/Broken.scala",
            "package app\nclass Broken(value: MissingType\n",
        )],
        "app/Broken.scala",
    );

    assert!(report.diagnostics().is_empty());
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { range: None, reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    SemanticDiagnosticIncompleteReason::UnsupportedSemantics { .. }
                ))
        )),
        "an unparseable file must say so: {:#?}",
        report.outcomes()
    );
}

/// A type that exists only in a dependency source jar. The diagnostic does not
/// build that index -- reading jars inside a request is what #1615 forbids -- so
/// the host's warm hook builds it and the ladder then reads it.
#[test]
fn scala_semantic_diagnostics_resolve_same_package_external_source_jar_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Consumer.scala",
            "package app\nclass Consumer(value: Dependency)\n",
        )
        .build();
    let artifact = project.root().join("dependency-sources.jar");
    write_source_jar(
        &artifact,
        "app/Dependency.scala",
        "package app\nclass Dependency\n",
    );
    let analyzer = ScalaAnalyzer::new_with_config(
        project.project_arc(),
        AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    artifact_paths: vec![JvmExternalArtifact {
                        artifact_path: artifact,
                        source_artifact_path: None,
                        ..JvmExternalArtifact::default()
                    }],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        },
    );
    let file = project.file("app/Consumer.scala");
    let source = analyzer.project().read_source(&file).unwrap();

    let cold = analyzer.semantic_diagnostics(&file, &source);
    assert!(cold.diagnostics().is_empty(), "{:#?}", cold.diagnostics());
    assert!(
        suppressed_for_missing_dependency(&cold),
        "an unbuilt jar index cannot resolve or refute anything: {:#?}",
        cold.outcomes()
    );

    analyzer.warm_query_indexes();
    let warm = analyzer.semantic_diagnostics(&file, &source);
    assert!(warm.diagnostics().is_empty(), "{:#?}", warm.diagnostics());
    assert!(
        resolved_at(&warm, BoundaryStatus::ExternalIndexed),
        "the warmed jar index holds `app.Dependency`: {:#?}",
        warm.outcomes()
    );
}

fn write_source_jar(path: &std::path::Path, entry: &str, source: &str) {
    let file = File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(entry, zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(source.as_bytes()).unwrap();
    zip.finish().unwrap();
}
