//! Kotlin semantic diagnostics (issue #1243, proof-gated by #1619).
//!
//! A reference is classified through Kotlin's whole ladder: imports, the file's
//! own package, star imports, Kotlin's default imports, the wider JVM source
//! realm, the retained jar-backed dependency index, and the active dependency
//! model. Only a name every retained surface was able to miss becomes an error,
//! and every suppression carries its reason.
//!
//! The error-producing half of the contract needs a published dependency model,
//! so it lives in `jvm_diagnostic_proof.rs` alongside Java's and Scala's. What
//! this file pins is Kotlin's own tier structure: which names each tier
//! resolves, and what a tier that cannot answer records instead.

use crate::common::InlineTestProject;
use crate::jvm_diagnostic_proof::{resolved_at, suppressed_for_missing_dependency};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::analyzer::structural::BoundaryStatus;
use brokk_bifrost::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
};
use brokk_bifrost::{
    AnalyzerConfig, AnalyzerDelegate, IAnalyzer, JavaAnalyzer, JvmAnalyzerConfig,
    JvmExternalArtifact, JvmExternalDependencies, KotlinAnalyzer, Language, MultiAnalyzer,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

fn report(files: &[(&str, &str)], target: &str) -> SemanticDiagnosticReport {
    let mut builder = InlineTestProject::with_language(Language::Kotlin);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    let file = project.file(target);
    let source = analyzer.project().read_source(&file).unwrap();
    analyzer.semantic_diagnostics(&file, &source)
}

/// Assert that `target` resolved every name it spells, at the workspace
/// boundary, and reported nothing.
fn assert_all_resolved_locally(files: &[(&str, &str)], target: &str) {
    let report = report(files, target);
    assert!(
        report.diagnostics().is_empty(),
        "{target}: {:#?}",
        report.diagnostics()
    );
    assert!(
        resolved_at(&report, BoundaryStatus::WorkspaceLocal),
        "{target} must resolve its reference against a workspace declaration: {:#?}",
        report.outcomes()
    );
    assert!(
        !suppressed_for_missing_dependency(&report),
        "{target} resolved locally, so no dependency boundary was needed: {:#?}",
        report.outcomes()
    );
}

/// A multi-language analyzer over an inline workspace, with one delegate per
/// JVM language the fixture actually uses (local to this test file -- the
/// shared `jvm_shared_realm.rs` helper belongs to a different issue's test
/// module).
fn jvm_workspace(files: &[(&str, &str)]) -> (crate::common::BuiltInlineTestProject, MultiAnalyzer) {
    let mut project = InlineTestProject::new();
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();

    let mut delegates = BTreeMap::new();
    for language in built.languages() {
        let delegate = match language {
            Language::Java => AnalyzerDelegate::Java(JavaAnalyzer::new(built.project_dyn())),
            Language::Kotlin => AnalyzerDelegate::Kotlin(KotlinAnalyzer::new(built.project_dyn())),
            other => panic!("unexpected language in JVM fixture: {other:?}"),
        };
        delegates.insert(language, delegate);
    }
    (built, MultiAnalyzer::new(delegates))
}

/// A name no tier reaches is suppressed, not reported: with no classpath
/// configured and no dependency model published, nothing past the workspace has
/// been read, so `MissingType` may well be a JDK or dependency type.
///
/// `jvm_diagnostic_proof.rs` pins the other half -- the same file *does* report
/// it once a model is published.
#[test]
fn kotlin_semantic_diagnostics_suppress_unproved_type_reference() {
    let report = report(
        &[(
            "app/Consumer.kt",
            "package app\n\nclass Consumer(value: MissingType)\n",
        )],
        "app/Consumer.kt",
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

#[test]
fn kotlin_semantic_diagnostics_resolve_import_resolved_type() {
    assert_all_resolved_locally(
        &[
            ("lib/Base.kt", "package lib\n\nopen class Base\n"),
            (
                "app/Consumer.kt",
                "package app\n\nimport lib.Base\n\nclass Consumer(value: Base)\n",
            ),
        ],
        "app/Consumer.kt",
    );
}

#[test]
fn kotlin_semantic_diagnostics_resolve_star_import_resolved_type() {
    assert_all_resolved_locally(
        &[
            ("lib/Base.kt", "package lib\n\nopen class Base\n"),
            (
                "app/Consumer.kt",
                "package app\n\nimport lib.*\n\nclass Consumer(value: Base)\n",
            ),
        ],
        "app/Consumer.kt",
    );
}

#[test]
fn kotlin_semantic_diagnostics_resolve_default_import_resolved_type() {
    // `kotlin.text` is one of Kotlin's default-import packages (no explicit
    // `import` names it). A real workspace declaration under that package is
    // enough to exercise the tier structurally, without depending on a real
    // `kotlin-stdlib` jar being on the configured classpath.
    assert_all_resolved_locally(
        &[
            (
                "kotlin/text/Snippet.kt",
                "package kotlin.text\n\nclass Snippet\n",
            ),
            (
                "app/Consumer.kt",
                "package app\n\nclass Consumer(value: Snippet)\n",
            ),
        ],
        "app/Consumer.kt",
    );
}

/// Two star imports binding one spelling to different owners: Kotlin itself
/// rejects the reference, so this is a known answer rather than a missing
/// declaration, and it must never be reported as unrecognized.
#[test]
fn kotlin_semantic_diagnostics_keep_a_star_import_collision_ambiguous() {
    let report = report(
        &[
            ("left/Base.kt", "package left\n\nopen class Base\n"),
            ("right/Base.kt", "package right\n\nopen class Base\n"),
            (
                "app/Consumer.kt",
                "package app\n\nimport left.*\nimport right.*\n\nclass Consumer(value: Base)\n",
            ),
        ],
        "app/Consumer.kt",
    );

    assert!(
        report.diagnostics().is_empty(),
        "an ambiguous reference is not an unrecognized one: {:#?}",
        report.diagnostics()
    );
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Ambiguous { .. })),
        "the collision must be recorded as ambiguity: {:#?}",
        report.outcomes()
    );
}

/// A file the parser could not read has no reliable reference sites, so no name
/// in it can be proved absent. The LSP still publishes the parse errors
/// themselves through its own path.
#[test]
fn kotlin_semantic_diagnostics_suppress_malformed_source() {
    let report = report(
        &[(
            "app/Broken.kt",
            "package app\n\nclass Broken(value: MissingType\n",
        )],
        "app/Broken.kt",
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

/// A type that exists only in a dependency source jar. The jar index is not
/// built by the diagnostic itself -- that would be package I/O inside a request
/// -- so the host's warm hook builds it first, and the ladder then resolves the
/// name at the external boundary.
#[test]
fn kotlin_semantic_diagnostics_resolve_same_package_external_source_jar_type() {
    let project = InlineTestProject::with_language(Language::Kotlin)
        .file(
            "app/Consumer.kt",
            "package app\n\nclass Consumer(value: Dependency)\n",
        )
        .build();
    let artifact = project.root().join("dependency-sources.jar");
    write_source_jar(
        &artifact,
        "app/Dependency.java",
        "package app;\npublic class Dependency {}\n",
    );
    let analyzer = KotlinAnalyzer::new_with_config(
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
    let file = project.file("app/Consumer.kt");
    let source = analyzer.project().read_source(&file).unwrap();

    // Before the warm hook runs, nothing past the workspace is readable.
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

/// The realm widens *resolution*: only `MultiAnalyzer` can see that a Kotlin
/// file's `Api` is a Java sibling's declaration. Without it the name is not
/// resolved -- and, since #1619, not reported either, because an unresolved
/// name over an unread classpath proves nothing.
#[test]
fn kotlin_semantic_diagnostics_resolve_jvm_realm_type_only_through_multi_analyzer() {
    let files = [
        (
            "src/app/Api.java",
            "package app;\n\npublic interface Api {}\n",
        ),
        (
            "src/app/Consumer.kt",
            "package app\n\nclass Consumer(value: Api)\n",
        ),
    ];

    // Without the wider JVM realm, Kotlin's own index never sees the Java
    // declaration next door.
    let kotlin_only = report(&files, "src/app/Consumer.kt");
    assert!(
        kotlin_only.diagnostics().is_empty(),
        "an unproved name is never reported: {:#?}",
        kotlin_only.diagnostics()
    );
    assert!(
        !resolved_at(&kotlin_only, BoundaryStatus::WorkspaceLocal),
        "a bare KotlinAnalyzer has no visibility into the Java sibling: {:#?}",
        kotlin_only.outcomes()
    );
    assert!(
        suppressed_for_missing_dependency(&kotlin_only),
        "it stops at the dependency boundary instead: {:#?}",
        kotlin_only.outcomes()
    );

    // Through `MultiAnalyzer`, the same reference resolves via the shared JVM
    // source realm.
    let (built, analyzer) = jvm_workspace(&files);
    let file = built.file("src/app/Consumer.kt");
    let source = analyzer.project().read_source(&file).unwrap();
    let realm_report = analyzer.semantic_diagnostics(&file, &source);
    assert!(
        realm_report.diagnostics().is_empty(),
        "{:#?}",
        realm_report.diagnostics()
    );
    assert!(
        resolved_at(&realm_report, BoundaryStatus::WorkspaceLocal),
        "the realm makes the Java sibling a workspace declaration: {:#?}",
        realm_report.outcomes()
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
