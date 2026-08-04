//! Kotlin semantic diagnostics (issue #1243): high-confidence unresolved-type
//! reporting only. A reference is flagged iff it resolves through NEITHER
//! imports, the file's own package, star imports, Kotlin's default imports,
//! the wider JVM source realm, NOR the external (jar-backed) dependency
//! index. Mirrors `scala_semantic_diagnostics.rs`'s shape.

use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{
    AnalyzerConfig, AnalyzerDelegate, IAnalyzer, JavaAnalyzer, JvmAnalyzerConfig,
    JvmExternalArtifact, JvmExternalDependencies, KotlinAnalyzer, Language, MultiAnalyzer,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

fn diagnostics(files: &[(&str, &str)], target: &str) -> String {
    let mut builder = InlineTestProject::with_language(Language::Kotlin);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    let file = project.file(target);
    let source = analyzer.project().read_source(&file).unwrap();
    format!("{:#?}", analyzer.semantic_diagnostics(&file, &source))
}

/// A multi-language analyzer over an inline workspace, with one delegate per
/// JVM language the fixture actually uses (local to this test file — the
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

#[test]
fn kotlin_semantic_diagnostics_report_unknown_type_reference() {
    let diagnostics = diagnostics(
        &[(
            "app/Consumer.kt",
            "package app\n\nclass Consumer(value: MissingType)\n",
        )],
        "app/Consumer.kt",
    );

    assert!(
        diagnostics.contains("kotlin_unrecognized_symbol"),
        "{diagnostics}"
    );
    assert!(diagnostics.contains("MissingType"), "{diagnostics}");
}

#[test]
fn kotlin_semantic_diagnostics_suppress_import_resolved_type() {
    let diagnostics = diagnostics(
        &[
            ("lib/Base.kt", "package lib\n\nopen class Base\n"),
            (
                "app/Consumer.kt",
                "package app\n\nimport lib.Base\n\nclass Consumer(value: Base)\n",
            ),
        ],
        "app/Consumer.kt",
    );

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn kotlin_semantic_diagnostics_suppress_star_import_resolved_type() {
    let diagnostics = diagnostics(
        &[
            ("lib/Base.kt", "package lib\n\nopen class Base\n"),
            (
                "app/Consumer.kt",
                "package app\n\nimport lib.*\n\nclass Consumer(value: Base)\n",
            ),
        ],
        "app/Consumer.kt",
    );

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn kotlin_semantic_diagnostics_suppress_default_import_resolved_type() {
    // `kotlin.text` is one of Kotlin's default-import packages (no explicit
    // `import` names it). A real workspace declaration under that package is
    // enough to exercise the tier structurally, without depending on a real
    // `kotlin-stdlib` jar being on the configured classpath.
    let diagnostics = diagnostics(
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

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn kotlin_semantic_diagnostics_suppress_malformed_source() {
    let diagnostics = diagnostics(
        &[(
            "app/Broken.kt",
            "package app\n\nclass Broken(value: MissingType\n",
        )],
        "app/Broken.kt",
    );

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn kotlin_semantic_diagnostics_suppress_same_package_external_source_jar_type() {
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
    let diagnostics = format!("{:#?}", analyzer.semantic_diagnostics(&file, &source));

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn kotlin_semantic_diagnostics_suppress_jvm_realm_resolved_type_only_through_multi_analyzer() {
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
    // declaration next door, and reports it as unrecognized.
    let kotlin_only = diagnostics(&files, "src/app/Consumer.kt");
    assert!(
        kotlin_only.contains("kotlin_unrecognized_symbol"),
        "a bare KotlinAnalyzer has no visibility into the Java sibling: {kotlin_only}"
    );

    // Through `MultiAnalyzer`, the same reference resolves via the shared
    // JVM source realm and stays silent.
    let (built, analyzer) = jvm_workspace(&files);
    let file = built.file("src/app/Consumer.kt");
    let source = analyzer.project().read_source(&file).unwrap();
    let realm_diagnostics = format!("{:#?}", analyzer.semantic_diagnostics(&file, &source));
    assert_eq!("[]", realm_diagnostics, "{realm_diagnostics}");
}

fn write_source_jar(path: &std::path::Path, entry: &str, source: &str) {
    let file = File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(entry, zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(source.as_bytes()).unwrap();
    zip.finish().unwrap();
}
