use crate::common::InlineTestProject;
use brokk_bifrost::{
    AnalyzerConfig, IAnalyzer, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
    Language, ScalaAnalyzer,
};
use std::fs::File;
use std::io::Write;

fn diagnostics(files: &[(&str, &str)], target: &str) -> String {
    let mut builder = InlineTestProject::with_language(Language::Scala);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let file = project.file(target);
    let source = analyzer.project().read_source(&file).unwrap();
    format!(
        "{:#?}",
        analyzer.semantic_diagnostics(&file, &source).diagnostics()
    )
}

#[test]
fn scala_semantic_diagnostics_report_unknown_simple_type() {
    let diagnostics = diagnostics(
        &[(
            "app/Consumer.scala",
            "package app\nclass Consumer(value: MissingType)\n",
        )],
        "app/Consumer.scala",
    );

    assert!(
        diagnostics.contains("scala_unrecognized_symbol"),
        "{diagnostics}"
    );
    assert!(diagnostics.contains("MissingType"), "{diagnostics}");
}

#[test]
fn scala_semantic_diagnostics_report_unknown_bare_local_reference() {
    let diagnostics = diagnostics(
        &[(
            "app/Consumer.scala",
            "package app\ndef run(): Unit = { missingValue }\n",
        )],
        "app/Consumer.scala",
    );

    assert!(
        diagnostics.contains("scala_unrecognized_symbol"),
        "{diagnostics}"
    );
    assert!(diagnostics.contains("missingValue"), "{diagnostics}");
}

#[test]
fn scala_semantic_diagnostics_suppress_known_and_uncertain_type_boundaries() {
    let diagnostics = diagnostics(
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

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn scala_semantic_diagnostics_suppress_same_package_singleton_term() {
    let diagnostics = diagnostics(
        &[(
            "app/Consumer.scala",
            "package app\nobject Service\ndef run(): Unit = { Service }\n",
        )],
        "app/Consumer.scala",
    );

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn scala_semantic_diagnostics_suppress_malformed_source() {
    let diagnostics = diagnostics(
        &[(
            "app/Broken.scala",
            "package app\nclass Broken(value: MissingType\n",
        )],
        "app/Broken.scala",
    );

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

#[test]
fn scala_semantic_diagnostics_suppress_same_package_external_source_jar_type() {
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
    let report = analyzer.semantic_diagnostics(&file, &source);
    let diagnostics = format!("{:#?}", report.diagnostics());

    assert_eq!("[]", diagnostics, "{diagnostics}");
}

fn write_source_jar(path: &std::path::Path, entry: &str, source: &str) {
    let file = File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(entry, zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(source.as_bytes()).unwrap();
    zip.finish().unwrap();
}
