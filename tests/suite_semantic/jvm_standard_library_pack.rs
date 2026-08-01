use std::fs::File;
use std::io::Write;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::analyzer::{
    JdkSourceArchiveLayout, JdkSourceArchivePackProducer, ScalaSourceJarPackProducer,
};
use brokk_bifrost::searchtools::{SymbolLookupParams, get_symbol_ancestors};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;
use zip::write::SimpleFileOptions;

use crate::common::InlineTestProject;

#[test]
fn jdk_pack_navigation_uses_explicit_hierarchy_then_lazy_object_fallback() {
    let archive_root = tempfile::tempdir().unwrap();
    let archive = archive_root.path().join("src.zip");
    write_zip(
        &archive,
        &[
            (
                "java.base/module-info.java",
                "module java.base { exports java.lang; }",
            ),
            (
                "java.base/java/lang/Object.java",
                "package java.lang; public class Object { public int hashCode() { return 0; } }",
            ),
            (
                "java.base/java/lang/Parent.java",
                "package java.lang; public class Parent extends Object {}",
            ),
            (
                "java.base/java/lang/Leaf.java",
                "package java.lang; public class Leaf {}",
            ),
        ],
    );
    let production = JdkSourceArchivePackProducer::new(JdkSourceArchiveLayout::ModulePrefixed)
        .produce_exact_artifact(
            &production_request(archive),
            &ArtifactProducerLimits::default(),
        );
    assert!(
        production.diagnostics.is_empty(),
        "{:#?}",
        production.diagnostics
    );
    let compiled = compile_pack(
        production.pack.as_ref().expect("JDK pack"),
        &CompilerOptions::default(),
    )
    .unwrap();

    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Main.java", "public class Main {}")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let files_before = analyzer.analyzer().project().all_files().unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "jdk-fixture".to_owned(),
            },
        )
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &jdk_activation_request(
            production
                .artifact_sha256
                .as_deref()
                .expect("exact artifact digest"),
            "21.0.2",
        ),
        &CancellationToken::default(),
    ) else {
        panic!("JDK pack must activate");
    };
    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("active JDK overlay");

    let parent = overlay.symbols_named("java.lang.Parent");
    let parent_ancestors = overlay.ancestors_of(parent.records[0]);
    assert_eq!(
        parent_ancestors
            .records
            .iter()
            .map(|symbol| symbol.qualified_name.as_str())
            .collect::<Vec<_>>(),
        vec!["java.lang.Object"]
    );
    let leaf = overlay.symbols_named("java.lang.Leaf");
    assert!(
        overlay
            .relations_from(&leaf.records[0].id)
            .records
            .is_empty()
    );
    let leaf_ancestors = overlay.ancestors_of(leaf.records[0]);
    assert_eq!(
        leaf_ancestors
            .records
            .iter()
            .map(|symbol| symbol.qualified_name.as_str())
            .collect::<Vec<_>>(),
        vec!["java.lang.Object"]
    );

    let navigation = get_symbol_ancestors(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["Main".to_owned(), "java.lang.Leaf".to_owned()],
        },
    );
    assert!(
        navigation.not_found.is_empty(),
        "{:#?}",
        navigation.not_found
    );
    assert!(
        navigation.ambiguous.is_empty(),
        "{:#?}",
        navigation.ambiguous
    );
    assert!(
        navigation
            .ancestors
            .iter()
            .any(|result| { result.symbol == "Main" && result.ancestors == ["java.lang.Object"] })
    );
    assert!(navigation.ancestors.iter().any(|result| {
        result.symbol == "java.lang.Leaf" && result.ancestors == ["java.lang.Object"]
    }));
    assert_eq!(
        files_before,
        analyzer.analyzer().project().all_files().unwrap()
    );

    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &jdk_activation_request(production.artifact_sha256.as_deref().unwrap(), "17.0.10"),
        &CancellationToken::default(),
    ) else {
        panic!("a complete mismatch is still a ready empty model set");
    };
    assert!(active.shards().is_empty());
    assert!(active.activation_report().explanations.iter().any(|entry| {
        entry.status == SemanticModelActivationStatus::Incompatible
            && entry.reason.contains("does not satisfy")
    }));
}

#[test]
fn scala_pack_navigation_uses_explicit_hierarchy_then_lazy_any_fallback() {
    let archive_root = tempfile::tempdir().unwrap();
    let archive = archive_root.path().join("scala-library-sources.jar");
    write_zip(
        &archive,
        &[(
            "scala/Core.scala",
            "package scala\ntrait Any\nclass Parent extends Any\nclass Leaf\n",
        )],
    );
    let production = ScalaSourceJarPackProducer.produce_exact_artifact(
        &scala_production_request(archive),
        &ArtifactProducerLimits::default(),
    );
    assert!(
        production.diagnostics.is_empty(),
        "{:#?}",
        production.diagnostics
    );
    let compiled = compile_pack(
        production.pack.as_ref().expect("Scala pack"),
        &CompilerOptions::default(),
    )
    .unwrap();
    let project = InlineTestProject::with_language(Language::Scala)
        .file("src/Main.scala", "class Main")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "scala-fixture".to_owned(),
            },
        )
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &scala_activation_request(production.artifact_sha256.as_deref().unwrap()),
        &CancellationToken::default(),
    ) else {
        panic!("Scala pack must activate");
    };
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    for name in ["scala.Parent", "scala.Leaf"] {
        let matched = overlay.symbols_named(name);
        let ancestors = overlay.ancestors_of(matched.records[0]);
        assert_eq!(
            ancestors
                .records
                .iter()
                .map(|symbol| symbol.qualified_name.as_str())
                .collect::<Vec<_>>(),
            vec!["scala.Any"]
        );
    }
    let navigation = get_symbol_ancestors(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["Main".to_owned(), "scala.Leaf".to_owned()],
        },
    );
    assert!(
        navigation.not_found.is_empty(),
        "{:#?}",
        navigation.not_found
    );
    assert!(
        navigation
            .ancestors
            .iter()
            .any(|result| { result.symbol == "Main" && result.ancestors == ["scala.Any"] })
    );
    assert!(
        navigation
            .ancestors
            .iter()
            .any(|result| { result.symbol == "scala.Leaf" && result.ancestors == ["scala.Any"] })
    );
}

fn production_request(path: std::path::PathBuf) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path,
        artifact_kind: ExternalArtifactKind::JdkSourceZip,
        pack_id: "jdk-21-fixture".to_owned(),
        pack_version: "21.0.2".to_owned(),
        ecosystem: "jdk".to_owned(),
        compatibility: Compatibility {
            bifrost: ">=0.8.0, <1.0.0".to_owned(),
            toolchains: vec![VersionConstraint {
                name: "jdk".to_owned(),
                requirement: "=21.0.2".to_owned(),
            }],
        },
        activation: vec![ActivationSelector {
            package: None,
            module: None,
            toolchain: Some(NameSelector {
                name: "jdk".to_owned(),
                version: Some("21.0.2".to_owned()),
            }),
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "checked-in test source".to_owned(),
            revision: Some("jdk-21.0.2+13".to_owned()),
        },
        license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn jdk_activation_request(artifact_sha256: &str, version: &str) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "jdk".to_owned(),
            package: None,
            module: Some(CatalogCoordinate {
                name: "java.base".to_owned(),
                version: None,
            }),
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse(version).unwrap()),
            }),
            target: None,
            configuration: None,
            artifact_sha256: Some(artifact_sha256.to_owned()),
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn scala_production_request(path: std::path::PathBuf) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path,
        artifact_kind: ExternalArtifactKind::ScalaSourceJar,
        pack_id: "scala-library-2.13-fixture".to_owned(),
        pack_version: "2.13.16".to_owned(),
        ecosystem: "maven".to_owned(),
        compatibility: Compatibility {
            bifrost: ">=0.8.0, <1.0.0".to_owned(),
            toolchains: vec![VersionConstraint {
                name: "scala".to_owned(),
                requirement: "=2.13.16".to_owned(),
            }],
        },
        activation: vec![ActivationSelector {
            package: Some(NameSelector {
                name: "org.scala-lang:scala-library".to_owned(),
                version: Some("=2.13.16".to_owned()),
            }),
            module: None,
            toolchain: Some(NameSelector {
                name: "scala".to_owned(),
                version: Some("=2.13.16".to_owned()),
            }),
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "checked-in test source".to_owned(),
            revision: Some("v2.13.16".to_owned()),
        },
        license: "Apache-2.0".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

fn scala_activation_request(artifact_sha256: &str) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "scala".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "org.scala-lang:scala-library".to_owned(),
                version: Some(Version::parse("2.13.16").unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "scala".to_owned(),
                version: Some(Version::parse("2.13.16").unwrap()),
            }),
            target: None,
            configuration: None,
            artifact_sha256: Some(artifact_sha256.to_owned()),
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn write_zip(path: &std::path::Path, entries: &[(&str, &str)]) {
    let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
    for (entry_name, source) in entries {
        writer
            .start_file(*entry_name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(source.as_bytes()).unwrap();
    }
    writer.finish().unwrap();
}
