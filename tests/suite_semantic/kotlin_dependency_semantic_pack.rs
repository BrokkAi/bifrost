use std::fs::File;
use std::io::Write;

use brokk_bifrost::analyzer::JvmDependencyPackAdapter;
use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, get_definitions_by_location,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;
use zip::write::SimpleFileOptions;

use crate::common::InlineTestProject;

#[test]
fn exact_kotlin_source_dependency_navigates_by_kotlin_identity() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("kotlin-library-2.2.0-sources.jar");
    let mut writer = zip::ZipWriter::new(File::create(&archive).unwrap());
    writer
        .start_file("kotlin/example/Dependency.kt", SimpleFileOptions::default())
        .unwrap();
    writer
        .write_all(
            br#"package kotlin.example
interface Contract {
    fun inherited(): String
}
class Dependency(val value: String) : Contract {
    companion object {
        fun create(): Dependency = Dependency("created")
    }
}
fun topLevelHelper(value: String): Dependency = Dependency(value)
fun Dependency.describe(): String = value
fun <T> T.identityLike(): T = this
fun <T> T.contractOnly(): String where T : Contract = inherited()
fun Contract.contractExtension(): String = inherited()
fun <T : Any> T.anyExtension(): String = toString()
fun Contract.makeDependency(): Dependency = Dependency("modeled")
fun shadowed(): String = "model"
"#,
        )
        .unwrap();
    writer.finish().unwrap();

    let dependency = ResolvedDependency {
        id: "example:kotlin-library:2.2.0".to_owned(),
        evidence: SemanticModelActivationEvidence {
            language: "kotlin".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "example:kotlin-library".to_owned(),
                version: Some(Version::new(2, 2, 0)),
            }),
            module: None,
            toolchain: None,
            target: Some("jvm".to_owned()),
            configuration: Some("compile".to_owned()),
            artifact_sha256: None,
        },
        provenance: Vec::new(),
        artifacts: vec![ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Sources,
            ExternalArtifactKind::KotlinSourceJar,
            archive,
        )],
    };
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &JvmDependencyPackAdapter,
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );
    assert!(prepared.complete, "{:#?}", prepared.diagnostics);
    assert_eq!(prepared.packs.len(), 1);
    assert_eq!(
        prepared.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );

    let project = InlineTestProject::with_language(Language::Kotlin)
        .file(
            "src/App.kt",
            "package app\nimport kotlin.example.Dependency\nimport kotlin.example.Contract\nimport kotlin.example.topLevelHelper\nimport kotlin.example.shadowed\nimport kotlin.example.describe\nimport kotlin.example.identityLike\nimport kotlin.example.contractOnly\nimport kotlin.example.contractExtension\nimport kotlin.example.anyExtension\nimport kotlin.example.makeDependency\nabstract class Local : Contract\nfun use(dep: Dependency): Dependency = topLevelHelper(dep.value)\nfun make(): Dependency = Dependency.create()\nfun construct(): Dependency = Dependency(\"x\")\nfun shadow(): String = shadowed()\nfun inherited(dep: Dependency): String = dep.inherited()\nfun extended(dep: Dependency): String = dep.describe()\nfun chained(): String = topLevelHelper(\"x\").describe()\nfun companionChained(): String = Dependency.create().describe()\nfun generic(dep: Dependency): Dependency = dep.identityLike()\nfun constrained(dep: Dependency): String = dep.contractOnly()\nfun nearMiss(value: String): String = value.contractOnly()\nfun localInherited(local: Local): String = local.inherited()\nfun localExtended(local: Local): String = local.contractExtension()\nfun localAny(local: Local): String = local.anyExtension()\nfun localChain(local: Local): String = local.makeDependency().describe()\n",
        )
        .file(
            "src/Workspace.kt",
            "package kotlin.example\nfun shadowed(): String = \"workspace\"\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let request = prepared
        .compose_activation_request(SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        })
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("Kotlin dependency pack must activate");
    };

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(2),
                    column: Some(24),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(4),
                    column: Some(24),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(13),
                    column: Some(28),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(13),
                    column: Some(41),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(13),
                    column: Some(60),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(14),
                    column: Some(38),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(15),
                    column: Some(32),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(16),
                    column: Some(24),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(17),
                    column: Some(46),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(18),
                    column: Some(45),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(19),
                    column: Some(47),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(20),
                    column: Some(57),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(21),
                    column: Some(50),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(22),
                    column: Some(55),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(23),
                    column: Some(55),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(24),
                    column: Some(55),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(25),
                    column: Some(55),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(26),
                    column: Some(50),
                },
                DefinitionReferenceQuery {
                    path: "src/App.kt".to_owned(),
                    line: Some(27),
                    column: Some(68),
                },
            ],
        },
    );
    assert_eq!(definitions.results.len(), 19, "{definitions:#?}");
    for result in &definitions.results[..7] {
        assert_eq!(result.status, "resolved", "{result:#?}");
        assert_eq!(result.definitions.len(), 1, "{result:#?}");
        assert_eq!(
            result.definitions[0].path, "kotlin/example/Dependency.kt",
            "{result:#?}"
        );
        assert!(
            !result.definitions[0]
                .fqn
                .as_deref()
                .unwrap_or_default()
                .contains("Kt"),
            "{result:#?}"
        );
    }
    assert_eq!(
        definitions.results[0].definitions[0].fqn.as_deref(),
        Some("kotlin.example.Dependency")
    );
    assert_eq!(
        definitions.results[1].definitions[0].fqn.as_deref(),
        Some("kotlin.example.topLevelHelper")
    );
    assert_eq!(
        definitions.results[2].definitions[0].fqn.as_deref(),
        Some("kotlin.example.Dependency")
    );
    assert_eq!(
        definitions.results[4].definitions[0].fqn.as_deref(),
        Some("kotlin.example.Dependency.value")
    );
    assert_eq!(
        definitions.results[5].definitions[0].fqn.as_deref(),
        Some("kotlin.example.Dependency.Companion.create")
    );
    assert_eq!(definitions.results[7].status, "resolved");
    assert_eq!(
        definitions.results[7].definitions[0].path,
        "src/Workspace.kt"
    );
    assert_eq!(
        definitions.results[8].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[8].definitions[0].fqn.as_deref(),
        Some("kotlin.example.Contract.inherited")
    );
    assert_eq!(
        definitions.results[9].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[9].definitions[0].fqn.as_deref(),
        Some("kotlin.example.describe")
    );
    assert_eq!(
        definitions.results[10].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[10].definitions[0].fqn.as_deref(),
        Some("kotlin.example.describe")
    );
    assert_eq!(
        definitions.results[11].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[11].definitions[0].fqn.as_deref(),
        Some("kotlin.example.describe")
    );
    assert_eq!(
        definitions.results[12].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[12].definitions[0].fqn.as_deref(),
        Some("kotlin.example.identityLike")
    );
    assert_eq!(
        definitions.results[13].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[13].definitions[0].fqn.as_deref(),
        Some("kotlin.example.contractOnly")
    );
    assert_eq!(
        definitions.results[14].status, "no_definition",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[15].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[15].definitions[0].fqn.as_deref(),
        Some("kotlin.example.Contract.inherited")
    );
    assert_eq!(
        definitions.results[16].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[16].definitions[0].fqn.as_deref(),
        Some("kotlin.example.contractExtension")
    );
    assert_eq!(
        definitions.results[17].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[17].definitions[0].fqn.as_deref(),
        Some("kotlin.example.anyExtension")
    );
    assert_eq!(
        definitions.results[18].status, "resolved",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[18].definitions[0].fqn.as_deref(),
        Some("kotlin.example.describe")
    );
}
