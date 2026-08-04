use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, ScanUsagesByReferenceParams, ScanUsagesStatus,
    SymbolLookupParams, get_definitions_by_location, get_symbol_sources, scan_usages_by_reference,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language, WorkspaceAnalyzer};
use semver::Version;

use crate::common::InlineTestProject;

fn activate_scala(analyzer: &WorkspaceAnalyzer) {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    brokk_bifrost::semantic_packs::BIFROST_EMBEDDED_PACKS
        .register_all(&catalog, &DecodeLimits::default())
        .unwrap();
    let request = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "scala".to_owned(),
            ecosystem: "maven".to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &request,
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));
}

fn activate_lombok(
    analyzer: &WorkspaceAnalyzer,
    package: Option<&str>,
    version: Option<&str>,
) -> SemanticModelRuntimeOutcome {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    brokk_bifrost::semantic_packs::BIFROST_EMBEDDED_PACKS
        .register_all(&catalog, &DecodeLimits::default())
        .unwrap();
    acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: package.map(|name| CatalogCoordinate {
                    name: name.to_owned(),
                    version: version.map(|value| Version::parse(value).unwrap()),
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    )
}

fn modeled_member<'a>(
    overlay: &'a SemanticModelOverlay,
    owner: &str,
    name: &str,
) -> Vec<&'a SemanticModelSymbol> {
    overlay
        .members_of(owner)
        .records
        .into_iter()
        .filter(|symbol| symbol.name == name)
        .collect()
}

#[test]
fn scala_case_class_model_emits_copy_and_exact_parameter_accessors() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/app/Workflow.scala",
            "package app\ncase class RenderRequest(value: String, count: Int)\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    activate_scala(&analyzer);

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let copy = overlay.symbols_with_id("app.RenderRequest.copy");
    assert_eq!(copy.disposition, SemanticModelOverlayDisposition::Unique);
    assert_eq!(copy.records[0].qualified_name, "app.RenderRequest.copy");
    assert_eq!(
        copy.records[0].provenance.rule_id.as_deref(),
        Some("scala.case-class.copy")
    );
    let SemanticModelLocation::Authored(copy_anchor) = &copy.records[0].location else {
        panic!("copy must navigate to the authored case class");
    };
    assert_eq!(copy_anchor.symbol, "app.RenderRequest");

    for parameter in ["value", "count"] {
        let id = format!("app.RenderRequest.{parameter}.accessor");
        let accessor = overlay.symbols_with_id(&id);
        assert_eq!(
            accessor.disposition,
            SemanticModelOverlayDisposition::Unique,
            "missing generated accessor {id}"
        );
        assert_eq!(accessor.records[0].name, parameter);
        assert_eq!(
            accessor.records[0].provenance.rule_id.as_deref(),
            Some("scala.case-class.parameter-accessor")
        );
        let SemanticModelLocation::Authored(anchor) = &accessor.records[0].location else {
            panic!("parameter accessor must use an authored anchor");
        };
        assert_eq!(anchor.symbol, format!("app.RenderRequest.{parameter}"));
        assert!(anchor.range.end_byte > anchor.range.start_byte);
    }
}

#[test]
fn scala_case_class_model_resolves_copy_named_argument_and_accessor() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/app/Workflow.scala",
            "package app\ncase class RenderRequest(value: String)\nobject Workflow {\n  val request = RenderRequest(\"old\")\n  val updated = request.copy(value = \"new\")\n  val accessed = request.value\n}\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    activate_scala(&analyzer);

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![
                DefinitionReferenceQuery {
                    path: "src/app/Workflow.scala".to_owned(),
                    line: Some(5),
                    column: Some(25),
                },
                DefinitionReferenceQuery {
                    path: "src/app/Workflow.scala".to_owned(),
                    line: Some(5),
                    column: Some(30),
                },
                DefinitionReferenceQuery {
                    path: "src/app/Workflow.scala".to_owned(),
                    line: Some(6),
                    column: Some(26),
                },
            ],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    assert_eq!(definitions.results[0].definitions[0].start_line, 2);
    assert_eq!(
        definitions.results[0].definitions[0]
            .semantic_model
            .as_ref()
            .map(|provenance| provenance.record_id.as_str()),
        Some("app.RenderRequest.copy")
    );
    assert_eq!(definitions.results[1].status, "resolved");
    assert_eq!(definitions.results[1].definitions[0].start_line, 2);
    assert_eq!(
        definitions.results[1].definitions[0]
            .semantic_model
            .as_ref()
            .map(|provenance| provenance.record_id.as_str()),
        Some("app.RenderRequest.value.accessor")
    );
    assert_eq!(definitions.results[2].status, "resolved");
    assert_eq!(definitions.results[2].definitions[0].start_line, 2);
    assert_eq!(
        definitions.results[2].definitions[0]
            .semantic_model
            .as_ref()
            .map(|provenance| provenance.record_id.as_str()),
        Some("app.RenderRequest.value.accessor"),
        "{definitions:#?}"
    );

    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec![
                "app.RenderRequest.copy".to_owned(),
                "app.RenderRequest.value.accessor".to_owned(),
            ],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(usages.results[0].status, ScanUsagesStatus::Found);
    assert!(
        usages.results[0]
            .files
            .iter()
            .any(|file| { file.hits.iter().any(|hit| hit.line == 5) })
    );
    assert_eq!(usages.results[1].status, ScanUsagesStatus::Found);
    let accessor_lines = usages.results[1]
        .files
        .iter()
        .flat_map(|file| file.hits.iter().map(|hit| hit.line))
        .collect::<Vec<_>>();
    assert!(accessor_lines.contains(&5));
    assert!(accessor_lines.contains(&6));
}

#[test]
fn scala_non_case_class_does_not_emit_case_class_members() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/app/Workflow.scala",
            "package app\nclass RenderRequest(value: String)\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    activate_scala(&analyzer);

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    assert_eq!(
        overlay
            .symbols_with_id("app.RenderRequest.copy")
            .disposition,
        SemanticModelOverlayDisposition::Empty
    );
}

#[test]
fn lombok_exact_coordinate_emits_getters_and_setters_with_field_anchors() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Person.java",
            r#"package app;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Person {
    String name;
    boolean ready;
}
"#,
        )
        .file(
            "src/app/UsePerson.java",
            r#"package app;
class UsePerson {
    void use(Person person) {
        String name = person.getName();
        boolean ready = person.isReady();
        person.setName("new");
    }
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    assert!(matches!(
        activate_lombok(&analyzer, Some("org.projectlombok:lombok"), Some("1.18.42")),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    for (field, member, rule) in [
        ("name", "getName", "java.lombok.getter"),
        ("ready", "isReady", "java.lombok.getter"),
        ("name", "setName", "java.lombok.setter"),
    ] {
        let record = modeled_member(&overlay, "app.Person", member);
        assert_eq!(record.len(), 1, "missing or conflicting {member}");
        assert_eq!(record[0].provenance.rule_id.as_deref(), Some(rule));
        let SemanticModelLocation::Authored(anchor) = &record[0].location else {
            panic!("{member} must use an authored field anchor");
        };
        assert_eq!(anchor.symbol, format!("app.Person.{field}"));
    }

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![
                DefinitionReferenceQuery {
                    path: "src/app/UsePerson.java".to_owned(),
                    line: Some(4),
                    column: Some(30),
                },
                DefinitionReferenceQuery {
                    path: "src/app/UsePerson.java".to_owned(),
                    line: Some(5),
                    column: Some(32),
                },
                DefinitionReferenceQuery {
                    path: "src/app/UsePerson.java".to_owned(),
                    line: Some(6),
                    column: Some(16),
                },
            ],
        },
    );
    for (result, record_id) in definitions.results.iter().zip([
        "app.Person.name.lombok-getter",
        "app.Person.ready.lombok-getter",
        "app.Person.name.lombok-setter",
    ]) {
        assert_eq!(result.status, "resolved", "{definitions:?}");
        assert_eq!(
            result.definitions[0]
                .semantic_model
                .as_ref()
                .map(|provenance| provenance.record_id.as_str()),
            Some(record_id)
        );
    }

    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["app.Person.name.lombok-getter".to_owned()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(usages.results[0].status, ScanUsagesStatus::Found);
    assert!(
        usages.results[0]
            .files
            .iter()
            .flat_map(|file| &file.hits)
            .any(|hit| hit.line == 4)
    );

    let sources = get_symbol_sources(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec![
                "app.Person.getName".to_owned(),
                "src/app/Person.java#app.Person.isReady".to_owned(),
            ],
        },
    );
    assert!(sources.not_found.is_empty(), "{sources:#?}");
    assert_eq!(sources.sources.len(), 2, "{sources:#?}");
    assert!(
        sources
            .sources
            .iter()
            .any(|source| source.text.contains("String name;"))
    );
    assert!(
        sources
            .sources
            .iter()
            .any(|source| source.text.contains("boolean ready;"))
    );
}

#[test]
fn lombok_requires_exact_package_version_and_annotation_owner() {
    for (import, package, version) in [
        ("lombok.Getter", None, None),
        ("lombok.Getter", Some("org.projectlombok:lombok"), None),
        (
            "lombok.Getter",
            Some("org.projectlombok:lombok"),
            Some("1.18.40"),
        ),
        (
            "other.Getter",
            Some("org.projectlombok:lombok"),
            Some("1.18.42"),
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "src/app/Person.java",
                &format!(
                    "package app;\nimport {import};\n@Getter class Person {{ String name; }}\n"
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let _ = activate_lombok(&analyzer, package, version);
        assert!(
            analyzer
                .analyzer()
                .semantic_model_overlay()
                .is_none_or(|overlay| modeled_member(&overlay, "app.Person", "getName").is_empty()),
            "unexpected match for {import} {package:?} {version:?}"
        );
    }
}

#[test]
fn lombok_models_only_valid_members_and_reference_shapes() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Flags.java",
            r#"package app;
import lombok.Getter;
import lombok.Setter;
@Getter @Setter class Flags {
    boolean isRunning;
    Boolean ready;
    static String global;
    final String id = "id";
}
"#,
        )
        .file(
            "src/app/UseFlags.java",
            r#"package app;
import java.util.function.Function;
class UseFlags {
    void use(Flags flags) {
        boolean running = flags.isRunning();
        Boolean ready = flags.getReady();
        flags.setReady(Boolean.TRUE);
        Function<Flags, Boolean> getter = Flags::getReady;
        flags.getReady(Boolean.TRUE);
        Object invalid = flags.getReady;
    }
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let _ = activate_lombok(&analyzer, Some("org.projectlombok:lombok"), Some("1.18.42"));
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    for member in ["isRunning", "getReady", "setReady"] {
        assert_eq!(modeled_member(&overlay, "app.Flags", member).len(), 1);
    }
    for member in ["isIsRunning", "isReady", "getGlobal", "setGlobal", "setId"] {
        assert!(modeled_member(&overlay, "app.Flags", member).is_empty());
    }

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![
                DefinitionReferenceQuery {
                    path: "src/app/UseFlags.java".to_owned(),
                    line: Some(9),
                    column: Some(16),
                },
                DefinitionReferenceQuery {
                    path: "src/app/UseFlags.java".to_owned(),
                    line: Some(10),
                    column: Some(32),
                },
                DefinitionReferenceQuery {
                    path: "src/app/UseFlags.java".to_owned(),
                    line: Some(8),
                    column: Some(50),
                },
            ],
        },
    );
    assert_eq!(
        definitions.results[0].status, "no_definition",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[1].status, "no_definition",
        "{definitions:#?}"
    );
    assert_eq!(
        definitions.results[2].status, "resolved",
        "{definitions:#?}"
    );

    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec![
                "app.Flags.ready.lombok-getter".to_owned(),
                "app.Flags.ready".to_owned(),
            ],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    let getter_lines = usages.results[0]
        .files
        .iter()
        .flat_map(|file| file.hits.iter().map(|hit| hit.line))
        .collect::<Vec<_>>();
    assert!(getter_lines.contains(&6));
    assert!(getter_lines.contains(&8), "{usages:#?}");
    let field_lines = usages.results[1]
        .files
        .iter()
        .flat_map(|file| file.hits.iter().map(|hit| hit.line))
        .collect::<Vec<_>>();
    assert!(field_lines.contains(&6), "{usages:#?}");
    assert!(field_lines.contains(&7), "{usages:#?}");
}

#[test]
fn lombok_rejects_ambiguous_short_annotation_imports() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Person.java",
            "package app; import lombok.Getter; import other.Getter; @Getter class Person { String name; }\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let _ = activate_lombok(&analyzer, Some("org.projectlombok:lombok"), Some("1.18.42"));
    assert!(
        analyzer
            .analyzer()
            .semantic_model_overlay()
            .is_none_or(|overlay| modeled_member(&overlay, "app.Person", "getName").is_empty())
    );
}

#[test]
fn lombok_supports_field_data_and_value_annotations() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Models.java",
            r#"package app;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.Value;

class FieldModel {
    @Getter String code;
    @Setter String note;
}

@Data class DataModel { String data; }
@Value class ValueModel { String value; }
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let _ = activate_lombok(&analyzer, Some("org.projectlombok:lombok"), Some("1.18.42"));
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    for (owner, member, rule) in [
        ("app.FieldModel", "getCode", "java.lombok.getter"),
        ("app.FieldModel", "setNote", "java.lombok.setter"),
        ("app.DataModel", "getData", "java.lombok.data-getter"),
        ("app.ValueModel", "getValue", "java.lombok.value-getter"),
    ] {
        let records = modeled_member(&overlay, owner, member);
        assert_eq!(records.len(), 1, "missing {owner}.{member}");
        assert_eq!(records[0].provenance.rule_id.as_deref(), Some(rule));
    }
}

#[test]
fn lombok_pack_is_inactive_when_the_catalog_does_not_contain_it() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Person.java",
            "package app; import lombok.Getter; @Getter class Person { String name; }\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let outcome = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: Some(CatalogCoordinate {
                    name: "org.projectlombok:lombok".to_owned(),
                    version: Some(Version::parse("1.18.42").unwrap()),
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }));
    assert!(
        analyzer
            .analyzer()
            .semantic_model_overlay()
            .is_none_or(|overlay| overlay.symbols().is_empty())
    );
}

#[test]
fn authored_java_method_precedes_lombok_model() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Person.java",
            r#"package app;
import lombok.Getter;
@Getter class Person {
    String name;
    public String getName() { return name; }
}
"#,
        )
        .file(
            "src/app/UsePerson.java",
            "package app;\nclass UsePerson {\n    String use(Person person) {\n        return person.getName();\n    }\n}\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let _ = activate_lombok(&analyzer, Some("org.projectlombok:lombok"), Some("1.18.42"));
    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: "src/app/UsePerson.java".to_owned(),
                line: Some(4),
                column: Some(23),
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    assert!(
        definitions.results[0].definitions[0]
            .semantic_model
            .is_none(),
        "{definitions:#?}"
    );
    assert_eq!(definitions.results[0].definitions[0].start_line, 5);
}
