use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, ScanUsagesByReferenceParams, ScanUsagesStatus,
    get_definitions_by_location, scan_usages_by_reference,
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
        assert_eq!(anchor.symbol, "app.RenderRequest");
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
        Some("app.RenderRequest.value.accessor")
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
