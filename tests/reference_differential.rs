mod common;

use brokk_bifrost::reference_differential::{
    ReferenceClassification, ReferenceDifferentialConfig, run_reference_differential,
};
use brokk_bifrost::{AnalyzerConfig, Language};
use common::InlineTestProject;

#[test]
fn typescript_export_alias_is_excluded_as_a_declaration_site() {
    let source = r#"const createListItem = () => {};
const createListItemWithValidation = () => {};
export { createListItemWithValidation as createListItem };
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("index.ts", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report = run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "ts".to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 100,
            ..ReferenceDifferentialConfig::default()
        },
    )
    .expect("run one-file TypeScript reference differential");

    let export_line = "export { createListItemWithValidation as createListItem };";
    let export_start = source.find(export_line).expect("export statement");
    let value_start = export_start
        + export_line
            .find("createListItemWithValidation")
            .expect("export value");
    let alias_start =
        export_start + export_line.find("as createListItem").expect("export alias") + "as ".len();

    assert!(
        report
            .sites
            .iter()
            .all(|site| site.start_byte != alias_start),
        "the exported alias is a declaration name, not a reference site: {report:#?}"
    );
    let export_value = report
        .sites
        .iter()
        .find(|site| site.start_byte == value_start)
        .expect("export value remains a sampled reference site");
    assert_eq!(export_value.forward_status, "resolved", "{export_value:#?}");
    assert_eq!(
        export_value.classification,
        ReferenceClassification::EditorOnly,
        "export bindings remain visible to editor navigation: {export_value:#?}"
    );
    assert_eq!(report.summary.classifications.missing, 0, "{report:#?}");
}
