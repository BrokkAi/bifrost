use super::*;
use brokk_bifrost_analysis::analyzer::AnalyzerConfig;
use brokk_bifrost_analysis::analyzer::Language;
use brokk_bifrost_analysis::analyzer::semantic::{
    DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticLanguage, SemanticRole,
    SourceAnchor, SourcePosition, SourceSpan, WorkspaceMountId,
};

#[test]
fn absent_display_path_serializes_as_json_null() {
    let cache = TaintDisplayPathCache::default();
    assert!(serde_json::to_value(cache).unwrap().is_null());
}

fn location(start: u64, end: u64) -> PolicySourceLocation {
    use crate::finding::{PolicyByteSpan, PolicyDisplayRegion};
    PolicySourceLocation::span(
        WorkspaceRelativePath::new("src/Foo.java").unwrap(),
        PolicyByteSpan::new(start, end).unwrap(),
        PolicyDisplayRegion::new(1, start + 1, 1, end + 1).unwrap(),
    )
}

fn row(kind: TaintDisplayStepKind, start: u64, end: u64, label: &str) -> RawDisplayStep {
    RawDisplayStep {
        step: TaintDisplayStep::new(kind, location(start, end), label),
        informative: true,
    }
}

fn projected(rows: Vec<RawDisplayStep>) -> TaintDisplayPath {
    project_display_rows(
        WitnessId::try_new("test", "path").unwrap(),
        TaintDisplayStep::new(TaintDisplayStepKind::Source, location(0, 1), "source"),
        rows,
        TaintDisplayStep::new(TaintDisplayStepKind::Sink, location(90, 91), "sink"),
        false,
        true,
    )
    .path
}

#[test]
fn same_file_call_sites_keep_distinct_spans() {
    let path = projected(vec![
        row(TaintDisplayStepKind::Call, 20, 21, "relay"),
        row(TaintDisplayStepKind::Call, 30, 31, "relay"),
    ]);
    assert_eq!(path.steps().len(), 4);
}

#[test]
fn equal_spans_with_distinct_evidence_remain_visible() {
    let path = projected(vec![
        row(TaintDisplayStepKind::Propagation, 20, 30, "first"),
        row(TaintDisplayStepKind::Propagation, 20, 30, "second"),
    ]);
    assert_eq!(path.steps().len(), 4);
}

#[test]
fn shared_start_nested_noise_is_removed() {
    let path = projected(vec![
        row(TaintDisplayStepKind::Propagation, 20, 40, "outer"),
        row(TaintDisplayStepKind::Propagation, 20, 30, "inner"),
    ]);
    assert_eq!(path.steps().len(), 3);
}

fn source_locator(root: &std::path::Path, path: &str) -> SemanticLocator {
    let start = SourcePosition::new(0, 0, 0);
    let end = SourcePosition::new(4, 0, 4);
    let anchor = SourceAnchor::new(SourceSpan::new(start, end).unwrap(), 0);
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(DeclarationSegmentKind::File, path, anchor, 0).unwrap(),
    ])
    .unwrap();
    SemanticLocator::new(
        WorkspaceMountId::from_root(root),
        WorkspaceRelativePath::new(path).unwrap(),
        SemanticLanguage::Standard(Language::Java),
        declaration,
        SemanticRole::CallSite,
        anchor,
    )
}

#[test]
fn unavailable_source_uses_the_canonical_display_label() {
    let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Foo.java", "call();\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let missing = source_locator(project.root(), "Absent.java");
    let projected = project_display_rows(
        WitnessId::try_new("test", "missing").unwrap(),
        TaintDisplayStep::new(TaintDisplayStepKind::Source, location(0, 1), "source"),
        vec![raw_step(
            &workspace,
            TaintDisplayStepKind::Propagation,
            &missing,
            "taint propagation",
            true,
        )],
        TaintDisplayStep::new(TaintDisplayStepKind::Sink, location(90, 91), "sink"),
        false,
        false,
    );
    let wire = serde_json::to_value(&projected.path).unwrap();
    assert_eq!(wire["steps"][1]["label"], "taint propagation");
}

#[test]
fn informative_raw_step_wins_display_path_selection() {
    let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Foo.java", "call();\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let present = source_locator(project.root(), "Foo.java");
    let source = TaintDisplayStep::new(TaintDisplayStepKind::Source, location(0, 1), "source");
    let sink = TaintDisplayStep::new(TaintDisplayStepKind::Sink, location(90, 91), "sink");
    let informative = project_display_rows(
        WitnessId::try_new("test", "z").unwrap(),
        source.clone(),
        vec![raw_step(
            &workspace,
            TaintDisplayStepKind::Call,
            &present,
            "call boundary",
            true,
        )],
        sink.clone(),
        false,
        true,
    );
    let noise = project_display_rows(
        WitnessId::try_new("test", "a").unwrap(),
        source,
        Vec::new(),
        sink,
        false,
        true,
    );
    let selected = select_taint_display_path(vec![noise, informative], 0).unwrap();
    let wire = serde_json::to_value(selected).unwrap();
    assert_eq!(wire["steps"][1]["label"], "call");
}
