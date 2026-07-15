//! Analyzer-owned bounded receiver queries for structural traversal.

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::js_ts::parse_js_ts_tree;
use crate::analyzer::usages::js_ts_graph::receiver_analysis::{
    node_range, smallest_named_node_covering,
};
use crate::analyzer::usages::js_ts_graph::{JsTsReceiverFactProvider, compute_jsts_import_binder};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverAnalysisReport, ReceiverAnalysisWork,
    ReceiverValue,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverQueryOperation {
    ReceiverTargets,
    PointsTo,
    MemberTargets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverQueryInput {
    Expression,
    ContainingSite,
}

impl ReceiverQueryOperation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReceiverTargets => "receiver_targets",
            Self::PointsTo => "points_to",
            Self::MemberTargets => "member_targets",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverQuerySite {
    pub(crate) file: ProjectFile,
    pub(crate) language: Language,
    pub(crate) range: Range,
    pub(crate) text: String,
    pub(crate) syntax_kind: String,
    pub(crate) member_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverQueryAnalysis {
    Values(ReceiverAnalysisOutcome<ReceiverValue>),
    MemberTargets(ReceiverAnalysisOutcome<CodeUnit>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverQueryReport {
    pub(crate) operation: ReceiverQueryOperation,
    pub(crate) site: ReceiverQuerySite,
    pub(crate) analysis: ReceiverQueryAnalysis,
    pub(crate) work: ReceiverAnalysisWork,
    pub(crate) candidates_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverQueryError {
    Cancelled,
}

pub(crate) struct ReceiverQueryService<'a> {
    analyzer: &'a dyn IAnalyzer,
}

impl<'a> ReceiverQueryService<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self { analyzer }
    }

    pub(crate) fn analyze(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        check_cancelled(cancellation)?;
        let language = language_for_file(file);
        let indexed_source = self.analyzer.indexed_source(file);
        if !matches!(language, Language::JavaScript | Language::TypeScript) {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_analysis_language_unsupported",
                indexed_source.as_deref(),
            ));
        }
        let Some(source) = indexed_source else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "indexed_source_unavailable",
                None,
            ));
        };
        let Some(tree) = parse_js_ts_tree(file, &source, language) else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_source_parse_failed",
                Some(&source),
            ));
        };
        let Some(input_node) =
            smallest_named_node_covering(tree.root_node(), range.start_byte, range.end_byte)
        else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_input_range_unavailable",
                Some(&source),
            ));
        };
        let provider = JsTsReceiverFactProvider::new(
            self.analyzer,
            self.analyzer.global_usage_definition_index(),
            language,
            file,
            &source,
            tree.root_node(),
            compute_jsts_import_binder(&source, &tree),
        );

        let report = match operation {
            ReceiverQueryOperation::PointsTo => {
                let analysis = provider.resolve_receiver_node_report(input_node, budget);
                values_report(operation, file, language, input_node, &source, analysis)
            }
            ReceiverQueryOperation::ReceiverTargets => {
                let receiver = match input {
                    ReceiverQueryInput::Expression => input_node,
                    ReceiverQueryInput::ContainingSite => {
                        let Some(receiver) = receiver_node_at_site(input_node) else {
                            return Ok(unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_site_without_receiver",
                                Some(&source),
                            ));
                        };
                        receiver
                    }
                };
                let analysis = provider.resolve_receiver_node_report(receiver, budget);
                values_report(operation, file, language, receiver, &source, analysis)
            }
            ReceiverQueryOperation::MemberTargets => {
                let Some(member_report) = provider.resolve_member_targets_at_site(
                    input_node,
                    None,
                    input_node.start_byte(),
                    budget,
                ) else {
                    return Ok(unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(&source),
                    ));
                };
                let site = site(
                    file,
                    language,
                    member_report.receiver_range,
                    &source,
                    "receiver",
                    Some(member_report.member_name),
                );
                ReceiverQueryReport {
                    operation,
                    site,
                    analysis: ReceiverQueryAnalysis::MemberTargets(member_report.analysis.outcome),
                    work: member_report.analysis.work,
                    candidates_truncated: member_report.analysis.candidates_truncated,
                }
            }
        };
        check_cancelled(cancellation)?;
        Ok(report)
    }
}

fn values_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    node: Node<'_>,
    source: &str,
    analysis: ReceiverAnalysisReport<ReceiverValue>,
) -> ReceiverQueryReport {
    ReceiverQueryReport {
        operation,
        site: site(file, language, node_range(node), source, node.kind(), None),
        analysis: ReceiverQueryAnalysis::Values(analysis.outcome),
        work: analysis.work,
        candidates_truncated: analysis.candidates_truncated,
    }
}

fn unsupported_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    range: Range,
    reason: &'static str,
    source: Option<&str>,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported { reason })
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported { reason })
        }
    };
    ReceiverQueryReport {
        operation,
        site: ReceiverQuerySite {
            file: file.clone(),
            language,
            range,
            text: source
                .and_then(|source| source.get(range.start_byte..range.end_byte))
                .unwrap_or_default()
                .to_string(),
            syntax_kind: "unsupported".to_string(),
            member_name: None,
        },
        analysis,
        work: ReceiverAnalysisWork::default(),
        candidates_truncated: false,
    }
}

fn site(
    file: &ProjectFile,
    language: Language,
    range: Range,
    source: &str,
    syntax_kind: &str,
    member_name: Option<String>,
) -> ReceiverQuerySite {
    ReceiverQuerySite {
        file: file.clone(),
        language,
        range,
        text: source
            .get(range.start_byte..range.end_byte)
            .unwrap_or_default()
            .to_string(),
        syntax_kind: syntax_kind.to_string(),
        member_name,
    }
}

fn receiver_node_at_site(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..5 {
        match node.kind() {
            "member_expression" => return node.child_by_field_name("object"),
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                return (function.kind() == "member_expression")
                    .then(|| function.child_by_field_name("object"))
                    .flatten();
            }
            _ => {}
        }
        let Some(parent) = node.parent() else {
            break;
        };
        node = parent;
    }
    None
}

fn check_cancelled(cancellation: Option<&CancellationToken>) -> Result<(), ReceiverQueryError> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(ReceiverQueryError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{TestProject, TypescriptAnalyzer};
    use std::path::PathBuf;

    fn test_project(source: &str) -> (tempfile::TempDir, ProjectFile, TypescriptAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("src/app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        (temp, file, analyzer)
    }

    fn marker_range(source: &str, marker: &str) -> Range {
        let start_byte = source.find(marker).expect("marker");
        range_at(source, marker, start_byte)
    }

    fn last_marker_range(source: &str, marker: &str) -> Range {
        let start_byte = source.rfind(marker).expect("marker");
        range_at(source, marker, start_byte)
    }

    fn range_at(source: &str, marker: &str, start_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte: start_byte + marker.len(),
            start_line: source[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            end_line: source[..start_byte + marker.len()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        }
    }

    #[test]
    fn points_to_reports_factory_and_allocation_provenance_with_work() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                last_marker_range(source, "makeService()"),
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("receiver query");

        assert_eq!(report.operation.as_str(), "points_to");
        assert_eq!(report.site.text, "makeService()");
        assert!(report.work.scope_nodes > 0);
        assert!(!report.candidates_truncated);
        assert!(
            matches!(
                &report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
                    if matches!(
                        values.as_slice(),
                        [ReceiverValue::FactoryReturn { factory, value }]
                            if factory.fq_name().ends_with("makeService")
                                && matches!(value.as_ref(), ReceiverValue::AllocationSite { ty, .. } if ty.fq_name().ends_with("Service"))
                    )
            ),
            "unexpected analysis: {:?}",
            report.analysis
        );
    }

    #[test]
    fn member_targets_only_returns_the_receiver_owner_member() {
        let source = r#"
class Service { run() {} }
class Other { run() {} }
export function caller() {
  const service = new Service();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                marker_range(source, "service.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("member target query");

        assert_eq!(report.site.member_name.as_deref(), Some("run"));
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                if targets.len() == 1
                    && targets[0].fq_name().contains("Service")
                    && !targets[0].fq_name().contains("Other")
        ));
    }

    #[test]
    fn unsupported_language_returns_an_explicit_row() {
        let source = "value = object.member\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.py"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                marker_range(source, "object.member"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("unsupported result");

        assert_eq!(report.site.language, Language::Python);
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_analysis_language_unsupported"
            })
        ));
    }

    #[test]
    fn tiny_budget_and_cancellation_are_deterministic() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let service = ReceiverQueryService::new(&analyzer);
        let range = marker_range(source, "service.run");

        let report = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::tiny(),
                None,
            )
            .expect("tiny-budget result");
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));
        assert!(report.work.scope_nodes > ReceiverAnalysisBudget::tiny().max_scope_nodes);

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service.analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            Err(ReceiverQueryError::Cancelled)
        );
    }
}
