//! Java's semantic diagnostics: every written type name a Java file spells,
//! classified as resolved, ambiguous, externally indexed, or unrecognized.
//!
//! The declaration index is a parameter rather than a lookup on the source,
//! because a mixed JVM workspace answers this question from the realm-wide
//! merged index (`MultiAnalyzer`) while a lone Java workspace answers it from
//! the analyzer's own. Whether the workspace has a semantic-model overlay is a
//! parameter for the same reason: both are properties of the *dispatching*
//! analyzer, not of the Java one.

use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::node_range;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, ProjectFile};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser};

use crate::java::graph_support::{JavaSource, resolve_java_type_name_candidates_in_realm};

pub const JAVA_UNRECOGNIZED_SYMBOL: &str = "java_unrecognized_symbol";
const SOURCE: &str = "bifrost-java";
const MAX_BYTES: usize = 512 * 1024;
const MAX_DIAGNOSTICS: usize = 200;

pub fn collect_java_semantic_diagnostics(
    java: &dyn JavaSource,
    definitions: &dyn BoundedDefinitionLookup,
    semantic_model_overlay_present: bool,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Java parser is unavailable".to_string(),
            }],
        );
        return report;
    }
    let Some(tree) = parser.parse(source, None) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Java source did not parse".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return report;
    }
    let line_starts = compute_line_starts(source);
    let mut stack = vec![tree.root_node()];
    let mut count = 0;
    while let Some(node) = stack.pop() {
        if node.kind() == "type_identifier" && is_type_reference(node) {
            let name = node.utf8_text(source.as_bytes()).unwrap_or_default().trim();
            if !name.is_empty() {
                let range = node_range(node, &line_starts);
                let candidates =
                    resolve_java_type_name_candidates_in_realm(java, definitions, file, name);
                match candidates.len() {
                    1 => report.push_resolved(range, BoundaryStatus::WorkspaceLocal),
                    n if n > 1 => {
                        report.push_ambiguous(range, vec![BoundaryStatus::WorkspaceLocal; n])
                    }
                    _ => {
                        let (boundary, external) = java.external_boundary_evidence(file, name);
                        if external.is_some() {
                            report.push_resolved(range, BoundaryStatus::ExternalIndexed);
                        } else if boundary == BoundaryStatus::ExternalDeclaredUnindexed {
                            report.push_incomplete(
                                Some(range),
                                vec![SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                                    boundary,
                                }],
                            );
                        } else if semantic_model_overlay_present {
                            report.push_absent(
                                SemanticAbsenceProof {
                                    range,
                                    domain: SemanticDiagnosticDomain::Type {
                                        name: name.to_string(),
                                    },
                                    boundary: BoundaryStatus::ExternalIndexed,
                                },
                                SemanticDiagnostic {
                                    range,
                                    source: SOURCE,
                                    kind: JAVA_UNRECOGNIZED_SYMBOL,
                                    message: format!("Unrecognized Java type `{name}`"),
                                },
                            );
                            count += 1;
                        } else {
                            report.push_incomplete(
                                Some(range),
                                vec![SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                                    boundary,
                                }],
                            );
                        }
                    }
                }
            }
        }
        if count >= MAX_DIAGNOSTICS {
            report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
            break;
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    report
}

fn is_type_reference(node: Node<'_>) -> bool {
    !matches!(
        node.parent().map(|parent| parent.kind()),
        Some(
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "type_parameter"
        )
    )
}
