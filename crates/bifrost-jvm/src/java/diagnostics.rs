//! Java's semantic diagnostics: every written type name a Java file spells,
//! classified as resolved, ambiguous, externally indexed, or unrecognized.
//!
//! The declaration index is a parameter rather than a lookup on the source,
//! because a mixed JVM workspace answers this question from the realm-wide
//! merged index (`MultiAnalyzer`) while a lone Java workspace answers it from
//! the analyzer's own. The active dependency model is a parameter for the same
//! reason: both are properties of the *dispatching* analyzer, not of the Java
//! one.
//!
//! The ladder and its one error-producing exit are [`crate::proof`]'s; this
//! module supplies only what is specific to Java, which is the tier order two
//! of its rungs walk. A name the workspace realm does not spell is looked for
//! in the retained jar index as Java's own resolver spells it, and then in the
//! active dependency model through
//! [`java_type_name_candidate_fqns`] -- the explicit-import, wildcard-import,
//! same-package, default-package and `java.lang` tiers, in that order. Checking
//! the model by simple name instead would let an unrelated dependency type
//! silence a real error.

use brokk_bifrost_core::analyzer::model::{
    SemanticDiagnostic, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::node_range;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, ProjectFile};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser};

use crate::java::graph_support::{
    JavaSource, java_package_name_of, java_type_name_candidate_fqns,
    resolve_java_type_name_candidates_in_realm,
};
use crate::proof::{
    JvmActiveSemanticModel, JvmNameProof, model_disposition_over_tiers, prove_against_active_model,
    record_jvm_name_proof,
};

pub const JAVA_UNRECOGNIZED_SYMBOL: &str = "java_unrecognized_symbol";
const SOURCE: &str = "bifrost-java";
const MAX_BYTES: usize = 512 * 1024;
const MAX_DIAGNOSTICS: usize = 200;

pub fn collect_java_semantic_diagnostics(
    java: &dyn JavaSource,
    definitions: &dyn BoundedDefinitionLookup,
    model: &dyn JvmActiveSemanticModel,
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
    let package_name = java_package_name_of(java, file).unwrap_or_default();
    let retained = java.retained_external_index();
    let mut stack = vec![tree.root_node()];
    let mut count = 0;
    while let Some(node) = stack.pop() {
        if node.kind() == "type_identifier" && is_type_reference(node) {
            let name = node.utf8_text(source.as_bytes()).unwrap_or_default().trim();
            if !name.is_empty() {
                let range = node_range(node, &line_starts);
                let candidates =
                    resolve_java_type_name_candidates_in_realm(java, definitions, file, name);
                let proof = match candidates.len() {
                    1 => JvmNameProof::Workspace,
                    n if n > 1 => JvmNameProof::Ambiguous {
                        boundaries: vec![BoundaryStatus::WorkspaceLocal; n],
                    },
                    _ => {
                        let spellings = java_type_name_candidate_fqns(java, file, name);
                        let indexed = retained.is_readable()
                            && spellings.iter().any(|fqn| {
                                java.retained_external_holds_qualified_name(fqn, &package_name)
                            });
                        if indexed {
                            JvmNameProof::ExternalIndexed
                        } else {
                            prove_against_active_model(retained, model, || {
                                model_disposition_over_tiers(
                                    model,
                                    spellings.iter().map(String::as_str),
                                )
                            })
                        }
                    }
                };
                if record_jvm_name_proof(&mut report, range, proof, || {
                    (
                        SemanticDiagnosticDomain::Type {
                            name: name.to_string(),
                        },
                        SemanticDiagnostic {
                            range,
                            source: SOURCE,
                            kind: JAVA_UNRECOGNIZED_SYMBOL,
                            message: format!("Unrecognized Java type `{name}`"),
                        },
                    )
                }) {
                    count += 1;
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
