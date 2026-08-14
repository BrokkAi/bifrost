//! Scala's semantic diagnostics: proof-gated unrecognized-symbol reporting
//! (#1619).
//!
//! The pass reports a name only when every retained surface was able to miss
//! it. What used to be silence is now a typed outcome: a wildcard or aliased
//! import this analyzer cannot follow records `UnsupportedSemantics` naming the
//! import, and an unreadable or unbuilt classpath records
//! `MissingDependencyDiscovery` naming the boundary. Both still suppress the
//! error; neither is silent about why.
//!
//! There is no `analyzer/scala/diagnostics.rs`: the analyzer calls this
//! directly and returns the report unchanged.
//!
//! Only type and term *names* are diagnosed. See [`crate::proof`] on why no JVM
//! language can claim a `MemberSurface` domain today.

use crate::proof::{JvmActiveSemanticModel, JvmNameProof, record_jvm_name_proof};
use crate::scala::graph_support::ScalaSource;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::{
    SemanticDiagnostic, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub const SCALA_UNRECOGNIZED_SYMBOL: &str = "scala_unrecognized_symbol";
pub const SCALA_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-scala";
const MAX_SCALA_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_SCALA_SEMANTIC_DIAGNOSTICS: usize = 200;

pub fn collect_scala_semantic_diagnostics(
    scala: &dyn ScalaSource,
    file: &ProjectFile,
    source: &str,
    model: &dyn JvmActiveSemanticModel,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_SCALA_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some(tree) = parse_scala_tree(source) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Scala source did not parse".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // A file the parser could not read has no reliable reference sites, so
        // no name in it can be proved absent. The LSP still publishes the parse
        // errors themselves through its own path.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("Scala source has {} parse errors", parse_errors.len()),
            }],
        );
        return report;
    }

    let line_starts = compute_line_starts(source);
    let declared_type_names = collect_declared_type_names(tree.root_node(), source);
    let declared_value_names = collect_declared_value_names(tree.root_node(), source);
    let mut collector = ScalaDiagnosticCollector {
        scala,
        model,
        file,
        source,
        line_starts: &line_starts,
        declared_type_names,
        declared_value_names,
        report,
        errors: 0,
    };
    collector.scan_tree(tree.root_node());
    collector.report
}

fn parse_scala_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::scala::language::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

struct ScalaDiagnosticCollector<'a> {
    scala: &'a dyn ScalaSource,
    model: &'a dyn JvmActiveSemanticModel,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    declared_type_names: HashSet<String>,
    declared_value_names: HashSet<String>,
    report: SemanticDiagnosticReport,
    errors: usize,
}

impl ScalaDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.errors >= MAX_SCALA_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                break;
            }
            if node.kind() == "type_identifier" && is_bare_type_reference(node) {
                self.check_type_identifier(node);
            }
            if node.kind() == "identifier" && is_bare_value_reference(node) {
                self.check_value_identifier(node);
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.into_iter().rev());
        }
    }

    fn check_type_identifier(&mut self, node: Node<'_>) {
        let name = node_text(node, self.source).trim();
        if name.is_empty() {
            return;
        }
        // A type parameter or a `type` member written in this very file binds
        // the spelling lexically, and no wider surface can overturn that.
        let proof = if self.declared_type_names.contains(name) {
            JvmNameProof::Workspace
        } else {
            self.scala.simple_type_proof(self.file, name, self.model)
        };
        let range = node_range(node, self.line_starts);
        if record_jvm_name_proof(&mut self.report, range, proof, || {
            (
                SemanticDiagnosticDomain::Type {
                    name: name.to_string(),
                },
                SemanticDiagnostic {
                    range,
                    source: SCALA_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind: SCALA_UNRECOGNIZED_SYMBOL,
                    message: format!("Unrecognized Scala type `{name}`"),
                },
            )
        }) {
            self.errors += 1;
        }
    }

    fn check_value_identifier(&mut self, node: Node<'_>) {
        let name = node_text(node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let proof = if self.declared_value_names.contains(name) || scala_default_term_name(name) {
            JvmNameProof::Workspace
        } else {
            self.scala.simple_term_proof(self.file, name, self.model)
        };
        let range = node_range(node, self.line_starts);
        if record_jvm_name_proof(&mut self.report, range, proof, || {
            (
                // A bare term is looked for from the position it is written at:
                // this file's declarations, then what its package and imports
                // make visible there. That is the lexical scope, not a named
                // type or member surface.
                SemanticDiagnosticDomain::LexicalScope {
                    file: self.file.rel_path().to_path_buf(),
                    range,
                },
                SemanticDiagnostic {
                    range,
                    source: SCALA_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind: SCALA_UNRECOGNIZED_SYMBOL,
                    message: format!("Unrecognized Scala symbol `{name}`"),
                },
            )
        }) {
            self.errors += 1;
        }
    }
}

fn is_bare_type_reference(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "import_declaration" | "package_clause" | "type_parameters" => return false,
            "stable_type_identifier"
            | "projected_type"
            | "singleton_type"
            | "match_type"
            | "type_lambda" => return false,
            _ => current = parent,
        }
    }
    true
}

fn is_bare_value_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "block" {
        return false;
    }
    !matches!(
        node.kind(),
        "this" | "super" | "true" | "false" | "null" | "wildcard"
    )
}

fn collect_declared_type_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "type_parameters" | "type_definition") {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "type_identifier") {
                    let name = node_text(child, source).trim();
                    if !name.is_empty() {
                        names.insert(name.to_string());
                    }
                }
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    names
}

fn collect_declared_value_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "function_definition"
                | "function_declaration"
                | "val_definition"
                | "var_definition"
                | "val_declaration"
                | "var_declaration"
                | "parameter"
        ) {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "identifier" {
                    let name = node_text(child, source).trim();
                    if !name.is_empty() {
                        names.insert(name.to_string());
                    }
                    break;
                }
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    names
}

fn scala_default_term_name(name: &str) -> bool {
    matches!(
        name,
        "println"
            | "print"
            | "printf"
            | "require"
            | "assert"
            | "assume"
            | "identity"
            | "summon"
            | "implicitly"
            | "???"
    )
}
