//! Scala's semantic diagnostics: conservative unrecognized-symbol reporting.
//!
//! The pass only reports a name when the workspace can prove it is absent. A
//! wildcard or aliased import that this analyzer cannot follow answers
//! [`ScalaTypeKnownness::Uncertain`], and an uncertain name is never reported.
//!
//! `analyzer/scala/diagnostics.rs` keeps nothing: the
//! `SemanticDiagnosticReport` wrapper `IAnalyzer::semantic_diagnostics`
//! returns stays on the analyzer, which calls this directly.

use crate::scala::graph_support::{ScalaSource, ScalaTypeKnownness};
use brokk_bifrost_core::analyzer::model::SemanticDiagnostic;
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{ProjectFile, Range};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub const SCALA_UNRECOGNIZED_SYMBOL: &str = "scala_unrecognized_symbol";
pub const SCALA_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-scala";
const MAX_SCALA_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_SCALA_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalaSemanticDiagnostic {
    pub range: Range,
    pub kind: &'static str,
    pub message: String,
}

impl From<ScalaSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: ScalaSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: SCALA_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

pub fn collect_scala_semantic_diagnostics(
    scala: &dyn ScalaSource,
    file: &ProjectFile,
    source: &str,
) -> Vec<ScalaSemanticDiagnostic> {
    if source.len() > MAX_SCALA_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(tree) = parse_scala_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let line_starts = compute_line_starts(source);
    let declared_type_names = collect_declared_type_names(tree.root_node(), source);
    let declared_value_names = collect_declared_value_names(tree.root_node(), source);
    let mut collector = ScalaDiagnosticCollector {
        scala,
        file,
        source,
        line_starts: &line_starts,
        declared_type_names,
        declared_value_names,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(tree.root_node());
    collector.diagnostics
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
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    declared_type_names: HashSet<String>,
    declared_value_names: HashSet<String>,
    diagnostics: Vec<ScalaSemanticDiagnostic>,
}

impl ScalaDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.diagnostics.len() >= MAX_SCALA_SEMANTIC_DIAGNOSTICS {
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
        if name.is_empty() || self.declared_type_names.contains(name) {
            return;
        }
        if self.scala.simple_type_knownness(self.file, name) != ScalaTypeKnownness::Absent {
            return;
        }
        self.diagnostics.push(ScalaSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind: SCALA_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized Scala type `{name}`"),
        });
    }

    fn check_value_identifier(&mut self, node: Node<'_>) {
        let name = node_text(node, self.source).trim();
        if name.is_empty()
            || self.declared_value_names.contains(name)
            || scala_default_term_name(name)
            || self.scala.is_known_simple_term(self.file, name)
        {
            return;
        }
        let imports = self.scala.import_info_of(self.file);
        if imports.iter().any(|import| import.is_wildcard)
            || imports
                .iter()
                .any(|import| import.local_name() == Some(name))
        {
            return;
        }
        self.diagnostics.push(ScalaSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind: SCALA_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized Scala symbol `{name}`"),
        });
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
