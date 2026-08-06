//! C++'s semantic diagnostics: conservative unrecognized-type reporting.
//!
//! The pass only fires where it can prove what a translation unit sees: a
//! `compile_commands.json` entry with no forced or system includes, an
//! `#include` closure of quoted project headers that all parse cleanly, and no
//! preprocessor conditionals or macro definitions anywhere in that closure. Any
//! of those gives up and reports nothing, because the alternative is to
//! second-guess a preprocessor this analyzer does not run.
//!
//! `analyzer/cpp/diagnostics.rs` in `brokk-bifrost-analysis` keeps only the
//! fixtures that build a real `CppAnalyzer`; the `SemanticDiagnosticReport`
//! wrapper `IAnalyzer::semantic_diagnostics` returns stays on the analyzer.

use crate::compile_context::CppCompileContext;
use crate::graph_support::CppSource;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::SemanticDiagnostic;
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub const CPP_UNRECOGNIZED_SYMBOL: &str = "cpp_unrecognized_symbol";
pub const CPP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-cpp";
const MAX_CPP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_CPP_SEMANTIC_DIAGNOSTICS: usize = 200;

pub fn collect_cpp_semantic_diagnostics(
    analyzer: &dyn CppSource,
    file: &ProjectFile,
    source: &str,
) -> Vec<SemanticDiagnostic> {
    if source.len() > MAX_CPP_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(context) = analyzer.compile_context_for(file) else {
        return Vec::new();
    };
    let Some(tree) = parse_cpp_tree(source) else {
        return Vec::new();
    };
    let Some(known_type_names) = proven_project_type_names(file, source, context) else {
        return Vec::new();
    };

    let line_starts = compute_line_starts(source);
    let mut diagnostics = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if diagnostics.len() >= MAX_CPP_SEMANTIC_DIAGNOSTICS {
            break;
        }
        if node.kind() == "type_identifier" && is_plain_type_reference(node) {
            let name = node_text(node, source);
            if !name.is_empty()
                && !context.defined_macros.contains(name)
                && !known_type_names.contains(name)
            {
                diagnostics.push(SemanticDiagnostic {
                    range: node_range(node, &line_starts),
                    source: CPP_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind: CPP_UNRECOGNIZED_SYMBOL,
                    message: format!("Unrecognized C++ type `{name}`"),
                });
            }
        }
        push_named_children(&mut stack, node);
    }
    diagnostics
}

fn parse_cpp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn has_parse_errors(root: Node<'_>) -> bool {
    let mut errors = Vec::new();
    collect_parse_errors(root, &mut errors);
    !errors.is_empty()
}

fn proven_project_type_names(
    source_file: &ProjectFile,
    source: &str,
    context: &CppCompileContext,
) -> Option<HashSet<String>> {
    if !context.forced_includes.is_empty() || !context.system_include_roots.is_empty() {
        return None;
    }

    let mut visited = HashSet::default();
    let mut known_type_names = HashSet::default();
    let mut pending = vec![(source_file.clone(), source.to_string())];
    while let Some((file, source)) = pending.pop() {
        if !visited.insert(file.abs_path()) {
            continue;
        }
        let tree = parse_cpp_tree(&source)?;
        if has_parse_errors(tree.root_node()) {
            return None;
        }
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "preproc_include" => {
                    let include = quoted_include_path(node, &source)?;
                    let header = resolve_project_header(&file, &include, context)?;
                    let Ok(header_source) = header.read_to_string() else {
                        return None;
                    };
                    pending.push((header, header_source));
                }
                "preproc_def"
                | "preproc_function_def"
                | "preproc_if"
                | "preproc_ifdef"
                | "preproc_ifndef"
                | "preproc_elif"
                | "preproc_else"
                | "preproc_call" => return None,
                "class_specifier" | "struct_specifier" | "enum_specifier" => {
                    if let Some(name) = declared_type_name(node, &source) {
                        known_type_names.insert(name);
                    }
                    push_named_children(&mut stack, node);
                }
                _ => push_named_children(&mut stack, node),
            }
        }
    }
    Some(known_type_names)
}

fn declared_type_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "type_identifier" | "identifier"))
    })?;
    let name = node_text(name, source).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn quoted_include_path(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let literal = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "string_literal")?;
    let text = node_text(literal, source);
    text.strip_prefix('"')?
        .strip_suffix('"')
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_project_header(
    source_file: &ProjectFile,
    include: &str,
    context: &CppCompileContext,
) -> Option<ProjectFile> {
    let mut candidates = HashSet::default();
    let source_parent = source_file.abs_path().parent()?.to_path_buf();
    for root in std::iter::once(source_parent).chain(context.project_include_roots.iter().cloned())
    {
        let candidate = root.join(include);
        if candidate.is_file() && candidate.starts_with(source_file.root()) {
            candidates.insert(candidate);
        }
    }
    (candidates.len() == 1).then(|| {
        ProjectFile::new(
            source_file.root().to_path_buf(),
            candidates
                .into_iter()
                .next()
                .expect("one candidate")
                .strip_prefix(source_file.root())
                .expect("candidate inside project")
                .to_path_buf(),
        )
    })
}

fn is_plain_type_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(
        parent.kind(),
        "declaration" | "type_descriptor" | "sized_type_specifier"
    ) {
        return false;
    }
    let mut current = parent;
    while let Some(ancestor) = current.parent() {
        if matches!(
            ancestor.kind(),
            "class_specifier"
                | "struct_specifier"
                | "enum_specifier"
                | "template_declaration"
                | "template_parameter_list"
                | "template_type"
                | "qualified_identifier"
                | "scoped_type_identifier"
        ) {
            return false;
        }
        current = ancestor;
    }
    true
}

fn push_named_children<'tree>(stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    stack.extend(children.into_iter().rev());
}
