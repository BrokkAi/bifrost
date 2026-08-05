use crate::analyzer::semantic_diagnostics::{node_range, node_text};
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::usages::ruby_graph::{
    RubySemanticIndex, is_declaration_constant, ruby_type_owner,
};
use crate::analyzer::{
    IAnalyzer, ProjectFile, Range, RubyAnalyzer, SemanticDiagnostic, resolve_analyzer,
};
use crate::text_utils::compute_line_starts;
use std::borrow::Cow;
use tree_sitter::Node;

pub(crate) const RUBY_UNRECOGNIZED_SYMBOL: &str = "ruby_unrecognized_symbol";
pub(crate) const RUBY_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-ruby";
const MAX_RUBY_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_RUBY_SEMANTIC_DIAGNOSTICS: usize = 200;
const MAX_RUBY_DIAGNOSTIC_VISIBLE_FILES: usize = 64;
const MAX_RUBY_DIAGNOSTIC_VISIBLE_SOURCE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubySemanticDiagnostic {
    pub(crate) range: Range,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

impl From<RubySemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: RubySemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: RUBY_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

/// Collect high-confidence Ruby unresolved-constant diagnostics.
///
/// The pass deliberately does not diagnose methods or members. Ruby can add
/// those dynamically through `method_missing`, runtime patching, gems, and
/// framework conventions. It only reports a terminal constant when a clean,
/// convention-free file names a known project-local namespace and the existing
/// structured resolver proves that the terminal is not indexed or visible.
pub(crate) fn collect_ruby_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<RubySemanticDiagnostic> {
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return Vec::new();
    };
    if source.len() > MAX_RUBY_SEMANTIC_DIAGNOSTIC_BYTES
        || ruby.zeitwerk_visible_files_for(file).is_some()
        || ruby.has_unresolved_load_directive(file)
    {
        return Vec::new();
    }
    let Some(tree) = super::parse_ruby_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() || file_has_open_runtime_boundary(tree.root_node(), source) {
        return Vec::new();
    }

    let line_starts = compute_line_starts(source);
    let semantic = RubySemanticIndex::build_for_lookup(analyzer, ruby);
    let Some(visible_files) =
        semantic.visible_files_from_bounded(file, MAX_RUBY_DIAGNOSTIC_VISIBLE_FILES)
    else {
        return Vec::new();
    };
    if visible_files_have_open_runtime_boundary(ruby, analyzer, file, source, &visible_files) {
        return Vec::new();
    }
    let mut collector = RubyDiagnosticCollector {
        semantic,
        ruby,
        file,
        source,
        line_starts: &line_starts,
        visible_files,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(tree.root_node());
    collector.diagnostics
}

struct RubyDiagnosticCollector<'a> {
    semantic: RubySemanticIndex<'a>,
    ruby: &'a RubyAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    visible_files: crate::hash::HashSet<ProjectFile>,
    diagnostics: Vec<RubySemanticDiagnostic>,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitNamespace(usize),
}

impl RubyDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut lexical_stack = Vec::new();
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostics.len() >= MAX_RUBY_SEMANTIC_DIAGNOSTICS {
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut lexical_stack, &mut stack),
                ScanFrame::ExitNamespace(len) => lexical_stack.truncate(len),
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        lexical_stack: &mut Vec<String>,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
        match node.kind() {
            "class" | "module" => {
                let Some(owner) = ruby_type_owner(
                    &self.semantic,
                    self.file,
                    &self.visible_files,
                    lexical_stack,
                    node,
                    self.source,
                ) else {
                    return;
                };
                let previous_len = lexical_stack.len();
                lexical_stack.push(owner);
                stack.push(ScanFrame::ExitNamespace(previous_len));
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push(ScanFrame::Node(body));
                }
            }
            "scope_resolution" => self.check_explicit_path(node, lexical_stack),
            "constant" => {}
            "assignment" | "operator_assignment" => {
                if let Some(right) = node.child_by_field_name("right") {
                    stack.push(ScanFrame::Node(right));
                }
            }
            "string" | "comment" => {}
            _ => push_named_children(stack, node),
        }
    }

    fn check_explicit_path(&mut self, node: Node<'_>, lexical_stack: &[String]) {
        if is_declaration_constant(node) {
            return;
        }
        let Some(owner) = node.child_by_field_name("scope") else {
            return;
        };
        let Some(owner_unit) = self.semantic.resolve_project_local_constant(
            self.file,
            &self.visible_files,
            lexical_stack,
            owner,
            self.source,
        ) else {
            return;
        };
        if !owner_unit.is_module() || self.owner_has_constant_lookup_escape(&owner_unit) {
            return;
        }
        if self
            .semantic
            .resolve_project_local_constant(
                self.file,
                &self.visible_files,
                lexical_stack,
                node,
                self.source,
            )
            .is_some()
        {
            return;
        }
        let Some(terminal) = node.child_by_field_name("name") else {
            return;
        };
        self.push_unrecognized(terminal);
    }

    fn owner_has_constant_lookup_escape(&self, owner: &crate::analyzer::CodeUnit) -> bool {
        let facts = self.ruby.semantic_facts();
        let owner = owner.fq_name();
        facts
            .ancestors
            .get(&owner)
            .is_some_and(|ancestors| !ancestors.is_empty())
            || facts.mixin_included_owners.contains_key(&owner)
            || facts.mixin_prepended_owners.contains_key(&owner)
            || facts.mixin_class_owners.contains_key(&owner)
    }

    fn push_unrecognized(&mut self, node: Node<'_>) {
        let name = node_text(node, self.source);
        if name.is_empty() {
            return;
        }
        self.diagnostics.push(RubySemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind: RUBY_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized Ruby constant `{name}`"),
        });
    }
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(ScanFrame::Node(child));
    }
}

fn file_has_open_runtime_boundary(root: Node<'_>, source: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call"
            && node.child_by_field_name("method").is_some_and(|method| {
                matches!(
                    node_text(method, source),
                    "const_get"
                        | "const_set"
                        | "remove_const"
                        | "const_missing"
                        | "class_eval"
                        | "module_eval"
                        | "eval"
                )
            })
        {
            return true;
        }
        if defines_const_missing_dynamically(node, source) {
            return true;
        }
        if node.kind() == "call"
            && let Some(method) = node.child_by_field_name("method")
        {
            match node_text(method, source) {
                "autoload" => return true,
                "require" | "require_relative" | "load"
                    if brokk_bifrost_ruby::imports::parse_ruby_require_call(node, source)
                        .is_none() =>
                {
                    return true;
                }
                _ => {}
            }
        }
        if matches!(node.kind(), "method" | "singleton_method")
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "const_missing")
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn defines_const_missing_dynamically(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call" {
        return false;
    }
    let Some(method) = node.child_by_field_name("method") else {
        return false;
    };
    if !matches!(
        node_text(method, source),
        "define_method" | "define_singleton_method"
    ) {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let Some(name) = arguments.named_children(&mut cursor).next() else {
        return false;
    };
    super::ruby_symbol_name(name, source).as_deref() == Some("const_missing")
        || super::single_static_string_content_node(name)
            .is_some_and(|content| node_text(content, source) == "const_missing")
}

fn visible_files_have_open_runtime_boundary(
    ruby: &RubyAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    visible_files: &crate::hash::HashSet<ProjectFile>,
) -> bool {
    let mut remaining_bytes = MAX_RUBY_DIAGNOSTIC_VISIBLE_SOURCE_BYTES;
    for visible_file in visible_files {
        if ruby.has_unresolved_load_directive(visible_file) {
            return true;
        }
        let visible_source = if visible_file == file {
            (source.len() <= remaining_bytes).then_some(Cow::Borrowed(source))
        } else {
            analyzer
                .project()
                .read_source_limited(visible_file, remaining_bytes)
                .ok()
                .flatten()
                .map(Cow::Owned)
        };
        let Some(visible_source) = visible_source else {
            return true;
        };
        let Some(next_remaining_bytes) = remaining_bytes.checked_sub(visible_source.len()) else {
            return true;
        };
        remaining_bytes = next_remaining_bytes;
        let Some(tree) = super::parse_ruby_tree(&visible_source) else {
            return true;
        };
        let mut parse_errors = Vec::new();
        collect_parse_errors(tree.root_node(), &mut parse_errors);
        if !parse_errors.is_empty()
            || file_has_open_runtime_boundary(tree.root_node(), &visible_source)
        {
            return true;
        }
    }
    false
}
