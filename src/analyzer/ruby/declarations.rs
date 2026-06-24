use super::imports::parse_ruby_require_call;
use super::*;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use tree_sitter::Node;

/// Reads the source text backing a tree-sitter node.
pub(super) fn ruby_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

/// Walks a Ruby file and emits its declarations into `parsed`.
///
/// Ruby symbol identity follows the shared `CodeUnit` scheme used by every
/// bifrost analyzer: `package_name` is empty, nested namespaces/types are joined
/// in `short_name` with `$`, and a type's members are appended after a `.`. So
/// `module A; class B; def c` yields `A$B` (class) and `A$B.c` (method), which
/// `CodeUnit::identifier` resolves back to `B` and `c`.
pub(super) struct RubyVisitor<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl RubyVisitor<'_> {
    pub(super) fn visit_program(&mut self, root: Node<'_>) {
        self.visit_container(root, &[], None);
    }

    fn visit_container(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children {
            self.visit_statement(child, segments, parent);
        }
    }

    fn visit_statement(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        match node.kind() {
            "class" => self.visit_class_like(node, segments, parent, false),
            "module" => self.visit_class_like(node, segments, parent, true),
            "singleton_class" => {
                // `class << self` — its methods belong to the enclosing type.
                if let Some(body) = node.child_by_field_name("body") {
                    self.visit_container(body, segments, parent);
                }
            }
            "method" | "singleton_method" => self.visit_method(node, segments, parent),
            "assignment" => self.visit_assignment(node, segments, parent),
            "call" => self.visit_call(node, segments, parent),
            kind if is_descendable_container(kind) => {
                self.visit_container(node, segments, parent);
            }
            _ => {}
        }
    }

    fn visit_class_like(
        &mut self,
        node: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        is_module: bool,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name_segments = extract_name_segments(name_node, self.source);
        if name_segments.is_empty() {
            return;
        }

        let mut new_segments = segments.to_vec();
        new_segments.extend(name_segments);
        let short_name = new_segments.join("$");

        let kind = if is_module {
            CodeUnitType::Module
        } else {
            CodeUnitType::Class
        };
        let code_unit = CodeUnit::new(self.file.clone(), kind, String::new(), short_name);
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.parsed
            .add_signature(code_unit.clone(), first_line(node, self.source));

        let supertypes = extract_ruby_supertypes(node, self.source);
        if !supertypes.is_empty() {
            self.parsed
                .set_raw_supertypes(code_unit.clone(), supertypes);
        }

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_container(body, &new_segments, Some(&code_unit));
        }
    }

    fn visit_method(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = ruby_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let short_name = member_short_name(segments, name);
        let signature = node
            .child_by_field_name("parameters")
            .map(|params| ruby_node_text(params, self.source).trim().to_string());
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            String::new(),
            short_name,
            signature,
            false,
        );
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.parsed
            .add_signature(code_unit, first_line(node, self.source));
        // Method bodies are leaves for declaration purposes.
    }

    fn visit_assignment(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        // Only constant assignments are declarations; locals are lowercase.
        if left.kind() != "constant" {
            return;
        }
        let name = ruby_node_text(left, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            String::new(),
            member_short_name(segments, name),
        );
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.parsed.add_signature(
            code_unit,
            ruby_node_text(node, self.source).trim().to_string(),
        );
    }

    fn visit_call(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        let Some(method) = node.child_by_field_name("method") else {
            return;
        };
        let method_name = ruby_node_text(method, self.source).trim();
        match method_name {
            "require" | "require_relative" | "load" | "autoload" => {
                if let Some(info) = parse_ruby_require_call(node, self.source) {
                    self.parsed.import_statements.push(info.raw_snippet.clone());
                    self.parsed.imports.push(info);
                }
            }
            "attr_accessor" | "attr_reader" | "attr_writer" => {
                self.visit_attr_macro(node, segments, parent);
            }
            _ => {}
        }
    }

    fn visit_attr_macro(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        // `attr_accessor` and friends only declare members inside a type body.
        let Some(parent) = parent else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            let Some(name) = symbol_name(arg, self.source) else {
                continue;
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                String::new(),
                member_short_name(segments, &name),
            );
            self.parsed.replace_code_unit(
                code_unit.clone(),
                node,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed.add_signature(
                code_unit,
                ruby_node_text(node, self.source).trim().to_string(),
            );
        }
    }
}

/// Builds a member's `short_name` from its enclosing type segments and own name.
fn member_short_name(segments: &[String], name: &str) -> String {
    if segments.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", segments.join("$"), name)
    }
}

/// Extracts the namespace segments from a class/module name node. A plain
/// `(constant)` yields one segment; a `(scope_resolution)` like `A::B` yields
/// `["A", "B"]`.
fn extract_name_segments(name_node: Node<'_>, source: &str) -> Vec<String> {
    let text = ruby_node_text(name_node, source).trim();
    if text.is_empty() {
        return Vec::new();
    }
    text.split("::")
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

/// Collects a class/module's supertypes: its `< Superclass` and any
/// `include`/`prepend`/`extend ModuleName` mixins declared directly in its body.
fn extract_ruby_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut supertypes = Vec::new();

    if let Some(superclass) = node.child_by_field_name("superclass") {
        let mut cursor = superclass.walk();
        if let Some(expr) = superclass.named_children(&mut cursor).next() {
            let text = ruby_node_text(expr, source).trim();
            if !text.is_empty() {
                supertypes.push(text.to_string());
            }
        }
    }

    if let Some(body) = node.child_by_field_name("body") {
        collect_mixins(body, source, &mut supertypes);
    }

    supertypes
}

/// Walks a type body for `include`/`prepend`/`extend` calls, descending through
/// control-flow containers but not into nested types or methods.
fn collect_mixins(node: Node<'_>, source: &str, supertypes: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "call" => {
                let Some(method) = child.child_by_field_name("method") else {
                    continue;
                };
                if !matches!(
                    ruby_node_text(method, source).trim(),
                    "include" | "prepend" | "extend"
                ) {
                    continue;
                }
                let Some(arguments) = child.child_by_field_name("arguments") else {
                    continue;
                };
                let mut arg_cursor = arguments.walk();
                for arg in arguments.named_children(&mut arg_cursor) {
                    if matches!(arg.kind(), "constant" | "scope_resolution") {
                        let text = ruby_node_text(arg, source).trim();
                        if !text.is_empty() {
                            supertypes.push(text.to_string());
                        }
                    }
                }
            }
            kind if is_descendable_container(kind) => collect_mixins(child, source, supertypes),
            _ => {}
        }
    }
}

/// Extracts the bare name from a `attr_*` argument, which is usually a symbol
/// (`:name`) or string (`"name"`).
fn symbol_name(node: Node<'_>, source: &str) -> Option<String> {
    let text = ruby_node_text(node, source).trim();
    let stripped = text
        .strip_prefix(':')
        .unwrap_or(text)
        .trim_matches(['"', '\'']);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

/// First non-blank line of a node's source, used as a one-line signature.
fn first_line(node: Node<'_>, source: &str) -> String {
    ruby_node_text(node, source)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// Container node kinds the visitor recurses through to find conditionally
/// declared symbols (e.g. a `def` inside an `if`). Excludes `method`/
/// `singleton_method`, whose bodies are treated as leaves.
fn is_descendable_container(kind: &str) -> bool {
    matches!(
        kind,
        "if" | "unless"
            | "elsif"
            | "else"
            | "while"
            | "until"
            | "for"
            | "case"
            | "case_match"
            | "when"
            | "in_clause"
            | "begin"
            | "do"
            | "do_block"
            | "block"
            | "then"
            | "ensure"
            | "rescue"
            | "body_statement"
            | "parenthesized_statements"
            | "begin_block"
            | "end_block"
    )
}

pub(super) fn collect_ruby_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        if matches!(node.kind(), "identifier" | "constant") {
            let text = ruby_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        WalkControl::Continue
    });
}
