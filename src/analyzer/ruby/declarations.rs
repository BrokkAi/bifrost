use super::imports::parse_ruby_require_call;
use super::*;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{RubyMethodDispatchMode, SignatureMetadata};
use tree_sitter::{Node, Parser, Tree};

/// Parses Ruby source into a tree-sitter tree, or `None` if parsing fails.
pub(crate) fn parse_ruby_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ruby::LANGUAGE.into())
        .expect("failed to load ruby parser");
    parser.parse(source, None)
}

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

/// A pending traversal step: visit `node` as a statement within the enclosing
/// type's `segments`/`parent` context. The visitor uses an explicit stack of
/// these instead of native recursion so deeply nested input cannot overflow the
/// call stack (per AGENTS.md, and mirroring the Python visitor).
struct RubyWork<'tree> {
    node: Node<'tree>,
    segments: Vec<String>,
    parent: Option<CodeUnit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RubyFieldScope {
    Instance,
    ClassVariable,
    SingletonClass,
}

/// Pushes a node's named children as statement work items. Children are pushed
/// in reverse so the stack pops them in source order.
fn push_named_children<'tree>(
    node: Node<'tree>,
    segments: &[String],
    parent: Option<&CodeUnit>,
    stack: &mut Vec<RubyWork<'tree>>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(RubyWork {
            node: child,
            segments: segments.to_vec(),
            parent: parent.cloned(),
        });
    }
}

impl RubyVisitor<'_> {
    pub(super) fn visit_program(&mut self, root: Node<'_>) {
        let mut stack = Vec::new();
        push_named_children(root, &[], None, &mut stack);
        while let Some(work) = stack.pop() {
            self.visit_statement(work.node, &work.segments, work.parent.as_ref(), &mut stack);
        }
    }

    fn visit_statement<'tree>(
        &mut self,
        node: Node<'tree>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        stack: &mut Vec<RubyWork<'tree>>,
    ) {
        match node.kind() {
            "class" => self.visit_class_like(node, segments, parent, false, stack),
            "module" => self.visit_class_like(node, segments, parent, true, stack),
            "singleton_class" => {
                // `class << self` — its methods belong to the enclosing type.
                if let Some(body) = node.child_by_field_name("body") {
                    push_named_children(body, segments, parent, stack);
                }
            }
            "method" | "singleton_method" => self.visit_method(node, segments, parent),
            "assignment" | "operator_assignment" => {
                self.visit_assignment(node, segments, parent, None)
            }
            "call" => self.visit_call(node, segments, parent),
            kind if is_descendable_container(kind) => {
                push_named_children(node, segments, parent, stack);
            }
            _ => {}
        }
    }

    fn visit_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        is_module: bool,
        stack: &mut Vec<RubyWork<'tree>>,
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

        let mut owner_relations = extract_ruby_supertypes(node, self.source)
            .into_iter()
            .map(|target| {
                let encoded = super::mixins::encode_superclass_relation(&target);
                (target, encoded)
            })
            .collect::<Vec<_>>();
        owner_relations.extend(
            super::mixins::raw_mixin_specs_for_type(node, self.source)
                .into_iter()
                .map(|spec| {
                    let encoded = super::mixins::encode_mixin_relation(&spec);
                    (spec.raw_target, encoded)
                }),
        );
        if !owner_relations.is_empty() {
            self.parsed.set_raw_supertypes(
                code_unit.clone(),
                owner_relations
                    .iter()
                    .map(|(target, _)| target.clone())
                    .collect(),
            );
            self.parsed.set_supertype_lookup_paths(
                code_unit.clone(),
                owner_relations
                    .into_iter()
                    .map(|(_, encoded)| encoded)
                    .collect(),
            );
        }

        self.visit_scope_field_assignments(
            node,
            &new_segments,
            Some(&code_unit),
            RubyFieldScope::SingletonClass,
        );
        if let Some(body) = node.child_by_field_name("body") {
            push_named_children(body, &new_segments, Some(&code_unit), stack);
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
        self.parsed.set_ruby_method_dispatch_mode(
            code_unit.clone(),
            ruby_method_dispatch_mode(node, self.source),
        );
        self.parsed.add_signature_with_metadata(
            code_unit,
            ruby_signature_metadata(first_line(node, self.source), node, self.source),
        );
        // Method bodies are otherwise leaves for declaration purposes, but Ruby
        // instance/class variables are declarations even when first assigned in
        // methods.
        self.visit_scope_field_assignments(node, segments, parent, ruby_method_field_scope(node));
    }

    fn visit_assignment(
        &mut self,
        node: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        field_scope: Option<RubyFieldScope>,
    ) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if let Some(field_scope) = ruby_field_scope_for_assignment_left(left, segments, field_scope)
        {
            self.visit_variable_field_assignment(node, left, segments, parent, field_scope);
            return;
        }
        // Only constant assignments are declarations; locals are lowercase.
        if !matches!(left.kind(), "constant" | "scope_resolution") {
            return;
        }
        let name_path = extract_name_path(left, self.source);
        if name_path.segments.is_empty() {
            return;
        }
        let short_name = assignment_constant_short_name(segments, &name_path);
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            String::new(),
            short_name,
        );
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.parsed.add_signature(
            code_unit,
            ruby_node_text(node, self.source).trim().to_string(),
        );
    }

    fn visit_scope_field_assignments(
        &mut self,
        node: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        field_scope: RubyFieldScope,
    ) {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current != node
                && matches!(
                    current.kind(),
                    "class" | "module" | "method" | "singleton_method" | "singleton_class"
                )
            {
                continue;
            }
            if matches!(current.kind(), "assignment" | "operator_assignment") {
                self.visit_assignment(current, segments, parent, Some(field_scope));
                continue;
            }
            for index in (0..current.named_child_count()).rev() {
                if let Some(child) = current.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }

    fn visit_variable_field_assignment(
        &mut self,
        node: Node<'_>,
        left: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        field_scope: RubyFieldScope,
    ) {
        let Some(short_name) = ruby_field_short_name(segments, left, self.source, field_scope)
        else {
            return;
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            String::new(),
            short_name,
        );
        if self
            .parsed
            .first_range_start(&code_unit)
            .is_some_and(|start| start <= node.start_byte())
        {
            return;
        }
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
                self.visit_attr_macro(node, method_name, segments, parent);
            }
            "alias_method" => {
                self.visit_alias_method(node, segments, parent);
            }
            _ => {}
        }
    }

    fn visit_attr_macro(
        &mut self,
        node: Node<'_>,
        method_name: &str,
        segments: &[String],
        parent: Option<&CodeUnit>,
    ) {
        // `attr_accessor` and friends only declare members inside a type body.
        let Some(parent) = parent else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            let Some(name) = literal_symbol_or_string_name(arg, self.source) else {
                continue;
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                String::new(),
                member_short_name(segments, &attr_field_member_name(node, &name)),
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
            if matches!(method_name, "attr_accessor" | "attr_reader") {
                self.add_member_function(node, arg, segments, parent, &name);
            }
            if matches!(method_name, "attr_accessor" | "attr_writer") {
                self.add_member_function(node, arg, segments, parent, &format!("{name}="));
            }
        }
    }

    fn visit_alias_method(
        &mut self,
        node: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
    ) {
        let Some(parent) = parent else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let Some(alias_arg) = arguments.named_children(&mut cursor).next() else {
            return;
        };
        let Some(alias_name) = literal_symbol_or_string_name(alias_arg, self.source) else {
            return;
        };
        self.add_member_function(node, alias_arg, segments, parent, &alias_name);
    }

    fn add_member_function(
        &mut self,
        signature_node: Node<'_>,
        range_node: Node<'_>,
        segments: &[String],
        parent: &CodeUnit,
        name: &str,
    ) {
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Function,
            String::new(),
            member_short_name(segments, name),
        );
        self.parsed.replace_code_unit(
            code_unit.clone(),
            range_node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed.set_ruby_method_dispatch_mode(
            code_unit.clone(),
            ruby_method_dispatch_mode(signature_node, self.source),
        );
        self.parsed.add_signature(
            code_unit,
            ruby_node_text(signature_node, self.source)
                .trim()
                .to_string(),
        );
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

fn attr_field_member_name(node: Node<'_>, name: &str) -> String {
    if method_is_singleton_context(node) {
        format!("$singleton.@{name}")
    } else {
        format!("@{name}")
    }
}

pub(crate) fn ruby_variable_field_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "instance_variable" | "class_variable") {
        return None;
    }
    let name = ruby_node_text(node, source).trim();
    (!name.is_empty()).then(|| name.to_string())
}

pub(crate) fn ruby_field_short_name(
    segments: &[String],
    node: Node<'_>,
    source: &str,
    scope: RubyFieldScope,
) -> Option<String> {
    if segments.is_empty() {
        return None;
    }
    let name = ruby_variable_field_name(node, source)?;
    let member = match scope {
        RubyFieldScope::Instance | RubyFieldScope::ClassVariable => name,
        RubyFieldScope::SingletonClass => format!("$singleton.{name}"),
    };
    Some(member_short_name(segments, &member))
}

pub(crate) fn ruby_field_scope_for_assignment_left(
    left: Node<'_>,
    segments: &[String],
    current_scope: Option<RubyFieldScope>,
) -> Option<RubyFieldScope> {
    if segments.is_empty() {
        return None;
    }
    match left.kind() {
        "class_variable" => Some(RubyFieldScope::ClassVariable),
        "instance_variable" => Some(current_scope.unwrap_or(RubyFieldScope::SingletonClass)),
        _ => None,
    }
}

fn ruby_method_field_scope(node: Node<'_>) -> RubyFieldScope {
    if method_is_singleton_context(node) {
        RubyFieldScope::SingletonClass
    } else {
        RubyFieldScope::Instance
    }
}

fn ruby_method_dispatch_mode(node: Node<'_>, source: &str) -> RubyMethodDispatchMode {
    if module_function_applies_to_method(node, source) {
        RubyMethodDispatchMode::ModuleFunction
    } else if method_is_singleton_context(node) {
        RubyMethodDispatchMode::Singleton
    } else {
        RubyMethodDispatchMode::Instance
    }
}

fn method_is_singleton_context(node: Node<'_>) -> bool {
    if node.kind() == "singleton_method" {
        return true;
    }
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == "singleton_class" {
            return true;
        }
        if matches!(current.kind(), "class" | "module") {
            break;
        }
        parent = current.parent();
    }
    false
}

fn module_function_applies_to_method(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "method" {
        return false;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return false;
    };
    let method_name = ruby_node_text(name_node, source).trim();
    let Some(module) = enclosing_module_for_module_function(node) else {
        return false;
    };
    let Some(body) = module.child_by_field_name("body") else {
        return false;
    };

    let mut bare_module_function_active = false;
    let mut stack = vec![body];
    while let Some(current) = stack.pop() {
        if current != body
            && matches!(
                current.kind(),
                "class" | "module" | "method" | "singleton_method"
            )
        {
            continue;
        }
        if current.kind() == "identifier"
            && current.start_byte() < node.start_byte()
            && ruby_node_text(current, source).trim() == "module_function"
        {
            bare_module_function_active = true;
            continue;
        }
        if current.kind() == "call"
            && let Some(method) = current.child_by_field_name("method")
            && ruby_node_text(method, source).trim() == "module_function"
        {
            let mut names = module_function_names(current, source);
            if names.next().is_none() {
                if current.start_byte() < node.start_byte() {
                    bare_module_function_active = true;
                }
            } else if module_function_names(current, source).any(|name| name == method_name) {
                return true;
            }
            continue;
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    bare_module_function_active
}

fn enclosing_module_for_module_function(node: Node<'_>) -> Option<Node<'_>> {
    let mut parent = node.parent();
    while let Some(current) = parent {
        match current.kind() {
            "module" => return Some(current),
            "class" => return None,
            _ => parent = current.parent(),
        }
    }
    None
}

fn module_function_names<'a>(node: Node<'_>, source: &'a str) -> impl Iterator<Item = String> + 'a {
    let mut names = Vec::new();
    if let Some(arguments) = node.child_by_field_name("arguments") {
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            if let Some(name) = literal_symbol_or_string_name(arg, source) {
                names.push(name);
            }
        }
    }
    names.into_iter()
}

fn assignment_constant_short_name(lexical_segments: &[String], name_path: &RubyNamePath) -> String {
    let Some((name, owner_segments)) = name_path.segments.split_last() else {
        return String::new();
    };
    if owner_segments.is_empty() {
        return member_short_name(lexical_segments, name);
    }
    if name_path.absolute || owner_segments.len() > 1 || lexical_segments.is_empty() {
        return member_short_name(owner_segments, name);
    }

    let mut resolved_owner = Vec::new();
    resolved_owner.extend_from_slice(lexical_segments);
    resolved_owner.extend_from_slice(owner_segments);
    member_short_name(&resolved_owner, name)
}

pub(crate) struct RubyNamePath {
    pub(crate) segments: Vec<String>,
    pub(crate) absolute: bool,
}

/// Extracts the namespace segments from a class/module name node by walking the
/// AST (not by string-splitting `::`). A plain `(constant)` yields one segment;
/// a `(scope_resolution)` like `A::B` walks its `scope` and `name` fields to
/// yield `["A", "B"]`.
pub(crate) fn extract_name_segments(name_node: Node<'_>, source: &str) -> Vec<String> {
    extract_name_path(name_node, source).segments
}

pub(crate) fn extract_name_path(name_node: Node<'_>, source: &str) -> RubyNamePath {
    match name_node.kind() {
        "scope_resolution" => {
            let mut path = name_node
                .child_by_field_name("scope")
                .map(|scope| extract_name_path(scope, source))
                .unwrap_or_else(|| RubyNamePath {
                    segments: Vec::new(),
                    absolute: true,
                });
            if let Some(name) = name_node.child_by_field_name("name") {
                path.segments.extend(extract_name_segments(name, source));
            }
            path
        }
        _ => {
            let text = ruby_node_text(name_node, source).trim();
            let segments = if text.is_empty() {
                Vec::new()
            } else {
                vec![text.to_string()]
            };
            RubyNamePath {
                segments,
                absolute: false,
            }
        }
    }
}

/// Renders a `constant`/`scope_resolution` reference node into the internal
/// `$`-joined name used as a `CodeUnit` key (e.g. `A::B` -> `A$B`).
pub(crate) fn qualified_internal_name(node: Node<'_>, source: &str) -> Option<String> {
    let segments = extract_name_segments(node, source);
    (!segments.is_empty()).then(|| segments.join("$"))
}

/// Collects a class/module's true superclass. Ruby mixins are intentionally not
/// type hierarchy ancestors; they are modeled separately for method lookup.
fn extract_ruby_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut supertypes = Vec::new();

    if let Some(superclass) = node.child_by_field_name("superclass") {
        let mut cursor = superclass.walk();
        if let Some(expr) = superclass.named_children(&mut cursor).next()
            && let Some(name) = qualified_internal_name(expr, source)
        {
            supertypes.push(name);
        }
    }

    supertypes
}

/// Extracts the bare name from a literal `attr_*`/`alias_method` argument,
/// which is usually a symbol (`:name`) or string (`"name"`).
fn literal_symbol_or_string_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "simple_symbol" | "string") {
        return None;
    }
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

fn ruby_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let mut cursor = parameters_node.walk();
    let labels = parameters_node
        .named_children(&mut cursor)
        .filter_map(|child| ruby_parameter_label_node(child))
        .map(|label_node| ruby_node_text(label_node, source).trim().to_string())
        .filter(|label| !label.is_empty())
        .collect();
    SignatureMetadata::with_parameter_labels(signature, labels)
}

fn ruby_parameter_label_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "optional_parameter"
        | "keyword_parameter"
        | "splat_parameter"
        | "hash_splat_parameter"
        | "block_parameter" => node
            .child_by_field_name("name")
            .or_else(|| first_identifier_descendant(node)),
        _ => None,
    }
}

fn first_identifier_descendant(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier" {
            return Some(current);
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

/// Container node kinds the visitor recurses through to find conditionally
/// declared symbols (e.g. a `def` inside an `if`). Excludes `method`/
/// `singleton_method`, whose bodies are treated as leaves.
pub(super) fn is_descendable_container(kind: &str) -> bool {
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
            | "body_statement"
            | "do"
            | "do_block"
            | "block"
            | "then"
            | "ensure"
            | "rescue"
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
