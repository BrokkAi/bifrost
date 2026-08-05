//! Rust's unrecognized-symbol semantic diagnostics.
//!
//! The scan resolves names through the same per-file
//! [`crate::graph_support::RustReferenceContext`] the usage graph uses, and
//! confirms survivors against a core
//! [`brokk_bifrost_core::analyzer::BoundedDefinitionLookup`]. Neither needs an
//! analyzer handle, so all of it lives here; `analyzer/rust/diagnostics.rs` in
//! `brokk-bifrost-analysis` keeps only the downcast that produces those two
//! arguments, and the tests that need a live analyzer to produce them.

use crate::graph_support::RustUsageSource;
use brokk_bifrost_core::analyzer::model::{ImportInfo, SemanticDiagnostic};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{
    contains_node, node_range, node_text, same_node,
};
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::Node;

/// The upper bound on source a diagnostics scan will look at, and on the number
/// of diagnostics one file may report.
pub const MAX_RUST_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
pub const MAX_RUST_SEMANTIC_DIAGNOSTICS: usize = 200;

pub const RUST_UNRECOGNIZED_SYMBOL: &str = "rust_unrecognized_symbol";
pub const RUST_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-rust";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSemanticDiagnostic {
    pub range: Range,
    pub kind: &'static str,
    pub message: String,
}

impl From<RustSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: RustSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: RUST_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

/// Scan `source` for names no declaration in the workspace explains.
///
/// `rust` supplies the per-file reference context and type-alias predicate;
/// `support` is the declaration lookup survivors are confirmed against. The
/// caller produces both -- see the analysis-side entry point of the same name.
pub fn collect_rust_semantic_diagnostics(
    rust: &dyn RustUsageSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
) -> Vec<RustSemanticDiagnostic> {
    if source.len() > MAX_RUST_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(tree) = crate::lexical_scope::parse_rust_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let line_starts = compute_line_starts(source);
    let root = tree.root_node();
    let visible_uses = collect_rust_use_bindings(root, source);
    let mut collector = RustDiagnosticCollector {
        rust,
        support,
        file,
        source,
        line_starts: &line_starts,
        root,
        visible_uses,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(root);
    collector.diagnostics
}

struct RustDiagnosticCollector<'a, 'tree> {
    rust: &'a dyn RustUsageSource,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    root: Node<'tree>,
    visible_uses: Vec<RustUseBinding>,
    diagnostics: Vec<RustSemanticDiagnostic>,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitScope,
    SeedPattern(Node<'tree>),
}

impl RustDiagnosticCollector<'_, '_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = RustScopeStack::default();
        scopes.enter();
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostics.len() >= MAX_RUST_SEMANTIC_DIAGNOSTICS {
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut scopes, &mut stack),
                ScanFrame::ExitScope => scopes.exit(),
                ScanFrame::SeedPattern(pattern) => {
                    seed_pattern_bindings(pattern, self.source, &mut scopes)
                }
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scopes: &mut RustScopeStack,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
        if is_subtree_suppressed(node, self.source) {
            return;
        }
        match node.kind() {
            "source_file" => push_named_children(stack, node),
            "block" => {
                scopes.enter();
                seed_block_item_bindings(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "function_item" | "function_signature_item" => {
                scopes.enter_isolated();
                seed_item_name(node, self.source, scopes);
                seed_function_like_bindings(node, self.source, scopes);
                seed_type_parameters(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "closure_expression" => {
                scopes.enter();
                seed_function_like_bindings(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "struct_item" | "enum_item" | "trait_item" | "type_item" | "impl_item" => {
                scopes.enter();
                seed_type_parameters(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "let_declaration" => {
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(ScanFrame::SeedPattern(
                        node.child_by_field_name("pattern").unwrap_or(value),
                    ));
                    stack.push(ScanFrame::Node(value));
                } else if let Some(pattern) = node.child_by_field_name("pattern") {
                    seed_pattern_bindings(pattern, self.source, scopes);
                }
                if let Some(type_node) = node.child_by_field_name("type") {
                    stack.push(ScanFrame::Node(type_node));
                }
            }
            "for_expression" => {
                if let Some(body) = node.child_by_field_name("body") {
                    scopes.enter();
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        seed_pattern_bindings(pattern, self.source, scopes);
                    }
                    stack.push(ScanFrame::ExitScope);
                    stack.push(ScanFrame::Node(body));
                }
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(ScanFrame::Node(value));
                }
            }
            "match_arm" => {
                scopes.enter();
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    seed_pattern_bindings(pattern, self.source, scopes);
                }
                stack.push(ScanFrame::ExitScope);
                push_named_children_except(stack, node, &["pattern"]);
            }
            "parameter" => {
                if let Some(type_node) = node.child_by_field_name("type") {
                    stack.push(ScanFrame::Node(type_node));
                }
            }
            "self_parameter" | "use_declaration" | "attribute_item" => {}
            "type_identifier" => {
                self.check_type_identifier(node, scopes);
                push_named_children(stack, node);
            }
            "scoped_type_identifier" => {
                self.check_scoped_type_identifier(node, scopes);
                push_named_children(stack, node);
            }
            "identifier" => {
                self.check_value_identifier(node, scopes);
                push_named_children(stack, node);
            }
            "scoped_identifier" => {
                self.check_scoped_identifier(node, scopes);
                push_named_children(stack, node);
            }
            _ => push_named_children(stack, node),
        }
    }

    fn check_type_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        if !is_type_reference_identifier(node) {
            return;
        }
        let name = node_text(node, self.source).trim();
        if self.name_is_known_or_uncertain(name, node, scopes, SymbolKind::Type) {
            return;
        }
        self.push_unrecognized(node, name);
    }

    fn check_scoped_type_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        if !is_scoped_reference(node) {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        let path = node.child_by_field_name("path");
        if self.scoped_name_is_known_or_uncertain(path, name, node, scopes, SymbolKind::Type) {
            return;
        }
        self.push_unrecognized(name_node, name);
    }

    fn check_value_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        if !is_value_reference_identifier(node) {
            return;
        }
        let name = node_text(node, self.source).trim();
        if self.name_is_known_or_uncertain(name, node, scopes, SymbolKind::Value) {
            return;
        }
        self.push_unrecognized(node, name);
    }

    fn check_scoped_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        if !is_scoped_reference(node) {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        let path = node.child_by_field_name("path");
        if self.scoped_name_is_known_or_uncertain(path, name, node, scopes, SymbolKind::Value) {
            return;
        }
        self.push_unrecognized(name_node, name);
    }

    fn name_is_known_or_uncertain(
        &self,
        name: &str,
        node: Node<'_>,
        scopes: &RustScopeStack,
        kind: SymbolKind,
    ) -> bool {
        if name.is_empty()
            || name == "_"
            || scopes.contains(name, kind)
            || is_rust_builtin_name(name)
            || is_inside_cfg_gated_item(node, self.source)
        {
            return true;
        }
        let binder = self.visible_import_binder_at(node.start_byte());
        if binder
            .bindings
            .values()
            .any(|binding| binding.kind == ImportKind::Glob)
        {
            return true;
        }
        if binder.bindings.contains_key(name) {
            return true;
        }
        let refs = self.rust.reference_context_of(self.file);
        if let Some(resolved) = refs.resolve_bare(name)
            && self.fqn_has_matching_declaration(resolved, kind)
        {
            return true;
        }
        self.support
            .file_identifier(self.file, name)
            .into_iter()
            .any(|unit| self.symbol_kind_matches(&unit, kind))
    }

    fn scoped_name_is_known_or_uncertain(
        &self,
        path_node: Option<Node<'_>>,
        name: &str,
        node: Node<'_>,
        scopes: &RustScopeStack,
        kind: SymbolKind,
    ) -> bool {
        if name.is_empty() || is_inside_cfg_gated_item(node, self.source) {
            return true;
        }
        let Some(path_node) = path_node else {
            return self.name_is_known_or_uncertain(name, node, scopes, kind);
        };
        if !is_crate_local_path(path_node, self.source) {
            return true;
        }
        let path = node_text(path_node, self.source).trim();
        let refs = self.rust.reference_context_of(self.file);
        refs.resolve_scoped(path, name)
            .is_some_and(|resolved| self.fqn_has_matching_declaration(&resolved, kind))
    }

    fn fqn_has_matching_declaration(&self, fqn: &str, kind: SymbolKind) -> bool {
        self.support
            .fqn(fqn)
            .into_iter()
            .any(|unit| self.symbol_kind_matches(&unit, kind))
    }

    fn symbol_kind_matches(&self, unit: &CodeUnit, kind: SymbolKind) -> bool {
        match kind {
            SymbolKind::Type => unit.is_class() || self.rust.is_type_alias(unit),
            SymbolKind::Value => unit.is_function() || unit.is_field() || unit.is_module(),
        }
    }

    fn visible_import_binder_at(&self, reference_byte: usize) -> ImportBinder {
        let reference_mod =
            crate::lexical_scope::enclosing_mod_item_range_at(self.root, reference_byte);
        let mut binder = ImportBinder::empty();
        for visible_use in &self.visible_uses {
            if visible_use.mod_range != reference_mod {
                continue;
            }
            if visible_use
                .scope_range
                .is_some_and(|(start, end)| !(start <= reference_byte && reference_byte < end))
            {
                continue;
            }
            for import in &visible_use.imports {
                crate::lexical_scope::insert_rust_import_binding(&mut binder, import);
            }
        }
        binder
    }

    fn push_unrecognized(&mut self, node: Node<'_>, name: &str) {
        self.diagnostics.push(RustSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind: RUST_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized Rust symbol `{name}`"),
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SymbolKind {
    Type,
    Value,
}

#[derive(Default)]
struct RustScopeStack {
    scopes: Vec<RustScope>,
}

#[derive(Default)]
struct RustScope {
    names: HashSet<(String, SymbolKind)>,
    isolated: bool,
}

impl RustScopeStack {
    fn enter(&mut self) {
        self.scopes.push(RustScope::default());
    }

    fn enter_isolated(&mut self) {
        self.scopes.push(RustScope {
            isolated: true,
            ..RustScope::default()
        });
    }

    fn exit(&mut self) {
        self.scopes.pop();
    }

    fn declare(&mut self, name: String, kind: SymbolKind) {
        if name == "_" {
            return;
        }
        if self.scopes.is_empty() {
            self.enter();
        }
        let scope = self.scopes.last_mut().expect("scope exists after enter");
        scope.names.insert((name, kind));
    }

    fn contains(&self, name: &str, kind: SymbolKind) -> bool {
        let key = (name.to_string(), kind);
        for scope in self.scopes.iter().rev() {
            if scope.names.contains(&key) {
                return true;
            }
            if scope.isolated {
                return false;
            }
        }
        false
    }
}

struct RustUseBinding {
    imports: Vec<ImportInfo>,
    mod_range: Option<(usize, usize)>,
    scope_range: Option<(usize, usize)>,
}

fn collect_rust_use_bindings(root: Node<'_>, source: &str) -> Vec<RustUseBinding> {
    let mut bindings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "use_declaration" {
            let imports = crate::imports::rust_imports_from_use_declaration(node, source);
            if !imports.is_empty() {
                bindings.push(RustUseBinding {
                    imports,
                    mod_range: enclosing_mod_item_range(node),
                    scope_range: enclosing_visibility_scope_range(node),
                });
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    bindings
}

fn enclosing_mod_item_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item" {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn enclosing_visibility_scope_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if lexical_scope_kind(parent.kind()) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn lexical_scope_kind(kind: &str) -> bool {
    matches!(
        kind,
        "block" | "function_item" | "impl_item" | "trait_item" | "mod_item"
    )
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(ScanFrame::Node(child));
    }
}

fn push_named_children_except<'tree>(
    stack: &mut Vec<ScanFrame<'tree>>,
    node: Node<'tree>,
    excluded_fields: &[&str],
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        if excluded_fields.iter().any(|field| {
            node.child_by_field_name(field)
                .is_some_and(|field_node| same_node(field_node, child))
        }) {
            continue;
        }
        stack.push(ScanFrame::Node(child));
    }
}

fn seed_function_like_bindings(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut cursor = params.walk();
        for child in params.named_children(&mut cursor) {
            if let Some(pattern) = child.child_by_field_name("pattern") {
                seed_pattern_bindings(pattern, source, scopes);
            }
        }
    }
}

fn seed_block_item_bindings(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        seed_item_name(child, source, scopes);
    }
}

fn seed_item_name(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let kind = match node.kind() {
        "function_item" | "const_item" | "static_item" => SymbolKind::Value,
        "struct_item" | "enum_item" | "trait_item" | "type_item" => SymbolKind::Type,
        "mod_item" => SymbolKind::Value,
        _ => return,
    };
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name, source).trim();
    if !name.is_empty() {
        scopes.declare(name.to_string(), kind);
    }
}

fn seed_type_parameters(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let mut stack = Vec::new();
    if let Some(params) = node.child_by_field_name("type_parameters") {
        stack.push(params);
    }
    while let Some(current) = stack.pop() {
        if current.kind() == "type_identifier" {
            let name = node_text(current, source).trim();
            if !name.is_empty() {
                scopes.declare(name.to_string(), SymbolKind::Type);
            }
            continue;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn seed_pattern_bindings(pattern: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" => {
                let name = node_text(node, source).trim();
                if !name.is_empty() {
                    scopes.declare(name.to_string(), SymbolKind::Value);
                }
            }
            "scoped_identifier" | "field_identifier" | "type_identifier" => {}
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

fn is_subtree_suppressed(node: Node<'_>, source: &str) -> bool {
    matches!(
        node.kind(),
        "macro_invocation"
            | "macro_definition"
            | "attribute_item"
            | "line_comment"
            | "block_comment"
    ) || is_inside_attribute(node)
        || is_inside_macro_invocation(node)
        || is_inside_cfg_gated_item(node, source)
}

fn is_type_reference_identifier(node: Node<'_>) -> bool {
    if node.kind() != "type_identifier" || is_declaration_name(node) || is_inside_use(node) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    !matches!(
        parent.kind(),
        "type_parameters"
            | "type_parameter"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "type_item"
    )
}

fn is_scoped_reference(node: Node<'_>) -> bool {
    !is_declaration_name(node)
        && !is_inside_use(node)
        && !is_inside_macro_invocation(node)
        && node.child_by_field_name("name").is_some()
}

fn is_value_reference_identifier(node: Node<'_>) -> bool {
    if node.kind() != "identifier"
        || is_declaration_name(node)
        || is_inside_use(node)
        || is_pattern_identifier(node)
    {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "call_expression" => parent
            .child_by_field_name("function")
            .is_some_and(|function| same_node(function, node)),
        "scoped_identifier" | "scoped_type_identifier" => false,
        "field_expression" | "field_initializer" | "field_declaration" => false,
        "macro_invocation" | "macro_definition" | "attribute_item" => false,
        "let_declaration" | "parameter" | "self_parameter" => false,
        _ => true,
    }
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "function_item"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "type_item"
            | "const_item"
            | "static_item"
            | "mod_item"
            | "field_declaration"
            | "enum_variant"
            | "function_signature_item"
    ) && parent
        .child_by_field_name("name")
        .is_some_and(|name| same_node(name, node))
}

fn is_pattern_identifier(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "let_declaration" | "parameter" | "match_arm" | "for_expression"
        ) && parent
            .child_by_field_name("pattern")
            .is_some_and(|pattern| contains_node(pattern, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "block" | "function_item" | "closure_expression"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn is_inside_use(node: Node<'_>) -> bool {
    has_ancestor(node, |ancestor| ancestor.kind() == "use_declaration")
}

fn is_inside_attribute(node: Node<'_>) -> bool {
    has_ancestor(node, |ancestor| ancestor.kind() == "attribute_item")
}

fn is_inside_macro_invocation(node: Node<'_>) -> bool {
    has_ancestor(node, |ancestor| {
        matches!(ancestor.kind(), "macro_invocation" | "macro_definition")
    })
}

fn is_inside_cfg_gated_item(node: Node<'_>, source: &str) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        let mut sibling = candidate.prev_named_sibling();
        while let Some(prev) = sibling {
            if prev.kind() != "attribute_item" {
                break;
            }
            let text = node_text(prev, source).trim();
            if text.starts_with("#[cfg") || text.starts_with("#![cfg") {
                return true;
            }
            sibling = prev.prev_named_sibling();
        }
        current = candidate.parent();
    }
    false
}

fn has_ancestor(node: Node<'_>, predicate: impl Fn(Node<'_>) -> bool) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if predicate(parent) {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn is_crate_local_path(path_node: Node<'_>, source: &str) -> bool {
    let Some(root) = path_root(path_node) else {
        return false;
    };
    matches!(node_text(root, source).trim(), "crate" | "self" | "super")
}

fn path_root(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                node = node.child_by_field_name("path")?;
            }
            "identifier" | "type_identifier" | "crate" | "self" | "super" => return Some(node),
            _ => return None,
        }
    }
}

fn is_rust_builtin_name(name: &str) -> bool {
    matches!(
        name,
        "Self"
            | "self"
            | "super"
            | "crate"
            | "bool"
            | "char"
            | "str"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f32"
            | "f64"
            | "Option"
            | "Result"
            | "Some"
            | "None"
            | "Ok"
            | "Err"
            | "Vec"
            | "String"
            | "Box"
            | "Default"
            | "Debug"
            | "Clone"
            | "Copy"
            | "Send"
            | "Sync"
            | "Sized"
            | "Drop"
            | "Iterator"
            | "IntoIterator"
            | "From"
            | "Into"
            | "AsRef"
            | "AsMut"
            | "ToString"
            | "ToOwned"
            | "println"
            | "format"
            | "vec"
            | "drop"
            | "panic"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "assert"
            | "assert_eq"
            | "assert_ne"
    )
}
