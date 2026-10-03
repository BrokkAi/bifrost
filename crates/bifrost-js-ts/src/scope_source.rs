//! Source-time binding evidence for JavaScript and TypeScript declarations.
//!
//! This module is used while the primary syntax tree is live.  It deliberately
//! returns tree-sitter nodes rather than display ranges so the caller can
//! intern the exact binder occurrence into the canonical source arena.

use crate::syntax::{JsTsLexicalBindingIndex, pattern_binder_identifiers};
use crate::typescript::ts_is_global_internal_module;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

/// File-level module facts computed once while the primary tree is live.
///
/// Namespace names stay private because consumers need the final
/// declaration-level `is_global` decision, not another parser-shaped export
/// representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsTsGlobalScopeFacts {
    pub file_is_esm: bool,
    global_namespace_names: HashSet<String>,
}

impl JsTsGlobalScopeFacts {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut cursor = root.walk();
        let file_is_esm = root
            .named_children(&mut cursor)
            .any(|statement| matches!(statement.kind(), "import_statement" | "export_statement"));
        let mut global_namespace_names = HashSet::default();
        let mut cursor = root.walk();
        for statement in root
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "export_statement")
        {
            if has_as_namespace_clause(statement)
                && let Some(name) = statement
                    .named_children(&mut statement.walk())
                    .find(|child| child.kind() == "identifier")
            {
                global_namespace_names.insert(
                    name.utf8_text(source.as_bytes())
                        .expect("identifier text")
                        .to_string(),
                );
            }
        }
        Self {
            file_is_esm,
            global_namespace_names,
        }
    }
}

fn has_as_namespace_clause(statement: Node<'_>) -> bool {
    let mut has_as = false;
    let mut has_namespace = false;
    let mut cursor = statement.walk();
    for child in statement.children(&mut cursor) {
        match child.kind() {
            "as" => has_as = true,
            "namespace" => has_namespace = true,
            _ => {}
        }
    }
    has_as && has_namespace
}

/// One exact binder that is visible from an admitted declaration.
///
/// A declaration may have more than one row here.  For example, a method in a
/// class carries the class name as an owner binding, while a destructuring
/// declaration carries each pattern binder.  The caller deduplicates by
/// declaration/name when publishing facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsTsDeclarationBinding<'tree> {
    pub binder: Node<'tree>,
    pub is_program: bool,
}

#[derive(Clone, Copy)]
struct DeclarationScope<'tree> {
    node: Node<'tree>,
    parent: Option<Node<'tree>>,
    owner: Option<Node<'tree>>,
    enclosing_scope: Node<'tree>,
    is_global: bool,
}

/// Source-time ancestry summaries. Ancestor queries follow binder-bearing
/// owners only; deeply nested statements never require a parent walk.
pub(crate) struct JsTsDeclarationScopeIndex<'tree> {
    root: Node<'tree>,
    contexts: brokk_bifrost_core::hash::HashMap<usize, DeclarationScope<'tree>>,
}

impl<'tree> JsTsDeclarationScopeIndex<'tree> {
    pub fn new(root: Node<'tree>, source: &str) -> Self {
        let globals = JsTsGlobalScopeFacts::new(root, source);
        let mut contexts = brokk_bifrost_core::hash::HashMap::default();
        let initial = DeclarationScope {
            node: root,
            parent: None,
            owner: None,
            enclosing_scope: root,
            is_global: !globals.file_is_esm,
        };
        let mut stack = vec![(root, initial)];
        while let Some((node, mut context)) = stack.pop() {
            context.node = node;
            context.is_global |= (node.kind() == "ambient_declaration"
                && node
                    .children(&mut node.walk())
                    .any(|child| child.kind() == "global"))
                || ts_is_global_internal_module(node, source)
                || (node.kind() == "internal_module"
                    && node
                        .child_by_field_name("name")
                        .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                        .is_some_and(|name| globals.global_namespace_names.contains(name)));
            contexts.insert(node.id(), context);
            let child_context = DeclarationScope {
                node,
                parent: Some(node),
                owner: if owns_declaration_binders(node) {
                    Some(node)
                } else {
                    context.owner
                },
                enclosing_scope: if is_declaration_scope(node) {
                    node
                } else {
                    context.enclosing_scope
                },
                is_global: context.is_global,
            };
            let mut cursor = node.walk();
            stack.extend(
                node.named_children(&mut cursor)
                    .map(|child| (child, child_context)),
            );
        }
        Self { root, contexts }
    }

    pub fn parent(&self, node: Node<'_>) -> Option<Node<'tree>> {
        self.contexts[&node.id()].parent
    }

    pub fn declaration_is_global(&self, node: Node<'_>) -> bool {
        self.contexts[&node.id()].is_global
    }

    pub fn declaration_bindings(
        &self,
        declaration: Node<'_>,
        admitted_name: Option<Node<'_>>,
        lexical_bindings: &JsTsLexicalBindingIndex,
    ) -> Vec<JsTsDeclarationBinding<'tree>> {
        let declaration = self.contexts[&declaration.id()].node;
        let definition = declaration
            .child_by_field_name("declaration")
            .or_else(|| declaration.child_by_field_name("value"))
            .unwrap_or(declaration);
        let mut bindings = Vec::new();
        let mut seen = HashSet::default();
        let mut node = Some(definition);
        while let Some(current) = node {
            for binder in declaration_binders(current) {
                if current.id() == definition.id()
                    && admitted_name.is_some_and(|name| name.id() != binder.id())
                {
                    continue;
                }
                if !seen.insert(binder.id()) {
                    continue;
                }
                let is_program = lexical_bindings
                    .binding_is_program_for_binder(binder)
                    .unwrap_or_else(|| {
                        self.contexts[&current.id()].enclosing_scope.id() == self.root.id()
                    });
                bindings.push(JsTsDeclarationBinding { binder, is_program });
            }
            node = self.contexts[&current.id()].owner;
        }
        bindings
    }
}

fn owns_declaration_binders(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "variable_declarator"
            | "formal_parameter"
            | "required_parameter"
            | "optional_parameter"
            | "rest_pattern"
            | "assignment_pattern"
            | "object_assignment_pattern"
            | "pair_pattern"
            | "object_pattern"
            | "array_pattern"
            | "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration"
            | "internal_module"
    )
}

fn is_declaration_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "program"
            | "statement_block"
            | "for_statement"
            | "for_in_statement"
            | "switch_body"
            | "catch_clause"
            | "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "arrow_function"
            | "method_definition"
            | "internal_module"
    )
}

/// Return binder identifiers owned directly by one syntax node.
fn declaration_binders<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    match node.kind() {
        "variable_declaration" | "lexical_declaration" => {
            let mut binders = Vec::new();
            let mut cursor = node.walk();
            for declarator in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "variable_declarator")
            {
                if let Some(pattern) = declarator.child_by_field_name("name") {
                    binders.extend(pattern_binder_identifiers(pattern));
                }
            }
            binders
        }
        "variable_declarator" => node
            .child_by_field_name("name")
            .map(pattern_binder_identifiers)
            .unwrap_or_default(),
        "formal_parameter"
        | "required_parameter"
        | "optional_parameter"
        | "rest_pattern"
        | "assignment_pattern"
        | "object_assignment_pattern"
        | "pair_pattern"
        | "object_pattern"
        | "array_pattern" => pattern_binder_identifiers(node),
        "function_declaration"
        | "generator_function_declaration"
        | "function_expression"
        | "generator_function"
        | "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "type_alias_declaration"
        | "internal_module" => node
            .child_by_field_name("name")
            .filter(|name| matches!(name.kind(), "identifier" | "type_identifier"))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::JsTsLexicalBindingIndex;
    use tree_sitter::Parser;

    fn declaration_bindings_for(source: &str, kind: &str) -> Vec<(String, bool)> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        let tree = parser.parse(source, None).expect("parse");
        let root = tree.root_node();
        let lexical = JsTsLexicalBindingIndex::build(root, source);
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                return JsTsDeclarationScopeIndex::new(root, source)
                    .declaration_bindings(node, None, &lexical)
                    .into_iter()
                    .map(|binding| {
                        (
                            binding
                                .binder
                                .utf8_text(source.as_bytes())
                                .expect("binder text")
                                .to_string(),
                            binding.is_program,
                        )
                    })
                    .collect();
            }
            for child_index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(child_index) {
                    stack.push(child);
                }
            }
        }
        Vec::new()
    }

    #[test]
    fn owner_links_keep_exact_variable_binder_without_siblings() {
        let bindings = declaration_bindings_for(
            "const first = {}, second = { method() {} };",
            "method_definition",
        );
        assert_eq!(bindings, vec![("second".to_string(), true)]);
        let local = declaration_bindings_for(
            "function outer() { var second = { method() {} }; }",
            "method_definition",
        );
        assert!(local.contains(&("second".to_string(), false)));
        assert!(local.contains(&("outer".to_string(), true)));
    }

    #[test]
    fn global_status_follows_structured_namespace_ancestry() {
        for (source, expected) in [
            ("export {}; declare global { interface Item {} }", true),
            ("export {}; namespace Local { interface Item {} }", false),
            ("namespace Local { interface Item {} }", true),
        ] {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let scopes = JsTsDeclarationScopeIndex::new(tree.root_node(), source);
            let mut stack = vec![tree.root_node()];
            let mut found = false;
            while let Some(node) = stack.pop() {
                if node.kind() == "interface_declaration" {
                    assert_eq!(scopes.declaration_is_global(node), expected, "{source}");
                    found = true;
                }
                stack.extend(node.named_children(&mut node.walk()));
            }
            assert!(found);
        }
    }

    #[test]
    fn includes_program_scope_owner_for_class_member() {
        let bindings =
            declaration_bindings_for("class Foo { method() { return 1; } }", "method_definition");
        assert!(
            bindings
                .iter()
                .any(|(name, is_program)| name == "Foo" && *is_program)
        );
    }

    #[test]
    fn class_inside_function_is_not_program_scope() {
        let bindings = declaration_bindings_for(
            "function outer() { class Foo { method() {} } }",
            "method_definition",
        );
        assert!(
            bindings
                .iter()
                .any(|(name, is_program)| name == "Foo" && !*is_program)
        );
    }

    #[test]
    fn interface_and_namespace_use_structured_scope() {
        let bindings = declaration_bindings_for(
            "namespace Local { interface Item {} } interface Root {}",
            "interface_declaration",
        );
        assert!(
            bindings
                .iter()
                .any(|(name, is_program)| name == "Item" && !*is_program)
        );
    }
}
