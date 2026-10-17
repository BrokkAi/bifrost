//! Mounted read-side input for Python declaration consumers.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::python_facts::PythonSourceFacts;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::source_facts::SourceFactRows;
use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;
use tree_sitter::Node;

/// Syntax-only proof candidates for module-level initializer values.
///
/// This is deliberately separate from [`PythonFileSourceFacts`]: that type is
/// a read projection over persisted rows, while this value is derived from the
/// current parse tree and belongs in the analyzer's generation/blob/file
/// cache. A returned range identifies only the RHS of a single, plain module
/// assignment; callers still classify that expression before using it.
#[derive(Debug, Clone, Default)]
pub struct PythonModuleGlobalSourceFacts {
    bindings: HashMap<Box<str>, PythonModuleGlobalBindingFact>,
    global_declarations: HashSet<Box<str>>,
    wildcard_import_offsets: Vec<usize>,
    has_dynamic_write: bool,
    has_exec: bool,
}

#[derive(Debug, Clone, Default)]
struct PythonModuleGlobalBindingFact {
    statements: u32,
    initializer: Option<Range>,
    initializer_statement_end: usize,
}

impl PythonModuleGlobalSourceFacts {
    /// Whether any module-scope syntax binds this name.
    pub fn module_binds_name(&self, name: &str) -> bool {
        self.bindings.contains_key(name)
    }

    /// The initializer's RHS range only when every local syntactic proof holds.
    pub fn initializer_range(&self, name: &str) -> Option<Range> {
        if self.has_dynamic_write || self.has_exec || self.global_declarations.contains(name) {
            return None;
        }
        let binding = self.bindings.get(name)?;
        if binding.statements != 1 {
            return None;
        }
        if self
            .wildcard_import_offsets
            .iter()
            .any(|offset| *offset > binding.initializer_statement_end)
        {
            return None;
        }
        binding.initializer
    }

    /// Approximate retained bytes for the analyzer's weighted per-file cache.
    pub fn estimated_retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self
                .bindings
                .keys()
                .map(|name| name.len() + size_of::<PythonModuleGlobalBindingFact>())
                .sum::<usize>()
            + self
                .global_declarations
                .iter()
                .map(|name| name.len() + size_of::<Box<str>>())
                .sum::<usize>()
            + self.wildcard_import_offsets.len() * size_of::<usize>()
    }
}

/// Collect bounded, per-file module-binding syntax facts.
///
/// The module binding walk skips function, lambda and class bodies, but still
/// visits their headers because decorators and defaults execute in the
/// enclosing scope. A second iterative walk records `global` declarations and
/// reflective writes wherever they occur in the module.
pub fn python_module_global_source_facts(
    root: Node<'_>,
    source: &str,
    max_nodes: usize,
    mut keep_going: impl FnMut() -> bool,
) -> Option<PythonModuleGlobalSourceFacts> {
    if root.kind() != "module" || root.has_error() {
        return None;
    }
    let mut remaining = max_nodes;
    let mut facts = PythonModuleGlobalSourceFacts::default();
    let mut stack = vec![(root, true)];
    while let Some((node, initializer_path)) = stack.pop() {
        if remaining == 0 || !keep_going() {
            return None;
        }
        remaining -= 1;

        if node.kind() == "wildcard_import" {
            facts.wildcard_import_offsets.push(node.start_byte());
        }

        let mut bound_names = HashSet::<String>::new();
        if matches!(
            node.kind(),
            "function_definition"
                | "class_definition"
                | "import_statement"
                | "import_from_statement"
                | "assignment"
                | "augmented_assignment"
                | "annotated_assignment"
                | "named_expression"
                | "for_statement"
                | "delete_statement"
                | "as_pattern"
                | "except_clause"
                | "case_clause"
        ) {
            let mut steps = || {
                if remaining == 0 || !keep_going() {
                    false
                } else {
                    remaining -= 1;
                    true
                }
            };
            for binding in
                crate::bindings::python_direct_scope_bindings_bounded(node, source, &mut steps)?
            {
                if binding.declaration.kind() == "identifier" {
                    bound_names.insert(
                        binding
                            .declaration
                            .utf8_text(source.as_bytes())
                            .ok()?
                            .to_owned(),
                    );
                }
            }
        }
        if node.kind() == "annotated_assignment"
            && let Some(target) = node.child_by_field_name("left")
        {
            module_target_names(
                target,
                source,
                &mut bound_names,
                &mut remaining,
                &mut keep_going,
            )?;
        }
        if node.kind() == "with_statement" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "with_clause" {
                    let mut with_stack = vec![child];
                    while let Some(item) = with_stack.pop() {
                        if remaining == 0 || !keep_going() {
                            return None;
                        }
                        remaining -= 1;
                        if item.kind() == "as_pattern"
                            && let Some(alias) = item.child_by_field_name("alias")
                        {
                            module_target_names(
                                alias,
                                source,
                                &mut bound_names,
                                &mut remaining,
                                &mut keep_going,
                            )?;
                        }
                        with_stack.extend(item.named_children(&mut item.walk()));
                    }
                }
            }
        }

        if !bound_names.is_empty() {
            let assignment_initializer = (node.kind() == "assignment"
                && initializer_path
                && node.parent().is_some_and(|parent| {
                    matches!(parent.kind(), "module" | "block" | "expression_statement")
                })
                && node.child_by_field_name("type").is_none()
                && node.child_by_field_name("annotation").is_none()
                && node
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == "identifier")
                && bound_names.len() == 1)
                .then(|| node.child_by_field_name("right"))
                .flatten();
            for name in bound_names {
                let binding = facts.bindings.entry(name.into_boxed_str()).or_default();
                binding.statements = binding.statements.saturating_add(1);
                if let Some(value) = assignment_initializer {
                    binding.initializer = Some(node_range(value, source));
                    binding.initializer_statement_end = node.end_byte();
                } else {
                    binding.initializer = None;
                    binding.initializer_statement_end = node.end_byte();
                }
            }
        }

        let allowed_block = matches!(
            node.kind(),
            "if_statement"
                | "try_statement"
                | "with_statement"
                | "for_statement"
                | "block"
                | "except_clause"
                | "else_clause"
                | "finally_clause"
                | "expression_statement"
        );
        let scope_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let name_node = matches!(node.kind(), "function_definition" | "class_definition")
            .then(|| node.child_by_field_name("name").map(|name| name.id()))
            .flatten();
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if Some(child.id()) == scope_body || Some(child.id()) == name_node {
                continue;
            }
            let child_initializer_path =
                if matches!(node.kind(), "module" | "block" | "expression_statement") {
                    initializer_path
                } else if matches!(
                    node.kind(),
                    "except_clause" | "else_clause" | "finally_clause"
                ) {
                    initializer_path && child.kind() == "block"
                } else if allowed_block {
                    if node.kind() == "try_statement" {
                        initializer_path
                            && matches!(
                                child.kind(),
                                "block" | "except_clause" | "else_clause" | "finally_clause"
                            )
                    } else if matches!(node.kind(), "if_statement" | "for_statement")
                        && child.kind() == "else_clause"
                    {
                        initializer_path
                    } else {
                        initializer_path
                            && child.kind() == "block"
                            && (node
                                .child_by_field_name("body")
                                .is_some_and(|body| body.id() == child.id())
                                || node
                                    .child_by_field_name("consequence")
                                    .is_some_and(|body| body.id() == child.id())
                                || node
                                    .child_by_field_name("alternative")
                                    .is_some_and(|body| body.id() == child.id()))
                    }
                } else {
                    false
                };
            if matches!(
                node.kind(),
                "list_comprehension"
                    | "set_comprehension"
                    | "dictionary_comprehension"
                    | "generator_expression"
            ) && child.kind() == "for_in_clause"
            {
                let target = child.child_by_field_name("left");
                let mut clause_cursor = child.walk();
                for clause_child in child.named_children(&mut clause_cursor) {
                    if target.is_some_and(|target| target.id() == clause_child.id()) {
                        continue;
                    }
                    stack.push((clause_child, false));
                }
                continue;
            }
            stack.push((child, child_initializer_path));
        }
    }

    remaining = max_nodes;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if remaining == 0 || !keep_going() {
            return None;
        }
        remaining -= 1;
        if node.kind() == "global_statement" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "identifier" {
                    facts.global_declarations.insert(
                        child
                            .utf8_text(source.as_bytes())
                            .ok()?
                            .to_owned()
                            .into_boxed_str(),
                    );
                }
            }
        }
        if node.kind() == "call" {
            let function = node.child_by_field_name("function");
            if function.is_some_and(|function| {
                function.kind() == "identifier"
                    && function.utf8_text(source.as_bytes()).ok() == Some("exec")
            }) {
                facts.has_exec = true;
            }
            if module_globals_write_call(node, source) {
                facts.has_dynamic_write = true;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    facts.wildcard_import_offsets.sort_unstable();
    Some(facts)
}

fn node_range(node: Node<'_>, source: &str) -> Range {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    let start_line = source.as_bytes()[..start_byte]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1;
    let end_line = source.as_bytes()[..end_byte]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1;
    Range {
        start_byte,
        end_byte,
        start_line,
        end_line,
    }
}

fn module_target_names(
    root: Node<'_>,
    source: &str,
    names: &mut HashSet<String>,
    remaining: &mut usize,
    keep_going: &mut impl FnMut() -> bool,
) -> Option<()> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if *remaining == 0 || !keep_going() {
            return None;
        }
        *remaining -= 1;
        match node.kind() {
            "identifier" => {
                names.insert(node.utf8_text(source.as_bytes()).ok()?.to_owned());
            }
            "attribute" | "subscript" | "call" | "string" | "integer" => {}
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
    Some(())
}

fn module_globals_write_call(call: Node<'_>, source: &str) -> bool {
    let function = call.child_by_field_name("function");
    let Some(function) = function else {
        return false;
    };
    if function.kind() == "attribute" {
        let method = function.child_by_field_name("attribute");
        let object = function.child_by_field_name("object");
        if method.is_some_and(|method| {
            method
                .utf8_text(source.as_bytes())
                .ok()
                .is_some_and(|name| matches!(name, "update" | "setdefault" | "pop" | "clear"))
        }) && object.is_some_and(|object| is_module_mapping_call(object, source))
        {
            return true;
        }
    }
    if !is_module_mapping_call(call, source) {
        return false;
    }
    let mut current = call;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "assignment" | "augmented_assignment" | "annotated_assignment" => {
                return parent.child_by_field_name("left").is_some_and(|left| {
                    left.start_byte() <= call.start_byte() && call.end_byte() <= left.end_byte()
                });
            }
            "delete_statement" => return true,
            "subscript" | "attribute" => current = parent,
            _ => return false,
        }
    }
    false
}

fn is_module_mapping_call(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call"
        || !node
            .child_by_field_name("arguments")
            .is_some_and(|arguments| {
                let mut cursor = arguments.walk();
                arguments.named_children(&mut cursor).next().is_none()
            })
    {
        return false;
    }
    node.child_by_field_name("function")
        .is_some_and(|function| {
            function.kind() == "identifier"
                && function
                    .utf8_text(source.as_bytes())
                    .ok()
                    .is_some_and(|name| matches!(name, "globals" | "vars"))
        })
}

#[derive(Debug, Clone)]
pub struct PythonFileSourceFacts {
    pub occurrences: SourceFactRows,
    pub facts: PythonSourceFacts,
}

impl PythonFileSourceFacts {
    /// Select the canonical callable for one exact current-syntax focus.
    pub fn callable_return_for_range(
        &self,
        start: usize,
        end: usize,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<&brokk_bifrost_core::analyzer::python_facts::PythonCallableReturnFact> {
        for fact in &self.facts.callable_returns {
            if !keep_going() {
                return None;
            }
            let declaration = self.occurrences.declaration(fact.declaration);
            let range = self.occurrences.occurrence(declaration.occurrence).range;
            if range.start_byte == start && range.end_byte == end {
                return Some(fact);
            }
        }
        None
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.occurrences
            .estimated_bytes()
            .saturating_add(self.facts.estimated_retained_bytes())
    }
}

pub trait PythonSourceFactProvider: Send + Sync {
    /// Missing publication is unavailable; a published empty file returns Some.
    /// `keep_going` is the caller's admission and traversal continuation check.
    fn python_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<PythonFileSourceFacts>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn module_facts(source: &str) -> PythonModuleGlobalSourceFacts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        let tree = parser.parse(source, None).expect("parse fixture");
        python_module_global_source_facts(tree.root_node(), source, 100_000, || true)
            .expect("complete Python module facts")
    }

    fn initializer<'a>(
        facts: &PythonModuleGlobalSourceFacts,
        source: &'a str,
        name: &str,
    ) -> Option<&'a str> {
        let range = facts.initializer_range(name)?;
        source.get(range.start_byte..range.end_byte)
    }

    #[test]
    #[hardwon(
        "#4622: module-global initializer classes became unsafe after rebinding or reflective writes"
    )]
    fn module_global_source_fact_requires_a_single_safe_assignment() {
        let source = "class Target: pass\n\
safe = Target()\n\
items = [safe for safe in ()]\n\
if True:\n    nested_safe = Target()\n";
        let facts = module_facts(source);
        assert_eq!(
            Some("Target()"),
            initializer(&facts, source, "safe"),
            "{facts:#?}"
        );
        assert_eq!(Some("Target()"), initializer(&facts, source, "nested_safe"));

        let source = "class Target: pass\n\
global_write = Target()\n\
def change():\n    global global_write\n    global_write = None\n";
        assert_eq!(
            None,
            initializer(&module_facts(source), source, "global_write")
        );

        let source = "class Target: pass\n\
twice = Target()\n\
twice = Target()\n";
        assert_eq!(None, initializer(&module_facts(source), source, "twice"));

        let source = "class Target: pass\n\
dynamic = Target()\n\
globals()[\"dynamic\"] = None\n";
        assert_eq!(None, initializer(&module_facts(source), source, "dynamic"));

        let source = "class Target: pass\n\
dynamic = Target()\n\
vars().update(dynamic=None)\n";
        assert_eq!(None, initializer(&module_facts(source), source, "dynamic"));

        let source = "class Target: pass\n\
dynamic = Target()\n\
exec(\"dynamic = None\")\n";
        assert_eq!(None, initializer(&module_facts(source), source, "dynamic"));

        let source = "class Target: pass\n\
wild = Target()\n\
from elsewhere import *\n";
        assert_eq!(None, initializer(&module_facts(source), source, "wild"));

        let source = "class Target: pass\n\
annotated: object = Target()\n\
augmented = Target()\n\
augmented += Target()\n\
deleted = Target()\n\
del deleted\n\
for loop_target in ():\n    pass\n\
with manager as with_target:\n    pass\n\
walrus = None\n\
(walrus := Target())\n\
import pathlib as imported\n\
from os import path as from_imported\n\
def declared():\n    pass\n\
class Declared: pass\n";
        let facts = module_facts(source);
        for name in [
            "annotated",
            "augmented",
            "deleted",
            "loop_target",
            "with_target",
            "walrus",
            "imported",
            "from_imported",
            "declared",
            "Declared",
        ] {
            assert_eq!(
                None,
                initializer(&facts, source, name),
                "{name}: {facts:#?}"
            );
        }
    }
}
