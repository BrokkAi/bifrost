//! Mounted read-side input for Python declaration consumers.

use crate::bindings::PythonLexicalScopeInventory;
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

#[derive(Debug)]
enum PythonModuleMutationHazard {
    Global(Vec<Box<str>>),
    Exec,
    ReflectiveWrite,
}

/// The same grammar classification feeds both file-wide initializer facts and
/// reference-time class binding. None is a stopped classifier, not no hazard.
fn python_module_mutation_hazard_bounded(
    node: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Option<PythonModuleMutationHazard>> {
    if !scope_step() {
        return None;
    }
    if node.kind() == "global_statement" {
        let mut names = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !scope_step() {
                return None;
            }
            if child.kind() == "identifier" {
                names.push(child.utf8_text(source.as_bytes()).ok()?.into());
            }
        }
        return Some(Some(PythonModuleMutationHazard::Global(names)));
    }
    if node.kind() != "call" {
        return Some(None);
    }
    if node
        .child_by_field_name("function")
        .is_some_and(|function| {
            function.kind() == "identifier"
                && function.utf8_text(source.as_bytes()).ok() == Some("exec")
        })
    {
        return Some(Some(PythonModuleMutationHazard::Exec));
    }
    Some(
        module_globals_write_call_bounded(node, source, &mut scope_step)?
            .then_some(PythonModuleMutationHazard::ReflectiveWrite),
    )
}

/// Native producers reuse the same selected-node hazard classification. This
/// retains unknown lexical binders during parsing rather than reparsing a file
/// to certify a later builtin lookup. Global directives have binding events.
pub(crate) fn python_module_dynamic_write_candidate(node: Node<'_>, source: &str) -> bool {
    matches!(
        python_module_mutation_hazard_bounded(node, source, || true),
        Some(Some(
            PythonModuleMutationHazard::Exec | PythonModuleMutationHazard::ReflectiveWrite
        ))
    )
}

/// Complete syntax-only module mutation facts for one request or operation.
///
/// These facts retain no tree nodes, selected reads, source owners or resolved
/// answers. Callers must pair them with the exact prepared-source bytes used
/// for collection, and validate each actual owner's source independently.
#[derive(Debug)]
pub struct PythonModuleMutationFacts {
    global_binding_events: HashSet<Box<str>>,
    dynamic_hazards: Vec<Range>,
}

impl PythonModuleMutationFacts {
    /// Collect all hazards before publishing facts. A stopped collection has
    /// no usable partial result, even if an earlier hazard already refused.
    pub fn collect_bounded(
        root: Node<'_>,
        source: &str,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Self> {
        use brokk_bifrost_core::analyzer::tree_walk::{
            WalkControl, node_range, try_walk_named_tree_preorder,
        };
        if !scope_step() || root.kind() != "module" || root.has_error() {
            return None;
        }
        let mut facts = Self {
            global_binding_events: HashSet::new(),
            dynamic_hazards: Vec::new(),
        };
        let mut checked_global_scopes = HashSet::new();
        try_walk_named_tree_preorder(root, true, |node| {
            if !scope_step() {
                return Err(());
            }
            match python_module_mutation_hazard_bounded(node, source, &mut scope_step).ok_or(())? {
                Some(PythonModuleMutationHazard::Global(_)) => {
                    // Directives belong to their nearest lexical body. Keep
                    // this outer scan file-wide to include sibling writers.
                    let mut current = node.parent();
                    while let Some(scope) = current {
                        if !scope_step() {
                            return Err(());
                        }
                        if scope.kind() == "module" {
                            // Module directives are inert; ordinary module
                            // writes remain the module binder's obligation.
                            break;
                        }
                        if matches!(
                            scope.kind(),
                            "function_definition" | "lambda" | "class_definition"
                        ) {
                            if !checked_global_scopes.contains(&scope.id()) {
                                // Unfiltered inventory preserves pending
                                // class/declaration/import/delete events.
                                let bindings = PythonLexicalScopeInventory::collect_bounded(
                                    scope,
                                    source,
                                    std::iter::empty::<String>(),
                                    &mut scope_step,
                                )
                                .ok_or(())?
                                .into_bindings();
                                // Merge ALL names before deduplicating this
                                // owner, not just the first directive's name.
                                for name in bindings.global_binding_events() {
                                    if !scope_step() {
                                        return Err(());
                                    }
                                    facts.global_binding_events.insert(name.into());
                                }
                                checked_global_scopes.insert(scope.id());
                            }
                            break;
                        }
                        current = scope.parent();
                    }
                }
                Some(
                    PythonModuleMutationHazard::Exec | PythonModuleMutationHazard::ReflectiveWrite,
                ) => {
                    facts.dynamic_hazards.push(node_range(node));
                }
                None => {}
            }
            Ok(WalkControl::Continue)
        })
        .ok()?;
        scope_step().then_some(facts)
    }

    /// Admit an actual read against the current prepared root and reference.
    /// The reference must belong to this root from the same prepared source.
    /// Earlier callable bodies can write; a later body cannot affect an
    /// immediate read except on a loop back-edge. Actual named global events
    /// remain file-wide barriers; read-only directives are not mutations.
    pub fn binding_unmutated_at_bounded(
        &self,
        root: Node<'_>,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        use brokk_bifrost_core::analyzer::tree_walk::node_range;
        use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope;
        if !scope_step() {
            return None;
        }
        if root.kind() != "module" || root.has_error() {
            return scope_step().then_some(false);
        }
        let deferred = crate::syntax::python_reference_is_deferred_function_body_bounded(
            reference,
            &mut scope_step,
        )?;
        let read_range = node_range(reference);
        let mut unmutated = !self.global_binding_events.contains(name);
        if unmutated {
            for hazard in &self.dynamic_hazards {
                if !scope_step() {
                    return None;
                }
                let node = smallest_named_node_covering_with_scope(
                    root,
                    hazard.start_byte,
                    hazard.end_byte,
                    &mut scope_step,
                )?;
                if node.start_byte() != hazard.start_byte || node.end_byte() != hazard.end_byte {
                    return None;
                }
                // A deeper named node with the identical span is sufficient:
                // order depends on this range and enclosing loops, not kind.
                if deferred
                    || crate::runtime_values::python_hazard_can_precede_bounded(
                        *hazard,
                        read_range,
                        node,
                        &mut scope_step,
                    )?
                {
                    unmutated = false;
                    break;
                }
            }
        }
        // A completed inventory does not erase a current caller's late stop,
        // including empty-hazard and known-global-membership return paths.
        scope_step().then_some(unmutated)
    }

    /// Imports consume the actual owner's completed export. Declaration-time
    /// or importer timing cannot dismiss any recorded dynamic hazard.
    pub fn export_unmutated_bounded(
        &self,
        name: &str,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        if !scope_step() {
            return None;
        }
        let unmutated =
            !self.global_binding_events.contains(name) && self.dynamic_hazards.is_empty();
        scope_step().then_some(unmutated)
    }
}

/// Stateless callers share the same complete collector and read evaluator.
pub fn python_module_binding_unmutated_at_bounded(
    root: Node<'_>,
    source: &str,
    name: &str,
    reference: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    PythonModuleMutationFacts::collect_bounded(root, source, &mut scope_step)?
        .binding_unmutated_at_bounded(root, name, reference, scope_step)
}

/// Each source module/facade supplies its own completed export inventory.
pub fn python_module_export_unmutated_bounded(
    root: Node<'_>,
    source: &str,
    name: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    PythonModuleMutationFacts::collect_bounded(root, source, &mut scope_step)?
        .export_unmutated_bounded(name, scope_step)
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
        // Preserve the file-wide/deferred contract, including its historical
        // node budget. The reference-time consumer meters classifier internals.
        match python_module_mutation_hazard_bounded(node, source, || true)? {
            Some(PythonModuleMutationHazard::Global(names)) => {
                facts.global_declarations.extend(names);
            }
            Some(PythonModuleMutationHazard::Exec) => facts.has_exec = true,
            Some(PythonModuleMutationHazard::ReflectiveWrite) => facts.has_dynamic_write = true,
            None => {}
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

fn module_globals_write_call_bounded(
    call: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    if !scope_step() {
        return None;
    }
    let function = call.child_by_field_name("function");
    let Some(function) = function else {
        return Some(false);
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
            return Some(true);
        }
    }
    if !is_module_mapping_call(call, source) {
        return Some(false);
    }
    let mut current = call;
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        match parent.kind() {
            "assignment" | "augmented_assignment" | "annotated_assignment" => {
                return Some(parent.child_by_field_name("left").is_some_and(|left| {
                    left.start_byte() <= call.start_byte() && call.end_byte() <= left.end_byte()
                }));
            }
            "delete_statement" => return Some(true),
            "subscript" | "attribute" => current = parent,
            _ => return Some(false),
        }
    }
    Some(false)
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
        "#4622+#5745: module mutation and stopped scans cannot prove unchanged initializer classes"
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

        let deferred_exec =
            "class Target: pass\nvalue = Target()\ndef later():\n    exec('value = None')\n";
        assert_eq!(
            None,
            initializer(&module_facts(deferred_exec), deferred_exec, "value")
        );

        // A stopped reference-time scan is not an absence proof. The later
        // exec stays irrelevant to this immediate read, but not to exports.
        let bounded_source =
            "class Base: pass\nclass D(Base): pass\ndef later():\n    exec('Base = object')\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        let tree = parser.parse(bounded_source, None).expect("parse fixture");
        let root = tree.root_node();
        let reference = root
            .named_child(1)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let mut visits = 0_usize;
        assert_eq!(
            Some(true),
            python_module_binding_unmutated_at_bounded(
                root,
                bounded_source,
                "Base",
                reference,
                || {
                    visits += 1;
                    true
                },
            )
        );
        for allowance in 0..visits {
            let mut remaining = allowance;
            assert_eq!(
                None,
                python_module_binding_unmutated_at_bounded(
                    root,
                    bounded_source,
                    "Base",
                    reference,
                    || {
                        let allowed = remaining > 0;
                        remaining = remaining.saturating_sub(1);
                        allowed
                    },
                ),
                "stopping after {allowance} of {visits} visits cannot admit Base"
            );
        }
        assert_eq!(
            Some(false),
            python_module_export_unmutated_bounded(root, bounded_source, "Base", || true)
        );

        // One complete inventory serves all selected names. In particular,
        // the first directive's owner must contribute its later names too.
        let multi_source = "class A: pass\nclass B: pass\nclass C: pass\nclass ReadOnly: pass\nclass Sibling: pass\nclass D(A, B, C, ReadOnly, Sibling): pass\ndef writer():\n    global A\n    global B, C\n    global ReadOnly\n    A = None\n    class B(B): pass\n    del C\n    return ReadOnly\ndef sibling():\n    global Sibling\n    from elsewhere import Sibling\n";
        let tree = parser
            .parse(multi_source, None)
            .expect("parse all-name events");
        let root = tree.root_node();
        assert!(!root.has_error());
        let arguments = root
            .named_child(5)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap();
        let mut collection_visits = 0_usize;
        let mutation = PythonModuleMutationFacts::collect_bounded(root, multi_source, || {
            collection_visits += 1;
            true
        })
        .expect("complete mutation inventory");
        for allowance in 0..collection_visits {
            let mut remaining = allowance;
            assert!(
                PythonModuleMutationFacts::collect_bounded(root, multi_source, || {
                    let allowed = remaining > 0;
                    remaining = remaining.saturating_sub(1);
                    allowed
                })
                .is_none(),
                "partial collection at {allowance} must not publish facts"
            );
        }
        for (index, name, expected) in [
            (0, "A", false),
            (1, "B", false),
            (2, "C", false),
            (3, "ReadOnly", true),
            (4, "Sibling", false),
        ] {
            let reference = arguments.named_child(index).unwrap();
            let mut read_visits = 0_usize;
            assert_eq!(
                Some(expected),
                mutation.binding_unmutated_at_bounded(root, name, reference, || {
                    read_visits += 1;
                    true
                }),
                "all-name inventory: {name}"
            );
            assert!(
                read_visits < collection_visits,
                "a reused name read must not recollect the module"
            );
            assert_eq!(
                None,
                mutation.binding_unmutated_at_bounded(root, name, reference, || false),
                "completed facts cannot override a stopped reader"
            );
            for allowance in 0..read_visits {
                let mut remaining = allowance;
                assert_eq!(
                    None,
                    mutation.binding_unmutated_at_bounded(root, name, reference, || {
                        let allowed = remaining > 0;
                        remaining = remaining.saturating_sub(1);
                        allowed
                    }),
                    "{name}: stopped read including final check at {allowance}"
                );
            }
            let mut export_visits = 0_usize;
            assert_eq!(
                Some(expected),
                mutation.export_unmutated_bounded(name, || {
                    export_visits += 1;
                    true
                })
            );
            for allowance in 0..export_visits {
                let mut remaining = allowance;
                assert_eq!(
                    None,
                    mutation.export_unmutated_bounded(name, || {
                        let allowed = remaining > 0;
                        remaining = remaining.saturating_sub(1);
                        allowed
                    }),
                    "{name}: stopped export including final check at {allowance}"
                );
            }
        }

        for (label, source, container_index, expected, export_expected) in [
            (
                "empty inventory still checks the final stop",
                "class Base: pass\nclass D(Base): pass\n",
                1,
                true,
                true,
            ),
            (
                "later exec is irrelevant to immediate read",
                bounded_source,
                1,
                true,
                false,
            ),
            (
                "deferred read includes later exec",
                "class Base: pass\ndef load():\n    class D(Base): pass\ndef later():\n    exec('Base = object')\n",
                1,
                false,
                false,
            ),
            (
                "later loop hazard can precede next read",
                "class Base: pass\nfor item in (1, 2):\n    class D(Base): pass\n    exec('Base = object')\n",
                1,
                false,
                false,
            ),
            (
                "earlier callable remains a possible writer",
                "class Base: pass\ndef earlier():\n    exec('Base = object')\nclass D(Base): pass\n",
                2,
                false,
                false,
            ),
            (
                "later reflective call is irrelevant to immediate read",
                "class Base: pass\nclass D(Base): pass\nglobals().update(Base=object)\n",
                1,
                true,
                false,
            ),
        ] {
            let tree = parser.parse(source, None).expect("parse hazard ordering");
            let root = tree.root_node();
            assert!(!root.has_error(), "{label}");
            let container = root.named_child(container_index).unwrap();
            let class = if container.kind() == "class_definition" {
                container
            } else {
                container
                    .child_by_field_name("body")
                    .unwrap()
                    .named_child(0)
                    .unwrap()
            };
            assert_eq!(class.kind(), "class_definition");
            let reference = class
                .child_by_field_name("superclasses")
                .unwrap()
                .named_child(0)
                .unwrap();
            let mutation =
                PythonModuleMutationFacts::collect_bounded(root, source, || true).unwrap();
            let mut read_visits = 0_usize;
            assert_eq!(
                Some(expected),
                mutation.binding_unmutated_at_bounded(root, "Base", reference, || {
                    read_visits += 1;
                    true
                }),
                "{label}"
            );
            assert_eq!(
                Some(export_expected),
                mutation.export_unmutated_bounded("Base", || true),
                "{label}: completed exports include all hazards"
            );
            for allowance in 0..read_visits {
                let mut remaining = allowance;
                assert_eq!(
                    None,
                    mutation.binding_unmutated_at_bounded(root, "Base", reference, || {
                        let allowed = remaining > 0;
                        remaining = remaining.saturating_sub(1);
                        allowed
                    }),
                    "{label}: recovery/ancestry/final stop at {allowance}"
                );
            }
        }

        // A covering-only recovery cannot stand in for the exact hazard.
        // Callers must prevent changed-source reuse; the evaluator still
        // refuses rather than treating a missing old site as harmless.
        let original_tree = parser.parse(bounded_source, None).unwrap();
        let mutation = PythonModuleMutationFacts::collect_bounded(
            original_tree.root_node(),
            bounded_source,
            || true,
        )
        .unwrap();
        let changed_source = "class Base: pass\nclass D(Base): pass\ndef later():\n    longer_call('a longer structured expression at the previous hazard site')\n";
        let changed_tree = parser.parse(changed_source, None).unwrap();
        let changed_root = changed_tree.root_node();
        let changed_reference = changed_root
            .named_child(1)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        assert_eq!(
            None,
            mutation
                .binding_unmutated_at_bounded(changed_root, "Base", changed_reference, || true,)
        );

        // Runtime namespace mutation requires an event in the directive's
        // own scope. Legacy initializer facts intentionally remain stricter.
        let read_only_initializer = "class Target: pass\nvalue = Target()\ndef read_only():\n    global value\n    return value\n";
        assert_eq!(
            None,
            initializer(
                &module_facts(read_only_initializer),
                read_only_initializer,
                "value"
            )
        );
        for (label, suffix, expected) in [
            (
                "read-only directives and unrelated local writer",
                "def read_only():\n    global Base\n    global Base\n    return Base\ndef local():\n    Base = 0\n",
                true,
            ),
            ("module directive is inert", "", true),
            (
                "sibling global assignment",
                "def read_only():\n    global Base\n    return Base\ndef change():\n    global Base\n    Base = 0\n",
                false,
            ),
            (
                "pending global class binding",
                "class Outer:\n    global Base\n    class Base(Base):\n        pass\n",
                false,
            ),
            (
                "global function declaration",
                "def change():\n    global Base\n    def Base():\n        pass\n",
                false,
            ),
            (
                "global import binding",
                "def change():\n    global Base\n    from elsewhere import Base\n",
                false,
            ),
            (
                "global delete binding",
                "def change():\n    global Base\n    del Base\n",
                false,
            ),
            (
                "nested directive uses nearest class owner",
                "def outer():\n    Base = 0\n    class ReadOnly:\n        global Base\n        value = Base\n",
                true,
            ),
        ] {
            // Place the inert module directive before any Base use, so these
            // controls also respect Python's directive ordering constraint.
            let source = format!("global Base\nclass Base: pass\nclass D(Base): pass\n{suffix}");
            let tree = parser
                .parse(&source, None)
                .expect("parse global event fixture");
            let root = tree.root_node();
            assert!(!root.has_error(), "{label}: {source}");
            let reference = root
                .named_child(2)
                .unwrap()
                .child_by_field_name("superclasses")
                .unwrap()
                .named_child(0)
                .unwrap();
            let mut visits = 0_usize;
            assert_eq!(
                Some(expected),
                python_module_binding_unmutated_at_bounded(
                    root,
                    &source,
                    "Base",
                    reference,
                    || {
                        visits += 1;
                        true
                    }
                ),
                "{label}"
            );
            assert_eq!(
                Some(expected),
                python_module_export_unmutated_bounded(root, &source, "Base", || true),
                "{label}: complete-module export uses the same event proof"
            );
            for allowance in 0..visits {
                let mut remaining = allowance;
                assert_eq!(
                    None,
                    python_module_binding_unmutated_at_bounded(
                        root,
                        &source,
                        "Base",
                        reference,
                        || {
                            let allowed = remaining > 0;
                            remaining = remaining.saturating_sub(1);
                            allowed
                        },
                    ),
                    "{label}: stop after {allowance} of {visits} visits cannot prove no writer"
                );
            }
        }

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
