use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded;
use crate::analyzer::{Language, Range};
use crate::hash::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PythonLexicalNameResolution {
    Unbound,
    Local,
    Nonlocal,
    Global,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PythonDirectScopeBindingKind {
    ClassDeclaration,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PythonDirectScopeBinding<'tree> {
    pub(crate) declaration: Node<'tree>,
    pub(crate) kind: PythonDirectScopeBindingKind,
}

#[derive(Clone, Debug)]
struct PythonLocalBinding<'tree> {
    name: Box<str>,
    declaration: Node<'tree>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PythonLocalBindingKind {
    FunctionOnly,
    Other,
}

#[derive(Clone, Debug)]
struct PythonComprehensionBinding {
    name: Box<str>,
    start_byte: usize,
    end_byte: usize,
    enclosing_iterable_ranges: Vec<(usize, usize)>,
}

/// Function-scope Python bindings discovered from tree-sitter structure.
///
/// The inventory models Python's whole-function symbol-table behavior while
/// retaining the implicit scope of comprehension targets. Construction is
/// iterative and every inspected node is gated by `scope_step`; `None` means
/// the caller stopped discovery and must conservatively avoid module fallback.
pub(crate) struct PythonLexicalScopeInventory<'tree> {
    parameters: HashSet<Box<str>>,
    locals: Vec<PythonLocalBinding<'tree>>,
    local_names: HashMap<Box<str>, PythonLocalBindingKind>,
    globals: HashSet<Box<str>>,
    nonlocals: HashSet<Box<str>>,
    comprehensions: Vec<PythonComprehensionBinding>,
}

#[derive(Clone, Copy)]
struct ScanFrame<'tree> {
    node: Node<'tree>,
    in_comprehension: bool,
}

impl<'tree> PythonLexicalScopeInventory<'tree> {
    pub(crate) fn collect_bounded(
        callable: Node<'tree>,
        source: &str,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Self> {
        let layout = formal_parameter_slots_for_owner_bounded(
            Language::Python,
            callable,
            source,
            &node_range(callable),
            &mut scope_step,
        )?;
        let mut inventory = Self {
            parameters: layout
                .slots
                .into_iter()
                .flat_map(|slot| slot.names)
                .map(Box::<str>::from)
                .collect(),
            locals: Vec::new(),
            local_names: HashMap::default(),
            globals: HashSet::default(),
            nonlocals: HashSet::default(),
            comprehensions: Vec::new(),
        };
        let Some(body) = callable.child_by_field_name("body") else {
            return Some(inventory);
        };
        let mut stack = vec![ScanFrame {
            node: body,
            in_comprehension: false,
        }];

        while let Some(frame) = stack.pop() {
            if !scope_step() {
                return None;
            }
            let node = frame.node;
            let nested_scope = node != body
                && matches!(
                    node.kind(),
                    "function_definition" | "lambda" | "class_definition"
                );
            if nested_scope {
                if matches!(node.kind(), "function_definition" | "class_definition")
                    && let Some(name) = node.child_by_field_name("name")
                {
                    inventory.record_local_node(name, source);
                }
                // Defaults, annotations, bases, and type-parameter expressions
                // execute in an enclosing scope. Keep scanning those headers
                // for walrus/comprehension bindings while pruning the nested
                // callable or class body itself.
                push_nested_scope_header_children(
                    &mut stack,
                    node,
                    frame.in_comprehension,
                    &mut scope_step,
                )?;
                continue;
            }

            match node.kind() {
                "global_statement" => {
                    collect_direct_identifier_names(node, source, &mut scope_step, |name| {
                        inventory.globals.insert(name.into());
                    })?;
                    continue;
                }
                "nonlocal_statement" => {
                    collect_direct_identifier_names(node, source, &mut scope_step, |name| {
                        inventory.nonlocals.insert(name.into());
                    })?;
                    continue;
                }
                "import_statement" | "import_from_statement" => {
                    collect_import_bindings(node, &mut scope_step, |binding| {
                        inventory.record_local_node(binding, source)
                    })?;
                    continue;
                }
                "assignment" | "augmented_assignment" => {
                    if let Some(target) = node.child_by_field_name("left") {
                        collect_binding_targets(
                            target,
                            source,
                            &mut scope_step,
                            |name, declaration| {
                                inventory.record_local(name, declaration);
                            },
                        )?;
                    }
                }
                "type_alias_statement" => {
                    if let Some(target) = node.child_by_field_name("left")
                        && let Some(binding) = first_identifier_bounded(target, &mut scope_step)?
                    {
                        inventory.record_local_node(binding, source);
                    }
                }
                "named_expression" => {
                    // PEP 572 binds a comprehension walrus in the containing
                    // non-comprehension scope, so this remains a function local.
                    if let Some(target) = node.child_by_field_name("name") {
                        collect_binding_targets(
                            target,
                            source,
                            &mut scope_step,
                            |name, declaration| {
                                inventory.record_local(name, declaration);
                            },
                        )?;
                    }
                }
                "for_statement" => {
                    if let Some(target) = node.child_by_field_name("left") {
                        collect_binding_targets(
                            target,
                            source,
                            &mut scope_step,
                            |name, declaration| {
                                inventory.record_local(name, declaration);
                            },
                        )?;
                    }
                }
                "for_in_clause" => {
                    // These occur inside comprehensions and belong to their
                    // implicit scope. The enclosing comprehension records them.
                }
                "delete_statement" => {
                    for target in named_children_bounded(node, &mut scope_step)? {
                        collect_binding_targets(
                            target,
                            source,
                            &mut scope_step,
                            |name, declaration| {
                                inventory.record_local(name, declaration);
                            },
                        )?;
                    }
                    continue;
                }
                "as_pattern" => {
                    if let Some(alias) = node.child_by_field_name("alias") {
                        collect_binding_targets(
                            alias,
                            source,
                            &mut scope_step,
                            |name, declaration| {
                                inventory.record_local(name, declaration);
                            },
                        )?;
                        push_named_children_except(
                            &mut stack,
                            node,
                            alias,
                            frame.in_comprehension,
                            &mut scope_step,
                        )?;
                        continue;
                    }
                }
                "except_clause" => {
                    // Older grammar shapes expose the alias directly. Current
                    // tree-sitter-python nests it in an `as_pattern`, handled
                    // above when the clause's children are scanned.
                    if let Some(alias) = node.child_by_field_name("alias") {
                        collect_binding_targets(
                            alias,
                            source,
                            &mut scope_step,
                            |name, declaration| {
                                inventory.record_local(name, declaration);
                            },
                        )?;
                    }
                }
                "case_clause" => {
                    let children = named_children_bounded(node, &mut scope_step)?;
                    for child in children.iter().copied() {
                        if child.kind() == "case_pattern" {
                            collect_match_pattern_bindings(
                                child,
                                source,
                                &mut scope_step,
                                |name, declaration| {
                                    inventory.record_local(name, declaration);
                                },
                            )?;
                        }
                    }
                    for child in children.into_iter().rev() {
                        if child.kind() != "case_pattern" {
                            stack.push(ScanFrame {
                                node: child,
                                in_comprehension: frame.in_comprehension,
                            });
                        }
                    }
                    continue;
                }
                kind if is_comprehension(kind) => {
                    let range = (node.start_byte(), node.end_byte());
                    let children = named_children_bounded(node, &mut scope_step)?;
                    let enclosing_iterable_ranges = if let Some(first_clause) = children
                        .iter()
                        .copied()
                        .find(|child| child.kind() == "for_in_clause")
                    {
                        children_by_field_name_bounded(first_clause, "right", &mut scope_step)?
                            .into_iter()
                            .map(|iterable| (iterable.start_byte(), iterable.end_byte()))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    for clause in children
                        .iter()
                        .copied()
                        .filter(|child| child.kind() == "for_in_clause")
                    {
                        if let Some(target) = clause.child_by_field_name("left") {
                            collect_binding_targets(target, source, &mut scope_step, |name, _| {
                                inventory.comprehensions.push(PythonComprehensionBinding {
                                    name: name.into(),
                                    start_byte: range.0,
                                    end_byte: range.1,
                                    enclosing_iterable_ranges: enclosing_iterable_ranges.clone(),
                                });
                            })?;
                        }
                    }
                    for child in children.into_iter().rev() {
                        stack.push(ScanFrame {
                            node: child,
                            in_comprehension: true,
                        });
                    }
                    continue;
                }
                _ => {}
            }

            push_named_children(&mut stack, node, frame.in_comprehension, &mut scope_step)?;
        }

        // `global` and `nonlocal` are whole-function directives regardless of
        // source order. Neither declaration may become a semantic local.
        inventory.locals.retain(|binding| {
            !inventory.globals.contains(binding.name.as_ref())
                && !inventory.nonlocals.contains(binding.name.as_ref())
        });
        inventory.local_names.retain(|name, _| {
            !inventory.globals.contains(name.as_ref())
                && !inventory.nonlocals.contains(name.as_ref())
        });
        Some(inventory)
    }

    pub(crate) fn name_resolution_at(
        &self,
        name: &str,
        reference: Node<'_>,
    ) -> PythonLexicalNameResolution {
        let reference_byte = reference.start_byte();
        if self.comprehensions.iter().any(|binding| {
            binding.name.as_ref() == name
                && binding.start_byte <= reference_byte
                && reference_byte < binding.end_byte
                && !binding
                    .enclosing_iterable_ranges
                    .iter()
                    .any(|(start, end)| *start <= reference_byte && reference_byte < *end)
        }) {
            return PythonLexicalNameResolution::Local;
        }
        if self.nonlocals.contains(name) {
            return PythonLexicalNameResolution::Nonlocal;
        }
        if self.globals.contains(name) {
            return PythonLexicalNameResolution::Global;
        }
        if self.parameters.contains(name) || self.local_names.contains_key(name) {
            PythonLexicalNameResolution::Local
        } else {
            PythonLexicalNameResolution::Unbound
        }
    }

    pub(crate) fn resolves_to_local_function(&self, name: &str, reference: Node<'_>) -> bool {
        let reference_byte = reference.start_byte();
        !self.parameters.contains(name)
            && !self.comprehensions.iter().any(|binding| {
                binding.name.as_ref() == name
                    && binding.start_byte <= reference_byte
                    && reference_byte < binding.end_byte
                    && !binding
                        .enclosing_iterable_ranges
                        .iter()
                        .any(|(start, end)| *start <= reference_byte && reference_byte < *end)
            })
            && self.local_names.get(name) == Some(&PythonLocalBindingKind::FunctionOnly)
    }

    pub(crate) fn local_function_declaration(
        &self,
        name: &str,
        reference: Node<'_>,
    ) -> Option<Node<'tree>> {
        self.resolves_to_local_function(name, reference)
            .then(|| {
                self.locals
                    .iter()
                    .find(|binding| binding.name.as_ref() == name)
                    .and_then(|binding| binding.declaration.parent())
                    .filter(|declaration| declaration.kind() == "function_definition")
            })
            .flatten()
    }

    pub(crate) fn local_bindings(&self) -> impl Iterator<Item = (&str, Node<'tree>)> + '_ {
        self.locals
            .iter()
            .map(|binding| (binding.name.as_ref(), binding.declaration))
    }

    fn record_local_node(&mut self, node: Node<'tree>, source: &str) {
        let name = node_text(node, source);
        self.record_local(name, node);
    }

    fn record_local(&mut self, name: &str, declaration: Node<'tree>) {
        if name.is_empty() {
            return;
        }
        let binding_kind = if is_function_declaration_name(declaration) {
            PythonLocalBindingKind::FunctionOnly
        } else {
            PythonLocalBindingKind::Other
        };
        match self.local_names.entry(name.into()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(binding_kind);
                self.locals.push(PythonLocalBinding {
                    name: name.into(),
                    declaration,
                });
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(PythonLocalBindingKind::Other);
            }
        }
    }
}

fn is_function_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "function_definition"
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id())
    })
}

/// Return the bindings introduced directly by `node`.
///
/// Descendant traversal remains the caller's responsibility. This lets the
/// semantic file walk build a module binding inventory without adding a
/// second whole-file scan, while reusing the same structured target handling
/// as function symbol-table discovery.
pub(crate) fn python_direct_scope_bindings_bounded<'tree>(
    node: Node<'tree>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Vec<PythonDirectScopeBinding<'tree>>> {
    let mut bindings = Vec::new();

    match node.kind() {
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                bindings.push(PythonDirectScopeBinding {
                    declaration: name,
                    kind: PythonDirectScopeBindingKind::Other,
                });
            }
        }
        "class_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                bindings.push(PythonDirectScopeBinding {
                    declaration: name,
                    kind: if is_direct_module_definition_bounded(node, &mut scope_step)? {
                        PythonDirectScopeBindingKind::ClassDeclaration
                    } else {
                        PythonDirectScopeBindingKind::Other
                    },
                });
            }
        }
        "import_statement" | "import_from_statement" => {
            collect_import_bindings(node, &mut scope_step, |declaration| {
                bindings.push(PythonDirectScopeBinding {
                    declaration,
                    kind: PythonDirectScopeBindingKind::Other,
                });
            })?;
        }
        "assignment" | "augmented_assignment" => {
            if let Some(target) = node.child_by_field_name("left") {
                collect_binding_targets(target, source, &mut scope_step, |_, declaration| {
                    bindings.push(PythonDirectScopeBinding {
                        declaration,
                        kind: PythonDirectScopeBindingKind::Other,
                    });
                })?;
            }
        }
        "type_alias_statement" => {
            if let Some(target) = node.child_by_field_name("left")
                && let Some(declaration) = first_identifier_bounded(target, &mut scope_step)?
            {
                bindings.push(PythonDirectScopeBinding {
                    declaration,
                    kind: PythonDirectScopeBindingKind::Other,
                });
            }
        }
        "named_expression" => {
            if let Some(target) = node.child_by_field_name("name") {
                collect_binding_targets(target, source, &mut scope_step, |_, declaration| {
                    bindings.push(PythonDirectScopeBinding {
                        declaration,
                        kind: PythonDirectScopeBindingKind::Other,
                    });
                })?;
            }
        }
        "for_statement" => {
            if let Some(target) = node.child_by_field_name("left") {
                collect_binding_targets(target, source, &mut scope_step, |_, declaration| {
                    bindings.push(PythonDirectScopeBinding {
                        declaration,
                        kind: PythonDirectScopeBindingKind::Other,
                    });
                })?;
            }
        }
        "delete_statement" => {
            for target in named_children_bounded(node, &mut scope_step)? {
                collect_binding_targets(target, source, &mut scope_step, |_, declaration| {
                    bindings.push(PythonDirectScopeBinding {
                        declaration,
                        kind: PythonDirectScopeBindingKind::Other,
                    });
                })?;
            }
        }
        "as_pattern" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                collect_binding_targets(alias, source, &mut scope_step, |_, declaration| {
                    bindings.push(PythonDirectScopeBinding {
                        declaration,
                        kind: PythonDirectScopeBindingKind::Other,
                    });
                })?;
            }
        }
        "except_clause" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                collect_binding_targets(alias, source, &mut scope_step, |_, declaration| {
                    bindings.push(PythonDirectScopeBinding {
                        declaration,
                        kind: PythonDirectScopeBindingKind::Other,
                    });
                })?;
            }
        }
        "case_clause" => {
            for child in named_children_bounded(node, &mut scope_step)? {
                if child.kind() == "case_pattern" {
                    collect_match_pattern_bindings(
                        child,
                        source,
                        &mut scope_step,
                        |_, declaration| {
                            bindings.push(PythonDirectScopeBinding {
                                declaration,
                                kind: PythonDirectScopeBindingKind::Other,
                            });
                        },
                    )?;
                }
            }
        }
        _ => {}
    }
    Some(bindings)
}

pub(crate) fn python_unambiguous_module_class_binding_bounded(
    root: Node<'_>,
    source: &str,
    target_name: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    let mut matched = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        for binding in python_direct_scope_bindings_bounded(node, source, &mut scope_step)? {
            if node_text(binding.declaration, source) != target_name {
                continue;
            }
            if matched.is_some() {
                return Some(false);
            }
            matched = Some(binding.kind);
            if binding.kind == PythonDirectScopeBindingKind::Other {
                return Some(false);
            }
        }

        let body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|child| child.id()))
        .flatten();
        let name = matches!(node.kind(), "function_definition" | "class_definition")
            .then(|| node.child_by_field_name("name").map(|child| child.id()))
            .flatten();
        for child in named_children_bounded(node, &mut scope_step)?
            .into_iter()
            .filter(|child| Some(child.id()) != body && Some(child.id()) != name)
            .rev()
        {
            stack.push(child);
        }
    }
    Some(matched == Some(PythonDirectScopeBindingKind::ClassDeclaration))
}

fn is_direct_module_definition_bounded(
    node: Node<'_>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<bool> {
    if !scope_step() {
        return None;
    }
    let Some(mut parent) = node.parent() else {
        return Some(false);
    };
    if parent.kind() == "decorated_definition" {
        if !scope_step() {
            return None;
        }
        let Some(grandparent) = parent.parent() else {
            return Some(false);
        };
        parent = grandparent;
    }
    Some(parent.kind() == "module")
}

fn collect_direct_identifier_names(
    node: Node<'_>,
    source: &str,
    scope_step: &mut impl FnMut() -> bool,
    mut record: impl FnMut(&str),
) -> Option<()> {
    for child in named_children_bounded(node, scope_step)? {
        if child.kind() == "identifier" {
            let name = node_text(child, source);
            if !name.is_empty() {
                record(name);
            }
        }
    }
    Some(())
}

fn collect_import_bindings<'tree>(
    statement: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
    mut record: impl FnMut(Node<'tree>),
) -> Option<()> {
    let mut cursor = statement.walk();
    let mut imports = Vec::new();
    for imported in statement.children_by_field_name("name", &mut cursor) {
        if !scope_step() {
            return None;
        }
        imports.push(imported);
    }
    for imported in imports {
        if let Some(alias) = imported.child_by_field_name("alias") {
            record(alias);
            continue;
        }
        let name = imported.child_by_field_name("name").unwrap_or(imported);
        let binding = if statement.kind() == "import_statement" {
            first_identifier_bounded(name, scope_step)?
        } else {
            last_identifier_bounded(name, scope_step)?
        };
        if let Some(binding) = binding {
            record(binding);
        }
    }
    Some(())
}

fn first_identifier_bounded<'tree>(
    root: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Option<Node<'tree>>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if node.kind() == "identifier" {
            return Some(Some(node));
        }
        let children = named_children_bounded(node, scope_step)?;
        stack.extend(children.into_iter().rev());
    }
    Some(None)
}

fn last_identifier_bounded<'tree>(
    root: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Option<Node<'tree>>> {
    let mut result = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if node.kind() == "identifier" {
            result = Some(node);
            continue;
        }
        let children = named_children_bounded(node, scope_step)?;
        stack.extend(children.into_iter().rev());
    }
    Some(result)
}

fn collect_binding_targets<'tree>(
    target: Node<'tree>,
    source: &str,
    scope_step: &mut impl FnMut() -> bool,
    mut record: impl FnMut(&str, Node<'tree>),
) -> Option<()> {
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        match node.kind() {
            // These mutate an existing object and do not bind either the
            // receiver or member name in the function.
            "attribute" | "subscript" => continue,
            "identifier" | "keyword_identifier" => {
                let name = node_text(node, source);
                if !name.is_empty() {
                    record(name, node);
                }
                continue;
            }
            _ => {}
        }
        let children = named_children_bounded(node, scope_step)?;
        if node.kind() == "as_pattern_target" && children.is_empty() {
            let name = node_text(node, source);
            if !name.is_empty() {
                record(name, node);
            }
            continue;
        }
        stack.extend(children.into_iter().rev());
    }
    Some(())
}

fn collect_match_pattern_bindings<'tree>(
    pattern: Node<'tree>,
    source: &str,
    scope_step: &mut impl FnMut() -> bool,
    mut record: impl FnMut(&str, Node<'tree>),
) -> Option<()> {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        match node.kind() {
            "dotted_name" => {
                let identifiers = named_children_bounded(node, scope_step)?
                    .into_iter()
                    .filter(|child| child.kind() == "identifier")
                    .collect::<Vec<_>>();
                if let [binding] = identifiers.as_slice() {
                    let name = node_text(*binding, source);
                    if !name.is_empty() {
                        record(name, *binding);
                    }
                }
                continue;
            }
            "splat_pattern" => {
                for child in named_children_bounded(node, scope_step)? {
                    if child.kind() == "identifier" {
                        let name = node_text(child, source);
                        if !name.is_empty() {
                            record(name, child);
                        }
                    }
                }
                continue;
            }
            "class_pattern" => {
                let mut children = named_children_bounded(node, scope_step)?;
                if children
                    .first()
                    .is_some_and(|child| child.kind() == "dotted_name")
                {
                    children.remove(0);
                }
                stack.extend(children.into_iter().rev());
                continue;
            }
            "keyword_pattern" => {
                let mut children = named_children_bounded(node, scope_step)?;
                if children
                    .first()
                    .is_some_and(|child| child.kind() == "identifier")
                {
                    children.remove(0);
                }
                stack.extend(children.into_iter().rev());
                continue;
            }
            "dict_pattern" => {
                let key_ids = children_by_field_name_bounded(node, "key", scope_step)?
                    .into_iter()
                    .map(|key| key.id())
                    .collect::<HashSet<_>>();
                let children = named_children_bounded(node, scope_step)?;
                stack.extend(
                    children
                        .into_iter()
                        .filter(|child| !key_ids.contains(&child.id()))
                        .rev(),
                );
                continue;
            }
            "as_pattern" => {
                if let Some(alias) = node.child_by_field_name("alias") {
                    collect_binding_targets(alias, source, scope_step, &mut record)?;
                    let children = named_children_bounded(node, scope_step)?;
                    stack.extend(
                        children
                            .into_iter()
                            .filter(|child| child.id() != alias.id())
                            .rev(),
                    );
                    continue;
                }
                let mut children = named_children_bounded(node, scope_step)?;
                if let Some(alias) = children
                    .last()
                    .copied()
                    .filter(|child| child.kind() == "identifier")
                {
                    let name = node_text(alias, source);
                    if !name.is_empty() {
                        record(name, alias);
                    }
                    children.pop();
                }
                stack.extend(children.into_iter().rev());
                continue;
            }
            "identifier" => {
                // Direct identifiers are match `as` aliases handled by their
                // parent. Keyword names and class heads are likewise skipped.
                continue;
            }
            kind if is_pattern_literal(kind) => continue,
            _ => {}
        }
        let children = named_children_bounded(node, scope_step)?;
        stack.extend(children.into_iter().rev());
    }
    Some(())
}

fn push_named_children<'tree>(
    stack: &mut Vec<ScanFrame<'tree>>,
    node: Node<'tree>,
    in_comprehension: bool,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    for child in named_children_bounded(node, scope_step)?.into_iter().rev() {
        stack.push(ScanFrame {
            node: child,
            in_comprehension,
        });
    }
    Some(())
}

fn push_named_children_except<'tree>(
    stack: &mut Vec<ScanFrame<'tree>>,
    node: Node<'tree>,
    excluded: Node<'tree>,
    in_comprehension: bool,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    for child in named_children_bounded(node, scope_step)?
        .into_iter()
        .filter(|child| child.id() != excluded.id())
        .rev()
    {
        stack.push(ScanFrame {
            node: child,
            in_comprehension,
        });
    }
    Some(())
}

fn push_nested_scope_header_children<'tree>(
    stack: &mut Vec<ScanFrame<'tree>>,
    node: Node<'tree>,
    in_comprehension: bool,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let body = node.child_by_field_name("body").map(|child| child.id());
    let name = node.child_by_field_name("name").map(|child| child.id());
    for child in named_children_bounded(node, scope_step)?
        .into_iter()
        .filter(|child| Some(child.id()) != body && Some(child.id()) != name)
        .rev()
    {
        stack.push(ScanFrame {
            node: child,
            in_comprehension,
        });
    }
    Some(())
}

fn named_children_bounded<'tree>(
    node: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Vec<Node<'tree>>> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    for child in node.named_children(&mut cursor) {
        if !scope_step() {
            return None;
        }
        children.push(child);
    }
    Some(children)
}

fn children_by_field_name_bounded<'tree>(
    node: Node<'tree>,
    field: &str,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Vec<Node<'tree>>> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    for child in node.children_by_field_name(field, &mut cursor) {
        if !scope_step() {
            return None;
        }
        children.push(child);
    }
    Some(children)
}

fn is_comprehension(kind: &str) -> bool {
    matches!(
        kind,
        "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression"
    )
}

fn is_pattern_literal(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "concatenated_string"
            | "integer"
            | "float"
            | "complex_pattern"
            | "true"
            | "false"
            | "none"
    )
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text_trimmed(node, source)
}
