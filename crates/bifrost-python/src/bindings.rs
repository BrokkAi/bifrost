use brokk_bifrost_core::analyzer::common::node_source_text_trimmed as node_text;
use brokk_bifrost_core::analyzer::tree_walk::{named_children_iter, push_bounded_nodes};
use tree_sitter::Node;

use brokk_bifrost_core::hash::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PythonLexicalNameResolution {
    Unbound,
    Local,
    Nonlocal,
    Global,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PythonDirectScopeBindingKind {
    ClassDeclaration,
    FunctionDeclaration,
    Import,
    Other,
}

/// Whether `reference` reads a target introduced by an enclosing comprehension.
///
/// Comprehensions create an implicit scope even at module level. The element
/// expression is textually before its `for` clauses but evaluates after their
/// binders. Only the first iterable evaluates in the enclosing scope; later
/// iterables use comprehension-local names, including not-yet-bound targets.
/// This structured walk models those scopes without source-text parsing.
pub fn python_comprehension_binds_name_at(name: &str, reference: Node<'_>, source: &str) -> bool {
    python_comprehension_binds_name_at_bounded(name, reference, source, || true)
        .expect("unbounded comprehension binding lookup completes")
}

/// The same scope proof under the caller's work/cancellation ledger.
/// An interrupted walk must not be interpreted as an unbound name.
pub fn python_comprehension_binds_name_at_bounded(
    name: &str,
    reference: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    if !scope_step() {
        return None;
    }
    let mut current = reference;
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        if is_comprehension(parent.kind()) {
            let mut cursor = parent.walk();
            let mut clauses = Vec::new();
            for child in parent.named_children(&mut cursor) {
                if !scope_step() {
                    return None;
                }
                if child.kind() == "for_in_clause" {
                    clauses.push(child);
                }
            }
            let mut in_outer_iterable = false;
            if let Some(clause) = clauses.first() {
                let mut cursor = clause.walk();
                for right in clause.children_by_field_name("right", &mut cursor) {
                    if !scope_step() {
                        return None;
                    }
                    if right.start_byte() <= reference.start_byte()
                        && reference.end_byte() <= right.end_byte()
                    {
                        in_outer_iterable = true;
                        break;
                    }
                }
            }
            if in_outer_iterable {
                current = parent;
                continue;
            }
            for clause in clauses {
                if !scope_step() {
                    return None;
                }
                let Some(target) = clause.child_by_field_name("left") else {
                    continue;
                };
                let mut bound = false;
                collect_binding_targets(target, source, &mut scope_step, |candidate, _| {
                    bound |= candidate == name;
                })?;
                if bound {
                    return Some(true);
                }
            }
        }
        if matches!(
            parent.kind(),
            "function_definition" | "lambda" | "class_definition" | "module"
        ) {
            break;
        }
        current = parent;
    }
    Some(false)
}

/// Whether `reference` reads a PEP 695 type parameter declared by its enclosing
/// class, function, or type-alias definition.
///
/// Type parameters are lexical bindings rather than indexed workspace
/// declarations. The binder is the first identifier in each structured
/// parameter node; identifiers in bounds and constraints remain references.
pub fn python_type_parameter_binds_name_at(name: &str, reference: Node<'_>, source: &str) -> bool {
    python_type_parameter_binds_name_at_bounded(name, reference, source, || true)
        .expect("unbounded type parameter lookup completes")
}

/// The shared type-parameter proof under the caller's live work budget.
/// An interrupted ancestor, binder, or directive walk supplies no answer.
pub fn python_type_parameter_binds_name_at_bounded(
    name: &str,
    reference: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    let mut current = reference;
    let mut enclosing_functions = Vec::new();
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        if parent.kind() == "function_definition" {
            enclosing_functions.push(parent);
        }
        if matches!(
            parent.kind(),
            "class_definition" | "function_definition" | "type_alias_statement"
        ) && let Some(parameters) = parent.child_by_field_name("type_parameters")
            && !(parameters.start_byte() <= reference.start_byte()
                && reference.end_byte() <= parameters.end_byte())
        {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if !scope_step() {
                    return None;
                }
                let binder = first_identifier_bounded(parameter, &mut scope_step)?;
                if binder.is_some_and(|binder| node_text(binder, source) == name) {
                    // Preserve the existing function-wide directive precedence.
                    return Some(
                        python_name_resolution_at_in_functions_bounded(
                            name,
                            reference,
                            source,
                            enclosing_functions,
                            &mut scope_step,
                        )? != PythonLexicalNameResolution::Global,
                    );
                }
            }
        }
        current = parent;
    }
    Some(false)
}

/// Resolve `name` through the nearest enclosing function scope. This is the
/// structured fallback for references inside nested functions that do not
/// have their own indexed `CodeUnit` scope snapshot.
pub fn python_name_resolution_at(
    name: &str,
    reference: Node<'_>,
    source: &str,
) -> PythonLexicalNameResolution {
    let mut functions = Vec::new();
    let mut current = reference;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            functions.push(parent);
        }
        current = parent;
    }
    python_name_resolution_at_in_functions(name, reference, source, functions)
}

fn python_name_resolution_at_in_functions(
    name: &str,
    reference: Node<'_>,
    source: &str,
    functions: Vec<Node<'_>>,
) -> PythonLexicalNameResolution {
    python_name_resolution_at_in_functions_bounded(name, reference, source, functions, || true)
        .expect("unbounded function binding lookup completes")
}

fn python_name_resolution_at_in_functions_bounded(
    name: &str,
    reference: Node<'_>,
    source: &str,
    functions: Vec<Node<'_>>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonLexicalNameResolution> {
    for function in functions {
        if !scope_step() {
            return None;
        }
        let mut parameter_names = Vec::new();
        if let Some(parameters) = function.child_by_field_name("parameters") {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if !scope_step() {
                    return None;
                }
                if let Some(name) = crate::syntax::python_parameter_name_bounded(
                    parameter,
                    source,
                    &mut scope_step,
                )? {
                    parameter_names.push(name);
                }
            }
        }
        let inventory = PythonLexicalScopeInventory::collect_bounded(
            function,
            source,
            parameter_names,
            &mut scope_step,
        )?;
        let resolution = inventory.name_resolution_at_bounded(name, reference, &mut scope_step)?;
        match resolution {
            PythonLexicalNameResolution::Global
            | PythonLexicalNameResolution::Local
            | PythonLexicalNameResolution::Nonlocal => return Some(resolution),
            PythonLexicalNameResolution::Unbound => {}
        }
    }
    Some(PythonLexicalNameResolution::Unbound)
}

/// Whether this identifier is the binder (rather than a bound/constraint use)
/// of one structured PEP 695 type parameter.
pub fn python_is_type_parameter_binder(node: Node<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "function_definition" | "type_alias_statement"
        ) && let Some(parameters) = parent.child_by_field_name("type_parameters")
            && parameters.start_byte() <= node.start_byte()
            && node.end_byte() <= parameters.end_byte()
        {
            let mut cursor = parameters.walk();
            return parameters.named_children(&mut cursor).any(|parameter| {
                let binder = python_type_parameter_binder_node(parameter);
                binder.is_some_and(|binder| binder.id() == node.id())
            });
        }
        if matches!(
            parent.kind(),
            "module" | "class_definition" | "function_definition" | "type_alias_statement"
        ) {
            return false;
        }
        current = parent;
    }
    false
}

fn python_type_parameter_binder_node(parameter: Node<'_>) -> Option<Node<'_>> {
    if parameter.kind() == "identifier" {
        Some(parameter)
    } else {
        first_identifier_bounded(parameter, &mut || true).flatten()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PythonDirectScopeBinding<'tree> {
    pub declaration: Node<'tree>,
    pub kind: PythonDirectScopeBindingKind,
}

#[derive(Clone, Debug)]
struct PythonLocalBinding<'tree> {
    name: Box<str>,
    declaration: Node<'tree>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PythonLocalBindingKind {
    FunctionOnly,
    ClassOnly,
    ImportOnly,
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
pub struct PythonLexicalScopeInventory<'tree> {
    binding_nodes: Vec<Node<'tree>>,
    locals: Vec<PythonLocalBinding<'tree>>,
    bindings: PythonLexicalScopeBindings,
}

/// Completed function binding facts without borrowed tree-sitter nodes.
/// Retain these only under the identity of the exact source that produced them.
pub struct PythonLexicalScopeBindings {
    parameters: HashSet<Box<str>>,
    local_names: HashMap<Box<str>, PythonLocalBindingKind>,
    binding_writes: HashSet<Box<str>>,
    // Real binding events retained before global declarations leave locals.
    global_binding_events: HashSet<Box<str>>,
    globals: HashSet<Box<str>>,
    nonlocals: HashSet<Box<str>>,
    comprehensions: Vec<PythonComprehensionBinding>,
}

impl PythonLexicalScopeBindings {
    pub fn name_resolution_at(
        &self,
        name: &str,
        reference: Node<'_>,
    ) -> PythonLexicalNameResolution {
        self.name_resolution_at_bounded(name, reference, || true)
            .expect("unbounded lexical name lookup completes")
    }

    /// Resolve a read while charging every comprehension binding and iterable
    /// range inspected. Exhaustion is distinct from an unbound name.
    pub fn name_resolution_at_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<PythonLexicalNameResolution> {
        if !scope_step() {
            return None;
        }
        if self.comprehension_binds_name_at_bounded(name, reference, &mut scope_step)? {
            return Some(PythonLexicalNameResolution::Local);
        }
        Some(if self.nonlocals.contains(name) {
            PythonLexicalNameResolution::Nonlocal
        } else if self.globals.contains(name) {
            PythonLexicalNameResolution::Global
        } else if self.parameters.contains(name) || self.local_names.contains_key(name) {
            PythonLexicalNameResolution::Local
        } else {
            PythonLexicalNameResolution::Unbound
        })
    }

    fn comprehension_binds_name_at_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        let reference_byte = reference.start_byte();
        for binding in &self.comprehensions {
            if !scope_step() {
                return None;
            }
            if binding.name.as_ref() == name
                && binding.start_byte <= reference_byte
                && reference_byte < binding.end_byte
            {
                let mut in_outer_iterable = false;
                for (start, end) in &binding.enclosing_iterable_ranges {
                    if !scope_step() {
                        return None;
                    }
                    in_outer_iterable |= *start <= reference_byte && reference_byte < *end;
                }
                if !in_outer_iterable {
                    return Some(true);
                }
            }
        }
        Some(false)
    }

    /// A directive alone is not an event. Declarations, imports, assignments,
    /// and every other collected binder/delete count, without value inference.
    pub fn has_global_binding_event(&self, name: &str) -> bool {
        self.global_binding_events.contains(name)
    }

    /// All actual global binding events, before any read-time filtering.
    /// Callers that copy this set must charge their own bounded iteration.
    pub fn global_binding_events(&self) -> impl Iterator<Item = &str> {
        self.global_binding_events.iter().map(|name| name.as_ref())
    }

    pub fn resolves_to_local_function_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        if !scope_step() {
            return None;
        }
        Some(
            !self.parameters.contains(name)
                && !self.comprehension_binds_name_at_bounded(name, reference, &mut scope_step)?
                && self.local_names.get(name) == Some(&PythonLocalBindingKind::FunctionOnly),
        )
    }

    /// Whether the active callable obtains `name` from a runtime binding
    /// rather than an untouched function or import declaration.
    pub fn has_runtime_callable_binding_at(&self, name: &str, reference: Node<'_>) -> bool {
        self.has_runtime_callable_binding_at_bounded(name, reference, || true)
            .expect("unbounded runtime binding lookup completes")
    }

    pub fn has_runtime_callable_binding_at_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        if !scope_step() {
            return None;
        }
        Some(
            self.parameters.contains(name)
                || self.binding_writes.contains(name)
                || self.comprehension_binds_name_at_bounded(name, reference, &mut scope_step)?,
        )
    }
}

/// Binding events in an executing class namespace at one reference. Only a
/// proved static superclass path precedes that class statement's name binding.
/// Lazy type-parameter expressions and other header contexts keep that event.
/// Other events retain the existing whole-scope conservative interpretation.
pub struct PythonClassReferenceScope<'tree> {
    scope: Node<'tree>,
    pending_name: Option<Node<'tree>>,
}

impl<'tree> PythonClassReferenceScope<'tree> {
    pub fn new_bounded(
        scope: Node<'tree>,
        reference: Node<'tree>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Self> {
        assert_eq!(scope.kind(), "class_definition");
        let mut current = reference;
        let mut pending_name = None;
        while current != scope {
            if !scope_step() {
                return None;
            }
            if current.kind() == "class_definition"
                && let Some(superclasses) = current.child_by_field_name("superclasses")
            {
                for expression in named_children_iter(superclasses) {
                    if !scope_step() {
                        return None;
                    }
                    if expression.start_byte() <= reference.start_byte()
                        && reference.end_byte() <= expression.end_byte()
                        && let Some(path) = crate::syntax::python_static_value_path_bounded(
                            expression,
                            &mut scope_step,
                        )?
                        && (path.first().copied() == Some(reference) || expression == reference)
                    {
                        pending_name = Some(current.child_by_field_name("name")?);
                    }
                }
            }
            current = current.parent()?;
        }
        Some(Self {
            scope,
            pending_name,
        })
    }

    fn includes_binding(&self, declaration: Node<'tree>) -> bool {
        Some(declaration) != self.pending_name
    }

    pub fn collect_bounded(
        &self,
        source: &str,
        scope_step: impl FnMut() -> bool,
    ) -> Option<PythonLexicalScopeInventory<'tree>> {
        PythonLexicalScopeInventory::collect_with_declaration_filter_bounded(
            self.scope,
            source,
            std::iter::empty::<String>(),
            |declaration| self.includes_binding(declaration),
            scope_step,
        )
    }

    pub fn binds_name_bounded(
        &self,
        name: &str,
        source: &str,
        scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        python_scope_binds_name_with_filter_bounded(
            self.scope,
            name,
            source,
            |declaration| self.includes_binding(declaration),
            scope_step,
        )
    }
}

impl<'tree> PythonLexicalScopeInventory<'tree> {
    /// `parameter_names` is the callable's formal-parameter name stream. The
    /// layout it comes from is resolved by `analyzer/lexical_definitions.rs`,
    /// which dispatches through the analysis-side language registry and so
    /// cannot be named here; `analyzer/python/lexical_scope.rs` in
    /// `brokk-bifrost-analysis` is the one caller that computes it, under the
    /// same `scope_step` meter this walk uses.
    pub fn collect_bounded(
        callable: Node<'tree>,
        source: &str,
        parameter_names: impl IntoIterator<Item = String>,
        scope_step: impl FnMut() -> bool,
    ) -> Option<Self> {
        Self::collect_with_declaration_filter_bounded(
            callable,
            source,
            parameter_names,
            |_| true,
            scope_step,
        )
    }

    fn collect_with_declaration_filter_bounded(
        callable: Node<'tree>,
        source: &str,
        parameter_names: impl IntoIterator<Item = String>,
        include_declaration: impl Fn(Node<'tree>) -> bool,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Self> {
        let mut inventory = Self {
            binding_nodes: Vec::new(),
            locals: Vec::new(),
            bindings: PythonLexicalScopeBindings {
                parameters: parameter_names.into_iter().map(Box::<str>::from).collect(),
                local_names: HashMap::default(),
                binding_writes: HashSet::default(),
                global_binding_events: HashSet::default(),
                globals: HashSet::default(),
                nonlocals: HashSet::default(),
                comprehensions: Vec::new(),
            },
        };
        // Recovery can replace the module grammar node with an ERROR root.
        // Its declarations still belong to the source file's module scope.
        let module_scope = callable.parent().is_none();
        let body = if module_scope {
            callable
        } else if let Some(body) = callable.child_by_field_name("body") {
            body
        } else {
            return Some(inventory);
        };
        let mut stack = vec![body];

        while let Some(node) = stack.pop() {
            if !scope_step() {
                return None;
            }
            let nested_scope = node != body
                && matches!(
                    node.kind(),
                    "function_definition" | "lambda" | "class_definition"
                );
            if nested_scope {
                if matches!(node.kind(), "function_definition" | "class_definition")
                    && let Some(name) = node.child_by_field_name("name")
                    && include_declaration(name)
                {
                    inventory.record_local_node(name, source);
                }
                // Defaults, annotations, bases, and type-parameter expressions
                // execute in an enclosing scope. Keep scanning those headers
                // for walrus/comprehension bindings while pruning the nested
                // callable or class body itself.
                push_nested_scope_header_children(&mut stack, node, &mut scope_step)?;
                continue;
            }

            match node.kind() {
                "global_statement" => {
                    if module_scope {
                        continue;
                    }
                    collect_direct_identifier_names(node, source, &mut scope_step, |name| {
                        inventory.bindings.globals.insert(name.into());
                    })?;
                    continue;
                }
                "nonlocal_statement" => {
                    collect_direct_identifier_names(node, source, &mut scope_step, |name| {
                        inventory.bindings.nonlocals.insert(name.into());
                    })?;
                    continue;
                }
                "import_statement" | "import_from_statement" => {
                    collect_import_bindings(node, &mut scope_step, |binding| {
                        inventory.record_local_kind(
                            node_text(binding, source),
                            binding,
                            PythonLocalBindingKind::ImportOnly,
                        )
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
                                inventory.record_binding_write(name, declaration);
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
                                inventory.record_binding_write(name, declaration);
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
                                inventory.record_binding_write(name, declaration);
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
                                inventory.record_binding_write(name, declaration);
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
                                inventory.record_binding_write(name, declaration);
                            },
                        )?;
                        push_named_children_except(&mut stack, node, alias, &mut scope_step)?;
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
                                inventory.record_binding_write(name, declaration);
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
                                    inventory.record_binding_write(name, declaration);
                                },
                            )?;
                        }
                    }
                    for child in children.into_iter().rev() {
                        if child.kind() != "case_pattern" {
                            stack.push(child);
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
                                inventory.bindings.comprehensions.push(
                                    PythonComprehensionBinding {
                                        name: name.into(),
                                        start_byte: range.0,
                                        end_byte: range.1,
                                        enclosing_iterable_ranges: enclosing_iterable_ranges
                                            .clone(),
                                    },
                                );
                            })?;
                        }
                    }
                    for child in children.into_iter().rev() {
                        stack.push(child);
                    }
                    continue;
                }
                _ => {}
            }

            push_named_children(&mut stack, node, &mut scope_step)?;
        }

        // Preserve all real global binding events before pruning semantic
        // locals, including def/class/import declarations that intentionally
        // do not belong to the runtime-callable-value predicate.
        for name in inventory.bindings.local_names.keys() {
            if !scope_step() {
                return None;
            }
            if inventory.bindings.globals.contains(name.as_ref()) {
                inventory
                    .bindings
                    .global_binding_events
                    .insert(name.clone());
            }
        }

        // `global` and `nonlocal` are whole-function directives regardless of
        // source order. Neither declaration may become a semantic local.
        inventory.locals.retain(|binding| {
            !inventory.bindings.globals.contains(binding.name.as_ref())
                && !inventory.bindings.nonlocals.contains(binding.name.as_ref())
        });
        inventory.bindings.local_names.retain(|name, _| {
            !inventory.bindings.globals.contains(name.as_ref())
                && !inventory.bindings.nonlocals.contains(name.as_ref())
        });
        Some(inventory)
    }

    pub fn into_bindings(self) -> PythonLexicalScopeBindings {
        self.bindings
    }

    pub fn name_resolution_at(
        &self,
        name: &str,
        reference: Node<'_>,
    ) -> PythonLexicalNameResolution {
        self.bindings.name_resolution_at(name, reference)
    }

    pub fn name_resolution_at_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        scope_step: impl FnMut() -> bool,
    ) -> Option<PythonLexicalNameResolution> {
        self.bindings
            .name_resolution_at_bounded(name, reference, scope_step)
    }

    pub fn has_runtime_callable_binding_at(&self, name: &str, reference: Node<'_>) -> bool {
        self.bindings
            .has_runtime_callable_binding_at(name, reference)
    }

    pub fn has_runtime_callable_binding_at_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        scope_step: impl FnMut() -> bool,
    ) -> Option<bool> {
        self.bindings
            .has_runtime_callable_binding_at_bounded(name, reference, scope_step)
    }

    pub fn local_function_declaration(
        &self,
        name: &str,
        reference: Node<'_>,
    ) -> Option<Node<'tree>> {
        self.local_function_declaration_bounded(name, reference, || true)
    }

    pub fn local_function_declaration_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Node<'tree>> {
        if !self
            .bindings
            .resolves_to_local_function_bounded(name, reference, &mut scope_step)?
        {
            return None;
        }
        for binding in &self.locals {
            if !scope_step() {
                return None;
            }
            if binding.name.as_ref() == name {
                return binding
                    .declaration
                    .parent()
                    .filter(|declaration| declaration.kind() == "function_definition");
            }
        }
        None
    }

    /// A single untouched local class declaration, not an inferred instance
    /// type. Statement ordering/containment is checked at the selected use.
    pub fn local_class_declaration_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Node<'tree>> {
        if self.name_resolution_at_bounded(name, reference, &mut scope_step)?
            != PythonLexicalNameResolution::Local
            || self.bindings.has_runtime_callable_binding_at_bounded(
                name,
                reference,
                &mut scope_step,
            )?
            || self.bindings.local_names.get(name) != Some(&PythonLocalBindingKind::ClassOnly)
        {
            return None;
        }
        for binding in &self.locals {
            if !scope_step() {
                return None;
            }
            if binding.name.as_ref() == name {
                return binding
                    .declaration
                    .parent()
                    .filter(|node| node.kind() == "class_definition");
            }
        }
        None
    }

    /// The import must be the only binding event, not merely the first
    /// retained token. Competing imports, def/class names and writes collapse
    /// ImportOnly to Other during collection, even when import metadata is absent.
    pub fn unique_import_declaration_bounded(
        &self,
        name: &str,
        reference: Node<'_>,
        mut scope_step: impl FnMut() -> bool,
    ) -> Option<Option<Node<'tree>>> {
        if self.name_resolution_at_bounded(name, reference, &mut scope_step)?
            != PythonLexicalNameResolution::Local
            || self.bindings.has_runtime_callable_binding_at_bounded(
                name,
                reference,
                &mut scope_step,
            )?
            || self.bindings.local_names.get(name) != Some(&PythonLocalBindingKind::ImportOnly)
        {
            return Some(None);
        }
        for binding in &self.locals {
            if !scope_step() {
                return None;
            }
            if binding.name.as_ref() == name {
                return Some(Some(binding.declaration));
            }
        }
        unreachable!("ImportOnly is constructed with its declaration token")
    }

    /// All binding tokens, including repeated and globally redirected writes.
    /// The native producer attributes these after the whole scope inventory exists.
    pub fn binding_nodes(&self) -> impl Iterator<Item = Node<'tree>> + '_ {
        self.binding_nodes.iter().copied()
    }

    pub fn global_names(&self) -> impl Iterator<Item = &str> {
        self.bindings.globals.iter().map(AsRef::as_ref)
    }

    pub fn nonlocal_names(&self) -> impl Iterator<Item = &str> {
        self.bindings.nonlocals.iter().map(AsRef::as_ref)
    }

    pub fn local_bindings(&self) -> impl Iterator<Item = (&str, Node<'tree>)> + '_ {
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
        } else if declaration.parent().is_some_and(|parent| {
            parent.kind() == "class_definition"
                && brokk_bifrost_core::analyzer::tree_walk::is_field_child(
                    parent,
                    declaration,
                    "name",
                )
        }) {
            PythonLocalBindingKind::ClassOnly
        } else {
            PythonLocalBindingKind::Other
        };
        self.record_local_kind(name, declaration, binding_kind);
    }

    fn record_local_kind(
        &mut self,
        name: &str,
        declaration: Node<'tree>,
        binding_kind: PythonLocalBindingKind,
    ) {
        if name.is_empty() {
            return;
        }
        self.binding_nodes.push(declaration);
        match self.bindings.local_names.entry(name.into()) {
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

    fn record_binding_write(&mut self, name: &str, declaration: Node<'tree>) {
        if !name.is_empty() {
            self.bindings.binding_writes.insert(name.into());
        }
        self.record_local(name, declaration);
    }
}

/// Prove that a selected `global` route has no known binding event in its
/// executing enclosing scopes. Outer locals are unrelated to this namespace;
/// an outer scope declaring the same global can still replace its identity.
/// Class namespaces are not captured: only explicit global events are read.
/// The caller has already selected `global_scope` by lexical precedence.
pub fn python_global_binding_is_untouched_bounded(
    name: &str,
    reference: Node<'_>,
    global_scope: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    assert!(matches!(
        global_scope.kind(),
        "function_definition" | "lambda" | "class_definition"
    ));
    let mut current = Some(global_scope);
    while let Some(scope) = current {
        if !scope_step() {
            return None;
        }
        if matches!(
            scope.kind(),
            "function_definition" | "lambda" | "class_definition"
        ) && scope.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        }) {
            let inventory = if scope.kind() == "class_definition" {
                PythonClassReferenceScope::new_bounded(scope, reference, &mut scope_step)?
                    .collect_bounded(source, &mut scope_step)?
            } else {
                PythonLexicalScopeInventory::collect_bounded(
                    scope,
                    source,
                    std::iter::empty::<String>(),
                    &mut scope_step,
                )?
            };
            if inventory.bindings.has_global_binding_event(name) {
                return Some(false);
            }
        }
        current = scope.parent();
    }
    Some(true)
}

fn is_function_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "function_definition"
            && brokk_bifrost_core::analyzer::tree_walk::is_field_child(parent, node, "name")
    })
}

/// Collect the binders in one already-selected assignment or loop target.
/// Attribute/subscript operands remain reads, and exhaustion stays explicit.
/// Callers supply the grammar field rather than reconstructing target syntax.
pub fn python_binding_targets_bounded<'tree>(
    target: Node<'tree>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Vec<PythonDirectScopeBinding<'tree>>> {
    let mut bindings = Vec::new();
    collect_binding_targets(target, source, &mut scope_step, |_, declaration| {
        bindings.push(PythonDirectScopeBinding {
            declaration,
            kind: PythonDirectScopeBindingKind::Other,
        });
    })?;
    Some(bindings)
}

/// Return the bindings introduced directly by `node`.
///
/// Descendant traversal remains the caller's responsibility. This lets the
/// semantic file walk build a module binding inventory without adding a
/// second whole-file scan, while reusing the same structured target handling
/// as function symbol-table discovery.
pub fn python_direct_scope_bindings_bounded<'tree>(
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
                    kind: if is_direct_module_definition_bounded(node, &mut scope_step)? {
                        PythonDirectScopeBindingKind::FunctionDeclaration
                    } else {
                        PythonDirectScopeBindingKind::Other
                    },
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
            let module_level = is_direct_module_definition_bounded(node, &mut scope_step)?;
            collect_import_bindings(node, &mut scope_step, |declaration| {
                bindings.push(PythonDirectScopeBinding {
                    declaration,
                    kind: if module_level {
                        PythonDirectScopeBindingKind::Import
                    } else {
                        PythonDirectScopeBindingKind::Other
                    },
                });
            })?;
        }
        "assignment" | "annotated_assignment" | "augmented_assignment" => {
            if let Some(target) = node.child_by_field_name("left") {
                bindings.extend(python_binding_targets_bounded(
                    target,
                    source,
                    &mut scope_step,
                )?);
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
                bindings.extend(python_binding_targets_bounded(
                    target,
                    source,
                    &mut scope_step,
                )?);
            }
        }
        "for_statement" | "async_for_statement" => {
            if let Some(target) = node.child_by_field_name("left") {
                bindings.extend(python_binding_targets_bounded(
                    target,
                    source,
                    &mut scope_step,
                )?);
            }
        }
        "with_statement" => {
            let mut cursor = node.walk();
            for item in node
                .named_children(&mut cursor)
                .filter(|item| item.kind() == "with_item")
            {
                if let Some(alias) = item.child_by_field_name("alias") {
                    collect_binding_targets(alias, source, &mut scope_step, |_, declaration| {
                        bindings.push(PythonDirectScopeBinding {
                            declaration,
                            kind: PythonDirectScopeBindingKind::Other,
                        });
                    })?;
                }
            }
        }
        "delete_statement" => {
            for target in named_children_bounded(node, &mut scope_step)? {
                bindings.extend(python_binding_targets_bounded(
                    target,
                    source,
                    &mut scope_step,
                )?);
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

/// Whether a module or class execution scope binds `target_name` anywhere in
/// its direct scope. Nested callable and class bodies are separate scopes, but
/// their headers still execute in this scope. A wildcard import keeps the
/// name's runtime identity open even when it does not expose a static binder.
pub fn python_module_or_class_scope_binds_name_bounded(
    scope: Node<'_>,
    target_name: &str,
    source: &str,
    scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    python_scope_binds_name_with_filter_bounded(scope, target_name, source, |_| true, scope_step)
}

fn python_scope_binds_name_with_filter_bounded<'tree>(
    scope: Node<'tree>,
    target_name: &str,
    source: &str,
    include_binding: impl Fn(Node<'tree>) -> bool,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    assert!(matches!(scope.kind(), "module" | "class_definition"));
    let body = scope.child_by_field_name("body").unwrap_or(scope);
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(true);
        }
        if python_direct_scope_bindings_bounded(node, source, &mut scope_step)?
            .into_iter()
            .any(|binding| {
                include_binding(binding.declaration)
                    && node_text(binding.declaration, source) == target_name
            })
        {
            return Some(true);
        }
        stack.extend(python_executable_scope_children(node));
    }
    Some(false)
}

/// Iterate executable-scope children, skipping nested callable and class bodies.
pub fn python_executable_scope_children<'tree>(
    node: Node<'tree>,
) -> impl Iterator<Item = Node<'tree>> {
    let excluded_body = matches!(
        node.kind(),
        "class_definition" | "function_definition" | "lambda"
    )
    .then(|| node.child_by_field_name("body").map(|body| body.id()))
    .flatten();
    named_children_iter(node).filter(move |child| Some(child.id()) != excluded_body)
}

pub fn python_unambiguous_module_class_binding_bounded(
    root: Node<'_>,
    source: &str,
    target_name: &str,
    scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    Some(
        python_unambiguous_module_binding_bounded(root, source, target_name, scope_step)?
            == Some(PythonDirectScopeBindingKind::ClassDeclaration),
    )
}

/// The kind of the module scope's one binding of `target_name`.
///
/// `Some(None)` says the module does not bind the name, binds it more than
/// once, or leaves its identity open through a wildcard import; the name is
/// then not a proven reference to one module-level declaration. `None` says the
/// bounded walk ran out of work.
pub fn python_unambiguous_module_binding_bounded(
    root: Node<'_>,
    source: &str,
    target_name: &str,
    scope_step: impl FnMut() -> bool,
) -> Option<Option<PythonDirectScopeBindingKind>> {
    Some(
        python_unambiguous_module_binding_node_bounded(root, source, target_name, scope_step)?
            .map(|binding| binding.kind),
    )
}

/// The module scope's unique binding event, after the bounded proof completes.
///
/// A returned node identifies the actual binder, not a proven runtime value.
/// `Other` still needs the caller's syntax and visibility checks. Competing
/// events or a later wildcard return `Some(None)`; an interrupted proof returns
/// `None` and must never expose a binder found before the interruption.
pub fn python_unambiguous_module_binding_node_bounded<'tree>(
    root: Node<'tree>,
    source: &str,
    target_name: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Option<PythonDirectScopeBinding<'tree>>> {
    let mut matched = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        // A later unconditional declaration replaces an earlier wildcard
        // binding; a wildcard after it leaves its identity open.
        if node.kind() == "wildcard_import" && matched.is_some() {
            return Some(None);
        }
        for binding in python_direct_scope_bindings_bounded(node, source, &mut scope_step)? {
            if node_text(binding.declaration, source) != target_name {
                continue;
            }
            if matched.is_some() {
                return Some(None);
            }
            matched = Some(binding);
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
    Some(matched)
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

pub(crate) fn collect_binding_targets<'tree>(
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
    stack: &mut Vec<Node<'tree>>,
    node: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let children = named_children_bounded(node, scope_step)?;
    push_bounded_children(stack, children.into_iter());
    Some(())
}

fn push_named_children_except<'tree>(
    stack: &mut Vec<Node<'tree>>,
    node: Node<'tree>,
    excluded: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let children = named_children_bounded(node, scope_step)?;
    push_bounded_children(
        stack,
        children
            .into_iter()
            .filter(|child| child.id() != excluded.id()),
    );
    Some(())
}

fn push_nested_scope_header_children<'tree>(
    stack: &mut Vec<Node<'tree>>,
    node: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<()> {
    let body = node.child_by_field_name("body").map(|child| child.id());
    let name = node.child_by_field_name("name").map(|child| child.id());
    // Prune execution boundaries before charging or visiting their bodies.
    // Only the header belongs to the enclosing scope's collector walk.
    let mut cursor = node.walk();
    let children = node
        .named_children(&mut cursor)
        .filter(|child| Some(child.id()) != body);
    let mut headers = Vec::new();
    push_bounded_nodes(children, &mut headers, scope_step).then_some(())?;
    push_bounded_children(
        stack,
        headers.into_iter().filter(|child| Some(child.id()) != name),
    );
    Some(())
}

fn push_bounded_children<'tree>(
    stack: &mut Vec<Node<'tree>>,
    children: impl DoubleEndedIterator<Item = Node<'tree>>,
) {
    for child in children.rev() {
        stack.push(child);
    }
}

fn named_children_bounded<'tree>(
    node: Node<'tree>,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Vec<Node<'tree>>> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    push_bounded_nodes(node.named_children(&mut cursor), &mut children, scope_step)
        .then_some(children)
}

fn children_by_field_name_bounded<'tree>(
    node: Node<'tree>,
    field: &str,
    scope_step: &mut impl FnMut() -> bool,
) -> Option<Vec<Node<'tree>>> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    push_bounded_nodes(
        node.children_by_field_name(field, &mut cursor),
        &mut children,
        scope_step,
    )
    .then_some(children)
}

pub(crate) fn is_comprehension(kind: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn only_the_first_comprehension_iterable_uses_the_enclosing_scope() {
        let source = "def run(first, second):\n    return [second for first in first for second in second]\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        let comprehension = loop {
            let node = stack.pop().expect("fixture contains a comprehension");
            if node.kind() == "list_comprehension" {
                break node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        };
        let mut cursor = comprehension.walk();
        let clauses = comprehension
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "for_in_clause")
            .collect::<Vec<_>>();
        let outer = clauses[0].child_by_field_name("right").unwrap();
        let inner = clauses[1].child_by_field_name("right").unwrap();
        assert!(!super::python_comprehension_binds_name_at(
            "first", outer, source
        ));
        assert!(super::python_comprehension_binds_name_at(
            "second", inner, source
        ));
    }

    #[test]
    #[hardwon(
        "#5044+#5511+#5751: bounded lexical proofs bypassed stops, lazy bindings or competing events"
    )]
    fn bounded_comprehension_lookup_preserves_exhaustion() {
        let source = "def run(xs):\n    class Base:\n        pass\n    def helper():\n        pass\n    class Derived(Base):\n        pass\n    helper()\n    return [target for target in xs]\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        let function = tree.root_node().named_child(0).unwrap();
        let inventory = super::PythonLexicalScopeInventory::collect_bounded(
            function,
            source,
            ["xs".to_owned()],
            || true,
        )
        .unwrap();
        let mut stack = vec![function];
        let comprehension = loop {
            let node = stack.pop().expect("fixture contains a comprehension");
            if node.kind() == "list_comprehension" {
                break node;
            }
            stack.extend(brokk_bifrost_core::analyzer::tree_walk::named_children_iter(node));
        };
        let reference = comprehension.named_child(0).unwrap();
        for mut remaining in [0_usize, 1] {
            assert_eq!(
                inventory.name_resolution_at_bounded("target", reference, || {
                    let available = remaining > 0;
                    remaining = remaining.saturating_sub(1);
                    available
                }),
                None
            );
        }
        assert_eq!(
            inventory.name_resolution_at_bounded("target", reference, || true),
            Some(super::PythonLexicalNameResolution::Local)
        );
        let body = function.child_by_field_name("body").unwrap();
        let derived = brokk_bifrost_core::analyzer::tree_walk::named_children_iter(body)
            .find(|node| node.child_by_field_name("superclasses").is_some())
            .unwrap();
        let base_reference = derived
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let call = brokk_bifrost_core::analyzer::tree_walk::named_children_iter(body)
            .filter(|node| node.kind() == "expression_statement")
            .find_map(|node| node.named_child(0).filter(|node| node.kind() == "call"))
            .unwrap();
        let helper_reference = call.child_by_field_name("function").unwrap();
        // Collection has completed, but every later lookup must still charge
        // retained comprehension facts. One step cannot finish that scan.
        let one_step = || {
            let mut available = true;
            move || std::mem::take(&mut available)
        };
        assert!(
            inventory
                .has_runtime_callable_binding_at_bounded("helper", helper_reference, one_step())
                .is_none()
        );
        assert!(
            inventory
                .local_function_declaration_bounded("helper", helper_reference, one_step())
                .is_none()
        );
        assert!(
            inventory
                .local_class_declaration_bounded("Base", base_reference, one_step())
                .is_none()
        );
        assert_eq!(
            inventory
                .local_function_declaration_bounded("helper", helper_reference, || true)
                .unwrap()
                .kind(),
            "function_definition"
        );
        assert_eq!(
            inventory
                .local_class_declaration_bounded("Base", base_reference, || true)
                .unwrap()
                .kind(),
            "class_definition"
        );
        let bindings = inventory.into_bindings();
        assert_eq!(
            bindings.name_resolution_at_bounded("missing", reference, one_step()),
            None,
            "stopped lookup must not manufacture Unbound"
        );
        assert_eq!(
            bindings.name_resolution_at_bounded("missing", reference, || true),
            Some(super::PythonLexicalNameResolution::Unbound)
        );
        assert_eq!(
            bindings.resolves_to_local_function_bounded("helper", helper_reference, one_step()),
            None
        );
        assert_eq!(
            bindings.resolves_to_local_function_bounded("helper", helper_reference, || true),
            Some(true)
        );
        assert_eq!(
            super::python_comprehension_binds_name_at_bounded(
                "target",
                reference,
                source,
                one_step()
            ),
            None
        );
        assert_eq!(
            super::python_comprehension_binds_name_at_bounded("target", reference, source, || true),
            Some(true)
        );
        let clause = brokk_bifrost_core::analyzer::tree_walk::named_children_iter(comprehension)
            .find(|node| node.kind() == "for_in_clause")
            .unwrap();
        let targets = super::python_binding_targets_bounded(
            clause.child_by_field_name("left").unwrap(),
            source,
            || true,
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(
            Some(targets[0].declaration),
            clause.child_by_field_name("left")
        );

        // An assignment binder is positive evidence only after later events
        // and executable headers have been checked. Body-local writes do not
        // compete, but header walrus writes and later wildcards do.
        use super::PythonDirectScopeBindingKind::{ClassDeclaration, Other};
        for (source, expected_kind) in [
            ("Alias = Base\ntrailing = None\n", Some(Other)),
            ("Alias = Base\nAlias = Other\n", None),
            ("Alias = Base\ndel Alias\n", None),
            ("Alias = Base\nfrom pkg import Target as Alias\n", None),
            ("Alias = Base\nfrom pkg import *\n", None),
            ("from pkg import *\nAlias = Base\n", Some(Other)),
            (
                "Alias = Base\ndef inner():\n    Alias = Other\nclass Container:\n    Alias = Other\n",
                Some(Other),
            ),
            (
                "Alias = Base\ndef inner(value=(Alias := Other)):\n    pass\n",
                None,
            ),
            ("class Alias:\n    pass\n", Some(ClassDeclaration)),
            (
                "from pkg import *\nclass Alias:\n    pass\n",
                Some(ClassDeclaration),
            ),
            ("class Alias:\n    pass\nfrom pkg import *\n", None),
            ("Other = Base\n", None),
        ] {
            let tree = crate::declarations::parse_python_tree(source).unwrap();
            let root = tree.root_node();
            assert!(!root.has_error(), "{source}");
            let mut steps = 0_usize;
            let binding = super::python_unambiguous_module_binding_node_bounded(
                root,
                source,
                "Alias",
                || {
                    steps += 1;
                    true
                },
            )
            .expect("uninterrupted binding proof completes");
            assert_eq!(
                binding.map(|binding| binding.kind),
                expected_kind,
                "{source}"
            );
            if let Some(binding) = binding {
                assert_eq!(binding.declaration.kind(), "identifier");
                assert_eq!(super::node_text(binding.declaration, source), "Alias");
                let parent = binding.declaration.parent().unwrap();
                let field = if binding.kind == ClassDeclaration {
                    "name"
                } else {
                    "left"
                };
                assert_eq!(parent.child_by_field_name(field), Some(binding.declaration));
                let statement = if binding.kind == ClassDeclaration {
                    parent
                } else {
                    parent.parent().unwrap()
                };
                assert_eq!(statement.parent(), Some(root), "exact module-owned binder");
            }
            assert_eq!(
                super::python_unambiguous_module_binding_bounded(root, source, "Alias", || true),
                Some(expected_kind),
                "kind-only consumers retain the same positive requirement: {source}"
            );
            assert_eq!(
                super::python_unambiguous_module_class_binding_bounded(
                    root,
                    source,
                    "Alias",
                    || true
                ),
                Some(expected_kind == Some(ClassDeclaration))
            );
            for mut remaining in 0..steps {
                assert!(
                    super::python_unambiguous_module_binding_node_bounded(
                        root,
                        source,
                        "Alias",
                        || {
                            let available = remaining > 0;
                            remaining = remaining.saturating_sub(1);
                            available
                        },
                    )
                    .is_none(),
                    "a stopped proof cannot publish its early binder: {source}"
                );
            }
        }

        // The same spelling is an immediate base root and a lazy bound root.
        // Generic hierarchy refusal cannot test this shared binding distinction.
        let source = "import ns_source as ns\nclass Outer:\n    class ns[T: ns.Target]((ns.Target)):\n        pass\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        assert!(!tree.root_node().has_error());
        let outer = brokk_bifrost_core::analyzer::tree_walk::first_named_child_of_kind(
            tree.root_node(),
            "class_definition",
        )
        .unwrap();
        let inner = brokk_bifrost_core::analyzer::tree_walk::first_named_child_of_kind(
            outer.child_by_field_name("body").unwrap(),
            "class_definition",
        )
        .unwrap();
        let base = inner
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let immediate = crate::syntax::python_static_value_path_bounded(base, || true)
            .unwrap()
            .unwrap()[0];
        let bound =
            brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(
                inner.child_by_field_name("type_parameters").unwrap(),
                "attribute",
            )
            .unwrap()
            .child_by_field_name("object")
            .unwrap();
        for (reference, resolution, binds) in [
            (
                immediate,
                super::PythonLexicalNameResolution::Unbound,
                false,
            ),
            (bound, super::PythonLexicalNameResolution::Local, true),
        ] {
            assert!(
                super::PythonClassReferenceScope::new_bounded(outer, reference, || false).is_none()
            );
            let scope =
                super::PythonClassReferenceScope::new_bounded(outer, reference, || true).unwrap();
            let inventory = scope.collect_bounded(source, || true).unwrap();
            assert_eq!(
                inventory.name_resolution_at_bounded("ns", reference, || true),
                Some(resolution)
            );
            assert_eq!(scope.binds_name_bounded("ns", source, || true), Some(binds));
        }
    }
}
