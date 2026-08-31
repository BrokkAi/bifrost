use crate::imports::{
    CommonJsRequireBindingKind, commonjs_require_module_specifier_from_declarator,
    parse_commonjs_require_bindings_from_node,
};
use brokk_bifrost_core::analyzer::tree_walk::subtree_contains;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinding, ImportKind};
use brokk_bifrost_core::analyzer::{Language, ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

pub const MAX_STATIC_IMPORT_BINDINGS_PER_NAME: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
struct JsTsImportBinding {
    binding: ImportBinding,
    is_static: bool,
}

/// JS/TS imports are usually unique by local name, but malformed or generated
/// sources can bind the same local name more than once. Keep those static
/// candidates together so every JS/TS consumer observes the same ambiguity.
/// CommonJS declarations retain the historical last-declaration-wins model;
/// source-position-sensitive CommonJS assignment flow is a separate concern.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JsTsImportBinder {
    bindings: HashMap<String, Vec<JsTsImportBinding>>,
    truncated_names: HashSet<String>,
}

impl JsTsImportBinder {
    pub fn empty() -> Self {
        Self::default()
    }

    fn bind_static(&mut self, local_name: String, binding: ImportBinding) {
        let bindings = self.bindings.entry(local_name.clone()).or_default();
        if bindings
            .iter()
            .any(|existing| existing.is_static && existing.binding == binding)
        {
            return;
        }
        if bindings.len() == MAX_STATIC_IMPORT_BINDINGS_PER_NAME {
            self.truncated_names.insert(local_name);
            return;
        }
        bindings.push(JsTsImportBinding {
            binding,
            is_static: true,
        });
    }

    fn bind_commonjs(&mut self, local_name: String, binding: ImportBinding) {
        self.bindings.insert(
            local_name,
            vec![JsTsImportBinding {
                binding,
                is_static: false,
            }],
        );
    }

    pub fn binding(&self, local_name: &str) -> Option<&ImportBinding> {
        Some(&self.bindings.get(local_name)?.last()?.binding)
    }

    pub fn bindings_for(&self, local_name: &str) -> impl Iterator<Item = &ImportBinding> {
        self.bindings
            .get(local_name)
            .into_iter()
            .flat_map(|bindings| bindings.iter().map(|binding| &binding.binding))
    }

    pub fn direct_bindings_for(&self, local_name: &str) -> impl Iterator<Item = &ImportBinding> {
        self.bindings
            .get(local_name)
            .into_iter()
            .flat_map(|bindings| bindings.iter())
            .filter(|binding| {
                binding.is_static
                    && matches!(
                        binding.binding.kind,
                        ImportKind::Named | ImportKind::Default
                    )
            })
            .map(|binding| &binding.binding)
    }

    pub fn resolvable_direct_bindings_for(
        &self,
        local_name: &str,
    ) -> impl Iterator<Item = &ImportBinding> {
        self.bindings_for(local_name)
            .filter(|binding| matches!(binding.kind, ImportKind::Named | ImportKind::Default))
    }

    pub fn has_competing_direct_imports(&self, local_name: &str) -> bool {
        self.direct_bindings_for(local_name).nth(1).is_some()
    }

    /// Whether more than one static import claims the same local binding,
    /// including namespace imports. Consumers deriving one external owner must
    /// reject this broader ambiguity; direct-definition resolution keeps using
    /// [`Self::has_competing_direct_imports`] for its narrower candidate set.
    pub fn has_competing_static_imports(&self, local_name: &str) -> bool {
        self.bindings
            .get(local_name)
            .into_iter()
            .flat_map(|bindings| bindings.iter())
            .filter(|binding| binding.is_static)
            .nth(1)
            .is_some()
    }

    pub fn was_truncated(&self, local_name: &str) -> bool {
        self.truncated_names.contains(local_name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.bindings.keys().map(String::as_str)
    }

    pub fn all_bindings(&self) -> impl Iterator<Item = (&str, &ImportBinding)> {
        self.bindings.iter().flat_map(|(local_name, bindings)| {
            bindings
                .iter()
                .map(move |binding| (local_name.as_str(), &binding.binding))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsTsLexicalBindingScope {
    start_byte: usize,
    end_byte: usize,
}

/// Tree-sitter-derived lexical bindings, indexed by the source range in which
/// each name shadows an outer/global binding. Declaration order is deliberately
/// irrelevant: `var` is hoisted and lexical declarations are in the TDZ for
/// their entire scope.
pub struct JsTsLexicalBindingIndex {
    scopes_by_name: HashMap<String, Vec<JsTsLexicalBindingScope>>,
    binding_ranges_by_name: HashMap<String, Vec<(JsTsLexicalBindingScope, Range)>>,
    /// Byte offsets of assignment targets, keyed by the assigned name. An
    /// assignment site whose name resolves to the program scope rebinds the
    /// program-level callable, so calls through that name stay ambiguous.
    assignments_by_name: HashMap<String, Vec<usize>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsTsDirectPropertyDefinition<'tree> {
    pub receiver: JsTsStaticMemberReceiver<'tree>,
    pub property_range: Range,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsTsStaticMemberReceiver<'tree> {
    pub root: Node<'tree>,
    pub members: Vec<Node<'tree>>,
}

impl JsTsLexicalBindingIndex {
    pub fn build(root: Node<'_>, source: &str) -> Self {
        let mut index = Self {
            scopes_by_name: HashMap::default(),
            binding_ranges_by_name: HashMap::default(),
            assignments_by_name: HashMap::default(),
        };
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "import_statement" => {
                    let mut binder = JsTsImportBinder::empty();
                    visit_import_statement(node, source, &mut binder);
                    let scope = node_scope(root);
                    for name in binder.names() {
                        index.insert(name, scope);
                    }
                    let imported_names: HashSet<_> = binder.names().collect();
                    let mut import_stack = vec![node];
                    while let Some(import_node) = import_stack.pop() {
                        if matches!(import_node.kind(), "identifier" | "type_identifier")
                            && is_declaration_identifier(import_node)
                        {
                            let name = slice(import_node, source);
                            if imported_names.contains(name) {
                                index.insert_binding(name, scope, import_node);
                            }
                        }
                        for child_index in (0..import_node.named_child_count()).rev() {
                            if let Some(child) = import_node.named_child(child_index) {
                                import_stack.push(child);
                            }
                        }
                    }
                }
                "variable_declarator" => {
                    if let Some(pattern) = node.child_by_field_name("name")
                        && let Some(scope) = variable_binding_scope(node)
                    {
                        index.insert_pattern(pattern, source, scope);
                    }
                }
                "for_in_statement" => {
                    if let Some(pattern) = node.child_by_field_name("left")
                        && let Some(declaration_kind) = for_in_declaration_kind(node, pattern)
                    {
                        let scope = if declaration_kind == "var" {
                            enclosing_var_binding_scope(node)
                        } else {
                            Some(node_scope(node))
                        };
                        if let Some(scope) = scope {
                            index.insert_pattern(pattern, source, scope);
                        }
                    }
                }
                "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                    if let Some(name) = node.child_by_field_name("name")
                        && let Some(scope) = enclosing_lexical_scope(node)
                    {
                        index.insert_pattern(name, source, scope);
                    }
                    index.insert_parameters(node, source);
                }
                "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition" => {
                    if matches!(node.kind(), "function_expression" | "generator_function")
                        && let Some(name) = node.child_by_field_name("name")
                    {
                        index.insert_pattern(name, source, node_scope(node));
                    }
                    index.insert_parameters(node, source);
                }
                "class" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        index.insert_pattern(name, source, node_scope(node));
                    }
                }
                "catch_clause" => {
                    if let Some(parameter) = node.child_by_field_name("parameter") {
                        index.insert_pattern(parameter, source, node_scope(node));
                    }
                }
                "assignment_expression" | "augmented_assignment_expression" => {
                    if let Some(target) = node.child_by_field_name("left") {
                        index.record_assignment_targets(target, source);
                    }
                }
                "update_expression" => {
                    if let Some(target) = node.child_by_field_name("argument") {
                        index.record_assignment_targets(target, source);
                    }
                }
                _ => {}
            }

            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        index
    }

    pub fn is_bound_at(&self, name: &str, byte: usize) -> bool {
        self.binding_scope_at(name, byte).is_some()
    }

    pub fn binding_scope_at(&self, name: &str, byte: usize) -> Option<JsTsLexicalBindingScope> {
        self.scopes_by_name
            .get(name)?
            .iter()
            .copied()
            .filter(|scope| scope.start_byte <= byte && byte < scope.end_byte)
            .min_by_key(|scope| scope.end_byte - scope.start_byte)
    }

    /// Declaration-token ranges for the active lexical binding. Consumers use
    /// these ranges to distinguish a program binding from a same-spelled object
    /// member in the same file without guessing from either FQN shape.
    pub fn binding_identifier_ranges_at(&self, name: &str, byte: usize) -> Vec<Range> {
        let Some(scope) = self.binding_scope_at(name, byte) else {
            return Vec::new();
        };
        self.binding_ranges_by_name
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|(binding_scope, range)| (*binding_scope == scope).then_some(*range))
            .collect()
    }

    pub fn is_program_binding_at(&self, name: &str, byte: usize, root: Node<'_>) -> bool {
        self.binding_scope_at(name, byte) == Some(node_scope(root))
    }

    /// Whether an assignment somewhere in the program rebinds `name` at the
    /// program scope: at the assignment site, `name` resolves to the program
    /// binding, not to a local shadow.
    pub fn is_program_binding_reassigned(&self, name: &str, root: Node<'_>) -> bool {
        self.assignments_by_name
            .get(name)
            .is_some_and(|assignments| {
                assignments
                    .iter()
                    .any(|byte| self.is_program_binding_at(name, *byte, root))
            })
    }

    /// Whether an assignment or update rebinds the active lexical binding of
    /// `name` at `byte`. A same-spelled assignment in a nested shadowing scope
    /// does not mutate this binding.
    pub fn is_binding_reassigned_at(&self, name: &str, byte: usize) -> bool {
        let Some(scope) = self.binding_scope_at(name, byte) else {
            return false;
        };
        self.assignments_by_name
            .get(name)
            .is_some_and(|assignments| {
                assignments
                    .iter()
                    .any(|assignment| self.binding_scope_at(name, *assignment) == Some(scope))
            })
    }

    fn record_assignment_targets(&mut self, target: Node<'_>, source: &str) {
        for binder in pattern_binder_identifiers(target) {
            let name = slice(binder, source);
            if !name.is_empty() {
                self.assignments_by_name
                    .entry(name.to_string())
                    .or_default()
                    .push(binder.start_byte());
            }
        }
    }

    fn insert_parameters(&mut self, function: Node<'_>, source: &str) {
        let Some(parameters) = function
            .child_by_field_name("parameters")
            .or_else(|| function.child_by_field_name("parameter"))
        else {
            return;
        };
        self.insert_pattern(parameters, source, node_scope(function));
    }

    fn insert_pattern(&mut self, pattern: Node<'_>, source: &str, scope: JsTsLexicalBindingScope) {
        for binder in pattern_binder_identifiers(pattern) {
            let name = slice(binder, source);
            if !name.is_empty() {
                self.insert_binding(name, scope, binder);
            }
        }
    }

    fn insert_binding(&mut self, name: &str, scope: JsTsLexicalBindingScope, binder: Node<'_>) {
        self.insert(name, scope);
        let range = Range {
            start_byte: binder.start_byte(),
            end_byte: binder.end_byte(),
            start_line: binder.start_position().row,
            end_line: binder.end_position().row,
        };
        let ranges = self
            .binding_ranges_by_name
            .entry(name.to_string())
            .or_default();
        if !ranges.contains(&(scope, range)) {
            ranges.push((scope, range));
        }
    }

    fn insert(&mut self, name: &str, scope: JsTsLexicalBindingScope) {
        let scopes = self.scopes_by_name.entry(name.to_string()).or_default();
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
}

/// Collects the binder identifier nodes of a binding pattern in source order:
/// plain identifiers, object/array destructuring (including renamed
/// `pair_pattern` values, defaults, and rest binders), and parameter wrappers.
pub fn pattern_binder_identifiers(pattern: Node<'_>) -> Vec<Node<'_>> {
    let mut binders = Vec::new();
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" | "type_identifier" | "shorthand_property_identifier_pattern" => {
                binders.push(node)
            }
            "required_parameter" | "optional_parameter" => {
                if let Some(pattern) = node
                    .child_by_field_name("pattern")
                    .or_else(|| node.child_by_field_name("name"))
                {
                    stack.push(pattern);
                }
            }
            "assignment_pattern" | "object_assignment_pattern" => {
                if let Some(left) = node.child_by_field_name("left") {
                    stack.push(left);
                }
            }
            "pair_pattern" => {
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(value);
                }
            }
            "formal_parameters" | "object_pattern" | "array_pattern" | "rest_pattern" => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                stack.extend(children.into_iter().rev());
            }
            _ => {}
        }
    }
    binders
}

pub fn direct_property_definitions<'tree>(
    root: Node<'tree>,
    source: &str,
    target_ranges: &[Range],
    target_member: &str,
) -> Vec<JsTsDirectPropertyDefinition<'tree>> {
    let mut definitions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let receiver = match node.kind() {
            "assignment_expression" | "augmented_assignment_expression" => node
                .child_by_field_name("left")
                .and_then(|left| direct_assignment_receiver(left, source, target_member)),
            // `{ key: value }` and `{ key }` mint the same property off the same
            // object literal; only the node that carries the key differs.
            "pair" => node
                .child_by_field_name("key")
                .and_then(|key| direct_object_property_receiver(node, key, source, target_member)),
            "shorthand_property_identifier" => {
                direct_object_property_receiver(node, node, source, target_member)
            }
            "method_definition" => node.child_by_field_name("name").and_then(|name| {
                direct_object_property_receiver(node, name, source, target_member)
            }),
            _ => None,
        };
        if let Some((receiver, property)) = receiver
            && target_ranges
                .iter()
                .any(|range| range_contains_node(range, property))
        {
            let definition = JsTsDirectPropertyDefinition {
                receiver,
                property_range: Range {
                    start_byte: property.start_byte(),
                    end_byte: property.end_byte(),
                    start_line: property.start_position().row,
                    end_line: property.end_position().row,
                },
            };
            definitions.push(definition);
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    definitions
}

fn direct_assignment_receiver<'tree>(
    left: Node<'tree>,
    source: &str,
    target_member: &str,
) -> Option<(JsTsStaticMemberReceiver<'tree>, Node<'tree>)> {
    if left.kind() != "member_expression" {
        return None;
    }
    let receiver = left.child_by_field_name("object")?;
    let property = left.child_by_field_name("property")?;
    if slice(property, source) != target_member {
        return None;
    }
    static_member_receiver(receiver, source).map(|receiver| (receiver, property))
}

/// The receiver chain that owns `property` when `property` is the key of
/// `entry`, an entry of an object literal that is the whole value of a binding.
/// `entry` is the `pair` for `{ key: value }` and the shorthand identifier
/// itself for `{ key }`.
fn direct_object_property_receiver<'tree>(
    entry: Node<'tree>,
    property: Node<'tree>,
    source: &str,
    target_member: &str,
) -> Option<(JsTsStaticMemberReceiver<'tree>, Node<'tree>)> {
    if slice(property, source) != target_member {
        return None;
    }
    let object = entry.parent().filter(|parent| parent.kind() == "object")?;
    let mut value = object;
    while let Some(parent) = value.parent()
        && parent.kind() == "parenthesized_expression"
        && parent
            .named_child(0)
            .is_some_and(|child| child.id() == value.id())
    {
        value = parent;
    }
    let bound = value.parent()?;
    // The literal is the whole value of a binding, so its keys are properties of
    // whatever that binding names: `const x = { key: ... }` mints `x.key`, and
    // `x.y = { key: ... }` mints `x.y.key`. A chained receiver is kept whole --
    // the read side compares receiver member chains element-wise.
    let receiver = match bound.kind() {
        "variable_declarator" => bound
            .child_by_field_name("value")
            .filter(|bound_value| bound_value.id() == value.id())
            .and_then(|_| bound.child_by_field_name("name")),
        "assignment_expression" => bound
            .child_by_field_name("right")
            .filter(|right| right.id() == value.id())
            .and_then(|_| bound.child_by_field_name("left")),
        _ => None,
    }?;
    static_member_receiver(receiver, source).map(|receiver| (receiver, property))
}

pub fn static_member_receiver<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<JsTsStaticMemberReceiver<'tree>> {
    let mut current = node;
    let mut members = Vec::new();
    while matches!(current.kind(), "member_expression" | "subscript_expression") {
        let (property, _) = static_member_property(current, source)?;
        // A private name is a static *member* name but not a receiver-chain
        // segment: `other.#inner.value` names a field of whatever `other` is,
        // and nothing in the chain text says which class that is. The chain
        // walk therefore stops here, as it did before the shared property
        // helper existed.
        if property.kind() == "private_property_identifier" {
            return None;
        }
        members.push(property);
        current = current.child_by_field_name("object")?;
    }
    if current.kind() != "identifier" || slice(current, source).is_empty() {
        return None;
    }
    members.reverse();
    Some(JsTsStaticMemberReceiver {
        root: current,
        members,
    })
}

/// The name-bearing node and decoded name of a statically nameable member.
///
/// Dot properties use their identifier node. A computed string property uses
/// its sole `string_fragment`, which both rejects escapes/dynamic expressions
/// and retains the editor-visible range inside the quotes.
///
/// A private name (`#field`) is a dot property like any other: the grammar
/// gives it its own node kind, the `#` is part of the name, and the field it
/// names is indexed under its exact class owner (#1926). Callers that need a
/// receiver *chain* rather than a member name reject it themselves; see
/// [`static_member_receiver`].
pub fn static_member_property<'tree>(
    member_expression: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String)> {
    let (property, computed) = match member_expression.kind() {
        "member_expression" => (member_expression.child_by_field_name("property")?, false),
        "subscript_expression" => (member_expression.child_by_field_name("index")?, true),
        _ => return None,
    };
    match property.kind() {
        "property_identifier" | "identifier" | "private_property_identifier" if !computed => {
            let name = slice(property, source);
            (!name.is_empty()).then(|| (property, name.to_string()))
        }
        "string" => static_string_property(property, source),
        "computed_property_name" => {
            let mut cursor = property.walk();
            let mut children = property.named_children(&mut cursor);
            let value = children.next()?;
            if children.next().is_some() || value.kind() != "string" {
                return None;
            }
            static_string_property(value, source)
        }
        _ => None,
    }
}

fn static_string_property<'tree>(
    string: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String)> {
    let mut cursor = string.walk();
    let mut children = string.named_children(&mut cursor);
    let fragment = children.next()?;
    if fragment.kind() != "string_fragment" || children.next().is_some() {
        return None;
    }
    let name = slice(fragment, source);
    (!name.is_empty()).then(|| (fragment, name.to_string()))
}

/// The identifier at the root of a static member chain (`module` in
/// `module.exports.foo`).
fn static_member_root(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" => return Some(node),
            "member_expression" => node = node.child_by_field_name("object")?,
            _ => return None,
        }
    }
}

/// Whether this program is an external module rather than a browser script:
/// it carries an ESM import/export, a `require(...)` call, or a CommonJS
/// `exports` / `module.exports` assignment.
///
/// A browser script's top-level `var` is a property of the one shared global
/// object, so a later script sees it; a module's top-level binding is
/// file-private. That is the whole reason an unexported `NS.Field = ...` can
/// be read from another file at all, so the forward definition lookup
/// (`jsts_cross_file_dotted_receiver_has_global_identity`) and the inverse
/// usage scan must decide it the same way -- hence one function here rather
/// than one per direction.
pub fn js_program_is_external_module(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    root.named_children(&mut cursor).any(|statement| {
        matches!(statement.kind(), "import_statement" | "export_statement")
            || subtree_contains(statement, |node| {
                (node.kind() == "call_expression"
                    && node.child_by_field_name("function").is_some_and(|callee| {
                        callee.kind() == "identifier" && slice(callee, source) == "require"
                    }))
                    || (node.kind() == "assignment_expression"
                        && node
                            .child_by_field_name("left")
                            .and_then(static_member_root)
                            .is_some_and(|root| {
                                matches!(slice(root, source), "exports" | "module")
                            }))
            })
    })
}

fn range_contains_node(range: &Range, node: Node<'_>) -> bool {
    range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte
}

fn node_scope(node: Node<'_>) -> JsTsLexicalBindingScope {
    JsTsLexicalBindingScope {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

fn variable_binding_scope(node: Node<'_>) -> Option<JsTsLexicalBindingScope> {
    js_ts_variable_declarator_binding_scope(node).map(node_scope)
}

/// The lexical scope that owns a JavaScript or TypeScript variable declarator.
///
/// `var` attaches to its nearest function or program. `let` and `const` attach
/// to their nearest block-like scope. The declaration order does not change
/// that identity: a lexical binding exists for its complete scope, including
/// its temporal-dead-zone portion before initialization.
pub fn js_ts_variable_declarator_binding_scope<'tree>(
    declarator: Node<'tree>,
) -> Option<Node<'tree>> {
    if declarator.kind() != "variable_declarator" {
        return None;
    }
    let declaration = declarator.parent()?;
    if declaration.kind() == "variable_declaration" {
        return var_binding_scope_node(declaration);
    }
    let mut current = Some(declaration);
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "program"
                | "statement_block"
                | "for_statement"
                | "for_in_statement"
                | "switch_body"
                | "catch_clause"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn enclosing_var_binding_scope(node: Node<'_>) -> Option<JsTsLexicalBindingScope> {
    var_binding_scope_node(node).map(node_scope)
}

/// The node a `var` binder attaches to: JavaScript hoists `var` to the nearest
/// enclosing function-like node, or to the program. `None` for a `let`/`const`
/// declarator, whose binder is block scoped and stays in its TDZ until its
/// declaration.
pub fn js_ts_var_declarator_binding_scope<'tree>(declarator: Node<'tree>) -> Option<Node<'tree>> {
    let declaration = declarator.parent()?;
    if declaration.kind() != "variable_declaration" {
        return None;
    }
    js_ts_variable_declarator_binding_scope(declarator)
}

fn var_binding_scope_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "program"
                | "function_declaration"
                | "generator_function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn for_in_declaration_kind<'tree>(
    statement: Node<'tree>,
    left: Node<'tree>,
) -> Option<&'static str> {
    let mut cursor = statement.walk();
    statement
        .children(&mut cursor)
        .take_while(|child| child.id() != left.id())
        .find_map(|child| match child.kind() {
            "const" => Some("const"),
            "let" => Some("let"),
            "var" => Some("var"),
            _ => None,
        })
}

fn enclosing_lexical_scope(node: Node<'_>) -> Option<JsTsLexicalBindingScope> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "program" | "statement_block") {
            return Some(node_scope(parent));
        }
        current = parent.parent();
    }
    None
}

pub fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

pub fn nested_type_identifier_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "nested_type_identifier").then_some(())?;
    Some((
        node.child_by_field_name("module")?,
        node.child_by_field_name("name")?,
    ))
}

pub fn is_lexically_nested_type_declaration(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration"
            | "internal_module"
    ) {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "statement_block"
                | "function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition"
        ) {
            return true;
        }
        if parent.kind() == "program" {
            return false;
        }
        current = parent.parent();
    }
    false
}

pub fn is_declaration_identifier(node: Node<'_>) -> bool {
    if is_export_alias_identifier(node) {
        return true;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    let parent_kind = parent.kind();
    if matches!(
        parent_kind,
        "variable_declarator"
            | "function_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration"
            | "method_definition"
            | "method_signature"
            | "abstract_method_signature"
            | "public_field_definition"
            | "property_signature"
            | "index_signature"
            | "field_definition"
            | "import_specifier"
            | "namespace_import"
            | "import_clause"
            | "labeled_statement"
            | "function_signature"
    ) {
        if let Some(name_node) = parent
            .child_by_field_name("name")
            .or_else(|| parent.child_by_field_name("property"))
            && name_node.id() == node.id()
        {
            return true;
        }
        if matches!(
            parent_kind,
            "import_specifier" | "namespace_import" | "import_clause"
        ) {
            return true;
        }
    }
    if matches!(
        parent_kind,
        "formal_parameters"
            | "required_parameter"
            | "optional_parameter"
            | "rest_pattern"
            | "object_pattern"
            | "array_pattern"
            | "pair_pattern"
            | "shorthand_property_identifier_pattern"
    ) {
        return true;
    }
    if parent_kind == "assignment_pattern"
        && let Some(pattern) = parent.named_child(0)
    {
        return pattern.start_byte() <= node.start_byte() && node.end_byte() <= pattern.end_byte();
    }
    false
}

/// Whether this identifier is the name of a JSX intrinsic element rather than
/// a reference to a workspace declaration. JSX assigns lowercase tag names to
/// the host environment; capitalized identifiers and member expressions keep
/// ordinary component-reference semantics.
pub fn is_jsx_intrinsic_element_name(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = node.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "jsx_opening_element" | "jsx_closing_element" | "jsx_self_closing_element"
        )
    }) else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && slice(node, source)
            .chars()
            .next()
            .is_some_and(char::is_lowercase)
}

/// Language-, runtime-, and common host-provided JS/TS bindings that do not
/// require a workspace declaration. Keep this shared with semantic diagnostics
/// so definition lookup and diagnostics make the same boundary decision.
pub fn is_known_js_ts_global(name: &str) -> bool {
    matches!(
        name,
        "Array"
            | "ArrayBuffer"
            | "BigInt"
            | "Boolean"
            | "Date"
            | "Error"
            | "EvalError"
            | "Function"
            | "Infinity"
            | "Intl"
            | "JSON"
            | "Map"
            | "Math"
            | "NaN"
            | "Number"
            | "Object"
            | "Promise"
            | "Proxy"
            | "RangeError"
            | "ReferenceError"
            | "Reflect"
            | "RegExp"
            | "Set"
            | "String"
            | "Symbol"
            | "SyntaxError"
            | "TypeError"
            | "URIError"
            | "WeakMap"
            | "WeakSet"
            | "console"
            | "document"
            | "window"
            | "global"
            | "globalThis"
            | "process"
            | "module"
            | "exports"
            | "require"
            | "React"
            | "JSX"
            | "undefined"
            | "null"
            | "true"
            | "false"
            | "any"
            | "unknown"
            | "never"
            | "void"
            | "object"
            | "string"
            | "number"
            | "boolean"
            | "bigint"
            | "symbol"
            | "describe"
            | "it"
            | "test"
            | "expect"
            | "beforeEach"
            | "afterEach"
            | "beforeAll"
            | "afterAll"
            | "jest"
            | "vi"
            | "setTimeout"
            | "clearTimeout"
            | "setInterval"
            | "clearInterval"
            | "fetch"
    )
}

/// Return the enclosing enum declaration and current member assignment when
/// `node` lies in that assignment's initializer. Deferred function and class
/// bodies introduce their own lexical scope and do not inherit bare enum-member
/// lookup from the surrounding initializer.
pub fn typescript_enclosing_enum_initializer(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut current = node;
    let assignment = loop {
        let parent = current.parent()?;
        if matches!(
            parent.kind(),
            "function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "class_declaration"
        ) {
            return None;
        }
        if parent.kind() == "enum_assignment" {
            let value = parent.child_by_field_name("value")?;
            if value.start_byte() <= node.start_byte() && node.end_byte() <= value.end_byte() {
                break parent;
            }
            return None;
        }
        current = parent;
    };
    let declaration = assignment
        .parent()
        .and_then(|body| body.parent())
        .filter(|parent| parent.kind() == "enum_declaration")?;
    Some((declaration, assignment))
}

pub fn is_export_alias_identifier(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "export_specifier"
            && parent
                .child_by_field_name("alias")
                .is_some_and(|alias| alias == node)
    })
}

/// The identifier a JS/TS declaration names, for the shape the generic field
/// and named-children lookups cannot reach: an `export default ...` statement,
/// whose name is the `default` keyword itself.
///
/// Both tree-sitter-javascript and tree-sitter-typescript spell that keyword as
/// an ANONYMOUS child of the `export_statement`, so a named-children walk never
/// visits it. Without this reader an anonymous default export (`export default
/// class extends HTMLElement {}`, `export default function () {}`, `export
/// default { ... }`) has no reachable name token, and name selection answers
/// with the first NAMED node spelled `default` in the body -- a destructuring
/// key (`const { default: Chart } = ...`), an object key (`{ default: true }`),
/// or a member (`options.default`) -- instead of the declaration keyword
/// (#2733).
///
/// The caller accepts this answer only when the node is spelled like the
/// identifier it seeks, so a named default export (`export default function
/// foo()`) falls through to the declaration's own `name` field, and a non-
/// default export statement (which has no `default` keyword child) falls
/// through here.
pub fn js_ts_declaration_name(declaration: Node<'_>) -> Option<Node<'_>> {
    if declaration.kind() != "export_statement" {
        return None;
    }
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| !child.is_named() && child.kind() == "default")
}

pub fn is_explicit_object_literal_key(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "pair" && is_object_property_key(node))
}

/// Whether the identifier writes a property name at its owner: the `key` field
/// of an object-literal `pair` (`{ total: 1 }`) or of a destructuring
/// `pair_pattern` (`const { total: sum } = row`).
///
/// A computed key (`{ [total]: 1 }`) is an expression that reads a binding, and
/// it is excluded here because such an identifier's parent is the
/// `computed_property_name`, not the pair.
pub fn is_object_property_key(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(parent.kind(), "pair" | "pair_pattern")
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| key.id() == node.id())
}

/// The value a renamed destructuring key reads its owner from.
///
/// `const { texture: frameTexture } = frame` names `texture` at whatever
/// `frame` is, so the key is a property read on that expression. The array
/// form takes one ELEMENT of the expression instead, which is a different
/// question about the same node and so a different variant rather than a flag.
#[derive(Clone, Copy, Debug)]
pub enum JsTsDestructuringSource<'tree> {
    /// `const { key: alias } = <expression>`.
    Value(Node<'tree>),
    /// `const [{ key: alias }] = <expression>`: one element of `<expression>`.
    Element(Node<'tree>),
}

/// The expression whose owner declares `key`, when `key` is the `key` field of
/// a destructuring `pair_pattern` and the pattern binds a whole initializer.
///
/// `None` covers both "not a renamed destructuring key" and every pattern whose
/// destructured value this walk cannot name: a nested pattern (the inner key
/// belongs to the outer key's member type, not to the initializer), a parameter
/// or `for ... of` binder, and a second array level. Those fail closed rather
/// than borrow the outer initializer's owner.
///
/// A shorthand entry (`const { cache } = state`) has no key node distinct from
/// its binder, so it never reaches here: `is_object_property_key` is false for
/// a `shorthand_property_identifier_pattern`, whose parent is the
/// `object_pattern` itself.
pub fn destructured_property_key_source(key: Node<'_>) -> Option<JsTsDestructuringSource<'_>> {
    let pair = key.parent()?;
    if pair.kind() != "pair_pattern" || !is_object_property_key(key) {
        return None;
    }
    let mut current = pair;
    let mut takes_element = false;
    loop {
        let parent = current.parent()?;
        let bound = match parent.kind() {
            "object_pattern" => None,
            "array_pattern" if !takes_element => {
                takes_element = true;
                None
            }
            "variable_declarator" => Some((
                parent.child_by_field_name("name")?,
                parent.child_by_field_name("value")?,
            )),
            "assignment_expression" => Some((
                parent.child_by_field_name("left")?,
                parent.child_by_field_name("right")?,
            )),
            _ => return None,
        };
        if let Some((pattern, value)) = bound {
            if pattern.id() != current.id() {
                return None;
            }
            return Some(if takes_element {
                JsTsDestructuringSource::Element(value)
            } else {
                JsTsDestructuringSource::Value(value)
            });
        }
        current = parent;
    }
}

/// The `object_type` a type annotation is written as, when it is written
/// inline rather than as a name.
///
/// `annotation` is either a `type_annotation` wrapper or a bare type node.
/// A named type -- `Latest`, `Promise<Latest>`, a union -- names an owner the
/// declaration index already publishes under that name, and the type-text owner
/// route answers it; only the anonymous literal has no such owner, which is why
/// its members are published off the declaration that carries it (#2159).
///
/// `Promise<{ ... }>` deliberately answers `None`: those members belong to the
/// AWAITED value, and treating them as the call's own would claim them for an
/// unawaited read too.
pub fn inline_object_type(annotation: Node<'_>) -> Option<Node<'_>> {
    let mut node = if annotation.kind() == "type_annotation" {
        annotation.named_child(0)?
    } else {
        annotation
    };
    loop {
        match node.kind() {
            "object_type" => return Some(node),
            "parenthesized_type" | "readonly_type" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

/// Whether the identifier names a function EXPRESSION: `const run = function
/// step() {...}`. The name binds only inside the expression's own body, so no
/// workspace declaration index publishes it.
pub fn is_named_function_expression_declaration(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "function_expression" | "generator_function")
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id())
    })
}

/// Whether the identifier is the exception binder a `catch` clause introduces:
/// the `parameter` field of `catch (error) {...}`.
///
/// A destructuring binder (`catch ({ message })`) reaches its terminals through
/// the pattern kinds [`is_declaration_identifier`] already covers.
pub fn is_catch_clause_binder(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "catch_clause"
            && parent
                .child_by_field_name("parameter")
                .is_some_and(|parameter| parameter.id() == node.id())
    })
}

pub fn is_property_key_in_member(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    parent
        .child_by_field_name("property")
        .map(|property| property.id() == node.id())
        .unwrap_or(false)
}

pub fn is_object_in_member_expression(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    parent
        .child_by_field_name("object")
        .map(|object| object.id() == node.id())
        .unwrap_or(false)
}

/// The single bare name a destructuring position introduces, when it
/// introduces one.
///
/// A default (`{ width = 1 }`, `[first = 1]`) binds through its `left` child;
/// a further pattern binds names of its own and so names none of its own here.
pub fn direct_pattern_binding(node: Node<'_>) -> Option<Node<'_>> {
    let binding = match node.kind() {
        "assignment_pattern" | "object_assignment_pattern" => node.child_by_field_name("left")?,
        _ => node,
    };
    matches!(
        binding.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    )
    .then_some(binding)
}

/// One entry of an object destructuring pattern.
#[derive(Clone, Copy, Debug)]
pub struct JsTsObjectPatternEntry<'tree> {
    /// The token that names the property the entry reads: a `pair_pattern`'s
    /// key, or the shorthand binder, which names and binds with one token.
    pub key: Node<'tree>,
    /// The single bare name the entry introduces, when it introduces one. A
    /// renamed entry can bind a further pattern (`{ texture: { width } }`)
    /// instead, whose names belong to the key's member type rather than to the
    /// destructured value; the key stays a reference all the same.
    pub binder: Option<Node<'tree>>,
}

/// Every entry of an object destructuring pattern, in source order.
///
/// A rest element (`{ ...others }`) names no property and is skipped.
pub fn object_pattern_entries(pattern: Node<'_>) -> Vec<JsTsObjectPatternEntry<'_>> {
    let mut entries = Vec::new();
    let mut cursor = pattern.walk();
    for property in pattern.named_children(&mut cursor) {
        let entry = match property.kind() {
            "shorthand_property_identifier_pattern" => JsTsObjectPatternEntry {
                key: property,
                binder: Some(property),
            },
            "pair_pattern" => {
                let Some(key) = property.child_by_field_name("key") else {
                    continue;
                };
                JsTsObjectPatternEntry {
                    key,
                    binder: property
                        .child_by_field_name("value")
                        .and_then(direct_pattern_binding),
                }
            }
            "object_assignment_pattern" => {
                let Some(left) = property.child_by_field_name("left") else {
                    continue;
                };
                JsTsObjectPatternEntry {
                    key: left,
                    binder: direct_pattern_binding(left),
                }
            }
            _ => continue,
        };
        entries.push(entry);
    }
    entries
}

/// The module whose export surface a value carries, when the author stated it
/// in the explicit type argument of the call that produced the value.
///
/// `vi.importActual<typeof UseBaseQueryModule>('../useBaseQuery')` types its own
/// result at the call site: `typeof M`, for a module namespace binding `M`,
/// names that module's export surface. This reads the same argument the forward
/// definition route reads for such a call (#2039), so the two directions answer
/// from one fact rather than from two spellings of it.
///
/// Exactly one type argument is required. A multi-argument generic such as
/// `makePair<typeof M, string>(...)` parameterizes the callee; it says nothing
/// about the call's own result, so it never claims one of its arguments.
/// `await` and parentheses wrap the call without changing what it produces.
pub fn call_type_argument_module_specifier(
    value: Node<'_>,
    source: &str,
    imports: &JsTsImportBinder,
) -> Option<String> {
    let mut call = value;
    while matches!(call.kind(), "await_expression" | "parenthesized_expression") {
        call = call.named_child(0)?;
    }
    if call.kind() != "call_expression" {
        return None;
    }
    let arguments = call.child_by_field_name("type_arguments")?;
    if arguments.named_child_count() != 1 {
        return None;
    }
    let argument = arguments.named_child(0)?;
    if argument.kind() != "type_query" {
        return None;
    }
    let namespace = argument.named_child(0)?;
    if !matches!(namespace.kind(), "identifier" | "nested_identifier") {
        return None;
    }
    let binding = imports.binding(slice(namespace, source))?;
    matches!(
        binding.kind,
        ImportKind::Namespace | ImportKind::CommonJsRequire
    )
    .then(|| binding.module_specifier.clone())
}

/// The module a top-level declarator's initializer denotes, when it denotes one.
///
/// Two spellings produce a module value: a `require` call, whose specifier is
/// its own argument, and a call whose explicit type argument names an already
/// bound module (#2160). Both bind the declared names to that module's exports,
/// so both answer the same question here.
pub fn declarator_module_value_specifier(
    declarator: Node<'_>,
    source: &str,
    imports: &JsTsImportBinder,
) -> Option<String> {
    if let Some(specifier) = commonjs_require_module_specifier_from_declarator(declarator, source) {
        return Some(specifier);
    }
    let value = declarator.child_by_field_name("value")?;
    call_type_argument_module_specifier(value, source, imports)
}

pub fn compute_import_binder(source: &str, tree: &Tree) -> JsTsImportBinder {
    let mut binder = JsTsImportBinder::empty();
    let root = tree.root_node();

    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if child.kind() == "import_statement" {
            visit_import_statement(child, source, &mut binder);
        } else if matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
            visit_commonjs_require_statement(child, source, &mut binder);
        }
    }
    // A module can also be bound by a call that states its own result type, and
    // the namespace binding that type argument names has to be bound already
    // for that to be readable -- so this is a second pass rather than another
    // arm above (#2160).
    bind_type_argument_module_values(root, source, &mut binder);
    binder
}

/// Bind the names a `const actual = importActual<typeof M>('./m')` declaration
/// introduces to `M`'s module, whether it binds the module value itself or
/// destructures exports out of it.
fn bind_type_argument_module_values(root: Node<'_>, source: &str, binder: &mut JsTsImportBinder) {
    let mut bound: Vec<(String, ImportBinding)> = Vec::new();
    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if !matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
            continue;
        }
        let mut cursor = child.walk();
        for declarator in child.named_children(&mut cursor) {
            if declarator.kind() != "variable_declarator" {
                continue;
            }
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(value) = declarator.child_by_field_name("value") else {
                continue;
            };
            let Some(module_specifier) = call_type_argument_module_specifier(value, source, binder)
            else {
                continue;
            };
            match name.kind() {
                "identifier" => {
                    let local = slice(name, source).to_string();
                    if !local.is_empty() {
                        bound.push((
                            local,
                            ImportBinding {
                                module_specifier,
                                namespace_imported_module: None,
                                kind: ImportKind::Namespace,
                                imported_name: None,
                            },
                        ));
                    }
                }
                "object_pattern" => {
                    for entry in object_pattern_entries(name) {
                        let Some(local) = entry.binder.map(|node| slice(node, source)) else {
                            continue;
                        };
                        let imported_name = slice(entry.key, source);
                        if local.is_empty() || imported_name.is_empty() {
                            continue;
                        }
                        bound.push((
                            local.to_string(),
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                namespace_imported_module: None,
                                kind: ImportKind::Named,
                                imported_name: Some(imported_name.to_string()),
                            },
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    for (local, binding) in bound {
        binder.bind_static(local, binding);
    }
}

fn visit_commonjs_require_statement(node: Node<'_>, source: &str, binder: &mut JsTsImportBinder) {
    for binding in parse_commonjs_require_bindings_from_node(node, source) {
        let (kind, imported_name) = match binding.kind {
            CommonJsRequireBindingKind::ModuleObject => (ImportKind::CommonJsRequire, None),
            CommonJsRequireBindingKind::Named => (ImportKind::Named, Some(binding.imported_name)),
        };
        binder.bind_commonjs(
            binding.local_name,
            ImportBinding {
                module_specifier: binding.module_specifier,
                namespace_imported_module: None,
                kind,
                imported_name,
            },
        );
    }
}

fn visit_import_statement(node: Node<'_>, source: &str, binder: &mut JsTsImportBinder) {
    let Some(source_node) = node.child_by_field_name("source") else {
        return;
    };
    let module_specifier = unquote(slice(source_node, source));
    if module_specifier.is_empty() {
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "import_clause" {
            continue;
        }
        let mut clause_cursor = child.walk();
        for clause_child in child.named_children(&mut clause_cursor) {
            match clause_child.kind() {
                "identifier" => {
                    let local = slice(clause_child, source).to_string();
                    if !local.is_empty() {
                        binder.bind_static(
                            local,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                namespace_imported_module: None,
                                kind: ImportKind::Default,
                                imported_name: None,
                            },
                        );
                    }
                }
                "namespace_import" => {
                    let mut ns_cursor = clause_child.walk();
                    let identifier = clause_child
                        .named_children(&mut ns_cursor)
                        .find(|node| node.kind() == "identifier")
                        .map(|node| slice(node, source).to_string());
                    if let Some(local) = identifier
                        && !local.is_empty()
                    {
                        binder.bind_static(
                            local,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                namespace_imported_module: None,
                                kind: ImportKind::Namespace,
                                imported_name: None,
                            },
                        );
                    }
                }
                "named_imports" => {
                    let mut spec_cursor = clause_child.walk();
                    for spec in clause_child.named_children(&mut spec_cursor) {
                        if spec.kind() != "import_specifier" {
                            continue;
                        }
                        let imported_name = spec
                            .child_by_field_name("name")
                            .map(|node| slice(node, source).to_string());
                        let alias = spec
                            .child_by_field_name("alias")
                            .map(|node| slice(node, source).to_string());
                        let local_name = alias
                            .clone()
                            .or_else(|| imported_name.clone())
                            .unwrap_or_default();
                        if local_name.is_empty() {
                            continue;
                        }
                        binder.bind_static(
                            local_name,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                namespace_imported_module: None,
                                kind: ImportKind::Named,
                                imported_name,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    let stripped = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        });
    stripped.unwrap_or(trimmed).to_string()
}

pub fn parse_js_ts_tree(file: &ProjectFile, source: &str, language: Language) -> Option<Tree> {
    let mut parser = Parser::new();
    let tree_sitter_language = crate::parse::js_ts_tree_sitter_language_for_file(file, language)?;
    parser.set_language(&tree_sitter_language).ok()?;
    parser.parse(source, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript grammar");
        parser.parse(source, None).expect("JavaScript tree")
    }

    fn parse_typescript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        parser.parse(source, None).expect("TypeScript tree")
    }

    #[test]
    fn program_binding_reassignment_is_recorded_and_local_shadows_are_not() {
        let source = r#"
function target() {}
function untouched() {}

target = function () {};

function local_shadow() {
  let untouched = 1;
  untouched = 2;
}

function property_write(box) {
  box.untouched = 3;
}
"#;
        let tree = parse_javascript(source);
        let index = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        assert!(index.is_program_binding_reassigned("target", tree.root_node()));
        assert!(!index.is_program_binding_reassigned("untouched", tree.root_node()));
        assert!(!index.is_program_binding_reassigned("missing", tree.root_node()));
    }

    #[test]
    fn lexical_binding_reassignment_distinguishes_same_spelled_scopes() {
        let source = r#"
function outer() {
  const stable = () => 1;
  {
    let stable = () => 2;
    stable = () => 3;
    stable();
  }
  stable();
}
"#;
        let tree = parse_javascript(source);
        let index = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let inner_use = source.find("stable();").expect("inner stable use");
        let outer_use = source.rfind("stable();").expect("outer stable use");

        assert!(index.is_binding_reassigned_at("stable", inner_use));
        assert!(!index.is_binding_reassigned_at("stable", outer_use));
        assert!(!index.is_binding_reassigned_at("missing", outer_use));
    }

    #[test]
    fn commonjs_redeclaration_replaces_binding_without_static_ambiguity() {
        let source = r#"
var { relay } = require("./a");
relay();
var { relay } = require("./b");
relay();
"#;
        let tree = parse_javascript(source);
        let imports = compute_import_binder(source, &tree);

        assert_eq!(imports.bindings_for("relay").count(), 1);
        assert_eq!(
            imports
                .binding("relay")
                .map(|binding| binding.module_specifier.as_str()),
            Some("./b")
        );
        assert!(!imports.has_competing_direct_imports("relay"));
    }

    #[test]
    fn commonjs_binding_does_not_count_as_competing_static_import() {
        let source = r#"
var { relay } = require("./commonjs");
import { relay } from "./static";
relay();
"#;
        let tree = parse_javascript(source);
        let imports = compute_import_binder(source, &tree);

        assert_eq!(imports.direct_bindings_for("relay").count(), 1);
        assert_eq!(imports.resolvable_direct_bindings_for("relay").count(), 2);
        assert!(!imports.has_competing_direct_imports("relay"));
    }

    #[test]
    fn duplicate_static_imports_are_deduplicated_and_bounded() {
        let mut source = String::new();
        source.push_str("import { relay } from \"./same\";\n");
        source.push_str("import { relay } from \"./same\";\n");
        for index in 0..MAX_STATIC_IMPORT_BINDINGS_PER_NAME {
            source.push_str(&format!("import {{ relay }} from \"./module-{index}\";\n"));
        }
        let tree = parse_javascript(&source);
        let imports = compute_import_binder(&source, &tree);

        assert_eq!(
            imports.bindings_for("relay").count(),
            MAX_STATIC_IMPORT_BINDINGS_PER_NAME
        );
        assert!(imports.was_truncated("relay"));
    }

    fn find_node<'tree>(root: Node<'tree>, source: &str, text: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if slice(node, source) == text {
                return node;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        panic!("missing node `{text}`");
    }

    #[test]
    fn static_member_receiver_rejects_private_property_segments() {
        let source = "class Box { #inner; read(other) { return other.#inner.value; } }";
        let tree = parse_javascript(source);
        let private_receiver = find_node(tree.root_node(), source, "other.#inner");

        assert_eq!("member_expression", private_receiver.kind());
        assert_eq!(
            "private_property_identifier",
            private_receiver
                .child_by_field_name("property")
                .expect("private property")
                .kind()
        );
        assert!(static_member_receiver(private_receiver, source).is_none());
    }

    #[test]
    fn direct_property_definitions_include_object_method_shorthand() {
        let source = "const Tools = { parse(value) { return value; } };";
        let tree = parse_javascript(source);
        let method = find_node(tree.root_node(), source, "parse(value) { return value; }");
        let name = method.child_by_field_name("name").expect("method name");
        let target_range = Range {
            start_byte: name.start_byte(),
            end_byte: name.end_byte(),
            start_line: name.start_position().row,
            end_line: name.end_position().row,
        };

        let definitions =
            direct_property_definitions(tree.root_node(), source, &[target_range], "parse");

        assert_eq!(definitions.len(), 1, "{definitions:#?}");
        assert_eq!(slice(definitions[0].receiver.root, source), "Tools");
        assert!(definitions[0].receiver.members.is_empty());
        assert_eq!(definitions[0].property_range, target_range);
    }

    #[test]
    fn static_member_property_names_a_private_field_access() {
        let source = "class Box { #inner; read(other) { return other.#inner.value; } }";
        let tree = parse_javascript(source);
        let private_access = find_node(tree.root_node(), source, "other.#inner");

        let (name_node, name) =
            static_member_property(private_access, source).expect("private property name");
        assert_eq!("#inner", name);
        assert_eq!("private_property_identifier", name_node.kind());
        assert_eq!(
            "#inner",
            slice(name_node, source),
            "the `#` belongs to the name the class indexed it under"
        );
    }

    #[test]
    fn static_member_property_accepts_only_literal_computed_names() {
        let source = r#"task["finish"](); task[name](); task["fi\nish"]();"#;
        let tree = parse_javascript(source);
        let literal = find_node(tree.root_node(), source, r#"task["finish"]"#);
        let dynamic = find_node(tree.root_node(), source, "task[name]");
        let escaped = find_node(tree.root_node(), source, r#"task["fi\nish"]"#);

        let (name_node, name) =
            static_member_property(literal, source).expect("literal property name");
        assert_eq!(name, "finish");
        assert_eq!(slice(name_node, source), "finish");
        let receiver = static_member_receiver(literal, source).expect("literal member receiver");
        assert_eq!(slice(receiver.root, source), "task");
        assert_eq!(receiver.members, vec![name_node]);
        assert!(static_member_property(dynamic, source).is_none());
        assert!(static_member_property(escaped, source).is_none());
    }

    #[test]
    fn static_member_property_accepts_a_terminal_private_name() {
        let source = "this.#value;";
        let tree = parse_javascript(source);
        let member = find_node(tree.root_node(), source, "this.#value");

        let (name_node, name) =
            static_member_property(member, source).expect("private property name");
        assert_eq!(name, "#value");
        assert_eq!(slice(name_node, source), "#value");
        assert!(static_member_receiver(member, source).is_none());
    }

    #[test]
    fn lexical_binding_index_tracks_for_of_and_single_arrow_parameters() {
        let source = r#"
function render(tasks) {
  for (const task of tasks) {
    consume(task.status);
  }
  return tasks.filter(task => task.status);
}
"#;
        let tree = parse_javascript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let for_of_use = source.find("task.status").expect("for-of task");
        let arrow_use = source.rfind("task.status").expect("arrow task");

        assert!(bindings.is_bound_at("task", for_of_use));
        assert!(bindings.is_bound_at("task", arrow_use));
        assert_ne!(
            bindings.binding_scope_at("task", for_of_use),
            bindings.binding_scope_at("task", arrow_use)
        );
    }

    #[test]
    fn lexical_binding_index_retains_the_active_declaration_token() {
        let source = r#"
const fresh = require("fresh");
function outer(fresh) {
  return fresh();
}
fresh();
"#;
        let tree = parse_javascript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let program_use = source.rfind("fresh();").expect("program fresh use");
        let parameter_use = source.find("return fresh").expect("parameter fresh use") + 7;

        assert_eq!(
            bindings.binding_identifier_ranges_at("fresh", program_use),
            vec![Range {
                start_byte: source.find("fresh =").expect("program binder"),
                end_byte: source.find("fresh =").expect("program binder") + "fresh".len(),
                start_line: 1,
                end_line: 1,
            }]
        );
        assert_eq!(
            bindings.binding_identifier_ranges_at("fresh", parameter_use),
            vec![Range {
                start_byte: source.find("fresh) {").expect("parameter binder"),
                end_byte: source.find("fresh) {").expect("parameter binder") + "fresh".len(),
                start_line: 2,
                end_line: 2,
            }]
        );
    }

    #[test]
    fn lexical_binding_index_tracks_typescript_class_names() {
        let source = r#"
export class ApiClient {
  static create() {}
}

ApiClient.create();
"#;
        let tree = parse_typescript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let use_byte = source.rfind("ApiClient.create").expect("static class use");

        assert!(bindings.is_program_binding_at("ApiClient", use_byte, tree.root_node()));
    }

    #[test]
    fn lexical_binding_index_keeps_var_for_of_function_scoped() {
        let source = r#"
function render(tasks) {
  for (var task of tasks) {
    consume(task.status);
  }
  return task.status;
}
"#;
        let tree = parse_javascript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let loop_use = source.find("task.status").expect("loop task");
        let later_use = source.rfind("task.status").expect("later task");

        assert_eq!(
            bindings.binding_scope_at("task", loop_use),
            bindings.binding_scope_at("task", later_use)
        );
    }

    #[test]
    fn lexical_binding_index_tracks_default_imports() {
        let source = "import window from \"./shim.js\";\nwindow.Promise = value;";
        let tree = parse_javascript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let use_byte = source.rfind("window.Promise").expect("window use");

        assert!(bindings.is_program_binding_at("window", use_byte, tree.root_node()));
    }

    #[test]
    fn lexical_binding_index_hoists_var_to_the_function_scope() {
        let source = r#"
function read() {
  const before = typeof Promise;
  var Promise;
  return before;
}
"#;
        let tree = parse_javascript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let use_byte = source.find("Promise;").expect("Promise read");

        assert!(bindings.is_bound_at("Promise", use_byte));
    }

    #[test]
    fn lexical_binding_index_does_not_declare_bare_for_of_target() {
        let source = "for (task of tasks) { consume(task.status); }";
        let tree = parse_javascript(source);
        let bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let use_byte = source.find("task.status").expect("task use");

        assert!(!bindings.is_bound_at("task", use_byte));
    }
}
