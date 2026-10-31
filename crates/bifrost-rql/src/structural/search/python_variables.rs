//! Query-local Python lexical-variable identities and their source facts.
//!
//! A binding row names one binder token. Python's local variable is the
//! resolved `(scope, name)` pair shared by those tokens, so this projection
//! derives that identity from the parsed file for the lifetime of one query.

use super::python_rule_facts::{PythonRuleFactValue, make_row, named_children, row_range};
use super::*;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::structural::lexical_environment::{BindingRow, EnvironmentFileResult};
use crate::analyzer::structural::occurrence_rows::OccurrenceRow;
use crate::analyzer::structural::resolution::EnvironmentAxis;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

const VARIABLE_ID_DOMAIN: &[u8] = b"bifrost.code_query.python_lexical_variable.v1";

#[derive(Debug, Clone)]
pub(super) struct PythonVariableDefinition {
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) range: CodeQueryRange,
    pub(super) kind: &'static str,
    /// Exact assignment RHS for a direct identifier target. The source bytes
    /// are retained as offsets so a structural matcher can join this local
    /// binding to the same normalized expression without comparing spellings.
    pub(super) assignment_value: Option<(usize, usize)>,
    /// Whether a direct assignment is unconditional in its enclosing scope.
    pub(super) assignment_unconditional: bool,
    /// Immediate suite and containing statement, recorded once during indexing.
    statement_location: Option<((usize, usize), (usize, usize))>,
    pub(super) order: usize,
    pub(super) first: bool,
    pub(super) reachability: &'static str,
    pub(super) in_main_guard: bool,
    pub(super) optimizing_parameter: bool,
    pub(super) self_assignment: bool,
    pub(super) is_unused: bool,
    pub(super) annotation_only: bool,
    pub(super) annotated_assignment: bool,
    pub(super) is_decorated: bool,
    pub(super) is_abstract: bool,
    pub(super) is_pytest_fixture: bool,
    pub(super) is_overriding_method: Option<bool>,
    pub(super) is_overridden_method: Option<bool>,
    pub(super) loop_info: Option<PythonVariableLoopInfo>,
}

#[derive(Debug, Clone)]
pub(super) struct PythonVariableLoopInfo {
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) range: CodeQueryRange,
    body_start_byte: usize,
    body_end_byte: usize,
    statement_container: (usize, usize),
    statement: (usize, usize),
    pub(super) has_body_read: bool,
    pub(super) policy_excluded: bool,
    body_unconditionally_redefines: bool,
}

#[derive(Debug, Clone)]
pub(super) struct PythonVariableUse {
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) range: CodeQueryRange,
    pub(super) access: &'static str,
    pub(super) nested_scope: bool,
    statement_container: Option<(usize, usize)>,
    statement: Option<(usize, usize)>,
}

#[derive(Debug, Clone)]
pub(super) struct PythonVariableFacts {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) scope_kind: &'static str,
    scope_start_byte: usize,
    scope_end_byte: usize,
    write_inventory_open: bool,
    pub(super) is_global: bool,
    pub(super) is_nonlocal: bool,
    pub(super) is_builtin: bool,
    pub(super) has_read: bool,
    pub(super) definitions: Vec<PythonVariableDefinition>,
    pub(super) uses: Vec<PythonVariableUse>,
    pub(super) complete: bool,
    pub(super) reason: Option<String>,
    content_identity: crate::analyzer::semantic::ContentIdentity,
}

#[derive(Debug, Default)]
pub(super) struct PythonVariableIndex {
    groups: Vec<Arc<PythonVariableFacts>>,
    nodes: HashMap<(usize, usize), usize>,
    by_name: HashMap<String, Vec<usize>>,
}

#[derive(Debug, Clone)]
enum PythonLocalValueAnswer {
    Unknown,
    Known(Vec<u32>),
}

#[derive(Debug, Default)]
pub(super) struct PythonLocalValueOracle {
    answers: HashMap<(usize, usize), PythonLocalValueAnswer>,
}

impl super::super::matcher::LocalValueOracle for PythonLocalValueOracle {
    fn lookup(&self, range: Range) -> Option<&[u32]> {
        match self.answers.get(&(range.start_byte, range.end_byte))? {
            PythonLocalValueAnswer::Unknown => None,
            PythonLocalValueAnswer::Known(targets) => Some(targets),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LexicalScopeKind {
    Module,
    Function,
    Class,
    Comprehension,
}

impl LexicalScopeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Function => "function",
            Self::Class => "class",
            Self::Comprehension => "comprehension",
        }
    }
}

struct LexicalScope<'tree> {
    node: Node<'tree>,
    parent: Option<usize>,
    kind: LexicalScopeKind,
    globals: HashSet<String>,
    nonlocals: HashSet<String>,
    // A wildcard import can write names without individual binder tokens.
    write_inventory_open: bool,
}

#[derive(Clone)]
struct RawDefinition<'tree> {
    name: String,
    node: Node<'tree>,
    scope: usize,
    kind: &'static str,
}

#[derive(Clone)]
struct ResolvedDefinition<'tree> {
    name: String,
    node: Node<'tree>,
    scope: usize,
    source_scope: usize,
    kind: &'static str,
    is_global: bool,
    is_nonlocal: bool,
}

struct LocalClassInfo {
    node_id: usize,
    name: String,
    bases: Vec<String>,
    methods: HashSet<String>,
}

#[derive(Debug)]
struct MutableVariable {
    scope: usize,
    name: String,
    is_global: bool,
    is_nonlocal: bool,
    definitions: Vec<PythonVariableDefinition>,
    uses: Vec<PythonVariableUse>,
}

impl PythonVariableIndex {
    pub(super) fn groups(&self) -> impl Iterator<Item = &Arc<PythonVariableFacts>> {
        self.groups.iter()
    }

    fn same_name_peers(
        &self,
        facts: &PythonVariableFacts,
    ) -> impl Iterator<Item = &Arc<PythonVariableFacts>> {
        self.by_name
            .get(&facts.name)
            .into_iter()
            .flatten()
            .filter_map(|index| self.groups.get(*index))
            .filter(move |peer| peer.id != facts.id)
    }

    pub(super) fn for_occurrence(
        &self,
        occurrence: &OccurrenceRow,
    ) -> Option<Arc<PythonVariableFacts>> {
        let index = self
            .nodes
            .get(&(occurrence.range.start_byte, occurrence.range.end_byte))?;
        self.groups.get(*index).cloned()
    }

    pub(super) fn for_binding(&self, binding: &BindingRow) -> Option<Arc<PythonVariableFacts>> {
        let exact = self
            .nodes
            .get(&(binding.range.start_byte, binding.range.end_byte))
            .copied();
        exact
            .or_else(|| {
                self.groups.iter().position(|group| {
                    group.name == binding.name
                        && group.definitions.iter().any(|definition| {
                            definition.start_byte <= binding.range.start_byte
                                && binding.range.end_byte <= definition.end_byte
                        })
                })
            })
            .and_then(|index| self.groups.get(index).cloned())
    }
}

/// One query's existing variable inventory and dynamic-write evidence. The
/// environment cache builds the inventory once per file, not per identifier.
/// Shared stability premises support assignment initializers and freshly
/// declared function objects. Mutable initializer contents still need a
/// separate consumer proof.
#[derive(Clone)]
pub(super) struct PythonInitializerProof {
    pub(super) index: Arc<PythonVariableIndex>,
    pub(super) dynamic_scope_calls: Arc<Vec<Range>>,
}

#[derive(Debug)]
pub(super) enum PythonInitializerFailure {
    Incomplete,
    DifferentOwner,
    ExternalWrite,
    OpenNamespace,
    DynamicWrite,
    AugmentedWrite,
    MultipleDefinitions,
    NotAssignment,
    Conditional,
    MissingValue,
    AfterUse,
}

impl PythonVariableFacts {
    fn stable_definition_for_read(
        &self,
        usage: &PythonVariableUse,
        dynamic_scope_calls: &[Range],
    ) -> Result<&PythonVariableDefinition, PythonInitializerFailure> {
        use PythonInitializerFailure::*;
        if !self.complete {
            return Err(Incomplete);
        }
        if usage.nested_scope || !matches!(self.scope_kind, "module" | "function") {
            return Err(DifferentOwner);
        }
        if self.is_global || self.is_nonlocal {
            return Err(ExternalWrite);
        }
        if self.write_inventory_open {
            return Err(OpenNamespace);
        }
        if dynamic_scope_calls.iter().any(|call| {
            self.scope_start_byte <= call.start_byte && call.end_byte <= self.scope_end_byte
        }) {
            return Err(DynamicWrite);
        }
        if self
            .definitions
            .iter()
            .any(|definition| definition.kind == "augmented")
        {
            return Err(AugmentedWrite);
        }
        let [definition] = self.definitions.as_slice() else {
            return Err(MultipleDefinitions);
        };
        Ok(definition)
    }

    fn initializer_for_read(
        &self,
        usage: &PythonVariableUse,
        dynamic_scope_calls: &[Range],
    ) -> Result<(usize, usize), PythonInitializerFailure> {
        use PythonInitializerFailure::*;
        let definition = self.stable_definition_for_read(usage, dynamic_scope_calls)?;
        if definition.kind != "assignment" {
            return Err(NotAssignment);
        }
        // A branch-local assignment can still be guaranteed before this read.
        // Identical immediate suites exclude sibling branches and reads after
        // a possibly skipped loop or a caught initializer exception.
        if !definition.assignment_unconditional
            && !definition
                .statement_location
                .is_some_and(|(container, statement)| {
                    usage.statement_container == Some(container)
                        && usage
                            .statement
                            .is_some_and(|usage_statement| statement.1 <= usage_statement.0)
                })
        {
            return Err(Conditional);
        }
        let value = definition.assignment_value.ok_or(MissingValue)?;
        if value.1 > usage.start_byte {
            return Err(AfterUse);
        }
        Ok(value)
    }
}

impl PythonInitializerProof {
    /// A freshly bound local function object is not a tuple. Adjacency is
    /// intentional: identifier-write facts alone cannot rule out intervening
    /// callbacks or reflective closure-cell mutation.
    pub(super) fn is_fresh_function_return(
        &self,
        callable: Node<'_>,
        return_node: Node<'_>,
        expression: Node<'_>,
    ) -> bool {
        if expression.kind() != "identifier" {
            return false;
        }
        let Some(variable) = self
            .index
            .nodes
            .get(&(expression.start_byte(), expression.end_byte()))
            .and_then(|index| self.index.groups.get(*index))
        else {
            return false;
        };
        // A captured cell can be rebound by nonlocal without writing this
        // scope's identifier, so any nested-scope use keeps the proof open.
        if variable.scope_kind != "function"
            || (variable.scope_start_byte, variable.scope_end_byte)
                != (callable.start_byte(), callable.end_byte())
            || variable.uses.iter().any(|usage| usage.nested_scope)
        {
            return false;
        }
        let Some(usage) = variable.uses.iter().find(|usage| {
            usage.access == "read"
                && (usage.start_byte, usage.end_byte)
                    == (expression.start_byte(), expression.end_byte())
        }) else {
            return false;
        };
        let Ok(definition) = variable.stable_definition_for_read(usage, &self.dynamic_scope_calls)
        else {
            return false;
        };
        if definition.kind != "function_declaration" || definition.is_decorated {
            return false;
        }
        let Some(container) = return_node
            .parent()
            .filter(|parent| parent.kind() == "block")
        else {
            return false;
        };
        let mut previous = return_node.prev_named_sibling();
        while previous.is_some_and(|node| node.is_extra()) {
            previous = previous.and_then(|node| node.prev_named_sibling());
        }
        let Some(previous) = previous.filter(|node| node.kind() == "function_definition") else {
            return false;
        };
        previous.child_by_field_name("name").is_some_and(|name| {
            (name.start_byte(), name.end_byte()) == (definition.start_byte, definition.end_byte)
        }) && definition.statement_location
            == Some((
                (container.start_byte(), container.end_byte()),
                (previous.start_byte(), previous.end_byte()),
            ))
            && usage.statement_container == Some((container.start_byte(), container.end_byte()))
            && usage.statement == Some((return_node.start_byte(), return_node.end_byte()))
            && previous.end_byte() <= expression.start_byte()
    }

    pub(super) fn for_binding_read(
        &self,
        binding: &BindingRow,
        use_range: (usize, usize),
    ) -> Result<(usize, usize), PythonInitializerFailure> {
        let variable = self
            .index
            .for_binding(binding)
            .ok_or(PythonInitializerFailure::Incomplete)?;
        let usage = variable
            .uses
            .iter()
            .find(|usage| usage.access == "read" && (usage.start_byte, usage.end_byte) == use_range)
            .ok_or(PythonInitializerFailure::DifferentOwner)?;
        variable.initializer_for_read(usage, &self.dynamic_scope_calls)
    }
}

pub(super) fn local_value_oracle(
    index: &PythonVariableIndex,
    facts: &super::super::facts::FileFacts,
    dynamic_scope_calls: &[Range],
) -> PythonLocalValueOracle {
    let mut expression_nodes = HashMap::<(usize, usize), Vec<u32>>::new();
    for (index, node) in facts.nodes().iter().enumerate() {
        expression_nodes
            .entry((node.range.start_byte, node.range.end_byte))
            .or_default()
            .push(u32::try_from(index).expect("normalized node ids fit in u32"));
    }

    let mut oracle = PythonLocalValueOracle::default();
    for variable in index.groups() {
        for usage in &variable.uses {
            if usage.access != "read" {
                continue;
            }
            let key = (usage.start_byte, usage.end_byte);
            let answer = if !variable.complete || usage.nested_scope {
                PythonLocalValueAnswer::Unknown
            } else if variable.scope_kind != "function"
                || variable.is_global
                || variable.is_nonlocal
            {
                PythonLocalValueAnswer::Known(Vec::new())
            } else {
                match variable.initializer_for_read(usage, dynamic_scope_calls) {
                    Ok(value) => match expression_nodes.get(&value).map(Vec::as_slice) {
                        Some([target]) => PythonLocalValueAnswer::Known(vec![*target]),
                        _ => PythonLocalValueAnswer::Unknown,
                    },
                    Err(
                        PythonInitializerFailure::NotAssignment
                        | PythonInitializerFailure::AfterUse,
                    ) => PythonLocalValueAnswer::Known(Vec::new()),
                    Err(PythonInitializerFailure::AugmentedWrite)
                        if variable.definitions.len() == 1 =>
                    {
                        PythonLocalValueAnswer::Known(Vec::new())
                    }
                    Err(_) => PythonLocalValueAnswer::Unknown,
                }
            };
            oracle.answers.insert(key, answer);
        }
    }
    oracle
}

fn scope_kind(node: Node<'_>) -> Option<LexicalScopeKind> {
    match node.kind() {
        "module" => Some(LexicalScopeKind::Module),
        "function_definition" | "lambda" => Some(LexicalScopeKind::Function),
        "class_definition" => Some(LexicalScopeKind::Class),
        "list_comprehension"
        | "set_comprehension"
        | "dictionary_comprehension"
        | "generator_expression" => Some(LexicalScopeKind::Comprehension),
        _ => None,
    }
}

fn syntax_nodes<'tree>(root: Node<'tree>) -> Vec<Node<'tree>> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        nodes.push(node);
        stack.extend(named_children(node).into_iter().rev());
    }
    nodes
}

fn contains_node(outer: Node<'_>, inner: Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

fn enclosing_scope(node: Node<'_>, scope_by_node: &HashMap<usize, usize>) -> usize {
    let mut current = node;
    loop {
        if let Some(scope) = scope_by_node.get(&current.id()) {
            return *scope;
        }
        let Some(parent) = current.parent() else {
            return 0;
        };
        current = parent;
    }
}

fn is_parameter_binder(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "parameters"
            | "lambda_parameters"
            | "typed_parameter"
            | "typed_default_parameter"
            | "default_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern"
    ) && brokk_bifrost_python::declarations::python_parameter_label_node(parent)
        .is_some_and(|label| label.id() == node.id())
}

fn in_scope_header(node: Node<'_>, scope: &LexicalScope<'_>) -> bool {
    match scope.node.kind() {
        "function_definition" | "class_definition" => scope
            .node
            .child_by_field_name("body")
            .is_none_or(|body| !contains_node(body, node)),
        "lambda" => scope
            .node
            .child_by_field_name("body")
            .is_none_or(|body| !contains_node(body, node)),
        _ => false,
    }
}

fn effective_scope<'tree>(
    node: Node<'tree>,
    scopes: &[LexicalScope<'tree>],
    scope_by_node: &HashMap<usize, usize>,
) -> usize {
    let scope = enclosing_scope(node, scope_by_node);
    let info = &scopes[scope];
    if info.kind == LexicalScopeKind::Comprehension {
        let clauses = named_children(info.node)
            .into_iter()
            .filter(|child| child.kind() == "for_in_clause")
            .collect::<Vec<_>>();
        if let Some(first) = clauses.first()
            && first
                .child_by_field_name("right")
                .is_some_and(|right| contains_node(right, node))
        {
            return info.parent.unwrap_or(0);
        }
    }
    if is_parameter_binder(node) {
        return scope;
    }
    if in_scope_header(node, info) {
        return info.parent.unwrap_or(0);
    }
    scope
}

fn definition_scope<'tree>(
    node: Node<'tree>,
    kind: &'static str,
    scopes: &[LexicalScope<'tree>],
    scope_by_node: &HashMap<usize, usize>,
) -> usize {
    if matches!(kind, "function_declaration" | "class_declaration") {
        return scopes[enclosing_scope(node, scope_by_node)]
            .parent
            .unwrap_or(0);
    }
    if kind == "parameter" {
        return enclosing_scope(node, scope_by_node);
    }
    let mut scope = effective_scope(node, scopes, scope_by_node);
    if kind == "assignment" {
        while scopes[scope].kind == LexicalScopeKind::Comprehension {
            scope = scopes[scope].parent.unwrap_or(0);
        }
    }
    scope
}

fn collect_target_identifiers<'tree>(target: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "attribute" | "subscript" => continue,
            "identifier" | "keyword_identifier" => {
                out.push(node);
                continue;
            }
            "as_pattern_target" if node.named_child_count() == 0 => {
                out.push(node);
                continue;
            }
            _ => {}
        }
        stack.extend(named_children(node).into_iter().rev());
    }
}

fn add_binding_nodes<'tree>(
    container: Node<'tree>,
    kind: &'static str,
    source: &str,
    output: &mut Vec<RawDefinition<'tree>>,
    seen: &mut HashSet<usize>,
) {
    if let Some(bindings) = brokk_bifrost_python::bindings::python_direct_scope_bindings_bounded(
        container,
        source,
        || true,
    ) {
        for binding in bindings {
            let definition_kind = match binding.kind {
                brokk_bifrost_python::bindings::PythonDirectScopeBindingKind::FunctionDeclaration => {
                    "function_declaration"
                }
                brokk_bifrost_python::bindings::PythonDirectScopeBindingKind::ClassDeclaration => {
                    "class_declaration"
                }
                brokk_bifrost_python::bindings::PythonDirectScopeBindingKind::Import => "import",
                brokk_bifrost_python::bindings::PythonDirectScopeBindingKind::Other => kind,
            };
            if seen.insert(binding.declaration.id())
                && let Some(name) = super::python_rule_facts::node_text(source, binding.declaration)
            {
                output.push(RawDefinition {
                    name: name.to_owned(),
                    node: binding.declaration,
                    scope: 0,
                    kind: definition_kind,
                });
            }
        }
    }
}

fn raw_definitions<'tree>(root: Node<'tree>, source: &str) -> Vec<RawDefinition<'tree>> {
    let nodes = syntax_nodes(root);
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for node in nodes.iter().copied() {
        match node.kind() {
            "function_definition" => {
                add_binding_nodes(node, "function_declaration", source, &mut output, &mut seen);
            }
            "class_definition" => {
                add_binding_nodes(node, "class_declaration", source, &mut output, &mut seen);
            }
            "parameters" | "lambda_parameters" => {
                for parameter in named_children(node) {
                    if let Some(name) =
                        brokk_bifrost_python::declarations::python_parameter_label_node(parameter)
                        && seen.insert(name.id())
                        && let Some(spelling) = super::python_rule_facts::node_text(source, name)
                    {
                        output.push(RawDefinition {
                            name: spelling.to_owned(),
                            node: name,
                            scope: 0,
                            kind: "parameter",
                        });
                    }
                }
            }
            "assignment" | "type_alias_statement" | "named_expression" => {
                add_binding_nodes(node, "assignment", source, &mut output, &mut seen);
            }
            "augmented_assignment" => {
                add_binding_nodes(node, "augmented", source, &mut output, &mut seen);
            }
            "for_statement" | "for_in_clause" => {
                if node.kind() == "for_statement" {
                    add_binding_nodes(node, "loop_target", source, &mut output, &mut seen);
                } else if let Some(target) = node.child_by_field_name("left") {
                    let mut targets = Vec::new();
                    collect_target_identifiers(target, &mut targets);
                    for target in targets {
                        if seen.insert(target.id())
                            && let Some(name) = super::python_rule_facts::node_text(source, target)
                        {
                            output.push(RawDefinition {
                                name: name.to_owned(),
                                node: target,
                                scope: 0,
                                kind: "loop_target",
                            });
                        }
                    }
                }
            }
            "delete_statement" => {
                add_binding_nodes(node, "del", source, &mut output, &mut seen);
            }
            "import_statement" | "import_from_statement" => {
                add_binding_nodes(node, "import", source, &mut output, &mut seen);
            }
            "with_item" => {
                if let Some(target) = node
                    .child_by_field_name("alias")
                    .or_else(|| node.child_by_field_name("optional_vars"))
                {
                    let mut targets = Vec::new();
                    collect_target_identifiers(target, &mut targets);
                    for target in targets {
                        if seen.insert(target.id())
                            && let Some(name) = super::python_rule_facts::node_text(source, target)
                        {
                            output.push(RawDefinition {
                                name: name.to_owned(),
                                node: target,
                                scope: 0,
                                kind: "with_target",
                            });
                        }
                    }
                }
            }
            "except_clause" => {
                add_binding_nodes(node, "except_target", source, &mut output, &mut seen);
            }
            "as_pattern" | "case_clause" => {
                add_binding_nodes(node, "pattern_target", source, &mut output, &mut seen);
            }
            _ => {}
        }
    }
    output
}

fn is_in_import_or_directive(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "import_statement"
                | "import_from_statement"
                | "global_statement"
                | "nonlocal_statement"
        ) {
            return true;
        }
        current = parent;
    }
    false
}

fn is_attribute_label(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "attribute"
            && parent
                .child_by_field_name("attribute")
                .is_some_and(|attribute| attribute.id() == node.id())
    })
}

fn is_keyword_label(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "keyword_argument"
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id())
    })
}

fn local_names(
    definitions: &[RawDefinition<'_>],
    scopes: &[LexicalScope<'_>],
) -> Vec<HashSet<String>> {
    let mut names = vec![HashSet::new(); scopes.len()];
    for definition in definitions {
        names[definition.scope].insert(definition.name.to_owned());
    }
    for (index, scope) in scopes.iter().enumerate() {
        names[index]
            .retain(|name| !scope.globals.contains(name) && !scope.nonlocals.contains(name));
        if index != 0 {
            names[0].extend(scope.globals.iter().cloned());
        }
    }
    names
}

fn nonlocal_owner(
    name: &str,
    scope: usize,
    scopes: &[LexicalScope<'_>],
    locals: &[HashSet<String>],
) -> Option<usize> {
    let mut current = scopes[scope].parent;
    while let Some(index) = current {
        if scopes[index].kind == LexicalScopeKind::Function
            && locals[index].contains(name)
            && !scopes[index].globals.contains(name)
            && !scopes[index].nonlocals.contains(name)
        {
            return Some(index);
        }
        current = scopes[index].parent;
    }
    None
}

fn resolved_scope(
    name: &str,
    scope: usize,
    scopes: &[LexicalScope<'_>],
    locals: &[HashSet<String>],
) -> Option<(usize, bool, bool)> {
    let info = &scopes[scope];
    if info.kind == LexicalScopeKind::Comprehension && locals[scope].contains(name) {
        return Some((scope, false, false));
    }
    if info.globals.contains(name) {
        return Some((0, true, false));
    }
    if info.nonlocals.contains(name) {
        return nonlocal_owner(name, scope, scopes, locals).map(|owner| (owner, false, true));
    }
    if locals[scope].contains(name) {
        return Some((scope, false, false));
    }

    let mut current = info.parent;
    while let Some(index) = current {
        let parent = &scopes[index];
        if parent.kind == LexicalScopeKind::Class
            && info.kind != LexicalScopeKind::Class
            && info.kind != LexicalScopeKind::Module
        {
            current = parent.parent;
            continue;
        }
        if parent.globals.contains(name) {
            return Some((0, true, false));
        }
        if parent.nonlocals.contains(name)
            && let Some(owner) = nonlocal_owner(name, index, scopes, locals)
        {
            return Some((owner, false, true));
        }
        if locals[index].contains(name) {
            return Some((index, false, false));
        }
        current = parent.parent;
    }
    (locals[0].contains(name)).then_some((0, false, false))
}

fn is_closure_access(
    source_scope: usize,
    variable_scope: usize,
    scopes: &[LexicalScope<'_>],
    is_global: bool,
) -> bool {
    source_scope != variable_scope
        && scopes[variable_scope].kind == LexicalScopeKind::Function
        && !is_global
}

fn definition_range(source: &str, node: Node<'_>) -> CodeQueryRange {
    row_range(source, node.start_byte()..node.end_byte())
}

fn statement_location(node: Node<'_>) -> Option<((usize, usize), (usize, usize))> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "block" | "module") {
            return Some((
                (parent.start_byte(), parent.end_byte()),
                (current.start_byte(), current.end_byte()),
            ));
        }
        current = parent;
    }
    None
}

fn assignment_value(node: Node<'_>, kind: &str) -> (Option<(usize, usize)>, bool) {
    if kind != "assignment" {
        return (None, false);
    }
    let Some(assignment) = node.parent().filter(|parent| parent.kind() == "assignment") else {
        return (None, false);
    };
    if !assignment
        .child_by_field_name("left")
        .is_some_and(|left| left.id() == node.id())
    {
        return (None, false);
    }
    let value = assignment
        .child_by_field_name("right")
        .map(|right| (right.start_byte(), right.end_byte()));
    let mut current = assignment.parent();
    let mut unconditional = true;
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "function_definition" | "lambda" | "class_definition" | "module"
        ) {
            break;
        }
        if matches!(
            ancestor.kind(),
            "if_statement"
                | "elif_clause"
                | "else_clause"
                | "for_statement"
                | "while_statement"
                | "try_statement"
                | "except_clause"
                | "finally_clause"
                | "with_statement"
                | "match_statement"
                | "case_clause"
                | "conditional_expression"
        ) {
            unconditional = false;
            break;
        }
        current = ancestor.parent();
    }
    (value, unconditional)
}

fn statement_may_exit(node: Node<'_>) -> bool {
    let mut stack = vec![(node, false)];
    while let Some((current, inside_loop)) = stack.pop() {
        if scope_kind(current).is_some() {
            continue;
        }
        if current.kind() == "return_statement"
            || (!inside_loop && matches!(current.kind(), "break_statement" | "continue_statement"))
        {
            return true;
        }
        let inside_loop =
            inside_loop || matches!(current.kind(), "for_statement" | "while_statement");
        stack.extend(
            named_children(current)
                .into_iter()
                .map(|child| (child, inside_loop)),
        );
    }
    false
}

fn loop_body_unconditionally_redefines(
    body: Node<'_>,
    name: &str,
    scope: usize,
    definitions: &[ResolvedDefinition<'_>],
) -> bool {
    let body_range = (body.start_byte(), body.end_byte());
    let statements = named_children(body);
    statements.iter().enumerate().any(|(index, statement)| {
        let statement_range = (statement.start_byte(), statement.end_byte());
        let redefines = definitions.iter().any(|definition| {
            definition.name == name
                && definition.scope == scope
                && matches!(definition.kind, "assignment" | "augmented")
                && statement_location(definition.node).is_some_and(
                    |(container, direct_statement)| {
                        container == body_range && direct_statement == statement_range
                    },
                )
        });
        redefines
            && statements[..index]
                .iter()
                .all(|prior| !statement_may_exit(*prior))
    })
}

fn in_main_guard(node: Node<'_>, source: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            return false;
        }
        if parent.kind() == "if_statement"
            && parent
                .child_by_field_name("consequence")
                .is_some_and(|body| body.id() == current.id())
            && let Some(condition) = parent.child_by_field_name("condition")
            && condition.kind() == "comparison_operator"
        {
            let mut cursor = condition.walk();
            let operators = condition
                .children_by_field_name("operators", &mut cursor)
                .map(|operator| operator.kind())
                .collect::<Vec<_>>();
            let operands = named_children(condition);
            if operators.as_slice() == ["=="]
                && let [left, right] = operands.as_slice()
                && super::python_rule_facts::node_text(source, *left) == Some("__name__")
                && brokk_bifrost_python::syntax::python_plain_string_literal(*right, source)
                    == Some("__main__")
            {
                return true;
            }
        }
        current = parent;
    }
    false
}

fn optimizing_parameter(node: Node<'_>, source: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "parameters" | "lambda_parameters") {
            return false;
        }
        if matches!(
            parent.kind(),
            "default_parameter" | "typed_default_parameter"
        ) && brokk_bifrost_python::declarations::python_parameter_label_node(parent).is_some_and(
            |label| {
                super::python_rule_facts::node_text(source, label)
                    .zip(parent.child_by_field_name("value"))
                    .is_some_and(|(name, value)| {
                        value.kind() == "identifier"
                            && super::python_rule_facts::node_text(source, value) == Some(name)
                    })
            },
        ) {
            return true;
        }
        current = parent;
    }
    false
}

fn self_assignment(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "assignment"
        || !parent
            .child_by_field_name("left")
            .is_some_and(|left| contains_node(left, node))
    {
        return false;
    }
    let Some(right) = parent.child_by_field_name("right") else {
        return false;
    };
    right.kind() == "identifier"
        && super::python_rule_facts::node_text(source, right)
            == super::python_rule_facts::node_text(source, node)
}

fn declaration_node<'tree>(node: Node<'tree>, kind: &'static str) -> Option<Node<'tree>> {
    let declaration_kind = match kind {
        "function_declaration" => "function_definition",
        "class_declaration" => "class_definition",
        _ => return None,
    };
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == declaration_kind {
            return Some(parent);
        }
        if matches!(
            parent.kind(),
            "module" | "function_definition" | "class_definition"
        ) {
            return None;
        }
        current = parent;
    }
    None
}

fn enclosing_function<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "function_definition" | "lambda" => return Some(parent),
            "module" | "class_definition" => return None,
            _ => current = parent,
        }
    }
    None
}

fn function_class<'tree>(function: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = function;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "class_definition" => return Some(parent),
            "function_definition" | "lambda" | "module" => return None,
            _ => current = parent,
        }
    }
    None
}

fn class_base_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => super::python_rule_facts::node_text(source, node).map(str::to_owned),
        // Retain the qualified identity: a local bare name cannot prove its ancestry.
        "attribute" => super::python_rule_facts::node_text(source, node).map(str::to_owned),
        _ => None,
    }
}

fn local_class_infos(nodes: &[Node<'_>], source: &str) -> Vec<LocalClassInfo> {
    let mut classes = nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "class_definition")
        .filter_map(|class| {
            let name = class
                .child_by_field_name("name")
                .and_then(|name| super::python_rule_facts::node_text(source, name))?
                .to_owned();
            let bases = class
                .child_by_field_name("superclasses")
                .map(named_children)
                .unwrap_or_default()
                .into_iter()
                .filter(|base| base.kind() != "keyword_argument")
                .filter_map(|base| {
                    let base = brokk_bifrost_python::declarations::python_base_origin_node(base);
                    class_base_name(base, source)
                })
                .collect();
            Some(LocalClassInfo {
                node_id: class.id(),
                name,
                bases,
                methods: HashSet::default(),
            })
        })
        .collect::<Vec<_>>();
    for function in nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "function_definition")
    {
        let Some(class) = function_class(function) else {
            continue;
        };
        let Some(name) = function
            .child_by_field_name("name")
            .and_then(|name| super::python_rule_facts::node_text(source, name))
        else {
            continue;
        };
        if let Some(info) = classes.iter_mut().find(|info| info.node_id == class.id()) {
            info.methods.insert(name.to_owned());
        }
    }
    classes
}

fn local_class_index(classes: &[LocalClassInfo]) -> HashMap<String, Option<usize>> {
    let mut class_by_name = HashMap::<String, Option<usize>>::new();
    for (index, info) in classes.iter().enumerate() {
        match class_by_name.entry(info.name.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(index));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
    class_by_name
}

fn class_inherits_from(
    class_index: usize,
    ancestor_name: &str,
    classes: &[LocalClassInfo],
    class_by_name: &HashMap<String, Option<usize>>,
) -> Option<bool> {
    let mut pending = classes[class_index].bases.clone();
    let mut visited = HashSet::new();
    let mut complete = true;
    while let Some(name) = pending.pop() {
        if name == ancestor_name {
            return Some(true);
        }
        if !visited.insert(name.clone()) || name == "object" {
            continue;
        }
        match class_by_name.get(&name) {
            Some(Some(index)) => pending.extend(classes[*index].bases.iter().cloned()),
            Some(None) | None => complete = false,
        }
    }
    complete.then_some(false)
}

fn method_override_flags(
    function: Node<'_>,
    source: &str,
    classes: &[LocalClassInfo],
    class_by_name: &HashMap<String, Option<usize>>,
) -> (Option<bool>, Option<bool>) {
    let Some(class) = function_class(function) else {
        return (Some(false), Some(false));
    };
    let Some(class_index) = classes.iter().position(|info| info.node_id == class.id()) else {
        return (None, None);
    };
    let Some(method_name) = function
        .child_by_field_name("name")
        .and_then(|name| super::python_rule_facts::node_text(source, name))
    else {
        return (None, None);
    };
    let mut overrides = false;
    let mut override_complete = true;
    for base in classes[class_index].bases.iter() {
        if base == "object" {
            continue;
        }
        match class_by_name.get(base) {
            Some(Some(base_index)) => {
                if classes[*base_index].methods.contains(method_name) {
                    overrides = true;
                    break;
                }
                let mut pending = classes[*base_index].bases.clone();
                let mut visited = HashSet::from([*base_index]);
                while let Some(ancestor_name) = pending.pop() {
                    if ancestor_name == "object" {
                        continue;
                    }
                    match class_by_name.get(&ancestor_name) {
                        Some(Some(ancestor)) => {
                            if classes[*ancestor].methods.contains(method_name) {
                                overrides = true;
                                break;
                            }
                            if visited.insert(*ancestor) {
                                pending.extend(classes[*ancestor].bases.iter().cloned());
                            }
                        }
                        Some(None) | None => override_complete = false,
                    }
                }
            }
            Some(None) | None => override_complete = false,
        }
    }
    let is_overriding = if overrides {
        Some(true)
    } else if classes[class_index].bases.is_empty() || override_complete {
        Some(false)
    } else {
        None
    };

    let mut is_overridden = false;
    let mut overridden_complete = true;
    for (index, info) in classes.iter().enumerate() {
        if index == class_index || !info.methods.contains(method_name) {
            continue;
        }
        match class_inherits_from(index, &classes[class_index].name, classes, class_by_name) {
            Some(true) => is_overridden = true,
            Some(false) => {}
            None => overridden_complete = false,
        }
    }
    (
        is_overriding,
        if is_overridden {
            Some(true)
        } else if overridden_complete {
            Some(false)
        } else {
            None
        },
    )
}

fn annotated_assignment_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "assignment"
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| contains_node(left, node))
        {
            return parent.child_by_field_name("type").map(|_| parent);
        }
        if matches!(
            parent.kind(),
            "module" | "function_definition" | "class_definition"
        ) {
            return None;
        }
        current = parent;
    }
    None
}

fn annotation_only(node: Node<'_>) -> bool {
    annotated_assignment_node(node)
        .is_some_and(|assignment| assignment.child_by_field_name("right").is_none())
}

fn annotated_assignment(node: Node<'_>) -> bool {
    annotated_assignment_node(node).is_some()
}

fn pytest_module_aliases(environment: &EnvironmentFileResult) -> HashSet<String> {
    environment
        .bindings
        .iter()
        .filter(|binding| {
            binding.declaring_scope == 0
                && matches!(
                    binding.kind,
                    crate::analyzer::structural::resolution::BindingKind::ImportBinder
                )
        })
        .filter_map(|binding| {
            binding
                .import
                .as_ref()
                .filter(|import| {
                    import.target_segments.len() == 1 && import.target_segments[0] == "pytest"
                })
                .map(|_| binding.name.clone())
        })
        .collect()
}

fn is_pytest_fixture_declaration(
    function: Node<'_>,
    source: &str,
    pytest_aliases: &HashSet<String>,
) -> bool {
    super::python_rule_facts::python_definition_decorators(function)
        .into_iter()
        .filter_map(|decorator| named_children(decorator).into_iter().next())
        .any(|expression| {
            let mut target = expression;
            while target.kind() == "call" {
                let Some(function) = target.child_by_field_name("function") else {
                    return false;
                };
                target = function;
            }
            if target.kind() != "attribute"
                || target
                    .child_by_field_name("attribute")
                    .and_then(|name| super::python_rule_facts::node_text(source, name))
                    != Some("fixture")
            {
                return false;
            }
            target
                .child_by_field_name("object")
                .filter(|object| object.kind() == "identifier")
                .and_then(|object| super::python_rule_facts::node_text(source, object))
                .is_some_and(|name| pytest_aliases.contains(name))
        })
}

fn definition_rhs(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "assignment" | "augmented_assignment")
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| contains_node(left, node))
        {
            return parent.child_by_field_name("right");
        }
        if matches!(parent.kind(), "expression_statement" | "return_statement") {
            return None;
        }
        current = parent;
    }
    None
}

fn definition_is_unused(
    definition: &PythonVariableDefinition,
    node: Node<'_>,
    next_definition_start: Option<usize>,
    uses: &[PythonVariableUse],
) -> bool {
    let rhs = definition_rhs(node);
    !uses.iter().any(|usage| {
        usage.access == "read"
            && usage.start_byte >= definition.end_byte
            && next_definition_start.is_none_or(|next| usage.start_byte < next)
            && !rhs.is_some_and(|rhs| {
                rhs.start_byte() <= usage.start_byte && usage.end_byte <= rhs.end_byte()
            })
    })
}

fn tuple_assignment_siblings(node: Node<'_>) -> Vec<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "assignment" {
            let Some(left) = parent.child_by_field_name("left") else {
                return Vec::new();
            };
            if !contains_node(left, node)
                || !matches!(left.kind(), "pattern_list" | "tuple_pattern" | "tuple")
            {
                return Vec::new();
            }
            let mut siblings = Vec::new();
            collect_target_identifiers(left, &mut siblings);
            return siblings;
        }
        if matches!(parent.kind(), "expression_statement" | "return_statement") {
            return Vec::new();
        }
        current = parent;
    }
    Vec::new()
}

fn enclosing_for_statement(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "for_statement"
            && parent
                .child_by_field_name("left")
                .is_some_and(|target| contains_node(target, node))
        {
            return Some(parent);
        }
        current = parent;
    }
    None
}

fn is_builtin_name(
    name: &str,
    node: Node<'_>,
    scopes: &[LexicalScope<'_>],
    scope_by_node: &HashMap<usize, usize>,
    locals: &[HashSet<String>],
) -> bool {
    resolved_scope(
        name,
        effective_scope(node, scopes, scope_by_node),
        scopes,
        locals,
    )
    .is_none()
}

fn is_range_call(
    mut node: Node<'_>,
    source: &str,
    scopes: &[LexicalScope<'_>],
    scope_by_node: &HashMap<usize, usize>,
    locals: &[HashSet<String>],
) -> bool {
    loop {
        if node.kind() != "call" {
            return false;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "identifier" {
            return false;
        }
        let Some(name) = super::python_rule_facts::node_text(source, function) else {
            return false;
        };
        if name == "range" && is_builtin_name(name, function, scopes, scope_by_node, locals) {
            return true;
        }
        if name != "list" || !is_builtin_name(name, function, scopes, scope_by_node, locals) {
            return false;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return false;
        };
        let args = named_children(arguments);
        let Some(argument) = args.first() else {
            return false;
        };
        node = *argument;
    }
}

fn loop_iterable_is_range(
    loop_node: Node<'_>,
    source: &str,
    scopes: &[LexicalScope<'_>],
    scope_by_node: &HashMap<usize, usize>,
    locals: &[HashSet<String>],
    definitions: &[ResolvedDefinition<'_>],
) -> bool {
    let Some(iterable) = loop_node.child_by_field_name("right") else {
        return false;
    };
    if is_range_call(iterable, source, scopes, scope_by_node, locals) {
        return true;
    }
    if iterable.kind() != "identifier" {
        return false;
    }
    let Some(name) = super::python_rule_facts::node_text(source, iterable) else {
        return false;
    };
    let scope = effective_scope(iterable, scopes, scope_by_node);
    definitions
        .iter()
        .filter(|definition| {
            definition.name == name
                && definition.scope == scope
                && definition.node.start_byte() < loop_node.start_byte()
        })
        .max_by_key(|definition| definition.node.start_byte())
        .is_some_and(|definition| {
            definition
                .node
                .parent()
                .filter(|assignment| assignment.kind() == "assignment")
                .and_then(|assignment| assignment.child_by_field_name("right"))
                .is_some_and(|right| is_range_call(right, source, scopes, scope_by_node, locals))
        })
}

fn has_continue(body: Node<'_>) -> bool {
    syntax_nodes(body)
        .into_iter()
        .any(|node| node.kind() == "continue_statement")
}

fn is_integer_literal(node: Node<'_>) -> bool {
    node.kind() == "integer"
}

fn is_increment(statement: Node<'_>, source: &str) -> bool {
    let statement = if statement.kind() == "expression_statement" {
        let Some(expression) = statement.named_child(0) else {
            return false;
        };
        expression
    } else {
        statement
    };
    if statement.kind() == "augmented_assignment" {
        return statement
            .child_by_field_name("right")
            .is_some_and(is_integer_literal);
    }
    if statement.kind() != "assignment" {
        return false;
    }
    let Some(target) = statement.child_by_field_name("left") else {
        return false;
    };
    let Some(value) = statement.child_by_field_name("right") else {
        return false;
    };
    if value.kind() != "binary_operator" {
        return false;
    }
    let Some(left) = value.child_by_field_name("left") else {
        return false;
    };
    let Some(right) = value.child_by_field_name("right") else {
        return false;
    };
    let mut targets = Vec::new();
    collect_target_identifiers(target, &mut targets);
    targets.first().is_some_and(|target| {
        left.kind() == "identifier"
            && super::python_rule_facts::node_text(source, left)
                == super::python_rule_facts::node_text(source, *target)
            && is_integer_literal(right)
    })
}

fn is_immutable_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer" | "float" | "string" | "true" | "false" | "none" | "ellipsis"
    )
}

fn is_inside_loop(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "for_statement" | "for_in_clause" | "while_statement"
        ) {
            return true;
        }
        current = parent;
    }
    false
}

fn body_has_non_constant_use(
    body: Node<'_>,
    source: &str,
    scopes: &[LexicalScope<'_>],
    scope_by_node: &HashMap<usize, usize>,
    locals: &[HashSet<String>],
    definitions: &[ResolvedDefinition<'_>],
) -> bool {
    syntax_nodes(body).into_iter().any(|node| {
        if !matches!(node.kind(), "identifier" | "keyword_identifier")
            || is_in_import_or_directive(node)
            || is_attribute_label(node)
            || is_keyword_label(node)
            || definitions
                .iter()
                .any(|definition| definition.node.id() == node.id())
        {
            return false;
        }
        let Some(name) = super::python_rule_facts::node_text(source, node) else {
            return false;
        };
        let usage_scope = effective_scope(node, scopes, scope_by_node);
        let Some((scope, _, _)) = resolved_scope(name, usage_scope, scopes, locals) else {
            return false;
        };
        scope != 0
            && (definitions
                .iter()
                .filter(|definition| definition.scope == scope && definition.name == name)
                .count()
                > 1
                || definitions.iter().any(|definition| {
                    definition.scope == scope
                        && definition.name == name
                        && is_inside_loop(definition.node)
                }))
    })
}

fn loop_is_policy_excluded(
    loop_node: Node<'_>,
    source: &str,
    scopes: &[LexicalScope<'_>],
    scope_by_node: &HashMap<usize, usize>,
    locals: &[HashSet<String>],
    definitions: &[ResolvedDefinition<'_>],
) -> bool {
    if loop_iterable_is_range(
        loop_node,
        source,
        scopes,
        scope_by_node,
        locals,
        definitions,
    ) {
        return true;
    }
    let Some(body) = loop_node.child_by_field_name("body") else {
        return false;
    };
    let statements = named_children(body);
    if statements.len() == 1 && statements[0].kind() == "pass_statement" {
        return true;
    }
    if !has_continue(body)
        && statements
            .last()
            .is_some_and(|last| matches!(last.kind(), "return_statement" | "break_statement"))
    {
        return true;
    }
    if statements
        .iter()
        .any(|statement| is_increment(*statement, source))
    {
        return true;
    }
    let has_literal = syntax_nodes(body).into_iter().any(is_immutable_literal);
    has_literal
        && !body_has_non_constant_use(body, source, scopes, scope_by_node, locals, definitions)
}

fn loop_info(
    node: Node<'_>,
    source: &str,
    scopes: &[LexicalScope<'_>],
    scope_by_node: &HashMap<usize, usize>,
    locals: &[HashSet<String>],
    definitions: &[ResolvedDefinition<'_>],
) -> Option<PythonVariableLoopInfo> {
    let loop_node = enclosing_for_statement(node)?;
    let body = loop_node.child_by_field_name("body")?;
    let (statement_container, statement) = statement_location(loop_node)?;
    let target = definitions
        .iter()
        .find(|definition| definition.node.id() == node.id())?;
    Some(PythonVariableLoopInfo {
        start_byte: loop_node.start_byte(),
        end_byte: loop_node.end_byte(),
        range: definition_range(source, loop_node),
        body_start_byte: body.start_byte(),
        body_end_byte: body.end_byte(),
        statement_container,
        statement,
        has_body_read: false,
        policy_excluded: loop_is_policy_excluded(
            loop_node,
            source,
            scopes,
            scope_by_node,
            locals,
            definitions,
        ),
        body_unconditionally_redefines: loop_body_unconditionally_redefines(
            body,
            &target.name,
            target.scope,
            definitions,
        ),
    })
}

fn variable_id(
    file: &ProjectFile,
    content_identity: crate::analyzer::semantic::ContentIdentity,
    scope: &LexicalScope<'_>,
    name: &str,
) -> String {
    let mut digest = LengthDelimitedDigest::new(VARIABLE_ID_DOMAIN);
    digest.push(rel_path_string(file).as_bytes());
    digest.push(content_identity.as_bytes());
    digest.push(scope.kind.label().as_bytes());
    digest.push(&(scope.node.start_byte() as u64).to_le_bytes());
    digest.push(&(scope.node.end_byte() as u64).to_le_bytes());
    digest.push(name.as_bytes());
    digest.finish().to_string()
}

pub(super) fn derive(
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    environment: &EnvironmentFileResult,
) -> PythonVariableIndex {
    let root = tree.root_node();
    let nodes = syntax_nodes(root);
    let mut scopes = vec![LexicalScope {
        node: root,
        parent: None,
        kind: LexicalScopeKind::Module,
        globals: HashSet::default(),
        nonlocals: HashSet::default(),
        write_inventory_open: false,
    }];
    let mut scope_by_node = HashMap::from([(root.id(), 0_usize)]);
    for node in nodes.iter().copied().skip(1) {
        let inherited = enclosing_scope(node, &scope_by_node);
        if let Some(kind) = scope_kind(node)
            && kind != LexicalScopeKind::Module
        {
            let index = scopes.len();
            scopes.push(LexicalScope {
                node,
                parent: Some(inherited),
                kind,
                globals: HashSet::default(),
                nonlocals: HashSet::default(),
                write_inventory_open: false,
            });
            scope_by_node.insert(node.id(), index);
        }
    }

    for node in nodes.iter().copied() {
        if node.kind() == "wildcard_import" {
            // Record unknown writes once in the importing execution namespace.
            // A module's wildcard import cannot rebind unrelated function locals.
            let scope = effective_scope(node, &scopes, &scope_by_node);
            scopes[scope].write_inventory_open = true;
        }
        if !matches!(node.kind(), "global_statement" | "nonlocal_statement") {
            continue;
        }
        let scope = enclosing_scope(node, &scope_by_node);
        for name in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "identifier")
        {
            let Some(spelling) = super::python_rule_facts::node_text(source, name) else {
                continue;
            };
            if node.kind() == "global_statement" {
                scopes[scope].globals.insert(spelling.to_owned());
            } else {
                scopes[scope].nonlocals.insert(spelling.to_owned());
            }
        }
    }

    let mut definitions = raw_definitions(root, source);
    for definition in &mut definitions {
        definition.scope =
            definition_scope(definition.node, definition.kind, &scopes, &scope_by_node);
    }
    let locals = local_names(&definitions, &scopes);
    let local_classes = local_class_infos(&nodes, source);
    let pytest_aliases = pytest_module_aliases(environment);
    let class_by_name = local_class_index(&local_classes);
    let method_flags_by_function = nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "function_definition")
        .map(|function| {
            (
                function.id(),
                method_override_flags(function, source, &local_classes, &class_by_name),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut resolved_definitions = Vec::with_capacity(definitions.len());
    let valid_nonlocals = scopes.iter().enumerate().all(|(scope, info)| {
        info.nonlocals
            .iter()
            .all(|name| nonlocal_owner(name, scope, &scopes, &locals).is_some())
    });
    let mut complete = environment.completeness.covers(EnvironmentAxis::Scopes)
        && environment
            .completeness
            .covers(EnvironmentAxis::BindingIntervals)
        && !root.has_error()
        && valid_nonlocals;
    for definition in definitions {
        let Some((scope, is_global, is_nonlocal)) =
            resolved_scope(&definition.name, definition.scope, &scopes, &locals)
        else {
            complete = false;
            continue;
        };
        resolved_definitions.push(ResolvedDefinition {
            name: definition.name,
            node: definition.node,
            scope,
            source_scope: definition.scope,
            kind: definition.kind,
            is_global,
            is_nonlocal,
        });
    }

    let mut variables = Vec::<MutableVariable>::new();
    let mut group_by_key = HashMap::<(usize, String), usize>::new();
    let mut group_of_definition_node = HashMap::<usize, usize>::new();
    let mut definition_nodes = HashMap::<(usize, usize), Node<'_>>::new();
    for definition in &resolved_definitions {
        let key = (definition.scope, definition.name.clone());
        let index = *group_by_key.entry(key.clone()).or_insert_with(|| {
            let index = variables.len();
            variables.push(MutableVariable {
                scope: definition.scope,
                name: definition.name.clone(),
                is_global: false,
                is_nonlocal: false,
                definitions: Vec::new(),
                uses: Vec::new(),
            });
            index
        });
        let variable = &mut variables[index];
        variable.is_global |= definition.is_global;
        variable.is_nonlocal |= definition.is_nonlocal;
        let declaration = if definition.kind == "parameter" {
            enclosing_function(definition.node)
        } else {
            declaration_node(definition.node, definition.kind)
        };
        let function = matches!(definition.kind, "parameter" | "function_declaration")
            .then_some(declaration)
            .flatten()
            .filter(|function| function.kind() == "function_definition");
        let (is_overriding_method, is_overridden_method) = function
            .and_then(|function| method_flags_by_function.get(&function.id()).copied())
            .unwrap_or((Some(false), Some(false)));
        let decorated = matches!(
            definition.kind,
            "function_declaration" | "class_declaration"
        ) && declaration.is_some_and(|declaration| {
            !super::python_rule_facts::python_definition_decorators(declaration).is_empty()
        });
        let is_abstract = function
            .is_some_and(|function| super::python_rule_facts::is_abstract_method(function, source));
        let is_pytest_fixture = (definition.kind == "function_declaration")
            .then_some(declaration)
            .flatten()
            .is_some_and(|function| {
                is_pytest_fixture_declaration(function, source, &pytest_aliases)
            });
        let (assignment_value, assignment_unconditional) =
            assignment_value(definition.node, definition.kind);
        variable.definitions.push(PythonVariableDefinition {
            start_byte: definition.node.start_byte(),
            end_byte: definition.node.end_byte(),
            range: definition_range(source, definition.node),
            kind: definition.kind,
            assignment_value,
            assignment_unconditional,
            statement_location: statement_location(definition.node),
            order: 0,
            first: false,
            // Lexical scope and binding intervals do not prove CFG reachability.
            // Keep the dimension explicit until a producer-authored CFG fact is
            // available for this exact definition.
            reachability: "open",
            in_main_guard: in_main_guard(definition.node, source),
            optimizing_parameter: optimizing_parameter(definition.node, source),
            self_assignment: self_assignment(definition.node, source),
            is_unused: false,
            annotation_only: annotation_only(definition.node),
            annotated_assignment: annotated_assignment(definition.node),
            is_decorated: decorated,
            is_abstract,
            is_pytest_fixture,
            is_overriding_method,
            is_overridden_method,
            loop_info: (definition.kind == "loop_target")
                .then(|| {
                    loop_info(
                        definition.node,
                        source,
                        &scopes,
                        &scope_by_node,
                        &locals,
                        &resolved_definitions,
                    )
                })
                .flatten(),
        });
        group_of_definition_node.insert(definition.node.id(), index);
        definition_nodes.insert(
            (definition.node.start_byte(), definition.node.end_byte()),
            definition.node,
        );
    }

    for node in nodes
        .iter()
        .copied()
        .filter(|node| node.kind() == "identifier")
    {
        if group_of_definition_node.contains_key(&node.id())
            || is_in_import_or_directive(node)
            || is_attribute_label(node)
            || is_keyword_label(node)
            || brokk_bifrost_python::bindings::python_is_type_parameter_binder(node)
        {
            continue;
        }
        let Some(name) = super::python_rule_facts::node_text(source, node) else {
            continue;
        };
        let raw_scope = effective_scope(node, &scopes, &scope_by_node);
        let Some((scope, is_global, is_nonlocal)) =
            resolved_scope(name, raw_scope, &scopes, &locals)
        else {
            continue;
        };
        let Some(&index) = group_by_key.get(&(scope, name.to_owned())) else {
            continue;
        };
        let variable = &mut variables[index];
        variable.is_global |= is_global;
        variable.is_nonlocal |= is_nonlocal;
        let location = statement_location(node);
        variable.uses.push(PythonVariableUse {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            range: definition_range(source, node),
            access: "read",
            nested_scope: is_closure_access(raw_scope, scope, &scopes, is_global),
            statement_container: location.map(|(container, _)| container),
            statement: location.map(|(_, statement)| statement),
        });
    }

    for definition in &resolved_definitions {
        if definition.kind == "parameter" {
            continue;
        }
        let index = group_of_definition_node[&definition.node.id()];
        let variable = &mut variables[index];
        let nested_scope = is_closure_access(
            definition.source_scope,
            definition.scope,
            &scopes,
            definition.is_global,
        );
        let location = statement_location(definition.node);
        if definition.kind == "augmented" {
            variable.uses.push(PythonVariableUse {
                start_byte: definition.node.start_byte(),
                end_byte: definition.node.end_byte(),
                range: definition_range(source, definition.node),
                access: "read",
                nested_scope,
                statement_container: location.map(|(container, _)| container),
                statement: location.map(|(_, statement)| statement),
            });
        }
        variable.uses.push(PythonVariableUse {
            start_byte: definition.node.start_byte(),
            end_byte: definition.node.end_byte(),
            range: definition_range(source, definition.node),
            access: "write",
            nested_scope,
            statement_container: location.map(|(container, _)| container),
            statement: location.map(|(_, statement)| statement),
        });
    }

    for variable in &mut variables {
        for definition in &mut variable.definitions {
            if let Some(loop_info) = &mut definition.loop_info {
                loop_info.has_body_read = variable.uses.iter().any(|usage| {
                    usage.access == "read"
                        && loop_info.body_start_byte <= usage.start_byte
                        && usage.end_byte <= loop_info.body_end_byte
                });
            }
        }
    }

    for variable in &mut variables {
        variable.definitions.sort_by_key(|definition| {
            (definition.start_byte, definition.end_byte, definition.kind)
        });
        variable
            .uses
            .sort_by_key(|usage| (usage.start_byte, usage.end_byte, usage.access));
        for order in 0..variable.definitions.len() {
            let next_definition_start = variable
                .definitions
                .get(order + 1)
                .map(|next| next.start_byte);
            let (start_byte, end_byte) = {
                let definition = &variable.definitions[order];
                (definition.start_byte, definition.end_byte)
            };
            let node = definition_nodes[&(start_byte, end_byte)];
            let is_unused = next_definition_start.is_none()
                && definition_is_unused(
                    &variable.definitions[order],
                    node,
                    next_definition_start,
                    &variable.uses,
                );
            let definition = &mut variable.definitions[order];
            definition.order = order;
            definition.first = order == 0;
            definition.is_unused = is_unused;
        }
    }
    let unused_by_node = variables
        .iter()
        .flat_map(|variable| {
            variable.definitions.iter().map(|definition| {
                let node = definition_nodes[&(definition.start_byte, definition.end_byte)];
                (node.id(), definition.is_unused)
            })
        })
        .collect::<HashMap<_, _>>();
    for variable in &mut variables {
        for definition in &mut variable.definitions {
            let node = definition_nodes[&(definition.start_byte, definition.end_byte)];
            let siblings = tuple_assignment_siblings(node);
            if siblings.len() > 1 {
                definition.is_unused &= siblings
                    .iter()
                    .all(|sibling| unused_by_node.get(&sibling.id()).copied().unwrap_or(false));
            }
        }
    }

    let mut index = PythonVariableIndex::default();
    for variable in variables {
        let scope = &scopes[variable.scope];
        let content_identity = environment
            .scopes
            .first()
            .expect("a parsed file environment has its synthetic file scope")
            .content_identity;
        let id = variable_id(file, content_identity, scope, &variable.name);
        let is_builtin =
            brokk_bifrost_python::diagnostics::is_python_builtin_or_constant(&variable.name);
        let has_read = variable.uses.iter().any(|usage| usage.access == "read");
        let facts = Arc::new(PythonVariableFacts {
            id,
            name: variable.name,
            scope_kind: scope.kind.label(),
            scope_start_byte: scope.node.start_byte(),
            scope_end_byte: scope.node.end_byte(),
            write_inventory_open: scope.write_inventory_open,
            is_global: variable.is_global,
            is_nonlocal: variable.is_nonlocal,
            is_builtin,
            has_read,
            definitions: variable.definitions,
            uses: variable.uses,
            complete,
            reason: (!complete).then(|| "python_lexical_variable_incomplete".to_owned()),
            content_identity,
        });
        let group_index = index.groups.len();
        index
            .by_name
            .entry(facts.name.clone())
            .or_default()
            .push(group_index);
        for definition in &facts.definitions {
            index
                .nodes
                .insert((definition.start_byte, definition.end_byte), group_index);
        }
        for usage in &facts.uses {
            index
                .nodes
                .insert((usage.start_byte, usage.end_byte), group_index);
        }
        index.groups.push(facts);
    }
    index
}

fn variable_row(file: &ProjectFile, facts: Arc<PythonVariableFacts>) -> PipelineExpansion {
    let first_definition = facts
        .definitions
        .first()
        .expect("every lexical variable is created by at least one definition");
    let anchor = first_definition.start_byte..first_definition.end_byte;
    let range = first_definition.range;
    let mut value = make_row(
        Incompleteness::Content,
        "lexical_variable",
        file,
        anchor,
        range,
        None,
        "variable",
        "proven",
        facts.complete,
        facts.reason.clone(),
    );
    value.row.id = facts.id.clone();
    value.row.variable_id = Some(facts.id.clone());
    value.row.name = Some(facts.name.clone());
    value.row.scope_kind = Some(facts.scope_kind);
    value.row.is_global = Some(facts.is_global);
    value.row.is_nonlocal = Some(facts.is_nonlocal);
    value.row.is_builtin = Some(facts.is_builtin);
    value.row.has_read = Some(facts.has_read);
    value.lexical_variable = Some(facts);
    pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(value)))
}

pub(super) fn variable_of_binding(
    value: &BindingValue,
    index: &PythonVariableIndex,
) -> Vec<PipelineExpansion> {
    index
        .for_binding(value.row())
        .map(|facts| vec![variable_row(value.file(), facts)])
        .unwrap_or_default()
}

pub(super) fn variable_of_binding_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    value: &BindingValue,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if crate::analyzer::common::language_for_file(value.file()) != crate::analyzer::Language::Python
    {
        return Vec::new();
    }
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(value.file().clone()), false)
    else {
        return Vec::new();
    };
    environment_cache.report_completeness(
        value.file(),
        &value.result,
        &[EnvironmentAxis::Scopes, EnvironmentAxis::BindingIntervals],
        diagnostics,
    );
    let Some(index) = environment_cache.python_variable_index_for(
        analyzer,
        value.file(),
        value.row().content_identity,
        &source,
        &value.result,
    ) else {
        return Vec::new();
    };
    variable_of_binding(value, &index)
}

pub(super) fn variable_of_occurrence_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    value: &OccurrenceValue,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if crate::analyzer::common::language_for_file(&value.row.file)
        != crate::analyzer::Language::Python
    {
        return Vec::new();
    }
    let environment = environment_cache.environment_for(analyzer, &value.row.file);
    environment_cache.report_completeness(
        &value.row.file,
        &environment,
        &[EnvironmentAxis::Scopes, EnvironmentAxis::BindingIntervals],
        diagnostics,
    );
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(value.row.file.clone()), false)
    else {
        return Vec::new();
    };
    let Some(index) = environment_cache.python_variable_index_for(
        analyzer,
        &value.row.file,
        value.row.content_identity,
        &source,
        &environment,
    ) else {
        return Vec::new();
    };
    variable_of_occurrence(value, &index)
}

pub(super) fn variable_of_occurrence(
    value: &OccurrenceValue,
    index: &PythonVariableIndex,
) -> Vec<PipelineExpansion> {
    index
        .for_occurrence(&value.row)
        .map(|facts| vec![variable_row(&value.row.file, facts)])
        .unwrap_or_default()
}

pub(super) fn variable_peer_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    value: &PythonRuleFactValue,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let Some(facts) = value
        .lexical_variable
        .as_ref()
        .filter(|_| value.row.relation == "lexical_variable")
    else {
        return Vec::new();
    };
    if crate::analyzer::common::language_for_file(&value.file) != crate::analyzer::Language::Python
    {
        return Vec::new();
    }
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(value.file.clone()), false) else {
        return Vec::new();
    };
    let environment = environment_cache.environment_for(analyzer, &value.file);
    environment_cache.report_completeness(
        &value.file,
        &environment,
        &[EnvironmentAxis::Scopes, EnvironmentAxis::BindingIntervals],
        diagnostics,
    );
    let Some(index) = environment_cache.python_variable_index_for(
        analyzer,
        &value.file,
        facts.content_identity,
        &source,
        &environment,
    ) else {
        return Vec::new();
    };
    variable_peers(&value.file, facts, &index)
}

fn variable_peers(
    file: &ProjectFile,
    facts: &Arc<PythonVariableFacts>,
    index: &PythonVariableIndex,
) -> Vec<PipelineExpansion> {
    let Some(first_definition) = facts.definitions.first() else {
        return Vec::new();
    };
    index
        .same_name_peers(facts)
        .map(|peer| {
            let complete = facts.complete && peer.complete;
            let mut row = make_row(
                Incompleteness::Content,
                "lexical_variable_peer",
                file,
                first_definition.start_byte..first_definition.end_byte,
                first_definition.range,
                Some(facts.id.clone()),
                "peer",
                "proven",
                complete,
                (!complete).then(|| "python_lexical_variable_incomplete".to_owned()),
            );
            let mut digest = LengthDelimitedDigest::new(VARIABLE_ID_DOMAIN);
            digest.push(b"peer");
            digest.push(facts.id.as_bytes());
            digest.push(peer.id.as_bytes());
            row.row.id = digest.finish().to_string();
            row.row.target_id = Some(peer.id.clone());
            row.row.variable_id = Some(facts.id.clone());
            row.row.name = Some(facts.name.clone());
            row.row.scope_kind = Some(facts.scope_kind);
            row.row.is_global = Some(facts.is_global);
            row.row.is_nonlocal = Some(facts.is_nonlocal);
            row.row.is_builtin = Some(facts.is_builtin);
            row.row.has_read = Some(facts.has_read);
            row.row.definition_kind = Some(first_definition.kind);
            row.row.definition_order = Some(first_definition.order);
            row.row.first_definition = Some(first_definition.first);
            row.row.related_scope_kind = Some(peer.scope_kind);
            row.row.related_has_definition_outside_main = Some(
                peer.definitions
                    .iter()
                    .any(|definition| definition.kind != "del" && !definition.in_main_guard),
            );
            row.row.related_has_deletion = Some(
                peer.definitions
                    .iter()
                    .any(|definition| definition.kind == "del"),
            );
            row.row.related_has_import = Some(
                peer.definitions
                    .iter()
                    .any(|definition| definition.kind == "import"),
            );
            row.row.related_is_pytest_fixture = Some(
                peer.definitions
                    .iter()
                    .any(|definition| definition.is_pytest_fixture),
            );
            row.row.optimizing_parameter = Some(first_definition.optimizing_parameter);
            row.row.in_main_guard = Some(first_definition.in_main_guard);
            row.row.self_assignment = Some(first_definition.self_assignment);
            row.lexical_variable = Some(Arc::clone(facts));
            pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(row)))
        })
        .collect()
}

pub(super) fn nested_loop_expansions(value: &PythonRuleFactValue) -> Vec<PipelineExpansion> {
    let Some(facts) = value
        .lexical_variable
        .as_ref()
        .filter(|_| value.row.relation == "lexical_variable")
    else {
        return Vec::new();
    };
    let loops = facts
        .definitions
        .iter()
        .filter(|definition| definition.kind == "loop_target")
        .filter_map(|definition| definition.loop_info.as_ref().map(|info| (definition, info)))
        .collect::<Vec<_>>();
    let mut pairs = HashSet::new();
    let mut expansions = Vec::new();
    for (_, outer) in &loops {
        for (_, inner) in &loops {
            if outer.start_byte == inner.start_byte
                || !(outer.body_start_byte <= inner.start_byte
                    && inner.end_byte <= outer.body_end_byte)
            {
                continue;
            }
            let pair = (
                outer.start_byte,
                outer.end_byte,
                inner.start_byte,
                inner.end_byte,
            );
            if !pairs.insert(pair) {
                continue;
            }
            let has_outer_use = facts.uses.iter().any(|usage| {
                usage.access == "read"
                    && outer.start_byte <= usage.start_byte
                    && usage.end_byte <= outer.end_byte
                    && !(inner.start_byte <= usage.start_byte && usage.end_byte <= inner.end_byte)
            });
            let reused = facts.uses.iter().any(|usage| {
                usage.access == "read"
                    && inner.end_byte < usage.start_byte
                    && usage.end_byte <= outer.end_byte
                    && usage.statement_container == Some(inner.statement_container)
                    && usage
                        .statement
                        .is_some_and(|statement| statement.0 >= inner.statement.1)
                    && !inner.body_unconditionally_redefines
                    && !facts.definitions.iter().any(|definition| {
                        definition.start_byte >= inner.end_byte
                            && definition.start_byte < usage.start_byte
                    })
            });
            let mut row = make_row(
                Incompleteness::Content,
                "nested_loop_same_variable",
                &value.file,
                inner.start_byte..inner.end_byte,
                inner.range,
                Some(facts.id.clone()),
                "loop_pair",
                "proven",
                facts.complete,
                facts.reason.clone(),
            );
            let mut digest = LengthDelimitedDigest::new(VARIABLE_ID_DOMAIN);
            digest.push(b"nested_loop");
            digest.push(facts.id.as_bytes());
            digest.push(&(outer.start_byte as u64).to_le_bytes());
            digest.push(&(outer.end_byte as u64).to_le_bytes());
            digest.push(&(inner.start_byte as u64).to_le_bytes());
            digest.push(&(inner.end_byte as u64).to_le_bytes());
            row.row.id = digest.finish().to_string();
            row.row.target_id = Some(digest_loop_id(facts, outer.start_byte, outer.end_byte));
            row.row.variable_id = Some(facts.id.clone());
            row.row.name = Some(facts.name.clone());
            row.row.scope_kind = Some(facts.scope_kind);
            row.row.nested_loop_reused = Some(reused);
            row.row.nested_loop_has_outer_use = Some(has_outer_use);
            row.lexical_variable = Some(Arc::clone(facts));
            expansions.push(pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                row,
            ))));
        }
    }
    expansions
}

fn digest_loop_id(facts: &PythonVariableFacts, start_byte: usize, end_byte: usize) -> String {
    let mut digest = LengthDelimitedDigest::new(VARIABLE_ID_DOMAIN);
    digest.push(b"loop");
    digest.push(facts.id.as_bytes());
    digest.push(&(start_byte as u64).to_le_bytes());
    digest.push(&(end_byte as u64).to_le_bytes());
    digest.finish().to_string()
}

pub(super) fn definitions(value: &PythonRuleFactValue) -> Vec<PipelineExpansion> {
    let Some(facts) = value
        .lexical_variable
        .as_ref()
        .filter(|_| value.row.relation == "lexical_variable")
    else {
        return Vec::new();
    };
    facts
        .definitions
        .iter()
        .map(|definition| {
            let mut row = make_row(
                Incompleteness::Content,
                "lexical_variable_definition",
                &value.file,
                definition.start_byte..definition.end_byte,
                definition.range,
                Some(facts.id.clone()),
                "definition",
                "proven",
                facts.complete,
                facts.reason.clone(),
            );
            row.row.variable_id = Some(facts.id.clone());
            row.row.name = Some(facts.name.clone());
            row.row.scope_kind = Some(facts.scope_kind);
            row.row.is_global = Some(facts.is_global);
            row.row.is_nonlocal = Some(facts.is_nonlocal);
            row.row.definition_kind = Some(definition.kind);
            row.row.definition_order = Some(definition.order);
            row.row.first_definition = Some(definition.first);
            row.row.definition_is_unused = Some(definition.is_unused);
            row.row.annotation_only = Some(definition.annotation_only);
            row.row.annotated_assignment = Some(definition.annotated_assignment);
            row.row.is_decorated = Some(definition.is_decorated);
            row.row.is_abstract = Some(definition.is_abstract);
            row.row.is_overriding_method = definition.is_overriding_method;
            row.row.is_overridden_method = definition.is_overridden_method;
            row.row.reachability = Some(definition.reachability);
            row.row.is_builtin = Some(facts.is_builtin);
            row.row.has_read = Some(facts.has_read);
            row.row.in_main_guard = Some(definition.in_main_guard);
            row.row.optimizing_parameter = Some(definition.optimizing_parameter);
            row.row.self_assignment = Some(definition.self_assignment);
            row.row.loop_has_body_read =
                definition.loop_info.as_ref().map(|info| info.has_body_read);
            row.row.loop_policy_excluded = definition
                .loop_info
                .as_ref()
                .map(|info| info.policy_excluded);
            row.lexical_variable = Some(Arc::clone(facts));
            pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(row)))
        })
        .collect()
}

pub(super) fn uses(value: &PythonRuleFactValue) -> Vec<PipelineExpansion> {
    let Some(facts) = value
        .lexical_variable
        .as_ref()
        .filter(|_| value.row.relation == "lexical_variable")
    else {
        return Vec::new();
    };
    facts
        .uses
        .iter()
        .map(|usage| {
            let mut row = make_row(
                Incompleteness::Content,
                "lexical_variable_use",
                &value.file,
                usage.start_byte..usage.end_byte,
                usage.range,
                Some(facts.id.clone()),
                "use",
                "proven",
                facts.complete,
                facts.reason.clone(),
            );
            row.row.variable_id = Some(facts.id.clone());
            row.row.name = Some(facts.name.clone());
            row.row.scope_kind = Some(facts.scope_kind);
            row.row.is_global = Some(facts.is_global);
            row.row.is_nonlocal = Some(facts.is_nonlocal);
            row.row.access_kind = Some(usage.access);
            row.row.nested_scope = Some(usage.nested_scope);
            row.lexical_variable = Some(Arc::clone(facts));
            pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(row)))
        })
        .collect()
}
