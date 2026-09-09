//! Query-local summaries for small Python guard helpers.
//!
//! The summary deliberately has a small, structural language.  It is useful
//! for helpers such as `callable(getattr(obj, "member", None))` while keeping
//! unresolved calls, rebinding, control flow, and dynamic expressions
//! conservative.  All syntax access is through the prepared tree-sitter tree;
//! there is no source-text parser here.

use std::collections::HashMap;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_python::bindings::{
    PythonLexicalNameResolution, python_comprehension_binds_name_at,
    python_direct_scope_bindings_bounded, python_type_parameter_binds_name_at,
};
use brokk_bifrost_python::syntax::python_plain_string_literal;
use tree_sitter::Node;

use super::lexical_scope::python_lexical_scope_inventory_bounded;
use super::type_flow::{
    builtin_base_is_unshadowed, current_indexed_prepared, node_at_span, prepared_for_procedure,
    python_analyzer,
};
use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner;
use crate::analyzer::semantic::type_flow::{
    ClassIdentity, MemberLookup, NarrowingVerdict, file_for_locator,
};
use crate::analyzer::semantic::{
    ArgumentDomain, CallArgumentExpansion, CallInvocationMode, GuardFact, GuardPredicate,
    ProcedureHandle, SemanticCallSite, SourceMappingKind, ValueId,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_target_batch_with_source,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, Language, QueryScope, WorkspaceAnalyzer,
};

const MAX_BODY_NODES: usize = 512;
const MAX_EXPRESSION_DEPTH: usize = 64;
const MAX_BINDING_NODES: usize = 32_768;

/// Resolve an opaque guard call and summarize its helper body.
pub(super) fn call_guard_narrowing(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    guard: &GuardFact,
    atoms: &[&ClassIdentity],
    member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
) -> Option<(ValueId, Vec<NarrowingVerdict>)> {
    if !matches!(guard.predicate, GuardPredicate::Opaque { .. }) {
        return None;
    }
    let semantics = procedure.semantics();
    let subject = guard.subject?;
    let subject_value = semantics.value(subject)?;
    let subject_mapping = semantics.source_mapping(subject_value.source)?;
    if subject_mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let file = file_for_locator(workspace, &subject_mapping.locator)?;
    let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
    let call_node = node_at_span(&prepared, subject_mapping.locator.anchor().span())?;
    if call_node.kind() != "call" {
        return None;
    }
    let call = exact_call_site(semantics.call_sites(), subject)?;
    if !matches!(call.invocation_mode, CallInvocationMode::Ordinary) || call.receiver.is_some() {
        return None;
    }
    let [argument] = call.arguments.as_ref() else {
        return None;
    };
    if argument.keyword.is_some()
        || !matches!(
            argument.expansion,
            CallArgumentExpansion::Direct(ArgumentDomain::Positional)
        )
    {
        return None;
    }

    let function = call_node.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    let caller_source = prepared.source();
    if !unbound_at_reference(function, caller_source, MAX_BINDING_NODES)? {
        return None;
    }
    unique_module_binding(
        prepared.tree().root_node(),
        node_text(function, caller_source)?,
        caller_source,
    )?;
    let target = resolve_workspace_function(workspace, &file, caller_source, function)?;
    let python = python_analyzer(workspace);
    let target_prepared = current_indexed_prepared(python, target.source())?;
    let target_function = target_function_node(python, &target_prepared, &target)?;
    if !ordinary_workspace_function(&target, target_function) {
        return None;
    }
    let target_name = target_function.child_by_field_name("name")?;
    if unique_module_binding(
        target_prepared.tree().root_node(),
        node_text(target_name, target_prepared.source())?,
        target_prepared.source(),
    )? != target_name
    {
        return None;
    }
    let parameter = single_positional_parameter(target_function, target_prepared.source())?;
    let expression = summarize_body(target_function, target_prepared.source(), &parameter)?;
    if !expression.depends_on_member() {
        return None;
    }
    let verdicts = atoms
        .iter()
        .map(|atom| expression.evaluate(atom, member_lookup))
        .map(verdict_from_truth)
        .collect();
    Some((argument.value, verdicts))
}

// Point mappings and expression-value mappings can differ for the same AST
// call. The call's result ValueId is the semantic identity tested by the guard.
fn exact_call_site(calls: &[SemanticCallSite], subject: ValueId) -> Option<&SemanticCallSite> {
    let mut matches = calls.iter().filter(|call| call.result == Some(subject));
    let call = matches.next()?;
    matches.next().is_none().then_some(call)
}

fn resolve_workspace_function(
    workspace: &WorkspaceAnalyzer,
    file: &crate::analyzer::ProjectFile,
    source: &str,
    function: Node<'_>,
) -> Option<CodeUnit> {
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(function.start_byte()),
        end_byte: Some(function.end_byte()),
    };
    let outcomes = resolve_call_target_batch_with_source(
        workspace.analyzer(),
        scope.token(),
        vec![request],
        file.clone(),
        Arc::<str>::from(source),
        None,
    );
    let [outcome] = outcomes.as_slice() else {
        return None;
    };
    if outcome.outcome.status != DefinitionLookupStatus::Resolved
        || outcome.outcome.definitions.len() != 1
    {
        return None;
    }
    outcome.outcome.definitions.first().cloned()
}

fn ordinary_workspace_function(target: &CodeUnit, node: Node<'_>) -> bool {
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    target.is_function()
        && !target.is_synthetic()
        && !target.owner_is_type_scope()
        && node.kind() == "function_definition"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "module")
        && !has_direct_token(node, "async")
        && body_is_small_and_valid(body)
}

fn target_function_node<'tree>(
    python: &super::PythonAnalyzer,
    prepared: &'tree PreparedSyntaxTree,
    target: &CodeUnit,
) -> Option<Node<'tree>> {
    let mut found = None;
    let mut seen = Vec::new();
    for range in python.ranges(target) {
        let Some(node) = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        else {
            continue;
        };
        if node.kind() != "function_definition"
            || node.start_byte() != range.start_byte
            || node.end_byte() != range.end_byte
            || seen.contains(&node.id())
        {
            continue;
        }
        seen.push(node.id());
        if found.replace(node).is_some() {
            return None;
        }
    }
    found
}

fn single_positional_parameter(function: Node<'_>, source: &str) -> Option<String> {
    let layout = formal_parameter_slots_for_owner(Language::Python, function, source)?;
    let [slot] = layout.slots.as_slice() else {
        return None;
    };
    if slot.receiver || slot.variadic.is_some() || !slot.passing_mode.accepts_positional() {
        return None;
    }
    slot.unique_name().map(str::to_owned)
}

/// A module binding must have exactly one structured declaration. This also
/// rejects import-plus-assignment and duplicate helper definitions.
fn unique_module_binding<'tree>(
    root: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut remaining = MAX_BINDING_NODES;
    let mut step = || {
        remaining = remaining.saturating_sub(1);
        remaining > 0
    };
    let mut found = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !step() || node.kind() == "wildcard_import" {
            return None;
        }
        for binding in python_direct_scope_bindings_bounded(node, source, &mut step)? {
            if node_text(binding.declaration, source) == Some(name)
                && found.replace(binding.declaration).is_some()
            {
                return None;
            }
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body"))
        .flatten();
        let mut cursor = node.walk();
        stack.extend(
            node.named_children(&mut cursor)
                .filter(|child| Some(*child) != excluded_body),
        );
    }
    found
}

fn summarize_body(function: Node<'_>, source: &str, parameter: &str) -> Option<GuardSummary> {
    let body = function.child_by_field_name("body")?;
    let mut expressions = ExpressionBuilder {
        source,
        parameter,
        aliases: HashMap::new(),
        nodes: Vec::new(),
    };
    let mut result = None;
    for (index, statement) in runtime_children(body).into_iter().enumerate() {
        // A return must be the last statement, including otherwise unreachable
        // code: this summary's contract is one straight-line return.
        if result.is_some() {
            return None;
        }
        match statement.kind() {
            "expression_statement" => {
                let expression = only_runtime_child(statement)?;
                if index == 0 && matches!(expression.kind(), "string" | "concatenated_string") {
                    continue;
                }
                if expression.kind() != "assignment"
                    || expression.child_by_field_name("type").is_some()
                {
                    return None;
                }
                let left = expression.child_by_field_name("left")?;
                if left.kind() != "identifier" {
                    return None;
                }
                let name = node_text(left, source)?;
                if name == parameter {
                    return None;
                }
                let right = expression.child_by_field_name("right")?;
                let value = expressions.lower(right, MAX_EXPRESSION_DEPTH)?;
                expressions.aliases.insert(name, value);
            }
            "return_statement" => {
                result =
                    Some(expressions.lower(only_runtime_child(statement)?, MAX_EXPRESSION_DEPTH)?);
            }
            _ => return None,
        }
    }
    Some(GuardSummary {
        nodes: expressions.nodes,
        result: result?,
    })
}

/// Aliases retain arena IDs rather than copying expression trees. Repeated
/// `guard = guard and guard` stays linear in the size of the helper body.
struct ExpressionBuilder<'source> {
    source: &'source str,
    parameter: &'source str,
    aliases: HashMap<&'source str, usize>,
    nodes: Vec<GuardExpr>,
}

impl ExpressionBuilder<'_> {
    fn lower(&mut self, node: Node<'_>, depth: usize) -> Option<usize> {
        if depth == 0 || self.nodes.len() >= MAX_BODY_NODES {
            return None;
        }
        let expression = match node.kind() {
            "identifier" => {
                let name = node_text(node, self.source)?;
                if name == self.parameter {
                    GuardExpr::Parameter
                } else {
                    return self.aliases.get(name).copied();
                }
            }
            "true" => GuardExpr::Constant(true),
            "false" | "none" => GuardExpr::Constant(false),
            "parenthesized_expression" => return self.lower(only_runtime_child(node)?, depth - 1),
            "not_operator" => {
                GuardExpr::Not(self.lower(node.child_by_field_name("argument")?, depth - 1)?)
            }
            "boolean_operator" => {
                let left = self.lower(node.child_by_field_name("left")?, depth - 1)?;
                let right = self.lower(node.child_by_field_name("right")?, depth - 1)?;
                match node.child_by_field_name("operator")?.kind() {
                    "and" => GuardExpr::And(left, right),
                    "or" => GuardExpr::Or(left, right),
                    _ => return None,
                }
            }
            "call" => self.lower_call(node, depth - 1)?,
            _ => return None,
        };
        let id = self.nodes.len();
        self.nodes.push(expression);
        Some(id)
    }

    fn lower_call(&mut self, node: Node<'_>, depth: usize) -> Option<GuardExpr> {
        let function = node.child_by_field_name("function")?;
        if function.kind() != "identifier"
            || builtin_base_is_unshadowed(function, self.source) != Some(true)
        {
            return None;
        }
        let name = node_text(function, self.source)?;
        let arguments = runtime_children(node.child_by_field_name("arguments")?);
        if arguments.iter().any(|argument| {
            matches!(
                argument.kind(),
                "keyword_argument" | "list_splat" | "dictionary_splat"
            )
        }) {
            return None;
        }
        match (name, arguments.as_slice()) {
            ("getattr", [object, member, default]) => {
                let object = self.lower(*object, depth)?;
                if !matches!(self.nodes[object], GuardExpr::Parameter) || default.kind() != "none" {
                    return None;
                }
                Some(GuardExpr::Member(
                    python_plain_string_literal(*member, self.source)?.into(),
                ))
            }
            ("hasattr", [object, member]) => {
                let object = self.lower(*object, depth)?;
                if !matches!(self.nodes[object], GuardExpr::Parameter) {
                    return None;
                }
                Some(GuardExpr::HasMember(
                    python_plain_string_literal(*member, self.source)?.into(),
                ))
            }
            ("callable", [value]) => {
                let value = self.lower(*value, depth)?;
                let GuardExpr::Member(member) = &self.nodes[value] else {
                    return None;
                };
                Some(GuardExpr::CallableMember(member.clone()))
            }
            ("isinstance", [object, class]) => {
                let object = self.lower(*object, depth)?;
                if !matches!(self.nodes[object], GuardExpr::Parameter)
                    || class.kind() != "identifier"
                    || node_text(*class, self.source) != Some("type")
                    || builtin_base_is_unshadowed(*class, self.source) != Some(true)
                {
                    return None;
                }
                Some(GuardExpr::IsClassObject)
            }
            _ => None,
        }
    }
}

fn runtime_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect()
}

fn only_runtime_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut children = node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra());
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn has_direct_token(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

/// Validate a small body before the bounded recursive expression lowerer.
/// Evaluation, alias expansion and destruction of the resulting arena are
/// iterative; only AST expression descent uses a fixed 64-level expression depth cap.
fn body_is_small_and_valid(body: Node<'_>) -> bool {
    let mut stack = vec![body];
    let mut seen = 0;
    while let Some(node) = stack.pop() {
        seen += 1;
        if seen > MAX_BODY_NODES || node.has_error() {
            return false;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    true
}

fn unbound_at_reference(reference: Node<'_>, source: &str, max_nodes: usize) -> Option<bool> {
    let name = node_text(reference, source)?;
    if python_comprehension_binds_name_at(name, reference, source)
        || python_type_parameter_binds_name_at(name, reference, source)
    {
        return Some(false);
    }
    let mut current = reference;
    let mut remaining = max_nodes;
    while let Some(parent) = current.parent() {
        remaining = remaining.checked_sub(1)?;
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference.start_byte()
                    && reference.end_byte() <= body.end_byte()
            })
        {
            let inventory = python_lexical_scope_inventory_bounded(parent, source, || {
                remaining = remaining.saturating_sub(1);
                remaining > 0
            })?;
            if inventory.name_resolution_at(name, reference) != PythonLexicalNameResolution::Unbound
            {
                return Some(false);
            }
        }
        current = parent;
    }
    Some(true)
}

enum GuardExpr {
    Parameter,
    Member(Box<str>),
    HasMember(Box<str>),
    CallableMember(Box<str>),
    IsClassObject,
    Constant(bool),
    Not(usize),
    And(usize, usize),
    Or(usize, usize),
}

struct GuardSummary {
    nodes: Vec<GuardExpr>,
    result: usize,
}

impl GuardSummary {
    fn depends_on_member(&self) -> bool {
        let mut dependent = Vec::with_capacity(self.nodes.len());
        for expression in &self.nodes {
            dependent.push(match expression {
                GuardExpr::Parameter | GuardExpr::IsClassObject | GuardExpr::Constant(_) => false,
                GuardExpr::Member(_) | GuardExpr::HasMember(_) | GuardExpr::CallableMember(_) => {
                    true
                }
                GuardExpr::Not(value) => dependent[*value],
                GuardExpr::And(left, right) | GuardExpr::Or(left, right) => {
                    dependent[*left] || dependent[*right]
                }
            });
        }
        dependent[self.result]
    }

    fn evaluate(
        &self,
        atom: &ClassIdentity,
        member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> Truth {
        let mut values: Vec<Truth> = Vec::with_capacity(self.nodes.len());
        for expression in &self.nodes {
            values.push(match expression {
                // The class domain does not establish whether a value is a
                // class object. Retain both outcomes of isinstance(obj, type).
                GuardExpr::Parameter | GuardExpr::IsClassObject => Truth::Unknown,
                GuardExpr::Member(member) | GuardExpr::CallableMember(member) => {
                    match member_lookup(atom, member) {
                        MemberLookup::Absent => Truth::False,
                        _ => Truth::Unknown,
                    }
                }
                GuardExpr::HasMember(member) => match member_lookup(atom, member) {
                    MemberLookup::Absent => Truth::False,
                    MemberLookup::Present(_) => Truth::True,
                    _ => Truth::Unknown,
                },
                GuardExpr::Constant(value) => {
                    if *value {
                        Truth::True
                    } else {
                        Truth::False
                    }
                }
                GuardExpr::Not(value) => values[*value].not(),
                GuardExpr::And(left, right) => values[*left].and(values[*right]),
                GuardExpr::Or(left, right) => values[*left].or(values[*right]),
            });
        }
        values[self.result]
    }
}

#[derive(Clone, Copy)]
enum Truth {
    True,
    False,
    Unknown,
}

impl Truth {
    const fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

fn verdict_from_truth(truth: Truth) -> NarrowingVerdict {
    match truth {
        Truth::True => NarrowingVerdict::Keep,
        Truth::False => NarrowingVerdict::Drop,
        Truth::Unknown => NarrowingVerdict::Unknown,
    }
}
