use super::resolver::node_text;
use crate::adapter::php_signature_return_type_text;
use crate::aliases::{
    PhpDeclaredType, PhpFileContext, php_dynamic_type_keyword, resolve_php_function_node,
    resolve_php_type, resolve_php_type_arms,
};
use crate::graph::PhpGraphSource;
use crate::graph_support::PhpSource;
use crate::graph_support::{php_direct_declared_class_parent, php_file_context_from_source};
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

const LOCAL_SCOPE_NODES: &[&str] = &[
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "anonymous_function_creation",
    "arrow_function",
];

pub fn is_local_scope(node: Node<'_>) -> bool {
    LOCAL_SCOPE_NODES.contains(&node.kind())
}

/// Seed every declared parameter of `node` into a local binding scope.
///
/// `resolve_type` receives the parameter's name and its declared type text, and
/// answers with every class that type names: one for an ordinary or nullable
/// type, several for a finite union, and none when the declaration proves
/// nothing. A union is seeded as the whole arm set rather than dropped, so a
/// surface that can carry bounded ambiguity sees it while every single-owner
/// reader still fails closed on it.
///
/// The name travels to `resolve_type` because a declared type can prove more
/// than the classes it names -- `object` and `mixed` prove the parameter's
/// member surface is dynamic -- and only the caller knows whether it records
/// that (#2030).
pub fn seed_parameter_types<F>(
    node: Node<'_>,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    mut resolve_type: F,
) where
    F: FnMut(&str, &str) -> Vec<String>,
{
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        let arms = child
            .child_by_field_name("type")
            .map(|type_node| resolve_type(name, node_text(type_node, source)))
            .unwrap_or_default();
        if arms.is_empty() {
            bindings.declare_shadow(name.to_string());
        } else {
            bindings.seed_symbol_many(name.to_string(), arms);
        }
    }
}

pub fn assignment_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "assignment_expression")
        .then(|| {
            node.child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
        })
        .flatten()
}

/// Reduce `((expr))` to `expr`. Parentheses nest without bound in generated
/// source, so this descends with a loop instead of a recursive call.
pub fn unwrap_parenthesized(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while current.kind() == "parenthesized_expression" {
        let Some(inner) = current.named_child(0) else {
            break;
        };
        current = inner;
    }
    current
}

/// Apply one PHP assignment to a local binding scope.
///
/// This is the single interpretation of what an assignment tells local
/// inference, shared by the targeted usage scan, the whole-workspace inverted
/// scan, forward definition lookup, and semantic diagnostics. Only a plain
/// `$name = ...` binds: an array element, property, or list target says nothing
/// about a local symbol. The right-hand side is unwrapped through parentheses
/// and then offered to `resolve_value`, which is the surface's own structured
/// type evaluator (it also receives the bindings in force before this
/// assignment, because a right-hand side may read them).
///
/// A resolvable right-hand side seeds the symbol with that type. A plain
/// `$a = $b` aliases, which is sound single-assignment flow. Anything else
/// declares a shadow so a later read of the name fails closed rather than
/// reaching an outer binding of the same name.
pub fn seed_assignment_binding<'tree, F>(
    node: Node<'tree>,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    resolve_value: F,
) where
    F: FnOnce(Node<'tree>, &LocalInferenceEngine<String>) -> Option<String>,
{
    let Some((left, right)) = assignment_parts(node) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let name = variable_identifier(left, source);
    if name.is_empty() {
        return;
    }
    let right = unwrap_parenthesized(right);
    if let Some(fq_name) = resolve_value(right, bindings) {
        bindings.seed_symbol(name.to_string(), fq_name);
        return;
    }
    if right.kind() == "variable_name" {
        let alias = variable_identifier(right, source);
        if !alias.is_empty() {
            bindings.alias_symbol(name.to_string(), alias);
            return;
        }
    }
    bindings.declare_shadow(name.to_string());
}

/// Resolve the declared object type an assignment's right-hand side produces,
/// for the two usage-graph surfaces. A construction names its class; a literal
/// free or scoped call is typed by its declared return. `enclosing_owner` is
/// consulted only for a scoped call, whose scope may be `self`/`static`/`parent`,
/// so a caller that pays an index lookup for it does not pay it otherwise.
pub fn assignment_value_type_fq_name<F>(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    enclosing_owner: F,
) -> Option<String>
where
    F: FnOnce() -> Option<String>,
{
    match node.kind() {
        "object_creation_expression" => object_creation_type(node)
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx)),
        "function_call_expression" => {
            direct_call_return_type_fq_name(php, analyzer, node, source, ctx, None)
        }
        "scoped_call_expression" => {
            let owner = enclosing_owner();
            direct_call_return_type_fq_name(php, analyzer, node, source, ctx, owner.as_deref())
        }
        _ => None,
    }
}

pub fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name" | "relative_scope"))
}

pub fn static_member_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let scope = node
        .child_by_field_name("scope")
        .or_else(|| node.child_by_field_name("class"))
        .or_else(|| node.named_child(0))?;
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("constant"))
        .or_else(|| node.named_child(1))?;
    Some((scope, name))
}

/// Resolve the class named by a PHP static scope. Unlike ordinary type syntax,
/// `self`, `static`, and `parent` are relative to the lexically enclosing class.
/// Keep that interpretation shared by the targeted and inverted usage walkers
/// so return-type inference for assignments follows the same owner semantics as
/// the static call edge itself.
pub fn static_scope_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    raw: &str,
    ctx: &PhpFileContext,
    enclosing_owner: Option<&str>,
) -> Option<String> {
    match raw {
        "self" | "static" => enclosing_owner.map(str::to_string),
        "parent" => {
            let enclosing_owner = enclosing_owner?;
            let mut definitions = analyzer
                .index
                .definitions(enclosing_owner)
                .filter(CodeUnit::is_class);
            let enclosing_class = definitions.next()?;
            if definitions.next().is_some() {
                return None;
            }
            php_direct_declared_class_parent(php, &enclosing_class).map(|parent| parent.fq_name())
        }
        _ => resolve_php_type(raw, ctx),
    }
}

pub fn variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

pub fn literal_member_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "name").then(|| node_text(node, source))
}

pub fn static_property_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "variable_name").then(|| variable_identifier(node, source))
}

pub fn declared_field_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    field: &CodeUnit,
) -> Option<String> {
    if !field.is_field() {
        return None;
    }
    indexed_declared_type_fq_name(analyzer, field)
        .or_else(|| signature_declared_type_fq_name(php, analyzer, field))
}

pub fn declared_callable_return_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    callable: &CodeUnit,
) -> Option<String> {
    if !callable.is_function() {
        return None;
    }
    indexed_declared_type_fq_name(analyzer, callable)
        .or_else(|| signature_declared_type_fq_name(php, analyzer, callable))
}

/// Resolve the declared object return type of one literal free or scoped PHP
/// call. Dynamic callable names and ambiguous physical declarations fail
/// closed. This is shared by direct receiver chains and assignment inference so
/// both usage-graph surfaces apply the same namespace and relative-scope rules.
pub fn direct_call_return_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    enclosing_owner: Option<&str>,
) -> Option<String> {
    let callable_fq_name = match node.kind() {
        "function_call_expression" => {
            let function = node.child_by_field_name("function")?;
            let candidates = resolve_php_function_node(function, source, ctx, || true)?;
            candidates
                .first_indexed(|candidate| {
                    analyzer
                        .index
                        .definitions(candidate)
                        .any(|unit| unit.is_function())
                })
                .to_string()
        }
        "scoped_call_expression" => {
            let (scope, member) = static_member_parts(node)?;
            let owner = static_scope_type_fq_name(
                php,
                analyzer,
                node_text(scope, source),
                ctx,
                enclosing_owner,
            )?;
            let member = literal_member_identifier(member, source)?;
            format!("{owner}.{member}")
        }
        _ => return None,
    };

    if let Some(return_type) = analyzer.facts.callable_return_type_fqn(&callable_fq_name) {
        return Some(return_type);
    }

    let mut definitions = analyzer
        .index
        .definitions(&callable_fq_name)
        .filter(CodeUnit::is_function);
    let callable = definitions.next()?;
    if definitions.next().is_some() {
        return None;
    }
    declared_callable_return_type_fq_name(php, analyzer, &callable)
}

/// Resolve the declared object type of a PHP instance receiver without walking
/// the source tree recursively. Method-call and field-access chains are reduced
/// from their innermost receiver outward, and every step fails closed unless it
/// has one structured declaration with a class return/type fact.
pub fn instance_receiver_type_fq_name<F>(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    root: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
    mut enclosing_owner: F,
) -> Option<String>
where
    F: FnMut(usize, usize) -> Option<String>,
{
    enum Visit<'tree> {
        Resolve(Node<'tree>),
        Finish(Node<'tree>),
    }

    let mut resolved = HashMap::default();
    let mut stack = vec![Visit::Resolve(root)];
    while let Some(visit) = stack.pop() {
        let node = match visit {
            Visit::Resolve(node) => {
                match node.kind() {
                    "variable_name" => {
                        let name = variable_identifier(node, source);
                        let value = if name == "this" {
                            enclosing_owner(node.start_byte(), node.end_byte())
                        } else {
                            match bindings.resolve_symbol(name) {
                                SymbolResolution::Precise(targets) if targets.len() == 1 => {
                                    targets.into_iter().next()
                                }
                                SymbolResolution::Unknown
                                | SymbolResolution::Ambiguous
                                | SymbolResolution::Precise(_) => None,
                            }
                        };
                        if let Some(value) = value {
                            resolved.insert(node.id(), value);
                        }
                    }
                    "object_creation_expression" => {
                        if let Some(type_node) = object_creation_type(node) {
                            let raw = node_text(type_node, source);
                            let owner =
                                enclosing_owner(type_node.start_byte(), type_node.end_byte());
                            if let Some(value) =
                                static_scope_type_fq_name(php, analyzer, raw, ctx, owner.as_deref())
                            {
                                resolved.insert(node.id(), value);
                            }
                        }
                    }
                    "function_call_expression" | "scoped_call_expression" => {
                        let owner = (node.kind() == "scoped_call_expression")
                            .then(|| enclosing_owner(node.start_byte(), node.end_byte()))
                            .flatten();
                        if let Some(value) = direct_call_return_type_fq_name(
                            php,
                            analyzer,
                            node,
                            source,
                            ctx,
                            owner.as_deref(),
                        ) {
                            resolved.insert(node.id(), value);
                        }
                    }
                    "parenthesized_expression"
                    | "member_access_expression"
                    | "nullsafe_member_access_expression"
                    | "member_call_expression"
                    | "nullsafe_member_call_expression" => {
                        let dependency = if node.kind() == "parenthesized_expression" {
                            node.named_child(0)
                        } else {
                            node.child_by_field_name("object")
                        };
                        if let Some(dependency) = dependency {
                            stack.push(Visit::Finish(node));
                            stack.push(Visit::Resolve(dependency));
                        }
                    }
                    _ => {}
                }
                continue;
            }
            Visit::Finish(node) => node,
        };

        let dependency = if node.kind() == "parenthesized_expression" {
            node.named_child(0)
        } else {
            node.child_by_field_name("object")
        }?;
        let owner = resolved.get(&dependency.id())?;
        let value = match node.kind() {
            "parenthesized_expression" => Some(owner.clone()),
            "member_access_expression" | "nullsafe_member_access_expression" => {
                let member = node.child_by_field_name("name")?;
                declared_instance_field(
                    php,
                    analyzer,
                    owner,
                    literal_member_identifier(member, source)?,
                )
                .and_then(|field| declared_field_type_fq_name(php, analyzer, &field))
            }
            "member_call_expression" | "nullsafe_member_call_expression" => {
                let member = node.child_by_field_name("name")?;
                declared_instance_callable(
                    php,
                    analyzer,
                    owner,
                    literal_member_identifier(member, source)?,
                )
                .and_then(|callable| {
                    declared_callable_return_type_fq_name(php, analyzer, &callable)
                })
            }
            _ => None,
        };
        if let Some(value) = value {
            resolved.insert(node.id(), value);
        }
    }
    resolved.remove(&root.id())
}

pub fn declared_instance_callable(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
) -> Option<CodeUnit> {
    declared_member(php, analyzer, owner_fq_name, member, CodeUnit::is_function)
}

pub fn declared_instance_field(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
) -> Option<CodeUnit> {
    declared_member(php, analyzer, owner_fq_name, member, CodeUnit::is_field)
}

fn declared_member(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
    wanted: fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if let Some(direct) = unique_member(analyzer, owner_fq_name, member, wanted).ok()? {
        return Some(direct);
    }

    let mut owners = analyzer
        .index
        .definitions(owner_fq_name)
        .filter(CodeUnit::is_class);
    let owner = owners.next()?;
    if owners.next().is_some() {
        return None;
    }

    let mut seen = HashSet::default();
    seen.insert(owner_fq_name.to_string());
    let mut level = php.get_direct_ancestors(&owner);
    while !level.is_empty() {
        let mut candidate = None;
        let mut next_level = Vec::new();
        for ancestor in level {
            let ancestor_fq_name = ancestor.fq_name();
            if !seen.insert(ancestor_fq_name.clone()) {
                continue;
            }
            if let Some(found) = unique_member(analyzer, &ancestor_fq_name, member, wanted).ok()? {
                if candidate.is_some() {
                    return None;
                }
                candidate = Some(found);
            }
            next_level.extend(php.get_direct_ancestors(&ancestor));
        }
        if candidate.is_some() {
            return candidate;
        }
        level = next_level;
    }
    None
}

fn unique_member(
    analyzer: PhpGraphSource<'_>,
    owner_fq_name: &str,
    member: &str,
    wanted: fn(&CodeUnit) -> bool,
) -> Result<Option<CodeUnit>, ()> {
    let mut definitions = analyzer
        .index
        .definitions(&format!("{owner_fq_name}.{member}"))
        .filter(wanted);
    let Some(definition) = definitions.next() else {
        return Ok(None);
    };
    if definitions.next().is_some() {
        return Err(());
    }
    Ok(Some(definition))
}

fn indexed_declared_type_fq_name(analyzer: PhpGraphSource<'_>, unit: &CodeUnit) -> Option<String> {
    analyzer.facts.declaration_return_type_fqn(unit)
}

/// Every class the declared type of one field or callable names.
///
/// This is the arms-aware form of [`declared_field_type_fq_name`] and
/// [`declared_callable_return_type_fq_name`], for the one surface that can
/// carry bounded ambiguity (forward definition lookup). A union declaration
/// yields one entry per arm; every other declaration yields at most one.
pub fn declared_type_arm_fq_names(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> Vec<String> {
    declared_type_of(php, analyzer, unit).arms()
}

/// What the declared type of one field or callable proves, including the case
/// where it proves the value is dynamic (`object`/`mixed`) rather than nothing.
///
/// [`declared_type_arm_fq_names`] is this computation read for its classes
/// only; forward definition lookup reads the whole answer so it can tell a
/// proven-dynamic declaration from one it does not follow (#2030).
pub fn declared_type_of(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> PhpDeclaredType {
    if !unit.is_field() && !unit.is_function() {
        return PhpDeclaredType::Unknown;
    }
    if let Some(indexed) = indexed_declared_type_fq_name(analyzer, unit) {
        return PhpDeclaredType::Nominal(vec![indexed]);
    }
    signature_declared_type(php, analyzer, unit)
}

fn signature_declared_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> Option<String> {
    let mut arms = signature_declared_type(php, analyzer, unit).arms();
    (arms.len() == 1).then(|| arms.remove(0))
}

fn signature_declared_type(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> PhpDeclaredType {
    let signatures = analyzer.index.signatures(unit);
    let Some(raw) = signatures
        .iter()
        .find_map(|signature| php_signature_return_type_text(signature))
    else {
        return PhpDeclaredType::Unknown;
    };
    if let Some(keyword) = php_dynamic_type_keyword(raw) {
        return PhpDeclaredType::Dynamic(keyword);
    }
    if matches!(raw, "self" | "static") {
        return PhpDeclaredType::nominal(
            php.parent_of(unit)
                .map(|owner| owner.fq_name())
                .into_iter()
                .collect(),
        );
    }
    let Ok(source) = unit.source().read_to_string() else {
        return PhpDeclaredType::Unknown;
    };
    let ctx = php_file_context_from_source(php, unit.source(), &source);
    PhpDeclaredType::nominal(resolve_php_type_arms(raw, &ctx))
}

/// The member surface a PHP reference addresses.
///
/// PHP resolves an absent member through a different magic method for each
/// surface, and [`magic_member_names`] is the one table of those methods that
/// both the semantic-diagnostics pass and forward definition lookup read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpMagicSurface {
    InstanceCall,
    InstanceProperty,
    StaticCall,
    /// A static property or class constant: PHP has no magic hook for either,
    /// so an absent member on this surface really is absent.
    StaticData,
}

/// The magic methods through which an owner resolves an absent member of
/// `surface` at run time.
pub fn magic_member_names(surface: PhpMagicSurface) -> &'static [&'static str] {
    match surface {
        PhpMagicSurface::InstanceCall => &["__call"],
        PhpMagicSurface::InstanceProperty => &["__get", "__set"],
        PhpMagicSurface::StaticCall => &["__callStatic"],
        PhpMagicSurface::StaticData => &[],
    }
}
