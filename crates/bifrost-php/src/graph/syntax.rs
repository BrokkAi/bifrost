use super::resolver::node_text;
use crate::adapter::php_signature_return_type_text;
use crate::aliases::{PhpFileContext, resolve_php_type};
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

pub fn seed_parameter_types<F>(
    node: Node<'_>,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    mut resolve_type: F,
) where
    F: FnMut(&str) -> Option<String>,
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
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type(node_text(type_node, source)))
        {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
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

fn signature_declared_type_fq_name(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    unit: &CodeUnit,
) -> Option<String> {
    let signatures = analyzer.index.signatures(unit);
    let raw = signatures
        .iter()
        .find_map(|signature| php_signature_return_type_text(signature))?;
    if matches!(raw, "self" | "static") {
        return php.parent_of(unit).map(|owner| owner.fq_name());
    }
    let source = unit.source().read_to_string().ok()?;
    let ctx = php_file_context_from_source(php, unit.source(), &source);
    resolve_php_type(raw, &ctx)
}
