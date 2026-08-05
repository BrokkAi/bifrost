use tree_sitter::Node;

use super::rbs_artifact::RubyMemberAlias;
use super::{extract_name_segments, parse_ruby_tree, ruby_call_arguments, ruby_symbol_name};
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, HierarchyFact, HierarchyKind, Locator,
    MemberFact, MemberIdentity, MemberKind, Parameter, ProducerDiagnostic, Signature, TypeFact,
    TypeIdentity, TypeKind, TypeRef, Visibility, member_declaration_id, type_declaration_id,
};
use brokk_bifrost_ruby::declarations::ruby_node_text;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubySourceProjection {
    pub types: Vec<TypeFact>,
    pub members: Vec<MemberFact>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: usize,
    pub complete: bool,
    pub aliases: Vec<RubyMemberAlias>,
}

struct Work<'tree> {
    node: Node<'tree>,
    namespace: Vec<String>,
    owner_id: Option<String>,
    singleton_context: bool,
    visibility: Visibility,
}

pub(crate) fn project_ruby_source(
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    rbi: bool,
    cancellation: Option<&CancellationToken>,
) -> RubySourceProjection {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        diagnostics.error(
            "ruby.source.cancelled",
            None,
            "Ruby declaration projection was cancelled",
        );
        return finish(Vec::new(), Vec::new(), Vec::new(), diagnostics, false);
    }
    let Some(tree) = parse_ruby_tree(source) else {
        diagnostics.error(
            "ruby.source.parse",
            Some(logical_path(archive_sha256, entry_path)),
            "could not parse Ruby declaration source",
        );
        return finish(Vec::new(), Vec::new(), Vec::new(), diagnostics, false);
    };
    if tree.root_node().has_error() {
        diagnostics.warning(
            if rbi {
                "ruby.rbi.syntax"
            } else {
                "ruby.source.syntax"
            },
            Some(logical_path(archive_sha256, entry_path)),
            "Ruby declaration source contains syntax errors",
        );
    }

    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut aliases = Vec::new();
    let mut stack = Vec::new();
    push_children(
        tree.root_node(),
        &[],
        None,
        false,
        Visibility::Public,
        &mut stack,
    );
    while let Some(work) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "ruby.source.cancelled",
                None,
                "Ruby declaration projection was cancelled",
            );
            break;
        }
        if types.len().saturating_add(members.len()) >= limits.max_records {
            diagnostics.error(
                "limit.records",
                Some(logical_path(archive_sha256, entry_path)),
                format!(
                    "Ruby declarations exceed the {} record limit",
                    limits.max_records
                ),
            );
            break;
        }
        match work.node.kind() {
            "class" | "module" => project_type(
                work,
                archive_sha256,
                entry_path,
                source,
                &mut stack,
                &mut types,
            ),
            "method" | "singleton_method" => {
                if let Some(member) = project_method(
                    work.node,
                    work.owner_id.as_deref(),
                    archive_sha256,
                    entry_path,
                    source,
                    rbi,
                    work.singleton_context,
                    work.visibility,
                ) {
                    members.push(member);
                }
            }
            "call" => {
                if work.node.child_by_field_name("receiver").is_none()
                    && ruby_call_arguments(work.node).is_empty()
                    && let Some(visibility) = visibility_directive(work.node, source)
                {
                    for pending in stack.iter_mut().filter(|pending| {
                        pending.owner_id == work.owner_id
                            && pending.singleton_context == work.singleton_context
                    }) {
                        pending.visibility = visibility;
                    }
                }
                project_call(
                    work.node,
                    work.owner_id.as_deref(),
                    archive_sha256,
                    entry_path,
                    source,
                    &mut types,
                    &mut members,
                    limits,
                    rbi,
                    work.singleton_context,
                    work.visibility,
                    &mut diagnostics,
                );
            }
            "assignment" => project_constant_assignment(
                work.node,
                work.owner_id.as_deref(),
                archive_sha256,
                entry_path,
                source,
                &mut members,
            ),
            "alias" => project_alias(
                work.node,
                work.owner_id.as_deref(),
                source,
                &mut members,
                &mut aliases,
                work.singleton_context,
            ),
            "singleton_class" => {
                if let Some(body) = work.node.child_by_field_name("body") {
                    push_children(
                        body,
                        &work.namespace,
                        work.owner_id,
                        true,
                        Visibility::Public,
                        &mut stack,
                    );
                }
            }
            "body_statement" | "program" => {
                push_children(
                    work.node,
                    &work.namespace,
                    work.owner_id,
                    work.singleton_context,
                    work.visibility,
                    &mut stack,
                );
            }
            "if" | "unless" | "if_modifier" | "unless_modifier" | "elsif" | "conditional"
            | "case" | "while" | "until" | "for" | "begin" | "rescue" => {
                diagnostics.warning(
                    if rbi {
                        "ruby.rbi.conditional_declaration"
                    } else {
                        "ruby.source.conditional_declaration"
                    },
                    Some(logical_path(archive_sha256, entry_path)),
                    format!(
                        "Ruby {} declarations are not projected because their execution is conditional",
                        work.node.kind()
                    ),
                );
            }
            "identifier" => {
                let name = ruby_node_text(work.node, source).trim();
                if let Some(visibility) = visibility_name(name) {
                    for pending in stack.iter_mut().filter(|pending| {
                        pending.owner_id == work.owner_id
                            && pending.singleton_context == work.singleton_context
                    }) {
                        pending.visibility = visibility;
                    }
                } else if work.owner_id.is_some() {
                    diagnostics.warning(
                        if rbi {
                            "ruby.rbi.unsupported_dsl"
                        } else {
                            "ruby.source.dynamic_declaration"
                        },
                        Some(logical_path(archive_sha256, entry_path)),
                        format!(
                            "Ruby declaration-scope identifier {name} is not statically projected"
                        ),
                    );
                }
            }
            _ => {}
        }
    }
    let complete = diagnostics.is_empty();
    finish(types, members, aliases, diagnostics, complete)
}

fn project_constant_assignment(
    node: Node<'_>,
    owner_id: Option<&str>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    members: &mut Vec<MemberFact>,
) {
    let Some(default_owner_id) = owner_id else {
        return;
    };
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let segments = extract_name_segments(left, source);
    let Some(name) = segments.last() else {
        return;
    };
    if left.kind() != "constant" && left.kind() != "scope_resolution" {
        return;
    }
    let explicit_owner_id;
    let owner_id = if segments.len() > 1 {
        explicit_owner_id = type_declaration_id(TypeIdentity {
            ecosystem: "rubygems",
            name: &segments[..segments.len() - 1].join("::"),
        });
        explicit_owner_id.as_str()
    } else {
        default_owner_id
    };
    let return_type = named("untyped".to_owned());
    let signature = Signature {
        type_parameters: Vec::new(),
        parameters: Vec::new(),
        returns: Some(return_type.clone()),
    };
    members.push(MemberFact {
        id: member_declaration_id(MemberIdentity {
            owner_id,
            kind: MemberKind::Constant,
            is_static: true,
            parameter_arity: 0,
            name,
            generic_arity: 0,
            parameter_types: &[],
            parameter_variadics: &[],
            return_type: Some(&return_type),
        }),
        owner: owner_id.to_owned(),
        name: name.clone(),
        member_kind: MemberKind::Constant,
        visibility: Visibility::Public,
        is_static: true,
        is_abstract: false,
        is_virtual: false,
        signature: Some(signature),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        locator: locator(archive_sha256, entry_path, name),
    });
}

#[allow(clippy::too_many_arguments)]
fn project_alias(
    node: Node<'_>,
    owner_id: Option<&str>,
    source: &str,
    members: &mut [MemberFact],
    aliases: &mut Vec<RubyMemberAlias>,
    singleton_context: bool,
) {
    let Some(owner_id) = owner_id else {
        return;
    };
    let Some(new_name) = node.child_by_field_name("name").and_then(|name| {
        ruby_symbol_name(name, source).or_else(|| Some(ruby_node_text(name, source).to_owned()))
    }) else {
        return;
    };
    let Some(old_name) = node.child_by_field_name("alias").and_then(|name| {
        ruby_symbol_name(name, source).or_else(|| Some(ruby_node_text(name, source).to_owned()))
    }) else {
        return;
    };
    aliases.push(RubyMemberAlias {
        owner: owner_id.to_owned(),
        old_name: old_name.clone(),
        new_name: new_name.clone(),
        is_static: singleton_context,
    });
    for member in members.iter_mut().filter(|member| {
        member.owner == owner_id && member.name == old_name && member.is_static == singleton_context
    }) {
        if !member.aliases.contains(&new_name) {
            member.aliases.push(new_name.clone());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn project_type<'tree>(
    work: Work<'tree>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    stack: &mut Vec<Work<'tree>>,
    types: &mut Vec<TypeFact>,
) {
    let Some(name_node) = work.node.child_by_field_name("name") else {
        return;
    };
    let segments = extract_name_segments(name_node, source);
    if segments.is_empty() {
        return;
    }
    let mut namespace = work.namespace;
    namespace.extend(segments);
    let name = namespace.join("::");
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "rubygems",
        name: &name,
    });
    let mut hierarchy = Vec::new();
    if work.node.kind() == "class"
        && let Some(superclass) = work.node.child_by_field_name("superclass")
        && let Some(superclass) = superclass.named_child(0)
    {
        let superclass = extract_name_segments(superclass, source);
        if !superclass.is_empty() {
            hierarchy.push(HierarchyFact {
                hierarchy_kind: HierarchyKind::Extends,
                target: named(superclass.join("::")),
                declaration_ordinal: None,
            });
        }
    }
    types.push(TypeFact {
        id: owner_id.clone(),
        name,
        type_kind: if work.node.kind() == "module" {
            TypeKind::Module
        } else {
            TypeKind::Class
        },
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
        has_explicit_type_terms: false,
        type_parameters: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        embedded_types: Vec::new(),
        hierarchy,
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        locator: locator(archive_sha256, entry_path, &namespace.join("::")),
    });
    if let Some(body) = work.node.child_by_field_name("body") {
        push_children(
            body,
            &namespace,
            Some(owner_id),
            false,
            Visibility::Public,
            stack,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn project_method(
    node: Node<'_>,
    owner_id: Option<&str>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    rbi: bool,
    singleton_context: bool,
    visibility: Visibility,
) -> Option<MemberFact> {
    let owner_id = owner_id?;
    let name_node = node.child_by_field_name("name")?;
    let name = ruby_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let is_static = singleton_context || node.kind() == "singleton_method";
    let mut parameters = node
        .child_by_field_name("parameters")
        .map(|parameters| source_parameters(parameters, source))
        .unwrap_or_default();
    let sorbet_signature = rbi
        .then(|| node.prev_named_sibling())
        .flatten()
        .and_then(|candidate| sorbet_signature(candidate, source));
    if let Some(signature) = &sorbet_signature {
        for parameter in &mut parameters {
            if let Some(name) = &parameter.name
                && let Some(parameter_type) = signature.parameters.get(name)
            {
                parameter.r#type = parameter_type.clone();
            }
        }
    }
    let parameter_types = parameters
        .iter()
        .map(|parameter| parameter.r#type.clone())
        .collect::<Vec<_>>();
    let signature = Signature {
        type_parameters: Vec::new(),
        parameters,
        returns: sorbet_signature.and_then(|signature| signature.returns),
    };
    let id = member_declaration_id(MemberIdentity {
        owner_id,
        kind: MemberKind::Method,
        is_static,
        parameter_arity: parameter_types.len(),
        name,
        generic_arity: 0,
        parameter_types: &parameter_types,
        parameter_variadics: &[],
        return_type: signature.returns.as_ref(),
    });
    Some(MemberFact {
        id,
        owner: owner_id.to_owned(),
        name: name.to_owned(),
        member_kind: MemberKind::Method,
        visibility,
        is_static,
        is_abstract: false,
        is_virtual: true,
        signature: Some(signature),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        locator: locator(archive_sha256, entry_path, name),
    })
}

#[allow(clippy::too_many_arguments)]
fn project_call(
    node: Node<'_>,
    owner_id: Option<&str>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    types: &mut [TypeFact],
    members: &mut Vec<MemberFact>,
    limits: &ArtifactProducerLimits,
    rbi: bool,
    singleton_context: bool,
    visibility: Visibility,
    diagnostics: &mut BoundedProducerDiagnostics,
) {
    let Some(owner_id) = owner_id else {
        return;
    };
    if node.child_by_field_name("receiver").is_some() {
        return;
    }
    let Some(method) = node.child_by_field_name("method") else {
        return;
    };
    let method = ruby_node_text(method, source).trim();
    let arguments = ruby_call_arguments(node);
    let hierarchy_kind = match method {
        "include" => Some(HierarchyKind::MixinInclude),
        "prepend" => Some(HierarchyKind::MixinPrepend),
        "extend" => Some(HierarchyKind::MixinExtend),
        _ => None,
    };
    if let Some(hierarchy_kind) = hierarchy_kind {
        let Some(owner) = types.iter_mut().rev().find(|fact| fact.id == owner_id) else {
            return;
        };
        for argument in arguments {
            let segments = extract_name_segments(argument, source);
            if segments.is_empty() {
                continue;
            }
            owner.hierarchy.push(HierarchyFact {
                hierarchy_kind,
                target: named(segments.join("::")),
                declaration_ordinal: Some(owner.hierarchy.len() as u32),
            });
        }
        return;
    }
    let property_kind = match method {
        "attr_reader" | "attr_writer" | "attr_accessor" => Some(MemberKind::Property),
        _ => None,
    };
    if let Some(property_kind) = property_kind {
        for argument in arguments {
            if types.len().saturating_add(members.len()) >= limits.max_records {
                diagnostics.error(
                    "limit.records",
                    Some(logical_path(archive_sha256, entry_path)),
                    format!(
                        "Ruby declarations exceed the {} record limit",
                        limits.max_records
                    ),
                );
                break;
            }
            let Some(name) = ruby_symbol_name(argument, source) else {
                continue;
            };
            let property_type = named("untyped".to_owned());
            let signature = Signature {
                type_parameters: Vec::new(),
                parameters: Vec::new(),
                returns: Some(property_type),
            };
            let id = member_declaration_id(MemberIdentity {
                owner_id,
                kind: property_kind,
                is_static: singleton_context,
                parameter_arity: 0,
                name: &name,
                generic_arity: 0,
                parameter_types: &[],
                parameter_variadics: &[],
                return_type: signature.returns.as_ref(),
            });
            members.push(MemberFact {
                id,
                owner: owner_id.to_owned(),
                name: name.clone(),
                member_kind: property_kind,
                visibility,
                is_static: singleton_context,
                is_abstract: false,
                is_virtual: true,
                signature: Some(signature),
                receiver: None,
                extension_receiver: None,
                extension_receiver_constraints: Vec::new(),
                aliases: Vec::new(),
                locator: locator(archive_sha256, entry_path, &name),
            });
        }
        return;
    }
    if let Some(declared_visibility) = visibility_name(method) {
        for argument in arguments {
            let Some(name) = ruby_symbol_name(argument, source) else {
                continue;
            };
            for member in members.iter_mut().filter(|member| {
                member.owner == owner_id
                    && member.name == name
                    && member.is_static == singleton_context
            }) {
                member.visibility = declared_visibility;
            }
        }
        return;
    }
    if method == "sig" {
        return;
    }
    if matches!(method, "abstract!" | "interface!") {
        if let Some(owner) = types.iter_mut().rev().find(|fact| fact.id == owner_id) {
            owner.is_abstract = true;
            if method == "interface!" {
                owner.type_kind = TypeKind::Interface;
            }
        }
        return;
    }
    diagnostics.warning(
        if rbi {
            "ruby.rbi.unsupported_dsl"
        } else {
            "ruby.source.dynamic_declaration"
        },
        Some(logical_path(archive_sha256, entry_path)),
        format!("Ruby declaration-scope call {method} is not statically projected"),
    );
}

fn source_parameters(parameters: Node<'_>, source: &str) -> Vec<Parameter> {
    let mut result = Vec::new();
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" => result.push(Parameter {
                name: Some(ruby_node_text(node, source).to_owned()),
                r#type: named("untyped".to_owned()),
                optional: false,
                variadic: false,
            }),
            "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "block_parameter" => {
                let name = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))
                    .filter(|name| name.kind() == "identifier")
                    .map(|name| ruby_node_text(name, source).to_owned());
                result.push(Parameter {
                    name,
                    r#type: named("untyped".to_owned()),
                    optional: matches!(node.kind(), "optional_parameter" | "keyword_parameter"),
                    variadic: matches!(node.kind(), "splat_parameter" | "hash_splat_parameter"),
                });
            }
            _ => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                stack.extend(children.into_iter().rev());
            }
        }
    }
    result
}

struct SorbetSignature {
    parameters: crate::hash::HashMap<String, TypeRef>,
    returns: Option<TypeRef>,
}

fn sorbet_signature(sig_call: Node<'_>, source: &str) -> Option<SorbetSignature> {
    if sig_call.kind() != "call" || call_method(sig_call, source)? != "sig" {
        return None;
    }
    let block = sig_call.child_by_field_name("block")?;
    let returns_call = descendant_calls(block)
        .into_iter()
        .find(|call| call_method(*call, source) == Some("returns"))?;
    let returns = ruby_call_arguments(returns_call)
        .into_iter()
        .next()
        .map(|node| sorbet_type(node, source));
    let mut parameters = crate::hash::HashMap::default();
    if let Some(params_call) = returns_call.child_by_field_name("receiver")
        && params_call.kind() == "call"
        && call_method(params_call, source) == Some("params")
    {
        for argument in ruby_call_arguments(params_call) {
            if argument.kind() != "pair" {
                continue;
            }
            let Some(key) = argument.child_by_field_name("key") else {
                continue;
            };
            let Some(value) = argument.child_by_field_name("value") else {
                continue;
            };
            if let Some(name) = rbi_parameter_name(key, source) {
                parameters.insert(name, sorbet_type(value, source));
            }
        }
    }
    Some(SorbetSignature {
        parameters,
        returns,
    })
}

fn rbi_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = ruby_symbol_name(node, source) {
        return Some(name);
    }
    if node.kind() != "hash_key_symbol" {
        return None;
    }
    let text = ruby_node_text(node, source).trim();
    let name = text.strip_suffix(':').unwrap_or(text);
    (!name.is_empty()).then(|| name.to_owned())
}

fn descendant_calls(root: Node<'_>) -> Vec<Node<'_>> {
    let mut calls = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            calls.push(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    calls
}

fn call_method<'a>(call: Node<'_>, source: &'a str) -> Option<&'a str> {
    let method = call.child_by_field_name("method")?;
    Some(ruby_node_text(method, source).trim())
}

fn visibility_directive(call: Node<'_>, source: &str) -> Option<Visibility> {
    visibility_name(call_method(call, source)?)
}

fn visibility_name(name: &str) -> Option<Visibility> {
    match name {
        "public" => Some(Visibility::Public),
        "protected" => Some(Visibility::Protected),
        "private" => Some(Visibility::Private),
        _ => None,
    }
}

fn sorbet_type(node: Node<'_>, source: &str) -> TypeRef {
    if node.kind() == "call" {
        let receiver = node.child_by_field_name("receiver");
        let method = call_method(node, source);
        let receiver_segments = receiver
            .map(|receiver| extract_name_segments(receiver, source))
            .unwrap_or_default();
        if receiver_segments == ["T"] {
            let arguments = ruby_call_arguments(node);
            match method {
                Some("nilable") => {
                    return arguments
                        .into_iter()
                        .next()
                        .map(|argument| nullable(sorbet_type(argument, source)))
                        .unwrap_or_else(|| named("untyped".to_owned()));
                }
                Some("any") => {
                    return TypeRef::Named {
                        name: "union".to_owned(),
                        arguments: arguments
                            .into_iter()
                            .map(|argument| sorbet_type(argument, source))
                            .collect(),
                        nullable: false,
                    };
                }
                Some("untyped") => return named("untyped".to_owned()),
                _ => {}
            }
        }
    }
    let segments = extract_name_segments(node, source);
    if segments.is_empty() {
        named("untyped".to_owned())
    } else {
        named(segments.join("::"))
    }
}

fn nullable(type_ref: TypeRef) -> TypeRef {
    match type_ref {
        TypeRef::Named {
            name, arguments, ..
        } => TypeRef::Named {
            name,
            arguments,
            nullable: true,
        },
        other => TypeRef::Named {
            name: "optional".to_owned(),
            arguments: vec![other],
            nullable: true,
        },
    }
}

fn push_children<'tree>(
    node: Node<'tree>,
    namespace: &[String],
    owner_id: Option<String>,
    singleton_context: bool,
    visibility: Visibility,
    stack: &mut Vec<Work<'tree>>,
) {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    for child in children.into_iter().rev() {
        stack.push(Work {
            node: child,
            namespace: namespace.to_vec(),
            owner_id: owner_id.clone(),
            singleton_context,
            visibility,
        });
    }
}

fn named(name: String) -> TypeRef {
    TypeRef::Named {
        name,
        arguments: Vec::new(),
        nullable: false,
    }
}

fn locator(archive_sha256: &str, entry_path: &str, symbol: &str) -> Locator {
    Locator::Artifact {
        path: logical_path(archive_sha256, entry_path),
        symbol: symbol.to_owned(),
    }
}

fn logical_path(archive_sha256: &str, entry_path: &str) -> String {
    format!("gem+sha256:{archive_sha256}!/{entry_path}")
}

fn finish(
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    aliases: Vec<RubyMemberAlias>,
    diagnostics: BoundedProducerDiagnostics,
    complete: bool,
) -> RubySourceProjection {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    RubySourceProjection {
        types,
        members,
        diagnostics,
        suppressed_diagnostics,
        complete: complete && suppressed_diagnostics == 0,
        aliases,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorbet_sig_projects_parameter_and_return_types() {
        let source = "sig { params(value: String).returns(Integer) }";
        let tree = parse_ruby_tree(source).unwrap();
        let sig = sorbet_signature(tree.root_node().named_child(0).unwrap(), source).unwrap();
        assert_eq!(
            sig.parameters.get("value"),
            Some(&named("String".to_owned()))
        );
        assert_eq!(sig.returns, Some(named("Integer".to_owned())));
    }

    #[test]
    fn rbi_and_source_declarations_use_structured_ruby_nodes() {
        let projection = project_ruby_source(
            &"c".repeat(64),
            "sorbet/rbi/widget.rbi",
            r#"
module Acme
  class Widget < Base
    prepend Instrumented
    include Enumerable
    extend Factory
    attr_reader :name
    sig { params(value: String, label: T.nilable(String)).returns(Integer) }
    def call(value, label: nil); end
    alias invoke call
    def self.build; end
    VERSION = 1
    class << self
      def create; end
    end
  end
end
"#,
            &ArtifactProducerLimits::default(),
            true,
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        let widget = projection
            .types
            .iter()
            .find(|fact| fact.name == "Acme::Widget")
            .unwrap();
        assert_eq!(widget.hierarchy.len(), 4);
        assert_eq!(
            widget.hierarchy[0].target,
            TypeRef::Named {
                name: "Base".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            }
        );
        assert!(projection.members.iter().any(|fact| fact.name == "name"));
        assert!(projection.members.iter().any(|fact| fact.name == "call"));
        let call = projection
            .members
            .iter()
            .find(|fact| fact.name == "call")
            .unwrap();
        let signature = call.signature.as_ref().unwrap();
        assert_eq!(
            signature
                .parameters
                .iter()
                .find(|parameter| parameter.name.as_deref() == Some("value"))
                .unwrap_or_else(|| panic!("{signature:?}"))
                .r#type,
            named("String".to_owned())
        );
        assert_eq!(signature.returns, Some(named("Integer".to_owned())));
        assert_eq!(call.aliases, ["invoke"]);
        assert!(
            projection
                .members
                .iter()
                .any(|fact| fact.name == "build" && fact.is_static)
        );
        assert!(projection.members.iter().any(|fact| fact.name == "VERSION"));
        assert!(
            projection
                .members
                .iter()
                .any(|fact| fact.name == "create" && fact.is_static)
        );
    }

    #[test]
    fn unsupported_declaration_scope_dsl_is_explicitly_partial() {
        let projection = project_ruby_source(
            &"e".repeat(64),
            "sorbet/rbi/dynamic.rbi",
            "class Widget\n  generated_api :call\nend\n",
            &ArtifactProducerLimits::default(),
            true,
            None,
        );

        assert!(!projection.complete);
        assert!(
            projection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "ruby.rbi.unsupported_dsl")
        );
    }

    #[test]
    fn one_declaration_cannot_exceed_the_record_budget() {
        let projection = project_ruby_source(
            &"f".repeat(64),
            "sorbet/rbi/bounded.rbi",
            "class Widget\n  attr_reader :one, :two, :three\nend\n",
            &ArtifactProducerLimits {
                max_records: 2,
                ..ArtifactProducerLimits::default()
            },
            true,
            None,
        );

        assert!(!projection.complete);
        assert!(projection.types.len() + projection.members.len() <= 2);
        assert!(
            projection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );
    }

    #[test]
    fn visibility_directives_update_following_and_named_methods() {
        let projection = project_ruby_source(
            &"1".repeat(64),
            "lib/visibility.rb",
            "class Widget\n  def visible; end\n  private\n  def hidden; end\n  protected :visible\nend\n",
            &ArtifactProducerLimits::default(),
            false,
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        assert_eq!(
            projection
                .members
                .iter()
                .find(|member| member.name == "hidden")
                .unwrap()
                .visibility,
            Visibility::Private
        );
        assert_eq!(
            projection
                .members
                .iter()
                .find(|member| member.name == "visible")
                .unwrap()
                .visibility,
            Visibility::Protected
        );
    }

    #[test]
    fn conditional_declarations_are_explicitly_partial() {
        let projection = project_ruby_source(
            &"2".repeat(64),
            "lib/conditional.rb",
            "class Widget\n  if enabled?\n    def generated; end\n  end\nend\n",
            &ArtifactProducerLimits::default(),
            false,
            None,
        );

        assert!(!projection.complete);
        assert!(projection.members.is_empty());
        assert!(
            projection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "ruby.source.conditional_declaration")
        );
    }

    #[test]
    fn singleton_visibility_and_attributes_are_scoped_separately() {
        let projection = project_ruby_source(
            &"3".repeat(64),
            "lib/singleton_visibility.rb",
            "class Widget\n  private\n  def hidden; end\n  class << self\n    attr_reader :name\n    def visible; end\n    private\n    def secret; end\n  end\n  def after; end\nend\n",
            &ArtifactProducerLimits::default(),
            false,
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        let member = |name: &str, is_static: bool| {
            projection
                .members
                .iter()
                .find(|member| member.name == name && member.is_static == is_static)
                .unwrap_or_else(|| panic!("missing {name}, static={is_static}"))
        };
        assert_eq!(member("hidden", false).visibility, Visibility::Private);
        assert_eq!(member("after", false).visibility, Visibility::Private);
        assert_eq!(member("name", true).visibility, Visibility::Public);
        assert_eq!(member("visible", true).visibility, Visibility::Public);
        assert_eq!(member("secret", true).visibility, Visibility::Private);
    }

    #[test]
    fn receiver_qualified_calls_are_not_declaration_dsl() {
        let projection = project_ruby_source(
            &"4".repeat(64),
            "lib/qualified_calls.rb",
            "class Widget\n  registry.attr_reader :not_a_member\n  registry.include Other\n  policy.private\nend\n",
            &ArtifactProducerLimits::default(),
            false,
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        assert!(projection.members.is_empty());
        assert!(projection.types[0].hierarchy.is_empty());
    }

    #[test]
    fn conditional_modifier_declarations_are_explicitly_partial() {
        let projection = project_ruby_source(
            &"5".repeat(64),
            "lib/conditional_modifier.rb",
            "class Widget\n  def generated; end if enabled?\nend\n",
            &ArtifactProducerLimits::default(),
            false,
            None,
        );

        assert!(!projection.complete);
        assert!(projection.members.is_empty());
    }
}
