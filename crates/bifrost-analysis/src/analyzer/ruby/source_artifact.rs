use tree_sitter::Node;

use super::declarations::ruby_node_text;
use super::{extract_name_segments, parse_ruby_tree, ruby_call_arguments, ruby_symbol_name};
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, HierarchyFact, HierarchyKind, Locator,
    MemberFact, MemberIdentity, MemberKind, Parameter, ProducerDiagnostic, Signature, TypeFact,
    TypeIdentity, TypeKind, TypeRef, Visibility, member_declaration_id, type_declaration_id,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubySourceProjection {
    pub types: Vec<TypeFact>,
    pub members: Vec<MemberFact>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: usize,
    pub complete: bool,
}

struct Work<'tree> {
    node: Node<'tree>,
    namespace: Vec<String>,
    owner_id: Option<String>,
}

pub(crate) fn project_ruby_source(
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    rbi: bool,
) -> RubySourceProjection {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    let Some(tree) = parse_ruby_tree(source) else {
        diagnostics.error(
            "ruby.source.parse",
            Some(logical_path(archive_sha256, entry_path)),
            "could not parse Ruby declaration source",
        );
        return finish(Vec::new(), Vec::new(), diagnostics, false);
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
    let mut stack = Vec::new();
    push_children(tree.root_node(), &[], None, &mut stack);
    while let Some(work) = stack.pop() {
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
                ) {
                    members.push(member);
                }
            }
            "call" => project_call(
                work.node,
                work.owner_id.as_deref(),
                archive_sha256,
                entry_path,
                source,
                &mut types,
                &mut members,
            ),
            "singleton_class" => {
                if let Some(body) = work.node.child_by_field_name("body") {
                    push_children(body, &work.namespace, work.owner_id, &mut stack);
                }
            }
            "body_statement" | "program" => {
                push_children(work.node, &work.namespace, work.owner_id, &mut stack);
            }
            _ => {}
        }
    }
    let complete = diagnostics.is_empty();
    finish(types, members, diagnostics, complete)
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
        type_parameters: Vec::new(),
        hierarchy,
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        locator: locator(archive_sha256, entry_path, &namespace.join("::")),
    });
    if let Some(body) = work.node.child_by_field_name("body") {
        push_children(body, &namespace, Some(owner_id), stack);
    }
}

fn project_method(
    node: Node<'_>,
    owner_id: Option<&str>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    rbi: bool,
) -> Option<MemberFact> {
    let owner_id = owner_id?;
    let name_node = node.child_by_field_name("name")?;
    let name = ruby_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let is_static = node.kind() == "singleton_method";
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
        return_type: signature.returns.as_ref(),
    });
    Some(MemberFact {
        id,
        owner: owner_id.to_owned(),
        name: name.to_owned(),
        member_kind: MemberKind::Method,
        visibility: Visibility::Public,
        is_static,
        is_abstract: false,
        is_virtual: true,
        signature: Some(signature),
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
) {
    let Some(owner_id) = owner_id else {
        return;
    };
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
                is_static: false,
                parameter_arity: 0,
                name: &name,
                generic_arity: 0,
                parameter_types: &[],
                return_type: signature.returns.as_ref(),
            });
            members.push(MemberFact {
                id,
                owner: owner_id.to_owned(),
                name: name.clone(),
                member_kind: property_kind,
                visibility: Visibility::Public,
                is_static: false,
                is_abstract: false,
                is_virtual: true,
                signature: Some(signature),
                aliases: Vec::new(),
                locator: locator(archive_sha256, entry_path, &name),
            });
        }
    }
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
    stack: &mut Vec<Work<'tree>>,
) {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    for child in children.into_iter().rev() {
        stack.push(Work {
            node: child,
            namespace: namespace.to_vec(),
            owner_id: owner_id.clone(),
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
    def self.build; end
  end
end
"#,
            &ArtifactProducerLimits::default(),
            true,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        let widget = projection
            .types
            .iter()
            .find(|fact| fact.name == "Acme::Widget")
            .unwrap();
        assert_eq!(widget.hierarchy.len(), 4);
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
        assert!(
            projection
                .members
                .iter()
                .any(|fact| fact.name == "build" && fact.is_static)
        );
    }
}
