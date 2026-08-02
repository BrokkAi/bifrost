use ruby_rbs::node::{
    AliasKind, AttributeKind, AttributeVisibility, ClassNode, FunctionParamNode, FunctionTypeNode,
    MethodDefinitionKind, MethodDefinitionNode, MethodDefinitionVisibility, ModuleNode, Node,
    RBSLocationRange, TypeNameNode,
};

use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, HierarchyFact, HierarchyKind, Locator,
    MemberFact, MemberIdentity, MemberKind, Parameter, ProducerDiagnostic, Signature, TypeFact,
    TypeIdentity, TypeKind, TypeRef, Visibility, member_declaration_id, type_declaration_id,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RbsProjection {
    pub types: Vec<TypeFact>,
    pub members: Vec<MemberFact>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: usize,
    pub complete: bool,
}

pub(crate) fn project_rbs(
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
) -> RbsProjection {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    let signature = match ruby_rbs::node::parse(source) {
        Ok(signature) => signature,
        Err(error) => {
            diagnostics.error(
                "ruby.rbs.parse",
                Some(logical_path(archive_sha256, entry_path)),
                format!("could not parse RBS declaration: {error}"),
            );
            let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
            return RbsProjection {
                types: Vec::new(),
                members: Vec::new(),
                diagnostics,
                suppressed_diagnostics,
                complete: false,
            };
        }
    };

    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut partial = false;
    for declaration in signature.declarations().iter() {
        if types.len().saturating_add(members.len()) >= limits.max_records {
            diagnostics.error(
                "limit.records",
                Some(logical_path(archive_sha256, entry_path)),
                format!(
                    "RBS declarations exceed the {} record limit",
                    limits.max_records
                ),
            );
            partial = true;
            break;
        }
        match declaration {
            Node::Class(class) => project_class(
                &class,
                archive_sha256,
                entry_path,
                source,
                limits,
                &mut types,
                &mut members,
                &mut diagnostics,
                &mut partial,
            ),
            Node::Module(module) => project_module(
                &module,
                archive_sha256,
                entry_path,
                source,
                limits,
                &mut types,
                &mut members,
                &mut diagnostics,
                &mut partial,
            ),
            unsupported => {
                diagnostics.warning(
                    "ruby.rbs.unsupported_declaration",
                    Some(logical_path(archive_sha256, entry_path)),
                    format!(
                        "RBS {} declaration is not yet projected",
                        unsupported_declaration_kind(&unsupported)
                    ),
                );
                partial = true;
            }
        }
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    RbsProjection {
        types,
        members,
        complete: !partial && suppressed_diagnostics == 0,
        diagnostics,
        suppressed_diagnostics,
    }
}

#[allow(clippy::too_many_arguments)]
fn project_class(
    class: &ClassNode<'_>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
) {
    let name = type_name(class.name());
    let mut hierarchy = Vec::new();
    if let Some(super_class) = class.super_class() {
        hierarchy.push(HierarchyFact {
            hierarchy_kind: HierarchyKind::Extends,
            target: named_type(
                type_name(super_class.name()),
                super_class.args(),
                source,
                limits.max_signature_depth,
            ),
            declaration_ordinal: None,
        });
    }
    project_type(
        name,
        TypeKind::Class,
        class.type_params(),
        class.members(),
        hierarchy,
        archive_sha256,
        entry_path,
        source,
        limits,
        types,
        members,
        diagnostics,
        partial,
    );
}

#[allow(clippy::too_many_arguments)]
fn project_module(
    module: &ModuleNode<'_>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
) {
    let mut hierarchy = Vec::new();
    for self_type in module.self_types().iter() {
        if let Node::ModuleSelf(self_type) = self_type {
            hierarchy.push(HierarchyFact {
                hierarchy_kind: HierarchyKind::Implements,
                target: named_type(
                    type_name(self_type.name()),
                    self_type.args(),
                    source,
                    limits.max_signature_depth,
                ),
                declaration_ordinal: None,
            });
        }
    }
    project_type(
        type_name(module.name()),
        TypeKind::Module,
        module.type_params(),
        module.members(),
        hierarchy,
        archive_sha256,
        entry_path,
        source,
        limits,
        types,
        members,
        diagnostics,
        partial,
    );
}

#[allow(clippy::too_many_arguments)]
fn project_type(
    name: String,
    type_kind: TypeKind,
    type_parameters: ruby_rbs::node::NodeList<'_>,
    rbs_members: ruby_rbs::node::NodeList<'_>,
    mut hierarchy: Vec<HierarchyFact>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
) {
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "rubygems",
        name: &name,
    });
    let type_parameters = type_parameters
        .iter()
        .filter_map(|parameter| match parameter {
            Node::TypeParam(parameter) => Some(parameter.name().to_string()),
            _ => None,
        })
        .collect();
    let locator = Locator::Artifact {
        path: logical_path(archive_sha256, entry_path),
        symbol: name.clone(),
    };
    let mut projected_members = Vec::new();
    let mut aliases = Vec::new();
    let mut visibility = Visibility::Public;
    let mut ordinal = 0_u32;
    for member in rbs_members.iter() {
        match member {
            Node::Public(_) => visibility = Visibility::Public,
            Node::Private(_) => visibility = Visibility::Private,
            Node::Include(include) => {
                hierarchy.push(HierarchyFact {
                    hierarchy_kind: HierarchyKind::MixinInclude,
                    target: named_type(
                        type_name(include.name()),
                        include.args(),
                        source,
                        limits.max_signature_depth,
                    ),
                    declaration_ordinal: Some(ordinal),
                });
                ordinal = ordinal.saturating_add(1);
            }
            Node::Prepend(prepend) => {
                hierarchy.push(HierarchyFact {
                    hierarchy_kind: HierarchyKind::MixinPrepend,
                    target: named_type(
                        type_name(prepend.name()),
                        prepend.args(),
                        source,
                        limits.max_signature_depth,
                    ),
                    declaration_ordinal: Some(ordinal),
                });
                ordinal = ordinal.saturating_add(1);
            }
            Node::Extend(extend) => {
                hierarchy.push(HierarchyFact {
                    hierarchy_kind: HierarchyKind::MixinExtend,
                    target: named_type(
                        type_name(extend.name()),
                        extend.args(),
                        source,
                        limits.max_signature_depth,
                    ),
                    declaration_ordinal: Some(ordinal),
                });
                ordinal = ordinal.saturating_add(1);
            }
            Node::MethodDefinition(method) => project_method(
                &method,
                &owner_id,
                &name,
                visibility,
                &locator,
                source,
                limits,
                &mut projected_members,
                diagnostics,
                partial,
            ),
            Node::Alias(alias) => aliases.push((
                alias.old_name().to_string(),
                alias.new_name().to_string(),
                alias.kind() == AliasKind::Singleton,
            )),
            Node::AttrReader(attribute) => projected_members.push(property(
                &owner_id,
                attribute.name().as_str(),
                attribute.kind(),
                attribute.visibility(),
                visibility,
                type_ref(attribute.type_(), source, 0, limits.max_signature_depth),
                &locator,
            )),
            Node::AttrWriter(attribute) => projected_members.push(property(
                &owner_id,
                attribute.name().as_str(),
                attribute.kind(),
                attribute.visibility(),
                visibility,
                type_ref(attribute.type_(), source, 0, limits.max_signature_depth),
                &locator,
            )),
            Node::AttrAccessor(attribute) => projected_members.push(property(
                &owner_id,
                attribute.name().as_str(),
                attribute.kind(),
                attribute.visibility(),
                visibility,
                type_ref(attribute.type_(), source, 0, limits.max_signature_depth),
                &locator,
            )),
            unsupported => {
                diagnostics.warning(
                    "ruby.rbs.unsupported_member",
                    Some(logical_path(archive_sha256, entry_path)),
                    format!(
                        "RBS {} member is not yet projected",
                        unsupported_member_kind(&unsupported)
                    ),
                );
                *partial = true;
            }
        }
    }
    for (old_name, alias, is_static) in aliases {
        for member in projected_members
            .iter_mut()
            .filter(|member| member.name == old_name && member.is_static == is_static)
        {
            member.aliases.push(alias.clone());
        }
    }
    types.push(TypeFact {
        id: owner_id,
        name,
        type_kind,
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
        type_parameters,
        hierarchy,
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        locator,
    });
    members.append(&mut projected_members);
}

#[allow(clippy::too_many_arguments)]
fn project_method(
    method: &MethodDefinitionNode<'_>,
    owner_id: &str,
    owner_name: &str,
    inherited_visibility: Visibility,
    locator: &Locator,
    source: &str,
    limits: &ArtifactProducerLimits,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
) {
    let name = method.name().to_string();
    let is_static = method.kind() != MethodDefinitionKind::Instance;
    let visibility = match method.visibility() {
        MethodDefinitionVisibility::Private => Visibility::Private,
        MethodDefinitionVisibility::Public => Visibility::Public,
        MethodDefinitionVisibility::Unspecified => inherited_visibility,
    };
    for overload in method.overloads().iter() {
        let Node::MethodDefinitionOverload(overload) = overload else {
            continue;
        };
        let Node::MethodType(method_type) = overload.method_type() else {
            diagnostics.warning(
                "ruby.rbs.unsupported_method_type",
                Some(owner_name.to_owned()),
                format!("RBS method {owner_name}::{name} has an unsupported method type"),
            );
            *partial = true;
            continue;
        };
        let Node::FunctionType(function) = method_type.type_() else {
            diagnostics.warning(
                "ruby.rbs.untyped_method",
                Some(owner_name.to_owned()),
                format!("RBS method {owner_name}::{name} has no structured function type"),
            );
            *partial = true;
            continue;
        };
        let signature = function_signature(&function, method_type.type_params(), source, limits);
        let parameter_types = signature
            .parameters
            .iter()
            .map(|parameter| parameter.r#type.clone())
            .collect::<Vec<_>>();
        let id = member_declaration_id(MemberIdentity {
            owner_id,
            kind: MemberKind::Method,
            is_static,
            parameter_arity: parameter_types.len(),
            name: &name,
            generic_arity: signature.type_parameters.len(),
            parameter_types: &parameter_types,
            return_type: signature.returns.as_ref(),
        });
        members.push(MemberFact {
            id,
            owner: owner_id.to_owned(),
            name: name.clone(),
            member_kind: MemberKind::Method,
            visibility,
            is_static,
            is_abstract: false,
            is_virtual: true,
            signature: Some(signature),
            aliases: Vec::new(),
            locator: locator.clone(),
        });
    }
}

fn function_signature(
    function: &FunctionTypeNode<'_>,
    type_parameters: ruby_rbs::node::NodeList<'_>,
    source: &str,
    limits: &ArtifactProducerLimits,
) -> Signature {
    let mut parameters = Vec::new();
    for parameter in function.required_positionals().iter() {
        push_parameter(&mut parameters, parameter, source, false, false, limits);
    }
    for parameter in function.optional_positionals().iter() {
        push_parameter(&mut parameters, parameter, source, true, false, limits);
    }
    if let Some(parameter) = function.rest_positionals() {
        push_parameter(&mut parameters, parameter, source, true, true, limits);
    }
    for parameter in function.trailing_positionals().iter() {
        push_parameter(&mut parameters, parameter, source, false, false, limits);
    }
    for (name, parameter) in function.required_keywords().iter() {
        push_keyword_parameter(&mut parameters, name, parameter, source, false, limits);
    }
    for (name, parameter) in function.optional_keywords().iter() {
        push_keyword_parameter(&mut parameters, name, parameter, source, true, limits);
    }
    if let Some(parameter) = function.rest_keywords() {
        push_parameter(&mut parameters, parameter, source, true, true, limits);
    }
    Signature {
        type_parameters: type_parameters
            .iter()
            .filter_map(|parameter| match parameter {
                Node::TypeParam(parameter) => Some(parameter.name().to_string()),
                _ => None,
            })
            .collect(),
        parameters,
        returns: Some(type_ref(
            function.return_type(),
            source,
            0,
            limits.max_signature_depth,
        )),
    }
}

fn push_parameter(
    parameters: &mut Vec<Parameter>,
    parameter: Node<'_>,
    source: &str,
    optional: bool,
    variadic: bool,
    limits: &ArtifactProducerLimits,
) {
    if let Node::FunctionParam(parameter) = parameter {
        parameters.push(function_parameter(
            &parameter, source, optional, variadic, limits,
        ));
    }
}

fn push_keyword_parameter(
    parameters: &mut Vec<Parameter>,
    name: Node<'_>,
    parameter: Node<'_>,
    source: &str,
    optional: bool,
    limits: &ArtifactProducerLimits,
) {
    let Node::FunctionParam(parameter) = parameter else {
        return;
    };
    let name = match name {
        Node::Symbol(name) => Some(name.to_string()),
        _ => None,
    };
    let mut parameter = function_parameter(&parameter, source, optional, false, limits);
    parameter.name = name;
    parameters.push(parameter);
}

fn function_parameter(
    parameter: &FunctionParamNode<'_>,
    source: &str,
    optional: bool,
    variadic: bool,
    limits: &ArtifactProducerLimits,
) -> Parameter {
    Parameter {
        name: parameter.name().map(|name| name.to_string()),
        r#type: type_ref(parameter.type_(), source, 0, limits.max_signature_depth),
        optional,
        variadic,
    }
}

fn type_ref(node: Node<'_>, source: &str, depth: usize, max_depth: usize) -> TypeRef {
    if depth >= max_depth {
        return TypeRef::Named {
            name: "untyped".to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
    }
    match node {
        Node::ClassInstanceType(node) => named_type_at_depth(
            type_name(node.name()),
            node.args(),
            source,
            depth,
            max_depth,
        ),
        Node::InterfaceType(node) => named_type_at_depth(
            type_name(node.name()),
            node.args(),
            source,
            depth,
            max_depth,
        ),
        Node::AliasType(node) => named_type_at_depth(
            type_name(node.name()),
            node.args(),
            source,
            depth,
            max_depth,
        ),
        Node::VariableType(node) => TypeRef::TypeParameter {
            name: node.name().to_string(),
        },
        Node::OptionalType(node) => nullable_type(type_ref(
            node.type_(),
            source,
            depth.saturating_add(1),
            max_depth,
        )),
        Node::TupleType(node) => TypeRef::Tuple {
            elements: node
                .types()
                .iter()
                .map(|node| type_ref(node, source, depth.saturating_add(1), max_depth))
                .collect(),
        },
        Node::FunctionType(node) => TypeRef::Function {
            parameters: node
                .required_positionals()
                .iter()
                .filter_map(|parameter| match parameter {
                    Node::FunctionParam(parameter) => Some(type_ref(
                        parameter.type_(),
                        source,
                        depth.saturating_add(1),
                        max_depth,
                    )),
                    _ => None,
                })
                .collect(),
            result: Box::new(type_ref(
                node.return_type(),
                source,
                depth.saturating_add(1),
                max_depth,
            )),
        },
        Node::BoolType(_) => simple_type("bool"),
        Node::NilType(_) => simple_type("nil"),
        Node::SelfType(_) => simple_type("self"),
        Node::VoidType(_) => simple_type("void"),
        Node::AnyType(_) => simple_type("untyped"),
        Node::TopType(_) => simple_type("top"),
        Node::BottomType(_) => simple_type("bottom"),
        Node::ClassType(_) => simple_type("class"),
        Node::InstanceType(_) => simple_type("instance"),
        Node::UnionType(node) => source_type(source, node.location()),
        Node::IntersectionType(node) => source_type(source, node.location()),
        Node::RecordType(node) => source_type(source, node.location()),
        Node::LiteralType(node) => source_type(source, node.location()),
        Node::ProcType(node) => source_type(source, node.location()),
        _ => simple_type("untyped"),
    }
}

fn named_type(
    name: String,
    arguments: ruby_rbs::node::NodeList<'_>,
    source: &str,
    max_depth: usize,
) -> TypeRef {
    named_type_at_depth(name, arguments, source, 0, max_depth)
}

fn named_type_at_depth(
    name: String,
    arguments: ruby_rbs::node::NodeList<'_>,
    source: &str,
    depth: usize,
    max_depth: usize,
) -> TypeRef {
    TypeRef::Named {
        name,
        arguments: arguments
            .iter()
            .map(|argument| type_ref(argument, source, depth.saturating_add(1), max_depth))
            .collect(),
        nullable: false,
    }
}

fn nullable_type(type_ref: TypeRef) -> TypeRef {
    match type_ref {
        TypeRef::Named {
            name, arguments, ..
        } => TypeRef::Named {
            name,
            arguments,
            nullable: true,
        },
        TypeRef::Declared { id, arguments, .. } => TypeRef::Declared {
            id,
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

fn simple_type(name: &str) -> TypeRef {
    TypeRef::Named {
        name: name.to_owned(),
        arguments: Vec::new(),
        nullable: false,
    }
}

fn source_type(source: &str, location: RBSLocationRange) -> TypeRef {
    let start = usize::try_from(location.start()).unwrap_or(0);
    let end = usize::try_from(location.end()).unwrap_or(start);
    simple_type(source.get(start..end).unwrap_or("untyped"))
}

fn type_name(name: TypeNameNode<'_>) -> String {
    let namespace = name.namespace();
    let mut segments = namespace
        .path()
        .iter()
        .filter_map(|node| match node {
            Node::Symbol(symbol) => Some(symbol.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    segments.push(name.name().to_string());
    if namespace.absolute() {
        format!("::{}", segments.join("::"))
    } else {
        segments.join("::")
    }
}

fn logical_path(archive_sha256: &str, entry_path: &str) -> String {
    format!("gem+sha256:{archive_sha256}!/{entry_path}")
}

fn property(
    owner_id: &str,
    name: &str,
    kind: AttributeKind,
    declared_visibility: AttributeVisibility,
    inherited_visibility: Visibility,
    property_type: TypeRef,
    locator: &Locator,
) -> MemberFact {
    let is_static = kind == AttributeKind::Singleton;
    let visibility = match declared_visibility {
        AttributeVisibility::Private => Visibility::Private,
        AttributeVisibility::Public => Visibility::Public,
        AttributeVisibility::Unspecified => inherited_visibility,
    };
    let signature = Signature {
        type_parameters: Vec::new(),
        parameters: Vec::new(),
        returns: Some(property_type),
    };
    let id = member_declaration_id(MemberIdentity {
        owner_id,
        kind: MemberKind::Property,
        is_static,
        parameter_arity: 0,
        name,
        generic_arity: 0,
        parameter_types: &[],
        return_type: signature.returns.as_ref(),
    });
    MemberFact {
        id,
        owner: owner_id.to_owned(),
        name: name.to_owned(),
        member_kind: MemberKind::Property,
        visibility,
        is_static,
        is_abstract: false,
        is_virtual: true,
        signature: Some(signature),
        aliases: Vec::new(),
        locator: locator.clone(),
    }
}

fn unsupported_declaration_kind(node: &Node<'_>) -> &'static str {
    match node {
        Node::ClassAlias(_) => "class alias",
        Node::Constant(_) => "constant",
        Node::Global(_) => "global",
        Node::Interface(_) => "interface",
        Node::ModuleAlias(_) => "module alias",
        Node::TypeAlias(_) => "type alias",
        Node::Use(_) => "use",
        _ => "unexpected",
    }
}

fn unsupported_member_kind(node: &Node<'_>) -> &'static str {
    match node {
        Node::ClassInstanceVariable(_) => "class instance variable",
        Node::ClassVariable(_) => "class variable",
        Node::InstanceVariable(_) => "instance variable",
        _ => "unexpected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbs_projects_overloads_singletons_aliases_and_ordered_mixins() {
        let projection = project_rbs(
            &"a".repeat(64),
            "sig/widget.rbs",
            r#"
class Widget[T] < Base[T]
  prepend Instrumented
  include Enumerable[T]
  extend Factory
  def call: (T value) -> String
          | (Integer value, ?String label) -> String?
  def self.build: () -> Widget[T]
  alias invoke call
end
"#,
            &ArtifactProducerLimits::default(),
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        assert_eq!(projection.types.len(), 1);
        assert_eq!(projection.types[0].name, "Widget");
        assert_eq!(projection.types[0].type_parameters, ["T"]);
        assert_eq!(
            projection.types[0]
                .hierarchy
                .iter()
                .map(|fact| (fact.hierarchy_kind, fact.declaration_ordinal))
                .collect::<Vec<_>>(),
            vec![
                (HierarchyKind::Extends, None),
                (HierarchyKind::MixinPrepend, Some(0)),
                (HierarchyKind::MixinInclude, Some(1)),
                (HierarchyKind::MixinExtend, Some(2)),
            ]
        );
        assert_eq!(projection.members.len(), 3);
        assert_eq!(
            projection
                .members
                .iter()
                .filter(|member| member.name == "call")
                .count(),
            2
        );
        assert!(
            projection
                .members
                .iter()
                .filter(|member| member.name == "call")
                .all(|member| member.aliases == ["invoke"])
        );
        assert!(
            projection
                .members
                .iter()
                .any(|member| member.name == "build" && member.is_static)
        );
    }

    #[test]
    fn malformed_rbs_is_partial_with_a_bounded_diagnostic() {
        let projection = project_rbs(
            &"b".repeat(64),
            "sig/broken.rbs",
            "class { end",
            &ArtifactProducerLimits::default(),
        );

        assert!(!projection.complete);
        assert!(projection.types.is_empty());
        assert_eq!(projection.diagnostics[0].code, "ruby.rbs.parse");
        assert!(
            projection.diagnostics[0]
                .location
                .as_deref()
                .unwrap()
                .starts_with("gem+sha256:")
        );
    }
}
