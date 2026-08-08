use tree_sitter::{Node, Parser};

use crate::CancellationToken;
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
    pub aliases: Vec<RubyMemberAlias>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubyMemberAlias {
    pub owner: String,
    pub old_name: String,
    pub new_name: String,
    pub is_static: bool,
}

/// A tree-sitter RBS arrangement that this projection does not model.
///
/// Gem archives are untrusted input. The `has_error` guard below rejects a
/// tree that failed to parse, but it cannot reject a tree that parsed cleanly
/// into an arrangement the projection did not anticipate: a newer RBS
/// construct, a grammar version change, or a crafted `.rbs`. Every grammar
/// shape lookup therefore returns this value instead of panicking.
///
/// `project_rbs` converts a miss in exactly two places: the declaration walk
/// skips one declaration, and the member walk inside `project_type` skips one
/// member. Both route through `report_unmodeled_shape`, which records one
/// `ruby.rbs.unmodeled_shape` warning and sets `partial`. The warning demotes
/// the produced pack to `Completeness::Partial`, so surface this projection
/// skipped can never be mistaken for surface it proved absent (#1624).
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnmodeledShape {
    node_kind: &'static str,
    expected: String,
}

pub(crate) fn project_rbs(
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
) -> RbsProjection {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    let mut parser = Parser::new();
    // The language is compiled in, so a load failure is a build defect rather
    // than anything the gem archive can reach.
    parser
        .set_language(&tree_sitter_rbs::LANGUAGE.into())
        .expect("tree-sitter RBS language must load");
    let Some(tree) = parser.parse(source, None) else {
        diagnostics.error(
            "ruby.rbs.parse",
            Some(logical_path(archive_sha256, entry_path)),
            "tree-sitter returned no RBS tree for this declaration",
        );
        return abandoned(diagnostics);
    };
    let root = tree.root_node();
    if root.has_error() {
        diagnostics.error(
            "ruby.rbs.parse",
            Some(logical_path(archive_sha256, entry_path)),
            "could not parse RBS declaration",
        );
        return abandoned(diagnostics);
    }

    let mut types = Vec::<TypeFact>::new();
    let mut members = Vec::new();
    let mut partial = false;
    let mut aliases = Vec::new();
    let mut declarations = Vec::new();
    for node in named_children(root).into_iter().rev() {
        match declaration_body(node) {
            Ok(declaration) => declarations.push((declaration, String::new())),
            Err(miss) => {
                report_unmodeled_shape(
                    &mut diagnostics,
                    archive_sha256,
                    entry_path,
                    "declaration",
                    miss,
                );
                partial = true;
            }
        }
    }
    while let Some((declaration, parent_namespace)) = declarations.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "ruby.rbs.cancelled",
                None,
                "RBS declaration projection was cancelled",
            );
            partial = true;
            break;
        }
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
        if is_trivia(declaration.kind()) {
            continue;
        }
        if declaration.kind() == "const_decl" {
            let required = match constant_record_cost(declaration, &parent_namespace, &types) {
                Ok(required) => required,
                Err(miss) => {
                    report_unmodeled_shape(
                        &mut diagnostics,
                        archive_sha256,
                        entry_path,
                        "declaration",
                        miss,
                    );
                    partial = true;
                    continue;
                }
            };
            if types
                .len()
                .saturating_add(members.len())
                .saturating_add(required)
                > limits.max_records
            {
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
        }
        let projected = match declaration.kind() {
            "class_decl" => project_class(
                declaration,
                &parent_namespace,
                archive_sha256,
                entry_path,
                source,
                limits,
                &mut types,
                &mut members,
                &mut diagnostics,
                &mut partial,
                &mut aliases,
                cancellation,
            )
            .map(Some),
            "module_decl" => project_module(
                declaration,
                &parent_namespace,
                archive_sha256,
                entry_path,
                source,
                limits,
                &mut types,
                &mut members,
                &mut diagnostics,
                &mut partial,
                &mut aliases,
                cancellation,
            )
            .map(Some),
            "interface_decl" => project_interface(
                declaration,
                &parent_namespace,
                archive_sha256,
                entry_path,
                source,
                limits,
                &mut types,
                &mut members,
                &mut diagnostics,
                &mut partial,
                &mut aliases,
                cancellation,
            )
            .map(Some),
            "const_decl" => project_constant(
                declaration,
                &parent_namespace,
                archive_sha256,
                entry_path,
                source,
                limits,
                &mut types,
                &mut members,
            )
            .map(|()| None),
            unsupported => {
                diagnostics.warning(
                    "ruby.rbs.unsupported_declaration",
                    Some(logical_path(archive_sha256, entry_path)),
                    format!(
                        "RBS {} declaration is not yet projected",
                        unsupported_declaration_kind(unsupported)
                    ),
                );
                partial = true;
                Ok(None)
            }
        };
        let projected_namespace = match projected {
            Ok(namespace) => namespace,
            Err(miss) => {
                report_unmodeled_shape(
                    &mut diagnostics,
                    archive_sha256,
                    entry_path,
                    "declaration",
                    miss,
                );
                partial = true;
                continue;
            }
        };
        if let Some(namespace) = projected_namespace
            && let Some(body) = declaration.child_by_field_name("body")
        {
            for nested in named_children(body).into_iter().rev() {
                match declaration_body(nested) {
                    Ok(nested) if is_declaration(nested.kind()) => {
                        declarations.push((nested, namespace.clone()));
                    }
                    Ok(_) => {}
                    Err(miss) => {
                        report_unmodeled_shape(
                            &mut diagnostics,
                            archive_sha256,
                            entry_path,
                            "declaration",
                            miss,
                        );
                        partial = true;
                    }
                }
            }
        }
    }
    for alias in &aliases {
        for member in members.iter_mut().filter(|member| {
            member.owner == alias.owner
                && member.name == alias.old_name
                && member.is_static == alias.is_static
        }) {
            if !member.aliases.contains(&alias.new_name) {
                member.aliases.push(alias.new_name.clone());
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
        aliases,
    }
}

fn abandoned(diagnostics: BoundedProducerDiagnostics) -> RbsProjection {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    RbsProjection {
        types: Vec::new(),
        members: Vec::new(),
        diagnostics,
        suppressed_diagnostics,
        complete: false,
        aliases: Vec::new(),
    }
}

fn report_unmodeled_shape(
    diagnostics: &mut BoundedProducerDiagnostics,
    archive_sha256: &str,
    entry_path: &str,
    skipped: &str,
    miss: UnmodeledShape,
) {
    diagnostics.warning(
        "ruby.rbs.unmodeled_shape",
        Some(logical_path(archive_sha256, entry_path)),
        format!(
            "RBS {} node is missing {}, so this {skipped} is not projected",
            miss.node_kind, miss.expected
        ),
    );
}

#[allow(clippy::too_many_arguments)]
fn project_interface(
    interface: Node<'_>,
    parent_namespace: &str,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
    aliases: &mut Vec<RubyMemberAlias>,
    cancellation: Option<&CancellationToken>,
) -> Result<String, UnmodeledShape> {
    let name = declaration_name(interface, parent_namespace, source)?;
    project_type(
        name.clone(),
        TypeKind::Interface,
        interface.child_by_field_name("type_parameters"),
        interface.child_by_field_name("body"),
        Vec::new(),
        archive_sha256,
        entry_path,
        source,
        limits,
        types,
        members,
        diagnostics,
        partial,
        aliases,
        cancellation,
    );
    Ok(name)
}

/// Records a top-level constant needs before it can be projected: the constant
/// itself, plus the synthetic `Object` owner when this is the first one.
fn constant_record_cost(
    constant: Node<'_>,
    parent_namespace: &str,
    types: &[TypeFact],
) -> Result<usize, UnmodeledShape> {
    let constant_name = required_child(constant, "const_name")?;
    let top_level =
        direct_child(constant_name, "namespace").is_none() && parent_namespace.is_empty();
    let object_id = type_declaration_id(TypeIdentity {
        ecosystem: "rubygems",
        name: "Object",
    });
    Ok(1 + usize::from(top_level && !types.iter().any(|fact| fact.id == object_id)))
}

#[allow(clippy::too_many_arguments)]
fn project_constant(
    constant: Node<'_>,
    parent_namespace: &str,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
) -> Result<(), UnmodeledShape> {
    let constant_name = required_child(constant, "const_name")?;
    let name = node_text(required_child(constant_name, "constant")?, source).to_owned();
    let owner_name = if let Some(namespace) = direct_child(constant_name, "namespace") {
        normalize_name(node_text(namespace, source))
            .trim_end_matches("::")
            .to_owned()
    } else if !parent_namespace.is_empty() {
        parent_namespace.to_owned()
    } else {
        "Object".to_owned()
    };
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "rubygems",
        name: &owner_name,
    });
    let return_type = match direct_child(constant, "type") {
        Some(node) => type_ref(node, source, &[], 0, limits.max_signature_depth)?,
        None => simple_type("untyped"),
    };
    if owner_name == "Object" && !types.iter().any(|fact| fact.id == owner_id) {
        types.push(TypeFact {
            id: owner_id.clone(),
            name: owner_name.clone(),
            type_kind: TypeKind::Class,
            visibility: Visibility::Public,
            is_abstract: false,
            is_sealed: false,
            has_explicit_type_terms: false,
            type_parameters: Vec::new(),
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            embedded_types: Vec::new(),
            hierarchy: Vec::new(),
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            locator: Locator::Artifact {
                path: logical_path(archive_sha256, entry_path),
                symbol: owner_name,
            },
        });
    }
    let signature = Signature {
        type_parameters: Vec::new(),
        parameters: Vec::new(),
        returns: Some(return_type.clone()),
    };
    members.push(MemberFact {
        id: member_declaration_id(MemberIdentity {
            owner_id: &owner_id,
            kind: MemberKind::Constant,
            is_static: true,
            parameter_arity: 0,
            name: &name,
            generic_arity: 0,
            parameter_types: &[],
            parameter_variadics: &[],
            return_type: Some(&return_type),
        }),
        owner: owner_id,
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
        locator: Locator::Artifact {
            path: logical_path(archive_sha256, entry_path),
            symbol: name,
        },
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn project_class(
    class: Node<'_>,
    parent_namespace: &str,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
    aliases: &mut Vec<RubyMemberAlias>,
    cancellation: Option<&CancellationToken>,
) -> Result<String, UnmodeledShape> {
    let name = declaration_name(class, parent_namespace, source)?;
    let mut hierarchy = Vec::new();
    if let Some(super_class) = class.child_by_field_name("superclass") {
        let super_name = required_field(super_class, "name")?;
        hierarchy.push(HierarchyFact {
            hierarchy_kind: HierarchyKind::Extends,
            target: named_type(
                type_name(super_name, source),
                super_class.child_by_field_name("type_arguments"),
                source,
                &type_parameters(class.child_by_field_name("type_parameters"), source),
                limits.max_signature_depth,
            )?,
            declaration_ordinal: None,
        });
    }
    project_type(
        name.clone(),
        TypeKind::Class,
        class.child_by_field_name("type_parameters"),
        class.child_by_field_name("body"),
        hierarchy,
        archive_sha256,
        entry_path,
        source,
        limits,
        types,
        members,
        diagnostics,
        partial,
        aliases,
        cancellation,
    );
    Ok(name)
}

#[allow(clippy::too_many_arguments)]
fn project_module(
    module: Node<'_>,
    parent_namespace: &str,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
    aliases: &mut Vec<RubyMemberAlias>,
    cancellation: Option<&CancellationToken>,
) -> Result<String, UnmodeledShape> {
    let name = declaration_name(module, parent_namespace, source)?;
    let parameters = type_parameters(module.child_by_field_name("type_parameters"), source);
    let mut hierarchy = Vec::new();
    if let Some(self_types) = module.child_by_field_name("self_type_binds") {
        for self_type in descendants_matching(self_types, &["class_name", "interface_name"]) {
            let arguments = self_type
                .next_named_sibling()
                .filter(|sibling| sibling.kind() == "type_arguments");
            hierarchy.push(HierarchyFact {
                hierarchy_kind: HierarchyKind::Implements,
                target: named_type(
                    type_name(self_type, source),
                    arguments,
                    source,
                    &parameters,
                    limits.max_signature_depth,
                )?,
                declaration_ordinal: None,
            });
        }
    }
    project_type(
        name.clone(),
        TypeKind::Module,
        module.child_by_field_name("type_parameters"),
        module.child_by_field_name("body"),
        hierarchy,
        archive_sha256,
        entry_path,
        source,
        limits,
        types,
        members,
        diagnostics,
        partial,
        aliases,
        cancellation,
    );
    Ok(name)
}

#[allow(clippy::too_many_arguments)]
fn project_type(
    name: String,
    type_kind: TypeKind,
    type_parameter_node: Option<Node<'_>>,
    rbs_members: Option<Node<'_>>,
    mut hierarchy: Vec<HierarchyFact>,
    archive_sha256: &str,
    entry_path: &str,
    source: &str,
    limits: &ArtifactProducerLimits,
    types: &mut Vec<TypeFact>,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
    aliases: &mut Vec<RubyMemberAlias>,
    cancellation: Option<&CancellationToken>,
) {
    let owner_id = type_declaration_id(TypeIdentity {
        ecosystem: "rubygems",
        name: &name,
    });
    let type_parameters = type_parameters(type_parameter_node, source);
    let locator = Locator::Artifact {
        path: logical_path(archive_sha256, entry_path),
        symbol: name.clone(),
    };
    let mut projected_members = Vec::new();
    let mut visibility = Visibility::Public;
    let mut ordinal = 0_u32;
    for member in rbs_members.map(named_children).unwrap_or_default() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "ruby.rbs.cancelled",
                None,
                "RBS declaration projection was cancelled",
            );
            *partial = true;
            break;
        }
        let record_base = types.len().saturating_add(members.len()).saturating_add(1);
        if record_base.saturating_add(projected_members.len()) >= limits.max_records {
            diagnostics.error(
                "limit.records",
                Some(logical_path(archive_sha256, entry_path)),
                format!(
                    "RBS declarations exceed the {} record limit",
                    limits.max_records
                ),
            );
            *partial = true;
            break;
        }
        let member = match declaration_body(member) {
            Ok(member) => member,
            Err(miss) => {
                report_unmodeled_shape(diagnostics, archive_sha256, entry_path, "member", miss);
                *partial = true;
                continue;
            }
        };
        if is_trivia(member.kind()) {
            continue;
        }
        let projected = match member.kind() {
            // An unmodeled visibility token leaves the running visibility on
            // its previous value. The warning the caller records demotes the
            // pack, so the members that follow cannot be read as proven.
            "visibility_member" => visibility_from_node(member, source).map(|modeled| {
                visibility = modeled.unwrap_or(visibility);
            }),
            "include_member" => {
                hierarchy_target(member, source, &type_parameters, limits).map(|target| {
                    push_mixin(
                        &mut hierarchy,
                        &mut ordinal,
                        HierarchyKind::MixinInclude,
                        target,
                    );
                })
            }
            "prepend_member" => {
                hierarchy_target(member, source, &type_parameters, limits).map(|target| {
                    push_mixin(
                        &mut hierarchy,
                        &mut ordinal,
                        HierarchyKind::MixinPrepend,
                        target,
                    );
                })
            }
            "extend_member" => {
                hierarchy_target(member, source, &type_parameters, limits).map(|target| {
                    push_mixin(
                        &mut hierarchy,
                        &mut ordinal,
                        HierarchyKind::MixinExtend,
                        target,
                    );
                })
            }
            "method_member" => project_method(
                member,
                &owner_id,
                &name,
                visibility,
                &locator,
                source,
                limits,
                &mut projected_members,
                diagnostics,
                partial,
                limits.max_records.saturating_sub(record_base),
                cancellation,
                &type_parameters,
            ),
            "alias_member" => {
                project_alias(member, &owner_id, source).map(|alias| aliases.push(alias))
            }
            "attribute_member" => project_attribute(
                member,
                &owner_id,
                visibility,
                &locator,
                source,
                &type_parameters,
                limits,
            )
            .map(|property| projected_members.push(property)),
            "ivar_member" => {
                diagnostics.warning(
                    "ruby.rbs.unsupported_member",
                    Some(logical_path(archive_sha256, entry_path)),
                    "RBS variable member is not yet projected",
                );
                *partial = true;
                Ok(())
            }
            unsupported if is_declaration(unsupported) => Ok(()),
            unsupported => {
                diagnostics.warning(
                    "ruby.rbs.unsupported_member",
                    Some(logical_path(archive_sha256, entry_path)),
                    format!("RBS {unsupported} member is not yet projected"),
                );
                *partial = true;
                Ok(())
            }
        };
        if let Err(miss) = projected {
            report_unmodeled_shape(diagnostics, archive_sha256, entry_path, "member", miss);
            *partial = true;
        }
    }
    types.push(TypeFact {
        id: owner_id,
        name,
        type_kind,
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
        has_explicit_type_terms: false,
        type_parameters,
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        embedded_types: Vec::new(),
        hierarchy,
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        locator,
    });
    members.append(&mut projected_members);
}

fn push_mixin(
    hierarchy: &mut Vec<HierarchyFact>,
    ordinal: &mut u32,
    hierarchy_kind: HierarchyKind,
    target: TypeRef,
) {
    hierarchy.push(HierarchyFact {
        hierarchy_kind,
        target,
        declaration_ordinal: Some(*ordinal),
    });
    *ordinal = ordinal.saturating_add(1);
}

fn project_alias(
    alias: Node<'_>,
    owner_id: &str,
    source: &str,
) -> Result<RubyMemberAlias, UnmodeledShape> {
    let new_name = required_field(alias, "name")?;
    let old_name = required_field(alias, "origin_name")?;
    Ok(RubyMemberAlias {
        owner: owner_id.to_owned(),
        old_name: member_name(old_name, source)?.to_owned(),
        new_name: member_name(new_name, source)?.to_owned(),
        is_static: direct_child(new_name, "self").is_some(),
    })
}

#[allow(clippy::too_many_arguments)]
fn project_attribute(
    attribute: Node<'_>,
    owner_id: &str,
    inherited_visibility: Visibility,
    locator: &Locator,
    source: &str,
    type_parameters: &[String],
    limits: &ArtifactProducerLimits,
) -> Result<MemberFact, UnmodeledShape> {
    let name = member_name(attribute, source)?;
    let is_static = direct_child(attribute, "self").is_some();
    let visibility = visibility_from_node(attribute, source)?.unwrap_or(inherited_visibility);
    let property_type = match direct_child(attribute, "type") {
        Some(node) => type_ref(node, source, type_parameters, 0, limits.max_signature_depth)?,
        None => simple_type("untyped"),
    };
    let signature = Signature {
        type_parameters: Vec::new(),
        parameters: Vec::new(),
        returns: Some(property_type),
    };
    Ok(MemberFact {
        id: member_declaration_id(MemberIdentity {
            owner_id,
            kind: MemberKind::Property,
            is_static,
            parameter_arity: 0,
            name,
            generic_arity: 0,
            parameter_types: &[],
            parameter_variadics: &[],
            return_type: signature.returns.as_ref(),
        }),
        owner: owner_id.to_owned(),
        name: name.to_owned(),
        member_kind: MemberKind::Property,
        visibility,
        is_static,
        is_abstract: false,
        is_virtual: true,
        signature: Some(signature),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        locator: locator.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn project_method(
    method: Node<'_>,
    owner_id: &str,
    owner_name: &str,
    inherited_visibility: Visibility,
    locator: &Locator,
    source: &str,
    limits: &ArtifactProducerLimits,
    members: &mut Vec<MemberFact>,
    diagnostics: &mut BoundedProducerDiagnostics,
    partial: &mut bool,
    max_members: usize,
    cancellation: Option<&CancellationToken>,
    owner_type_parameters: &[String],
) -> Result<(), UnmodeledShape> {
    let name = member_name(method, source)?.to_owned();
    let is_static = direct_child(method, "self").is_some();
    let visibility = visibility_from_node(method, source)?.unwrap_or(inherited_visibility);
    let Some(overloads) = direct_child(method, "method_types") else {
        diagnostics.warning(
            "ruby.rbs.untyped_method",
            Some(owner_name.to_owned()),
            format!("RBS method {owner_name}::{name} has no structured function type"),
        );
        *partial = true;
        return Ok(());
    };
    let overloads = direct_children(overloads, "method_type");
    if overloads.is_empty() {
        diagnostics.warning(
            "ruby.rbs.untyped_method",
            Some(owner_name.to_owned()),
            format!("RBS method {owner_name}::{name} has no structured function type"),
        );
        *partial = true;
    }
    // Overloads land in `projected` first so that a shape miss in a later
    // overload skips the whole method instead of publishing a truncated set.
    let mut projected = Vec::new();
    for overload in overloads {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "ruby.rbs.cancelled",
                None,
                "RBS declaration projection was cancelled",
            );
            *partial = true;
            break;
        }
        if members.len().saturating_add(projected.len()) >= max_members {
            diagnostics.error(
                "limit.records",
                Some(owner_name.to_owned()),
                "RBS method overloads exceed the record limit",
            );
            *partial = true;
            break;
        }
        let function = required_field(overload, "body")?;
        if direct_child(function, "block").is_some() {
            diagnostics.warning(
                "ruby.rbs.unsupported_block_signature",
                Some(owner_name.to_owned()),
                format!(
                    "RBS method {owner_name}::{name} has a block signature that cannot be represented exactly"
                ),
            );
            *partial = true;
            continue;
        }
        let signature = function_signature(
            function,
            overload.child_by_field_name("type_parameters"),
            owner_type_parameters,
            source,
            limits,
        )?;
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
            parameter_variadics: &[],
            return_type: signature.returns.as_ref(),
        });
        projected.push(MemberFact {
            id,
            owner: owner_id.to_owned(),
            name: name.clone(),
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
            locator: locator.clone(),
        });
    }
    members.append(&mut projected);
    Ok(())
}

fn function_signature(
    function: Node<'_>,
    method_type_parameters: Option<Node<'_>>,
    owner_type_parameters: &[String],
    source: &str,
    limits: &ArtifactProducerLimits,
) -> Result<Signature, UnmodeledShape> {
    let mut parameters = Vec::new();
    let method_type_parameters = type_parameters(method_type_parameters, source);
    let mut scoped_type_parameters = owner_type_parameters.to_vec();
    scoped_type_parameters.extend(method_type_parameters.iter().cloned());
    if let Some(parameter_list) = direct_child(function, "parameters") {
        project_parameters(
            parameter_list,
            source,
            &scoped_type_parameters,
            limits,
            &mut parameters,
        )?;
    }
    let returns = match direct_child(function, "type") {
        Some(node) => Some(type_ref(
            node,
            source,
            &scoped_type_parameters,
            0,
            limits.max_signature_depth,
        )?),
        None => None,
    };
    Ok(Signature {
        type_parameters: method_type_parameters,
        parameters,
        returns,
    })
}

fn project_parameters(
    parameter_list: Node<'_>,
    source: &str,
    type_parameters: &[String],
    limits: &ArtifactProducerLimits,
    parameters: &mut Vec<Parameter>,
) -> Result<(), UnmodeledShape> {
    for group in named_children(parameter_list) {
        match group.kind() {
            "required_positionals" | "trailing_positionals" | "optional_positionals" => {
                let optional = group.kind() == "optional_positionals";
                for parameter in direct_children(group, "parameter") {
                    parameters.push(function_parameter(
                        parameter,
                        source,
                        type_parameters,
                        optional,
                        false,
                        limits,
                    )?);
                }
            }
            "rest_positional" => {
                if let Some(parameter) = direct_child(group, "parameter") {
                    parameters.push(function_parameter(
                        parameter,
                        source,
                        type_parameters,
                        true,
                        true,
                        limits,
                    )?);
                }
            }
            "keywords" => {
                project_keywords(group, source, type_parameters, limits, parameters)?;
            }
            "unnamed_parameter" => parameters.push(Parameter {
                name: None,
                r#type: simple_type("untyped"),
                optional: true,
                variadic: true,
            }),
            _ => {}
        }
    }
    Ok(())
}

fn project_keywords(
    keywords: Node<'_>,
    source: &str,
    type_parameters: &[String],
    limits: &ArtifactProducerLimits,
    parameters: &mut Vec<Parameter>,
) -> Result<(), UnmodeledShape> {
    let mut stack = named_children(keywords)
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    while let Some(keyword) = stack.pop() {
        match keyword.kind() {
            "required_keywords" | "optional_keywords" => {
                let optional = keyword.kind() == "optional_keywords";
                let name =
                    direct_child(keyword, "keyword").map(|node| node_text(node, source).to_owned());
                let r#type = match direct_child(keyword, "type") {
                    Some(node) => {
                        type_ref(node, source, type_parameters, 0, limits.max_signature_depth)?
                    }
                    None => simple_type("untyped"),
                };
                parameters.push(Parameter {
                    name,
                    r#type,
                    optional,
                    variadic: false,
                });
            }
            "splat_keyword" => {
                if let Some(parameter) = direct_child(keyword, "parameter") {
                    parameters.push(function_parameter(
                        parameter,
                        source,
                        type_parameters,
                        true,
                        true,
                        limits,
                    )?);
                }
            }
            _ => {}
        }
        stack.extend(named_children(keyword).into_iter().rev());
    }
    Ok(())
}

fn function_parameter(
    parameter: Node<'_>,
    source: &str,
    type_parameters: &[String],
    optional: bool,
    variadic: bool,
    limits: &ArtifactProducerLimits,
) -> Result<Parameter, UnmodeledShape> {
    let r#type = match direct_child(parameter, "type") {
        Some(node) => type_ref(node, source, type_parameters, 0, limits.max_signature_depth)?,
        None => simple_type("untyped"),
    };
    Ok(Parameter {
        name: direct_child(parameter, "var_name").map(|node| node_text(node, source).to_owned()),
        r#type,
        optional,
        variadic,
    })
}

fn type_ref(
    node: Node<'_>,
    source: &str,
    type_parameters: &[String],
    depth: usize,
    max_depth: usize,
) -> Result<TypeRef, UnmodeledShape> {
    if depth >= max_depth {
        return Ok(simple_type("untyped"));
    }
    let node = unwrap_type(node);
    match node.kind() {
        "class_type" | "interface_type" | "alias_type" => {
            let name = named_type_name(node, source);
            let arguments = direct_child(node, "type_arguments");
            if arguments.is_none() && type_parameters.iter().any(|parameter| parameter == &name) {
                Ok(TypeRef::TypeParameter { name })
            } else {
                named_type_at_depth(name, arguments, source, type_parameters, depth, max_depth)
            }
        }
        "optional_type" => Ok(nullable_type(type_ref(
            required_child(node, "type")?,
            source,
            type_parameters,
            depth.saturating_add(1),
            max_depth,
        )?)),
        "tuple_type" => {
            let mut elements = Vec::new();
            for element in direct_children(node, "type") {
                elements.push(type_ref(
                    element,
                    source,
                    type_parameters,
                    depth.saturating_add(1),
                    max_depth,
                )?);
            }
            Ok(TypeRef::Tuple { elements })
        }
        "builtin_type" => Ok(match node_text(node, source) {
            "bot" => simple_type("bottom"),
            "__todo__" => simple_type("untyped"),
            name => simple_type(name),
        }),
        "union_type" => Ok(TypeRef::Named {
            name: "union".to_owned(),
            arguments: compound_type_arguments(
                node,
                "union_type",
                source,
                type_parameters,
                depth,
                max_depth,
            )?,
            nullable: false,
        }),
        "intersection_type" => Ok(TypeRef::Named {
            name: "intersection".to_owned(),
            arguments: compound_type_arguments(
                node,
                "intersection_type",
                source,
                type_parameters,
                depth,
                max_depth,
            )?,
            nullable: false,
        }),
        "record_type" => Ok(simple_type("record")),
        "string_literal" | "symbol_literal" | "integer_literal" => Ok(simple_type("literal")),
        "proc" => Ok(simple_type("proc")),
        "singleton_type" => Ok(simple_type("class")),
        _ => Ok(simple_type("untyped")),
    }
}

fn named_type(
    name: String,
    arguments: Option<Node<'_>>,
    source: &str,
    type_parameters: &[String],
    max_depth: usize,
) -> Result<TypeRef, UnmodeledShape> {
    named_type_at_depth(name, arguments, source, type_parameters, 0, max_depth)
}

fn named_type_at_depth(
    name: String,
    arguments: Option<Node<'_>>,
    source: &str,
    type_parameters: &[String],
    depth: usize,
    max_depth: usize,
) -> Result<TypeRef, UnmodeledShape> {
    let mut projected = Vec::new();
    for argument in arguments
        .map(|node| direct_children(node, "type"))
        .unwrap_or_default()
    {
        projected.push(type_ref(
            argument,
            source,
            type_parameters,
            depth.saturating_add(1),
            max_depth,
        )?);
    }
    Ok(TypeRef::Named {
        name,
        arguments: projected,
        nullable: false,
    })
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

fn compound_type_arguments(
    node: Node<'_>,
    compound_kind: &str,
    source: &str,
    type_parameters: &[String],
    depth: usize,
    max_depth: usize,
) -> Result<Vec<TypeRef>, UnmodeledShape> {
    let mut arguments = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        let unwrapped = unwrap_type(node);
        if unwrapped.kind() == compound_kind {
            let right = required_field(unwrapped, "right")?;
            let left = required_field(unwrapped, "left")?;
            stack.push(right);
            stack.push(left);
        } else {
            arguments.push(type_ref(
                unwrapped,
                source,
                type_parameters,
                depth.saturating_add(1),
                max_depth,
            )?);
        }
    }
    Ok(arguments)
}

fn type_name(name: Node<'_>, source: &str) -> String {
    normalize_name(node_text(name, source))
}

fn logical_path(archive_sha256: &str, entry_path: &str) -> String {
    format!("gem+sha256:{archive_sha256}!/{entry_path}")
}

fn hierarchy_target(
    member: Node<'_>,
    source: &str,
    type_parameters: &[String],
    limits: &ArtifactProducerLimits,
) -> Result<TypeRef, UnmodeledShape> {
    let name = required_field(member, "name")?;
    named_type(
        type_name(name, source),
        direct_child(member, "type_arguments"),
        source,
        type_parameters,
        limits.max_signature_depth,
    )
}

fn declaration_name(
    declaration: Node<'_>,
    parent_namespace: &str,
    source: &str,
) -> Result<String, UnmodeledShape> {
    let name = required_field(declaration, "name")?;
    let normalized = type_name(name, source).trim_start_matches("::").to_owned();
    if parent_namespace.is_empty()
        || direct_child(name, "namespace").is_some()
        || node_text(name, source).starts_with("::")
    {
        Ok(normalized)
    } else {
        Ok(format!("{parent_namespace}::{normalized}"))
    }
}

fn named_type_name(node: Node<'_>, source: &str) -> String {
    direct_child(node, "class_name")
        .or_else(|| direct_child(node, "interface_name"))
        .or_else(|| direct_child(node, "alias_name"))
        .map(|name| type_name(name, source))
        .unwrap_or_else(|| "untyped".to_owned())
}

fn type_parameters(node: Option<Node<'_>>, source: &str) -> Vec<String> {
    node.map(|node| descendants_matching(node, &["type_variable"]))
        .unwrap_or_default()
        .into_iter()
        .map(|node| node_text(node, source).to_owned())
        .collect()
}

fn member_name<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Result<&'source str, UnmodeledShape> {
    (node.kind() == "method_name")
        .then_some(node)
        .or_else(|| {
            descendants_matching(node, &["method_name"])
                .into_iter()
                .next()
        })
        .map(|node| node_text(node, source))
        .ok_or_else(|| UnmodeledShape {
            node_kind: node.kind(),
            expected: "a method_name descendant".to_owned(),
        })
}

fn visibility_from_node(
    node: Node<'_>,
    source: &str,
) -> Result<Option<Visibility>, UnmodeledShape> {
    let Some(visibility) = direct_child(node, "visibility") else {
        return Ok(None);
    };
    modeled_visibility(node.kind(), node_text(visibility, source)).map(Some)
}

/// The grammar in use spells only `public` and `private`, but the projection
/// reads the token text rather than the node kind, so a grammar that adds a
/// third spelling would otherwise reach an unhandled arm on gem-supplied bytes.
fn modeled_visibility(node_kind: &'static str, token: &str) -> Result<Visibility, UnmodeledShape> {
    match token {
        "private" => Ok(Visibility::Private),
        "public" => Ok(Visibility::Public),
        unmodeled => Err(UnmodeledShape {
            node_kind,
            expected: format!("a modeled visibility, but its token is {unmodeled}"),
        }),
    }
}

fn declaration_body(node: Node<'_>) -> Result<Node<'_>, UnmodeledShape> {
    if matches!(node.kind(), "decl" | "member" | "interface_member") {
        required_field(node, "body")
    } else {
        Ok(node)
    }
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, UnmodeledShape> {
    node.child_by_field_name(field)
        .ok_or_else(|| UnmodeledShape {
            node_kind: node.kind(),
            expected: format!("a {field} field"),
        })
}

fn required_child<'tree>(node: Node<'tree>, kind: &str) -> Result<Node<'tree>, UnmodeledShape> {
    direct_child(node, kind).ok_or_else(|| UnmodeledShape {
        node_kind: node.kind(),
        expected: format!("a {kind} child"),
    })
}

/// tree-sitter keeps comments as named siblings of declarations and members.
/// They carry no declared surface, so skipping one loses nothing and must not
/// demote the pack the way an unmodeled construct does.
fn is_trivia(kind: &str) -> bool {
    kind == "comment"
}

fn is_declaration(kind: &str) -> bool {
    matches!(
        kind,
        "class_decl"
            | "module_decl"
            | "interface_decl"
            | "const_decl"
            | "class_alias_decl"
            | "module_alias_decl"
            | "type_alias_decl"
            | "global_decl"
            | "use_directive"
    )
}

fn unsupported_declaration_kind(kind: &str) -> &str {
    kind.strip_suffix("_decl").unwrap_or(kind)
}

fn unwrap_type(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "type" {
        let Some(child) = named_children(node)
            .into_iter()
            .find(|child| !is_trivia(child.kind()))
        else {
            break;
        };
        node = child;
    }
    node
}

fn normalize_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    // tree-sitter reports byte ranges on character boundaries of the `&str` it
    // was handed, so this cannot depend on the archive's contents.
    node.utf8_text(source.as_bytes())
        .expect("tree-sitter RBS ranges must be valid UTF-8")
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn direct_child<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == kind)
}

fn direct_children<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == kind)
        .collect()
}

fn descendants_matching<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    let mut stack = named_children(node).into_iter().rev().collect::<Vec<_>>();
    while let Some(node) = stack.pop() {
        if kinds.contains(&node.kind()) {
            matches.push(node);
        } else {
            stack.extend(named_children(node).into_iter().rev());
        }
    }
    matches
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
  alias self.create self.build
end
class Widget[T]
  alias invoke call
end
Widget::VERSION: String
"#,
            &ArtifactProducerLimits::default(),
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        assert_eq!(projection.types.len(), 2);
        assert!(projection.types.iter().all(|fact| fact.name == "Widget"));
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
        assert_eq!(projection.members.len(), 4);
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
                .any(|member| member.name == "build"
                    && member.is_static
                    && member.aliases == ["create"])
        );
        assert!(projection.members.iter().any(|member| {
            member.name == "VERSION" && member.member_kind == MemberKind::Constant
        }));
    }

    #[test]
    fn tree_sitter_rbs_projects_nested_types_interfaces_attributes_and_keywords() {
        let projection = project_rbs(
            &"5".repeat(64),
            "sig/nested.rbs",
            r#"
module Outer : Base, _Feature
  class Widget[T]
    private
    attr_reader name: String
    attr_reader self.count: Integer
    def transform: [U] (T value, ?String label, key: Integer, ?mode: String, **untyped rest) -> U
    VERSION: String
  end
  interface _Callable[T]
    def call: (T value) -> String
  end
end
"#,
            &ArtifactProducerLimits::default(),
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        assert_eq!(
            projection
                .types
                .iter()
                .map(|fact| fact.name.as_str())
                .collect::<Vec<_>>(),
            ["Outer", "Outer::Widget", "Outer::_Callable"]
        );
        assert_eq!(projection.types[0].hierarchy.len(), 2);
        assert_eq!(projection.types[1].type_parameters, ["T"]);
        let name = projection
            .members
            .iter()
            .find(|member| member.name == "name")
            .unwrap();
        assert_eq!(name.visibility, Visibility::Private);
        assert!(!name.is_static);
        let count = projection
            .members
            .iter()
            .find(|member| member.name == "count")
            .unwrap();
        assert!(count.is_static);
        let transform = projection
            .members
            .iter()
            .find(|member| member.name == "transform")
            .unwrap();
        let signature = transform.signature.as_ref().unwrap();
        assert_eq!(signature.type_parameters, ["U"]);
        assert_eq!(signature.parameters.len(), 5);
        assert_eq!(signature.parameters[2].name.as_deref(), Some("key"));
        assert!(signature.parameters[3].optional);
        assert!(signature.parameters[4].variadic);
        assert!(matches!(
            signature.returns,
            Some(TypeRef::TypeParameter { ref name }) if name == "U"
        ));
        assert!(
            projection.members.iter().any(|member| {
                member.name == "VERSION" && member.owner == projection.types[1].id
            })
        );
    }

    #[test]
    fn malformed_rbs_is_partial_with_a_bounded_diagnostic() {
        let projection = project_rbs(
            &"b".repeat(64),
            "sig/broken.rbs",
            "class { end",
            &ArtifactProducerLimits::default(),
            None,
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

    #[test]
    fn top_level_constant_respects_the_record_budget() {
        let projection = project_rbs(
            &"3".repeat(64),
            "sig/constants.rbs",
            "VERSION: String\n",
            &ArtifactProducerLimits {
                max_records: 1,
                ..ArtifactProducerLimits::default()
            },
            None,
        );

        assert!(!projection.complete);
        assert!(projection.types.len() + projection.members.len() <= 1);
        assert!(
            projection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );
    }

    #[test]
    fn block_signatures_are_explicitly_partial_until_the_model_can_represent_them() {
        let projection = project_rbs(
            &"4".repeat(64),
            "sig/blocks.rbs",
            "class Widget\n  def each: () { (String) -> void } -> void\nend\n",
            &ArtifactProducerLimits::default(),
            None,
        );

        assert!(!projection.complete);
        assert!(projection.members.is_empty());
        assert!(
            projection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "ruby.rbs.unsupported_block_signature")
        );
    }

    #[test]
    fn comments_are_trivia_that_neither_demote_the_pack_nor_hide_a_type() {
        let projection = project_rbs(
            &"6".repeat(64),
            "sig/commented.rbs",
            r#"# a gem's own copyright header
class Widget
  # a comment before the first member
  def call: (String value) -> Integer
  # a comment between two members
  def self.build: () -> (
    # a comment inside a parenthesised type
    Widget)
end
"#,
            &ArtifactProducerLimits::default(),
            None,
        );

        assert!(projection.complete, "{:?}", projection.diagnostics);
        assert!(projection.diagnostics.is_empty());
        assert_eq!(projection.types.len(), 1);
        assert_eq!(projection.members.len(), 2);
        let build = projection
            .members
            .iter()
            .find(|member| member.name == "build")
            .unwrap();
        assert_eq!(
            build.signature.as_ref().unwrap().returns,
            Some(simple_type("Widget"))
        );
    }

    #[test]
    fn unmodeled_visibility_degrades_instead_of_aborting_the_producer() {
        let miss = modeled_visibility("visibility_member", "protected").unwrap_err();
        assert_eq!(miss.node_kind, "visibility_member");
        assert!(miss.expected.contains("protected"), "{miss:?}");
        assert_eq!(
            modeled_visibility("method_member", "private"),
            Ok(Visibility::Private)
        );
        assert_eq!(
            modeled_visibility("attribute_member", "public"),
            Ok(Visibility::Public)
        );
    }

    #[test]
    fn every_grammar_shape_lookup_reports_a_miss_instead_of_panicking() {
        // The pinned grammar cannot emit these arrangements without also
        // raising a parse error, so each lookup is driven with a node of a kind
        // that lacks the field or child the projection reads. That is exactly
        // the state a grammar change or a newer RBS construct would produce.
        let source =
            "class Widget\n  def call: (String value) -> Integer\n  alias invoke call\nend\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rbs::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let class = declaration_body(tree.root_node().named_child(0).unwrap()).unwrap();
        let class_name = required_field(class, "name").unwrap();
        let members = class.child_by_field_name("body").unwrap();
        let method = declaration_body(members.named_child(0).unwrap()).unwrap();
        let alias = declaration_body(members.named_child(1).unwrap()).unwrap();
        let limits = ArtifactProducerLimits::default();

        // A class, module, or interface whose name field moved or was renamed.
        let miss = declaration_name(class_name, "", source).unwrap_err();
        assert_eq!(miss.node_kind, "class_name");
        assert_eq!(miss.expected, "a name field");
        // A `decl`, `member`, or `interface_member` wrapper with no body, and
        // the identical lookup a method overload makes for its function type.
        assert_eq!(
            required_field(class_name, "body").unwrap_err().expected,
            "a body field"
        );
        // An alias member missing either of its two names.
        assert_eq!(
            project_alias(class_name, "owner", source)
                .unwrap_err()
                .expected,
            "a name field"
        );
        // A union or intersection type with no operands.
        assert_eq!(
            compound_type_arguments(class_name, "class_name", source, &[], 0, 8)
                .unwrap_err()
                .expected,
            "a right field"
        );
        // A constant declaration with no const_name, both where the record
        // budget reads it and where the projection reads it.
        assert_eq!(
            constant_record_cost(class, "", &[]).unwrap_err().node_kind,
            "class_decl"
        );
        assert_eq!(
            required_child(class, "const_name").unwrap_err().expected,
            "a const_name child"
        );
        // An optional type that wraps nothing.
        assert_eq!(
            required_child(class_name, "type").unwrap_err().expected,
            "a type child"
        );
        // A method or attribute member with no method name beneath it.
        assert_eq!(
            member_name(class_name, source).unwrap_err().expected,
            "a method_name descendant"
        );
        assert_eq!(
            project_attribute(
                class_name,
                "owner",
                Visibility::Public,
                &Locator::Artifact {
                    path: "gem".to_owned(),
                    symbol: "Widget".to_owned(),
                },
                source,
                &[],
                &limits,
            )
            .unwrap_err()
            .expected,
            "a method_name descendant"
        );
        // An include, prepend, or extend member with no name field.
        assert_eq!(
            hierarchy_target(class_name, source, &[], &limits)
                .unwrap_err()
                .expected,
            "a name field"
        );
        // The shapes that are present still project.
        assert!(member_name(method, source).is_ok());
        assert!(project_alias(alias, "owner", source).is_ok());
    }

    #[test]
    fn adversarial_rbs_entries_never_abort_and_never_claim_completeness_with_a_diagnostic() {
        // Gem archives are untrusted, so a crafted or merely unusual entry has
        // to leave the producer with a projection it can still publish.
        let adversarial = [
            "",
            "\u{0}\u{0}\u{0}",
            "end\n",
            "Integer\n",
            "#: () -> void\n#: () -> void\n",
            "$hostile: untyped\n",
            "type shadow = Integer\n",
            "class Widget = Other\n",
            "module Widget = Other\n",
            "use Foo::Bar\n",
            "class Widget\n  @hidden: untyped\nend\n",
            "class Widget\n  def call: ...\nend\n",
            "class Widget\n  def call: () -> ((((((Integer))))))\nend\n",
            "class Widget\n  def call: () -> (Integer | String | Symbol | bot)?\nend\n",
            "class Widget\n  def call: () -> [Integer, [String, [Symbol]]]\nend\n",
            "class Widget\n  def call: () -> { a: Integer }\nend\n",
            "class Widget\n  def call: () -> ^(Integer) -> void\nend\n",
            "class Widget\n  def self?.call: () -> void\nend\n",
            "class ::A::B::C\n  def []=: (Integer, String) -> void\nend\n",
            "class Widget\n  attr_accessor self.name(@n): String\nend\n",
            "interface _Widget\n  include _Other\n  alias self.a self.b\nend\n",
        ];
        for source in adversarial {
            let projection = project_rbs(
                &"7".repeat(64),
                "sig/adversarial.rbs",
                source,
                &ArtifactProducerLimits::default(),
                None,
            );
            assert!(
                projection.diagnostics.is_empty() || !projection.complete,
                "{source:?} claimed completeness with {:?}",
                projection.diagnostics
            );
            assert!(
                !projection.complete || projection.suppressed_diagnostics == 0,
                "{source:?}"
            );
        }
    }
}
