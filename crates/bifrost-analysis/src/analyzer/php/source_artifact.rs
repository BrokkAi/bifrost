//! Project one Composer package's PHP sources into declaration facts.
//!
//! Every name this module records comes from the tree-sitter PHP AST and from
//! the crate's own `use`-alias resolver. Nothing here scans source text for a
//! declaration.

use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, HierarchyFact, HierarchyKind, Locator,
    MemberFact, MemberIdentity, MemberKind, Parameter, ProducerDiagnostic, Signature,
    SuppressedDiagnostics, TypeFact, TypeIdentity, TypeKind, TypeRef, Visibility,
    member_declaration_id, type_declaration_id,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::node_text;
use brokk_bifrost_php::aliases::{
    PhpFileContext, PhpFileContextIndex, php_namespace_to_fq, resolve_php_type,
};
use brokk_bifrost_php::graph::syntax::declaration_doc_comment;

/// The ecosystem term that binds every Composer declaration identity.
pub(crate) const COMPOSER_ECOSYSTEM: &str = "composer";

/// The ecosystem term that binds every PHP *runtime* declaration identity.
///
/// The runtime is not a Composer package, so a builtin `PDO` and a vendor
/// class that happens to be named `PDO` must not collapse onto one identity.
pub(crate) const PHP_RUNTIME_ECOSYSTEM: &str = "php";

/// The logical-path scheme a Composer package's projected locators carry.
pub(crate) const COMPOSER_LOCATOR_SCHEME: &str = "composer";

/// The logical-path scheme a PHP declaration stub's projected locators carry.
pub(crate) const PHP_STUB_LOCATOR_SCHEME: &str = "php-stub";

/// The identity domain one PHP projection publishes into.
///
/// `ecosystem` is the term hashed into every declaration id, and `scheme` is
/// the prefix of the logical artifact path a locator records. These are data,
/// not a mode: both callers use them identically, and only the domain they
/// name differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PhpProjectionOrigin<'a> {
    pub ecosystem: &'a str,
    pub scheme: &'a str,
}

impl PhpProjectionOrigin<'static> {
    /// The domain a Composer package's declarations belong to.
    pub(crate) const fn composer() -> Self {
        Self {
            ecosystem: COMPOSER_ECOSYSTEM,
            scheme: COMPOSER_LOCATOR_SCHEME,
        }
    }

    /// The domain a pinned PHP runtime stub tree's declarations belong to.
    pub(crate) const fn php_runtime_stub() -> Self {
        Self {
            ecosystem: PHP_RUNTIME_ECOSYSTEM,
            scheme: PHP_STUB_LOCATOR_SCHEME,
        }
    }
}

/// The owner name for declarations in PHP's global namespace.
///
/// A fact must carry a non-empty qualified name, and `files` autoloading really
/// does define global helper functions, so they need an owner. This name is not
/// a claim that the pack covers the global namespace: PHP's own built-in global
/// surface is far larger than any one package, so the collector never treats
/// global coverage as grounds to prove a name absent.
pub(crate) const PHP_GLOBAL_NAMESPACE: &str = "_php_global_";

/// The Composer autoload rule that admitted one file.
///
/// The rule reaches production through the artifact that carries the file, not
/// through an encoded string, so a PSR-4 prefix stays attached to the files it
/// admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhpAutoloadRule<'a> {
    /// The file is mapped by a PSR-4 prefix, so its declared namespace and its
    /// path must agree.
    Psr4 { namespace_prefix: &'a str },
    /// Composer scanned the file and registered whatever it declares. There is
    /// no namespace or path constraint.
    Classmap,
    /// Composer includes the file unconditionally, so its free functions and
    /// constants are always defined.
    Files,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhpSourceProjection {
    pub types: Vec<TypeFact>,
    pub members: Vec<MemberFact>,
    /// Everything this projection noticed about a declaration it published but
    /// did not model.
    ///
    /// The walk records the observation rather than interpreting it: a stub
    /// tree states version-dependent types and availability windows as PHP
    /// attributes, and states extra members in docblocks. The producer that
    /// reads such a tree must be able to say which records it therefore read
    /// incompletely. A Composer projection has no such need and ignores the
    /// field.
    pub notes: Vec<PhpDeclarationNote>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
    pub complete: bool,
}

/// One declaration this projection published together with one thing the walk
/// noticed but did not model. `declaration` is the fact id, so a caller can
/// name the exact record its marker is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PhpDeclarationNote {
    pub declaration: String,
    pub marker: PhpDeclarationMarker,
}

/// What the walk noticed on one declaration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PhpDeclarationMarker {
    /// A PHP attribute written on the declaration or on one of its
    /// parameters, resolved through the file's `use` bindings so that an
    /// aliased import and a plain one name the same attribute.
    Attribute(String),
    /// The declaration states one parameter name more than once. PHP itself
    /// rejects that at compile time, so it arises only in a declaration-stub
    /// dialect that spells one parameter twice for different runtime
    /// versions. The projection keeps the first spelling, which is the one a
    /// reader of the declaration sees, and reports the rest here.
    DuplicateParameterName(String),
    /// The declaration's own docblock states `@method`, `@property`,
    /// `@property-read`, or `@property-write` members. Bifrost synthesizes no
    /// declaration from those tags, so the published surface is not all of the
    /// declaration's surface.
    DocblockOnlyMembers,
}

struct Work<'tree> {
    node: Node<'tree>,
    namespace: String,
    owner: Option<PhpOwner>,
}

#[derive(Debug, Clone)]
struct PhpOwner {
    id: String,
    name: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn project_php_source(
    artifact_sha256: &str,
    entry_path: &str,
    source: &str,
    rule: PhpAutoloadRule<'_>,
    origin: PhpProjectionOrigin<'_>,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
) -> PhpSourceProjection {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    if is_cancelled(cancellation) {
        diagnostics.error(
            "php.source.cancelled",
            None,
            "PHP declaration projection was cancelled",
        );
        return finish(Vec::new(), Vec::new(), Vec::new(), diagnostics, false);
    }
    let Some(tree) = parse_php_tree(source) else {
        diagnostics.error(
            "php.source.parse",
            Some(logical_path(origin, artifact_sha256, entry_path)),
            "could not parse PHP declaration source",
        );
        return finish(Vec::new(), Vec::new(), Vec::new(), diagnostics, false);
    };
    if tree.root_node().has_error() {
        diagnostics.warning(
            "php.source.syntax",
            Some(logical_path(origin, artifact_sha256, entry_path)),
            "PHP declaration source contains syntax errors",
        );
    }

    let Some(contexts) =
        PhpFileContextIndex::from_tree(tree.root_node(), source, || !is_cancelled(cancellation))
    else {
        diagnostics.error(
            "php.source.cancelled",
            None,
            "PHP declaration projection was cancelled",
        );
        return finish(Vec::new(), Vec::new(), Vec::new(), diagnostics, false);
    };
    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut notes = Vec::new();
    let mut namespaces = Vec::new();
    let mut stack = Vec::new();
    expand_container(
        tree.root_node(),
        String::new(),
        None,
        source,
        &mut namespaces,
        &mut stack,
    );

    while let Some(work) = stack.pop() {
        if is_cancelled(cancellation) {
            diagnostics.error(
                "php.source.cancelled",
                None,
                "PHP declaration projection was cancelled",
            );
            break;
        }
        if types.len().saturating_add(members.len()) >= limits.max_records {
            diagnostics.error(
                "limit.records",
                Some(logical_path(origin, artifact_sha256, entry_path)),
                format!(
                    "PHP declarations exceed the {} record limit",
                    limits.max_records
                ),
            );
            break;
        }
        let ctx = contexts.context_at(work.node.start_byte());
        debug_assert_eq!(
            ctx.namespace, work.namespace,
            "the PHP declaration walk and context index must agree on namespace scope"
        );
        match work.node.kind() {
            "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration" => {
                project_type(
                    &work,
                    ctx,
                    origin,
                    artifact_sha256,
                    entry_path,
                    source,
                    &mut namespaces,
                    &mut types,
                    &mut notes,
                    &mut stack,
                );
            }
            "function_definition" => {
                if let Some(member) = project_callable(
                    work.node,
                    owner_for(&work, origin, &mut namespaces),
                    ctx,
                    origin,
                    artifact_sha256,
                    entry_path,
                    source,
                    MemberKind::Function,
                ) {
                    record_callable_notes(work.node, source, ctx, &member.id, &mut notes);
                    members.push(member);
                }
            }
            "method_declaration" => {
                let Some(owner) = work.owner.clone() else {
                    continue;
                };
                let name = declaration_name(work.node, source).unwrap_or_default();
                let kind = if name == "__construct" {
                    MemberKind::Constructor
                } else {
                    MemberKind::Method
                };
                if let Some(member) = project_callable(
                    work.node,
                    owner,
                    ctx,
                    origin,
                    artifact_sha256,
                    entry_path,
                    source,
                    kind,
                ) {
                    record_callable_notes(work.node, source, ctx, &member.id, &mut notes);
                    members.push(member);
                }
            }
            "property_declaration" => {
                let Some(owner) = work.owner.clone() else {
                    continue;
                };
                let first_property = members.len();
                project_properties(
                    work.node,
                    owner,
                    ctx,
                    origin,
                    artifact_sha256,
                    entry_path,
                    source,
                    &mut members,
                );
                record_declaration_notes(
                    work.node,
                    source,
                    ctx,
                    &members[first_property..],
                    &mut notes,
                );
            }
            "const_declaration" => {
                let owner = owner_for(&work, origin, &mut namespaces);
                let first_constant = members.len();
                project_constants(
                    work.node,
                    owner,
                    origin,
                    artifact_sha256,
                    entry_path,
                    source,
                    &mut members,
                );
                record_declaration_notes(
                    work.node,
                    source,
                    ctx,
                    &members[first_constant..],
                    &mut notes,
                );
            }
            "enum_case" => {
                let Some(owner) = work.owner.clone() else {
                    continue;
                };
                if let Some(name) = declaration_name(work.node, source) {
                    members.push(constant_member(
                        owner,
                        name,
                        Visibility::Public,
                        origin,
                        artifact_sha256,
                        entry_path,
                    ));
                }
            }
            _ => {}
        }
    }

    if let PhpAutoloadRule::Psr4 { namespace_prefix } = rule {
        check_psr4_agreement(
            namespace_prefix,
            entry_path,
            origin,
            artifact_sha256,
            &types,
            &mut diagnostics,
        );
        // The prefix itself is part of the package's declared surface even when
        // this file declares a deeper namespace.
        record_namespace(namespace_prefix, &mut namespaces);
    }
    for namespace in namespaces {
        types.push(namespace_fact(
            &namespace,
            origin,
            artifact_sha256,
            entry_path,
        ));
    }
    types.sort_by(|left, right| left.id.cmp(&right.id));
    types.dedup_by(|left, right| left.id == right.id);
    members.sort_by(|left, right| left.id.cmp(&right.id));
    members.dedup_by(|left, right| left.id == right.id);
    notes.sort();
    notes.dedup();
    let complete = diagnostics.is_empty();
    finish(types, members, notes, diagnostics, complete)
}

/// Expand a container's declarations in source order.
///
/// A bare `namespace Foo;` applies to every later sibling, so the namespace is
/// resolved while the children are walked rather than after.
fn expand_container<'tree>(
    container: Node<'tree>,
    namespace: String,
    owner: Option<PhpOwner>,
    source: &str,
    namespaces: &mut Vec<String>,
    stack: &mut Vec<Work<'tree>>,
) {
    let mut current = namespace;
    let mut pending = Vec::new();
    let mut cursor = container.walk();
    for child in container.named_children(&mut cursor) {
        if child.kind() == "namespace_definition" {
            let declared = child
                .child_by_field_name("name")
                .map(|name| php_namespace_to_fq(node_text(name, source)))
                .unwrap_or_default();
            match namespace_body(child) {
                // `namespace Foo { ... }` scopes only its own body.
                Some(body) => {
                    record_namespace(&declared, namespaces);
                    pending.push(Work {
                        node: body,
                        namespace: declared,
                        owner: owner.clone(),
                    });
                }
                // `namespace Foo;` applies to every later sibling.
                None => {
                    record_namespace(&declared, namespaces);
                    current = declared;
                }
            }
            continue;
        }
        pending.push(Work {
            node: child,
            namespace: current.clone(),
            owner: owner.clone(),
        });
    }
    // A container body is itself expanded, so re-expand it inline instead of
    // dispatching on it in the main loop.
    for work in pending.into_iter().rev() {
        if matches!(
            work.node.kind(),
            "compound_statement" | "declaration_list" | "program"
        ) {
            expand_container(
                work.node,
                work.namespace,
                work.owner,
                source,
                namespaces,
                stack,
            );
        } else {
            stack.push(work);
        }
    }
}

fn namespace_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "compound_statement" | "declaration_list"))
    })
}

#[allow(clippy::too_many_arguments)]
fn project_type<'tree>(
    work: &Work<'tree>,
    ctx: &PhpFileContext,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
    source: &str,
    namespaces: &mut Vec<String>,
    types: &mut Vec<TypeFact>,
    notes: &mut Vec<PhpDeclarationNote>,
    stack: &mut Vec<Work<'tree>>,
) {
    let Some(name) = declaration_name(work.node, source) else {
        return;
    };
    let qualified = qualify(&work.namespace, &name);
    let id = type_declaration_id(TypeIdentity {
        ecosystem: origin.ecosystem,
        name: &qualified,
    });
    let type_kind = match work.node.kind() {
        "interface_declaration" => TypeKind::Interface,
        "trait_declaration" => TypeKind::Trait,
        "enum_declaration" => TypeKind::Enum,
        _ => TypeKind::Class,
    };
    record_namespace(&work.namespace, namespaces);
    types.push(TypeFact {
        id: id.clone(),
        name: qualified.clone(),
        type_kind,
        visibility: Visibility::Public,
        is_abstract: has_modifier(work.node, source, "abstract"),
        is_sealed: has_modifier(work.node, source, "final"),
        has_explicit_type_terms: false,
        type_parameters: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        value_semantics: None,
        embedded_types: Vec::new(),
        hierarchy: hierarchy_of(work.node, source, ctx),
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        guard: None,
        locator: artifact_locator(origin, artifact_sha256, entry_path, &qualified),
    });
    for attribute in declaration_attribute_names(work.node, source, ctx) {
        notes.push(PhpDeclarationNote {
            declaration: id.clone(),
            marker: PhpDeclarationMarker::Attribute(attribute),
        });
    }
    if declaration_doc_comment(work.node, source)
        .is_some_and(brokk_bifrost_php::phpdoc::declares_docblock_only_members)
    {
        notes.push(PhpDeclarationNote {
            declaration: id.clone(),
            marker: PhpDeclarationMarker::DocblockOnlyMembers,
        });
    }
    if let Some(body) = type_body(work.node) {
        expand_container(
            body,
            work.namespace.clone(),
            Some(PhpOwner {
                id,
                name: qualified,
            }),
            source,
            namespaces,
            stack,
        );
    }
}

fn type_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
    })
}

fn hierarchy_of(node: Node<'_>, source: &str, ctx: &PhpFileContext) -> Vec<HierarchyFact> {
    let mut hierarchy = Vec::new();
    let mut ordinal = 0_u32;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let kind = match child.kind() {
            "base_clause" => HierarchyKind::Extends,
            "class_interface_clause" => HierarchyKind::Implements,
            _ => continue,
        };
        for target in clause_targets(child, source, ctx) {
            hierarchy.push(HierarchyFact {
                hierarchy_kind: kind,
                target,
                declaration_ordinal: Some(ordinal),
            });
            ordinal = ordinal.saturating_add(1);
        }
    }
    if let Some(body) = type_body(node) {
        let mut body_cursor = body.walk();
        for child in body.named_children(&mut body_cursor) {
            if child.kind() != "use_declaration" {
                continue;
            }
            for target in clause_targets(child, source, ctx) {
                hierarchy.push(HierarchyFact {
                    hierarchy_kind: HierarchyKind::UsesTrait,
                    target,
                    declaration_ordinal: Some(ordinal),
                });
                ordinal = ordinal.saturating_add(1);
            }
        }
    }
    hierarchy
}

fn clause_targets(clause: Node<'_>, source: &str, ctx: &PhpFileContext) -> Vec<TypeRef> {
    let mut targets = Vec::new();
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if !matches!(child.kind(), "name" | "qualified_name") {
            continue;
        }
        let raw = node_text(child, source).trim();
        if raw.is_empty() {
            continue;
        }
        targets.push(TypeRef::Named {
            name: resolve_php_type(raw, ctx).unwrap_or_else(|| php_namespace_to_fq(raw)),
            arguments: Vec::new(),
            nullable: false,
        });
    }
    targets
}

#[allow(clippy::too_many_arguments)]
fn project_callable(
    node: Node<'_>,
    owner: PhpOwner,
    ctx: &PhpFileContext,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
    source: &str,
    member_kind: MemberKind,
) -> Option<MemberFact> {
    let name = declaration_name(node, source)?;
    let is_static = has_modifier(node, source, "static");
    let signature = callable_signature(node, source, ctx);
    let parameter_types = signature
        .parameters
        .iter()
        .map(|parameter| parameter.r#type.clone())
        .collect::<Vec<_>>();
    let parameter_variadics = signature
        .parameters
        .iter()
        .map(|parameter| parameter.variadic)
        .collect::<Vec<_>>();
    let id = member_declaration_id(MemberIdentity {
        owner_id: &owner.id,
        kind: member_kind,
        is_static,
        parameter_arity: parameter_types.len(),
        name: &name,
        generic_arity: 0,
        parameter_types: &parameter_types,
        parameter_variadics: &parameter_variadics,
        return_type: signature.returns.as_ref(),
    });
    Some(MemberFact {
        id,
        owner: owner.id,
        name: name.clone(),
        member_kind,
        visibility: visibility_of(node, source),
        is_static,
        is_abstract: has_modifier(node, source, "abstract"),
        is_virtual: false,
        implicit_operation: None,
        callable_family_complete: false,
        signature: Some(signature),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        guard: None,
        locator: artifact_locator(
            origin,
            artifact_sha256,
            entry_path,
            &format!("{}.{name}", owner.name),
        ),
    })
}

fn callable_signature(node: Node<'_>, source: &str, ctx: &PhpFileContext) -> Signature {
    let mut parameters = Vec::new();
    if let Some(list) = node.child_by_field_name("parameters") {
        let mut cursor = list.walk();
        for child in list.named_children(&mut cursor) {
            if !matches!(
                child.kind(),
                "simple_parameter" | "variadic_parameter" | "property_promotion_parameter"
            ) {
                continue;
            }
            let name = child
                .child_by_field_name("name")
                .map(|name| node_text(name, source).trim_start_matches('$').to_owned());
            // PHP rejects a repeated parameter name at compile time, so a
            // repeat can only come from a declaration-stub dialect spelling
            // one parameter twice for two runtime versions. The first
            // spelling is the one a reader of the declaration sees; the walk
            // keeps it and `record_callable_notes` reports the rest.
            if name.as_ref().is_some_and(|name| {
                parameters
                    .iter()
                    .any(|existing: &Parameter| existing.name.as_ref() == Some(name))
            }) {
                continue;
            }
            parameters.push(Parameter {
                name,
                r#type: child
                    .child_by_field_name("type")
                    .and_then(|type_node| php_type_ref(type_node, source, ctx))
                    .unwrap_or_else(unknown_type),
                optional: child.child_by_field_name("default_value").is_some(),
                variadic: child.kind() == "variadic_parameter",
                passing_mode: Default::default(),
            });
        }
    }
    Signature {
        type_parameters: Vec::new(),
        parameters,
        returns: node
            .child_by_field_name("return_type")
            .and_then(|type_node| php_type_ref(type_node, source, ctx)),
    }
}

#[allow(clippy::too_many_arguments)]
fn project_properties(
    node: Node<'_>,
    owner: PhpOwner,
    ctx: &PhpFileContext,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
    source: &str,
    members: &mut Vec<MemberFact>,
) {
    let visibility = visibility_of(node, source);
    let is_static = has_modifier(node, source, "static");
    let declared = node
        .child_by_field_name("type")
        .and_then(|type_node| php_type_ref(type_node, source, ctx));
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "property_element" {
            continue;
        }
        let Some(name_node) = child
            .child_by_field_name("name")
            .or_else(|| child.named_child(0))
        else {
            continue;
        };
        let name = node_text(name_node, source).trim_start_matches('$').trim();
        if name.is_empty() {
            continue;
        }
        let signature = Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: declared.clone(),
        };
        let id = member_declaration_id(MemberIdentity {
            owner_id: &owner.id,
            kind: MemberKind::Property,
            is_static,
            parameter_arity: 0,
            name,
            generic_arity: 0,
            parameter_types: &[],
            parameter_variadics: &[],
            return_type: signature.returns.as_ref(),
        });
        members.push(MemberFact {
            id,
            owner: owner.id.clone(),
            name: name.to_owned(),
            member_kind: MemberKind::Property,
            visibility,
            is_static,
            is_abstract: false,
            is_virtual: false,
            implicit_operation: None,
            callable_family_complete: false,
            signature: Some(signature),
            receiver: None,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            guard: None,
            locator: artifact_locator(
                origin,
                artifact_sha256,
                entry_path,
                &format!("{}.{name}", owner.name),
            ),
        });
    }
}

fn project_constants(
    node: Node<'_>,
    owner: PhpOwner,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
    source: &str,
    members: &mut Vec<MemberFact>,
) {
    let visibility = visibility_of(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "const_element" {
            continue;
        }
        let Some(name_node) = child
            .child_by_field_name("name")
            .or_else(|| child.named_child(0))
        else {
            continue;
        };
        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }
        members.push(constant_member(
            owner.clone(),
            name.to_owned(),
            visibility,
            origin,
            artifact_sha256,
            entry_path,
        ));
    }
}

fn constant_member(
    owner: PhpOwner,
    name: String,
    visibility: Visibility,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
) -> MemberFact {
    let id = member_declaration_id(MemberIdentity {
        owner_id: &owner.id,
        kind: MemberKind::Constant,
        is_static: true,
        parameter_arity: 0,
        name: &name,
        generic_arity: 0,
        parameter_types: &[],
        parameter_variadics: &[],
        return_type: None,
    });
    MemberFact {
        id,
        owner: owner.id,
        name: name.clone(),
        member_kind: MemberKind::Constant,
        visibility,
        is_static: true,
        is_abstract: false,
        is_virtual: false,
        implicit_operation: None,
        callable_family_complete: false,
        signature: None,
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        guard: None,
        locator: artifact_locator(
            origin,
            artifact_sha256,
            entry_path,
            &format!("{}.{name}", owner.name),
        ),
    }
}

/// A namespace scaffold type. Free functions and constants need an owner, and
/// the collector reads these facts to learn which namespaces an indexed pack
/// actually covers.
fn namespace_fact(
    namespace: &str,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
) -> TypeFact {
    TypeFact {
        id: type_declaration_id(TypeIdentity {
            ecosystem: origin.ecosystem,
            name: namespace,
        }),
        name: namespace.to_owned(),
        type_kind: TypeKind::Module,
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
        has_explicit_type_terms: false,
        type_parameters: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        value_semantics: None,
        embedded_types: Vec::new(),
        hierarchy: Vec::new(),
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        guard: None,
        locator: artifact_locator(origin, artifact_sha256, entry_path, namespace),
    }
}

/// PSR-4 requires a class's namespace below the mapped prefix to match its path
/// below the mapped root. A file that breaks the rule would not autoload at
/// run time, so it must not silently become part of a provable surface.
fn check_psr4_agreement(
    namespace_prefix: &str,
    entry_path: &str,
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    types: &[TypeFact],
    diagnostics: &mut BoundedProducerDiagnostics,
) {
    for fact in types {
        if fact.type_kind == TypeKind::Module {
            continue;
        }
        let matches_prefix = namespace_prefix.is_empty()
            || fact.name == namespace_prefix
            || fact
                .name
                .strip_prefix(namespace_prefix)
                .is_some_and(|rest| rest.starts_with('.'));
        if !matches_prefix {
            diagnostics.warning(
                "php.autoload.psr4_namespace",
                Some(logical_path(origin, artifact_sha256, entry_path)),
                format!(
                    "PHP type {} is not below its PSR-4 prefix {namespace_prefix}",
                    fact.name
                ),
            );
            continue;
        }
        let relative = fact
            .name
            .strip_prefix(namespace_prefix)
            .map(|rest| rest.trim_start_matches('.'))
            .unwrap_or(fact.name.as_str());
        let expected = format!("{}.php", relative.replace('.', "/"));
        if !entry_path.ends_with(&expected) {
            diagnostics.warning(
                "php.autoload.psr4_path",
                Some(logical_path(origin, artifact_sha256, entry_path)),
                format!(
                    "PHP type {} does not autoload from {entry_path} under PSR-4 prefix {namespace_prefix}",
                    fact.name
                ),
            );
        }
    }
}

fn owner_for(
    work: &Work<'_>,
    origin: PhpProjectionOrigin<'_>,
    namespaces: &mut Vec<String>,
) -> PhpOwner {
    if let Some(owner) = &work.owner {
        return owner.clone();
    }
    record_namespace(&work.namespace, namespaces);
    let name = scaffold_name(&work.namespace);
    PhpOwner {
        id: type_declaration_id(TypeIdentity {
            ecosystem: origin.ecosystem,
            name,
        }),
        name: name.to_owned(),
    }
}

fn record_namespace(namespace: &str, namespaces: &mut Vec<String>) {
    let namespace = scaffold_name(namespace);
    if !namespaces.iter().any(|existing| existing == namespace) {
        namespaces.push(namespace.to_owned());
    }
}

fn scaffold_name(namespace: &str) -> &str {
    if namespace.is_empty() {
        PHP_GLOBAL_NAMESPACE
    } else {
        namespace
    }
}

fn php_type_ref(node: Node<'_>, source: &str, ctx: &PhpFileContext) -> Option<TypeRef> {
    let mut current = node;
    let mut nullable = false;
    loop {
        match current.kind() {
            "optional_type" => {
                nullable = true;
                current = current.named_child(0)?;
            }
            // A union or intersection keeps its first member, which is the
            // receiver the rest of the analyzer already reasons about.
            "union_type" | "intersection_type" | "named_type" => {
                current = current.named_child(0)?;
            }
            _ => break,
        }
    }
    let raw = node_text(current, source).trim();
    if raw.is_empty() {
        return None;
    }
    Some(TypeRef::Named {
        name: resolve_php_type(raw, ctx).unwrap_or_else(|| raw.to_owned()),
        arguments: Vec::new(),
        nullable,
    })
}

fn unknown_type() -> TypeRef {
    TypeRef::Named {
        name: "mixed".to_owned(),
        arguments: Vec::new(),
        nullable: false,
    }
}

fn declaration_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name")?;
    let text = node_text(name, source).trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn visibility_of(node: Node<'_>, source: &str) -> Visibility {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "visibility_modifier" {
            continue;
        }
        return match node_text(child, source).trim() {
            "private" => Visibility::Private,
            "protected" => Visibility::Protected,
            _ => Visibility::Public,
        };
    }
    Visibility::Public
}

fn has_modifier(node: Node<'_>, source: &str, modifier: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "abstract_modifier" | "final_modifier" | "static_modifier" | "readonly_modifier"
        ) && node_text(child, source).trim() == modifier
    })
}

fn qualify(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_owned()
    } else {
        format!("{namespace}.{name}")
    }
}

fn artifact_locator(
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
    symbol: &str,
) -> Locator {
    Locator::Artifact {
        path: logical_path(origin, artifact_sha256, entry_path),
        symbol: symbol.to_owned(),
    }
}

fn logical_path(
    origin: PhpProjectionOrigin<'_>,
    artifact_sha256: &str,
    entry_path: &str,
) -> String {
    format!("{}+sha256:{artifact_sha256}!/{entry_path}", origin.scheme)
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

/// Whether `path` names a PHP source file.
pub(crate) fn is_php_entry(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("php"))
}

fn finish(
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    notes: Vec<PhpDeclarationNote>,
    diagnostics: BoundedProducerDiagnostics,
    complete: bool,
) -> PhpSourceProjection {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    PhpSourceProjection {
        types,
        members,
        notes,
        diagnostics,
        suppressed_diagnostics,
        complete,
    }
}

/// Every PHP attribute name written directly on `node`, resolved to its
/// qualified identity.
///
/// The grammar stores an attribute block on the declaration's `attributes`
/// field as an `attribute_list` of `attribute_group`s of `attribute`s, and an
/// attribute's own name is its `name` or `qualified_name` child. The read is
/// entirely by node kind and field, never by scanning source text.
///
/// The written name is then resolved through the file's own `use` bindings,
/// exactly as a base-class name is. A declaration-stub tree imports the same
/// attribute plainly in one file and under an alias in another, and a
/// consumer that matched the written spelling would see one of those two and
/// miss the other.
fn declaration_attribute_names(node: Node<'_>, source: &str, ctx: &PhpFileContext) -> Vec<String> {
    let Some(list) = node.child_by_field_name("attributes") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut group_cursor = list.walk();
    for group in list.named_children(&mut group_cursor) {
        if group.kind() != "attribute_group" {
            continue;
        }
        let mut attribute_cursor = group.walk();
        for attribute in group.named_children(&mut attribute_cursor) {
            if attribute.kind() != "attribute" {
                continue;
            }
            let Some(name) = attribute
                .named_child(0)
                .filter(|child| matches!(child.kind(), "name" | "qualified_name"))
            else {
                continue;
            };
            let text = node_text(name, source).trim();
            if !text.is_empty() {
                names
                    .push(resolve_php_type(text, ctx).unwrap_or_else(|| php_namespace_to_fq(text)));
            }
        }
    }
    names
}

/// Record the attributes one declaration node carries against every member it
/// published. A `property_declaration` or `const_declaration` can declare more
/// than one element, and the block's attributes apply to all of them.
fn record_declaration_notes(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    published: &[MemberFact],
    notes: &mut Vec<PhpDeclarationNote>,
) {
    if published.is_empty() {
        return;
    }
    for attribute in declaration_attribute_names(node, source, ctx) {
        for member in published {
            notes.push(PhpDeclarationNote {
                declaration: member.id.clone(),
                marker: PhpDeclarationMarker::Attribute(attribute.clone()),
            });
        }
    }
}

/// Record what one callable states that the projected signature does not
/// model: the attributes it and its parameters carry, and any parameter name
/// it spells more than once.
///
/// A stub tree states a parameter's availability window with a parameter
/// attribute, and spells a version-varying parameter twice, so a callable
/// whose parameter list is version dependent must be reported as read
/// incompletely too.
fn record_callable_notes(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    declaration: &str,
    notes: &mut Vec<PhpDeclarationNote>,
) {
    let mut names = declaration_attribute_names(node, source, ctx);
    let mut seen: Vec<String> = Vec::new();
    if let Some(list) = node.child_by_field_name("parameters") {
        let mut cursor = list.walk();
        for parameter in list.named_children(&mut cursor) {
            names.extend(declaration_attribute_names(parameter, source, ctx));
            let Some(name) = parameter
                .child_by_field_name("name")
                .map(|name| node_text(name, source).trim_start_matches('$').to_owned())
            else {
                continue;
            };
            if seen.contains(&name) {
                notes.push(PhpDeclarationNote {
                    declaration: declaration.to_owned(),
                    marker: PhpDeclarationMarker::DuplicateParameterName(name),
                });
            } else {
                seen.push(name);
            }
        }
    }
    for attribute in names {
        notes.push(PhpDeclarationNote {
            declaration: declaration.to_owned(),
            marker: PhpDeclarationMarker::Attribute(attribute),
        });
    }
}
