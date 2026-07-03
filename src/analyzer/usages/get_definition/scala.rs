use super::*;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;

pub(crate) enum ScalaTypeLookupResolution {
    Type {
        fqn: String,
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

pub(crate) fn scala_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    types: &ScalaProjectTypes,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<ScalaTypeLookupResolution> {
    let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
    let resolver = ScalaNameResolver::for_file(scala, file, types);
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        types,
        file,
        source,
    };
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    scala_type_lookup_node_fqn(ctx, &resolver, root, node)
}

pub(super) fn resolve_scala(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_definition(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("scala_parse_failed", "Scala source could not be parsed");
    };
    let types = context.scala_project_types(scala);
    let support = context.support;
    let resolver = ScalaNameResolver::for_file(scala, file, types.as_ref());
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Scala definition",
                site.text
            ),
        );
    };
    if scala_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Scala reference site", site.text),
        );
    }

    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        types: types.as_ref(),
        file,
        source,
    };

    match scala_reference_node(node) {
        Some(ScalaReferenceNode::Type(type_node)) => {
            resolve_scala_type(ctx, &resolver, root, type_node)
        }
        Some(ScalaReferenceNode::Constructor(constructor)) => {
            resolve_scala_constructor(ctx, &resolver, constructor)
        }
        Some(ScalaReferenceNode::Call(call)) => resolve_scala_call(ctx, &resolver, root, call),
        Some(ScalaReferenceNode::NamedArgument { call, name }) => {
            resolve_scala_named_argument(ctx, &resolver, call, name)
        }
        Some(ScalaReferenceNode::InfixCall(call)) => {
            resolve_scala_infix_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::PostfixCall(call)) => {
            resolve_scala_postfix_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::Field(field)) => resolve_scala_field(ctx, &resolver, root, field),
        Some(ScalaReferenceNode::StableIdentifier(identifier)) => {
            resolve_scala_stable_identifier(ctx, &resolver, root, identifier)
        }
        Some(ScalaReferenceNode::Identifier(identifier)) => {
            let text = scala_node_text(identifier, source).trim();
            if text.is_empty() {
                return no_definition("no_reference_text", "Scala identifier is blank");
            }
            let bindings = scala_bindings_before(ctx, &resolver, root, identifier.start_byte());
            if bindings.is_shadowed(text) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Scala value"),
                );
            }
            if let Some(fqn) = resolver.resolve_member(text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            if let Some(fqn) = resolver.resolve(text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            if scala_import_boundary_for_name(scala, context.support, file, text) {
                return boundary(format!(
                    "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Scala definition"),
            )
        }
        None => no_definition(
            "unsupported_scala_reference_shape",
            format!(
                "`{}` is a Scala `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn scala_type_lookup_node_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<ScalaTypeLookupResolution> {
    if matches!(
        node.kind(),
        "type_identifier" | "stable_type_identifier" | "generic_type"
    ) && scala_is_type_position(node)
    {
        return scala_resolve_visible_type_annotation(
            ctx,
            resolver,
            scala_node_text(node, ctx.source),
        )
        .map(|fqn| ScalaTypeLookupResolution::Type {
            fqn,
            target_kind: TypeLookupTargetKind::TypeReference,
        });
    }

    if matches!(node.kind(), "instance_expression" | "call_expression") {
        return scala_constructed_type(ctx, node, resolver).map(|fqn| {
            ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            }
        });
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "field_expression" && parent.child_by_field_name("object") == Some(node)
        {
            return scala_receiver_type_fqn(ctx, resolver, root, node, node.start_byte()).map(
                |fqn| ScalaTypeLookupResolution::Type {
                    fqn,
                    target_kind: TypeLookupTargetKind::ValueExpression,
                },
            );
        }
        if scala_is_callable_declaration_name(parent, node) {
            return Some(ScalaTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(fqn) = scala_declaration_name_type_fqn(ctx, resolver, root, parent, node) {
            return Some(ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
    }

    if !matches!(
        node.kind(),
        "identifier" | "operator_identifier" | "type_identifier"
    ) {
        return None;
    }

    let name = scala_node_text(node, ctx.source).trim();
    let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
    first_precise(&bindings, name).map(|fqn| ScalaTypeLookupResolution::Type {
        fqn,
        target_kind: TypeLookupTargetKind::ValueExpression,
    })
}

fn scala_declaration_name_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<String> {
    match parent.kind() {
        "parameter" | "class_parameter" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    scala_node_text(type_node, ctx.source),
                )
            })
        }
        "val_definition" | "var_definition"
            if parent
                .child_by_field_name("pattern")
                .is_some_and(|pattern| {
                    pattern.start_byte() <= name.start_byte()
                        && name.end_byte() <= pattern.end_byte()
                }) =>
        {
            parent.child_by_field_name("type").and_then(|type_node| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    scala_node_text(type_node, ctx.source),
                )
            })
        }
        "function_definition" if parent.child_by_field_name("name") == Some(name) => parent
            .child_by_field_name("return_type")
            .and_then(|type_node| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    scala_node_text(type_node, ctx.source),
                )
            }),
        _ => {
            let name_text = scala_node_text(name, ctx.source).trim();
            let bindings = scala_bindings_before(ctx, resolver, root, name.end_byte());
            first_precise(&bindings, name_text)
        }
    }
}

fn scala_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(parent.kind(), "function_definition")
}

pub(super) fn parse_scala_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum ScalaReferenceNode<'tree> {
    Type(Node<'tree>),
    Constructor(Node<'tree>),
    Call(Node<'tree>),
    InfixCall(Node<'tree>),
    PostfixCall(Node<'tree>),
    Field(Node<'tree>),
    StableIdentifier(Node<'tree>),
    Identifier(Node<'tree>),
    /// A named argument `name = value` in a call `Callee(name = ..)`: `name`
    /// resolves to the callee type's member/parameter, not a name in scope.
    NamedArgument {
        call: Node<'tree>,
        name: Node<'tree>,
    },
}

/// A named-argument identifier (`a` in `Foo(a = 3)`): the LHS of an
/// `assignment_expression` directly inside a call's `arguments`.
fn scala_named_argument(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    if node.kind() != "identifier" {
        return None;
    }
    let assignment = node
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")?;
    let is_lhs = assignment
        .child_by_field_name("left")
        .or_else(|| assignment.named_child(0))
        == Some(node);
    if !is_lhs {
        return None;
    }
    let arguments = assignment
        .parent()
        .filter(|parent| parent.kind() == "arguments")?;
    let call = arguments
        .parent()
        .filter(|parent| parent.kind() == "call_expression")?;
    Some(ScalaReferenceNode::NamedArgument { call, name: node })
}

fn scala_reference_node(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    if let Some(named) = scala_named_argument(node) {
        return Some(named);
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "infix_expression"
            && parent.child_by_field_name("operator") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "postfix_expression"
            && scala_postfix_method_node(parent) == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "instance_expression"
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte()
        {
            current = parent;
            continue;
        }
        if parent.kind() == "stable_identifier" {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "call_expression" => Some(ScalaReferenceNode::Call(current)),
        "infix_expression" => Some(ScalaReferenceNode::InfixCall(current)),
        "postfix_expression" => Some(ScalaReferenceNode::PostfixCall(current)),
        "instance_expression" => Some(ScalaReferenceNode::Constructor(current)),
        "field_expression" => Some(ScalaReferenceNode::Field(current)),
        "stable_identifier" => Some(ScalaReferenceNode::StableIdentifier(current)),
        "type_identifier" | "stable_type_identifier" | "generic_type" => {
            Some(ScalaReferenceNode::Type(current))
        }
        "identifier" | "operator_identifier" => Some(ScalaReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn scala_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "function_definition"
                | "parameter"
                | "val_definition"
                | "var_definition"
        )
}

fn scala_is_type_position(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.child_by_field_name("type") == Some(current)
            || parent.child_by_field_name("return_type") == Some(current)
        {
            return true;
        }
        if matches!(parent.kind(), "generic_type" | "stable_type_identifier") {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

#[derive(Clone, Copy)]
struct ScalaLookupCtx<'a> {
    scala: &'a ScalaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    types: &'a ScalaProjectTypes,
    file: &'a ProjectFile,
    source: &'a str,
}

fn resolve_scala_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = scala_node_text(node, ctx.source).trim();
    if text.is_empty() {
        return no_definition("no_reference_text", "Scala type reference is blank");
    }
    if !scala_is_type_position(node) {
        let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
        if bindings.is_shadowed(text) {
            return no_definition(
                "local_variable_reference",
                format!("`{text}` is a local Scala value"),
            );
        }
    }
    if let Some(fqn) = resolver.resolve(text) {
        return scala_fqn_outcome(ctx.support, &fqn, text);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, scala_simple_name(text)) {
        return boundary(format!(
            "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala type"),
    )
}

/// Resolve a named argument (`Foo(a = 3)`, caret on `a`) to the callee type's
/// member `a` — case-class parameters are members (`Foo.a`).
fn resolve_scala_named_argument(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    call: Node<'_>,
    name_node: Node<'_>,
) -> DefinitionLookupOutcome {
    let arg_name = scala_node_text(name_node, ctx.source).trim();
    if arg_name.is_empty() {
        return no_definition("no_reference_text", "Scala named argument is blank");
    }
    let owner_fqn = call
        .child_by_field_name("function")
        .filter(|function| matches!(function.kind(), "identifier" | "type_identifier"))
        .map(|function| scala_node_text(function, ctx.source).trim())
        .filter(|callee| !callee.is_empty())
        .and_then(|callee| resolver.resolve(callee));
    let Some(owner_fqn) = owner_fqn else {
        return no_definition(
            "no_indexed_definition",
            format!("named argument `{arg_name}` receiver could not be typed"),
        );
    };
    let candidates = scala_member_candidate_units(ctx, &owner_fqn, arg_name, false);
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("named argument `{arg_name}` is not a member of `{owner_fqn}`"),
        );
    }
    candidates_outcome(candidates)
}

fn resolve_scala_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "Scala call expression has no function");
    };
    match function.kind() {
        "instance_expression" => resolve_scala_constructor(ctx, resolver, function),
        "field_expression" => resolve_scala_field(ctx, resolver, root, function),
        "identifier" | "type_identifier" => {
            let name = scala_node_text(function, ctx.source).trim();
            if name.is_empty() {
                return no_definition("no_function_name", "Scala call name is blank");
            }
            let bindings = scala_bindings_before(ctx, resolver, root, function.start_byte());
            if bindings.is_shadowed(name) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local Scala value"),
                );
            }
            if let Some(fqn) = resolver.resolve_member(name) {
                return scala_fqn_outcome(ctx.support, &fqn, name);
            }
            if function.kind() == "identifier"
                && let Some(owner) =
                    scala_enclosing_class(ctx.analyzer, ctx.file, function.start_byte())
                && owner.identifier() != name
            {
                let mut candidates =
                    scala_member_candidate_units(ctx, &owner.fq_name(), name, false);
                if candidates.is_empty() {
                    candidates = scala_source_ancestor_member_units(ctx, resolver, function, name);
                }
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if let Some(owner_fqn) = resolver.resolve(name) {
                // A call `Foo(..)` resolves to the companion object's `apply` when
                // one exists. `name` may resolve to the class `Foo` or the companion
                // object `Foo$` — they share a simple name, so `resolve` picks one
                // arbitrarily — so reconstruct the companion object fqn (`Foo$`) and
                // prefer its `apply` deterministically, regardless of which resolved.
                let companion_base = owner_fqn.trim_end_matches('$');
                let mut apply_candidates = ctx.support.fqn(&format!("{companion_base}$.apply"));
                if apply_candidates.is_empty() {
                    apply_candidates = ctx.support.fqn(&format!("{owner_fqn}.apply"));
                }
                if !apply_candidates.is_empty() {
                    return candidates_outcome(apply_candidates);
                }
                return scala_fqn_outcome(ctx.support, &owner_fqn, name);
            }
            if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, name) {
                return boundary(format!(
                    "`{name}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed Scala callable"),
            )
        }
        _ => no_definition(
            "unsupported_scala_reference_shape",
            format!(
                "Scala `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn resolve_scala_infix_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(operator) = call.child_by_field_name("operator") else {
        return no_definition("no_function_name", "Scala infix expression has no operator");
    };
    let Some(receiver) = call.child_by_field_name("left") else {
        return no_definition(
            "unsupported_scala_receiver",
            "Scala infix expression has no receiver",
        );
    };
    let name = scala_node_text(operator, ctx.source).trim();
    if name.is_empty() {
        return no_definition("no_function_name", "Scala infix operator is blank");
    }
    if let Some(owner) =
        scala_receiver_type_fqn(ctx, resolver, root, receiver, operator.start_byte())
    {
        let candidates = scala_member_candidate_units(ctx, &owner, name, false);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(ctx, resolver, name, Some(&owner));
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, name, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        "unsupported_scala_receiver",
        format!("receiver for Scala infix member `{name}` is not resolved"),
    )
}

fn resolve_scala_postfix_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(method) = scala_postfix_method_node(call) else {
        return no_definition("no_function_name", "Scala postfix expression has no method");
    };
    let Some(receiver) = scala_postfix_receiver_node(call, method) else {
        return no_definition(
            "unsupported_scala_receiver",
            "Scala postfix expression has no receiver",
        );
    };
    let name = scala_node_text(method, ctx.source).trim();
    if name.is_empty() {
        return no_definition("no_function_name", "Scala postfix method is blank");
    }
    if let Some(owner) = scala_receiver_type_fqn(ctx, resolver, root, receiver, method.start_byte())
    {
        let candidates = scala_member_candidate_units(ctx, &owner, name, false);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(ctx, resolver, name, Some(&owner));
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, name, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        "unsupported_scala_receiver",
        format!("receiver for Scala postfix member `{name}` is not resolved"),
    )
}

pub(super) fn scala_postfix_method_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut method = None;
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "operator_identifier") {
            method = Some(child);
        }
    }
    method
}

fn scala_postfix_receiver_node<'tree>(
    node: Node<'tree>,
    method: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.end_byte() <= method.start_byte())
}

fn resolve_scala_constructor(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    constructor: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(owner_fqn) = scala_constructed_type(ctx, constructor, resolver) else {
        return no_definition(
            "no_indexed_definition",
            "Scala constructor call did not resolve to an indexed type",
        );
    };
    let member = scala_constructor_member_name(&owner_fqn);
    let candidates = ctx.support.fqn(&format!("{owner_fqn}.{member}"));
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    scala_fqn_outcome(ctx.support, &owner_fqn, member)
}

fn scala_constructor_member_name(owner_fqn: &str) -> &str {
    owner_fqn
        .trim_end_matches('$')
        .rsplit('.')
        .next()
        .unwrap_or(owner_fqn)
}

fn resolve_scala_field(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    field: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = field.child_by_field_name("field") else {
        return no_definition(
            "no_member_name",
            "Scala field expression has no member name",
        );
    };
    let member = scala_node_text(field_node, ctx.source).trim();
    let Some(receiver) = field.child_by_field_name("value") else {
        return no_definition(
            "no_member_receiver",
            "Scala field expression has no receiver",
        );
    };
    if let Some(owner) = scala_receiver_type_fqn(ctx, resolver, root, receiver, field.start_byte())
    {
        let include_companion = scala_receiver_allows_companion_lookup(
            ctx,
            resolver,
            root,
            receiver,
            field.start_byte(),
            &owner,
        );
        let candidates = scala_member_candidate_units(ctx, &owner, member, include_companion);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(ctx, resolver, member, Some(&owner));
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, member, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        "unsupported_scala_receiver",
        format!("receiver for Scala member `{member}` is not resolved"),
    )
}

fn scala_receiver_allows_companion_lookup(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
    owner_fqn: &str,
) -> bool {
    if !matches!(receiver.kind(), "identifier" | "type_identifier") {
        return false;
    }
    let name = scala_node_text(receiver, ctx.source).trim();
    if name == "this" {
        return false;
    }
    let bindings = scala_bindings_before(ctx, resolver, root, cutoff_start);
    if first_precise(&bindings, name).is_some()
        || bindings.is_shadowed(name)
        || scala_enclosing_class_parameter_type(ctx, receiver, name, resolver).is_some()
    {
        return false;
    }
    resolver
        .resolve(name)
        .is_some_and(|resolved| resolved == owner_fqn)
}

fn resolve_scala_stable_identifier(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    identifier: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = scala_node_text(identifier, ctx.source).trim();
    let Some((owner_text, member)) = text.rsplit_once('.') else {
        return resolve_scala_type(ctx, resolver, root, identifier);
    };
    if owner_text.is_empty() || member.is_empty() {
        return no_definition("no_reference_text", "Scala stable identifier is blank");
    }
    let bindings = scala_bindings_before(ctx, resolver, root, identifier.start_byte());
    let owner = first_precise(&bindings, owner_text).or_else(|| {
        (!bindings.is_shadowed(owner_text))
            .then(|| resolver.resolve(owner_text))
            .flatten()
    });
    if let Some(owner) = owner {
        return scala_member_candidates(ctx, &owner, member, true);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, owner_text) {
        return boundary(format!(
            "`{owner_text}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala definition"),
    )
}

fn scala_member_candidates(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
) -> DefinitionLookupOutcome {
    let candidates = scala_member_candidate_units(ctx, owner_fqn, member, include_companion);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }

    scala_member_not_found(ctx, owner_fqn, member)
}

fn scala_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
) -> Vec<CodeUnit> {
    let mut seen_owner_fqns = HashSet::default();
    scala_member_candidate_units_with_seen(
        ctx,
        owner_fqn,
        member,
        include_companion,
        &mut seen_owner_fqns,
    )
}

fn scala_extension_candidates(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    member: &str,
    receiver_owner: Option<&str>,
) -> DefinitionLookupOutcome {
    let candidates = scala_extension_candidate_units(ctx, resolver, member, receiver_owner);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    no_definition(
        "unsupported_scala_receiver",
        format!("receiver for Scala extension member `{member}` is not resolved"),
    )
}

fn scala_extension_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    member: &str,
    receiver_owner: Option<&str>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for method in resolver.visible_extension_methods(member) {
        if !scala_extension_receiver_matches(
            resolver,
            method.receiver_type.as_deref(),
            receiver_owner,
        ) {
            continue;
        }
        candidates.extend(ctx.support.fqn(&method.fqn));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.len() == 1 {
        candidates
    } else {
        Vec::new()
    }
}

fn scala_extension_receiver_matches(
    resolver: &ScalaNameResolver,
    extension_receiver_type: Option<&str>,
    receiver_owner: Option<&str>,
) -> bool {
    let (Some(receiver_owner), Some(extension_receiver_type)) =
        (receiver_owner, extension_receiver_type)
    else {
        return true;
    };
    resolver
        .resolve(extension_receiver_type)
        .is_none_or(|extension_receiver| extension_receiver == receiver_owner)
}

fn scala_member_candidate_units_with_seen(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
    seen_owner_fqns: &mut HashSet<String>,
) -> Vec<CodeUnit> {
    if !seen_owner_fqns.insert(owner_fqn.to_string()) {
        return Vec::new();
    }

    let mut candidates = ctx.support.fqn(&format!("{owner_fqn}.{member}"));
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        return candidates;
    }

    if include_companion && !owner_fqn.ends_with('$') {
        let mut object_candidates = ctx.support.fqn(&format!("{owner_fqn}$.{member}"));
        sort_units(&mut object_candidates);
        object_candidates.dedup();
        if !object_candidates.is_empty() {
            return object_candidates;
        }
    }

    if let Some(owner) = ctx.analyzer.definitions(owner_fqn).next().cloned()
        && let Some(provider) = ctx.analyzer.type_hierarchy_provider()
    {
        let mut seen = HashSet::default();
        let mut level = provider.get_direct_ancestors(&owner);
        seen.insert(owner);
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates
                    .extend(ctx.support.fqn(&format!("{}.{member}", ancestor.fq_name())));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            if !level_candidates.is_empty() {
                return level_candidates;
            }
            level = next_level;
        }
    }

    scala_owner_source_ancestor_member_units(ctx, owner_fqn, member, seen_owner_fqns)
}

fn scala_owner_source_ancestor_member_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    seen_owner_fqns: &mut HashSet<String>,
) -> Vec<CodeUnit> {
    for owner in ctx
        .analyzer
        .definitions(owner_fqn)
        .filter(|unit| unit.is_class())
    {
        let Some(source) = ctx.analyzer.get_source(owner, false) else {
            continue;
        };
        let Some(tree) = parse_scala_tree(&source) else {
            continue;
        };
        let Some(owner_node) = scala_find_type_declaration_node_for_unit(
            ctx.analyzer,
            tree.root_node(),
            &source,
            owner,
        ) else {
            continue;
        };

        let mut ancestor_types = Vec::new();
        scala_collect_extends_type_text(owner_node, &source, &mut ancestor_types);
        if ancestor_types.is_empty() {
            continue;
        }

        let owner_resolver = ScalaNameResolver::for_file(ctx.scala, owner.source(), ctx.types);
        for ancestor_type in ancestor_types {
            let Some(ancestor_fqn) = owner_resolver.resolve(&ancestor_type) else {
                continue;
            };
            let candidates = scala_member_candidate_units_with_seen(
                ctx,
                &ancestor_fqn,
                member,
                false,
                seen_owner_fqns,
            );
            if !candidates.is_empty() {
                return candidates;
            }
        }
    }

    Vec::new()
}

fn scala_find_type_declaration_node_for_unit<'tree>(
    analyzer: &dyn IAnalyzer,
    root: Node<'tree>,
    source: &str,
    owner: &CodeUnit,
) -> Option<Node<'tree>> {
    let ranges = analyzer.ranges(owner);
    let owner_path = scala_owner_relative_type_path(owner);
    scala_find_type_declaration_node(
        root,
        source,
        owner.identifier(),
        ranges,
        &owner_path,
        &mut Vec::new(),
    )
}

fn scala_find_type_declaration_node<'tree>(
    node: Node<'tree>,
    source: &str,
    owner_identifier: &str,
    ranges: &[Range],
    owner_path: &[String],
    current_path: &mut Vec<String>,
) -> Option<Node<'tree>> {
    let is_type = matches!(
        node.kind(),
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
    );
    if is_type && let Some(name_node) = node.child_by_field_name("name") {
        let name = scala_node_text(name_node, source).trim();
        let path_name = if node.kind() == "object_definition" {
            format!("{name}$")
        } else {
            name.to_string()
        };
        current_path.push(path_name);
        let name_matches = name == owner_identifier || format!("{name}$") == owner_identifier;
        let path_matches = current_path == owner_path;
        let range_matches = ranges.iter().any(|range| {
            let start_line = node.start_position().row + 1;
            range.start_line <= start_line && start_line <= range.end_line
        });
        if name_matches && (path_matches || range_matches) {
            return Some(node);
        }
    }

    let mut cursor = node.walk();
    let found = node.named_children(&mut cursor).find_map(|child| {
        scala_find_type_declaration_node(
            child,
            source,
            owner_identifier,
            ranges,
            owner_path,
            current_path,
        )
    });
    if is_type {
        current_path.pop();
    }
    found
}

fn scala_owner_relative_type_path(owner: &CodeUnit) -> Vec<String> {
    let fqn = owner.fq_name();
    let package = owner.package_name();
    let relative = fqn
        .strip_prefix(package)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(fqn.as_str());
    relative
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn scala_source_ancestor_member_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    member: &str,
) -> Vec<CodeUnit> {
    let Some(owner_node) = scala_enclosing_definition_node(node) else {
        return Vec::new();
    };
    let mut ancestor_types = Vec::new();
    scala_collect_extends_type_text(owner_node, ctx.source, &mut ancestor_types);
    for ancestor_type in ancestor_types {
        let Some(owner_fqn) = resolver.resolve(&ancestor_type) else {
            continue;
        };
        let candidates = scala_member_candidate_units(ctx, &owner_fqn, member, false);
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

fn scala_enclosing_definition_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn scala_collect_extends_type_text(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    scala_collect_extends_type_text_inner(node, source, out, true);
}

fn scala_collect_extends_type_text_inner(
    node: Node<'_>,
    source: &str,
    out: &mut Vec<String>,
    is_root: bool,
) {
    if !is_root
        && matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        )
    {
        return;
    }
    let in_extends = node.kind() == "extends_clause";
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if in_extends
            && matches!(
                child.kind(),
                "type_identifier" | "stable_type_identifier" | "generic_type"
            )
        {
            let text = scala_node_text(child, source).trim();
            if !text.is_empty() {
                out.push(text.to_string());
            }
            continue;
        }
        scala_collect_extends_type_text_inner(child, source, out, false);
    }
}

fn scala_member_not_found(
    _ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    no_definition(
        "unsupported_scala_receiver",
        format!(
            "receiver for Scala member `{member}` resolved to `{owner_fqn}`, but `{owner_fqn}.{member}` was not indexed"
        ),
    )
}

fn scala_receiver_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
) -> Option<String> {
    match receiver.kind() {
        "identifier" | "type_identifier" => {
            let name = scala_node_text(receiver, ctx.source).trim();
            if name == "this" {
                return ClassRangeIndex::build(ctx.analyzer, ctx.file)
                    .enclosing(receiver.start_byte())
                    .map(str::to_string);
            }
            let bindings = scala_bindings_before(ctx, resolver, root, cutoff_start);
            first_precise(&bindings, name).or_else(|| {
                scala_enclosing_class_parameter_type(ctx, receiver, name, resolver).or_else(|| {
                    if !bindings.is_shadowed(name)
                        && let Some(imported_member) = resolver.resolve_member(name)
                        && let Some(return_type) =
                            scala_imported_member_return_type(ctx, resolver, &imported_member)
                    {
                        return Some(return_type);
                    }
                    (!bindings.is_shadowed(name))
                        .then(|| resolver.resolve(name))
                        .flatten()
                })
            })
        }
        // `new Foo().member` — the receiver is typed by the constructed class.
        "instance_expression" => {
            let name = scala_first_type_name(receiver, ctx.source)?;
            resolver.resolve(name)
        }
        _ => None,
    }
}

fn scala_imported_member_return_type(
    ctx: ScalaLookupCtx<'_>,
    _resolver: &ScalaNameResolver,
    member_fqn: &str,
) -> Option<String> {
    let unit = ctx
        .support
        .fqn(member_fqn)
        .into_iter()
        .find(|unit| unit.is_function())?;
    let signature = unit
        .signature()
        .or_else(|| ctx.scala.signatures(&unit).first().map(String::as_str))?;
    let return_type = scala_signature_return_type(signature)?;
    let factory_resolver = ScalaNameResolver::for_file(ctx.scala, unit.source(), ctx.types);
    scala_resolve_type_annotation(&factory_resolver, return_type).or_else(|| {
        scala_package_type_fqn(unit.package_name(), return_type)
            .filter(|fqn| !ctx.support.fqn(fqn).is_empty())
    })
}

fn scala_signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

/// The first `type_identifier` (else `identifier`) in a pre-order walk — the
/// constructed type of a `new Foo(...)` instance expression.
fn scala_first_type_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut fallback = None;
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_identifier" => return Some(scala_node_text(node, source).trim()),
            "identifier" if fallback.is_none() => {
                fallback = Some(scala_node_text(node, source).trim());
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    fallback
}

fn scala_enclosing_class_parameter_type(
    ctx: ScalaLookupCtx<'_>,
    node: Node<'_>,
    name: &str,
    resolver: &ScalaNameResolver,
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            let parameters = parent.child_by_field_name("class_parameters")?;
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                    continue;
                }
                let Some(param_name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                if scala_node_text(param_name, ctx.source).trim() != name {
                    continue;
                }
                if scala_active_path_declares_name_after(
                    parent,
                    ctx.source,
                    name,
                    parameter.end_byte(),
                    node.start_byte(),
                ) {
                    return None;
                }
                return parameter.child_by_field_name("type").and_then(|type_node| {
                    let type_text = scala_node_text(type_node, ctx.source);
                    scala_resolve_visible_type_annotation(ctx, resolver, type_text)
                });
            }
            return None;
        }
        current = parent.parent();
    }
    None
}

fn scala_active_path_declares_name_after(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    if target_byte < node.start_byte() || node.end_byte() <= target_byte {
        return false;
    }

    let mut containing_child = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= target_byte && target_byte < child.end_byte() {
            containing_child = Some(child);
        }
        if child.start_byte() >= target_byte || child.end_byte() <= lower_bound {
            continue;
        }
        if scala_node_declares_name_before(child, source, name, lower_bound, target_byte) {
            return true;
        }
    }

    containing_child.is_some_and(|child| {
        scala_active_path_declares_name_after(child, source, name, lower_bound, target_byte)
    })
}

fn scala_node_declares_name_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    match node.kind() {
        "parameter" | "class_parameter" => {
            node.child_by_field_name("name").is_some_and(|name_node| {
                lower_bound <= name_node.start_byte()
                    && name_node.start_byte() < target_byte
                    && scala_node_text(name_node, source).trim() == name
            })
        }
        "parameters" | "class_parameters" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).any(|child| {
                scala_node_declares_name_before(child, source, name, lower_bound, target_byte)
            })
        }
        "val_definition" | "var_definition" => {
            if node.start_byte() >= target_byte {
                return false;
            }
            node.child_by_field_name("pattern").is_some_and(|pattern| {
                lower_bound <= pattern.start_byte()
                    && scala_pattern_names(pattern, source).contains(&name)
            })
        }
        "function_definition" => node.child_by_field_name("name").is_some_and(|name_node| {
            lower_bound <= name_node.start_byte()
                && name_node.start_byte() < target_byte
                && scala_node_text(name_node, source).trim() == name
        }),
        _ => false,
    }
}

fn scala_existing_package_type_fqn(
    analyzer: &dyn IAnalyzer,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let fqn = scala_package_type_fqn(package, type_text)?;
    let exists = analyzer.definitions(&fqn).any(|unit| unit.is_class());
    exists.then_some(fqn)
}

fn scala_package_type_fqn(package: &str, type_text: &str) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    if package.is_empty() {
        Some(simple.to_string())
    } else {
        Some(format!("{package}.{simple}"))
    }
}

fn scala_resolve_type_annotation(resolver: &ScalaNameResolver, type_text: &str) -> Option<String> {
    let trimmed = type_text.trim();
    if let Some(base_type) = trimmed.strip_suffix(".type") {
        return resolver.resolve(base_type).map(|fqn| {
            if fqn.ends_with('$') {
                fqn
            } else {
                format!("{fqn}$")
            }
        });
    }
    let fqn = resolver
        .resolve(type_text)
        .or_else(|| scala_type_base_text(trimmed).and_then(|base| resolver.resolve(base)))?;
    Some(fqn.trim_end_matches('$').to_string())
}

fn scala_resolve_visible_type_annotation(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    type_text: &str,
) -> Option<String> {
    if type_text.trim().ends_with(".type") {
        return scala_resolve_type_annotation(resolver, type_text);
    }
    let current_package = scala_package_name_of(ctx.scala, ctx.file).unwrap_or_default();
    let resolved = scala_resolve_type_annotation(resolver, type_text);
    if resolved.as_deref().is_some_and(|fqn| {
        scala_fqn_package(fqn) != current_package
            && scala_type_annotation_imported(ctx, type_text, fqn)
    }) {
        return resolved;
    }
    if scala_type_annotation_has_explicit_import(ctx, type_text) {
        return None;
    }
    scala_package_name_of(ctx.scala, ctx.file)
        .and_then(|package| scala_existing_package_type_fqn(ctx.analyzer, &package, type_text))
        .or(resolved)
}

fn scala_type_annotation_has_explicit_import(ctx: ScalaLookupCtx<'_>, type_text: &str) -> bool {
    let simple = scala_simple_name(type_text);
    ctx.scala.import_info_of(ctx.file).iter().any(|import| {
        if import.is_wildcard {
            return false;
        }
        let Some(path) = scala_import_path(import) else {
            return false;
        };
        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        local_name == simple
    })
}

fn scala_type_annotation_imported(
    ctx: ScalaLookupCtx<'_>,
    type_text: &str,
    resolved_fqn: &str,
) -> bool {
    let simple = scala_simple_name(type_text);
    let resolved_package = scala_fqn_package(resolved_fqn);
    ctx.scala.import_info_of(ctx.file).iter().any(|import| {
        let Some(path) = scala_import_path(import) else {
            return false;
        };
        if import.is_wildcard {
            return path == resolved_package;
        }
        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        local_name == simple
    })
}

fn scala_fqn_package(fqn: &str) -> &str {
    fqn.trim_end_matches('$')
        .rsplit_once('.')
        .map(|(package, _)| package)
        .unwrap_or("")
}

fn scala_type_base_text(type_text: &str) -> Option<&str> {
    let base = type_text
        .split(['[', '<'])
        .next()
        .unwrap_or(type_text)
        .trim();
    (!base.is_empty() && base != type_text.trim()).then_some(base)
}

fn scala_fqn_outcome(
    support: &DefinitionLookupIndex,
    fqn: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let candidates = support.fqn(fqn);
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("`{reference}` resolved to `{fqn}`, but no indexed definition was found"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn scala_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    analyzer.definitions(&fqn).next().cloned()
}

const SCALA_SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
];

fn scala_bindings_before(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    scala_seed_active_path(ctx, resolver, root, cutoff_start, &mut bindings);
    bindings
}

fn scala_seed_active_path(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
        }
        match node.kind() {
            "class_definition" | "function_definition" => {
                scala_seed_parameters(ctx, resolver, node, cutoff_start, bindings)
            }
            "val_definition" | "var_definition" if node.start_byte() < cutoff_start => {
                scala_seed_value_definition(ctx, resolver, node, cutoff_start, bindings)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < cutoff_start)
            .collect();
        children.reverse();
        stack.extend(children);
    }
}

fn scala_seed_parameters(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !matches!(child.kind(), "parameters" | "class_parameters")
            || child.start_byte() >= cutoff_start
        {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if matches!(parameter.kind(), "parameter" | "class_parameter")
                && parameter.start_byte() < cutoff_start
            {
                scala_seed_parameter(ctx, resolver, parameter, cutoff_start, bindings);
            }
        }
    }
}

fn scala_seed_parameter(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    parameter: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    if name.start_byte() >= cutoff_start {
        return;
    }
    let binding_name = scala_node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    let resolved = parameter
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            let type_text = scala_node_text(type_node, ctx.source);
            scala_resolve_visible_type_annotation(ctx, resolver, type_text)
        });
    scala_seed_typed(binding_name, resolved, bindings);
}

fn scala_seed_value_definition(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let resolved = node
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            scala_resolve_visible_type_annotation(
                ctx,
                resolver,
                scala_node_text(type_node, ctx.source),
            )
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start)
                .and_then(|value| scala_constructed_type(ctx, value, resolver))
                .or_else(|| {
                    scala_constructor_type_text(scala_node_text(node, ctx.source)).and_then(
                        |type_text| scala_resolve_visible_type_annotation(ctx, resolver, type_text),
                    )
                })
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    if pattern.start_byte() >= cutoff_start {
        return;
    }
    for name in scala_pattern_names(pattern, ctx.source) {
        scala_seed_typed(name, resolved.clone(), bindings);
    }
}

fn scala_constructed_type(
    ctx: ScalaLookupCtx<'_>,
    node: Node<'_>,
    resolver: &ScalaNameResolver,
) -> Option<String> {
    if node.kind() == "call_expression"
        && let Some(function) = node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
    {
        return scala_constructed_type(ctx, function, resolver);
    }
    if !matches!(
        node.kind(),
        "instance_expression" | "generic_type" | "type_identifier" | "identifier"
    ) {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "type_identifier" || child.kind() == "generic_type")
        .or_else(|| {
            matches!(
                node.kind(),
                "type_identifier" | "generic_type" | "identifier"
            )
            .then_some(node)
        })
        .and_then(|type_node| {
            scala_resolve_visible_type_annotation(
                ctx,
                resolver,
                scala_node_text(type_node, ctx.source),
            )
        })
}

fn scala_constructor_type_text(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let value = if let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    {
        after_keyword.split_once('=')?.1.trim_start()
    } else {
        trimmed
    };
    let value = value.strip_prefix("new ").unwrap_or(value).trim_start();
    let end = value
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(value.len());
    if end == 0 {
        return None;
    }
    let type_text = &value[..end];
    let simple_name = type_text.rsplit('.').next().unwrap_or(type_text);
    simple_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
        .then_some(type_text)
}

fn scala_pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            let name = scala_node_text(node, source).trim();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
        _ => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(scala_pattern_names(child, source));
            }
            names
        }
    }
}

fn scala_seed_typed(
    name: &str,
    resolved: Option<String>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn scala_import_boundary_for_name(
    scala: &ScalaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
) -> bool {
    let simple = scala_simple_name(name);
    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(import) else {
            continue;
        };
        if import.is_wildcard {
            if simple.chars().next().is_some_and(char::is_uppercase)
                && !scala_workspace_package_exists(support, &path)
            {
                return true;
            }
            continue;
        }
        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name == simple && supportless_scala_import_target_missing(support, &path) {
            return true;
        }
    }
    false
}

fn supportless_scala_import_target_missing(support: &DefinitionLookupIndex, path: &str) -> bool {
    let normalized = path.replace("$.", ".").trim_end_matches('$').to_string();
    !support.fqn_exists(&normalized) && !support.normalized_fqn_exists(&normalized)
}

fn scala_workspace_package_exists(support: &DefinitionLookupIndex, package: &str) -> bool {
    support.package_exists(package)
}

fn scala_simple_name(name: &str) -> &str {
    name.split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .unwrap_or(name)
        .trim()
}
