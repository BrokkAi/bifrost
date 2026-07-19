use super::inverted::{
    BareMemberResolution, FieldResolution, MemberReturnResolution, NameResolver, ProjectTypes,
    TypeApplicationResolution, TypeApplicationRole,
};
use super::method_call_arity_applies;
use crate::analyzer::scala::imports::scala_import_infos_from_node;
use crate::analyzer::scala::{scala_supertype_lookup_nodes, scala_type_lookup_segments};
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::scala_graph::hits::{
    add_hit, add_import_hit, add_override_declaration_hit,
};
use crate::analyzer::usages::scala_graph::local::{
    ScalaLocalBinding, precise_scala_binding, seed_scala_binding,
};
use crate::analyzer::usages::scala_graph::namespace::{
    ScalaTypeNamespaceResolution, scala_qualified_type_root, scala_type_reference_is_singleton,
    scala_unindexed_type_binding_shadows,
};
use crate::analyzer::usages::scala_graph::resolver::{
    TargetKind, TargetSpec, Visibility, method_signature_arity, package_name_of,
    scala_builtin_type_name, scala_extension_receiver_matches_resolved, scala_literal_type_name,
    scala_normalized_fq_name, scala_resolve_declared_type,
};
use crate::analyzer::usages::scala_graph::syntax::{
    ScalaCallSiteShape, ScalaCallableParameterList, ScalaCallableRole, ScalaCallableSiteRole,
    ScalaCallableUsePolicy, ScalaImportContextIndex, ScalaMethodValueContext,
    ScalaPackageContextIndex, ScalaQualifiedStableTypeRole, applied_expression_for_reference,
    call_arities_for_reference, call_site_shape_for_reference, enclosing_template_declarations,
    has_ancestor_kind, has_member_qualifier, infix_receiver_for_operator,
    is_bare_companion_method_value_reference, is_call_function_reference,
    is_constructor_like_reference, is_declaration_name, is_extractor_reference, is_identifier_node,
    is_infix_pattern_operator, is_owner_qualified_this, is_scala_case_pattern_binder,
    is_scala_class_reference, is_scala_object_reference, is_terminal_stable_field_reference,
    member_qualifier, member_qualifier_node, named_argument_invocation_owner, node_text,
    parenthesized_arity, qualified_stable_type_reference, resolve_stable_object_expression,
    scala_callable_alternative_is_candidate, scala_callable_alternative_matches,
    scala_callable_shape_matches, scala_pattern_binder_names, scala_union_type_alternative_paths,
    stable_identifier_reference, template_direct_term_member_named, template_self_type,
    terminal_invocation_owner_name,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile, Range, ScalaAnalyzer,
    TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Node, Parser};

pub(super) fn scan_file(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
    max_usages: usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded {
        return;
    }
    let Some(source) = analyzer.indexed_source(file) else {
        return;
    };
    if source.is_empty() {
        return;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);
    let types = scala.project_types();
    let file_package = package_name_of(scala, file).unwrap_or_default();
    let imports = scala.import_info_of(file);
    let import_contexts = ScalaImportContextIndex::new(&imports, tree.root_node().end_byte());
    let package_contexts = ScalaPackageContextIndex::new(tree.root_node(), &source);
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    let name_resolver = Arc::new(NameResolver::for_file_with_facts(
        scala,
        Some(file),
        Some(&file_package),
        &[],
        &types,
    ));
    let visibility = Arc::new(Visibility::for_file_with_imports(
        scala,
        file,
        &file_package,
        spec,
        &name_resolver,
        &[],
    ));
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut ctx = ScanCtx {
        scala,
        analyzer,
        file,
        active_package: file_package,
        source: &source,
        line_starts: &line_starts,
        spec,
        types,
        name_resolver,
        visibility,
        imports,
        import_contexts,
        import_context_cursor: 0,
        package_contexts,
        class_ranges,
        package_context_cursor: 0,
        active_resolver_key: None,
        resolver_contexts: HashMap::default(),
        bindings: &mut bindings,
        hits,
        max_usages,
        limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_tree(tree.root_node(), &mut ctx);
}

pub(super) struct ScanCtx<'a> {
    pub(super) scala: &'a ScalaAnalyzer,
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) active_package: String,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) types: Arc<ProjectTypes>,
    pub(super) name_resolver: Arc<NameResolver>,
    pub(super) visibility: Arc<Visibility>,
    imports: Vec<ImportInfo>,
    import_contexts: ScalaImportContextIndex,
    import_context_cursor: usize,
    package_contexts: ScalaPackageContextIndex,
    class_ranges: ClassRangeIndex,
    package_context_cursor: usize,
    active_resolver_key: Option<ResolverContextKey>,
    resolver_contexts: HashMap<ResolverContextKey, ResolverContext>,
    pub(super) bindings: &'a mut LocalInferenceEngine<ScalaLocalBinding>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
}

type ResolverContextKey = (Vec<String>, Vec<usize>);
type ResolverContext = (Arc<NameResolver>, Arc<Visibility>);

enum ScanEvent<'tree> {
    Enter(Node<'tree>),
    Exit {
        node: Node<'tree>,
        exits_scope: bool,
    },
}

fn scan_tree(root: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![ScanEvent::Enter(root)];
    while let Some(event) = stack.pop() {
        match event {
            ScanEvent::Enter(node) => {
                if *ctx.limit_exceeded {
                    continue;
                }
                activate_import_context(node, ctx);
                seed_parent_scope_declarations(node, ctx);
                let enters_scope = enters_local_scope(node);
                if enters_scope {
                    ctx.bindings.enter_scope();
                    seed_scope_declarations(node, ctx);
                } else {
                    seed_inline_declarations(node, ctx);
                }

                if node.kind() == "call_expression" {
                    scan_call_expression(node, ctx);
                }
                if node.kind() == "infix_expression" {
                    scan_infix_expression(node, ctx);
                }
                if matches!(node.kind(), "function_definition" | "function_declaration") {
                    scan_method_declaration(node, ctx);
                }
                if node.kind() == "import_declaration" {
                    scan_import_declaration(node, ctx);
                } else if is_identifier_node(node) {
                    scan_identifier(node, ctx);
                }

                stack.push(ScanEvent::Exit {
                    node,
                    exits_scope: enters_scope,
                });
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                stack.extend(children.into_iter().rev().map(ScanEvent::Enter));
            }
            ScanEvent::Exit { node, exits_scope } => {
                if node.kind() == "assignment_expression" {
                    refresh_assignment_binding(node, ctx);
                }
                activate_case_pattern_binders(node, ctx);
                if exits_scope {
                    ctx.bindings.exit_scope();
                }
            }
        }
    }
}

fn activate_import_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let visible_imports = ctx
        .import_contexts
        .advance_to(node.start_byte(), &mut ctx.import_context_cursor);
    let visible_packages = ctx
        .package_contexts
        .advance_to(node.start_byte(), &mut ctx.package_context_cursor);
    if ctx
        .active_resolver_key
        .as_ref()
        .is_some_and(|(packages, imports)| {
            packages.as_slice() == visible_packages && imports.as_slice() == visible_imports
        })
    {
        return;
    }
    let key = (visible_packages.to_vec(), visible_imports.to_vec());
    if let Some((resolver, visibility)) = ctx.resolver_contexts.get(&key) {
        ctx.name_resolver = resolver.clone();
        ctx.visibility = visibility.clone();
        ctx.active_package = key.0.last().cloned().unwrap_or_default();
        ctx.active_resolver_key = Some(key);
        return;
    }

    let imports = key
        .1
        .iter()
        .filter_map(|index| ctx.imports.get(*index).cloned())
        .collect::<Vec<_>>();
    let resolver = Arc::new(NameResolver::for_file_with_package_context(
        ctx.scala,
        Some(ctx.file),
        &key.0,
        &imports,
        &ctx.types,
    ));
    let visibility = Arc::new(Visibility::for_file_with_imports(
        ctx.scala,
        ctx.file,
        key.0.last().map(String::as_str).unwrap_or_default(),
        ctx.spec,
        &resolver,
        &imports,
    ));
    ctx.resolver_contexts
        .insert(key.clone(), (resolver.clone(), visibility.clone()));
    ctx.name_resolver = resolver;
    ctx.visibility = visibility;
    ctx.active_package = key.0.last().cloned().unwrap_or_default();
    ctx.active_resolver_key = Some(key);
}

fn scan_import_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let matching_names = matching_names_for_import_declaration(node, ctx);
    if matching_names.is_empty() {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_import_declaration_identifier(child, ctx, &matching_names);
    }
}

fn scan_import_declaration_identifier(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    matching_names: &HashSet<String>,
) {
    walk_tree_iterative(
        node,
        ctx,
        |current, ctx| {
            if is_identifier_node(current) {
                let text = node_text(current, ctx.source).trim();
                if !text.is_empty() && matching_names.contains(text) {
                    add_import_hit(current, ctx);
                }
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn matching_names_for_import_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> HashSet<String> {
    let mut names = HashSet::default();
    for import in scala_import_infos_from_node(node, ctx.source) {
        let matched = Visibility::matching_import_names(&import, ctx.spec, &ctx.active_package);
        names.extend(matched.type_names);
        names.extend(matched.owner_names.into_keys());
        names.extend(matched.direct_member_names);
    }
    names
}

fn scan_call_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(ctx.spec.kind, TargetKind::Method) {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let text = node_text(function, ctx.source).trim();
    if companion_apply_call_is_proven(function, text, ctx) {
        add_hit(function, ctx);
        return;
    }
    if text != ctx.spec.member_name || has_member_qualifier(function) {
        return;
    }
    if bare_member_reference_is_proven(function, text, ctx) {
        add_hit(function, ctx);
    }
}

fn companion_apply_call_is_proven(function: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if !ctx.spec.accepts_companion_apply_syntax {
        return false;
    }
    if resolve_unqualified_type_application(
        function,
        text,
        TypeApplicationRole::BareApplication,
        ctx,
    )
    .is_some_and(|resolution| resolution.callable_targets.contains(&ctx.spec.target))
    {
        return true;
    }

    let lexical_type = exact_lexically_visible_type(function, ctx);
    ctx.spec.owner_name.as_deref() == Some(text)
        && !has_member_qualifier(function)
        && !is_locally_shadowed(ctx, text)
        && !bare_call_is_claimed_by_enclosing_member(function, text, ctx)
        && member_call_arity_matches(function, ctx)
        && match lexical_type {
            ScalaTypeNamespaceResolution::NoMatch => {
                ctx.visibility
                    .owner_fq_name_for(text)
                    .is_some_and(|owner| ctx.spec.owner_fq_matches(owner))
                    || nested_target_owner_is_lexically_visible(function, ctx)
            }
            ScalaTypeNamespaceResolution::Resolved(lexical_type) => {
                ctx.spec.owner.as_ref() == Some(&lexical_type)
            }
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => false,
        }
}

fn nested_target_owner_is_lexically_visible(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    let Some(target_parent) = ctx.analyzer.parent_of(owner) else {
        return false;
    };
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(unit) = current {
        if unit == target_parent {
            return true;
        }
        current = ctx.analyzer.parent_of(&unit);
    }
    false
}

fn resolve_unqualified_type_application(
    node: Node<'_>,
    name: &str,
    role: TypeApplicationRole,
    ctx: &ScanCtx<'_>,
) -> Option<TypeApplicationResolution> {
    if name.is_empty()
        || has_member_qualifier(node)
        || (role != TypeApplicationRole::ExplicitConstructor
            && type_reference_is_locally_bound(name, ctx))
        || (role == TypeApplicationRole::BareApplication
            && bare_call_is_claimed_by_enclosing_member(node, name, ctx))
    {
        return None;
    }
    let class_fqn = match exact_lexically_visible_type(node, ctx) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration.fq_name()),
        ScalaTypeNamespaceResolution::NoMatch => ctx.name_resolver.resolve(name),
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => None,
    };
    let object_fqn = lexically_visible_nested_object(node, name, ctx)
        .or_else(|| ctx.name_resolver.resolve_object(name));
    (class_fqn.is_some() || object_fqn.is_some()).then(|| {
        ctx.types.resolve_type_application(
            ctx.scala,
            &ctx.name_resolver,
            class_fqn.as_deref(),
            object_fqn.as_deref(),
            name,
            call_site_shape_for_reference(node).as_ref(),
            role,
            Some(ctx.file),
        )
    })
}

fn scan_infix_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.kind != TargetKind::Method {
        return;
    }
    let (Some(operator), Some(left)) = (
        node.child_by_field_name("operator"),
        node.child_by_field_name("left"),
    ) else {
        return;
    };
    let text = node_text(operator, ctx.source).trim();
    if text != ctx.spec.member_name || infix_receiver_for_operator(operator) != Some(left) {
        return;
    }
    if member_call_arity_matches(operator, ctx)
        && extension_receiver_type(left, ctx)
            .is_some_and(|owner| ctx.spec.receiver_owner_fq_matches(&owner))
    {
        add_hit(operator, ctx);
    }
}

fn scan_method_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.kind != TargetKind::Method {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name, ctx.source).trim() != ctx.spec.member_name {
        return;
    }
    if !function_arity_matches(node, ctx) {
        return;
    }
    let Some(owner_fq_name) = enclosing_owner_fq_name(name, ctx) else {
        return;
    };
    if ctx
        .spec
        .related_override_owner_fq_matches(owner_fq_name.as_str())
    {
        add_override_declaration_hit(name, ctx);
    }
}

fn seed_parent_scope_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "function_definition" || !has_ancestor_kind(node, "function_definition") {
        return;
    }
    if let Some(name) = node.child_by_field_name("name") {
        let name = node_text(name, ctx.source).trim();
        if !name.is_empty() {
            ctx.bindings.declare_shadow(name.to_string());
        }
    }
}

fn enters_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
    )
}

fn seed_scope_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_class_parameter_bindings(node, ctx);
            seed_owner_field_bindings(node, ctx);
        }
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
            seed_enclosing_owner_field_bindings(node, ctx);
            seed_parameter_bindings(node, ctx);
        }
        _ => {}
    }
}

fn seed_inline_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "val_definition" | "var_definition" => {
            if let Some(owner) = direct_template_field_owner(node, ctx) {
                seed_owner_field_definition(node, &owner, ctx);
            } else {
                seed_value_definition(node, ctx);
            }
        }
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
        }
        _ => {}
    }
}

fn seed_owner_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "template_body" | "enum_body") {
            seed_direct_field_bindings(child, ctx);
        }
    }
}

fn seed_enclosing_owner_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                seed_owner_field_bindings(ancestor, ctx);
                return;
            }
            "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => return,
            _ => current = ancestor.parent(),
        }
    }
}

fn seed_direct_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => {
                if let Some(owner) = direct_template_field_owner(child, ctx) {
                    seed_owner_field_definition(child, &owner, ctx);
                }
            }
            "function_definition"
            | "function_declaration"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => {}
            _ => seed_direct_field_bindings(child, ctx),
        }
    }
}

fn seed_owner_field_definition(node: Node<'_>, owner: &CodeUnit, ctx: &mut ScanCtx<'_>) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let receiver_type = value_definition_receiver_type(node, ctx);
    for name in scala_pattern_binder_names(pattern, ctx.source) {
        seed_scala_binding(
            name,
            receiver_type.clone(),
            Some(owner.clone()),
            ctx.bindings,
        );
    }
}

fn direct_template_field_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "template_body" | "enum_body" => {
                return enclosing_owner(node, ctx);
            }
            "function_definition"
            | "function_declaration"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => return None,
            _ => current = ancestor.parent(),
        }
    }
    None
}

fn seed_parameter_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        seed_parameters(child, ctx);
    }
}

fn seed_class_parameter_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let enclosing_owner = node
        .child_by_field_name("name")
        .and_then(|name| enclosing_owner(name, ctx));
    let mut cursor = node.walk();
    for parameters in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "class_parameters")
    {
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() != "class_parameter" {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, ctx.source).trim();
            if name.is_empty() {
                continue;
            }
            if class_parameter_is_field(parameter)
                && let Some(owner) = enclosing_owner.as_ref()
            {
                let receiver_type = parameter
                    .child_by_field_name("type")
                    .and_then(|type_node| resolve_type_node(type_node, ctx));
                seed_scala_binding(name, receiver_type, Some(owner.clone()), ctx.bindings);
            } else {
                seed_parameter(parameter, ctx);
            }
        }
    }
}

fn class_parameter_is_field(parameter: Node<'_>) -> bool {
    let mut cursor = parameter.walk();
    parameter
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "val" | "var"))
}

fn seed_parameters(parameters: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if matches!(parameter.kind(), "parameter" | "class_parameter") {
            seed_parameter(parameter, ctx);
        }
    }
}

fn seed_parameter(parameter: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name, ctx.source).trim();
    if name.is_empty() {
        return;
    }
    let type_node = parameter.child_by_field_name("type");
    if let Some(type_node) = type_node
        && let Some(paths) = scala_union_type_alternative_paths(type_node, ctx.source)
    {
        let owners = paths
            .iter()
            .map(|path| {
                ctx.types
                    .resolve_type_in_declaration_context(ctx.scala, &ctx.name_resolver, path)
            })
            .collect::<Option<Vec<_>>>();
        if let Some(owners) = owners {
            ctx.bindings.seed_symbol_many(
                name.to_string(),
                owners.into_iter().map(|receiver_type| ScalaLocalBinding {
                    receiver_type: Some(receiver_type),
                    declaration_owner: None,
                }),
            );
        } else {
            ctx.bindings.declare_shadow(name.to_string());
        }
        return;
    }
    if let Some(owner) = type_node.and_then(|type_node| resolve_type_node(type_node, ctx)) {
        seed_scala_binding(name, Some(owner), None, ctx.bindings);
        return;
    }
    let type_name = type_node.map(|type_node| node_text(type_node, ctx.source).trim());
    seed_or_shadow_typed_symbol(name, type_name, None, ctx);
}

fn seed_value_definition(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    };
    let receiver_type = value_definition_receiver_type(node, ctx);
    if receiver_type.is_none() {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    }
    for name in scala_pattern_binder_names(pattern, ctx.source) {
        seed_scala_binding(name, receiver_type.clone(), None, ctx.bindings);
    }
}

fn value_definition_receiver_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let value = node.child_by_field_name("value");
    node.child_by_field_name("type")
        .and_then(|type_node| resolve_type_node(type_node, ctx))
        .or_else(|| value.and_then(|value| constructed_or_applied_type_owner(value, ctx)))
        .or_else(|| value.and_then(|value| call_initializer_return_owner(value, ctx)))
        .or_else(|| {
            let type_name = node
                .child_by_field_name("type")
                .map(|type_node| node_text(type_node, ctx.source).trim());
            let value_name = value
                .and_then(|value_node| constructor_type_name(node_text(value_node, ctx.source)));
            type_name
                .or(value_name)
                .and_then(|name| ctx.visibility.receiver_type_fq_name_for(name))
                .map(str::to_string)
        })
}

fn constructed_type_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "arguments" | "template_body"))
        .and_then(|type_node| resolve_type_node(type_node, ctx))
}

fn constructed_or_applied_type_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    constructed_type_owner(node, ctx).or_else(|| {
        if node.kind() != "call_expression" {
            return None;
        }
        let mut function = node.child_by_field_name("function")?;
        while function.kind() == "call_expression" {
            function = function.child_by_field_name("function")?;
        }
        if !matches!(function.kind(), "identifier" | "type_identifier") {
            return None;
        }
        let name = node_text(function, ctx.source).trim();
        if name.is_empty() {
            return None;
        }
        resolve_unqualified_type_application(
            function,
            name,
            TypeApplicationRole::BareApplication,
            ctx,
        )
        .and_then(|resolution| resolution.type_target)
        .map(|target| target.fq_name())
    })
}

fn constructed_receiver_type_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let type_node = node
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "arguments" | "template_body"))?;
    let path = scala_type_lookup_segments(type_node, ctx.source);
    let name = path.last()?;
    let class_fqn = resolve_type_node(type_node, ctx)?;
    ctx.types
        .resolve_type_application(
            ctx.scala,
            &ctx.name_resolver,
            Some(&class_fqn),
            None,
            name,
            call_site_shape_for_reference(type_node).as_ref(),
            TypeApplicationRole::ExplicitConstructor,
            Some(ctx.file),
        )
        .type_target
        .map(|target| target.fq_name())
}

fn resolve_type_node(type_node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let path = scala_type_lookup_segments(type_node, ctx.source);
    if path.is_empty() {
        return None;
    }
    match exact_lexically_visible_type(type_node, ctx) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            return Some(declaration.fq_name());
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => return None,
        ScalaTypeNamespaceResolution::NoMatch => {}
    }
    ctx.types
        .resolve_type_in_declaration_context(ctx.scala, &ctx.name_resolver, &path)
        .or_else(|| {
            (path.len() == 1)
                .then(|| scala_builtin_type_name(&path[0]).map(str::to_string))
                .flatten()
        })
}

fn refresh_assignment_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if !matches!(left.kind(), "identifier" | "operator_identifier") {
        return;
    }
    let name = node_text(left, ctx.source).trim();
    if name.is_empty() || !ctx.bindings.is_shadowed(name) {
        return;
    }

    let declaration_owner =
        precise_scala_binding(ctx.bindings, name).and_then(|binding| binding.declaration_owner);
    if let Some(receiver_type) = call_initializer_return_owner(right, ctx)
        .or_else(|| constructed_or_applied_type_owner(right, ctx))
    {
        seed_scala_binding(name, Some(receiver_type), declaration_owner, ctx.bindings);
        return;
    }
    if matches!(right.kind(), "identifier" | "operator_identifier") {
        let source_name = node_text(right, ctx.source).trim();
        if !source_name.is_empty()
            && let Some(source) = precise_scala_binding(ctx.bindings, source_name)
        {
            seed_scala_binding(name, source.receiver_type, declaration_owner, ctx.bindings);
            return;
        }
    }
    seed_scala_binding(name, None, declaration_owner, ctx.bindings);
}

fn call_initializer_return_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "field_expression" => {
            let owner_node = function.child_by_field_name("value")?;
            let member_node = function.child_by_field_name("field")?;
            let member_name = node_text(member_node, ctx.source).trim();
            if member_name.is_empty() {
                return None;
            }
            let owner = if owner_node.kind() == "field_expression" {
                stable_object_expression_fqn(owner_node, ctx)
            } else if matches!(owner_node.kind(), "identifier" | "type_identifier") {
                let owner_name = node_text(owner_node, ctx.source).trim();
                precise_scala_binding(ctx.bindings, owner_name)
                    .and_then(|binding| binding.receiver_type)
                    .or_else(|| ctx.name_resolver.resolve_object(owner_name))
                    .or_else(|| ctx.name_resolver.resolve(owner_name))
            } else {
                None
            }?;
            let call_arities = call_arities_for_reference(member_node);
            ctx.types.member_return_type_for_owner_member(
                ctx.scala,
                &ctx.name_resolver,
                &owner,
                member_name,
                call_arities.as_deref(),
            )
        }
        "identifier" | "operator_identifier" => {
            let member_name = node_text(function, ctx.source).trim();
            if member_name.is_empty() || ctx.bindings.is_shadowed(member_name) {
                return None;
            }
            let call_arities = call_arities_for_reference(function);
            match lexically_visible_unqualified_member_return_type(
                function,
                member_name,
                call_arities.as_deref(),
                ctx,
            ) {
                MemberReturnResolution::Resolved(return_type) => return Some(return_type),
                MemberReturnResolution::Unresolved => return None,
                MemberReturnResolution::NoMatch => {}
            }
            ctx.name_resolver
                .resolve_member(member_name)
                .and_then(|member| {
                    ctx.types.member_return_type_for_fqn_call(
                        ctx.scala,
                        &ctx.name_resolver,
                        &member,
                        call_arities.as_deref(),
                    )
                })
        }
        _ => None,
    }
}

fn seed_value_definition_from_text(text: &str, ctx: &mut ScanCtx<'_>) {
    let trimmed = text.trim_start();
    let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    else {
        return;
    };
    let name_end = after_keyword
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(after_keyword.len());
    if name_end == 0 {
        return;
    }
    let name = &after_keyword[..name_end];
    let rest = after_keyword[name_end..].trim_start();
    let type_name = rest
        .strip_prefix(':')
        .and_then(|after_colon| simple_type_name(after_colon.trim_start()));
    let value_name = rest
        .split_once('=')
        .and_then(|(_, value)| constructor_type_name(value));
    seed_or_shadow_typed_symbol(name, type_name, value_name, ctx);
}

fn lexically_visible_unqualified_member_return_type(
    node: Node<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScanCtx<'_>,
) -> MemberReturnResolution {
    for declaration in enclosing_template_declarations(node) {
        let resolution = if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            ctx.types.unqualified_member_return_type(
                ctx.scala,
                &ctx.name_resolver,
                owner,
                member,
                call_arities,
            )
        } else if template_direct_term_member_named(declaration, member, ctx.source) {
            MemberReturnResolution::Unresolved
        } else {
            let Some(owners) = template_supertype_owners(declaration, ctx) else {
                return MemberReturnResolution::Unresolved;
            };
            ctx.types.unqualified_member_return_type_for_owners(
                ctx.scala,
                &ctx.name_resolver,
                &owners,
                member,
                call_arities,
            )
        };
        match resolution {
            MemberReturnResolution::NoMatch => {}
            resolution => return resolution,
        }
        let Some(self_owner) =
            template_self_type(declaration).and_then(|type_node| resolve_type_node(type_node, ctx))
        else {
            continue;
        };
        let mut declarations = ctx
            .scala
            .definitions(&self_owner)
            .filter(CodeUnit::is_class);
        let Some(declaration) = declarations.next() else {
            continue;
        };
        if declarations.next().is_some() {
            return MemberReturnResolution::Unresolved;
        }
        match ctx.types.unqualified_member_return_type(
            ctx.scala,
            &ctx.name_resolver,
            &declaration,
            member,
            call_arities,
        ) {
            MemberReturnResolution::NoMatch => {}
            resolution => return resolution,
        }
    }
    MemberReturnResolution::NoMatch
}

fn seed_or_shadow_typed_symbol(
    name: &str,
    type_name: Option<&str>,
    value_name: Option<&str>,
    ctx: &mut ScanCtx<'_>,
) {
    let visible_owner = type_name
        .or(value_name)
        .and_then(|name| ctx.visibility.receiver_type_fq_name_for(name));
    if let Some(owner_fq_name) = visible_owner {
        seed_scala_binding(name, Some(owner_fq_name.to_string()), None, ctx.bindings);
        return;
    }
    if let Some(type_name) = type_name
        && let Some(owner_fq_name) =
            scala_resolve_declared_type(ctx.scala, ctx.file, &ctx.active_package, type_name)
    {
        seed_scala_binding(name, Some(owner_fq_name), None, ctx.bindings);
        return;
    }
    if let Some(type_name) = type_name
        && let Some(builtin) = scala_builtin_type_name(type_name)
    {
        seed_scala_binding(name, Some(builtin.to_string()), None, ctx.bindings);
        return;
    }
    ctx.bindings.declare_shadow(name.to_string());
}

fn simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .split(['[', '(', '{', '.', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn constructor_type_name(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let trimmed = trimmed.strip_prefix("new ").unwrap_or(trimmed).trim_start();
    let end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(trimmed.len());
    (end > 0).then_some(&trimmed[..end])
}

fn activate_case_pattern_binders(pattern: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(case_clause) = pattern
        .parent()
        .filter(|parent| parent.kind() == "case_clause")
    else {
        return;
    };
    if case_clause.child_by_field_name("pattern") != Some(pattern) {
        return;
    }
    for name in scala_pattern_binder_names(pattern, ctx.source) {
        ctx.bindings.declare_shadow(name.to_string());
    }
}

fn scan_identifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "import_declaration")
        || is_declaration_name(node)
        || is_scala_case_pattern_binder(node)
    {
        return;
    }
    let text = node_text(node, ctx.source).trim();
    if text.is_empty() {
        return;
    }
    if seed_value_binding_identifier(node, text, ctx) {
        return;
    }

    let proven = match ctx.spec.kind {
        TargetKind::Type => {
            let qualified = qualified_stable_type_reference(node, ctx.source).filter(|reference| {
                reference
                    .segments
                    .first()
                    .is_some_and(|root| !ctx.bindings.is_shadowed(root))
            });
            let object_syntax = is_scala_object_reference(node);
            let qualified_class_target = qualified.as_ref().and_then(|reference| {
                resolve_qualified_stable_type_at(node, &reference.segments, false, ctx)
            });
            let qualified_object_target = qualified.as_ref().and_then(|reference| {
                resolve_qualified_stable_type_at(node, &reference.segments, true, ctx)
            });
            let qualified_class_matches = qualified_class_target
                .as_deref()
                .is_some_and(|fqn| exact_type_declaration_matches(fqn, &ctx.spec.target, ctx));
            let qualified_object_matches = qualified_object_target.as_deref().is_some_and(|fqn| {
                fqn == ctx.spec.target.fq_name() || ctx.spec.object_role_fq_matches(fqn)
            });
            let qualified_role_matches = qualified.as_ref().is_some_and(|reference| {
                let call_arities = call_arities_for_reference(reference.expression);
                let call_shape = call_site_shape_for_reference(reference.expression);
                match reference.role {
                    ScalaQualifiedStableTypeRole::Type => qualified_class_matches,
                    ScalaQualifiedStableTypeRole::Constructor => {
                        qualified_class_matches
                            && (ctx
                                .types
                                .is_scala_trait_declaration(ctx.scala, &ctx.spec.target)
                                || qualified_class_target.as_deref().is_some_and(|fqn| {
                                    ctx.types.explicit_constructor_call_matches(
                                        ctx.scala,
                                        fqn,
                                        call_shape.as_ref(),
                                    )
                                }))
                    }
                    ScalaQualifiedStableTypeRole::Apply => {
                        (qualified_class_matches
                            && ctx.spec.accepts_apply_role
                            && ctx.types.class_companion_apply_call_matches(
                                ctx.scala,
                                &ctx.name_resolver,
                                &ctx.spec.target,
                                call_arities.as_deref(),
                            ))
                            || (ctx.spec.is_object_type && qualified_object_matches)
                    }
                    ScalaQualifiedStableTypeRole::Extractor => {
                        (qualified_class_matches && ctx.spec.accepts_extractor_role)
                            || (ctx.spec.is_object_type && qualified_object_matches)
                    }
                }
            });
            let terminal_object_matches = is_terminal_stable_field_reference(node)
                && node
                    .parent()
                    .and_then(|expression| stable_object_expression_fqn(expression, ctx))
                    .is_some_and(|fqn| fqn == ctx.spec.target.fq_name());
            let stable_identifier_object_matches = stable_identifier_object_fqn(node, ctx)
                .is_some_and(|fqn| fqn == ctx.spec.target.fq_name());
            let lexical_type = exact_lexically_visible_type(node, ctx);
            let lexical_type_matches = matches!(
                &lexical_type,
                ScalaTypeNamespaceResolution::Resolved(declaration)
                    if declaration == &ctx.spec.target
            );
            let lexical_object = lexically_visible_nested_object(node, text, ctx);
            let lexical_object_matches = lexical_object.as_deref().is_some_and(|fqn| {
                fqn == ctx.spec.target.fq_name() || ctx.spec.object_role_fq_matches(fqn)
            });
            let class_call_shape_matches = !is_constructor_like_reference(node, ctx.source)
                || ctx
                    .types
                    .is_scala_trait_declaration(ctx.scala, &ctx.spec.target)
                || ctx.types.explicit_constructor_target_matches(
                    ctx.scala,
                    &ctx.spec.target,
                    call_site_shape_for_reference(node).as_ref(),
                );
            let class_reference = qualified.is_none()
                && is_scala_class_reference(node, ctx.source)
                && !is_call_function_reference(node)
                && !ctx.spec.is_object_type
                && (lexical_type_matches
                    || matches!(lexical_type, ScalaTypeNamespaceResolution::NoMatch)
                        && ctx.visibility.class_type_name_matches(text))
                && class_call_shape_matches;
            let class_application = qualified.is_none()
                && is_call_function_reference(node)
                && !ctx.spec.is_object_type
                && resolve_unqualified_type_application(
                    node,
                    text,
                    TypeApplicationRole::BareApplication,
                    ctx,
                )
                .and_then(|resolution| resolution.type_target)
                .as_ref()
                    == Some(&ctx.spec.target);
            let extractor_projection = qualified.is_none()
                && (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && resolve_unqualified_type_application(
                    node,
                    text,
                    TypeApplicationRole::Extractor,
                    ctx,
                )
                .and_then(|resolution| resolution.type_target)
                .as_ref()
                    == Some(&ctx.spec.target);
            let bare_method_value_context = is_bare_companion_method_value_reference(node)
                .then(|| companion_method_value_context(node, ctx));
            let object_reference = qualified.is_none()
                && object_syntax
                && !type_reference_is_locally_bound(text, ctx)
                && (lexical_object_matches
                    || lexical_object.is_none() && ctx.visibility.object_type_name_matches(text))
                && if is_call_function_reference(node) {
                    !bare_call_is_claimed_by_enclosing_member(node, text, ctx)
                        && (ctx.spec.is_object_type
                            || ctx.spec.accepts_apply_role
                                && ctx.types.class_companion_apply_call_matches(
                                    ctx.scala,
                                    &ctx.name_resolver,
                                    &ctx.spec.target,
                                    call_arities_for_reference(node).as_deref(),
                                ))
                } else {
                    ctx.spec.is_object_type
                        || ctx.spec.accepts_stable_object_role
                        || (is_extractor_reference(node) || is_infix_pattern_operator(node))
                            && ctx.spec.accepts_extractor_role
                };
            let incompatible_companion_object_reference = qualified.is_none()
                && ctx.spec.is_object_type
                && !type_reference_is_locally_bound(text, ctx)
                && matches!(
                    bare_method_value_context,
                    Some(ScalaMethodValueContext::Incompatible)
                )
                && ctx.name_resolver.resolve_object(text).as_deref()
                    == Some(ctx.spec.target.fq_name().as_str());
            let companion_method_value = qualified.is_none()
                && ctx.spec.member_name == text
                && ctx.spec.accepts_apply_role
                && bare_method_value_context.is_some()
                && ctx.name_resolver.resolve(text).as_deref()
                    == Some(ctx.spec.target.fq_name().as_str())
                && match bare_method_value_context.unwrap_or(ScalaMethodValueContext::Unknown) {
                    ScalaMethodValueContext::Unknown => {
                        ctx.types.class_companion_apply_method_value_matches(
                            ctx.scala,
                            &ctx.spec.target,
                            None,
                        )
                    }
                    ScalaMethodValueContext::Function(arity) => {
                        ctx.types.class_companion_apply_method_value_matches(
                            ctx.scala,
                            &ctx.spec.target,
                            Some(&[arity]),
                        )
                    }
                    ScalaMethodValueContext::Incompatible => false,
                };
            let stable_alias_type_member = ctx.spec.is_type_alias
                && qualified.as_ref().is_some_and(|reference| {
                    matches!(
                        reference.role,
                        ScalaQualifiedStableTypeRole::Type
                            | ScalaQualifiedStableTypeRole::Constructor
                    ) && member_reference_is_proven(node, text, ctx)
                });
            qualified_role_matches
                || class_reference
                || class_application
                || extractor_projection
                || object_reference
                || incompatible_companion_object_reference
                || companion_method_value
                || terminal_object_matches
                || stable_identifier_object_matches
                || stable_alias_type_member
        }
        TargetKind::Constructor => {
            let qualified = qualified_stable_type_reference(node, ctx.source).filter(|reference| {
                reference
                    .segments
                    .first()
                    .is_some_and(|root| !ctx.bindings.is_shadowed(root))
            });
            let qualified_owner_matches = qualified.as_ref().is_some_and(|reference| {
                reference.role == ScalaQualifiedStableTypeRole::Constructor
                    && resolve_qualified_type_application(node, ctx).is_some_and(|resolution| {
                        resolution.callable_targets.contains(&ctx.spec.target)
                    })
            });
            let lexical_owner = exact_lexically_visible_type(node, ctx);
            let lexical_owner_matches = matches!(
                &lexical_owner,
                ScalaTypeNamespaceResolution::Resolved(owner)
                    if Some(owner) == ctx.spec.owner.as_ref()
            );
            let exact_source_owner_matches = ctx.spec.owner.as_ref().is_some_and(|owner| {
                owner.source() == ctx.file && ctx.spec.owner_name.as_deref() == Some(text)
            });
            let extractor_role = is_extractor_reference(node) || is_infix_pattern_operator(node);
            let unqualified_role = if extractor_role {
                TypeApplicationRole::Extractor
            } else if is_call_function_reference(node) {
                TypeApplicationRole::BareApplication
            } else {
                TypeApplicationRole::ExplicitConstructor
            };
            let unqualified_constructor_matches =
                resolve_unqualified_type_application(node, text, unqualified_role, ctx)
                    .is_some_and(|resolution| {
                        resolution.callable_targets.contains(&ctx.spec.target)
                    });
            qualified_owner_matches
                || ((lexical_owner_matches
                    || matches!(lexical_owner, ScalaTypeNamespaceResolution::NoMatch)
                        && (exact_source_owner_matches
                            || ctx.visibility.class_type_name_matches(text)))
                    && (is_constructor_like_reference(node, ctx.source) || extractor_role)
                    && unqualified_constructor_matches)
        }
        TargetKind::Method => {
            ((is_extractor_reference(node) || is_infix_pattern_operator(node))
                && resolve_unqualified_type_application(
                    node,
                    text,
                    TypeApplicationRole::Extractor,
                    ctx,
                )
                .is_some_and(|resolution| resolution.callable_targets.contains(&ctx.spec.target)))
                || resolve_qualified_type_application(node, ctx).is_some_and(|resolution| {
                    resolution.callable_targets.contains(&ctx.spec.target)
                })
                || member_reference_is_proven(node, text, ctx)
        }
        TargetKind::Field => {
            named_argument_field_is_proven(node, text, ctx)
                || member_reference_is_proven(node, text, ctx)
        }
    };
    if proven {
        add_hit(node, ctx);
    }
}

fn exact_lexically_visible_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> ScalaTypeNamespaceResolution {
    let lookup_node = scala_qualified_type_root(node);
    let segments = scala_type_lookup_segments(lookup_node, ctx.source);
    let resolution = exact_lexically_visible_type_root(node, ctx);
    if segments.len() == 1 {
        return resolution;
    }
    match resolution {
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => resolution,
        ScalaTypeNamespaceResolution::NoMatch | ScalaTypeNamespaceResolution::Resolved(_) => {
            ScalaTypeNamespaceResolution::NoMatch
        }
    }
}

fn exact_lexically_visible_type_root(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> ScalaTypeNamespaceResolution {
    let lookup_node = scala_qualified_type_root(node);
    if scala_type_reference_is_singleton(lookup_node) {
        return ScalaTypeNamespaceResolution::NoMatch;
    }
    let segments = scala_type_lookup_segments(lookup_node, ctx.source);
    let Some(root_name) = segments.first() else {
        return ScalaTypeNamespaceResolution::NoMatch;
    };
    if scala_unindexed_type_binding_shadows(ctx.source, lookup_node, root_name) {
        return ScalaTypeNamespaceResolution::AuthoritativeMiss;
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let mut owners = Vec::new();
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(unit) = current {
        current = ctx.scala.structural_parent_of(&unit);
        if unit.is_class() {
            owners.push(unit);
        }
    }
    ctx.types
        .exact_lexical_type_namespace(ctx.scala, owners, root_name, false)
}

fn lexically_visible_nested_object_unit(
    node: Node<'_>,
    name: &str,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(unit) = current {
        if unit.is_class()
            && let Some(nested) = ctx
                .types
                .exact_nested_object_for_owner(ctx.scala, &unit, name)
        {
            return Some(nested);
        }
        current = ctx.analyzer.parent_of(&unit);
    }
    None
}

fn lexically_visible_nested_object(
    node: Node<'_>,
    name: &str,
    ctx: &ScanCtx<'_>,
) -> Option<String> {
    lexically_visible_nested_object_unit(node, name, ctx).map(|unit| unit.fq_name())
}

fn resolve_qualified_stable_type_at(
    node: Node<'_>,
    segments: &[String],
    terminal_object: bool,
    ctx: &ScanCtx<'_>,
) -> Option<String> {
    let root = segments.first()?;
    let lexical_root = if terminal_object {
        lexically_visible_nested_object_unit(node, root, ctx)
    } else {
        match exact_lexically_visible_type_root(node, ctx) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration),
            ScalaTypeNamespaceResolution::NoMatch => {
                lexically_visible_nested_object_unit(node, root, ctx)
            }
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => return None,
        }
    };
    ctx.types.resolve_qualified_stable_type_at(
        ctx.scala,
        &ctx.name_resolver,
        segments,
        terminal_object,
        lexical_root,
    )
}

fn resolve_qualified_type_application(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<TypeApplicationResolution> {
    let reference = qualified_stable_type_reference(node, ctx.source)?;
    let role = match reference.role {
        ScalaQualifiedStableTypeRole::Constructor => TypeApplicationRole::ExplicitConstructor,
        ScalaQualifiedStableTypeRole::Apply => TypeApplicationRole::BareApplication,
        ScalaQualifiedStableTypeRole::Extractor => TypeApplicationRole::Extractor,
        ScalaQualifiedStableTypeRole::Type => return None,
    };
    let root = reference.segments.first()?;
    if ctx.bindings.is_shadowed(root) {
        return None;
    }
    let name = reference.segments.last()?;
    let class_fqn = resolve_qualified_stable_type_at(node, &reference.segments, false, ctx);
    let object_fqn = resolve_qualified_stable_type_at(node, &reference.segments, true, ctx);
    if class_fqn.is_none() && object_fqn.is_none() {
        return None;
    }
    Some(ctx.types.resolve_type_application(
        ctx.scala,
        &ctx.name_resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_site_shape_for_reference(reference.expression).as_ref(),
        role,
        Some(ctx.file),
    ))
}

fn exact_type_declaration_matches(fqn: &str, expected: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    let mut declarations = ctx.scala.definitions(fqn).filter(|unit| unit.is_class());
    let declaration = declarations.next();
    declarations.next().is_none() && declaration.as_ref() == Some(expected)
}

fn named_argument_field_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if text != ctx.spec.member_name {
        return false;
    }
    let Some(owner) =
        named_argument_invocation_owner(node).and_then(terminal_invocation_owner_name)
    else {
        return false;
    };
    let owner_name = node_text(owner, ctx.source).trim();
    !is_locally_shadowed(ctx, owner_name)
        && ctx
            .visibility
            .owner_fq_name_for(owner_name)
            .or_else(|| ctx.visibility.receiver_type_fq_name_for(owner_name))
            .is_some_and(|owner| ctx.spec.receiver_owner_fq_matches(owner))
}

fn type_reference_is_locally_bound(text: &str, ctx: &ScanCtx<'_>) -> bool {
    !ctx.bindings.resolve_symbol(text).is_unknown() || ctx.bindings.is_shadowed(text)
}

fn bare_call_is_claimed_by_enclosing_member(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if !is_call_function_reference(node) {
        return false;
    }
    let Some(owner) = enclosing_owner(node, ctx) else {
        return false;
    };
    match ctx.types.bare_member_declarations_for_owner(
        ctx.scala,
        &owner,
        text,
        call_arities_for_reference(node).as_deref(),
    ) {
        BareMemberResolution::Resolved(methods) => {
            methods.iter().any(|method| !method.is_synthetic())
        }
        BareMemberResolution::Unresolved => true,
        BareMemberResolution::NoMatch => false,
    }
}

fn seed_value_binding_identifier(node: Node<'_>, text: &str, ctx: &mut ScanCtx<'_>) -> bool {
    if is_direct_owner_field_declaration_identifier(node, ctx) {
        return true;
    }
    if node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "parameter" | "class_parameter")
            && parent.child_by_field_name("name") == Some(node)
    }) {
        return true;
    }
    if node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "val_definition" | "var_definition")
            && parent.child_by_field_name("pattern") == Some(node)
    }) {
        return true;
    }
    let before = ctx.source[..node.start_byte()].trim_end();
    let Some(keyword) = previous_word(before) else {
        return false;
    };
    if !matches!(keyword, "val" | "var") {
        return false;
    }
    let line_end = ctx.source[node.end_byte()..]
        .find(['\n', '\r', ';'])
        .map(|offset| node.end_byte() + offset)
        .unwrap_or(ctx.source.len());
    let rest = ctx.source[node.end_byte()..line_end].trim_start();
    let type_name = rest
        .strip_prefix(':')
        .and_then(|after_colon| simple_type_name(after_colon.trim_start()));
    let value_name = rest
        .split_once('=')
        .and_then(|(_, value)| constructor_type_name(value));
    seed_or_shadow_typed_symbol(text, type_name, value_name, ctx);
    true
}

fn is_direct_owner_field_declaration_identifier(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(parent.kind(), "val_definition" | "var_definition")
        || parent.child_by_field_name("pattern") != Some(node)
    {
        return false;
    }
    direct_template_field_owner(parent, ctx).is_some()
}

fn previous_word(value: &str) -> Option<&str> {
    value
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())
}

fn member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    let field_like_target = ctx.spec.kind == TargetKind::Field || ctx.spec.is_type_alias;
    if ctx.visibility.direct_member_names.contains(text)
        && !ctx.visibility.ambiguous_direct_member_names.contains(text)
        && !has_member_qualifier(node)
        && !is_locally_shadowed(ctx, text)
        && member_call_arity_matches(node, ctx)
    {
        return true;
    }

    if extension_member_reference_is_proven(node, text, ctx) {
        return true;
    }

    if text != ctx.spec.member_name {
        return false;
    }

    if field_like_target
        && let Some(reference) = qualified_stable_type_reference(node, ctx.source)
        && let Some((member, owner_segments)) = reference.segments.split_last()
        && member == &ctx.spec.member_name
        && let Some(owner) = resolve_qualified_stable_type_at(node, owner_segments, true, ctx)
    {
        return match ctx
            .types
            .stable_type_member_for_owner(ctx.scala, &owner, member)
        {
            FieldResolution::Resolved(field) => field.declaration == ctx.spec.target,
            FieldResolution::NoMatch | FieldResolution::Unresolved => false,
        };
    }

    if let Some(owner_fq_name) = stable_identifier_field_owner_fqn(node, ctx) {
        if field_like_target {
            return match ctx.types.field_for_owner_member(
                ctx.scala,
                &owner_fq_name,
                &ctx.spec.member_name,
            ) {
                FieldResolution::Resolved(field) => field.declaration == ctx.spec.target,
                FieldResolution::NoMatch | FieldResolution::Unresolved => false,
            };
        }
        return ctx.spec.owner_fq_matches(&owner_fq_name);
    }

    if ctx.spec.owner.is_none() {
        return member_qualifier(node, ctx.source)
            .is_some_and(|qualifier| qualifier == ctx.spec.target.package_name());
    }

    let Some(qualifier_node) = member_qualifier_node(node) else {
        return if ctx.spec.kind == TargetKind::Method {
            bare_member_reference_is_proven(node, text, ctx)
        } else {
            if is_locally_shadowed(ctx, text) || !member_call_arity_matches(node, ctx) {
                return false;
            }
            match lexically_visible_field(node, &ctx.spec.member_name, ctx) {
                FieldResolution::Resolved(field) => field.declaration == ctx.spec.target,
                FieldResolution::NoMatch | FieldResolution::Unresolved => false,
            }
        };
    };
    if ctx.spec.kind == TargetKind::Method
        && let Some(owner_fq_name) = stable_object_expression_fqn(qualifier_node, ctx)
    {
        return ctx.spec.owner_fq_matches(&owner_fq_name) && member_call_arity_matches(node, ctx);
    }
    if target_is_owned_ordinary_class_method(ctx)
        && let Some(owner_fq_name) = structured_receiver_type(qualifier_node, ctx)
    {
        let call_shape = call_site_shape_with_method_value_context(node, ctx);
        if !member_call_shape_matches(call_shape.as_ref(), ScalaCallableSiteRole::Ordinary, ctx) {
            return false;
        }
        return call_shape.as_ref().map_or_else(
            || ordinary_class_owner_matches_target(&owner_fq_name, text, None, ctx),
            |shape| {
                ordinary_class_owner_matches_target_with_shape(&owner_fq_name, text, shape, ctx)
            },
        );
    }
    if field_like_target && let Some(owner_fq_name) = structured_receiver_type(qualifier_node, ctx)
    {
        return match ctx.types.field_for_owner_member(
            ctx.scala,
            &owner_fq_name,
            &ctx.spec.member_name,
        ) {
            FieldResolution::Resolved(field) => field.declaration == ctx.spec.target,
            FieldResolution::NoMatch | FieldResolution::Unresolved => false,
        };
    }
    if let Some(owner_fq_name) = stable_object_expression_fqn(qualifier_node, ctx) {
        return ctx.spec.owner_fq_matches(&owner_fq_name) && member_call_arity_matches(node, ctx);
    }
    if qualifier_node.kind() == "call_expression"
        && let Some(owner_fq_name) = call_initializer_return_owner(qualifier_node, ctx)
    {
        return ctx.spec.receiver_owner_fq_matches(&owner_fq_name)
            && member_call_arity_matches(node, ctx);
    }
    if qualifier_node.kind() == "instance_expression"
        && !ctx
            .types
            .is_scala_trait_declaration(ctx.scala, &ctx.spec.target)
        && let Some(owner_fq_name) = constructed_receiver_type_owner(qualifier_node, ctx)
    {
        return receiver_owner_matches_target_family(&owner_fq_name, ctx)
            && member_call_arity_matches(node, ctx);
    }
    if is_owner_qualified_this(qualifier_node, ctx.source) {
        return owner_qualified_this_matches(qualifier_node, ctx)
            && member_call_arity_matches(node, ctx);
    }
    let qualifier = node_text(qualifier_node, ctx.source)
        .trim()
        .trim_end_matches('$');
    if qualifier == "this" {
        return enclosing_matches_owner(node, ctx) && member_call_arity_matches(node, ctx);
    }
    if ctx.visibility.owner_names.contains(qualifier)
        && !is_locally_shadowed(ctx, qualifier)
        && member_call_arity_matches(node, ctx)
    {
        return ctx
            .visibility
            .owner_fq_name_for(qualifier)
            .is_some_and(|owner_fq_name| ctx.spec.owner_fq_matches(owner_fq_name));
    }
    receiver_binding_matches(node, qualifier, ctx)
}

fn lexically_visible_field(node: Node<'_>, name: &str, ctx: &ScanCtx<'_>) -> FieldResolution {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(unit) = current {
        if unit.is_class() {
            match ctx
                .types
                .field_for_owner_member(ctx.scala, &unit.fq_name(), name)
            {
                FieldResolution::NoMatch => {}
                resolution => return resolution,
            }
        }
        current = ctx.analyzer.parent_of(&unit);
    }
    FieldResolution::NoMatch
}

fn bare_member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if text != ctx.spec.member_name || is_locally_shadowed(ctx, text) {
        return false;
    }
    let call_shape = call_site_shape_with_method_value_context(node, ctx);
    let call_arities = call_shape.as_ref().map(|shape| {
        shape
            .lists
            .iter()
            .map(|list| list.arity)
            .collect::<Vec<_>>()
    });
    if !member_call_shape_matches(call_shape.as_ref(), ScalaCallableSiteRole::Ordinary, ctx) {
        return false;
    }
    let templates = enclosing_template_declarations(node);
    if templates.is_empty() {
        return false;
    }
    for declaration in templates {
        let resolution = if target_is_owned_ordinary_class_method(ctx) {
            call_shape.as_ref().map_or_else(
                || ordinary_class_member_declarations_for_template(declaration, text, None, ctx),
                |shape| {
                    ordinary_class_member_declarations_for_template_with_shape(
                        declaration,
                        text,
                        shape,
                        ctx,
                    )
                },
            )
        } else {
            let Some(owner) = ctx
                .class_ranges
                .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
            else {
                return false;
            };
            call_shape.as_ref().map_or_else(
                || {
                    ctx.types.bare_member_declarations_for_owner(
                        ctx.scala,
                        owner,
                        text,
                        call_arities.as_deref(),
                    )
                },
                |shape| {
                    ctx.types.bare_member_declarations_for_owner_with_shape(
                        ctx.scala, owner, text, shape,
                    )
                },
            )
        };
        match resolution {
            BareMemberResolution::Resolved(methods) => {
                return methods_match_target_owner(&methods, ctx);
            }
            BareMemberResolution::Unresolved => return false,
            BareMemberResolution::NoMatch => {}
        }
        if target_is_owned_ordinary_class_method(ctx)
            && let Some(self_owner) = template_self_type(declaration)
                .and_then(|type_node| resolve_type_node(type_node, ctx))
        {
            let resolution = call_shape.as_ref().map_or_else(
                || ordinary_class_owner_resolution(&self_owner, text, None, ctx),
                |shape| ordinary_class_owner_resolution_with_shape(&self_owner, text, shape, ctx),
            );
            match resolution {
                BareMemberResolution::Resolved(methods) => {
                    return methods_match_target_owner(&methods, ctx);
                }
                BareMemberResolution::Unresolved => return false,
                BareMemberResolution::NoMatch => {}
            }
        }
    }
    false
}

fn ordinary_class_member_declarations_for_template(
    declaration: Node<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScanCtx<'_>,
) -> BareMemberResolution {
    if let Some(owner) = ctx
        .class_ranges
        .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
    {
        return ctx.types.ordinary_class_member_declarations_for_owner(
            ctx.scala,
            owner,
            member,
            call_arities,
        );
    }
    if template_direct_term_member_named(declaration, member, ctx.source) {
        return BareMemberResolution::Unresolved;
    }
    let Some(owners) = template_supertype_owners(declaration, ctx) else {
        return BareMemberResolution::Unresolved;
    };
    if owners.is_empty() {
        BareMemberResolution::NoMatch
    } else {
        ctx.types.ordinary_class_member_declarations_for_owners(
            ctx.scala,
            &owners,
            member,
            call_arities,
        )
    }
}

fn ordinary_class_member_declarations_for_template_with_shape(
    declaration: Node<'_>,
    member: &str,
    call_shape: &ScalaCallSiteShape,
    ctx: &ScanCtx<'_>,
) -> BareMemberResolution {
    if let Some(owner) = ctx
        .class_ranges
        .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
    {
        return ctx
            .types
            .ordinary_class_member_declarations_for_owner_with_shape(
                ctx.scala, owner, member, call_shape,
            );
    }
    if template_direct_term_member_named(declaration, member, ctx.source) {
        return BareMemberResolution::Unresolved;
    }
    let Some(owners) = template_supertype_owners(declaration, ctx) else {
        return BareMemberResolution::Unresolved;
    };
    if owners.is_empty() {
        BareMemberResolution::NoMatch
    } else {
        ctx.types
            .ordinary_class_member_declarations_for_owners_with_shape(
                ctx.scala, &owners, member, call_shape,
            )
    }
}

fn template_supertype_owners(declaration: Node<'_>, ctx: &ScanCtx<'_>) -> Option<Vec<CodeUnit>> {
    let mut owners = Vec::new();
    for (_, lookup_node) in scala_supertype_lookup_nodes(declaration) {
        let fqn = resolve_type_node(lookup_node, ctx)?;
        let mut declarations = ctx.scala.definitions(&fqn).filter(CodeUnit::is_class);
        let owner = declarations.next()?;
        if declarations.next().is_some() {
            return None;
        }
        owners.push(owner);
    }
    Some(owners)
}

fn target_is_owned_ordinary_class_method(ctx: &ScanCtx<'_>) -> bool {
    ctx.spec.kind == TargetKind::Method
        && !ctx.spec.is_extension_method
        && ctx
            .spec
            .owner
            .as_ref()
            .is_some_and(|owner| !ctx.types.is_scala_trait_declaration(ctx.scala, owner))
}

fn methods_match_target_owner(methods: &[CodeUnit], ctx: &ScanCtx<'_>) -> bool {
    !methods.is_empty()
        && methods.iter().all(|method| {
            method == &ctx.spec.target
                || ctx
                    .scala
                    .structural_parent_of(method)
                    .or_else(|| ctx.scala.parent_of(method))
                    .is_some_and(|owner| ctx.spec.owner_fq_matches(&owner.fq_name()))
        })
}

fn ordinary_class_owner_matches_target(
    owner_fq_name: &str,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScanCtx<'_>,
) -> bool {
    match ordinary_class_owner_resolution(owner_fq_name, member, call_arities, ctx) {
        BareMemberResolution::Resolved(methods) => methods_match_target_owner(&methods, ctx),
        BareMemberResolution::NoMatch | BareMemberResolution::Unresolved => false,
    }
}

fn ordinary_class_owner_matches_target_with_shape(
    owner_fq_name: &str,
    member: &str,
    call_shape: &ScalaCallSiteShape,
    ctx: &ScanCtx<'_>,
) -> bool {
    match ordinary_class_owner_resolution_with_shape(owner_fq_name, member, call_shape, ctx) {
        BareMemberResolution::Resolved(methods) => methods_match_target_owner(&methods, ctx),
        BareMemberResolution::NoMatch | BareMemberResolution::Unresolved => false,
    }
}

fn ordinary_class_owner_resolution(
    owner_fq_name: &str,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScanCtx<'_>,
) -> BareMemberResolution {
    let mut owners = ctx
        .scala
        .definitions(owner_fq_name)
        .filter(CodeUnit::is_class);
    let Some(owner) = owners.next() else {
        return BareMemberResolution::NoMatch;
    };
    if owners.next().is_some() {
        return BareMemberResolution::Unresolved;
    }
    ctx.types
        .ordinary_class_member_declarations_for_owner(ctx.scala, &owner, member, call_arities)
}

fn ordinary_class_owner_resolution_with_shape(
    owner_fq_name: &str,
    member: &str,
    call_shape: &ScalaCallSiteShape,
    ctx: &ScanCtx<'_>,
) -> BareMemberResolution {
    let mut owners = ctx
        .scala
        .definitions(owner_fq_name)
        .filter(CodeUnit::is_class);
    let Some(owner) = owners.next() else {
        return BareMemberResolution::NoMatch;
    };
    if owners.next().is_some() {
        return BareMemberResolution::Unresolved;
    }
    ctx.types
        .ordinary_class_member_declarations_for_owner_with_shape(
            ctx.scala, &owner, member, call_shape,
        )
}

fn companion_method_value_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> ScalaMethodValueContext {
    if let Some(expected_type) = node
        .parent()
        .and_then(|definition| match definition.kind() {
            "val_definition" | "var_definition"
                if definition.child_by_field_name("value") == Some(node) =>
            {
                definition.child_by_field_name("type")
            }
            "function_definition" if definition.child_by_field_name("body") == Some(node) => {
                definition.child_by_field_name("return_type")
            }
            _ => None,
        })
    {
        let Some(arity) = function_type_arity(expected_type) else {
            return ScalaMethodValueContext::Incompatible;
        };
        return ScalaMethodValueContext::Function(arity);
    }
    call_parameter_method_value_context(node, ctx)
}

fn function_type_arity(type_node: Node<'_>) -> Option<usize> {
    if type_node.kind() != "function_type" {
        return None;
    }
    let parameter_types = type_node.child_by_field_name("parameter_types")?;
    let mut cursor = parameter_types.walk();
    Some(parameter_types.named_children(&mut cursor).count())
}

fn call_parameter_method_value_context(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> ScalaMethodValueContext {
    let Some(arguments) = node.parent() else {
        return ScalaMethodValueContext::Unknown;
    };
    if arguments.kind() != "arguments" {
        return ScalaMethodValueContext::Unknown;
    }
    let mut arguments_cursor = arguments.walk();
    let Some(parameter_index) = arguments
        .named_children(&mut arguments_cursor)
        .position(|argument| argument == node)
    else {
        return ScalaMethodValueContext::Unknown;
    };
    let Some(call) = arguments.parent() else {
        return ScalaMethodValueContext::Unknown;
    };
    if call.kind() != "call_expression" || call.child_by_field_name("arguments") != Some(arguments)
    {
        return ScalaMethodValueContext::Unknown;
    }

    let mut parameter_list = 0usize;
    let Some(mut function) = call.child_by_field_name("function") else {
        return ScalaMethodValueContext::Unknown;
    };
    while function.kind() == "call_expression" {
        parameter_list += 1;
        let Some(inner) = function.child_by_field_name("function") else {
            return ScalaMethodValueContext::Unknown;
        };
        function = inner;
    }
    if function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            return ScalaMethodValueContext::Unknown;
        };
        function = inner;
    }
    if !matches!(function.kind(), "identifier" | "operator_identifier") {
        return ScalaMethodValueContext::Unknown;
    }
    let function_name = node_text(function, ctx.source).trim();
    if function_name.is_empty() {
        return ScalaMethodValueContext::Unknown;
    }
    if ctx.bindings.is_shadowed(function_name) {
        return ScalaMethodValueContext::Incompatible;
    }
    let Some(call_arities) = call_arities_for_reference(function) else {
        return ScalaMethodValueContext::Unknown;
    };
    let Some(owner) = enclosing_owner(function, ctx) else {
        return ScalaMethodValueContext::Unknown;
    };
    let methods = match ctx.types.bare_member_declarations_for_owner(
        ctx.scala,
        &owner,
        function_name,
        Some(&call_arities),
    ) {
        BareMemberResolution::Resolved(methods) => methods,
        BareMemberResolution::NoMatch => {
            let Some(imported) = ctx.name_resolver.resolve_member(function_name) else {
                return ScalaMethodValueContext::Unknown;
            };
            ctx.scala
                .definitions(&imported)
                .filter(CodeUnit::is_function)
                .collect()
        }
        BareMemberResolution::Unresolved => return ScalaMethodValueContext::Incompatible,
    };
    if methods.is_empty() {
        return ScalaMethodValueContext::Incompatible;
    }

    let mut resolved = None;
    for method in methods {
        let Some(arity) = ctx.types.callable_parameter_function_arity(
            ctx.scala,
            &method,
            &call_arities,
            parameter_list,
            parameter_index,
        ) else {
            return ScalaMethodValueContext::Incompatible;
        };
        if resolved.is_some_and(|resolved| resolved != arity) {
            return ScalaMethodValueContext::Incompatible;
        }
        resolved = Some(arity);
    }
    resolved.map_or(
        ScalaMethodValueContext::Incompatible,
        ScalaMethodValueContext::Function,
    )
}

fn stable_object_expression_fqn(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    resolve_stable_object_expression(
        node,
        ctx.source,
        |root| {
            (ctx.bindings.resolve_symbol(root).is_unknown() && !ctx.bindings.is_shadowed(root))
                .then(|| ctx.name_resolver.resolve_object(root))
                .flatten()
        },
        |owner, member| ctx.types.exact_nested_object(ctx.scala, owner, member),
    )
}

fn stable_identifier_object_fqn(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let reference = stable_identifier_reference(node, ctx.source)?;
    let root = reference.segments.first()?;
    if !ctx.bindings.resolve_symbol(root).is_unknown() || ctx.bindings.is_shadowed(root) {
        return None;
    }
    resolve_qualified_stable_type_at(node, &reference.segments, true, ctx)
}

fn stable_identifier_field_owner_fqn(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let reference = stable_identifier_reference(node, ctx.source)?;
    let (member, owner_segments) = reference.segments.split_last()?;
    if member != &ctx.spec.member_name {
        return None;
    }
    let root = owner_segments.first()?;
    if !ctx.bindings.resolve_symbol(root).is_unknown() || ctx.bindings.is_shadowed(root) {
        return None;
    }
    resolve_qualified_stable_type_at(node, owner_segments, true, ctx)
}

fn owner_qualified_this_matches(qualifier_node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let qualifier = node_text(qualifier_node, ctx.source).trim();
    let Some(owner_name) = qualifier.strip_suffix(".this") else {
        return false;
    };
    ctx.visibility
        .receiver_type_fq_name_for(owner_name.trim().trim_end_matches('$'))
        .is_some_and(|owner_fq_name| ctx.spec.receiver_owner_fq_matches(owner_fq_name))
}

fn extension_member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.kind != TargetKind::Method
        || text != ctx.spec.member_name
        || !target_is_extension(ctx.spec)
        || !ctx.visibility.direct_member_names.contains(text)
        || !has_member_qualifier(node)
    {
        return false;
    }

    let Some(qualifier_node) = member_qualifier_node(node) else {
        return false;
    };
    let qualifier = node_text(qualifier_node, ctx.source).trim();
    if qualifier.is_empty() || is_unresolved_local_shadow(ctx, qualifier) {
        return false;
    }
    extension_receiver_matches(
        qualifier_node,
        call_arities_for_reference(node).as_deref(),
        ctx,
    )
}

fn target_is_extension(spec: &TargetSpec) -> bool {
    spec.is_extension_method
}

fn extension_receiver_matches(
    qualifier_node: Node<'_>,
    call_arities: Option<&[usize]>,
    ctx: &ScanCtx<'_>,
) -> bool {
    let Some(receiver_owner) = extension_receiver_type(qualifier_node, ctx) else {
        return false;
    };
    let matching_alternatives = ctx
        .spec
        .callable_alternatives
        .iter()
        .filter(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && scala_extension_receiver_matches_resolved(
                    alternative.extension_receiver_type.as_deref(),
                    Some(&receiver_owner),
                    |type_text| {
                        ctx.name_resolver
                            .resolve(type_text)
                            .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
                    },
                )
        })
        .collect::<Vec<_>>();
    let unique_callable = ctx.spec.unapplied_reference_is_unambiguous;
    if !matching_alternatives.iter().any(|alternative| {
        alternative.role == ScalaCallableRole::Ordinary
            && ordinary_callable_shape_matches(&alternative.shape, call_arities, unique_callable)
    }) {
        return false;
    }
    !receiver_has_member(
        &receiver_owner,
        ctx.spec.member_name.as_str(),
        call_arities.and_then(|arities| arities.first().copied()),
        ctx,
    )
}

fn extension_receiver_type(receiver: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source).trim();
            if name == "this" {
                return enclosing_owner_fq_name(receiver, ctx);
            }
            precise_scala_binding(ctx.bindings, name)
                .and_then(|binding| binding.receiver_type)
                .or_else(|| {
                    (!ctx.bindings.is_shadowed(name))
                        .then(|| ctx.visibility.owner_fq_name_for(name).map(str::to_string))
                        .flatten()
                })
                .or_else(|| {
                    (!ctx.bindings.is_shadowed(name))
                        .then(|| {
                            ctx.visibility
                                .receiver_fq_name_for(name)
                                .map(str::to_string)
                        })
                        .flatten()
                })
        }
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn structured_receiver_type(receiver: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source).trim();
            if name == "this" {
                return enclosing_owner_fq_name(receiver, ctx);
            }
            precise_scala_binding(ctx.bindings, name)
                .and_then(|binding| binding.receiver_type)
                .or_else(|| {
                    if ctx.bindings.is_shadowed(name) {
                        return None;
                    }
                    let owner = enclosing_owner_fq_name(receiver, ctx)?;
                    match ctx.types.field_for_owner_member(ctx.scala, &owner, name) {
                        FieldResolution::Resolved(field) => field.declared_type,
                        FieldResolution::NoMatch | FieldResolution::Unresolved => None,
                    }
                })
                .or_else(|| {
                    (!ctx.bindings.is_shadowed(name))
                        .then(|| {
                            ctx.name_resolver
                                .resolve_object(name)
                                .or_else(|| ctx.name_resolver.resolve(name))
                        })
                        .flatten()
                })
        }
        "field_expression" => stable_object_expression_fqn(receiver, ctx).or_else(|| {
            let value = receiver.child_by_field_name("value")?;
            let field = receiver.child_by_field_name("field")?;
            let owner = structured_receiver_type(value, ctx)?;
            let member = node_text(field, ctx.source).trim();
            if member.is_empty() {
                return None;
            }
            match ctx.types.field_for_owner_member(ctx.scala, &owner, member) {
                FieldResolution::Resolved(field) => field.declared_type,
                FieldResolution::NoMatch | FieldResolution::Unresolved => None,
            }
        }),
        "call_expression" => call_initializer_return_owner(receiver, ctx),
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn receiver_has_member(
    receiver_owner: &str,
    member: &str,
    call_arity: Option<usize>,
    ctx: &ScanCtx<'_>,
) -> bool {
    if receiver_owner == ctx.spec.owner_fq_name.as_deref().unwrap_or_default() {
        return false;
    }
    if receiver_has_direct_member(receiver_owner, member, call_arity, ctx) {
        return true;
    }
    ctx.scala
        .definitions(receiver_owner)
        .find(|unit| unit.is_class())
        .is_some_and(|owner| {
            ctx.scala.get_ancestors(&owner).into_iter().any(|ancestor| {
                receiver_has_direct_member(&ancestor.fq_name(), member, call_arity, ctx)
            })
        })
}

fn receiver_has_direct_member(
    receiver_owner: &str,
    member: &str,
    call_arity: Option<usize>,
    ctx: &ScanCtx<'_>,
) -> bool {
    let member_fqn = format!("{}.{}", scala_normalized_fq_name(receiver_owner), member);
    ctx.analyzer
        .definitions(&member_fqn)
        .any(|unit| receiver_member_applies(&unit, call_arity, ctx))
}

fn receiver_member_applies(unit: &CodeUnit, call_arity: Option<usize>, ctx: &ScanCtx<'_>) -> bool {
    if unit.is_field() {
        return true;
    }
    if !unit.is_function() || ctx.spec.kind != TargetKind::Method {
        return false;
    }
    match call_arity {
        Some(call_arity) => method_call_arity_applies(ctx.scala, unit, call_arity),
        None => method_signature_arity(ctx.scala, unit).is_none_or(|arity| arity == 0),
    }
}

fn is_locally_shadowed(ctx: &ScanCtx<'_>, name: &str) -> bool {
    if !ctx.bindings.is_shadowed(name) {
        return false;
    }
    !ctx.bindings
        .resolve_symbol(name)
        .as_precise()
        .is_some_and(|targets| {
            targets.iter().any(|binding| {
                binding
                    .declaration_owner
                    .as_ref()
                    .is_some_and(|owner| ctx.spec.owner.as_ref() == Some(owner))
            })
        })
}

fn is_unresolved_local_shadow(ctx: &ScanCtx<'_>, name: &str) -> bool {
    ctx.bindings.is_shadowed(name) && ctx.bindings.resolve_symbol(name).is_unknown()
}

fn receiver_binding_matches(node: Node<'_>, qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.owner.is_none() {
        return false;
    }
    if !member_call_arity_matches(node, ctx) {
        return false;
    }
    let resolution = ctx.bindings.resolve_symbol(qualifier);
    if let Some(targets) = resolution
        .as_precise()
        .filter(|targets| !targets.is_empty())
    {
        // Multiple precise receiver owners originate from a parser-proven union type. Scala
        // selects a member shared by every alternative through their common ancestor; a
        // compatible field override on one alternative does not erase that inherited family.
        if targets.len() > 1 {
            return targets.iter().all(|binding| {
                binding
                    .receiver_type
                    .as_deref()
                    .is_some_and(|target| receiver_owner_inherits_target_family(target, ctx))
            });
        }
        if targets.iter().all(|binding| {
            binding
                .receiver_type
                .as_deref()
                .is_some_and(|target| receiver_owner_matches_target_family(target, ctx))
        }) {
            return true;
        }
    }
    ctx.visibility
        .receiver_fq_name_for(qualifier)
        .is_some_and(|owner_fq_name| ctx.spec.receiver_owner_fq_matches(owner_fq_name))
}

fn receiver_owner_matches_target_family(owner_fq_name: &str, ctx: &ScanCtx<'_>) -> bool {
    let mut owners = ctx
        .scala
        .definitions(owner_fq_name)
        .filter(|unit| unit.is_class());
    let owner = owners.next();
    if owners.next().is_some() {
        return false;
    }
    if ctx.spec.receiver_owner_fq_matches(owner_fq_name) {
        return true;
    }
    if ctx.spec.kind != TargetKind::Method {
        return false;
    }
    let Some(owner) = owner else {
        return false;
    };
    receiver_owner_resolves_to_method_family(owner, ctx)
}

fn receiver_owner_inherits_target_family(owner_fq_name: &str, ctx: &ScanCtx<'_>) -> bool {
    let mut owners = ctx
        .scala
        .definitions(owner_fq_name)
        .filter(|unit| unit.is_class());
    let Some(owner) = owners.next() else {
        return false;
    };
    if owners.next().is_some() {
        return false;
    }
    ctx.spec.owner_fq_matches(owner_fq_name)
        || ctx
            .scala
            .get_ancestors(&owner)
            .iter()
            .any(|ancestor| ctx.spec.owner_fq_matches(&ancestor.fq_name()))
}

fn receiver_owner_resolves_to_method_family(owner: CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    let mut level = vec![owner];
    let mut seen = HashSet::default();
    while !level.is_empty() {
        let mut declaring_owners = Vec::new();
        let mut next = Vec::new();
        for owner in level {
            if !seen.insert(owner.clone()) {
                continue;
            }
            let member_fqn = format!(
                "{}.{}",
                scala_normalized_fq_name(&owner.fq_name()),
                ctx.spec.member_name
            );
            let direct = ctx
                .scala
                .definitions(&member_fqn)
                .filter(|member| ctx.scala.parent_of(member).as_ref() == Some(&owner))
                .collect::<Vec<_>>();
            if direct.iter().any(CodeUnit::is_field) {
                return false;
            }
            if direct.iter().any(CodeUnit::is_function) {
                declaring_owners.push(owner);
            } else {
                next.extend(ctx.scala.get_direct_ancestors(&owner));
            }
        }
        if !declaring_owners.is_empty() {
            return declaring_owners.into_iter().all(|declaring_owner| {
                ctx.spec.owner_fq_matches(&declaring_owner.fq_name())
                    || ctx
                        .scala
                        .get_ancestors(&declaring_owner)
                        .iter()
                        .any(|ancestor| ctx.spec.owner_fq_matches(&ancestor.fq_name()))
            });
        }
        level = next;
    }
    false
}

fn enclosing_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    ctx.class_ranges
        .find_in_enclosing_units(node.start_byte(), |owner| {
            ctx.spec
                .receiver_owner_fq_matches(&owner.fq_name())
                .then_some(())
        })
        .is_some()
}

fn enclosing_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    ctx.class_ranges.enclosing_unit(node.start_byte()).cloned()
}

fn enclosing_owner_fq_name(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    enclosing_owner(node, ctx).map(|owner| owner.fq_name())
}

fn member_call_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let shape = call_site_shape_with_method_value_context(node, ctx);
    member_call_shape_matches(shape.as_ref(), ScalaCallableSiteRole::Ordinary, ctx)
}

fn call_site_shape_with_method_value_context(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<ScalaCallSiteShape> {
    if let Some(shape) = call_site_shape_for_reference(node) {
        let method_value_arity = applied_expression_for_reference(node).and_then(|expression| {
            match companion_method_value_context(expression, ctx) {
                ScalaMethodValueContext::Function(arity) => Some(arity),
                ScalaMethodValueContext::Unknown | ScalaMethodValueContext::Incompatible => None,
            }
        });
        return Some(shape.with_method_value_arity(method_value_arity));
    }
    match companion_method_value_context(node, ctx) {
        ScalaMethodValueContext::Function(arity) => Some(ScalaCallSiteShape {
            lists: Vec::new(),
            method_value_arity: Some(arity),
        }),
        ScalaMethodValueContext::Unknown | ScalaMethodValueContext::Incompatible => None,
    }
}

fn member_call_shape_matches(
    call_shape: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
    ctx: &ScanCtx<'_>,
) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::Method | TargetKind::Constructor) {
        return true;
    }
    if !ctx.spec.callable_alternatives.is_empty() {
        let unique_callable =
            call_shape.map_or(ctx.spec.unapplied_reference_is_unambiguous, |shape| {
                ctx.spec
                    .callable_alternatives
                    .iter()
                    .filter(|alternative| {
                        scala_callable_alternative_is_candidate(
                            alternative.role,
                            &alternative.shape,
                            shape,
                            site_role,
                        )
                    })
                    .count()
                    == 1
            });
        return ctx.spec.callable_alternatives.iter().any(|alternative| {
            scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                call_shape,
                site_role,
                unique_callable,
            )
        });
    }
    let fallback_shape = ctx
        .spec
        .callable_arity
        .map(|arity| vec![ScalaCallableParameterList::explicit(arity)])
        .unwrap_or_default();
    let fallback_role = if ctx.spec.kind == TargetKind::Constructor {
        if ctx.spec.target.is_synthetic() {
            ScalaCallableRole::PrimaryConstructor
        } else {
            ScalaCallableRole::SecondaryConstructor
        }
    } else {
        ScalaCallableRole::Ordinary
    };
    scala_callable_alternative_matches(
        fallback_role,
        &fallback_shape,
        call_shape,
        site_role,
        ctx.spec.unapplied_reference_is_unambiguous,
    )
}

fn ordinary_callable_shape_matches(
    declared: &[ScalaCallableParameterList],
    call_arities: Option<&[usize]>,
    unique_callable: bool,
) -> bool {
    let actual = call_arities.map(ScalaCallSiteShape::ordinary);
    scala_callable_shape_matches(
        declared,
        actual.as_ref(),
        ScalaCallableUsePolicy::OrdinaryMethod,
        unique_callable,
    )
}

fn function_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_arity) = ctx.spec.arity else {
        return true;
    };
    let mut cursor = node.walk();
    let arity = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "parameters")
        .and_then(|parameters| parenthesized_arity(node_text(parameters, ctx.source)))
        .unwrap_or(0);
    arity == target_arity
}
