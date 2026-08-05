use crate::analyzer::cpp::{
    CppSentinelRecoveredClass, cpp_export_macro_token, cpp_sentinel_recovered_scope_for_node,
    recovered_macro_return_type_node,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::cpp_call_match::{
    CppArgType, cpp_filter_candidates_by_args, cpp_literal_arg_type, cpp_signature_param_types,
    cpp_type_text_pointer_depth, normalize_cpp_type_name,
};
use crate::analyzer::usages::cpp_graph::hits::{
    enclosing_context, is_member_field_own_declarator, push_definition_hit, push_hit,
    push_recursive_reference_hit, push_self_receiver_hit, push_type_hit,
    push_unproven_definition_hit, push_unproven_hit,
};
use crate::analyzer::usages::cpp_graph::resolver::*;
use crate::analyzer::usages::cpp_graph::syntax::explicit_qualified_callable_value;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CodeUnit, CppAnalyzer, IAnalyzer, ProjectFile, Range,
    cpp_callable_definitions_share_identity_evidence, cpp_node_text as node_text,
};
use crate::hash::{HashMap, HashSet};
#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::Node;

#[cfg(test)]
thread_local! {
    static LEXICAL_SCOPE_RECONSTRUCTIONS_FOR_TEST: Cell<usize> = const { Cell::new(0) };
}

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct ScanCtx<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) visibility: &'a VisibilityIndex<'a>,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    ordinary_type_imports: OrdinaryTypeImportCell,
    recovered_sentinel_classes: &'a [CppSentinelRecoveredClass],
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) target_group: &'a HashSet<CodeUnit>,
    type_reference_component_names: HashSet<String>,
    pub(super) target_declaration_ranges: Vec<Range>,
    orphaned_namespaces: Vec<OrphanedNamespaceEnvelope>,
    pub(super) bindings: LocalInferenceEngine<CppScanBinding>,
    local_shadows: LocalInferenceEngine<()>,
    using_enum_owners: ScopedUsingEnumOwners,
    semantic_using_enum_owners: SemanticUsingEnumOwners,
    needs_using_enum_member_resolution: bool,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: RefCell<HashMap<(usize, usize), EnclosingContext>>,
    pub(super) enclosing_owner_cache: RefCell<HashMap<CodeUnit, Option<CodeUnit>>>,
    lexical_scope_cache: LexicalScopeCache,
    lexical_free_function_cache: RefCell<HashMap<(String, String), bool>>,
    member_owner_cache: RefCell<HashMap<CodeUnit, EnclosingMemberOwnerResolution>>,
    global_field_internal_linkage_cache: RefCell<HashMap<CodeUnit, bool>>,
    receiver_canonical_type_cache: RefCell<HashMap<CodeUnit, Option<CodeUnit>>>,
}

impl ScanCtx<'_> {
    fn recovered_sentinel_scope(&self, node: Node<'_>) -> Option<Vec<String>> {
        cpp_sentinel_recovered_scope_for_node(node, self.source, self.recovered_sentinel_classes)
    }
}

#[derive(Clone, Default)]
pub(super) struct EnclosingContext {
    pub(super) enclosing: Option<CodeUnit>,
    pub(super) owner: Option<CodeUnit>,
}

pub(super) fn prepare_file(
    cpp: &CppAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    cpp.prepared_syntax(file)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_prepared_file(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    recovered_sentinel_classes: &[CppSentinelRecoveredClass],
    spec: &TargetSpec,
    target_group: &HashSet<CodeUnit>,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    let needs_using_enum_member_resolution = spec.enum_owner_kind == EnumOwnerKind::Scoped;
    let target_declaration_ranges = if spec.kind == TargetKind::Type {
        target_group
            .iter()
            .filter(|target| target.source() == file && same_logical_symbol(target, &spec.target))
            .flat_map(|target| analyzer.ranges(target))
            .collect()
    } else if spec.target.source() == file {
        analyzer.ranges(&spec.target)
    } else {
        Vec::new()
    };
    let ordinary_type_imports = initialized_ordinary_type_imports(
        prepared.tree().root_node(),
        analyzer,
        visibility,
        file,
        prepared.source(),
    );
    let type_reference_component_names = if spec.kind == TargetKind::Type {
        visibility.visible_type_reference_component_names_for_target(analyzer, file, &spec.target)
    } else {
        HashSet::default()
    };
    let orphaned_namespaces = if spec.kind == TargetKind::Type
        && prepared.tree().root_node().has_error()
    {
        collect_orphaned_namespace_type_envelopes(prepared.tree().root_node(), prepared.source())
    } else {
        Vec::new()
    };
    let mut ctx = ScanCtx {
        analyzer,
        visibility,
        file,
        source: prepared.source(),
        ordinary_type_imports,
        recovered_sentinel_classes,
        line_starts: prepared.line_starts(),
        spec,
        target_group,
        type_reference_component_names,
        target_declaration_ranges,
        orphaned_namespaces,
        bindings: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        local_shadows: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        using_enum_owners: ScopedUsingEnumOwners::new(),
        semantic_using_enum_owners: SemanticUsingEnumOwners::new(),
        needs_using_enum_member_resolution,
        hits: state.hits,
        unproven_hits: state.unproven_hits,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: RefCell::new(HashMap::default()),
        enclosing_owner_cache: RefCell::new(HashMap::default()),
        lexical_scope_cache: RefCell::new(HashMap::default()),
        lexical_free_function_cache: RefCell::new(HashMap::default()),
        member_owner_cache: RefCell::new(HashMap::default()),
        global_field_internal_linkage_cache: RefCell::new(HashMap::default()),
        receiver_canonical_type_cache: RefCell::new(HashMap::default()),
    };
    if needs_using_enum_member_resolution {
        collect_semantic_using_enums(prepared.tree().root_node(), &mut ctx);
    }
    scan_node(prepared.tree().root_node(), &mut ctx);
}

enum UsingEnumDeclarationScope {
    Block,
    Class(CodeUnit),
    Namespace(Vec<String>),
    UnsupportedClass,
}

fn using_enum_declaration_scope(node: Node<'_>, ctx: &ScanCtx<'_>) -> UsingEnumDeclarationScope {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "compound_statement"
                | "function_definition"
                | "lambda_expression"
                | "for_statement"
                | "while_statement"
                | "if_statement"
        ) {
            return UsingEnumDeclarationScope::Block;
        }
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            let resolution = enclosing_lexical_scope_components(
                node,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
            );
            if let LexicalScopeResolution::Resolved(components) = resolution
                && let LexicalTypeResolution::Resolved { unit, .. } =
                    ctx.visibility.resolve_type_components_lexically(
                        ctx.analyzer,
                        ctx.file,
                        &components,
                        true,
                        &[],
                    )
            {
                return UsingEnumDeclarationScope::Class(unit);
            }
            return UsingEnumDeclarationScope::UnsupportedClass;
        }
        current = parent.parent();
    }
    UsingEnumDeclarationScope::Namespace(enclosing_namespace_components(node, ctx.source))
}

fn collect_semantic_using_enums(root: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "using_declaration"
            && let LexicalTypeResolution::Resolved { unit, .. } =
                resolve_using_enum_declaration_owner(
                    node,
                    ctx.analyzer,
                    ctx.visibility,
                    &ctx.ordinary_type_imports,
                    ctx.file,
                    ctx.source,
                )
        {
            match using_enum_declaration_scope(node, ctx) {
                UsingEnumDeclarationScope::Block => {}
                UsingEnumDeclarationScope::Class(class) => {
                    ctx.semantic_using_enum_owners.import_class(class, unit);
                }
                UsingEnumDeclarationScope::Namespace(namespace) => {
                    ctx.semantic_using_enum_owners.import_namespace(
                        namespace,
                        node.start_byte(),
                        unit,
                    );
                }
                UsingEnumDeclarationScope::UnsupportedClass => {}
            }
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let enters_scope = matches!(
        node.kind(),
        "compound_statement"
            | "function_definition"
            | "lambda_expression"
            | "for_statement"
            | "for_range_loop"
            | "while_statement"
            | "if_statement"
    );
    let enters_using_enum_scope = ctx.needs_using_enum_member_resolution
        && (enters_scope
            || matches!(
                node.kind(),
                "namespace_definition" | "class_specifier" | "struct_specifier" | "union_specifier"
            ));
    if enters_scope {
        ctx.bindings.enter_scope();
        ctx.local_shadows.enter_scope();
    }
    if enters_using_enum_scope {
        ctx.using_enum_owners.enter_scope();
    }

    seed_declarations(node, ctx);
    maybe_record_hit(node, ctx);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }

    if enters_scope {
        ctx.bindings.exit_scope();
        ctx.local_shadows.exit_scope();
    }
    if enters_using_enum_scope {
        ctx.using_enum_owners.exit_scope();
    }
}

fn seed_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if crate::analyzer::cpp::is_direct_recovered_exported_class_field_declaration(node, ctx.source)
        || (ctx.spec.kind != TargetKind::Type
            && indexed_recovered_class_field_declaration(node, ctx))
    {
        return;
    }
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration" => seed_typed_binding(node, ctx),
        "declaration" | "field_declaration" => seed_variable_declaration(node, ctx),
        "for_range_loop" => seed_range_binding(node, ctx),
        "using_declaration" => seed_using_enum(node, ctx),
        _ => {}
    }
}

fn indexed_recovered_class_field_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if node.kind() != "declaration"
        || !has_function_scope_ancestor(node)
        || has_ancestor_kind(node, "lambda_expression")
        || !(has_recovered_class_shape_ancestor(node)
            || has_malformed_wrapper_function_definition_ancestor(node))
    {
        return false;
    }
    let context = enclosing_context(node, ctx);
    context.enclosing.as_ref().is_some_and(CodeUnit::is_field)
        && context.owner.as_ref().is_some_and(CodeUnit::is_class)
}

fn seed_using_enum(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !ctx.needs_using_enum_member_resolution {
        return;
    }
    if let LexicalTypeResolution::Resolved { unit, .. } = resolve_using_enum_declaration_owner(
        node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
    ) && matches!(
        using_enum_declaration_scope(node, ctx),
        UsingEnumDeclarationScope::Block
    ) {
        ctx.using_enum_owners.import(unit);
    }
}

fn seed_variable_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    // Class and local-struct fields are resolved from their enclosing owner
    // when they appear as an unqualified receiver. Seeding them into the
    // function-wide binding scope would make same-spelled fields from sibling
    // owners overwrite one another before the owner-aware path runs.
    if node.kind() == "field_declaration" {
        return;
    }
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node));
    let type_text = type_node.map(|node| node_text(node, ctx.source).to_string());
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        let Some(name) = extract_variable_name(declarator, ctx.source) else {
            continue;
        };
        if declarator.kind() == "function_declarator"
            && !constructor_style_local_declaration(
                ctx.visibility,
                ctx.file,
                ctx.source,
                declarator,
                type_text.as_deref(),
                &ctx.bindings,
            )
        {
            if node.kind() == "declaration" && has_function_scope_ancestor(node) {
                ctx.local_shadows.declare_shadow(name);
            }
            continue;
        }
        if node.kind() == "declaration" && has_function_scope_ancestor(node) {
            ctx.local_shadows.declare_shadow(name.clone());
        }
        if ctx.spec.kind == TargetKind::Type {
            ctx.bindings.declare_shadow(name);
            continue;
        }
        let value = child.child_by_field_name("value");
        seed_binding_from_type_or_value(&name, type_node, value, ctx);
    }
}

fn seed_typed_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !parameter_belongs_to_callable_scope(node) {
        return;
    }
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    if has_function_scope_ancestor(node) {
        ctx.local_shadows.declare_shadow(name.clone());
    }
    if ctx.spec.kind == TargetKind::Type {
        ctx.bindings.declare_shadow(name);
        return;
    }
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node));
    seed_binding_from_type_or_value(&name, type_node, None, ctx);
}

fn seed_range_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    if has_function_scope_ancestor(node) {
        ctx.local_shadows.declare_shadow(name.clone());
    }
    if ctx.spec.kind == TargetKind::Type {
        ctx.bindings.declare_shadow(name);
        return;
    }
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node));
    seed_binding_from_type_or_value(&name, type_node, None, ctx);
}

fn has_function_scope_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        // Error recovery can wrap a complete namespace in a bogus outer
        // `function_definition` (for example when an object-like namespace
        // macro is parsed as a return type).  Declarations below that
        // namespace are still namespace-scoped: do not let the malformed
        // callable envelope seed them as local shadows.  A real function
        // body is encountered before its enclosing namespace, so this keeps
        // ordinary local binding detection unchanged.
        if parent.kind() == "namespace_definition" {
            return false;
        }
        if parent.kind() == "function_definition" {
            // The malformed sentinel envelope is not a callable scope. Its
            // body may contain a recovered namespace (or, in a smaller error
            // tree, only an ERROR node standing in for that namespace), so
            // declarations directly below it must remain namespace-scoped.
            // Real nested functions are encountered first and still seed
            // ordinary local bindings.
            return !is_malformed_wrapper_function_definition(parent);
        }
        if parent.kind() == "lambda_expression" {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn seed_binding_from_type_or_value(
    name: &str,
    type_node: Option<Node<'_>>,
    value: Option<Node<'_>>,
    ctx: &mut ScanCtx<'_>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_node
        .filter(|node| normalize_type_text(node_text(*node, ctx.source)) != "auto")
        .map(|node| {
            let text = node_text(node, ctx.source);
            let name = normalize_cpp_type_name(text);
            // Bare type names need lexical ownership before the coarse visible-name
            // fallback (two namespaces can each declare `CopyResult`). Template
            // references keep the specialization-aware resolver first because a
            // component-only lexical lookup cannot rank partial specializations.
            let lexical_scope = ctx.recovered_sentinel_scope(node).or_else(|| {
                if cpp_template_reference_arguments(node, ctx.source).is_some() {
                    return None;
                }
                match enclosing_lexical_scope_components(
                    node,
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    ctx.source,
                ) {
                    LexicalScopeResolution::Resolved(scope) => Some(scope),
                    LexicalScopeResolution::Ambiguous | LexicalScopeResolution::Missing => None,
                }
            });
            let unit = lexical_scope
                .as_deref()
                .and_then(|scope| resolve_seed_type_node_lexically(node, ctx, scope))
                .or_else(|| {
                    match ctx
                        .visibility
                        .resolve_type_node_result(ctx.file, node, ctx.source)
                    {
                        Ok(Some(unit)) => Some(unit),
                        Ok(None) => ctx
                            .visibility
                            .canonical_type_for_reference(ctx.file, &name)
                            .or_else(|| ctx.visibility.resolve_type(ctx.file, &name)),
                        Err(()) => None,
                    }
                });
            CppScanBinding::from_type_name(name.clone(), unit, cpp_type_text_pointer_depth(text))
        })
        .or_else(|| value.and_then(|value| infer_type_from_value(value, ctx)));

    if let Some(resolved) = resolved {
        ctx.bindings.seed_symbol(name.to_string(), resolved);
    } else if let Some(value) = value
        && value.kind() == "identifier"
    {
        ctx.bindings
            .alias_symbol(name.to_string(), node_text(value, ctx.source));
    } else {
        ctx.bindings.declare_shadow(name.to_string());
    }
}

fn resolve_seed_type_node_lexically(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    scope: &[String],
) -> Option<CodeUnit> {
    let (components, global) = type_reference_components(node, ctx.source)?;
    match ctx.visibility.resolve_type_components_lexically(
        ctx.analyzer,
        ctx.file,
        &components,
        global,
        scope,
    ) {
        LexicalTypeResolution::Resolved { unit, .. } => Some(unit),
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => None,
    }
}

const MAX_RECEIVER_CALL_RESOLUTION_DEPTH: usize = 32;

fn infer_type_from_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CppScanBinding> {
    infer_type_from_value_with_budget(node, ctx, MAX_RECEIVER_CALL_RESOLUTION_DEPTH)
}

fn infer_type_from_value_with_budget(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    remaining_call_depth: usize,
) -> Option<CppScanBinding> {
    match node.kind() {
        "new_expression" | "call_expression" if remaining_call_depth == 0 => {
            infer_cpp_initializer_binding(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
                node,
                None,
            )
        }
        "new_expression" | "call_expression" => infer_cpp_initializer_binding(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
            Some(&|receiver, source| {
                receiver_type_units_with_budget(receiver, source, ctx, remaining_call_depth - 1)
            }),
        ),
        "initializer_list" => None,
        "identifier" => {
            let resolved = ctx.bindings.resolve_symbol(node_text(node, ctx.source));
            resolved
                .as_precise()?
                .iter()
                .find(|binding| binding.unit.as_ref().is_some_and(CodeUnit::is_class))
                .cloned()
        }
        _ => {
            let text = node_text(node, ctx.source);
            let name = normalize_cpp_type_name(text);
            ctx.visibility
                .resolve_type(ctx.file, &name)
                .map(|unit| CppScanBinding::from_unit(unit, 0))
        }
    }
}

fn maybe_record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_type_hit(node, ctx),
        TargetKind::Constructor => maybe_record_constructor_hit(node, ctx),
        TargetKind::FreeFunction => maybe_record_free_function_hit(node, ctx),
        TargetKind::Method => maybe_record_method_hit(node, ctx),
        TargetKind::GlobalField => maybe_record_global_field_hit(node, ctx),
        TargetKind::MemberField => maybe_record_member_field_hit(node, ctx),
    }
}

fn maybe_record_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(return_type) = recovered_macro_return_type_node(node, ctx.source) {
        maybe_record_recovered_macro_return_type_hit(return_type, ctx);
        return;
    }
    if let Some((owner, _member_pointer)) = member_pointer_owner_components(node, ctx.source) {
        // A member-pointer owner can itself end in a nested alias, as in
        // `type_identity<T>::type::*`. Resolving the complete owner
        // canonicalizes that alias to its underlying type and loses the alias
        // declaration that inverse lookup is targeting. Retain every
        // structurally proven qualifier component before asking for the
        // canonical owner type.
        if ctx
            .analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(&ctx.spec.target))
            && canonical_cpp_scope_components(&ctx.spec.target) == owner.names
            && let Some(terminal) = owner.nodes.last().copied()
        {
            if !member_pointer_alias_owner_prefix_matches(node, &owner, ctx) {
                return;
            }
            if ctx.visibility.external_type_candidate_visible_in_context(
                ctx.analyzer,
                ctx.file,
                &ctx.spec.target,
                terminal,
            ) || ctx
                .visibility
                .dependent_member_pointer_alias_visible_in_context(
                    ctx.analyzer,
                    ctx.file,
                    &ctx.spec.target,
                    &owner.names,
                    terminal,
                )
            {
                *ctx.raw_match_count += 1;
                push_type_hit(terminal, ctx);
            }
            return;
        }
        if let Some(scopes) = static_qualifier_type_scopes_for_components(node, owner, ctx) {
            *ctx.raw_match_count += 1;
            for scope in scopes {
                push_type_hit(scope, ctx);
            }
            return;
        }
        return;
    }
    if node.kind() == "call_expression" {
        maybe_record_direct_temporary_type_hit(node, ctx);
        return;
    }
    if node.parent().is_some_and(|parent| {
        parent.kind() == "operator_cast"
            && parent
                .child_by_field_name("type")
                .is_some_and(|target| same_node(target, node))
    }) {
        return;
    }
    if let Some(hit) = target_guided_static_cast_alias_type_descriptor(node, ctx) {
        *ctx.raw_match_count += 1;
        push_type_hit(hit, ctx);
        return;
    }
    if matches!(node.kind(), "identifier" | "template_function")
        && call_for_function_node(node).is_some()
    {
        return;
    }
    if node.kind() == "using_declaration" {
        let (resolution, type_node) =
            if let Some(type_node) = using_enum_declaration_type_node(node) {
                (
                    resolve_using_enum_declaration_owner(
                        node,
                        ctx.analyzer,
                        ctx.visibility,
                        &ctx.ordinary_type_imports,
                        ctx.file,
                        ctx.source,
                    ),
                    type_node,
                )
            } else if let Some(type_node) = ordinary_using_declaration_type_node(node) {
                (
                    resolve_ordinary_using_declaration_owner(
                        node,
                        ctx.analyzer,
                        ctx.visibility,
                        ctx.file,
                        ctx.source,
                    ),
                    type_node,
                )
            } else {
                return;
            };
        if let LexicalTypeResolution::Resolved { unit, .. } = resolution
            && same_visible_symbol(&unit, &ctx.spec.target)
        {
            *ctx.raw_match_count += 1;
            push_type_hit(type_node, ctx);
        }
        return;
    }
    if let Some((type_node, _)) = recovered_macro_decorated_type_node(node) {
        // A missing `::` can put either the macro or the real type in the
        // recovered scope. Resolve both candidates against this inverse
        // target before choosing one: a unique match is routed through the
        // ordinary target-guided path, while two distinct matches are
        // ambiguous and must not invent a hit. With no target match, retain
        // the existing recovered-scope path below for its conservative
        // fallback behaviour.
        let mut matching = Vec::new();
        for candidate in [node, type_node] {
            if matching
                .iter()
                .any(|existing| same_node(*existing, candidate))
            {
                continue;
            }
            if let LexicalTypeResolution::Resolved {
                unit, candidates, ..
            } = resolve_type_node_lexically_for_target(
                candidate,
                ctx.analyzer,
                ctx.visibility,
                &ctx.ordinary_type_imports,
                ctx.file,
                ctx.source,
                &ctx.spec.target,
                Some(&ctx.lexical_scope_cache),
                ctx.recovered_sentinel_scope(candidate).as_deref(),
            ) && type_resolution_matches_target(candidate, &unit, &candidates, ctx)
            {
                matching.push(candidate);
            }
        }
        match matching.as_slice() {
            [candidate] if !same_node(*candidate, node) => {
                maybe_record_type_hit(*candidate, ctx);
                return;
            }
            [candidate] if same_node(*candidate, node) => {}
            [] => {}
            _ => return,
        }
    }
    let recovered_type = recovered_macro_decorated_declarator_type(node).is_some();
    if !recovered_type
        && !matches!(
            node.kind(),
            "type_identifier" | "qualified_identifier" | "scoped_type_identifier" | "template_type"
        )
    {
        return;
    }
    if type_reference_components(node, ctx.source).is_some_and(|(components, global)| {
        components.len() == 1 && !global && local_type_alias_shadows(node, ctx)
    }) {
        return;
    }
    if !recovered_type
        && matches!(node.kind(), "qualified_identifier" | "scoped_identifier")
        && is_declaration_name(node)
        && let Some(owners) = out_of_line_member_definition_owner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
        )
    {
        let terminal_destructor = out_of_line_destructor_type_reference(node);
        let innermost = owners.innermost().map(|(_, owner)| owner.clone());
        *ctx.raw_match_count += 1;
        let mut matched_owner = false;
        for (owner_node, owner) in owners.owners {
            if same_visible_symbol(&owner, &ctx.spec.target) {
                matched_owner = true;
                push_hit(owner_node, ctx);
            }
        }
        if !matched_owner && let Some(scopes) = target_guided_qualifier_type_scopes(node, ctx) {
            for scope in scopes {
                push_hit(scope, ctx);
            }
        }
        if let Some(terminal_destructor) = terminal_destructor
            && innermost
                .as_ref()
                .is_some_and(|owner| same_visible_symbol(owner, &ctx.spec.target))
        {
            push_hit(terminal_destructor, ctx);
        }
        return;
    }
    // A qualified template-id is represented as a qualified_identifier whose
    // name child is the template_type. Resolve the complete qualified
    // reference from that inner template node below; handling the outer node
    // independently would either lose the qualifier or emit a duplicate,
    // wider hit range.
    if ctx.visibility.is_template_specialization(&ctx.spec.target)
        && node.kind() == "qualified_identifier"
        && node
            .child_by_field_name("name")
            .is_some_and(|name| name.kind() == "template_type")
    {
        return;
    }
    if !recovered_type && is_nested_type_node(node) {
        // A concrete template specialization can be absent from the coarse
        // per-file component-name index: that index contains the primary name
        // while this recovered child may expose only the malformed template
        // leaf.  Resolve the complete enclosing template before applying the
        // component prefilter so an exact target candidate can prove this
        // reference.  Non-specialization targets retain the cheap gate.
        let nested_template = if node.kind() == "template_type" {
            Some(node)
        } else {
            node.parent().filter(|parent| {
                parent.kind() == "template_type" && parent.child_by_field_name("name") == Some(node)
            })
        };
        // Concrete specializations need their nested template-id inspected.
        // An ordinary alias application does too when it is itself the scope
        // of a member-qualified type, because the enclosing node denotes the
        // member rather than the alias. In every other primary/alias shape the
        // enclosing structured type owns the hit range; descending would emit
        // a duplicate terminal subrange.
        let nested_alias_qualifier = nested_template.is_some_and(|template| {
            let enclosing_qualified_type_owns_range = template.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
                ) && parent.child_by_field_name("name") == Some(template)
            });
            let Some(alias_provider) = ctx.analyzer.type_alias_provider() else {
                return false;
            };
            let Some(name) = template_reference_name_node(template) else {
                return false;
            };
            let alias_candidates = ctx
                .visibility
                .visible_identifier_candidates(ctx.file, node_text(name, ctx.source))
                .filter(|candidate| alias_provider.is_type_alias(candidate))
                .cloned()
                .collect::<Vec<_>>();
            let direct_target_alias_visible = !alias_candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
                || ctx.visibility.external_type_candidate_visible_in_context(
                    ctx.analyzer,
                    ctx.file,
                    &ctx.spec.target,
                    template,
                );
            !enclosing_qualified_type_owns_range
                && direct_target_alias_visible
                && template_reference_candidates_select_target(
                    template,
                    &alias_candidates,
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    ctx.source,
                    &ctx.spec.target,
                )
        });
        if !ctx.visibility.is_template_specialization(&ctx.spec.target) && !nested_alias_qualifier {
            return;
        }
        if nested_alias_qualifier {
            let template = nested_template.expect("a nested alias qualifier has a template node");
            *ctx.raw_match_count += 1;
            let hit =
                target_guided_missing_alias_rhs_type_leaf(template, ctx).unwrap_or_else(|| {
                    type_reference_hit_node(template, ctx.file, ctx.source, &ctx.bindings)
                });
            push_type_hit(hit, ctx);
            return;
        }
        // For concrete specializations, the visible identifier index can
        // already contain the exact template spelling even when lexical
        // resolution rejects the recovered child (the child itself has no
        // argument list).  That exact candidate is sufficient structured
        // evidence: retain the narrow template-name leaf and avoid emitting
        // the entire template-id range.
        if ctx.visibility.is_template_specialization(&ctx.spec.target)
            && let Some(template) = nested_template
            && template_type_component_preserves_target(
                template,
                &ctx.visibility
                    .visible_identifier_candidates(ctx.file, node_text(template, ctx.source))
                    .cloned()
                    .collect::<Vec<_>>(),
                ctx,
            )
        {
            *ctx.raw_match_count += 1;
            let hit = template
                .child_by_field_name("name")
                .filter(|name| name.kind() == "type_identifier")
                .unwrap_or(template);
            push_type_hit(hit, ctx);
            return;
        }
        if let Some(template) = nested_template
            && let Some(_resolution) = resolve_nested_template_type_for_target(template, ctx)
        {
            *ctx.raw_match_count += 1;
            let hit =
                target_guided_missing_alias_rhs_type_leaf(template, ctx).unwrap_or_else(|| {
                    if ctx.visibility.is_template_specialization(&ctx.spec.target) {
                        template
                            .child_by_field_name("name")
                            .filter(|name| name.kind() == "type_identifier")
                            .unwrap_or(template)
                    } else {
                        type_reference_hit_node(template, ctx.file, ctx.source, &ctx.bindings)
                    }
                });
            push_type_hit(hit, ctx);
        }
        return;
    }
    if !recovered_type && !type_reference_components_may_name_target(node, ctx) {
        return;
    }
    if !recovered_type && let Some(call) = call_for_function_node(node) {
        let direct_target = resolve_qualified_call_target(
            call,
            node,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
        );
        if matches!(direct_target, BareCallTargetResolution::Type(_))
            && let LexicalTypeResolution::Resolved {
                unit, candidates, ..
            } = resolve_type_node_lexically_for_target(
                node,
                ctx.analyzer,
                ctx.visibility,
                &ctx.ordinary_type_imports,
                ctx.file,
                ctx.source,
                &ctx.spec.target,
                Some(&ctx.lexical_scope_cache),
                ctx.recovered_sentinel_scope(node).as_deref(),
            )
            && (same_visible_symbol(&unit, &ctx.spec.target)
                || candidates
                    .iter()
                    .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)))
        {
            *ctx.raw_match_count += 1;
            push_type_hit(
                type_reference_hit_node(node, ctx.file, ctx.source, &ctx.bindings),
                ctx,
            );
        } else if let Some(scopes) = static_qualifier_type_scopes(node, ctx) {
            *ctx.raw_match_count += 1;
            for scope in scopes {
                push_type_hit(scope, ctx);
            }
        }
        return;
    }
    if !recovered_type && is_declaration_name(node) {
        let mut matched_owner = false;
        if let Some(owners) = out_of_line_member_definition_owner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
        ) {
            for (owner_node, owner) in owners.owners {
                if same_visible_symbol(&owner, &ctx.spec.target) {
                    matched_owner = true;
                    *ctx.raw_match_count += 1;
                    push_hit(owner_node, ctx);
                }
            }
        }
        if !matched_owner && let Some(scopes) = target_guided_qualifier_type_scopes(node, ctx) {
            *ctx.raw_match_count += 1;
            for scope in scopes {
                push_hit(scope, ctx);
            }
        }
        return;
    }
    let hit_node = node;
    let text = node_text(hit_node, ctx.source);
    let type_resolution = if hit_node.kind() == "template_type"
        && ctx.visibility.is_template_specialization(&ctx.spec.target)
    {
        resolve_nested_template_type_for_target(hit_node, ctx).unwrap_or_else(|| {
            resolve_type_node_lexically_for_target(
                hit_node,
                ctx.analyzer,
                ctx.visibility,
                &ctx.ordinary_type_imports,
                ctx.file,
                ctx.source,
                &ctx.spec.target,
                Some(&ctx.lexical_scope_cache),
                ctx.recovered_sentinel_scope(hit_node).as_deref(),
            )
        })
    } else {
        resolve_type_node_lexically_for_target(
            hit_node,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
            &ctx.spec.target,
            Some(&ctx.lexical_scope_cache),
            ctx.recovered_sentinel_scope(hit_node).as_deref(),
        )
    };
    match type_resolution {
        LexicalTypeResolution::Resolved {
            unit, candidates, ..
        } if type_resolution_matches_target(node, &unit, &candidates, ctx) => {
            *ctx.raw_match_count += 1;
            if let Some(scopes) = static_qualifier_type_scopes(node, ctx) {
                for scope in scopes {
                    push_type_hit(scope, ctx);
                }
            } else {
                let hit_node = if ctx.visibility.is_template_specialization(&ctx.spec.target) {
                    hit_node
                        .child_by_field_name("name")
                        .filter(|name| name.kind() == "type_identifier")
                        .unwrap_or(hit_node)
                } else if qualified_type_scope_contains_template(hit_node) {
                    function_terminal_node(hit_node)
                } else {
                    hit_node
                };
                push_type_hit(
                    type_reference_hit_node(hit_node, ctx.file, ctx.source, &ctx.bindings),
                    ctx,
                );
            }
            return;
        }
        LexicalTypeResolution::Resolved { .. } => {
            if let Some(scopes) = static_qualifier_type_scopes(node, ctx) {
                *ctx.raw_match_count += 1;
                for scope in scopes {
                    push_type_hit(scope, ctx);
                }
            } else if let Some(leaf) = target_guided_missing_alias_rhs_type_leaf(node, ctx)
                .or_else(|| target_guided_missing_member_alias_type_leaf(node, ctx))
            {
                *ctx.raw_match_count += 1;
                push_type_hit(leaf, ctx);
            }
            return;
        }
        LexicalTypeResolution::Ambiguous => {
            if let Some(scopes) = static_qualifier_type_scopes(node, ctx) {
                *ctx.raw_match_count += 1;
                for scope in scopes {
                    push_type_hit(scope, ctx);
                }
            } else if let Some(leaf) = target_guided_missing_alias_rhs_type_leaf(node, ctx)
                .or_else(|| target_guided_missing_member_alias_type_leaf(node, ctx))
                .or_else(|| target_guided_ambiguous_owned_parameter_alias_type_leaf(node, ctx))
            {
                *ctx.raw_match_count += 1;
                push_type_hit(leaf, ctx);
            }
            return;
        }
        LexicalTypeResolution::Missing => {
            if let Some(leaf) = target_guided_missing_type_leaf(node, ctx) {
                *ctx.raw_match_count += 1;
                push_type_hit(leaf, ctx);
                return;
            }
            let raw_resolution = resolve_type_node_lexically_for_target_without_visibility(
                hit_node,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
                &ctx.spec.target,
            );
            let raw_matches = matches!(
                raw_resolution,
                LexicalTypeResolution::Resolved {
                    ref unit,
                    ref candidates,
                    ..
                } if type_resolution_matches_target(hit_node, unit, candidates, ctx)
            );
            if raw_matches
                || type_node_has_exact_target_identity_without_visibility(
                    hit_node,
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    ctx.source,
                    &ctx.spec.target,
                )
            {
                *ctx.raw_match_count += 1;
                push_unproven_hit(
                    type_reference_hit_node(hit_node, ctx.file, ctx.source, &ctx.bindings),
                    ctx,
                );
                return;
            }
        }
    }
    if ctx
        .visibility
        .parser_alias_resolves_to_type(ctx.analyzer, ctx.file, text, &ctx.spec.target)
    {
        *ctx.raw_match_count += 1;
        push_type_hit(
            type_reference_hit_node(hit_node, ctx.file, ctx.source, &ctx.bindings),
            ctx,
        );
        return;
    }
    if let Some(scopes) = static_qualifier_type_scopes(node, ctx) {
        *ctx.raw_match_count += 1;
        for scope in scopes {
            push_type_hit(scope, ctx);
        }
        return;
    }
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if !ctx.visibility.external_type_candidate_visible_in_context(
        ctx.analyzer,
        ctx.file,
        &ctx.spec.target,
        hit_node,
    ) {
        if let Some(scope) = static_qualifier_name_scope(node, ctx) {
            push_unproven_hit(scope, ctx);
        } else {
            push_unproven_hit(hit_node, ctx);
        }
    }
}

/// Tree-sitter can split a macro-qualified member return type into a phantom
/// field followed by the real function definition.  The declaration visitor
/// discards that phantom field, but its declarator token remains a semantic
/// type reference. Resolve it from the recovered or indexed class scope so an
/// enclosing-class alias remains distinguishable from same-spelled siblings.
fn maybe_record_recovered_macro_return_type_hit(return_type: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let name = node_text(return_type, ctx.source);
    if name != ctx.spec.target.identifier() || ctx.local_shadows.is_shadowed(name) {
        return;
    }
    if physically_visible_type_target(ctx).is_some()
        && type_alias_owner_encloses_structured_reference(return_type, ctx)
        && !nearer_type_name_shadows_structured_reference(return_type, ctx)
        && ctx.visibility.external_type_candidate_visible_in_context(
            ctx.analyzer,
            ctx.file,
            &ctx.spec.target,
            return_type,
        )
    {
        *ctx.raw_match_count += 1;
        push_type_hit(return_type, ctx);
        return;
    }
    let Some(scope) = ctx
        .recovered_sentinel_scope(return_type)
        .or_else(|| indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, return_type))
    else {
        return;
    };
    let components = [name.to_string()];
    let resolution = ctx.visibility.resolve_type_components_lexically(
        ctx.analyzer,
        ctx.file,
        &components,
        false,
        &scope,
    );
    if let LexicalTypeResolution::Resolved {
        unit, candidates, ..
    } = resolution
        && (same_visible_symbol(&unit, &ctx.spec.target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)))
    {
        *ctx.raw_match_count += 1;
        push_type_hit(return_type, ctx);
    }
}

/// Return the class/struct scope in a C++ pointer-to-member declarator such as
/// `double Owner::*member`. Tree-sitter represents the owner as the `scope` of
/// a `qualified_identifier`, while the `name` is a pointer declarator rather
/// than a type node; ordinary type-reference traversal therefore skips it.
fn member_pointer_owner_components<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(QualifiedOwnerComponents<'tree>, Node<'tree>)> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let declarator = node.child_by_field_name("name")?;
    if !matches!(
        declarator.kind(),
        "pointer_type_declarator" | "abstract_pointer_declarator"
    ) {
        return None;
    }
    let scope = node.child_by_field_name("scope")?;
    // Keep this check entirely structural.  C and C++ share the
    // `qualified_identifier` node shape for some recovered declarations, but
    // only the C++ member-pointer form has an actual `::` grammar child
    // between the owner scope and pointer declarator.  Looking at the source
    // slice here would make a recovered C declarator look like a C++ owner
    // merely because its bytes happen to contain the same punctuation.
    let mut saw_scope = false;
    let has_scope_separator = (0..node.child_count()).any(|index| {
        let Some(child) = node.child(index) else {
            return false;
        };
        if same_node(child, scope) {
            saw_scope = true;
            return false;
        }
        saw_scope && !same_node(child, declarator) && child.kind() == "::" && !child.is_missing()
    });
    if !has_scope_separator {
        return None;
    }
    let mut nodes = cpp_name_component_nodes(scope)?;
    let mut outer = node;
    while let Some(parent) = outer.parent()
        && parent.kind() == "qualified_identifier"
        && parent.child_by_field_name("name") == Some(outer)
    {
        let mut prefix = cpp_name_component_nodes(parent.child_by_field_name("scope")?)?;
        prefix.append(&mut nodes);
        nodes = prefix;
        outer = parent;
    }
    let names = nodes
        .iter()
        .map(|component| node_text(*component, source).to_string())
        .collect();
    Some((
        QualifiedOwnerComponents {
            nodes,
            names,
            global: is_globally_qualified_cpp_name(outer),
        },
        outer,
    ))
}

fn member_pointer_alias_owner_prefix_matches(
    node: Node<'_>,
    owner: &QualifiedOwnerComponents<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    let Some((_, owner_prefix)) = owner.names.split_last() else {
        return false;
    };
    let Some(parent) = type_owner_of(ctx.analyzer, &ctx.spec.target) else {
        return false;
    };
    let recovered_scope = ctx.recovered_sentinel_scope(node);
    let resolution = if let Some(recovered_scope) = recovered_scope {
        resolve_type_components_lexically_at_for_target_with_recovered_scope(
            node,
            owner_prefix,
            owner.global,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
            &parent,
            false,
            &recovered_scope,
        )
    } else {
        resolve_type_components_lexically_at_for_target_with_scope_cache(
            node,
            owner_prefix,
            owner.global,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
            &parent,
            false,
            Some(&ctx.lexical_scope_cache),
        )
    };
    let LexicalTypeResolution::Resolved {
        unit, candidates, ..
    } = resolution
    else {
        return false;
    };
    same_member_pointer_owner_identity(&unit, &parent)
        || candidates
            .iter()
            .any(|candidate| same_member_pointer_owner_identity(candidate, &parent))
}

fn same_member_pointer_owner_identity(left: &CodeUnit, right: &CodeUnit) -> bool {
    same_visible_symbol(left, right)
        || (left.kind() == right.kind()
            && left.fq_name() == right.fq_name()
            && left.source() == right.source())
}

/// Resolve a template type nested in a qualified identifier against a concrete
/// type target. The target-guided lexical path intentionally applies a
/// structured candidate prefilter; that prefilter cannot see a partial
/// specialization until the template arguments have selected it. Resolve the
/// complete qualified primary first, then apply the parsed arguments and
/// retain the result only when it is the requested target.
fn resolve_nested_template_type_for_target(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<LexicalTypeResolution> {
    let reference_node = node
        .parent()
        .filter(|parent| {
            parent.kind() == "qualified_identifier"
                && parent.child_by_field_name("name") == Some(node)
        })
        .unwrap_or(node);
    let target_resolution = resolve_type_node_lexically_for_target(
        reference_node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &ctx.spec.target,
        Some(&ctx.lexical_scope_cache),
        ctx.recovered_sentinel_scope(reference_node).as_deref(),
    );
    if let LexicalTypeResolution::Resolved {
        unit, candidates, ..
    } = target_resolution
        && template_reference_candidates_select_target(
            reference_node,
            &candidates,
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            &ctx.spec.target,
        )
    {
        return Some(LexicalTypeResolution::Resolved {
            unit,
            components: Vec::new(),
            candidates,
        });
    }

    let normal_resolution = resolve_type_node_lexically(
        reference_node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
    );
    let LexicalTypeResolution::Resolved {
        unit,
        components,
        candidates,
    } = normal_resolution
    else {
        return None;
    };
    let arguments = cpp_template_reference_arguments(reference_node, ctx.source)?;
    let specialized = ctx
        .visibility
        .resolve_template_arguments(ctx.file, unit.clone(), &arguments)
        .ok()
        .unwrap_or(unit);
    (same_visible_symbol(&specialized, &ctx.spec.target)
        || template_type_component_preserves_target(reference_node, &candidates, ctx))
    .then_some(LexicalTypeResolution::Resolved {
        unit: specialized,
        components,
        candidates,
    })
}

fn type_reference_components_may_name_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some((components, _)) = type_reference_components(node, ctx.source) else {
        return false;
    };
    components
        .iter()
        .any(|component| ctx.type_reference_component_names.contains(component))
}

fn qualified_type_scope_contains_template(node: Node<'_>) -> bool {
    let Some(scope) = node.child_by_field_name("scope") else {
        return false;
    };
    let mut pending = vec![scope];
    while let Some(candidate) = pending.pop() {
        if candidate.kind() == "template_type" {
            return true;
        }
        if matches!(
            candidate.kind(),
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
        ) {
            if let Some(scope) = candidate.child_by_field_name("scope") {
                pending.push(scope);
            }
            if let Some(name) = candidate.child_by_field_name("name") {
                pending.push(name);
            }
        }
    }
    false
}

fn call_for_function_node(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(node))
        .then_some(parent)
}

fn physically_visible_type_target<'a>(ctx: &'a ScanCtx<'_>) -> Option<&'a CodeUnit> {
    ctx.target_group.iter().find(|target| {
        same_logical_symbol(target, &ctx.spec.target)
            && ctx.visibility.is_physically_visible(ctx.file, target)
    })
}

fn target_guided_missing_direct_temporary_type<'tree>(
    function: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let target = physically_visible_type_target(ctx)?;
    let component_nodes = cpp_name_component_nodes(function)?;
    let terminal = component_nodes.last().copied()?;
    if node_text(terminal, ctx.source) != target.identifier() {
        return None;
    }
    let components = component_nodes
        .iter()
        .map(|component| node_text(*component, ctx.source).to_string())
        .collect::<Vec<_>>();
    let indexed_scope = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, function)?;
    indexed_scope_matches_target_name(
        &indexed_scope,
        &components,
        is_globally_qualified_cpp_name(function),
        target,
    )
    .then_some(terminal)
}

fn maybe_record_direct_temporary_type_hit(call: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    if !matches!(
        function.kind(),
        "identifier"
            | "type_identifier"
            | "template_function"
            | "template_type"
            | "qualified_identifier"
            | "scoped_identifier"
            | "scoped_type_identifier"
    ) {
        return;
    }
    if !type_reference_components_may_name_target(function, ctx) {
        return;
    }
    if let Some(scopes) = static_qualifier_type_scopes(function, ctx) {
        *ctx.raw_match_count += 1;
        for scope in scopes {
            push_type_hit(scope, ctx);
        }
        return;
    }
    let terminal = function_terminal_node(function);
    let name = node_text(terminal, ctx.source);
    if name.is_empty() || ctx.local_shadows.is_shadowed(name) {
        return;
    }
    if let Some(enclosing_owner) = structured_enclosing_owner(function, ctx) {
        match resolve_declaring_member_owner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            &enclosing_owner,
            name,
        ) {
            EnclosingMemberOwnerResolution::Owner(owner)
                if matches!(
                    ctx.visibility
                        .visible_member_for_owner_name(ctx.file, &owner, name,),
                    VisibleMemberResolution::Callable(_) | VisibleMemberResolution::AmbiguousKind
                ) =>
            {
                return;
            }
            EnclosingMemberOwnerResolution::Ambiguous => return,
            EnclosingMemberOwnerResolution::Owner(_) | EnclosingMemberOwnerResolution::Missing => {}
        }
    }

    // A type alias used as a direct temporary (`result_type(value)`) is parsed
    // as an ordinary identifier call. Callable lookup can be ambiguous when
    // parser recovery flattens a namespace or same-spelled aliases are
    // visible from sibling distributions. An exact enclosing class owner
    // proves the member alias without treating the call as an arbitrary name;
    // retain the shadow and declaration-visibility guards above and below.
    if ctx
        .analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(&ctx.spec.target))
        && physically_visible_type_target(ctx).is_some()
        && !local_type_alias_shadows(function, ctx)
        && type_alias_owner_matches_structured_reference(function, ctx)
        && ctx.visibility.external_type_candidate_visible_in_context(
            ctx.analyzer,
            ctx.file,
            &ctx.spec.target,
            function,
        )
    {
        *ctx.raw_match_count += 1;
        push_type_hit(terminal, ctx);
        return;
    }

    let call_resolution = resolve_qualified_call_target(
        call,
        function,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
    );
    match call_resolution {
        BareCallTargetResolution::Type(unit) => {
            if same_visible_symbol(&unit, &ctx.spec.target) {
                *ctx.raw_match_count += 1;
                let hit_node = if matches!(
                    function.kind(),
                    "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
                ) {
                    function_terminal_node(function)
                } else {
                    function
                };
                push_type_hit(hit_node, ctx);
                return;
            }
        }
        BareCallTargetResolution::FreeFunctions(units)
            if units.iter().all(|unit| {
                unit.fq_name() == ctx.spec.target.fq_name()
                    && ctx
                        .visibility
                        .callable_is_constructor_declaration(ctx.analyzer, unit)
            }) => {}
        BareCallTargetResolution::Ambiguous => {
            push_unproven_hit(function, ctx);
            return;
        }
        BareCallTargetResolution::FreeFunctions(_)
        | BareCallTargetResolution::UnprovenFreeFunctions(_)
        | BareCallTargetResolution::CallableShadow => return,
        // Generated `.c` includes can leave ordinary callable resolution with
        // no active callable even when target-preserving type resolution can
        // prove the constructor's class. Let the structured type fallback
        // below make that decision.
        BareCallTargetResolution::Missing => {}
    }
    let target_resolution = resolve_type_node_lexically_for_target(
        function,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &ctx.spec.target,
        Some(&ctx.lexical_scope_cache),
        ctx.recovered_sentinel_scope(function).as_deref(),
    );
    match target_resolution {
        LexicalTypeResolution::Resolved {
            unit, candidates, ..
        } if same_visible_symbol(&unit, &ctx.spec.target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
        {
            *ctx.raw_match_count += 1;
            let hit_node = if matches!(
                function.kind(),
                "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
            ) {
                function_terminal_node(function)
            } else {
                function
            };
            push_type_hit(hit_node, ctx);
        }
        LexicalTypeResolution::Missing => {
            if let Some(hit) = target_guided_missing_direct_temporary_type(function, ctx) {
                *ctx.raw_match_count += 1;
                push_type_hit(hit, ctx);
            }
        }
        LexicalTypeResolution::Resolved { .. } | LexicalTypeResolution::Ambiguous => {}
    }
}

pub(in crate::analyzer::usages) enum BareCallTargetResolution {
    Type(CodeUnit),
    FreeFunctions(Vec<CodeUnit>),
    UnprovenFreeFunctions(Vec<CodeUnit>),
    CallableShadow,
    Ambiguous,
    Missing,
}

#[allow(clippy::too_many_arguments)]
fn resolve_qualified_call_target(
    call: Node<'_>,
    function: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
) -> BareCallTargetResolution {
    if matches!(function.kind(), "identifier" | "template_function") {
        return resolve_bare_call_target(
            call,
            function,
            analyzer,
            visibility,
            ordinary_type_imports,
            file,
            source,
        );
    }
    if !matches!(
        function.kind(),
        "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
    ) {
        return BareCallTargetResolution::Missing;
    }
    let terminal = function_terminal_node(function);
    let name = node_text(terminal, source);
    let Some((mut components, _)) = qualified_callable_owner_components(function, source) else {
        return BareCallTargetResolution::Missing;
    };
    components.push(name.to_string());
    let qualified_name = components.join("::");
    let type_resolution = resolve_type_node_lexically(
        function,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
    );
    let same_name_resolves_to_type = matches!(
        &type_resolution,
        LexicalTypeResolution::Resolved {
            unit,
            candidates,
            ..
        } if cpp_name_for(unit) == qualified_name
            || candidates
                .iter()
                .any(|candidate| cpp_name_for(candidate) == qualified_name)
    );
    let candidates = visibility
        .visible_identifier_candidates(file, name)
        .filter(|candidate| {
            candidate.is_function()
                && type_owner_of(analyzer, candidate).is_none()
                && !(same_name_resolves_to_type
                    && visibility.callable_is_constructor_declaration(analyzer, candidate))
                && cpp_name_for(candidate) == qualified_name
                && visibility.declaration_visible_at(analyzer, file, candidate, call.start_byte())
        })
        .cloned()
        .collect::<Vec<_>>();
    if !candidates.is_empty() {
        return resolve_callable_candidates(
            candidates,
            visibility.call_arity_evidence(file, call, source).exact(),
            call.start_byte(),
            analyzer,
            visibility,
            file,
        );
    }
    match type_resolution {
        LexicalTypeResolution::Resolved { unit, .. } => BareCallTargetResolution::Type(unit),
        LexicalTypeResolution::Ambiguous => BareCallTargetResolution::Ambiguous,
        LexicalTypeResolution::Missing => BareCallTargetResolution::Missing,
    }
}

fn binding_free_function_candidates(
    binding: &OrdinaryTypeImport,
    active_bindings: &[&OrdinaryTypeImport],
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    name: &str,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let Some(qualified) = binding.resolved_target_components.as_ref() else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    match binding.target {
        EffectiveUsingTarget::Ordinary { .. } => targets.push(qualified.clone()),
        EffectiveUsingTarget::Namespace { .. } => {
            let mut stack = vec![qualified.clone()];
            let mut visited = HashSet::default();
            while let Some(namespace) = stack.pop() {
                if !visited.insert(namespace.clone()) {
                    continue;
                }
                let mut target = namespace.clone();
                target.push(name.to_string());
                targets.push(target);
                stack.extend(active_bindings.iter().filter_map(|candidate| {
                    (matches!(candidate.target, EffectiveUsingTarget::Namespace { .. })
                        && candidate.namespace_scope.as_deref() == Some(namespace.as_slice()))
                    .then(|| candidate.resolved_target_components.clone())
                    .flatten()
                }));
            }
        }
    }
    targets
        .into_iter()
        .flat_map(|target| {
            let qualified_name = target.join("::");
            visibility
                .visible_identifier_candidates(file, name)
                .filter(move |candidate| {
                    candidate.is_function()
                        && type_owner_of(analyzer, candidate).is_none()
                        && cpp_name_for(candidate) == qualified_name
                        && visibility.declaration_visible_at(
                            analyzer,
                            file,
                            candidate,
                            reference_byte,
                        )
                })
                .cloned()
        })
        .collect()
}

fn dedupe_callable_candidates(candidates: &mut Vec<CodeUnit>) {
    let mut deduped = Vec::with_capacity(candidates.len());
    for candidate in candidates.drain(..) {
        if !deduped
            .iter()
            .any(|existing| same_logical_symbol(existing, &candidate))
        {
            deduped.push(candidate);
        }
    }
    *candidates = deduped;
}

fn resolve_callable_candidates(
    candidates: Vec<CodeUnit>,
    call_arity: Option<usize>,
    reference_byte: usize,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
) -> BareCallTargetResolution {
    let mut candidates = candidates;
    dedupe_callable_candidates(&mut candidates);
    if candidates.is_empty() {
        return BareCallTargetResolution::Missing;
    }
    let Some(call_arity) = call_arity else {
        return BareCallTargetResolution::UnprovenFreeFunctions(candidates);
    };
    let applicable = candidates
        .into_iter()
        .filter(|candidate| {
            visibility
                .callable_arity_at_reference(analyzer, file, candidate, reference_byte)
                .is_some_and(|arity| arity.accepts(call_arity))
        })
        .collect::<Vec<_>>();
    if applicable.is_empty() {
        BareCallTargetResolution::CallableShadow
    } else {
        BareCallTargetResolution::FreeFunctions(applicable)
    }
}

fn resolve_direct_type_candidates(
    candidates: Vec<(CodeUnit, Vec<String>)>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
) -> BareCallTargetResolution {
    let mut logical = Vec::<(CodeUnit, Vec<String>)>::new();
    for candidate in candidates {
        if !logical
            .iter()
            .any(|(existing, _)| same_logical_symbol(existing, &candidate.0))
        {
            logical.push(candidate);
        }
    }
    let [(target, components)] = logical.as_slice() else {
        return if logical.is_empty() {
            BareCallTargetResolution::Missing
        } else {
            BareCallTargetResolution::Ambiguous
        };
    };
    match visibility
        .resolve_imported_type_candidate(analyzer, file, target, components, None, false)
    {
        LexicalTypeResolution::Resolved { unit, .. } => BareCallTargetResolution::Type(unit),
        LexicalTypeResolution::Ambiguous => BareCallTargetResolution::Ambiguous,
        LexicalTypeResolution::Missing => BareCallTargetResolution::Missing,
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::usages) fn resolve_bare_call_target(
    call: Node<'_>,
    function: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
) -> BareCallTargetResolution {
    if !matches!(function.kind(), "identifier" | "template_function") {
        return BareCallTargetResolution::Missing;
    }
    let terminal = function_terminal_node(function);
    let name = node_text(terminal, source);
    if name.is_empty() {
        return BareCallTargetResolution::Missing;
    }
    let call_arity = visibility.call_arity_evidence(file, call, source).exact();
    let lexical_scope =
        match enclosing_lexical_scope_components(function, analyzer, visibility, file, source) {
            LexicalScopeResolution::Resolved(scope) => scope,
            LexicalScopeResolution::Ambiguous => return BareCallTargetResolution::Ambiguous,
            LexicalScopeResolution::Missing => return BareCallTargetResolution::Missing,
        };
    let type_resolution = resolve_type_node_lexically(
        function,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
    );
    let type_components = match &type_resolution {
        LexicalTypeResolution::Resolved { components, .. } => Some(components.as_slice()),
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => None,
    };
    let direct_type_resolution = visibility.resolve_type_components_lexically(
        analyzer,
        file,
        &[name.to_string()],
        false,
        &lexical_scope,
    );
    let direct_type_components = match &direct_type_resolution {
        LexicalTypeResolution::Resolved { components, .. } => Some(components.as_slice()),
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => None,
    };
    let bindings = effective_using_bindings_for_name(
        visibility,
        ordinary_type_imports,
        file,
        root_node(function),
        source,
        name,
    );
    let active_bindings = bindings
        .iter()
        .filter(|binding| {
            effective_using_binding_active(
                binding,
                function,
                &lexical_scope,
                source,
                visibility,
                file,
            )
        })
        .collect::<Vec<_>>();
    let function_guards = preprocessor_guard_environment(function, source);
    let transitive_bindings = bindings
        .iter()
        .filter(|binding| {
            binding.declaration_byte <= function.start_byte()
                && function_guards
                    .as_ref()
                    .is_some_and(|active| binding.required_guards.is_subset(active))
                && visibility.preprocessor_guards_stable_between(
                    file,
                    0,
                    function.start_byte(),
                    &binding.required_guards,
                )
                && (binding.namespace_scope.is_some()
                    || (binding.scope_start <= function.start_byte()
                        && function.end_byte() <= binding.scope_end))
        })
        .collect::<Vec<_>>();
    let mut concrete_depths = active_bindings
        .iter()
        .filter(|binding| binding.namespace_scope.is_none())
        .map(|binding| binding.scope_depth)
        .collect::<Vec<_>>();
    concrete_depths.sort_unstable();
    concrete_depths.dedup();
    for depth in concrete_depths.into_iter().rev() {
        let at_tier = active_bindings
            .iter()
            .copied()
            .filter(|binding| binding.namespace_scope.is_none() && binding.scope_depth == depth);
        let direct = at_tier
            .clone()
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Ordinary { .. }))
            .flat_map(|binding| {
                binding_free_function_candidates(
                    binding,
                    &transitive_bindings,
                    analyzer,
                    visibility,
                    file,
                    name,
                    call.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !direct.is_empty() {
            return resolve_callable_candidates(
                direct,
                call_arity,
                call.start_byte(),
                analyzer,
                visibility,
                file,
            );
        }
        let direct_types = at_tier
            .clone()
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Ordinary { .. }))
            .flat_map(|binding| {
                binding_type_candidates(
                    binding,
                    &transitive_bindings,
                    visibility,
                    file,
                    name,
                    None,
                    call.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !direct_types.is_empty() {
            if call_arity.is_none() {
                return BareCallTargetResolution::Ambiguous;
            }
            return resolve_direct_type_candidates(direct_types, analyzer, visibility, file);
        }
        let directives = at_tier
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Namespace { .. }))
            .flat_map(|binding| {
                binding_free_function_candidates(
                    binding,
                    &transitive_bindings,
                    analyzer,
                    visibility,
                    file,
                    name,
                    call.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !directives.is_empty() {
            return resolve_callable_candidates(
                directives,
                call_arity,
                call.start_byte(),
                analyzer,
                visibility,
                file,
            );
        }
    }
    for prefix_len in (0..=lexical_scope.len()).rev() {
        let mut qualified = lexical_scope[..prefix_len].to_vec();
        qualified.push(name.to_string());
        let same_name_resolves_to_type = direct_type_components
            .is_some_and(|components| components == qualified.as_slice())
            || type_components.is_some_and(|components| components == qualified.as_slice());
        let mut direct = visibility
            .visible_identifier_candidates(file, name)
            .filter(|candidate| {
                candidate.is_function()
                    && type_owner_of(analyzer, candidate).is_none()
                    && !(same_name_resolves_to_type
                        && visibility.callable_is_constructor_declaration(analyzer, candidate))
                    && cpp_name_for(candidate) == qualified.join("::")
                    && visibility.declaration_visible_at(
                        analyzer,
                        file,
                        candidate,
                        call.start_byte(),
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        let at_tier = active_bindings.iter().copied().filter(|binding| {
            binding.namespace_scope.as_deref() == Some(&lexical_scope[..prefix_len])
        });
        direct.extend(
            at_tier
                .clone()
                .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Ordinary { .. }))
                .flat_map(|binding| {
                    binding_free_function_candidates(
                        binding,
                        &transitive_bindings,
                        analyzer,
                        visibility,
                        file,
                        name,
                        call.start_byte(),
                    )
                }),
        );
        if !direct.is_empty() {
            return resolve_callable_candidates(
                direct,
                call_arity,
                call.start_byte(),
                analyzer,
                visibility,
                file,
            );
        }
        let mut direct_types = at_tier
            .clone()
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Ordinary { .. }))
            .flat_map(|binding| {
                binding_type_candidates(
                    binding,
                    &transitive_bindings,
                    visibility,
                    file,
                    name,
                    None,
                    call.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if direct_type_components.is_some_and(|components| components == qualified.as_slice())
            && let LexicalTypeResolution::Resolved {
                unit, components, ..
            } = &direct_type_resolution
        {
            direct_types.push((unit.clone(), components.clone()));
        }
        if !direct_types.is_empty() {
            if call_arity.is_none() {
                return BareCallTargetResolution::Ambiguous;
            }
            return resolve_direct_type_candidates(direct_types, analyzer, visibility, file);
        }
        let directives = at_tier
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Namespace { .. }))
            .flat_map(|binding| {
                binding_free_function_candidates(
                    binding,
                    &transitive_bindings,
                    analyzer,
                    visibility,
                    file,
                    name,
                    call.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !directives.is_empty() {
            return resolve_callable_candidates(
                directives,
                call_arity,
                call.start_byte(),
                analyzer,
                visibility,
                file,
            );
        }
        if type_components.is_some_and(|components| components == qualified.as_slice()) {
            if call_arity.is_none() {
                return BareCallTargetResolution::Ambiguous;
            }
            return match type_resolution {
                LexicalTypeResolution::Resolved { unit, .. } => {
                    BareCallTargetResolution::Type(unit)
                }
                LexicalTypeResolution::Ambiguous => BareCallTargetResolution::Ambiguous,
                LexicalTypeResolution::Missing => BareCallTargetResolution::Missing,
            };
        }
    }
    if call_arity.is_none() {
        return BareCallTargetResolution::Ambiguous;
    }
    match type_resolution {
        LexicalTypeResolution::Resolved { unit, .. } => BareCallTargetResolution::Type(unit),
        LexicalTypeResolution::Ambiguous => BareCallTargetResolution::Ambiguous,
        LexicalTypeResolution::Missing => BareCallTargetResolution::Missing,
    }
}

fn static_qualifier_type_scopes<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Vec<Node<'tree>>> {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier"
    ) {
        return None;
    }
    // `maybe_record_type_hit` rejects nested type nodes before this helper, so
    // this root contains every structured component needed for prefix lookup.
    debug_assert!(!is_nested_type_node(node));
    let qualified = qualified_owner_components(node, ctx.source)?;
    static_qualifier_type_scopes_for_components(node, qualified, ctx)
}

fn static_qualifier_type_scopes_for_components<'tree>(
    node: Node<'tree>,
    qualified: QualifiedOwnerComponents<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Vec<Node<'tree>>> {
    let mut matches = Vec::new();
    let mut inherited_injected_name_is_shadowed = false;
    for component_count in 1..=qualified.names.len() {
        match resolve_type_components_lexically_at_for_target_with_scope_cache(
            node,
            &qualified.names[..component_count],
            qualified.global,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
            &ctx.spec.target,
            false,
            Some(&ctx.lexical_scope_cache),
        ) {
            LexicalTypeResolution::Resolved {
                unit, candidates, ..
            } if same_visible_symbol(&unit, &ctx.spec.target)
                || candidates
                    .iter()
                    .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
            {
                let matched =
                    qualified_type_component_hit_node(qualified.nodes[component_count - 1], node);
                if !template_type_component_preserves_target(matched, &candidates, ctx) {
                    continue;
                }
                if !matches.iter().any(|existing: &Node<'_>| {
                    existing.start_byte() == matched.start_byte()
                        && existing.end_byte() == matched.end_byte()
                }) {
                    matches.push(matched);
                }
            }
            // The ordinary lexical resolver can remain ambiguous when the
            // qualified terminal is an alias whose canonical target is not
            // indexed (for example, `Hash::Digest` aliases an external
            // `std::array`). The target-guided path below still requires one
            // physically visible logical class for every emitted prefix.
            LexicalTypeResolution::Ambiguous => {
                return (!inherited_injected_name_is_shadowed)
                    .then(|| inherited_injected_class_qualifier_scope(node, ctx))
                    .flatten()
                    .map(|scope| vec![scope])
                    .or_else(|| target_guided_qualifier_type_scopes(node, ctx));
            }
            LexicalTypeResolution::Resolved { .. } => {
                inherited_injected_name_is_shadowed |= component_count == 1;
            }
            LexicalTypeResolution::Missing => {}
        }
    }
    if matches.is_empty() {
        (!inherited_injected_name_is_shadowed)
            .then(|| inherited_injected_class_qualifier_scope(node, ctx))
            .flatten()
            .map(|scope| vec![scope])
            .or_else(|| target_guided_qualifier_type_scopes(node, ctx))
    } else {
        Some(matches)
    }
}

fn qualified_type_component_hit_node<'tree>(
    component: Node<'tree>,
    qualified: Node<'tree>,
) -> Node<'tree> {
    let mut current = component;
    while let Some(parent) = current.parent() {
        let is_type_name = matches!(
            parent.kind(),
            "template_type"
                | "qualified_identifier"
                | "scoped_identifier"
                | "scoped_type_identifier"
        ) && parent
            .child_by_field_name("name")
            .is_some_and(|name| same_node(name, current));
        if !is_type_name {
            break;
        }
        current = parent;
        if same_node(parent, qualified) {
            break;
        }
    }
    current
}

fn template_type_component_preserves_target(
    node: Node<'_>,
    candidates: &[CodeUnit],
    ctx: &ScanCtx<'_>,
) -> bool {
    template_reference_candidates_select_target(
        node,
        candidates,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.source,
        &ctx.spec.target,
    )
}

fn template_reference_candidates_select_target(
    node: Node<'_>,
    candidates: &[CodeUnit],
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
) -> bool {
    let Some(arguments) = cpp_template_reference_arguments(node, source) else {
        return !visibility.is_template_specialization(target);
    };
    let direct_template_name =
        template_reference_name_node(node).map(|name| node_text(name, source));
    let named_alias_selects_target = direct_template_name.is_some_and(|name| {
        analyzer.type_alias_provider().is_some_and(|provider| {
            visibility
                .visible_identifier_candidates(file, name)
                .filter(|candidate| provider.is_type_alias(candidate))
                .any(|candidate| {
                    visibility.template_alias_arguments_preserve_target(
                        analyzer, file, candidate, &arguments, target,
                    )
                })
        })
    });
    named_alias_selects_target
        || candidates.iter().any(|candidate| {
            (same_visible_symbol(candidate, target)
                && visibility.is_primary_template(target)
                && direct_template_name == Some(candidate.identifier()))
                || visibility.template_alias_arguments_preserve_target(
                    analyzer, file, candidate, &arguments, target,
                )
                || visibility
                    .resolve_template_arguments(file, candidate.clone(), &arguments)
                    .is_ok_and(|resolved| same_visible_symbol(&resolved, target))
        })
}

fn template_reference_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let template = if node.kind() == "template_type" {
        node
    } else {
        node.child_by_field_name("name")
            .filter(|name| name.kind() == "template_type")?
    };
    template.child_by_field_name("name")
}

fn type_resolution_matches_target(
    node: Node<'_>,
    unit: &CodeUnit,
    candidates: &[CodeUnit],
    ctx: &ScanCtx<'_>,
) -> bool {
    type_resolution_matches_unit_target(node, unit, candidates, &ctx.spec.target, ctx)
}

fn type_resolution_matches_unit_target(
    node: Node<'_>,
    unit: &CodeUnit,
    candidates: &[CodeUnit],
    target: &CodeUnit,
    ctx: &ScanCtx<'_>,
) -> bool {
    if ctx.visibility.is_template_specialization(target)
        && cpp_template_reference_arguments(node, ctx.source).is_some()
    {
        let selected_unit =
            cpp_template_reference_arguments(node, ctx.source).and_then(|arguments| {
                ctx.visibility
                    .resolve_template_arguments(ctx.file, unit.clone(), &arguments)
                    .ok()
            });
        return selected_unit
            .as_ref()
            .is_some_and(|selected| same_visible_symbol(selected, target))
            || template_reference_candidates_select_target(
                node,
                candidates,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
                target,
            );
    }
    same_visible_symbol(unit, target)
        || candidates
            .iter()
            .any(|candidate| same_visible_symbol(candidate, target))
}

fn inherited_injected_class_qualifier_scope<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let qualified = qualified_owner_components(node, ctx.source)?;
    if qualified.global || qualified.names.is_empty() {
        return None;
    }
    let injected_name = &qualified.names[0];
    if !ctx.spec.target.is_class()
        || ctx.spec.target.identifier() != injected_name
        || !ctx
            .visibility
            .is_physically_visible(ctx.file, &ctx.spec.target)
    {
        return None;
    }
    let enclosing_owner = structured_enclosing_owner(node, ctx)?;
    let hierarchy = ctx.analyzer.type_hierarchy_provider()?;
    let mut frontier = hierarchy.get_direct_ancestors(&enclosing_owner);
    let mut visited = HashSet::default();
    while !frontier.is_empty() {
        let mut level_matches = Vec::new();
        let mut next_frontier = Vec::new();
        for raw_owner in frontier {
            let owner = ctx.visibility.canonical_visible_full_type_unit(
                ctx.analyzer,
                ctx.file,
                &raw_owner,
            )?;
            if !visited.insert(owner.clone()) {
                continue;
            }
            if owner.identifier() == injected_name
                && !level_matches
                    .iter()
                    .any(|existing| same_logical_symbol(existing, &owner))
            {
                level_matches.push(owner.clone());
            }
            next_frontier.extend(hierarchy.get_direct_ancestors(&owner));
        }
        if let Some(first) = level_matches.first() {
            if level_matches
                .iter()
                .all(|candidate| same_logical_symbol(candidate, first))
                && same_visible_symbol(first, &ctx.spec.target)
            {
                return qualified.nodes.first().copied();
            }
            // A distinct matching base at the nearest hierarchy tier makes
            // the injected class name ambiguous and hides deeper tiers.
            return None;
        }
        frontier = next_frontier;
    }
    None
}

/// Resolve each qualified type component against the inverse target while
/// preserving C++ lexical-tier precedence and structured alias identity.
fn target_guided_qualifier_type_scopes<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Vec<Node<'tree>>> {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier"
    ) {
        return None;
    }
    let target = physically_visible_type_target(ctx)?;
    let qualified = qualified_owner_components(node, ctx.source)?;
    // Prefer the C++ lexical tier that exactly matches a candidate's indexed
    // scope before falling back to suffix recovery.  A short unqualified
    // owner can have a same-spelled class in a nested namespace (for example
    // `ThreadDetails` and `Ui::ThreadDetails`).  Suffix-only matching treats
    // both as possible owners and then fails closed, even though the
    // translation unit's lexical scope selects the global class.  Keep the
    // suffix path for malformed namespace sentinels, where the parser does
    // not expose every indexed scope component.
    let lexical_scope = match enclosing_lexical_scope_components(
        node,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.source,
    ) {
        LexicalScopeResolution::Resolved(scope) => scope,
        LexicalScopeResolution::Ambiguous | LexicalScopeResolution::Missing => {
            enclosing_namespace_components(node, ctx.source)
        }
    };
    let mut matches = Vec::new();
    for component_count in 1..=qualified.names.len() {
        let components = &qualified.names[..component_count];
        let lexical_tiers = lexical_component_tiers(components, qualified.global, &lexical_scope)
            .collect::<Vec<_>>();
        let name = components.last()?;
        let mut candidates = Vec::new();
        let mut exact_candidates = Vec::new();
        for candidate in ctx
            .visibility
            .visible_identifier_candidates(ctx.file, name)
            .filter(|candidate| candidate.is_class())
        {
            let candidate_components = crate::analyzer::symbol_lookup::parse_symbol_path(
                crate::analyzer::Language::Cpp,
                &cpp_name_for(candidate),
            );
            if !candidate_components.ends_with(components)
                || candidates
                    .iter()
                    .any(|existing| same_logical_symbol(existing, candidate))
            {
                continue;
            }
            let exact_lexical_scope = lexical_tiers
                .iter()
                .any(|expected| expected == &candidate_components);
            candidates.push(candidate.clone());
            if exact_lexical_scope {
                exact_candidates.push(candidate.clone());
            }
        }
        if !exact_candidates.is_empty() {
            candidates = exact_candidates;
        }
        // A typedef spelling can qualify nested C++ members while forward
        // lookup canonicalizes that spelling to its underlying class. Preserve
        // the exact alias prefix only when structured alias resolution proves
        // that it denotes this inverse target.
        let canonical_alias_target = matches!(
            candidates.as_slice(),
            [candidate]
                if crate::analyzer::symbol_lookup::parse_symbol_path(
                    crate::analyzer::Language::Cpp,
                    &cpp_name_for(candidate),
                ) == components
                    && ctx
                    .analyzer
                    .type_alias_provider()
                    .is_some_and(|provider| provider.is_type_alias(candidate))
                    && ctx
                        .visibility
                        .canonical_type_unit(ctx.analyzer, ctx.file, candidate)
                        .is_some_and(|canonical| {
                            same_visible_symbol(&canonical, target)
                        })
        );
        let direct_alias_target = ctx
            .analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(target))
            && candidates
                .iter()
                .any(|candidate| same_symbol(candidate, target));
        let unique_target = matches!(
            candidates.as_slice(),
            [candidate] if same_visible_symbol(candidate, target)
        );
        if direct_alias_target || unique_target || canonical_alias_target {
            let matched =
                qualified_type_component_hit_node(qualified.nodes[component_count - 1], node);
            if template_type_component_preserves_target(matched, &candidates, ctx) {
                matches.push(matched);
            }
        }
    }
    (!matches.is_empty()).then_some(matches)
}

fn target_guided_missing_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    if !ctx
        .visibility
        .is_physically_visible(ctx.file, &ctx.spec.target)
    {
        return None;
    }
    target_guided_missing_dependent_nested_type_leaf(node, ctx)
        .or_else(|| target_guided_missing_declaration_type_leaf(node, ctx))
        .or_else(|| target_guided_missing_alias_rhs_type_leaf(node, ctx))
        .or_else(|| target_guided_missing_member_alias_type_leaf(node, ctx))
        .or_else(|| target_guided_missing_template_argument_type_leaf(node, ctx))
        .or_else(|| target_guided_missing_orphaned_namespace_type_leaf(node, ctx))
}

/// Recover an ambiguous unqualified alias used by a parameter only when the
/// indexed class owner proves the alias declaration. This narrow path covers
/// malformed preprocessor class bodies without accepting unrelated aliases.
fn target_guided_ambiguous_owned_parameter_alias_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let declaration = nearest_declaration_type_context(node)?;
    if !matches!(
        declaration.kind(),
        "parameter_declaration" | "optional_parameter_declaration"
    ) {
        return None;
    }
    if !ctx
        .analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(&ctx.spec.target))
        || !type_alias_owner_matches_structured_reference(node, ctx)
    {
        return None;
    }
    target_guided_missing_declaration_type_leaf(node, ctx)
}

/// Recover the terminal leaf of `Owner<T>::Nested` when a malformed namespace
/// sentinel prevents ordinary lexical resolution. The indexed target must have
/// an indexed class parent, the structured owner path must compose with one
/// proven lexical namespace source, and every visible candidate at that exact
/// owner path must be the indexed parent. This keeps the fallback owner-based;
/// a same-spelled nested type under another template remains unproven.
fn target_guided_missing_dependent_nested_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier"
    ) || !qualified_type_scope_contains_template(node)
    {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .filter(|name| name.kind() == "type_identifier")?;
    if node_text(name, ctx.source) != ctx.spec.target.identifier() {
        return None;
    }
    let owner_target = ctx.analyzer.parent_of(&ctx.spec.target)?;
    if !owner_target.is_class() {
        return None;
    }
    let owner = node.child_by_field_name("scope")?;
    let owner_resolution = resolve_type_node_lexically_for_target(
        owner,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &owner_target,
        Some(&ctx.lexical_scope_cache),
        ctx.recovered_sentinel_scope(owner).as_deref(),
    );
    if matches!(
        owner_resolution,
        LexicalTypeResolution::Resolved {
            ref unit,
            ref candidates,
            ..
        } if type_resolution_matches_unit_target(
            owner,
            unit,
            candidates,
            &owner_target,
            ctx,
        )
    ) {
        return Some(name);
    }

    let qualified = qualified_owner_components(node, ctx.source)?;
    let parser_namespace = enclosing_namespace_components(node, ctx.source);
    let orphaned_namespace = ctx
        .orphaned_namespaces
        .iter()
        .filter(|envelope| envelope.error_marked && envelope.body_end < node.start_byte())
        .max_by_key(|envelope| envelope.body_end)
        .map(|envelope| envelope.components.clone());
    let indexed_scope = ctx
        .recovered_sentinel_scope(node)
        .or_else(|| (!parser_namespace.is_empty()).then_some(parser_namespace))
        .or(orphaned_namespace)
        .or_else(|| indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node))?;
    let owner_components = canonical_cpp_scope_components(&owner_target);
    if !lexical_component_tiers(&qualified.names, qualified.global, &indexed_scope)
        .any(|components| components == owner_components)
    {
        return None;
    }
    let scoped_candidates = visible_type_identifier_candidates(ctx, owner_target.identifier())
        .into_iter()
        .filter(|candidate| canonical_cpp_scope_components(candidate) == owner_components)
        .collect::<Vec<_>>();
    (!scoped_candidates.is_empty()
        && scoped_candidates
            .iter()
            .all(|candidate| same_visible_symbol(candidate, &owner_target)))
    .then_some(name)
}

/// Recover a type leaf after tree-sitter has prematurely closed a malformed
/// namespace around a preprocessor construct. The parser-derived lexical scope
/// is empty (or stops at an outer namespace), while the indexed target and a
/// syntax-error namespace envelope still provide a structured owner boundary.
///
/// This is deliberately narrower than a general target-name fallback:
/// - only direct class/enum leaves are eligible (aliases use their own paths);
/// - the reference must be after an error-marked namespace envelope whose full
///   namespace path equals the target package;
/// - same-file targets must have a declaration range inside that envelope; and
/// - every visible type candidate with this spelling must be the target symbol.
///
/// These checks keep an unqualified same-spelled type in another namespace from
/// becoming a false positive merely because an earlier namespace was malformed.
fn target_guided_missing_orphaned_namespace_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let target = &ctx.spec.target;
    let name = node_text(node, ctx.source);
    let (components, global) = type_reference_components(node, ctx.source)?;
    if global || components.len() != 1 || components[0] != name {
        return None;
    }
    if !target.is_class()
        || ctx
            .analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(target))
        || is_declaration_name(node)
        || name != target.identifier()
        || ctx.local_shadows.is_shadowed(name)
        || local_type_alias_shadows(node, ctx)
        || !ctx.visibility.is_physically_visible(ctx.file, target)
        || !ctx.visibility.external_type_candidate_visible_in_context(
            ctx.analyzer,
            ctx.file,
            target,
            node,
        )
    {
        return None;
    }

    let target_components = canonical_cpp_scope_components(target);
    let target_package_len = target_components.len().checked_sub(1)?;
    let target_package = &target_components[..target_package_len];
    let surviving_namespace = enclosing_namespace_components(node, ctx.source);
    if !target_package.starts_with(&surviving_namespace) {
        return None;
    }
    let envelope = ctx
        .orphaned_namespaces
        .iter()
        .filter(|envelope| envelope.error_marked && envelope.body_end < node.start_byte())
        .max_by_key(|envelope| envelope.body_end)?;
    if envelope.components.as_slice() != target_package {
        return None;
    }

    if target.source() == ctx.file
        && !ctx.analyzer.ranges(target).iter().any(|range| {
            range.start_byte < envelope.body_end && range.end_byte <= envelope.body_end
        })
    {
        return None;
    }

    let candidates = visible_type_identifier_candidates(ctx, name);
    if candidates.is_empty()
        || candidates
            .iter()
            .any(|candidate| !same_visible_symbol(candidate, target))
    {
        return None;
    }
    Some(node)
}

/// Recover a nested type-alias reference when parser recovery leaves an
/// unqualified template argument under a member function.  The ordinary
/// lexical lookup can select a same-spelled namespace alias (or fail closed)
/// even though the indexed callable owner proves that the reference is inside
/// the class which declares the target alias.
fn target_guided_missing_member_alias_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    if !is_template_argument_type_leaf(node)
        || is_declaration_name(node)
        || node_text(node, ctx.source) != ctx.spec.target.identifier()
        || local_type_alias_shadows(node, ctx)
        || !ctx
            .analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(&ctx.spec.target))
    {
        return None;
    }
    let indexed_scope = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node)?;
    if !indexed_scope_matches_target_name(
        &indexed_scope,
        &[ctx.spec.target.identifier().to_string()],
        false,
        &ctx.spec.target,
    ) {
        return None;
    }
    // The indexed symbol table intentionally retains declarations from every
    // preprocessor branch and from later source positions.  The recovered
    // class-owner scope proves the spelling, but it does not prove that this
    // alias was active and introduced before the reference.  Apply the same
    // structured guard/source-order check used by the ordinary resolver before
    // turning the target-guided recovery into a proven hit.
    if !(ctx.visibility.external_type_candidate_visible_in_context(
        ctx.analyzer,
        ctx.file,
        &ctx.spec.target,
        node,
    ) || member_alias_owner_matches_reference(node, ctx)
        && ctx
            .visibility
            .external_type_candidate_guard_compatible_in_context(
                ctx.analyzer,
                ctx.file,
                &ctx.spec.target,
                node,
            ))
    {
        return None;
    }
    let target_visible = ctx
        .visibility
        .visible_identifier_candidates(ctx.file, ctx.spec.target.identifier())
        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target));
    target_visible.then_some(node)
}

/// Recover a class/enum template argument only when the parser's ordinary
/// lexical lookup failed but the indexed scope and visible declaration still
/// prove the exact target. This intentionally excludes aliases: an alias
/// argument needs its own template-argument selection path, while a direct
/// class/enum argument can be identified by its canonical scope and symbol.
fn target_guided_missing_template_argument_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let target = &ctx.spec.target;
    let name = node_text(node, ctx.source);
    if !target.is_class()
        || !is_template_argument_type_leaf(node)
        || is_declaration_name(node)
        || name != target.identifier()
        || ctx.local_shadows.is_shadowed(name)
        || local_type_alias_shadows(node, ctx)
        || !ctx.visibility.is_physically_visible(ctx.file, target)
        || ctx
            .analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(target))
    {
        return None;
    }

    let indexed_scope = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node)?;
    let target_components = canonical_cpp_scope_components(target);
    if target_components.last().map(String::as_str) != Some(name)
        || !lexical_component_tiers(&[name.to_string()], false, &indexed_scope)
            .any(|components| components == target_components)
    {
        return None;
    }

    // The direct visible class candidate supplies the declaration identity;
    // the scope check above supplies its canonical owner path. Do not let an
    // alias or a same-scoped competing class enter this recovery path.
    let candidates = visible_type_identifier_candidates(ctx, name);
    if candidates.is_empty()
        || candidates.iter().any(|candidate| {
            !candidate.is_class()
                || ctx
                    .analyzer
                    .type_alias_provider()
                    .is_some_and(|provider| provider.is_type_alias(candidate))
                || (!same_visible_symbol(candidate, target)
                    && lexical_component_tiers(&[name.to_string()], false, &indexed_scope)
                        .any(|components| components == canonical_cpp_scope_components(candidate)))
        })
        || !candidates
            .iter()
            .any(|candidate| same_visible_symbol(candidate, target))
    {
        return None;
    }

    // Physical visibility covers the file/import projection; this second
    // guard preserves declaration ordering and preprocessor branch identity.
    ctx.visibility
        .external_type_candidate_visible_in_context(ctx.analyzer, ctx.file, target, node)
        .then_some(node)
}

/// A class member alias is visible throughout its complete class scope, even
/// when its declaration byte follows a recovered out-of-line member's
/// trailing return type. Match the indexed owner path structurally before
/// allowing the guard-only visibility check above to waive source ordering.
fn member_alias_owner_matches_reference(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.analyzer.parent_of(&ctx.spec.target) else {
        return false;
    };
    if !owner.is_class() {
        return false;
    }
    if structured_enclosing_owner(node, ctx)
        .is_some_and(|reference_owner| same_logical_symbol(&owner, &reference_owner))
    {
        return true;
    }
    let Some(reference_scope) = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node)
    else {
        return false;
    };
    let owner_components = crate::analyzer::symbol_lookup::parse_symbol_path(
        crate::analyzer::Language::Cpp,
        &cpp_name_for(&owner),
    );
    !owner_components.is_empty() && reference_scope.ends_with(&owner_components)
}

fn type_alias_owner_matches_structured_reference(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !ctx
        .analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(&ctx.spec.target))
    {
        return false;
    }
    let Some(owner) = ctx.analyzer.parent_of(&ctx.spec.target) else {
        return false;
    };
    let reference_owner = structured_enclosing_owner(node, ctx);
    owner.is_class()
        && reference_owner
            .is_some_and(|reference_owner| same_logical_symbol(&owner, &reference_owner))
}

/// A nested class can use aliases declared by any enclosing class. Preserve
/// that structured owner chain for malformed macro-return nodes, whose phantom
/// field spelling otherwise makes ordinary lexical lookup ambiguous.
fn type_alias_owner_encloses_structured_reference(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !ctx
        .analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(&ctx.spec.target))
    {
        return false;
    }
    let Some(target_owner) = ctx.analyzer.parent_of(&ctx.spec.target) else {
        return false;
    };
    let mut reference_owner = structured_enclosing_owner(node, ctx);
    while let Some(owner) = reference_owner {
        if same_logical_symbol(&target_owner, &owner) {
            return true;
        }
        reference_owner = ctx.analyzer.parent_of(&owner);
    }
    false
}

/// An enclosing class alias is only usable when no nearer class declares the
/// same type name. The recovered macro-return path does not have a complete
/// lexical declaration node, so ordinary lookup cannot apply this shadowing
/// rule before the enclosing alias fast path runs.
fn nearer_type_name_shadows_structured_reference(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner) = ctx.analyzer.parent_of(&ctx.spec.target) else {
        return false;
    };
    let Some(alias_provider) = ctx.analyzer.type_alias_provider() else {
        return false;
    };
    let Some(reference_owner) = structured_enclosing_owner(node, ctx) else {
        return false;
    };
    let candidates = ctx
        .visibility
        .visible_identifier_candidates(ctx.file, ctx.spec.target.identifier())
        .filter(|candidate| {
            candidate.is_class()
                && alias_provider.is_type_alias(candidate)
                && !same_visible_symbol(candidate, &ctx.spec.target)
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut owner = Some(reference_owner);
    while let Some(owner_unit) = owner {
        if same_logical_symbol(&target_owner, &owner_unit) {
            return false;
        }
        if candidates.iter().any(|candidate| {
            ctx.analyzer
                .parent_of(candidate)
                .is_some_and(|candidate_owner| {
                    candidate_owner.is_class() && same_logical_symbol(&candidate_owner, &owner_unit)
                })
                && ctx
                    .visibility
                    .external_type_candidate_guard_compatible_in_context(
                        ctx.analyzer,
                        ctx.file,
                        candidate,
                        node,
                    )
        }) {
            return true;
        }
        owner = ctx.analyzer.parent_of(&owner_unit);
    }
    false
}

fn local_type_alias_shadows(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(callable) = nearest_callable_scope(node) else {
        return false;
    };
    let mut root_callable = callable;
    let mut ancestor = callable.parent();
    while let Some(current) = ancestor {
        if matches!(current.kind(), "function_definition" | "lambda_expression") {
            root_callable = current;
        }
        ancestor = current.parent();
    }

    let mut stack = vec![root_callable];
    while let Some(current) = stack.pop() {
        if current.start_byte() >= node.start_byte() {
            continue;
        }
        if let Some(name) = local_type_alias_name_node(current)
            && node_text(name, ctx.source) == ctx.spec.target.identifier()
            && nearest_callable_scope(current).is_some_and(|owner| {
                !is_malformed_wrapper_function_definition(owner)
                    && owner.start_byte() <= callable.start_byte()
                    && callable.end_byte() <= owner.end_byte()
            })
            && local_alias_scope_contains_node(current, node)
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn nearest_callable_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(node.kind(), "function_definition" | "lambda_expression") {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn local_type_alias_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "alias_declaration" => node.child_by_field_name("name"),
        "type_definition" => node
            .child_by_field_name("declarator")
            .and_then(declarator_name_node),
        _ => None,
    }
}

fn local_alias_scope_contains_node(alias: Node<'_>, node: Node<'_>) -> bool {
    let mut current = alias.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            return false;
        }
        if parent.kind() == "compound_statement" {
            return parent.start_byte() <= node.start_byte()
                && node.end_byte() <= parent.end_byte();
        }
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            return parent.start_byte() <= node.start_byte()
                && node.end_byte() <= parent.end_byte();
        }
        current = parent.parent();
    }
    false
}

fn target_guided_missing_declaration_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    if is_declaration_name(node) {
        return None;
    }
    let component_nodes = cpp_name_component_nodes(node)?;
    let name_node = component_nodes.last().copied()?;
    let name = node_text(name_node, ctx.source);
    if name != ctx.spec.target.identifier() {
        return None;
    }
    let inside_target_declaration = ctx
        .target_declaration_ranges
        .iter()
        .any(|range| range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte);
    if !inside_target_declaration
        && !ctx.visibility.external_type_candidate_visible_in_context(
            ctx.analyzer,
            ctx.file,
            &ctx.spec.target,
            node,
        )
    {
        return None;
    }
    let components = component_nodes
        .iter()
        .map(|component| node_text(*component, ctx.source).to_string())
        .collect::<Vec<_>>();
    if !local_type_alias_shadows(node, ctx)
        && type_alias_owner_matches_structured_reference(node, ctx)
    {
        return Some(node);
    }
    let indexed_scope = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node)?;
    let declaration = nearest_declaration_type_context(node)?;
    let exact_scope_match = indexed_scope_matches_target_name(
        &indexed_scope,
        &components,
        is_globally_qualified_cpp_name(node),
        &ctx.spec.target,
    );
    let candidates = visible_type_identifier_candidates(ctx, name);
    let unique_visible_target = !candidates.is_empty()
        && candidates
            .iter()
            .all(|candidate| same_visible_symbol(candidate, &ctx.spec.target));
    if matches!(declaration.kind(), "field_declaration" | "declaration") {
        let parser_lost_declaration_scope =
            target_guided_scope_lost_namespace(&indexed_scope, &ctx.spec.target)
                && unique_visible_target;
        return (exact_scope_match || parser_lost_declaration_scope).then_some(node);
    }
    let lost_namespace_parameter_context =
        matches!(
            declaration.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        ) && target_guided_scope_lost_namespace(&indexed_scope, &ctx.spec.target);
    if exact_scope_match || (lost_namespace_parameter_context && unique_visible_target) {
        return Some(node);
    }
    None
}

fn target_guided_missing_alias_rhs_type_leaf<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(candidate) = stack.pop() {
        if candidate.kind() == "type_identifier"
            && !is_declaration_name(candidate)
            && matches!(
                candidate.parent().map(|parent| parent.kind()),
                Some("template_type")
            )
        {
            let mut current = candidate.parent();
            let mut saw_qualified = false;
            let mut saw_dependent = false;
            let mut saw_type_descriptor = false;
            let mut saw_alias_declaration = false;
            while let Some(ancestor) = current {
                match ancestor.kind() {
                    "qualified_identifier" | "scoped_type_identifier" => saw_qualified = true,
                    "dependent_type" => saw_dependent = true,
                    "type_descriptor" => saw_type_descriptor = true,
                    "alias_declaration" => {
                        saw_alias_declaration = true;
                        break;
                    }
                    "template_type"
                    | "template_argument_list"
                    | "typename"
                    | "template_declaration" => {}
                    _ => {}
                }
                current = ancestor.parent();
            }
            let name = node_text(candidate, ctx.source);
            let visible_candidates = visible_type_identifier_candidates(ctx, name);
            let canonical_alias_target = visible_candidates
                .iter()
                .filter_map(|alias| ctx.visibility.alias_target(alias))
                .any(|target| same_visible_symbol(&target, &ctx.spec.target));
            let alias_resolves = ctx.visibility.parser_alias_resolves_to_type(
                ctx.analyzer,
                ctx.file,
                name,
                &ctx.spec.target,
            ) || canonical_alias_target;
            if saw_qualified
                && saw_dependent
                && saw_type_descriptor
                && saw_alias_declaration
                && alias_resolves
                && ctx.visibility.external_type_candidate_visible_in_context(
                    ctx.analyzer,
                    ctx.file,
                    &ctx.spec.target,
                    candidate,
                )
            {
                return Some(candidate);
            }
        }
        for index in (0..candidate.named_child_count()).rev() {
            if let Some(child) = candidate.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn nearest_declaration_type_context(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "field_declaration"
                | "parameter_declaration"
                | "optional_parameter_declaration"
                | "declaration"
                | "type_descriptor"
        ) {
            let contains_type = ancestor
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    type_node.start_byte() <= node.start_byte()
                        && node.end_byte() <= type_node.end_byte()
                });
            if contains_type
                && !(ancestor.kind() == "type_descriptor" && is_template_argument_type_leaf(node))
            {
                return Some(ancestor);
            }
            if ancestor.kind() == "type_descriptor"
                && ancestor.parent().is_some_and(|parent| {
                    matches!(
                        parent.kind(),
                        "cast_expression"
                            | "new_expression"
                            | "sizeof_expression"
                            | "alignof_expression"
                            | "typeid_expression"
                    )
                })
            {
                return Some(ancestor);
            }
        }
        if matches!(
            ancestor.kind(),
            "compound_statement"
                | "translation_unit"
                | "namespace_definition"
                | "alias_declaration"
                | "type_definition"
                | "base_class_clause"
        ) {
            return None;
        }
        current = ancestor.parent();
    }
    None
}

fn visible_type_identifier_candidates(ctx: &ScanCtx<'_>, name: &str) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for candidate in ctx
        .visibility
        .visible_identifier_candidates(ctx.file, name)
        .filter(|candidate| {
            candidate.is_class()
                || ctx
                    .analyzer
                    .type_alias_provider()
                    .is_some_and(|provider| provider.is_type_alias(candidate))
        })
    {
        if !candidates
            .iter()
            .any(|existing| same_logical_symbol(existing, candidate))
        {
            candidates.push(candidate.clone());
        }
    }
    candidates
}

/// Recover a direct type-alias argument of `static_cast` when parser recovery
/// misclassifies a namespace alias as a local declaration. The indexed scope
/// and exact alias identity are required so a same-spelled alias in another
/// namespace remains excluded.
fn target_guided_static_cast_alias_type_descriptor<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    if node.kind() != "type_descriptor" {
        return None;
    }
    let argument_list = node.parent().filter(|parent| {
        parent.kind() == "template_argument_list"
            && parent.named_child_count() == 1
            && parent.named_child(0) == Some(node)
    })?;
    let template = argument_list.parent().filter(|parent| {
        parent.kind() == "template_function"
            && parent.child_by_field_name("arguments") == Some(argument_list)
    })?;
    let name = template.child_by_field_name("name")?;
    if name.kind() != "identifier" || node_text(name, ctx.source) != "static_cast" {
        return None;
    }
    let target = &ctx.spec.target;
    if node_text(node, ctx.source) != target.identifier()
        || !ctx
            .analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(target))
        || !ctx.visibility.is_physically_visible(ctx.file, target)
        || !ctx.visibility.external_type_candidate_visible_in_context(
            ctx.analyzer,
            ctx.file,
            target,
            node,
        )
    {
        return None;
    }

    let indexed_scope = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node)?;
    let target_scope = canonical_cpp_scope_components(target);
    let name_components = [target.identifier().to_string()];
    if !lexical_component_tiers(&name_components, false, &indexed_scope)
        .any(|components| components == target_scope)
    {
        return None;
    }

    let candidates = visible_type_identifier_candidates(ctx, target.identifier());
    if !candidates
        .iter()
        .any(|candidate| same_visible_symbol(candidate, target))
    {
        return None;
    }
    if candidates.iter().any(|candidate| {
        !same_visible_symbol(candidate, target)
            && lexical_component_tiers(&name_components, false, &indexed_scope)
                .any(|components| components == canonical_cpp_scope_components(candidate))
    }) {
        return None;
    }
    Some(node)
}

fn indexed_scope_matches_target_name(
    indexed_scope: &[String],
    components: &[String],
    global: bool,
    target: &CodeUnit,
) -> bool {
    let target_name = cpp_name_for(target);
    lexical_component_tiers(components, global, indexed_scope)
        .any(|qualified| qualified.join("::") == target_name)
}

fn target_guided_scope_lost_namespace(indexed_scope: &[String], target: &CodeUnit) -> bool {
    if target.package_name().is_empty() {
        return false;
    }
    if indexed_scope.len() <= 1 {
        return true;
    }
    let mut target_scope = crate::analyzer::symbol_lookup::parse_symbol_path(
        crate::analyzer::Language::Cpp,
        &cpp_name_for(target),
    );
    target_scope.pop();
    (1..indexed_scope.len())
        .rev()
        .any(|prefix_len| target_scope.ends_with(&indexed_scope[..prefix_len]))
}

fn indexed_enclosing_lexical_scope(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
) -> Option<Vec<String>> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let enclosing = analyzer.enclosing_code_unit(file, &range)?;
    let mut components = crate::analyzer::symbol_lookup::parse_symbol_path(
        crate::analyzer::Language::Cpp,
        &cpp_name_for(&enclosing),
    );
    if !enclosing.is_class() && !enclosing.is_module() {
        components.pop();
    }
    Some(components)
}

fn static_qualifier_name_scope<'tree>(node: Node<'tree>, ctx: &ScanCtx<'_>) -> Option<Node<'tree>> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() != "qualified_identifier" {
            continue;
        }
        if let Some(scope) = current.child_by_field_name("scope") {
            let text = qualified_scope_text(scope, ctx.source);
            if name_mentions(&text, &ctx.spec.member_name) {
                return Some(scope);
            }
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if child.kind() == "qualified_identifier" {
                stack.push(child);
            }
        }
    }
    None
}

fn qualified_scope_text(scope: Node<'_>, source: &str) -> String {
    let mut parts = vec![node_text(scope, source).to_string()];
    let mut current = scope.parent();
    while let Some(qualified) = current {
        let Some(parent) = qualified.parent() else {
            break;
        };
        if parent.kind() != "qualified_identifier"
            || parent.child_by_field_name("name") != Some(qualified)
        {
            break;
        }
        if let Some(outer_scope) = parent.child_by_field_name("scope") {
            parts.push(node_text(outer_scope, source).to_string());
        }
        current = Some(parent);
    }
    parts.reverse();
    parts.join("::")
}

fn maybe_record_constructor_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "function_definition" {
        return;
    }
    if !matches!(
        node.kind(),
        "call_expression"
            | "new_expression"
            | "compound_literal_expression"
            | "declaration"
            | "field_initializer"
    ) {
        return;
    }
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return;
    };
    if node.kind() == "field_initializer" {
        if !field_initializer_constructs_target(node, ctx, owner) {
            return;
        }
        if let Some(expected) = ctx.spec.callable_arity_at(node.start_byte()) {
            match ctx
                .visibility
                .call_arity_evidence(ctx.file, node, ctx.source)
                .accepts(expected)
            {
                Some(true) => {}
                Some(false) => return,
                None => {
                    push_unproven_hit(node, ctx);
                    return;
                }
            }
        }
        push_hit(node, ctx);
        return;
    }
    if node.kind() == "declaration" {
        if declaration_is_object_construction_candidate(node, ctx)
            && declaration_mentions_type(node, ctx, owner)
            && ctx
                .spec
                .callable_arity_at(node.start_byte())
                .is_none_or(|expected| expected.accepts(declaration_constructor_arity(node, ctx)))
        {
            push_hit(node, ctx);
        }
        return;
    }
    let Some(type_node) = constructor_type_node(node) else {
        return;
    };
    let hit_node = function_terminal_node(type_node);
    let text = node_text(type_node, ctx.source);
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.callable_arity_at(node.start_byte()) {
        match ctx
            .visibility
            .call_arity_evidence(ctx.file, node, ctx.source)
            .accepts(expected)
        {
            Some(true) => {}
            Some(false) => return,
            None => {
                push_unproven_hit(hit_node, ctx);
                return;
            }
        }
    }
    let structured_resolution = resolve_type_node_lexically_for_target(
        type_node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        owner,
        Some(&ctx.lexical_scope_cache),
        ctx.recovered_sentinel_scope(type_node).as_deref(),
    );
    let structurally_resolves = matches!(
        &structured_resolution,
        LexicalTypeResolution::Resolved {
            unit, candidates, ..
        } if same_visible_symbol(unit, owner)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, owner))
    );
    if structurally_resolves
        || matches!(structured_resolution, LexicalTypeResolution::Missing)
            && ctx
                .visibility
                .resolves_to_type(ctx.analyzer, ctx.file, text, owner)
    {
        push_hit(hit_node, ctx);
    } else {
        push_unproven_hit(hit_node, ctx);
    }
}

fn maybe_record_free_function_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "function_definition" {
        maybe_record_free_function_definition_hit(node, ctx);
        return;
    }
    if node.kind() == "identifier" {
        maybe_record_free_function_value_reference(node, ctx);
        return;
    }
    if node.kind() != "call_expression" {
        return;
    }
    let Some(function) = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))
    else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.callable_arity_at(node.start_byte()) {
        match ctx
            .visibility
            .call_arity_evidence(ctx.file, node, ctx.source)
            .accepts(expected)
        {
            Some(true) => {}
            Some(false) => return,
            None => {
                push_unproven_hit(function_terminal_node(function), ctx);
                return;
            }
        }
    }
    if matches!(function.kind(), "identifier" | "template_function") {
        let terminal = function_terminal_node(function);
        let name = node_text(terminal, ctx.source);
        if ctx.local_shadows.is_shadowed(name) {
            return;
        }
        if let Some(enclosing_owner) = structured_enclosing_owner(function, ctx)
            && !matches!(
                resolve_declaring_member_owner(
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    &enclosing_owner,
                    name,
                ),
                EnclosingMemberOwnerResolution::Missing
            )
        {
            return;
        }
        match resolve_bare_call_target(
            node,
            function,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
        ) {
            BareCallTargetResolution::FreeFunctions(units)
                if units
                    .iter()
                    .any(|unit| same_visible_symbol(unit, &ctx.spec.target)) =>
            {
                if free_function_call_may_target(node, text, ctx) {
                    let recursive = enclosing_context(terminal, ctx)
                        .enclosing
                        .as_ref()
                        .is_some_and(|enclosing| same_logical_symbol(enclosing, &ctx.spec.target));
                    if recursive {
                        push_recursive_reference_hit(terminal, ctx);
                    } else {
                        push_hit(terminal, ctx);
                    }
                }
            }
            BareCallTargetResolution::UnprovenFreeFunctions(units)
                if units
                    .iter()
                    .any(|unit| same_visible_symbol(unit, &ctx.spec.target)) =>
            {
                push_unproven_hit(terminal, ctx);
            }
            BareCallTargetResolution::FreeFunctions(_)
            | BareCallTargetResolution::UnprovenFreeFunctions(_)
            | BareCallTargetResolution::Type(_)
            | BareCallTargetResolution::CallableShadow => {}
            BareCallTargetResolution::Ambiguous | BareCallTargetResolution::Missing => {
                push_unproven_hit(terminal, ctx);
            }
        }
        return;
    }
    if !free_function_call_may_target(node, text, ctx) {
        return;
    }
    if ctx.visibility.contains_named_symbol(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        push_hit(function_terminal_node(function), ctx);
    } else if ctx.visibility.resolve_known_non_target(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        // An explicitly namespace-qualified call to a different namespace (e.g. `other::run()` when
        // the target is `ns::run`) is a proven non-match, not an unresolved reference.
    } else {
        push_unproven_hit(function_terminal_node(function), ctx);
    }
}

fn free_function_call_may_target(call: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.param_types.is_none() {
        return true;
    }
    let mut candidates = ctx
        .visibility
        .named_candidates(ctx.file, text, TargetKind::FreeFunction);
    candidates.retain(|candidate| {
        ctx.visibility
            .declaration_visible_at(ctx.analyzer, ctx.file, candidate, call.start_byte())
    });
    let Some(arity) = ctx
        .visibility
        .call_arity_evidence(ctx.file, call, ctx.source)
        .exact()
    else {
        return true;
    };
    candidates.retain(|unit| cpp_callable_arity(ctx.analyzer, unit).accepts(arity));
    if candidates.is_empty()
        || !candidates
            .iter()
            .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
    {
        return true;
    }
    let arg_types = call_argument_types(call, ctx);
    let filtered = cpp_filter_candidates_by_args(
        candidates,
        &arg_types,
        &|name| ctx.visibility.resolve_type(ctx.file, name),
        &|left, right| same_visible_symbol(left, right),
    );
    filtered
        .iter()
        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
}

fn call_argument_types(call: Node<'_>, ctx: &ScanCtx<'_>) -> Vec<Option<CppArgType>> {
    let Some(args) = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("parameters"))
        .or_else(|| call.child_by_field_name("value"))
    else {
        return Vec::new();
    };
    argument_children(args)
        .map(|arg| expression_arg_type(arg, ctx))
        .collect()
}

fn expression_arg_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CppArgType> {
    match node.kind() {
        "number_literal" | "true" | "false" | "char_literal" | "string_literal"
        | "unary_expression" => cpp_literal_arg_type(node, ctx.source).map(|mut literal| {
            literal.unit = ctx.visibility.resolve_type(ctx.file, &literal.name);
            literal
        }),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .and_then(|bindings| bindings.iter().find_map(CppScanBinding::as_arg_type)),
        "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .and_then(|inner| expression_arg_type(inner, ctx)),
        "pointer_expression" => {
            let delta = match node.child_by_field_name("operator")?.kind() {
                "&" => 1,
                "*" => -1,
                _ => return None,
            };
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            let mut arg_type = expression_arg_type(inner, ctx)?;
            arg_type.indirection += delta;
            Some(arg_type)
        }
        _ => None,
    }
}

/// Record a *non-call* reference to a free function used as a value: `&foo`,
/// `fp = foo`, `foo` passed as an argument, etc. The callee identifier of a call
/// `foo()` is recorded by the call_expression arm, and the function's own
/// declaration/definition name is not a reference.
fn maybe_record_free_function_value_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let text = node_text(node, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    if is_declaration_name(node) || is_call_callee_node(node) {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx.visibility.contains_named_symbol(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        push_hit(node, ctx);
    } else if ctx.visibility.resolve_known_non_target(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        // A qualified reference proven to a different namespace is not a match.
    } else {
        push_unproven_hit(node, ctx);
    }
}

fn maybe_record_free_function_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(function) = function_definition_name_node(node) else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_callable(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if !function_definition_signature_matches_target(node, ctx) {
        return;
    }
    if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            ctx.visibility.contains_named_symbol(
                ctx.file,
                name,
                TargetKind::FreeFunction,
                &ctx.spec.target,
            )
        })
    {
        push_definition_hit(function, ctx);
    } else if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            ctx.visibility.resolve_known_non_target(
                ctx.file,
                name,
                TargetKind::FreeFunction,
                &ctx.spec.target,
            )
        })
    {
        // A definition in another explicit namespace is a proven non-match.
    } else {
        push_unproven_definition_hit(function, ctx);
    }
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "using_declaration" {
        maybe_record_using_member_hit(node, ctx);
        return;
    }
    if let Some(member) = recovered_direct_initializer_qualified_callable(node) {
        maybe_record_qualified_method_value_hit(node, member, ctx);
        return;
    }
    if let Some(value) = explicit_qualified_callable_value(node) {
        maybe_record_qualified_method_value_hit(value.qualified, value.member, ctx);
        return;
    }
    if node.kind() == "function_definition" {
        maybe_record_method_definition_hit(node, ctx);
        return;
    }
    if node.kind() != "call_expression" {
        return;
    }
    if let Some((receiver, operator)) = explicit_operator_call(node) {
        let text = node_text(operator, ctx.source);
        if !name_matches_callable(text, &ctx.spec.member_name) {
            return;
        }
        *ctx.raw_match_count += 1;
        if let Some(expected) = ctx.spec.callable_arity_at(node.start_byte()) {
            match ctx
                .visibility
                .call_arity_evidence(ctx.file, node, ctx.source)
                .accepts(expected)
            {
                Some(true) => {}
                Some(false) => return,
                None => {
                    push_unproven_hit(operator, ctx);
                    return;
                }
            }
        }
        match explicit_receiver_target_resolution(receiver, ctx) {
            MethodReceiverTargetResolution::Target if receiver_is_self_like(receiver) => {
                push_self_receiver_hit(operator, ctx);
            }
            MethodReceiverTargetResolution::Target => push_hit(operator, ctx),
            MethodReceiverTargetResolution::Missing => push_unproven_hit(operator, ctx),
            MethodReceiverTargetResolution::NonTarget
            | MethodReceiverTargetResolution::Ambiguous => {}
        }
        return;
    }
    let Some(function) = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))
    else {
        return;
    };
    if !callable_node_matches(function, &ctx.spec.member_name, ctx.source) {
        return;
    }
    if function.kind() == "identifier"
        && ctx
            .local_shadows
            .is_shadowed(node_text(function, ctx.source))
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.callable_arity_at(node.start_byte()) {
        match ctx
            .visibility
            .call_arity_evidence(ctx.file, node, ctx.source)
            .accepts(expected)
        {
            Some(true) => {}
            Some(false) => return,
            None => {
                push_unproven_hit(function_terminal_node(function), ctx);
                return;
            }
        }
    }
    if !method_call_may_target(node, ctx) {
        return;
    }
    if is_structurally_qualified(function) {
        match qualified_owner_resolution(function, ctx) {
            QualifiedOwnerResolution::Target => {
                push_hit(function_terminal_node(function), ctx);
            }
            QualifiedOwnerResolution::NonTarget => {}
            QualifiedOwnerResolution::Unresolved => {
                push_unproven_hit(function_terminal_node(function), ctx);
            }
        }
        return;
    }
    match call_function_target_resolution(function, ctx) {
        MethodReceiverTargetResolution::Target
            if call_function_has_direct_self_receiver(function) =>
        {
            push_self_receiver_hit(function_terminal_node(function), ctx);
        }
        MethodReceiverTargetResolution::Target => {
            push_hit(function_terminal_node(function), ctx);
        }
        MethodReceiverTargetResolution::NonTarget | MethodReceiverTargetResolution::Ambiguous => {}
        // A bare `m()` whose name resolves through the enclosing class's base hierarchy to
        // the target member declared on a base is a genuine external usage of that inherited
        // base member (e.g. `Derived::run` calling inherited `Base::value`), so it is an
        // ordinary Reference hit -- not a same-type self call. Checked before the self-owner
        // arm because `same_owner_context` also accepts this inherited case.
        MethodReceiverTargetResolution::Missing
            if inherited_target_owner_context(function, ctx) =>
        {
            push_hit(function_terminal_node(function), ctx);
        }
        MethodReceiverTargetResolution::Missing
            if same_owner_context(function, ctx)
                || out_of_line_target_owner_context(function, ctx) =>
        {
            push_self_receiver_hit(function_terminal_node(function), ctx);
        }
        MethodReceiverTargetResolution::Missing
            if function.kind() == "identifier"
                && resolves_to_lexical_free_function(function, ctx) =>
        {
            // A visible namespace/free function is a proven negative once the
            // enclosing structured owner and its hierarchy contain no such member.
        }
        MethodReceiverTargetResolution::Missing
            if !receiver_has_known_non_target(function, ctx)
                && !known_non_target_owner_context(function, ctx) =>
        {
            push_unproven_hit(function_terminal_node(function), ctx);
        }
        MethodReceiverTargetResolution::Missing => {}
    }
}

fn recovered_direct_initializer_qualified_callable(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let parameter = node
        .parent()
        .filter(|parent| parent.kind() == "parameter_declaration")?;
    let parameter_declarator = parameter.child_by_field_name("declarator")?;
    // Tree-sitter recovers `Value value(Owner::method(arg));` as a function
    // declaration whose sole pseudo-parameter has `Owner::method` as its type
    // and `(arg)` as an abstract function declarator. Ordinary qualified
    // parameter types have named/pointer/reference declarators instead.
    if parameter.child_by_field_name("type") != Some(node)
        || parameter_declarator.kind() != "abstract_function_declarator"
    {
        return None;
    }
    let parameter_list = parameter
        .parent()
        .filter(|parent| parent.kind() == "parameter_list")?;
    if parameter_list.named_child_count() != 1 {
        return None;
    }
    let function_declarator = parameter_list
        .parent()
        .filter(|parent| parent.kind() == "function_declarator")?;
    if function_declarator
        .child_by_field_name("declarator")
        .is_none_or(|declarator| declarator.kind() != "identifier")
        || function_declarator
            .parent()
            .is_none_or(|parent| parent.kind() != "declaration")
    {
        return None;
    }
    node.child_by_field_name("name")
}

fn maybe_record_using_member_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(imported) = ordinary_using_declaration_type_node(node) else {
        return;
    };
    if !callable_node_matches(imported, &ctx.spec.member_name, ctx.source) {
        return;
    }
    let Some(target_owner) = ctx.spec.owner.as_ref() else {
        return;
    };
    *ctx.raw_match_count += 1;
    let owner_resolution = qualified_owner_components(imported, ctx.source)
        .map(|qualified| {
            let lexical_scope = match enclosing_lexical_scope_components(
                imported,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
            ) {
                LexicalScopeResolution::Resolved(scope) => scope,
                LexicalScopeResolution::Ambiguous => return LexicalTypeResolution::Ambiguous,
                LexicalScopeResolution::Missing => return LexicalTypeResolution::Missing,
            };
            ctx.visibility.resolve_type_components_lexically(
                ctx.analyzer,
                ctx.file,
                &qualified.names,
                qualified.global,
                &lexical_scope,
            )
        })
        .unwrap_or(LexicalTypeResolution::Missing);
    let matches_target_owner = matches!(
        owner_resolution,
        LexicalTypeResolution::Resolved {
            ref unit,
            ref candidates,
            ..
        } if same_visible_symbol(unit, target_owner)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, target_owner))
    );
    if !matches_target_owner {
        match owner_resolution {
            LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => {
                push_unproven_hit(imported, ctx);
            }
            LexicalTypeResolution::Resolved { .. } => {}
        }
        return;
    }
    match ctx.visibility.visible_member_for_owner_name(
        ctx.file,
        target_owner,
        &ctx.spec.member_name,
    ) {
        VisibleMemberResolution::Callable(candidates)
            if candidates.iter().all(|candidate| {
                ctx.target_group.contains(candidate)
                    || ctx
                        .target_group
                        .iter()
                        .any(|target| same_visible_symbol(candidate, target))
            }) =>
        {
            push_hit(imported, ctx);
        }
        VisibleMemberResolution::NonCallable => {}
        VisibleMemberResolution::Callable(_)
        | VisibleMemberResolution::AmbiguousKind
        | VisibleMemberResolution::Missing => {
            push_unproven_hit(imported, ctx);
        }
    }
}

fn resolves_to_lexical_free_function(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let name = node_text(node, ctx.source);
    let namespace = enclosing_namespace_components(node, ctx.source).join(".");
    let key = (namespace.clone(), name.to_string());
    if let Some(resolved) = ctx.lexical_free_function_cache.borrow().get(&key).copied() {
        return resolved;
    }
    let resolved = ctx
        .visibility
        .visible_identifier_candidates(ctx.file, name)
        .any(|unit| {
            unit.is_function()
                && type_owner_of(ctx.analyzer, unit).is_none()
                && unit.package_name() == namespace
        });
    ctx.lexical_free_function_cache
        .borrow_mut()
        .insert(key, resolved);
    resolved
}

fn maybe_record_qualified_method_value_hit(
    qualified: Node<'_>,
    member: Node<'_>,
    ctx: &mut ScanCtx<'_>,
) {
    if !name_matches_callable(node_text(member, ctx.source), &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    let resolution =
        qualified_callable_value_resolution(qualified, node_text(member, ctx.source), ctx);
    match resolution {
        LexicalCallableValueResolution::Type(resolved_owner) => {
            let Some(owner) = ctx.spec.owner.as_ref() else {
                push_unproven_hit(member, ctx);
                return;
            };
            if !receiver_owner_matches_target(&resolved_owner, owner, member.start_byte(), ctx) {
                if same_visible_symbol(&resolved_owner, owner) {
                    push_unproven_hit(member, ctx);
                }
                return;
            }
            match ctx.visibility.visible_member_for_owner_name(
                ctx.file,
                owner,
                &ctx.spec.member_name,
            ) {
                VisibleMemberResolution::Callable(candidates)
                    if candidates.iter().all(|candidate| {
                        ctx.target_group.contains(candidate)
                            || ctx
                                .target_group
                                .iter()
                                .any(|target| same_visible_symbol(candidate, target))
                    }) =>
                {
                    // An explicitly qualified method value remains an external
                    // reference even when its owner is the enclosing class.
                    push_hit(member, ctx);
                }
                VisibleMemberResolution::NonCallable => {}
                VisibleMemberResolution::Callable(_)
                | VisibleMemberResolution::AmbiguousKind
                | VisibleMemberResolution::Missing => {
                    push_unproven_hit(member, ctx);
                }
            }
        }
        LexicalCallableValueResolution::FreeFunction(_) => {}
        LexicalCallableValueResolution::Ambiguous | LexicalCallableValueResolution::Missing => {
            push_unproven_hit(member, ctx);
        }
    }
}

fn qualified_callable_value_resolution(
    qualified: Node<'_>,
    member_name: &str,
    ctx: &ScanCtx<'_>,
) -> LexicalCallableValueResolution {
    let Some((owner_components, global)) =
        qualified_callable_owner_components(qualified, ctx.source)
    else {
        return LexicalCallableValueResolution::Missing;
    };
    let lexical_scope = if global {
        Vec::new()
    } else {
        match enclosing_lexical_scope_components(
            qualified,
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
        ) {
            LexicalScopeResolution::Resolved(scope) => scope,
            LexicalScopeResolution::Ambiguous => {
                return LexicalCallableValueResolution::Ambiguous;
            }
            LexicalScopeResolution::Missing => return LexicalCallableValueResolution::Missing,
        }
    };
    if let Some(target_owner) = ctx.spec.owner.as_ref()
        && let LexicalTypeResolution::Resolved { unit, .. } =
            resolve_type_components_lexically_at_for_target_with_scope_cache(
                qualified,
                &owner_components,
                global,
                ctx.analyzer,
                ctx.visibility,
                &ctx.ordinary_type_imports,
                ctx.file,
                ctx.source,
                target_owner,
                false,
                Some(&ctx.lexical_scope_cache),
            )
    {
        return LexicalCallableValueResolution::Type(unit);
    }
    ctx.visibility.resolve_callable_value_components_lexically(
        ctx.analyzer,
        ctx.file,
        &owner_components,
        member_name,
        global,
        &lexical_scope,
    )
}

fn method_call_may_target(call: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return true;
    };
    if ctx.spec.param_types.is_none() {
        return true;
    }
    let mut candidates = ctx
        .visibility
        .visible_members_for_owner_name(ctx.file, owner, &ctx.spec.member_name)
        .into_iter()
        .filter(|unit| unit.is_function())
        .cloned()
        .collect::<Vec<_>>();
    let Some(arity) = ctx
        .visibility
        .call_arity_evidence(ctx.file, call, ctx.source)
        .exact()
    else {
        return true;
    };
    candidates.retain(|unit| cpp_callable_arity(ctx.analyzer, unit).accepts(arity));
    if candidates.is_empty()
        || !candidates
            .iter()
            .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
    {
        return true;
    }
    let arg_types = call_argument_types(call, ctx);
    let filtered = cpp_filter_candidates_by_args(
        candidates,
        &arg_types,
        &|name| ctx.visibility.resolve_type(ctx.file, name),
        &|left, right| same_visible_symbol(left, right),
    );
    filtered
        .iter()
        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
}

fn maybe_record_method_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(function) = function_definition_name_node(node) else {
        return;
    };
    if !callable_node_matches(function, &ctx.spec.member_name, ctx.source) {
        return;
    }
    *ctx.raw_match_count += 1;
    if !function_definition_signature_matches_target(node, ctx) {
        return;
    }
    if node_inside_target_declaration(function, ctx) {
        return;
    }
    if is_structurally_qualified(function) {
        match qualified_owner_resolution(function, ctx) {
            QualifiedOwnerResolution::Target => push_definition_hit(function, ctx),
            QualifiedOwnerResolution::NonTarget => {}
            QualifiedOwnerResolution::Unresolved => push_unproven_definition_hit(function, ctx),
        }
        return;
    }
    if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            name.contains("::")
                && ctx.visibility.contains_named_symbol(
                    ctx.file,
                    name,
                    TargetKind::Method,
                    &ctx.spec.target,
                )
        })
    {
        push_definition_hit(function, ctx);
    } else if definition_name_candidates(function, ctx)
        .iter()
        .any(|name| {
            ctx.visibility.resolve_known_non_target(
                ctx.file,
                name,
                TargetKind::Method,
                &ctx.spec.target,
            )
        })
        || known_non_target_owner_context(function, ctx)
    {
        // A method definition for another visible owner is a proven non-match.
    } else {
        push_unproven_definition_hit(function, ctx);
    }
}

fn node_inside_target_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    ctx.target_declaration_ranges
        .iter()
        .any(|range| node.start_byte() >= range.start_byte && node.end_byte() <= range.end_byte)
}

fn explicit_operator_call(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut receiver = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "argument_list" {
            continue;
        }
        if let Some(operator) = first_descendant_of_kind(child, "operator_name") {
            return receiver.map(|receiver| (receiver, operator));
        }
        if receiver.is_none() {
            receiver = Some(child);
        }
    }
    None
}

fn function_definition_name_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "function_definition" {
        return None;
    }
    node.child_by_field_name("declarator")
        .and_then(declarator_name_node)
}

fn function_definition_owner_lookup_node(node: Node<'_>) -> Option<Node<'_>> {
    function_definition_name_node(node)
}

fn function_definition_signature_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let definition = node_text(node, ctx.source);
    let Some(expected) = ctx.spec.callable_arity_at(node.start_byte()) else {
        return true;
    };
    if !expected.accepts(signature_arity(Some(definition))) {
        return false;
    }
    let Some(target_signature) = ctx.spec.target.signature() else {
        return true;
    };
    cpp_signature_param_types(definition) == cpp_signature_param_types(target_signature)
}

fn callable_node_matches(node: Node<'_>, expected: &str, source: &str) -> bool {
    name_matches_callable(node_text(function_terminal_node(node), source), expected)
}

fn definition_name_candidates(function: Node<'_>, ctx: &ScanCtx<'_>) -> Vec<String> {
    let raw = normalize_cpp_reference_text(node_text(function, ctx.source));
    if raw.is_empty() {
        return Vec::new();
    }
    let Some(namespace) = enclosing_namespace_context(function, ctx.source) else {
        return vec![raw];
    };
    if !raw.contains("::") {
        return vec![format!("{namespace}::{raw}")];
    }
    // fqname-M4: peeks at the raw first `::`-split token, including the empty
    // token a leading-`::` absolute reference (`::Foo::Bar`) produces (same
    // shape as rust's `rust_reference_looks_external`); the shared structured
    // splitter filters empty segments, which would shift "which token is
    // first" for that one lead-`::` shape and is not proven equivalent here.
    if raw
        .split("::")
        .next()
        .is_some_and(|head| head != namespace && !namespace.ends_with(&format!("::{head}")))
    {
        vec![format!("{namespace}::{raw}"), raw]
    } else {
        vec![raw]
    }
}

fn first_descendant_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_descendant_of_kind(child, kind) {
            return Some(found);
        }
    }
    None
}

fn maybe_record_global_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if matches!(node.kind(), "identifier" | "field_identifier")
        && designated_initializer_owner(ctx.visibility, ctx.file, ctx.source, node).is_some()
    {
        return;
    }
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        || is_declaration_name(node)
        || is_member_field_own_declarator(node, ctx)
        || is_selected_field_expression_member_descendant(node)
        || is_nested_in_qualified_identifier(node)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if global_field_resolves_to_target(node, ctx) {
        push_hit(node, ctx);
    } else if global_field_is_known_non_target(node, ctx) {
    } else {
        push_unproven_hit(node, ctx);
    }
}

/// Whether `node` belongs to the selected-member side of any enclosing field
/// expression. A reference may be nested arbitrarily inside the receiver side
/// (for example, an argument to a call-built fluent receiver), so direct child
/// equality is insufficient: classify each ancestor by structured subtree
/// containment instead.
fn is_selected_field_expression_member_descendant(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "field_expression" {
            if parent
                .child_by_field_name("field")
                .is_some_and(|field| node_is_within(field, node))
            {
                return true;
            }
            let receiver = parent
                .child_by_field_name("argument")
                .or_else(|| parent.child_by_field_name("object"))
                .or_else(|| parent.named_child(0));
            if !receiver.is_some_and(|receiver| node_is_within(receiver, node)) {
                // Unknown grammar shape inside a field expression: fail closed
                // rather than treating it as a receiver reference.
                return true;
            }
        }
        node = parent;
    }
    false
}

fn node_is_within(parent: Node<'_>, child: Node<'_>) -> bool {
    parent.start_byte() <= child.start_byte() && child.end_byte() <= parent.end_byte()
}

fn global_field_resolves_to_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let text = node_text(node, ctx.source);
    if !text.contains("::") && ctx.local_shadows.is_shadowed(text) {
        return false;
    }
    if text.contains("::") {
        return ctx.visibility.contains_named_symbol(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    if let Some(namespace) = enclosing_namespace_context(node, ctx.source)
        && cpp_namespace_for(&ctx.spec.target).as_deref() == Some(namespace.as_str())
    {
        return ctx.visibility.contains_named_symbol(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    if let Some(indexed_scope) = indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, node)
        && cpp_namespace_for(&ctx.spec.target).is_some_and(|namespace| {
            crate::analyzer::symbol_lookup::parse_symbol_path(
                crate::analyzer::Language::Cpp,
                &namespace,
            ) == indexed_scope
        })
    {
        return ctx.visibility.contains_named_symbol(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    bare_global_field_uniquely_resolves_to_target(text, ctx)
}

fn bare_global_field_uniquely_resolves_to_target(text: &str, ctx: &ScanCtx<'_>) -> bool {
    let mut matched_target = false;
    for unit in ctx.visibility.visible_identifier_candidates(ctx.file, text) {
        if !has_persisted_global_field_identity(unit)
            || !name_matches_terminal(unit.identifier(), &ctx.spec.member_name)
        {
            continue;
        }
        if !name_matches_terminal(cpp_name_for(unit).as_str(), text) {
            continue;
        }
        if same_visible_global_field_symbol(
            ctx.analyzer,
            &mut ctx.global_field_internal_linkage_cache.borrow_mut(),
            unit,
            &ctx.spec.target,
        ) {
            matched_target = true;
        } else {
            return false;
        }
    }
    matched_target
}

fn has_persisted_global_field_identity(unit: &CodeUnit) -> bool {
    // C++ type members persist their owner in `short_name` (`Owner.member`), while namespace
    // identity lives in `package_name`; global and namespace-scoped fields therefore have a
    // terminal-only short name. Keep this hot lookup projection-only instead of asking the
    // analyzer for every same-named candidate's parent.
    unit.is_field() && !unit.short_name().contains('.')
}

fn global_field_is_known_non_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let text = node_text(node, ctx.source);
    if !text.contains("::") && ctx.local_shadows.is_shadowed(text) {
        return true;
    }
    if text.contains("::") {
        return ctx.visibility.resolve_known_non_target(
            ctx.file,
            text,
            TargetKind::GlobalField,
            &ctx.spec.target,
        );
    }
    let Some(namespace) = enclosing_namespace_context(node, ctx.source) else {
        return false;
    };
    cpp_namespace_for(&ctx.spec.target).as_deref() != Some(namespace.as_str())
        && ctx
            .visibility
            .visible_identifier_candidates(ctx.file, &ctx.spec.member_name)
            .any(|unit| {
                has_persisted_global_field_identity(unit)
                    && unit.identifier() == ctx.spec.member_name
                    && cpp_namespace_for(unit).as_deref() == Some(namespace.as_str())
                    && !same_visible_global_field_symbol(
                        ctx.analyzer,
                        &mut ctx.global_field_internal_linkage_cache.borrow_mut(),
                        unit,
                        &ctx.spec.target,
                    )
            })
}

fn maybe_record_member_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "field_expression" {
        let Some(field) = node.child_by_field_name("field") else {
            return;
        };
        if node_text(field, ctx.source) != ctx.spec.member_name {
            return;
        }
        *ctx.raw_match_count += 1;
        let receiver = node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"));
        match receiver.map(|receiver| explicit_receiver_target_resolution(receiver, ctx)) {
            Some(MethodReceiverTargetResolution::Target) => push_hit(field, ctx),
            Some(MethodReceiverTargetResolution::Missing) | None => push_unproven_hit(field, ctx),
            Some(
                MethodReceiverTargetResolution::NonTarget
                | MethodReceiverTargetResolution::Ambiguous,
            ) => {}
        }
        return;
    }

    if matches!(node.kind(), "identifier" | "field_identifier")
        && name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        && let Some(designator_owner) =
            designated_initializer_owner(ctx.visibility, ctx.file, ctx.source, node)
    {
        *ctx.raw_match_count += 1;
        match designator_owner {
            DesignatedInitializerOwner::Resolved(owner)
                if ctx
                    .spec
                    .owner
                    .as_ref()
                    .is_some_and(|target_owner| same_visible_symbol(&owner, target_owner)) =>
            {
                push_hit(node, ctx);
            }
            DesignatedInitializerOwner::Unresolved => push_unproven_hit(node, ctx),
            DesignatedInitializerOwner::Resolved(_) => {}
        }
        return;
    }

    let qualified_member_name_matches =
        matches!(node.kind(), "qualified_identifier" | "scoped_identifier")
            && cpp_name_component_nodes(node)
                .and_then(|components| components.last().copied())
                .is_some_and(|terminal| node_text(terminal, ctx.source) == ctx.spec.member_name);
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier" | "scoped_identifier"
    ) || (!name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        && !qualified_member_name_matches)
        || is_declaration_name(node)
        || is_member_field_own_declarator(node, ctx)
        || is_selected_field_expression_member_descendant(node)
        || is_nested_in_qualified_identifier(node)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if is_structurally_qualified(node) {
        match qualified_owner_resolution(node, ctx) {
            QualifiedOwnerResolution::Target => push_hit(node, ctx),
            QualifiedOwnerResolution::NonTarget => {}
            QualifiedOwnerResolution::Unresolved => push_unproven_hit(node, ctx),
        }
        return;
    }
    let text = node_text(node, ctx.source);
    if ctx.local_shadows.is_shadowed(text) {
        return;
    }
    let unscoped_enum_match = ctx.spec.enum_owner_kind == EnumOwnerKind::Unscoped
        && ctx.visibility.is_visible(ctx.file, &ctx.spec.target);
    let owner_context = structured_owner_context_resolution(node, ctx);
    if matches!(
        owner_context,
        StructuredOwnerContextResolution::SelfTarget
            | StructuredOwnerContextResolution::InheritedTarget
    ) || unscoped_enum_match
    {
        push_hit(node, ctx);
    } else if let Some(target_owner) = (ctx.spec.enum_owner_kind == EnumOwnerKind::Scoped)
        .then_some(ctx.spec.owner.as_ref())
        .flatten()
    {
        let resolution =
            match resolve_active_using_enum_member(node, ctx) {
                ActiveUsingEnumMemberResolution::Block(resolution) => resolution,
                ActiveUsingEnumMemberResolution::Class(resolution) => {
                    if direct_class_member_shadows(node, ctx) {
                        return;
                    }
                    resolution
                }
                ActiveUsingEnumMemberResolution::Namespace(resolution) => {
                    if let Some(owner) = structured_enclosing_owner(node, ctx) {
                        if direct_class_member_shadows(node, ctx) {
                            return;
                        }
                        let complete_same_file_leaf =
                            owner.source() == ctx.file
                                && ctx.analyzer.type_hierarchy_provider().is_some_and(
                                    |hierarchy| hierarchy.get_direct_ancestors(&owner).is_empty(),
                                );
                        if !complete_same_file_leaf {
                            push_unproven_hit(node, ctx);
                            return;
                        }
                    }
                    match owner_context {
                        StructuredOwnerContextResolution::SelfTarget
                        | StructuredOwnerContextResolution::InheritedTarget
                        | StructuredOwnerContextResolution::NonTarget => return,
                        StructuredOwnerContextResolution::Ambiguous => {
                            push_unproven_hit(node, ctx);
                            return;
                        }
                        StructuredOwnerContextResolution::Missing => {}
                    }
                    if namespace_value_shadows(node, ctx) {
                        return;
                    }
                    resolution
                }
                ActiveUsingEnumMemberResolution::Missing => {
                    if direct_class_member_shadows(node, ctx)
                        || (structured_enclosing_owner(node, ctx).is_none()
                            && namespace_value_shadows(node, ctx))
                    {
                        return;
                    }
                    UsingEnumMemberResolution::Missing
                }
            };
        match resolution {
            UsingEnumMemberResolution::Resolved { owner, member }
                if same_visible_symbol(&owner, target_owner)
                    && same_visible_symbol(&member, &ctx.spec.target) =>
            {
                push_hit(node, ctx);
            }
            UsingEnumMemberResolution::Resolved { .. } => {}
            UsingEnumMemberResolution::Ambiguous | UsingEnumMemberResolution::Missing => {
                push_unproven_hit(node, ctx)
            }
        }
    } else if !matches!(owner_context, StructuredOwnerContextResolution::NonTarget) {
        push_unproven_hit(node, ctx);
    }
}

enum ActiveUsingEnumMemberResolution {
    Block(UsingEnumMemberResolution),
    Class(UsingEnumMemberResolution),
    Namespace(UsingEnumMemberResolution),
    Missing,
}

fn direct_class_member_shadows(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    structured_enclosing_owner(node, ctx).is_some_and(|owner| {
        ctx.visibility
            .visible_members_for_owner_name(ctx.file, &owner, &ctx.spec.member_name)
            .into_iter()
            .next()
            .is_some()
    })
}

fn resolve_active_using_enum_member(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> ActiveUsingEnumMemberResolution {
    let block =
        ctx.using_enum_owners
            .resolve_member(ctx.visibility, ctx.file, &ctx.spec.member_name);
    if !matches!(block, UsingEnumMemberResolution::Missing) {
        return ActiveUsingEnumMemberResolution::Block(block);
    }
    let class = structured_enclosing_owner(node, ctx);
    let namespace = enclosing_namespace_components(node, ctx.source);
    match ctx.semantic_using_enum_owners.resolve_member(
        ctx.visibility,
        ctx.file,
        class.as_ref(),
        &namespace,
        node.start_byte(),
        &ctx.spec.member_name,
    ) {
        SemanticUsingEnumMemberResolution::Class(resolution) => {
            ActiveUsingEnumMemberResolution::Class(resolution)
        }
        SemanticUsingEnumMemberResolution::Namespace(resolution) => {
            ActiveUsingEnumMemberResolution::Namespace(resolution)
        }
        SemanticUsingEnumMemberResolution::Missing => ActiveUsingEnumMemberResolution::Missing,
    }
}

fn namespace_value_shadows(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let namespace = enclosing_namespace_components(node, ctx.source).join("::");
    !matches!(
        resolve_namespace_value(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            &namespace,
            &ctx.spec.member_name,
            node.start_byte(),
        ),
        NamespaceValueResolution::Missing
    )
}

fn is_nested_in_qualified_identifier(node: Node<'_>) -> bool {
    if node.kind() == "qualified_identifier" {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        // A malformed declaration can place a complete member initializer
        // inside an ERROR child of a synthetic qualified_identifier.  The
        // qualified-identifier filter is correct for a well-formed `A::b`
        // path, but not for that recovered subtree: there is no structured
        // scope/name path to collapse, and the indexed enclosing member is
        // the authoritative owner.  Stop at the recovery boundary so these
        // identifiers reach the normal member-owner resolver.
        if parent.kind() == "ERROR" {
            return false;
        }
        if parent.kind() == "qualified_identifier" {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn receiver_type_units(node: Node<'_>, source: &str, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
    receiver_type_units_with_budget(node, source, ctx, MAX_RECEIVER_CALL_RESOLUTION_DEPTH)
}

fn receiver_type_units_with_budget(
    node: Node<'_>,
    source: &str,
    ctx: &ScanCtx<'_>,
    remaining_call_depth: usize,
) -> Vec<CodeUnit> {
    let mut current = node;
    let mut member_chain = Vec::new();
    let mut base_units = loop {
        match current.kind() {
            "field_expression" => {
                let Some(member) = current.child_by_field_name("field") else {
                    return Vec::new();
                };
                let Some(receiver) = current
                    .child_by_field_name("argument")
                    .or_else(|| current.child_by_field_name("object"))
                    .or_else(|| current.named_child(0))
                else {
                    return Vec::new();
                };
                member_chain.push(node_text(member, source));
                current = receiver;
            }
            "pointer_expression" | "parenthesized_expression" | "subscript_expression" => {
                let Some(inner) = current
                    .child_by_field_name("argument")
                    .or_else(|| current.named_child(0))
                else {
                    return Vec::new();
                };
                current = inner;
            }
            // Tree-sitter uses `field_identifier` for an unqualified member
            // field when it appears as the base of another field expression
            // (`data_.as_chars()` / `prefix.edge`).  Resolve it through the
            // same structured binding and enclosing-owner paths as an
            // ordinary identifier; falling through to `resolve_type` would
            // treat the field name as a type and lose the receiver identity.
            "identifier" | "field_identifier" => {
                let name = node_text(current, source);
                let local = ctx.bindings.resolve_symbol(name);
                if let Some(bindings) = local.as_precise() {
                    break receiver_units_from_bindings(current, bindings, ctx);
                }
                if ctx.bindings.is_shadowed(name) {
                    return Vec::new();
                }
                let owner = structured_enclosing_owner(current, ctx)
                    .filter(CodeUnit::is_class)
                    .or_else(|| {
                        enclosing_context(current, ctx)
                            .owner
                            .filter(CodeUnit::is_class)
                    });
                if let Some(owner) = owner {
                    let implicit_fields = ctx
                        .visibility
                        .visible_members_for_owner_name(ctx.file, &owner, name)
                        .into_iter()
                        .filter(|unit| unit.is_field())
                        .collect::<Vec<_>>();
                    if !implicit_fields.is_empty() {
                        break receiver_units_from_declared_fields(implicit_fields, current, ctx);
                    }
                }
                let global_fields = ctx
                    .visibility
                    .visible_identifier_candidates(ctx.file, name)
                    .filter(|unit| {
                        has_persisted_global_field_identity(unit) && unit.identifier() == name
                    })
                    .collect::<Vec<_>>();
                if global_fields.is_empty() {
                    break ctx
                        .visibility
                        .resolve_type(ctx.file, name)
                        .into_iter()
                        .collect();
                }
                if let Some(first) = global_fields.first()
                    && global_fields
                        .iter()
                        .skip(1)
                        .any(|field| !same_visible_symbol(first, field))
                {
                    return Vec::new();
                }
                break receiver_units_from_declared_fields(global_fields, current, ctx);
            }
            "call_expression" | "new_expression" => {
                break infer_type_from_value_with_budget(current, ctx, remaining_call_depth)
                    .and_then(|binding| binding.unit)
                    .into_iter()
                    .collect();
            }
            "this" => {
                break enclosing_context(current, ctx).owner.into_iter().collect();
            }
            "qualified_identifier" | "scoped_identifier" => {
                let reference = node_text(current, source);
                let fields = ctx
                    .visibility
                    .named_candidates(ctx.file, reference, TargetKind::GlobalField)
                    .into_iter()
                    .filter(has_persisted_global_field_identity)
                    .collect::<Vec<_>>();
                if fields.is_empty() {
                    break ctx
                        .visibility
                        .resolve_type(ctx.file, reference)
                        .into_iter()
                        .collect();
                }
                break receiver_units_from_declared_fields(fields.iter().collect(), current, ctx);
            }
            _ => {
                break ctx
                    .visibility
                    .resolve_type(ctx.file, node_text(current, source))
                    .into_iter()
                    .collect();
            }
        }
    };

    base_units = canonical_receiver_units(base_units, ctx);
    if base_units.is_empty() {
        return Vec::new();
    }

    while let Some(member_name) = member_chain.pop() {
        let mut next_units = Vec::new();
        for owner in &base_units {
            let fields =
                ctx.visibility
                    .visible_members_for_owner_name(ctx.file, owner, member_name);
            for field in fields.into_iter().filter(|unit| unit.is_field()) {
                let Some(unit) =
                    field_declared_binding(ctx.analyzer, ctx.visibility, ctx.file, field)
                        .and_then(|binding| binding.unit)
                        .or_else(|| recovered_receiver_field_type(current, field, ctx))
                else {
                    continue;
                };
                if !next_units
                    .iter()
                    .any(|existing| same_visible_symbol(existing, &unit))
                {
                    next_units.push(unit);
                }
            }
        }
        if next_units.is_empty() {
            return Vec::new();
        }
        base_units = unanimous_receiver_units(next_units);
        if base_units.is_empty() {
            return Vec::new();
        }
    }
    base_units
}

fn receiver_units_from_bindings(
    node: Node<'_>,
    bindings: &HashSet<CppScanBinding>,
    ctx: &ScanCtx<'_>,
) -> Vec<CodeUnit> {
    let mut units = Vec::new();
    for binding in bindings {
        let raw_unit = if let Some(unit) = &binding.unit {
            unit.clone()
        } else {
            let Some(type_name) = binding.type_name.as_deref() else {
                return Vec::new();
            };
            let Some(unit) = receiver_type_name_unit(node, type_name, ctx) else {
                return Vec::new();
            };
            unit
        };
        if let Some(unit) = canonical_receiver_unit(&raw_unit, ctx) {
            units.push(unit);
            continue;
        }
        if let Some(unit) = recovered_receiver_alias_target(node, &raw_unit, ctx) {
            units.push(unit);
            continue;
        }
        return Vec::new();
    }
    unanimous_receiver_units(units)
}

/// Resolve a using-alias receiver from its declaration's structured RHS when
/// the alias target index cannot cross a malformed namespace-sentinel node.
/// The inverse target owner supplies only the exact class identity to prove;
/// lexical AST resolution still decides whether the alias denotes that class.
fn recovered_receiver_alias_target(
    reference: Node<'_>,
    alias: &CodeUnit,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    if !ctx
        .analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(alias))
    {
        return None;
    }
    let target = ctx.spec.owner.as_ref()?.clone();
    if !target.is_class() || alias.source() != ctx.file {
        return None;
    }
    let range = ctx
        .analyzer
        .ranges(alias)
        .into_iter()
        .find(|range| range.start_byte < range.end_byte)?;
    let mut node =
        root_node(reference).descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while node.kind() != "alias_declaration" {
        node = node.parent()?;
    }
    let type_descriptor = node.child_by_field_name("type")?;
    let type_node = first_type_child(type_descriptor).unwrap_or(type_descriptor);
    let resolution = resolve_type_node_lexically_for_target(
        type_node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &target,
        Some(&ctx.lexical_scope_cache),
        ctx.recovered_sentinel_scope(type_node).as_deref(),
    );
    if let LexicalTypeResolution::Resolved {
        unit, candidates, ..
    } = resolution
        && (same_visible_symbol(&unit, &target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &target)))
    {
        return Some(target);
    }
    let (components, global) = type_reference_components(type_node, ctx.source)?;
    let scope = ctx
        .recovered_sentinel_scope(type_node)
        .or_else(|| indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, type_node))?;
    let path_matches = indexed_scope_matches_target_name(&scope, &components, global, &target);
    let visible = ctx.visibility.external_type_candidate_visible_in_context(
        ctx.analyzer,
        ctx.file,
        &target,
        type_node,
    );
    (path_matches && visible).then_some(target)
}

fn receiver_type_name_unit(node: Node<'_>, type_name: &str, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let normalized = normalize_cpp_type_name(type_name);
    if normalized.is_empty() {
        return None;
    }

    // A function-local alias is intentionally absent from the visibility
    // index. Recover its RHS from the structured alias declaration before
    // trying file-visible type lookup; this keeps the alias's lexical shadow
    // boundary intact.
    if let Some(alias_type) = local_receiver_alias_type_node(node, &normalized, ctx) {
        let alias_type = receiver_type_node_base(alias_type);
        match ctx
            .visibility
            .resolve_type_node_result(ctx.file, alias_type, ctx.source)
        {
            Ok(Some(unit)) => return Some(unit),
            Err(()) => return None,
            Ok(None) => {}
        }
        if let Some(unit) = resolve_receiver_type_node_lexically(alias_type, ctx) {
            return Some(unit);
        }
    }

    match resolve_receiver_type_name_lexically(node, &normalized, ctx) {
        LexicalTypeResolution::Resolved { unit, .. } => return Some(unit),
        LexicalTypeResolution::Ambiguous => return None,
        LexicalTypeResolution::Missing => {}
    }
    let candidates = ctx
        .visibility
        .type_name_candidates(ctx.file, &normalized)
        .into_iter()
        .filter_map(|candidate| canonical_receiver_unit(candidate, ctx))
        .collect();
    unanimous_receiver_units(candidates).into_iter().next()
}

fn resolve_receiver_type_node_lexically(
    type_node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let type_node = receiver_type_node_base(type_node);
    let components = cpp_type_name_components(type_node, ctx.source)?;
    let lexical_scope = match enclosing_lexical_scope_components(
        type_node,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.source,
    ) {
        LexicalScopeResolution::Resolved(scope) => scope,
        LexicalScopeResolution::Ambiguous | LexicalScopeResolution::Missing => return None,
    };
    match ctx.visibility.resolve_type_components_lexically(
        ctx.analyzer,
        ctx.file,
        &components,
        is_globally_qualified_cpp_name(type_node),
        &lexical_scope,
    ) {
        LexicalTypeResolution::Resolved { unit, .. } => Some(unit),
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => None,
    }
}

fn receiver_type_node_base(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "type_descriptor" {
        let Some(inner) = node.child_by_field_name("type") else {
            break;
        };
        node = inner;
    }
    node
}

fn resolve_receiver_type_name_lexically(
    node: Node<'_>,
    normalized: &str,
    ctx: &ScanCtx<'_>,
) -> LexicalTypeResolution {
    let components = crate::analyzer::symbol_lookup::parse_symbol_path(
        crate::analyzer::Language::Cpp,
        normalized,
    );
    if components.is_empty() {
        return LexicalTypeResolution::Missing;
    }
    let lexical_scope = match enclosing_lexical_scope_components(
        node,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.source,
    ) {
        LexicalScopeResolution::Resolved(scope) => scope,
        LexicalScopeResolution::Ambiguous => return LexicalTypeResolution::Ambiguous,
        LexicalScopeResolution::Missing => return LexicalTypeResolution::Missing,
    };
    ctx.visibility.resolve_type_components_lexically(
        ctx.analyzer,
        ctx.file,
        &components,
        normalized.starts_with("::"),
        &lexical_scope,
    )
}

fn local_receiver_alias_type_node<'tree>(
    node: Node<'tree>,
    name: &str,
    ctx: &ScanCtx<'_>,
) -> Option<Node<'tree>> {
    let callable = nearest_callable_scope(node)?;
    let mut root_callable = callable;
    let mut ancestor = callable.parent();
    while let Some(current) = ancestor {
        if matches!(current.kind(), "function_definition" | "lambda_expression") {
            root_callable = current;
        }
        ancestor = current.parent();
    }

    let mut stack = vec![root_callable];
    let mut best = None;
    while let Some(current) = stack.pop() {
        if current.start_byte() >= node.start_byte() {
            continue;
        }
        if local_type_alias_name_node(current)
            .is_some_and(|alias_name| node_text(alias_name, ctx.source) == name)
            && local_alias_scope_contains_node(current, node)
        {
            let replace = best
                .is_none_or(|existing: Node<'tree>| existing.start_byte() < current.start_byte());
            if replace {
                best = current.child_by_field_name("type");
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    best
}

fn canonical_receiver_units(units: Vec<CodeUnit>, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
    let mut canonical = Vec::with_capacity(units.len());
    for unit in units {
        let Some(unit) = canonical_receiver_unit(&unit, ctx) else {
            return Vec::new();
        };
        canonical.push(unit);
    }
    unanimous_receiver_units(canonical)
}

fn canonical_receiver_unit(unit: &CodeUnit, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    if let Some(cached) = ctx.receiver_canonical_type_cache.borrow().get(unit) {
        return cached.clone();
    }
    let canonical = ctx
        .visibility
        .canonical_visible_full_type_unit(ctx.analyzer, ctx.file, unit);
    ctx.receiver_canonical_type_cache
        .borrow_mut()
        .insert(unit.clone(), canonical.clone());
    canonical
}

fn receiver_units_from_declared_fields(
    fields: Vec<&CodeUnit>,
    reference: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Vec<CodeUnit> {
    let Some(first) = fields.first() else {
        return Vec::new();
    };
    if fields
        .iter()
        .skip(1)
        .any(|field| !same_visible_symbol(first, field))
    {
        return Vec::new();
    }
    unanimous_receiver_units(
        fields
            .into_iter()
            .filter_map(|field| {
                field_declared_binding(ctx.analyzer, ctx.visibility, ctx.file, field)
                    .and_then(|binding| binding.unit)
                    .or_else(|| recovered_receiver_field_type(reference, field, ctx))
            })
            .collect(),
    )
}

/// Resolve a field receiver's declared type from its structured declaration
/// when the persisted type fact was built under a malformed sentinel scope.
/// The queried member owner supplies the exact class identity to prove; the
/// declaration's type node and recovered lexical path provide the evidence.
fn recovered_receiver_field_type(
    reference: Node<'_>,
    field: &CodeUnit,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let target = ctx.spec.owner.as_ref()?.clone();
    if !target.is_class() || field.source() != ctx.file {
        return None;
    }
    let range = ctx
        .analyzer
        .ranges(field)
        .into_iter()
        .find(|range| range.start_byte < range.end_byte)?;
    let mut declaration =
        root_node(reference).descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while !matches!(declaration.kind(), "declaration" | "field_declaration") {
        declaration = declaration.parent()?;
    }
    let type_node = first_type_child(declaration)?;
    let resolution = resolve_type_node_lexically_for_target(
        type_node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &target,
        Some(&ctx.lexical_scope_cache),
        ctx.recovered_sentinel_scope(type_node).as_deref(),
    );
    if let LexicalTypeResolution::Resolved {
        unit, candidates, ..
    } = resolution
        && (same_visible_symbol(&unit, &target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &target)))
    {
        return Some(target);
    }
    let type_node = receiver_type_node_base(type_node);
    let (components, global) = type_reference_components(type_node, ctx.source)?;
    let scope = ctx
        .recovered_sentinel_scope(type_node)
        .or_else(|| indexed_enclosing_lexical_scope(ctx.analyzer, ctx.file, type_node))?;
    (indexed_scope_matches_target_name(&scope, &components, global, &target)
        && ctx.visibility.external_type_candidate_visible_in_context(
            ctx.analyzer,
            ctx.file,
            &target,
            type_node,
        ))
    .then_some(target)
}

fn unanimous_receiver_units(units: Vec<CodeUnit>) -> Vec<CodeUnit> {
    let mut unique = Vec::new();
    for unit in units {
        if !unique
            .iter()
            .any(|existing| same_visible_symbol(existing, &unit))
        {
            unique.push(unit);
            if unique.len() > 1 {
                return Vec::new();
            }
        }
    }
    unique
}

fn receiver_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    match node.kind() {
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .is_some_and(|receiver| {
                receiver_is_self_like(receiver) && same_owner_context(receiver, ctx)
                    || receiver_type_units(receiver, ctx.source, ctx)
                        .iter()
                        .any(|target| {
                            receiver_owner_matches_target(target, owner, node.start_byte(), ctx)
                        })
            }),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(|function| receiver_matches_target(function, ctx)),
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(|child| receiver_matches_target(child, ctx)),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .is_some_and(|targets| {
                targets
                    .iter()
                    .filter_map(|target| target.unit.as_ref())
                    .any(|target| {
                        receiver_owner_matches_target(target, owner, node.start_byte(), ctx)
                    })
            }),
        "this" => same_owner_context(node, ctx),
        _ => qualified_owner_matches(node, ctx),
    }
}

fn declaring_owner_for_explicit_receiver(
    receiver: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> EnclosingMemberOwnerResolution {
    if receiver_is_self_like(receiver) {
        return EnclosingMemberOwnerResolution::Missing;
    }
    let receiver_units = receiver_type_units(receiver, ctx.source, ctx);
    let mut declaring_owner = None;
    for receiver_owner in receiver_units {
        if ctx.spec.owner.as_ref().is_some_and(|target_owner| {
            receiver_owner_matches_target(&receiver_owner, target_owner, receiver.start_byte(), ctx)
        }) {
            if declaring_owner
                .as_ref()
                .is_some_and(|existing| !same_visible_symbol(existing, &receiver_owner))
            {
                return EnclosingMemberOwnerResolution::Ambiguous;
            }
            declaring_owner = Some(receiver_owner);
            continue;
        }
        match cached_declaring_member_owner(&receiver_owner, ctx) {
            EnclosingMemberOwnerResolution::Owner(owner) => {
                if declaring_owner
                    .as_ref()
                    .is_some_and(|existing| !same_visible_symbol(existing, &owner))
                {
                    return EnclosingMemberOwnerResolution::Ambiguous;
                }
                declaring_owner = Some(owner);
            }
            EnclosingMemberOwnerResolution::Ambiguous => {
                return EnclosingMemberOwnerResolution::Ambiguous;
            }
            EnclosingMemberOwnerResolution::Missing => {}
        }
    }
    declaring_owner
        .map(EnclosingMemberOwnerResolution::Owner)
        .unwrap_or(EnclosingMemberOwnerResolution::Missing)
}

fn declaring_owner_from_call_function(
    function: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<EnclosingMemberOwnerResolution> {
    match function.kind() {
        "field_expression" => function
            .child_by_field_name("argument")
            .or_else(|| function.child_by_field_name("object"))
            .map(|receiver| declaring_owner_for_explicit_receiver(receiver, ctx))
            .or(Some(EnclosingMemberOwnerResolution::Missing)),
        "call_expression" => function
            .child_by_field_name("function")
            .and_then(|inner| declaring_owner_from_call_function(inner, ctx)),
        _ => None,
    }
}

enum MethodReceiverTargetResolution {
    Target,
    NonTarget,
    Ambiguous,
    Missing,
}

fn method_receiver_target_resolution(
    node: Node<'_>,
    declaring_owner: EnclosingMemberOwnerResolution,
    ctx: &ScanCtx<'_>,
) -> MethodReceiverTargetResolution {
    let Some(target_owner) = ctx.spec.owner.as_ref() else {
        return MethodReceiverTargetResolution::Missing;
    };
    match declaring_owner {
        EnclosingMemberOwnerResolution::Owner(owner)
            if receiver_owner_matches_target(&owner, target_owner, node.start_byte(), ctx) =>
        {
            MethodReceiverTargetResolution::Target
        }
        EnclosingMemberOwnerResolution::Owner(owner)
            if receiver_owner_is_known_non_target(&owner, target_owner, node.start_byte(), ctx) =>
        {
            MethodReceiverTargetResolution::NonTarget
        }
        EnclosingMemberOwnerResolution::Owner(_) => MethodReceiverTargetResolution::Missing,
        EnclosingMemberOwnerResolution::Ambiguous => MethodReceiverTargetResolution::Ambiguous,
        EnclosingMemberOwnerResolution::Missing if receiver_matches_target(node, ctx) => {
            MethodReceiverTargetResolution::Target
        }
        EnclosingMemberOwnerResolution::Missing if receiver_has_known_non_target(node, ctx) => {
            MethodReceiverTargetResolution::NonTarget
        }
        EnclosingMemberOwnerResolution::Missing => MethodReceiverTargetResolution::Missing,
    }
}

fn explicit_receiver_target_resolution(
    receiver: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> MethodReceiverTargetResolution {
    method_receiver_target_resolution(
        receiver,
        declaring_owner_for_explicit_receiver(receiver, ctx),
        ctx,
    )
}

fn call_function_target_resolution(
    function: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> MethodReceiverTargetResolution {
    let Some(declaring_owner) = declaring_owner_from_call_function(function, ctx) else {
        // A bare function identifier has an implicit receiver. Do not reinterpret
        // that identifier as a same-named type or value before enclosing-owner
        // lookup gets a chance to establish the member call.
        return MethodReceiverTargetResolution::Missing;
    };
    method_receiver_target_resolution(function, declaring_owner, ctx)
}

fn receiver_owner_matches_target(
    receiver_owner: &CodeUnit,
    target_owner: &CodeUnit,
    reference_byte: usize,
    ctx: &ScanCtx<'_>,
) -> bool {
    same_symbol(receiver_owner, target_owner)
        || same_logical_symbol(receiver_owner, target_owner)
            && (ctx.visibility.is_physically_visible(ctx.file, target_owner)
                || (ctx.spec.owner_is_forward_declaration
                    && ctx
                        .visibility
                        .is_physically_visible(ctx.file, receiver_owner))
                || visible_target_peer_matches_owner(receiver_owner, reference_byte, ctx)
                || target_group_contains_owner_peer(receiver_owner, ctx))
}

fn receiver_owner_is_known_non_target(
    receiver_owner: &CodeUnit,
    target_owner: &CodeUnit,
    reference_byte: usize,
    ctx: &ScanCtx<'_>,
) -> bool {
    if receiver_owner_matches_target(receiver_owner, target_owner, reference_byte, ctx) {
        return false;
    }
    if !same_logical_symbol(receiver_owner, target_owner) {
        return true;
    }
    !ctx.target_group.iter().any(|target| {
        same_logical_symbol(target, &ctx.spec.target) && target.source() == target_owner.source()
    })
}

fn target_group_contains_owner_peer(owner: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    ctx.visibility
        .external_type_declaration_visible_at(ctx.file, owner, usize::MAX)
        && ctx.target_group.iter().any(|target| {
            type_owner_of(ctx.analyzer, target)
                .as_ref()
                .is_some_and(|target_owner| {
                    same_symbol(target_owner, owner)
                        || (same_logical_symbol(target_owner, owner)
                            && target_owner.source() == owner.source())
                })
        })
}

fn visible_target_peer_matches_owner(
    owner: &CodeUnit,
    reference_byte: usize,
    ctx: &ScanCtx<'_>,
) -> bool {
    ctx.visibility
        .external_type_declaration_visible_at(ctx.file, owner, reference_byte)
        && ctx
            .visibility
            .visible_identifier_candidates(ctx.file, &ctx.spec.member_name)
            .any(|candidate| {
                cpp_callable_definitions_share_identity_evidence(
                    ctx.analyzer,
                    candidate,
                    &ctx.spec.target,
                ) && ctx.visibility.declaration_visible_at(
                    ctx.analyzer,
                    ctx.file,
                    candidate,
                    reference_byte,
                ) && type_owner_of(ctx.analyzer, candidate).as_ref().is_some_and(
                    |candidate_owner| {
                        same_symbol(candidate_owner, owner)
                            || (same_logical_symbol(candidate_owner, owner)
                                && candidate_owner.source() == owner.source())
                    },
                )
            })
}

fn receiver_is_self_like(node: Node<'_>) -> bool {
    match node.kind() {
        "this" => true,
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(receiver_is_self_like),
        _ => false,
    }
}

fn call_function_has_direct_self_receiver(function: Node<'_>) -> bool {
    match function.kind() {
        "field_expression" => function
            .child_by_field_name("argument")
            .or_else(|| function.child_by_field_name("object"))
            .is_some_and(receiver_is_self_like),
        _ => receiver_is_self_like(function),
    }
}

fn receiver_has_known_non_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    match node.kind() {
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .is_some_and(|receiver| {
                let units = receiver_type_units(receiver, ctx.source, ctx);
                !units.is_empty()
                    && units.iter().all(|target| {
                        receiver_owner_is_known_non_target(target, owner, node.start_byte(), ctx)
                    })
            }),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(|function| receiver_has_known_non_target(function, ctx)),
        "pointer_expression" | "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(|child| receiver_has_known_non_target(child, ctx)),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .is_some_and(|targets| {
                let units = targets
                    .iter()
                    .filter_map(|target| target.unit.as_ref())
                    .collect::<Vec<_>>();
                !units.is_empty()
                    && units.iter().all(|target| {
                        receiver_owner_is_known_non_target(target, owner, node.start_byte(), ctx)
                    })
            }),
        "this" => known_non_target_owner_context(node, ctx),
        "qualified_identifier" | "scoped_identifier" | "field_identifier" => {
            qualified_owner_is_known_non_target(node, ctx)
        }
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QualifiedOwnerResolution {
    Target,
    NonTarget,
    Unresolved,
}

#[derive(Clone)]
pub(in crate::analyzer::usages) enum LexicalScopeResolution {
    Resolved(Vec<String>),
    Ambiguous,
    Missing,
}

type LexicalScopeCache = RefCell<HashMap<(usize, usize, bool, bool), LexicalScopeResolution>>;

fn qualified_owner_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    qualified_owner_resolution(node, ctx) == QualifiedOwnerResolution::Target
}

fn qualified_owner_is_known_non_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    qualified_owner_resolution(node, ctx) == QualifiedOwnerResolution::NonTarget
}

fn is_structurally_qualified(node: Node<'_>) -> bool {
    matches!(node.kind(), "qualified_identifier" | "scoped_identifier")
}

fn qualified_owner_resolution(node: Node<'_>, ctx: &ScanCtx<'_>) -> QualifiedOwnerResolution {
    let Some(target_owner) = ctx.spec.owner.as_ref() else {
        return QualifiedOwnerResolution::Unresolved;
    };
    let Some((components, global)) = qualified_callable_owner_components(node, ctx.source) else {
        return QualifiedOwnerResolution::Unresolved;
    };
    if !global
        && !matches!(
            enclosing_lexical_scope_components(
                node,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
            ),
            LexicalScopeResolution::Resolved(_)
        )
    {
        return QualifiedOwnerResolution::Unresolved;
    }
    match resolve_type_components_lexically_at_for_target_with_scope_cache(
        node,
        &components,
        global,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        target_owner,
        false,
        Some(&ctx.lexical_scope_cache),
    ) {
        LexicalTypeResolution::Resolved { unit: owner, .. }
            if receiver_owner_matches_target(&owner, target_owner, node.start_byte(), ctx) =>
        {
            QualifiedOwnerResolution::Target
        }
        LexicalTypeResolution::Resolved { unit: owner, .. }
            if same_visible_symbol(&owner, target_owner) =>
        {
            QualifiedOwnerResolution::Unresolved
        }
        LexicalTypeResolution::Resolved { .. } => QualifiedOwnerResolution::NonTarget,
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => {
            QualifiedOwnerResolution::Unresolved
        }
    }
}

fn qualified_callable_owner_components(
    node: Node<'_>,
    source: &str,
) -> Option<(Vec<String>, bool)> {
    if !matches!(node.kind(), "qualified_identifier" | "scoped_identifier") {
        return None;
    }
    let global = is_globally_qualified_cpp_name(node);
    let mut components = Vec::new();
    append_cpp_name_components(node, source, &mut components)?;
    components.pop()?;
    (!components.is_empty()).then_some((components, global))
}

fn type_reference_components(node: Node<'_>, source: &str) -> Option<(Vec<String>, bool)> {
    if !matches!(
        node.kind(),
        "identifier"
            | "type_identifier"
            | "namespace_identifier"
            | "qualified_identifier"
            | "scoped_identifier"
            | "scoped_type_identifier"
            | "template_type"
            | "template_function"
    ) {
        return None;
    }
    let mut components = Vec::new();
    append_cpp_name_components(node, source, &mut components)?;
    (!components.is_empty()).then_some((components, is_globally_qualified_cpp_name(node)))
}

pub(super) fn enclosing_namespace_components(node: Node<'_>, source: &str) -> Vec<String> {
    let mut namespaces = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            let mut components = Vec::new();
            if append_cpp_name_components(name, source, &mut components).is_some() {
                namespaces.push(components);
            }
        }
        current = parent.parent();
    }
    namespaces.reverse();
    namespaces.into_iter().flatten().collect()
}

pub(in crate::analyzer::usages) fn enclosing_lexical_scope_components(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
) -> LexicalScopeResolution {
    enclosing_lexical_scope_components_with_unresolved_owner(
        node, analyzer, visibility, file, source, false, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn cached_enclosing_lexical_scope_components_with_unresolved_owner(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    allow_structured_unresolved_owner: bool,
    ignore_function_owner: bool,
    cache: Option<&LexicalScopeCache>,
) -> LexicalScopeResolution {
    let Some(cache) = cache else {
        return enclosing_lexical_scope_components_with_unresolved_owner(
            node,
            analyzer,
            visibility,
            file,
            source,
            allow_structured_unresolved_owner,
            ignore_function_owner,
        );
    };
    let (anchor_start, anchor_end) = lexical_scope_cache_anchor(node);
    let key = (
        anchor_start,
        anchor_end,
        allow_structured_unresolved_owner,
        ignore_function_owner,
    );
    if let Some(cached) = cache.borrow().get(&key).cloned() {
        return cached;
    }
    let resolved = enclosing_lexical_scope_components_with_unresolved_owner(
        node,
        analyzer,
        visibility,
        file,
        source,
        allow_structured_unresolved_owner,
        ignore_function_owner,
    );
    cache.borrow_mut().insert(key, resolved.clone());
    resolved
}

fn lexical_scope_cache_anchor(node: Node<'_>) -> (usize, usize) {
    let mut current = node;
    loop {
        if matches!(
            current.kind(),
            "function_definition"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "namespace_definition"
                | "translation_unit"
        ) {
            return (current.start_byte(), current.end_byte());
        }
        let Some(parent) = current.parent() else {
            return (current.start_byte(), current.end_byte());
        };
        current = parent;
    }
}

fn enclosing_lexical_scope_components_with_unresolved_owner(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    allow_structured_unresolved_owner: bool,
    ignore_function_owner: bool,
) -> LexicalScopeResolution {
    #[cfg(test)]
    LEXICAL_SCOPE_RECONSTRUCTIONS_FOR_TEST.with(|count| count.set(count.get() + 1));
    let namespace = enclosing_namespace_components(node, source);
    let mut scope = namespace.clone();
    let mut classes = Vec::new();
    let mut function_definition = None;
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            let mut components = Vec::new();
            if append_cpp_name_components(name, source, &mut components).is_some() {
                classes.push(components);
            }
        }
        if function_definition.is_none() && parent.kind() == "function_definition" {
            function_definition = Some(parent);
        }
        current = parent.parent();
    }
    let displaced_class_scope = has_recovered_class_shape_ancestor(node)
        || has_malformed_wrapper_function_definition_ancestor(node);
    let has_qualified_function_owner = function_definition
        .and_then(function_definition_owner_lookup_node)
        .is_some_and(|owner| {
            is_structurally_qualified(owner) && !is_macro_decorated_function_owner(owner)
        });
    let indexed_scope = displaced_class_scope
        .then(|| {
            indexed_structural_class_scope(visibility, file, node, source)
                .or_else(|| indexed_enclosing_owner_scope(analyzer, visibility, file, node))
        })
        .flatten()
        .or_else(|| {
            // A qualified out-of-line definition can lose its class owner from
            // the parser tree when a namespace sentinel or export macro wraps
            // the declaration.  Recover the indexed owner scope up front so
            // all unqualified type references in the body see the same class
            // boundary as C++ lookup, including aliases in parameters and
            // local declarations (not only template-argument leaves).
            (has_qualified_function_owner && function_definition.is_some())
                .then(|| indexed_enclosing_owner_scope(analyzer, visibility, file, node))
                .flatten()
                .filter(|indexed| {
                    qualified_owner_scope_is_recoverable(
                        indexed,
                        &namespace,
                        &classes,
                        function_definition
                            .and_then(function_definition_owner_lookup_node)
                            .and_then(|owner| qualified_callable_owner_components(owner, source))
                            .map(|(components, _)| components),
                    )
                })
        })
        .or_else(|| {
            // A nested class declaration can likewise lose one of its outer
            // class ancestors from the CST.  Prefer the exact indexed
            // structural class scope when the surviving parser names are a
            // suffix of that scope (for example `const_iterator` inside
            // `AnySpan<T>`).
            indexed_structural_class_scope(visibility, file, node, source)
                .or_else(|| indexed_enclosing_owner_scope(analyzer, visibility, file, node))
                .filter(|indexed| {
                    qualified_owner_scope_is_recoverable(indexed, &namespace, &classes, None)
                })
        })
        .or_else(|| {
            // Retain the existing indexed lexical-scope recovery for
            // unqualified function bodies.  It is intentionally last so a
            // canonical class owner wins whenever one is available.
            (classes.is_empty() && function_definition.is_some() && !has_qualified_function_owner)
                .then(|| indexed_enclosing_lexical_scope(analyzer, file, node))
                .flatten()
                .filter(|indexed| indexed.len() > namespace.len())
        });
    if let Some(indexed_scope) = indexed_scope.as_ref() {
        // A macro-displaced namespace can leave the parser with the real class
        // body but no namespace ancestor. Prefer the structural class match;
        // partial specializations whose structured name cannot round-trip use
        // the exact indexed enclosing-owner chain instead.
        scope = indexed_scope.clone();
        classes.clear();
    }

    if !ignore_function_owner
        && has_qualified_function_owner
        && let Some(function) = function_definition.and_then(function_definition_owner_lookup_node)
    {
        let Some((owner, global)) = qualified_callable_owner_components(function, source) else {
            return LexicalScopeResolution::Missing;
        };
        match visibility.resolve_type_components_lexically(analyzer, file, &owner, global, &scope) {
            LexicalTypeResolution::Resolved { components, .. } => scope = components,
            LexicalTypeResolution::Ambiguous => return LexicalScopeResolution::Ambiguous,
            LexicalTypeResolution::Missing if allow_structured_unresolved_owner => {
                if let Some(indexed) = indexed_scope.as_ref().filter(|indexed| {
                    qualified_owner_scope_is_recoverable(
                        indexed,
                        &namespace,
                        &classes,
                        Some(owner.clone()),
                    )
                }) {
                    scope = indexed.clone();
                } else {
                    scope = if global || owner.starts_with(&namespace) {
                        owner
                    } else {
                        let mut relative = namespace;
                        relative.extend(owner);
                        relative
                    };
                }
            }
            LexicalTypeResolution::Missing => {
                // Structural lexical resolution cannot see an owner class that
                // is reachable only through an in-scope `using namespace`
                // directive, so it would otherwise hard-fail here. The indexed
                // definition already carries the true fully-qualified owner
                // (its package reflects the directive), so recover the real
                // enclosing scope from the analyzer graph -- exactly the scope
                // chain real C++ unqualified lookup traverses. Only the strict
                // callers reach this arm; the best-effort callers above keep
                // their existing structural guess (and its query profile).
                match indexed_enclosing_owner_scope(analyzer, visibility, file, node) {
                    Some(indexed) => scope = indexed,
                    None => return LexicalScopeResolution::Missing,
                }
            }
        }
    }

    classes.reverse();
    scope.extend(classes.into_iter().flatten());
    LexicalScopeResolution::Resolved(scope)
}

fn has_recovered_class_shape_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition"
            && parent.child_by_field_name("type").is_some_and(|type_node| {
                matches!(
                    type_node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                )
            })
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn has_malformed_wrapper_function_definition_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition"
            && is_malformed_wrapper_function_definition(parent)
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn is_malformed_wrapper_function_definition(node: Node<'_>) -> bool {
    node.has_error()
        && node
            .child_by_field_name("declarator")
            .is_some_and(|declarator| {
                declarator.kind() != "function_declarator"
                    && first_descendant_of_kind(declarator, "function_declarator").is_none()
            })
}

/// Tree-sitter can make an attribute/nullability macro look like the namespace
/// component of a qualified function owner when it appears between the return
/// type and the declarator (for example `CordRep* absl_nullable VerifyTree`).
/// The recovered owner is not a C++ lexical owner, so callers resolving the
/// ordinary return/parameter type must retain the surrounding namespace scope.
fn is_macro_decorated_function_owner(node: Node<'_>) -> bool {
    node.child_by_field_name("scope")
        .and_then(|scope| recovered_macro_decorated_type_node(scope))
        .is_some()
}

fn indexed_structural_class_scope(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            return visibility.indexed_structural_class_scope(file, parent, source);
        }
        current = parent.parent();
    }
    None
}

/// Check that an indexed owner scope is a structured completion of the parser
/// scope rather than an unrelated same-spelled declaration.
///
/// Error recovery around C++ namespace sentinels can preserve only a subset of
/// the namespace/class chain.  The indexed definition still carries the full
/// owner path, so require every surviving parser component to occur in order
/// and require any explicit qualified function owner to be the terminal
/// suffix.  An empty parser scope is accepted only with that qualified-owner
/// suffix evidence; a lone top-level short name is not evidence that a
/// namespace was lost.
fn qualified_owner_scope_is_recoverable(
    indexed: &[String],
    namespace: &[String],
    classes: &[Vec<String>],
    qualified_owner: Option<Vec<String>>,
) -> bool {
    if let Some(owner) = qualified_owner {
        if indexed.len() <= owner.len() || !indexed.ends_with(&owner) {
            return false;
        }
        // A malformed namespace sentinel can erase every parser namespace
        // ancestor.  The indexed enclosing callable still provides an
        // authoritative class owner, so the qualified owner suffix itself is
        // enough evidence in that case.  When namespace components survived,
        // retain the stricter subsequence check below.
        if namespace.is_empty() {
            return true;
        }
        if indexed.len() <= namespace.len() {
            return false;
        }
        let mut prefix = indexed.iter();
        return namespace
            .iter()
            .all(|component| prefix.any(|candidate| candidate == component));
    }
    let class_components = classes.iter().flatten().cloned().collect::<Vec<_>>();
    if !class_components.is_empty() {
        return indexed.len() > class_components.len() && indexed.ends_with(&class_components);
    }
    if namespace.is_empty() || indexed.len() <= namespace.len() {
        return false;
    }
    let mut prefix = indexed.iter();
    namespace
        .iter()
        .all(|component| prefix.any(|candidate| candidate == component))
}

/// Whether `unit` is a real (non-alias) class owner. A `using` alias never
/// counts as the true lexical owner recovered from the indexed graph.
fn is_indexed_class_owner(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        && !analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(unit))
}

/// Recover the enclosing member's true lexical scope from the *indexed*
/// definition when structural resolution cannot see the owner class.
///
/// An out-of-line member defined at file scope (`int HTMLLayout::method()
/// {...}`) whose owner class is reachable only through an in-scope `using
/// namespace X;` directive cannot be resolved by `resolve_type_components_
/// lexically`, which walks structural lexical tiers and never consults
/// using-directives. The definition itself, however, is indexed with its true
/// fully-qualified identity (its package already reflects the directive), so
/// the analyzer graph knows the real owner. Walk from the reference's indexed
/// enclosing code unit up to the innermost enclosing class and return that
/// class's fully-qualified scope components (e.g. `["log4cxx", "HTMLLayout"]`)
/// -- exactly the scope chain C++ unqualified lookup traverses.
fn indexed_enclosing_owner_scope(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    node: Node<'_>,
) -> Option<Vec<String>> {
    visibility.indexed_enclosing_owner_scope(analyzer, file, node)
}

fn cached_indexed_enclosing_class_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let start = enclosing_context(node, ctx).enclosing?;
    crate::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
        ctx.analyzer.parent_of(unit)
    })
    .find(|unit| is_indexed_class_owner(ctx.analyzer, unit))
}

pub(in crate::analyzer::usages) fn resolve_type_node_lexically(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
) -> LexicalTypeResolution {
    let Some((components, global)) = type_reference_components(node, source) else {
        return LexicalTypeResolution::Missing;
    };
    let resolution = resolve_type_components_lexically_at(
        node,
        &components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
    );
    if !is_template_argument_type_leaf(node) {
        return resolution;
    }

    // Error recovery can detach a member function from its class while
    // leaving an unqualified type argument (for example `error_type` in
    // `expected<..., error_type>`). The normal structural scope then lacks
    // the class owner and resolves the wrong same-spelled alias, or fails
    // closed. The indexed enclosing unit still carries the authoritative
    // class scope; retry only this narrowly-shaped leaf with that scope.
    let Some(indexed_scope) = indexed_enclosing_lexical_scope(analyzer, file, node) else {
        return resolution;
    };
    let namespace_scope = enclosing_namespace_components(node, source);
    if indexed_scope.len() <= namespace_scope.len() {
        return resolution;
    }
    let indexed = visibility.resolve_type_components_lexically(
        analyzer,
        file,
        &components,
        global,
        &indexed_scope,
    );
    match indexed {
        LexicalTypeResolution::Resolved { ref unit, .. }
            if !visibility
                .external_type_candidate_visible_in_context(analyzer, file, unit, node) =>
        {
            resolution
        }
        LexicalTypeResolution::Resolved { .. } => indexed,
        _ => resolution,
    }
}

fn is_template_argument_type_leaf(node: Node<'_>) -> bool {
    let Some(type_descriptor) = node.parent() else {
        return false;
    };
    if type_descriptor.kind() != "type_descriptor"
        || type_descriptor.child_by_field_name("type") != Some(node)
    {
        return false;
    }
    let Some(arguments) = type_descriptor.parent() else {
        return false;
    };
    if arguments.kind() != "template_argument_list" {
        return false;
    }
    arguments.parent().is_some_and(|parent| {
        matches!(parent.kind(), "template_type" | "template_function")
            && parent.child_by_field_name("arguments") == Some(arguments)
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_node_lexically_for_target(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
    scope_cache: Option<&LexicalScopeCache>,
    recovered_scope: Option<&[String]>,
) -> LexicalTypeResolution {
    let Some((reference_components, global)) = type_reference_components(node, source) else {
        return LexicalTypeResolution::Missing;
    };
    let terminal = reference_components
        .last()
        .expect("type reference components are non-empty");
    if !visibility.coarse_unqualified_type_reference_may_resolve(file, terminal) {
        return LexicalTypeResolution::Missing;
    }
    let template_arguments = cpp_template_reference_arguments(node, source);
    let selects_concrete_specialization =
        template_arguments.is_some() && visibility.is_template_specialization(target);
    if !selects_concrete_specialization
        && !visibility.structured_type_reference_may_resolve_to_target(
            analyzer,
            file,
            std::slice::from_ref(terminal),
            false,
            &[],
            target,
        )
    {
        return LexicalTypeResolution::Missing;
    }
    if let Some(arguments) = template_arguments.as_ref() {
        let alias_resolution = if let Some(recovered_scope) = recovered_scope {
            resolve_type_components_lexically_at_preserving_alias_with_recovered_scope(
                node,
                &reference_components,
                global,
                analyzer,
                visibility,
                ordinary_type_imports,
                file,
                source,
                recovered_scope,
            )
        } else {
            resolve_type_components_lexically_at_preserving_alias_with_scope_cache(
                node,
                &reference_components,
                global,
                analyzer,
                visibility,
                ordinary_type_imports,
                file,
                source,
                scope_cache,
            )
        };
        return match alias_resolution {
            LexicalTypeResolution::Resolved {
                unit,
                components,
                candidates,
            } if visibility.template_alias_arguments_preserve_target(
                analyzer, file, &unit, arguments, target,
            ) =>
            {
                LexicalTypeResolution::Resolved {
                    unit: target.clone(),
                    components,
                    candidates,
                }
            }
            LexicalTypeResolution::Resolved {
                unit,
                components,
                candidates,
            } => match visibility.resolve_template_arguments(file, unit.clone(), arguments) {
                Ok(resolved_unit) => {
                    let target_guided = (!same_visible_symbol(&resolved_unit, target))
                        .then(|| {
                            target_guided_malformed_template_alias_resolution(
                                node,
                                analyzer,
                                visibility,
                                file,
                                arguments,
                                &reference_components,
                                target,
                            )
                        })
                        .flatten();
                    target_guided.unwrap_or(LexicalTypeResolution::Resolved {
                        unit: resolved_unit,
                        components,
                        candidates,
                    })
                }
                Err(()) => LexicalTypeResolution::Ambiguous,
            },
            LexicalTypeResolution::Missing => {
                let target_preserving = if let Some(recovered_scope) = recovered_scope {
                    resolve_type_components_lexically_at_for_target_with_recovered_scope(
                        node,
                        &reference_components,
                        global,
                        analyzer,
                        visibility,
                        ordinary_type_imports,
                        file,
                        source,
                        target,
                        true,
                        recovered_scope,
                    )
                } else {
                    resolve_type_components_lexically_at_for_target_with_scope_cache(
                        node,
                        &reference_components,
                        global,
                        analyzer,
                        visibility,
                        ordinary_type_imports,
                        file,
                        source,
                        target,
                        true,
                        scope_cache,
                    )
                };
                match target_preserving {
                    LexicalTypeResolution::Resolved {
                        unit: _,
                        components,
                        candidates,
                    } if template_reference_candidates_select_target(
                        node,
                        &candidates,
                        analyzer,
                        visibility,
                        file,
                        source,
                        target,
                    ) =>
                    {
                        LexicalTypeResolution::Resolved {
                            unit: target.clone(),
                            components,
                            candidates,
                        }
                    }
                    _ => target_guided_malformed_template_alias_resolution(
                        node,
                        analyzer,
                        visibility,
                        file,
                        arguments,
                        &reference_components,
                        target,
                    )
                    .unwrap_or(LexicalTypeResolution::Missing),
                }
            }
            LexicalTypeResolution::Ambiguous => LexicalTypeResolution::Ambiguous,
        };
    }
    let resolution = if let Some(recovered_scope) = recovered_scope {
        resolve_type_components_lexically_at_for_target_with_recovered_scope(
            node,
            &reference_components,
            global,
            analyzer,
            visibility,
            ordinary_type_imports,
            file,
            source,
            target,
            true,
            recovered_scope,
        )
    } else {
        resolve_type_components_lexically_at_for_target_with_scope_cache(
            node,
            &reference_components,
            global,
            analyzer,
            visibility,
            ordinary_type_imports,
            file,
            source,
            target,
            true,
            scope_cache,
        )
    };
    if !is_template_argument_type_leaf(node) {
        return resolution;
    }

    // Preprocessor recovery can lift a member declaration out of its class
    // field list.  The unqualified template argument is then resolved from
    // the namespace only, even though the indexed enclosing callable still
    // identifies the class owner.  Retry this exact leaf against that
    // structured owner scope; ordinary type nodes must continue to use the
    // parser-derived lexical scope so unrelated same-spelled aliases remain
    // excluded.
    let Some(indexed_scope) = indexed_enclosing_lexical_scope(analyzer, file, node) else {
        return resolution;
    };
    let namespace_scope = enclosing_namespace_components(node, source);
    if indexed_scope.len() <= namespace_scope.len() {
        return resolution;
    }
    let indexed = visibility.resolve_type_components_lexically_for_target(
        analyzer,
        file,
        &reference_components,
        global,
        &indexed_scope,
        target,
    );
    match indexed {
        LexicalTypeResolution::Resolved {
            ref unit,
            ref candidates,
            ..
        } if (same_visible_symbol(unit, target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, target)))
            && visibility
                .external_type_candidate_visible_in_context(analyzer, file, unit, node) =>
        {
            indexed
        }
        _ => resolution,
    }
}

#[allow(clippy::too_many_arguments)]
fn target_guided_malformed_template_alias_resolution(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    arguments: &[crate::analyzer::CppTemplateExpression],
    components: &[String],
    target: &CodeUnit,
) -> Option<LexicalTypeResolution> {
    if components.len() != 1 || !has_malformed_wrapper_function_definition_ancestor(node) {
        return None;
    }

    let identifier = &components[0];
    let namespace =
        visibility.target_preserving_reference_namespace(analyzer, file, identifier, target)?;
    let namespace_name = namespace.join("::");
    let candidates = visibility
        .visible_identifier_candidates(file, identifier)
        .filter(|candidate| {
            cpp_namespace_for(candidate).unwrap_or_default() == namespace_name
                && visibility.type_candidate_may_be_visible_before_reference(
                    analyzer,
                    file,
                    candidate,
                    node.start_byte(),
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    let first = candidates.first()?;
    if !candidates
        .iter()
        .all(|candidate| same_logical_symbol(first, candidate))
        || !candidates.iter().all(|candidate| {
            visibility.template_alias_arguments_preserve_target(
                analyzer, file, candidate, arguments, target,
            )
        })
    {
        return None;
    }

    let mut resolved_components = namespace;
    resolved_components.push(identifier.clone());
    Some(LexicalTypeResolution::Resolved {
        unit: target.clone(),
        components: resolved_components,
        candidates,
    })
}

fn resolve_type_node_lexically_for_target_without_visibility(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
) -> LexicalTypeResolution {
    let Some((components, global)) = type_reference_components(node, source) else {
        return LexicalTypeResolution::Missing;
    };
    let lexical_scope = match enclosing_lexical_scope_components_with_unresolved_owner(
        node,
        analyzer,
        visibility,
        file,
        source,
        true,
        recovered_macro_decorated_declarator_type(node)
            == Some(RecoveredDeclaratorTypeContext::FunctionDefinition),
    ) {
        LexicalScopeResolution::Resolved(scope) => scope,
        LexicalScopeResolution::Ambiguous => return LexicalTypeResolution::Ambiguous,
        LexicalScopeResolution::Missing => return LexicalTypeResolution::Missing,
    };
    visibility.resolve_type_components_lexically_for_target(
        analyzer,
        file,
        &components,
        global,
        &lexical_scope,
        target,
    )
}

fn type_node_has_exact_target_identity_without_visibility(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
) -> bool {
    let Some((components, global)) = type_reference_components(node, source) else {
        return false;
    };
    let LexicalScopeResolution::Resolved(lexical_scope) =
        enclosing_lexical_scope_components_with_unresolved_owner(
            node,
            analyzer,
            visibility,
            file,
            source,
            true,
            recovered_macro_decorated_declarator_type(node)
                == Some(RecoveredDeclaratorTypeContext::FunctionDefinition),
        )
    else {
        return false;
    };
    let target_name = cpp_name_for(target);
    lexical_component_tiers(&components, global, &lexical_scope)
        .any(|qualified| qualified.join("::") == target_name)
}

pub(super) fn resolve_using_enum_declaration_owner(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
) -> LexicalTypeResolution {
    let Some(type_node) = using_enum_declaration_type_node(node) else {
        return LexicalTypeResolution::Missing;
    };
    let mut components = Vec::new();
    if append_cpp_name_components(type_node, source, &mut components).is_none()
        || components.is_empty()
    {
        return LexicalTypeResolution::Missing;
    }
    resolve_type_components_lexically_at(
        type_node,
        &components,
        is_globally_qualified_cpp_name(type_node),
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
    )
}

pub(super) fn resolve_ordinary_using_declaration_owner(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
) -> LexicalTypeResolution {
    let Some(type_node) = ordinary_using_declaration_type_node(node) else {
        return LexicalTypeResolution::Missing;
    };
    let mut components = Vec::new();
    if append_cpp_name_components(type_node, source, &mut components).is_none()
        || components.len() < 2
    {
        return LexicalTypeResolution::Missing;
    }
    let lexical_scope =
        match enclosing_lexical_scope_components(type_node, analyzer, visibility, file, source) {
            LexicalScopeResolution::Resolved(scope) => scope,
            LexicalScopeResolution::Ambiguous => return LexicalTypeResolution::Ambiguous,
            LexicalScopeResolution::Missing => return LexicalTypeResolution::Missing,
        };
    visibility.resolve_type_components_lexically(
        analyzer,
        file,
        &components,
        is_globally_qualified_cpp_name(type_node),
        &lexical_scope,
    )
}

pub(super) fn using_enum_declaration_type_node(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "using_declaration"
        && (0..node.child_count()).any(|index| {
            node.child(index)
                .is_some_and(|child| child.kind() == "enum")
        }))
    .then(|| node.named_child(0))
    .flatten()
}

pub(super) fn ordinary_using_declaration_type_node(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "using_declaration"
        && using_enum_declaration_type_node(node).is_none()
        && using_namespace_directive_name_node(node).is_none())
    .then(|| node.named_child(0))
    .flatten()
}

/// Tree-sitter can recover `using ::absl::cord_internal::CordRep;` after an
/// undefined namespace-sentinel macro as a declaration whose type is the
/// all-caps sentinel and whose qualified declarator starts with a pseudo
/// `using` scope. The real imported name remains a structured qualified
/// identifier under that declarator. Recover only this exact CST envelope so
/// ordinary macro-decorated variables are not treated as imports.
fn recovered_macro_using_declaration_type_node<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, bool)> {
    if node.kind() != "declaration" {
        return None;
    }
    let macro_type = node.child_by_field_name("type")?;
    if macro_type.kind() != "type_identifier"
        || !cpp_export_macro_token(node_text(macro_type, source))
    {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "qualified_identifier" {
        return None;
    }
    let scope = declarator.child_by_field_name("scope")?;
    if scope.kind() != "namespace_identifier" || node_text(scope, source) != "using" {
        return None;
    }
    let target = declarator.child_by_field_name("name")?;
    let mut components = Vec::new();
    append_cpp_name_components(target, source, &mut components)?;
    (components.len() >= 2).then_some((target, is_globally_qualified_cpp_name(target)))
}

fn using_namespace_directive_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let is_directive = node.kind() == "using_directive"
        || (node.kind() == "using_declaration"
            && (0..node.child_count()).any(|index| {
                node.child(index)
                    .is_some_and(|child| child.kind() == "namespace")
            }));
    if !is_directive {
        return None;
    }
    node.child_by_field_name("name")
        .or_else(|| node.named_child(node.named_child_count().checked_sub(1)?))
}

fn using_named_scope(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "compound_statement"
                | "function_definition"
                | "lambda_expression"
                | "for_statement"
                | "while_statement"
                | "if_statement"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
        ) {
            return None;
        }
        current = parent.parent();
    }
    Some(enclosing_namespace_components(node, source))
}

fn ordinary_using_scope(node: Node<'_>) -> Option<(usize, usize, usize)> {
    let mut current = node.parent();
    while let Some(scope) = current {
        if matches!(
            scope.kind(),
            "compound_statement"
                | "declaration_list"
                | "field_declaration_list"
                | "translation_unit"
        ) {
            let mut depth = 0;
            let mut ancestor = scope.parent();
            while let Some(parent) = ancestor {
                depth += 1;
                ancestor = parent.parent();
            }
            return Some((scope.start_byte(), scope.end_byte(), depth));
        }
        current = scope.parent();
    }
    None
}

fn collect_source_using_index(
    source_file: &ProjectFile,
    root: Node<'_>,
    source: &str,
) -> SourceUsingIndex {
    let mut index = SourceUsingIndex::default();
    let orphaned_namespaces = collect_orphaned_namespace_envelopes(root, source);
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let required_guards = if callable_preprocessor_context_is_visible(node, source) {
            Some(HashSet::default())
        } else {
            preprocessor_guard_environment(node, source)
        };
        let Some(required_guards) = required_guards else {
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
            continue;
        };
        let target = if let Some(namespace_node) = using_namespace_directive_name_node(node) {
            let mut namespace_components = Vec::new();
            append_cpp_name_components(namespace_node, source, &mut namespace_components).map(
                |_| EffectiveUsingTarget::Namespace {
                    namespace_components,
                    global: is_globally_qualified_cpp_name(namespace_node),
                },
            )
        } else if let Some((type_node, global)) =
            recovered_macro_using_declaration_type_node(node, source)
        {
            let mut target_components = Vec::new();
            (append_cpp_name_components(type_node, source, &mut target_components).is_some()
                && target_components.len() >= 2)
                .then(|| EffectiveUsingTarget::Ordinary {
                    name: target_components
                        .last()
                        .expect("recovered ordinary using has a terminal component")
                        .clone(),
                    target_components,
                    global,
                })
        } else if let Some(type_node) = ordinary_using_declaration_type_node(node) {
            let mut target_components = Vec::new();
            (append_cpp_name_components(type_node, source, &mut target_components).is_some()
                && target_components.len() >= 2)
                .then(|| EffectiveUsingTarget::Ordinary {
                    name: target_components
                        .last()
                        .expect("ordinary using has a terminal component")
                        .clone(),
                    target_components,
                    global: is_globally_qualified_cpp_name(type_node),
                })
        } else {
            None
        };
        if let Some(target) = target
            && let Some((scope_start, scope_end, scope_depth)) = ordinary_using_scope(node)
        {
            let declaration_namespace = enclosing_namespace_components(node, source);
            let declaration_namespace = if declaration_namespace.is_empty() {
                recovered_orphaned_namespace_components(node, source, &orphaned_namespaces)
                    .unwrap_or(declaration_namespace)
            } else {
                declaration_namespace
            };
            let namespace_scope = using_named_scope(node, source);
            let lexical_depth = declaration_namespace.len();
            let binding = OrdinaryTypeImport {
                target,
                source: source_file.clone(),
                declaration_byte: node.end_byte(),
                scope_start,
                scope_end,
                scope_depth,
                lexical_depth,
                declaration_namespace,
                namespace_scope,
                resolved_target_components: None,
                required_guards,
            };
            match &binding.target {
                EffectiveUsingTarget::Ordinary { name, .. } => index
                    .ordinary_by_name
                    .entry(name.clone())
                    .or_default()
                    .push(binding),
                EffectiveUsingTarget::Namespace { .. } => index.directives.push(binding),
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    index
}

struct OrphanedNamespaceEnvelope {
    body_end: usize,
    components: Vec<String>,
    class_names: HashSet<String>,
    error_marked: bool,
}

/// Tree-sitter can terminate a namespace body at an object-like namespace
/// macro (for example `ABSL_NAMESPACE_BEGIN`), then parse the following
/// out-of-line definitions at translation-unit scope. A block-scoped using
/// declaration in one of those definitions still belongs to the namespace
/// selected by the malformed namespace envelope. Keep the envelope scan
/// source-local and reuse its structural ownership evidence for each using.
fn collect_orphaned_namespace_envelopes(
    root: Node<'_>,
    source: &str,
) -> Vec<OrphanedNamespaceEnvelope> {
    let mut envelopes = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.kind() == "namespace_definition"
            && let Some(body) = current.child_by_field_name("body")
            && current.end_byte() == body.end_byte()
            && let Some(name) = current.child_by_field_name("name")
        {
            let mut components = enclosing_namespace_components(current, source);
            if append_cpp_name_components(name, source, &mut components).is_some()
                && !components.is_empty()
            {
                let mut class_names = HashSet::default();
                let mut body_stack = vec![body];
                while let Some(node) = body_stack.pop() {
                    if let Some(name) = orphaned_class_definition_name(node, source) {
                        class_names.insert(name);
                    }
                    let mut cursor = node.walk();
                    if node.kind() == "ERROR" {
                        body_stack.extend(node.children(&mut cursor));
                    } else {
                        body_stack.extend(node.named_children(&mut cursor));
                    }
                }
                envelopes.push(OrphanedNamespaceEnvelope {
                    body_end: body.end_byte(),
                    components,
                    class_names,
                    error_marked: current.has_error(),
                });
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    envelopes
}

/// Lightweight type-reference variant of [`collect_orphaned_namespace_envelopes`].
/// Type recovery needs only the error-marked namespace boundary, not the
/// class-name inventory used by using-directive recovery. Prune clean
/// subtrees so repeated target scans do not walk every declaration body in a
/// malformed file; retaining all error-marked namespace envelopes lets the
/// target-guided caller reject a later unrelated namespace explicitly.
fn collect_orphaned_namespace_type_envelopes(
    root: Node<'_>,
    source: &str,
) -> Vec<OrphanedNamespaceEnvelope> {
    let mut envelopes = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.kind() == "namespace_definition"
            && current.has_error()
            && let Some(body) = current.child_by_field_name("body")
            && current.end_byte() == body.end_byte()
            && let Some(name) = current.child_by_field_name("name")
        {
            let mut components = enclosing_namespace_components(current, source);
            if append_cpp_name_components(name, source, &mut components).is_some() {
                envelopes.push(OrphanedNamespaceEnvelope {
                    body_end: body.end_byte(),
                    components,
                    class_names: HashSet::default(),
                    error_marked: true,
                });
            }
        }
        if !current.has_error() {
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(
            current
                .named_children(&mut cursor)
                .filter(|child| child.has_error()),
        );
    }
    envelopes
}

fn orphaned_class_definition_name(node: Node<'_>, source: &str) -> Option<String> {
    if matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        let body = node.child_by_field_name("body")?;
        let name = node.child_by_field_name("name")?;
        return (!name.is_missing() && !body.is_missing())
            .then(|| node_text(name, source).to_string());
    }
    if node.kind() != "ERROR" {
        return None;
    }

    // When an object-like namespace macro is parsed as a function definition,
    // tree-sitter can place the entire class declaration inside an ERROR node
    // and leave the `class`/`struct` keyword as an anonymous child. Keep the
    // fallback structural: accept only a named class-like keyword followed by
    // a real body, never an arbitrary identifier mentioned in the envelope.
    for index in 0..node.child_count() {
        let Some(keyword) = node.child(index) else {
            continue;
        };
        if !matches!(keyword.kind(), "class" | "struct" | "union") {
            continue;
        }
        let mut name = None;
        for next_index in (index + 1)..node.child_count() {
            let Some(next) = node.child(next_index) else {
                continue;
            };
            if next.kind() == ";" {
                break;
            }
            if next.kind() == "{" {
                return name
                    .filter(|name_node: &Node<'_>| !name_node.is_missing())
                    .map(|name_node| node_text(name_node, source).to_string());
            }
            if name.is_none() && matches!(next.kind(), "identifier" | "type_identifier") {
                name = Some(next);
            }
        }
    }
    None
}

fn recovered_orphaned_namespace_components(
    node: Node<'_>,
    source: &str,
    envelopes: &[OrphanedNamespaceEnvelope],
) -> Option<Vec<String>> {
    let owner_name = orphaned_using_owner_name(node, source)?;
    envelopes
        .iter()
        .filter(|envelope| {
            envelope.body_end <= node.start_byte() && envelope.class_names.contains(&owner_name)
        })
        .max_by_key(|envelope| envelope.body_end)
        .map(|envelope| envelope.components.clone())
}

fn orphaned_using_owner_name(node: Node<'_>, source: &str) -> Option<String> {
    let function = std::iter::successors(node.parent(), |current| current.parent())
        .find(|current| current.kind() == "function_definition")?;
    let owner = function_definition_owner_lookup_node(function)?;
    let scope = owner.child_by_field_name("scope")?;
    let mut components = Vec::new();
    append_cpp_name_components(scope, source, &mut components)?;
    // A qualified out-of-line member definition already carries its namespace
    // in the declarator scope (for example `foo::Widget::run`). The recovery
    // path is only for parser-orphaned top-level members whose owner scope
    // collapsed to the bare class name; requiring that shape prevents an
    // earlier, unrelated namespace/class from leaking into a global function's
    // using-directive lookup.
    if components.len() != 1 {
        return None;
    }
    components.pop()
}

fn build_project_using_index(visibility: &VisibilityIndex<'_>) -> ProjectUsingIndex {
    let mut project = ProjectUsingIndex::default();
    for source_file in visibility.all_visible_source_files() {
        visibility.note_using_source_index_walk_for_test();
        let Some(prepared) = visibility.cpp().prepared_syntax(&source_file) else {
            continue;
        };
        let source_index = collect_source_using_index(
            &source_file,
            prepared.tree().root_node(),
            prepared.source(),
        );
        for (name, bindings) in source_index.ordinary_by_name {
            project
                .ordinary_by_name
                .entry(name)
                .or_default()
                .extend(bindings);
        }
        project.directives.extend(source_index.directives);
    }
    project
}

fn effective_using_target_tiers(binding: &OrdinaryTypeImport) -> Vec<Vec<String>> {
    let (components, global) = match &binding.target {
        EffectiveUsingTarget::Ordinary {
            target_components,
            global,
            ..
        } => (target_components, *global),
        EffectiveUsingTarget::Namespace {
            namespace_components,
            global,
        } => (namespace_components, *global),
    };
    lexical_component_tiers(components, global, &binding.declaration_namespace).collect()
}

fn using_binding_target_components_for_name(
    binding: &OrdinaryTypeImport,
    project: &ProjectUsingIndex,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    name: &str,
) -> Option<Vec<String>> {
    let visible_candidates = visibility
        .visible_identifier_candidates(file, name)
        .filter(|candidate| {
            candidate.is_class()
                || is_type_alias(candidate)
                || (candidate.is_function() && type_owner_of(visibility.cpp(), candidate).is_none())
        })
        .collect::<Vec<_>>();
    if visible_candidates.is_empty() {
        return None;
    }
    match &binding.target {
        EffectiveUsingTarget::Ordinary {
            name: imported_name,
            ..
        } if imported_name == name => {
            effective_using_target_tiers(binding)
                .into_iter()
                .find(|qualified| {
                    let qualified_name = qualified.join("::");
                    visible_candidates
                        .iter()
                        .any(|candidate| cpp_name_for(candidate) == qualified_name)
                })
        }
        EffectiveUsingTarget::Namespace { .. } => {
            visibility.note_using_namespace_lookup_for_test();
            let target_tiers = effective_using_target_tiers(binding);
            let resolved = target_tiers
                .iter()
                .find(|namespace_components| {
                    let namespace = namespace_components.join("::");
                    visible_candidates.iter().any(|candidate| {
                        visibility.note_using_name_candidate_inspection_for_test();
                        cpp_namespace_for(candidate).is_some_and(|candidate_namespace| {
                            candidate_namespace == namespace
                                || candidate_namespace.starts_with(&format!("{namespace}::"))
                        })
                    }) || project.directives.iter().any(|candidate| {
                        candidate.namespace_scope.as_deref()
                            == Some(namespace_components.as_slice())
                    }) || project
                        .ordinary_by_name
                        .values()
                        .flatten()
                        .any(|candidate| {
                            candidate.namespace_scope.as_deref()
                                == Some(namespace_components.as_slice())
                        })
                })
                .cloned();
            resolved.or_else(|| {
                // A sole lexical namespace tier is itself enough to retain the
                // directive. Candidate identity is resolved later, where
                // target guidance and macro-expanded owner names are available.
                // Dropping it here makes an unrelated same-terminal type hide
                // the actual namespace member before lookup can compare owners.
                (target_tiers.len() == 1)
                    .then(|| target_tiers.into_iter().next())
                    .flatten()
            })
        }
        EffectiveUsingTarget::Ordinary { .. } => None,
    }
}

fn include_node_for_activation(root: Node<'_>, activation: usize) -> Option<Node<'_>> {
    let start = activation.checked_sub(1)?;
    let mut node = root.descendant_for_byte_range(start, activation)?;
    while node.kind() != "preproc_include" {
        node = node.parent()?;
    }
    Some(node)
}

fn project_using_bindings(
    binding: OrdinaryTypeImport,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
) -> Vec<OrdinaryTypeImport> {
    if binding.source == *file {
        return vec![binding];
    }
    if !visibility.source_is_visible(file, &binding.source) || binding.namespace_scope.is_none() {
        return Vec::new();
    }
    visibility.note_using_donor_activation_for_test();
    let Some(prepared) = visibility.cpp().prepared_syntax(file) else {
        return Vec::new();
    };
    let projections = visibility
        .include_activation_for_source(visibility.cpp(), file, prepared.as_ref(), &binding.source)
        .map_or_else(
            || {
                visibility.conditional_include_projections_for_source(
                    file,
                    prepared.as_ref(),
                    &binding.source,
                )
            },
            |activation_byte| {
                Arc::from([ConditionalIncludeProjection {
                    activation_byte,
                    required_guards: HashSet::default(),
                }])
            },
        );
    projections
        .iter()
        .cloned()
        .filter_map(|projection| {
            let required_guards =
                merge_preprocessor_guards(&binding.required_guards, &projection.required_guards)?;
            let mut projected = binding.clone();
            projected.required_guards = required_guards;
            project_using_binding_at_activation(projected, projection.activation_byte, root, source)
        })
        .collect()
}

fn project_using_binding_at_activation(
    mut binding: OrdinaryTypeImport,
    activation: usize,
    root: Node<'_>,
    source: &str,
) -> Option<OrdinaryTypeImport> {
    let include = include_node_for_activation(root, activation)?;
    let include_namespace = enclosing_namespace_components(include, source);
    let mut declaration_namespace = include_namespace.clone();
    declaration_namespace.extend(binding.declaration_namespace);
    binding.declaration_namespace = declaration_namespace;
    binding.declaration_byte = activation;
    if let Some(prefix) = using_named_scope(include, source) {
        let mut projected = prefix;
        projected.extend(binding.namespace_scope.take().unwrap_or_default());
        binding.scope_depth = projected.len();
        binding.lexical_depth = projected.len();
        binding.namespace_scope = Some(projected);
        binding.scope_start = 0;
        binding.scope_end = usize::MAX;
        Some(binding)
    } else if let Some((start, end, depth)) = ordinary_using_scope(include) {
        binding.namespace_scope = None;
        binding.scope_start = start;
        binding.scope_end = end;
        binding.scope_depth = depth;
        binding.lexical_depth = include_namespace.len();
        Some(binding)
    } else {
        None
    }
}

fn effective_using_bindings_for_name(
    visibility: &VisibilityIndex<'_>,
    imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    name: &str,
) -> Arc<[OrdinaryTypeImport]> {
    imports
        .projection_cell(name)
        .get_or_init(|| {
            let project = visibility.project_using_index(|| build_project_using_index(visibility));
            let mut projected = Vec::new();
            for binding in project
                .ordinary_by_name
                .get(name)
                .into_iter()
                .flatten()
                .chain(project.directives.iter())
            {
                if !visibility.source_is_visible(file, &binding.source) {
                    continue;
                }
                let Some(target_components) = using_binding_target_components_for_name(
                    binding, project, visibility, file, name,
                ) else {
                    continue;
                };
                let mut binding = binding.clone();
                binding.resolved_target_components = Some(target_components);
                projected.extend(project_using_bindings(
                    binding, visibility, file, root, source,
                ));
            }
            Arc::from(projected)
        })
        .clone()
}

pub(in crate::analyzer::usages) fn initialized_ordinary_type_imports(
    root: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
) -> OrdinaryTypeImportCell {
    let cell = visibility.ordinary_type_import_cell(file);
    let _ = (root, analyzer, source);
    cell
}

fn root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

fn effective_using_binding_active(
    binding: &OrdinaryTypeImport,
    node: Node<'_>,
    lexical_scope: &[String],
    source: &str,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
) -> bool {
    binding.declaration_byte <= node.start_byte()
        && preprocessor_guard_environment(node, source)
            .is_some_and(|active| binding.required_guards.is_subset(&active))
        && visibility.preprocessor_guards_stable_between(
            file,
            0,
            node.start_byte(),
            &binding.required_guards,
        )
        && binding.namespace_scope.as_ref().map_or_else(
            || binding.scope_start <= node.start_byte() && node.end_byte() <= binding.scope_end,
            |namespace| lexical_scope.starts_with(namespace),
        )
}

fn binding_type_candidates(
    binding: &OrdinaryTypeImport,
    active_bindings: &[&OrdinaryTypeImport],
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    name: &str,
    direct_target: Option<&CodeUnit>,
    reference_byte: usize,
) -> Vec<(CodeUnit, Vec<String>)> {
    let Some(qualified) = binding.resolved_target_components.clone() else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    match binding.target {
        EffectiveUsingTarget::Ordinary { .. } => targets.push(qualified),
        EffectiveUsingTarget::Namespace { .. } => {
            let mut stack = vec![qualified];
            let mut visited = HashSet::default();
            while let Some(namespace) = stack.pop() {
                if !visited.insert(namespace.clone()) {
                    continue;
                }
                let mut target = namespace.clone();
                target.push(name.to_string());
                targets.push(target);
                stack.extend(active_bindings.iter().filter_map(|candidate| {
                    (matches!(candidate.target, EffectiveUsingTarget::Namespace { .. })
                        && candidate.namespace_scope.as_deref() == Some(namespace.as_slice()))
                    .then(|| candidate.resolved_target_components.clone())
                    .flatten()
                }));
            }
        }
    }
    targets
        .into_iter()
        .flat_map(|target| {
            let mut candidates = visibility
                .visible_identifier_candidates(file, name)
                .filter(|candidate| {
                    (candidate.is_class() || is_type_alias(candidate))
                        && macro_expanded_cpp_name_components(
                            visibility,
                            file,
                            candidate,
                            reference_byte,
                        ) == target
                })
                .cloned()
                .collect::<Vec<_>>();
            if candidates.is_empty()
                && matches!(binding.target, EffectiveUsingTarget::Namespace { .. })
                && let Some(target_unit) = direct_target
            {
                let expanded_target_name = macro_expanded_cpp_name_components(
                    visibility,
                    file,
                    target_unit,
                    reference_byte,
                );
                if (target_unit.is_class() || is_type_alias(target_unit))
                    && expanded_target_name == target
                    && visibility.external_type_candidate_visible_at(
                        file,
                        target_unit,
                        reference_byte,
                    )
                {
                    candidates.push(target_unit.clone());
                }
            }
            if candidates.is_empty()
                && matches!(binding.target, EffectiveUsingTarget::Namespace { .. })
                && let Some(target_unit) = direct_target
            {
                let visible_types = visibility
                    .visible_identifier_candidates(file, name)
                    .filter(|candidate| candidate.is_class() || is_type_alias(candidate))
                    .collect::<Vec<_>>();
                let uniquely_names_target = !visible_types.is_empty()
                    && visible_types
                        .iter()
                        .all(|candidate| same_visible_symbol(candidate, target_unit));
                if uniquely_names_target {
                    candidates.extend(visible_types.into_iter().cloned());
                }
            }
            candidates
                .into_iter()
                .map(move |candidate| (candidate, target.clone()))
        })
        .collect()
}

fn macro_expanded_cpp_name_components(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    unit: &CodeUnit,
    reference_byte: usize,
) -> Vec<String> {
    crate::analyzer::symbol_lookup::parse_symbol_path(
        crate::analyzer::Language::Cpp,
        &cpp_name_for(unit),
    )
    .into_iter()
    .flat_map(|component| {
        let Some(replacement) =
            visibility.object_macro_replacement_at(file, &component, reference_byte)
        else {
            return vec![component];
        };
        let expanded = crate::analyzer::symbol_lookup::parse_symbol_path(
            crate::analyzer::Language::Cpp,
            &replacement,
        );
        if expanded.is_empty() {
            vec![component]
        } else {
            expanded
        }
    })
    .collect()
}

fn resolved_type_import(
    candidates: Vec<(CodeUnit, Vec<String>)>,
    lexical_depth: usize,
    is_direct: bool,
) -> OrdinaryTypeImportResolution {
    let mut logical = Vec::<(CodeUnit, Vec<String>)>::new();
    for candidate in candidates {
        if !logical
            .iter()
            .any(|(existing, _)| same_logical_symbol(existing, &candidate.0))
        {
            logical.push(candidate);
        }
    }
    match logical.as_slice() {
        [] => OrdinaryTypeImportResolution::Missing,
        [(target, target_components)] => OrdinaryTypeImportResolution::Resolved {
            target: target.clone(),
            target_components: target_components.clone(),
            lexical_depth,
            is_direct,
        },
        _ => OrdinaryTypeImportResolution::Ambiguous { lexical_depth },
    }
}

#[allow(clippy::too_many_arguments)]
fn ordinary_type_import_resolution(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    lexical_scope: &[String],
    direct_target: Option<&CodeUnit>,
) -> OrdinaryTypeImportResolution {
    if global || components.len() != 1 {
        return OrdinaryTypeImportResolution::Missing;
    }
    let _ = analyzer;
    let name = &components[0];
    let bindings =
        effective_using_bindings_for_name(visibility, imports, file, root_node(node), source, name);
    let active = bindings
        .iter()
        .filter(|binding| {
            effective_using_binding_active(binding, node, lexical_scope, source, visibility, file)
        })
        .collect::<Vec<_>>();
    let reference_guards = preprocessor_guard_environment(node, source);
    let transitive = bindings
        .iter()
        .filter(|binding| {
            binding.declaration_byte <= node.start_byte()
                && reference_guards
                    .as_ref()
                    .is_some_and(|active| binding.required_guards.is_subset(active))
                && visibility.preprocessor_guards_stable_between(
                    file,
                    0,
                    node.start_byte(),
                    &binding.required_guards,
                )
                && (binding.namespace_scope.is_some()
                    || (binding.scope_start <= node.start_byte()
                        && node.end_byte() <= binding.scope_end))
        })
        .collect::<Vec<_>>();
    let mut concrete_depths = active
        .iter()
        .filter(|binding| binding.namespace_scope.is_none())
        .map(|binding| binding.scope_depth)
        .collect::<Vec<_>>();
    concrete_depths.sort_unstable();
    concrete_depths.dedup();
    for depth in concrete_depths.into_iter().rev() {
        let at_tier = active
            .iter()
            .copied()
            .filter(|binding| binding.namespace_scope.is_none() && binding.scope_depth == depth);
        let direct = at_tier
            .clone()
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Ordinary { .. }))
            .flat_map(|binding| {
                binding_type_candidates(
                    binding,
                    &transitive,
                    visibility,
                    file,
                    name,
                    direct_target,
                    node.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !direct.is_empty() {
            return resolved_type_import(direct, lexical_scope.len(), true);
        }
        let directives = at_tier
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Namespace { .. }))
            .flat_map(|binding| {
                binding_type_candidates(
                    binding,
                    &transitive,
                    visibility,
                    file,
                    name,
                    direct_target,
                    node.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !directives.is_empty() {
            return resolved_type_import(directives, lexical_scope.len(), false);
        }
    }
    for prefix_len in (0..=lexical_scope.len()).rev() {
        let tier = &lexical_scope[..prefix_len];
        let at_tier = active
            .iter()
            .copied()
            .filter(|binding| binding.namespace_scope.as_deref() == Some(tier));
        let direct = at_tier
            .clone()
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Ordinary { .. }))
            .flat_map(|binding| {
                binding_type_candidates(
                    binding,
                    &transitive,
                    visibility,
                    file,
                    name,
                    direct_target,
                    node.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !direct.is_empty() {
            return resolved_type_import(direct, prefix_len, true);
        }
        let directives = at_tier
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Namespace { .. }))
            .flat_map(|binding| {
                binding_type_candidates(
                    binding,
                    &transitive,
                    visibility,
                    file,
                    name,
                    direct_target,
                    node.start_byte(),
                )
            })
            .collect::<Vec<_>>();
        if !directives.is_empty() {
            return resolved_type_import(directives, prefix_len, false);
        }
    }
    OrdinaryTypeImportResolution::Missing
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_type_components_lexically_at(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
) -> LexicalTypeResolution {
    resolve_type_components_lexically_at_inner(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        None,
        false,
        false,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_preserving_alias_with_scope_cache(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    scope_cache: Option<&LexicalScopeCache>,
) -> LexicalTypeResolution {
    resolve_type_components_lexically_at_inner(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        None,
        false,
        true,
        scope_cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_for_target_with_scope_cache(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
    apply_structured_prefilter: bool,
    scope_cache: Option<&LexicalScopeCache>,
) -> LexicalTypeResolution {
    resolve_type_components_lexically_at_inner(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        Some(target),
        apply_structured_prefilter,
        false,
        scope_cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_preserving_alias_with_recovered_scope(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    recovered_scope: &[String],
) -> LexicalTypeResolution {
    resolve_type_components_lexically_at_scoped(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        None,
        false,
        true,
        recovered_scope.to_vec(),
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_for_target_with_recovered_scope(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
    apply_structured_prefilter: bool,
    recovered_scope: &[String],
) -> LexicalTypeResolution {
    resolve_type_components_lexically_at_scoped(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        Some(target),
        apply_structured_prefilter,
        false,
        recovered_scope.to_vec(),
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_inner(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    direct_target: Option<&CodeUnit>,
    apply_structured_prefilter: bool,
    preserve_alias: bool,
    scope_cache: Option<&LexicalScopeCache>,
) -> LexicalTypeResolution {
    let lexical_scope = if global {
        Vec::new()
    } else {
        match cached_enclosing_lexical_scope_components_with_unresolved_owner(
            node,
            analyzer,
            visibility,
            file,
            source,
            true,
            recovered_macro_decorated_declarator_type(node)
                == Some(RecoveredDeclaratorTypeContext::FunctionDefinition),
            scope_cache,
        ) {
            LexicalScopeResolution::Resolved(scope) => scope,
            LexicalScopeResolution::Ambiguous => return LexicalTypeResolution::Ambiguous,
            LexicalScopeResolution::Missing => return LexicalTypeResolution::Missing,
        }
    };
    resolve_type_components_lexically_at_scoped(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        direct_target,
        apply_structured_prefilter,
        preserve_alias,
        lexical_scope,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_scoped(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex<'_>,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    direct_target: Option<&CodeUnit>,
    apply_structured_prefilter: bool,
    preserve_alias: bool,
    mut lexical_scope: Vec<String>,
) -> LexicalTypeResolution {
    if apply_structured_prefilter
        && direct_target.is_some()
        && !preserve_alias
        && !global
        && components.len() == 1
        && !visibility.coarse_unqualified_type_reference_may_resolve(file, &components[0])
    {
        return LexicalTypeResolution::Missing;
    }
    if !global
        && components.len() == 1
        // A recovered class may contain a real member function nested inside
        // the malformed outer wrapper (for example tinyxml2's macro-prefixed
        // XMLConstHandle).  The nearest function_definition is then the
        // member itself, so checking only that node misses the wrapper and
        // leaves an unqualified return type outside its namespace.  Walk the
        // complete ancestor chain for the malformed wrapper instead.
        && has_malformed_wrapper_function_definition_ancestor(node)
        && let Some(target) = direct_target
        && let Some(indexed_namespace) =
            visibility.target_preserving_reference_namespace(analyzer, file, &components[0], target)
        && (lexical_scope.is_empty() || !lexical_scope.starts_with(&indexed_namespace))
        && lexical_scope
            .last()
            .is_none_or(|last| last != &components[0])
    {
        // A malformed wrapper can make the indexed enclosing owner look like
        // the lexical namespace (for example XMLHandle around tinyxml2
        // declarations). Prefer the target's structured namespace whenever
        // the parser-derived scope is empty or clearly outside that namespace.
        lexical_scope = indexed_namespace;
    }
    if apply_structured_prefilter
        && let Some(target) = direct_target
        && !preserve_alias
        && !visibility.structured_type_reference_may_resolve_to_target(
            analyzer,
            file,
            components,
            global,
            &lexical_scope,
            target,
        )
    {
        return LexicalTypeResolution::Missing;
    }
    let normal = if preserve_alias {
        visibility.resolve_type_components_lexically_for_forward(
            analyzer,
            file,
            components,
            global,
            &lexical_scope,
        )
    } else {
        direct_target.map_or_else(
            || {
                visibility.resolve_type_components_lexically(
                    analyzer,
                    file,
                    components,
                    global,
                    &lexical_scope,
                )
            },
            |target| {
                visibility.resolve_type_components_lexically_for_target(
                    analyzer,
                    file,
                    components,
                    global,
                    &lexical_scope,
                    target,
                )
            },
        )
    };
    let normal = match normal {
        LexicalTypeResolution::Resolved { ref unit, .. }
            if !visibility
                .external_type_candidate_visible_in_context(analyzer, file, unit, node) =>
        {
            LexicalTypeResolution::Missing
        }
        resolution => resolution,
    };
    let normal_depth = match &normal {
        LexicalTypeResolution::Resolved { components, .. } => {
            Some(components.len().saturating_sub(1))
        }
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => None,
    };
    // Ordinary using-declarations participate in unqualified lookup at their
    // lexical scope. They therefore replace the resolver's terminal/global
    // fallback at the same or a shallower depth. A declaration in a more deeply
    // nested named scope is the closer lexical result and remains authoritative.
    // Ambiguous imports fail closed unless such a closer declaration exists.
    match ordinary_type_import_resolution(
        node,
        components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        &lexical_scope,
        direct_target,
    ) {
        OrdinaryTypeImportResolution::Missing => normal,
        OrdinaryTypeImportResolution::Resolved {
            lexical_depth,
            is_direct,
            ..
        } if matches!(&normal, LexicalTypeResolution::Ambiguous)
            || normal_depth.is_some_and(|depth| {
                depth > lexical_depth || (!is_direct && depth == lexical_depth)
            }) =>
        {
            normal
        }
        OrdinaryTypeImportResolution::Resolved {
            target,
            target_components,
            ..
        } => visibility.resolve_imported_type_candidate(
            analyzer,
            file,
            &target,
            &target_components,
            direct_target,
            preserve_alias,
        ),
        OrdinaryTypeImportResolution::Ambiguous { lexical_depth }
            if normal_depth.is_some_and(|depth| depth > lexical_depth) =>
        {
            normal
        }
        OrdinaryTypeImportResolution::Ambiguous { .. } => LexicalTypeResolution::Ambiguous,
    }
}

fn same_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    matches!(
        structured_owner_context_resolution(node, ctx),
        StructuredOwnerContextResolution::SelfTarget
            | StructuredOwnerContextResolution::InheritedTarget
    )
}

/// A bare/`this->` member call whose name resolves, through the enclosing class's base
/// hierarchy, to the target member declared on a base (the target owner). This is a
/// genuine external usage of the inherited base member rather than a same-type self call.
fn inherited_target_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    matches!(
        structured_owner_context_resolution(node, ctx),
        StructuredOwnerContextResolution::InheritedTarget
    )
}

fn known_non_target_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    matches!(
        structured_owner_context_resolution(node, ctx),
        StructuredOwnerContextResolution::NonTarget
    )
}

fn out_of_line_target_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            let Some(owner_lookup) = function_definition_owner_lookup_node(parent) else {
                return false;
            };
            if let Some(owners) = out_of_line_member_definition_owner(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
                owner_lookup,
            ) && let Some((_, owner)) = owners.innermost()
            {
                return receiver_owner_matches_target(owner, target_owner, node.start_byte(), ctx);
            }
            if let Some(owner) = target_guided_out_of_line_owner(owner_lookup, ctx) {
                return receiver_owner_matches_target(&owner, target_owner, node.start_byte(), ctx);
            }
            return false;
        }
        current = parent.parent();
    }
    false
}

#[cfg(test)]
mod effective_using_scale_tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, AnalyzerQueryScope, CodeUnitType, Language, TestProject, WorkspaceAnalyzer,
        resolve_analyzer,
    };
    use std::sync::Arc;

    fn reset_lexical_scope_reconstructions_for_test() {
        LEXICAL_SCOPE_RECONSTRUCTIONS_FOR_TEST.with(|count| count.set(0));
    }

    fn lexical_scope_reconstructions_for_test() -> usize {
        LEXICAL_SCOPE_RECONSTRUCTIONS_FOR_TEST.with(Cell::get)
    }

    #[test]
    fn effective_using_projection_and_callable_metadata_are_cached_at_scale() {
        const HEADER_COUNT: usize = 24;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let mut includes = String::new();
        for index in 0..HEADER_COUNT {
            let header = ProjectFile::new(root.clone(), format!("api_{index}.h"));
            let mut header_source = format!(
                "#pragma once\nnamespace api_{index} {{\nint Call_{index}(int value = 0);\n"
            );
            for unrelated in 0..64 {
                header_source.push_str(&format!("struct Noise_{index}_{unrelated} {{}};\n"));
            }
            header_source.push_str(&format!("}}\nusing namespace api_{index};\n"));
            header.write(header_source).expect("write scale header");
            includes.push_str(&format!("#include \"api_{index}.h\"\n"));
        }
        let left = ProjectFile::new(root.clone(), "left.cc");
        let right = ProjectFile::new(root.clone(), "right.cc");
        left.write(format!("{includes}int left() {{ return Call_0(); }}\n"))
            .expect("write left consumer");
        right
            .write(format!("{includes}int right() {{ return Call_0(); }}\n"))
            .expect("write right consumer");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).expect("C++ analyzer");
        let _scope = AnalyzerQueryScope::new(analyzer);
        let roots = HashSet::from_iter([left.clone(), right]);
        let visibility = VisibilityIndex::build(cpp, analyzer, &roots);
        let prepared = cpp.prepared_syntax(&left).expect("prepared left consumer");
        let root_node = prepared.tree().root_node();
        let imports = initialized_ordinary_type_imports(
            root_node,
            analyzer,
            &visibility,
            &left,
            prepared.source(),
        );

        for _ in 0..1_000 {
            assert!(
                effective_using_bindings_for_name(
                    &visibility,
                    &imports,
                    &left,
                    root_node,
                    prepared.source(),
                    "Absent",
                )
                .is_empty()
            );
        }
        let after_absent = visibility.using_work_counts_for_test();
        assert_eq!(
            after_absent.0,
            visibility.all_visible_source_files().len(),
            "the union source index must walk each physical source once"
        );
        assert_eq!(
            (
                after_absent.1,
                after_absent.2,
                after_absent.3,
                after_absent.4
            ),
            (0, 0, 0, 0),
            "an absent name must not activate donors, expand namespaces, hydrate callables, or inspect unrelated declarations"
        );
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let imports = Arc::clone(&imports);
                let left = left.clone();
                let visibility = &visibility;
                scope.spawn(move || {
                    let prepared = visibility
                        .cpp()
                        .prepared_syntax(&left)
                        .expect("prepared concurrent consumer");
                    for _ in 0..100 {
                        let _ = effective_using_bindings_for_name(
                            visibility,
                            &imports,
                            &left,
                            prepared.tree().root_node(),
                            prepared.source(),
                            "Call_0",
                        );
                    }
                });
            }
        });
        let after_projection = visibility.using_work_counts_for_test();
        assert!(
            after_projection.4 <= HEADER_COUNT,
            "namespace validation must inspect only requested-name candidates, not the unrelated declaration population: {after_projection:?}"
        );
        let _ = effective_using_bindings_for_name(
            &visibility,
            &imports,
            &left,
            root_node,
            prepared.source(),
            "Call_0",
        );
        assert_eq!(
            visibility.using_work_counts_for_test(),
            after_projection,
            "repeated name lookup must reuse donor projection and namespace expansion"
        );

        let callable = cpp
            .get_all_declarations()
            .into_iter()
            .find(|candidate| candidate.fq_name() == "api_0.Call_0" && candidate.is_function())
            .expect("scale callable");
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let callable = callable.clone();
                let left = left.clone();
                let visibility = &visibility;
                scope.spawn(move || {
                    for _ in 0..100 {
                        assert!(visibility
                            .callable_arity_at_reference(
                                analyzer,
                                &left,
                                &callable,
                                usize::MAX,
                            )
                            .is_some());
                    }
                });
            }
        });
        assert_eq!(
            visibility.using_work_counts_for_test().3,
            1,
            "repeated logical callable lookup must hydrate default metadata once"
        );
    }

    #[test]
    fn structured_prefilter_skips_unrelated_unqualified_type_before_scope_or_alias_work() {
        const NOISE_COUNT: usize = 96;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let header = ProjectFile::new(root.clone(), "types.h");
        let alias_header = ProjectFile::new(root.clone(), "aliases.h");
        alias_header
            .write("namespace aliasing { using SeenAlias = int; }\n")
            .expect("write alias header");
        let mut header_source =
            String::from("#include \"aliases.h\"\nnamespace target { struct Wanted {}; }\n");
        for index in 0..NOISE_COUNT {
            header_source.push_str(&format!(
                "namespace noise_{index} {{ struct Value {{}}; }}\n"
            ));
        }
        header.write(header_source).expect("write header");
        let consumer = ProjectFile::new(root.clone(), "consumer.cc");
        consumer
            .write(
                "#include \"types.h\"\nvoid consume() { Missing value; Missing<int> templated; }\n",
            )
            .expect("write consumer");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).expect("C++ analyzer");
        let _scope = AnalyzerQueryScope::new(analyzer);
        let roots = HashSet::from_iter([consumer.clone()]);
        let visibility = VisibilityIndex::build(cpp, analyzer, &roots);
        let prepared = cpp.prepared_syntax(&consumer).expect("prepared consumer");
        let source = prepared.source();
        let start = source.find("Missing").expect("unqualified type reference");
        let end = start + "Missing".len();
        let mut stack = vec![prepared.tree().root_node()];
        let mut type_node = None;
        while let Some(node) = stack.pop() {
            if node.start_byte() == start
                && node.end_byte() == end
                && matches!(node.kind(), "type_identifier" | "identifier")
            {
                type_node = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let type_node = type_node.expect("qualified type node");
        let template_start = source.rfind("Missing<int>").expect("template reference");
        let template_end = template_start + "Missing<int>".len();
        let mut stack = vec![prepared.tree().root_node()];
        let mut template_node = None;
        while let Some(node) = stack.pop() {
            if node.start_byte() == template_start
                && node.end_byte() == template_end
                && node.kind() == "template_type"
            {
                template_node = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let template_node = template_node.expect("template type node");
        let imports = initialized_ordinary_type_imports(
            prepared.tree().root_node(),
            analyzer,
            &visibility,
            &consumer,
            source,
        );
        let target = cpp
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.kind() == CodeUnitType::Class && unit.fq_name() == "target.Wanted")
            .expect("target declaration");
        let first_alias_names = visibility
            .visible_type_reference_component_names_for_target(analyzer, &consumer, &target);
        let second_alias_names = visibility
            .visible_type_reference_component_names_for_target(analyzer, &consumer, &target);
        assert_eq!(
            first_alias_names, second_alias_names,
            "repeated target component-name lookups must reuse the root alias index"
        );

        reset_lexical_scope_reconstructions_for_test();
        visibility.reset_target_preserving_type_resolution_count();
        for node in [type_node, template_node] {
            for _ in 0..2 {
                let resolution = resolve_type_node_lexically_for_target(
                    node,
                    analyzer,
                    &visibility,
                    &imports,
                    &consumer,
                    source,
                    &target,
                    None,
                    None,
                );
                assert!(
                    matches!(resolution, LexicalTypeResolution::Missing),
                    "an unrelated bare or template type must fail closed before scope reconstruction"
                );
            }
        }
        assert_eq!(
            lexical_scope_reconstructions_for_test(),
            0,
            "the coarse unqualified prefilter must bypass lexical-scope reconstruction"
        );
        assert_eq!(
            visibility.target_preserving_type_resolution_count(),
            0,
            "the coarse unqualified prefilter must bypass target-preserving lexical resolution"
        );
        assert_eq!(
            visibility.visible_parser_alias_name_set_build_count(),
            1,
            "the visible parser-alias-name set must build lazily once and then be reused"
        );
        assert_eq!(
            visibility.visible_parser_alias_target_names_build_count(),
            1,
            "the visible parser-alias target index must build once per root and serve repeated target scans"
        );
        assert_eq!(
            visibility.alias_source_parse_count_for_test(&alias_header),
            1,
            "the shared visible parser-alias-name set must parse each visible alias source at most once"
        );
    }
}

#[derive(Clone, Copy)]
enum StructuredOwnerContextResolution {
    /// The enclosing class is itself the target owner: a bare/`this->` call here is a
    /// genuine same-type self call (the SelfReceiver policy from #1014-B applies).
    SelfTarget,
    /// The enclosing class does not declare the member but inherits it from a base that
    /// is the target owner. A bare/`this->` call to that inherited member is a genuine
    /// external usage OF the base member (e.g. `Derived` calling inherited `Base::value`),
    /// not a self call, so it is attributed as an ordinary Reference.
    InheritedTarget,
    NonTarget,
    Ambiguous,
    Missing,
}

fn structured_owner_context_resolution(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> StructuredOwnerContextResolution {
    let Some(target_owner) = ctx.spec.owner.as_ref() else {
        return StructuredOwnerContextResolution::Missing;
    };
    let Some(enclosing_owner) = structured_enclosing_owner(node, ctx) else {
        return StructuredOwnerContextResolution::Missing;
    };
    if receiver_owner_matches_target(&enclosing_owner, target_owner, node.start_byte(), ctx) {
        return StructuredOwnerContextResolution::SelfTarget;
    }
    // The enclosing class is not the target owner, so any match reached by walking its
    // base hierarchy is an inherited-member usage of the base, not a self call.
    let member_owner = cached_declaring_member_owner(&enclosing_owner, ctx);
    match member_owner {
        EnclosingMemberOwnerResolution::Owner(owner)
            if receiver_owner_matches_target(&owner, target_owner, node.start_byte(), ctx) =>
        {
            StructuredOwnerContextResolution::InheritedTarget
        }
        EnclosingMemberOwnerResolution::Owner(_) => StructuredOwnerContextResolution::NonTarget,
        EnclosingMemberOwnerResolution::Ambiguous => StructuredOwnerContextResolution::Ambiguous,
        EnclosingMemberOwnerResolution::Missing => StructuredOwnerContextResolution::Missing,
    }
}

fn cached_declaring_member_owner(
    receiver_owner: &CodeUnit,
    ctx: &ScanCtx<'_>,
) -> EnclosingMemberOwnerResolution {
    if let Some(cached) = ctx.member_owner_cache.borrow().get(receiver_owner).cloned() {
        return cached;
    }
    let resolved = resolve_declaring_member_owner(
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        receiver_owner,
        &ctx.spec.member_name,
    );
    ctx.member_owner_cache
        .borrow_mut()
        .insert(receiver_owner.clone(), resolved.clone());
    resolved
}

fn structured_enclosing_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    // Declaration recovery can index the true class/member ranges even when
    // the original error tree wraps that region in a bogus function. Prefer
    // the analyzer's exact enclosing-owner graph at the reference byte before
    // interpreting such a wrapper as a real callable owner.
    if (has_recovered_class_shape_ancestor(node)
        || has_malformed_wrapper_function_definition_ancestor(node))
        && let Some(owner) = cached_indexed_enclosing_class_owner(node, ctx)
    {
        return Some(owner);
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            let owner_lookup = function_definition_owner_lookup_node(parent);
            if let Some(owner_lookup) = owner_lookup
                && let Some(owners) = out_of_line_member_definition_owner(
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    ctx.source,
                    owner_lookup,
                )
                && let Some((_, owner)) = owners.innermost()
            {
                return Some(owner.clone());
            }
            if let Some(owner) = cached_indexed_enclosing_class_owner(parent, ctx) {
                return Some(owner);
            }
            if let Some(owner) = enclosing_context(parent, ctx)
                .owner
                .filter(|owner| owner.is_class())
            {
                return Some(owner);
            }
            if let Some(owner_lookup) = owner_lookup
                && let Some(owner) = target_guided_out_of_line_owner(owner_lookup, ctx)
            {
                return Some(owner);
            }
            break;
        }
        current = parent.parent();
    }
    enclosing_context(node, ctx)
        .owner
        .filter(|owner| owner.is_class())
}

fn target_guided_out_of_line_owner(function: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let target_owner = ctx.spec.owner.as_ref()?;
    let (owner_components, _) = qualified_callable_owner_components(function, ctx.source)?;
    let owner_name = owner_components.last()?;
    let mut candidates = Vec::new();
    for candidate in ctx
        .visibility
        .visible_identifier_candidates(ctx.file, owner_name)
        .filter(|candidate| candidate.is_class())
    {
        let components = crate::analyzer::symbol_lookup::parse_symbol_path(
            crate::analyzer::Language::Cpp,
            &cpp_name_for(candidate),
        );
        if !components.ends_with(&owner_components)
            || candidates
                .iter()
                .any(|existing| same_logical_symbol(existing, candidate))
        {
            continue;
        }
        candidates.push(candidate.clone());
    }
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    (same_logical_symbol(candidate, target_owner)
        && target_group_contains_owner_peer(candidate, ctx))
    .then(|| candidate.clone())
}
