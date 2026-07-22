use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::usages::cpp_call_match::{
    CppArgType, cpp_filter_candidates_by_args, cpp_literal_arg_type, cpp_signature_param_types,
    cpp_type_text_pointer_depth, normalize_cpp_type_name,
};
use crate::analyzer::usages::cpp_graph::hits::{
    enclosing_context, is_member_field_own_declarator, push_definition_hit, push_hit,
    push_self_receiver_hit, push_type_hit, push_unproven_definition_hit, push_unproven_hit,
};
use crate::analyzer::usages::cpp_graph::resolver::*;
use crate::analyzer::usages::cpp_graph::syntax::explicit_qualified_callable_value;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CodeUnit, CppAnalyzer, IAnalyzer, ProjectFile, Range, cpp_node_text as node_text,
};
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::Node;

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct ScanCtx<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) visibility: &'a VisibilityIndex,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    ordinary_type_imports: OrdinaryTypeImportCell,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) target_group: &'a HashSet<CodeUnit>,
    pub(super) target_declaration_ranges: Vec<Range>,
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
    lexical_free_function_cache: RefCell<HashMap<(String, String), bool>>,
    member_owner_cache: RefCell<HashMap<CodeUnit, EnclosingMemberOwnerResolution>>,
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

pub(super) fn scan_prepared_file(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
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
    let mut ctx = ScanCtx {
        analyzer,
        visibility,
        file,
        source: prepared.source(),
        ordinary_type_imports,
        line_starts: prepared.line_starts(),
        spec,
        target_group,
        target_declaration_ranges,
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
        lexical_free_function_cache: RefCell::new(HashMap::default()),
        member_owner_cache: RefCell::new(HashMap::default()),
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
    {
        return;
    }
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration" => seed_typed_binding(node, ctx),
        "declaration" | "field_declaration" => seed_variable_declaration(node, ctx),
        "using_declaration" => seed_using_enum(node, ctx),
        _ => {}
    }
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
            if node.kind() == "declaration"
                && has_function_scope_ancestor(node)
                && let Some(name) = extract_variable_name(declarator, ctx.source)
            {
                ctx.local_shadows.declare_shadow(name);
            }
            continue;
        }
        let Some(name) = extract_variable_name(declarator, ctx.source) else {
            continue;
        };
        if node.kind() == "declaration" && has_function_scope_ancestor(node) {
            ctx.local_shadows.declare_shadow(name.clone());
        }
        let value = child.child_by_field_name("value");
        seed_binding_from_type_or_value(&name, type_node, value, ctx);
    }
}

fn seed_typed_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    if has_function_scope_ancestor(node) {
        ctx.local_shadows.declare_shadow(name.clone());
    }
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node));
    seed_binding_from_type_or_value(&name, type_node, None, ctx);
}

fn has_function_scope_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
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
            let unit = match ctx
                .visibility
                .resolve_type_node_result(ctx.file, node, ctx.source)
            {
                Ok(Some(unit)) => Some(unit),
                Ok(None) => ctx
                    .visibility
                    .canonical_type_for_reference(ctx.file, &name)
                    .or_else(|| ctx.visibility.resolve_type(ctx.file, &name)),
                Err(()) => None,
            };
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
    if node.kind() == "call_expression" {
        maybe_record_direct_temporary_type_hit(node, ctx);
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
    let recovered_type = recovered_macro_decorated_declarator_type(node).is_some();
    if !recovered_type
        && !matches!(
            node.kind(),
            "type_identifier" | "qualified_identifier" | "scoped_type_identifier" | "template_type"
        )
    {
        return;
    }
    if !recovered_type
        && matches!(node.kind(), "qualified_identifier" | "scoped_identifier")
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
        for (owner_node, owner) in owners.owners {
            if same_visible_symbol(&owner, &ctx.spec.target) {
                push_hit(owner_node, ctx);
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
    if !recovered_type && is_nested_type_node(node) {
        return;
    }
    if !recovered_type
        && let Some(call) = call_for_function_node(node)
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
        )
        && (same_visible_symbol(&unit, &ctx.spec.target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)))
    {
        if !direct_temporary_resolves_to_explicit_constructor(call, &unit, ctx) {
            *ctx.raw_match_count += 1;
            push_type_hit(
                type_reference_hit_node(node, ctx.file, ctx.source, &ctx.bindings),
                ctx,
            );
        }
        return;
    }
    if !recovered_type && is_declaration_name(node) {
        if let Some(owners) = out_of_line_member_definition_owner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
        ) {
            for (owner_node, owner) in owners.owners {
                if same_visible_symbol(&owner, &ctx.spec.target) {
                    *ctx.raw_match_count += 1;
                    push_hit(owner_node, ctx);
                }
            }
        }
        return;
    }
    let hit_node = node;
    let text = node_text(hit_node, ctx.source);
    let type_resolution = resolve_type_node_lexically_for_target(
        hit_node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &ctx.spec.target,
    );
    match type_resolution {
        LexicalTypeResolution::Resolved {
            unit, candidates, ..
        } if same_visible_symbol(&unit, &ctx.spec.target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
        {
            *ctx.raw_match_count += 1;
            push_type_hit(
                type_reference_hit_node(hit_node, ctx.file, ctx.source, &ctx.bindings),
                ctx,
            );
            return;
        }
        LexicalTypeResolution::Resolved { .. } => {
            if let Some(scopes) = static_qualifier_type_scopes(node, ctx) {
                *ctx.raw_match_count += 1;
                for scope in scopes {
                    push_type_hit(scope, ctx);
                }
            }
            return;
        }
        LexicalTypeResolution::Ambiguous => return,
        LexicalTypeResolution::Missing => {
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
                } if same_visible_symbol(unit, &ctx.spec.target)
                    || candidates
                        .iter()
                        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target))
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

fn call_for_function_node(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(node))
        .then_some(parent)
}

fn maybe_record_direct_temporary_type_hit(call: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    if !matches!(function.kind(), "identifier" | "template_function") {
        return;
    }
    let terminal = function_terminal_node(function);
    let name = node_text(terminal, ctx.source);
    if name.is_empty() || ctx.local_shadows.is_shadowed(name) {
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
        call,
        function,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
    ) {
        BareCallTargetResolution::Type(_) => {}
        BareCallTargetResolution::Ambiguous => {
            push_unproven_hit(function, ctx);
            return;
        }
        BareCallTargetResolution::FreeFunctions(_)
        | BareCallTargetResolution::UnprovenFreeFunctions(_)
        | BareCallTargetResolution::CallableShadow
        | BareCallTargetResolution::Missing => return,
    }
    match resolve_type_node_lexically_for_target(
        function,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        &ctx.spec.target,
    ) {
        LexicalTypeResolution::Resolved {
            unit, candidates, ..
        } if same_visible_symbol(&unit, &ctx.spec.target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
        {
            if direct_temporary_resolves_to_explicit_constructor(call, &unit, ctx) {
                return;
            }
            *ctx.raw_match_count += 1;
            push_type_hit(function, ctx);
        }
        LexicalTypeResolution::Resolved { .. }
        | LexicalTypeResolution::Ambiguous
        | LexicalTypeResolution::Missing => {}
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

fn binding_free_function_candidates(
    binding: &OrdinaryTypeImport,
    active_bindings: &[&OrdinaryTypeImport],
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
                binding_type_candidates(binding, &transitive_bindings, visibility, file, name)
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
                binding_type_candidates(binding, &transitive_bindings, visibility, file, name)
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

fn direct_temporary_resolves_to_explicit_constructor(
    call: Node<'_>,
    owner: &CodeUnit,
    ctx: &ScanCtx<'_>,
) -> bool {
    let Some(call_arity) = ctx
        .visibility
        .call_arity_evidence(ctx.file, call, ctx.source)
        .exact()
    else {
        return false;
    };
    matches!(
        ctx.visibility
            .visible_member_for_owner_name(ctx.file, owner, owner.identifier()),
        VisibleMemberResolution::Callable(constructors)
            if constructors.iter().any(|constructor| {
                cpp_callable_arity(ctx.analyzer, constructor).accepts(call_arity)
            })
    )
}

fn static_qualifier_type_scopes<'tree>(
    node: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<Vec<Node<'tree>>> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    // `maybe_record_type_hit` rejects nested type nodes before this helper, so
    // this root contains every structured component needed for prefix lookup.
    debug_assert!(!is_nested_type_node(node));
    let qualified = qualified_owner_components(node, ctx.source)?;
    let mut matches = Vec::new();
    for component_count in 1..=qualified.names.len() {
        match resolve_type_components_lexically_at_for_target(
            node,
            &qualified.names[..component_count],
            qualified.global,
            ctx.analyzer,
            ctx.visibility,
            &ctx.ordinary_type_imports,
            ctx.file,
            ctx.source,
            &ctx.spec.target,
        ) {
            LexicalTypeResolution::Resolved {
                unit, candidates, ..
            } if same_visible_symbol(&unit, &ctx.spec.target)
                || candidates
                    .iter()
                    .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
            {
                let matched = qualified.nodes[component_count - 1];
                if !matches.iter().any(|existing: &Node<'_>| {
                    existing.start_byte() == matched.start_byte()
                        && existing.end_byte() == matched.end_byte()
                }) {
                    matches.push(matched);
                }
            }
            // One ambiguous owner prefix makes the entire qualified occurrence
            // unsafe to attribute, even if another prefix happened to match.
            LexicalTypeResolution::Ambiguous => return None,
            LexicalTypeResolution::Resolved { .. } | LexicalTypeResolution::Missing => {}
        }
    }
    (!matches.is_empty()).then_some(matches)
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
    if ctx
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
                    push_hit(terminal, ctx);
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
        MethodReceiverTargetResolution::Missing if same_owner_context(function, ctx) => {
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
            if !receiver_owner_matches_target(&resolved_owner, owner, ctx) {
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
        if same_visible_symbol(unit, &ctx.spec.target) {
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
        if receiver_matches_target(node, ctx) {
            push_hit(field, ctx);
        } else if !receiver_has_known_non_target(node, ctx) {
            push_unproven_hit(field, ctx);
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

    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier" | "scoped_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
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
    if matches!(owner_context, StructuredOwnerContextResolution::Target) || unscoped_enum_match {
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
                        StructuredOwnerContextResolution::Target
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
    node.kind() != "qualified_identifier" && has_ancestor_kind(node, "qualified_identifier")
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
            "identifier" => {
                let name = node_text(current, source);
                let local = ctx.bindings.resolve_symbol(name);
                if let Some(bindings) = local.as_precise() {
                    break unanimous_receiver_units(
                        bindings
                            .iter()
                            .filter_map(|binding| binding.unit.clone())
                            .collect(),
                    );
                }
                if ctx.bindings.is_shadowed(name) {
                    return Vec::new();
                }
                if let Some(owner) = enclosing_context(current, ctx).owner {
                    let implicit_fields = ctx
                        .visibility
                        .visible_members_for_owner_name(ctx.file, &owner, name)
                        .into_iter()
                        .filter(|unit| unit.is_field())
                        .collect::<Vec<_>>();
                    if !implicit_fields.is_empty() {
                        break receiver_units_from_declared_fields(implicit_fields, ctx);
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
                break receiver_units_from_declared_fields(global_fields, ctx);
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
                break receiver_units_from_declared_fields(fields.iter().collect(), ctx);
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
            for field in ctx
                .visibility
                .visible_members_for_owner_name(ctx.file, owner, member_name)
                .into_iter()
                .filter(|unit| unit.is_field())
            {
                let Some(unit) =
                    field_declared_binding(ctx.analyzer, ctx.visibility, ctx.file, field)
                        .and_then(|binding| binding.unit)
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

fn canonical_receiver_units(units: Vec<CodeUnit>, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
    let mut canonical = Vec::with_capacity(units.len());
    for unit in units {
        let Some(unit) = ctx
            .visibility
            .canonical_type_unit(ctx.analyzer, ctx.file, &unit)
        else {
            return Vec::new();
        };
        canonical.push(unit);
    }
    unanimous_receiver_units(canonical)
}

fn receiver_units_from_declared_fields(fields: Vec<&CodeUnit>, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
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
            })
            .collect(),
    )
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
                        .any(|target| receiver_owner_matches_target(target, owner, ctx))
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
                    .any(|target| receiver_owner_matches_target(target, owner, ctx))
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
            if receiver_owner_matches_target(&owner, target_owner, ctx) =>
        {
            MethodReceiverTargetResolution::Target
        }
        EnclosingMemberOwnerResolution::Owner(owner)
            if receiver_owner_is_known_non_target(&owner, target_owner, ctx) =>
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
    ctx: &ScanCtx<'_>,
) -> bool {
    same_symbol(receiver_owner, target_owner)
        || (ctx.visibility.is_physically_visible(ctx.file, target_owner)
            || (ctx.spec.owner_is_forward_declaration
                && ctx
                    .visibility
                    .is_physically_visible(ctx.file, receiver_owner)))
            && same_logical_symbol(receiver_owner, target_owner)
}

fn receiver_owner_is_known_non_target(
    receiver_owner: &CodeUnit,
    target_owner: &CodeUnit,
    ctx: &ScanCtx<'_>,
) -> bool {
    if receiver_owner_matches_target(receiver_owner, target_owner, ctx) {
        return false;
    }
    if !same_logical_symbol(receiver_owner, target_owner) {
        return true;
    }
    !ctx.target_group.iter().any(|target| {
        same_logical_symbol(target, &ctx.spec.target) && target.source() == target_owner.source()
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
                    && units
                        .iter()
                        .all(|target| receiver_owner_is_known_non_target(target, owner, ctx))
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
                    && units
                        .iter()
                        .all(|target| receiver_owner_is_known_non_target(target, owner, ctx))
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

pub(in crate::analyzer::usages) enum LexicalScopeResolution {
    Resolved(Vec<String>),
    Ambiguous,
    Missing,
}

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
    match resolve_type_components_lexically_at_for_target(
        node,
        &components,
        global,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
        target_owner,
    ) {
        LexicalTypeResolution::Resolved { unit: owner, .. }
            if receiver_owner_matches_target(&owner, target_owner, ctx) =>
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
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
) -> LexicalScopeResolution {
    enclosing_lexical_scope_components_with_unresolved_owner(
        node, analyzer, visibility, file, source, false, false,
    )
}

fn enclosing_lexical_scope_components_with_unresolved_owner(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    allow_structured_unresolved_owner: bool,
    ignore_function_owner: bool,
) -> LexicalScopeResolution {
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
    if has_recovered_class_shape_ancestor(node)
        && let Some(indexed_classes) = indexed_enclosing_class_components(analyzer, file, node)
    {
        classes = indexed_classes
            .into_iter()
            .map(|component| vec![component])
            .collect();
    }

    if !ignore_function_owner
        && let Some(function) = function_definition.and_then(function_definition_name_node)
        && is_structurally_qualified(function)
    {
        let Some((owner, global)) = qualified_callable_owner_components(function, source) else {
            return LexicalScopeResolution::Missing;
        };
        match visibility
            .resolve_type_components_lexically(analyzer, file, &owner, global, &namespace)
        {
            LexicalTypeResolution::Resolved { components, .. } => scope = components,
            LexicalTypeResolution::Ambiguous => return LexicalScopeResolution::Ambiguous,
            LexicalTypeResolution::Missing if allow_structured_unresolved_owner => {
                scope = if global || owner.starts_with(&namespace) {
                    owner
                } else {
                    let mut relative = namespace;
                    relative.extend(owner);
                    relative
                };
            }
            LexicalTypeResolution::Missing => return LexicalScopeResolution::Missing,
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

fn indexed_enclosing_class_components(
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
    let mut current = analyzer.enclosing_code_unit(file, &range)?;
    let mut classes = Vec::new();
    loop {
        let is_alias = analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(&current));
        if current.is_class() && !is_alias {
            classes.push(current.identifier().to_string());
        }
        let Some(parent) = analyzer.parent_of(&current) else {
            break;
        };
        current = parent;
    }
    if classes.is_empty() {
        return None;
    }
    Some(classes)
}

pub(in crate::analyzer::usages) fn resolve_type_node_lexically(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
) -> LexicalTypeResolution {
    let Some((components, global)) = type_reference_components(node, source) else {
        return LexicalTypeResolution::Missing;
    };
    resolve_type_components_lexically_at(
        node,
        &components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
    )
}

fn resolve_type_node_lexically_for_target(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
) -> LexicalTypeResolution {
    let Some((components, global)) = type_reference_components(node, source) else {
        return LexicalTypeResolution::Missing;
    };
    if let Some(arguments) = cpp_template_reference_arguments(node, source) {
        let alias_resolution = resolve_type_components_lexically_at_preserving_alias(
            node,
            &components,
            global,
            analyzer,
            visibility,
            ordinary_type_imports,
            file,
            source,
        );
        return match alias_resolution {
            LexicalTypeResolution::Resolved {
                unit,
                components,
                candidates,
            } => match visibility.resolve_template_arguments(file, unit, &arguments) {
                Ok(unit) => LexicalTypeResolution::Resolved {
                    unit,
                    components,
                    candidates,
                },
                Err(()) => LexicalTypeResolution::Ambiguous,
            },
            unresolved => unresolved,
        };
    }
    resolve_type_components_lexically_at_for_target(
        node,
        &components,
        global,
        analyzer,
        visibility,
        ordinary_type_imports,
        file,
        source,
        target,
    )
}

fn resolve_type_node_lexically_for_target_without_visibility(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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

fn build_project_using_index(visibility: &VisibilityIndex) -> ProjectUsingIndex {
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
    visibility: &VisibilityIndex,
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
            effective_using_target_tiers(binding)
                .into_iter()
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
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
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    name: &str,
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
            let qualified_name = target.join("::");
            visibility
                .visible_identifier_candidates(file, name)
                .filter(move |candidate| {
                    (candidate.is_class() || is_type_alias(candidate))
                        && cpp_name_for(candidate) == qualified_name
                })
                .cloned()
                .map(move |candidate| (candidate, target.clone()))
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
    visibility: &VisibilityIndex,
    imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    lexical_scope: &[String],
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
                binding_type_candidates(binding, &transitive, visibility, file, name)
            })
            .collect::<Vec<_>>();
        if !direct.is_empty() {
            return resolved_type_import(direct, lexical_scope.len(), true);
        }
        let directives = at_tier
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Namespace { .. }))
            .flat_map(|binding| {
                binding_type_candidates(binding, &transitive, visibility, file, name)
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
                binding_type_candidates(binding, &transitive, visibility, file, name)
            })
            .collect::<Vec<_>>();
        if !direct.is_empty() {
            return resolved_type_import(direct, prefix_len, true);
        }
        let directives = at_tier
            .filter(|binding| matches!(binding.target, EffectiveUsingTarget::Namespace { .. }))
            .flat_map(|binding| {
                binding_type_candidates(binding, &transitive, visibility, file, name)
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
    visibility: &VisibilityIndex,
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
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_preserving_alias(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
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
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_for_target(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    target: &CodeUnit,
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
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_type_components_lexically_at_inner(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    ordinary_type_imports: &OrdinaryTypeImportCell,
    file: &ProjectFile,
    source: &str,
    direct_target: Option<&CodeUnit>,
    preserve_alias: bool,
) -> LexicalTypeResolution {
    let lexical_scope = if global {
        Vec::new()
    } else {
        match enclosing_lexical_scope_components_with_unresolved_owner(
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
        }
    };
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
        StructuredOwnerContextResolution::Target
    )
}

fn known_non_target_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    matches!(
        structured_owner_context_resolution(node, ctx),
        StructuredOwnerContextResolution::NonTarget
    )
}

#[cfg(test)]
mod effective_using_scale_tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, AnalyzerQueryScope, Language, TestProject, WorkspaceAnalyzer,
        resolve_analyzer,
    };
    use std::sync::Arc;

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
}

#[derive(Clone, Copy)]
enum StructuredOwnerContextResolution {
    Target,
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
    if receiver_owner_matches_target(&enclosing_owner, target_owner, ctx) {
        return StructuredOwnerContextResolution::Target;
    }
    let member_owner = cached_declaring_member_owner(&enclosing_owner, ctx);
    match member_owner {
        EnclosingMemberOwnerResolution::Owner(owner)
            if receiver_owner_matches_target(&owner, target_owner, ctx) =>
        {
            StructuredOwnerContextResolution::Target
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
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            let function = function_definition_name_node(parent)?;
            if let Some(owners) = out_of_line_member_definition_owner(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
                function,
            ) && let Some((_, owner)) = owners.innermost()
            {
                return Some(owner.clone());
            }
            break;
        }
        current = parent.parent();
    }
    enclosing_context(node, ctx)
        .owner
        .filter(|owner| owner.is_class())
}
