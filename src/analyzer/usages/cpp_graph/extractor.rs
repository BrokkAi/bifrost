use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::usages::cpp_call_match::{
    CppArgType, cpp_filter_candidates_by_args, cpp_literal_type_name, cpp_signature_param_types,
    cpp_type_text_pointer_depth, normalize_cpp_type_name,
};
use crate::analyzer::usages::cpp_graph::hits::{
    enclosing_context, is_member_field_declaration_context, push_definition_hit, push_hit,
    push_self_receiver_hit, push_type_hit, push_unproven_hit,
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
    let mut ctx = ScanCtx {
        analyzer,
        visibility,
        file,
        source: prepared.source(),
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
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
        .map(|node| node_text(node, ctx.source).to_string());
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
            continue;
        }
        let Some(name) = extract_variable_name(declarator, ctx.source) else {
            continue;
        };
        if node.kind() == "declaration" && has_function_scope_ancestor(node) {
            ctx.local_shadows.declare_shadow(name.clone());
        }
        let value = child.child_by_field_name("value");
        seed_binding_from_type_or_value(&name, type_text.as_deref(), value, ctx);
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
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
        .map(|node| node_text(node, ctx.source).to_string());
    seed_binding_from_type_or_value(&name, type_text.as_deref(), None, ctx);
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
    type_text: Option<&str>,
    value: Option<Node<'_>>,
    ctx: &mut ScanCtx<'_>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| normalize_type_text(text) != "auto")
        .map(|text| {
            let name = normalize_cpp_type_name(text);
            CppScanBinding::from_type_name(
                name.clone(),
                ctx.visibility
                    .canonical_type_for_reference(ctx.file, &name)
                    .or_else(|| ctx.visibility.resolve_type(ctx.file, &name)),
                cpp_type_text_pointer_depth(text),
            )
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
    if node.kind() == "using_declaration" {
        if let LexicalTypeResolution::Resolved { unit, .. } = resolve_using_enum_declaration_owner(
            node,
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
        ) && same_visible_symbol(&unit, &ctx.spec.target)
            && let Some(type_node) = using_enum_declaration_type_node(node)
        {
            *ctx.raw_match_count += 1;
            push_type_hit(type_node, ctx);
        }
        return;
    }
    let recovered_return_type = recovered_macro_function_return_type(node).is_some();
    if !recovered_return_type
        && !matches!(
            node.kind(),
            "type_identifier" | "qualified_identifier" | "scoped_type_identifier" | "template_type"
        )
    {
        return;
    }
    if !recovered_return_type
        && matches!(node.kind(), "qualified_identifier" | "scoped_identifier")
        && let Some(owners) = out_of_line_member_definition_owner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
        )
    {
        *ctx.raw_match_count += 1;
        for (owner_node, owner) in owners.owners {
            if same_visible_symbol(&owner, &ctx.spec.target) {
                push_hit(owner_node, ctx);
            }
        }
        return;
    }
    if !recovered_return_type && is_nested_type_node(node) {
        return;
    }
    if !recovered_return_type && is_declaration_name(node) {
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
    let type_resolution =
        resolve_type_node_lexically(hit_node, ctx.analyzer, ctx.visibility, ctx.file, ctx.source);
    match type_resolution {
        LexicalTypeResolution::Resolved {
            unit, candidates, ..
        } if same_visible_symbol(&unit, &ctx.spec.target)
            || candidates
                .iter()
                .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
        {
            *ctx.raw_match_count += 1;
            push_type_hit(hit_node, ctx);
            return;
        }
        LexicalTypeResolution::Resolved { .. } => {
            if let Some(scope) = static_qualifier_type_scope(node, ctx) {
                *ctx.raw_match_count += 1;
                push_hit(scope, ctx);
            }
            return;
        }
        LexicalTypeResolution::Ambiguous => return,
        LexicalTypeResolution::Missing => {}
    }
    if ctx
        .visibility
        .parser_alias_resolves_to_type(ctx.analyzer, ctx.file, text, &ctx.spec.target)
    {
        *ctx.raw_match_count += 1;
        push_type_hit(hit_node, ctx);
        return;
    }
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(scope) = static_qualifier_type_scope(node, ctx) {
        push_hit(scope, ctx);
    } else if !ctx.visibility.is_visible(ctx.file, &ctx.spec.target) {
        if let Some(scope) = static_qualifier_name_scope(node, ctx) {
            push_unproven_hit(scope, ctx);
        } else {
            push_unproven_hit(hit_node, ctx);
        }
    }
}

fn static_qualifier_type_scope<'tree>(node: Node<'tree>, ctx: &ScanCtx<'_>) -> Option<Node<'tree>> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() != "qualified_identifier" {
            continue;
        }
        if let Some((components, global)) =
            qualified_callable_owner_components_in_context(current, ctx.source)
        {
            match resolve_type_components_lexically_at(
                current,
                &components,
                global,
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
            ) {
                LexicalTypeResolution::Resolved {
                    unit, candidates, ..
                } if same_visible_symbol(&unit, &ctx.spec.target)
                    || candidates
                        .iter()
                        .any(|candidate| same_visible_symbol(candidate, &ctx.spec.target)) =>
                {
                    return qualified_owner_terminal_scope_node(current);
                }
                LexicalTypeResolution::Ambiguous => return None,
                LexicalTypeResolution::Resolved { .. } | LexicalTypeResolution::Missing => {}
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
        if field_initializer_constructs_target(node, ctx, owner)
            && ctx
                .spec
                .callable_arity
                .is_none_or(|expected| expected.accepts(call_arity(node)))
        {
            push_hit(node, ctx);
        }
        return;
    }
    if node.kind() == "declaration" {
        if declaration_is_object_construction_candidate(node, ctx)
            && declaration_mentions_type(node, ctx, owner)
            && ctx
                .spec
                .callable_arity
                .is_none_or(|expected| expected.accepts(declaration_constructor_arity(node, ctx)))
        {
            push_hit(node, ctx);
        }
        return;
    }
    let Some(type_node) = constructor_type_node(node) else {
        return;
    };
    let text = node_text(type_node, ctx.source);
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.callable_arity
        && !expected.accepts(call_arity(node))
    {
        return;
    }
    if ctx
        .visibility
        .resolves_to_type(ctx.analyzer, ctx.file, text, owner)
    {
        push_hit(type_node, ctx);
    } else {
        push_unproven_hit(type_node, ctx);
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
    if let Some(expected) = ctx.spec.callable_arity
        && !expected.accepts(call_arity(node))
    {
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
        push_hit(function, ctx);
    } else if ctx.visibility.resolve_known_non_target(
        ctx.file,
        text,
        TargetKind::FreeFunction,
        &ctx.spec.target,
    ) {
        // An explicitly namespace-qualified call to a different namespace (e.g. `other::run()` when
        // the target is `ns::run`) is a proven non-match, not an unresolved reference.
    } else {
        push_unproven_hit(function, ctx);
    }
}

fn free_function_call_may_target(call: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.param_types.is_none() {
        return true;
    }
    let mut candidates = ctx
        .visibility
        .named_candidates(ctx.file, text, TargetKind::FreeFunction);
    let arity = call_arity(call);
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
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .map(|arg| expression_arg_type(arg, ctx))
        .collect()
}

fn expression_arg_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CppArgType> {
    match node.kind() {
        "number_literal" | "true" | "false" | "char_literal" | "string_literal"
        | "unary_expression" => cpp_literal_type_name(node, ctx.source).map(|name| CppArgType {
            name: name.to_string(),
            unit: ctx.visibility.resolve_type(ctx.file, name),
            indirection: 0,
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
    if is_declaration_name(node) || cpp_reference_is_call_callee(node) {
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

/// Whether `node` is (part of) the callee expression of a call — walking through
/// the qualified/template/field wrappers so `foo`, `ns::foo`, and `obj.foo` in
/// `…()` are all recognised (and thus left to the call_expression arm).
fn cpp_reference_is_call_callee(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "call_expression" => {
                return parent
                    .child_by_field_name("function")
                    .or_else(|| parent.named_child(0))
                    == Some(node);
            }
            "qualified_identifier" | "template_function" | "field_expression" => node = parent,
            _ => return false,
        }
    }
    false
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
        push_unproven_hit(function, ctx);
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
        if let Some(expected) = ctx.spec.callable_arity
            && !expected.accepts(call_arity(node))
        {
            return;
        }
        if receiver_matches_target(receiver, ctx) {
            if receiver_is_self_like(receiver) {
                push_self_receiver_hit(operator, ctx);
            } else {
                push_hit(operator, ctx);
            }
        } else if !receiver_has_known_non_target(receiver, ctx) {
            push_unproven_hit(operator, ctx);
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
    if let Some(expected) = ctx.spec.callable_arity
        && !expected.accepts(call_arity(node))
    {
        return;
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
    if receiver_matches_target(function, ctx) {
        if receiver_is_self_like(function) {
            push_self_receiver_hit(function_terminal_node(function), ctx);
        } else {
            push_hit(function_terminal_node(function), ctx);
        }
    } else if same_owner_context(function, ctx) {
        push_self_receiver_hit(function_terminal_node(function), ctx);
    } else if function.kind() == "identifier" && resolves_to_lexical_free_function(function, ctx) {
        // A visible namespace/free function is a proven negative once the
        // enclosing structured owner and its hierarchy contain no such member.
    } else if !receiver_has_known_non_target(function, ctx)
        && !known_non_target_owner_context(function, ctx)
    {
        push_unproven_hit(function_terminal_node(function), ctx);
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
    let arity = call_arity(call);
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
            QualifiedOwnerResolution::Unresolved => push_unproven_hit(function, ctx),
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
        push_unproven_hit(function, ctx);
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
    let Some(expected) = ctx.spec.callable_arity else {
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
        || is_member_field_declaration_context(node, ctx)
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
        || is_member_field_declaration_context(node, ctx)
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
    let mut current = node;
    loop {
        match current.kind() {
            "this" => return true,
            "field_expression" => {
                let Some(receiver) = current
                    .child_by_field_name("argument")
                    .or_else(|| current.child_by_field_name("object"))
                else {
                    return false;
                };
                current = receiver;
            }
            "call_expression" => {
                let Some(function) = current.child_by_field_name("function") else {
                    return false;
                };
                current = function;
            }
            "pointer_expression" | "parenthesized_expression" => {
                let Some(inner) = current
                    .child_by_field_name("argument")
                    .or_else(|| current.named_child(0))
                else {
                    return false;
                };
                current = inner;
            }
            _ => return false,
        }
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

pub(super) enum LexicalScopeResolution {
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
    let lexical_scope = match enclosing_lexical_scope_components(
        node,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.source,
    ) {
        LexicalScopeResolution::Resolved(scope) => scope,
        LexicalScopeResolution::Ambiguous | LexicalScopeResolution::Missing => {
            return QualifiedOwnerResolution::Unresolved;
        }
    };
    match ctx.visibility.resolve_type_components_lexically(
        ctx.analyzer,
        ctx.file,
        &components,
        global,
        &lexical_scope,
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

fn qualified_callable_owner_components_in_context(
    node: Node<'_>,
    source: &str,
) -> Option<(Vec<String>, bool)> {
    let (components, mut global) = qualified_callable_owner_components(node, source)?;
    let mut prefixes = Vec::new();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() != "qualified_identifier"
            || parent.child_by_field_name("name") != Some(current)
        {
            break;
        }
        if let Some(scope) = parent.child_by_field_name("scope") {
            let mut prefix = Vec::new();
            append_cpp_name_components(scope, source, &mut prefix)?;
            prefixes.push(prefix);
        } else if parent.child(0).is_some_and(|child| child.kind() == "::") {
            global = true;
        } else {
            return None;
        }
        current = parent;
    }
    prefixes.reverse();
    let mut qualified = prefixes.into_iter().flatten().collect::<Vec<_>>();
    qualified.extend(components);
    (!qualified.is_empty()).then_some((qualified, global))
}

fn qualified_owner_terminal_scope_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "qualified_identifier" {
            return node.child_by_field_name("scope");
        }
        node = name;
    }
}

fn type_reference_components(node: Node<'_>, source: &str) -> Option<(Vec<String>, bool)> {
    if !matches!(
        node.kind(),
        "type_identifier"
            | "namespace_identifier"
            | "qualified_identifier"
            | "scoped_type_identifier"
            | "template_type"
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

pub(super) fn enclosing_lexical_scope_components(
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

pub(super) fn resolve_type_node_lexically(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
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
        file,
        source,
    )
}

pub(super) fn resolve_using_enum_declaration_owner(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
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
        file,
        source,
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

fn resolve_type_components_lexically_at(
    node: Node<'_>,
    components: &[String],
    global: bool,
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
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
            recovered_macro_function_return_type(node).is_some(),
        ) {
            LexicalScopeResolution::Resolved(scope) => scope,
            LexicalScopeResolution::Ambiguous => return LexicalTypeResolution::Ambiguous,
            LexicalScopeResolution::Missing => return LexicalTypeResolution::Missing,
        }
    };
    visibility.resolve_type_components_lexically(analyzer, file, components, global, &lexical_scope)
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
    let cached = ctx
        .member_owner_cache
        .borrow()
        .get(&enclosing_owner)
        .cloned();
    let member_owner = if let Some(cached) = cached {
        cached
    } else {
        let resolved = resolve_enclosing_member_owner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            &enclosing_owner,
            &ctx.spec.member_name,
        );
        ctx.member_owner_cache
            .borrow_mut()
            .insert(enclosing_owner, resolved.clone());
        resolved
    };
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
