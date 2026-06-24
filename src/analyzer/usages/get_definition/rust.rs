use super::*;
use crate::analyzer::rust::lexical_scope;

pub(super) fn resolve_rust(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return no_definition("rust_analyzer_unavailable", "Rust analyzer is unavailable");
    };
    let reference = site.text.as_str();
    if reference.contains('.')
        && let Some(tree) = tree
        && let Some(outcome) = resolve_rust_field(analyzer, support, file, source, tree, site)
    {
        return outcome;
    }
    let refs = rust.reference_context_of(file);
    let (candidates, scoped_lookup_failed) = if let Some((path, name)) = reference.rsplit_once("::")
    {
        let resolved = refs
            .resolve_scoped(path, name)
            .map(|fqn| support.fqn(&fqn))
            .unwrap_or_default();
        (resolved, true)
    } else {
        let mut resolved = refs
            .resolve_bare(reference)
            .map(|fqn| support.fqn(fqn))
            .unwrap_or_default();
        if resolved.is_empty() {
            let imported = rust_imported_export_candidates(
                rust,
                support,
                file,
                reference,
                Some(site.range.start_byte),
            );
            resolved = if imported.is_empty() {
                support.file_identifier(file, reference)
            } else {
                imported
            };
        }
        (resolved, false)
    };
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if rust_reference_looks_external(reference) {
        return boundary(format!(
            "`{reference}` appears to cross a Rust crate/module boundary not indexed in this workspace"
        ));
    }
    if scoped_lookup_failed {
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve through its Rust module path"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Rust definition"),
    )
}

fn resolve_rust_field(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    if let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
        && let Some(field_expression) = rust_enclosing_field_expression(node)
    {
        let field = field_expression.child_by_field_name("field")?;
        let member = rust_node_text(field, source).trim();
        let receiver = field_expression.child_by_field_name("value")?;
        let owner = rust_expression_type_fqn(
            analyzer,
            support,
            file,
            source,
            tree.root_node(),
            receiver,
            field_expression.start_byte(),
        )?;
        let candidates = rust_member_candidates(
            support.fqn(&format!("{owner}.{member}")),
            rust_field_expression_member_kind(field_expression),
        );
        return if candidates.is_empty() {
            Some(no_definition(
                "no_indexed_definition",
                format!("`{owner}.{member}` is not indexed as a Rust definition"),
            ))
        } else {
            Some(candidates_outcome(candidates))
        };
    }
    rust_resolve_dotted_reference_text(analyzer, support, file, source, tree, site)
}

fn rust_resolve_dotted_reference_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let segments = dotted_reference_segments(site)?;
    if segments.len() < 2 {
        return None;
    }
    let focus_index = dotted_focus_segment_index(site, &segments)?;
    if focus_index == 0 {
        return None;
    }
    let base = &segments[0].0;
    let mut owner = if base == "self" {
        let node = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )?;
        rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)?
    } else {
        rust_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            tree.root_node(),
            base,
            site.range.start_byte,
        )?
    };
    for (index, (member, _, _)) in segments.iter().enumerate().skip(1) {
        let candidates = rust_member_candidates(
            support.fqn(&format!("{owner}.{member}")),
            RustMemberKind::Field,
        );
        if index == focus_index {
            return if candidates.is_empty() {
                Some(no_definition(
                    "no_indexed_definition",
                    format!("`{owner}.{member}` is not indexed as a Rust definition"),
                ))
            } else {
                Some(candidates_outcome(candidates))
            };
        }
        if candidates.is_empty() {
            return None;
        }
        owner = rust_field_type_fqn(analyzer, support, file, source, &owner, member, false)?;
    }
    None
}

fn dotted_reference_segments(site: &ResolvedReferenceSite) -> Option<Vec<(String, usize, usize)>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for part in site.text.split('.') {
        if part.is_empty()
            || !part
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return None;
        }
        let start = offset;
        let end = start + part.len();
        segments.push((part.to_string(), start, end));
        offset = end + 1;
    }
    Some(segments)
}

fn dotted_focus_segment_index(
    site: &ResolvedReferenceSite,
    segments: &[(String, usize, usize)],
) -> Option<usize> {
    let focus = site.focus_start_byte.checked_sub(site.range.start_byte)?;
    segments
        .iter()
        .position(|(_, start, end)| *start <= focus && focus < *end)
}

fn rust_enclosing_field_expression(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "field_expression" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

#[derive(Debug, Clone, Copy)]
enum RustMemberKind {
    Field,
    Function,
}

fn rust_field_expression_member_kind(field_expression: Node<'_>) -> RustMemberKind {
    if let Some(parent) = field_expression.parent()
        && parent.kind() == "call_expression"
        && parent
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == field_expression.id())
    {
        RustMemberKind::Function
    } else {
        RustMemberKind::Field
    }
}

fn rust_member_candidates(candidates: Vec<CodeUnit>, kind: RustMemberKind) -> Vec<CodeUnit> {
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| match kind {
            RustMemberKind::Field => unit.is_field(),
            RustMemberKind::Function => unit.is_function(),
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn rust_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "self" => rust_enclosing_impl_type_fqn(analyzer, support, file, source, expression),
        "identifier" => rust_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            rust_node_text(expression, source).trim(),
            before_byte,
        ),
        "field_expression" => {
            let receiver = expression.child_by_field_name("value")?;
            let field = expression.child_by_field_name("field")?;
            let owner = rust_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                before_byte,
            )?;
            let member = rust_node_text(field, source).trim();
            rust_field_type_fqn(analyzer, support, file, source, &owner, member, false)
        }
        "call_expression" => rust_value_type_fqn(analyzer, support, file, source, root, expression),
        "try_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_unwrapped_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                )
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn(analyzer, support, file, source, root, child, before_byte)
            })
        }
        _ => None,
    }
}

fn rust_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let mut found = None;
    let ctx = RustBindingLookupCtx {
        analyzer,
        support,
        file,
        source,
        root,
        name,
        before_byte,
    };
    rust_collect_binding_type_fqn(ctx, root, &mut found);
    found
}

#[derive(Clone, Copy)]
struct RustBindingLookupCtx<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    name: &'a str,
    before_byte: usize,
}

fn rust_collect_binding_type_fqn(
    ctx: RustBindingLookupCtx<'_, '_>,
    node: Node<'_>,
    found: &mut Option<String>,
) {
    if node.start_byte() >= ctx.before_byte {
        return;
    }
    match node.kind() {
        "parameter" => {
            if let Some((binding, type_node)) = rust_typed_binding(node, ctx.source)
                && binding == ctx.name
                && let Some(fqn) = rust_resolve_type_node_fqn(
                    ctx.analyzer,
                    ctx.support,
                    ctx.file,
                    ctx.source,
                    type_node,
                    Some(type_node.start_byte()),
                )
            {
                *found = Some(fqn);
            }
        }
        "let_declaration" => {
            if let Some(binding) = node
                .child_by_field_name("pattern")
                .and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                && binding == ctx.name
            {
                if let Some(type_node) = node.child_by_field_name("type")
                    && let Some(fqn) = rust_resolve_type_node_fqn(
                        ctx.analyzer,
                        ctx.support,
                        ctx.file,
                        ctx.source,
                        type_node,
                        Some(type_node.start_byte()),
                    )
                {
                    *found = Some(fqn);
                } else if let Some(value) = node.child_by_field_name("value")
                    && let Some(fqn) = rust_value_type_fqn(
                        ctx.analyzer,
                        ctx.support,
                        ctx.file,
                        ctx.source,
                        ctx.root,
                        value,
                    )
                {
                    *found = Some(fqn);
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= ctx.before_byte {
            break;
        }
        if rust_scope_boundary_excludes_reference(child, ctx.before_byte) {
            continue;
        }
        rust_collect_binding_type_fqn(ctx, child, found);
    }
}

fn rust_scope_boundary_excludes_reference(node: Node<'_>, reference_byte: usize) -> bool {
    rust_is_scope_boundary(node.kind())
        && !(node.start_byte() <= reference_byte && reference_byte <= node.end_byte())
}

fn rust_is_scope_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "block"
            | "block_expression"
            | "closure_expression"
            | "const_item"
            | "enum_item"
            | "function_item"
            | "impl_item"
            | "macro_definition"
            | "mod_item"
            | "static_item"
            | "trait_item"
    )
}

fn rust_typed_binding<'tree>(node: Node<'tree>, source: &str) -> Option<(String, Node<'tree>)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = rust_simple_identifier_text(pattern, source)?;
    let type_node = node.child_by_field_name("type")?;
    Some((name, type_node))
}

fn rust_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value: Node<'_>,
) -> Option<String> {
    match value.kind() {
        "try_expression" => {
            let mut cursor = value.walk();
            value.named_children(&mut cursor).find_map(|child| {
                rust_unwrapped_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    value.start_byte(),
                )
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = value.walk();
            value
                .named_children(&mut cursor)
                .find_map(|child| rust_value_type_fqn(analyzer, support, file, source, root, child))
        }
        "call_expression" => {
            let function = value.child_by_field_name("function")?;
            if function.kind() == "field_expression"
                && let Some(method) = function.child_by_field_name("field")
                && let Some(receiver) = function.child_by_field_name("value")
            {
                let method_name = rust_node_text(method, source).trim();
                if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
                    return rust_unwrapped_expression_type_fqn(
                        analyzer,
                        support,
                        file,
                        source,
                        root,
                        receiver,
                        value.start_byte(),
                    );
                }
                let owner = rust_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    receiver,
                    value.start_byte(),
                )?;
                return rust_callable_return_type_fqn(
                    analyzer,
                    support,
                    file,
                    support.fqn(&format!("{owner}.{method_name}")),
                    false,
                );
            }
            let name = rust_callable_name(function, source)?;
            rust_callable_return_type_fqn(
                analyzer,
                support,
                file,
                rust_named_candidates(support, file, &name),
                false,
            )
        }
        "struct_expression" => {
            let name = value.child_by_field_name("name")?;
            rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                name,
                Some(name.start_byte()),
            )
        }
        _ => None,
    }
}

fn rust_unwrapped_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => rust_binding_unwrapped_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            rust_node_text(expression, source).trim(),
            before_byte,
        ),
        "field_expression" => {
            let receiver = expression.child_by_field_name("value")?;
            let field = expression.child_by_field_name("field")?;
            let owner = rust_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                before_byte,
            )?;
            let member = rust_node_text(field, source).trim();
            rust_field_type_fqn(analyzer, support, file, source, &owner, member, true)
        }
        "call_expression" => {
            let function = expression.child_by_field_name("function")?;
            if function.kind() == "field_expression"
                && let Some(method) = function.child_by_field_name("field")
                && let Some(receiver) = function.child_by_field_name("value")
            {
                let method_name = rust_node_text(method, source).trim();
                if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
                    return rust_unwrapped_expression_type_fqn(
                        analyzer,
                        support,
                        file,
                        source,
                        root,
                        receiver,
                        expression.start_byte(),
                    );
                }
                let owner = rust_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    receiver,
                    expression.start_byte(),
                )?;
                return rust_callable_return_type_fqn(
                    analyzer,
                    support,
                    file,
                    support.fqn(&format!("{owner}.{method_name}")),
                    true,
                );
            }
            let name = rust_callable_name(function, source)?;
            rust_callable_return_type_fqn(
                analyzer,
                support,
                file,
                rust_named_candidates(support, file, &name),
                true,
            )
        }
        "try_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_unwrapped_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                )
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_unwrapped_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                )
            })
        }
        "struct_expression" => None,
        _ => None,
    }
}

fn rust_binding_unwrapped_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let mut found = None;
    let ctx = RustBindingLookupCtx {
        analyzer,
        support,
        file,
        source,
        root,
        name,
        before_byte,
    };
    rust_collect_binding_unwrapped_type_fqn(ctx, root, &mut found);
    found
}

fn rust_collect_binding_unwrapped_type_fqn(
    ctx: RustBindingLookupCtx<'_, '_>,
    node: Node<'_>,
    found: &mut Option<String>,
) {
    if node.start_byte() >= ctx.before_byte {
        return;
    }
    match node.kind() {
        "parameter" => {
            if let Some((binding, type_node)) = rust_typed_binding(node, ctx.source)
                && binding == ctx.name
                && let Some(inner) = rust_unwrap_container_type_node(type_node, ctx.source)
                && let Some(fqn) = rust_resolve_type_node_fqn(
                    ctx.analyzer,
                    ctx.support,
                    ctx.file,
                    ctx.source,
                    inner,
                    Some(inner.start_byte()),
                )
            {
                *found = Some(fqn);
            }
        }
        "let_declaration" => {
            if let Some(binding) = node
                .child_by_field_name("pattern")
                .and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                && binding == ctx.name
            {
                if let Some(type_node) = node.child_by_field_name("type")
                    && let Some(inner) = rust_unwrap_container_type_node(type_node, ctx.source)
                    && let Some(fqn) = rust_resolve_type_node_fqn(
                        ctx.analyzer,
                        ctx.support,
                        ctx.file,
                        ctx.source,
                        inner,
                        Some(inner.start_byte()),
                    )
                {
                    *found = Some(fqn);
                } else if let Some(value) = node.child_by_field_name("value")
                    && let Some(fqn) = rust_unwrapped_expression_type_fqn(
                        ctx.analyzer,
                        ctx.support,
                        ctx.file,
                        ctx.source,
                        ctx.root,
                        value,
                        value.start_byte(),
                    )
                {
                    *found = Some(fqn);
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= ctx.before_byte {
            break;
        }
        if rust_scope_boundary_excludes_reference(child, ctx.before_byte) {
            continue;
        }
        rust_collect_binding_unwrapped_type_fqn(ctx, child, found);
    }
}

fn rust_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    _source: &str,
    owner_fqn: &str,
    member: &str,
    unwrap_container: bool,
) -> Option<String> {
    let field = support
        .fqn(&format!("{owner_fqn}.{member}"))
        .into_iter()
        .next()?;
    rust_field_code_unit_type_fqn(analyzer, support, file, &field, unwrap_container)
}

fn rust_callable_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    candidates: Vec<CodeUnit>,
    unwrap_container: bool,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        rust_function_code_unit_return_type_fqn(
            analyzer,
            support,
            file,
            &candidate,
            unwrap_container,
        )
    })
}

fn rust_field_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    field: &CodeUnit,
    unwrap_container: bool,
) -> Option<String> {
    rust_code_unit_type_fqn(analyzer, support, file, field, "type", unwrap_container)
}

fn rust_function_code_unit_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    function: &CodeUnit,
    unwrap_container: bool,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        support,
        file,
        function,
        "return_type",
        unwrap_container,
    )
}

fn rust_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    _file: &ProjectFile,
    code_unit: &CodeUnit,
    field_name: &str,
    unwrap_container: bool,
) -> Option<String> {
    let source = code_unit.source().read_to_string().ok()?;
    let tree = lexical_scope::parse_rust_tree(&source)?;
    let declaration = rust_code_unit_declaration_node(analyzer, code_unit, tree.root_node())?;
    let type_node = declaration.child_by_field_name(field_name)?;
    let target_node = if unwrap_container {
        rust_unwrap_container_type_node(type_node, &source)?
    } else {
        type_node
    };
    rust_resolve_type_node_fqn(
        analyzer,
        support,
        code_unit.source(),
        &source,
        target_node,
        Some(target_node.start_byte()),
    )
}

fn rust_code_unit_declaration_node<'tree>(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    root: Node<'tree>,
) -> Option<Node<'tree>> {
    analyzer
        .ranges(code_unit)
        .iter()
        .filter_map(|range| root.descendant_for_byte_range(range.start_byte, range.end_byte))
        .find(|node| node.child_by_field_name("name").is_some())
}

fn rust_resolve_type_node_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    let type_ref = rust_type_ref(type_node, source)?;
    let name = type_ref.name.as_str();
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) {
        let refs = rust.reference_context_of(file);
        if let Some(path) = type_ref.path.as_deref()
            && let Some(resolved) = refs.resolve_scoped(path, name)
            && support
                .fqn(&resolved)
                .into_iter()
                .any(|unit| unit.is_class())
        {
            return Some(resolved);
        }
        if let Some(reference_byte) = reference_byte {
            if let Some(local) =
                rust_local_type_fqn_visible_at(analyzer, support, file, name, reference_byte)
            {
                return Some(local);
            }
        } else if let Some(resolved) = refs.resolve_bare(name)
            && support
                .fqn(resolved)
                .into_iter()
                .any(|unit| unit.is_class())
            && rust_type_fqn_visible_from_file(file, resolved)
        {
            return Some(resolved.to_string());
        }
        if let Some(imported) = rust_import_type_fqn(rust, support, file, name, reference_byte) {
            return Some(imported);
        }
    }
    support
        .fqn(name)
        .into_iter()
        .find(|unit| unit.is_class())
        .map(|unit| unit.fq_name().to_string())
}

#[derive(Debug)]
struct RustTypeRef {
    path: Option<String>,
    name: String,
}

fn rust_type_ref(type_node: Node<'_>, source: &str) -> Option<RustTypeRef> {
    let node = rust_named_type_node(type_node)?;
    match node.kind() {
        "type_identifier" | "identifier" | "self" | "super" | "crate" => {
            let name = rust_node_text(node, source).trim();
            (!name.is_empty()).then(|| RustTypeRef {
                path: None,
                name: name.to_string(),
            })
        }
        "scoped_type_identifier" => {
            let name = node.child_by_field_name("name")?;
            let name = rust_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            Some(RustTypeRef {
                path: node
                    .child_by_field_name("path")
                    .and_then(|path| rust_type_path_text(path, source)),
                name: name.to_string(),
            })
        }
        "generic_type" => {
            let base = node.child_by_field_name("type")?;
            rust_type_ref(base, source)
        }
        "qualified_type" => {
            let inner = node.child_by_field_name("type")?;
            rust_type_ref(inner, source)
        }
        _ => None,
    }
}

fn rust_named_type_node(type_node: Node<'_>) -> Option<Node<'_>> {
    match type_node.kind() {
        "reference_type" | "pointer_type" | "array_type" | "bracketed_type" => type_node
            .child_by_field_name("type")
            .and_then(rust_named_type_node),
        "generic_type" | "qualified_type" => Some(type_node),
        "scoped_type_identifier"
        | "type_identifier"
        | "identifier"
        | "self"
        | "super"
        | "crate" => Some(type_node),
        _ => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(rust_named_type_node)
        }
    }
}

fn rust_type_path_text(path: Node<'_>, source: &str) -> Option<String> {
    match path.kind() {
        "generic_type" => path
            .child_by_field_name("type")
            .and_then(|base| rust_type_path_text(base, source)),
        "scoped_type_identifier"
        | "scoped_identifier"
        | "identifier"
        | "self"
        | "super"
        | "crate" => {
            let text = rust_node_text(path, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => {
            let text = rust_node_text(path, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
    }
}

fn rust_unwrap_container_type_node<'tree>(
    type_node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let node = rust_named_type_node(type_node)?;
    let type_ref = rust_type_ref(node, source)?;
    let is_container = matches!(
        (type_ref.path.as_deref(), type_ref.name.as_str()),
        (None, "Result")
            | (Some("std::result"), "Result")
            | (Some("anyhow"), "Result")
            | (None, "Option")
            | (Some("std::option"), "Option")
    );
    if !is_container {
        return None;
    }
    let type_arguments = node.child_by_field_name("type_arguments")?;
    let mut cursor = type_arguments.walk();
    type_arguments
        .named_children(&mut cursor)
        .find_map(rust_named_type_node)
}

fn rust_import_type_fqn(
    rust: &RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
    reference_byte: Option<usize>,
) -> Option<String> {
    let mut candidates: Vec<_> =
        rust_imported_export_candidates(rust, support, file, name, reference_byte)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

fn rust_type_fqn_visible_from_file(file: &ProjectFile, fqn: &str) -> bool {
    rust_fqn_package(fqn) == rust_local_package_name(file)
}

fn rust_local_type_fqn_visible_at(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
    reference_byte: usize,
) -> Option<String> {
    let source = file.read_to_string().ok()?;
    let tree = lexical_scope::parse_rust_tree(&source)?;
    let reference_mod =
        lexical_scope::enclosing_mod_item_range_at(tree.root_node(), reference_byte);
    let mut candidates: Vec<_> = support
        .file_identifier(file, name)
        .into_iter()
        .filter(|unit| unit.is_class())
        .filter(|unit| {
            analyzer.ranges(unit).iter().any(|range| {
                rust_definition_scope_visible_at(tree.root_node(), range.start_byte, reference_byte)
                    && lexical_scope::enclosing_mod_item_range_at(
                        tree.root_node(),
                        range.start_byte,
                    ) == reference_mod
            })
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

fn rust_definition_scope_visible_at(
    root: Node<'_>,
    definition_byte: usize,
    reference_byte: usize,
) -> bool {
    let Some(definition_node) =
        smallest_named_node_covering(root, definition_byte, definition_byte)
    else {
        return false;
    };
    lexical_scope::enclosing_visibility_scope_range(definition_node)
        .is_none_or(|(start, end)| start <= reference_byte && reference_byte < end)
}

fn rust_fqn_package(fqn: &str) -> &str {
    fqn.rsplit_once('.')
        .map(|(package, _)| package)
        .unwrap_or("")
}

fn rust_local_package_name(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();

    if components.first().map(|component| component.as_str()) == Some("src") {
        components.remove(0);
    }
    if components.is_empty() {
        return String::new();
    }

    let file_name = components.pop().unwrap_or_default();
    let stem = std::path::Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if stem == "lib" || stem == "main" || stem == "mod" {
        components.join(".")
    } else if rel.starts_with("src") {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        components.join(".")
    }
}

fn rust_enclosing_impl_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<String> {
    let mut current = node.parent()?;
    loop {
        if current.kind() == "impl_item"
            && let Some(type_node) = current.child_by_field_name("type")
        {
            return rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                type_node,
                Some(type_node.start_byte()),
            );
        }
        current = current.parent()?;
    }
}

fn rust_named_candidates(
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = support.file_identifier(file, name);
    candidates.extend(support.fqn(name));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_callable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        "scoped_identifier" => node
            .child_by_field_name("name")
            .map(|name| rust_node_text(name, source).trim().to_string()),
        _ => None,
    }
}

fn rust_simple_identifier_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        _ => None,
    }
}

fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
}

fn rust_imported_export_candidates(
    rust: &crate::analyzer::RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
    reference_byte: Option<usize>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    let targets = if let Some(reference_byte) = reference_byte
        && let Ok(source) = file.read_to_string()
    {
        if lexical_scope::name_shadowed_at(&source, reference, reference_byte) {
            Vec::new()
        } else {
            let binder = lexical_scope::visible_import_binder_at(&source, reference_byte);
            rust.resolve_imported_export_from_binder(file, &binder, reference)
        }
    } else {
        rust.resolve_imported_export(file, reference)
    };
    for (target_file, target_name) in targets {
        candidates.extend(support.file_identifier(&target_file, &target_name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_reference_looks_external(reference: &str) -> bool {
    reference
        .split("::")
        .next()
        .is_some_and(|root| !matches!(root, "crate" | "self" | "super") && root != reference)
}

pub(super) fn parse_rust_tree(source: &str) -> Option<Tree> {
    lexical_scope::parse_rust_tree(source)
}
