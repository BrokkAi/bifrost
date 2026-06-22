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
        owner = rust_field_type_fqn(analyzer, support, file, source, &owner, member)?;
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
            rust_field_type_fqn(analyzer, support, file, source, &owner, member)
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

fn rust_binding_type_text(
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
    rust_collect_binding_type_text(ctx, root, &mut found);
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

fn rust_collect_binding_type_text(
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
            {
                *found = Some(rust_node_text(type_node, ctx.source).trim().to_string());
            }
        }
        "let_declaration" => {
            if let Some(binding) = node
                .child_by_field_name("pattern")
                .and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                && binding == ctx.name
            {
                if let Some(type_node) = node.child_by_field_name("type") {
                    *found = Some(rust_node_text(type_node, ctx.source).trim().to_string());
                } else if let Some(value) = node.child_by_field_name("value")
                    && let Some(type_text) = rust_value_type_text(
                        ctx.analyzer,
                        ctx.support,
                        ctx.file,
                        ctx.source,
                        ctx.root,
                        value,
                    )
                {
                    *found = Some(type_text);
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
        rust_collect_binding_type_text(ctx, child, found);
    }
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
                    rust_node_text(type_node, ctx.source),
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
                        rust_node_text(type_node, ctx.source),
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
    let type_text = rust_value_type_text(analyzer, support, file, source, root, value)?;
    rust_resolve_type_node_fqn(
        analyzer,
        support,
        file,
        &type_text,
        Some(value.start_byte()),
    )
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
    let type_text = rust_expression_type_text(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
    )?;
    let inner = rust_unwrap_container_type(&type_text)?;
    rust_resolve_type_node_fqn(
        analyzer,
        support,
        file,
        inner,
        Some(expression.start_byte()),
    )
}

fn rust_expression_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => rust_binding_type_text(
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
            rust_field_type_text(analyzer, support, &owner, member)
        }
        "call_expression" => {
            rust_value_type_text(analyzer, support, file, source, root, expression)
        }
        "try_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                let type_text = rust_expression_type_text(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                )?;
                rust_unwrap_container_type(&type_text).map(str::to_string)
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_text(analyzer, support, file, source, root, child, before_byte)
            })
        }
        "struct_expression" => expression
            .child_by_field_name("name")
            .map(|name| rust_node_text(name, source).trim().to_string()),
        _ => rust_call_text_name(rust_node_text(expression, source)).and_then(|name| {
            rust_callable_return_type(analyzer, support.file_identifier(file, name))
        }),
    }
}

fn rust_value_type_text(
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
                let type_text = rust_value_type_text(analyzer, support, file, source, root, child)?;
                rust_unwrap_container_type(&type_text).map(str::to_string)
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = value.walk();
            value.named_children(&mut cursor).find_map(|child| {
                rust_value_type_text(analyzer, support, file, source, root, child)
            })
        }
        "call_expression" => {
            let function = value.child_by_field_name("function")?;
            if function.kind() == "field_expression"
                && let Some(method) = function.child_by_field_name("field")
                && let Some(receiver) = function.child_by_field_name("value")
            {
                let method_name = rust_node_text(method, source).trim();
                if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
                    let type_text = rust_expression_type_text(
                        analyzer,
                        support,
                        file,
                        source,
                        root,
                        receiver,
                        value.start_byte(),
                    )?;
                    return rust_unwrap_container_type(&type_text).map(str::to_string);
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
                return rust_callable_return_type(
                    analyzer,
                    support.fqn(&format!("{owner}.{method_name}")),
                );
            }
            let name = rust_callable_name(function, source)?;
            rust_callable_return_type(analyzer, rust_named_candidates(support, file, &name))
        }
        "struct_expression" => value
            .child_by_field_name("name")
            .map(|name| rust_node_text(name, source).trim().to_string()),
        _ => rust_call_text_name(rust_node_text(value, source)).and_then(|name| {
            rust_callable_return_type(analyzer, support.file_identifier(file, name))
        }),
    }
}

fn rust_callable_return_type(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        let signature = analyzer
            .signatures(&candidate)
            .iter()
            .next()
            .cloned()
            .or_else(|| candidate.signature().map(str::to_string))?;
        rust_function_return_type_text(&signature).map(str::to_string)
    })
}

fn rust_function_return_type_text(signature: &str) -> Option<&str> {
    let return_type = signature.split_once("->")?.1.trim();
    let return_type = return_type
        .split('{')
        .next()
        .unwrap_or(return_type)
        .trim()
        .trim_end_matches(';')
        .trim();
    Some(return_type)
}

fn rust_unwrap_container_type(type_text: &str) -> Option<&str> {
    let generic = type_text
        .strip_prefix("Result<")
        .or_else(|| type_text.strip_prefix("std::result::Result<"))
        .or_else(|| type_text.strip_prefix("anyhow::Result<"))
        .or_else(|| type_text.strip_prefix("Option<"))
        .or_else(|| type_text.strip_prefix("std::option::Option<"))?;
    let mut depth = 0usize;
    for (index, ch) in generic.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' if depth == 0 => return Some(generic[..index].trim()),
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some(generic[..index].trim()),
            _ => {}
        }
    }
    None
}

fn rust_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    _source: &str,
    owner_fqn: &str,
    member: &str,
) -> Option<String> {
    let field = support
        .fqn(&format!("{owner_fqn}.{member}"))
        .into_iter()
        .next()?;
    let signature = field
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(&field).iter().next().cloned())?;
    let type_text = signature.split_once(':')?.1.trim();
    rust_resolve_type_node_fqn(analyzer, support, file, type_text, None)
        .or_else(|| rust_resolve_type_node_fqn(analyzer, support, field.source(), type_text, None))
}

fn rust_field_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    member: &str,
) -> Option<String> {
    let field = support
        .fqn(&format!("{owner_fqn}.{member}"))
        .into_iter()
        .next()?;
    let signature = field
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(&field).iter().next().cloned())?;
    signature
        .split_once(':')
        .map(|(_, type_text)| type_text.trim().to_string())
}

fn rust_resolve_type_node_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    type_text: &str,
    reference_byte: Option<usize>,
) -> Option<String> {
    let name = rust_simple_type_name(type_text)?;
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) {
        let refs = rust.reference_context_of(file);
        if let Some((path, scoped_name)) = rust_type_path_and_name(type_text)
            && let Some(resolved) = refs.resolve_scoped(path, scoped_name)
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

fn rust_type_path_and_name(type_text: &str) -> Option<(&str, &str)> {
    let trimmed = type_text
        .trim()
        .trim_start_matches('&')
        .trim_start()
        .trim_start_matches("mut ")
        .trim_start()
        .trim_start_matches('&')
        .trim_start()
        .trim_start_matches("mut ")
        .trim();
    let raw = trimmed
        .split(['<', '>', ',', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    raw.rsplit_once("::")
        .and_then(|(path, name)| (!path.is_empty() && !name.is_empty()).then_some((path, name)))
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
                rust_node_text(type_node, source),
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

fn rust_simple_type_name(type_text: &str) -> Option<&str> {
    let trimmed = type_text
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    let raw = trimmed
        .rsplit("::")
        .next()
        .unwrap_or(trimmed)
        .split(['<', '>', ',', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    (!raw.is_empty()).then_some(raw)
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

fn rust_call_text_name(value: &str) -> Option<&str> {
    let head = value
        .trim()
        .trim_end_matches('?')
        .trim()
        .split_once('(')?
        .0
        .trim();
    let name = head.rsplit("::").next().unwrap_or(head).trim();
    (!name.is_empty()).then_some(name)
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
