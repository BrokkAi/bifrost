use super::*;
use crate::analyzer::RustReferenceContext;
use crate::analyzer::rust::lexical_scope;
use crate::hash::HashMap;

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
    let mut cache = RustTypeLookupCache::default();
    let reference = site.text.as_str();
    if let Some(tree) = tree
        && !reference.contains(['.', ':'])
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )
        && node.kind() == "identifier"
        && (lexical_scope::is_pattern_binding_identifier(node)
            || lexical_scope::name_shadowed_in_tree(
                tree.root_node(),
                source,
                reference,
                site.focus_start_byte,
            ))
    {
        return no_definition(
            "local_binding",
            format!("`{reference}` is a local Rust binding, which is not indexed"),
        );
    }
    if let Some(tree) = tree
        && let Some(outcome) = rust_impl_associated_type_declaration_outcome(
            analyzer, support, file, source, tree, site,
        )
    {
        return outcome;
    }
    if reference.contains('.')
        && let Some(tree) = tree
        && let Some(outcome) =
            resolve_rust_field(analyzer, support, file, source, tree, site, &mut cache)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) =
            rust_self_scoped_associated_type_candidates(analyzer, file, source, tree, site)
        && !candidates.is_empty()
    {
        return candidates_outcome(candidates);
    }
    // `Self` (as a type) denotes the lexically enclosing impl's type — the Rust
    // form of the `LexicalEnclosingType` receiver origin. Name-based resolution
    // (`resolve_bare` / `resolve_scoped`) has no notion of `Self`, so resolve it
    // here where the cursor node is available: bare `Self` / `Self { .. }` goes
    // to the type declaration, and `Self::assoc` to the associated item.
    if let Some(tree) = tree
        && (reference == "Self" || reference.starts_with("Self::"))
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )
        && let Some(self_type) = rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
    {
        let focused_segment = reference_segments(site, "::", 2)
            .and_then(|segments| focus_segment_index(site, &segments));
        let candidates = match reference.split_once("::") {
            Some(_) if focused_segment == Some(0) => support.fqn(&self_type),
            Some((_, name)) => {
                let mut candidates = rust_member_candidates(
                    support.fqn(&format!("{self_type}.{name}")),
                    RustMemberKind::Function,
                );
                if candidates.is_empty() {
                    // The enclosing impl's type may get the associated item from an
                    // implemented trait; the owner fqn is already resolved, so this
                    // enters the shared resolver past its scoped-path step.
                    let refs = rust.reference_context_of(file);
                    candidates =
                        match crate::analyzer::usages::rust_graph::resolve_trait_associated_item(
                            rust, support, &refs, file, &self_type, name,
                        ) {
                            ReceiverAnalysisOutcome::Precise(resolved) => {
                                rust_member_candidates(resolved, RustMemberKind::Function)
                            }
                            ReceiverAnalysisOutcome::Ambiguous(_)
                            | ReceiverAnalysisOutcome::Unknown
                            | ReceiverAnalysisOutcome::Unsupported { .. }
                            | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                        };
                }
                if candidates.is_empty() {
                    let refs = rust.reference_context_of(file);
                    candidates = match crate::analyzer::usages::rust_graph::resolve_trait_associated_item_matching(
                        rust,
                        support,
                        &refs,
                        file,
                        &self_type,
                        name,
                        CodeUnit::is_field,
                    ) {
                        ReceiverAnalysisOutcome::Precise(resolved) => {
                            rust_member_candidates(resolved, RustMemberKind::Field)
                        }
                        ReceiverAnalysisOutcome::Ambiguous(_)
                        | ReceiverAnalysisOutcome::Unknown
                        | ReceiverAnalysisOutcome::Unsupported { .. }
                        | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                    };
                }
                candidates
            }
            None => support.fqn(&self_type),
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    let refs = rust.reference_context_of(file);
    if let Some(tree) = tree
        && let Some(candidates) =
            rust_use_path_module_candidates(rust, support, file, source, tree, site, &refs)
        && !candidates.is_empty()
    {
        return candidates_outcome(candidates);
    }
    let (candidates, scoped_lookup_failed) = if let Some((path, name)) = reference.rsplit_once("::")
    {
        let resolved = rust_focused_scoped_segment_candidates(rust, support, file, site)
            .unwrap_or_else(|| {
                match crate::analyzer::usages::rust_graph::resolve_scoped_associated_item(
                    rust, support, &refs, file, path, name,
                ) {
                    ReceiverAnalysisOutcome::Precise(candidates) => candidates,
                    ReceiverAnalysisOutcome::Ambiguous(_)
                    | ReceiverAnalysisOutcome::Unknown
                    | ReceiverAnalysisOutcome::Unsupported { .. }
                    | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                }
            });
        (resolved, true)
    } else {
        // Prefer a type declared in the lexically enclosing scope (module) over the
        // flat same-file name map, so a bare `Config` inside `mod b` resolves to
        // `b::Config` rather than a same-named sibling module's `Config` (#431). The
        // `is_class` filter keeps this to type references — a bare function call is
        // left to the name map below, so free-function resolution is unchanged.
        if let Some(unit) = resolve_in_enclosing_scopes(
            analyzer,
            file,
            reference,
            site.focus_start_byte,
            CodeUnit::is_class,
        ) {
            return candidates_outcome(vec![unit]);
        }
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

fn rust_impl_associated_type_declaration_outcome(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let type_item =
        rust_enclosing_named_associated_type(node, site.focus_start_byte, site.focus_end_byte)?;
    let name = type_item.child_by_field_name("name")?;
    let associated_type = rust_node_text(name, source).trim();
    if associated_type.is_empty() {
        return None;
    }
    let impl_item = rust_enclosing_ancestor(type_item, "impl_item")?;
    let trait_type = impl_item.child_by_field_name("trait")?;
    let trait_fqn = rust_resolve_type_node_fqn(
        analyzer,
        support,
        file,
        source,
        trait_type,
        Some(trait_type.start_byte()),
    )?;
    let mut candidates: Vec<_> = support
        .fqn(&format!("{trait_fqn}.{associated_type}"))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates_outcome(candidates))
}

fn rust_enclosing_named_associated_type(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(candidate.kind(), "associated_type" | "type_item")
            && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn rust_self_scoped_associated_type_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped = rust_enclosing_scoped_type_identifier_name(
        node,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let path = scoped.child_by_field_name("path")?;
    if rust_node_text(path, source).trim() != "Self" {
        return None;
    }
    let name = scoped.child_by_field_name("name")?;
    let name = rust_node_text(name, source).trim();
    let associated_type = resolve_in_enclosing_scopes(
        analyzer,
        file,
        name,
        site.focus_start_byte,
        CodeUnit::is_field,
    )?;
    Some(vec![associated_type])
}

fn rust_enclosing_scoped_type_identifier_name(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "scoped_type_identifier"
            && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn rust_enclosing_ancestor<'tree>(mut node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn rust_use_path_module_candidates(
    rust: &RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
) -> Option<Vec<CodeUnit>> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if !matches!(node.kind(), "identifier" | "self" | "super" | "crate") {
        return None;
    }
    let path = rust_enclosing_scoped_use_path(node)?;
    if !(path.start_byte() <= site.focus_start_byte && site.focus_start_byte < path.end_byte()) {
        return None;
    }
    let path_text = rust_node_text(path, source).trim();
    if path_text.is_empty() {
        return None;
    }
    let fqn = rust_module_path_fqn(rust, file, refs, path_text)?;
    let candidates: Vec<_> = support
        .fqn(&fqn)
        .into_iter()
        .filter(CodeUnit::is_module)
        .collect();
    (!candidates.is_empty()).then_some(candidates)
}

fn rust_enclosing_scoped_use_path(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = node.parent()?;
        match parent.kind() {
            "use_declaration" | "use_list" => return None,
            "scoped_use_list" => {
                let path = parent.child_by_field_name("path")?;
                return node_within(path, node).then_some(path);
            }
            _ => node = parent,
        }
    }
}

fn node_within(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

fn rust_module_path_fqn(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    refs: &RustReferenceContext,
    path: &str,
) -> Option<String> {
    if let Some((module_path, name)) = path.rsplit_once("::")
        && let Some(fqn) = refs.resolve_scoped(module_path, name)
    {
        return Some(fqn);
    }
    refs.resolve_bare(path)
        .map(str::to_string)
        .or_else(|| rust.resolve_module_package(file, path))
}

fn rust_focused_scoped_segment_candidates(
    rust: &RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let segments = reference_segments(site, "::", 2)?;
    let focus_index = focus_segment_index(site, &segments)?;
    if focus_index + 1 == segments.len() {
        return None;
    }
    let refs = rust.reference_context_of(file);
    let resolved = if focus_index == 0 {
        let (reference, _, _) = &segments[0];
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
                Some(site.focus_start_byte),
            );
            resolved = if imported.is_empty() {
                support.file_identifier(file, reference)
            } else {
                imported
            };
        }
        resolved
    } else {
        let path = segments[..focus_index]
            .iter()
            .map(|(segment, _, _)| segment.as_str())
            .collect::<Vec<_>>()
            .join("::");
        let (name, _, _) = &segments[focus_index];
        refs.resolve_scoped(&path, name)
            .map(|fqn| support.fqn(&fqn))
            .unwrap_or_default()
    };
    (!resolved.is_empty()).then_some(resolved)
}

fn resolve_rust_field(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    if let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
        && let Some(field_expression) = rust_enclosing_field_expression(node)
    {
        let field = field_expression.child_by_field_name("field")?;
        let receiver = field_expression.child_by_field_name("value")?;
        if receiver.start_byte() <= site.focus_start_byte
            && site.focus_end_byte <= receiver.end_byte()
        {
            if rust_node_text(receiver, source).trim() == "self"
                && let Some(owner) =
                    rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
            {
                let candidates = support.fqn(&owner);
                if !candidates.is_empty() {
                    return Some(candidates_outcome(candidates));
                }
            }
            return Some(no_definition(
                "local_receiver",
                "the focused Rust receiver is a local expression, which is not indexed",
            ));
        }
        if !(field.start_byte() <= site.focus_start_byte && site.focus_end_byte <= field.end_byte())
        {
            return None;
        }
        let member = rust_node_text(field, source).trim();
        let owner = rust_expression_type_fqn(
            analyzer,
            support,
            file,
            source,
            tree.root_node(),
            receiver,
            field_expression.start_byte(),
            cache,
        )?;
        let candidates = rust_member_candidates(
            support.fqn(&format!("{owner}.{member}")),
            rust_field_expression_member_kind(field_expression),
        );
        if candidates.is_empty()
            && rust_field_expression_member_kind(field_expression) == RustMemberKind::Function
            && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        {
            let refs = rust.reference_context_of(file);
            let trait_candidates =
                match crate::analyzer::usages::rust_graph::resolve_trait_associated_item(
                    rust, support, &refs, file, &owner, member,
                ) {
                    ReceiverAnalysisOutcome::Precise(resolved) => {
                        rust_member_candidates(resolved, RustMemberKind::Function)
                    }
                    ReceiverAnalysisOutcome::Ambiguous(_)
                    | ReceiverAnalysisOutcome::Unknown
                    | ReceiverAnalysisOutcome::Unsupported { .. }
                    | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                };
            if !trait_candidates.is_empty() {
                return Some(candidates_outcome(trait_candidates));
            }
        }
        return if candidates.is_empty() {
            Some(no_definition(
                "no_indexed_definition",
                format!("`{owner}.{member}` is not indexed as a Rust definition"),
            ))
        } else {
            Some(candidates_outcome(candidates))
        };
    }
    rust_resolve_dotted_reference_text(analyzer, support, file, source, tree, site, cache)
}

fn rust_resolve_dotted_reference_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    let segments = reference_segments(site, ".", 1)?;
    if segments.len() < 2 {
        return None;
    }
    let focus_index = focus_segment_index(site, &segments)?;
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
            RustTypeMode::Direct,
            cache,
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
        owner = rust_field_type_fqn(
            analyzer,
            support,
            file,
            source,
            &owner,
            member,
            RustTypeMode::Direct,
            cache,
        )?;
    }
    None
}

fn reference_segments(
    site: &ResolvedReferenceSite,
    delimiter: &str,
    delimiter_width: usize,
) -> Option<Vec<(String, usize, usize)>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for part in site.text.split(delimiter) {
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
        offset = end + delimiter_width;
    }
    Some(segments)
}

fn focus_segment_index(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustMemberKind {
    Field,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustTypeMode {
    Direct,
    UnwrapContainer,
}

#[derive(Default)]
pub(crate) struct RustTypeLookupCache {
    declarations: HashMap<ProjectFile, Option<RustParsedDeclarationSource>>,
}

struct RustParsedDeclarationSource {
    source: String,
    tree: Tree,
}

impl RustTypeLookupCache {
    fn parsed(&mut self, file: &ProjectFile) -> Option<&RustParsedDeclarationSource> {
        self.declarations
            .entry(file.clone())
            .or_insert_with(|| {
                let source = file.read_to_string().ok()?;
                let tree = lexical_scope::parse_rust_tree(&source)?;
                Some(RustParsedDeclarationSource { source, tree })
            })
            .as_ref()
    }
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

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_expression_type_fqn_mode(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        RustTypeMode::Direct,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_expression_type_definition_fqn_cached(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn_mode(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    match expression.kind() {
        "self" if mode == RustTypeMode::Direct => {
            rust_enclosing_impl_type_fqn(analyzer, support, file, source, expression)
        }
        "identifier" => rust_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            rust_node_text(expression, source).trim(),
            before_byte,
            mode,
            cache,
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
                cache,
            )?;
            let member = rust_node_text(field, source).trim();
            rust_field_type_fqn(analyzer, support, file, source, &owner, member, mode, cache)
        }
        "call_expression" => rust_call_expression_type_fqn(
            analyzer, support, file, source, root, expression, mode, cache,
        ),
        "try_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn_mode(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                    RustTypeMode::UnwrapContainer,
                    cache,
                )
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn_mode(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                    mode,
                    cache,
                )
            })
        }
        "struct_expression" if mode == RustTypeMode::Direct => {
            let name = expression.child_by_field_name("name")?;
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

#[allow(clippy::too_many_arguments)]
fn rust_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let mut found = None;
    let mut ctx = RustBindingLookupCtx {
        analyzer,
        support,
        file,
        source,
        root,
        name,
        before_byte,
        mode,
        cache,
    };
    rust_collect_binding_type_fqn(&mut ctx, root, &mut found);
    found
}

struct RustBindingLookupCtx<'a, 'tree, 'cache> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    name: &'a str,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &'cache mut RustTypeLookupCache,
}

fn rust_collect_binding_type_fqn(
    ctx: &mut RustBindingLookupCtx<'_, '_, '_>,
    root: Node<'_>,
    found: &mut Option<String>,
) {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.start_byte() >= ctx.before_byte {
            continue;
        }
        match node.kind() {
            "parameter" => {
                if let Some((binding, type_node)) = rust_typed_binding(node, ctx.source)
                    && binding == ctx.name
                    && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                        ctx,
                        type_node,
                        Some(type_node.start_byte()),
                    )
                {
                    *found = Some(fqn);
                }
            }
            "let_declaration" if node.end_byte() <= ctx.before_byte => {
                if let Some(binding) = node
                    .child_by_field_name("pattern")
                    .and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                    && binding == ctx.name
                {
                    if let Some(type_node) = node.child_by_field_name("type")
                        && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                            ctx,
                            type_node,
                            Some(type_node.start_byte()),
                        )
                    {
                        *found = Some(fqn);
                    } else if let Some(value) = node.child_by_field_name("value")
                        && let Some(fqn) = rust_expression_type_fqn_mode(
                            ctx.analyzer,
                            ctx.support,
                            ctx.file,
                            ctx.source,
                            ctx.root,
                            value,
                            value.start_byte(),
                            ctx.mode,
                            ctx.cache,
                        )
                    {
                        *found = Some(fqn);
                    }
                }
            }
            _ => {}
        }

        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            if child.start_byte() < ctx.before_byte
                && !rust_scope_boundary_excludes_reference(child, ctx.before_byte)
            {
                pending.push(child);
            }
        }
    }
}

fn rust_resolve_type_node_fqn_mode(
    ctx: &mut RustBindingLookupCtx<'_, '_, '_>,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    let target_node = match ctx.mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => rust_unwrap_container_type_node(type_node, ctx.source)?,
    };
    rust_resolve_type_node_fqn(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.source,
        target_node,
        reference_byte,
    )
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

#[allow(clippy::too_many_arguments)]
fn rust_call_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    if function.kind() == "field_expression"
        && let Some(method) = function.child_by_field_name("field")
        && let Some(receiver) = function.child_by_field_name("value")
    {
        let method_name = rust_node_text(method, source).trim();
        if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
            return rust_expression_type_fqn_mode(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                call.start_byte(),
                RustTypeMode::UnwrapContainer,
                cache,
            );
        }
        let owner = rust_expression_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            receiver,
            call.start_byte(),
            cache,
        )?;
        return rust_callable_return_type_fqn(
            analyzer,
            support,
            file,
            support.fqn(&format!("{owner}.{method_name}")),
            mode,
            cache,
        );
    }
    let name = rust_callable_name(function, source)?;
    rust_callable_return_type_fqn(
        analyzer,
        support,
        file,
        rust_callable_candidates(analyzer, support, file, &name, function.start_byte()),
        mode,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    _source: &str,
    owner_fqn: &str,
    member: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let field = support
        .fqn(&format!("{owner_fqn}.{member}"))
        .into_iter()
        .next()?;
    rust_field_code_unit_type_fqn(analyzer, support, file, &field, mode, cache)
}

fn rust_callable_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    candidates: Vec<CodeUnit>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        rust_function_code_unit_return_type_fqn(analyzer, support, file, &candidate, mode, cache)
    })
}

fn rust_field_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    field: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(analyzer, support, file, field, "type", mode, cache)
}

fn rust_function_code_unit_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    function: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        support,
        file,
        function,
        "return_type",
        mode,
        cache,
    )
}

fn rust_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    _file: &ProjectFile,
    code_unit: &CodeUnit,
    field_name: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let parsed = cache.parsed(code_unit.source())?;
    let declaration =
        rust_code_unit_declaration_node(analyzer, code_unit, parsed.tree.root_node())?;
    let type_node = declaration.child_by_field_name(field_name)?;
    let target_node = match mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => {
            rust_unwrap_container_type_node(type_node, &parsed.source)?
        }
    };
    rust_resolve_type_node_fqn(
        analyzer,
        support,
        code_unit.source(),
        &parsed.source,
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

pub(crate) fn rust_resolve_type_node_fqn(
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
                .any(|unit| rust_is_type_definition(analyzer, &unit))
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
                .any(|unit| rust_is_type_definition(analyzer, &unit))
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
        .find(|unit| rust_is_type_definition(analyzer, unit))
        .map(|unit| unit.fq_name().to_string())
}

pub(crate) fn rust_is_type_definition(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        || analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(unit))
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
        .next()
        .and_then(rust_named_type_node)
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

fn rust_callable_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let mut candidates = rust_named_candidates(support, file, name);
    if candidates.is_empty()
        && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
    {
        candidates =
            rust_imported_export_candidates(rust, support, file, name, Some(reference_byte));
    }
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
            let targets = rust.resolve_imported_export_from_binder(file, &binder, reference);
            if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
                return Vec::new();
            }
            targets
        }
    } else {
        let binder = rust.import_binder_of(file);
        let targets = rust.resolve_imported_export(file, reference);
        if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
            return Vec::new();
        }
        targets
    };
    for (target_file, target_name) in targets {
        candidates.extend(support.file_identifier(&target_file, &target_name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_binder_has_external_binding(binder: &ImportBinder, reference: &str) -> bool {
    binder
        .bindings
        .iter()
        .any(|(local_name, binding)| match binding.kind {
            ImportKind::Named | ImportKind::Namespace if local_name == reference => true,
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => false,
            ImportKind::Named | ImportKind::Namespace => false,
        })
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
