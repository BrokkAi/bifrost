use crate::analyzer::js_ts::AliasResolver;
use crate::analyzer::js_ts::model::node_text;
use crate::analyzer::usages::{ImportKind, js_ts_graph::JsTsUsageIndex};
use crate::analyzer::{
    CodeUnit, DirectDescendantIndex, IAnalyzer, Language, ProjectFile, TypeHierarchyProvider,
    resolve_js_ts_module_specifier,
};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub(crate) fn extract_js_supertypes(declaration: Node<'_>, source: &str) -> Vec<String> {
    if let Some(superclass) = declaration.child_by_field_name("superclass")
        && let Some(text) = type_reference_text(superclass, source)
    {
        return vec![text];
    }

    let name_id = declaration
        .child_by_field_name("name")
        .map(|name| name.id());
    let mut saw_name = name_id.is_none();
    let mut cursor = declaration.walk();
    for child in declaration.named_children(&mut cursor) {
        if Some(child.id()) == name_id {
            saw_name = true;
            continue;
        }
        if child.kind() == "class_body" {
            break;
        }
        if saw_name && let Some(text) = type_reference_text(child, source) {
            return vec![text];
        }
    }
    Vec::new()
}

pub(crate) fn extract_ts_supertypes(declaration: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();
    let mut seen = HashSet::default();
    collect_ts_heritage_types(declaration, source, &mut raw, &mut seen);
    raw
}

fn collect_ts_heritage_types(
    node: Node<'_>,
    source: &str,
    raw: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if node.kind() == "class_body" || node.kind() == "object_type" {
        return;
    }
    if matches!(
        node.kind(),
        "class_heritage" | "extends_type_clause" | "implements_clause"
    ) {
        collect_heritage_clause_types(node, source, raw, seen);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ts_heritage_types(child, source, raw, seen);
    }
}

pub(crate) fn resolve_direct_ancestors(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    code_unit: &CodeUnit,
    raw_supertypes: &[String],
) -> Vec<CodeUnit> {
    if !code_unit.is_class() {
        return Vec::new();
    }

    let mut ancestors = Vec::new();
    let mut seen = HashSet::default();
    for raw in raw_supertypes {
        let Some(ancestor) = resolve_unique_type(
            analyzer,
            index,
            language,
            alias_resolver,
            code_unit.source(),
            raw,
        ) else {
            continue;
        };
        if seen.insert(ancestor.clone()) {
            ancestors.push(ancestor);
        }
    }
    ancestors
}

pub(crate) fn build_direct_descendant_index_by_unit<A, P>(
    analyzer: &A,
    provider: &P,
) -> DirectDescendantIndex
where
    A: IAnalyzer,
    P: TypeHierarchyProvider + ?Sized,
{
    let mut nodes = analyzer
        .all_declarations()
        .filter(|candidate| candidate.is_class())
        .collect::<Vec<_>>();
    nodes.sort();
    let mut index_by_node: HashMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            (
                node.clone(),
                u32::try_from(index).expect("hierarchy index declarations must fit in a u32"),
            )
        })
        .collect();
    let candidates = nodes.clone();
    let mut edges = Vec::new();
    for candidate in candidates {
        let descendant = index_by_node[&candidate];
        for ancestor in provider.get_direct_ancestors(&candidate) {
            let ancestor = *index_by_node.entry(ancestor.clone()).or_insert_with(|| {
                let index = u32::try_from(nodes.len())
                    .expect("hierarchy index declarations must fit in a u32");
                nodes.push(ancestor);
                index
            });
            edges.push((ancestor, descendant));
        }
    }
    DirectDescendantIndex::from_indexed_nodes(nodes, index_by_node, edges)
}

fn collect_heritage_clause_types(
    clause: Node<'_>,
    source: &str,
    raw: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if let Some(text) = type_reference_text(child, source)
            && seen.insert(text.clone())
        {
            raw.push(text);
        }
    }
}

fn type_reference_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier"
        | "type_identifier"
        | "property_identifier"
        | "member_expression"
        | "nested_type_identifier" => non_empty_node_text(node, source),
        "generic_type" => {
            first_named_child(node).and_then(|child| type_reference_text(child, source))
        }
        "type_query" => node
            .child_by_field_name("name")
            .and_then(|name| type_reference_text(name, source)),
        _ => {
            if node.named_child_count() == 1 {
                first_named_child(node).and_then(|child| type_reference_text(child, source))
            } else {
                None
            }
        }
    }
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn non_empty_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source).trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn resolve_unique_type(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    source_file: &ProjectFile,
    raw: &str,
) -> Option<CodeUnit> {
    let mut candidates = Vec::new();
    candidates.extend(type_declarations_in_file(analyzer, source_file, raw));
    candidates.extend(resolve_imported_type(
        analyzer,
        index,
        language,
        alias_resolver,
        source_file,
        raw,
    ));
    dedupe_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.pop().expect("one candidate"))
}

fn resolve_imported_type(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    source_file: &ProjectFile,
    raw: &str,
) -> Vec<CodeUnit> {
    let Some((local_name, namespace_export)) = raw.split_once('.') else {
        return resolve_local_import_binding(
            analyzer,
            index,
            language,
            alias_resolver,
            source_file,
            raw,
        );
    };

    let Some(binding) = index.import_binding(source_file, local_name) else {
        return Vec::new();
    };
    if binding.kind != ImportKind::Namespace {
        return Vec::new();
    }
    let module_files = resolve_js_ts_module_specifier(
        source_file,
        &binding.module_specifier,
        language,
        Some(alias_resolver),
    );
    exported_type_declarations(analyzer, index, &module_files, namespace_export)
}

fn resolve_local_import_binding(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    source_file: &ProjectFile,
    local_name: &str,
) -> Vec<CodeUnit> {
    let Some(binding) = index.import_binding(source_file, local_name) else {
        return Vec::new();
    };
    let module_files = resolve_js_ts_module_specifier(
        source_file,
        &binding.module_specifier,
        language,
        Some(alias_resolver),
    );
    let exported_name = match binding.kind {
        ImportKind::Default => "default",
        ImportKind::Named => binding.imported_name.as_deref().unwrap_or(local_name),
        ImportKind::CommonJsRequire => binding.imported_name.as_deref().unwrap_or("default"),
        ImportKind::Namespace | ImportKind::Glob => return Vec::new(),
    };
    exported_type_declarations(analyzer, index, &module_files, exported_name)
}

fn exported_type_declarations(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    module_files: &[ProjectFile],
    exported_name: &str,
) -> Vec<CodeUnit> {
    index
        .local_bindings_for_exported_name(module_files, exported_name)
        .into_iter()
        .flat_map(|(file, local_name)| type_declarations_in_file(analyzer, &file, &local_name))
        .collect()
}

fn type_declarations_in_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    identifier: &str,
) -> Vec<CodeUnit> {
    analyzer
        .top_level_declarations(file)
        .into_iter()
        .filter(|candidate| candidate.is_class() && candidate.identifier() == identifier)
        .collect()
}

fn dedupe_candidates(candidates: &mut Vec<CodeUnit>) {
    let mut seen = HashSet::default();
    candidates.retain(|candidate| seen.insert(candidate.clone()));
}
