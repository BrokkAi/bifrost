use crate::graph::resolver::JsTsUsageIndex;
use crate::imports::resolve_js_ts_module_specifier;
use crate::tsconfig::AliasResolver;
use brokk_bifrost_core::analyzer::capabilities::{
    DescendantIndexScope, DirectDescendantIndex, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::common::nonempty_node_source_text as non_empty_node_text;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::first_named_child;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub fn extract_js_supertypes(declaration: Node<'_>, source: &str) -> Vec<String> {
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

pub fn extract_ts_supertypes(declaration: Node<'_>, source: &str) -> Vec<String> {
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
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_body" || node.kind() == "object_type" {
            continue;
        }
        if matches!(
            node.kind(),
            "class_heritage" | "extends_type_clause" | "implements_clause"
        ) {
            collect_heritage_clause_types(node, source, raw, seen);
        }
        for index in (0..node.named_child_count()).rev() {
            stack.push(node.named_child(index).expect("named child in bounds"));
        }
    }
}

pub fn resolve_direct_ancestors(
    analyzer: &dyn CodeUnitIndex,
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
        let Some(ancestor) =
            resolve_unique_type(analyzer, index, language, alias_resolver, code_unit, raw)
        else {
            continue;
        };
        if seen.insert(ancestor.clone()) {
            ancestors.push(ancestor);
        }
    }
    ancestors
}

/// Invert the ancestor relation over every class in the workspace.
///
/// Unlike the shared core builder this one keys its nodes by declaration
/// identity rather than by fully qualified name, which is what JS/TS needs.
/// `scope` carries the same two duties it does there: it drops out-of-slice
/// declarations before their ancestors are resolved, and it bounds the loop --
/// `None` means the build stopped short and must not be published (#1748).
pub fn build_direct_descendant_index_by_unit<P>(
    analyzer: &dyn CodeUnitIndex,
    provider: &P,
    scope: &DescendantIndexScope<'_>,
) -> Option<DirectDescendantIndex>
where
    P: TypeHierarchyProvider + ?Sized,
{
    let mut nodes = analyzer
        .all_declarations()
        .filter(|candidate| candidate.is_class() && scope.admits(candidate))
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
        if scope.cancellation().is_cancelled() {
            return None;
        }
        let descendant = index_by_node[&candidate];
        for ancestor in provider
            .get_direct_ancestors_within(&candidate, scope)
            .ok()?
            .definite()
            .to_vec()
        {
            let ancestor = *index_by_node.entry(ancestor.clone()).or_insert_with(|| {
                let index = u32::try_from(nodes.len())
                    .expect("hierarchy index declarations must fit in a u32");
                nodes.push(ancestor);
                index
            });
            edges.push((ancestor, descendant));
        }
    }
    Some(DirectDescendantIndex::from_indexed_nodes(
        nodes,
        index_by_node,
        edges,
    ))
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

fn type_reference_text(mut node: Node<'_>, source: &str) -> Option<String> {
    loop {
        node = match node.kind() {
            "identifier"
            | "type_identifier"
            | "property_identifier"
            | "member_expression"
            | "nested_type_identifier" => return non_empty_node_text(node, source),
            "generic_type" => node.child_by_field_name("name")?,
            "extends_clause" => node.child_by_field_name("value")?,
            "type_query" => node.child_by_field_name("name")?,
            _ if node.named_child_count() == 1 => first_named_child(node)?,
            _ => return None,
        };
    }
}

fn resolve_unique_type(
    analyzer: &dyn CodeUnitIndex,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    owner: &CodeUnit,
    raw: &str,
) -> Option<CodeUnit> {
    let source_file = owner.source();
    // The persisted heritage spelling has a textual API, as do textual type
    // annotations. Recover its grammar structure before selecting qualifiers.
    let synthetic_source = format!("type __BifrostHeritage = {raw};");
    let tree =
        crate::syntax::parse_js_ts_tree(source_file, &synthetic_source, Language::TypeScript)?;
    let mut node = tree
        .root_node()
        .named_child(0)?
        .child_by_field_name("value")?;
    let mut segments = Vec::new();
    while let Some((module, name)) = crate::syntax::nested_type_identifier_parts(node) {
        segments.push(crate::syntax::slice(name, &synthetic_source).to_string());
        node = module;
    }
    if !matches!(node.kind(), "type_identifier" | "identifier") {
        return None;
    }
    segments.push(crate::syntax::slice(node, &synthetic_source).to_string());
    segments.reverse();

    // The structured owner segments retain namespace nesting. Resolve the
    // qualified spelling at the nearest owner before considering outer scopes.
    let mut prefix: Vec<_> = owner
        .fq()
        .resolved_segments()
        .map(|(name, _)| name)
        .collect();
    prefix.pop();
    loop {
        let qualified = prefix
            .iter()
            .copied()
            .chain(segments.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(".");
        let mut local = type_declarations_in_file(analyzer, source_file, &qualified);
        dedupe_candidates(&mut local);
        if !local.is_empty() {
            return (local.len() == 1).then(|| local.pop().expect("one candidate"));
        }
        if prefix.pop().is_none() {
            break;
        }
    }
    let mut candidates = Vec::new();
    candidates.extend(resolve_imported_type(
        analyzer,
        index,
        language,
        alias_resolver,
        source_file,
        &segments,
    ));
    dedupe_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.pop().expect("one candidate"))
}

fn resolve_imported_type(
    analyzer: &dyn CodeUnitIndex,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    source_file: &ProjectFile,
    segments: &[String],
) -> Vec<CodeUnit> {
    let (local_name, tail) = segments
        .split_first()
        .expect("heritage has a root identifier");
    if tail.is_empty() {
        return resolve_local_import_binding(
            analyzer,
            index,
            language,
            alias_resolver,
            source_file,
            local_name,
        );
    }
    let namespace_export = tail.join(".");

    let mut candidates = Vec::new();
    for binding in index
        .import_bindings(source_file, local_name)
        .filter(|binding| binding.kind == ImportKind::Namespace)
    {
        candidates.extend(imported_export_type_declarations(
            analyzer,
            index,
            language,
            alias_resolver,
            source_file,
            &binding.module_specifier,
            &namespace_export,
        ));
    }
    sort_and_deduplicate_type_candidates(&mut candidates);
    candidates
}

fn resolve_local_import_binding(
    analyzer: &dyn CodeUnitIndex,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    source_file: &ProjectFile,
    local_name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for binding in index.import_bindings(source_file, local_name) {
        let exported_name = match binding.kind {
            ImportKind::Default => "default",
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(local_name),
            ImportKind::CommonJsRequire => binding.imported_name.as_deref().unwrap_or("default"),
            ImportKind::Namespace | ImportKind::Glob => continue,
        };
        candidates.extend(imported_export_type_declarations(
            analyzer,
            index,
            language,
            alias_resolver,
            source_file,
            &binding.module_specifier,
            exported_name,
        ));
    }
    sort_and_deduplicate_type_candidates(&mut candidates);
    candidates
}

fn imported_export_type_declarations(
    analyzer: &dyn CodeUnitIndex,
    index: &JsTsUsageIndex,
    language: Language,
    alias_resolver: &AliasResolver,
    source_file: &ProjectFile,
    module_specifier: &str,
    exported_name: &str,
) -> Vec<CodeUnit> {
    let module_files = resolve_js_ts_module_specifier(
        source_file,
        module_specifier,
        language,
        Some(alias_resolver),
    );
    exported_type_declarations(analyzer, index, &module_files, exported_name)
}

fn sort_and_deduplicate_type_candidates(candidates: &mut Vec<CodeUnit>) {
    candidates.sort();
    candidates.dedup();
}

fn exported_type_declarations(
    analyzer: &dyn CodeUnitIndex,
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
    analyzer: &dyn CodeUnitIndex,
    file: &ProjectFile,
    identifier: &str,
) -> Vec<CodeUnit> {
    analyzer
        .declarations(file)
        .into_iter()
        .filter(|candidate| candidate.is_class() && candidate.fq_name_str() == identifier)
        .collect()
}

fn dedupe_candidates(candidates: &mut Vec<CodeUnit>) {
    let mut seen = HashSet::default();
    candidates.retain(|candidate| seen.insert(candidate.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: extends type arguments hid the base expression"
    )]
    fn heritage_grammar_keeps_clause_order_and_body_boundaries() {
        for (source, expected) in [
            ("class C extends B implements I, J {}", vec!["B", "I", "J"]),
            ("interface K extends I, J {}", vec!["I", "J"]),
            (
                "class Outer extends Base { method() { class Inner extends Other {} } }",
                vec!["Base"],
            ),
            (
                "class C extends ns.Base<A> implements N.I {}",
                vec!["ns.Base", "N.I"],
            ),
        ] {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            let declaration = tree.root_node().named_child(0).unwrap();
            assert_eq!(
                extract_ts_supertypes(declaration, source),
                expected,
                "{source}"
            );
        }
    }
}
