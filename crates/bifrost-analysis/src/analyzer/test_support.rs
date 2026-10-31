use tree_sitter::Node;

use crate::analyzer::semantic::{SourceMapping, SourceSpan};
use crate::analyzer::semantic_model::{AuthoredPayload, MemberFact, RelationFact, TypeFact};
use crate::analyzer::usages::inverted_edges::UsageEdgesCache;

#[doc(hidden)]
pub fn authored_declaration_facts(
    payload: &AuthoredPayload,
) -> Option<(&[TypeFact], &[MemberFact], &[RelationFact])> {
    match payload {
        AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
            ..
        } => Some((types, members, relations)),
        AuthoredPayload::GeneratorRules { .. } | AuthoredPayload::ProcedureSummaries { .. } => None,
    }
}

#[doc(hidden)]
#[track_caller]
pub fn assert_dead_code_cache_reset_after_update_paths<A>(
    analyzer: &A,
    key: &std::sync::Arc<[String]>,
    cache_for: impl for<'a> Fn(&'a A) -> &'a UsageEdgesCache,
    update: impl Fn(&A) -> A,
    update_all: impl Fn(&A) -> A,
    overlay_clone: impl Fn(&A) -> A,
) {
    let updated = update(analyzer);
    assert!(cache_for(&updated).get(key).is_none());
    let rebuilt = update_all(analyzer);
    assert!(cache_for(&rebuilt).get(key).is_none());
    let overlay = overlay_clone(analyzer);
    assert!(cache_for(&overlay).get(key).is_none());
}

#[doc(hidden)]
pub fn python_package_project(
    module_sources: impl IntoIterator<Item = String>,
) -> (
    tempfile::TempDir,
    std::sync::Arc<dyn crate::analyzer::Project>,
) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    std::fs::create_dir_all(root.join("pkg")).expect("create pkg");
    std::fs::write(root.join("pkg/__init__.py"), "").expect("write package marker");
    for (index, source) in module_sources.into_iter().enumerate() {
        std::fs::write(root.join(format!("pkg/mod_{index}.py")), source).expect("write module");
    }
    let project: std::sync::Arc<dyn crate::analyzer::Project> = std::sync::Arc::new(
        crate::analyzer::TestProject::new(root, crate::analyzer::Language::Python),
    );
    (temp, project)
}

#[doc(hidden)]
pub fn source_mapping_span(mapping: &SourceMapping) -> SourceSpan {
    mapping.locator.anchor().span()
}

#[doc(hidden)]
pub fn source_mapping_text<'source>(mapping: &SourceMapping, source: &'source str) -> &'source str {
    let span = source_mapping_span(mapping);
    source
        .get(span.start_byte() as usize..span.end_byte() as usize)
        .expect("semantic source mapping must index its fixture")
}

#[doc(hidden)]
pub fn graph_reaches<T>(
    source: T,
    target: T,
    mut append_successors: impl FnMut(T, &mut Vec<T>),
) -> bool
where
    T: Copy + Eq + std::hash::Hash,
{
    let mut pending = vec![source];
    let mut visited = crate::hash::HashSet::default();
    while let Some(current) = pending.pop() {
        if current == target {
            return true;
        }
        if !visited.insert(current) {
            continue;
        }
        append_successors(current, &mut pending);
    }
    false
}

#[doc(hidden)]
pub fn first_named_node_matching_reverse_preorder<'tree>(
    root: Node<'tree>,
    mut matches: impl FnMut(Node<'tree>) -> bool,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches(node) {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

#[doc(hidden)]
pub fn first_named_kind<'tree>(
    root: tree_sitter::Node<'tree>,
    kind: &str,
) -> tree_sitter::Node<'tree> {
    crate::analyzer::test_support::first_named_node_matching_reverse_preorder(root, |node| {
        node.kind() == kind
    })
    .unwrap_or_else(|| panic!("missing `{kind}` node"))
}
