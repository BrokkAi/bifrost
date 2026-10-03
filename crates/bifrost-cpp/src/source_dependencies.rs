//! Declaration dependency evidence collected from one AST preorder per tree.

use brokk_bifrost_core::analyzer::cpp_facts::{CppDeclarationSourceFact, CppMemberUsingFact};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub(crate) struct DependencyIndex {
    events: Vec<DependencyEvent>,
    spans: HashMap<usize, std::ops::Range<usize>>,
    open: Vec<OpenNode>,
}

struct OpenNode {
    id: usize,
    remaining_children: usize,
    first_event: usize,
}

enum DependencyEvent {
    TypeName(String),
    MemberUsing(CppMemberUsingFact),
}

impl DependencyIndex {
    pub(crate) fn enter(&mut self, node: Node<'_>, source: &str) {
        self.close_finished();
        if let Some(parent) = self.open.last_mut() {
            parent.remaining_children = parent
                .remaining_children
                .checked_sub(1)
                .expect("dependency events follow AST preorder");
        }
        self.open.push(OpenNode {
            id: node.id(),
            remaining_children: node.child_count(),
            first_event: self.events.len(),
        });
        if matches!(node.kind(), "type_identifier" | "namespace_identifier") {
            self.events.push(DependencyEvent::TypeName(
                crate::declarations::node_text(node, source).to_owned(),
            ));
        }
        if node.kind() == "using_declaration"
            && let Some(imported) = node.named_child(0)
            && let Some(mut scope) =
                crate::graph::resolver::cpp_type_name_components(imported, source)
            && let Some(member) = scope.pop()
            && !scope.is_empty()
        {
            self.events
                .push(DependencyEvent::MemberUsing(CppMemberUsingFact {
                    member,
                    scope,
                }));
        }
    }

    fn close_finished(&mut self) {
        while self
            .open
            .last()
            .is_some_and(|node| node.remaining_children == 0)
        {
            let node = self.open.pop().expect("completed dependency owner");
            self.spans
                .insert(node.id, node.first_event..self.events.len());
        }
    }

    pub(crate) fn finish(&mut self) {
        self.close_finished();
        assert!(self.open.is_empty(), "complete dependency AST stream");
    }

    fn apply(&self, node: usize, is_class: bool, fact: &mut CppDeclarationSourceFact) {
        let span = self
            .spans
            .get(&node)
            .expect("exact dependency owner was visited");
        let mut names = HashSet::default();
        for event in &self.events[span.clone()] {
            match event {
                DependencyEvent::TypeName(name) if names.insert(name) => {
                    fact.dependency_type_names.push(name.clone());
                }
                DependencyEvent::MemberUsing(import) if is_class => {
                    fact.member_usings.push(import.clone());
                }
                _ => {}
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct DeclarationDependencies {
    pub primary: DependencyIndex,
    primary_owners: HashMap<SourceDeclarationId, (usize, bool)>,
    recovered: Vec<Option<DependencyIndex>>,
    vacant_recovery_arenas: Vec<usize>,
    recovered_nodes: HashMap<usize, usize>,
}

impl DeclarationDependencies {
    pub(crate) fn register_primary(
        &mut self,
        fact: SourceDeclarationId,
        node: Node<'_>,
        is_class: bool,
    ) {
        self.primary_owners.insert(fact, (node.id(), is_class));
    }

    fn add_recovered(&mut self, index: DependencyIndex) -> usize {
        let arena = self.vacant_recovery_arenas.pop().unwrap_or_else(|| {
            self.recovered.push(None);
            self.recovered.len() - 1
        });
        for node in index.spans.keys() {
            assert!(
                self.recovered_nodes.insert(*node, arena).is_none(),
                "distinct live recovery trees"
            );
        }
        self.recovered[arena] = Some(index);
        arena
    }

    fn release_recovered(&mut self, arena: usize) {
        let index = self.recovered[arena]
            .take()
            .expect("live recovery dependency arena");
        for node in index.spans.keys() {
            assert_eq!(self.recovered_nodes.remove(node), Some(arena));
        }
        self.vacant_recovery_arenas.push(arena);
    }

    pub(crate) fn apply_recovered(
        &self,
        node: Node<'_>,
        is_class: bool,
        fact: &mut CppDeclarationSourceFact,
    ) {
        let arena = self
            .recovered_nodes
            .get(&node.id())
            .expect("recovery dependency tree registered");
        self.recovered[*arena]
            .as_ref()
            .expect("live recovery dependency index")
            .apply(node.id(), is_class, fact);
    }

    pub(crate) fn finish_primary(
        &mut self,
        facts: &mut HashMap<SourceDeclarationId, CppDeclarationSourceFact>,
    ) {
        self.primary.finish();
        for (id, (node, is_class)) in &self.primary_owners {
            self.primary.apply(
                *node,
                *is_class,
                facts.get_mut(id).expect("registered declaration fact"),
            );
        }
    }
}

/// Keep dependency evidence for exactly the lifetime of its recovery traversal.
/// Nested recovery guards retain their parent tree's index until it resumes.
pub(crate) struct RecoveryAncestry<'owner, 'tree> {
    ancestry: ParentIndex<'tree>,
    dependencies: &'owner RefCell<DeclarationDependencies>,
    arena: usize,
}

impl<'owner, 'tree> RecoveryAncestry<'owner, 'tree> {
    pub(crate) fn new(
        root: Node<'tree>,
        source: &str,
        dependencies: &'owner RefCell<DeclarationDependencies>,
    ) -> Self {
        let mut index = DependencyIndex::default();
        let ancestry = ParentIndex::new_with_visit(root, |node| index.enter(node, source));
        index.finish();
        let arena = dependencies.borrow_mut().add_recovered(index);
        Self {
            ancestry,
            dependencies,
            arena,
        }
    }
}

impl<'tree> std::ops::Deref for RecoveryAncestry<'_, 'tree> {
    type Target = ParentIndex<'tree>;
    fn deref(&self) -> &Self::Target {
        &self.ancestry
    }
}

impl Drop for RecoveryAncestry<'_, '_> {
    fn drop(&mut self) {
        self.dependencies.borrow_mut().release_recovered(self.arena);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;

    #[test]
    fn deeply_nested_dependency_index_consumes_each_ast_node_once() {
        let depth = 128;
        let mut source = String::new();
        for index in 0..depth {
            source.push_str(&format!("struct N{index} {{ "));
        }
        source.push_str("Leaf value;");
        for _ in 0..depth {
            source.push_str("};");
        }
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let mut dependencies = DependencyIndex::default();
        let mut visited = HashSet::default();
        let ancestry = ParentIndex::new_with_visit(tree.root_node(), |node| {
            assert!(visited.insert(node.id()));
            dependencies.enter(node, &source);
        });
        dependencies.finish();
        assert_eq!(dependencies.spans.len(), visited.len());
        assert_eq!(dependencies.events.len(), depth + 1);
        let first = tree.root_node().named_child(0).unwrap();
        assert!(ancestry.contains(first));
        assert_eq!(dependencies.spans[&first.id()], 0..depth + 1);
    }
    #[test]
    fn recovery_dependency_arenas_follow_nested_traversal_lifetimes() {
        let source = "struct Outer { Member value; };";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let outer = parser.parse(source, None).unwrap();
        let inner = parser.parse(source, None).unwrap();
        let dependencies = RefCell::new(DeclarationDependencies::default());
        {
            let outer_guard = RecoveryAncestry::new(outer.root_node(), source, &dependencies);
            let outer_nodes = dependencies.borrow().recovered_nodes.len();
            {
                let _inner_guard = RecoveryAncestry::new(inner.root_node(), source, &dependencies);
                assert_eq!(dependencies.borrow().recovered_nodes.len(), outer_nodes * 2);
            }
            assert_eq!(dependencies.borrow().recovered_nodes.len(), outer_nodes);
            assert!(outer_guard.contains(outer.root_node().named_child(0).unwrap()));
        }
        assert!(dependencies.borrow().recovered_nodes.is_empty());
        assert!(dependencies.borrow().recovered.iter().all(Option::is_none));
        for _ in 0..128 {
            let _guard = RecoveryAncestry::new(inner.root_node(), source, &dependencies);
        }
        assert_eq!(
            dependencies.borrow().recovered.len(),
            2,
            "sequential recoveries reuse vacant arenas"
        );
        assert!(dependencies.borrow().recovered_nodes.is_empty());
    }
}
