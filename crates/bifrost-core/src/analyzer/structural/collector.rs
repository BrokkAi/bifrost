//! Grammar-blind assembly of structural fact rows.
//!
//! A language-owned walk supplies one event for each parsed node. This
//! collector owns only the durable model assembly: preorder ids and parent
//! bounds, embedded facts, role admission, and the final exact AST-node-key
//! resolution. Parsing, grammar lookup, and language-specific traversal state
//! remain outside this crate.

use super::callable::CallSiteContext;
use super::facts::{NormalizedNode, SourceRoleTarget, StructuralFactRows};
use super::kinds::NormalizedKind;
use super::occurrences::OccurrenceRole;
use super::spec::{PendingRoleTarget, RoleSink, RoleSinkStop, StructuralSpec};
use crate::analyzer::source_facts::PrimarySourceFactCollector;
use crate::analyzer::tree_walk::{ParentIndex, node_range};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactRowsBuilder;
use crate::hash::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralFactCollectorStop {
    Exceeded,
    Cancelled,
}

enum PendingOccurrenceTarget {
    AstNode(usize),
    Fact(u32),
}

struct PendingOccurrence {
    target: PendingOccurrenceTarget,
    role: OccurrenceRole,
}

/// Assembles structural fact rows from events supplied by a language-owned
/// parser walk.
pub struct StructuralFactCollector<'a> {
    spec: &'a dyn StructuralSpec,
    source: &'a str,
    context: &'a CallSiteContext,
    max_work_items: usize,
    cancellation: Option<&'a CancellationToken>,
    nodes: Vec<NormalizedNode>,
    fact_by_ast_node: HashMap<usize, u32>,
    pending_roles: Vec<Vec<PendingRoleTarget>>,
    pending_occurrence_roles: Vec<PendingOccurrence>,
    role_count: usize,
}

impl<'a> StructuralFactCollector<'a> {
    pub fn new(
        spec: &'a dyn StructuralSpec,
        source: &'a str,
        context: &'a CallSiteContext,
        max_work_items: usize,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            spec,
            source,
            context,
            max_work_items,
            cancellation,
            nodes: Vec::new(),
            fact_by_ast_node: HashMap::default(),
            pending_roles: Vec::new(),
            pending_occurrence_roles: Vec::new(),
            role_count: 0,
        }
    }

    /// Return the normalized kind already admitted for an enclosing fact.
    pub fn normalized_kind(&self, fact_id: u32) -> NormalizedKind {
        self.nodes[fact_id as usize].kind
    }

    /// Look up the fact id for an exact primary parser node key. This remains
    /// available throughout the language-owned walk for native consumers that
    /// need to link their site to the same canonical structural occurrence.
    pub fn fact_id_for_node(&self, node: Node<'_>) -> Option<u32> {
        self.fact_by_ast_node.get(&node.id()).copied()
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(CancellationToken::is_cancelled)
    }

    fn admit(&self) -> Result<(), StructuralFactCollectorStop> {
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        if self.nodes.len().saturating_add(self.role_count) >= self.max_work_items {
            return Err(StructuralFactCollectorStop::Exceeded);
        }
        Ok(())
    }

    /// Admit one normalized parser event and return its preorder fact id.
    ///
    /// `enclosing_normalized_id` is supplied by the language-owned walk. The
    /// collector does not inspect parser ancestry or decide which grammar
    /// nodes are normalized. Embedded facts are the one exception: the
    /// language spec supplies their exact source ranges and this collector
    /// inserts them directly below the admitted event.
    pub fn enter(
        &mut self,
        node: Node<'_>,
        normalized_kind: NormalizedKind,
        enclosing_normalized_id: Option<u32>,
        source_facts: &mut PrimarySourceFactCollector<'_>,
    ) -> Result<u32, StructuralFactCollectorStop> {
        self.admit()?;
        let range = node_range(node);
        assert!(
            range.end_byte <= self.source.len()
                && self.source.is_char_boundary(range.start_byte)
                && self.source.is_char_boundary(range.end_byte),
            "normalized node range {:?} must be within UTF-8 source bounds",
            range
        );

        let fact_id = u32::try_from(self.nodes.len())
            .expect("structural fact ids must fit in a u32 before allocation");
        let occurrence = source_facts.intern_node(node);
        let boolean_value = if normalized_kind == NormalizedKind::BooleanLiteral {
            let value = self.spec.boolean_literal_value(node);
            assert!(
                !self.spec.supports_boolean_literal_value() || value.is_some(),
                "{} structural adapter declares boolean-literal value support but grammar node {} has no exact value",
                self.spec.language().config_label(),
                node.grammar_name()
            );
            value
        } else {
            None
        };
        self.nodes.push(NormalizedNode {
            kind: normalized_kind,
            occurrence,
            boolean_value,
            construct: self
                .spec
                .generator_construct(node, normalized_kind)
                .map(str::to_owned),
            parent: enclosing_normalized_id,
            name: None,
            subtree_end: fact_id + 1,
            call_site: (normalized_kind == NormalizedKind::Call)
                .then(|| self.spec.call_site_facts(node, self.source, self.context))
                .flatten(),
        });
        self.pending_roles.push(Vec::new());
        assert!(
            self.fact_by_ast_node.insert(node.id(), fact_id).is_none(),
            "one AST node must produce at most one normalized fact"
        );

        let embedded =
            self.spec
                .embedded_leaf_facts(node, normalized_kind, self.source, self.cancellation);
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let mut previous_end = range.start_byte;
        for embedded in embedded {
            assert!(
                embedded.range.start_byte < embedded.range.end_byte
                    && range.start_byte <= embedded.range.start_byte
                    && embedded.range.end_byte <= range.end_byte
                    && (range.start_byte < embedded.range.start_byte
                        || embedded.range.end_byte < range.end_byte),
                "embedded fact range {:?} must be nonempty and contained by anchor {:?}",
                embedded.range,
                range
            );
            assert!(
                embedded.range.start_byte >= previous_end,
                "embedded facts must be ordered and non-overlapping: previous end {previous_end}, next {:?}",
                embedded.range
            );
            assert!(
                self.source.is_char_boundary(embedded.range.start_byte)
                    && self.source.is_char_boundary(embedded.range.end_byte),
                "embedded fact range {:?} must use UTF-8 boundaries",
                embedded.range
            );
            self.admit()?;
            let embedded_id = u32::try_from(self.nodes.len())
                .expect("embedded structural fact ids must fit in a u32 before allocation");
            let occurrence = source_facts.intern_embedded(embedded.range);
            self.nodes.push(NormalizedNode {
                kind: embedded.kind,
                occurrence,
                boolean_value: None,
                construct: None,
                parent: Some(fact_id),
                name: None,
                subtree_end: embedded_id + 1,
                call_site: None,
            });
            self.pending_roles.push(Vec::new());
            self.pending_occurrence_roles.push(PendingOccurrence {
                target: PendingOccurrenceTarget::Fact(embedded_id),
                role: embedded.occurrence_role,
            });
            previous_end = embedded.range.end_byte;
        }
        Ok(fact_id)
    }

    /// Create the temporary role sink for the fact most recently admitted.
    /// Role edges share the node admission budget and are checked before each
    /// role allocation by the sink.
    pub fn role_sink<'borrow, 'source>(
        &self,
        source_facts: &'borrow mut PrimarySourceFactCollector<'source>,
        parents: &'borrow ParentIndex<'borrow>,
    ) -> RoleSink<'borrow>
    where
        'a: 'borrow,
    {
        RoleSink::for_source(
            source_facts,
            self.max_work_items
                .saturating_sub(self.nodes.len().saturating_add(self.role_count)),
            self.cancellation,
            parents,
        )
    }

    /// Finish role extraction for `fact_id`, retaining exact AST node keys for
    /// resolution when the complete walk is finalized.
    pub fn accept_roles<'borrow>(
        &mut self,
        fact_id: u32,
        sink: RoleSink<'borrow>,
    ) -> Result<(), StructuralFactCollectorStop> {
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let (name, roles, occurrence_roles, stop) = sink.into_source_parts();
        match stop {
            Some(RoleSinkStop::Exceeded) => return Err(StructuralFactCollectorStop::Exceeded),
            Some(RoleSinkStop::Cancelled) => return Err(StructuralFactCollectorStop::Cancelled),
            None => {}
        }
        let fact = &mut self.nodes[fact_id as usize];
        fact.name = name;
        self.role_count = self.role_count.saturating_add(roles.len());
        assert!(
            self.nodes.len().saturating_add(self.role_count) <= self.max_work_items,
            "role admission must remain within the combined structural budget"
        );
        self.pending_roles[fact_id as usize] = roles;
        self.pending_occurrence_roles
            .extend(
                occurrence_roles
                    .into_iter()
                    .map(|pending| PendingOccurrence {
                        target: PendingOccurrenceTarget::AstNode(pending.target_node),
                        role: pending.role,
                    }),
            );
        Ok(())
    }

    /// Finalize parent subtree bounds and resolve all temporary AST node keys.
    pub fn finish(self) -> Result<StructuralFactRows, StructuralFactCollectorStop> {
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let StructuralFactCollector {
            mut nodes,
            fact_by_ast_node,
            pending_roles,
            pending_occurrence_roles,
            role_count,
            cancellation,
            ..
        } = self;
        for fact_id in (0..nodes.len()).rev() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            if let Some(parent) = nodes[fact_id].parent {
                let subtree_end = nodes[fact_id].subtree_end;
                let parent = &mut nodes[parent as usize];
                parent.subtree_end = parent.subtree_end.max(subtree_end);
            }
        }

        let mut roles = CompactRowsBuilder::with_capacity(nodes.len(), role_count);
        for pending in pending_roles {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            for pending in pending {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Err(StructuralFactCollectorStop::Cancelled);
                }
                roles.values_mut().push(SourceRoleTarget {
                    role: pending.role,
                    spread: pending.spread,
                    keyword: pending.keyword,
                    node: fact_by_ast_node.get(&pending.target_node).copied(),
                    occurrence: pending.occurrence,
                    name: pending.name,
                });
            }
            roles.finish_row();
        }

        let mut occurrence_roles = Vec::with_capacity(pending_occurrence_roles.len());
        for pending in pending_occurrence_roles {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            let node = match pending.target {
                PendingOccurrenceTarget::AstNode(ast_node) => {
                    let node = fact_by_ast_node.get(&ast_node).copied();
                    debug_assert!(
                        node.is_some(),
                        "occurrence role {:?} emitted for non-fact AST node {ast_node}",
                        pending.role
                    );
                    node
                }
                PendingOccurrenceTarget::Fact(fact_id) => Some(fact_id),
            };
            if let Some(node) = node {
                occurrence_roles.push((node, pending.role));
            }
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        occurrence_roles.sort_unstable();
        occurrence_roles.dedup();
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let mut occurrence_rows =
            CompactRowsBuilder::with_capacity(nodes.len(), occurrence_roles.len());
        let mut next = 0usize;
        let node_count = u32::try_from(nodes.len())
            .expect("structural fact ids must fit in a u32 before finalization");
        for fact_id in 0..node_count {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            while occurrence_roles
                .get(next)
                .is_some_and(|&(node, _)| node == fact_id)
            {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Err(StructuralFactCollectorStop::Cancelled);
                }
                occurrence_rows.values_mut().push(occurrence_roles[next].1);
                next += 1;
            }
            occurrence_rows.finish_row();
        }
        debug_assert_eq!(next, occurrence_roles.len());

        Ok(StructuralFactRows::new(
            nodes,
            roles.finish(),
            occurrence_rows.finish(),
        ))
    }
}
