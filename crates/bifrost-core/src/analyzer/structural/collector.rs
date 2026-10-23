//! Grammar-blind assembly of structural fact rows.
//!
//! A language-owned walk supplies one event for each parsed node. This
//! collector owns only the durable model assembly: preorder ids and parent
//! bounds, embedded facts, role admission, and the final exact AST-node-key
//! resolution. Parsing, grammar lookup, and language-specific traversal state
//! remain outside this crate.

use super::callable::CallSiteContext;
use super::facts::{NormalizedNode, RoleTarget, Span, StructuralFactRows};
use super::kinds::NormalizedKind;
use super::occurrences::OccurrenceRole;
use super::spec::{PendingRoleTarget, RoleSink, RoleSinkParts, RoleSinkStop, StructuralSpec};
use crate::analyzer::source_facts::PrimarySourceFactCollector;
use crate::analyzer::tree_walk::{ParentIndex, collect_parse_errors, node_range};
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
pub struct StructuralFactCollector<'a, 'tree> {
    spec: &'a dyn StructuralSpec,
    source: &'a str,
    context: &'a CallSiteContext,
    /// AST parents for the tree being walked.
    ///
    /// Specs ask what encloses a node on essentially every fact, and
    /// `Node::parent` re-descends from the root each time, which is quadratic
    /// over a large file: on goqu's vendored 248k-line `sqlite3-binding.c` that
    /// was 97% of process CPU and timed out 100 probes. The driver that already
    /// visits every node supplies the index instead, either whole with
    /// [`ParentIndex::new`] or edge by edge with [`Self::record_children`].
    parents: ParentIndex<'tree>,
    max_work_items: usize,
    cancellation: Option<&'a CancellationToken>,
    nodes: Vec<NormalizedNode>,
    fact_by_ast_node: HashMap<usize, u32>,
    pending_roles: Vec<Vec<PendingRoleTarget>>,
    pending_occurrence_roles: Vec<PendingOccurrence>,
    role_count: usize,
}

impl<'a, 'tree> StructuralFactCollector<'a, 'tree> {
    pub fn new(
        spec: &'a dyn StructuralSpec,
        source: &'a str,
        context: &'a CallSiteContext,
        parents: ParentIndex<'tree>,
        max_work_items: usize,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            spec,
            source,
            context,
            parents,
            max_work_items,
            cancellation,
            nodes: Vec::new(),
            fact_by_ast_node: HashMap::default(),
            pending_roles: Vec::new(),
            pending_occurrence_roles: Vec::new(),
            role_count: 0,
        }
    }

    /// Normalize an ordinary parser event with the language-owned kind table
    /// and role hooks. Canonical producers and query-time extraction share it.
    pub fn enter_syntax(
        &mut self,
        node: Node<'tree>,
        enclosing: Option<u32>,
        kinds: &super::spec::CompiledKinds,
        source_facts: &mut PrimarySourceFactCollector<'_>,
    ) -> Result<Option<u32>, StructuralFactCollectorStop> {
        self.record_children(node);
        let spec = self.spec;
        let Some(kind) = node
            .is_named()
            .then(|| kinds.kind_of(&node))
            .flatten()
            .filter(|kind| spec.should_extract(node, *kind))
        else {
            return Ok(enclosing);
        };
        let kind = spec.refine_kind_with_parents(
            node,
            kind,
            enclosing.map(|id| self.normalized_kind(id)),
            self.source,
            self.context,
            self.parents(),
        );
        let fact_id = self.enter(node, kind, enclosing, source_facts)?;
        let mut sink = self.role_sink(source_facts);
        spec.extract(node, kind, &mut sink);
        self.accept_roles(fact_id, sink.into_parts())?;
        Ok(Some(fact_id))
    }

    /// Iteratively extract one syntax subtree, replacing opaque children with
    /// the admitted forest. This algorithm is also used inside Rust's primary
    /// producer, without replaying declaration or native-resolution events.
    pub fn collect_syntax(
        &mut self,
        root: Node<'tree>,
        enclosing: Option<u32>,
        forest: &'tree super::spec::EmbeddedSyntaxForest,
        kinds: &super::spec::CompiledKinds,
        source_facts: &mut PrimarySourceFactCollector<'_>,
    ) -> Result<(), StructuralFactCollectorStop> {
        let mut stack = vec![(root, enclosing)];
        while let Some((node, enclosing)) = stack.pop() {
            if self.is_cancelled() {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            let parent = self.enter_syntax(node, enclosing, kinds, source_facts)?;
            if let Some(children) = forest.children(node.id()) {
                for child in children.rev() {
                    self.record_embedded_parent(child, node);
                    stack.push((child, parent));
                }
            } else {
                crate::analyzer::tree_walk::push_named_children_reversed_as(
                    node,
                    &mut stack,
                    |child| (child, parent),
                );
            }
        }
        Ok(())
    }

    pub fn node_index(&self) -> &HashMap<usize, u32> {
        &self.fact_by_ast_node
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
        crate::cancellation::optional_is_cancelled(self.cancellation)
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
        let parenthesized = if normalized_kind == NormalizedKind::StringLiteral {
            let value = self.spec.string_literal_parenthesized(node);
            assert!(
                !self.spec.supports_string_literal_parenthesized() || value.is_some(),
                "{} structural adapter declares string-literal parenthesization support but grammar node {} has no exact value",
                self.spec.language().config_label(),
                node.grammar_name()
            );
            value
        } else {
            None
        };
        let is_async = normalized_kind
            .satisfies(NormalizedKind::Callable)
            .then(|| self.spec.async_callable_value(node))
            .flatten();
        let string_value = if normalized_kind == NormalizedKind::StringLiteral {
            let value = self.spec.string_literal_value(node, self.source);
            let requires_string_value = self.spec.supports_string_literal_value()
                && matches!(node.kind(), "string_literal" | "raw_string_literal")
                && !self
                    .spec
                    .string_literal_value_may_be_absent(node, self.source);
            assert!(
                !requires_string_value || value.is_some(),
                "{} structural adapter declares string-literal value support but grammar node {} has no exact value",
                self.spec.language().config_label(),
                node.grammar_name()
            );
            value
        } else {
            None
        };
        let assignment_shape = (normalized_kind == NormalizedKind::Assignment)
            .then(|| self.spec.assignment_shape(node))
            .flatten();
        let integer_literal_value = (normalized_kind == NormalizedKind::NumericLiteral)
            .then(|| self.spec.integer_literal_value(node, self.source))
            .flatten();
        let duplicate_key = (normalized_kind == NormalizedKind::ObjectProperty)
            .then(|| self.spec.duplicate_dictionary_key(node, self.source))
            .flatten();
        let (call_site, unsafe_context) = if normalized_kind.satisfies(NormalizedKind::Call) {
            let mut work = 0usize;
            // Keep the reserved node admission available after the syntax walk.
            let remaining = self
                .max_work_items
                .saturating_sub(self.nodes.len() + self.role_count + 1);
            let cancellation = self.cancellation;
            let mut charge = |amount| {
                if crate::cancellation::optional_is_cancelled(cancellation) {
                    return Err(StructuralFactCollectorStop::Cancelled);
                }
                work = work.saturating_add(amount);
                if work > remaining {
                    return Err(StructuralFactCollectorStop::Exceeded);
                }
                Ok(())
            };
            let provenance = self
                .spec
                .callee_provenance(node, self.source, &mut charge)?;
            let unsafe_context = self.spec.unsafe_context_value(node, &mut charge)?;
            self.max_work_items -= work;
            let site = self.spec.call_site_facts(node, self.source, self.context);
            let call_site = match provenance {
                Some(provenance) => {
                    let mut site = site.unwrap_or_else(super::callable::CallSiteFacts::unrefined);
                    site.callee_provenance = Some(provenance);
                    Some(site)
                }
                None => site,
            };
            (call_site, unsafe_context)
        } else {
            (None, None)
        };
        self.nodes.push(NormalizedNode {
            kind: normalized_kind,
            occurrence,
            boolean_value,
            parenthesized,
            assignment_shape,
            integer_literal_value,
            duplicate_key,
            is_async,
            unsafe_context,
            string_value,
            construct: self
                .spec
                .generator_construct(node, normalized_kind, self.source)
                .map(str::to_owned),
            parent: enclosing_normalized_id,
            name: None,
            subtree_end: fact_id + 1,
            call_site,
        });
        self.pending_roles.push(Vec::new());
        assert!(
            self.fact_by_ast_node.insert(node.id(), fact_id).is_none(),
            "one AST node must produce at most one normalized fact"
        );

        let embedded_facts =
            self.spec
                .embedded_leaf_facts(node, normalized_kind, self.source, self.cancellation);
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let embedded_base = u32::try_from(self.nodes.len())
            .expect("embedded structural fact ids must fit in a u32 before allocation");
        for (embedded_index, embedded) in embedded_facts.iter().enumerate() {
            assert!(
                range.start_byte <= embedded.range.start_byte
                    && embedded.range.end_byte <= range.end_byte,
                "embedded fact range {:?} must be contained by anchor {:?}",
                embedded.range,
                range
            );
            assert!(
                self.source.is_char_boundary(embedded.range.start_byte)
                    && self.source.is_char_boundary(embedded.range.end_byte),
                "embedded fact range {:?} must use UTF-8 boundaries",
                embedded.range
            );
            if let Some(parent) = embedded.parent {
                assert!(
                    parent < embedded_index,
                    "embedded fact {embedded_index} must refer to an earlier local parent {parent}"
                );
                let parent_fact = &embedded_facts[parent];
                assert!(
                    parent_fact.range.start_byte <= embedded.range.start_byte
                        && embedded.range.end_byte <= parent_fact.range.end_byte,
                    "embedded fact range {:?} must be contained by embedded parent {:?}",
                    embedded.range,
                    parent_fact.range
                );
            }
            self.admit()?;
            let embedded_id = u32::try_from(self.nodes.len())
                .expect("embedded structural fact ids must fit in a u32 before allocation");
            let occurrence = source_facts.intern_embedded(embedded.range);
            self.nodes.push(NormalizedNode {
                kind: embedded.kind,
                occurrence,
                boolean_value: None,
                parenthesized: None,
                assignment_shape: None,
                integer_literal_value: None,
                duplicate_key: None,
                is_async: None,
                unsafe_context: None,
                string_value: None,
                construct: embedded.construct.clone(),
                parent: Some(
                    embedded
                        .parent
                        .map_or(fact_id, |parent| embedded_base + parent as u32),
                ),
                name: None,
                subtree_end: embedded_id + 1,
                call_site: None,
            });
            self.pending_roles.push(Vec::new());
            if let Some(role) = embedded.occurrence_role {
                self.pending_occurrence_roles.push(PendingOccurrence {
                    target: PendingOccurrenceTarget::Fact(embedded_id),
                    role,
                });
            }
        }
        for (embedded_index, embedded) in embedded_facts.iter().enumerate().rev() {
            let embedded_id = embedded_base + embedded_index as u32;
            let parent_id = embedded
                .parent
                .map_or(fact_id, |parent| embedded_base + parent as u32);
            self.nodes[parent_id as usize].subtree_end = self.nodes[parent_id as usize]
                .subtree_end
                .max(self.nodes[embedded_id as usize].subtree_end);
        }
        Ok(fact_id)
    }

    /// Create the temporary role sink for the fact most recently admitted.
    /// Role edges share the node admission budget and are checked before each
    /// role allocation by the sink.
    pub fn role_sink<'borrow, 'source>(
        &'borrow self,
        source_facts: &'borrow mut PrimarySourceFactCollector<'source>,
    ) -> RoleSink<'borrow>
    where
        'a: 'borrow,
        'tree: 'borrow,
    {
        RoleSink::new(
            self.source,
            source_facts,
            self.max_work_items
                .saturating_sub(self.nodes.len().saturating_add(self.role_count)),
            self.cancellation,
            &self.parents,
        )
    }

    /// Record `node`'s visible children in the walk's parent index.
    ///
    /// A driver that enters every parser node fills the index as it goes and
    /// pays no second whole-tree pass; one that walks only part of the tree
    /// passes a complete [`ParentIndex::new`] to [`Self::new`] instead.
    pub fn record_children(&mut self, node: Node<'tree>) {
        self.parents.record_children(node);
    }

    /// Bridge a fragment root back to its original opaque container, so
    /// lexical ancestry does not escape through the synthetic parser wrapper.
    pub fn record_embedded_parent(&mut self, child: Node<'tree>, parent: Node<'tree>) {
        self.parents.record_parent(child, parent);
    }

    /// Return the parent index maintained by this structural walk.
    pub fn parents(&self) -> &ParentIndex<'tree> {
        &self.parents
    }

    /// Finish role extraction for `fact_id`, retaining exact AST node keys for
    /// resolution when the complete walk is finalized.
    pub fn accept_roles(
        &mut self,
        fact_id: u32,
        sink: RoleSinkParts,
    ) -> Result<(), StructuralFactCollectorStop> {
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let (name, roles, occurrence_roles, stop) = sink;
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

    /// Finalize parent subtree bounds, resolve all temporary AST node keys, and
    /// record the regions error recovery produced in the tree under `root`.
    ///
    /// `root` is the root of the tree the walk visited. Recovered regions are
    /// read from the tree rather than from the walk's events because an
    /// `ERROR` region is exactly where the walk may have admitted no fact.
    pub fn finish(self, root: Node<'_>) -> Result<StructuralFactRows, StructuralFactCollectorStop> {
        if self.is_cancelled() {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let mut parse_errors = Vec::new();
        collect_parse_errors(root, &mut parse_errors);
        let recovered_regions = parse_errors
            .into_iter()
            .map(|error| {
                assert!(
                    error.range.end_byte <= self.source.len(),
                    "recovered region {:?} ends past the {}-byte source",
                    error.range,
                    self.source.len()
                );
                Span {
                    start_byte: error.range.start_byte,
                    end_byte: error.range.end_byte,
                }
            })
            .collect();
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
                roles.values_mut().push(RoleTarget {
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
            recovered_regions,
        ))
    }
}
