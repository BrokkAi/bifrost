//! Lazy, operation-owned hierarchy sequences. Policies choose order; this
//! module owns merge cursors, cooperative work, tail membership and retention.
use super::*;
use hierarchy_provenance::{HierarchyProvenanceId, HierarchyRequestIdentity};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct HierarchyOrderExprId(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HierarchyOrderPolicyId(pub(crate) u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HierarchySequenceId {
    identity: HierarchyRequestIdentity,
    cursor_generation: u64,
    slot: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HierarchyOrderedBase {
    pub(super) expression: HierarchyOrderExprId,
    pub(super) reference: SemanticId,
    pub(super) kind: Option<ResolutionSupertypeKind>,
    pub(super) ordinal: u32,
}
#[derive(Debug)]
struct OrderExpr {
    owner: SemanticId,
    bases: Box<[HierarchyOrderedBase]>,
    provenance: HierarchyProvenanceId,
    unsearched: bool,
}
#[derive(Debug, Default)]
pub(super) struct HierarchyOrderArena {
    expressions: Vec<OrderExpr>,
}
impl HierarchyOrderArena {
    pub(super) fn owner(
        &mut self,
        owner: SemanticId,
        mut bases: Vec<HierarchyOrderedBase>,
        provenance: HierarchyProvenanceId,
        unsearched: bool,
    ) -> HierarchyOrderExprId {
        bases.sort_by_key(|base| base.ordinal);
        let id = HierarchyOrderExprId(self.expressions.len());
        self.expressions.push(OrderExpr {
            owner,
            bases: bases.into_boxed_slice(),
            provenance,
            unsearched,
        });
        id
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HierarchyOrderRequest {
    pub(crate) policy: &'static dyn HierarchyLinearizationPolicy,
    pub(crate) start_after: Option<SemanticId>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum HierarchySequenceRole {
    Base {
        reference: SemanticId,
        kind: Option<ResolutionSupertypeKind>,
        ordinal: u32,
    },
    DeclaredBases,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct HierarchyOrderHead {
    pub(crate) sequence: HierarchySequenceId,
    pub(crate) owner: SemanticId,
    pub(crate) role: HierarchySequenceRole,
    pub(crate) provenance: HierarchySelectionProvenance,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HierarchyTailMembership {
    Present,
    Absent,
    Unknown,
}

pub(crate) struct HierarchyOrderBudget<'a> {
    step: &'a mut dyn FnMut() -> bool,
    stopped: bool,
}
impl HierarchyOrderBudget<'_> {
    pub(crate) fn step(&mut self) -> bool {
        if self.stopped || !(self.step)() {
            self.stopped = true;
            false
        } else {
            true
        }
    }
}

pub(crate) struct HierarchyOrderFrontier<'a> {
    pub(crate) heads: &'a [HierarchyOrderHead],
    pub(crate) owner: SemanticId,
    state: &'a HierarchyOrderState,
    arena: &'a HierarchyOrderArena,
}
impl HierarchyOrderFrontier<'_> {
    /// Query membership without copying an ancestor set or expanding a row.
    /// Unknown is distinct from absent when a base was intentionally unsearched.
    pub(crate) fn tail_contains(
        &self,
        sequence: HierarchySequenceId,
        owner: SemanticId,
        budget: &mut HierarchyOrderBudget<'_>,
    ) -> HierarchyTailMembership {
        assert_eq!(sequence.identity, self.state.identity);
        assert_eq!(sequence.cursor_generation, self.state.cursor_generation);
        let mut pending = Vec::new();
        self.state.tail_items(sequence.slot, &mut pending);
        let mut seen = HashSet::default();
        let mut unknown = false;
        while let Some(item) = pending.pop() {
            if !budget.step() {
                return HierarchyTailMembership::Unknown;
            }
            if !seen.insert(item) {
                continue;
            }
            match item {
                TailItem::Children(id) => {
                    let expr = &self.arena.expressions[id.0];
                    unknown |= expr.unsearched;
                    pending.extend(
                        expr.bases
                            .iter()
                            .map(|base| TailItem::Expr(base.expression)),
                    );
                }
                TailItem::Expr(id) => {
                    let expr = &self.arena.expressions[id.0];
                    if expr.owner == owner {
                        return HierarchyTailMembership::Present;
                    }
                    unknown |= expr.unsearched;
                    pending.extend(
                        expr.bases
                            .iter()
                            .map(|base| TailItem::Expr(base.expression)),
                    );
                }
                TailItem::Cursor(id) => {
                    if self.state.cursors[id]
                        .head
                        .flatten()
                        .is_some_and(|head| head.owner == owner)
                    {
                        return HierarchyTailMembership::Present;
                    }
                    self.state.tail_items(id, &mut pending);
                }
                TailItem::Direct { expr, ordinal } => {
                    let bases = &self.arena.expressions[expr.0].bases;
                    if let Some(base) = bases.get(ordinal) {
                        if self.arena.expressions[base.expression.0].owner == owner {
                            return HierarchyTailMembership::Present;
                        }
                        pending.push(TailItem::Direct {
                            expr,
                            ordinal: ordinal + 1,
                        });
                    }
                }
                TailItem::Unknown => unknown = true,
            }
        }
        if unknown {
            HierarchyTailMembership::Unknown
        } else {
            HierarchyTailMembership::Absent
        }
    }
}

pub(crate) enum HierarchyOrderDecision {
    Emit {
        owner: SemanticId,
        advance: Box<[HierarchySequenceId]>,
        provenance: HierarchySelectionProvenance,
    },
    RequireBase {
        reference: SemanticId,
        provenance: HierarchySelectionProvenance,
    },
    Incomplete {
        completion: ResolutionCompletion,
        provenance: HierarchySelectionProvenance,
    },
    Done {
        provenance: HierarchySelectionProvenance,
    },
}
pub(crate) trait HierarchyLinearizationPolicy: std::fmt::Debug + Sync {
    fn identity(&self) -> HierarchyOrderPolicyId;
    fn next(
        &self,
        frontier: &HierarchyOrderFrontier<'_>,
        budget: &mut HierarchyOrderBudget<'_>,
    ) -> StoreResult<HierarchyOrderDecision>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TailItem {
    Children(HierarchyOrderExprId),
    Expr(HierarchyOrderExprId),
    Cursor(usize),
    Direct {
        expr: HierarchyOrderExprId,
        ordinal: usize,
    },
    Unknown,
}
#[derive(Clone, Copy)]
struct Head {
    owner: SemanticId,
    provenance: HierarchyProvenanceId,
}
enum CursorKind {
    Owner {
        expr: HierarchyOrderExprId,
        emitted: bool,
    },
    Direct {
        expr: HierarchyOrderExprId,
        ordinal: usize,
    },
    Merge {
        expr: HierarchyOrderExprId,
        children: Vec<(usize, HierarchySequenceRole)>,
    },
    Alias(usize),
}
struct Cursor {
    kind: CursorKind,
    head: Option<Option<Head>>,
}

#[derive(Clone, Debug)]
pub(crate) struct HierarchyOrderedOwner {
    pub(crate) root: SemanticId,
    pub(crate) owner: SemanticId,
    pub(crate) provenance: HierarchySelectionProvenance,
}
/// One requested order, not a flattened ancestor set attached to every summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct HierarchyOrderOutcomeId {
    identity: HierarchyRequestIdentity,
    slot: usize,
}
impl HierarchyOrderOutcomeId {
    pub(super) fn retain(
        hierarchy: &mut HierarchyOperationArena,
        outcome: HierarchyOrderOutcome,
    ) -> Self {
        let identity = HierarchyProvenanceView::new(hierarchy).identity();
        let slot = hierarchy.order_outcomes.len();
        hierarchy.order_outcomes.push(outcome);
        Self { identity, slot }
    }
}
pub(crate) struct HierarchyOrderStatus<'a> {
    pub(crate) complete: bool,
    pub(crate) required_base: Option<SemanticId>,
    pub(crate) completion: &'a ResolutionCompletion,
    pub(crate) cursor_scope: Option<&'a HierarchyCursorScope>,
}
impl HierarchyProvenanceView<'_> {
    pub(crate) fn order_status(&self, id: HierarchyOrderOutcomeId) -> HierarchyOrderStatus<'_> {
        self.assert_identity(id.identity);
        let outcome = &self.hierarchy.order_outcomes[id.slot];
        HierarchyOrderStatus {
            complete: outcome.complete,
            required_base: outcome.required_base,
            completion: &outcome.completion,
            cursor_scope: outcome.cursor_scope.as_deref(),
        }
    }
    pub(crate) fn visit_order(
        &self,
        id: HierarchyOrderOutcomeId,
        cancelled: &mut dyn FnMut() -> bool,
        visitor: &mut dyn FnMut(&HierarchyOrderedOwner) -> StoreResult<()>,
    ) -> StoreResult<bool> {
        self.assert_identity(id.identity);
        for owner in &self.hierarchy.order_outcomes[id.slot].owners {
            if cancelled() {
                return Ok(false);
            }
            visitor(owner)?;
        }
        Ok(true)
    }
}
#[derive(Debug)]
pub(crate) struct HierarchyCursorScope {
    pub(crate) start_after: SemanticId,
    pub(crate) roots: Box<[SemanticId]>,
}

pub(crate) struct HierarchyOrderOutcome {
    pub(crate) owners: Vec<HierarchyOrderedOwner>,
    pub(crate) complete: bool,
    pub(crate) required_base: Option<SemanticId>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) cursor_scope: Option<Box<HierarchyCursorScope>>,
}

// Default-language snapshots must not acquire a new None field.
impl std::fmt::Debug for HierarchyOrderOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("HierarchyOrderOutcome");
        debug
            .field("owners", &self.owners)
            .field("complete", &self.complete)
            .field("required_base", &self.required_base)
            .field("completion", &self.completion);
        if let Some(scope) = &self.cursor_scope {
            debug.field("cursor_scope", scope);
        }
        debug.finish()
    }
}

pub(super) struct HierarchyOrderState {
    request: HierarchyOrderRequest,
    policy: HierarchyOrderPolicyId,
    identity: HierarchyRequestIdentity,
    cursor_generation: u64,
    cursors: Vec<Cursor>,
    roots: Vec<(usize, SemanticId)>,
    root_index: usize,
    owners: Vec<HierarchyOrderedOwner>,
    emitted: HashSet<(usize, SemanticId)>,
    started: bool,
    complete: bool,
    required_base: Option<SemanticId>,
    completion: ResolutionCompletion,
}
impl HierarchyOrderState {
    pub(super) fn new(request: HierarchyOrderRequest, view: HierarchyProvenanceView<'_>) -> Self {
        Self {
            request,
            policy: request.policy.identity(),
            identity: view.identity(),
            cursor_generation: {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            },
            cursors: Vec::new(),
            roots: Vec::new(),
            root_index: 0,
            owners: Vec::new(),
            emitted: HashSet::default(),
            started: request.start_after.is_none(),
            complete: true,
            required_base: None,
            completion: ResolutionCompletion::Complete,
        }
    }
    fn cursor(&mut self, kind: CursorKind) -> usize {
        let id = self.cursors.len();
        self.cursors.push(Cursor { kind, head: None });
        id
    }
    pub(super) fn root(&mut self, expression: HierarchyOrderExprId, owner: SemanticId) {
        let root = self.cursor(CursorKind::Owner {
            expr: expression,
            emitted: false,
        });
        self.roots.push((root, owner));
    }
    fn tail_items(&self, mut cursor: usize, pending: &mut Vec<TailItem>) {
        loop {
            match &self.cursors[cursor].kind {
                CursorKind::Owner { expr, .. } => pending.push(TailItem::Children(*expr)),
                CursorKind::Direct { expr, ordinal } => pending.push(TailItem::Direct {
                    expr: *expr,
                    ordinal: ordinal + 1,
                }),
                CursorKind::Merge { children, .. } => {
                    pending.extend(children.iter().map(|(id, _)| TailItem::Cursor(*id)))
                }
                CursorKind::Alias(id) => {
                    cursor = *id;
                    continue;
                }
            }
            break;
        }
    }
    fn advance(&mut self, mut cursor: usize) {
        loop {
            assert!(
                self.cursors[cursor].head.take().flatten().is_some(),
                "only a ready head advances"
            );
            match &mut self.cursors[cursor].kind {
                CursorKind::Owner { emitted, .. } => {
                    assert!(!*emitted);
                    *emitted = true;
                    break;
                }
                CursorKind::Direct { ordinal, .. } => {
                    *ordinal += 1;
                    break;
                }
                CursorKind::Merge { .. } => break,
                CursorKind::Alias(child) => cursor = *child,
            }
        }
    }
    fn head(
        &mut self,
        root: usize,
        arena: &HierarchyOrderArena,
        view: HierarchyProvenanceView<'_>,
        budget: &mut HierarchyOrderBudget<'_>,
    ) -> StoreResult<bool> {
        let mut pending = vec![root];
        while let Some(&cursor) = pending.last() {
            if self.cursors[cursor].head.is_some() {
                pending.pop();
                continue;
            }
            if let CursorKind::Owner { expr, emitted } = self.cursors[cursor].kind {
                let node = &arena.expressions[expr.0];
                if node.bases.is_empty() {
                    self.complete &= !node.unsearched;
                    self.cursors[cursor].head = Some((!emitted).then_some(Head {
                        owner: node.owner,
                        provenance: node.provenance,
                    }));
                    pending.pop();
                    continue;
                }
            }
            if !budget.step() {
                return Ok(false);
            }
            match &self.cursors[cursor].kind {
                CursorKind::Owner {
                    expr,
                    emitted: false,
                } => {
                    let node = &arena.expressions[expr.0];
                    self.cursors[cursor].head = Some(Some(Head {
                        owner: node.owner,
                        provenance: node.provenance,
                    }));
                }
                CursorKind::Owner {
                    expr,
                    emitted: true,
                } => {
                    let expr = *expr;
                    let node = &arena.expressions[expr.0];
                    self.complete &= !node.unsearched;
                    let mut children = Vec::with_capacity(node.bases.len() + 1);
                    for base in &node.bases {
                        if !budget.step() {
                            return Ok(false);
                        }
                        let child = self.cursor(CursorKind::Owner {
                            expr: base.expression,
                            emitted: false,
                        });
                        children.push((
                            child,
                            HierarchySequenceRole::Base {
                                reference: base.reference,
                                kind: base.kind,
                                ordinal: base.ordinal,
                            },
                        ));
                    }
                    if !node.bases.is_empty() {
                        let direct = self.cursor(CursorKind::Direct { expr, ordinal: 0 });
                        children.push((direct, HierarchySequenceRole::DeclaredBases));
                    }
                    self.cursors[cursor].kind = CursorKind::Merge { expr, children };
                }
                CursorKind::Direct { expr, ordinal } => {
                    let node = &arena.expressions[expr.0];
                    self.cursors[cursor].head = Some(node.bases.get(*ordinal).map(|base| {
                        let child = &arena.expressions[base.expression.0];
                        Head {
                            owner: child.owner,
                            provenance: child.provenance,
                        }
                    }));
                }
                CursorKind::Alias(child) => {
                    let child = *child;
                    if let CursorKind::Alias(grandchild) = self.cursors[child].kind {
                        self.cursors[cursor].kind = CursorKind::Alias(grandchild);
                        continue;
                    }
                    if let Some(head) = self.cursors[child].head {
                        self.cursors[cursor].head = Some(head);
                    } else {
                        pending.push(child);
                    }
                }
                CursorKind::Merge { expr, children } => {
                    let expr = *expr;
                    if let Some((child, _)) = children
                        .iter()
                        .find(|(id, _)| self.cursors[*id].head.is_none())
                    {
                        pending.push(*child);
                        continue;
                    }
                    let heads = children
                        .iter()
                        .filter_map(|(id, role)| {
                            self.cursors[*id]
                                .head
                                .flatten()
                                .map(|head| HierarchyOrderHead {
                                    sequence: HierarchySequenceId {
                                        identity: self.identity,
                                        cursor_generation: self.cursor_generation,
                                        slot: *id,
                                    },
                                    owner: head.owner,
                                    role: *role,
                                    provenance: view.selection(head.provenance),
                                })
                        })
                        .collect::<Vec<_>>();
                    if heads.is_empty() {
                        self.cursors[cursor].head = Some(None);
                        continue;
                    }
                    // One remaining sequence has no merge decision. Aliasing it
                    // shares the suffix, keeping a deep chain linear in memory.
                    if heads.len() == 1 {
                        self.cursors[cursor].kind = CursorKind::Alias(heads[0].sequence.slot);
                        continue;
                    }
                    let frontier = HierarchyOrderFrontier {
                        heads: &heads,
                        owner: arena.expressions[expr.0].owner,
                        state: self,
                        arena,
                    };
                    match self.request.policy.next(&frontier, budget)? {
                        HierarchyOrderDecision::Emit {
                            owner,
                            advance,
                            provenance,
                        } => {
                            view.assert_selection(provenance);
                            assert!(
                                !advance.is_empty(),
                                "a linearization step advances a sequence"
                            );
                            let mut seen = HashSet::default();
                            for sequence in advance {
                                assert_eq!(sequence.identity, self.identity);
                                assert_eq!(sequence.cursor_generation, self.cursor_generation);
                                assert!(
                                    heads.iter().any(
                                        |head| head.sequence == sequence && head.owner == owner
                                    ),
                                    "order selects a current head"
                                );
                                assert!(
                                    seen.insert(sequence.slot),
                                    "a sequence advances once per order step"
                                );
                                self.advance(sequence.slot);
                            }
                            self.cursors[cursor].head = Some(Some(Head {
                                owner,
                                provenance: provenance.root,
                            }));
                        }
                        HierarchyOrderDecision::Done { provenance } => {
                            view.assert_selection(provenance);
                            self.complete = false; // remaining sequences were intentionally unsearched
                            self.cursors[cursor].head = Some(None);
                        }
                        HierarchyOrderDecision::RequireBase {
                            reference,
                            provenance,
                        } => {
                            view.assert_selection(provenance);
                            // Ordering is for discharge only. Never reopen a
                            // parent beyond the aggregate hierarchy's cutoff.
                            self.required_base = Some(reference);
                            self.complete = false;
                            self.cursors[cursor].head = Some(None);
                        }
                        HierarchyOrderDecision::Incomplete {
                            completion,
                            provenance,
                        } => {
                            view.assert_selection(provenance);
                            self.completion = self.completion.combine(&completion);
                            self.complete = false;
                            self.cursors[cursor].head = Some(None);
                        }
                    }
                }
            }
        }
        Ok(!budget.stopped)
    }
    pub(super) fn poll(
        &mut self,
        arena: &HierarchyOrderArena,
        view: HierarchyProvenanceView<'_>,
        step: &mut dyn FnMut() -> bool,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> StoreResult<Option<HierarchyOrderOutcome>> {
        view.assert_identity(self.identity);
        assert_eq!(
            self.policy,
            self.request.policy.identity(),
            "an order cursor retains its policy identity across waits"
        );
        let mut budget = HierarchyOrderBudget {
            step,
            stopped: false,
        };
        while let Some(&(root, root_owner)) = self.roots.get(self.root_index) {
            if cancelled() {
                return Ok(None);
            }
            if !self.head(root, arena, view, &mut budget)? {
                if cancelled() {
                    return Ok(None);
                }
                // An optional-order cap is not an aggregate resolution stop.
                // Discard every provisional ordered owner/proof, not a prefix.
                self.owners.clear();
                self.complete = false;
                self.required_base = None;
                self.completion = ResolutionCompletion::Complete;
                return Ok(Some(HierarchyOrderOutcome {
                    cursor_scope: None,
                    owners: Vec::new(),
                    complete: false,
                    required_base: None,
                    completion: ResolutionCompletion::Complete,
                }));
            }
            let Some(head) = self.cursors[root].head.flatten() else {
                self.complete &= self.started;
                self.root_index += 1;
                self.started = self.request.start_after.is_none();
                continue;
            };
            if self.started && self.emitted.insert((self.root_index, head.owner)) {
                self.owners.push(HierarchyOrderedOwner {
                    root: root_owner,
                    owner: head.owner,
                    provenance: view.selection(head.provenance),
                });
            } else if self.request.start_after == Some(head.owner) {
                self.started = true;
            }
            self.advance(root);
        }
        if cancelled() {
            return Ok(None);
        }
        let mut cursor_scope = None;
        if self.complete
            && self.required_base.is_none()
            && self.completion == ResolutionCompletion::Complete
            && let Some(start_after) = self.request.start_after
        {
            let mut roots = Vec::new();
            for &(_, owner) in &self.roots {
                if cancelled() {
                    return Ok(None);
                }
                if !budget.step() {
                    self.owners.clear();
                    self.complete = false;
                    break;
                }
                roots.push(owner);
            }
            if self.complete {
                cursor_scope = Some(Box::new(HierarchyCursorScope {
                    start_after,
                    roots: roots.into_boxed_slice(),
                }));
            }
        }
        Ok(Some(HierarchyOrderOutcome {
            cursor_scope,
            owners: std::mem::take(&mut self.owners),
            complete: self.complete,
            required_base: self.required_base,
            completion: std::mem::replace(&mut self.completion, ResolutionCompletion::Complete),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Declared;
    impl HierarchyLinearizationPolicy for Declared {
        fn identity(&self) -> HierarchyOrderPolicyId {
            HierarchyOrderPolicyId(1)
        }
        fn next(
            &self,
            frontier: &HierarchyOrderFrontier<'_>,
            budget: &mut HierarchyOrderBudget<'_>,
        ) -> StoreResult<HierarchyOrderDecision> {
            let first = frontier.heads.first().expect("a nonempty merge frontier");
            let mut advance = Vec::new();
            for head in frontier.heads {
                if !budget.step() {
                    return Ok(HierarchyOrderDecision::Done {
                        provenance: first.provenance,
                    });
                }
                if head.owner == first.owner {
                    advance.push(head.sequence);
                }
            }
            Ok(HierarchyOrderDecision::Emit {
                owner: first.owner,
                advance: advance.into_boxed_slice(),
                provenance: first.provenance,
            })
        }
    }
    static DECLARED: Declared = Declared;
    #[test]
    fn shared_closer_order_keeps_declared_ordinals_and_unknown_base_provenance() {
        let mut arena = HierarchyOperationArena::default();
        let ids = ["order-a", "order-b", "order-c", "order-root"].map(SemanticId::for_test);
        let provenance = HierarchyProvenanceId::default();
        let a = arena.order.owner(ids[0], Vec::new(), provenance, false);
        let b = arena.order.owner(
            ids[1],
            vec![HierarchyOrderedBase {
                expression: a,
                reference: ids[0],
                kind: None,
                ordinal: 0,
            }],
            provenance,
            false,
        );
        let c = arena.order.owner(
            ids[2],
            vec![HierarchyOrderedBase {
                expression: a,
                reference: ids[0],
                kind: None,
                ordinal: 0,
            }],
            provenance,
            true,
        );
        let root = arena.order.owner(
            ids[3],
            vec![
                HierarchyOrderedBase {
                    expression: c,
                    reference: ids[2],
                    kind: None,
                    ordinal: 2,
                },
                HierarchyOrderedBase {
                    expression: b,
                    reference: ids[1],
                    kind: None,
                    ordinal: 1,
                },
            ],
            provenance,
            false,
        );
        let view = HierarchyProvenanceView::new(&arena);
        let mut state = HierarchyOrderState::new(
            HierarchyOrderRequest {
                policy: &DECLARED,
                start_after: None,
            },
            view,
        );
        state.root(root, ids[3]);
        let outcome = state
            .poll(&arena.order, view, &mut || true, &mut || false)
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome
                .owners
                .iter()
                .map(|row| row.owner)
                .collect::<Vec<_>>(),
            [ids[3], ids[1], ids[0], ids[2]]
        );
        assert!(outcome.owners.iter().all(|row| row.root == ids[3]));
        assert!(
            !outcome.complete,
            "an intentionally unsearched base is not an absence proof"
        );
        assert_eq!(
            outcome.completion,
            ResolutionCompletion::Complete,
            "order adds no aggregate reasons"
        );
    }
}
