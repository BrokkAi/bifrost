//! Client contracts for bounded distributive data-flow problems.

use std::hash::Hash;

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::semantic::{
    CallSiteHandle, EvidenceCompleteness, IcfgEdgeId, IcfgEdgeKind, IcfgNodeId, IcfgSnapshot,
    ProgramPointHandle, ProofStatus,
};

define_dense_id! {
    /// A run-local dense identifier for one client fact.
    ///
    /// Fact IDs are assigned deterministically by the solver and are meaningful
    /// only within the result of that solver run.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FactId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

/// One context-specific input fact for a bounded ICFG solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataflowSeed<F> {
    pub node: IcfgNodeId,
    pub fact: F,
}

impl<F> DataflowSeed<F> {
    pub const fn new(node: IcfgNodeId, fact: F) -> Self {
        Self { node, fact }
    }
}

/// Kernel-controlled output for seeds and transfer facts.
///
/// The kernel deduplicates rows into a request-bounded callback buffer before
/// canonicalizing them and atomically checking their semantic publication
/// charge. [`DataflowOutput::emit`] returns `false` when cancellation or that
/// row cap asks the callback to stop. The kernel will not retain additional
/// rows even if a callback ignores the signal, but clients must return
/// cooperatively to keep their own CPU work bounded.
pub trait DataflowOutput<T> {
    /// Emit one row, returning whether the callback may continue.
    #[must_use]
    fn emit(&mut self, value: T) -> bool;
}

/// Procedure-local semantic edge for one transfer-function evaluation.
///
/// The descriptor deliberately omits snapshot-local IDs and expanded call
/// contexts. A bounded-snapshot runner and a later summary runner can
/// therefore invoke the same transfer relation without making client
/// semantics depend on one materialized call stack.
#[derive(Debug, Clone, Copy)]
pub struct DataflowEdge<'graph> {
    kind: IcfgEdgeKind,
    origin: Option<&'graph CallSiteHandle>,
    source: &'graph ProgramPointHandle,
    target: &'graph ProgramPointHandle,
    proof: &'graph ProofStatus,
    completeness: &'graph EvidenceCompleteness,
}

impl<'graph> DataflowEdge<'graph> {
    pub const fn new(
        kind: IcfgEdgeKind,
        origin: Option<&'graph CallSiteHandle>,
        source: &'graph ProgramPointHandle,
        target: &'graph ProgramPointHandle,
        proof: &'graph ProofStatus,
        completeness: &'graph EvidenceCompleteness,
    ) -> Self {
        Self {
            kind,
            origin,
            source,
            target,
            proof,
            completeness,
        }
    }

    /// Resolve one semantic edge and both procedure-local endpoint handles
    /// from the same bounded snapshot.
    ///
    /// Returning a descriptor only after all three rows resolve prevents
    /// callers from pairing an edge with nodes from a different snapshot.
    pub fn from_snapshot(snapshot: &'graph IcfgSnapshot, edge_id: IcfgEdgeId) -> Option<Self> {
        let edge = snapshot.edge(edge_id)?;
        let source = snapshot.node(edge.source)?;
        let target = snapshot.node(edge.target)?;
        Some(Self::new(
            edge.kind,
            edge.origin.as_ref(),
            source.point(),
            target.point(),
            &edge.proof,
            &edge.completeness,
        ))
    }

    pub const fn kind(self) -> IcfgEdgeKind {
        self.kind
    }

    pub const fn origin(self) -> Option<&'graph CallSiteHandle> {
        self.origin
    }

    pub const fn source(self) -> &'graph ProgramPointHandle {
        self.source
    }

    pub const fn target(self) -> &'graph ProgramPointHandle {
        self.target
    }

    pub const fn proof(self) -> &'graph ProofStatus {
        self.proof
    }

    pub const fn completeness(self) -> &'graph EvidenceCompleteness {
        self.completeness
    }
}

/// A finite, union-distributive may-data-flow transfer relation.
///
/// Each callback maps one input fact independently to zero or more output
/// facts. Because clients cannot inspect or replace the whole reached set,
/// these unary relations lift pointwise to union-distributive propagation.
/// Non-distributive analyses require a separately named solver contract.
///
/// For a given edge descriptor and fact, callbacks must produce a finite,
/// repeatable relation independent of invocation order. The kernel may
/// evaluate the same pair again when a stronger path-quality profile reaches
/// it. Cooperative cancellation is the only supported callback side effect.
pub trait DistributiveDataflowProblem {
    type Fact: Copy + Eq + Hash + Ord;

    /// The distinguished fact injected at every seed node and preserved by
    /// the kernel across every edge.
    ///
    /// Transfer callbacks still receive this fact and may generate additional
    /// facts from it. They do not need to return the zero fact themselves.
    fn zero_fact(&self) -> Self::Fact;

    /// Transfer over an ordinary intraprocedural edge.
    ///
    /// This includes branch, loop, cleanup, and async-normal edges. Cleanup
    /// remains visible through the original `IcfgEdgeKind`.
    fn normal_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    );

    /// Transfer from a call site to a materialized callee entry.
    fn call_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    );

    /// Transfer from a callee exit to its matched caller continuation.
    ///
    /// The original edge distinguishes normal from exceptional return.
    fn return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    );

    /// Transfer along an ICFG-provided call-to-continuation edge.
    ///
    /// In the current bounded ICFG these edges model explicit boundary arms,
    /// such as deferred invocation; they are not an implicit bypass edge for
    /// every materialized call.
    fn call_to_return_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    );

    /// Transfer over local exceptional or async-exceptional control flow.
    fn exceptional_flow(
        &self,
        edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    );
}

/// Snapshot-specific seeds paired with a reusable transfer relation.
///
/// Only this bounded runner consumes dense, context-expanded `IcfgNodeId`
/// seeds. Keeping them out of [`DistributiveDataflowProblem`] allows later
/// procedure-summary backends to reuse transfer callbacks with their own
/// entry and incoming-call contracts.
pub trait BoundedSnapshotDataflowProblem: DistributiveDataflowProblem {
    /// Append every explicit, context-specific seed for this snapshot run.
    ///
    /// Seed production, like transfer evaluation, must be finite, repeatable,
    /// and cooperatively returning. The kernel bounds the unique seed buffer
    /// by the remaining callback-row budget, then canonicalizes the complete
    /// retained relation before charging facts and exact zero-inclusive states.
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>);
}
