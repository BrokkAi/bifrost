//! The port graph the composition searches: nodes are positions inside one
//! procedure and hops are the composition edges, read in the forward
//! direction (from where a value is to where it goes).

use crate::analyzer::semantic::partial_flow::PartialFlowPort;
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, CallSiteId, DispatchBoundaryKind,
    ExactExternalProcedureTarget, ProgramPointId, UnmaterializedExternalTarget,
};
use crate::value_flow::{
    DurableCallSiteKey, DurableProcedureKey, ValueFlowCarrier, ValueFlowObservationPhase,
    ValueFlowSinkId,
};

use super::labels::LabelFunctionId;
use super::provider::{CallerLocation, DispatchCandidate, ExecutionCertificate};

/// A source of one composition: its index in the search's source table,
/// which holds the plan's bound sources first and then the sources the
/// provider matched on the frontier, in the order the search met them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComposedSourceId(pub(super) u32);

/// A call target with no body retains the resolver's typed identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExternalTargetIdentity {
    Unmaterialized {
        target: Box<UnmaterializedExternalTarget>,
        boundary: DispatchBoundaryKind,
    },
    Exact {
        target: Box<ExactExternalProcedureTarget>,
        boundary: DispatchBoundaryKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExecutionTarget {
    Procedure(Box<DurableProcedureKey>),
    External(Box<ExternalTargetIdentity>),
}

/// A query-local position of one tracked object. The terminal variants need
/// no live value at the exit point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObjectAnchorSite {
    ProgramPoint(ProgramPointId),
    CallSite(CallSiteId),
    NormalExit,
    ExceptionalExit,
}

/// The semantic role in which the same object is observed at an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectAnchorRole {
    MatchedValue,
    AllocationResult,
    Receiver,
    Argument,
    FormalReceiver,
    FormalArgument(u32),
    NormalReturn,
    ExceptionalReturn,
    FieldBase,
    FieldValue,
    FieldLocation,
    EscapedObject,
    CurrentObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectAnchor {
    pub procedure: DurableProcedureKey,
    pub site: ObjectAnchorSite,
    pub role: ObjectAnchorRole,
    pub object: AbstractObject,
}

impl ComposedSourceId {
    pub fn index(self) -> usize {
        usize::try_from(self.0).expect("a source index fits usize")
    }
}

/// One position inside one procedure. A port is a position of the stored
/// partial flows; sources, sinks and caller-side locations are the interior
/// positions only an interior run sees.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Execution(Box<ExecutionTarget>),
    Object(Box<ObjectAnchor>),
    Source(ComposedSourceId),
    Sink(ValueFlowSinkId),
    StoreWrite(usize),
    Port(PartialFlowPort),
    /// One object's state at a call's normal or exceptional continuation.
    /// This is separate from a returned or thrown value and from heap
    /// writeback, which describe different transports.
    CallHandoff {
        call: CallSiteId,
        candidate: Box<DispatchCandidate>,
        binding: super::provider::CallHandoffBinding,
        function: LabelFunctionId,
        quality: HopQuality,
    },
    Location(CallerLocation),
    Writeback {
        call: CallSiteId,
        candidate: Box<DispatchCandidate>,
        heap: PartialFlowPort,
        storage: Box<AbstractLocation>,
        uncertain: bool,
    },
}

/// One node of the port graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortNode {
    pub procedure: DurableProcedureKey,
    pub endpoint: Endpoint,
}

/// The best proof and completeness over a set of paths, independently.
/// `certain` additionally records that one path supplies both axes at every
/// hop; independent alternatives may supply `proven` and `complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HopQuality {
    pub proven: bool,
    pub complete: bool,
    /// One path is proven and complete at every hop. Private so that every
    /// value comes from `new`, `conjoin` or `join`, which keep it implying
    /// `proven && complete`.
    certain: bool,
}

impl HopQuality {
    /// Proven and complete on one path.
    pub const CERTAIN: Self = Self::new(true, true);
    /// Neither proven nor complete.
    pub const UNCERTAIN: Self = Self::new(false, false);

    /// Evidence for one hop, before joining alternative paths.
    pub const fn new(proven: bool, complete: bool) -> Self {
        Self {
            proven,
            complete,
            certain: proven && complete,
        }
    }

    /// The quality of evidence that is either proven and complete or neither.
    pub const fn from_uncertain(uncertain: bool) -> Self {
        Self::new(!uncertain, !uncertain)
    }

    /// Qualities on one path, one after the other.
    #[must_use]
    pub const fn conjoin(self, other: Self) -> Self {
        Self {
            proven: self.proven && other.proven,
            complete: self.complete && other.complete,
            certain: self.certain && other.certain,
        }
    }

    /// The best of two alternatives, with certainty supplied by one path.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self {
            proven: self.proven || other.proven,
            complete: self.complete || other.complete,
            certain: self.certain || other.certain,
        }
    }

    /// Whether `self` is at least as good as `other` on every axis.
    pub const fn dominates(self, other: Self) -> bool {
        (self.proven || !other.proven)
            && (self.complete || !other.complete)
            && (self.certain || !other.certain)
    }

    pub const fn is_certain(self) -> bool {
        self.certain
    }
}

/// One edge of the port graph, in forward order. Every hop records its
/// quality: an interior or stored flow from its relations and from the
/// dispatches of the calls it crossed, every other hop proven and complete
/// or neither (`uncertain`). Label-carrying hops record what the label stage
/// applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Hop {
    Invocation {
        call: DurableCallSiteKey,
        /// Ordinal in this call's dispatch answer; distinguishes arms with the same target.
        ordinal: usize,
        target: Box<ExecutionTarget>,
        function: LabelFunctionId,
        quality: HopQuality,
        certificate: ExecutionCertificate,
    },
    /// A selected store write reaches a may-alias read output.
    Store {
        write_call: DurableCallSiteKey,
        read_call: DurableCallSiteKey,
        write_site: Box<crate::analyzer::semantic::SemanticLocator>,
        read_site: Box<crate::analyzer::semantic::SemanticLocator>,
        read_origin: crate::taint::SourceEventKey,
        read_phase: ValueFlowObservationPhase,
        read_carrier: ValueFlowCarrier,
        uncertain: bool,
    },
    /// An interior run of `procedure`: from a source or an input port to a
    /// sink, an output port or a caller-side location. `crossed` are the
    /// calls of `procedure` that the path class this hop names crossed.
    Interior {
        procedure: DurableProcedureKey,
        from: Endpoint,
        to: Endpoint,
        function: LabelFunctionId,
        quality: HopQuality,
        crossed: Box<[CallSiteId]>,
    },
    /// A stored partial flow of `procedure`, with `crossed` as for
    /// `Interior`.
    Stored {
        procedure: DurableProcedureKey,
        from: PartialFlowPort,
        to: PartialFlowPort,
        function: LabelFunctionId,
        quality: HopQuality,
        crossed: Box<[CallSiteId]>,
    },
    /// Out of a callee at the end of a call: a return port to the caller's
    /// result or thrown-value port.
    Callee {
        call: DurableCallSiteKey,
        callee: DurableProcedureKey,
        from: PartialFlowPort,
        to: Endpoint,
        uncertain: bool,
        function: LabelFunctionId,
    },
    /// Into a callee at a call: a caller-side actual to the callee's formal,
    /// or a location rooted at the actual to the callee's heap input port on
    /// that formal.
    Caller {
        call: DurableCallSiteKey,
        callee: DurableProcedureKey,
        actual: PartialFlowPort,
        formal: PartialFlowPort,
        uncertain: bool,
        function: LabelFunctionId,
    },
    /// The same tracked object crosses a call and reaches its continuation.
    /// `function` is the callee's entry-to-matching-exit state relation.
    CallHandoff {
        call: DurableCallSiteKey,
        callee: DurableProcedureKey,
        actual: PartialFlowPort,
        formal: PartialFlowPort,
        exit: super::provider::CallHandoffExit,
        continuity: super::provider::CallObjectContinuity,
        function: LabelFunctionId,
        quality: HopQuality,
    },
    /// From a parent's capture binding into the closure's capture slot.
    Closure {
        parent: DurableProcedureKey,
        closure: DurableProcedureKey,
        binding: PartialFlowPort,
        slot: PartialFlowPort,
        uncertain: bool,
        certificate: Option<ExecutionCertificate>,
    },
    /// A model transfer from a call input to a result or caller storage output.
    /// `function` is what the model's labels do.
    /// `quality` is the model's own ([`super::CallModel::quality`]).
    Model {
        call: DurableCallSiteKey,
        actual: PartialFlowPort,
        result: PartialFlowPort,
        summary: Option<Box<crate::dataflow::ProcedureSummaryKey>>,
        retains_dispatch: bool,
        function: LabelFunctionId,
        quality: HopQuality,
    },
    /// The paranoid unmodeled-call fallback at `call`: a call input to the
    /// call's result or thrown value, as the ICFG engine's fallback transfer
    /// carries it. It is the identity on labels and always uncertain.
    Unmodeled {
        call: DurableCallSiteKey,
        input: PartialFlowPort,
        output: PartialFlowPort,
    },
    /// A bound sanitizer on the path through `call`. Only a proven sanitizer
    /// removes its labels, so an unproven one's `function` is the identity;
    /// an unresolved one makes the hop uncertain.
    Sanitizer {
        call: DurableCallSiteKey,
        function: LabelFunctionId,
        proven: bool,
        uncertain: bool,
    },
    /// A bound transform at `call`: an in-place transform of the plan on the
    /// path through the call, or a transform the provider matched, which is
    /// its own flow from a call input to a call output.
    Transform {
        call: DurableCallSiteKey,
        function: LabelFunctionId,
        uncertain: bool,
    },
}

impl Hop {
    /// Label relation retained on this hop. Hops without a relation are
    /// identity transfers for clients that fold a retained path.
    pub const fn function(&self) -> Option<LabelFunctionId> {
        match self {
            Self::Invocation { function, .. }
            | Self::Interior { function, .. }
            | Self::Stored { function, .. }
            | Self::Callee { function, .. }
            | Self::Caller { function, .. }
            | Self::CallHandoff { function, .. }
            | Self::Model { function, .. }
            | Self::Sanitizer { function, .. }
            | Self::Transform { function, .. } => Some(*function),
            Self::Store { .. } | Self::Closure { .. } | Self::Unmodeled { .. } => None,
        }
    }

    pub const fn quality(&self) -> HopQuality {
        match self {
            Self::Invocation { quality, .. }
            | Self::Interior { quality, .. }
            | Self::Stored { quality, .. }
            | Self::Model { quality, .. } => *quality,
            Self::CallHandoff { quality, .. } => *quality,
            Self::Callee { uncertain, .. }
            | Self::Caller { uncertain, .. }
            | Self::Closure { uncertain, .. }
            | Self::Sanitizer { uncertain, .. }
            | Self::Transform { uncertain, .. } => HopQuality::from_uncertain(*uncertain),
            Self::Store { uncertain, .. } => HopQuality::from_uncertain(*uncertain),
            Self::Unmodeled { .. } => HopQuality::UNCERTAIN,
        }
    }

    /// The quality of a run of hops, in path order.
    pub fn path_quality(hops: &[Self]) -> HopQuality {
        hops.iter().fold(HopQuality::CERTAIN, |quality, hop| {
            quality.conjoin(hop.quality())
        })
    }
}
