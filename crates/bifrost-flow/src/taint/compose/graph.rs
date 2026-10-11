//! The port graph the composition searches: nodes are positions inside one
//! procedure and hops are the edges of spec M3.2, read in the forward
//! direction (from where a value is to where it goes).

use crate::analyzer::semantic::CallSiteId;
use crate::analyzer::semantic::partial_flow::PartialFlowPort;
use crate::value_flow::{DurableCallSiteKey, DurableProcedureKey, ValueFlowSinkId};

use super::provider::CallerLocation;
use crate::taint::{TaintClassSet, TaintEdgeFunction};

/// A source of one composition: its index in the search's source table,
/// which holds the plan's bound sources first and then the sources the
/// provider matched on the frontier, in the order the search met them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComposedSourceId(pub(super) u32);

impl ComposedSourceId {
    pub(super) fn index(self) -> usize {
        usize::try_from(self.0).expect("a source index fits usize")
    }
}

/// One position inside one procedure. A port is a position of the stored
/// partial flows; sources, sinks and caller-side locations are the interior
/// positions only an interior run sees.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Source(ComposedSourceId),
    Sink(ValueFlowSinkId),
    Port(PartialFlowPort),
    Location(CallerLocation),
}

/// One node of the port graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortNode {
    pub procedure: DurableProcedureKey,
    pub endpoint: Endpoint,
}

/// The best proof and the best completeness over a set of paths: `proven`
/// when some path is proven at every hop, `complete` when some path is
/// complete at every hop, each judged on its own. A finding reads the two
/// axes separately, as the ICFG engine's `has_proven_path` and
/// `has_complete_path` do, so conjoining hops and joining alternatives axis
/// by axis answers both questions exactly. It is not always one path's
/// quality: two different paths can set the two axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HopQuality {
    pub proven: bool,
    pub complete: bool,
}

impl HopQuality {
    /// Proven and complete.
    pub const CERTAIN: Self = Self {
        proven: true,
        complete: true,
    };
    /// Neither proven nor complete.
    pub const UNCERTAIN: Self = Self {
        proven: false,
        complete: false,
    };

    /// The quality of evidence that is either proven and complete or
    /// neither.
    pub const fn from_uncertain(uncertain: bool) -> Self {
        if uncertain {
            Self::UNCERTAIN
        } else {
            Self::CERTAIN
        }
    }

    /// Both qualities on one path, one after the other.
    #[must_use]
    pub const fn conjoin(self, other: Self) -> Self {
        Self {
            proven: self.proven && other.proven,
            complete: self.complete && other.complete,
        }
    }

    /// The best of two alternatives, axis by axis.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self {
            proven: self.proven || other.proven,
            complete: self.complete || other.complete,
        }
    }

    /// Whether `self` is at least as good as `other` on both axes.
    pub const fn dominates(self, other: Self) -> bool {
        (self.proven || !other.proven) && (self.complete || !other.complete)
    }

    pub const fn is_certain(self) -> bool {
        self.proven && self.complete
    }
}

/// One edge of the port graph, in forward order. Every hop records its
/// quality: an interior or stored flow from its relations and from the
/// dispatches of the calls it crossed, every other hop proven and complete
/// or neither (`uncertain`). Label-carrying hops record what the label stage
/// applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Hop {
    /// An interior run of `procedure`: from a source or an input port to a
    /// sink, an output port or a caller-side location. `crossed` are the
    /// calls of `procedure` that the path class this hop names crossed.
    Interior {
        procedure: DurableProcedureKey,
        from: Endpoint,
        to: Endpoint,
        quality: HopQuality,
        crossed: Box<[CallSiteId]>,
    },
    /// A stored partial flow of `procedure`, with `crossed` as for
    /// `Interior`.
    Stored {
        procedure: DurableProcedureKey,
        from: PartialFlowPort,
        to: PartialFlowPort,
        quality: HopQuality,
        crossed: Box<[CallSiteId]>,
    },
    /// Out of a callee at the end of a call: a return port to the caller's
    /// result port.
    Callee {
        call: DurableCallSiteKey,
        callee: DurableProcedureKey,
        from: PartialFlowPort,
        to: Endpoint,
        uncertain: bool,
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
    },
    /// From a parent's capture binding into the closure's capture slot.
    Closure {
        parent: DurableProcedureKey,
        closure: DurableProcedureKey,
        binding: PartialFlowPort,
        slot: PartialFlowPort,
        uncertain: bool,
    },
    /// A model transfer that replaces a call to `candidate`, from a call input
    /// port to the call's result. `moved` and `removed` are the model's
    /// labels, resolved against the plan's universe. `quality` is the
    /// model's own ([`super::CallModel::quality`]).
    Model {
        call: DurableCallSiteKey,
        actual: PartialFlowPort,
        result: PartialFlowPort,
        moved: Option<TaintClassSet>,
        removed: TaintClassSet,
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
    /// removes its classes; an unresolved one makes the hop uncertain.
    Sanitizer {
        call: DurableCallSiteKey,
        removed: TaintClassSet,
        proven: bool,
        uncertain: bool,
    },
    /// A bound transform at `call`: an in-place transform of the plan on the
    /// path through the call, or a transform the provider matched, which is
    /// its own flow from a call input to a call output.
    Transform {
        call: DurableCallSiteKey,
        function: TaintEdgeFunction,
        uncertain: bool,
    },
}

impl Hop {
    pub const fn quality(&self) -> HopQuality {
        match self {
            Self::Interior { quality, .. }
            | Self::Stored { quality, .. }
            | Self::Model { quality, .. } => *quality,
            Self::Callee { uncertain, .. }
            | Self::Caller { uncertain, .. }
            | Self::Closure { uncertain, .. }
            | Self::Sanitizer { uncertain, .. }
            | Self::Transform { uncertain, .. } => HopQuality::from_uncertain(*uncertain),
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
