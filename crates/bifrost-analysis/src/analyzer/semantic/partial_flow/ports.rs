//! Ports of one procedure: the positions where a value enters or leaves the
//! procedure, or one of its call sites. The variants follow the port kinds of
//! the stored row vocabulary (kinds 0 to 11).

use std::collections::HashMap;

use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

use crate::analyzer::semantic::{
    AccessPathRoot, AccessPathTail, AccessSelector, CallSiteId, IndexSelector, MemoryLocationId,
    ProcedureId, ProcedurePortHandle, ProcedurePortKind, SemanticCallSite, SemanticLocator,
    SemanticValueKind, ValueFlowEndpoint, ValueId,
};

define_dense_id! {
    /// Index of one port within its procedure's port table.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PortId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

/// One port of a procedure. A `Heap` port is an access path rooted at an
/// input port (receiver, parameter or capture slot) of the same procedure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PartialFlowPort {
    Receiver,
    Parameter {
        ordinal: u32,
    },
    NormalReturn,
    IndexedNormalReturn {
        ordinal: u32,
    },
    ExceptionalReturn,
    CallReceiver {
        call: CallSiteId,
    },
    CallArgument {
        call: CallSiteId,
        ordinal: u32,
    },
    /// `ordinal` is `None` for the singular `result` of a call.
    CallResult {
        call: CallSiteId,
        ordinal: Option<u32>,
    },
    CallThrown {
        call: CallSiteId,
    },
    Capture {
        slot: MemoryLocationId,
    },
    Heap {
        root: Box<PartialFlowPort>,
        selectors: Box<[HeapSelector]>,
        tail: AccessPathTail,
    },
    /// The captured value of a closure binding, as it enters the closure's
    /// capture slot `destination` in procedure `target`.
    CaptureOut {
        target: ProcedureId,
        destination: MemoryLocationId,
    },
}

/// One selector of a `Heap` port. Mirrors [`AccessSelector`] with the
/// procedure-local scope made explicit: a field is a durable locator, and an
/// exact index names a value of the same procedure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HeapSelector {
    Field(SemanticLocator),
    Property(Box<str>),
    /// The decimal text of the index; the row stores the text id.
    ConstantIndex(Box<str>),
    ExactIndex(ValueId),
    AnyIndex,
}

impl PartialFlowPort {
    /// Whether this port can be the root of a `Heap` port (kinds 0, 1 and 9).
    pub(crate) fn is_heap_root(&self) -> bool {
        matches!(
            self,
            Self::Receiver | Self::Parameter { .. } | Self::Capture { .. }
        )
    }
}

fn port_of_handle(port: &ProcedurePortHandle) -> PartialFlowPort {
    match port.kind() {
        ProcedurePortKind::Receiver => PartialFlowPort::Receiver,
        ProcedurePortKind::Parameter { ordinal } => PartialFlowPort::Parameter { ordinal },
        ProcedurePortKind::NormalReturn => PartialFlowPort::NormalReturn,
        ProcedurePortKind::IndexedNormalReturn { ordinal } => {
            PartialFlowPort::IndexedNormalReturn { ordinal }
        }
        ProcedurePortKind::ExceptionalReturn => PartialFlowPort::ExceptionalReturn,
        ProcedurePortKind::Capture { slot } => PartialFlowPort::Capture { slot },
    }
}

/// The heap selectors of an access path's selectors.
pub fn heap_selectors(selectors: &[AccessSelector]) -> Box<[HeapSelector]> {
    selectors
        .iter()
        .map(|selector| match selector {
            AccessSelector::Field(field) => HeapSelector::Field(field.locator().clone()),
            AccessSelector::Property(name) => HeapSelector::Property(name.as_str().into()),
            AccessSelector::Index(IndexSelector::Exact(value)) => {
                HeapSelector::ExactIndex(value.id())
            }
            AccessSelector::Index(IndexSelector::Constant(index)) => {
                HeapSelector::ConstantIndex(index.to_string().into_boxed_str())
            }
            AccessSelector::Index(IndexSelector::Any) => HeapSelector::AnyIndex,
        })
        .collect()
}

/// The port of one carrier of the procedure that owns it, or `None` when the
/// carrier is not a port: a local value, a call's callee, a return of a
/// location, or a location whose root is not an input port.
pub fn port_of_endpoint(endpoint: &ValueFlowEndpoint) -> Option<PartialFlowPort> {
    match endpoint {
        ValueFlowEndpoint::Value(value) => {
            match value.procedure().semantics().value(value.id())?.kind {
                SemanticValueKind::Parameter { ordinal, .. } => {
                    Some(PartialFlowPort::Parameter { ordinal })
                }
                SemanticValueKind::Receiver { .. } => Some(PartialFlowPort::Receiver),
                _ => None,
            }
        }
        ValueFlowEndpoint::Port(port) => Some(port_of_handle(port)),
        ValueFlowEndpoint::Location(location) => {
            let root = match location.path().root() {
                AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
                    port_of_handle(port)
                }
                _ => return None,
            };
            root.is_heap_root().then(|| PartialFlowPort::Heap {
                root: Box::new(root),
                selectors: heap_selectors(location.path().selectors()),
                tail: location.path().tail(),
            })
        }
    }
}

/// The values a call site binds to ports: receiver, arguments, results and
/// thrown value. The callee is not a port. Results and the thrown value are
/// defined by the call; the others are read by it.
pub fn call_port_values(call: &SemanticCallSite) -> Vec<(PartialFlowPort, ValueId)> {
    let mut ports = Vec::new();
    if let Some(receiver) = call.receiver {
        ports.push((PartialFlowPort::CallReceiver { call: call.id }, receiver));
    }
    for (ordinal, argument) in call.arguments.iter().enumerate() {
        ports.push((
            PartialFlowPort::CallArgument {
                call: call.id,
                ordinal: u32::try_from(ordinal).expect("a call's argument count fits u32"),
            },
            argument.value,
        ));
    }
    if let Some(result) = call.result {
        ports.push((
            PartialFlowPort::CallResult {
                call: call.id,
                ordinal: None,
            },
            result,
        ));
    }
    for (ordinal, &value) in call.normal_results.iter().enumerate() {
        ports.push((
            PartialFlowPort::CallResult {
                call: call.id,
                ordinal: Some(u32::try_from(ordinal).expect("a call's result count fits u32")),
            },
            value,
        ));
    }
    if let Some(thrown) = call.thrown {
        ports.push((PartialFlowPort::CallThrown { call: call.id }, thrown));
    }
    ports
}

/// The value a call input port (`CallReceiver` or `CallArgument`) of `call`
/// reads, or `None` when the call has no such receiver or argument.
pub fn call_input_value(call: &SemanticCallSite, port: &PartialFlowPort) -> Option<ValueId> {
    match port {
        PartialFlowPort::CallReceiver { call: id } if *id == call.id => call.receiver,
        PartialFlowPort::CallArgument { call: id, ordinal } if *id == call.id => call
            .arguments
            .get(*ordinal as usize)
            .map(|argument| argument.value),
        _ => None,
    }
}

/// Interned ports of one procedure. A port's id is its first-use index.
#[derive(Debug, Default)]
pub(crate) struct PortTable {
    ports: Vec<PartialFlowPort>,
    ids: HashMap<PartialFlowPort, PortId>,
}

impl PortTable {
    /// Intern a port. A heap port's root is interned first, so every row's
    /// root id is smaller than the row's own id.
    pub(crate) fn intern(&mut self, port: PartialFlowPort) -> PortId {
        if let Some(&id) = self.ids.get(&port) {
            return id;
        }
        if let PartialFlowPort::Heap { root, .. } = &port {
            self.intern((**root).clone());
        }
        let id =
            PortId::try_from_index(self.ports.len()).expect("a procedure's port count fits u32");
        self.ports.push(port.clone());
        self.ids.insert(port, id);
        id
    }

    pub(crate) fn into_ports(self) -> Vec<PartialFlowPort> {
        self.ports
    }
}
