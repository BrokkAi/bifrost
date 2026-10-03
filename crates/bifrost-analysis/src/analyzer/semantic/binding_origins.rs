//! Procedure-local origins for values that carry an address to a binding.

use std::collections::{HashMap, HashSet};

use super::{
    MemoryLocationId, MemoryLocationKind, ProcedureHandle, ProcedureSemantics, SemanticEffect,
    SemanticValueKind, ValueId,
};

/// A set of binding cells an address may denote and whether every origin was
/// found in the structured value graph.
#[derive(Debug, Clone)]
pub struct AddressedBindingOrigins {
    bindings: HashSet<ValueId>,
    complete: bool,
}

impl AddressedBindingOrigins {
    pub fn bindings(&self) -> &HashSet<ValueId> {
        &self.bindings
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn unique_binding(&self) -> Option<ValueId> {
        (self.complete && self.bindings.len() == 1)
            .then(|| *self.bindings.iter().next().expect("one binding origin"))
    }
}

/// Structured value predecessors used to recover possible binding origins of
/// address values. Joins are retained as may-origins; missing edges remain
/// incomplete so callers can invalidate every address-taken binding.
pub struct BindingOriginIndex {
    predecessors: HashMap<ValueId, Vec<ValueId>>,
    values: HashMap<ValueId, SemanticValueKind>,
    binding_locations: HashMap<ValueId, MemoryLocationId>,
    address_values: Vec<ValueId>,
    address_taken_bindings: HashSet<ValueId>,
}

impl BindingOriginIndex {
    pub fn new(procedure: &ProcedureHandle) -> Self {
        Self::from_semantics(procedure.semantics())
    }

    pub fn from_semantics(semantics: &ProcedureSemantics) -> Self {
        let mut predecessors = HashMap::<ValueId, Vec<ValueId>>::new();
        for point in semantics.points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                    | SemanticEffect::ValueFlow {
                        source: value,
                        target,
                        ..
                    } => predecessors.entry(target).or_default().push(value),
                    _ => {}
                }
            }
        }
        let values = semantics
            .values()
            .iter()
            .map(|value| (value.id, value.kind.clone()))
            .collect();
        let binding_locations = semantics
            .memory_locations()
            .iter()
            .filter_map(|location| match &location.kind {
                MemoryLocationKind::LexicalCell { binding } => Some((*binding, location.id)),
                _ => None,
            })
            .collect();
        let address_values = semantics
            .values()
            .iter()
            .filter_map(|value| (value.kind == SemanticValueKind::Address).then_some(value.id))
            .collect();
        let mut index = Self {
            predecessors,
            values,
            binding_locations,
            address_values,
            address_taken_bindings: HashSet::new(),
        };
        index.address_taken_bindings = index
            .address_values
            .iter()
            .flat_map(|address| index.addressed_binding_origins(*address).bindings)
            .collect();
        index
    }

    pub fn binding_memory_location(&self, binding: ValueId) -> Option<MemoryLocationId> {
        self.binding_locations.get(&binding).copied()
    }

    pub fn unique_binding_origin(&self, subject: ValueId) -> Option<ValueId> {
        let mut pending = vec![subject];
        let mut visited = HashSet::new();
        let mut bindings = HashSet::new();
        while let Some(value) = pending.pop() {
            if !visited.insert(value) {
                continue;
            }
            match self.values.get(&value)? {
                SemanticValueKind::Local
                | SemanticValueKind::Parameter { .. }
                | SemanticValueKind::Receiver { .. } => {
                    bindings.insert(value);
                }
                _ => pending.extend(self.predecessors.get(&value).into_iter().flatten().copied()),
            }
        }
        (bindings.len() == 1).then(|| *bindings.iter().next().expect("one binding"))
    }

    pub fn addressed_binding_origins(&self, subject: ValueId) -> AddressedBindingOrigins {
        let mut pending = vec![(subject, false)];
        let mut visited = HashSet::new();
        let mut bindings = HashSet::new();
        let mut complete = true;
        let mut found_address = false;
        while let Some((value, address_source)) = pending.pop() {
            if !visited.insert((value, address_source)) {
                continue;
            }
            let Some(value_kind) = self.values.get(&value) else {
                complete = false;
                continue;
            };
            if *value_kind == SemanticValueKind::Address {
                found_address = true;
                let Some(sources) = self.predecessors.get(&value) else {
                    complete = false;
                    continue;
                };
                if sources.is_empty() {
                    complete = false;
                }
                for &source in sources {
                    if self.values.get(&source).is_some_and(|kind| {
                        matches!(
                            kind,
                            SemanticValueKind::Local
                                | SemanticValueKind::Parameter { .. }
                                | SemanticValueKind::Receiver { .. }
                        )
                    }) {
                        bindings.insert(source);
                    } else {
                        complete = false;
                        pending.push((source, true));
                    }
                }
                continue;
            }
            if address_source
                && matches!(
                    value_kind,
                    SemanticValueKind::Local
                        | SemanticValueKind::Parameter { .. }
                        | SemanticValueKind::Receiver { .. }
                )
            {
                bindings.insert(value);
                continue;
            }
            if let Some(sources) = self.predecessors.get(&value) {
                if sources.is_empty() {
                    complete = false;
                }
                pending.extend(
                    sources
                        .iter()
                        .copied()
                        .map(|source| (source, address_source)),
                );
            } else {
                complete = false;
            }
        }
        complete &= found_address && !bindings.is_empty();
        AddressedBindingOrigins { bindings, complete }
    }

    pub fn address_taken_bindings(&self) -> HashSet<ValueId> {
        self.address_taken_bindings.clone()
    }

    pub fn address_taken_binding_set(&self) -> &HashSet<ValueId> {
        &self.address_taken_bindings
    }
}
