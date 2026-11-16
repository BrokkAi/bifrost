use super::*;
use crate::analyzer::semantic::{CallSiteId, MemoryLocationId, ProgramPointId, ValueId};

/// Request-local facts shared by every private-cell proof in one query. The
/// procedure scans and binding-origin graph are built once; per-cell checks
/// visit only indexed definitions, stores and calls for that cell.
pub(super) struct PrivateCellFacts {
    procedure: ProcedureHandle,
    blocked: bool,
    blocked_bindings: HashSet<ValueId>,
    blocked_cells: HashSet<MemoryLocationId>,
    definitions: HashMap<ValueId, Vec<PrivateCellEvent>>,
    assignments: HashMap<(ProgramPointId, ValueId), Vec<PrivateCellEvent>>,
    stores: HashMap<MemoryLocationId, Vec<PrivateCellEvent>>,
    loads: HashMap<(ProgramPointId, MemoryLocationId), Vec<usize>>,
    stored_values: HashMap<(ProgramPointId, MemoryLocationId, ValueId), Vec<usize>>,
    calls: HashMap<MemoryLocationId, Vec<CallSiteId>>,
    // Declared last: the lease outlives the index allocations during Drop.
    _resident_rows: std::sync::Arc<()>,
}

// The ledger keeps a weak receipt; this query-owned lease keeps the rows
// charged across nested calls and refunds them on every query exit, including
// cancellation/error, when PrivateCellFacts drops. It never retains the index.
pub(super) fn retain_index_rows(
    staged: &mut WorkStager,
    rows: usize,
) -> Result<std::sync::Arc<()>, InterruptionOrProvider> {
    let census = SemanticWork {
        nested_entries: rows,
        ..SemanticWork::default()
    };
    let owner = std::sync::Arc::new(());
    staged
        .admit(census)
        .map_err(InterruptionOrProvider::Interruption)?;
    staged.budget.track_replay_holder(&owner, census);
    Ok(owner)
}

#[derive(Clone, Copy)]
struct PrivateCellEvent {
    point: ProgramPointId,
    index: usize,
    value: ValueId,
}

impl PrivateCellFacts {
    fn derive(
        oracle: &WorkspaceSemanticOracle<'_>,
        procedure: &ProcedureHandle,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<Self, InterruptionOrProvider> {
        use crate::analyzer::semantic::{BindingOriginIndex, SemanticCapability};
        let semantics = procedure.semantics();
        // Conservative row census, including map keys and vector payloads:
        // each event creates at most two key/payload pairs. The temporary
        // origin graph coexists with the blocked sets during preparation.
        // Charge before allocating any of these copies, using the existing
        // nested-entry allowance rather than a separate index limit.
        let mut events = 0usize;
        for point in semantics.points() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                program_points: 1,
                ..SemanticWork::default()
            });
            events = events.saturating_add(point.events.len());
        }
        let rows = events
            .saturating_mul(4)
            .saturating_add(1)
            .saturating_add(semantics.values().len().saturating_mul(5))
            .saturating_add(semantics.memory_locations().len())
            .saturating_add(semantics.captures().len().saturating_mul(2))
            .saturating_add(semantics.pointer_origins().len().saturating_mul(2))
            .saturating_add(semantics.gaps().len().saturating_mul(3))
            .saturating_add(semantics.call_sites().len().saturating_mul(2));
        let resident_rows = retain_index_rows(staged, rows)?;
        let mut facts = Self {
            procedure: procedure.clone(),
            _resident_rows: resident_rows,
            blocked: false,
            blocked_bindings: HashSet::default(),
            blocked_cells: HashSet::default(),
            definitions: HashMap::default(),
            assignments: HashMap::default(),
            stores: HashMap::default(),
            loads: HashMap::default(),
            stored_values: HashMap::default(),
            calls: HashMap::default(),
        };
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled.into());
        }
        // The shared origin owner visits these rows once to build its graph
        // and precomputed address-taken set. Do not rebuild it for each alias.
        staged.charge_work(SemanticWork {
            program_points: semantics.points().len(),
            events,
            values: semantics.values().len().saturating_mul(2),
            memory_locations: semantics.memory_locations().len(),
            ..SemanticWork::default()
        });
        let origins = BindingOriginIndex::from_semantics(semantics);
        facts
            .blocked_bindings
            .extend(origins.address_taken_binding_set());
        for capture in semantics.captures() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                captures: 1,
                ..SemanticWork::default()
            });
            match capture.captured {
                CaptureSource::Value(value) => {
                    facts.blocked_bindings.insert(value);
                }
                CaptureSource::Location(location) => {
                    facts.blocked_cells.insert(location);
                }
            }
        }
        for origin in semantics.pointer_origins() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                values: 1,
                ..SemanticWork::default()
            });
            if let crate::analyzer::semantic::PointerOriginKind::StackPlace { place } = &origin.kind
                && let Some(AccessPathRoot::LexicalCell(cell)) =
                    addressed_place_root(procedure, place)
            {
                facts.blocked_cells.insert(cell.id());
            }
        }
        let discharged = discharged_inert_drop_gaps(oracle, procedure, staged, cancellation)?;
        let mut abort_user_code = None;
        for logical in semantics.logical_gaps() {
            let gap = logical.base;
            if logical
                .key()
                .is_discharged_by(|key| discharged.contains(&key))
            {
                continue;
            }
            if logical.member.is_some() {
                // Member obligations cannot enter ordinary ID-based proofs.
                // Keep the whole procedure blocked unless the exact traced
                // owner's obligation is proven by the caller.
                if gap_impacts_heap(gap)
                    || matches!(
                        gap.capability,
                        SemanticCapability::NormalControlFlow
                            | SemanticCapability::CleanupControlFlow
                            | SemanticCapability::NonLocalControl
                            | SemanticCapability::ExceptionalControlFlow
                    )
                {
                    facts.blocked = true;
                    return Ok(facts);
                }
                continue;
            }
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                gaps: 1,
                ..SemanticWork::default()
            });
            if matches!(
                gap.capability,
                SemanticCapability::NormalControlFlow
                    | SemanticCapability::CleanupControlFlow
                    | SemanticCapability::NonLocalControl
            ) {
                facts.blocked = true;
                return Ok(facts);
            }
            if gap.capability == SemanticCapability::ExceptionalControlFlow {
                if matches!(gap.control_flow_discharge(), crate::analyzer::semantic::SemanticGapDischarge::NonRejoiningExceptionalExit | crate::analyzer::semantic::SemanticGapDischarge::ExitOnlyProcedureCompletion) { continue; }
                facts.blocked = true;
                return Ok(facts);
            }
            if !gap_can_open_heap(procedure, gap, &mut abort_user_code)
                || !gap.impacts.contains(SemanticGapImpact::HeapWrite)
            {
                continue;
            }
            match gap.subject {
                SemanticGapSubject::Value(value) => {
                    facts.blocked_bindings.insert(value);
                }
                SemanticGapSubject::MemoryLocation(cell) => {
                    facts.blocked_cells.insert(cell);
                    if let Some(location) = semantics.memory_location(cell) {
                        // These are exactly the operands tested by uses_value;
                        // querying them avoids an all-values scan per cell.
                        let operands = match location.kind {
                            MemoryLocationKind::Field { base, .. }
                            | MemoryLocationKind::Property { base, .. } => [Some(base), None],
                            MemoryLocationKind::Index { base, index, .. } => [Some(base), index],
                            MemoryLocationKind::Dereference { address } => [Some(address), None],
                            MemoryLocationKind::LexicalCell { binding } => [Some(binding), None],
                            MemoryLocationKind::Capture { binding, .. } => [binding, None],
                            MemoryLocationKind::Static { .. } => [None, None],
                        };
                        for value in operands.into_iter().flatten() {
                            staged.charge_work(SemanticWork {
                                values: 1,
                                ..SemanticWork::default()
                            });
                            if let Some(binding) = origins.unique_binding_origin(value) {
                                facts.blocked_bindings.insert(binding);
                            }
                        }
                    }
                }
                SemanticGapSubject::Procedure | SemanticGapSubject::Point => {
                    facts.blocked = true;
                    return Ok(facts);
                }
                _ => {}
            }
        }
        // The origin graph is construction scratch, not part of the retained
        // cell index. End its lifetime before allocating the event indexes.
        drop(origins);
        for point in semantics.points() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                program_points: 1,
                ..SemanticWork::default()
            });
            for (index, event) in point.events.iter().enumerate() {
                if cancellation.is_cancelled() {
                    return Err(Interruption::Cancelled.into());
                }
                staged.charge_work(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                });
                match event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        let row = PrivateCellEvent {
                            point: point.id,
                            index,
                            value,
                        };
                        facts.definitions.entry(target).or_default().push(row);
                        facts
                            .assignments
                            .entry((point.id, target))
                            .or_default()
                            .push(row);
                    }
                    SemanticEffect::ValueFlow { target, source, .. } => {
                        facts
                            .definitions
                            .entry(target)
                            .or_default()
                            .push(PrivateCellEvent {
                                point: point.id,
                                index,
                                value: source,
                            });
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        facts
                            .stores
                            .entry(location)
                            .or_default()
                            .push(PrivateCellEvent {
                                point: point.id,
                                index,
                                value,
                            });
                        facts
                            .stored_values
                            .entry((point.id, location, value))
                            .or_default()
                            .push(index);
                    }
                    SemanticEffect::MemoryLoad { location, .. } => {
                        facts
                            .loads
                            .entry((point.id, location))
                            .or_default()
                            .push(index);
                    }
                    _ => {}
                }
            }
        }
        for call in semantics.call_sites() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                call_sites: 1,
                ..SemanticWork::default()
            });
            if let Some(AccessPathRoot::LexicalCell(cell)) = call
                .member_selection
                .as_ref()
                .and_then(|selection| selection.receiver_place.as_ref())
                .and_then(|place| addressed_place_root(procedure, place))
            {
                facts.calls.entry(cell.id()).or_default().push(call.id);
            }
        }
        Ok(facts)
    }

    fn binding(
        &self,
        oracle: &WorkspaceSemanticOracle<'_>,
        location: MemoryLocationId,
        staged: &mut WorkStager,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<Option<ValueId>, InterruptionOrProvider> {
        let procedure = &self.procedure;
        let semantics = procedure.semantics();
        let Some(MemoryLocationKind::LexicalCell { binding }) =
            semantics.memory_location(location).map(|row| &row.kind)
        else {
            return Ok(None);
        };
        let binding = *binding;
        if self.blocked
            || self.blocked_cells.contains(&location)
            || self.blocked_bindings.contains(&binding)
            || !semantics
                .value(binding)
                .is_some_and(|value| value.kind == SemanticValueKind::Local)
        {
            return Ok(None);
        }
        let complete = |row: &PrivateCellEvent| {
            semantics
                .point(row.point)
                .and_then(|point| point.events.get(row.index))
                .and_then(|event| semantics.evidence_row(event.evidence))
                .is_some_and(|evidence| {
                    evidence
                        .proof
                        .establishes_complete_evidence(&evidence.completeness)
                })
        };
        for row in self.definitions.get(&binding).into_iter().flatten() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });
            if !complete(row) {
                return Ok(None);
            }
            let assignments = self
                .assignments
                .get(&(row.point, binding))
                .map_or(&[][..], Vec::as_slice);
            let next_assignment = assignments.partition_point(|next| {
                staged.charge_work(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                });
                next.index <= row.index
            });
            let loads = self
                .loads
                .get(&(row.point, location))
                .map_or(&[][..], Vec::as_slice);
            let next_load = loads.partition_point(|index| {
                staged.charge_work(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                });
                *index <= row.index
            });
            let stop = assignments
                .get(next_assignment)
                .map_or(usize::MAX, |next| next.index)
                .min(loads.get(next_load).copied().unwrap_or(usize::MAX));
            let paired = [row.value, binding].into_iter().any(|value| {
                let stores = self
                    .stored_values
                    .get(&(row.point, location, value))
                    .map_or(&[][..], Vec::as_slice);
                let next = stores.partition_point(|index| {
                    staged.charge_work(SemanticWork {
                        events: 1,
                        ..SemanticWork::default()
                    });
                    *index <= row.index
                });
                stores.get(next).is_some_and(|index| *index < stop)
            });
            if !paired {
                return Ok(None);
            }
        }
        for row in self.stores.get(&location).into_iter().flatten() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });
            if !complete(row) {
                return Ok(None);
            }
            let assignments = self
                .assignments
                .get(&(row.point, binding))
                .map_or(&[][..], Vec::as_slice);
            let previous = assignments.partition_point(|previous| {
                staged.charge_work(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                });
                previous.index < row.index
            });
            let Some(assignment) = previous
                .checked_sub(1)
                .and_then(|index| assignments.get(index))
            else {
                return Ok(None);
            };
            let loads = self
                .loads
                .get(&(row.point, location))
                .map_or(&[][..], Vec::as_slice);
            let previous_load = loads.partition_point(|index| {
                staged.charge_work(SemanticWork {
                    events: 1,
                    ..SemanticWork::default()
                });
                *index < row.index
            });
            if previous_load
                .checked_sub(1)
                .and_then(|index| loads.get(index))
                .is_some_and(|index| *index > assignment.index)
                || (row.value != assignment.value && row.value != binding)
            {
                return Ok(None);
            }
        }
        for call_id in self.calls.get(&location).into_iter().flatten() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled.into());
            }
            staged.charge_work(SemanticWork {
                call_sites: 1,
                ..SemanticWork::default()
            });
            let handle = procedure
                .call_site_handle(*call_id)
                .expect("an indexed private-cell call exists");
            let dispatch = oracle
                .resolve_call(&handle, &mut staged.request(cancellation))
                .map_err(InterruptionOrProvider::Provider)?;
            staged.work = staged.work.conservative_add(dispatch.work());
            if let Some(stop) = outcome_interruption(&dispatch) {
                return Err(InterruptionOrProvider::Interruption(stop));
            }
            if dispatch
                .available_value()
                .and_then(|value| value.member_receiver_preparation())
                != Some(crate::analyzer::semantic::MemberReceiverPreparation::Reference)
            {
                return Ok(None);
            }
        }
        Ok(Some(binding))
    }
}

/// Reuse procedure facts while preserving the existing unfinished-property
/// recursion guard for each query-time dispatch refinement.
pub(super) fn mirrored_private_cell_binding(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    location: MemoryLocationId,
    prepared: &mut Option<PrivateCellFacts>,
    staged: &mut WorkStager,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<Option<ValueId>, InterruptionOrProvider> {
    let Some(_active) =
        crate::analyzer::semantic::property_reaching::ActivePropertyProcedure::enter(procedure)
    else {
        return Ok(None);
    };
    // A field or index publication is not a private local-cell query. Keep
    // this rejection cheap instead of constructing unused procedure indexes.
    let semantics = procedure.semantics();
    let Some(MemoryLocationKind::LexicalCell { binding }) =
        semantics.memory_location(location).map(|row| &row.kind)
    else {
        return Ok(None);
    };
    if !semantics
        .value(*binding)
        .is_some_and(|value| value.kind == SemanticValueKind::Local)
    {
        return Ok(None);
    }
    if prepared.is_none() {
        *prepared = Some(PrivateCellFacts::derive(
            oracle,
            procedure,
            staged,
            cancellation,
        )?);
    }
    let facts = prepared.as_ref().expect("private-cell facts were prepared");
    debug_assert_eq!(&facts.procedure, procedure);
    facts.binding(oracle, location, staged, cancellation)
}

#[cfg(test)]
mod resident_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11547: private-cell indexes escaped resident admission and peak accounting")]
    fn private_cell_rows_live_with_query_and_refuse_existing_limit() {
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut limits = crate::analyzer::semantic::SemanticBudget::default().limits();
        limits.nested_entries = 20;
        let mut budget = crate::analyzer::semantic::SemanticBudget::new(limits).unwrap();
        let mut staged = WorkStager::new(&SemanticRequest::new(&mut budget, &cancellation));
        let owner = retain_index_rows(&mut staged, 17).unwrap_or_else(|_| panic!("index fits"));
        assert_eq!(staged.budget.resident().nested_entries, 17);
        assert_eq!(staged.budget.resident_peak().nested_entries, 17);
        assert!(matches!(
            retain_index_rows(&mut staged, 4),
            Err(InterruptionOrProvider::Interruption(Interruption::Budget(
                _
            )))
        ));
        assert_eq!(staged.budget.resident().nested_entries, 17);
        drop(owner);
        assert_eq!(staged.budget.resident().nested_entries, 0);
        assert_eq!(staged.budget.resident_peak().nested_entries, 17);
        let again = retain_index_rows(&mut staged, 20)
            .unwrap_or_else(|_| panic!("released room can be reused"));
        assert_eq!(staged.budget.resident().nested_entries, 20);
        drop(again);
        assert_eq!(staged.budget.resident().nested_entries, 0);
    }
}
