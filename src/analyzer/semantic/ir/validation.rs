use crate::hash::{HashMap, HashSet};

use super::super::capabilities::{CapabilitySupport, SemanticCapabilities, SemanticCapability};
use super::super::ids::{
    AllocationId, BlockId, CallSiteId, CaptureId, DeclarationSegmentKind, EvidenceId,
    MemoryLocationId, ProcedureId, ProgramPointId, SemanticArtifactKey, SemanticGapId,
    SemanticLocator, SemanticRole, SourceMappingId, ValueId,
};
use super::super::provider::SemanticWork;
use super::model::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct Boundaries {
    pub(super) entry: ProgramPointId,
    pub(super) normal_exit: ProgramPointId,
    pub(super) exceptional_exit: ProgramPointId,
}

#[derive(Default)]
struct ControlEdgeIndex {
    exact: HashSet<(
        ProgramPointId,
        ProgramPointId,
        ControlEdgeKind,
        SourceMappingId,
        EvidenceId,
    )>,
    topology: HashSet<(ProgramPointId, ProgramPointId, ControlEdgeKind)>,
    outgoing_by_kind: HashMap<(ProgramPointId, ControlEdgeKind), usize>,
    outgoing_total: HashMap<ProgramPointId, usize>,
}

impl ControlEdgeIndex {
    fn insert(&mut self, edge: &ControlEdge) -> bool {
        if !self.exact.insert((
            edge.source_point,
            edge.target_point,
            edge.kind,
            edge.source,
            edge.evidence,
        )) {
            return false;
        }
        let topology_inserted =
            self.topology
                .insert((edge.source_point, edge.target_point, edge.kind));
        if topology_inserted {
            *self
                .outgoing_by_kind
                .entry((edge.source_point, edge.kind))
                .or_default() += 1;
            *self.outgoing_total.entry(edge.source_point).or_default() += 1;
        }
        true
    }

    fn contains(
        &self,
        source: ProgramPointId,
        target: ProgramPointId,
        kind: ControlEdgeKind,
    ) -> bool {
        self.topology.contains(&(source, target, kind))
    }

    fn outgoing_count(&self, source: ProgramPointId, kind: ControlEdgeKind) -> usize {
        self.outgoing_by_kind
            .get(&(source, kind))
            .copied()
            .unwrap_or_default()
    }

    fn total_outgoing_count(&self, source: ProgramPointId) -> usize {
        self.outgoing_total
            .get(&source)
            .copied()
            .unwrap_or_default()
    }
}

type CaptureDestinationIndex = HashSet<(ProcedureId, MemoryLocationId)>;
type ProcedureLocatorIndex = HashMap<SemanticLocator, ProcedureId>;
type AsyncSuspendIndex = HashMap<ProgramPointId, (ControlContinuation, ControlContinuation)>;

#[derive(Default)]
struct GapIndex {
    facts: HashMap<(ProgramPointId, SemanticGapSubject, SemanticCapability), SemanticGapKind>,
    subjects: HashSet<(SemanticGapSubject, SemanticCapability)>,
}

impl GapIndex {
    fn insert(&mut self, procedure: ProcedureId, gap: &SemanticGap) -> Result<(), SemanticIrError> {
        let fact = (gap.point, gap.subject, gap.capability);
        if let Some(previous) = self.facts.insert(fact, gap.kind) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::GapContract,
                format!(
                    "gap {} duplicates the same scoped fact with {} and {} outcomes",
                    gap.id,
                    previous.label(),
                    gap.kind.label()
                ),
            ));
        }
        self.subjects.insert((gap.subject, gap.capability));
        Ok(())
    }

    fn fact_kind(
        &self,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
    ) -> Option<SemanticGapKind> {
        self.facts.get(&(point, subject, capability)).copied()
    }

    fn has_subject(&self, subject: SemanticGapSubject, capability: SemanticCapability) -> bool {
        self.subjects.contains(&(subject, capability))
    }
}

pub(super) fn measure_artifact_work(
    key: &SemanticArtifactKey,
    procedures: &[ProcedureSemanticsParts],
) -> SemanticWork {
    let mut work = SemanticWork {
        procedures: procedures.len(),
        owned_text_bytes: key
            .path()
            .as_str()
            .len()
            .saturating_add(key.adapter().name().len()),
        ..SemanticWork::default()
    };

    for procedure in procedures {
        work.values = work.values.saturating_add(procedure.values.len());
        work.allocations = work.allocations.saturating_add(procedure.allocations.len());
        work.memory_locations = work
            .memory_locations
            .saturating_add(procedure.memory_locations.len());
        work.captures = work.captures.saturating_add(procedure.captures.len());
        work.call_sites = work.call_sites.saturating_add(procedure.call_sites.len());
        work.source_mappings = work
            .source_mappings
            .saturating_add(procedure.source_mappings.len());
        work.evidence = work.evidence.saturating_add(procedure.evidence_rows.len());
        work.gaps = work.gaps.saturating_add(procedure.gaps.len());
        work.blocks = work.blocks.saturating_add(procedure.blocks.len());
        work.program_points = work.program_points.saturating_add(procedure.points.len());
        work.control_edges = work
            .control_edges
            .saturating_add(procedure.control_edges.len());
        // The frozen CFG retains two point-indexed offset arrays plus one
        // incoming procedure-local edge ID per canonical rich edge.
        let adjacency_entries = procedure
            .points
            .len()
            .saturating_add(1)
            .saturating_mul(2)
            .saturating_add(procedure.control_edges.len());
        work.nested_entries = work.nested_entries.saturating_add(adjacency_entries);

        // The locator is retained once on the procedure and once as the key
        // in the artifact's locator index.
        account_locator(&procedure.locator, &mut work);
        account_locator(&procedure.locator, &mut work);

        for value in &procedure.values {
            match &value.kind {
                SemanticValueKind::LanguageDefined(name) => account_text(name, &mut work),
                SemanticValueKind::Parameter {
                    multiplicity: FormalMultiplicity::Rest(ArgumentDomain::LanguageDefined(name)),
                    ..
                } => account_text(name, &mut work),
                SemanticValueKind::Local
                | SemanticValueKind::Parameter { .. }
                | SemanticValueKind::Receiver
                | SemanticValueKind::Return
                | SemanticValueKind::Temporary
                | SemanticValueKind::Constant
                | SemanticValueKind::Exception
                | SemanticValueKind::Callable
                | SemanticValueKind::AwaitResult => {}
            }
        }
        for allocation in &procedure.allocations {
            if let AllocationKind::LanguageDefined(name) = &allocation.kind {
                account_text(name, &mut work);
            }
        }
        for location in &procedure.memory_locations {
            match &location.kind {
                MemoryLocationKind::Field { member, .. }
                | MemoryLocationKind::Static { member } => account_locator(member, &mut work),
                MemoryLocationKind::Index { .. }
                | MemoryLocationKind::LexicalCell { .. }
                | MemoryLocationKind::Capture { .. } => {}
            }
        }
        for capture in &procedure.captures {
            if let CaptureMode::LanguageDefined(name) = &capture.mode {
                account_text(name, &mut work);
            }
        }
        for call_site in &procedure.call_sites {
            work.nested_entries = work
                .nested_entries
                .saturating_add(call_site.arguments.len());
            for argument in &call_site.arguments {
                if let Some(ArgumentDomain::LanguageDefined(name)) = argument.expansion.domain() {
                    account_text(name, &mut work);
                }
            }
            account_target_resolution(&call_site.declared_targets, &mut work);
        }
        for mapping in &procedure.source_mappings {
            account_locator(&mapping.locator, &mut work);
        }
        for evidence in &procedure.evidence_rows {
            work.nested_entries = work.nested_entries.saturating_add(evidence.sources.len());
            if let ProofStatus::Unproven(detail) = &evidence.proof {
                account_text(detail, &mut work);
            }
            if let EvidenceCompleteness::Partial(detail) = &evidence.completeness {
                account_text(detail, &mut work);
            }
        }
        for gap in &procedure.gaps {
            account_text(&gap.detail, &mut work);
        }
        for block in &procedure.blocks {
            work.nested_entries = work.nested_entries.saturating_add(block.points.len());
        }
        for point in &procedure.points {
            work.events = work.events.saturating_add(point.events.len());
            for event in &point.events {
                match &event.effect {
                    SemanticEffect::CallableCreation { callable, .. }
                    | SemanticEffect::CallableReference { callable, .. } => {
                        account_target_resolution(&callable.targets, &mut work);
                    }
                    SemanticEffect::Entry
                    | SemanticEffect::NormalExit
                    | SemanticEffect::ExceptionalExit
                    | SemanticEffect::Assignment { .. }
                    | SemanticEffect::ValueFlow { .. }
                    | SemanticEffect::Allocation { .. }
                    | SemanticEffect::MemoryLoad { .. }
                    | SemanticEffect::MemoryStore { .. }
                    | SemanticEffect::CaptureBind { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::ProcedureReturn { .. }
                    | SemanticEffect::Throw { .. }
                    | SemanticEffect::AsyncSuspend { .. }
                    | SemanticEffect::AsyncResume { .. }
                    | SemanticEffect::Gap { .. } => {}
                }
            }
        }
    }
    work
}

fn account_target_resolution(resolution: &CallableTargetResolution, work: &mut SemanticWork) {
    work.nested_entries = work
        .nested_entries
        .saturating_add(resolution.candidates().len());
    for target in resolution.candidates() {
        match target {
            CallableTarget::Local(_) => {}
            CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                account_locator(locator, work);
            }
        }
    }
}

fn account_locator(locator: &SemanticLocator, work: &mut SemanticWork) {
    account_text(locator.path().as_str(), work);
    work.nested_entries = work
        .nested_entries
        .saturating_add(locator.declaration().segments().len());
    for segment in locator.declaration().segments() {
        if let Some(name) = segment.name() {
            account_text(name, work);
        }
    }
}

fn account_text(text: &str, work: &mut SemanticWork) {
    work.owned_text_bytes = work.owned_text_bytes.saturating_add(text.len());
}

pub(super) fn validate_artifact(
    key: &SemanticArtifactKey,
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
) -> Result<(), SemanticIrError> {
    if key.language().language() == crate::analyzer::Language::None {
        return Err(SemanticIrError::artifact(
            SemanticIrErrorKind::ArtifactIdentity,
            "semantic artifact language must be analyzable",
        ));
    }
    if !procedures.is_empty() {
        for capability in [
            SemanticCapability::Procedures,
            SemanticCapability::EntryBoundary,
            SemanticCapability::NormalExitBoundary,
            SemanticCapability::ExceptionalExitBoundary,
            SemanticCapability::BasicBlocks,
            SemanticCapability::ProgramPoints,
        ] {
            require_artifact_capability(capabilities, capability, "procedure core")?;
        }
    }
    let mut locators = HashMap::default();
    for (index, procedure) in procedures.iter().enumerate() {
        if procedure.id.index() != index {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::DenseId,
                format!(
                    "procedures row {index} carries id {}; expected {index}",
                    procedure.id
                ),
            ));
        }
        validate_locator_scope(key, procedure.id, "procedure locator", &procedure.locator)?;
        if procedure.locator.role() != SemanticRole::Procedure {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::LocatorRole,
                format!(
                    "procedure locator has role {}, expected {}",
                    procedure.locator.role().stable_label(),
                    SemanticRole::Procedure.stable_label()
                ),
            ));
        }
        if let Some(first) = locators.insert(procedure.locator.clone(), procedure.id) {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::DuplicateLocator,
                format!("procedure locator is already owned by procedure {first}"),
            ));
        }
        if let Some(parent) = procedure.lexical_parent {
            ensure_index(
                procedure.id,
                "lexical parent",
                parent.index(),
                procedures.len(),
            )?;
            if parent == procedure.id {
                return Err(SemanticIrError::procedure(
                    procedure.id,
                    SemanticIrErrorKind::ParentCycle,
                    "procedure cannot be its own lexical parent",
                ));
            }
        }
    }

    validate_parent_forest(procedures)?;
    let capture_destinations = procedures
        .iter()
        .flat_map(|procedure| {
            procedure
                .captures
                .iter()
                .map(|capture| (capture.target, capture.destination))
        })
        .collect();
    for procedure in procedures {
        validate_procedure(
            key,
            capabilities,
            procedures,
            &locators,
            procedure,
            &capture_destinations,
        )?;
    }
    Ok(())
}

fn validate_locator_scope(
    key: &SemanticArtifactKey,
    procedure: ProcedureId,
    context: &str,
    locator: &SemanticLocator,
) -> Result<(), SemanticIrError> {
    if locator.mount() != key.mount()
        || locator.path() != key.path()
        || locator.language() != key.language()
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::SourceScope,
            format!(
                "{context} belongs to mount/path/language outside artifact {}/{} ({})",
                key.mount(),
                key.path(),
                key.language()
            ),
        ));
    }
    Ok(())
}

/// Validate a single-parent forest without recursive stack growth.
fn validate_parent_forest(procedures: &[ProcedureSemanticsParts]) -> Result<(), SemanticIrError> {
    // 0 = unseen, 1 = on the current iterative path, 2 = complete.
    let mut state = vec![0_u8; procedures.len()];
    for start in 0..procedures.len() {
        if state[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            match state[index] {
                0 => {
                    state[index] = 1;
                    path.push(index);
                    cursor = procedures[index].lexical_parent.map(ProcedureId::index);
                }
                1 => {
                    return Err(SemanticIrError::procedure(
                        procedures[index].id,
                        SemanticIrErrorKind::ParentCycle,
                        "lexical-parent relation contains a cycle",
                    ));
                }
                2 => break,
                _ => unreachable!("parent validation state is internal"),
            }
        }
        for index in path {
            state[index] = 2;
        }
    }
    Ok(())
}

fn validate_procedure(
    key: &SemanticArtifactKey,
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    capture_destinations: &CaptureDestinationIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;

    validate_dense_rows(procedure)?;
    for mapping in &procedure.source_mappings {
        validate_locator_scope(key, id, "source mapping", &mapping.locator)?;
    }

    ensure_source(
        id,
        procedure.source,
        procedure.source_mappings.len(),
        "procedure",
    )?;
    ensure_evidence(
        id,
        procedure.evidence,
        procedure.evidence_rows.len(),
        "procedure",
    )?;

    for evidence in &procedure.evidence_rows {
        if evidence.sources.is_empty() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::OutOfBounds,
                format!("evidence {} has no source mapping", evidence.id),
            ));
        }
        for source in &evidence.sources {
            ensure_source(
                id,
                *source,
                procedure.source_mappings.len(),
                "evidence source",
            )?;
        }
        if matches!(&evidence.proof, ProofStatus::Unproven(reason) if reason.is_empty()) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("evidence {} has an empty unproven reason", evidence.id),
            ));
        }
        if matches!(
            &evidence.completeness,
            EvidenceCompleteness::Partial(reason) if reason.is_empty()
        ) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("evidence {} has an empty partial reason", evidence.id),
            ));
        }
    }

    let async_suspends = index_async_suspends(procedure)?;
    let mut gap_index = GapIndex::default();
    for gap in &procedure.gaps {
        ensure_point(id, gap.point, procedure.points.len(), "gap point")?;
        validate_metadata(id, gap.source, gap.evidence, procedure, "gap")?;
        if gap.detail.is_empty() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("gap {} has no diagnostic detail", gap.id),
            ));
        }
        if gap.kind == SemanticGapKind::Unproven
            && !matches!(
                procedure.evidence_rows[gap.evidence.index()].proof,
                ProofStatus::Unproven(_)
            )
        {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!("unproven gap {} cites proven evidence", gap.id),
            ));
        }
        validate_gap_capability(id, capabilities, gap)?;
        validate_gap_subject(id, procedure, &async_suspends, gap)?;
        validate_gap_impacts(id, gap)?;
        if (gap.kind == SemanticGapKind::ExceededBudget) != gap.budget.is_some() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::GapContract,
                format!(
                    "gap {} must carry structured budget data exactly for an exceeded-budget outcome",
                    gap.id
                ),
            ));
        }
        gap_index.insert(id, gap)?;
    }

    let mut parameter_ordinals = HashSet::default();
    for value in &procedure.values {
        validate_metadata(id, value.source, value.evidence, procedure, "value")?;
        if let SemanticValueKind::Parameter { ordinal, .. } = &value.kind
            && !parameter_ordinals.insert(*ordinal)
        {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallContract,
                format!("parameter ordinal {ordinal} is published more than once"),
            ));
        }
    }
    if !procedure.values.is_empty() {
        require_capability(id, capabilities, SemanticCapability::Values, "value rows")?;
    }

    for allocation in &procedure.allocations {
        ensure_point(
            id,
            allocation.point,
            procedure.points.len(),
            "allocation point",
        )?;
        ensure_value(
            id,
            allocation.result,
            procedure.values.len(),
            "allocation result",
        )?;
        validate_metadata(
            id,
            allocation.source,
            allocation.evidence,
            procedure,
            "allocation",
        )?;
    }
    if !procedure.allocations.is_empty() {
        require_capability(
            id,
            capabilities,
            SemanticCapability::Allocations,
            "allocation rows",
        )?;
    }

    for location in &procedure.memory_locations {
        validate_memory_location(
            procedures,
            procedure,
            location,
            capture_destinations,
            &gap_index,
        )?;
        require_capability(
            id,
            capabilities,
            memory_location_capability(&location.kind),
            "memory-location row",
        )?;
        validate_metadata(
            id,
            location.source,
            location.evidence,
            procedure,
            "memory location",
        )?;
    }

    for capture in &procedure.captures {
        validate_capture_row(procedures, procedure, capture, &gap_index)?;
        validate_metadata(id, capture.source, capture.evidence, procedure, "capture")?;
    }
    if !procedure.captures.is_empty() {
        require_capability(
            id,
            capabilities,
            SemanticCapability::Captures,
            "capture rows",
        )?;
    }
    validate_capture_consistency(procedure)?;

    for call_site in &procedure.call_sites {
        validate_metadata(
            id,
            call_site.source,
            call_site.evidence,
            procedure,
            "call site",
        )?;
        validate_call_site(procedures, procedure_locators, procedure, call_site)?;
    }
    if !procedure.call_sites.is_empty() {
        require_capability(
            id,
            capabilities,
            SemanticCapability::Calls,
            "call-site rows",
        )?;
    }

    validate_blocks(procedure)?;
    let control_edges = validate_control_edges(capabilities, procedure)?;
    validate_events(
        capabilities,
        procedures,
        procedure_locators,
        procedure,
        &gap_index,
        &control_edges,
    )?;
    find_boundaries(procedure)?;
    Ok(())
}

fn validate_dense_rows(procedure: &ProcedureSemanticsParts) -> Result<(), SemanticIrError> {
    macro_rules! dense {
        ($rows:expr, $table:literal) => {
            for (expected, row) in $rows.iter().enumerate() {
                if row.id.index() != expected {
                    return Err(SemanticIrError::procedure(
                        procedure.id,
                        SemanticIrErrorKind::DenseId,
                        format!(
                            "{} row {expected} carries id {}; expected {expected}",
                            $table, row.id
                        ),
                    ));
                }
            }
        };
    }

    dense!(procedure.values, "values");
    dense!(procedure.allocations, "allocations");
    dense!(procedure.memory_locations, "memory_locations");
    dense!(procedure.captures, "captures");
    dense!(procedure.call_sites, "call_sites");
    dense!(procedure.source_mappings, "source_mappings");
    dense!(procedure.evidence_rows, "evidence");
    dense!(procedure.gaps, "gaps");
    dense!(procedure.blocks, "blocks");
    dense!(procedure.points, "points");
    Ok(())
}

fn validate_memory_location(
    procedures: &[ProcedureSemanticsParts],
    procedure: &ProcedureSemanticsParts,
    location: &MemoryLocation,
    capture_destinations: &CaptureDestinationIndex,
    gaps: &GapIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    match &location.kind {
        MemoryLocationKind::Field { base, member } => {
            ensure_value(id, *base, procedure.values.len(), "field base")?;
            validate_memory_member_locator(id, member, "field member")?;
        }
        MemoryLocationKind::Static { member } => {
            validate_memory_member_locator(id, member, "static member")?;
        }
        MemoryLocationKind::Index { base, index } => {
            ensure_value(id, *base, procedure.values.len(), "indexed base")?;
            if let Some(index) = index {
                ensure_value(id, *index, procedure.values.len(), "index value")?;
            }
        }
        MemoryLocationKind::LexicalCell { binding } => {
            ensure_value(id, *binding, procedure.values.len(), "lexical-cell binding")?;
        }
        MemoryLocationKind::Capture { lexical_parent } => {
            ensure_index(
                id,
                "capture-slot lexical parent",
                lexical_parent.index(),
                procedures.len(),
            )?;
            if procedure.lexical_parent != Some(*lexical_parent) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture location {} names procedure {} as lexical parent, but procedure {} has parent {:?}",
                        location.id, lexical_parent, id, procedure.lexical_parent
                    ),
                ));
            }
            let has_binding = capture_destinations.contains(&(id, location.id));
            let has_gap = gaps.has_subject(
                SemanticGapSubject::MemoryLocation(location.id),
                SemanticCapability::Captures,
            );
            if !has_binding && !has_gap {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture location {} has no lexical-parent binding or explicit capture gap",
                        location.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn index_async_suspends(
    procedure: &ProcedureSemanticsParts,
) -> Result<AsyncSuspendIndex, SemanticIrError> {
    let mut suspends = AsyncSuspendIndex::default();
    for point in &procedure.points {
        for event in &point.events {
            if let SemanticEffect::AsyncSuspend {
                normal_resume,
                exceptional_resume,
                ..
            } = event.effect
                && suspends
                    .insert(point.id, (normal_resume, exceptional_resume))
                    .is_some()
            {
                return Err(SemanticIrError::procedure(
                    procedure.id,
                    SemanticIrErrorKind::AsyncContract,
                    format!("point {} contains more than one async suspend", point.id),
                ));
            }
        }
    }
    Ok(suspends)
}

fn validate_gap_subject(
    procedure_id: ProcedureId,
    procedure: &ProcedureSemanticsParts,
    async_suspends: &AsyncSuspendIndex,
    gap: &SemanticGap,
) -> Result<(), SemanticIrError> {
    match gap.subject {
        SemanticGapSubject::Procedure | SemanticGapSubject::Point => {}
        SemanticGapSubject::Value(value) => {
            ensure_value(
                procedure_id,
                value,
                procedure.values.len(),
                "gap subject value",
            )?;
        }
        SemanticGapSubject::MemoryLocation(location) => {
            ensure_location(
                procedure_id,
                location,
                procedure.memory_locations.len(),
                "gap subject memory location",
            )?;
        }
        SemanticGapSubject::Capture(capture) => {
            ensure_capture(
                procedure_id,
                capture,
                procedure.captures.len(),
                "gap subject capture",
            )?;
            if procedure.captures[capture.index()].point != gap.point
                || gap.capability != SemanticCapability::Captures
            {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} capture subject must use the binding point and captures capability",
                        gap.id
                    ),
                ));
            }
            let expected = (procedure.captures[capture.index()].mode == CaptureMode::Unknown)
                .then_some(SemanticGapKind::Unknown);
            if expected != Some(gap.kind) {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts capture {} mode {}",
                        gap.id,
                        gap.kind.label(),
                        capture,
                        procedure.captures[capture.index()].mode.label()
                    ),
                ));
            }
        }
        SemanticGapSubject::CallSite(call_site) => {
            ensure_call_site(
                procedure_id,
                call_site,
                procedure.call_sites.len(),
                "gap subject call site",
            )?;
            if procedure.call_sites[call_site.index()].point != gap.point {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} point {} differs from subject call site {} point {}",
                        gap.id,
                        gap.point,
                        call_site,
                        procedure.call_sites[call_site.index()].point
                    ),
                ));
            }
            if gap.capability == SemanticCapability::Calls
                && required_gap_kind(&procedure.call_sites[call_site.index()].declared_targets)
                    != Some(gap.kind)
            {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts call site {} target outcome {}",
                        gap.id,
                        gap.kind.label(),
                        call_site,
                        procedure.call_sites[call_site.index()]
                            .declared_targets
                            .label()
                    ),
                ));
            }
        }
        SemanticGapSubject::CallContinuation { call_site, kind } => {
            ensure_call_site(
                procedure_id,
                call_site,
                procedure.call_sites.len(),
                "gap subject call continuation",
            )?;
            if procedure.call_sites[call_site.index()].point != gap.point {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} point {} differs from subject call site {} point {}",
                        gap.id,
                        gap.point,
                        call_site,
                        procedure.call_sites[call_site.index()].point
                    ),
                ));
            }
            let expected = match kind {
                CallContinuationKind::Normal => SemanticCapability::NormalCallContinuation,
                CallContinuationKind::Exceptional => {
                    SemanticCapability::ExceptionalCallContinuation
                }
            };
            if gap.capability != expected {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} subject {} requires capability {}, found {}",
                        gap.id,
                        kind.label(),
                        expected.label(),
                        gap.capability.label()
                    ),
                ));
            }
            let continuation = match kind {
                CallContinuationKind::Normal => {
                    procedure.call_sites[call_site.index()].normal_continuation
                }
                CallContinuationKind::Exceptional => {
                    procedure.call_sites[call_site.index()].exceptional_continuation
                }
            };
            if continuation_gap_kind(continuation) != Some(gap.kind) {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts call {} {} continuation outcome {}",
                        gap.id,
                        gap.kind.label(),
                        call_site,
                        kind.label(),
                        continuation.label()
                    ),
                ));
            }
        }
        SemanticGapSubject::AsyncContinuation { suspend, kind } => {
            ensure_point(
                procedure_id,
                suspend,
                procedure.points.len(),
                "gap subject async suspend",
            )?;
            if gap.point != suspend || gap.capability != SemanticCapability::AsyncSuspendResume {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} async-continuation subject must use its suspend point and async capability",
                        gap.id
                    ),
                ));
            }
            let Some((normal, exceptional)) = async_suspends.get(&suspend) else {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} names point {} as an async continuation source, but it has no async suspend",
                        gap.id, suspend
                    ),
                ));
            };
            let continuation = match kind {
                AsyncResumeKind::Normal => *normal,
                AsyncResumeKind::Exceptional => *exceptional,
            };
            if continuation_gap_kind(continuation) != Some(gap.kind) {
                return Err(SemanticIrError::procedure(
                    procedure_id,
                    SemanticIrErrorKind::GapContract,
                    format!(
                        "gap {} outcome {} contradicts suspend {} {} continuation outcome {}",
                        gap.id,
                        gap.kind.label(),
                        suspend,
                        kind.label(),
                        continuation.label()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_capture_consistency(
    procedure: &ProcedureSemanticsParts,
) -> Result<(), SemanticIrError> {
    let mut static_bindings = HashSet::default();
    let mut slot_modes = HashMap::default();
    for capture in &procedure.captures {
        let static_key = (
            capture.point,
            capture.callable,
            capture.environment,
            capture.target,
            capture.destination,
        );
        if !static_bindings.insert(static_key) {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "capture {} duplicates a binding at point {} for callable {}, environment {}, and procedure {} location {}",
                    capture.id,
                    capture.point,
                    capture.callable,
                    capture.environment,
                    capture.target,
                    capture.destination
                ),
            ));
        }

        let slot = (capture.target, capture.destination);
        if let Some(previous) = slot_modes.insert(slot, capture.mode.clone())
            && previous != capture.mode
        {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "procedure {} capture slot {} has contradictory {} and {} modes",
                    capture.target,
                    capture.destination,
                    previous.label(),
                    capture.mode.label()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_capture_row(
    procedures: &[ProcedureSemanticsParts],
    procedure: &ProcedureSemanticsParts,
    capture: &CaptureBinding,
    gaps: &GapIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    ensure_point(id, capture.point, procedure.points.len(), "capture point")?;
    ensure_value(
        id,
        capture.callable,
        procedure.values.len(),
        "capturing callable",
    )?;
    ensure_index(
        id,
        "capture target procedure",
        capture.target.index(),
        procedures.len(),
    )?;
    if procedures[capture.target.index()].lexical_parent != Some(id) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CaptureContract,
            format!(
                "capture {} targets procedure {}, which is not a lexical child",
                capture.id, capture.target
            ),
        ));
    }
    ensure_allocation(
        id,
        capture.environment,
        procedure.allocations.len(),
        "capture environment",
    )?;
    let target = &procedures[capture.target.index()];
    if capture.destination.index() >= target.memory_locations.len() {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CaptureContract,
            format!(
                "capture {} destination {} is outside target procedure {} memory-location table of length {}; creator-local locations cannot be used here",
                capture.id,
                capture.destination,
                capture.target,
                target.memory_locations.len()
            ),
        ));
    }
    match capture.captured {
        CaptureSource::Value(value) => {
            ensure_value(id, value, procedure.values.len(), "captured value")?;
            if matches!(
                &capture.mode,
                CaptureMode::SharedCell | CaptureMode::MutableCell
            ) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture {} uses {} mode with a value source; cell modes require a location",
                        capture.id,
                        capture.mode.label()
                    ),
                ));
            }
            if capture.mode == CaptureMode::Receiver
                && !matches!(
                    procedure.values[value.index()].kind,
                    SemanticValueKind::Receiver
                )
            {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture {} uses receiver mode with non-receiver value {}",
                        capture.id, value
                    ),
                ));
            }
        }
        CaptureSource::Location(location) => {
            ensure_location(
                id,
                location,
                procedure.memory_locations.len(),
                "captured location",
            )?;
            if matches!(
                &capture.mode,
                CaptureMode::Value | CaptureMode::Move | CaptureMode::Receiver
            ) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CaptureContract,
                    format!(
                        "capture {} uses {} mode with a location source; snapshot, move, and receiver modes require a value",
                        capture.id,
                        capture.mode.label()
                    ),
                ));
            }
        }
    }
    if matches!(&capture.mode, CaptureMode::LanguageDefined(name) if name.is_empty()) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CaptureContract,
            format!("capture {} has an empty language-defined mode", capture.id),
        ));
    }
    if capture.mode == CaptureMode::Unknown
        && gaps.fact_kind(
            capture.point,
            SemanticGapSubject::Capture(capture.id),
            SemanticCapability::Captures,
        ) != Some(SemanticGapKind::Unknown)
    {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::GapContract,
            format!(
                "capture {} has unknown mode without a subject-specific capture gap",
                capture.id
            ),
        ));
    }
    match &target.memory_locations[capture.destination.index()].kind {
        MemoryLocationKind::Capture { lexical_parent } if *lexical_parent == id => {}
        _ => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "capture {} destination {} in procedure {} is not a capture slot for lexical parent {}",
                    capture.id, capture.destination, capture.target, id
                ),
            ));
        }
    }
    Ok(())
}

fn validate_call_site(
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    call_site: &SemanticCallSite,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    ensure_point(id, call_site.point, procedure.points.len(), "call point")?;
    ensure_value(id, call_site.callee, procedure.values.len(), "callee")?;
    if !matches!(
        procedure.values[call_site.callee.index()].kind,
        SemanticValueKind::Callable
    ) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallableContract,
            format!(
                "call site {} callee {} is not a callable value row",
                call_site.id, call_site.callee
            ),
        ));
    }
    if let Some(receiver) = call_site.receiver {
        ensure_value(id, receiver, procedure.values.len(), "call receiver")?;
    }
    for argument in &call_site.arguments {
        ensure_value(id, argument.value, procedure.values.len(), "call argument")?;
    }
    if let Some(result) = call_site.result {
        ensure_value(id, result, procedure.values.len(), "call result")?;
    }
    if let Some(thrown) = call_site.thrown {
        ensure_value(id, thrown, procedure.values.len(), "thrown call value")?;
    }
    ensure_evidence(
        id,
        call_site.target_evidence,
        procedure.evidence_rows.len(),
        "call-site target evidence",
    )?;
    if let Some(normal) = call_site.normal_continuation.target() {
        ensure_point(
            id,
            normal,
            procedure.points.len(),
            "normal call continuation",
        )?;
    }
    if let Some(exceptional) = call_site.exceptional_continuation.target() {
        ensure_point(
            id,
            exceptional,
            procedure.points.len(),
            "exceptional call continuation",
        )?;
    }
    let normal = call_site.normal_continuation.target();
    let exceptional = call_site.exceptional_continuation.target();
    if normal == Some(call_site.point) || exceptional == Some(call_site.point) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallContract,
            format!(
                "call site {} cannot continue at its own invocation point",
                call_site.id
            ),
        ));
    }
    validate_target_resolution(
        id,
        procedures,
        procedure_locators,
        &call_site.declared_targets,
        &procedure.evidence_rows[call_site.target_evidence.index()].proof,
        "call site declared target",
    )
}

fn validate_target_resolution(
    procedure: ProcedureId,
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    resolution: &CallableTargetResolution,
    proof: &ProofStatus,
    context: &str,
) -> Result<(), SemanticIrError> {
    if let CallableTargetResolution::Ambiguous(candidates) = resolution
        && candidates.len() < 2
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::CallableContract,
            format!("{context} is ambiguous but has fewer than two candidates"),
        ));
    }

    if matches!(resolution, CallableTargetResolution::Proven(_))
        && !matches!(proof, ProofStatus::Proven)
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::CallableContract,
            format!("{context} is proven but cites unproven evidence"),
        ));
    }
    if matches!(resolution, CallableTargetResolution::Unproven(_))
        && !matches!(proof, ProofStatus::Unproven(_))
    {
        return Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::CallableContract,
            format!("{context} is unproven but cites proven evidence"),
        ));
    }

    let allows_unmaterialized = matches!(
        resolution,
        CallableTargetResolution::Unproven(_) | CallableTargetResolution::ExceededBudget(_)
    );
    let mut unique = HashSet::default();
    for target in resolution.candidates() {
        if !unique.insert(target) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::CallableContract,
                format!("{context} contains a duplicate candidate"),
            ));
        }
        match target {
            CallableTarget::Local(target) => {
                ensure_index(procedure, context, target.index(), procedures.len())?
            }
            CallableTarget::Unmaterialized(locator) => {
                validate_procedure_target_locator(procedure, procedures, locator, context)?;
                if let Some(materialized) = procedure_locators.get(locator) {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "{context} marks the locator of materialized procedure {materialized} as unmaterialized; use its local ProcedureId"
                        ),
                    ));
                }
                let owner = &procedures[procedure.index()].locator;
                if locator.mount() != owner.mount()
                    || locator.path() != owner.path()
                    || locator.language() != owner.language()
                {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!("{context} unmaterialized locator is outside the owning artifact"),
                    ));
                }
                if !allows_unmaterialized {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "{context} may use an unmaterialized locator only for an unproven or budget-exceeded outcome"
                        ),
                    ));
                }
            }
            CallableTarget::External(locator) => {
                validate_procedure_target_locator(procedure, procedures, locator, context)?;
                let owner = &procedures[procedure.index()].locator;
                if locator.mount() == owner.mount()
                    && locator.path() == owner.path()
                    && locator.language() == owner.language()
                {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "{context} uses an external locator in the owning artifact; exhaustive file procedures require a local ProcedureId"
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_procedure_target_locator(
    procedure: ProcedureId,
    procedures: &[ProcedureSemanticsParts],
    locator: &SemanticLocator,
    context: &str,
) -> Result<(), SemanticIrError> {
    if locator.role() == SemanticRole::Procedure {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::LocatorRole,
        format!(
            "{context} locator has role {}, expected procedure (owner {})",
            locator.role().stable_label(),
            procedures[procedure.index()].id
        ),
    ))
}

fn is_direct_lexical_child(parent: &SemanticLocator, child: &SemanticLocator) -> bool {
    let parent_segments = parent.declaration().segments();
    let child_segments = child.declaration().segments();
    child_segments.len() == parent_segments.len().saturating_add(1)
        && child_segments.starts_with(parent_segments)
        && child_segments.last().is_some_and(|segment| {
            matches!(
                segment.kind(),
                DeclarationSegmentKind::Function
                    | DeclarationSegmentKind::Method
                    | DeclarationSegmentKind::Constructor
                    | DeclarationSegmentKind::Initializer
                    | DeclarationSegmentKind::LocalFunction
                    | DeclarationSegmentKind::Lambda
                    | DeclarationSegmentKind::Closure
                    | DeclarationSegmentKind::AnonymousCallable
            )
        })
}

fn validate_memory_member_locator(
    procedure: ProcedureId,
    locator: &SemanticLocator,
    context: &str,
) -> Result<(), SemanticIrError> {
    if locator.role() == SemanticRole::MemoryLocation {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::LocatorRole,
        format!(
            "{context} locator has role {}, expected memory_location",
            locator.role().stable_label()
        ),
    ))
}

fn validate_blocks(procedure: &ProcedureSemanticsParts) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    let mut membership = vec![None; procedure.points.len()];
    for block in &procedure.blocks {
        validate_metadata(id, block.source, block.evidence, procedure, "block")?;
        if block.points.is_empty() {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::BlockMembership,
                format!("block {} contains no program point", block.id),
            ));
        }
        for point in &block.points {
            ensure_point(id, *point, procedure.points.len(), "block member")?;
            if let Some(previous) = membership[point.index()].replace(block.id) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::BlockMembership,
                    format!(
                        "program point {} appears in blocks {} and {}",
                        point, previous, block.id
                    ),
                ));
            }
            if procedure.points[point.index()].block != block.id {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::BlockMembership,
                    format!(
                        "block {} lists point {}, but the point names block {}",
                        block.id,
                        point,
                        procedure.points[point.index()].block
                    ),
                ));
            }
        }
    }
    for point in &procedure.points {
        ensure_block(
            id,
            point.block,
            procedure.blocks.len(),
            "program-point block",
        )?;
        if membership[point.id.index()] != Some(point.block) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::BlockMembership,
                format!("program point {} is not listed by its block", point.id),
            ));
        }
        validate_metadata(id, point.source, point.evidence, procedure, "program point")?;
    }
    Ok(())
}

fn validate_control_edges(
    capabilities: &SemanticCapabilities,
    procedure: &ProcedureSemanticsParts,
) -> Result<ControlEdgeIndex, SemanticIrError> {
    let id = procedure.id;
    let mut edges = ControlEdgeIndex::default();
    for edge in &procedure.control_edges {
        require_capability(
            id,
            capabilities,
            control_edge_capability(edge.kind),
            "control edge",
        )?;
        ensure_point(
            id,
            edge.source_point,
            procedure.points.len(),
            "control-edge source",
        )?;
        ensure_point(
            id,
            edge.target_point,
            procedure.points.len(),
            "control-edge target",
        )?;
        validate_metadata(id, edge.source, edge.evidence, procedure, "control edge")?;
        if !matches!(
            procedure.evidence_rows[edge.evidence.index()].proof,
            ProofStatus::Proven
        ) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "{} edge {} -> {} cites unproven evidence; omit the edge and emit an unproven gap instead",
                    edge.kind.label(),
                    edge.source_point,
                    edge.target_point
                ),
            ));
        }
        if !edges.insert(edge) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::DuplicateEdge,
                format!(
                    "duplicate {} edge {} -> {} with source {} and evidence {}",
                    edge.kind.label(),
                    edge.source_point,
                    edge.target_point,
                    edge.source,
                    edge.evidence,
                ),
            ));
        }
    }
    Ok(edges)
}

fn validate_events(
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    control_edges: &ControlEdgeIndex,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    let mut allocation_events = vec![0_usize; procedure.allocations.len()];
    let mut capture_events = vec![0_usize; procedure.captures.len()];
    let mut invoke_events = vec![0_usize; procedure.call_sites.len()];
    let mut continuation_events = vec![[0_usize; 2]; procedure.call_sites.len()];
    let mut gap_events = vec![0_usize; procedure.gaps.len()];
    let mut callable_creations =
        HashSet::<(ProgramPointId, ValueId, AllocationId, ProcedureId)>::default();
    let mut suspends: HashMap<ProgramPointId, (ControlContinuation, ControlContinuation)> =
        HashMap::default();
    let mut resumes: HashMap<(ProgramPointId, AsyncResumeKind), Vec<ProgramPointId>> =
        HashMap::default();

    for point in &procedure.points {
        let mut control_splits = 0_usize;
        for event in &point.events {
            validate_metadata(id, event.source, event.evidence, procedure, "event")?;
            if is_control_splitting_effect(&event.effect) {
                control_splits += 1;
                if control_splits > 1 {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "program point {} contains more than one control-splitting or terminating effect",
                            point.id
                        ),
                    ));
                }
            }
            match &event.effect {
                SemanticEffect::Entry
                | SemanticEffect::NormalExit
                | SemanticEffect::ExceptionalExit => {}
                SemanticEffect::Assignment { target, value } => {
                    ensure_value(id, *target, procedure.values.len(), "assignment target")?;
                    ensure_value(id, *value, procedure.values.len(), "assigned value")?;
                }
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } => {
                    ensure_value(id, *source, procedure.values.len(), "value-flow source")?;
                    ensure_value(id, *target, procedure.values.len(), "value-flow target")?;
                    validate_value_flow_kind(procedure, *kind, *source, *target)?;
                }
                SemanticEffect::Allocation { allocation } => {
                    ensure_allocation(
                        id,
                        *allocation,
                        procedure.allocations.len(),
                        "allocation event",
                    )?;
                    let row = &procedure.allocations[allocation.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::OutOfBounds,
                            format!(
                                "allocation {} is emitted at point {}, but its row names point {}",
                                allocation, point.id, row.point
                            ),
                        ));
                    }
                    allocation_events[allocation.index()] += 1;
                }
                SemanticEffect::MemoryLoad {
                    kind,
                    location,
                    result,
                } => {
                    ensure_location(
                        id,
                        *location,
                        procedure.memory_locations.len(),
                        "load location",
                    )?;
                    ensure_value(id, *result, procedure.values.len(), "load result")?;
                    validate_memory_access_kind(procedure, *location, *kind)?;
                }
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value,
                } => {
                    ensure_location(
                        id,
                        *location,
                        procedure.memory_locations.len(),
                        "store location",
                    )?;
                    ensure_value(id, *value, procedure.values.len(), "stored value")?;
                    validate_memory_access_kind(procedure, *location, *kind)?;
                }
                SemanticEffect::CallableCreation { result, callable } => {
                    validate_callable_value(
                        procedures,
                        procedure_locators,
                        procedure,
                        point.id,
                        *result,
                        callable,
                        gaps,
                        true,
                    )?;
                    if let Some(environment) = callable.environment {
                        for target in callable.targets.candidates() {
                            if let CallableTarget::Local(target) = target {
                                callable_creations.insert((
                                    point.id,
                                    *result,
                                    environment,
                                    *target,
                                ));
                            }
                        }
                    }
                }
                SemanticEffect::CallableReference { result, callable } => {
                    validate_callable_value(
                        procedures,
                        procedure_locators,
                        procedure,
                        point.id,
                        *result,
                        callable,
                        gaps,
                        false,
                    )?;
                }
                SemanticEffect::CaptureBind { capture } => {
                    ensure_capture(id, *capture, procedure.captures.len(), "capture event")?;
                    let row = &procedure.captures[capture.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CaptureContract,
                            format!(
                                "capture {} is bound at point {}, but its row names point {}",
                                capture, point.id, row.point
                            ),
                        ));
                    }
                    capture_events[capture.index()] += 1;
                }
                SemanticEffect::Invoke { call_site } => {
                    ensure_call_site(id, *call_site, procedure.call_sites.len(), "invoke event")?;
                    let row = &procedure.call_sites[call_site.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CallContract,
                            format!(
                                "call site {} is invoked at point {}, but its row names point {}",
                                call_site, point.id, row.point
                            ),
                        ));
                    }
                    invoke_events[call_site.index()] += 1;
                }
                SemanticEffect::CallContinuation { call_site, kind } => {
                    ensure_call_site(
                        id,
                        *call_site,
                        procedure.call_sites.len(),
                        "call continuation",
                    )?;
                    let row = &procedure.call_sites[call_site.index()];
                    let (continuation, slot) = match kind {
                        CallContinuationKind::Normal => (row.normal_continuation, 0),
                        CallContinuationKind::Exceptional => (row.exceptional_continuation, 1),
                    };
                    let Some(expected) = continuation.target() else {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CallContract,
                            format!(
                                "{} continuation event for call {} contradicts {} continuation outcome",
                                kind.label(),
                                call_site,
                                continuation.label()
                            ),
                        ));
                    };
                    if expected != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::CallContract,
                            format!(
                                "{} continuation for call {} occurs at point {}, expected {}",
                                kind.label(),
                                call_site,
                                point.id,
                                expected
                            ),
                        ));
                    }
                    continuation_events[call_site.index()][slot] += 1;
                }
                SemanticEffect::ProcedureReturn { value } => {
                    if let Some(value) = value {
                        ensure_value(id, *value, procedure.values.len(), "returned value")?;
                    }
                }
                SemanticEffect::Throw { value } => {
                    if let Some(value) = value {
                        ensure_value(id, *value, procedure.values.len(), "thrown value")?;
                    }
                }
                SemanticEffect::AsyncSuspend {
                    awaited,
                    normal_resume,
                    exceptional_resume,
                } => {
                    if let Some(awaited) = awaited {
                        ensure_value(id, *awaited, procedure.values.len(), "awaited value")?;
                    }
                    if let Some(normal) = normal_resume.target() {
                        ensure_point(id, normal, procedure.points.len(), "normal async resume")?;
                    }
                    if let Some(exceptional) = exceptional_resume.target() {
                        ensure_point(
                            id,
                            exceptional,
                            procedure.points.len(),
                            "exceptional async resume",
                        )?;
                    }
                    let normal = normal_resume.target();
                    let exceptional = exceptional_resume.target();
                    if normal == Some(point.id) || exceptional == Some(point.id) {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::AsyncContract,
                            format!("suspend point {} cannot resume at itself", point.id),
                        ));
                    }
                    if suspends
                        .insert(point.id, (*normal_resume, *exceptional_resume))
                        .is_some()
                    {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::AsyncContract,
                            format!("point {} contains more than one async suspend", point.id),
                        ));
                    }
                }
                SemanticEffect::AsyncResume {
                    suspend,
                    kind,
                    result,
                } => {
                    ensure_point(
                        id,
                        *suspend,
                        procedure.points.len(),
                        "async suspend reference",
                    )?;
                    if let Some(result) = result {
                        ensure_value(id, *result, procedure.values.len(), "async result")?;
                    }
                    resumes.entry((*suspend, *kind)).or_default().push(point.id);
                }
                SemanticEffect::Gap { gap } => {
                    ensure_gap(id, *gap, procedure.gaps.len(), "gap event")?;
                    let row = &procedure.gaps[gap.index()];
                    if row.point != point.id {
                        return Err(SemanticIrError::procedure(
                            id,
                            SemanticIrErrorKind::GapContract,
                            format!(
                                "gap {} is emitted at point {}, but its row names point {}",
                                gap, point.id, row.point
                            ),
                        ));
                    }
                    gap_events[gap.index()] += 1;
                }
            }
            for capability in effect_capabilities(&event.effect) {
                require_capability(id, capabilities, *capability, event.effect.label())?;
            }
        }
    }

    validate_exactly_once(id, "allocation", &allocation_events)?;
    validate_exactly_once(id, "capture", &capture_events)?;
    validate_exactly_once(id, "invoke", &invoke_events)?;
    validate_exactly_once(id, "gap", &gap_events)?;
    for (index, counts) in continuation_events.into_iter().enumerate() {
        let call_site = &procedure.call_sites[index];
        let expected = [
            usize::from(call_site.normal_continuation.target().is_some()),
            usize::from(call_site.exceptional_continuation.target().is_some()),
        ];
        if counts != expected {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallContract,
                format!(
                    "call site {index} continuation events do not match available arms; expected {} and {}, found {} and {}",
                    expected[0], expected[1], counts[0], counts[1]
                ),
            ));
        }
    }

    for call_site in &procedure.call_sites {
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            call_site.point,
            call_site.normal_continuation,
            SemanticGapSubject::CallContinuation {
                call_site: call_site.id,
                kind: CallContinuationKind::Normal,
            },
            SemanticCapability::NormalCallContinuation,
            ControlEdgeKind::Normal,
            "normal call continuation",
        )?;
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            call_site.point,
            call_site.exceptional_continuation,
            SemanticGapSubject::CallContinuation {
                call_site: call_site.id,
                kind: CallContinuationKind::Exceptional,
            },
            SemanticCapability::ExceptionalCallContinuation,
            ControlEdgeKind::Exceptional,
            "exceptional call continuation",
        )?;
        validate_complete_outgoing_topology(
            procedure,
            control_edges,
            call_site.point,
            usize::from(call_site.normal_continuation.target().is_some())
                + usize::from(call_site.exceptional_continuation.target().is_some()),
            "call",
        )?;
        require_resolution_gap(
            procedure,
            gaps,
            call_site.point,
            SemanticGapSubject::CallSite(call_site.id),
            SemanticCapability::Calls,
            &call_site.declared_targets,
        )?;
    }

    for capture in &procedure.captures {
        let matches_creation = callable_creations.contains(&(
            capture.point,
            capture.callable,
            capture.environment,
            capture.target,
        ));
        if !matches_creation {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CaptureContract,
                format!(
                    "capture {} has no same-point callable creation with matching body and environment",
                    capture.id
                ),
            ));
        }
    }

    validate_async_pairs(
        capabilities,
        procedure,
        gaps,
        control_edges,
        &suspends,
        &resumes,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_callable_value(
    procedures: &[ProcedureSemanticsParts],
    procedure_locators: &ProcedureLocatorIndex,
    procedure: &ProcedureSemanticsParts,
    point: ProgramPointId,
    result: ValueId,
    callable: &CallableValue,
    gaps: &GapIndex,
    creation: bool,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    ensure_value(id, result, procedure.values.len(), "callable result")?;
    if !matches!(
        procedure.values[result.index()].kind,
        SemanticValueKind::Callable
    ) {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallableContract,
            format!("callable event result {result} is not a callable value row"),
        ));
    }
    match (creation, callable.kind) {
        (
            true,
            CallableReferenceKind::BoundMethod
            | CallableReferenceKind::UnboundMethod
            | CallableReferenceKind::StaticMethod
            | CallableReferenceKind::Constructor,
        ) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "{} must be represented as a callable reference, not callable creation",
                    callable.kind.label()
                ),
            ));
        }
        (false, CallableReferenceKind::Lambda) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                "lambda evaluation must be represented as callable creation",
            ));
        }
        _ => {}
    }
    ensure_evidence(
        id,
        callable.target_evidence,
        procedure.evidence_rows.len(),
        "callable target evidence",
    )?;
    validate_target_resolution(
        id,
        procedures,
        procedure_locators,
        &callable.targets,
        &procedure.evidence_rows[callable.target_evidence.index()].proof,
        "callable target",
    )?;
    if creation {
        if callable.targets.candidates().len() > 1 {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                "callable creation cannot identify more than one nested executable body",
            ));
        }
        for target in callable.targets.candidates() {
            match target {
                CallableTarget::Local(target)
                    if procedures[target.index()].lexical_parent == Some(id) => {}
                CallableTarget::Local(target) => {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::CallableContract,
                        format!(
                            "callable creation targets procedure {}, which is not a lexical child",
                            target
                        ),
                    ));
                }
                CallableTarget::Unmaterialized(locator)
                    if is_direct_lexical_child(&procedure.locator, locator) => {}
                CallableTarget::Unmaterialized(_) => {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::CallableContract,
                        "unmaterialized callable creation target is not a direct lexical child",
                    ));
                }
                CallableTarget::External(_) => {
                    return Err(SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::CallableContract,
                        "callable creation must target a separate lexical-child procedure; existing declarations are callable references",
                    ));
                }
            }
        }
    }
    match (callable.kind, callable.bound_receiver) {
        (CallableReferenceKind::BoundMethod, Some(receiver)) => {
            ensure_value(id, receiver, procedure.values.len(), "bound receiver")?;
        }
        (CallableReferenceKind::BoundMethod, None) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                "bound method reference is missing its evaluated receiver",
            ));
        }
        (_, Some(_)) => {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "{} callable cannot carry a bound receiver",
                    callable.kind.label()
                ),
            ));
        }
        (_, None) => {}
    }
    if !creation && callable.environment.is_some() {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::CallableContract,
            "callable reference cannot allocate a capture environment",
        ));
    }
    if let Some(environment) = callable.environment {
        ensure_allocation(
            id,
            environment,
            procedure.allocations.len(),
            "callable environment",
        )?;
        if !matches!(
            procedure.allocations[environment.index()].kind,
            AllocationKind::ClosureEnvironment | AllocationKind::LanguageDefined(_)
        ) {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "callable environment {} is not a closure-environment allocation",
                    environment
                ),
            ));
        }
        if procedure.allocations[environment.index()].point != point {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::CallableContract,
                format!(
                    "callable environment {} is allocated at point {}, not creation point {}",
                    environment,
                    procedure.allocations[environment.index()].point,
                    point
                ),
            ));
        }
    }
    require_resolution_gap(
        procedure,
        gaps,
        point,
        SemanticGapSubject::Value(result),
        SemanticCapability::CallableReferences,
        &callable.targets,
    )
}

fn validate_value_flow_kind(
    procedure: &ProcedureSemanticsParts,
    kind: ValueFlowKind,
    source: ValueId,
    target: ValueId,
) -> Result<(), SemanticIrError> {
    let source_kind = &procedure.values[source.index()].kind;
    let target_kind = &procedure.values[target.index()].kind;
    let valid = match kind {
        ValueFlowKind::Local => true,
        ValueFlowKind::Parameter => {
            matches!(source_kind, SemanticValueKind::Parameter { .. })
                || matches!(target_kind, SemanticValueKind::Parameter { .. })
        }
        ValueFlowKind::Receiver => {
            matches!(source_kind, SemanticValueKind::Receiver)
                || matches!(target_kind, SemanticValueKind::Receiver)
        }
        ValueFlowKind::Return => {
            matches!(source_kind, SemanticValueKind::Return)
                || matches!(target_kind, SemanticValueKind::Return)
        }
    };
    if !valid {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::ValueFlowContract,
            format!(
                "{} flow {} -> {} has no value row with that role",
                kind.label(),
                source,
                target
            ),
        ));
    }
    Ok(())
}

fn validate_memory_access_kind(
    procedure: &ProcedureSemanticsParts,
    location: MemoryLocationId,
    access: MemoryAccessKind,
) -> Result<(), SemanticIrError> {
    let location_kind = &procedure.memory_locations[location.index()].kind;
    let matches = matches!(
        (access, location_kind),
        (MemoryAccessKind::Field, MemoryLocationKind::Field { .. })
            | (MemoryAccessKind::Static, MemoryLocationKind::Static { .. })
            | (MemoryAccessKind::Index, MemoryLocationKind::Index { .. })
            | (
                MemoryAccessKind::LexicalCell,
                MemoryLocationKind::LexicalCell { .. }
            )
            | (
                MemoryAccessKind::Capture,
                MemoryLocationKind::Capture { .. }
            )
    );
    if !matches {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::MemoryContract,
            format!(
                "{} access names {} location {}",
                access.label(),
                location_kind.label(),
                location
            ),
        ));
    }
    Ok(())
}

fn required_gap_kind(resolution: &CallableTargetResolution) -> Option<SemanticGapKind> {
    match resolution {
        CallableTargetResolution::Proven(_) => None,
        CallableTargetResolution::Ambiguous(_) => Some(SemanticGapKind::Ambiguous),
        CallableTargetResolution::Unknown => Some(SemanticGapKind::Unknown),
        CallableTargetResolution::Unsupported => Some(SemanticGapKind::Unsupported),
        CallableTargetResolution::Unproven(_) => Some(SemanticGapKind::Unproven),
        CallableTargetResolution::ExceededBudget(_) => Some(SemanticGapKind::ExceededBudget),
    }
}

fn continuation_gap_kind(continuation: ControlContinuation) -> Option<SemanticGapKind> {
    match continuation {
        ControlContinuation::Target(_) | ControlContinuation::Absent => None,
        ControlContinuation::Unknown => Some(SemanticGapKind::Unknown),
        ControlContinuation::Unsupported => Some(SemanticGapKind::Unsupported),
        ControlContinuation::Unproven => Some(SemanticGapKind::Unproven),
        ControlContinuation::ExceededBudget => Some(SemanticGapKind::ExceededBudget),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_control_continuation(
    capabilities: &SemanticCapabilities,
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    control_edges: &ControlEdgeIndex,
    source: ProgramPointId,
    continuation: ControlContinuation,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
    edge_kind: ControlEdgeKind,
    context: &str,
) -> Result<(), SemanticIrError> {
    let outgoing_count = control_edges.outgoing_count(source, edge_kind);
    if let Some(target) = continuation.target() {
        require_capability(procedure.id, capabilities, capability, context)?;
        if outgoing_count != 1 || !control_edges.contains(source, target, edge_kind) {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "{context} requires exactly one {} edge {} -> {}; found {outgoing_count} outgoing edges of that kind",
                    edge_kind.label(),
                    source,
                    target
                ),
            ));
        }
    } else {
        if outgoing_count != 0 {
            return Err(SemanticIrError::procedure(
                procedure.id,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "{context} {} outcome forbids {} edges from point {}; found {outgoing_count}",
                    continuation.label(),
                    edge_kind.label(),
                    source
                ),
            ));
        }
        if continuation == ControlContinuation::Absent {
            require_capability(procedure.id, capabilities, capability, context)?;
        }
    }
    validate_expected_gap(
        procedure,
        gaps,
        source,
        subject,
        capability,
        continuation_gap_kind(continuation),
        context,
    )
}

fn validate_complete_outgoing_topology(
    procedure: &ProcedureSemanticsParts,
    control_edges: &ControlEdgeIndex,
    source: ProgramPointId,
    expected: usize,
    context: &str,
) -> Result<(), SemanticIrError> {
    let actual = control_edges.total_outgoing_count(source);
    if actual == expected {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure.id,
        SemanticIrErrorKind::ControlFlowContract,
        format!(
            "{context} point {source} owns its complete outgoing topology; expected {expected} continuation edges, found {actual} total outgoing edges"
        ),
    ))
}

fn require_resolution_gap(
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    point: ProgramPointId,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
    resolution: &CallableTargetResolution,
) -> Result<(), SemanticIrError> {
    validate_expected_gap(
        procedure,
        gaps,
        point,
        subject,
        capability,
        required_gap_kind(resolution),
        resolution.label(),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_expected_gap(
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    point: ProgramPointId,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
    expected: Option<SemanticGapKind>,
    context: &str,
) -> Result<(), SemanticIrError> {
    let actual = gaps.fact_kind(point, subject, capability);
    if actual == expected {
        return Ok(());
    }
    let expected = expected.map_or("none", SemanticGapKind::label);
    let actual = actual.map_or("none", SemanticGapKind::label);
    Err(SemanticIrError::procedure(
        procedure.id,
        SemanticIrErrorKind::GapContract,
        format!(
            "{context} outcome at point {point} requires gap {expected}, found {actual} for {}",
            capability.label()
        ),
    ))
}

fn validate_async_pairs(
    capabilities: &SemanticCapabilities,
    procedure: &ProcedureSemanticsParts,
    gaps: &GapIndex,
    control_edges: &ControlEdgeIndex,
    suspends: &HashMap<ProgramPointId, (ControlContinuation, ControlContinuation)>,
    resumes: &HashMap<(ProgramPointId, AsyncResumeKind), Vec<ProgramPointId>>,
) -> Result<(), SemanticIrError> {
    let id = procedure.id;
    for (suspend, (normal, exceptional)) in suspends {
        let normal_points = resumes
            .get(&(*suspend, AsyncResumeKind::Normal))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let exceptional_points = resumes
            .get(&(*suspend, AsyncResumeKind::Exceptional))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let normal_matches = match normal.target() {
            Some(target) => normal_points == [target],
            None => normal_points.is_empty(),
        };
        let exceptional_matches = match exceptional.target() {
            Some(target) => exceptional_points == [target],
            None => exceptional_points.is_empty(),
        };
        if !normal_matches || !exceptional_matches {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::AsyncContract,
                format!(
                    "suspend point {} resume events do not match its normal {} and exceptional {} outcomes",
                    suspend,
                    normal.label(),
                    exceptional.label()
                ),
            ));
        }
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            *suspend,
            *normal,
            SemanticGapSubject::AsyncContinuation {
                suspend: *suspend,
                kind: AsyncResumeKind::Normal,
            },
            SemanticCapability::AsyncSuspendResume,
            ControlEdgeKind::AsyncNormal,
            "normal async resume",
        )?;
        validate_control_continuation(
            capabilities,
            procedure,
            gaps,
            control_edges,
            *suspend,
            *exceptional,
            SemanticGapSubject::AsyncContinuation {
                suspend: *suspend,
                kind: AsyncResumeKind::Exceptional,
            },
            SemanticCapability::AsyncSuspendResume,
            ControlEdgeKind::AsyncExceptional,
            "exceptional async resume",
        )?;
        validate_complete_outgoing_topology(
            procedure,
            control_edges,
            *suspend,
            usize::from(normal.target().is_some()) + usize::from(exceptional.target().is_some()),
            "async suspend",
        )?;
    }
    for ((suspend, _), points) in resumes {
        if !suspends.contains_key(suspend) || points.len() != 1 {
            return Err(SemanticIrError::procedure(
                id,
                SemanticIrErrorKind::AsyncContract,
                format!(
                    "async resume references absent or non-unique suspend point {}",
                    suspend
                ),
            ));
        }
    }
    if (!suspends.is_empty() || !resumes.is_empty()) && !procedure.properties.is_async {
        return Err(SemanticIrError::procedure(
            id,
            SemanticIrErrorKind::AsyncContract,
            "async suspend/resume events require an async procedure",
        ));
    }
    Ok(())
}

fn validate_exactly_once(
    procedure: ProcedureId,
    table: &str,
    counts: &[usize],
) -> Result<(), SemanticIrError> {
    for (index, count) in counts.iter().copied().enumerate() {
        if count != 1 {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::EventContract,
                format!("{table} row {index} must have exactly one event; found {count}"),
            ));
        }
    }
    Ok(())
}

pub(super) fn find_boundaries(
    procedure: &ProcedureSemanticsParts,
) -> Result<Boundaries, SemanticIrError> {
    let mut entry = None;
    let mut normal_exit = None;
    let mut exceptional_exit = None;
    let mut counts = [0_usize; 3];
    for point in &procedure.points {
        for event in &point.events {
            match event.effect {
                SemanticEffect::Entry => {
                    counts[0] += 1;
                    entry.get_or_insert(point.id);
                }
                SemanticEffect::NormalExit => {
                    counts[1] += 1;
                    normal_exit.get_or_insert(point.id);
                }
                SemanticEffect::ExceptionalExit => {
                    counts[2] += 1;
                    exceptional_exit.get_or_insert(point.id);
                }
                _ => {}
            }
        }
    }
    if counts != [1, 1, 1] {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::Boundary,
            format!(
                "expected exactly one entry, normal exit, and exceptional exit; found {}, {}, and {}",
                counts[0], counts[1], counts[2]
            ),
        ));
    }
    let entry = entry.expect("exactly one entry was counted");
    let normal_exit = normal_exit.expect("exactly one normal exit was counted");
    let exceptional_exit = exceptional_exit.expect("exactly one exceptional exit was counted");
    if entry == normal_exit || entry == exceptional_exit || normal_exit == exceptional_exit {
        return Err(SemanticIrError::procedure(
            procedure.id,
            SemanticIrErrorKind::Boundary,
            "entry, normal exit, and exceptional exit must be distinct program points",
        ));
    }
    Ok(Boundaries {
        entry,
        normal_exit,
        exceptional_exit,
    })
}

fn validate_metadata(
    procedure: ProcedureId,
    source: SourceMappingId,
    evidence: EvidenceId,
    parts: &ProcedureSemanticsParts,
    context: &str,
) -> Result<(), SemanticIrError> {
    ensure_source(procedure, source, parts.source_mappings.len(), context)?;
    ensure_evidence(procedure, evidence, parts.evidence_rows.len(), context)
}

fn ensure_index(
    procedure: ProcedureId,
    context: &str,
    index: usize,
    len: usize,
) -> Result<(), SemanticIrError> {
    if index < len {
        Ok(())
    } else {
        Err(SemanticIrError::procedure(
            procedure,
            SemanticIrErrorKind::OutOfBounds,
            format!("{context} id {index} is outside dense table length {len}"),
        ))
    }
}

macro_rules! ensure_local_id {
    ($name:ident, $id_ty:ty, $label:literal) => {
        fn $name(
            procedure: ProcedureId,
            id: $id_ty,
            len: usize,
            context: &str,
        ) -> Result<(), SemanticIrError> {
            ensure_index(
                procedure,
                &format!("{context} ({})", $label),
                id.index(),
                len,
            )
        }
    };
}

ensure_local_id!(ensure_block, BlockId, "block");
ensure_local_id!(ensure_point, ProgramPointId, "program point");
ensure_local_id!(ensure_value, ValueId, "value");
ensure_local_id!(ensure_allocation, AllocationId, "allocation");
ensure_local_id!(ensure_call_site, CallSiteId, "call site");
ensure_local_id!(ensure_location, MemoryLocationId, "memory location");
ensure_local_id!(ensure_capture, CaptureId, "capture");
ensure_local_id!(ensure_source, SourceMappingId, "source mapping");
ensure_local_id!(ensure_evidence, EvidenceId, "evidence");
ensure_local_id!(ensure_gap, SemanticGapId, "semantic gap");

fn require_artifact_capability(
    capabilities: &SemanticCapabilities,
    capability: SemanticCapability,
    context: &str,
) -> Result<(), SemanticIrError> {
    if capabilities.is_available(capability) {
        return Ok(());
    }
    Err(SemanticIrError::artifact(
        SemanticIrErrorKind::CapabilityContract,
        format!(
            "{context} emits {}, but the capability table marks it unsupported",
            capability.label()
        ),
    ))
}

fn require_capability(
    procedure: ProcedureId,
    capabilities: &SemanticCapabilities,
    capability: SemanticCapability,
    context: &str,
) -> Result<(), SemanticIrError> {
    if capabilities.is_available(capability) {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::CapabilityContract,
        format!(
            "{context} emits {}, but the capability table marks it unsupported",
            capability.label()
        ),
    ))
}

fn validate_gap_capability(
    procedure: ProcedureId,
    capabilities: &SemanticCapabilities,
    gap: &SemanticGap,
) -> Result<(), SemanticIrError> {
    let support = capabilities.support(gap.capability);
    let consistent = match gap.kind {
        SemanticGapKind::Unsupported => support != CapabilitySupport::Complete,
        SemanticGapKind::Ambiguous
        | SemanticGapKind::Unknown
        | SemanticGapKind::Unproven
        | SemanticGapKind::ExceededBudget => support != CapabilitySupport::Unsupported,
    };
    if consistent {
        return Ok(());
    }
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::CapabilityContract,
        format!(
            "{} gap for {} contradicts capability support {:?}",
            gap.kind.label(),
            gap.capability.label(),
            support
        ),
    ))
}

fn validate_gap_impacts(procedure: ProcedureId, gap: &SemanticGap) -> Result<(), SemanticIrError> {
    let required = SemanticGapImpacts::for_gap(gap.capability, gap.subject);
    let Some(missing) = required
        .iter()
        .find(|impact| !gap.impacts.contains(*impact))
    else {
        return Ok(());
    };
    Err(SemanticIrError::procedure(
        procedure,
        SemanticIrErrorKind::GapContract,
        format!(
            "gap {} for {} is missing mandatory {} impact",
            gap.id,
            gap.capability.label(),
            missing.label(),
        ),
    ))
}

fn memory_location_capability(kind: &MemoryLocationKind) -> SemanticCapability {
    match kind {
        MemoryLocationKind::Field { .. } => SemanticCapability::FieldMemory,
        MemoryLocationKind::Static { .. } => SemanticCapability::StaticMemory,
        MemoryLocationKind::Index { .. } => SemanticCapability::IndexMemory,
        MemoryLocationKind::LexicalCell { .. } => SemanticCapability::LocalFlow,
        MemoryLocationKind::Capture { .. } => SemanticCapability::Captures,
    }
}

fn memory_access_capability(kind: MemoryAccessKind) -> SemanticCapability {
    match kind {
        MemoryAccessKind::Field => SemanticCapability::FieldMemory,
        MemoryAccessKind::Static => SemanticCapability::StaticMemory,
        MemoryAccessKind::Index => SemanticCapability::IndexMemory,
        MemoryAccessKind::LexicalCell => SemanticCapability::LocalFlow,
        MemoryAccessKind::Capture => SemanticCapability::Captures,
    }
}

fn control_edge_capability(kind: ControlEdgeKind) -> SemanticCapability {
    match kind {
        ControlEdgeKind::Normal
        | ControlEdgeKind::ConditionalTrue
        | ControlEdgeKind::ConditionalFalse
        | ControlEdgeKind::SwitchCase
        | ControlEdgeKind::LoopBack => SemanticCapability::NormalControlFlow,
        ControlEdgeKind::Exceptional => SemanticCapability::ExceptionalControlFlow,
        ControlEdgeKind::Cleanup => SemanticCapability::CleanupControlFlow,
        ControlEdgeKind::AsyncNormal | ControlEdgeKind::AsyncExceptional => {
            SemanticCapability::AsyncSuspendResume
        }
    }
}

fn is_control_splitting_effect(effect: &SemanticEffect) -> bool {
    matches!(
        effect,
        SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit
            | SemanticEffect::Invoke { .. }
            | SemanticEffect::ProcedureReturn { .. }
            | SemanticEffect::Throw { .. }
            | SemanticEffect::AsyncSuspend { .. }
    )
}

fn effect_capabilities(effect: &SemanticEffect) -> &'static [SemanticCapability] {
    match effect {
        SemanticEffect::Entry => &[SemanticCapability::EntryBoundary],
        SemanticEffect::NormalExit => &[SemanticCapability::NormalExitBoundary],
        SemanticEffect::ExceptionalExit => &[SemanticCapability::ExceptionalExitBoundary],
        SemanticEffect::Assignment { .. } => {
            &[SemanticCapability::Assignments, SemanticCapability::Values]
        }
        SemanticEffect::ValueFlow { kind, .. } => match kind {
            ValueFlowKind::Local => &[SemanticCapability::Values, SemanticCapability::LocalFlow],
            ValueFlowKind::Parameter => &[
                SemanticCapability::Values,
                SemanticCapability::ParameterFlow,
            ],
            ValueFlowKind::Receiver => {
                &[SemanticCapability::Values, SemanticCapability::ReceiverFlow]
            }
            ValueFlowKind::Return => &[SemanticCapability::Values, SemanticCapability::ReturnFlow],
        },
        SemanticEffect::Allocation { .. } => &[SemanticCapability::Allocations],
        SemanticEffect::MemoryLoad { kind, .. } | SemanticEffect::MemoryStore { kind, .. } => {
            match memory_access_capability(*kind) {
                SemanticCapability::FieldMemory => {
                    &[SemanticCapability::Values, SemanticCapability::FieldMemory]
                }
                SemanticCapability::StaticMemory => {
                    &[SemanticCapability::Values, SemanticCapability::StaticMemory]
                }
                SemanticCapability::IndexMemory => {
                    &[SemanticCapability::Values, SemanticCapability::IndexMemory]
                }
                SemanticCapability::LocalFlow => {
                    &[SemanticCapability::Values, SemanticCapability::LocalFlow]
                }
                SemanticCapability::Captures => {
                    &[SemanticCapability::Values, SemanticCapability::Captures]
                }
                _ => unreachable!("memory access maps only to memory capabilities"),
            }
        }
        SemanticEffect::CallableCreation { .. } | SemanticEffect::CallableReference { .. } => &[
            SemanticCapability::Values,
            SemanticCapability::CallableReferences,
        ],
        SemanticEffect::CaptureBind { .. } => &[SemanticCapability::Captures],
        SemanticEffect::Invoke { .. } => &[SemanticCapability::Calls],
        SemanticEffect::CallContinuation { kind, .. } => match kind {
            CallContinuationKind::Normal => &[SemanticCapability::NormalCallContinuation],
            CallContinuationKind::Exceptional => &[SemanticCapability::ExceptionalCallContinuation],
        },
        SemanticEffect::ProcedureReturn { .. } => &[SemanticCapability::ReturnFlow],
        SemanticEffect::Throw { .. } => &[SemanticCapability::ExceptionalControlFlow],
        SemanticEffect::AsyncSuspend { .. } | SemanticEffect::AsyncResume { .. } => {
            &[SemanticCapability::AsyncSuspendResume]
        }
        SemanticEffect::Gap { .. } => &[],
    }
}
