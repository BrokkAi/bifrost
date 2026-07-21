//! Deterministic, bounded rendering for semantic artifacts.
//!
//! The renderer is intentionally a view over validated semantic IR. It does
//! not parse source, resolve targets, or infer missing semantics.

use std::fmt;

use crate::analyzer::bounded_output::{BalancedWriter, TruncationStyle, quoted};

use super::capabilities::{CapabilitySupport, SemanticCapabilities};
use super::ids::{
    ControlEdgeId, DeclarationSegmentKind, ProcedureId, SemanticArtifactKey, SemanticLocator,
    SourceRevision,
};
use super::ir::{
    AllocationKind, AllocationSite, ArgumentDomain, BasicBlock, CallableTarget,
    CallableTargetResolution, CallableValue, CaptureBinding, CaptureSource, ControlContinuation,
    ControlEdge, Evidence, EvidenceCompleteness, FormalMultiplicity, MemoryLocation,
    MemoryLocationKind, ProcedureSemantics, ProgramPoint, ProofStatus, SemanticArtifact,
    SemanticCallSite, SemanticEffect, SemanticEvent, SemanticGap, SemanticGapSubject,
    SemanticValue, SemanticValueKind, SourceMapping,
};
use super::{
    DispatchBoundaryKind, IcfgBoundary, IcfgBoundaryKind, IcfgEdge, IcfgLimitKind, IcfgNodeKey,
    IcfgSnapshot,
};

const TRUNCATION_RESERVE: usize = 160;
const MIN_OUTPUT_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticIrLimits {
    pub max_procedures: usize,
    pub max_rows: usize,
    pub max_source_entries: usize,
    pub max_output_bytes: usize,
}

impl Default for SemanticIrLimits {
    fn default() -> Self {
        Self {
            max_procedures: 256,
            max_rows: 100_000,
            max_source_entries: 20_000,
            max_output_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticIrSelection {
    Artifact,
    Procedure(ProcedureId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedSemanticIr {
    pub semantic_ir: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcfgRenderLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_boundaries: usize,
    pub max_output_bytes: usize,
}

impl Default for IcfgRenderLimits {
    fn default() -> Self {
        Self {
            max_nodes: 50_000,
            max_edges: 200_000,
            max_boundaries: 50_000,
            max_output_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedIcfgSnapshot {
    pub icfg: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticRenderError {
    InvalidLimits,
    UnknownProcedure(ProcedureId),
}

impl fmt::Display for SemanticRenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => write!(
                f,
                "semantic IR procedure, row, and source-entry limits must be greater than zero, and the output limit must be at least {MIN_OUTPUT_BYTES} bytes"
            ),
            Self::UnknownProcedure(procedure) => {
                write!(
                    f,
                    "semantic artifact does not contain procedure {procedure}"
                )
            }
        }
    }
}

impl std::error::Error for SemanticRenderError {}

/// Render one already-bounded ICFG slice without resolving or materializing
/// additional procedures. Node references are source-backed and never expose
/// snapshot-local dense IDs as an assertion contract.
pub fn render_icfg_snapshot(
    snapshot: &IcfgSnapshot,
    limits: IcfgRenderLimits,
) -> Result<RenderedIcfgSnapshot, SemanticRenderError> {
    if limits.max_nodes == 0
        || limits.max_edges == 0
        || limits.max_boundaries == 0
        || limits.max_output_bytes < MIN_OUTPUT_BYTES
    {
        return Err(SemanticRenderError::InvalidLimits);
    }
    let mut writer = BalancedWriter::new(
        limits.max_output_bytes,
        TRUNCATION_RESERVE,
        TruncationStyle::ReasonAttribute,
    );
    if writer.open(0, "(icfg-snapshot") && writer.open(1, "(nodes") {
        for node in snapshot.nodes().iter().take(limits.max_nodes) {
            if !writer.line_with(2, |output| write_icfg_node(output, node)) {
                break;
            }
        }
        if snapshot.node_count() > limits.max_nodes {
            writer.truncate("ICFG node render limit reached");
        }
        if !writer.is_truncated() {
            writer.close(1);
            writer.open(1, "(edges");
            for edge in snapshot.edges().iter().take(limits.max_edges) {
                if !writer.line_with(2, |output| write_icfg_edge(output, snapshot, edge)) {
                    break;
                }
            }
            if snapshot.edge_count() > limits.max_edges {
                writer.truncate("ICFG edge render limit reached");
            }
        }
        if !writer.is_truncated() {
            writer.close(1);
            writer.open(1, "(boundaries");
            for boundary in snapshot.boundaries().iter().take(limits.max_boundaries) {
                if !writer.line_with(2, |output| write_icfg_boundary(output, snapshot, boundary)) {
                    break;
                }
            }
            if snapshot.boundaries().len() > limits.max_boundaries {
                writer.truncate("ICFG boundary render limit reached");
            }
        }
    }
    if !writer.is_truncated() {
        writer.close(1);
        writer.close(0);
    }
    let (icfg, truncated) = writer.finish();
    Ok(RenderedIcfgSnapshot { icfg, truncated })
}

impl SemanticIrLimits {
    fn validate(self) -> Result<Self, SemanticRenderError> {
        if self.max_procedures == 0
            || self.max_rows == 0
            || self.max_source_entries == 0
            || self.max_output_bytes < MIN_OUTPUT_BYTES
        {
            return Err(SemanticRenderError::InvalidLimits);
        }
        Ok(self)
    }
}

pub fn render_semantic_ir(
    artifact: &SemanticArtifact,
    selection: SemanticIrSelection,
    limits: SemanticIrLimits,
) -> Result<RenderedSemanticIr, SemanticRenderError> {
    let limits = limits.validate()?;
    let selected = match selection {
        SemanticIrSelection::Artifact => None,
        SemanticIrSelection::Procedure(id) => Some(
            artifact
                .procedure(id)
                .ok_or(SemanticRenderError::UnknownProcedure(id))?,
        ),
    };
    let mut state = RenderState::new(limits);
    if open_artifact(&mut state, artifact.key())
        && render_capabilities(&mut state, artifact.capabilities())
    {
        match selected {
            Some(procedure) => {
                render_procedure(&mut state, procedure);
            }
            None => {
                for procedure in artifact.procedures() {
                    if !render_procedure(&mut state, procedure) {
                        break;
                    }
                }
            }
        }
    }
    if !state.writer.is_truncated() {
        state.writer.close(1);
        state.writer.close(0);
    }
    let (semantic_ir, truncated) = state.writer.finish();
    Ok(RenderedSemanticIr {
        semantic_ir,
        truncated,
    })
}

struct RenderState {
    limits: SemanticIrLimits,
    writer: BalancedWriter,
    rendered_procedures: usize,
    rendered_rows: usize,
    rendered_source_entries: usize,
}

impl RenderState {
    fn new(limits: SemanticIrLimits) -> Self {
        Self {
            writer: BalancedWriter::new(
                limits.max_output_bytes,
                TRUNCATION_RESERVE,
                TruncationStyle::ReasonAttribute,
            ),
            limits,
            rendered_procedures: 0,
            rendered_rows: 0,
            rendered_source_entries: 0,
        }
    }

    fn begin_procedure(&mut self) -> bool {
        if self.rendered_procedures >= self.limits.max_procedures {
            self.writer.truncate("procedure limit reached");
            return false;
        }
        self.rendered_procedures += 1;
        true
    }

    fn row_with(
        &mut self,
        depth: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        if self.rendered_rows >= self.limits.max_rows {
            self.writer.truncate("row limit reached");
            return false;
        }
        if !self.writer.line_with(depth, render) {
            return false;
        }
        self.rendered_rows += 1;
        true
    }

    fn open_row_with(
        &mut self,
        depth: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        if self.rendered_rows >= self.limits.max_rows {
            self.writer.truncate("row limit reached");
            return false;
        }
        if !self.writer.open_with(depth, render) {
            return false;
        }
        self.rendered_rows += 1;
        true
    }

    fn source_row_with(
        &mut self,
        depth: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        if self.rendered_source_entries >= self.limits.max_source_entries {
            self.writer.truncate("source entry limit reached");
            return false;
        }
        if !self.row_with(depth, render) {
            return false;
        }
        self.rendered_source_entries += 1;
        true
    }
}

fn render_procedure(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.begin_procedure() {
        return false;
    }
    let properties = procedure.properties();
    if !state.writer.open_with(2, |writer| {
        write!(
            writer,
            "(procedure :id {} :kind {} :parent {} :source {} :evidence {} :entry {} :normal-exit {} :exceptional-exit {} :async {} :generator {} :static {} :synthetic {} :invocation {}",
            procedure.id(),
            quoted(procedure.kind().label()),
            optional_id(procedure.lexical_parent()),
            procedure.source(),
            procedure.evidence(),
            procedure.entry_point(),
            procedure.normal_exit_point(),
            procedure.exceptional_exit_point(),
            properties.is_async,
            properties.is_generator,
            properties.is_static,
            properties.is_synthetic,
            quoted(properties.invocation.label()),
        )
    }) {
        return false;
    }
    if !state.source_row_with(3, |writer| {
        writer.write_str("(locator ")?;
        write_locator(writer, procedure.locator())?;
        writer.write_char(')')
    }) || !render_values(state, procedure)
        || !render_allocations(state, procedure)
        || !render_memory_locations(state, procedure)
        || !render_captures(state, procedure)
        || !render_call_sites(state, procedure)
        || !render_source_mappings(state, procedure)
        || !render_evidence(state, procedure)
        || !render_gaps(state, procedure)
        || !render_blocks(state, procedure)
        || !render_points(state, procedure)
        || !render_control_edges(state, procedure)
    {
        return false;
    }
    state.writer.close(2)
}

fn render_values(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(values") {
        return false;
    }
    for value in procedure.values() {
        if !state.row_with(4, |writer| write_value(writer, value)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_allocations(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(allocations") {
        return false;
    }
    for allocation in procedure.allocations() {
        if !state.row_with(4, |writer| write_allocation(writer, allocation)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_memory_locations(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(memory-locations") {
        return false;
    }
    for location in procedure.memory_locations() {
        if !state.row_with(4, |writer| write_memory_location(writer, location)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_captures(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(captures") {
        return false;
    }
    for capture in procedure.captures() {
        if !state.row_with(4, |writer| write_capture(writer, capture)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_call_sites(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(call-sites") {
        return false;
    }
    for call_site in procedure.call_sites() {
        if !state.row_with(4, |writer| write_call_site(writer, call_site)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_source_mappings(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(source-mappings") {
        return false;
    }
    for mapping in procedure.source_mappings() {
        if !state.source_row_with(4, |writer| write_source_mapping(writer, mapping)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_evidence(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(evidence") {
        return false;
    }
    for evidence in procedure.evidence_rows() {
        if !state.row_with(4, |writer| write_evidence(writer, evidence)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_gaps(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(gaps") {
        return false;
    }
    for gap in procedure.gaps() {
        if !state.row_with(4, |writer| write_gap(writer, gap)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_blocks(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(blocks") {
        return false;
    }
    for block in procedure.blocks() {
        if !state.row_with(4, |writer| write_block(writer, block)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_points(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(program-points") {
        return false;
    }
    for point in procedure.points() {
        if !render_point(state, procedure, point) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_control_edges(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(control-edges") {
        return false;
    }
    for (index, edge) in procedure.cfg().edges().iter().enumerate() {
        let edge_id = ControlEdgeId::try_from_index(index)
            .expect("validated semantic control-edge count must fit in a u32");
        if !state.row_with(4, |writer| write_control_edge(writer, edge_id, edge)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn write_value(writer: &mut dyn fmt::Write, value: &SemanticValue) -> fmt::Result {
    write!(
        writer,
        "(value :id {} :kind {}",
        value.id,
        quoted(value.kind.label())
    )?;
    match &value.kind {
        SemanticValueKind::Parameter {
            ordinal,
            multiplicity,
        } => {
            write!(
                writer,
                " :ordinal {ordinal} :multiplicity {}",
                quoted(multiplicity.label())
            )?;
            if let FormalMultiplicity::Rest(domain) = multiplicity {
                write!(writer, " :argument-domain {}", quoted(domain.label()))?;
                if let ArgumentDomain::LanguageDefined(detail) = domain {
                    write!(writer, " :language-domain {}", quoted(detail))?;
                }
            }
        }
        SemanticValueKind::LanguageDefined(kind) => {
            write!(writer, " :language-kind {}", quoted(kind))?;
        }
        SemanticValueKind::Local
        | SemanticValueKind::Receiver
        | SemanticValueKind::Return
        | SemanticValueKind::Temporary
        | SemanticValueKind::Constant
        | SemanticValueKind::Exception
        | SemanticValueKind::Callable
        | SemanticValueKind::AwaitResult => {}
    }
    write!(
        writer,
        " :source {} :evidence {})",
        value.source, value.evidence
    )
}

fn write_allocation(writer: &mut dyn fmt::Write, allocation: &AllocationSite) -> fmt::Result {
    write!(
        writer,
        "(allocation :id {} :point {} :result {} :kind {}",
        allocation.id,
        allocation.point,
        allocation.result,
        quoted(allocation.kind.label())
    )?;
    if let AllocationKind::LanguageDefined(kind) = &allocation.kind {
        write!(writer, " :language-kind {}", quoted(kind))?;
    }
    write!(
        writer,
        " :source {} :evidence {})",
        allocation.source, allocation.evidence
    )
}

fn write_memory_location(writer: &mut dyn fmt::Write, location: &MemoryLocation) -> fmt::Result {
    write!(
        writer,
        "(memory-location :id {} :kind {}",
        location.id,
        quoted(location.kind.label())
    )?;
    match &location.kind {
        MemoryLocationKind::Field { base, member } => {
            write!(writer, " :base {base} :member (locator ")?;
            write_locator(writer, member)?;
            writer.write_char(')')?;
        }
        MemoryLocationKind::Static { member } => {
            writer.write_str(" :member (locator ")?;
            write_locator(writer, member)?;
            writer.write_char(')')?;
        }
        MemoryLocationKind::Index { base, index } => {
            write!(writer, " :base {base} :index {}", optional_id(*index))?;
        }
        MemoryLocationKind::LexicalCell { binding } => {
            write!(writer, " :binding-value {binding}")?;
        }
        MemoryLocationKind::Capture { lexical_parent } => {
            write!(writer, " :lexical-parent {lexical_parent}")?;
        }
    }
    write!(
        writer,
        " :source {} :evidence {})",
        location.source, location.evidence
    )
}

fn write_capture(writer: &mut dyn fmt::Write, capture: &CaptureBinding) -> fmt::Result {
    write!(
        writer,
        "(capture :id {} :point {} :callable {} :target-procedure {} :environment {} :source-kind {}",
        capture.id,
        capture.point,
        capture.callable,
        capture.target,
        capture.environment,
        quoted(capture.captured.label()),
    )?;
    match capture.captured {
        CaptureSource::Value(value) => write!(writer, " :source-value {value}")?,
        CaptureSource::Location(location) => write!(writer, " :source-location {location}")?,
    }
    write!(
        writer,
        " :destination (procedure {} :memory-location {}) :mode {}",
        capture.target,
        capture.destination,
        quoted(capture.mode.label()),
    )?;
    if let super::ir::CaptureMode::LanguageDefined(mode) = &capture.mode {
        write!(writer, " :language-mode {}", quoted(mode))?;
    }
    write!(
        writer,
        " :source {} :evidence {})",
        capture.source, capture.evidence,
    )
}

fn write_call_site(writer: &mut dyn fmt::Write, call_site: &SemanticCallSite) -> fmt::Result {
    write!(
        writer,
        "(call-site :id {} :point {} :callee {} :receiver {} :arguments ",
        call_site.id,
        call_site.point,
        call_site.callee,
        optional_id(call_site.receiver),
    )?;
    writer.write_char('(')?;
    for (index, argument) in call_site.arguments.iter().enumerate() {
        if index > 0 {
            writer.write_char(' ')?;
        }
        write!(
            writer,
            "(argument :value {} :expansion {}",
            argument.value,
            quoted(argument.expansion.label()),
        )?;
        if let Some(domain) = argument.expansion.domain() {
            write!(writer, " :domain {}", quoted(domain.label()))?;
            if let ArgumentDomain::LanguageDefined(detail) = domain {
                write!(writer, " :language-domain {}", quoted(detail))?;
            }
        }
        writer.write_char(')')?;
    }
    writer.write_char(')')?;
    write!(
        writer,
        " :result {} :thrown {} :declared-targets (",
        optional_id(call_site.result),
        optional_id(call_site.thrown),
    )?;
    write_target_resolution(writer, &call_site.declared_targets)?;
    write!(
        writer,
        ") :target-evidence {} :normal-continuation ",
        call_site.target_evidence,
    )?;
    write_control_continuation(writer, call_site.normal_continuation)?;
    writer.write_str(" :exceptional-continuation ")?;
    write_control_continuation(writer, call_site.exceptional_continuation)?;
    write!(
        writer,
        " :source {} :evidence {})",
        call_site.source, call_site.evidence,
    )
}

fn write_source_mapping(writer: &mut dyn fmt::Write, mapping: &SourceMapping) -> fmt::Result {
    write!(
        writer,
        "(source-mapping :id {} :kind {} :locator (locator ",
        mapping.id,
        quoted(mapping.kind.label()),
    )?;
    write_locator(writer, &mapping.locator)?;
    writer.write_str("))")
}

fn write_control_continuation(
    writer: &mut dyn fmt::Write,
    continuation: ControlContinuation,
) -> fmt::Result {
    match continuation {
        ControlContinuation::Target(target) => {
            write!(writer, "(continuation :outcome \"target\" :point {target})")
        }
        continuation => write!(
            writer,
            "(continuation :outcome {})",
            quoted(continuation.label())
        ),
    }
}

fn write_evidence(writer: &mut dyn fmt::Write, evidence: &Evidence) -> fmt::Result {
    write!(
        writer,
        "(evidence-row :id {} :proof {}",
        evidence.id,
        quoted(evidence.proof.label())
    )?;
    if let ProofStatus::Unproven(detail) = &evidence.proof {
        write!(writer, " :proof-detail {}", quoted(detail))?;
    }
    write!(
        writer,
        " :completeness {}",
        quoted(evidence.completeness.label())
    )?;
    if let EvidenceCompleteness::Partial(detail) = &evidence.completeness {
        write!(writer, " :completeness-detail {}", quoted(detail))?;
    }
    writer.write_str(" :sources ")?;
    write_id_list(writer, evidence.sources.iter().copied())?;
    writer.write_char(')')
}

fn write_gap(writer: &mut dyn fmt::Write, gap: &SemanticGap) -> fmt::Result {
    write!(writer, "(gap :id {} :point {} :subject ", gap.id, gap.point)?;
    write_gap_subject(writer, gap.subject)?;
    write!(
        writer,
        " :capability {} :impacts (",
        quoted(gap.capability.label()),
    )?;
    for (index, impact) in gap.impacts.iter().enumerate() {
        if index > 0 {
            writer.write_char(' ')?;
        }
        write!(writer, "{}", quoted(impact.label()))?;
    }
    write!(writer, ") :kind {} :budget ", quoted(gap.kind.label()),)?;
    if let Some(budget) = gap.budget {
        write!(
            writer,
            "(budget :dimension {} :limit {} :attempted {})",
            quoted(budget.dimension().label()),
            budget.limit(),
            budget.attempted(),
        )?;
    } else {
        writer.write_str("none")?;
    }
    write!(
        writer,
        " :detail {} :source {} :evidence {})",
        quoted(&gap.detail),
        gap.source,
        gap.evidence,
    )
}

fn write_gap_subject(writer: &mut dyn fmt::Write, subject: SemanticGapSubject) -> fmt::Result {
    write!(writer, "(subject :kind {}", quoted(subject.label()))?;
    match subject {
        SemanticGapSubject::Procedure | SemanticGapSubject::Point => {}
        SemanticGapSubject::Value(value) => write!(writer, " :value {value}")?,
        SemanticGapSubject::MemoryLocation(location) => {
            write!(writer, " :memory-location {location}")?;
        }
        SemanticGapSubject::Capture(capture) => {
            write!(writer, " :capture {capture}")?;
        }
        SemanticGapSubject::CallSite(call_site) => {
            write!(writer, " :call-site {call_site}")?;
        }
        SemanticGapSubject::CallContinuation { call_site, kind } => {
            write!(
                writer,
                " :call-site {call_site} :continuation-kind {}",
                quoted(kind.label())
            )?;
        }
        SemanticGapSubject::AsyncContinuation { suspend, kind } => {
            write!(
                writer,
                " :suspend {suspend} :resume-kind {}",
                quoted(kind.label())
            )?;
        }
    }
    writer.write_char(')')
}

fn write_block(writer: &mut dyn fmt::Write, block: &BasicBlock) -> fmt::Result {
    write!(writer, "(block :id {} :points ", block.id)?;
    write_id_list(writer, block.points.iter().copied())?;
    write!(
        writer,
        " :source {} :evidence {})",
        block.source, block.evidence,
    )
}

fn render_point(
    state: &mut RenderState,
    procedure: &ProcedureSemantics,
    point: &ProgramPoint,
) -> bool {
    if !state.open_row_with(4, |writer| {
        write!(
            writer,
            "(program-point :id {} :block {} :source {} :evidence {}",
            point.id, point.block, point.source, point.evidence
        )?;
        writer.write_str(" :predecessor-edges ")?;
        write_id_list(
            writer,
            procedure
                .predecessor_edges(point.id)
                .map(|(edge_id, _)| edge_id),
        )?;
        writer.write_str(" :successor-edges ")?;
        write_id_list(
            writer,
            procedure
                .successor_edges(point.id)
                .map(|(edge_id, _)| edge_id),
        )
    }) {
        return false;
    }
    for (index, event) in point.events.iter().enumerate() {
        if !state.row_with(5, |writer| write_event(writer, index, event)) {
            return false;
        }
    }
    state.writer.close(4)
}

fn write_event(writer: &mut dyn fmt::Write, index: usize, event: &SemanticEvent) -> fmt::Result {
    write!(
        writer,
        "(event :index {index} :effect {}",
        quoted(event.effect.label())
    )?;
    match &event.effect {
        SemanticEffect::Entry | SemanticEffect::NormalExit | SemanticEffect::ExceptionalExit => {}
        SemanticEffect::Assignment { target, value } => {
            write!(writer, " :target {target} :value {value}")?;
        }
        SemanticEffect::ValueFlow {
            kind,
            source,
            target,
        } => {
            write!(
                writer,
                " :flow-kind {} :flow-source {source} :target {target}",
                quoted(kind.label())
            )?;
        }
        SemanticEffect::Allocation { allocation } => {
            write!(writer, " :allocation {allocation}")?;
        }
        SemanticEffect::MemoryLoad {
            kind,
            location,
            result,
        } => {
            write!(
                writer,
                " :access-kind {} :location {location} :result {result}",
                quoted(kind.label())
            )?;
        }
        SemanticEffect::MemoryStore {
            kind,
            location,
            value,
        } => {
            write!(
                writer,
                " :access-kind {} :location {location} :value {value}",
                quoted(kind.label())
            )?;
        }
        SemanticEffect::CallableCreation { result, callable }
        | SemanticEffect::CallableReference { result, callable } => {
            write!(writer, " :result {result} ")?;
            write_callable(writer, callable)?;
        }
        SemanticEffect::CaptureBind { capture } => {
            write!(writer, " :capture {capture}")?;
        }
        SemanticEffect::Invoke { call_site } => {
            write!(writer, " :call-site {call_site}")?;
        }
        SemanticEffect::CallContinuation { call_site, kind } => {
            write!(
                writer,
                " :call-site {call_site} :continuation-kind {}",
                quoted(kind.label())
            )?;
        }
        SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
            write!(writer, " :value {}", optional_id(*value))?;
        }
        SemanticEffect::AsyncSuspend {
            awaited,
            normal_resume,
            exceptional_resume,
        } => {
            write!(
                writer,
                " :awaited {} :normal-resume ",
                optional_id(*awaited)
            )?;
            write_control_continuation(writer, *normal_resume)?;
            writer.write_str(" :exceptional-resume ")?;
            write_control_continuation(writer, *exceptional_resume)?;
        }
        SemanticEffect::AsyncResume {
            suspend,
            kind,
            result,
        } => {
            write!(
                writer,
                " :suspend {suspend} :resume-kind {} :result {}",
                quoted(kind.label()),
                optional_id(*result)
            )?;
        }
        SemanticEffect::Gap { gap } => {
            write!(writer, " :gap {gap}")?;
        }
    }
    write!(
        writer,
        " :source {} :evidence {})",
        event.source, event.evidence
    )
}

fn write_callable(writer: &mut dyn fmt::Write, callable: &CallableValue) -> fmt::Result {
    write!(writer, ":callable-kind {} ", quoted(callable.kind.label()))?;
    write_target_resolution(writer, &callable.targets)?;
    write!(
        writer,
        " :target-evidence {} :bound-receiver {} :environment {}",
        callable.target_evidence,
        optional_id(callable.bound_receiver),
        optional_id(callable.environment),
    )
}

fn write_target_resolution(
    writer: &mut dyn fmt::Write,
    resolution: &CallableTargetResolution,
) -> fmt::Result {
    write!(
        writer,
        ":target-resolution {} :targets (",
        quoted(resolution.label())
    )?;
    for target in resolution.candidates() {
        write!(writer, "(target :kind {}", quoted(target.label()))?;
        match target {
            CallableTarget::Local(procedure) => write!(writer, " :procedure {procedure}")?,
            CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                writer.write_str(" :locator (locator ")?;
                write_locator(writer, locator)?;
                writer.write_char(')')?;
            }
        }
        writer.write_char(')')?;
    }
    writer.write_char(')')
}

fn write_control_edge(
    writer: &mut dyn fmt::Write,
    edge_id: ControlEdgeId,
    edge: &ControlEdge,
) -> fmt::Result {
    write!(
        writer,
        "(control-edge :id {} :source-point {} :target-point {} :kind {} :source {} :evidence {})",
        edge_id,
        edge.source_point,
        edge.target_point,
        quoted(edge.kind.label()),
        edge.source,
        edge.evidence,
    )
}

fn write_icfg_node(writer: &mut dyn fmt::Write, node: &IcfgNodeKey) -> fmt::Result {
    writer.write_str("(icfg-node :point ")?;
    write_icfg_point_ref(writer, node.point())?;
    writer.write_str(" :context (")?;
    for call in node.call_context() {
        writer.write_str("(call ")?;
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("published ICFG call context retains a valid call handle");
        let mapping = call
            .procedure()
            .semantics()
            .source_mapping(semantic_call.source)
            .expect("published semantic call retains a valid source mapping");
        write_locator(writer, &mapping.locator)?;
        writer.write_char(')')?;
    }
    writer.write_str("))")
}

fn write_icfg_point_ref(
    writer: &mut dyn fmt::Write,
    point: &super::ProgramPointHandle,
) -> fmt::Result {
    let procedure = point.procedure().semantics();
    let semantic_point = procedure
        .point(point.id())
        .expect("published ICFG node retains a valid point handle");
    let mapping = procedure
        .source_mapping(semantic_point.source)
        .expect("published semantic point retains a valid source mapping");
    writer.write_str("(point :procedure (locator ")?;
    write_locator(writer, procedure.locator())?;
    writer.write_str(") :source (locator ")?;
    write_locator(writer, &mapping.locator)?;
    writer.write_str(") :effects (")?;
    for event in semantic_point.events.iter() {
        write!(writer, "{} ", quoted(event.effect.label()))?;
    }
    writer.write_str("))")
}

fn write_icfg_edge(
    writer: &mut dyn fmt::Write,
    snapshot: &IcfgSnapshot,
    edge: &IcfgEdge,
) -> fmt::Result {
    write!(
        writer,
        "(icfg-edge :kind {} :source ",
        quoted(edge.kind.label())
    )?;
    write_icfg_node(
        writer,
        snapshot
            .node(edge.source)
            .expect("published ICFG edge source exists"),
    )?;
    writer.write_str(" :target ")?;
    write_icfg_node(
        writer,
        snapshot
            .node(edge.target)
            .expect("published ICFG edge target exists"),
    )?;
    write!(
        writer,
        " :proof {} :completeness {}",
        quoted(edge.proof.label()),
        quoted(edge.completeness.label())
    )?;
    if let Some(origin) = &edge.origin {
        writer.write_str(" :origin ")?;
        let semantic_call = origin
            .procedure()
            .semantics()
            .call_site(origin.id())
            .expect("published ICFG edge origin exists");
        let mapping = origin
            .procedure()
            .semantics()
            .source_mapping(semantic_call.source)
            .expect("published ICFG edge origin has a source mapping");
        writer.write_str("(call ")?;
        write_locator(writer, &mapping.locator)?;
        writer.write_char(')')?;
    }
    writer.write_char(')')
}

fn write_icfg_boundary(
    writer: &mut dyn fmt::Write,
    snapshot: &IcfgSnapshot,
    boundary: &IcfgBoundary,
) -> fmt::Result {
    writer.write_str("(icfg-boundary :at ")?;
    write_icfg_node(
        writer,
        snapshot
            .node(boundary.at)
            .expect("published ICFG boundary node exists"),
    )?;
    writer.write_str(" :kind ")?;
    match &boundary.kind {
        IcfgBoundaryKind::Dispatch(dispatch) => {
            write!(writer, "{}", quoted(dispatch_boundary_label(dispatch)))?
        }
        IcfgBoundaryKind::Limit(limit) => write!(
            writer,
            "{}",
            quoted(match limit {
                IcfgLimitKind::CallDepth => "call_depth_limit",
                IcfgLimitKind::Nodes => "node_limit",
                IcfgLimitKind::Edges => "edge_limit",
            })
        )?,
        IcfgBoundaryKind::Continuation { kind, state } => write!(
            writer,
            "{} :continuation-state {}",
            quoted(match kind {
                super::CallContinuationKind::Normal => "normal_continuation",
                super::CallContinuationKind::Exceptional => "exceptional_continuation",
            }),
            quoted(state.label())
        )?,
    }
    if let IcfgBoundaryKind::Dispatch(
        DispatchBoundaryKind::External(Some(locator))
        | DispatchBoundaryKind::Unmaterialized(locator)
        | DispatchBoundaryKind::Deferred {
            target: locator, ..
        },
    ) = &boundary.kind
    {
        writer.write_str(" :target (locator ")?;
        write_locator(writer, locator)?;
        writer.write_char(')')?;
    }
    if let Some(origin) = &boundary.origin {
        writer.write_str(" :origin ")?;
        let semantic_call = origin
            .procedure()
            .semantics()
            .call_site(origin.id())
            .expect("published ICFG boundary origin exists");
        let mapping = origin
            .procedure()
            .semantics()
            .source_mapping(semantic_call.source)
            .expect("published ICFG boundary origin has a source mapping");
        writer.write_str("(call ")?;
        write_locator(writer, &mapping.locator)?;
        writer.write_char(')')?;
    }
    writer.write_char(')')
}

fn dispatch_boundary_label(boundary: &DispatchBoundaryKind) -> &'static str {
    match boundary {
        DispatchBoundaryKind::External(_) => "external",
        DispatchBoundaryKind::Unmaterialized(_) => "unmaterialized",
        DispatchBoundaryKind::Deferred { kind, .. } => match kind {
            super::DeferredInvocationKind::Async => "deferred_async",
            super::DeferredInvocationKind::Generator => "deferred_generator",
            super::DeferredInvocationKind::AsyncGenerator => "deferred_async_generator",
            super::DeferredInvocationKind::LanguageDefined => "deferred_language_defined",
        },
        DispatchBoundaryKind::Unresolved => "unresolved",
        DispatchBoundaryKind::Truncated => "truncated",
    }
}

fn write_locator(writer: &mut dyn fmt::Write, locator: &SemanticLocator) -> fmt::Result {
    let anchor = locator.anchor();
    let span = anchor.span();
    let start = span.start();
    let end = span.end();
    writer.write_str(":mount ")?;
    write_quoted_display(writer, locator.mount())?;
    write!(
        writer,
        " :path {} :language {} :role {} :byte-span (start-inclusive {} end-exclusive {}) :start (position :line0 {} :utf8-byte-column {}) :end (position :line0 {} :utf8-byte-column {}) :occurrence {} :declaration (",
        quoted(locator.path().as_str()),
        quoted(locator.language().stable_label()),
        quoted(locator.role().stable_label()),
        span.start_byte(),
        span.end_byte(),
        start.line(),
        start.byte_column(),
        end.line(),
        end.byte_column(),
        anchor.occurrence(),
    )?;
    for segment in locator.declaration().segments() {
        let segment_anchor = segment.anchor();
        let segment_span = segment_anchor.span();
        write!(
            writer,
            "(segment :kind {} :name ",
            quoted(declaration_segment_kind_label(segment.kind())),
        )?;
        if let Some(name) = segment.name() {
            write!(writer, "{}", quoted(name))?;
        } else {
            writer.write_str("none")?;
        }
        write!(
            writer,
            " :byte-span (start-inclusive {} end-exclusive {}) :occurrence {} :sibling-ordinal {})",
            segment_span.start_byte(),
            segment_span.end_byte(),
            segment_anchor.occurrence(),
            segment.sibling_ordinal(),
        )?;
    }
    writer.write_char(')')
}
const fn declaration_segment_kind_label(kind: DeclarationSegmentKind) -> &'static str {
    match kind {
        DeclarationSegmentKind::File => "file",
        DeclarationSegmentKind::Namespace => "namespace",
        DeclarationSegmentKind::Type => "type",
        DeclarationSegmentKind::Function => "function",
        DeclarationSegmentKind::Method => "method",
        DeclarationSegmentKind::Constructor => "constructor",
        DeclarationSegmentKind::Initializer => "initializer",
        DeclarationSegmentKind::LocalFunction => "local_function",
        DeclarationSegmentKind::Lambda => "lambda",
        DeclarationSegmentKind::Closure => "closure",
        DeclarationSegmentKind::AnonymousCallable => "anonymous_callable",
    }
}

struct OptionalId<T>(Option<T>);

impl<T: fmt::Display> fmt::Display for OptionalId<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(value) => value.fmt(formatter),
            None => formatter.write_str("none"),
        }
    }
}

const fn optional_id<T>(id: Option<T>) -> OptionalId<T> {
    OptionalId(id)
}

fn write_id_list<T: fmt::Display>(
    writer: &mut dyn fmt::Write,
    ids: impl IntoIterator<Item = T>,
) -> fmt::Result {
    writer.write_char('(')?;
    let mut first = true;
    for id in ids {
        if !first {
            writer.write_char(' ')?;
        }
        first = false;
        write!(writer, "{id}")?;
    }
    writer.write_char(')')
}

fn write_quoted_display(writer: &mut dyn fmt::Write, value: impl fmt::Display) -> fmt::Result {
    writer.write_char('"')?;
    write!(writer, "{value}")?;
    writer.write_char('"')
}

fn open_artifact(state: &mut RenderState, key: &SemanticArtifactKey) -> bool {
    if !state.writer.open(0, "(semantic-ir") {
        return false;
    }
    if !state.writer.open_with(1, |writer| {
        writer.write_str("(artifact :fingerprint ")?;
        write_quoted_display(writer, key.fingerprint())
    }) {
        return false;
    }
    if !state.source_row_with(2, |writer| {
        writer.write_str("(source :mount ")?;
        write_quoted_display(writer, key.mount())?;
        write!(
            writer,
            " :path {} :language {})",
            quoted(key.path().as_str()),
            quoted(key.language().stable_label()),
        )
    }) {
        return false;
    }
    if !state.row_with(2, |writer| match key.revision() {
        SourceRevision::Disk { content } => {
            writer.write_str("(revision :kind \"disk\" :content ")?;
            write_quoted_display(writer, content)?;
            writer.write_char(')')
        }
        SourceRevision::Overlay { content, snapshot } => {
            writer.write_str("(revision :kind \"overlay\" :content ")?;
            write_quoted_display(writer, content)?;
            writer.write_str(" :snapshot ")?;
            write_quoted_display(writer, snapshot)?;
            writer.write_char(')')
        }
    }) || !state.row_with(2, |writer| {
        write!(
            writer,
            "(adapter :name {} :fingerprint ",
            quoted(key.adapter().name()),
        )?;
        write_quoted_display(writer, key.adapter().fingerprint())?;
        writer.write_char(')')
    }) || !state.row_with(2, |writer| {
        writer.write_str("(versions :semantic-ir ")?;
        write_quoted_display(writer, key.ir_version())?;
        writer.write_str(" :configuration ")?;
        write_quoted_display(writer, key.configuration())?;
        writer.write_str(" :dependencies ")?;
        write_quoted_display(writer, key.dependencies())?;
        writer.write_char(')')
    }) {
        return false;
    }
    true
}

fn render_capabilities(state: &mut RenderState, capabilities: &SemanticCapabilities) -> bool {
    if !state.writer.open(2, "(capabilities") {
        return false;
    }
    for (capability, support) in capabilities.iter() {
        if !state.row_with(3, |writer| {
            write!(
                writer,
                "(capability :name {} :support {})",
                quoted(capability.label()),
                quoted(capability_support_label(support))
            )
        }) {
            return false;
        }
    }
    state.writer.close(2)
}

const fn capability_support_label(support: CapabilitySupport) -> &'static str {
    match support {
        CapabilitySupport::Complete => "complete",
        CapabilitySupport::Partial => "partial",
        CapabilitySupport::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, BasicBlock, BlockId, ConfigurationFingerprint, ContentIdentity,
        ControlEdgeKind, DeclarationLocator, DeclarationSegment, DeclarationSegmentKind,
        DependencyFingerprint, EvidenceId, ProcedureKind, ProcedureSemanticsParts, ProgramPointId,
        SemanticBudget, SemanticCapabilities, SemanticCapability, SemanticEvent, SemanticGapId,
        SemanticGapImpact, SemanticGapImpacts, SemanticIrVersion, SemanticLanguage,
        SemanticLocator, SemanticRole, SemanticWork, SourceAnchor, SourceMappingId,
        SourceMappingKind, SourcePosition, SourceRevision, SourceSpan, StableDigest,
        WorkspaceMountId, WorkspaceRelativePath,
    };

    #[test]
    fn bounded_writer_escapes_strings_and_balances_truncation() {
        let mut writer = BalancedWriter::new(
            MIN_OUTPUT_BYTES,
            TRUNCATION_RESERVE,
            TruncationStyle::ReasonAttribute,
        );
        assert!(writer.open(0, "(semantic-ir"));
        assert!(writer.open(1, "(procedure :id 0"));
        assert!(writer.line(2, &format!("(label {})", quoted("a\\\"b\n(c)"))));
        writer.truncate("row limit reached");
        let (output, truncated) = writer.finish();

        assert!(truncated);
        assert!(output.contains("a\\\\\\\"b\\n(c)"), "{output:?}");
        assert!(output.contains("(truncated :reason \"row limit reached\")"));
        assert!(output.len() <= MIN_OUTPUT_BYTES);
        assert_balanced(&output);
    }

    #[test]
    fn streamed_quoting_preserves_json_string_escaping() {
        let mut value: String = ('\0'..='\u{1f}').collect();
        value.push_str("quoted \" slash \\ unicode é \u{2028}");

        assert_eq!(
            quoted(&value).to_string(),
            serde_json::to_string(&value).unwrap()
        );
    }

    #[test]
    fn limits_reject_zero_or_too_small_dimensions() {
        for limits in [
            SemanticIrLimits {
                max_procedures: 0,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_rows: 0,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_source_entries: 0,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_output_bytes: MIN_OUTPUT_BYTES - 1,
                ..SemanticIrLimits::default()
            },
        ] {
            assert_eq!(limits.validate(), Err(SemanticRenderError::InvalidLimits));
        }
    }

    #[test]
    fn render_state_marks_each_non_output_budget() {
        let cases = [
            (
                SemanticIrLimits {
                    max_procedures: 1,
                    ..SemanticIrLimits::default()
                },
                "procedure limit reached",
                0,
            ),
            (
                SemanticIrLimits {
                    max_rows: 1,
                    ..SemanticIrLimits::default()
                },
                "row limit reached",
                1,
            ),
            (
                SemanticIrLimits {
                    max_source_entries: 1,
                    ..SemanticIrLimits::default()
                },
                "source entry limit reached",
                2,
            ),
        ];

        for (limits, reason, dimension) in cases {
            let mut state = RenderState::new(limits);
            assert!(state.writer.open(0, "(semantic-ir"));
            match dimension {
                0 => {
                    assert!(state.begin_procedure());
                    assert!(!state.begin_procedure());
                }
                1 => {
                    assert!(state.row_with(1, |writer| writer.write_str("(row 0)")));
                    assert!(!state.row_with(1, |writer| writer.write_str("(row 1)")));
                }
                2 => {
                    assert!(state.source_row_with(1, |writer| writer.write_str("(source 0)")));
                    assert!(!state.source_row_with(1, |writer| writer.write_str("(source 1)")));
                }
                _ => unreachable!(),
            }
            let (output, truncated) = state.writer.finish();
            assert!(truncated);
            assert!(output.contains(reason), "{output:?}");
            assert_balanced(&output);
        }
    }

    #[test]
    fn artifact_rendering_is_deterministic_scoped_and_source_backed() {
        let artifact = fixture_artifact(2);
        let first = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();
        let second = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert_eq!(first, second);
        assert!(!first.truncated);
        assert!(first.semantic_ir.contains(":path \"src/render.ts\""));
        assert!(first.semantic_ir.contains("procedure\\\"0\\nline"));
        assert!(first.semantic_ir.contains("(capability :name \"captures\""));
        let scope = first.semantic_ir.find("(artifact :fingerprint").unwrap();
        let local_id = first.semantic_ir.find("(procedure :id 0").unwrap();
        assert!(scope < local_id, "{}", first.semantic_ir);
        assert!(!first.semantic_ir.contains("/Users/"));
        assert_balanced(&first.semantic_ir);
    }

    #[test]
    fn control_edge_ids_and_point_adjacency_are_rendered_deterministically() {
        let artifact = fixture_artifact(1);
        let procedure = &artifact.procedures()[0];
        let first = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();
        let second = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert_eq!(first, second);
        assert!(!first.truncated);
        assert_eq!(
            first.semantic_ir.matches("(control-edge :id ").count(),
            procedure.cfg().edges().len()
        );
        assert!(first.semantic_ir.contains(
            "(control-edge :id 0 :source-point 0 :target-point 2 :kind \"exceptional\" :source 0 :evidence 0)"
        ));
        assert!(first.semantic_ir.contains(
            "(program-point :id 0 :block 0 :source 0 :evidence 0 :predecessor-edges () :successor-edges (0 1)"
        ));

        for point in procedure.points() {
            let mut predecessors = String::new();
            write_id_list(
                &mut predecessors,
                procedure
                    .predecessor_edges(point.id)
                    .map(|(edge_id, _)| edge_id),
            )
            .unwrap();
            let mut successors = String::new();
            write_id_list(
                &mut successors,
                procedure
                    .successor_edges(point.id)
                    .map(|(edge_id, _)| edge_id),
            )
            .unwrap();
            let expected = format!(
                "(program-point :id {} :block {} :source {} :evidence {} :predecessor-edges {} :successor-edges {}",
                point.id, point.block, point.source, point.evidence, predecessors, successors,
            );
            assert!(first.semantic_ir.contains(&expected), "{expected:?}");
        }

        for (index, edge) in procedure.cfg().edges().iter().enumerate() {
            let edge_id = ControlEdgeId::try_from_index(index).unwrap();
            let mut expected = String::new();
            write_control_edge(&mut expected, edge_id, edge).unwrap();
            assert!(first.semantic_ir.contains(&expected), "{expected:?}");
        }
        assert_balanced(&first.semantic_ir);
    }

    #[test]
    fn high_degree_adjacency_rows_truncate_transactionally_and_stay_balanced() {
        const DEGREE: usize = 4_096;
        let artifact = fixture_high_degree_artifact(DEGREE);
        let procedure = &artifact.procedures()[0];
        assert!(procedure.successor_edges(ProgramPointId::new(0)).len() > DEGREE);
        assert!(procedure.predecessor_edges(ProgramPointId::new(1)).len() > DEGREE);

        for point_id in [ProgramPointId::new(0), ProgramPointId::new(1)] {
            let limits = SemanticIrLimits {
                max_output_bytes: 512,
                ..SemanticIrLimits::default()
            };
            let mut state = RenderState::new(limits);
            assert!(state.writer.open(0, "(semantic-ir"));
            assert!(state.writer.open(1, "(program-points"));
            let point = procedure.point(point_id).unwrap();

            assert!(!render_point(&mut state, procedure, point));
            let (output, truncated) = state.writer.finish();

            assert!(truncated);
            assert!(output.contains("output byte limit reached"), "{output:?}");
            assert!(!output.contains(&format!("(program-point :id {point_id} ")));
            assert!(output.len() <= limits.max_output_bytes);
            assert_balanced(&output);
        }
    }

    #[test]
    fn selected_procedure_keeps_artifact_scope_and_lexical_parent() {
        let artifact = fixture_artifact(3);
        let rendered = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Procedure(ProcedureId::new(2)),
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.semantic_ir.contains("(artifact :fingerprint"));
        assert!(
            rendered
                .semantic_ir
                .contains("(procedure :id 2 :kind \"lambda\" :parent 1")
        );
        assert!(!rendered.semantic_ir.contains("(procedure :id 0"));
        assert!(!rendered.semantic_ir.contains("(procedure :id 1"));
        assert_balanced(&rendered.semantic_ir);

        assert_eq!(
            render_semantic_ir(
                &artifact,
                SemanticIrSelection::Procedure(ProcedureId::new(9)),
                SemanticIrLimits::default(),
            ),
            Err(SemanticRenderError::UnknownProcedure(ProcedureId::new(9)))
        );
    }

    #[test]
    fn artifact_renderer_marks_every_budget_and_stays_balanced() {
        let artifact = fixture_artifact(3);
        let limits = [
            SemanticIrLimits {
                max_procedures: 1,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_rows: 10,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_source_entries: 1,
                ..SemanticIrLimits::default()
            },
            SemanticIrLimits {
                max_output_bytes: MIN_OUTPUT_BYTES,
                ..SemanticIrLimits::default()
            },
        ];

        for limits in limits {
            let rendered =
                render_semantic_ir(&artifact, SemanticIrSelection::Artifact, limits).unwrap();
            assert!(rendered.truncated, "limits: {limits:?}");
            assert!(rendered.semantic_ir.contains("(truncated :reason"));
            assert!(rendered.semantic_ir.len() <= limits.max_output_bytes);
            assert_balanced(&rendered.semantic_ir);
        }
    }

    #[test]
    fn new_target_continuation_gap_and_language_capture_fields_are_rendered() {
        let locator = fixture_artifact(1).procedures()[0].locator().clone();
        let call_site = SemanticCallSite {
            id: super::super::ids::CallSiteId::new(0),
            point: ProgramPointId::new(4),
            callee: super::super::ids::ValueId::new(0),
            receiver: None,
            arguments: Box::new([super::super::ir::SemanticCallArgument::direct(
                super::super::ids::ValueId::new(1),
            )]),
            result: None,
            thrown: None,
            declared_targets: CallableTargetResolution::ExceededBudget(Box::new([
                CallableTarget::Unmaterialized(locator),
            ])),
            target_evidence: EvidenceId::new(7),
            normal_continuation: ControlContinuation::Absent,
            exceptional_continuation: ControlContinuation::ExceededBudget,
            source: SourceMappingId::new(2),
            evidence: EvidenceId::new(3),
        };
        let mut call_rendered = String::new();
        write_call_site(&mut call_rendered, &call_site).unwrap();
        assert!(call_rendered.contains(":declared-targets"));
        assert!(call_rendered.contains(":kind \"unmaterialized\""));
        assert!(call_rendered.contains(":target-evidence 7"));
        assert!(call_rendered.contains(":outcome \"absent\""));
        assert!(call_rendered.contains(":outcome \"exceeded_budget\""));

        let mut budget = SemanticBudget::uniform(1).unwrap();
        let exceeded = budget
            .charge(SemanticWork {
                program_points: 2,
                ..SemanticWork::default()
            })
            .unwrap_err();
        let gap = SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(4),
            subject: SemanticGapSubject::CallContinuation {
                call_site: super::super::ids::CallSiteId::new(0),
                kind: super::super::ir::CallContinuationKind::Exceptional,
            },
            capability: SemanticCapability::ExceptionalCallContinuation,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation)
                .with(SemanticGapImpact::ReturnTransfer),
            kind: super::super::ir::SemanticGapKind::ExceededBudget,
            budget: Some(exceeded),
            detail: "bounded target proof".into(),
            source: SourceMappingId::new(2),
            evidence: EvidenceId::new(3),
        };
        let mut gap_rendered = String::new();
        write_gap(&mut gap_rendered, &gap).unwrap();
        assert!(gap_rendered.contains(":subject (subject :kind \"call_continuation\""));
        assert!(gap_rendered.contains(":continuation-kind \"exceptional\""));
        assert!(gap_rendered.contains(":impacts (\"call_evaluation\" \"return_transfer\")"));
        assert!(gap_rendered.contains(":dimension \"program_points\" :limit 1 :attempted 2"));

        let capture = CaptureBinding {
            id: super::super::ids::CaptureId::new(0),
            point: ProgramPointId::new(1),
            callable: super::super::ids::ValueId::new(0),
            target: ProcedureId::new(1),
            environment: super::super::ids::AllocationId::new(0),
            captured: CaptureSource::Value(super::super::ids::ValueId::new(1)),
            destination: super::super::ids::MemoryLocationId::new(0),
            mode: super::super::ir::CaptureMode::LanguageDefined("borrowed-ref".into()),
            source: SourceMappingId::new(2),
            evidence: EvidenceId::new(3),
        };
        let mut capture_rendered = String::new();
        write_capture(&mut capture_rendered, &capture).unwrap();
        assert!(capture_rendered.contains(":mode \"language_defined\""));
        assert!(capture_rendered.contains(":language-mode \"borrowed-ref\""));
    }

    #[test]
    fn multi_megabyte_gap_detail_is_rejected_without_retaining_a_partial_row() {
        const DETAIL_BYTES: usize = 4 * 1024 * 1024;
        let artifact =
            fixture_feature_artifact_with_gap_detail("x".repeat(DETAIL_BYTES).into_boxed_str());
        let limits = SemanticIrLimits {
            max_output_bytes: 64 * 1024,
            ..SemanticIrLimits::default()
        };

        let rendered =
            render_semantic_ir(&artifact, SemanticIrSelection::Artifact, limits).unwrap();

        assert!(rendered.truncated);
        assert!(rendered.semantic_ir.len() <= limits.max_output_bytes);
        assert!(rendered.semantic_ir.contains("output byte limit reached"));
        assert!(
            !rendered.semantic_ir.contains(&"x".repeat(1_024)),
            "the rejected gap row must be rolled back instead of retained partially"
        );
        assert_balanced(&rendered.semantic_ir);
    }

    #[test]
    fn callable_capture_gap_and_evidence_details_are_explicit_and_escaped() {
        let artifact = fixture_feature_artifact();
        let rendered = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Artifact,
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert!(
            rendered
                .semantic_ir
                .contains(":effect \"callable_creation\"")
        );
        assert!(
            rendered
                .semantic_ir
                .contains(":effect \"callable_reference\"")
        );
        assert!(
            rendered
                .semantic_ir
                .contains(":callable-kind \"bound_method\"")
        );
        assert!(
            rendered
                .semantic_ir
                .contains(":target-resolution \"proven\"")
        );
        assert!(rendered.semantic_ir.contains(":procedure 1"));
        assert!(rendered.semantic_ir.contains(":bound-receiver 1"));
        assert!(
            rendered
                .semantic_ir
                .contains(":source-kind \"location\" :source-location 0")
        );
        assert!(
            rendered
                .semantic_ir
                .contains(":destination (procedure 1 :memory-location 0)")
        );
        assert!(rendered.semantic_ir.contains(":lexical-parent 0"));
        assert!(rendered.semantic_ir.contains(":mode \"mutable_cell\""));
        assert!(rendered.semantic_ir.contains(":kind \"lexical_cell\""));
        assert!(rendered.semantic_ir.contains(":binding-value 2"));
        assert!(
            rendered
                .semantic_ir
                .contains(":access-kind \"lexical_cell\"")
        );
        assert!(rendered.semantic_ir.contains(":kind \"unsupported\""));
        assert!(
            rendered
                .semantic_ir
                .contains("adapter said \\\"no\\\"\\nnext")
        );
        assert_balanced(&rendered.semantic_ir);
    }

    #[test]
    fn deeply_nested_procedure_selection_is_stack_safe() {
        const DEPTH: usize = 4_096;
        let artifact = fixture_artifact(DEPTH);
        let selected = ProcedureId::try_from_index(DEPTH - 1).unwrap();
        let rendered = render_semantic_ir(
            &artifact,
            SemanticIrSelection::Procedure(selected),
            SemanticIrLimits::default(),
        )
        .unwrap();

        assert!(!rendered.truncated);
        assert!(rendered.semantic_ir.contains(&format!(
            "(procedure :id {} :kind \"lambda\" :parent {}",
            DEPTH - 1,
            DEPTH - 2
        )));
        assert_balanced(&rendered.semantic_ir);
    }

    fn fixture_artifact(procedure_count: usize) -> SemanticArtifact {
        let key = fixture_key();
        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .complete(SemanticCapability::ExceptionalControlFlow)
            .partial(SemanticCapability::Captures)
            .build();
        let procedures = (0..procedure_count)
            .map(|index| fixture_procedure(&key, index))
            .collect();
        SemanticArtifact::try_new(key, capabilities, procedures).unwrap()
    }

    fn fixture_high_degree_artifact(degree: usize) -> SemanticArtifact {
        let key = fixture_key();
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut procedure = fixture_procedure(&key, 0);
        for _ in 0..degree {
            let point_id = ProgramPointId::try_from_index(procedure.points.len()).unwrap();
            procedure.points.push(ProgramPoint {
                id: point_id,
                block: BlockId::new(0),
                events: Vec::new().into_boxed_slice(),
                source,
                evidence,
            });
            procedure.control_edges.push(ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: point_id,
                kind: ControlEdgeKind::SwitchCase,
                source,
                evidence,
            });
            procedure.control_edges.push(ControlEdge {
                source_point: point_id,
                target_point: ProgramPointId::new(1),
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            });
        }
        procedure.blocks[0].points = procedure
            .points
            .iter()
            .map(|point| point.id)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .complete(SemanticCapability::ExceptionalControlFlow)
            .build();
        SemanticArtifact::try_new(key, capabilities, vec![procedure]).unwrap()
    }

    fn fixture_feature_artifact() -> SemanticArtifact {
        fixture_feature_artifact_with_gap_detail("adapter said \"no\"\nnext".into())
    }

    fn fixture_feature_artifact_with_gap_detail(detail: Box<str>) -> SemanticArtifact {
        let key = fixture_key();
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut outer = fixture_procedure(&key, 0);
        let mut child = fixture_procedure(&key, 1);

        outer.values = vec![
            SemanticValue {
                id: super::super::ids::ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source,
                evidence,
            },
            SemanticValue {
                id: super::super::ids::ValueId::new(1),
                kind: SemanticValueKind::Receiver,
                source,
                evidence,
            },
            SemanticValue {
                id: super::super::ids::ValueId::new(2),
                kind: SemanticValueKind::Local,
                source,
                evidence,
            },
            SemanticValue {
                id: super::super::ids::ValueId::new(3),
                kind: SemanticValueKind::Callable,
                source,
                evidence,
            },
            SemanticValue {
                id: super::super::ids::ValueId::new(4),
                kind: SemanticValueKind::Temporary,
                source,
                evidence,
            },
        ];
        outer.allocations = vec![AllocationSite {
            id: super::super::ids::AllocationId::new(0),
            point: ProgramPointId::new(1),
            result: super::super::ids::ValueId::new(4),
            kind: AllocationKind::ClosureEnvironment,
            source,
            evidence,
        }];
        outer.memory_locations = vec![MemoryLocation {
            id: super::super::ids::MemoryLocationId::new(0),
            kind: MemoryLocationKind::LexicalCell {
                binding: super::super::ids::ValueId::new(2),
            },
            source,
            evidence,
        }];
        child.memory_locations = vec![MemoryLocation {
            id: super::super::ids::MemoryLocationId::new(0),
            kind: MemoryLocationKind::Capture {
                lexical_parent: ProcedureId::new(0),
            },
            source,
            evidence,
        }];
        outer.captures = vec![CaptureBinding {
            id: super::super::ids::CaptureId::new(0),
            point: ProgramPointId::new(1),
            callable: super::super::ids::ValueId::new(0),
            target: ProcedureId::new(1),
            environment: super::super::ids::AllocationId::new(0),
            captured: CaptureSource::Location(super::super::ids::MemoryLocationId::new(0)),
            destination: super::super::ids::MemoryLocationId::new(0),
            mode: super::super::ir::CaptureMode::MutableCell,
            source,
            evidence,
        }];
        outer.gaps = vec![SemanticGap {
            id: SemanticGapId::new(0),
            point: ProgramPointId::new(2),
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::ExceptionalControlFlow,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::ReturnTransfer),
            kind: super::super::ir::SemanticGapKind::Unsupported,
            budget: None,
            detail,
            source,
            evidence,
        }];
        outer.blocks = vec![BasicBlock {
            id: BlockId::new(0),
            points: (0_u32..5).map(ProgramPointId::new).collect(),
            source,
            evidence,
        }];
        outer.points = vec![
            fixture_point(0, vec![SemanticEffect::Entry], source, evidence),
            fixture_point(
                1,
                vec![
                    SemanticEffect::Allocation {
                        allocation: super::super::ids::AllocationId::new(0),
                    },
                    SemanticEffect::MemoryStore {
                        kind: super::super::ir::MemoryAccessKind::LexicalCell,
                        location: super::super::ids::MemoryLocationId::new(0),
                        value: super::super::ids::ValueId::new(2),
                    },
                    SemanticEffect::CallableCreation {
                        result: super::super::ids::ValueId::new(0),
                        callable: CallableValue {
                            kind: super::super::ir::CallableReferenceKind::Lambda,
                            targets: CallableTargetResolution::Proven(CallableTarget::Local(
                                ProcedureId::new(1),
                            )),
                            target_evidence: evidence,
                            bound_receiver: None,
                            environment: Some(super::super::ids::AllocationId::new(0)),
                        },
                    },
                    SemanticEffect::CaptureBind {
                        capture: super::super::ids::CaptureId::new(0),
                    },
                ],
                source,
                evidence,
            ),
            fixture_point(
                2,
                vec![
                    SemanticEffect::CallableReference {
                        result: super::super::ids::ValueId::new(3),
                        callable: CallableValue {
                            kind: super::super::ir::CallableReferenceKind::BoundMethod,
                            targets: CallableTargetResolution::Proven(CallableTarget::Local(
                                ProcedureId::new(1),
                            )),
                            target_evidence: evidence,
                            bound_receiver: Some(super::super::ids::ValueId::new(1)),
                            environment: None,
                        },
                    },
                    SemanticEffect::Gap {
                        gap: SemanticGapId::new(0),
                    },
                ],
                source,
                evidence,
            ),
            fixture_point(3, vec![SemanticEffect::NormalExit], source, evidence),
            fixture_point(4, vec![SemanticEffect::ExceptionalExit], source, evidence),
        ];
        outer.control_edges = vec![
            fixture_edge(0, 1, ControlEdgeKind::Normal, source, evidence),
            fixture_edge(1, 2, ControlEdgeKind::Normal, source, evidence),
            fixture_edge(2, 3, ControlEdgeKind::Normal, source, evidence),
            fixture_edge(2, 4, ControlEdgeKind::Exceptional, source, evidence),
        ];

        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .partial(SemanticCapability::ExceptionalControlFlow)
            .complete(SemanticCapability::Values)
            .complete(SemanticCapability::Allocations)
            .complete(SemanticCapability::LocalFlow)
            .complete(SemanticCapability::CallableReferences)
            .complete(SemanticCapability::Captures)
            .build();
        SemanticArtifact::try_new(key, capabilities, vec![outer, child]).unwrap()
    }

    fn fixture_point(
        id: u32,
        effects: Vec<SemanticEffect>,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> ProgramPoint {
        ProgramPoint {
            id: ProgramPointId::new(id),
            block: BlockId::new(0),
            events: effects
                .into_iter()
                .map(|effect| SemanticEvent::new(effect, source, evidence))
                .collect(),
            source,
            evidence,
        }
    }

    fn fixture_edge(
        source_point: u32,
        target_point: u32,
        kind: ControlEdgeKind,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> ControlEdge {
        ControlEdge {
            source_point: ProgramPointId::new(source_point),
            target_point: ProgramPointId::new(target_point),
            kind,
            source,
            evidence,
        }
    }

    fn fixture_key() -> SemanticArtifactKey {
        let digest = |label: &str| StableDigest::sha256(label);
        SemanticArtifactKey::new(
            WorkspaceMountId::from_digest(digest("mount")),
            WorkspaceRelativePath::new("src/render.ts").unwrap(),
            SemanticLanguage::Standard(Language::TypeScript),
            SourceRevision::Disk {
                content: ContentIdentity::from_digest(digest("content")),
            },
            AdapterSemanticsVersion::new("typescript", digest("adapter")).unwrap(),
            SemanticIrVersion::from_digest(digest("semantic-ir")),
            ConfigurationFingerprint::from_digest(digest("configuration")),
            DependencyFingerprint::from_digest(digest("dependencies")),
        )
    }

    fn fixture_procedure(key: &SemanticArtifactKey, index: usize) -> ProcedureSemanticsParts {
        let id = ProcedureId::try_from_index(index).unwrap();
        let offset = u32::try_from(index).unwrap();
        let start = SourcePosition::new(offset, offset, 0);
        let end = SourcePosition::new(offset + 1, offset, 1);
        let span = SourceSpan::new(start, end).unwrap();
        let anchor = SourceAnchor::new(span, offset);
        let name = format!("procedure\"{index}\nline");
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::Lambda, name, anchor, offset)
                .unwrap(),
        ])
        .unwrap();
        let locator = SemanticLocator::new(
            key.mount(),
            key.path().clone(),
            key.language(),
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut parts = ProcedureSemanticsParts::new(
            id,
            locator.clone(),
            if index == 0 {
                ProcedureKind::Function
            } else {
                ProcedureKind::Lambda
            },
            source,
            evidence,
        );
        parts.lexical_parent = index
            .checked_sub(1)
            .map(|parent| ProcedureId::try_from_index(parent).unwrap());
        parts.source_mappings = vec![SourceMapping {
            id: source,
            locator,
            kind: SourceMappingKind::Exact,
        }];
        parts.evidence_rows = vec![Evidence {
            id: evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: vec![source].into_boxed_slice(),
        }];
        parts.blocks = vec![BasicBlock {
            id: BlockId::new(0),
            points: vec![
                ProgramPointId::new(0),
                ProgramPointId::new(1),
                ProgramPointId::new(2),
            ]
            .into_boxed_slice(),
            source,
            evidence,
        }];
        parts.points = [
            SemanticEffect::Entry,
            SemanticEffect::NormalExit,
            SemanticEffect::ExceptionalExit,
        ]
        .into_iter()
        .enumerate()
        .map(|(point, effect)| ProgramPoint {
            id: ProgramPointId::try_from_index(point).unwrap(),
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(effect, source, evidence)].into_boxed_slice(),
            source,
            evidence,
        })
        .collect();
        parts.control_edges = vec![
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(1),
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ProgramPointId::new(0),
                target_point: ProgramPointId::new(2),
                kind: ControlEdgeKind::Exceptional,
                source,
                evidence,
            },
        ];
        parts
    }

    fn assert_balanced(value: &str) {
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for byte in value.bytes() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            match byte {
                b'"' => quoted = true,
                b'(' => depth += 1,
                b')' => {
                    depth = depth
                        .checked_sub(1)
                        .expect("unexpected closing parenthesis")
                }
                _ => {}
            }
        }
        assert!(!quoted, "unterminated string in {value:?}");
        assert_eq!(depth, 0, "unclosed form in {value:?}");
    }
}
