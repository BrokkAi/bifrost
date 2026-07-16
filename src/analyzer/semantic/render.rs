//! Deterministic, bounded rendering for semantic artifacts.
//!
//! The renderer is intentionally a view over validated semantic IR. It does
//! not parse source, resolve targets, or infer missing semantics.

use std::fmt;

use super::capabilities::{CapabilitySupport, SemanticCapabilities};
use super::ids::{
    DeclarationSegmentKind, ProcedureId, SemanticArtifactKey, SemanticLocator, SourceRevision,
};
use super::ir::{
    AllocationKind, AllocationSite, BasicBlock, CallableTarget, CallableTargetResolution,
    CallableValue, CaptureBinding, CaptureSource, ControlEdge, Evidence, EvidenceCompleteness,
    MemoryLocation, MemoryLocationKind, ProcedureSemantics, ProgramPoint, ProofStatus,
    SemanticArtifact, SemanticCallSite, SemanticEffect, SemanticEvent, SemanticGap, SemanticValue,
    SemanticValueKind, SourceMapping,
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
    if state.writer.truncated.is_none() {
        state.writer.close(1);
        state.writer.close(0);
    }
    let (semantic_ir, truncated) = state.writer.finish();
    Ok(RenderedSemanticIr {
        semantic_ir,
        truncated,
    })
}

struct BoundedWriter {
    output: String,
    max_output_bytes: usize,
    open_forms: usize,
    truncated: Option<&'static str>,
}

struct RenderState {
    limits: SemanticIrLimits,
    writer: BoundedWriter,
    rendered_procedures: usize,
    rendered_rows: usize,
    rendered_source_entries: usize,
}

impl RenderState {
    fn new(limits: SemanticIrLimits) -> Self {
        Self {
            writer: BoundedWriter::new(limits.max_output_bytes),
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

    fn row(&mut self, depth: usize, line: &str) -> bool {
        if self.rendered_rows >= self.limits.max_rows {
            self.writer.truncate("row limit reached");
            return false;
        }
        if !self.writer.line(depth, line) {
            return false;
        }
        self.rendered_rows += 1;
        true
    }

    fn open_row(&mut self, depth: usize, line: &str) -> bool {
        if self.rendered_rows >= self.limits.max_rows {
            self.writer.truncate("row limit reached");
            return false;
        }
        if !self.writer.open(depth, line) {
            return false;
        }
        self.rendered_rows += 1;
        true
    }

    fn source_row(&mut self, depth: usize, line: &str) -> bool {
        if self.rendered_source_entries >= self.limits.max_source_entries {
            self.writer.truncate("source entry limit reached");
            return false;
        }
        if !self.row(depth, line) {
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
    let parent = optional_id(procedure.lexical_parent());
    if !state.writer.open(
        2,
        &format!(
            "(procedure :id {} :kind {} :parent {} :source {} :evidence {} :entry {} :normal-exit {} :exceptional-exit {} :async {} :generator {} :static {} :synthetic {}",
            procedure.id(),
            quoted(procedure.kind().label()),
            parent,
            procedure.source(),
            procedure.evidence(),
            procedure.entry_point(),
            procedure.normal_exit_point(),
            procedure.exceptional_exit_point(),
            properties.is_async,
            properties.is_generator,
            properties.is_static,
            properties.is_synthetic,
        ),
    ) {
        return false;
    }
    if !state.source_row(
        3,
        &format!("(locator {})", format_locator(procedure.locator())),
    ) || !render_values(state, procedure)
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
        if !state.row(4, &format_value(value)) {
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
        if !state.row(4, &format_allocation(allocation)) {
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
        if !state.row(4, &format_memory_location(location)) {
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
        if !state.row(4, &format_capture(capture)) {
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
        if !state.row(4, &format_call_site(call_site)) {
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
        if !state.source_row(4, &format_source_mapping(mapping)) {
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
        if !state.row(4, &format_evidence(evidence)) {
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
        if !state.row(4, &format_gap(gap)) {
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
        if !state.row(4, &format_block(block)) {
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
        if !render_point(state, point) {
            return false;
        }
    }
    state.writer.close(3)
}

fn render_control_edges(state: &mut RenderState, procedure: &ProcedureSemantics) -> bool {
    if !state.writer.open(3, "(control-edges") {
        return false;
    }
    for edge in procedure.control_edges() {
        if !state.row(4, &format_control_edge(edge)) {
            return false;
        }
    }
    state.writer.close(3)
}

fn format_value(value: &SemanticValue) -> String {
    let mut line = format!(
        "(value :id {} :kind {}",
        value.id,
        quoted(value.kind.label())
    );
    match &value.kind {
        SemanticValueKind::Parameter { ordinal } => {
            line.push_str(&format!(" :ordinal {ordinal}"));
        }
        SemanticValueKind::LanguageDefined(kind) => {
            line.push_str(" :language-kind ");
            line.push_str(&quoted(kind));
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
    line.push_str(&format!(
        " :source {} :evidence {})",
        value.source, value.evidence
    ));
    line
}

fn format_allocation(allocation: &AllocationSite) -> String {
    let mut line = format!(
        "(allocation :id {} :point {} :result {} :kind {}",
        allocation.id,
        allocation.point,
        allocation.result,
        quoted(allocation.kind.label())
    );
    if let AllocationKind::LanguageDefined(kind) = &allocation.kind {
        line.push_str(" :language-kind ");
        line.push_str(&quoted(kind));
    }
    line.push_str(&format!(
        " :source {} :evidence {})",
        allocation.source, allocation.evidence
    ));
    line
}

fn format_memory_location(location: &MemoryLocation) -> String {
    let mut line = format!(
        "(memory-location :id {} :kind {}",
        location.id,
        quoted(location.kind.label())
    );
    match &location.kind {
        MemoryLocationKind::Field { base, member } => {
            line.push_str(&format!(
                " :base {base} :member (locator {})",
                format_locator(member)
            ));
        }
        MemoryLocationKind::Static { member } => {
            line.push_str(&format!(" :member (locator {})", format_locator(member)));
        }
        MemoryLocationKind::Index { base, index } => {
            line.push_str(&format!(" :base {base} :index {}", optional_id(*index)));
        }
        MemoryLocationKind::LexicalCell { binding } => {
            line.push_str(&format!(" :binding-value {binding}"));
        }
        MemoryLocationKind::Capture { lexical_parent } => {
            line.push_str(&format!(" :lexical-parent {lexical_parent}"));
        }
    }
    line.push_str(&format!(
        " :source {} :evidence {})",
        location.source, location.evidence
    ));
    line
}

fn format_capture(capture: &CaptureBinding) -> String {
    let source = match capture.captured {
        CaptureSource::Value(value) => format!(" :source-value {value}"),
        CaptureSource::Location(location) => format!(" :source-location {location}"),
    };
    format!(
        "(capture :id {} :point {} :callable {} :target-procedure {} :environment {} :source-kind {}{} :destination (procedure {} :memory-location {}) :mode {} :source {} :evidence {})",
        capture.id,
        capture.point,
        capture.callable,
        capture.target,
        capture.environment,
        quoted(capture.captured.label()),
        source,
        capture.target,
        capture.destination,
        quoted(capture.mode.label()),
        capture.source,
        capture.evidence,
    )
}

fn format_call_site(call_site: &SemanticCallSite) -> String {
    format!(
        "(call-site :id {} :point {} :callee {} :receiver {} :arguments {} :result {} :thrown {} {} :normal-continuation {} :exceptional-continuation {} :source {} :evidence {})",
        call_site.id,
        call_site.point,
        call_site.callee,
        optional_id(call_site.receiver),
        id_list(call_site.arguments.iter().copied()),
        optional_id(call_site.result),
        optional_id(call_site.thrown),
        format_target_resolution(&call_site.targets),
        call_site.normal_continuation,
        call_site.exceptional_continuation,
        call_site.source,
        call_site.evidence,
    )
}

fn format_source_mapping(mapping: &SourceMapping) -> String {
    format!(
        "(source-mapping :id {} :kind {} :locator (locator {}))",
        mapping.id,
        quoted(mapping.kind.label()),
        format_locator(&mapping.locator)
    )
}

fn format_evidence(evidence: &Evidence) -> String {
    let mut line = format!(
        "(evidence-row :id {} :proof {}",
        evidence.id,
        quoted(evidence.proof.label())
    );
    if let ProofStatus::Unproven(detail) = &evidence.proof {
        line.push_str(" :proof-detail ");
        line.push_str(&quoted(detail));
    }
    line.push_str(" :completeness ");
    line.push_str(&quoted(evidence.completeness.label()));
    if let EvidenceCompleteness::Partial(detail) = &evidence.completeness {
        line.push_str(" :completeness-detail ");
        line.push_str(&quoted(detail));
    }
    line.push_str(" :sources ");
    line.push_str(&id_list(evidence.sources.iter().copied()));
    line.push(')');
    line
}

fn format_gap(gap: &SemanticGap) -> String {
    format!(
        "(gap :id {} :point {} :capability {} :kind {} :detail {} :source {} :evidence {})",
        gap.id,
        gap.point,
        quoted(gap.capability.label()),
        quoted(gap.kind.label()),
        quoted(&gap.detail),
        gap.source,
        gap.evidence,
    )
}

fn format_block(block: &BasicBlock) -> String {
    format!(
        "(block :id {} :points {} :source {} :evidence {})",
        block.id,
        id_list(block.points.iter().copied()),
        block.source,
        block.evidence,
    )
}

fn render_point(state: &mut RenderState, point: &ProgramPoint) -> bool {
    if !state.open_row(
        4,
        &format!(
            "(program-point :id {} :block {} :source {} :evidence {}",
            point.id, point.block, point.source, point.evidence
        ),
    ) {
        return false;
    }
    for (index, event) in point.events.iter().enumerate() {
        if !state.row(5, &format_event(index, event)) {
            return false;
        }
    }
    state.writer.close(4)
}

fn format_event(index: usize, event: &SemanticEvent) -> String {
    let mut line = format!(
        "(event :index {index} :effect {}",
        quoted(event.effect.label())
    );
    match &event.effect {
        SemanticEffect::Entry | SemanticEffect::NormalExit | SemanticEffect::ExceptionalExit => {}
        SemanticEffect::Assignment { target, value } => {
            line.push_str(&format!(" :target {target} :value {value}"));
        }
        SemanticEffect::ValueFlow {
            kind,
            source,
            target,
        } => {
            line.push_str(&format!(
                " :flow-kind {} :flow-source {source} :target {target}",
                quoted(kind.label())
            ));
        }
        SemanticEffect::Allocation { allocation } => {
            line.push_str(&format!(" :allocation {allocation}"));
        }
        SemanticEffect::MemoryLoad {
            kind,
            location,
            result,
        } => {
            line.push_str(&format!(
                " :access-kind {} :location {location} :result {result}",
                quoted(kind.label())
            ));
        }
        SemanticEffect::MemoryStore {
            kind,
            location,
            value,
        } => {
            line.push_str(&format!(
                " :access-kind {} :location {location} :value {value}",
                quoted(kind.label())
            ));
        }
        SemanticEffect::CallableCreation { result, callable }
        | SemanticEffect::CallableReference { result, callable } => {
            line.push_str(&format!(" :result {result} "));
            line.push_str(&format_callable(callable));
        }
        SemanticEffect::CaptureBind { capture } => {
            line.push_str(&format!(" :capture {capture}"));
        }
        SemanticEffect::Invoke { call_site } => {
            line.push_str(&format!(" :call-site {call_site}"));
        }
        SemanticEffect::CallContinuation { call_site, kind } => {
            line.push_str(&format!(
                " :call-site {call_site} :continuation-kind {}",
                quoted(kind.label())
            ));
        }
        SemanticEffect::ProcedureReturn { value } => {
            line.push_str(&format!(" :value {}", optional_id(*value)));
        }
        SemanticEffect::Throw { value } => {
            line.push_str(&format!(" :value {}", optional_id(*value)));
        }
        SemanticEffect::AsyncSuspend {
            awaited,
            normal_resume,
            exceptional_resume,
        } => {
            line.push_str(&format!(
                " :awaited {} :normal-resume {normal_resume} :exceptional-resume {exceptional_resume}",
                optional_id(*awaited)
            ));
        }
        SemanticEffect::AsyncResume {
            suspend,
            kind,
            result,
        } => {
            line.push_str(&format!(
                " :suspend {suspend} :resume-kind {} :result {}",
                quoted(kind.label()),
                optional_id(*result)
            ));
        }
        SemanticEffect::Gap { gap } => {
            line.push_str(&format!(" :gap {gap}"));
        }
    }
    line.push_str(&format!(
        " :source {} :evidence {})",
        event.source, event.evidence
    ));
    line
}

fn format_callable(callable: &CallableValue) -> String {
    format!(
        ":callable-kind {} {} :bound-receiver {} :environment {}",
        quoted(callable.kind.label()),
        format_target_resolution(&callable.targets),
        optional_id(callable.bound_receiver),
        optional_id(callable.environment),
    )
}

fn format_target_resolution(resolution: &CallableTargetResolution) -> String {
    let mut rendered = format!(
        ":target-resolution {} :targets (",
        quoted(resolution.label())
    );
    for target in resolution.candidates() {
        match target {
            CallableTarget::Local(procedure) => rendered.push_str(&format!(
                "(target :kind {} :procedure {procedure})",
                quoted(target.label())
            )),
            CallableTarget::External(locator) => rendered.push_str(&format!(
                "(target :kind {} :locator (locator {}))",
                quoted(target.label()),
                format_locator(locator)
            )),
        }
    }
    rendered.push(')');
    rendered
}

fn format_control_edge(edge: &ControlEdge) -> String {
    format!(
        "(control-edge :source-point {} :target-point {} :kind {} :source {} :evidence {})",
        edge.source_point,
        edge.target_point,
        quoted(edge.kind.label()),
        edge.source,
        edge.evidence,
    )
}

fn format_locator(locator: &SemanticLocator) -> String {
    let anchor = locator.anchor();
    let span = anchor.span();
    let start = span.start();
    let end = span.end();
    let mut rendered = format!(
        ":mount {} :path {} :language {} :role {} :byte-span (start-inclusive {} end-exclusive {}) :start (position :line0 {} :utf8-byte-column {}) :end (position :line0 {} :utf8-byte-column {}) :occurrence {} :declaration (",
        quoted(&locator.mount().to_string()),
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
    );
    for segment in locator.declaration().segments() {
        let segment_anchor = segment.anchor();
        let segment_span = segment_anchor.span();
        rendered.push_str(&format!(
            "(segment :kind {} :name {} :byte-span (start-inclusive {} end-exclusive {}) :occurrence {} :sibling-ordinal {})",
            quoted(declaration_segment_kind_label(segment.kind())),
            segment
                .name()
                .map(quoted)
                .unwrap_or_else(|| "none".to_string()),
            segment_span.start_byte(),
            segment_span.end_byte(),
            segment_anchor.occurrence(),
            segment.sibling_ordinal(),
        ));
    }
    rendered.push(')');
    rendered
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

fn optional_id<T: fmt::Display>(id: Option<T>) -> String {
    id.map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn id_list<T: fmt::Display>(ids: impl IntoIterator<Item = T>) -> String {
    let mut rendered = String::from("(");
    let mut first = true;
    for id in ids {
        if !first {
            rendered.push(' ');
        }
        first = false;
        rendered.push_str(&id.to_string());
    }
    rendered.push(')');
    rendered
}

fn open_artifact(state: &mut RenderState, key: &SemanticArtifactKey) -> bool {
    if !state.writer.open(0, "(semantic-ir") {
        return false;
    }
    if !state.writer.open(
        1,
        &format!(
            "(artifact :fingerprint {}",
            quoted(&key.fingerprint().to_string())
        ),
    ) {
        return false;
    }
    if !state.source_row(
        2,
        &format!(
            "(source :mount {} :path {} :language {})",
            quoted(&key.mount().to_string()),
            quoted(key.path().as_str()),
            quoted(key.language().stable_label()),
        ),
    ) {
        return false;
    }
    let revision = match key.revision() {
        SourceRevision::Disk { content } => format!(
            "(revision :kind \"disk\" :content {})",
            quoted(&content.to_string())
        ),
        SourceRevision::Overlay { content, snapshot } => format!(
            "(revision :kind \"overlay\" :content {} :snapshot {})",
            quoted(&content.to_string()),
            quoted(&snapshot.to_string())
        ),
    };
    if !state.row(2, &revision)
        || !state.row(
            2,
            &format!(
                "(adapter :name {} :fingerprint {})",
                quoted(key.adapter().name()),
                quoted(&key.adapter().fingerprint().to_string())
            ),
        )
        || !state.row(
            2,
            &format!(
                "(versions :semantic-ir {} :configuration {} :dependencies {})",
                quoted(&key.ir_version().to_string()),
                quoted(&key.configuration().to_string()),
                quoted(&key.dependencies().to_string())
            ),
        )
    {
        return false;
    }
    true
}

fn render_capabilities(state: &mut RenderState, capabilities: &SemanticCapabilities) -> bool {
    if !state.writer.open(2, "(capabilities") {
        return false;
    }
    for (capability, support) in capabilities.iter() {
        if !state.row(
            3,
            &format!(
                "(capability :name {} :support {})",
                quoted(capability.label()),
                quoted(capability_support_label(support))
            ),
        ) {
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

impl BoundedWriter {
    fn new(max_output_bytes: usize) -> Self {
        Self {
            output: String::new(),
            max_output_bytes,
            open_forms: 0,
            truncated: None,
        }
    }

    fn open(&mut self, depth: usize, line: &str) -> bool {
        if !self.push_line(depth, line, self.open_forms.saturating_add(1)) {
            return false;
        }
        self.open_forms += 1;
        true
    }

    fn line(&mut self, depth: usize, line: &str) -> bool {
        self.push_line(depth, line, self.open_forms)
    }

    fn close(&mut self, depth: usize) -> bool {
        let remaining = self.open_forms.saturating_sub(1);
        if !self.push_line(depth, ")", remaining) {
            return false;
        }
        self.open_forms = remaining;
        true
    }

    fn truncate(&mut self, reason: &'static str) {
        self.truncated.get_or_insert(reason);
    }

    fn push_line(&mut self, depth: usize, line: &str, prospective_open_forms: usize) -> bool {
        if self.truncated.is_some() {
            return false;
        }
        let indent = depth.saturating_mul(2);
        let needed = indent.saturating_add(line.len()).saturating_add(1);
        let reserve = TRUNCATION_RESERVE.saturating_add(prospective_open_forms);
        if self
            .output
            .len()
            .saturating_add(needed)
            .saturating_add(reserve)
            > self.max_output_bytes
        {
            self.truncate("output byte limit reached");
            return false;
        }
        self.output.extend(std::iter::repeat_n(' ', indent));
        self.output.push_str(line);
        self.output.push('\n');
        true
    }

    fn finish(mut self) -> (String, bool) {
        let truncated = self.truncated.is_some();
        if let Some(reason) = self.truncated {
            let marker = format!("(truncated :reason {})\n", quoted(reason));
            debug_assert!(
                self.output.len() + marker.len() + self.open_forms < self.max_output_bytes
            );
            self.output.push_str(&marker);
            self.output
                .extend(std::iter::repeat_n(')', self.open_forms));
            if self.open_forms > 0 {
                self.output.push('\n');
            }
            self.open_forms = 0;
        }
        debug_assert!(truncated || self.open_forms == 0);
        (self.output, truncated)
    }
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, BasicBlock, BlockId, ConfigurationFingerprint, ContentIdentity,
        ControlEdgeKind, DeclarationLocator, DeclarationSegment, DeclarationSegmentKind,
        DependencyFingerprint, EvidenceId, ProcedureKind, ProcedureSemanticsParts, ProgramPointId,
        SemanticCapabilities, SemanticCapability, SemanticEvent, SemanticGapId, SemanticIrVersion,
        SemanticLanguage, SemanticLocator, SemanticRole, SourceAnchor, SourceMappingId,
        SourceMappingKind, SourcePosition, SourceRevision, SourceSpan, StableDigest,
        WorkspaceMountId, WorkspaceRelativePath,
    };

    #[test]
    fn bounded_writer_escapes_strings_and_balances_truncation() {
        let mut writer = BoundedWriter::new(MIN_OUTPUT_BYTES);
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
                    assert!(state.row(1, "(row 0)"));
                    assert!(!state.row(1, "(row 1)"));
                }
                2 => {
                    assert!(state.source_row(1, "(source 0)"));
                    assert!(!state.source_row(1, "(source 1)"));
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

    fn fixture_feature_artifact() -> SemanticArtifact {
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
            capability: SemanticCapability::ExceptionalControlFlow,
            kind: super::super::ir::SemanticGapKind::Unsupported,
            detail: "adapter said \"no\"\nnext".into(),
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
