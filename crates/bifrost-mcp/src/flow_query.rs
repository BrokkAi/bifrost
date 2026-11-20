//! `flow_query`: flow and reachability questions between selected program
//! points (#13213).
//!
//! One implementation serves the MCP host and the CLI (`--tool flow_query`).
//! A question names points by file and position. Each point is selected with
//! [`select_program_point`], which refuses anything that is not exactly one
//! program point. The answer passes the engine's own typed outcome through:
//!
//! - value flow runs the label-free composition search (`search_value_flow`)
//!   with sources and sinks bound at the selected points;
//! - a control path runs `shortest_path` inside one procedure;
//! - a call path runs RQL `call_reachability` and is labelled callable-level.
//!
//! Complete or incomplete is the engine's. `not_reached` is reported only from
//! a complete search, and an incomplete answer always carries at least one
//! engine reason. Witnesses are the engine's own evidence, rendered one
//! [`SiteContextView`] per step. A path is never reconstructed here.

use std::collections::HashMap;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, shortest_path,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    CallSiteId, EvidenceCompleteness, IcfgProvider, ProcedureHandle, ProcedurePortHandle,
    ProgramPointHandle, ProofStatus, SemanticArtifact, SemanticArtifactKey, SemanticBudget,
    SemanticExecutionBudget, SemanticLocator, SemanticOutcome, SemanticRequest, SemanticValueKind,
    ValueAtPoint, WorkspaceIcfgProvider,
};
use brokk_bifrost_core::analyzer::model::{ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_flow::composition::UnitCompositionProvider;
use brokk_bifrost_flow::dataflow::WitnessTruncationCause;
use brokk_bifrost_flow::taint::compose::{
    BudgetLane, ComposeError, CompositionBudget, Hop, HopQuality, IncompleteCause, Incompleteness,
    OperationalCause, SourceSinkPair, search_value_flow,
};
use brokk_bifrost_flow::value_flow::{
    DurableCallSiteKey, DurableProcedureKey, ValueFlowCache, ValueFlowCarrier, ValueFlowEventKey,
    ValueFlowEventKind, ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec,
    ValueFlowSourceSpec, WorkspaceValueFlowProvider,
};
use brokk_bifrost_rql::CodeQueryExecutionLimits;
use brokk_bifrost_tools::program_point_selection::{
    PointSelectionRefusal, SelectedProgramPoint, SourcePosition, select_program_point,
};
use brokk_bifrost_tools::site_context::{
    NotAnalyzedCause, SiteAdmission, SiteAdmissionRefusal, SiteContext, SiteContextView,
    SiteLocation, SiteRole, SiteValue, UnknownValueCause, view,
};
use serde::{Deserialize, Serialize};

use crate::call_path_query;
use crate::flow::FlowWorkspaceState;

/// The issue that owns point-sensitive interprocedural control reachability.
const CONTROL_ACROSS_PROCEDURES_ISSUE: &str = "#13528";

/// A question about two sets of selected points.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowQueryParams {
    pub question: FlowQuestion,
    /// The origin points. One for every question except candidate sources.
    pub from: Vec<PointParams>,
    /// The destination points. One for every question except candidate sinks.
    pub to: Vec<PointParams>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowQuestion {
    /// Does the value at a point reach another point?
    ValueFlow,
    /// Is there a control path between two points of one procedure?
    ControlPath,
    /// Can the callable of one point reach a call site through static calls?
    CallPath,
}

/// One point: a file, a position and an optional role.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointParams {
    /// Workspace-relative path.
    pub path: String,
    /// 1-based line, with `column`.
    pub line: Option<usize>,
    /// 1-based column counting characters, with `line`.
    pub column: Option<usize>,
    /// Byte offset into the file. Use this or `line` with `column`.
    pub byte_offset: Option<usize>,
    /// Defaults to `value`.
    pub role: Option<PointRole>,
    /// The zero-based argument position of `role: argument`.
    pub argument_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointRole {
    Value,
    Call,
    Binding,
    Argument,
    Receiver,
    Return,
}

/// A request error the caller must correct. It is not an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowQueryInvalid(pub String);

/// A failure of `run_flow_query` that is not an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowQueryError {
    /// The request must be corrected.
    Invalid(String),
    /// A provider or store failed; an internal tool error, never invalid_params.
    Internal(String),
    /// Required site presentation could not be admitted by the existing owner.
    PresentationRefused(SiteAdmissionRefusal),
}

impl From<SiteAdmissionRefusal> for FlowQueryError {
    fn from(refusal: SiteAdmissionRefusal) -> Self {
        Self::PresentationRefused(refusal)
    }
}

impl From<FlowQueryInvalid> for FlowQueryError {
    fn from(invalid: FlowQueryInvalid) -> Self {
        Self::Invalid(invalid.0)
    }
}

impl FlowQueryParams {
    fn points(&self) -> impl Iterator<Item = &PointParams> {
        self.from.iter().chain(&self.to)
    }
}

impl PointParams {
    fn position(&self) -> Result<SourcePosition, FlowQueryInvalid> {
        match (self.line, self.column, self.byte_offset) {
            (Some(line), Some(column), None) => Ok(SourcePosition::LineColumn { line, column }),
            (None, None, Some(offset)) => Ok(SourcePosition::ByteOffset(offset)),
            _ => Err(FlowQueryInvalid(format!(
                "point `{}` needs either line with column or byte_offset",
                self.path
            ))),
        }
    }

    fn site_role(&self) -> Result<SiteRole, FlowQueryInvalid> {
        Ok(
            match (self.role.unwrap_or(PointRole::Value), self.argument_index) {
                (PointRole::Argument, Some(index)) => SiteRole::Argument { index, name: None },
                (PointRole::Argument, None) => {
                    return Err(FlowQueryInvalid(
                        "role argument needs argument_index".to_owned(),
                    ));
                }
                (_, Some(_)) => {
                    return Err(FlowQueryInvalid(
                        "argument_index applies only to role argument".to_owned(),
                    ));
                }
                (PointRole::Value, None) => SiteRole::Value,
                (PointRole::Call, None) => SiteRole::Call,
                (PointRole::Binding, None) => SiteRole::Binding,
                (PointRole::Receiver, None) => SiteRole::Receiver,
                (PointRole::Return, None) => SiteRole::Return,
            },
        )
    }
}

/// The answer, identical on both hosts.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowQueryResult {
    /// The engine answered each pair of points.
    Answered {
        question: FlowQuestion,
        engine: FlowEngine,
        granularity: FlowGranularity,
        /// One entry per (from, to) pair, from-major.
        results: Vec<PairAnswer>,
    },
    /// The question or a point is outside what V1 answers. Never an empty
    /// answer.
    Unsupported {
        question: FlowQuestion,
        reason: Unsupported,
    },
}

/// Which engine entry point answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEngine {
    /// `search_value_flow`.
    CompositionSearch,
    /// `shortest_path` over one procedure's control-flow graph.
    CfgShortestPath,
    /// RQL `call_reachability`.
    CallReachability,
}

/// What an answer says about order and position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowGranularity {
    /// The answer is about the selected points.
    Point,
    /// The answer is about the point's whole callable. It says nothing about
    /// order from the selected position (#13528).
    Callable,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairAnswer {
    pub from: SiteContextView,
    pub to: SiteContextView,
    pub answer: Answer,
    /// Present for `reached`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Reached,
    /// Only from a complete search.
    NotReached,
    Incomplete,
}

/// One or more items. An empty list cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmpty<T> {
    first: T,
    rest: Vec<T>,
}

impl<T> NonEmpty<T> {
    pub fn one(first: T) -> Self {
        Self {
            first,
            rest: Vec::new(),
        }
    }

    /// `None` for an empty list.
    pub fn from_vec(mut items: Vec<T>) -> Option<Self> {
        if items.is_empty() {
            return None;
        }
        let first = items.remove(0);
        Some(Self { first, rest: items })
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

impl<T: Serialize> Serialize for NonEmpty<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

/// Complete, or incomplete with the engine's reasons, unchanged.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Incomplete { reasons: NonEmpty<EngineReason> },
}

impl Completeness {
    fn from_reasons(reasons: Vec<EngineReason>) -> Self {
        NonEmpty::from_vec(reasons).map_or(Self::Complete, |reasons| Self::Incomplete { reasons })
    }

    fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// One typed engine reason. A variant is the engine's own typed outcome; the
/// `reason` text is the engine's own, where the engine carries one.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineReason {
    /// A composition-search `Incompleteness`.
    Composition {
        /// The variant name, snake case.
        incompleteness: &'static str,
        /// The engine's `IncompleteCause`.
        cause: CauseView,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        procedure: Option<ProcedureIdentity>,
    },
    /// The composition search failed to run.
    CompositionError { error: String },
    /// A selected point's value observation was not complete.
    EndpointObservation {
        /// `from[0]`, `to[1]` and so on.
        point: String,
        cause: NotAnalyzedCauseView,
    },
    /// `CfgAlgorithmError`.
    Cfg {
        error: CfgErrorKind,
        node_visits: Option<usize>,
        edge_visits: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<CfgLimit>,
    },
    /// An RQL diagnostic of the call-reachability query, as it states it.
    CallReachabilityDiagnostic {
        code: String,
        incompleteness: serde_json::Value,
        message: String,
    },
    /// A call-path coverage gap, as `CallPathCoverage::Incomplete` lists it.
    CallPathGap { gap: String },
    /// The call-reachability evidence was truncated (`CallPathEvidence::truncated`).
    CallPathTruncated,
    /// The call-reachability query's own completion was not complete.
    CallReachabilityCompletion {
        /// `proven_subset`, `incomplete` or `cancelled`.
        completion: &'static str,
        /// The diagnostic codes the completion holds, as the engine labels them.
        codes: Vec<String>,
    },
    /// The query ran out of its host-wide request budget.
    DeadlineExceeded,
}

/// The engine's `IncompleteCause`, in the tool's snake-case tagged form.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CauseView {
    Content,
    Operational { operational: OperationalView },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationalView {
    /// A composition budget lane ran out.
    Budget {
        lane: &'static str,
    },
    Cancelled,
    Provider,
}

fn cause_view(cause: IncompleteCause) -> CauseView {
    match cause {
        IncompleteCause::Content => CauseView::Content,
        IncompleteCause::Operational(operational) => CauseView::Operational {
            operational: match operational {
                OperationalCause::Budget(lane) => OperationalView::Budget {
                    lane: match lane {
                        BudgetLane::Procedures => "procedures",
                        BudgetLane::Hops => "hops",
                        BudgetLane::CallersPerProcedure => "callers_per_procedure",
                        BudgetLane::Semantic => "semantic",
                    },
                },
                OperationalCause::Cancelled => OperationalView::Cancelled,
                OperationalCause::Provider => OperationalView::Provider,
            },
        },
    }
}

pub type NotAnalyzedCauseView = brokk_bifrost_tools::site_context::NotAnalyzedCauseView;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgErrorKind {
    InvalidNode,
    Cancelled,
    ExceededBudget,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgLimit {
    pub kind: &'static str,
    pub limit: usize,
    pub attempted: usize,
}

/// A procedure, as the engine keys it: its file and procedure number.
#[derive(Debug, Clone, Serialize)]
pub struct ProcedureIdentity {
    pub path: String,
    pub procedure: usize,
}

/// Why V1 does not answer a question.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Unsupported {
    /// The number of points does not fit the question.
    PointCount {
        question: FlowQuestion,
        from: usize,
        to: usize,
    },
    /// A point did not select exactly one program point.
    PointRefused {
        /// `from` or `to`, with the zero-based index.
        point: String,
        refusal: RefusalView,
    },
    /// A control path between points of different procedures. Interprocedural
    /// control reachability is #13528.
    ControlPathAcrossProcedures { issue: &'static str },
    /// The point's language is not served by the composition search.
    CompositionLanguage { point: String },
    /// The point's file has no complete semantic IR rows to compose.
    CompositionNoRows { point: String },
    /// The endpoints cannot be composed; the engine's exclusion, as it names it.
    CompositionExclusion { exclusion: String },
    /// The selected point has no observable value.
    NoObservableValue { point: String },
    /// The value-flow plan refused the endpoints; the engine's message.
    PlanRefused { error: String },
    /// The call path question needs one callable owner for the origin and an
    /// exact call site for the destination, and the points did not give them.
    CallPathEndpoints { detail: &'static str },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RefusalView {
    NoNodeAtPosition,
    Ambiguous { candidates: usize },
    UnsupportedNode { node_kind: String },
    FileNotAnalyzed,
    ProcedureUnavailable { cause: NotAnalyzedCauseView },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Witness {
    Steps { steps: Vec<WitnessStep> },
    WitnessUnavailable { cause: WitnessUnavailableCause },
}

/// The engine's `WitnessTruncationCause`, by its stable label.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct WitnessUnavailableCause(&'static str);

impl From<WitnessTruncationCause> for WitnessUnavailableCause {
    fn from(cause: WitnessTruncationCause) -> Self {
        Self(cause.stable_label())
    }
}

/// One step of the engine's evidence: a site plus the engine's hop data.
#[derive(Debug, Clone, Serialize)]
pub struct WitnessStep {
    pub site: SiteContextView,
    /// The hop, edge or call kind, as the engine names it.
    pub step: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<StepProof>,
    /// The summary a model hop used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<SummaryIdentityView>,
    /// For a control path: the kind of the edge that enters this point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_in: Option<&'static str>,
    /// For a call path: the engine's static call edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_call: Option<StaticCallStep>,
}

/// A `StaticCallPath` edge, as the engine states it.
#[derive(Debug, Clone, Serialize)]
pub struct StaticCallStep {
    pub caller: String,
    pub static_target: String,
    /// The engine's `StaticCallProof`.
    pub proof: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct StepProof {
    pub proven: bool,
    pub complete: bool,
}

impl From<HopQuality> for StepProof {
    fn from(quality: HopQuality) -> Self {
        Self {
            proven: quality.proven,
            complete: quality.complete,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryIdentityView {
    pub path: String,
    pub declaration: Vec<String>,
}

/// A selected point with its caller-facing index.
pub(crate) struct Selected {
    label: String,
    selected: SelectedProgramPoint,
}

fn refusal_view(
    refusal: &PointSelectionRefusal,
    admission: &SiteAdmission<'_>,
) -> Result<RefusalView, SiteAdmissionRefusal> {
    Ok(match refusal {
        PointSelectionRefusal::NoNodeAtPosition => RefusalView::NoNodeAtPosition,
        PointSelectionRefusal::Ambiguous(candidates) => RefusalView::Ambiguous {
            candidates: candidates.len(),
        },
        PointSelectionRefusal::UnsupportedNode(kind) => RefusalView::UnsupportedNode {
            node_kind: format!("{kind:?}"),
        },
        PointSelectionRefusal::FileNotAnalyzed => RefusalView::FileNotAnalyzed,
        PointSelectionRefusal::ProcedureUnavailable(cause) => RefusalView::ProcedureUnavailable {
            cause: brokk_bifrost_tools::site_context::not_analyzed_view(cause, admission)?,
        },
    })
}

fn select_all(
    workspace: &WorkspaceAnalyzer,
    side: &str,
    points: &[PointParams],
    cancellation: &CancellationToken,
) -> Result<Result<Vec<Selected>, Unsupported>, FlowQueryError> {
    let root = workspace.analyzer().project().root().to_path_buf();
    let mut selected = Vec::new();
    for (index, params) in points.iter().enumerate() {
        let rel = std::path::Path::new(&params.path);
        if rel.is_absolute()
            || rel
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(FlowQueryInvalid(format!(
                "point path `{}` must be workspace-relative",
                params.path
            ))
            .into());
        }
        let file = ProjectFile::new(root.clone(), rel);
        let label = format!("{side}[{index}]");
        // A file the workspace does not analyze has no facts to select from.
        if !workspace.analyzer().is_analyzed(&file) {
            return Ok(Err(Unsupported::PointRefused {
                point: label,
                refusal: RefusalView::FileNotAnalyzed,
            }));
        }
        match select_program_point(
            workspace,
            &file,
            params.position()?,
            params.site_role()?,
            cancellation,
        ) {
            Ok(point) => selected.push(Selected {
                label,
                selected: point,
            }),
            Err(refusal) => {
                return Ok(Err(Unsupported::PointRefused {
                    point: label,
                    refusal: refusal_view(
                        &refusal,
                        &SiteAdmission::new(Some(workspace.retention_budget())),
                    )?,
                }));
            }
        }
    }
    Ok(Ok(selected))
}

/// Run one flow question against the workspace.
pub fn run_flow_query(
    workspace: &WorkspaceAnalyzer,
    flow_state: &FlowWorkspaceState,
    params: &FlowQueryParams,
    cancellation: &CancellationToken,
) -> Result<FlowQueryResult, FlowQueryError> {
    if params.from.is_empty() || params.to.is_empty() {
        return Err(FlowQueryError::Invalid(
            "from and to each need at least one point".to_owned(),
        ));
    }
    debug_assert!(params.points().count() >= 2);
    let question = params.question;
    let (from_count, to_count) = (params.from.len(), params.to.len());
    // Value flow takes one origin and any number of destinations, or any
    // number of origins and one destination. The other questions take one pair.
    let fits = match question {
        FlowQuestion::ValueFlow => from_count == 1 || to_count == 1,
        FlowQuestion::ControlPath | FlowQuestion::CallPath => from_count == 1 && to_count == 1,
    };
    if !fits {
        return Ok(FlowQueryResult::Unsupported {
            question,
            reason: Unsupported::PointCount {
                question,
                from: from_count,
                to: to_count,
            },
        });
    }
    let from = match select_all(workspace, "from", &params.from, cancellation)? {
        Ok(points) => points,
        Err(reason) => return Ok(FlowQueryResult::Unsupported { question, reason }),
    };
    let to = match select_all(workspace, "to", &params.to, cancellation)? {
        Ok(points) => points,
        Err(reason) => return Ok(FlowQueryResult::Unsupported { question, reason }),
    };
    match question {
        FlowQuestion::ValueFlow => value_flow(workspace, &from, &to, cancellation),
        FlowQuestion::ControlPath => control_path(workspace, &from[0], &to[0], cancellation),
        FlowQuestion::CallPath => {
            call_path_query::call_path(workspace, flow_state, &from[0], &to[0], cancellation)
        }
    }
}

// ---------------------------------------------------------------------------
// Sites

/// A witness site has no analyzed value of its own.
fn step_value() -> SiteValue {
    SiteValue::Unknown(UnknownValueCause::NotAnalyzed(NotAnalyzedCause::Unknown))
}

fn locator_site(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
    role: SiteRole,
) -> SiteContext {
    let span = locator.anchor().span();
    span_site(
        workspace,
        locator.path().as_path(),
        span.start_byte() as usize..span.end_byte() as usize,
        role,
    )
}

/// The site of a byte span of a workspace file.
pub(crate) fn span_site(
    workspace: &WorkspaceAnalyzer,
    rel_path: &std::path::Path,
    byte_range: std::ops::Range<usize>,
    role: SiteRole,
) -> SiteContext {
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        rel_path,
    );
    let source = workspace
        .analyzer()
        .indexed_source(&file)
        .expect("a site names a workspace file with indexed source");
    let starts = compute_line_starts(&source);
    let (start_line, start_column) = line_column_for_offset(&source, &starts, byte_range.start);
    let (end_line, end_column) = line_column_for_offset(&source, &starts, byte_range.end);
    SiteContext {
        site: SiteLocation::Source {
            path: file,
            text: source[byte_range.clone()].to_owned(),
            byte_range,
            start_line,
            start_column,
            end_line,
            end_column,
        },
        role,
        value: step_value(),
    }
}

/// Resolves the sites of durable keys through the artifact that owns them.
struct StepSites<'a> {
    workspace: &'a WorkspaceAnalyzer,
    cancellation: &'a CancellationToken,
    artifacts: HashMap<SemanticArtifactKey, Arc<SemanticArtifact>>,
}

impl<'a> StepSites<'a> {
    fn new(workspace: &'a WorkspaceAnalyzer, cancellation: &'a CancellationToken) -> Self {
        Self {
            workspace,
            cancellation,
            artifacts: HashMap::new(),
        }
    }

    fn procedure(&mut self, key: &DurableProcedureKey) -> ProcedureHandle {
        let artifact_key = &key.0;
        if !self.artifacts.contains_key(artifact_key) {
            let file = ProjectFile::new(
                self.workspace.analyzer().project().root().to_path_buf(),
                artifact_key.path().as_path(),
            );
            let mut budget = SemanticBudget::default();
            let outcome = self
                .workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, self.cancellation),
                )
                .expect("the search read this artifact, so it materializes again");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("the search read this artifact, so it materializes completely");
            };
            self.artifacts.insert(artifact_key.clone(), value);
        }
        self.artifacts[artifact_key]
            .procedure_handle(key.1)
            .expect("a hop names a procedure of its artifact")
    }

    fn procedure_site(&mut self, key: &DurableProcedureKey) -> SiteContext {
        let procedure = self.procedure(key);
        locator_site(
            self.workspace,
            procedure.semantics().locator(),
            SiteRole::Value,
        )
    }

    fn call_site(&mut self, key: &DurableCallSiteKey) -> SiteContext {
        let procedure = self.procedure(&key.0);
        let call: CallSiteId = key.1;
        let handle = procedure
            .call_site_handle(call)
            .expect("a hop names a call of its procedure");
        let locator = handle
            .locator()
            .expect("a call named by a hop has a source mapping");
        locator_site(self.workspace, locator, SiteRole::Call)
    }
}

// ---------------------------------------------------------------------------
// Value flow

struct BoundEndpoints {
    /// One entry per observation: the candidate it belongs to.
    candidate_of: Vec<usize>,
    carriers: Vec<(
        ProgramPointHandle,
        ValueFlowObservationPhase,
        ValueFlowCarrier,
    )>,
}

fn phase_for(role: &SiteRole) -> ValueFlowObservationPhase {
    match role {
        // An argument or receiver as an endpoint holds its value before the
        // call's effects. Every produced value, a call's result, a return or
        // a binding, holds after the effects that produce it.
        SiteRole::Argument { .. } | SiteRole::Receiver => ValueFlowObservationPhase::BeforeEffects,
        _ => ValueFlowObservationPhase::AfterEffects,
    }
}

fn not_analyzed(outcome: &SemanticOutcome<Box<[ValueAtPoint]>>) -> Option<NotAnalyzedCause> {
    match outcome {
        SemanticOutcome::Complete { .. } => None,
        SemanticOutcome::Unsupported { capability, .. } => {
            Some(NotAnalyzedCause::Unsupported(*capability))
        }
        SemanticOutcome::ExceededBudget { exceeded, .. } => {
            Some(NotAnalyzedCause::ExceededBudget(*exceeded))
        }
        SemanticOutcome::Cancelled { .. } => Some(NotAnalyzedCause::Cancelled),
        SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unproven { .. } => Some(NotAnalyzedCause::Unknown),
    }
}

/// The values observed at each selected point. A point whose observation is
/// not complete is an incomplete answer with the engine's typed cause.
fn observe_endpoints(
    oracle: &brokk_bifrost_analysis::analyzer::semantic::WorkspaceSemanticOracle<'_>,
    points: &[Selected],
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<Result<BoundEndpoints, ObservationStop>, FlowQueryError> {
    let mut bound = BoundEndpoints {
        candidate_of: Vec::new(),
        carriers: Vec::new(),
    };
    for (candidate, point) in points.iter().enumerate() {
        let SiteLocation::Source {
            path, byte_range, ..
        } = &point.selected.site.site
        else {
            unreachable!("a selected point is a source site");
        };
        let outcome = oracle
            .value_observations_at_source(
                path,
                Range {
                    start_byte: byte_range.start,
                    end_byte: byte_range.end,
                    start_line: 0,
                    end_line: 0,
                },
                &mut SemanticRequest::new(budget, cancellation),
            )
            .map_err(|error| {
                FlowQueryError::Internal(format!("point observation failed: {error}"))
            })?;
        if let Some(cause) = not_analyzed(&outcome) {
            return Ok(Err(ObservationStop::Incomplete(point.label.clone(), cause)));
        }
        let SemanticOutcome::Complete { value, .. } = outcome else {
            unreachable!("not_analyzed returned none only for a complete outcome");
        };
        let phase = phase_for(&point.selected.site.role);
        let mut any = false;
        for observation in value.iter() {
            // Only the values the selected point itself observes.
            if observation.point() != &point.selected.point {
                continue;
            }
            any = true;
            let value = observation.value();
            let procedure = value.procedure().clone();
            let parameter =
                procedure
                    .semantics()
                    .value(value.id())
                    .and_then(|row| match &row.kind {
                        SemanticValueKind::Parameter { ordinal, .. } => Some(*ordinal),
                        _ => None,
                    });
            let (at, phase, carrier) = match parameter {
                // A formal parameter holds at its procedure's entry.
                Some(ordinal) => (
                    procedure
                        .point_handle(procedure.semantics().entry_point())
                        .expect("a procedure has an entry point handle"),
                    ValueFlowObservationPhase::BeforeEffects,
                    ValueFlowCarrier::Port(
                        ProcedurePortHandle::parameter(procedure.clone(), ordinal)
                            .expect("a parameter value has a procedure port"),
                    ),
                ),
                None => (
                    observation.point().clone(),
                    phase,
                    ValueFlowCarrier::for_value(value.clone()),
                ),
            };
            bound.candidate_of.push(candidate);
            bound.carriers.push((at, phase, carrier));
        }
        if !any {
            return Ok(Err(ObservationStop::NoValue(point.label.clone())));
        }
    }
    Ok(Ok(bound))
}

enum ObservationStop {
    Incomplete(String, NotAnalyzedCause),
    NoValue(String),
}

fn composition_reason(item: &Incompleteness) -> EngineReason {
    let identity = |procedure: &DurableProcedureKey| ProcedureIdentity {
        path: procedure.0.path().as_str().to_owned(),
        procedure: procedure.1.index(),
    };
    let (label, reason, procedure): (&'static str, Option<&str>, Option<&DurableProcedureKey>) =
        match item {
            Incompleteness::ExecutionRoots { reason, .. } => {
                ("execution_roots", Some(reason), None)
            }
            Incompleteness::Execution {
                procedure, reason, ..
            } => ("execution", Some(reason), Some(procedure)),
            Incompleteness::Dispatch { call, reason, .. } => {
                ("dispatch", Some(reason), Some(&call.0))
            }
            Incompleteness::ModelOutputStorage { call, .. } => {
                ("model_output_storage", None, Some(&call.0))
            }
            Incompleteness::Callers {
                procedure, reason, ..
            } => ("callers", Some(reason), Some(procedure)),
            Incompleteness::Model { call, reason, .. } => ("model", Some(reason), Some(&call.0)),
            Incompleteness::UnknownSummaryEffects { call, .. } => {
                ("unknown_summary_effects", None, Some(&call.0))
            }
            Incompleteness::Interior {
                procedure, reason, ..
            } => ("interior", Some(reason), Some(procedure)),
            Incompleteness::PartialFlows { procedure, .. } => {
                ("partial_flows", None, Some(procedure))
            }
            Incompleteness::Open {
                procedure, reason, ..
            } => ("open", Some(reason), Some(procedure)),
            Incompleteness::MissingCaptureBinding { procedure, .. } => {
                ("missing_capture_binding", None, Some(procedure))
            }
            Incompleteness::UnplacedTransfer { procedure, .. } => {
                ("unplaced_transfer", None, Some(procedure))
            }
            Incompleteness::Endpoints {
                procedure, reason, ..
            } => ("endpoints", Some(reason), Some(procedure)),
            Incompleteness::StoreInventory {
                procedure, reason, ..
            } => ("store_inventory", Some(reason), Some(procedure)),
            Incompleteness::SourceEvidence { point, .. } => {
                ("source_evidence", None, Some(&point_key(point)))
            }
            Incompleteness::SinkEvidence { point, .. } => {
                ("sink_evidence", None, Some(&point_key(point)))
            }
            Incompleteness::Budget(_) => ("budget", None, None),
            Incompleteness::Cancelled => ("cancelled", None, None),
            Incompleteness::Object { reason, .. } => ("object", Some(reason), None),
        };
    EngineReason::Composition {
        incompleteness: label,
        cause: cause_view(item.cause()),
        reason: reason.map(str::to_owned),
        procedure: procedure.map(identity),
    }
}

fn point_key(point: &ProgramPointHandle) -> DurableProcedureKey {
    point.procedure().durable_key()
}

fn value_flow(
    workspace: &WorkspaceAnalyzer,
    from: &[Selected],
    to: &[Selected],
    cancellation: &CancellationToken,
) -> Result<FlowQueryResult, FlowQueryError> {
    let question = FlowQuestion::ValueFlow;
    let unsupported = |reason| Ok(FlowQueryResult::Unsupported { question, reason });
    // The composition search serves the languages whose caller inventory is
    // certified, over files with complete IR rows.
    for point in from.iter().chain(to) {
        match workspace.composition_readiness(point.selected.point.procedure().artifact().key()) {
            Ok(brokk_bifrost_analysis::analyzer::workspace::CompositionReadiness::Ready) => {}
            Ok(brokk_bifrost_analysis::analyzer::workspace::CompositionReadiness::Language) => {
                return unsupported(Unsupported::CompositionLanguage {
                    point: point.label.clone(),
                });
            }
            Ok(brokk_bifrost_analysis::analyzer::workspace::CompositionReadiness::NoRows) => {
                return unsupported(Unsupported::CompositionNoRows {
                    point: point.label.clone(),
                });
            }
            Err(error) => return Err(FlowQueryError::Internal(error.to_string())),
        }
    }

    let limits = CodeQueryExecutionLimits::default();
    let icfg = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
        workspace,
        workspace.analyzer().active_semantic_model_snapshot(),
    );
    let mut semantic_budget = SemanticBudget::default();
    let sources = match observe_endpoints(icfg.oracle(), from, &mut semantic_budget, cancellation) {
        Ok(Ok(bound)) => bound,
        Ok(Err(stop)) => {
            return observation_stop(
                &SiteAdmission::new(Some(workspace.retention_budget())),
                question,
                from,
                to,
                stop,
            );
        }
        Err(error) => return Err(error),
    };
    let sinks = match observe_endpoints(icfg.oracle(), to, &mut semantic_budget, cancellation) {
        Ok(Ok(bound)) => bound,
        Ok(Err(stop)) => {
            return observation_stop(
                &SiteAdmission::new(Some(workspace.retention_budget())),
                question,
                from,
                to,
                stop,
            );
        }
        Err(error) => return Err(error),
    };

    let mut source_specs = Vec::new();
    for (ordinal, (point, phase, carrier)) in sources.carriers.iter().enumerate() {
        let key = ValueFlowEventKey::at_point(point, ordinal as u32, ValueFlowEventKind::Source)
            .expect("a selected point has a source mapping");
        source_specs.push(ValueFlowSourceSpec::new(
            key,
            point.clone(),
            *phase,
            carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
    }
    let mut sink_specs = Vec::new();
    for (ordinal, (point, phase, carrier)) in sinks.carriers.iter().enumerate() {
        let key = ValueFlowEventKey::at_point(point, ordinal as u32, ValueFlowEventKind::Sink)
            .expect("a selected point has a source mapping");
        sink_specs.push(ValueFlowSinkSpec::new(
            key,
            point.clone(),
            *phase,
            carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
    }
    let root = sink_specs[0].point().procedure().clone();
    let plan = match ValueFlowPlan::try_new(
        root,
        Vec::new(),
        Vec::new(),
        source_specs.clone(),
        sink_specs.clone(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return unsupported(Unsupported::PlanRefused {
                error: error.to_string(),
            });
        }
    };
    if let Some(exclusion) = plan.composition_exclusion() {
        return unsupported(Unsupported::CompositionExclusion {
            exclusion: format!("{exclusion:?}"),
        });
    }

    let provider = WorkspaceValueFlowProvider::with_oracle(
        icfg.oracle().clone(),
        icfg.behavior_identity(),
        ValueFlowCache::new(limits.value_flow.max_retained_bytes as u64),
    );
    let composition = UnitCompositionProvider::new(
        workspace,
        provider,
        &plan,
        SemanticExecutionBudget::new(limits.semantic.max_materialized_files),
        limits.value_flow.max_endpoints,
        limits.value_flow.max_retained_bytes,
    );
    let budget = CompositionBudget {
        max_procedures: semantic_budget.remaining().procedures,
        max_hops: limits.value_flow.max_retained_relations,
        max_callers_per_procedure: limits.value_flow.max_endpoints,
    };
    let mut request = SemanticRequest::new(&mut semantic_budget, cancellation);
    let outcome = match search_value_flow(&plan, &composition, budget, &mut request) {
        Ok(outcome) => outcome,
        // A refused acquisition is a typed engine stop. Any other error is a
        // provider or store failure, which is not an answer.
        Err(error @ ComposeError::AcquisitionRefused(_)) => {
            return answered_all(
                &SiteAdmission::new(Some(workspace.retention_budget())),
                question,
                from,
                to,
                |_, _| PairOutcome {
                    answer: Answer::Incomplete,
                    witness: None,
                    reasons: vec![EngineReason::CompositionError {
                        error: error.to_string(),
                    }],
                },
                FlowEngine::CompositionSearch,
                FlowGranularity::Point,
            );
        }
        Err(error) => return Err(FlowQueryError::Internal(error.to_string())),
    };

    // The search's incompleteness is global to the search, not per pair.
    let mut reasons: Vec<EngineReason> =
        outcome.incomplete.iter().map(composition_reason).collect();
    // The plan holds only the endpoints, as policy composition builds it, so
    // its own discovery flag is not read here: it would report every endpoint
    // outside the root procedure as unentered. The search discovers each
    // procedure itself and reports what it could not as `outcome.incomplete`.
    if cancellation.is_cancelled() && reasons.is_empty() {
        reasons.push(EngineReason::DeadlineExceeded);
    }

    // Plan order: sinks are sorted by key, sources keep registration order.
    let sink_candidate: Vec<usize> = plan
        .sinks()
        .map(|(_, spec)| {
            let index = sink_specs
                .iter()
                .position(|candidate| candidate.key() == spec.key())
                .expect("the plan holds the sinks it was given");
            sinks.candidate_of[index]
        })
        .collect();
    let source_candidate: Vec<usize> = plan
        .sources()
        .map(|(_, spec)| {
            let index = source_specs
                .iter()
                .position(|candidate| candidate.key() == spec.key())
                .expect("the plan holds the sources it was given");
            sources.candidate_of[index]
        })
        .collect();

    let mut sites = StepSites::new(workspace, cancellation);
    let mut by_pair: HashMap<(usize, usize), &SourceSinkPair> = HashMap::new();
    for pair in &outcome.pairs {
        let key = (
            source_candidate[pair.source.index()],
            sink_candidate[pair.sink.get() as usize],
        );
        by_pair.entry(key).or_insert(pair);
    }
    let mut witnesses: HashMap<(usize, usize), Witness> = HashMap::new();
    for (key, pair) in &by_pair {
        witnesses.insert(*key, hop_witness(&mut sites, pair)?);
    }
    let from_index: HashMap<&str, usize> = from
        .iter()
        .enumerate()
        .map(|(index, point)| (point.label.as_str(), index))
        .collect();
    let to_index: HashMap<&str, usize> = to
        .iter()
        .enumerate()
        .map(|(index, point)| (point.label.as_str(), index))
        .collect();
    answered_all(
        &SiteAdmission::new(Some(workspace.retention_budget())),
        question,
        from,
        to,
        |from_point, to_point| {
            let key = (
                from_index[from_point.label.as_str()],
                to_index[to_point.label.as_str()],
            );
            match witnesses.remove(&key) {
                Some(witness) => PairOutcome {
                    answer: Answer::Reached,
                    witness: Some(witness),
                    reasons: reasons.clone(),
                },
                None if reasons.is_empty() => PairOutcome {
                    answer: Answer::NotReached,
                    witness: None,
                    reasons: Vec::new(),
                },
                None => PairOutcome {
                    answer: Answer::Incomplete,
                    witness: None,
                    reasons: reasons.clone(),
                },
            }
        },
        FlowEngine::CompositionSearch,
        FlowGranularity::Point,
    )
}

fn hop_witness(
    sites: &mut StepSites<'_>,
    pair: &SourceSinkPair,
) -> Result<Witness, SiteAdmissionRefusal> {
    // The engine keeps one path per distinct label function; the first is the
    // engine's own first.
    let Some((hops, _quality)) = pair.paths.first() else {
        return Ok(Witness::WitnessUnavailable {
            cause: WitnessTruncationCause::RetentionExhausted.into(),
        });
    };
    Ok(Witness::Steps {
        steps: hops
            .iter()
            .map(|hop| hop_step(sites, hop))
            .collect::<Result<_, _>>()?,
    })
}

fn summary_identity(
    key: &brokk_bifrost_flow::dataflow::ProcedureSummaryKey,
) -> SummaryIdentityView {
    SummaryIdentityView {
        path: key.artifact().path().as_str().to_owned(),
        declaration: key
            .declaration()
            .segments()
            .iter()
            .map(|segment| segment.name().unwrap_or("<anonymous>").to_owned())
            .collect(),
    }
}

fn hop_step(sites: &mut StepSites<'_>, hop: &Hop) -> Result<WitnessStep, SiteAdmissionRefusal> {
    let uncertain = |uncertain: bool| Some(HopQuality::from_uncertain(uncertain).into());
    let (step, site, proof, summary) = match hop {
        Hop::Invocation { call, quality, .. } => (
            "invocation",
            sites.call_site(call),
            Some((*quality).into()),
            None,
        ),
        Hop::Store {
            write_call,
            uncertain: flag,
            ..
        } => ("store", sites.call_site(write_call), uncertain(*flag), None),
        Hop::Interior {
            procedure, quality, ..
        } => (
            "interior",
            sites.procedure_site(procedure),
            Some((*quality).into()),
            None,
        ),
        Hop::Stored {
            procedure, quality, ..
        } => (
            "stored",
            sites.procedure_site(procedure),
            Some((*quality).into()),
            None,
        ),
        Hop::Callee {
            call,
            uncertain: flag,
            ..
        } => ("callee", sites.call_site(call), uncertain(*flag), None),
        Hop::Caller {
            call,
            uncertain: flag,
            ..
        } => ("caller", sites.call_site(call), uncertain(*flag), None),
        Hop::CallHandoff { call, quality, .. } => (
            "call_handoff",
            sites.call_site(call),
            Some((*quality).into()),
            None,
        ),
        Hop::Closure {
            closure,
            uncertain: flag,
            ..
        } => (
            "closure",
            sites.procedure_site(closure),
            uncertain(*flag),
            None,
        ),
        Hop::Model {
            call,
            summary,
            quality,
            ..
        } => (
            "model",
            sites.call_site(call),
            Some((*quality).into()),
            summary.as_deref().map(summary_identity),
        ),
        Hop::Unmodeled { call, .. } => ("unmodeled", sites.call_site(call), uncertain(true), None),
        Hop::Sanitizer {
            call,
            proven,
            uncertain: flag,
            ..
        } => (
            "sanitizer",
            sites.call_site(call),
            Some(StepProof {
                proven: *proven,
                complete: !*flag,
            }),
            None,
        ),
        Hop::Transform {
            call,
            uncertain: flag,
            ..
        } => ("transform", sites.call_site(call), uncertain(*flag), None),
    };
    Ok(WitnessStep {
        site: view(
            &site,
            &SiteAdmission::new(Some(sites.workspace.retention_budget())),
        )?,
        step,
        proof,
        summary,
        edge_in: None,
        static_call: None,
    })
}

// ---------------------------------------------------------------------------
// Answer assembly

pub(crate) struct PairOutcome {
    pub answer: Answer,
    pub witness: Option<Witness>,
    pub reasons: Vec<EngineReason>,
}

pub(crate) fn answered_all(
    admission: &SiteAdmission<'_>,
    question: FlowQuestion,
    from: &[Selected],
    to: &[Selected],
    mut answer: impl FnMut(&Selected, &Selected) -> PairOutcome,
    engine: FlowEngine,
    granularity: FlowGranularity,
) -> Result<FlowQueryResult, FlowQueryError> {
    let mut results = Vec::new();
    for from_point in from {
        for to_point in to {
            let outcome = answer(from_point, to_point);
            results.push(pair_answer(admission, from_point, to_point, outcome)?);
        }
    }
    Ok(FlowQueryResult::Answered {
        question,
        engine,
        granularity,
        results,
    })
}

pub(crate) fn pair_answer(
    admission: &SiteAdmission<'_>,
    from: &Selected,
    to: &Selected,
    outcome: PairOutcome,
) -> Result<PairAnswer, SiteAdmissionRefusal> {
    let completeness = Completeness::from_reasons(outcome.reasons);
    match outcome.answer {
        Answer::NotReached => assert!(
            completeness.is_complete(),
            "not_reached is reported only from a complete search"
        ),
        Answer::Incomplete => assert!(
            !completeness.is_complete(),
            "an incomplete answer carries at least one engine reason"
        ),
        Answer::Reached => {}
    }
    Ok(PairAnswer {
        from: view(&from.selected.site, admission)?,
        to: view(&to.selected.site, admission)?,
        answer: outcome.answer,
        witness: outcome.witness,
        completeness,
    })
}

fn observation_stop(
    admission: &SiteAdmission<'_>,
    question: FlowQuestion,
    from: &[Selected],
    to: &[Selected],
    stop: ObservationStop,
) -> Result<FlowQueryResult, FlowQueryError> {
    match stop {
        ObservationStop::NoValue(point) => Ok(FlowQueryResult::Unsupported {
            question,
            reason: Unsupported::NoObservableValue { point },
        }),
        ObservationStop::Incomplete(point, cause) => {
            let cause = brokk_bifrost_tools::site_context::not_analyzed_view(&cause, admission)?;
            answered_all(
                admission,
                question,
                from,
                to,
                |_, _| PairOutcome {
                    answer: Answer::Incomplete,
                    witness: None,
                    reasons: vec![EngineReason::EndpointObservation {
                        point: point.clone(),
                        cause: cause.clone(),
                    }],
                },
                FlowEngine::CompositionSearch,
                FlowGranularity::Point,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Control path

fn control_path(
    workspace: &WorkspaceAnalyzer,
    from: &Selected,
    to: &Selected,
    cancellation: &CancellationToken,
) -> Result<FlowQueryResult, FlowQueryError> {
    let question = FlowQuestion::ControlPath;
    let procedure = from.selected.point.procedure();
    if procedure != to.selected.point.procedure() {
        return Ok(FlowQueryResult::Unsupported {
            question,
            reason: Unsupported::ControlPathAcrossProcedures {
                issue: CONTROL_ACROSS_PROCEDURES_ISSUE,
            },
        });
    }
    let semantics = procedure.semantics();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation);
    let found = shortest_path(
        semantics,
        from.selected.point.id(),
        to.selected.point.id(),
        &mut request,
    );
    let outcome = match found {
        Ok(Some(path)) => {
            let steps = path
                .nodes
                .iter()
                .enumerate()
                .map(|(index, node)| {
                    let point = procedure
                        .point_handle(*node)
                        .expect("a path node is a point of its procedure");
                    let locator = point
                        .locator()
                        .expect("a point on a selected path has a source mapping");
                    let edge_in = index.checked_sub(1).map(|edge| {
                        semantics
                            .control_edge(path.edges[edge])
                            .expect("a path edge is an edge of its procedure")
                            .kind
                            .label()
                    });
                    Ok(WitnessStep {
                        site: view(
                            &locator_site(workspace, locator, SiteRole::Statement),
                            &SiteAdmission::new(Some(workspace.retention_budget())),
                        )?,
                        step: "point",
                        proof: None,
                        summary: None,
                        edge_in,
                        static_call: None,
                    })
                })
                .collect::<Result<Vec<_>, SiteAdmissionRefusal>>()?;
            PairOutcome {
                answer: Answer::Reached,
                witness: Some(Witness::Steps { steps }),
                reasons: Vec::new(),
            }
        }
        Ok(None) => PairOutcome {
            answer: Answer::NotReached,
            witness: None,
            reasons: Vec::new(),
        },
        Err(error) => PairOutcome {
            answer: Answer::Incomplete,
            witness: None,
            reasons: vec![cfg_reason(error)],
        },
    };
    answered_all(
        &SiteAdmission::new(Some(workspace.retention_budget())),
        question,
        std::slice::from_ref(from),
        std::slice::from_ref(to),
        |_, _| PairOutcome {
            answer: outcome.answer,
            witness: outcome.witness.clone(),
            reasons: outcome.reasons.clone(),
        },
        FlowEngine::CfgShortestPath,
        FlowGranularity::Point,
    )
}

fn cfg_reason<Node>(error: CfgAlgorithmError<Node>) -> EngineReason {
    match error {
        CfgAlgorithmError::InvalidNode(_) => EngineReason::Cfg {
            error: CfgErrorKind::InvalidNode,
            node_visits: None,
            edge_visits: None,
            limit: None,
        },
        CfgAlgorithmError::Cancelled { work } => EngineReason::Cfg {
            error: CfgErrorKind::Cancelled,
            node_visits: Some(work.node_visits),
            edge_visits: Some(work.edge_visits),
            limit: None,
        },
        CfgAlgorithmError::ExceededBudget(exceeded) => EngineReason::Cfg {
            error: CfgErrorKind::ExceededBudget,
            node_visits: Some(exceeded.work.node_visits),
            edge_visits: Some(exceeded.work.edge_visits),
            limit: Some(CfgLimit {
                kind: match exceeded.limit_kind {
                    brokk_bifrost_analysis::analyzer::semantic::cfg_algorithms::CfgAlgorithmLimit::NodeVisits => "node_visits",
                    brokk_bifrost_analysis::analyzer::semantic::cfg_algorithms::CfgAlgorithmLimit::EdgeVisits => "edge_visits",
                },
                limit: exceeded.limit,
                attempted: exceeded.attempted,
            }),
        },
    }
}

/// The source span of a selected point.
pub(crate) struct SelectedSpan<'a> {
    pub path: &'a ProjectFile,
    pub rel_path: String,
    pub byte_range: std::ops::Range<usize>,
}

impl Selected {
    pub(crate) fn span(&self) -> SelectedSpan<'_> {
        let SiteLocation::Source {
            path, byte_range, ..
        } = &self.selected.site.site
        else {
            unreachable!("a selected point is a source site");
        };
        SelectedSpan {
            path,
            rel_path: brokk_bifrost_core::path_utils::workspace_relative_slash_path(
                path.rel_path(),
            ),
            byte_range: byte_range.clone(),
        }
    }

    pub(crate) fn point(&self) -> &ProgramPointHandle {
        &self.selected.point
    }
}
