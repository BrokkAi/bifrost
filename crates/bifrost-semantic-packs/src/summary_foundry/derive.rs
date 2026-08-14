//! Stage 1: deterministic derivation of procedure summaries from pinned
//! standard-library sources.
//!
//! The engine is the analyzer's own value-flow machinery, not a second
//! implementation of it. For one target procedure the derivation binds a
//! [`ValueFlowSourceSpec`] to every input port at the entry point, binds a
//! [`ValueFlowSinkSpec`] to every write into an output port at that write's own
//! program point, discovers the interprocedural closure through the semantic
//! oracle, and solves. Every meeting the solver reports is one derived flow.
//!
//! Sources and sinks bind access-path carriers, not only bare ports, so a
//! field- or element-sensitive flow keeps its selectors. The authored IR has no
//! access paths, so an entry ships the argument-level projection of its derived
//! flows and keeps the full-granularity form beside it. The projection is
//! irreversible, so it happens once, after the answer is known.
//!
//! The call behavior is [`UnmodeledCallBehavior::RequireModel`], so a call the
//! closure cannot enter abstains instead of manufacturing a transfer. That is
//! what makes the typed incompleteness meaningful: an entry never states a flow
//! past a boundary it did not cross, and it records why it stopped.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::dataflow::{
    DataflowRequest, SemanticInputStatus, SolverBudget, SolverTermination, UnmodeledCallBehavior,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    CallBindings, CancellationToken, DeclarationLocator, DeclarationSegmentKind,
    DispatchBoundaryKind, DispatchOracle, EvidenceCompleteness, OracleCallContext, ProcedureHandle,
    ProcedureKind, ProcedurePortHandle, ProgramPointHandle, ProgramPointId, ProofStatus,
    SemanticBudget, SemanticLocator, SemanticRequest, SemanticValueKind, ValueFlowOracle,
    ValueFlowRelation, ValueFlowRelationKind, ValueFlowSnapshot,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer,
};
use brokk_bifrost_analysis::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowPortKey, ValueFlowSelectorKey,
    ValueFlowSinkSpec, ValueFlowSourceSpec, solve_value_flow_with_summaries,
};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, FilesystemProject, Language, Project, ProjectFile, Range, WorkspaceAnalyzer,
};

use super::FoundryError;
use super::ir::{
    FoundryAccessPath, FoundryArtifactBinding, FoundryBoundary, FoundryClaim, FoundryCompleteness,
    FoundryCorpus, FoundryDerivation, FoundryDerivationBoundary, FoundryEntry,
    FoundryFineGrainedTransfer, FoundrySelector, FoundrySignature, FoundryTarget, class_file_path,
    render_transfer, summary_id,
};

/// The JVM spelling of a constructor, which is also the spelling milestone 1's
/// corpus translators normalize to.
const CONSTRUCTOR_MEMBER: &str = "<init>";

/// Bounds on one derivation run.
///
/// The closure bound is the derivation's own budget: crossing it is a typed
/// incompleteness, not a silent truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivationLimits {
    /// The largest interprocedural closure one target may discover.
    pub max_closure_procedures: usize,
}

impl Default for DerivationLimits {
    fn default() -> Self {
        Self {
            max_closure_procedures: 64,
        }
    }
}

/// Output ports the derivation observes, and the ones it does not.
///
/// A receiver, capture, or heap output states that the callee mutated memory
/// reachable from an input. The value-flow client reports flow between
/// carriers; proving a write into the receiver's object graph needs the heap
/// oracle, which this stage does not drive. The derived slot is therefore
/// silent about those outputs rather than denying them, and every derived entry
/// carries `partial` completeness unless the body was fully traversed.
pub const DERIVED_OUTPUT_PORTS: [&str; 2] = ["normal_return", "exceptional_return"];

/// What one derivation run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationRun {
    pub files_read: u32,
    pub procedures_read: u32,
    pub entries: Vec<FoundryEntry>,
    /// Files the semantic provider could not materialize, with the reason it
    /// gave. A corpus-scale run reports these and keeps going: one file the
    /// analyzer rejects is a finding about the analyzer, not a reason to stop
    /// deriving the rest of the standard library.
    pub unavailable_files: Vec<String>,
}

/// Derive summaries for every Java procedure under `sources`.
///
/// `sources` is the package root of an extracted pinned source archive, so a
/// file's package comes from its own `package` declaration and never from a
/// path convention.
pub fn derive_jvm_summaries(
    sources: &Path,
    limits: DerivationLimits,
) -> Result<DerivationRun, FoundryError> {
    let project = FilesystemProject::new(sources).map_err(|error| FoundryError::Io {
        path: sources.to_path_buf(),
        error,
    })?;
    let project: Arc<dyn Project> = Arc::new(project);
    let analyzer = WorkspaceAnalyzer::build_ephemeral(project, AnalyzerConfig::default()).map_err(
        |error| FoundryError::Derivation {
            detail: format!(
                "cannot build an analyzer over {}: {error}",
                sources.display()
            ),
        },
    )?;

    let mut files = analyzer
        .analyzer()
        .get_analyzed_files()
        .into_iter()
        .filter(|file| {
            file.rel_path()
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| Language::from_extension(extension) == Language::Java)
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.rel_path().cmp(right.rel_path()));

    let declarations = DeclarationIndex::build(&analyzer, &files);
    let cancellation = CancellationToken::default();
    let mut entries = Vec::new();
    let mut unavailable_files = Vec::new();
    let mut procedures_read = 0u32;
    for file in &files {
        let mut semantic_budget = SemanticBudget::default();
        let path = file.rel_path().to_string_lossy().replace('\\', "/");
        let outcome = match analyzer.materialize_program_semantics(
            file,
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                unavailable_files.push(format!("{path}: {error}"));
                continue;
            }
        };
        let Some(artifact) = outcome.available_value().cloned() else {
            unavailable_files.push(format!("{path}: no semantic artifact"));
            continue;
        };
        for procedure in artifact.procedures() {
            if !matches!(
                procedure.kind(),
                ProcedureKind::Method | ProcedureKind::Constructor
            ) {
                continue;
            }
            let handle = artifact
                .procedure_handle(procedure.id())
                .expect("a procedure enumerated from a live artifact keeps its handle");
            procedures_read += 1;
            if let Some(entry) = derive_procedure(&analyzer, &declarations, &handle, limits)? {
                entries.push(entry);
            }
        }
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    unavailable_files.sort();
    Ok(DerivationRun {
        files_read: files.len() as u32,
        procedures_read,
        entries,
        unavailable_files,
    })
}

/// Derive one procedure's summary, or `None` when the target has no JVM
/// spelling the foundry can key on.
fn derive_procedure(
    analyzer: &WorkspaceAnalyzer,
    declarations: &DeclarationIndex,
    root: &ProcedureHandle,
    limits: DerivationLimits,
) -> Result<Option<FoundryEntry>, FoundryError> {
    let Some(target) = declarations.target_for(root) else {
        return Ok(None);
    };
    let shape = ProcedureShape::read(root);
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let mut boundaries = BTreeSet::new();

    let closure = discover_closure(
        analyzer,
        root,
        declarations,
        limits,
        &mut semantic_budget,
        &cancellation,
        &mut boundaries,
    );

    let entry_point = root
        .point_handle(root.semantics().entry_point())
        .expect("a live procedure owns its entry point");

    // Inputs are observed at the entry: the receiver, each parameter, and every
    // access path beneath one of them that the body actually reaches. Binding
    // the qualified paths too is what keeps the derivation from assuming that a
    // summary is argument-level. The authored IR projects the answer down to
    // whole ports, but the projection happens once, at the end, and the entry
    // keeps the full-granularity form beside it.
    let input_carriers = shape
        .input_ports(root)
        .into_iter()
        .map(ValueFlowCarrier::Port)
        .collect::<Vec<_>>();
    let input_ports = input_carriers
        .iter()
        .map(|carrier| {
            access_path(carrier)
                .expect("a receiver or parameter port has a foundry spelling")
                .port
        })
        .collect::<Vec<_>>();
    let sources = input_carriers
        .into_iter()
        .chain(qualified_carriers(closure.root_relations(), &input_ports))
        .enumerate()
        .map(|(ordinal, carrier)| port_source(&entry_point, ordinal as u32, carrier))
        .collect::<Vec<_>>();

    // An output port is observed where the body writes to it, not at the exit
    // point. The exit point is a sink of control, never the source of an edge
    // the solver evaluates, so a sink bound there never fires. The snapshot
    // states each write's exact point, which is also the point whose local rule
    // makes the port carrier live.
    let output_ports = DERIVED_OUTPUT_PORTS.map(str::to_owned);
    let mut sinks = Vec::new();
    let mut ordinals: BTreeMap<ProgramPointId, u32> = BTreeMap::new();
    let mut bind_sink = |point: &ProgramPointHandle, carrier: ValueFlowCarrier| {
        let ordinal = ordinals.entry(point.id()).or_default();
        sinks.push(port_sink(point, *ordinal, carrier));
        *ordinal += 1;
    };
    for relation in closure.root_relations() {
        match relation.kind {
            ValueFlowRelationKind::NormalReturn => bind_sink(
                relation.point(),
                ValueFlowCarrier::Port(ProcedurePortHandle::normal_return(root.clone())),
            ),
            ValueFlowRelationKind::ExceptionalReturn => bind_sink(
                relation.point(),
                ValueFlowCarrier::Port(ProcedurePortHandle::exceptional_return(root.clone())),
            ),
            _ => {}
        }
        for endpoint in [&relation.source, &relation.target] {
            let carrier = ValueFlowCarrier::from(endpoint);
            if carrier_is_qualified_under(&carrier, &output_ports) {
                bind_sink(relation.point(), carrier);
            }
        }
    }

    // A target the engine refuses is one entry that states nothing and says
    // why, not a run that stops. The refusal is a foundry finding: it names a
    // shape the value-flow machinery cannot accept, and the report counts it.
    let closure_procedures = closure.procedures;
    let plan = match ValueFlowPlan::with_call_behavior(
        root.clone(),
        closure.snapshots,
        closure.bindings,
        sources,
        sinks,
        UnmodeledCallBehavior::RequireModel,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            boundaries.insert(FoundryDerivationBoundary::EngineRejected {
                detail: format!("plan: {error}"),
            });
            return Ok(Some(rejected_entry(
                target,
                &shape,
                closure_procedures,
                boundaries,
            )));
        }
    };

    let mut solver_budget = SolverBudget::default();
    let result = match solve_value_flow_with_summaries(
        root,
        &analyzer.icfg_provider(),
        &plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    ) {
        Ok(result) => result,
        Err(error) => {
            boundaries.insert(FoundryDerivationBoundary::EngineRejected {
                detail: format!("solve: {error}"),
            });
            return Ok(Some(rejected_entry(
                target,
                &shape,
                closure_procedures,
                boundaries,
            )));
        }
    };

    match result.result().termination() {
        SolverTermination::FixedPoint => {}
        SolverTermination::Cancelled => {
            boundaries.insert(FoundryDerivationBoundary::SolverCancelled);
        }
        SolverTermination::ExceededBudget(exceeded) => {
            boundaries.insert(FoundryDerivationBoundary::BudgetExceeded {
                detail: exceeded.to_string(),
            });
        }
    }

    let mut transfers: BTreeMap<String, AuthoredSummaryTransfer> = BTreeMap::new();
    let mut fine_grained: BTreeSet<FoundryFineGrainedTransfer> = BTreeSet::new();
    let mut unproven_transfers = 0u32;
    for meeting in result.meetings() {
        let Some(source) = plan.source(meeting.source()) else {
            continue;
        };
        let Some(sink) = plan.sink(meeting.sink()) else {
            continue;
        };
        let Some(input) = authored_input(source.carrier()) else {
            continue;
        };
        let Some((output, exit_kind)) = authored_output(sink.carrier()) else {
            continue;
        };
        let transfer = AuthoredSummaryTransfer {
            input,
            exit_kind,
            output,
        };
        if meeting.is_uncertain() {
            unproven_transfers += 1;
        }
        if let (Some(input_path), Some(output_path)) =
            (access_path(source.carrier()), access_path(sink.carrier()))
        {
            fine_grained.insert(FoundryFineGrainedTransfer {
                input: input_path,
                output: output_path,
                exit_kind: match exit_kind {
                    AuthoredSummaryExitKind::Normal => "normal".to_owned(),
                    AuthoredSummaryExitKind::Exceptional => "exceptional".to_owned(),
                },
            });
        }
        transfers.insert(render_transfer(&transfer), transfer);
    }

    let completeness = if boundaries.is_empty() && result.is_complete() {
        FoundryCompleteness::Complete
    } else {
        FoundryCompleteness::Partial
    };
    let transfers = transfers.into_values().collect::<Vec<_>>();
    let claim = if transfers.is_empty() && completeness == FoundryCompleteness::Complete {
        FoundryClaim::NoFlow
    } else {
        FoundryClaim::Flows
    };
    Ok(Some(FoundryEntry {
        id: summary_id(FoundryCorpus::Derived, &target),
        corpus: FoundryCorpus::Derived,
        target,
        boundary: FoundryBoundary {
            has_receiver: shape.has_receiver,
            parameter_count: shape.parameter_count,
        },
        claim,
        completeness,
        transfers,
        artifact: FoundryArtifactBinding::Unresolved,
        evidence: Vec::new(),
        notes: Vec::new(),
        derivation: Some(FoundryDerivation {
            unproven_transfers,
            closure_procedures: closure.procedures as u32,
            boundaries: boundaries.into_iter().collect(),
            fine_grained: fine_grained.into_iter().collect(),
        }),
    }))
}

/// One entry for a target the value-flow machinery refused: no transfer, no
/// completeness claim, and the typed refusal that explains both.
fn rejected_entry(
    target: FoundryTarget,
    shape: &ProcedureShape,
    closure_procedures: usize,
    boundaries: BTreeSet<FoundryDerivationBoundary>,
) -> FoundryEntry {
    FoundryEntry {
        id: summary_id(FoundryCorpus::Derived, &target),
        corpus: FoundryCorpus::Derived,
        target,
        boundary: FoundryBoundary {
            has_receiver: shape.has_receiver,
            parameter_count: shape.parameter_count,
        },
        claim: FoundryClaim::Flows,
        completeness: FoundryCompleteness::Partial,
        transfers: Vec::new(),
        artifact: FoundryArtifactBinding::Unresolved,
        evidence: Vec::new(),
        notes: Vec::new(),
        derivation: Some(FoundryDerivation {
            unproven_transfers: 0,
            closure_procedures: closure_procedures as u32,
            boundaries: boundaries.into_iter().collect(),
            fine_grained: Vec::new(),
        }),
    }
}

/// Every access-path carrier the relations mention that is rooted at one of
/// `ports` and says more than the bare port.
fn qualified_carriers(relations: &[ValueFlowRelation], ports: &[String]) -> Vec<ValueFlowCarrier> {
    let mut carriers: BTreeMap<String, ValueFlowCarrier> = BTreeMap::new();
    for relation in relations {
        for endpoint in [&relation.source, &relation.target] {
            let carrier = ValueFlowCarrier::from(endpoint);
            if !carrier_is_qualified_under(&carrier, ports) {
                continue;
            }
            let Some(path) = access_path(&carrier) else {
                continue;
            };
            carriers.insert(path.render(), carrier);
        }
    }
    carriers.into_values().collect()
}

/// Whether a carrier is an access path rooted at one of `ports` with at least
/// one selector.
fn carrier_is_qualified_under(carrier: &ValueFlowCarrier, ports: &[String]) -> bool {
    access_path(carrier).is_some_and(|path| path.is_qualified() && ports.contains(&path.port))
}

/// The foundry spelling of a carrier that is a procedure port, with any access
/// path beneath it.
fn access_path(carrier: &ValueFlowCarrier) -> Option<FoundryAccessPath> {
    let key = carrier.stable_key().ok()?;
    let (port, selectors) = match &key {
        ValueFlowCarrierKey::Port { kind, .. } => (*kind, &[][..]),
        ValueFlowCarrierKey::Location {
            root, selectors, ..
        } => match root.as_ref() {
            ValueFlowCarrierKey::Port { kind, .. } => (*kind, selectors.as_ref()),
            _ => return None,
        },
        _ => return None,
    };
    Some(FoundryAccessPath {
        port: port_key_label(port)?,
        selectors: selectors.iter().map(foundry_selector).collect(),
    })
}

fn foundry_selector(selector: &ValueFlowSelectorKey) -> FoundrySelector {
    match selector {
        ValueFlowSelectorKey::Field(locator) => FoundrySelector::Field {
            name: locator
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                .unwrap_or_default()
                .to_owned(),
        },
        ValueFlowSelectorKey::ExactIndex(_) => FoundrySelector::ExactIndex,
        ValueFlowSelectorKey::AnyIndex => FoundrySelector::AnyIndex,
    }
}

/// The port spelling shared with [`render_transfer`].
fn port_key_label(port: ValueFlowPortKey) -> Option<String> {
    match port {
        ValueFlowPortKey::Receiver => Some("receiver".to_owned()),
        ValueFlowPortKey::Parameter { ordinal } => Some(format!("parameter[{ordinal}]")),
        ValueFlowPortKey::NormalReturn => Some("normal_return".to_owned()),
        ValueFlowPortKey::ExceptionalReturn => Some("exceptional_return".to_owned()),
        ValueFlowPortKey::Capture { .. } => None,
    }
}

/// The receiver and parameter shape a live procedure declares.
struct ProcedureShape {
    has_receiver: bool,
    parameter_count: u32,
}

impl ProcedureShape {
    fn read(procedure: &ProcedureHandle) -> Self {
        let mut has_receiver = false;
        let mut highest_ordinal: Option<u32> = None;
        for value in procedure.semantics().values() {
            match value.kind {
                SemanticValueKind::Receiver { .. } => has_receiver = true,
                SemanticValueKind::Parameter { ordinal, .. } => {
                    highest_ordinal =
                        Some(highest_ordinal.map_or(ordinal, |seen: u32| seen.max(ordinal)));
                }
                _ => {}
            }
        }
        Self {
            has_receiver,
            parameter_count: highest_ordinal.map_or(0, |ordinal| ordinal + 1),
        }
    }

    /// The receiver and parameter ports, in port order.
    ///
    /// The port constructors validate against the same value table this shape
    /// was read from, so a port this shape declares always exists.
    fn input_ports(&self, procedure: &ProcedureHandle) -> Vec<ProcedurePortHandle> {
        let mut ports = Vec::new();
        if self.has_receiver {
            ports.push(
                ProcedurePortHandle::receiver(procedure.clone())
                    .expect("a procedure with a receiver value owns a receiver port"),
            );
        }
        for ordinal in 0..self.parameter_count {
            ports.push(
                ProcedurePortHandle::parameter(procedure.clone(), ordinal)
                    .expect("a declared parameter ordinal owns a parameter port"),
            );
        }
        ports
    }
}

fn port_source(
    point: &ProgramPointHandle,
    ordinal: u32,
    carrier: ValueFlowCarrier,
) -> ValueFlowSourceSpec {
    ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(point, ordinal, ValueFlowEventKind::Source)
            .expect("a live entry point yields a stable event key"),
        point.clone(),
        ValueFlowObservationPhase::BeforeEffects,
        carrier,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    )
}

fn port_sink(
    point: &ProgramPointHandle,
    ordinal: u32,
    carrier: ValueFlowCarrier,
) -> ValueFlowSinkSpec {
    ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(point, ordinal, ValueFlowEventKind::Sink)
            .expect("a live exit point yields a stable event key"),
        point.clone(),
        ValueFlowObservationPhase::AfterEffects,
        carrier,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    )
}

/// The argument-level projection of an input carrier.
fn authored_input(carrier: &ValueFlowCarrier) -> Option<AuthoredSummaryInput> {
    match root_port(carrier)? {
        ValueFlowPortKey::Receiver => Some(AuthoredSummaryInput::Receiver {}),
        ValueFlowPortKey::Parameter { ordinal } => {
            Some(AuthoredSummaryInput::Parameter { ordinal })
        }
        _ => None,
    }
}

/// The argument-level projection of an output carrier.
fn authored_output(
    carrier: &ValueFlowCarrier,
) -> Option<(AuthoredSummaryOutput, AuthoredSummaryExitKind)> {
    match root_port(carrier)? {
        ValueFlowPortKey::NormalReturn => Some((
            AuthoredSummaryOutput::NormalReturn {},
            AuthoredSummaryExitKind::Normal,
        )),
        ValueFlowPortKey::ExceptionalReturn => Some((
            AuthoredSummaryOutput::ExceptionalReturn {},
            AuthoredSummaryExitKind::Exceptional,
        )),
        _ => None,
    }
}

/// The procedure port a carrier is rooted at, ignoring any access path.
fn root_port(carrier: &ValueFlowCarrier) -> Option<ValueFlowPortKey> {
    match carrier.stable_key().ok()? {
        ValueFlowCarrierKey::Port { kind, .. } => Some(kind),
        ValueFlowCarrierKey::Location { root, .. } => match root.as_ref() {
            ValueFlowCarrierKey::Port { kind, .. } => Some(*kind),
            _ => None,
        },
        _ => None,
    }
}

/// The value-flow inputs one target's interprocedural closure produced.
struct ClosureInputs {
    snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
    bindings: Vec<ValueFlowInput<CallBindings>>,
    procedures: usize,
    /// Where the root's own snapshot landed. `None` when the oracle returned no
    /// snapshot for the root at all, which is a target with no observable body
    /// rather than a target with no flow.
    root_snapshot: Option<usize>,
}

impl ClosureInputs {
    /// The target's own relations, which are the only ones whose program points
    /// may carry this target's sinks.
    fn root_relations(&self) -> &[ValueFlowRelation] {
        self.root_snapshot
            .and_then(|index| self.snapshots.get(index))
            .map_or(&[][..], |input| input.value().relations())
    }
}

/// Walk the resolved call closure from `root`, collecting the plan's inputs and
/// every typed reason the walk could not continue.
///
/// This is deliberately not the taint policy's `discover_value_flow`. That walk
/// aborts on the first interrupted oracle outcome because a policy verdict must
/// not rest on a partial input; this one records the interruption as typed
/// incompleteness on the entry and keeps going, because a partial derivation
/// that names its boundary is exactly the artifact this stage ships. A provider
/// error is treated the same way: over a whole standard library it is a finding
/// about one target, not a reason to stop deriving the rest.
fn discover_closure(
    analyzer: &WorkspaceAnalyzer,
    root: &ProcedureHandle,
    declarations: &DeclarationIndex,
    limits: DerivationLimits,
    semantic_budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
    boundaries: &mut BTreeSet<FoundryDerivationBoundary>,
) -> ClosureInputs {
    let oracle = analyzer.semantic_oracle_provider();
    let context = OracleCallContext::empty();
    let mut pending = vec![root.clone()];
    let mut seen: HashSet<ProcedureHandle> = HashSet::new();
    let mut seen_bindings = BTreeSet::new();
    let mut snapshots = Vec::new();
    let mut bindings = Vec::new();
    let mut root_snapshot = None;
    while let Some(procedure) = pending.pop() {
        if !seen.insert(procedure.clone()) {
            continue;
        }
        if seen.len() > limits.max_closure_procedures {
            boundaries.insert(FoundryDerivationBoundary::ClosureLimit {
                limit: limits.max_closure_procedures as u32,
            });
            break;
        }

        let outcome = match oracle.procedure_relations(
            &procedure,
            &context,
            &mut SemanticRequest::new(semantic_budget, cancellation),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                boundaries.insert(FoundryDerivationBoundary::EngineRejected {
                    detail: format!("relations: {error}"),
                });
                continue;
            }
        };
        let status = SemanticInputStatus::from_outcome(&outcome);
        record_status(boundaries, status);
        let Some(snapshot) = outcome.available_value().cloned() else {
            continue;
        };
        if &procedure == root {
            root_snapshot = Some(snapshots.len());
        }
        snapshots.push(ValueFlowInput::new(snapshot, status));

        for call_row in procedure.semantics().call_sites() {
            let call = procedure
                .call_site_handle(call_row.id)
                .expect("a live procedure owns each retained call site");
            let dispatch = match oracle.resolve_call(
                &call,
                &mut SemanticRequest::new(semantic_budget, cancellation),
            ) {
                Ok(dispatch) => dispatch,
                Err(error) => {
                    boundaries.insert(FoundryDerivationBoundary::EngineRejected {
                        detail: format!("dispatch: {error}"),
                    });
                    continue;
                }
            };
            let dispatch_status = SemanticInputStatus::from_outcome(&dispatch);
            record_status(boundaries, dispatch_status);
            let Some(dispatch) = dispatch.available_value() else {
                boundaries.insert(FoundryDerivationBoundary::UnresolvedCall);
                continue;
            };
            for boundary in dispatch.boundaries() {
                boundaries.insert(classify_boundary(declarations, &boundary.kind));
            }
            for candidate in dispatch.candidates() {
                let key = (call.id(), candidate.target().semantics().locator().clone());
                if !seen_bindings.insert(key) {
                    continue;
                }
                let outcome = match oracle.call_bindings(
                    &call,
                    candidate,
                    &context,
                    &mut SemanticRequest::new(semantic_budget, cancellation),
                ) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        boundaries.insert(FoundryDerivationBoundary::EngineRejected {
                            detail: format!("binding: {error}"),
                        });
                        continue;
                    }
                };
                let status = dispatch_status.merge(SemanticInputStatus::from_outcome(&outcome));
                record_status(boundaries, status);
                if let Some(binding) = outcome.available_value().cloned() {
                    bindings.push(ValueFlowInput::new(binding, status));
                    pending.push(candidate.target().clone());
                }
            }
        }
    }
    ClosureInputs {
        snapshots,
        bindings,
        procedures: seen.len(),
        root_snapshot,
    }
}

fn record_status(
    boundaries: &mut BTreeSet<FoundryDerivationBoundary>,
    status: SemanticInputStatus,
) {
    if status.is_complete() {
        return;
    }
    if let Some(exceeded) = status.budget_exceeded() {
        boundaries.insert(FoundryDerivationBoundary::BudgetExceeded {
            detail: exceeded.to_string(),
        });
        return;
    }
    boundaries.insert(FoundryDerivationBoundary::SemanticGap {
        status: status.label().to_owned(),
        capability: status
            .unsupported_capability()
            .map(|capability| capability.label().to_owned()),
    });
}

/// Turn one dispatch boundary into the foundry's typed reason.
///
/// A callee the workspace declares but never materializes is the interesting
/// case: the analyzer cannot tell `native` from `abstract` at the call site,
/// because neither produces a body, so the reason comes from the callee's own
/// declared modifiers.
fn classify_boundary(
    declarations: &DeclarationIndex,
    kind: &DispatchBoundaryKind,
) -> FoundryDerivationBoundary {
    match kind {
        DispatchBoundaryKind::Unmaterialized(target) => {
            let callee = declarations.render(target);
            if declarations.is_native(target) {
                FoundryDerivationBoundary::NativeCallee { callee }
            } else {
                FoundryDerivationBoundary::CalleeWithoutBody { callee }
            }
        }
        DispatchBoundaryKind::External(target) => FoundryDerivationBoundary::ExternalCallee {
            callee: target.as_ref().map(|target| declarations.render(target)),
        },
        DispatchBoundaryKind::Deferred { target, kind } => {
            FoundryDerivationBoundary::DeferredCallee {
                callee: declarations.render(target),
                kind: format!("{kind:?}"),
            }
        }
        DispatchBoundaryKind::Unresolved => FoundryDerivationBoundary::UnresolvedCall,
        DispatchBoundaryKind::Truncated => FoundryDerivationBoundary::TruncatedDispatch,
    }
}

/// Every callable the pinned sources declare, keyed the way a semantic locator
/// names it.
///
/// The semantic IR drops a Java method that has no body, so a native or
/// abstract callee exists only here. The index is also where a derived target
/// gets its package and its parameter-type spellings: both are declaration
/// facts the structural analyzer already reads from the declaration's own
/// nodes.
struct DeclarationIndex {
    /// (file, member identifier) to every overload declared under that name.
    ///
    /// The member identifier is the key both locator shapes share. A semantic
    /// procedure is named `[File, Type.., Method]`; a dispatch boundary names a
    /// declaration the resolver found, which carries `[File, Function]` and no
    /// owning type. Keying on the identifier plus the file lets one index serve
    /// both, and the owning type comes back from the declaration itself.
    callables: BTreeMap<(PathBuf, String), Vec<DeclaredCallable>>,
}

#[derive(Debug, Clone)]
struct DeclaredCallable {
    /// The `Type.member` spelling, which disambiguates two same-named members
    /// declared by different types in one file.
    short_name: String,
    package_name: String,
    parameter_types: Vec<String>,
    is_native: bool,
    range: Range,
}

impl DeclarationIndex {
    fn build(analyzer: &WorkspaceAnalyzer, files: &[ProjectFile]) -> Self {
        let mut callables: BTreeMap<(PathBuf, String), Vec<DeclaredCallable>> = BTreeMap::new();
        for file in files {
            for code_unit in analyzer.analyzer().get_declarations(file) {
                if !code_unit.kind().is_callable_kind() {
                    continue;
                }
                let ranges = analyzer.analyzer().ranges(&code_unit);
                for (index, metadata) in analyzer
                    .analyzer()
                    .signature_metadata(&code_unit)
                    .into_iter()
                    .enumerate()
                {
                    if !metadata.callable_modifiers_recorded() {
                        continue;
                    }
                    let Some(range) = ranges
                        .get(index)
                        .copied()
                        .or_else(|| ranges.first().copied())
                    else {
                        continue;
                    };
                    callables
                        .entry((
                            file.rel_path().to_path_buf(),
                            code_unit.identifier().to_owned(),
                        ))
                        .or_default()
                        .push(DeclaredCallable {
                            short_name: code_unit.short_name().to_owned(),
                            package_name: code_unit.package_name().to_owned(),
                            parameter_types: metadata
                                .callable_parameter_types()
                                .unwrap_or_default()
                                .to_vec(),
                            is_native: metadata.callable_is_native(),
                            range,
                        });
                }
            }
        }
        for overloads in callables.values_mut() {
            overloads.sort_by_key(|overload| overload.range.start_byte);
        }
        Self { callables }
    }

    /// Every declaration the locator's file and member identifier name, in
    /// source order.
    fn overloads(&self, locator: &SemanticLocator) -> &[DeclaredCallable] {
        let Some(identifier) = locator
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
        else {
            return &[];
        };
        self.callables
            .get(&(
                PathBuf::from(locator.path().as_str()),
                identifier.to_owned(),
            ))
            .map_or(&[][..], |overloads| overloads.as_slice())
    }

    /// Whether every declaration the locator names is `native`.
    ///
    /// One name can cover more than one overload, and a dispatch boundary names
    /// the declaration without pinning the overload. Claiming "native" when
    /// only some overloads are would overstate the boundary, so the answer is
    /// the conjunction.
    fn is_native(&self, locator: &SemanticLocator) -> bool {
        let overloads = self.overloads(locator);
        !overloads.is_empty() && overloads.iter().all(|overload| overload.is_native)
    }

    /// A stable spelling for a boundary callee.
    ///
    /// A boundary locator carries the declaring file and the member, never the
    /// owning type, so the spelling names those two. That is also exactly what
    /// a reviewer needs to find the declaration in the pinned sources.
    fn render(&self, locator: &SemanticLocator) -> String {
        format!("{}#{}", locator.path().as_str(), member_name(locator))
    }

    /// The foundry target one derived procedure claims.
    fn target_for(&self, procedure: &ProcedureHandle) -> Option<FoundryTarget> {
        let locator = procedure.semantics().locator();
        let short = short_name(locator.declaration());
        let anchor = locator.anchor().span();
        let declared = self
            .overloads(locator)
            .iter()
            .filter(|declared| declared.short_name == short)
            .find(|declared| {
                declared.range.start_byte <= anchor.start_byte() as usize
                    && declared.range.end_byte >= anchor.end_byte() as usize
            })?;
        Some(FoundryTarget {
            artifact_path: class_file_path(&declared.package_name, &binary_type_name(locator)),
            member: member_name(locator),
            signature: FoundrySignature::Overload {
                types: declared.parameter_types.clone(),
            },
        })
    }
}

/// The `Type.member` spelling a structural declaration carries.
///
/// The structural adapter builds a callable's short name as the owner's short
/// name plus the member name, so the same string keys both sides of the join
/// between the semantic IR and the declaration surface.
fn short_name(declaration: &DeclarationLocator) -> String {
    declaration
        .segments()
        .iter()
        .filter_map(|segment| match segment.kind() {
            DeclarationSegmentKind::Type
            | DeclarationSegmentKind::Method
            | DeclarationSegmentKind::Constructor => segment.name().map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The `Outer$Inner` binary spelling of the type that owns a declaration.
fn binary_type_name(locator: &SemanticLocator) -> String {
    locator
        .declaration()
        .segments()
        .iter()
        .filter(|segment| segment.kind() == DeclarationSegmentKind::Type)
        .filter_map(|segment| segment.name().map(str::to_owned))
        .collect::<Vec<_>>()
        .join("$")
}

/// The member spelling, with constructors normalized to the JVM's `<init>`.
fn member_name(locator: &SemanticLocator) -> String {
    let Some(segment) = locator.declaration().segments().last() else {
        return String::new();
    };
    match segment.kind() {
        DeclarationSegmentKind::Constructor => CONSTRUCTOR_MEMBER.to_owned(),
        _ => segment.name().unwrap_or_default().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reduced verbatim slices of the pinned Temurin 21.0.8+9 `src.zip`. See
    /// `PROVENANCE.md` beside them.
    fn pinned_jdk_slices() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/summary-sources/temurin-jdk-21.0.8+9")
    }

    fn entry_for<'run>(run: &'run DerivationRun, symbol: &str) -> &'run FoundryEntry {
        run.entries
            .iter()
            .find(|entry| entry.target.signature.symbol(&entry.target.member) == symbol)
            .unwrap_or_else(|| {
                panic!(
                    "no derived entry for {symbol}; derived {:?}",
                    run.entries
                        .iter()
                        .map(|entry| entry.target.signature.symbol(&entry.target.member))
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn a_pure_java_class_derives_exactly_the_flows_its_body_carries() {
        let run = derive_jvm_summaries(&pinned_jdk_slices(), DerivationLimits::default())
            .expect("the pinned slices derive");

        // `return obj;`
        assert_eq!(
            entry_for(&run, "requireNonNull(T)").rendered_transfers(),
            vec!["parameter[0]->normal_return@normal".to_owned()]
        );
        // `return (obj != null) ? obj : requireNonNull(defaultObj, "defaultObj");`
        // The second transfer exists only because the derivation entered the
        // callee, so this is the interprocedural case.
        assert_eq!(
            entry_for(&run, "requireNonNullElse(T,T)").rendered_transfers(),
            vec![
                "parameter[0]->normal_return@normal".to_owned(),
                "parameter[1]->normal_return@normal".to_owned(),
            ]
        );
        // `return (o != null) ? o.toString() : nullDefault;` The receiver's
        // `toString` is a virtual call the closure cannot enter, so only the
        // default reaches the return. Nothing is guessed past that call.
        assert_eq!(
            entry_for(&run, "toString(Object,String)").rendered_transfers(),
            vec!["parameter[1]->normal_return@normal".to_owned()]
        );
        // The same shape through `supplier.get()`.
        assert_eq!(
            entry_for(&run, "requireNonNullElseGet(T,Supplier<? extends T>)").rendered_transfers(),
            vec!["parameter[0]->normal_return@normal".to_owned()]
        );
    }

    #[test]
    fn a_native_backed_body_records_the_native_boundary_instead_of_guessing() {
        let run = derive_jvm_summaries(&pinned_jdk_slices(), DerivationLimits::default())
            .expect("the pinned slices derive");

        // `return newArray(componentType, length);` where `newArray` is
        // `private static native`.
        let entry = entry_for(&run, "newInstance(Class<?>,int)");
        let derivation = entry.derivation.as_ref().expect("a derived entry");

        assert!(
            entry.transfers.is_empty(),
            "the return value comes from a native call: {:?}",
            entry.rendered_transfers()
        );
        assert!(
            derivation
                .boundaries
                .contains(&FoundryDerivationBoundary::NativeCallee {
                    callee: "java/lang/reflect/Array.java#newArray".to_owned()
                }),
            "boundaries: {:?}",
            derivation.boundaries
        );
        assert_eq!(entry.completeness, FoundryCompleteness::Partial);
        assert_eq!(entry.claim, FoundryClaim::Flows);
    }

    #[test]
    fn an_unmodeled_heap_read_is_recorded_rather_than_answered_with_no_flow() {
        let root = tempfile::tempdir().expect("temporary workspace");
        std::fs::create_dir_all(root.path().join("probe")).expect("package directory");
        std::fs::write(
            root.path().join("probe/Box.java"),
            concat!(
                "package probe;\n",
                "public final class Box {\n",
                "    public String value;\n",
                "    public static String read(Box box) {\n",
                "        return box.value;\n",
                "    }\n",
                "}\n",
            ),
        )
        .expect("fixture source");

        let run = derive_jvm_summaries(root.path(), DerivationLimits::default())
            .expect("fixture derives");
        let entry = entry_for(&run, "read(Box)");
        let derivation = entry.derivation.as_ref().expect("a derived entry");

        // The field read reaches the return, but the value-flow oracle reports
        // the heap capability as unsupported rather than relating the parameter
        // port to a path beneath it. The entry must therefore stay partial: a
        // `no_flow` claim here would be a silent false negative.
        assert!(entry.transfers.is_empty());
        assert_eq!(entry.claim, FoundryClaim::Flows);
        assert_eq!(entry.completeness, FoundryCompleteness::Partial);
        assert!(
            derivation
                .boundaries
                .iter()
                .any(|boundary| boundary.kind() == "semantic_gap"),
            "boundaries: {:?}",
            derivation.boundaries
        );
    }

    #[test]
    fn an_access_path_carrier_keeps_its_selectors_and_projects_onto_its_port() {
        // The shipping transfer is the projection of the derived flow onto its
        // two ports. The projection must be the only place granularity is lost,
        // so the fine-grained form has to survive it.
        let qualified = FoundryFineGrainedTransfer {
            input: FoundryAccessPath {
                port: "parameter[0]".to_owned(),
                selectors: vec![
                    FoundrySelector::AnyIndex,
                    FoundrySelector::Field {
                        name: "value".to_owned(),
                    },
                ],
            },
            output: FoundryAccessPath {
                port: "normal_return".to_owned(),
                selectors: Vec::new(),
            },
            exit_kind: "normal".to_owned(),
        };

        assert_eq!(
            qualified.render(),
            "parameter[0].Element.Field[value]->normal_return@normal"
        );
        assert!(qualified.is_qualified());
        assert_eq!(qualified.input.port, "parameter[0]");
        assert!(!qualified.output.is_qualified());
    }

    #[test]
    fn two_runs_over_the_same_sources_agree() {
        let first = derive_jvm_summaries(&pinned_jdk_slices(), DerivationLimits::default())
            .expect("the pinned slices derive");
        let second = derive_jvm_summaries(&pinned_jdk_slices(), DerivationLimits::default())
            .expect("the pinned slices derive");

        assert_eq!(first, second);
    }
}
