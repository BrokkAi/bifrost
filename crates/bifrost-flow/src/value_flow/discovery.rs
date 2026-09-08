//! Shared resolved-call closure discovery for whole-program flow clients.
//!
//! One worklist serves every client that plans over a root's reachable
//! procedures: pop a procedure, deduplicate by durable key, stop at the
//! procedure cap, fetch its relation snapshot, resolve each of its call
//! sites, bind every entered candidate, and record the dispatch arms nobody
//! could enter. The type-flow client and the dataflow differential consume
//! the workspace convenience below; the policy compiler and the summary
//! foundry walk the same loop through their own [`ValueFlowProvider`]
//! implementations.
//!
//! Discovery is honest about what it did not enter. Every skipped procedure
//! and dispatch boundary is returned, and per call site a [`CallSiteCoverage`]
//! records the dispatch and binding statuses, which candidates were entered,
//! and whether the procedure cap stopped before an entered candidate could be
//! processed. A caller must never read incomplete coverage as a call whose
//! result carries no values.

use std::sync::Arc;

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CallBindings, CallSiteId, CancellationToken, CandidateCoverage, DispatchBoundary,
    DispatchBoundaryKind, OracleCallContext, ProcedureHandle, ProcedureId, SemanticArtifactKey,
    SemanticBudget, SemanticProviderError, SemanticRequest, ValueFlowSnapshot,
};
use crate::dataflow::SemanticInputStatus;
use crate::hash::{HashMap, HashSet};

use super::{ValueFlowCache, ValueFlowInput, ValueFlowProvider, WorkspaceValueFlowProvider};

/// How the closure walk names one procedure across two materializations of
/// its artifact. `ProcedureHandle::durable_key` returns exactly this pair.
pub type DurableProcedureKey = (SemanticArtifactKey, ProcedureId);

/// Bounds on one closure discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosureLimits {
    pub max_procedures: usize,
}

/// What the walk learned about one resolved call site.
#[derive(Debug, Clone)]
pub struct CallSiteCoverage {
    /// Candidates whose bindings were obtained and whose procedures were
    /// queued for discovery.
    pub entered: Vec<ProcedureHandle>,
    /// The dispatch answer named at least one arm that cannot be entered or
    /// modeled completely. A proven external arm with complete authored
    /// summary evidence remains in `boundaries` but does not set this bit.
    pub has_uncovered_boundary: bool,
    /// The walk stopped before it could process at least one arm of this
    /// call: a truncated dispatch enumeration, or an entered candidate left
    /// unprocessed when the procedure cap was reached.
    pub truncated: bool,
    /// The dispatch answer was truncated only because a syntax-derived
    /// external receiver arm could not prove workspace override absence. A
    /// complete type-flow receiver hint may refine that exact arm.
    pub complete_receiver_hint_refinable: bool,
    /// Whether dispatch produced a usable answer and the semantic quality of
    /// that answer, or the provider error that prevented one.
    pub dispatch: DispatchStatus,
    /// One status for every in-mount dispatch candidate whose bindings the
    /// walk requested.
    pub bindings: Vec<BindingCoverage>,
}

/// A persisted, replay-validated procedure surface mounted for identity and
/// result-coverage parity without making its body executable in this plan.
#[derive(Debug, Clone)]
pub struct HydratedProcedureSurface {
    pub procedure: ProcedureHandle,
    pub snapshot: ValueFlowInput<ValueFlowSnapshot>,
    pub coverage: Vec<(CallSiteId, CallSiteCoverage)>,
    pub dispatch_reads: Box<[crate::analyzer::ReadKey]>,
    pub boundaries: Vec<DispatchBoundary>,
}

/// What happened when the walk requested one call site's dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchStatus {
    Resolved {
        status: SemanticInputStatus,
        coverage: CandidateCoverage,
    },
    Unavailable {
        status: SemanticInputStatus,
    },
    ProviderError {
        detail: String,
    },
}

/// What happened when the walk requested one dispatch candidate's bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingCoverage {
    /// The provider returned a semantic outcome. `status` is merged with the
    /// call site's dispatch status because both inputs bound this candidate.
    Answered {
        status: SemanticInputStatus,
    },
    ProviderError {
        detail: String,
    },
}

/// Why a visited procedure did not contribute a relation snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    ProviderError { detail: String },
    RelationsUnavailable { status: SemanticInputStatus },
}

/// One root's resolved-call closure.
#[derive(Debug)]
pub struct DiscoveredClosure {
    /// Every procedure that produced a snapshot, in discovery order.
    pub procedures: Vec<ProcedureHandle>,
    pub snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
    pub bindings: Vec<ValueFlowInput<CallBindings>>,
    pub coverage: HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
    /// Exact replay-validated dispatch reads for identity-only surfaces. Live
    /// ordinary procedures are populated by the observing provider instead.
    pub certified_dispatch_reads: HashMap<DurableProcedureKey, Box<[crate::analyzer::ReadKey]>>,
    /// Every visited procedure that did not produce a relation snapshot, in
    /// discovery order.
    pub skipped: Vec<(ProcedureHandle, SkipReason)>,
    /// Every dispatch boundary seen at every resolved call site, in
    /// discovery order. Consumers classify the arms they care about.
    pub boundaries: Vec<DispatchBoundary>,
    /// Procedures whose own snapshot was retained but whose entered call
    /// descendants were deliberately not acquired because a reusable summary
    /// is mandatory for every entry reached through this plan. Immediate
    /// lexical children are still acquired normally. A pre-dispatch cut also
    /// supplies replay-validated direct coverage instead of asking the live
    /// provider for the cut procedure's dispatch and bindings.
    pub summary_cuts: Vec<ProcedureHandle>,
    /// The walk stopped at `limits.max_procedures` with work left over.
    pub truncated: bool,
    /// Index into `snapshots` of the root's own relations, absent when the
    /// root's relations were unavailable.
    pub root_snapshot: Option<usize>,
}

/// Decides whether one non-root procedure may stand on a mandatory reusable
/// summary instead of acquiring its descendant closure.
///
/// A positive answer is speculative. A pre-dispatch answer supplies the
/// current procedure's replay-validated surface before live dispatch; a
/// post-dispatch answer uses the direct coverage discovery just acquired.
/// Identity-only descendant surfaces may lack executable bodies in either
/// case. The summary provider must turn every later miss or validation failure
/// into a typed full-plan retry rather than letting the solver enter an
/// incomplete mounted body.
pub trait ClosureCutDecider {
    /// Try to certify this non-root procedure before discovery asks the live
    /// provider for its direct dispatch and bindings.
    ///
    /// The returned surface must belong to the exact `procedure` handle and
    /// snapshot passed here. Discovery accepts it only when all staged
    /// identity surfaces and the procedure's immediate lexical children fit
    /// the procedure cap. A miss or rejected reservation falls back to the
    /// ordinary live acquisition path.
    fn pre_dispatch_cut(
        &mut self,
        _procedure: &ProcedureHandle,
        _snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        _request: &mut SemanticRequest<'_>,
    ) -> Option<HydratedProcedureSurface> {
        None
    }

    fn should_cut(
        &mut self,
        procedure: &ProcedureHandle,
        snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        coverage: &HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
        request: &mut SemanticRequest<'_>,
    ) -> bool;

    /// Descendant procedure identity surfaces staged by the same cut decision.
    /// They are mounted only if ordinary discovery did not independently reach
    /// and fully process the same durable procedure. Discovery calls exactly
    /// one of [`Self::accept_staged_cut`] and [`Self::discard_staged_cut`] after
    /// checking whether the complete reservation fits the procedure cap.
    fn take_hydrated_surfaces(&mut self) -> Vec<HydratedProcedureSurface> {
        Vec::new()
    }

    /// Commit state staged by the most recent positive cut decision.
    fn accept_staged_cut(&mut self) {}

    /// Roll back state staged by the most recent positive cut decision.
    fn discard_staged_cut(&mut self) {}
}

#[derive(Debug, Default)]
struct NoClosureCuts;

impl ClosureCutDecider for NoClosureCuts {
    fn should_cut(
        &mut self,
        _procedure: &ProcedureHandle,
        _snapshot: &ValueFlowInput<ValueFlowSnapshot>,
        _coverage: &HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
        _request: &mut SemanticRequest<'_>,
    ) -> bool {
        false
    }
}

/// Walk the resolved call closure from `root` over the default
/// [`WorkspaceValueFlowProvider`] and collect the plan inputs a whole-program
/// flow client needs. This is a convenience over [`discover_closure_with`];
/// the fresh per-call cache never hits because the walk dedups every request,
/// so outcomes and budget charges match a direct oracle walk.
pub fn discover_closure(
    workspace: &WorkspaceAnalyzer,
    root: &ProcedureHandle,
    limits: ClosureLimits,
    semantic_budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<DiscoveredClosure, SemanticProviderError> {
    let provider = WorkspaceValueFlowProvider::new(workspace, ValueFlowCache::default());
    discover_closure_with(&provider, root, limits, semantic_budget, cancellation)
}

/// Walk the resolved call closure from `root` through `provider` and collect
/// the plan inputs a whole-program flow client needs.
///
/// An interrupted or failed oracle outcome is recorded only as the typed
/// status on the input it produced, never as an abort: the client audits
/// whatever plan the engine can actually build. A provider `Err` away from
/// the root is likewise recorded and skipped (the consumer's provider decides
/// whether to keep answering after it); the single hard failure is a provider
/// error on the root's own relation request, because a closure without its
/// root plans nothing.
///
/// Lexical children are enqueued the way the taint client does (#2640): a
/// lambda, closure, or block body is part of its enclosing procedure's
/// analysis region even though no call dispatches to its declaration, so a
/// call-only closure would leave those bodies unmounted and their gaps open.
///
/// A callee outside the root's mount is dropped before it is bound.
/// `ValueFlowPlan` rejects a foreign-mount snapshot or binding outright
/// (`ForeignWorkspace`), so enqueueing one would fail every plan built from
/// this closure rather than losing one callee's detail.
pub fn discover_closure_with<P: ValueFlowProvider>(
    provider: &P,
    root: &ProcedureHandle,
    limits: ClosureLimits,
    semantic_budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<DiscoveredClosure, P::Error> {
    discover_closure_with_cuts(
        provider,
        root,
        limits,
        semantic_budget,
        cancellation,
        &mut NoClosureCuts,
    )
}

/// Walk the resolved call closure, allowing `cuts` to stop descendant
/// acquisition after a non-root procedure's own snapshot is retained.
pub fn discover_closure_with_cuts<P: ValueFlowProvider, C: ClosureCutDecider>(
    provider: &P,
    root: &ProcedureHandle,
    limits: ClosureLimits,
    semantic_budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
    cuts: &mut C,
) -> Result<DiscoveredClosure, P::Error> {
    let context = OracleCallContext::empty();
    let mount = root.artifact().key().mount();

    let root_key = root.durable_key();
    let mut pending = vec![root.clone()];
    // Keyed on the durable key, not the handle: `ProcedureHandle` equality
    // compares the owning `Arc<SemanticArtifact>` by pointer, and the
    // complete-artifact cache can evict and re-materialize a large file while
    // this closure is still being walked. Keyed on the handle, the walk would
    // push a second copy of one procedure's snapshot, whose local rules would
    // then appear twice in every plan built from it.
    let mut seen: HashSet<DurableProcedureKey> = HashSet::default();
    // Every durable key ever pushed onto `pending`: the union of `seen` and
    // the keys still queued. One key enters the worklist at most once, so a
    // procedure still queued when the cap stops the walk was never processed
    // -- the premise the truncation pass below asserts. Without this dedup a
    // callee bound from two call sites is pushed once per binding, and the
    // copy still queued when its sibling tripped the cap was both discovered
    // and unprocessed, which is exactly what the assertion rejects.
    let mut queued: HashSet<DurableProcedureKey> = HashSet::default();
    queued.insert(root_key.clone());
    // `CallSiteId` indexes its own procedure's dense call-site table, so the
    // caller has to be part of the key: without it, two callers whose call
    // sites share an index and a callee collapse to one entry and the second
    // caller's bindings are silently dropped from the plan.
    let mut seen_bindings: HashSet<(DurableProcedureKey, CallSiteId, DurableProcedureKey)> =
        HashSet::default();
    // Which call sites queued each procedure, so the cap can name the calls
    // whose entered candidates were never processed.
    let mut queued_by: HashMap<DurableProcedureKey, Vec<(DurableProcedureKey, CallSiteId)>> =
        HashMap::default();
    let mut hydrated_surfaces = HashMap::<DurableProcedureKey, HydratedProcedureSurface>::default();

    let mut closure = DiscoveredClosure {
        procedures: Vec::new(),
        snapshots: Vec::new(),
        bindings: Vec::new(),
        coverage: HashMap::default(),
        certified_dispatch_reads: HashMap::default(),
        skipped: Vec::new(),
        boundaries: Vec::new(),
        summary_cuts: Vec::new(),
        truncated: false,
        root_snapshot: None,
    };

    while let Some(procedure) = pending.pop() {
        // Anchor every popped handle to the provider's canonical artifact
        // instance, so every handle the walk mints beneath it (call sites,
        // snapshots) belongs to one instance (#2289). The default provider
        // keeps the handle as minted.
        let procedure = provider.canonical_procedure(&procedure);
        let procedure_key = procedure.durable_key();
        if seen.contains(&procedure_key) {
            continue;
        }
        // An ordinarily reached procedure supersedes an identity-only surface
        // for the same durable key. Remove it before checking the cap so this
        // full acquisition consumes the slot that the surface had reserved.
        hydrated_surfaces.remove(&procedure_key);
        if seen.len().saturating_add(hydrated_surfaces.len()) >= limits.max_procedures {
            closure.truncated = true;
            // Keep the refused procedure with the other queued work so the
            // truncation pass marks every call site whose entered candidate
            // was not processed, including the candidate that tripped the cap.
            pending.push(procedure);
            break;
        }
        assert!(
            seen.insert(procedure_key.clone()),
            "a new procedure key enters the discovered set"
        );

        // A root whose own relations are unavailable yields a closure with no
        // root snapshot; the caller decides whether planning can proceed.
        let is_root = procedure_key == root_key;
        let outcome = provider.procedure_snapshot(
            &procedure,
            &context,
            &mut SemanticRequest::new(semantic_budget, cancellation),
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if is_root {
                    return Err(error);
                }
                closure.skipped.push((
                    procedure.clone(),
                    SkipReason::ProviderError {
                        detail: error.to_string(),
                    },
                ));
                continue;
            }
        };
        let status = SemanticInputStatus::from_outcome(&outcome);
        let Some(snapshot) = outcome.available_value().cloned() else {
            closure.skipped.push((
                procedure.clone(),
                SkipReason::RelationsUnavailable { status },
            ));
            continue;
        };
        if is_root {
            closure.root_snapshot = Some(closure.snapshots.len());
        }
        closure.procedures.push(procedure.clone());
        closure
            .snapshots
            .push(ValueFlowInput::new(snapshot, status));

        let mut lexical_descendants = Vec::new();
        let mut call_descendants = Vec::new();
        let artifact = Arc::clone(procedure.artifact());
        for &id in artifact.lexical_children(procedure.id()) {
            let child = artifact
                .procedure_handle(id)
                .expect("a live artifact owns each retained procedure");
            lexical_descendants.push(child);
        }

        let pre_dispatch_surface = if is_root {
            None
        } else {
            cuts.pre_dispatch_cut(
                &procedure,
                closure
                    .snapshots
                    .last()
                    .expect("the retained procedure snapshot was just appended"),
                &mut SemanticRequest::new(semantic_budget, cancellation),
            )
        };
        if let Some(surface) = pre_dispatch_surface {
            assert_eq!(
                surface.procedure, procedure,
                "a pre-dispatch cut surface belongs to the exact current procedure handle"
            );
            assert_eq!(
                surface.snapshot.value().procedure(),
                &procedure,
                "a pre-dispatch cut snapshot belongs to the exact current procedure handle"
            );
            let staged_surfaces = cuts.take_hydrated_surfaces();
            let mut reserved = queued.clone();
            reserved.extend(hydrated_surfaces.keys().cloned());
            reserved.extend(
                staged_surfaces
                    .iter()
                    .map(|surface| surface.procedure.durable_key()),
            );
            reserved.extend(lexical_descendants.iter().map(ProcedureHandle::durable_key));
            if reserved.len() <= limits.max_procedures {
                cuts.accept_staged_cut();
                *closure
                    .snapshots
                    .last_mut()
                    .expect("the retained procedure snapshot was just appended") = surface.snapshot;
                for (call, coverage) in surface.coverage {
                    let previous = closure
                        .coverage
                        .insert((procedure_key.clone(), call), coverage);
                    assert!(
                        previous.is_none(),
                        "a pre-dispatch cut has no ordinary coverage row"
                    );
                }
                closure.boundaries.extend(surface.boundaries);
                let previous = closure
                    .certified_dispatch_reads
                    .insert(procedure_key.clone(), surface.dispatch_reads);
                assert!(
                    previous.is_none(),
                    "one pre-dispatch cut has one dispatch-read contract"
                );
                closure.summary_cuts.push(procedure);
                for surface in staged_surfaces {
                    let surface_key = surface.procedure.durable_key();
                    if !seen.contains(&surface_key) && !queued.contains(&surface_key) {
                        hydrated_surfaces.entry(surface_key).or_insert(surface);
                    }
                }
                for descendant in lexical_descendants {
                    let key = descendant.durable_key();
                    hydrated_surfaces.remove(&key);
                    if queued.insert(key) {
                        pending.push(descendant);
                    }
                }
                continue;
            }
            cuts.discard_staged_cut();
        }

        for call_row in procedure.semantics().call_sites() {
            let call = procedure
                .call_site_handle(call_row.id)
                .expect("a live procedure owns each retained call site");
            let dispatch = provider.resolve_call(
                &call,
                &mut SemanticRequest::new(semantic_budget, cancellation),
            );
            let dispatch = match dispatch {
                Ok(dispatch) => dispatch,
                Err(error) => {
                    let previous = closure.coverage.insert(
                        (procedure_key.clone(), call_row.id),
                        CallSiteCoverage {
                            entered: Vec::new(),
                            has_uncovered_boundary: false,
                            truncated: false,
                            complete_receiver_hint_refinable: false,
                            dispatch: DispatchStatus::ProviderError {
                                detail: error.to_string(),
                            },
                            bindings: Vec::new(),
                        },
                    );
                    assert!(previous.is_none(), "a call site is visited exactly once");
                    continue;
                }
            };
            let dispatch_status = SemanticInputStatus::from_outcome(&dispatch);
            let Some(dispatch) = dispatch.available_value() else {
                let previous = closure.coverage.insert(
                    (procedure_key.clone(), call_row.id),
                    CallSiteCoverage {
                        entered: Vec::new(),
                        has_uncovered_boundary: false,
                        truncated: false,
                        complete_receiver_hint_refinable: false,
                        dispatch: DispatchStatus::Unavailable {
                            status: dispatch_status,
                        },
                        bindings: Vec::new(),
                    },
                );
                assert!(previous.is_none(), "a call site is visited exactly once");
                continue;
            };
            let coverage_key = (procedure_key.clone(), call_row.id);
            let previous = closure.coverage.insert(
                coverage_key.clone(),
                CallSiteCoverage {
                    entered: Vec::new(),
                    has_uncovered_boundary: dispatch
                        .boundaries()
                        .iter()
                        .any(dispatch_boundary_is_uncovered),
                    truncated: dispatch
                        .boundaries()
                        .iter()
                        .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Truncated)),
                    complete_receiver_hint_refinable: dispatch.complete_receiver_hint_refinable(),
                    dispatch: DispatchStatus::Resolved {
                        status: dispatch_status,
                        coverage: dispatch.coverage(),
                    },
                    bindings: Vec::new(),
                },
            );
            assert!(previous.is_none(), "a call site is visited exactly once");
            closure
                .boundaries
                .extend(dispatch.boundaries().iter().cloned());
            for candidate in dispatch.candidates() {
                let target = candidate.target();
                let target_key = target.durable_key();
                if target_key.0.mount() != mount {
                    continue;
                }
                if !seen_bindings.insert((procedure_key.clone(), call.id(), target_key.clone())) {
                    continue;
                }
                let outcome = provider.call_bindings(
                    &call,
                    candidate,
                    &context,
                    &mut SemanticRequest::new(semantic_budget, cancellation),
                );
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        closure
                            .coverage
                            .get_mut(&coverage_key)
                            .expect("dispatch initialized this call's coverage")
                            .bindings
                            .push(BindingCoverage::ProviderError {
                                detail: error.to_string(),
                            });
                        continue;
                    }
                };
                let status = dispatch_status.merge(SemanticInputStatus::from_outcome(&outcome));
                closure
                    .coverage
                    .get_mut(&coverage_key)
                    .expect("dispatch initialized this call's coverage")
                    .bindings
                    .push(BindingCoverage::Answered { status });
                if let Some(binding) = outcome.available_value().cloned() {
                    closure.bindings.push(ValueFlowInput::new(binding, status));
                    closure
                        .coverage
                        .get_mut(&coverage_key)
                        .expect("dispatch initialized this call's coverage")
                        .entered
                        .push(target.clone());
                    // Every call site that bound this target is a caller whose
                    // entered arm the cap could strand, whether or not this
                    // binding is the one that queued the target.
                    queued_by
                        .entry(target_key.clone())
                        .or_default()
                        .push((procedure_key.clone(), call_row.id));
                    call_descendants.push(target.clone());
                }
            }
        }

        let requested_cut = !is_root
            && cuts.should_cut(
                &procedure,
                closure
                    .snapshots
                    .last()
                    .expect("the retained procedure snapshot was just appended"),
                &closure.coverage,
                &mut SemanticRequest::new(semantic_budget, cancellation),
            );
        let staged_surfaces = if requested_cut {
            cuts.take_hydrated_surfaces()
        } else {
            Vec::new()
        };
        let mut reserved = queued.clone();
        reserved.extend(hydrated_surfaces.keys().cloned());
        reserved.extend(
            staged_surfaces
                .iter()
                .map(|surface| surface.procedure.durable_key()),
        );
        reserved.extend(lexical_descendants.iter().map(ProcedureHandle::durable_key));
        let cut = requested_cut && reserved.len() <= limits.max_procedures;
        if cut {
            cuts.accept_staged_cut();
            closure.summary_cuts.push(procedure);
            for surface in staged_surfaces {
                let surface_key = surface.procedure.durable_key();
                if !seen.contains(&surface_key) && !queued.contains(&surface_key) {
                    hydrated_surfaces.entry(surface_key).or_insert(surface);
                }
            }
        } else if requested_cut {
            cuts.discard_staged_cut();
        }
        if !cut {
            lexical_descendants.append(&mut call_descendants);
        }
        for descendant in lexical_descendants {
            let key = descendant.durable_key();
            // Ordinary lexical/call reachability upgrades a previously staged
            // identity surface to a full discovery pass.
            hydrated_surfaces.remove(&key);
            if queued.insert(key) {
                pending.push(descendant);
            }
        }
    }

    debug_assert!(
        seen.len().saturating_add(hydrated_surfaces.len()) <= limits.max_procedures,
        "ordinary attempts plus reserved cut surfaces stay within the procedure cap"
    );
    let mut hydrated_surfaces = hydrated_surfaces.into_iter().collect::<Vec<_>>();
    hydrated_surfaces.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (key, surface) in hydrated_surfaces {
        if seen.contains(&key) {
            continue;
        }
        if closure.procedures.len() == limits.max_procedures {
            closure.truncated = true;
            break;
        }
        for (call, coverage) in surface.coverage {
            let previous = closure.coverage.insert((key.clone(), call), coverage);
            assert!(
                previous.is_none(),
                "a deferred surface has no ordinary coverage row"
            );
        }
        closure.boundaries.extend(surface.boundaries);
        let previous = closure
            .certified_dispatch_reads
            .insert(key, surface.dispatch_reads);
        assert!(
            previous.is_none(),
            "one deferred surface has one dispatch-read contract"
        );
        closure.procedures.push(surface.procedure.clone());
        closure.snapshots.push(surface.snapshot);
        closure.summary_cuts.push(surface.procedure);
    }

    if closure.truncated {
        // The cap stopped the walk with queued procedures unprocessed. Every
        // call site that queued one of them has an arm whose relations never
        // entered the closure, which is truncation, not an empty target set.
        for procedure in &pending {
            let key = procedure.durable_key();
            debug_assert!(
                !seen.contains(&key),
                "an unprocessed queued procedure was already discovered"
            );
            if let Some(callers) = queued_by.get(&key) {
                for caller in callers {
                    closure
                        .coverage
                        .get_mut(caller)
                        .expect("a successful binding initialized its call coverage")
                        .truncated = true;
                }
            }
        }
    }

    Ok(closure)
}

fn dispatch_boundary_is_uncovered(boundary: &DispatchBoundary) -> bool {
    !matches!(
        (&boundary.kind, &boundary.completeness),
        (
            DispatchBoundaryKind::External(Some(_)),
            crate::analyzer::semantic::EvidenceCompleteness::Complete
        )
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::analyzer::semantic::{
        CallSiteHandle, DispatchCandidate, DispatchResult, SemanticOutcome, SemanticWork,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProviderMode {
        DispatchUnavailable,
        DispatchError,
        SkipHelperRelations,
    }

    struct ControlledProvider<'a> {
        inner: WorkspaceValueFlowProvider<'a>,
        mode: ProviderMode,
    }

    impl ValueFlowProvider for ControlledProvider<'_> {
        type Error = &'static str;

        fn procedure_snapshot(
            &self,
            procedure: &ProcedureHandle,
            context: &OracleCallContext,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<ValueFlowSnapshot>, Self::Error> {
            if self.mode == ProviderMode::SkipHelperRelations && handle_name(procedure) == "helper"
            {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            Ok(self
                .inner
                .procedure_snapshot(procedure, context, request)
                .expect("fixture relation lookup succeeds"))
        }

        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<DispatchResult>, Self::Error> {
            match self.mode {
                ProviderMode::DispatchUnavailable => Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: SemanticWork::default(),
                }),
                ProviderMode::DispatchError => Err("dispatch failed"),
                ProviderMode::SkipHelperRelations => Ok(self
                    .inner
                    .resolve_call(call, request)
                    .expect("fixture dispatch lookup succeeds")),
            }
        }

        fn call_bindings(
            &self,
            call: &CallSiteHandle,
            candidate: &DispatchCandidate,
            context: &OracleCallContext,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<CallBindings>, Self::Error> {
            Ok(self
                .inner
                .call_bindings(call, candidate, context, request)
                .expect("fixture binding lookup succeeds"))
        }
    }

    /// An analyzer over one inline Python file plus the handle of the
    /// procedure whose final locator segment is `name`.
    fn fixture(
        source: &str,
        name: &str,
    ) -> (BuiltInlineTestProject, WorkspaceAnalyzer, ProcedureHandle) {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the fixture materializes")
            .available_value()
            .cloned()
            .expect("the fixture artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure_name(procedure) == name)
            .unwrap_or_else(|| panic!("the fixture declares {name}"));
        let handle = artifact
            .procedure_handle(procedure.id())
            .expect("a live artifact owns the procedure");
        (project, workspace, handle)
    }

    fn procedure_name(procedure: &crate::analyzer::semantic::ProcedureSemantics) -> &str {
        procedure
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .expect("a named fixture procedure")
    }

    fn handle_name(handle: &ProcedureHandle) -> &str {
        procedure_name(handle.semantics())
    }

    fn discover(
        workspace: &WorkspaceAnalyzer,
        root: &ProcedureHandle,
        max_procedures: usize,
    ) -> DiscoveredClosure {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        discover_closure(
            workspace,
            root,
            ClosureLimits { max_procedures },
            &mut budget,
            &cancellation,
        )
        .expect("discovery succeeds")
    }

    fn discover_with_mode(
        workspace: &WorkspaceAnalyzer,
        root: &ProcedureHandle,
        mode: ProviderMode,
    ) -> DiscoveredClosure {
        let provider = ControlledProvider {
            inner: WorkspaceValueFlowProvider::new(workspace, ValueFlowCache::default()),
            mode,
        };
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        discover_closure_with(
            &provider,
            root,
            ClosureLimits { max_procedures: 10 },
            &mut budget,
            &cancellation,
        )
        .expect("controlled discovery succeeds")
    }

    struct NamedCut(&'static str);

    impl ClosureCutDecider for NamedCut {
        fn should_cut(
            &mut self,
            procedure: &ProcedureHandle,
            _snapshot: &ValueFlowInput<ValueFlowSnapshot>,
            _coverage: &HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
            _request: &mut SemanticRequest<'_>,
        ) -> bool {
            handle_name(procedure) == self.0
        }
    }

    struct StagedNamedCut {
        name: &'static str,
        surfaces: Option<Vec<HydratedProcedureSurface>>,
        accepted: usize,
        discarded: usize,
    }

    struct PreDispatchNamedCut {
        name: &'static str,
        descendants: Option<Vec<HydratedProcedureSurface>>,
        accepted: usize,
        discarded: usize,
    }

    impl ClosureCutDecider for PreDispatchNamedCut {
        fn pre_dispatch_cut(
            &mut self,
            procedure: &ProcedureHandle,
            snapshot: &ValueFlowInput<ValueFlowSnapshot>,
            _request: &mut SemanticRequest<'_>,
        ) -> Option<HydratedProcedureSurface> {
            (handle_name(procedure) == self.name).then(|| HydratedProcedureSurface {
                procedure: procedure.clone(),
                snapshot: snapshot.clone(),
                coverage: Vec::new(),
                dispatch_reads: Box::default(),
                boundaries: Vec::new(),
            })
        }

        fn should_cut(
            &mut self,
            _procedure: &ProcedureHandle,
            _snapshot: &ValueFlowInput<ValueFlowSnapshot>,
            _coverage: &HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
            _request: &mut SemanticRequest<'_>,
        ) -> bool {
            false
        }

        fn take_hydrated_surfaces(&mut self) -> Vec<HydratedProcedureSurface> {
            self.descendants.take().unwrap_or_default()
        }

        fn accept_staged_cut(&mut self) {
            self.accepted = self.accepted.saturating_add(1);
        }

        fn discard_staged_cut(&mut self) {
            self.discarded = self.discarded.saturating_add(1);
        }
    }

    struct CountingProvider<'a> {
        inner: WorkspaceValueFlowProvider<'a>,
        dispatch_calls: Cell<usize>,
        binding_calls: Cell<usize>,
    }

    impl ValueFlowProvider for CountingProvider<'_> {
        type Error = SemanticProviderError;

        fn canonical_procedure(&self, procedure: &ProcedureHandle) -> ProcedureHandle {
            self.inner.canonical_procedure(procedure)
        }

        fn procedure_snapshot(
            &self,
            procedure: &ProcedureHandle,
            context: &OracleCallContext,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<ValueFlowSnapshot>, Self::Error> {
            self.inner.procedure_snapshot(procedure, context, request)
        }

        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<DispatchResult>, Self::Error> {
            self.dispatch_calls
                .set(self.dispatch_calls.get().saturating_add(1));
            self.inner.resolve_call(call, request)
        }

        fn call_bindings(
            &self,
            call: &CallSiteHandle,
            candidate: &DispatchCandidate,
            context: &OracleCallContext,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<CallBindings>, Self::Error> {
            self.binding_calls
                .set(self.binding_calls.get().saturating_add(1));
            self.inner.call_bindings(call, candidate, context, request)
        }
    }

    impl ClosureCutDecider for StagedNamedCut {
        fn should_cut(
            &mut self,
            procedure: &ProcedureHandle,
            _snapshot: &ValueFlowInput<ValueFlowSnapshot>,
            _coverage: &HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
            _request: &mut SemanticRequest<'_>,
        ) -> bool {
            handle_name(procedure) == self.name
        }

        fn take_hydrated_surfaces(&mut self) -> Vec<HydratedProcedureSurface> {
            self.surfaces.take().unwrap_or_default()
        }

        fn accept_staged_cut(&mut self) {
            self.accepted = self.accepted.saturating_add(1);
        }

        fn discard_staged_cut(&mut self) {
            self.discarded = self.discarded.saturating_add(1);
        }
    }

    fn named_procedure(root: &ProcedureHandle, name: &str) -> ProcedureHandle {
        root.artifact()
            .procedures()
            .iter()
            .find(|procedure| procedure_name(procedure) == name)
            .and_then(|procedure| root.artifact().procedure_handle(procedure.id()))
            .unwrap_or_else(|| panic!("the fixture declares {name}"))
    }

    fn staged_surface(
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> HydratedProcedureSurface {
        let provider = WorkspaceValueFlowProvider::new(workspace, ValueFlowCache::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .procedure_snapshot(
                procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture surface lookup succeeds");
        let status = SemanticInputStatus::from_outcome(&outcome);
        let snapshot = outcome
            .available_value()
            .cloned()
            .expect("fixture surface is available");
        HydratedProcedureSurface {
            procedure: procedure.clone(),
            snapshot: ValueFlowInput::new(snapshot, status),
            coverage: Vec::new(),
            dispatch_reads: Box::default(),
            boundaries: Vec::new(),
        }
    }

    fn discover_with_counting_pre_dispatch_cut(
        workspace: &WorkspaceAnalyzer,
        root: &ProcedureHandle,
        cut: &mut PreDispatchNamedCut,
        max_procedures: usize,
    ) -> (DiscoveredClosure, usize, usize) {
        let provider = CountingProvider {
            inner: WorkspaceValueFlowProvider::new(workspace, ValueFlowCache::default()),
            dispatch_calls: Cell::new(0),
            binding_calls: Cell::new(0),
        };
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            root,
            ClosureLimits { max_procedures },
            &mut budget,
            &cancellation,
            cut,
        )
        .expect("counted cut discovery succeeds");
        (
            closure,
            provider.dispatch_calls.get(),
            provider.binding_calls.get(),
        )
    }

    #[test]
    fn an_accepted_pre_dispatch_cut_avoids_live_call_acquisition() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def leaf(value):\n    return value\n",
                "def helper(value):\n",
                "    def lexical():\n        return 1\n",
                "    return leaf(value)\n",
                "def main(value):\n    return helper(value)\n",
            ),
            "main",
        );
        let leaf = named_procedure(&root, "leaf");
        let mut cut = PreDispatchNamedCut {
            name: "helper",
            descendants: Some(vec![staged_surface(&workspace, &leaf)]),
            accepted: 0,
            discarded: 0,
        };
        let (closure, dispatch_calls, binding_calls) =
            discover_with_counting_pre_dispatch_cut(&workspace, &root, &mut cut, 10);

        assert_eq!(
            dispatch_calls, 1,
            "only main dispatches through the provider"
        );
        assert_eq!(
            binding_calls, 1,
            "only main's helper binding is acquired live"
        );
        assert_eq!((cut.accepted, cut.discarded), (1, 0));
        assert_eq!(
            closure
                .summary_cuts
                .iter()
                .map(handle_name)
                .collect::<Vec<_>>(),
            ["helper", "leaf"],
            "the cut root and its identity-only call descendant are mandatory cuts"
        );
        assert!(
            closure
                .procedures
                .iter()
                .any(|procedure| handle_name(procedure) == "lexical")
                && !closure
                    .summary_cuts
                    .iter()
                    .any(|procedure| handle_name(procedure) == "lexical"),
            "an immediate lexical child still runs through ordinary discovery"
        );
    }

    #[test]
    fn a_rejected_pre_dispatch_cut_runs_live_call_acquisition() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def leaf(value):\n    return value\n",
                "def helper(value):\n",
                "    def lexical():\n        return 1\n",
                "    return leaf(value)\n",
                "def main(value):\n    return helper(value)\n",
            ),
            "main",
        );
        let leaf = named_procedure(&root, "leaf");
        let mut cut = PreDispatchNamedCut {
            name: "helper",
            descendants: Some(vec![staged_surface(&workspace, &leaf)]),
            accepted: 0,
            discarded: 0,
        };
        let (closure, dispatch_calls, binding_calls) =
            discover_with_counting_pre_dispatch_cut(&workspace, &root, &mut cut, 3);

        assert_eq!(dispatch_calls, 2, "main and helper both dispatch live");
        assert_eq!(binding_calls, 2, "main and helper both bind live");
        assert_eq!(
            (cut.accepted, cut.discarded),
            (0, 1),
            "cap refusal rolls back the staged cut exactly once"
        );
        assert!(closure.summary_cuts.is_empty(), "{closure:?}");
        assert!(
            closure.truncated,
            "the ordinary four-procedure closure exceeds three"
        );
    }

    #[test]
    fn a_summary_cut_retains_the_callee_surface_and_skips_its_descendants() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def leaf(value):\n    return value\n",
                "def helper(value):\n    return leaf(value)\n",
                "def main(value):\n    return helper(value)\n",
            ),
            "main",
        );
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            &root,
            ClosureLimits { max_procedures: 10 },
            &mut budget,
            &cancellation,
            &mut NamedCut("helper"),
        )
        .expect("cut discovery succeeds");

        assert_eq!(
            closure
                .procedures
                .iter()
                .map(handle_name)
                .collect::<Vec<_>>(),
            ["main", "helper"],
            "the cut keeps the helper snapshot but never acquires leaf"
        );
        assert_eq!(
            closure
                .summary_cuts
                .iter()
                .map(handle_name)
                .collect::<Vec<_>>(),
            ["helper"]
        );
        assert!(
            closure
                .coverage
                .keys()
                .any(|(caller, _)| caller == &root.durable_key())
                && closure.coverage.keys().any(|(caller, _)| {
                    closure
                        .procedures
                        .iter()
                        .find(|procedure| handle_name(procedure) == "helper")
                        .is_some_and(|helper| caller == &helper.durable_key())
                }),
            "the cut procedure's own direct call is certified before pruning"
        );
        assert_eq!(
            closure.bindings.len(),
            2,
            "the inbound helper and certified helper-to-leaf bindings remain"
        );
    }

    #[test]
    fn a_cut_reserves_only_unique_deferred_surfaces_at_the_exact_cap() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def c():\n    return 1\n",
                "def b():\n    return 2\n",
                "def a():\n",
                "    def lexical():\n        return 3\n",
                "    return c()\n",
                "def main():\n    before = b()\n    after = a()\n    return before + after\n",
            ),
            "main",
        );
        let b = named_procedure(&root, "b");
        let c = named_procedure(&root, "c");
        let mut cuts = StagedNamedCut {
            name: "a",
            // `b` is already queued independently. It must not consume a
            // second slot; `c` is the one genuinely deferred surface.
            surfaces: Some(vec![
                staged_surface(&workspace, &b),
                staged_surface(&workspace, &c),
                staged_surface(&workspace, &c),
            ]),
            accepted: 0,
            discarded: 0,
        };
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            &root,
            ClosureLimits { max_procedures: 5 },
            &mut budget,
            &cancellation,
            &mut cuts,
        )
        .expect("cut discovery succeeds at the exact unique cap");

        assert_eq!((cuts.accepted, cuts.discarded), (1, 0));
        assert!(!closure.truncated, "{closure:?}");
        let names = closure
            .procedures
            .iter()
            .map(handle_name)
            .collect::<Vec<_>>();
        for name in ["main", "a", "lexical", "b", "c"] {
            assert_eq!(
                names.iter().filter(|candidate| **candidate == name).count(),
                1,
                "{name} is mounted exactly once: {closure:?}"
            );
        }
        let cut_names = closure
            .summary_cuts
            .iter()
            .map(handle_name)
            .collect::<Vec<_>>();
        assert!(cut_names.contains(&"a"), "{closure:?}");
        assert!(cut_names.contains(&"c"), "{closure:?}");
        assert!(!cut_names.contains(&"b"), "queued b is fully processed");
        assert!(
            !cut_names.contains(&"lexical"),
            "lexical is fully processed"
        );
    }

    #[test]
    fn a_cut_that_cannot_reserve_every_surface_is_rejected_without_partial_state() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def c():\n    return 1\n",
                "def b():\n    return 2\n",
                "def a():\n",
                "    def lexical():\n        return 3\n",
                "    return c()\n",
                "def main():\n    before = b()\n    after = a()\n    return before + after\n",
            ),
            "main",
        );
        let b = named_procedure(&root, "b");
        let c = named_procedure(&root, "c");
        let mut cuts = StagedNamedCut {
            name: "a",
            surfaces: Some(vec![
                staged_surface(&workspace, &b),
                staged_surface(&workspace, &c),
            ]),
            accepted: 0,
            discarded: 0,
        };
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            &root,
            ClosureLimits { max_procedures: 4 },
            &mut budget,
            &cancellation,
            &mut cuts,
        )
        .expect("ordinary discovery continues after refusing the cut");

        assert_eq!(
            (cuts.accepted, cuts.discarded),
            (0, 1),
            "post-dispatch cap refusal rolls back staged cut state exactly once"
        );
        assert!(
            closure.truncated,
            "the ordinary five-procedure closure exceeds four"
        );
        assert!(closure.summary_cuts.is_empty(), "{closure:?}");
        assert_eq!(closure.procedures.len(), 4, "{closure:?}");
    }

    #[test]
    fn later_ordinary_fanout_cannot_displace_an_accepted_cut_surface() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def c(value):\n    return value.member\n",
                "def d():\n    return 1\n",
                "def b():\n    return d()\n",
                "def a():\n    return 2\n",
                "def main():\n    before = b()\n    after = a()\n    return before + after\n",
            ),
            "main",
        );
        let b = named_procedure(&root, "b");
        let c = named_procedure(&root, "c");
        let mut cuts = StagedNamedCut {
            name: "a",
            // `b` is independently queued and must be upgraded to full
            // processing. The dependency-only `c` surface keeps its slot when
            // `b` later discovers `d` beyond the cap.
            surfaces: Some(vec![
                staged_surface(&workspace, &b),
                staged_surface(&workspace, &c),
            ]),
            accepted: 0,
            discarded: 0,
        };
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            &root,
            ClosureLimits { max_procedures: 4 },
            &mut budget,
            &cancellation,
            &mut cuts,
        )
        .expect("cut discovery preserves its reserved surface");

        assert!(
            closure.truncated,
            "later d fanout exceeds the cap: {closure:?}"
        );
        let names = closure
            .procedures
            .iter()
            .map(handle_name)
            .collect::<Vec<_>>();
        assert_eq!(
            names.iter().filter(|name| **name == "b").count(),
            1,
            "independently reached b is processed once: {closure:?}"
        );
        assert!(
            names.contains(&"c"),
            "c's member-site surface remains mounted"
        );
        assert!(!names.contains(&"d"), "d is the refused ordinary procedure");
        let b_key = b.durable_key();
        let b_rows = closure
            .coverage
            .iter()
            .filter(|((caller, _), _)| caller == &b_key)
            .collect::<Vec<_>>();
        assert_eq!(b_rows.len(), 1, "b's dispatch is acquired exactly once");
        assert!(b_rows[0].1.truncated, "b-to-d records the refused arm");
        let cut_names = closure
            .summary_cuts
            .iter()
            .map(handle_name)
            .collect::<Vec<_>>();
        assert!(cut_names.contains(&"a"), "{closure:?}");
        assert!(cut_names.contains(&"c"), "{closure:?}");
        assert!(!cut_names.contains(&"b"), "b is not identity-only");
    }

    #[test]
    fn a_surface_processed_before_staging_remains_one_fully_acquired_procedure() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def c():\n    return 1\n",
                "def d():\n    return 2\n",
                "def b():\n    return d()\n",
                "def a():\n    return 3\n",
                "def main():\n    before = a()\n    after = b()\n    return before + after\n",
            ),
            "main",
        );
        let b = named_procedure(&root, "b");
        let c = named_procedure(&root, "c");
        let mut cuts = StagedNamedCut {
            name: "a",
            surfaces: Some(vec![
                staged_surface(&workspace, &b),
                staged_surface(&workspace, &c),
            ]),
            accepted: 0,
            discarded: 0,
        };
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            &root,
            ClosureLimits { max_procedures: 5 },
            &mut budget,
            &cancellation,
            &mut cuts,
        )
        .expect("processed-before-staged discovery succeeds");

        assert!(!closure.truncated, "{closure:?}");
        assert_eq!(
            closure
                .procedures
                .iter()
                .filter(|procedure| handle_name(procedure) == "b")
                .count(),
            1,
            "b retains one ordinary snapshot"
        );
        assert_eq!(
            closure
                .coverage
                .keys()
                .filter(|(caller, _)| caller == &b.durable_key())
                .count(),
            1,
            "b's direct dispatch is acquired once"
        );
        assert!(
            closure
                .summary_cuts
                .iter()
                .all(|procedure| handle_name(procedure) != "b"),
            "an already processed procedure is never downgraded to a surface"
        );
    }

    #[test]
    fn an_unavailable_ordinary_snapshot_does_not_free_a_reserved_surface_slot() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def c(value):\n    return value.member\n",
                "def helper():\n    return 1\n",
                "def a():\n    return 2\n",
                "def main():\n    before = helper()\n    after = a()\n    return before + after\n",
            ),
            "main",
        );
        let c = named_procedure(&root, "c");
        let provider = ControlledProvider {
            inner: WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
            mode: ProviderMode::SkipHelperRelations,
        };
        let mut cuts = StagedNamedCut {
            name: "a",
            surfaces: Some(vec![staged_surface(&workspace, &c)]),
            accepted: 0,
            discarded: 0,
        };
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let closure = discover_closure_with_cuts(
            &provider,
            &root,
            ClosureLimits { max_procedures: 4 },
            &mut budget,
            &cancellation,
            &mut cuts,
        )
        .expect("unavailable ordinary snapshot is typed and non-fatal");

        assert!(
            !closure.truncated,
            "all four attempted slots fit: {closure:?}"
        );
        assert_eq!(
            closure.procedures.len(),
            3,
            "helper has no snapshot: {closure:?}"
        );
        assert!(
            closure
                .procedures
                .iter()
                .any(|procedure| handle_name(procedure) == "c"),
            "the reserved dependency surface is still mounted"
        );
        assert_eq!(
            closure
                .skipped
                .iter()
                .filter(|(procedure, _)| handle_name(procedure) == "helper")
                .count(),
            1,
            "the unavailable helper consumes one attempted slot"
        );
    }

    #[test]
    fn the_procedure_cap_marks_the_calls_left_with_an_unprocessed_candidate() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def helper():\n    return 1\n",
                "def other():\n    return 2\n",
                "def main():\n    a = helper()\n    b = other()\n    return a\n",
            ),
            "main",
        );
        let closure = discover(&workspace, &root, 1);
        assert!(
            closure.truncated,
            "the cap stopped the walk with callees queued: {closure:?}"
        );
        assert_eq!(
            closure.procedures.len(),
            1,
            "only the root's relations entered the closure: {closure:?}"
        );
        // `other` pops first and trips the cap; `helper` is still queued, so
        // the call that bound it is truncation, not an empty target set.
        let helper_coverage = closure
            .coverage
            .values()
            .find(|coverage| {
                coverage.entered.len() == 1 && handle_name(&coverage.entered[0]) == "helper"
            })
            .expect("the helper call has a coverage row");
        assert!(
            helper_coverage.truncated,
            "the still-queued callee's call site is marked truncated: {helper_coverage:?}"
        );
    }

    #[test]
    fn a_callee_reached_from_two_call_sites_is_queued_once() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def target():\n    return 1\n",
                "def filler():\n    return 2\n",
                "def main():\n    a = target()\n    b = target()\n    c = filler()\n    return a\n",
            ),
            "main",
        );
        // Both `target` bindings succeed, and `filler` keeps the walk busy
        // until the cap trips. Pushed once per binding, `target`'s second copy
        // was still queued when its first tripped the cap, which failed the
        // truncation pass's debug assertion; the durable-key worklist dedup
        // queues it once.
        let closure = discover(&workspace, &root, 2);
        assert!(closure.truncated, "{closure:?}");
        let discovered = closure
            .procedures
            .iter()
            .map(handle_name)
            .collect::<Vec<_>>();
        assert_eq!(discovered, ["main", "filler"], "{closure:?}");
        let target_rows = closure
            .coverage
            .values()
            .filter(|coverage| {
                coverage.entered.len() == 1 && handle_name(&coverage.entered[0]) == "target"
            })
            .count();
        assert_eq!(
            target_rows, 2,
            "each of the two call sites entered the callee once: {closure:?}"
        );
    }

    #[test]
    fn lexical_children_enter_their_enclosing_procedures_closure() {
        let (_project, workspace, root) = fixture(
            concat!(
                "def main():\n",
                "    def nested():\n",
                "        return 1\n",
                "    return 2\n",
            ),
            "main",
        );
        let closure = discover(&workspace, &root, 10);
        let discovered = closure
            .procedures
            .iter()
            .map(handle_name)
            .collect::<Vec<_>>();
        assert_eq!(discovered, ["main", "nested"], "{closure:?}");
    }

    #[test]
    fn every_dispatch_outcome_has_a_typed_coverage_row() {
        let (_project, workspace, root) = fixture(
            "def helper():\n    return 1\ndef main():\n    return helper()\n",
            "main",
        );

        let unavailable = discover_with_mode(&workspace, &root, ProviderMode::DispatchUnavailable);
        let coverage = unavailable
            .coverage
            .values()
            .next()
            .expect("the unresolved call has coverage");
        assert_eq!(
            coverage.dispatch,
            DispatchStatus::Unavailable {
                status: SemanticInputStatus::Unknown,
            }
        );
        assert!(coverage.bindings.is_empty(), "{coverage:?}");

        let failed = discover_with_mode(&workspace, &root, ProviderMode::DispatchError);
        let coverage = failed
            .coverage
            .values()
            .next()
            .expect("the failed call has coverage");
        assert_eq!(
            coverage.dispatch,
            DispatchStatus::ProviderError {
                detail: "dispatch failed".into(),
            }
        );
        assert!(coverage.bindings.is_empty(), "{coverage:?}");
    }

    #[test]
    fn a_value_less_callee_snapshot_is_a_typed_skip() {
        let (_project, workspace, root) = fixture(
            "def helper():\n    return 1\ndef main():\n    return helper()\n",
            "main",
        );
        let closure = discover_with_mode(&workspace, &root, ProviderMode::SkipHelperRelations);

        assert_eq!(closure.skipped.len(), 1, "{closure:?}");
        assert_eq!(handle_name(&closure.skipped[0].0), "helper");
        assert_eq!(
            closure.skipped[0].1,
            SkipReason::RelationsUnavailable {
                status: SemanticInputStatus::Unknown,
            }
        );
        let coverage = closure
            .coverage
            .values()
            .next()
            .expect("the entered call has coverage");
        assert!(
            matches!(coverage.dispatch, DispatchStatus::Resolved { .. }),
            "{coverage:?}"
        );
        assert_eq!(coverage.bindings.len(), 1, "{coverage:?}");
        assert_eq!(coverage.entered.len(), 1, "{coverage:?}");
    }
}
