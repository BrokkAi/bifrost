use crate::analyzer::python::native_request::{
    PythonNativeOpen, PythonNativeRequest, open_python_native_request,
};
use crate::analyzer::python::*;
use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
use brokk_bifrost_analysis::analyzer::resolution::{
    HierarchyEdgeProjection, ResolutionCompletion, SemanticId,
};
use brokk_bifrost_analysis::analyzer::semantic_model::python_runtime_bases::{
    MAX_PYTHON_HIERARCHY_VISITS, PythonRuntimeClaimBudget, runtime_bases,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    LocatedSemantic, PythonClassHierarchy, PythonHierarchyOwner, PythonHierarchyRead,
    SelectedResolutionOperationOutcome,
};
use brokk_bifrost_core::analyzer::capabilities::{
    HierarchyAnswer, HierarchyOpenReason, UnreadMemberFamilyAncestor,
};
use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;

use brokk_bifrost_semantic::analyzer::semantic::type_flow::ClassIdentity;

use brokk_bifrost_semantic::analyzer::semantic::type_flow::ExternalClassCache;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeFact;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonAncestryBasis;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonBaseFact;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonBaseOrigin;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonBaseResolution;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonClassHierarchyAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonClassHierarchyProvider;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonHierarchyReason;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonMroMember;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonMroMembersAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonOverrideAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonOverrideOutcome;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use std::sync::Arc;

pub(crate) const MAX_PYTHON_C3_WORK: usize = 65_536;
const MAX_PYTHON_MEMBER_VISITS: usize = 32_768;
const PYTHON_OBJECT_ROOT: &str = "builtins.object";

/// Accounting for the model claim reads of one hierarchy request. Everything
/// retained belongs to this invocation, not the analyzer.
struct ClaimBudget<'a> {
    visits: usize,
    session: &'a ResolutionSession,
    retained_claims: HashSet<(*const ActiveSemanticModelShard, *const TypeFact)>,
}

impl PythonRuntimeClaimBudget for ClaimBudget<'_> {
    fn charge(&mut self, visits: usize, work: usize) -> Result<(), PythonHierarchyReason> {
        ClaimBudget::charge(self, visits, work)
    }
    fn has_claim(&self, key: (*const ActiveSemanticModelShard, *const TypeFact)) -> bool {
        self.retained_claims.contains(&key)
    }
    fn mark_claim(&mut self, key: (*const ActiveSemanticModelShard, *const TypeFact)) {
        self.retained_claims.insert(key);
    }
}

impl ClaimBudget<'_> {
    fn charge(&mut self, visits: usize, work: usize) -> Result<(), PythonHierarchyReason> {
        brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            self.visits,
            MAX_PYTHON_HIERARCHY_VISITS,
        )
        .try_allow(visits)
        .map_err(|_| PythonHierarchyReason::VisitLimit)?;
        if !self.session.scope_steps(work.max(visits)) {
            return Err(session_reason(self.session));
        }
        self.visits += visits;
        Ok(())
    }
}

fn session_reason(session: &ResolutionSession) -> PythonHierarchyReason {
    match session.finish(()) {
        BoundedResolution::Cancelled { .. } => PythonHierarchyReason::Cancelled,
        BoundedResolution::Exceeded { .. } => PythonHierarchyReason::VisitLimit,
        BoundedResolution::Unavailable { .. } => PythonHierarchyReason::UnknownMemberSurface,
        BoundedResolution::Complete { .. } => unreachable!("failed charge has a sticky stop"),
    }
}

/// Why the selected native hierarchy request produced no hierarchy.
fn operational_hierarchy_stop() -> QueryReadIncomplete {
    QueryReadIncomplete::ProofStopped {
        reason: "python_hierarchy_request_stopped",
        cause: Some(
            brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Provider,
        ),
    }
}

fn hierarchy_stop_reason(
    stop: &brokk_bifrost_analysis::analyzer::resolution::HierarchyStop,
) -> QueryReadIncomplete {
    use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
    use brokk_bifrost_analysis::analyzer::resolution::HierarchyStop;
    match stop {
        HierarchyStop::Unavailable { .. } | HierarchyStop::Provider(_) => {
            operational_hierarchy_stop()
        }
        HierarchyStop::Cancelled(_) => QueryReadIncomplete::ProofStopped {
            reason: "python_hierarchy_request_stopped",
            cause: Some(DerivationExecutionCause::Cancelled),
        },
        HierarchyStop::Cyclic(_) => QueryReadIncomplete::ProofStopped {
            reason: "resolution_cyclic_expansion",
            cause: None,
        },
        HierarchyStop::Deterministic(reason) => {
            assert!(
                brokk_bifrost_analysis::analyzer::i_analyzer::DETERMINISTIC_PROOF_STOP_LABELS
                    .contains(reason)
            );
            QueryReadIncomplete::ProofStopped {
                reason,
                cause: None,
            }
        }
    }
}

enum NativeHierarchy {
    Ready(Box<PythonClassHierarchy>),
    Unavailable(PythonHierarchyReason),
    Stopped(PythonHierarchyReason),
}

impl PythonAnalyzer {
    /// The single analyzer-local hierarchy-reader injection. Clearing it does
    /// not clear caches: the recovery regression proves operational refusal
    /// was not retained by the preceding request.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_hierarchy_stop_for_test(&mut self, stop: Option<(String, Option<&'static str>)>) {
        if let Some((_, Some(label))) = &stop {
            assert!(
                brokk_bifrost_analysis::analyzer::i_analyzer::DETERMINISTIC_PROOF_STOP_LABELS
                    .contains(label)
            );
        }
        self.hierarchy_stop_for_test = stop;
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn descendant_memo_entries_for_test(&self) -> u64 {
        self.direct_descendant_index.read(
            &memo_attribution(self),
            |(memo, _)| {
                memo.run_pending_tasks();
                memo.entry_count()
            },
            |_| super::AuthorityInputs::Unnamed,
        )
    }

    /// One selected native request, opened for one hierarchy query or walk.
    fn open_hierarchy_request<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<PythonNativeRequest<'a>, PythonHierarchyReason> {
        match open_python_native_request(self, cancellation) {
            Ok(PythonNativeOpen::Ready(request)) => Ok(request),
            Ok(PythonNativeOpen::Cancelled) => Err(PythonHierarchyReason::Cancelled),
            Ok(PythonNativeOpen::Unavailable { .. }) => Err(PythonHierarchyReason::UnresolvedBase),
            Err(error) => {
                self.record_query_failure(error);
                Err(PythonHierarchyReason::UnresolvedBase)
            }
        }
    }

    /// The full hierarchy (bases, order) on a held request.
    fn native_class_hierarchy(
        &self,
        class: &CodeUnit,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> NativeHierarchy {
        match self.open_hierarchy_request(cancellation) {
            Ok(mut request) => self.hierarchy_in(
                &mut request,
                class,
                cancellation,
                session,
                |operation, environment, definition, session| {
                    operation.python_class_hierarchy(environment, definition, session)
                },
            ),
            Err(PythonHierarchyReason::UnresolvedBase) => {
                NativeHierarchy::Unavailable(PythonHierarchyReason::UnresolvedBase)
            }
            Err(reason) => NativeHierarchy::Stopped(reason),
        }
    }

    /// One demand on a held request: locate the class in the selected crosswalk,
    /// run `demand`, and classify how it stopped.
    fn hierarchy_in(
        &self,
        request: &mut PythonNativeRequest<'_>,
        class: &CodeUnit,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        demand: impl FnOnce(
            &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
            &brokk_bifrost_analysis::analyzer::store::python_unit_summaries::PythonSelectedEnvironment,
            brokk_bifrost_analysis::analyzer::resolution::SemanticId,
            &ResolutionSession,
        ) -> brokk_bifrost_analysis::analyzer::store::Result<
            BoundedResolution<SelectedResolutionOperationOutcome<PythonClassHierarchy>>,
        >,
    ) -> NativeHierarchy {
        let definition =
            match request
                .operation
                .selected_hierarchy_definition(class, cancellation, session)
            {
                Ok(LocatedSemantic::Found(definition)) => definition,
                Ok(LocatedSemantic::Missing) => {
                    return NativeHierarchy::Unavailable(PythonHierarchyReason::UnresolvedBase);
                }
                Ok(LocatedSemantic::Cancelled) => {
                    return NativeHierarchy::Stopped(PythonHierarchyReason::Cancelled);
                }
                Err(error) => {
                    self.record_query_failure(error);
                    return NativeHierarchy::Stopped(PythonHierarchyReason::UnresolvedBase);
                }
            };
        match demand(
            &mut request.operation,
            &request.environment,
            definition,
            session,
        ) {
            Ok(BoundedResolution::Complete {
                value: SelectedResolutionOperationOutcome::Native(hierarchy),
                ..
            }) => {
                if let Some(stop) = &hierarchy.projection.stop {
                    self.record_hierarchy_stop(hierarchy_stop_reason(stop));
                }
                NativeHierarchy::Ready(Box::new(hierarchy))
            }
            Ok(BoundedResolution::Complete {
                value: SelectedResolutionOperationOutcome::Cancelled(_),
                ..
            })
            | Ok(BoundedResolution::Cancelled { .. }) => {
                NativeHierarchy::Stopped(PythonHierarchyReason::Cancelled)
            }
            Ok(BoundedResolution::Exceeded { .. }) => {
                NativeHierarchy::Stopped(PythonHierarchyReason::VisitLimit)
            }
            Ok(BoundedResolution::Unavailable { .. }) => {
                NativeHierarchy::Unavailable(PythonHierarchyReason::UnknownMemberSurface)
            }
            Ok(BoundedResolution::Complete {
                value: SelectedResolutionOperationOutcome::Unavailable(_),
                ..
            }) => NativeHierarchy::Unavailable(PythonHierarchyReason::UnresolvedBase),
            Ok(BoundedResolution::Complete { .. }) => {
                NativeHierarchy::Stopped(PythonHierarchyReason::UnresolvedBase)
            }
            Err(error) => {
                self.record_query_failure(error);
                NativeHierarchy::Stopped(PythonHierarchyReason::UnresolvedBase)
            }
        }
    }

    fn hierarchy_session(cancellation: &CancellationToken) -> ResolutionSession {
        ResolutionSession::bounded_with_total_work(
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
            MAX_PYTHON_C3_WORK,
            Some(cancellation),
        )
    }
}

/// The class identity of each projected owner. The language-fixed
/// `builtins.object` takes the selected model's identity when a model declares
/// it. Any other language-fixed class has no declared bases in the language
/// table, so its ancestry is unknown without a model and it names no identity.
struct Identities {
    of: HashMap<SemanticId, Option<ClassIdentity>>,
    /// Language-fixed owners that a selected model claims but that no model
    /// identity can bind (#5738): their bases are missing, not unresolved.
    claimed_unbound: HashSet<SemanticId>,
    /// Language-fixed owners no selected model declares at all: their bases
    /// are missing. A declaration that is not admitted (ambiguous owners) is
    /// an unresolved base instead.
    undeclared: HashSet<SemanticId>,
    external_failures: HashMap<(SemanticId, u32), PythonHierarchyReason>,
}

impl Identities {
    fn of(&self, id: SemanticId) -> Option<&ClassIdentity> {
        self.of.get(&id).and_then(Option::as_ref)
    }
}

/// What one projected edge says about its base.
struct EdgeVerdict {
    target: Option<ClassIdentity>,
    resolution: PythonBaseResolution,
    failure: PythonHierarchyReason,
}

impl EdgeVerdict {
    fn resolved(&self) -> bool {
        self.target.is_some()
    }
}

/// A base is definite only with exactly one target and no open evidence.
fn edge_verdict(
    hierarchy: &PythonClassHierarchy,
    identities: &Identities,
    owner: SemanticId,
    edge: &HierarchyEdgeProjection,
) -> EdgeVerdict {
    let unresolved = EdgeVerdict {
        target: None,
        resolution: PythonBaseResolution::Unresolved,
        failure: PythonHierarchyReason::UnresolvedBase,
    };
    if edge.implicit_undecided && !edge.implicit_external {
        return EdgeVerdict {
            failure: PythonHierarchyReason::ImplicitGenericUndecidedFactory,
            ..unresolved
        };
    }
    // An import that left the workspace for a selected provider is an external
    // base, not an inference failure of a workspace class.
    if edge.targets.is_empty() && hierarchy.provider_open.contains(&(owner, edge.ordinal)) {
        return EdgeVerdict {
            target: None,
            resolution: PythonBaseResolution::External,
            failure: if edge.implicit_undecided {
                PythonHierarchyReason::ImplicitGenericUndecidedSourceBase
            } else {
                identities
                    .external_failures
                    .get(&(owner, edge.ordinal))
                    .copied()
                    .unwrap_or(PythonHierarchyReason::ExternalBase)
            },
        };
    }
    // The shared member walk reads a bound edge's binding evidence only when
    // its type transfer is open; the same rule decides a definite base here.
    let ([target], true) = (
        edge.targets.as_slice(),
        edge.transfer == ResolutionCompletion::Complete
            && edge.residual == ResolutionCompletion::Complete,
    ) else {
        return unresolved;
    };
    match (hierarchy.owner(*target), identities.of(*target)) {
        // A non-class declaration reaching a class header does not prove the
        // value that header reads (#5668), so the base stays unresolved.
        (PythonHierarchyOwner::Source(unit), _) if !unit.is_class() => unresolved,
        (_, Some(identity)) => EdgeVerdict {
            target: Some(identity.clone()),
            resolution: PythonBaseResolution::Resolved,
            failure: PythonHierarchyReason::UnresolvedBase,
        },
        (_, None)
            if identities.undeclared.contains(target)
                || (identities.claimed_unbound.contains(target)
                    && matches!(hierarchy.owner(*target), PythonHierarchyOwner::Intrinsic { canonical_name } if canonical_name == PYTHON_OBJECT_ROOT)) =>
        {
            EdgeVerdict {
                failure: PythonHierarchyReason::MissingRuntimeBases,
                ..unresolved
            }
        }
        (_, None) => unresolved,
    }
}

impl PythonClassHierarchyProvider for PythonAnalyzer {
    fn class_hierarchy(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonClassHierarchyAnswer {
        let uncancelled = CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&uncancelled);
        let stopped = |outcome, reason| {
            PythonClassHierarchyAnswer::stopped(
                outcome,
                reason,
                Vec::new(),
                PythonAncestryBasis::default(),
            )
        };
        if !class.is_class() {
            return stopped(
                PythonHierarchyOutcome::Unsupported,
                PythonHierarchyReason::NotClass,
            );
        }
        if class.is_synthetic() {
            return stopped(
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::ExternalBase,
            );
        }
        let session = Self::hierarchy_session(cancellation);
        let hierarchy = match self.native_class_hierarchy(class, cancellation, &session) {
            NativeHierarchy::Ready(hierarchy) => hierarchy,
            NativeHierarchy::Unavailable(reason) | NativeHierarchy::Stopped(reason) => {
                return stopped(PythonHierarchyOutcome::Incomplete, reason);
            }
        };
        self.answer_from_native(class, &hierarchy, cancellation, &session)
    }

    fn mro_members(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer {
        self.mro_members_from_hierarchy(self.class_hierarchy(class, cancellation), cancellation)
    }

    fn method_override(
        &self,
        method: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonOverrideAnswer {
        let owner = self.parent_of(method).filter(CodeUnit::is_class);
        if !method.is_function() || owner.is_none() {
            return PythonOverrideAnswer::stopped(
                PythonOverrideOutcome::Unsupported,
                Some(PythonHierarchyReason::NotClass),
                owner,
                PythonAncestryBasis::default(),
            );
        }
        let owner = owner.expect("class owner checked");
        let hierarchy = self.class_hierarchy(&owner, cancellation);
        let stopped = |outcome, reason| {
            PythonOverrideAnswer::stopped(
                outcome,
                reason,
                Some(owner.clone()),
                hierarchy.ancestry_basis.clone(),
            )
        };
        if hierarchy.outcome != PythonHierarchyOutcome::Complete {
            return stopped(
                if hierarchy.outcome == PythonHierarchyOutcome::Unsupported {
                    PythonOverrideOutcome::Unsupported
                } else {
                    PythonOverrideOutcome::Incomplete
                },
                hierarchy.reason,
            );
        }
        let mut visits = 0usize;
        for (rank, identity) in hierarchy.mro.iter().enumerate() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::Cancelled),
                );
            }
            let ClassIdentity::Workspace(mro_owner) = identity else {
                if matches!(identity, ClassIdentity::Intrinsic { .. }) {
                    // The language-supplied object root declares no source
                    // member that could override the selected method.
                    continue;
                }
                // A complete ancestry claim is not a complete member inventory.
                return stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::UnknownMemberSurface),
                );
            };
            let declarations = self.direct_children_in_source_order(mro_owner);
            visits = visits.saturating_add(declarations.len());
            if brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                visits,
                MAX_PYTHON_MEMBER_VISITS,
            )
            .try_allow(0)
            .is_err()
            {
                return stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::VisitLimit),
                );
            }
            let selected = declarations
                .into_iter()
                .rev()
                .find(|declaration| declaration.terminal_name() == method.terminal_name());
            if rank == 0 {
                if selected.as_ref() != Some(method) {
                    return stopped(
                        PythonOverrideOutcome::Unsupported,
                        Some(PythonHierarchyReason::NotEffectiveMember),
                    );
                }
                continue;
            }
            if let Some(target) = selected {
                if !target.is_function() {
                    return stopped(PythonOverrideOutcome::NoOverride, None);
                }
                return PythonOverrideAnswer {
                    outcome: PythonOverrideOutcome::Overrides,
                    reason: None,
                    source_owner: Some(owner.clone()),
                    target: Some(target),
                    target_owner: Some(mro_owner.clone()),
                    mro_rank: Some(rank),
                    ancestry_basis: hierarchy.ancestry_basis.clone(),
                };
            }
        }
        stopped(PythonOverrideOutcome::NoOverride, None)
    }
}

impl PythonAnalyzer {
    /// The written spelling of each positional base of `class`, by the same
    /// ordinal the producer assigns its base operands.
    fn written_base_spellings(
        &self,
        class: &CodeUnit,
        session: &ResolutionSession,
    ) -> Option<Vec<String>> {
        let spellings = (|| {
            let prepared = session
                .query(|| {
                    crate::analyzer::python::type_flow::current_indexed_prepared(
                        self,
                        class.source(),
                    )
                })
                .flatten()?;
            let node = crate::analyzer::python::type_flow::class_node_for_unit_in_session(
                self, &prepared, class, session,
            )?;
            let mut spellings = Vec::new();
            if let Some(arguments) = node.child_by_field_name("superclasses") {
                for operand in
                    brokk_bifrost_core::analyzer::tree_walk::named_children_iter(arguments)
                {
                    if !session.scope_step() {
                        return None;
                    }
                    if matches!(operand.kind(), "keyword_argument" | "dictionary_splat") {
                        continue;
                    }
                    spellings.push(
                        operand
                            .utf8_text(prepared.source().as_bytes())
                            .ok()?
                            .to_owned(),
                    );
                }
            }
            self.indexed_source_matches(class.source(), prepared.source())
                .then_some(spellings)
        })();
        if spellings.is_none() {
            use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
            let cause = match session.finish(()) {
                BoundedResolution::Exceeded { .. } => DerivationExecutionCause::Budget,
                BoundedResolution::Cancelled { .. } => DerivationExecutionCause::Cancelled,
                BoundedResolution::Complete { .. } | BoundedResolution::Unavailable { .. } => {
                    DerivationExecutionCause::Provider
                }
            };
            // A stable projection stop does not certify a failed source read.
            // Record this failure here so direct bases and full MRO agree.
            self.record_hierarchy_stop(QueryReadIncomplete::ProofStopped {
                reason: "python_hierarchy_base_facts_unavailable",
                cause: Some(cause),
            });
        }
        spellings
    }

    /// Whether the class statement declares PEP 695 type parameters. Such a class
    /// gets `typing.Generic` among its bases, which no written base names.
    /// `None` when the source cannot be read.
    fn class_has_type_parameters(
        &self,
        class: &CodeUnit,
        session: &ResolutionSession,
    ) -> Option<bool> {
        let prepared = session
            .query(|| {
                crate::analyzer::python::type_flow::current_indexed_prepared(self, class.source())
            })
            .flatten()?;
        let node = crate::analyzer::python::type_flow::class_node_for_unit_in_session(
            self, &prepared, class, session,
        )?;
        self.indexed_source_matches(class.source(), prepared.source())
            .then(|| node.child_by_field_name("type_parameters").is_some())
    }

    /// Project the selected native hierarchy into the public answer. A base is
    /// definite only with its native proof; every other base stays open.
    fn answer_from_native(
        &self,
        class: &CodeUnit,
        hierarchy: &PythonClassHierarchy,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> PythonClassHierarchyAnswer {
        let projection = &hierarchy.projection;
        let mut basis = PythonAncestryBasis::default();
        let open = |outcome, reason, bases, basis| {
            PythonClassHierarchyAnswer::stopped(outcome, reason, bases, basis)
        };
        let Some(root) = projection.nodes.first() else {
            return open(
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::UnresolvedBase,
                Vec::new(),
                basis,
            );
        };
        debug_assert_eq!(root.owner, projection.root);
        let Some(spellings) = self.written_base_spellings(class, session) else {
            return open(
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::UnresolvedBase,
                Vec::new(),
                basis,
            );
        };

        // Selected models name the language-fixed `object` and supply the
        // claims every model class in the answer rests on.
        let snapshot = self.active_semantic_model_snapshot();
        let active = snapshot
            .as_ref()
            .map(|snapshot| snapshot.active_models().as_ref());
        let overlay = snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.semantic_model_overlay().map(Arc::as_ref));
        let mut cache = ExternalClassCache::default();
        let mut budget = ClaimBudget {
            visits: 0,
            session,
            retained_claims: HashSet::default(),
        };
        let mut failure = None;
        let mut identities = HashMap::default();
        let mut claimed_unbound = HashSet::default();
        let mut undeclared = HashSet::default();
        let mut fixed = std::collections::HashMap::<String, (Option<ClassIdentity>, bool)>::new();
        for (id, owner) in &hierarchy.owners {
            let identity = match owner {
                PythonHierarchyOwner::Source(unit) => Some(ClassIdentity::Workspace(unit.clone())),
                PythonHierarchyOwner::Model(symbol) => Some(ClassIdentity::External {
                    qualified_name: symbol.qualified_name.as_str().into(),
                    symbol_id: symbol.id.as_str().into(),
                }),
                PythonHierarchyOwner::Intrinsic { canonical_name } => {
                    if !fixed.contains_key(canonical_name) {
                        let resolved = match self.fixed_class_identity(
                            canonical_name,
                            active,
                            overlay,
                            &mut cache,
                            &mut basis,
                            &mut budget,
                        ) {
                            Ok(resolved) => resolved,
                            Err(reason) => {
                                failure.get_or_insert((PythonHierarchyOutcome::Incomplete, reason));
                                (None, false)
                            }
                        };
                        fixed.insert(canonical_name.clone(), resolved);
                    }
                    let (identity, unbound) = fixed[canonical_name].clone();
                    if unbound {
                        claimed_unbound.insert(*id);
                    } else if identity.is_none()
                        && !overlay.is_some_and(|overlay| {
                            !overlay
                                .symbols_named_for(canonical_name, "python")
                                .records
                                .is_empty()
                        })
                    {
                        undeclared.insert(*id);
                    }
                    identity
                }
                PythonHierarchyOwner::Unprojected => None,
            };
            identities.insert(*id, identity);
        }
        let mut external_failures = HashMap::default();
        let mut external_claim_names = HashMap::default();
        if let (Some(active), Some(overlay)) = (active, overlay) {
            for (owner, ordinal, name) in &hierarchy.provider_names {
                let records = overlay.symbols_named_for(name, "python");
                let Some(first) = records.records.first() else {
                    continue;
                };
                // This only diagnoses an open import. It admits no declaration
                // or member from one of the conflicting providers.
                if records.records.iter().all(|record| {
                    record.kind == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Class
                        && record.id == first.id && record.qualified_name == first.qualified_name

                }) {
                    let identity = ClassIdentity::External {
                        qualified_name: first.qualified_name.as_str().into(),
                        symbol_id: first.id.as_str().into(),
                    };
                    if let Err(reason) = runtime_bases(active, Some(overlay), &identity,
                        &mut basis, &mut cache, &mut budget) {
                        external_failures.insert((*owner, *ordinal), reason);
                        external_claim_names.insert((*owner, *ordinal), first.qualified_name.to_string());
                    }
                }
            }
        }
        let identities = Identities {
            of: identities,
            claimed_unbound,
            undeclared,
            external_failures,
        };

        let mut facts = Vec::with_capacity(root.edges.len());
        for edge in &root.edges {
            let verdict = edge_verdict(hierarchy, &identities, root.owner, edge);
            let (origin, spelling) = if edge.implicit {
                if edge.implicit_undecided && !edge.implicit_external {
                    (
                        PythonBaseOrigin::ImplicitGenericUndecidedFactory,
                        "typing._GenericAlias".to_owned(),
                    )
                } else if edge.implicit_undecided {
                    (
                        PythonBaseOrigin::ImplicitGenericUndecided,
                        "typing.Generic".to_owned(),
                    )
                } else if self.class_has_type_parameters(class, session) == Some(true) {
                    (
                        PythonBaseOrigin::ImplicitGeneric,
                        "typing.Generic".to_owned(),
                    )
                } else {
                    (
                        PythonBaseOrigin::ImplicitObject,
                        PYTHON_OBJECT_ROOT.to_owned(),
                    )
                }
            } else {
                (
                    PythonBaseOrigin::Source,
                    spellings
                        .get(edge.ordinal as usize)
                        .cloned()
                        .unwrap_or_default(),
                )
            };
            facts.push(PythonBaseFact {
                origin,
                ordinal: edge.ordinal as usize,
                spelling,
                resolution: verdict.resolution,
                target: verdict.target,
            });
        }
        // The first failure in walk order decides the outcome, as one walk of
        // the class graph would meet it. The owners that walk met before it
        // stopped are the only ones whose model claims the answer rests on.
        let failed_before_walk = failure.is_some();
        let mut met = Vec::new();
        let mut met_external_names = HashSet::default();
        'nodes: for node in &projection.nodes {
            if failure.is_some() {
                break;
            }
            met.push(node.owner);
            if !node.expanded {
                failure = Some((
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::UnresolvedBase,
                ));
                break;
            }
            // A decorator may return any object, whether or not it is known to
            // preserve members; the class header then names no class.
            // Unsupported hierarchy traversal (a call, subscript or splat base)
            // is evidence on the node; it has no edge to carry it.
            if hierarchy.decorated.contains(&node.owner)
                || !node.inventory_complete
                || node.completion != ResolutionCompletion::Complete
            {
                failure = Some(match hierarchy.owner(node.owner) {
                    PythonHierarchyOwner::Source(_)
                        if node
                            .edges
                            .iter()
                            .any(|edge| edge.implicit_undecided && !edge.implicit_external) =>
                    {
                        (
                            PythonHierarchyOutcome::Incomplete,
                            PythonHierarchyReason::ImplicitGenericUndecidedFactory,
                        )
                    }
                    PythonHierarchyOwner::Source(_) => (
                        PythonHierarchyOutcome::Unsupported,
                        PythonHierarchyReason::UnsupportedBaseExpression,
                    ),
                    // The runtime-base authority names why a model class has no
                    // agreed bases (conflicting or ambiguous claims, a cycle);
                    // its claims stay on the answer as the evidence.
                    _ => (
                        PythonHierarchyOutcome::Incomplete,
                        match (active, identities.of(node.owner)) {
                            (Some(active), Some(identity @ ClassIdentity::External { .. })) => {
                                runtime_bases(
                                    active,
                                    overlay,
                                    identity,
                                    &mut basis,
                                    &mut cache,
                                    &mut budget,
                                )
                                .err()
                                .unwrap_or(PythonHierarchyReason::MissingRuntimeBases)
                            }
                            // A fixed class the model declares but no unique owner
                            // admits is an unresolved base, not a missing claim.
                            (_, None)
                                if matches!(
                                    hierarchy.owner(node.owner),
                                    PythonHierarchyOwner::Intrinsic { canonical_name }
                                        if overlay.is_some_and(|overlay| !overlay
                                            .symbols_named_for(canonical_name, "python")
                                            .records
                                            .is_empty())
                                ) =>
                            {
                                PythonHierarchyReason::UnresolvedBase
                            }
                            _ => PythonHierarchyReason::MissingRuntimeBases,
                        },
                    ),
                });
                break;
            }
            let mut seen = HashSet::default();
            for edge in &node.edges {
                let verdict = edge_verdict(hierarchy, &identities, node.owner, edge);
                if !verdict.resolved() {
                    if let Some(name) = external_claim_names.get(&(node.owner, edge.ordinal)) {
                        met_external_names.insert(name.clone());
                    }
                    // A class a model claims but no identity binds keeps its
                    // claims: they are the evidence of this failure.
                    met.extend(
                        edge.targets
                            .iter()
                            .copied()
                            .filter(|target| identities.claimed_unbound.contains(target)),
                    );
                    failure = Some((PythonHierarchyOutcome::Incomplete, verdict.failure));
                    break 'nodes;
                }
                met.extend(edge.targets.iter().copied());
                // Two spellings of one class (IOError and OSError) are one base.
                if !seen.insert(verdict.target) {
                    failure = Some((
                        PythonHierarchyOutcome::Inconsistent,
                        PythonHierarchyReason::DuplicateBase,
                    ));
                    break 'nodes;
                }
            }
            if node.cyclic {
                failure = Some((
                    PythonHierarchyOutcome::Inconsistent,
                    PythonHierarchyReason::CyclicBases,
                ));
                break;
            }
        }
        if failure.is_none() && !projection.order_complete {
            failure = Some(match &projection.order_completion {
                ResolutionCompletion::Complete => (
                    PythonHierarchyOutcome::Inconsistent,
                    PythonHierarchyReason::InconsistentLinearization,
                ),
                _ => (
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::VisitLimit,
                ),
            });
        }
        let mro = projection
            .order
            .iter()
            .map(|id| identities.of(*id).cloned())
            .collect::<Option<Vec<_>>>();
        // One class has one place in an MRO. A builtin reached both through a
        // model declaration and through the fixed table has two owners here
        // (a model class below it keeps the model identity), so the shared
        // linearization can list it twice. Publish no ordering rather than a
        // complete but repeated one.
        if failure.is_none()
            && let Some(mro) = &mro
        {
            let mut distinct = HashSet::default();
            if !mro.iter().all(|identity| distinct.insert(identity)) {
                failure = Some((
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::AmbiguousRuntimeBase,
                ));
            }
        }
        // Model claims are premises of every ordering that crosses a model class.
        if let (Some(active), Some(mro)) = (active, &mro) {
            for identity in mro {
                if matches!(identity, ClassIdentity::External { .. })
                    && let Err(reason) = runtime_bases(
                        active,
                        overlay,
                        identity,
                        &mut basis,
                        &mut cache,
                        &mut budget,
                    )
                {
                    failure.get_or_insert((PythonHierarchyOutcome::Incomplete, reason));
                    break;
                }
            }
        }
        // A class a model claims but no identity can bind keeps every raw
        // claim: they are the evidence of the failure itself.
        let met_unbound = met.iter().any(|id| identities.claimed_unbound.contains(id));
        if failure.is_some() && !failed_before_walk && !met_unbound {
            // Identities are resolved for the whole projection up front, so a
            // claim about a class the walk never reached (the `object` below
            // an unread base) must not appear on a stopped answer.
            let mut met_names = met
                .iter()
                .filter_map(|id| match identities.of(*id) {
                    Some(
                        ClassIdentity::External { qualified_name, .. }
                        | ClassIdentity::Intrinsic { qualified_name },
                    ) => Some(qualified_name.to_string()),
                    _ => None,
                })
                .collect::<HashSet<_>>();
            let met_model_ids = met
                .iter()
                .filter_map(|id| match identities.of(*id) {
                    Some(ClassIdentity::External { symbol_id, .. }) => Some(symbol_id.as_ref()),
                    _ => None,
                })
                .collect::<HashSet<_>>();
            met_names.extend(met_external_names);
            basis.claims.retain(|claim| {
                claim
                    .class
                    .as_ref()
                    .is_some_and(|class| met_names.contains(class.qualified_name.as_str()))
                    || met_model_ids.contains(claim.declared_class.symbol_id.as_str())
            });
        }
        // `object` is the root of every MRO, so a claim that it has a base
        // closes a cycle through that base's own MRO.
        if failure.is_none()
            && basis.claims.iter().any(|claim| {
                claim
                    .class
                    .as_ref()
                    .is_some_and(|class| class.qualified_name == PYTHON_OBJECT_ROOT)
                    && !claim.bases.is_empty()
            })
        {
            failure = Some((
                PythonHierarchyOutcome::Inconsistent,
                PythonHierarchyReason::CyclicBases,
            ));
        }
        if cancellation.is_cancelled() {
            failure = Some((
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::Cancelled,
            ));
        }
        match (failure, mro) {
            (None, Some(mro)) => PythonClassHierarchyAnswer::complete(facts, mro, basis),
            (Some((outcome, reason)), _) => open(outcome, reason, facts, basis),
            (None, None) => open(
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::UnresolvedBase,
                facts,
                basis,
            ),
        }
    }

    /// The identity of a language-fixed class. A model that declares the class
    /// names it; the language names only `builtins.object`, and only when no
    /// model declares it. Any other fixed class is open without a model, since
    /// the language table gives no bases for it. `None` also while a model
    /// claims the class that no model identity can yet bind (#5738).
    fn fixed_class_identity(
        &self,
        canonical_name: &str,
        active: Option<&brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels>,
        overlay: Option<
            &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
        >,
        cache: &mut ExternalClassCache,
        basis: &mut PythonAncestryBasis,
        budget: &mut ClaimBudget<'_>,
    ) -> Result<(Option<ClassIdentity>, bool), PythonHierarchyReason> {
        use brokk_bifrost_analysis::analyzer::semantic_model::python_runtime_bases::{
            retain_open_claims, runtime_base_claim_declared,
        };
        let language_fixed =
            (canonical_name == PYTHON_OBJECT_ROOT).then(|| ClassIdentity::Intrinsic {
                qualified_name: PYTHON_OBJECT_ROOT.into(),
            });
        let Some(active) = active else {
            return Ok((language_fixed, false));
        };
        let target = crate::analyzer::python::type_flow::exact_external_class_name_with_visits(
            overlay,
            canonical_name,
            cache,
            &mut || budget.charge(1, 1),
        )?;
        Ok(match target {
            Some(target)
                if canonical_name != PYTHON_OBJECT_ROOT
                    || runtime_base_claim_declared(active, &target, budget)? =>
            {
                (Some(target), false)
            }
            None if retain_open_claims(active, canonical_name, overlay, basis, budget)? => {
                (None, true)
            }
            _ => (language_fixed, false),
        })
    }

    fn mro_members_from_hierarchy(
        &self,
        hierarchy: PythonClassHierarchyAnswer,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer {
        let mut answer = PythonMroMembersAnswer {
            outcome: hierarchy.outcome,
            reason: hierarchy.reason,
            hierarchy,
            members: Vec::new(),
        };
        if answer.outcome != PythonHierarchyOutcome::Complete {
            return answer;
        }
        let mut selected = HashSet::<String>::default();
        let mut visits = 0usize;
        for (rank, identity) in answer.hierarchy.mro.iter().enumerate() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                answer.outcome = PythonHierarchyOutcome::Incomplete;
                answer.reason = Some(PythonHierarchyReason::Cancelled);
                break;
            }
            let ClassIdentity::Workspace(owner) = identity else {
                // The implicit object root is a language-supplied terminal;
                // it contributes no source declarations. Any other external
                // class leaves the member surface unknown.
                if matches!(identity, ClassIdentity::Intrinsic { .. }) {
                    continue;
                }
                answer.outcome = PythonHierarchyOutcome::Incomplete;
                answer.reason = Some(PythonHierarchyReason::UnknownMemberSurface);
                break;
            };
            let declarations = self.direct_children_in_source_order(owner);
            visits = visits.saturating_add(declarations.len());
            if brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                visits,
                MAX_PYTHON_MEMBER_VISITS,
            )
            .try_allow(0)
            .is_err()
            {
                answer.outcome = PythonHierarchyOutcome::Incomplete;
                answer.reason = Some(PythonHierarchyReason::VisitLimit);
                break;
            }
            for member in declarations.into_iter().rev() {
                let name = member.terminal_name().to_owned();
                if selected.insert(name.clone()) {
                    answer.members.push(PythonMroMember {
                        name,
                        member,
                        owner: owner.clone(),
                        rank,
                    });
                }
            }
        }
        answer
            .members
            .sort_by(|left, right| (left.rank, &left.name).cmp(&(right.rank, &right.name)));
        answer
    }

    fn direct_children_in_source_order(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        let mut declarations = self.direct_children(owner);
        declarations.sort_by_key(|member| {
            self.ranges(member)
                .iter()
                .map(|range| range.start_byte)
                .max()
                .unwrap_or(usize::MAX)
        });
        declarations
    }
}

/// The memoized direct-ancestor answer: definite workspace edges and every
/// uncertainty the native hierarchy request reported, in a cloneable form.
#[derive(Debug, Clone, Default)]
pub(crate) struct DirectAncestors {
    edges: Vec<CodeUnit>,
    ambiguous: Vec<Vec<CodeUnit>>,
    open: Vec<HierarchyOpenReason>,
}

impl DirectAncestors {
    fn truncated() -> Self {
        Self {
            open: vec![HierarchyOpenReason::MemberFamily(
                MemberFamilyReason::HierarchyTruncated,
            )],
            ..Default::default()
        }
    }

    fn to_answer(&self) -> HierarchyAnswer {
        HierarchyAnswer {
            edges: self.edges.clone(),
            ambiguous: self.ambiguous.clone(),
            open: self.open.clone(),
        }
    }
}

/// One selected forward operation held for a whole hierarchy walk or index
/// build, as the JVM languages hold theirs. Ancestors are read from it; other
/// questions use the provider's own memoized paths.
struct PythonHierarchyQuery<'a, 'r> {
    python: &'a PythonAnalyzer,
    read: &'r mut dyn FnMut(
        &CodeUnit,
    )
        -> brokk_bifrost_analysis::analyzer::store::Result<PythonHierarchyRead>,
}

impl brokk_bifrost_core::analyzer::capabilities::HierarchyQuery for PythonHierarchyQuery<'_, '_> {
    fn direct_ancestors(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        self.python.direct_ancestors_through(unit, self.read)
    }
    fn direct_descendants(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        self.python.get_direct_descendants(unit)
    }
    fn member_family_ancestors(
        &mut self,
        unit: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::capabilities::MemberFamilyAncestors {
        self.python.member_family_ancestors(unit)
    }
    fn direct_descendants_within(
        &mut self,
        unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.python.get_direct_descendants_within(unit, scope)
    }
}

pub(crate) fn weight_direct_ancestors(_key: &CodeUnit, value: &Arc<DirectAncestors>) -> u32 {
    let units = |units: &[CodeUnit]| {
        units
            .iter()
            .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
            .sum::<usize>()
    };
    let size = units(&value.edges)
        + value
            .ambiguous
            .iter()
            .map(|group| units(group))
            .sum::<usize>()
        + value.open.len() * size_of::<HierarchyOpenReason>()
        + size_of::<DirectAncestors>();
    size.min(u32::MAX as usize) as u32
}

impl PythonAnalyzer {
    /// A class's own bases read through `read`, which answers from a native
    /// operation the caller already holds (see `with_python_direct_bases`). A
    /// read that stops records why and leaves the answer open.
    pub(crate) fn direct_ancestors_through(
        &self,
        unit: &CodeUnit,
        read: &mut dyn FnMut(
            &CodeUnit,
        ) -> brokk_bifrost_analysis::analyzer::store::Result<
            PythonHierarchyRead,
        >,
    ) -> HierarchyAnswer {
        if !unit.is_class() {
            return DirectAncestors::default().to_answer();
        }
        let result = read(unit);
        #[cfg(any(test, feature = "test-support"))]
        let result = match (&self.hierarchy_stop_for_test, result) {
            (Some((name, label)), Ok(PythonHierarchyRead::Ready(hierarchy)))
                if unit.short_name() == *name =>
            {
                use brokk_bifrost_analysis::analyzer::resolution::HierarchyStop;
                let stop = label.map(HierarchyStop::Deterministic).unwrap_or_else(|| {
                    HierarchyStop::missing_provenance_for_test(hierarchy.projection.root)
                });
                Ok(PythonHierarchyRead::Stopped {
                    stop,
                    hierarchy: Some(hierarchy),
                })
            }
            (_, result) => result,
        };
        match result {
            Ok(PythonHierarchyRead::Ready(hierarchy)) => {
                self.ancestors_of(unit, &hierarchy, &ResolutionSession::unbounded())
            }
            Ok(PythonHierarchyRead::Unavailable) => Self::unavailable_ancestors(unit),
            Ok(PythonHierarchyRead::Stopped { stop, hierarchy }) => {
                let mut answer = hierarchy
                    .as_ref()
                    .map(|hierarchy| {
                        self.ancestors_of(unit, hierarchy, &ResolutionSession::unbounded())
                    })
                    .unwrap_or_default();
                for reason in self.stopped_ancestors(hierarchy_stop_reason(&stop)).open {
                    if !answer.open.contains(&reason) {
                        answer.open.push(reason);
                    }
                }
                answer
            }
            Err(error) => {
                self.record_query_failure(error);
                self.stopped_ancestors(operational_hierarchy_stop())
            }
        }
        .to_answer()
    }

    /// Direct workspace ancestors, projected from the same native request as
    /// the MRO. A base that is not definitely bound keeps the answer open.
    fn native_direct_ancestors(&self, code_unit: &CodeUnit) -> DirectAncestors {
        let cancellation = self.inner.active_query_cancellation().unwrap_or_default();
        if !code_unit.is_class() {
            return DirectAncestors::default();
        }
        match self.open_hierarchy_request(&cancellation) {
            Ok(mut request) => self.direct_ancestors_in(&mut request, code_unit, &cancellation),
            Err(PythonHierarchyReason::UnresolvedBase) => Self::unavailable_ancestors(code_unit),
            Err(_) => self.stopped_ancestors(operational_hierarchy_stop()),
        }
    }

    fn unavailable_ancestors(unit: &CodeUnit) -> DirectAncestors {
        // PEP 695 aliases are class-shaped CodeUnits but TypeAliasType values,
        // so they deliberately have no class crosswalk. Keep the answer open
        // without claiming that the request was cancelled or budget-stopped.
        DirectAncestors {
            open: vec![HierarchyOpenReason::UnreadAncestor(
                UnreadMemberFamilyAncestor {
                    name: unit.fq_name().to_owned(),
                    inventory: None,
                },
            )],
            ..Default::default()
        }
    }

    /// Preserve the producer classification so receipts retain only stable stops.
    fn record_hierarchy_stop(&self, reason: QueryReadIncomplete) {
        debug_assert!(
            match reason.base_cause() {
                QueryReadIncomplete::ProofStopped { cause, .. } =>
                    cause.is_some() || reason.stable_replay_reason().is_some(),
                _ => false,
            },
            "hierarchy stop must have a classified cause: {reason:?}"
        );
        self.record_query_incomplete(reason);
    }

    fn stopped_ancestors(&self, reason: QueryReadIncomplete) -> DirectAncestors {
        self.record_hierarchy_stop(reason);
        DirectAncestors::truncated()
    }

    /// The class's own bases on a held request: no base is expanded.
    fn direct_ancestors_in(
        &self,
        request: &mut PythonNativeRequest<'_>,
        code_unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> DirectAncestors {
        if !code_unit.is_class() {
            return DirectAncestors::default();
        }
        let session = Self::hierarchy_session(cancellation);
        let hierarchy = match self.hierarchy_in(
            request,
            code_unit,
            cancellation,
            &session,
            |operation, environment, definition, session| {
                operation.python_direct_bases(environment, definition, session)
            },
        ) {
            NativeHierarchy::Ready(hierarchy) => hierarchy,
            NativeHierarchy::Unavailable(_) => return Self::unavailable_ancestors(code_unit),
            NativeHierarchy::Stopped(_) => {
                return self.stopped_ancestors(operational_hierarchy_stop());
            }
        };
        self.ancestors_of(code_unit, &hierarchy, &session)
    }

    /// The class's own bases from a direct-bases hierarchy. Unavailable source
    /// facts keep the answer open and record their operational cause.
    fn ancestors_of(
        &self,
        code_unit: &CodeUnit,
        hierarchy: &PythonClassHierarchy,
        session: &ResolutionSession,
    ) -> DirectAncestors {
        // Native handoff records projection stops; the held reader takes the
        // stop out of the projection and records it alongside this answer.
        let mut answer = if hierarchy.projection.stop.is_some() {
            DirectAncestors::truncated()
        } else {
            DirectAncestors::default()
        };
        let Some(spellings) = self.written_base_spellings(code_unit, session) else {
            return DirectAncestors::truncated();
        };
        let root = hierarchy
            .projection
            .nodes
            .first()
            .expect("a projected class hierarchy has its root node");
        for edge in &root.edges {
            let unread = |answer: &mut DirectAncestors| {
                answer.open.push(HierarchyOpenReason::UnreadAncestor(
                    UnreadMemberFamilyAncestor {
                        name: if edge.implicit_undecided && !edge.implicit_external {
                            "typing._GenericAlias".to_owned()
                        } else {
                            spellings
                                .get(edge.ordinal as usize)
                                .cloned()
                                .unwrap_or_else(|| PYTHON_OBJECT_ROOT.to_owned())
                        },
                        inventory: None,
                    },
                ));
            };
            match edge.targets.as_slice() {
                // An import that left the workspace names an external class,
                // and nothing behind it can be a workspace ancestor.
                [] if hierarchy
                    .provider_open
                    .contains(&(root.owner, edge.ordinal)) => {}
                [] => unread(&mut answer),
                // A decorated base may have been replaced by the decorator.
                [target] if hierarchy.decorated.contains(target) => unread(&mut answer),
                [target]
                    if edge.transfer == ResolutionCompletion::Complete
                        && edge.residual == ResolutionCompletion::Complete =>
                {
                    match hierarchy.owner(*target) {
                        PythonHierarchyOwner::Source(unit) if unit.is_class() => {
                            answer.edges.push(unit.clone());
                        }
                        // A non-class declaration does not prove the value
                        // the header reads (#5668).
                        PythonHierarchyOwner::Source(_) | PythonHierarchyOwner::Unprojected => {
                            unread(&mut answer)
                        }
                        // A resolved class outside the workspace is not a
                        // workspace ancestor, and nothing behind it can be one.
                        PythonHierarchyOwner::Intrinsic { .. } | PythonHierarchyOwner::Model(_) => {
                        }
                    }
                }
                [_] => unread(&mut answer),
                targets => {
                    answer.ambiguous.push(
                        targets
                            .iter()
                            .filter_map(|target| match hierarchy.owner(*target) {
                                PythonHierarchyOwner::Source(unit) => Some(unit.clone()),
                                _ => None,
                            })
                            .collect(),
                    );
                    answer.open.push(HierarchyOpenReason::MemberFamily(
                        MemberFamilyReason::HierarchyAmbiguous,
                    ));
                }
            }
        }
        // Unsupported hierarchy traversal (a call, subscript or splat base) is
        // evidence on the node and produces no edge: a written base operand
        // without an edge is an unread ancestor. They are not a stopped walk,
        // so the descendant index keeps this class as an open candidate
        // instead of publishing nothing for the workspace.
        //
        // A decorator marks the node open for member lookup, but the class
        // statement's own bases are readable whatever the decorator returns.
        // For a decorated class the node evidence therefore opens this answer
        // only when some written operand has no edge; a use of the decorated
        // NAME as a base is checked on the edge above.
        let covered = root
            .edges
            .iter()
            .filter(|edge| !edge.implicit)
            .map(|edge| edge.ordinal as usize)
            .collect::<HashSet<_>>();
        let mut names = spellings
            .iter()
            .enumerate()
            .filter(|(ordinal, _)| !covered.contains(ordinal))
            .map(|(_, spelling)| spelling.clone())
            .collect::<Vec<_>>();
        let node_open = hierarchy.projection.stop.is_some()
            || !root.inventory_complete
            || root.completion != ResolutionCompletion::Complete;
        if node_open
            && names.is_empty()
            && !hierarchy.decorated.contains(&root.owner)
            && !root
                .edges
                .iter()
                .any(|edge| edge.implicit_undecided && !edge.implicit_external)
        {
            names.push(
                spellings
                    .first()
                    .cloned()
                    .unwrap_or_else(|| PYTHON_OBJECT_ROOT.to_owned()),
            );
        }
        if node_open || !names.is_empty() {
            answer.open.extend(names.into_iter().map(|name| {
                HierarchyOpenReason::UnreadAncestor(UnreadMemberFamilyAncestor {
                    name,
                    inventory: None,
                })
            }));
        }
        answer
    }
}

impl TypeHierarchyProvider for PythonAnalyzer {
    fn with_hierarchy_query(
        &self,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        let cancellation = self.inner.active_query_cancellation().unwrap_or_default();
        let Ok(mut request) = self.open_hierarchy_request(&cancellation) else {
            // No selected request: every ancestor read is a stopped read.
            return run(&mut PythonHierarchyQuery {
                python: self,
                read: &mut |_| {
                    Ok(PythonHierarchyRead::Stopped {
                        stop: if cancellation.is_cancelled() {
                            brokk_bifrost_analysis::analyzer::resolution::HierarchyStop::Cancelled(
                                brokk_bifrost_analysis::analyzer::resolution::cancelled_completion(
                                ),
                            )
                        } else {
                            brokk_bifrost_analysis::analyzer::resolution::HierarchyStop::Provider(
                                ResolutionCompletion::Complete,
                            )
                        },
                        hierarchy: None,
                    })
                },
            });
        };
        match request.operation.with_python_direct_bases(
            &request.environment,
            &cancellation,
            |read| run(&mut PythonHierarchyQuery { python: self, read }),
        ) {
            Ok(SelectedResolutionOperationOutcome::Native(())) => {}
            // The walk's reads were taken against a selection that is no
            // longer current, or the request was cancelled: nothing it
            // returned is retainable.
            Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => {
                self.record_query_incomplete(QueryReadIncomplete::Cancelled)
            }
            Ok(
                SelectedResolutionOperationOutcome::Stale(_)
                | SelectedResolutionOperationOutcome::Unavailable(_),
            ) => {
                self.record_query_incomplete(QueryReadIncomplete::ProofStopped {
                    reason: "python_hierarchy_request_stopped",
                    cause: Some(brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Snapshot),
                });
            }
            Err(error) => self.record_query_failure(error),
        }
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let ancestors = super::read_memo(
            self,
            &self.direct_ancestors,
            code_unit.clone(),
            || Arc::new(self.native_direct_ancestors(code_unit)),
            weight_direct_ancestors,
        );
        ancestors.to_answer()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a whole-workspace descendant query cannot be cancelled")
    }
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.direct_descendant_index.read(
            &super::memo_attribution(self),
            |(memo, _)| {
                brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
                    self,
                    scope,
                    code_unit,
                    memo,
                    || build_direct_descendant_index(self, self, scope),
                    |_| {},
                )
            },
            |answer| {
                if answer.as_ref().is_ok_and(|answer| answer.is_complete()) {
                    self.descendants_authority_digest()
                        .map_or(super::AuthorityInputs::Unnamed, super::whole_fact)
                } else {
                    // A stopped build has no answer to certify. Do not start
                    // an unbounded build after the request has stopped.
                    super::AuthorityInputs::Unnamed
                }
            },
        )
    }
}

#[cfg(test)]
mod secondary_stop_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::common::{
        read_replayable_query_cache, replayable_descendant_fill,
    };
    use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
    use brokk_bifrost_analysis::analyzer::resolution::HierarchyStop;
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index_from_candidates;
    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#12288: a deterministic stop plus an operational ancestor-read failure retained an empty stable answer"
    )]
    fn deterministic_projection_keeps_operational_base_read_failure() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("model.py"),
            "class Base:\n    pass\n\nclass Child(Base):\n    pass\n",
        )
        .unwrap();
        let python = PythonAnalyzer::from_project(TestProject::new(temp.path(), Language::Python));
        let cancellation = CancellationToken::new();
        python
            .prepare_native_environment_for_test(&cancellation)
            .unwrap();
        let declarations = python.get_all_declarations();
        let base = declarations
            .iter()
            .find(|unit| unit.short_name() == "Base")
            .unwrap();
        let child = declarations
            .iter()
            .find(|unit| unit.short_name() == "Child")
            .unwrap();
        let NativeHierarchy::Ready(mut hierarchy) =
            python.native_class_hierarchy(child, &cancellation, &ResolutionSession::unbounded())
        else {
            panic!("fixture must project a real class hierarchy");
        };
        // Keep the real root and positive edge, with a deterministic stop on
        // the remaining projection. No analyzer hook or additional memo is needed.
        hierarchy.projection.stop =
            Some(HierarchyStop::Deterministic("resolution_cyclic_expansion"));
        let scope = DescendantIndexScope::whole_workspace(&cancellation);
        let read = |session: &ResolutionSession| {
            let _request = AnalyzerQueryScope::capturing_read_incompleteness(&python);
            python.direct_descendant_index.read(
                &super::super::memo_attribution(&python),
                |(memo, _)| {
                    let entry = read_replayable_query_cache(memo, &scope.variant(), || {
                        replayable_descendant_fill(&python, &scope, || {
                            python.record_hierarchy_stop(hierarchy_stop_reason(
                                hierarchy.projection.stop.as_ref().unwrap(),
                            ));
                            build_direct_descendant_index_from_candidates(
                                vec![base.clone(), child.clone()],
                                |unit| {
                                    Some(if unit == child {
                                        python.ancestors_of(unit, &hierarchy, session).to_answer()
                                    } else {
                                        HierarchyAnswer::complete(Vec::new())
                                    })
                                },
                                &|| true,
                            )
                        })
                    });
                    let answer = entry
                        .replay()
                        .as_ref()
                        .expect("stopped index stays available")
                        .answer(base);
                    let reasons = entry.incomplete_reasons().to_vec();
                    memo.run_pending_tasks();
                    (answer, reasons, memo.entry_count())
                },
                |_| super::super::AuthorityInputs::Unnamed,
            )
        };
        let exhausted =
            ResolutionSession::bounded_with_total_work(INTERACTIVE_TYPE_LOOKUP_BUDGET, 0, None);
        let (stopped, reasons, retained) = read(&exhausted);
        assert!(stopped.edges.is_empty());
        assert!(!stopped.is_complete());
        assert_eq!(retained, 0);
        assert!(
            reasons.iter().any(|reason| matches!(
                reason.base_cause(),
                QueryReadIncomplete::ProofStopped {
                    reason: "python_hierarchy_base_facts_unavailable",
                    cause: Some(DerivationExecutionCause::Budget),
                }
            )),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.stable_replay_reason().is_some()),
            "{reasons:?}"
        );

        let (recovered, reasons, retained) = read(&ResolutionSession::unbounded());
        assert_eq!(recovered.edges, vec![child.clone()]);
        assert_eq!(retained, 1);
        assert!(
            reasons
                .iter()
                .all(|reason| !reason.is_execution_dependent()),
            "{reasons:?}"
        );
    }
}
