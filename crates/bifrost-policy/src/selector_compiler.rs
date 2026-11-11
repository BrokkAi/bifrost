use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Range as ByteRange;
use std::sync::Arc;

use crate::resolved::LoadedPolicy;
use crate::unit_execution::{UnitAttempt, UnitReuse, query_slicing_widen_reason, recompute_unit};
use crate::units::{
    PolicyIncrementalContext, PolicyUnitKey, PolicyUnitProduct, SelectorProduct,
    SelectorProductSite, UnitPartition, WidenReason,
};
use crate::{PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit, ResolvedPolicySelector};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::i_analyzer::{capture_query_reads, replay_query_reads};
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic::{
    CallBinding, CallSiteHandle, CallerReceiverBinding, CandidateCoverage, DispatchOracle,
    DurablePortIdentity, EvidenceCompleteness, OracleCallContext, ProcedureHandle, ProofStatus,
    SemanticArtifact, SemanticArtifactKey, SemanticArtifactLeaseCharge, SemanticArtifactLeaseChild,
    SemanticArtifactLeaseError, SemanticArtifactLeaseSet, SemanticArtifactLeaseWindow,
    SemanticBudget, SemanticBudgetDimension, SemanticBudgetScopeSnapshot, SemanticExecutionBudget,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork, ValueFlowOracle,
    ValueId,
};
use brokk_bifrost_analysis::analyzer::structural::OccurrenceRole;
use brokk_bifrost_analysis::analyzer::usages::call_relations::CallTargetOutcomeCache;
use brokk_bifrost_analysis::analyzer::usages::effects::EffectCoverage;
use brokk_bifrost_analysis::analyzer::{
    ProjectFile, Range, ReadKey, ReadLedger, WorkspaceAnalyzer,
};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_rql::PlanWidenDetail;
use brokk_bifrost_rql::structural::search::{
    CodeQueryCallBinding, CodeQueryExecutionScope, CodeQueryRowFamilySession,
    CodeQuerySemanticReceipt, DetailedCodeQueryDecoratedParameterEvidence, DetailedCodeQueryDomain,
    DetailedCodeQueryEvidence, DetailedCodeQueryResult, UnitExecutionResult, UnitRowItemTerminal,
    execute_code_query_detailed_eager_index_workspace_with_semantic_receipt,
    execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_and_row_family_session,
    execute_code_query_selector_unit, merge_unit_rows_in_scope, plan_seed_files,
};
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryExecutionLimits, CodeQueryExecutionWork, CodeQueryResult, CodeQueryResultItem,
    CodeQueryResultValue, CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence,
    CodeQuerySemanticLimits, CodeQuerySemanticProof, CodeQuerySemanticRowLimits,
    CodeQuerySemanticWork,
};
use brokk_bifrost_rql::{
    CallArgumentSelector, CallInputSelector, CodeQuery, CodeQueryPlan, CodeQueryPlanSource,
    PlanPartitioning, QueryStep, ResolvedCallProof,
};

#[derive(Debug)]
pub(super) enum PolicySelectorSessionError {
    Incomplete {
        completion: CodeQueryCompletion,
        detail: String,
    },
    Unavailable(String),
    Provider(String),
    /// The sliced compile cannot claim to have produced what a whole compile
    /// would have produced, and the caller must compile the policy again with
    /// no units. Not a failure: the reason says which step refused, and the
    /// answer is the compile this session was avoiding.
    Widen(WidenReason),
}

impl fmt::Display for PolicySelectorSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { detail, .. }
            | Self::Unavailable(detail)
            | Self::Provider(detail) => formatter.write_str(detail),
            Self::Widen(reason) => write!(
                formatter,
                "the sliced selector compile widened: {}",
                reason.stable_label()
            ),
        }
    }
}

#[derive(Clone)]
pub(super) struct PolicySelectedSite {
    pub(super) file: ProjectFile,
    pub(super) span: ByteRange<usize>,
    pub(super) proof: ProofStatus,
    pub(super) completeness: EvidenceCompleteness,
    pub(super) result_contract: Option<PolicyResultContractSelection>,
    pub(super) call_shape: Option<PolicyCallShapeSelection>,
    pub(super) call_binding: Option<PolicySelectedCallBinding>,
    /// Selected semantic record even on receiver-only rows without an actual.
    pub(super) selected_model_record: Option<(String, String)>,
    /// The authored summary whose override contract made this call binding's
    /// selector exact, as (pack digest, record ID). It is independent of the
    /// declaration record above: the declaration can be a workspace source
    /// target, or live in another pack, and the selector still rests on this
    /// summary.
    pub(super) selected_summary_record: Option<(String, String)>,
    /// Model identity retained even for a receiver-only row. Those rows have
    /// no written actual to populate `call_binding`, but their declaration
    /// identity is still needed by consumers that validate an external
    /// procedure summary.
    pub(super) modeled_member_id: Option<String>,
    pub(super) modeled_target_origin: Option<&'static str>,
    /// Exact semantic value/parameter-port identity retained by a complete
    /// decorated-parameter query row. The corresponding artifact dependency
    /// is admitted into this selector session before the row escapes.
    pub(super) decorated_parameter: Option<PolicyDecoratedParameterSelection>,
    /// Exact runtime keyed-read endpoint retained for matched-value policy
    /// binding. This live descriptor is never persisted in unit products.
    pub(super) runtime_keyed_read:
        Option<brokk_bifrost_analysis::analyzer::semantic::RuntimeKeyedReadEndpoint>,
    /// A keyed-read selector may produce a complete terminal row proving that
    /// no endpoint exists. Preserve that distinction for matched-value.
    pub(super) runtime_keyed_read_row: bool,
    pub(super) runtime_keyed_read_conclusive_exclusion: bool,
    /// Exact syntactic role for a taint selector's occurrence row. A binder
    /// can be name-classified without denoting an executable value point.
    pub(super) occurrence_role: Option<OccurrenceRole>,
    /// This exact row came from the narrowly retained positive subset of an
    /// otherwise incomplete result-contract query.
    pub(super) retained_incomplete_result_contract_query: bool,
}

#[derive(Clone)]
pub(super) struct PolicyDecoratedParameterSelection {
    pub(super) value_locator:
        brokk_bifrost_analysis::analyzer::semantic::ProcedureLocalLocator<ValueId>,
    pub(super) port: brokk_bifrost_analysis::analyzer::semantic::DurablePortIdentity,
}

#[cfg(test)]
fn query_plan_contains_decorator_bindings(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan
            .steps
            .iter()
            .any(|step| matches!(step, QueryStep::DecoratorBindings(_)))
        {
            return true;
        }
        pending.extend(plan.source.child_plans());
    }
    false
}

// Candidate results remain opt-in until policy families adopt their enumeration proof.
#[allow(dead_code)]
pub(crate) mod candidate_enumeration {
    use super::*;
    use brokk_bifrost_analysis::analyzer::Language;
    use brokk_bifrost_analysis::analyzer::structural::kinds::NormalizedKind;
    use brokk_bifrost_rql::{CallIdentity, Pattern, StringPredicate};

    pub(crate) struct WhitelistedCallSelector {
        pub(crate) target_fqn: String,
        pub(crate) callee_name: String,
        pub(crate) language: Language,
        structural_query: CodeQuery,
    }

    impl WhitelistedCallSelector {
        pub(crate) fn check(query: &CodeQuery) -> Option<Self> {
            let CodeQueryPlanSource::Seed(seed) = &query.plan.source else {
                return None;
            };
            let [
                QueryStep::CallShape,
                QueryStep::CallBindings,
                QueryStep::ResolvedCall(filter),
            ] = query.plan.steps.as_slice()
            else {
                return None;
            };
            let CallIdentity::Qualified { value, .. } = &filter.resolves_to else {
                return None;
            };
            if filter.proof != ResolvedCallProof::Declared
                || filter.receiver_type.is_some()
                || seed.languages != [Language::Java]
                || seed.inside.is_some()
                || seed.inside_decl.is_some()
                || seed.not_inside.is_some()
            {
                return None;
            }
            let callee = seed.root.callee.as_ref()?;
            let Some(StringPredicate::Exact(name)) = &callee.name else {
                return None;
            };
            let expected = Pattern {
                kinds: vec![NormalizedKind::Call],
                callee: Some(Box::new(Pattern {
                    name: Some(StringPredicate::Exact(name.clone())),
                    ..Pattern::default()
                })),
                ..Pattern::default()
            };
            // Compare the canonical projections of typed patterns to reject every
            // additional constraint, including future Pattern fields. No query
            // text is parsed or inspected here.
            let mut structural_query = query.clone();
            structural_query.plan.steps.clear();
            structural_query.result_detail = brokk_bifrost_rql::CodeQueryResultDetail::Full;
            let mut expected_query = structural_query.clone();
            let CodeQueryPlanSource::Seed(expected_seed) = &mut expected_query.plan.source else {
                unreachable!();
            };
            expected_seed.root = expected;
            if structural_query.to_canonical_query_plan_json()
                != expected_query.to_canonical_query_plan_json()
            {
                return None;
            }
            Some(Self {
                target_fqn: value.clone(),
                callee_name: name.clone(),
                language: Language::Java,
                structural_query,
            })
        }
    }

    #[derive(Clone)]
    pub(crate) struct StructuralCallCandidate {
        pub(crate) file: ProjectFile,
        pub(crate) span: ByteRange<usize>,
        pub(crate) ast_id: String,
    }

    /// Only `enumerate` can mint this proof; it belongs to the returned inventory.
    pub(crate) struct CompleteStructuralCandidateEnumeration {
        candidates: Vec<StructuralCallCandidate>,
        structural_plan: String,
        session_id: u64,
        request_id: u64,
    }

    #[derive(Debug)]
    pub(crate) enum CandidateEnumerationRefusal {
        Execution(PolicySelectorSessionError),
        Incomplete(CodeQueryCompletion),
        Truncated,
        MissingLocation,
        ReadIncomplete(brokk_bifrost_analysis::analyzer::QueryReadIncomplete),
    }

    pub(crate) enum CandidateOutcome {
        Selected {
            proof: ProofStatus,
            completeness: EvidenceCompleteness,
            /// Indices into the proof-bound result's detailed evidence.
            bindings: Vec<usize>,
        },
        Rejected,
        Undecided {
            reasons: Vec<CandidateReason>,
        },
    }

    #[derive(Debug, Clone)]
    pub(crate) enum CandidateReason {
        Read(brokk_bifrost_analysis::analyzer::QueryReadIncomplete),
        SilentDrop,
        IncompleteQuery(CodeQueryCompletion),
        Disagreement {
            file: ProjectFile,
            span: ByteRange<usize>,
        },
    }

    impl CandidateReason {
        pub(crate) fn label(&self) -> String {
            match self {
                Self::Read(reason) => format!("read:{}", reason.label()),
                Self::SilentDrop => "silent_drop".to_owned(),
                Self::IncompleteQuery(_) => "incomplete_query".to_owned(),
                Self::Disagreement { .. } => "disagreement".to_owned(),
            }
        }
    }

    /// The proof and its outcomes cannot be separated by consumers. Batch
    /// diagnostics stay conservative; binding storage also retains recovered
    /// isolated rows for M2.
    pub(crate) struct ProvenSelectorClassification {
        enumeration: CompleteStructuralCandidateEnumeration,
        outcomes: Vec<CandidateOutcome>,
        batch: DetailedCodeQueryResult,
    }

    impl ProvenSelectorClassification {
        pub(crate) fn batch_result_for_binding(&self) -> &DetailedCodeQueryResult {
            &self.batch
        }

        pub(crate) fn candidates(
            &self,
        ) -> impl Iterator<Item = (&StructuralCallCandidate, &CandidateOutcome)> {
            self.enumeration.candidates.iter().zip(&self.outcomes)
        }

        /// Complete binding rows are accessible only through their candidate
        /// outcome and enumeration proof, including selections absent in batch.
        pub(crate) fn selected_bindings(
            &self,
            candidate_index: usize,
        ) -> impl Iterator<Item = (&CodeQueryResultItem, &DetailedCodeQueryEvidence)> {
            let indices = match &self.outcomes[candidate_index] {
                CandidateOutcome::Selected { bindings, .. } => bindings.as_slice(),
                _ => &[],
            };
            indices.iter().map(move |&index| {
                let evidence = &self.batch.evidence[index];
                (&self.batch.result.results[evidence.result_index], evidence)
            })
        }

        /// Until family adoption, uncertainty remains whole-selector failure.
        pub(crate) fn into_conservative_result(
            self,
        ) -> Result<DetailedCodeQueryResult, PolicySelectorSessionError> {
            if self
                .outcomes
                .iter()
                .any(|outcome| matches!(outcome, CandidateOutcome::Undecided { .. }))
            {
                return Err(PolicySelectorSessionError::Incomplete {
                    completion: CodeQueryCompletion::Incomplete {
                        codes: vec![CodeQueryDiagnosticCode::SemanticProviderFailed],
                    },
                    detail: self
                        .candidates()
                        .filter_map(|(candidate, outcome)| {
                            if let CandidateOutcome::Undecided { reasons } = outcome {
                                Some(format!(
                                    "{}:{:?}: {reasons:?}",
                                    candidate.file, candidate.span
                                ))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                });
            }
            Ok(self.batch)
        }
    }

    pub(crate) fn global_stop(result: &DetailedCodeQueryResult) -> bool {
        result.result.truncated
            || result.work.semantic.budget_exhausted
            || matches!(
                result.result.completion(),
                CodeQueryCompletion::Cancelled | CodeQueryCompletion::Invalid { .. }
            )
            || result.result.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.incompleteness,
                    brokk_bifrost_rql::Incompleteness::Operational(_)
                ) || matches!(
                    diagnostic.code,
                    CodeQueryDiagnosticCode::CallShapeCoverageIncomplete
                        | CodeQueryDiagnosticCode::IdentityAxisUnsupported
                )
            })
    }

    fn whole_selector(
        result: &DetailedCodeQueryResult,
        detail: String,
    ) -> PolicySelectorSessionError {
        PolicySelectorSessionError::Incomplete {
            completion: if matches!(result.result.completion(), CodeQueryCompletion::Complete) {
                CodeQueryCompletion::Incomplete {
                    codes: vec![CodeQueryDiagnosticCode::SemanticProviderFailed],
                }
            } else {
                result.result.completion()
            },
            detail: format!("{detail}: {:?}", result.result.diagnostics),
        }
    }

    type CandidateLocations<'a> = HashMap<&'a ProjectFile, HashMap<&'a str, &'a ByteRange<usize>>>;
    type CandidateBindingIndex = HashMap<(ProjectFile, ByteRange<usize>), Vec<usize>>;

    pub(crate) fn candidate_locations(
        candidates: &[StructuralCallCandidate],
    ) -> CandidateLocations<'_> {
        let mut locations: CandidateLocations<'_> = HashMap::new();
        for candidate in candidates {
            assert!(
                locations
                    .entry(&candidate.file)
                    .or_default()
                    .insert(&candidate.ast_id, &candidate.span)
                    .is_none(),
                "enumerated candidate AST identities are unique per file"
            );
        }
        locations
    }

    pub(crate) fn selected_candidate_bindings(
        locations: &CandidateLocations<'_>,
        result: &DetailedCodeQueryResult,
    ) -> Result<CandidateBindingIndex, PolicySelectorSessionError> {
        let mut selected: CandidateBindingIndex = HashMap::new();
        for (index, evidence) in result.evidence.iter().enumerate() {
            let Some(item) = result.result.results.get(evidence.result_index) else {
                return Err(PolicySelectorSessionError::Unavailable(
                    "candidate evidence points outside result rows".into(),
                ));
            };
            if let CodeQueryResultValue::CallBinding { value } = &item.value {
                // Structural enumeration already published this content-scoped
                // AST identity. Join once-indexed identities; never hash/walk
                // file facts again for each argument row or isolated selection.
                let span = locations
                    .get(&evidence.file)
                    .and_then(|file| file.get(value.site_ast_id.as_str()))
                    .ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "binding AST identity {} in {} is absent from candidate inventory",
                            value.site_ast_id, evidence.file
                        ))
                    })?;
                selected
                    .entry((evidence.file.clone(), (*span).clone()))
                    .or_default()
                    .push(index);
            }
        }
        Ok(selected)
    }

    fn charge_binding_indices(
        session: &mut PolicySelectorSession<'_>,
        selected: &CandidateBindingIndex,
    ) -> Result<(), PolicySelectorSessionError> {
        // Cover the grouping buffers and the outcome/reconciliation copies.
        // These index vectors scale with binding rows, not candidate count.
        let bytes = selected.values().fold(0usize, |bytes, indices| {
            bytes.saturating_add(
                indices
                    .capacity()
                    .saturating_add(2 * indices.len())
                    .saturating_mul(std::mem::size_of::<usize>()),
            )
        });
        session
            .semantic_budget
            .admit(SemanticWork {
                owned_text_bytes: bytes,
                ..SemanticWork::default()
            })
            .map_err(|error| {
                semantic_budget_error(format!("candidate binding index retention: {error}"))
            })
    }

    type RejectedCandidateIndex<'a> = HashSet<(&'a ProjectFile, usize, usize)>;

    fn rejected_candidate_locations<'a>(
        session: &mut PolicySelectorSession<'_>,
        rejected: &'a [(ProjectFile, Range)],
    ) -> Result<RejectedCandidateIndex<'a>, PolicySelectorSessionError> {
        // Cover hash-table slots and control bytes before constructing the
        // request-local index. Borrow the receipt's files instead of cloning.
        session
            .semantic_budget
            .admit(SemanticWork {
                owned_text_bytes: rejected
                    .len()
                    .saturating_add(1)
                    .saturating_mul(2)
                    .saturating_mul(
                        std::mem::size_of::<(&ProjectFile, usize, usize)>()
                            + std::mem::size_of::<usize>(),
                    ),
                ..SemanticWork::default()
            })
            .map_err(|error| {
                semantic_budget_error(format!("candidate rejection index retention: {error}"))
            })?;
        if !session
            .semantic_execution_budget
            .charge_external_query_work(0, rejected.len())
        {
            return Err(semantic_budget_error(
                "candidate rejection indexing exhausted request traversal budget",
            ));
        }
        Ok(rejected
            .iter()
            .map(|(file, span)| (file, span.start_byte, span.end_byte))
            .collect())
    }

    pub(crate) fn outcome_for(
        candidate: &StructuralCallCandidate,
        selected: &CandidateBindingIndex,
        rejected: &RejectedCandidateIndex<'_>,
        reasons: Vec<brokk_bifrost_analysis::analyzer::QueryReadIncomplete>,
    ) -> CandidateOutcome {
        if !reasons.is_empty() {
            return CandidateOutcome::Undecided {
                reasons: reasons.into_iter().map(CandidateReason::Read).collect(),
            };
        }
        if let Some(bindings) = selected.get(&(candidate.file.clone(), candidate.span.clone())) {
            return CandidateOutcome::Selected {
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                bindings: bindings.clone(),
            };
        }
        if rejected.contains(&(&candidate.file, candidate.span.start, candidate.span.end)) {
            return CandidateOutcome::Rejected;
        }
        CandidateOutcome::Undecided {
            reasons: vec![CandidateReason::SilentDrop],
        }
    }

    #[cfg(test)]
    thread_local! {
        static FORCE_DISAGREEMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static FORCE_SETUP_GAP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static DROP_BATCH_SITE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
        static DROP_BATCH_ROW: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }

    #[cfg(test)]
    pub(crate) fn force_next_setup_gap() {
        FORCE_SETUP_GAP.set(true);
    }

    #[cfg(test)]
    pub(crate) fn drop_next_batch_site(ast_id: String) {
        DROP_BATCH_SITE.set(Some(ast_id));
    }

    #[cfg(test)]
    pub(crate) fn drop_next_batch_row(row_id: String) {
        DROP_BATCH_ROW.set(Some(row_id));
    }

    #[cfg(test)]
    fn inject_batch_drop(batch: &mut DetailedCodeQueryResult) {
        let ast_id = DROP_BATCH_SITE.take();
        let row_id = DROP_BATCH_ROW.take();
        if ast_id.is_none() && row_id.is_none() {
            return;
        }
        let mut remap = vec![None; batch.result.results.len()];
        let mut rows = Vec::new();
        for (index, row) in std::mem::take(&mut batch.result.results)
            .into_iter()
            .enumerate()
        {
            if matches!(&row.value, CodeQueryResultValue::CallBinding { value } if ast_id.as_deref() == Some(value.site_ast_id.as_str()) || row_id.as_deref() == Some(value.id.as_str()))
            {
                continue;
            }
            remap[index] = Some(rows.len());
            rows.push(row);
        }
        batch.result.results = rows;
        batch.evidence.retain_mut(|evidence| {
            if let Some(index) = remap[evidence.result_index] {
                evidence.result_index = index;
                true
            } else {
                false
            }
        });
    }

    fn reconcile(
        candidate: &StructuralCallCandidate,
        batch: &CandidateOutcome,
        isolated: CandidateOutcome,
    ) -> CandidateOutcome {
        let decided_disagreement = matches!(
            (batch, &isolated),
            (
                CandidateOutcome::Selected { .. },
                CandidateOutcome::Rejected
            ) | (
                CandidateOutcome::Rejected,
                CandidateOutcome::Selected { .. }
            )
        );
        #[cfg(test)]
        let decided_disagreement = decided_disagreement || FORCE_DISAGREEMENT.get();
        if decided_disagreement {
            CandidateOutcome::Undecided {
                reasons: vec![CandidateReason::Disagreement {
                    file: candidate.file.clone(),
                    span: candidate.span.clone(),
                }],
            }
        } else {
            isolated
        }
    }

    #[cfg(test)]
    #[test]
    fn isolated_decision_disagreement_names_the_candidate() {
        let root = std::env::current_dir().unwrap();
        let candidate = StructuralCallCandidate {
            file: ProjectFile::new(&root, "App.java"),
            span: 25..31,
            ast_id: "test:call".into(),
        };
        let selected = || CandidateOutcome::Selected {
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            bindings: Vec::new(),
        };
        let result = reconcile(&candidate, &selected(), CandidateOutcome::Rejected);
        assert!(
            matches!(result, CandidateOutcome::Undecided { reasons } if matches!(&reasons[..], [CandidateReason::Disagreement { file, span }] if *file == candidate.file && *span == candidate.span))
        );
        FORCE_DISAGREEMENT.set(true);
        let forced = reconcile(&candidate, &selected(), selected());
        FORCE_DISAGREEMENT.set(false);
        assert!(
            matches!(forced, CandidateOutcome::Undecided { reasons } if matches!(&reasons[..], [CandidateReason::Disagreement { .. }]))
        );
        assert!(matches!(
            reconcile(&candidate, &selected(), selected()),
            CandidateOutcome::Selected { .. }
        ));
    }

    impl CompleteStructuralCandidateEnumeration {
        /// Both proof objects are required before requesting split receipts.
        /// Execution shares the session workspace snapshot (#10979), budgets,
        /// cancellation and enclosing read ledger with ordinary selectors.
        pub(crate) fn execute(
            &self,
            session: &mut PolicySelectorSession<'_>,
            selector: &WhitelistedCallSelector,
            query: &CodeQuery,
            scope: CodeQueryExecutionScope<'_>,
        ) -> Result<
            (
                DetailedCodeQueryResult,
                brokk_bifrost_rql::structural::search::CallBindingReadReceipts,
            ),
            PolicySelectorSessionError,
        > {
            let request = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(
                session.workspace.analyzer(),
            );
            assert_eq!(
                self.session_id, session.session_id,
                "candidate proof belongs to this selector session"
            );
            assert_eq!(
                self.request_id,
                request.outer_request().id(),
                "candidate proof belongs to this request (#10979)"
            );
            let checked = WhitelistedCallSelector::check(query).expect("whitelisted selector");
            assert_eq!(checked.target_fqn, selector.target_fqn);
            assert_eq!(
                checked
                    .structural_query
                    .to_canonical_query_plan_json()
                    .to_string(),
                self.structural_plan
            );
            let receipts =
                brokk_bifrost_rql::structural::search::CallBindingReadReceipts::default();
            let scope = scope.with_call_binding_receipts(receipts.clone());
            let (detailed, semantic_receipt) = session.execute_selector_query_core(query, scope)?;
            session.charge_query_semantic_work(detailed.work.semantic, semantic_receipt)?;
            Ok((detailed, receipts))
        }

        /// Preserve batching, then pay for independent classification only
        /// when candidate-request reads were incomplete. Each new execution
        /// owns fresh binding, dispatch and prepared-source state; owned call
        /// anchors disable compilation-wide target memo reuse. It uses the
        /// same session workspace snapshot (#10979), ledger and budgets.
        #[cfg(test)]
        pub(crate) fn classify(
            self,
            session: &mut PolicySelectorSession<'_>,
            selector: &WhitelistedCallSelector,
            query: &CodeQuery,
        ) -> Result<ProvenSelectorClassification, PolicySelectorSessionError> {
            let scope = session.execution_scope.clone();
            self.classify_in_scope(session, selector, query, scope)
        }

        pub(crate) fn classify_in_scope(
            self,
            session: &mut PolicySelectorSession<'_>,
            selector: &WhitelistedCallSelector,
            query: &CodeQuery,
            scope: CodeQueryExecutionScope<'_>,
        ) -> Result<ProvenSelectorClassification, PolicySelectorSessionError> {
            // Keep the request-local result inventory under the existing
            // semantic resident byte allowance. Outcomes cannot be persisted
            // or reused independently of this proof.
            let retained = self
                .candidates
                .capacity()
                .saturating_mul(
                    std::mem::size_of::<StructuralCallCandidate>()
                        .saturating_add(2 * std::mem::size_of::<CandidateOutcome>())
                        .saturating_add(8 * std::mem::size_of::<(ProjectFile, ByteRange<usize>)>())
                        .saturating_add(2 * std::mem::size_of::<CandidateReason>()),
                )
                .saturating_add(self.structural_plan.capacity())
                .saturating_add(self.candidates.iter().fold(0usize, |bytes, candidate| {
                    bytes
                        .saturating_add(candidate.file.retained_bytes())
                        .saturating_add(candidate.ast_id.capacity())
                }));
            session
                .semantic_budget
                .admit(SemanticWork {
                    owned_text_bytes: retained,
                    ..SemanticWork::default()
                })
                .map_err(|error| {
                    semantic_budget_error(format!("candidate inventory retention: {error}"))
                })?;
            let (mut batch, receipts) = self.execute(session, selector, query, scope.clone())?;
            #[cfg(test)]
            inject_batch_drop(&mut batch);
            if global_stop(&batch) {
                return Err(whole_selector(
                    &batch,
                    "batch execution stopped globally".into(),
                ));
            }
            let Some((setup, union)) = receipts.take() else {
                if self.candidates.is_empty()
                    && matches!(batch.result.completion(), CodeQueryCompletion::Complete)
                {
                    return Ok(ProvenSelectorClassification {
                        enumeration: self,
                        outcomes: Vec::new(),
                        batch,
                    });
                }
                return Err(whole_selector(
                    &batch,
                    "call binding route supplied no split receipt".into(),
                ));
            };
            #[cfg(test)]
            let setup = if FORCE_SETUP_GAP.replace(false) {
                let (_, receipt) =
                    brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(
                        session.workspace.analyzer(),
                        || {
                            setup.replay(session.workspace.analyzer());
                            session.workspace.analyzer().record_query_incomplete(brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ArtifactUnavailable("test setup gap".into()));
                        },
                    );
                receipt
            } else {
                setup
            };
            if !setup.incomplete_reasons().is_empty() {
                return Err(whole_selector(
                    &batch,
                    format!(
                        "selector setup incomplete: {:?}",
                        setup.incomplete_reasons()
                    ),
                ));
            }
            if union
                .incomplete_reasons()
                .iter()
                .any(|reason| reason.is_execution_dependent())
            {
                return Err(whole_selector(
                    &batch,
                    format!(
                        "selector execution incomplete: {:?}",
                        union.incomplete_reasons()
                    ),
                ));
            }
            let rejected_receipts = receipts.take_rejected();
            let rejected = rejected_candidate_locations(session, &rejected_receipts)?;
            let locations = candidate_locations(&self.candidates);
            let selected = selected_candidate_bindings(&locations, &batch)?;
            charge_binding_indices(session, &selected)?;
            let batch_outcomes = self
                .candidates
                .iter()
                .map(|candidate| outcome_for(candidate, &selected, &rejected, Vec::new()))
                .collect::<Vec<_>>();
            if union.incomplete_reasons().is_empty() {
                if !matches!(batch.result.completion(), CodeQueryCompletion::Complete) {
                    return Err(whole_selector(
                        &batch,
                        "selector incomplete outside candidate requests".into(),
                    ));
                }
                return Ok(ProvenSelectorClassification {
                    enumeration: self,
                    outcomes: batch_outcomes,
                    batch,
                });
            }
            let mut ranges_by_file: HashMap<&ProjectFile, Vec<ByteRange<usize>>> = HashMap::new();
            for candidate in &self.candidates {
                ranges_by_file
                    .entry(&candidate.file)
                    .or_default()
                    .push(candidate.span.clone());
            }
            let anchor_bytes = ranges_by_file.iter().fold(0usize, |bytes, (file, ranges)| {
                bytes.saturating_add(
                    brokk_bifrost_rql::structural::search::OwnedCallAnchors::allocation_upper_bound(
                        file,
                        ranges.len(),
                    ),
                )
            });
            session
                .semantic_budget
                .admit(SemanticWork {
                    owned_text_bytes: anchor_bytes,
                    ..SemanticWork::default()
                })
                .map_err(|error| {
                    semantic_budget_error(format!("candidate anchor inventory retention: {error}"))
                })?;
            if !session
                .semantic_execution_budget
                .charge_external_query_work(0, self.candidates.len())
            {
                return Err(semantic_budget_error(
                    "candidate anchor inventory exhausted request traversal budget",
                ));
            }
            let anchor_inventories = ranges_by_file
                .into_iter()
                .map(|(file, ranges)| {
                    (
                        file,
                        brokk_bifrost_rql::structural::search::CallAnchorInventory::new(
                            file.clone(),
                            ranges,
                        ),
                    )
                })
                .collect::<HashMap<_, _>>();
            // Once isolation is needed, batch payloads are provisional. Keep
            // their decisions for disagreement checks, but replace every
            // Selected binding set with its complete isolated evidence. Reuse
            // the bounded output buffers instead of retaining duplicate rows.
            batch.result.results.clear();
            batch.evidence.clear();
            let mut outcomes = Vec::with_capacity(self.candidates.len());
            let mut isolation_work = batch.work;
            let mut isolation_budgeted_work = batch.budgeted_work.clone();
            for (candidate, batch_outcome) in self.candidates.iter().zip(&batch_outcomes) {
                let receipts =
                    brokk_bifrost_rql::structural::search::CallBindingReadReceipts::default();
                let anchors = std::sync::Arc::new(
                    anchor_inventories[&candidate.file].owned(vec![candidate.span.clone()]),
                );
                let scope = scope
                    .clone()
                    .restrict_seed_files(std::slice::from_ref(&candidate.file))
                    .with_owned_call_anchors(anchors)
                    .with_isolated_call_binding_receipts(receipts.clone());
                // These are executions of one logical selector, not new
                // selector entries with renewed structural allowances.
                let mut limits = session.remaining_query_limits()?;
                let remaining = |limit: usize, used: u64| {
                    limit.saturating_sub(usize::try_from(used).unwrap_or(usize::MAX))
                };
                limits.max_scanned_files = remaining(
                    limits.max_scanned_files,
                    isolation_work
                        .scanned_files
                        .max(isolation_budgeted_work.import_files_resolved),
                );
                limits.max_scanned_source_bytes = remaining(
                    limits.max_scanned_source_bytes,
                    isolation_work.scanned_source_bytes,
                );
                limits.max_fact_nodes = remaining(limits.max_fact_nodes, isolation_work.fact_nodes);
                limits.max_pipeline_rows = remaining(
                    limits.max_pipeline_rows,
                    isolation_work
                        .pipeline_rows
                        .max(isolation_budgeted_work.provenance_steps)
                        .max(isolation_budgeted_work.import_edges_resolved),
                );
                if [
                    limits.max_scanned_files,
                    limits.max_scanned_source_bytes,
                    limits.max_fact_nodes,
                    limits.max_pipeline_rows,
                ]
                .contains(&0)
                {
                    return Err(whole_selector(
                        &batch,
                        "candidate isolation exhausted selector structural allowance".into(),
                    ));
                }
                // Prefix/plan reads are outside classification. A reason there
                // is global even if this candidate's binding receipt is clean.
                let outside = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::capturing_read_incompleteness(session.workspace.analyzer());
                let (isolated, semantic_receipt) =
                    session.execute_selector_query_with_limits(query, scope, limits)?;
                let outside_reasons = outside.captured_read_incompleteness();
                drop(outside);
                if !outside_reasons.is_empty() {
                    return Err(whole_selector(
                        &isolated,
                        format!(
                            "reads outside candidate classification incomplete: {outside_reasons:?}"
                        ),
                    ));
                }
                isolation_work = isolation_work.saturating_add(isolated.work);
                isolation_budgeted_work =
                    isolation_budgeted_work.saturating_add(&isolated.budgeted_work);
                session.charge_query_semantic_work(isolated.work.semantic, semantic_receipt)?;
                if global_stop(&isolated) {
                    return Err(whole_selector(
                        &isolated,
                        "candidate isolation exhausted request execution".into(),
                    ));
                }
                if let Some((setup, _)) = receipts.take()
                    && !setup.incomplete_reasons().is_empty()
                {
                    return Err(whole_selector(
                        &isolated,
                        format!(
                            "isolated setup incomplete: {:?}",
                            setup.incomplete_reasons()
                        ),
                    ));
                }
                let Some(receipt) = receipts.take_isolated() else {
                    return Err(whole_selector(
                        &isolated,
                        "candidate isolation supplied no binding receipt".into(),
                    ));
                };
                if receipt
                    .incomplete_reasons()
                    .iter()
                    .any(|reason| reason.is_execution_dependent())
                {
                    return Err(whole_selector(
                        &isolated,
                        format!(
                            "candidate execution failed: {:?}",
                            receipt.incomplete_reasons()
                        ),
                    ));
                }
                let reason_bytes =
                    receipt
                        .incomplete_reasons()
                        .iter()
                        .fold(0usize, |bytes, reason| {
                            use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
                            let content = match reason {
                                QueryReadIncomplete::ArtifactUnavailable(detail)
                                | QueryReadIncomplete::SemanticEvidenceGap(detail)
                                | QueryReadIncomplete::SemanticEvidenceUnavailable(detail) => {
                                    detail.len()
                                }
                                QueryReadIncomplete::StructureUnavailable(file) => {
                                    file.retained_bytes()
                                }
                                QueryReadIncomplete::Cancelled
                                | QueryReadIncomplete::StoreFailure(_) => 0,
                            };
                            bytes
                                .saturating_add(std::mem::size_of::<CandidateReason>())
                                .saturating_add(content)
                        });
                session
                    .semantic_budget
                    .admit(SemanticWork {
                        owned_text_bytes: reason_bytes,
                        ..SemanticWork::default()
                    })
                    .map_err(|error| {
                        semantic_budget_error(format!("candidate reason retention: {error}"))
                    })?;
                let selected = selected_candidate_bindings(&locations, &isolated)?;
                charge_binding_indices(session, &selected)?;
                let rejected_receipts = receipts.take_rejected();
                let rejected = rejected_candidate_locations(session, &rejected_receipts)?;
                let mut isolated_outcome = outcome_for(
                    candidate,
                    &selected,
                    &rejected,
                    receipt.incomplete_reasons().to_vec(),
                );
                if !matches!(isolated.result.completion(), CodeQueryCompletion::Complete)
                    && !matches!(isolated_outcome, CandidateOutcome::Undecided { .. })
                {
                    isolated_outcome = CandidateOutcome::Undecided {
                        reasons: vec![CandidateReason::IncompleteQuery(
                            isolated.result.completion(),
                        )],
                    };
                }
                let mut outcome = reconcile(candidate, batch_outcome, isolated_outcome);
                if let CandidateOutcome::Selected { bindings, .. } = &mut outcome {
                    // Keep the complete isolated set even when some batch
                    // bindings survived. Evidence indices refer only to this
                    // rebuilt result, never to a provisional batch subset.
                    if batch
                        .result
                        .results
                        .len()
                        .saturating_add(isolated.result.results.len())
                        > query.limit
                    {
                        session.workspace.analyzer().mark_execution_dependent();
                        session.workspace.analyzer().record_budget_dependences(1);
                        return Err(PolicySelectorSessionError::Incomplete {
                            completion: CodeQueryCompletion::Incomplete {
                                codes: vec![CodeQueryDiagnosticCode::ResultLimitReached],
                            },
                            detail: "recovered bindings exceeded the selector result limit".into(),
                        });
                    }
                    let row_offset = batch.result.results.len();
                    let evidence_offset = batch.evidence.len();
                    batch.result.results.extend(isolated.result.results);
                    batch
                        .evidence
                        .extend(isolated.evidence.into_iter().map(|mut evidence| {
                            evidence.result_index += row_offset;
                            evidence
                        }));
                    for index in bindings {
                        *index += evidence_offset;
                    }
                }
                outcomes.push(outcome);
            }
            Ok(ProvenSelectorClassification {
                enumeration: self,
                outcomes,
                batch,
            })
        }

        pub(crate) fn candidates(&self) -> &[StructuralCallCandidate] {
            &self.candidates
        }

        #[cfg(test)]
        pub(crate) fn enumerate(
            session: &mut PolicySelectorSession<'_>,
            selector: &WhitelistedCallSelector,
        ) -> Result<Self, CandidateEnumerationRefusal> {
            let execution_scope = session.execution_scope.clone();
            Self::enumerate_in_scope(session, selector, execution_scope)
        }

        pub(crate) fn enumerate_in_scope(
            session: &mut PolicySelectorSession<'_>,
            selector: &WhitelistedCallSelector,
            execution_scope: CodeQueryExecutionScope<'_>,
        ) -> Result<Self, CandidateEnumerationRefusal> {
            let workspace = session.workspace;
            let scope =
                brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
            let (detailed, receipt) = session
                .execute_selector_query_core(&selector.structural_query, execution_scope)
                .map_err(CandidateEnumerationRefusal::Execution)?;
            session
                .charge_query_semantic_work(detailed.work.semantic, receipt)
                .map_err(CandidateEnumerationRefusal::Execution)?;
            scope
                .read_completion()
                .map_err(CandidateEnumerationRefusal::ReadIncomplete)?;
            if detailed.result.truncated {
                return Err(CandidateEnumerationRefusal::Truncated);
            }
            let completion = detailed.result.completion();
            if !matches!(completion, CodeQueryCompletion::Complete) {
                return Err(CandidateEnumerationRefusal::Incomplete(completion));
            }
            // The seed executor records index/store failures and skipped files
            // in completion. Require one exact structural location per result;
            // never silently filter out an unlocated row.
            let mut locations = vec![None; detailed.result.results.len()];
            for row in &detailed.evidence {
                let location = locations
                    .get_mut(row.result_index)
                    .ok_or(CandidateEnumerationRefusal::MissingLocation)?;
                if location.is_some()
                    || !matches!(row.domain, DetailedCodeQueryDomain::StructuralMatch)
                {
                    return Err(CandidateEnumerationRefusal::MissingLocation);
                }
                *location = Some(row);
            }
            let mut candidates = Vec::with_capacity(locations.len());
            for row in locations {
                let row = row.ok_or(CandidateEnumerationRefusal::MissingLocation)?;
                candidates.push(StructuralCallCandidate {
                    file: row.file.clone(),
                    span: row
                        .byte_span
                        .clone()
                        .ok_or(CandidateEnumerationRefusal::MissingLocation)?,
                    ast_id: match &detailed.result.results[row.result_index].value {
                        CodeQueryResultValue::StructuralMatch { value } => value
                            .ast_id
                            .clone()
                            .ok_or(CandidateEnumerationRefusal::MissingLocation)?,
                        _ => return Err(CandidateEnumerationRefusal::MissingLocation),
                    },
                });
            }
            candidates.sort_by(|a, b| {
                a.file
                    .rel_path()
                    .cmp(b.file.rel_path())
                    .then(a.span.start.cmp(&b.span.start))
                    .then(a.span.end.cmp(&b.span.end))
            });
            Ok(Self {
                candidates,
                structural_plan: selector
                    .structural_query
                    .to_canonical_query_plan_json()
                    .to_string(),
                session_id: session.session_id,
                request_id: scope.outer_request().id(),
            })
        }
    }
}

fn query_guarantees_declared_call_proof(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![(plan, false)];
    while let Some((plan, has_declared_proof)) = pending.pop() {
        let has_declared_proof = has_declared_proof
            || plan.steps.iter().any(|step| {
                matches!(
                    step,
                    QueryStep::ResolvedCall(filter)
                        if filter.proof == ResolvedCallProof::Declared
                )
            });
        match &plan.source {
            CodeQueryPlanSource::Set { branches, .. } => {
                pending.extend(branches.iter().map(|branch| (branch, has_declared_proof)));
            }
            _ if !has_declared_proof => return false,
            _ => {}
        }
    }
    true
}

fn query_guarantees_workspace_exact_call_proof(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![(plan, false)];
    while let Some((plan, has_workspace_exact_proof)) = pending.pop() {
        // A formal-annotation filter reads the formal from the declaration the
        // resolver selected, so a surviving row proves the same declared
        // target/formal relation an exact workspace `resolved-call` does.
        let has_workspace_exact_proof = has_workspace_exact_proof
            || plan.steps.iter().any(|step| {
                matches!(
                    step,
                    QueryStep::ResolvedCall(filter)
                        if filter.proof == ResolvedCallProof::Exact
                            && filter.resolves_to.is_resolved_workspace_declaration()
                ) || matches!(
                    step,
                    QueryStep::CallArgument(CallArgumentSelector::FormalAnnotationType(_))
                )
            });
        match &plan.source {
            CodeQueryPlanSource::Set { branches, .. } => {
                pending.extend(
                    branches
                        .iter()
                        .map(|branch| (branch, has_workspace_exact_proof)),
                );
            }
            _ if !has_workspace_exact_proof => return false,
            _ => {}
        }
    }
    true
}

// A receiver constraint adds a dispatch obligation even to a declared selector.
// Visit set branches structurally; an obligation on any branch is conservative.
fn query_requires_receiver_dispatch(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan.steps.iter().any(|step| {
            matches!(step, QueryStep::ResolvedCall(filter) if filter.receiver_type.is_some())
        }) {
            return true;
        }
        pending.extend(plan.source.child_plans());
    }
    false
}

// A resolved-call predicate validates each surviving binding independently of
// other sites' diagnostics. Carry that proof through incomplete projections;
// it proves the declared target/formal relation, not runtime dispatch.
fn query_call_binding_proof(plan: &CodeQueryPlan) -> Option<&'static str> {
    if query_guarantees_declared_call_proof(plan) {
        Some("declared")
    } else if query_guarantees_workspace_exact_call_proof(plan) {
        Some("resolved_workspace")
    } else {
        None
    }
}

fn admits_existing_incomplete_call_bindings(
    result: &CodeQueryResult,
    declared_call: bool,
    workspace_exact_call: bool,
) -> bool {
    let declared_call_complete = declared_call
        && !result.truncated
        && !result.diagnostics.is_empty()
        && result.diagnostics.iter().all(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::CallBindingDispatchPartial
        });
    let workspace_exact_positive = workspace_exact_call
        && !result.results.is_empty()
        && !result.truncated
        && !result.diagnostics.is_empty()
        && result.diagnostics.iter().all(|diagnostic| {
            matches!(
                diagnostic.code,
                CodeQueryDiagnosticCode::CallBindingDispatchPartial
                    | CodeQueryDiagnosticCode::SemanticAnalysisPartial
            )
        });
    declared_call_complete || workspace_exact_positive
}

impl From<DetailedCodeQueryDecoratedParameterEvidence> for PolicyDecoratedParameterSelection {
    fn from(value: DetailedCodeQueryDecoratedParameterEvidence) -> Self {
        Self {
            value_locator: value.value_locator,
            port: value.port,
        }
    }
}

#[derive(Clone)]
pub(super) struct PolicyResultContractSelection {
    pub(super) result_ordinal: u32,
    pub(super) fresh_allocation: bool,
    pub(super) success_guard_coverage: EffectCoverage,
    pub(super) success_guard_edges:
        Vec<brokk_bifrost_analysis::analyzer::semantic::ControlEdgeLocator>,
    pub(super) possible_success_guard_edges:
        Vec<brokk_bifrost_analysis::analyzer::semantic::ControlEdgeLocator>,
    pub(super) member_contracts:
        Vec<brokk_bifrost_analysis::analyzer::semantic_model::CompiledResultMemberContract>,
}

#[derive(Clone)]
pub(super) struct PolicyCallShapeSelection {
    pub(super) callee_name: Option<String>,
    pub(super) argument_count: u32,
}

/// Whether a receiver-bound endpoint applies to one selected source call.
///
/// A structural selector can name syntax such as Go `package.Name(...)` that
/// looks like member access while local callable evidence or exact dispatch
/// proves it is a package function. `ExactNonMatch` is reserved for those
/// proven cases. An absent caller-side receiver without complete evidence
/// stays `Indeterminate`, so the policy compiler preserves its existing
/// fail-closed diagnostic rather than treating missing semantic support as a
/// clean miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiverBindingApplicability {
    Applicable,
    /// The lowered call has one consistent caller-side receiver, but dispatch
    /// cannot yet prove whether it is a method or a function-valued field.
    /// Consumers may inspect that structured receiver as partial evidence;
    /// they must not turn a possible match into a definite finding.
    CandidateReceiver,
    ExactNonMatch,
    Indeterminate,
    Inconsistent,
}

struct PolicySelectorQueryResult {
    result: CodeQueryResult,
    evidence: Vec<DetailedCodeQueryEvidence>,
    artifact_charge: Option<SemanticArtifactLeaseCharge>,
    retained_incomplete_result_contracts: bool,
    retained_incomplete_taint_rows: bool,
}

/// Admit a positive result-contract subset when only its guard/use derivation
/// is incomplete.
///
/// The typed contract row independently proves result identity and reviewed
/// member metadata. A converted condition result can therefore make that row
/// partial without erasing it. This exception remains deliberately narrow:
/// terminal rows, non-exhaustive dispatch, unproven rows, truncation, any other
/// incomplete diagnostic, cancellation, and invalid queries still fail closed.
/// Declared-non-exhaustive diagnostics may coexist with these exact positive
/// rows: they open the run but do not invalidate evidence already proven.
fn retains_independently_proven_result_contracts(
    result: &CodeQueryResult,
    evidence: &[DetailedCodeQueryEvidence],
) -> bool {
    let CodeQueryCompletion::Incomplete { codes } = result.completion() else {
        return false;
    };
    if result.truncated
        || codes.is_empty()
        || codes
            .iter()
            .any(|code| *code != CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        || result
            .diagnostics
            .iter()
            .any(|diagnostic| match diagnostic.impact {
                CodeQueryDiagnosticImpact::Advisory
                | CodeQueryDiagnosticImpact::DeclaredNonExhaustive => false,
                CodeQueryDiagnosticImpact::Incomplete => {
                    diagnostic.code != CodeQueryDiagnosticCode::ResultContractDerivationIncomplete
                }
                CodeQueryDiagnosticImpact::Invalid => true,
            })
    {
        return false;
    }

    let mut retained = false;
    for evidence in evidence
        .iter()
        .filter(|evidence| !matches!(evidence.domain, DetailedCodeQueryDomain::File))
    {
        let Some(item) = result.results.get(evidence.result_index) else {
            return false;
        };
        match &item.value {
            CodeQueryResultValue::CallResultContract { value }
                if !value.terminal
                    && value.result_ordinal.is_some()
                    && value.proof == Some("proven")
                    && value.coverage == "exhaustive" =>
            {
                retained = true;
            }
            _ => return false,
        }
    }
    retained
}

/// A taint endpoint row is useful only when the query retained a located
/// structural or semantic site. An open dispatch may still have a concrete
/// call-binding row. A terminal binding row is also a usable call site when it
/// proves an exhaustively empty actual-to-formal partition: a zero-argument
/// source still binds the call's normal return value, even though it has no
/// argument row to emit.
fn usable_taint_row(
    item: &CodeQueryResultItem,
    evidence: &DetailedCodeQueryEvidence,
    query_binding_proof: Option<&str>,
) -> bool {
    if evidence.byte_span.is_none() || matches!(evidence.domain, DetailedCodeQueryDomain::File) {
        return false;
    }
    match &item.value {
        CodeQueryResultValue::CallBinding { value } => {
            let located_source_binding = incomplete_source_call_binding(value);
            let exact_site = value.formal_layout_id.is_some()
                && value.selector_proof.or(query_binding_proof).is_some()
                && (value.semantic_target_id.is_some()
                    || value.model_callable_id.is_some()
                    // A resolver-owned external call can have no materialized
                    // dispatch target or callable id. Its declared selector
                    // proof is the exact target identity for a terminal
                    // zero-argument partition.
                    || (value.selector_exact && value.terminal));
            if value.terminal {
                value.mapping == "exact"
                    && value.coverage == "exhaustive"
                    && value.actual_count == 0
                    && exact_site
            } else if value.binding_kind == Some("receiver") {
                // A receiver row binds the call's receiver operand, which has
                // no argument identity. The same site proof identifies it, and
                // it is the only row of a zero-argument call (#10014).
                value.argument_id.is_none()
                    && value.mapping == "exact"
                    && (exact_site || located_source_binding)
            } else {
                value.argument_id.is_some()
                    && value.actual_index.is_some()
                    && value.formal_index.is_some()
                    && value.formal_layout_id.is_some()
                    && (exact_site || located_source_binding)
            }
        }
        CodeQueryResultValue::DecoratedParameter { value } => {
            value.completion == "complete"
                && value.coverage == "complete"
                && value.parameter_ordinal.is_some()
                && value.procedure_id.is_some()
                && value.value_id.is_some()
                && value.port_id.is_some()
                && evidence.decorated_parameter.is_some()
        }
        CodeQueryResultValue::RuntimeKeyedReadValue { value } => {
            !value.terminal && evidence.runtime_keyed_read.is_some()
        }
        // A located name or shape match alone cannot identify the selected
        // semantic endpoint when the query as a whole is incomplete.
        _ => false,
    }
}

fn incomplete_source_call_binding(value: &CodeQueryCallBinding) -> bool {
    value.target.is_some()
        && value.declared_target_id.is_some()
        && value.target_origin == Some("source")
        && value.coverage == "incomplete"
        && value.dispatch_outcome == "resolved"
        && value.dispatch_coverage == "exhaustive"
        && value.dispatch_target_count == 1
        && !value.dispatch_targets_truncated
        && value.mapping == "exact"
        && value.actual_count == value.bound_count
}

fn retains_usable_taint_rows(
    result: &CodeQueryResult,
    evidence: &[DetailedCodeQueryEvidence],
    query_binding_proof: Option<&str>,
) -> bool {
    matches!(
        result.completion(),
        CodeQueryCompletion::Incomplete { .. } | CodeQueryCompletion::ProvenSubset { .. }
    ) && evidence.iter().any(|row| {
        result
            .results
            .get(row.result_index)
            .is_some_and(|item| usable_taint_row(item, row, query_binding_proof))
    })
}

pub(super) type PolicyArtifactLeases = SemanticArtifactLeaseSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PolicySemanticPeaks {
    pub(super) row_dimension: usize,
    pub(super) retained_bytes: usize,
    pub(super) traversal_steps: usize,
}

impl PolicySemanticPeaks {
    /// Extend one compile-time semantic region through a child evaluation.
    ///
    /// The child scalar ledger starts at zero with the parent's remaining
    /// allowance, so its row and owned-text work are incremental and must be
    /// added to the compile work exactly once. The lease child already
    /// contains the compile-time base allocations, while the execution budget
    /// is the same shared ledger used during compilation; those two cumulative
    /// quantities must therefore be compared with the compile peak, not added
    /// to it.
    pub(super) fn with_child_evaluation(
        self,
        compile_work: SemanticWork,
        evaluation_work: SemanticWork,
        evaluation_retained_peak: usize,
        cumulative_traversal_steps: usize,
    ) -> Self {
        let total_work = compile_work
            .checked_add(evaluation_work)
            .expect("a bounded semantic child fits its parent's original limits");
        let row_dimension = CodeQuerySemanticRowLimits::ROW_DIMENSIONS
            .into_iter()
            .map(|dimension| total_work.get(dimension))
            .max()
            .unwrap_or(0);
        Self {
            row_dimension: self.row_dimension.max(row_dimension),
            retained_bytes: self
                .retained_bytes
                .max(total_work.owned_text_bytes)
                .max(evaluation_retained_peak),
            traversal_steps: self.traversal_steps.max(cumulative_traversal_steps),
        }
    }
}

pub(super) struct PolicySemanticLeaseWindow {
    child: SemanticArtifactLeaseChild,
    window: SemanticArtifactLeaseWindow,
}

impl PolicySemanticLeaseWindow {
    fn new(leases: &SemanticArtifactLeaseSet) -> Self {
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        Self { child, window }
    }

    pub(super) fn collector(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::semantic::SemanticArtifactCollector {
        self.window.collector()
    }

    fn overflow(&self) -> Option<SemanticArtifactLeaseError> {
        self.window.overflow()
    }

    pub(super) fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        self.window.contains_exact(artifact)
    }

    fn into_charge(self) -> Result<SemanticArtifactLeaseCharge, SemanticArtifactLeaseError> {
        let Self { mut child, window } = self;
        window.commit(&mut child)?;
        Ok(child.into_charge())
    }

    pub(super) fn discard(self) {
        let Self { child, window } = self;
        window.discard();
        drop(child);
    }

    pub(super) fn finish_scalar<R>(
        self,
        value: R,
        operation: &str,
    ) -> Result<R, PolicySelectorSessionError> {
        let error = self.overflow();
        self.discard();
        if let Some(error) = error {
            return Err(semantic_budget_error(format!(
                "{operation} exhausted the shared semantic retained-artifact budget: {error}"
            )));
        }
        Ok(value)
    }
}

pub(super) struct PolicySemanticContinuation<T> {
    // Keep the outcome first so ordinary field drop releases every handle
    // before the bounded lease window is discarded.
    outcome: SemanticOutcome<T>,
    leases: PolicySemanticLeaseWindow,
}

impl<T> PolicySemanticContinuation<T> {
    pub(super) fn outcome(&self) -> &SemanticOutcome<T> {
        &self.outcome
    }

    pub(super) fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        self.leases.contains_exact(artifact)
    }

    pub(super) fn commit(
        self,
        session: &mut PolicySelectorSession<'_>,
        operation: &str,
    ) -> Result<SemanticOutcome<T>, PolicySelectorSessionError> {
        let Self { outcome, leases } = self;
        session.apply_artifact_charge(leases.into_charge(), operation)?;
        Ok(outcome)
    }

    pub(super) fn finish_scalar<R>(
        self,
        value: R,
        operation: &str,
    ) -> Result<R, PolicySelectorSessionError> {
        let Self { outcome, leases } = self;
        drop(outcome);
        leases.finish_scalar(value, operation)
    }
}

/// Structured relational identity retained from one selected `call_binding` row.
///
/// `actual_index` is the caller-side operand ordinal. `formal_index` is kept
/// only as evidence and must never be passed to a `PolicyPort::ArgumentIndex`.
#[derive(Clone)]
pub(super) struct PolicySelectedCallBinding {
    pub(super) row_id: String,
    pub(super) site_id: String,
    pub(super) site_ast_id: String,
    pub(super) argument_id: String,
    pub(super) call_span: ByteRange<usize>,
    pub(super) actual_index: usize,
    pub(super) formal_index: usize,
    pub(super) formal_name: Option<String>,
    pub(super) semantic_target_id: Option<String>,
    pub(super) model_callable_id: Option<String>,
    pub(super) formal_layout_id: String,
    pub(super) signature_id: Option<String>,
    pub(super) model_id: Option<String>,
    pub(super) pack_id: Option<String>,
    pub(super) selector_proof: &'static str,
    pub(super) requires_receiver_dispatch: bool,
    /// Whether the row has an exact selector proof or only a retained source
    /// candidate under incomplete selected-native resolution.
    pub(super) selector_provenance: &'static str,
    pub(super) selector_summary_id: Option<String>,
    pub(super) selector_summary_model_id: Option<String>,
    pub(super) selector_summary_pack_id: Option<String>,
    pub(super) selector_summary_pack_digest: Option<String>,
}

fn accepted_model_record(
    selector_exact: bool,
    target_present: bool,
    unique_external_layout: bool,
    target_origin: Option<&str>,
    model_ambiguous: bool,
    pack_digest: Option<&str>,
    record_id: Option<&str>,
) -> Option<(String, String)> {
    if !selector_exact
        || !(target_present || unique_external_layout)
        || target_origin != Some("semantic_model")
        || model_ambiguous
    {
        return None;
    }
    Some((pack_digest?.to_owned(), record_id?.to_owned()))
}

/// The authored summary a call binding's exact selector rests on, as (pack
/// digest, record ID). The target's origin plays no part: a model declaration
/// and a workspace source target both depend on the summary that closed their
/// override boundary. A query whose own filter proves the binding does not.
fn accepted_summary_record(
    query_proves_binding: bool,
    selector_exact: bool,
    selector_proof: Option<&str>,
    pack_digest: Option<&str>,
    record_id: Option<&str>,
) -> Option<(String, String)> {
    if query_proves_binding || !selector_exact || selector_proof != Some("authored_summary") {
        return None;
    }
    Some((pack_digest?.to_owned(), record_id?.to_owned()))
}

impl PolicySelectedCallBinding {
    pub(super) fn requires_dispatch(&self) -> bool {
        self.requires_receiver_dispatch
            || matches!(
                self.selector_proof,
                "resolved_workspace" | "authored_summary"
            )
    }

    pub(super) fn assert_valid_identity(&self) {
        debug_assert!(!self.row_id.is_empty());
        debug_assert!(!self.site_id.is_empty());
        debug_assert!(!self.site_ast_id.is_empty());
        debug_assert!(!self.argument_id.is_empty());
        debug_assert!(
            self.semantic_target_id
                .as_ref()
                .is_none_or(|identity| !identity.is_empty())
        );
        debug_assert!(
            self.model_callable_id
                .as_ref()
                .is_none_or(|identity| !identity.is_empty())
        );
        debug_assert!(!self.formal_layout_id.is_empty());
        debug_assert!(self.signature_id.as_ref().is_none_or(|id| !id.is_empty()));
        debug_assert!(self.model_id.as_ref().is_none_or(|id| !id.is_empty()));
        debug_assert!(self.pack_id.as_ref().is_none_or(|pack| !pack.is_empty()));
        debug_assert!(matches!(
            self.selector_provenance,
            "declared"
                | "derived"
                | "authored_summary"
                | "resolved_workspace"
                | "incomplete_source_candidate"
        ));
        debug_assert!(
            self.selector_provenance != "declared"
                || (self.signature_id.is_some() && self.model_id.is_some())
        );
        debug_assert_eq!(
            self.selector_provenance == "authored_summary",
            self.selector_summary_id.is_some()
                && self.selector_summary_model_id.is_some()
                && self.selector_summary_pack_id.is_some()
                && self.selector_summary_pack_digest.is_some()
        );
        debug_assert!(matches!(
            self.selector_proof,
            "declared" | "derived" | "authored_summary" | "resolved_workspace"
        ));
    }
}

/// A taint endpoint selector whose discovery did not finish. The path says
/// which endpoint role the gap belongs to, so the compiler can tell a gap
/// that could hide a flow from one that cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IncompleteTaintSelector {
    pub(super) path: crate::definition::PolicySelectorPath,
    pub(super) message: String,
    /// The code and source site of each query diagnostic that left discovery
    /// open, in the order the query reported them. Empty for a selector that
    /// could not be applied at all.
    pub(super) discovery: Vec<(CodeQueryDiagnosticCode, Option<DiscoverySite>)>,
    /// The query stopped at a result cap. A cap leaves rows missing for a
    /// reason of the execution, even when its own limit diagnostic was
    /// suppressed because another incomplete diagnostic already exists.
    pub(super) truncated: bool,
}

/// Metrics-only details of one incomplete selector. Never used for deduplication.
pub(super) struct IncompleteSelectorObservation {
    pub(super) original_completion: Option<CodeQueryCompletion>,
    pub(super) original_locator_refusal_code: Option<&'static str>,
    pub(super) attributed_file: Option<String>,
}

/// A workspace-relative path and, when the diagnostic named an exact site, its
/// one-based line.
pub(super) type DiscoverySite = (String, Option<usize>);

struct MaterializedArtifact {
    artifact: Arc<SemanticArtifact>,
    reads: Option<Arc<ReadLedger>>,
    complete_key: Option<SemanticArtifactKey>,
}

pub(super) struct PolicySelectorSession<'a> {
    session_id: u64,
    #[cfg(all(test, feature = "test-support"))]
    binding_candidate_probe: brokk_bifrost_rql::structural::search::CallBindingCandidateProbe,
    workspace: &'a WorkspaceAnalyzer,
    flow_state: brokk_bifrost_rql::SemanticFlowResources,
    analysis: &'static str,
    query_limits: CodeQueryExecutionLimits,
    root_allotment: brokk_bifrost_rql::CodeQueryRootAllotment,
    max_selector_results: usize,
    cancellation: &'a CancellationToken,
    /// Which files every selector this session runs enumerates seeds over.
    ///
    /// The whole analyzed file set by default, which is byte for byte what
    /// every selector did before units existed. A caller compiling one
    /// selector unit per seed file narrows it, and only the seed enumeration
    /// narrows: callers, importers, descendants, dispatch and references still
    /// answer over the whole workspace, because those answers are what make a
    /// finding in an unedited file change.
    execution_scope: CodeQueryExecutionScope<'a>,
    /// Exact Rust call-target outcomes shared by selector scans in this
    /// compilation. The cache is bounded by the files and call sites the
    /// compilation actually queries and is dropped with the session.
    call_target_outcomes: Option<CallTargetOutcomeCache>,
    /// The per-seed selector units this compile may reuse, when it holds an
    /// incremental context. Absent for a compile that has nothing to reuse and
    /// for every family that does not unitize its selectors, which then run
    /// byte for byte as they always have.
    units: Option<SelectorUnits<'a>>,
    semantic_budget: SemanticBudget,
    semantic_execution_budget: SemanticExecutionBudget,
    query_work: CodeQueryExecutionWork,
    artifacts: HashMap<ProjectFile, MaterializedArtifact>,
    // A refusal in an earlier region must survive its budget counter reset.
    semantic_stop_seen: bool,
    artifact_leases: PolicyArtifactLeases,
    materialized_files_limit: usize,
    // Semantic work retired by prior regions. `reset_region_semantic_budget`
    // replaces the live budgets, so their `used`/`work` counters only reflect
    // the current region; without this the reported work would collapse to the
    // last region's consumption. Accumulating the consumed counters here keeps
    // the compile-wide work report accurate. The materialization cache charges
    // each distinct file once, in whichever region first pulls it, so summing
    // per-region charges still totals distinct materializations, not duplicates.
    retired_program_points: usize,
    retired_source_bytes: usize,
    retired_semantic: SemanticWork,
    retired_materialized_files: usize,
    retired_traversal_steps: usize,
    // The largest single-region charge each per-region lane saw.  The lane
    // limits are per region -- `reset_region_semantic_budget` restores them --
    // so the quantity a lane must exceed for the compile to finish is the peak
    // one region reaches, not the sum the retired counters above accumulate.
    // These are the calibration inputs the derived-lane model never had (#1936).
    peak_row_dimension: usize,
    resident_peak: SemanticWork,
    root_work_peak: SemanticWork,
    work_peak_row_dimension: usize,
    work_peak_retained_bytes: usize,
    peak_retained_bytes: usize,
    peak_traversal_steps: usize,
    live_selector_retained_peak: usize,
    // How many procedure value-flow snapshots this compile actually built
    // through the semantic oracle, as opposed to reusing from the per-compile
    // materialization cache (#2284). The per-region budget resets above hide
    // this in the program-point total, and the program-point total also mixes
    // in dispatch, binding, and solve work, so a repeated materialization is
    // not visible there. This counter is: it must equal the number of distinct
    // procedures the compile reached, whatever their snapshots' completeness.
    semantic_snapshot_materializations: u64,
    // How many procedure visits this compile served on a handle that named a
    // second materialization of an artifact it had already seen (#2289). Keyed
    // on handles, each of those visits missed the discovery cache and re-ran
    // the oracle for the procedure's snapshot, each of its call sites'
    // dispatch, and each candidate's bindings; keyed durably they are hits. A
    // non-zero value here means the byte-bounded artifact cache is evicting
    // files this compile is still walking, which is worth knowing on its own.
    semantic_handle_identity_reuses: u64,
    // How many selector entries this compile scanned.  Each scan is granted the
    // whole-workspace scan allowance (see `remaining_query_limits`), so this is
    // the multiplier on that allowance the compile actually spent.
    selector_scans: u64,
    // Exact allocations first admitted from result-contract query receipts.
    // Later direct materialization can retain the same allocation, so keeping
    // this boundary-specific count makes immediate receipt adoption auditable.
    result_contract_artifact_leases: usize,
    // Result-contract selectors whose exact positive rows were retained while
    // guard/use projection remained incomplete. Typestate carries this query-
    // level fact into its final completion even when no row can seed a subject.
    retained_incomplete_result_contract_selectors: usize,
    incomplete_taint_selectors: Vec<IncompleteTaintSelector>,
    incomplete_selector_observations: Vec<IncompleteSelectorObservation>,
    /// Complete identity-only occurrence and environment rows shared across
    /// selectors in this policy compilation. The session is dropped with the
    /// compiler and keys every product by the workspace snapshot, role set
    /// and derivation options.
    row_family_session: CodeQueryRowFamilySession,
}

impl<'a> PolicySelectorSession<'a> {
    /// `execution_scope` is which files every selector of this session
    /// enumerates seeds over. A per-seed selector unit passes its one seed
    /// file; everything else passes
    /// [`CodeQueryExecutionScope::whole_workspace`] and executes byte for byte
    /// as it always has.
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
        analysis: &'static str,
        query_limits: CodeQueryExecutionLimits,
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
        execution_scope: CodeQueryExecutionScope<'a>,
    ) -> Self {
        static NEXT_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let session_id = NEXT_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_ne!(session_id, 0, "selector session identity exhausted");
        let flow_state = flow_state.into();
        // Size the materialized-file budget to the workspace, not the fixed
        // per-query IDE cap. That cap bounds how much a single interactive query
        // loads; a policy compile is a whole-workspace analysis that must reach
        // every source and sink, so on a corpus larger than the cap the endpoint
        // enumeration exhausts it before discovery even begins and the whole
        // compile abstains (#1936). The content-keyed materialization cache makes
        // the real cost proportional to distinct files, which cannot exceed the
        // project file count, so this is a principled bound rather than an
        // uncapped one. `max` keeps the per-query default as the floor, so a
        // small workspace is unaffected. The per-region traversal budget, reset
        // in `reset_region_semantic_budget`, still bounds each region's work.
        let materialized_files_limit = query_limits
            .semantic
            .max_materialized_files
            .max(workspace.project_file_count());
        let call_target_outcomes =
            CallTargetOutcomeCache::for_policy_compilation(workspace.analyzer());
        Self {
            #[cfg(all(test, feature = "test-support"))]
            binding_candidate_probe: Default::default(),
            workspace,
            session_id,
            flow_state: flow_state.clone(),
            analysis,
            query_limits,
            root_allotment: brokk_bifrost_rql::CodeQueryRootAllotment::from_execution_limits(
                &query_limits,
            ),
            max_selector_results,
            cancellation,
            execution_scope: execution_scope.with_depth_bound_status(false),
            call_target_outcomes,
            units: None,
            semantic_budget: SemanticBudget::new(semantic_resident_limits(query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive"),
            semantic_execution_budget: SemanticExecutionBudget::new(materialized_files_limit),
            query_work: CodeQueryExecutionWork::default(),
            artifacts: HashMap::new(),
            semantic_stop_seen: false,
            artifact_leases: SemanticArtifactLeaseSet::new(
                query_limits.semantic.max_retained_bytes,
            ),
            materialized_files_limit,
            retired_program_points: 0,
            retired_source_bytes: 0,
            retired_semantic: SemanticWork::default(),
            retired_materialized_files: 0,
            retired_traversal_steps: 0,
            peak_row_dimension: 0,
            resident_peak: SemanticWork::default(),
            root_work_peak: SemanticWork::default(),
            work_peak_row_dimension: 0,
            work_peak_retained_bytes: 0,
            peak_retained_bytes: 0,
            peak_traversal_steps: 0,
            live_selector_retained_peak: 0,
            semantic_snapshot_materializations: 0,
            semantic_handle_identity_reuses: 0,
            selector_scans: 0,
            result_contract_artifact_leases: 0,
            retained_incomplete_result_contract_selectors: 0,
            incomplete_taint_selectors: Vec::new(),
            incomplete_selector_observations: Vec::new(),
            row_family_session: CodeQueryRowFamilySession::default(),
        }
    }

    /// Record how many procedure value-flow snapshots discovery built through
    /// the oracle rather than reusing cached outcomes (#2284, #2951).
    pub(super) fn record_semantic_snapshot_materializations(&mut self, count: u64) {
        self.semantic_snapshot_materializations = self
            .semantic_snapshot_materializations
            .saturating_add(count);
    }

    /// Record how many procedure visits this compile served on a handle from a
    /// second materialization of one artifact (#2289).
    pub(super) fn record_semantic_handle_identity_reuses(&mut self, reuses: u64) {
        self.semantic_handle_identity_reuses =
            self.semantic_handle_identity_reuses.saturating_add(reuses);
    }

    /// Reset the semantic and execution budgets to their per-region starting
    /// limits.
    ///
    /// Require-model taint discovers and solves each source-to-sink region
    /// independently (#1935). Charging every region against one shared budget
    /// makes an N-file corpus abstain by accumulation, even though each region's
    /// own materialization is small: at corpus scale the shared `nested_entries`
    /// lane crosses its cap after ~76 files and the whole compile aborts.
    /// Resetting per region bounds each region on its own and lets independent
    /// flows all be analyzed. The shared materialization caches (the `#1936`
    /// discovery cache and the semantic artifact cache) are untouched, so
    /// cross-region work stays amortized and each region's budget only accounts
    /// for the material it newly pulls.
    pub(super) fn reset_region_semantic_budget(&mut self) {
        self.semantic_stop_seen |= self.semantic_budget.first_refusal().is_some()
            || self.semantic_execution_budget.work().exhausted;
        // Retire the finishing region's consumed work before the counters are
        // discarded, so the compile-wide work report stays a running total.
        let used = self.semantic_budget.used();
        self.retired_semantic = self.retired_semantic.conservative_add(used);
        self.retired_program_points = self
            .retired_program_points
            .saturating_add(used.program_points);
        // The legacy source-byte lane reports performed reads and parses, not
        // the resident holds a later region re-admits (see #5920).
        self.retired_source_bytes = self
            .retired_source_bytes
            .saturating_add(self.semantic_budget.performed().source_bytes);
        let execution = self.semantic_execution_budget.work();
        self.retired_materialized_files = self
            .retired_materialized_files
            .saturating_add(execution.materialized_files);
        self.retired_traversal_steps = self
            .retired_traversal_steps
            .saturating_add(execution.traversal_steps);
        let (row_work_peak, retained_work_peak, _) = self.region_peaks(used);
        self.work_peak_row_dimension = self.work_peak_row_dimension.max(row_work_peak);
        self.work_peak_retained_bytes = self.work_peak_retained_bytes.max(retained_work_peak);
        let (row_peak, retained_peak, traversal_peak) = self.live_region_peaks();
        self.peak_row_dimension = self.peak_row_dimension.max(row_peak);
        self.root_work_peak = self
            .root_work_peak
            .component_max(self.semantic_budget.root_work_peak());
        self.resident_peak = self
            .resident_peak
            .component_max(self.semantic_budget.resident_peak());
        self.peak_retained_bytes = self.peak_retained_bytes.max(retained_peak);
        self.peak_traversal_steps = self.peak_traversal_steps.max(traversal_peak);

        // The region's scalar limits reset, but the artifact censuses this
        // compile already paid stay paid: a shared artifact is charged once per
        // compile, and a later region pays only the repeat lookup.
        let census = self.semantic_budget.scope_snapshot();
        self.semantic_budget = SemanticBudget::new_child(
            semantic_resident_limits(self.query_limits.semantic),
            &census,
        );
        self.semantic_execution_budget =
            SemanticExecutionBudget::new(self.materialized_files_limit);
        self.live_selector_retained_peak = 0;
    }

    /// The source spans of the actuals one selector's call sites pass to the
    /// formal named `name`, through the analyzer's own actual-to-formal
    /// relation (`call-input :parameter-name`, issue #2438).
    ///
    /// This is the second of the two sources a formal-name port reads. The
    /// dispatch-aware oracle relation is the first and the authoritative one,
    /// but the semantic call row records only that an actual is a keyword
    /// argument, never which keyword, so the oracle retains no mapping for
    /// `put(value=x)`. The structural relation reads the label from the call's
    /// own syntax and is exactly what `(call-input :parameter-name "value")`
    /// publishes, so a port and a query row cannot disagree about which operand
    /// the formal names.
    ///
    /// The result is a flat span list per file, not a per-call map, because a
    /// row's evidence carries only its own byte span. The caller intersects it
    /// with one selected call's own operand spans, which is what distinguishes
    /// a nested call's actual from the enclosing call's.
    pub(super) fn select_named_actuals(
        &mut self,
        selector: &ResolvedPolicySelector,
        name: &str,
    ) -> Result<Vec<(ProjectFile, ByteRange<usize>)>, PolicySelectorSessionError> {
        let Some((_, query)) = selector.as_query() else {
            return Err(PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` is relational; its exact call-binding row must supply the actual directly",
                selector.path
            )));
        };
        let mut query = query.clone();
        query.limit = self.max_selector_results;
        query
            .plan
            .steps
            .push(QueryStep::CallInput(CallInputSelector::ParameterName(
                name.to_owned(),
            )));
        // A selector that does not end at call sites cannot carry a call-input
        // step. That is a typed shortfall of this route, not a failure: the
        // caller falls back to refusing the row with a named reason.
        if query.validate_steps().is_err() {
            return Ok(Vec::new());
        }
        self.selector_scans = self.selector_scans.saturating_add(1);
        let query_limits = self.remaining_query_limits()?;
        let artifact_leases = self.artifact_leases.snapshot();
        let mut detailed = execute_code_query_detailed_eager_index_workspace_with_semantic_receipt(
            self.workspace,
            &self.flow_state,
            &query,
            query_limits,
            self.root_allotment,
            Some(self.cancellation),
            &self.semantic_budget,
            &self.semantic_execution_budget,
            artifact_leases,
            self.execution_scope
                .clone()
                .with_optional_shared_call_target_outcomes(self.call_target_outcomes.as_ref()),
        );
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        self.charge_query_semantic_work(detailed.work.semantic, semantic_receipt)?;
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete) {
            return Ok(Vec::new());
        }
        Ok(detailed
            .evidence
            .into_iter()
            .filter(|evidence| matches!(evidence.domain, DetailedCodeQueryDomain::ExpressionSite))
            .filter_map(|evidence| Some((evidence.file, evidence.byte_span?)))
            .collect())
    }

    #[cfg(test)]
    pub(super) fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        let retain_decorated_parameter_artifacts =
            query_plan_contains_decorator_bindings(&query.plan);
        let detailed = if retain_decorated_parameter_artifacts {
            self.execute_selector_query_with_artifact_continuation(&query)?
        } else {
            self.execute_selector_query(&query)?
        };
        let (selected, artifact_charge) = self.selected_sites(selector, detailed)?;
        if let Some(artifact_charge) = artifact_charge {
            self.apply_artifact_charge(
                Ok(artifact_charge),
                "selector decorated-parameter continuation",
            )?;
        }
        Ok(selected)
    }

    pub(super) fn select_taint(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        let scope = self.execution_scope.clone();
        self.select_taint_in(selector, &query, scope)
    }

    /// Run a taint selector sliced to the seed files `files`, or
    /// over the whole workspace when its query cannot be sliced. The second
    /// value is the reason the whole workspace answered, which the caller
    /// records; a sliced run widens nothing.
    pub(super) fn select_taint_sliced(
        &mut self,
        selector: &ResolvedPolicySelector,
        files: &[ProjectFile],
    ) -> Result<(Vec<PolicySelectedSite>, Option<WidenReason>), PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        if let Some(widen) = query_slicing_widen_reason(&query) {
            return Ok((self.select_taint(selector)?, Some(widen.reason)));
        }
        // The whole-workspace enumeration is what seed diagnostics still walk;
        // the slice narrows only which files seed.
        let workspace_files = self.workspace.analyzer().analyzed_files();
        let scope = CodeQueryExecutionScope::for_seed_files(files, &workspace_files);
        Ok((self.select_taint_in(selector, &query, scope)?, None))
    }

    /// Select one taint endpoint selector with its seed enumeration narrowed
    /// to `file`, as a per-seed unit does: callers, dispatch and references
    /// still answer over the whole workspace. The caller has checked that the
    /// query can be sliced (`query_slicing_widen_reason`).
    pub(super) fn select_taint_in_file(
        &mut self,
        selector: &ResolvedPolicySelector,
        file: &ProjectFile,
        workspace_files: &[ProjectFile],
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        self.select_taint_in(
            selector,
            &query,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), workspace_files),
        )
    }

    /// A site-local conditional selector evaluates only the current
    /// procedure's source calls, preserving global anchor ranking. The caller still classifies source
    /// ambiguities across the entire artifact after selection.
    pub(super) fn select_taint_in_procedure(
        &mut self,
        selector: &ResolvedPolicySelector,
        file: &ProjectFile,
        workspace_files: &[ProjectFile],
        procedure: &ProcedureHandle,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        use brokk_bifrost_rql::structural::search::{
            OwnedCallAnchors, conditional_selector_is_site_local,
        };
        let query = self.selector_query(selector)?;
        if !conditional_selector_is_site_local(&query.plan) {
            return self.select_taint_in_file(selector, file, workspace_files);
        }
        let artifact = self.materialize(file)?;
        if artifact.key() != procedure.artifact().key() {
            return Err(PolicySelectorSessionError::Unavailable(
                "conditional procedure source revision changed".into(),
            ));
        }
        let analyzer = self.workspace.analyzer();
        // This artifact is the complete source-call/procedure index, not a
        // textual enclosing range. Preserve honest coarse file dependencies:
        // same-file edits invalidate even when they affect another procedure.
        analyzer.record_read_obligation(&ReadKey::semantic_artifact(artifact.key()));
        let language = procedure.artifact().key().language();
        let mut recorded_file = false;
        for provider in analyzer.structural_fact_providers() {
            if language
                == brokk_bifrost_analysis::analyzer::semantic::SemanticLanguage::Standard(
                    provider.structural_language(),
                )
                && let Some(key) = provider.structural_file_read_key(file)
            {
                analyzer.record_read_obligation(&key);
                recorded_file = true;
            }
        }
        if !recorded_file {
            analyzer.record_unattributed_read();
        }
        let has_exact_ownership = procedure.semantics().call_sites().iter().all(|call| {
            procedure
                .semantics()
                .source_mapping(call.source)
                .is_some_and(|mapping| {
                    mapping.kind
                        == brokk_bifrost_analysis::analyzer::semantic::SourceMappingKind::Exact
                        && mapping.locator.path() == artifact.key().path()
                })
        });
        if !has_exact_ownership {
            // Unsupported/inexact ownership never proves that a site is foreign.
            return self.select_taint_in_file(selector, file, workspace_files);
        }
        let peak_scope_work = SemanticWork {
            owned_text_bytes: OwnedCallAnchors::allocation_upper_bound(
                file,
                artifact
                    .procedures()
                    .iter()
                    .map(|procedure| procedure.call_sites().len())
                    .sum(),
            ),
            ..SemanticWork::default()
        };
        self.semantic_budget
            .admit(peak_scope_work)
            .map_err(|error| {
                semantic_budget_error(format!("conditional call ownership: {error}"))
            })?;
        let anchors = procedure
            .semantics()
            .call_sites()
            .iter()
            .map(|call| {
                let mapping = procedure
                    .semantics()
                    .source_mapping(call.source)
                    .expect("ownership validated");
                let span = mapping.locator.anchor().span();
                span.start_byte() as usize..span.end_byte() as usize
            })
            .collect::<Vec<_>>();
        // Compare structural candidates against every semantic call range,
        // including closure calls, before choosing which procedure may own it.
        // This reads structural metadata only; receiver resolution stays scoped.
        let all_anchors = artifact
            .procedures()
            .iter()
            .flat_map(|procedure| {
                procedure.call_sites().iter().map(|call| {
                    let mapping = procedure
                        .source_mapping(call.source)
                        .expect("validated semantic call has a source mapping");
                    let span = mapping.locator.anchor().span();
                    span.start_byte() as usize..span.end_byte() as usize
                })
            })
            .collect::<Vec<_>>();
        let owned = Arc::new(OwnedCallAnchors::new(file.clone(), anchors, all_anchors));
        let scope_work = SemanticWork {
            owned_text_bytes: owned.retained_bytes(),
            ..SemanticWork::default()
        };
        self.semantic_budget
            .release_admission(peak_scope_work.saturating_sub(scope_work));
        let result = self.select_taint_in(
            selector,
            &query,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), workspace_files)
                .with_owned_call_anchors(owned),
        );
        self.semantic_budget.release_admission(scope_work);
        result
    }

    fn select_taint_in(
        &mut self,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
        scope: CodeQueryExecutionScope<'_>,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let _cpu = crate::phase_cpu::Scope::new(crate::phase_cpu::Phase::Selector);
        // Missing model declarations limit this endpoint alone. Never execute
        // an unresolved query, including an unresolved sanitizer selector.
        let mut bound_query = query.clone();
        if let Err(error) = crate::locator::resolve_query_locators(
            &mut bound_query,
            &mut Vec::new(),
            crate::locator::LocatorResolution::Analyzer(self.workspace.analyzer()),
        ) {
            if !crate::locator::is_qualified_locator_code(error.diagnostic.code) {
                return Err(PolicySelectorSessionError::Provider(error.to_string()));
            }
            self.record_unavailable_taint_selector(selector, &error);
            return Ok(Vec::new());
        }
        let mut detailed = self.execute_taint_selector_query(&bound_query, scope)?;
        let completion = detailed.result.completion();
        // Opt-in profiling only: measure query completeness without changing
        // selector answers, receipts, logical work or persisted unit products.
        brokk_bifrost_analysis::profiling::note_with(|| {
            format!(
                "policy.taint_selection path={} completion={completion:?} rows={}",
                selector.path,
                detailed.result.results.len(),
            )
        });
        if matches!(
            completion,
            CodeQueryCompletion::Cancelled | CodeQueryCompletion::Invalid { .. }
        ) {
            return Err(PolicySelectorSessionError::Incomplete {
                completion,
                detail: format!(
                    "selector `{}` was cancelled or invalid: {:?}",
                    selector.path, detailed.result.diagnostics
                ),
            });
        }
        let declared_call = selector
            .as_query()
            .is_some_and(|(_, query)| query_guarantees_declared_call_proof(&query.plan));
        let workspace_exact_call = selector
            .as_query()
            .is_some_and(|(_, query)| query_guarantees_workspace_exact_call_proof(&query.plan));
        if !matches!(completion, CodeQueryCompletion::Complete)
            && !admits_existing_incomplete_call_bindings(
                &detailed.result,
                declared_call,
                workspace_exact_call,
            )
        {
            let diagnostics = detailed
                .result
                .diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {diagnostic:?}", diagnostic.code.as_str()))
                .collect::<Vec<_>>();
            let discovery = detailed
                .result
                .diagnostics
                .iter()
                .map(|diagnostic| {
                    let site = match (&diagnostic.source, &diagnostic.withheld_rows_path) {
                        (Some(source), _) => {
                            Some((source.path.clone(), Some(source.range.start_line)))
                        }
                        (None, Some(path)) => Some((path.clone(), None)),
                        (None, None) => None,
                    };
                    (diagnostic.code, site)
                })
                .collect();
            let attributed_file = detailed
                .result
                .diagnostics
                .iter()
                .try_fold(None::<&str>, |prior, diagnostic| {
                    let path = diagnostic.withheld_rows_path.as_deref()?;
                    match prior {
                        None => Some(Some(path)),
                        Some(previous) if previous == path => Some(prior),
                        Some(_) => None,
                    }
                })
                .flatten()
                .map(str::to_owned);
            self.incomplete_taint_selectors
                .push(IncompleteTaintSelector {
                    path: selector.path.clone(),
                    message: format!(
                        "selector `{}` discovery is {:?}; only individually usable rows were retained: {:?}",
                        selector.path, completion, diagnostics
                    ),
                    discovery,
                    truncated: detailed.result.truncated,
                });
            self.incomplete_selector_observations
                .push(IncompleteSelectorObservation {
                    original_completion: Some(completion),
                    original_locator_refusal_code: None,
                    attributed_file,
                });
            detailed.retained_incomplete_taint_rows = true;
        }
        let (selected, artifact_charge) = self.selected_sites(selector, detailed)?;
        if let Some(artifact_charge) = artifact_charge {
            self.apply_artifact_charge(Ok(artifact_charge), "taint selector continuation")?;
        }
        Ok(selected)
    }

    fn record_unavailable_taint_selector(
        &mut self,
        selector: &ResolvedPolicySelector,
        error: &crate::source::PolicySourceError,
    ) {
        let gap = IncompleteTaintSelector {
            path: selector.path.clone(),
            message: format!(
                "selector `{}` could not be applied: {}: {}",
                selector.path, error.diagnostic.code, error.diagnostic.message,
            ),
            discovery: Vec::new(),
            truncated: false,
        };
        if !self.incomplete_taint_selectors.contains(&gap) {
            self.incomplete_taint_selectors.push(gap);
            self.incomplete_selector_observations
                .push(IncompleteSelectorObservation {
                    original_completion: None,
                    original_locator_refusal_code: Some(error.diagnostic.code),
                    attributed_file: None,
                });
        }
    }

    /// Binding gaps belong to the run even when no sink site or composition
    /// frontier caused the endpoint's selector to execute.
    pub(super) fn record_taint_binding_gaps(
        &mut self,
        policy: &LoadedPolicy,
    ) -> Result<(), PolicySelectorSessionError> {
        for selector in policy.resolved_selectors() {
            let (_, query) = selector.as_query().expect("endpoint is an RQL query");
            let mut query = query.clone();
            if let Err(error) = crate::locator::resolve_query_locators(
                &mut query,
                &mut Vec::new(),
                crate::locator::LocatorResolution::Analyzer(self.workspace.analyzer()),
            ) {
                if !crate::locator::is_qualified_locator_code(error.diagnostic.code) {
                    return Err(PolicySelectorSessionError::Provider(error.to_string()));
                }
                self.record_unavailable_taint_selector(selector, &error);
            }
        }
        Ok(())
    }

    pub(super) fn take_incomplete_taint_selectors(&mut self) -> Vec<IncompleteTaintSelector> {
        self.incomplete_selector_observations.clear();
        std::mem::take(&mut self.incomplete_taint_selectors)
    }

    pub(super) fn take_incomplete_taint_selector_observations(
        &mut self,
    ) -> (
        Vec<IncompleteTaintSelector>,
        Vec<IncompleteSelectorObservation>,
    ) {
        (
            std::mem::take(&mut self.incomplete_taint_selectors),
            std::mem::take(&mut self.incomplete_selector_observations),
        )
    }

    /// Keep the first `len` incomplete-selector notes, so a caller that binds
    /// a selector twice can drop the first pass's notes.
    pub(super) fn truncate_incomplete_taint_selectors(&mut self, len: usize) {
        self.incomplete_taint_selectors.truncate(len);
        self.incomplete_selector_observations.truncate(len);
    }

    /// Put back messages taken with `take_incomplete_taint_selectors`, after
    /// the ones recorded since.
    pub(super) fn extend_incomplete_taint_selectors(&mut self, gaps: Vec<IncompleteTaintSelector>) {
        self.incomplete_selector_observations.extend(
            std::iter::repeat_with(|| IncompleteSelectorObservation {
                original_completion: None,
                original_locator_refusal_code: None,
                attributed_file: None,
            })
            .take(gaps.len()),
        );
        self.incomplete_taint_selectors.extend(gaps);
    }

    /// Compile this session's selectors one seed file at a time, reusing what
    /// a previous run published.
    ///
    /// Called once per compile, before any selector runs. A session that is
    /// never given units executes every selector over the whole workspace,
    /// which is byte for byte what every family did before units existed.
    pub(super) fn with_units(
        &mut self,
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a crate::budget::PolicyBudget,
    ) {
        self.units = Some(SelectorUnits::new(
            policy,
            incremental,
            budget,
            self.workspace,
            &self.flow_state,
        ));
    }

    /// The keys this compile decided about and what it did with them.
    pub(super) fn take_units(&mut self) -> Option<SelectorUnitOutcome> {
        self.units.take().map(SelectorUnits::into_outcome)
    }

    pub(super) fn select_with_artifact_continuation(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        if self.units.is_some() {
            return self.select_sliced(selector, &query);
        }
        let detailed = self.execute_selector_query_with_artifact_continuation(&query)?;
        let retained_incomplete_result_contracts = detailed.retained_incomplete_result_contracts;
        let (selected, artifact_charge) = self.selected_sites(selector, detailed)?;
        if retained_incomplete_result_contracts {
            self.retained_incomplete_result_contract_selectors = self
                .retained_incomplete_result_contract_selectors
                .saturating_add(1);
        }
        #[cfg(any(test, feature = "test-support"))]
        let promoted_artifacts = artifact_charge
            .as_ref()
            .is_some_and(|charge| !charge.is_empty());
        if let Some(artifact_charge) = artifact_charge {
            let retained_before = self.artifact_leases.len();
            self.apply_artifact_charge(
                Ok(artifact_charge),
                "selector result-contract continuation",
            )?;
            self.result_contract_artifact_leases = self
                .result_contract_artifact_leases
                .saturating_add(self.artifact_leases.len().saturating_sub(retained_before));
        }
        #[cfg(any(test, feature = "test-support"))]
        if promoted_artifacts && !selected.is_empty() {
            self.workspace
                .analyzer()
                .test_hooks()
                .invalidate_selector_continuation_semantic_cache_if_armed_for_test();
        }
        Ok(selected)
    }

    /// Compile one selector as the merge of one execution per seed file.
    ///
    /// The units are taken out of the session for the duration, because every
    /// unit's execution charges the session's own ledgers and the two cannot
    /// be borrowed at once. They go back in either way: a widened compile
    /// still reports what its attempt did.
    fn select_sliced(
        &mut self,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let mut units = self
            .units
            .take()
            .expect("a sliced selector compile holds its units");
        let selected = self.select_sliced_units(&mut units, selector, query);
        if let Err(PolicySelectorSessionError::Widen(reason)) = &selected {
            units.widened(*reason);
        }
        self.units = Some(units);
        selected
    }

    /// The ordinary sliced compile: a recomputed unit is published.
    ///
    /// This stays a separate, non-generic function so an ordinary selector's
    /// deep execution chain keeps its own frame instead of paying for the
    /// candidate-classifying path below.
    fn select_sliced_units(
        &mut self,
        units: &mut SelectorUnits<'_>,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        self.selector_scans = self.selector_scans.saturating_add(1);
        let seed_files = units.enumerate(query, selector.path.as_str())?;
        let set_source = matches!(query.plan.source, CodeQueryPlanSource::Set { .. });
        let mut products = Vec::with_capacity(seed_files.len());
        let mut selected = Vec::new();
        for (index, file) in seed_files.iter().enumerate() {
            let rows = match units.published(index)? {
                Some(product) => {
                    // The unit's own execution moved the compile's shared
                    // semantic ledgers, and reusing it must move them the same
                    // way or the next unit would run under an allowance no
                    // whole compile would have given it.
                    self.charge_stored_selector_work(&product)?;
                    if !set_source {
                        selected.extend(units.sites(&product)?);
                    }
                    product.rows
                }
                None => {
                    let executed = match self.execute_selector_unit(units, selector, query, file)? {
                        SelectorUnitRun::Complete(executed) => executed,
                        // A unit that did not complete is not a partition
                        // of a complete execution, whatever it selected.
                        SelectorUnitRun::Incomplete(_) => {
                            return Err(PolicySelectorSessionError::Widen(
                                WidenReason::UnitDiagnostics,
                            ));
                        }
                    };
                    if !set_source {
                        selected.extend(executed.sites.iter().cloned());
                    }
                    units.publish(index, &executed);
                    executed.rows
                }
            };
            super::unit_execution::check_exhaustive_rows(&rows)
                .map_err(PolicySelectorSessionError::Widen)?;
            products.push(rows);
        }
        self.merge_sliced_selection(selector, query, set_source, products, selected, false)
    }

    /// The candidate-classifying sliced compile: every recomputed seed file
    /// runs its ordinary unit, then is classified under the request's ledger
    /// and withheld from publication. Only a certified candidate selector
    /// reaches this path, so ordinary selectors never pay its wider frame.
    fn select_withheld_sliced_units(
        &mut self,
        units: &mut SelectorUnits<'_>,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
        undecided: &mut Vec<UndecidedCandidate>,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        self.selector_scans = self.selector_scans.saturating_add(1);
        let seed_files = units.enumerate(query, selector.path.as_str())?;
        let set_source = matches!(query.plan.source, CodeQueryPlanSource::Set { .. });
        assert!(!set_source, "only acquisition subjects withhold units");
        let mut products = Vec::with_capacity(seed_files.len());
        let mut selected = Vec::new();
        let mut withheld = false;
        for (index, file) in seed_files.iter().enumerate() {
            let rows = match units.published(index)? {
                Some(product) => {
                    self.charge_stored_selector_work(&product)?;
                    selected.extend(units.sites(&product)?);
                    product.rows
                }
                None => {
                    let run = self.execute_selector_unit(units, selector, query, file)?;
                    // A complete execution does not prove that a candidate
                    // it did not select was rejected, so the file is also
                    // classified, after the unit and under the request's
                    // own ledger, exactly as an unsliced compile is.
                    let outer = std::mem::take(&mut self.query_work);
                    let classified = self.classify_selector_candidates_in_scope(
                        query,
                        CodeQueryExecutionScope::for_seed_files(
                            std::slice::from_ref(file),
                            &units.workspace_files,
                        ),
                    );
                    let work = std::mem::replace(&mut self.query_work, outer);
                    self.query_work = self.query_work.saturating_add(work);
                    let classified = classified?.expect("a certified selector classifies");
                    // The unit's receipt and stored work hold neither the
                    // classification's reads nor its budget charges, so a
                    // reused unit would replay less than a cold compile
                    // did. The file answers this compile and is withheld.
                    let mut rows = match run {
                        SelectorUnitRun::Complete(executed) => Box::new(executed.rows),
                        SelectorUnitRun::Incomplete(rows) => rows,
                    };
                    rows.work = rows.work.saturating_add(work);
                    undecided.extend(UndecidedCandidate::of(&classified));
                    selected.extend(self.classified_sites(selector, &classified)?);
                    units.withhold();
                    withheld = true;
                    // Not exhaustive, but still this file's share of the
                    // work and rows the cumulative caps below sum.
                    products.push(*rows);
                    continue;
                }
            };
            super::unit_execution::check_exhaustive_rows(&rows)
                .map_err(PolicySelectorSessionError::Widen)?;
            products.push(rows);
        }
        self.merge_sliced_selection(selector, query, set_source, products, selected, withheld)
    }

    /// Merge one sliced compile's units into the vector a whole execution
    /// would have produced, and project the sites of a set-source compile.
    fn merge_sliced_selection(
        &self,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
        set_source: bool,
        products: Vec<UnitExecutionResult>,
        selected: Vec<PolicySelectedSite>,
        withheld: bool,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let merged = merge_unit_rows_in_scope(
            query,
            products,
            CodeQueryExecutionScope::whole_workspace().with_depth_bound_status(false),
        );
        // Every cumulative cap the whole execution enforces, summed over the
        // units. Reaching one means the whole execution might have truncated
        // somewhere in its own order, so the merged rows are not its rows.
        // A withheld file's sites can outnumber its incomplete rows, so the
        // result cap is also checked against everything selected.
        if merged
            .reached_limit(&self.query_limits, query.limit)
            .is_some()
            || (withheld && selected.len() >= query.limit)
        {
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::MergedLimitReached,
            ));
        }
        if set_source {
            let evidence = merged.detailed_evidence(self.workspace.analyzer().project().root());
            return merged
                .items
                .iter()
                .zip(evidence)
                .map(|(item, evidence)| {
                    let UnitRowItemTerminal::StructuralMatch { .. } = item
                        .terminal
                        .as_ref()
                        .ok_or(PolicySelectorSessionError::Widen(
                            WidenReason::PlanCrossesSeeds,
                        ))?
                    else {
                        return Err(PolicySelectorSessionError::Widen(
                            WidenReason::PlanCrossesSeeds,
                        ));
                    };
                    let span = evidence.byte_span.ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` produced a row without a source span",
                            selector.path
                        ))
                    })?;
                    Ok(PolicySelectedSite {
                        file: evidence.file,
                        span,
                        proof: ProofStatus::Proven,
                        completeness: if item.provenance_truncated {
                            EvidenceCompleteness::Partial(
                                "selector provenance was truncated".into(),
                            )
                        } else {
                            EvidenceCompleteness::Complete
                        },
                        result_contract: None,
                        call_shape: None,
                        call_binding: None,
                        selected_model_record: None,
                        selected_summary_record: None,
                        modeled_member_id: None,
                        modeled_target_origin: None,
                        decorated_parameter: None,
                        runtime_keyed_read: None,
                        runtime_keyed_read_row: false,
                        runtime_keyed_read_conclusive_exclusion: false,
                        occurrence_role: None,
                        retained_incomplete_result_contract_query: false,
                    })
                })
                .collect();
        }
        Ok(selected)
    }

    /// Run one seed file's execution of one selector, and read its sites.
    fn execute_selector_unit(
        &mut self,
        units: &SelectorUnits<'_>,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
        file: &ProjectFile,
    ) -> Result<SelectorUnitRun, PolicySelectorSessionError> {
        let query_limits = self.remaining_query_limits()?;
        let artifact_leases = self.artifact_leases.snapshot();
        let semantic_before = self.semantic_budget.replay_snapshot();
        let refusals_before = self.semantic_budget.refusal_count();
        let execution_before = self.semantic_execution_budget.work();
        let (executed, mut reads, elapsed) = recompute_unit(
            self.workspace.analyzer(),
            Some(self.cancellation),
            || {
                format!(
                    "policy={} partition=selector selector={:?} file={}",
                    units.policy.definition().metadata.id,
                    selector.path,
                    rel_path_string(file)
                )
            },
            || {
                execute_code_query_selector_unit(
                    self.workspace,
                    &self.flow_state,
                    query,
                    query_limits,
                    self.root_allotment,
                    Some(self.cancellation),
                    &self.semantic_budget,
                    &self.semantic_execution_budget,
                    artifact_leases,
                    CodeQueryExecutionScope::for_seed_files(
                        std::slice::from_ref(file),
                        &units.workspace_files,
                    )
                    .with_depth_bound_status(false)
                    .with_optional_shared_call_target_outcomes(self.call_target_outcomes.as_ref()),
                )
            },
        );
        units.reuse.record_recompute(elapsed);
        let mut detailed = executed.detailed;
        let rows = executed.unit;
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        let complete = matches!(detailed.result.completion(), CodeQueryCompletion::Complete);
        let artifact_charge = self.charge_query_semantic_work_with_artifact_continuation(
            detailed.work.semantic,
            semantic_receipt,
            complete,
        )?;
        // A unit that did not complete is not a partition of a complete
        // execution, whatever it selected.
        if !complete {
            return Ok(SelectorUnitRun::Incomplete(Box::new(rows)));
        }
        // The allocations this unit retained cannot be reproduced from a
        // stored product -- they are process-local artifacts -- so a unit that
        // retained any is used here and never published.
        let retained_artifacts = artifact_charge
            .as_ref()
            .is_some_and(|charge| !charge.is_empty());
        let (sites, artifact_charge) =
            if matches!(query.plan.source, CodeQueryPlanSource::Set { .. }) {
                (Vec::new(), artifact_charge)
            } else {
                self.selected_sites(
                    selector,
                    PolicySelectorQueryResult {
                        result: detailed.result,
                        evidence: detailed.evidence,
                        artifact_charge,
                        retained_incomplete_result_contracts: false,
                        retained_incomplete_taint_rows: false,
                    },
                )?
            };
        if let Some(artifact_charge) = artifact_charge {
            let retained_before = self.artifact_leases.len();
            self.apply_artifact_charge(
                Ok(artifact_charge),
                "selector result-contract continuation",
            )?;
            self.result_contract_artifact_leases = self
                .result_contract_artifact_leases
                .saturating_add(self.artifact_leases.len().saturating_sub(retained_before));
        }
        let semantic = self.semantic_budget.replay_since(&semantic_before);
        let execution_after = self.semantic_execution_budget.work();
        if self.semantic_budget.refusal_count() > refusals_before || execution_after.exhausted {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=selector_boundary semantic={} execution={}",
                    file!(),
                    line!(),
                    self.semantic_budget.refusal_count() > refusals_before,
                    execution_after.exhausted
                )
            });
            reads = None;
        }
        Ok(SelectorUnitRun::Complete(Box::new(ExecutedSelectorUnit {
            reads,
            publishable: !retained_artifacts && sites.iter().all(selector_site_is_projectable),
            product: SelectorProduct {
                rows: rows.clone(),
                sites: sites.iter().map(project_selector_site).collect(),
                semantic,
                materialized_files: lane(
                    execution_after
                        .materialized_files
                        .saturating_sub(execution_before.materialized_files),
                ),
                traversal_steps: lane(
                    execution_after
                        .traversal_steps
                        .saturating_sub(execution_before.traversal_steps),
                ),
            },
            rows,
            sites,
        })))
    }

    /// Charge what a reused unit's own execution took out of the shared
    /// semantic ledgers.
    ///
    /// The scalar work rather than the child charge the live path applies: a
    /// stored product carries no process-local artifact identities, so a later
    /// unit may pay a census this one already paid. That over-charges the
    /// semantic lane, which can only widen more often, never less.
    fn charge_stored_selector_work(
        &mut self,
        product: &SelectorProduct,
    ) -> Result<(), PolicySelectorSessionError> {
        if self
            .semantic_budget
            .replay_product(product.semantic)
            .is_err()
            || !self.semantic_execution_budget.charge_external_query_work(
                usize::try_from(product.materialized_files).unwrap_or(usize::MAX),
                usize::try_from(product.traversal_steps).unwrap_or(usize::MAX),
            )
        {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic materialization budget",
                self.analysis
            )));
        }
        self.query_work = self.query_work.saturating_add(product.rows.work);
        Ok(())
    }

    pub(crate) fn selector_query(
        &self,
        selector: &ResolvedPolicySelector,
    ) -> Result<CodeQuery, PolicySelectorSessionError> {
        // A policy batch runs many selectors against one immutable snapshot,
        // so index reuse is guaranteed: build it on the first selector rather
        // than letting Auto's first-request deferral turn the whole batch
        // into repeated full-workspace scans.
        //
        // Endpoint selection must bind every matching site, not the interactive
        // pagination sample the selector query carries: the catalog validates
        // the authored `limit` to the shared `DEFAULT_LIMIT` of 100, which
        // truncates a corpus-scale source or sink selector before binding and
        // fails the compile closed (#1935). Raise the selection result cap to
        // the host-controlled policy bound; the structural pipeline budget
        // still governs honest truncation above it.
        let (_, query) = selector.as_query().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` has no executable query kind",
                selector.path
            ))
        })?;
        let mut query = query.clone();
        query.limit = self.max_selector_results;
        Ok(query)
    }

    /// Whether this selector selects subjects through the certified candidate
    /// inventory. A selector that is not certified keeps the ordinary
    /// whole-selector path: its candidate set is not enumerable, so it has no
    /// undecided-site product to retain.
    pub(crate) fn subject_uses_candidate_enumeration(
        &self,
        selector: &ResolvedPolicySelector,
    ) -> Result<bool, PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        Ok(candidate_enumeration::WhitelistedCallSelector::check(&query).is_some())
    }

    /// Select a certified acquisition subject's sites. A certified selector
    /// also reports the candidates it could not decide, instead of failing
    /// whole. A sliced compile runs each recomputed seed file's ordinary
    /// unit, then classifies that file under the request's ledger and
    /// withholds every classified file from publication.
    pub(crate) fn select_subject_candidates(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<SubjectSelection, PolicySelectorSessionError> {
        let query = self.selector_query(selector)?;
        assert!(
            candidate_enumeration::WhitelistedCallSelector::check(&query).is_some(),
            "only a certified candidate selector classifies its subject sites"
        );
        let mut undecided = Vec::new();
        let sites = match self.units.take() {
            Some(mut units) => {
                let selected =
                    self.select_withheld_sliced_units(&mut units, selector, &query, &mut undecided);
                if let Err(PolicySelectorSessionError::Widen(reason)) = &selected {
                    units.widened(*reason);
                }
                self.units = Some(units);
                selected?
            }
            None => {
                let classified = self
                    .classify_selector_candidates(&query)?
                    .expect("a certified selector classifies");
                undecided.extend(UndecidedCandidate::of(&classified));
                self.classified_sites(selector, &classified)?
            }
        };
        Ok(SubjectSelection { sites, undecided })
    }

    /// Scoped starting subjects bypass the whole-workspace selector memo.
    /// Events and terminals may reuse the query but must still see excluded files.
    pub(crate) fn select_subject_candidates_in_scope(
        &mut self,
        selector: &ResolvedPolicySelector,
        scope: CodeQueryExecutionScope<'_>,
    ) -> Result<SubjectSelection, PolicySelectorSessionError> {
        assert!(
            self.units.is_none(),
            "scoped subjects cannot use selector units"
        );
        let query = self.selector_query(selector)?;
        let classified = self
            .classify_selector_candidates_in_scope(&query, scope)?
            .expect("only certified subject selectors support execution scope");
        Ok(SubjectSelection {
            undecided: UndecidedCandidate::of(&classified).collect(),
            sites: self.classified_sites(selector, &classified)?,
        })
    }

    /// Explicit opt-in for consumers that can carry a complete inventory
    /// proof. Ordinary selector execution does not request candidate outcomes.
    pub(crate) fn classify_selector_candidates(
        &mut self,
        query: &CodeQuery,
    ) -> Result<
        Option<candidate_enumeration::ProvenSelectorClassification>,
        PolicySelectorSessionError,
    > {
        let scope = self.execution_scope.clone();
        self.classify_selector_candidates_in_scope(query, scope)
    }

    fn classify_selector_candidates_in_scope(
        &mut self,
        query: &CodeQuery,
        scope: CodeQueryExecutionScope<'_>,
    ) -> Result<
        Option<candidate_enumeration::ProvenSelectorClassification>,
        PolicySelectorSessionError,
    > {
        use candidate_enumeration::{
            CompleteStructuralCandidateEnumeration, WhitelistedCallSelector,
        };
        let Some(selector) = WhitelistedCallSelector::check(query) else {
            return Ok(None);
        };
        let _request =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(self.workspace.analyzer());
        let _models = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(self.workspace.analyzer(), self.workspace.analyzer().active_semantic_model_snapshot());
        // All nested scopes inherit this OuterRequest, the selected-snapshot
        // sharing point of #10979, across enumeration, batch and isolation.
        let enumeration = CompleteStructuralCandidateEnumeration::enumerate_in_scope(
            self,
            &selector,
            scope.clone(),
        )
        .map_err(|refusal| {
            use candidate_enumeration::CandidateEnumerationRefusal;
            let detail = format!("structural candidate enumeration refused: {refusal:?}");
            let completion = match refusal {
                CandidateEnumerationRefusal::Execution(error) => return error,
                // A cancelled or limited enumeration keeps that cause.
                CandidateEnumerationRefusal::Incomplete(completion) => completion,
                CandidateEnumerationRefusal::Truncated => CodeQueryCompletion::Incomplete {
                    codes: vec![CodeQueryDiagnosticCode::ResultLimitReached],
                },
                CandidateEnumerationRefusal::MissingLocation
                | CandidateEnumerationRefusal::ReadIncomplete(_) => {
                    CodeQueryCompletion::Incomplete {
                        codes: vec![CodeQueryDiagnosticCode::SemanticProviderFailed],
                    }
                }
            };
            PolicySelectorSessionError::Incomplete { completion, detail }
        })?;
        enumeration
            .classify_in_scope(self, &selector, query, scope)
            .map(Some)
    }

    /// Project only proof-certified Selected rows into the ordinary binding path.
    pub(crate) fn classified_sites(
        &self,
        selector: &ResolvedPolicySelector,
        classified: &candidate_enumeration::ProvenSelectorClassification,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let batch = &classified.batch_result_for_binding().result;
        let mut result = CodeQueryResult {
            results: Vec::new(),
            truncated: false,
            depth_bound_status: batch.depth_bound_status,
            session_subset: batch.session_subset,
            diagnostics: Vec::new(),
        };
        let mut evidence = Vec::new();
        for (index, _) in classified.candidates().enumerate() {
            for (item, row) in classified.selected_bindings(index) {
                let mut row = row.clone();
                row.result_index = result.results.len();
                result.results.push(item.clone());
                evidence.push(row);
            }
        }
        let (sites, charge) = self.selected_sites(
            selector,
            PolicySelectorQueryResult {
                result,
                evidence,
                artifact_charge: None,
                retained_incomplete_result_contracts: false,
                retained_incomplete_taint_rows: false,
            },
        )?;
        assert!(charge.is_none());
        Ok(sites)
    }

    fn execute_selector_query_core(
        &mut self,
        query: &brokk_bifrost_rql::CodeQuery,
        scope: CodeQueryExecutionScope<'_>,
    ) -> Result<
        (DetailedCodeQueryResult, Option<CodeQuerySemanticReceipt>),
        PolicySelectorSessionError,
    > {
        let query_limits = self.remaining_query_limits()?;
        self.execute_selector_query_with_limits(query, scope, query_limits)
    }

    fn execute_selector_query_with_limits(
        &mut self,
        query: &CodeQuery,
        scope: CodeQueryExecutionScope<'_>,
        query_limits: CodeQueryExecutionLimits,
    ) -> Result<
        (DetailedCodeQueryResult, Option<CodeQuerySemanticReceipt>),
        PolicySelectorSessionError,
    > {
        self.selector_scans = self.selector_scans.saturating_add(1);
        #[cfg(all(test, feature = "test-support"))]
        let scope = scope.with_binding_candidate_probe(self.binding_candidate_probe.clone());
        let artifact_leases = self.artifact_leases.snapshot();
        let mut detailed = execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_and_row_family_session(
            self.workspace,
    &self.flow_state,
            query,
            query_limits,
            self.root_allotment,
            Some(self.cancellation),
            &self.semantic_budget,
            &self.semantic_execution_budget,
            artifact_leases,
            scope.with_depth_bound_status(false).with_optional_shared_call_target_outcomes(self.call_target_outcomes.as_ref()),
            &mut self.row_family_session,
        );
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        Ok((detailed, semantic_receipt))
    }

    #[cfg(test)]
    fn execute_selector_query(
        &mut self,
        query: &brokk_bifrost_rql::CodeQuery,
    ) -> Result<PolicySelectorQueryResult, PolicySelectorSessionError> {
        let scope = self.execution_scope.clone();
        let (detailed, semantic_receipt) = self.execute_selector_query_core(query, scope)?;
        self.charge_query_semantic_work(detailed.work.semantic, semantic_receipt)?;
        Ok(PolicySelectorQueryResult {
            result: detailed.result,
            evidence: detailed.evidence,
            artifact_charge: None,
            retained_incomplete_result_contracts: false,
            retained_incomplete_taint_rows: false,
        })
    }

    fn execute_selector_query_with_artifact_continuation(
        &mut self,
        query: &brokk_bifrost_rql::CodeQuery,
    ) -> Result<PolicySelectorQueryResult, PolicySelectorSessionError> {
        let scope = self.execution_scope.clone();
        let (detailed, semantic_receipt) = self.execute_selector_query_core(query, scope)?;
        let retain_result_contract_subset =
            retains_independently_proven_result_contracts(&detailed.result, &detailed.evidence);
        let artifact_charge = self.charge_query_semantic_work_with_artifact_continuation(
            detailed.work.semantic,
            semantic_receipt,
            matches!(detailed.result.completion(), CodeQueryCompletion::Complete)
                || retain_result_contract_subset,
        )?;
        Ok(PolicySelectorQueryResult {
            result: detailed.result,
            evidence: detailed.evidence,
            artifact_charge,
            retained_incomplete_result_contracts: retain_result_contract_subset,
            retained_incomplete_taint_rows: false,
        })
    }

    fn execute_taint_selector_query(
        &mut self,
        query: &brokk_bifrost_rql::CodeQuery,
        scope: CodeQueryExecutionScope<'_>,
    ) -> Result<PolicySelectorQueryResult, PolicySelectorSessionError> {
        let (detailed, semantic_receipt) = self.execute_selector_query_core(query, scope)?;
        let retain_rows = retains_usable_taint_rows(
            &detailed.result,
            &detailed.evidence,
            query_call_binding_proof(&query.plan),
        );
        let artifact_charge = self.charge_query_semantic_work_with_artifact_continuation(
            detailed.work.semantic,
            semantic_receipt,
            matches!(detailed.result.completion(), CodeQueryCompletion::Complete) || retain_rows,
        )?;
        Ok(PolicySelectorQueryResult {
            result: detailed.result,
            evidence: detailed.evidence,
            artifact_charge,
            retained_incomplete_result_contracts: false,
            retained_incomplete_taint_rows: false,
        })
    }

    fn selected_sites(
        &self,
        selector: &ResolvedPolicySelector,
        detailed: PolicySelectorQueryResult,
    ) -> Result<
        (Vec<PolicySelectedSite>, Option<SemanticArtifactLeaseCharge>),
        PolicySelectorSessionError,
    > {
        let result_contract_subset = detailed.retained_incomplete_result_contracts;
        let taint_subset = detailed.retained_incomplete_taint_rows;
        let declared_call = selector
            .as_query()
            .is_some_and(|(_, query)| query_guarantees_declared_call_proof(&query.plan));
        let workspace_exact_call = selector
            .as_query()
            .is_some_and(|(_, query)| query_guarantees_workspace_exact_call_proof(&query.plan));
        let query_binding_proof = selector
            .as_query()
            .and_then(|(_, query)| query_call_binding_proof(&query.plan));
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete)
            && !admits_existing_incomplete_call_bindings(
                &detailed.result,
                declared_call,
                workspace_exact_call,
            )
            && !result_contract_subset
            && !taint_subset
        {
            let diagnostics = detailed
                .result
                .diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {}", diagnostic.code.as_str(), diagnostic.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(PolicySelectorSessionError::Incomplete {
                completion: detailed.result.completion(),
                detail: format!("`{}` ({diagnostics})", selector.path),
            });
        }
        let selected = detailed
            .evidence
            .into_iter()
            .filter(|evidence| !matches!(evidence.domain, DetailedCodeQueryDomain::File))
            .filter(|evidence| {
                !taint_subset
                    || detailed.result.results.get(evidence.result_index)
                        .is_some_and(|item| usable_taint_row(item, evidence, query_binding_proof))
            })
            .map(|evidence| {
                let item = detailed
                    .result
                    .results
                    .get(evidence.result_index)
                    .ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` evidence refers to an absent result row",
                            selector.path
                        ))
                    })?;
                if matches!(
                    &item.value,
                    CodeQueryResultValue::CallResultContract { value } if value.terminal
                ) {
                    // A terminal row proves that this call has no universally
                    // applicable reviewed result contract. It is not an
                    // ordinary call selection and must never fall through to
                    // indexed-result or receiver binding.
                    return Ok(None);
                }
                let decorated_parameter = match (
                    &item.value,
                    evidence.decorated_parameter.as_ref(),
                ) {
                    (
                        CodeQueryResultValue::DecoratedParameter { value },
                        Some(semantic),
                    ) => {
                        let parameter_port_matches = matches!(
                            &semantic.port,
                            DurablePortIdentity::Parameter { ordinal }
                                if value.parameter_ordinal == Some(*ordinal as usize)
                        );
                        let identity_matches = value.procedure_id.as_deref()
                            == Some(semantic.procedure_id.as_str())
                            && value.value_id.as_deref() == Some(semantic.value_id.as_str())
                            && value.port_id.as_deref() == Some(semantic.port_id.as_str());
                        if value.completion != "complete"
                            || value.coverage != "complete"
                            || !identity_matches
                            || !parameter_port_matches
                        {
                            return Err(PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` produced inconsistent decorated-parameter semantic evidence",
                                selector.path
                            )));
                        }
                        Some(semantic.clone().into())
                    }
                    (CodeQueryResultValue::DecoratedParameter { .. }, None) => {
                        return Err(PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` produced a decorated parameter without exact semantic evidence",
                            selector.path
                        )));
                    }
                    (_, Some(_)) => {
                        return Err(PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` attached decorated-parameter evidence to another row kind",
                            selector.path
                        )));
                    }
                    (_, None) => None,
                };
                let evidence_span = evidence.byte_span.ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` produced a row without a source span",
                        selector.path
                    ))
                })?;
                let receiver_only_call = match &item.value {
                    CodeQueryResultValue::CallBinding { value } => {
                        value.argument_id.is_none() && value.binding_kind == Some("receiver")
                    }
                    _ => false,
                };
                let span = if receiver_only_call {
                    match &item.value {
                        CodeQueryResultValue::CallBinding { value } =>
                            self.call_span_for_ast_id(&evidence.file, &value.site_ast_id)?,
                        _ => unreachable!("receiver-only marker belongs to a call binding"),
                    }
                } else {
                    evidence_span
                };
                let (proof, completeness) = if query_binding_proof.is_some()
                    && matches!(item.value, CodeQueryResultValue::CallBinding { .. })
                {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    selected_site_quality(item)
                };
                let result_contract = match &item.value {
                    CodeQueryResultValue::CallResultContract { value } => {
                        Some(PolicyResultContractSelection {
                            result_ordinal: value.result_ordinal.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` produced a positive result-contract row without a result ordinal",
                                    selector.path
                                ))
                            })?,
                            fresh_allocation: value.fresh_allocation,
                            success_guard_coverage: value.success_guard_coverage.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` produced a positive result-contract row without success-guard coverage",
                                    selector.path
                                ))
                            })?,
                            success_guard_edges: value.success_guard_edges.clone(),
                            possible_success_guard_edges: value
                                .possible_success_guard_edges
                                .clone(),
                            member_contracts: value.member_contracts.clone(),
                        })
                    }
                    _ => None,
                };
                let call_shape = match &item.value {
                    CodeQueryResultValue::CallShape { value } => Some(PolicyCallShapeSelection {
                        callee_name: value.callee_name.clone(),
                        argument_count: u32::try_from(value.argument_count).map_err(|_| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` produced a call with too many arguments",
                                selector.path
                            ))
                        })?,
                    }),
                    _ => None,
                };
                let retained_incomplete_result_contract_query =
                    result_contract_subset && result_contract.is_some();
                let (
                    runtime_keyed_read,
                    runtime_keyed_read_row,
                    runtime_keyed_read_conclusive_exclusion,
                ) = match (
                    &item.value,
                    evidence.runtime_keyed_read.as_ref(),
                ) {
                    (
                        CodeQueryResultValue::RuntimeKeyedReadValue { .. },
                        Some(endpoint),
                    ) => (Some(endpoint.clone()), true, false),
                    (CodeQueryResultValue::RuntimeKeyedReadValue { value }, None) => {
                        (None, true, value.conclusive_exclusion)
                    }
                    (_, Some(_)) => {
                        return Err(PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` attached runtime keyed-read evidence to another row kind",
                            selector.path
                        )));
                    }
                    (_, None) => (None, false, false),
                };
                let call_binding = match &item.value {
                    CodeQueryResultValue::CallBinding { value } if value.terminal => None,
                    CodeQueryResultValue::CallBinding { .. } if receiver_only_call => None,
                    CodeQueryResultValue::CallBinding { value } => {
                        let call_span = self.call_span_for_ast_id(
                            &evidence.file,
                            &value.site_ast_id,
                        )?;
                        Some(PolicySelectedCallBinding {
                            row_id: value.id.clone(),
                            site_id: value.site_id.clone(),
                            site_ast_id: value.site_ast_id.clone(),
                            argument_id: value.argument_id.clone().ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` selected a binding without an argument identity",
                                    selector.path
                                ))
                            })?,
                            call_span,
                            actual_index: value.actual_index.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` selected a binding without an actual index",
                                    selector.path
                                ))
                            })?,
                            formal_index: value.formal_index.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` selected a binding without a formal index",
                                    selector.path
                                ))
                            })?,
                            formal_name: value.formal_name.clone(),
                            semantic_target_id: value.semantic_target_id.clone(),
                            model_callable_id: value.model_callable_id.clone(),
                            formal_layout_id: value.formal_layout_id.clone().ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` selected a binding without formal-layout identity",
                                    selector.path
                                ))
                            })?,
                            signature_id: value.signature_id.clone(),
                            model_id: value.model_id.clone(),
                            pack_id: value.pack_id.clone(),
                            requires_receiver_dispatch: selector.as_query().is_some_and(|(_, query)| {
                                query_requires_receiver_dispatch(&query.plan)
                            }),
                            selector_proof: if declared_call {
                                "declared"
                            } else if workspace_exact_call {
                                "resolved_workspace"
                            } else {
                                value.selector_proof.ok_or_else(|| {
                                    PolicySelectorSessionError::Unavailable(format!(
                                        "selector `{}` selected a binding without selector proof",
                                        selector.path
                                    ))
                                })?
                            },
                            selector_provenance: if declared_call {
                                "declared"
                            } else if workspace_exact_call {
                                "resolved_workspace"
                            } else if taint_subset && incomplete_source_call_binding(value) {
                                "incomplete_source_candidate"
                            } else {
                                value.selector_proof.ok_or_else(|| {
                                    PolicySelectorSessionError::Unavailable(format!(
                                        "selector `{}` selected a binding without selector proof",
                                        selector.path
                                    ))
                                })?
                            },
                            selector_summary_id: if query_binding_proof.is_some()
                            {
                                None
                            } else {
                                value.selector_summary_id.clone()
                            },
                            selector_summary_model_id: if query_binding_proof.is_some()
                            {
                                None
                            } else {
                                value.selector_summary_model_id.clone()
                            },
                            selector_summary_pack_id: if query_binding_proof.is_some()
                            {
                                None
                            } else {
                                value.selector_summary_pack_id.clone()
                            },
                            selector_summary_pack_digest: if query_binding_proof.is_some()
                            {
                                None
                            } else {
                                value.selector_summary_pack_digest.clone()
                            },
                        })
                    }
                    _ => None,
                };
                let (modeled_member_id, modeled_target_origin) = match &item.value {
                    CodeQueryResultValue::CallBinding { value } => {
                        (value.model_id.clone(), value.target_origin)
                    }
                    _ => (None, None),
                };
                // A source target renders directly. An unmaterialized external
                // target is accepted only with the unique callable's three exact
                // layout identities. Candidate provenance is deliberately
                // excluded, and receiver-only rows keep the record too.
                let selected_model_record = match &item.value {
                    CodeQueryResultValue::CallBinding { value } => accepted_model_record(
                        value.selector_exact,
                        value.target.is_some(),
                        value.model_callable_id.is_some()
                            && value.formal_layout_id.is_some()
                            && value.signature_id.is_some(),
                        value.target_origin,
                        value.model_ambiguous.unwrap_or(true),
                        value.model_pack_digest.as_deref(),
                        value.model_record_id.as_deref(),
                    ),
                    _ => None,
                };
                // A binding that is exact only through an authored override
                // contract rests on that summary even when the flow ends at
                // the call and never traverses it. A query whose own filter
                // proves the binding does not rest on the summary.
                let selected_summary_record = match &item.value {
                    CodeQueryResultValue::CallBinding { value } => accepted_summary_record(
                        query_binding_proof.is_some(),
                        value.selector_exact,
                        value.selector_proof,
                        value.selector_summary_pack_digest.as_deref(),
                        value.selector_summary_record_id.as_deref(),
                    ),
                    _ => None,
                };
                let occurrence_role = if self.analysis == "taint" {
                    match &item.value {
                        CodeQueryResultValue::Occurrence { value } => Some(
                            OccurrenceRole::from_label(value.role)
                                .expect("occurrence rows use the registered role vocabulary"),
                        ),
                        _ => None,
                    }
                } else {
                    None
                };
                Ok(Some(PolicySelectedSite {
                    file: evidence.file,
                    span,
                    proof,
                    completeness,
                    result_contract,
                    call_shape,
                    call_binding,
                    selected_model_record,
                    selected_summary_record,
                    modeled_member_id,
                    modeled_target_origin,
                    decorated_parameter,
                    runtime_keyed_read,
                    runtime_keyed_read_row,
                    runtime_keyed_read_conclusive_exclusion,
                    occurrence_role,
                    retained_incomplete_result_contract_query,
                }))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok((selected, detailed.artifact_charge))
    }

    fn call_span_for_ast_id(
        &self,
        file: &ProjectFile,
        expected_ast_id: &str,
    ) -> Result<ByteRange<usize>, PolicySelectorSessionError> {
        let facts = self
            .workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file))
            .ok_or_else(|| {
                PolicySelectorSessionError::Unavailable(format!(
                    "call-binding site identity cannot be resolved for `{}`",
                    file
                ))
            })?;
        let mut matches = facts.nodes().iter().enumerate().filter(|(index, _)| {
            brokk_bifrost_analysis::analyzer::structural::occurrence_rows::ast_id(
                facts.source_identity(),
                u32::try_from(*index).expect("facts arena node IDs fit u32"),
            ) == expected_ast_id
        });
        let (_, node) = matches.next().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(
                "selected call-binding AST identity is absent from structural facts".to_owned(),
            )
        })?;
        if matches.next().is_some() {
            return Err(PolicySelectorSessionError::Unavailable(
                "selected call-binding AST identity is ambiguous".to_owned(),
            ));
        }
        Ok(node.range.start_byte..node.range.end_byte)
    }

    pub(super) fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub(super) fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    pub(super) fn semantic_request(&mut self) -> SemanticRequest<'_> {
        SemanticRequest::with_execution_budget(
            &mut self.semantic_budget,
            self.cancellation,
            &self.semantic_execution_budget,
        )
    }

    pub(super) fn begin_semantic_lease_window(&self) -> PolicySemanticLeaseWindow {
        PolicySemanticLeaseWindow::new(&self.artifact_leases)
    }

    pub(super) fn continue_semantic_in_window<T>(
        &mut self,
        leases: &PolicySemanticLeaseWindow,
        run: impl FnOnce(&mut SemanticRequest<'_>) -> Result<SemanticOutcome<T>, SemanticProviderError>,
    ) -> Result<SemanticOutcome<T>, PolicySelectorSessionError> {
        let collector = leases.collector();
        let outcome = {
            let mut request = SemanticRequest::with_execution_budget(
                &mut self.semantic_budget,
                self.cancellation,
                &self.semantic_execution_budget,
            )
            .with_artifact_collector(&collector);
            run(&mut request)
        };
        match outcome {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(PolicySelectorSessionError::Provider(error.to_string())),
        }
    }

    /// Run one typestate continuation operation in one bounded lease window.
    /// The caller classifies and fully decodes the primary outcome before it
    /// either commits escaping handles or discards a scalar-only result.
    pub(super) fn continue_semantic<T>(
        &mut self,
        run: impl FnOnce(&mut SemanticRequest<'_>) -> Result<SemanticOutcome<T>, SemanticProviderError>,
    ) -> Result<PolicySemanticContinuation<T>, PolicySelectorSessionError> {
        let leases = self.begin_semantic_lease_window();
        let outcome = self.continue_semantic_in_window(&leases, run)?;
        Ok(PolicySemanticContinuation { outcome, leases })
    }

    /// Classify one source call's tied semantic lowerings for a receiver port.
    ///
    /// Duplicate lowerings of one source site (for example, a `finally` body
    /// specialized per completion route) must agree on whether they publish a
    /// candidate caller-side receiver. Complete callable-reference evidence
    /// can prove a bound receiver or a receiverless function locally. When the
    /// syntax is deliberately ambiguous, only uninterrupted, exhaustive
    /// dispatch may refine it. Exact Go declarations prove their receiver
    /// shape independently of a named formal receiver binding: materialized
    /// methods carry declaration-owned procedure kinds, while external targets
    /// carry resolver-owned call shape. Other materialized targets still need
    /// complete candidate-specific call bindings. Anything less remains
    /// indeterminate and reaches the compiler's fail-closed diagnostic.
    pub(super) fn receiver_binding_applicability(
        &mut self,
        calls: &[(ProcedureHandle, CallSiteHandle)],
    ) -> Result<ReceiverBindingApplicability, PolicySelectorSessionError> {
        assert!(
            !calls.is_empty(),
            "receiver applicability requires at least one semantic call lowering"
        );
        let mut receiver_presence = calls.iter().map(|(procedure, call)| {
            procedure
                .semantics()
                .call_site(call.id())
                .expect("validated call handle resolves")
                .receiver
                .is_some()
        });
        let first = receiver_presence
            .next()
            .expect("non-empty semantic call set has one receiver state");
        if receiver_presence.any(|present| present != first) {
            return Ok(ReceiverBindingApplicability::Inconsistent);
        }
        if first
            && calls.iter().all(|(procedure, call)| {
                let row = procedure
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call handle resolves");
                matches!(
                    procedure
                        .semantics()
                        .proven_caller_receiver_binding(call.id()),
                    Some(CallerReceiverBinding::Bound(receiver))
                        if Some(receiver) == row.receiver
                )
            })
        {
            return Ok(ReceiverBindingApplicability::Applicable);
        }

        if !first
            && calls.iter().all(|(procedure, call)| {
                matches!(
                    procedure
                        .semantics()
                        .proven_caller_receiver_binding(call.id()),
                    Some(CallerReceiverBinding::Absent)
                )
            })
        {
            return Ok(ReceiverBindingApplicability::ExactNonMatch);
        }

        let oracle = self.workspace.semantic_oracle_provider();
        let leases = self.begin_semantic_lease_window();
        let mut exact_receiver = first;
        let mut exact_non_match = true;
        for (procedure, call) in calls {
            let dispatch_outcome = self.continue_semantic_in_window(&leases, |request| {
                oracle.resolve_call(call, request)
            })?;
            self.require_uninterrupted(&dispatch_outcome, "receiver-port dispatch")?;
            self.require_execution_budget("receiver-port dispatch")?;
            let proven_receiver_shape = match &dispatch_outcome {
                // `Unproven` can describe evidence outside receiver shape,
                // such as an unavailable external body. It does not weaken an
                // independently complete declaration or resolver proof.
                // Unknown, unsupported, ambiguous, interrupted, and
                // budget-limited outcomes remain unusable here.
                SemanticOutcome::Complete {
                    value: dispatch, ..
                }
                | SemanticOutcome::Unproven {
                    partial: dispatch, ..
                } => dispatch.proven_receiver_shape(),
                _ => None,
            };
            if let Some(has_receiver) = proven_receiver_shape {
                // An exact receiver-shape proof does not depend on whether the
                // declaration names its receiver. Accept only the exhaustive,
                // unanimous result above: an unproven shape or conflicting
                // target set remains indeterminate.
                exact_receiver &= first && has_receiver;
                exact_non_match &= !has_receiver;
                drop(dispatch_outcome);
                continue;
            }
            let exact_dispatch = dispatch_outcome.is_complete()
                && dispatch_outcome.available_value().is_some_and(|dispatch| {
                    dispatch.coverage() == CandidateCoverage::Exhaustive
                        && !dispatch.candidates().is_empty()
                        && dispatch.boundaries().is_empty()
                        && dispatch.candidates().iter().all(|candidate| {
                            matches!(candidate.proof(), ProofStatus::Proven)
                                && matches!(
                                    candidate.completeness(),
                                    EvidenceCompleteness::Complete
                                )
                        })
                });
            if !exact_dispatch {
                exact_receiver = false;
                exact_non_match = false;
                drop(dispatch_outcome);
                continue;
            }

            let dispatch = dispatch_outcome
                .available_value()
                .expect("an exact dispatch outcome retains its result");
            for candidate in dispatch.candidates() {
                let bindings_outcome = self.continue_semantic_in_window(&leases, |request| {
                    oracle.call_bindings(call, candidate, &OracleCallContext::empty(), request)
                })?;
                self.require_uninterrupted(&bindings_outcome, "receiver-port binding")?;
                self.require_execution_budget("receiver-port binding")?;
                let exact_bindings = bindings_outcome.is_complete()
                    && bindings_outcome.available_value().is_some_and(|bindings| {
                        bindings.coverage() == CandidateCoverage::Exhaustive
                    });
                if !exact_bindings {
                    exact_receiver = false;
                    exact_non_match = false;
                    drop(bindings_outcome);
                    continue;
                }
                let bindings = bindings_outcome
                    .available_value()
                    .expect("exact call bindings retain their result");
                let receiver_bindings = bindings
                    .bindings()
                    .iter()
                    .filter_map(|binding| match binding {
                        CallBinding::Receiver { actual, .. } => Some(actual.id()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let expected = procedure
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call handle resolves")
                    .receiver;
                exact_receiver &= receiver_bindings.as_slice() == expected.as_slice();
                exact_non_match &= receiver_bindings.is_empty();
                drop(bindings_outcome);
            }
            drop(dispatch_outcome);
        }
        leases.finish_scalar(
            if exact_receiver {
                ReceiverBindingApplicability::Applicable
            } else if exact_non_match {
                ReceiverBindingApplicability::ExactNonMatch
            } else if first {
                ReceiverBindingApplicability::CandidateReceiver
            } else {
                ReceiverBindingApplicability::Indeterminate
            },
            "receiver-port classification",
        )
    }

    fn apply_artifact_charge(
        &mut self,
        charge: Result<SemanticArtifactLeaseCharge, SemanticArtifactLeaseError>,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        let charge = charge.map_err(|error| {
            semantic_budget_error(format!(
                "{operation} exhausted the shared semantic retained-artifact budget: {error}"
            ))
        })?;
        if charge.is_empty() {
            return Ok(());
        }
        self.artifact_leases
            .try_apply_charge(charge, 0)
            .map_err(|error| {
                semantic_budget_error(format!(
                    "{operation} exhausted the shared semantic retained-artifact budget: {error}"
                ))
            })
    }

    pub(super) fn execution_budget(&self) -> &SemanticExecutionBudget {
        &self.semantic_execution_budget
    }

    pub(super) fn semantic_budget_mut(&mut self) -> &mut SemanticBudget {
        &mut self.semantic_budget
    }

    pub(super) fn semantic_used(&self) -> SemanticWork {
        self.semantic_budget.used()
    }

    pub(super) fn semantic_resident_peak(&self) -> SemanticWork {
        self.resident_peak
            .component_max(self.semantic_budget.resident_peak())
    }

    pub(super) fn semantic_root_work_peak(&self) -> SemanticWork {
        self.root_work_peak
            .component_max(self.semantic_budget.root_work_peak())
    }

    pub(super) fn semantic_remaining(&self) -> SemanticWork {
        self.semantic_budget.remaining()
    }

    pub(super) fn semantic_scope_snapshot(&self) -> SemanticBudgetScopeSnapshot {
        self.semantic_budget.scope_snapshot()
    }

    pub(super) fn query_work(&self) -> CodeQueryExecutionWork {
        self.query_work
    }

    pub(super) const fn result_contract_artifact_leases(&self) -> usize {
        self.result_contract_artifact_leases
    }

    pub(super) const fn retained_incomplete_result_contract_selectors(&self) -> usize {
        self.retained_incomplete_result_contract_selectors
    }

    #[cfg(all(test, feature = "test-support"))]
    pub(super) fn binding_candidate_count_for_test(&self) -> u64 {
        self.binding_candidate_probe.count()
    }

    pub(super) const fn selector_scans(&self) -> u64 {
        self.selector_scans
    }

    pub(super) fn materialized_artifacts(&self) -> impl Iterator<Item = &Arc<SemanticArtifact>> {
        self.artifacts.values().map(|entry| &entry.artifact)
    }

    pub(super) fn remember_artifact(&mut self, file: ProjectFile, artifact: Arc<SemanticArtifact>) {
        self.artifacts.entry(file).or_insert(MaterializedArtifact {
            artifact,
            reads: None,
            complete_key: None,
        });
    }

    /// Admit only the exact key of a charged Complete observed in this compile.
    /// A durable binding or a partial artifact can have the same read keys but
    /// has no typed outcome receipt here.
    pub(super) fn admits_rowless_complete(&self, key: &SemanticArtifactKey) -> bool {
        if self.semantic_stop_seen
            || self.semantic_budget.first_refusal().is_some()
            || self.semantic_execution_budget.work().exhausted
            || self.cancellation.is_cancelled()
        {
            return false;
        }
        let root = self.workspace.analyzer().project().root();
        let file = ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some(entry) = self.artifacts.get(&file) else {
            return false;
        };
        let Some(complete_key) = &entry.complete_key else {
            return false;
        };
        debug_assert_eq!(entry.artifact.key(), complete_key);
        // A refused stored-IR read prevents replay of the unit, but does not
        // make a complete artifact lowered from an overlay unusable here.
        let Some(reads) = entry
            .reads
            .as_ref()
            .filter(|reads| reads.unattributed_reads() == 0 && reads.execution_dependences() == 0)
        else {
            return false;
        };
        if complete_key != key {
            return false;
        }
        replay_query_reads(self.workspace.analyzer(), reads);
        true
    }

    pub(super) fn materialize_with_artifact_continuation(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Arc<SemanticArtifact>, PolicySelectorSessionError> {
        let workspace = self.workspace;
        let (continuation, reads) = capture_query_reads(workspace.analyzer(), || {
            self.continue_semantic(|request| workspace.materialize_program_semantics(file, request))
        });
        let continuation = continuation?;
        self.require_uninterrupted(continuation.outcome(), "program semantics materialization")?;
        self.require_execution_budget("program semantics materialization")?;
        if !continuation.outcome().is_complete() {
            return Err(PolicySelectorSessionError::Incomplete {
                completion: CodeQueryCompletion::Incomplete {
                    codes: vec![CodeQueryDiagnosticCode::SemanticAnalysisPartial],
                },
                detail: format!(
                    "program semantics are incomplete for {}",
                    file.abs_path().display()
                ),
            });
        }
        let artifact = continuation
            .outcome()
            .available_value()
            .cloned()
            .ok_or_else(|| unavailable_semantic_artifact(file))?;
        let outcome = continuation.commit(self, "program semantics materialization")?;
        drop(outcome);
        assert!(
            self.artifact_leases.snapshot().contains_exact(&artifact),
            "a complete typestate materialization is leased before its handle escapes"
        );
        self.artifacts.insert(
            file.clone(),
            MaterializedArtifact {
                artifact: Arc::clone(&artifact),
                reads: Some(reads),
                complete_key: None,
            },
        );
        Ok(artifact)
    }

    pub(super) fn take_artifact_leases(&mut self) -> PolicyArtifactLeases {
        {
            let snapshot = self.artifact_leases.snapshot();
            assert!(
                self.artifacts
                    .values()
                    .all(|entry| snapshot.contains_exact(&entry.artifact)),
                "typestate materialized artifacts must enter the lease ledger before handles escape"
            );
        }
        let max_retained_bytes = self.artifact_leases.max_retained_bytes();
        std::mem::replace(
            &mut self.artifact_leases,
            SemanticArtifactLeaseSet::new(max_retained_bytes),
        )
    }

    pub(super) fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Arc<SemanticArtifact>, PolicySelectorSessionError> {
        if let Some(entry) = self.artifacts.get(file) {
            if let Some(reads) = &entry.reads {
                replay_query_reads(self.workspace.analyzer(), reads);
            }
            return Ok(Arc::clone(&entry.artifact));
        }
        let workspace = self.workspace;
        let (outcome, reads) = capture_query_reads(workspace.analyzer(), || {
            let mut request = self.semantic_request();
            workspace
                .materialize_program_semantics(file, &mut request)
                .map_err(|error| PolicySelectorSessionError::Provider(error.to_string()))
        });
        let outcome = outcome?;
        self.require_uninterrupted(&outcome, "program semantics materialization")?;
        self.require_execution_budget("program semantics materialization")?;
        let complete = outcome.is_complete();
        let artifact = outcome
            .available_value()
            .cloned()
            .ok_or_else(|| unavailable_semantic_artifact(file))?;
        self.artifacts.insert(
            file.clone(),
            MaterializedArtifact {
                complete_key: complete.then(|| artifact.key().clone()),
                artifact: Arc::clone(&artifact),
                reads: Some(reads),
            },
        );
        Ok(artifact)
    }

    pub(super) fn require_execution_budget(
        &self,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        semantic_execution_budget_failure(&self.semantic_execution_budget, operation)
            .map_or(Ok(()), |detail| Err(semantic_budget_error(detail)))
    }

    pub(super) fn require_uninterrupted<T>(
        &self,
        outcome: &brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome<T>,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        semantic_outcome_failure(outcome, operation).map_or(Ok(()), |(completion, detail)| {
            Err(PolicySelectorSessionError::Incomplete { completion, detail })
        })
    }

    pub(super) fn work_report(&self, analysis: &str) -> PolicyWorkReport {
        // Report retired regions' work plus the live region's, so per-region
        // budget resets do not hide the compile's cumulative semantic cost.
        let semantic = self.semantic_budget.used();
        let execution = self.semantic_execution_budget.work();
        let semantic_peaks = self.semantic_peaks();
        let (row_work_peak, retained_work_peak, _) = self.region_peaks(semantic);
        let mut metrics: Vec<PolicyWorkMetric> = [
            (
                "semantic_materialized_files",
                PolicyWorkUnit::Count,
                self.retired_materialized_files
                    .saturating_add(execution.materialized_files),
            ),
            (
                "semantic_traversal_steps",
                PolicyWorkUnit::Count,
                self.retired_traversal_steps
                    .saturating_add(execution.traversal_steps),
            ),
            (
                "semantic_source_bytes",
                PolicyWorkUnit::Bytes,
                self.retired_source_bytes
                    .saturating_add(self.semantic_budget.performed().source_bytes),
            ),
            (
                "semantic_program_points",
                PolicyWorkUnit::Rows,
                self.retired_program_points
                    .saturating_add(semantic.program_points),
            ),
            // Each selector entry's subject scan is granted the whole-workspace
            // scan allowance, so this count is the multiplier on that allowance
            // the compile spent.  Reporting it keeps the compile's total scan
            // cost auditable instead of implicit in the entry list.
            (
                "selector_scans",
                PolicyWorkUnit::Count,
                usize::try_from(self.selector_scans).unwrap_or(usize::MAX),
            ),
            // Preserve the historical work-counter high-water marks across
            // regions. Resident refunds do not reduce these counters. The new
            // metrics below report residency; cache grants use semantic_peaks.
            (
                "semantic_peak_row_dimension",
                PolicyWorkUnit::Rows,
                self.work_peak_row_dimension.max(row_work_peak),
            ),
            (
                "semantic_peak_retained_bytes",
                PolicyWorkUnit::Bytes,
                self.work_peak_retained_bytes.max(retained_work_peak),
            ),
            (
                "semantic_resident_peak_nested_entries",
                PolicyWorkUnit::Rows,
                self.resident_peak
                    .nested_entries
                    .max(self.semantic_budget.resident_peak().nested_entries),
            ),
            (
                "semantic_resident_peak_retained_bytes",
                PolicyWorkUnit::Bytes,
                self.resident_peak
                    .owned_text_bytes
                    .max(self.semantic_budget.resident_peak().owned_text_bytes),
            ),
            (
                "semantic_peak_traversal_steps",
                PolicyWorkUnit::Count,
                semantic_peaks.traversal_steps,
            ),
            // The next three were once reported only when their counters had
            // moved, so a compile that materialized no value-flow snapshot
            // (#2284), saw no artifact-cache handle reuse (#2289), or took no
            // result-contract lease was not given a permanent zero. That
            // reasoning is reversed here, because the name set is not free.
            // Retention accounting sums metric name capacities
            // (`PolicyWorkReport::retained_size` feeds `PolicyRun`'s), and the
            // evaluator's retention search decides how many findings a run
            // keeps from that size. A name set that depends on the run's data
            // therefore makes the *retained finding set* depend on it. The
            // incremental/full equivalence contract requires byte-identical
            // reports, so the name set must be a function of the policy family
            // and the `analysis` label alone. #2659 already
            // settled that a permanent zero is the honest signal -- it says
            // the compile did none of this work, not that nothing was measured.
            (
                "semantic_snapshot_materializations",
                PolicyWorkUnit::Count,
                usize::try_from(self.semantic_snapshot_materializations).unwrap_or(usize::MAX),
            ),
            (
                "semantic_handle_identity_reuses",
                PolicyWorkUnit::Count,
                usize::try_from(self.semantic_handle_identity_reuses).unwrap_or(usize::MAX),
            ),
            (
                "semantic_result_contract_artifact_leases",
                PolicyWorkUnit::Count,
                self.result_contract_artifact_leases,
            ),
        ]
        .into_iter()
        .filter_map(|(name, unit, value)| {
            PolicyWorkMetric::try_new(
                format!("{analysis}.{name}"),
                unit,
                u64::try_from(value).unwrap_or(u64::MAX),
            )
            .ok()
        })
        .collect();
        let resident = self
            .resident_peak
            .component_max(self.semantic_budget.resident_peak());
        let root_work = self
            .root_work_peak
            .component_max(self.semantic_budget.root_work_peak());
        super::finding::append_semantic_budget_metrics(
            &mut metrics,
            analysis,
            self.retired_semantic.conservative_add(semantic),
            resident,
            root_work,
        );
        PolicyWorkReport::try_new(
            self.query_work.scanned_files,
            self.query_work.scanned_source_bytes,
            self.query_work.fact_nodes,
            self.query_work.pipeline_rows,
            self.query_work.examined_references,
            0,
            0,
            0,
            metrics,
        )
        .unwrap_or_default()
    }

    pub(super) fn semantic_peaks(&self) -> PolicySemanticPeaks {
        let (row_dimension, retained_bytes, traversal_steps) = self.live_region_peaks();
        PolicySemanticPeaks {
            row_dimension: self.peak_row_dimension.max(row_dimension),
            retained_bytes: self.peak_retained_bytes.max(retained_bytes),
            traversal_steps: self.peak_traversal_steps.max(traversal_steps),
        }
    }

    /// The current region's charge against each per-region lane, as
    /// `(largest row dimension, retained bytes, traversal steps)`.
    ///
    /// This calibrates `PolicyBudget`'s row lane, and that lane is one
    /// uniform `max_rows_per_dimension` granted to every row dimension, so
    /// the charge it must exceed is the largest single dimension's, not any
    /// one dimension's on its own. Queries inside the region are now capped
    /// per dimension from this budget's own remainders (#2523), but what is
    /// being calibrated here is still the uniform grant those remainders
    /// start from.
    fn live_region_peaks(&self) -> (usize, usize, usize) {
        let peak = self
            .semantic_budget
            .resident_peak()
            .component_max(self.semantic_budget.root_work_peak());
        self.region_peaks(peak)
    }

    fn region_peaks(&self, used: SemanticWork) -> (usize, usize, usize) {
        let row_peak = CodeQuerySemanticRowLimits::ROW_DIMENSIONS
            .into_iter()
            .map(|dimension| used.get(dimension))
            .max()
            .unwrap_or(0);
        (
            row_peak,
            used.owned_text_bytes
                .max(self.live_selector_retained_peak)
                .max(self.artifact_leases.retained_bytes()),
            self.semantic_execution_budget.work().traversal_steps,
        )
    }

    /// What one more selector query may spend, taken from this session's own
    /// shared ledger.
    ///
    /// The row lanes are published per dimension rather than collapsed. They
    /// deplete at wildly different rates -- `nested_entries` is a census of
    /// every artifact's nested collections and also the dispatch walk's
    /// exploration lane, while `procedures` counts one row per procedure --
    /// so one whole-workspace bind can legitimately spend most of the first
    /// while barely touching the second. Reporting the minimum of the
    /// remainders as a uniform cap made every later query in the session run
    /// against the most depleted lane: on google/gson, reference policy B's
    /// second bind published verdicts for 6 of its 98 marked procedures
    /// before it stopped (#2523). Each dimension now carries its own
    /// remainder, so a drained lane bounds itself and nothing else.
    ///
    /// The uniform scalar stays populated with the minimum. It is not read
    /// while the table is present, and the minimum is the value that cannot
    /// overrun any lane if some later consumer reads it alone.
    fn remaining_query_limits(
        &self,
    ) -> Result<CodeQueryExecutionLimits, PolicySelectorSessionError> {
        let semantic_remaining = self.semantic_budget.remaining();
        let semantic = CodeQuerySemanticLimits {
            max_materialized_files: self
                .semantic_execution_budget
                .remaining_materialized_files(),
            max_source_bytes: semantic_remaining.source_bytes,
            max_rows_per_dimension: CodeQuerySemanticRowLimits::ROW_DIMENSIONS
                .into_iter()
                .map(|dimension| semantic_remaining.get(dimension))
                .min()
                .unwrap_or(0),
            // This is a physical live-window cap, not an additive ledger
            // remainder. Sequential selectors release their windows, so each
            // receives the region's full cap; the forked provider budget is
            // independently bounded by `semantic_remaining.owned_text_bytes`.
            max_retained_bytes: self.query_limits.semantic.max_retained_bytes,

            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                semantic_remaining.get(dimension)
            })),
        };
        // The structural scan lanes are granted per selector entry, not shared
        // across the compile.  `PolicyBudget::scaled_for_workspace` sizes them to
        // one whole-workspace subject scan because that is what one selector
        // costs: Theta(workspace facts) (#1771).  Deducting each entry's scan
        // from the next entry's allowance therefore divides one whole-workspace
        // allowance across every source and sink a policy declares, so the
        // first entries consume it and the rest cannot run at all.  On OWASP
        // BenchmarkJava (2766 files, 11.5MB; scaled lane 5532 files, 23.1MB)
        // the third of the taint policy's nine selector entries was left 639
        // files and 2.57MB, exhausted mid-scan, and every category abstained
        // (#1935).  Each entry now gets the whole-workspace allowance; the
        // compile total stays bounded because `select` runs exactly once per
        // declared entry and the policy schema bounds those sets (`:entries`
        // is `SET_256` for sources and for sinks, and the registry bounds
        // match-directory endpoints at `MAX_REGISTERED_ENDPOINTS`).  The
        // `selector_scans` metric reports the multiplier this compile actually
        // used, so the total cost stays auditable rather than implicit.
        //
        // `max_pipeline_rows` follows workspace volume (#6420), but bounds
        // one query's materialized rows. It is not shared across entries;
        // retention remains per-query by construction.
        Ok(CodeQueryExecutionLimits {
            max_scanned_files: self.query_limits.max_scanned_files,
            max_scanned_source_bytes: self.query_limits.max_scanned_source_bytes,
            max_fact_nodes: self.query_limits.max_fact_nodes,
            max_pipeline_rows: self.query_limits.max_pipeline_rows,
            semantic,
            typestate: self.query_limits.typestate,
            value_flow: self.query_limits.value_flow,
            taint: self.query_limits.taint,
        })
    }

    fn charge_query_semantic_work(
        &mut self,
        work: CodeQuerySemanticWork,
        receipt: Option<CodeQuerySemanticReceipt>,
    ) -> Result<(), PolicySelectorSessionError> {
        self.charge_query_semantic_work_with_artifact_continuation(work, receipt, false)?;
        Ok(())
    }

    fn charge_query_semantic_work_with_artifact_continuation(
        &mut self,
        work: CodeQuerySemanticWork,
        receipt: Option<CodeQuerySemanticReceipt>,
        completed: bool,
    ) -> Result<Option<SemanticArtifactLeaseCharge>, PolicySelectorSessionError> {
        let semantic_work = self.selector_semantic_work(work);
        let Some(receipt) = receipt else {
            assert_eq!(
                work,
                CodeQuerySemanticWork::default(),
                "a selector that performs semantic work must return its one-shot charge",
            );
            return Ok(None);
        };
        let (semantic_charge, execution_before, execution_charge, artifact_charge) =
            receipt.into_parts();
        self.apply_query_charge(
            semantic_work,
            semantic_charge,
            execution_before,
            execution_charge,
        )?;
        if completed {
            Ok(Some(artifact_charge))
        } else {
            drop(artifact_charge);
            Ok(None)
        }
    }

    fn selector_semantic_work(&mut self, work: CodeQuerySemanticWork) -> SemanticWork {
        let usize_work = |value| usize::try_from(value).unwrap_or(usize::MAX);
        self.live_selector_retained_peak = self
            .live_selector_retained_peak
            .max(usize_work(work.retained_bytes));
        SemanticWork {
            source_bytes: usize_work(work.source_bytes),
            procedures: usize_work(work.procedures),
            blocks: usize_work(work.blocks),
            program_points: usize_work(work.program_points),
            values: usize_work(work.values),
            allocations: usize_work(work.allocations),
            call_sites: usize_work(work.call_sites),
            memory_locations: usize_work(work.memory_locations),
            captures: usize_work(work.captures),
            source_mappings: usize_work(work.source_mappings),
            evidence: usize_work(work.evidence),
            gaps: usize_work(work.gaps),
            events: usize_work(work.events),
            control_edges: usize_work(work.control_edges),
            nested_entries: usize_work(work.nested_entries),
            // CodeQuery reports a per-query live high-water mark here, not
            // additive semantic work. The child charge below carries the
            // provider's exact additive owned-text work.
            owned_text_bytes: 0,
        }
    }

    fn apply_query_charge(
        &mut self,
        semantic_work: SemanticWork,
        semantic_charge: brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetCharge,
        execution_before: brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudgetSnapshot,
        execution_charge: brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudgetCharge,
    ) -> Result<(), PolicySelectorSessionError> {
        if self
            .semantic_budget
            .check_child_charge(semantic_work, &semantic_charge)
            .is_err()
            || !self
                .semantic_execution_budget
                .can_replay_charge(&execution_before, &execution_charge)
        {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic materialization budget",
                self.analysis
            )));
        }
        assert!(
            self.semantic_execution_budget
                .replay_charge(&execution_before, &execution_charge),
            "the preflighted selector execution child extends the exclusively borrowed parent"
        );
        self.semantic_budget
            .apply_child_charge(semantic_work, semantic_charge)
            .expect("semantic charge was preflighted against an exclusively borrowed ledger");
        Ok(())
    }
}

/// An acquisition subject's selection: the sites to bind, and the candidates
/// whose selection could not be decided.
pub(super) struct SubjectSelection {
    pub(super) sites: Vec<PolicySelectedSite>,
    pub(super) undecided: Vec<UndecidedCandidate>,
}

pub(super) struct UndecidedCandidate {
    pub(super) file: ProjectFile,
    pub(super) span: ByteRange<usize>,
    pub(super) reasons: Vec<candidate_enumeration::CandidateReason>,
}

impl UndecidedCandidate {
    fn of(
        classified: &candidate_enumeration::ProvenSelectorClassification,
    ) -> impl Iterator<Item = Self> + '_ {
        classified
            .candidates()
            .filter_map(|(candidate, outcome)| match outcome {
                candidate_enumeration::CandidateOutcome::Undecided { reasons } => Some(Self {
                    file: candidate.file.clone(),
                    span: candidate.span.clone(),
                    reasons: reasons.clone(),
                }),
                _ => None,
            })
    }
}

/// A seed file's selector execution: complete, or the rows of one that was not.
enum SelectorUnitRun {
    Complete(Box<ExecutedSelectorUnit>),
    Incomplete(Box<UnitExecutionResult>),
}

/// One recomputed selector unit, both as the compile consumes it and as the
/// store would keep it.
struct ExecutedSelectorUnit {
    rows: UnitExecutionResult,
    sites: Vec<PolicySelectedSite>,
    product: SelectorProduct,
    /// The reads that licence publishing this unit, absent when the ledger
    /// could not name every read the execution made.
    reads: Option<Vec<ReadKey>>,
    publishable: bool,
}

/// Whether a selected site is one a stored product can name.
///
/// A site whose selection carries result-contract, call-shape, call-binding or
/// decorated-parameter evidence is derived from semantic identities the
/// product does not project, so the unit that produced it is used by this
/// compile and never published. Publishability is per unit: the units around
/// it are still independent partitions and stay reusable.
fn selector_site_is_projectable(site: &PolicySelectedSite) -> bool {
    site.result_contract.is_none()
        && site.call_shape.is_none()
        && site.call_binding.is_none()
        && site.decorated_parameter.is_none()
        && !site.runtime_keyed_read_row
        && site.runtime_keyed_read.is_none()
        && !site.runtime_keyed_read_conclusive_exclusion
        && site.occurrence_role != Some(OccurrenceRole::Binder)
        && !site.retained_incomplete_result_contract_query
}

fn project_selector_site(site: &PolicySelectedSite) -> SelectorProductSite {
    SelectorProductSite {
        rel_path: Box::from(rel_path_string(&site.file).as_str()),
        start: site.span.start,
        end: site.span.end,
        unproven: match &site.proof {
            ProofStatus::Proven => None,
            ProofStatus::Unproven(reason) => Some(reason.clone()),
        },
        partial: match &site.completeness {
            EvidenceCompleteness::Complete => None,
            EvidenceCompleteness::Partial(reason) => Some(reason.clone()),
        },
    }
}

/// Exhaustiveness is checked on the product rather than on how it was
/// obtained: a unit that truncated or raised a diagnostic is not a partition
/// of a whole execution, whichever run computed it.
fn lane(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The per-seed selector units of one policy compile.
///
/// One of these is built per compile that holds an incremental context. It
/// owns the shared reuse decision, the key of every unit every selector of the
/// policy asks about, and the count of what the compile did with them.
pub(super) struct SelectorUnits<'a> {
    reuse: UnitReuse<'a>,
    policy: &'a LoadedPolicy,
    incremental: &'a PolicyIncrementalContext<'a>,
    workspace_files: Vec<ProjectFile>,
    files_by_rel: HashMap<String, ProjectFile>,
    /// The keys of the selector this session is executing now, in seed order.
    current: Vec<PolicyUnitKey>,
    keys: Vec<PolicyUnitKey>,
    attempt: UnitAttempt,
    widen: Option<WidenReason>,
    /// Whether every unit this compile decided about is in the store. A run's
    /// unit list is what another run replays instead of evaluating the policy,
    /// so a list naming a unit that was never published would name work no run
    /// did.
    all_published: bool,
}

impl<'a> SelectorUnits<'a> {
    fn new(
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a crate::budget::PolicyBudget,
        workspace: &WorkspaceAnalyzer,
        flow: &brokk_bifrost_flow::FlowWorkspaceState,
    ) -> Self {
        let workspace_files = workspace.analyzer().analyzed_files();
        let files_by_rel = workspace_files
            .iter()
            .map(|file| (rel_path_string(file), file.clone()))
            .collect();
        Self {
            reuse: UnitReuse::new(policy, incremental, budget, flow),
            policy,
            incremental,
            workspace_files,
            files_by_rel,
            current: Vec::new(),
            keys: Vec::new(),
            attempt: UnitAttempt::default(),
            widen: None,
            all_published: true,
        }
    }

    /// Key every seed file of one selector, and load them all in one batch.
    fn enumerate(
        &mut self,
        query: &CodeQuery,
        selector_path: &str,
    ) -> Result<Vec<ProjectFile>, PolicySelectorSessionError> {
        if let Some(reason) = self
            .incremental
            .base_workspace_widen(&self.policy.definition().metadata.id)
        {
            return Err(PolicySelectorSessionError::Widen(reason));
        }
        // Set selectors must retain typed rows through the shared merge.
        // Only seed-local unions of structural matches have a site projection.
        if matches!(query.plan.source, CodeQueryPlanSource::Set { .. })
            && (PlanPartitioning::classify(&query.plan) != PlanPartitioning::BySeedUnion
                || query.validate_row_kinds().ok()
                    != Some(vec![brokk_bifrost_rql::QueryValueKind::StructuralMatch]))
        {
            self.attempt
                .set_widen_detail(Some(PlanWidenDetail::TypestateSetSource));
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::PlanCrossesSeeds,
            ));
        }
        if let PlanPartitioning::Whole(detail) = PlanPartitioning::classify(&query.plan) {
            self.attempt.set_widen_detail(Some(detail));
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::PlanCrossesSeeds,
            ));
        }
        // A changed-fact set that could not be completed is smaller than the
        // truth, and a smaller set would let a changed input pass verification.
        if !self.incremental.changed().is_complete() {
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::ReverseDependencyEvidenceMissing,
            ));
        }
        let seed_files = plan_seed_files(&query.plan, &self.workspace_files);
        self.attempt.enumerated(seed_files.len());
        let selector = StableDigest::sha256(selector_path);
        self.current = Vec::with_capacity(seed_files.len());
        for file in &seed_files {
            let language = language_for_file(file);
            let rel_path = rel_path_string(file);
            let Some(blob) = self.incremental.changed().head_blob(language, &rel_path) else {
                // Without the blob this path resolves to there is no content
                // identity to key the unit by, which is missing evidence rather
                // than evidence of sameness.
                return Err(PolicySelectorSessionError::Widen(
                    WidenReason::ReverseDependencyEvidenceMissing,
                ));
            };
            self.current.push(self.incremental.inputs().unit_key(
                self.policy,
                UnitPartition::Selector {
                    language,
                    rel_path: rel_path.into_boxed_str(),
                    blob,
                    selector,
                },
            ));
        }
        self.reuse
            .prefetch(&self.current, None)
            .map_err(PolicySelectorSessionError::Widen)?;
        self.keys.extend(self.current.iter().cloned());
        Ok(seed_files)
    }

    /// The published product for one seed file of the selector being compiled.
    fn published(
        &mut self,
        index: usize,
    ) -> Result<Option<SelectorProduct>, PolicySelectorSessionError> {
        let key = self.current[index].clone();
        match self
            .reuse
            .published(&key)
            .map_err(PolicySelectorSessionError::Widen)?
        {
            Some(product) => {
                self.attempt.reused();
                // One key names one product shape; anything else is a store
                // that answered a different question.
                let product = product
                    .into_selector()
                    .ok_or(PolicySelectorSessionError::Widen(
                        WidenReason::ProductLoadFailed,
                    ))?;
                Ok(Some(product))
            }
            None => {
                self.attempt.recomputed();
                Ok(None)
            }
        }
    }

    /// One stored product's sites, against this workspace's files.
    fn sites(
        &self,
        product: &SelectorProduct,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        product
            .sites
            .iter()
            .map(|site| {
                let file = self.files_by_rel.get(site.rel_path.as_ref()).ok_or(
                    // The unit verified against this head, so every path it
                    // named is a path this head analyzes.
                    PolicySelectorSessionError::Widen(
                        WidenReason::ReverseDependencyEvidenceMissing,
                    ),
                )?;
                Ok(PolicySelectedSite {
                    file: file.clone(),
                    span: site.start..site.end,
                    proof: match &site.unproven {
                        None => ProofStatus::Proven,
                        Some(reason) => ProofStatus::Unproven(reason.clone()),
                    },
                    completeness: match &site.partial {
                        None => EvidenceCompleteness::Complete,
                        Some(reason) => EvidenceCompleteness::Partial(reason.clone()),
                    },
                    result_contract: None,
                    call_shape: None,
                    call_binding: None,
                    selected_model_record: None,
                    selected_summary_record: None,
                    modeled_member_id: None,
                    modeled_target_origin: None,
                    decorated_parameter: None,
                    runtime_keyed_read: None,
                    runtime_keyed_read_row: false,
                    runtime_keyed_read_conclusive_exclusion: false,
                    occurrence_role: None,
                    retained_incomplete_result_contract_query: false,
                })
            })
            .collect()
    }

    /// Publish one recomputed unit under the reads that produced it.
    fn publish(&mut self, index: usize, executed: &ExecutedSelectorUnit) {
        if !executed.publishable {
            self.all_published = false;
            return;
        }
        let Some(reads) = executed.reads.clone() else {
            self.all_published = false;
            self.attempt.unbounded();
            return;
        };
        self.reuse.publish(
            self.current[index].clone(),
            PolicyUnitProduct::Selector(Box::new(executed.product.clone())),
            reads,
        );
    }

    fn widened(&mut self, reason: WidenReason) {
        self.widen.get_or_insert(reason);
    }

    /// A seed file answered by an execution that is not published.
    fn withhold(&mut self) {
        self.all_published = false;
    }

    fn into_outcome(mut self) -> SelectorUnitOutcome {
        // Consumers may share a selector, but the recorded dependency set
        // names each unit once. Preserve first-consumer order.
        let mut seen = HashSet::with_capacity(self.keys.len());
        self.keys.retain(|key| seen.insert(key.clone()));
        SelectorUnitOutcome {
            staged: self.reuse.take_staged(),
            all_published: self.all_published,
            keys: if self.all_published {
                self.keys
            } else {
                Vec::new()
            },
            attempt: self.attempt,
            widen: self.widen,
        }
    }
}

/// What one compile's selector units did.
///
/// `keys` is empty when any unit was not published, because a run's unit list
/// is what another run replays instead of evaluating the policy, and a list
/// naming a unit that was never published would name work no run did.
#[derive(Debug, Default)]
pub(super) struct SelectorUnitOutcome {
    pub(super) keys: Vec<PolicyUnitKey>,
    /// The units the compile recomputed, provisional until the solve that
    /// shares its attempt commits them or drops them.
    pub(super) staged: crate::units::StagedUnits,
    pub(super) attempt: UnitAttempt,
    pub(super) widen: Option<WidenReason>,
    pub(super) all_published: bool,
}

fn semantic_budget_error(detail: impl Into<String>) -> PolicySelectorSessionError {
    PolicySelectorSessionError::Incomplete {
        completion: incomplete_code_query_completion(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
        ),
        detail: detail.into(),
    }
}

pub(super) fn find_resolved_selector<'a>(
    selectors: &HashMap<&crate::definition::PolicySelectorPath, &'a ResolvedPolicySelector>,
    path: &crate::definition::PolicySelectorPath,
) -> Option<&'a ResolvedPolicySelector> {
    selectors.get(path).copied()
}

fn unavailable_semantic_artifact(file: &ProjectFile) -> PolicySelectorSessionError {
    PolicySelectorSessionError::Unavailable(format!(
        "program semantics are unavailable for {}",
        file.abs_path().display()
    ))
}

pub(super) fn incomplete_code_query_completion(
    code: CodeQueryDiagnosticCode,
) -> CodeQueryCompletion {
    CodeQueryCompletion::Incomplete { codes: vec![code] }
}

pub(super) fn semantic_execution_budget_failure(
    budget: &SemanticExecutionBudget,
    operation: &str,
) -> Option<String> {
    budget
        .work()
        .exhausted
        .then(|| format!("{operation} exhausted the shared semantic file or traversal budget"))
}

pub(super) fn semantic_outcome_failure<T>(
    outcome: &SemanticOutcome<T>,
    operation: &str,
) -> Option<(CodeQueryCompletion, String)> {
    match outcome {
        SemanticOutcome::Cancelled { .. } => Some((
            CodeQueryCompletion::Cancelled,
            format!("{operation} was cancelled"),
        )),
        SemanticOutcome::ExceededBudget { exceeded, .. } => Some((
            incomplete_code_query_completion(CodeQueryDiagnosticCode::SemanticBudgetExhausted),
            format!("{operation} exceeded the shared semantic budget: {exceeded}"),
        )),
        SemanticOutcome::Complete { .. }
        | SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unsupported { .. }
        | SemanticOutcome::Unproven { .. } => None,
    }
}

pub(super) fn semantic_resident_limits(limits: CodeQuerySemanticLimits) -> SemanticWork {
    use SemanticBudgetDimension as Dimension;
    SemanticWork {
        source_bytes: limits.max_source_bytes,
        procedures: limits.rows(Dimension::Procedures),
        blocks: limits.rows(Dimension::Blocks),
        program_points: limits.rows(Dimension::ProgramPoints),
        values: limits.rows(Dimension::Values),
        allocations: limits.rows(Dimension::Allocations),
        call_sites: limits.rows(Dimension::CallSites),
        memory_locations: limits.rows(Dimension::MemoryLocations),
        captures: limits.rows(Dimension::Captures),
        source_mappings: limits.rows(Dimension::SourceMappings),
        evidence: limits.rows(Dimension::Evidence),
        gaps: limits.rows(Dimension::Gaps),
        events: limits.rows(Dimension::Events),
        control_edges: limits.rows(Dimension::ControlEdges),
        nested_entries: limits.rows(Dimension::NestedEntries),
        owned_text_bytes: limits.max_retained_bytes,
    }
}

pub(super) fn source_range(span: &ByteRange<usize>) -> Range {
    Range {
        start_byte: span.start,
        end_byte: span.end,
        start_line: 0,
        end_line: 0,
    }
}

pub(super) fn selected_site_quality(
    item: &CodeQueryResultItem,
) -> (ProofStatus, EvidenceCompleteness) {
    let semantic = match &item.value {
        CodeQueryResultValue::Procedure { value } => Some(&value.evidence),
        CodeQueryResultValue::ProgramPoint { value } => Some(&value.evidence),
        CodeQueryResultValue::ControlEdge { value } => Some(&value.evidence),
        CodeQueryResultValue::TypestateWitness { value } => Some(&value.evidence),
        CodeQueryResultValue::AbsentMemberWitness { value } => Some(&value.evidence),
        CodeQueryResultValue::TaintFinding { value } => Some(&value.evidence),
        _ => None,
    };
    let (proof, mut completeness) = if let Some(semantic) = semantic {
        semantic_binding_quality(semantic)
    } else {
        match &item.value {
            CodeQueryResultValue::DependencyEvidence { value } => (
                ProofStatus::Proven,
                if value.complete {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial("dependency file record was only partially interpreted".into())
                },
            ),
            CodeQueryResultValue::PythonRuleFact { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Python rule fact evidence is incomplete".into())
                            .into(),
                    )
                },
            ),
            CodeQueryResultValue::RustMarkerImpl { value } => (
                proof_from_label(if value.completeness == "complete" { "proven" } else { "unproven" }),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "Rust marker impl evidence is incomplete".to_owned()
                            .into(),
                    )
                },
            ),
            CodeQueryResultValue::RustPointerFinding { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Rust pointer finding evidence is incomplete".into())
                            .into(),
                    )
                },
            ),
            CodeQueryResultValue::TypestateFinding { value } => (
                if value.path_proven {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("selector path is unproven".into())
                },
                if value.path_complete && value.analysis_complete {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial("selector analysis is incomplete".into())
                },
            ),
            CodeQueryResultValue::ReferenceSite { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            CodeQueryResultValue::CallSite { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" && value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "call-site target is unresolved or candidate coverage is incomplete".into(),
                    )
                },
            ),
            CodeQueryResultValue::PointsToCandidate { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" && value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "points-to candidate set is not exhaustive".into(),
                    )
                },
            ),
            CodeQueryResultValue::JsxAttributeValue { value } => (
                ProofStatus::Proven,
                if value.coverage == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reason
                            .unwrap_or("JSX attribute value projection is incomplete")
                            .to_string()
                            .into(),
                    )
                },
            ),
            CodeQueryResultValue::FieldWriteValue { value } => (
                if value.proof == "precise" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        format!("field-write proof is {}", value.proof).into(),
                    )
                },
                if value.completeness == "complete" && value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!(
                            "field-write evidence is completeness={}, coverage={}",
                            value.completeness, value.coverage
                        )
                        .into(),
                    )
                },
            ),
            CodeQueryResultValue::RuntimeKeyedReadValue { value } => {
                if value.terminal {
                    if value.conclusive_exclusion && value.outcome == "conclusive_exclusion" {
                        (ProofStatus::Proven, EvidenceCompleteness::Complete)
                    } else {
                        (
                            ProofStatus::Unproven(
                                "runtime keyed-read endpoint coverage is incomplete".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                format!(
                                    "runtime keyed-read limitations are {:?}",
                                    value.limitations
                                )
                                .into(),
                            ),
                        )
                    }
                } else {
                    let proof = proof_from_label(value.proof);
                    let completeness = if value.outcome == "endpoint"
                        && value.completeness == "complete"
                        && value.source_origin == "pristine_runtime_input"
                    {
                        EvidenceCompleteness::Complete
                    } else {
                        EvidenceCompleteness::Partial(
                            format!(
                                "runtime keyed-read evidence is outcome={}, source_origin={}, completeness={}",
                                value.outcome, value.source_origin, value.completeness
                            )
                            .into(),
                        )
                    };
                    (proof, completeness)
                }
            }
            // An edge row carries its own proof attribution, exactly as a
            // reference site does; set-level completeness is the query's
            // diagnostics' business (#1479).
            CodeQueryResultValue::ReferenceEdge { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            // A flow-state row is exactly what the derivation computed; its
            // per-axis account is the row's own `completeness` field, so a
            // partial derivation makes the selector's evidence partial rather
            // than silently complete (#1480).
            CodeQueryResultValue::StateEvent { value } => (
                ProofStatus::Proven,
                flow_state_completeness(value.completeness, &value.uncovered_axes),
            ),
            // Each relation row is an exact binding-to-call AST link; overall
            // derivation completeness is carried by query diagnostics.
            CodeQueryResultValue::BindingInitializerCall { .. } => {
                (ProofStatus::Proven, EvidenceCompleteness::Complete)
            }
            CodeQueryResultValue::FlowRelation { value } => (
                ProofStatus::Proven,
                flow_state_completeness(value.completeness, &value.uncovered_axes),
            ),
            // A control-relation row states its own per-relation completeness
            // the same way, so a derivation whose budget ran out makes the
            // selector's evidence partial rather than silently complete
            // (#2443).
            CodeQueryResultValue::ControlRelation { value } => (
                ProofStatus::Proven,
                control_relation_completeness(value.completeness, &value.uncovered_relations),
            ),
            CodeQueryResultValue::BranchRelation { value } => (
                ProofStatus::Proven,
                if value.verdict == "open" {
                    EvidenceCompleteness::Partial(format!(
                        "branch relation is open: {:?}",
                        value.reason
                    ).into())
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::LoopRelation { value } => (
                ProofStatus::Proven,
                if value.verdict == "open" {
                    EvidenceCompleteness::Partial(
                        format!("loop relation is open: {:?}", value.reasons).into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::StatementReachability { value } => (
                ProofStatus::Proven,
                if value.verdict == "open" {
                    EvidenceCompleteness::Partial(
                        format!("statement reachability is open: {:?}", value.reason).into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::PendingCleanupFlow { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        format!("pending cleanup proof is {}", value.proof).into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("pending cleanup flow is incomplete: {:?}", value.reason).into(),
                    )
                },
            ),
            CodeQueryResultValue::FailureHandlerState { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        format!("failure handler proof is {}", value.proof).into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("failure handler is incomplete: {:?}", value.reason).into(),
                    )
                },
            ),
            // A guard row carries the IR evidence of the decision it records,
            // so an unproven or partial lowering makes the selector's evidence
            // unproven or partial rather than silently clean (#2443).
            CodeQueryResultValue::Guard { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "guard lowering evidence is partial".into(),
                    )
                },
            ),
            CodeQueryResultValue::CallResult { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "call-result lowering evidence is partial".into(),
                    )
                },
            ),
            CodeQueryResultValue::ResultSubjectUse { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("normal-result subject coverage is incomplete").into(),
                    )
                },
            ),
            // A topology row states its own completeness the same way: a build
            // model nobody could read in full makes the selector's evidence
            // partial rather than silently complete (#2448).
            CodeQueryResultValue::SourceSet { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            CodeQueryResultValue::BuildTarget { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            CodeQueryResultValue::TopologyEdge { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            // An undecided build constraint makes the selector's evidence
            // partial: the row cannot say whether the file is built (#9048).
            CodeQueryResultValue::BuildConfiguration { value } => (
                ProofStatus::Proven,
                if value.file_status == "unknown"
                    || value.os_scope == "unknown"
                    || value.arch_scope == "unknown"
                {
                    EvidenceCompleteness::Partial(
                        "the file's build constraint is undecided under its build configuration"
                            .into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            // A rewrite-path row states its own per-domain completeness the
            // same way, so a derivation that could not run makes the
            // selector's evidence partial rather than silently complete
            // (#1480).
            CodeQueryResultValue::RewritePath { value } => (
                ProofStatus::Proven,
                rewrite_path_completeness(value.completeness, &value.uncovered_domains),
            ),
            CodeQueryResultValue::ReceiverAnalysis { .. }
            | CodeQueryResultValue::MemberTargetAnalysis { .. }
            | CodeQueryResultValue::FlowEndpoint { .. }
            | CodeQueryResultValue::FlowWitness { .. } => (
                ProofStatus::Unproven("selector evidence is not exact".into()),
                EvidenceCompleteness::Partial("selector evidence is not exhaustive".into()),
            ),
            CodeQueryResultValue::CallShape { value } => (
                ProofStatus::Proven,
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("call shape coverage is {}", value.coverage).into(),
                    )
                },
            ),
            // A signature row is proven evidence of what the analyzer
            // persisted, but it is only complete when the language actually
            // recorded an arity. An `arity_unrecorded` or `unrecorded` row
            // must turn an exact-arity assertion unreliable rather than clean.
            CodeQueryResultValue::CallableSignature { value } => (
                ProofStatus::Proven,
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("callable signature coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::LiteralOccurrence { value } => (
                if value.coverage == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("literal decoder coverage is open".into())
                },
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("literal occurrence coverage is {}", value.coverage).into(),
                    )
                },
            ),
            // Callable-metrics rows are exact only when the shared AST walk
            // and ownership evidence are exact. Incomplete and unrecorded
            // rows keep selector policies open, so a stale overlay cannot
            // become a clean negative by omission.
            CodeQueryResultValue::CallableMetrics { value } => {
                if value.coverage == "exact" {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    (
                        ProofStatus::Unproven(
                            format!("callable metrics coverage is {}", value.coverage).into(),
                        ),
                        EvidenceCompleteness::Partial(
                            format!("callable metrics coverage is {}", value.coverage).into(),
                        ),
                    )
                }
            }
            // A parameter row whose optionality the language never recorded
            // cannot support a required-versus-optional claim.
            CodeQueryResultValue::SignatureParameter { value } => (
                ProofStatus::Proven,
                if value.optional.is_some() {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "declared parameter optionality is unrecorded".into(),
                    )
                },
            ),
            // A decorated parameter is an exact source anchor, but a policy
            // endpoint can bind its value only when the row retained a
            // complete parameter port and decorator-binding identity.
            CodeQueryResultValue::DecoratedParameter { value } => {
                let complete = value.terminal
                    && value.completion == "complete"
                    && value.coverage == "complete"
                    && value.procedure_id.is_some()
                    && value.value_id.is_some()
                    && value.parameter_ordinal.is_some()
                    && value.port_id.is_some();
                if complete {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    (
                        ProofStatus::Unproven(
                            "decorated parameter binding or value port is incomplete".into(),
                        ),
                        EvidenceCompleteness::Partial(
                            "decorated parameter binding or value port is incomplete".into(),
                        ),
                    )
                }
            }
            // An overload-selection summary is proven evidence of what the
            // resolver considered, but it is complete only when every verdict
            // was decidable. `unknown_shape` -- an unsupported language, an
            // untraced site, or any undecidable candidate -- must turn an
            // exact-cardinality assertion over the site unreliable rather than
            // clean.
            CodeQueryResultValue::OverloadSelection { value } => (
                ProofStatus::Proven,
                if value.resolution == "unknown_shape" {
                    EvidenceCompleteness::Partial(
                        if value.supported {
                            "overload selection is undecidable at this site"
                        } else {
                            "this language does not report callable applicability"
                        }
                        .into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            // A candidate whose applicability nobody could decide cannot
            // support an applicable-or-not claim.
            CodeQueryResultValue::CallableApplicability { value } => (
                ProofStatus::Proven,
                if value.verdict == "unknown" {
                    EvidenceCompleteness::Partial(
                        "candidate applicability is undecided".into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::CallArgumentGroup { .. }
            | CodeQueryResultValue::CallArgument { .. } => (
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            ),
            // An effect row's own quality is its derivation and its coverage:
            // a `declared` row with an exhaustive site or procedure is a
            // complete claim, and anything else admits a missing effect.
            CodeQueryResultValue::CallEffect { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("call effect coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ResultContractUse { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-contract use coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ResultContractFailureUse { value } => (
                proof_from_label(value.proof),
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-contract failure-use coverage is {}", value.coverage)
                            .into(),
                    )
                },
            ),
            // Result-contract identity is a dispatch-derived claim. A row can
            // have exhaustive candidate coverage while its target proof is
            // still unproven, so neither axis may be inferred from query-level
            // completion alone.
            CodeQueryResultValue::CallResultContract { value } => (
                value.proof.map_or_else(
                    || ProofStatus::Unproven("result-contract dispatch proof is absent".into()),
                    proof_from_label,
                ),
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-contract dispatch coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::CallResultObligation { value } => (
                if !value.terminal && value.coverage == "exhaustive" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("reviewed result obligation is not established".into())
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-obligation coverage is {}: {:?}", value.coverage, value.reason).into(),
                    )
                },
            ),
            CodeQueryResultValue::ProcedureEffect { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("procedure effect coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::CallBinding { value } => (
                if value.selector_exact {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("call-binding selector proof is absent".into())
                },
                if value.mapping == "exact"
                    && value.coverage == "exhaustive"
                    && value.selector_exact
                    && value.selector_proof.is_some()
                    && ((!value.terminal
                        && value.argument_id.is_some())
                        || (value.terminal && value.actual_count == 0))
                {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!(
                            "call binding is mapping={}, coverage={}, terminal={}, selector={}/{:?}, dispatch={}/{}/{:?}, targets={}, truncated={}",
                            value.mapping,
                            value.coverage,
                            value.terminal,
                            value.selector_exact,
                            value.selector_proof,
                            value.dispatch_outcome,
                            value.dispatch_coverage,
                            value.dispatch_completeness,
                            value.dispatch_target_count,
                            value.dispatch_targets_truncated,
                        )
                        .into(),
                    )
                },
            ),
            CodeQueryResultValue::ReceiverOutcome { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("receiver outcome coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ReceiverEvidence { value } => (
                proof_from_label(value.proof),
                if value.completeness == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("receiver evidence is {}", value.completeness).into(),
                    )
                },
            ),
            CodeQueryResultValue::MemberSelection { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("member selection coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::NilnessOperation { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value.reason.unwrap_or("nilness proof is open").into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("nilness coverage is open").into(),
                    )
                },
            ),
            CodeQueryResultValue::SwitchCoverage { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value.reason.unwrap_or("switch coverage proof is open").into(),
                    )
                },
                if value.verdict == "unknown" {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("switch coverage is unknown").into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::AssignmentRelation { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value
                            .reason
                            .unwrap_or("assignment relation proof is open")
                            .into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reason
                            .unwrap_or("assignment relation coverage is open")
                            .into(),
                    )
                },
            ),
            // A class-set row's own status is its proof story: only a `known`
            // row is a proven claim, every other status carries no proof.
            CodeQueryResultValue::ClassSetRow { value } => (
                if value.status == "known" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("class-set row carries no proof".into())
                },
                if value.status == "known" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("class-set status is {}", value.status).into(),
                    )
                },
            ),
            // A proven absent-member finding fires only on a fully known class
            // set and a proven-absent member lookup, so the row is its own
            // proof; set-level completeness is the query diagnostics'
            // business, the reference-edge precedent. A conditional finding
            // proves the class and the absence but not that the class is the
            // only value that reaches the access, so it is reported unproven
            // with the open remainders as its partial evidence.
            CodeQueryResultValue::AbsentMemberFinding { value } => {
                if value.proof == "proven" {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    let condition = value
                        .condition
                        .as_deref()
                        .expect("a conditional absent-member row states its condition");
                    (
                        ProofStatus::Unproven(condition.into()),
                        EvidenceCompleteness::Partial(
                            format!(
                                "receiver class set is open: {}",
                                value.remainders.join(", ")
                            )
                            .into(),
                        ),
                    )
                }
            }
            CodeQueryResultValue::DetachedTaskTransfer { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value.reason.unwrap_or("detached object identity is open").into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("detached object identity is open").into(),
                    )
                },
            ),
            CodeQueryResultValue::PythonHierarchyFact { value } => (
                ProofStatus::Proven,
                if value.coverage == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!(
                            "Python hierarchy fact is open: outcome={}, reason={:?}",
                            value.outcome, value.reason
                        )
                        .into(),
                    )
                },
            ),
            CodeQueryResultValue::StructuralMatch { .. }
            | CodeQueryResultValue::CppExpression { .. }
            | CodeQueryResultValue::Declaration { .. }
            | CodeQueryResultValue::File { .. }
            | CodeQueryResultValue::CandidateHop { .. }
            | CodeQueryResultValue::DispatchOutcome { .. }
            | CodeQueryResultValue::DispatchTarget { .. }
            | CodeQueryResultValue::MemberFamily { .. }
            | CodeQueryResultValue::MemberFamilyEdge { .. }
            | CodeQueryResultValue::ExpressionSite { .. }
            // An occurrence row is an exact parser fact about one token. Its
            // completeness question is per role and is answered by the query's
            // diagnostics, not by this per-row evidence judgement.
            | CodeQueryResultValue::Occurrence { .. }
            // A scope, a binding and a candidate row are each an exact record
            // of what one producer derived at one position; whether the *set*
            // is complete is per axis and is answered by the query's
            // diagnostics, exactly as for an occurrence.
            | CodeQueryResultValue::LexicalScope { .. }
            | CodeQueryResultValue::Binding { .. }
            | CodeQueryResultValue::ResolutionCandidate { .. }
            // The materialization rows follow the same reasoning (#1476):
            // each is an exact record of recorded provenance, and per-axis
            // completeness arrives through the query's diagnostics.
            | CodeQueryResultValue::GenerationSite { .. }
            | CodeQueryResultValue::Export { .. }
            | CodeQueryResultValue::DeclarationState { .. }
            // A configuration-fact row is an exact parser record of one
            // authored document fact (#3277); whether the ingested document
            // set is whole arrives through the query's diagnostics, never
            // through this per-row judgement.
            | CodeQueryResultValue::ConfigurationFact { .. }
            // A cross-domain row records one structurally proven pair or one
            // contributing row of a satisfied requirement (#3284); a key that
            // names several facts is the row's own `binding` column, and
            // input completeness arrives through the query's diagnostics.
            | CodeQueryResultValue::CrossDomain { .. }
            // The identity-route rows are parser facts with the same per-axis
            // completeness story (#1475).
            | CodeQueryResultValue::QualifiedPath { .. }
            | CodeQueryResultValue::PathSegment { .. } => {
                (ProofStatus::Proven, EvidenceCompleteness::Complete)
            }
            CodeQueryResultValue::Procedure { .. }
            | CodeQueryResultValue::ProgramPoint { .. }
            | CodeQueryResultValue::ControlEdge { .. }
            | CodeQueryResultValue::TypestateWitness { .. }
            | CodeQueryResultValue::AbsentMemberWitness { .. }
            | CodeQueryResultValue::TaintFinding { .. } => {
                unreachable!("semantic result evidence was handled above")
            }
        }
    };
    if item.provenance_truncated {
        completeness = EvidenceCompleteness::Partial("selector provenance was truncated".into());
    }
    (proof, completeness)
}

fn semantic_binding_quality(
    evidence: &CodeQuerySemanticEvidence,
) -> (ProofStatus, EvidenceCompleteness) {
    let proof = match evidence.proof {
        CodeQuerySemanticProof::Proven => ProofStatus::Proven,
        CodeQuerySemanticProof::Unproven => {
            ProofStatus::Unproven("selector semantic evidence is unproven".into())
        }
    };
    let completeness = match evidence.completeness {
        CodeQuerySemanticCompleteness::Complete => EvidenceCompleteness::Complete,
        CodeQuerySemanticCompleteness::Partial => {
            EvidenceCompleteness::Partial("selector semantic evidence is partial".into())
        }
    };
    (proof, completeness)
}

/// The evidence completeness one flow-state row carries (#1480).
///
/// `partial` is never silently upgraded: the uncovered axes travel into the
/// reason string so a policy reader sees which part of the derivation is
/// missing rather than a bare "incomplete".
fn flow_state_completeness(
    completeness: &str,
    uncovered_axes: &[&'static str],
) -> EvidenceCompleteness {
    derivation_completeness(completeness, "flow-state", uncovered_axes)
}

/// The evidence completeness one rewrite-path row carries (#1480).
fn rewrite_path_completeness(
    completeness: &str,
    uncovered_domains: &[&'static str],
) -> EvidenceCompleteness {
    derivation_completeness(completeness, "rewrite-path", uncovered_domains)
}

fn derivation_completeness(
    completeness: &str,
    derivation: &str,
    uncovered: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "{derivation} derivation does not cover [{}]",
                uncovered.join(", ")
            )
            .into(),
        )
    }
}

fn topology_completeness(completeness: &str) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            "the workspace's declared build topology was not read in full".into(),
        )
    }
}

fn control_relation_completeness(
    completeness: &str,
    uncovered_relations: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "control-relation derivation does not cover [{}]",
                uncovered_relations.join(", ")
            )
            .into(),
        )
    }
}

fn proof_from_label(label: &str) -> ProofStatus {
    if label == "proven" {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven(format!("selector evidence is {label}").into())
    }
}

/// Whether one formal parameter slot names `expected`.
///
/// A slot carries every spelling the declaration gives one parameter, because
/// some languages name a formal twice (Swift's external and internal labels)
/// and some prefix it in source but not in a call (PHP's `$value`). Matching
/// any spelling is what lets one authored `(argument :name "value")` bind the
/// same formal in every language that declares it.
pub(super) fn parameter_names_match(names: &[String], expected: &str) -> bool {
    names
        .iter()
        .any(|name| parameter_name_matches(name, expected))
}

/// The single-spelling form of [`parameter_names_match`], for a name taken
/// from a call's keyword actual rather than from a declaration slot.
pub(super) fn parameter_name_matches(name: &str, expected: &str) -> bool {
    name == expected
        || name.strip_prefix('$') == Some(expected)
        || expected.strip_prefix('$') == Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_candidate_enumeration_whitelist_and_limits() {
        use super::candidate_enumeration::*;
        let source = "(resolved-call :resolves-to \"java.nio.file.Files.newInputStream\" :proof declared (language java (call-bindings (call-shape (call :callee (name \"open\"))))))";
        let query = CodeQuery::from_source(source).unwrap();
        let selector = WhitelistedCallSelector::check(&query).expect("whitelisted pipeline");
        assert_eq!(selector.target_fqn, "java.nio.file.Files.newInputStream");
        assert_eq!(selector.callee_name, "open");
        assert_eq!(selector.language, Language::Java);
        for steps in [
            vec![QueryStep::CallShape, query.plan.steps[2].clone()],
            vec![
                QueryStep::CallShape,
                QueryStep::CallBindings,
                QueryStep::FileOf,
            ],
            {
                let mut steps = query.plan.steps.clone();
                steps.push(QueryStep::FileOf);
                steps
            },
        ] {
            let mut other = query.clone();
            other.plan.steps = steps;
            assert!(WhitelistedCallSelector::check(&other).is_none());
        }
        let code = "class App { void run() { open(); other(); open(); } }";
        let project = InlineTestProject::with_language(Language::Java)
            .file("App.java", code)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let _request =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        let cancellation = CancellationToken::default();
        let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let inventory =
            CompleteStructuralCandidateEnumeration::enumerate(&mut session, &selector).unwrap();
        let candidates = inventory.candidates();
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|c| c.file.rel_path() == std::path::Path::new("App.java"))
        );
        assert_eq!(
            candidates
                .iter()
                .map(|c| c.span.clone())
                .collect::<Vec<_>>(),
            vec![25..31, 42..48]
        );
        let scope = session.execution_scope.clone();
        let (captured, receipts) = inventory
            .execute(&mut session, &selector, &query, scope)
            .unwrap();
        assert!(
            receipts.take().is_some(),
            "execution must reach split receipt producer"
        );
        let ordinary = session.execute_selector_query(&query).unwrap();
        assert_eq!(captured.result.results.len(), ordinary.result.results.len());
        assert_eq!(captured.result.completion(), ordinary.result.completion());
        // A complete structural inventory does not turn a filtered-away row
        // into a rejection. Missing proof remains an explicit silent drop.
        let locations = candidate_locations(inventory.candidates());
        let selected = selected_candidate_bindings(&locations, &captured).unwrap();
        for candidate in inventory.candidates() {
            let outcome = outcome_for(candidate, &selected, &HashSet::new(), Vec::new());
            assert!(
                matches!(outcome, CandidateOutcome::Undecided { reasons } if matches!(reasons.as_slice(), [CandidateReason::SilentDrop]))
            );
            let gap = brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ArtifactUnavailable(
                "test missing artifact".into(),
            );
            assert!(
                matches!(outcome_for(candidate, &selected, &HashSet::new(), vec![gap]), CandidateOutcome::Undecided { reasons } if matches!(reasons.as_slice(), [CandidateReason::Read(_)]))
            );
        }
        let first = &inventory.candidates()[0];
        let isolated_receipts =
            brokk_bifrost_rql::structural::search::CallBindingReadReceipts::default();
        let anchors = std::sync::Arc::new(
            brokk_bifrost_rql::structural::search::OwnedCallAnchors::new(
                first.file.clone(),
                vec![first.span.clone()],
                inventory
                    .candidates()
                    .iter()
                    .map(|candidate| candidate.span.clone())
                    .collect(),
            ),
        );
        let (mut isolated, semantic_receipt) = session
            .execute_selector_query_core(
                &query,
                CodeQueryExecutionScope::whole_workspace()
                    .with_owned_call_anchors(anchors)
                    .with_isolated_call_binding_receipts(isolated_receipts.clone()),
            )
            .unwrap();
        session
            .charge_query_semantic_work(isolated.work.semantic, semantic_receipt)
            .unwrap();
        assert!(
            isolated_receipts.take_isolated().is_some(),
            "isolated call-binding boundary must run"
        );
        isolated.work.semantic.budget_exhausted = true;
        assert!(
            global_stop(&isolated),
            "a budget stop cannot enter candidate isolation"
        );
        let non_whitelisted = CodeQuery::from_source("(language java (call))").unwrap();
        assert!(
            session
                .classify_selector_candidates(&non_whitelisted)
                .unwrap()
                .is_none()
        );
        let mut limited = query.clone();
        limited.limit = 1;
        let limited = WhitelistedCallSelector::check(&limited).unwrap();
        assert!(matches!(
            CompleteStructuralCandidateEnumeration::enumerate(&mut session, &limited),
            Err(CandidateEnumerationRefusal::Truncated)
        ));
    }

    #[test]
    fn selected_summary_record_follows_the_authored_proof_only() {
        let accepted = |proves, exact, proof, digest, record| {
            accepted_summary_record(proves, exact, proof, digest, record)
        };
        let expected = Some(("pack-digest".to_owned(), "summary-id".to_owned()));
        assert_eq!(
            accepted(
                false,
                true,
                Some("authored_summary"),
                Some("pack-digest"),
                Some("summary-id")
            ),
            expected,
            "declaration origin is not an input: model and source targets alike"
        );
        for (proves, exact, proof) in [
            (true, true, Some("authored_summary")),
            (false, false, Some("authored_summary")),
            (false, true, Some("derived")),
            (false, true, None),
        ] {
            assert_eq!(
                accepted(
                    proves,
                    exact,
                    proof,
                    Some("pack-digest"),
                    Some("summary-id")
                ),
                None
            );
        }
        assert_eq!(
            accepted(
                false,
                true,
                Some("authored_summary"),
                Some("pack-digest"),
                None
            ),
            None
        );
    }

    #[test]
    fn selected_model_record_rejects_incomplete_candidate_provenance() {
        let selected = accepted_model_record(
            true,
            true,
            false,
            Some("semantic_model"),
            false,
            Some("pack-digest"),
            Some("member-id"),
        );
        assert_eq!(selected, Some(("pack-digest".into(), "member-id".into())));
        assert_eq!(
            accepted_model_record(
                true,
                false,
                true,
                Some("semantic_model"),
                false,
                Some("pack-digest"),
                Some("member-id")
            ),
            selected,
            "a receiver-only Unique external binding has no rendered target"
        );
        // A partial pack can supply this exact selected member: pack-wide
        // completeness is deliberately absent from the acceptance test.
        assert_eq!(
            accepted_model_record(
                true,
                false,
                false,
                Some("semantic_model"),
                false,
                Some("pack-digest"),
                Some("member-id")
            ),
            None
        );
        assert_eq!(
            accepted_model_record(
                false,
                true,
                true,
                Some("semantic_model"),
                false,
                Some("pack-digest"),
                Some("member-id")
            ),
            None
        );
        assert_eq!(
            accepted_model_record(
                true,
                true,
                true,
                Some("semantic_model"),
                true,
                Some("pack-digest"),
                Some("member-id")
            ),
            None
        );
    }
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::{
        PolicyBudget, PolicySelectorPath, PolicySourceIdentity, SchemaVersionOrigin,
        SchemaVersionResolution, SelectorOrigin,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
        acquire_active_semantic_models, compile_source,
    };
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
    use brokk_bifrost_rql::structural::CodeQuery;
    use brokk_bifrost_test_macros::hardwon;

    const EXACT_EXTERNAL_RECEIVER_MODEL: &str = r#"{
  "schema_version": 2,
  "pack_id": "bifrost.test.go.external-receiver",
  "version": "1.0.0",
  "producer": { "name": "bifrost-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.6, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test fixture", "revision": "1" },
  "license": "MIT",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "go.external.receiver.declarations",
    "activation": [{}],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "type.external-module",
        "name": "example.com/external",
        "type_kind": "module",
        "visibility": "package",
        "is_abstract": false,
        "is_sealed": false,
        "has_explicit_type_terms": false,
        "type_parameters": [],
        "type_parameter_constraints": [],
        "embedded_types": [],
        "hierarchy": [],
        "aliases": ["external"],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external"
        }
      }, {
        "id": "type.external-resource",
        "name": "example.com/external.Resource",
        "type_kind": "struct",
        "visibility": "public",
        "is_abstract": false,
        "is_sealed": false,
        "has_explicit_type_terms": false,
        "type_parameters": [],
        "type_parameter_constraints": [],
        "embedded_types": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Resource"
        }
      }],
      "members": [{
        "id": "member.external-open",
        "owner": "type.external-module",
        "name": "Open",
        "member_kind": "function",
        "visibility": "public",
        "is_static": true,
        "is_abstract": false,
        "is_virtual": false,
        "signature": {
          "type_parameters": [],
          "parameters": [],
          "returns": {
            "kind": "tuple",
            "elements": [{
              "kind": "pointer",
              "element": {
                "kind": "declared",
                "id": "type.external-resource",
                "arguments": [],
                "nullable": false
              }
            }, {
              "kind": "named",
              "name": "error",
              "arguments": [],
              "nullable": false
            }]
          }
        },
        "aliases": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Open"
        }
      }, {
        "id": "member.external-resource-read",
        "owner": "type.external-resource",
        "name": "Read",
        "member_kind": "method",
        "visibility": "public",
        "is_static": false,
        "is_abstract": false,
        "is_virtual": false,
        "signature": {
          "type_parameters": [],
          "parameters": [],
          "returns": {
            "kind": "named",
            "name": "error",
            "arguments": [],
            "nullable": false
          }
        },
        "receiver": { "pointer": true },
        "aliases": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Resource.Read"
        }
      }],
      "relations": []
    }
  }, {
    "id": "go.external.receiver.summaries",
    "activation": [{}],
    "payload": {
      "kind": "procedure_summaries",
      "summaries": [{
        "id": "external.open",
        "target": {
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Open()",
          "has_receiver": false,
          "parameter_count": 0
        },
        "completeness": "complete",
        "normal_result_count": 2,
        "transfers": [],
        "effects": [],
        "result_contracts": [{
          "result_ordinal": 0,
          "condition_result_ordinal": 1,
          "predicate": "null",
          "result_success_predicate": "non_null",
          "member_contracts": [{
            "member": "Read",
            "parameter_count": 0,
            "completeness": "complete",
            "preconditions": []
          }]
        }]
      }]
    }
  }]
}"#;

    #[test]
    fn scoped_selector_keeps_excluded_source_dependency_reads() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "src/Included.java",
                "class Included { void run() { dep.Api.useDependency(1); } }",
            )
            .file(
                "excluded/dep/Api.java",
                "package dep; public class Api { public static void useDependency(int value) {} }",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let seed = project.file("src/Included.java");
        let files = workspace.analyzer().analyzed_files();
        let selector = resolved_selector(
            r#"(language java (call-bindings (call-shape (call :callee (name "useDependency")))))"#,
            "/analysis/test",
        );
        let (selected, reads) = brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(
            workspace.analyzer(),
            || {
                let _request =
                    brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
                let cancellation = CancellationToken::default();
                let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
                let mut session = PolicySelectorSession::new(
                    &workspace,
                    &flow,
                    "test",
                    PolicyBudget::default().query_limits(),
                    64,
                    &cancellation,
                    CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&seed), &files),
                );
                session.select_with_artifact_continuation(&selector)
            },
        );
        assert!(!selected.unwrap().is_empty());
        assert!(
            format!("{:?}", reads.keys()).contains("excluded/dep/Api.java"),
            "{:?}",
            reads.keys()
        );
    }

    #[test]
    #[hardwon("#10985: isolation exhausted file budgets and discarded recovered binding rows")]
    fn candidate_isolation_keeps_the_complete_sibling_selected() {
        use super::candidate_enumeration::{CandidateOutcome, CandidateReason};
        // Test-only declarations, derived from the small receiver fixture in
        // this module. The Api surface is closed; String's callable inventory
        // deliberately remains unavailable.
        let mut model: serde_json::Value =
            serde_json::from_str(EXACT_EXTERNAL_RECEIVER_MODEL).unwrap();
        model["schema_version"] = serde_json::json!(19);
        model["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        model["pack_id"] = serde_json::json!("test.candidate-isolation");
        model["language"] = serde_json::json!("java");
        model["ecosystem"] = serde_json::json!("jdk");
        model["shards"].as_array_mut().unwrap().truncate(1);
        let mut api = model["shards"][0]["payload"]["types"][0].clone();
        api["id"] = serde_json::json!("type.api");
        api["name"] = serde_json::json!("test.Api");
        api["type_kind"] = serde_json::json!("class");
        api["visibility"] = serde_json::json!("public");
        api["aliases"] = serde_json::json!([]);
        api["locator"] = serde_json::json!({"kind":"artifact", "path":"test-only/test/Api.java", "symbol":"test.Api"});
        api["jvm_inventory"] = serde_json::json!({"callables_complete":true,"values_complete":true,"types_complete":true,"supertypes_complete":true,"supertypes":[],"nested_types":[],"additional_members":[]});
        let mut object = api.clone();
        object["id"] = serde_json::json!("type.object");
        object["name"] = serde_json::json!("java.lang.Object");
        object["locator"]["path"] = serde_json::json!("test-only/java/lang/Object.java");
        object["locator"]["symbol"] = serde_json::json!("java.lang.Object");
        let mut string = object.clone();
        string["id"] = serde_json::json!("type.string");
        string["name"] = serde_json::json!("java.lang.String");
        string["locator"]["path"] = serde_json::json!("test-only/java/lang/String.java");
        string["locator"]["symbol"] = serde_json::json!("java.lang.String");
        string["jvm_inventory"]["callables_complete"] = serde_json::json!(false);
        let mut open = model["shards"][0]["payload"]["members"][0].clone();
        open["id"] = serde_json::json!("member.api-open");
        open["owner"] = serde_json::json!("type.api");
        open["name"] = serde_json::json!("open");
        open["member_kind"] = serde_json::json!("method");
        open["callable_family_complete"] = serde_json::json!(true);
        open["signature"]["returns"] =
            serde_json::json!({"kind":"named","name":"void","arguments":[],"nullable":false});
        open["locator"] = serde_json::json!({"kind":"artifact", "path":"test-only/test/Api.java", "symbol":"test.Api.open(int,int)"});
        open["signature"]["parameters"] = serde_json::json!([
            {"name":"a","type":{"kind":"named","name":"int","arguments":[],"nullable":false},"optional":false,"variadic":false},
            {"name":"b","type":{"kind":"named","name":"int","arguments":[],"nullable":false},"optional":false,"variadic":false}
        ]);
        model["shards"][0]["payload"]["types"] = serde_json::json!([api, object, string]);
        model["shards"][0]["payload"]["members"] = serde_json::json!([open]);
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&model).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("test declarations: {diagnostics:?}"));
        let mut project = InlineTestProject::with_language(Language::Java)
            .file(
                "Known.java",
                format!(
                    "class Known {{ void run() {{ {} }} }}",
                    "test.Api.open(1, 2);".repeat(64)
                ),
            )
            .file(
                "Unknown.java",
                "class Unknown { void run() { String.open(1, 2); } }",
            );
        for index in 0..64 {
            project = project.file(
                format!("Unrelated{index}.java"),
                format!("class Unrelated{index} {{}}"),
            );
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:candidate-isolation".into(),
                },
            )
            .unwrap();
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".into(),
                    ecosystem: "jdk".into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
            "{activation:?}"
        );
        let _request =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        let cancellation = CancellationToken::default();
        let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        // One batch workspace scan plus one file per candidate must fit.
        // Repeating workspace scans exhausted this shared allowance instead.
        session.query_limits.max_scanned_files = workspace.project_file_count() + 65;
        let mut query = CodeQuery::from_source(r#"(resolved-call :resolves-to "test.Api.open" :proof declared (language java (call-bindings (call-shape (call :callee (name "open"))))))"#).unwrap();
        query.limit = 256;
        crate::locator::resolve_query_locators(
            &mut query,
            &mut Vec::new(),
            crate::locator::LocatorResolution::Analyzer(workspace.analyzer()),
        )
        .unwrap();
        let mut default_session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        // Opt-in measurement reuses the hard-won mixed corpus and production
        // counters. Initialization and model activation are outside samples.
        if std::env::var_os("BIFROST_MEASURE_CANDIDATE_ISOLATION").is_some() {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
                begin_production_selected_sql_trace, finish_production_selected_sql_trace,
            };
            for complete in [false, true] {
                for classify in [false, true] {
                    let complete_files = [ProjectFile::new(project.root(), "Known.java")];
                    let scope = if complete {
                        CodeQueryExecutionScope::whole_workspace()
                            .restrict_seed_files(&complete_files)
                    } else {
                        CodeQueryExecutionScope::whole_workspace()
                    };
                    let mut measured = PolicySelectorSession::new(
                        &workspace,
                        &flow,
                        "test",
                        PolicyBudget::default().query_limits(),
                        256,
                        &cancellation,
                        scope,
                    );
                    let store = workspace.store().unwrap();
                    begin_production_selected_sql_trace(store);
                    let started = brokk_bifrost_analysis::profiling::thread_cpu_time();
                    if classify {
                        let result = measured
                            .classify_selector_candidates(&query)
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            result
                                .candidates()
                                .filter(|(_, outcome)| matches!(
                                    outcome,
                                    CandidateOutcome::Undecided { .. }
                                ))
                                .count(),
                            usize::from(!complete)
                        );
                    } else {
                        measured.execute_selector_query(&query).unwrap();
                    }
                    let cpu = brokk_bifrost_analysis::profiling::thread_cpu_time()
                        .saturating_sub(started);
                    let sql = finish_production_selected_sql_trace(store);
                    eprintln!(
                        "M1_COST complete={complete} classify={classify} cpu_seconds={:.6} selected_reader_sql={} scans={} work={:?}",
                        cpu.as_secs_f64(),
                        sql.statement_count(),
                        measured.selector_scans,
                        measured.query_work
                    );
                }
            }
        }
        let default = default_session.execute_selector_query(&query).unwrap();
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace, finish_production_selected_sql_trace,
        };
        let store = workspace.store().expect("fixture workspace store");
        begin_production_selected_sql_trace(store);
        let classified = session
            .classify_selector_candidates(&query)
            .unwrap_or_else(|error| panic!("classification: {error:?}"))
            .expect("whitelisted");
        let selected_sql = finish_production_selected_sql_trace(store);
        eprintln!(
            "candidate isolation selected-reader SQL: statements={}, decoded_rows={}",
            selected_sql.statement_count(),
            selected_sql.decoded_rows,
        );
        let outcomes = classified.candidates().collect::<Vec<_>>();
        assert_eq!(outcomes.len(), 65);
        assert!(
            session.semantic_execution_budget.work().traversal_steps >= outcomes.len(),
            "anchor inventory preprocessing is charged to request traversal work"
        );
        assert!(
            session.query_work.scanned_files
                <= u64::try_from(workspace.project_file_count() + outcomes.len()).unwrap()
                    + classified.batch_result_for_binding().work.scanned_files,
            "enumeration and batch scan the workspace; isolation scans one candidate file: {:?}",
            session.query_work,
        );
        assert_eq!(
            serde_json::to_value(&default.result).unwrap(),
            serde_json::to_value(&classified.batch_result_for_binding().result).unwrap(),
            "opting in preserves the batched answer"
        );
        let diagnostics = outcomes
            .iter()
            .map(|(candidate, outcome)| match outcome {
                CandidateOutcome::Selected { .. } => format!("{}: Selected", candidate.file),
                CandidateOutcome::Rejected => format!("{}: Rejected", candidate.file),
                CandidateOutcome::Undecided { reasons } => {
                    format!("{}: Undecided {reasons:?}", candidate.file)
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|(candidate, outcome)| candidate.file.rel_path()
                    == std::path::Path::new("Known.java")
                    && matches!(
                        outcome,
                        CandidateOutcome::Selected {
                            proof: ProofStatus::Proven,
                            completeness: EvidenceCompleteness::Complete,
                            ..
                        }
                    ))
                .count(),
            64,
            "{diagnostics:?}"
        );
        assert!(outcomes.iter().any(|(candidate, outcome)| candidate.file.rel_path() == std::path::Path::new("Unknown.java") && matches!(outcome, CandidateOutcome::Undecided { reasons } if reasons.iter().any(|reason| matches!(reason, CandidateReason::Read(_))))), "{diagnostics:?}");
        for (index, (candidate, outcome)) in classified.candidates().enumerate() {
            let bindings = classified.selected_bindings(index).collect::<Vec<_>>();
            if matches!(outcome, CandidateOutcome::Selected { .. }) {
                assert_eq!(
                    bindings.len(),
                    2,
                    "each selected call retains both argument bindings"
                );
                assert!(bindings.iter().all(|(row, evidence)| evidence.file == candidate.file && matches!(&row.value, CodeQueryResultValue::CallBinding { value } if value.site_ast_id == candidate.ast_id)));
            } else {
                assert!(bindings.is_empty());
            }
        }
        eprintln!(
            "candidate isolation corpus: Known.java=64 complete calls, Unknown.java=1 gap; selector scans={}, query work={:?}",
            session.selector_scans, session.query_work
        );
        // Simulate a complete candidate silently disappearing from the
        // incomplete batch. Isolation must restore all of its binding data,
        // not only the Selected label, and rebase both evidence indices.
        let dropped_id = outcomes
            .iter()
            .find(|(candidate, _)| candidate.file.rel_path() == std::path::Path::new("Known.java"))
            .unwrap()
            .0
            .ast_id
            .clone();
        assert!(classified.into_conservative_result().is_err());
        let mut recovery_session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            256,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        super::candidate_enumeration::drop_next_batch_site(dropped_id.clone());
        let recovered = recovery_session
            .classify_selector_candidates(&query)
            .unwrap()
            .unwrap();
        let assert_recovered =
            |recovered: super::candidate_enumeration::ProvenSelectorClassification| {
                let recovered_index = recovered
                    .candidates()
                    .position(|(candidate, outcome)| {
                        candidate.ast_id == dropped_id
                            && matches!(outcome, CandidateOutcome::Selected { .. })
                    })
                    .expect("isolated selection recovered");
                let expected = default.evidence.iter().filter_map(|evidence| {
            let row = &default.result.results[evidence.result_index];
            matches!(&row.value, CodeQueryResultValue::CallBinding { value } if value.site_ast_id == dropped_id).then_some((row, evidence))
        }).collect::<Vec<_>>();
                let actual = recovered
                    .selected_bindings(recovered_index)
                    .collect::<Vec<_>>();
                assert_eq!(actual.len(), 2);
                assert_eq!(expected.len(), 2);
                for ((row, evidence), (expected_row, expected_evidence)) in
                    actual.iter().zip(&expected)
                {
                    assert_eq!(
                        serde_json::to_value(row).unwrap(),
                        serde_json::to_value(expected_row).unwrap()
                    );
                    let mut expected_evidence = (*expected_evidence).clone();
                    expected_evidence.result_index = evidence.result_index;
                    assert_eq!(**evidence, expected_evidence);
                }
                assert_eq!(
                    recovered.batch_result_for_binding().result.results.len(),
                    default.result.results.len()
                );
                assert!(recovered.into_conservative_result().is_err());
            };
        assert_recovered(recovered);
        let dropped_row = default
            .result
            .results
            .iter()
            .find_map(|row| match &row.value {
                CodeQueryResultValue::CallBinding { value } if value.site_ast_id == dropped_id => {
                    Some(value.id.clone())
                }
                _ => None,
            })
            .unwrap();
        let mut partial_session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            256,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        super::candidate_enumeration::drop_next_batch_row(dropped_row);
        assert_recovered(
            partial_session
                .classify_selector_candidates(&query)
                .unwrap()
                .unwrap(),
        );

        // The complete batch path uses the same published AST-ID index for
        // multiple rows per site, with no isolation or per-row fact traversal.
        let complete_file = ProjectFile::new(project.root(), "Known.java");
        let mut complete_session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            256,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace()
                .restrict_seed_files(std::slice::from_ref(&complete_file)),
        );
        let complete = complete_session
            .classify_selector_candidates(&query)
            .unwrap()
            .unwrap();
        assert_eq!(complete.candidates().count(), 64);
        assert_eq!(
            complete_session.selector_scans, 2,
            "complete batches do not isolate"
        );
        for (index, (_, outcome)) in complete.candidates().enumerate() {
            assert!(matches!(outcome, CandidateOutcome::Selected { .. }));
            assert_eq!(complete.selected_bindings(index).count(), 2);
        }
        assert_eq!(
            complete
                .into_conservative_result()
                .unwrap()
                .result
                .results
                .len(),
            128
        );

        // M3: a scoped subject read must neither visit the undecidable sibling
        // nor seed the whole-workspace memo used for event and terminal roles.
        let selector = ResolvedPolicySelector::try_new(
            PolicySelectorPath::new("/analysis/subjects/test").unwrap(),
            SchemaVersionResolution {
                version: 1,
                origin: SchemaVersionOrigin::Explicit,
            },
            query.clone(),
            SelectorOrigin::Document {
                source: PolicySourceIdentity::new("test.rqlp"),
            },
        )
        .unwrap();
        let mut scoped_session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            256,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let scope =
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::capturing_read_incompleteness(
                workspace.analyzer(),
            );
        let scoped = scoped_session
            .select_subject_candidates_in_scope(
                &selector,
                CodeQueryExecutionScope::whole_workspace()
                    .restrict_seed_files(std::slice::from_ref(&complete_file)),
            )
            .unwrap();
        assert!(scoped.undecided.is_empty());
        assert_eq!(scoped.sites.len(), 128);
        assert!(
            scope.captured_read_incompleteness().is_empty(),
            "{:?}",
            scope.captured_read_incompleteness()
        );
        // An auxiliary selector must still execute the global query and
        // encounter its undecidable sibling, even after scoped selection.
        assert!(
            scoped_session
                .select_with_artifact_continuation(&selector)
                .is_err()
        );
        let global = scoped_session.select_subject_candidates(&selector).unwrap();
        assert_eq!(global.undecided.len(), 1);
        assert_eq!(
            global.undecided[0].file.rel_path(),
            std::path::Path::new("Unknown.java")
        );
        let narrowed = scoped_session
            .select_subject_candidates_in_scope(
                &selector,
                CodeQueryExecutionScope::whole_workspace()
                    .restrict_seed_files(std::slice::from_ref(&complete_file)),
            )
            .unwrap();
        assert_eq!(narrowed.sites.len(), 128);
        assert!(narrowed.undecided.is_empty());

        let mut setup_session = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        super::candidate_enumeration::force_next_setup_gap();
        assert!(
            matches!(setup_session.classify_selector_candidates(&query), Err(PolicySelectorSessionError::Incomplete { detail, .. }) if detail.contains("selector setup incomplete"))
        );
        assert_eq!(
            setup_session.selector_scans, 2,
            "enumeration and batch only; setup failure forbids isolation"
        );
        let mut limited = PolicySelectorSession::new(
            &workspace,
            &flow,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let selector =
            super::candidate_enumeration::WhitelistedCallSelector::check(&query).unwrap();
        let proof =
            super::candidate_enumeration::CompleteStructuralCandidateEnumeration::enumerate(
                &mut limited,
                &selector,
            )
            .unwrap();
        limited.query_limits.max_pipeline_rows = 1;
        let scans = limited.selector_scans;
        assert!(matches!(
            proof.classify(&mut limited, &selector, &query),
            Err(PolicySelectorSessionError::Incomplete { .. })
        ));
        assert_eq!(
            limited.selector_scans - scans,
            1,
            "a batch budget stop forbids isolation"
        );
    }

    fn one_file_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "subject.go",
                "package subject\n\nfunc subject() {}\nfunc second() {}\nfunc third() {}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, workspace)
    }

    #[test]
    #[hardwon("#8386: a cached selector artifact lost its original materialization reads")]
    fn cached_materialization_replays_its_receipt_to_sites_and_partitions() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            capture_query_reads, capture_query_reads_deferred,
        };

        let (project, workspace) = one_file_workspace();
        let file = ProjectFile::new(project.root(), "subject.go");
        let cancellation = CancellationToken::default();
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &flow_state,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let analyzer = workspace.analyzer();
        let ((cold, warm_site, warm_partition, cold_reads, site_reads, partition_reads), whole) =
            capture_query_reads(analyzer, || {
                let (cold, cold_reads) =
                    capture_query_reads_deferred(analyzer, || session.materialize(&file).unwrap());
                replay_query_reads(analyzer, &cold_reads);
                let charged = session.semantic_used();
                let (warm_site, site_reads) =
                    capture_query_reads_deferred(analyzer, || session.materialize(&file).unwrap());
                replay_query_reads(analyzer, &site_reads);
                let (warm_partition, partition_reads) =
                    capture_query_reads_deferred(analyzer, || session.materialize(&file).unwrap());
                replay_query_reads(analyzer, &partition_reads);
                assert_eq!(
                    session.semantic_used(),
                    charged,
                    "cached reads do not recharge work"
                );
                (
                    cold,
                    warm_site,
                    warm_partition,
                    cold_reads,
                    site_reads,
                    partition_reads,
                )
            });
        assert!(Arc::ptr_eq(&cold, &warm_site));
        assert!(Arc::ptr_eq(&cold, &warm_partition));
        assert!(!cold_reads.keys().is_empty());
        assert_eq!(cold_reads.keys(), site_reads.keys());
        assert_eq!(cold_reads.keys(), partition_reads.keys());
        assert_eq!(cold_reads.keys(), whole.keys());
        assert!(session.admits_rowless_complete(cold.key()));

        let mut unobserved = PolicySelectorSession::new(
            &workspace,
            &flow_state,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        unobserved.remember_artifact(file, Arc::clone(&cold));
        assert!(!unobserved.admits_rowless_complete(cold.key()));

        use brokk_bifrost_analysis::analyzer::{OverlayProject, Project};
        let overlay = Arc::new(OverlayProject::new(project.project_dyn()));
        assert!(overlay.set(
            project.root().join("subject.go"),
            "package subject\n\nfunc subject() {}\nfunc second() {}\nfunc third() {}\n// revised\n"
                .to_owned(),
        ));
        let snapshot: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let overlay_workspace = workspace.clone_with_project(snapshot);
        let mut overlay_session = PolicySelectorSession::new(
            &overlay_workspace,
            &flow_state,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let overlay_artifact = overlay_session
            .materialize(&ProjectFile::new(project.root(), "subject.go"))
            .unwrap();
        assert_ne!(cold.key(), overlay_artifact.key());
        assert!(!session.admits_rowless_complete(overlay_artifact.key()));

        cancellation.cancel();
        assert!(!session.admits_rowless_complete(cold.key()));
    }

    #[test]
    #[hardwon(
        "#3732: keep located taint findings from partial selector discovery without claiming completion"
    )]
    fn taint_selection_retains_located_rows_under_a_result_limit() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "subject.go",
                "package subject\nfunc target(value int) {}\nfunc run() { target(1); target(2) }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let selector = resolved_selector(
            "(language go (call-bindings (call-shape (call :callee (name \"target\")))))",
            "/analysis/sources/entries/target/selector",
        );
        let cancellation = CancellationToken::default();
        let limits = PolicyBudget::default().query_limits();
        let mut limited = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "taint",
            limits,
            1,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let retained = limited
            .select_taint(&selector)
            .expect("a located positive row survives incomplete enumeration");
        assert_eq!(retained.len(), 1);
        assert_eq!(limited.take_incomplete_taint_selectors().len(), 1);

        let mut complete = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "taint",
            limits,
            16,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert_eq!(complete.select_taint(&selector).unwrap().len(), 2);
        assert!(complete.take_incomplete_taint_selectors().is_empty());
    }

    #[test]
    fn zero_argument_call_binding_retains_the_call_site() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "subject.go",
                "package subject\n\nfunc source() {}\nfunc caller() { source() }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let selector = resolved_selector(
            "(language go (call-bindings (call-shape (call :callee (name \"source\") (arity 0)))))",
            "/analysis/sources/zero-argument",
        );
        let cancellation = CancellationToken::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "taint",
            PolicyBudget::default().query_limits(),
            16,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        let selected = session
            .select_taint(&selector)
            .expect("an exact zero-argument call binding is a usable source site");

        assert_eq!(selected.len(), 1);
        assert!(
            selected[0].call_binding.is_none(),
            "a terminal row has no operand binding but retains its call-site span"
        );
        assert!(selected[0].span.start < selected[0].span.end);
    }

    #[test]
    #[hardwon(
        "#10014: an exact receiver-only binding of a zero-argument call was dropped under incomplete discovery"
    )]
    fn exact_receiver_only_binding_is_usable_under_incomplete_discovery() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "App.java",
                "class App { void zero() {} void run() { new App().zero(); } }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let selector = resolved_selector(
            "(language java (call-bindings (call-shape (call :callee (name \"zero\") (arity 0)))))",
            "/analysis/sinks/zero",
        );
        let cancellation = CancellationToken::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "taint",
            PolicyBudget::default().query_limits(),
            16,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let (_, query) = selector.as_query().expect("query selector");
        let (detailed, _) = session
            .execute_selector_query_core(query, CodeQueryExecutionScope::whole_workspace())
            .expect("call-binding query");
        let (index, item) = detailed
            .result
            .results
            .iter()
            .enumerate()
            .find(|(_, item)| matches!(&item.value, CodeQueryResultValue::CallBinding { value } if value.binding_kind == Some("receiver")))
            .expect("receiver binding");
        let evidence = detailed
            .evidence
            .iter()
            .find(|row| row.result_index == index)
            .expect("located receiver evidence");
        let mut item = item.clone();
        let CodeQueryResultValue::CallBinding { value } = &mut item.value else {
            unreachable!("selected receiver binding");
        };
        // Give the located row the proof fields of the model-backed JDK row
        // that was dropped (`File.exists()` in the CodeQL CWE-022 test).
        value.target = None;
        value.declared_target_id = None;
        value.target_origin = Some("model");
        value.coverage = "exhaustive";
        value.mapping = "exact";
        value.actual_count = 0;
        value.bound_count = 0;
        value.formal_layout_id = Some("layout".into());
        value.selector_proof = Some("authored_summary");
        value.selector_exact = true;
        value.semantic_target_id = Some("target".into());
        value.model_callable_id = Some("callable".into());
        assert!(!value.terminal);
        assert_eq!(value.argument_id, None);
        assert_eq!(value.actual_index, None);
        assert_eq!(value.formal_index, None);
        assert!(usable_taint_row(&item, evidence, None));

        if let CodeQueryResultValue::CallBinding { value } = &mut item.value {
            value.mapping = "incomplete";
        }
        assert!(!usable_taint_row(&item, evidence, None));
        if let CodeQueryResultValue::CallBinding { value } = &mut item.value {
            value.mapping = "exact";
            value.formal_layout_id = None;
            value.selector_proof = None;
        }
        assert!(!usable_taint_row(&item, evidence, None));
    }

    fn cfg_entry_selector(name: &str, path: &str) -> ResolvedPolicySelector {
        let query = CodeQuery::from_source(&format!(
            r#"(cfg-entry (procedure-of (function :name "{name}")))"#
        ))
        .expect("valid semantic selector");
        ResolvedPolicySelector::try_new(
            PolicySelectorPath::new(path).expect("valid selector path"),
            SchemaVersionResolution {
                version: u32::try_from(query.schema_version).expect("u32 schema version"),
                origin: SchemaVersionOrigin::Explicit,
            },
            query,
            SelectorOrigin::Document {
                source: PolicySourceIdentity::new("test.rqlp"),
            },
        )
        .expect("resolved selector")
    }

    fn resolved_selector(source: &str, path: &str) -> ResolvedPolicySelector {
        let query = CodeQuery::from_source(source).expect("valid test selector");
        ResolvedPolicySelector::try_new(
            PolicySelectorPath::new(path).expect("valid selector path"),
            SchemaVersionResolution {
                version: u32::try_from(query.schema_version).expect("u32 schema version"),
                origin: SchemaVersionOrigin::Explicit,
            },
            query,
            SelectorOrigin::Document {
                source: PolicySourceIdentity::new("test.rqlp"),
            },
        )
        .expect("resolved selector")
    }

    fn limits_for_one_census_and_repeats(
        mut limits: CodeQueryExecutionLimits,
        census: SemanticWork,
        retained_peak: usize,
        repeats: usize,
    ) -> CodeQueryExecutionLimits {
        let row_limit = |dimension| {
            census.get(dimension).max(1).saturating_add(
                usize::from(dimension == SemanticBudgetDimension::NestedEntries) * repeats,
            )
        };
        limits.semantic = CodeQuerySemanticLimits {
            max_materialized_files: 1,
            max_source_bytes: census.source_bytes.max(1),
            max_rows_per_dimension: 1,
            max_retained_bytes: retained_peak.max(census.owned_text_bytes).max(1),
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(row_limit)),
        };
        limits
    }

    #[test]
    #[hardwon(
        "57a6c0b0faa6: successful typestate evaluation must preserve compile peaks without recounting cumulative work"
    )]
    fn child_evaluation_extends_peaks_without_recounting_cumulative_ledgers() {
        let compile_peaks = PolicySemanticPeaks {
            row_dimension: 12,
            retained_bytes: 150,
            traversal_steps: 17,
        };
        let compile_work = SemanticWork {
            nested_entries: 10,
            owned_text_bytes: 100,
            ..SemanticWork::default()
        };
        let evaluation_work = SemanticWork {
            nested_entries: 7,
            owned_text_bytes: 40,
            ..SemanticWork::default()
        };

        let peaks = compile_peaks.with_child_evaluation(compile_work, evaluation_work, 180, 23);

        assert_eq!(peaks.row_dimension, 17);
        assert_eq!(peaks.retained_bytes, 180);
        assert_eq!(peaks.traversal_steps, 23);
    }

    #[test]
    #[hardwon(
        "3ac44dca99bb: Go receiver binding must keep function, method, field, and unknown outcomes distinct"
    )]
    fn receiver_binding_distinguishes_go_function_method_field_and_unknown() {
        let project = InlineTestProject::new()
            .file("go.mod", "module example.com/receiver-binding\n\ngo 1.22\n")
            .file(
                "app.go",
                r#"package app

import (
    "encoding/binary"
    external "example.com/external"
    unknownpkg "example.com/unknown"
)

type resource struct{}
type callbacks struct { Read func() error }

func Source() resource { return resource{} }
func (resource) Read() error { return nil }

func inspect(item resource, callback callbacks, unknown unknownpkg.Resource) {
    _ = binary.Read(nil, binary.LittleEndian, nil)
    _ = item.Read()
    _ = callback.Read()
    known, err := external.Open()
    if err != nil { return }
    _ = known.Read()
    _ = Source().Read()
    _ = unknown.Read()
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let pack = compile_source(
            SourceFormat::Json,
            EXACT_EXTERNAL_RECEIVER_MODEL.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| {
            panic!("external receiver model must compile: {diagnostics:#?}")
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:exact-external-receiver".to_owned(),
                },
            )
            .expect("external receiver model registers");
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
            "external receiver model activates: {activation:#?}"
        );
        let selector = resolved_selector(
            r#"(language go (call-shape (call :callee (name "Read"))))"#,
            "/analysis/events/inspect",
        );
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let mut selected = session
            .select(&selector)
            .expect("all Read calls are selected structurally");
        selected.sort_by_key(|site| site.span.start);
        assert_eq!(selected.len(), 6);

        let mut applicability = Vec::new();
        for (site_index, site) in selected.into_iter().enumerate() {
            let artifact = session
                .materialize(&site.file)
                .expect("selected Go file materializes");
            let mut calls = Vec::new();
            for semantics in artifact.procedures() {
                let procedure = artifact
                    .procedure_handle(semantics.id())
                    .expect("artifact procedure has a handle");
                for call in semantics.call_sites() {
                    let span = semantics
                        .source_mapping(call.source)
                        .expect("validated call has a source mapping")
                        .locator
                        .anchor()
                        .span();
                    if span.start_byte() as usize == site.span.start
                        && span.end_byte() as usize == site.span.end
                    {
                        calls.push((
                            procedure.clone(),
                            procedure
                                .call_site_handle(call.id)
                                .expect("validated call has a handle"),
                        ));
                    }
                }
            }
            assert!(!calls.is_empty(), "selected row names a semantic call");
            if site_index == 3 {
                let [(_, call)] = calls.as_slice() else {
                    panic!("the exact external receiver has one semantic lowering: {calls:#?}");
                };
                let oracle = workspace.semantic_oracle_provider();
                let mut semantic_budget = SemanticBudget::default();
                let dispatch_outcome = oracle
                    .resolve_call(
                        call,
                        &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
                    )
                    .expect("exact external receiver dispatch runs");
                let SemanticOutcome::Complete {
                    value: dispatch, ..
                } = dispatch_outcome
                else {
                    panic!(
                        "the declaration and summary packs must close this exact external dispatch: {dispatch_outcome:#?}"
                    );
                };
                assert_eq!(dispatch.coverage(), CandidateCoverage::Exhaustive);
                assert!(dispatch.candidates().is_empty());
                let [boundary] = dispatch.boundaries() else {
                    panic!("exact external receiver keeps one boundary: {dispatch:#?}");
                };
                assert!(matches!(
                    &boundary.completeness,
                    EvidenceCompleteness::Partial(_)
                ));
                assert_eq!(boundary.proven_external_receiver_shape(), Some(true));
            }
            applicability.push(
                session
                    .receiver_binding_applicability(&calls)
                    .expect("receiver applicability is available"),
            );
        }

        assert_eq!(
            applicability,
            [
                ReceiverBindingApplicability::ExactNonMatch,
                ReceiverBindingApplicability::Applicable,
                ReceiverBindingApplicability::ExactNonMatch,
                ReceiverBindingApplicability::Applicable,
                ReceiverBindingApplicability::Applicable,
                ReceiverBindingApplicability::CandidateReceiver,
            ]
        );
    }

    /// Issue #2523. The lanes of the shared semantic ledger deplete at wildly
    /// different rates, so one bind that legitimately spends most of
    /// `nested_entries` must not cap every other dimension of every later
    /// query at what is left of that one lane.
    #[test]
    #[hardwon("#2523: draining nested-entry work must not cap independent semantic row dimensions")]
    fn a_drained_lane_caps_itself_and_no_other_dimension() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let rows = budget.query_limits().semantic.max_rows_per_dimension;
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        session
            .semantic_budget
            .admit(SemanticWork {
                nested_entries: rows - 1,
                procedures: 1,
                ..SemanticWork::default()
            })
            .expect("the charge fits the fresh ledger");

        let semantic = session
            .remaining_query_limits()
            .expect("one drained lane does not exhaust the session")
            .semantic;
        assert_eq!(semantic.rows(SemanticBudgetDimension::NestedEntries), 1);
        assert_eq!(semantic.rows(SemanticBudgetDimension::Procedures), rows - 1);
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            if matches!(
                dimension,
                SemanticBudgetDimension::NestedEntries | SemanticBudgetDimension::Procedures
            ) {
                continue;
            }
            assert_eq!(
                semantic.rows(dimension),
                rows,
                "an untouched lane keeps its whole remainder: {dimension:?}"
            );
        }
    }

    /// A selector and the policy compiler continuation are one accounting
    /// scope. The selector pays the artifact census; immediate materialization
    /// may pay only the one repeat lookup, even though RQL released its Arc.
    #[test]
    #[hardwon(
        "9b6029ba83b9: immediate materialization must reuse the selector's paid semantic census"
    )]
    fn selector_charge_allows_immediate_post_selection_materialization() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let default_limits = PolicyBudget::default().query_limits();
        let selector = cfg_entry_selector("subject", "/analysis/subject");

        let mut calibration = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            default_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let calibrated = calibration
            .select(&selector)
            .expect("calibration selector completes");
        assert_eq!(calibrated.len(), 1);
        let census = calibration.semantic_used();
        let retained_peak = calibration.live_selector_retained_peak;
        assert!(retained_peak > 0);
        assert!(retained_peak >= census.owned_text_bytes);

        let tight_limits =
            limits_for_one_census_and_repeats(default_limits, census, retained_peak, 1);
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            tight_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let selected = session
            .select(&selector)
            .expect("one tightly budgeted selector completes");
        assert_eq!(selected.len(), 1);
        assert_eq!(session.materialized_artifacts().count(), 0);
        let before = session.semantic_used();
        let execution_before = session.execution_budget().work();

        session
            .materialize(&selected[0].file)
            .expect("the continuation pays only repeat work");

        let after = session.semantic_used();
        for dimension in SemanticBudgetDimension::ALL {
            let expected = before.get(dimension).saturating_add(usize::from(
                dimension == SemanticBudgetDimension::NestedEntries,
            ));
            assert_eq!(after.get(dimension), expected, "{dimension:?}");
        }
        assert_eq!(
            session.execution_budget().work().materialized_files,
            execution_before.materialized_files
        );
    }

    /// Sequential RQL windows have a physical high-water limit, while the
    /// provider's exact owned-text and row work remains additive. A paid file
    /// can therefore be revisited with zero new-file and no additive
    /// owned-text allowance. Its revisits are non-refusing repeat lookups.
    #[test]
    #[hardwon(
        "9b6029ba83b9: overlapping selectors must share paid identity and a truthful retention high-water mark"
    )]
    fn overlapping_selectors_share_identity_and_retained_high_water() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let default_limits = PolicyBudget::default().query_limits();
        let first = cfg_entry_selector("subject", "/analysis/first");
        let second = cfg_entry_selector("second", "/analysis/second");
        let third = cfg_entry_selector("third", "/analysis/third");

        let mut calibration = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            default_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert_eq!(
            calibration
                .select(&first)
                .expect("calibration selector completes")
                .len(),
            1
        );
        let census = calibration.semantic_used();
        let retained_peak = calibration.live_selector_retained_peak;
        assert!(retained_peak >= census.owned_text_bytes);

        let tight_limits =
            limits_for_one_census_and_repeats(default_limits, census, retained_peak, 1);
        assert_eq!(tight_limits.semantic.max_retained_bytes, retained_peak);
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            tight_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert_eq!(
            session
                .select(&first)
                .expect("the first selector pays one census")
                .len(),
            1
        );
        assert_eq!(session.execution_budget().work().materialized_files, 1);

        // Drain the additive provider-owned lane. Residency is separate: the
        // live windows have already released their own admissions, so the
        // physical cap still has room for the paid revisit's live census.
        let owned_remaining = tight_limits
            .semantic
            .max_retained_bytes
            .saturating_sub(session.semantic_used().owned_text_bytes);
        session
            .semantic_budget
            .admit(SemanticWork {
                owned_text_bytes: owned_remaining,
                ..SemanticWork::default()
            })
            .expect("the test fills only the additive provider-owned lane");
        assert_eq!(
            tight_limits
                .semantic
                .max_retained_bytes
                .saturating_sub(session.semantic_used().owned_text_bytes),
            0,
            "the additive provider-owned lane is drained"
        );
        assert_eq!(
            session
                .remaining_query_limits()
                .expect("zero provider-owned delta still permits a paid revisit")
                .semantic
                .max_retained_bytes,
            tight_limits.semantic.max_retained_bytes
        );
        let before_second = session.semantic_used();

        assert_eq!(
            session
                .select(&second)
                .expect("the overlapping selector pays one repeat")
                .len(),
            1
        );
        let after_second = session.semantic_used();
        // `procedure_of` and `cfg_entry` are independent semantic windows.
        // Each resolves the same paid artifact through the complete-artifact
        // cache and closes it before the next, so the overlapping selector
        // performs one repeat lookup per window and never the census again.
        const REPEAT_LOOKUPS: usize = 2;
        for dimension in SemanticBudgetDimension::ALL {
            let expected = before_second.get(dimension).saturating_add(
                usize::from(dimension == SemanticBudgetDimension::NestedEntries) * REPEAT_LOOKUPS,
            );
            assert_eq!(after_second.get(dimension), expected, "{dimension:?}");
        }
        assert_eq!(session.execution_budget().work().materialized_files, 1);
        assert_eq!(session.live_selector_retained_peak, retained_peak);
        let work_report = session.work_report("test");
        let reported_retained_peak = work_report
            .metrics()
            .iter()
            .find(|metric| metric.name() == "test.semantic_peak_retained_bytes")
            .expect("retained peak metric");
        assert_eq!(
            reported_retained_peak.value(),
            u64::try_from(retained_peak).expect("fixture retained peak fits u64")
        );

        // Repeat lookups are non-refusing work (#5113): a third visit pays
        // the same two lookups and re-admits only its live census. It never
        // recharges the artifact census into the work counters, and it cannot
        // be refused by an additive lane the scope already spent.
        let before_third = session.semantic_used();
        assert_eq!(
            session
                .select(&third)
                .expect("repeat lookups are non-refusing work")
                .len(),
            1
        );
        let after_third = session.semantic_used();
        for dimension in SemanticBudgetDimension::ALL {
            let expected = before_third.get(dimension).saturating_add(
                usize::from(dimension == SemanticBudgetDimension::NestedEntries) * REPEAT_LOOKUPS,
            );
            assert_eq!(after_third.get(dimension), expected, "{dimension:?}");
        }
    }

    #[test]
    fn terminal_result_contract_rows_do_not_become_policy_sites() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "subject.go",
                r#"package subject

func target() {}
func caller() { target() }
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let cancellation = CancellationToken::default();
        let selector = resolved_selector(
            r#"(call-result-contracts (call-shape (call :callee (name "target"))))"#,
            "/analysis/terminal-result-contract",
        );
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        let selected = session
            .select_with_artifact_continuation(&selector)
            .expect("an exact unmodeled call produces a complete terminal contract row");

        assert!(
            selected.is_empty(),
            "a terminal result-contract row is a proven non-applicability result"
        );
    }
    #[test]
    fn a_fully_spent_ledger_publishes_zero_delta_row_limits() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let rows = budget.query_limits().semantic.max_rows_per_dimension;
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        session
            .semantic_budget
            .admit(SemanticWork {
                procedures: rows,
                blocks: rows,
                program_points: rows,
                values: rows,
                allocations: rows,
                call_sites: rows,
                memory_locations: rows,
                captures: rows,
                source_mappings: rows,
                evidence: rows,
                gaps: rows,
                events: rows,
                control_edges: rows,
                nested_entries: rows,
                ..SemanticWork::default()
            })
            .expect("the charge exactly fills every row lane");

        let semantic = session
            .remaining_query_limits()
            .expect("zero delta limits are valid for a paid-artifact revisit")
            .semantic;
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            assert_eq!(semantic.rows(dimension), 0, "{dimension:?}");
        }
        assert!(semantic.max_retained_bytes > 0);
    }

    #[test]
    #[should_panic(
        expected = "a selector that performs semantic work must return its one-shot charge"
    )]
    fn semantic_query_work_without_a_charge_fails_closed() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        let _ = session.charge_query_semantic_work(
            CodeQuerySemanticWork {
                procedures: 1,
                ..CodeQuerySemanticWork::default()
            },
            None,
        );
    }
    #[test]
    fn a_narrowed_selector_session_enumerates_only_its_seed_files() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("a.go", "package p\n\nfunc target() {}\n")
            .file("b.go", "package p\n\nfunc target() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let limits = PolicyBudget::default().query_limits();
        let selector = resolved_selector(r#"(function :name "target")"#, "/analysis/subject");

        let mut whole = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let every_site = whole
            .select_with_artifact_continuation(&selector)
            .expect("the whole-workspace selector completes");
        assert_eq!(
            every_site.len(),
            2,
            "the default scope enumerates both files, not {}",
            every_site.len()
        );

        let mut files = workspace.analyzer().analyzed_files();
        files.sort();
        let seed = project.file("a.go");
        let mut narrowed = PolicySelectorSession::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            "test",
            limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&seed), &files),
        );
        let one_site = narrowed
            .select_with_artifact_continuation(&selector)
            .expect("the narrowed selector completes");
        assert_eq!(
            one_site.len(),
            1,
            "the narrowed scope enumerates one file, not {}",
            one_site.len()
        );
        assert_eq!(one_site[0].file, seed);
    }
}
