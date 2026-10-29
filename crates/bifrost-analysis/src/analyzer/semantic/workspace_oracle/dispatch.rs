//! Exact, location-first workspace dispatch and candidate materialization.
//!
//! Control-flow stitching consumes the workspace-oracle facade; it does not
//! reach into the usage-graph dispatch resolver directly.

use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::oracle::dispatch::UnmaterializedExternalTargetEngineExt;

use crate::analyzer::languages::language_support_for_hook;

use crate::analyzer::semantic::completeness_reason_bytes;

use crate::analyzer::semantic::type_flow::DispatchHintProof;

use crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;

use crate::analyzer::semantic::AbstractObjectIdentity;
use crate::analyzer::semantic::ArgumentCallableProvenance;
use crate::analyzer::semantic::CallArgumentEndpoint;
use crate::analyzer::semantic::CallBinding;
use crate::analyzer::semantic::CallSiteHandle;
use crate::analyzer::semantic::CallableTarget;
use crate::analyzer::semantic::CallableTargetResolution;
use crate::analyzer::semantic::CallerReceiverBinding;
use crate::analyzer::semantic::CancellationToken;
use crate::analyzer::semantic::CandidateCoverage;
use crate::analyzer::semantic::DeclarationLocator;
use crate::analyzer::semantic::DeclarationSegment;
use crate::analyzer::semantic::DeclarationSegmentKind;
use crate::analyzer::semantic::DispatchBoundary;
use crate::analyzer::semantic::DispatchBoundaryKind;
use crate::analyzer::semantic::DispatchCandidate;
use crate::analyzer::semantic::DispatchExtensibility;
use crate::analyzer::semantic::DispatchOracle;
use crate::analyzer::semantic::DispatchResult;
use crate::analyzer::semantic::EvidenceCompleteness;
use crate::analyzer::semantic::EvidenceHandle;
use crate::analyzer::semantic::ExactExternalProcedureTarget;
use crate::analyzer::semantic::HeapOracle;
use crate::analyzer::semantic::MemberDeclaration;
use crate::analyzer::semantic::MemoryLocationKind;
use crate::analyzer::semantic::ObjectCardinality;
use crate::analyzer::semantic::ObservationPhase;
use crate::analyzer::semantic::OracleCallContext;
use crate::analyzer::semantic::OracleLimits;
use crate::analyzer::semantic::OracleRelationArena;
use crate::analyzer::semantic::OracleRelationId;
use crate::analyzer::semantic::OracleRelationOwner;
use crate::analyzer::semantic::OracleRelationRecord;
use crate::analyzer::semantic::OracleRelationSubject;
use crate::analyzer::semantic::ProcedureHandle;
use crate::analyzer::semantic::ProcedureKind;
use crate::analyzer::semantic::ProcedurePortKind;
use crate::analyzer::semantic::ProofStatus;
use crate::analyzer::semantic::ReturnedCallableProvenance;
use crate::analyzer::semantic::SemanticArtifact;
use crate::analyzer::semantic::SemanticBudgetExceeded;
use crate::analyzer::semantic::SemanticCallSite;
use crate::analyzer::semantic::SemanticCapability;
use crate::analyzer::semantic::SemanticGap;
use crate::analyzer::semantic::SemanticGapKind;
use crate::analyzer::semantic::SemanticGapSubject;
use crate::analyzer::semantic::SemanticLanguage;
use crate::analyzer::semantic::SemanticLocator;
use crate::analyzer::semantic::SemanticOutcome;
use crate::analyzer::semantic::SemanticProviderError;
use crate::analyzer::semantic::SemanticRequest;
use crate::analyzer::semantic::SemanticRole;
use crate::analyzer::semantic::SemanticWork;
use crate::analyzer::semantic::SourceSiteKind;
use crate::analyzer::semantic::StablePackageValueProvenance;
use crate::analyzer::semantic::UnmaterializedExternalTarget;
use crate::analyzer::semantic::ValueAtPoint;
use crate::analyzer::semantic::ValueFlowOracle;
use crate::analyzer::semantic::WorkspaceMountId;
use crate::analyzer::semantic::WorkspaceRelativePath;
use crate::analyzer::semantic::split_canonical_qualified_callee;
use crate::analyzer::semantic::unmaterialized_external_mount;
use crate::analyzer::semantic::unmaterialized_external_path;

use crate::analyzer::semantic_model::CompiledProcedureSummary;
use crate::analyzer::semantic_model::Completeness;
use crate::analyzer::semantic_model::ProcedureSummaryApplicability;
use crate::analyzer::semantic_model::ProcedureSummaryMatch;
use crate::analyzer::semantic_model::ProcedureSummaryMemberKey;
use crate::analyzer::semantic_model::SemanticModelCompleteness;
use crate::analyzer::semantic_model::SemanticModelMatchDisposition;
use crate::analyzer::semantic_model::SemanticModelSymbolKind;
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::semantic_model::compiled_flow_claims_agree;

use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::structural::resolution::MethodFamilyRelation;

use crate::analyzer::usages::call_relations::PrefetchedCallFile;

use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::get_definition::CallApplicationKind;
use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
use crate::analyzer::usages::get_definition::DispatchQuality;
use crate::analyzer::usages::get_definition::ExactExternalCallProof;
use crate::analyzer::usages::get_definition::dispatch_quality_for_status;
use crate::analyzer::usages::get_definition::parse_tree_for_language;

use crate::analyzer::usages::CallDispatchBoundaryKind;
use crate::analyzer::usages::CallDispatchLookup;
use crate::analyzer::usages::CallDispatchSession;
use crate::analyzer::usages::CallDispatchTarget;
use crate::analyzer::usages::CallRelationService;
use crate::analyzer::usages::ExternalMemberFamilyStatus;
use crate::analyzer::usages::UsageProof;
use crate::analyzer::usages::call_dispatch_equivalence_source;

use crate::analyzer::AnalyzerQueryScope;
use crate::analyzer::QueryScope;

use crate::analyzer::CodeUnit;
use crate::analyzer::CodeUnitType;
use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::LanguageDialect;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;
use crate::analyzer::WorkspaceAnalyzer;

use crate::hash::HashMap;
use crate::hash::HashSet;

use brokk_bifrost_jvm::realm::JvmExternalMemberIdentity;
use brokk_bifrost_jvm::realm::JvmReceiverSemantics;

pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::dispatch::*;

use std::cmp::Ordering;

use std::collections::VecDeque;

use std::sync::Arc;
use std::sync::Mutex;

/// Source-scoped callable identity used only while resolving dispatch. The
/// location-first resolver may return both a C/C++ declaration and a related
/// body, but the oracle never manufactures equivalents from a workspace-global
/// FQN: external linkage does not identify one link unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallableDefinitionIdentity {
    kind: CodeUnitType,
    fq_name: String,
    signature: Option<String>,
    source_scope: Option<ProjectFile>,
}

impl CallableDefinitionIdentity {
    fn of(analyzer: &dyn IAnalyzer, definition: &CodeUnit) -> Self {
        Self::with_source_scope(
            definition,
            call_dispatch_equivalence_source(analyzer, definition),
        )
    }

    pub(in crate::analyzer::semantic) fn with_source_scope(
        definition: &CodeUnit,
        source_scope: Option<ProjectFile>,
    ) -> Self {
        Self {
            kind: definition.kind(),
            fq_name: definition.fq_name(),
            signature: definition.signature().map(str::to_owned),
            source_scope,
        }
    }
}

#[doc(hidden)]
pub fn dispatch_target_groups(
    analyzer: &dyn IAnalyzer,
    targets: Vec<CallDispatchTarget>,
) -> Vec<DispatchTargetGroup> {
    let mut groups = Vec::<DispatchTargetGroup>::new();
    let mut index = HashMap::<CallableDefinitionIdentity, usize>::default();
    for target in targets {
        let identity = CallableDefinitionIdentity::of(analyzer, &target.definition);
        if let Some(group) = index
            .get(&identity)
            .and_then(|group| groups.get_mut(*group))
        {
            if target.definition < group.representative {
                group.representative = target.definition;
            }
            if target.proof == UsageProof::Proven {
                group.proof = ProofStatus::Proven;
                group.completeness = EvidenceCompleteness::Complete;
            }
            if group.native_incomplete_source_reason.as_deref()
                != target.native_incomplete_source_reason.as_deref()
            {
                group.native_incomplete_source_reason = None;
            }
            continue;
        }
        index.insert(identity, groups.len());
        groups.push(DispatchTargetGroup {
            representative: target.definition,
            proof: proof_from_usage(target.proof),
            completeness: completeness_from_usage(target.proof),
            receiver_hint: false,
            native_incomplete_source_reason: target.native_incomplete_source_reason,
        });
    }
    groups
}

#[doc(hidden)]
pub struct PreparedCallDispatch {
    #[doc(hidden)]
    pub lookup: CallDispatchLookup,
}

/// Byte-bounded provider-local prepared syntax keyed by artifact content identity.
///
/// The pool shares only the immutable caller source and its parsed syntax.
/// Every call still performs its own resolver work, consumes its own remaining
/// budget, and returns the ordinary workspace-oracle outcome. A source parse
/// whose charge rolls back remains absent from the prepared session, so a
/// later call must parse and pay for it again.
#[doc(hidden)]
pub struct PreparedWorkspaceDispatchPool<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    #[doc(hidden)]
    pub sessions: Cache<StableDigest, (u32, Arc<PreparedWorkspaceDispatchPoolEntry>)>,
    expected: Cache<StableDigest, Vec<Range>>,
    prefetched: Mutex<HashMap<ProjectFile, PrefetchedCallFile>>,
}

#[doc(hidden)]
pub struct PreparedWorkspaceDispatchPoolEntry {
    artifact: crate::analyzer::semantic::service::CachedSemanticArtifact,
    source: Mutex<Option<CallDispatchSession>>,
}

impl<'a> PreparedWorkspaceDispatchPool<'a> {
    /// Resolve only native forward answers for the reverse inventory. Artifact
    /// materialization and all semantic projection stay on the demanding thread.
    #[doc(hidden)]
    pub fn prefetch_callers(
        &self,
        sites: &[crate::analyzer::usages::CallSite],
        request: &SemanticRequest<'_>,
    ) -> Result<(), SemanticProviderError> {
        if request.budget.first_refusal().is_some()
            || request.cancellation.is_cancelled()
            || request.cancellation.soft_deadline_passed()
        {
            self.discard_prefetched();
            return Ok(());
        }
        // The prefetch is one language's native operation, so ask the supports
        // that own the submitted sites. A language without a selected native
        // reverse operation answers nothing and stays on the demand path.
        let snapshot = self.oracle.active_semantic_model_snapshot();
        let languages = sites
            .iter()
            .map(|site| site.file.language())
            .collect::<HashSet<_>>();
        let mut answers = HashMap::default();
        for language in languages {
            let Some(support) =
                language_support_for_hook(language, "prefetch_reverse_call_targets")
            else {
                continue;
            };
            let Some(result) = support.prefetch_reverse_call_targets(
                self.oracle.workspace,
                sites,
                request.cancellation,
                snapshot.clone(),
            ) else {
                continue;
            };
            answers.extend(
                result.map_err(|error| SemanticProviderError::internal(error.to_string()))?,
            );
        }
        if crate::profiling::enabled() {
            let prefetched = answers
                .values()
                .map(|file| file.outcomes.len())
                .sum::<usize>();
            crate::profiling::note(format!(
                "taint.compose.callers.prefetch retained={} prefetched={prefetched}",
                sites.len()
            ));
        }
        self.prefetched
            .lock()
            .expect("caller prefetch lock")
            .extend(answers);
        Ok(())
    }

    #[doc(hidden)]
    pub fn discard_prefetched(&self) {
        self.prefetched
            .lock()
            .expect("caller prefetch lock")
            .clear();
        for (_, (_, entry)) in self.sessions.iter() {
            if let Some(source) = entry.source.lock().expect("prepared source lock").as_mut() {
                source.discard_prefetched();
            }
        }
    }

    /// Estimated artifact bytes pinned by ready prepared sessions.
    #[doc(hidden)]
    pub fn artifact_bytes(&self) -> u64 {
        self.sessions.run_pending_tasks();
        let mut census = ArtifactRetentionCensus::default();
        for (_, (_, entry)) in self.sessions.iter() {
            census.artifact(&entry.artifact);
        }
        census.artifact_bytes()
    }

    /// Announce calls this pool will be asked to resolve.
    ///
    /// Nothing is resolved or charged here. The next call of the same
    /// artifact whose resolution reaches the source resolver resolves the
    /// announced calls' callee ranges in its own batch, and each announced
    /// call later reads its outcome from the session and pays only its own
    /// post-resolution work. An announced call that is never resolved costs
    /// its share of that batch and nothing else.
    #[doc(hidden)]
    pub fn expect_calls<'c>(&self, calls: impl IntoIterator<Item = &'c CallSiteHandle>) {
        let mut expected = HashMap::<StableDigest, Vec<Range>>::default();
        for call in calls {
            let Ok(range) = exact_call_range(call) else {
                continue;
            };
            expected
                .entry(call.procedure().artifact().key().fingerprint())
                .or_default()
                .push(range);
        }
        for (key, ranges) in expected {
            let mut pending = self.expected.get(&key).unwrap_or_default();
            pending.extend(ranges);
            self.expected.insert(key, pending);
        }
    }

    /// Resolve a contextual callback with the same paid caller-source pool.
    /// Contextual answers are not memoized: each binding and capture proof is
    /// re-established against the supplied exact suffix and request budget.
    #[doc(hidden)]
    pub fn resolve_call_in_context(
        &self,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let before = request.budget.used();
        if let Some(outcome) =
            self.oracle
                .resolve_argument_callable(call, context, request, |entering, request| {
                    self.resolve_call(entering, request)
                })?
        {
            return Ok(outcome);
        }
        let probe = request.budget.used().saturating_sub(before);
        let mut outcome = self.resolve_call(call, request)?;
        match &mut outcome {
            SemanticOutcome::Complete { work, .. }
            | SemanticOutcome::Ambiguous { work, .. }
            | SemanticOutcome::Unknown { work, .. }
            | SemanticOutcome::Unsupported { work, .. }
            | SemanticOutcome::Unproven { work, .. }
            | SemanticOutcome::ExceededBudget { work, .. }
            | SemanticOutcome::Cancelled { work, .. } => *work = probe.conservative_add(*work),
        }
        Ok(outcome)
    }

    /// Resolve one call through the prepared session for its exact artifact
    /// allocation.
    #[doc(hidden)]
    pub fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        if request.budget.first_refusal().is_some()
            || request.cancellation.is_cancelled()
            || request.cancellation.soft_deadline_passed()
        {
            self.discard_prefetched();
        }
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }

        let key = call.procedure().artifact().key().fingerprint();
        let mut expected = Some(self.expected.remove(&key).unwrap_or_default());
        let mut built = None;
        // Single-flight builds finish before admission. An unpaid or empty
        // source session never becomes a ready cache entry.
        let cached = self.sessions.optionally_get_with(key, || {
            let entry = Arc::new(PreparedWorkspaceDispatchPoolEntry {
                artifact: crate::analyzer::semantic::service::CachedSemanticArtifact::new(
                    call.procedure().artifact(),
                ),
                source: Mutex::new(None),
            });
            let (outcome, weight) = self.resolve_with_entry(
                &entry,
                call,
                expected.take().expect("builder owns expected calls"),
                request,
            );
            built = Some(outcome);
            weight.map(|weight| (weight, entry))
        });
        if let Some(outcome) = built {
            self.sessions.run_pending_tasks();
            return outcome;
        }
        // A follower of a rejected build has no ready source. It still runs
        // its own call with its own budget and typed outcome.
        let entry = cached.map_or_else(
            || {
                Arc::new(PreparedWorkspaceDispatchPoolEntry {
                    artifact: crate::analyzer::semantic::service::CachedSemanticArtifact::new(
                        call.procedure().artifact(),
                    ),
                    source: Mutex::new(None),
                })
            },
            |(_, entry)| entry,
        );
        let (outcome, weight) = self.resolve_with_entry(
            &entry,
            call,
            expected.take().expect("follower owns expected calls"),
            request,
        );
        if let Some(weight) = weight {
            self.sessions.insert(key, (weight, entry));
        } else {
            self.sessions.invalidate(&key);
        }
        self.sessions.run_pending_tasks();
        outcome
    }

    fn resolve_with_entry(
        &self,
        entry: &PreparedWorkspaceDispatchPoolEntry,
        call: &CallSiteHandle,
        expected: Vec<Range>,
        request: &mut SemanticRequest<'_>,
    ) -> (
        Result<SemanticOutcome<DispatchResult>, SemanticProviderError>,
        Option<u32>,
    ) {
        // Keep the source lock for the call so concurrent users pay once.
        // Native syntax has no semantic handles; bind emitted provenance to
        // the demanding allocation, even after equal-content re-lowering.
        let mut source = entry.source.lock().expect("prepared source lock");
        let previously_paid = source.is_some();
        let mut session = self
            .oracle
            .prepare_call_dispatch_session(Arc::clone(call.procedure().artifact()));
        session.low_level = source.take();
        session.low_level_source_paid = session.low_level.is_some();
        let file = ProjectFile::new(
            self.oracle.workspace.analyzer().project().root(),
            call.procedure().artifact().key().path().as_path(),
        );
        session.prefetched = self
            .prefetched
            .lock()
            .expect("caller prefetch lock")
            .remove(&file);
        session.expect_calls(expected);
        let outcome = session.resolve_call(call, request);
        let replayable = outcome.as_ref().is_ok_and(|outcome| {
            matches!(
                outcome,
                SemanticOutcome::Complete { .. }
                    | SemanticOutcome::Ambiguous { .. }
                    | SemanticOutcome::Unproven { .. }
                    | SemanticOutcome::Unknown {
                        partial: Some(_),
                        ..
                    }
                    | SemanticOutcome::Unsupported {
                        partial: Some(_),
                        ..
                    }
            )
        });
        let weight = if (previously_paid || replayable)
            && session.retains_exact_source()
            && session.retained_bytes() > 0
        {
            let bytes = crate::analyzer::semantic::semantic_artifact_retained_bytes(&entry.artifact)
                .saturating_add(session.retained_bytes() as u64)
                .saturating_add(std::mem::size_of::<PreparedWorkspaceDispatchPoolEntry>() as u64)
                .min(u64::from(u32::MAX)) as u32;
            *source = session.low_level.take();
            Some(bytes)
        } else {
            None
        };
        (outcome, weight)
    }
}

/// A lazy serial dispatch session bound to one exact semantic artifact.
///
/// Construction performs no source or resolver work. The first actual call
/// reads and parses its exact source snapshot; later calls from the same
/// artifact reuse that tree while definition lookup, target materialization,
/// cancellation, and budgets remain ordered per call.
#[doc(hidden)]
pub struct PreparedWorkspaceDispatchSession<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    artifact: Arc<SemanticArtifact>,
    low_level: Option<CallDispatchSession>,
    low_level_source_paid: bool,
    source_residency: Arc<()>,
    /// Announced whole-call spans held until the exact-syntax session exists.
    expected_calls: Vec<Range>,
    prefetched: Option<PrefetchedCallFile>,
}

impl<'a> PreparedWorkspaceDispatchSession<'a> {
    #[doc(hidden)]
    pub fn retained_bytes(&self) -> usize {
        debug_assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "retained exact syntax must have a committed source charge"
        );
        self.low_level
            .as_ref()
            .map_or(0, CallDispatchSession::retained_bytes)
    }

    /// Announce whole-call spans this session will be asked to resolve; see
    /// [`PreparedWorkspaceDispatchPool::expect_calls`].
    pub(crate) fn expect_calls(&mut self, call_spans: Vec<Range>) {
        match self.low_level.as_mut() {
            Some(low_level) => low_level.expect_calls(call_spans),
            None => self.expected_calls.extend(call_spans),
        }
    }

    #[doc(hidden)]
    pub const fn retains_exact_source(&self) -> bool {
        self.low_level_source_paid
    }

    pub(crate) fn discard_exact_source(&mut self) {
        self.low_level = None;
        self.low_level_source_paid = false;
        self.source_residency = Arc::new(());
    }

    /// Resolve one call through this session. The first call that parses the
    /// session's file pays the source charge; later calls reuse that parse.
    #[doc(hidden)]
    pub fn resolve_call(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.resolve_call_with_definition_session(call, request, None)
    }

    pub(crate) fn resolve_call_with_definition_session(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
        mut definition_session: Option<
            &mut crate::analyzer::usages::get_definition::ScalarCallTargetSession<'a>,
        >,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        if let Some(source) = &self.low_level {
            let (_, bytes) = source.source_admission();
            // This session already retained (and parsed) its source. Moving it
            // into the requesting region's resident ledger is not another read.
            if let Err(exceeded) = request.budget.readmit_source(&self.source_residency, bytes) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: SemanticWork::default(),
                });
            }
        }
        let _timing = self.oracle.dispatch_materialization_timer();
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            self.oracle.workspace.analyzer(),
            self.oracle.active_semantic_model_snapshot(),
        );
        if !Arc::ptr_eq(call.procedure().artifact(), &self.artifact) {
            return Err(SemanticProviderError::invalid_identity(
                "prepared dispatch call must belong to the exact semantic artifact allocation",
            ));
        }
        if let Some(outcome) = self.resolve_declared_indirect_local_call(call, request)? {
            return Ok(outcome);
        }
        let before_callable_probe = request.budget.used();
        if let Some(outcome) =
            self.resolve_returned_local_callable(call, request, definition_session.as_deref_mut())?
        {
            return Ok(outcome);
        }
        let probe_work = request.budget.used().saturating_sub(before_callable_probe);
        let mut outcome = self.resolve_call_through_source(call, request, definition_session)?;
        match &mut outcome {
            SemanticOutcome::Complete { work, .. }
            | SemanticOutcome::Ambiguous { work, .. }
            | SemanticOutcome::Unknown { work, .. }
            | SemanticOutcome::Unsupported { work, .. }
            | SemanticOutcome::Unproven { work, .. }
            | SemanticOutcome::ExceededBudget { work, .. }
            | SemanticOutcome::Cancelled { work, .. } => {
                *work = probe_work.conservative_add(*work);
            }
        }
        Ok(outcome)
    }

    /// Finish one invocation on the ordinary source-resolver route.
    ///
    /// The extracted body owns the lazy exact-syntax session and its paid
    /// source accounting, so every route that reaches the resolver pays the
    /// same way and the session cannot return with unpaid exact syntax.
    fn resolve_call_through_source(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
        mut definition_session: Option<
            &mut crate::analyzer::usages::get_definition::ScalarCallTargetSession<'a>,
        >,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            self.oracle.workspace.analyzer(),
            self.oracle.active_semantic_model_snapshot(),
        );
        let call_span = exact_call_range(call)?;
        debug_assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "a returned prepared session retains only paid exact syntax"
        );
        let initialized_low_level = self.low_level.is_none();
        if self.low_level.is_none() {
            let max_source_bytes = request.budget.limits().source_bytes;
            let Some((file, exact_source)) = exact_source_for_procedure(
                self.oracle.workspace,
                call.procedure(),
                max_source_bytes,
            )?
            else {
                let (exceeded, work) = source_budget_exceeded(request, max_source_bytes);
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            };
            self.low_level = Some(CallRelationService::dispatch_session(file, exact_source));
            let (_, bytes) = self
                .low_level
                .as_ref()
                .expect("opened source")
                .source_admission();
            // The parse that follows charges this source's bytes as work, so
            // this admission is the retained hold, not another read.
            if let Err(exceeded) = request.budget.hold_source(&self.source_residency, bytes) {
                self.low_level = None;
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: SemanticWork::default(),
                });
            }
        }
        let low_level = self
            .low_level
            .as_mut()
            .expect("the first real dispatch call initializes its source session");
        if let Some(prefetched) = self.prefetched.take() {
            low_level.install_prefetched(prefetched);
        }
        low_level.expect_calls(std::mem::take(&mut self.expected_calls));
        let lookup = low_level.dispatch_at_bounded_with_operation(
            self.oracle.workspace.analyzer(),
            _scope.token(),
            &call_span,
            usize::MAX,
            Some(request.cancellation),
            definition_session.as_deref_mut(),
        );
        // Generic target expansion may check out another store reader. An
        // exclusive reader must leave before that checkout on this thread.
        if let Some(session) = definition_session {
            session.release_before_store_read();
        }
        let parsed_source = lookup.work.scanned_files > 0;
        let outcome =
            self.oracle
                .resolve_prepared_call(call, PreparedCallDispatch { lookup }, request);
        if initialized_low_level || parsed_source {
            // The source admission was taken before parsing. Work telemetry
            // survives a rejected result, so it cannot prove holder ownership.
            let keep_source = outcome
                .as_ref()
                .is_ok_and(|outcome| outcome.available_value().is_some());
            self.low_level_source_paid = keep_source;
            if !keep_source {
                self.discard_exact_source();
            }
        }
        assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "a prepared session cannot return with unpaid exact syntax"
        );
        outcome
    }

    /// Materialize an adapter-proven same-artifact indirect target without asking
    /// a source-level definition resolver to rediscover a lexical callable
    /// value binding it does not model. Direct callable syntax stays on the
    /// ordinary resolver route. The semantic artifact validation already
    /// proved the local procedure ID, and dispatch provenance below retains
    /// the exact call and target evidence just like that route.
    fn resolve_declared_indirect_local_call(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<SemanticOutcome<DispatchResult>>, SemanticProviderError> {
        if !matches!(self.artifact.key().language(), LanguageDialect::Standard(_)) {
            return Ok(None);
        }
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let CallableTargetResolution::Proven(CallableTarget::Local(target_id)) =
            &semantic_call.declared_targets
        else {
            return Ok(None);
        };
        let target = self.artifact.procedure_handle(*target_id).ok_or_else(|| {
            SemanticProviderError::internal(
                "validated local call target is absent from its semantic artifact",
            )
        })?;
        let call_span = exact_call_range(call)?;
        let target_span = target.semantics().locator().anchor().span();
        if call_span.start_byte <= target_span.start_byte() as usize
            && target_span.end_byte() as usize <= call_span.end_byte
        {
            return Ok(None);
        }
        let initialized_low_level = self.low_level.is_none();
        let source_work = if initialized_low_level {
            let max_source_bytes = request.budget.limits().source_bytes;
            let Some((file, exact_source)) = exact_source_for_procedure(
                self.oracle.workspace,
                call.procedure(),
                max_source_bytes,
            )?
            else {
                let (exceeded, work) = source_budget_exceeded(request, max_source_bytes);
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            };
            let source_work = SemanticWork {
                source_bytes: exact_source.len(),
                ..SemanticWork::default()
            };
            self.low_level = Some(CallRelationService::dispatch_session(file, exact_source));
            source_work
        } else {
            SemanticWork::default()
        };
        let mut candidates = vec![
            DispatchCandidate::new(
                target,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                *self.oracle.limits(),
            )
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "declared local dispatch candidate is invalid: {error}"
                ))
            })?,
        ];
        let mut boundaries = Vec::new();
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call),
            scoped_procedure_dispatch_gap(call.procedure()),
            *self.oracle.limits(),
        )?;
        let result = DispatchResult::new(
            call,
            candidates,
            boundaries,
            CandidateCoverage::Exhaustive,
            *self.oracle.limits(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "declared local dispatch result is invalid: {error}"
            ))
        })?;
        let work = source_work.conservative_add(dispatch_result_work(&result));
        let mut staged = request.budget.clone();
        let source_admission = self
            .low_level
            .as_ref()
            .map(|session| session.source_admission());
        let admitted = match source_admission {
            Some((_, bytes)) if initialized_low_level => {
                staged.hold_source(&self.source_residency, bytes)
            }
            Some((_, bytes)) => staged.readmit_source(&self.source_residency, bytes),
            None => Ok(()),
        }
        .and_then(|()| staged.admit(dispatch_result_work(&result)));
        if let Err(exceeded) = admitted {
            request.budget.retain_performed_work(&staged);
            if initialized_low_level {
                self.low_level = None;
            }
            return Ok(Some(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            }));
        }
        *request.budget = staged;
        if initialized_low_level {
            self.low_level_source_paid = true;
        }
        assert_eq!(
            self.low_level.is_some(),
            self.low_level_source_paid,
            "a prepared session cannot return with unpaid exact syntax"
        );
        Ok(Some(SemanticOutcome::Complete {
            value: result,
            work,
        }))
    }

    /// Resolve an invocation whose local callee is proven to hold the exact
    /// callable one procedure returned.
    ///
    /// This is the shared consumer of callable-result provenance. The value
    /// walk locates the producing call site from the invocation's own callee
    /// value, the ordinary resolver identifies that call, and the value-flow
    /// provider proves which local callable the result carries. Only the
    /// adapters that publish the structured local capture association the
    /// proof consumes are gated in; every other language keeps the ordinary
    /// resolver route, and an unproven chain keeps the refusal it has today.
    fn resolve_returned_local_callable(
        &mut self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
        definition_session: Option<
            &mut crate::analyzer::usages::get_definition::ScalarCallTargetSession<'a>,
        >,
    ) -> Result<Option<SemanticOutcome<DispatchResult>>, SemanticProviderError> {
        let SemanticLanguage::Standard(language) = self.artifact.key().language() else {
            return Ok(None);
        };
        if !matches!(
            language,
            Language::Go | Language::JavaScript | Language::TypeScript
        ) {
            return Ok(None);
        }
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            self.oracle.workspace.analyzer(),
            self.oracle.active_semantic_model_snapshot(),
        );
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let producer_outcome =
            returned_callable_producer(call.procedure(), semantic_call.callee, request)?;
        let producer_work = producer_outcome.work();
        let (factory_call, returned_result) = match producer_outcome {
            SemanticOutcome::Complete {
                value: Some(producer),
                ..
            } => producer,
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            }
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
            _ => return Ok(None),
        };
        debug_assert_ne!(
            factory_call.id(),
            call.id(),
            "an invocation cannot consume its own result as its callee"
        );
        let factory_outcome = match self
            .resolve_declared_indirect_local_call(&factory_call, request)?
        {
            Some(outcome) => outcome,
            None => self.resolve_call_through_source(&factory_call, request, definition_session)?,
        };
        let factory_work = producer_work.conservative_add(factory_outcome.work());
        let factory_result = match factory_outcome {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: producer_work.conservative_add(work),
                }));
            }
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work: producer_work.conservative_add(work),
                }));
            }
            _ => return Ok(None),
        };
        if factory_result.coverage() != CandidateCoverage::Exhaustive {
            return Ok(None);
        }
        let [candidate] = factory_result.candidates() else {
            return Ok(None);
        };
        if !matches!(candidate.proof(), ProofStatus::Proven)
            || !matches!(candidate.completeness(), EvidenceCompleteness::Complete)
        {
            return Ok(None);
        }
        let target_outcome = self.oracle.returned_callable_target(
            &factory_call,
            candidate,
            returned_result,
            &OracleCallContext::empty(),
            request,
        )?;
        let target_work = target_outcome.work();
        let Some(target) = (match target_outcome {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: factory_work.conservative_add(work),
                }));
            }
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work: factory_work.conservative_add(work),
                }));
            }
            _ => None,
        }) else {
            return Ok(None);
        };
        let provenance = ReturnedCallableProvenance::new(
            factory_call.clone(),
            candidate.target().clone(),
            target.closure.clone(),
            target.captures.clone(),
        );
        let mut candidates = vec![
            DispatchCandidate::new(
                target.closure,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                *self.oracle.limits(),
            )
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "returned-callable dispatch candidate is invalid: {error}"
                ))
            })?,
        ];
        let mut boundaries = Vec::new();
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call),
            scoped_procedure_dispatch_gap(call.procedure()),
            *self.oracle.limits(),
        )?;
        let mut result = DispatchResult::new(
            call,
            candidates,
            boundaries,
            CandidateCoverage::Exhaustive,
            *self.oracle.limits(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "returned-callable dispatch result is invalid: {error}"
            ))
        })?;
        result.mark_returned_callable(provenance);
        let result_work = dispatch_result_work(&result);
        let work = factory_work
            .conservative_add(target_work)
            .conservative_add(result_work);
        if let Err(exceeded) = request.budget.admit(result_work) {
            return Ok(Some(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            }));
        }
        Ok(Some(SemanticOutcome::Complete {
            value: result,
            work,
        }))
    }
}

impl<'a> WorkspaceSemanticOracle<'a> {
    /// Open an empty provider-local pool of exact-artifact dispatch sessions.
    #[doc(hidden)]
    pub fn prepare_workspace_dispatch_pool(&self) -> PreparedWorkspaceDispatchPool<'a> {
        PreparedWorkspaceDispatchPool {
            oracle: self.clone(),
            sessions: Cache::builder()
                .max_capacity(
                    crate::analyzer::semantic::service::SEMANTIC_MATERIALIZATION_CACHE_BYTES,
                )
                .weigher(
                    |_: &StableDigest, entry: &(u32, Arc<PreparedWorkspaceDispatchPoolEntry>)| {
                        entry.0
                    },
                )
                .build(),
            expected: Cache::builder()
                .max_capacity(
                    self.workspace
                        .config()
                        .map_or(256 * 1024 * 1024, |config| config.memo_cache_budget_bytes())
                        / 8,
                )
                .weigher(|_: &StableDigest, ranges: &Vec<Range>| {
                    (ranges.capacity() * std::mem::size_of::<Range>()).min(u32::MAX as usize) as u32
                })
                .build(),
            prefetched: Mutex::new(HashMap::default()),
        }
    }

    /// Open a dispatch session over one artifact. Opening does no source work.
    #[doc(hidden)]
    pub fn prepare_call_dispatch_session(
        &self,
        artifact: Arc<SemanticArtifact>,
    ) -> PreparedWorkspaceDispatchSession<'a> {
        PreparedWorkspaceDispatchSession {
            oracle: self.clone(),
            artifact,
            low_level: None,
            low_level_source_paid: false,
            source_residency: Arc::new(()),
            expected_calls: Vec::new(),
            prefetched: None,
        }
    }

    #[doc(hidden)]
    pub fn resolve_prepared_call(
        &self,
        call: &CallSiteHandle,
        prepared: PreparedCallDispatch,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let call_language = call.procedure().artifact().key().language();
        let type_selected_method = matches!(
            call.procedure()
                .semantics()
                .proven_caller_receiver_binding(call.id()),
            Some(CallerReceiverBinding::TypeQualified(_))
        );
        let call_dispatch_gap =
            scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call);
        let procedure_call_gap = scoped_procedure_dispatch_gap(call.procedure());
        let declared_targets_ambiguous = matches!(
            &semantic_call.declared_targets,
            CallableTargetResolution::Ambiguous(_)
        );

        let max_dispatch_targets = self.limits.dispatch_targets();
        // `dispatch_targets` bounds the final unique ProcedureHandle projection,
        // not raw resolver declarations. Raw exploration instead consumes the
        // request's generic nested-entry budget; any omission at this layer is
        // therefore a semantic-budget partial, not an oracle-target cap.
        let mut staged_budget = request.budget.clone();
        let PreparedCallDispatch { lookup } = prepared;
        let go_interface_receiver = lookup.go_interface_receiver;
        let go_selector_member = lookup.go_selector_member.clone();
        let member_field_anchor = semantic_call
            .member_selection
            .as_ref()
            .filter(|_| !lookup.truncated && !lookup.cancelled && !lookup.budget_exhausted)
            .and(lookup.member_field_anchor);
        let member_receiver_preparation = semantic_call
            .member_selection
            .as_ref()
            .filter(|_| !lookup.truncated && !lookup.cancelled && !lookup.budget_exhausted)
            .and(lookup.member_receiver_preparation);
        debug_assert!(lookup.work.scanned_files <= 1);
        debug_assert!(
            lookup.status.is_none()
                || !lookup.targets.is_empty()
                || !lookup.boundaries.is_empty()
                || lookup.adjudicated_non_callable,
            "every completed dispatch status must retain a target or typed boundary"
        );
        let dispatch_work = low_level_dispatch_work(lookup.work);
        if lookup.cancelled || request.cancellation.is_cancelled() {
            return cancelled_lookup_outcome(
                self.workspace,
                call,
                self.limits,
                CancelledLookupArtifacts {
                    resolved_targets: &lookup.targets,
                    low_level_boundaries: &lookup.boundaries,
                    exact_external_call: lookup.exact_external_call.as_ref(),
                    call_dispatch_gap,
                    procedure_call_gap,
                    observed_work: dispatch_work,
                },
                request,
            );
        }
        staged_budget.charge_work(dispatch_work);
        let mut reported_work = dispatch_work;
        debug_assert!(
            !lookup.budget_exhausted || lookup.truncated,
            "prepared dispatch never submits a zero-sized low-level budget"
        );
        // Go has no virtual override dispatch, and a Rust method call on a
        // concrete receiver type dispatches statically (#3757): an exact
        // closed proof from either selects the whole target set.
        let exact_closed_external_call = if matches!(
            call_language,
            SemanticLanguage::Standard(Language::Go | Language::Rust)
        ) && lookup.status
            == Some(DefinitionLookupStatus::UnresolvableImportBoundary)
            && lookup.boundary == Some(BoundaryStatus::ExternalIndexed)
        {
            lookup.exact_external_call.as_ref().filter(|proof| {
                matches!(
                    proof.call_application(),
                    CallApplicationKind::PackageFunction
                ) || (proof.call_application() == CallApplicationKind::BoundReceiver
                    && proof.dispatch_extensibility() == Some(DispatchExtensibility::Closed))
            })
        } else {
            None
        };

        let native_java_candidate_set_proven = call_language
            == LanguageDialect::Standard(Language::Java)
            && lookup.status == Some(DefinitionLookupStatus::Ambiguous)
            && !lookup.targets.is_empty()
            && lookup
                .targets
                .iter()
                .all(|target| target.proof == UsageProof::Proven)
            && lookup.boundaries.is_empty()
            && !lookup.truncated
            && !lookup.cancelled
            && !lookup.budget_exhausted;
        // This is call-local proof: Java super invocations are nonvirtual,
        // Rust concrete receivers select one impl or trait-default body, and a
        // Ruby member call on an exact receiver with a closed method table
        // selects the one body the resolver found (#3494). None needs an
        // override-family proof for the selected body.
        let nonvirtual_receiver = matches!(
            call_language,
            SemanticLanguage::Standard(Language::Java | Language::Rust | Language::Ruby)
        ) && lookup.status == Some(DefinitionLookupStatus::Resolved)
            && lookup.call_application == CallApplicationKind::BoundReceiver
            && lookup.dispatch_extensibility == Some(DispatchExtensibility::Closed)
            && matches!(lookup.targets.as_slice(), [target]
                if target.proof == UsageProof::Proven
                    && target.native_incomplete_source_reason.is_none())
            && lookup.boundaries.is_empty()
            && !lookup.truncated
            && !lookup.cancelled
            && !lookup.budget_exhausted;
        if let Some(proof) = lookup.exact_external_call.as_ref().filter(|proof| {
            proof.call_application() == CallApplicationKind::PackageFunction && !lookup.truncated
        }) && lookup.targets.is_empty()
        {
            let before_materialization = staged_budget.used();
            let mut materialization_request = request.staged(&mut staged_budget);
            let attempted =
                language_support_for_hook(call_language.language(), "materialize_callable_factory")
                    .expect("call language has registered support")
                    .materialize_callable_factory(
                        self,
                        call,
                        proof,
                        &mut materialization_request,
                    )?;
            if let Some(outcome) = attempted {
                *request.budget = staged_budget;
                let mut outcome = outcome;
                match &mut outcome {
                    SemanticOutcome::Complete { work, .. }
                    | SemanticOutcome::Ambiguous { work, .. }
                    | SemanticOutcome::Unknown { work, .. }
                    | SemanticOutcome::Unsupported { work, .. }
                    | SemanticOutcome::Unproven { work, .. }
                    | SemanticOutcome::ExceededBudget { work, .. }
                    | SemanticOutcome::Cancelled { work, .. } => {
                        *work = work.conservative_add(dispatch_work);
                    }
                }
                return Ok(outcome);
            }
            reported_work = reported_work
                .conservative_add(staged_budget.used().saturating_sub(before_materialization));
        }
        let mut candidates = Vec::new();
        let mut boundaries = lookup
            .boundaries
            .iter()
            .map(|boundary| {
                low_level_boundary(
                    boundary,
                    call_language,
                    Some(semantic_call),
                    lookup.exact_external_call.as_ref(),
                    &lookup.diagnostic_kinds,
                )
            })
            .collect::<Vec<_>>();
        let exact_standard_format_macro = (call_language
            == SemanticLanguage::Standard(Language::Rust)
            && lookup.status == Some(DefinitionLookupStatus::Resolved)
            && lookup.targets.len() == 1
            && lookup.targets[0].proof == UsageProof::Proven)
            .then(|| rust_builtin_format_macro_identity(&lookup.targets[0].definition))
            .flatten();
        let mut ordinary_targets = Vec::with_capacity(lookup.targets.len());
        for target in &lookup.targets {
            if call_language == SemanticLanguage::Standard(Language::Rust)
                && target.definition.is_macro()
            {
                let locator =
                    locator_for_definition(self.workspace.analyzer(), &target.definition)?;
                let proof = proof_from_usage(target.proof);
                if exact_standard_format_macro
                    .as_ref()
                    .is_some_and(|identity| identity.member() == target.definition.terminal_name())
                {
                    let identity = exact_standard_format_macro
                        .as_ref()
                        .expect("matching exact standard macro identity");
                    boundaries.push(DispatchBoundary {
                        kind: DispatchBoundaryKind::External(Some(locator)),
                        external_callee_identity: Some(identity.clone()),
                        exact_external_target: None,
                        unmaterialized_external_target: None,
                        proof,
                        completeness: completeness_from_usage(target.proof),
                        provenance: Box::new([]),
                    });
                } else {
                    boundaries.push(DispatchBoundary {
                        kind: DispatchBoundaryKind::Unmaterialized(locator),
                        external_callee_identity: None,
                        exact_external_target: None,
                        unmaterialized_external_target: None,
                        proof,
                        completeness: EvidenceCompleteness::Partial(
                            "resolved Rust macro definition has no executable expansion summary"
                                .into(),
                        ),
                        provenance: Box::new([]),
                    });
                }
                continue;
            }
            ordinary_targets.push(target.clone());
        }
        let mut target_groups = VecDeque::from(dispatch_target_groups(
            self.workspace.analyzer(),
            ordinary_targets,
        ));
        // A resolved receiver call can still have a DynamicDispatch gap. A
        // complete receiver set answers that gap only when its declarations
        // agree with the resolver's targets. Keep those targets and their
        // proofs: feedback must not redirect an already selected callable.
        // Receiverless calls (including class-qualified Python calls) have a
        // different callable-identity contract and cannot use this discharge.
        let resolved_receiver_hint = self
            .dispatch_hints()
            .for_call(call.procedure(), call.id())
            .filter(|hints| {
                hints.exhaustive()
                    && !hints.hints().is_empty()
                    && semantic_call.receiver.is_some()
                    && lookup.status == Some(DefinitionLookupStatus::Resolved)
                    && !lookup.truncated
                    && boundaries.is_empty()
                    && !target_groups.is_empty()
                    && call_dispatch_gap.is_some_and(|gap| {
                        gap.subject == SemanticGapSubject::CallSite(call.id())
                            && gap.capability == SemanticCapability::DynamicDispatch
                            && matches!(
                                gap.kind,
                                SemanticGapKind::Unknown | SemanticGapKind::Unproven
                            )
                    })
            })
            .filter(|hints| {
                let resolved = target_groups
                    .iter()
                    .map(|group| &group.representative)
                    .collect::<HashSet<_>>();
                let propagated = hints
                    .hints()
                    .iter()
                    .map(|hint| match hint.declaration() {
                        MemberDeclaration::Workspace(declaration) => Some(declaration),
                        MemberDeclaration::External(_) => None,
                    })
                    .collect::<Option<HashSet<_>>>();
                propagated.is_some_and(|declarations| declarations == resolved)
            });
        let displaceable_heuristic_external_boundaries = boundaries
            .iter()
            .filter(|boundary| {
                heuristic_external_boundary_without_resolver_authority(boundary)
                    && boundary
                        .unmaterialized_external_target()
                        .is_none_or(|target| !external_target_has_active_model(self, target))
            })
            .cloned()
            .collect::<Vec<_>>();
        let ordinary_dispatch_is_only_unresolved_or_heuristic_external = target_groups.is_empty()
            && !lookup.truncated
            && boundaries.iter().all(|boundary| {
                boundary.kind == DispatchBoundaryKind::Unresolved
                    || displaceable_heuristic_external_boundaries.contains(boundary)
            })
            && (call_dispatch_gap.is_some()
                || boundaries
                    .iter()
                    .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved));
        let hinted_dispatch = ordinary_dispatch_is_only_unresolved_or_heuristic_external
            .then(|| self.dispatch_hints().for_call(call.procedure(), call.id()))
            .flatten();
        let mut hinted_arms_materialized = hinted_dispatch.is_some();
        let mut hinted_external_targets = HashSet::<SemanticLocator>::default();
        if let Some(hint_set) = hinted_dispatch {
            let receiver_classes = hint_set
                .hints()
                .iter()
                .map(|hint| hint.receiver_class().qualified_name())
                .collect::<Vec<_>>();
            let proof = match hint_set.proof() {
                DispatchHintProof::Proven => ProofStatus::Proven,
                DispatchHintProof::Unproven => ProofStatus::Unproven(
                    format!("target selected by propagated receiver classes {receiver_classes:?}")
                        .into(),
                ),
            };
            let completeness = if hint_set.exhaustive() {
                EvidenceCompleteness::Complete
            } else {
                EvidenceCompleteness::Partial(
                    "propagated receiver classes do not cover every call arm".into(),
                )
            };
            let mut declarations = HashSet::default();
            for hint in hint_set.hints() {
                match hint.declaration() {
                    MemberDeclaration::Workspace(declaration) => {
                        if declarations.insert(declaration.clone()) {
                            target_groups.push_back(DispatchTargetGroup {
                                representative: declaration.clone(),
                                proof: proof.clone(),
                                completeness: completeness.clone(),
                                receiver_hint: true,
                                native_incomplete_source_reason: None,
                            });
                        }
                    }
                    MemberDeclaration::External(declaration) => {
                        let Some(targets) = hinted_external_member_targets(
                            self,
                            declaration,
                            call_language,
                            semantic_call,
                        ) else {
                            hinted_arms_materialized = false;
                            continue;
                        };
                        for (target, summary_complete) in targets {
                            hinted_arms_materialized &= summary_complete;
                            hinted_external_targets.insert(target.locator().clone());
                            boundaries.push(DispatchBoundary {
                                kind: DispatchBoundaryKind::External(Some(
                                    target.locator().clone(),
                                )),
                                external_callee_identity: None,
                                exact_external_target: None,
                                unmaterialized_external_target: Some(target),
                                proof: proof.clone(),
                                completeness: if summary_complete {
                                    EvidenceCompleteness::Complete
                                } else {
                                    EvidenceCompleteness::Partial(
                                        "propagated external receiver member has no complete authored procedure summary"
                                            .into(),
                                    )
                                },
                                provenance: Box::new([]),
                            });
                        }
                    }
                }
            }
        }
        // The Python adapter marks external receiver classes exhaustive only
        // after proving the exact result, a stable local binding, every
        // selected declaration's callable shape, and no workspace member
        // replacement. A complete procedure summary is not needed to close
        // each target identity; external body boundaries stay partial.
        let python_exact_external_receiver_identities = hinted_dispatch
            .and_then(|hint_set| {
                python_exact_external_receiver_hints(self, call_language, semantic_call, hint_set)
            })
            .or_else(|| {
                (call_language.language() == Language::Python
                    && hinted_external_targets.is_empty()
                    && semantic_call.receiver.is_some()
                    && !lookup.budget_exhausted
                    && !request.cancellation.is_cancelled()
                    && call_dispatch_gap.is_none_or(|gap| gap.budget.is_none()))
                .then(|| {
                    language_support_for_hook(
                        Language::Python,
                        "exact_external_receiver_identities",
                    )?
                    .exact_external_receiver_identities(
                        self.workspace,
                        call.procedure(),
                        semantic_call,
                    )
                })
                .flatten()
            });
        let mut python_exact_external_receiver = false;
        if let Some(identities) = &python_exact_external_receiver_identities {
            if hinted_external_targets.is_empty() {
                let arity = u32::try_from(semantic_call.arguments.len()).ok();
                let targets = arity.and_then(|arity| {
                    let overlay = self.workspace.analyzer().semantic_model_overlay()?;
                    let active = self.active_semantic_models()?;
                    identities
                        .iter()
                        .map(|identity| {
                            let owners = overlay.symbols_named(identity.owner_fqn());
                            let [owner] = owners.records.as_slice() else {
                                return None;
                            };
                            if owner.kind != SemanticModelSymbolKind::Class
                                || owner.language != Language::Python.config_label()
                                || owner.provenance.ambiguous
                            {
                                return None;
                            }
                            let declaration = language_support_for_hook(
                                Language::Python,
                                "external_member_declaration",
                            )?
                            .external_member_declaration(&overlay, &owner.id, identity.member())?;
                            let signature = declaration.structured_signature()?;
                            let formals = python_external_model_formals(signature);
                            let target = UnmaterializedExternalTarget::new_modeled(
                                identity.owner_fqn(),
                                identity.member(),
                                call_language,
                                arity,
                                true,
                            )?
                            .with_python_artifact_selection_from(
                                None,
                                &semantic_call.arguments,
                                &formals,
                            )?;
                            let target = if target.selected_python_artifact().is_some() {
                                Some(target)
                            } else if let Some((evidence, manifest)) =
                                python_external_class_artifact_selection(active, owner)
                            {
                                target.with_python_artifact_selection(
                                    &evidence,
                                    &manifest,
                                    &semantic_call.arguments,
                                    &formals,
                                )
                            } else {
                                Some(target)
                            }?;
                            Some((identity.clone(), target))
                        })
                        .collect::<Option<Vec<_>>>()
                });
                if let Some(targets) = targets.filter(|targets| !targets.is_empty()) {
                    let reusable_boundary = boundaries
                        .iter()
                        .position(|boundary| {
                            matches!(boundary.kind, DispatchBoundaryKind::External(_))
                                && boundary.unmaterialized_external_target().is_some_and(
                                    |existing| {
                                        targets.iter().any(|(identity, _)| {
                                            existing.owner_fqn() == identity.owner_fqn()
                                                && existing.member() == identity.member()
                                        })
                                    },
                                )
                        })
                        .or_else(|| {
                            boundaries.iter().position(|boundary| {
                                boundary.kind == DispatchBoundaryKind::Unresolved
                            })
                        })
                        .or_else(|| (!boundaries.is_empty()).then_some(0));
                    if let Some(index) = reusable_boundary {
                        let template = boundaries.remove(index);
                        boundaries.clear();
                        candidates.clear();
                        for (identity, target) in targets {
                            let mut boundary = template.clone();
                            boundary.kind =
                                DispatchBoundaryKind::External(Some(target.locator().clone()));
                            boundary.external_callee_identity = Some(identity);
                            boundary.unmaterialized_external_target = Some(target);
                            boundary.proof = ProofStatus::Proven;
                            boundary.completeness = EvidenceCompleteness::Partial(
                                "the exact external method body is outside the workspace".into(),
                            );
                            boundaries.push(boundary);
                        }
                        python_exact_external_receiver = true;
                    }
                }
            } else {
                let mut matched_targets = HashSet::default();
                for boundary in &mut boundaries {
                    if let Some(target) = boundary.unmaterialized_external_target() {
                        let locator = target.locator().clone();
                        if hinted_external_targets.contains(&locator)
                            && let Some(identity) = identities.iter().find(|identity| {
                                identity.matches_unmaterialized_external_target(target)
                            })
                        {
                            boundary.external_callee_identity = Some(identity.clone());
                            matched_targets.insert(locator);
                        }
                    }
                }
                python_exact_external_receiver = matched_targets == hinted_external_targets;
            }
        }
        // Every declaration this call has already queued, so a class-hierarchy
        // expansion (below) can never queue the same implementor twice and two
        // interfaces that declare the same member cannot loop.
        let mut queued_declarations = target_groups
            .iter()
            .map(|group| group.representative.clone())
            .collect::<HashSet<CodeUnit>>();
        let mut candidate_indexes = HashMap::<ProcedureHandle, usize>::default();
        let mut final_candidates_truncated = false;
        let mut cancelled_targets_truncated = false;
        let mut materialization_quality = DispatchQuality::Complete;
        // #3507: whether every C++ target this call retained names a member
        // whose declaration rows all answer `closed` for dispatch. The
        // question is a property of the declaration, not of the call, so it is
        // read from the analyzer's joined metadata (an out-of-line definition
        // gets its answer from the include-visible class body) and only for
        // the definitions that actually retained a target.
        let mut cpp_target_dispatch_closed =
            call_language == SemanticLanguage::Standard(Language::Cpp);
        // #2480: whether every concrete (materialized-body) match this call
        // resolved to has a class-hierarchy-proven *empty* override set. A
        // concrete match starts this `true`; it becomes `false` the moment
        // any matched declaration's override set is unproven or non-empty.
        // Distinct from `hierarchy_expansion().concrete_overrides` (#2277),
        // which controls whether a *non-empty* proven override set widens the
        // candidate list with `Unproven` entries -- a precision question this
        // wave does not touch. Proving the set empty is not a precision
        // question: an empty, proven override set cannot select a different
        // target, so it is sound to trust regardless of that flag.
        let mut concrete_overrides_proven_absent = true;
        let mut matched_concrete_groups = false;
        let mut unproven_member_family_reasons = Vec::new();
        let lookup_truncated_by_unique_python_receiver =
            python_exact_external_receiver && !lookup.budget_exhausted;
        let mut materialized_files: HashMap<ProjectFile, SemanticOutcome<Arc<SemanticArtifact>>> =
            HashMap::default();
        let mut staged_request = request.staged(&mut staged_budget);

        let (go_interface_receiver_refined, go_receiver_work, go_receiver_exceeded) =
            if call_language == SemanticLanguage::Standard(Language::Go) && go_interface_receiver {
                self.refine_go_interface_receiver_dispatch(
                    call,
                    semantic_call,
                    go_selector_member.as_deref(),
                    &mut target_groups,
                    &mut boundaries,
                    &mut staged_request,
                )?
            } else {
                (false, SemanticWork::default(), None)
            };
        reported_work = reported_work.conservative_add(go_receiver_work);
        let mut materialization_exceeded = go_receiver_exceeded;
        if go_interface_receiver_refined {
            materialization_quality = DispatchQuality::Complete;
        }

        // #2580: an external member has no workspace CodeUnit from which the
        // ordinary member-family inversion can start. Ask the JVM hierarchy
        // seam with the resolver-owned external identity before materializing
        // targets. A complete answer queues its exact workspace members into
        // the ordinary path below; complete-empty is recorded just as
        // authoritatively. Every non-complete status is retained for the
        // targetless boundary added after dispatch-gap refinement.
        let mut external_workspace_families = HashMap::default();
        if call_dispatch_gap.is_some() && !python_exact_external_receiver {
            let mut external_targets = boundaries
                .iter()
                .filter_map(|boundary| boundary.unmaterialized_external_target.clone())
                .filter(UnmaterializedExternalTarget::has_receiver)
                .collect::<Vec<_>>();
            external_targets.sort();
            external_targets.dedup();
            for target in external_targets {
                let Some(identity) = jvm_external_member_identity(&target) else {
                    continue;
                };
                let answer = if staged_request.charge_execution_traversal(1) {
                    let max_visits = usize::MAX;
                    self.workspace
                        .analyzer()
                        .member_family_provider()
                        .map(|provider| {
                            provider.external_member_family(
                                &identity,
                                max_visits,
                                Some(request.cancellation),
                            )
                        })
                        .unwrap_or_else(
                            crate::analyzer::usages::ExternalMemberFamilyAnswer::unsupported,
                        )
                } else {
                    crate::analyzer::usages::ExternalMemberFamilyAnswer {
                        status: ExternalMemberFamilyStatus::BudgetExhausted,
                        candidates: Vec::new(),
                        visited: 0,
                    }
                };
                let hierarchy_work = SemanticWork {
                    nested_entries: answer.visited,
                    ..SemanticWork::default()
                };
                staged_request.budget.charge_work(hierarchy_work);
                reported_work = reported_work.conservative_add(hierarchy_work);
                if answer.is_complete() {
                    for candidate in answer.candidates {
                        if queued_declarations.insert(candidate.clone()) {
                            target_groups.push_back(DispatchTargetGroup {
                                representative: candidate,
                                proof: ProofStatus::Unproven(
                                    "dispatch target is a possible workspace implementation of the external member"
                                        .into(),
                                ),
                                completeness: EvidenceCompleteness::Partial(
                                    "dispatch cannot prove one runtime implementation target identity"
                                        .into(),
                                ),
                                receiver_hint: false,
                                native_incomplete_source_reason: None,
                            });
                        }
                    }
                }
                external_workspace_families.insert(target, answer.status);
            }
        }

        // #3787: candidates reached through a Go package variable carry the
        // workspace census that proves the variable still holds its
        // function-literal initializer.
        let mut stable_package_values = Vec::new();
        while let Some(group) = target_groups.pop_front() {
            if request.cancellation.is_cancelled() {
                cancelled_targets_truncated |= append_cancelled_target_boundaries(
                    self.workspace.analyzer(),
                    &candidates,
                    &mut boundaries,
                    std::iter::once(group).chain(target_groups.drain(..)),
                    self.limits,
                    call_dispatch_gap,
                    procedure_call_gap,
                )?;
                materialization_quality = DispatchQuality::Cancelled;
                break;
            }
            if !staged_request.charge_execution_traversal(1) {
                append_execution_budget_target_boundaries(
                    self.workspace.analyzer(),
                    &candidates,
                    &mut boundaries,
                    std::iter::once(group).chain(target_groups.drain(..)),
                    self.limits,
                    call_dispatch_gap,
                    procedure_call_gap,
                )?;
                materialization_quality = DispatchQuality::Truncated;
                break;
            }
            // Exact dispatch already performed the structured, language-aware
            // declaration/body expansion. Do not repeat it by global FQN here:
            // that would cross C/C++ link units and bypass dispatch work bounds.
            let mut matched_any = false;
            let mut matched_quality = match &group.proof {
                ProofStatus::Proven => DispatchQuality::Complete,
                ProofStatus::Unproven(_) => DispatchQuality::Unproven,
            };
            let mut failure_quality = DispatchQuality::Complete;
            // Whether the declaration's own file was materialized completely.
            // Only then does "no procedure matched this declaration" mean "this
            // declaration has no body", which is the condition the
            // class-hierarchy expansion below is scoped to.
            let mut complete_materialization = false;
            // Why a declaration without its own body did not reach one.
            let mut no_body_reason = None;
            let definition = group.representative.clone();
            let outcome = if let Some(outcome) = materialized_files.get(definition.source()) {
                outcome.clone()
            } else {
                let outcome = self
                    .workspace
                    .materialize_program_semantics(definition.source(), &mut staged_request)?;
                reported_work = reported_work.conservative_add(outcome.work());
                materialized_files.insert(definition.source().clone(), outcome.clone());
                outcome
            };
            let exact_external_artifact =
                outcome.available_value().map(|value| value.key().clone());
            match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    let (has_match, truncated) = retain_artifact_candidates(
                        self.workspace.analyzer(),
                        &definition,
                        semantic_call.arguments.len(),
                        &value,
                        &mut candidates,
                        &mut candidate_indexes,
                        group.proof.clone(),
                        group.completeness.clone(),
                        group.native_incomplete_source_reason.clone(),
                        max_dispatch_targets,
                    );
                    matched_any |= has_match;
                    final_candidates_truncated |= truncated;
                    if !has_match
                        && call_language == SemanticLanguage::Standard(Language::Go)
                        && definition.is_field()
                    {
                        match self.stable_package_function_value(
                            &definition,
                            &value,
                            &staged_request,
                        )? {
                            None => {}
                            Some(Ok(provenance)) => {
                                final_candidates_truncated |= retain_dispatch_candidate(
                                    &mut candidates,
                                    &mut candidate_indexes,
                                    DispatchCandidate::new(
                                        provenance.initializer().clone(),
                                        group.proof.clone(),
                                        group.completeness.clone(),
                                        std::iter::empty(),
                                        OracleLimits::default(),
                                    )
                                    .expect(
                                        "an empty dispatch draft fits every positive provenance limit",
                                    ),
                                    max_dispatch_targets,
                                );
                                stable_package_values.push(provenance);
                                matched_any = true;
                            }
                            Some(Err(reason)) => {
                                no_body_reason = Some(format!(
                                    "package variable `{}` is not proven to hold its function-literal initializer: {reason}",
                                    definition.identifier()
                                ));
                            }
                        }
                    }
                    if has_match && cpp_target_dispatch_closed {
                        let rows = self.workspace.analyzer().signature_metadata(&definition);
                        cpp_target_dispatch_closed = !rows.is_empty()
                            && rows.iter().all(|entry| {
                                entry.dispatch_extensibility()
                                    == Some(DispatchExtensibility::Closed)
                            });
                    }
                    // A selected native-Java source declaration may publish a
                    // semantic callable for candidate-local binding while its
                    // executable body remains outside the workspace. Keep the
                    // candidate, but do not classify that declaration as a
                    // published workspace body for dispatch expansion.
                    complete_materialization = language_for_file(definition.source())
                        != Language::Java
                        || group.native_incomplete_source_reason.is_none();
                }
                SemanticOutcome::Ambiguous {
                    candidates: value, ..
                }
                | SemanticOutcome::Unproven { partial: value, .. } => {
                    let (has_match, truncated) = retain_artifact_candidates(
                        self.workspace.analyzer(),
                        &definition,
                        semantic_call.arguments.len(),
                        &value,
                        &mut candidates,
                        &mut candidate_indexes,
                        ProofStatus::Unproven(
                            "target semantic materialization is not authoritative".into(),
                        ),
                        EvidenceCompleteness::Partial(
                            "target semantic materialization is incomplete".into(),
                        ),
                        group.native_incomplete_source_reason.clone(),
                        max_dispatch_targets,
                    );
                    matched_any |= has_match;
                    final_candidates_truncated |= truncated;
                    if has_match {
                        matched_quality =
                            merge_dispatch_quality(matched_quality, DispatchQuality::Unproven);
                    } else {
                        failure_quality =
                            merge_dispatch_quality(failure_quality, DispatchQuality::Unproven);
                    }
                }
                SemanticOutcome::Unknown { partial, .. } => {
                    let has_match = partial.as_ref().is_some_and(|value| {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            semantic_call.arguments.len(),
                            value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                "target semantic materialization is unknown".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained only an unknown partial"
                                    .into(),
                            ),
                            group.native_incomplete_source_reason.clone(),
                            max_dispatch_targets,
                        );
                        final_candidates_truncated |= truncated;
                        has_match
                    });
                    matched_any |= has_match;
                    let quality = DispatchQuality::Unknown;
                    if has_match {
                        matched_quality = merge_dispatch_quality(matched_quality, quality);
                    } else {
                        failure_quality = merge_dispatch_quality(failure_quality, quality);
                    }
                }
                SemanticOutcome::Unsupported {
                    capability,
                    partial,
                    ..
                } => {
                    let has_match = partial.as_ref().is_some_and(|value| {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            semantic_call.arguments.len(),
                            value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                format!(
                                    "target semantic materialization does not completely support {}",
                                    capability.label()
                                )
                                .into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained an unsupported partial"
                                    .into(),
                            ),
                            group.native_incomplete_source_reason.clone(),
                            max_dispatch_targets,
                        );
                        final_candidates_truncated |= truncated;
                        has_match
                    });
                    matched_any |= has_match;
                    let quality = DispatchQuality::Unsupported(capability);
                    if has_match {
                        matched_quality = merge_dispatch_quality(matched_quality, quality);
                    } else {
                        failure_quality = merge_dispatch_quality(failure_quality, quality);
                    }
                }
                SemanticOutcome::ExceededBudget {
                    partial, exceeded, ..
                } => {
                    if let Some(value) = partial {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            semantic_call.arguments.len(),
                            &value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                "target semantic materialization exceeded its budget".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained a budget-limited partial"
                                    .into(),
                            ),
                            group.native_incomplete_source_reason.clone(),
                            max_dispatch_targets,
                        );
                        matched_any |= has_match;
                        final_candidates_truncated |= truncated;
                    }
                    boundaries.push(truncated_dispatch_boundary());
                    materialization_exceeded = Some(exceeded);
                    materialization_quality = DispatchQuality::Truncated;
                }
                SemanticOutcome::Cancelled { partial, .. } => {
                    if let Some(value) = partial {
                        let (has_match, truncated) = retain_artifact_candidates(
                            self.workspace.analyzer(),
                            &definition,
                            semantic_call.arguments.len(),
                            &value,
                            &mut candidates,
                            &mut candidate_indexes,
                            ProofStatus::Unproven(
                                "target semantic materialization was cancelled".into(),
                            ),
                            EvidenceCompleteness::Partial(
                                "target semantic materialization retained a cancelled partial"
                                    .into(),
                            ),
                            group.native_incomplete_source_reason.clone(),
                            max_dispatch_targets,
                        );
                        matched_any |= has_match;
                        final_candidates_truncated |= truncated;
                    }
                    materialization_quality = DispatchQuality::Cancelled;
                }
            }

            let interruption = materialization_interruption(
                materialization_quality,
                materialization_exceeded.is_some(),
                request.cancellation,
            );
            if matched_any {
                materialization_quality =
                    merge_dispatch_quality(materialization_quality, matched_quality);
                // The declaration's file materialized completely and did
                // publish a body for it: this callee is a concrete method. A
                // subclass may still override it, in which case the code that
                // runs at this call site is the override rather than the body
                // just retained. Offering those overrides is the second, wider
                // class-hierarchy lever (#2277): unlike the body-less case in
                // the other arm of this branch, there is already something
                // analyzable here, so this strictly widens the candidate set
                // and is off unless a host asked for it.
                //
                // The retained concrete candidate keeps its own proof. The
                // overrides enter as `Unproven`, exactly like the implementors
                // of a body-less declaration, so the answer says "the callee
                // the types name runs, and these overrides could run instead"
                // and never claims a proven edge to an override.
                //
                // #2480: the class-hierarchy question is asked here
                // unconditionally (not just under `concrete_overrides`) so a
                // *proven-empty* answer can discharge the call's own
                // "may select an override" gap below. This mirrors
                // `virtual_dispatch_implementor_targets`'s other caller (the
                // body-less arm), which already asks unconditionally. Only
                // *acting* on a non-empty answer by widening the candidate
                // set stays behind the flag.
                if complete_materialization
                    && !group.receiver_hint
                    && !type_selected_method
                    && !nonvirtual_receiver
                {
                    if staged_request.charge_execution_traversal(1) {
                        matched_concrete_groups = true;
                        let implementor_targets = virtual_dispatch_implementor_targets(
                            self.workspace.analyzer(),
                            &group.representative,
                            request.cancellation,
                        );
                        if let ImplementorTargets::Unproven {
                            reason: Some(reason),
                            ..
                        } = &implementor_targets
                        {
                            unproven_member_family_reasons.push(reason.label());
                        }
                        match implementor_targets {
                            ImplementorTargets::Proven(overrides) if overrides.is_empty() => {
                                // Proven: no workspace declaration overrides
                                // this member. `concrete_overrides_proven_absent`
                                // stays true.
                            }
                            ImplementorTargets::Proven(overrides)
                            | ImplementorTargets::Unproven {
                                established: overrides,
                                ..
                            } => {
                                concrete_overrides_proven_absent = false;
                                if self.hierarchy_expansion().concrete_overrides {
                                    for overriding in overrides {
                                        if queued_declarations.insert(overriding.clone()) {
                                            target_groups.push_back(DispatchTargetGroup {
                                                representative: overriding,
                                                proof: ProofStatus::Unproven(
                                                    "dispatch target is a possible override".into(),
                                                ),
                                                completeness: EvidenceCompleteness::Partial(
                                                    "dispatch cannot prove one complete override target identity"
                                                        .into(),
                                                ),
                                                receiver_hint: false,
                                                native_incomplete_source_reason: None,
                                            });
                                        }
                                    }
                                }
                            }
                            ImplementorTargets::NotApplicable => {
                                // No applicable member-family proof establishes
                                // whether overrides exist.
                                concrete_overrides_proven_absent = false;
                            }
                        }
                    } else {
                        // The expansion could not be charged, so the target set
                        // is knowingly short of the overrides that could run,
                        // and the empty-override proof this call would have
                        // needed to discharge its dispatch gap was not taken.
                        concrete_overrides_proven_absent = false;
                        if self.hierarchy_expansion().concrete_overrides {
                            materialization_quality = merge_dispatch_quality(
                                materialization_quality,
                                DispatchQuality::Truncated,
                            );
                        }
                    }
                }
            } else if interruption.is_none() {
                let target =
                    locator_for_definition(self.workspace.analyzer(), &group.representative)?;
                boundaries.push(DispatchBoundary {
                    kind: DispatchBoundaryKind::Unmaterialized(target.clone()),
                    external_callee_identity: None,
                    exact_external_target: exact_external_artifact.as_ref().and_then(|artifact| {
                        exact_external_procedure_target(
                            self.workspace.analyzer(),
                            &group.representative,
                            artifact,
                            target.clone(),
                            semantic_call.receiver.is_some(),
                        )
                    }),
                    unmaterialized_external_target: None,
                    proof: group.proof.clone(),
                    completeness: EvidenceCompleteness::Partial(
                        no_body_reason
                            .unwrap_or_else(|| {
                                "equivalent callable declarations have no published workspace body"
                                    .to_owned()
                            })
                            .into(),
                    ),
                    provenance: Box::new([]),
                });
                let missing_quality = if failure_quality == DispatchQuality::Complete {
                    DispatchQuality::Unproven
                } else {
                    failure_quality
                };
                materialization_quality =
                    merge_dispatch_quality(materialization_quality, missing_quality);
                // The declaration's own file was analyzed completely and still
                // published no body for it, so this callee is an interface or
                // abstract member and the code that runs is in the workspace
                // types below it (#2205). Queue those implementors as further
                // dispatch targets. They stay `Unproven`, and the boundary
                // pushed just above stays with them, so the answer says "the
                // named callee has no body, and these are the members that
                // could run" rather than claiming a resolved edge.
                if complete_materialization
                    && !group.receiver_hint
                    && !type_selected_method
                    && !nonvirtual_receiver
                {
                    if staged_request.charge_execution_traversal(1) {
                        if let ImplementorTargets::Proven(implementors)
                        | ImplementorTargets::Unproven {
                            established: implementors,
                            ..
                        } = virtual_dispatch_implementor_targets(
                            self.workspace.analyzer(),
                            &group.representative,
                            request.cancellation,
                        ) {
                            for implementor in implementors {
                                if queued_declarations.insert(implementor.clone()) {
                                    target_groups.push_back(DispatchTargetGroup {
                                        representative: implementor,
                                        proof: ProofStatus::Unproven(
                                            "dispatch target is a possible implementor".into(),
                                        ),
                                        completeness: EvidenceCompleteness::Partial(
                                            "dispatch cannot prove one complete implementor target identity"
                                                .into(),
                                        ),
                                        receiver_hint: false,
                                        native_incomplete_source_reason: None,
                                    });
                                }
                            }
                        }
                    } else {
                        // The expansion this body-less callee needs could not be
                        // charged, so the target set is knowingly short of the
                        // members that could run. Say so instead of answering as
                        // if the hierarchy had been consulted.
                        materialization_quality = merge_dispatch_quality(
                            materialization_quality,
                            DispatchQuality::Truncated,
                        );
                    }
                }
            }

            if let Some(interruption) = interruption {
                if interruption == MaterializationInterruption::Cancelled {
                    let current = (!matched_any).then_some(group);
                    cancelled_targets_truncated |= append_cancelled_target_boundaries(
                        self.workspace.analyzer(),
                        &candidates,
                        &mut boundaries,
                        current.into_iter().chain(target_groups.drain(..)),
                        self.limits,
                        call_dispatch_gap,
                        procedure_call_gap,
                    )?;
                    materialization_quality = DispatchQuality::Cancelled;
                }
                break;
            }
        }

        // A structured ambiguous call names possible local bodies without
        // proving which one runs. Preserve those candidates in the shared
        // dispatch projection while keeping each arm partial; this applies
        // across languages and does not let a lower-level single-target
        // lookup erase the call site's explicit ambiguity.
        if let CallableTargetResolution::Ambiguous(declared_targets) =
            &semantic_call.declared_targets
        {
            for declared_target in declared_targets.iter() {
                let CallableTarget::Local(procedure_id) = declared_target else {
                    continue;
                };
                let target = call
                    .procedure()
                    .artifact()
                    .procedure_handle(*procedure_id)
                    .expect("validated local call target has a procedure row");
                let proof_reason: Box<str> =
                    "the call site retains multiple possible local bodies".into();
                let completeness_reason: Box<str> =
                    "ambiguous call targets do not cover one selected body".into();
                if let Some(index) = candidate_indexes.get(&target).cloned() {
                    let candidate = candidates
                        .get_mut(index)
                        .expect("dispatch candidate index points into the candidate list");
                    candidate.proof = ProofStatus::Unproven(proof_reason);
                    candidate.completeness = EvidenceCompleteness::Partial(completeness_reason);
                } else {
                    let candidate = DispatchCandidate::new(
                        target,
                        ProofStatus::Unproven(proof_reason),
                        EvidenceCompleteness::Partial(completeness_reason),
                        std::iter::empty(),
                        self.limits,
                    )
                    .map_err(|error| {
                        SemanticProviderError::internal(format!(
                            "ambiguous local dispatch candidate is invalid: {error}"
                        ))
                    })?;
                    final_candidates_truncated |= retain_dispatch_candidate(
                        &mut candidates,
                        &mut candidate_indexes,
                        candidate,
                        max_dispatch_targets,
                    );
                }
            }
            if !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
            {
                boundaries.push(DispatchBoundary {
                    kind: DispatchBoundaryKind::Unresolved,
                    external_callee_identity: None,
                    exact_external_target: None,
                    unmaterialized_external_target: None,
                    proof: ProofStatus::Unproven(
                        "the call site retains multiple possible local bodies".into(),
                    ),
                    completeness: EvidenceCompleteness::Partial(
                        "ambiguous call resolution leaves an open target boundary".into(),
                    ),
                    provenance: Box::new([]),
                });
            }
        }

        if final_candidates_truncated {
            if !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
            {
                boundaries.push(truncated_dispatch_boundary());
            }
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }

        let resolved_receiver_refined = resolved_receiver_hint.is_some()
            && materialization_quality == DispatchQuality::Complete
            && materialization_exceeded.is_none()
            && !final_candidates_truncated
            && !request.cancellation.is_cancelled()
            && boundaries.is_empty()
            && !candidates.is_empty()
            && candidates.iter().all(|candidate| {
                matches!(candidate.proof, ProofStatus::Proven)
                    && matches!(candidate.completeness, EvidenceCompleteness::Complete)
            });
        let hint_refinement_complete = resolved_receiver_refined
            || hinted_dispatch.is_some_and(|hint_set| {
                hint_set.exhaustive()
                    && (hinted_arms_materialized || python_exact_external_receiver)
                    && materialization_exceeded.is_none()
                    && !final_candidates_truncated
                    && !request.cancellation.is_cancelled()
                    && boundaries.iter().all(|boundary| {
                        boundary.kind == DispatchBoundaryKind::Unresolved
                            || displaceable_heuristic_external_boundaries.contains(boundary)
                            || matches!(
                                &boundary.kind,
                                DispatchBoundaryKind::External(Some(target))
                                    if hinted_external_targets.contains(target)
                                        && (matches!(
                                            boundary.completeness,
                                            EvidenceCompleteness::Complete
                                        ) || (python_exact_external_receiver
                                            && boundary.proof == ProofStatus::Proven))
                            )
                    })
            });
        if hint_refinement_complete {
            boundaries.retain(|boundary| {
                boundary.kind != DispatchBoundaryKind::Unresolved
                    && !displaceable_heuristic_external_boundaries.contains(boundary)
            });
        }

        let (anonymous_receiver_refined, receiver_refinement_work) = self
            .refine_java_anonymous_receiver_dispatch(
                call,
                semantic_call,
                &mut candidates,
                &mut boundaries,
                &mut staged_request,
            )?;
        reported_work = reported_work.conservative_add(receiver_refinement_work);
        if anonymous_receiver_refined {
            materialization_quality = DispatchQuality::Complete;
        }

        let resolver_proven_external_static =
            resolver_proven_external_static_boundary(lookup.status, &candidates, &boundaries);
        // An exact closed receiver proof names one method on
        // one concrete nominal type. Rust inherent methods and Go concrete
        // method sets cannot acquire overrides.
        // A unique complete procedure summary additionally closes the external
        // body boundary; without one, effects remain partial. Trait, ambiguous,
        // incomplete, or merely name-matched receivers never receive this
        // resolver proof and keep the generic gap below.
        let proven_bound_receiver = resolver_proven_closed_bound_receiver_boundary(
            call_language,
            lookup.status,
            lookup.exact_external_call.as_ref(),
            &candidates,
            &boundaries,
        );
        let proven_bound_receiver_dispatch = proven_bound_receiver.is_some();
        let modeled_bound_receiver_closure = proven_bound_receiver
            .filter(|target| active_unique_complete_receiver_summary(self, target))
            .cloned();
        if let Some(target) = &modeled_bound_receiver_closure {
            for boundary in &mut boundaries {
                if boundary.unmaterialized_external_target() == Some(target) {
                    boundary.completeness = EvidenceCompleteness::Complete;
                }
            }
        }
        let resolver_proven_java_final = resolver_proven_java_final_boundary(
            call_language,
            lookup.status,
            lookup.exact_external_call.as_ref(),
            &candidates,
            &boundaries,
        );
        // #3406: a require-bound or namespace-bound JS/TS member call whose
        // exact resolver proved the external member closes its residual
        // dynamic-dispatch arm when the activated models carry one complete,
        // override-covering procedure summary for that exact member and no
        // workspace source can replace the member value first. The reviewed
        // summary then also supplies the call's complete transfer set, so the
        // external boundary stops stating the body as unobserved. A call
        // without such a summary, or with a visible member write or
        // module-object escape, keeps the arm and stays honestly open.
        let (js_ts_modeled_member_closure, js_ts_member_mutation_unproven) = {
            let shape =
                js_ts_proven_external_member_boundary(call_language, &candidates, &boundaries)
                    .filter(|target| active_covering_complete_summary(self, target));
            let mutation_free = shape.map(|target| {
                js_ts_module_member_mutation_free(
                    self.workspace.analyzer(),
                    target,
                    request.cancellation,
                )
            });
            let closure = match (shape, mutation_free) {
                (Some(target), Some(true)) => Some(target.clone()),
                _ => None,
            };
            let unproven = shape.is_some() && closure.is_none();
            (closure, unproven)
        };
        // C# receiver resolution carries the same exact owner/member and
        // arity proof for an external instance method. A complete summary
        // that explicitly covers overrides closes the external member family;
        // without that author claim, an XmlWriter-style virtual call must
        // retain its dynamic-dispatch gap.
        let csharp_modeled_member_closure = csharp_proven_external_member_boundary(
            call_language,
            lookup.exact_external_call.as_ref(),
            &candidates,
            &boundaries,
        )
        .filter(|target| active_covering_complete_summary(self, target))
        .cloned();
        // The Python analogue: a receiverless call of an imported module's
        // function whose exact resolver proved the external member and whose
        // activated models carry one complete summary for it. The same
        // replacement hazard has to be absent before the boundary is upgraded.
        let (python_modeled_function_closure, python_function_mutation_unproven) = {
            let boundary_target =
                python_proven_external_function_boundary(call_language, &candidates, &boundaries);
            let summary_complete = boundary_target
                .is_some_and(|target| active_covering_complete_summary(self, target));
            let shape = boundary_target.filter(|_| summary_complete);
            let closure = shape
                .filter(|target| {
                    python_module_member_mutation_free(self.workspace.analyzer(), target, request)
                })
                .cloned();
            let unproven = shape.is_some() && closure.is_none();
            (closure, unproven)
        };
        let python_external_class_call = python_external_class_result_call(
            self,
            call.procedure(),
            call_language,
            &candidates,
            &boundaries,
            semantic_call,
        );
        // When the reviewed summary is active but a member write or a
        // module-object escape may replace the member, the plan-level authored
        // closure must not close the residual arm over the write: the call may
        // not dispatch to the modeled member at all. Refuse the workspace half
        // the same way an unenumerated hierarchy refuses it (#2371), so the
        // run stays typed inconclusive instead of asserting a precision the
        // authored claim does not cover.
        for target in [
            &csharp_modeled_member_closure,
            &js_ts_modeled_member_closure,
            &python_modeled_function_closure,
        ]
        .into_iter()
        .flatten()
        {
            for boundary in &mut boundaries {
                if boundary.unmaterialized_external_target() == Some(target) {
                    boundary.completeness = EvidenceCompleteness::Complete;
                }
            }
        }
        if let Some(class_call) = &python_external_class_call {
            let [boundary] = boundaries.as_mut_slice() else {
                unreachable!("external class call helper returned for one boundary");
            };
            boundary.kind =
                DispatchBoundaryKind::External(Some(class_call.target.locator().clone()));
            boundary.external_callee_identity = Some(class_call.identity.clone());
            boundary.unmaterialized_external_target = Some(class_call.target.clone());
            boundary.proof = ProofStatus::Proven;
            boundary.completeness = EvidenceCompleteness::Complete;
        }
        if js_ts_member_mutation_unproven || python_function_mutation_unproven {
            boundaries.push(modeled_member_mutation_unproven_boundary());
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }
        let call_dispatch_gap = (!anonymous_receiver_refined
            && !go_interface_receiver_refined
            && !hint_refinement_complete)
            .then_some(call_dispatch_gap)
            .flatten()
            .filter(|gap| {
                !closed_dispatch_discharges_gap(&candidates, gap)
                    && !proven_static_target_discharges_gap(
                        call.procedure(),
                        &semantic_call.declared_targets,
                        semantic_call.receiver.is_none(),
                        &candidates,
                        &boundaries,
                        lookup.status == Some(DefinitionLookupStatus::Resolved),
                        materialization_quality,
                        gap,
                    )
                    && !exact_nonvirtual_member_dispatch_discharges_gap(
                        lookup.status == Some(DefinitionLookupStatus::Resolved),
                        &candidates,
                        &boundaries,
                        materialization_quality,
                        match call_language {
                            SemanticLanguage::Standard(Language::Cpp) => cpp_target_dispatch_closed,
                            SemanticLanguage::Standard(
                                Language::Java | Language::Rust | Language::Ruby,
                            ) => nonvirtual_receiver,
                            _ => false,
                        },
                        gap,
                    )
                    && !concrete_overrides_proven_absent_discharges_gap(
                        &candidates,
                        &boundaries,
                        gap,
                        matched_concrete_groups,
                        concrete_overrides_proven_absent,
                    )
                    && !exact_closed_external_dispatch_discharges_gap(
                        exact_closed_external_call,
                        call_language,
                        &candidates,
                        &boundaries,
                        gap,
                    )
                    && !resolver_proven_external_static_dispatch_discharges_gap(
                        resolver_proven_external_static || resolver_proven_java_final,
                        gap,
                    )
                    && !(proven_bound_receiver_dispatch
                        && matches!(
                            gap.capability,
                            SemanticCapability::Calls | SemanticCapability::DynamicDispatch
                        )
                        && matches!(
                            gap.kind,
                            SemanticGapKind::Unknown | SemanticGapKind::Unproven
                        ))
                    && !kotlin_external_declared_callee_discharges_gap(
                        call_language,
                        lookup.status,
                        &candidates,
                        &boundaries,
                        semantic_call.receiver.is_none(),
                        gap,
                    )
                    && !((csharp_modeled_member_closure.is_some()
                        || js_ts_modeled_member_closure.is_some()
                        || python_modeled_function_closure.is_some())
                        && gap.capability == SemanticCapability::DynamicDispatch
                        && matches!(
                            gap.kind,
                            SemanticGapKind::Unknown | SemanticGapKind::Unproven
                        ))
                    && !(python_external_class_call.is_some()
                        && matches!(
                            gap.capability,
                            SemanticCapability::Calls | SemanticCapability::DynamicDispatch
                        )
                        && matches!(
                            gap.kind,
                            SemanticGapKind::Unknown | SemanticGapKind::Unproven
                        ))
            });
        let gap_exceeded = call_dispatch_gap
            .and_then(|gap| gap.budget)
            .or_else(|| procedure_call_gap.and_then(|gap| gap.budget));
        if let Some(gap) = call_dispatch_gap.filter(|gap| {
            !(python_exact_external_receiver
                && gap.capability == SemanticCapability::DynamicDispatch
                && matches!(
                    gap.kind,
                    SemanticGapKind::Unknown | SemanticGapKind::Unproven
                )
                && gap.budget.is_none())
        }) {
            materialization_quality = merge_dispatch_quality(
                materialization_quality,
                apply_dynamic_dispatch_gap(gap, &unproven_member_family_reasons, &mut boundaries),
            );
        }
        if let Some(gap) = procedure_call_gap {
            materialization_quality = merge_dispatch_quality(
                materialization_quality,
                apply_procedure_call_gap(gap, &mut boundaries),
            );
        }

        // #2371/#2580: an ordinary external member call needs the workspace
        // implementor family enumerated before its residual dynamic-dispatch
        // gap can close. An exact Python constructor receiver has a narrower
        // proof: C3 selected the pack declaration for the exact class, its
        // callable shape is complete, and no workspace replacement is visible.
        // That proof closes this member call without requiring overload-family
        // completeness, which a Python CSMI declaration cannot establish.
        let mut workspace_hierarchy_unenumerated = false;
        if call_dispatch_gap.is_some() && !python_exact_external_receiver {
            let mut classified_targets = HashSet::default();
            let statuses = boundaries
                .iter()
                .filter_map(|boundary| match &boundary.kind {
                    DispatchBoundaryKind::External(Some(_)) => {
                        boundary.unmaterialized_external_target.as_ref()
                    }
                    _ => None,
                })
                // The exact Python function closure above already discharges
                // this target. Keep the prior unresolved-hierarchy evidence
                // for every other external function, including C/C++ calls.
                .filter(|target| python_modeled_function_closure.as_ref() != Some(*target))
                .filter(|target| classified_targets.insert((*target).clone()))
                .filter_map(|target| {
                    if let Some(status) = external_workspace_families.get(target) {
                        return (*status != ExternalMemberFamilyStatus::Complete)
                            .then_some(*status);
                    }
                    (!external_member_workspace_override_proven_absent(
                        self.workspace.analyzer(),
                        target,
                    ))
                    .then_some(ExternalMemberFamilyStatus::Unsupported)
                })
                .collect::<Vec<_>>();
            if !statuses.is_empty() {
                for status in statuses {
                    boundaries.push(workspace_hierarchy_unenumerated_boundary(status));
                    if status == ExternalMemberFamilyStatus::Cancelled {
                        materialization_quality = DispatchQuality::Cancelled;
                    }
                }
                workspace_hierarchy_unenumerated = true;
                materialization_quality =
                    merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
            }
        }

        candidates.sort_by(|left, right| {
            left.target
                .semantics()
                .locator()
                .cmp(right.target.semantics().locator())
        });
        boundaries.sort_by(compare_dispatch_boundaries);
        boundaries.dedup();
        if boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
        {
            // A typed unresolved arm is itself unproven, even when the
            // low-level location lookup reported `Resolved`. That status can
            // describe a lexical callable value (for example a function-typed
            // parameter) without publishing any callable body.
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Unproven);
        }
        if lookup.truncated && !lookup_truncated_by_unique_python_receiver {
            if !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
            {
                boundaries.push(truncated_dispatch_boundary());
            }
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }
        let provenance_truncated = bound_dispatch_projection(
            &mut candidates,
            &mut boundaries,
            self.limits,
            call_dispatch_gap,
            procedure_call_gap,
        );
        if provenance_truncated {
            materialization_quality =
                merge_dispatch_quality(materialization_quality, DispatchQuality::Truncated);
        }
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            call_dispatch_gap,
            procedure_call_gap,
            self.limits,
        )?;
        let cancelled = materialization_quality == DispatchQuality::Cancelled
            || request.cancellation.is_cancelled();
        let dispatch_truncated = cancelled_targets_truncated
            || provenance_truncated
            || boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated);
        // A call expression the resolver proved is not an applicable call at
        // all -- a Go conversion to a type an activated model publishes --
        // has no callee. Its empty target set is a complete answer, not an
        // unreached one, so it reports exhaustive coverage with no arm.
        let resolver_proved_no_callee = lookup.adjudicated_non_callable
            && !dispatch_truncated
            && !cancelled
            && candidates.is_empty()
            && boundaries.is_empty();
        let coverage = if dispatch_truncated {
            CandidateCoverage::Truncated
        } else if cancelled {
            CandidateCoverage::Open
        } else if resolver_proved_no_callee
            || anonymous_receiver_refined
            || go_interface_receiver_refined
            || resolver_proven_external_static
            || resolver_proven_java_final
            || hint_refinement_complete
            || python_exact_external_receiver
            || csharp_modeled_member_closure.is_some()
            || js_ts_modeled_member_closure.is_some()
            || python_external_class_call.is_some()
            || python_modeled_function_closure.is_some()
        {
            CandidateCoverage::Exhaustive
        } else {
            dispatch_coverage(lookup.status, &boundaries)
        };
        let mut result = DispatchResult::new(call, candidates, boundaries, coverage, self.limits)
            .map_err(|error| {
            SemanticProviderError::internal(format!(
                "workspace dispatch produced invalid relation provenance: {error}"
            ))
        })?;
        result.mark_member_receiver_preparation(member_receiver_preparation);
        result.mark_member_field_anchor(member_field_anchor);
        if resolver_proved_no_callee {
            result.mark_resolver_proved_no_callee();
        }
        stable_package_values.retain(|proof: &StablePackageValueProvenance| {
            result
                .candidates()
                .iter()
                .any(|candidate| candidate.target() == proof.initializer())
        });
        result.mark_stable_package_values(stable_package_values);
        if workspace_hierarchy_unenumerated
            && ordinary_dispatch_is_only_unresolved_or_heuristic_external
            && !displaceable_heuristic_external_boundaries.is_empty()
            && hinted_dispatch.is_none()
            && !final_candidates_truncated
            && !cancelled_targets_truncated
            && !provenance_truncated
            && materialization_exceeded.is_none()
            && !request.cancellation.is_cancelled()
        {
            result.mark_complete_receiver_hint_refinable();
        }
        let retained_work = dispatch_result_work(&result);
        let total_work = reported_work.conservative_add(retained_work);
        if let Err(exceeded) = staged_budget.admit(retained_work) {
            request.budget.retain_performed_work(&staged_budget);
            if cancelled {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                });
            }
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: total_work,
            });
        }
        reported_work = total_work;
        *request.budget = staged_budget;

        let interruption = materialization_exceeded.or(gap_exceeded);
        let result =
            match finish_dispatch_interruption(result, cancelled, interruption, reported_work) {
                Ok(result) => result,
                Err(outcome) => return Ok(*outcome),
            };
        let status_quality = if declared_targets_ambiguous {
            DispatchQuality::Ambiguous
        } else if anonymous_receiver_refined
            || proven_bound_receiver_dispatch
            || go_interface_receiver_refined
            || resolver_proven_external_static
            || resolver_proven_java_final
            || native_java_candidate_set_proven
            || csharp_modeled_member_closure.is_some()
            || js_ts_modeled_member_closure.is_some()
            || python_modeled_function_closure.is_some()
            || python_external_class_call.is_some()
            || python_exact_external_receiver
            || resolver_proved_no_callee
        {
            // The modeled-member closure answers the same target-set question
            // the receiverless static closure answers: the exact resolver
            // proved the external member and the reviewed complete summary
            // closes its behavior, so the boundary is a resolved external
            // arm, not an unknown external root (#3406).
            //
            // A native Java overload envelope can retain multiple targets
            // while proving that every possible target was retained. Keep
            // that call complete at the dispatch layer; the declaration lookup
            // remains Ambiguous for consumers that need one overload.
            //
            // A conversion the resolver adjudicated as not applicable names
            // no callee at all: the empty target set is the complete answer,
            // so the low-level `NoDefinition` status cannot degrade it to an
            // unknown outcome (#3428).
            DispatchQuality::Complete
        } else {
            dispatch_quality_for_status(lookup.status, lookup.boundary)
        };
        let quality = if status_quality == DispatchQuality::Ambiguous
            && matches!(
                materialization_quality,
                DispatchQuality::Complete | DispatchQuality::Ambiguous | DispatchQuality::Unproven
            ) {
            // Ambiguous lookup remains the precise dispatch classification
            // when its retained candidates are merely unproven or partial.
            // Candidate evidence must not collapse the set-level ambiguity
            // into generic Unproven.
            DispatchQuality::Ambiguous
        } else {
            merge_dispatch_quality(status_quality, materialization_quality)
        };
        dispatch_outcome(result, quality, reported_work)
    }

    /// The function-literal body a Go package variable holds at every call in
    /// the workspace, with the census that proves it (#3787), or the reason
    /// the proof does not hold.
    ///
    /// `None` means the rule does not apply: the declaration is not a
    /// package-level `var` spec, or the execution or source budget, or a
    /// changed source, prevents reading it. The ordinary no-body boundary
    /// then stands.
    ///
    /// `artifact` is the declaring file's complete semantic artifact. The
    /// proof reads that artifact's exact source so the initializer span it
    /// returns names a procedure of the same revision.
    fn stable_package_function_value(
        &self,
        variable: &CodeUnit,
        artifact: &Arc<SemanticArtifact>,
        request: &SemanticRequest<'_>,
    ) -> Result<Option<Result<StablePackageValueProvenance, String>>, SemanticProviderError> {
        if !request.charge_execution_traversal(1) {
            return Ok(None);
        }
        let Some(snapshot) = self
            .workspace
            .current_program_semantics_artifact_source(variable.source(), usize::MAX)?
        else {
            return Ok(None);
        };
        if snapshot.key() != artifact.key() {
            return Ok(None);
        }
        let (_, source) = snapshot.into_parts();
        let proof = match language_support_for_hook(
            variable.source().language(),
            "stable_package_function_value_proof",
        )
        .and_then(|support| {
            support.stable_package_function_value_proof(
                self.workspace.analyzer(),
                variable,
                &source,
            )
        }) {
            None => return Ok(None),
            Some(Ok(proof)) => proof,
            Some(Err(reason)) => return Ok(Some(Err(reason))),
        };
        let bodies = artifact
            .procedures()
            .iter()
            .filter(|procedure| {
                let span = procedure.locator().anchor().span();
                procedure.kind() == ProcedureKind::Lambda
                    && procedure.lexical_parent().is_none()
                    && span.start_byte() as usize == proof.initializer_start
                    && span.end_byte() as usize == proof.initializer_end
            })
            .collect::<Vec<_>>();
        let [body] = bodies.as_slice() else {
            return Ok(Some(Err(format!(
                "the initializer has {} published bodies, not one",
                bodies.len()
            ))));
        };
        let initializer = artifact
            .procedure_handle(body.id())
            .expect("a procedure of the artifact has a handle in that artifact");
        Ok(Some(Ok(StablePackageValueProvenance::new(
            variable.clone(),
            initializer,
            proof.references.into_boxed_slice(),
            proof.scope,
        ))))
    }

    /// Refine a Java virtual call only when the source resolver and heap
    /// oracle independently close the callable and receiver identities.
    ///
    /// Resolver candidates own callable identity. A proven singleton
    /// allocation owns receiver identity. An anonymous implementation method
    /// is structurally contained by its object-creation source anchor, so one
    /// contained resolver candidate composes those facts without comparing a
    /// method name or rendered signature.
    fn refine_java_anonymous_receiver_dispatch(
        &self,
        call: &CallSiteHandle,
        semantic_call: &SemanticCallSite,
        candidates: &mut Vec<DispatchCandidate>,
        boundaries: &mut Vec<DispatchBoundary>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(bool, SemanticWork), SemanticProviderError> {
        if call.procedure().artifact().key().language()
            != SemanticLanguage::Standard(Language::Java)
        {
            return Ok((false, SemanticWork::default()));
        }
        let Some(receiver_id) = semantic_call.receiver else {
            return Ok((false, SemanticWork::default()));
        };
        if candidates.is_empty()
            || boundaries.is_empty()
            || boundaries
                .iter()
                .any(|boundary| !matches!(boundary.kind, DispatchBoundaryKind::Unmaterialized(_)))
            || candidates.iter().any(|candidate| {
                !candidate
                    .target()
                    .semantics()
                    .locator()
                    .declaration()
                    .segments()
                    .iter()
                    .any(|segment| {
                        segment.kind() == DeclarationSegmentKind::Type && segment.name().is_none()
                    })
            })
        {
            return Ok((false, SemanticWork::default()));
        }

        let procedure = call.procedure();
        let receiver = procedure.value_handle(receiver_id).ok_or_else(|| {
            SemanticProviderError::internal("Java dispatch receiver value is stale")
        })?;
        let point = procedure
            .point_handle(semantic_call.point)
            .ok_or_else(|| SemanticProviderError::internal("Java dispatch call point is stale"))?;
        let query = ValueAtPoint::new(
            receiver,
            point,
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not construct Java receiver points-to query: {error}"
            ))
        })?;
        let outcome = HeapOracle::pointees(self, &query, request)?;
        let work = outcome.work();
        let SemanticOutcome::Complete {
            value: points_to, ..
        } = &outcome
        else {
            return Ok((false, work));
        };
        if points_to.objects().coverage() != CandidateCoverage::Exhaustive {
            return Ok((false, work));
        }
        let [object] = points_to.objects().candidates() else {
            return Ok((false, work));
        };
        if !object.is_proven_complete()
            || object.value().cardinality() != ObjectCardinality::Singleton
        {
            return Ok((false, work));
        }
        let AbstractObjectIdentity::Allocation(allocation) = object.value().identity() else {
            return Ok((false, work));
        };
        if allocation.procedure() != procedure {
            return Ok((false, work));
        }
        let allocation_row = procedure
            .semantics()
            .allocation(allocation.id())
            .ok_or_else(|| SemanticProviderError::internal("Java receiver allocation is stale"))?;
        let allocation_span = procedure
            .semantics()
            .source_mapping(allocation_row.source)
            .ok_or_else(|| {
                SemanticProviderError::internal("Java receiver allocation source is stale")
            })?
            .locator
            .anchor()
            .span();

        let mut retained = candidates
            .iter()
            .filter(|candidate| {
                let target = candidate.target();
                if target.artifact().key() != procedure.artifact().key() {
                    return false;
                }
                let span = target.semantics().locator().anchor().span();
                allocation_span.start_byte() <= span.start_byte()
                    && span.end_byte() <= allocation_span.end_byte()
            })
            .cloned();
        let Some(mut exact) = retained.next() else {
            return Ok((false, work));
        };
        if retained.next().is_some() {
            return Ok((false, work));
        }

        exact.excluded_targets = candidates
            .iter()
            .filter(|candidate| candidate.target() != exact.target())
            .map(|candidate| candidate.target().clone())
            .collect();
        exact.proof = ProofStatus::Proven;
        exact.completeness = EvidenceCompleteness::Complete;
        candidates.clear();
        candidates.push(exact);
        boundaries.clear();
        Ok((true, work))
    }

    /// Close a Go interface call only when the heap oracle proves an
    /// exhaustive set of allocation objects and every allocation has one
    /// structured concrete Go method for the selected member.
    fn refine_go_interface_receiver_dispatch(
        &self,
        call: &CallSiteHandle,
        semantic_call: &SemanticCallSite,
        member: Option<&str>,
        target_groups: &mut VecDeque<DispatchTargetGroup>,
        boundaries: &mut Vec<DispatchBoundary>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(bool, SemanticWork, Option<SemanticBudgetExceeded>), SemanticProviderError> {
        let Some(member) = member else {
            return Ok((false, SemanticWork::default(), None));
        };
        let Some(receiver_id) = semantic_call.receiver else {
            return Ok((false, SemanticWork::default(), None));
        };
        let procedure = call.procedure();
        let receiver = procedure.value_handle(receiver_id).ok_or_else(|| {
            SemanticProviderError::internal("Go dispatch receiver value is stale")
        })?;
        let point = procedure
            .point_handle(semantic_call.point)
            .ok_or_else(|| SemanticProviderError::internal("Go dispatch call point is stale"))?;
        let query = ValueAtPoint::new(
            receiver,
            point,
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not construct Go receiver points-to query: {error}"
            ))
        })?;
        let outcome = HeapOracle::pointees(self, &query, request)?;
        let mut work = outcome.work();
        let SemanticOutcome::Complete {
            value: points_to, ..
        } = outcome
        else {
            return Ok((false, work, None));
        };
        if points_to.objects().coverage() != CandidateCoverage::Exhaustive {
            return Ok((false, work, None));
        }

        // Points-to proves which allocation sites can reach the receiver, but
        // the implementation must still satisfy the declared interface
        // method's structured signature. Reuse Go's method-family relation as
        // that independent check; matching the selector name alone is not a
        // sufficient proof.
        let Some(interface_member) = target_groups
            .front()
            .map(|group| &group.representative)
            .filter(|member| member.owner_is_type_scope())
        else {
            return Ok((false, work, None));
        };
        let ImplementorTargets::Proven(compatible_methods) = virtual_dispatch_implementor_targets(
            self.workspace.analyzer(),
            interface_member,
            request.cancellation,
        ) else {
            return Ok((false, work, None));
        };
        let compatible_methods = compatible_methods.into_iter().collect::<HashSet<_>>();

        let analyzer = self.workspace.analyzer();
        let project_root = analyzer.project().root();
        let mount = WorkspaceMountId::from_root(project_root);
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut methods = HashSet::default();
        for object in points_to.objects().candidates() {
            if !object.is_proven_complete() {
                return Ok((false, work, None));
            }
            let AbstractObjectIdentity::Allocation(allocation) = object.value().identity() else {
                return Ok((false, work, None));
            };
            let allocation_procedure = allocation.procedure();
            let key = allocation_procedure.artifact().key();
            if key.mount() != mount || key.language() != SemanticLanguage::Standard(Language::Go) {
                return Ok((false, work, None));
            }
            let allocation_site = allocation_procedure
                .semantics()
                .allocation(allocation.id())
                .ok_or_else(|| {
                    SemanticProviderError::internal("Go receiver allocation is stale")
                })?;
            let allocation_span = allocation_procedure
                .semantics()
                .source_mapping(allocation_site.source)
                .ok_or_else(|| {
                    SemanticProviderError::internal("Go receiver allocation has no source mapping")
                })?
                .locator
                .anchor()
                .span();
            let file = ProjectFile::new(project_root.to_path_buf(), key.path().as_path());
            let Some(source) = analyzer.indexed_source(&file) else {
                return Ok((false, work, None));
            };
            let Some(tree) = parse_tree_for_language(&file, Language::Go, &source) else {
                return Ok((false, work, None));
            };
            let start = allocation_span.start_byte() as usize;
            let end = allocation_span.end_byte() as usize;
            let Some(allocation_node) = tree.root_node().descendant_for_byte_range(start, end)
            else {
                return Ok((false, work, None));
            };
            let resolution =
                language_support_for_hook(Language::Go, "definition_allocation_selector_method")
                    .expect("Go allocation language support")
                    .definition_allocation_selector_method(
                        analyzer,
                        scope.token(),
                        &file,
                        &source,
                        tree.root_node(),
                        allocation_node,
                        member,
                        start,
                        crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(
                        ),
                        Some(request.cancellation),
                    );
            let resolution_work = resolution.work();
            let charged = SemanticWork {
                nested_entries: resolution_work
                    .setup_nodes
                    .saturating_add(resolution_work.scope_nodes)
                    .saturating_add(resolution_work.summary_expansions)
                    .saturating_add(resolution_work.resolution_rounds),
                ..SemanticWork::default()
            };
            work = work.conservative_add(charged);
            request.budget.charge_work(charged);
            match resolution {
                BoundedResolution::Complete {
                    value: Some(method),
                    ..
                } if compatible_methods.contains(&method) => {
                    methods.insert(method);
                }
                BoundedResolution::Complete { value: None, .. }
                | BoundedResolution::Complete { value: Some(_), .. }
                | BoundedResolution::Exceeded { .. }
                | BoundedResolution::Cancelled { .. } => {
                    return Ok((false, work, None));
                }
            }
        }
        if methods.is_empty() {
            return Ok((false, work, None));
        }

        target_groups.clear();
        let mut methods = methods.into_iter().collect::<Vec<_>>();
        methods.sort();
        target_groups.extend(methods.into_iter().map(|method| DispatchTargetGroup {
            representative: method,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            receiver_hint: false,
            native_incomplete_source_reason: None,
        }));
        boundaries.retain(|boundary| {
            if matches!(boundary.kind, DispatchBoundaryKind::External(_)) {
                return false;
            }
            !matches!(
                (&boundary.kind, &boundary.proof),
                (
                    DispatchBoundaryKind::Unresolved,
                    ProofStatus::Unproven(reason)
                ) if reason.as_ref()
                    == "Go interface implementations are not closed by the analyzed module"
            )
        });
        Ok((true, work, None))
    }
}

impl WorkspaceSemanticOracle<'_> {
    pub(crate) fn resolve_argument_callable(
        &self,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
        mut resolve_entering: impl FnMut(
            &CallSiteHandle,
            &mut SemanticRequest<'_>,
        ) -> Result<
            SemanticOutcome<DispatchResult>,
            SemanticProviderError,
        >,
    ) -> Result<Option<SemanticOutcome<DispatchResult>>, SemanticProviderError> {
        if context.was_truncated()
            || context.calls().len() > self.limits().call_context_depth()
            || call.procedure().artifact().key().language()
                != SemanticLanguage::Standard(Language::Go)
        {
            return Ok(None);
        }
        let Some(entering_call) = context.calls().last() else {
            return Ok(None);
        };
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("callback call is absent"))?;
        let ordinal_outcome = callback_parameter(call.procedure(), row.callee, request)?;
        let ordinal_work = ordinal_outcome.work();
        let ordinal = match ordinal_outcome {
            SemanticOutcome::Complete {
                value: Some(value), ..
            } => value,
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            }
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
            _ => return Ok(None),
        };
        let entering_outcome = resolve_entering(entering_call, request)?;
        let work = ordinal_work.conservative_add(entering_outcome.work());
        let entering = match entering_outcome {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
            _ => return Ok(None),
        };
        if entering.coverage() != CandidateCoverage::Exhaustive {
            return Ok(None);
        }
        let [candidate] = entering.candidates() else {
            return Ok(None);
        };
        if candidate.target() != call.procedure()
            || candidate.proof() != &ProofStatus::Proven
            || candidate.completeness() != &EvidenceCompleteness::Complete
        {
            return Ok(None);
        }
        let caller_context = OracleCallContext::bounded(
            context.calls()[..context.calls().len() - 1].to_vec(),
            *self.limits(),
        );
        let bindings_outcome =
            self.call_bindings(entering_call, candidate, &caller_context, request)?;
        let mut work = work.conservative_add(bindings_outcome.work());
        let bindings = match bindings_outcome {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
            _ => return Ok(None),
        };
        if bindings.coverage() != CandidateCoverage::Exhaustive {
            return Ok(None);
        }
        let mut selected = None;
        for binding in bindings.bindings() {
            let CallBinding::ArgumentGroup(group) = binding else {
                continue;
            };
            if group.coverage() != CandidateCoverage::Exhaustive {
                return Ok(None);
            }
            for mapping in group.mappings() {
                if request.cancellation.is_cancelled() {
                    return Ok(Some(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    }));
                }
                let scan = SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                };
                work = work.conservative_add(scan);
                request.budget.charge_work(scan);
                if mapping.value().formal().kind() != (ProcedurePortKind::Parameter { ordinal }) {
                    continue;
                }
                if mapping.value().formal().procedure() != call.procedure()
                    || mapping.proof() != &ProofStatus::Proven
                    || mapping.completeness() != &EvidenceCompleteness::Complete
                    || !mapping.value().preserves_reference_identity()
                    || !matches!(mapping.value().actual(), CallArgumentEndpoint::Value(_))
                    || selected.is_some()
                {
                    return Ok(None);
                }
                selected = Some(mapping);
            }
        }
        let Some(mapping) = selected else {
            return Ok(None);
        };
        let actual = mapping.value().actual().value();
        let target_outcome =
            self.local_callable_target(actual.procedure(), actual.id(), request)?;
        work = work.conservative_add(target_outcome.work());
        let mut producer = None;
        let target = match target_outcome {
            SemanticOutcome::Complete {
                value: Some(value), ..
            } => value,
            SemanticOutcome::Complete { value: None, .. } => {
                let produced =
                    returned_callable_producer(actual.procedure(), actual.id(), request)?;
                work = work.conservative_add(produced.work());
                let (factory_call, returned_result) = match produced {
                    SemanticOutcome::Complete {
                        value: Some(value), ..
                    } => value,
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        return Ok(Some(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        }));
                    }
                    SemanticOutcome::Cancelled { .. } => {
                        return Ok(Some(SemanticOutcome::Cancelled {
                            partial: None,
                            work,
                        }));
                    }
                    _ => return Ok(None),
                };
                let factory = resolve_entering(&factory_call, request)?;
                work = work.conservative_add(factory.work());
                let factory = match factory {
                    SemanticOutcome::Complete { value, .. } => value,
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        return Ok(Some(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        }));
                    }
                    SemanticOutcome::Cancelled { .. } => {
                        return Ok(Some(SemanticOutcome::Cancelled {
                            partial: None,
                            work,
                        }));
                    }
                    _ => return Ok(None),
                };
                if factory.coverage() != CandidateCoverage::Exhaustive {
                    return Ok(None);
                }
                let [factory_candidate] = factory.candidates() else {
                    return Ok(None);
                };
                if factory_candidate.proof() != &ProofStatus::Proven
                    || factory_candidate.completeness() != &EvidenceCompleteness::Complete
                {
                    return Ok(None);
                }
                let returned = self.returned_callable_target(
                    &factory_call,
                    factory_candidate,
                    returned_result,
                    &caller_context,
                    request,
                )?;
                work = work.conservative_add(returned.work());
                let target = match returned {
                    SemanticOutcome::Complete {
                        value: Some(value), ..
                    } => value,
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        return Ok(Some(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        }));
                    }
                    SemanticOutcome::Cancelled { .. } => {
                        return Ok(Some(SemanticOutcome::Cancelled {
                            partial: None,
                            work,
                        }));
                    }
                    _ => return Ok(None),
                };
                producer = Some(ReturnedCallableProvenance::new(
                    factory_call,
                    factory_candidate.target().clone(),
                    target.closure.clone(),
                    target.captures.clone(),
                ));
                target
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(Some(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                }));
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(Some(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
            _ => return Ok(None),
        };
        let mut candidates = vec![
            DispatchCandidate::new(
                target.closure.clone(),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                *self.limits(),
            )
            .map_err(|error| {
                SemanticProviderError::internal(format!("invalid callback candidate: {error}"))
            })?,
        ];
        let mut boundaries = Vec::new();
        attach_dispatch_provenance(
            call,
            &mut candidates,
            &mut boundaries,
            scoped_call_dispatch_gap(call.procedure().semantics(), row),
            scoped_procedure_dispatch_gap(call.procedure()),
            *self.limits(),
        )?;
        let mut result = DispatchResult::new(
            call,
            candidates,
            boundaries,
            CandidateCoverage::Exhaustive,
            *self.limits(),
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!("invalid callback dispatch: {error}"))
        })?;
        result.mark_argument_callable(ArgumentCallableProvenance {
            producer,
            entering_call: entering_call.clone(),
            caller_context,
            callee: call.procedure().clone(),
            formal_ordinal: ordinal,
            actual: actual.clone(),
            creation: target.creation,
            closure: target.closure,
            captures: target.captures,
            capture_bindings: target.capture_bindings,
            binding: mapping.provenance().to_vec().into_boxed_slice(),
        });
        let output_work = dispatch_result_work(&result).conservative_add(SemanticWork {
            captures: result
                .argument_callable()
                .expect("argument proof just published")
                .producer()
                .map_or(0, |producer| producer.captures().len()),
            nested_entries: (8usize
                + result
                    .argument_callable()
                    .expect("argument proof just published")
                    .producer()
                    .map_or(0, |producer| 3 + producer.captures().len()))
            .saturating_add(
                result
                    .argument_callable()
                    .expect("argument proof just published")
                    .captures()
                    .len()
                    .saturating_add(
                        result
                            .argument_callable()
                            .expect("argument proof just published")
                            .capture_bindings()
                            .len(),
                    )
                    .saturating_add(
                        result
                            .argument_callable()
                            .expect("argument proof just published")
                            .binding()
                            .len(),
                    ),
            ),
            ..SemanticWork::default()
        });
        let work = work.conservative_add(output_work);
        if let Err(exceeded) = request.budget.admit(output_work) {
            return Ok(Some(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            }));
        }
        Ok(Some(SemanticOutcome::Complete {
            value: result,
            work,
        }))
    }
}

impl DispatchOracle for WorkspaceSemanticOracle<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let mut session =
            self.prepare_call_dispatch_session(Arc::clone(call.procedure().artifact()));
        session.resolve_call(call, request)
    }
    fn resolve_call_in_context(
        &self,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let before = request.budget.used();
        if let Some(outcome) =
            self.resolve_argument_callable(call, context, request, |entering, request| {
                self.resolve_call(entering, request)
            })?
        {
            return Ok(outcome);
        }
        let probe = request.budget.used().saturating_sub(before);
        let mut outcome = self.resolve_call(call, request)?;
        match &mut outcome {
            SemanticOutcome::Complete { work, .. }
            | SemanticOutcome::Ambiguous { work, .. }
            | SemanticOutcome::Unknown { work, .. }
            | SemanticOutcome::Unsupported { work, .. }
            | SemanticOutcome::Unproven { work, .. }
            | SemanticOutcome::ExceededBudget { work, .. }
            | SemanticOutcome::Cancelled { work, .. } => *work = probe.conservative_add(*work),
        }
        Ok(outcome)
    }
}

/// Proof state of the workspace implementor set for one declaration.
#[derive(Debug)]
#[doc(hidden)]
pub enum ImplementorTargets {
    NotApplicable,
    Unproven {
        established: Vec<CodeUnit>,
        reason: Option<crate::analyzer::structural::resolution::MemberFamilyReason>,
    },
    Proven(Vec<CodeUnit>),
}

/// The workspace members that implement or override a body-less callee
/// declaration: class-hierarchy analysis for virtual dispatch (#2205).
///
/// A call written against an interface, or against an abstract method, names a
/// declaration that has no body. Dispatch resolves the call to that declaration,
/// materializes its file, finds no procedure, and stops. The value-flow snapshot
/// of the enclosing procedure is then reported unknown and require-model taint
/// abstains -- even though the code that actually runs is in the same workspace,
/// in the classes below the declared type. This function supplies those classes'
/// members so the flow can continue through one of them.
///
/// Three properties make this honest rather than a guess.
///
/// It is *scoped*. The caller only asks after the declaration's own file
/// materialized completely, so "no member family" is a fact about the hierarchy
/// rather than about how far materialization got. Two callers ask, and they are
/// scoped differently.
///
/// The first is the body-less case: the file published no procedure for the
/// declaration, which is exactly the interface-method and abstract-method case
/// (#2205). Without expansion there is no code to analyze at all, so this
/// caller always asks.
///
/// The second is the concrete case: the file did publish a body, and the
/// question is whether a subclass override could run instead (#2277). That
/// strictly widens a candidate set which already names analyzable code, so this
/// caller always asks to establish whether the override set is empty, but
/// expands nonempty targets only when the workspace's
/// [`crate::analyzer::DispatchHierarchyExpansion::concrete_overrides`] is on.
///
/// A `native` method is excluded from both: its body is outside every source
/// this workspace can read, which is a boundary fact rather than a hierarchy
/// question, and the declaration records it.
///
/// It is *exact*. The edges come from the member-family capability
/// ([`crate::analyzer::usages::MemberFamilyProvider`], #1477), which derives
/// `implemented_by` and `overridden_by` by bounded inversion over the same
/// forward `implements`/`overrides` relation an analyzer proves from a
/// declaration and its owner's hierarchy. Nothing is matched by fully-qualified
/// name or by rendered signature text. Callers expand only a proven family; an
/// inheritance cycle, an unrecorded modifier, or an unresolved overload set
/// leaves the dispatch gap open.
///
/// It is *bounded*. The family walk carries its own shared visit budget and the
/// caller's cancellation token, and the caller charges the expansion against the
/// request's traversal allowance before asking.
///
/// The result is a set of *candidates*, never proven edges. The caller queues
/// them with [`UsageProof::Unproven`] and keeps the unmaterialized boundary for
/// the declaration itself, so an implementor the analyzer cannot materialize
/// still surfaces as its own honest diagnostic beside any flow that completes
/// through a sibling implementor.
///
/// `Proven` contains the targets of a proven family, possibly empty. Only a
/// proven empty set establishes the absence of implementors. `Unproven` carries
/// the targets an unproven family did establish and its reason; callers must
/// not treat that set as exhaustive. `NotApplicable` means the question does not
/// apply to this declaration or the language states no member-family capability.
///
/// Set `BIFROST_DEBUG_CHA=1` to print one line per expansion, which is how the
/// resolution was measured at corpus scale.
#[doc(hidden)]
pub fn virtual_dispatch_implementor_targets(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    cancellation: &CancellationToken,
) -> ImplementorTargets {
    if !declaration.is_function() {
        return ImplementorTargets::NotApplicable;
    }
    let metadata = analyzer.signature_metadata(declaration);
    if metadata
        .iter()
        .any(|entry| entry.callable_modifiers_recorded() && entry.callable_is_native())
    {
        return ImplementorTargets::NotApplicable;
    }
    let Some(provider) = analyzer.member_family_provider() else {
        return ImplementorTargets::NotApplicable;
    };
    // A provider that exists for the workspace as a whole may still state no
    // family for *this* member's language (Kotlin publishes the external-root
    // half only, for example). That is `NotApplicable`: the language
    // states no member family, which is not an empty answer about the
    // hierarchy and must never read as one.
    if provider.member_family_capability(declaration)
        == crate::analyzer::structural::resolution::MemberFamilyCapability::Unsupported
    {
        return ImplementorTargets::NotApplicable;
    }
    let answer = provider.member_family(declaration, Some(cancellation));
    let targets = answer
        .edges
        .iter()
        .filter(|edge| {
            matches!(
                edge.relation,
                MethodFamilyRelation::ImplementedBy | MethodFamilyRelation::OverriddenBy
            )
        })
        .filter(|edge| {
            language_support_for_hook(
                declaration.source().language(),
                "virtual_dispatch_target_is_applicable",
            )
            .is_none_or(|support| {
                support.virtual_dispatch_target_is_applicable(
                    analyzer,
                    declaration,
                    edge.owner.source(),
                )
            })
        })
        .map(|edge| edge.target.clone())
        .collect::<Vec<_>>();
    if debug_cha_enabled() {
        eprintln!(
            "virtual_dispatch_implementor_targets {} proven={} outcome={:?} reason={:?} implemented_by={}",
            declaration.fq_name(),
            answer.descendants.is_proven(),
            answer.outcome,
            answer.reason,
            targets.len()
        );
    }
    if answer.descendants.is_proven() {
        ImplementorTargets::Proven(targets)
    } else {
        ImplementorTargets::Unproven {
            established: targets,
            reason: answer.descendants.reason,
        }
    }
}

pub(crate) fn jvm_external_member_identity(
    target: &UnmaterializedExternalTarget,
) -> Option<JvmExternalMemberIdentity> {
    let SemanticLanguage::Standard(language) = target.language() else {
        return None;
    };
    if !matches!(
        language,
        Language::Java | Language::Kotlin | Language::Scala
    ) {
        return None;
    }
    Some(JvmExternalMemberIdentity::new(
        language,
        target.owner_fqn(),
        target.member(),
        usize::try_from(target.arity()).expect("u32 call arity fits usize"),
        if target.has_receiver() {
            JvmReceiverSemantics::Instance
        } else {
            JvmReceiverSemantics::Static
        },
    ))
}

/// #2371 fallback for non-JVM analyzers: whether the complete short-name index
/// proves that no workspace declaration can override `target`'s external
/// member.
///
/// `virtual_dispatch_implementor_targets` above answers the same "workspace
/// half" question for a *workspace* declaration with no body, by expanding its
/// `CodeUnit` through class-hierarchy analysis. An unmaterialized external
/// member has no such `CodeUnit` -- it is definitionally not indexed -- so
/// that expansion never runs for it, and #2371's discharge rule cannot treat
/// "never ran" as "enumerated and proven empty". JVM calls no longer use this
/// fallback: #2580 asks their exact external-root hierarchy query instead.
///
/// The proof this asks instead: a workspace type overriding `target` must
/// declare a member spelled exactly like it (the same terminal identifier), so
/// no workspace declaration with that identifier means no workspace type
/// overrides it. `lookup_candidates_by_identifier` answers this from the
/// analyzer's persisted index without a source scan, but only a *complete*
/// index makes an empty answer conclusive; an analyzer that cannot answer
/// cheaply reports an empty set regardless, so the completeness flag is
/// checked first.
///
/// The proof is sound only in the refusing direction. An unrelated
/// same-named declaration -- a workspace class with its own, unconnected
/// `getParameter` method, say -- costs a discharge, exactly like an
/// incomplete index does: both fail closed rather than open. Neither
/// manufactures a false discharge, which is what keeps the workspace-double
/// fixture (#2371) from being skated past in languages without the stronger
/// capability.
pub(crate) fn external_member_workspace_override_proven_absent(
    analyzer: &dyn IAnalyzer,
    target: &UnmaterializedExternalTarget,
) -> bool {
    language_support_for_hook(target.language().language(), "external_type_is_sealed")
        .and_then(|support| {
            support.external_type_is_sealed(
                analyzer,
                analyzer.semantic_model_overlay(),
                target.owner_fqn(),
            )
        })
        .is_some_and(|sealed| sealed)
        || (analyzer.has_complete_symbol_lookup_index()
            && analyzer
                .lookup_candidates_by_identifier(target.member())
                .is_empty())
}

/// #2371: the arm a call keeps when the workspace half of its residual
/// dynamic-dispatch gap is not proven enumerated. Distinct from the generic
/// [`truncated_dispatch_boundary`] reason so a corpus trace can tell the two
/// causes apart; both are `Truncated`, so both refuse discharge identically.
pub(crate) fn workspace_hierarchy_unenumerated_boundary(
    status: ExternalMemberFamilyStatus,
) -> DispatchBoundary {
    let completeness = match status {
        ExternalMemberFamilyStatus::Complete => {
            unreachable!("a complete external member family needs no refusing boundary")
        }
        ExternalMemberFamilyStatus::Incomplete(reason) => {
            format!("external-root workspace hierarchy query was incomplete: {reason:?}")
        }
        ExternalMemberFamilyStatus::Unsupported => {
            "external-root workspace hierarchy query is unsupported".to_owned()
        }
        ExternalMemberFamilyStatus::Cancelled => {
            "external-root workspace hierarchy query was cancelled".to_owned()
        }
        ExternalMemberFamilyStatus::BudgetExhausted => {
            "external-root workspace hierarchy query exhausted its caller budget".to_owned()
        }
    };
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: ProofStatus::Unproven(
            "workspace implementors of the external member are not proven enumerated".into(),
        ),
        completeness: EvidenceCompleteness::Partial(completeness.into()),
        provenance: Box::new([]),
    }
}

/// #3406: the arm a modeled member call keeps when the reviewed summary is
/// active but a workspace member write or module-object escape means the
/// member value may have been replaced before the call runs. The authored
/// claim describes implementations of the external member, not a different
/// value written over it, so the workspace half refuses the closure with the
/// same typed shape an unenumerated hierarchy uses (#2371).
pub(crate) fn modeled_member_mutation_unproven_boundary() -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: ProofStatus::Unproven(
            "workspace mutation of the external member is not proven absent".into(),
        ),
        completeness: EvidenceCompleteness::Partial(
            "a member write or module-object escape may replace the external member before the call runs"
                .into(),
        ),
        provenance: Box::new([]),
    }
}

/// Whether a class-hierarchy-proven *empty* override set discharges a call's
/// dynamic-dispatch gap, for an overridable (non-final, non-private,
/// non-static) concrete method (#2480).
///
/// `closed_dispatch_discharges_gap` only answers the structural half: a
/// `final`/`private`/`static` member cannot be overridden, so its call sites
/// never carry a residual dispatch arm. An ordinary overridable instance
/// method called on a same-class or same-object receiver -- `doPost(...)`
/// inside `doGet`'s own body, say -- is `DispatchExtensibility::Open`
/// regardless of whether any override actually exists, so that predicate
/// never discharges it, and the call's own "may select an override" gap
/// (added unconditionally at Java-adapter lowering) stays open on every such
/// call in the corpus.
///
/// The class-hierarchy answer this call's own resolution already computed
/// (`concrete_overrides_proven_absent` in `resolve_call`, independent of the
/// `concrete_overrides` widen flag) closes exactly that residual honestly: if
/// class-hierarchy analysis *proves* the override set of every concrete match
/// is empty, no other target could have run, so the single retained candidate
/// is the whole answer. This can only discharge more, never select a
/// different target: an empty proven set contributes no candidate of its own,
/// so a wrong answer here would require `virtual_dispatch_implementor_targets`
/// itself to be unsound, which is the same proof #2205 and #2371 already rely
/// on for the body-less and external-interface cases.
///
/// `matched_concrete_groups` guards against the vacuous case where no
/// concrete match happened at all (`concrete_overrides_proven_absent` starts
/// `true` and is never touched): a call resolved only through a body-less
/// declaration, or not resolved at all, must not discharge here.
///
/// `boundaries` must be empty because a boundary arm is exactly a dispatch
/// arm the empty-override proof does not cover. A body-less root (an
/// interface or abstract member) queues its workspace implementors as
/// further target groups, and each implementor is itself a concrete match
/// with a possibly proven-empty override set -- but the open question at
/// such a call is the *implementor set* of the root, which the boundary
/// pushed for the body-less declaration records and which proving each known
/// implementor override-free does not close. The same holds for external,
/// truncated, and unenumerated-hierarchy arms. Without this condition,
/// `interface Shape { int area(); }` with two workspace implementors claimed
/// an exhaustive target set (caught by
/// `open_interface_receiver_never_upgrades_to_proven_dispatch` and
/// `a_possible_dispatch_downgrades_a_definite_declaration_to_a_possible_effect`).
pub(crate) fn concrete_overrides_proven_absent_discharges_gap(
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    gap: &SemanticGap,
    matched_concrete_groups: bool,
    concrete_overrides_proven_absent: bool,
) -> bool {
    gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && !candidates.is_empty()
        && candidates.iter().all(|candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
        })
        && boundaries.is_empty()
        && matched_concrete_groups
        && concrete_overrides_proven_absent
}

/// Whether exact Go or Rust resolution closes the target set of an external
/// package function or concrete method selected from an activated
/// declaration overlay.
///
/// A package function is statically selected. Go also has no virtual method
/// override dispatch: the resolver carries a closed receiver proof only after
/// structured value typing and the declaration overlay prove one direct public
/// method on one concrete struct. A Rust method on a receiver whose written
/// type names one concrete type is statically dispatched too, and the Rust
/// route carries a closed proof only for that shape (#3757). Interface, trait
/// object, and otherwise unresolved receiver calls carry no proof and remain
/// open.
pub(crate) fn exact_closed_external_dispatch_discharges_gap(
    exact_closed_external_call: Option<&ExactExternalCallProof>,
    call_language: SemanticLanguage,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    gap: &SemanticGap,
) -> bool {
    let Some(proof) = exact_closed_external_call else {
        return false;
    };
    let SemanticLanguage::Standard(language) = call_language else {
        return false;
    };
    let Some((expected_owner, expected_member)) =
        split_canonical_qualified_callee(proof.canonical_callee(), language)
    else {
        return false;
    };
    gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && candidates.is_empty()
        && matches!(
            boundaries,
            [boundary]
                if matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
                    && matches!(boundary.proof, ProofStatus::Proven)
                    && boundary
                        .unmaterialized_external_target
                        .as_ref()
                        .is_some_and(|target| {
                            target.language() == call_language
                                && target.owner_fqn() == expected_owner
                                && target.member() == expected_member
                                && target.has_receiver() == proof.has_receiver()
                                && target.arity() == proof.parameter_count()
                        })
        )
}

/// Finality closes only this exact selected Java declaration's target set.
/// The missing external body remains an independent boundary.
pub(crate) fn resolver_proven_java_final_boundary(
    language: SemanticLanguage,
    status: Option<DefinitionLookupStatus>,
    proof: Option<&ExactExternalCallProof>,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
) -> bool {
    if language != SemanticLanguage::Standard(Language::Java)
        || !matches!(
            status,
            Some(
                DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            )
        )
        || !candidates.is_empty()
    {
        return false;
    }
    let Some(proof) = proof.filter(|proof| {
        proof.has_receiver()
            && proof.dispatch_extensibility() == Some(DispatchExtensibility::Closed)
    }) else {
        return false;
    };
    let Some((owner, member)) =
        split_canonical_qualified_callee(proof.canonical_callee(), Language::Java)
    else {
        return false;
    };
    matches!(boundaries, [boundary] if matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
        && matches!(boundary.proof, ProofStatus::Proven)
        && boundary.unmaterialized_external_target.as_ref().is_some_and(|target|
            target.language() == language && target.owner_fqn() == owner && target.member() == member
            && target.has_receiver() && target.arity() == proof.parameter_count()))
}

/// Whether structured language resolution proved one receiverless external
/// target whose call cannot participate in dynamic dispatch.
///
/// The boundary stays partial with respect to the unavailable body. This
/// answers only the target-set question; exact declaration and formal proof
/// remain the semantic-model binder's responsibility.
#[doc(hidden)]
pub fn resolver_proven_external_static_boundary(
    status: Option<DefinitionLookupStatus>,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
) -> bool {
    matches!(
        status,
        Some(
            DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::UnresolvableImportBoundary
        )
    ) && candidates.is_empty()
        && matches!(
            boundaries,
            [boundary]
                if matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
                    && matches!(boundary.proof, ProofStatus::Proven)
                    && boundary
                        .unmaterialized_external_target
                        .as_ref()
                        .is_some_and(UnmaterializedExternalTarget::resolver_proves_static_call)
        )
}

/// The exact bound-receiver shape whose external method has a
/// closed target set. The resolver publishes this proof only for one complete
/// nominal receiver and one unique active-model method declaration.
pub(crate) fn resolver_proven_closed_bound_receiver_boundary<'a>(
    language: SemanticLanguage,
    status: Option<DefinitionLookupStatus>,
    proof: Option<&ExactExternalCallProof>,
    candidates: &[DispatchCandidate],
    boundaries: &'a [DispatchBoundary],
) -> Option<&'a UnmaterializedExternalTarget> {
    if !language_support_for_hook(
        language.language(),
        "closed_receiver_summary_closes_external_body",
    )?
    .closed_receiver_summary_closes_external_body()
        || status != Some(DefinitionLookupStatus::UnresolvableImportBoundary)
        || !candidates.is_empty()
    {
        return None;
    }
    let proof = proof.filter(|proof| {
        proof.call_application() == CallApplicationKind::BoundReceiver
            && proof.dispatch_extensibility() == Some(DispatchExtensibility::Closed)
    })?;
    let (expected_owner, expected_member) = split_canonical_qualified_callee(
        proof.canonical_callee(),
        match language {
            SemanticLanguage::Standard(language) => language,
            _ => return None,
        },
    )?;
    let [boundary] = boundaries else {
        return None;
    };
    if !matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
        || !matches!(boundary.proof, ProofStatus::Proven)
    {
        return None;
    }
    boundary.unmaterialized_external_target().filter(|target| {
        target.language() == language
            && target.owner_fqn() == expected_owner
            && target.member() == expected_member
            && target.has_receiver()
            && target.arity() == proof.parameter_count()
    })
}

/// Closed concrete method sets have no override set: one unambiguous complete
/// summary for the exact proven receiver method may replace the absent body.
pub(crate) fn active_unique_complete_receiver_summary(
    oracle: &WorkspaceSemanticOracle<'_>,
    target: &UnmaterializedExternalTarget,
) -> bool {
    debug_assert!(
        language_support_for_hook(
            target.language().language(),
            "closed_receiver_summary_closes_external_body"
        )
        .is_some_and(|support| support.closed_receiver_summary_closes_external_body()),
        "closed-receiver summary requires language admission: {target:?}",
    );
    if !target.has_receiver() {
        return false;
    }
    let Some(active) = oracle.active_semantic_models() else {
        return false;
    };
    let matched = active.procedure_summaries_for_external_target(target);
    matches!(matched.disposition, SemanticModelMatchDisposition::Unique)
        && matches!(
            matched.records.as_slice(),
            [selected] if selected.record.completeness == Completeness::Complete
        )
}

/// Whether a receiverless Kotlin call the resolver proved lands on a declared
/// external type discharges the blanket per-call dynamic-dispatch gap (#3453).
///
/// Kotlin writes a construction as an ordinary call -- `URL(address)` -- and
/// the lowering cannot tell that spelling from a workspace call, because the
/// type is declared outside the file. It therefore publishes the same blanket
/// "a Kotlin call may select an override" gap it publishes for every call
/// whose callee the file does not index. For the external shape the resolver
/// actually proved, the gap's premise does not hold: the callee bound through
/// Kotlin's import ladder to a dependency type the shared JVM surface
/// declares, so the target is a declaration no workspace code can subclass,
/// and a receiverless call names no receiver whose override set could select
/// anything else. The site keeps its single proven external boundary as the
/// residual -- the returned answer still states the body is outside the
/// workspace -- and the covered target set is complete.
///
/// Every part of the shape is resolver evidence: the boundary status, the
/// empty candidate set, the one proven boundary that named no unmaterialized
/// target, and the receiverless call. A workspace-resolved callee never
/// reaches this predicate (`Resolved`, not the boundary status), a Kotlin
/// member call keeps its receiver, and any second or unproven boundary
/// refuses the discharge, so an unproven hierarchy still opens the run.
pub(crate) fn kotlin_external_declared_callee_discharges_gap(
    language: SemanticLanguage,
    status: Option<DefinitionLookupStatus>,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    receiverless: bool,
    gap: &SemanticGap,
) -> bool {
    language == SemanticLanguage::Standard(Language::Kotlin)
        && gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && receiverless
        && status == Some(DefinitionLookupStatus::UnresolvableImportBoundary)
        && candidates.is_empty()
        && matches!(
            boundaries,
            [boundary]
                if matches!(boundary.kind, DispatchBoundaryKind::External(None))
                    && matches!(boundary.proof, ProofStatus::Proven)
                    && boundary.unmaterialized_external_target.is_none()
        )
}

/// Whether a statically proven target set discharges an avoidable per-call
/// dynamic-dispatch gap (#1952).
///
/// Several adapters publish a blanket `Unknown` dynamic-dispatch gap on every
/// call site -- "complete target coverage requires lexical and value-flow
/// refinement" -- including calls whose target is statically known. The gap is
/// answered, and must not open the run, in exactly two proven situations:
/// the adapter itself proved `declared_targets` and dispatch retained that
/// target with proven, complete evidence; or the workspace resolver performed
/// the demanded whole-program refinement and proved a clean result (lookup
/// resolved, every retained candidate proven and complete, no boundary, no
/// truncation). The second situation is decided per receiver route: only the
/// routes whose receiver identity the source itself fixes -- a receiverless
/// call, a Go concrete method set -- accept a clean result, because only there
/// is the resolver's candidate list the whole selectable set. A Ruby member
/// call needs more than its written receiver (#3494): the resolver proves the
/// receiver exact and its method table closed, and the call discharges through
/// [`exact_nonvirtual_member_dispatch_discharges_gap`] instead. `Unsupported`,
/// `Ambiguous`, and `ExceededBudget` gaps keep standing: they assert something
/// a proven target set does not answer.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn proven_static_target_discharges_gap(
    caller: &ProcedureHandle,
    declared_targets: &CallableTargetResolution,
    receiverless: bool,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    lookup_resolved: bool,
    materialization_quality: DispatchQuality,
    gap: &SemanticGap,
) -> bool {
    if gap.capability != SemanticCapability::DynamicDispatch
        || !matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        || candidates.is_empty()
    {
        return false;
    }
    let proven_complete = |candidate: &DispatchCandidate| {
        matches!(candidate.proof, ProofStatus::Proven)
            && matches!(candidate.completeness, EvidenceCompleteness::Complete)
    };
    if let CallableTargetResolution::Proven(target) = declared_targets
        && candidates.iter().all(|candidate| {
            proven_complete(candidate)
                && candidate_matches_declared_target(caller, candidate, target)
        })
    {
        return true;
    }
    // The resolver-proven arm normally accepts only receiverless calls whose
    // retained candidates are free functions: a plain function call's target
    // set is exactly what the whole-program resolver proved. Go is the one
    // receiver-call exception. Its named concrete methods are selected from a
    // compile-time method set and cannot be overridden; interface calls remain
    // open because their body-less declaration or implementor search retains a
    // boundary. Thus a resolved, boundary-free Go method candidate is the same
    // exhaustive proof as a resolved free function, including promoted methods
    // whose structured method-set lookup selected one declaration.
    let go_concrete_method = matches!(
        caller.artifact().key().language(),
        LanguageDialect::Standard(crate::analyzer::Language::Go)
    ) && candidates
        .iter()
        .all(|candidate| candidate.target().semantics().kind() == ProcedureKind::Method);
    // Selecting a function through a type does not dispatch on the explicit
    // receiver actual's dynamic class. The resolver already chose the body.
    let type_selected_method = matches!(gap.subject, SemanticGapSubject::CallSite(id)
        if matches!(caller.semantics().proven_caller_receiver_binding(id),
            Some(CallerReceiverBinding::TypeQualified(_))));
    (receiverless || go_concrete_method)
        && lookup_resolved
        && boundaries.is_empty()
        && materialization_quality == DispatchQuality::Complete
        && candidates.iter().all(|candidate| {
            proven_complete(candidate)
                && (go_concrete_method
                    || type_selected_method
                    || candidate_has_free_target(candidate))
        })
}

/// Whether an exact nonvirtual member call discharges its own
/// dynamic-dispatch gap (#3507).
///
/// Discharge a member-call gap only after the language proves nonvirtual
/// selection and every retained source body is proven and complete. C++ gets
/// that proof from include-visible declaration rows; Java also has call-local
/// superclass invocation evidence. Both use the same materialization checks.
///
/// Everything else keeps the gap standing. For C++, `open` is what a `virtual` member,
/// a member of a class that writes a base clause, a template, and a recovered
/// region publish, and a declaration that keeps no answer -- unresolved, or
/// declared in a class body this workspace cannot see -- refuses the proof
/// too. A candidate set that names a free function refuses it as well, so the
/// receiverless proof stays the only route out of the gap for those calls.
pub(crate) fn exact_nonvirtual_member_dispatch_discharges_gap(
    lookup_resolved: bool,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    materialization_quality: DispatchQuality,
    selection_dispatch_closed: bool,
    gap: &SemanticGap,
) -> bool {
    selection_dispatch_closed
        && gap.capability == SemanticCapability::DynamicDispatch
        && matches!(
            gap.kind,
            SemanticGapKind::Unknown | SemanticGapKind::Unproven
        )
        && lookup_resolved
        && boundaries.is_empty()
        && !candidates.is_empty()
        && materialization_quality == DispatchQuality::Complete
        && candidates.iter().all(|candidate| {
            matches!(candidate.proof, ProofStatus::Proven)
                && matches!(candidate.completeness, EvidenceCompleteness::Complete)
                && candidate_is_type_owned_member(candidate)
        })
}

#[doc(hidden)]
pub fn finish_dispatch_interruption(
    result: DispatchResult,
    cancelled: bool,
    exceeded: Option<SemanticBudgetExceeded>,
    work: SemanticWork,
) -> Result<DispatchResult, Box<SemanticOutcome<DispatchResult>>> {
    if cancelled {
        return Err(Box::new(SemanticOutcome::Cancelled {
            partial: Some(result),
            work,
        }));
    }
    if let Some(exceeded) = exceeded {
        return Err(Box::new(SemanticOutcome::ExceededBudget {
            partial: Some(result),
            exceeded,
            work,
        }));
    }
    Ok(result)
}

/// Keep the final projected answer within the finite provenance arena. The
/// result-level `Truncated` coverage records any omitted arms, so no synthetic
/// uncharged boundary is needed merely to report the cap.
#[doc(hidden)]
pub fn bound_dispatch_projection(
    candidates: &mut Vec<DispatchCandidate>,
    boundaries: &mut Vec<DispatchBoundary>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> bool {
    let original_candidates = candidates.len();
    let original_boundaries = boundaries.len();
    let retained_candidates = candidates
        .len()
        .min(limits.dispatch_targets())
        .min(limits.provenance_records())
        .min(limits.evidence_handles());
    candidates.truncate(retained_candidates);

    let mut remaining_records = limits
        .provenance_records()
        .saturating_sub(retained_candidates);
    let mut remaining_evidence = limits
        .evidence_handles()
        .saturating_sub(retained_candidates);
    let mut retained_boundaries = 0;
    for boundary in boundaries.iter() {
        let evidence =
            dispatch_boundary_evidence_count(boundary, call_dispatch_gap, procedure_call_gap);
        if remaining_records == 0 || evidence > remaining_evidence {
            break;
        }
        remaining_records -= 1;
        remaining_evidence -= evidence;
        retained_boundaries += 1;
    }
    boundaries.truncate(retained_boundaries);

    candidates.len() != original_candidates || boundaries.len() != original_boundaries
}

pub(crate) fn dispatch_boundary_evidence_count(
    boundary: &DispatchBoundary,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> usize {
    let expected_exceeded = match &boundary.kind {
        DispatchBoundaryKind::Unresolved => Some(false),
        DispatchBoundaryKind::Truncated => Some(true),
        DispatchBoundaryKind::External(_)
        | DispatchBoundaryKind::Unmaterialized(_)
        | DispatchBoundaryKind::Deferred { .. } => None,
    };
    let mut evidence = Vec::with_capacity(2);
    for gap in [call_dispatch_gap, procedure_call_gap]
        .into_iter()
        .flatten()
    {
        if expected_exceeded
            .is_some_and(|exceeded| (gap.kind == SemanticGapKind::ExceededBudget) == exceeded)
            && !evidence.contains(&gap.evidence)
        {
            evidence.push(gap.evidence);
        }
    }
    evidence.len().max(1)
}

#[doc(hidden)]
pub fn attach_dispatch_provenance(
    call: &CallSiteHandle,
    candidates: &mut [DispatchCandidate],
    boundaries: &mut [DispatchBoundary],
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
    limits: OracleLimits,
) -> Result<(), SemanticProviderError> {
    let call_row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
    let call_evidence = call
        .procedure()
        .evidence_handle(call_row.evidence)
        .ok_or_else(|| SemanticProviderError::internal("semantic call site has no evidence row"))?;
    let target_evidence = call
        .procedure()
        .evidence_handle(call_row.target_evidence)
        .ok_or_else(|| {
            SemanticProviderError::internal("semantic call site has no target evidence row")
        })?;
    let mut gap_evidence = Vec::new();
    for gap in [call_dispatch_gap, procedure_call_gap]
        .into_iter()
        .flatten()
    {
        let evidence = call
            .procedure()
            .evidence_handle(gap.evidence)
            .ok_or_else(|| {
                SemanticProviderError::internal("semantic dispatch gap has no evidence row")
            })?;
        if !gap_evidence
            .iter()
            .any(|(kind, retained): &(SemanticGapKind, EvidenceHandle)| {
                *kind == gap.kind && retained == &evidence
            })
        {
            gap_evidence.push((gap.kind, evidence));
        }
    }
    let mut records = Vec::with_capacity(candidates.len().saturating_add(boundaries.len()));
    records.extend(
        candidates
            .iter()
            .map(|candidate| {
                OracleRelationRecord::dispatch_candidate(
                    candidate.target().clone(),
                    [target_evidence.clone()],
                    limits,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "could not create bounded dispatch provenance: {error}"
                ))
            })?,
    );
    records.extend(
        boundaries
            .iter()
            .map(|boundary| {
                let evidence = if boundary.target_locator().is_some()
                    || boundary.external_callee_identity().is_some()
                {
                    vec![target_evidence.clone()]
                } else {
                    let expected_gap_kind = match &boundary.kind {
                        DispatchBoundaryKind::Unresolved => Some(false),
                        DispatchBoundaryKind::Truncated => Some(true),
                        DispatchBoundaryKind::External(None) => None,
                        DispatchBoundaryKind::External(Some(_))
                        | DispatchBoundaryKind::Unmaterialized(_)
                        | DispatchBoundaryKind::Deferred { .. } => {
                            unreachable!("named dispatch boundaries handled above")
                        }
                    };
                    let mut evidence = Vec::new();
                    for (_, retained) in gap_evidence.iter().filter(|(kind, _)| {
                        expected_gap_kind.is_some_and(|exceeded| {
                            (*kind == SemanticGapKind::ExceededBudget) == exceeded
                        })
                    }) {
                        if !evidence.contains(retained) {
                            evidence.push(retained.clone());
                        }
                    }
                    if evidence.is_empty() {
                        evidence.push(call_evidence.clone());
                    }
                    evidence
                };
                OracleRelationRecord::dispatch_boundary(boundary.kind.clone(), evidence, limits)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "could not create bounded dispatch provenance: {error}"
                ))
            })?,
    );
    let arena =
        OracleRelationArena::new(OracleRelationOwner::Dispatch(call.clone()), records, limits)
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "could not create bounded dispatch provenance: {error}"
                ))
            })?;
    for (index, candidate) in candidates.iter_mut().enumerate() {
        let id = u32::try_from(index)
            .map(OracleRelationId::new)
            .map_err(|_| {
                SemanticProviderError::internal(
                    "dispatch provenance exceeds dense relation ID space",
                )
            })?;
        let relation = arena
            .handle(id)
            .expect("dispatch candidate record was inserted into the relation arena");
        candidate.provenance = vec![relation].into_boxed_slice();
    }
    let offset = candidates.len();
    for (index, boundary) in boundaries.iter_mut().enumerate() {
        let id = u32::try_from(offset.saturating_add(index))
            .map(OracleRelationId::new)
            .map_err(|_| {
                SemanticProviderError::internal(
                    "dispatch provenance exceeds dense relation ID space",
                )
            })?;
        let relation = arena
            .handle(id)
            .expect("dispatch boundary record was inserted into the relation arena");
        boundary.provenance = vec![relation].into_boxed_slice();
    }
    Ok(())
}

/// Materialize the single target already proven by the reverse call relation.
/// The caller may use this only after matching that relation to exactly one
/// semantic call-site handle; the normal dispatch query is still required for
/// ambiguous or incomplete incoming edges.
pub(crate) fn candidate_for_proven_incoming_relation(
    call: &CallSiteHandle,
    target: &ProcedureHandle,
    limits: OracleLimits,
) -> Result<DispatchCandidate, SemanticProviderError> {
    let mut candidates = vec![
        DispatchCandidate::new(
            target.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
            std::iter::empty(),
            limits,
        )
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "proven incoming dispatch candidate is invalid: {error}"
            ))
        })?,
    ];
    attach_dispatch_provenance(call, &mut candidates, &mut [], None, None, limits)?;
    let result = DispatchResult::new(
        call,
        candidates,
        Vec::new(),
        CandidateCoverage::Exhaustive,
        limits,
    )
    .map_err(|error| {
        SemanticProviderError::internal(format!(
            "proven incoming dispatch result is invalid: {error}"
        ))
    })?;
    Ok(result
        .candidates()
        .first()
        .expect("one incoming dispatch candidate was constructed")
        .clone())
}

#[doc(hidden)]
pub struct CancelledLookupArtifacts<'a> {
    #[doc(hidden)]
    pub resolved_targets: &'a [CallDispatchTarget],
    #[doc(hidden)]
    pub low_level_boundaries: &'a [CallDispatchBoundaryKind],
    #[doc(hidden)]
    pub exact_external_call: Option<&'a ExactExternalCallProof>,
    #[doc(hidden)]
    pub call_dispatch_gap: Option<&'a SemanticGap>,
    #[doc(hidden)]
    pub procedure_call_gap: Option<&'a SemanticGap>,
    #[doc(hidden)]
    pub observed_work: SemanticWork,
}

#[doc(hidden)]
pub fn cancelled_lookup_outcome(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
    limits: OracleLimits,
    artifacts: CancelledLookupArtifacts<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
    let CancelledLookupArtifacts {
        resolved_targets,
        low_level_boundaries,
        exact_external_call,
        call_dispatch_gap,
        procedure_call_gap,
        observed_work,
    } = artifacts;
    if observed_work == SemanticWork::default()
        && resolved_targets.is_empty()
        && low_level_boundaries.is_empty()
    {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    let cancelled_language = call.procedure().artifact().key().language();
    let cancelled_semantic_call = call.procedure().semantics().call_site(call.id());
    let mut boundaries = low_level_boundaries
        .iter()
        .map(|boundary| {
            low_level_boundary(
                boundary,
                cancelled_language,
                cancelled_semantic_call,
                exact_external_call,
                &[],
            )
        })
        .collect::<Vec<_>>();
    let resolved_target_groups =
        dispatch_target_groups(workspace.analyzer(), resolved_targets.to_vec());
    let resolved_target_limit = limits
        .dispatch_targets()
        .min(limits.provenance_records())
        .min(limits.evidence_handles());
    let resolved_targets_truncated = resolved_target_groups.len() > resolved_target_limit;
    boundaries.extend(
        resolved_target_groups
            .iter()
            .take(resolved_target_limit)
            .map(|target| cancelled_target_boundary(workspace.analyzer(), target))
            .collect::<Result<Vec<_>, _>>()?,
    );
    boundaries.sort_by(compare_dispatch_boundaries);
    boundaries.dedup();
    let mut candidates = Vec::new();
    let truncated = bound_dispatch_projection(
        &mut candidates,
        &mut boundaries,
        limits,
        call_dispatch_gap,
        procedure_call_gap,
    );
    attach_dispatch_provenance(
        call,
        &mut candidates,
        &mut boundaries,
        call_dispatch_gap,
        procedure_call_gap,
        limits,
    )?;
    let retained_truncation = resolved_targets_truncated
        || truncated
        || boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated);
    let result = DispatchResult::new(
        call,
        candidates,
        boundaries,
        // Cancellation alone leaves coverage open. An independent finite cap
        // still records known omission as truncated while the outer outcome
        // preserves the operation-level cancellation state.
        if retained_truncation {
            CandidateCoverage::Truncated
        } else {
            CandidateCoverage::Open
        },
        limits,
    )
    .map_err(|error| {
        SemanticProviderError::internal(format!(
            "cancelled dispatch produced invalid relation provenance: {error}"
        ))
    })?;
    let retained_work = dispatch_result_work(&result);
    let total_work = observed_work.conservative_add(retained_work);
    let mut staged_budget = request.budget.clone();
    staged_budget.charge_work(observed_work);
    if staged_budget.admit(retained_work).is_err() {
        request.budget.retain_performed_work(&staged_budget);
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: total_work,
        });
    }
    *request.budget = staged_budget;
    Ok(SemanticOutcome::Cancelled {
        partial: Some(result),
        work: total_work,
    })
}

pub(crate) fn cancelled_target_boundary(
    analyzer: &dyn IAnalyzer,
    target: &DispatchTargetGroup,
) -> Result<DispatchBoundary, SemanticProviderError> {
    unmaterialized_target_boundary(analyzer, target, CANCELLED_TARGET_REASON)
}

pub(crate) fn unmaterialized_target_boundary(
    analyzer: &dyn IAnalyzer,
    target: &DispatchTargetGroup,
    reason: &'static str,
) -> Result<DispatchBoundary, SemanticProviderError> {
    Ok(DispatchBoundary {
        kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
            analyzer,
            &target.representative,
        )?),
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: target.proof.clone(),
        completeness: EvidenceCompleteness::Partial(reason.into()),
        provenance: Box::new([]),
    })
}

#[doc(hidden)]
pub fn append_cancelled_target_boundaries(
    analyzer: &dyn IAnalyzer,
    candidates: &[DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
    groups: impl IntoIterator<Item = DispatchTargetGroup>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> Result<bool, SemanticProviderError> {
    append_unmaterialized_target_boundaries(
        analyzer,
        candidates,
        boundaries,
        groups,
        limits,
        call_dispatch_gap,
        procedure_call_gap,
        CANCELLED_TARGET_REASON,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_execution_budget_target_boundaries(
    analyzer: &dyn IAnalyzer,
    candidates: &[DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
    groups: impl IntoIterator<Item = DispatchTargetGroup>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
) -> Result<bool, SemanticProviderError> {
    append_unmaterialized_target_boundaries(
        analyzer,
        candidates,
        boundaries,
        groups,
        limits,
        call_dispatch_gap,
        procedure_call_gap,
        "resolved target was not materialized because the request execution budget was exhausted",
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_unmaterialized_target_boundaries(
    analyzer: &dyn IAnalyzer,
    candidates: &[DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
    groups: impl IntoIterator<Item = DispatchTargetGroup>,
    limits: OracleLimits,
    call_dispatch_gap: Option<&SemanticGap>,
    procedure_call_gap: Option<&SemanticGap>,
    reason: &'static str,
) -> Result<bool, SemanticProviderError> {
    let retained_target_arms = candidates.len().saturating_add(
        boundaries
            .iter()
            .filter(|boundary| boundary.target_locator().is_some())
            .count(),
    );
    let retained_records = candidates.len().saturating_add(boundaries.len());
    let retained_evidence = candidates.len().saturating_add(
        boundaries
            .iter()
            .map(|boundary| {
                dispatch_boundary_evidence_count(boundary, call_dispatch_gap, procedure_call_gap)
            })
            .fold(0usize, usize::saturating_add),
    );
    let mut remaining_targets = limits
        .dispatch_targets()
        .saturating_sub(retained_target_arms);
    let mut remaining_records = limits.provenance_records().saturating_sub(retained_records);
    let mut remaining_evidence = limits.evidence_handles().saturating_sub(retained_evidence);
    let mut groups = groups.into_iter();

    loop {
        if remaining_targets == 0 || remaining_records == 0 || remaining_evidence == 0 {
            // Consume at most one omitted group to distinguish an exactly-full
            // projection from a truncated one without allocating the tail.
            return Ok(groups.next().is_some());
        }
        let Some(group) = groups.next() else {
            return Ok(false);
        };
        let boundary = unmaterialized_target_boundary(analyzer, &group, reason)?;
        let evidence =
            dispatch_boundary_evidence_count(&boundary, call_dispatch_gap, procedure_call_gap);
        if evidence > remaining_evidence {
            return Ok(true);
        }
        boundaries.push(boundary);
        remaining_targets -= 1;
        remaining_records -= 1;
        remaining_evidence -= evidence;
    }
}

#[doc(hidden)]
pub fn dispatch_result_work(result: &DispatchResult) -> SemanticWork {
    let relation_subject_work = result
        .candidates()
        .iter()
        .flat_map(|candidate| candidate.provenance.iter())
        .chain(
            result
                .boundaries()
                .iter()
                .flat_map(|boundary| boundary.provenance.iter()),
        )
        .filter_map(|relation| match relation.record().subject() {
            Some(OracleRelationSubject::DispatchBoundary(kind)) => {
                Some(dispatch_boundary_kind_locator_work(kind))
            }
            Some(OracleRelationSubject::DispatchCandidate(_))
            | Some(OracleRelationSubject::MemoryOperation(_))
            | None => None,
        })
        .fold(SemanticWork::default(), SemanticWork::conservative_add);
    let owned_text_bytes = result
        .candidates()
        .iter()
        .map(|candidate| {
            candidate
                .proof
                .retained_heap_bytes()
                .saturating_add(completeness_reason_bytes(&candidate.completeness))
        })
        .chain(result.boundaries().iter().map(|boundary| {
            boundary
                .proof
                .retained_heap_bytes()
                .saturating_add(completeness_reason_bytes(&boundary.completeness))
                .saturating_add(dispatch_boundary_locator_work(boundary).owned_text_bytes)
        }))
        .fold(0usize, usize::saturating_add)
        .saturating_add(relation_subject_work.owned_text_bytes);
    let provenance_entries = result
        .candidates()
        .iter()
        .flat_map(|candidate| candidate.provenance.iter())
        .chain(
            result
                .boundaries()
                .iter()
                .flat_map(|boundary| boundary.provenance.iter()),
        )
        .map(|relation| {
            // One payload handle, one arena record, and the record's retained
            // evidence-handle array are all distinct nested entries.
            2usize.saturating_add(relation.record().evidence().len())
        })
        .fold(0usize, usize::saturating_add);
    SemanticWork {
        nested_entries: result
            .candidates()
            .len()
            .saturating_add(result.boundaries().len())
            .saturating_add(
                result
                    .boundaries()
                    .iter()
                    .map(dispatch_boundary_locator_work)
                    .map(|work| work.nested_entries)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(provenance_entries)
            .saturating_add(relation_subject_work.nested_entries),
        owned_text_bytes,
        ..SemanticWork::default()
    }
}

pub(crate) fn dispatch_boundary_locator_work(boundary: &DispatchBoundary) -> SemanticWork {
    let mut work = dispatch_boundary_kind_locator_work(&boundary.kind);
    if let Some(target) = boundary.exact_external_target() {
        let procedure = semantic_locator_work(target.procedure());
        let formal = target.formal_contract();
        let formal_text_bytes =
            formal
                .parameters()
                .iter()
                .fold(formal.label().len(), |bytes, parameter| {
                    bytes
                        .saturating_add(parameter.label().len())
                        .saturating_add(parameter.declared_type().map_or(0, str::len))
                });
        work.nested_entries = work
            .nested_entries
            .saturating_add(1)
            .saturating_add(procedure.nested_entries)
            .saturating_add(formal.parameters().len());
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(target.symbol().len())
            .saturating_add(target.artifact().path().as_str().len())
            .saturating_add(target.artifact().adapter().name().len())
            .saturating_add(procedure.owned_text_bytes)
            .saturating_add(formal_text_bytes);
    } else if let Some(target) = boundary.unmaterialized_external_target() {
        let locator = semantic_locator_work(target.locator());
        work.nested_entries = work
            .nested_entries
            .saturating_add(1)
            .saturating_add(locator.nested_entries);
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(locator.owned_text_bytes)
            .saturating_add(target.owner_fqn().len())
            .saturating_add(target.member().len());
    }
    if let Some(identity) = boundary.external_callee_identity() {
        work.nested_entries = work.nested_entries.saturating_add(1);
        work.owned_text_bytes = work
            .owned_text_bytes
            .saturating_add(identity.owner_fqn().len())
            .saturating_add(identity.member().len());
    }
    work
}

#[doc(hidden)]
pub fn exact_source_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    max_source_bytes: usize,
) -> Result<Option<(ProjectFile, Arc<str>)>, SemanticProviderError> {
    let key = procedure.artifact().key();
    let project = workspace.analyzer().project();
    let root = project.root();
    if key.mount() != WorkspaceMountId::from_root(root) {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact belongs to a different workspace mount",
        ));
    }
    let file = ProjectFile::new(root.to_path_buf(), key.path().as_path());
    if let Some(source) = procedure.artifact().query_source() {
        return Ok((source.len() <= max_source_bytes).then(|| (file, source.clone())));
    }
    if workspace
        .program_semantics_provider_for_file(&file)
        .is_none()
    {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact has no semantic provider in the current analyzer generation",
        ));
    }
    let Some(snapshot) =
        workspace.current_program_semantics_artifact_source(&file, max_source_bytes)?
    else {
        return Ok(None);
    };
    if snapshot.key() != key {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact no longer matches the current semantic analyzer generation",
        ));
    }
    let (_, source) = snapshot.into_parts();
    Ok(Some((file, source)))
}

/// Whether a `FieldMemory` gap is discharged because the field it occurs on
/// is provably a `static final` field on an *external* type (#2538).
///
/// A `static final` field on an external type is, by Java Language
/// Specification semantics, either a compile-time constant (a primitive or
/// `String` field initialized with a constant expression) or an immutable
/// reference (any other type); either way, reading it carries no
/// attacker-influenced value flow. Java's own field-identity resolution
/// (`memory_member_locator`,
/// `crates/bifrost-analysis/src/analyzer/java/semantic/values.rs`) has no
/// path at all for a type-qualified static access -- it only resolves
/// `instance.field` through a local variable of a same-file-declared type --
/// so lowering mints an ordinary, unresolved `FieldMemory` gap for every
/// `Type.FIELD`-shaped read, external or not, and lowering itself has no
/// access to the external declaration surface to tell the two apart: Java
/// CFG lowering is a per-file, syntax-only pass with no analyzer or
/// dependency access (see the #2538 ExecPlan's Decision Log for why the
/// proof is not attempted there instead).
///
/// This predicate runs at query time, where full analyzer access exists, and
/// mirrors exactly how [`exact_source_for_procedure`] and
/// `CallRelationService::dispatch_at_bounded` already resolve an unmaterialized
/// external *call* target above: recover the field access's own literal
/// written spelling from the gap's own recorded source span (fetch the
/// procedure's exact source text via [`exact_source_for_procedure`], slice it
/// at the span), and resolve that spelling through the language's
/// `LanguageSupport::external_compile_time_constant_member` capability (Java
/// answers via the same resolver `#1900` built for "go to definition" and
/// diagnostics, unmodified; every other language currently answers `false`).
///
/// Fails closed in every case the proof is unavailable: a non-`FieldMemory`
/// gap, a gap not on a `MemoryLocation`, a non-`Field` memory location, a
/// language whose support offers no external-constant proof, a dialect
/// projection, a source fetch that comes up empty or over budget, a
/// spelling the resolver cannot place on any external declaration, or a
/// resolved member that is not proven both `is_static()` and
/// `is_compile_time_constant()`. None of those return an error; they return
/// `Ok(false)`, leaving the gap exactly as open as it was, because a missing
/// proof for one gap must never abort the rest of the sweep it is composed
/// into.
/// Language-owned exact field-read proofs also participate in this predicate.
pub(crate) fn external_constant_field_read_discharges_gap(
    gap: &SemanticGap,
    procedure: &ProcedureHandle,
    workspace: &WorkspaceAnalyzer,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    if language_support_for_hook(
        procedure.artifact().key().language().language(),
        "external_field_read_discharges_gap",
    )
    .is_some_and(|support| support.external_field_read_discharges_gap(workspace, procedure, gap))
    {
        return Ok(true);
    }
    if gap.capability != SemanticCapability::FieldMemory {
        return Ok(false);
    }
    let SemanticGapSubject::MemoryLocation(location_id) = gap.subject else {
        return Ok(false);
    };
    let LanguageDialect::Standard(language) = procedure.artifact().key().language() else {
        return Ok(false);
    };
    let Some(support) =
        language_support_for_hook(language, "external_compile_time_constant_member")
    else {
        return Ok(false);
    };
    let Some(location) = procedure.semantics().memory_location(location_id) else {
        return Ok(false);
    };
    if !matches!(location.kind, MemoryLocationKind::Field { .. }) {
        return Ok(false);
    }

    let max_source_bytes = request.budget.limits().source_bytes;
    let Some((file, exact_source)) =
        exact_source_for_procedure(workspace, procedure, max_source_bytes)?
    else {
        // A budget-exhausted or otherwise unavailable source fetch does not
        // abort the sweep this predicate is composed into; it only leaves
        // this one gap undischarged.
        return Ok(false);
    };
    let Some(mapping) = procedure.semantics().source_mapping(gap.source) else {
        return Ok(false);
    };
    let span = mapping.locator.anchor().span();
    let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
    if start > end || end > exact_source.len() {
        return Ok(false);
    }
    let Some(spelling) = exact_source.get(start..end) else {
        return Ok(false);
    };

    Ok(support.external_compile_time_constant_member(workspace.analyzer(), &file, spelling))
}

/// Whether `gap` is an implicit-drop omission whose obligation the procedure's
/// language discharges (#3757): every parameter and `let` binding the omitted
/// drop can destroy has drop glue that provably runs no user code.
///
/// The answer covers the whole procedure, so `inert` memoizes it across the
/// gaps one sweep visits. An unavailable source leaves the gap standing.
pub(crate) fn inert_drop_glue_discharges_gap(
    gap: &SemanticGap,
    procedure: &ProcedureHandle,
    workspace: &WorkspaceAnalyzer,
    request: &mut SemanticRequest<'_>,
    inert: &mut Option<bool>,
) -> Result<bool, SemanticProviderError> {
    if gap.discharge != crate::analyzer::semantic::SemanticGapDischarge::InertDropGlue {
        return Ok(false);
    }
    if let Some(answer) = *inert {
        return Ok(answer);
    }
    let LanguageDialect::Standard(language) = procedure.artifact().key().language() else {
        return Ok(false);
    };
    let Some(support) = language_support_for_hook(language, "procedure_drops_run_no_user_code")
    else {
        return Ok(false);
    };
    let max_source_bytes = request.budget.limits().source_bytes;
    let Some((file, exact_source)) =
        exact_source_for_procedure(workspace, procedure, max_source_bytes)?
    else {
        return Ok(false);
    };
    let span = procedure.semantics().locator().anchor().span();
    let answer = support.procedure_drops_run_no_user_code(
        workspace.analyzer(),
        &file,
        &exact_source,
        span.start_byte() as usize..span.end_byte() as usize,
    );
    *inert = Some(answer);
    Ok(answer)
}

/// Whether `gap` is a residual-conversion obligation the procedure's language
/// discharges (#4967): the `?` operator's `From` conversion on the error path
/// provably runs no user code.
///
/// The decision belongs to the language's own support; generic dispatch only
/// checks that the gap carries the obligation and that the procedure has a
/// language whose support can answer it. An unavailable source leaves the gap
/// standing rather than aborting the sweep this predicate is composed into.
pub(crate) fn residual_conversion_discharges_gap(
    gap: &SemanticGap,
    procedure: &ProcedureHandle,
    workspace: &WorkspaceAnalyzer,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    if gap.discharge != crate::analyzer::semantic::SemanticGapDischarge::ResidualConversion {
        return Ok(false);
    }
    let LanguageDialect::Standard(language) = procedure.artifact().key().language() else {
        return Ok(false);
    };
    let Some(support) =
        language_support_for_hook(language, "residual_conversion_runs_no_user_code")
    else {
        return Ok(false);
    };
    let max_source_bytes = request.budget.limits().source_bytes;
    let Some((file, exact_source)) =
        exact_source_for_procedure(workspace, procedure, max_source_bytes)?
    else {
        return Ok(false);
    };
    let Some(mapping) = procedure.semantics().source_mapping(gap.source) else {
        return Ok(false);
    };
    let span = mapping.locator.anchor().span();
    Ok(support.residual_conversion_runs_no_user_code(
        workspace.analyzer(),
        &file,
        &exact_source,
        span.start_byte() as usize..span.end_byte() as usize,
    ))
}

#[doc(hidden)]
pub fn low_level_boundary(
    boundary: &CallDispatchBoundaryKind,
    language: SemanticLanguage,
    semantic_call: Option<&SemanticCallSite>,
    exact_external_call: Option<&ExactExternalCallProof>,
    lookup_diagnostic_kinds: &[Box<str>],
) -> DispatchBoundary {
    match boundary {
        // #1978: when the resolver retained a fully-qualified callee text for an
        // external boundary, synthesize its canonical identity so an activated
        // authored summary can bind it even though it never materializes.
        CallDispatchBoundaryKind::External {
            callee_text,
            normalized_static_owner,
            external_callee_identity,
        } => {
            // PHP's resolver proves global functions through its ordered
            // namespace lookup, but the resulting identity has no source
            // spelling that `synthetic_unmaterialized_external` can split:
            // the global owner is a synthetic namespace. Keep this narrow
            // identity-to-target bridge here rather than reaching into the
            // PHP adapter from the shared oracle. A non-global PHP identity
            // remains an external boundary until a reviewed model can prove
            // it, so namespaced functions and methods do not acquire a
            // name-only target.
            let php_global_target = external_callee_identity
                .as_ref()
                .filter(|identity| {
                    identity.language() == Language::Php && identity.owner_fqn() == "_php_global_"
                })
                .zip(semantic_call)
                .and_then(|(identity, semantic_call)| {
                    synthetic_php_global_external(identity, semantic_call)
                });
            let resolver_owned_callee = match language {
                SemanticLanguage::Standard(Language::Rust) => {
                    exact_external_call.map(ExactExternalCallProof::canonical_callee)
                }
                SemanticLanguage::Standard(Language::Python) => exact_external_call
                    .filter(|proof| {
                        proof.call_application() == CallApplicationKind::PackageFunction
                    })
                    .map(ExactExternalCallProof::canonical_callee),
                _ => None,
            };
            let rust_builtin_target = external_callee_identity
                .as_ref()
                .filter(|identity| rust_builtin_macro_identity_is_intrinsic(identity))
                .zip(semantic_call)
                .and_then(|(identity, semantic_call)| {
                    synthetic_rust_builtin_macro_external(identity, semantic_call)
                });
            let rust_builtin_target_is_complete = rust_builtin_target.is_some();
            match rust_builtin_target.or(php_global_target).or_else(|| {
                resolver_owned_callee
                    .or(callee_text.as_deref())
                    .zip(semantic_call)
                    .and_then(|(text, semantic_call)| {
                        synthetic_unmaterialized_external(
                            text,
                            language,
                            semantic_call,
                            exact_external_call,
                            normalized_static_owner.as_deref(),
                        )
                    })
            }) {
                Some(target) => DispatchBoundary {
                    kind: DispatchBoundaryKind::External(Some(target.locator().clone())),
                    external_callee_identity: external_identity_for_target(
                        external_callee_identity.as_ref(),
                        &target,
                    ),
                    exact_external_target: None,
                    unmaterialized_external_target: Some(target),
                    proof: ProofStatus::Proven,
                    completeness: if rust_builtin_target_is_complete {
                        EvidenceCompleteness::Complete
                    } else {
                        EvidenceCompleteness::Partial(
                            "external callee body is outside the indexed workspace; an activated summary supplies its transfers"
                                .into(),
                        )
                    },
                    provenance: Box::new([]),
                },
                None => DispatchBoundary {
                    kind: DispatchBoundaryKind::External(None),
                    external_callee_identity: external_identity_for_language(
                        external_callee_identity.as_ref(),
                        language,
                    ),
                    exact_external_target: None,
                    unmaterialized_external_target: None,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Partial(
                        "external declaration body is outside the indexed workspace".into(),
                    ),
                    provenance: Box::new([]),
                },
            }
        }
        CallDispatchBoundaryKind::Unresolved(status) => {
            unresolved_dispatch_boundary(*status, lookup_diagnostic_kinds)
        }
        CallDispatchBoundaryKind::UnresolvedReason(reason) => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Unproven(reason.clone()),
            completeness: EvidenceCompleteness::Partial(reason.clone()),
            provenance: Box::new([]),
        },
        CallDispatchBoundaryKind::UnresolvedWithTarget {
            status,
            callee_text,
            normalized_static_owner,
        } => {
            let resolver_owned_callee = match language {
                SemanticLanguage::Standard(Language::Rust) => {
                    exact_external_call.map(ExactExternalCallProof::canonical_callee)
                }
                SemanticLanguage::Standard(Language::Python) => exact_external_call
                    .filter(|proof| {
                        proof.call_application() == CallApplicationKind::PackageFunction
                    })
                    .map(ExactExternalCallProof::canonical_callee),
                _ => None,
            };
            match semantic_call.and_then(|semantic_call| {
                synthetic_unmaterialized_external(
                    resolver_owned_callee.unwrap_or(callee_text),
                    language,
                    semantic_call,
                    exact_external_call,
                    normalized_static_owner.as_deref(),
                )
            }) {
                Some(target) => DispatchBoundary {
                    kind: DispatchBoundaryKind::External(Some(target.locator().clone())),
                    external_callee_identity: None,
                    exact_external_target: None,
                    unmaterialized_external_target: Some(target),
                    proof: ProofStatus::Unproven(
                        format!("exact dispatch status is {}", status.as_str()).into(),
                    ),
                    completeness: EvidenceCompleteness::Partial(
                        "the retained canonical callee does not prove one resolved dispatch target"
                            .into(),
                    ),
                    provenance: Box::new([]),
                },
                None => unresolved_dispatch_boundary(*status, lookup_diagnostic_kinds),
            }
        }
        CallDispatchBoundaryKind::UnprovenTargetIdentity => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Unproven(
                "C/C++ include evidence does not prove one link-unit target identity".into(),
            ),
            completeness: EvidenceCompleteness::Partial(
                "additional or alternative linked bodies may exist".into(),
            ),
            provenance: Box::new([]),
        },
        CallDispatchBoundaryKind::Truncated => truncated_dispatch_boundary(),
    }
}

/// Build a complete modeled target for a Rust built-in macro's already-lowered
/// external effect. The exact identity comes from Rust macro dispatch, and the
/// macro lowerer accounts for the value semantics; the target keeps endpoint
/// models bound to the standard library sink identity.
pub(crate) fn synthetic_rust_builtin_macro_external(
    identity: &crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity,
    semantic_call: &SemanticCallSite,
) -> Option<UnmaterializedExternalTarget> {
    let arity = u32::try_from(semantic_call.arguments.len()).ok()?;
    Some(
        UnmaterializedExternalTarget::new_modeled(
            identity.owner_fqn(),
            identity.member(),
            SemanticLanguage::Standard(Language::Rust),
            arity,
            semantic_call.receiver.is_some(),
        )?
        .with_call_arguments(&semantic_call.arguments),
    )
}

/// Build the resolver-owned target for a PHP global function. PHP's builtin
/// functions are published by the test/authoring declaration pack under the
/// synthetic `_php_global_` owner; the resolver has already proved that owner
/// through PHP's namespace-first/global-fallback lookup. The target therefore
/// uses the source call's actual argument count, while the identity supplies
/// the declaration owner and member without parsing source text.
pub(crate) fn synthetic_php_global_external(
    identity: &crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity,
    semantic_call: &SemanticCallSite,
) -> Option<UnmaterializedExternalTarget> {
    let arity = u32::try_from(semantic_call.arguments.len()).ok()?;
    let anchor = zero_source_anchor();
    let owner_segment = DeclarationSegment::named(
        DeclarationSegmentKind::Type,
        identity.owner_fqn(),
        anchor,
        0,
    )
    .ok()?;
    let member_segment = DeclarationSegment::named(
        DeclarationSegmentKind::Function,
        identity.member(),
        anchor,
        arity,
    )
    .ok()?;
    let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
    let locator = SemanticLocator::new(
        unmaterialized_external_mount(),
        unmaterialized_external_path(),
        SemanticLanguage::Standard(Language::Php),
        declaration,
        SemanticRole::Procedure,
        anchor,
    );
    Some(
        UnmaterializedExternalTarget::new_for_resolver_owned_call(
            identity.owner_fqn(),
            identity.member(),
            arity,
            false,
            None,
            locator,
        )
        .with_call_arguments(&semantic_call.arguments),
    )
}

pub(crate) fn external_identity_for_language(
    identity: Option<&crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>,
    language: SemanticLanguage,
) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
    let identity = identity?;
    let matches_language = identity.language() == language.language();
    debug_assert!(
        matches_language,
        "resolver-owned external identity language must match its call boundary"
    );
    matches_language.then(|| identity.clone())
}

pub(crate) fn external_identity_for_target(
    identity: Option<&crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>,
    target: &UnmaterializedExternalTarget,
) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
    let identity = identity?;
    let matches_target = identity.matches_unmaterialized_external_target(target);
    debug_assert!(
        matches_target,
        "resolver-owned external identity must match its unmaterialized target"
    );
    matches_target.then(|| identity.clone())
}

pub(crate) fn hinted_external_member_targets(
    oracle: &WorkspaceSemanticOracle<'_>,
    declaration: &crate::analyzer::semantic::ExternalMemberDeclaration,
    language: SemanticLanguage,
    semantic_call: &SemanticCallSite,
) -> Option<Vec<(UnmaterializedExternalTarget, bool)>> {
    let overlay = oracle.semantic_model_overlay()?;
    let arity = u32::try_from(semantic_call.arguments.len()).ok()?;
    let mut targets = Vec::new();
    for symbol_id in declaration.symbol_ids() {
        let matched = overlay.symbols_with_id(symbol_id);
        let [symbol] = matched.records.as_slice() else {
            return None;
        };
        if !matches!(
            symbol.kind,
            SemanticModelSymbolKind::Constructor
                | SemanticModelSymbolKind::Method
                | SemanticModelSymbolKind::Function
        ) || symbol.language != language.semantic_pack_label()
        {
            return None;
        }
        let owner_id = symbol.owner_id.as_deref()?;
        let owners = overlay.symbols_with_id(owner_id);
        let [owner] = owners.records.as_slice() else {
            return None;
        };
        let target = modeled_unmaterialized_external(
            &owner.qualified_name,
            &symbol.name,
            language,
            arity,
            symbol.has_receiver(),
        )?
        .with_call_arguments(&semantic_call.arguments);
        let complete = hinted_external_summary_is_complete(oracle, &target);
        targets.push((target, complete));
    }
    targets.sort_unstable();
    targets.dedup_by(|left, right| {
        if left.0 == right.0 {
            left.1 &= right.1;
            true
        } else {
            false
        }
    });
    (!targets.is_empty()).then_some(targets)
}

pub(crate) fn hinted_external_summary_is_complete(
    oracle: &WorkspaceSemanticOracle<'_>,
    target: &UnmaterializedExternalTarget,
) -> bool {
    let Some(active) = oracle.active_semantic_models() else {
        return false;
    };
    let matched = active.procedure_summaries_for_external_target(target);
    matching_summaries_satisfy(&matched, |record| {
        record.completeness == Completeness::Complete
    })
}

pub(crate) fn external_target_has_active_model(
    oracle: &WorkspaceSemanticOracle<'_>,
    target: &UnmaterializedExternalTarget,
) -> bool {
    let Some(active) = oracle.active_semantic_models() else {
        return false;
    };
    active
        .procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
            target.language().semantic_pack_label(),
            target.owner_fqn(),
            target.member(),
            target.has_receiver(),
            target
                .python_formal_parameter_count()
                .unwrap_or_else(|| target.arity()),
        ))
        .disposition
        != SemanticModelMatchDisposition::Empty
}

/// Whether the activated models select one complete procedure summary for the
/// exact member `target`, with the override claim a receiver-bearing target
/// needs before the summary can close its whole target set (#3406).
///
/// The selection rule is the one the policy route's summary binding applies
/// (`select_unmaterialized_flow_summary`): a unique match, or a conflict set
/// whose candidates all make the same flow-observable claims. The completeness
/// and `covers_overrides` checks are the ones `authored_target_closure`
/// applies to the same target, so the dispatch discharge below and the
/// plan-level closure never disagree about which summary was consumed.
pub(crate) fn active_covering_complete_summary(
    oracle: &WorkspaceSemanticOracle<'_>,
    target: &UnmaterializedExternalTarget,
) -> bool {
    let Some(active) = oracle.active_semantic_models() else {
        return false;
    };
    let claims_cover = |record: &CompiledProcedureSummary| {
        record.completeness == Completeness::Complete
            && (!target.has_receiver() || record.covers_overrides)
    };
    let matched = active.procedure_summaries_for_external_target(target);
    if matched.applicability != ProcedureSummaryApplicability::Complete {
        return false;
    }
    matching_summaries_satisfy(&matched, claims_cover)
}

pub(crate) fn matching_summaries_satisfy(
    matched: &ProcedureSummaryMatch,
    accepts: impl Fn(&CompiledProcedureSummary) -> bool,
) -> bool {
    match matched.disposition {
        SemanticModelMatchDisposition::Unique => {
            matches!(matched.records.as_slice(), [selected] if accepts(&selected.record))
        }
        SemanticModelMatchDisposition::Conflict => {
            let Some((first, rest)) = matched.records.split_first() else {
                return false;
            };
            !rest.is_empty()
                && accepts(&first.record)
                && rest.iter().all(|other| {
                    accepts(&other.record)
                        && compiled_flow_claims_agree(&other.record, &first.record)
                })
        }
        SemanticModelMatchDisposition::Empty => false,
    }
}

/// The one boundary shape the JS/TS modeled-member discharge answers: the
/// exact resolver proved a receiver-bound external member (no workspace
/// candidate at all) and named it through one proven external boundary
/// (#3406).
pub(crate) fn js_ts_proven_external_member_boundary<'a>(
    call_language: SemanticLanguage,
    candidates: &[DispatchCandidate],
    boundaries: &'a [DispatchBoundary],
) -> Option<&'a UnmaterializedExternalTarget> {
    if !matches!(
        call_language.language(),
        Language::JavaScript | Language::TypeScript
    ) {
        return None;
    }
    proven_unmaterialized_external_boundary(candidates, boundaries)
        .filter(|target| target.has_receiver())
}

/// The exact C# receiver-bound member shape whose complete, override-covering
/// summary closes the external target family. C# instance methods remain
/// dynamically dispatchable unless the authored summary makes that family
/// claim; the resolver proof supplies the identity and arity used here.
pub(crate) fn csharp_proven_external_member_boundary<'a>(
    call_language: SemanticLanguage,
    proof: Option<&ExactExternalCallProof>,
    candidates: &[DispatchCandidate],
    boundaries: &'a [DispatchBoundary],
) -> Option<&'a UnmaterializedExternalTarget> {
    if call_language != SemanticLanguage::Standard(Language::CSharp) || !candidates.is_empty() {
        return None;
    }
    let proof =
        proof.filter(|proof| proof.call_application() == CallApplicationKind::BoundReceiver)?;
    let (expected_owner, expected_member) =
        split_canonical_qualified_callee(proof.canonical_callee(), Language::CSharp)?;
    let [boundary] = boundaries else {
        return None;
    };
    if !matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
        || !matches!(boundary.proof, ProofStatus::Proven)
    {
        return None;
    }
    boundary.unmaterialized_external_target().filter(|target| {
        target.language() == call_language
            && target.owner_fqn() == expected_owner
            && target.member() == expected_member
            && target.has_receiver()
            && target.arity() == proof.parameter_count()
    })
}

/// Whether no workspace source can replace the member value a require or
/// namespace binding reads from `target`'s module before the call runs
/// (#3406).
///
/// The require-bound receiver resolution proves the receiver *is* the shared
/// module object, but JavaScript permits replacing an own member of that
/// object (`cp.execSync = fake`), and the member-minting route deliberately
/// leaves that question open. A reviewed complete summary closes the residual
/// dynamic-dispatch arm only while the member value at the call can still be
/// the module's own, so every JavaScript and TypeScript file in the workspace
/// is scanned for member writes and module-object escapes before the arm is
/// discharged. The scan runs once per discharged call and only after the
/// cheaper summary check has already selected the closure.
pub(crate) fn js_ts_module_member_mutation_free(
    analyzer: &dyn IAnalyzer,
    target: &UnmaterializedExternalTarget,
    cancellation: &CancellationToken,
) -> bool {
    let Ok(files) = analyzer.project().all_files_shared() else {
        return false;
    };
    for file in files.iter() {
        if cancellation.is_cancelled() {
            return false;
        }
        let language = crate::analyzer::common::language_for_file(file);
        if !matches!(language, Language::JavaScript | Language::TypeScript) {
            continue;
        }
        let Ok(source) = file.read_to_string() else {
            return false;
        };
        let Some(tree) = brokk_bifrost_js_ts::syntax::parse_js_ts_tree(file, &source, language)
        else {
            return false;
        };
        if !brokk_bifrost_js_ts::syntax::module_member_is_mutation_free(
            tree.root_node(),
            &source,
            target.owner_fqn(),
            target.member(),
        ) {
            return false;
        }
    }
    true
}

/// The one boundary shape the Python modeled-function discharge answers: the
/// exact resolver proved a receiverless external module function (no workspace
/// candidate at all) and named it through one proven external boundary.
///
/// The Python analogue of the JS/TS member shape above is simpler, because the
/// call has no receiver: `os.system(...)` names a member of an imported module
/// object, and the import binder is what proves the module. The replacement
/// hazard is the same one, and it is proven absent the same way.
pub(crate) fn python_proven_external_function_boundary<'a>(
    call_language: SemanticLanguage,
    candidates: &[DispatchCandidate],
    boundaries: &'a [DispatchBoundary],
) -> Option<&'a UnmaterializedExternalTarget> {
    if call_language.language() != Language::Python {
        return None;
    }
    proven_unmaterialized_external_boundary(candidates, boundaries)
        .filter(|target| !target.has_receiver())
}

pub(crate) fn proven_unmaterialized_external_boundary<'a>(
    candidates: &[DispatchCandidate],
    boundaries: &'a [DispatchBoundary],
) -> Option<&'a UnmaterializedExternalTarget> {
    if !candidates.is_empty() {
        return None;
    }
    let [boundary] = boundaries else {
        return None;
    };
    if !matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
        || !matches!(boundary.proof, ProofStatus::Proven)
    {
        return None;
    }
    boundary.unmaterialized_external_target()
}

/// Recheck every exhaustive Python external receiver hint before closing its
/// dispatch. Exact result claims must prove a stable local origin; each hinted
/// method must still be complete and selected by C3 for its exact class.
pub(crate) fn python_exact_external_receiver_hints(
    oracle: &WorkspaceSemanticOracle<'_>,
    call_language: SemanticLanguage,
    semantic_call: &SemanticCallSite,
    hint_set: &crate::analyzer::semantic::DispatchHintSet,
) -> Option<Vec<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>> {
    if call_language.language() != Language::Python
        || semantic_call.receiver.is_none()
        || !hint_set.exhaustive()
    {
        return None;
    }
    let hints = hint_set.hints();
    let [_, ..] = hints else {
        return None;
    };
    let proven = hint_set.proof() == DispatchHintProof::Proven;
    let constructor_origin = proven
        && hints
            .iter()
            .all(|hint| hint.origin().kind == SourceSiteKind::ConstructorCall);
    let exact_result_origin = proven
        && hints.iter().all(|hint| {
            matches!(
                hint.origin().kind,
                SourceSiteKind::ExactCallResult | SourceSiteKind::ExactAccessResult
            )
        });
    if !constructor_origin && !exact_result_origin {
        return None;
    }
    let overlay = oracle.semantic_model_overlay()?;
    let mut identities = Vec::with_capacity(hints.len());
    for hint in hints {
        let crate::analyzer::semantic::ClassIdentity::External {
            symbol_id: receiver_class_id,
            ..
        } = hint.receiver_class()
        else {
            return None;
        };
        let crate::analyzer::semantic::MemberDeclaration::External(declaration) =
            hint.declaration()
        else {
            return None;
        };
        let [member_id] = declaration.symbol_ids() else {
            return None;
        };
        let matched = overlay.symbols_with_id(member_id);
        let [member] = matched.records.as_slice() else {
            return None;
        };
        if member.id != member_id.as_ref()
            || member.kind != SemanticModelSymbolKind::Method
            || !member.has_receiver()
            || member.language != Language::Python.config_label()
            || member.provenance.ambiguous
            || !member.has_complete_callable_shape_evidence()
            || member.structured_signature().is_none()
        {
            return None;
        }
        let selected = language_support_for_hook(Language::Python, "external_member_declaration")?
            .external_member_declaration(&overlay, receiver_class_id, &member.name)?;
        if selected.id != member.id {
            return None;
        }
        let owner_id = member.owner_id.as_deref()?;
        let owners = overlay.symbols_with_id(owner_id);
        let [owner] = owners.records.as_slice() else {
            return None;
        };
        if owner.kind != SemanticModelSymbolKind::Class
            || owner.language != Language::Python.config_label()
            || owner.provenance.ambiguous
        {
            return None;
        }
        identities.push(
            crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
                Language::Python,
                owner.qualified_name.clone(),
                member.name.clone(),
            ),
        );
    }
    identities.sort_unstable();
    identities.dedup();
    Some(identities)
}

pub(crate) struct PythonExternalClassCall {
    identity: crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity,
    target: UnmaterializedExternalTarget,
}

/// Resolve an external Python class call to its exact initializer when one
/// complete active summary applies. Otherwise, an exact class or factory
/// result with no applicable summary is a resolved no-flow constructor.
pub(crate) fn python_external_class_result_call(
    oracle: &WorkspaceSemanticOracle<'_>,
    procedure: &ProcedureHandle,
    call_language: SemanticLanguage,
    candidates: &[DispatchCandidate],
    boundaries: &[DispatchBoundary],
    semantic_call: &SemanticCallSite,
) -> Option<PythonExternalClassCall> {
    if call_language.language() != Language::Python || !candidates.is_empty() {
        return None;
    }
    let [boundary] = boundaries else {
        return None;
    };
    let exact_external_boundary = matches!(boundary.kind, DispatchBoundaryKind::External(_))
        && boundary.proof == ProofStatus::Proven;
    let direct_constructor_class = if exact_external_boundary {
        None
    } else {
        language_support_for_hook(Language::Python, "external_class_call_identity")?
            .external_class_call_identity(oracle.workspace, procedure, semantic_call)
    };
    let (owner_fqn, member) = if exact_external_boundary {
        if let Some(identity) = boundary.external_callee_identity.as_ref() {
            if identity.language() != Language::Python {
                return None;
            }
            (
                identity.owner_fqn().to_owned(),
                identity.member().to_owned(),
            )
        } else {
            let target = boundary.unmaterialized_external_target()?;
            if target.language().language() != Language::Python
                || !target.has_resolver_owned_call_shape()
                || target.has_receiver()
            {
                return None;
            }
            (target.owner_fqn().to_owned(), target.member().to_owned())
        }
    } else {
        let class = direct_constructor_class.as_ref()?;
        split_canonical_qualified_callee(class.qualified_name(), Language::Python)?
    };
    let arity = u32::try_from(semantic_call.arguments.len()).ok()?;
    let canonical = format!("{owner_fqn}.{member}");
    let overlay = oracle.semantic_model_overlay()?;
    let exact_records = overlay
        .symbols_named(&canonical)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.qualified_name == canonical
                && symbol.language == Language::Python.config_label()
                && !symbol.provenance.ambiguous
        })
        .collect::<Vec<_>>();
    let expected_constructor_class_id =
        direct_constructor_class
            .as_ref()
            .and_then(|class| match class {
                crate::analyzer::semantic::ClassIdentity::External { symbol_id, .. } => {
                    Some(symbol_id.as_ref())
                }
                crate::analyzer::semantic::ClassIdentity::Workspace(_)
                | crate::analyzer::semantic::ClassIdentity::Intrinsic { .. } => None,
            });
    let direct_class = match exact_records.as_slice() {
        [class]
            if class.kind == SemanticModelSymbolKind::Class
                && class.owner_id.is_none()
                && expected_constructor_class_id.is_none_or(|symbol_id| class.id == symbol_id) =>
        {
            Some(std::sync::Arc::clone(class))
        }
        _ => None,
    };
    let function_records = exact_records
        .iter()
        .filter(|&symbol| {
            symbol.kind == SemanticModelSymbolKind::Function
                && !symbol.has_receiver()
                && symbol.has_complete_callable_shape_evidence()
                && symbol.structured_signature().is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let modeled_factory_result = function_records.len() == 1
        && function_records.len() == exact_records.len()
        && python_model_function_returns_one_exact_class(&overlay, &function_records).is_some();
    let class = direct_class
        .clone()
        .filter(|_| exact_records.len() == 1)
        .or_else(|| {
            modeled_factory_result.then(|| {
                python_model_function_returns_one_exact_class(&overlay, &function_records)
                    .expect("the exact modeled factory return was checked above")
            })
        })?;

    let active = oracle.active_semantic_models()?;
    let call_summary = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
        LanguageDialect::from(Language::Python).semantic_pack_label(),
        &owner_fqn,
        &member,
        false,
        arity,
    ));
    if call_summary.applicability != ProcedureSummaryApplicability::Complete
        || call_summary.disposition != SemanticModelMatchDisposition::Empty
    {
        return None;
    }
    let initializer_target = match direct_class {
        Some(_) => {
            let initializer_declaration =
                language_support_for_hook(Language::Python, "external_member_declaration")?
                    .external_member_declaration(&overlay, &class.id, "__init__");
            match initializer_declaration {
                Some(initializer) => {
                    let signature = initializer.structured_signature()?;
                    let owner_id = initializer.owner_id.as_deref()?;
                    let declaring_owner = overlay.symbols_with_id(owner_id);
                    let [declaring_owner] = declaring_owner.records.as_slice() else {
                        return None;
                    };
                    if declaring_owner.kind != SemanticModelSymbolKind::Class
                        || declaring_owner.language != Language::Python.config_label()
                        || declaring_owner.provenance.ambiguous
                        || initializer.provenance.pack_id != class.provenance.pack_id
                    {
                        return None;
                    }
                    let formals = python_external_model_formals(signature);
                    let target = UnmaterializedExternalTarget::new_modeled(
                        declaring_owner.qualified_name.as_str(),
                        "__init__",
                        call_language,
                        arity,
                        true,
                    )?;
                    let target = target.with_python_artifact_selection_from(
                        boundary.unmaterialized_external_target(),
                        &semantic_call.arguments,
                        &formals,
                    );
                    let target = target?;
                    let target = if declaring_owner.id != class.id {
                        target.with_python_constructor_class(class.qualified_name.as_str())?
                    } else {
                        target
                    };
                    let artifact_selection =
                        python_external_class_artifact_selection(active, &class);
                    let target = if target.selected_python_artifact().is_some() {
                        target
                    } else if let Some((evidence, manifest)) = artifact_selection {
                        let selected = target.with_python_artifact_selection(
                            &evidence,
                            &manifest,
                            &semantic_call.arguments,
                            &formals,
                        );
                        selected?
                    } else {
                        target
                    };
                    let summary = active.procedure_summaries_for_external_target(&target);
                    if summary.applicability != ProcedureSummaryApplicability::Complete {
                        return None;
                    }
                    match summary.disposition {
                        SemanticModelMatchDisposition::Empty => {}
                        SemanticModelMatchDisposition::Unique if summary.records.len() == 1 => {}
                        SemanticModelMatchDisposition::Unique
                        | SemanticModelMatchDisposition::Conflict => return None,
                    }
                    Some(target)
                }
                None => None,
            }
        }
        None => None,
    };
    let target = if let Some(target) = initializer_target {
        target
    } else if let Some(target) = boundary.unmaterialized_external_target() {
        if target.language() != call_language
            || target.owner_fqn() != owner_fqn
            || target.member() != member
            || target.has_receiver()
            || target.arity() != arity
        {
            return None;
        }
        target.clone()
    } else {
        modeled_unmaterialized_external(&owner_fqn, &member, call_language, arity, false)?
    };
    let identity = crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
        Language::Python,
        owner_fqn.to_owned(),
        member.to_owned(),
    );
    Some(PythonExternalClassCall { identity, target })
}

pub(crate) fn python_external_class_artifact_selection(
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
    class: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Option<(
    crate::analyzer::semantic_model::SemanticModelActivationEvidence,
    String,
)> {
    let shards = active.shards();
    let mut selections = shards
        .iter()
        .filter(|shard| {
            shard.manifest.pack_id == class.provenance.pack_id
                && shard.manifest.semantic_sha256 == class.provenance.pack_digest
                && shard.source_id == class.provenance.activation.source_id
        })
        .flat_map(|shard| {
            shard.matching_evidence.iter().filter_map(move |evidence| {
                (evidence.language == "python"
                    && evidence.ecosystem == "python"
                    && evidence
                        .package
                        .as_ref()
                        .is_some_and(|package| package.name.starts_with("pkg:pypi/"))
                    && evidence.artifact_sha256.is_some())
                .then_some((evidence, shard.manifest.content_sha256.as_str()))
            })
        })
        .collect::<Vec<_>>();
    selections.sort_unstable();
    selections.dedup();
    let [(evidence, manifest)] = selections.as_slice() else {
        return None;
    };
    Some(((*evidence).clone(), (*manifest).to_owned()))
}

pub(crate) fn python_model_function_returns_one_exact_class(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    records: &[Arc<crate::analyzer::semantic_model::SemanticModelSymbol>],
) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelSymbol>> {
    let mut classes = records.iter().map(|record| {
        let returns = record.structured_signature()?.returns.as_ref()?;
        let candidates = match returns {
            TypeRef::Named {
                name,
                arguments,
                nullable: false,
            } if arguments.is_empty() => overlay
                .symbols_named(name)
                .records
                .into_iter()
                .filter(|symbol| symbol.qualified_name == *name)
                .collect::<Vec<_>>(),
            TypeRef::Declared {
                id,
                arguments,
                nullable: false,
            } if arguments.is_empty() => overlay.symbols_with_id(id).records,
            _ => return None,
        };
        match candidates.as_slice() {
            [class]
                if class.kind == SemanticModelSymbolKind::Class
                    && class.language == Language::Python.config_label()
                    && class.owner_id.is_none()
                    && !class.provenance.ambiguous
                    && class.provenance.completeness == SemanticModelCompleteness::Complete =>
            {
                Some(std::sync::Arc::clone(class))
            }
            _ => None,
        }
    });
    let class = classes.next()??;
    classes
        .all(|candidate| candidate.is_some_and(|candidate| candidate.id == class.id))
        .then_some(class)
}

/// Whether no workspace Python source can replace the member an import binding
/// reads from `target`'s module before the call runs.
///
/// Python permits replacing an attribute of a shared module object
/// (`os.system = fake`), and the member-minting route deliberately leaves that
/// question open. A reviewed complete summary closes the call only while the
/// member value at the call can still be the module's own, so every Python file
/// in the workspace is scanned for member writes and module-object escapes
/// before the boundary is upgraded. The scan runs once per discharged call and
/// only after the cheaper summary check has already selected the closure.
pub(crate) fn python_module_member_mutation_free(
    analyzer: &dyn IAnalyzer,
    target: &UnmaterializedExternalTarget,
    request: &SemanticRequest<'_>,
) -> bool {
    python_workspace_module_member_mutation_free(
        analyzer,
        target.owner_fqn(),
        target.member(),
        usize::MAX,
        &|| !request.cancellation.is_cancelled(),
    )
    .unwrap_or(false)
}

/// Scan the current Python workspace for writes through aliases of one module.
///
/// This is the shared implementation for semantic-model module members and
/// Python's proven module-global initializer reads. `None` means the caller's
/// bounded query stopped; a completed but unprovable workspace returns
/// `Some(false)` and is safe to memoize as an open answer.
#[doc(hidden)]
pub fn python_workspace_module_member_mutation_free(
    analyzer: &dyn IAnalyzer,
    module: &str,
    member: &str,
    max_nodes: usize,
    keep_going: &dyn Fn() -> bool,
) -> Option<bool> {
    language_support_for_hook(Language::Python, "workspace_module_member_mutation_free")?
        .workspace_module_member_mutation_free(analyzer, module, member, max_nodes, keep_going)
}

/// Whether a low-level external boundary is only a syntax-derived placeholder
/// for a receiver whose concrete type the resolver did not know.
///
/// A complete type-flow hint may refine this arm because none of its external
/// identity, target, or call shape came from the language resolver. Exact and
/// resolver-owned arms must remain; the caller separately excludes targets
/// selected by the active semantic-model snapshot.
#[doc(hidden)]
pub fn heuristic_external_boundary_without_resolver_authority(boundary: &DispatchBoundary) -> bool {
    matches!(
        (&boundary.kind, boundary.unmaterialized_external_target()),
        (DispatchBoundaryKind::External(Some(locator)), Some(target))
            if locator == target.locator()
                && target.language() == SemanticLanguage::Standard(Language::Python)
                && !target.has_resolver_owned_call_shape()
                && target.normalized_static_owner().is_none()
                && boundary.external_callee_identity().is_none()
                && boundary.exact_external_target().is_none()
    )
}

/// The proof names the definition-lookup diagnostic kinds behind `status`, so
/// an incomplete consumer can say which lookup outcome left the call unresolved
/// (#4823).
pub(crate) fn unresolved_dispatch_boundary(
    status: DefinitionLookupStatus,
    lookup_diagnostic_kinds: &[Box<str>],
) -> DispatchBoundary {
    let proof = if lookup_diagnostic_kinds.is_empty() {
        format!("exact dispatch status is {}", status.as_str())
    } else {
        format!(
            "exact dispatch status is {}; definition lookup diagnostics: {lookup_diagnostic_kinds:?}",
            status.as_str()
        )
    };
    DispatchBoundary {
        kind: DispatchBoundaryKind::Unresolved,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: ProofStatus::Unproven(proof.into()),
        completeness: EvidenceCompleteness::Partial(
            "no materialized workspace target is available".into(),
        ),
        provenance: Box::new([]),
    }
}

/// Build the canonical identity for a fully-qualified external callee that never
/// materializes to a workspace or classpath artifact (#1978).
///
/// Only fully-qualified callees are in scope: the owner must be a multi-segment
/// path present verbatim in the callee text, written with the separator the
/// language uses (`java.net.URLDecoder.decode`, `std::str::from_utf8`). The
/// owner is published dot-joined whatever the source separator was, because
/// that is the spelling authored summaries are indexed under (#2596).
///
/// Instance-method transforms whose owner needs type resolution (`s.trim()`)
/// are deliberately excluded; they need type resolution this cut does not
/// perform. An import-qualified call (`URLDecoder.decode`, `Path::new`) reaches
/// here already expanded when its language could prove the expansion from its
/// import binders, and is otherwise excluded for the same reason.
///
/// A language whose external surface is spelled with single-segment owners
/// (`JSON.parse`, `path.join`) opts out of the multi-segment requirement
/// through [`brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge::publishes_single_segment_external_owners`]
/// (#2598). The owner such a callee arrives with has already been decided by
/// the classification stage, which is the only place that holds the call site's
/// file and can tell a runtime global from a parameter of the enclosing
/// procedure. Keeping the requirement for every other language is what stops a
/// Java `URLDecoder.decode` from minting under a bare class name that import
/// resolution should have expanded.
///
/// Go is another reviewed single-segment case. Its exact resolver replaces a
/// source alias such as `files.Open` with the structured canonical import path
/// `os.Open` before classification. JS/TS direct named imports likewise arrive
/// with the module specifier and imported symbol proven by the import binder,
/// even though the source call itself is bare. Any resolver-owned exact proof
/// may carry a single-segment owner: Python's explicit import binder proves
/// `subprocess.run` without treating that spelling as a global API.
#[doc(hidden)]
pub fn synthetic_unmaterialized_external(
    callee_text: &str,
    language: SemanticLanguage,
    semantic_call: &SemanticCallSite,
    exact_external_call: Option<&ExactExternalCallProof>,
    normalized_static_owner: Option<&str>,
) -> Option<UnmaterializedExternalTarget> {
    let defining_callee = exact_external_call
        .filter(|proof| {
            language == SemanticLanguage::Standard(Language::Python)
                && proof.call_application() == CallApplicationKind::PackageFunction
        })
        .map(ExactExternalCallProof::canonical_callee)
        .unwrap_or(callee_text);
    let (owner_fqn, member) =
        split_canonical_qualified_callee(defining_callee, language.language())?;
    let canonical_go_import = language == SemanticLanguage::Standard(Language::Go);
    let resolver_owned_identity =
        exact_external_call.is_some_and(|proof| proof.canonical_callee() == defining_callee);
    if !owner_fqn.contains('.')
        && !canonical_go_import
        && !resolver_owned_identity
        && !crate::analyzer::languages::language_knowledge(language.language())
            .is_some_and(|support| support.publishes_single_segment_external_owners())
    {
        return None;
    }
    let normalized_static_owner = normalized_static_owner.map(Box::<str>::from);
    let (arity, has_receiver, resolver_owned_call_shape) = match exact_external_call {
        Some(proof) if proof.canonical_callee() == defining_callee => {
            match proof.call_application() {
                CallApplicationKind::PackageFunction | CallApplicationKind::BoundReceiver => {}
                CallApplicationKind::ReceiverBindingUnknown | CallApplicationKind::Unknown => {
                    return None;
                }
            }
            (proof.parameter_count(), proof.has_receiver(), true)
        }
        Some(_) => return None,
        None if language == SemanticLanguage::Standard(Language::Go) => return None,
        None => (
            u32::try_from(semantic_call.arguments.len()).ok()?,
            crate::analyzer::semantic::normalized_external_has_receiver(
                semantic_call.receiver.is_some(),
                language,
                &owner_fqn,
                normalized_static_owner.as_deref(),
            ),
            false,
        ),
    };
    let anchor = zero_source_anchor();
    let owner_segment =
        DeclarationSegment::named(DeclarationSegmentKind::Type, owner_fqn.clone(), anchor, 0)
            .ok()?;
    // Arity and receiver shape enter the synthetic declaration, so the locator
    // distinguishes different-arity overloads of one `owner.member`. Same-arity
    // overloads that differ only by parameter type cannot be told apart for an
    // unmaterialized callee, whose parameter types are unrecoverable.
    let member_kind = if has_receiver {
        DeclarationSegmentKind::Method
    } else {
        DeclarationSegmentKind::Function
    };
    let member_segment =
        DeclarationSegment::named(member_kind, member.clone(), anchor, arity).ok()?;
    let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
    // The callee is declared outside the calling artifact, so it carries the
    // dialect of its declaration. A `.c` translation unit is a `cpp-c`
    // artifact, but everything it calls outside the workspace is declared in
    // a header, which keeps the C++ interpretation
    // (`LanguageDialect::for_path`) and the `cpp` label the header pack
    // publishes under. That is also the label `modeled_procedure_key_for_unit`
    // gives a `.c` workspace function, so a C procedure key has one label
    // whichever side of the boundary its callee is on (#3535).
    let declaring_language = match language {
        SemanticLanguage::CppC => SemanticLanguage::Standard(Language::Cpp),
        other => other,
    };
    let locator = SemanticLocator::new(
        unmaterialized_external_mount(),
        unmaterialized_external_path(),
        declaring_language,
        declaration,
        SemanticRole::Procedure,
        anchor,
    );
    let target = if resolver_owned_call_shape {
        UnmaterializedExternalTarget::new_for_resolver_owned_call(
            owner_fqn,
            member,
            arity,
            has_receiver,
            exact_external_call
                .and_then(ExactExternalCallProof::source_jdk_artifact)
                .cloned(),
            locator,
        )
    } else {
        UnmaterializedExternalTarget::new_with_normalized_static_owner(
            owner_fqn,
            member,
            arity,
            has_receiver,
            normalized_static_owner,
            locator,
        )
    };
    let mut target = target.with_call_arguments(&semantic_call.arguments);
    target.selected_external_descriptor = exact_external_call
        .and_then(ExactExternalCallProof::external_member_identity)
        .cloned();
    if let Some(proof) =
        exact_external_call.filter(|proof| proof.python_runtime_artifact().is_some())
    {
        target.with_selected_python_artifact(proof, &semantic_call.arguments)
    } else {
        Some(target)
    }
}

pub(crate) fn modeled_unmaterialized_external(
    owner_fqn: &str,
    member: &str,
    language: SemanticLanguage,
    arity: u32,
    has_receiver: bool,
) -> Option<UnmaterializedExternalTarget> {
    let anchor = zero_source_anchor();
    let owner_segment = DeclarationSegment::named(
        DeclarationSegmentKind::Type,
        owner_fqn.to_owned(),
        anchor,
        0,
    )
    .ok()?;
    let member_kind = if has_receiver {
        DeclarationSegmentKind::Method
    } else {
        DeclarationSegmentKind::Function
    };
    let member_segment =
        DeclarationSegment::named(member_kind, member.to_owned(), anchor, arity).ok()?;
    let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
    let locator = SemanticLocator::new(
        unmaterialized_external_mount(),
        unmaterialized_external_path(),
        language,
        declaration,
        SemanticRole::Procedure,
        anchor,
    );
    Some(
        UnmaterializedExternalTarget::new_with_normalized_static_owner(
            owner_fqn.to_owned(),
            member.to_owned(),
            arity,
            has_receiver,
            None,
            locator,
        ),
    )
}

pub(crate) fn truncated_dispatch_boundary() -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        external_callee_identity: None,
        exact_external_target: None,
        unmaterialized_external_target: None,
        proof: ProofStatus::Unproven("dispatch candidate set was truncated".into()),
        completeness: EvidenceCompleteness::Partial(
            "not every dispatch candidate was retained".into(),
        ),
        provenance: Box::new([]),
    }
}

#[doc(hidden)]
pub fn dispatch_coverage(
    status: Option<DefinitionLookupStatus>,
    boundaries: &[DispatchBoundary],
) -> CandidateCoverage {
    if boundaries
        .iter()
        .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
    {
        CandidateCoverage::Truncated
    } else if boundaries.iter().any(|boundary| {
        boundary.kind == DispatchBoundaryKind::Unresolved
            || matches!(boundary.proof, ProofStatus::Unproven(_))
    }) {
        CandidateCoverage::Open
    } else {
        match status {
            Some(
                DefinitionLookupStatus::Resolved
                | DefinitionLookupStatus::Ambiguous
                | DefinitionLookupStatus::UnresolvableImportBoundary,
            ) => CandidateCoverage::Exhaustive,
            Some(
                DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::Unavailable
                | DefinitionLookupStatus::Incomplete
                | DefinitionLookupStatus::Cancelled
                | DefinitionLookupStatus::ExceededBudget(_)
                | DefinitionLookupStatus::UnsupportedLanguage
                | DefinitionLookupStatus::InvalidLocation
                | DefinitionLookupStatus::NotFound,
            )
            | None => CandidateCoverage::Open,
        }
    }
}

pub(crate) fn rust_builtin_format_macro_identity(
    definition: &CodeUnit,
) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
    if !definition.is_macro() || !definition.is_synthetic() {
        return None;
    }
    let package = definition.package_name();
    if !matches!(package, "std" | "core" | "alloc") {
        return None;
    }
    let member = definition.terminal_name();
    if !matches!(
        member,
        "format"
            | "format_args"
            | "print"
            | "println"
            | "eprint"
            | "eprintln"
            | "write"
            | "writeln"
            | "panic"
    ) {
        return None;
    }
    Some(
        crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
            Language::Rust,
            package,
            member,
        ),
    )
}

pub(crate) fn rust_builtin_macro_identity_is_intrinsic(
    identity: &crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity,
) -> bool {
    if identity.language() != Language::Rust {
        return false;
    }
    matches!(
        (identity.owner_fqn(), identity.member()),
        (
            "std" | "core" | "alloc",
            "format"
                | "format_args"
                | "print"
                | "println"
                | "eprint"
                | "eprintln"
                | "write"
                | "writeln"
                | "panic",
        ) | ("alloc.fmt", "format")
            | ("core.panicking", "panic_fmt" | "assert_failed")
            | ("std.io.stdio", "_print" | "_eprint")
            | ("core", "matches")
            | ("alloc", "vec")
    )
}

#[doc(hidden)]
pub fn apply_dynamic_dispatch_gap(
    gap: &SemanticGap,
    member_family_reasons: &[&str],
    boundaries: &mut Vec<DispatchBoundary>,
) -> DispatchQuality {
    let mut proof_reason = format!(
        "{} dynamic-dispatch evidence does not prove the complete target set: {}",
        gap.kind.label(),
        gap.detail
    );
    for family_reason in member_family_reasons {
        proof_reason.push_str("; member family unproven: ");
        proof_reason.push_str(family_reason);
    }
    let completeness_reason = format!(
        "dynamic-dispatch target coverage is incomplete: {}",
        gap.detail
    );
    push_dispatch_gap_boundary(gap.kind, proof_reason, completeness_reason, boundaries);
    dispatch_gap_quality(gap)
}

pub(crate) fn apply_procedure_call_gap(
    gap: &SemanticGap,
    boundaries: &mut Vec<DispatchBoundary>,
) -> DispatchQuality {
    let proof_reason = format!(
        "procedure-wide {} evidence does not prove this complete call target set: {}",
        gap.capability.label(),
        gap.detail
    );
    let completeness_reason = format!(
        "procedure-wide {} coverage is incomplete: {}",
        gap.capability.label(),
        gap.detail
    );
    push_dispatch_gap_boundary(gap.kind, proof_reason, completeness_reason, boundaries);
    if gap.kind == SemanticGapKind::ExceededBudget {
        DispatchQuality::Truncated
    } else {
        DispatchQuality::Unproven
    }
}

pub(crate) fn push_dispatch_gap_boundary(
    gap_kind: SemanticGapKind,
    proof_reason: String,
    completeness_reason: String,
    boundaries: &mut Vec<DispatchBoundary>,
) {
    let boundary_kind = if gap_kind == SemanticGapKind::ExceededBudget {
        DispatchBoundaryKind::Truncated
    } else {
        DispatchBoundaryKind::Unresolved
    };
    if !boundaries
        .iter()
        .any(|boundary| boundary.kind == boundary_kind)
    {
        boundaries.push(DispatchBoundary {
            kind: boundary_kind,
            external_callee_identity: None,
            exact_external_target: None,
            unmaterialized_external_target: None,
            proof: ProofStatus::Unproven(proof_reason.into()),
            completeness: EvidenceCompleteness::Partial(completeness_reason.into()),
            provenance: Box::new([]),
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_artifact_candidates(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    actual_count: usize,
    artifact: &Arc<SemanticArtifact>,
    candidates: &mut Vec<DispatchCandidate>,
    indexes: &mut HashMap<ProcedureHandle, usize>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    native_incomplete_source_reason: Option<Box<str>>,
    max_candidates: usize,
) -> (bool, bool) {
    let mut targets = procedures_for_definition(analyzer, definition, artifact);
    if !targets.is_empty()
        && analyzer.ranges_of(definition).len() > 1
        && !cpp_unit_written_twice(artifact, analyzer, definition)
        && let Some(range) = crate::analyzer::usages::call_relations::selected_callable_range(
            analyzer,
            definition,
            actual_count,
        )
    {
        targets.retain(|target| {
            let span = target.semantics().locator().anchor().span();
            range.start_byte <= span.start_byte() as usize
                && range.end_byte >= span.end_byte() as usize
        });
    }
    let matched = !targets.is_empty();
    let mut truncated = false;
    for target in targets {
        let candidate = DispatchCandidate::new(
            target,
            proof.clone(),
            completeness.clone(),
            std::iter::empty(),
            OracleLimits::default(),
        )
        .expect("an empty dispatch draft fits every positive provenance limit");
        let candidate = if let Some(reason) = native_incomplete_source_reason.as_deref() {
            candidate.with_unique_incomplete_native_source(reason)
        } else {
            candidate
        };
        truncated |= retain_dispatch_candidate(candidates, indexes, candidate, max_candidates);
    }
    (matched, truncated)
}

/// Whether the retention above keeps every written range of `definition`
/// instead of narrowing a multi-range unit to the one declaration a call
/// selects.
///
/// The written shape is [`declares_one_logical_callable`]'s question, and the
/// unit's language decides whether this oracle asks it at all. Only a C++
/// translation unit answers yes. The C++ adapter gives a `.c` translation unit
/// its own dialect and its own storage identity, and a C prototype beside the
/// body that completes it stays on the base narrowing until #3640 settles how
/// a C prototype is keyed across translation units; no other language pairs a
/// prototype with an out-of-line body this way.
///
/// The dialect is the analyzer's own structured answer for the materialized
/// file: the artifact key records exactly the language the semantic layer
/// decided for the unit's source when it planned the materialization, so this
/// reads no path and no extension.
pub(crate) fn cpp_unit_written_twice(
    artifact: &Arc<SemanticArtifact>,
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
) -> bool {
    artifact.key().language() == SemanticLanguage::Standard(Language::Cpp)
        && declares_one_logical_callable(analyzer, definition)
}

/// Whether a declaration's several ranges are several written occurrences of
/// one callable -- an in-class prototype beside the out-of-line definition that
/// completes it -- rather than an overload set (#3507, #3508).
///
/// [`selected_callable_range`] narrows a multi-range unit to the accepting
/// declaration a call selects, which is what an overload set needs. It is the
/// wrong question for one callable written twice: the definition range carries
/// the body, and narrowing to the prototype beside it drops the only
/// materialized target and reports a resolved call as an unmaterialized
/// boundary. The published shape decides which case this is, exactly as it
/// decides identity elsewhere ([`agreed_callable_identity`]).
///
/// [`selected_callable_range`]: crate::analyzer::usages::call_relations::selected_callable_range
pub(crate) fn declares_one_logical_callable(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
) -> bool {
    use crate::analyzer::usages::callable_signature::{
        agreed_callable_identity, callable_signature_reports,
    };

    let entries = analyzer.signature_metadata(definition);
    let reports = callable_signature_reports("dispatch-retention", definition, &entries);
    agreed_callable_identity(&reports).is_some()
}

pub(crate) fn dispatch_outcome(
    result: DispatchResult,
    quality: DispatchQuality,
    work: SemanticWork,
) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
    Ok(match quality {
        DispatchQuality::Complete => SemanticOutcome::Complete {
            value: result,
            work,
        },
        DispatchQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: result,
            work,
        },
        DispatchQuality::Unproven | DispatchQuality::Truncated => SemanticOutcome::Unproven {
            partial: result,
            work,
        },
        DispatchQuality::Unknown => SemanticOutcome::Unknown {
            partial: Some(result),
            work,
        },
        DispatchQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(result),
            work,
        },
        DispatchQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(result),
            work,
        },
    })
}

pub(crate) fn procedures_for_definition(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &Arc<SemanticArtifact>,
) -> Vec<ProcedureHandle> {
    let cancellation = CancellationToken::default();
    let lookup = procedures_for_definition_with_limits(
        analyzer,
        definition,
        artifact,
        usize::MAX,
        &cancellation,
    );
    if lookup.status == ProcedureRangeLookupStatus::Complete {
        lookup.handles
    } else {
        Vec::new()
    }
}

pub fn procedures_for_definition_with_limits(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &Arc<SemanticArtifact>,
    max_examined: usize,
    cancellation: &CancellationToken,
) -> ProcedureRangeLookup {
    let mut progress = ProcedureLookupProgress::new(max_examined, cancellation);
    if let Err(status) = progress.examine() {
        return progress.failed(status);
    }
    let Some(indexed_source) = analyzer.indexed_source(definition.source()) else {
        return ProcedureRangeLookup {
            handles: Vec::new(),
            examined: progress.examined,
            status: ProcedureRangeLookupStatus::SourceChanged,
        };
    };
    let indexed_identity = match content_identity_with_progress(&indexed_source, &mut progress) {
        Ok(identity) => identity,
        Err(status) => return progress.failed(status),
    };
    if indexed_identity != artifact.key().revision().content() {
        return ProcedureRangeLookup {
            handles: Vec::new(),
            examined: progress.examined,
            status: ProcedureRangeLookupStatus::SourceChanged,
        };
    }
    if let Err(status) = progress.examine() {
        return progress.failed(status);
    }
    let (ranges, inspected_ranges, range_lookup_incomplete) =
        analyzer.ranges_with_limit(definition, progress.remaining(), cancellation);
    for _ in 0..inspected_ranges {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
    }
    if range_lookup_incomplete {
        let status = if cancellation.is_cancelled() {
            ProcedureRangeLookupStatus::Cancelled
        } else {
            ProcedureRangeLookupStatus::BudgetExhausted
        };
        return progress.failed(status);
    }
    let mut exact = Vec::new();
    let mut boundary_aligned = Vec::new();
    let mut enclosing = Vec::new();
    for procedure in artifact.procedures() {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        if !procedure_matches_definition(procedure, definition) {
            continue;
        }
        let span = procedure.locator().anchor().span();
        let mut exact_match = false;
        let mut boundary_aligned_match = false;
        let mut enclosing_match = false;
        for range in &ranges {
            if let Err(status) = progress.examine() {
                return progress.failed(status);
            }
            if range.start_byte == span.start_byte() as usize
                && range.end_byte == span.end_byte() as usize
            {
                exact_match = true;
                break;
            }
            boundary_aligned_match |= range.start_byte == span.start_byte() as usize
                || range.end_byte == span.end_byte() as usize;
            enclosing_match |= (range.start_byte <= span.start_byte() as usize
                && range.end_byte >= span.end_byte() as usize)
                || (span.start_byte() as usize <= range.start_byte
                    && span.end_byte() as usize >= range.end_byte);
        }
        let target = if exact_match {
            &mut exact
        } else if boundary_aligned_match {
            &mut boundary_aligned
        } else if enclosing_match {
            &mut enclosing
        } else {
            continue;
        };
        target.push(procedure);
    }
    let matches = if !exact.is_empty() {
        exact
    } else if !boundary_aligned.is_empty() {
        boundary_aligned
    } else {
        enclosing
    };
    let matches = match sort_procedures_by_locator(matches, &mut progress) {
        Ok(matches) => matches,
        Err(status) => return progress.failed(status),
    };
    let mut handles = Vec::with_capacity(matches.len());
    for procedure in matches {
        if let Err(status) = progress.examine() {
            return progress.failed(status);
        }
        if let Some(handle) = artifact.procedure_handle(procedure.id()) {
            handles.push(handle);
        }
    }
    ProcedureRangeLookup {
        handles,
        examined: progress.examined,
        status: ProcedureRangeLookupStatus::Complete,
    }
}

pub(crate) fn exact_external_procedure_target(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &crate::analyzer::semantic::SemanticArtifactKey,
    procedure: SemanticLocator,
    call_has_receiver: bool,
) -> Option<ExactExternalProcedureTarget> {
    let has_receiver = if artifact.language() == SemanticLanguage::Standard(Language::Go) {
        let declaration_has_receiver = definition.owner_is_type_scope();
        if call_has_receiver != declaration_has_receiver {
            return None;
        }
        declaration_has_receiver
    } else {
        call_has_receiver
    };
    let formal_contract = agreed_external_formal_contract(analyzer.signature_metadata(definition))?;
    let symbol = format!("{}{}", definition.identifier(), definition.signature()?);
    ExactExternalProcedureTarget::new(
        artifact.clone(),
        procedure,
        symbol,
        has_receiver,
        formal_contract,
    )
}

pub(crate) fn locator_for_definition(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
) -> Result<SemanticLocator, SemanticProviderError> {
    let source = analyzer
        .indexed_source(definition.source())
        .ok_or_else(|| {
            SemanticProviderError::source_access(format!(
                "indexed source is unavailable for resolved declaration `{}`",
                definition.fq_name()
            ))
        })?;
    let mut ranges = analyzer.ranges_of(definition);
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    let range = ranges.into_iter().next().unwrap_or(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 0,
        end_line: source.lines().count().saturating_sub(1),
    });
    let anchor = source_anchor_for_range(&source, &range)?;
    let file_name = definition
        .source()
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let kind = match definition.kind() {
        CodeUnitType::Class => DeclarationSegmentKind::Type,
        CodeUnitType::Function => DeclarationSegmentKind::Function,
        CodeUnitType::Field
        | CodeUnitType::Module
        | CodeUnitType::Macro
        | CodeUnitType::FileScope => DeclarationSegmentKind::AnonymousCallable,
    };
    let declaration_segment =
        DeclarationSegment::named(kind, definition.identifier(), anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let declaration = DeclarationLocator::new(vec![file_segment, declaration_segment])
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let path = WorkspaceRelativePath::try_from_path(definition.source().rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    Ok(SemanticLocator::new(
        WorkspaceMountId::from_root(definition.source().root()),
        path,
        LanguageDialect::for_path(
            crate::analyzer::common::language_for_file(definition.source()),
            definition.source().rel_path(),
        ),
        declaration,
        SemanticRole::Procedure,
        anchor,
    ))
}

#[doc(hidden)]
pub fn compare_dispatch_boundaries(left: &DispatchBoundary, right: &DispatchBoundary) -> Ordering {
    dispatch_boundary_rank(&left.kind)
        .cmp(&dispatch_boundary_rank(&right.kind))
        .then_with(|| match (&left.kind, &right.kind) {
            (DispatchBoundaryKind::External(left), DispatchBoundaryKind::External(right)) => {
                compare_optional_locators(left.as_ref(), right.as_ref())
            }
            (
                DispatchBoundaryKind::Unmaterialized(left),
                DispatchBoundaryKind::Unmaterialized(right),
            ) => compare_locator_fields(left, right),
            (
                DispatchBoundaryKind::Deferred {
                    target: left_target,
                    kind: left_kind,
                },
                DispatchBoundaryKind::Deferred {
                    target: right_target,
                    kind: right_kind,
                },
            ) => left_kind
                .label()
                .cmp(right_kind.label())
                .then_with(|| compare_locator_fields(left_target, right_target)),
            (DispatchBoundaryKind::Unresolved, DispatchBoundaryKind::Unresolved)
            | (DispatchBoundaryKind::Truncated, DispatchBoundaryKind::Truncated) => Ordering::Equal,
            _ => unreachable!("matching boundary ranks must identify the same variant"),
        })
        .then_with(|| {
            left.external_callee_identity
                .cmp(&right.external_callee_identity)
        })
}

impl Drop for PreparedWorkspaceDispatchPool<'_> {
    fn drop(&mut self) {
        if crate::profiling::enabled() {
            crate::profiling::note(format!(
                "semantic.prepared_pool.run_end prepared_pool_artifact_bytes={}",
                self.artifact_bytes()
            ));
        }
    }
}

use crate::analyzer::semantic::service::ArtifactRetentionCensus;

use moka::sync::Cache;

use crate::analyzer::semantic::StableDigest;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "dispatch/js_ts_tests_support.rs"]
pub mod js_ts_tests_support;

#[doc(hidden)]
#[cfg(test)]
pub mod tests {

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::agreed_external_formal_contract;

    use crate::analyzer::CallableArity;

    use crate::analyzer::ParameterMetadata;

    use crate::analyzer::SignatureMetadata;

    fn external_signature(
        label: &str,
        parameter_label: &str,
        parameter_type: Option<&str>,
    ) -> SignatureMetadata {
        let metadata = SignatureMetadata::new(
            label,
            vec![ParameterMetadata::new(
                parameter_label,
                0,
                parameter_label.len(),
            )],
        )
        .with_callable_arity(CallableArity::exact(1));
        match parameter_type {
            Some(parameter_type) => {
                metadata.with_callable_parameter_types(vec![parameter_type.to_owned()])
            }
            None => metadata,
        }
    }

    #[cfg(test)]
    #[test]
    fn exact_external_formal_contract_rejects_same_arity_overloads() {
        let contract = agreed_external_formal_contract([
            external_signature("execute(String)", "value", Some("String")),
            external_signature("execute(int)", "value", Some("int")),
        ]);

        assert!(contract.is_none());
    }

    #[cfg(test)]
    #[test]
    fn exact_external_formal_contract_rejects_missing_discriminators() {
        let contract = agreed_external_formal_contract([
            external_signature("execute(String)", "value", None),
            external_signature("execute(String)", "value", Some("String")),
        ]);

        assert!(contract.is_none());
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_tests_test_support {

    /// The Rust fixture behind the #2596 acceptance. Each function holds one
    /// external call, written in one of the three spellings the issue names.
    #[doc(hidden)]
    pub const RUST_EXTERNAL_CALL_SOURCE: &str = r#"use std::path::Path;

pub fn scoped(bytes: &[u8]) {
    let _ = std::str::from_utf8(bytes);
}

pub fn imported(text: &str) {
    let _ = Path::new(text);
}

pub fn prelude(text: &str) {
    let _ = String::from(text);
}
"#;
}
