//! Bounded Python definition points shared by navigation and receiver requests.

use super::{PythonNativeOpen, PythonNativeRequest, open_python_native_request};
use crate::analyzer::PythonAnalyzer;
use crate::analyzer::python::external_authority::native::{
    PythonExternalAuthority, PythonExternalAuthorityResult, PythonExternalIdentityKind,
    PythonExternalRefusal,
};
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
use brokk_bifrost_analysis::analyzer::native_points::{
    adapt_definition_answer, adapt_type_answer, unavailable_definition, unavailable_type,
};
use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
use brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion;
use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;
use brokk_bifrost_analysis::analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionLocated,
    SelectedResolutionOperationOutcome, native_units::SelectedNativeDefinitions,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    CallEvidence, DefinitionLookupOutcome, DefinitionLookupStatus,
};
use brokk_bifrost_analysis::analyzer::usages::get_type::{
    TypeLookupOutcome, TypeLookupStatus, candidates_outcome_with_target_kind,
    semantic_model_lookup_type,
};
use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};

/// Add work done earlier in the same request to every outcome's work.
fn with_prior_work<T>(
    result: BoundedResolution<T>,
    prior: ReceiverAnalysisWork,
) -> BoundedResolution<T> {
    match result {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value,
            work: prior.saturating_add(work),
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded {
            limit,
            work: prior.saturating_add(work),
        },
        BoundedResolution::Unavailable { reason, work } => BoundedResolution::Unavailable {
            reason,
            work: prior.saturating_add(work),
        },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled {
            work: prior.saturating_add(work),
        },
    }
}

/// Selected operation or its explicit opening refusal, retained for one query.
/// Opening failures are answers too; they never trigger legacy recovery.
/// A store error also records a query failure on the current request, so a
/// transient error is reported and never reused as an answer (#8411).
///
/// The operation opens on first use: a request whose definition lookups are
/// all answered by the outer request's memo opens nothing (#13847).
pub(crate) struct PythonReceiverRequest<'a> {
    python: &'a PythonAnalyzer,
    cancellation: brokk_bifrost_core::cancellation::CancellationToken,
    opened: Option<OpenedPythonRequest<'a>>,
    artifacts: brokk_bifrost_analysis::analyzer::resolution::batch::ForwardCandidateArtifactCache,
}

/// The opened operation and the receipt of the reads that opened it. A
/// memoized definition answer replays that receipt as well as its own reads,
/// because a hit in another receiver request never opened this operation.
/// The answers of one operation share the receipt.
struct OpenedPythonRequest<'a> {
    native: PythonNativeOpen<'a>,
    reads: Option<std::sync::Arc<brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads>>,
}

impl<'a> PythonReceiverRequest<'a> {
    /// The selected native request, opened on first use under `analyzer`'s
    /// read attribution.
    fn native(&mut self, analyzer: &dyn IAnalyzer) -> &mut PythonNativeOpen<'a> {
        let python = self.python;
        let cancellation = &self.cancellation;
        &mut self
            .opened
            .get_or_insert_with(|| {
                let (native, admission) =
                    brokk_bifrost_analysis::analyzer::usages::common::capture_memo_reads(
                        brokk_bifrost_analysis::analyzer::usages::common::QueryMemoOwner::PythonDefinitionAnswer,
                        analyzer,
                        || open_native(python, cancellation),
                    );
                OpenedPythonRequest {
                    native,
                    reads: admission.admitted().map(std::sync::Arc::new),
                }
            })
            .native
    }

    /// Run `read` on the selected native request this receiver request holds,
    /// or return `None` when opening it did not produce one.
    pub(crate) fn with_native_request<R>(
        &mut self,
        analyzer: &dyn IAnalyzer,
        read: impl FnOnce(&mut PythonNativeRequest<'a>) -> R,
    ) -> Option<R> {
        let PythonNativeOpen::Ready(request) = self.native(analyzer) else {
            return None;
        };
        Some(read(request))
    }
}

/// One outer request's Python definition answers (#13847).
///
/// Value-flow discovery, ICFG call transfers, and the import and constructor
/// probes of one dispatch each resolve the same callee site through a receiver
/// request of their own, so one site used to be resolved several times per
/// request, each time on a fresh forward operation. A lookup builds its own
/// forward operation, so its answer and work depend only on the key below, not
/// on which receiver request asks. Within one outer request each site is now
/// resolved once; later asks replay its answer, its work and its read receipt,
/// including the reads that opened the operation it ran on.
///
/// The memo is a resource of the outer request, carried to its workers and
/// closed with it. It is not in the analyzer's query-scope memos, which
/// overlapping requests share. Its entries live in request-private regions of
/// the analyzer owner's retention budget, which invalidate when the request
/// closes or drops; eviction under pressure means recomputation. Only a
/// complete answer from a live lookup whose receipt was admitted is kept: a
/// stopped, failed, cancelled or traced lookup is recomputed by the next ask.
pub(crate) struct PythonDefinitionAnswers {
    /// One region per retention owner; `None` once the request has closed,
    /// so a worker still computing then keeps nothing.
    regions: std::sync::Mutex<Option<Vec<PythonDefinitionRegion>>>,
    /// The project views this request's answers name by allocation. Holding
    /// them keeps an address from naming another view within the request.
    projects:
        std::sync::Mutex<Vec<std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project>>>,
    #[cfg(any(test, feature = "test-support"))]
    fills: std::sync::atomic::AtomicUsize,
}

type PythonDefinitionRegion = (
    brokk_bifrost_core::retention_budget::RetentionBudget,
    brokk_bifrost_core::retention_budget::BudgetRegion<PythonDefinitionKey, PythonDefinitionAnswer>,
);

struct PythonDefinitionAnswer {
    value: (DefinitionLookupOutcome, CallEvidence),
    work: ReceiverAnalysisWork,
    opening: std::sync::Arc<brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads>,
    reads: brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads,
    bytes: usize,
}

impl brokk_bifrost_core::retention_budget::RetainedBytes for PythonDefinitionAnswer {
    fn retained_bytes(&self) -> usize {
        self.bytes
    }
}

impl PythonDefinitionAnswer {
    fn new(
        value: (DefinitionLookupOutcome, CallEvidence),
        work: ReceiverAnalysisWork,
        opening: std::sync::Arc<brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads>,
        reads: brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads,
    ) -> Self {
        use brokk_bifrost_analysis::analyzer::usages::common::allocated_memo_read_bytes;
        // The shared opening receipt is charged to every answer: that
        // overstates the retention of one operation's answers, never hides it.
        let bytes = std::mem::size_of::<Self>()
            + value.0.retained_heap_bytes()
            + value.1.retained_heap_bytes()
            + allocated_memo_read_bytes(&reads)
            + allocated_memo_read_bytes(&opening);
        Self {
            value,
            work,
            opening,
            reads,
            bytes,
        }
    }
}

/// Everything a definition lookup reads besides the store: the selected
/// snapshot and project view, the active model sets and runtime
/// publication, and the caller's site, source and budget. An overlay clone
/// keeps its base's snapshot but has a project view of its own, and an
/// overlay edit within the request advances that view's generation.
#[derive(Clone, PartialEq, Eq, Hash)]
struct PythonDefinitionKey {
    snapshot: brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    /// The analyzer's project allocation, retained by the memo, and the
    /// generation its mutable inputs last published.
    project: usize,
    generation: u64,
    model_snapshot: Option<String>,
    model_overlay: Option<String>,
    runtime: Option<[u8; 32]>,
    file: brokk_bifrost_core::analyzer::ProjectFile,
    site: brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    source: [u8; 32],
    parsed: bool,
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
}

impl brokk_bifrost_core::retention_budget::RetainedBytes for PythonDefinitionKey {
    fn retained_bytes(&self) -> usize {
        use brokk_bifrost_core::allocation_size::allocation_size;
        let strings = [
            Some(&self.snapshot.workspace_id.0),
            Some(&self.snapshot.lang),
            self.model_snapshot.as_ref(),
            self.model_overlay.as_ref(),
            Some(&self.site.path),
            Some(&self.site.text),
        ];
        std::mem::size_of::<Self>()
            + strings
                .into_iter()
                .flatten()
                .map(|text| allocation_size(text.capacity()))
                .sum::<usize>()
            + self
                .file
                .retained_bytes()
                .saturating_sub(std::mem::size_of_val(&self.file))
    }
}

impl PythonDefinitionKey {
    fn new(project: usize, python: &PythonAnalyzer, query: &BoundedReceiverQuery<'_>) -> Self {
        let snapshot = python
            .inner
            .selected_workspace_snapshots()
            .get("python")
            .expect("selected Python snapshot")
            .clone();
        let active = query.analyzer.active_semantic_model_snapshot();
        Self {
            snapshot,
            project,
            generation: python.inner.project().analysis_generation(),
            model_snapshot: active
                .as_ref()
                .map(|active| active.active_models().active_model_set_hash().to_owned()),
            model_overlay: query
                .analyzer
                .semantic_model_overlay_read()
                .published()
                .as_ref()
                .map(|overlay| overlay.active_model_set_hash().to_owned()),
            runtime: active
                .as_ref()
                .and_then(|active| active.python_runtime())
                .map(|publication| publication.evidence_digest),
            file: query.file.clone(),
            site: query.site.clone(),
            source: brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                query.source.as_bytes(),
            ),
            parsed: query.tree.is_some(),
            budget: query.budget,
        }
    }
}

impl brokk_bifrost_core::analyzer::outer_request::RequestResource for PythonDefinitionAnswers {
    fn close(&self) {
        self.invalidate();
    }
}

impl Drop for PythonDefinitionAnswers {
    fn drop(&mut self) {
        self.invalidate();
    }
}

impl Default for PythonDefinitionAnswers {
    fn default() -> Self {
        Self {
            regions: std::sync::Mutex::new(Some(Vec::new())),
            projects: std::sync::Mutex::default(),
            #[cfg(any(test, feature = "test-support"))]
            fills: std::sync::atomic::AtomicUsize::default(),
        }
    }
}

impl PythonDefinitionAnswers {
    fn invalidate(&self) {
        let closed = self
            .regions
            .lock()
            .expect("Python definition answers poisoned")
            .take();
        for (_, region) in closed.into_iter().flatten() {
            region.invalidate_all();
        }
    }

    /// Keep `answer` unless the request has closed. The check and the insert
    /// hold the lock `invalidate` takes, so no answer lands after it.
    fn insert(
        &self,
        region: &brokk_bifrost_core::retention_budget::BudgetRegion<
            PythonDefinitionKey,
            PythonDefinitionAnswer,
        >,
        key: PythonDefinitionKey,
        answer: PythonDefinitionAnswer,
    ) {
        let regions = self
            .regions
            .lock()
            .expect("Python definition answers poisoned");
        if regions.is_some() {
            // A refused admission keeps nothing; the next ask recomputes.
            region.insert(key, answer);
        }
    }

    /// Answers this request computed under its memo, kept or not.
    #[cfg(test)]
    pub(crate) fn fills(&self) -> usize {
        self.fills.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Answers this request keeps.
    #[cfg(test)]
    pub(crate) fn retained(&self) -> usize {
        self.regions
            .lock()
            .expect("Python definition answers poisoned")
            .iter()
            .flatten()
            .map(|(_, region)| region.stats().entries)
            .sum()
    }

    /// `python`'s project view, held for the rest of the request.
    fn project(&self, python: &PythonAnalyzer) -> usize {
        let project = python.inner.shared_project();
        let address = std::sync::Arc::as_ptr(&project).cast::<()>() as usize;
        let mut projects = self
            .projects
            .lock()
            .expect("Python definition answers poisoned");
        if !projects
            .iter()
            .any(|held| std::sync::Arc::as_ptr(held).cast::<()>() as usize == address)
        {
            projects.push(project);
        }
        address
    }

    /// This request's private region of `python`'s retention owner; `None`
    /// once the request has closed.
    fn region(
        &self,
        python: &PythonAnalyzer,
    ) -> Option<
        brokk_bifrost_core::retention_budget::BudgetRegion<
            PythonDefinitionKey,
            PythonDefinitionAnswer,
        >,
    > {
        let budget = python.inner.analyzer_store().retention_budget();
        let mut regions = self
            .regions
            .lock()
            .expect("Python definition answers poisoned");
        let regions = regions.as_mut()?;
        if let Some((_, region)) = regions.iter().find(|(owner, _)| owner.ptr_eq(budget)) {
            return Some(region.clone());
        }
        let region = budget.region("python-definition-answers", None);
        regions.push((budget.clone(), region.clone()));
        Some(region)
    }
}

/// The current outer request's answers; `None` outside a request or once it
/// has closed.
pub(crate) fn request_definition_answers() -> Option<std::sync::Arc<PythonDefinitionAnswers>> {
    brokk_bifrost_analysis::analyzer::i_analyzer::current_outer_request()?
        .resource::<PythonDefinitionAnswers, std::convert::Infallible>(
            brokk_bifrost_core::analyzer::outer_request::RequestEntryKey::PythonDefinitionAnswers,
            || Ok(std::sync::Arc::default()),
        )
        .ok()
}

fn open_native<'a>(
    python: &'a PythonAnalyzer,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> PythonNativeOpen<'a> {
    match open_python_native_request(python, cancellation) {
        Ok(opened) => opened,
        Err(error) => {
            let message = error.to_string();
            python.record_query_failure(error);
            PythonNativeOpen::Unavailable {
                kind: "native_store_error",
                message,
            }
        }
    }
}

impl PythonReceiverRequest<'_> {
    pub(crate) fn begin_receiver_query(&mut self) {
        self.artifacts.reset_owner_expansions();
    }

    /// Read the selected native value type at an expression site. The request
    /// stays private until Python's type consumers are switched together.
    pub(crate) fn resolve_native_type_at(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<BoundedResolution<
        SelectedResolutionOperationOutcome<SelectedResolutionLocated<
            brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeReferenceTypes,
        >>,
    >>>{
        self.native(query.analyzer);
        let Some(OpenedPythonRequest {
            native: PythonNativeOpen::Ready(request),
            ..
        }) = &mut self.opened
        else {
            return Ok(None);
        };
        let Some(tree) = query.tree else {
            return Ok(None);
        };
        let Some(mut expression) = tree.root_node().named_descendant_for_byte_range(
            query.site.focus_start_byte,
            query.site.focus_end_byte,
        ) else {
            return Ok(None);
        };
        // A selection on the attribute identifier denotes the value of the
        // enclosing attribute expression, whose producer site is that token.
        if let Some(parent) = expression.parent()
            && parent.kind() == "attribute"
            && parent.child_by_field_name("attribute") == Some(expression)
        {
            expression = parent;
        }
        let is_call = expression.kind() == "call";
        if is_call {
            expression = expression
                .child_by_field_name("function")
                .expect("call has a function");
        }
        let focus = if expression.kind() == "attribute" {
            expression
                .child_by_field_name("attribute")
                .expect("attribute has its field")
        } else {
            expression
        };
        let locator = SelectedSemanticLocator::for_reference_range(
            "python",
            brokk_bifrost_core::path_utils::rel_path_string(query.file),
            focus.start_byte(),
            focus.end_byte(),
        );
        let locator = if is_call {
            locator.for_call_result()
        } else {
            locator
        };
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        request
            .operation
            .resolve_native_reference_types_bounded_for_python_request(
                &request.environment,
                &locator,
                None,
                query.budget,
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut self.artifacts,
            )
            .map(Some)
    }
}

impl<'a> PythonReceiverRequest<'a> {
    pub(crate) fn exact_model_type_owner_id(
        &mut self,
        analyzer: &dyn IAnalyzer,
        fqn: &str,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<Option<String>, String> {
        self.native(analyzer);
        let Some(OpenedPythonRequest {
            native: PythonNativeOpen::Ready(request),
            ..
        }) = &mut self.opened
        else {
            return Ok(None);
        };
        request
            .operation
            .python_exact_model_type_owner(fqn, cancellation)
            .map(|owner| owner.map(|owner| owner.id))
            .map_err(|error| {
                let message = error.to_string();
                self.python.record_query_failure(error);
                message
            })
    }

    pub(crate) fn resolve_type_bounded(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        self.begin_receiver_query();
        let result = self.resolve_native_type_bounded(query);
        let native_work = result.work();
        // A native answer that is open because the selected provider or the
        // lexical selection is open keeps the legacy structural answer until
        // provider work proves it natively (#5658). The typed reason selects
        // the site, never a name.
        let typed_open = matches!(&result, BoundedResolution::Complete { value, .. }
        if value.status == TypeLookupStatus::Incomplete
            && value.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.kind.as_str(),
                    "python_provider_open" | "python_lexical_selection_open"
                )
            }));
        if !typed_open {
            return result;
        }
        use brokk_bifrost_core::analyzer::query_token::QueryScope as _;
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(query.analyzer);
        // One request has one allowance: the native attempt's work is spent.
        with_prior_work(
            crate::analyzer::usages::get_type::python::resolve_python_type_legacy_bounded(
                query.analyzer,
                scope.token(),
                query.file,
                query.source,
                query.tree,
                query.site,
                query.budget.remaining_after(&native_work),
                query.cancellation,
            ),
            native_work,
        )
    }

    fn resolve_native_type_bounded(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        // Work done before the type lookup proper belongs to this request.
        let mut prior = ReceiverAnalysisWork::default();
        let result = self.resolve_native_type_after_prior_work(query, &mut prior);
        with_prior_work(result, prior)
    }

    /// Everything but the work accumulated in `prior`: the node walk and the
    /// preliminary definition lookup run before the type lookup, which then
    /// gets only the allowance they left.
    fn resolve_native_type_after_prior_work(
        &mut self,
        query: BoundedReceiverQuery<'_>,
        prior: &mut ReceiverAnalysisWork,
    ) -> BoundedResolution<TypeLookupOutcome> {
        // The supplied source must be the selected source before any selected
        // fact is read, including the class fast path below.
        let session = ResolutionSession::bounded(query.budget, query.cancellation);
        match self.native(query.analyzer) {
            PythonNativeOpen::Ready(_) => {}
            PythonNativeOpen::Unavailable { kind, message } => {
                return session.finish(unavailable_type(query.site, kind, message.clone()));
            }
            PythonNativeOpen::Cancelled => {
                return BoundedResolution::Cancelled {
                    work: session.finish(()).work(),
                };
            }
        };
        if !self
            .python
            .inner
            .source_matches_selected_native_content(query.file, query.source)
        {
            return session.finish(unavailable_type(
                query.site,
                "native_source_mismatch",
                "supplied Python source differs from the selected source".into(),
            ));
        }
        if let Some(tree) = query.tree {
            let mut steps = 0usize;
            let node = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
                tree.root_node(), query.site.focus_start_byte, query.site.focus_end_byte, || {
                    steps += 1;
                    true
                },
            );
            // The walk's steps are telemetry: work never refuses (#13216).
            prior.scope_nodes = steps;
            let preliminary_query = BoundedReceiverQuery {
                budget: query.budget.remaining_after(prior),
                ..query
            };
            if let Some(mut expression) = node {
                while let Some(parent) = expression.parent() {
                    if parent.kind() != "attribute"
                        || parent.child_by_field_name("attribute") != Some(expression)
                    {
                        break;
                    }
                    expression = parent;
                }
                let preliminary = matches!(expression.kind(), "identifier" | "attribute")
                    .then(|| self.resolve_definition_with_call_evidence_bounded(preliminary_query));
                // A stop of the preliminary lookup is the query's stop. Only a
                // complete answer that is not a resolved definition continues
                // to the type reference lookup below.
                let preliminary = match preliminary {
                    Some(BoundedResolution::Complete { value, work }) => Some((value, work)),
                    Some(BoundedResolution::Exceeded { limit, work }) => {
                        return BoundedResolution::Exceeded { limit, work };
                    }
                    Some(BoundedResolution::Unavailable { reason, work }) => {
                        return BoundedResolution::Unavailable { reason, work };
                    }
                    Some(BoundedResolution::Cancelled { work }) => {
                        return BoundedResolution::Cancelled { work };
                    }
                    None => None,
                };
                // A nested class reached through self/cls can be shadowed by
                // instance writes or subclass overrides, so the resolved
                // class is not a complete type reference.
                if let Some(((definition, _), work)) = &preliminary
                    && definition.status == DefinitionLookupStatus::Resolved
                    && !brokk_bifrost_python::syntax::python_attribute_names_nested_class_through_current_receiver_bounded(
                        query.source,
                        expression,
                    )
                {
                    let work = *work;
                    if let [unit] = definition.definitions.as_slice()
                        && unit.kind() == CodeUnitType::Class
                    {
                        return BoundedResolution::Complete {
                            value: candidates_outcome_with_target_kind(
                                unit.fq_name(),
                                vec![unit.clone()],
                                TypeLookupTargetKind::TypeReference,
                            ),
                            work,
                        };
                    }
                    if definition.definitions.is_empty()
                        && let [symbol] = definition.modeled_definitions.as_slice()
                        && symbol.kind == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Class
                    {
                        let cancellation = query.cancellation.cloned().unwrap_or_default();
                        match self.exact_model_type_owner_id(query.analyzer, &symbol.qualified_name, &cancellation) {
                            Ok(Some(id)) if id == symbol.id => return BoundedResolution::Complete {
                                value: TypeLookupOutcome {
                                    status: TypeLookupStatus::Resolved,
                                    reference: Some(query.site.clone()),
                                    types: vec![semantic_model_lookup_type(query.file, symbol)],
                                    diagnostics: vec![],
                                    target_kind: TypeLookupTargetKind::TypeReference,
                                }, work,
                            },
                            Err(message) => return BoundedResolution::Complete {
                                value: unavailable_type(query.site, "native_store_error", message), work,
                            },
                            Ok(_) => {}
                        }
                    }
                }
                // A preliminary answer that did not end the request spent
                // part of its allowance.
                if let Some((_, work)) = &preliminary {
                    *prior = prior.saturating_add(*work);
                }
            }
        }
        let query = BoundedReceiverQuery {
            budget: query.budget.remaining_after(prior),
            ..query
        };
        let selected = self.resolve_native_type_at(query);
        let Some(OpenedPythonRequest {
            native: PythonNativeOpen::Ready(request),
            ..
        }) = &mut self.opened
        else {
            unreachable!("native opening was checked above")
        };
        let cancellation = query.cancellation.cloned().unwrap_or_default();
        let result = selected.and_then(|selected| {
            selected.map(Ok).unwrap_or_else(|| {
                let locator = SelectedSemanticLocator::for_reference_range(
                    "python",
                    brokk_bifrost_core::path_utils::rel_path_string(query.file),
                    query.site.focus_start_byte,
                    query.site.focus_end_byte,
                );
                request
                    .operation
                    .resolve_native_reference_types_bounded_for_python_request(
                        &request.environment,
                        &locator,
                        None,
                        query.budget,
                        &cancellation,
                        &mut SelectedResolutionContextMetrics,
                        &mut self.artifacts,
                    )
            })
        });
        match result {
            Ok(BoundedResolution::Complete { value, work }) => {
                let mut has_nominal_or_external_owner = false;
                let mut value_identities = Vec::new();
                let mut value = match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) => {
                        if matches!(answer.value_types, brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes::Cancelled) {
                            return BoundedResolution::Cancelled { work };
                        }
                        if let brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes::Ready { nominal, external_owners, .. } = &answer.value_types {
                            has_nominal_or_external_owner = !nominal.is_empty() || !external_owners.is_empty();
                        }
                        value_identities.extend(
                            answer
                                .answer
                                .projected_frontiers()
                                .iter()
                                .flat_map(|frontier| frontier.possible_values())
                                .map(|value| value.ty().identity()),
                        );
                        adapt_type_answer(query.site, Language::Python, answer)
                    }
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing(_),
                    ) => {
                        let mut outcome = unavailable_type(
                            query.site,
                            "native_reference_missing",
                            "selected Python source has no type reference at this range".into(),
                        );
                        outcome.status = TypeLookupStatus::NotFound;
                        outcome
                    }
                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                        unavailable_type(query.site, "native_unavailable", format!("{reason:?}"))
                    }
                    SelectedResolutionOperationOutcome::Stale(reason) => {
                        unavailable_type(query.site, "native_stale", format!("{reason:?}"))
                    }
                    SelectedResolutionOperationOutcome::Cancelled(_) => {
                        return BoundedResolution::Cancelled { work };
                    }
                };
                if has_nominal_or_external_owner
                    && value.status == brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus::Resolved
                    && let [ty] = value.types.as_mut_slice()
                {
                    // The model owner is the answer's own value identity, never
                    // a workspace class that only shares the owner's spelling.
                    // A modeled type carries the synthetic compatibility
                    // declaration that type flow seeds from.
                    for identity in value_identities {
                        match request.operation.python_model_value_owner(identity, &cancellation) {
                            Ok(Some(owner)) if owner.qualified_name == ty.fqn => {
                                *ty = semantic_model_lookup_type(query.file, &owner);
                                break;
                            }
                            Ok(_) => {}
                            Err(error) => {
                                let message = error.to_string();
                                self.python.record_query_failure(error);
                                return BoundedResolution::Complete {
                                    value: unavailable_type(query.site, "native_store_error", message),
                                    work,
                                };
                            }
                        }
                    }
                    if cancellation.is_cancelled() {
                        return BoundedResolution::Cancelled { work };
                    }
                }
                BoundedResolution::Complete { value, work }
            }
            Ok(BoundedResolution::Exceeded { limit, work }) => {
                BoundedResolution::Exceeded { limit, work }
            }
            Ok(BoundedResolution::Unavailable { reason, work }) => {
                BoundedResolution::Unavailable { reason, work }
            }
            Ok(BoundedResolution::Cancelled { work }) => BoundedResolution::Cancelled { work },
            Err(error) => {
                let message = error.to_string();
                self.python.record_query_failure(error);
                session.finish(unavailable_type(query.site, "native_store_error", message))
            }
        }
    }
    pub(crate) fn open(
        python: &'a PythonAnalyzer,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Self {
        Self {
            python,
            cancellation: cancellation.clone(),
            opened: None,
            artifacts: Default::default(),
        }
    }

    /// Resolve one definition, at most once per site in the outer request.
    /// A later ask replays the first answer, its work and its read receipt.
    pub(crate) fn resolve_definition_with_call_evidence_bounded(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
        use brokk_bifrost_analysis::analyzer::usages::common::{
            QueryMemoOwner, capture_memo_reads, is_native_operation_failure, replay_memo_reads,
        };
        // A trace records the selection as it happens, and a replayed answer
        // has no selection to record. A cancelled ask, or one in a request
        // whose store has failed, reports its own stop rather than an earlier
        // answer, as a fresh resolution session does.
        let answers =
            if brokk_bifrost_analysis::analyzer::usages::get_definition::trace::recording()
                || query.cancellation.is_some_and(|token| token.is_cancelled())
                || brokk_bifrost_core::analyzer::carried_context::request_store_failed()
            {
                None
            } else {
                request_definition_answers()
            };
        let Some(answers) = answers else {
            return self.resolve_definition_uncached(query);
        };
        let Some(region) = answers.region(self.python) else {
            return self.resolve_definition_uncached(query);
        };
        let key = PythonDefinitionKey::new(answers.project(self.python), self.python, &query);
        if let Some(answer) = region.get(&key) {
            replay_memo_reads(&answer.opening, query.analyzer);
            replay_memo_reads(&answer.reads, query.analyzer);
            return BoundedResolution::Complete {
                value: answer.value.clone(),
                work: answer.work,
            };
        }
        // Open outside the answer's capture: its receipt is shared by every
        // answer this operation gives.
        self.native(query.analyzer);
        let Some(opening) = self.opened.as_ref().and_then(|opened| opened.reads.clone()) else {
            return self.resolve_definition_uncached(query);
        };
        let (result, admission) = capture_memo_reads(
            QueryMemoOwner::PythonDefinitionAnswer,
            query.analyzer,
            || self.resolve_definition_uncached(query),
        );
        #[cfg(any(test, feature = "test-support"))]
        answers
            .fills
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let BoundedResolution::Complete { value, work } = &result
            && !query.cancellation.is_some_and(|token| token.is_cancelled())
            && !value
                .0
                .diagnostics
                .iter()
                .any(|diagnostic| is_native_operation_failure(&diagnostic.kind))
            && let Some(reads) = admission.admitted()
        {
            answers.insert(
                &region,
                key,
                PythonDefinitionAnswer::new(value.clone(), *work, opening, reads),
            );
        }
        result
    }

    fn resolve_definition_uncached(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
        self.begin_receiver_query();
        // The operation is reusable, but work and sticky stops belong to one
        // query. A warm request must still charge the current query's reads.
        let session = ResolutionSession::bounded(query.budget, query.cancellation);
        self.native(query.analyzer);
        let request = match &mut self.opened.as_mut().expect("opened above").native {
            PythonNativeOpen::Ready(request) => request,
            PythonNativeOpen::Unavailable { kind, message } => {
                return session.finish((
                    unavailable_definition(query.site, kind, message.clone()),
                    CallEvidence::default(),
                ));
            }
            PythonNativeOpen::Cancelled => {
                return BoundedResolution::Cancelled {
                    work: session.finish(()).work(),
                };
            }
        };
        let result = request.operation.python_definition_at(
            &request.environment,
            query.file,
            query.site.focus_start_byte..query.site.focus_end_byte,
            &session,
        );
        match result {
            Ok(BoundedResolution::Complete { value, work }) => {
                let mut evidence = CallEvidence::default();
                let outcome = match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(mut answer),
                    ) => {
                        if matches!(
                            answer.reference.definitions,
                            SelectedNativeDefinitions::Cancelled
                        ) {
                            return BoundedResolution::Cancelled { work };
                        }
                        if let Some((import_target, spellings)) = &answer.source_root_gap {
                            let reference = &query.site.text;
                            let outcome = brokk_bifrost_analysis::analyzer::usages::get_definition::no_definition(
                                "python_source_root_resolution_gap",
                                format!("`{reference}` is imported from `{import_target}`, which this workspace indexes under a source root below the project root as {spellings:?}; the module is inside the workspace, so this is a resolution gap rather than an import that left it"),
                            );
                            return BoundedResolution::Complete {
                                value: (outcome, evidence),
                                work,
                            };
                        }
                        // Definition identity uses binding completion, not
                        // invocation completion or argument application.
                        if let Some(dispatch) = answer.dispatch_extensibility {
                            evidence.call_application = brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind::BoundReceiver;
                            evidence.dispatch_extensibility = Some(dispatch);
                        }
                        // The shared resolver proves absence only after a complete
                        // member search on a complete nominal receiver frontier.
                        // Multiple owners do not identify a unique Python receiver.
                        if let [owner] = answer.reference.absent_member_owners.as_slice()
                            && owner.source().declaration_language() == Language::Python
                        {
                            answer.reference.named_reasons.push((
                                "no_indexed_definition",
                                format!(
                                    "`{}.{}` is not indexed as a Python definition",
                                    owner.fq_name_str(),
                                    query.site.text,
                                ),
                            ));
                        }
                        // A lexical miss is distinct from a member search with
                        // an unknown receiver. Keep open and builtin answers intact.
                        if answer.reference.answer.binding().completion()
                            == &ResolutionCompletion::Complete
                            && answer.reference.answer.binding().targets().is_empty()
                            && !answer.reference.predeclared_symbol
                            && answer.selected_external_imports.is_empty()
                            && answer.reference.named_argument.is_none()
                            && answer.reference.named_reasons.is_empty()
                            && answer
                                .reference
                                .answer
                                .site_metadata()
                                .is_some_and(|metadata| {
                                    matches!(
                                        metadata.site_kind(),
                                        ResolutionSiteKind::ValueReference
                                            | ResolutionSiteKind::CallableReference
                                            | ResolutionSiteKind::TypeReference
                                    )
                                })
                        {
                            answer.reference.named_reasons.push((
                                "no_indexed_definition",
                                format!(
                                    "`{}` did not resolve to an indexed Python definition",
                                    query.site.text,
                                ),
                            ));
                        }
                        let mut selected_imports = answer.selected_external_imports;
                        let model_binding_complete = answer.reference.answer.binding().completion()
                            == &ResolutionCompletion::Complete;
                        // Descriptor application can be unknown while the selected member
                        // identity is exact. Preserve the reason and keep call binding open.
                        let descriptor_binding_unknown =
                            match answer.reference.answer.binding().completion() {
                                ResolutionCompletion::Incomplete(reasons) => {
                                    !answer.reference.named_reasons.is_empty()
                                        && reasons.iter().count()
                                            == answer.reference.named_reasons.len()
                                        && answer.reference.named_reasons.iter().all(|(name, _)| {
                                            *name == "python_model_descriptor_role_unknown"
                                        })
                                }
                                _ => false,
                            };
                        let models = answer.modeled_definitions;
                        for (target, key, declaration) in &models {
                            assert!(answer.reference.answer.binding().targets().contains(target));
                            assert_eq!(key.symbol_id, declaration.id);
                            assert_eq!(key.provider, (&declaration.provenance).into());
                        }
                        let mut outcome = adapt_definition_answer(
                            query.analyzer,
                            query.site,
                            Language::Python,
                            answer.reference,
                        );
                        // A loaded-library symbol has source-proven callable identity
                        // even when native member lookup has an open receiver frontier.
                        // Use the same proof as symbol aliases; it also rejects lexical
                        // shadowing of the library handle.
                        if outcome.status != DefinitionLookupStatus::Ambiguous
                            && outcome.definitions.is_empty()
                            && let Some(tree) = query.tree
                            && let Some(identity) = crate::analyzer::python::ctypes_loaded_symbol_identity(
                                &brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite {
                                    source: query.source,
                                    tree,
                                    callee_start_byte: query.site.focus_start_byte,
                                    file_evidence: &Default::default(),
                                },
                            )
                            && let Some(proof) = identity.exact_external_call
                        {
                            let mut reference = query.site.clone();
                            reference.text = proof.canonical_callee().to_owned();
                            outcome.reference = Some(reference);
                            evidence.call_application = proof.call_application();
                            evidence.dispatch_extensibility = proof.dispatch_extensibility();
                            evidence.external_callee_identity = identity.external_callee_identity;
                            evidence.exact_external_call = Some(proof);
                        }
                        if !models.is_empty() {
                            outcome.modeled_definitions = models
                                .into_iter()
                                .map(|(_, _, declaration)| std::sync::Arc::new(declaration))
                                .collect();
                            brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_modeled(&outcome);
                            if model_binding_complete || descriptor_binding_unknown {
                                outcome.status = if outcome.modeled_definitions.len() == 1 {
                                    DefinitionLookupStatus::Resolved
                                } else {
                                    DefinitionLookupStatus::Ambiguous
                                };
                            }
                            if let [symbol] = outcome.modeled_definitions.as_slice() {
                                let mut reference = query.site.clone();
                                reference.text = symbol.qualified_name.clone();
                                outcome.reference = Some(reference);
                            }
                            if descriptor_binding_unknown {
                                evidence.call_application = brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind::ReceiverBindingUnknown;
                            }
                            if let [symbol] = outcome.modeled_definitions.as_slice()
                                && model_binding_complete
                                && matches!(symbol.kind,
                                    brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Method
                                    | brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Function)
                                && symbol.has_complete_callable_shape_evidence()
                                && let Some((owner, member)) = brokk_bifrost_analysis::analyzer::semantic::split_canonical_qualified_callee(&symbol.qualified_name, Language::Python)
                                && let Some(count) = query.tree.and_then(|tree| crate::analyzer::python::external_authority::python_selected_callee_call(tree, query.site.focus_start_byte, query.site.focus_end_byte, || query.cancellation.is_none_or(|token| !token.is_cancelled()))).and_then(|(_, call)| call.child_by_field_name("arguments")).map(|arguments| u32::try_from(arguments.named_child_count()).expect("call arguments fit u32"))
                            {
                                use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;
                                let proof = if symbol.has_receiver() && !symbol.is_static {
                                    ExactExternalCallProof::python_bound_external_member(&owner, &member, count)
                                } else {
                                    ExactExternalCallProof::python_imported_call(symbol.qualified_name.clone(), count)
                                };
                                let mut reference = query.site.clone();
                                reference.text = symbol.qualified_name.clone();
                                outcome.reference = Some(reference);
                                evidence.call_application = proof.call_application();
                                evidence.dispatch_extensibility = proof.dispatch_extensibility();
                                evidence.external_callee_identity = Some(brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(Language::Python, owner, member));
                                evidence.exact_external_call = Some(proof);
                            }
                        }
                        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_lexical(&outcome);
                        if !outcome.modeled_definitions.is_empty()
                            && !outcome.modeled_definitions.iter().any(|symbol| symbol.kind == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Function)
                        {
                            // The native operation already admitted and selected this
                            // identity. A spelling-based import expansion cannot replace it.
                            return session.finish((outcome, evidence));
                        }

                        // Typed member routes retain value qualifiers rather than
                        // lexical root links. Select the static source root through
                        // the same native operation for definition projection only.
                        if selected_imports.is_empty()
                            && outcome.definitions.is_empty()
                            && outcome.lexical_definition.is_none()
                            && outcome.status != DefinitionLookupStatus::Ambiguous
                            && let Some((root, members)) = static_import_root(&query, &session)
                        {
                            match request.operation.python_definition_at(
                                &request.environment,
                                query.file,
                                root,
                                &session,
                            ) {
                                Ok(BoundedResolution::Complete {
                                    value:
                                        SelectedResolutionOperationOutcome::Native(
                                            SelectedResolutionLocated::Found(root),
                                        ),
                                    ..
                                }) => {
                                    selected_imports = root.selected_external_imports;
                                    for selected in &mut selected_imports {
                                        selected.remaining_member_path.extend_from_slice(&members);
                                    }
                                }
                                Ok(BoundedResolution::Complete { .. }) => {}
                                Ok(BoundedResolution::Exceeded { limit, work }) => {
                                    return BoundedResolution::Exceeded { limit, work };
                                }
                                Ok(BoundedResolution::Unavailable { reason, work }) => {
                                    return BoundedResolution::Unavailable { reason, work };
                                }
                                Ok(BoundedResolution::Cancelled { work }) => {
                                    return BoundedResolution::Cancelled { work };
                                }
                                Err(error) => {
                                    let message = error.to_string();
                                    self.python.record_query_failure(error);
                                    return session.finish((
                                        unavailable_definition(
                                            query.site,
                                            "native_store_error",
                                            message,
                                        ),
                                        CallEvidence::default(),
                                    ));
                                }
                            }
                        }
                        if outcome.definitions.is_empty()
                            && outcome.lexical_definition.is_none()
                            && outcome.status != DefinitionLookupStatus::Ambiguous
                            && let [selected] = selected_imports.as_slice()
                            && let Some(mut foreign) =
                                cross_language_import_definition(&query, selected, &session)
                        {
                            foreign.diagnostics.extend(outcome.diagnostics);
                            return session.finish((foreign, evidence));
                        }
                        let active = query.analyzer.active_semantic_model_snapshot();
                        let cancellation = query.cancellation.cloned().unwrap_or_default();
                        let parameter_count = query.tree.and_then(|tree| crate::analyzer::python::external_authority::python_imported_callee_shape(tree, query.site.focus_start_byte, query.site.focus_end_byte, || !cancellation.is_cancelled())).and_then(|(_, call)| call.child_by_field_name("arguments")).map(|arguments| u32::try_from(arguments.named_child_count()).expect("call arguments fit u32"));
                        if let Some(active) = active.as_ref().filter(|_| {
                            selected_imports
                                .iter()
                                .any(|selected| selected.boundary.relative_level == 0)
                        }) {
                            let mut authority = PythonExternalAuthority::new(
                                query.analyzer,
                                query.file,
                                active,
                                active.python_runtime(),
                                &cancellation,
                            )
                            .with_selected_snapshot(&request.snapshot);
                            let mut checked = Vec::new();
                            let mut ambiguous = selected_imports.len() > 1;
                            for selected in &selected_imports {
                                // A relative provider-open route proves only the
                                // missing-package-module boundary, never external identity.
                                if selected.boundary.relative_level != 0 {
                                    continue;
                                }
                                let mut path = selected
                                    .boundary
                                    .bound_name
                                    .iter()
                                    .cloned()
                                    .collect::<Vec<_>>();
                                path.extend_from_slice(&selected.remaining_member_path);
                                // Generic identity needs the unique unconditional reaching
                                // import, independently of its still-open provider rows.
                                if active.python_runtime().is_none() && !selected.identity_is_unique
                                {
                                    continue;
                                }
                                let admitted = authority.check(&selected.boundary, &path);
                                match admitted.as_ref() {
                                    PythonExternalAuthorityResult::Cancelled => {
                                        return BoundedResolution::Cancelled { work };
                                    }
                                    PythonExternalAuthorityResult::Checked(_) => {
                                        checked.push((selected, admitted))
                                    }
                                    PythonExternalAuthorityResult::Open(refusal) => {
                                        if outcome.status != DefinitionLookupStatus::Ambiguous {
                                            outcome.status = DefinitionLookupStatus::Incomplete;
                                            // Generic summaries can use the native imported call
                                            // shape. It carries no installed-artifact authority.
                                            if selected_imports.len() == 1
                                                && selected.identity_is_unique
                                                && outcome.definitions.is_empty()
                                                && outcome.lexical_definition.is_none()
                                                && let Some(count) = parameter_count
                                            {
                                                let canonical = crate::analyzer::python::external_authority::native::imported_spelling(&selected.boundary, &selected.remaining_member_path).join(".");
                                                let proof = brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof::python_imported_call(canonical.clone(), count);
                                                let mut reference = query.site.clone();
                                                reference.text = canonical;
                                                outcome.reference = Some(reference);
                                                evidence.call_application =
                                                    proof.call_application();
                                                evidence.dispatch_extensibility =
                                                    proof.dispatch_extensibility();
                                                evidence.exact_external_call = Some(proof);
                                            }
                                        }
                                        outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::native_points::project_named_definition_reason(refusal.kind.code(), refusal));
                                    }
                                    PythonExternalAuthorityResult::Stale(refusal) => {
                                        if outcome.status != DefinitionLookupStatus::Ambiguous {
                                            outcome.status = DefinitionLookupStatus::Incomplete;
                                        }
                                        outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::native_points::project_named_definition_reason(refusal.kind.code(), refusal));
                                    }
                                    PythonExternalAuthorityResult::Ambiguous(refusal) => {
                                        ambiguous = true;
                                        outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::native_points::project_named_definition_reason(refusal.kind.code(), refusal));
                                    }
                                }
                            }
                            if ambiguous {
                                outcome.status = DefinitionLookupStatus::Ambiguous;
                            } else if let [(selected, admitted)] = checked.as_slice() {
                                let PythonExternalAuthorityResult::Checked(identity) =
                                    admitted.as_ref()
                                else {
                                    unreachable!("only checked admission is retained");
                                };
                                // Admission identifies this selected imported binding; it never
                                // traverses owner/member inventory (the shared stage is #7857).
                                if outcome.definitions.is_empty()
                                    && outcome.lexical_definition.is_none()
                                    && selected.identity_is_unique
                                    && outcome.status != DefinitionLookupStatus::Ambiguous
                                {
                                    let mut reference = outcome
                                        .reference
                                        .take()
                                        .unwrap_or_else(|| query.site.clone());
                                    reference.text = identity.canonical().join(".");
                                    outcome.reference = Some(reference);
                                    match identity.kind() {
                                        PythonExternalIdentityKind::Callable => {
                                            outcome.status =
                                                DefinitionLookupStatus::UnresolvableImportBoundary;
                                            if let Some(count) = parameter_count {
                                                let proof = identity
                                                    .call_proof(count)
                                                    .expect("checked callable identity");
                                                evidence.call_application =
                                                    proof.call_application();
                                                evidence.dispatch_extensibility =
                                                    proof.dispatch_extensibility();
                                                let (member, owner) =
                                                    identity.canonical().split_last().expect(
                                                        "checked imported callable names a member",
                                                    );
                                                evidence.external_callee_identity = Some(
                                                    brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
                                                        Language::Python, owner.join("."), member.clone(),
                                                    ),
                                                );
                                                evidence.exact_external_call = Some(proof);
                                            }
                                        }
                                        PythonExternalIdentityKind::Class
                                        | PythonExternalIdentityKind::ModuleValue => match identity
                                            .model_symbol(query.analyzer)
                                        {
                                            Ok(symbol) => {
                                                outcome.modeled_definitions = vec![symbol];
                                                outcome.status = DefinitionLookupStatus::Resolved;
                                                brokk_bifrost_analysis::analyzer::usages::get_definition::trace::record_selected_modeled(&outcome);
                                            }
                                            Err(refusal) => {
                                                outcome.status = DefinitionLookupStatus::Incomplete;
                                                outcome.reference = Some(query.site.clone());
                                                outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::native_points::project_named_definition_reason(refusal.kind.code(), refusal));
                                            }
                                        },
                                    }
                                }
                            }
                            if cancellation.is_cancelled() {
                                return BoundedResolution::Cancelled { work };
                            }
                        } else if selected_imports
                            .iter()
                            .any(|selected| selected.boundary.relative_level == 0)
                        {
                            let refusal =
                                PythonExternalRefusal::unacquired(query.file, &request.snapshot);
                            if outcome.status != DefinitionLookupStatus::Ambiguous {
                                outcome.status = DefinitionLookupStatus::Incomplete;
                            }
                            outcome.diagnostics.push(brokk_bifrost_analysis::analyzer::native_points::project_named_definition_reason(refusal.kind.code(), refusal));
                        }
                        // The selected import proves an external boundary even when
                        // neither installed bytes nor a generic model identify its
                        // member. This does not close the native binding rows.
                        if outcome.status == DefinitionLookupStatus::Incomplete
                            && outcome.definitions.is_empty()
                            && outcome.lexical_definition.is_none()
                            && let [selected] = selected_imports.as_slice()
                            && selected.boundary_is_unique
                            && (selected.boundary.relative_level != 0 || active.as_ref().is_none_or(|active| active.python_runtime().is_none()))
                            // Annotations have separate source/model type admission;
                            // legacy never fell through to the value boundary here.
                            && query.tree.and_then(|tree| {
                                brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
                                    tree.root_node(), query.site.focus_start_byte, query.site.focus_end_byte,
                                    || session.scope_step(),
                                )
                            }).is_some_and(|node| !brokk_bifrost_python::syntax::python_node_is_in_annotation(node))
                        {
                            use crate::analyzer::python::lookup_helpers::python_workspace_module_exists;
                            use brokk_bifrost_analysis::analyzer::usages::get_definition::{
                                ClaimSubjectRole, UnindexedClaim, gated_boundary,
                            };
                            let python = resolve_analyzer::<PythonAnalyzer>(query.analyzer)
                                .expect("Python request has a Python analyzer");
                            let support =
                                brokk_bifrost_analysis::analyzer::AnalyzerDefinitionLookup::new(
                                    query.analyzer,
                                    Language::None,
                                );
                            let canonical = crate::analyzer::python::external_authority::native::imported_spelling(&selected.boundary, &selected.remaining_member_path);
                            let module = selected.boundary.route
                                [..selected.boundary.module_segment_count as usize]
                                .join(".");
                            let relative = selected.boundary.relative_level != 0;
                            let claimed_module = format!("{}{module}", ".".repeat(selected.boundary.relative_level as usize));
                            let boundary = gated_boundary(
                                || !relative && {
                                    python_workspace_module_exists(python, &support, &module)
                                        || python_workspace_module_exists(python, &support, &canonical.join("."))
                                        || python_workspace_module_exists(python, &support, &canonical[..canonical.len().saturating_sub(1)].join("."))
                                },
                                format!(
                                    "selected Python import crosses an unindexed boundary through `{claimed_module}`"
                                ),
                                UnindexedClaim::external_boundary(
                                    claimed_module,
                                    ClaimSubjectRole::Module,
                                ),
                                "no_indexed_definition",
                                "selected Python import has a workspace namespace",
                            );
                            if boundary.status == DefinitionLookupStatus::UnresolvableImportBoundary
                            {
                                outcome.status = boundary.status;
                                outcome.diagnostics.extend(boundary.diagnostics);
                                let mut reference = outcome
                                    .reference
                                    .take()
                                    .unwrap_or_else(|| query.site.clone());
                                if !relative {
                                    reference.text = canonical.join(".");
                                    if let Some(count) = parameter_count {
                                        let proof = brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof::python_imported_call(reference.text.clone(), count);
                                        evidence.call_application = proof.call_application();
                                        evidence.dispatch_extensibility = proof.dispatch_extensibility();
                                        evidence.exact_external_call = Some(proof);
                                    }
                                }
                                outcome.reference = Some(reference);
                            }
                        }
                        outcome
                    }
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing(_),
                    ) => {
                        let non_reference = query.tree.and_then(|tree| {
                            brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
                                tree.root_node(), query.site.focus_start_byte, query.site.focus_end_byte,
                                || session.scope_step(),
                            )
                        }).is_some_and(|node| !brokk_bifrost_python::syntax::python_node_can_be_reference(node));
                        if non_reference {
                            brokk_bifrost_analysis::analyzer::usages::get_definition::no_definition(
                                "python_non_reference_node",
                                "selected Python syntax is not a source reference",
                            )
                        } else {
                            unavailable_definition(
                                query.site,
                                "native_reference_unavailable",
                                "selected Python producer has no reference at this source range"
                                    .into(),
                            )
                        }
                    }
                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                        unavailable_definition(
                            query.site,
                            "native_unavailable",
                            format!("{reason:?}"),
                        )
                    }
                    SelectedResolutionOperationOutcome::Stale(reason) => {
                        unavailable_definition(query.site, "native_stale", format!("{reason:?}"))
                    }
                    SelectedResolutionOperationOutcome::Cancelled(_) => {
                        return BoundedResolution::Cancelled { work };
                    }
                };
                session.finish((outcome, evidence))
            }
            Ok(BoundedResolution::Exceeded { limit, work }) => {
                BoundedResolution::Exceeded { limit, work }
            }
            Ok(BoundedResolution::Unavailable { reason, work }) => {
                BoundedResolution::Unavailable { reason, work }
            }
            Ok(BoundedResolution::Cancelled { work }) => BoundedResolution::Cancelled { work },
            Err(error) => {
                let message = error.to_string();
                self.python.record_query_failure(error);
                session.finish((
                    unavailable_definition(query.site, "native_store_error", message),
                    CallEvidence::default(),
                ))
            }
        }
    }
}

/// Recover the static qualifier syntax, then let native lexical selection
/// prove the root import. This never infers an import from source spelling.
fn static_import_root(
    query: &BoundedReceiverQuery<'_>,
    session: &ResolutionSession,
) -> Option<(std::ops::Range<usize>, Vec<String>)> {
    let tree = query.tree?;
    let mut node = brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        tree.root_node(), query.site.focus_start_byte, query.site.focus_end_byte,
        || session.scope_step(),
    )?;
    if let Some(parent) = node.parent()
        && parent.kind() == "attribute"
        && parent.child_by_field_name("attribute") == Some(node)
    {
        node = parent;
    }
    let path = brokk_bifrost_python::syntax::python_static_value_path_bounded(node, || {
        session.scope_step()
    })??;
    let [root, members @ ..] = path.as_slice() else {
        return None;
    };
    if members.is_empty() {
        return None;
    }
    Some((
        root.byte_range(),
        members
            .iter()
            .map(|member| query.source[member.byte_range()].to_owned())
            .collect(),
    ))
}

/// Workspace foreign declarations are a projection of the selected import,
/// never a search for another declaration sharing its simple name.
fn cross_language_import_definition(
    query: &BoundedReceiverQuery<'_>,
    selected: &brokk_bifrost_analysis::analyzer::store::resolution_operation::PythonSelectedExternalImport,
    session: &ResolutionSession,
) -> Option<DefinitionLookupOutcome> {
    use brokk_bifrost_analysis::analyzer::AnalyzerDefinitionLookup;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        ambiguous_without_candidates, candidates_outcome, cross_language_declarations,
        no_definition,
    };
    use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;
    if selected.boundary.relative_level != 0 || !selected.identity_is_unique {
        return None;
    }
    let canonical = crate::analyzer::python::external_authority::native::imported_spelling(
        &selected.boundary,
        &selected.remaining_member_path,
    );
    let foreign_languages = query
        .analyzer
        .languages()
        .into_iter()
        .filter(|language| *language != Language::Python)
        .collect::<Vec<_>>();
    if foreign_languages.is_empty() {
        return None;
    }
    let support = AnalyzerDefinitionLookup::new(query.analyzer, Language::None);
    let mut namespace = false;
    for end in (1..=canonical.len()).rev() {
        let name = canonical[..end].join(".");
        let units =
            session.query(|| cross_language_declarations(&support, &name, Language::Python))?;
        if units.is_empty() {
            // Foreign namespace prefixes are workspace authority too, even
            // when a particular member is absent from that namespace.
            namespace |= session.query(|| {
                foreign_languages
                    .iter()
                    .any(|language| support.package_exists_in_language(&name, *language))
            })?;
            continue;
        }
        let mut outcome = candidates_outcome(units);
        for member in &canonical[end..] {
            let [owner] = outcome.definitions.as_slice() else {
                // No candidates: competing foreign owners do not identify the
                // requested downstream member. Do not return an owner as it.
                return Some(ambiguous_without_candidates(format!(
                    "the exact foreign owners do not identify downstream member {member:?}: {:?}",
                    outcome.definitions
                )));
            };
            outcome = session.query(|| {
                crate::analyzer::python::lookup_helpers::python_member_outcome(
                    query.analyzer,
                    &support,
                    owner.clone(),
                    member,
                    query.site,
                )
            })?;
            if outcome.status == DefinitionLookupStatus::NoDefinition {
                return Some(outcome);
            }
        }
        let mut reference = query.site.clone();
        reference.text = canonical.join(".");
        outcome.reference = Some(reference);
        return Some(outcome);
    }
    namespace.then(|| {
        no_definition(
            "no_indexed_definition",
            format!(
                "`{}` names an indexed workspace namespace but no declaration",
                canonical.join(".")
            ),
        )
    })
}

impl PythonReceiverRequest<'_> {
    pub(crate) fn resolve_definition_bounded(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        match self.resolve_definition_with_call_evidence_bounded(query) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: value.0,
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Unavailable { reason, work } => {
                BoundedResolution::Unavailable { reason, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }
}

pub(crate) fn resolve_definition_with_call_evidence_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<(DefinitionLookupOutcome, CallEvidence)> {
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(query.analyzer) else {
        return ResolutionSession::bounded(query.budget, query.cancellation).finish((
            unavailable_definition(
                query.site,
                "python_analyzer_unavailable",
                "Python analyzer unavailable".into(),
            ),
            CallEvidence::default(),
        ));
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    PythonReceiverRequest::open(python, &cancellation)
        .resolve_definition_with_call_evidence_bounded(query)
}

pub(crate) fn resolve_type_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<TypeLookupOutcome> {
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(query.analyzer) else {
        return ResolutionSession::bounded(query.budget, query.cancellation).finish(
            unavailable_type(
                query.site,
                "python_analyzer_unavailable",
                "Python analyzer unavailable".into(),
            ),
        );
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    PythonReceiverRequest::open(python, &cancellation).resolve_type_bounded(query)
}

impl brokk_bifrost_analysis::analyzer::languages::ReceiverRequest for PythonReceiverRequest<'_> {
    fn resolve_type(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
        brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome,
    > {
        self.resolve_type_bounded(query)
    }

    fn resolve_definition(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome,
    > {
        self.resolve_definition_bounded(query)
    }
}

pub(crate) fn resolve_definition_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(query.analyzer) else {
        return ResolutionSession::bounded(query.budget, query.cancellation).finish(
            unavailable_definition(
                query.site,
                "python_analyzer_unavailable",
                "Python analyzer unavailable".into(),
            ),
        );
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    PythonReceiverRequest::open(python, &cancellation).resolve_definition_bounded(query)
}

/// The same point admission for Python hooks that start from a source range.
pub(crate) fn definition_at_range_with_request(
    retained: &mut PythonReceiverRequest<'_>,
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    file: &brokk_bifrost_core::analyzer::ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    range: std::ops::Range<usize>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> Result<Option<(DefinitionLookupOutcome, CallEvidence)>, DerivationExecutionCause> {
    let _scope = cancellation.map_or_else(
        || brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(analyzer),
        |cancellation| {
            brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_cancellation(
                analyzer,
                cancellation,
            )
        },
    );
    let Some(node) = tree
        .root_node()
        .named_descendant_for_byte_range(range.start, range.end)
    else {
        return Ok(None);
    };
    let expression = if node.kind() == "call" {
        match node.child_by_field_name("function") {
            Some(function) => function,
            None => return Ok(None),
        }
    } else {
        node
    };
    let focus = if expression.kind() == "attribute" {
        match expression.child_by_field_name("attribute") {
            Some(attribute) => attribute,
            None => return Ok(None),
        }
    } else {
        expression
    };
    let site = brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
        path: brokk_bifrost_core::path_utils::rel_path_string(file),
        text: match node.utf8_text(source.as_bytes()) {
            Ok(text) => text.to_owned(),
            Err(_) => return Ok(None),
        },
        range: brokk_bifrost_core::analyzer::Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        },
        focus_start_byte: focus.start_byte(),
        focus_end_byte: focus.end_byte(),
    };
    match retained.resolve_definition_with_call_evidence_bounded(BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree: Some(tree),
        site: &site,
        budget:
            brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation,
    }) {
        BoundedResolution::Complete { value, .. } => Ok(Some(value)),
        BoundedResolution::Exceeded { .. } => Err(DerivationExecutionCause::Budget),
        BoundedResolution::Unavailable { .. } => Err(DerivationExecutionCause::Provider),
        BoundedResolution::Cancelled { .. } => Err(DerivationExecutionCause::Cancelled),
    }
}

#[cfg(test)]
mod native_type_reader_tests {
    use super::*;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn python_published_call_and_attribute_value_slots_reach_shared_reader() {
        let source = "class Widget:\n    pass\n\nclass Holder:\n    value: Widget\n    def make(self) -> Widget:\n        return Widget()\n\ndef build() -> Widget:\n    return Widget()\n\nholder = Holder()\nleft = Holder().make()\nx = build()\nright = holder.value\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("sample.py", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let file = ProjectFile::new(fixture.project_root(), "sample.py");
        let tree = crate::analyzer::usages::get_definition::python::parse_python_tree(source)
            .expect("Python tree");
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        python
            .prepare_native_environment_for_test(&cancellation)
            .expect("native fixture");
        let mut request = PythonReceiverRequest::open(python, &cancellation);
        assert!(
            matches!(request.native(analyzer), PythonNativeOpen::Ready(_)),
            "Python native request did not open"
        );
        for (expression, expected_slot, expected_widget_type) in [
            ("Holder().make()", true, true),
            ("Holder().make", false, false),
            ("build()", true, true),
            ("build", false, false),
            ("holder.value", false, true),
        ] {
            let start = source.rfind(expression).expect("expression");
            let end = start + expression.len();
            let site = ResolvedReferenceSite {
                path: "sample.py".into(),
                text: expression.into(),
                range: brokk_bifrost_core::analyzer::Range {
                    start_byte: start,
                    end_byte: end,
                    start_line: 1,
                    end_line: 1,
                },
                focus_start_byte: start,
                focus_end_byte: end,
            };
            let result = request
                .resolve_native_type_at(BoundedReceiverQuery {
                    analyzer,
                    file: &file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                    cancellation: Some(&cancellation),
                })
                .expect("store read")
                .expect("native request");
            let answer = match result {
                BoundedResolution::Complete {
                    value:
                        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                            answer,
                        )),
                    ..
                } => answer,
                BoundedResolution::Complete {
                    value:
                        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing(
                            _,
                        )),
                    ..
                } => panic!("native value missing for {expression}: missing"),
                BoundedResolution::Complete { .. } => {
                    panic!("native value missing for {expression}: other outcome")
                }
                BoundedResolution::Exceeded { .. } => {
                    panic!("native value missing for {expression}: budget")
                }
                BoundedResolution::Unavailable { reason, .. } => {
                    panic!("native value missing for {expression}: unavailable input {reason}")
                }
                BoundedResolution::Cancelled { .. } => {
                    panic!("native value missing for {expression}: cancelled")
                }
            };
            assert_eq!(
                answer.query_result_slot.is_some(),
                expected_slot,
                "{expression} selected the wrong result slot"
            );
            // The producer's callee-to-result projection owns callee reference types.
            if !expected_widget_type {
                continue;
            }
            let brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes::Ready { nominal, .. } = answer.value_types else {
                panic!("native type unavailable for {expression}");
            };
            assert!(nominal.iter().any(|(_, definition)| matches!(definition,
                brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinition::Unit(unit)
                    if unit.fq_name().to_string().ends_with("Widget")
            )), "{expression} did not resolve Widget");
        }
    }

    fn site_at(source: &str, expression: &str) -> ResolvedReferenceSite {
        let start = source.rfind(expression).expect("expression");
        let end = start + expression.len();
        ResolvedReferenceSite {
            path: "sample.py".into(),
            text: expression.into(),
            range: brokk_bifrost_core::analyzer::Range {
                start_byte: start,
                end_byte: end,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: end,
        }
    }

    #[test]
    #[hardwon(
        "#5658: the legacy fallback of a provider-open type answer ran while the request held the writer-only store mutex"
    )]
    fn provider_open_type_fallback_on_pooled_store() {
        // This regression now runs on the pooled store.
        // The lookup runs on its own thread, so a regression fails by timeout
        // instead of hanging the suite.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let source = "from missing_provider import direct\n\ndef probe():\n    direct()\n";
            let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
                .file("sample.py", source)
                .build();
            let project = fixture.project_dyn();
            let store =
                brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context(
                    project.as_ref(),
                )
                .expect("pooled store");
            let python = PythonAnalyzer::new_with_config_store_context(
                project,
                Default::default(),
                store,
                None,
            )
            .expect("Python analyzer");
            let analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer = &python;
            let file = fixture.file("sample.py");
            let tree = crate::analyzer::usages::get_definition::python::parse_python_tree(source)
                .expect("Python tree");
            let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
            python
                .prepare_native_environment_for_test(&cancellation)
                .expect("native fixture");
            let mut request = PythonReceiverRequest::open(&python, &cancellation);
            let site = site_at(source, "direct()");
            let native = request.resolve_native_type_bounded(BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: Some(&cancellation),
            });
            let BoundedResolution::Complete { value, .. } = native else {
                panic!("native answer did not complete");
            };
            assert!(
                value
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.kind == "python_provider_open"),
                "the fixture must reach the legacy fallback: {value:?}"
            );
            let _ = request.resolve_type_bounded(BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: Some(&cancellation),
            });
            sender.send(()).expect("test is waiting");
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the legacy fallback completed through the pooled store");
    }

    #[test]
    fn receiver_service_reopens_after_fallback() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use brokk_bifrost_analysis::analyzer::usages::receiver_query::{
                ReceiverQueryInput, ReceiverQueryOperation, ReceiverQueryService,
            };
            let source = "from .missing_provider import direct\nclass Widget:\n    pass\ndirect()\nWidget()\n";
            let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
                .file("sample.py", source)
                .build();
            let project = fixture.project_dyn();
            let store =
                brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context(
                    project.as_ref(),
                )
                .expect("pooled store");
            let workspace = brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer::build_with_store_context_for_test(
                project, Default::default(), store,
            ).expect("pooled workspace");
            let python =
                resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).expect("Python analyzer");
            let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
            python
                .prepare_native_environment_for_test(&cancellation)
                .expect("native fixture");
            let service = ReceiverQueryService::from_workspace(&workspace);
            let file = fixture.file("sample.py");
            let facts = workspace
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .find(|provider| provider.structural_language() == Language::Python)
                .and_then(|provider| provider.structural_facts(&file))
                .expect("Python structural facts");
            for expression in ["direct()", "Widget()"] {
                let site = site_at(source, expression);
                let report = service
                    .analyze_with_structural_facts(
                        ReceiverQueryOperation::ReceiverTargets,
                        &file,
                        site.range,
                        ReceiverQueryInput::Expression,
                        &facts,
                        INTERACTIVE_TYPE_LOOKUP_BUDGET,
                        Some(&cancellation),
                    )
                    .expect("receiver report");
                if expression == "Widget()" {
                    let rendered = format!("{:?}", report.analysis);
                    assert!(!rendered.contains("native_request_released"), "{rendered}");
                    assert!(rendered.contains("Widget"), "{rendered}");
                }
            }
            sender.send(()).expect("test is waiting");
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("receiver lookup deadlocked or failed");
    }

    #[test]
    #[hardwon(
        "#5658: the class fast path read the selected reference before checking that the supplied source was the selected source"
    )]
    fn class_fast_path_refuses_source_that_differs_at_the_same_range() {
        let selected = "class Widget:\n    pass\n\nclass Gadget:\n    pass\n\nvalue = Widget\n";
        let unsaved = "class Widget:\n    pass\n\nclass Gadget:\n    pass\n\nvalue = Gadget\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("sample.py", selected)]);
        let analyzer = fixture.analyzer.analyzer();
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let file = ProjectFile::new(fixture.project_root(), "sample.py");
        let tree = crate::analyzer::usages::get_definition::python::parse_python_tree(unsaved)
            .expect("Python tree");
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        python
            .prepare_native_environment_for_test(&cancellation)
            .expect("native fixture");
        let mut request = PythonReceiverRequest::open(python, &cancellation);
        let site = site_at(unsaved, "Gadget");
        assert_eq!(
            site.focus_start_byte,
            selected.rfind("Widget").expect("selected reference")
        );
        let BoundedResolution::Complete { value, .. } =
            request.resolve_type_bounded(BoundedReceiverQuery {
                analyzer,
                file: &file,
                source: unsaved,
                tree: Some(&tree),
                site: &site,
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: Some(&cancellation),
            })
        else {
            panic!("lookup did not complete");
        };
        assert!(value.types.is_empty(), "stale source answered: {value:?}");
        assert!(
            value
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "native_source_mismatch"),
            "{value:?}"
        );
    }

    #[hardwon(
        "c24837579cb4: a Python callee type query met the synthetic callee-value site and failed"
    )]
    #[test]
    fn python_callee_type_query_selects_the_user_addressable_reference() {
        let source = "class Holder:\n    def load(self, other):\n        self.__dict__.update(other)\n\ndef read(obj):\n    return getattr(obj, \"name\")\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("sample.py", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let file = ProjectFile::new(fixture.project_root(), "sample.py");
        let tree = crate::analyzer::usages::get_definition::python::parse_python_tree(source)
            .expect("Python tree");
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        python
            .prepare_native_environment_for_test(&cancellation)
            .expect("native fixture");
        let mut request = PythonReceiverRequest::open(python, &cancellation);
        assert!(
            matches!(request.native(analyzer), PythonNativeOpen::Ready(_)),
            "Python native request did not open"
        );
        // Each callee name is a call's `function`; the producer publishes a
        // call reference and a synthetic callee-value read at that range.
        let mut failures = Vec::new();
        for callee in ["getattr", "update"] {
            let start = source.rfind(callee).expect("callee");
            let end = start + callee.len();
            let site = ResolvedReferenceSite {
                path: "sample.py".into(),
                text: callee.into(),
                range: brokk_bifrost_core::analyzer::Range {
                    start_byte: start,
                    end_byte: end,
                    start_line: 1,
                    end_line: 1,
                },
                focus_start_byte: start,
                focus_end_byte: end,
            };
            match request.resolve_native_type_at(BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation: Some(&cancellation),
            }) {
                Err(error) => failures.push(format!("store error at callee {callee}: {error:?}")),
                Ok(None) => failures.push(format!("no native request for callee {callee}")),
                Ok(Some(BoundedResolution::Unavailable { reason, .. })) => {
                    failures.push(format!("callee {callee} was unavailable: {reason}"))
                }
                Ok(Some(_)) => {}
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}

#[cfg(test)]
mod definition_answer_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::outer_request::{OuterRequest, RequestEntryKey};
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

    /// The owner's state is one outer request: its answers are the memo.
    #[test]
    fn request_definition_answer_memo_completion_conformance() {
        use brokk_bifrost_analysis::analyzer::usages::common::{
            QueryMemoOwner, assert_memo_owner_conformance_for_test,
        };
        let source =
            "from service import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                ("app.py", source),
            ],
        );
        let analyzer = fixture.analyzer.analyzer();
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let tree = crate::analyzer::usages::get_definition::python::parse_python_tree(source)
            .expect("Python tree");
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        python
            .prepare_native_environment_for_test(&cancellation)
            .expect("native fixture");
        let start = source.rfind("run").expect("call");
        let site = ResolvedReferenceSite {
            path: "app.py".into(),
            text: "run".into(),
            range: brokk_bifrost_core::analyzer::Range {
                start_byte: start,
                end_byte: start + 3,
                start_line: 4,
                end_line: 4,
            },
            focus_start_byte: start,
            focus_end_byte: start + 3,
        };
        assert_memo_owner_conformance_for_test(
            QueryMemoOwner::PythonDefinitionAnswer,
            analyzer,
            OuterRequest::new,
            |request| {
                let _scope = AnalyzerQueryScope::with_outer_request(
                    analyzer,
                    std::sync::Arc::clone(request),
                );
                match PythonReceiverRequest::open(python, &cancellation)
                    .resolve_definition_with_call_evidence_bounded(BoundedReceiverQuery {
                        analyzer,
                        file: &file,
                        source,
                        tree: Some(&tree),
                        site: &site,
                        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                        cancellation: Some(&cancellation),
                    }) {
                    BoundedResolution::Complete { value, work } => {
                        format!("{:?} {:?} {work:?}", value.0.definitions, value.0.status)
                    }
                    other => panic!("complete definition answer: {:?}", other.work()),
                }
            },
            |request| {
                request
                    .resource_if_present::<PythonDefinitionAnswers>(
                        &RequestEntryKey::PythonDefinitionAnswers,
                    )
                    .is_some_and(|answers| answers.retained() > 0)
            },
        );
    }
}
