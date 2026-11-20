//! Query-private, demanded site projection. Raw file facts never leave a window.

use super::*;
use brokk_bifrost_core::admitted_text::AdmittedText;
use brokk_bifrost_core::allocation_size::allocation_size;
use brokk_bifrost_core::retention_budget::{
    ENTRY_OVERHEAD_BYTES, RetentionBudget, SharedBackingLease,
};
use brokk_bifrost_tools::program_point_selection::node_site_value_ref;
use brokk_bifrost_tools::site_context::{
    self, SiteAdmission, SiteAdmissionRefusal, SiteRoleRef, SiteRoleView, SiteValueRef,
    SiteValueView, UnknownValueCauseRef,
};

pub(super) type PresentationRefusal = SiteAdmissionRefusal;

/// Source validity failures are semantic, not optional output admission.
#[derive(Debug)]
pub(super) enum PreparationError {
    Admission(PresentationRefusal),
    Snapshot(ProjectFile),
    Cancelled,
    /// Source hydration already reported its real execution-budget refusal.
    SourceBudget(ProjectFile),
    ProviderBudget {
        file: ProjectFile,
        minimum_fact_nodes: usize,
    },
}

impl From<PresentationRefusal> for PreparationError {
    fn from(refusal: PresentationRefusal) -> Self {
        Self::Admission(refusal)
    }
}

pub(super) struct SiteProjection {
    pub path: AdmittedText,
    pub role: SiteRoleView,
    pub value: SiteValueView,
}

pub(super) struct PresentationWindow {
    owner: Option<RetentionBudget>,
    slots: Vec<Option<Result<SiteProjection, PresentationRefusal>>>,
    next: usize,
    pub source_refused: bool,
    _slots_lease: Option<SharedBackingLease>,
}

#[derive(Clone, Copy)]
enum NodeSelection {
    Span,
    Recorded(Option<u32>),
}

struct Demand<'a> {
    ordinal: usize,
    file: &'a ProjectFile,
    range: Range,
    role: SiteRoleRef<'a>,
    node: NodeSelection,
    facts: Option<&'a FileFacts>,
    matched: Option<u32>,
    // Hash of decoded bytes, never compared with an indexed raw blob OID.
    observed_source: Option<git2::Oid>,
}

// References only: native rows retain the already-accounted facts backing.
// Ordinal preserves the old first-held-trace selection within a file.
struct HeldTraceFacts<'a> {
    file: &'a ProjectFile,
    facts: &'a FileFacts,
    ordinal: usize,
}

fn argument_role(position: Option<usize>, name: Option<&str>) -> SiteRoleRef<'_> {
    position.map_or(SiteRoleRef::Value, |index| SiteRoleRef::Argument {
        index,
        name,
    })
}

fn demands<'a>(row: &'a PipelineRow, mut visit: impl FnMut(Demand<'a>)) {
    let mut push = |file, range, role, node, facts| {
        visit(Demand {
            ordinal: 0,
            file,
            range,
            role,
            node,
            facts,
            matched: None,
            observed_source: None,
        })
    };
    match &row.value {
        PipelineValue::CallSite(site) => {
            if let Some(range) = site.0.receiver {
                push(
                    &site.0.file,
                    range,
                    SiteRoleRef::Receiver,
                    NodeSelection::Span,
                    None,
                );
            }
            for argument in &site.0.arguments {
                push(
                    &site.0.file,
                    argument.range,
                    argument_role(argument.written_position, argument.name.as_deref()),
                    NodeSelection::Span,
                    None,
                );
            }
        }
        PipelineValue::ExpressionSite(site) => {
            let role = match &site.input {
                ExpressionInput::Receiver => SiteRoleRef::Receiver,
                ExpressionInput::Parameter {
                    actual_written_position,
                    actual_name,
                    ..
                } => argument_role(*actual_written_position, actual_name.as_deref()),
            };
            push(
                &site.call_site.0.file,
                site.range,
                role,
                NodeSelection::Span,
                None,
            );
        }
        PipelineValue::CallArgument(value) => {
            let argument = &value.shape.report.arguments[value.argument_index];
            push(
                &value.shape.report.outcome.file,
                argument.range,
                argument_role(argument.position, argument.name.as_deref()),
                NodeSelection::Recorded(argument.node),
                value.shape.facts.as_deref(),
            );
        }
        PipelineValue::CallBinding(value) => {
            let row = value.row();
            if let Some(id) = &row.argument_id {
                let argument = value
                    .site
                    .shape
                    .report
                    .arguments
                    .iter()
                    .find(|argument| &argument.id == id)
                    .expect("a binding names an argument of its own shape");
                push(
                    &value.site.report.file,
                    argument.range,
                    argument_role(argument.position, argument.name.as_deref()),
                    NodeSelection::Recorded(argument.node),
                    value.site.shape.facts.as_deref(),
                );
            } else if row.binding_kind
                == Some(crate::analyzer::usages::call_binding::CallBindingKind::Receiver)
                && !row.terminal
            {
                push(
                    &value.site.report.file,
                    row.range,
                    SiteRoleRef::Receiver,
                    NodeSelection::Span,
                    None,
                );
            }
        }
        _ => {}
    }
}

fn admit_vec<T>(
    owner: Option<&RetentionBudget>,
    count: usize,
) -> Result<Option<SharedBackingLease>, PresentationRefusal> {
    if count == 0 {
        return Ok(None);
    }
    let owner = owner.ok_or(PresentationRefusal::OwnerUnavailable)?;
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .map(allocation_size)
        .and_then(|bytes| bytes.checked_add(ENTRY_OVERHEAD_BYTES))
        .ok_or(PresentationRefusal::RetainedBytes)?;
    owner
        .shared_backing(u64::try_from(bytes).map_err(|_| PresentationRefusal::RetainedBytes)?)
        .map(Some)
        .ok_or(PresentationRefusal::RetainedBytes)
}

pub(super) struct PreparePresentationSources;

impl NativeSourcePreparation for PreparePresentationSources {
    type Output = Result<PresentationWindow, PreparationError>;

    fn prepare(
        self,
        analyzer: &dyn IAnalyzer,
        rows: &[PipelineRow],
        owner: Option<RetentionBudget>,
        cancellation: Option<&CancellationToken>,
        prepare: impl FnOnce(&mut dyn FnMut(&ProjectFile, &str)) -> NativeRowMetadata,
    ) -> (NativeRowMetadata, Self::Output) {
        let mut builder = PresentationWindowBuilder::new(rows, owner);
        let metadata = prepare(&mut |file, source| {
            if let Ok(window) = &mut builder
                && let Err(error) =
                    window.observe_selected_source(analyzer, file, source, cancellation)
            {
                builder = Err(error);
            }
        });
        // Even an admission failure must leave ordinary source/evidence work
        // and its receipt intact. No failed window can publish a positive row.
        let window = builder
            .and_then(|builder| builder.finish(analyzer, &metadata.render_cache, cancellation));
        (metadata, window)
    }
}

pub(super) struct PresentationWindowBuilder<'a> {
    requested: Vec<Demand<'a>>,
    trace_facts: Vec<HeldTraceFacts<'a>>,
    window: PresentationWindow,
    _demands_lease: Option<SharedBackingLease>,
    _traces_lease: Option<SharedBackingLease>,
}

impl<'a> PresentationWindowBuilder<'a> {
    pub fn new(
        rows: &'a [PipelineRow],
        owner: Option<RetentionBudget>,
    ) -> Result<Self, PreparationError> {
        let mut count = 0usize;
        for row in rows {
            #[cfg(test)]
            super::admission_acceptance::observe_candidate_row();
            demands(row, |_| {
                count = count.checked_add(1).expect("site demand count fits usize")
            });
        }
        let demands_lease = admit_vec::<Demand<'_>>(owner.as_ref(), count)?;
        let mut requested = Vec::with_capacity(count);
        for row in rows {
            #[cfg(test)]
            super::admission_acceptance::observe_candidate_row();
            demands(row, |mut demand| {
                demand.ordinal = requested.len();
                requested.push(demand);
            });
        }
        let slots_lease = admit_vec::<Option<Result<SiteProjection, PresentationRefusal>>>(
            owner.as_ref(),
            count,
        )?;
        let mut slots = Vec::with_capacity(count);
        slots.resize_with(count, || None);
        // Unstable sorting needs no temporary heap allocation. Ordinal makes
        // duplicate demands totally ordered and restores authored output order.
        requested.sort_unstable_by(|a, b| {
            (a.file, a.range.start_byte, a.range.end_byte, a.ordinal).cmp(&(
                b.file,
                b.range.start_byte,
                b.range.end_byte,
                b.ordinal,
            ))
        });
        // Count and fill borrowed trace references in two global passes. Only
        // demanded files enter the vector; reserve its concrete storage before
        // allocation. No facts backing is cloned or charged a second time.
        let demanded = |file: &ProjectFile| {
            requested
                .binary_search_by(|demand| demand.file.cmp(file))
                .is_ok()
        };
        let mut trace_count = 0usize;
        for row in rows {
            #[cfg(test)]
            super::admission_acceptance::observe_candidate_row();
            for trace in &row.traces {
                #[cfg(test)]
                super::admission_acceptance::observe_candidate_trace();
                if demanded(&trace.seed.file) {
                    trace_count = trace_count.checked_add(1).expect("trace count fits usize");
                }
            }
        }
        let traces_lease = admit_vec::<HeldTraceFacts<'_>>(owner.as_ref(), trace_count)?;
        let mut trace_facts = Vec::with_capacity(trace_count);
        for row in rows {
            #[cfg(test)]
            super::admission_acceptance::observe_candidate_row();
            for trace in &row.traces {
                #[cfg(test)]
                super::admission_acceptance::observe_candidate_trace();
                if demanded(&trace.seed.file) {
                    trace_facts.push(HeldTraceFacts {
                        file: &trace.seed.file,
                        facts: trace.seed.facts.as_ref(),
                        ordinal: trace_facts.len(),
                    });
                }
            }
        }
        trace_facts.sort_unstable_by(|a, b| (a.file, a.ordinal).cmp(&(b.file, b.ordinal)));
        Ok(Self {
            requested,
            trace_facts,
            window: PresentationWindow {
                owner,
                slots,
                next: 0,
                source_refused: false,
                _slots_lease: slots_lease,
            },
            _demands_lease: demands_lease,
            _traces_lease: traces_lease,
        })
    }

    /// Observe only bytes already obtained by the ordinary source preparation.
    /// A rejected render-text grant still leaves this exact borrow alive.
    pub fn observe_selected_source(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), PreparationError> {
        self.project_file(analyzer, file, Some(source), cancellation)
    }

    fn project_file(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: Option<&str>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), PreparationError> {
        let start = self.requested.partition_point(|demand| demand.file < file);
        let end = start + self.requested[start..].partition_point(|demand| demand.file == file);
        if start == end {
            return Ok(());
        }
        let window = &mut self.requested[start..end];
        let observed_source = source.map(|source| {
            git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                .expect("hash selected decoded source")
        });
        if self.window.slots[window[0].ordinal].is_some() {
            if observed_source.is_some() && observed_source != window[0].observed_source {
                return Err(PreparationError::Snapshot(file.clone()));
            }
            return Ok(());
        }
        #[cfg(test)]
        let _observed_window = super::admission_acceptance::observe_file_window(file);
        let trace_start = self.trace_facts.partition_point(|trace| trace.file < file);
        let trace_end = trace_start
            + self.trace_facts[trace_start..].partition_point(|trace| trace.file == file);
        let held = window.iter().filter_map(|demand| demand.facts).chain(
            self.trace_facts[trace_start..trace_end]
                .iter()
                .map(|trace| trace.facts),
        );
        let provided = held.clone().next();
        let selected_source = source.or_else(|| provided.map(FileFacts::source));
        for facts in held {
            #[cfg(test)]
            super::admission_acceptance::observe_held_fact();
            if selected_source.is_some_and(|source| facts.source() != source) {
                return Err(PreparationError::Snapshot(file.clone()));
            }
        }
        window[0].observed_source = selected_source.map(|source| {
            git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                .expect("hash selected decoded source")
        });
        let acquired = if provided.is_none()
            && window
                .iter()
                .any(|demand| !matches!(demand.node, NodeSelection::Recorded(None)))
            && let Some(source) = source
        {
            let language = crate::analyzer::common::language_for_file(file);
            match analyzer
                .structural_fact_providers()
                .into_iter()
                .find(|provider| provider.structural_language() == language)
                .map(|provider| {
                    provider.structural_facts_limited(file, source, usize::MAX, cancellation)
                }) {
                Some(StructuralFactsLimitedOutcome::Available { facts, .. }) => Some(facts),
                Some(StructuralFactsLimitedOutcome::Exceeded { minimum_fact_nodes }) => {
                    return Err(PreparationError::ProviderBudget {
                        file: file.clone(),
                        minimum_fact_nodes,
                    });
                }
                Some(StructuralFactsLimitedOutcome::Cancelled) => {
                    return Err(PreparationError::Cancelled);
                }
                Some(StructuralFactsLimitedOutcome::Unavailable) | None => None,
            }
        } else {
            None
        };
        #[cfg(test)]
        super::admission_acceptance::observe_acquired(file, acquired.as_ref());
        let facts = provided.or(acquired.as_deref());
        if let Some(facts) = facts {
            if source.is_some_and(|source| facts.source() != source) {
                return Err(PreparationError::Snapshot(file.clone()));
            }
            // Keep only demanded spans; repeated equal spans choose the
            // last arena node, the existing innermost-node convention.
            if window
                .iter()
                .any(|demand| matches!(demand.node, NodeSelection::Span))
            {
                for (node_id, node) in facts.nodes().iter().enumerate() {
                    let span = node.span();
                    let key = (span.start_byte, span.end_byte);
                    let first = window.partition_point(|demand| {
                        (demand.range.start_byte, demand.range.end_byte) < key
                    });
                    for demand in window[first..].iter_mut().take_while(|demand| {
                        (demand.range.start_byte, demand.range.end_byte) == key
                    }) {
                        if matches!(demand.node, NodeSelection::Span) {
                            demand.matched = Some(node_id as u32);
                        }
                    }
                }
            }
        }
        let admission = SiteAdmission::new(self.window.owner.as_ref());
        let path = admission.path(file);
        for demand in window.iter() {
            let value = match demand.node {
                NodeSelection::Recorded(None) => {
                    SiteValueRef::Unknown(UnknownValueCauseRef::NotConstant)
                }
                _ => match facts {
                    Some(facts) => match demand.node {
                        NodeSelection::Recorded(Some(node)) => {
                            node_site_value_ref(facts.node(node))
                        }
                        NodeSelection::Span => demand.matched.map_or(
                            SiteValueRef::Unknown(UnknownValueCauseRef::NotConstant),
                            |node| node_site_value_ref(facts.node(node)),
                        ),
                        NodeSelection::Recorded(None) => unreachable!(),
                    },
                    None => SiteValueRef::Unknown(UnknownValueCauseRef::NotAnalyzed(
                        &site_context::NotAnalyzedCause::Unknown,
                    )),
                },
            };
            self.window.slots[demand.ordinal] = Some((|| {
                Ok(SiteProjection {
                    path: path.clone()?,
                    role: site_context::role_view(demand.role, &admission)?,
                    value: site_context::value_view(value, &admission)?,
                })
            })());
        }
        // The acquired facts are dropped before another file is observed.
        Ok(())
    }

    pub fn finish(
        mut self,
        analyzer: &dyn IAnalyzer,
        cache: &PipelineRenderCache,
        cancellation: Option<&CancellationToken>,
    ) -> Result<PresentationWindow, PreparationError> {
        let mut start = 0;
        while start < self.requested.len() {
            let file = self.requested[start].file;
            let end = start + self.requested[start..].partition_point(|demand| demand.file == file);
            if cache.conflicting_sources.contains(file)
                || matches!(cache.sources.get(file), Some(RetainedSource::Conflicting))
            {
                return Err(PreparationError::Snapshot(file.clone()));
            }
            let source = cache.source_snapshot(analyzer, file);
            if self.window.slots[self.requested[start].ordinal].is_none()
                && source.is_none()
                && matches!(cache.sources.get(file), Some(RetainedSource::BudgetRefused))
            {
                let has_held = self.requested[start..end]
                    .iter()
                    .any(|demand| demand.facts.is_some())
                    || self
                        .trace_facts
                        .binary_search_by(|trace| trace.file.cmp(file))
                        .is_ok();
                let needs_facts = self.requested[start..end]
                    .iter()
                    .any(|demand| !matches!(demand.node, NodeSelection::Recorded(None)));
                if !has_held && needs_facts {
                    return Err(PreparationError::SourceBudget(file.clone()));
                }
            }
            self.project_file(analyzer, file, source, cancellation)?;
            start = end;
        }
        Ok(self.window)
    }
}

impl PresentationWindow {
    #[cfg(test)]
    pub fn prepare(
        analyzer: &dyn IAnalyzer,
        rows: &[PipelineRow],
        owner: Option<RetentionBudget>,
        cache: &PipelineRenderCache,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, PreparationError> {
        PresentationWindowBuilder::new(rows, owner)?.finish(analyzer, cache, cancellation)
    }

    pub fn take(&mut self) -> Result<SiteProjection, PresentationRefusal> {
        let slot = self
            .slots
            .get_mut(self.next)
            .expect("every rendered site was demanded")
            .take()
            .expect("a projected site is consumed once");
        self.next += 1;
        slot
    }

    #[cfg(test)]
    pub fn from_test_projection(owner: RetentionBudget, projection: SiteProjection) -> Self {
        let lease =
            admit_vec::<Option<Result<SiteProjection, PresentationRefusal>>>(Some(&owner), 1)
                .unwrap();
        Self {
            owner: Some(owner),
            slots: vec![Some(Ok(projection))],
            next: 0,
            source_refused: false,
            _slots_lease: lease,
        }
    }

    #[cfg(test)]
    pub fn from_test_refusal(owner: RetentionBudget, refusal: PresentationRefusal) -> Self {
        let lease =
            admit_vec::<Option<Result<SiteProjection, PresentationRefusal>>>(Some(&owner), 1)
                .unwrap();
        Self {
            owner: Some(owner),
            slots: vec![Some(Err(refusal))],
            next: 0,
            source_refused: false,
            _slots_lease: lease,
        }
    }

    pub fn owner(&self) -> Option<&RetentionBudget> {
        self.owner.as_ref()
    }
}

/// Presentation diagnostics affect only the presented response. In particular,
/// this does not mark the semantic collector or its reuse receipt dependent.
pub(super) fn presentation_diagnostic(refusal: PresentationRefusal) -> PresentationDiagnostic {
    match refusal {
        PresentationRefusal::RetainedBytes => PresentationDiagnostic::RowsRefused,
        PresentationRefusal::OwnerUnavailable => PresentationDiagnostic::OwnerUnavailable,
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::structural::search::tests::inline_project::InlineTestProject;
    use brokk_bifrost_test_macros::hardwon;

    struct MixedSelectedFacts(Arc<FileFacts>);

    impl QueryRowsFinalizer for MixedSelectedFacts {
        type Output = DetailedCodeQueryResult;

        fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
            panic!("fixture did not execute: {result:?}")
        }

        fn finish(
            self,
            mut rows: ExecutedQueryRows<'_>,
            context: QueryFinalizationContext<'_, '_>,
        ) -> Self::Output {
            assert_eq!(rows.execution.rows.len(), 2, "two files reach presentation");
            let mut replaced = 0;
            for row in &mut rows.execution.rows {
                if let PipelineValue::CallArgument(argument) = &mut row.value
                    && argument.shape.report.outcome.file.rel_path()
                        == std::path::Path::new("app.py")
                {
                    // Real normalized facts from source B emulate a provider
                    // returning a different snapshot for a selected source A.
                    argument.shape.facts = Some(Arc::clone(&self.0));
                    replaced += 1;
                }
            }
            assert!(replaced > 0, "exercise a selected written argument");
            present_query_rows(rows, context)
        }
    }

    struct OtherRowTraceFacts(Arc<FileFacts>);

    impl QueryRowsFinalizer for OtherRowTraceFacts {
        type Output = DetailedCodeQueryResult;

        fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
            panic!("fixture did not execute: {result:?}")
        }

        fn finish(
            self,
            mut rows: ExecutedQueryRows<'_>,
            context: QueryFinalizationContext<'_, '_>,
        ) -> Self::Output {
            assert_eq!(rows.execution.rows.len(), 2, "two files reach presentation");
            let selected = rows
                .execution
                .rows
                .iter()
                .find(|row| {
                    matches!(&row.value, PipelineValue::CallArgument(argument)
                    if argument.shape.report.outcome.file.rel_path()
                        == std::path::Path::new("app.py"))
                })
                .expect("selected app.py demand");
            let mut seed = selected
                .traces
                .first()
                .expect("real query trace")
                .seed
                .as_ref()
                .clone();
            assert_eq!(seed.file.rel_path(), std::path::Path::new("app.py"));
            assert_ne!(seed.facts.source(), self.0.source());
            seed.facts = self.0;
            let other = rows
                .execution
                .rows
                .iter_mut()
                .find(|row| {
                    matches!(&row.value, PipelineValue::CallArgument(argument)
                    if argument.shape.report.outcome.file.rel_path()
                        == std::path::Path::new("other.py"))
                })
                .expect("other.py row with its own unaffected demand");
            // Keep app.py's selected demand facts intact. Its contradictory
            // snapshot exists only on another row's trace for the same file.
            other.traces.first_mut().expect("other row trace").seed = Arc::new(seed);
            present_query_rows(rows, context)
        }
    }

    #[test]
    #[hardwon("#14068: site preparation mixed selected facts with another retained source")]
    fn snapshot_mismatch_omits_unpublished_site_batch_before_finalizing() {
        assert_snapshot_mismatch(MixedSelectedFacts);
    }

    #[test]
    fn other_row_trace_snapshot_mismatch_omits_unpublished_site_batch() {
        assert_snapshot_mismatch(OtherRowTraceFacts);
    }

    fn assert_snapshot_mismatch<F>(make_finalizer: impl FnOnce(Arc<FileFacts>) -> F)
    where
        F: QueryRowsFinalizer<Output = DetailedCodeQueryResult>,
    {
        const SOURCE_A: &str =
            "def sink(value):\n    return value\ndef use():\n    sink(\"old\")\n";
        const SOURCE_B: &str =
            "def sink(value):\n    return value\ndef use():\n    sink(\"new\")\n";
        let selected = InlineTestProject::with_language(Language::Python)
            .file("app.py", SOURCE_A)
            .file("other.py", "def other_use():\n    sink(\"kept\")\n")
            .build();
        let changed = InlineTestProject::with_language(Language::Python)
            .file("app.py", SOURCE_B)
            .build();
        let workspace = selected.workspace_analyzer(AnalyzerConfig::default());
        let changed_workspace = changed.workspace_analyzer(AnalyzerConfig::default());
        let changed_file = changed_workspace
            .analyzer()
            .analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().to_string_lossy() == "app.py")
            .expect("changed file");
        let facts = changed_workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Python)
            .and_then(|provider| provider.structural_facts(&changed_file))
            .expect("real normalized source B");
        assert_eq!(facts.source(), SOURCE_B);
        let query = CodeQuery::from_sexp(
            "(call-arguments (call-argument-groups (call-shape (call :callee (name \"sink\")))))",
        )
        .expect("query");
        let scope = AnalyzerQueryScope::new(workspace.analyzer());
        let mut keys = Vec::new();
        let result = execute_query_rows_with_finalizer(
            workspace.analyzer(),
            scope.token(),
            None,
            Some(&workspace),
            Some((&brokk_bifrost_flow::FlowWorkspaceState::new()).into()),
            None,
            0,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            false,
            UnionExecutionStrategy::Auto,
            CODE_QUERY_SCHEDULER_WORKERS,
            eager_structural_access_mode(),
            OccurrenceDerivationOptions::IDENTITY_ONLY,
            None,
            None,
            None,
            CodeQueryExecutionScope::whole_workspace(),
            Some(&mut keys),
            None,
            EdgeTraversalCache::default(),
            make_finalizer(facts),
        );
        assert!(
            result.result.results.is_empty(),
            "no contradictory positive row: {result:?}"
        );
        assert!(result.evidence.is_empty());
        assert!(keys.is_empty());
        assert!(result.result.truncated);
        assert_ne!(result.reuse, ReuseVerdict::Content);
        let refusal = result
            .result
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code() == CodeQueryDiagnosticCode::SemanticResultsOmitted)
            .expect("typed source refusal");
        assert_eq!(
            refusal.incompleteness(),
            Incompleteness::Operational(DerivationExecutionCause::Snapshot)
        );
        assert!(
            refusal.withheld_rows_path().is_none(),
            "whole-batch omission cannot certify absence in other.py"
        );
        assert!(result.result.diagnostics.iter().all(|diagnostic| !matches!(
            diagnostic.code(),
            CodeQueryDiagnosticCode::PresentationRowsRefused
                | CodeQueryDiagnosticCode::PresentationOwnerUnavailable
        )));
    }
}
