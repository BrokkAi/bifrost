// Node identity, node text, fqn prefix walking, and hit recording and
// reclassification need nothing but a node, a string, or the hit set, so they
// moved to `brokk-bifrost-core` and are re-exported here at the paths their
// callers already use. What stays needs an `IAnalyzer` or a `Language`.
pub(crate) use brokk_bifrost_core::analyzer::usages::common::{
    classify_recursive_hit, namespace_prefixes,
};

use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile, Range, SignatureMetadata,
};
use std::collections::BTreeSet;

#[doc(hidden)]
pub fn build_reference_site(
    path: String,
    text: String,
    range: Range,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> crate::analyzer::usages::reference_site::ResolvedReferenceSite {
    crate::analyzer::usages::reference_site::ResolvedReferenceSite {
        path,
        text,
        range,
        focus_start_byte,
        focus_end_byte,
    }
}

// Graph strategy selection uses source language, not declaration naming.
// An unclaimed extension may be eligible for C++ include inference without
// supplying a C++ graph surface.
#[doc(hidden)]
pub fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
}

pub(crate) fn is_constructor_metadata(metadata: &[SignatureMetadata]) -> bool {
    metadata
        .iter()
        .any(SignatureMetadata::callable_is_constructor)
}

/// Apply [`classify_recursive_hit`] to a proven hit set: a recursive call into
/// a callable target is kept and classified `SelfReceiver` (#1638), and every
/// other enclosing-equals-target hit stays dropped unless it reads a field
/// initializer value.
///
/// The target's own declared name is refused first. A scan records a
/// declaration's name token like any other occurrence -- Rust's `fn is_unpin<T>
/// () {}` yields an `is_unpin` identifier enclosed by, and equal in identity
/// to, the declaration it names. Dropping every enclosing-equals-target hit
/// used to hide that; the name is now excluded on its own structural terms,
/// through the analyzer's declaration name ranges rather than any source-text
/// comparison.
///
/// Both the declaration name ranges and the file read behind them are computed
/// only when some hit is a candidate, so the ordinary query pays nothing.
#[doc(hidden)]
pub fn classify_recursive_hits(
    analyzer: &dyn IAnalyzer,
    hits: BTreeSet<UsageHit>,
    target: &CodeUnit,
) -> BTreeSet<UsageHit> {
    if !hits.iter().any(|hit| &hit.enclosing == target) {
        return hits;
    }
    let context = analyzer
        .indexed_source(target.source())
        .map(|content| DeclarationNameRangeContext::new(target.source(), content));
    let name_ranges = context
        .as_ref()
        .map(|context| context.name_ranges(analyzer, target))
        .unwrap_or_default();
    let knowledge = crate::analyzer::languages::language_knowledge(language_for_target(target))
        .expect("a usage target has a supported language");
    hits.into_iter()
        .filter(|hit| {
            &hit.enclosing != target
                || hit.file != *target.source()
                || !name_ranges.iter().any(|range| {
                    hit.start_offset >= range.start_byte && hit.end_offset <= range.end_byte
                })
        })
        .filter_map(|hit| {
            let site = context
                .as_ref()
                .filter(|_| target.is_field() && hit.enclosing == *target)
                .and_then(|context| context.root_node())
                .and_then(|root| root.descendant_for_byte_range(hit.start_offset, hit.end_offset));
            classify_recursive_hit(hit, target, site, knowledge)
        })
        .collect()
}

pub(super) use crate::analyzer::common::language_for_file;

#[doc(hidden)]
pub fn analyzed_files_for_language(
    analyzer: &dyn CodeUnitIndex,
    language: Language,
) -> Vec<ProjectFile> {
    analyzer.analyzed_files_for_language(language)
}

#[doc(hidden)]
pub fn analyzable_usage_graph_files(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<Vec<ProjectFile>> {
    Some(
        analyzer
            .project()
            .analyzable_files(language)
            .ok()?
            .into_iter()
            .collect(),
    )
}

#[doc(hidden)]
pub fn select_usage_graph_files(
    files: &[ProjectFile],
    keep_file: impl Fn(&ProjectFile) -> bool,
) -> Vec<ProjectFile> {
    files
        .iter()
        .filter(|file| keep_file(file))
        .cloned()
        .collect()
}

#[doc(hidden)]
pub fn with_relational_frontier<R>(
    analyzer: &dyn IAnalyzer,
    language: &str,
    mut visit: impl FnMut(&dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier) -> R,
) -> R {
    let cancellation = crate::CancellationToken::new();
    match crate::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        &cancellation,
        |frontier| visit(frontier),
    ) {
        crate::analyzer::RelationalFrontierOutcome::Complete(result) => result,
        crate::analyzer::RelationalFrontierOutcome::Cancelled => {
            unreachable!("an uncancelled {language} helper frontier cannot cancel")
        }
        crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
            panic!("{language} relational helper frontier failed: {error:?}")
        }
    }
}

pub(crate) use brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain;

// These maps belong to one usage operation, which can serve several nested
// read captures. Each immutable answer carries its own transitive inputs.
pub(crate) type QueryReadMemo<K, V> = crate::analyzer::workspace_authority::ReplayingMemo<
    std::sync::Mutex<
        crate::hash::HashMap<
            K,
            std::sync::Arc<
                crate::analyzer::workspace_authority::ReplayingMemoEntry<
                    CompletedMemoValue<V>,
                    crate::analyzer::ReadKey,
                >,
            >,
        >,
    >,
>;

/// Completion evidence is captured inside advisory scopes as well as real queries.
#[derive(Debug)]
pub(crate) struct CompletedMemoValue<V> {
    value: V,
    receipt: MemoCompletionReceipt,
}

#[derive(Debug, Default)]
pub(crate) struct MemoCompletionReceipt {
    reasons: Vec<crate::analyzer::QueryReadIncomplete>,
    operational: bool,
}

impl MemoCompletionReceipt {
    pub(crate) fn capture<V>(
        analyzer: &dyn crate::analyzer::IAnalyzer,
        build: impl FnOnce() -> V,
    ) -> (V, Self) {
        let scope = crate::analyzer::AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        let value = build();
        let mut receipt = Self::default();
        for reason in scope.captured_read_incompleteness() {
            if reason.is_execution_dependent() {
                receipt.operational = true;
            } else {
                receipt.reasons.push(reason);
            }
        }
        (value, receipt)
    }

    fn include_read_channels(
        &mut self,
        channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
    ) {
        self.operational |= channels.execution_dependences > 0 || channels.budget_dependences > 0;
    }

    /// [`Self::retained_heap_bytes`] with every owned buffer rounded to its
    /// allocation, for pure evictable caches.
    fn allocated_heap_bytes(&self) -> usize {
        brokk_bifrost_core::hash::allocated_vec_slot_bytes(&self.reasons)
            + self
                .reasons
                .iter()
                .map(crate::analyzer::QueryReadIncomplete::allocated_payload_bytes)
                .sum::<usize>()
    }

    fn retained_heap_bytes(&self) -> usize {
        self.reasons.capacity() * std::mem::size_of::<crate::analyzer::QueryReadIncomplete>()
            + self
                .reasons
                .iter()
                .map(crate::analyzer::QueryReadIncomplete::retained_payload_bytes)
                .sum::<usize>()
    }

    fn capture_partial_flows<'request, E>(
        _owner: QueryMemoOwner,
        analyzer: &dyn IAnalyzer,
        request: &mut crate::analyzer::semantic::SemanticRequest<'request>,
        build: impl FnOnce(
            &mut crate::analyzer::semantic::SemanticRequest<'request>,
        ) -> Result<
            std::sync::Arc<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
            E,
        >,
    ) -> (
        Result<std::sync::Arc<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>, E>,
        Self,
    ) {
        let (value, mut receipt) = Self::capture(analyzer, || {
            let value = build(request);
            #[cfg(any(test, feature = "test-support"))]
            inject_memo_fill_reason_for_test(_owner, analyzer);
            value
        });
        use crate::analyzer::semantic::partial_flow::PartialFlowOutcome;
        receipt.operational |= request.stop_observed()
            || value.as_ref().is_ok_and(|flows| {
                matches!(
                    flows.outcome,
                    PartialFlowOutcome::ExceededBudget
                        | PartialFlowOutcome::Truncated
                        | PartialFlowOutcome::Error
                )
            });
        (value, receipt)
    }

    pub(crate) fn reusable(&self) -> bool {
        !self.operational
    }

    fn is_complete(&self) -> bool {
        self.reusable() && self.reasons.is_empty()
    }

    pub(crate) fn replay(&self) {
        crate::analyzer::common::replay_captured_query_read_incompleteness(&self.reasons);
    }
}

// Inspect the existing capture before sharing it; preserve its read-key Arc so
// ReplayingMemo still recognizes the fill it has already forwarded.
fn complete_memo_entry<V>(
    entry: crate::analyzer::workspace_authority::ReplayingMemoEntry<
        CompletedMemoValue<V>,
        crate::analyzer::ReadKey,
    >,
) -> crate::analyzer::workspace_authority::ReplayingMemoEntry<
    CompletedMemoValue<V>,
    crate::analyzer::ReadKey,
> {
    let (mut value, reads) = entry.into_parts();
    value.receipt.include_read_channels(reads.channels);
    crate::analyzer::workspace_authority::ReplayingMemoEntry::from_parts(value, reads)
}

/// A retained payload can only be constructed by shared completion admission.
/// Access replays completion before exposing the value; core replays its reads.
#[doc(hidden)]
#[derive(Debug)]
pub struct AdmittedMemoValue<V>(CompletedMemoValue<V>);

impl<V> std::ops::Deref for AdmittedMemoValue<V> {
    type Target = V;
    fn deref(&self) -> &V {
        self.0.receipt.replay();
        &self.0.value
    }
}

#[doc(hidden)]
#[must_use = "an admitted entry may be retained; an unretained answer is current-only"]
pub enum MemoValueAdmission<V> {
    Admitted(
        std::sync::Arc<
            crate::analyzer::workspace_authority::ReplayingMemoEntry<
                AdmittedMemoValue<V>,
                crate::analyzer::ReadKey,
            >,
        >,
    ),
    Unretained(V),
}

/// Bridge the core weighted capture to the same typed receipt used by query
/// memos. Preserve its read-key Arc so core recognizes the forwarded fill.
#[doc(hidden)]
pub fn try_capture_partial_flow_memo_entry<'request, A, E>(
    owner: QueryMemoOwner,
    analyzer: &dyn IAnalyzer,
    capture: &brokk_bifrost_core::analyzer::memo_attribution::MemoReadCapture<'_, A>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'request>,
    build: impl FnOnce(
        &mut crate::analyzer::semantic::SemanticRequest<'request>,
    ) -> Result<
        std::sync::Arc<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
        E,
    >,
    weight: impl FnOnce(
        &std::sync::Arc<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
    ) -> usize,
    discard: impl FnOnce(),
) -> Result<
    MemoValueAdmission<
        std::sync::Arc<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
    >,
    E,
>
where
    A: brokk_bifrost_core::analyzer::memo_attribution::MemoAttribution<
            Key = crate::analyzer::ReadKey,
        >,
{
    // Register rollback before a producer can mutate its request-local inputs.
    struct DiscardRejectedFill<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for DiscardRejectedFill<F> {
        fn drop(&mut self) {
            if let Some(discard) = self.0.take() {
                discard();
            }
        }
    }
    let mut rollback = DiscardRejectedFill(Some(discard));
    let mut value_bytes = 0;
    let entry = capture.try_build_weighted(|| {
        let (value, receipt) =
            MemoCompletionReceipt::capture_partial_flows(owner, analyzer, request, build);
        let value = value?;
        value_bytes = weight(&value)
            .saturating_add(std::mem::size_of::<MemoCompletionReceipt>())
            .saturating_add(receipt.retained_heap_bytes());
        Ok::<_, E>((CompletedMemoValue { value, receipt }, value_bytes))
    })?;
    let (mut value, reads) = entry.into_parts();
    value.receipt.include_read_channels(reads.channels);
    if value.receipt.reusable() {
        let entry = std::sync::Arc::new(
            crate::analyzer::workspace_authority::ReplayingMemoEntry::from_parts_weighted(
                AdmittedMemoValue(value),
                reads,
                value_bytes,
            ),
        );
        rollback.0 = None;
        Ok(MemoValueAdmission::Admitted(entry))
    } else {
        Ok(MemoValueAdmission::Unretained(value.value))
    }
}

struct CompletedMemoGuard<G>(G);
impl<V, G: std::ops::Deref<Target = CompletedMemoValue<V>>> std::ops::Deref
    for CompletedMemoGuard<G>
{
    type Target = V;
    fn deref(&self) -> &V {
        &self.0.value
    }
}

pub(crate) fn query_read_memo<K, V>() -> QueryReadMemo<K, V> {
    crate::analyzer::workspace_authority::ReplayingMemo::new(std::sync::Mutex::new(
        crate::hash::HashMap::default(),
    ))
}

// Recursive expression proofs can ask this same memo about a child. Build
// outside its lock; concurrent immutable fills may race, and the retained
// entry always carries the complete receipt of the fill that won insertion.
pub(crate) fn query_reentrant_memo_value<K: Clone + Eq + std::hash::Hash, V>(
    memo: &QueryReadMemo<K, V>,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    key: &K,
    build: impl FnOnce() -> V,
    retain: impl FnOnce(&V) -> bool,
) -> impl std::ops::Deref<Target = V> {
    let guard = memo
        .read(
            &crate::analyzer::workspace_authority::memo_attribution(analyzer),
            |entries, capture| {
                if let Some(value) = entries
                    .lock()
                    .expect("usage read memo poisoned")
                    .get(key)
                    .cloned()
                {
                    return Ok::<_, std::convert::Infallible>(value);
                }
                let value = std::sync::Arc::new(complete_memo_entry(capture.build(|| {
                    let (value, receipt) = MemoCompletionReceipt::capture(analyzer, build);
                    CompletedMemoValue { value, receipt }
                })));
                if !value.value().receipt.reusable() || !retain(&value.value().value) {
                    return Ok(value);
                }
                let mut entries = entries.lock().expect("usage read memo poisoned");
                Ok(std::sync::Arc::clone(
                    entries.entry(key.clone()).or_insert(value),
                ))
            },
        )
        .expect("usage memo acquisition is infallible");
    guard.receipt.replay();
    CompletedMemoGuard(guard)
}

pub(crate) fn query_memo_value<K: Clone + Eq + std::hash::Hash, V>(
    memo: &QueryReadMemo<K, V>,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    key: &K,
    build: impl FnOnce() -> V,
) -> impl std::ops::Deref<Target = V> {
    query_reentrant_memo_value(memo, analyzer, key, build, |_| true)
}

/// Like [`query_memo_value`], but an `Err` answer (such as a cancellation) is
/// returned without being retained, so a later request recomputes it.
pub(crate) fn query_memo_result<K: Clone + Eq + std::hash::Hash, V, E>(
    memo: &QueryReadMemo<K, V>,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    key: &K,
    build: impl FnOnce() -> Result<V, E>,
) -> Result<impl std::ops::Deref<Target = V>, E> {
    let guard = memo.read(
        &crate::analyzer::workspace_authority::memo_attribution(analyzer),
        |entries, capture| {
            let mut entries = entries.lock().expect("usage read memo poisoned");
            if let Some(entry) = entries.get(key) {
                return Ok(std::sync::Arc::clone(entry));
            }
            let entry = std::sync::Arc::new(complete_memo_entry(capture.try_build(|| {
                let (value, receipt) = MemoCompletionReceipt::capture(analyzer, build);
                value.map(|value| CompletedMemoValue { value, receipt })
            })?));
            if entry.value().receipt.reusable() {
                entries.insert(key.clone(), std::sync::Arc::clone(&entry));
            }
            Ok(entry)
        },
    )?;
    guard.receipt.replay();
    Ok(CompletedMemoGuard(guard))
}

type CompletedReadMemoEntry = std::sync::Arc<
    crate::analyzer::workspace_authority::ReplayingMemoEntry<
        CompletedMemoValue<()>,
        crate::analyzer::ReadKey,
    >,
>;

/// A shared replay wrapper for the inputs of mutable request state. These
/// requests can be restored by successive captures, so capture scoping alone
/// cannot certify their hits.
#[derive(Debug)]
pub struct QueryMemoReads {
    memo: crate::analyzer::workspace_authority::ReplayingMemo<Option<CompletedReadMemoEntry>>,
}

impl QueryMemoReads {
    pub(crate) fn is_complete(&self, analyzer: &dyn crate::analyzer::IAnalyzer) -> bool {
        let entry = self
            .memo
            .read(
                &crate::analyzer::workspace_authority::memo_attribution(analyzer),
                |slot, _| {
                    Ok::<_, std::convert::Infallible>(std::sync::Arc::clone(
                        slot.as_ref().expect("admitted memo inputs initialized"),
                    ))
                },
            )
            .expect("request input replay is infallible");
        entry.receipt.is_complete()
    }
}

// Every capture names an owner. Adding a variant also registers it in the
// shared completion/rollback conformance matrix below.
macro_rules! memo_owners {
    ($($owner:ident),+ $(,)?) => {
        #[doc(hidden)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum QueryMemoOwner { $($owner),+ }
        impl QueryMemoOwner {
            pub const ALL: &[Self] = &[$(Self::$owner),+];
        }
    };
}
memo_owners!(
    CallBinding,
    ScalarDefinition,
    ReceiverQuery,
    DispatchPrefetch,
    DispatchSession,
    CallTransfer,
    ExitProfile,
    RustOperator,
    GoFileContext,
    GoDefinition,
    NonreturnDiscovery,
    PythonDefinition,
    PythonType,
    RequestRead,
    CompositionPartialFlow,
    InertDropProof
);

#[cfg(any(test, feature = "test-support"))]
impl QueryMemoOwner {
    /// Exhaustive registration: adding an owner requires a real conformance site.
    pub fn conformance_site_for_test(self) -> &'static str {
        match self {
            Self::CallBinding => {
                "crates/bifrost-analysis/src/analyzer/usages/owner_memo_tests.rs::concrete_call_binding_memo_completion"
            }
            Self::ScalarDefinition => {
                "crates/bifrost-analysis/src/analyzer/usages/get_definition/owner_memo_tests.rs::concrete_scalar_definition_memo_completion"
            }
            Self::ReceiverQuery => {
                "crates/bifrost-analysis/src/analyzer/usages/receiver_query/owner_memo_tests.rs::concrete_receiver_memo_completion"
            }
            Self::DispatchPrefetch => {
                "crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/prefetch_memo_conformance.rs::concrete_prefetch_memo_completion"
            }
            Self::DispatchSession => {
                "crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/owner_memo_tests.rs::concrete_dispatch_memo_completion"
            }
            Self::CallTransfer | Self::ExitProfile => {
                "crates/bifrost-analysis/src/analyzer/semantic/icfg.rs::icfg_outcome_memo_completion_conformance"
            }
            Self::RustOperator => {
                "crates/bifrost-rust-analysis/src/analyzer/rust/call_conversion.rs::operator_candidates_memo_completion_conformance"
            }
            Self::GoFileContext => {
                "crates/bifrost-go-analysis/src/analyzer/go/native_points.rs::assert_file_context_conformance_for_test"
            }
            Self::GoDefinition => {
                "crates/bifrost-go-analysis/src/analyzer/usages/get_definition/go.rs::go_definition_memo_completion_conformance"
            }
            Self::NonreturnDiscovery => {
                "crates/bifrost-flow/src/flow_state.rs::nonreturn_memo_completion_conformance"
            }
            Self::PythonDefinition => {
                "crates/bifrost-python-analysis/src/analyzer/usages/get_definition/python.rs::native_definition_batch_memo_completion_conformance"
            }
            Self::PythonType => {
                "crates/bifrost-python-analysis/src/analyzer/python/type_flow.rs::native_type_request_memo_completion_conformance"
            }
            Self::CompositionPartialFlow => {
                "crates/bifrost-flow/src/composition/mod.rs::unit_partial_flow_memo_completion_conformance"
            }
            Self::InertDropProof => {
                "tests/suite_semantic/summary_reuse_contracts.rs::rust_drop_query_memo_admits_inventory_at_cold_boundary"
            }
            Self::RequestRead => {
                "crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs::request_read_memo_completion_conformance"
            }
        }
    }

    fn conformance_retains_incomplete(self) -> bool {
        match self {
            Self::RequestRead => false,
            Self::CallBinding
            | Self::ScalarDefinition
            | Self::ReceiverQuery
            | Self::DispatchPrefetch
            | Self::DispatchSession
            | Self::CallTransfer
            | Self::ExitProfile
            | Self::RustOperator
            | Self::GoFileContext
            | Self::GoDefinition
            | Self::NonreturnDiscovery
            | Self::PythonDefinition
            | Self::PythonType
            | Self::CompositionPartialFlow
            | Self::InertDropProof => true,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static MEMO_TEST_REASON: std::cell::RefCell<Option<(QueryMemoOwner, crate::analyzer::QueryReadIncomplete)>> = const { std::cell::RefCell::new(None) };
}

/// Inject a completion event after one real owner fill, before shared
/// admission. The hook is consumed once and never substitutes a product.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_memo_fill_reason_for_test<T>(
    owner: QueryMemoOwner,
    reason: crate::analyzer::QueryReadIncomplete,
    build: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MEMO_TEST_REASON.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    MEMO_TEST_REASON.with(|slot| {
        assert!(
            slot.borrow_mut().replace((owner, reason)).is_none(),
            "memo test injections cannot nest"
        );
    });
    let _reset = Reset;
    let value = build();
    MEMO_TEST_REASON.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "{owner:?} did not fill on the injecting thread"
        )
    });
    value
}

#[cfg(any(test, feature = "test-support"))]
fn inject_memo_fill_reason_for_test(
    owner: QueryMemoOwner,
    analyzer: &dyn crate::analyzer::IAnalyzer,
) {
    MEMO_TEST_REASON.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(expected, _)| *expected == owner)
        {
            let (_, reason) = slot.take().expect("matching injection exists");
            analyzer.record_query_incomplete(reason);
        }
    });
}

/// The same conformance matrix runs against each owner's real state and
/// acquisition API. A fixture supplies construction, one query, and retention
/// inspection; all completion and retry assertions live here.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_memo_owner_conformance_for_test<S, V: std::fmt::Debug + PartialEq>(
    owner: QueryMemoOwner,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    make: impl Fn() -> S,
    query: impl Fn(&mut S) -> V,
    retained: impl Fn(&S) -> bool,
) {
    use crate::analyzer::read_ledger::DerivationExecutionCause;
    use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
    for (reason, keep) in [
        (
            QueryReadIncomplete::SemanticEvidenceGap("memo conformance deterministic gap".into()),
            owner.conformance_retains_incomplete(),
        ),
        (QueryReadIncomplete::Cancelled, false),
        (
            QueryReadIncomplete::ProofStopped {
                reason: "memo conformance budget",
                cause: Some(DerivationExecutionCause::Budget),
            },
            false,
        ),
        (
            QueryReadIncomplete::ProofStopped {
                reason: "memo conformance deadline",
                cause: Some(DerivationExecutionCause::Budget),
            },
            false,
        ),
        (
            QueryReadIncomplete::StoreFailure(crate::analyzer::store::StoreError::new(
                "memo conformance store failure",
            )),
            false,
        ),
    ] {
        let mut state = make();
        // Each attempt reports to its own receipt. Keep operational failure
        // from poisoning the test's enclosing request-memo namespace, whose
        // lifetime is needed to exercise real warm entries (inherit_query_incompleteness).
        let attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
        let fill = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        let first = with_memo_fill_reason_for_test(owner, reason.clone(), || query(&mut state));
        let fill_reasons = fill.captured_read_incompleteness();
        assert!(
            fill_reasons.contains(&reason),
            "{owner:?}: {fill_reasons:?}"
        );
        assert_eq!(retained(&state), keep, "{owner:?}: {reason:?}");
        drop(fill);
        drop(attempt);
        if keep {
            // The receipt belongs to this retained owner, not the last query
            // on the analyzer. Keep it alive while a separate owner fills and
            // hits without inheriting its completion.
            let intrinsic_reasons: Vec<_> = fill_reasons
                .iter()
                .filter(|captured| *captured != &reason)
                .cloned()
                .collect();
            let mut independent = make();
            for _ in 0..2 {
                let _attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
                let completion = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
                assert_eq!(
                    first,
                    query(&mut independent),
                    "{owner:?}: independent answer"
                );
                assert!(
                    retained(&independent),
                    "{owner:?}: independent fill retained"
                );
                assert_eq!(
                    completion.captured_read_incompleteness(),
                    intrinsic_reasons,
                    "{owner:?}: independent owner inherited {:?}",
                    completion.captured_read_incompleteness()
                );
            }
            assert!(
                retained(&state),
                "{owner:?}: original owner remains retained"
            );
        }
        let attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
        let hit = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        let second = query(&mut state);
        let hit_reasons = hit.captured_read_incompleteness();
        assert_eq!(
            first, second,
            "{owner:?}: current answer and retry/hit disagree"
        );
        if keep {
            assert_eq!(
                fill_reasons, hit_reasons,
                "{owner:?}: hit lost fill completion"
            );
        } else {
            assert!(
                !hit_reasons.contains(&reason),
                "{owner:?}: retry reused operational {reason:?} in {hit_reasons:?}"
            );
        }
        assert!(
            retained(&state),
            "{owner:?}: normal retry must retain a product"
        );
        drop(hit);
        drop(attempt);
        let _attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
        let warm = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        assert_eq!(
            second,
            query(&mut state),
            "{owner:?}: complete fill must remain reusable"
        );
        assert_eq!(
            hit_reasons,
            warm.captured_read_incompleteness(),
            "{owner:?}: repeat hit changed completion"
        );
    }
}

/// Only shared completion admission can create a retained receipt. Products
/// with a required QueryMemoReads field therefore cannot retain rejected fills.
#[doc(hidden)]
#[must_use = "a memo fill must be admitted or discarded"]
pub struct MemoAdmission {
    reads: Option<QueryMemoReads>,
}

impl MemoAdmission {
    #[must_use]
    pub fn admitted(self) -> Option<QueryMemoReads> {
        self.reads
    }
}

pub fn capture_memo_reads<T>(
    _owner: QueryMemoOwner,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    build: impl FnOnce() -> T,
) -> (T, MemoAdmission) {
    let mut memo = crate::analyzer::workspace_authority::ReplayingMemo::default();
    let mut value = None;
    let mut reusable = false;
    memo.read_mut(
        &crate::analyzer::workspace_authority::memo_attribution(analyzer),
        |slot, capture| {
            let entry = std::sync::Arc::new(complete_memo_entry(capture.build(|| {
                let (_, receipt) = MemoCompletionReceipt::capture(analyzer, || {
                    value = Some(build());
                    #[cfg(any(test, feature = "test-support"))]
                    inject_memo_fill_reason_for_test(_owner, analyzer);
                });
                CompletedMemoValue { value: (), receipt }
            })));
            reusable = entry.value().receipt.reusable();
            *slot = Some(std::sync::Arc::clone(&entry));
            Ok::<_, std::convert::Infallible>(entry)
        },
    )
    .expect("request input capture is infallible");
    (
        value.expect("request builder ran"),
        MemoAdmission {
            reads: reusable.then_some(QueryMemoReads { memo }),
        },
    )
}

/// Register rollback before a mutable fill begins. Shared admission drives
/// rollback, including writes made before an operational early return. Replay
/// prior completion before calling the builder, including its early errors.
#[doc(hidden)]
pub fn capture_mutable_memo_reads<S, T>(
    owner: QueryMemoOwner,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    state: &mut S,
    previous: Option<&QueryMemoReads>,
    discard: impl FnOnce(&mut S),
    build: impl FnOnce(&mut S) -> T,
) -> (T, Option<QueryMemoReads>) {
    let (value, admission) = capture_memo_reads(owner, analyzer, || {
        if let Some(previous) = previous {
            replay_memo_reads(previous, analyzer);
        }
        build(state)
    });
    let reads = admission.admitted();
    if reads.is_none() {
        discard(state);
    }
    (value, reads)
}

/// Store errors must join the completion capture even when a caller returns
/// them before recording its rendered diagnostic.
#[doc(hidden)]
pub fn memo_store_result<T>(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    result: crate::analyzer::store::Result<T>,
) -> crate::analyzer::store::Result<T> {
    if let Err(error) = &result {
        analyzer.record_query_incomplete(crate::analyzer::QueryReadIncomplete::StoreFailure(
            error.clone(),
        ));
    }
    result
}

/// Whether a native answer's diagnostic reports that the operation itself
/// failed: a stale selection, a store error or an unavailable native engine. A
/// retained native request is released after one. Any other completed answer,
/// including an incomplete or unprojectable one, leaves the request and its
/// completed candidate artifacts usable for the next site.
pub fn is_native_operation_failure(kind: &str) -> bool {
    matches!(
        kind,
        "native_stale" | "native_store_error" | "native_unavailable"
    )
}

pub fn replay_memo_reads(reads: &QueryMemoReads, analyzer: &dyn crate::analyzer::IAnalyzer) {
    let guard = reads
        .memo
        .read(
            &crate::analyzer::workspace_authority::memo_attribution(analyzer),
            |slot, _| {
                Ok::<_, std::convert::Infallible>(std::sync::Arc::clone(
                    slot.as_ref().expect("request inputs initialized"),
                ))
            },
        )
        .expect("request input replay is infallible");
    guard.receipt.replay();
}

pub(crate) fn memo_read_bytes(reads: &QueryMemoReads) -> usize {
    reads.memo.account(|slot| {
        slot.as_ref().map_or(0, |entry| {
            entry.value().receipt.retained_heap_bytes()
                + entry.retained_bytes(|key| {
                    let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::default();
                    crate::analyzer::store::cache_budget::retained_read_key(&mut heap, key);
                    heap.total()
                })
        })
    })
}

/// [`memo_read_bytes`] with every owned buffer rounded to its allocation, for
/// pure evictable caches. The dispatch session keeps the requested-byte form.
pub(crate) fn allocated_memo_read_bytes(reads: &QueryMemoReads) -> usize {
    reads.memo.account(|slot| {
        slot.as_ref().map_or(0, |entry| {
            entry.value().receipt.allocated_heap_bytes()
                + entry.allocated_retained_bytes(|key| {
                    let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::allocated();
                    crate::analyzer::store::cache_budget::retained_read_key(&mut heap, key);
                    heap.total()
                })
        })
    })
}

#[cfg(test)]
mod memo_read_tests {
    use super::*;
    use crate::analyzer::semantic::StableDigest;
    use crate::analyzer::{IAnalyzer, MultiAnalyzer, ReadKey, capture_query_reads};

    use brokk_bifrost_test_macros::hardwon;

    macro_rules! memo_completion_case {
        ($name:ident, $call:ident $(, $extra:expr)*) => {
            #[test]
            #[hardwon("#11145: operation memo cached operational stops and lost advisory completion receipts")]
            fn $name() {
                use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
                use crate::analyzer::read_ledger::DerivationExecutionCause;
                let analyzer = MultiAnalyzer::default();
                let memo = query_read_memo::<u8, usize>();
                let fills = std::cell::Cell::new(0);
                for cause in [DerivationExecutionCause::Cancelled, DerivationExecutionCause::Budget, DerivationExecutionCause::Snapshot, DerivationExecutionCause::Provider] {
                    let _scope = AnalyzerQueryScope::for_advisory_read(&analyzer);
                    let build = || {
                        fills.set(fills.get() + 1);
                        analyzer.record_query_incomplete(QueryReadIncomplete::ProofStopped { reason: "test_stop", cause: Some(cause) });
                        fills.get()
                    };
                    assert_eq!(*$call(&memo, &analyzer, &0, build $(, $extra)*), fills.get());
                }
                assert_eq!(fills.get(), 4);
                for _ in 0..2 {
                    let build = || { analyzer.record_budget_dependences(1); fills.set(fills.get() + 1); fills.get() };
                    assert_eq!(*$call(&memo, &analyzer, &0, build $(, $extra)*), fills.get());
                }
                assert_eq!(fills.get(), 6);
                let stable = QueryReadIncomplete::ProofStopped { reason: "not_found", cause: None };
                {
                    let _scope = AnalyzerQueryScope::for_advisory_read(&analyzer);
                    let build = || { analyzer.record_query_incomplete(stable.clone()); 17 };
                    assert_eq!(*$call(&memo, &analyzer, &0, build $(, $extra)*), 17);
                }
                let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                assert_eq!(*$call(&memo, &analyzer, &0, || panic!("warm hit rebuilt") $(, $extra)*), 17);
                assert_eq!(scope.captured_read_incompleteness(), vec![stable]);
            }
        }
    }
    fn result_value(
        memo: &QueryReadMemo<u8, usize>,
        analyzer: &dyn IAnalyzer,
        key: &u8,
        build: impl FnOnce() -> usize,
    ) -> impl std::ops::Deref<Target = usize> {
        query_memo_result(memo, analyzer, key, || {
            Ok::<_, std::convert::Infallible>(build())
        })
        .unwrap()
    }
    memo_completion_case!(value_memo_completion, query_memo_value);
    memo_completion_case!(
        reentrant_memo_completion,
        query_reentrant_memo_value,
        |_| true
    );
    memo_completion_case!(result_memo_completion, result_value);

    #[test]
    #[hardwon(
        "f3fffc13b78d: a cache fill that consumed a request-local value computed under an execution failure must not be published as complete, with no reason inherited from the enclosing request"
    )]
    #[hardwon("#12288: completion-only admission treated unknown cause-less stops as stable")]
    fn cache_fill_consuming_a_failed_request_local_value_is_refused() {
        use crate::analyzer::read_ledger::DerivationExecutionCause;
        use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete, ReadLedger};
        let analyzer = MultiAnalyzer::default();
        let _request = AnalyzerQueryScope::new(&analyzer);
        let memo = query_read_memo::<u8, usize>();
        // A cross-request cache fill is admitted by its own scope's completion
        // and its own ledger, as `QueryCacheFill::is_complete` decides.
        let fill = || {
            let ledger = std::sync::Arc::new(ReadLedger::new());
            let scope =
                AnalyzerQueryScope::with_read_ledger(&analyzer, std::sync::Arc::clone(&ledger));
            (scope, ledger)
        };
        let admitted = |scope: &AnalyzerQueryScope<'_>, ledger: &ReadLedger| {
            scope.read_completion().is_ok()
                && ledger.execution_dependences() == 0
                && !ledger.reuse_refused()
        };
        let operational = QueryReadIncomplete::ProofStopped {
            reason: "test_stop",
            cause: Some(DerivationExecutionCause::Provider),
        };
        {
            let (scope, ledger) = fill();
            let value = query_memo_value(&memo, &analyzer, &0, || {
                analyzer.record_query_incomplete(operational.clone());
                1
            });
            assert_eq!(*value, 1);
            assert!(!admitted(&scope, &ledger), "the fill's own build failed");
        }
        {
            // The failed value was not retained, so a later fill in the same
            // request does not consume it: it computes from its own reads, and
            // the enclosing request's failure does not make its answer partial.
            let (scope, ledger) = fill();
            let value = query_memo_value(&memo, &analyzer, &0, || 2);
            assert_eq!(*value, 2);
            assert!(admitted(&scope, &ledger));
        }
        // Completion-only admission uses the same classifier even when no
        // read channels have been projected into the receipt yet.
        let (_, unknown) = MemoCompletionReceipt::capture(&analyzer, || {
            analyzer.record_query_incomplete(QueryReadIncomplete::ProofStopped {
                reason: "unregistered_proof_stop",
                cause: None,
            });
        });
        assert!(
            !unknown.reusable(),
            "an unknown cause-less stop cannot be retained"
        );
        let stable = QueryReadIncomplete::ProofStopped {
            reason: "not_found",
            cause: None,
        };
        {
            let (scope, ledger) = fill();
            let value = query_memo_value(&memo, &analyzer, &1, || {
                analyzer.record_query_incomplete(stable.clone());
                3
            });
            assert_eq!(*value, 3);
            assert!(!admitted(&scope, &ledger));
        }
        {
            // A retained value that was built under a gap replays the gap into
            // its consumer's own receipt, so the consuming fill is refused.
            let (scope, ledger) = fill();
            let value = query_memo_value(&memo, &analyzer, &1, || panic!("warm hit rebuilt"));
            assert_eq!(*value, 3);
            assert!(!admitted(&scope, &ledger));
        }
    }

    #[test]
    #[hardwon("#11234: restored mutable memo hits dropped deterministic incompleteness")]
    fn restored_query_state_replays_incomplete_fill_on_hit() {
        use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        for &owner in QueryMemoOwner::ALL {
            let key = ReadKey::Configuration(StableDigest::sha256(b"incomplete mutable request"));
            let gap = QueryReadIncomplete::SemanticEvidenceGap(
                "test-only unresolved semantic premise".into(),
            );
            let fill = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            let (value, admission) = capture_memo_reads(owner, &analyzer, || {
                analyzer.record_read(key.clone());
                analyzer.record_query_incomplete(gap.clone());
                37
            });
            assert_eq!(value, 37);
            assert_eq!(
                fill.captured_read_incompleteness(),
                vec![gap.clone()],
                "{owner:?}"
            );
            drop(fill);
            let receipt = admission.admitted().expect("deterministic fill admitted");
            for _ in 0..2 {
                let hit = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                let (_, reads) =
                    capture_query_reads(&analyzer, || replay_memo_reads(&receipt, &analyzer));
                assert_eq!(reads.keys(), vec![key.clone()], "{owner:?}");
                assert_eq!(
                    hit.captured_read_incompleteness(),
                    vec![gap.clone()],
                    "{owner:?}"
                );
            }
            // An early return can leave the old derived state in place. The
            // shared capture must replay its prior receipt before the builder
            // has any opportunity to return without doing work.
            let mut state = vec![37];
            let (answer, next) = capture_mutable_memo_reads(
                owner,
                &analyzer,
                &mut state,
                Some(&receipt),
                Vec::clear,
                |_| Err::<(), ()>(()),
            );
            assert_eq!(answer, Err(()));
            assert_eq!(state, vec![37]);
            let next = next.expect("deterministic prior state remains admitted");
            let hit = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            let (_, reads) = capture_query_reads(&analyzer, || replay_memo_reads(&next, &analyzer));
            assert_eq!(reads.keys(), vec![key], "{owner:?}");
            assert_eq!(hit.captured_read_incompleteness(), vec![gap], "{owner:?}");
        }
    }

    #[test]
    #[hardwon("#11234: refusing a receipt left operationally filled mutable products retained")]
    fn registered_memo_owners_obey_shared_admission_and_rollback() {
        use crate::analyzer::read_ledger::DerivationExecutionCause;
        use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        let analyzer = MultiAnalyzer::default();
        for &owner in QueryMemoOwner::ALL {
            for reason in [
                QueryReadIncomplete::Cancelled,
                QueryReadIncomplete::ProofStopped {
                    reason: "budget",
                    cause: Some(DerivationExecutionCause::Budget),
                },
                QueryReadIncomplete::StoreFailure(crate::analyzer::store::StoreError::new(
                    "test store failure",
                )),
            ] {
                let mut state = vec![1];
                let (_, receipt) = capture_mutable_memo_reads(
                    owner,
                    &analyzer,
                    &mut state,
                    None,
                    Vec::clear,
                    |state| {
                        state.push(2);
                        analyzer.record_query_incomplete(reason);
                    },
                );
                assert!(receipt.is_none(), "{owner:?}");
                assert!(state.is_empty(), "{owner:?}");
            }
            // A soft deadline can end a fill without a typed reason. Its
            // execution dependence must reject the value and all mutations too.
            let mut state = vec![1];
            let (_, receipt) = capture_mutable_memo_reads(
                owner,
                &analyzer,
                &mut state,
                None,
                Vec::clear,
                |state| {
                    state.push(2);
                    analyzer.mark_execution_dependent_reads(1);
                },
            );
            assert!(receipt.is_none(), "{owner:?}");
            assert!(state.is_empty(), "{owner:?}");
            let (answer, receipt) = capture_mutable_memo_reads(
                owner,
                &analyzer,
                &mut state,
                None,
                Vec::clear,
                |state| {
                    state.push(3);
                    41
                },
            );
            assert_eq!(answer, 41);
            let receipt = receipt.expect("complete fill admitted");
            for _ in 0..2 {
                let hit = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                replay_memo_reads(&receipt, &analyzer);
                assert!(hit.captured_read_incompleteness().is_empty(), "{owner:?}");
                assert_eq!(state, vec![3]);
            }
        }
    }

    #[test]
    #[hardwon(
        "#11234: truncated producer heads must recompute instead of becoming stable memo hits"
    )]
    fn weighted_partial_flow_memo_rejects_operational_heads() {
        use crate::analyzer::semantic::partial_flow::{PartialFlowOutcome, ProcedurePartialFlows};
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
        use crate::analyzer::workspace_authority::{ReplayingMemo, memo_attribution};
        use std::{
            cell::{Cell, RefCell},
            collections::HashMap,
            sync::Arc,
        };
        let analyzer = MultiAnalyzer::default();
        for outcome in [
            PartialFlowOutcome::Truncated,
            PartialFlowOutcome::ExceededBudget,
            PartialFlowOutcome::Error,
            PartialFlowOutcome::Complete,
        ] {
            let memo = ReplayingMemo::new(RefCell::new(HashMap::new()));
            let fills = Cell::new(0);
            let derived = Cell::new(false);
            let discards = Cell::new(0);
            for _ in 0..2 {
                let _scope = crate::analyzer::AnalyzerQueryScope::for_advisory_read(&analyzer);
                let cancellation = CancellationToken::new();
                let mut budget = SemanticBudget::default();
                let answer = memo.read(&memo_attribution(&analyzer), |map, capture| {
                    if let Some(entry) = map.borrow().get(&()).cloned() {
                        return Ok(entry);
                    }
                    let admission = try_capture_partial_flow_memo_entry(
                        QueryMemoOwner::CompositionPartialFlow,
                        &analyzer,
                        capture,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                        |_| {
                            fills.set(fills.get() + 1);
                            derived.set(true);
                            Ok::<_, std::convert::Infallible>(Arc::new(ProcedurePartialFlows::new(
                                outcome,
                                Some("original producer cause".into()),
                                Vec::new(),
                                Vec::new(),
                                false,
                                true,
                                Vec::new(),
                            )))
                        },
                        |head| head.retained_bytes(),
                        || {
                            derived.set(false);
                            discards.set(discards.get() + 1);
                        },
                    )
                    .unwrap();
                    match admission {
                        MemoValueAdmission::Admitted(entry) => {
                            map.borrow_mut().insert((), Arc::clone(&entry));
                            Ok(entry)
                        }
                        MemoValueAdmission::Unretained(head) => Err(head),
                    }
                });
                let head = match answer {
                    Ok(entry) => Arc::clone(&entry),
                    Err(head) => head,
                };
                assert_eq!(derived.get(), outcome == PartialFlowOutcome::Complete);
                assert_eq!(head.outcome, outcome);
                assert_eq!(head.detail.as_deref(), Some("original producer cause"));
                assert_eq!(
                    memo.account(|map| usize::from(!map.borrow().is_empty())) != 0,
                    outcome == PartialFlowOutcome::Complete,
                );
            }
            assert_eq!(
                discards.get(),
                if outcome == PartialFlowOutcome::Complete {
                    0
                } else {
                    2
                }
            );
            assert_eq!(
                fills.get(),
                if outcome == PartialFlowOutcome::Complete {
                    1
                } else {
                    2
                }
            );
        }
    }

    #[test]
    #[hardwon("#11234: a failed composition producer left request-local artifact refs behind")]
    fn weighted_partial_flow_memo_rolls_back_producer_errors() {
        use crate::analyzer::semantic::partial_flow::ProcedurePartialFlows;
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
        use crate::analyzer::workspace_authority::{
            ReplayingMemo, ReplayingMemoEntry, memo_attribution,
        };
        use std::{cell::Cell, sync::Arc};
        type Entry =
            Arc<ReplayingMemoEntry<AdmittedMemoValue<Arc<ProcedurePartialFlows>>, ReadKey>>;
        let analyzer = MultiAnalyzer::default();
        let memo = ReplayingMemo::new(());
        let derived = Cell::new(false);
        let cancellation = CancellationToken::new();
        let mut budget = SemanticBudget::default();
        let result = memo.read(
            &memo_attribution(&analyzer),
            |_, capture| -> Result<Entry, &str> {
                let admission = try_capture_partial_flow_memo_entry(
                    QueryMemoOwner::CompositionPartialFlow,
                    &analyzer,
                    capture,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                    |_| {
                        derived.set(true);
                        Err::<Arc<ProcedurePartialFlows>, _>("producer store failure")
                    },
                    |head| head.retained_bytes(),
                    || derived.set(false),
                )?;
                drop(admission);
                panic!("the failed producer must return its error");
            },
        );
        assert_eq!(result.err(), Some("producer store failure"));
        assert!(
            !derived.get(),
            "shared admission must roll back before propagating Err"
        );
    }

    #[test]
    fn restored_query_state_replays_reads_from_an_uncaptured_build() {
        let analyzer = MultiAnalyzer::default();
        let key = ReadKey::Configuration(StableDigest::sha256(b"query state input"));
        let (value, receipt) = capture_memo_reads(QueryMemoOwner::CallBinding, &analyzer, || {
            analyzer.record_read(key.clone());
            analyzer.record_unattributed_read();
            37
        });
        let receipt = receipt.admitted().expect("complete fill admitted");
        assert_eq!(value, 37);
        for _ in 0..2 {
            let (_, reads) =
                capture_query_reads(&analyzer, || replay_memo_reads(&receipt, &analyzer));
            assert_eq!(reads.keys(), vec![key.clone()]);
            assert_eq!(reads.unattributed_reads(), 1);
        }
    }
}

#[cfg(test)]
mod native_operation_failure_tests {
    use super::is_native_operation_failure;

    // The shared native point layer (native_points.rs) reports these three kinds
    // when the operation itself failed. An unprojectable or missing answer is
    // not one, so a retained request keeps its candidate artifacts after it.
    #[test]
    fn only_operation_failures_release_a_retained_request() {
        for kind in ["native_stale", "native_store_error", "native_unavailable"] {
            assert!(is_native_operation_failure(kind), "{kind}");
        }
        for kind in [
            "native_type_projection_unavailable",
            "native_reference_missing",
            "incomplete_binding",
        ] {
            assert!(!is_native_operation_failure(kind), "{kind}");
        }
    }
}
