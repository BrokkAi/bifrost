use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use brokk_bifrost_core::CancellationToken;
use brokk_bifrost_core::analyzer::PackageRelationKind;
use rayon::prelude::*;

use crate::analyzer::{
    IAnalyzer, RelationalBatchOutcome, RelationalDefinitionFrontier, RelationalDefinitionQuestion,
    RelationalDefinitionRequest, RelationalDefinitionValue, RelationalFrontierOutcome,
};
use crate::hash::{HashMap, HashSet};

const QUERY_SHAPE_COUNT: usize = 16;
const QUERY_SHAPE_NAMES: [&str; QUERY_SHAPE_COUNT] = [
    "exact_name",
    "normalized_name",
    "structural_children",
    "structural_members",
    "visible_members",
    "file_identifier",
    "identifier",
    "file_identifier_prefix",
    "identifier_prefix",
    "package_types",
    "package_types_in_package",
    "package_exists",
    "package_files",
    "package_children",
    "package_descendants",
    "callable_facts",
];

fn query_shape(query: &crate::analyzer::RelationalDefinitionQuery) -> (&'static str, usize) {
    match query {
        crate::analyzer::RelationalDefinitionQuery::ExactName => (QUERY_SHAPE_NAMES[0], 0),
        crate::analyzer::RelationalDefinitionQuery::NormalizedName => (QUERY_SHAPE_NAMES[1], 1),
        crate::analyzer::RelationalDefinitionQuery::StructuralChildren => (QUERY_SHAPE_NAMES[2], 2),
        crate::analyzer::RelationalDefinitionQuery::StructuralMembers { .. } => {
            (QUERY_SHAPE_NAMES[3], 3)
        }
        crate::analyzer::RelationalDefinitionQuery::VisibleMembers { .. } => {
            (QUERY_SHAPE_NAMES[4], 4)
        }
        crate::analyzer::RelationalDefinitionQuery::Identifier { file: Some(_) } => {
            (QUERY_SHAPE_NAMES[5], 5)
        }
        crate::analyzer::RelationalDefinitionQuery::Identifier { file: None } => {
            (QUERY_SHAPE_NAMES[6], 6)
        }
        crate::analyzer::RelationalDefinitionQuery::IdentifierPrefix { file: Some(_) } => {
            (QUERY_SHAPE_NAMES[7], 7)
        }
        crate::analyzer::RelationalDefinitionQuery::IdentifierPrefix { file: None } => {
            (QUERY_SHAPE_NAMES[8], 8)
        }
        crate::analyzer::RelationalDefinitionQuery::PackageTypes { .. } => {
            (QUERY_SHAPE_NAMES[9], 9)
        }
        crate::analyzer::RelationalDefinitionQuery::PackageTypesInPackage => {
            (QUERY_SHAPE_NAMES[10], 10)
        }
        crate::analyzer::RelationalDefinitionQuery::PackageRelation(relation) => match relation {
            PackageRelationKind::Exists => (QUERY_SHAPE_NAMES[11], 11),
            PackageRelationKind::Files => (QUERY_SHAPE_NAMES[12], 12),
            PackageRelationKind::Children => (QUERY_SHAPE_NAMES[13], 13),
            PackageRelationKind::Descendants => (QUERY_SHAPE_NAMES[14], 14),
        },
        crate::analyzer::RelationalDefinitionQuery::CallableFacts => (QUERY_SHAPE_NAMES[15], 15),
    }
}

fn query_count_summary(counts: &[usize; QUERY_SHAPE_COUNT]) -> HashMap<&'static str, usize> {
    counts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count != 0)
        .map(|(index, count)| (QUERY_SHAPE_NAMES[index], count))
        .collect()
}

#[derive(Default)]
struct FrontierState {
    answers: HashMap<RelationalDefinitionQuestion, Arc<RelationalDefinitionValue>>,
    pending_set: HashSet<RelationalDefinitionQuestion>,
    pending: Vec<RelationalDefinitionQuestion>,
    ask_count: usize,
    answer_hit_count: usize,
    batch_count: usize,
}

#[derive(Clone, Copy)]
struct FrontierMetrics {
    answers: usize,
    asks: usize,
    answer_hits: usize,
    batches: usize,
}

impl FrontierMetrics {
    fn delta(self, earlier: Self) -> Self {
        Self {
            answers: self.answers - earlier.answers,
            asks: self.asks - earlier.asks,
            answer_hits: self.answer_hits - earlier.answer_hits,
            batches: self.batches - earlier.batches,
        }
    }
}

/// Request-local recording lookup used by [`resolve_relational_frontier_with`].
///
/// It deliberately has no analyzer or store handle. The graph computation may
/// run in a language crate, while the runner alone crosses back into analysis
/// to execute each newly discovered layer as one relational batch.
#[derive(Default)]
struct RecordingRelationalFrontier {
    state: Mutex<FrontierState>,
}

impl RelationalDefinitionFrontier for RecordingRelationalFrontier {
    fn ask(&self, question: &RelationalDefinitionQuestion) -> RelationalDefinitionValue {
        let mut state = self.state.lock().expect("relational frontier poisoned");
        state.ask_count += 1;
        if let Some(value) = state.answers.get(question).cloned() {
            state.answer_hit_count += 1;
            return value.as_ref().clone();
        }
        if state.pending_set.insert(question.clone()) {
            state.pending.push(question.clone());
        }
        RelationalDefinitionValue::empty_for(&question.query)
    }
}

impl RecordingRelationalFrontier {
    fn take_pending(&self) -> Vec<RelationalDefinitionQuestion> {
        let mut state = self.state.lock().expect("relational frontier poisoned");
        state.pending_set.clear();
        let pending = std::mem::take(&mut state.pending);
        if !pending.is_empty() {
            state.batch_count += 1;
        }
        pending
    }

    fn install(
        &self,
        questions: Vec<RelationalDefinitionQuestion>,
        values: Vec<RelationalDefinitionValue>,
    ) {
        assert_eq!(questions.len(), values.len());
        let mut state = self.state.lock().expect("relational frontier poisoned");
        for (question, value) in questions.into_iter().zip(values) {
            assert!(
                value.matches_query(&question.query),
                "a relational frontier answer must match its query shape"
            );
            let previous = state.answers.insert(question, Arc::new(value));
            assert!(previous.is_none(), "a frontier question is installed once");
        }
    }

    fn answer_snapshot(
        &self,
    ) -> Arc<HashMap<RelationalDefinitionQuestion, Arc<RelationalDefinitionValue>>> {
        Arc::new(
            self.state
                .lock()
                .expect("relational frontier poisoned")
                .answers
                .clone(),
        )
    }

    fn metrics(&self) -> FrontierMetrics {
        let state = self.state.lock().expect("relational frontier poisoned");
        FrontierMetrics {
            answers: state.answers.len(),
            asks: state.ask_count,
            answer_hits: state.answer_hit_count,
            batches: state.batch_count,
        }
    }

    fn query_shape_counts(&self) -> HashMap<&'static str, usize> {
        let state = self.state.lock().expect("relational frontier poisoned");
        let mut counts = HashMap::default();
        for question in state.answers.keys() {
            let (shape, _) = query_shape(&question.query);
            *counts.entry(shape).or_insert(0) += 1;
        }
        counts
    }
}

#[derive(Default)]
struct PendingQuestions {
    set: HashSet<RelationalDefinitionQuestion>,
    ordered: Vec<RelationalDefinitionQuestion>,
}

/// One file worker's read-only view of a converged request answer set.
///
/// Hits never lock. A miss is recorded only in this worker's local recorder;
/// the worker cannot reach an analyzer, connection pool, or SQLite handle.
/// The owning runner executes all missing questions after the parallel barrier.
struct ImmutableRecordingFrontier {
    answers: Arc<HashMap<RelationalDefinitionQuestion, Arc<RelationalDefinitionValue>>>,
    pending: Mutex<PendingQuestions>,
    query_shape_counts: Option<Box<[AtomicUsize; QUERY_SHAPE_COUNT]>>,
}

impl ImmutableRecordingFrontier {
    fn new(
        answers: Arc<HashMap<RelationalDefinitionQuestion, Arc<RelationalDefinitionValue>>>,
    ) -> Self {
        Self {
            answers,
            pending: Mutex::new(PendingQuestions::default()),
            query_shape_counts: crate::profiling::enabled()
                .then(|| Box::new(std::array::from_fn(|_| AtomicUsize::new(0)))),
        }
    }

    fn take_pending(&self) -> Vec<RelationalDefinitionQuestion> {
        let mut pending = self.pending.lock().expect("relational frontier poisoned");
        pending.set.clear();
        std::mem::take(&mut pending.ordered)
    }

    fn query_shape_counts(&self) -> Option<[usize; QUERY_SHAPE_COUNT]> {
        self.query_shape_counts
            .as_ref()
            .map(|counts| std::array::from_fn(|index| counts[index].load(Ordering::Relaxed)))
    }
}

impl RelationalDefinitionFrontier for ImmutableRecordingFrontier {
    fn ask(&self, question: &RelationalDefinitionQuestion) -> RelationalDefinitionValue {
        if let Some(counts) = &self.query_shape_counts {
            counts[query_shape(&question.query).1].fetch_add(1, Ordering::Relaxed);
        }
        if let Some(value) = self.answers.get(question) {
            return value.as_ref().clone();
        }
        let mut pending = self.pending.lock().expect("relational frontier poisoned");
        if pending.set.insert(question.clone()) {
            pending.ordered.push(question.clone());
        }
        RelationalDefinitionValue::empty_for(&question.query)
    }
}

pub(crate) enum RelationalItemFrontierOutcome<T> {
    Complete(Vec<T>),
    Cancelled(Vec<Option<T>>),
    Failed(crate::analyzer::RelationalBatchError),
}

/// Evaluate one finite graph-resolution frontier to a fixed point.
///
/// `evaluate` must return an owned provisional result and must not publish
/// side effects: it can run more than once. Every pass sees all answers from
/// earlier layers. Newly asked questions are deduplicated and executed in one
/// batch; complete empty answers are installed and therefore converge too.
/// The frontier and all hydrated rows are dropped when this function returns.
pub(crate) fn resolve_relational_frontier_with<T>(
    cancellation: &CancellationToken,
    execute: impl FnMut(&[RelationalDefinitionRequest]) -> RelationalBatchOutcome,
    mut evaluate: impl FnMut(&dyn RelationalDefinitionFrontier) -> T,
) -> RelationalFrontierOutcome<T> {
    resolve_relational_frontier_with_owned(cancellation, execute, |frontier| {
        evaluate(frontier.as_ref())
    })
}

/// [`resolve_relational_frontier_with`] with an owned frontier handle.
///
/// Language-crate adapters stored behind `Arc<dyn Trait>` cannot borrow the
/// recorder, but they may own this handle for one replay pass. The handle has
/// no store or analyzer reference and remains request-local; the returned
/// computation must still be owned and side-effect free for the same reason as
/// the borrowed form.
pub(crate) fn resolve_relational_frontier_with_owned<T>(
    cancellation: &CancellationToken,
    execute: impl FnMut(&[RelationalDefinitionRequest]) -> RelationalBatchOutcome,
    evaluate: impl FnMut(Arc<dyn RelationalDefinitionFrontier>) -> T,
) -> RelationalFrontierOutcome<T> {
    let frontier = Arc::new(RecordingRelationalFrontier::default());
    resolve_relational_frontier_on(&frontier, cancellation, execute, evaluate)
}

fn resolve_relational_frontier_on<T>(
    frontier: &Arc<RecordingRelationalFrontier>,
    cancellation: &CancellationToken,
    mut execute: impl FnMut(&[RelationalDefinitionRequest]) -> RelationalBatchOutcome,
    mut evaluate: impl FnMut(Arc<dyn RelationalDefinitionFrontier>) -> T,
) -> RelationalFrontierOutcome<T> {
    loop {
        if cancellation.is_cancelled() {
            return RelationalFrontierOutcome::Cancelled;
        }
        let provisional = evaluate(frontier.clone());
        let questions = frontier.take_pending();
        if questions.is_empty() {
            return RelationalFrontierOutcome::Complete(provisional);
        }
        let requests = questions
            .iter()
            .enumerate()
            .map(|(ordinal, question)| question.request(ordinal))
            .collect::<Vec<_>>();
        let results = match execute(&requests) {
            RelationalBatchOutcome::Complete(results) => results,
            RelationalBatchOutcome::Cancelled => return RelationalFrontierOutcome::Cancelled,
            RelationalBatchOutcome::Failed(error) => {
                crate::profiling::note_with(|| {
                    format!("relational_frontier batch failed: {}", error.message())
                });
                return RelationalFrontierOutcome::Failed(error);
            }
        };
        assert_eq!(results.len(), requests.len());
        let mut values = vec![None; results.len()];
        for result in results {
            assert!(result.ordinal < values.len());
            let slot = &mut values[result.ordinal];
            assert!(
                slot.is_none(),
                "a relational batch returned an ordinal twice"
            );
            *slot = Some(result.value);
        }
        frontier.install(
            questions,
            values
                .into_iter()
                .map(|value| value.expect("a relational batch omitted an ordinal"))
                .collect(),
        );
    }
}

fn resolve_relational_items_with_barriers<I, T>(
    frontier: &Arc<RecordingRelationalFrontier>,
    cancellation: &CancellationToken,
    items: &[I],
    mut execute: impl FnMut(&[RelationalDefinitionRequest]) -> RelationalBatchOutcome,
    evaluate: impl Fn(&I, Arc<dyn RelationalDefinitionFrontier>) -> T + Sync,
) -> RelationalItemFrontierOutcome<T>
where
    I: Sync,
    T: Send,
{
    // Each evaluation builds parser/resolver memo state. Letting a 100+ core
    // host run one item per worker multiplies allocator arenas and peak memory
    // without increasing the amount of useful frontier work. Keep enough tasks
    // to saturate ordinary development machines while bounding that transient
    // state independently of host core count.
    const MAX_PARALLEL_ITEM_EVALUATIONS: usize = 12;
    let mut completed = std::iter::repeat_with(|| None)
        .take(items.len())
        .collect::<Vec<Option<T>>>();
    let mut active = (0..items.len()).collect::<Vec<_>>();
    let mut evaluation_count = 0usize;
    let mut barrier_count = 0usize;
    let mut query_counts = [0usize; QUERY_SHAPE_COUNT];

    loop {
        if cancellation.is_cancelled() {
            crate::profiling::note_with(|| {
                format!(
                    "relational_item_frontier cancelled completed={} evaluations={evaluation_count} barriers={barrier_count}",
                    completed.iter().filter(|result| result.is_some()).count(),
                )
            });
            return RelationalItemFrontierOutcome::Cancelled(completed);
        }

        let answers = frontier.answer_snapshot();
        let chunk_len = active.len().div_ceil(MAX_PARALLEL_ITEM_EVALUATIONS).max(1);
        let passes = active
            .par_chunks(chunk_len)
            .flat_map_iter(|indices| {
                indices.iter().map(|&index| {
                    let item_frontier =
                        Arc::new(ImmutableRecordingFrontier::new(Arc::clone(&answers)));
                    let provisional = evaluate(&items[index], item_frontier.clone());
                    (
                        index,
                        provisional,
                        item_frontier.take_pending(),
                        item_frontier.query_shape_counts(),
                    )
                })
            })
            .collect::<Vec<_>>();
        evaluation_count += passes.len();
        for (_, _, _, counts) in &passes {
            if let Some(counts) = counts {
                for (total, count) in query_counts.iter_mut().zip(counts) {
                    *total += count;
                }
            }
        }
        crate::profiling::note_with(|| {
            format!(
                "relational_item_frontier pass={} active={} cumulative_query_counts={:?}",
                barrier_count + 1,
                passes.len(),
                query_count_summary(&query_counts),
            )
        });

        // A cancelled graph walk may have stopped inside an item. Do not
        // publish any result from that pass, even when it happened not to ask
        // a missing relational question.
        if cancellation.is_cancelled() {
            crate::profiling::note_with(|| {
                format!(
                    "relational_item_frontier cancelled completed={} evaluations={evaluation_count} barriers={barrier_count}",
                    completed.iter().filter(|result| result.is_some()).count(),
                )
            });
            return RelationalItemFrontierOutcome::Cancelled(completed);
        }

        let mut unique_questions = HashSet::default();
        let mut questions = Vec::new();
        let mut next_active = Vec::new();
        for (index, provisional, pending, _) in passes {
            if pending.is_empty() {
                assert!(
                    completed[index].is_none(),
                    "a relational item is published once"
                );
                completed[index] = Some(provisional);
                continue;
            }
            next_active.push(index);
            for question in pending {
                if unique_questions.insert(question.clone()) {
                    questions.push(question);
                }
            }
        }

        if questions.is_empty() {
            assert!(next_active.is_empty());
            crate::profiling::note_with(|| {
                format!(
                    "relational_item_frontier complete items={} evaluations={evaluation_count} barriers={barrier_count} query_counts={:?}",
                    completed.len(),
                    query_count_summary(&query_counts),
                )
            });
            return RelationalItemFrontierOutcome::Complete(
                completed
                    .into_iter()
                    .map(|result| result.expect("every relational item converged"))
                    .collect(),
            );
        }

        barrier_count += 1;
        if crate::profiling::enabled() {
            let mut pending_counts = [0usize; QUERY_SHAPE_COUNT];
            for question in &questions {
                pending_counts[query_shape(&question.query).1] += 1;
            }
            crate::profiling::note_with(|| {
                format!(
                    "relational_item_frontier barrier={barrier_count} questions={} replay_items={} pending_shapes={:?}",
                    questions.len(),
                    next_active.len(),
                    query_count_summary(&pending_counts),
                )
            });
        }
        let requests = questions
            .iter()
            .enumerate()
            .map(|(ordinal, question)| question.request(ordinal))
            .collect::<Vec<_>>();
        let _barrier_scope = crate::profiling::enabled().then(|| {
            crate::profiling::scope(format!(
                "relational_item_frontier::barrier_sql[{}]",
                requests.len()
            ))
        });
        let results = match execute(&requests) {
            RelationalBatchOutcome::Complete(results) => results,
            RelationalBatchOutcome::Cancelled => {
                return RelationalItemFrontierOutcome::Cancelled(completed);
            }
            RelationalBatchOutcome::Failed(error) => {
                crate::profiling::note_with(|| {
                    format!("relational_item_frontier batch failed: {}", error.message())
                });
                return RelationalItemFrontierOutcome::Failed(error);
            }
        };
        assert_eq!(results.len(), requests.len());
        let mut values = std::iter::repeat_with(|| None)
            .take(results.len())
            .collect::<Vec<_>>();
        for result in results {
            assert!(result.ordinal < values.len());
            let slot = &mut values[result.ordinal];
            assert!(
                slot.is_none(),
                "a relational batch returned an ordinal twice"
            );
            *slot = Some(result.value);
        }
        frontier.install(
            questions,
            values
                .into_iter()
                .map(|value| value.expect("a relational batch omitted an ordinal"))
                .collect(),
        );
        active = next_active;
    }
}

/// Request-scoped relational answers shared by several dependent graph
/// computations.
///
/// Each call still evaluates into fresh owned state and replays until its new
/// questions converge. Only immutable, generation-validated SQL answers are
/// retained between calls. The session therefore avoids repeating the same
/// indexed lookup for every file without becoming analyzer-lifetime state or
/// rebuilding a workspace-wide definition materialization.
pub(crate) struct RelationalFrontierSession<'a> {
    analyzer: &'a dyn IAnalyzer,
    cancellation: &'a CancellationToken,
    frontier: Arc<RecordingRelationalFrontier>,
}

impl<'a> RelationalFrontierSession<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer, cancellation: &'a CancellationToken) -> Self {
        Self {
            analyzer,
            cancellation,
            frontier: Arc::new(RecordingRelationalFrontier::default()),
        }
    }

    pub(crate) fn resolve_owned<T>(
        &self,
        phase: &'static str,
        evaluate: impl FnMut(Arc<dyn RelationalDefinitionFrontier>) -> T,
    ) -> RelationalFrontierOutcome<T> {
        let before = self.frontier.metrics();
        let outcome = resolve_relational_frontier_on(
            &self.frontier,
            self.cancellation,
            |requests| {
                self.analyzer
                    .relational_definition_batch(requests, self.cancellation)
            },
            evaluate,
        );
        let after = self.frontier.metrics();
        let delta = after.delta(before);
        crate::profiling::note_with(|| {
            format!(
                "relational_frontier phase={phase} new_answers={} asks={} answer_hits={} batches={} total_answers={} shapes={:?}",
                delta.answers,
                delta.asks,
                delta.answer_hits,
                delta.batches,
                after.answers,
                self.frontier.query_shape_counts(),
            )
        });
        outcome
    }

    /// Resolve ordered independent items over immutable answer snapshots.
    ///
    /// File workers can only read already converged answers and record misses.
    /// The caller thread executes one deduplicated relational batch after each
    /// parallel barrier, then only the items that observed a miss are replayed.
    /// This restores pure semantic file concurrency without multiplying SQLite
    /// readers or publishing provisional empty answers.
    pub(crate) fn resolve_owned_items<I, T>(
        &self,
        phase: &'static str,
        items: &[I],
        evaluate: impl Fn(&I, Arc<dyn RelationalDefinitionFrontier>) -> T + Sync,
    ) -> RelationalItemFrontierOutcome<T>
    where
        I: Sync,
        T: Send,
    {
        let _scope = crate::profiling::scope(format!("relational_item_frontier::{phase}"));
        resolve_relational_items_with_barriers(
            &self.frontier,
            self.cancellation,
            items,
            |requests| {
                self.analyzer
                    .relational_definition_batch(requests, self.cancellation)
            },
            evaluate,
        )
    }
}

pub(crate) fn resolve_relational_frontier<T>(
    analyzer: &dyn IAnalyzer,
    cancellation: &CancellationToken,
    evaluate: impl FnMut(&dyn RelationalDefinitionFrontier) -> T,
) -> RelationalFrontierOutcome<T> {
    resolve_relational_frontier_with(
        cancellation,
        |requests| analyzer.relational_definition_batch(requests, cancellation),
        evaluate,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::fq_name::{SegmentKind, segment_interner};
    use crate::analyzer::{
        DefinitionLanguageScope, FqName, Language, RelationalDefinitionQuery,
        RelationalDefinitionResult,
    };
    use brokk_bifrost_core::analyzer::{PackageRelationKind, PackageRelationValue, RelationalName};
    use std::cell::Cell;

    fn package_question(name: &str) -> RelationalDefinitionQuestion {
        let mut fq = FqName::new();
        fq.push(segment_interner().intern(name, SegmentKind::Package));
        RelationalDefinitionQuestion {
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: RelationalName::stable(fq),
            query: RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
        }
    }

    fn exists(
        frontier: &dyn RelationalDefinitionFrontier,
        question: &RelationalDefinitionQuestion,
    ) -> bool {
        match frontier.ask(question) {
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Exists(value)) => {
                value
            }
            _ => panic!("package existence question returned the wrong shape"),
        }
    }

    #[test]
    fn layered_questions_batch_once_per_discovered_frontier_and_converge_on_empty() {
        let first = package_question("first");
        let second = package_question("second");
        let evaluations = Cell::new(0usize);
        let batches = Cell::new(0usize);
        let outcome = resolve_relational_frontier_with(
            &CancellationToken::new(),
            |requests| {
                batches.set(batches.get() + 1);
                RelationalBatchOutcome::Complete(
                    requests
                        .iter()
                        .map(|request| RelationalDefinitionResult {
                            ordinal: request.ordinal,
                            value: RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(batches.get() == 1),
                            ),
                        })
                        .collect(),
                )
            },
            |frontier| {
                evaluations.set(evaluations.get() + 1);
                let first_exists = exists(frontier, &first);
                let second_exists = first_exists && exists(frontier, &second);
                (first_exists, second_exists)
            },
        );
        assert_eq!(outcome, RelationalFrontierOutcome::Complete((true, false)));
        assert_eq!(batches.get(), 2);
        assert_eq!(evaluations.get(), 3);
    }

    #[test]
    fn one_pass_deduplicates_shape_equivalent_questions() {
        let question = package_question("same");
        let batches = Cell::new(0usize);
        let outcome = resolve_relational_frontier_with(
            &CancellationToken::new(),
            |requests| {
                batches.set(batches.get() + 1);
                assert_eq!(requests.len(), 1);
                RelationalBatchOutcome::Complete(vec![RelationalDefinitionResult {
                    ordinal: 0,
                    value: RelationalDefinitionValue::PackageRelation(
                        PackageRelationValue::Exists(false),
                    ),
                }])
            },
            |frontier| (exists(frontier, &question), exists(frontier, &question)),
        );
        assert_eq!(outcome, RelationalFrontierOutcome::Complete((false, false)));
        assert_eq!(batches.get(), 1);
    }

    #[test]
    fn owned_frontier_supports_request_local_arc_adapters() {
        struct Adapter {
            frontier: Arc<dyn RelationalDefinitionFrontier>,
        }

        let question = package_question("owned");
        let outcome = resolve_relational_frontier_with_owned(
            &CancellationToken::new(),
            |requests| {
                RelationalBatchOutcome::Complete(
                    requests
                        .iter()
                        .map(|request| RelationalDefinitionResult {
                            ordinal: request.ordinal,
                            value: RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(true),
                            ),
                        })
                        .collect(),
                )
            },
            |frontier| {
                let adapter = Adapter { frontier };
                exists(adapter.frontier.as_ref(), &question)
            },
        );
        assert_eq!(outcome, RelationalFrontierOutcome::Complete(true));
    }

    #[test]
    fn cancelled_batch_never_publishes_the_provisional_result() {
        let question = package_question("cancelled");
        let outcome = resolve_relational_frontier_with(
            &CancellationToken::new(),
            |_requests| RelationalBatchOutcome::Cancelled,
            |frontier| exists(frontier, &question),
        );
        assert_eq!(outcome, RelationalFrontierOutcome::Cancelled);
    }

    #[test]
    fn one_request_session_reuses_installed_answers_across_computations() {
        let first = package_question("first");
        let second = package_question("second");
        let frontier = Arc::new(RecordingRelationalFrontier::default());
        let cancellation = CancellationToken::new();
        let batches = Cell::new(0usize);
        let execute = |requests: &[RelationalDefinitionRequest]| {
            batches.set(batches.get() + 1);
            RelationalBatchOutcome::Complete(
                requests
                    .iter()
                    .map(|request| RelationalDefinitionResult {
                        ordinal: request.ordinal,
                        value: RelationalDefinitionValue::PackageRelation(
                            PackageRelationValue::Exists(true),
                        ),
                    })
                    .collect(),
            )
        };

        let first_result =
            resolve_relational_frontier_on(&frontier, &cancellation, execute, |answers| {
                exists(answers.as_ref(), &first)
            });
        assert_eq!(first_result, RelationalFrontierOutcome::Complete(true));
        assert_eq!(batches.get(), 1);

        let second_result =
            resolve_relational_frontier_on(&frontier, &cancellation, execute, |answers| {
                (
                    exists(answers.as_ref(), &first),
                    exists(answers.as_ref(), &second),
                )
            });
        assert_eq!(
            second_result,
            RelationalFrontierOutcome::Complete((true, true))
        );
        assert_eq!(
            batches.get(),
            2,
            "the second computation must query only its newly discovered question"
        );
    }

    #[test]
    fn immutable_item_frontier_batches_at_the_caller_barrier_and_preserves_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let frontier = Arc::new(RecordingRelationalFrontier::default());
        let cancellation = CancellationToken::new();
        let common = package_question("common");
        let seed = resolve_relational_frontier_on(
            &frontier,
            &cancellation,
            |requests| {
                RelationalBatchOutcome::Complete(
                    requests
                        .iter()
                        .map(|request| RelationalDefinitionResult {
                            ordinal: request.ordinal,
                            value: RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(true),
                            ),
                        })
                        .collect(),
                )
            },
            |answers| exists(answers.as_ref(), &common),
        );
        assert_eq!(seed, RelationalFrontierOutcome::Complete(true));

        let caller = std::thread::current().id();
        let batches = AtomicUsize::new(0);
        let evaluations = AtomicUsize::new(0);
        let items = ["third", "first", "second"];
        let outcome = resolve_relational_items_with_barriers(
            &frontier,
            &cancellation,
            &items,
            |requests| {
                assert_eq!(std::thread::current().id(), caller);
                assert_eq!(requests.len(), items.len());
                batches.fetch_add(1, Ordering::Relaxed);
                RelationalBatchOutcome::Complete(
                    requests
                        .iter()
                        .map(|request| RelationalDefinitionResult {
                            ordinal: request.ordinal,
                            value: RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(true),
                            ),
                        })
                        .collect(),
                )
            },
            |item, answers| {
                evaluations.fetch_add(1, Ordering::Relaxed);
                (
                    item.to_string(),
                    exists(answers.as_ref(), &common),
                    exists(answers.as_ref(), &package_question(item)),
                )
            },
        );
        let RelationalItemFrontierOutcome::Complete(results) = outcome else {
            panic!("item frontiers must converge")
        };
        assert_eq!(
            results,
            vec![
                ("third".to_string(), true, true),
                ("first".to_string(), true, true),
                ("second".to_string(), true, true),
            ]
        );
        assert_eq!(batches.load(Ordering::Relaxed), 1);
        assert_eq!(evaluations.load(Ordering::Relaxed), 2 * items.len());
    }

    #[test]
    fn immutable_item_frontier_replays_only_items_that_observed_a_miss() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let frontier = Arc::new(RecordingRelationalFrontier::default());
        let cancellation = CancellationToken::new();
        let ready = package_question("ready");
        let seeded = resolve_relational_frontier_on(
            &frontier,
            &cancellation,
            |requests| {
                RelationalBatchOutcome::Complete(
                    requests
                        .iter()
                        .map(|request| RelationalDefinitionResult {
                            ordinal: request.ordinal,
                            value: RelationalDefinitionValue::PackageRelation(
                                PackageRelationValue::Exists(true),
                            ),
                        })
                        .collect(),
                )
            },
            |answers| exists(answers.as_ref(), &ready),
        );
        assert_eq!(seeded, RelationalFrontierOutcome::Complete(true));

        let ready_evaluations = AtomicUsize::new(0);
        let missing_evaluations = AtomicUsize::new(0);
        let batches = AtomicUsize::new(0);
        let items = ["ready", "missing", "missing"];
        let outcome = resolve_relational_items_with_barriers(
            &frontier,
            &cancellation,
            &items,
            |requests| {
                assert_eq!(requests.len(), 1, "equal misses batch once");
                batches.fetch_add(1, Ordering::Relaxed);
                RelationalBatchOutcome::Complete(vec![RelationalDefinitionResult {
                    ordinal: 0,
                    value: RelationalDefinitionValue::PackageRelation(
                        PackageRelationValue::Exists(false),
                    ),
                }])
            },
            |item, answers| {
                if *item == "ready" {
                    ready_evaluations.fetch_add(1, Ordering::Relaxed);
                } else {
                    missing_evaluations.fetch_add(1, Ordering::Relaxed);
                }
                exists(answers.as_ref(), &package_question(item))
            },
        );
        let RelationalItemFrontierOutcome::Complete(results) = outcome else {
            panic!("item frontiers must converge")
        };
        assert_eq!(results, vec![true, false, false]);
        assert_eq!(batches.load(Ordering::Relaxed), 1);
        assert_eq!(ready_evaluations.load(Ordering::Relaxed), 1);
        assert_eq!(missing_evaluations.load(Ordering::Relaxed), 4);
    }
}
