pub use brokk_bifrost_core::analyzer::common::{
    declaration_language_for_file, declaration_language_for_rel_path, is_unparseable_source,
    language_for_file, language_for_target, languages_may_analyze, workspace_language_for_file,
};
pub(crate) use brokk_bifrost_core::analyzer::common::{
    max_line_length_limit, try_node_source_text,
};
// Each language's identifier sigil moved with the language: Rust's to
// `brokk-bifrost-rust`, C#'s to `brokk-bifrost-csharp` (its one consumer,
// `graph::resolver::node_text`, moved with it). The segment-level `r#` strip
// went to core's `symbol_path`, where the client-selector normalizer that needs
// it lives.

use crate::analyzer::semantic_model::Visibility;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::{
    CodeUnit, FqName, IAnalyzer, Language, Project, ProjectFile, Range, SummaryFileProjection,
};

use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

use crate::hash::{HashMap, HashSet};

#[doc(hidden)]
pub fn read_bounded_source(
    project: &dyn Project,
    file: &ProjectFile,
    max_bytes: usize,
) -> Option<String> {
    project.read_source_limited(file, max_bytes).ok().flatten()
}

#[doc(hidden)]
pub fn limited_known_rows<T>(
    len: usize,
    values: impl IntoIterator<Item = T>,
    limit: usize,
) -> LimitedQueryRows<T> {
    if limit == 0 {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }
    let inspected = len.min(limit);
    let rows = values.into_iter().take(limit).collect();
    if len > limit {
        LimitedQueryRows::incomplete(rows, inspected)
    } else {
        // Callers provide an exact row count, so equality with the cap is complete.
        LimitedQueryRows::complete(rows, inspected)
    }
}

#[doc(hidden)]
pub fn take_little_endian_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Option<[u8; N]> {
    let end = (*offset).checked_add(N)?;
    let value = bytes.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(value)
}

#[doc(hidden)]
pub struct CandidateState<T> {
    #[doc(hidden)]
    pub rows: Vec<T>,
    #[doc(hidden)]
    pub complete: bool,
    #[doc(hidden)]
    pub reason: Option<&'static str>,
}

/// A completed cell with a transient coordinator for concurrent cold fills.
/// Failed attempts live only as long as their wave's callers; the OnceLock
/// itself contains completed values exclusively.
#[doc(hidden)]
#[derive(Debug)]
pub struct QueryCacheCell<T> {
    value: std::sync::OnceLock<T>,
    attempts: crate::analyzer::pool_memo::PoolSafeMemo<T>,
}

impl<T> QueryCacheCell<T> {
    pub fn new() -> Self {
        Self {
            value: std::sync::OnceLock::new(),
            attempts: crate::analyzer::pool_memo::PoolSafeMemo::new(),
        }
    }
}

impl<T> Default for QueryCacheCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> std::ops::Deref for QueryCacheCell<T> {
    type Target = std::sync::OnceLock<T>;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Read a complete shared cell, or return this invocation's unretained answer.
/// Values are cheap owned handles (usually Arc), so a failed build need not be
/// stored on the analyzer merely to satisfy a borrowed result's lifetime.
#[doc(hidden)]
pub fn complete_query_cache_cell<T: Clone + Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    cell: &QueryCacheCell<T>,
    build: impl FnOnce() -> T,
) -> T {
    if let Some(value) = cell.get() {
        return value.clone();
    }
    match cell
        .attempts
        .get_or_try_build_wave_inline(|| shared_query_cache_fill(analyzer, build))
    {
        Ok(value) => cell.value.get_or_init(|| value.as_ref().clone()).clone(),
        Err(failure) => replay_failed_query_cache_build(failure).as_ref().clone(),
    }
}

/// Complete-only publication for an immutable owned cache result.
#[doc(hidden)]
pub fn complete_query_cache_arc_cell<T: Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    cell: &QueryCacheCell<Arc<T>>,
    build: impl FnOnce() -> T,
) -> Arc<T> {
    complete_query_cache_cell(analyzer, cell, || Arc::new(build()))
}

/// A retained answer with the typed evidence of its exact build. Stable
/// artifact gaps are values of the snapshot; transient attempts are not.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct ReplayableQueryCacheValue<T> {
    value: T,
    receipt: Arc<QueryCacheBuildReceipt>,
}

impl<T> ReplayableQueryCacheValue<T> {
    pub fn replay(&self) -> &T {
        self.receipt.replay();
        &self.value
    }
}

impl<T> std::ops::Deref for ReplayableQueryCacheValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.replay()
    }
}

/// Retain snapshot-deterministic incompleteness with its typed receipt. The
/// failed-wave path still shares transient attempts only with their consumers.
/// Named input keys remain in the caller's bounded authority memo; this cell
/// retains completion evidence rather than a second workspace-sized read set.
#[doc(hidden)]
pub fn replayable_query_cache_cell<T: Clone + Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    cell: &QueryCacheCell<ReplayableQueryCacheValue<T>>,
    build: impl FnOnce() -> T,
) -> T {
    if let Some(value) = cell.get() {
        return value.replay().clone();
    }
    let result = cell.attempts.get_or_try_build_wave_inline(|| {
        let (attempt, mut receipt) =
            capture_query_cache_build(analyzer, || replayable_query_cache_fill(analyzer, build));
        let attempt = attempt.inspect(|_| receipt.keys = Arc::default());
        let receipt = Arc::new(receipt);
        let entry = |value| ReplayableQueryCacheValue {
            value,
            receipt: Arc::clone(&receipt),
        };
        attempt.map(entry).map_err(entry)
    });
    match result {
        Ok(value) => cell
            .value
            .get_or_init(|| value.as_ref().clone())
            .replay()
            .clone(),
        Err(failure) => failure.replay().clone(),
    }
}

/// Typed completion and read evidence of one cache build. Transient failures
/// live only with their wave; replayable entries retain stable completion gaps.
#[doc(hidden)]
#[derive(Debug)]
pub struct QueryCacheBuildReceipt {
    keys: Arc<[crate::analyzer::ReadKey]>,
    reasons: Vec<crate::analyzer::QueryReadIncomplete>,
    unattributed_reads: usize,
    execution_dependences: usize,
}

impl QueryCacheBuildReceipt {
    pub fn is_complete(&self) -> bool {
        self.reasons.is_empty() && self.execution_dependences == 0
    }

    pub fn unattributed_reads(&self) -> usize {
        self.unattributed_reads
    }

    pub fn replay(&self) {
        for reason in &self.reasons {
            match reason {
                crate::analyzer::QueryReadIncomplete::StoreFailure(error) => {
                    crate::analyzer::i_analyzer::record_store_error_on_current_contexts(
                        error.clone(),
                    );
                }
                reason => crate::analyzer::i_analyzer::record_query_incomplete_on_current_contexts(
                    reason.clone(),
                ),
            }
        }
        crate::analyzer::i_analyzer::replay_query_read_receipt_on_current_contexts(
            &self.keys,
            self.unattributed_reads,
            self.execution_dependences,
        );
    }
}

#[doc(hidden)]
pub fn capture_query_cache_build<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> T,
) -> (T, QueryCacheBuildReceipt) {
    let ((value, reasons), reads) = crate::analyzer::capture_query_reads(analyzer, || {
        let scope = crate::analyzer::AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        let value = build();
        (value, scope.captured_read_incompleteness())
    });
    (
        value,
        QueryCacheBuildReceipt {
            keys: Arc::from(reads.keys()),
            reasons,
            unattributed_reads: reads.unattributed_reads(),
            execution_dependences: reads.execution_dependences(),
        },
    )
}

struct FailedQueryCacheBuild<T> {
    value: Arc<T>,
    receipt: QueryCacheBuildReceipt,
}

fn shared_query_cache_fill<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> T,
) -> Result<T, FailedQueryCacheBuild<T>> {
    let (attempt, receipt) =
        capture_query_cache_build(analyzer, || complete_query_cache_fill(analyzer, build));
    attempt.map_err(|value| FailedQueryCacheBuild {
        value: Arc::new(value),
        receipt,
    })
}

fn replay_failed_query_cache_build<T>(failure: Arc<FailedQueryCacheBuild<T>>) -> Arc<T> {
    failure.receipt.replay();
    Arc::clone(&failure.value)
}

/// Completed values stay cached; waiters share only their current failed wave.
#[doc(hidden)]
pub fn complete_query_cache_pool<T: Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    memo: &crate::analyzer::pool_memo::PoolSafeMemo<T>,
    build_parallel: impl FnOnce() -> T,
    build_serial: impl FnOnce() -> T,
) -> Arc<T> {
    memo.get_or_try_build_wave(
        || shared_query_cache_fill(analyzer, build_parallel),
        || shared_query_cache_fill(analyzer, build_serial),
    )
    .unwrap_or_else(|failure| replay_failed_query_cache_build(failure))
}

fn shared_optional_query_cache_fill<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> Option<T>,
) -> Result<T, QueryCacheBuildReceipt> {
    let (attempt, receipt) =
        capture_query_cache_build(analyzer, || complete_query_cache_fill(analyzer, build));
    match attempt {
        Ok(Some(value)) => Ok(value),
        Ok(None) | Err(_) => Err(receipt),
    }
}

/// Share failed attempts without keeping a cancelled waiter parked.
#[doc(hidden)]
pub fn complete_query_cache_pool_while<T: Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    memo: &crate::analyzer::pool_memo::PoolSafeMemo<T>,
    keep_going: &impl Fn() -> bool,
    parallel: impl FnOnce() -> Option<T>,
    serial: impl FnOnce() -> Option<T>,
) -> Option<Arc<T>> {
    memo.get_or_try_build_wave_while(
        keep_going,
        || shared_optional_query_cache_fill(analyzer, parallel),
        || shared_optional_query_cache_fill(analyzer, serial),
    )
    .unwrap_or_else(|failure| {
        failure.replay();
        None
    })
}

/// Preserve a store-only memo's pool-independent wait policy.
#[doc(hidden)]
pub fn complete_query_cache_pool_independent<T: Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    memo: &crate::analyzer::pool_memo::PoolSafeMemo<T>,
    build: impl FnOnce() -> T,
) -> Arc<T> {
    memo.get_or_try_build_pool_independent_wave(|| shared_query_cache_fill(analyzer, build))
        .unwrap_or_else(|failure| replay_failed_query_cache_build(failure))
}

/// The dedicated-pool variant preserves the caller's existing execution seam.
#[doc(hidden)]
pub fn complete_query_cache_on_dedicated_pool<T: Send + Sync + 'static>(
    analyzer: &dyn IAnalyzer,
    memo: &crate::analyzer::pool_memo::PoolSafeMemo<T>,
    build: impl FnOnce() -> T + Send,
) -> Arc<T> {
    memo.get_or_try_build_on_dedicated_pool_wave(|| shared_query_cache_fill(analyzer, build))
        .unwrap_or_else(|failure| replay_failed_query_cache_build(failure))
}

/// Values without retained failure evidence cannot replay an incomplete read
/// on a warm hit. Refuse those fills, including deterministic content gaps,
/// without mistaking a content gap for execution dependence.
#[doc(hidden)]
pub fn complete_query_cache_fill<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> T,
) -> Result<T, T> {
    let fill = QueryCacheFill::new(analyzer);
    let value = build();
    if fill.is_complete() {
        Ok(value)
    } else {
        Err(value)
    }
}

/// For cache values that retain every deterministic incomplete-read reason
/// and replay it into each reader's scope. Execution failures are never stored;
/// Err carries only this invocation's best-effort value.
#[doc(hidden)]
pub fn replayable_query_cache_fill<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> T,
) -> Result<T, T> {
    let generation_before = analyzer.project().analysis_generation();
    let ((value, incompleteness), reads) =
        crate::analyzer::i_analyzer::capture_query_reads(analyzer, || {
            let scope =
                crate::analyzer::AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            let value = build();
            (value, scope.captured_read_incompleteness())
        });
    let mut incomplete = false;
    for reason in incompleteness {
        incomplete |= reason.is_execution_dependent();
        analyzer.record_query_incomplete(reason);
    }
    let snapshot_changed = analyzer.project().analysis_generation() != generation_before;
    if incomplete
        || snapshot_changed
        || reads.execution_dependences() > 0
        || analyzer
            .active_query_cancellation()
            .is_some_and(|token| token.is_cancelled())
    {
        crate::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=cache_fill snapshot={snapshot_changed}",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        Err(value)
    } else {
        Ok(value)
    }
}

/// A scoped complete-only fill for accessors that compute before publishing.
/// Its private ledger observes worker marks without losing enclosing reads.
#[doc(hidden)]
pub struct QueryCacheFill<'a> {
    analyzer: &'a dyn IAnalyzer,
    generation_before: u64,
    scope: Option<crate::analyzer::AnalyzerQueryScope<'a>>,
    enclosing: Option<Arc<crate::analyzer::ReadLedger>>,
    reads: Arc<crate::analyzer::ReadLedger>,
}

impl<'a> QueryCacheFill<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        let reads = Arc::new(crate::analyzer::ReadLedger::new());
        let enclosing = analyzer.current_thread_read_ledger();
        let scope = match &enclosing {
            Some(enclosing) => crate::analyzer::AnalyzerQueryScope::with_nested_read_ledger(
                analyzer,
                Arc::clone(&reads),
                Arc::clone(enclosing),
            ),
            None => {
                crate::analyzer::AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&reads))
            }
        };
        Self {
            analyzer,
            generation_before: analyzer.project().analysis_generation(),
            scope: Some(scope),
            enclosing,
            reads,
        }
    }

    pub fn is_complete(&self) -> bool {
        let snapshot_changed =
            self.analyzer.project().analysis_generation() != self.generation_before;
        let cancelled = self
            .analyzer
            .active_query_cancellation()
            .is_some_and(|token| token.is_cancelled());
        if snapshot_changed || cancelled {
            self.analyzer.mark_execution_dependent();
        }
        let completion = self
            .scope
            .as_ref()
            .expect("fill scope stays open until drop")
            .read_completion();
        if completion
            .as_ref()
            .is_err_and(|reason| !reason.is_execution_dependent())
        {
            // No completed cache fact licenses this best-effort answer for a
            // policy unit. Refuse the consumer without classifying a stable
            // content gap as transient execution state.
            self.analyzer.record_unattributed_read();
        }
        completion.is_ok()
            && !snapshot_changed
            && !cancelled
            && self.reads.execution_dependences() == 0
    }
}

impl Drop for QueryCacheFill<'_> {
    fn drop(&mut self) {
        drop(self.scope.take());
        if let Some(enclosing) = &self.enclosing {
            crate::analyzer::i_analyzer::forward_captured_query_reads(enclosing, &self.reads);
        }
    }
}

/// Share a fallible Moka build together with its typed read receipt.
/// Every failed-wave consumer replays that receipt into its own request chain;
/// Moka does not retain the Err for a later wave. The builder decides admission
/// (normally through complete_query_cache_fill), so success and failure may
/// have different payload types, including weighted replay entries.
#[doc(hidden)]
pub fn query_cache_moka<K, V, E>(
    analyzer: &dyn IAnalyzer,
    cache: &moka::sync::Cache<K, V>,
    key: &K,
    build: impl FnOnce() -> Result<V, E>,
) -> Result<V, Arc<E>>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    cache
        .try_get_with_by_ref(key, || {
            let (attempt, receipt) = capture_query_cache_build(analyzer, build);
            attempt.map_err(|value| (Arc::new(value), receipt))
        })
        .map_err(|failure| {
            failure.1.replay();
            Arc::clone(&failure.0)
        })
}

#[doc(hidden)]
pub fn import_target_files_from_cache(
    analyzer: &dyn IAnalyzer,
    cache: &moka::sync::Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    file: &ProjectFile,
    resolve: impl FnOnce() -> HashSet<ProjectFile>,
) -> Arc<HashSet<ProjectFile>> {
    query_cache_moka(analyzer, cache, file, || {
        complete_query_cache_fill(analyzer, || Arc::new(resolve()))
    })
    .unwrap_or_else(|value| Arc::clone(value.as_ref()))
}

impl<T> CandidateState<T> {
    #[doc(hidden)]
    pub fn unavailable(reason: &'static str) -> Self {
        Self {
            rows: Vec::new(),
            complete: false,
            reason: Some(reason),
        }
    }
}

#[doc(hidden)]
pub fn visibility_from_modifier_text(text: &str) -> Visibility {
    match text.trim() {
        "private" => Visibility::Private,
        "protected" => Visibility::Protected,
        _ => Visibility::Public,
    }
}

/// Find the value whose canonical label matches `label`.
pub fn find_by_label<T: Copy>(
    values: impl IntoIterator<Item = T>,
    label: &str,
    label_for: impl Fn(T) -> &'static str,
) -> Option<T> {
    values.into_iter().find(|value| label_for(*value) == label)
}

#[doc(hidden)]
pub fn reuse_cached_expression_value<K, Q, V, N>(
    values: &HashMap<K, V>,
    expression_values: &mut HashMap<N, V>,
    key: &Q,
    expression: N,
) -> Option<V>
where
    K: std::borrow::Borrow<Q> + Eq + std::hash::Hash,
    Q: Eq + std::hash::Hash + ?Sized,
    V: Copy,
    N: Eq + std::hash::Hash,
{
    let value = values.get(key).copied()?;
    expression_values.insert(expression, value);
    Some(value)
}

/// Count serialized JSON bytes without allocating the encoded document.
pub fn serialized_json_len(value: &impl serde::Serialize) -> usize {
    struct ByteCounter(usize);

    impl std::io::Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("serialized byte count overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value).map_or(usize::MAX, |()| counter.0)
}

#[doc(hidden)]
pub fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let name = node.child_by_field_name("name")?;
    let text = try_node_source_text(name, source)?;
    (!text.is_empty()).then(|| Box::from(text))
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn project_file_for_test(root: &Path, rel_path: &str) -> ProjectFile {
    ProjectFile::new(root.to_path_buf(), rel_path)
}

#[doc(hidden)]
pub fn workspace_files_matching_language(
    project: &dyn Project,
    includes_language: impl Fn(Language) -> bool,
) -> Vec<ProjectFile> {
    let Ok(files) = project.all_files_shared() else {
        return Vec::new();
    };
    files
        .iter()
        .filter(|file| includes_language(language_for_file(file)))
        .cloned()
        .collect()
}

#[doc(hidden)]
pub fn integer_literal_value(source: &str, node: Node<'_>) -> Option<i64> {
    integer_literal_value_with_kind(source, node, "integer_literal")
}

#[doc(hidden)]
pub fn integer_literal_value_with_kind(source: &str, node: Node<'_>, kind: &str) -> Option<i64> {
    (node.kind() == kind)
        .then(|| try_node_source_text(node, source))
        .flatten()
        .and_then(|text| text.parse().ok())
}

#[doc(hidden)]
pub fn local_value_for_declaration(
    mut bindings: impl Iterator<Item = (usize, crate::analyzer::semantic::ValueId)>,
    declaration_start: usize,
) -> Option<crate::analyzer::semantic::ValueId> {
    bindings.find_map(|(start, value)| (start == declaration_start).then_some(value))
}

#[doc(hidden)]
pub fn visible_local_binding<T, Key: Ord>(
    bindings: &[T],
    byte: usize,
    bounds: impl Fn(&T) -> (usize, usize, usize),
    key: impl Fn(&T, (usize, usize, usize)) -> Key,
) -> Option<&T> {
    bindings
        .iter()
        .filter(|binding| {
            let (visible_from, scope_start, scope_end) = bounds(binding);
            visible_from <= byte && scope_start <= byte && byte < scope_end
        })
        .min_by_key(|binding| {
            let binding: &T = binding;
            key(binding, bounds(binding))
        })
}

#[doc(hidden)]
pub fn non_synthetic_children(children: Vec<CodeUnit>) -> Vec<CodeUnit> {
    children
        .into_iter()
        .filter(|child| !child.is_synthetic())
        .collect()
}

#[doc(hidden)]
pub fn non_synthetic_summary_projection(
    projection: Arc<SummaryFileProjection>,
) -> Arc<SummaryFileProjection> {
    let mut projection = (*projection).clone();
    for children in projection.children.values_mut() {
        children.retain(|child| !child.is_synthetic());
    }
    Arc::new(projection)
}

#[doc(hidden)]
pub fn should_persist_code_unit(code_unit: &CodeUnit) -> bool {
    !code_unit.is_file_scope() && !code_unit.is_module()
}

#[doc(hidden)]
pub fn dependency_pack_warning(
    code: &str,
    location: &Path,
    message: String,
) -> crate::analyzer::semantic_model::DependencyPackDiagnostic {
    crate::analyzer::semantic_model::DependencyPackDiagnostic {
        severity: crate::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Warning,
        code: code.to_owned(),
        dependency_id: None,
        location: Some(location.display().to_string()),
        message,
    }
}

#[doc(hidden)]
pub fn exact_span(span: crate::analyzer::semantic::SourceSpan, node: Node<'_>) -> bool {
    node.start_byte() == span.start_byte() as usize && node.end_byte() == span.end_byte() as usize
}

pub(crate) const fn same_byte_range(left: Range, right: Range) -> bool {
    left.start_byte == right.start_byte && left.end_byte == right.end_byte
}

#[doc(hidden)]
pub fn is_comment_kind(kind: &str) -> bool {
    brokk_bifrost_core::analyzer::tree_walk::is_comment_kind(kind)
}

#[doc(hidden)]
pub fn display_symbol_name(language: Language, symbol: &str) -> String {
    crate::analyzer::languages::language_knowledge(language).map_or_else(
        || symbol.to_string(),
        |support| support.display_symbol_name(symbol),
    )
}

/// The undecorated spelling of a structured name: [`display_symbol_name`] for
/// a caller that holds the declaration rather than a typed string.
///
/// A language that answers [`LanguageKnowledge::undecorated_fq_name`] answers
/// here from segment kinds, so a `$` or `.` inside a segment's own text
/// survives; the rest fall back to the string reading, which is unchanged.
///
/// [`LanguageKnowledge::undecorated_fq_name`]: brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge::undecorated_fq_name
fn undecorated_fq_name(language: Language, fq: &FqName) -> Option<FqName> {
    crate::analyzer::languages::language_knowledge(language)
        .and_then(|support| support.undecorated_fq_name(fq))
}

fn display_fq_name(language: Language, fq: &FqName, rendered: &str) -> String {
    match undecorated_fq_name(language, fq) {
        Some(undecorated) => {
            undecorated.display_native(language, crate::analyzer::fq_name::segment_interner())
        }
        None => display_symbol_name(language, rendered),
    }
}

/// The qualified spelling a result prints for `target`: its display name when
/// that name still addresses `target` alone, otherwise its indexed name.
///
/// Display normalization exists to hide index decoration nobody writes in
/// source (Scala's companion `$`, C#'s generic arity and nested-owner `$`,
/// TypeScript's `$static` marker). A printed selector is a promise
/// (#1056/#1057), so the undecorated spelling may only be printed when it
/// addresses this declaration and no other. Three shapes break that promise,
/// and each was a fuzz finding:
///
/// * Another declaration owns the undecorated spelling as its own indexed
///   name. Monocle's `object GenLens` declares `apply`, stored `GenLens$.apply`
///   and undecorating to `GenLens.apply`, which is `class GenLens`'s own
///   `apply`; exact-fq resolution answers there, so the object's half of the
///   pair was unreachable (#3302).
/// * Another declaration *with different segment text* would be printed under
///   the same undecorated spelling. A C# nested type and its generic sibling
///   are indexed ``Owner$Name`` and ``Owner$Name`1``: different names, sharing
///   one arity-free display, so the one printed selector resolved ambiguously
///   and addressed neither (#3505). A Scala companion pair is the opposite
///   case -- `CharsetRange$.Atom` and `CharsetRange$.Atom$` carry the *same*
///   segment texts and differ only in the terminal segment's kind, which is
///   one source-written name under two decorations. `distinct_definitions`
///   groups exactly that pair under one selector that answers with both
///   halves (#2451), so a same-text sibling does not contest.
/// * The undecorated spelling addresses nothing at all, because it was derived
///   by re-reading the rendering instead of the structure. That is what
///   [`display_fq_name`] now prevents (#3505).
///
/// Asking those questions of `definitions(display)` keeps the other property
/// too: a decorated declaration whose undecorated spelling is uncontested
/// still prints the idiomatic name.
pub fn display_symbol_for_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> String {
    let target = analyzer.canonical_code_unit(target, None);
    addressable_symbol_name(
        analyzer,
        language_for_target(&target),
        target.fq(),
        target.fq_name_str(),
    )
}

/// The one question [`display_symbol_for_target`] asks: does the undecorated
/// spelling of `fq` address `fq` alone?
fn addressable_symbol_name(
    analyzer: &dyn IAnalyzer,
    language: Language,
    fq: &FqName,
    fq_name: &str,
) -> String {
    let display = display_fq_name(language, fq, fq_name);
    if display == fq_name {
        return display;
    }
    // The same lookup `resolve_codeunit_exact` runs, asked of the undecorated
    // spelling. A candidate contests it when it is a different declaration
    // (overloads share one indexed name and are meant to share one selector)
    // and either owns that spelling outright or is a different *name* that
    // would be printed under it too.
    let contested = analyzer.definitions(&display).any(|other| {
        other.fq_name_str() != fq_name
            && (other.fq_name_str() == display
                || (!fq.same_segment_texts(other.fq())
                    && display_fq_name(
                        language_for_target(&other),
                        other.fq(),
                        other.fq_name_str(),
                    ) == display))
    });
    if contested {
        fq_name.to_string()
    } else {
        display
    }
}

/// One batched store read for the questions [`display_symbol_for_target`] is
/// about to ask of each of `targets`.
///
/// The question is per declaration and the analyzer answers one name per
/// call, so rendering a whole file's summary asked for a store round trip
/// apiece: 110 ms on a 64-file http4s `get_summaries`.
/// `IAnalyzer::prefetch_definitions` is the batch form of exactly that read,
/// and the per-name calls then land in the query-scoped memo it fills.
#[doc(hidden)]
pub fn prefetch_display_symbols<'a>(
    analyzer: &dyn IAnalyzer,
    targets: impl IntoIterator<Item = &'a CodeUnit>,
) {
    let names: Vec<String> = targets
        .into_iter()
        .filter_map(|target| {
            let fq_name = target.fq_name_str();
            let display = display_fq_name(language_for_target(target), target.fq(), fq_name);
            (display != fq_name).then_some(display)
        })
        .collect();
    IAnalyzer::prefetch_definitions(analyzer, &names);
}

/// The indexed qualified name of the code unit's enclosing scope (the
/// receiver/declaring type for a method, the outer type for a nested type), or
/// `None` for a top-level declaration.
///
/// Methods are not always lexically nested in their type (Go receivers, Rust `impl`,
/// C++ out-of-line definitions), so consumers can't reliably reconstruct the parent from
/// line spans. The enclosing scope is the declaration's [`FqName`] with its terminal
/// segment dropped, so that is what this renders: the parent is a *structured* prefix of
/// the name, never a cut of the rendered spelling.
///
/// Deriving the parent by scanning the rendered `short_name` right-to-left for a `.` or
/// `$` cannot be made correct, because those characters are also ordinary segment text:
///
/// * `$` inside a terminal identifier is a name, not a join -- a Java method `render$` or
///   `a$b`, a JS `angular.mock.$LogProvider` or `$http` (the same misreading
///   `split_segments_on_dollar` guards against on the query side, #1057). The scan cut at
///   the last `$` and named `com.example.Gadget.render`, or `angular.mock.` with the
///   trailing separator still attached, as the parent.
/// * A trailing `$` can be a segment's own decoration: a Scala companion object renders
///   `Probe$` / `CharsetRange$.Atom$` ([`SegmentKind::Companion`]), and a TypeScript
///   static member is indexed as `create$static` (one `Member` segment, per
///   `visit_ts_method`). Read as a separator, an object named itself as its own parent.
/// * A `.` can be inside one segment: a JS/TS object-literal key such as
///   `"data/web-interface.csv"` is a single recorded segment (#2111).
///
/// Dropping a whole segment answers all of these the same way, with no per-language
/// pre-stripping: a `$` or `.` that belongs to a segment's text travels with that
/// segment. Rendering the remaining prefix natively also makes `parent_symbol` a genuine
/// prefix of the unit's own indexed spelling by construction,
/// because [`FqName::render_native`] joins each pair of segments from their kinds alone.
///
/// A declaration whose parent prefix is exactly its package prefix is top level and has
/// no enclosing scope: a package is not a parent symbol.
///
/// [`FqName`]: brokk_bifrost_core::analyzer::fq_name::FqName
/// [`FqName::render_native`]: brokk_bifrost_core::analyzer::fq_name::FqName::render_native
/// [`SegmentKind::Companion`]: brokk_bifrost_core::analyzer::fq_name::SegmentKind::Companion
pub(crate) fn parent_fq_for_target(target: &CodeUnit) -> Option<FqName> {
    let fq = target.fq();
    // `CodeUnit::from_fq` asserts a non-empty name whose package prefix leaves a
    // non-empty declaration tail, so the parent prefix always exists and is never
    // shorter than the package prefix.
    let parent_len = fq.len() - 1;
    if parent_len == target.package_segment_count() {
        return None;
    }
    Some(fq.prefix(parent_len))
}

/// [`parent_fq_for_target`] rendered in the target's own language.
#[doc(hidden)]
pub fn parent_fq_name_for_target(target: &CodeUnit) -> Option<String> {
    parent_fq_for_target(target).map(|parent| {
        parent.display_native(
            language_for_target(target),
            crate::analyzer::fq_name::segment_interner(),
        )
    })
}

/// The enclosing scope of [`parent_fq_for_target`], spelled the way
/// [`display_symbol_for_target`] spells the unit itself, so that a printed
/// `parent_symbol` addresses the owner it names.
#[doc(hidden)]
pub fn display_parent_symbol_for_target(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> Option<String> {
    let target = analyzer.canonical_code_unit(target, None);
    let language = language_for_target(&target);
    let parent = parent_fq_for_target(&target)?;
    let parent_fq_name =
        parent.display_native(language, crate::analyzer::fq_name::segment_interner());
    Some(addressable_symbol_name(
        analyzer,
        language,
        &parent,
        &parent_fq_name,
    ))
}

/// The user-facing terminal name of `target`: its recorded terminal segment,
/// respelled the way its language displays a name.
///
/// The terminal boundary is read from the `CodeUnit`'s [`FqName`], never
/// re-derived by splitting the rendered short name on `.`. A terminal segment
/// may legitimately contain a dot or a slash -- a JS/TS object-literal key such
/// as `"data/web-interface.csv"` is one recorded `Member` segment -- and the
/// re-split named such a declaration `csv`, a name that addresses nothing:
/// outlines, document symbols, completion labels and the selector an agent
/// copies from them all pointed at a segment fragment (#2111).
///
/// The undecorated spelling comes from the same structured normalization
/// [`display_symbol_for_target`] uses, read back as the terminal segment's own
/// span. Stripping decoration off the rendered `identifier()` instead cannot
/// tell a Scala object's own trailing `$` from the renderer's (#3505).
///
/// [`FqName`]: brokk_bifrost_core::analyzer::fq_name::FqName
pub fn display_identifier_for_target(target: &CodeUnit) -> String {
    let language = language_for_target(target);
    match undecorated_fq_name(language, target.fq()) {
        Some(undecorated) => {
            let rendered =
                undecorated.render_native(language, crate::analyzer::fq_name::segment_interner());
            rendered.text()[rendered.segment_start(undecorated.len() - 1)..].to_string()
        }
        None => display_symbol_name(language, target.identifier()),
    }
}

pub fn source_identifier_for_target(target: &CodeUnit) -> &str {
    let identifier = target.identifier();
    crate::analyzer::languages::language_knowledge(language_for_target(target))
        .map_or(identifier, |support| support.source_identifier(identifier))
}

/// Whether `identifier` is a spelling a caller can address `target` by: the
/// persisted `identifier`, or the source spelling
/// ([`source_identifier_for_target`]) when the two differ. This is exactly the
/// membership [`decorated_identifier_seeks`] widens the index seek to, so a
/// caller that re-filters seeked rows must use this and not `==` on the raw
/// identifier, or it narrows the seek back to the bug.
pub(crate) fn identifier_addresses_target(target: &CodeUnit, identifier: &str) -> bool {
    target.identifier() == identifier || source_identifier_for_target(target) == identifier
}

/// One key range in the persisted `(lang, identifier)` index.
///
/// `Prefix` is a half-open byte range over the same index, not a scan: see
/// [`decorated_identifier_seeks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentifierSeek {
    Exact(String),
    /// Every identifier that starts with this string.
    Prefix(String),
}

/// The persisted `identifier` spellings, beyond `source_identifier` itself,
/// whose [`source_identifier_for_target`] is `source_identifier`. The exact
/// inverse of that function, per language.
///
/// Symbol lookup seeks the identifier index by the terminal segment of a query
/// path, and compares the rows it gets back against a declaration's lookup
/// aliases. Those aliases are derived from the *source* spelling: `#1063` made
/// the arity-free `Widget` an alias of the C# generic type indexed as
/// ``Widget`1``, and the `$`-splitting variant makes `create` an alias of the
/// TypeScript static member indexed as `create$static`. So an alias tail is
/// *not* always a spelling of the persisted identifier, and a seek for the
/// source spelling alone cannot see those declarations.
///
/// That matters beyond a missed candidate, because two gates in
/// `symbol_lookup` treat an indexed miss as conclusive rather than fall back to
/// a whole-workspace scan (`#1688`, `#1758`; the scan cost 194.3 s and 443.1 s
/// respectively on the measured workspaces). Both gates rest on exactly the
/// claim this function repairs: that seeking the query's terminal finds every
/// candidate an alias comparison could match.
///
/// The returned keys are a candidate filter, never the answer. A prefix range
/// admits spellings that are not decorations at all (``Widget`x`` is not a
/// generic arity), so the caller must still compare
/// `source_identifier_for_target` on each row -- the same seek-then-verify
/// discipline `sql_search_definitions_by_suffix_pattern` uses.
pub(crate) fn decorated_identifier_seeks(
    language: Language,
    source_identifier: &str,
) -> Vec<IdentifierSeek> {
    if source_identifier.is_empty() {
        return Vec::new();
    }
    match language {
        // A generic type or method carries CLR arity: `Widget`1`, and
        // `Widget``2` for a generic method's own parameters. Arity is a digit
        // run of no fixed length, so the decorated spellings are a prefix
        // range rather than an enumerable set.
        Language::CSharp => vec![IdentifierSeek::Prefix(format!("{source_identifier}`"))],
        Language::TypeScript => vec![IdentifierSeek::Exact(format!("{source_identifier}$static"))],
        // A Scala object is indexed with a trailing `$` that its display form
        // drops (`LabelEquivalenceRelation$`); nobody types the marker, so the
        // source spelling's seek must name the decorated row (#2419).
        Language::Scala => vec![IdentifierSeek::Exact(format!("{source_identifier}$"))],
        _ => Vec::new(),
    }
}

#[doc(hidden)]
pub fn is_valid_rename_identifier(language: Language, name: &str) -> bool {
    is_identifier_text(name) && !is_reserved_identifier(language, name)
}

fn is_identifier_text(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn is_reserved_identifier(language: Language, name: &str) -> bool {
    let Some(parser_language) = super::parser_language_for(language) else {
        return false;
    };
    (0..parser_language.node_kind_count()).any(|id| {
        let Ok(id) = u16::try_from(id) else {
            return false;
        };
        !parser_language.node_kind_is_named(id)
            && parser_language.node_kind_for_id(id) == Some(name)
    })
}

/// One unit of pending skeleton-rendering work.
enum SkeletonWork {
    /// Emit `unit`'s signatures, then enqueue its children.
    Render { unit: CodeUnit, indent: String },
    /// Emit the trailing `[...]` elision marker and/or closing brace that
    /// follow a unit's children.
    Close {
        indent: String,
        child_indent: String,
        elide: bool,
        close_brace: bool,
    },
}

/// Render `code_unit`'s skeleton — its signature, then its children indented
/// beneath it, closing class-like units with `}`.
///
/// `header_only` keeps just the field children and marks the elided remainder
/// with `[...]`.
///
/// Shared by the language analyzers that override `direct_children` (to hide
/// synthetic units) and therefore cannot use the engine's own renderer, which
/// reads `TreeSitterAnalyzer::direct_children` directly. Dispatching through
/// `&dyn IAnalyzer` here means each analyzer's overrides still apply.
///
/// Iterative rather than recursive: declaration nesting is attacker-controlled
/// (a generated or hostile source file can nest types thousands deep), so a
/// recursive walk risks exhausting the native stack.
#[doc(hidden)]
pub fn render_skeleton(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    code_unit: &CodeUnit,
    header_only: bool,
) -> String {
    let mut out = String::new();
    let mut stack = vec![SkeletonWork::Render {
        unit: code_unit.clone(),
        indent: String::new(),
    }];

    while let Some(work) = stack.pop() {
        match work {
            SkeletonWork::Render { unit, indent } => {
                for signature in analyzer.signatures(&unit) {
                    if signature.is_empty() {
                        continue;
                    }
                    for line in signature.lines() {
                        out.push_str(&indent);
                        out.push_str(line);
                        out.push('\n');
                    }
                }

                // Kotlin class skeletons omit separate constructor children;
                // the primary constructor is already in the type header. Use
                // the declared role, not synthetic identity, for presentation.
                let all_children = analyzer
                    .direct_children(&unit)
                    .into_iter()
                    .filter(|child| {
                        language_for_target(child) != Language::Kotlin
                            || !analyzer
                                .signature_metadata(child)
                                .iter()
                                .any(|entry| entry.callable_is_constructor())
                    })
                    .collect::<Vec<_>>();
                let all_child_count = all_children.len();
                let is_class = unit.is_class();
                let children: Vec<CodeUnit> = if header_only {
                    all_children
                        .into_iter()
                        .filter(CodeUnit::is_field)
                        .collect()
                } else {
                    all_children
                };

                if children.is_empty() && !is_class {
                    continue;
                }
                let child_indent = format!("{indent}  ");
                // Pushed before the children so it pops after them. The
                // elision marker compares against the pre-filter child count,
                // so it fires exactly when `header_only` dropped something.
                stack.push(SkeletonWork::Close {
                    indent,
                    child_indent: child_indent.clone(),
                    elide: header_only && all_child_count > children.len(),
                    close_brace: is_class,
                });
                for child in children.into_iter().rev() {
                    stack.push(SkeletonWork::Render {
                        unit: child,
                        indent: child_indent.clone(),
                    });
                }
            }
            SkeletonWork::Close {
                indent,
                child_indent,
                elide,
                close_brace,
            } => {
                if elide {
                    out.push_str(&child_indent);
                    out.push_str("[...]\n");
                }
                if close_brace {
                    out.push_str(&indent);
                    out.push_str("}\n");
                }
            }
        }
    }

    out
}

/// Trim trailing whitespace from rendered skeleton output and omit empty results.
#[doc(hidden)]
pub fn normalize_skeleton(rendered: String) -> Option<String> {
    let trimmed = rendered.trim_end();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[doc(hidden)]
pub fn is_scala_object_like(target: &CodeUnit) -> bool {
    language_for_target(target) == Language::Scala && (target.is_class() || target.is_module()) && {
        // A `.`-joined short_name segment "ending in `$`" is exactly a
        // Scala companion-object segment: Scala's only `$`-spelling is
        // the `Companion` kind's trailing suffix on its own segment text
        // (never a join, and Scala never emits `Nested`), so walking the
        // unit's structured `fq()` for a `Companion` segment reproduces
        // the string check exactly without re-splitting the rendered name.
        let interner = crate::analyzer::fq_name::segment_interner();
        target
            .fq()
            .segments()
            .iter()
            .any(|&id| interner.resolve(id).1 == crate::analyzer::fq_name::SegmentKind::Companion)
    }
}

#[doc(hidden)]
pub fn declaration_header(source: &str) -> &str {
    source.split('{').next().unwrap_or(source)
}

pub use crate::analyzer::resolution::file_paths::{
    is_java_module_descriptor_file, rebase_project_file_to_root,
};

pub use crate::analyzer::store::xml_name::local_xml_name;

/// An index pinned for a request, or borrowed from an already retained value.
#[doc(hidden)]
pub enum IndexOwner<'a, T> {
    Borrowed(&'a T),
    Shared(Arc<T>),
}
impl<'a, T> From<&'a T> for IndexOwner<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::Borrowed(value)
    }
}
impl<T> From<Arc<T>> for IndexOwner<'_, T> {
    fn from(value: Arc<T>) -> Self {
        Self::Shared(value)
    }
}
impl<T> std::ops::Deref for IndexOwner<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Self::Borrowed(value) => value,
            Self::Shared(value) => value,
        }
    }
}

/// Producer codes identify the source of a diagnostic. Only enumerated
/// content/configuration failures are stable; unknown codes, I/O and limits
/// remain transient until their producer supplies a stronger contract.
#[doc(hidden)]
pub fn external_index_incompleteness(
    diagnostic: &crate::analyzer::semantic_model::ProducerDiagnostic,
) -> crate::analyzer::QueryReadIncomplete {
    use crate::analyzer::QueryReadIncomplete;
    let detail = format!("{}: {}", diagnostic.code, diagnostic.message).into_boxed_str();
    match diagnostic.code.as_str() {
        "artifact.kind"
        | "artifact.role"
        | "artifact.count"
        | "csharp.metadata.invalid"
        | "csharp.assembly_identity"
        | "csharp.metadata.export_omitted"
        | "java.archive.invalid"
        | "java.class.invalid"
        | "java.source_binary_conflict"
        | "jvm.dependency_unresolved"
        | "jdk.home.unavailable" => QueryReadIncomplete::ArtifactUnavailable(detail),
        "artifact.cancelled" => QueryReadIncomplete::Cancelled,
        _ => QueryReadIncomplete::SemanticEvidenceUnavailable(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_valid_rename_identifier, parent_fq_name_for_target};
    use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use crate::analyzer::{CodeUnit, CodeUnitType, Language, ProjectFile};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn scala_companion_segments_match_object_declarations() {
        use crate::analyzer::usages::get_definition::parse_tree_for_language;
        let dir = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(dir.path(), "Companion.scala");
        let source = "class A {}\nobject A { class B {}\n object B {} }\n";
        let tree = parse_tree_for_language(&file, Language::Scala, source).unwrap();
        assert!(!tree.root_node().has_error());
        let parsed = brokk_bifrost_jvm::scala::declarations::parse_scala_file(&file, source, &tree);
        let units = parsed.declarations();
        let mut stack = vec![tree.root_node()];
        let mut objects = 0;
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "class_definition" | "object_definition") {
                let name = node.child_by_field_name("name").unwrap();
                let name_text = &source[name.byte_range()];
                let is_object = node.kind() == "object_definition";
                let unit = units
                    .iter()
                    .find(|unit| {
                        unit.is_class()
                            && unit.identifier().trim_end_matches('$') == name_text
                            && unit.short_name().ends_with('$') == is_object
                    })
                    .unwrap();
                assert_eq!(
                    super::is_scala_object_like(unit),
                    is_object || name_text == "B"
                );
                objects += usize::from(is_object);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(objects, 2);
    }

    #[test]
    fn bounded_sources_obey_the_filesystem_byte_cap() {
        let dir = tempfile::tempdir().unwrap();
        let project = crate::analyzer::project::TestProject::new(dir.path(), Language::Java);
        for source in ["", "abcd", "\u{e9}\u{65e5}"] {
            let file = ProjectFile::new(dir.path(), "Input.java");
            std::fs::write(file.abs_path(), source).unwrap();
            for cap in [
                0,
                source.len().saturating_sub(1),
                source.len(),
                source.len() + 1,
                usize::MAX,
            ] {
                assert_eq!(
                    super::read_bounded_source(&project, &file, cap),
                    (source.len() <= cap).then(|| source.to_string()),
                    "source={source:?}, cap={cap}"
                );
            }
        }
    }

    #[test]
    fn bounded_batches_account_for_actual_iterator_visits() {
        use std::cell::Cell;
        for len in 0..6 {
            for cap in 0..8 {
                let visits = Cell::new(0);
                let source = (0..len).inspect(|_| visits.set(visits.get() + 1));
                let batch = super::limited_known_rows(len, source, cap);
                assert_eq!(batch.inspected, visits.get());
                assert_eq!(batch.rows, (0..len).take(cap).collect::<Vec<_>>());
                assert_eq!(batch.complete, cap != 0 && len <= cap);
            }
        }
    }

    #[test]
    fn access_modifier_nodes_exclude_comment_words() {
        use crate::analyzer::semantic_model::Visibility;
        use tree_sitter::Parser;
        let source = "class C { public /* private */ a() {} protected /* public */ b() {} private /* protected */ c() {} }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let mut stack = vec![tree.root_node()];
        let mut modifiers = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "accessibility_modifier" {
                modifiers.push((
                    node.start_byte(),
                    super::visibility_from_modifier_text(&source[node.byte_range()]),
                ));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        modifiers.sort_by_key(|(start, _)| *start);
        assert_eq!(
            modifiers
                .into_iter()
                .map(|(_, visibility)| visibility)
                .collect::<Vec<_>>(),
            vec![
                Visibility::Public,
                Visibility::Protected,
                Visibility::Private
            ]
        );
    }

    #[test]
    fn lexical_binding_selection_matches_half_open_grammar_scopes() {
        use crate::analyzer::usages::get_definition::parse_tree_for_language;
        let dir = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(dir.path(), "Scope.java");
        let source = "class C { void f() { int x = 0; { int x = 1; }x++; } }";
        let tree = parse_tree_for_language(&file, Language::Java, source).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut blocks = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "block" {
                blocks.push((node.start_byte(), node.end_byte()));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(blocks.len(), 2);
        for byte in 0..=source.len() {
            // Enumerate the grammar's byte ranges, independently of the lookup's predicates.
            let expected = blocks
                .iter()
                .filter(|(start, end)| (*start..*end).contains(&byte))
                .min_by_key(|(start, end)| end - start);
            let actual = super::visible_local_binding(
                &blocks,
                byte,
                |&(start, end)| (start, start, end),
                |_, (_, start, end)| end - start,
            );
            assert_eq!(actual, expected, "byte={byte}");
        }
    }

    /// `$` inside segment text is ordinary identifier text. Parent boundaries
    /// come from the structured FqName segments, including Scala companion
    /// suffixes and Java nested-class joins.
    #[test]
    #[hardwon(
        "6bffdc94176f+8e5bc37d1cb3: dollar text in Scala, JavaScript, and Java names must not determine parent boundaries"
    )]
    fn dollar_in_segment_text_does_not_define_parent_boundaries() {
        let root = std::env::temp_dir().join("bifrost-common-parent-dollar-test");
        let interner = segment_interner();

        // Top-level `object Probe` -> short_name "Probe$": the trailing `$` must
        // not be read as a separator, so there is no parent.
        let mut scala_top_level_fq = FqName::new();
        scala_top_level_fq.push(interner.intern("com.example", SegmentKind::Package));
        scala_top_level_fq.push(interner.intern("Probe", SegmentKind::Companion));
        let scala_top_level = CodeUnit::from_fq(
            ProjectFile::new(&root, "Probe.scala"),
            CodeUnitType::Class,
            scala_top_level_fq,
            1,
            None,
            false,
        );
        assert_eq!(None, parent_fq_name_for_target(&scala_top_level));

        // Nested Scala companions retain the `$` on the parent segment.
        let mut scala_nested_fq = FqName::new();
        scala_nested_fq.push(interner.intern("org.http4s", SegmentKind::Package));
        scala_nested_fq.push(interner.intern("CharsetRange", SegmentKind::Companion));
        scala_nested_fq.push(interner.intern("Atom", SegmentKind::Companion));
        let scala_nested = CodeUnit::from_fq(
            ProjectFile::new(&root, "CharsetRange.scala"),
            CodeUnitType::Class,
            scala_nested_fq,
            1,
            None,
            false,
        );
        assert_eq!(
            Some("org.http4s.CharsetRange$".to_string()),
            parent_fq_name_for_target(&scala_nested)
        );

        // A leading `$` in a JavaScript identifier does not change its owner.
        let mut javascript_fq = FqName::new();
        javascript_fq.push(interner.intern("angular.mock", SegmentKind::Member));
        javascript_fq.push(interner.intern("$LogProvider", SegmentKind::Member));
        let javascript_member = CodeUnit::from_fq(
            ProjectFile::new(&root, "angular-mocks.js"),
            CodeUnitType::Function,
            javascript_fq,
            0,
            None,
            false,
        );
        assert_eq!(
            Some("angular.mock".to_string()),
            parent_fq_name_for_target(&javascript_member)
        );

        // A bare `$`-prefixed top-level function has no parent.
        let mut javascript_top_level_fq = FqName::new();
        javascript_top_level_fq.push(interner.intern("$LogProvider", SegmentKind::Member));
        let javascript_top_level = CodeUnit::from_fq(
            ProjectFile::new(&root, "log.js"),
            CodeUnitType::Function,
            javascript_top_level_fq,
            0,
            None,
            false,
        );
        assert_eq!(None, parent_fq_name_for_target(&javascript_top_level));

        // `$` at the end or within a Java member remains part of that member.
        let expected_java_parent = Some("com.example.tool.Gadget".to_string());
        for method in ["render$", "a$b", "compute"] {
            let mut fq = FqName::new();
            fq.push(interner.intern("com.example.tool", SegmentKind::Package));
            fq.push(interner.intern("Gadget", SegmentKind::Type));
            fq.push(interner.intern(method, SegmentKind::Member));
            let unit = CodeUnit::from_fq(
                ProjectFile::new(&root, "Gadget.java"),
                CodeUnitType::Function,
                fq,
                1,
                None,
                false,
            );
            assert_eq!(
                expected_java_parent,
                parent_fq_name_for_target(&unit),
                "method `{method}` must report its declaring class"
            );
        }

        // A Java nested-class join IS a boundary because the FqName says so.
        for nested_name in ["Helper", "anon$3:5"] {
            let mut nested_fq = FqName::new();
            nested_fq.push(interner.intern("com.example.tool", SegmentKind::Package));
            nested_fq.push(interner.intern("Gadget", SegmentKind::Type));
            nested_fq.push(interner.intern(nested_name, SegmentKind::Nested));
            let nested = CodeUnit::from_fq(
                ProjectFile::new(&root, "Gadget.java"),
                CodeUnitType::Class,
                nested_fq,
                1,
                None,
                false,
            );
            assert_eq!(
                expected_java_parent,
                parent_fq_name_for_target(&nested),
                "nested class `{nested_name}` must report its outer class"
            );
        }

        // A top-level Java class has no enclosing scope; package is not parent.
        let mut java_top_level_fq = FqName::new();
        java_top_level_fq.push(interner.intern("com.example.tool", SegmentKind::Package));
        java_top_level_fq.push(interner.intern("Gadget", SegmentKind::Type));
        let java_top_level = CodeUnit::from_fq(
            ProjectFile::new(&root, "Gadget.java"),
            CodeUnitType::Class,
            java_top_level_fq,
            1,
            None,
            false,
        );
        assert_eq!(None, parent_fq_name_for_target(&java_top_level));
    }

    /// A TypeScript static member's `$static` marker is part of its own
    /// `Member` segment's text (`visit_ts_method`), so dropping the terminal
    /// segment takes the marker with it. The parent is the class.
    #[test]
    #[hardwon("8e5bc37d1cb3: TypeScript static marker belongs to the terminal member segment")]
    fn typescript_static_marker_is_not_a_parent_separator() {
        let root = std::env::temp_dir().join("bifrost-common-ts-parent-test");
        let interner = segment_interner();

        let mut fq = FqName::new();
        fq.push(interner.intern("Widget", SegmentKind::Type));
        fq.push(interner.intern("create$static", SegmentKind::Member));
        let member = CodeUnit::from_fq(
            ProjectFile::new(&root, "widget.ts"),
            CodeUnitType::Function,
            fq,
            0,
            None,
            false,
        );
        assert_eq!(
            Some("Widget".to_string()),
            parent_fq_name_for_target(&member)
        );
    }

    #[test]
    fn rename_identifier_validation_uses_language_grammar_keywords() {
        assert!(is_valid_rename_identifier(Language::Java, "renamed_1"));
        assert!(is_valid_rename_identifier(Language::Java, "café"));
        assert!(!is_valid_rename_identifier(Language::Java, ""));
        assert!(!is_valid_rename_identifier(Language::Java, "1renamed"));
        assert!(!is_valid_rename_identifier(Language::Java, "renamed-name"));
        assert!(!is_valid_rename_identifier(Language::Java, "class"));
        assert!(!is_valid_rename_identifier(Language::Cpp, "namespace"));
        assert!(!is_valid_rename_identifier(Language::Python, "def"));
        assert!(!is_valid_rename_identifier(Language::Rust, "fn"));
    }
}
