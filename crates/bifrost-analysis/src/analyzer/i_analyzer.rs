use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::store::StoreError;
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder};
use crate::analyzer::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, DefinitionIndexHandle, ExceptionHandlingAnalysis, ExceptionSmellWeights,
    GlobalUsageDefinitionIndex, ImportAnalysisProvider, ParseError, Project, ProjectFile,
    SearchSymbolCandidate, SemanticDiagnosticReport, TestAssertionAnalysis, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider,
    UsageFactsIndex, metrics_from_declarations,
};
use crate::cancellation::CancellationToken;
use crate::gitblob;
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
pub(crate) use brokk_bifrost_core::analyzer::code_unit_index::default_parent_fq_name;
pub use brokk_bifrost_core::analyzer::query_batch::QueryBatch;
pub use brokk_bifrost_core::analyzer::query_token::{QueryScope, QueryToken};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, OnceLock};

/// One analyzer's contribution to a batched symbol-search request.
///
/// `complete` is false when cooperative cancellation stopped enumeration.
/// Callers may retain the candidates produced before that checkpoint, but
/// must not present an incomplete batch as an authoritative search result.
#[doc(hidden)]
pub type SearchSymbolCandidates = QueryBatch<SearchSymbolCandidate>;

#[derive(Debug, Clone)]
enum CompiledSymbolPatterns {
    Set(RegexSet),
    Individual(Vec<Regex>),
}

/// A request-scoped, language-neutral symbol matcher shared by every analyzer delegate.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SearchSymbolPatternBatch {
    patterns: Vec<String>,
    auto_quote: bool,
    compiled: Option<CompiledSymbolPatterns>,
    /// One required-literal set per *compiled* pattern, in the same order, set
    /// only when every compiled pattern contributed at least one literal.
    ///
    /// A batch is prefiltered in SQL as `OR` over patterns of `AND` over that
    /// pattern's literals, so a single pattern without a required literal makes
    /// the whole disjunction unconditionally true and is stored as `None`
    /// instead.
    required_literals: Option<Vec<Vec<String>>>,
    complete: bool,
}

impl SearchSymbolPatternBatch {
    pub fn compile(
        patterns: Vec<String>,
        auto_quote: bool,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Self {
        let mut compiled_patterns = Vec::new();
        let mut compiled_regexes = Vec::new();
        let mut required_literals = Vec::new();
        for pattern in &patterns {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return Self {
                    patterns,
                    auto_quote,
                    compiled: None,
                    required_literals: None,
                    complete: false,
                };
            }
            let pattern = normalize_search_pattern(pattern, auto_quote);
            if let Ok(compiled) = RegexBuilder::new(&pattern).case_insensitive(true).build() {
                // Extract from the normalized pattern, which is the exact text
                // the authoritative matcher compiled.
                required_literals.push(required_storage_literals(&pattern));
                compiled_patterns.push(pattern);
                compiled_regexes.push(compiled);
            }
        }

        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return Self {
                patterns,
                auto_quote,
                compiled: None,
                required_literals: None,
                complete: false,
            };
        }
        let required_literals = (!required_literals.is_empty()
            && required_literals
                .iter()
                .all(|literals| !literals.is_empty()))
        .then_some(required_literals);
        let compiled = if compiled_patterns.is_empty() {
            None
        } else {
            match RegexSetBuilder::new(&compiled_patterns)
                .case_insensitive(true)
                .build()
            {
                Ok(set) => Some(CompiledSymbolPatterns::Set(set)),
                Err(_) => Some(CompiledSymbolPatterns::Individual(compiled_regexes)),
            }
        };
        Self {
            patterns,
            auto_quote,
            compiled,
            required_literals,
            complete: true,
        }
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    pub fn auto_quote(&self) -> bool {
        self.auto_quote
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn is_match(&self, value: &str) -> bool {
        match &self.compiled {
            Some(CompiledSymbolPatterns::Set(patterns)) => patterns.is_match(value),
            Some(CompiledSymbolPatterns::Individual(patterns)) => {
                patterns.iter().any(|pattern| pattern.is_match(value))
            }
            None => false,
        }
    }

    /// Return the per-pattern required-literal sets that a storage prefilter can
    /// be built from, or `None` when at least one pattern in the batch has no
    /// required literal at all.
    ///
    /// Every returned set is non-empty, and every literal in a set occurs in
    /// each name the corresponding pattern matches, so the prefilter stays a
    /// strict superset of the authoritative regular-expression match.
    pub(crate) fn required_storage_literals(&self) -> Option<&[Vec<String>]> {
        self.required_literals.as_deref()
    }
}

/// Bound on the literals kept for one pattern. Each literal is required, so
/// dropping some only widens the prefilter, and a pattern like `a.b.c.d.e.f`
/// would otherwise spend more per row on single-character `LIKE` probes than
/// the scan it replaces.
const MAX_LITERALS_PER_PATTERN: usize = 4;

/// Extract the ASCII substrings that every name matching `pattern` must
/// contain, in the charset the persisted name projection can be searched with.
///
/// The walk is over the parsed regular expression (`regex-syntax`'s HIR), not
/// over the pattern text: a literal is collected only from HIR positions that
/// every match has to traverse, so the result is a sound prefilter and the
/// regular expression stays authoritative. An empty result means "no prefilter".
///
/// Two deliberate restrictions:
///
/// * Only `[A-Za-z0-9_]` bytes join a literal; anything else (including `.`)
///   ends the run. This is the charset the pure-literal pushdown this replaces
///   already assumed, and it is what keeps a literal inside one name segment:
///   the fully-qualified name a pattern is matched against is the hydrated
///   package prefix joined to the short name with `.`, so a run without `.`
///   cannot straddle that join and is visible in one of the three channels the
///   storage prefilter probes.
/// * Case is left to SQLite's `LIKE`, which folds ASCII only. That is a
///   superset of a case-sensitive match and of `(?i)` over ASCII. A name that
///   reaches an extracted ASCII letter only through non-ASCII Unicode case
///   folding (U+212A KELVIN SIGN, U+017F LATIN SMALL LETTER LONG S) is not
///   covered, exactly as it was not covered before this change.
fn required_storage_literals(pattern: &str) -> Vec<String> {
    let Ok(hir) = regex_syntax::Parser::new().parse(pattern) else {
        return Vec::new();
    };
    reduce_literals(hir_literals(&hir).into_required())
}

/// What one HIR node forces every string it matches to contain.
#[derive(Debug, Default)]
struct RequiredLiterals {
    /// Set when the node matches exactly one string and that string is entirely
    /// in the storage charset. Concatenation can then extend it, which is what
    /// recovers `Solver` from the per-character classes a `(?i)` group parses to.
    exact: Option<String>,
    /// Storage-charset substrings that every match of the node contains.
    substrings: Vec<String>,
}

impl RequiredLiterals {
    fn exact(text: String) -> Self {
        Self {
            exact: Some(text),
            substrings: Vec::new(),
        }
    }

    fn into_required(mut self) -> Vec<String> {
        if let Some(text) = self.exact.take().filter(|text| !text.is_empty()) {
            self.substrings.push(text);
        }
        self.substrings
    }
}

/// Post-order HIR walk with an explicit stack: regex nesting is bounded by the
/// parser's nest limit, but the analyzer walks every tree iteratively.
fn hir_literals(hir: &regex_syntax::hir::Hir) -> RequiredLiterals {
    use regex_syntax::hir::HirKind;

    enum Step<'a> {
        Visit(&'a regex_syntax::hir::Hir),
        /// Combine the last `usize` results on the result stack.
        Concat(usize),
        Alternate(usize),
        /// A repetition that must run at least once; a `min == 0` repetition
        /// requires nothing and never reaches the result stack.
        RepeatAtLeastOnce,
    }

    let mut work = vec![Step::Visit(hir)];
    let mut results: Vec<RequiredLiterals> = Vec::new();
    while let Some(step) = work.pop() {
        match step {
            Step::Visit(node) => match node.kind() {
                // A zero-width assertion neither contributes a literal nor
                // separates its neighbours: the text around it stays adjacent.
                HirKind::Empty | HirKind::Look(_) => {
                    results.push(RequiredLiterals::exact(String::new()));
                }
                HirKind::Literal(literal) => results.push(literal_node_literals(&literal.0)),
                HirKind::Class(class) => results.push(class_node_literals(class)),
                HirKind::Capture(capture) => work.push(Step::Visit(capture.sub.as_ref())),
                HirKind::Repetition(repetition) => {
                    if repetition.min == 0 {
                        results.push(RequiredLiterals::default());
                    } else {
                        work.push(Step::RepeatAtLeastOnce);
                        work.push(Step::Visit(repetition.sub.as_ref()));
                    }
                }
                HirKind::Concat(subs) => {
                    work.push(Step::Concat(subs.len()));
                    work.extend(subs.iter().rev().map(Step::Visit));
                }
                HirKind::Alternation(subs) => {
                    work.push(Step::Alternate(subs.len()));
                    work.extend(subs.iter().rev().map(Step::Visit));
                }
            },
            Step::RepeatAtLeastOnce => {
                // The node matches its child at least once, so the child's
                // literals are required; the repeat count is unknown, so the
                // child's exact text cannot be extended by a neighbour.
                let child = results.pop().expect("repetition child result");
                results.push(RequiredLiterals {
                    exact: None,
                    substrings: child.into_required(),
                });
            }
            Step::Concat(len) => {
                let children = results.split_off(results.len() - len);
                results.push(concat_literals(children));
            }
            Step::Alternate(len) => {
                let children = results.split_off(results.len() - len);
                results.push(alternation_literals(children));
            }
        }
    }
    results.pop().expect("one result per parsed pattern")
}

fn concat_literals(children: Vec<RequiredLiterals>) -> RequiredLiterals {
    let mut run = String::new();
    let mut substrings = Vec::new();
    let mut every_child_exact = true;
    for child in children {
        match child.exact {
            Some(text) => run.push_str(&text),
            None => {
                every_child_exact = false;
                if !run.is_empty() {
                    substrings.push(std::mem::take(&mut run));
                }
                substrings.extend(child.substrings);
            }
        }
    }
    if every_child_exact {
        RequiredLiterals::exact(run)
    } else {
        if !run.is_empty() {
            substrings.push(run);
        }
        RequiredLiterals {
            exact: None,
            substrings,
        }
    }
}

/// An alternation requires only what every branch requires, compared as whole
/// literals: `(?:FooBar|FooBaz)` yields nothing rather than the common `Foo`,
/// because a shared prefix is not what the branch results carry.
fn alternation_literals(children: Vec<RequiredLiterals>) -> RequiredLiterals {
    let mut branches = children.into_iter();
    let Some(first) = branches.next() else {
        return RequiredLiterals::default();
    };
    let exact = first.exact.clone();
    let mut shared = first.into_required();
    let mut same_exact = exact.is_some();
    for branch in branches {
        same_exact &= branch.exact == exact;
        let required = branch.into_required();
        shared.retain(|literal| required.contains(literal));
    }
    if same_exact {
        RequiredLiterals::exact(exact.unwrap_or_default())
    } else {
        RequiredLiterals {
            exact: None,
            substrings: shared,
        }
    }
}

fn literal_node_literals(bytes: &[u8]) -> RequiredLiterals {
    if bytes.iter().all(|byte| is_storage_byte(*byte)) {
        return RequiredLiterals::exact(storage_run(bytes));
    }
    RequiredLiterals {
        exact: None,
        substrings: bytes
            .split(|byte| !is_storage_byte(*byte))
            .filter(|run| !run.is_empty())
            .map(storage_run)
            .collect(),
    }
}

/// A class contributes a literal character only when it denotes exactly one
/// storage character, or exactly one storage letter's two ASCII cases -- the
/// shape `(?i)x` translates to. Non-ASCII members are ignored per the ASCII
/// case rule documented on `required_storage_literals`.
fn class_node_literals(class: &regex_syntax::hir::Class) -> RequiredLiterals {
    use regex_syntax::hir::Class;

    let mut ascii = Vec::new();
    let mut push = |start: u32, end: u32| {
        for scalar in start..=end.min(0x7f) {
            let byte = u8::try_from(scalar).expect("ASCII scalar fits one byte");
            if ascii.len() <= 2 {
                ascii.push(byte);
            }
        }
    };
    match class {
        Class::Unicode(class) => {
            for range in class.ranges() {
                push(u32::from(range.start()), u32::from(range.end()));
            }
        }
        Class::Bytes(class) => {
            for range in class.ranges() {
                push(u32::from(range.start()), u32::from(range.end()));
            }
        }
    }
    let single = match ascii.as_slice() {
        [byte] => Some(*byte),
        [upper, lower] if upper.is_ascii_uppercase() && *lower == upper.to_ascii_lowercase() => {
            Some(*lower)
        }
        _ => None,
    };
    single
        .filter(|byte| is_storage_byte(*byte))
        .map_or_else(RequiredLiterals::default, |byte| {
            RequiredLiterals::exact(storage_run(&[byte]))
        })
}

/// Keep the literals that carry selectivity: compare case-insensitively (the
/// prefilter does), drop a literal another kept literal already contains, and
/// keep the longest few.
fn reduce_literals(literals: Vec<String>) -> Vec<String> {
    let mut literals = literals
        .into_iter()
        .map(|mut literal| {
            literal.make_ascii_lowercase();
            literal
        })
        .collect::<Vec<_>>();
    literals.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    let mut kept: Vec<String> = Vec::new();
    for literal in literals {
        if kept.len() == MAX_LITERALS_PER_PATTERN {
            break;
        }
        if !kept.iter().any(|longer| longer.contains(&literal)) {
            kept.push(literal);
        }
    }
    kept
}

fn is_storage_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn storage_run(bytes: &[u8]) -> String {
    debug_assert!(
        bytes.iter().all(|byte| is_storage_byte(*byte)),
        "storage runs are ASCII by construction: {bytes:?}"
    );
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn normalize_search_pattern(pattern: &str, auto_quote: bool) -> String {
    if auto_quote {
        if pattern.contains(".*") {
            pattern.to_string()
        } else {
            format!(".*?{}.*?", regex::escape(pattern))
        }
    } else {
        escape_sigil_anchors(pattern)
    }
}

/// Escape anchor metacharacters only where they form part of an identifier token.
fn escape_sigil_anchors(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut escaped = String::with_capacity(pattern.len());
    for (index, ch) in chars.iter().enumerate() {
        let prev_is_word = index > 0
            && (chars[index - 1].is_alphanumeric() || matches!(chars[index - 1], '_' | '^'));
        let next_is_word = chars
            .get(index + 1)
            .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '$'));
        let unsatisfiable = match ch {
            '$' => next_is_word || prev_is_word,
            '^' => prev_is_word,
            _ => false,
        };
        if unsatisfiable {
            escaped.push('\\');
        }
        escaped.push(*ch);
    }
    escaped
}

/// Failure state and deadline for one top-level analyzer request.
///
/// The analyzer trait intentionally retains best-effort collection-returning APIs, so persisted
/// implementations record storage failures here before returning their compatibility fallback.
/// Service boundaries inspect the context before presenting a successful response.
///
/// The context also carries the request's cancellation token, because a
/// request's deadline has to be visible at the depth where the request spends
/// its time. `IAnalyzer`'s read APIs take no token -- `definitions(fq_name)` is
/// a plain lookup -- yet one of those reads can be the single longest thing a
/// scan does: on the rustc tree `definitions` for a hot short name such as
/// `main` is a 1.14 s store read, issued from inside the polled import-graph
/// walk, and it was the whole of the `scan_usages` deadline overshoot. Passing
/// the token through every read signature would mean a cancellation parameter
/// on most of `IAnalyzer`; carrying it on the request boundary that already
/// exists gives the same reach without one.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct AnalyzerQueryContext {
    first_store_error: Mutex<Option<StoreError>>,
    cancellation: Option<CancellationToken>,
    /// Storage-funnel crossings observed while this request boundary was
    /// active, one counter per [`InformationTier`]. Scopes nest, so an access
    /// made under an inner scope is recorded on every enclosing scope too:
    /// each of them did pay for it.
    tier_accesses: [AtomicUsize; InformationTier::COUNT],
}

/// One rung of the information-cost ladder (issue #2414).
///
/// Bifrost answers a query by consuming progressively more expensive derived
/// information, and the recurring defect family behind #2414 is a query path
/// that should stay on a cheap rung silently reaching a costlier one while
/// staying functionally correct. The variants are ordered cheap to expensive
/// by convention, and their discriminants index the per-scope counters above.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InformationTier {
    /// A per-file tree-sitter parse.
    Syntax,
    /// A store read of a file's import statements.
    Imports,
    /// A store read of a code unit's raw supertypes.
    Supertypes,
    /// A build of the whole-workspace usage/definition index.
    UsageGraph,
}

impl InformationTier {
    pub const COUNT: usize = 4;

    pub const ALL: [InformationTier; Self::COUNT] = [
        InformationTier::Syntax,
        InformationTier::Imports,
        InformationTier::Supertypes,
        InformationTier::UsageGraph,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Analyzer-snapshot-owned query caches. The container is public only because
/// `IAnalyzer` is an extension boundary; concrete cache representations remain
/// crate-private and can evolve without coupling external analyzers to query
/// execution internals.
#[doc(hidden)]
#[derive(Default)]
pub struct AnalyzerSnapshotCaches {
    derived_layers: crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache,
    usage_graphs: crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache,
    semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache,
}

impl AnalyzerSnapshotCaches {
    pub(crate) fn new(derived_layer_budget_bytes: u64) -> Self {
        Self {
            derived_layers:
                crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache::new(
                    derived_layer_budget_bytes,
                ),
            usage_graphs: crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache::new(
                derived_layer_budget_bytes,
            ),
            semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache::new(
                derived_layer_budget_bytes,
            ),
        }
    }

    pub(crate) fn derived_layers(
        &self,
    ) -> &crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache {
        &self.derived_layers
    }

    pub(crate) fn usage_graphs(
        &self,
    ) -> &crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache {
        &self.usage_graphs
    }

    pub(crate) fn semantic_models(
        &self,
    ) -> &crate::analyzer::semantic_model::SemanticModelRuntimeCache {
        &self.semantic_models
    }

    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        self.semantic_models.overlay()
    }

    fn active_semantic_models(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::ResolvedActiveSemanticModels>> {
        self.semantic_models.active()
    }

    #[cfg(test)]
    pub(crate) fn retain_dependency_discovery_evidence(
        &self,
        languages: &[crate::analyzer::Language],
        evidence: crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
    ) {
        self.semantic_models
            .retain_dependency_discovery_evidence(languages, evidence);
    }

    pub(crate) fn invalidate_dependency_pack_state(
        &self,
        languages: &[crate::analyzer::Language],
    ) -> bool {
        self.semantic_models
            .invalidate_dependency_pack_state(languages)
    }

    fn dependency_discovery_evidence(
        &self,
        language: crate::analyzer::Language,
    ) -> Option<Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>> {
        self.semantic_models.dependency_discovery_evidence(language)
    }
}

/// Every workspace file bucketed by basename, captured by one ignore-aware
/// listing of the project tree.
///
/// This is what `WorkspaceFileResolver` needs to answer "which file does the
/// bare name `Widget.cs` mean?", and building it costs a whole-workspace walk.
/// The type lives beside the query-scope machinery rather than in
/// `path_utils` because the *cell* holding it is request-scoped analyzer state
/// (`IAnalyzer::workspace_file_index_cell`), exactly like
/// `AnalyzerSnapshotCaches`: `IAnalyzer` is a public extension boundary, so the
/// container must be nameable from the trait signature even though its
/// representation stays crate-private.
#[doc(hidden)]
#[derive(Debug)]
pub struct WorkspaceFileIndex {
    root: std::path::PathBuf,
    /// The bucketed listing, or the error that prevented it.
    ///
    /// The failure is carried here rather than returned from
    /// [`WorkspaceFileIndex::build`] because the index is published through a
    /// shared `OnceLock` whose `get_or_init` cannot carry one, and dropping the
    /// single-flight guarantee to gain a `Result` would restore the repeated
    /// whole-workspace walk that cell exists to eliminate (#1334). Discarding
    /// the failure and keeping an empty map is the alternative this replaces:
    /// it made a failed listing indistinguishable from a workspace in which
    /// every path anchor genuinely does not exist (#2325).
    by_basename: Result<crate::hash::HashMap<String, Vec<ProjectFile>>, String>,
}

/// The request-scoped, single-flight cell that holds one [`WorkspaceFileIndex`].
///
/// `Arc<OnceLock<..>>` for the same reason `top_level_class_units_by_package`
/// uses it (#1194): resolvers are built concurrently inside `rayon` closures,
/// and a check-then-build-then-store `Option` would let every thread that
/// missed the check redo the same whole-workspace walk.
#[doc(hidden)]
pub type WorkspaceFileIndexCell = Arc<OnceLock<Arc<WorkspaceFileIndex>>>;

impl WorkspaceFileIndex {
    /// One ignore-aware listing of `project`, bucketed by basename.
    pub(crate) fn build(project: &dyn Project) -> Self {
        Self {
            root: project.root().to_path_buf(),
            by_basename: Self::bucket_by_basename(project),
        }
    }

    fn bucket_by_basename(
        project: &dyn Project,
    ) -> Result<crate::hash::HashMap<String, Vec<ProjectFile>>, String> {
        let files = project
            .all_files()
            .map_err(|err| format!("listing workspace files under {:?}: {err}", project.root()))?;
        let mut by_basename: crate::hash::HashMap<String, Vec<ProjectFile>> = Default::default();
        for file in files {
            let Some(name) = file.rel_path().file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            by_basename.entry(name.to_string()).or_default().push(file);
        }
        for matches in by_basename.values_mut() {
            matches.sort();
        }
        Ok(by_basename)
    }

    /// Whether this index describes the workspace rooted at `root`. A shared
    /// cell is scoped to one request, and a request can legitimately touch more
    /// than one analyzer (reference differentials hold a before/after pair), so
    /// consumers must confirm the cached listing is about *their* workspace
    /// before trusting it.
    pub(crate) fn covers(&self, root: &std::path::Path) -> bool {
        self.root == root
    }

    /// The workspace files named `basename`, or the listing failure that makes
    /// the question unanswerable. `Ok(None)` means the workspace was listed and
    /// holds no such file; `Err` must not be reported as that answer.
    pub(crate) fn matches(&self, basename: &str) -> Result<Option<&[ProjectFile]>, &str> {
        match &self.by_basename {
            Ok(by_basename) => Ok(by_basename.get(basename).map(Vec::as_slice)),
            Err(error) => Err(error),
        }
    }
}

impl AnalyzerQueryContext {
    pub fn with_cancellation(cancellation: CancellationToken) -> Self {
        Self {
            first_store_error: Mutex::new(None),
            cancellation: Some(cancellation),
            tier_accesses: Default::default(),
        }
    }

    /// Records one crossing of `tier`'s storage funnel under this request.
    pub fn record_tier_access(&self, tier: InformationTier) {
        self.tier_accesses[tier.index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Crossings of `tier`'s storage funnel observed while this request was
    /// active. Read relaxed: the counts are advisory bounds for tests and
    /// diagnostics, not a synchronization edge.
    pub fn tier_access_count(&self, tier: InformationTier) -> usize {
        self.tier_accesses[tier.index()].load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The deadline this request is running under, if its opener set one.
    pub fn cancellation(&self) -> Option<&CancellationToken> {
        self.cancellation.as_ref()
    }

    pub fn record_store_error(&self, error: StoreError) {
        let mut slot = self
            .first_store_error
            .lock()
            .expect("analyzer query error mutex poisoned");
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    pub fn store_error(&self) -> Option<StoreError> {
        self.first_store_error
            .lock()
            .expect("analyzer query error mutex poisoned")
            .clone()
    }
}

pub trait IAnalyzer: CodeUnitIndex + Send + Sync + Any {
    /// Test-only counter hooks, quarantined behind one accessor so the
    /// analyzer contract does not carry twenty-one instrumentation methods in
    /// every build. The accessor is feature-gated rather than the hooks being a
    /// side trait: the root integration suites enable `test-support` and call
    /// these through `&dyn IAnalyzer`.
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn AnalyzerTestHooks {
        &NoOpAnalyzerTestHooks
    }

    /// Starts a top-level query boundary. Persisted analyzers use this to
    /// memoize filesystem liveness checks for the duration of one request.
    fn begin_query(&self, _context: &Arc<AnalyzerQueryContext>) {}

    /// Ends a top-level query boundary and releases request-scoped memoized state.
    fn end_query(&self, _context: &Arc<AnalyzerQueryContext>) {}

    /// Starts a disposable, file-local analyzer read used by broad sequential
    /// consumers such as semantic materialization.
    #[doc(hidden)]
    fn begin_streaming_file_read(&self, _file: &ProjectFile) {}

    /// Ends the matching disposable file-local read.
    #[doc(hidden)]
    fn end_streaming_file_read(&self, _file: &ProjectFile) {}

    /// Releases idle connections and page caches owned by the streaming path.
    #[doc(hidden)]
    fn release_streaming_readers(&self) {}

    /// The cell in which the active request memoizes its workspace file
    /// listing, or `None` when no query scope is open.
    ///
    /// Resolving a bare or dotted name to a workspace file needs every file's
    /// basename, which costs a full ignore-aware tree walk. That walk was paid
    /// once per `WorkspaceFileResolver`, and resolvers are constructed per call
    /// site and per symbol — so one `get_symbol_sources` request over N dotted
    /// C# names walked the repository O(N) times (#1334). The listing is stable
    /// for the duration of one request by the same argument the rest of the
    /// read cache rests on, so it is memoized against the request scope rather
    /// than a process-global cache with bespoke invalidation.
    #[doc(hidden)]
    fn workspace_file_index_cell(&self) -> Option<WorkspaceFileIndexCell> {
        None
    }

    /// Record a failure that a collection-returning read could not return, on
    /// every request boundary this analyzer currently has open.
    ///
    /// This is the producer side of [`AnalyzerQueryContext`]: a best-effort API
    /// that answers with a collection has no way to say "the answer is not
    /// zero results, it is unknown", so it records the failure here and the
    /// service boundary turns the apparently successful response into an error
    /// (`WorkspaceQueryScope::finish`). Without it a failed workspace listing
    /// or store probe reads as genuine absence (#2325).
    ///
    /// The default is a no-op because an analyzer that opens no request
    /// boundary has no context to record on.
    #[doc(hidden)]
    fn record_query_failure(&self, _error: StoreError) {}

    /// Build the expensive lazily-initialized per-generation query indexes
    /// ahead of demand (#1442). Idempotent and safe to call from a background
    /// thread: concurrent demand for the same index blocks on its one-time
    /// initialization instead of double-building, and calling this on an
    /// already-warm analyzer generation is free. The default warms nothing.
    fn warm_query_indexes(&self) {}

    /// Whether every index `warm_query_indexes` would build is already built
    /// for this analyzer generation. Analyzers with nothing to warm are
    /// always warm.
    fn query_indexes_warm(&self) -> bool {
        true
    }

    /// Drop any cached bulk working-tree identities before an explicit
    /// from-disk rebuild. Implementations without such a cache do nothing.
    fn invalidate_cached_file_identities(&self) {}

    /// The repository-wide Git identity scan this analyzer already took for its
    /// workspace, when it has one.
    ///
    /// A host that must derive its own content identities for the same worktree
    /// -- the semantic indexer does, because the semantic cache keys on the
    /// bytes Git shows rather than on the bytes tree-sitter parsed -- takes this
    /// instead of re-reading the Git index and re-diffing the working tree. On
    /// firefox that duplicate read cost 4.1 s over 401,804 index entries at cold
    /// start, immediately after the analyzer had scanned the same entries.
    ///
    /// `None` means no scan is available and the caller must take its own.
    fn working_tree_identity(&self) -> Option<Arc<gitblob::WorkingTreeIdentity>> {
        None
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized;

    fn update_all(&self) -> Self
    where
        Self: Sized;

    fn global_usage_definition_index(&self) -> DefinitionIndexHandle<'_> {
        static EMPTY: OnceLock<GlobalUsageDefinitionIndex> = OnceLock::new();
        DefinitionIndexHandle::Single(EMPTY.get_or_init(GlobalUsageDefinitionIndex::default))
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        static EMPTY: OnceLock<UsageFactsIndex> = OnceLock::new();
        EMPTY.get_or_init(UsageFactsIndex::default)
    }

    /// Return the declaration node's tree-sitter kind when structured syntax
    /// for this exact code unit is available.
    fn declaration_syntax_kind(&self, _code_unit: &CodeUnit) -> Option<&'static str> {
        None
    }

    /// Return the tree-sitter parse errors recorded for `file` during the
    /// most recent `analyze_file` pass. Returns `None` when the analyzer
    /// holds no state for this file (file outside the analyzer's language,
    /// `FileState` hydrated from the persisted baseline this session and
    /// not yet re-parsed, or analysis failed); callers fall back to a fresh
    /// parse in that case. An empty `Some(...)` means the file parsed
    /// cleanly. Today's `TreeSitterAnalyzer` impl clones the cached `Vec`
    /// per call — fine on clean files (the vec is empty), but a buffer
    /// mid-edit with many errors does one alloc per request. Acceptable
    /// while the second-parse cost still dominates; revisit by switching
    /// the return type to `Option<&[ParseError]>` (needs a lifetime on the
    /// trait method) or wrapping in `Arc<[ParseError]>` if it shows up in
    /// profiles.
    fn parse_errors(&self, _file: &ProjectFile) -> Option<Vec<ParseError>> {
        None
    }

    fn semantic_diagnostics(&self, _file: &ProjectFile, _source: &str) -> SemanticDiagnosticReport {
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(
            None,
            vec![
                crate::analyzer::SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: "analyzer does not implement semantic diagnostics".to_string(),
                },
            ],
        );
        report
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String>;

    fn import_statements(&self, _file: &ProjectFile) -> Vec<String> {
        Vec::new()
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo>;

    /// Search candidates with the metadata needed by `search_symbols`. The
    /// default preserves existing analyzer behavior; persisted analyzers
    /// override it with a projection that avoids full file hydration.
    fn search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> SearchSymbolCandidates {
        let mut candidates = Vec::new();
        let mut inspected = 0usize;
        if !patterns.complete() {
            return SearchSymbolCandidates::incomplete(candidates, inspected);
        }
        for pattern in patterns.patterns() {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return SearchSymbolCandidates::incomplete(candidates, inspected);
            }
            for code_unit in self.search_definitions(pattern, patterns.auto_quote()) {
                if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                    return SearchSymbolCandidates::incomplete(candidates, inspected);
                }
                inspected = inspected.saturating_add(1);
                candidates.push(SearchSymbolCandidate {
                    primary_range: self
                        .ranges(&code_unit)
                        .into_iter()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    // Structurally-evidenced suppression only: analyzers without a
                    // per-declaration taint surface default untainted here (path-based
                    // test filtering in `search_symbols` still applies), so production
                    // symbols in a file with inline tests are never hidden (#1102).
                    in_test_region: self.in_test_region(&code_unit),
                    is_type_alias: self
                        .type_alias_provider()
                        .is_some_and(|provider| provider.is_type_alias(&code_unit)),
                    code_unit,
                });
            }
        }
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            SearchSymbolCandidates::incomplete(candidates, inspected)
        } else {
            SearchSymbolCandidates::complete(candidates, inspected)
        }
    }

    /// The physical parts of a declaration the language spells in several
    /// pieces (a C# `partial` type), including `code_unit` itself. `None`
    /// means this analyzer does not model partial declarations at all —
    /// which is different from `Some(vec![code_unit])`, a modeled declaration
    /// with exactly one part (issue #1475).
    fn partial_declaration_parts(&self, _code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        None
    }

    /// The concrete members that implement an abstract member (a Rust trait
    /// member's impl items). `None` means this analyzer does not model the
    /// implementation relation, or `code_unit` is not an abstract member it
    /// can enumerate implementations for (issue #1475).
    fn abstract_member_implementations(&self, _code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        None
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.import_statements(file)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        None
    }

    /// Import provider for one file. Composite analyzers override this to
    /// distinguish a language with no import capability from a supported
    /// language whose file simply has no imports.
    fn import_analysis_provider_for_file(
        &self,
        _file: &ProjectFile,
    ) -> Option<&dyn ImportAnalysisProvider> {
        self.import_analysis_provider()
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        None
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        None
    }

    /// Exact method-family edges for one member (#1477 M4).
    ///
    /// `None` is the honest default: a language whose analyzer has not landed
    /// an override/implements relation says so, and the query layer reports an
    /// `unsupported` outcome instead of an empty exhaustive answer. There is
    /// deliberately no default `supported` implementation.
    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        None
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        None
    }

    /// Per-language structural-search capabilities (issue #328), one provider
    /// per language whose adapter has a structural spec. Languages without a
    /// spec are absent; `query_code` reports them as capability diagnostics
    /// instead of silently returning nothing.
    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        Vec::new()
    }

    /// The complete semantic declaration overlay published for this analyzer
    /// snapshot, if active semantic models have been acquired successfully.
    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        self.snapshot_caches()
            .and_then(AnalyzerSnapshotCaches::semantic_model_overlay)
    }

    /// The activated semantic-model set published for this analyzer snapshot,
    /// if a host has acquired active semantic models against it (#2437).
    ///
    /// This is the same publication `semantic_model_overlay` reads, and it is
    /// how the detailed-query path reaches a pack's `declared_effects` without
    /// opening its own activation: a host that already ran
    /// `acquire_active_semantic_models` — the policy coordinator, the MCP
    /// service, a test — makes those declarations visible here. An analyzer
    /// with no publication answers `None`, and every effect row then states an
    /// unmodeled callee rather than a proven absence.
    fn active_semantic_models(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::ResolvedActiveSemanticModels>> {
        self.snapshot_caches()
            .and_then(AnalyzerSnapshotCaches::active_semantic_models)
    }

    /// Dependency-discovery evidence a host retained for `language`'s
    /// ecosystem, if discovery has run against this analyzer at all. This
    /// reads what the analyzer already holds; it never triggers discovery.
    fn dependency_discovery_evidence(
        &self,
        language: crate::analyzer::Language,
    ) -> Option<Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>> {
        self.snapshot_caches()
            .and_then(|caches| caches.dependency_discovery_evidence(language))
    }

    /// Snapshot-owned immutable derived query layers. Concrete analyzers keep
    /// the default when they cannot bind a complete snapshot lifecycle.
    #[doc(hidden)]
    fn snapshot_caches(&self) -> Option<&AnalyzerSnapshotCaches> {
        None
    }

    /// Monotonic source generations covered by the snapshot-owned derived
    /// layer cache. A composite analyzer overrides this with one ordered entry
    /// per delegate so a change outside its primary project cannot reuse stale
    /// workspace-wide relations.
    #[doc(hidden)]
    fn snapshot_source_generations(&self) -> Box<[u64]> {
        Box::new([self.project().analysis_generation()])
    }

    /// Allocation-free freshness check for a previously captured generation
    /// vector. Composite analyzers override this to compare every delegate in
    /// the same deterministic order as [`Self::snapshot_source_generations`].
    #[doc(hidden)]
    fn snapshot_generations_match(&self, expected: &[u64]) -> bool {
        expected == [self.project().analysis_generation()]
    }

    fn autocomplete_definitions(&self, query: &str) -> Vec<CodeUnit> {
        if query.is_empty() {
            return Vec::new();
        }

        let base_results = self.search_definitions(&format!(".*?{query}.*?"), false);

        // Short prefixes additionally run a fuzzy `c.*?h.*?a.*?r` pass to
        // surface camelCase matches the strict substring wouldn't catch. Skip
        // that pass when the strict pass already saturated downstream caps:
        // every reasonable caller truncates somewhere ≤ AUTOCOMPLETE_SATURATION,
        // so the fuzzy pass can only contribute items that will be discarded.
        // This is the dominant cost on per-keystroke completion paths.
        const AUTOCOMPLETE_SATURATION: usize = 1000;
        let fuzzy_results = if query.len() < 5 && base_results.len() < AUTOCOMPLETE_SATURATION {
            let mut pattern = String::from(".*?");
            for ch in query.chars() {
                pattern.push_str(&regex::escape(&ch.to_string()));
                pattern.push_str(".*?");
            }
            self.search_definitions(&pattern, false)
        } else {
            BTreeSet::new()
        };

        let mut by_fq_name: BTreeMap<String, BTreeSet<CodeUnit>> = BTreeMap::new();
        for code_unit in base_results.into_iter().chain(fuzzy_results) {
            by_fq_name
                .entry(code_unit.fq_name())
                .or_default()
                .insert(code_unit);
        }

        let mut merged: Vec<_> = by_fq_name
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .filter(|code_unit| !code_unit.is_synthetic())
            .collect();
        merged.sort_by(autocomplete_definitions_sort_comparator);
        merged
    }

    fn as_capability<T: Any>(&self) -> Option<&T>
    where
        Self: Sized,
    {
        (self as &dyn Any).downcast_ref::<T>()
    }

    /// Find call sites and references to the given overloads using the default
    /// [`UsageFinder`] strategy. The free function [`crate::analyzer::usages::find_usages`] is the
    /// equivalent for callers that hold a `&dyn IAnalyzer`.
    fn find_usages(&self, overloads: &[CodeUnit]) -> FuzzyResult
    where
        Self: Sized,
    {
        UsageFinder::new().find_usages(self, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
    }

    /// Like [`Self::find_usages`] but returns the candidate file set alongside the result.
    fn query_usages(
        &self,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> crate::analyzer::usages::QueryResult
    where
        Self: Sized,
    {
        UsageFinder::new().query(self, overloads, max_files, max_usages)
    }

    fn metrics(&self) -> CodeBaseMetrics {
        metrics_from_declarations(self.all_declarations())
    }

    fn contains_tests(&self, _file: &ProjectFile) -> bool {
        false
    }

    /// Whether `code_unit` sits in a structurally-evidenced test region — a
    /// test-attributed item, or a declaration nested inside a `#[cfg(test)]`
    /// (or otherwise test-attributed) module/item (issue #1102).
    ///
    /// Unlike [`contains_tests`](Self::contains_tests), which classifies whole
    /// files, this is per declaration, so symbol-level test filtering can hide a
    /// file's test symbols while still surfacing its production API. Analyzers
    /// that do not thread per-declaration taint default to `false` (untainted):
    /// structurally-evidenced suppression only.
    fn in_test_region(&self, _code_unit: &CodeUnit) -> bool {
        false
    }

    /// Whether `file` is compiled only into test builds, on structural evidence
    /// that lives *outside* the file (issue #1546).
    ///
    /// This exists because Rust's sibling test-module layout puts the gate on
    /// the parent's `#[cfg(test)] mod tests;` declaration: `tests.rs` matches no
    /// path convention, sits under no test directory, and its plain helper
    /// functions carry no test attribute, so neither
    /// [`contains_tests`](Self::contains_tests) nor any path rule can see it.
    ///
    /// Unlike `contains_tests`, which answers "does this file define tests",
    /// this answers "can production code reach this file at all", so a
    /// production file full of inline `#[cfg(test)] mod tests { .. }` is `false`
    /// here while a test-only file that defines no test of its own is `true`.
    /// Analyzers whose language has no such out-of-file gate default to `false`.
    fn file_is_test_only(&self, _file: &ProjectFile) -> bool {
        false
    }

    /// Compute heuristic cognitive complexity for every function-like code
    /// unit declared in `file`, preserving source order.
    ///
    /// The default implementation returns an empty vector — analyzers that
    /// expose tree-sitter ASTs override this with a per-language scorer.
    /// Callers must treat a missing key as "not computed" rather than
    /// "complexity is zero".
    fn compute_cognitive_complexities(&self, _file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        Vec::new()
    }

    /// Comment density for a single declaration. All tree-sitter-backed
    /// languages use the shared parser-backed implementation; specialized
    /// analyzers may override it when they need compatibility behavior.
    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        crate::analyzer::comment_density::for_code_unit(self, code_unit)
    }

    /// Comment density for the first resolved declaration that supports it.
    /// Mirrors brokk-shared `IAnalyzer.commentDensity(String)`.
    fn comment_density_by_fq_name(&self, fq_name: &str) -> Option<CommentDensityStats> {
        self.get_definitions(fq_name)
            .into_iter()
            .find_map(|cu| self.comment_density(&cu))
    }

    /// Per-top-level-declaration comment density for a parsed source file.
    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        crate::analyzer::comment_density::by_top_level(self, file)
    }

    /// Detect suspicious exception-handling sites in `file` using `weights`.
    /// Analyzers without an implementation return an explicit unsupported
    /// result so callers cannot mistake missing semantics for a clean file.
    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        crate::analyzer::exception_handling::analyze_for_file(self, file, weights)
    }

    /// Detect suspicious low-value or brittle test assertions in `file`
    /// using `weights`. Default is an empty vector so analyzers that do not
    /// yet implement this heuristic stay silent.
    fn find_test_assertion_smells(
        &self,
        _file: &ProjectFile,
        _weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        Vec::new()
    }

    /// Detect assertion-smell candidates with an optional work budget.
    /// Structured bounded implementations should override this method. The
    /// default preserves complete legacy analysis without candidate accounting.
    fn find_test_assertion_smells_limited(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
        _max_candidates: usize,
    ) -> TestAssertionAnalysis {
        TestAssertionAnalysis {
            findings: self.find_test_assertion_smells(file, weights),
            inspected_candidates: None,
            truncated: false,
        }
    }

    fn find_structural_clone_smells(
        &self,
        _file: &ProjectFile,
        _weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        Vec::new()
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        files
            .iter()
            .flat_map(|file| self.find_structural_clone_smells(file, weights))
            .collect()
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .flat_map(|file| self.top_level_declarations(file))
            .map(|code_unit| {
                if code_unit.is_module() {
                    code_unit.fq_name()
                } else {
                    code_unit.package_name().to_string()
                }
            })
            .filter(|module| !module.is_empty())
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        files
            .iter()
            .flat_map(|file| self.top_level_declarations(file))
            .filter(|code_unit| {
                code_unit.is_class() || code_unit.is_function() || code_unit.is_module()
            })
            .collect()
    }

    fn get_symbols(&self, sources: &BTreeSet<CodeUnit>) -> BTreeSet<String> {
        let mut symbols = BTreeSet::new();
        for source in sources {
            symbols.insert(source.identifier().to_string());
            if source.is_class() || source.is_module() {
                for child in self.direct_children(source) {
                    symbols.insert(child.identifier().to_string());
                }
            }
        }
        symbols
    }

    fn list_symbols(&self, file: &ProjectFile) -> String {
        self.list_symbols_with_types(file, &all_code_unit_types())
    }

    fn list_top_level_symbols(&self, file: &ProjectFile) -> String {
        summarize_code_units_impl(
            self,
            &summary_root_units(self, file),
            &all_code_unit_types(),
            0,
            false,
        )
    }

    fn list_symbols_with_types(
        &self,
        file: &ProjectFile,
        types: &BTreeSet<CodeUnitType>,
    ) -> String {
        summarize_code_units_impl(self, &summary_root_units(self, file), types, 0, true)
    }
}

/// The `*_for_test` counter hooks, reached through
/// [`IAnalyzer::test_hooks`]. Every method keeps the no-op / `0` default the
/// hook carried on `IAnalyzer`, so an implementor that instruments nothing
/// inherits [`NoOpAnalyzerTestHooks`] and behaves exactly as before.
#[cfg(any(test, feature = "test-support"))]
pub trait AnalyzerTestHooks {
    #[doc(hidden)]
    fn reset_global_usage_definition_index_build_count_for_test(&self) {}

    #[doc(hidden)]
    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_definition_candidates_query_count_for_test(&self) {}

    #[doc(hidden)]
    fn definition_candidates_query_count_for_test(&self) -> usize {
        0
    }

    /// Batched import-target prefetches issued by candidate discovery (#1748):
    /// one per language group per request, against the per-candidate
    /// `definition_candidates` reads the batch replaces.
    #[doc(hidden)]
    fn reset_definition_prefetch_batch_count_for_test(&self) {}

    #[doc(hidden)]
    fn definition_prefetch_batch_count_for_test(&self) -> usize {
        0
    }

    /// Store round trips the definition-candidate row read actually issued,
    /// as distinct from the calls that were served by the request's
    /// single-flight memo.
    #[doc(hidden)]
    fn reset_definition_candidate_row_read_count_for_test(&self) {}

    #[doc(hidden)]
    fn definition_candidate_row_read_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_full_declaration_scan_count_for_test(&self) {}

    #[doc(hidden)]
    fn full_declaration_scan_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_search_candidate_hydration_count_for_test(&self) {}

    /// Declarations a symbol search hydrated into `CodeUnit`s. Bounded work
    /// means this tracks the matched answer, not the workspace (#1199).
    #[doc(hidden)]
    fn search_candidate_hydration_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_package_declaration_scan_count_for_test(&self) {}

    #[doc(hidden)]
    fn package_declaration_scan_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_candidate_hydration_count_for_test(&self) {}

    #[doc(hidden)]
    fn candidate_hydration_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn full_candidate_hydration_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_workspace_path_scan_count_for_test(&self) {}

    #[doc(hidden)]
    fn workspace_path_scan_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_scala_project_types_build_count_for_test(&self) {}

    #[doc(hidden)]
    fn scala_project_types_build_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn reset_scala_query_scan_counts_for_test(&self) {}

    #[doc(hidden)]
    fn scala_query_parse_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn scala_query_walk_count_for_test(&self) -> usize {
        0
    }
}

/// The hooks object every implementor that instruments nothing shares.
#[cfg(any(test, feature = "test-support"))]
pub struct NoOpAnalyzerTestHooks;

#[cfg(any(test, feature = "test-support"))]
impl AnalyzerTestHooks for NoOpAnalyzerTestHooks {}

/// Releases request-scoped analyzer memoization on every return path.
pub struct AnalyzerQueryScope<'a> {
    analyzer: &'a dyn IAnalyzer,
    context: Arc<AnalyzerQueryContext>,
}

impl<'a> AnalyzerQueryScope<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        let context = Arc::new(AnalyzerQueryContext::default());
        analyzer.begin_query(&context);
        Self { analyzer, context }
    }

    /// Open a request boundary that carries the caller's deadline, so reads
    /// issued anywhere below it can stop when that deadline expires.
    pub fn with_cancellation(
        analyzer: &'a dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Self {
        let context = Arc::new(AnalyzerQueryContext::with_cancellation(
            cancellation.clone(),
        ));
        analyzer.begin_query(&context);
        Self { analyzer, context }
    }

    pub fn store_error(&self) -> Option<StoreError> {
        self.context.store_error()
    }

    /// How often `tier`'s storage funnel was crossed since this scope opened
    /// (issue #2414). This is the executable form of "a tier-N query touches
    /// no tier-N+1 storage": open a scope, run the query, assert the tiers it
    /// must not reach report zero.
    pub fn tier_access_count(&self, tier: InformationTier) -> usize {
        self.context.tier_access_count(tier)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn record_store_error_for_test(&self, error: StoreError) {
        self.context.record_store_error(error);
    }
}

/// The one mint for [`QueryToken`]: an open scope proves request-scoped
/// memoization is active, which is exactly what the syntax accessors demand.
impl QueryScope for AnalyzerQueryScope<'_> {}

impl Drop for AnalyzerQueryScope<'_> {
    fn drop(&mut self) {
        self.analyzer.end_query(&self.context);
    }
}

/// Releases one disposable file-local analyzer read on every return path.
/// Public for the brokk-bifrost-nlp chunker, the streaming consumer.
pub struct AnalyzerStreamingFileScope<'a> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
}

impl<'a> AnalyzerStreamingFileScope<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, file: &'a ProjectFile) -> Self {
        analyzer.begin_streaming_file_read(file);
        Self { analyzer, file }
    }
}

impl Drop for AnalyzerStreamingFileScope<'_> {
    fn drop(&mut self) {
        self.analyzer.end_streaming_file_read(self.file);
    }
}

fn summary_root_units<A: IAnalyzer + ?Sized>(analyzer: &A, file: &ProjectFile) -> Vec<CodeUnit> {
    let declarations: Vec<_> = analyzer.declarations(file).into_iter().collect();
    let declaration_set: BTreeSet<_> = declarations.iter().cloned().collect();
    let mut roots: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| {
            analyzer
                .parent_of(code_unit)
                .map(|parent| parent.is_module() || !declaration_set.contains(&parent))
                .unwrap_or(true)
        })
        .collect();
    roots.sort_by(|left, right| summary_root_order(analyzer, left, right));
    roots
}

fn summary_root_order<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    left: &CodeUnit,
    right: &CodeUnit,
) -> Ordering {
    let left_range = analyzer.ranges(left).into_iter().min();
    let right_range = analyzer.ranges(right).into_iter().min();
    left_range.cmp(&right_range).then_with(|| left.cmp(right))
}

fn summarize_code_units_impl<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    units: &[CodeUnit],
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
    recursive: bool,
) -> String {
    let indent_str = "  ".repeat(indent);
    let mut summary = String::new();

    if indent == 0 && !units.is_empty() {
        let mut grouped: Vec<(String, Vec<CodeUnit>)> = Vec::new();
        for code_unit in units {
            if code_unit.is_anonymous() || code_unit.is_module() {
                continue;
            }

            let fq_name = code_unit.fq_name();
            let group_prefix = fq_name
                .rfind('.')
                .filter(|index| *index > 0)
                .map(|index| fq_name[..index].to_string())
                .unwrap_or_default();

            if let Some((_, group_units)) = grouped
                .iter_mut()
                .find(|(prefix, _)| prefix == &group_prefix)
            {
                group_units.push(code_unit.clone());
            } else {
                grouped.push((group_prefix, vec![code_unit.clone()]));
            }
        }

        for (group_prefix, group_units) in grouped {
            if !group_prefix.is_empty() {
                summary.push_str("# ");
                summary.push_str(&group_prefix);
                summary.push('\n');
            }

            for code_unit in group_units {
                render_symbol_summary(
                    analyzer,
                    &mut summary,
                    &code_unit,
                    types,
                    indent,
                    &indent_str,
                    recursive,
                );
            }
        }
    } else {
        for code_unit in units {
            if code_unit.is_anonymous() {
                continue;
            }
            render_symbol_summary(
                analyzer,
                &mut summary,
                code_unit,
                types,
                indent,
                &indent_str,
                recursive,
            );
        }
    }

    summary.trim_end().to_string()
}

fn render_symbol_summary<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    summary: &mut String,
    code_unit: &CodeUnit,
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
    indent_str: &str,
    recursive: bool,
) {
    summary.push_str(indent_str);
    summary.push_str("- ");
    summary.push_str(&display_identifier_for_target(code_unit));

    if recursive {
        let children: Vec<_> = ordered_summary_children(
            analyzer,
            code_unit,
            analyzer
                .direct_children(code_unit)
                .into_iter()
                .filter(|child| types.contains(&child.kind()))
                .collect(),
        );
        if !children.is_empty() {
            summary.push('\n');
            summary.push_str(&summarize_code_units_impl(
                analyzer,
                &children,
                types,
                indent + 1,
                recursive,
            ));
        }
    }
    summary.push('\n');
}

fn ordered_summary_children<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    parent: &CodeUnit,
    children: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    if children.len() < 2 {
        return children;
    }

    let parent_start = analyzer
        .ranges(parent)
        .iter()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX);
    let mut ordered = Vec::with_capacity(children.len());
    ordered.extend(children.iter().filter(|child| child.is_field()).cloned());
    ordered.extend(
        children
            .iter()
            .filter(|child| !child.is_field() && child_first_start(analyzer, child) >= parent_start)
            .cloned(),
    );
    ordered.extend(
        children
            .iter()
            .filter(|child| !child.is_field() && child_first_start(analyzer, child) < parent_start)
            .cloned(),
    );
    ordered
}

fn child_first_start<A: IAnalyzer + ?Sized>(analyzer: &A, child: &CodeUnit) -> usize {
    analyzer
        .ranges(child)
        .iter()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX)
}

fn all_code_unit_types() -> BTreeSet<CodeUnitType> {
    [
        CodeUnitType::Class,
        CodeUnitType::Function,
        CodeUnitType::Field,
        CodeUnitType::Module,
        CodeUnitType::Macro,
    ]
    .into_iter()
    .collect()
}

fn autocomplete_definitions_sort_comparator(left: &CodeUnit, right: &CodeUnit) -> Ordering {
    autocomplete_rank(left)
        .cmp(&autocomplete_rank(right))
        .then_with(|| {
            left.fq_name()
                .to_lowercase()
                .cmp(&right.fq_name().to_lowercase())
        })
        .then_with(|| {
            left.signature()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&right.signature().unwrap_or("").to_lowercase())
        })
}

fn autocomplete_rank(code_unit: &CodeUnit) -> usize {
    match code_unit.kind() {
        crate::analyzer::CodeUnitType::Class => 0,
        crate::analyzer::CodeUnitType::Function => 1,
        crate::analyzer::CodeUnitType::Field => 2,
        crate::analyzer::CodeUnitType::Macro => 3,
        crate::analyzer::CodeUnitType::Module => 4,
        crate::analyzer::CodeUnitType::FileScope => 5,
    }
}

#[cfg(test)]
mod required_literal_tests {
    use super::{SearchSymbolPatternBatch, required_storage_literals};

    /// Longest first, then alphabetical, which is the order the prefilter emits.
    fn literals(pattern: &str) -> Vec<String> {
        required_storage_literals(pattern)
    }

    #[test]
    fn a_plain_identifier_is_its_own_required_literal() {
        assert_eq!(
            literals("ProductionTaintPolicyEvaluator"),
            vec!["productiontaintpolicyevaluator".to_string()]
        );
    }

    /// The three shapes from issue #2316: a wildcard between literals leaves
    /// every literal required.
    #[test]
    fn wildcards_between_literals_keep_every_literal() {
        assert_eq!(
            literals("Java.*Value.*Flow"),
            vec!["value".to_string(), "flow".to_string(), "java".to_string()]
        );
        assert_eq!(
            literals(".*Taint.*Solver.*"),
            vec!["solver".to_string(), "taint".to_string()]
        );
        assert_eq!(literals(".*ValueFlow.*"), vec!["valueflow".to_string()]);
    }

    #[test]
    fn an_optional_group_contributes_nothing() {
        assert_eq!(literals("Foo(Bar)?"), vec!["foo".to_string()]);
        assert_eq!(literals("Foo(Bar)*"), vec!["foo".to_string()]);
        assert_eq!(
            literals("Foo(Bar)+"),
            vec!["bar".to_string(), "foo".to_string()]
        );
        assert_eq!(
            literals("Foo(?:Bar){2,4}"),
            vec!["bar".to_string(), "foo".to_string()]
        );
    }

    /// An alternation is required only where every branch requires the same
    /// literal, so a differing branch yields nothing rather than a wrong filter.
    #[test]
    fn an_alternation_requires_only_what_every_branch_requires() {
        assert!(literals("Foo|Bar").is_empty());
        assert_eq!(literals("Search(Foo|Bar)"), vec!["search".to_string()]);
        assert_eq!(literals("(?:Solver|Solver)"), vec!["solver".to_string()]);
    }

    /// An escaped metacharacter is a literal character, but it is not in the
    /// storage charset, so it ends the run instead of joining it.
    #[test]
    fn a_non_charset_character_splits_the_run_instead_of_joining_it() {
        assert_eq!(
            literals(r"Foo\.Bar"),
            vec!["bar".to_string(), "foo".to_string()]
        );
        assert_eq!(literals(r"Foo\$"), vec!["foo".to_string()]);
        // Each side of the split stays required on its own.
        assert_eq!(literals(r"a\-b"), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn case_insensitive_groups_recover_their_letters() {
        assert_eq!(literals("(?i)Solver"), vec!["solver".to_string()]);
        assert_eq!(
            literals("(?i)Value.*Flow"),
            vec!["value".to_string(), "flow".to_string()]
        );
        // A class that is not one letter's two cases contributes nothing itself,
        // and separates the literals around it.
        assert_eq!(
            literals("Sol[vw]er"),
            vec!["sol".to_string(), "er".to_string()]
        );
    }

    #[test]
    fn a_pattern_without_a_required_literal_yields_none() {
        for pattern in [".*", r"\w+", "^$", "[A-Za-z]+", ".", "(a|b)+"] {
            assert!(
                literals(pattern).is_empty(),
                "{pattern} must not produce a prefilter literal: {:?}",
                literals(pattern)
            );
        }
    }

    #[test]
    fn a_literal_another_literal_contains_is_dropped() {
        assert_eq!(literals("Foo.*FooBar"), vec!["foobar".to_string()]);
    }

    /// The literal count per pattern is bounded, and dropping a required literal
    /// only widens the prefilter.
    #[test]
    fn the_literal_set_is_bounded() {
        assert_eq!(
            literals("aa.*bb.*cc.*dd.*ee"),
            vec![
                "aa".to_string(),
                "bb".to_string(),
                "cc".to_string(),
                "dd".to_string()
            ]
        );
    }

    #[test]
    fn a_mixed_batch_prefilters_every_pattern_separately() {
        let batch = SearchSymbolPatternBatch::compile(
            vec![
                "Java.*Value.*Flow".to_string(),
                "ProductionTaintPolicyEvaluator".to_string(),
                ".*Taint.*Solver.*".to_string(),
                ".*ValueFlow.*".to_string(),
            ],
            false,
            None,
        );

        assert_eq!(
            batch.required_storage_literals(),
            Some(
                [
                    vec!["value".to_string(), "flow".to_string(), "java".to_string()],
                    vec!["productiontaintpolicyevaluator".to_string()],
                    vec!["solver".to_string(), "taint".to_string()],
                    vec!["valueflow".to_string()],
                ]
                .as_slice()
            )
        );
    }

    /// One pattern without a required literal voids the batch's prefilter: an
    /// unconditionally true disjunct would filter nothing anyway, and emitting
    /// the others would drop rows that pattern matches.
    #[test]
    fn one_unfilterable_pattern_voids_the_batch_prefilter() {
        let batch = SearchSymbolPatternBatch::compile(
            vec!["ValueFlow".to_string(), ".*".to_string()],
            false,
            None,
        );
        assert_eq!(batch.required_storage_literals(), None);
    }

    /// `auto_quote` wraps a pattern in wildcards, which leaves the quoted
    /// identifier required.
    #[test]
    fn auto_quoted_patterns_keep_their_identifier_literal() {
        let batch = SearchSymbolPatternBatch::compile(vec!["ValueFlow".to_string()], true, None);
        assert_eq!(
            batch.required_storage_literals(),
            Some([vec!["valueflow".to_string()]].as_slice())
        );
    }
}
