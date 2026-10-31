use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::store::StoreError;
use crate::analyzer::usages::{FuzzyResult, UsageFinder};
use crate::analyzer::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, ExceptionHandlingAnalysis, ExceptionSmellWeights, ImportAnalysisProvider,
    ParseError, Project, ProjectFile, SearchSymbolCandidate, SemanticDiagnosticReport,
    TestAssertionAnalysis, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TypeAliasProvider, TypeHierarchyProvider, metrics_from_declarations,
};
use crate::cancellation::CancellationToken;
use crate::gitblob;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
pub(crate) use brokk_bifrost_core::analyzer::code_unit_index::default_parent_fq_name;
pub use brokk_bifrost_core::analyzer::query_batch::QueryBatch;
pub use brokk_bifrost_core::analyzer::query_token::{QueryScope, QueryToken};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, OnceLock};

/// One analyzer's contribution to a batched symbol-search request.
///
/// `complete` is false when cooperative cancellation stopped enumeration.
/// Callers may retain the candidates produced before that checkpoint, but
/// must not present an incomplete batch as an authoritative search result.
#[doc(hidden)]
pub type SearchSymbolCandidates = QueryBatch<SearchSymbolCandidate>;

/// A resolved file import edge persisted by the workspace import graph.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct PersistedImportEdge {
    pub importer: ProjectFile,
    pub import_ordinal: u32,
    pub target: ProjectFile,
    pub provenance_json: String,
    /// Workspace-relative files consulted along this import's route,
    /// including the importer and direct target.
    pub route_dependencies: Vec<String>,
}

/// Candidate dependencies for one source, persisted even when it currently
/// resolves no file edges.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct PersistedImportDependencies {
    pub importer: ProjectFile,
    pub facts: crate::analyzer::ImportResolutionDependencies,
}

/// Work performed while advancing a persisted import graph to the current
/// workspace identity.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PersistedImportGraphRefresh {
    pub recomputed_files: usize,
    pub recomputed_imports: usize,
    pub recomputed_edges: usize,
}

/// One indexed adjacency read from the persistent workspace import graph.
#[doc(hidden)]
#[derive(Debug)]
pub struct PersistedImportAdjacency {
    pub by_file: HashMap<ProjectFile, Vec<ProjectFile>>,
    pub rows_read: usize,
    pub exhausted: bool,
}

/// Direction for a persistent file import adjacency query.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedImportDirection {
    Forward,
    Reverse,
}

/// Forward [`IAnalyzer::relational_definition_batch`] from a public language
/// analyzer wrapper to its generic `TreeSitterAnalyzer`. Keeping the forwarding
/// body singular prevents one language from silently retaining a different
/// point/batch contract during the migration.
#[doc(hidden)]
#[macro_export]
macro_rules! forward_relational_definition_batch {
    () => {
        fn relational_definition_batch(
            &self,
            requests: &[$crate::analyzer::definition_lookup::RelationalDefinitionRequest],
            cancellation: &$crate::CancellationToken,
        ) -> $crate::analyzer::definition_lookup::RelationalBatchOutcome {
            $crate::analyzer::definition_lookup::RelationalDefinitionLookup::batch(
                &self.inner,
                requests,
                cancellation,
            )
        }

        fn reference_names_in_files(
            &self,
            request: $crate::analyzer::i_analyzer::ReferenceNamesInFilesRequest<'_>,
        ) -> Result<
            $crate::analyzer::i_analyzer::ReferenceNamesInFilesResult,
            $crate::analyzer::store::StoreError,
        > {
            self.inner.reference_names_in_files(request)
        }

        fn source_file_inventory(
            &self,
        ) -> $crate::analyzer::QueryBatch<$crate::analyzer::ProjectFile> {
            self.inner.source_file_inventory()
        }

        fn workspace_declarations_with_primary_ranges(
            &self,
            cancellation: &$crate::CancellationToken,
        ) -> Option<Vec<($crate::analyzer::CodeUnit, Option<$crate::analyzer::Range>)>> {
            self.inner
                .workspace_declarations_with_primary_ranges(cancellation)
        }

        fn active_query_cancellation(&self) -> Option<$crate::CancellationToken> {
            self.inner.active_query_cancellation()
        }

        fn active_query_semantic_model_overlay(
            &self,
        ) -> Option<Option<std::sync::Arc<$crate::analyzer::semantic_model::SemanticModelOverlay>>>
        {
            self.inner.active_query_semantic_model_overlay()
        }

        fn active_query_semantic_model_snapshot(
            &self,
        ) -> Option<
            Option<std::sync::Arc<$crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
        > {
            self.inner.active_query_semantic_model_snapshot()
        }
    };
}

#[doc(hidden)]
pub use crate::forward_relational_definition_batch;

/// Forward request-ledger capture and replay through a language wrapper.
#[doc(hidden)]
#[macro_export]
macro_rules! forward_query_read_ledger {
    () => {
        fn current_query_read_completion(
            &self,
        ) -> Result<(), $crate::analyzer::QueryReadIncomplete> {
            $crate::analyzer::IAnalyzer::current_query_read_completion(&self.inner)
        }

        fn record_query_incomplete(&self, reason: $crate::analyzer::QueryReadIncomplete) {
            $crate::analyzer::IAnalyzer::record_query_incomplete(&self.inner, reason);
        }

        fn record_read(&self, key: $crate::analyzer::read_ledger::ReadKey) {
            $crate::analyzer::IAnalyzer::record_read(&self.inner, key);
        }

        fn record_read_receipt(&self, keys: &std::sync::Arc<[$crate::analyzer::ReadKey]>) {
            $crate::analyzer::IAnalyzer::record_read_receipt(&self.inner, keys);
        }

        fn record_read_capture(&self, reads: &$crate::analyzer::ReadLedger) {
            $crate::analyzer::IAnalyzer::record_read_capture(&self.inner, reads);
        }

        fn record_unattributed_reads(&self, count: usize) {
            $crate::analyzer::IAnalyzer::record_unattributed_reads(&self.inner, count);
        }

        fn mark_execution_dependent_reads(&self, count: usize) {
            $crate::analyzer::IAnalyzer::mark_execution_dependent_reads(&self.inner, count);
        }

        fn records_query_reads(&self) -> bool {
            $crate::analyzer::IAnalyzer::records_query_reads(&self.inner)
        }

        fn read_ledger_attached(&self) -> bool {
            $crate::analyzer::IAnalyzer::read_ledger_attached(&self.inner)
        }

        fn read_ledger_contexts(
            &self,
        ) -> Vec<std::sync::Arc<$crate::analyzer::AnalyzerQueryContext>> {
            $crate::analyzer::IAnalyzer::read_ledger_contexts(&self.inner)
        }

        fn current_thread_read_ledger(
            &self,
        ) -> Option<std::sync::Arc<$crate::analyzer::ReadLedger>> {
            $crate::analyzer::IAnalyzer::current_thread_read_ledger(&self.inner)
        }
    };
}

/// Forward the two Git-identity invalidation operations from a public language
/// wrapper to its generic `TreeSitterAnalyzer`.
#[doc(hidden)]
#[macro_export]
macro_rules! forward_file_identity_invalidation {
    () => {
        fn invalidate_cached_file_identities(&self) {
            self.inner.invalidate_cached_file_identities();
        }

        fn invalidate_cached_file_identities_for(
            &self,
            changed_files: &std::collections::BTreeSet<$crate::analyzer::ProjectFile>,
        ) {
            self.inner
                .invalidate_cached_file_identities_for(changed_files);
        }
    };
}

#[doc(hidden)]
pub use crate::forward_file_identity_invalidation;

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
    /// Request patterns that are neither valid regex nor a translatable glob.
    /// Reported to the caller instead of silently matching nothing: a dropped
    /// pattern turns "your syntax is wrong" into "the workspace has no such
    /// symbols", which is a false negative about the code (#3279).
    invalid_patterns: Vec<String>,
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
        let mut invalid_patterns = Vec::new();
        for pattern in &patterns {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return Self {
                    patterns,
                    auto_quote,
                    compiled: None,
                    required_literals: None,
                    invalid_patterns: Vec::new(),
                    complete: false,
                };
            }
            let raw_pattern = pattern.clone();
            let pattern = normalize_search_pattern(pattern, auto_quote);
            if let Some((effective_pattern, compiled)) = compile_search_pattern(&pattern) {
                // Literals are extracted from the effective pattern, which is
                // the exact text the authoritative matcher compiled.
                required_literals.push(required_storage_literals(&effective_pattern));
                compiled_patterns.push(effective_pattern);
                compiled_regexes.push(compiled);
            } else {
                invalid_patterns.push(raw_pattern);
            }
        }

        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return Self {
                patterns,
                auto_quote,
                compiled: None,
                required_literals: None,
                invalid_patterns: Vec::new(),
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
            invalid_patterns,
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

    /// The request patterns that could not be interpreted at all, verbatim as
    /// requested and in request order. Empty when every pattern compiled.
    pub fn invalid_patterns(&self) -> &[String] {
        &self.invalid_patterns
    }

    /// Whether at least one pattern compiled. A batch with patterns but no
    /// compiled matcher can only match nothing; callers use this to skip the
    /// storage scan and answer from the invalid-pattern report instead.
    pub fn has_compiled_patterns(&self) -> bool {
        self.compiled.is_some()
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
    if bytes
        .iter()
        .all(|byte| brokk_bifrost_core::text_utils::is_ident_byte(*byte))
    {
        return RequiredLiterals::exact(storage_run(bytes));
    }
    RequiredLiterals {
        exact: None,
        substrings: bytes
            .split(|byte| !brokk_bifrost_core::text_utils::is_ident_byte(*byte))
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
        .filter(|byte| brokk_bifrost_core::text_utils::is_ident_byte(*byte))
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

fn storage_run(bytes: &[u8]) -> String {
    debug_assert!(
        bytes
            .iter()
            .all(|byte| brokk_bifrost_core::text_utils::is_ident_byte(*byte)),
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

/// Compile one normalized search pattern, falling back to glob wildcards when
/// it is not a valid regular expression.
///
/// A leading `*` (as in `*Language*`) never compiles as a regex -- a
/// repetition operator with nothing to repeat -- and the glob spelling is the
/// one callers reach for first, so a pattern that fails as a regex and carries
/// `*` or `?` is reinterpreted as a glob: `*` matches any run of characters,
/// `?` matches exactly one, and every other character is literal. Returns the
/// pattern text that compiled (the normalized regex, or its glob translation)
/// with the compiled regex, or `None` when neither interpretation is valid and
/// the pattern must be reported instead of silently matching nothing (#3279).
fn compile_search_pattern(normalized: &str) -> Option<(String, Regex)> {
    if let Ok(compiled) = RegexBuilder::new(normalized).case_insensitive(true).build() {
        return Some((normalized.to_string(), compiled));
    }
    if !normalized.contains('*') && !normalized.contains('?') {
        return None;
    }
    let mut translated = String::with_capacity(normalized.len() * 2);
    for character in normalized.chars() {
        match character {
            '*' => translated.push_str(".*"),
            '?' => translated.push('.'),
            other => translated.push_str(&regex::escape(&other.to_string())),
        }
    }
    let compiled = RegexBuilder::new(&translated)
        .case_insensitive(true)
        .build()
        .ok()?;
    Some((translated, compiled))
}

/// Escape anchor metacharacters only where they form part of an identifier token.
fn escape_sigil_anchors(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut escaped = String::with_capacity(pattern.len());
    for (index, ch) in chars.iter().enumerate() {
        let prev_is_word = index > 0
            && (chars[index - 1].is_alphanumeric() || matches!(chars[index - 1], '_' | '$' | '^'));
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

/// A typed reason a request could not establish a complete read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryReadIncomplete {
    /// Cooperative cancellation stopped a read before it could establish a
    /// complete answer.
    Cancelled,
    /// The structured source needed by a read was unavailable.
    StructureUnavailable(ProjectFile),
    /// Structured semantic evidence required for a complete answer was
    /// unavailable or incomplete.
    SemanticEvidenceUnavailable(Box<str>),
    /// A dependency's content or declared configuration deterministically
    /// prevents a complete external surface. Retained entries replay this gap.
    ArtifactUnavailable(Box<str>),
    /// Snapshot-deterministic unknown or unsupported semantics. The partial
    /// answer remains incomplete, but its named inputs can be replayed.
    SemanticEvidenceGap(Box<str>),
    /// A store failure prevented a read from establishing a complete answer.
    StoreFailure(StoreError),
}

impl QueryReadIncomplete {
    /// Structural admission refusals and typed semantic gaps are properties of
    /// recorded inputs. Unclassified semantic failures remain conservative;
    /// typed producers use SemanticEvidenceGap only for deterministic gaps.
    pub fn is_execution_dependent(&self) -> bool {
        match self {
            Self::StructureUnavailable(_)
            | Self::ArtifactUnavailable(_)
            | Self::SemanticEvidenceGap(_) => false,
            Self::Cancelled | Self::StoreFailure(_) | Self::SemanticEvidenceUnavailable(_) => true,
        }
    }
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
#[derive(Debug)]
pub struct AnalyzerQueryContext {
    /// The scope whose request memos this scope may reuse. Transported with
    /// ReadAttribution, never inferred from the analyzer-wide registry.
    enclosing: Option<Arc<AnalyzerQueryContext>>,
    first_store_error: Mutex<Option<StoreError>>,
    first_read_incomplete: Mutex<Option<QueryReadIncomplete>>,
    /// Only file-cache builders capture every reason, so a stable first reason
    /// cannot conceal a later transient failure when deciding cache admission.
    captured_read_incompleteness: Option<Mutex<Vec<QueryReadIncomplete>>>,
    cancellation: Option<CancellationToken>,
    identifier_candidate_memo_owner: Option<std::thread::ThreadId>,
    /// A resolver overlay frozen by this scope's owner thread. The outer
    /// `Option` distinguishes no override from a deliberately frozen absence;
    /// the thread identity prevents the analyzer's shared context stack from
    /// leaking one concurrent request's overlay into another.
    semantic_model_overlay_override: Option<(
        std::thread::ThreadId,
        Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    )>,
    active_semantic_model_snapshot_override: Option<(
        std::thread::ThreadId,
        Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    )>,
    /// Storage-funnel crossings observed while this request boundary was
    /// active, one counter per [`InformationTier`]. Scopes nest, so an access
    /// made under an inner scope is recorded on every enclosing scope too:
    /// each of them did pay for it.
    tier_accesses: [AtomicUsize; InformationTier::COUNT],
    /// The read ledger this request records its inputs into, when its opener
    /// asked for one (`AnalyzerQueryScope::with_read_ledger`). `None` is the
    /// ordinary case and costs nothing: every funnel checks the analyzer's
    /// attached-ledger count before it builds a key.
    read_ledger: Option<Arc<crate::analyzer::read_ledger::ReadLedger>>,
    /// The enclosing ledger this nested capture replaces.
    ///
    /// Other ledgers in the current attribution frame still receive the read.
    /// Explicit Broadcast uses this edge to narrow the analyzer-wide registry
    /// without exposing implementation reads to the linked caller.
    shadowed_read_ledger: Option<Arc<crate::analyzer::read_ledger::ReadLedger>>,
}

impl AnalyzerQueryContext {
    /// An independent request never inherits another request running on this thread.
    pub fn root() -> Self {
        Self {
            enclosing: None,
            ..Self::default()
        }
    }

    /// Enter this request on the thread performing its work.
    pub fn enter(self: &Arc<Self>) -> ReadAttributionGuard {
        query_attribution(self)
    }

    pub(crate) fn assert_current(&self) {
        debug_assert!(
            current_query_contexts().any(|active| std::ptr::eq(active.as_ref(), self)),
            "query registration requires current request attribution"
        );
    }
}

impl Default for AnalyzerQueryContext {
    fn default() -> Self {
        Self {
            enclosing: current_query_context(),
            first_store_error: Mutex::new(None),
            first_read_incomplete: Mutex::new(None),
            captured_read_incompleteness: None,
            cancellation: None,
            identifier_candidate_memo_owner: None,
            semantic_model_overlay_override: None,
            active_semantic_model_snapshot_override: None,
            tier_accesses: Default::default(),
            read_ledger: None,
            shadowed_read_ledger: None,
        }
    }
}

/// Tier crossings paid while constructing one workspace analyzer.
///
/// Construction happens before an [`AnalyzerQueryScope`] can exist, so the
/// request-scoped counters cannot describe the work done by workspace open.
/// This small observer gives that build a separate accounting boundary without
/// changing the meaning of per-operation tier reports.
#[derive(Debug)]
pub struct AnalyzerBuildTierAccess {
    active: std::sync::atomic::AtomicBool,
    tier_accesses: [AtomicUsize; InformationTier::COUNT],
}

impl AnalyzerBuildTierAccess {
    #[doc(hidden)]
    pub fn new_active() -> Self {
        Self {
            active: std::sync::atomic::AtomicBool::new(true),
            tier_accesses: Default::default(),
        }
    }

    pub(crate) fn finish(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn record_tier_access(&self, tier: InformationTier) {
        if !self.active.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        record_tier_access_in(&self.tier_accesses, tier);
    }

    pub fn tier_access_count(&self, tier: InformationTier) -> usize {
        tier_access_count_from(&self.tier_accesses, tier)
    }
}

impl Default for AnalyzerBuildTierAccess {
    fn default() -> Self {
        Self {
            active: std::sync::atomic::AtomicBool::new(false),
            tier_accesses: Default::default(),
        }
    }
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

fn record_tier_access_in(
    tier_accesses: &[AtomicUsize; InformationTier::COUNT],
    tier: InformationTier,
) {
    tier_accesses[tier.index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn tier_access_count_from(
    tier_accesses: &[AtomicUsize; InformationTier::COUNT],
    tier: InformationTier,
) -> usize {
    tier_accesses[tier.index()].load(std::sync::atomic::Ordering::Relaxed)
}

/// Analyzer-snapshot-owned query caches. The container is public only because
/// `IAnalyzer` is an extension boundary; concrete cache representations remain
/// crate-private and can evolve without coupling external analyzers to query
/// execution internals.
#[doc(hidden)]
#[derive(Default)]
pub struct AnalyzerSnapshotCaches {
    derived_layers: Arc<crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache>,
    #[doc(hidden)]
    pub usage_graphs:
        Arc<crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache>,
    java_usage_evidence:
        Arc<crate::analyzer::usages::java_usage_evidence_cache::SnapshotJavaUsageEvidenceCache>,
    semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache,
    /// Pure content- and dialect-keyed facts outlive per-root semantic oracles.
    runtime_syntax: OnceLock<crate::analyzer::semantic::workspace_oracle::RuntimeSyntaxCache>,
}

impl AnalyzerSnapshotCaches {
    pub(crate) fn new(derived_layer_budget_bytes: u64) -> Self {
        Self {
            derived_layers: Arc::new(
                crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache::new(
                    derived_layer_budget_bytes,
                ),
            ),
            usage_graphs: Arc::new(crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache::new(
                derived_layer_budget_bytes,
            )),
            java_usage_evidence: Arc::new(
                crate::analyzer::usages::java_usage_evidence_cache::SnapshotJavaUsageEvidenceCache::new(
                    derived_layer_budget_bytes,
                ),
            ),
            semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache::new(
                derived_layer_budget_bytes,
            ),
            runtime_syntax: OnceLock::new(),
        }
    }

    /// The caches an analyzer update inherits from the generation before it
    /// (#2449).
    ///
    /// The derived layers and usage graphs are keyed by workspace content, so
    /// an update cannot make an entry wrong: an entry whose content moved is
    /// simply never asked for again and is retired by the cache's own byte
    /// budget. The semantic-model publication is not content-keyed -- it
    /// records what a host activated against one snapshot -- so it is minted
    /// fresh, exactly as it was before this change.
    pub(crate) fn carry_content_keyed_values_forward(&self) -> Self {
        Self {
            derived_layers: Arc::clone(&self.derived_layers),
            usage_graphs: Arc::clone(&self.usage_graphs),
            java_usage_evidence: Arc::clone(&self.java_usage_evidence),
            semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache::new(
                self.derived_layers.max_retained_bytes(),
            ),
            runtime_syntax: self.runtime_syntax.clone(),
        }
    }

    pub fn derived_layers(
        &self,
    ) -> &crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache {
        &self.derived_layers
    }

    #[doc(hidden)]
    pub fn usage_graphs(
        &self,
    ) -> &crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache {
        &self.usage_graphs
    }

    #[doc(hidden)]
    pub fn java_usage_evidence(
        &self,
    ) -> &crate::analyzer::usages::java_usage_evidence_cache::SnapshotJavaUsageEvidenceCache {
        &self.java_usage_evidence
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn reset_java_usage_evidence_stats_for_test(&self) {
        self.java_usage_evidence.reset_stats_for_test();
    }

    pub(crate) fn semantic_models(
        &self,
    ) -> &crate::analyzer::semantic_model::SemanticModelRuntimeCache {
        &self.semantic_models
    }

    pub(crate) fn runtime_syntax(
        &self,
    ) -> &crate::analyzer::semantic::workspace_oracle::RuntimeSyntaxCache {
        self.runtime_syntax
            .get_or_init(crate::analyzer::semantic::workspace_oracle::runtime_syntax_cache)
    }

    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        self.semantic_models.overlay()
    }

    fn active_semantic_model_snapshot(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>> {
        self.semantic_models.snapshot()
    }

    #[cfg(any(test, feature = "test-support"))]
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
    /// The complete workspace inventory certified by this listing.
    inventory_answer: Option<super::semantic::ids::StableDigest>,
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
        let listed = brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let files = project.all_files().map_err(|err| {
                format!("listing workspace files under {:?}: {err}", project.root())
            })?;
            let receipt =
                brokk_bifrost_core::analyzer::project_reads::file_set_receipt(project, &files)
                    .map_err(|err| {
                        format!(
                            "certifying workspace files under {:?}: {err}",
                            project.root()
                        )
                    })?;
            Ok((
                Self::bucket_by_basename(files),
                receipt
                    .inventory
                    .map(super::semantic::ids::StableDigest::from_array),
            ))
        });
        let (by_basename, inventory_answer) = match listed {
            Ok((buckets, answer)) => (Ok(buckets), answer),
            Err(error) => (Err(error), None),
        };
        Self {
            root: project.root().to_path_buf(),
            inventory_answer,
            by_basename,
        }
    }

    pub(crate) fn inventory_answer(&self) -> Option<super::semantic::ids::StableDigest> {
        self.inventory_answer
    }

    fn bucket_by_basename(
        files: std::collections::BTreeSet<ProjectFile>,
    ) -> crate::hash::HashMap<String, Vec<ProjectFile>> {
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
        by_basename
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
            cancellation: Some(cancellation),
            ..Self::default()
        }
    }

    fn with_semantic_model_overlay(
        semantic_model_overlay: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    ) -> Self {
        Self {
            semantic_model_overlay_override: Some((
                std::thread::current().id(),
                semantic_model_overlay,
            )),
            ..Self::default()
        }
    }

    fn with_active_semantic_model_snapshot(
        snapshot: Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self {
            active_semantic_model_snapshot_override: Some((std::thread::current().id(), snapshot)),
            ..Self::default()
        }
    }

    fn for_identifier_candidate_memo() -> Self {
        Self {
            identifier_candidate_memo_owner: Some(std::thread::current().id()),
            ..Self::default()
        }
    }

    pub(crate) fn identifier_candidate_memo_owner(&self) -> Option<std::thread::ThreadId> {
        self.identifier_candidate_memo_owner
    }

    pub(crate) fn semantic_model_overlay_override_for_current_thread(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        if let Some(snapshot) = self.active_semantic_model_snapshot_override_for_current_thread() {
            return Some(
                snapshot.and_then(|snapshot| snapshot.semantic_model_overlay().map(Arc::clone)),
            );
        }
        let (owner, overlay) = self.semantic_model_overlay_override.as_ref()?;
        (owner == &std::thread::current().id()).then(|| overlay.clone())
    }

    pub(crate) fn active_semantic_model_snapshot_override_for_current_thread(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        let (owner, snapshot) = self.active_semantic_model_snapshot_override.as_ref()?;
        (owner == &std::thread::current().id()).then(|| snapshot.clone())
    }

    fn with_read_ledger(ledger: Arc<crate::analyzer::read_ledger::ReadLedger>) -> Self {
        Self {
            read_ledger: Some(ledger),
            ..Self::default()
        }
    }

    fn with_nested_read_ledger(
        ledger: Arc<crate::analyzer::read_ledger::ReadLedger>,
        shadowed: Arc<crate::analyzer::read_ledger::ReadLedger>,
    ) -> Self {
        Self {
            read_ledger: Some(ledger),
            shadowed_read_ledger: Some(shadowed),
            ..Self::default()
        }
    }

    /// The read ledger this request records into, if its opener attached one.
    pub fn read_ledger(&self) -> Option<&Arc<crate::analyzer::read_ledger::ReadLedger>> {
        self.read_ledger.as_ref()
    }

    pub(crate) fn shadows_read_ledger(
        &self,
        ledger: &Arc<crate::analyzer::read_ledger::ReadLedger>,
    ) -> bool {
        self.shadowed_read_ledger
            .as_ref()
            .is_some_and(|shadowed| Arc::ptr_eq(shadowed, ledger))
    }

    /// Records one named input under this request. A request with no ledger
    /// drops the key; the funnels avoid building one at all by consulting the
    /// analyzer's attached-ledger count first.
    pub fn record_read(&self, key: crate::analyzer::read_ledger::ReadKey) {
        if let Some(ledger) = &self.read_ledger {
            ledger.record(key);
        }
    }

    /// Records one funnel crossing this request could not name.
    pub fn record_unattributed_read(&self) {
        self.record_unattributed_reads(1);
    }

    /// Records a batch of crossings this request could not name.
    pub fn record_unattributed_reads(&self, count: usize) {
        if let Some(ledger) = &self.read_ledger {
            ledger.record_unattributed_reads(count);
        }
    }

    /// Marks a batch of crossings that depended on transient execution state.
    pub fn mark_execution_dependent_reads(&self, count: usize) {
        if let Some(ledger) = &self.read_ledger {
            ledger.mark_execution_dependent_reads(count);
        }
    }

    /// Records one crossing of `tier`'s storage funnel under this request.
    pub fn record_tier_access(&self, tier: InformationTier) {
        record_tier_access_in(&self.tier_accesses, tier);
    }

    /// Crossings of `tier`'s storage funnel observed while this request was
    /// active. Read relaxed: the counts are advisory bounds for tests and
    /// diagnostics, not a synchronization edge.
    pub fn tier_access_count(&self, tier: InformationTier) -> usize {
        tier_access_count_from(&self.tier_accesses, tier)
    }

    /// The deadline this request is running under, if its opener set one.
    pub fn cancellation(&self) -> Option<&CancellationToken> {
        self.cancellation.as_ref()
    }

    pub fn record_store_error(&self, error: StoreError) {
        if let Some(ledger) = &self.read_ledger {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=store",
                    file!(),
                    line!()
                )
            });
            ledger.mark_execution_dependent();
        }
        self.capture_read_incomplete(QueryReadIncomplete::StoreFailure(error.clone()));
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

    /// Records the first structured reason this request could not establish a
    /// complete read. The reason is sticky so an outer scope retains an inner
    /// scope's cancellation after that inner scope closes.
    pub fn record_read_incomplete(&self, reason: QueryReadIncomplete) {
        if reason.is_execution_dependent()
            && let Some(ledger) = &self.read_ledger
        {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=read_incomplete detail={reason:?}",
                    file!(),
                    line!(),
                )
            });
            ledger.mark_execution_dependent();
        }
        self.capture_read_incomplete(reason.clone());
        let mut slot = self
            .first_read_incomplete
            .lock()
            .expect("analyzer query incompleteness mutex poisoned");
        if slot.is_none() {
            *slot = Some(reason);
        }
    }

    fn capture_read_incomplete(&self, reason: QueryReadIncomplete) {
        if let Some(captured) = &self.captured_read_incompleteness {
            let mut reasons = captured.lock().expect("read incompleteness mutex poisoned");
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
    }

    /// Returns the first typed read incompleteness, falling back to the first
    /// recorded store failure when no more specific reason was recorded.
    pub fn read_completion(&self) -> Result<(), QueryReadIncomplete> {
        if let Some(reason) = self
            .first_read_incomplete
            .lock()
            .expect("analyzer query incompleteness mutex poisoned")
            .clone()
        {
            return Err(reason);
        }
        self.store_error().map_or(Ok(()), |error| {
            Err(QueryReadIncomplete::StoreFailure(error))
        })
    }
}

pub(crate) fn decrement_attached_read_ledger(
    attached_read_ledgers: &AtomicUsize,
    context: &AnalyzerQueryContext,
) {
    if context.read_ledger().is_some() {
        let before = attached_read_ledgers.fetch_sub(1, AtomicOrdering::Relaxed);
        debug_assert!(before > 0, "an attached read ledger was retired twice");
    }
}

pub(crate) fn innermost_query_context_value<T>(
    contexts: &[Arc<AnalyzerQueryContext>],
    mut select: impl FnMut(&AnalyzerQueryContext) -> Option<T>,
) -> Option<T> {
    contexts.iter().rev().find_map(|context| select(context))
}

/// Only the actual enclosing scope can have supplied request-memo values.
pub(crate) fn inherit_query_incompleteness(
    context: &AnalyzerQueryContext,
    registered: &[Arc<AnalyzerQueryContext>],
) {
    context.assert_current();
    if let Some(parent) = &context.enclosing
        && registered.iter().any(|active| Arc::ptr_eq(active, parent))
    {
        if let Err(reason) = parent.read_completion() {
            context.record_read_incomplete(reason);
        }
        // A stable first reason must not conceal a later transient store
        // failure when a nested builder decides whether its value is reusable.
        if let Some(error) = parent.store_error() {
            context.record_store_error(error);
        }
    }
}

fn current_query_contexts() -> impl Iterator<Item = Arc<AnalyzerQueryContext>> {
    std::iter::successors(current_query_context(), |context| context.enclosing.clone())
}

fn for_each_current_query_context(mut record: impl FnMut(&AnalyzerQueryContext)) {
    for context in current_query_contexts() {
        record(&context);
    }
}

pub(crate) fn current_query_context_value<T>(
    registered: &[Arc<AnalyzerQueryContext>],
    mut select: impl FnMut(&AnalyzerQueryContext) -> Option<T>,
) -> Option<T> {
    current_query_contexts()
        .filter(|context| registered.iter().any(|active| Arc::ptr_eq(active, context)))
        .find_map(|context| select(&context))
}

pub(crate) fn record_query_incomplete_on_current_contexts(reason: QueryReadIncomplete) {
    for_each_current_query_context(|context| context.record_read_incomplete(reason.clone()));
}

pub(crate) fn record_store_error_on_current_contexts(error: StoreError) {
    for_each_current_query_context(|context| context.record_store_error(error.clone()));
}

/// A shared failed build belongs only to its actual consumers. Preserve read
/// shadowing, but never use the analyzer registry as a Broadcast fallback.
pub(crate) fn replay_query_read_receipt_on_current_contexts(
    keys: &Arc<[crate::analyzer::ReadKey]>,
    unattributed_reads: usize,
    execution_dependences: usize,
) {
    let contexts: Vec<_> = current_query_contexts().collect();
    if contexts.is_empty() {
        return;
    }
    for_each_unshadowed_active_ledger(&contexts, |ledger| {
        ledger.absorb_receipt(keys);
        ledger.record_unattributed_reads(unattributed_reads);
        ledger.mark_execution_dependent_reads(execution_dependences);
    });
}

/// Enumerate source identities independently of persisted parse-product readiness.
#[doc(hidden)]
pub fn project_source_file_inventory(
    analyzer: &(impl IAnalyzer + ?Sized),
) -> QueryBatch<ProjectFile> {
    let project = analyzer.project();
    let listed = match project.all_files_shared() {
        Ok(files) => files,
        Err(error) => {
            analyzer.record_query_failure(StoreError::new(format!(
                "listing source inventory under {:?}: {error}",
                project.root()
            )));
            return QueryBatch::incomplete(Vec::new(), 0);
        }
    };
    let mut inventory = QueryBatch::complete(Vec::new(), listed.len());
    for language in analyzer.languages() {
        if super::languages::language_support(language).is_none() {
            continue;
        }
        match project.analyzable_files_from(&listed, language) {
            Ok(files) => inventory.rows.extend(files),
            Err(error) => {
                analyzer.record_query_failure(StoreError::new(format!(
                    "listing {language:?} source inventory under {:?}: {error}",
                    project.root()
                )));
                inventory.complete = false;
            }
        }
    }
    inventory.rows.sort();
    inventory.rows.dedup();
    inventory
}

fn record_active_model_hash(analyzer: &(impl IAnalyzer + ?Sized), hash: &str) {
    analyzer.record_read(crate::analyzer::read_ledger::ReadKey::Models(
        crate::analyzer::semantic::ids::StableDigest::sha256(hash),
    ));
}

fn active_query_model_or_snapshot<T>(
    active_query: Option<Option<Arc<T>>>,
    snapshot: impl FnOnce() -> Option<Arc<T>>,
) -> Option<Arc<T>> {
    active_query.unwrap_or_else(snapshot)
}

fn structural_index_inputs(
    provider: &dyn crate::analyzer::structural::StructuralFactProvider,
) -> Option<(
    &crate::analyzer::structural::provider::StructuralFactSnapshotCache,
    crate::analyzer::content_identity::WorkspaceContentIdentity,
)> {
    let cache = provider.snapshot_structural_index_cache();
    let content_identity = provider.structural_content_identity();
    match (cache, content_identity) {
        (Some(cache), Some(content_identity)) => Some((cache, content_identity)),
        _ => None,
    }
}

/// A bounded name selection over an explicit source-file set.
#[doc(hidden)]
pub struct ReferenceNamesInFilesRequest<'a> {
    pub files: &'a [ProjectFile],
    pub names: &'a [String],
}

/// One example source for each referenced normalized terminal name.
#[doc(hidden)]
#[derive(Default)]
pub struct ReferenceNamesInFilesResult {
    pub by_name: HashMap<String, ProjectFile>,
}

pub trait IAnalyzer: CodeUnitIndex + Send + Sync + Any {
    /// Read live dynamic import source paths from the selected workspace
    /// publication. `seed_files` scopes `imports-of`; `None` asks for every
    /// live source, which is the scope required by `importers-of`.
    fn dynamic_import_sources(
        &self,
        _seed_files: Option<&[ProjectFile]>,
    ) -> std::result::Result<Vec<(String, String)>, crate::analyzer::store::StoreError> {
        Ok(Vec::new())
    }

    /// The snapshot's confirmed structural identity for a physical declaration.
    /// Extraction identities and their persisted facts are immutable. An
    /// adapter may reconcile ownership from structured cross-file evidence,
    /// retaining physical provenance for later range/source reads. Ambiguous
    /// ownership remains provisional; incomplete reads retain the query's typed
    /// completion state and must never be admitted to an identity cache.
    fn canonical_code_unit(
        &self,
        unit: &CodeUnit,
        _cancellation: Option<&crate::CancellationToken>,
    ) -> CodeUnit {
        unit.clone()
    }

    /// Build loop candidates for one semantic procedure. Read failures remain
    /// typed errors; syntax-incomplete candidate sets remain successful values.
    fn loop_candidates_for(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Arc<crate::analyzer::LoopCandidates>, QueryReadIncomplete> {
        Ok(Arc::new(crate::analyzer::build_loop_candidates(
            workspace,
            procedure,
            cancellation,
        )))
    }

    /// Build statement assessments for one semantic procedure.
    fn statement_assessments_for(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<crate::analyzer::semantic::StatementAssessments> {
        Arc::new(
            crate::analyzer::semantic::statement_entries::build_statement_assessments(
                workspace,
                procedure,
                cancellation,
            ),
        )
    }

    /// Return query-lifetime, AST-owned C++ expression facts for one file.
    /// Languages without the C++ adapter return `None`; an empty expression
    /// vector is an authoritative expression-free C++ source snapshot.
    fn cpp_expression_source_facts(
        &self,
        _file: &ProjectFile,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::analyzer::cpp_facts::CppExpressionSourceFacts>>
    {
        None
    }

    /// Return bounded, AST-owned statement facts for one source snapshot.
    /// Adapters without statement-fact support return `None`.
    fn statement_source_facts(
        &self,
        _file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::statement_facts::StatementFactRows>> {
        None
    }

    /// Return query-lifetime, AST-owned C++ class and exception facts for one
    /// file. Languages without the C++ adapter return `None`; an empty row
    /// set is an authoritative class-free C++ source snapshot.
    fn cpp_class_source_facts(
        &self,
        _file: &ProjectFile,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::analyzer::cpp_facts::CppClassFactRows>> {
        None
    }

    /// Return the existing query-lifetime C++ declaration/base rows for one
    /// file. The class relation uses these rows for bounded hierarchy joins;
    /// no second hierarchy is retained in RQL.
    fn cpp_class_declaration_source_facts(
        &self,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
    ) -> Option<
        std::sync::Arc<Vec<brokk_bifrost_core::analyzer::cpp_facts::CppDeclarationSourceFact>>,
    > {
        None
    }

    /// Read bounded presentation proofs from the same selected publication.
    fn dependency_file_locations(
        &self,
    ) -> crate::analyzer::store::Result<
        Vec<(
            String,
            crate::analyzer::semantic_model::DependencyEvidenceLocation,
        )>,
    > {
        Ok(Vec::new())
    }

    /// Read bounded static dependency facts from this immutable store selection.
    /// This method must never discover files or prepare dependency artifacts.
    fn dependency_file_evidence(
        &self,
    ) -> crate::analyzer::store::Result<crate::analyzer::semantic_model::DependencyFileEvidence>
    {
        Err(StoreError::new(
            "static dependency evidence is unavailable for this analyzer",
        ))
    }

    /// Source files owned by this analyzer, including files whose parse products
    /// are unavailable. Listing failures preserve available identities and mark
    /// the batch incomplete. This inventory must not hydrate declarations, read
    /// source text, or retry publication. Concrete analyzers retain any adopted
    /// extension identities from their selected source snapshot.
    fn source_file_inventory(&self) -> QueryBatch<ProjectFile> {
        project_source_file_inventory(self)
    }

    /// Test-only counter hooks, quarantined behind one accessor so the
    /// analyzer contract does not carry twenty-one instrumentation methods in
    /// every build. The accessor is feature-gated rather than the hooks being a
    /// side trait: the root integration suites enable `test-support` and call
    /// these through `&dyn IAnalyzer`.
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn AnalyzerTestHooks {
        &NoOpAnalyzerTestHooks
    }

    /// Files this analyzer adopted through a structured language relation even
    /// though the extension registry does not route them to the language.
    ///
    /// This is the narrow, cheap ownership surface hosts such as the workspace
    /// watcher need. It does not validate parse products and must not infer
    /// ownership from a filename extension at the host boundary.
    #[doc(hidden)]
    fn claimed_files(&self) -> Vec<ProjectFile> {
        Vec::new()
    }

    /// Return the complete declaration inventory for this workspace snapshot,
    /// retaining each declaration's optional primary source range. `None`
    /// distinguishes an incomplete answer (for example cancellation or a
    /// store failure) from a successful inventory, including an empty one.
    fn workspace_declarations_with_primary_ranges(
        &self,
        cancellation: &CancellationToken,
    ) -> Option<Vec<(CodeUnit, Option<crate::analyzer::Range>)>> {
        if cancellation.is_cancelled() {
            return None;
        }
        let declarations = self.all_declarations_with_primary_ranges();
        (!cancellation.is_cancelled()).then_some(declarations)
    }

    /// Starts a top-level query boundary. Persisted analyzers use this to
    /// memoize filesystem liveness checks for the duration of one request.
    fn begin_query(&self, _context: &Arc<AnalyzerQueryContext>) {}

    /// Ends a top-level query boundary and releases request-scoped memoized state.
    fn end_query(&self, _context: &Arc<AnalyzerQueryContext>) {}

    /// Records one input this analyzer read, on every read ledger open around
    /// it (issue: impact-sliced `--diff-base`, Milestone 1).
    ///
    /// This is the seam the funnels that hold only a `&dyn IAnalyzer` -- the
    /// usage-ranking graph acquisition, the direct-import layer, the reference
    /// candidate derivation, the descendant index, the dispatch oracle -- use
    /// to reach the request boundary, exactly as `begin_query` and `end_query`
    /// do. Reads follow this thread's attribution frame. Helper tasks transport
    /// that frame; shared builders explicitly broadcast to active contexts.
    /// An explicit nested capture replaces only the enclosing ledger it names.
    fn record_read(&self, _key: crate::analyzer::read_ledger::ReadKey) {}

    /// Record a shared set-valued receipt. Custom recorders retain the scalar
    /// fallback; ledger-bearing analyzers can absorb its identity directly.
    fn record_read_receipt(&self, keys: &Arc<[crate::analyzer::ReadKey]>) {
        for key in keys.iter() {
            self.record_read(key.clone());
        }
    }

    /// Record the immutable named set observed at this capture boundary.
    fn record_read_capture(&self, reads: &crate::analyzer::ReadLedger) {
        for key in reads.unordered_keys() {
            self.record_read(key);
        }
    }

    /// Records one funnel crossing this analyzer could not name through the
    /// current attribution frame.
    ///
    /// This is the contract for a funnel that reaches a derived value it has
    /// no identity for: it says so instead of staying silent, and the ledger's
    /// unattributed count makes every unit produced under it `Unbounded`. A
    /// silent crossing would leave the read set looking complete while an
    /// input it never named could move.
    fn record_unattributed_read(&self) {
        self.record_unattributed_reads(1);
    }

    fn record_unattributed_reads(&self, _count: usize) {}

    /// Owned capability for static relational frontier handles. Unsupported
    /// analyzers fail closed if a frontier is read under capture.
    fn relational_frontier_read_recorder(
        &self,
    ) -> crate::analyzer::relational_frontier::FrontierReadRecorder {
        crate::analyzer::relational_frontier::unbound_frontier_read_recorder()
    }

    /// Mark transient execution state through the same worker broadcasting and
    /// nested-capture attribution used by reads.
    fn mark_execution_dependent(&self) {
        self.mark_execution_dependent_reads(1);
    }

    fn mark_execution_dependent_reads(&self, _count: usize) {}

    /// Whether read recording reaches the active attribution frame. Wrappers
    /// must forward this capability along with the recording operations; a
    /// local ledger registration is not required for thread-owned captures.
    /// The default is deliberately false: hand-written fakes must opt in only
    /// when their recording operations reach the active consumers.
    fn records_query_reads(&self) -> bool {
        false
    }

    /// Whether any open request boundary carries a read ledger.
    ///
    /// A funnel consults this before it builds a key: with no ledger attached
    /// -- every run that is not an incremental policy evaluation -- recording
    /// must cost one relaxed atomic load and no allocation.
    fn read_ledger_attached(&self) -> bool {
        false
    }

    /// Read-only fallback destinations for the active-ledger key check.
    /// Carried frames supply their own destinations instead of this registry.
    #[doc(hidden)]
    fn read_ledger_contexts(&self) -> Vec<Arc<AnalyzerQueryContext>> {
        Vec::new()
    }

    /// The innermost ledger opened by the current thread, if one is active.
    ///
    /// This identifies the one enclosing ledger a nested replayable funnel may
    /// shadow. Ledgers opened by other threads cannot be shadowed here.
    #[doc(hidden)]
    fn current_thread_read_ledger(&self) -> Option<Arc<crate::analyzer::read_ledger::ReadLedger>> {
        current_thread_read_ledger()
    }

    /// Best-effort batch-warm the request-scoped `definitions()` memo for
    /// names the caller already knows it will query.
    fn prefetch_definitions(&self, fq_names: &[String]) {
        CodeUnitIndex::prefetch_definitions(self, fq_names);
    }

    /// The cancellation token carried by the innermost active query boundary.
    ///
    /// Compatibility APIs such as `CodeUnitIndex::definitions` cannot accept a
    /// token without breaking their public contract. Their relational adapters
    /// consult this hook so moving a lookup behind SQL does not make it
    /// uncancellable. Implementations without request-scoped state return
    /// `None` and retain their ordinary unbounded behavior.
    #[doc(hidden)]
    fn active_query_cancellation(&self) -> Option<CancellationToken> {
        None
    }

    /// The innermost frozen semantic-model overlay on the current thread.
    ///
    /// `None` means no query override is active and the analyzer may read its
    /// live publication. `Some(None)` deliberately freezes an absent overlay.
    #[doc(hidden)]
    fn active_query_semantic_model_overlay(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        None
    }

    #[doc(hidden)]
    fn active_query_semantic_model_snapshot(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        None
    }

    /// Starts a disposable file-local analyzer read used by broad sequential
    /// consumers such as C++ include-visibility traversal.
    #[doc(hidden)]
    fn begin_streaming_file_read(&self, _file: &ProjectFile) {}

    /// Ends the matching disposable file-local read.
    #[doc(hidden)]
    fn end_streaming_file_read(&self, _file: &ProjectFile) {}

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

    /// The definition-lookup memos for the request this analyzer has open, or
    /// `None` when no query scope is open.
    ///
    /// Candidate discovery builds one `AnalyzerDefinitionLookup` per candidate
    /// file, so memos owned by the lookup made every candidate repeat the same
    /// store batches for the same names (#2883). Sharing them across the
    /// request is the same argument the rest of the query read cache rests on.
    /// See [`crate::analyzer::DefinitionLookupMemo`].
    #[doc(hidden)]
    fn definition_lookup_memo(&self) -> Option<Arc<crate::analyzer::DefinitionLookupMemo>> {
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

    /// Records a typed reason a collection-returning read could not establish
    /// a complete answer, on the current request context and its enclosing chain.
    #[doc(hidden)]
    fn current_query_read_completion(&self) -> Result<(), QueryReadIncomplete> {
        Ok(())
    }

    fn record_query_incomplete(&self, _reason: QueryReadIncomplete) {}

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

    /// Build the structural posting index of every provider a structural query
    /// has already asked to reuse.
    ///
    /// Unlike `warm_query_indexes`, what this warms is not fixed when the
    /// snapshot is installed: the posting index is built only for a provider
    /// whose Auto admission a query has already exercised, so the work appears
    /// after the first structural query rather than at session start (#2879).
    /// A host that warms after every request therefore picks it up on the
    /// request after the one that asked, and a request arriving mid-build
    /// takes its scan path instead of parking on the build.
    ///
    /// Written once over `structural_fact_providers`, which every wrapping
    /// analyzer already forwards, so no language analyzer implements it.
    ///
    /// The providers are warmed together rather than one after another. Each
    /// build claims its own single-flight before it acquires a fact, and a
    /// request that finds a claim takes its scan path; warming serially would
    /// leave every later provider unclaimed for the whole of the first
    /// provider's build, which is exactly the request-path build this exists
    /// to prevent. They run on the dedicated build pool for the same reason
    /// the hierarchy builds do (#1772): a background warm must not consume a
    /// worker of the pool interactive requests fan out on.
    fn warm_structural_indexes(&self) {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            // Warm workers must mask any request frame on a receiving thread.
            let _maintenance = brokk_bifrost_core::analyzer::carried_context::push(None);
            let carried_context =
                brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
            let providers = self.structural_fact_providers();
            crate::analyzer::install_on_dedicated_build_pool(|| {
                use rayon::prelude::*;
                providers.into_par_iter().for_each(|provider| {
                    carried_context.run(|| {
                        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
                            let Some((cache, content_identity)) = structural_index_inputs(provider)
                            else {
                                return;
                            };
                            let cache = cache.inner();
                            if cache.auto_build_outstanding(content_identity) {
                                cache.acquire(provider, &crate::CancellationToken::default());
                            }
                        })
                    })
                });
            });
        })
    }

    /// Whether every posting index `warm_structural_indexes` would build is
    /// already built or already rejected for this analyzer generation.
    fn structural_indexes_warm(&self) -> bool {
        self.structural_fact_providers().iter().all(|provider| {
            structural_index_inputs(*provider).is_none_or(|(cache, content_identity)| {
                !cache.inner().auto_build_outstanding(content_identity)
            })
        })
    }

    /// Stable identity of any external declaration surface consulted while
    /// resolving dispatch for this analyzer generation.
    ///
    /// Asking for the identity may initialize the same lazy index dispatch
    /// would read. `None` means this analyzer has no external dispatch surface,
    /// not that its identity is unknown.
    #[doc(hidden)]
    fn external_dispatch_behavior_identity(
        &self,
    ) -> Option<crate::analyzer::semantic::StableDigest> {
        None
    }

    /// Drop any cached bulk working-tree identities before an explicit
    /// from-disk rebuild. Implementations without such a cache do nothing.
    fn invalidate_cached_file_identities(&self) {}

    /// Stop trusting cached Git identities for paths explicitly reported as
    /// changed before an incremental from-disk rebuild.
    fn invalidate_cached_file_identities_for(&self, _changed_files: &BTreeSet<ProjectFile>) {}

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

    /// Read source-owned reference identities without exposing store handles.
    #[doc(hidden)]
    fn reference_names_in_files(
        &self,
        request: ReferenceNamesInFilesRequest<'_>,
    ) -> Result<ReferenceNamesInFilesResult, StoreError> {
        if request.files.is_empty() || request.names.is_empty() {
            Ok(ReferenceNamesInFilesResult::default())
        } else {
            Err(StoreError::new(
                "reference names in files: unsupported analyzer",
            ))
        }
    }

    /// Execute one typed relational definition batch through this analyzer's
    /// store-backed language projection. Composite analyzers override this to
    /// partition a mixed-language request without exposing store connections
    /// to language crates.
    fn relational_definition_batch(
        &self,
        _requests: &[crate::analyzer::RelationalDefinitionRequest],
        _cancellation: &CancellationToken,
    ) -> crate::analyzer::RelationalBatchOutcome {
        crate::analyzer::RelationalBatchOutcome::Failed(crate::analyzer::RelationalBatchError::new(
            "this analyzer does not provide relational definition lookup",
        ))
    }

    /// The optional structured property-reaching capability.  A missing
    /// provider is distinct from a provider returning a complete empty result.
    fn property_reaching_provider(
        &self,
    ) -> Option<&dyn crate::analyzer::semantic::PropertyReachingProvider> {
        None
    }

    /// Query structured property and evaluation relations at a source range.
    /// Implementations acquire the current semantic artifact and value-flow
    /// snapshot behind this capability, so callers holding only `&dyn
    /// IAnalyzer` do not need to cross the analysis/flow dependency boundary.
    fn property_reaching_for_source_range(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
        limits: crate::analyzer::semantic::PropertyReachingLimits,
        cancellation: &CancellationToken,
    ) -> crate::analyzer::semantic::PropertySourceQueryResult {
        self.property_reaching_provider().map_or_else(
            crate::analyzer::semantic::PropertySourceQueryResult::unsupported,
            |provider| {
                provider.property_reaching_for_source_range(file, range, limits, cancellation)
            },
        )
    }

    /// Execute a relational batch from a compatibility API that has no token
    /// parameter, inheriting the innermost request token when one exists.
    #[doc(hidden)]
    fn relational_definition_batch_for_active_query(
        &self,
        requests: &[crate::analyzer::RelationalDefinitionRequest],
    ) -> crate::analyzer::RelationalBatchOutcome {
        let local_cancellation = CancellationToken::new();
        let active_cancellation = self.active_query_cancellation();
        let outcome = self.relational_definition_batch(
            requests,
            active_cancellation.as_ref().unwrap_or(&local_cancellation),
        );
        if matches!(&outcome, crate::analyzer::RelationalBatchOutcome::Cancelled) {
            self.record_query_incomplete(QueryReadIncomplete::Cancelled);
        }
        outcome
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

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

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
                let ranges = self.ranges(&code_unit);
                candidates.push(SearchSymbolCandidate {
                    primary_range: ranges
                        .iter()
                        .copied()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    has_multiple_ranges: ranges.len() > 1,
                    secondary_range: ranges.get(1).copied(),
                    has_more_ranges: ranges.len() > 2,
                    all_ranges_are_definitions: false,
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

    /// The declaration heads `file` spells paired with the definition bodies
    /// that complete them: a C++ prototype here and the out-of-line body that
    /// defines it, in this file or in a translation unit the include evidence
    /// relates to it. `None` means this analyzer does not model the
    /// declaration/definition peer relation at all -- which is different from
    /// an empty `Some`, a modeled file that holds no peer (issue #1650).
    ///
    /// Asked per file rather than per declaration because the head/body label
    /// comes from classifying the file's occurrences against its parse tree,
    /// which is one pass over the file however many declarations it holds.
    fn declaration_definition_peers(
        &self,
        _file: &ProjectFile,
    ) -> Option<crate::analyzer::structural::DeclarationDefinitionPeers> {
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

    /// Python's ordered direct bases, C3 linearization, effective members, and
    /// nearest inherited method overrides for one selected declaration.
    fn python_class_hierarchy_provider_for(
        &self,
        _declaration: &CodeUnit,
    ) -> Option<&dyn crate::analyzer::usages::python_class_hierarchy::PythonClassHierarchyProvider>
    {
        None
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        None
    }

    /// Per-language structural-search capabilities (issue #328), one provider
    /// per language whose adapter has a structural spec. Languages without a
    /// spec are absent; `query_code` reports them as capability diagnostics
    /// instead of silently returning nothing.
    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        Vec::new()
    }

    /// The complete semantic declaration overlay published for this analyzer
    /// snapshot, if active semantic models have been acquired successfully.
    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        let overlay =
            active_query_model_or_snapshot(self.active_query_semantic_model_overlay(), || {
                self.snapshot_caches()
                    .and_then(AnalyzerSnapshotCaches::semantic_model_overlay)
            });
        if crate::analyzer::read_attribution_records_reads(|| self.read_ledger_attached())
            && let Some(overlay) = overlay.as_ref()
        {
            record_active_model_hash(self, overlay.active_model_set_hash());
        }
        overlay
    }

    /// The activated models and declaration overlay from one atomic runtime
    /// publication, if a host has acquired them for this analyzer snapshot.
    fn active_semantic_model_snapshot(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>> {
        let snapshot =
            active_query_model_or_snapshot(self.active_query_semantic_model_snapshot(), || {
                self.snapshot_caches()
                    .and_then(AnalyzerSnapshotCaches::active_semantic_model_snapshot)
            });
        if crate::analyzer::read_attribution_records_reads(|| self.read_ledger_attached())
            && let Some(snapshot) = snapshot.as_ref()
        {
            record_active_model_hash(self, snapshot.active_models().active_model_set_hash());
        }
        snapshot
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
        self.active_semantic_model_snapshot()
            .map(|snapshot| Arc::clone(snapshot.active_models()))
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

    /// The content identity of every language scope this analyzer serves
    /// (#2449).
    ///
    /// This is what the snapshot-scoped caches key on. It replaced the
    /// process-local source-generation vector, which reported "something in
    /// this process changed" and therefore threw away every workspace relation
    /// on every edit. An identity moves only when the analyzed content, the
    /// language epoch, or the analyzer configuration moves, and it names no
    /// absolute path, so it also compares equal across two checkouts of the
    /// same content.
    ///
    /// An analyzer that cannot answer returns `None`. That is not a licence to
    /// reuse: a caller with no identity must rebuild and record
    /// [`crate::analyzer::invalidation::InvalidationReason::ContentIdentityEvidenceMissing`].
    #[doc(hidden)]
    fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities> {
        None
    }

    /// The [`crate::analyzer::read_ledger::ReadKey::Scope`] naming exactly
    /// `languages`, folded the way verification recomputes it.
    ///
    /// Stated once here because producer and verifier must agree by
    /// construction: verification folds the head's per-language identities
    /// over the key's language set, so a producer that recorded a raw language
    /// digest, or a delegate's own fold, would record a key nothing could ever
    /// match. An analyzer that states no identities has nothing to name the
    /// read by, so the key carries the unattested identity, which compares
    /// equal to no analyzed content and therefore always invalidates.
    #[doc(hidden)]
    fn workspace_scope_read_key(
        &self,
        languages: &[crate::analyzer::Language],
    ) -> crate::analyzer::read_ledger::ReadKey {
        let identity = self
            .workspace_content_identities()
            .and_then(|identities| identities.scope(|language| languages.contains(&language)))
            .unwrap_or_else(
                crate::analyzer::content_identity::WorkspaceContentIdentity::unattested,
            );
        crate::analyzer::read_ledger::ReadKey::scope(languages.iter().copied(), identity)
    }

    /// One read-ledger fact index per language this analyzer serves.
    ///
    /// The producer side of `ReadKey::File` and `ReadKey::Index`: which paths
    /// resolve to which blobs, and which index keys one blob's facts publish.
    /// A composite returns one entry per delegate; an analyzer that publishes
    /// none returns nothing, and a caller with fewer entries than
    /// [`crate::analyzer::CodeUnitIndex::languages`] must widen rather than
    /// conclude that the missing language changed nothing.
    #[doc(hidden)]
    fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
        Vec::new()
    }

    /// The whole-workspace content identity, for a cache whose value spans
    /// every language this analyzer serves.
    #[doc(hidden)]
    fn workspace_content_identity(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentity> {
        self.workspace_content_identities()
            .and_then(|identities| identities.whole_workspace())
    }

    /// Whether a previously captured whole-workspace identity is still the
    /// current one. A missing identity is never a match.
    #[doc(hidden)]
    fn workspace_content_matches(
        &self,
        expected: crate::analyzer::content_identity::WorkspaceContentIdentity,
    ) -> bool {
        self.workspace_content_identity() == Some(expected)
    }

    /// Incrementally refresh the durable import graph after a content change.
    /// `None` means this analyzer cannot prove a complete persistent update.
    #[doc(hidden)]
    fn refresh_persisted_import_graph(
        &self,
        _content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        _cancellation: Option<&CancellationToken>,
        _max_files: usize,
        _max_edges: usize,
    ) -> Result<Option<PersistedImportGraphRefresh>, StoreError> {
        Ok(None)
    }

    /// Read adjacency rows from the complete durable import graph for this
    /// exact workspace identity. `None` means no durable graph is available or
    /// one or more seeds are outside its supported source set.
    #[doc(hidden)]
    fn read_persisted_import_adjacency(
        &self,
        _content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        _direction: PersistedImportDirection,
        _files: &[ProjectFile],
        _edge_limit: usize,
    ) -> Result<Option<PersistedImportAdjacency>, StoreError> {
        Ok(None)
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
        crate::analyzer::usages::find_usages(self as &dyn IAnalyzer, overloads)
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
        let query = UsageFinder::new().query(self, overloads, max_files, max_usages);
        record_usage_lookup(self as &dyn IAnalyzer, overloads, &query.result);
        query
    }

    fn metrics(&self) -> CodeBaseMetrics {
        metrics_from_declarations(self.all_declarations())
    }

    fn contains_tests(&self, _file: &ProjectFile) -> bool {
        false
    }

    /// Whether a directly changed file contains runnable test evidence that is
    /// too repository-local to classify every reverse-walk graph candidate.
    fn contains_tests_for_changed_file(&self, file: &ProjectFile) -> bool {
        self.contains_tests(file)
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

pub(crate) fn increment_test_hook_counter(counter: &AtomicUsize) {
    counter.fetch_add(1, AtomicOrdering::Relaxed);
}

#[doc(hidden)]
pub fn reset_test_hook_counter(counter: &AtomicUsize) {
    counter.store(0, AtomicOrdering::Relaxed);
}

/// The `*_for_test` counter hooks, reached through
/// [`IAnalyzer::test_hooks`]. Every method keeps the no-op / `0` default the
/// hook carried on `IAnalyzer`, so an implementor that instruments nothing
/// inherits [`NoOpAnalyzerTestHooks`] and behaves exactly as before.
#[cfg(any(test, feature = "test-support"))]
pub trait AnalyzerTestHooks {
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

    /// Relational-store round trips issued by `RelationalDefinitionLookup::batch`,
    /// one per call regardless of how many requests it carried. Paired with
    /// a test that also counts the distinct names it resolved, to show "one
    /// batched call for many names" instead of "one call per name" (bifrost#15).
    #[doc(hidden)]
    fn reset_relational_definition_batch_call_count_for_test(&self) {}

    #[doc(hidden)]
    fn relational_definition_batch_call_count_for_test(&self) -> usize {
        0
    }

    /// Records one call to `resolve_definition_batch_with_source`, so a
    /// batching caller can assert it collapsed many per-edge calls into one
    /// call per file rather than re-deriving that from timing (bifrost#15).
    /// Recorded through this hook, rather than a process-wide static,
    /// because the call site holds only `&dyn IAnalyzer` and per-instance
    /// counting keeps concurrently running tests from inflating each
    /// other's counts (#3010).
    #[doc(hidden)]
    fn record_resolve_definition_batch_with_source_call_for_test(&self) {}

    #[doc(hidden)]
    fn reset_resolve_definition_batch_with_source_call_count_for_test(&self) {}

    #[doc(hidden)]
    fn resolve_definition_batch_with_source_call_count_for_test(&self) -> usize {
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
        self.full_candidate_hydration_count_for_test()
            + self.bulk_candidate_hydration_count_for_test()
    }

    #[doc(hidden)]
    fn full_candidate_hydration_count_for_test(&self) -> usize {
        0
    }

    #[doc(hidden)]
    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        0
    }

    /// Lifecycle counters for the snapshot-owned Java exact usage-evidence
    /// cache. These counters are deliberately request-independent: they make
    /// cold/warm and shared-work tests observable without timing assumptions.
    #[doc(hidden)]
    fn reset_java_usage_evidence_cache_stats_for_test(&self) {}

    #[doc(hidden)]
    fn java_usage_evidence_cache_stats_for_test(
        &self,
    ) -> crate::analyzer::JavaUsageEvidenceCacheStats {
        Default::default()
    }

    #[doc(hidden)]
    fn reset_workspace_path_scan_count_for_test(&self) {}

    #[doc(hidden)]
    fn workspace_path_scan_count_for_test(&self) -> usize {
        0
    }

    /// SHA-1 blob hashes the analyzer ran to key facts by a file's exact
    /// source (#2917). A query over N unchanged files performs at most N; a
    /// repeat query over the same files performs zero.
    #[doc(hidden)]
    fn reset_blob_hash_count_for_test(&self) {}

    #[doc(hidden)]
    fn blob_hash_count_for_test(&self) -> usize {
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

    /// Files whose full per-file facts one targeted Scala usage query
    /// materialized (sweep-excluded; #3142). The eager whole-workspace read
    /// this replaces materialized every analyzable file.
    #[doc(hidden)]
    fn reset_scala_query_file_facts_touched_for_test(&self) {}

    #[doc(hidden)]
    fn scala_query_file_facts_touched_for_test(&self) -> usize {
        0
    }

    /// Arm one deterministic semantic-cache invalidation after a selected
    /// result-contract artifact has been promoted and before it is
    /// materialized through the policy continuation.
    #[doc(hidden)]
    fn arm_selector_continuation_semantic_cache_invalidation_for_test(&self) {}

    #[doc(hidden)]
    fn invalidate_selector_continuation_semantic_cache_if_armed_for_test(&self) {}

    #[doc(hidden)]
    fn selector_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> crate::analyzer::semantic::SemanticCacheRevivalCensus {
        crate::analyzer::semantic::SemanticCacheRevivalCensus::default()
    }

    /// Arm one deterministic semantic-cache invalidation after a successful
    /// typestate evaluation root has committed its artifact window and before
    /// the next root starts.
    #[doc(hidden)]
    fn arm_evaluation_root_continuation_semantic_cache_invalidation_for_test(&self) {}

    #[doc(hidden)]
    fn invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test(&self) {}

    #[doc(hidden)]
    fn evaluation_root_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> crate::analyzer::semantic::SemanticCacheRevivalCensus {
        crate::analyzer::semantic::SemanticCacheRevivalCensus::default()
    }

    /// How this analyzer produced each file's semantics, per file, split into
    /// physical lowerings and the two kinds of complete-artifact cache hit.
    ///
    /// This is the physical unit behind semantic work accounting across a
    /// cache eviction: whether one touch of a file lowers it again or is
    /// served from the complete cache is what the cache's ready state
    /// decides, and only a lowering repeats that file's materialization work.
    #[doc(hidden)]
    fn semantic_materialization_census_for_test(
        &self,
    ) -> Vec<(
        crate::analyzer::semantic::WorkspaceRelativePath,
        crate::analyzer::semantic::SemanticMaterializationCensus,
    )> {
        Vec::new()
    }
}

/// The hooks object every implementor that instruments nothing shares.
#[cfg(any(test, feature = "test-support"))]
pub struct NoOpAnalyzerTestHooks;

#[cfg(any(test, feature = "test-support"))]
impl AnalyzerTestHooks for NoOpAnalyzerTestHooks {}

type AttributionLedger = (Arc<crate::analyzer::ReadLedger>, std::thread::ThreadId);

type PathModuleFailureCell = Arc<Mutex<Option<StoreError>>>;

/// Scalar failures belong to one request, including its transported work.
/// This finite language-keyed map never lives in a shared QueryReadCache.
#[derive(Default)]
struct PathModuleRequestFailures(Mutex<HashMap<crate::Language, PathModuleFailureCell>>);

/// Query ancestry and path failures travel together without manufacturing a
/// read-routing frame for ordinary scopes. Nested states share only the
/// request's finite language-keyed failure cells; ancestry stays immutable.
struct AnalyzerRequestState {
    path_modules: Arc<PathModuleRequestFailures>,
    context: Option<Arc<AnalyzerQueryContext>>,
}

#[derive(Clone)]
enum AttributionFrame {
    Broadcast,
    Ledgers(Vec<AttributionLedger>),
}

use brokk_bifrost_core::analyzer::carried_context::{self, CarriedContextGuard};

impl carried_context::ExecutionAttribution for AttributionFrame {
    fn mark_execution_dependent(&self) {
        if let Self::Ledgers(ledgers) = self {
            for (ledger, _) in ledgers {
                ledger.mark_execution_dependent();
            }
        }
    }
}

static READ_ATTRIBUTION_FALLBACKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Number of read recorder crossings using implicit broadcast with a ledger attached.
pub fn read_attribution_fallback_count() -> u64 {
    READ_ATTRIBUTION_FALLBACKS.load(AtomicOrdering::Relaxed)
}

/// Request read attribution that can be transported to a helper task.
#[derive(Clone)]
pub struct ReadAttribution {
    frame: AttributionFrame,
    request_state: Option<Arc<AnalyzerRequestState>>,
}

impl ReadAttribution {
    /// Start a request. A thread that already records into ledgers -- its
    /// caller wrapped the request in a ledger scope, or handed the request to
    /// this worker -- keeps them, exactly as a serial run records. Any other
    /// thread records nothing until the request opens its own ledger scopes,
    /// so its reads never reach another request's ledgers through the
    /// broadcast fallback.
    pub fn for_request() -> Self {
        let frame = with_attribution_frame(|frame| match frame {
            Some(frame @ AttributionFrame::Ledgers(_)) => frame.clone(),
            _ => AttributionFrame::Ledgers(Vec::new()),
        });
        Self {
            frame,
            request_state: carried_context::request_state::<AnalyzerRequestState>(),
        }
    }

    /// Attribute background reads to all active analyzer ledgers.
    pub fn broadcast() -> Self {
        Self {
            frame: AttributionFrame::Broadcast,
            request_state: carried_context::request_state::<AnalyzerRequestState>(),
        }
    }

    /// Install this attribution for the lifetime of the returned guard.
    pub fn install(&self) -> ReadAttributionGuard {
        ReadAttributionGuard {
            _guard: Some(carried_context::push_with_execution_attribution(Arc::new(
                self.frame.clone(),
            ))),
            _request_state: carried_context::push_request_state(
                self.request_state
                    .as_ref()
                    .map(|state| Arc::clone(state) as _),
            ),
        }
    }
}

/// Restores the previous attribution on the installing thread.
pub struct ReadAttributionGuard {
    _guard: Option<CarriedContextGuard>,
    _request_state: carried_context::RequestStateGuard,
}

fn current_query_context() -> Option<Arc<AnalyzerQueryContext>> {
    carried_context::request_state::<AnalyzerRequestState>().and_then(|state| state.context.clone())
}

fn with_attribution_frame<R>(f: impl FnOnce(Option<&AttributionFrame>) -> R) -> R {
    carried_context::with_top::<AttributionFrame, _>(|slot| f(slot.flatten()))
}

fn query_attribution(context: &Arc<AnalyzerQueryContext>) -> ReadAttributionGuard {
    let frame = context.read_ledger().map(|ledger| {
        let mut ledgers = with_attribution_frame(|frame| match frame {
            Some(AttributionFrame::Ledgers(ledgers)) => ledgers.clone(),
            _ => Vec::new(),
        });
        ledgers.retain(|(ledger, _)| !context.shadows_read_ledger(ledger));
        ledgers.push((Arc::clone(ledger), std::thread::current().id()));
        AttributionFrame::Ledgers(ledgers)
    });
    let path_modules = carried_context::request_state::<AnalyzerRequestState>()
        .map(|state| Arc::clone(&state.path_modules))
        .unwrap_or_default();
    ReadAttributionGuard {
        _guard: frame
            .map(|frame| carried_context::push_with_execution_attribution(Arc::new(frame))),
        _request_state: carried_context::push_request_state(Some(Arc::new(AnalyzerRequestState {
            path_modules,
            context: Some(Arc::clone(context)),
        }))),
    }
}

fn path_module_request_state() -> Option<carried_context::RequestStateGuard> {
    carried_context::request_state::<AnalyzerRequestState>()
        .is_none()
        .then(|| {
            carried_context::push_request_state(Some(Arc::new(AnalyzerRequestState {
                path_modules: Arc::new(PathModuleRequestFailures::default()),
                context: None,
            })))
        })
}

pub(crate) fn path_module_request_failure_cell(
    language: crate::Language,
) -> Option<PathModuleFailureCell> {
    let state = carried_context::request_state::<AnalyzerRequestState>()?;
    let mut cells = state
        .path_modules
        .0
        .lock()
        .expect("request path-module failure lock poisoned");
    Some(Arc::clone(cells.entry(language).or_default()))
}

pub(super) fn innermost_read_ledger() -> Option<Arc<crate::analyzer::ReadLedger>> {
    with_attribution_frame(|frame| match frame {
        Some(AttributionFrame::Ledgers(ledgers)) => {
            ledgers.last().map(|(ledger, _)| Arc::clone(ledger))
        }
        _ => None,
    })
}

pub(crate) fn current_thread_read_ledger() -> Option<Arc<crate::analyzer::ReadLedger>> {
    with_attribution_frame(|frame| match frame {
        Some(AttributionFrame::Ledgers(ledgers)) => {
            let current = std::thread::current().id();
            ledgers
                .iter()
                .rev()
                .find(|(_, owner)| *owner == current)
                .map(|(ledger, _)| Arc::clone(ledger))
        }
        _ => None,
    })
}

/// Whether a read has consumers. A ledger frame owns its attribution even
/// when its ledgers were registered on a different analyzer; only broadcast
/// needs the destination analyzer's attached-ledger count.
pub fn read_attribution_records_reads(analyzer_has_ledger: impl FnOnce() -> bool) -> bool {
    with_attribution_frame(|frame| match frame {
        Some(AttributionFrame::Ledgers(ledgers)) => !ledgers.is_empty(),
        _ => analyzer_has_ledger(),
    })
}

/// True when recording can use the thread frame without analyzer contexts.
pub(crate) fn has_read_attribution_ledgers() -> bool {
    with_attribution_frame(|frame| matches!(frame, Some(AttributionFrame::Ledgers(_))))
}

/// Releases request-scoped analyzer memoization on every return path.
pub struct AnalyzerQueryScope<'a> {
    analyzer: &'a dyn IAnalyzer,
    context: Arc<AnalyzerQueryContext>,
    attribution: Option<ReadAttributionGuard>,
    _request_state: Option<carried_context::RequestStateGuard>,
}

impl<'a> AnalyzerQueryScope<'a> {
    fn with_context(analyzer: &'a dyn IAnalyzer, context: AnalyzerQueryContext) -> Self {
        let request_state = path_module_request_state();
        let context = Arc::new(context);
        let attribution = Some(query_attribution(&context));
        analyzer.begin_query(&context);
        Self {
            analyzer,
            context,
            attribution,
            _request_state: request_state,
        }
    }

    pub fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(analyzer, AnalyzerQueryContext::default())
    }

    /// Capture every distinct incomplete-read reason for a file-derived cache
    /// admission. Ordinary scopes retain their first-reason behavior.
    #[doc(hidden)]
    pub fn capturing_read_incompleteness(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                captured_read_incompleteness: Some(Mutex::new(Vec::new())),
                ..Default::default()
            },
        )
    }

    /// Reasons observed by a scope opened with `capturing_read_incompleteness`.
    #[doc(hidden)]
    pub fn captured_read_incompleteness(&self) -> Vec<QueryReadIncomplete> {
        self.context
            .captured_read_incompleteness
            .as_ref()
            .expect("only a capturing scope can enumerate read incompleteness")
            .lock()
            .expect("read incompleteness mutex poisoned")
            .clone()
    }

    /// Open a request boundary that memoizes identifier candidate results
    /// without retaining the analyzer's other request caches on this thread.
    /// This is for census work that repeats the same bounded store lookup
    /// across many reference sites (#4510).
    #[doc(hidden)]
    pub fn for_identifier_candidate_memo(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext::for_identifier_candidate_memo(),
        )
    }

    /// Open a request boundary that carries the caller's deadline, so reads
    /// issued anywhere below it can stop when that deadline expires.
    pub fn with_cancellation(
        analyzer: &'a dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext::with_cancellation(cancellation.clone()),
        )
    }

    /// Open a resolver boundary against one exact semantic-model overlay.
    /// Passing `None` freezes the absence instead of falling through to a
    /// publication that may appear later in the request.
    pub fn with_semantic_model_overlay(
        analyzer: &'a dyn IAnalyzer,
        semantic_model_overlay: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    ) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext::with_semantic_model_overlay(semantic_model_overlay),
        )
    }

    /// Open a request boundary against one atomic active/overlay publication.
    /// Nested consumers can recapture this snapshot without observing a later
    /// live publication; `None` deliberately freezes the absence.
    pub fn with_active_semantic_model_snapshot(
        analyzer: &'a dyn IAnalyzer,
        snapshot: Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext::with_active_semantic_model_snapshot(snapshot),
        )
    }

    /// Open a request boundary that records every input it reads into
    /// `ledger`.
    ///
    /// Ordinarily only the outermost scope of a unit's execution carries one.
    /// Nested scopes without a ledger -- the RQL executor opens at least two
    /// of them per execution -- keep recording on that outer ledger. Analyzer
    /// funnels shadow only their explicit enclosing ledger. Reads follow this
    /// thread's attribution frame; helper tasks must transport that frame.
    pub fn with_read_ledger(
        analyzer: &'a dyn IAnalyzer,
        ledger: Arc<crate::analyzer::read_ledger::ReadLedger>,
    ) -> Self {
        Self::with_context(analyzer, AnalyzerQueryContext::with_read_ledger(ledger))
    }

    pub(crate) fn with_nested_read_ledger(
        analyzer: &'a dyn IAnalyzer,
        ledger: Arc<crate::analyzer::read_ledger::ReadLedger>,
        shadowed: Arc<crate::analyzer::read_ledger::ReadLedger>,
    ) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext::with_nested_read_ledger(ledger, shadowed),
        )
    }

    pub fn store_error(&self) -> Option<StoreError> {
        self.context.store_error()
    }

    pub fn read_completion(&self) -> Result<(), QueryReadIncomplete> {
        self.context.read_completion()
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

#[doc(hidden)]
pub fn with_query_scope<R>(analyzer: &dyn IAnalyzer, query: impl FnOnce(QueryToken<'_>) -> R) -> R {
    let scope = AnalyzerQueryScope::new(analyzer);
    query(scope.token())
}

impl Drop for AnalyzerQueryScope<'_> {
    fn drop(&mut self) {
        drop(self.attribution.take());
        self.analyzer.end_query(&self.context);
    }
}

/// Releases one disposable file-local analyzer read on every return path.
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

/// Domain for the digest of one declaration's usage answer.
const USAGE_ANSWER_DOMAIN: &[u8] = b"bifrost-read-ledger:usage-answer:v1";

/// Run one usage lookup behind a private ledger and publish only declaration
/// facts and signature metadata that the result does not itself encode.
///
/// Candidate-file, index, descendant, and scope reads are implementation
/// details of the replayable [`LookupKind::Usages`] answer published after
/// this scope closes. Call resolution also consumes the target's exact
/// declaration identity, structured signature metadata, and owner. Those facts
/// can change while the set of usage sites stays fixed, so their precise
/// lookup keys remain inputs of the caller's unit.
pub(crate) fn capture_usage_lookup_reads<T>(
    analyzer: &dyn IAnalyzer,
    lookup: impl FnOnce() -> T,
) -> T {
    if !crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return lookup();
    }

    let (result, reads) = capture_nested_reads(analyzer, lookup);
    for key in reads {
        if matches!(
            key,
            crate::analyzer::read_ledger::ReadKey::Lookup {
                kind: crate::analyzer::read_ledger::LookupKind::DeclarationFacts
                    | crate::analyzer::read_ledger::LookupKind::SignatureMetadata,
                ..
            }
        ) {
            analyzer.record_read(key);
        }
    }
    result
}

/// Run `read` behind a ledger that shadows the caller's ledger and return the
/// captured implementation reads with the result.
///
/// Callers must publish the subset their own replayable answer does not
/// subsume. This helper is crate-private so only analyzer funnels, which own
/// that result contract, can establish such a boundary.
#[doc(hidden)]
pub fn capture_nested_reads<T>(
    analyzer: &dyn IAnalyzer,
    read: impl FnOnce() -> T,
) -> (T, Vec<crate::analyzer::read_ledger::ReadKey>) {
    let Some(enclosing) = analyzer.current_thread_read_ledger() else {
        // No scope in this frame was opened by this thread. Keep recording
        // through the frame without a private capture.
        return (read(), Vec::new());
    };
    let (result, captured) = capture_with_read_ledger_scope(analyzer, Some(&enclosing), read);
    enclosing.mark_execution_dependent_reads(captured.execution_dependences());
    (result, captured.unordered_keys())
}

pub(super) fn capture_with_read_ledger_scope<T>(
    analyzer: &dyn IAnalyzer,
    enclosing: Option<&Arc<crate::analyzer::read_ledger::ReadLedger>>,
    query: impl FnOnce() -> T,
) -> (T, Arc<crate::analyzer::read_ledger::ReadLedger>) {
    capture_with_read_registration(
        enclosing,
        |context| {
            // capture_with_read_registration installed this context before
            // invoking us. Do not install its ledger a second time.
            analyzer.begin_query(&context);
            AnalyzerQueryScope {
                analyzer,
                context,
                attribution: None,
                _request_state: path_module_request_state(),
            }
        },
        query,
    )
}

pub(super) fn capture_with_read_registration<T, G>(
    enclosing: Option<&Arc<crate::analyzer::ReadLedger>>,
    register: impl FnOnce(Arc<AnalyzerQueryContext>) -> G,
    query: impl FnOnce() -> T,
) -> (T, Arc<crate::analyzer::ReadLedger>) {
    let captured = Arc::new(crate::analyzer::ReadLedger::new());
    let context = Arc::new(match enclosing {
        Some(enclosing) => AnalyzerQueryContext::with_nested_read_ledger(
            Arc::clone(&captured),
            Arc::clone(enclosing),
        ),
        None => AnalyzerQueryContext::with_read_ledger(Arc::clone(&captured)),
    });
    let result = {
        let _attribution = query_attribution(&context);
        let _registration = register(Arc::clone(&context));
        query()
    };
    (result, captured)
}

/// Replay all dependencies of a completed query into its current caller.
#[doc(hidden)]
pub fn replay_query_reads(analyzer: &dyn IAnalyzer, reads: &crate::analyzer::ReadLedger) {
    analyzer.record_read_capture(reads);
    replay_query_read_receipt(
        analyzer,
        [],
        reads.unattributed_reads(),
        reads.execution_dependences(),
    );
}

/// Replay an immutable memo receipt without reinserting its keys per consumer.
#[doc(hidden)]
pub fn replay_shared_query_read_receipt(
    analyzer: &dyn IAnalyzer,
    keys: &Arc<[crate::analyzer::ReadKey]>,
    unattributed_reads: usize,
    execution_dependences: usize,
) {
    analyzer.record_read_receipt(keys);
    replay_query_read_receipt(analyzer, [], unattributed_reads, execution_dependences);
}

/// Replay an owned snapshot of a query's named and unattributed reads.
/// Named keys are sets in each ledger; unattributed crossings are counts and
/// must be replayed only for a consumer, never again after its own capture.
#[doc(hidden)]
pub fn replay_query_read_keys(
    analyzer: &dyn IAnalyzer,
    keys: impl IntoIterator<Item = crate::analyzer::ReadKey>,
    unattributed_reads: usize,
) {
    replay_query_read_receipt(analyzer, keys, unattributed_reads, 0);
}

/// Replay all three dependency channels from an owned receipt.
pub fn replay_query_read_receipt(
    analyzer: &dyn IAnalyzer,
    keys: impl IntoIterator<Item = crate::analyzer::ReadKey>,
    unattributed_reads: usize,
    execution_dependences: usize,
) {
    replay_read_channels(
        keys,
        unattributed_reads,
        execution_dependences,
        |key| analyzer.record_read(key),
        |count| analyzer.record_unattributed_reads(count),
        |count| analyzer.mark_execution_dependent_reads(count),
    );
}

pub(super) fn replay_read_channels(
    keys: impl IntoIterator<Item = crate::analyzer::ReadKey>,
    unattributed_reads: usize,
    execution_dependences: usize,
    mut record: impl FnMut(crate::analyzer::ReadKey),
    mut unattributed: impl FnMut(usize),
    mut execution_dependent: impl FnMut(usize),
) {
    for key in keys {
        record(key);
    }
    if unattributed_reads > 0 {
        unattributed(unattributed_reads);
    }
    if execution_dependences > 0 {
        execution_dependent(execution_dependences);
    }
}

/// Capture the dependency reads of a replayable query without changing its
/// enclosing caller's ledger. Unlike a resolver funnel, the query subsumes no
/// dependencies: all captured reads, including unattributed crossings, are
/// forwarded to that caller when execution finishes.
///
/// Every recorded read must come from analyzers and projects of the workspace
/// snapshot used to verify this capture. Read keys carry no workspace identity,
/// and attribution does not check ownership; see #7749.
///
/// A separate ordinary ledger would become the parent of nested resolver
/// captures, exposing their implementation reads to the original caller. Link
/// the capture to that caller explicitly instead. Other threads' ledgers remain
/// visible beside the capture and receive reads directly; only a ledger whose
/// scope was opened by this thread is shadowed and receives reads on completion.
#[doc(hidden)]
pub fn capture_query_reads<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> T,
) -> (T, Arc<crate::analyzer::read_ledger::ReadLedger>) {
    let enclosing = analyzer.current_thread_read_ledger();
    let (result, captured) = capture_with_read_ledger_scope(analyzer, enclosing.as_ref(), query);
    if let Some(enclosing) = enclosing {
        forward_captured_query_reads(&enclosing, &captured);
    }
    (result, captured)
}

/// Capture an authority build whose named inputs are subsumed by its answer
/// keys. Unattributed crossings cannot be subsumed and still reach the caller.
/// Return their count so a retained authority can replay them on later hits.
#[doc(hidden)]
pub fn capture_subsumed_query_reads<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> T,
) -> (T, usize) {
    let (result, reads) = capture_subsumed_query_read_receipt(analyzer, query);
    (result, reads.unattributed_reads)
}

/// Retain the unsubsumable channels for an authority that can be read again.
pub fn capture_subsumed_query_read_receipt<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> T,
) -> (
    T,
    brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<crate::analyzer::ReadKey>,
) {
    let enclosing = analyzer.current_thread_read_ledger();
    let (result, captured) = capture_with_read_ledger_scope(analyzer, enclosing.as_ref(), query);
    let reads = brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads {
        keys: Arc::from([]),
        unattributed_reads: captured.unattributed_reads(),
        execution_dependences: captured.execution_dependences(),
    };
    if let Some(enclosing) = enclosing {
        replay_read_channels(
            [],
            reads.unattributed_reads,
            reads.execution_dependences,
            |key| enclosing.record(key),
            |count| enclosing.record_unattributed_reads(count),
            |count| enclosing.mark_execution_dependent_reads(count),
        );
    }
    (result, reads)
}

pub(crate) fn forward_captured_query_reads(
    enclosing: &crate::analyzer::ReadLedger,
    captured: &crate::analyzer::ReadLedger,
) {
    enclosing.absorb_capture(captured);
    enclosing.record_unattributed_reads(captured.unattributed_reads());
    enclosing.mark_execution_dependent_reads(captured.execution_dependences());
}

/// Record one funnel key through the current attribution frame. Broadcast
/// visits active contexts except explicitly shadowed enclosing ledgers.
pub(crate) fn record_read_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    key: crate::analyzer::read_ledger::ReadKey,
) {
    note_read_attribution_fallback(contexts, 1);
    let mut hash = None;
    for_each_unshadowed_active_ledger(contexts, |ledger| ledger.record_borrowed(&key, &mut hash));
}

/// Handle the common request-frame route before consulting analyzer registries.
/// An empty ledger frame still handles the read: it must not fall back to a
/// different request's attached contexts.
pub(crate) fn record_read_on_attribution_frame(key: &crate::analyzer::ReadKey) -> bool {
    with_attribution_frame(|frame| {
        let Some(AttributionFrame::Ledgers(ledgers)) = frame else {
            return false;
        };
        let mut hash = None;
        for (ledger, _) in ledgers {
            ledger.record_borrowed(key, &mut hash);
        }
        true
    })
}

pub(crate) fn record_receipt_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    keys: &Arc<[crate::analyzer::ReadKey]>,
) {
    if keys.is_empty() {
        return;
    }
    note_read_attribution_fallback(contexts, 1);
    for_each_unshadowed_active_ledger(contexts, |ledger| ledger.absorb_receipt(keys));
}

pub(crate) fn record_capture_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    reads: &crate::analyzer::ReadLedger,
) {
    if reads.is_empty() {
        return;
    }
    note_read_attribution_fallback(contexts, 1);
    for_each_unshadowed_active_ledger(contexts, |ledger| ledger.absorb_capture(reads));
}

/// Whether every destination of a read already contains `key`.
/// Uses the recorder's routing, including transported and shadowed ledgers.
/// No destinations means there is no recording obligation.
#[doc(hidden)]
pub fn read_key_recorded_on_active_ledgers(
    analyzer: &dyn IAnalyzer,
    key: &crate::analyzer::ReadKey,
) -> bool {
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        analyzer.read_ledger_contexts()
    };
    let mut recorded = true;
    for_each_unshadowed_active_ledger(&contexts, |ledger| {
        recorded &= ledger.contains_read_key(key);
    });
    recorded
}

// Only actual recorder crossings count fallbacks. The presence predicate
// visits the same destinations without creating diagnostic events.
fn note_read_attribution_fallback(contexts: &[Arc<AnalyzerQueryContext>], count: usize) {
    if contexts
        .iter()
        .any(|context| context.read_ledger().is_some())
        && carried_context::with_top::<AttributionFrame, _>(|slot| slot.is_none())
    {
        READ_ATTRIBUTION_FALLBACKS.fetch_add(count as u64, AtomicOrdering::Relaxed);
        debug_assert!(
            rayon::current_thread_index().is_none(),
            "#7116: rayon read with an attached ledger requires transported ReadAttribution or explicit Broadcast"
        );
    }
}

fn for_each_unshadowed_active_ledger(
    contexts: &[Arc<AnalyzerQueryContext>],
    mut record: impl FnMut(&crate::analyzer::read_ledger::ReadLedger),
) {
    let handled = with_attribution_frame(|frame| match frame {
        Some(AttributionFrame::Ledgers(ledgers)) => {
            for (ledger, _) in ledgers {
                record(ledger);
            }
            true
        }
        Some(AttributionFrame::Broadcast) => false,
        None => false,
    });
    if handled {
        return;
    }
    for context in contexts {
        let Some(ledger) = context.read_ledger() else {
            continue;
        };
        if contexts
            .iter()
            .any(|candidate| candidate.shadows_read_ledger(ledger))
        {
            continue;
        }
        record(ledger);
    }
}

/// Record one unattributed funnel crossing under the same shadowing contract
/// as [`record_read_on_active_ledgers`].
pub(crate) fn record_unattributed_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    count: usize,
) {
    if count == 0 {
        return;
    }
    note_read_attribution_fallback(contexts, count);
    for_each_unshadowed_active_ledger(contexts, |ledger| ledger.record_unattributed_reads(count));
}

/// Admit unattributed reads before acquiring caller-specific fallback contexts.
pub(crate) fn record_unattributed_reads(
    count: usize,
    ledger_attached: impl FnOnce() -> bool,
    fallback_contexts: impl FnOnce() -> Vec<Arc<AnalyzerQueryContext>>,
) {
    if count == 0 {
        return;
    }
    if !crate::analyzer::read_attribution_records_reads(ledger_attached) {
        return;
    }
    record_unattributed_on_active_ledgers(&fallback_contexts(), count);
}

/// Acquire owner contexts only when recording needs a fallback registry.
pub(crate) fn record_execution_dependence(
    count: usize,
    ledger_attached: impl FnOnce() -> bool,
    fallback_contexts: impl FnOnce() -> Vec<Arc<AnalyzerQueryContext>>,
) {
    if count == 0 {
        return;
    }
    if !crate::analyzer::read_attribution_records_reads(ledger_attached) {
        return;
    }
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        fallback_contexts()
    };
    record_execution_dependence_on_active_ledgers(&contexts, count);
}

/// Execution dependence follows the same frame routing as input attribution.
pub(crate) fn record_execution_dependence_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    count: usize,
) {
    if count == 0 {
        return;
    }
    note_read_attribution_fallback(contexts, count);
    for_each_unshadowed_active_ledger(contexts, |ledger| {
        ledger.mark_execution_dependent_reads(count)
    });
}

/// Record one usage lookup per overload the caller asked about, each carrying
/// the digest of that overload's own answer.
///
/// This is a cross-file channel: the answer changes when a file the reader
/// never mentions gains a call site, and no `File` or `Index` key the reader
/// recorded would move. Recording the answer digest is what lets Milestone 2
/// re-run the lookup against the head and see the difference.
pub(crate) fn record_usage_lookup(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    result: &FuzzyResult,
) {
    if !crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return;
    }
    for overload in overloads {
        analyzer.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
            crate::analyzer::read_ledger::LookupKind::Usages,
            crate::analyzer::read_ledger::LookupQuestion::declaration(overload),
            usage_answer_digest(result, overload),
        ));
    }
}

/// The canonical digest of what a usage query answered about one overload.
///
/// Sites are folded by workspace-relative path and byte range, never by
/// `ProjectFile` (which knows its root) and never by row address, so the same
/// answer over the same content at two roots digests identically. A refusal
/// digests as the refusal, not as an empty answer: "we did not look" and "there
/// is nothing" must not compare equal.
pub(crate) fn usage_answer_digest(
    result: &FuzzyResult,
    overload: &CodeUnit,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut hasher = crate::analyzer::canonical_hash::CanonicalHasher::new(USAGE_ANSWER_DOMAIN);
    if let FuzzyResult::Incomplete { diagnostics, .. } = result {
        hasher.value(b"semantic_incomplete");
        let mut reasons = diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    &diagnostic.fq_name,
                    &diagnostic.strategy,
                    &diagnostic.reason_kind,
                    &diagnostic.reason,
                )
            })
            .collect::<Vec<_>>();
        reasons.sort();
        for (fq_name, strategy, reason_kind, reason) in reasons {
            hasher.field(fq_name, strategy.as_bytes());
            hasher.field(reason_kind, reason.as_bytes());
        }
    }
    match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        }
        | FuzzyResult::Incomplete {
            hits_by_overload, ..
        }
        | FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => {
            hasher.value(b"hits");
            let mut sites = hits_by_overload
                .get(overload)
                .into_iter()
                .flatten()
                .map(|hit| {
                    (
                        crate::path_utils::rel_path_string(&hit.file),
                        hit.start_offset,
                        hit.end_offset,
                    )
                })
                .collect::<Vec<_>>();
            sites.sort();
            sites.dedup();
            for (path, start, end) in sites {
                hasher.field(&path, &(start as u64).to_be_bytes());
                hasher.value(&(end as u64).to_be_bytes());
            }
        }
        FuzzyResult::Failure { reason_kind, .. } => hasher.field("failure", reason_kind.as_bytes()),
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => {
            hasher.field(
                "too_many_callsites",
                &(*total_callsites as u64).to_be_bytes(),
            );
            hasher.field("limit", &(*limit as u64).to_be_bytes());
        }
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish())
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

pub(crate) fn child_first_start<A: IAnalyzer + ?Sized>(analyzer: &A, child: &CodeUnit) -> usize {
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
mod read_ledger_scope_tests {

    use super::AnalyzerQueryContext;

    use super::record_read_on_active_ledgers;

    use super::record_unattributed_on_active_ledgers;
    use crate::analyzer::read_ledger::{ReadKey, ReadLedger};
    use crate::analyzer::semantic::ids::StableDigest;

    use std::sync::Arc;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7876: a starting query inherited read incompleteness from an unrelated concurrent request"
    )]
    fn unrelated_concurrent_queries_do_not_share_incompleteness() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
        use crate::analyzer::{MultiAnalyzer, store::StoreError};
        use std::sync::Barrier;

        let analyzer = MultiAnalyzer::default();
        let barrier = Barrier::new(2);
        std::thread::scope(|threads| {
            let failed = threads.spawn(|| {
                let cancellation = crate::CancellationToken::default();
                let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
                cancellation.cancel();
                barrier.wait();
                analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
                analyzer.record_query_failure(StoreError::new("unrelated request failed"));
                barrier.wait();
                barrier.wait();
                assert_eq!(scope.read_completion(), Err(QueryReadIncomplete::Cancelled));
                assert!(scope.store_error().is_some());
            });
            let ledger = Arc::new(ReadLedger::new());
            let clean = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            barrier.wait();
            barrier.wait();
            assert!(clean.read_completion().is_ok());
            assert!(clean.store_error().is_none());
            assert!(analyzer.active_query_cancellation().is_none());
            assert_eq!(ledger.execution_dependences(), 0);
            drop(clean);
            // The failed request remains registered while this one starts.
            let starting = AnalyzerQueryScope::new(&analyzer);
            assert!(starting.read_completion().is_ok());
            assert!(starting.store_error().is_none());
            // Maintenance without transported query context affects neither request.
            threads
                .spawn(|| {
                    analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
                    analyzer.record_query_failure(StoreError::new("maintenance failed"));
                })
                .join()
                .expect("maintenance thread panicked");
            assert!(starting.read_completion().is_ok());
            barrier.wait();
            failed.join().expect("failing request panicked");
        });
    }

    #[test]
    fn nested_queries_inherit_their_transported_parent_and_record_into_ancestors() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
        use crate::analyzer::{
            MultiAnalyzer, store::StoreError, tree_sitter_analyzer::QueryReadCache,
        };
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;

        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::new(&analyzer);
        let mut delegate = QueryReadCache::default();
        assert!(delegate.begin(&outer.context));
        analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
        {
            let nested = AnalyzerQueryScope::new(&analyzer);
            assert_eq!(
                nested.read_completion(),
                Err(QueryReadIncomplete::Cancelled)
            );
        }
        {
            // Registration also checks ancestry when bypassing MultiAnalyzer.
            let nested = Arc::new(AnalyzerQueryContext::default());
            assert!(nested.read_completion().is_ok());
            let _attribution = nested.enter();
            assert!(delegate.begin(&nested));
            assert_eq!(
                nested.read_completion(),
                Err(QueryReadIncomplete::Cancelled)
            );
            assert!(delegate.end(&nested));
        }
        let carried = CarriedContext::current();
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    carried.run(|| {
                        let child = AnalyzerQueryScope::new(&analyzer);
                        assert_eq!(child.read_completion(), Err(QueryReadIncomplete::Cancelled));
                        analyzer.record_query_failure(StoreError::new("transported child failed"));
                        assert!(child.store_error().is_some());
                    })
                })
                .join()
                .expect("transported child panicked");
        });
        assert!(
            outer.store_error().is_some(),
            "outer retains the child's failure"
        );
        assert!(delegate.end(&outer.context));
    }

    #[test]
    fn ordinary_scope_keeps_attribution_absent_and_transports_only_request_state() {
        use super::{AnalyzerQueryScope, path_module_request_failure_cell};
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
        let analyzer = crate::analyzer::MultiAnalyzer::default();
        let fresh_request = CarriedContext::current();
        {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            assert!(super::with_attribution_frame(|frame| frame.is_none()));
            assert!(!super::has_read_attribution_ledgers());
            let cell = path_module_request_failure_cell(crate::Language::JavaScript).unwrap();
            let carried = CarriedContext::current();
            std::thread::scope(|threads| {
                threads
                    .spawn(|| {
                        carried.run(|| {
                            let _nested = AnalyzerQueryScope::with_read_ledger(
                                &analyzer,
                                Arc::new(ReadLedger::new()),
                            );
                            assert!(Arc::ptr_eq(
                                &cell,
                                &path_module_request_failure_cell(crate::Language::JavaScript)
                                    .unwrap()
                            ));
                        })
                    })
                    .join()
                    .unwrap();
                threads
                    .spawn(|| {
                        fresh_request.run(|| {
                            let _independent = AnalyzerQueryScope::new(&analyzer);
                            assert!(!Arc::ptr_eq(
                                &cell,
                                &path_module_request_failure_cell(crate::Language::JavaScript)
                                    .unwrap()
                            ));
                        })
                    })
                    .join()
                    .unwrap();
            });
        }
        assert!(path_module_request_failure_cell(crate::Language::JavaScript).is_none());
    }

    #[test]
    fn threaded_read_attribution_is_request_local_and_transportable() {
        use super::{AnalyzerQueryScope, IAnalyzer, ReadAttribution, capture_query_reads};
        use crate::analyzer::MultiAnalyzer;
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
        use std::sync::Barrier;

        let analyzer = MultiAnalyzer::default();
        let empty_context = CarriedContext::current();
        let ledgers = [Arc::new(ReadLedger::new()), Arc::new(ReadLedger::new())];
        let barrier = Barrier::new(2);
        let key = |value: &[u8]| ReadKey::Configuration(StableDigest::sha256(value));
        let own = [key(b"owner-a"), key(b"owner-b")];
        let transported = key(b"transported");
        let broadcast = key(b"broadcast");
        let nested = key(b"nested");
        std::thread::scope(|threads| {
            let handles: Vec<_> = (0..2)
                .map(|owner| {
                    let analyzer = &analyzer;
                    let ledgers = &ledgers;
                    let barrier = &barrier;
                    let own = &own;
                    let transported = &transported;
                    let broadcast = &broadcast;
                    let nested = &nested;
                    let empty_context = &empty_context;
                    threads.spawn(move || {
                        let _scope = AnalyzerQueryScope::with_read_ledger(
                            analyzer,
                            Arc::clone(&ledgers[owner]),
                        );
                        barrier.wait();
                        // Both owners are live, but direct reads stay with their request.
                        analyzer.record_read(own[owner].clone());
                        barrier.wait();
                        assert_eq!(ledgers[owner].keys(), vec![own[owner].clone()]);
                        barrier.wait();
                        if owner == 0 {
                            let carried = CarriedContext::current();
                            std::thread::scope(|helpers| {
                                helpers
                                    .spawn(|| {
                                        carried.run(|| {
                                            assert!(
                                                analyzer.current_thread_read_ledger().is_none()
                                            );
                                            // The frame also owns reads through another analyzer
                                            // whose registry has no attached ledger.
                                            let other = MultiAnalyzer::default();
                                            assert!(!other.read_ledger_attached());
                                            other.record_read(transported.clone());
                                            // A helper capture records beside the installed ledger.
                                            let (_, captured) =
                                                capture_query_reads(analyzer, || {
                                                    analyzer.record_read(nested.clone())
                                                });
                                            assert_eq!(captured.keys(), vec![nested.clone()]);
                                        })
                                    })
                                    .join()
                                    .expect("transported helper panicked");
                                assert!(ledgers[0].keys().contains(transported));
                                assert!(ledgers[0].keys().contains(nested));
                                assert_eq!(ledgers[1].keys(), vec![own[1].clone()]);
                                // Generic transports retain owner IDs; an explicit empty
                                // transport masks any frame on the receiving thread.
                                helpers
                                    .spawn(|| {
                                        carried.run(|| {
                                            assert!(
                                                analyzer.current_thread_read_ledger().is_none()
                                            );
                                            analyzer.record_read(transported.clone());
                                            empty_context
                                                .run(|| analyzer.record_read(broadcast.clone()));
                                            assert!(
                                                analyzer.current_thread_read_ledger().is_none()
                                            );
                                            assert!(super::has_read_attribution_ledgers());
                                        })
                                    })
                                    .join()
                                    .expect("generic helper panicked");
                                assert!(ledgers[1].keys().contains(broadcast));
                                helpers
                                    .spawn(|| {
                                        let _attribution = ReadAttribution::broadcast().install();
                                        let _scope = AnalyzerQueryScope::new(analyzer);
                                        analyzer.record_read(broadcast.clone());
                                    })
                                    .join()
                                    .expect("broadcast helper panicked");
                            });
                        }
                        barrier.wait();
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("owner thread panicked");
            }
        });
        assert_eq!(ledgers[0].keys().len(), 4);
        assert_eq!(ledgers[1].keys().len(), 2);
        for ledger in ledgers {
            assert!(ledger.keys().contains(&broadcast));
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: hit checks skipped foreign-owned and broadcast ledger destinations"
    )]
    fn recorded_key_checks_require_every_unshadowed_destination() {
        use super::{
            AnalyzerQueryScope, IAnalyzer, ReadAttribution, read_key_recorded_on_active_ledgers,
        };
        use crate::analyzer::MultiAnalyzer;

        let analyzer = MultiAnalyzer::default();
        let empty_request = ReadAttribution::for_request();
        let key = ReadKey::Configuration(StableDigest::sha256(b"recorded input"));
        assert!(read_key_recorded_on_active_ledgers(&analyzer, &key));
        let owner = Arc::new(ReadLedger::new());
        let other = Arc::new(ReadLedger::new());
        let _owner_scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&owner));
        let _other_scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&other));
        assert!(!read_key_recorded_on_active_ledgers(&analyzer, &key));
        {
            let _empty = empty_request.install();
            assert!(read_key_recorded_on_active_ledgers(&analyzer, &key));
        }
        owner.record(key.clone());
        assert!(!read_key_recorded_on_active_ledgers(&analyzer, &key));
        analyzer.record_read(key.clone());
        assert!(read_key_recorded_on_active_ledgers(&analyzer, &key));

        let nested_key = ReadKey::Configuration(StableDigest::sha256(b"nested input"));
        let nested = Arc::new(ReadLedger::new());
        {
            let _nested_scope = AnalyzerQueryScope::with_nested_read_ledger(
                &analyzer,
                Arc::clone(&nested),
                Arc::clone(&owner),
            );
            other.record(nested_key.clone());
            assert!(!read_key_recorded_on_active_ledgers(&analyzer, &nested_key));
            nested.record(nested_key.clone());
            assert!(read_key_recorded_on_active_ledgers(&analyzer, &nested_key));
            let _broadcast = ReadAttribution::broadcast().install();
            assert!(read_key_recorded_on_active_ledgers(&analyzer, &nested_key));
            assert!(!owner.keys().contains(&nested_key));
        }
        assert!(!read_key_recorded_on_active_ledgers(&analyzer, &nested_key));
        let _broadcast = ReadAttribution::broadcast().install();
        assert!(!read_key_recorded_on_active_ledgers(&analyzer, &nested_key));
        analyzer.record_read(nested_key.clone());
        assert!(read_key_recorded_on_active_ledgers(&analyzer, &nested_key));
    }

    #[test]
    fn a_nested_capture_shadows_only_its_explicit_enclosing_ledger() {
        let enclosing = Arc::new(ReadLedger::new());
        let concurrent = Arc::new(ReadLedger::new());
        let captured = Arc::new(ReadLedger::new());
        let contexts = vec![
            Arc::new(AnalyzerQueryContext::with_read_ledger(Arc::clone(
                &enclosing,
            ))),
            Arc::new(AnalyzerQueryContext::with_read_ledger(Arc::clone(
                &concurrent,
            ))),
            Arc::new(AnalyzerQueryContext::with_nested_read_ledger(
                Arc::clone(&captured),
                Arc::clone(&enclosing),
            )),
        ];
        let key = ReadKey::Configuration(StableDigest::sha256(b"configuration"));

        record_read_on_active_ledgers(&contexts, key.clone());
        record_unattributed_on_active_ledgers(&contexts, 1);

        assert!(enclosing.keys().is_empty());
        assert_eq!(enclosing.unattributed_reads(), 0);
        assert_eq!(concurrent.keys(), vec![key.clone()]);
        assert_eq!(concurrent.unattributed_reads(), 1);
        assert_eq!(captured.keys(), vec![key]);
        assert_eq!(captured.unattributed_reads(), 1);
    }
}

#[cfg(test)]
mod required_literal_tests {
    use super::{SearchSymbolPatternBatch, required_storage_literals};
    use brokk_bifrost_test_macros::hardwon;

    /// Longest first, then alphabetical, which is the order the prefilter emits.
    fn literals(pattern: &str) -> Vec<String> {
        required_storage_literals(pattern)
    }

    #[test]
    #[hardwon("#2316: required-literal prefilter must retain a plain identifier match")]
    fn a_plain_identifier_is_its_own_required_literal() {
        assert_eq!(
            literals("ProductionTaintPolicyEvaluator"),
            vec!["productiontaintpolicyevaluator".to_string()]
        );
    }
    #[test]
    #[hardwon(
        "#2316: regex searches scanned every indexed declaration when literal pushdown was available"
    )]
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
    #[hardwon(
        "#2316: regex literal pushdown excluded valid matches when an optional group was absent"
    )]
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
    #[hardwon(
        "#2316: regex literal pushdown excluded valid alternatives by requiring a branch-specific literal"
    )]
    fn an_alternation_requires_only_what_every_branch_requires() {
        assert!(literals("Foo|Bar").is_empty());
        assert_eq!(literals("Search(Foo|Bar)"), vec!["search".to_string()]);
        assert_eq!(literals("(?:Solver|Solver)"), vec!["solver".to_string()]);
    }

    /// An escaped metacharacter is a literal character, but it is not in the
    /// storage charset, so it ends the run instead of joining it.
    #[test]
    #[hardwon(
        "#2316: regex literal pushdown built an unsound substring across the stored-name join"
    )]
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
    #[hardwon(
        "#2316: regex literal pushdown excluded case-insensitive matches from normalized storage"
    )]
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
    #[hardwon("#2316: regex literal pushdown must not narrow patterns with no mandatory literal")]
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
    #[hardwon("#2316: substring reduction must preserve the symbol-search result set")]
    fn a_literal_another_literal_contains_is_dropped() {
        assert_eq!(literals("Foo.*FooBar"), vec!["foobar".to_string()]);
    }
    /// The literal count per pattern is bounded, and dropping a required literal
    /// only widens the prefilter.
    #[test]
    #[hardwon("#2316: literal prefilter cap must only widen the candidate scan")]
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
    #[hardwon(
        "#3279: structural MCP regex batches stalled because one pattern disabled safe per-pattern pushdown"
    )]
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
    #[hardwon("#3279: an unfilterable symbol selector must disable the entire batch prefilter")]
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
    #[hardwon("#3279: auto-quoted symbol patterns must retain their identifier literal")]
    fn auto_quoted_patterns_keep_their_identifier_literal() {
        let batch = SearchSymbolPatternBatch::compile(vec!["ValueFlow".to_string()], true, None);
        assert_eq!(
            batch.required_storage_literals(),
            Some([vec!["valueflow".to_string()]].as_slice())
        );
    }

    /// #3279: `*Language*` is the spelling callers reach for first and is not
    /// valid regex (a leading repetition operator has nothing to repeat), so it
    /// must fall back to glob semantics -- containment -- instead of silently
    /// matching nothing. The translated pattern keeps its required literal so
    /// the storage prefilter still applies.
    #[test]
    #[hardwon("#3279: leading wildcard symbol selectors must compile as glob containment")]
    fn leading_wildcard_patterns_compile_as_glob_containment() {
        let batch = SearchSymbolPatternBatch::compile(
            vec!["*Language*".to_string(), "*Query*Domain*".to_string()],
            false,
            None,
        );

        assert!(batch.complete());
        assert!(batch.invalid_patterns().is_empty());
        assert!(batch.is_match("bifrost_core::Language"));
        assert!(batch.is_match("crates::rql::QueryEvaluationDomain"));
        assert!(!batch.is_match("crates::rql::Lantern"));
        assert_eq!(
            batch.required_storage_literals(),
            Some(
                [
                    vec!["language".to_string()],
                    vec!["domain".to_string(), "query".to_string()],
                ]
                .as_slice()
            )
        );
    }

    /// A pattern that is neither valid regex nor carries glob wildcards cannot
    /// be interpreted at all. It must be reported, not dropped: a dropped
    /// pattern answers "no such symbols" about a request that was malformed.
    #[test]
    #[hardwon("#3279: invalid symbol selectors must be reported instead of silently dropped")]
    fn uninterpretable_patterns_are_reported_not_dropped() {
        let batch = SearchSymbolPatternBatch::compile(
            vec!["foo(bar".to_string(), "Language".to_string()],
            false,
            None,
        );

        assert_eq!(batch.invalid_patterns(), ["foo(bar".to_string()].as_slice());
        assert!(batch.has_compiled_patterns());
        assert!(batch.is_match("app::LanguageTool"));
        assert!(!batch.is_match("app::foo(bar"));

        let all_invalid =
            SearchSymbolPatternBatch::compile(vec!["foo(bar".to_string()], false, None);
        assert!(!all_invalid.has_compiled_patterns());
        assert_eq!(all_invalid.invalid_patterns().len(), 1);
    }
}

#[cfg(test)]
mod memo_handle_tests {
    use super::*;
    use crate::analyzer::MultiAnalyzer;

    #[test]
    fn snapshot_cache_handles_do_not_read_workspace_facts() {
        let analyzer = MultiAnalyzer::default();
        let caches = AnalyzerSnapshotCaches::new(1024);
        let derived = caches.derived_layers() as *const _;
        let usage = caches.usage_graphs() as *const _;
        let java = caches.java_usage_evidence() as *const _;
        let models = caches.semantic_models() as *const _;
        let syntax = caches.runtime_syntax() as *const _;
        let structural =
            crate::analyzer::structural::provider::StructuralFactSnapshotCache::new(1024);
        let postings = structural.inner() as *const _;
        let (_, reads) = capture_query_reads(&analyzer, || {
            assert_eq!(derived, caches.derived_layers() as *const _);
            assert_eq!(usage, caches.usage_graphs() as *const _);
            assert_eq!(java, caches.java_usage_evidence() as *const _);
            assert_eq!(models, caches.semantic_models() as *const _);
            assert_eq!(syntax, caches.runtime_syntax() as *const _);
            assert_eq!(postings, structural.inner() as *const _);
        });
        assert!(reads.keys().is_empty());
        assert!(reads.is_bounded());
    }

    #[test]
    fn query_diagnostics_only_retain_reported_failures() {
        let analyzer = MultiAnalyzer::default();
        let context = AnalyzerQueryContext {
            captured_read_incompleteness: Some(Mutex::default()),
            ..Default::default()
        };
        let (_, reads) = capture_query_reads(&analyzer, || {
            context.record_store_error(StoreError::new("first"));
            context.record_store_error(StoreError::new("second"));
            context.record_read_incomplete(QueryReadIncomplete::Cancelled);
            assert!(context.store_error().is_some());
            assert!(matches!(
                context.read_completion(),
                Err(QueryReadIncomplete::Cancelled)
            ));
            assert_eq!(
                context
                    .captured_read_incompleteness
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .len(),
                3
            );
        });
        assert!(reads.keys().is_empty());
        assert!(reads.is_bounded());
    }
    #[test]
    fn caught_budget_refusal_is_execution_dependent() {
        let analyzer = MultiAnalyzer::default();
        let (answer, reads) = capture_query_reads(&analyzer, || {
            let mut limits = crate::analyzer::semantic::SemanticBudget::default().limits();
            limits.nested_entries = 1;
            let budget = crate::analyzer::semantic::SemanticBudget::new(limits).unwrap();
            let refused = budget.check_admission(crate::analyzer::semantic::SemanticWork {
                nested_entries: 2,
                ..Default::default()
            });
            assert!(refused.is_err());
            17 // The caller catches the refusal and publishes a useful fallback.
        });
        assert_eq!(answer, 17);
        assert!(reads.execution_dependences() > 0);
        assert!(!reads.is_bounded());
    }

    #[test]
    fn caught_worker_cancellation_is_execution_dependent() {
        let analyzer = MultiAnalyzer::default();
        let run = crate::CancellationToken::default();
        let token = run.child();
        let (_, cancelled_only) = capture_query_reads(&analyzer, || token.cancel());
        assert!(
            cancelled_only.is_bounded(),
            "cancelling does not observe a stop"
        );
        let (_, reads) = capture_query_reads(&analyzer, || {
            let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
            let token = token.clone();
            std::thread::spawn(move || carried.run(|| assert!(token.is_cancelled())))
                .join()
                .expect("worker must finish");
        });
        assert!(reads.execution_dependences() > 0);
        assert!(!reads.is_bounded());
        assert!(
            !run.is_cancelled(),
            "caught child cancellation leaves the run live"
        );

        let owner = std::thread::current().id();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        assert_eq!(pool.current_num_threads(), 2);
        let (answer, worker_reads) = capture_query_reads(&analyzer, || {
            let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
            pool.install(|| {
                carried.run(|| {
                    assert_ne!(std::thread::current().id(), owner);
                    assert!(token.is_cancelled());
                    17
                })
            })
        });
        assert_eq!(answer, 17);
        assert!(worker_reads.execution_dependences() > 0);
        assert!(!worker_reads.is_bounded());
    }

    #[test]
    fn caught_distributed_cap_is_execution_dependent() {
        let analyzer = MultiAnalyzer::default();
        let (_, reads) = capture_query_reads(&analyzer, || {
            assert!(
                !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(1, 1)
                    .charge(1)
            );
        });
        assert!(reads.execution_dependences() > 0);
        assert!(!reads.is_bounded());
    }

    #[test]
    fn caught_provider_failure_is_execution_dependent() {
        let analyzer = MultiAnalyzer::default();
        let (_, reads) = capture_query_reads(&analyzer, || {
            drop(crate::analyzer::semantic::SemanticProviderError::internal(
                "caught failure",
            ));
        });
        assert!(reads.execution_dependences() > 0);
        assert!(!reads.is_bounded());
    }
}
