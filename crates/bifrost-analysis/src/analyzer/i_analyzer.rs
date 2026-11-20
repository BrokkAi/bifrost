use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::store::StoreError;
use crate::analyzer::usages::FuzzyResult;
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
use brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing;
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

        fn active_query_semantic_model_overlay_read(
            &self,
        ) -> Option<$crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead> {
            self.inner.active_query_semantic_model_overlay_read()
        }

        fn active_query_semantic_model_overlay(
            &self,
        ) -> Option<Option<std::sync::Arc<$crate::analyzer::semantic_model::SemanticModelOverlay>>>
        {
            self.inner.active_query_semantic_model_overlay()
        }

        fn active_query_host_activation_context(
            &self,
        ) -> Option<Option<std::sync::Arc<$crate::analyzer::semantic_model::HostActivationContext>>>
        {
            self.inner.active_query_host_activation_context()
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

// Select forwarding in the trait's defining crate, not in the language crate
// expanding the macro: those crates need not enable their own test-support.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[macro_export]
macro_rules! forward_retention_census {
    () => {
        fn retention_census_for_test(
            &self,
            census: &mut $crate::retention_census::RetentionCensus,
        ) {
            $crate::analyzer::IAnalyzer::retention_census_for_test(&self.inner, census);
        }
    };
}

#[cfg(not(feature = "test-support"))]
#[doc(hidden)]
#[macro_export]
macro_rules! forward_retention_census {
    () => {};
}

/// Forward request-ledger capture and replay through a language wrapper.
#[doc(hidden)]
#[macro_export]
macro_rules! forward_query_read_ledger {
    () => {
        $crate::forward_retention_census!();

        fn declaration_candidates_for_question(
            &self,
            file: &$crate::analyzer::ProjectFile,
            question: &$crate::analyzer::read_ledger::LookupQuestion,
        ) -> Option<Vec<$crate::analyzer::CodeUnit>> {
            $crate::analyzer::IAnalyzer::declaration_candidates_for_question(
                &self.inner,
                file,
                question,
            )
        }

        fn project_parse_variant_reader(
            &self,
        ) -> Option<$crate::analyzer::tree_sitter_analyzer::ProjectVariantReader> {
            $crate::analyzer::IAnalyzer::project_parse_variant_reader(&self.inner)
        }
        fn set_project_parse_variant_reader(
            &self,
            reader: $crate::analyzer::tree_sitter_analyzer::ProjectVariantReader,
        ) {
            $crate::analyzer::IAnalyzer::set_project_parse_variant_reader(&self.inner, reader);
        }
        fn current_query_read_completion(
            &self,
        ) -> Result<(), $crate::analyzer::QueryReadIncomplete> {
            $crate::analyzer::IAnalyzer::current_query_read_completion(&self.inner)
        }

        fn record_query_incomplete(&self, reason: $crate::analyzer::QueryReadIncomplete) {
            $crate::analyzer::IAnalyzer::record_query_incomplete(&self.inner, reason);
        }

        fn supports_selected_read_recording(&self) -> bool {
            $crate::analyzer::IAnalyzer::supports_selected_read_recording(&self.inner)
        }

        fn record_read(&self, key: $crate::analyzer::read_ledger::ReadKey) {
            $crate::analyzer::IAnalyzer::record_read(&self.inner, key);
        }

        fn record_read_obligation(&self, key: &$crate::analyzer::read_ledger::ReadKey) {
            $crate::analyzer::IAnalyzer::record_read_obligation(&self.inner, key);
        }

        fn record_read_receipt(&self, keys: &std::sync::Arc<[$crate::analyzer::ReadKey]>) {
            $crate::analyzer::IAnalyzer::record_read_receipt(&self.inner, keys);
        }

        fn record_read_capture(&self, reads: &$crate::analyzer::ReadLedger) {
            $crate::analyzer::IAnalyzer::record_read_capture(&self.inner, reads);
        }

        #[track_caller]
        fn record_unattributed_reads(&self, count: usize) {
            $crate::analyzer::IAnalyzer::record_unattributed_reads(&self.inner, count);
        }

        #[track_caller]
        fn refuse_read_reuse(&self) {
            $crate::analyzer::IAnalyzer::refuse_read_reuse(&self.inner);
        }

        fn mark_execution_dependent_reads(&self, count: usize) {
            $crate::analyzer::IAnalyzer::mark_execution_dependent_reads(&self.inner, count);
        }

        fn mark_runtime_cache_touched(&self) {
            $crate::analyzer::IAnalyzer::mark_runtime_cache_touched(&self.inner);
        }

        fn record_attributed_dependences(
            &self,
            record: $crate::analyzer::i_analyzer::AttributeDependences,
            count: usize,
        ) {
            $crate::analyzer::IAnalyzer::record_attributed_dependences(&self.inner, record, count);
        }

        fn join_reuse_verdict(
            &self,
            verdict: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict,
        ) {
            $crate::analyzer::IAnalyzer::join_reuse_verdict(&self.inner, verdict);
        }

        fn records_query_reads(&self) -> bool {
            $crate::analyzer::IAnalyzer::records_query_reads(&self.inner)
        }

        fn require_workspace_languages(
            &self,
            languages: &[$crate::analyzer::Language],
        ) -> Result<(), $crate::analyzer::store::StoreError> {
            $crate::analyzer::IAnalyzer::require_workspace_languages(&self.inner, languages)
        }

        fn selected_workspace_snapshots_for_reads(
            &self,
        ) -> Option<std::sync::Arc<$crate::analyzer::store::WorkspaceSnapshots>> {
            $crate::analyzer::IAnalyzer::selected_workspace_snapshots_for_reads(&self.inner)
        }

        #[cfg(any(test, feature = "test-support"))]
        fn selected_receiver_proofs_after_transfer_batch_for_test(
            &self,
            file: &$crate::analyzer::ProjectFile,
            questions: &[$crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion],
            cancellation: &$crate::CancellationToken,
        ) -> $crate::analyzer::store::Result<
            Vec<Option<$crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer>>,
        > {
            $crate::analyzer::IAnalyzer::selected_receiver_proofs_after_transfer_batch_for_test(
                &self.inner,
                file,
                questions,
                cancellation,
            )
        }

        fn selected_receiver_proof_read(
            &self,
            file: &$crate::analyzer::ProjectFile,
            question: &$crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
            cancellation: &$crate::CancellationToken,
        ) -> $crate::analyzer::store::Result<
            Option<$crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer>,
        > {
            $crate::analyzer::IAnalyzer::selected_receiver_proof_read(
                &self.inner,
                file,
                question,
                cancellation,
            )
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
        // A qualified name is a spelling, not a regular expression: `\`, `$`,
        // `+`, `::`, `/` and `.` all join components in some language, and
        // compiling them as regex syntax drops the declaration the request
        // names (#8697). Anything else keeps the ordinary regex reading.
        let regex_reading = crate::analyzer::search_pattern::escape_sigil_anchors(pattern);
        let Some(qualified) =
            crate::analyzer::search_pattern::qualified_search_pattern_regex(pattern)
        else {
            return regex_reading;
        };
        // `\` is the one separator that is also regex escape syntax, so a
        // backslash-joined request that compiles as a regex has two readings:
        // `yii\base\Widget` and `yii\base\b` are PHP classes and also
        // regexes. Match either; scoring ranks the qualified reading's exact
        // declaration first, and the prefilter keeps only the literals both
        // branches require. A request that does not compile as a regex
        // (`App\Models\C`) has only the qualified reading.
        if pattern.contains('\\')
            && RegexBuilder::new(&regex_reading)
                .case_insensitive(true)
                .build()
                .is_ok()
        {
            format!("(?:{regex_reading})|(?:{qualified})")
        } else {
            qualified
        }
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

pub use brokk_bifrost_core::analyzer::query_read_incomplete::{
    AttributedQueryReadIncomplete, DETERMINISTIC_PROOF_STOP_LABELS, LookupOutcome,
    QueryLookupProvenance, QueryReadIncomplete, SELECTED_PATTERN_ALIAS_LIMIT_REASON,
};

/// Own a lookup's read completion, including identity probes and memo replay.
pub fn capture_lookup_answer<T>(
    analyzer: &dyn IAnalyzer,
    run: impl FnOnce() -> brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome<T>,
) -> brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome<T> {
    use brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome;
    let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
    // Beginning a request can itself fail to bind the required snapshot.
    let initial = scope.captured_read_incompleteness();
    if initial
        .iter()
        .any(QueryReadIncomplete::invalidates_positive_evidence)
    {
        drop(scope);
        for reason in &initial {
            analyzer.record_query_incomplete(reason.clone());
        }
        return LookupOutcome::Incomplete(
            initial
                .into_iter()
                .fold(None, |reason, next| {
                    QueryReadIncomplete::merge_optional(reason, Some(next))
                })
                .expect("captured failure"),
        );
    }
    let answer = run();
    let captured = scope.captured_read_incompleteness();
    let failed = captured
        .iter()
        .any(QueryReadIncomplete::invalidates_positive_evidence);
    // Content gaps leave positive evidence usable, but cannot establish absence.
    // Replay after closing our capture so enclosing completion retains each gap.
    drop(scope);
    let reason = captured.into_iter().fold(None, |reason, next| {
        analyzer.record_query_incomplete(next.clone());
        QueryReadIncomplete::merge_optional(reason, Some(next))
    });
    match (answer, reason) {
        (LookupOutcome::Incomplete(own), reason) => LookupOutcome::Incomplete(
            QueryReadIncomplete::merge_optional(reason, Some(own)).expect("lookup failure"),
        ),
        (_, Some(reason)) if failed => LookupOutcome::Incomplete(reason),
        (LookupOutcome::NotFound, Some(reason)) => LookupOutcome::Incomplete(reason),
        (answer, _) => answer,
    }
}

/// Capture operational read failures while retaining the producer's ordinary value.
pub fn capture_read_execution_cause<T>(
    analyzer: &dyn IAnalyzer,
    run: impl FnOnce() -> T,
) -> (
    T,
    Option<crate::analyzer::read_ledger::DerivationExecutionCause>,
) {
    let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
    let value = run();
    let cause = scope
        .captured_read_incompleteness()
        .into_iter()
        .find_map(|reason| reason.execution_cause());
    if cause.is_some() {
        analyzer.mark_execution_dependent();
    }
    (value, cause)
}

/// Evaluate one independently reported answer, refusing its value if any read
/// was incomplete. Reads remain in the enclosing receipt, while completion is
/// consumed by this answer's caller. Execution failures still reach enclosing scopes.
#[must_use = "An independently scoped answer must handle its read completion"]
pub fn complete_independent_answer<T>(
    analyzer: &dyn IAnalyzer,
    run: impl FnOnce() -> T,
) -> Result<Result<T, Vec<QueryReadIncomplete>>, StoreError> {
    let scope = AnalyzerQueryScope::capturing_candidate_classification(analyzer);
    let value = run();
    if let Some(error) = scope.store_error() {
        return Err(error);
    }
    let reasons = scope.captured_read_incompleteness();
    Ok(if reasons.is_empty() {
        Ok(value)
    } else {
        Err(reasons)
    })
}

/// Owns analyzer caches shared by retained fills in one request.
#[derive(Debug)]
pub(crate) struct RequestCacheDomain {
    pub(crate) id: u64,
    registries:
        Mutex<Vec<std::sync::Weak<std::sync::RwLock<super::tree_sitter_analyzer::QueryReadCache>>>>,
}

#[derive(Default)]
struct FillLocalMemos(Mutex<HashMap<std::any::TypeId, Arc<dyn Any + Send + Sync>>>);

impl std::fmt::Debug for FillLocalMemos {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FillLocalMemos")
    }
}

/// A certificate stored here dies with the cold fill, even when later fills
/// inherit its request cache domain.
pub(crate) fn active_retained_fill_memo<T: Default + Send + Sync + 'static>() -> Option<Arc<T>> {
    let context = current_query_contexts().find(|context| context.fill_local_memos.is_some())?;
    let mut memos = context
        .fill_local_memos
        .as_ref()
        .expect("retained fill memo exists")
        .0
        .lock()
        .expect("retained fill memo poisoned");
    let memo = memos
        .entry(std::any::TypeId::of::<T>())
        .or_insert_with(|| Arc::new(T::default()));
    Some(
        Arc::clone(memo)
            .downcast::<T>()
            .expect("fill memo type disagrees"),
    )
}
impl RequestCacheDomain {
    pub(crate) fn register(
        &self,
        registry: &Arc<std::sync::RwLock<super::tree_sitter_analyzer::QueryReadCache>>,
    ) {
        let weak = Arc::downgrade(registry);
        let mut registries = self
            .registries
            .lock()
            .expect("fill retirement registry poisoned");
        if !registries.iter().any(|entry| entry.ptr_eq(&weak)) {
            // One handle per distinct analyzer cache owner the fill reaches (each
            // language analyzer and its realm peers, a few dozen at most). The
            // bound is per fill, not per workspace; exceeding it means peers are
            // registering without deduplication.
            assert!(
                registries.len() < 256,
                "a fill exceeded 256 analyzer cache owners"
            );
            registries.push(weak);
        }
    }
}
impl Drop for RequestCacheDomain {
    fn drop(&mut self) {
        for registry in self
            .registries
            .get_mut()
            .expect("fill retirement registry poisoned")
        {
            if let Some(registry) = registry.upgrade() {
                registry
                    .write()
                    .expect("query cache poisoned")
                    .retire_domain(self.id);
            }
        }
    }
}

pub use brokk_bifrost_core::analyzer::outer_request::OuterRequest;

thread_local! {
    static PRODUCT_ENTRY_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Marks a synchronous product dispatch on the current thread.
pub struct ProductEntryGuard;

pub fn enter_product_entry() -> ProductEntryGuard {
    PRODUCT_ENTRY_DEPTH.with(|depth| {
        depth.set(
            depth
                .get()
                .checked_add(1)
                .expect("product entry depth overflow"),
        )
    });
    ProductEntryGuard
}

impl Drop for ProductEntryGuard {
    fn drop(&mut self) {
        PRODUCT_ENTRY_DEPTH.with(|depth| {
            depth.set(
                depth
                    .get()
                    .checked_sub(1)
                    .expect("product entry depth underflow"),
            )
        });
    }
}

/// Returns the scoped outer request; never creates a request.
pub fn current_outer_request() -> Option<Arc<OuterRequest>> {
    current_query_context().map(|context| Arc::clone(&context.outer_request))
}

/// Failure to reach the selection captured when this request opened.
/// This is an ownership error, not permission to read the current selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestWorkspaceSelectionError {
    MissingRequest,
    MissingSelection,
    ClosedRequest,
}

/// One request's immutable selection and the allocation that identifies it.
/// Retaining the source prevents its address from being reused in the request.
#[derive(Debug)]
struct RequestWorkspaceSelection {
    owner: Arc<arc_swap::ArcSwap<crate::analyzer::store::WorkspaceSnapshots>>,
    snapshots: Arc<crate::analyzer::store::WorkspaceSnapshots>,
}

// This private owner is the single production binding extractor. Readers use
// the already registered entry and cannot supply a projection closure.
impl brokk_bifrost_core::analyzer::outer_request::WorkspaceEntryBinding
    for RequestWorkspaceSelection
{
    type Binding = Arc<crate::analyzer::store::WorkspaceSnapshots>;

    fn binding(&self) -> &Self::Binding {
        &self.snapshots
    }
}

/// Read the eagerly bound request selection, including on transported workers.
/// No request or binding is a design error; never manufacture a replacement.
pub(crate) fn request_workspace_snapshots(
    source: &Arc<arc_swap::ArcSwap<crate::analyzer::store::WorkspaceSnapshots>>,
) -> Result<Arc<crate::analyzer::store::WorkspaceSnapshots>, RequestWorkspaceSelectionError> {
    let request = current_outer_request();
    debug_assert!(request.is_some(), "selected read has no query context");
    let request = request.ok_or(RequestWorkspaceSelectionError::MissingRequest)?;
    if request.is_closed() {
        return Err(RequestWorkspaceSelectionError::ClosedRequest);
    }
    let snapshots = request.with_workspace_selection::<RequestWorkspaceSelection, _>(
        Arc::as_ptr(source) as usize,
        |entry| {
            debug_assert!(Arc::ptr_eq(&entry.value().owner, source));
            Arc::clone(entry.project().value())
        },
    );
    debug_assert!(
        snapshots.is_some(),
        "selected read has no selection bound at query entry"
    );
    snapshots.ok_or(RequestWorkspaceSelectionError::MissingSelection)
}

/// Refuse reuse when a request row read cannot name certified selection inputs.
/// Its process-local binding must never enter a receipt.
pub fn refuse_request_row_read_reuse() {
    brokk_bifrost_core::analyzer::carried_context::join_evaluation_verdict(
        crate::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
            crate::analyzer::reuse_verdict::ExecutionCause::Other,
        ),
    );
    let contexts: Vec<_> = current_query_contexts().collect();
    for_each_unshadowed_active_ledger(&contexts, |ledger| ledger.refuse_read_reuse());
}

/// Record that the current request read an input it pinned but a later request
/// cannot verify, such as a JVM dependency selection that is not replayable
/// (#14322). Every enclosing capture becomes request-pinned: no later request
/// may reuse its answer, while the request that read the input may.
pub fn record_request_pinned_input() {
    brokk_bifrost_core::analyzer::carried_context::join_evaluation_verdict(
        crate::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
            crate::analyzer::reuse_verdict::ExecutionCause::RequestPinned,
        ),
    );
    let contexts: Vec<_> = current_query_contexts().collect();
    for_each_unshadowed_active_ledger(&contexts, |ledger| {
        ledger.mark_request_pinned_dependences(1);
        ledger.join_verdict(
            crate::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                crate::analyzer::reuse_verdict::ExecutionCause::RequestPinned,
            ),
        );
    });
}

/// Record request-reader cancellation on every enclosing query context.
pub fn record_request_row_read_cancelled() {
    record_query_incomplete_on_current_contexts(QueryReadIncomplete::Cancelled);
}

/// Record a certified request-row selection on every active capture.
pub fn record_request_row_selection_read(key: crate::analyzer::ReadKey) {
    let contexts: Vec<_> = current_query_contexts().collect();
    record_read_on_active_ledgers(&contexts, key);
}

pub fn current_query_cancellation() -> Option<CancellationToken> {
    current_query_context_value(|context| context.cancellation().cloned())
}

/// A direct library read without a scope owns only this temporary request.
pub fn current_outer_request_or_transient() -> Arc<OuterRequest> {
    current_query_context()
        .map(|context| Arc::clone(&context.outer_request))
        .unwrap_or_else(|| {
            debug_assert!(
                PRODUCT_ENTRY_DEPTH.with(|depth| depth.get() == 0),
                "product read escaped its outer request scope"
            );
            OuterRequest::new()
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryCompletionBoundary {
    AdvisoryRead,
    CandidateClassification,
    IndependentAnswer,
    PolicyEvaluation,
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
    outer_request: Arc<OuterRequest>,
    /// The scope whose request memos this scope may reuse. Transported with
    /// ReadAttribution, never inferred from the analyzer-wide registry.
    enclosing: Option<Arc<AnalyzerQueryContext>>,
    // Transported independently of ancestry: retained fills cannot consume
    // request memos built under their caller's unrelated failures.
    request_cache_domain: Option<Arc<RequestCacheDomain>>,
    retained_fill_domain: Arc<std::sync::OnceLock<Arc<RequestCacheDomain>>>,
    fill_local_memos: Option<FillLocalMemos>,
    completion: Mutex<QueryCompletion>,
    /// Keyed by the base interpretation's durable key, a value: handle
    /// equality is allocation identity, and a selected alternate's base
    /// handle is a different allocation from the original base handle.
    pub(crate) selected_procedures: Mutex<
        std::collections::HashMap<
            crate::analyzer::semantic::DurableProcedureKey,
            crate::analyzer::semantic::service::QuerySelectedProcedure,
        >,
    >,
    pub(crate) ownership_files: Mutex<
        std::collections::HashMap<
            crate::analyzer::semantic::SemanticArtifactMaterializationId,
            Arc<crate::analyzer::semantic::service::OwnershipFileSlot>,
        >,
    >,
    // The key's interpretation names the acquiring authority, so ownership
    // and executable entries for one base retain their independent receipts.
    pub(crate) ownership_procedures: Mutex<
        std::collections::HashMap<
            crate::analyzer::semantic::DurableProcedureKey,
            crate::analyzer::semantic::service::QueryOwnershipProcedure,
        >,
    >,
    // Receipt observation only; selection hits use selected_procedures above.
    pub(crate) candidate_macro_procedure_overlay:
        Mutex<Option<crate::analyzer::semantic::service::CandidateMacroProcedureOverlay>>,
    completion_boundary: Option<QueryCompletionBoundary>,
    /// Tripwire for receipt reads made while recomputing a taint Output unit.
    taint_output_receipt_capture: bool,

    cancellation: Option<CancellationToken>,
    identifier_candidate_memo_owner: Option<std::thread::ThreadId>,
    /// Selection status frozen with an overlay or active snapshot override.
    semantic_models_selected: Option<bool>,
    /// A resolver overlay frozen by this scope's owner thread. The outer
    /// `Option` distinguishes no override from a deliberately frozen absence;
    /// the thread identity prevents the analyzer's shared context stack from
    /// leaking one concurrent request's overlay into another.
    semantic_model_overlay_override: Option<(
        std::thread::ThreadId,
        Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    )>,
    host_activation_override: Option<(
        std::thread::ThreadId,
        Option<Arc<crate::analyzer::semantic_model::HostActivationContext>>,
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
    policy_unit_label: Option<Arc<str>>,
}

/// Identity of one recorded store failure, preserved across nested contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoreErrorId(usize);

/// A store failure and its shared acknowledgment state.
#[derive(Debug, Clone)]
pub struct RecordedStoreError(Arc<RecordedStoreErrorState>);

#[derive(Debug)]
struct RecordedStoreErrorState {
    id: StoreErrorId,
    error: StoreError,
    // No policy origin means the enclosing request/preparation owns this record.
    // A weak reference identifies the original evaluation without a retain cycle.
    origin_policy: Option<std::sync::Weak<PolicyCompletionOwner>>,
    acknowledged: std::sync::atomic::AtomicBool,
}

impl RecordedStoreError {
    fn new(error: StoreError) -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
        let id = NEXT_ID.fetch_add(1, AtomicOrdering::Relaxed);
        assert_ne!(id, usize::MAX, "store error identity exhausted");
        Self(Arc::new(RecordedStoreErrorState {
            id: StoreErrorId(id),
            error,
            origin_policy: PolicyCompletionOwner::current()
                .as_ref()
                .map(Arc::downgrade),
            acknowledged: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    pub fn id(&self) -> StoreErrorId {
        self.0.id
    }

    pub fn error(&self) -> &StoreError {
        &self.0.error
    }

    fn originated_in(&self, policy: &PolicyCompletionOwner) -> bool {
        self.0
            .origin_policy
            .as_ref()
            .is_some_and(|origin| std::ptr::eq(origin.as_ptr(), policy))
    }

    /// Origin isolates policies even while a sibling has not acknowledged its
    /// failure. Acknowledgment discharges inherited/request-level reporting;
    /// it does not recover the evaluation that originated the error.
    fn inherited_by(&self, policy: Option<&PolicyCompletionOwner>) -> bool {
        match (self.0.origin_policy.as_ref(), policy) {
            (Some(_), Some(policy)) => self.originated_in(policy),
            (None, _) | (Some(_), None) => !self.0.acknowledged.load(AtomicOrdering::Acquire),
        }
    }
}

/// Errors owned by the innermost carried policy evaluation.
#[derive(Default)]
pub struct PolicyCompletionOwner {
    errors: Mutex<Vec<RecordedStoreError>>,
    pending: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static POLICY_COMPLETION_INSTALL_COUNTER: std::cell::RefCell<Option<Arc<AtomicUsize>>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Count actual installations on this thread, restoring the probe on unwind.
/// A single-policy coordinator batch executes on its caller's thread.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_policy_completion_install_counter_for_test<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Restore(Option<Arc<AtomicUsize>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            POLICY_COMPLETION_INSTALL_COUNTER.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let counter = Arc::new(AtomicUsize::new(0));
    let previous =
        POLICY_COMPLETION_INSTALL_COUNTER.with(|slot| slot.replace(Some(counter.clone())));
    let restore = Restore(previous);
    let result = run();
    drop(restore);
    (result, counter.load(AtomicOrdering::Relaxed))
}

impl PolicyCompletionOwner {
    pub fn install(self: &Arc<Self>) -> CarriedContextGuard {
        #[cfg(any(test, feature = "test-support"))]
        POLICY_COMPLETION_INSTALL_COUNTER.with(|slot| {
            if let Some(counter) = slot.borrow().as_ref() {
                counter.fetch_add(1, AtomicOrdering::Relaxed);
            }
        });
        carried_context::push_completion(self.clone())
    }

    /// Access policy-owned provisional products without exposing them to readers.
    pub fn with_pending<T: Default + Send + 'static, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut pending = self.pending.lock().expect("policy completion poisoned");
        let value = pending.get_or_insert_with(|| Box::<T>::default());
        f(value
            .downcast_mut::<T>()
            .expect("one pending product type per policy"))
    }

    pub fn current() -> Option<Arc<Self>> {
        carried_context::completion::<Self>()
    }

    pub fn errors(&self) -> Vec<RecordedStoreError> {
        self.errors
            .lock()
            .expect("policy completion poisoned")
            .clone()
    }

    pub fn acknowledge(&self) {
        for error in self.errors() {
            // An inherited preparation failure must remain visible to siblings.
            // The weak origin keeps its allocation unique even after its last
            // strong owner drops, so an address cannot be reused while retained.
            if error.originated_in(self) {
                error.0.acknowledged.store(true, AtomicOrdering::Release);
            }
        }
    }

    fn record(error: &RecordedStoreError) {
        if let Some(owner) = carried_context::completion::<Self>() {
            let mut errors = owner.errors.lock().expect("policy completion poisoned");
            if !errors.iter().any(|existing| existing.id() == error.id()) {
                errors.push(error.clone());
            }
            carried_context::join_evaluation_verdict(
                brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                    brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
                ),
            );
        }
    }
}

/// One typed read-incompleteness reason with its canonical keys computed at
/// most once. Receipts, replays and enclosing capture scopes share the `Arc`,
/// so no reader re-serializes or re-orders a cause it already holds.
#[doc(hidden)]
pub struct CapturedCause {
    reason: QueryReadIncomplete,
    order_key: std::sync::OnceLock<Box<[u8]>>,
    replay_key: std::sync::OnceLock<Option<Arc<[u8]>>>,
    computations: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for CapturedCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(f)
    }
}

impl CapturedCause {
    #[doc(hidden)]
    pub fn new(reason: QueryReadIncomplete) -> Arc<Self> {
        Arc::new(Self {
            reason,
            order_key: std::sync::OnceLock::new(),
            replay_key: std::sync::OnceLock::new(),
            computations: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    #[doc(hidden)]
    pub fn reason(&self) -> &QueryReadIncomplete {
        &self.reason
    }

    /// `QueryReadIncomplete::answer_order_key`, computed once.
    #[doc(hidden)]
    pub fn order_key(&self) -> &[u8] {
        self.order_key.get_or_init(|| {
            self.note_computation();
            self.reason.answer_order_key().into_boxed_slice()
        })
    }

    /// `QueryReadIncomplete::canonical_replay_key`, computed once.
    #[doc(hidden)]
    pub fn replay_key(&self) -> Option<&Arc<[u8]>> {
        self.replay_key
            .get_or_init(|| {
                self.note_computation();
                self.reason.canonical_replay_key().map(Arc::from)
            })
            .as_ref()
    }

    fn note_computation(&self) {
        self.computations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Finalize both lazy keys before weighing their retained allocations.
    /// A fixed admission charge must cover later merges as well as singleton
    /// captures, whose sort never needs the presentation key.
    #[doc(hidden)]
    pub fn retained_key_bytes(&self) -> usize {
        use brokk_bifrost_core::allocation_size::allocation_size;
        let order_key = self.order_key();
        let replay_key = self.replay_key();
        allocation_size(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())
            + allocation_size(order_key.len())
            + replay_key.map_or(0, |key| {
                allocation_size(key.len() + 2 * std::mem::size_of::<usize>())
            })
    }

    /// How many canonical keys this cause has computed. Pins (in tests) that
    /// replay never recomputes.
    #[doc(hidden)]
    pub fn key_computations(&self) -> usize {
        self.computations.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The canonical of two causes, as `QueryReadIncomplete::merge_optional`
    /// chooses between two reasons.
    fn merge(first: Arc<Self>, second: Arc<Self>) -> Arc<Self> {
        if !first.reason.is_execution_dependent() && second.reason.is_execution_dependent() {
            return second;
        }
        if Arc::ptr_eq(&first, &second)
            || first.reason == second.reason
            || first.order_key() <= second.order_key()
        {
            first
        } else {
            second
        }
    }
}

/// Distinct causes in first-seen order. Keyed causes are found through a hash
/// index and confirmed by full equality; causes without a replay key (operational
/// stops) keep the exact linear comparison, so membership equals `Vec::contains`.
#[derive(Debug, Default)]
struct CapturedSet {
    items: Vec<Arc<CapturedCause>>,
    keyed: std::collections::HashMap<Arc<[u8]>, Vec<usize>>,
    unkeyed: Vec<usize>,
}

impl CapturedSet {
    fn insert(&mut self, cause: &Arc<CapturedCause>) {
        let at = self.items.len();
        match cause.replay_key() {
            Some(key) => {
                let bucket = self.keyed.entry(Arc::clone(key)).or_default();
                if bucket.iter().any(|&seen| {
                    Arc::ptr_eq(&self.items[seen], cause) || self.items[seen].reason == cause.reason
                }) {
                    return;
                }
                bucket.push(at);
            }
            None => {
                if self.unkeyed.iter().any(|&seen| {
                    Arc::ptr_eq(&self.items[seen], cause) || self.items[seen].reason == cause.reason
                }) {
                    return;
                }
                self.unkeyed.push(at);
            }
        }
        self.items.push(Arc::clone(cause));
    }
}

/// The sticky incompleteness of one request. Every slot moves under one lock,
/// through `record_store_error` and `record`, so the slots cannot be observed
/// half-updated.
#[derive(Debug, Default)]
struct QueryCompletion {
    /// Kept apart from `first`: `completion` prefers a typed reason over a
    /// bare store failure. `first` is the canonical presentation representative,
    /// independent of recording order.
    store_errors: Vec<RecordedStoreError>,
    first: Option<Arc<CapturedCause>>,
    /// Only file-cache builders capture every reason, so a stable first reason
    /// cannot conceal a later transient failure when deciding cache admission.
    captured: Option<CapturedSet>,
    proof_attempt: bool,
}

impl QueryCompletion {
    fn capturing() -> Self {
        Self {
            captured: Some(CapturedSet::default()),
            ..Self::default()
        }
    }

    fn capture(&mut self, cause: &Arc<CapturedCause>) {
        if let Some(captured) = &mut self.captured {
            captured.insert(cause);
        }
    }

    fn record_store_error(&mut self, error: RecordedStoreError) {
        if self.captured.is_some() {
            self.capture(&CapturedCause::new(QueryReadIncomplete::StoreFailure(
                error.error().clone(),
            )));
        }
        self.store_errors.push(error);
    }

    /// Record an already-interned cause. Its keys were computed when it was
    /// first created; nothing here recomputes them.
    fn record_interned(&mut self, cause: Arc<CapturedCause>) {
        self.capture(&cause);
        self.first = Some(match self.first.take() {
            None => cause,
            Some(first) => CapturedCause::merge(first, cause),
        });
    }

    fn completion(&self) -> Result<(), QueryReadIncomplete> {
        let store_error = self.store_errors.iter().min_by_key(|error| {
            QueryReadIncomplete::StoreFailure(error.error().clone()).answer_order_key()
        });
        match (&self.first, store_error) {
            (Some(reason), _) => Err(reason.reason().clone()),
            (None, Some(error)) => Err(QueryReadIncomplete::StoreFailure(error.error().clone())),
            (None, None) => Ok(()),
        }
    }
}

impl AnalyzerQueryContext {
    /// Decide this analyzer source's selection at query entry. Nested scopes
    /// and attached workers share the outer request's first capture.
    pub(crate) fn bind_workspace_snapshots(
        &self,
        source: &Arc<arc_swap::ArcSwap<crate::analyzer::store::WorkspaceSnapshots>>,
    ) {
        if self.outer_request.is_closed() {
            return;
        }
        self.outer_request
            .bind_workspace_selection(Arc::as_ptr(source) as usize, || RequestWorkspaceSelection {
                owner: Arc::clone(source),
                snapshots: source.load_full(),
            });
    }

    /// An independent request never inherits another request running on this thread.
    pub fn root() -> Self {
        Self {
            enclosing: None,
            outer_request: OuterRequest::new(),
            retained_fill_domain: Arc::default(),
            fill_local_memos: None,
            request_cache_domain: None,
            ..Self::default()
        }
    }

    /// Enter this request on the thread performing its work.
    pub fn enter(self: &Arc<Self>) -> ReadAttributionGuard {
        query_attribution(self)
    }

    pub(crate) fn request_cache_domain(&self) -> Option<u64> {
        self.request_cache_domain.as_ref().map(|domain| domain.id)
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
            outer_request: current_query_context()
                .map(|context| Arc::clone(&context.outer_request))
                .unwrap_or_else(OuterRequest::new),
            request_cache_domain: current_query_context()
                .and_then(|c| c.request_cache_domain.clone()),
            retained_fill_domain: current_query_context()
                .map(|context| context.retained_fill_domain.clone())
                .unwrap_or_default(),
            fill_local_memos: None,
            enclosing: current_query_context(),
            completion: Mutex::default(),
            selected_procedures: Mutex::default(),
            ownership_files: Mutex::default(),
            ownership_procedures: Mutex::default(),
            candidate_macro_procedure_overlay: Mutex::default(),
            completion_boundary: None,
            taint_output_receipt_capture: current_query_context()
                .is_some_and(|context| context.taint_output_receipt_capture),

            cancellation: None,
            identifier_candidate_memo_owner: None,
            semantic_models_selected: None,
            semantic_model_overlay_override: None,
            active_semantic_model_snapshot_override: None,
            host_activation_override: None,
            tier_accesses: Default::default(),
            read_ledger: None,
            shadowed_read_ledger: None,
            policy_unit_label: None,
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
pub struct AnalyzerSnapshotCaches {
    retention_budget: brokk_bifrost_core::retention_budget::RetentionBudget,
    pub artifact_digests: Arc<crate::analyzer::artifact_digest::ArtifactDigestMemo>,
    derivations: Arc<crate::analyzer::derivation_host::AnalyzerDerivations>,
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

#[cfg(any(test, feature = "test-support"))]
impl Default for AnalyzerSnapshotCaches {
    fn default() -> Self {
        Self::new(crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache::DEFAULT_CONSTRUCTION_LIMIT_BYTES)
    }
}

impl AnalyzerSnapshotCaches {
    pub(crate) fn retention_budget(
        &self,
    ) -> &brokk_bifrost_core::retention_budget::RetentionBudget {
        &self.retention_budget
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new(derived_layer_budget_bytes: u64) -> Self {
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
            derived_layer_budget_bytes * 8,
        );
        Self::new_with_budget(derived_layer_budget_bytes, &budget)
    }

    pub(crate) fn new_with_budget(
        derived_layer_budget_bytes: u64,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Self {
        Self {
            retention_budget: budget.clone(),
            artifact_digests: Arc::new(crate::analyzer::artifact_digest::ArtifactDigestMemo::new(budget)),
            derivations: Arc::new(crate::analyzer::derivation_host::AnalyzerDerivations::new(budget)),
            derived_layers: Arc::new(
                crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache::new(
                    derived_layer_budget_bytes, budget,
                ),
            ),
            usage_graphs: Arc::new(crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache::new(
                budget,
            )),
            java_usage_evidence: Arc::new(
                crate::analyzer::usages::java_usage_evidence_cache::SnapshotJavaUsageEvidenceCache::new(
                    budget,
                ),
            ),
            semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache::new(
                budget,
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
            retention_budget: self.retention_budget.clone(),
            artifact_digests: Arc::clone(&self.artifact_digests),
            derivations: Arc::clone(&self.derivations),
            derived_layers: Arc::clone(&self.derived_layers),
            usage_graphs: Arc::clone(&self.usage_graphs),
            java_usage_evidence: Arc::clone(&self.java_usage_evidence),
            semantic_models: self
                .semantic_models
                .new_for_updated_snapshot(&self.retention_budget),
            runtime_syntax: self.runtime_syntax.clone(),
        }
    }

    pub fn derived_layers(
        &self,
    ) -> &crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache {
        &self.derived_layers
    }

    pub fn derivations(&self) -> &crate::analyzer::derivation_host::AnalyzerDerivations {
        &self.derivations
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

    pub(crate) fn install_carried_dependency_evidence(
        &self,
        models_selected: bool,
        evidence: Vec<(
            crate::analyzer::Language,
            Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>,
        )>,
        stale: Vec<crate::analyzer::DependencyPackEcosystem>,
        old_request: Option<crate::analyzer::semantic_model::ActivationInputs>,
        activated: Option<Vec<crate::analyzer::DependencyPackEcosystem>>,
        request_evidence: HashMap<
            crate::analyzer::DependencyPackEcosystem,
            crate::analyzer::semantic_model::DependencyRequestEvidence,
        >,
    ) {
        self.semantic_models.install_carried_dependency_evidence(
            models_selected,
            evidence,
            stale,
            old_request,
            activated,
            request_evidence,
        );
    }

    pub(crate) fn carried_activation_request(
        &self,
    ) -> Option<crate::analyzer::semantic_model::SemanticModelActivationRequest> {
        self.semantic_models.carried_activation_request()
    }

    pub(crate) fn carried_activation_inputs(
        &self,
    ) -> Option<crate::analyzer::semantic_model::ActivationInputs> {
        self.semantic_models.carried_activation_inputs()
    }

    pub(crate) fn activated_dependency_ecosystems(
        &self,
    ) -> Option<Vec<crate::analyzer::DependencyPackEcosystem>> {
        self.semantic_models.activated_dependency_ecosystems()
    }

    pub(crate) fn requires_whole_dependency_refresh(&self) -> bool {
        self.semantic_models.requires_whole_dependency_refresh()
    }

    pub(crate) fn stale_dependency_ecosystems(
        &self,
    ) -> Vec<crate::analyzer::DependencyPackEcosystem> {
        self.semantic_models.stale_dependency_ecosystems()
    }

    pub(crate) fn runtime_syntax(
        &self,
    ) -> &crate::analyzer::semantic::workspace_oracle::RuntimeSyntaxCache {
        self.runtime_syntax.get_or_init(|| {
            crate::analyzer::semantic::workspace_oracle::runtime_syntax_cache(
                &self.retention_budget,
            )
        })
    }

    pub fn bind_host_activation_context(
        &self,
        host: Arc<crate::analyzer::semantic_model::HostActivationContext>,
    ) -> Result<(), String> {
        self.semantic_models.bind_host_activation(host)
    }
    pub fn host_activation_context(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::HostActivationContext>> {
        self.semantic_models.host_activation()
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

    pub(crate) fn store_captured_dependency_discovery(
        &self,
        ecosystem: crate::analyzer::DependencyPackEcosystem,
        discovery: crate::analyzer::semantic_model::CapturedDependencyDiscovery,
    ) {
        self.semantic_models
            .store_captured_dependency_discovery(ecosystem, discovery);
    }

    pub(crate) fn captured_dependency_discovery_is_complete(
        &self,
        ecosystem: crate::analyzer::DependencyPackEcosystem,
    ) -> bool {
        self.semantic_models
            .captured_dependency_discovery_is_complete(ecosystem)
    }

    pub(crate) fn take_captured_dependency_discovery(
        &self,
        ecosystem: crate::analyzer::DependencyPackEcosystem,
    ) -> Option<crate::analyzer::semantic_model::CapturedDependencyDiscovery> {
        self.semantic_models
            .take_captured_dependency_discovery(ecosystem)
    }

    #[doc(hidden)]
    pub fn dependency_discovery_evidence(
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
pub type WorkspaceFileIndexCell = Arc<WorkspaceFileListingCell>;

/// One request's workspace listing, shared by every consumer that needs the
/// whole tree: the basename [`WorkspaceFileIndex`] and the C# configuration
/// digest (#13799). Whichever consumer asks first performs the only walk; the
/// others reuse its (files, omissions) pair. A failed walk is never stored, so
/// the next asker walks again and the listing stays current per request.
///
/// The listings sit in a slot that every delegate of one multi-language
/// analyzer shares (`share_listing_with`), so the consumers need not reach the
/// same delegate's cell. Each listing is keyed by the project view it describes.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct WorkspaceFileListingCell {
    index: OnceLock<Arc<WorkspaceFileIndex>>,
    listings: OnceLock<Arc<WorkspaceListings>>,
}

/// Listings of this request, one per project view. The lock is held across a
/// walk so concurrent askers wait for it instead of walking again.
#[derive(Debug, Default)]
struct WorkspaceListings(Mutex<Vec<WorkspaceListing>>);

#[derive(Debug)]
struct WorkspaceListing {
    view: ProjectViewKey,
    files: SharedWorkspaceFileListing,
    /// What the walk published, replayed on every reuse so a reader records
    /// the read its own walk would have recorded.
    receipt: brokk_bifrost_core::analyzer::project_reads::PublishedInventoryReads,
}

/// Identity of the project view a listing describes: the view object itself,
/// and its complete certified listing revisions. Delegates of one workspace
/// hold the same view object; a different view of the same root (a filtered, overlaid
/// or captured one) can list different files and must walk its own listing.
/// The key retains the original read slot, preventing source identity reuse
/// while an entry survives. Certified revisions identify the listing owner;
/// a raw view address alone is not a lifetime or identity guarantee.
#[derive(Clone, Debug)]
struct ProjectViewKey {
    view: usize,
    source: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot,
    stamps: Vec<brokk_bifrost_core::analyzer::project::ProjectViewStamp>,
}

impl PartialEq for ProjectViewKey {
    fn eq(&self, other: &Self) -> bool {
        self.view == other.view
            && self.source.is_same_source(&other.source)
            && self.stamps == other.stamps
    }
}
impl Eq for ProjectViewKey {}

impl ProjectViewKey {
    fn of(project: &dyn Project) -> Option<Self> {
        let source = project.project_read_slot()?.clone();
        let stamps = project.file_listing_stamp()?;
        if stamps.is_empty() {
            return None;
        }
        Some(Self {
            view: std::ptr::from_ref(project).addr(),
            source,
            stamps,
        })
    }
}

impl WorkspaceFileListingCell {
    pub fn get(&self) -> Option<&Arc<WorkspaceFileIndex>> {
        self.index.get()
    }

    pub(crate) fn get_or_init(
        &self,
        build: impl FnOnce() -> Arc<WorkspaceFileIndex>,
    ) -> &Arc<WorkspaceFileIndex> {
        self.index.get_or_init(build)
    }

    fn listings(&self) -> &Arc<WorkspaceListings> {
        self.listings.get_or_init(Arc::default)
    }

    /// Make this cell use `other`'s listings. A multi-language analyzer calls
    /// this on every delegate's cell when a request opens, before anything
    /// lists the workspace, so whichever delegate a consumer reaches serves the
    /// one listing. A cell that already holds listings keeps them.
    pub fn share_listing_with(&self, other: &WorkspaceFileListingCell) {
        self.listings.get_or_init(|| Arc::clone(other.listings()));
    }

    /// The request's listing of `project`, walked at most once per certified,
    /// unchanged view. Unknown or concurrently moved views are not retained.
    ///
    /// A walk records its own project read through `all_files_with_omissions`.
    /// A reuse replays the receipt that walk published, so the asker records
    /// what its own walk would have recorded: a digest fill keeps its inventory
    /// read, and a caller under `without_project_reads` still records nothing.
    pub fn listing(&self, project: &dyn Project) -> std::io::Result<SharedWorkspaceFileListing> {
        let mut listings = self
            .listings()
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(view) = ProjectViewKey::of(project) else {
            drop(listings);
            return project.all_files_with_omissions();
        };
        if let Some(listing) = listings.iter().find(|listing| listing.view == view) {
            debug_assert!(
                listing
                    .files
                    .0
                    .first()
                    .into_iter()
                    .chain(listing.files.0.last())
                    .all(|file| file.root() == project.root()),
                "a reused listing must describe the project view that asks for it: {:?}",
                project.root()
            );
            brokk_bifrost_core::analyzer::project_reads::replay_published_inventory_reads(
                &listing.receipt,
            );
            return Ok(listing.files.clone());
        }
        let (walked, receipt) =
            brokk_bifrost_core::analyzer::project_reads::capture_published_inventory_reads(|| {
                project.all_files_with_omissions()
            });
        let files = walked?;
        // Keep the pre-getter key. An invalidation during or after the getter
        // makes this a miss, never an old answer relabelled with a new stamp.
        if ProjectViewKey::of(project).as_ref() == Some(&view) {
            listings.retain(|listing| listing.view.view != view.view);
            listings.push(WorkspaceListing {
                view,
                files: files.clone(),
                receipt,
            });
        }
        Ok(files)
    }
}

/// One scalar getter-owned inventory certificate per request, independent of
/// the optional basename resolver index. The root prevents cross-view reuse.
#[doc(hidden)]
pub type WorkspaceFileInventoryCell = Arc<
    OnceLock<(
        std::path::PathBuf,
        Option<super::semantic::ids::StableDigest>,
    )>,
>;

impl WorkspaceFileIndex {
    /// One ignore-aware listing of `project`, bucketed by basename. With a
    /// request cell the listing is the request's shared one (#13799).
    pub(crate) fn build(project: &dyn Project, shared: Option<&WorkspaceFileListingCell>) -> Self {
        let listed = brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let files = match shared {
                Some(cell) => cell.listing(project).map(|(files, _)| files),
                None => project.all_files().map(Arc::new),
            }
            .map_err(|err| format!("listing workspace files under {:?}: {err}", project.root()))?;
            let receipt =
                brokk_bifrost_core::analyzer::project_reads::file_set_receipt(project, &files)
                    .map_err(|err| {
                        format!(
                            "certifying workspace files under {:?}: {err}",
                            project.root()
                        )
                    })?;
            Ok((
                Self::bucket_by_basename(&files),
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
        files: &std::collections::BTreeSet<ProjectFile>,
    ) -> crate::hash::HashMap<String, Vec<ProjectFile>> {
        let mut by_basename: crate::hash::HashMap<String, Vec<ProjectFile>> = Default::default();
        for file in files {
            let Some(name) = file.rel_path().file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            by_basename
                .entry(name.to_string())
                .or_default()
                .push(file.clone());
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

    pub(crate) fn semantic_model_overlay_read_override_for_current_thread(
        &self,
    ) -> Option<crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead> {
        use crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead;
        let overlay = self.semantic_model_overlay_override_for_current_thread()?;
        Some(match overlay {
            Some(overlay) => SemanticModelOverlayRead::Published(overlay),
            None if self
                .semantic_models_selected
                .expect("model override freezes selection") =>
            {
                SemanticModelOverlayRead::Pending(QueryReadIncomplete::SemanticModelsPending)
            }
            None => SemanticModelOverlayRead::NotSelected,
        })
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

    pub(crate) fn host_activation_override_for_current_thread(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::HostActivationContext>>> {
        let (owner, host) = self.host_activation_override.as_ref()?;
        (owner == &std::thread::current().id()).then(|| host.clone())
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
    #[track_caller]
    pub fn record_unattributed_read(&self) {
        self.record_unattributed_reads(1);
    }

    /// Records a batch of crossings this request could not name.
    #[track_caller]
    pub fn record_unattributed_reads(&self, count: usize) {
        if let Some(ledger) = &self.read_ledger {
            ledger.record_unattributed_reads(count);
        }
    }

    /// Marks a batch of crossings that depended on transient execution state.
    #[track_caller]
    pub fn mark_execution_dependent_reads(&self, count: usize) {
        if let Some(ledger) = &self.read_ledger {
            ledger.mark_execution_dependent_reads(count);
        }
    }

    /// Attributes `count` of the execution dependences marked on this request
    /// to a refused budget charge.
    pub fn record_budget_dependences(&self, count: usize) {
        if let Some(ledger) = &self.read_ledger {
            ledger.record_budget_dependences(count);
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
        let error = RecordedStoreError::new(error);
        PolicyCompletionOwner::record(&error);
        self.record_store_error_record(error);
    }

    fn record_store_error_record(&self, error: RecordedStoreError) {
        if let Some(ledger) = &self.read_ledger {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=store",
                    file!(),
                    line!()
                )
            });
            ledger.mark_execution_dependent();
            ledger.join_verdict(
                brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                    brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
                ),
            );
            ledger.record_store_failure();
        }
        self.append_store_error(error);
    }

    fn append_store_error(&self, error: RecordedStoreError) {
        self.lock_completion().record_store_error(error);
    }

    pub fn store_error(&self) -> Option<StoreError> {
        self.lock_completion()
            .store_errors
            .first()
            .map(|record| record.error().clone())
    }

    /// All failures, including acknowledged failures, in recording order.
    pub fn recorded_store_errors(&self) -> Vec<RecordedStoreError> {
        self.lock_completion().store_errors.clone()
    }

    /// Acknowledge only failures represented by a completed typed outcome.
    /// Shared records propagate acknowledgment to enclosing request contexts.
    pub fn acknowledge_store_errors(&self, identities: &[StoreErrorId]) {
        for record in &self.lock_completion().store_errors {
            if identities.contains(&record.id()) {
                record.0.acknowledged.store(true, AtomicOrdering::Release);
            }
        }
    }

    pub fn unacknowledged_store_error(&self) -> Option<StoreError> {
        self.lock_completion()
            .store_errors
            .iter()
            .find(|record| !record.0.acknowledged.load(AtomicOrdering::Acquire))
            .map(|record| record.error().clone())
    }

    /// Completion belongs to this evaluation, including its boundary itself.
    /// Start at the parent when importing shared preparation into a new owner.
    fn completion_ancestry(&self) -> impl Iterator<Item = &Self> {
        std::iter::successors(Some(self), |context| {
            if matches!(
                context.completion_boundary,
                Some(
                    QueryCompletionBoundary::AdvisoryRead
                        | QueryCompletionBoundary::PolicyEvaluation
                )
            ) {
                return None;
            }
            context
                .enclosing
                .as_deref()
                .filter(|parent| Arc::ptr_eq(&parent.outer_request, &self.outer_request))
        })
    }

    /// Independent answers isolate answer gaps, while a store failure remains
    /// an operational fact of their request or policy evaluation. New requests
    /// and sibling policies are clean; advisory reads keep their own boundary.
    fn request_store_error(&self) -> Option<StoreError> {
        for context in self.completion_ancestry() {
            if let Some(error) = context.store_error() {
                return Some(error);
            }
            if context.completion_boundary == Some(QueryCompletionBoundary::PolicyEvaluation) {
                // #11701 keeps preparation records on their original scopes.
                // This evaluation's owner already has their filtered, unique
                // references. Observe that view only at this boundary; never
                // copy it into an independent fill's own completion.
                return PolicyCompletionOwner::current().and_then(|owner| {
                    owner
                        .errors
                        .lock()
                        .expect("policy completion poisoned")
                        .first()
                        .map(|record| record.error().clone())
                });
            }
        }
        None
    }

    fn lock_completion(&self) -> std::sync::MutexGuard<'_, QueryCompletion> {
        self.completion
            .lock()
            .expect("analyzer query completion mutex poisoned")
    }

    /// Records the first structured reason this request could not establish a
    /// complete read. The reason is sticky so an outer scope retains an inner
    /// scope's cancellation after that inner scope closes.
    pub fn record_read_incomplete(&self, reason: QueryReadIncomplete) {
        self.record_read_incomplete_with_store_error(&CapturedCause::new(reason), None);
    }

    /// Records `reason` and, under the same lock, the store error an attributed
    /// store failure carries, without capturing it as a second reason.
    fn record_read_incomplete_with_store_error(
        &self,
        cause: &Arc<CapturedCause>,
        store_error: Option<&RecordedStoreError>,
    ) {
        let reason = cause.reason();
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
            ledger.join_verdict(
                brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                    brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
                ),
            );
        }
        // Whether or not an error record accompanies it, an attributed store
        // failure leaves a product that no other consumer may reuse (#11534).
        if matches!(reason.base_cause(), QueryReadIncomplete::StoreFailure(_))
            && let Some(ledger) = &self.read_ledger
        {
            ledger.record_store_failure();
        }
        self.append_read_incomplete(Arc::clone(cause), store_error);
    }

    // Captured channels own ledger effects on replay. Completion storage and
    // store-owner propagation still run, without a second channel writer.
    fn append_read_incomplete(
        &self,
        cause: Arc<CapturedCause>,
        store_error: Option<&RecordedStoreError>,
    ) {
        let mut completion = self.lock_completion();
        if let Some(record) = store_error {
            completion.store_errors.push(record.clone());
        }
        completion.record_interned(cause);
    }

    /// Returns the canonical typed read incompleteness, falling back to a
    /// canonical store failure when no more specific reason was recorded.
    pub fn read_completion(&self) -> Result<(), QueryReadIncomplete> {
        self.lock_completion().completion()
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

pub(crate) fn current_request_cache_domain() -> Option<u64> {
    current_query_context().and_then(|context| context.request_cache_domain())
}

pub(crate) fn current_request_cache_domain_owner() -> Option<Arc<RequestCacheDomain>> {
    current_query_context().and_then(|context| context.request_cache_domain.clone())
}

/// The contexts from `start` outward that share its request cache domain,
/// through the first policy-evaluation boundary.
fn request_domain_contexts(
    start: Option<Arc<AnalyzerQueryContext>>,
) -> impl Iterator<Item = Arc<AnalyzerQueryContext>> {
    let domain = start
        .as_ref()
        .and_then(|context| context.request_cache_domain());
    let mut stopped = false;
    std::iter::successors(start, |context| context.enclosing.clone()).take_while(move |context| {
        if stopped || context.request_cache_domain() != domain {
            return false;
        }
        stopped = context.completion_boundary == Some(QueryCompletionBoundary::PolicyEvaluation);
        true
    })
}

pub(crate) fn current_domain_read_completion() -> Result<(), QueryReadIncomplete> {
    let policy = PolicyCompletionOwner::current();
    let mut contexts = request_domain_contexts(current_query_context());
    // The running scope's own reads count in full. An enclosing scope's store
    // failure counts only when this evaluation would own or inherit it: a
    // concurrent sibling policy's failure on the shared request scope does
    // not make this evaluation refuse its fills (#11829).
    if let Some(own) = contexts.next() {
        own.read_completion()?;
    }
    for context in contexts {
        let completion = context.lock_completion();
        if let Some(reason) = &completion.first {
            return Err(reason.reason().clone());
        }
        if let Some(error) = completion
            .store_errors
            .iter()
            .find(|error| error.inherited_by(policy.as_deref()))
        {
            return Err(QueryReadIncomplete::StoreFailure(error.error().clone()));
        }
    }
    Ok(())
}

/// The completion of the innermost context only: what the running build has
/// itself recorded. An enclosing scope's failure describes that scope's reads,
/// so a check that protects the build's own value must not depend on it.
pub(crate) fn current_own_read_completion() -> Result<(), QueryReadIncomplete> {
    current_query_context().map_or(Ok(()), |context| context.read_completion())
}

pub(crate) fn candidate_overlay_query_context() -> Option<Arc<AnalyzerQueryContext>> {
    current_query_contexts().last()
}

fn current_query_contexts() -> impl Iterator<Item = Arc<AnalyzerQueryContext>> {
    std::iter::successors(current_query_context(), |context| context.enclosing.clone())
}

pub(crate) fn current_query_context_value<T>(
    mut select: impl FnMut(&AnalyzerQueryContext) -> Option<T>,
) -> Option<T> {
    current_query_contexts().find_map(|context| select(&context))
}

pub(crate) fn current_policy_unit_label() -> Option<String> {
    current_query_context_value(|context| context.policy_unit_label.as_deref().map(str::to_owned))
}

/// A model override belongs only to analyzers that registered its scope.
/// Retained-fill domains still share their analyzer's registered ancestry.
pub(crate) fn registered_query_context_value<T>(
    mut registered: impl FnMut(&Arc<AnalyzerQueryContext>) -> bool,
    mut select: impl FnMut(&AnalyzerQueryContext) -> Option<T>,
) -> Option<T> {
    current_query_contexts()
        .filter(|context| registered(context))
        .find_map(|context| select(&context))
}

/// Inspect the innermost proof's ordinary completion capture.
#[doc(hidden)]
pub fn current_captured_proof_stop() -> Option<QueryReadIncomplete> {
    current_query_contexts()
        .find_map(|context| {
            let completion = context.lock_completion();
            completion.proof_attempt.then(|| {
                completion
                    .captured
                    .as_ref()
                    .expect("proof captures completion")
                    .items
                    .iter()
                    .map(|cause| cause.reason())
                    .filter(|reason| matches!(reason, QueryReadIncomplete::ProofStopped { .. }))
                    .cloned()
                    .reduce(|first, next| {
                        QueryReadIncomplete::merge_optional(Some(first), Some(next)).unwrap()
                    })
            })
        })
        .flatten()
}

/// A proof stop outside an attempt has no enclosing proof to make incomplete.
#[doc(hidden)]
pub fn record_proof_incomplete_on_current_contexts(reason: QueryReadIncomplete) {
    assert!(matches!(reason, QueryReadIncomplete::ProofStopped { .. }));
    if current_query_contexts().any(|context| context.lock_completion().proof_attempt) {
        record_query_incomplete_on_current_contexts(reason);
    }
}

/// Record `reason` on the query contexts the calling thread is reading under,
/// for a reader that learns of a gap outside any analyzer handle.
pub fn record_current_query_incomplete(reason: QueryReadIncomplete) {
    record_query_incomplete_on_current_contexts(reason)
}

#[doc(hidden)]
pub(crate) fn record_query_incomplete_on_current_contexts(reason: QueryReadIncomplete) {
    // One interned cause for every enclosing scope: its keys are computed at
    // most once however deeply captures nest.
    let cause = CapturedCause::new(reason);
    visit_query_incomplete_contexts(cause.reason(), |context, _, store_error| {
        context.record_read_incomplete_with_store_error(&cause, store_error);
    });
}

pub(crate) fn replay_captured_query_incomplete(reason: QueryReadIncomplete) {
    replay_captured_cause(&CapturedCause::new(reason));
}

/// Replay one interned cause into every enclosing context. The keys it carries
/// were computed once when the cause was created.
pub(crate) fn replay_captured_cause(cause: &Arc<CapturedCause>) {
    visit_query_incomplete_contexts(cause.reason(), |context, _, store_error| {
        context.append_read_incomplete(Arc::clone(cause), store_error);
    });
}

/// Inject one completion event into every active capturing scope, stopping at
/// the same advisory boundary as ordinary completion propagation. This is a
/// test hook: unlike recording the reason through an analyzer, it does not
/// install a store-error side channel or mark a read ledger, so it cannot
/// change the product whose memo receipt it is meant to exercise.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn record_captured_read_incomplete_for_test(reason: QueryReadIncomplete) {
    let cause = CapturedCause::new(reason);
    for context in current_query_contexts() {
        if context.lock_completion().captured.is_some() {
            context.append_read_incomplete(Arc::clone(&cause), None);
        }
        if context.completion_boundary == Some(QueryCompletionBoundary::AdvisoryRead) {
            break;
        }
    }
}

fn visit_query_incomplete_contexts(
    reason: &QueryReadIncomplete,
    record: impl Fn(&AnalyzerQueryContext, &QueryReadIncomplete, Option<&RecordedStoreError>),
) {
    // Completion's aggregate verdict is independent of ledger channels:
    // structural incomplete causes can conservatively veto an evaluation
    // without adding a read dependence. Preserve that existing join on both
    // routes; only the fresh-recording callback writes ledger channels.
    if !reason.has_stable_replay_reason() {
        brokk_bifrost_core::analyzer::carried_context::join_evaluation_verdict(
            brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
            ),
        );
    }
    // An attributed store failure (#10984) also fills the store-error side
    // channel of every context the reason reaches, with one identity, and
    // reaches the policy owner when the walk passes every advisory boundary,
    // unless the same error was already recorded directly. The
    // attributed reason stays the only captured reason. A replayed receipt
    // reaches this path too, so a deferred failure becomes visible where the
    // receipt is replayed.
    let attributed_store_error = match reason.base_cause() {
        QueryReadIncomplete::StoreFailure(error)
            if !current_query_contexts().next().is_some_and(|context| {
                context
                    .lock_completion()
                    .store_errors
                    .iter()
                    .any(|record| record.error() == error)
            }) =>
        {
            Some(RecordedStoreError::new(error.clone()))
        }
        _ => None,
    };
    let mut stopped_at_advisory_read = false;
    for context in current_query_contexts() {
        record(&context, reason, attributed_store_error.as_ref());
        stopped_at_advisory_read =
            context.completion_boundary == Some(QueryCompletionBoundary::AdvisoryRead);
        if stopped_at_advisory_read
            || context.completion_boundary == Some(QueryCompletionBoundary::PolicyEvaluation)
            || (context.completion_boundary
                == Some(QueryCompletionBoundary::CandidateClassification)
                && !reason.is_execution_dependent())
        {
            break;
        }
    }
    // An advisory capture owns the failure until its receipt is replayed; the
    // replay reaches this function again and registers it then.
    if !stopped_at_advisory_read && let Some(record) = &attributed_store_error {
        PolicyCompletionOwner::record(record);
    }
}

pub(crate) fn record_store_error_on_current_contexts(error: StoreError) {
    visit_store_error_contexts(error, |context, error| {
        context.record_store_error_record(error)
    });
}

pub(crate) fn replay_captured_store_error(error: StoreError) {
    visit_store_error_contexts(error, |context, error| context.append_store_error(error));
}

fn visit_store_error_contexts(
    error: StoreError,
    record: impl Fn(&AnalyzerQueryContext, RecordedStoreError),
) {
    let error = RecordedStoreError::new(error);
    let mut stopped_at_advisory_read = false;
    for context in current_query_contexts() {
        record(&context, error.clone());
        stopped_at_advisory_read =
            context.completion_boundary == Some(QueryCompletionBoundary::AdvisoryRead);
        if stopped_at_advisory_read {
            break;
        }
    }
    // An advisory capture owns the failure until its receipt is replayed: a
    // discarded receipt must not fail the policy (#11534).
    if !stopped_at_advisory_read {
        PolicyCompletionOwner::record(&error);
    }
}

/// A shared failed build belongs only to its actual consumers. Preserve read
/// shadowing, but never use the analyzer registry as a Broadcast fallback.
pub(crate) fn replay_query_read_receipt_on_current_contexts(
    keys: &Arc<[crate::analyzer::ReadKey]>,
    channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
) {
    let contexts: Vec<_> = current_query_contexts().collect();
    if contexts.is_empty() {
        return;
    }
    for_each_unshadowed_active_ledger(&contexts, |ledger| {
        ledger.absorb_receipt(keys);
        ledger.record_unattributed_reads(channels.unattributed_reads);
        ledger.mark_execution_dependent_reads(channels.unpinned_execution_dependences());
        ledger.record_budget_dependences(channels.budget_dependences);
        ledger.mark_request_pinned_dependences(channels.request_pinned_dependences);
        ledger.join_verdict(channels.explicit_verdict);
        if channels.reuse_refused {
            ledger.refuse_read_reuse();
        }
        if channels.store_failed {
            ledger.record_store_failure();
        }
        ledger.record_persistence_refusals(channels.persistence_refusals);
    });
}

/// Replay the transient runtime-cache marker retained by a shared query cell.
pub(crate) fn record_runtime_cache_touch_on_current_contexts() {
    let contexts: Vec<_> = current_query_contexts().collect();
    for_each_unshadowed_active_ledger(&contexts, |ledger| ledger.mark_runtime_cache_touched());
}

/// Missing source identities leave workspace-wide absence proofs uncertain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SourceInventoryIncompleteReason {
    SourceInventoryIncomplete,
    ListingOmissions(Vec<brokk_bifrost_core::analyzer::query_batch::QueryIncompleteReason>),
}

/// Completeness obligation retained independently of filtering the inventory rows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SourceInventoryCompletion {
    Complete,
    Uncertain(SourceInventoryIncompleteReason),
}

impl SourceInventoryCompletion {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Shared acquisition and interpretation of source inventory authority.
pub struct SourceInventoryPreflight {
    pub rows: Vec<ProjectFile>,
    pub completion: SourceInventoryCompletion,
}

impl SourceInventoryPreflight {
    pub fn acquire(analyzer: &(impl IAnalyzer + ?Sized)) -> Self {
        let mut inventory = analyzer.source_file_inventory();
        // Parallel walks and multiple language delegates can repeat omissions
        // in different orders. Keep the public evidence stable and unique.
        inventory.incomplete_reasons.sort_unstable();
        inventory.incomplete_reasons.dedup();
        Self {
            rows: inventory.rows,
            completion: if inventory.complete {
                SourceInventoryCompletion::Complete
            } else {
                SourceInventoryCompletion::Uncertain(if inventory.incomplete_reasons.is_empty() {
                    SourceInventoryIncompleteReason::SourceInventoryIncomplete
                } else {
                    SourceInventoryIncompleteReason::ListingOmissions(inventory.incomplete_reasons)
                })
            },
        }
    }
}

/// Enumerate source identities independently of persisted parse-product readiness.
#[doc(hidden)]
pub fn project_source_file_inventory(
    analyzer: &(impl IAnalyzer + ?Sized),
) -> QueryBatch<ProjectFile> {
    let languages = analyzer.languages();
    project_source_file_inventory_where(analyzer, |omission| {
        super::languages::omission_hides_workspace_source(languages.iter().copied(), omission)
    })
}

/// The source inventory, incomplete for the omissions `hides` selects. A
/// consumer that resolves only some languages (JS/TS) passes the omissions that
/// can hide one of its own sources, so an unrelated link does not make it refuse.
#[doc(hidden)]
pub fn project_source_file_inventory_where(
    analyzer: &(impl IAnalyzer + ?Sized),
    hides: impl Fn(&brokk_bifrost_core::analyzer::project::WorkspaceFileOmission) -> bool,
) -> QueryBatch<ProjectFile> {
    let project = analyzer.project();
    let (listed, omissions) = match project.all_files_with_omissions() {
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
    let languages = analyzer.languages();
    inventory.incomplete_reasons.extend(
        omissions
            .iter()
            .filter(|omission| hides(omission))
            .cloned()
            .map(brokk_bifrost_core::analyzer::query_batch::QueryIncompleteReason::WorkspaceFileOmission),
    );
    inventory.complete = inventory.incomplete_reasons.is_empty();
    for language in languages {
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

pub fn current_model_set_digest(
    hash: Option<&str>,
) -> crate::analyzer::semantic::ids::StableDigest {
    hash.map_or_else(no_active_model_set_digest, active_model_digest)
}

/// The digest a recorded model-set read can verify against at this head.
///
/// A request can pin its model snapshot and its overlay apart, and either one
/// may carry the model set a compute read observed. The read verifies only
/// while both name the same set, so an overlay or snapshot pinned without the
/// other answers `None` and the receipt fails closed.
pub fn current_model_set_read_digest(
    analyzer: &dyn IAnalyzer,
) -> Option<crate::analyzer::semantic::ids::StableDigest> {
    let overlay = analyzer.model_set_digest(
        analyzer
            .semantic_model_overlay_read()
            .published()
            .as_ref()
            .map(|overlay| overlay.active_model_set_hash()),
    );
    let snapshot = analyzer.model_set_digest(
        analyzer
            .active_semantic_model_snapshot()
            .as_ref()
            .map(|snapshot| snapshot.active_models().active_model_set_hash()),
    );
    (overlay == snapshot).then_some(overlay)
}

pub(crate) fn no_active_model_set_digest() -> crate::analyzer::semantic::ids::StableDigest {
    crate::analyzer::semantic_model::LIBRARY_NONE_NO_MODEL_DIGEST
}

pub(crate) fn active_model_digest(hash: &str) -> crate::analyzer::semantic::ids::StableDigest {
    crate::analyzer::semantic::ids::StableDigest::sha256(hash)
}

fn effective_semantic_model_overlay<A: IAnalyzer + ?Sized>(
    analyzer: &A,
) -> crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead {
    use crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead;
    if let Some(frozen) = analyzer.active_query_semantic_model_overlay_read() {
        return frozen;
    }
    let query_override = analyzer.active_query_semantic_model_overlay();
    if let Some(caches) = analyzer.snapshot_caches() {
        caches.semantic_models.overlay_read(query_override)
    } else {
        match query_override.flatten() {
            Some(overlay) => SemanticModelOverlayRead::Published(overlay),
            None => SemanticModelOverlayRead::NotSelected,
        }
    }
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
    /// Conservative whole-file authority for a selected canonical parser span.
    /// Implementations must check the expected publication before recording it.
    fn certify_selected_source_file(
        &self,
        _expected: &crate::analyzer::store::resolution_operation::SelectedSourceFileCertificate<'_>,
    ) -> bool {
        self.record_unattributed_read();
        false
    }

    /// Revalidate the external receipts consumed when acquiring this analyzer's
    /// configuration. A retained revision must check this before reuse: source
    /// snapshots and store generations do not track ambient configuration edits.
    /// Languages without external configuration acquisition have no receipts.
    fn configuration_external_inputs_unchanged(&self) -> bool {
        true
    }

    fn certify_selected_configuration(
        &self,
        _language: crate::analyzer::Language,
        _snapshot: &crate::analyzer::store::WorkspaceSnapshotId,
        _input_identity: &[u8; 32],
        _connection: &rusqlite::Connection,
    ) -> crate::analyzer::store::resolution_operation::ConfigurationCertificate {
        crate::analyzer::store::resolution_operation::ConfigurationCertificate::Uncertified
    }

    #[doc(hidden)]
    fn project_parse_variant_reader(
        &self,
    ) -> Option<crate::analyzer::tree_sitter_analyzer::ProjectVariantReader> {
        None
    }
    #[doc(hidden)]
    fn set_project_parse_variant_reader(
        &self,
        _reader: crate::analyzer::tree_sitter_analyzer::ProjectVariantReader,
    ) {
    }

    /// The variant of the bytes this analyzer currently serves for the path, overlay included.
    /// Other languages return Some(Empty). None is unreadable, with the read
    /// failure recorded on the request; it certifies neither facts nor absence.
    fn selected_parse_variant(
        &self,
        file: &ProjectFile,
    ) -> Option<brokk_bifrost_core::gitblob::ParseVariant> {
        if file.language().uses_configured_parse_variants() {
            return None;
        }
        Some(brokk_bifrost_core::gitblob::ParseVariant::Empty)
    }

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
    ) -> Result<
        Arc<brokk_bifrost_core::retention_budget::Accounted<crate::analyzer::LoopCandidates>>,
        QueryReadIncomplete,
    > {
        Ok(Arc::new(
            brokk_bifrost_core::retention_budget::Accounted::uncharged(
                crate::analyzer::build_loop_candidates(workspace, procedure, cancellation),
            ),
        ))
    }

    /// Build statement assessments for one semantic procedure.
    fn statement_assessments_for(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<
        brokk_bifrost_core::retention_budget::Accounted<
            crate::analyzer::semantic::statement_entries::AccountedStatementAssessments,
        >,
    > {
        // No memo captures this build; its verdict joins the current captures,
        // where its ambient marks went.
        let (assessments, reuse) =
            crate::analyzer::semantic::statement_entries::build_statement_assessments(
                workspace,
                procedure,
                cancellation,
            );
        self.join_reuse_verdict(reuse);
        Arc::new(brokk_bifrost_core::retention_budget::Accounted::uncharged(
            crate::analyzer::semantic::statement_entries::AccountedStatementAssessments::new(
                assessments,
            ),
        ))
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
        _reuse: &mut brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict,
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
    /// Recording is implemented, independently of which consumer is active now.
    fn supports_selected_read_recording(&self) -> bool {
        false
    }

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
    #[track_caller]
    fn record_unattributed_read(&self) {
        self.record_unattributed_reads(1);
    }

    #[track_caller]
    fn record_unattributed_reads(&self, _count: usize) {}

    #[track_caller]
    fn refuse_read_reuse(&self) {}

    /// Owned capability for static relational frontier handles. Unsupported
    /// analyzers fail closed if a frontier is read under capture.
    fn relational_frontier_read_recorder(
        &self,
    ) -> crate::analyzer::relational_frontier::FrontierReadRecorder {
        crate::analyzer::relational_frontier::unbound_frontier_read_recorder()
    }

    /// Mark transient execution state through the same worker broadcasting and
    /// nested-capture attribution used by reads.
    #[track_caller]
    fn mark_execution_dependent(&self) {
        let _census = brokk_bifrost_core::analyzer::execution_census::mark_scope(
            std::panic::Location::caller(),
            "analyzer",
        );
        self.mark_execution_dependent_reads(1);
    }

    #[track_caller]
    fn mark_execution_dependent_reads(&self, _count: usize) {}

    /// Attribute `count` of the execution dependences already marked to a
    /// refused budget charge, through the same routing as
    /// [`Self::mark_execution_dependent_reads`].
    fn record_budget_dependences(&self, count: usize) {
        self.record_attributed_dependences(
            crate::analyzer::ReadLedger::record_budget_dependences,
            count,
        );
    }

    /// Record `count` execution dependences of the cause `record` counts (see
    /// [`AttributeDependences`]), through the same routing as
    /// [`Self::mark_execution_dependent_reads`].
    fn record_attributed_dependences(&self, _record: AttributeDependences, _count: usize) {}

    /// Join a replayed explicit reuse verdict into the consuming captures,
    /// through the same routing as [`Self::mark_execution_dependent_reads`].
    fn join_reuse_verdict(
        &self,
        _verdict: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict,
    ) {
    }

    /// Record transient runtime-cache eligibility evidence.
    fn mark_runtime_cache_touched(&self) {
        if let Some(ledger) = self.current_thread_read_ledger() {
            ledger.mark_runtime_cache_touched();
        }
    }

    /// Whether read recording reaches the active attribution frame. Wrappers
    /// must forward this capability along with the recording operations; a
    /// local ledger registration is not required for thread-owned captures.
    /// The default is deliberately false: hand-written fakes must opt in only
    /// when their recording operations reach the active consumers.
    fn records_query_reads(&self) -> bool {
        false
    }

    /// The exact selected revision used by a store-backed query-time read.
    /// An analyzer without a selected relational snapshot cannot certify it.
    #[doc(hidden)]
    fn selected_workspace_snapshots_for_reads(
        &self,
    ) -> Option<Arc<crate::analyzer::store::WorkspaceSnapshots>> {
        None
    }

    /// Replay one source-owned proof through the selected head's normal session.
    /// `None` refuses retained reuse; it never certifies an empty proof.
    #[doc(hidden)]
    fn selected_receiver_proof_read(
        &self,
        _file: &ProjectFile,
        _question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        _cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<
        Option<crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer>,
    > {
        self.refuse_read_reuse();
        Ok(None)
    }

    /// Test the ordinary session's exact proof after warming a transfer batch.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    fn selected_receiver_proofs_after_transfer_batch_for_test(
        &self,
        _file: &ProjectFile,
        questions: &[crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion],
        _cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<
        Vec<Option<crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer>>,
    > {
        self.refuse_read_reuse();
        Ok(vec![None; questions.len()])
    }

    /// Admit a query's source languages against this workspace's build selection.
    /// A deliberately unselected language is unavailable, not an empty inventory.
    #[doc(hidden)]
    fn require_workspace_languages(
        &self,
        _languages: &[crate::analyzer::Language],
    ) -> Result<(), StoreError> {
        Ok(())
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
    /// Prime selected readings for the paths an operation is about to scan.
    fn prefetch_parse_variants(&self, _files: &[ProjectFile]) {}

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

    /// The innermost frozen overlay and selection status on this thread.
    /// Scope creation captures this state without recording a model read.
    #[doc(hidden)]
    fn active_query_semantic_model_overlay_read(
        &self,
    ) -> Option<crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead> {
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

    #[doc(hidden)]
    fn active_query_host_activation_context(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::HostActivationContext>>> {
        None
    }

    /// Immutable host authority in this request, even when no model was active.
    fn host_activation_context(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::HostActivationContext>> {
        self.active_query_host_activation_context()
            .unwrap_or_else(|| {
                self.snapshot_caches()
                    .and_then(AnalyzerSnapshotCaches::host_activation_context)
            })
    }
    fn bind_host_activation_context(
        &self,
        host: Arc<crate::analyzer::semantic_model::HostActivationContext>,
    ) -> Result<(), String> {
        if self
            .snapshot_caches()
            .and_then(AnalyzerSnapshotCaches::host_activation_context)
            .as_ref()
            .is_some_and(|pinned| Arc::ptr_eq(pinned, &host))
        {
            return Ok(());
        }
        if host.requires_analyzed_root_validation() {
            host.validate_analyzed_root(self.project().root())?;
        }
        match self.snapshot_caches() {
            Some(cache) => cache.bind_host_activation_context(host),
            None if host.identity()
                == crate::analyzer::semantic_model::LIBRARY_NONE_APPROVAL_IDENTITY =>
            {
                Ok(())
            }
            None => Err("host activation requires an analyzer activation-context owner".into()),
        }
    }
    fn host_activation_identity(&self) -> crate::analyzer::semantic::StableDigest {
        self.host_activation_context().map_or(
            crate::analyzer::semantic_model::LIBRARY_NONE_APPROVAL_IDENTITY,
            |host| host.identity(),
        )
    }
    fn model_set_digest(&self, hash: Option<&str>) -> crate::analyzer::semantic::StableDigest {
        hash.map_or_else(
            || {
                self.host_activation_context().map_or(
                    crate::analyzer::semantic_model::LIBRARY_NONE_NO_MODEL_DIGEST,
                    |host| host.no_model_digest(),
                )
            },
            active_model_digest,
        )
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

    /// The request's scalar inventory receipt, without a resolver index build.
    #[doc(hidden)]
    fn workspace_file_inventory_cell(&self) -> Option<WorkspaceFileInventoryCell> {
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
    /// Bounded Drop inventories owned by the active query, released at its end.
    #[doc(hidden)]
    fn owned_lookup_memo(
        &self,
    ) -> Option<Arc<crate::analyzer::read_verification::OwnedLookupMemo>> {
        None
    }

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
    fn record_query_failure(&self, error: StoreError) {
        record_store_error_on_current_contexts(error);
    }

    /// Records a typed reason a collection-returning read could not establish
    /// a complete answer, on the current request context and its enclosing chain.
    #[doc(hidden)]
    fn current_query_read_completion(&self) -> Result<(), QueryReadIncomplete> {
        Ok(())
    }

    /// Complete parser candidates for a declaration-shaped question in one
    /// selected file. None means the inventory cannot certify even absence.
    #[doc(hidden)]
    fn declaration_candidates_for_question(
        &self,
        file: &ProjectFile,
        question: &crate::analyzer::read_ledger::LookupQuestion,
    ) -> Option<Vec<CodeUnit>> {
        self.is_analyzed(file).then(|| {
            self.get_declarations(file)
                .into_iter()
                .filter(|unit| {
                    crate::analyzer::read_ledger::declaration_question_matches(question, unit)
                })
                .collect()
        })
    }

    fn record_query_incomplete(&self, _reason: QueryReadIncomplete) {}

    /// Apply language-specific obligations for a consumed read key, even when
    /// no read ledger is attached to this request.
    fn record_read_obligation(&self, _key: &crate::analyzer::ReadKey) {}

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

    /// Re-index `changed_files`, certifying whole-workspace facts from
    /// `listing` when the project keeps no listing cache.
    ///
    /// `listing` is the one workspace listing read the enclosing update already
    /// took, after resolving watcher and pending paths against it. The supplied
    /// paths are already resolved and are never merged with unresolved pending
    /// paths or re-resolved here. `None` means the caller took no
    /// listing, and a project without a listing cache then cannot certify
    /// whole-workspace facts on this update.
    fn update_with_listing(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
    ) -> Self
    where
        Self: Sized;

    /// Return the producer's effect coverage alongside the new endpoint.
    /// Existing producers are broad until they explicitly report coverage.
    fn update_with_listing_report(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
    ) -> (Self, crate::analyzer::read_verification::UpdateEffects)
    where
        Self: Sized,
    {
        (
            self.update_with_listing(changed_files, listing),
            crate::analyzer::read_verification::UpdateEffects::AllMayHaveChanged(
                "delegate did not report update effects",
            ),
        )
    }

    /// Re-index `changed_files` for a caller that took no workspace listing.
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized,
    {
        self.update_with_listing(changed_files, None)
    }

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
                // None is an unknown verdict; search_symbols asks again for the
                // typed reason when the verdict filters the result (#11385).
                let in_test_region = self.in_test_region(&code_unit).ok();
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
                    in_test_region,
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

    /// Resolve effective overlay publication once, preserving frozen-query precedence.
    fn semantic_model_overlay_read(
        &self,
    ) -> crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead {
        use crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead;
        let read = effective_semantic_model_overlay(self);
        if crate::analyzer::read_attribution_records_reads(|| self.read_ledger_attached()) {
            let hash = match &read {
                SemanticModelOverlayRead::Published(overlay) => {
                    Some(overlay.active_model_set_hash())
                }
                _ => None,
            };
            self.record_read(crate::analyzer::read_ledger::ReadKey::Models(
                self.model_set_digest(hash),
            ));
        }
        read
    }

    /// Compatibility handle for transport and callers that retain the overlay.
    /// Missing selected publications still record the shared query evidence.
    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        self.semantic_model_overlay_read().published()
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
        if crate::analyzer::read_attribution_records_reads(|| self.read_ledger_attached()) {
            self.record_read(crate::analyzer::read_ledger::ReadKey::Models(
                self.model_set_digest(
                    snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.active_models().active_model_set_hash()),
                ),
            ));
        }
        if snapshot.is_none()
            && let crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead::Pending(
                reason,
            ) = self.semantic_model_overlay_read()
        {
            record_query_incomplete_on_current_contexts(reason);
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

    /// Explicit passive census; unsupported implementations report unknown.
    #[cfg(feature = "test-support")]
    fn retention_census_for_test(
        &self,
        census: &mut brokk_bifrost_core::retention_census::RetentionCensus,
    ) {
        use brokk_bifrost_core::retention_census::{FamilyLifetime, UnknownKind};
        census.record_unknown(
            "analyzer.unsupported_implementation",
            FamilyLifetime::Persistent,
            UnknownKind::Coverage,
            "implementation_has_no_retained_state_visitor",
        );
    }

    /// Snapshot-owned immutable derived query layers. Concrete analyzers keep
    /// the default when they cannot bind a complete snapshot lifecycle.
    #[doc(hidden)]
    /// Immutable generation owner, shared with every language delegate.
    fn generation_membership(
        &self,
    ) -> &Arc<crate::analyzer::tree_sitter_analyzer::GenerationWorkspaceMembership> {
        crate::analyzer::tree_sitter_analyzer::GenerationWorkspaceMembership::unavailable()
    }

    fn snapshot_caches(&self) -> Option<&AnalyzerSnapshotCaches> {
        None
    }

    fn derivations(&self) -> Option<&crate::analyzer::derivation_host::AnalyzerDerivations> {
        self.snapshot_caches()
            .map(AnalyzerSnapshotCaches::derivations)
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
    fn external_selection_authorities(
        &self,
    ) -> Vec<&dyn brokk_bifrost_core::analyzer::external_selection::ExternalSelectionAuthority>
    {
        Vec::new()
    }

    fn request_row_reader_source(
        &self,
        _catalog: &crate::analyzer::semantic_model::catalog::PinnedCatalogSource,
    ) -> Option<Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>> {
        None
    }

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
    /// [`crate::analyzer::usages::UsageFinder`] strategy. The free function [`crate::analyzer::usages::find_usages`] is the
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
        crate::analyzer::usages::query_usages(self, overloads, max_files, max_usages)
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
    fn in_test_region(
        &self,
        _code_unit: &CodeUnit,
    ) -> Result<bool, crate::analyzer::QueryReadIncomplete> {
        Ok(false)
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
    fn file_is_test_only(&self, _file: &ProjectFile) -> Result<bool, QueryReadIncomplete> {
        Ok(false)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandProbeTestAction {
    Cancel,
    IncompleteEmpty,
}

#[cfg(any(test, feature = "test-support"))]
pub trait AnalyzerTestHooks {
    /// Arm one probe-only fault at the next operand-0 evaluation.
    #[doc(hidden)]
    fn arm_operand_probe_action_for_test(&self, _action: OperandProbeTestAction) {}

    #[doc(hidden)]
    fn take_operand_probe_action_for_test(&self) -> Option<OperandProbeTestAction> {
        None
    }

    #[doc(hidden)]
    fn record_empty_operand_probe_shortcut_for_test(&self) {}

    #[doc(hidden)]
    fn empty_operand_probe_shortcut_count_for_test(&self) -> usize {
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

    /// Install the per-analyzer structured batch fake on its actual backend.
    #[doc(hidden)]
    fn relational_definition_batch_callback_for_test(
        &self,
        _callback: Arc<crate::analyzer::tree_sitter_analyzer::RelationalBatchTestCallback>,
    ) -> crate::analyzer::tree_sitter_analyzer::RelationalDefinitionBatchTestGuard {
        unimplemented!("this analyzer has no relational batch test callback")
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

impl carried_context::RequestCompletion for AnalyzerRequestState {
    fn store_failed(&self) -> bool {
        self.context
            .as_ref()
            .is_some_and(|context| context.request_store_error().is_some())
    }
}

#[derive(Clone)]
enum AttributionFrame {
    Broadcast,
    Ledgers(Vec<AttributionLedger>),
}

use brokk_bifrost_core::analyzer::carried_context::{self, CarriedContextGuard};

impl carried_context::ExecutionAttribution for AttributionFrame {
    #[track_caller]
    fn mark_execution_dependent(&self) {
        carried_context::join_evaluation_verdict(
            brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
            ),
        );
        if let Self::Ledgers(ledgers) = self {
            for (ledger, _) in ledgers {
                ledger.mark_execution_dependent();
            }
        }
    }

    #[track_caller]
    fn mark_budget_refusal(&self) {
        if let Self::Ledgers(ledgers) = self {
            for (ledger, _) in ledgers {
                ledger.mark_budget_dependent();
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

    /// Verify a previously captured receipt against current state without
    /// recording the verifier's own reads. A Current verdict must replay the
    /// verified receipt into the enclosing capture; any other verdict must
    /// recompute the body.
    pub fn for_receipt_verification() -> Self {
        Self {
            frame: AttributionFrame::Ledgers(Vec::new()),
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
            _request_state: carried_context::push_request_state_with_completion(
                self.request_state.as_ref().map(Arc::clone),
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
        .filter(|state| {
            state
                .context
                .as_ref()
                .and_then(|parent| parent.request_cache_domain())
                == context.request_cache_domain()
        })
        .map(|state| Arc::clone(&state.path_modules))
        .unwrap_or_default();
    ReadAttributionGuard {
        _guard: frame
            .map(|frame| carried_context::push_with_execution_attribution(Arc::new(frame))),
        _request_state: carried_context::push_request_state_with_completion(Some(Arc::new(
            AnalyzerRequestState {
                path_modules,
                context: Some(Arc::clone(context)),
            },
        ))),
    }
}

fn path_module_request_state() -> Option<carried_context::RequestStateGuard> {
    carried_context::request_state::<AnalyzerRequestState>()
        .is_none()
        .then(|| {
            carried_context::push_request_state_with_completion(Some(Arc::new(
                AnalyzerRequestState {
                    path_modules: Arc::new(PathModuleRequestFailures::default()),
                    context: None,
                },
            )))
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

/// A public site result exposes positions even when its semantic read is ranked.
/// Keep the source identity as a separate dependency for such consumers.
#[doc(hidden)]
pub fn record_position_read(analyzer: &dyn IAnalyzer, file: &ProjectFile) {
    if !read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return;
    }
    match analyzer.indexed_blob_oid(file) {
        Some(blob) => {
            if let Some(variant) = analyzer.selected_parse_variant(file) {
                analyzer.record_read(crate::analyzer::read_ledger::ReadKey::file(
                    crate::analyzer::common::language_for_file(file),
                    crate::path_utils::rel_path_string(file),
                    blob,
                    variant,
                ));
            }
        }
        None => analyzer.record_unattributed_read(),
    }
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
    owns_outer_request: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct IncompatibleSelectedModelSnapshot;

impl<'a> AnalyzerQueryScope<'a> {
    fn with_context(analyzer: &'a dyn IAnalyzer, mut context: AnalyzerQueryContext) -> Self {
        if context.host_activation_override.is_none() {
            let host = context
                .active_semantic_model_snapshot_override
                .as_ref()
                .and_then(|(_, snapshot)| snapshot.as_ref())
                .map(|snapshot| Arc::clone(snapshot.active_models().host_activation()))
                .or_else(|| analyzer.host_activation_context());
            context.host_activation_override = Some((std::thread::current().id(), host));
        }
        if context.semantic_models_selected.is_none()
            && (context.semantic_model_overlay_override.is_some()
                || context.active_semantic_model_snapshot_override.is_some())
        {
            context.semantic_models_selected = Some(!matches!(
                effective_semantic_model_overlay(analyzer),
                crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead::NotSelected
            ));
        }
        let request_state = path_module_request_state();
        let owns_outer_request = context.enclosing.is_none();
        let context = Arc::new(context);
        let attribution = Some(query_attribution(&context));
        analyzer.begin_query(&context);
        Self {
            analyzer,
            context,
            attribution,
            _request_state: request_state,
            owns_outer_request,
        }
    }

    /// Start a policy run in its existing selected-model scope with a fresh request.
    #[doc(hidden)]
    pub fn with_new_outer_request_and_active_semantic_model_snapshot(
        analyzer: &'a dyn IAnalyzer,
        snapshot: Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    ) -> Self {
        let context = AnalyzerQueryContext::with_active_semantic_model_snapshot(snapshot);
        let mut scope = Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                outer_request: OuterRequest::new(),
                ..context
            },
        );
        scope.owns_outer_request = true;
        scope
    }

    /// Attach a policy worker to the enclosing run's request on this thread.
    #[doc(hidden)]
    pub fn with_outer_request(analyzer: &'a dyn IAnalyzer, request: Arc<OuterRequest>) -> Self {
        let mut scope = Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                outer_request: request,
                ..Default::default()
            },
        );
        scope.owns_outer_request = false;
        scope
    }

    /// Keep execution reasons local while retaining store errors for request finish.
    pub fn for_policy_evaluation(analyzer: &'a dyn IAnalyzer) -> Self {
        let scope = Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                completion_boundary: Some(QueryCompletionBoundary::PolicyEvaluation),
                ..Default::default()
            },
        );
        // Preparation failures remain on their original contexts. Forward the
        // shared records to the policy owner without acknowledgment authority.
        let policy = PolicyCompletionOwner::current();
        let domain = scope.context.request_cache_domain();
        let mut seen = std::collections::HashSet::new();
        for context in request_domain_contexts(scope.context.enclosing.clone())
            .take_while(|context| context.request_cache_domain() == domain)
        {
            for error in context.recorded_store_errors() {
                if error.inherited_by(policy.as_deref()) && seen.insert(error.id()) {
                    PolicyCompletionOwner::record(&error);
                }
            }
        }
        scope
    }

    pub fn outer_request(&self) -> Arc<OuterRequest> {
        Arc::clone(&self.context.outer_request)
    }

    /// Retained fills share request memos isolated from the ordinary request domain.
    #[doc(hidden)]
    pub fn for_retained_fill(analyzer: &'a dyn IAnalyzer) -> Self {
        static NEXT_DOMAIN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut context = AnalyzerQueryContext::default();
        context.fill_local_memos = Some(FillLocalMemos::default());
        context.request_cache_domain = Some(
            context
                .retained_fill_domain
                .get_or_init(|| {
                    let id = NEXT_DOMAIN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    assert_ne!(id, 0, "request cache domain identity exhausted");
                    Arc::new(RequestCacheDomain {
                        id,
                        registries: Mutex::new(Vec::new()),
                    })
                })
                .clone(),
        );
        Self::with_context(analyzer, context)
    }

    pub fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(analyzer, AnalyzerQueryContext::default())
    }

    /// Start an independently reported row with fresh completion. Failures still
    /// propagate to enclosing scopes and ledgers, refusing whole-request reuse.
    #[doc(hidden)]
    pub fn independent_answer(
        analyzer: &'a dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                cancellation: cancellation.cloned(),
                completion_boundary: Some(QueryCompletionBoundary::IndependentAnswer),
                ..Default::default()
            },
        )
    }

    /// Capture every distinct incomplete-read reason for a file-derived cache
    /// admission. Ordinary scopes retain only the canonical representative.
    #[doc(hidden)]
    pub fn capturing_read_incompleteness(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                completion: Mutex::new(QueryCompletion::capturing()),
                ..Default::default()
            },
        )
    }

    /// Capture one language proof using the normal query completion channel.
    #[doc(hidden)]
    pub fn capturing_proof_completion(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                completion: Mutex::new(QueryCompletion {
                    proof_attempt: true,
                    ..QueryCompletion::capturing()
                }),
                ..Default::default()
            },
        )
    }

    /// Internal cross-crate seam for inspecting an optional relation while retaining
    /// its reads in the enclosing receipt. Do not use for ordinary query work.
    /// A failed inspection makes the probe undecided, not the enclosing query incomplete.
    #[doc(hidden)]
    pub fn for_advisory_read(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                completion: Mutex::new(QueryCompletion::capturing()),
                completion_boundary: Some(QueryCompletionBoundary::AdvisoryRead),

                ..Default::default()
            },
        )
    }

    /// Capture completion for one independently reported answer or policy
    /// selector candidate (#10985, #11089).
    /// Stable content gaps stop here. Execution failures and store errors still
    /// reach the selector. This boundary never shadows read-ledger channels:
    /// reads, unattributed crossings and reuse refusals remain dependencies of
    /// the enclosing selector. Receipt replay records completion in this active
    /// candidate, rather than retaining the identity of its original consumer.
    /// Policy selector classification and independently scoped answers may open
    /// this boundary; provider products must not be computed under it without
    /// reviewing their identity.
    #[doc(hidden)]
    pub fn capturing_candidate_classification(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                completion: Mutex::new(QueryCompletion::capturing()),
                completion_boundary: Some(QueryCompletionBoundary::CandidateClassification),
                ..Default::default()
            },
        )
    }

    /// Mark the read capture for a taint Output unit and its nested queries.
    #[doc(hidden)]
    pub fn capturing_taint_output_receipt(analyzer: &'a dyn IAnalyzer) -> Self {
        Self::with_context(
            analyzer,
            AnalyzerQueryContext {
                completion: Mutex::new(QueryCompletion::capturing()),
                taint_output_receipt_capture: true,
                ..Default::default()
            },
        )
    }

    #[doc(hidden)]
    pub fn is_taint_output_receipt_capture_active() -> bool {
        current_query_context().is_some_and(|context| context.taint_output_receipt_capture)
    }

    /// Reasons observed by a scope opened with `capturing_read_incompleteness`.
    #[doc(hidden)]
    pub fn runtime_cache_touched(&self) -> bool {
        self.context
            .read_ledger
            .as_ref()
            .is_some_and(|ledger| ledger.runtime_cache_touched())
    }

    pub fn captured_read_incompleteness(&self) -> Vec<QueryReadIncomplete> {
        self.captured_causes()
            .iter()
            .map(|cause| cause.reason().clone())
            .collect()
    }

    /// The captured causes in canonical presentation order, sharing each
    /// cause's interned keys with every receipt and replay that holds it.
    #[doc(hidden)]
    pub fn captured_causes(&self) -> Vec<Arc<CapturedCause>> {
        let mut causes = self
            .context
            .lock_completion()
            .captured
            .as_ref()
            .expect("only a capturing scope can enumerate read incompleteness")
            .items
            .clone();
        causes.sort_by(|left, right| left.order_key().cmp(right.order_key()));
        causes
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

    /// Own an internal request even when invoked inside a caller's query.
    #[doc(hidden)]
    pub fn with_new_outer_request_and_cancellation(
        analyzer: &'a dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Self {
        let mut context = AnalyzerQueryContext::with_cancellation(cancellation.clone());
        context.outer_request = OuterRequest::new();
        let mut scope = Self::with_context(analyzer, context);
        scope.owns_outer_request = true;
        scope
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

    /// Transport the complete effective overlay state into a worker scope.
    pub(crate) fn with_frozen_semantic_model_overlay(
        analyzer: &'a dyn IAnalyzer,
        read: crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead,
    ) -> Self {
        use crate::analyzer::semantic_model::runtime::SemanticModelOverlayRead;
        let (overlay, selected) = match read {
            SemanticModelOverlayRead::Published(overlay) => (Some(overlay), true),
            SemanticModelOverlayRead::Pending(_) => (None, true),
            SemanticModelOverlayRead::NotSelected => (None, false),
        };
        let mut context = AnalyzerQueryContext::with_semantic_model_overlay(overlay);
        context.semantic_models_selected = Some(selected);
        Self::with_context(analyzer, context)
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

    /// Pin a selected point answer to the current publication without recording a read.
    /// An incompatible outer overlay is a stale request, not permission to replace it.
    pub fn pin_selected_model_snapshot(
        analyzer: &'a dyn IAnalyzer,
    ) -> Result<Option<Self>, IncompatibleSelectedModelSnapshot> {
        if analyzer.active_query_semantic_model_snapshot().is_some() {
            return Ok(None);
        }
        let snapshot = analyzer
            .snapshot_caches()
            .and_then(AnalyzerSnapshotCaches::active_semantic_model_snapshot);
        Self::with_compatible_selected_model_snapshot(analyzer, snapshot)
    }

    pub fn with_compatible_selected_model_snapshot(
        analyzer: &'a dyn IAnalyzer,
        snapshot: Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    ) -> Result<Option<Self>, IncompatibleSelectedModelSnapshot> {
        if let Some(outer) = analyzer.active_query_semantic_model_snapshot() {
            let compatible = match (outer.as_ref(), snapshot.as_ref()) {
                (None, None) => true,
                (Some(outer), Some(snapshot)) => Arc::ptr_eq(outer, snapshot),
                _ => false,
            };
            return compatible
                .then_some(None)
                .ok_or(IncompatibleSelectedModelSnapshot);
        }
        if let Some(outer) = analyzer.active_query_semantic_model_overlay() {
            let selected = snapshot
                .as_ref()
                .and_then(|value| value.semantic_model_overlay());
            let compatible = match (outer.as_ref(), selected) {
                (None, None) => true,
                (Some(outer), Some(selected)) => Arc::ptr_eq(outer, selected),
                _ => false,
            };
            if !compatible {
                return Err(IncompatibleSelectedModelSnapshot);
            }
        }
        Ok(Some(Self::with_active_semantic_model_snapshot(
            analyzer, snapshot,
        )))
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

    /// The policy unit label is diagnostic context for query-local timing notes.
    pub fn with_policy_unit_read_ledger(
        analyzer: &'a dyn IAnalyzer,
        ledger: Arc<crate::analyzer::read_ledger::ReadLedger>,
        label: String,
    ) -> Self {
        let mut context = AnalyzerQueryContext::with_read_ledger(ledger);
        context.policy_unit_label = Some(label.into());
        Self::with_context(analyzer, context)
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

    /// The original operational failure under this scope's completion owner.
    /// Includes independent answers in the same evaluation, without crossing
    /// policy, advisory-read or outer-request completion boundaries.
    #[doc(hidden)]
    pub fn request_store_error(&self) -> Option<StoreError> {
        self.context.request_store_error()
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
        if self.owns_outer_request {
            self.context.outer_request.close();
        }
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
    let _refusal = brokk_bifrost_core::profiling::read_refusal_scope(if captured.reuse_refused() {
        captured.first_refusal()
    } else {
        captured.first_execution_refusal()
    });
    enclosing.mark_execution_dependent_reads(captured.unpinned_execution_dependences());
    enclosing.record_budget_dependences(captured.budget_dependences());
    enclosing.mark_request_pinned_dependences(captured.request_pinned_dependences());
    enclosing.join_verdict(captured.explicit_verdict());
    if captured.runtime_cache_touched() {
        enclosing.mark_runtime_cache_touched();
    }
    if captured.reuse_refused() {
        enclosing.refuse_read_reuse();
    }
    if captured.store_failed() {
        enclosing.record_store_failure();
    }
    enclosing.record_persistence_refusals(captured.persistence_refusals());
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
            let owns_outer_request = context.enclosing.is_none();
            AnalyzerQueryScope {
                analyzer,
                context,
                attribution: None,
                _request_state: path_module_request_state(),
                owns_outer_request,
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
    let context = match enclosing {
        Some(enclosing) => AnalyzerQueryContext::with_nested_read_ledger(
            Arc::clone(&captured),
            Arc::clone(enclosing),
        ),
        None => AnalyzerQueryContext::with_read_ledger(Arc::clone(&captured)),
    };
    let result = capture_registered_reads(Arc::new(context), register, query);
    (result, captured)
}

/// Internal memo partition: isolate channel writes while preserving completion
/// observations during the walk. Completion is forwarded without ledger marks
/// after the private context closes; the memo later forwards its channels once.
pub(super) fn capture_memo_partition_with_registration<T, G>(
    enclosing: Option<&Arc<crate::analyzer::ReadLedger>>,
    register: impl FnOnce(Arc<AnalyzerQueryContext>) -> G,
    query: impl FnOnce() -> T,
) -> (T, Arc<crate::analyzer::ReadLedger>) {
    let captured = Arc::new(crate::analyzer::ReadLedger::new());
    let mut context = match enclosing {
        Some(enclosing) => AnalyzerQueryContext::with_nested_read_ledger(
            Arc::clone(&captured),
            Arc::clone(enclosing),
        ),
        None => AnalyzerQueryContext::with_read_ledger(Arc::clone(&captured)),
    };
    context.completion = Mutex::new(QueryCompletion::capturing());
    context.completion_boundary = Some(QueryCompletionBoundary::AdvisoryRead);
    let context = Arc::new(context);
    let result = capture_registered_reads(Arc::clone(&context), register, query);
    let causes = context
        .lock_completion()
        .captured
        .as_ref()
        .expect("a memo partition captures completion")
        .items
        .clone();
    crate::analyzer::common::replay_captured_causes(&causes);
    (result, captured)
}

pub(super) fn capture_memo_partition<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> T,
) -> (T, Arc<crate::analyzer::ReadLedger>) {
    let enclosing = analyzer.current_thread_read_ledger();
    capture_memo_partition_with_registration(
        enclosing.as_ref(),
        |context| {
            analyzer.begin_query(&context);
            let owns_outer_request = context.enclosing.is_none();
            AnalyzerQueryScope {
                analyzer,
                context,
                attribution: None,
                _request_state: path_module_request_state(),
                owns_outer_request,
            }
        },
        query,
    )
}

fn capture_registered_reads<T, G>(
    context: Arc<AnalyzerQueryContext>,
    register: impl FnOnce(Arc<AnalyzerQueryContext>) -> G,
    query: impl FnOnce() -> T,
) -> T {
    let _attribution = query_attribution(&context);
    let _registration = register(Arc::clone(&context));
    query()
}

/// Capture catalog composition without requiring an analyzer handle. The
/// transported query context remains the owner of completion and attribution.
pub(crate) fn capture_current_query_reads<T>(
    query: impl FnOnce() -> T,
) -> (
    T,
    Arc<crate::analyzer::ReadLedger>,
    Vec<QueryReadIncomplete>,
) {
    let enclosing = current_thread_read_ledger();
    let context = std::cell::OnceCell::new();
    let (result, reads) = capture_with_read_registration(
        enclosing.as_ref(),
        |registered| {
            *registered.lock_completion() = QueryCompletion::capturing();
            context.set(registered).expect("one capture registration");
        },
        query,
    );
    let mut causes = context
        .get()
        .expect("registered capture")
        .lock_completion()
        .captured
        .as_ref()
        .expect("capturing completion")
        .items
        .clone();
    causes.sort_by(|left, right| left.order_key().cmp(right.order_key()));
    let reasons = causes.iter().map(|cause| cause.reason().clone()).collect();
    (result, reads, reasons)
}

/// Replay all dependencies of a completed query into its current caller.
#[doc(hidden)]
pub fn replay_query_reads(analyzer: &dyn IAnalyzer, reads: &crate::analyzer::ReadLedger) {
    let _refusal = brokk_bifrost_core::profiling::read_refusal_scope(reads.first_refusal());
    let _execution_refusal = brokk_bifrost_core::profiling::read_execution_refusal_scope(
        reads.first_execution_refusal(),
    );
    if reads.runtime_cache_touched() {
        analyzer.mark_runtime_cache_touched();
    }
    analyzer.record_read_capture(reads);
    replay_query_read_receipt(analyzer, [], reads.channels());
}

/// Replay an immutable memo receipt without reinserting its keys per consumer.
#[doc(hidden)]
pub fn replay_shared_query_read_receipt(
    analyzer: &dyn IAnalyzer,
    keys: &Arc<[crate::analyzer::ReadKey]>,
    channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
) {
    analyzer.record_read_receipt(keys);
    replay_query_read_receipt(analyzer, [], channels);
}

/// Replay an owned snapshot of a query's named reads and refusal channels.
/// Named keys are sets in each ledger; refusal crossings are counts and
/// must be replayed only for a consumer, never again after its own capture.
#[doc(hidden)]
pub fn replay_query_read_keys(
    analyzer: &dyn IAnalyzer,
    keys: impl IntoIterator<Item = crate::analyzer::ReadKey>,
    unattributed_reads: usize,
    persistence_refusals: usize,
) {
    replay_query_read_receipt(
        analyzer,
        keys,
        brokk_bifrost_core::analyzer::memo_attribution::ReadChannels {
            unattributed_reads,
            persistence_refusals,
            ..Default::default()
        },
    );
}

/// Replay all three dependency channels from an owned receipt.
pub fn replay_query_read_receipt(
    analyzer: &dyn IAnalyzer,
    keys: impl IntoIterator<Item = crate::analyzer::ReadKey>,
    channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
) {
    replay_read_channels(
        keys,
        channels,
        |key| analyzer.record_read(key),
        |count| analyzer.record_unattributed_reads(count),
        |count| analyzer.mark_execution_dependent_reads(count),
        |record, count| analyzer.record_attributed_dependences(record, count),
        |verdict| analyzer.join_reuse_verdict(verdict),
        || analyzer.refuse_read_reuse(),
        || record_store_failure(analyzer),
        |count| record_persistence_refusals(analyzer, count),
    );
}

/// Record a store failure on every unshadowed consumer of this read, with the
/// reuse refusal it implies (#11534).
pub fn record_store_failure(analyzer: &dyn IAnalyzer) {
    if !read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return;
    }
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        analyzer.read_ledger_contexts()
    };
    for_each_unshadowed_active_ledger(&contexts, |ledger| ledger.record_store_failure());
}

/// Record a persistence refusal on every unshadowed consumer of this read.
pub fn record_persistence_refusals(analyzer: &dyn IAnalyzer, count: usize) {
    if count == 0 || !read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return;
    }
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        analyzer.read_ledger_contexts()
    };
    for_each_unshadowed_active_ledger(&contexts, |ledger| {
        ledger.record_persistence_refusals(count)
    });
}

#[allow(clippy::too_many_arguments)] // One sink per read channel; callers pass their own ledger's recorders.
pub(super) fn replay_read_channels(
    keys: impl IntoIterator<Item = crate::analyzer::ReadKey>,
    channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
    mut record: impl FnMut(crate::analyzer::ReadKey),
    mut unattributed: impl FnMut(usize),
    mut execution_dependent: impl FnMut(usize),
    mut attributed: impl FnMut(AttributeDependences, usize),
    mut join_verdict: impl FnMut(brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict),
    mut refuse: impl FnMut(),
    mut store_failure: impl FnMut(),
    mut refuse_persistence: impl FnMut(usize),
) {
    for key in keys {
        record(key);
    }
    if channels.unattributed_reads > 0 {
        unattributed(channels.unattributed_reads);
    }
    // Request-pinned dependences are marked with their own cause, so the
    // carried evaluation verdict does not degrade them to `Other`.
    if channels.unpinned_execution_dependences() > 0 {
        execution_dependent(channels.unpinned_execution_dependences());
    }
    if channels.budget_dependences > 0 {
        attributed(
            crate::analyzer::ReadLedger::record_budget_dependences,
            channels.budget_dependences,
        );
    }
    if channels.request_pinned_dependences > 0 {
        attributed(
            crate::analyzer::ReadLedger::mark_request_pinned_dependences,
            channels.request_pinned_dependences,
        );
    }
    if !channels.explicit_verdict.is_content() {
        join_verdict(channels.explicit_verdict);
    }
    if channels.reuse_refused {
        refuse();
    }
    if channels.store_failed {
        store_failure();
    }
    if channels.persistence_refusals > 0 {
        refuse_persistence(channels.persistence_refusals);
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

/// [`capture_query_reads`] for a query that returns its reuse verdict. The
/// verdict joins the captured ledger before it is forwarded to the enclosing
/// capture.
pub fn capture_query_reads_judged<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> (T, brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict),
) -> (T, Arc<crate::analyzer::read_ledger::ReadLedger>) {
    let enclosing = analyzer.current_thread_read_ledger();
    let ((result, verdict), captured) =
        capture_with_read_ledger_scope(analyzer, enclosing.as_ref(), query);
    captured.join_verdict(verdict);
    if let Some(enclosing) = enclosing {
        forward_captured_query_reads(&enclosing, &captured);
    }
    (result, captured)
}

/// Mark the current capture execution dependent through the ambient channel
/// and return the matching explicit verdict, so a producer dual-writes both
/// until the ambient channel is retired.
#[track_caller]
pub fn execution_dependent(
    analyzer: &(impl IAnalyzer + ?Sized),
) -> brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict {
    analyzer.mark_execution_dependent();
    brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
        brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
    )
}

/// [`execution_dependent`] for a producer whose result cannot carry a verdict
/// (a shared cached product, or a hook result another crate reads): the
/// verdict joins the current captures, where the ambient mark went.
#[track_caller]
pub fn join_execution_dependence(analyzer: &(impl IAnalyzer + ?Sized)) {
    let verdict = execution_dependent(analyzer);
    analyzer.join_reuse_verdict(verdict);
}

/// Capture one partition of a larger query without forwarding it into the
/// immediate enclosing capture. The caller must replay the returned receipt
/// into the whole-query ledger after its shared capture has closed.
#[doc(hidden)]
pub fn capture_query_reads_deferred<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> T,
) -> (T, Arc<crate::analyzer::read_ledger::ReadLedger>) {
    let enclosing = analyzer.current_thread_read_ledger();
    capture_with_read_ledger_scope(analyzer, enclosing.as_ref(), query)
}

/// Read dependencies and incomplete reasons produced by one query-local read.
#[doc(hidden)]
#[derive(Clone)]
pub struct QueryReadReceipt {
    reads: QueryReceiptReads,
    incomplete: Vec<QueryReadIncomplete>,
}

#[derive(Clone)]
enum QueryReceiptReads {
    Captured(Arc<crate::analyzer::ReadLedger>),
    Retained(Box<RetainedQueryReads>),
}

struct RetainedQueryReads {
    reads:
        brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<crate::analyzer::ReadKey>,
    digest: crate::analyzer::read_ledger::ReadSetDigest,
}

impl Clone for RetainedQueryReads {
    fn clone(&self) -> Self {
        Self {
            reads: brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads {
                runtime_cache_touched: self.reads.runtime_cache_touched,
                keys: Arc::clone(&self.reads.keys),
                channels: self.reads.channels,
                first_refusal: self.reads.first_refusal.clone(),
                first_execution_refusal: self.reads.first_execution_refusal.clone(),
            },
            digest: self.digest,
        }
    }
}

impl std::fmt::Debug for QueryReadReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryReadReceipt")
            .field("incomplete", &self.incomplete)
            .finish_non_exhaustive()
    }
}

impl QueryReadReceipt {
    /// Census owned heaps, excluding this receipt's inline value/Arc header.
    /// Shared ledgers and project paths are counted once in the caller's walk.
    #[doc(hidden)]
    pub fn retained_heap(&self, heap: &mut crate::analyzer::store::cache_budget::RetainedHeap) {
        use crate::analyzer::store::cache_budget::RetainedHeap;

        fn retained_file(file: &ProjectFile, heap: &mut RetainedHeap) {
            let (owner, root, path_capacity) = file.retained_parts();
            heap.arc(owner, |_, heap| {
                heap.add_allocation(path_capacity);
                heap.arc(root, |_, _| {});
            });
        }

        fn retained_plain_reason(reason: &QueryReadIncomplete, heap: &mut RetainedHeap) {
            match reason {
                QueryReadIncomplete::Attributed(_) => {
                    unreachable!("lookup provenance rejects nested annotations")
                }
                QueryReadIncomplete::Cancelled
                | QueryReadIncomplete::InternalInvariant(_)
                | QueryReadIncomplete::SemanticModelsPending
                | QueryReadIncomplete::ProofStopped {
                    reason: _,
                    cause: _,
                } => {}
                QueryReadIncomplete::StructureUnavailable(file) => retained_file(file, heap),
                QueryReadIncomplete::SemanticEvidenceUnavailable(reason)
                | QueryReadIncomplete::ArtifactUnavailable(reason)
                | QueryReadIncomplete::SemanticEvidenceGap(reason) => {
                    heap.add_allocation(reason.len())
                }
                QueryReadIncomplete::StoreFailure(error) => {
                    heap.add_allocation(error.retained_message_capacity());
                }
            }
        }

        match &self.reads {
            QueryReceiptReads::Captured(reads) => {
                heap.arc(reads, |reads, heap| reads.retained_heap(heap));
            }
            QueryReceiptReads::Retained(retained) => {
                heap.add(std::mem::size_of::<RetainedQueryReads>());
                heap.arc(&retained.reads.keys, |keys, heap| {
                    heap.add_entries(keys.len());
                    for key in keys {
                        crate::analyzer::store::cache_budget::retained_read_key(heap, key);
                    }
                });
                for refusal in [
                    &retained.reads.first_refusal,
                    &retained.reads.first_execution_refusal,
                ]
                .into_iter()
                .flatten()
                {
                    heap.add_allocation(refusal.reason.capacity());
                }
            }
        }
        heap.vec(&self.incomplete);
        for reason in &self.incomplete {
            match reason {
                QueryReadIncomplete::Attributed(shared) => {
                    heap.arc(shared, |data, heap| {
                        let QueryLookupProvenance {
                            file,
                            byte_span: _,
                            name,
                            tier: _,
                        } = data.lookup();
                        retained_file(file, heap);
                        heap.add_allocation(name.len());
                        // The constructor forbids nested annotations. Charge its
                        // one cause while the attribution still owns the census.
                        retained_plain_reason(data.cause(), heap);
                    });
                }
                _ => retained_plain_reason(reason, heap),
            }
        }
    }

    /// Run `read` and record every read key and incomplete reason it causes.
    pub fn capture<T>(analyzer: &dyn IAnalyzer, read: impl FnOnce() -> T) -> (T, Self) {
        let ((result, incomplete), reads) = capture_query_reads(analyzer, || {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            let result = read();
            (result, scope.captured_read_incompleteness())
        });
        (
            result,
            Self {
                reads: QueryReceiptReads::Captured(reads),
                incomplete,
            },
        )
    }

    /// Capture one component without publishing its reads or incompleteness.
    /// The consumer replays only components that decide its answer.
    pub fn capture_deferred<T>(analyzer: &dyn IAnalyzer, read: impl FnOnce() -> T) -> (T, Self) {
        // The deferred ledger must be INSIDE its completion boundary: a
        // Provider/store cause marks that ledger before the advisory boundary
        // stops propagation to the parent. Its channels are then authoritative.
        let scope = AnalyzerQueryScope::for_advisory_read(analyzer);
        let (result, reads) = capture_query_reads_deferred(analyzer, read);
        let incomplete = scope.captured_read_incompleteness();
        (
            result,
            Self {
                reads: QueryReceiptReads::Captured(reads),
                incomplete,
            },
        )
    }

    /// Append a deferred component without publishing it to an enclosing query.
    #[doc(hidden)]
    pub fn extend(&mut self, component: &Self) {
        // Deferred receipts are combined while the request runs; only a
        // selected memo entry's retain_root makes a receipt Retained, later.
        let (QueryReceiptReads::Captured(enclosing), QueryReceiptReads::Captured(captured)) =
            (&self.reads, &component.reads)
        else {
            unreachable!("deferred receipts are extended before any retain_root")
        };
        forward_captured_query_reads(enclosing, captured);
        for reason in &component.incomplete {
            if !self.incomplete.contains(reason) {
                self.incomplete.push(reason.clone());
            }
        }
        self.incomplete
            .sort_by_cached_key(QueryReadIncomplete::answer_order_key);
    }

    /// Replay the captured read keys and incomplete reasons into the current query.
    pub fn replay(&self, analyzer: &dyn IAnalyzer) {
        match &self.reads {
            QueryReceiptReads::Captured(reads) => replay_query_reads(analyzer, reads),
            QueryReceiptReads::Retained(retained) => {
                let reads = &retained.reads;
                let _refusal =
                    brokk_bifrost_core::profiling::read_refusal_scope(reads.first_refusal.clone());
                let _execution_refusal =
                    brokk_bifrost_core::profiling::read_execution_refusal_scope(
                        reads.first_execution_refusal.clone(),
                    );
                if reads.runtime_cache_touched {
                    analyzer.mark_runtime_cache_touched();
                }
                replay_shared_query_read_receipt(analyzer, &reads.keys, reads.channels);
            }
        }
        for reason in &self.incomplete {
            replay_captured_query_incomplete(reason.clone());
        }
    }

    /// Owned storage a retained receipt keeps alive: its read set, with the
    /// canonical publication a later replay may memoize, and its reasons.
    pub fn retained_bytes(&self) -> usize {
        let reads_bytes = match &self.reads {
            QueryReceiptReads::Captured(reads) => reads.retained_snapshot_bytes(),
            QueryReceiptReads::Retained(_) => {
                let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::default();
                self.retained_heap(&mut heap);
                return std::mem::size_of::<Self>().saturating_add(heap.bytes());
            }
        };
        std::mem::size_of::<Self>()
            + reads_bytes
            + self.incomplete.capacity() * std::mem::size_of::<QueryReadIncomplete>()
            + self
                .incomplete
                .iter()
                .map(QueryReadIncomplete::retained_payload_bytes)
                .sum::<usize>()
    }

    /// Whether this capture has no incomplete reasons and only bounded reads.
    pub(crate) fn reusable(&self) -> bool {
        self.incomplete.is_empty()
            && match &self.reads {
                QueryReceiptReads::Captured(reads) => reads.is_bounded(),
                QueryReceiptReads::Retained(retained) => retained.reads.channels.is_bounded(),
            }
    }

    /// Inspect the named inputs of a bounded, complete receipt without replay.
    /// Captured DAGs use the ledger's existing temporary uniqueness walk;
    /// retained receipts borrow their immutable canonical keys directly.
    pub(crate) fn keys_satisfy(
        &self,
        mut predicate: impl FnMut(&crate::analyzer::ReadKey) -> bool,
    ) -> bool {
        self.reusable()
            && match &self.reads {
                QueryReceiptReads::Captured(reads) => reads.keys_satisfy(predicate),
                QueryReceiptReads::Retained(retained) => {
                    retained.reads.keys.iter().all(&mut predicate)
                }
            }
    }

    /// True when two receipts share the same captured input set.
    pub fn shares_capture_with(&self, other: &Self) -> bool {
        match (&self.reads, &other.reads) {
            (QueryReceiptReads::Captured(left), QueryReceiptReads::Captured(right)) => {
                Arc::ptr_eq(left, right)
            }
            (QueryReceiptReads::Retained(left), QueryReceiptReads::Retained(right)) => {
                Arc::ptr_eq(&left.reads.keys, &right.reads.keys)
            }
            _ => false,
        }
    }

    /// Every captured completion reason, in canonical presentation order. Setup
    /// consumers must inspect the whole receipt, including zero-row batches.
    pub fn incomplete_reasons(&self) -> &[QueryReadIncomplete] {
        &self.incomplete
    }

    /// Content identity of the admission inputs, independent of capture order.
    pub fn digest(&self) -> crate::analyzer::read_ledger::ReadSetDigest {
        match &self.reads {
            QueryReceiptReads::Captured(reads) => reads.digest(),
            QueryReceiptReads::Retained(retained) => retained.digest,
        }
    }

    /// Replace a selected entry's capture DAG with its immutable canonical root.
    /// Returns work to charge once at construction, never on replay or census.
    #[doc(hidden)]
    pub fn retain_root(&mut self) -> crate::analyzer::semantic::SemanticWork {
        let QueryReceiptReads::Captured(captured) = &self.reads else {
            return crate::analyzer::semantic::SemanticWork::default();
        };
        let (keys, gather_work) = captured.unordered_keys_with_work();
        let (keys, digest, canonical_work) =
            brokk_bifrost_store::analyzer::read_ledger::retained_read_set(keys);
        let reads = brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads {
            runtime_cache_touched: captured.runtime_cache_touched(),
            keys,
            channels: captured.channels(),
            first_refusal: captured.first_refusal(),
            first_execution_refusal: captured.first_execution_refusal(),
        };
        self.reads = QueryReceiptReads::Retained(Box::new(RetainedQueryReads { reads, digest }));
        crate::analyzer::semantic::SemanticWork {
            nested_entries: gather_work.saturating_add(canonical_work),
            ..Default::default()
        }
    }
}

/// Apply the selected descendant scope without changing open evidence.
#[doc(hidden)]
pub fn scope_filter_descendant_answer(
    mut answer: brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer,
    scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
) -> std::result::Result<
    brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer,
    brokk_bifrost_core::analyzer::capabilities::Cancelled,
> {
    use brokk_bifrost_core::analyzer::capabilities::Cancelled;
    if scope.cancellation().is_cancelled() {
        return Err(Cancelled);
    }
    let mut unavailable = false;
    let mut admits = |unit: &CodeUnit| match scope.admits(unit) {
        Ok(admitted) => admitted,
        Err(_) => {
            unavailable = true;
            false
        }
    };
    answer.edges.retain(&mut admits);
    for group in &mut answer.ambiguous {
        group.retain(&mut admits);
    }
    if unavailable {
        answer.open.push(
            brokk_bifrost_core::analyzer::capabilities::HierarchyOpenReason::DescendantIndexUnavailable,
        );
    }
    answer.ambiguous.retain(|group| !group.is_empty());
    if scope.cancellation().is_cancelled() {
        return Err(Cancelled);
    }
    Ok(answer)
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
    (result, reads.channels.unattributed_reads)
}

/// Retain the unsubsumable channels for an authority that can be read again.
pub fn capture_subsumed_query_read_receipt<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> T,
) -> (
    T,
    brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<crate::analyzer::ReadKey>,
) {
    capture_subsumed_query_read_receipt_judged(analyzer, || {
        (
            query(),
            brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
        )
    })
}

/// [`capture_subsumed_query_read_receipt`] for a query that returns its reuse
/// verdict; the verdict joins the receipt's channels.
pub fn capture_subsumed_query_read_receipt_judged<T>(
    analyzer: &dyn IAnalyzer,
    query: impl FnOnce() -> (T, brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict),
) -> (
    T,
    brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<crate::analyzer::ReadKey>,
) {
    let enclosing = analyzer.current_thread_read_ledger();
    let ((result, verdict), captured) =
        capture_with_read_ledger_scope(analyzer, enclosing.as_ref(), query);
    captured.join_verdict(verdict);
    let reads = brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads {
        runtime_cache_touched: captured.runtime_cache_touched(),
        keys: Arc::from([]),
        channels: captured.channels(),
        first_refusal: captured.first_refusal(),
        first_execution_refusal: captured.first_execution_refusal(),
    };
    if let Some(enclosing) = enclosing {
        if reads.runtime_cache_touched {
            enclosing.mark_runtime_cache_touched();
        }
        let _refusal =
            brokk_bifrost_core::profiling::read_refusal_scope(reads.first_refusal.clone());
        let _execution_refusal = brokk_bifrost_core::profiling::read_execution_refusal_scope(
            reads.first_execution_refusal.clone(),
        );
        replay_read_channels(
            [],
            reads.channels,
            |key| enclosing.record(key),
            |count| enclosing.record_unattributed_reads(count),
            |count| enclosing.mark_execution_dependent_reads(count),
            |record, count| record(&enclosing, count),
            |verdict| enclosing.join_verdict(verdict),
            || enclosing.refuse_read_reuse(),
            || enclosing.record_store_failure(),
            |count| enclosing.record_persistence_refusals(count),
        );
    }
    (result, reads)
}

pub(crate) fn forward_captured_query_reads(
    enclosing: &crate::analyzer::ReadLedger,
    captured: &crate::analyzer::ReadLedger,
) {
    let _refusal = brokk_bifrost_core::profiling::read_refusal_scope(captured.first_refusal());
    let _execution_refusal = brokk_bifrost_core::profiling::read_execution_refusal_scope(
        captured.first_execution_refusal(),
    );
    enclosing.absorb_capture(captured);
    enclosing.record_unattributed_reads(captured.unattributed_reads());
    enclosing.mark_execution_dependent_reads(captured.unpinned_execution_dependences());
    enclosing.record_budget_dependences(captured.budget_dependences());
    enclosing.mark_request_pinned_dependences(captured.request_pinned_dependences());
    enclosing.join_verdict(captured.explicit_verdict());
    if captured.runtime_cache_touched() {
        enclosing.mark_runtime_cache_touched();
    }
    if captured.reuse_refused() {
        enclosing.refuse_read_reuse();
    }
    if captured.store_failed() {
        enclosing.record_store_failure();
    }
    enclosing.record_persistence_refusals(captured.persistence_refusals());
}

/// Record one funnel key through the current attribution frame. Broadcast
/// visits active contexts except explicitly shadowed enclosing ledgers.
pub(crate) fn record_read_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    key: crate::analyzer::read_ledger::ReadKey,
) {
    crate::analyzer::read_ledger::record_evaluation_selection_read(&key);
    note_read_attribution_fallback(contexts, 1);
    let mut hash = None;
    for_each_unshadowed_active_ledger(contexts, |ledger| ledger.record_borrowed(&key, &mut hash));
}

/// Whether a request ledger frame is active on this thread, opened here or
/// carried from the thread that handed this work over.
pub(crate) fn attribution_ledger_frame_active() -> bool {
    with_attribution_frame(|frame| matches!(frame, Some(AttributionFrame::Ledgers(_))))
}

/// Handle the common request-frame route before consulting analyzer registries.
/// An empty ledger frame still handles the read: it must not fall back to a
/// different request's attached contexts.
pub(crate) fn record_read_on_attribution_frame(key: &crate::analyzer::ReadKey) -> bool {
    crate::analyzer::read_ledger::record_evaluation_selection_read(key);
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
    for key in keys.iter() {
        crate::analyzer::read_ledger::record_evaluation_selection_read(key);
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
    if brokk_bifrost_core::analyzer::carried_context::current_evaluation().is_some() {
        for key in reads.keys() {
            crate::analyzer::read_ledger::record_evaluation_selection_read(&key);
        }
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

pub(super) fn for_each_unshadowed_active_ledger(
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
#[track_caller]
pub(crate) fn record_unattributed_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    count: usize,
) {
    let _refusal = brokk_bifrost_core::profiling::read_refusal_scope(
        brokk_bifrost_core::profiling::current_read_refusal("unattributed"),
    );
    if count == 0 {
        return;
    }
    note_read_attribution_fallback(contexts, count);
    for_each_unshadowed_active_ledger(contexts, |ledger| ledger.record_unattributed_reads(count));
}

/// Admit unattributed reads before acquiring caller-specific fallback contexts.
#[track_caller]
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

#[track_caller]
pub(crate) fn record_reuse_refusal(
    ledger_attached: impl FnOnce() -> bool,
    fallback_contexts: impl FnOnce() -> Vec<Arc<AnalyzerQueryContext>>,
) {
    if !crate::analyzer::read_attribution_records_reads(ledger_attached) {
        return;
    }
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        fallback_contexts()
    };
    for_each_unshadowed_active_ledger(&contexts, |ledger| ledger.refuse_read_reuse());
}

/// Acquire owner contexts only when recording needs a fallback registry.
#[track_caller]
pub(crate) fn record_execution_dependence(
    count: usize,
    ledger_attached: impl FnOnce() -> bool,
    fallback_contexts: impl FnOnce() -> Vec<Arc<AnalyzerQueryContext>>,
) {
    if count == 0 {
        return;
    }
    carried_context::join_evaluation_verdict(
        brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
            brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
        ),
    );
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

/// Runtime-cache evidence uses the same capture routing without altering any
/// persisted read channel or refusing successful product admission.
pub(crate) fn record_runtime_cache_touch(
    ledger_attached: impl FnOnce() -> bool,
    fallback_contexts: impl FnOnce() -> Vec<Arc<AnalyzerQueryContext>>,
) {
    if !crate::analyzer::read_attribution_records_reads(ledger_attached) {
        return;
    }
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        fallback_contexts()
    };
    for_each_unshadowed_active_ledger(&contexts, |ledger| ledger.mark_runtime_cache_touched());
}

/// The ledger method that records one cause's count of execution
/// dependences: [`crate::analyzer::ReadLedger::record_budget_dependences`],
/// which attributes dependences already marked, or
/// [`crate::analyzer::ReadLedger::mark_request_pinned_dependences`], which marks
/// them with their cause.
pub type AttributeDependences = fn(&crate::analyzer::ReadLedger, usize);

/// Record one cause's execution dependences, with the routing of
/// [`record_execution_dependence`].
pub(crate) fn record_attributed_dependence(
    record: AttributeDependences,
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
    record_attributed_dependence_on_active_ledgers(&contexts, record, count);
}

/// Join a replayed explicit verdict, with the routing of
/// [`record_execution_dependence`].
pub(crate) fn record_reuse_verdict(
    verdict: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict,
    ledger_attached: impl FnOnce() -> bool,
    fallback_contexts: impl FnOnce() -> Vec<Arc<AnalyzerQueryContext>>,
) {
    carried_context::join_evaluation_verdict(verdict);
    if verdict.is_content() || !crate::analyzer::read_attribution_records_reads(ledger_attached) {
        return;
    }
    let contexts = if has_read_attribution_ledgers() {
        Vec::new()
    } else {
        fallback_contexts()
    };
    for_each_unshadowed_active_ledger(&contexts, |ledger| ledger.join_verdict(verdict));
}

/// Execution dependence follows the same frame routing as input attribution.
#[track_caller]
pub(crate) fn record_execution_dependence_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    count: usize,
) {
    let _refusal = brokk_bifrost_core::profiling::read_refusal_scope(
        brokk_bifrost_core::profiling::current_read_refusal("execution_dependent"),
    );
    let _execution_refusal = brokk_bifrost_core::profiling::read_execution_refusal_scope(
        brokk_bifrost_core::profiling::current_execution_read_refusal(),
    );
    if count == 0 {
        return;
    }
    carried_context::join_evaluation_verdict(
        brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
            brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
        ),
    );
    note_read_attribution_fallback(contexts, count);
    for_each_unshadowed_active_ledger(contexts, |ledger| {
        ledger.mark_execution_dependent_reads(count)
    });
}

/// Cause attribution follows the same frame routing as the execution
/// dependence it qualifies.
pub(crate) fn record_attributed_dependence_on_active_ledgers(
    contexts: &[Arc<AnalyzerQueryContext>],
    record: AttributeDependences,
    count: usize,
) {
    if count == 0 {
        return;
    }
    for_each_unshadowed_active_ledger(contexts, |ledger| record(ledger, count));
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
    query: &crate::analyzer::usages::QueryResult,
) {
    if !crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return;
    }
    match &query.result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        }
        | FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => {
            for hits in hits_by_overload
                .values()
                .chain(unproven_by_overload.values())
            {
                for hit in hits {
                    crate::analyzer::record_position_read(analyzer, &hit.file);
                }
            }
        }
        _ => {}
    }
    for overload in overloads {
        let Some(digest) = crate::analyzer::usages::reusable_usage_answer_digest(query, overload)
        else {
            analyzer.refuse_read_reuse();
            continue;
        };
        analyzer.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
            crate::analyzer::read_ledger::LookupKind::Usages,
            crate::analyzer::read_ledger::LookupQuestion::declaration(overload),
            digest,
        ));
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
mod host_activation_context_tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        HostActivationContext, VerifiedFirstPartyReleaseInventory,
    };

    #[test]
    fn carried_generation_preserves_host_authority_without_carrying_publication() {
        let before = AnalyzerSnapshotCaches::default();
        let host = HostActivationContext::from_inventory(
            VerifiedFirstPartyReleaseInventory::compiled_default().unwrap(),
            before.retention_budget(),
        )
        .unwrap();
        before
            .bind_host_activation_context(Arc::clone(&host))
            .unwrap();
        let after = before.carry_content_keyed_values_forward();
        let inherited = after
            .host_activation_context()
            .expect("updated snapshot keeps its host");
        assert!(Arc::ptr_eq(&host, &inherited));
        assert_eq!(host.no_model_digest(), inherited.no_model_digest());
        assert_ne!(
            inherited.no_model_digest(),
            crate::analyzer::semantic_model::LIBRARY_NONE_NO_MODEL_DIGEST
        );
        assert!(
            after.active_semantic_model_snapshot().is_none(),
            "host inheritance is independent of a generation's publication"
        );
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

    // Lives beside the analysis-layer recorders it drives; the read ledger
    // itself is in the semantic layer and must not call up into them.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12792: replayed causes double-marked captured execution channels"
    )]
    fn captured_receipt_round_trips_every_cause() {
        use super::{
            IAnalyzer, QueryLookupProvenance, QueryReadIncomplete as Cause, QueryReadReceipt,
            QueryReceiptReads,
        };
        use crate::analyzer::read_ledger::DerivationExecutionCause;
        use crate::analyzer::{MultiAnalyzer, ProjectFile};
        let file = ProjectFile::new(std::env::current_dir().unwrap(), "receipt.rs");
        let mut causes = vec![
            Cause::Cancelled,
            Cause::SemanticModelsPending,
            Cause::StructureUnavailable(file.clone()),
            Cause::SemanticEvidenceUnavailable("missing".into()),
            Cause::ArtifactUnavailable("missing".into()),
            Cause::SemanticEvidenceGap("gap".into()),
            Cause::StoreFailure(crate::analyzer::store::StoreError::new("receipt error")),
            Cause::ProofStopped {
                reason: super::DETERMINISTIC_PROOF_STOP_LABELS[0],
                cause: None,
            },
        ];
        for cause in [
            DerivationExecutionCause::Provider,
            DerivationExecutionCause::Budget,
            DerivationExecutionCause::Cancelled,
            DerivationExecutionCause::Snapshot,
        ] {
            causes.push(Cause::ProofStopped {
                reason: "resolution_open_boundary",
                cause: Some(cause),
            });
        }
        causes.extend(causes.clone().into_iter().map(|cause| {
            cause.attributed(QueryLookupProvenance {
                file: file.clone(),
                byte_span: 2..7,
                name: "value".into(),
                tier: "receipt-test",
            })
        }));
        let fingerprint = |receipt: &QueryReadReceipt| {
            let QueryReceiptReads::Captured(reads) = &receipt.reads else {
                unreachable!()
            };
            (
                reads.canonical_keys(),
                reads.channels(),
                reads.runtime_cache_touched(),
                format!("{:?}", reads.first_refusal()),
                format!("{:?}", reads.first_execution_refusal()),
                receipt.incomplete.clone(),
            )
        };
        let batches = causes
            .iter()
            .cloned()
            .map(|cause| vec![cause])
            .chain(std::iter::once(causes.clone()));
        for causes in batches {
            for deferred in [false, true] {
                let analyzer = MultiAnalyzer::default();
                let capture = |read: &mut dyn FnMut()| {
                    if deferred {
                        QueryReadReceipt::capture_deferred(&analyzer, read)
                    } else {
                        QueryReadReceipt::capture(&analyzer, read)
                    }
                };
                let (_, first) = capture(&mut || {
                    for cause in &causes {
                        analyzer.record_query_incomplete(cause.clone());
                    }
                    analyzer.record_unattributed_reads(2);
                    analyzer.mark_execution_dependent_reads(3);
                    analyzer.record_budget_dependences(1);
                    analyzer.refuse_read_reuse();
                    analyzer.mark_runtime_cache_touched();
                });
                let (_, second) = capture(&mut || first.replay(&analyzer));
                let (_, third) = capture(&mut || second.replay(&analyzer));
                assert_eq!(fingerprint(&first), fingerprint(&second), "{causes:?}");
                assert_eq!(
                    fingerprint(&first),
                    fingerprint(&third),
                    "replay of replay: {causes:?}"
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12792: channel-authoritative replay must preserve completion boundaries and store identities"
    )]
    fn captured_receipt_replay_preserves_boundaries_and_store_identity() {
        use super::{
            AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete as Cause, QueryReadReceipt,
            capture_query_reads,
        };
        use crate::analyzer::{MultiAnalyzer, read_ledger::DerivationExecutionCause};
        type Boundary = for<'a> fn(&'a dyn IAnalyzer) -> AnalyzerQueryScope<'a>;
        let boundaries: [(&str, Boundary); 4] = [
            ("advisory", |analyzer| {
                AnalyzerQueryScope::for_advisory_read(analyzer)
            }),
            ("candidate", |analyzer| {
                AnalyzerQueryScope::capturing_candidate_classification(analyzer)
            }),
            ("policy", |analyzer| {
                AnalyzerQueryScope::for_policy_evaluation(analyzer)
            }),
            ("ordinary", |analyzer| {
                AnalyzerQueryScope::capturing_read_incompleteness(analyzer)
            }),
        ];
        for (name, boundary) in boundaries {
            for cause in [
                Cause::SemanticEvidenceGap("gap".into()),
                Cause::ProofStopped {
                    reason: "resolution_open_boundary",
                    cause: Some(DerivationExecutionCause::Provider),
                },
                Cause::StoreFailure(crate::analyzer::store::StoreError::new("receipt store")),
            ] {
                let run = |replay| {
                    let analyzer = MultiAnalyzer::default();
                    let (_, receipt) = QueryReadReceipt::capture_deferred(&analyzer, || {
                        analyzer.record_query_incomplete(cause.clone())
                    });
                    let owner = Arc::new(super::PolicyCompletionOwner::default());
                    let _owner = owner.install();
                    let parent = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                    let child = boundary(&analyzer);
                    let (_, reads) = capture_query_reads(&analyzer, || {
                        if replay {
                            receipt.replay(&analyzer);
                        } else {
                            analyzer.record_query_incomplete(cause.clone());
                        }
                    });
                    let parent_errors = parent.context.recorded_store_errors();
                    let child_errors = child.context.recorded_store_errors();
                    let owned = owner.errors();
                    for error in &owned {
                        assert!(error.originated_in(&owner));
                        assert!(child_errors.iter().any(|child| child.id() == error.id()));
                    }
                    owner.acknowledge();
                    for error in &owned {
                        assert!(
                            error
                                .0
                                .acknowledged
                                .load(std::sync::atomic::Ordering::Acquire)
                        );
                    }
                    // Identity is shared across eligible ancestors of ONE
                    // replay, and remains fresh for independent replays.
                    let shared = parent_errors
                        .iter()
                        .map(|p| child_errors.iter().any(|c| p.id() == c.id()))
                        .collect::<Vec<_>>();
                    (
                        reads.channels(),
                        format!("{:?}", reads.first_refusal()),
                        format!("{:?}", reads.first_execution_refusal()),
                        owned.len(),
                        parent.captured_read_incompleteness(),
                        child.read_completion(),
                        parent_errors
                            .iter()
                            .map(|e| e.error().clone())
                            .collect::<Vec<_>>(),
                        child_errors
                            .iter()
                            .map(|e| e.error().clone())
                            .collect::<Vec<_>>(),
                        shared,
                    )
                };
                assert_eq!(run(false), run(true), "{name}: {cause:?}");
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12792: receipt replay must preserve the carried execution verdict too"
    )]
    fn captured_receipt_preserves_carried_verdict() {
        use super::{IAnalyzer, QueryReadIncomplete, QueryReadReceipt};
        use crate::analyzer::{MultiAnalyzer, ProjectFile};
        use brokk_bifrost_core::analyzer::carried_context::EvaluationExecution;
        let analyzer = MultiAnalyzer::default();
        let first = Arc::new(EvaluationExecution::default());
        let (receipt, verdict) = {
            let _evaluation = first.install();
            let (_, receipt) = QueryReadReceipt::capture(&analyzer, || {
                analyzer.record_query_incomplete(QueryReadIncomplete::StructureUnavailable(
                    ProjectFile::new(std::env::current_dir().unwrap(), "missing.rs"),
                ))
            });
            (receipt, first.verdict())
        };
        let second = Arc::new(EvaluationExecution::default());
        let _evaluation = second.install();
        receipt.replay(&analyzer);
        assert_eq!(verdict, second.verdict());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11482: selection collection follows declared authority across nested scopes"
    )]
    fn evaluation_selection_reads_follow_authority_declarations() {
        use crate::analyzer::Language;
        use crate::analyzer::read_ledger::{
            EvaluationSelectionReads, FactSubject, LookupKind, LookupQuestion, WorkspaceFactFamily,
        };
        use brokk_bifrost_core::analyzer::carried_context::EvaluationExecution;
        let evaluation = Arc::new(EvaluationExecution::default());
        let _evaluation = evaluation.install();
        let key = ReadKey::Lookup {
            kind: LookupKind::WorkspaceFact,
            question: LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::CSharpCompilationConfiguration,
                language: Language::CSharp,
                subject: FactSubject::Named {
                    name: "configuration".into(),
                },
            },
            digest: StableDigest::from_array([7; 32]),
        };
        let direct = ReadLedger::new();
        direct.record(key.clone());
        let receipt: Arc<[ReadKey]> = Arc::from([key.clone()]);
        direct.absorb_receipt(&receipt);
        let capture = ReadLedger::new();
        capture.record(key.clone());
        direct.absorb_capture(&capture);
        // Replaying already-deduplicated inputs into a fresh evaluation must
        // collect the evidence before the ordinary ledger's early returns.
        for route in 0..3 {
            let replay = Arc::new(EvaluationExecution::default());
            let _replay = replay.install();
            match route {
                0 => direct.record(key.clone()),
                1 => direct.absorb_receipt(&receipt),
                2 => direct.absorb_capture(&capture),
                _ => unreachable!(),
            }
            assert_eq!(
                replay.selection_reads::<EvaluationSelectionReads>().keys(),
                vec![key.clone()]
            );
        }
        // This family is declared beside the read vocabulary. The collector
        // never names it, and an empty nested frame cannot shadow collection.
        {
            let _nested = crate::analyzer::ReadAttribution::for_request().install();
            super::record_read_on_attribution_frame(&key);
        }
        super::record_receipt_on_active_ledgers(&[], &Arc::from([key.clone()]));
        assert_eq!(
            evaluation
                .selection_reads::<EvaluationSelectionReads>()
                .keys(),
            vec![key]
        );
        // An uncertified external-selection answer has no key to collect.
        // Its refusal must still reach evaluation-only execution.
        super::refuse_request_row_read_reuse();
        assert!(!evaluation.verdict().is_content());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11539: one unproven lookup's provider stop marked every sibling row incomplete"
    )]
    fn independent_lookup_completion_preserves_parent_refusal() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
        use crate::analyzer::{MultiAnalyzer, read_ledger::DerivationExecutionCause};
        let analyzer = MultiAnalyzer::default();
        let ledger = Arc::new(ReadLedger::new());
        let parent = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let rows: Vec<_> = [true, false]
            .into_iter()
            .map(|unproven| {
                let row = AnalyzerQueryScope::independent_answer(&analyzer, None);
                if unproven {
                    analyzer.record_query_incomplete(QueryReadIncomplete::ProofStopped {
                        reason: "incomplete",
                        cause: Some(DerivationExecutionCause::Provider),
                    });
                }
                row.read_completion().is_err()
            })
            .collect();
        assert_eq!(rows, vec![true, false]);
        assert!(parent.read_completion().is_err());
        assert!(ledger.execution_dependences() > 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "f78115f8dd72+#10984: deferred receipts leaked failures or lost attributed store errors"
    )]
    fn deferred_read_receipts_isolate_completion_until_replayed() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete, QueryReadReceipt};
        use crate::analyzer::{MultiAnalyzer, store::StoreError};
        let analyzer = MultiAnalyzer::default();
        let ledger = Arc::new(ReadLedger::new());
        let _reads = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let outer = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let discarded = ReadKey::Configuration(StableDigest::sha256(b"discarded component"));
        let deciding = ReadKey::Configuration(StableDigest::sha256(b"deciding component"));
        let (_, unused) = QueryReadReceipt::capture_deferred(&analyzer, || {
            analyzer.record_read(discarded.clone());
            analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
                "unlisted component".into(),
            ));
            analyzer.record_query_failure(StoreError::new("discarded component store failure"));
        });
        drop(unused);
        assert_eq!(outer.read_completion(), Ok(()));
        assert!(outer.store_error().is_none());
        assert!(ledger.keys().is_empty());
        let (_, selected) = QueryReadReceipt::capture_deferred(&analyzer, || {
            let (_, nested) = QueryReadReceipt::capture_deferred(&analyzer, || {
                analyzer.record_read(deciding.clone());
                analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceUnavailable(
                    "selected component".into(),
                ));
            });
            nested.replay(&analyzer);
            assert_eq!(outer.read_completion(), Ok(()));
        });
        assert_eq!(outer.read_completion(), Ok(()));
        assert!(outer.captured_read_incompleteness().is_empty());
        assert!(ledger.keys().is_empty());
        selected.replay(&analyzer);
        assert_eq!(
            outer.read_completion(),
            Err(QueryReadIncomplete::SemanticEvidenceUnavailable(
                "selected component".into()
            ))
        );
        assert_eq!(ledger.keys(), vec![deciding]);
        drop(outer);
        drop(_reads);
        let replay_scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let error = StoreError::new("attributed store failure");
        let gap = QueryReadIncomplete::StoreFailure(error.clone()).attributed(
            super::QueryLookupProvenance {
                file: super::ProjectFile::new(std::env::current_dir().unwrap(), "Lookup.java"),
                byte_span: 12..19,
                name: "Missing".into(),
                tier: "same-package",
            },
        );
        let (_, receipt) = QueryReadReceipt::capture_deferred(&analyzer, || {
            let captured = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            analyzer.record_query_incomplete(gap.clone());
            assert_eq!(captured.store_error(), Some(error.clone()));
            assert_eq!(captured.captured_read_incompleteness(), vec![gap.clone()]);
        });
        assert!(replay_scope.store_error().is_none());
        assert_eq!(receipt.incomplete_reasons(), std::slice::from_ref(&gap));
        receipt.replay(&analyzer);
        assert_eq!(replay_scope.store_error(), Some(error));
        assert_eq!(replay_scope.read_completion(), Err(gap.clone()));
        assert_eq!(replay_scope.captured_read_incompleteness(), vec![gap]);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12747: reusable() ignored the receipt's unbounded read channels"
    )]
    fn query_read_receipt_reuse_requires_bounded_channels() {
        use super::{IAnalyzer, QueryReadReceipt};
        use crate::analyzer::MultiAnalyzer;

        let analyzer = MultiAnalyzer::default();
        let (_, clean) = QueryReadReceipt::capture_deferred(&analyzer, || ());
        assert!(clean.reusable());

        let (_, execution_dependent) = QueryReadReceipt::capture_deferred(&analyzer, || {
            let mut limits = crate::analyzer::semantic::SemanticBudget::default().limits();
            limits.nested_entries = 1;
            let budget = crate::analyzer::semantic::SemanticBudget::new(limits).unwrap();
            assert!(
                budget
                    .check_admission(crate::analyzer::semantic::SemanticWork {
                        nested_entries: 2,
                        ..Default::default()
                    })
                    .is_err()
            );
        });
        assert!(execution_dependent.incomplete_reasons().is_empty());
        assert!(!execution_dependent.reusable());

        let (_, refused) = QueryReadReceipt::capture_deferred(&analyzer, || {
            analyzer.refuse_read_reuse();
        });
        assert!(refused.incomplete_reasons().is_empty());
        assert!(!refused.reusable());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: attributed receipt cause bytes were charged to the outer owner instead of their shared allocation"
    )]
    fn attributed_receipt_census_keeps_cause_bytes_with_shared_owner() {
        use super::{
            AttributedQueryReadIncomplete, ProjectFile, QueryLookupProvenance, QueryReadIncomplete,
            QueryReadReceipt, QueryReceiptReads,
        };
        use crate::analyzer::store::cache_budget::RetainedHeap;
        use std::mem::{size_of, size_of_val};

        let file = ProjectFile::new(std::env::current_dir().unwrap(), "Lookup.rs");
        let reason = QueryReadIncomplete::SemanticEvidenceGap("missing selected field".into())
            .attributed(QueryLookupProvenance {
                file: file.clone(),
                byte_span: 12..19,
                name: "selected".into(),
                tier: "test-owned-provenance",
            });
        let QueryReadIncomplete::Attributed(attribution) = &reason else {
            unreachable!();
        };
        let QueryReadIncomplete::SemanticEvidenceGap(leaf) = attribution.cause() else {
            unreachable!();
        };
        let attribution_id = Arc::as_ptr(attribution) as usize;
        let attribution_bytes = size_of::<AttributedQueryReadIncomplete>()
            + 2 * size_of::<usize>()
            + attribution.lookup().name.len()
            + leaf.len();
        let reads = Arc::new(ReadLedger::new());
        let receipts = [0, 1].map(|_| {
            Arc::new(QueryReadReceipt {
                reads: QueryReceiptReads::Captured(Arc::clone(&reads)),
                incomplete: vec![reason.clone()],
            })
        });
        assert!(!Arc::ptr_eq(&receipts[0], &receipts[1]));
        let (file_owner, root, path_capacity) = file.retained_parts();
        let file_id = Arc::as_ptr(file_owner) as usize;
        let root_id = Arc::as_ptr(root).cast::<()>() as usize;
        let file_bytes = size_of_val(&**file_owner) + 2 * size_of::<usize>() + path_capacity;
        let root_bytes = size_of_val(&**root) + 2 * size_of::<usize>();
        let check = |heap: &RetainedHeap, receipt: &Arc<QueryReadReceipt>| {
            let bytes_for = |id| {
                heap.shared_allocations()
                    .find_map(|(owner, bytes)| (owner == id).then_some(bytes))
                    .expect("live shared allocation has its own record")
            };
            assert_eq!(bytes_for(attribution_id), attribution_bytes);
            assert_eq!(bytes_for(file_id), file_bytes);
            assert_eq!(bytes_for(root_id), root_bytes);
            // Only the receipt's own inline data, Arc counters and vector
            // backing belong here; attribution name/cause stay with its Arc.
            assert_eq!(
                bytes_for(Arc::as_ptr(receipt) as usize),
                size_of::<QueryReadReceipt>()
                    + 2 * size_of::<usize>()
                    + receipt.incomplete.capacity() * size_of::<QueryReadIncomplete>()
            );
            for id in [attribution_id, file_id, root_id] {
                assert_eq!(
                    heap.shared_allocations()
                        .filter(|(owner, _)| *owner == id)
                        .count(),
                    1
                );
            }
        };
        for receipt in &receipts {
            let mut heap = RetainedHeap::default();
            heap.arc(receipt, |receipt, heap| receipt.retained_heap(heap));
            check(&heap, receipt);
        }
        let mut shared_walk = RetainedHeap::default();
        for receipt in &receipts {
            shared_walk.arc(receipt, |receipt, heap| receipt.retained_heap(heap));
        }
        for receipt in &receipts {
            check(&shared_walk, receipt);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: selected receipts retained capture DAGs that grew after memory admission"
    )]
    fn retained_receipt_preserves_replay_without_ancestor_publication_growth() {
        use super::{
            AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete, QueryReadReceipt,
            QueryReceiptReads, capture_query_reads_deferred, replay_query_reads,
        };
        use crate::analyzer::{MultiAnalyzer, store::cache_budget::RetainedHeap};
        let analyzer = MultiAnalyzer::default();
        let read_origin = std::panic::Location::caller();
        let execution_origin = std::panic::Location::caller();
        let read_refusal = brokk_bifrost_core::profiling::ReadRefusal {
            kind: "unattributed",
            reason: "selected input provenance".into(),
            origin: read_origin,
        };
        let execution_refusal = brokk_bifrost_core::profiling::ReadRefusal {
            kind: "execution_dependent",
            reason: "outer guard provenance".into(),
            origin: execution_origin,
        };
        let ancestor = Arc::new(ReadLedger::new());
        ancestor.set_test_refusal_origins(read_refusal.clone(), execution_refusal.clone());
        ancestor.record(ReadKey::Configuration(StableDigest::sha256(b"ancestor")));
        ancestor.mark_runtime_cache_touched();
        ancestor.record_unattributed_reads(2);
        ancestor.mark_execution_dependent_reads(5);
        ancestor.record_budget_dependences(3);
        ancestor.record_persistence_refusals(4);
        ancestor.refuse_read_reuse();
        let (_, mut receipt) = QueryReadReceipt::capture_deferred(&analyzer, || {
            replay_query_reads(&analyzer, &ancestor);
            analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                "guarded outer match".into(),
            ));
        });
        let QueryReceiptReads::Captured(captured) = &receipt.reads else {
            panic!("new receipt is captured");
        };
        captured.set_test_refusal_origins(read_refusal, execution_refusal);
        let digest = receipt.digest();
        let (_, before) = capture_query_reads_deferred(&analyzer, || receipt.replay(&analyzer));
        assert!(receipt.retain_root().nested_entries > 0);
        assert_eq!(receipt.retain_root(), Default::default());
        assert_eq!(receipt.digest(), digest);
        let QueryReceiptReads::Retained(retained_reads) = &receipt.reads else {
            panic!("selected receipt is compact");
        };
        let retained_read = retained_reads.reads.first_refusal.as_ref().unwrap();
        let retained_execution = retained_reads
            .reads
            .first_execution_refusal
            .as_ref()
            .unwrap();
        assert_eq!(
            (
                retained_read.kind,
                retained_read.reason.as_str(),
                retained_read.origin
            ),
            ("unattributed", "selected input provenance", read_origin)
        );
        assert_eq!(
            (
                retained_execution.kind,
                retained_execution.reason.as_str(),
                retained_execution.origin
            ),
            (
                "execution_dependent",
                "outer guard provenance",
                execution_origin
            )
        );
        let (_, after) = capture_query_reads_deferred(&analyzer, || {
            let completion = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            receipt.replay(&analyzer);
            assert!(
                matches!(completion.captured_read_incompleteness().as_slice(),
                [QueryReadIncomplete::SemanticEvidenceGap(reason)] if reason.as_ref() == "guarded outer match")
            );
        });
        assert_eq!(before.canonical_keys(), after.canonical_keys());
        assert_eq!(before.channels(), after.channels());
        assert_eq!(after.channels().unattributed_reads, 2);
        assert_eq!(after.channels().execution_dependences, 5);
        assert_eq!(after.channels().budget_dependences, 3);
        assert_eq!(after.channels().persistence_refusals, 4);
        assert!(after.channels().reuse_refused);
        assert!(after.runtime_cache_touched());
        if brokk_bifrost_core::profiling::enabled() {
            let read = after.first_refusal().expect("replayed read refusal");
            let execution = after
                .first_execution_refusal()
                .expect("replayed execution refusal");
            assert_eq!(
                (read.kind, read.reason.as_str(), read.origin),
                ("unattributed", "selected input provenance", read_origin)
            );
            assert_eq!(
                (execution.kind, execution.reason.as_str(), execution.origin),
                (
                    "execution_dependent",
                    "outer guard provenance",
                    execution_origin
                )
            );
        }
        assert_eq!(
            before.runtime_cache_touched(),
            after.runtime_cache_touched()
        );
        assert!(
            matches!(receipt.incomplete_reasons(), [QueryReadIncomplete::SemanticEvidenceGap(reason)] if reason.as_ref() == "guarded outer match")
        );
        let duplicate_roots = ReadLedger::new();
        let one_visit_count = ancestor.unordered_keys_with_work().1;
        for _ in 0..4 {
            let child = ReadLedger::new();
            child.record(ReadKey::Configuration(StableDigest::sha256(b"ancestor")));
            duplicate_roots.absorb_capture(&child);
        }
        let (unique, duplicate_visits) = duplicate_roots.unordered_keys_with_work();
        assert_eq!(unique.len(), 1);
        assert!(duplicate_visits >= one_visit_count + 4);
        let bytes = || {
            let mut heap = RetainedHeap::default();
            receipt.retained_heap(&mut heap);
            heap.total()
        };
        let retained = bytes();
        let _published = ancestor.canonical_keys();
        assert_eq!(bytes(), retained);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "80d3ed76dc51: advisory failures leaked into enclosing query completion"
    )]
    fn advisory_read_failure_does_not_relabel_enclosing_query() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
        use crate::analyzer::{MultiAnalyzer, store::StoreError};

        let analyzer = MultiAnalyzer::default();
        let ledger = Arc::new(ReadLedger::new());
        let outer = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let key = ReadKey::Configuration(StableDigest::sha256(b"advisory frontier"));
        {
            let advisory = AnalyzerQueryScope::for_advisory_read(&analyzer);
            analyzer.record_read(key.clone());
            analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
            analyzer.record_query_failure(StoreError::new("advisory probe failed"));
            assert_eq!(
                advisory.read_completion(),
                Err(QueryReadIncomplete::Cancelled)
            );
            assert!(!advisory.captured_read_incompleteness().is_empty());
        }
        assert_eq!(outer.read_completion(), Ok(()));
        assert!(outer.store_error().is_none());
        assert!(ledger.keys().contains(&key));
    }

    #[test]
    fn candidate_capture_rehomes_receipts_and_preserves_global_failures() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete, QueryReadReceipt};
        use crate::analyzer::{MultiAnalyzer, store::StoreError};

        let analyzer = MultiAnalyzer::default();
        let ledger = Arc::new(ReadLedger::new());
        let outer = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let gap = QueryReadIncomplete::SemanticEvidenceGap("candidate dependency".into());
        let key = ReadKey::Configuration(StableDigest::sha256(b"candidate receipt"));
        let receipt = {
            let candidate = AnalyzerQueryScope::capturing_candidate_classification(&analyzer);
            let (_, receipt) = QueryReadReceipt::capture(&analyzer, || {
                analyzer.record_read(key.clone());
                analyzer.record_unattributed_read();
                analyzer.refuse_read_reuse();
                analyzer.record_query_incomplete(gap.clone());
            });
            assert_eq!(candidate.captured_read_incompleteness(), vec![gap.clone()]);
            receipt
        };
        assert_eq!(outer.read_completion(), Ok(()));
        {
            let candidate = AnalyzerQueryScope::capturing_candidate_classification(&analyzer);
            receipt.replay(&analyzer);
            assert_eq!(candidate.captured_read_incompleteness(), vec![gap.clone()]);
            {
                let nested = AnalyzerQueryScope::capturing_candidate_classification(&analyzer);
                analyzer.record_query_incomplete(QueryReadIncomplete::ArtifactUnavailable(
                    "nested dependency".into(),
                ));
                assert_eq!(nested.captured_read_incompleteness().len(), 1);
            }
            assert_eq!(candidate.captured_read_incompleteness(), vec![gap]);
            assert_eq!(outer.read_completion(), Ok(()));
            analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
            analyzer.record_query_failure(StoreError::new("candidate store failure"));
            assert!(candidate.store_error().is_some());
        }
        assert_eq!(outer.read_completion(), Err(QueryReadIncomplete::Cancelled));
        assert!(outer.store_error().is_some());
        assert!(ledger.keys().contains(&key));
        assert!(ledger.unattributed_reads() > 0);
        assert!(ledger.reuse_refused());
    }

    #[test]
    fn candidate_capture_preserves_reasons_recorded_outside_the_boundary() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
        use crate::analyzer::MultiAnalyzer;

        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let global = QueryReadIncomplete::ArtifactUnavailable("shared enumeration input".into());
        analyzer.record_query_incomplete(global.clone());
        {
            let candidate = AnalyzerQueryScope::capturing_candidate_classification(&analyzer);
            assert!(candidate.captured_read_incompleteness().is_empty());
            assert_eq!(
                analyzer.current_query_read_completion(),
                Err(global.clone())
            );
            analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                "local dependency".into(),
            ));
        }
        assert_eq!(outer.captured_read_incompleteness(), vec![global]);
    }

    #[test]
    fn nested_read_ledger_inherits_outer_cancellation() {
        use super::{AnalyzerQueryScope, current_query_cancellation};
        use crate::analyzer::MultiAnalyzer;
        let analyzer = MultiAnalyzer::default();
        let token = crate::CancellationToken::new();
        let _outer = AnalyzerQueryScope::with_cancellation(&analyzer, &token);
        let _inner = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::new(ReadLedger::new()));
        assert!(!current_query_cancellation().unwrap().is_cancelled());
        token.cancel();
        assert!(current_query_cancellation().unwrap().is_cancelled());
    }

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
    #[brokk_bifrost_test_macros::hardwon(
        "f3fffc13b78d: a sink-phase proof stop became the own incompleteness of every later scope and dropped literal taint sources"
    )]
    fn nested_queries_report_only_their_own_reads_but_do_not_fill_under_an_incomplete_chain() {
        use super::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
        use crate::analyzer::MultiAnalyzer;

        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        // A stable gap (#8618) and an operational stop recorded in the
        // enclosing request describe the enclosing request's own reads.
        let stable =
            QueryReadIncomplete::SemanticEvidenceGap("nested-call result arity unavailable".into());
        let operational = QueryReadIncomplete::ProofStopped {
            reason: "resolution_unsupported_semantic",
            cause: Some(crate::analyzer::read_ledger::DerivationExecutionCause::Provider),
        };
        let own = QueryReadIncomplete::SemanticEvidenceGap("read by the nested scope".into());
        analyzer.record_query_incomplete(stable.clone());
        analyzer.record_query_incomplete(operational.clone());
        analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
        {
            let sibling = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            // The nested scope's answer does not carry them: they were not
            // consumed by anything the nested scope read.
            assert_eq!(sibling.read_completion(), Ok(()));
            assert!(sibling.captured_read_incompleteness().is_empty());
            // A cache fill under the incomplete chain is still refused: the
            // admission check walks the chain of the request domain.
            // #13024 chooses the canonical representative; the inherited
            // chain is still incomplete and the nested scope stays clean.
            assert_eq!(
                analyzer.current_query_read_completion(),
                Err(QueryReadIncomplete::Cancelled)
            );
            // A policy unit's scope under that chain keeps a clean ledger, so
            // the inherited stop does not make its receipt execution-dependent.
            let ledger = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
            let unit = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            assert_eq!(ledger.execution_dependences(), 0);
            assert!(unit.read_completion().is_ok());
            drop(unit);
            // What the nested scope itself reads is recorded on it and on
            // every enclosing scope.
            analyzer.record_query_incomplete(own.clone());
            assert_eq!(sibling.captured_read_incompleteness(), vec![own.clone()]);
        }
        assert_eq!(
            outer.captured_read_incompleteness(),
            vec![QueryReadIncomplete::Cancelled, operational, stable, own]
        );
    }

    /// The candidate selection table lives in the root query context, one per
    /// request (#11936): every nested scope of the request shares it, so the
    /// first selection holds for the request, and the next request's root
    /// starts with an empty table, so admission runs again.
    #[test]
    fn a_new_root_query_starts_an_empty_selection_table() {
        use super::{AnalyzerQueryScope, candidate_overlay_query_context};
        use crate::analyzer::MultiAnalyzer;

        let analyzer = MultiAnalyzer::default();
        let first = {
            let _request = AnalyzerQueryScope::new(&analyzer);
            let root = candidate_overlay_query_context().expect("root query context");
            {
                let _nested = AnalyzerQueryScope::new(&analyzer);
                let seen = candidate_overlay_query_context().expect("root query context");
                assert!(Arc::ptr_eq(&root, &seen), "a nested scope shares the root");
            }
            root
        };
        let _next = AnalyzerQueryScope::new(&analyzer);
        let next = candidate_overlay_query_context().expect("root query context");
        assert!(!Arc::ptr_eq(&first, &next), "a new request has a new root");
        assert!(
            next.selected_procedures
                .lock()
                .expect("selection lock")
                .is_empty()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10979: nested queries and workers could select a successor snapshot inside one request"
    )]
    fn request_workspace_selection_survives_publication_nested_scopes_and_workers() {
        use super::{
            AnalyzerQueryScope, RequestWorkspaceSelectionError, request_workspace_snapshots,
        };
        use crate::analyzer::MultiAnalyzer;
        use crate::analyzer::store::{GenerationId, WorkspaceId, WorkspaceSnapshotId};
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;

        let workspace_id = WorkspaceId::for_session();
        let snapshots = |revision| {
            Arc::new(
                ["python", "rust"]
                    .into_iter()
                    .map(|lang| {
                        (
                            lang.to_owned(),
                            WorkspaceSnapshotId {
                                workspace_id: workspace_id.clone(),
                                lang: lang.to_owned(),
                                generation: GenerationId(1),
                                revision,
                            },
                        )
                    })
                    .collect(),
            )
        };
        let first = snapshots(1);
        let second = snapshots(2);
        let source = Arc::new(arc_swap::ArcSwap::from(Arc::clone(&first)));
        let other_source = Arc::new(arc_swap::ArcSwap::from(Arc::clone(&second)));
        let analyzer = MultiAnalyzer::default();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let context_after_close = {
            let outer = AnalyzerQueryScope::new(&analyzer);
            // This is the eager bind performed by TreeSitterAnalyzer::begin_query.
            outer.context.bind_workspace_snapshots(&source);
            source.store(Arc::clone(&second));
            // The first read occurs after publication; it must still see S1.
            assert!(Arc::ptr_eq(
                &request_workspace_snapshots(&source).unwrap(),
                &first
            ));
            {
                let nested = AnalyzerQueryScope::new(&analyzer);
                nested.context.bind_workspace_snapshots(&source);
                nested.context.bind_workspace_snapshots(&other_source);
                assert!(Arc::ptr_eq(
                    &request_workspace_snapshots(&source).unwrap(),
                    &first
                ));
                assert!(Arc::ptr_eq(
                    &request_workspace_snapshots(&other_source).unwrap(),
                    &second
                ));
            }
            let carried = CarriedContext::current();
            pool.install(|| {
                rayon::join(
                    || {
                        carried.run(|| {
                            let nested = AnalyzerQueryScope::new(&analyzer);
                            nested.context.bind_workspace_snapshots(&source);
                            assert_eq!(*request_workspace_snapshots(&source).unwrap(), *first);
                        });
                    },
                    || {
                        carried.run(|| {
                            assert_eq!(*request_workspace_snapshots(&source).unwrap(), *first);
                        });
                    },
                );
            });
            let request = outer.outer_request();
            std::thread::scope(|threads| {
                threads
                    .spawn(|| {
                        let worker =
                            AnalyzerQueryScope::with_outer_request(&analyzer, Arc::clone(&request));
                        worker.context.bind_workspace_snapshots(&source);
                        assert_eq!(*request_workspace_snapshots(&source).unwrap(), *first);
                    })
                    .join()
                    .expect("selected snapshot worker panicked");
            });
            carried
        };
        context_after_close.run(|| {
            assert_eq!(
                request_workspace_snapshots(&source),
                Err(RequestWorkspaceSelectionError::ClosedRequest)
            );
        });
        let next = AnalyzerQueryScope::new(&analyzer);
        next.context.bind_workspace_snapshots(&source);
        assert!(Arc::ptr_eq(
            &request_workspace_snapshots(&source).unwrap(),
            &second
        ));
    }

    #[test]
    fn outer_request_lifetime_follows_nested_scopes_and_explicit_worker_attachment() {
        use super::AnalyzerQueryScope;
        use crate::analyzer::MultiAnalyzer;

        let analyzer = MultiAnalyzer::default();
        let (first_id, first_request) = {
            let run = AnalyzerQueryScope::new(&analyzer);
            let request = run.outer_request();
            let nested = AnalyzerQueryScope::new(&analyzer);
            assert_eq!(nested.outer_request().id(), request.id());
            drop(nested);
            assert!(!request.is_closed());
            let (captured_id, _) = super::capture_query_reads(&analyzer, || {
                super::current_outer_request_or_transient().id()
            });
            assert_eq!(captured_id, request.id());
            std::thread::scope(|threads| {
                threads
                    .spawn(|| {
                        let worker =
                            AnalyzerQueryScope::with_outer_request(&analyzer, Arc::clone(&request));
                        let unit = AnalyzerQueryScope::new(&analyzer);
                        assert_eq!(worker.outer_request().id(), request.id());
                        assert_eq!(unit.outer_request().id(), request.id());
                    })
                    .join()
                    .expect("policy worker panicked");
            });
            assert!(!request.is_closed());
            (request.id(), request)
        };
        assert!(first_request.is_closed());
        let second = AnalyzerQueryScope::new(&analyzer);
        assert_ne!(second.outer_request().id(), first_id);
        drop(second);
        assert_ne!(super::current_outer_request_or_transient().id(), first_id);
    }

    #[test]
    fn nested_queries_record_into_their_transported_ancestors() {
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
            assert_eq!(nested.read_completion(), Ok(()));
        }
        {
            // Registration also checks ancestry when bypassing MultiAnalyzer.
            let nested = Arc::new(AnalyzerQueryContext::default());
            assert!(nested.read_completion().is_ok());
            let _attribution = nested.enter();
            assert!(delegate.begin(&nested));
            assert_eq!(nested.read_completion(), Ok(()));
            assert!(delegate.end(&nested));
        }
        let carried = CarriedContext::current();
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    carried.run(|| {
                        let child = AnalyzerQueryScope::new(&analyzer);
                        assert_eq!(child.read_completion(), Ok(()));
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
    fn retained_fills_share_one_isolated_request_domain() {
        use super::AnalyzerQueryScope;
        let analyzer = crate::analyzer::MultiAnalyzer::default();
        let request = AnalyzerQueryScope::new(&analyzer);
        let domain;
        {
            let fill = AnalyzerQueryScope::for_retained_fill(&analyzer);
            domain = fill.context.request_cache_domain();
            assert_ne!(domain, request.context.request_cache_domain());
            let nested = AnalyzerQueryScope::for_retained_fill(&analyzer);
            assert_eq!(domain, nested.context.request_cache_domain());
        }
        let later = AnalyzerQueryScope::for_retained_fill(&analyzer);
        assert_eq!(domain, later.context.request_cache_domain());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#8546: a retained fill borrowed another analyzer's pinned model absence"
    )]
    fn retained_fill_uses_only_its_analyzers_model_override() {
        use super::{AnalyzerQueryScope, IAnalyzer};
        let head = crate::analyzer::MultiAnalyzer::default();
        let base = crate::analyzer::MultiAnalyzer::default();
        let _head = AnalyzerQueryScope::with_active_semantic_model_snapshot(&head, None);
        assert!(matches!(
            head.active_query_semantic_model_snapshot(),
            Some(None)
        ));

        let _fill = AnalyzerQueryScope::for_retained_fill(&base);
        assert!(base.active_query_semantic_model_snapshot().is_none());
        assert!(base.active_query_semantic_model_overlay().is_none());

        let _base = AnalyzerQueryScope::with_active_semantic_model_snapshot(&base, None);
        let _base_fill = AnalyzerQueryScope::for_retained_fill(&base);
        assert!(matches!(
            base.active_query_semantic_model_snapshot(),
            Some(None)
        ));
        // An analyzer that registered no scope must not borrow the innermost
        // (base's) override, which the unfiltered lookup returned.
        let other = crate::analyzer::MultiAnalyzer::default();
        assert!(other.active_query_semantic_model_snapshot().is_none());
        assert!(other.active_query_semantic_model_overlay().is_none());
    }

    #[test]
    fn retained_fill_path_module_failures_are_isolated_both_ways() {
        use super::{AnalyzerQueryScope, path_module_request_failure_cell};
        use crate::analyzer::store::StoreError;
        let analyzer = crate::analyzer::MultiAnalyzer::default();
        let _outer = AnalyzerQueryScope::new(&analyzer);
        let outer = path_module_request_failure_cell(crate::Language::JavaScript).unwrap();
        *outer.lock().unwrap() = Some(StoreError::new("enclosing failure"));
        {
            let _fill = AnalyzerQueryScope::for_retained_fill(&analyzer);
            let own = path_module_request_failure_cell(crate::Language::JavaScript).unwrap();
            assert!(!Arc::ptr_eq(&outer, &own));
            assert!(own.lock().unwrap().is_none());
            *own.lock().unwrap() = Some(StoreError::new("fill failure"));
            let _nested = AnalyzerQueryScope::new(&analyzer);
            assert!(Arc::ptr_eq(
                &own,
                &path_module_request_failure_cell(crate::Language::JavaScript).unwrap()
            ));
        }
        assert!(Arc::ptr_eq(
            &outer,
            &path_module_request_failure_cell(crate::Language::JavaScript).unwrap()
        ));
        assert_eq!(
            outer.lock().unwrap().as_ref().unwrap().to_string(),
            "enclosing failure"
        );
        {
            let _fill = AnalyzerQueryScope::for_retained_fill(&analyzer);
            assert!(
                path_module_request_failure_cell(crate::Language::JavaScript)
                    .unwrap()
                    .lock()
                    .unwrap()
                    .is_none()
            );
        }
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

    fn qualified_batch(patterns: &[&str]) -> SearchSymbolPatternBatch {
        SearchSymbolPatternBatch::compile(
            patterns.iter().map(|pattern| pattern.to_string()).collect(),
            false,
            None,
        )
    }

    /// Every separator the classifier accepts names the declaration whose
    /// stored spelling uses any other one. The stored spellings here are the
    /// ones the language adapters produce: PHP joins a namespace with `.`,
    /// Java and C++ nested types with `.`/`$`, C++ nested namespaces with
    /// `::`, and every language joins a member to its owner with `.`.
    #[test]
    #[hardwon("#8697: the candidate matcher dropped qualified requests that scoring ranked first")]
    fn a_qualified_request_matches_every_languages_stored_spelling() {
        for (request, stored) in [
            (r"App\Models\User", "App.Models.User"),
            (r"PHPMailer\PHPMailer\SMTP", "PHPMailer.PHPMailer.SMTP"),
            ("Outer$Inner", "N.Outer.Inner"),
            ("N.Outer$Inner.Method", "N.Outer.Inner.Method"),
            ("ns::C", "ns.C"),
            ("ns::Outer::Inner", "ns.Outer$Inner"),
            ("pkg/Thing", "pkg.Thing"),
            ("Outer+Inner", "N.Outer.Inner"),
            ("S::operator+", "S.operator+"),
            // A Scala companion chain stores `$.` where the source spells `.`.
            ("Fiber.Promise.Unsafe", "kyo.Fiber$.Promise$.Unsafe"),
            ("Fiber$.Promise.Unsafe", "kyo.Fiber.Promise.Unsafe"),
        ] {
            let batch = qualified_batch(&[request]);
            assert!(batch.complete(), "{request}");
            assert!(batch.invalid_patterns().is_empty(), "{request}");
            assert!(
                batch.is_match(stored),
                "`{request}` must reach the stored spelling `{stored}`"
            );
        }
    }

    /// The separator is a join, not a wildcard: a qualified request must not
    /// start matching names that share only the text between separators.
    #[test]
    #[hardwon("#8697: a qualified request must not match a name with no separator")]
    fn a_qualified_request_does_not_match_an_unrelated_name() {
        for (request, unrelated) in [
            (r"App\Models\User", "AppModelsUser"),
            (r"App\Models\User", "App.Other.User"),
            (r"PHPMailer\PHPMailer\SMTP", "PHPMailer.PHPMailer.Other"),
            ("Outer$Inner", "OuterInner"),
            ("Outer+Inner", "OuterInner"),
            ("ns::C", "nsC"),
            ("ns::C", "other::C"),
            ("pkg/Thing", "pkgThing"),
        ] {
            let batch = qualified_batch(&[request]);
            assert!(
                !batch.is_match(unrelated),
                "`{request}` must not match `{unrelated}`"
            );
        }
    }

    /// A sigil at the boundary of a request is identifier text, not a join.
    #[test]
    #[hardwon("#1127: a trailing dollar sigil stays identifier text in the matcher")]
    fn a_boundary_sigil_keeps_its_identifier_meaning() {
        let dollar = qualified_batch(&["Foo$"]);
        assert!(dollar.is_match("Foo$"));
        assert!(!dollar.is_match("Foo"));
        assert!(!dollar.is_match("N.Foo.bar"));

        let anchor = qualified_batch(&["foo.$"]);
        assert!(anchor.is_match("foo."));
        assert!(!anchor.is_match("foo.$"));

        let dollars = qualified_batch(&["_$$"]);
        assert!(dollars.is_match("_$$"));
        assert!(!dollars.is_match("_$"));
    }

    /// A qualified request keeps its per-component required literals, so the
    /// storage prefilter stays a superset of the matcher.
    #[test]
    #[hardwon("#8697: a qualified request must keep its per-component prefilter literals")]
    fn a_qualified_request_prefilters_on_its_components() {
        for (request, expected) in [
            (r"App\Models\User", vec!["app", "models", "user"]),
            ("PHPMailer.PHPMailer.SMTP", vec!["phpmailer", "smtp"]),
            ("ns::Outer::Inner", vec!["inner", "ns", "outer"]),
        ] {
            let batch = qualified_batch(&[request]);
            let mut expected = expected
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<String>>();
            expected.sort();
            let mut actual = batch
                .required_storage_literals()
                .unwrap_or_else(|| panic!("`{request}` must keep a prefilter"))
                .concat();
            actual.sort();
            assert_eq!(actual, expected, "{request}");
        }
    }

    /// A request that spells a regular expression with escapes keeps its
    /// anchors and escaped dots; the qualified translation must not consume
    /// them as name text.
    #[test]
    #[hardwon("#8697: an anchored regex request lost its anchors in the qualified matcher")]
    fn an_anchored_regex_request_keeps_its_regex_reading() {
        let batch = qualified_batch(&[r"\ADetail\.Outer$Inner\.run\z"]);
        assert!(batch.is_match("Detail.Outer$Inner.run"));
        assert!(!batch.is_match("XDetail.Outer$Inner.run"));
        assert!(!batch.is_match("Detail.Outer.Inner.run"));
    }

    /// `\` is both a PHP namespace separator and regex escape syntax. A
    /// backslash-joined request that also compiles as a regex keeps both
    /// readings, so neither the PHP class nor the regex match is lost; a
    /// pattern ending in a one-letter escape is a regex only.
    #[test]
    #[hardwon("#8697: a backslash request lost one of its PHP and regex readings")]
    fn a_backslash_request_keeps_both_readings_when_both_compile() {
        let php = qualified_batch(&[r"yii\base\Widget"]);
        assert!(php.invalid_patterns().is_empty());
        assert!(php.is_match("yii.base.Widget"));
        assert!(!php.is_match("yii.other.Widget"));

        let rooted = qualified_batch(&[r"\yii\base\Widget"]);
        assert!(rooted.is_match("yii.base.Widget"));
        assert!(!rooted.is_match("yii.other.Widget"));

        let boundary = qualified_batch(&[r"\bfoo\b"]);
        assert!(boundary.invalid_patterns().is_empty());
        assert!(boundary.is_match("app.foo.Bar"));
        assert!(!boundary.is_match("app.food"));
        assert!(!boundary.is_match("bfoo.b"));

        let anchored = qualified_batch(&[r"\AFoo\z"]);
        assert!(anchored.is_match("Foo"));
        assert!(!anchored.is_match("AFoo.z"));

        // A one-letter last component is a PHP name, whether or not the
        // request is also a valid regex.
        let short = qualified_batch(&[r"App\Models\C", r"yii\base\b"]);
        assert!(short.invalid_patterns().is_empty());
        assert!(short.is_match("App.Models.C"));
        assert!(short.is_match("yii.base.b"));
    }

    /// Regular expressions and globs keep their own meaning, and a pattern
    /// that is neither is still reported instead of silently matching nothing.
    #[test]
    #[hardwon("#3279: a malformed request must still be reported beside qualified requests")]
    fn explicit_regex_and_glob_requests_are_unchanged() {
        let regex = qualified_batch(&["Java.*Value.*Flow"]);
        assert!(regex.is_match("crates::java::JavaValueFlow"));
        assert!(!regex.is_match("crates::java::Value"));

        let glob = qualified_batch(&["*Language*"]);
        assert!(glob.is_match("bifrost_core::Language"));
        assert!(!glob.is_match("crates::rql::Lantern"));

        let invalid = qualified_batch(&["foo(bar", "App\\Models\\User"]);
        assert_eq!(
            invalid.invalid_patterns(),
            ["foo(bar".to_string()].as_slice()
        );
        assert!(invalid.is_match("App.Models.User"));
        assert!(!invalid.is_match("app::foo(bar"));
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
    use crate::analyzer::{MultiAnalyzer, ReadLedger};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: acknowledged policy errors leaked into sibling reads"
    )]
    fn policy_completion_owner_isolates_siblings_and_retains_shared_failures() {
        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::new(&analyzer);
        let first = Arc::new(PolicyCompletionOwner::default());
        {
            let _owner = carried_context::push_completion(first.clone());
            let _policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
            analyzer.record_query_failure(StoreError::new("first policy"));
            analyzer.record_query_incomplete(QueryReadIncomplete::Cancelled);
            assert!(current_domain_read_completion().is_err());
            assert_eq!(first.errors().len(), 1);
            assert!(carried_context::request_store_failed());
            first.acknowledge();
            assert!(
                carried_context::request_store_failed(),
                "acknowledgment does not recover this failed evaluation"
            );
            let _independent = AnalyzerQueryScope::independent_answer(&analyzer, None);
            assert!(
                carried_context::request_store_failed(),
                "an independent answer still belongs to its failed evaluation"
            );
        }
        let second = Arc::new(PolicyCompletionOwner::default());
        {
            let _owner = carried_context::push_completion(second.clone());
            let policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
            assert!(policy.store_error().is_none());
            assert!(
                !carried_context::request_store_failed(),
                "acknowledged sibling errors do not stop a new policy"
            );
            assert!(current_domain_read_completion().is_ok());
            // A failed shared reader must report its failure again to its new consumer.
            analyzer.record_query_failure(StoreError::new("aborted reader consumed again"));
            assert!(current_domain_read_completion().is_err());
            assert!(carried_context::request_store_failed());
            assert_ne!(first.errors()[0].id(), second.errors()[0].id());
            second.acknowledge();
        }
        assert!(outer.context.unacknowledged_store_error().is_none());
        analyzer.record_query_failure(StoreError::new("shared preparation"));
        assert!(outer.context.unacknowledged_store_error().is_some());
        for _ in 0..2 {
            let owner = Arc::new(PolicyCompletionOwner::default());
            let _owner = owner.install();
            let policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
            assert!(policy.store_error().is_none());
            assert_eq!(owner.errors().len(), 1);
            assert_eq!(
                owner.errors()[0].error(),
                &StoreError::new("shared preparation")
            );
            assert!(carried_context::request_store_failed());
            // Operation refusal observes preparation through the owner, while
            // nested derivations keep clean own completion (#11701).
            assert!(current_domain_read_completion().is_ok());
        }
        drop(outer);
        let _new_request = AnalyzerQueryScope::new(&analyzer);
        assert!(!carried_context::request_store_failed());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11775: completion inheritance missed a shared failure above its immediate parent"
    )]
    fn request_store_failure_observes_shared_ancestors_without_copying_to_fills() {
        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::new(&analyzer);
        let middle = AnalyzerQueryScope::new(&analyzer);
        // Inject after opening the middle scope: its completion has no copy.
        outer
            .context
            .record_store_error(StoreError::new("grandparent preparation"));
        assert!(middle.store_error().is_none());
        {
            let owner = Arc::new(PolicyCompletionOwner::default());
            let _owner = owner.install();
            let policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
            assert!(policy.context.recorded_store_errors().is_empty());
            assert_eq!(owner.errors().len(), 1);
            assert!(carried_context::request_store_failed());
            let nested = AnalyzerQueryScope::new(&analyzer);
            assert!(nested.context.recorded_store_errors().is_empty());
            assert!(nested.read_completion().is_ok());
            assert!(carried_context::request_store_failed());
            assert!(current_domain_read_completion().is_ok());
        }
        outer.context.acknowledge_store_errors(
            &outer
                .context
                .recorded_store_errors()
                .iter()
                .map(|error| error.id())
                .collect::<Vec<_>>(),
        );
        let _sibling = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
        assert!(!carried_context::request_store_failed());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11829: a parallel policy inherited its sibling's failure before acknowledgment"
    )]
    fn policy_completion_excludes_unacknowledged_concurrent_sibling_failures() {
        let analyzer = MultiAnalyzer::default();
        let outer = AnalyzerQueryScope::new(&analyzer);
        let request = outer.outer_request();
        let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        let rendezvous = std::sync::Barrier::new(2);
        let (failed, healthy) = std::thread::scope(|threads| {
            let first = threads.spawn(|| {
                carried.run(|| {
                    let _request =
                        AnalyzerQueryScope::with_outer_request(&analyzer, request.clone());
                    let owner = Arc::new(PolicyCompletionOwner::default());
                    let _owner = owner.install();
                    let _policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
                    analyzer.record_query_failure(StoreError::new("unacknowledged sibling"));
                    let before_ack = current_domain_read_completion().is_err();
                    let core_before_ack = carried_context::request_store_failed();
                    rendezvous.wait();
                    // Keep the error unacknowledged until the other policy has
                    // entered and inspected both its query and owner completions.
                    rendezvous.wait();
                    owner.acknowledge();
                    (
                        before_ack,
                        current_domain_read_completion().is_err(),
                        core_before_ack,
                        carried_context::request_store_failed(),
                    )
                })
            });
            let second = threads.spawn(|| {
                carried.run(|| {
                    rendezvous.wait();
                    let _request =
                        AnalyzerQueryScope::with_outer_request(&analyzer, request.clone());
                    let owner = Arc::new(PolicyCompletionOwner::default());
                    let _owner = owner.install();
                    let policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
                    let clean = (
                        policy.store_error().is_none(),
                        owner.errors().is_empty(),
                        current_domain_read_completion().is_ok(),
                        !carried_context::request_store_failed(),
                    );
                    let independent_clean = {
                        let _independent = AnalyzerQueryScope::independent_answer(&analyzer, None);
                        !carried_context::request_store_failed()
                    };
                    // Release the sibling before assertions, including on the
                    // pre-fix failure path, so a failed check cannot strand it.
                    rendezvous.wait();
                    (clean.0, clean.1, clean.2, clean.3, independent_clean)
                })
            });
            (
                first.join().expect("failed-policy thread"),
                second.join().expect("healthy-policy thread"),
            )
        });
        assert_eq!(
            failed,
            (true, true, true, true),
            "acknowledgment never recovers its own evaluation"
        );
        assert_eq!(
            healthy,
            (true, true, true, true, true),
            "a concurrent sibling owns neither failure channel"
        );
        assert!(outer.context.unacknowledged_store_error().is_none());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: a store error in a dropped deferred receipt failed the policy"
    )]
    fn deferred_receipt_store_error_reaches_policy_owner_only_when_replayed() {
        let analyzer = MultiAnalyzer::default();
        let owner = Arc::new(PolicyCompletionOwner::default());
        let _owner = carried_context::push_completion(owner.clone());
        let _policy = AnalyzerQueryScope::for_policy_evaluation(&analyzer);
        let (_, dropped) = QueryReadReceipt::capture_deferred(&analyzer, || {
            analyzer.record_query_failure(StoreError::new("discarded component"));
        });
        let (_, replayed) = QueryReadReceipt::capture_deferred(&analyzer, || {
            analyzer.record_query_failure(StoreError::new("deciding component"));
        });
        assert!(owner.errors().is_empty());
        drop(dropped);
        replayed.replay(&analyzer);
        let errors = owner.errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].error(), &StoreError::new("deciding component"));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: an attributed store failure left the read ledger reusable"
    )]
    fn attributed_store_failure_marks_the_read_ledger() {
        let analyzer = MultiAnalyzer::default();
        let ledger = Arc::new(ReadLedger::new());
        let _reads = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        analyzer.record_query_incomplete(
            QueryReadIncomplete::StoreFailure(StoreError::new("attributed")).attributed(
                QueryLookupProvenance {
                    file: ProjectFile::new(std::env::current_dir().unwrap(), "Lookup.java"),
                    byte_span: 12..19,
                    name: "Missing".into(),
                    tier: "same-package",
                },
            ),
        );
        assert!(ledger.store_failed());
        assert!(ledger.reuse_refused());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: replaying or forwarding a capture lost its store failure"
    )]
    fn replayed_and_forwarded_captures_carry_store_failure() {
        let analyzer = MultiAnalyzer::default();
        let consumer = Arc::new(ReadLedger::new());
        {
            let _reads = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&consumer));
            // A field-slot acquisition's failure sits in a ledger no context
            // chain reaches; only the replay can carry it to the consumer.
            let failed = Arc::new(ReadLedger::new());
            failed.record_store_failure();
            assert!(!consumer.store_failed());
            replay_query_reads(&analyzer, &failed);
        }
        assert!(consumer.store_failed());
        assert!(consumer.reuse_refused());

        let forwarded = Arc::new(ReadLedger::new());
        {
            let _reads = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&forwarded));
            capture_query_reads(&analyzer, || {
                analyzer.record_query_failure(StoreError::new("nested solve read"));
            });
        }
        assert!(forwarded.store_failed());
    }

    #[test]
    fn snapshot_cache_handles_do_not_read_workspace_facts() {
        let analyzer = MultiAnalyzer::default();
        let caches = AnalyzerSnapshotCaches::new(1024);
        let derived = caches.derived_layers() as *const _;
        let usage = caches.usage_graphs() as *const _;
        let java = caches.java_usage_evidence() as *const _;
        let models = caches.semantic_models() as *const _;
        let syntax = caches.runtime_syntax() as *const _;
        let structural = crate::analyzer::structural::provider::StructuralFactSnapshotCache::new(
            1024,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        );
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
            completion: Mutex::new(QueryCompletion::capturing()),
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
                    .lock_completion()
                    .captured
                    .as_ref()
                    .unwrap()
                    .items
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
        use brokk_bifrost_core::analyzer::reuse_verdict::{
            CarriesReuseVerdict, ExecutionCause, ReuseVerdict,
        };
        let analyzer = MultiAnalyzer::default();
        let (_, reads) = capture_query_reads_judged(&analyzer, || {
            // A caught failure is dropped, but its verdict still decides.
            let failure =
                crate::analyzer::semantic::SemanticProviderError::internal("caught failure");
            ((), failure.reuse_verdict())
        });
        assert!(reads.execution_dependences() > 0);
        assert_eq!(
            reads.explicit_verdict(),
            ReuseVerdict::ExecutionDependent(ExecutionCause::Other)
        );
        assert!(!reads.is_bounded());
    }
}

#[cfg(test)]
mod model_absence_digest_test {
    #[test]
    fn no_active_model_digest_is_pinned() {
        assert_eq!(
            super::no_active_model_set_digest().as_bytes(),
            &[
                202, 229, 131, 58, 232, 54, 62, 38, 25, 168, 52, 173, 107, 47, 170, 226, 49, 83,
                29, 160, 9, 153, 238, 150, 6, 242, 178, 46, 164, 182, 31, 124,
            ]
        );
    }
}

#[cfg(test)]
mod listing_cell_receipt_tests {
    use super::*;
    use crate::analyzer::Language;
    use brokk_bifrost_core::analyzer::memo_attribution::CaptureIdentity;
    use brokk_bifrost_core::analyzer::memo_attribution::ReadChannels;
    use brokk_bifrost_core::analyzer::project::{FilesystemProject, OverlayProject};
    use brokk_bifrost_core::analyzer::project_reads::{
        ErasedCapturedReads, ErasedReadAttribution, OpaqueReadReceipt, ProjectRead,
        ProjectReadReceipt, ReadCapability, without_project_reads,
    };
    use brokk_bifrost_test_macros::hardwon;

    /// Every read a project records, as (was it an inventory read, receipt).
    type RecordedReads = Vec<(bool, String)>;

    #[derive(Clone, Default)]
    struct Tape(Arc<Mutex<RecordedReads>>);

    impl Tape {
        fn take(&self) -> RecordedReads {
            std::mem::take(&mut self.0.lock().expect("tape"))
        }
    }

    impl brokk_bifrost_core::analyzer::internal_memo_partitions::DeferredMemoAttribution for Tape {
        fn capture_deferred(&self, build: &mut dyn FnMut()) -> ErasedCapturedReads {
            self.capture(build)
        }
    }

    impl ErasedReadAttribution for Tape {
        fn is_live(&self) -> bool {
            true
        }
        fn is_capturing(&self) -> bool {
            true
        }
        fn record(&self, _: &dyn Project, read: ProjectRead<'_>, receipt: ProjectReadReceipt) {
            self.0.lock().expect("tape").push((
                matches!(read, ProjectRead::Inventory),
                format!("{receipt:?}"),
            ));
        }
        fn record_inventory(
            &self,
            receipt: &brokk_bifrost_core::analyzer::project_reads::InventoryReadReceipt,
        ) {
            self.0
                .lock()
                .expect("tape")
                .push((true, format!("{receipt:?}")));
        }
        fn capture_identity(&self) -> Option<CaptureIdentity> {
            None
        }
        fn record_unattributed(&self) {
            unimplemented!()
        }
        fn capture(&self, _: &mut dyn FnMut()) -> ErasedCapturedReads {
            unimplemented!()
        }
        fn capture_authority(&self, _: &mut dyn FnMut()) -> ErasedCapturedReads {
            unimplemented!()
        }
        fn replay(&self, _: &[OpaqueReadReceipt], _: ReadChannels) {
            unimplemented!()
        }
    }

    fn recorded(project: &dyn Project) -> Tape {
        let tape = Tape::default();
        assert!(project.install_read_recorder(ReadCapability::new(tape.clone())));
        tape
    }

    /// The reads recorded by a direct walk, a cell fill and a cell hit, each
    /// over its own fresh view of the same files so that no cached listing
    /// separates them.
    fn direct_fill_and_hit(
        view: impl Fn() -> Arc<dyn Project>,
    ) -> (RecordedReads, RecordedReads, RecordedReads) {
        let direct_view = view();
        let direct_tape = recorded(direct_view.as_ref());
        direct_view.all_files_with_omissions().expect("direct walk");

        let cell = WorkspaceFileListingCell::default();
        let cell_view = view();
        let cell_tape = recorded(cell_view.as_ref());
        cell.listing(cell_view.as_ref()).expect("fill");
        let fill = cell_tape.take();
        cell.listing(cell_view.as_ref()).expect("hit");
        (direct_tape.take(), fill, cell_tape.take())
    }

    fn assert_same_recorded_read(
        (direct, fill, hit): (RecordedReads, RecordedReads, RecordedReads),
    ) {
        assert_eq!(direct.len(), 1, "one inventory read: {direct:?}");
        assert!(direct[0].0, "the walk records an inventory read");
        assert!(
            direct[0].1.contains("inventory: Some("),
            "the walk's receipt certifies the listing: {direct:?}"
        );
        assert_eq!(fill, direct, "a fill records what a direct walk records");
        assert_eq!(hit, direct, "a hit replays what the walk recorded");
    }

    fn files() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("workspace");
        std::fs::write(root.path().join("a.cs"), "class A {}").expect("write");
        std::fs::create_dir(root.path().join("sub")).expect("dir");
        std::fs::write(root.path().join("sub/b.cs"), "class B {}").expect("write");
        std::fs::write(root.path().join(".gitignore"), "ignored.cs\n").expect("write");
        std::fs::write(root.path().join("ignored.cs"), "class I {}").expect("write");
        root
    }

    #[test]
    #[hardwon(
        "#13799: a reused workspace listing replayed a default receipt, not the one its walk published"
    )]
    fn reused_listing_records_the_receipt_its_walk_published() {
        let root = files();
        assert_same_recorded_read(direct_fill_and_hit(|| {
            Arc::new(FilesystemProject::new(root.path()).expect("filesystem project"))
        }));
    }

    #[test]
    #[hardwon(
        "#13799: a reused workspace listing replayed a default receipt, not the one its walk published"
    )]
    fn reused_overlay_listing_records_the_receipt_its_walk_published() {
        let root = files();
        assert_same_recorded_read(direct_fill_and_hit(|| {
            let delegate: Arc<dyn Project> =
                Arc::new(FilesystemProject::new(root.path()).expect("filesystem project"));
            Arc::new(OverlayProject::new(delegate))
        }));
    }

    /// Suppression is part of the read semantics: a consumer under
    /// `without_project_reads` records nothing whether it walks or reuses.
    #[test]
    fn suppressed_fill_and_hit_record_nothing() {
        let root = files();
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(root.path()).expect("filesystem project"));
        let tape = recorded(project.as_ref());
        let cell = WorkspaceFileListingCell::default();
        without_project_reads(|| {
            cell.listing(project.as_ref()).expect("suppressed fill");
            cell.listing(project.as_ref()).expect("suppressed hit");
        });
        assert!(tape.take().is_empty());
        cell.listing(project.as_ref()).expect("unsuppressed hit");
        assert_eq!(
            tape.take().len(),
            1,
            "an unsuppressed asker records the read"
        );
    }
    /// Use the production ProjectReadAttribution, including current-capture
    /// registration checks, rather than a recorder that merely logs receipts.
    fn captured_by<T>(
        registries: &[crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry],
        read: impl FnOnce() -> T,
    ) -> (T, Arc<crate::analyzer::ReadLedger>) {
        struct Registered<'a> {
            registries: &'a [crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry],
            context: Arc<AnalyzerQueryContext>,
        }
        impl Drop for Registered<'_> {
            fn drop(&mut self) {
                for registry in self.registries {
                    registry.end_query(&self.context);
                }
            }
        }
        capture_with_read_registration(
            None,
            |context| {
                for registry in registries {
                    registry.begin_query(&context);
                }
                Registered {
                    registries,
                    context,
                }
            },
            read,
        )
    }

    fn assert_same_dependencies(
        expected: &crate::analyzer::ReadLedger,
        actual: &crate::analyzer::ReadLedger,
    ) {
        assert_eq!(actual.keys(), expected.keys());
        assert_eq!(actual.channels(), expected.channels());
    }

    #[test]
    #[hardwon(
        "#13799: live-backed file-set listing hits replaced original inventory owners and receipts"
    )]
    fn live_file_set_listing_replays_original_inventory_dependencies() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::FileSetProject;
        use brokk_bifrost_core::analyzer::project_reads::{
            capture_published_inventory_reads, measure_project_io, replay_published_inventory_reads,
        };

        for both_sources in [false, true] {
            let root = files();
            // .bifrostignore leaves file-tool membership intact but changes
            // inventory ignore decisions, distinguishing the two authorities.
            std::fs::write(root.path().join(".bifrostignore"), "a.cs\n").unwrap();
            let live = Arc::new(FilesystemProject::new(root.path()).unwrap());
            let inventory = live.all_files_shared().unwrap();
            let selected = FileSetProject::from_listing(
                live.root(),
                inventory.iter().map(|file| file.rel_path().to_path_buf()),
                vec![],
            )
            .with_live_delegate(Arc::clone(&live), inventory);
            let mut registries = vec![ProjectReadRegistry::try_new(&selected).unwrap()];
            if both_sources {
                registries.push(ProjectReadRegistry::try_new(live.as_ref()).unwrap());
            }

            let (_, direct) =
                captured_by(&registries, || selected.all_files_with_omissions().unwrap());
            assert!(direct.is_bounded());
            assert_eq!(
                direct.keys().len(),
                if both_sources { 2 } else { 1 },
                "the real .bifrostignore must distinguish file-set and live inventory certificates"
            );
            let cell = WorkspaceFileListingCell::default();
            let (_, fill) = captured_by(&registries, || cell.listing(&selected).unwrap());
            let (_, hit) = captured_by(&registries, || cell.listing(&selected).unwrap());
            assert_same_dependencies(&direct, &fill);
            assert_same_dependencies(&direct, &hit);

            // Capture-of-hit and nested captures at the same getter depth must
            // retain all original owners without replaying the fill twice.
            let ((inner, outer), captured_hit) = captured_by(&registries, || {
                capture_published_inventory_reads(|| {
                    let (_, inner) =
                        capture_published_inventory_reads(|| cell.listing(&selected).unwrap());
                    inner
                })
            });
            assert_same_dependencies(&direct, &captured_hit);
            for captured in [&inner, &outer] {
                let (_, replay) =
                    captured_by(&registries, || replay_published_inventory_reads(captured));
                assert_same_dependencies(&direct, &replay);
            }

            // A suppressed fill is the WorkspaceFileIndex -> C# digest order.
            // The ordinary consumer must keep BOTH the walk and its latent
            // per-source reads, without using the fill's active registrations.
            let suppressed_cell = WorkspaceFileListingCell::default();
            live.invalidate_cached_file_listing();
            let (((), fill_io), suppressed) = captured_by(&registries, || {
                measure_project_io(|| {
                    without_project_reads(|| {
                        suppressed_cell.listing(&selected).unwrap();
                    })
                })
            });
            assert!(
                fill_io.walks > 0,
                "the suppressed fill must perform the real filesystem walk"
            );
            assert!(suppressed.keys().is_empty());
            assert_eq!(suppressed.channels(), ReadChannels::default());
            let walks = live.workspace_file_listing_count();
            let ((_, hit_io), hit) = captured_by(&registries, || {
                measure_project_io(|| {
                    suppressed_cell.listing(&selected).unwrap();
                })
            });
            assert_same_dependencies(&direct, &hit);
            assert_eq!(
                live.workspace_file_listing_count(),
                walks,
                "hit must not list the delegate again"
            );
            assert_eq!(
                hit_io.walks, 0,
                "hit must not physically walk the filesystem"
            );

            let (_, suppressed_hit) = captured_by(&registries, || {
                without_project_reads(|| {
                    suppressed_cell.listing(&selected).unwrap();
                })
            });
            assert!(suppressed_hit.keys().is_empty());
            assert_eq!(suppressed_hit.channels(), ReadChannels::default());

            // Under a real enclosing getter there is one combined inventory,
            // not an independent read for each inner source.
            let (_, nested_direct) = captured_by(&registries, || {
                let _outer = selected.project_read_slot().unwrap().inventory(&selected);
                selected.all_files_with_omissions().unwrap();
            });
            let nested_cell = WorkspaceFileListingCell::default();
            let (_, nested_fill) = captured_by(&registries, || {
                let _outer = selected.project_read_slot().unwrap().inventory(&selected);
                nested_cell.listing(&selected).unwrap();
            });
            let (_, nested_hit) = captured_by(&registries, || {
                let _outer = selected.project_read_slot().unwrap().inventory(&selected);
                nested_cell.listing(&selected).unwrap();
            });
            assert_same_dependencies(&nested_direct, &nested_fill);
            assert_same_dependencies(&nested_direct, &nested_hit);
            let (_, outer_hit) =
                captured_by(&registries, || nested_cell.listing(&selected).unwrap());
            assert_same_dependencies(&direct, &outer_hit);

            if !both_sources {
                // Empty-at-fill original slots must see registrations added
                // later; retaining only the fill's active recorders loses FS.
                registries.push(ProjectReadRegistry::try_new(live.as_ref()).unwrap());
                let (_, now_direct) =
                    captured_by(&registries, || selected.all_files_with_omissions().unwrap());
                let (_, now_hit) =
                    captured_by(&registries, || suppressed_cell.listing(&selected).unwrap());
                assert_eq!(now_direct.keys().len(), 2);
                assert_same_dependencies(&now_direct, &now_hit);
            }
        }
    }

    #[test]
    #[hardwon(
        "#13799: inventory replay must preserve refusal channels and original source-root checks"
    )]
    fn inventory_replay_preserves_incomplete_and_source_root_refusals() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::{
            FileSetProject, IgnoreObservationError, IgnoreObservationOperation,
        };
        use brokk_bifrost_core::analyzer::project_reads::{
            capture_published_inventory_reads, publish_receipt, replay_published_inventory_reads,
        };

        let root = files();
        let other_root = tempfile::tempdir().unwrap();
        let selected = FileSetProject::from_listing(root.path(), [], vec![]);
        let registry = ProjectReadRegistry::try_new(&selected).unwrap();
        // Share its slot with a different source root, as a composite source
        // can do. The actual source root must survive cached replay.
        struct ForeignSource<'a> {
            root: &'a std::path::Path,
            selected: &'a FileSetProject,
        }
        impl Project for ForeignSource<'_> {
            fn root(&self) -> &std::path::Path {
                self.root
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                BTreeSet::new()
            }
            fn project_read_slot(
                &self,
            ) -> Option<&brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot> {
                self.selected.project_read_slot()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                Ok(BTreeSet::new())
            }
            fn analyzable_files(&self, _: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
                Ok(BTreeSet::new())
            }
            fn file_by_rel_path(&self, _: &std::path::Path) -> Option<ProjectFile> {
                None
            }
        }
        let foreign = ForeignSource {
            root: other_root.path(),
            selected: &selected,
        };
        let registries = [registry];
        for source in [&selected as &dyn Project, &foreign as &dyn Project] {
            for incomplete in [false, true] {
                for inventory in [None, Some([9; 32])] {
                    let read = || {
                        let _guard = source.project_read_slot().unwrap().inventory(source);
                        publish_receipt(ProjectReadReceipt {
                            inventory,
                            incomplete: incomplete.then(|| {
                                IgnoreObservationError::new(
                                    source.root(),
                                    IgnoreObservationOperation::Listing,
                                    std::io::Error::other("injected incomplete inventory"),
                                )
                            }),
                            ..ProjectReadReceipt::default()
                        });
                    };
                    let (_, direct) = captured_by(&registries, read);
                    let (((), captured), fill) =
                        captured_by(&registries, || capture_published_inventory_reads(read));
                    let (_, hit) =
                        captured_by(&registries, || replay_published_inventory_reads(&captured));
                    assert_same_dependencies(&direct, &fill);
                    assert_same_dependencies(&direct, &hit);
                    assert_eq!(
                        direct.unattributed_reads(),
                        usize::from(
                            incomplete || inventory.is_none() || source.root() != selected.root()
                        )
                    );
                }
            }
        }
    }
    #[test]
    #[hardwon(
        "#13799: a partially completed listing capture must not survive a panic or failed fill"
    )]
    fn listing_capture_retries_after_partial_failure_and_unwind() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing;
        use brokk_bifrost_core::analyzer::project_reads::{
            capture_published_inventory_reads, replay_published_inventory_reads,
        };
        struct InterruptedListing {
            delegate: Arc<dyn Project>,
            attempts: std::sync::atomic::AtomicUsize,
        }
        impl Project for InterruptedListing {
            fn invalidate_cached_file_listing(&self) {
                self.delegate.invalidate_cached_file_listing();
            }
            fn file_listing_stamp(
                &self,
            ) -> Option<Vec<brokk_bifrost_core::analyzer::project::ProjectViewStamp>> {
                self.delegate.file_listing_stamp()
            }
            fn root(&self) -> &std::path::Path {
                self.delegate.root()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.delegate.analyzer_languages()
            }
            fn project_read_slot(
                &self,
            ) -> Option<&brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot> {
                self.delegate.project_read_slot()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.all_files()
            }
            fn analyzable_files(
                &self,
                language: Language,
            ) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.analyzable_files(language)
            }
            fn file_by_rel_path(&self, path: &std::path::Path) -> Option<ProjectFile> {
                self.delegate.file_by_rel_path(path)
            }
            fn all_files_with_omissions(&self) -> std::io::Result<SharedWorkspaceFileListing> {
                // Complete a real source read before failing: the capture has
                // already collected an effect that must not become an entry.
                let listing = self.delegate.all_files_with_omissions()?;
                match self
                    .attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                {
                    0 => panic!("injected failure after a completed read"),
                    1 => Err(std::io::Error::other("injected listing error")),
                    _ => Ok(listing),
                }
            }
        }
        let root = files();
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.path()).unwrap());
        let registries = [ProjectReadRegistry::try_new(delegate.as_ref()).unwrap()];
        let source = InterruptedListing {
            delegate,
            attempts: std::sync::atomic::AtomicUsize::new(0),
        };
        let cell = WorkspaceFileListingCell::default();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            captured_by(&registries, || cell.listing(&source))
        }));
        assert!(unwound.is_err());
        assert!(
            captured_by(&registries, || cell.listing(&source))
                .0
                .is_err()
        );
        let (_, expected) = captured_by(&registries, || {
            source.delegate.all_files_with_omissions().unwrap()
        });
        let (((), captured), fill) = captured_by(&registries, || {
            capture_published_inventory_reads(|| {
                cell.listing(&source).unwrap();
            })
        });
        let (_, hit) = captured_by(&registries, || cell.listing(&source).unwrap());
        let (_, replay) = captured_by(&registries, || replay_published_inventory_reads(&captured));
        assert_same_dependencies(&expected, &fill);
        assert_same_dependencies(&expected, &hit);
        assert_same_dependencies(&expected, &replay);
        assert_eq!(
            source.attempts.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "neither partial failure was cached, and successful reuse does not call the getter"
        );
    }
    #[test]
    #[hardwon(
        "#13799: cold listing fills retained the pre-getter view stamp and immediately missed on reuse"
    )]
    fn cold_listing_fill_retains_the_completed_view_stamp() {
        use brokk_bifrost_core::analyzer::project::WorkspaceFileListingCache;
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;
        for cached in [false, true] {
            let root = files();
            let project = if cached {
                let cache = Arc::new(WorkspaceFileListingCache::new(
                    root.path().canonicalize().unwrap(),
                ));
                let project =
                    FilesystemProject::with_cached_listing(root.path(), Arc::clone(&cache))
                        .unwrap();
                // Construction eagerly lists this cache. Make the shared
                // cache cold again before the request's first consumer.
                cache.invalidate();
                project
            } else {
                // Keep the constructor seed unconsumed until the cell fills.
                FilesystemProject::new(root.path()).unwrap()
            };
            let before = project.view_stamp();
            let cell = WorkspaceFileListingCell::default();
            let filled = without_project_reads(|| cell.listing(&project).unwrap());
            let completed = project.view_stamp();
            assert_eq!(
                before, completed,
                "consuming a seed or warming a cache must not invalidate the listing view"
            );
            let getters = project.workspace_file_listing_count();
            let (hit, io) = measure_project_io(|| cell.listing(&project).unwrap());
            assert!(Arc::ptr_eq(&filled.0, &hit.0));
            assert!(Arc::ptr_eq(&filled.1, &hit.1));
            assert_eq!(
                project.workspace_file_listing_count(),
                getters,
                "the next consumer must reuse the successful cold fill"
            );
            assert_eq!(
                io.walks, 0,
                "reuse must not physically enumerate the workspace"
            );
            assert_eq!(project.view_stamp(), completed);
        }
    }
    #[test]
    #[hardwon(
        "#13799: an invalidation after a listing getter relabelled old files with the new revision"
    )]
    fn listing_fill_does_not_admit_a_post_getter_invalidation() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::{ProjectViewStamp, WorkspaceFileListingCache};
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        };

        struct AdmissionPause {
            post_sample: mpsc::Sender<()>,
            invalidated: mpsc::Receiver<std::io::Result<()>>,
        }
        struct PausedListing {
            delegate: Arc<FilesystemProject>,
            completed: AtomicBool,
            getters: AtomicUsize,
            pause: Mutex<Option<AdmissionPause>>,
        }
        impl Project for PausedListing {
            fn project_read_slot(
                &self,
            ) -> Option<&brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot> {
                self.delegate.project_read_slot()
            }

            fn invalidate_cached_file_listing(&self) {
                self.delegate.invalidate_cached_file_listing();
            }
            fn root(&self) -> &std::path::Path {
                self.delegate.root()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.delegate.analyzer_languages()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.all_files()
            }
            fn analyzable_files(
                &self,
                language: Language,
            ) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.analyzable_files(language)
            }
            fn file_by_rel_path(&self, path: &std::path::Path) -> Option<ProjectFile> {
                self.delegate.file_by_rel_path(path)
            }
            fn all_files_with_omissions(&self) -> std::io::Result<SharedWorkspaceFileListing> {
                self.getters.fetch_add(1, Ordering::Relaxed);
                let answer = self.delegate.all_files_with_omissions()?;
                self.completed.store(true, Ordering::Release);
                Ok(answer)
            }
            fn file_listing_stamp(&self) -> Option<Vec<ProjectViewStamp>> {
                if self.completed.load(Ordering::Acquire)
                    && let Some(pause) = self.pause.lock().unwrap().take()
                {
                    // The outer getter has returned. Mutate before the cell's
                    // post-getter admission sample, without timing sleeps.
                    pause.post_sample.send(()).unwrap();
                    pause
                        .invalidated
                        .recv()
                        .expect("watcher stopped")
                        .expect("watcher update failed");
                }
                self.delegate.file_listing_stamp()
            }
        }

        for cached in [false, true] {
            let root = files();
            let delegate = Arc::new(if cached {
                let cache = Arc::new(WorkspaceFileListingCache::new(
                    root.path().canonicalize().unwrap(),
                ));
                FilesystemProject::with_cached_listing(root.path(), cache).unwrap()
            } else {
                FilesystemProject::new(root.path()).unwrap()
            });
            let registries = [ProjectReadRegistry::try_new(delegate.as_ref()).unwrap()];
            let (direct_a, reads_a) =
                captured_by(&registries, || delegate.all_files_with_omissions().unwrap());
            let (post_sample_tx, post_sample_rx) = mpsc::channel();
            let (invalidated_tx, invalidated_rx) = mpsc::channel();
            let source = PausedListing {
                delegate: Arc::clone(&delegate),
                completed: AtomicBool::new(false),
                getters: AtomicUsize::new(0),
                pause: Mutex::new(Some(AdmissionPause {
                    post_sample: post_sample_tx,
                    invalidated: invalidated_rx,
                })),
            };
            let watcher = {
                let delegate = Arc::clone(&delegate);
                std::thread::spawn(move || {
                    post_sample_rx.recv().unwrap();
                    let result = std::fs::write(delegate.root().join("new.cs"), "class New {}\n");
                    if result.is_ok() {
                        delegate.invalidate_cached_file_listing();
                    }
                    invalidated_tx.send(result).unwrap();
                })
            };
            let cell = WorkspaceFileListingCell::default();
            let (returned_a, fill_a) = captured_by(&registries, || cell.listing(&source).unwrap());
            watcher.join().unwrap();
            assert_eq!(returned_a.0, direct_a.0);
            assert_same_dependencies(&reads_a, &fill_a);
            let (returned_b, fill_b) = captured_by(&registries, || cell.listing(&source).unwrap());
            assert_eq!(
                returned_b.0.len(),
                returned_a.0.len() + 1,
                "the invalidated answer must not fill a slot under the new revision"
            );
            assert!(returned_b.0.iter().any(|file| file.rel_path().file_name() == Some(std::ffi::OsStr::new("new.cs"))));
            let (direct_b, reads_b) =
                captured_by(&registries, || delegate.all_files_with_omissions().unwrap());
            assert_eq!(returned_b.0, direct_b.0);
            assert_same_dependencies(&reads_b, &fill_b);
            assert_ne!(reads_a.keys(), reads_b.keys());
            let ((hit_b, io), hit_reads) = captured_by(&registries, || {
                measure_project_io(|| cell.listing(&source).unwrap())
            });
            assert!(Arc::ptr_eq(&returned_b.0, &hit_b.0));
            assert_same_dependencies(&reads_b, &hit_reads);
            assert_eq!(source.getters.load(Ordering::Relaxed), 2);
            assert_eq!(io.walks, 0);
        }
    }

    fn cached_listing_fixture() -> (
        tempfile::TempDir,
        brokk_bifrost_core::analyzer::project::IgnoreTestEnvironment,
        Arc<FilesystemProject>,
        Arc<brokk_bifrost_core::analyzer::project::WorkspaceFileListingCache>,
    ) {
        use brokk_bifrost_core::analyzer::project::{
            IgnoreTestEnvironment, WorkspaceFileListingCache, age_ignore_test_inputs,
        };
        let parent = tempfile::tempdir().unwrap();
        // Global git and ignore inputs must resolve under the aged parent. A
        // proxy in the real HOME or XDG tree can be touched by other processes
        // within the racy window, which forces a confirmation walk.
        let env = IgnoreTestEnvironment::new(&parent.path().join("home"));
        let root = parent.path().join("repo");
        let repository = git2::Repository::init(&root).unwrap();
        repository.index().unwrap().write().unwrap();
        std::fs::write(root.join("a.cs"), "class A {}\n").unwrap();
        std::fs::write(root.join(".bifrostignore"), "never-matches-one\n").unwrap();
        age_ignore_test_inputs(&root);
        let root = root.canonicalize().unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            Arc::new(FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap());
        (parent, env, project, cache)
    }

    #[test]
    #[hardwon("#13799: pending equal listings restored a key with an obsolete inventory receipt")]
    fn pending_listing_events_preserve_equal_storage_but_refresh_read_effects() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::{
            RetainedIgnoreObservation, age_ignore_test_inputs,
        };
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;

        let (_parent, _env, project, _cache) = cached_listing_fixture();
        let project = project.as_ref();
        let registries = [ProjectReadRegistry::try_new(project).unwrap()];
        let cell = WorkspaceFileListingCell::default();
        let old = without_project_reads(|| cell.listing(project).unwrap());
        let generic = project.view_stamp();
        let initial_stamp = project.file_listing_stamp();
        let lineage = project.membership_point_observation(&old).unwrap().lineage;
        let (_, old_reads) =
            captured_by(&registries, || project.all_files_with_omissions().unwrap());
        let (((), io), nested) = captured_by(&registries, || {
            measure_project_io(|| {
                let (_, inner) = registries[0].capture_judged(|| {
                    (
                        cell.listing(project).unwrap(),
                        crate::analyzer::reuse_verdict::ReuseVerdict::Content,
                    )
                });
                assert_same_dependencies(&old_reads, &inner);
            })
        });
        assert_eq!(io.walks, 0);
        assert_same_dependencies(&old_reads, &nested);
        assert_eq!(project.file_listing_stamp(), initial_stamp);

        // Inventory asks only about observed paths/decisions. An enclosing
        // IgnoreRules question consumes the aggregate rule publication too.
        let (_, old_rule_reads) = captured_by(&registries, || {
            let _rules = project.project_read_slot().unwrap().ignore_rules(project);
            project.all_files_with_omissions().unwrap()
        });

        let changed = BTreeSet::from([ProjectFile::new(project.root(), ".bifrostignore")]);
        std::fs::write(
            project.root().join(".bifrostignore"),
            "another-nonmatching-pattern\n",
        )
        .unwrap();
        age_ignore_test_inputs(project.root());
        project.revalidate_symlink_omissions(&changed);
        let pending = project.file_listing_stamp();
        // Another invalidating event before materialization must not reuse the
        // preceding pending certificate, even though the pending bit stays set.
        project.revalidate_symlink_omissions(&changed);
        let repeated = project.file_listing_stamp();
        assert_eq!(project.view_stamp(), generic);
        let (filled, fill_reads) = captured_by(&registries, || {
            let _rules = project.project_read_slot().unwrap().ignore_rules(project);
            cell.listing(project).unwrap()
        });
        let (direct, direct_reads) = captured_by(&registries, || {
            let _rules = project.project_read_slot().unwrap().ignore_rules(project);
            project.all_files_with_omissions().unwrap()
        });
        let ((hit, io), hit_reads) = captured_by(&registries, || {
            measure_project_io(|| {
                let _rules = project.project_read_slot().unwrap().ignore_rules(project);
                cell.listing(project).unwrap()
            })
        });
        assert_same_dependencies(&direct_reads, &fill_reads);
        assert_same_dependencies(&direct_reads, &hit_reads);
        assert_ne!(old_rule_reads.keys(), direct_reads.keys());

        let (_, plain_fill) = captured_by(&registries, || cell.listing(project).unwrap());
        let (_, plain_direct) =
            captured_by(&registries, || project.all_files_with_omissions().unwrap());
        let (_, plain_hit) = captured_by(&registries, || cell.listing(project).unwrap());
        assert_same_dependencies(&plain_direct, &plain_fill);
        assert_same_dependencies(&plain_direct, &plain_hit);
        assert_eq!(
            old_reads.keys(),
            plain_direct.keys(),
            "nonmatching rules do not change Inventory"
        );
        assert_same_dependencies(&old_reads, &plain_direct);
        assert_ne!(pending, initial_stamp);
        assert_ne!(repeated, pending);
        assert!(direct_reads.is_bounded());
        assert_eq!(filled.0, direct.0);
        assert!(Arc::ptr_eq(&old.0, &filled.0));
        assert!(Arc::ptr_eq(&old.1, &filled.1));
        assert!(Arc::ptr_eq(&filled.0, &hit.0));
        assert_eq!(project.view_stamp(), generic);
        assert_eq!(project.file_listing_stamp(), repeated);
        assert_eq!(
            project
                .membership_point_observation(&filled)
                .unwrap()
                .lineage,
            lineage
        );
        assert_eq!(io.walks, 0);

        // A real matcher failure keeps its typed cause and refuses reuse of
        // the read set; repairing it never restores the old certificate.
        std::fs::write(project.root().join(".bifrostignore"), "[z-a]\n").unwrap();
        age_ignore_test_inputs(project.root());
        project.revalidate_symlink_omissions(&changed);
        let (_, failed_fill) = captured_by(&registries, || cell.listing(project).unwrap());
        let (failed_listing, failed_direct) =
            captured_by(&registries, || project.all_files_with_omissions().unwrap());
        let (_, failed_hit) = captured_by(&registries, || cell.listing(project).unwrap());
        assert_same_dependencies(&failed_direct, &failed_fill);
        assert_same_dependencies(&failed_direct, &failed_hit);
        assert!(!failed_direct.is_bounded());
        assert!(
            project
                .ignore_observation_for_files(&failed_listing.0)
                .is_err()
        );
        assert!(matches!(
            project.retained_ignore_observation(),
            RetainedIgnoreObservation::Failed(_)
        ));
        std::fs::write(project.root().join(".bifrostignore"), "never-matches-one\n").unwrap();
        age_ignore_test_inputs(project.root());
        project.revalidate_symlink_omissions(&changed);
        let (_, recovered) = captured_by(&registries, || cell.listing(project).unwrap());
        let (_, recovered_direct) =
            captured_by(&registries, || project.all_files_with_omissions().unwrap());
        let (_, recovered_hit) = captured_by(&registries, || cell.listing(project).unwrap());
        assert_same_dependencies(&recovered_direct, &recovered);
        assert_same_dependencies(&recovered_direct, &recovered_hit);
        assert!(recovered.is_bounded());
        assert_ne!(project.file_listing_stamp(), initial_stamp);
    }

    #[test]
    #[hardwon(
        "#13799: removing cold-fill bumps also removed semantic replacement epochs after pending validation"
    )]
    fn pending_changed_membership_advances_semantic_epoch_without_another_walk() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::age_ignore_test_inputs;
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;
        let (_parent, _env, project, _cache) = cached_listing_fixture();
        let project = project.as_ref();
        let cell = WorkspaceFileListingCell::default();
        let old = cell.listing(project).unwrap();
        let before = project.view_stamp();
        let registries = [ProjectReadRegistry::try_new(project).unwrap()];
        std::fs::write(project.root().join("new.cs"), "class New {}\n").unwrap();
        std::fs::write(
            project.root().join(".bifrostignore"),
            "another-absent-pattern\n",
        )
        .unwrap();
        age_ignore_test_inputs(project.root());
        project.revalidate_symlink_omissions(&BTreeSet::from([ProjectFile::new(
            project.root(),
            ".bifrostignore",
        )]));
        let ((changed, io), first_reads) = captured_by(&registries, || {
            measure_project_io(|| cell.listing(project).unwrap())
        });
        assert_eq!(changed.0.len(), old.0.len() + 1);
        assert_ne!(project.view_stamp(), before);
        assert_eq!(io.walks, 1);
        let ((cached, io), next_reads) = captured_by(&registries, || {
            measure_project_io(|| cell.listing(project).unwrap())
        });
        assert!(Arc::ptr_eq(&changed.0, &cached.0));
        assert_same_dependencies(&first_reads, &next_reads);
        assert_eq!(io.walks, 0);
        let (_, final_reads) = captured_by(&registries, || cell.listing(project).unwrap());
        assert_same_dependencies(&next_reads, &final_reads);

        // The same existing owner can be explicitly emptied: warming that
        // empty slot, unlike replacing published contents, is not semantic.
        project.invalidate_cached_file_listing();
        let invalidated = project.view_stamp();
        project.all_files_with_omissions().unwrap();
        assert_eq!(project.view_stamp(), invalidated);
    }

    #[test]
    #[hardwon("#13799: pending validation between getter return and POST admitted an old receipt")]
    fn post_getter_pending_validation_refuses_admission_without_promotion() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::{
            ProjectViewStamp, SharedWorkspaceFileListing, age_ignore_test_inputs,
        };
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct ValidatedAfterGetter {
            delegate: Arc<FilesystemProject>,
            completed: AtomicBool,
            getters: AtomicUsize,
            validate: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        }
        impl Project for ValidatedAfterGetter {
            fn root(&self) -> &std::path::Path {
                self.delegate.root()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.delegate.analyzer_languages()
            }
            fn project_read_slot(
                &self,
            ) -> Option<&brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot> {
                self.delegate.project_read_slot()
            }
            fn file_listing_stamp(&self) -> Option<Vec<ProjectViewStamp>> {
                if self.completed.load(Ordering::Acquire)
                    && let Some(validate) = self.validate.lock().unwrap().take()
                {
                    validate();
                }
                self.delegate.file_listing_stamp()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.all_files()
            }
            fn analyzable_files(
                &self,
                language: Language,
            ) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.analyzable_files(language)
            }
            fn file_by_rel_path(&self, path: &std::path::Path) -> Option<ProjectFile> {
                self.delegate.file_by_rel_path(path)
            }
            fn all_files_with_omissions(&self) -> std::io::Result<SharedWorkspaceFileListing> {
                self.getters.fetch_add(1, Ordering::Relaxed);
                let files = self.delegate.all_files_with_omissions()?;
                self.completed.store(true, Ordering::Release);
                Ok(files)
            }
        }
        let (_parent, _env, project, _cache) = cached_listing_fixture();
        let registries = [ProjectReadRegistry::try_new(project.as_ref()).unwrap()];
        let generic = project.view_stamp();
        let validation_project = Arc::clone(&project);
        let view = ValidatedAfterGetter {
            delegate: project,
            completed: AtomicBool::new(false),
            getters: AtomicUsize::new(0),
            validate: Mutex::new(Some(Box::new(move || {
                std::fs::write(
                    validation_project.root().join(".bifrostignore"),
                    "post-getter-nonmatching-rule\n",
                )
                .unwrap();
                age_ignore_test_inputs(validation_project.root());
                validation_project.revalidate_symlink_omissions(&BTreeSet::from([
                    ProjectFile::new(validation_project.root(), ".bifrostignore"),
                ]));
            }))),
        };
        let cell = WorkspaceFileListingCell::default();
        let (_, old_inventory) = captured_by(&registries, || {
            view.delegate.all_files_with_omissions().unwrap()
        });
        let (_, returned_a) = captured_by(&registries, || {
            let project = view.delegate.as_ref();
            let _rules = project.project_read_slot().unwrap().ignore_rules(project);
            cell.listing(&view).unwrap()
        });
        assert_eq!(view.delegate.view_stamp(), generic);
        assert_eq!(view.getters.load(Ordering::Relaxed), 1);
        let (value_b, returned_b) = captured_by(&registries, || {
            let project = view.delegate.as_ref();
            let _rules = project.project_read_slot().unwrap().ignore_rules(project);
            cell.listing(&view).unwrap()
        });
        assert_ne!(returned_a.keys(), returned_b.keys());
        assert_eq!(
            view.getters.load(Ordering::Relaxed),
            2,
            "raced answer must not have filled the cell"
        );
        let (direct_value, direct_reads) = captured_by(&registries, || {
            let project = view.delegate.as_ref();
            let _rules = project.project_read_slot().unwrap().ignore_rules(project);
            project.all_files_with_omissions().unwrap()
        });
        let ((hit_value, io), hit) = captured_by(&registries, || {
            measure_project_io(|| {
                let project = view.delegate.as_ref();
                let _rules = project.project_read_slot().unwrap().ignore_rules(project);
                cell.listing(&view).unwrap()
            })
        });
        assert_same_dependencies(&direct_reads, &returned_b);
        assert_same_dependencies(&direct_reads, &hit);
        assert!(direct_reads.is_bounded());
        assert!(Arc::ptr_eq(&value_b.0, &direct_value.0));
        assert!(Arc::ptr_eq(&value_b.1, &direct_value.1));
        assert!(Arc::ptr_eq(&value_b.0, &hit_value.0));
        assert!(Arc::ptr_eq(&value_b.1, &hit_value.1));
        assert_eq!(view.getters.load(Ordering::Relaxed), 2);
        assert_eq!(view.delegate.view_stamp(), generic);
        assert_eq!(io.walks, 0);
        let (_, plain_fill) = captured_by(&registries, || cell.listing(&view).unwrap());
        let (_, plain_direct) = captured_by(&registries, || {
            view.delegate.all_files_with_omissions().unwrap()
        });
        let (_, plain_hit) = captured_by(&registries, || cell.listing(&view).unwrap());
        assert_same_dependencies(&plain_direct, &plain_fill);
        assert_same_dependencies(&plain_direct, &plain_hit);
        assert_eq!(
            old_inventory.keys(),
            plain_direct.keys(),
            "nonmatching rules do not change Inventory"
        );
        assert_same_dependencies(&old_inventory, &plain_direct);
        assert_eq!(view.getters.load(Ordering::Relaxed), 2);
    }

    #[test]
    #[hardwon("#13799: unstamped custom listing sources were silently cached as immutable")]
    fn uncertified_listings_are_not_admitted_but_explicit_immutable_views_are() {
        struct UnknownListing<'a>(&'a FilesystemProject);
        impl Project for UnknownListing<'_> {
            fn root(&self) -> &std::path::Path {
                self.0.root()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.0.analyzer_languages()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.0.all_files()
            }
            fn analyzable_files(
                &self,
                language: Language,
            ) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.0.analyzable_files(language)
            }
            fn file_by_rel_path(&self, path: &std::path::Path) -> Option<ProjectFile> {
                self.0.file_by_rel_path(path)
            }
        }
        let root = files();
        let live = FilesystemProject::new(root.path()).unwrap();
        let unknown = UnknownListing(&live);
        assert!(unknown.file_listing_stamp().is_none());
        let cell = WorkspaceFileListingCell::default();
        let before = live.workspace_file_listing_count();
        cell.listing(&unknown).unwrap();
        cell.listing(&unknown).unwrap();
        assert_eq!(live.workspace_file_listing_count(), before + 2);

        let fixed = brokk_bifrost_core::analyzer::project::FileSetProject::from_listing(
            live.root(),
            [std::path::PathBuf::from("a.cs")],
            vec![],
        );
        assert_eq!(fixed.file_listing_stamp().unwrap().len(), 1);
        let first = cell.listing(&fixed).unwrap();
        let second = cell.listing(&fixed).unwrap();
        assert!(Arc::ptr_eq(&first.0, &second.0));
    }

    #[test]
    #[hardwon("#13799: replacing an immutable file set at the same address reused old membership")]
    fn listing_identity_survives_file_set_replacement_in_place() {
        use brokk_bifrost_core::analyzer::project::FileSetProject;

        let root = files();
        let mut view = Box::new(FileSetProject::from_listing(
            root.path(),
            [std::path::PathBuf::from("a.cs")],
            vec![],
        ));
        let address = std::ptr::from_ref(view.as_ref()).addr();
        let cell = WorkspaceFileListingCell::default();
        let a = cell.listing(view.as_ref()).unwrap();
        *view = FileSetProject::from_listing(
            root.path(),
            [std::path::PathBuf::from("sub/b.cs")],
            vec![],
        );
        assert_eq!(std::ptr::from_ref(view.as_ref()).addr(), address);
        let b = cell.listing(view.as_ref()).unwrap();
        assert_eq!(b.0, view.all_files_shared().unwrap());
        assert_ne!(a.0, b.0);
        let hit = cell.listing(view.as_ref()).unwrap();
        assert!(Arc::ptr_eq(&b.0, &hit.0));
    }

    #[test]
    #[hardwon(
        "#13799: equal revisions from a replacement source replayed the previous slot's registrations"
    )]
    fn listing_identity_preserves_replacement_source_registrations() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use brokk_bifrost_core::analyzer::project::{ProjectViewStamp, SharedWorkspaceFileListing};
        use brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot;

        struct Source {
            delegate: Arc<FilesystemProject>,
            slot: ProjectReadSlot,
        }
        impl Project for Source {
            fn root(&self) -> &std::path::Path {
                self.delegate.root()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.delegate.analyzer_languages()
            }
            fn file_listing_stamp(&self) -> Option<Vec<ProjectViewStamp>> {
                self.delegate.file_listing_stamp()
            }
            fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
                Some(&self.slot)
            }
            fn install_read_recorder(
                &self,
                capability: brokk_bifrost_core::analyzer::project_reads::ReadCapability,
            ) -> bool {
                self.slot.install(capability);
                true
            }
            fn ignore_rules_digest(&self) -> std::io::Result<[u8; 32]> {
                self.delegate.ignore_rules_digest()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.all_files_with_omissions()
                    .map(|(files, _)| (*files).clone())
            }
            fn all_files_with_omissions(&self) -> std::io::Result<SharedWorkspaceFileListing> {
                let _read = self.slot.inventory(self);
                self.delegate.all_files_with_omissions()
            }
            fn analyzable_files(
                &self,
                language: Language,
            ) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.delegate.analyzable_files(language)
            }
            fn file_by_rel_path(&self, path: &std::path::Path) -> Option<ProjectFile> {
                self.delegate.file_by_rel_path(path)
            }
        }

        let root = files();
        std::fs::write(root.path().join(".bifrostignore"), "a.cs\n").unwrap();
        let delegate = Arc::new(FilesystemProject::new(root.path()).unwrap());
        let mut view = Box::new(Source {
            delegate: Arc::clone(&delegate),
            slot: ProjectReadSlot::default(),
        });
        let address = std::ptr::from_ref(view.as_ref()).addr();
        let stamp = view.file_listing_stamp();
        let first_registry = [ProjectReadRegistry::try_new(view.as_ref()).unwrap()];
        let cell = WorkspaceFileListingCell::default();
        let (_, first) = captured_by(&first_registry, || cell.listing(view.as_ref()).unwrap());
        assert!(!first.keys().is_empty());
        *view = Source {
            delegate,
            slot: ProjectReadSlot::default(),
        };
        assert_eq!(std::ptr::from_ref(view.as_ref()).addr(), address);
        assert_eq!(view.file_listing_stamp(), stamp);
        let current_registry = [ProjectReadRegistry::try_new(view.as_ref()).unwrap()];
        let (_, direct) = captured_by(&current_registry, || {
            view.all_files_with_omissions().unwrap()
        });
        let (filled, fill) =
            captured_by(&current_registry, || cell.listing(view.as_ref()).unwrap());
        let (hit, reads) = captured_by(&current_registry, || cell.listing(view.as_ref()).unwrap());
        assert!(!direct.keys().is_empty());
        assert_same_dependencies(&direct, &fill);
        assert_same_dependencies(&direct, &reads);
        assert!(Arc::ptr_eq(&filled.0, &hit.0));
    }

    #[test]
    #[hardwon(
        "#13799: mutable multi-root and selected-configuration listings had no currentness stamp"
    )]
    fn mutable_listing_wrappers_preserve_their_real_source_invalidations() {
        use crate::analyzer::tree_sitter_analyzer::ProjectReadRegistry;
        use crate::analyzer::workspace::SelectedConfigurationProject;
        use brokk_bifrost_core::analyzer::project::MultiRootProject;
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;

        let check = |project: &dyn Project, new_file: &std::path::Path| {
            assert!(
                project.view_stamp().is_none(),
                "listing authority must not widen generic view certification"
            );
            let before = project
                .file_listing_stamp()
                .expect("all mutable listing owners participate");
            let registries = [ProjectReadRegistry::try_new(project).unwrap()];
            let cell = WorkspaceFileListingCell::default();
            let old = cell.listing(project).unwrap();
            std::fs::write(new_file, "class New {}\n").unwrap();
            project.invalidate_cached_file_listing();
            assert_ne!(project.file_listing_stamp().unwrap(), before);
            let (updated, fill) = captured_by(&registries, || cell.listing(project).unwrap());
            let (direct, reads) =
                captured_by(&registries, || project.all_files_with_omissions().unwrap());
            assert_eq!(updated.0.len(), old.0.len() + 1);
            assert_eq!(updated.0, direct.0);
            assert_same_dependencies(&reads, &fill);
            let ((hit, io), hit_reads) = captured_by(&registries, || {
                measure_project_io(|| cell.listing(project).unwrap())
            });
            assert!(Arc::ptr_eq(&updated.0, &hit.0));
            assert_same_dependencies(&reads, &hit_reads);
            assert_eq!(io.walks, 0);
        };

        let roots = tempfile::tempdir().unwrap();
        for name in ["first", "second"] {
            std::fs::create_dir(roots.path().join(name)).unwrap();
            std::fs::write(roots.path().join(name).join("app.cs"), "class App {}\n").unwrap();
        }
        let multi =
            MultiRootProject::new([roots.path().join("first"), roots.path().join("second")])
                .unwrap();
        assert_eq!(multi.file_listing_stamp().unwrap().len(), 2);
        check(&multi, &roots.path().join("first/new.cs"));

        let root = files();
        let live: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.path()).unwrap());
        let selected = SelectedConfigurationProject::captured(
            live,
            Language::CSharp,
            Arc::new(Vec::new()),
            &[],
        );
        check(&selected, &root.path().join("new.cs"));

        // The overlay has a real mutable listing even when its delegate is an
        // explicitly immutable file set and supplies no generic view stamp.
        let root = files();
        let fixed = brokk_bifrost_core::analyzer::project::FileSetProject::from_listing(
            root.path(),
            [std::path::PathBuf::from("a.cs")],
            vec![],
        );
        let overlay = OverlayProject::new(Arc::new(fixed));
        assert!(overlay.view_stamp().is_none());
        let before = overlay.file_listing_stamp().unwrap();
        let cell = WorkspaceFileListingCell::default();
        let old = cell.listing(&overlay).unwrap();
        assert!(overlay.set(overlay.root().join("new.cs"), "class New {}\n".to_string()));
        assert_ne!(overlay.file_listing_stamp().unwrap(), before);
        let updated = cell.listing(&overlay).unwrap();
        assert_eq!(updated.0.len(), old.0.len() + 1);
        let (hit, io) = measure_project_io(|| cell.listing(&overlay).unwrap());
        assert!(Arc::ptr_eq(&updated.0, &hit.0));
        assert_eq!(io.walks, 0);
    }
}

#[cfg(test)]
mod captured_cause_tests {
    use super::*;

    fn reasons() -> Vec<QueryReadIncomplete> {
        let gap = |t: &str| QueryReadIncomplete::SemanticEvidenceGap(t.into());
        vec![
            gap("b"),
            gap("a"),
            gap("b"),
            QueryReadIncomplete::ArtifactUnavailable("a".into()),
            QueryReadIncomplete::Cancelled,
            QueryReadIncomplete::Cancelled,
            QueryReadIncomplete::SemanticModelsPending,
            QueryReadIncomplete::SemanticEvidenceUnavailable("u".into()),
            gap("Rust route evidence is incomplete for units []"),
            gap("a"),
        ]
    }

    #[test]
    fn captured_set_membership_equals_vec_contains() {
        let mut old: Vec<QueryReadIncomplete> = Vec::new();
        let mut set = CapturedSet::default();
        for reason in reasons() {
            if !old.contains(&reason) {
                old.push(reason.clone());
            }
            set.insert(&CapturedCause::new(reason));
        }
        let new: Vec<_> = set.items.iter().map(|c| c.reason().clone()).collect();
        assert_eq!(new, old);
    }

    #[test]
    fn merge_chooses_what_merge_optional_chooses() {
        let all = reasons();
        for first in &all {
            for second in &all {
                let old =
                    QueryReadIncomplete::merge_optional(Some(first.clone()), Some(second.clone()))
                        .unwrap();
                let new = CapturedCause::merge(
                    CapturedCause::new(first.clone()),
                    CapturedCause::new(second.clone()),
                );
                assert_eq!(new.reason(), &old, "{first:?} vs {second:?}");
            }
        }
    }

    #[test]
    fn captured_order_equals_the_answer_order_sort() {
        let mut old = reasons();
        old.sort_by_cached_key(QueryReadIncomplete::answer_order_key);
        let mut completion = QueryCompletion::capturing();
        for reason in reasons() {
            completion.record_interned(CapturedCause::new(reason));
        }
        let mut causes = completion.captured.as_ref().unwrap().items.clone();
        causes.sort_by(|a, b| a.order_key().cmp(b.order_key()));
        let mut dedup = Vec::new();
        for reason in old {
            if !dedup.contains(&reason) {
                dedup.push(reason);
            }
        }
        assert_eq!(
            causes
                .iter()
                .map(|c| c.reason().clone())
                .collect::<Vec<_>>(),
            dedup
        );
    }
}
