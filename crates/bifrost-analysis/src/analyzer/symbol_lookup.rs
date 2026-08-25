use crate::analyzer::common::identifier_addresses_target;
use crate::analyzer::common::language_for_target as code_unit_language;
use crate::analyzer::{CodeUnit, GO_MODULE_SCOPE_SEGMENT, IAnalyzer, Language};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) enum CodeUnitResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous(Vec<CodeUnit>),
    NotFound,
}

/// Why a budgeted fuzzy resolution produced no answer.
///
/// Both arms report the *caller's own* limits back to it, never an analyzer
/// failure: the caller asked for an answer under conditions the selector could
/// not be answered under, and gets those conditions named.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FuzzyResolveStop {
    /// The caller's `keep_going` predicate went false. Nothing was concluded.
    Cancelled,
    /// The selector names more declarations than the caller will process.
    /// `total` is the true count of matched declarations, counted before any
    /// per-declaration store read.
    TooManyCandidates { total: usize, limit: usize },
}

/// One caller's limits on one fuzzy resolution.
///
/// `keep_going` is the caller's budget or cancellation predicate. Every loop
/// here that charges a store read per iteration polls it, so a caller whose
/// budget already expired stops paying for an answer it would discard (#1839;
/// the same rule 575c2ffb applied to the Rust usage walks). The in-memory
/// filter loops that only *count* matches deliberately do not poll: their
/// product is the input to `admits`, and cancelling there would report the
/// caller's clock in place of a verdict already reached. See
/// [`bare_name_resolution`].
///
/// `max_candidates` bounds how many distinct declarations one selector may
/// name before the resolver reports the count instead of building the list.
/// The expensive phase of a fuzzy resolution is per matched declaration -- one
/// `definitions` store read each -- so a selector that tens of thousands of
/// declarations answer costs tens of thousands of reads to produce a candidate
/// list nobody can act on. Skipping that phase and reporting the true count is
/// the `searchtools-too-broad-scope-guards` skip-not-truncate idiom.
#[derive(Clone, Copy)]
pub(crate) struct FuzzyResolveBudget<'a> {
    keep_going: Option<&'a dyn Fn() -> bool>,
    max_candidates: usize,
}

impl<'a> FuzzyResolveBudget<'a> {
    /// No cancellation and no fan-out limit: what every caller that does not
    /// carry a budget has always done.
    pub(crate) fn unbounded() -> Self {
        Self {
            keep_going: None,
            max_candidates: usize::MAX,
        }
    }

    pub(crate) fn new(keep_going: &'a dyn Fn() -> bool, max_candidates: usize) -> Self {
        assert!(
            max_candidates > 0,
            "a fuzzy resolution budget must admit at least one candidate"
        );
        Self {
            keep_going: Some(keep_going),
            max_candidates,
        }
    }

    fn keep_going(&self) -> Result<(), FuzzyResolveStop> {
        match self.keep_going {
            Some(predicate) if !predicate() => Err(FuzzyResolveStop::Cancelled),
            _ => Ok(()),
        }
    }

    fn admits(&self, total: usize) -> Result<(), FuzzyResolveStop> {
        if total > self.max_candidates {
            return Err(FuzzyResolveStop::TooManyCandidates {
                total,
                limit: self.max_candidates,
            });
        }
        Ok(())
    }
}

pub(crate) fn resolve_codeunit_fuzzy(analyzer: &dyn IAnalyzer, input: &str) -> CodeUnitResolution {
    resolve_codeunit_fuzzy_with(analyzer, input, |_| true)
}

/// [`resolve_codeunit_fuzzy`] under a caller's cancellation and fan-out
/// budget. See [`FuzzyResolveBudget`].
pub(crate) fn resolve_codeunit_fuzzy_bounded(
    analyzer: &dyn IAnalyzer,
    input: &str,
    budget: FuzzyResolveBudget<'_>,
) -> Result<CodeUnitResolution, FuzzyResolveStop> {
    resolve_codeunit_fuzzy_bounded_with(analyzer, input, |_| true, budget)
}

/// Resolve the deepest indexed symbol that encloses an unresolved descendant
/// selector. This lets callers associate a newly-added member with its
/// already-indexed owner without guessing at language-specific separators.
pub(crate) fn resolve_enclosing_codeunits(analyzer: &dyn IAnalyzer, input: &str) -> Vec<CodeUnit> {
    let _scope = crate::profiling::scope(format!("resolve_enclosing_codeunits[{input}]"));
    let trimmed = strip_trailing_call_suffix(input.trim());
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut best_depth = 0;
    let mut matches = BTreeMap::new();
    for language in analyzer.languages() {
        for query_path in query_symbol_interpretations(language, &trimmed) {
            if query_path.len() < 2 {
                continue;
            }
            for depth in (1..query_path.len()).rev() {
                if depth < best_depth {
                    break;
                }
                let owner_path = &query_path[..depth];
                let pattern = suffix_search_pattern(language, owner_path);
                if pattern.is_empty() {
                    continue;
                }
                let terminal = owner_path.last().expect("non-empty owner path");

                let mut found_at_depth = false;
                let candidates = if analyzer.has_complete_symbol_lookup_index() {
                    // The identifier index covers every persisted declaration. A
                    // missing owner after this lookup cannot match the suffix
                    // regex, and the regex scan can read millions of rows.
                    analyzer.lookup_candidates_by_identifier(terminal)
                } else {
                    analyzer
                        .search_definitions_by_suffix_pattern(
                            &pattern,
                            &suffix_terminal_identifiers(owner_path),
                            language,
                        )
                        .into_iter()
                        .collect()
                };
                for candidate in candidates {
                    if code_unit_language(&candidate) != language
                        || !codeunit_lookup_aliases(&candidate)
                            .iter()
                            .any(|alias| alias == owner_path || path_ends_with(alias, owner_path))
                    {
                        continue;
                    }
                    if depth > best_depth {
                        best_depth = depth;
                        matches.clear();
                    }
                    insert_match(&mut matches, &candidate);
                    found_at_depth = true;
                }
                if found_at_depth {
                    break;
                }
            }
        }
    }

    let resolved =
        resolution_from_matches(analyzer, matches, |_| true, FuzzyResolveBudget::unbounded())
            .expect("an unbounded enclosing-scope resolution has no stop condition");
    match resolved {
        Some(CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units)) => units,
        Some(CodeUnitResolution::NotFound) | None => Vec::new(),
    }
}

/// Exact, non-fuzzy definition lookup for a fully-qualified name. Returns the
/// matching definitions verbatim (empty if none). Used to short-circuit before
/// file-pattern resolution so canonical names containing `/` (e.g. Go import
/// paths) are never misread as filesystem paths.
pub(crate) fn resolve_codeunit_exact(analyzer: &dyn IAnalyzer, input: &str) -> Vec<CodeUnit> {
    let _scope = crate::profiling::scope(format!("resolve_codeunit_exact[{input}]"));
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let matches: Vec<_> = analyzer.definitions(trimmed).collect();
    let exact: Vec<_> = matches
        .iter()
        .filter(|unit| unit.fq_name() == trimmed)
        .cloned()
        .collect();
    if exact.is_empty() { matches } else { exact }
}

pub(crate) fn resolve_codeunit_fuzzy_with(
    analyzer: &dyn IAnalyzer,
    input: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> CodeUnitResolution {
    resolve_codeunit_fuzzy_bounded_with(analyzer, input, include, FuzzyResolveBudget::unbounded())
        .expect("an unbounded fuzzy resolution has no stop condition")
}

pub(crate) fn resolve_codeunit_fuzzy_bounded_with(
    analyzer: &dyn IAnalyzer,
    input: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    budget: FuzzyResolveBudget<'_>,
) -> Result<CodeUnitResolution, FuzzyResolveStop> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(CodeUnitResolution::NotFound);
    }
    budget.keep_going()?;

    // Bare (single-segment) queries must see same-named members. Otherwise
    // stage 1 (exact) silently returns a lone top-level namesake the instant it
    // finds one, hiding same-terminal-name members and never reaching the
    // one-vs-many ambiguity decision (#1057). Gather the union of the exact
    // top-level hits and the identifier-indexed members, then let
    // `resolution_from_matches` decide Resolved (one distinct declaration) vs
    // Ambiguous (several) with the same fq-keying and type/constructor
    // preference used by the later stages. Non-bare (qualified/anchored)
    // queries are untouched: they already reach members via the suffix stages.
    if let Some(leaf) = bare_query_leaf(analyzer, trimmed)
        && let Some(resolved) = bare_name_resolution(analyzer, trimmed, &leaf, include, budget)?
    {
        return Ok(resolved);
    }

    budget.keep_going()?;
    if let Some(resolved) = exact_resolution(analyzer, trimmed, include) {
        return Ok(resolved);
    }

    let stripped = strip_trailing_call_suffix(trimmed);
    if stripped != trimmed
        && let Some(resolved) = exact_resolution(analyzer, &stripped, include)
    {
        return Ok(resolved);
    }

    // The indexed suffix stage answers only when its answer is *unique*. A
    // query several declarations can answer therefore falls through, and the
    // ambiguity decision below is what reports it. Keep the candidates that
    // stage already matched instead of throwing them away: they are the same
    // candidates the ambiguity decision needs.
    let mut indexed = FuzzyMatches::default();
    match suffix_stage_from_index(analyzer, trimmed, include, budget)? {
        SuffixStageOutcome::Decided(resolved) => return Ok(resolved),
        SuffixStageOutcome::Undecided(matches) => indexed.merge(matches),
    }
    if stripped != trimmed {
        match suffix_stage_from_index(analyzer, &stripped, include, budget)? {
            SuffixStageOutcome::Decided(resolved) => return Ok(resolved),
            SuffixStageOutcome::Undecided(matches) => indexed.merge(matches),
        }
    }

    // An analyzer whose indexed lookups cover every persisted declaration has
    // already seen, in the stage above, every candidate a whole-workspace scan
    // could match: a full or suffix alias comparison can only succeed when the
    // query path's tail equals an alias tail, and an alias tail is a spelling
    // of the persisted `identifier` that the stage seeks (the same reasoning
    // the #1688 conclusive-miss gate and the #1688 suffix seek rest on).
    //
    // Materializing the workspace to re-derive them cost, on the #1758
    // workspace, 443.1 s and 4.4 GB to build a `Vec` of 3,480,147 `CodeUnit`s
    // -- plus one whole-workspace live-path scan per language inside each of
    // those reads, 55 of them at 6.63 s across the request -- to feed a match
    // loop that takes 2.6 s.
    if analyzer.has_complete_symbol_lookup_index() {
        let full = resolution_from_matches(analyzer, indexed.full, include, budget)?;
        let resolved = match full {
            Some(resolved) => Some(resolved),
            None => resolution_from_matches(analyzer, indexed.suffix, include, budget)?,
        };
        return Ok(resolved.unwrap_or(CodeUnitResolution::NotFound));
    }

    // No complete index to seek (in-memory and third-party analyzers, whose
    // `lookup_candidates_by_*` default to empty): the workspace scan is the
    // only candidate source they have.
    let query_inputs = if stripped == trimmed {
        vec![trimmed]
    } else {
        vec![trimmed, stripped.as_str()]
    };
    let declarations = {
        let _scope = crate::profiling::scope("resolve_codeunit_fuzzy.materialize_declarations");
        analyzer.get_all_declarations()
    };
    let _scan_scope = crate::profiling::scope(format!(
        "resolve_codeunit_fuzzy.full_scan[{} declarations]",
        declarations.len()
    ));
    let mut full_matches = BTreeMap::new();
    let mut suffix_matches = BTreeMap::new();
    // The per-language interpretations plus the terminal segment of each
    // interpretation. Both a full match (`query_paths.contains`) and a suffix
    // match (`path_ends_with`) require the query's terminal segment to equal
    // some segment of a candidate alias, and every alias segment is a
    // separator-delimited run of the candidate's raw name strings, so the
    // terminals support an allocation-free prefilter over this whole-index
    // scan (a no-match lookup previously built alias sets for every
    // declaration in the workspace and took seconds; #1430, #1419).
    struct LanguageQueryPaths {
        paths: BTreeSet<Vec<String>>,
        terminals: BTreeSet<String>,
    }
    let mut query_paths_by_language: BTreeMap<Language, LanguageQueryPaths> = BTreeMap::new();

    for candidate in &declarations {
        budget.keep_going()?;
        let language = code_unit_language(candidate);
        let query = query_paths_by_language.entry(language).or_insert_with(|| {
            let paths: BTreeSet<Vec<String>> = query_inputs
                .iter()
                .flat_map(|query| resolution_query_interpretations(language, query))
                .collect();
            let terminals = paths
                .iter()
                .filter_map(|path| path.last().cloned())
                .collect();
            LanguageQueryPaths { paths, terminals }
        });
        if query.paths.is_empty() {
            continue;
        }
        if !candidate_has_terminal_segment(candidate, &query.terminals) {
            continue;
        }
        collect_fuzzy_matches(
            analyzer,
            candidate,
            include,
            &query.paths,
            &mut full_matches,
            &mut suffix_matches,
        );
    }

    let full = resolution_from_matches(analyzer, full_matches, include, budget)?;
    let resolved = match full {
        Some(resolved) => Some(resolved),
        None => resolution_from_matches(analyzer, suffix_matches, include, budget)?,
    };
    Ok(resolved.unwrap_or(CodeUnitResolution::NotFound))
}

/// Whether `input` is a bare (single-segment) terminal name in every language
/// in play — the queries that must see same-named members instead of silently
/// resolving a lone top-level namesake (#1057). Exposed so the `get_symbol_sources`
/// surface, which otherwise short-circuits on an exact fully-qualified hit, can
/// route bare names through the member-aware fuzzy resolver while keeping
/// qualified names on their exact-first path.
pub(crate) fn is_bare_symbol_query(analyzer: &dyn IAnalyzer, input: &str) -> bool {
    let trimmed = input.trim();
    !trimmed.is_empty() && bare_query_leaf(analyzer, trimmed).is_some()
}

/// A query is "bare" when, for every language in play, all of its structured
/// interpretations are a single terminal segment (no `.`/`::`/`/`/`+`
/// structure). Returns that shared terminal leaf so the caller can gather
/// same-named members from the identifier index; returns `None` (fall through
/// to the normal staged resolution) for qualified queries or when the
/// languages disagree on the leaf. Derived entirely from the existing
/// structured interpretation helpers — no string hand-parsing.
fn bare_query_leaf(analyzer: &dyn IAnalyzer, trimmed: &str) -> Option<String> {
    let languages = analyzer.languages();
    let all_single_segment = languages.iter().all(|&language| {
        let paths = query_symbol_interpretations(language, trimmed);
        !paths.is_empty() && paths.iter().all(|path| path.len() == 1)
    });
    if !all_single_segment {
        return None;
    }

    let leaves: BTreeSet<String> = languages
        .iter()
        .filter_map(|&language| symbol_selector_leaf(language, trimmed))
        .collect();
    (leaves.len() == 1)
        .then(|| leaves.into_iter().next())
        .flatten()
}

/// Union of (a) exact top-level definitions of the bare query and (b) every
/// declaration whose terminal identifier equals `leaf` (members included, via
/// the indexed identifier lookup), keyed by fq-name exactly as stages 2-3.
/// Yields `Resolved` for one distinct declaration and `Ambiguous` for several;
/// returns `None` when the union is empty so the caller falls through to the
/// existing stages and NotFound handling is untouched.
fn bare_name_resolution(
    analyzer: &dyn IAnalyzer,
    trimmed: &str,
    leaf: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    budget: FuzzyResolveBudget<'_>,
) -> Result<Option<CodeUnitResolution>, FuzzyResolveStop> {
    // Neither accumulation loop below polls `keep_going`, and that is the
    // point. Both are cheap in-memory filters over rows two indexed store
    // reads have already produced (306 ms for 22,177 rows on the rustc tree;
    // 11.7 ms to filter them), and what they produce is the deduplicated match
    // count -- the input to the fan-out gate at the top of
    // `resolution_from_matches`. Polling here meant a caller whose budget
    // expired during those two reads got a bare `Cancelled` instead of the
    // structured `TooManyCandidates` the count was about to justify, because
    // `keep_going` is asked before `admits` is ever reached. Measured on the
    // rustc tree: the `main` cell returned `time_budget` and never evaluated
    // its own gate (`.agents/docs/gate-cell-overhead-2026-08.md`). The budget
    // still governs everything expensive: the per-match `definitions` reads in
    // `resolution_from_matches` poll it per match, and the caller polls it
    // again on entry to the next resolution stage.
    let mut matches = BTreeMap::new();
    for definition in analyzer.definitions(trimmed) {
        if include(&definition) {
            insert_match(&mut matches, &definition);
        }
    }
    // One indexed lookup answers "how many declarations carry this name" for
    // the whole workspace. On a large tree that count reaches the tens of
    // thousands for a name like `main`, and each of them costs a store read in
    // `resolution_from_matches` below -- so the count has to be taken here,
    // before that phase, not discovered by paying for it (#1839).
    for candidate in analyzer.lookup_candidates_by_identifier(leaf) {
        // `identifier_addresses_target`, not `identifier() == leaf`: the
        // indexed lookup is keyed on the spelling a caller can address, and a
        // C# generic type or a TypeScript static member is addressed by a
        // source spelling its persisted identifier decorates. Re-filtering on
        // the raw identifier would drop exactly those declarations, and a bare
        // query would then silently resolve a lone same-named namesake instead
        // of reporting the ambiguity this function exists to report (#1057).
        if include(&candidate) && identifier_addresses_target(&candidate, leaf) {
            insert_match(&mut matches, &candidate);
        }
    }
    resolution_from_matches(analyzer, matches, include, budget)
}

pub(crate) fn strip_trailing_call_suffix(symbol: &str) -> String {
    if !symbol.ends_with(')') {
        return symbol.to_string();
    }

    let Some(open_paren) = symbol.rfind('(') else {
        return symbol.to_string();
    };
    if !symbol[open_paren + 1..symbol.len() - 1].contains(')') {
        let prefix = &symbol[..open_paren];
        if prefix
            .chars()
            .last()
            .map(|ch| ch.is_alphanumeric() || ch == '_')
            .unwrap_or(false)
        {
            return prefix.to_string();
        }
    }

    symbol.to_string()
}

fn exact_resolution(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
    let _scope = crate::profiling::scope(format!("exact_resolution[{symbol}]"));
    let definitions = matching_definitions(analyzer, symbol, include);
    (!definitions.is_empty()).then_some(CodeUnitResolution::Resolved(definitions))
}

fn matching_definitions(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    analyzer
        .definitions(symbol)
        .filter(|code_unit| include(code_unit))
        .collect()
}

/// Declarations one indexed suffix stage matched, keyed by fq name exactly as
/// [`collect_fuzzy_matches`] keys them: `full` for an alias that equals a query
/// path, `suffix` for one that ends with it.
#[derive(Default)]
struct FuzzyMatches {
    full: BTreeMap<String, CodeUnit>,
    suffix: BTreeMap<String, CodeUnit>,
}

impl FuzzyMatches {
    /// Union with `other`. The maps dedup by fq name and the first insertion
    /// wins, matching `insert_match`, so merging the two accepted spellings of
    /// one query yields the same map a single pass over their union would.
    fn merge(&mut self, other: Self) {
        for (fq_name, unit) in other.full {
            self.full.entry(fq_name).or_insert(unit);
        }
        for (fq_name, unit) in other.suffix {
            self.suffix.entry(fq_name).or_insert(unit);
        }
    }
}

/// What one run of the indexed suffix stage concluded.
enum SuffixStageOutcome {
    /// The stage reached a conclusion: return it verbatim. Either a unique
    /// resolution, or the #1688 conclusive miss.
    Decided(CodeUnitResolution),
    /// No unique answer. These are the candidates the stage matched, for the
    /// caller's ambiguity decision.
    Undecided(FuzzyMatches),
}

fn suffix_stage_from_index(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    budget: FuzzyResolveBudget<'_>,
) -> Result<SuffixStageOutcome, FuzzyResolveStop> {
    let _scope = crate::profiling::scope(format!("suffix_resolution_from_index[{symbol}]"));
    let stage1_scope = crate::profiling::scope("suffix_resolution.short_name_stage");
    let mut exact_matches = BTreeMap::new();
    let mut exact_suffix_matches = BTreeMap::new();
    let query_paths_by_language: BTreeMap<_, BTreeSet<_>> = analyzer
        .languages()
        .into_iter()
        .map(|language| (language, resolution_query_interpretations(language, symbol)))
        .collect();
    let terminal_identifiers: BTreeSet<_> = query_paths_by_language
        .values()
        .flat_map(|paths| paths.iter().filter_map(|path| path.last().cloned()))
        .collect();
    let mut indexed_candidates = analyzer.lookup_candidates_by_short_name(symbol);
    // A client can use another accepted separator at an owner boundary. For
    // example, CodeScale used `kvserver/Replica.handleRaftReady` where the Go
    // index renders `kvserver.Replica.handleRaftReady`. The persisted short
    // name includes the receiver, so that spelling misses its short-name key.
    // Use the indexed terminal identifier before the substring fallback. On a
    // large shared cache, that fallback otherwise scans all code_units (#1688).
    for terminal in terminal_identifiers {
        budget.keep_going()?;
        indexed_candidates.extend(analyzer.lookup_candidates_by_identifier(&terminal));
    }
    for candidate in indexed_candidates {
        budget.keep_going()?;
        let language = code_unit_language(&candidate);
        let Some(query_paths) = query_paths_by_language.get(&language) else {
            continue;
        };
        if !include(&candidate) {
            continue;
        }
        collect_fuzzy_matches(
            analyzer,
            &candidate,
            include,
            query_paths,
            &mut exact_matches,
            &mut exact_suffix_matches,
        );
    }
    let no_indexed_matches = exact_matches.is_empty() && exact_suffix_matches.is_empty();
    if let Some(CodeUnitResolution::Resolved(matches)) =
        unique_resolution_from_matches(analyzer, &exact_matches, include, budget)?
    {
        return Ok(SuffixStageOutcome::Decided(CodeUnitResolution::Resolved(
            matches,
        )));
    }

    // The persisted identifier index is complete for tree-sitter analyzers.
    // If it found no alias for the terminal, the suffix regex cannot find a
    // declaration either. Avoid the unbounded SQLite scan on this miss.
    if analyzer.has_complete_symbol_lookup_index() && no_indexed_matches {
        return Ok(SuffixStageOutcome::Decided(CodeUnitResolution::NotFound));
    }
    // Only a *full* stage-1 match may short-circuit. A lone stage-1 suffix
    // match is not evidence that the query resolves uniquely: this stage
    // enumerates through `lookup_candidates_by_short_name`, which the
    // `CodeUnitIndex` contract defines as best-effort ("Implementations return
    // an empty set when they cannot answer this cheaply; callers retain their
    // broader lookup path then"). The pattern stage below is the authority on
    // which declarations a suffix query reaches, and it reaches strictly more
    // of them, because `suffix_search_pattern` treats `$` as a path delimiter
    // and lets Go's module-scope segment be skipped. Returning the lone
    // short-name hit early therefore turned missing recall into a confident
    // wrong answer: `pkg.Foo$Bar` lost its full-match precedence to
    // `pkg.Foo.Bar`, and a genuinely ambiguous `pkg.Name` collapsed onto
    // whichever package the short-name index happened to hold (#1739).

    drop(stage1_scope);

    let _stage2_scope = crate::profiling::scope("suffix_resolution.pattern_stage");
    let mut full_matches = BTreeMap::new();
    let mut suffix_matches = BTreeMap::new();
    for language in analyzer.languages() {
        budget.keep_going()?;
        let query_paths = resolution_query_interpretations(language, symbol);
        if query_paths.iter().all(|path| path.len() < 2) {
            continue;
        }

        for query_path in &query_paths {
            budget.keep_going()?;
            let pattern = suffix_search_pattern(language, query_path);
            if pattern.is_empty() {
                continue;
            }
            for candidate in analyzer.search_definitions_by_suffix_pattern(
                &pattern,
                &suffix_terminal_identifiers(query_path),
                language,
            ) {
                budget.keep_going()?;
                if code_unit_language(&candidate) != language || !include(&candidate) {
                    continue;
                }
                collect_fuzzy_matches(
                    analyzer,
                    &candidate,
                    include,
                    &query_paths,
                    &mut full_matches,
                    &mut suffix_matches,
                );
            }
        }
    }

    let decided = if full_matches.is_empty() {
        unique_resolution_from_matches(analyzer, &suffix_matches, include, budget)?
    } else {
        unique_resolution_from_matches(analyzer, &full_matches, include, budget)?
    };
    if let Some(resolution) = decided {
        return Ok(SuffixStageOutcome::Decided(resolution));
    }

    // Both stages matched against the same query paths with the same
    // `collect_fuzzy_matches`, so their maps union by match kind.
    let mut matched = FuzzyMatches {
        full: exact_matches,
        suffix: exact_suffix_matches,
    };
    matched.merge(FuzzyMatches {
        full: full_matches,
        suffix: suffix_matches,
    });
    Ok(SuffixStageOutcome::Undecided(matched))
}

/// The resolution for `matches` when it names exactly one declaration.
///
/// Borrows rather than consumes: the stage that finds no unique answer hands
/// the same maps to its caller, so only the one-match path pays a copy.
fn unique_resolution_from_matches(
    analyzer: &dyn IAnalyzer,
    matches: &BTreeMap<String, CodeUnit>,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    budget: FuzzyResolveBudget<'_>,
) -> Result<Option<CodeUnitResolution>, FuzzyResolveStop> {
    if matches.len() != 1 {
        return Ok(None);
    }
    resolution_from_matches(analyzer, matches.clone(), include, budget)
}

fn suffix_search_pattern(language: Language, query_path: &[String]) -> String {
    let Some((last, prefix)) = query_path.split_last() else {
        return String::new();
    };
    if prefix.is_empty() {
        return String::new();
    }

    let delimiter = r"(?:\.|::|/|\\|\+|\$)";
    let mut pattern = String::from("(?:^|");
    pattern.push_str(delimiter);
    pattern.push(')');
    for segment in prefix {
        pattern.push_str(&regex::escape(segment));
        pattern.push_str(r"\$?");
        pattern.push_str(delimiter);
        if language == Language::Go {
            pattern.push_str(r"(?:");
            pattern.push_str(&regex::escape(GO_MODULE_SCOPE_SEGMENT));
            pattern.push_str(r"\$?");
            pattern.push_str(delimiter);
            pattern.push_str(r")?");
        }
    }
    pattern.push_str(&regex::escape(last));
    pattern.push_str(r"\$?");
    pattern.push('$');
    pattern
}

/// Every spelling of `query_path`'s tail that one persisted `identifier` value
/// can hold, so a store can answer `suffix_search_pattern` by seeking its
/// `(lang, identifier)` index instead of reading every declaration it has for
/// the language (#1688).
///
/// The pattern accepts any of `. :: / \ + $` between segments, but a store
/// segments `identifier` structurally, and the nesting sigils live *inside* a
/// segment: `pkg.Foo$Bar` is one declaration named `Foo$Bar`, `N.Outer+Inner`
/// one named `Outer+Inner`. Both alias back to the dotted spelling, because
/// `parse_symbol_path` splits an indexed name on those sigils too, so both must
/// be seekable. The pattern also admits a trailing sigil on the terminal (a
/// scala object is indexed as `Foo$`), which every spelling can carry.
fn suffix_terminal_identifiers(query_path: &[String]) -> Vec<String> {
    const NESTING_SIGILS: [&str; 2] = ["$", "+"];

    let terminal = query_path.last().expect("a suffix query path has segments");
    let mut spellings = vec![terminal.clone()];
    for tail_len in 2..=query_path.len() {
        let tail = &query_path[query_path.len() - tail_len..];
        spellings.extend(NESTING_SIGILS.iter().map(|sigil| tail.join(sigil)));
    }
    let sigil_free = spellings.len();
    for index in 0..sigil_free {
        spellings.push(format!("{}$", spellings[index]));
    }
    spellings
}

fn collect_fuzzy_matches(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    query_paths: &BTreeSet<Vec<String>>,
    full_matches: &mut BTreeMap<String, CodeUnit>,
    suffix_matches: &mut BTreeMap<String, CodeUnit>,
) {
    if !include(candidate) {
        return;
    }

    let candidate_paths = codeunit_lookup_aliases(candidate);
    if candidate_paths.is_empty() {
        return;
    }

    let full_match = candidate_paths
        .iter()
        .any(|candidate_path| query_paths.contains(candidate_path));
    if full_match {
        insert_match(full_matches, candidate);
        return;
    }

    let suffix_match = query_paths.iter().any(|query_path| {
        candidate_paths
            .iter()
            .any(|candidate_path| path_ends_with(candidate_path, query_path))
    });
    if suffix_match {
        let definitions = matching_definitions(analyzer, &candidate.fq_name(), include);
        if definitions.is_empty() {
            insert_match(suffix_matches, candidate);
        } else {
            for definition in definitions {
                insert_match(suffix_matches, &definition);
            }
        }
    }
}

fn insert_match(matches: &mut BTreeMap<String, CodeUnit>, candidate: &CodeUnit) {
    matches
        .entry(candidate.fq_name())
        .or_insert_with(|| candidate.clone());
}

fn resolution_from_matches(
    analyzer: &dyn IAnalyzer,
    mut matches: BTreeMap<String, CodeUnit>,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    budget: FuzzyResolveBudget<'_>,
) -> Result<Option<CodeUnitResolution>, FuzzyResolveStop> {
    // The fan-out gate, before any per-match work. Everything below is one
    // store read per surviving key -- `prefer_types_over_their_owner_named_constructors`
    // asks `parent_of` per JVM-family function and the `_` arm asks
    // `definitions` per key -- so a selector that tens of thousands of
    // declarations answer must be reported by its count here rather than
    // expanded into a candidate list nobody can act on (#1839). The count is
    // the deduplicated matched-declaration count: the constructor pruning
    // below can only shrink it, and running that pruning first would be the
    // very per-match work the gate exists to skip.
    budget.admits(matches.len())?;
    prefer_types_over_their_owner_named_constructors(analyzer, &mut matches);

    match matches.len() {
        0 => Ok(None),
        1 => {
            let fq_name = matches.keys().next().expect("one match").clone();
            let definitions = matching_definitions(analyzer, &fq_name, include);
            if definitions.is_empty() {
                Ok(Some(CodeUnitResolution::Resolved(
                    matches.into_values().collect(),
                )))
            } else {
                Ok(Some(CodeUnitResolution::Resolved(definitions)))
            }
        }
        _ => {
            // Like the `len == 1` arm above, each surviving key in `matches`
            // holds only the single first-inserted representative for its fq
            // name (see `insert_match`'s dedup-by-fq behavior). But a bare
            // name's fq bucket can itself contain multiple independent
            // declarations across files (e.g. several top-level
            // `const Input = ...` arrow functions in different modules, all
            // with empty package -> fq == short_name; see #1087). Re-expand
            // every remaining key to its full set of declarations via
            // `matching_definitions`, falling back to the stored
            // representative when the lookup comes up empty, exactly as the
            // `len == 1` arm does, so ambiguous results surface every
            // candidate instead of silently collapsing cross-file
            // duplicates down to one representative per fq.
            //
            // This expansion must run *after*
            // `prefer_types_over_their_owner_named_constructors` has already
            // pruned constructor-shaped functions above, not before: that
            // filter reasons about one representative CodeUnit per fq key in
            // the dedup'd map (owner/identifier checks against a single
            // `unit`), so it needs the deduplicated shape to stay correct.
            // Expanding first would turn `matches` into a multi-valued
            // collection the filter isn't written to consume, and would risk
            // re-introducing declarations the filter meant to drop before
            // ambiguity was ever computed.
            let mut expanded = Vec::with_capacity(matches.len());
            for (fq_name, representative) in matches {
                budget.keep_going()?;
                let definitions = matching_definitions(analyzer, &fq_name, include);
                if definitions.is_empty() {
                    expanded.push(representative);
                } else {
                    expanded.extend(definitions);
                }
            }
            Ok(Some(CodeUnitResolution::Ambiguous(expanded)))
        }
    }
}

/// A bare type name can also suffix-match that type's owner-named constructor
/// (`pkg.Type` and `pkg.Type.Type`). Prefer the type when both declarations are
/// present, while leaving an explicitly repeated constructor selector and
/// ambiguity between independently declared types untouched.
fn prefer_types_over_their_owner_named_constructors(
    analyzer: &dyn IAnalyzer,
    matches: &mut BTreeMap<String, CodeUnit>,
) {
    let competing_types: BTreeSet<_> = matches
        .values()
        .filter(|unit| unit.is_class())
        .map(CodeUnit::fq_name)
        .collect();
    if competing_types.is_empty() {
        return;
    }

    matches.retain(|_, unit| {
        if !unit.is_function()
            || !matches!(
                code_unit_language(unit),
                Language::Java | Language::CSharp | Language::Cpp
            )
        {
            return true;
        }

        let Some(owner) = analyzer.parent_of(unit) else {
            return true;
        };
        !(owner.is_class()
            && unit.identifier() == owner.identifier()
            && competing_types.contains(&owner.fq_name()))
    });
}

/// Allocation-free over-approximation of "some alias of this candidate has a
/// segment equal to one of `terminals`". Alias paths are built by splitting
/// the candidate's `fq_name` (`package_name` + `.` + `short_name`), `short_name`,
/// and `identifier` on separator characters (plus `$`-trim/`$`-split and
/// receiver-selector variants, which only remove non-identifier characters at
/// segment boundaries), so every alias segment occurs in one of those raw
/// strings delimited by non-identifier characters or the string edge. A miss
/// here therefore proves `collect_fuzzy_matches` cannot match, letting the
/// whole-index fallback scan skip alias construction for nearly every
/// declaration when the query cannot resolve (#1430, #1419).
fn candidate_has_terminal_segment(candidate: &CodeUnit, terminals: &BTreeSet<String>) -> bool {
    terminals.iter().any(|terminal| {
        !terminal.is_empty()
            && [
                candidate.package_name(),
                candidate.short_name(),
                candidate.identifier(),
            ]
            .into_iter()
            .any(|haystack| contains_boundary_delimited(haystack, terminal))
    })
}

fn contains_boundary_delimited(haystack: &str, needle: &str) -> bool {
    let is_boundary = |ch: char| !(ch.is_alphanumeric() || ch == '_');
    let mut start = 0;
    while let Some(found) = haystack[start..].find(needle) {
        let begin = start + found;
        let end = begin + needle.len();
        let before_ok = haystack[..begin]
            .chars()
            .next_back()
            .is_none_or(is_boundary);
        let after_ok = haystack[end..].chars().next().is_none_or(is_boundary);
        if before_ok && after_ok {
            return true;
        }
        // Advance one full character so `start` stays on a char boundary.
        start = begin + haystack[begin..].chars().next().map_or(1, char::len_utf8);
        if start >= haystack.len() {
            return false;
        }
    }
    false
}

fn codeunit_lookup_aliases(code_unit: &CodeUnit) -> BTreeSet<Vec<String>> {
    let mut paths = BTreeSet::new();
    let language = code_unit_language(code_unit);
    insert_path_variants(&mut paths, language, &code_unit.fq_name());
    insert_path_variants(&mut paths, language, code_unit.short_name());
    insert_path_variants(&mut paths, language, code_unit.identifier());
    // The recorded segment boundaries, which the three re-parses above cannot
    // recover. `parse_symbol_path` splits on `.`, `/`, `\` and `+` because it
    // is reading a string with no structure attached; a real segment can
    // contain all of them (a JS/TS object-literal key such as
    // `"data/web-interface.csv"` is one recorded `Member` segment, a Go
    // import-path head is one `Path` segment spelled `github.com`). Without
    // this alias no query could ever match such a declaration by its terminal
    // name, because both sides were being shredded the same wrong way (#2111).
    let structured = code_unit.fq_segment_texts();
    if !structured.is_empty() {
        paths.insert(structured);
    }
    paths
}

/// The readings of a user-supplied selector that *resolution* compares against
/// [`codeunit_lookup_aliases`]: [`query_symbol_interpretations`] plus, when
/// every split reading is multi-segment, the input read as a single terminal
/// segment.
///
/// The split readings alone cannot address a declaration whose terminal segment
/// contains a delimiter character: `data/web-interface.csv` splits into three
/// segments and seeks the identifier index for `csv`, which names nothing. The
/// unsplit reading seeks the identifier the extractor actually recorded, so the
/// declaration is matched on its structured boundary instead of a re-guessed
/// one (#2111).
///
/// Only the resolution stages use this. [`symbol_selector_leaf`] and
/// [`bare_query_leaf`] must keep answering with the *canonical* terminal of a
/// qualified query, which is the split reading's leaf.
fn resolution_query_interpretations(language: Language, input: &str) -> BTreeSet<Vec<String>> {
    let mut paths = query_symbol_interpretations(language, input);
    let trimmed = input.trim();
    if !trimmed.is_empty() && paths.iter().all(|path| path.len() > 1) {
        paths.insert(vec![trimmed.to_string()]);
    }
    paths
}

fn query_symbol_interpretations(language: Language, input: &str) -> BTreeSet<Vec<String>> {
    let mut paths = BTreeSet::new();
    insert_path_variants(&mut paths, language, input);
    let parsed = parse_symbol_path(language, input);
    let aliased = alias_segments(language, &parsed);
    if aliased != parsed && aliased.iter().all(|segment| !segment.is_empty()) {
        paths.insert(aliased);
    }
    paths
}

/// Each segment respelled the way its language also accepts it, or the segments unchanged
/// when it accepts only one spelling.
fn alias_segments(language: Language, segments: &[String]) -> Vec<String> {
    let Some(support) = crate::analyzer::languages::language_support(language) else {
        return segments.to_vec();
    };
    segments
        .iter()
        .map(|segment| support.alias_name_segment(segment).to_string())
        .collect()
}

pub(crate) fn symbol_selector_leaf(language: Language, input: &str) -> Option<String> {
    // A leaf containing whitespace (e.g. the untouched `struct git_refdb`
    // primary reading, kept alongside its tag-stripped variant per #1019) can
    // never be a real indexed identifier, so it cannot be *the* canonical
    // terminal name and must not spoil cross-variant agreement here.
    let leaves: BTreeSet<_> = query_symbol_interpretations(language, input)
        .into_iter()
        .filter_map(|path| path.into_iter().next_back())
        .filter(|leaf| !leaf.contains(char::is_whitespace))
        .collect();
    (leaves.len() == 1)
        .then(|| leaves.into_iter().next())
        .flatten()
}

fn insert_path_variants(paths: &mut BTreeSet<Vec<String>>, language: Language, value: &str) {
    for variant in symbol_path_variants(language, value) {
        if !variant.is_empty() {
            paths.insert(variant);
        }
    }
}

fn symbol_path_variants(language: Language, value: &str) -> Vec<Vec<String>> {
    let primary = if language == Language::Go {
        go_receiver_declaration_selector(value)
            .map(|selector| parse_symbol_path(language, &selector))
            .unwrap_or_else(|| parse_symbol_path(language, value))
    } else {
        parse_symbol_path(language, value)
    };
    if primary.is_empty() {
        return Vec::new();
    }

    let mut variants = vec![primary.clone()];
    let scala_normalized: Vec<_> = primary
        .iter()
        .map(|segment| segment.trim_end_matches('$').to_string())
        .collect();
    if scala_normalized != primary && scala_normalized.iter().all(|segment| !segment.is_empty()) {
        variants.push(scala_normalized);
    }

    let dollar_split = split_segments_on_dollar(&primary);
    if dollar_split != primary {
        variants.push(dollar_split);
    }

    // Respell every variant, not just the primary: a nested C# generic member
    // (`Ns.Outer$Inner`1.Method`) displays as `Ns.Outer.Inner.Method`, so the
    // arity-free dollar-split form has to exist too (xunit/MudBlazor tier-3
    // more-specific-fails). The query side strips arity in
    // query_symbol_interpretations, so without these aliases generic types are
    // unaddressable (#1063).
    let aliased: Vec<Vec<String>> = variants
        .iter()
        .map(|variant| alias_segments(language, variant))
        .filter(|aliased| !aliased.is_empty() && aliased.iter().all(|segment| !segment.is_empty()))
        .collect();
    for variant in aliased {
        if !variants.contains(&variant) {
            variants.push(variant);
        }
    }

    // C/C++ elaborated-type-specifier tags: agents naturally spell C/C++ type
    // references the way a use site requires them (`struct git_refdb`, `enum
    // Color`, `union Value`), but Bifrost indexes the bare type identifier.
    // Offer the tag-stripped spelling as an additional variant so `struct Foo`,
    // `file::struct Foo`, and `file#struct Foo` resolve/ambiguate exactly like
    // the keyword-free `Foo` (#1019).
    if language == Language::Cpp {
        let normalized: Vec<_> = primary
            .iter()
            .map(|segment| strip_cpp_tag_keyword(segment).to_string())
            .collect();
        if normalized != primary && normalized.iter().all(|segment| !segment.is_empty()) {
            variants.push(normalized);
        }
    }

    if language == Language::TypeScript
        && let Some(ts_static) = trim_trailing_static_member_segment(&primary)
    {
        variants.push(ts_static);
    }

    variants
}

/// Strip a leading C/C++ elaborated-type-specifier keyword (`struct`, `enum`,
/// `union`, `class`) from a symbol-selector segment, repeatedly (so `enum
/// class Color` also normalizes to `Color`). No real C/C++ identifier can
/// contain an embedded space, so this only ever fires on client-provided tag
/// syntax, never on an indexed name (#1019).
fn strip_cpp_tag_keyword(segment: &str) -> &str {
    let mut current = segment;
    loop {
        let Some(rest) = ["struct", "enum", "union", "class"]
            .into_iter()
            .find_map(|keyword| current.strip_prefix(keyword))
        else {
            return current;
        };
        if !rest.starts_with(char::is_whitespace) {
            return current;
        }
        let rest = rest.trim_start();
        if rest.is_empty() {
            return current;
        }
        current = rest;
    }
}

fn trim_trailing_static_member_segment(segments: &[String]) -> Option<Vec<String>> {
    let (last, prefix) = segments.split_last()?;
    let member = last.strip_suffix("$static")?;
    if member.is_empty() {
        return None;
    }

    let mut variant = prefix.to_vec();
    variant.push(member.to_string());
    Some(variant)
}

/// The `$`-joined nesting encoding (`Outer$Inner`) read back as separate
/// segments.
///
/// `$` names a join only when it stands *between* two names. A leading `$` has
/// no name to its left, so it is the identifier's own first character -- which
/// is exactly how JS/Angular spells `$LogProvider`, `$http`, and `$q`. It is
/// kept on the segment it belongs to.
///
/// Dropping it was not a cosmetic loss. It minted `LogProvider` as a second
/// reading of the bare query `$LogProvider`, the two readings then disagreed on
/// the terminal leaf, and [`symbol_selector_leaf`] answers `None` on
/// disagreement -- which switched off the whole member-aware bare-name stage in
/// [`bare_query_leaf`] and let a lone top-level namesake silently win over a
/// same-named member (`angular.mock.$LogProvider`; #1057). A trailing `$` is
/// still split off, because that is the Scala object marker the sibling
/// `scala_normalized` variant strips too.
fn split_segments_on_dollar(segments: &[String]) -> Vec<String> {
    segments
        .iter()
        .flat_map(|segment| {
            let body = segment.trim_start_matches('$');
            let leading = &segment[..segment.len() - body.len()];
            let mut parts = body
                .split('$') // fqname-M4: input-edge splitter of a client-supplied symbol path (pre-language, no CodeUnit/fq yet); the sanctioned MCP input boundary
                .filter(|part| !part.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if let Some(first) = parts.first_mut() {
                first.insert_str(0, leading);
            }
            parts
        })
        .collect()
}

/// Split a client- or source-provided qualified-name path into its canonical
/// segments, honoring every separator the language uses (`::`, `.`, `\`, `/`,
/// `+`) plus per-language segment normalization (Go receivers, Rust `r#`
/// raw-identifier escapes, C++ `operator` tokens). The returned segments are
/// separator-free and join with `.` to match how indexed fq strings compose,
/// which is what makes this the structured way to normalize a `::`-qualified
/// reference before an enclosing-scope walk.
///
/// The splitter itself is core-owned: `brokk-bifrost-rust` resolves Rust
/// use-paths through it and cannot depend on analysis.
pub(crate) use brokk_bifrost_core::analyzer::symbol_path::{
    parse_symbol_path, parse_symbol_path_fq,
};

fn go_receiver_declaration_selector(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let receiver_end = trimmed.find(')')?;
    let receiver = trimmed.get(..=receiver_end)?;
    let method = trimmed.get(receiver_end + 1..)?.trim();
    let method = method.strip_prefix('.').unwrap_or(method).trim();
    if method.is_empty() || method.chars().any(char::is_whitespace) {
        return None;
    }

    let (prefix, receiver) = receiver
        .rsplit_once(".(")
        .map(|(prefix, receiver)| (Some(prefix), format!("({receiver}")))
        .unwrap_or((None, receiver.to_string()));
    let receiver_type =
        brokk_bifrost_core::analyzer::symbol_path::normalized_go_client_symbol_segment(&receiver);
    if receiver_type == receiver {
        return None;
    }
    Some(match prefix {
        Some(prefix) => format!("{prefix}.{receiver_type}.{method}"),
        None => format!("{receiver_type}.{method}"),
    })
}

fn path_ends_with(candidate: &[String], query: &[String]) -> bool {
    if query.is_empty() {
        return false;
    }

    let mut candidate_index = candidate.len();
    let mut query_index = query.len();
    while query_index > 0 {
        if candidate_index == 0 {
            return false;
        }
        candidate_index -= 1;
        if candidate[candidate_index] == query[query_index - 1] {
            query_index -= 1;
        } else if candidate[candidate_index] != GO_MODULE_SCOPE_SEGMENT {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::python::PythonAdapter;
    use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use crate::analyzer::{Project, TestProject};
    use std::cell::Cell;
    use std::sync::Arc;

    /// A workspace where one identifier names `count` distinct declarations —
    /// the shape #1839 measured at 20,935 on the rustc tree for `main`.
    fn same_named_declarations(
        count: usize,
    ) -> (tempfile::TempDir, TreeSitterAnalyzer<PythonAdapter>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("pkg")).expect("create pkg");
        std::fs::write(root.join("pkg/__init__.py"), "").expect("write package marker");
        for index in 0..count {
            std::fs::write(
                root.join(format!("pkg/mod_{index}.py")),
                "class Shared:\n    pass\n",
            )
            .expect("write module");
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        (temp, analyzer)
    }

    /// A predicate that survives `polls` questions and then reports the
    /// caller's budget as spent, so the stop point is deterministic rather
    /// than a race against a wall clock.
    fn budget_spent_after(polls: usize) -> impl Fn() -> bool {
        let asked = Cell::new(0usize);
        move || {
            let seen = asked.get();
            asked.set(seen + 1);
            seen < polls
        }
    }

    /// #1839 component 1: the caller's budget reaches the resolver's loops.
    /// Without the polls the resolution runs to completion and charges one
    /// `definitions` read per matched declaration — the 20,935-read storm.
    /// `definitions` reads charged by one resolution in its own fresh request
    /// scope. The fixture is warmed outside any scope first, so the figure is
    /// steady-state store traffic rather than first-touch analysis.
    fn definition_reads_for(
        analyzer: &TreeSitterAnalyzer<PythonAdapter>,
        resolve: impl FnOnce() -> Result<CodeUnitResolution, FuzzyResolveStop>,
    ) -> (Result<CodeUnitResolution, FuzzyResolveStop>, usize) {
        let _scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        analyzer.reset_definition_candidates_query_count_for_test();
        let resolution = resolve();
        let reads = analyzer.definition_candidates_query_count_for_test();
        (resolution, reads)
    }

    #[test]
    fn issue_1839_a_spent_budget_stops_resolution_before_the_per_candidate_reads() {
        let (_temp, analyzer) = same_named_declarations(6);
        let warm = resolve_codeunit_fuzzy(&analyzer, "Shared");
        assert!(
            matches!(&warm, CodeUnitResolution::Ambiguous(units) if units.len() == 6),
            "fixture must offer six same-named declarations: {warm:?}"
        );
        let (_, complete_reads) = definition_reads_for(&analyzer, || {
            Ok(resolve_codeunit_fuzzy(&analyzer, "Shared"))
        });

        let keep_going = budget_spent_after(1);
        let (stopped, stopped_reads) = definition_reads_for(&analyzer, || {
            resolve_codeunit_fuzzy_bounded(
                &analyzer,
                "Shared",
                FuzzyResolveBudget::new(&keep_going, usize::MAX),
            )
        });

        assert!(
            matches!(stopped, Err(FuzzyResolveStop::Cancelled)),
            "a spent budget must stop the resolution: {stopped:?}"
        );
        assert!(
            stopped_reads < complete_reads,
            "a stopped resolution must charge fewer reads than the completed one: \
             {stopped_reads} against {complete_reads}"
        );
    }

    /// #1839 component 3: a selector that too many declarations answer reports
    /// the true count instead of expanding a candidate list nobody can act on.
    /// The count is exact and is taken before any per-candidate store read.
    #[test]
    fn issue_1839_an_over_cap_selector_reports_its_true_count_and_skips_the_expansion() {
        let (_temp, analyzer) = same_named_declarations(6);
        let _ = resolve_codeunit_fuzzy(&analyzer, "Shared");
        let (_, complete_reads) = definition_reads_for(&analyzer, || {
            Ok(resolve_codeunit_fuzzy(&analyzer, "Shared"))
        });

        let keep_going = || true;
        let (over, over_reads) = definition_reads_for(&analyzer, || {
            resolve_codeunit_fuzzy_bounded(
                &analyzer,
                "Shared",
                FuzzyResolveBudget::new(&keep_going, 5),
            )
        });

        match over {
            Err(FuzzyResolveStop::TooManyCandidates { total, limit }) => {
                assert_eq!(6, total, "the reported count must be the true match count");
                assert_eq!(5, limit);
            }
            other => panic!("an over-cap selector must report its count: {other:?}"),
        }
        assert!(
            over_reads < complete_reads,
            "an over-cap selector must skip the per-candidate expansion: \
             {over_reads} reads against {complete_reads}"
        );
    }

    /// #1839 seam 2: the fan-out verdict beats the caller's clock.
    ///
    /// The count that the gate exists to report is fully determined once the
    /// two indexed reads in `bare_name_resolution` return. A caller whose
    /// budget expires during those reads used to get a bare `Cancelled` --
    /// `keep_going` was polled per candidate, before `admits` was ever reached
    /// -- so the tool reported the caller's own clock instead of the answer it
    /// already had. Measured on the rustc tree: the `main` cell reported
    /// `time_budget` and never evaluated its own gate, in every repetition
    /// where resolution ran at all
    /// (`.agents/docs/gate-cell-overhead-2026-08.md`).
    ///
    /// `budget_spent_after(1)` leaves exactly the entry poll in
    /// `resolve_codeunit_fuzzy_bounded_with` alive, so the budget is spent by
    /// the time the accumulation loops run -- deterministically, without a
    /// wall clock.
    #[test]
    fn issue_1839_an_over_cap_selector_reports_its_count_even_on_a_spent_budget() {
        let (_temp, analyzer) = same_named_declarations(6);
        let warm = resolve_codeunit_fuzzy(&analyzer, "Shared");
        assert!(
            matches!(&warm, CodeUnitResolution::Ambiguous(units) if units.len() == 6),
            "fixture must offer six same-named declarations: {warm:?}"
        );

        let keep_going = budget_spent_after(1);
        let outcome = resolve_codeunit_fuzzy_bounded(
            &analyzer,
            "Shared",
            FuzzyResolveBudget::new(&keep_going, 5),
        );

        match outcome {
            Err(FuzzyResolveStop::TooManyCandidates { total, limit }) => {
                assert_eq!(
                    6, total,
                    "the deduplicated match count, not the pre-dedup row count"
                );
                assert_eq!(5, limit);
            }
            other => panic!("a spent budget must not hide the fan-out verdict: {other:?}"),
        }
    }

    /// The same selector one candidate under the cap is untouched: the whole
    /// candidate set resolves exactly as an unbudgeted call resolves it.
    #[test]
    fn issue_1839_an_under_cap_selector_resolves_exactly_as_an_unbudgeted_call() {
        let (_temp, analyzer) = same_named_declarations(6);
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let keep_going = || true;

        let unbudgeted = resolve_codeunit_fuzzy(&analyzer, "Shared");
        let budgeted = resolve_codeunit_fuzzy_bounded(
            &analyzer,
            "Shared",
            FuzzyResolveBudget::new(&keep_going, 6),
        )
        .expect("six candidates are within a six-candidate budget");

        let units = |resolution: &CodeUnitResolution| match resolution {
            CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => {
                units.iter().map(CodeUnit::fq_name).collect::<Vec<_>>()
            }
            CodeUnitResolution::NotFound => Vec::new(),
        };
        assert_eq!(units(&unbudgeted), units(&budgeted));
        assert_eq!(6, units(&budgeted).len());
    }

    #[test]
    fn terminal_segment_prefilter_matches_only_boundary_delimited_occurrences() {
        // The full-scan prefilter must never falsely reject: a query terminal
        // that any alias variant could match has to occur boundary-delimited
        // in one of the raw name strings (fq split, `$`-trim, `$`-split, and
        // receiver-selector variants only remove non-identifier characters).
        assert!(contains_boundary_delimited("overlay.rs", "rs"));
        assert!(contains_boundary_delimited("overlay.rs", "overlay"));
        assert!(contains_boundary_delimited("Foo$", "Foo"));
        assert!(contains_boundary_delimited("A$B", "B"));
        assert!(contains_boundary_delimited(
            "crate::inner::Config",
            "Config"
        ));
        assert!(contains_boundary_delimited("(*T).M", "T"));
        assert!(contains_boundary_delimited("x::operator+", "operator+"));
        assert!(contains_boundary_delimited("rs", "rs"));

        // Identifier-character neighbors are not segment boundaries.
        assert!(!contains_boundary_delimited("parse", "rs"));
        assert!(!contains_boundary_delimited("overlays", "overlay"));
        assert!(!contains_boundary_delimited("wrapper", "rap"));

        // A later boundary-delimited occurrence is still found after an
        // earlier embedded one, and multibyte neighbors do not panic.
        assert!(contains_boundary_delimited("parse.rs", "rs"));
        assert!(!contains_boundary_delimited("héllo", "llo"));
        assert!(contains_boundary_delimited("héllo.llo", "llo"));
    }

    #[test]
    fn parse_symbol_path_fq_renders_to_dot_joined_parse_symbol_path() {
        // The structured input parser must reduce to exactly the legacy
        // `parse_symbol_path(..).join(".")` normalization for every language and
        // every separator spelling, so migrating the enclosing-scope resolver
        // onto it is byte-for-byte behavior-preserving.
        let interner = crate::analyzer::fq_name::segment_interner();
        for (language, input) in [
            (Language::Rust, "inner::Config"),
            (Language::Rust, "DbColumn.r#type"),
            (Language::Cpp, "testing::internal::EachMatcher"),
            (Language::Php, "App\\Models\\User"),
            (Language::Go, "pkg/sub.Thing"),
            (Language::CSharp, "Ns.Outer.Inner"),
        ] {
            let expected = parse_symbol_path(language, input).join(".");
            let fq = parse_symbol_path_fq(language, input, interner);
            assert_eq!(
                fq.display(interner),
                expected,
                "input {input:?} ({language:?}) must round-trip to the dot-joined parse"
            );
            assert_eq!(
                fq.display_native(language, interner),
                expected,
                "input {input:?} ({language:?}) must render identically natively (Unknown never triggers a native rule)"
            );
        }
    }

    #[test]
    fn csharp_generic_member_alias_includes_arity_free_form() {
        let variants = symbol_path_variants(Language::CSharp, "Ns.Top`1.Go");
        assert!(
            variants
                .iter()
                .any(|v| v == &vec!["Ns".to_string(), "Top".to_string(), "Go".to_string()]),
            "arity-free member variant must be offered: {variants:?}"
        );
    }

    #[test]
    fn csharp_nested_generic_member_alias_includes_dollar_split_arity_free_form() {
        let variants = symbol_path_variants(Language::CSharp, "Ns.Outer$Inner`1.Method");
        assert!(
            variants.iter().any(|v| v
                == &vec![
                    "Ns".to_string(),
                    "Outer".to_string(),
                    "Inner".to_string(),
                    "Method".to_string()
                ]),
            "nested arity-free member variant must be offered: {variants:?}"
        );
    }
}
