use crate::analyzer::common::source_identifier_for_target;
use crate::analyzer::usages::common::{
    analyzed_files_for_language, language_for_file, language_for_target,
};
use crate::analyzer::usages::traits::CandidateFileProvider;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, Language, ProjectFile,
    cpp_callable_definitions_share_identity_evidence,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet, set_with_capacity};
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

/// Candidate provider that walks the import graph and type hierarchy.
///
/// 1. Expand the target by polymorphism (target + descendants of its parent class).
/// 2. Add the defining file of every expanded target plus its directory siblings.
/// 3. Add every direct importer of those files when the analyzer exposes
///    [`crate::analyzer::ImportAnalysisProvider`].
pub struct ImportGraphCandidateProvider;

impl ImportGraphCandidateProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ImportGraphCandidateProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateFileProvider for ImportGraphCandidateProvider {
    fn find_candidates(&self, target: &CodeUnit, analyzer: &dyn IAnalyzer) -> HashSet<ProjectFile> {
        find_import_graph_candidates(target, analyzer, None)
    }
}

fn find_import_graph_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> HashSet<ProjectFile> {
    let mut candidates: HashSet<ProjectFile> = set_with_capacity(16);

    // (1) Polymorphic expansion: target + descendants of its parent type.
    let mut all_targets: HashSet<CodeUnit> = set_with_capacity(4);
    all_targets.insert(target.clone());

    // A top-level function's `parent_of` is its enclosing MODULE (a plain FQN-segment pop, not a
    // type-hierarchy relationship) -- only a class parent means "this function is a method that
    // could be polymorphically overridden," which is the only case `get_descendants` needs to
    // answer. Skipping the module case avoids triggering `get_descendants`' full workspace-wide
    // class-hierarchy index build (`build_direct_descendant_index`, `OnceLock`-cached but tens of
    // seconds on a large codebase) for a query -- "what are a module's subclasses" -- that would
    // always return nothing anyway.
    if let Some(provider) = analyzer.type_hierarchy_provider()
        && target.is_function()
        && let Some(parent) = analyzer.parent_of(target)
        && parent.is_class()
    {
        for descendant in provider.get_descendants(&parent) {
            if is_cancelled(cancellation) {
                return candidates;
            }
            all_targets.insert(descendant);
        }
    }

    // (2) Defining files + directory siblings.
    let mut source_files: BTreeSet<ProjectFile> =
        all_targets.iter().map(|cu| cu.source().clone()).collect();
    source_files.extend(cpp_related_callable_source_files(
        &all_targets,
        analyzer,
        cancellation,
    ));

    for source_file in &source_files {
        if is_cancelled(cancellation) {
            return candidates;
        }
        candidates.insert(source_file.clone());

        let parent_dir: PathBuf = source_file
            .rel_path()
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        let language = language_for_file(source_file);

        if language == Language::None {
            continue;
        }

        for file in analyzed_files_for_language(analyzer, language) {
            if is_cancelled(cancellation) {
                return candidates;
            }
            let file_parent: PathBuf = file
                .rel_path()
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_default();
            if file_parent == parent_dir {
                candidates.insert(file);
            }
        }
    }

    // (3) Importers — only if the analyzer exposes import analysis. Ruby
    // `require` chains make a transitive walk necessary: a call site can live
    // in a file that requires an intermediary, rather than the declaration
    // file itself. Python is deliberately excluded here: its analyzer-owned
    // usage index below provides the same structured importer relation (with
    // re-export expansion) without re-resolving every workspace import on
    // every query. Keeping both paths made a warm Python query repeatedly pay
    // for a workspace-wide candidate walk before the index could narrow it.
    if language_for_target(target) != Language::Python
        && let Some(import_provider) = analyzer.import_analysis_provider()
    {
        if let Some(cancellation) = cancellation {
            let importers = if language_for_target(target) == Language::Ruby {
                find_transitive_importers_with_cancellation(
                    analyzer.analyzed_files(),
                    import_provider,
                    &candidates,
                    cancellation,
                )
            } else {
                find_direct_importers_with_cancellation(
                    analyzer.analyzed_files(),
                    import_provider,
                    &source_files,
                    cancellation,
                )
            };
            candidates.extend(importers);
        } else {
            let snapshot: Vec<ProjectFile> = candidates.iter().cloned().collect();
            for source_file in snapshot {
                if is_cancelled(cancellation) {
                    return candidates;
                }
                candidates.extend(import_provider.referencing_files_of(&source_file));
            }
        }
    }

    add_cross_language_jvm_candidates(target, analyzer, &mut candidates, cancellation);

    candidates
}

fn cpp_related_callable_source_files(
    targets: &HashSet<CodeUnit>,
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> BTreeSet<ProjectFile> {
    if !targets
        .iter()
        .any(|target| language_for_target(target) == Language::Cpp && target.is_callable())
    {
        return BTreeSet::new();
    }

    let mut related = BTreeSet::new();
    for target in targets {
        if is_cancelled(cancellation) {
            break;
        }
        if language_for_target(target) != Language::Cpp || !target.is_callable() {
            continue;
        }
        let identifier = source_identifier_for_target(target);
        let target_fqn = target.fq_name();
        for candidate in analyzer.global_usage_definition_index().fqn(&target_fqn) {
            if is_cancelled(cancellation) {
                break;
            }
            if !candidate.is_callable()
                || source_identifier_for_target(&candidate) != identifier
                || candidate.fq_name() != target_fqn
                || candidate.signature() != target.signature()
            {
                continue;
            }
            if cpp_callable_definitions_share_identity_evidence(analyzer, target, &candidate) {
                related.insert(candidate.source().clone());
            }
        }
    }
    related
}

fn find_direct_importers_with_cancellation(
    files: impl IntoIterator<Item = ProjectFile>,
    import_provider: &dyn ImportAnalysisProvider,
    source_files: &BTreeSet<ProjectFile>,
    cancellation: &CancellationToken,
) -> HashSet<ProjectFile> {
    let mut files: Vec<_> = files.into_iter().collect();
    files.sort();
    let import_infos = import_provider.import_infos_for_files(&files);
    // Each candidate's resolution is independent (own cache entries, own store-reader-pool
    // checkout) and the pool is sized for `num_cpus` concurrent readers -- running this
    // workspace-wide loop on a single thread leaves that capacity idle. `ImportAnalysisProvider:
    // Sync` is what makes sharing `import_provider` across the pool sound.
    let importers: Mutex<HashSet<ProjectFile>> = Mutex::new(HashSet::default());
    // `try_for_each` (not `for_each`): returning `Err` on cancellation lets rayon stop dispatching
    // new work across the pool instead of still visiting every remaining file -- with `for_each` a
    // cancelled scan degrades from an immediate `break` to an O(files) pass that just skips work per
    // item, so cancel latency would scale with workspace size instead of staying near-instant.
    let _ = files.par_iter().try_for_each(|candidate| {
        if cancellation.is_cancelled() {
            return Err(());
        }
        if source_files.contains(candidate) {
            return Ok(());
        }
        let imports = import_infos
            .as_ref()
            .and_then(|infos| infos.get(candidate))
            .cloned()
            .unwrap_or_else(|| import_provider.import_info_of(candidate));
        let could_import_target = source_files
            .iter()
            .any(|target| import_provider.could_import_file(candidate, &imports, target));
        if cancellation.is_cancelled() {
            return Err(());
        }
        if could_import_target {
            if let Ok(mut sink) = importers.lock() {
                sink.insert(candidate.clone());
            }
            return Ok(());
        }
        let imported = import_provider
            .imported_code_units_from_infos(candidate, &imports)
            .unwrap_or_else(|| import_provider.imported_code_units_of(candidate));
        if cancellation.is_cancelled() {
            return Err(());
        }
        if imported
            .iter()
            .any(|unit| source_files.contains(unit.source()))
            && let Ok(mut sink) = importers.lock()
        {
            sink.insert(candidate.clone());
        }
        Ok(())
    });
    importers.into_inner().expect("importers set poisoned")
}

fn find_transitive_importers_with_cancellation(
    files: impl IntoIterator<Item = ProjectFile>,
    import_provider: &dyn ImportAnalysisProvider,
    seed_files: &HashSet<ProjectFile>,
    cancellation: &CancellationToken,
) -> HashSet<ProjectFile> {
    let mut files: Vec<_> = files.into_iter().collect();
    files.sort();
    let import_infos = import_provider.import_infos_for_files(&files);
    let mut reverse_edges: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();

    for candidate in files {
        if cancellation.is_cancelled() {
            return HashSet::default();
        }
        let imports = import_infos
            .as_ref()
            .and_then(|infos| infos.get(&candidate))
            .cloned()
            .unwrap_or_else(|| import_provider.import_info_of(&candidate));
        let imported_files = crate::analyzer::resolve_imported_files_from_infos(
            import_provider,
            &candidate,
            &imports,
        );
        for imported_file in imported_files {
            reverse_edges
                .entry(imported_file)
                .or_default()
                .push(candidate.clone());
        }
    }

    let mut importers = HashSet::default();
    let mut visited = seed_files.clone();
    let mut queue: VecDeque<ProjectFile> = seed_files.iter().cloned().collect();
    while let Some(imported_file) = queue.pop_front() {
        if cancellation.is_cancelled() {
            return HashSet::default();
        }
        for importer in reverse_edges.get(&imported_file).into_iter().flatten() {
            if visited.insert(importer.clone()) {
                importers.insert(importer.clone());
                queue.push_back(importer.clone());
            }
        }
    }

    importers
}

/// Add candidate files written in another JVM language when the target's usage
/// strategy can prove references there.
///
/// Java, Scala, and Kotlin share one usage candidate space, so a reference to a
/// type declared in any of them can live in a file of any of the others. This
/// used to be a single pairwise special case (a Java class also collected Scala
/// candidates); expressing it as "for a JVM type target, consider every JVM
/// language" removes the special case rather than adding two more (#1239
/// milestone 4).
///
/// Java static members are also nameable from Scala. The Java strategy proves
/// those member references from an explicit Java type receiver, so Scala files
/// containing the member name must reach that strategy too.
///
/// The membership test is a literal substring scan, and deliberately so: this
/// is candidate *discovery*, whose contract is to over-approximate. Proving that
/// a token in one of these files really names the target is the strategy's job,
/// and it does it from the syntax tree.
fn add_cross_language_jvm_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    candidates: &mut HashSet<ProjectFile>,
    cancellation: Option<&CancellationToken>,
) {
    const JVM_LANGUAGES: [Language; 3] = [Language::Java, Language::Scala, Language::Kotlin];

    let target_language = language_for_target(target);
    if !JVM_LANGUAGES.contains(&target_language) {
        return;
    }

    let target_name = target.identifier();
    let target_fq_name = target.fq_name();
    let candidate_languages: &[Language] = if target.is_class() {
        &JVM_LANGUAGES
    } else if target_language == Language::Java && (target.is_function() || target.is_field()) {
        &[Language::Scala]
    } else {
        return;
    };
    for &language in candidate_languages {
        if language == target_language {
            continue;
        }
        for file in analyzed_files_for_language(analyzer, language) {
            if is_cancelled(cancellation) {
                return;
            }
            if file.is_binary().unwrap_or(true) {
                continue;
            }
            let Ok(source) = file.read_to_string() else {
                continue;
            };
            if source.contains(target_name) || source.contains(&target_fq_name) {
                candidates.insert(file);
            }
        }
    }
}

/// Cheap fallback: scan every analyzable file for the literal identifier as a substring.
///
/// Used when [`ImportGraphCandidateProvider`] returns an empty set on a non-empty analyzer
/// (e.g. languages where the import graph is incomplete or unsupported).
pub struct TextSearchCandidateProvider;

impl TextSearchCandidateProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TextSearchCandidateProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateFileProvider for TextSearchCandidateProvider {
    fn find_candidates(&self, target: &CodeUnit, analyzer: &dyn IAnalyzer) -> HashSet<ProjectFile> {
        find_text_candidates(target, analyzer, None)
    }
}

fn find_text_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> HashSet<ProjectFile> {
    let identifier = source_identifier_for_target(target);
    let companion_identifier = scala_companion_syntax_candidate_identifier(target);
    if identifier.trim().is_empty() && companion_identifier.is_none() {
        return HashSet::default();
    }

    let language = language_for_target(target);

    if language == Language::None {
        return HashSet::default();
    }

    // JS and TS form one runtime module ecosystem: JavaScript tests commonly
    // consume emitted output from TypeScript sources, and the emitted path may
    // not exist in a source-only workspace. Candidate discovery therefore spans
    // both languages; the graph still decides whether each AST hit is proven.
    let files = if matches!(language, Language::JavaScript | Language::TypeScript) {
        analyzer
            .analyzed_files()
            .into_iter()
            .filter(|file| {
                matches!(
                    language_for_file(file),
                    Language::JavaScript | Language::TypeScript
                )
            })
            .collect()
    } else {
        analyzed_files_for_language(analyzer, language)
    };
    if files.is_empty() {
        return HashSet::default();
    }

    let matches: Mutex<HashSet<ProjectFile>> = Mutex::new(HashSet::default());

    files.par_iter().for_each(|file| {
        if is_cancelled(cancellation) {
            return;
        }
        if file.is_binary().unwrap_or(true) {
            return;
        }
        let Ok(content) = file.read_to_string() else {
            return;
        };
        if is_cancelled(cancellation) {
            return;
        }
        if (content.contains(identifier)
            || companion_identifier.is_some_and(|owner| content.contains(owner)))
            && let Ok(mut sink) = matches.lock()
        {
            sink.insert(file.clone());
        }
    });

    matches.into_inner().expect("candidate match set poisoned")
}

/// Candidate provider for path-scoped `scan_usages` queries (called with `paths`).
/// The caller has already named the files to search, so enumerating references
/// workspace-wide — the import-graph walk and the substring scan over every file — is pure
/// waste: whatever it finds is immediately filtered back down to `paths`. This provider skips
/// that sweep and hands the pre-resolved path-scoped files straight to the language strategy,
/// making cost O(paths) instead of O(workspace) per symbol regardless of how common the symbol is.
///
/// The set is filtered to the target's language because
/// [`super::finder::graph_find_usages`] dispatches each query to a single
/// language strategy. JVM type targets retain every JVM-language file. Java
/// member targets also retain Scala files because the Java strategy proves
/// explicit static-owner member references there.
pub struct ExplicitCandidateProvider {
    files: Arc<HashSet<ProjectFile>>,
}

impl ExplicitCandidateProvider {
    pub fn new(files: Arc<HashSet<ProjectFile>>) -> Self {
        Self { files }
    }
}

impl CandidateFileProvider for ExplicitCandidateProvider {
    fn find_candidates(
        &self,
        target: &CodeUnit,
        _analyzer: &dyn IAnalyzer,
    ) -> HashSet<ProjectFile> {
        let language = language_for_target(target);
        // Cross-language files must reach the strategy whenever it has a
        // structured scanner for that target shape.
        const JVM_LANGUAGES: [Language; 3] = [Language::Java, Language::Scala, Language::Kotlin];
        self.files
            .iter()
            .filter(|file| {
                let file_language = language_for_file(file);
                file_language == language
                    || (target.is_class()
                        && JVM_LANGUAGES.contains(&language)
                        && JVM_LANGUAGES.contains(&file_language))
                    || (language == Language::Java
                        && (target.is_function() || target.is_field())
                        && file_language == Language::Scala)
            })
            .cloned()
            .collect()
    }
}

/// Combinator that returns the graph provider's results, or falls back to the text provider
/// when the graph result is empty (mirrors brokk's `UsageFinder.createFallbackProvider`).
pub struct FallbackCandidateProvider<G, T> {
    graph: G,
    text: T,
}

impl<G, T> FallbackCandidateProvider<G, T> {
    pub fn new(graph: G, text: T) -> Self {
        Self { graph, text }
    }
}

impl<G, T> CandidateFileProvider for FallbackCandidateProvider<G, T>
where
    G: CandidateFileProvider,
    T: CandidateFileProvider,
{
    fn find_candidates(&self, target: &CodeUnit, analyzer: &dyn IAnalyzer) -> HashSet<ProjectFile> {
        apply_fallback_policy(
            target,
            analyzer,
            || self.graph.find_candidates(target, analyzer),
            || self.text.find_candidates(target, analyzer),
            || false,
        )
    }
}

fn apply_fallback_policy(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    mut find_graph: impl FnMut() -> HashSet<ProjectFile>,
    mut find_text: impl FnMut() -> HashSet<ProjectFile>,
    is_cancelled: impl Fn() -> bool,
) -> HashSet<ProjectFile> {
    let mut candidates = find_graph();
    if is_cancelled() {
        return candidates;
    }
    if candidates.is_empty() && !analyzer.is_empty() {
        return find_text();
    }
    if should_union_text_candidates(target) {
        candidates.extend(find_text());
    }
    candidates
}

fn should_union_text_candidates(target: &CodeUnit) -> bool {
    let language = language_for_target(target);
    let member = target.short_name().contains('.');
    (language == Language::Python && (target.is_function() || target.is_field()) && member)
        // Dynamic instance receivers can cross unresolved emitted-file import
        // boundaries, so the import graph alone cannot prove candidate absence.
        || (matches!(language, Language::JavaScript | Language::TypeScript)
            && target.is_function()
            && member
            && !target.short_name().ends_with("$static"))
        // Symbolic Scala methods such as `-` and `<` are commonly visible through
        // Predef rather than a source import edge. Text candidates only select
        // files; the Scala AST resolver still proves the exact receiver target.
        || (language == Language::Scala
            && target.is_function()
            && is_scala_symbolic_method_identifier(target.identifier()))
        // `scala.*` is imported implicitly, so ordinary import-graph
        // candidates contain the declaration file but not its consumers.
        // Text search supplies candidate files only; the structured Scala
        // resolver still enforces lexical/import precedence and exact identity.
        || (language == Language::Scala && target.package_name() == "scala")
        // Calls and extractors can use companion syntax without spelling the
        // callable (`pkg.Factory(...)`, `case pkg.Factory(...)`). Scan the
        // terminal stable owner name to admit those files as candidates; the
        // Scala graph still proves the exact object and callable role.
        || scala_companion_syntax_candidate_identifier(target).is_some()
}

fn scala_companion_syntax_candidate_identifier(target: &CodeUnit) -> Option<&str> {
    if language_for_target(target) != Language::Scala
        || !target.is_function()
        || !matches!(target.identifier(), "apply" | "unapply" | "unapplySeq")
    {
        return None;
    }
    let (owner, _) = target.short_name().rsplit_once('.')?; // fqname-M4: package-less short_name owner; fq.parent() would add the package prefix, changing the downstream match
    let terminal = owner.rsplit('.').next()?;
    terminal.strip_suffix('$').filter(|name| !name.is_empty())
}

fn is_scala_symbolic_method_identifier(identifier: &str) -> bool {
    if let Some(operator) = identifier.strip_prefix("unary_") {
        return matches!(operator, "+" | "-" | "!" | "~");
    }
    !identifier.is_empty() && identifier.chars().all(is_scala_ascii_operator_char)
}

fn is_scala_ascii_operator_char(ch: char) -> bool {
    matches!(
        ch,
        '!' | '#'
            | '%'
            | '&'
            | '*'
            | '+'
            | '-'
            | '/'
            | ':'
            | '<'
            | '='
            | '>'
            | '?'
            | '@'
            | '\\'
            | '^'
            | '|'
            | '~'
    )
}

/// Convenience constructor for the standard [`ImportGraphCandidateProvider`] +
/// [`TextSearchCandidateProvider`] fallback chain.
pub fn default_provider()
-> FallbackCandidateProvider<ImportGraphCandidateProvider, TextSearchCandidateProvider> {
    FallbackCandidateProvider::new(
        ImportGraphCandidateProvider::new(),
        TextSearchCandidateProvider::new(),
    )
}

pub(crate) fn find_default_candidates_with_cancellation(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    cancellation: &CancellationToken,
) -> HashSet<ProjectFile> {
    let mut candidates = apply_fallback_policy(
        target,
        analyzer,
        || find_import_graph_candidates(target, analyzer, Some(cancellation)),
        || find_text_candidates(target, analyzer, Some(cancellation)),
        || cancellation.is_cancelled(),
    );
    if !cancellation.is_cancelled() && language_for_target(target) == Language::Python {
        candidates.extend(super::python_graph::python_usage_candidate_files(
            analyzer, target,
        ));
    }
    if !cancellation.is_cancelled() && language_for_target(target) == Language::Rust {
        candidates.extend(super::rust_graph::rust_usage_candidate_files(
            analyzer,
            target,
            cancellation,
        ));
    }
    candidates
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitType, ImportInfo};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CancellingImportProvider {
        cancellation: CancellationToken,
        calls: Arc<AtomicUsize>,
        imported: CodeUnit,
    }

    struct BatchedImportProvider {
        calls: Arc<AtomicUsize>,
        imported: CodeUnit,
    }

    struct FileEdgeProvider {
        edges: HashMap<ProjectFile, HashSet<ProjectFile>>,
        edge_lookups: Arc<AtomicUsize>,
    }

    impl ImportAnalysisProvider for FileEdgeProvider {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> HashSet<CodeUnit> {
            HashSet::default()
        }

        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            HashSet::default()
        }

        fn imported_files_from_infos(
            &self,
            file: &ProjectFile,
            _imports: &[ImportInfo],
        ) -> Option<HashSet<ProjectFile>> {
            self.edge_lookups.fetch_add(1, Ordering::AcqRel);
            Some(self.edges.get(file).cloned().unwrap_or_default())
        }
    }

    impl ImportAnalysisProvider for BatchedImportProvider {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> HashSet<CodeUnit> {
            panic!("batched importer discovery must not hydrate individual import states");
        }

        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            panic!("cancellable discovery must not build the global reverse index");
        }

        fn import_infos_for_files(
            &self,
            files: &[ProjectFile],
        ) -> Option<crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Some(
                files
                    .iter()
                    .cloned()
                    .map(|file| (file, Vec::new()))
                    .collect(),
            )
        }

        fn import_info_of(&self, _file: &ProjectFile) -> Vec<ImportInfo> {
            panic!("batched import facts must be used when available");
        }

        fn imported_code_units_from_infos(
            &self,
            _file: &ProjectFile,
            _imports: &[ImportInfo],
        ) -> Option<HashSet<CodeUnit>> {
            Some([self.imported.clone()].into_iter().collect())
        }
    }

    impl ImportAnalysisProvider for CancellingImportProvider {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> HashSet<CodeUnit> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.cancellation.cancel();
            [self.imported.clone()].into_iter().collect()
        }

        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            panic!("cancellable discovery must not build the global reverse index");
        }

        fn import_info_of(&self, _file: &ProjectFile) -> Vec<ImportInfo> {
            Vec::new()
        }
    }

    #[test]
    fn scala_symbolic_candidate_names_exclude_synthetic_dollar_identifiers() {
        for identifier in ["-", "<", "::", "++", "unary_-", "unary_!"] {
            assert!(
                is_scala_symbolic_method_identifier(identifier),
                "expected Scala operator {identifier:?}"
            );
        }
        for identifier in [
            "",
            "apply",
            "foo+",
            "$anonfun",
            "$plus",
            "`named method`",
            "unary_*",
        ] {
            assert!(
                !is_scala_symbolic_method_identifier(identifier),
                "unexpected Scala operator {identifier:?}"
            );
        }
    }

    #[test]
    fn cancellable_importer_scan_stops_after_current_file_without_recording_partial_work() {
        let root = std::env::temp_dir();
        let target_file = ProjectFile::new(root.clone(), "Target.java");
        let importer = ProjectFile::new(root, "Importer.java");
        let cancellation = CancellationToken::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CancellingImportProvider {
            cancellation: cancellation.clone(),
            calls: Arc::clone(&calls),
            imported: CodeUnit::new(target_file.clone(), CodeUnitType::Class, "pkg", "Target"),
        };

        let importers = find_direct_importers_with_cancellation(
            [importer],
            &provider,
            &[target_file].into_iter().collect(),
            &cancellation,
        );

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(importers.is_empty());
    }

    /// The single-file test above can't exercise real concurrency. This runs enough files through
    /// the now-parallel `par_iter().try_for_each(..)` that many are genuinely in flight at once, and
    /// checks the same cancellation invariant still holds when multiple worker threads can observe
    /// (and race on) the same cancellation flag and the same shared `importers` sink.
    #[test]
    fn cancellable_importer_scan_stops_early_without_recording_partial_work_under_concurrency() {
        let root = std::env::temp_dir();
        let target_file = ProjectFile::new(root.clone(), "Target.java");
        let file_count = 200;
        let importers_input: Vec<ProjectFile> = (0..file_count)
            .map(|i| ProjectFile::new(root.clone(), format!("Importer{i}.java")))
            .collect();
        let cancellation = CancellationToken::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CancellingImportProvider {
            cancellation: cancellation.clone(),
            calls: Arc::clone(&calls),
            imported: CodeUnit::new(target_file.clone(), CodeUnitType::Class, "pkg", "Target"),
        };

        let importers = find_direct_importers_with_cancellation(
            importers_input,
            &provider,
            &[target_file].into_iter().collect(),
            &cancellation,
        );

        assert!(
            importers.is_empty(),
            "a cancelled scan must not record partial matches, even with many files racing \
             concurrently on the same cancellation flag and the same shared sink"
        );
        let observed_calls = calls.load(Ordering::Acquire);
        assert!(
            observed_calls >= 1,
            "at least the file that triggered cancellation should have run"
        );
        assert!(
            observed_calls < file_count,
            "cancellation should stop the scan short of visiting every one of the {file_count} \
             files, got {observed_calls}"
        );
    }

    #[test]
    fn cancellable_importer_scan_uses_batched_import_facts_when_available() {
        let root = std::env::temp_dir();
        let target_file = ProjectFile::new(root.clone(), "Target.java");
        let importer = ProjectFile::new(root, "Importer.java");
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = BatchedImportProvider {
            calls: Arc::clone(&calls),
            imported: CodeUnit::new(target_file.clone(), CodeUnitType::Class, "pkg", "Target"),
        };

        let importers = find_direct_importers_with_cancellation(
            [importer.clone()],
            &provider,
            &[target_file].into_iter().collect(),
            &CancellationToken::default(),
        );

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(importers, [importer].into_iter().collect());
    }

    #[test]
    fn transitive_importer_scan_follows_file_edges_once() {
        let root = std::env::temp_dir();
        let target = ProjectFile::new(root.clone(), "target.rb");
        let loader = ProjectFile::new(root.clone(), "loader.rb");
        let entrypoint = ProjectFile::new(root, "main.rb");
        let edge_lookups = Arc::new(AtomicUsize::new(0));
        let provider = FileEdgeProvider {
            edges: [
                (loader.clone(), [target.clone()].into_iter().collect()),
                (entrypoint.clone(), [loader.clone()].into_iter().collect()),
            ]
            .into_iter()
            .collect(),
            edge_lookups: Arc::clone(&edge_lookups),
        };

        let importers = find_transitive_importers_with_cancellation(
            [target.clone(), loader.clone(), entrypoint.clone()],
            &provider,
            &[target].into_iter().collect(),
            &CancellationToken::default(),
        );

        assert_eq!(
            [loader, entrypoint].into_iter().collect::<HashSet<_>>(),
            importers
        );
        assert_eq!(3, edge_lookups.load(Ordering::Acquire));
    }
}
