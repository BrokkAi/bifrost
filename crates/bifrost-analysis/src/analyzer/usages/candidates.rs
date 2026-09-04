use crate::analyzer::common::source_identifier_for_target;
use crate::analyzer::languages::language_support;
use crate::analyzer::usages::common::{
    analyzed_files_for_language, language_for_file, language_for_target,
};
use crate::analyzer::usages::traits::CandidateFileProvider;
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    CodeUnit, DescendantIndexScope, IAnalyzer, ImportAnalysisProvider, ImportReachability,
    Language, ProjectFile, cpp_callable_definitions_share_identity_evidence,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet, set_with_capacity};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
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

/// `scope` is the request's view of the type hierarchy: the deadline the
/// polymorphic expansion below must respect, and the slice of the workspace its
/// descendant index is allowed to cover. `None` is the no-deadline caller
/// (`CandidateFileProvider::find_candidates`, which takes no request state).
fn find_import_graph_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    scope: Option<&DescendantIndexScope<'_>>,
) -> HashSet<ProjectFile> {
    let cancellation = scope.map(DescendantIndexScope::cancellation);
    // The importer walks below read import facts, so this candidate pass owns
    // a request scope for the whole walk (issue #2423).
    let query_scope = AnalyzerQueryScope::new(analyzer);
    let token = query_scope.token();
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
        && !is_constructor_target(target, analyzer)
    {
        // The index build behind this call is the one that used to run past
        // the request's whole budget without ever looking at it (#1748). A
        // `None` means it stopped: everything discovered so far is real, and
        // the finder reports the incompleteness through the completion it
        // already has, so return rather than inventing a second channel.
        let descendants = match scope {
            Some(scope) => match provider.get_descendants_within(&parent, scope) {
                Some(descendants) => descendants,
                None => return candidates,
            },
            None => provider.get_descendants(&parent),
        };
        for descendant in descendants {
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
    let target_language = language_for_target(target);
    // A request-scoped default Rust query immediately enters
    // `PreparedRustUsageQuery`, which derives the complete structured importer
    // closure from binding seeds. Running the generic importer prefetch here
    // resolves every Rust file's imports first and then repeats the same walk.
    // The standalone provider has no prepared phase, so it retains this path.
    let rust_prepared_query_owns_importers = target_language == Language::Rust && scope.is_some();
    // Some languages own a structured transitive reverse-import relation that is both
    // more complete and cheaper than the generic workspace-wide importer walk. Dispatch
    // through the language registry so this framework stays independent of its providers.
    let language_importers_own_candidates = language_support(target_language)
        .and_then(|support| {
            support.transitive_referencing_files(analyzer, &source_files, cancellation)
        })
        .is_some_and(|importers| {
            candidates.extend(importers);
            true
        });
    if target_language != Language::Python
        && !rust_prepared_query_owns_importers
        && !language_importers_own_candidates
        && let Some(import_provider) = analyzer.import_analysis_provider()
    {
        // `analyzer.analyzed_files()` fans out and sorts across every
        // language the workspace has, then `usage_ecosystem_files` throws
        // most of that away by ecosystem -- going straight to the languages
        // that actually share this one avoids paying for every other
        // language's files on every candidate query (issue #1738's shape,
        // same as `CodeUnitIndex::analyzed_files_for_language`'s default).
        let target_ecosystem = UsageEcosystem::of(target_language);
        let ecosystem_files: Vec<ProjectFile> = analyzer
            .languages()
            .into_iter()
            .filter(|&language| UsageEcosystem::of(language) == target_ecosystem)
            .flat_map(|language| analyzer.analyzed_files_for_language(language))
            .collect();
        let importer_files = usage_ecosystem_files(ecosystem_files, target_language);
        if let Some(cancellation) = cancellation {
            let importers = if target_language == Language::Ruby {
                find_transitive_importers_with_cancellation(
                    importer_files,
                    import_provider,
                    token,
                    &candidates,
                    cancellation,
                )
            } else {
                find_direct_importers_with_cancellation(
                    importer_files,
                    import_provider,
                    token,
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

fn is_constructor_target(target: &CodeUnit, analyzer: &dyn IAnalyzer) -> bool {
    analyzer
        .signature_metadata(target)
        .iter()
        .any(|metadata| metadata.callable_is_constructor())
}

/// Files that can name declarations in `target_language` through the usage
/// graph's declared language ecosystem.
///
/// Java, Scala, and Kotlin intentionally share one candidate space, as do
/// JavaScript and TypeScript. Every other supported language is isolated. This
/// boundary must be applied before import prefetch: filtering resolved answers
/// afterwards still pays to hydrate every unrelated language in the workspace.
fn usage_ecosystem_files(
    files: impl IntoIterator<Item = ProjectFile>,
    target_language: Language,
) -> Vec<ProjectFile> {
    let target_ecosystem = UsageEcosystem::of(target_language);
    files
        .into_iter()
        .filter(|file| UsageEcosystem::of(language_for_file(file)) == target_ecosystem)
        .collect()
}

fn cpp_related_callable_source_files(
    targets: &HashSet<CodeUnit>,
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> BTreeSet<ProjectFile> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    if !targets
        .iter()
        .any(|target| language_for_target(target) == Language::Cpp && target.is_callable())
    {
        return BTreeSet::new();
    }

    let mut related = BTreeSet::new();
    let definitions =
        crate::analyzer::AnalyzerDefinitionLookup::new(analyzer, crate::analyzer::Language::None);
    for target in targets {
        if is_cancelled(cancellation) {
            break;
        }
        if language_for_target(target) != Language::Cpp || !target.is_callable() {
            continue;
        }
        let identifier = source_identifier_for_target(target);
        let target_fqn = target.fq_name();
        for candidate in definitions.fqn(&target_fqn) {
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
            if cpp_callable_definitions_share_identity_evidence(analyzer, token, target, &candidate)
            {
                related.insert(candidate.source().clone());
            }
        }
    }
    related
}

fn find_direct_importers_with_cancellation(
    files: impl IntoIterator<Item = ProjectFile>,
    import_provider: &dyn ImportAnalysisProvider,
    token: QueryToken<'_>,
    source_files: &BTreeSet<ProjectFile>,
    cancellation: &CancellationToken,
) -> HashSet<ProjectFile> {
    let mut files: Vec<_> = files.into_iter().collect();
    // Everything from here to the per-candidate loop is workspace-scale and
    // uninterruptible once entered: sorting every analyzed file, and the
    // provider's bulk import-fact read over all of them. Poll before paying
    // for either, so a scan whose budget is already gone stops here rather
    // than at the first candidate.
    if cancellation.is_cancelled() {
        return HashSet::default();
    }
    files.sort();
    let import_infos = import_provider.import_infos_for_files(&files);
    // The walk below is about to ask the provider the same shape of question
    // once per candidate. Every key it will ask about is derivable from the
    // import facts already in hand, so give the provider one chance to resolve
    // the whole set in a batch first (#1748). Providers without a shared
    // lookup do nothing here.
    if cancellation.is_cancelled() {
        return HashSet::default();
    }
    import_provider.prefetch_import_targets(&files, import_infos.as_ref(), cancellation);
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
            .unwrap_or_else(|| import_provider.import_info_of(token, candidate));
        // A single `DoesNotReach` only rules out one target, so the walk keeps
        // asking until a target reaches or one answers `Unknown`. The backstop
        // below is skipped only when EVERY target was proved unreachable
        // (#1730): one undecided pair is enough to need it.
        let mut verdict = ImportReachability::DoesNotReach;
        for target in source_files {
            match import_provider.import_reachability(candidate, &imports, target) {
                ImportReachability::Reaches => {
                    verdict = ImportReachability::Reaches;
                    break;
                }
                ImportReachability::Unknown => verdict = ImportReachability::Unknown,
                ImportReachability::DoesNotReach => {}
            }
        }
        if cancellation.is_cancelled() {
            return Err(());
        }
        match verdict {
            ImportReachability::Reaches => {
                if let Ok(mut sink) = importers.lock() {
                    sink.insert(candidate.clone());
                }
                return Ok(());
            }
            ImportReachability::DoesNotReach => return Ok(()),
            ImportReachability::Unknown => {}
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
    token: QueryToken<'_>,
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
            .unwrap_or_else(|| import_provider.import_info_of(token, &candidate));
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
        let mut files = analyzed_files_for_language(analyzer, Language::JavaScript);
        files.extend(analyzed_files_for_language(analyzer, Language::TypeScript));
        files.sort();
        files
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

    fn is_complete_scope(&self) -> bool {
        true
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
    if should_union_text_candidates(target, analyzer) {
        candidates.extend(find_text());
    }
    candidates
}

fn should_union_text_candidates(target: &CodeUnit, analyzer: &dyn IAnalyzer) -> bool {
    let language = language_for_target(target);
    let member = target.short_name().contains('.');
    (language == Language::Python && (target.is_function() || target.is_field()) && member)
        // Dynamic instance receivers can cross unresolved emitted-file import
        // boundaries, so the import graph alone cannot prove candidate absence.
        // A browser-script namespace field (`WLT.Utils = ...`) is read across
        // files with no import edge at all, so fields need the same union
        // (#1777). Text search only selects files that spell the identifier;
        // the JS/TS graph still proves each receiver.
        || (matches!(language, Language::JavaScript | Language::TypeScript)
            && (target.is_function() || target.is_field())
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
        || is_java_enum_member(target, analyzer)
}

/// Whether `target` is a member declared in a Java `enum` body.
///
/// JLS 14.11 lets a case label on an enum-typed switch spell a constant as a
/// bare simple name: no import, no qualifier, no other mention of the enum
/// anywhere in the reading file. The import graph therefore has no edge to
/// follow from the enum to that reader, and the graph result is not empty
/// either -- the enum's own package always supplies candidates -- so the
/// empty-result fallback never runs and the label site is never offered to the
/// scanner (#2180).
///
/// Text search only *selects files that spell the constant*. The Java scanner
/// still types the switch selector and proves the label against it before it
/// claims a hit (`java/graph/resolver.rs`), so a local variable, a parameter or
/// an `int` switch that happens to share the spelling stays unclaimed.
///
/// [`IAnalyzer::declaration_syntax_kind`] answers with the *enclosing type
/// declaration*, so this admits an ordinary instance field written in an enum
/// body as well as a constant. Separating the two would cost a second parse to
/// read the declaration node's own kind; the over-inclusion is bounded by one
/// enum's field count, so it is not worth that.
///
/// The rule is Java-only on purpose. A Kotlin `when` branch and a Scala pattern
/// match both spell an enum entry through a name their import graphs already
/// carry, so neither language has this blind spot.
fn is_java_enum_member(target: &CodeUnit, analyzer: &dyn IAnalyzer) -> bool {
    language_for_target(target) == Language::Java
        && target.is_field()
        && analyzer.declaration_syntax_kind(target) == Some("enum_declaration")
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

pub(crate) fn find_default_candidates_within(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    scope: &DescendantIndexScope<'_>,
) -> HashSet<ProjectFile> {
    let cancellation = scope.cancellation();
    let candidates = apply_fallback_policy(
        target,
        analyzer,
        || find_import_graph_candidates(target, analyzer, Some(scope)),
        || find_text_candidates(target, analyzer, Some(cancellation)),
        || cancellation.is_cancelled(),
    );
    if !cpp_free_function_requires_written_identifier(target, analyzer)
        || cancellation.is_cancelled()
    {
        return candidates;
    }

    // A C++ free function can be called, have its address taken, or be
    // redeclared only where its source identifier is written. The reverse
    // include closure remains necessary to establish visibility, but shared
    // headers can otherwise admit hundreds of translation units that cannot
    // possibly contain a use. Use the spelling only to narrow file admission;
    // the C++ AST resolver still proves every occurrence reported as a usage.
    let written_identifier_candidates = find_text_candidates(target, analyzer, Some(cancellation));
    if written_identifier_candidates.is_empty() {
        // Preserve the graph result on read failures and for unusual targets
        // whose source identifier cannot be recovered.
        return candidates;
    }
    candidates
        .intersection(&written_identifier_candidates)
        .cloned()
        .collect()
}

fn cpp_free_function_requires_written_identifier(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
) -> bool {
    if language_for_target(target) != Language::Cpp || !target.is_function() {
        return false;
    }
    let identifier = source_identifier_for_target(target);
    !identifier.trim().is_empty()
        && !identifier.starts_with("operator")
        && analyzer
            .parent_of(target)
            .is_none_or(|owner| !owner.is_class())
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::KotlinAnalyzer;
    use crate::analyzer::workspace::EmptyAnalyzer;
    use crate::analyzer::{CodeUnitType, ImportInfo, Language};
    use crate::test_support::AnalyzerFixture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The importer walks take a `QueryToken`, and these tests drive them with
    /// hand-written providers rather than a real analyzer. The scope is opened
    /// over an analyzer that owns nothing: the token is proof that a request
    /// scope is live, never a handle to the analyzer that minted it.
    fn scope_analyzer() -> EmptyAnalyzer {
        EmptyAnalyzer::new(Arc::new(crate::TestProject::new(
            std::env::temp_dir(),
            Language::Java,
        )))
    }

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
        fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
            Arc::new(HashSet::default())
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
        fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
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

        fn import_info_of(&self, _token: QueryToken<'_>, _file: &ProjectFile) -> Vec<ImportInfo> {
            panic!("batched import facts must be used when available");
        }

        fn imported_code_units_from_infos(
            &self,
            _file: &ProjectFile,
            _imports: &[ImportInfo],
        ) -> Option<Arc<HashSet<CodeUnit>>> {
            Some(Arc::new([self.imported.clone()].into_iter().collect()))
        }
    }

    impl ImportAnalysisProvider for CancellingImportProvider {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.cancellation.cancel();
            Arc::new([self.imported.clone()].into_iter().collect())
        }

        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            panic!("cancellable discovery must not build the global reverse index");
        }

        fn import_info_of(&self, _token: QueryToken<'_>, _file: &ProjectFile) -> Vec<ImportInfo> {
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

    /// Constructors do not participate in polymorphic dispatch. Before this
    /// gate, asking for one constructor's usages built Kotlin's complete
    /// descendant index and resolved every unrelated class hierarchy in the
    /// workspace (#1748).
    #[test]
    fn kotlin_constructor_candidates_skip_workspace_descendant_resolution() {
        let unrelated_hierarchy = (0..64)
            .map(|index| format!("open class Base{index}\nclass Child{index} : Base{index}()\n"))
            .collect::<String>();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Kotlin,
            &[
                (
                    "DuplicateColumnException.kt",
                    "package api\nclass DuplicateColumnException(message: String) : Exception(message)\n",
                ),
                ("Unrelated.kt", &unrelated_hierarchy),
            ],
        );
        let analyzer = KotlinAnalyzer::new(Arc::new(fixture.test_project().clone()));
        let constructor = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "api.DuplicateColumnException.DuplicateColumnException")
            .expect("fixture declares the DuplicateColumnException constructor");
        assert!(is_constructor_target(&constructor, &analyzer));

        let cancellation = CancellationToken::default();
        let scope = DescendantIndexScope::whole_workspace(&cancellation);
        analyzer
            .test_hooks()
            .reset_definition_candidates_query_count_for_test();
        let candidates = find_default_candidates_within(&constructor, &analyzer, &scope);
        let definition_queries = analyzer
            .test_hooks()
            .definition_candidates_query_count_for_test();

        assert!(candidates.contains(constructor.source()));
        assert!(
            definition_queries < 8,
            "constructor discovery must not resolve the unrelated workspace hierarchy; got {definition_queries} definition queries"
        );
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

        let scope_analyzer = scope_analyzer();
        let scope = AnalyzerQueryScope::new(&scope_analyzer);
        let token = scope.token();
        let importers = find_direct_importers_with_cancellation(
            [importer],
            &provider,
            token,
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

        let scope_analyzer = scope_analyzer();
        let scope = AnalyzerQueryScope::new(&scope_analyzer);
        let token = scope.token();
        let importers = find_direct_importers_with_cancellation(
            importers_input,
            &provider,
            token,
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

        let scope_analyzer = scope_analyzer();
        let scope = AnalyzerQueryScope::new(&scope_analyzer);
        let token = scope.token();
        let importers = find_direct_importers_with_cancellation(
            [importer.clone()],
            &provider,
            token,
            &[target_file].into_iter().collect(),
            &CancellationToken::default(),
        );

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(importers, [importer].into_iter().collect());
    }

    struct PrefetchingImportProvider {
        prefetched_files: Arc<Mutex<Vec<usize>>>,
        per_candidate_calls: Arc<AtomicUsize>,
        prefetches_before_first_candidate: Arc<AtomicUsize>,
    }

    impl ImportAnalysisProvider for PrefetchingImportProvider {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
            Arc::new(HashSet::default())
        }

        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            panic!("cancellable discovery must not build the global reverse index");
        }

        fn import_info_of(&self, _token: QueryToken<'_>, _file: &ProjectFile) -> Vec<ImportInfo> {
            Vec::new()
        }

        fn could_import_file(
            &self,
            _source_file: &ProjectFile,
            _imports: &[ImportInfo],
            _target: &ProjectFile,
        ) -> bool {
            if self.per_candidate_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.prefetches_before_first_candidate.store(
                    self.prefetched_files
                        .lock()
                        .expect("prefetch record poisoned")
                        .len(),
                    Ordering::Release,
                );
            }
            false
        }

        fn prefetch_import_targets(
            &self,
            files: &[ProjectFile],
            _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
            _cancellation: &CancellationToken,
        ) {
            self.prefetched_files
                .lock()
                .expect("prefetch record poisoned")
                .push(files.len());
        }
    }

    /// #1748: the walk asks the provider the same shape of question once per
    /// workspace file, so a provider whose answer needs a shared lookup must
    /// get one chance to resolve the whole set first. Fails with zero
    /// prefetches before the hook is called.
    #[test]
    fn importer_scan_prefetches_import_targets_once_before_asking_per_candidate() {
        let root = std::env::temp_dir();
        let target_file = ProjectFile::new(root.clone(), "Target.java");
        let candidates: Vec<ProjectFile> = (0..64)
            .map(|index| ProjectFile::new(root.clone(), format!("Candidate{index}.java")))
            .collect();
        let provider = PrefetchingImportProvider {
            prefetched_files: Arc::new(Mutex::new(Vec::new())),
            per_candidate_calls: Arc::new(AtomicUsize::new(0)),
            prefetches_before_first_candidate: Arc::new(AtomicUsize::new(0)),
        };

        let scope_analyzer = scope_analyzer();
        let scope = AnalyzerQueryScope::new(&scope_analyzer);
        let token = scope.token();
        let importers = find_direct_importers_with_cancellation(
            candidates.clone(),
            &provider,
            token,
            &[target_file].into_iter().collect(),
            &CancellationToken::default(),
        );

        assert!(importers.is_empty());
        assert_eq!(
            vec![candidates.len()],
            *provider
                .prefetched_files
                .lock()
                .expect("prefetch record poisoned"),
            "the whole candidate set must be offered to the provider exactly once"
        );
        assert_eq!(
            1,
            provider
                .prefetches_before_first_candidate
                .load(Ordering::Acquire),
            "the batch must run before the first per-candidate question"
        );
        assert_eq!(
            candidates.len(),
            provider.per_candidate_calls.load(Ordering::Acquire)
        );
    }

    /// A cancelled scan must not spend the batch either.
    #[test]
    fn cancelled_importer_scan_skips_the_prefetch_and_the_walk() {
        let root = std::env::temp_dir();
        let target_file = ProjectFile::new(root.clone(), "Target.java");
        let candidate = ProjectFile::new(root, "Candidate.java");
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let provider = PrefetchingImportProvider {
            prefetched_files: Arc::new(Mutex::new(Vec::new())),
            per_candidate_calls: Arc::new(AtomicUsize::new(0)),
            prefetches_before_first_candidate: Arc::new(AtomicUsize::new(0)),
        };

        let scope_analyzer = scope_analyzer();
        let scope = AnalyzerQueryScope::new(&scope_analyzer);
        let token = scope.token();
        let importers = find_direct_importers_with_cancellation(
            [candidate],
            &provider,
            token,
            &[target_file].into_iter().collect(),
            &cancellation,
        );

        assert!(importers.is_empty());
        assert_eq!(0, provider.per_candidate_calls.load(Ordering::Acquire));
        assert!(
            provider
                .prefetched_files
                .lock()
                .expect("prefetch record poisoned")
                .is_empty(),
            "a pre-cancelled scan must not spend the batch either"
        );
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

        let scope_analyzer = scope_analyzer();
        let scope = AnalyzerQueryScope::new(&scope_analyzer);
        let token = scope.token();
        let importers = find_transitive_importers_with_cancellation(
            [target.clone(), loader.clone(), entrypoint.clone()],
            &provider,
            token,
            &[target].into_iter().collect(),
            &CancellationToken::default(),
        );

        assert_eq!(
            [loader, entrypoint].into_iter().collect::<HashSet<_>>(),
            importers
        );
        assert_eq!(3, edge_lookups.load(Ordering::Acquire));
    }

    #[test]
    fn importer_prefetch_scope_follows_language_ecosystems() {
        let root = std::env::temp_dir();
        let files = [
            ProjectFile::new(root.clone(), "lib.rs"),
            ProjectFile::new(root.clone(), "Main.java"),
            ProjectFile::new(root.clone(), "Main.scala"),
            ProjectFile::new(root.clone(), "Main.kt"),
            ProjectFile::new(root.clone(), "app.js"),
            ProjectFile::new(root, "app.ts"),
        ];
        let relative_paths = |selected: Vec<ProjectFile>| {
            selected
                .into_iter()
                .map(|file| file.rel_path().to_string_lossy().into_owned())
                .collect::<BTreeSet<_>>()
        };

        assert_eq!(
            relative_paths(usage_ecosystem_files(files.clone(), Language::Rust)),
            BTreeSet::from(["lib.rs".to_string()])
        );
        assert_eq!(
            relative_paths(usage_ecosystem_files(files.clone(), Language::Java)),
            BTreeSet::from([
                "Main.java".to_string(),
                "Main.kt".to_string(),
                "Main.scala".to_string(),
            ])
        );
        assert_eq!(
            relative_paths(usage_ecosystem_files(files, Language::TypeScript)),
            BTreeSet::from(["app.js".to_string(), "app.ts".to_string()])
        );
    }
}
