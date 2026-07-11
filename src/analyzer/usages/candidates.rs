use crate::analyzer::usages::common::{
    analyzed_files_for_language, language_for_file, language_for_target,
};
use crate::analyzer::usages::traits::CandidateFileProvider;
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashSet, set_with_capacity};
use rayon::prelude::*;
use std::collections::BTreeSet;
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

    if let Some(provider) = analyzer.type_hierarchy_provider()
        && target.is_function()
        && let Some(parent) = analyzer.parent_of(target)
    {
        for descendant in provider.get_descendants(&parent) {
            if is_cancelled(cancellation) {
                return candidates;
            }
            all_targets.insert(descendant);
        }
    }

    // (2) Defining files + directory siblings.
    let source_files: BTreeSet<ProjectFile> =
        all_targets.iter().map(|cu| cu.source().clone()).collect();

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

    // (3) Direct importers — only if the analyzer exposes import analysis.
    if let Some(import_provider) = analyzer.import_analysis_provider() {
        if let Some(cancellation) = cancellation {
            let importers = find_direct_importers_with_cancellation(
                analyzer.analyzed_files(),
                import_provider,
                &source_files,
                cancellation,
            );
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

    add_scala_candidates_for_java_type(target, analyzer, &mut candidates, cancellation);

    candidates
}

fn find_direct_importers_with_cancellation(
    files: impl IntoIterator<Item = ProjectFile>,
    import_provider: &dyn ImportAnalysisProvider,
    source_files: &BTreeSet<ProjectFile>,
    cancellation: &CancellationToken,
) -> HashSet<ProjectFile> {
    let mut files: Vec<_> = files.into_iter().collect();
    files.sort();
    let mut importers = HashSet::default();
    for candidate in files {
        if cancellation.is_cancelled() {
            break;
        }
        if source_files.contains(&candidate) {
            continue;
        }
        let imports = import_provider.import_info_of(&candidate);
        let could_import_target = source_files
            .iter()
            .any(|target| import_provider.could_import_file(&candidate, imports, target));
        if cancellation.is_cancelled() {
            break;
        }
        if could_import_target {
            importers.insert(candidate);
            continue;
        }
        let imported = import_provider.imported_code_units_of(&candidate);
        if cancellation.is_cancelled() {
            break;
        }
        if imported
            .iter()
            .any(|unit| source_files.contains(unit.source()))
        {
            importers.insert(candidate);
        }
    }
    importers
}

fn add_scala_candidates_for_java_type(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    candidates: &mut HashSet<ProjectFile>,
    cancellation: Option<&CancellationToken>,
) {
    if language_for_target(target) != Language::Java || !target.is_class() {
        return;
    }

    let files = analyzed_files_for_language(analyzer, Language::Scala);
    if files.is_empty() {
        return;
    }

    let target_name = target.identifier();
    let target_fq_name = target.fq_name();
    for file in files {
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
    let identifier = target.identifier();
    if identifier.trim().is_empty() {
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
        if content.contains(identifier)
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
/// The set is filtered to the target's language because [`super::finder::graph_find_usages`]
/// dispatches each query to a single language strategy. The one exception is a Java class, whose
/// strategy also scans Scala candidates for cross-language (Scala → Java) usages, so Scala files
/// are kept for that case — mirroring the Scala candidates the workspace-wide path contributes via
/// `add_scala_candidates_for_java_type`. Dropping them would silently lose those usages.
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
        // A Java-class query also resolves usages from Scala source (see the doc comment), so the
        // Scala files must reach the strategy alongside the Java ones.
        let keep_scala_for_java = language == Language::Java && target.is_class();
        self.files
            .iter()
            .filter(|file| {
                let file_language = language_for_file(file);
                file_language == language
                    || (keep_scala_for_java && file_language == Language::Scala)
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
    apply_fallback_policy(
        target,
        analyzer,
        || find_import_graph_candidates(target, analyzer, Some(cancellation)),
        || find_text_candidates(target, analyzer, Some(cancellation)),
        || cancellation.is_cancelled(),
    )
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

    impl ImportAnalysisProvider for CancellingImportProvider {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> HashSet<CodeUnit> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.cancellation.cancel();
            [self.imported.clone()].into_iter().collect()
        }

        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            panic!("cancellable discovery must not build the global reverse index");
        }

        fn import_info_of<'a>(&'a self, _file: &ProjectFile) -> &'a [ImportInfo] {
            &[]
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
}
