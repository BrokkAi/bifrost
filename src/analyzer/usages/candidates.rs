use crate::analyzer::usages::common::{language_for_file, language_for_target};
use crate::analyzer::usages::traits::CandidateFileProvider;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, RubyAnalyzer, resolve_analyzer};
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
        let mut candidates: HashSet<ProjectFile> = set_with_capacity(16);

        // (1) Polymorphic expansion: target + descendants of its parent type.
        let mut all_targets: HashSet<CodeUnit> = set_with_capacity(4);
        all_targets.insert(target.clone());

        if let Some(provider) = analyzer.type_hierarchy_provider()
            && target.is_function()
            && let Some(parent) = analyzer.parent_of(target)
        {
            for descendant in provider.get_descendants(&parent) {
                all_targets.insert(descendant);
            }
        }

        // (2) Defining files + directory siblings.
        let source_files: BTreeSet<ProjectFile> =
            all_targets.iter().map(|cu| cu.source().clone()).collect();

        for source_file in &source_files {
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

            if let Ok(files) = analyzer.project().analyzable_files(language) {
                for file in files {
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
        }

        // (3) Direct importers — only if the analyzer exposes import analysis.
        if let Some(import_provider) = analyzer.import_analysis_provider() {
            let snapshot: Vec<ProjectFile> = candidates.iter().cloned().collect();
            for source_file in snapshot {
                for importer in import_provider.referencing_files_of(&source_file) {
                    candidates.insert(importer);
                }
            }
        }

        add_ruby_zeitwerk_candidates(target, analyzer, &mut candidates);
        add_scala_candidates_for_java_type(target, analyzer, &mut candidates);

        candidates
    }
}

fn add_ruby_zeitwerk_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    candidates: &mut HashSet<ProjectFile>,
) {
    if language_for_target(target) != Language::Ruby {
        return;
    }
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return;
    };
    for file in ruby.zeitwerk_autoload_candidate_files_for_identifier(target.identifier()) {
        candidates.insert(file);
    }
}

fn add_scala_candidates_for_java_type(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    candidates: &mut HashSet<ProjectFile>,
) {
    if language_for_target(target) != Language::Java || !target.is_class() {
        return;
    }

    let Ok(files) = analyzer.project().analyzable_files(Language::Scala) else {
        return;
    };
    if files.is_empty() {
        return;
    }

    let target_name = target.identifier();
    let target_fq_name = target.fq_name();
    for file in files {
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
        let identifier = target.identifier();
        if identifier.trim().is_empty() {
            return HashSet::default();
        }

        let language = language_for_target(target);

        if language == Language::None {
            return HashSet::default();
        }

        let files = match analyzer.project().analyzable_files(language) {
            Ok(files) => files,
            Err(_) => return HashSet::default(),
        };
        if files.is_empty() {
            return HashSet::default();
        }

        let matches: Mutex<HashSet<ProjectFile>> = Mutex::new(HashSet::default());
        let files: Vec<ProjectFile> = files.into_iter().collect();

        files.par_iter().for_each(|file| {
            if file.is_binary().unwrap_or(true) {
                return;
            }
            let Ok(content) = file.read_to_string() else {
                return;
            };
            if content.contains(identifier)
                && let Ok(mut sink) = matches.lock()
            {
                sink.insert(file.clone());
            }
        });

        matches.into_inner().expect("candidate match set poisoned")
    }
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
        let candidates = self.graph.find_candidates(target, analyzer);
        if candidates.is_empty() && !analyzer.is_empty() {
            return self.text.find_candidates(target, analyzer);
        }
        candidates
    }
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
