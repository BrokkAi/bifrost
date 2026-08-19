//! The `CppAnalyzer` half of C++ include analysis.
//!
//! `#include` parsing, the workspace-wide [`IncludeTargetIndex`] and every
//! target-resolution rule moved to [`brokk_bifrost_cpp::imports`]; what stays
//! here is the two provider impls the analyzer satisfies and the memo cells
//! (`OnceLock`, `PoolSafeMemo`) whose contents those functions produce.
//!
//! Every resolution point here reads `#include <...>` and `#include "..."` the
//! same way, through [`parse_include_path`] / [`include_paths`]. The
//! quoted-only spellings this module used to carry made a project that reaches
//! its own headers with angle brackets invisible to the inverse while the
//! forward resolved it (#1829).
//!
//! The two include-to-file rules differ by what the caller does with the
//! answer, not by include spelling. A *visibility* claim
//! (`imported_code_units_of`, `imported_files_from_infos`) uses
//! [`resolve_include_targets_with_index`], the same direct-then-unique-suffix
//! rule the forward resolver's include closure uses; its unique-suffix step is
//! what makes admitting `<...>` safe without a compiler include path, because
//! it refuses an ambiguous basename rather than picking one. *Candidate
//! discovery* (`referencing_files_of`, via `include_targets_for_file`) uses
//! `IncludeTargetIndex::resolve_indexed`, which deliberately over-approximates:
//! a file that only might reach the target still has to be scanned, and the
//! usage strategy proves or rejects each hit from the syntax tree.

use super::*;
use brokk_bifrost_cpp::compile_context::CompiledLanguage;
use brokk_bifrost_cpp::imports::{
    include_paths, parse_include_path, resolve_include_targets_with_index,
};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;

/// Extensions [`Language::Cpp`] claims that are headers, not translation
/// units. Everything else in [`Language::Cpp::extensions`] (`c`, `cc`, `cpp`,
/// `cxx`) is a translation unit -- see [`is_cpp_translation_unit`]. `hin` is
/// the C header-template spelling (krb5's `krb5.hin`), so it is a header too.
const CPP_HEADER_EXTENSIONS: &[&str] = &["h", "hin", "hpp", "hh", "hxx"];

/// Whether `file` is a C/C++ translation unit (as opposed to a header): one of
/// [`Language::Cpp::extensions`] that is not in [`CPP_HEADER_EXTENSIONS`].
/// Matched case-insensitively, the same normalization `Language::from_extension`
/// applies.
pub(crate) fn is_cpp_translation_unit(file: &ProjectFile) -> bool {
    file.rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .is_some_and(|extension| {
            Language::Cpp.extensions().contains(&extension.as_str())
                && !CPP_HEADER_EXTENSIONS.contains(&extension.as_str())
        })
}

/// What a compile configuration or a workspace extension says about the
/// language(s) that reach one header, reduced to the four attribution states.
fn attribution_from_languages(
    languages: impl Iterator<Item = CompiledLanguage>,
) -> HeaderLanguageAttribution {
    let mut has_c = false;
    let mut has_cpp = false;
    for language in languages {
        match language {
            CompiledLanguage::C => has_c = true,
            CompiledLanguage::Cpp => has_cpp = true,
        }
    }
    match (has_c, has_cpp) {
        (true, true) => HeaderLanguageAttribution::Mixed,
        (true, false) => HeaderLanguageAttribution::C,
        (false, true) => HeaderLanguageAttribution::Cpp,
        (false, false) => HeaderLanguageAttribution::Unknown,
    }
}

/// Which language(s) provably compile a header, evidence-ranked per the
/// ExecPlan (`.agents/plans/c-compilation-language-tag-scope.md`, Milestone
/// 2): pure infrastructure -- no resolution surface reads this yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderLanguageAttribution {
    /// Every translation unit that reaches this header (by compile-database
    /// evidence where the database resolves it, else by workspace TU
    /// extension) compiles it as C.
    C,
    /// Every reaching translation unit compiles it as C++.
    Cpp,
    /// Reaching translation units disagree: at least one compiles it as C and
    /// at least one as C++.
    Mixed,
    /// No workspace translation unit's include closure reaches this header,
    /// and no compile-database entry names it directly.
    Unknown,
}

impl TestDetectionProvider for CppAnalyzer {}

impl ImportAnalysisProvider for CppAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let mut resolved = HashSet::default();
        let include_targets = self.include_target_index();
        let imports = self.import_statements_from_projection(file);
        for path in include_paths(&imports) {
            for target in resolve_include_targets_with_index(file, &path, include_targets) {
                resolved.extend(self.inner.top_level_declarations(&target));
            }
        }

        let resolved = Arc::new(resolved);
        self.imported_code_units
            .insert(file.clone(), Arc::clone(&resolved));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let references = self
            .reverse_include_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        self.referencing_files
            .insert(file.clone(), Arc::new(references.clone()));
        references
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let include_targets = self.include_target_index();
        Some(
            imports
                .iter()
                .filter_map(|import| parse_include_path(&import.raw_snippet))
                .flat_map(|path| resolve_include_targets_with_index(file, &path, include_targets))
                .collect(),
        )
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let source = code_unit.source();
        let identifiers = brokk_bifrost_cpp::imports::extract_type_identifiers(
            &self.inner.get_source(code_unit, true).unwrap_or_default(),
        );
        self.import_statements_from_projection(source)
            .iter()
            .filter(|line| {
                parse_include_path(line).is_some_and(|path| {
                    let stem = Path::new(&path)
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("");
                    identifiers.contains(stem)
                })
            })
            .cloned()
            .collect()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_name = target
            .rel_path()
            .file_name()
            .and_then(|value| value.to_str());
        imports.iter().any(|import| {
            parse_include_path(&import.raw_snippet).is_some_and(|include| {
                target.rel_path() == Path::new(&include)
                    || target_name.is_some_and(|name| include.ends_with(name))
                    || source_file.parent().join(&include) == target.rel_path()
            })
        })
    }
}

impl CppAnalyzer {
    /// The path -> file map every include resolution reads.
    ///
    /// Two sources, and each is there for a reason the other does not cover.
    ///
    /// The workspace listing, filtered to C++'s own extensions, is the bulk of
    /// it: the index only ever answers `by_rel_path`/`by_file_name` lookups, so
    /// it needs file identity and never a parse product, and an include target
    /// with a C++ extension exists the moment the file exists (#1758). Reading
    /// the analyzed set alone made a header resolvable only after something had
    /// parsed it.
    ///
    /// The analyzed set supplies the rest: include-driven inference (#1837)
    /// adopts a file whose extension no language claims -- a `.inc` fragment,
    /// say -- into this analyzer, and adoption is recorded in the live path map
    /// rather than being derivable from the name. Widening the listing filter
    /// to every unclaimed extension instead would be wrong, not merely broad:
    /// an unadopted extensionless `vendor/vector` would then satisfy
    /// `#include <vector>` on basename alone, which
    /// `cpp_extensionless_angle_include_with_unrelated_basename_reports_boundary`
    /// pins as a boundary.
    pub(crate) fn include_target_index(&self) -> &IncludeTargetIndex {
        self.include_target_index.get_or_init(|| {
            let _scope = crate::profiling::scope("cpp.include_target_index.build");
            let mut files = self.inner.workspace_language_files();
            let listed: HashSet<ProjectFile> = files.iter().cloned().collect();
            files.extend(
                self.inner
                    .all_files()
                    .into_iter()
                    .filter(|file| !listed.contains(file)),
            );
            IncludeTargetIndex::build(files.iter())
        })
    }

    fn reverse_include_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_include_index,
            || self.inner.all_files(),
            |candidate| self.include_targets_for_file(candidate),
        )
    }

    fn include_targets_for_file(&self, candidate: &ProjectFile) -> Vec<ProjectFile> {
        let include_targets = self.include_target_index();
        let mut matched_targets = HashSet::default();
        let mut resolved_targets = Vec::new();
        let imports = self.import_statements_from_projection(candidate);
        for include in include_paths(&imports) {
            for target in include_targets.resolve_indexed(&include) {
                if matched_targets.insert(target.clone()) {
                    resolved_targets.push(target);
                }
            }
        }
        resolved_targets
    }

    /// For every file the direct reverse-include index reaches, the set of
    /// workspace translation units whose include closure reaches it -- the
    /// transitive answer over [`Self::reverse_include_index`]. Memoized
    /// exactly like `reverse_include_index`, and reset at the same points
    /// (`from_inner`, `with_updated_inner`) since it is invalidated only when
    /// the whole analyzer generation turns over.
    fn transitive_reverse_tu_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.transitive_reverse_tu_index.get_or_build(
            || self.build_transitive_reverse_tu_index_data(),
            || self.build_transitive_reverse_tu_index_data(),
        )
    }

    /// The inputs and worklist propagation behind
    /// [`Self::transitive_reverse_tu_index`], gathered lazily so an
    /// already-built memo never re-scans the workspace.
    fn build_transitive_reverse_tu_index_data(
        &self,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let direct_reverse = self.reverse_include_index();
        let translation_units = self
            .inner
            .all_files()
            .into_iter()
            .filter(is_cpp_translation_unit)
            .collect::<Vec<_>>();
        build_transitive_reverse_tu_index(&direct_reverse, &translation_units)
    }

    /// Every workspace translation unit whose `#include` closure transitively
    /// reaches `file`, empty when none does.
    pub(crate) fn transitive_reaching_translation_units(
        &self,
        file: &ProjectFile,
    ) -> Arc<HashSet<ProjectFile>> {
        self.transitive_reverse_tu_index()
            .get(file)
            .cloned()
            .unwrap_or_default()
    }

    /// Which language(s) provably compile `file` when it is a header, per the
    /// ExecPlan Milestone 2 evidence order:
    ///
    /// 1. A compile-database entry naming `file` itself is decisive on its
    ///    own.
    /// 2. Otherwise, the compile-database entries of the workspace
    ///    translation units whose transitive include closure reaches `file`,
    ///    when the database covers at least one of them.
    /// 3. Otherwise, the extensions of the workspace translation units that
    ///    reach `file` (`.c` is C, everything else is C++).
    /// 4. [`HeaderLanguageAttribution::Unknown`] when nothing reaches `file`
    ///    and no database entry names it.
    ///
    /// No resolution surface consults this yet; it exists so Milestone 3 can
    /// select a header's C or C++ projection without inventing this evidence
    /// hierarchy at the call site.
    pub(crate) fn header_language_attribution(
        &self,
        file: &ProjectFile,
    ) -> HeaderLanguageAttribution {
        let direct_contexts = self.compile_contexts_for(file);
        if !direct_contexts.is_empty() {
            return attribution_from_languages(
                direct_contexts
                    .iter()
                    .map(|context| context.tu_language(file.rel_path())),
            );
        }

        let reaching_translation_units = self.transitive_reaching_translation_units(file);

        let database_languages = reaching_translation_units
            .iter()
            .flat_map(|translation_unit| {
                self.compile_contexts_for(translation_unit)
                    .iter()
                    .map(move |context| context.tu_language(translation_unit.rel_path()))
            })
            .collect::<Vec<_>>();
        if !database_languages.is_empty() {
            return attribution_from_languages(database_languages.into_iter());
        }

        if reaching_translation_units.is_empty() {
            return HeaderLanguageAttribution::Unknown;
        }
        attribution_from_languages(reaching_translation_units.iter().map(|translation_unit| {
            if translation_unit
                .rel_path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("c")
            {
                CompiledLanguage::C
            } else {
                CompiledLanguage::Cpp
            }
        }))
    }
}

/// One iterative fixed point over the direct reverse-include index: starting
/// from every translation unit, propagate "reached by this TU" forward along
/// `#include` edges until nothing changes. `direct_reverse` is keyed the
/// other way around (`header -> its direct includers`, the shape
/// `referencing_files_of` reads), so the first step inverts it into forward
/// adjacency (`includer -> what it directly includes`) -- the direction
/// propagation must run in, since a TU's identity has to flow out through
/// what it includes, not through who includes the TU. A worklist, not
/// recursion, per repository convention for graph walks.
fn build_transitive_reverse_tu_index(
    direct_reverse: &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>,
    translation_units: &[ProjectFile],
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
    let mut forward: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
    for (target, includers) in direct_reverse {
        for includer in includers.iter() {
            forward
                .entry(includer.clone())
                .or_default()
                .push(target.clone());
        }
    }

    let mut closure: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
    let mut worklist: VecDeque<ProjectFile> = VecDeque::new();
    for translation_unit in translation_units {
        closure
            .entry(translation_unit.clone())
            .or_default()
            .insert(translation_unit.clone());
        worklist.push_back(translation_unit.clone());
    }
    while let Some(current) = worklist.pop_front() {
        let Some(targets) = forward.get(&current) else {
            continue;
        };
        let Some(current_tus) = closure.get(&current).cloned() else {
            continue;
        };
        for target in targets {
            let entry = closure.entry(target.clone()).or_default();
            let before = entry.len();
            entry.extend(current_tus.iter().cloned());
            if entry.len() != before {
                worklist.push_back(target.clone());
            }
        }
    }
    closure
        .into_iter()
        .map(|(file, tus)| (file, Arc::new(tus)))
        .collect()
}
