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
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let mut resolved = HashSet::default();
        let include_targets = self.include_target_index();
        let imports = self.import_statements_from_projection(token, file);
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
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let references = self
            .reverse_include_index(token)
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        self.referencing_files
            .insert(file.clone(), Arc::new(references.clone()));
        references
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
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
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let source = code_unit.source();
        let identifiers = brokk_bifrost_cpp::imports::extract_type_identifiers(
            &self.inner.get_source(code_unit, true).unwrap_or_default(),
        );
        self.import_statements_from_projection(token, source)
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

    fn reverse_include_index(
        &self,
        token: QueryToken<'_>,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_include_index,
            || self.inner.all_files(),
            |candidate| self.include_targets_for_file(token, candidate),
        )
    }

    fn include_targets_for_file(
        &self,
        token: QueryToken<'_>,
        candidate: &ProjectFile,
    ) -> Vec<ProjectFile> {
        let include_targets = self.include_target_index();
        let mut matched_targets = HashSet::default();
        let mut resolved_targets = Vec::new();
        let imports = self.import_statements_from_projection(token, candidate);
        for include in include_paths(&imports) {
            for target in include_targets.resolve_indexed(&include) {
                if matched_targets.insert(target.clone()) {
                    resolved_targets.push(target);
                }
            }
        }
        resolved_targets
    }

    /// For every file the direct reverse-include index reaches, the workspace
    /// translation units whose include closure reaches it -- the transitive
    /// answer over [`Self::reverse_include_index`]. Memoized exactly like
    /// `reverse_include_index`, and reset at the same points (`from_inner`,
    /// `with_updated_inner`) since it is invalidated only when the whole
    /// analyzer generation turns over.
    fn transitive_reverse_tu_index(&self, token: QueryToken<'_>) -> Arc<TransitiveReverseTuIndex> {
        self.transitive_reverse_tu_index.get_or_build(
            || self.build_transitive_reverse_tu_index_data(token),
            || self.build_transitive_reverse_tu_index_data(token),
        )
    }

    /// The inputs and propagation behind [`Self::transitive_reverse_tu_index`],
    /// gathered lazily so an already-built memo never re-scans the workspace.
    fn build_transitive_reverse_tu_index_data(
        &self,
        token: QueryToken<'_>,
    ) -> TransitiveReverseTuIndex {
        let _scope = crate::profiling::scope("cpp.build_transitive_reverse_tu_index");
        let direct_reverse = self.reverse_include_index(token);
        let mut translation_units = self
            .inner
            .all_files()
            .into_iter()
            .filter(is_cpp_translation_unit)
            .collect::<Vec<_>>();
        // A unit's ordinal is its position here, so this order is the order
        // every materialized answer comes out in. Sorting once at the source
        // is what lets `reaching_translation_units` hand back a sorted list
        // without a per-query sort.
        translation_units.sort_unstable();
        debug_assert!(
            translation_units.windows(2).all(|pair| pair[0] != pair[1]),
            "the workspace listing must not repeat a translation unit: {translation_units:?}"
        );
        let build = build_transitive_reverse_tu_index(&direct_reverse, &translation_units);
        // Total membership, not key count, is what this index represents: a
        // header reachable from many translation units contributes one entry
        // per unit, so the product grows far faster than the workspace does.
        // `edge_visits` is the number that says the build no longer pays for
        // that product -- it is one visit per include edge whatever the
        // memberships those edges carry (#2899).
        crate::profiling::note_with(|| {
            format!(
                "transitive_reverse_tu_index keys={} total_membership={} edge_visits={}",
                build.index.keys(),
                build.index.total_membership(),
                build.edge_visits
            )
        });
        build.index
    }

    /// Every workspace translation unit whose `#include` closure transitively
    /// reaches `file`, ascending by path and empty when none does.
    ///
    /// This materializes one `ProjectFile` per reaching unit, which is why the
    /// index stores ordinals and hands them out only here: a caller that just
    /// reads the units (like [`Self::header_language_attribution`]) iterates
    /// the index directly and clones nothing.
    pub(crate) fn transitive_reaching_translation_units(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<ProjectFile> {
        self.transitive_reverse_tu_index(token)
            .reaching_translation_units(file)
            .cloned()
            .collect()
    }

    /// Every file of `files` that some workspace translation unit provably
    /// compiles as C -- exactly the files
    /// [`Self::header_language_attribution`] answers
    /// [`HeaderLanguageAttribution::C`] or [`HeaderLanguageAttribution::Mixed`]
    /// for, decided by the same evidence order, but computed for the whole
    /// workspace in one propagation.
    ///
    /// This is the workspace mount's question, and the mount asks it of every
    /// analyzed file. Asking it through the attribution function materializes
    /// [`Self::transitive_reverse_tu_index`], which holds the reaching
    /// translation units of every file: on Godot that is 1,887,205 memberships
    /// to produce 8,356 booleans. #2899 turned those per-file sets into
    /// bitsets over the include graph's SCC condensation, so holding them is
    /// no longer the cost it was; reading them still is, because the
    /// attribution materializes one `ProjectFile` per membership. Only three
    /// monotone bits of each set are ever read (see
    /// [`ReachingCompilationEvidence`]), so propagating the bits instead
    /// answers the same question in the size of the include graph.
    ///
    /// The full index is not replaced: the resolution-time attribution surface
    /// still needs the sets, and this function must agree with it file for
    /// file. `predicate_agrees_with_the_transitive_index_over_a_mixed_workspace`
    /// is that check.
    pub(crate) fn files_compiled_as_c(
        &self,
        token: QueryToken<'_>,
        files: &[ProjectFile],
    ) -> HashSet<ProjectFile> {
        if files.is_empty() {
            // Asking about no file is not the propagation's answer for an
            // empty set; it is no question at all. A workspace with no C
            // translation unit reaches here, and building the include graph
            // to answer nothing is what the mount used to avoid by testing
            // that condition before calling the attribution.
            return HashSet::default();
        }
        let _scope = crate::profiling::scope("cpp.files_compiled_as_c");
        let evidence = self.propagate_reaching_compilation_evidence(token);
        files
            .iter()
            .filter(|file| self.compiled_as_c(file, evidence.get(*file)))
            .cloned()
            .collect()
    }

    /// The evidence tiers of [`Self::header_language_attribution`], read off
    /// one file's own compile-database entries and the propagated evidence of
    /// the translation units that reach it.
    fn compiled_as_c(
        &self,
        file: &ProjectFile,
        reaching: Option<&ReachingCompilationEvidence>,
    ) -> bool {
        let direct_contexts = self.compile_contexts_for(file);
        if !direct_contexts.is_empty() {
            return direct_contexts
                .iter()
                .any(|context| context.tu_language(file.rel_path()) == CompiledLanguage::C);
        }
        let Some(reaching) = reaching else {
            // Nothing reaches it and no entry names it: `Unknown`.
            return false;
        };
        if reaching.database_entry {
            reaching.database_c
        } else {
            reaching.extension_c
        }
    }

    /// One iterative propagation of [`ReachingCompilationEvidence`] from every
    /// workspace translation unit outward along `#include` edges, to a fixed
    /// point. Same graph, same direction and same seeds as
    /// [`build_transitive_reverse_tu_index`]; what differs is that a file
    /// accumulates three bits rather than a set of translation units, so the
    /// cost is the size of the graph and not the size of the reachability
    /// relation over it.
    fn propagate_reaching_compilation_evidence(
        &self,
        token: QueryToken<'_>,
    ) -> HashMap<ProjectFile, ReachingCompilationEvidence> {
        let direct_reverse = self.reverse_include_index(token);
        let mut forward: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        for (target, includers) in direct_reverse.iter() {
            for includer in includers.iter() {
                forward
                    .entry(includer.clone())
                    .or_default()
                    .push(target.clone());
            }
        }

        let mut evidence: HashMap<ProjectFile, ReachingCompilationEvidence> = HashMap::default();
        let mut worklist: VecDeque<ProjectFile> = VecDeque::new();
        for translation_unit in self
            .inner
            .all_files()
            .into_iter()
            .filter(is_cpp_translation_unit)
        {
            let seed = ReachingCompilationEvidence::of_translation_unit(
                &translation_unit,
                self.compile_contexts_for(&translation_unit),
            );
            evidence
                .entry(translation_unit.clone())
                .or_default()
                .absorb(seed);
            worklist.push_back(translation_unit);
        }
        while let Some(current) = worklist.pop_front() {
            let Some(targets) = forward.get(&current) else {
                continue;
            };
            let current_evidence = evidence
                .get(&current)
                .copied()
                .expect("a file on the worklist was reached, so it carries evidence");
            for target in targets {
                if evidence
                    .entry(target.clone())
                    .or_default()
                    .absorb(current_evidence)
                {
                    worklist.push_back(target.clone());
                }
            }
        }
        crate::profiling::note_with(|| {
            format!("reaching_compilation_evidence files={}", evidence.len())
        });
        evidence
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
        token: QueryToken<'_>,
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

        // Read straight off the index rather than through
        // `transitive_reaching_translation_units`: this is a per-file question
        // the resolver asks of every header it enumerates, and nothing here
        // outlives the borrow, so none of the reaching units need cloning.
        let index = self.transitive_reverse_tu_index(token);

        let database_languages = index
            .reaching_translation_units(file)
            .flat_map(|translation_unit| {
                self.compile_contexts_for(translation_unit)
                    .iter()
                    .map(move |context| context.tu_language(translation_unit.rel_path()))
            })
            .collect::<Vec<_>>();
        if !database_languages.is_empty() {
            return attribution_from_languages(database_languages.into_iter());
        }

        let mut reaching_translation_units = index.reaching_translation_units(file).peekable();
        if reaching_translation_units.peek().is_none() {
            return HeaderLanguageAttribution::Unknown;
        }
        attribution_from_languages(reaching_translation_units.map(|translation_unit| {
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

/// Everything [`HeaderLanguageAttribution`] reads off the set of translation
/// units that reach one file, reduced to three monotone bits.
///
/// The attribution's tiers only ever ask three yes/no questions of that set:
/// does any of its translation units have a compile-database entry at all
/// (which decides whether tier 2 or tier 3 answers), does any entry compile
/// its unit as C, and is any reaching unit spelled `.c`. Each is a union over
/// the set, so each survives being merged along an include edge, which is what
/// lets the propagation carry the answer instead of the set.
///
/// The reduction is exact for the C-or-Mixed question the workspace mount
/// asks; it is deliberately not enough to reproduce the four-way attribution,
/// because `Cpp` and `Unknown` differ only by whether anything reaches the
/// file at all and the mount treats both the same way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReachingCompilationEvidence {
    /// Some reaching translation unit has a compile-database entry. Tier 2
    /// answers when this holds, and tier 3 when it does not.
    database_entry: bool,
    /// Some reaching translation unit has a compile-database entry that
    /// compiles it as C.
    database_c: bool,
    /// Some reaching translation unit is named `*.c`.
    extension_c: bool,
}

impl ReachingCompilationEvidence {
    fn of_translation_unit(
        translation_unit: &ProjectFile,
        contexts: &[brokk_bifrost_cpp::compile_context::CppCompileContext],
    ) -> Self {
        Self {
            database_entry: !contexts.is_empty(),
            database_c: contexts.iter().any(|context| {
                context.tu_language(translation_unit.rel_path()) == CompiledLanguage::C
            }),
            extension_c: translation_unit
                .rel_path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("c"),
        }
    }

    /// Union `other` into `self`, reporting whether anything changed. The
    /// worklist re-visits a file exactly when this says yes, so the
    /// propagation terminates: three bits can only ever turn on.
    fn absorb(&mut self, other: Self) -> bool {
        let before = *self;
        self.database_entry |= other.database_entry;
        self.database_c |= other.database_c;
        self.extension_c |= other.extension_c;
        *self != before
    }
}

/// A set of translation units, one bit per ordinal.
///
/// An ordinal is a position in the `translation_units` slice
/// [`build_transitive_reverse_tu_index`] was given: bit `i` set means
/// `translation_units[i]` reaches whatever this set describes. That slice is
/// sorted, so [`Self::iter`] yields ordinals in ascending path order and a
/// materialized answer comes out sorted for free.
#[derive(Clone, Debug, Default)]
struct TranslationUnitSet {
    words: Vec<u64>,
}

/// How many ordinals one [`TranslationUnitSet`] word holds.
const UNITS_PER_WORD: usize = u64::BITS as usize;

impl TranslationUnitSet {
    /// The empty set over `units` ordinals.
    fn with_capacity(units: usize) -> Self {
        Self {
            words: vec![0; units.div_ceil(UNITS_PER_WORD)],
        }
    }

    fn insert(&mut self, ordinal: usize) {
        self.words[ordinal / UNITS_PER_WORD] |= 1 << (ordinal % UNITS_PER_WORD);
    }

    /// Union `other` into `self`. Both index the same slice of translation
    /// units, so both hold the same number of words.
    fn union_from(&mut self, other: &Self) {
        debug_assert_eq!(
            self.words.len(),
            other.words.len(),
            "translation-unit sets of one index share their ordinal space"
        );
        for (word, source) in self.words.iter_mut().zip(&other.words) {
            *word |= *source;
        }
    }

    fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(index, word)| {
            let word = *word;
            (0..UNITS_PER_WORD)
                .filter(move |bit| word & (1 << bit) != 0)
                .map(move |bit| index * UNITS_PER_WORD + bit)
        })
    }
}

/// Which workspace translation units reach each file, over the whole include
/// graph.
///
/// Files that include one another are reached by exactly the same units, so
/// the index holds one [`TranslationUnitSet`] per strongly connected component
/// of the forward include graph and maps each file to its component. Only a
/// file that some unit actually reaches is keyed: an unreached file and an
/// absent file are the same answer.
pub(super) struct TransitiveReverseTuIndex {
    /// Ordinal -> translation unit, ascending; the ordinal space every
    /// [`TranslationUnitSet`] here indexes.
    translation_units: Vec<ProjectFile>,
    /// The component each reached file belongs to, indexing `component_units`.
    component_of_file: HashMap<ProjectFile, u32>,
    component_units: Vec<TranslationUnitSet>,
}

impl TransitiveReverseTuIndex {
    /// Every translation unit whose `#include` closure reaches `file`,
    /// ascending by path and empty when none does.
    ///
    /// Borrowed, not cloned: the index holds ordinals, and the only caller
    /// that needs owned files is the one whose signature demands them.
    pub(super) fn reaching_translation_units(
        &self,
        file: &ProjectFile,
    ) -> impl Iterator<Item = &ProjectFile> + '_ {
        self.component_of_file
            .get(file)
            .into_iter()
            .flat_map(|component| {
                self.component_units[*component as usize]
                    .iter()
                    .map(|ordinal| &self.translation_units[ordinal])
            })
    }

    /// How many files some translation unit reaches.
    fn keys(&self) -> usize {
        self.component_of_file.len()
    }

    /// The size of the reachability relation: over every keyed file, how many
    /// translation units reach it.
    pub(super) fn total_membership(&self) -> usize {
        self.component_of_file
            .values()
            .map(|component| self.component_units[*component as usize].len())
            .sum()
    }
}

/// What one [`build_transitive_reverse_tu_index`] run produced.
pub(super) struct TransitiveReverseTuIndexBuild {
    pub(super) index: TransitiveReverseTuIndex,
    /// How many include edges the propagation looked at. Collapsing cycles and
    /// ordering the components is what holds this at one visit per edge; the
    /// worklist this replaced re-walked an edge once per translation unit that
    /// arrived late at its source, which is why envoy's 5.05M memberships took
    /// 1,362 s to build (#2899).
    pub(super) edge_visits: usize,
}

/// Which workspace translation units reach each file, in the size of the
/// include graph.
///
/// `direct_reverse` is keyed the other way around (`header -> its direct
/// includers`, the shape `referencing_files_of` reads), so the first step
/// inverts it into forward adjacency (`includer -> what it directly
/// includes`) -- the direction propagation must run in, since a translation
/// unit's identity has to flow out through what it includes, not through who
/// includes the unit.
///
/// Then: collapse the strongly connected components of that graph (iterative
/// Tarjan, an explicit stack per repository convention), seed each unit's
/// ordinal into its own component's [`TranslationUnitSet`], and OR each
/// component's set into its successors'. Tarjan closes a component only after
/// every component reachable from it, so walking the components by descending
/// id is a topological order and one pass over the edges reaches the fixed
/// point. Guard-protected mutual includes are answered by the collapse, not by
/// re-queuing them until their sets agree.
pub(super) fn build_transitive_reverse_tu_index(
    direct_reverse: &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>,
    translation_units: &[ProjectFile],
) -> TransitiveReverseTuIndexBuild {
    /// The node id of `file`, assigning the next one on first sight.
    fn node_id(
        file: &ProjectFile,
        node_ids: &mut HashMap<ProjectFile, u32>,
        node_files: &mut Vec<ProjectFile>,
        forward: &mut Vec<Vec<u32>>,
    ) -> u32 {
        if let Some(id) = node_ids.get(file) {
            return *id;
        }
        let id =
            u32::try_from(node_files.len()).expect("an include graph has fewer than 2^32 files");
        node_ids.insert(file.clone(), id);
        node_files.push(file.clone());
        forward.push(Vec::new());
        id
    }

    let mut node_ids: HashMap<ProjectFile, u32> = HashMap::default();
    let mut node_files: Vec<ProjectFile> = Vec::new();
    let mut forward: Vec<Vec<u32>> = Vec::new();
    for (target, includers) in direct_reverse {
        let target_id = node_id(target, &mut node_ids, &mut node_files, &mut forward);
        for includer in includers.iter() {
            let includer_id = node_id(includer, &mut node_ids, &mut node_files, &mut forward);
            forward[includer_id as usize].push(target_id);
        }
    }
    // A translation unit that includes nothing still reaches itself.
    for translation_unit in translation_units {
        node_id(
            translation_unit,
            &mut node_ids,
            &mut node_files,
            &mut forward,
        );
    }

    let node_count = node_files.len();
    let mut discovery = vec![u32::MAX; node_count];
    let mut lowlink = vec![0u32; node_count];
    let mut on_component_stack = vec![false; node_count];
    let mut component_of = vec![u32::MAX; node_count];
    let mut component_stack: Vec<u32> = Vec::new();
    // (node, how many of its out-edges the walk has taken) -- the explicit
    // stack that replaces Tarjan's recursion.
    let mut walk: Vec<(u32, usize)> = Vec::new();
    let mut next_discovery = 0u32;
    let mut component_count = 0usize;
    for root in 0..node_count {
        if discovery[root] != u32::MAX {
            continue;
        }
        discovery[root] = next_discovery;
        lowlink[root] = next_discovery;
        next_discovery += 1;
        component_stack.push(root as u32);
        on_component_stack[root] = true;
        walk.push((root as u32, 0));
        while let Some((node, edge)) = walk.last_mut() {
            let node = *node as usize;
            if let Some(target) = forward[node].get(*edge).copied() {
                *edge += 1;
                let target = target as usize;
                if discovery[target] == u32::MAX {
                    discovery[target] = next_discovery;
                    lowlink[target] = next_discovery;
                    next_discovery += 1;
                    component_stack.push(target as u32);
                    on_component_stack[target] = true;
                    walk.push((target as u32, 0));
                } else if on_component_stack[target] {
                    lowlink[node] = lowlink[node].min(discovery[target]);
                }
                continue;
            }
            walk.pop();
            if lowlink[node] == discovery[node] {
                let component = u32::try_from(component_count)
                    .expect("an include graph has fewer than 2^32 components");
                loop {
                    let member = component_stack
                        .pop()
                        .expect("a closed component's members are on the component stack");
                    on_component_stack[member as usize] = false;
                    component_of[member as usize] = component;
                    if member as usize == node {
                        break;
                    }
                }
                component_count += 1;
            }
            if let Some((parent, _)) = walk.last() {
                let parent = *parent as usize;
                lowlink[parent] = lowlink[parent].min(lowlink[node]);
            }
        }
    }

    let mut members: Vec<Vec<u32>> = vec![Vec::new(); component_count];
    for (node, component) in component_of.iter().enumerate() {
        members[*component as usize].push(node as u32);
    }
    let mut component_units =
        vec![TranslationUnitSet::with_capacity(translation_units.len()); component_count];
    for (ordinal, translation_unit) in translation_units.iter().enumerate() {
        let node = *node_ids
            .get(translation_unit)
            .expect("every translation unit was interned as a node");
        component_units[component_of[node as usize] as usize].insert(ordinal);
    }

    let mut edge_visits = 0usize;
    // Descending component id is topological order: Tarjan closes a component
    // only after every component reachable from it, so a component's
    // successors all have smaller ids and are still waiting for this union.
    for component in (0..component_count).rev() {
        let (earlier, current) = component_units.split_at_mut(component);
        let current_units = &current[0];
        for node in &members[component] {
            for target in &forward[*node as usize] {
                edge_visits += 1;
                let target_component = component_of[*target as usize] as usize;
                if target_component == component {
                    continue;
                }
                debug_assert!(
                    target_component < component,
                    "Tarjan closes a component only after the components it reaches"
                );
                earlier[target_component].union_from(current_units);
            }
        }
    }

    let component_of_file = node_files
        .into_iter()
        .enumerate()
        .filter(|(node, _)| !component_units[component_of[*node] as usize].is_empty())
        .map(|(node, file)| (file, component_of[node]))
        .collect();

    TransitiveReverseTuIndexBuild {
        index: TransitiveReverseTuIndex {
            translation_units: translation_units.to_vec(),
            component_of_file,
            component_units,
        },
        edge_visits,
    }
}
