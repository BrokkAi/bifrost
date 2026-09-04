//! The read-only index over a project's declarations.
//!
//! [`CodeUnitIndex`] is the half of the analyzer contract that answers from the
//! declaration index alone: enumerating declarations, resolving names to them,
//! rendering their sources, skeletons and signatures, navigating parent/child
//! structure, and answering which declaration encloses a source location.
//! Every signature here closes over this crate's model
//! types, which is what lets it sit below `brokk-bifrost-analysis` and lets
//! generic index consumers (`capabilities`, `pool_memo`) live here too.
//!
//! `IAnalyzer` in `brokk-bifrost-analysis` extends this trait and retains
//! everything that needs a grammar, a store, the usages framework or the
//! language registry -- including the batched symbol search, whose request type
//! owns compiled `regex` values.

use crate::analyzer::fq_name::{FqName, segment_interner};
use crate::analyzer::model::{
    CodeUnit, Language, ProjectFile, Range, SignatureMetadata, SummaryFileProjection,
};
use crate::analyzer::project::Project;
use crate::analyzer::query_batch::LimitedQueryRows;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub trait CodeUnitIndex: Send + Sync {
    fn project(&self) -> &dyn Project;

    fn languages(&self) -> BTreeSet<Language>;

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        Vec::new()
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.analyzed_files().into_iter().collect()
    }

    /// This analyzer's own files for one language, in path order.
    ///
    /// The default filters and sorts `analyzed_files`, which is right for an
    /// analyzer that only ever holds one language. A multi-language analyzer
    /// overrides this to go straight to the delegate that owns `language`
    /// instead: the default's `analyzed_files` already fans out across every
    /// delegate and sorts the combined result, so filtering it back down to
    /// one language re-pays that whole-workspace, every-language fan-out and
    /// sort for an answer only one delegate's own (already sorted) file list
    /// could give directly. A usage query that calls this once per candidate
    /// declaration -- once per ambiguous target's every overload, on a
    /// workspace with heavy same-name duplication -- turns that into
    /// thousands of repeats of the same whole-workspace scan (issue #1738's
    /// shape, one call site further out).
    fn analyzed_files_for_language(&self, language: Language) -> Vec<ProjectFile> {
        let mut files: Vec<ProjectFile> = self
            .analyzed_files()
            .into_iter()
            .filter(|file| crate::analyzer::common::language_for_file(file) == language)
            .collect();
        files.sort();
        files
    }

    /// Whether `file` is one this analyzer has indexed. The default scans
    /// `analyzed_files`; concrete analyzers override with an O(1) lookup so
    /// incremental callers don't pay O(repo) per changed file.
    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.analyzed_files()
            .iter()
            .any(|candidate| candidate == file)
    }

    /// The subset of `candidates` this analyzer has indexed, in path order.
    ///
    /// The membership rule is exactly [`CodeUnitIndex::is_analyzed`]'s, but a
    /// caller holding a whole match set must not pay one store round trip per
    /// file: persisted analyzers override this to check ownership and liveness
    /// per candidate and then confirm the survivors in a single store query.
    ///
    /// This exists so that resolving a directory or glob target costs work
    /// proportional to what the target matched instead of to the workspace.
    /// Before it, the glob leg of `resolve_file_patterns` enumerated
    /// `analyzed_files` -- a whole-workspace filesystem scan plus a
    /// whole-workspace store query, once per language, once per request -- to
    /// answer a pattern that matched three files (issue #1738).
    ///
    /// The default materializes the analyzed set once, which is what every
    /// caller effectively did before and is still right for an analyzer with
    /// no store behind it.
    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        let analyzed = self.get_analyzed_files();
        let mut retained: Vec<_> = candidates
            .iter()
            .filter(|candidate| analyzed.contains(*candidate))
            .cloned()
            .collect();
        retained.sort();
        retained
    }

    fn is_empty(&self) -> bool {
        self.all_declarations().next().is_none()
    }

    fn top_level_declarations(&self, _file: &ProjectFile) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.top_level_declarations(file)
    }

    fn declarations(&self, _file: &ProjectFile) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.declarations(file)
    }

    /// The per-file [`ClassRangeIndex`] over this index's class-like
    /// declarations.
    ///
    /// Building the index clones the file's whole declaration set and issues
    /// one range lookup per class, and its result is a pure function of the
    /// index state for `file`. The interactive definition resolvers ask the
    /// enclosing-class question once per reference site, so the unified
    /// reference engine's bulk shape — resolving every occurrence of a file —
    /// rebuilt the index once per occurrence, in several languages inside
    /// per-import or per-preceding-binding loops (issue #2679; the Rust
    /// analogue was public issue #11). Analyzers with a request-scoped read
    /// cache override this to build at most once per file per request; the
    /// default is the plain uncached build.
    fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> Arc<crate::analyzer::usages::inverted_edges::ClassRangeIndex> {
        Arc::new(crate::analyzer::usages::inverted_edges::ClassRangeIndex::build(self, file))
    }

    /// Declarations for a source-location query. Persisted analyzers can
    /// override this when the working-tree source needs a compatible range
    /// projection without changing ordinary snapshot queries.
    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.get_declarations(file)
    }

    /// Declaration-materialization provenance recorded for `file` by its
    /// language walk (issue #1476). Default empty: an analyzer that records
    /// nothing has no records, and the materialization support tables decide
    /// whether that absence means anything.
    fn materialization_records(
        &self,
        _file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        Vec::new()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_>;

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.all_declarations().collect()
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.all_declarations()
            .map(|unit| {
                let range = self
                    .ranges(&unit)
                    .into_iter()
                    .min_by_key(|range| (range.start_line, range.start_byte));
                (unit, range)
            })
            .collect()
    }

    /// A compact, self-contained view for rendering one file summary. The
    /// default lets callers retain the existing method-by-method behavior.
    fn summary_file_projection(&self, _file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        None
    }

    /// Every declaration whose fully-qualified name equals `unit`'s, `unit`
    /// itself included when the index still holds it.
    ///
    /// [`Self::definitions`] answers a different question -- which definition
    /// a name resolves to -- and keeps at most one module out of the group,
    /// because one definition is what a lookup wants. A module is declared
    /// once per file that declares it (a Java or Go package, a C++ namespace),
    /// so rendering a module target needs the whole group, not the
    /// representative.
    ///
    /// Takes the declaration rather than a rendered name so an implementation
    /// can seek on its structured identity: a persisted index overrides this
    /// with a seek on `unit`'s terminal identifier and compares whole names.
    /// The default scan is what an index holding its units in memory can do,
    /// and it is what a persisted index must not do: hydrating every
    /// declaration in the workspace to answer one name cost 1.7 s per module
    /// selector on a 360k-declaration workspace (#2880).
    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        let fq_name = unit.fq_name();
        self.all_declarations()
            .filter(|candidate| candidate.fq_name() == fq_name)
            .collect()
    }

    fn definitions(&self, _fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    /// Hint that the caller will soon ask [`Self::definitions`] for every name.
    ///
    /// Persisted indexes can override this to fill a request-scoped memo with
    /// one batched read. The hint is never a correctness boundary: indexes
    /// without a bulk path do nothing, and callers still issue the ordinary
    /// definition lookups that own fallback and identity filtering.
    fn prefetch_definitions(&self, _fq_names: &[String]) {}

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.definitions(fq_name).collect()
    }

    /// Exact definitions for a name whose segment boundaries and kinds are
    /// already known. Persisted analyzers override this to keep the structured
    /// identity intact through their relational query. The default preserves
    /// compatibility for indexes that only implement the rendered lookup.
    fn definitions_by_structured_name(
        &self,
        fq_name: &FqName,
        language: Language,
    ) -> Vec<CodeUnit> {
        self.get_definitions(&fq_name.display_native(language, segment_interner()))
    }

    /// Candidate declarations whose persisted short names match a qualified
    /// lookup input. Implementations return an empty set when they cannot
    /// answer this cheaply; callers retain their broader lookup path then.
    fn lookup_candidates_by_short_name(&self, _symbol: &str) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

    /// Candidate declarations *or definition-lookup-only units* (#1088: a
    /// spelling the fq lookup path resolves must be visible here too, or
    /// bare-name ambiguity silently drops it) whose persisted terminal
    /// identifier (the leaf display name, e.g. `bar` for `pkg.Foo.bar`)
    /// equals `identifier`. Backed by the partial
    /// `idx_code_units_lang_identifier_lookup` index. Implementations that
    /// cannot answer cheaply return an empty set; callers retain their
    /// broader lookup path.
    fn lookup_candidates_by_identifier(&self, _identifier: &str) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;

    /// `search_definitions` for one language's suffix `pattern`, the shape
    /// `symbol_lookup::suffix_search_pattern` builds: every fully-qualified
    /// name the pattern can match *ends* at the query path's tail, on a
    /// separator boundary. `terminal_identifiers`, from
    /// `symbol_lookup::suffix_terminal_identifiers`, is every way one persisted
    /// `identifier` value can spell that tail.
    ///
    /// That lets a persisted store answer with an index seek on
    /// `code_units.identifier` instead of regex-scanning every declaration of
    /// the language (#1688), and lets a multi-language workspace route to
    /// `language`'s delegate alone instead of fanning the query out to every
    /// delegate (#1430, #1419). Callers must still filter candidates by
    /// language; implementations that cannot exploit the hints fall back to a
    /// plain `search_definitions`.
    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        _terminal_identifiers: &[String],
        _language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.search_definitions(pattern, false)
    }

    /// Whether the indexed lookup methods cover every persisted declaration.
    ///
    /// A complete index makes a qualified miss conclusive. Callers can then
    /// avoid a whole-table regex scan. In-memory or third-party analyzers keep
    /// the default and retain their broader fallback paths.
    fn has_complete_symbol_lookup_index(&self) -> bool {
        false
    }

    /// Cold-start substring search that runs against the persisted FTS5
    /// symbol index, without requiring `AnalyzerState` to be fully built.
    /// Implementations that have no persistence layer (or whose storage
    /// open failed) should fall back to `search_definitions(pattern, true)`,
    /// which preserves the legacy in-memory behavior.
    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.search_definitions(pattern, true)
    }

    fn direct_children(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_children(code_unit)
    }

    /// Return only children declared in the same source file as `code_unit`.
    ///
    /// This differs from [`CodeUnitIndex::direct_children`] for analyzers whose
    /// logical hierarchy crosses file boundaries. Java package modules are the
    /// motivating case: their ordinary children include classes from every file
    /// in the package, while source-local traversals such as semantic chunking
    /// must not expand the whole package merely to discard foreign files.
    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_children(code_unit)
            .into_iter()
            .filter(|child| child.source() == code_unit.source())
            .collect()
    }

    fn get_members_in_class(&self, class_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !class_unit.is_class() && !class_unit.is_module() {
            return Vec::new();
        }

        self.direct_children(class_unit)
            .into_iter()
            .filter(|child| child.is_class() || child.is_function() || child.is_field())
            .collect()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        let parent_name = code_unit
            .fq()
            .parent()
            .filter(|parent| !parent.is_empty())?;
        let language = crate::analyzer::common::language_for_file(code_unit.source());
        self.definitions_by_structured_name(&parent_name, language)
            .into_iter()
            .next()
    }

    fn ranges(&self, _code_unit: &CodeUnit) -> Vec<Range> {
        Vec::new()
    }

    /// The innermost declaration whose range encloses `range`, or `None` when
    /// no indexed declaration covers it.
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit>;

    /// [`CodeUnitIndex::enclosing_code_unit`] over a line span, for callers
    /// holding row positions rather than byte offsets.
    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit>;

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.ranges(code_unit)
    }

    /// Ranges for a source-location query. Persisted analyzers can override
    /// this when the working-tree source needs a compatible range projection.
    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.ranges_of(code_unit)
    }

    /// Returns at most `max_ranges` declaration ranges, the provider rows
    /// inspected, and whether more work remained (including cancellation).
    /// Production analyzers override this so bounded semantic queries never
    /// clone an unbounded stored range set.
    #[doc(hidden)]
    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        if max_ranges == 0 || cancellation.is_cancelled() {
            return (Vec::new(), 0, true);
        }
        let mut ranges = self.ranges(code_unit);
        let inspected = ranges.len().min(max_ranges);
        let incomplete = ranges.len() > max_ranges || cancellation.is_cancelled();
        ranges.truncate(max_ranges);
        (ranges, inspected, incomplete)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String>;

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;

    fn get_skeletons(&self, file: &ProjectFile) -> BTreeMap<CodeUnit, String> {
        let mut skeletons = BTreeMap::new();
        for symbol in self.top_level_declarations(file) {
            if let Some(skeleton) = self.get_skeleton(&symbol) {
                skeletons.insert(symbol, skeleton);
            }
        }
        skeletons
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;

    fn signatures(&self, _code_unit: &CodeUnit) -> Vec<String> {
        Vec::new()
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.signatures(code_unit)
    }

    fn signature_metadata(&self, _code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        Vec::new()
    }

    fn signature_metadata_of(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.signature_metadata(code_unit)
    }

    /// Source text retained by the analyzer generation that produced this
    /// file's declarations and byte ranges. The text is owned because a
    /// persisted analyzer may hydrate it on demand rather than retain a
    /// workspace-sized source map.
    fn indexed_source(&self, _file: &ProjectFile) -> Option<String> {
        None
    }

    /// Whether the supplied on-disk source still matches this analyzer
    /// generation. Persisted analyzers compare blob identities so freshness
    /// checks do not need to hydrate stale source text.
    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.indexed_source(file)
            .is_some_and(|indexed| indexed == source)
    }

    /// Applies language-specific rendering to an extracted source fragment.
    /// `declaration_start` is the byte offset of the declaration inside the
    /// fragment, after any attached comments. The default preserves the
    /// indexed text unchanged.
    fn render_source_fragment(
        &self,
        _code_unit: &CodeUnit,
        source: String,
        _declaration_start: usize,
    ) -> String {
        source
    }
}

/// The fully-qualified name of `code_unit`'s owner (the unit with its final
/// name segment removed), or `None` if it has no owner (a top-level or
/// synthetic file-scope unit).
///
/// The owner is a pure segment pop on the unit's structured [`FqName`], rendered
/// in its native spelling -- the boundaries were recorded at construction and are
/// never re-guessed from the joined string. Every unit that reaches here carries
/// a populated `fq`: freshly-extracted units populate it at emission (M1),
/// FileState- and candidate-row-loaded cache units rebuild it from the persisted
/// segments (M3/M4). The M2-era legacy separator-scan fallback (which split the
/// joined name on the rightmost of `.`/`$`/`::`/`->`) is deleted; an empty `fq`
/// now genuinely means "no owner" rather than "not yet migrated".
///
/// [`FqName`]: crate::analyzer::fq_name::FqName
pub fn default_parent_fq_name(code_unit: &CodeUnit) -> Option<String> {
    let parent = code_unit
        .fq()
        .parent()
        .filter(|parent| !parent.is_empty())?;
    let interner = crate::analyzer::fq_name::segment_interner();
    let language = crate::analyzer::common::language_for_file(code_unit.source());
    Some(parent.display_native(language, interner))
}

/// The file-level namespace every spelling of a namespace-per-file query must
/// answer with: the qualifier the extractor recorded for the file when it is
/// non-empty, otherwise the namespace carried by the first TOP-LEVEL
/// declaration in source order.
///
/// Only top-level declarations are eligible, because they are the one
/// declaration sequence that keeps source order everywhere this rule is
/// evaluated -- the hydrated file state's vector, the
/// [`CodeUnitIndex::top_level_declarations`] projection and the persisted
/// `top_level_ordinal` column. Scanning every declaration instead ordered the
/// scan by `CodeUnit`'s `Ord`, so a file holding two namespaces answered with
/// whichever namespace happened to sort first; C#'s bounded and unbounded
/// `namespace_of_file` spellings then disagreed while sharing one memo cell,
/// which made the memoized answer depend on which spelling ran first (#1726).
///
/// `limit` caps the declarations inspected and counts the recorded-qualifier
/// probe as one of them. `usize::MAX` is the unbounded spelling: the cap can
/// never be reached, so that batch is always complete.
pub fn file_namespace_from_top_level_declarations<'a, I>(
    recorded_qualifier: &str,
    top_level_declarations: I,
    limit: usize,
) -> LimitedQueryRows<String>
where
    I: IntoIterator<Item = &'a CodeUnit>,
{
    if limit == 0 {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }
    if !recorded_qualifier.is_empty() {
        return LimitedQueryRows::complete(vec![recorded_qualifier.to_string()], 1);
    }
    let mut inspected = 1usize;
    for unit in top_level_declarations {
        if inspected == limit {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }
        inspected += 1;
        if !unit.package_name().is_empty() {
            return LimitedQueryRows::complete(vec![unit.package_name().to_string()], inspected);
        }
    }
    LimitedQueryRows::complete(vec![String::new()], inspected)
}

#[cfg(test)]
mod parent_of_tests {
    use super::default_parent_fq_name;
    use crate::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
    use crate::analyzer::model::{CodeUnit, CodeUnitType, ProjectFile};

    fn structured_unit(
        rel: &str,
        kind: CodeUnitType,
        package_name: &str,
        short_name: &str,
        package_segment_count: usize,
        segments: &[(&str, SegmentKind)],
    ) -> CodeUnit {
        let root = std::env::current_dir().expect("test working directory should be available");
        let source = ProjectFile::new(root, rel);
        let interner = segment_interner();
        let mut fq = FqName::new();
        for &(text, seg_kind) in segments {
            let id: SegmentId = interner.intern(text, seg_kind);
            fq.push(id);
        }
        let unit = CodeUnit::from_fq(source, kind, fq, package_segment_count, None, false);
        assert_eq!(unit.package_name(), package_name);
        assert_eq!(unit.short_name(), short_name);
        unit
    }

    fn assert_structured_parent(
        rel: &str,
        kind: CodeUnitType,
        package_name: &str,
        short_name: &str,
        package_segment_count: usize,
        segments: &[(&str, SegmentKind)],
        expected_parent: Option<&str>,
    ) {
        let unit = structured_unit(
            rel,
            kind,
            package_name,
            short_name,
            package_segment_count,
            segments,
        );
        let popped = default_parent_fq_name(&unit);
        assert_eq!(
            popped.as_deref(),
            expected_parent,
            "segment-pop owner name mismatch for {short_name:?}"
        );
    }

    #[test]
    fn cpp_namespace_head_owner_uses_structured_segments() {
        // `::` between namespaces, `.` down the owner/member tail — the mixed
        // separator the plan calls out. Both arms drop the trailing member.
        assert_structured_parent(
            "a.cpp",
            CodeUnitType::Function,
            "ns1::ns2",
            "Outer.method",
            2,
            &[
                ("ns1", SegmentKind::Package),
                ("ns2", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
            Some("ns1::ns2.Outer"),
        );
    }

    #[test]
    fn cpp_namespace_component_owner_uses_structured_segments() {
        // Popping into the `::`-joined namespace head: both arms agree because
        // `::` is in the parent-of separator set (unlike the shrinking-scope
        // walk, which deliberately never descends it).
        assert_structured_parent(
            "a.cpp",
            CodeUnitType::Class,
            "ns1::ns2",
            "Outer",
            2,
            &[
                ("ns1", SegmentKind::Package),
                ("ns2", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
            ],
            Some("ns1::ns2"),
        );
    }

    #[test]
    fn dotted_package_owner_uses_structured_segments() {
        assert_structured_parent(
            "a.py",
            CodeUnitType::Function,
            "pkg.mod",
            "Cls.method",
            2,
            &[
                ("pkg", SegmentKind::Package),
                ("mod", SegmentKind::Package),
                ("Cls", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
            Some("pkg.mod.Cls"),
        );
    }

    #[test]
    fn dollar_nested_owner_uses_structured_segments() {
        // A `$`-joined nested type: dropping the member, then dropping the
        // nested type, agrees between the segment pop and the `$`/`.` scan.
        assert_structured_parent(
            "a.py",
            CodeUnitType::Field,
            "",
            "Owner$Inner.member",
            0,
            &[
                ("Owner", SegmentKind::Type),
                ("Inner", SegmentKind::Nested),
                ("member", SegmentKind::Member),
            ],
            Some("Owner$Inner"),
        );
        assert_structured_parent(
            "a.py",
            CodeUnitType::Class,
            "",
            "Owner$Inner",
            0,
            &[("Owner", SegmentKind::Type), ("Inner", SegmentKind::Nested)],
            Some("Owner"),
        );
    }

    #[test]
    fn go_import_path_member_owner_uses_structured_segments() {
        // Path components carry literal dots (`github.com`) and `/` joins; both
        // arms drop only the trailing member, so the embedded dot never splits.
        assert_structured_parent(
            "a.go",
            CodeUnitType::Function,
            "github.com/foo/bar",
            "Baz.method",
            3,
            &[
                ("github.com", SegmentKind::Path),
                ("foo", SegmentKind::Path),
                ("bar", SegmentKind::Path),
                ("Baz", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
            Some("github.com/foo/bar.Baz"),
        );
    }

    #[test]
    fn single_segment_has_no_owner() {
        assert_structured_parent(
            "a.py",
            CodeUnitType::Class,
            "",
            "Solo",
            0,
            &[("Solo", SegmentKind::Type)],
            None,
        );
    }
}
