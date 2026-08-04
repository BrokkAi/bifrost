//! The read-only index over a project's declarations.
//!
//! [`CodeUnitIndex`] is the half of the analyzer contract that answers from the
//! declaration index alone: enumerating declarations, resolving names to them,
//! rendering their sources, skeletons and signatures, and navigating
//! parent/child structure. Every signature here closes over this crate's model
//! types, which is what lets it sit below `brokk-bifrost-analysis` and lets
//! generic index consumers (`capabilities`, `pool_memo`) live here too.
//!
//! `IAnalyzer` in `brokk-bifrost-analysis` extends this trait and retains
//! everything that needs a grammar, a store, the usages framework or the
//! language registry -- including the batched symbol search, whose request type
//! owns compiled `regex` values.

use crate::analyzer::model::{
    CodeUnit, Language, ProjectFile, Range, SignatureMetadata, SummaryFileProjection,
};
use crate::analyzer::project::Project;
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

    /// Whether `file` is one this analyzer has indexed. The default scans
    /// `analyzed_files`; concrete analyzers override with an O(1) lookup so
    /// incremental callers don't pay O(repo) per changed file.
    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.analyzed_files()
            .iter()
            .any(|candidate| candidate == file)
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

    fn definitions(&self, _fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.definitions(fq_name).collect()
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

    /// `search_definitions` for one language's non-literal `pattern` whose
    /// every match is nevertheless guaranteed by the caller to contain
    /// `required_literal` as a substring. Persisted stores use the literal as
    /// a substring prefilter instead of regex-scanning the whole declaration
    /// index, and multi-language workspaces route to `language`'s delegate
    /// alone instead of fanning the query out to every delegate -- the
    /// generated suffix patterns of symbol lookup are built per language and
    /// always require their terminal segment verbatim, and the combination of
    /// a whole-index regex scan fanned out per language pair made
    /// unresolvable symbol targets take seconds (#1430, #1419).
    /// Implementations that cannot exploit the hints fall back to a plain
    /// `search_definitions`; callers must still filter candidates by language.
    fn search_definitions_with_literal(
        &self,
        pattern: &str,
        _required_literal: &str,
        _language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.search_definitions(pattern, false)
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
        let parent_name = default_parent_fq_name(code_unit)?;
        self.definitions(&parent_name).next()
    }

    fn ranges(&self, _code_unit: &CodeUnit) -> Vec<Range> {
        Vec::new()
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.ranges(code_unit)
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
