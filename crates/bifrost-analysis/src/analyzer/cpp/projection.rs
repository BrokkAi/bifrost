//! Resolution-time selection between a header's two readings (issue #1970).
//!
//! `Language::Cpp` serves C and C++ with one grammar, and a header has no
//! compilation language of its own. Extraction therefore stores two readings
//! of a header blob when they disagree -- the `cpp` row-set and, under the
//! `cpp:c` storage language key, the C row-set where a tag declared inside an
//! aggregate member list has file scope (C17 6.2.1). See
//! [`crate::analyzer::cpp::adapter::CppAdapter::additional_projections`].
//!
//! What lives here is the *reading selector*: which of the two a given
//! reference sees, which extra identities the workspace index therefore
//! carries, and how the two identities of one declaration site are paired so
//! inverse results can be unioned across them.
//!
//! Site equivalence is keyed on `(source file, declaration byte range)` and
//! never on a name: the two readings of one `struct` keyword span exactly the
//! same bytes, and nothing else in either reading does.

use super::*;
use crate::analyzer::cpp::adapter::CPP_C_STORAGE_LANGUAGE_KEY;
use crate::analyzer::tree_sitter_analyzer::FileState;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_cpp::graph::resolver::is_c_source_file;

/// The identity of one declaration site: a file and the byte span the
/// declaration occupies. Two units carrying this same pair under the two
/// readings of one blob are one declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CppDeclarationSite {
    file: ProjectFile,
    start_byte: usize,
    end_byte: usize,
}

impl CppDeclarationSite {
    fn of(unit: &CodeUnit, ranges: &HashMap<CodeUnit, Vec<Range>>) -> Option<Self> {
        let range = ranges.get(unit)?.first()?;
        Some(Self {
            file: unit.source().clone(),
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        })
    }
}

/// One header's C reading, reduced to what resolution asks of it.
///
/// Absent (`None` from [`CppAnalyzer::c_reading`]) means the store holds no
/// `cpp:c` rows for the blob, which by the adapter's contract means the C
/// reading *is* the C++ reading and every question about it is answered from
/// the file's own row-set.
pub(crate) struct CppCReading {
    /// Every declaration the C reading mints.
    pub(crate) declarations: BTreeSet<CodeUnit>,
    /// Declaration ranges under the C reading. A C-only unit is not in the
    /// `cpp` row-set, so the store cannot answer for it.
    pub(crate) ranges: HashMap<CodeUnit, Vec<Range>>,
    /// Child edges under the C reading (a file-scope tag is a child of the
    /// module, not of the aggregate that lexically contains it).
    pub(crate) children: HashMap<CodeUnit, Vec<CodeUnit>>,
    /// The C reading's top-level declarations.
    pub(crate) top_level_declarations: Vec<CodeUnit>,
    /// Units the C reading mints that the C++ reading does not.
    pub(crate) c_only: Vec<CodeUnit>,
    /// Units the C++ reading mints that the C reading does not.
    pub(crate) cpp_only: Vec<CodeUnit>,
    /// For each unit of either reading that a unit of the other reading shares
    /// a declaration site with, that other unit.
    pub(crate) site_equivalents: HashMap<CodeUnit, Vec<CodeUnit>>,
}

impl CppCReading {
    fn build(c_state: &FileState, cpp_state: &FileState) -> Self {
        let c_only: Vec<CodeUnit> = c_state
            .declarations
            .iter()
            .filter(|unit| !cpp_state.declarations.contains(*unit))
            .cloned()
            .collect();
        let cpp_only: Vec<CodeUnit> = cpp_state
            .declarations
            .iter()
            .filter(|unit| !c_state.declarations.contains(*unit))
            .cloned()
            .collect();

        let mut by_site: HashMap<CppDeclarationSite, (Vec<CodeUnit>, Vec<CodeUnit>)> =
            HashMap::default();
        for unit in &c_only {
            if let Some(site) = CppDeclarationSite::of(unit, &c_state.ranges) {
                by_site.entry(site).or_default().0.push(unit.clone());
            }
        }
        for unit in &cpp_only {
            if let Some(site) = CppDeclarationSite::of(unit, &cpp_state.ranges) {
                by_site.entry(site).or_default().1.push(unit.clone());
            }
        }
        let mut site_equivalents: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
        for (c_units, cpp_units) in by_site.into_values() {
            for unit in &c_units {
                site_equivalents
                    .entry(unit.clone())
                    .or_default()
                    .extend(cpp_units.iter().cloned());
            }
            for unit in &cpp_units {
                site_equivalents
                    .entry(unit.clone())
                    .or_default()
                    .extend(c_units.iter().cloned());
            }
        }
        site_equivalents.retain(|_, equivalents| !equivalents.is_empty());

        Self {
            declarations: c_state.declarations.iter().cloned().collect(),
            ranges: c_state.ranges.clone(),
            children: c_state.children.clone(),
            top_level_declarations: c_state.top_level_declarations.clone(),
            c_only,
            cpp_only,
            site_equivalents,
        }
    }
}

/// Every C-reading-only identity in the workspace, keyed for lookup by the
/// two names resolution asks about.
#[derive(Default)]
pub(crate) struct CppCReadingIndex {
    pub(crate) all: Vec<CodeUnit>,
    pub(crate) by_identifier: HashMap<String, Vec<CodeUnit>>,
    pub(crate) by_fq_name: HashMap<String, Vec<CodeUnit>>,
}

impl CppAnalyzer {
    /// The C reading of `file`'s blob, or `None` when the two readings agree
    /// (no `cpp:c` rows were stored) or `file` is not a header this analyzer
    /// serves.
    ///
    /// Memoized per analyzer generation: the answer is a pure function of the
    /// blob, and the memo is what keeps a store hydration off the per-query
    /// path. A translation unit never has a second reading -- its own
    /// extension settles its dialect -- so it is refused without touching the
    /// store.
    pub(crate) fn c_reading(&self, file: &ProjectFile) -> Option<Arc<CppCReading>> {
        if imports::is_cpp_translation_unit(file) {
            return None;
        }
        self.c_readings_by_file.get_with_by_ref(file, || {
            let c_state = self
                .inner
                .projection_file_state(file, CPP_C_STORAGE_LANGUAGE_KEY)?;
            let cpp_state = self.inner.fetch_file_state(file)?;
            Some(Arc::new(CppCReading::build(&c_state, &cpp_state)))
        })
    }

    /// Whether a reference written in the header `file` reads its visible
    /// declarations with C semantics: every translation unit that provably
    /// compiles this header compiles it as C.
    ///
    /// `Mixed` is deliberately false: per the ExecPlan's decision log, forward
    /// resolution from a header both languages include reports the C++
    /// identity, and forward/inverse agreement is restored by the
    /// site-equivalence union instead. A translation unit answers false here
    /// because its own extension already settles the question -- the two
    /// halves meet in
    /// [`brokk_bifrost_cpp::graph::resolver::reference_uses_c_semantics`].
    pub(crate) fn header_uses_c_semantics(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> bool {
        !is_c_source_file(file)
            && !imports::is_cpp_translation_unit(file)
            && self.header_language_attribution(token, file) == HeaderLanguageAttribution::C
    }

    /// The declarations of `file` as the reading named by `c_semantics` sees
    /// them.
    ///
    /// This is the one place candidate enumeration chooses a reading. Every
    /// include-activation, guard-compatibility, block-scope and ambiguity rule
    /// downstream runs unchanged on whichever set comes back.
    pub(crate) fn declarations_in_reading(
        &self,
        file: &ProjectFile,
        c_semantics: bool,
    ) -> BTreeSet<CodeUnit> {
        if !c_semantics {
            return CodeUnitIndex::declarations(self, file);
        }
        match self.c_reading(file) {
            Some(reading) => reading.declarations.clone(),
            None => CodeUnitIndex::declarations(self, file),
        }
    }

    /// The C reading of `file`, but only where the workspace index actually
    /// publishes its identities.
    ///
    /// Extraction is content-pure, so a `cpp:c` row-set exists for ANY header
    /// declaring a tag inside an aggregate -- including in a workspace no C
    /// translation unit touches. Publishing those identities there would put a
    /// phantom file-scope tag in every symbol listing and let a bare `struct
    /// Inner` in a `.cpp` file match it. Only a header some translation unit
    /// provably compiles as C (`C` or `Mixed`) publishes its second identity;
    /// `Cpp` and `Unknown` keep the single C++ reading they always had.
    ///
    /// [`Self::declarations_in_reading`] deliberately does NOT go through this
    /// gate: it is asked for the C reading only when the reference's own root
    /// compiles as C, which already implies this attribution.
    fn published_c_reading(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<CppCReading>> {
        if is_c_source_file(file)
            || matches!(
                self.header_language_attribution(token, file),
                HeaderLanguageAttribution::Cpp | HeaderLanguageAttribution::Unknown
            )
        {
            return None;
        }
        self.c_reading(file)
    }

    /// The units of the other reading that share `code_unit`'s declaration
    /// site, empty when the two readings agree about it or when only one of
    /// them is published (see [`Self::published_c_reading`]).
    ///
    /// Matched on `(source file, declaration byte range)`. A caller unions
    /// inverse results across these so a query against either identity of one
    /// declaration reports every reference found under both.
    pub(crate) fn site_equivalent_units(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let Some(reading) = self.published_c_reading(token, code_unit.source()) else {
            return Vec::new();
        };
        reading
            .site_equivalents
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
    }

    /// The identities the C reading of `file` adds to the workspace index.
    pub(crate) fn c_reading_index_additions(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<CodeUnit> {
        self.published_c_reading(token, file)
            .map(|reading| reading.c_only.clone())
            .unwrap_or_default()
    }

    /// Every C-reading identity the workspace index carries, keyed for the
    /// two questions resolution asks by name.
    ///
    /// One whole-workspace pass, memoized for the analyzer generation exactly
    /// like the include target index beside it. It is cheap on a C++ workspace
    /// -- no header is attributed C or Mixed, so no blob is probed at all --
    /// and bounded by the headers a C translation unit reaches otherwise.
    pub(crate) fn c_reading_index(&self, token: QueryToken<'_>) -> Arc<CppCReadingIndex> {
        self.c_reading_index.get_or_build(
            || self.build_c_reading_index(token),
            || self.build_c_reading_index(token),
        )
    }

    fn build_c_reading_index(&self, token: QueryToken<'_>) -> CppCReadingIndex {
        let mut index = CppCReadingIndex::default();
        for file in self.inner.analyzed_files() {
            for unit in self.c_reading_index_additions(token, &file) {
                index
                    .by_identifier
                    .entry(unit.identifier().to_string())
                    .or_default()
                    .push(unit.clone());
                index
                    .by_fq_name
                    .entry(unit.fq_name())
                    .or_default()
                    .push(unit.clone());
                index.all.push(unit);
            }
        }
        index
    }

    /// Every C-reading identity the workspace index carries, over all files
    /// this analyzer serves.
    pub(crate) fn c_reading_index_additions_for_workspace(
        &self,
        token: QueryToken<'_>,
    ) -> Vec<CodeUnit> {
        self.c_reading_index(token).all.clone()
    }

    /// Declaration ranges for a unit the C reading mints and the `cpp` row-set
    /// therefore has none for. `None` leaves the store's answer alone.
    pub(crate) fn c_reading_ranges(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
    ) -> Option<Vec<Range>> {
        let reading = self.published_c_reading(token, code_unit.source())?;
        reading.ranges.get(code_unit).cloned()
    }

    /// The C reading's child edges for `code_unit`, for the same reason.
    pub(crate) fn c_reading_children(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
    ) -> Option<Vec<CodeUnit>> {
        let reading = self.published_c_reading(token, code_unit.source())?;
        reading.children.get(code_unit).cloned()
    }

    /// The C reading's syntactic owner of `code_unit`.
    pub(crate) fn c_reading_parent(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        let reading = self.published_c_reading(token, code_unit.source())?;
        reading.children.iter().find_map(|(parent, children)| {
            children
                .iter()
                .any(|child| child == code_unit)
                .then(|| parent.clone())
        })
    }
}
