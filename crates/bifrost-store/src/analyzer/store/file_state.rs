use crate::analyzer::semantic::source_admission::SourceAdmissionRefusal;

use brokk_bifrost_core::analyzer::prepared_syntax::IndexedFileFacts;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceIndex;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

use crate::analyzer::CodeUnit;
use crate::analyzer::CppTemplateMetadata;
use crate::analyzer::ImportInfo;
use crate::analyzer::Range;
use crate::analyzer::RubyMethodDispatchMode;
use crate::analyzer::SignatureMetadata;

use crate::hash::HashMap;
use crate::hash::HashSet;

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct FileState {
    #[doc(hidden)]
    pub source: String,
    #[doc(hidden)]
    pub package_name: String,
    /// Content-only qualifier persisted with a blob. Languages whose canonical
    /// package identity depends on the live path recompose it during hydration.
    #[doc(hidden)]
    pub content_qualifier: String,
    #[doc(hidden)]
    pub top_level_declarations: Vec<CodeUnit>,
    #[doc(hidden)]
    pub declarations: HashSet<CodeUnit>,
    #[doc(hidden)]
    pub definition_lookup_units: HashSet<CodeUnit>,
    #[doc(hidden)]
    pub imports: Vec<ImportInfo>,
    #[doc(hidden)]
    pub scala_exports: HashMap<CodeUnit, Vec<crate::analyzer::ScalaExportInfo>>,
    /// Per-file Rust usage facts on their way to the `rust_*` fact tables (see
    /// [`brokk_bifrost_core::analyzer::rust_facts`]). Empty for every other
    /// language, and empty on a `FileState` hydrated from the store: the query
    /// side reads those rows straight from SQL by blob oid rather than through
    /// a materialized `FileState`, so hydrating them here would be dead weight
    /// on every cache hit. Same rule as `parse_errors` below.
    #[doc(hidden)]
    pub rust_usage_facts: brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts,
    /// Immutable file-local resolution inputs produced by the adapter's parse.
    /// Store hydration leaves this empty until the fact family is persisted;
    /// request-time consumers must not reconstruct it by parsing source.
    #[doc(hidden)]
    pub resolution_facts: brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    /// Write-side canonical source rows. Hydration intentionally does not
    /// materialize these: bounded consumers read selected persisted rows.
    #[doc(hidden)]
    pub source_facts: Option<brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts>,
    #[doc(hidden)]
    pub source_declaration_units: Vec<(
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
        CodeUnit,
    )>,
    #[doc(hidden)]
    pub source_declaration_metadata:
        Vec<brokk_bifrost_core::analyzer::parsed_file::SourceDeclarationMetadataLink>,
    #[doc(hidden)]
    pub raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    #[doc(hidden)]
    pub supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>,
    #[doc(hidden)]
    pub type_identifiers: HashSet<String>,
    #[doc(hidden)]
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    #[doc(hidden)]
    pub signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    /// Captured display-label ordinal for each metadata ordinal, including
    /// synthetic units that have no written source-declaration identity.
    #[doc(hidden)]
    pub signature_metadata_signature_ordinals: HashMap<CodeUnit, Vec<usize>>,
    #[doc(hidden)]
    pub cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    #[doc(hidden)]
    pub ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    #[doc(hidden)]
    pub ranges: HashMap<CodeUnit, Vec<Range>>,
    #[doc(hidden)]
    pub children: HashMap<CodeUnit, Vec<CodeUnit>>,
    #[doc(hidden)]
    pub scala_traits: HashSet<CodeUnit>,
    #[doc(hidden)]
    pub type_aliases: HashSet<CodeUnit>,
    #[doc(hidden)]
    pub contains_tests: bool,
    /// Declarations that lie in a structurally-evidenced test region (see
    /// [`ParsedFile::test_region_units`]). Persisted per-unit via the
    /// `code_units.in_test_region` column and consulted by symbol-level test
    /// filtering (`search_symbols`, commit symbol snapshots). Empty for
    /// languages that do not thread test-region taint.
    #[doc(hidden)]
    pub test_region_units: HashSet<CodeUnit>,
    /// Declaration-materialization provenance recorded by the language walk
    /// (see [`ParsedFile::materialization_records`]); persisted per file.
    #[doc(hidden)]
    pub materialization_records: Vec<MaterializationRecord>,
    /// Tree-sitter parse errors captured during `analyze_file`. The LSP
    /// diagnostic handler reads this instead of re-parsing on every keystroke
    /// — see issue #102. `None` when the `FileState` was hydrated from the
    /// blob store (which does not carry parse_errors); the diagnostic handler
    /// falls back to a fresh parse in that case until the next `update`
    /// re-populates the field.
    #[doc(hidden)]
    pub parse_errors: Option<Vec<crate::analyzer::ParseError>>,
    /// Whether tree-sitter completed the whole source before this state was
    /// assembled. A timed-out parse still carries a conservative file-scope
    /// marker for in-memory reads, but the store must never publish that
    /// marker as a complete parsed blob.
    #[doc(hidden)]
    pub parse_complete: bool,
    /// Whether every declaration above is a reading of a completed parse
    /// (#3501). Unlike `parse_complete`, a partial file is published: its
    /// blob is persisted with this value, and hydration restores it.
    #[doc(hidden)]
    pub completeness: crate::analyzer::ParseCompleteness,
    /// Row-sets this same blob contributes under storage language keys other
    /// than the file's own, produced by
    /// [`LanguageAdapter::parse_file_with_projections`] and persisted alongside
    /// the primary row-set (see `write_parsed_blob_tx`).
    ///
    /// Empty for every language but C++, and empty on a hydrated state: a
    /// projection is a write-side product of one parse, never a hydration
    /// output. `blobs`/`code_units` are already keyed `(blob_oid, lang)`, so
    /// this needs no schema of its own.
    #[doc(hidden)]
    pub additional_projections: Vec<(&'static str, Arc<FileState>)>,
}

impl FileState {
    /// Return a conservative retained-byte estimate for cache admission.
    ///
    /// Rust cannot report heap allocation sizes. This accounts for owned
    /// buffers and map slots, then charges a fixed allocator allowance. The
    /// value is a cache budget estimate, not an RSS measurement.
    #[doc(hidden)]
    pub fn estimated_retained_bytes(&self) -> usize {
        const ALLOCATION_ALLOWANCE_NUMERATOR: usize = 3;
        const ALLOCATION_ALLOWANCE_DENOMINATOR: usize = 2;

        let strings = self
            .imports
            .iter()
            .map(|import| import.raw_snippet.capacity())
            .chain(self.type_identifiers.iter().map(|value| value.capacity()))
            .chain(self.raw_supertypes.iter().flat_map(|(unit, values)| {
                std::iter::once(unit.fq_name().capacity())
                    .chain(values.iter().map(|value| value.capacity()))
            }))
            .chain(
                self.supertype_lookup_paths
                    .values()
                    .flat_map(|values| values.iter().map(|value| value.capacity())),
            )
            .chain(
                self.signatures
                    .values()
                    .flat_map(|values| values.iter().map(|value| value.capacity())),
            )
            .fold(0usize, usize::saturating_add);
        let collection_slots = self
            .top_level_declarations
            .capacity()
            .saturating_mul(std::mem::size_of::<CodeUnit>())
            .saturating_add(
                self.declarations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.definition_lookup_units
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.imports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ImportInfo>()),
            )
            .saturating_add(
                self.scala_exports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(
                        CodeUnit,
                        Vec<crate::analyzer::ScalaExportInfo>,
                    )>()),
            )
            .saturating_add(
                self.raw_supertypes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<String>)>()),
            )
            .saturating_add(
                self.supertype_lookup_paths
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<String>)>()),
            )
            .saturating_add(
                self.type_identifiers
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.signatures
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<String>)>()),
            )
            .saturating_add(
                self.signature_metadata
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<SignatureMetadata>)>()),
            )
            .saturating_add(
                self.signature_metadata_signature_ordinals
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<usize>)>())
                    .saturating_add(
                        self.signature_metadata_signature_ordinals
                            .values()
                            .map(|ordinals| {
                                ordinals
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<usize>())
                            })
                            .fold(0usize, usize::saturating_add),
                    ),
            )
            .saturating_add(
                self.cpp_template_metadata
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, CppTemplateMetadata)>()),
            )
            .saturating_add(
                self.ruby_method_dispatch_modes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, RubyMethodDispatchMode)>()),
            )
            .saturating_add(
                self.ranges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<Range>)>()),
            )
            .saturating_add(
                self.children
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(CodeUnit, Vec<CodeUnit>)>()),
            )
            .saturating_add(
                self.scala_traits
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.type_aliases
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.test_region_units
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CodeUnit>()),
            )
            .saturating_add(
                self.materialization_records
                    .capacity()
                    .saturating_mul(std::mem::size_of::<MaterializationRecord>()),
            )
            .saturating_add(
                self.parse_errors
                    .as_ref()
                    .map(|errors| {
                        errors
                            .capacity()
                            .saturating_mul(std::mem::size_of::<crate::analyzer::ParseError>())
                    })
                    .unwrap_or_default(),
            );
        let direct = std::mem::size_of::<Self>()
            .saturating_add(self.source.capacity())
            .saturating_add(self.package_name.capacity())
            .saturating_add(self.content_qualifier.capacity())
            .saturating_add(self.resolution_facts.estimated_retained_bytes())
            .saturating_add(
                self.source_facts
                    .as_ref()
                    .map_or(0, |facts| facts.estimated_retained_bytes()),
            )
            .saturating_add(self.source_declaration_units.capacity().saturating_mul(
                std::mem::size_of::<(
                    brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
                    CodeUnit,
                )>(),
            ))
            .saturating_add(self.source_declaration_metadata.capacity().saturating_mul(
                std::mem::size_of::<
                    brokk_bifrost_core::analyzer::parsed_file::SourceDeclarationMetadataLink,
                >(),
            ))
            .saturating_add(strings)
            .saturating_add(collection_slots);
        direct
            .saturating_mul(ALLOCATION_ALLOWANCE_NUMERATOR)
            .saturating_div(ALLOCATION_ALLOWANCE_DENOMINATOR)
    }
}

/// The indexed backing a prepared tree consults for declaration facts. The
/// contract itself is core-owned so a language crate can consume prepared
/// syntax; `FileState` is the analysis-side storage record that satisfies it.
impl PreparedSourceIndex for FileState {
    fn source(&self) -> &str {
        &self.source
    }

    fn declaration_ranges(&self, code_unit: &CodeUnit) -> Option<&[Range]> {
        self.ranges.get(code_unit).map(Vec::as_slice)
    }

    fn direct_children(&self, owner: &CodeUnit) -> Option<&[CodeUnit]> {
        self.children.get(owner).map(Vec::as_slice)
    }
}

/// The narrowed view a bulk state read hands to a whole-workspace pass; see
/// [`IndexedFileFacts`].
impl IndexedFileFacts for FileState {
    fn top_level_declarations(&self) -> &[CodeUnit] {
        &self.top_level_declarations
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }
}

#[doc(hidden)]
pub enum PreparedSyntaxPreparation {
    Complete(Option<Arc<PreparedSyntaxTree>>),
    Refused(SourceAdmissionRefusal),
    TimedOut,
    Cancelled,
}
