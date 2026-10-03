//! The per-file parse product a language walk returns.
//!
//! `ParsedFile` accumulates the declarations, imports, signatures and ranges
//! that one source file yields. It holds model-layer data only, so a language
//! crate below `brokk-bifrost-analysis` can build one and return it; the
//! storage pipeline that consumes it stays in the analysis crate.

use std::hash::{Hash, Hasher};
use tree_sitter::Node;

use crate::analyzer::model::{
    CodeUnit, CppTemplateMetadata, ImportInfo, ProjectFile, Range, RubyMethodDispatchMode,
    ScalaExportInfo, SignatureMetadata, StructuredImportPath, StructuredImportPathKind,
    StructuredImportScope,
};
use crate::analyzer::resolution_facts::{FileResolutionFacts, ResolutionSiteId};
use crate::analyzer::rust_facts::{
    RustDeclarationPropertyFact, RustImportContextFact, RustItemSourceFacts, RustModuleSourceFacts,
    RustTypeSourceFact, RustUsageFacts,
};
use crate::analyzer::source_facts::{
    SourceDeclarationId, SourceDeclarationVisibilityFact, SourceFactRows, SourceImportId,
    SourceOccurrenceId,
};
use crate::analyzer::structural::facts::StructuralFactRows;
use crate::analyzer::structural::materialization::MaterializationRecord;
use crate::analyzer::tree_walk::node_range;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;

#[cfg(test)]
#[path = "parsed_file_source_import_tests.rs"]
mod parsed_file_source_import_tests;

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub package_name: String,
    pub content_qualifier: String,
    pub top_level_declarations: Vec<CodeUnit>,
    declarations: HashSet<CodeUnit>,
    declaration_identities: HashMap<DeclarationIdentity, usize>,
    pub definition_lookup_units: HashSet<CodeUnit>,
    pub imports: Vec<ImportInfo>,
    pub scala_exports: HashMap<CodeUnit, Vec<ScalaExportInfo>>,
    pub raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>,
    pub type_identifiers: HashSet<String>,
    /// File test classification captured by the coordinated primary producer.
    /// None means the language still supplies its separate adapter classifier.
    pub contains_tests: Option<bool>,
    /// Transient executable-lowering projection produced with C# declarations.
    /// No indexed consumer reads this projection; complete executable artifacts
    /// own their derived cache. Source identities belong to `source_facts`.
    pub csharp_semantic_declarations: Vec<CSharpSemanticDeclaration>,
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    pub signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    /// For each metadata ordinal, the deduplicated display-signature ordinal
    /// created at the same admission point. These are separate identities:
    /// different metadata rows may share a label, and plain signatures can
    /// be admitted before any metadata exists.
    pub signature_metadata_signature_ordinals: HashMap<CodeUnit, Vec<usize>>,
    pub cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    pub ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    pub scala_traits: HashSet<CodeUnit>,
    pub type_aliases: HashSet<CodeUnit>,
    pub ranges: HashMap<CodeUnit, Vec<Range>>,
    /// Physical declaration occurrences retained only for request-time navigation.
    ///
    /// Unlike `ranges`, this collection is not persisted or exposed through
    /// `IAnalyzer`: broad consumers continue to observe the preferred semantic
    /// declaration range, while explicit navigation may distinguish prototypes
    /// and bodies that share one `CodeUnit` identity.
    pub navigation_ranges: HashMap<CodeUnit, Vec<Range>>,
    pub navigation_ranges_truncated: HashSet<CodeUnit>,
    pub children: HashMap<CodeUnit, Vec<CodeUnit>>,
    /// The inverse of `children`: for each unit, the owners whose child list
    /// names it.
    ///
    /// Kept so that removing a unit can unlink it from the one or two lists
    /// that actually name it. Without the inverse edge the only way to find
    /// them is to `retain` over every vec in `children`, which costs the whole
    /// file per removal; a generated C header that declares one aggregate per
    /// type -- pwru's 2.5MB `vmlinux-x86.h` yields 75,899 declarations under a
    /// single module -- then spends quadratic time comparing `CodeUnit`s
    /// against each other (#2358).
    child_owners: HashMap<CodeUnit, Vec<CodeUnit>>,
    /// The declarations currently exposed through `top_level_declarations`.
    ///
    /// This inverse membership lets deferred replacement preserve the public
    /// ordering contract without scanning the whole top-level vec to discover
    /// whether one declaration occurs there.
    top_level_units: HashSet<CodeUnit>,
    /// Units whose old physical ordering entries remain until one batched
    /// compaction at the end of a language walk.
    deferred_replacements: HashMap<CodeUnit, DeferredReplacement>,
    /// Declarations that lie in a structurally-evidenced test region: a
    /// test-attributed item or any declaration nested inside a `#[cfg(test)]`
    /// (or otherwise test-attributed) module/item. Populated by language walks
    /// that thread test-region taint through their traversal (currently Rust);
    /// other languages leave it empty, so their declarations default untainted.
    pub test_region_units: HashSet<CodeUnit>,
    /// Per-file Rust usage facts (exports, import targets, modules, identifier
    /// occurrences, module routes) on their way to the `rust_*` fact tables.
    /// Default-empty for every other language. See
    /// [`crate::analyzer::rust_facts`].
    pub rust_usage_facts: RustUsageFacts,
    /// Immutable file-local inputs to compositional binding and type transfer.
    /// Default-empty until a language lowerer explicitly supports this fact
    /// family. The rows contain no selected cross-file targets.
    pub resolution_facts: FileResolutionFacts,
    /// Canonical source occurrences and their file-local consumer projections.
    /// Present once a language's coordinated producer supplies the complete
    /// supported structural output. These handles never contain a mount path.
    pub source_facts: Option<ParsedSourceFacts>,
    /// The placement-dependent bridge from canonical declarations to display
    /// units. It is deliberately outside the content-owned source rows.
    pub source_declaration_units: Vec<(SourceDeclarationId, CodeUnit)>,
    /// Exact placement and metadata-row links for source declarations. The
    /// metadata ordinal is the index in this unit's deduplicated
    /// `signature_metadata` vector, not the display signature ordinal.
    pub source_declaration_metadata: Vec<SourceDeclarationMetadataLink>,
    /// Declaration-materialization provenance recorded by the language walk
    /// that created the declarations it describes (issue #1476): generation
    /// sites and their generated units, dynamic generation sites, export
    /// declarations, recovered declarations, and preprocessor-conditional
    /// intervals. Persisted with the file's other analysis facts.
    pub materialization_records: Vec<MaterializationRecord>,
}

/// A primary-owned C# declaration input to fresh executable lowering. Event
/// declarations participate without manufacturing display CodeUnits.
#[derive(Debug, Clone)]
pub struct CSharpSemanticDeclaration {
    pub declaration: SourceDeclarationId,
    pub namespace: Vec<String>,
    pub owner: String,
    pub kind: CSharpSemanticDeclarationKind,
    pub is_static: bool,
    pub type_spelling: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpSemanticDeclarationKind {
    StaticMethodReturn,
    Member,
}

/// Links one source declaration to the display metadata row created for it.
///
/// This is placement-dependent, so it remains on [`ParsedFile`] rather than
/// in the content-owned source fact arena. Multiple source declarations may
/// intentionally share one metadata ordinal when their complete metadata is
/// deduplicated; each link is retained independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDeclarationMetadataLink {
    pub declaration: SourceDeclarationId,
    pub unit: CodeUnit,
    pub metadata_ordinal: usize,
}

/// One canonical source-backed import leaf. The enclosing `ParsedSourceFacts`
/// vector assigns its dense [`SourceImportId`] by index; projections carry that
/// id explicitly rather than matching consumer ordinals, names, or ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceImportFact {
    pub declaration: SourceOccurrenceId,
    pub target: Option<SourceOccurrenceId>,
    pub alias_occurrence: Option<SourceOccurrenceId>,
    pub statement: String,
    pub is_wildcard: bool,
    pub is_global: bool,
    /// Rust `#[macro_use] extern crate` imports the target macro prelude.
    pub is_macro_use: bool,
    pub identifier: Option<String>,
    pub alias: Option<String>,
    /// A malformed directive still owns source identity and display metadata,
    /// even when its path cannot be interpreted. This differs from a known
    /// structured path with empty lists.
    pub path: Option<SourceImportPathFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceImportPathFact {
    pub kind: Option<StructuredImportPathKind>,
    pub segments: Vec<String>,
    pub lexical_prefixes: Vec<String>,
    pub lexical_scopes: Vec<SourceOccurrenceId>,
}

impl SourceImportPathFact {
    fn estimated_retained_bytes(&self) -> usize {
        self.segments
            .capacity()
            .saturating_mul(std::mem::size_of::<String>())
            .saturating_add(
                self.segments
                    .iter()
                    .map(String::capacity)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.lexical_prefixes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.lexical_prefixes
                    .iter()
                    .map(String::capacity)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.lexical_scopes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceOccurrenceId>()),
            )
    }
}

impl SourceImportFact {
    /// Heap storage owned by this leaf, excluding its inline struct storage.
    pub fn estimated_retained_bytes(&self) -> usize {
        self.statement
            .capacity()
            .saturating_add(self.identifier.as_ref().map_or(0, String::capacity))
            .saturating_add(self.alias.as_ref().map_or(0, String::capacity))
            .saturating_add(
                self.path
                    .as_ref()
                    .map_or(0, SourceImportPathFact::estimated_retained_bytes),
            )
    }

    /// Capture the structured import interpretation while the producer owns
    /// the source occurrences. Display byte spans in `ImportInfo` are not
    /// copied; `import_info` materializes them from the canonical arena.
    pub fn from_import(
        import: ImportInfo,
        declaration: SourceOccurrenceId,
        target: Option<SourceOccurrenceId>,
        alias_occurrence: Option<SourceOccurrenceId>,
        lexical_scopes: Vec<SourceOccurrenceId>,
    ) -> Self {
        assert!(
            import.path.is_some() || lexical_scopes.is_empty(),
            "an unavailable import path cannot own path scope projections"
        );
        let path = import.path.map(|path| SourceImportPathFact {
            kind: path.kind,
            segments: path.segments,
            lexical_prefixes: path.lexical_prefixes,
            lexical_scopes,
        });
        Self {
            declaration,
            target,
            alias_occurrence,
            statement: import.raw_snippet,
            is_wildcard: import.is_wildcard,
            is_global: import.is_global,
            is_macro_use: false,
            identifier: import.identifier,
            alias: import.alias,
            path,
        }
    }

    /// Materialize the existing generic DTO without making its byte ranges a
    /// second source authority.
    pub fn import_info(&self, source: &SourceFactRows) -> ImportInfo {
        let declaration_start_byte = source.occurrence(self.declaration).range.start_byte;
        let binder_span = self
            .alias_occurrence
            .or(self.target)
            .map(|occurrence| source.occurrence(occurrence).range)
            .map(|range| crate::analyzer::structural::facts::Span {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            });
        ImportInfo {
            raw_snippet: self.statement.clone(),
            is_wildcard: self.is_wildcard,
            is_global: self.is_global,
            identifier: self.identifier.clone(),
            alias: self.alias.clone(),
            path: self.path.as_ref().map(|path| StructuredImportPath {
                segments: path.segments.clone(),
                kind: path.kind,
                lexical_prefixes: path.lexical_prefixes.clone(),
                lexical_scopes: path
                    .lexical_scopes
                    .iter()
                    .map(|occurrence| {
                        let range = source.occurrence(*occurrence).range;
                        StructuredImportScope {
                            start_byte: range.start_byte,
                            end_byte: range.end_byte,
                        }
                    })
                    .collect(),
                declaration_start_byte,
            }),
            binder_span,
        }
    }
}

/// Write-side output of the coordinated source producer. Native site ids and
/// structural preorder ids are interpretation indices into the source arena.
/// Neither projection may author a separate source range during publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSourceFacts {
    pub js_ts: Option<crate::analyzer::js_ts_facts::JsTsSourceFacts>,
    pub php: Option<crate::analyzer::php_facts::PhpSourceFacts>,
    pub cpp: Option<crate::analyzer::cpp_facts::CppSourceFacts>,
    /// Complete Go declaration syntax before display/native admission.
    /// Absence is unavailable, not an authoritative empty file.
    pub go: Option<crate::analyzer::go_facts::GoSourceFacts>,
    pub java: Option<crate::analyzer::java_facts::JavaSourceFacts>,
    pub scala: Option<crate::analyzer::scala_facts::ScalaSourceFacts>,
    pub ruby: Option<crate::analyzer::ruby_facts::RubySourceFacts>,
    pub python: Option<crate::analyzer::python_facts::PythonSourceFacts>,
    /// Exact input extent captured by the producer. Storage projections may
    /// omit transient source text without losing canonical occurrence bounds.
    pub source_bytes: usize,
    pub occurrences: SourceFactRows,
    pub structural: StructuralFactRows,
    pub native_site_occurrences: Vec<SourceOccurrenceId>,
    pub native_declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    /// Canonical source-owned declaration visibility. `None` means the
    /// producer has not published this family; `Some(empty)` means it has
    /// published the family and found no eligible declarations.
    pub declaration_visibilities: Option<Vec<SourceDeclarationVisibilityFact>>,
    /// Rust visibility, cfg, and value-constructor properties keyed by the
    /// exact source declaration identity created by the producer. Local
    /// parameter and pattern declarations are intentionally absent.
    pub rust_declaration_properties: Vec<RustDeclarationPropertyFact>,
    /// Canonical Rust module declarations, invocation identities, and ordered
    /// inventory/scope/route links. `None` means this language has no Rust
    /// module-source extension; Rust preparation always publishes `Some`.
    pub rust_modules: Option<RustModuleSourceFacts>,
    /// Structured Rust type syntax captured before declaration-owner lookup.
    /// These construction rows retain unsupported shapes without inventing a
    /// nominal owner. Persisted impl/type consumers are migrated separately.
    pub rust_types: Vec<RustTypeSourceFact>,
    /// Canonical source-owned impl, trait, alias, callable, and lexical
    /// context rows. These are produced before display/native admission.
    pub rust_items: RustItemSourceFacts,
    /// Every producer-linked semantic import leaf, including Rust local-only
    /// leaves that are absent from the generic projection and embedded macro
    /// leaves that have no Rust target fact. `SourceImportId` is this vector's
    /// dense index.
    pub imports: Vec<SourceImportFact>,
    /// Explicit projection links in the final `ParsedFile::imports` order.
    /// The order is producer-defined and need not match `imports` order.
    pub generic_imports: Vec<SourceImportId>,
    /// Rust-only owner, scope, visibility, and cfg interpretation attached to
    /// each primary import declaration. Embedded macro imports intentionally do
    /// not appear here because they have no primary Rust target authority.
    pub rust_import_contexts: Vec<RustImportContextFact>,
}

impl ParsedSourceFacts {
    /// Assert the invariants that relate the occurrence arena to the other
    /// common families. No narrower constructor holds both sides, so the
    /// store writer calls this before it inserts the facts. `SourceFactRows`,
    /// `StructuralFactRows` and the language `valid_links` checks own the rest.
    pub fn assert_storable(&self) {
        let occurrences = &self.occurrences;
        for (index, occurrence) in occurrences.occurrences().iter().enumerate() {
            assert!(
                occurrence.range.end_byte <= self.source_bytes,
                "source occurrence {index} {occurrence:?} ends past the {}-byte source",
                self.source_bytes
            );
        }
        let range = |id: SourceOccurrenceId| occurrences.occurrence(id).range;
        for (index, import) in self.imports.iter().enumerate() {
            let declaration = range(import.declaration);
            for part in [import.target, import.alias_occurrence]
                .into_iter()
                .flatten()
            {
                assert!(
                    declaration.contains(&range(part)),
                    "source import {index} occurrence {part:?} {:?} lies outside its declaration {declaration:?}: {import:?}",
                    range(part)
                );
            }
            // Scopes run from outermost to innermost, and the innermost
            // contains the declaration.
            let scopes = import.path.iter().flat_map(|path| &path.lexical_scopes);
            let mut inner = declaration;
            for &scope in scopes.rev() {
                let outer = range(scope);
                assert!(
                    outer.contains(&inner),
                    "source import {index} scope {scope:?} {outer:?} does not contain {inner:?}: {import:?}"
                );
                inner = outer;
            }
        }
        let nodes = self.structural.nodes();
        for (index, node) in nodes.iter().enumerate() {
            let Some(name) = node.name.map(range) else {
                continue;
            };
            let span = range(node.occurrence);
            if span.contains(&name) {
                continue;
            }
            // A constructor can use its enclosing class's written name. The
            // walk is as deep as the nesting, so it runs only in debug builds.
            let same_bytes = |other: Range| {
                (other.start_byte, other.end_byte) == (name.start_byte, name.end_byte)
            };
            debug_assert!(
                std::iter::successors(node.parent, |&parent| nodes[parent as usize].parent).any(
                    |parent| nodes[parent as usize]
                        .name
                        .map(range)
                        .is_some_and(same_bytes)
                ),
                "structural node {index} name {name:?} lies outside its span {span:?} and is no ancestor's name: {node:?}"
            );
        }
    }

    /// Present optional families published by an adapter-owned storage capability.
    /// `Some(empty)` still requires publication.
    pub fn adapter_source_family_count(&self) -> usize {
        [
            self.rust_modules.is_some(),
            self.js_ts.is_some(),
            self.php.is_some(),
            self.cpp.is_some(),
            self.go.is_some(),
            self.java.is_some(),
            self.scala.is_some(),
            self.ruby.is_some(),
            self.python.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.occurrences
            .estimated_bytes()
            .saturating_add(self.js_ts.as_ref().map_or(
                0,
                crate::analyzer::js_ts_facts::JsTsSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.scala.as_ref().map_or(
                0,
                crate::analyzer::scala_facts::ScalaSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.php.as_ref().map_or(
                0,
                crate::analyzer::php_facts::PhpSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.cpp.as_ref().map_or(
                0,
                crate::analyzer::cpp_facts::CppSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.go.as_ref().map_or(
                0,
                crate::analyzer::go_facts::GoSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.ruby.as_ref().map_or(
                0,
                crate::analyzer::ruby_facts::RubySourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.java.as_ref().map_or(
                0,
                crate::analyzer::java_facts::JavaSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(self.python.as_ref().map_or(
                0,
                crate::analyzer::python_facts::PythonSourceFacts::estimated_retained_bytes,
            ))
            .saturating_add(
                usize::try_from(self.structural.estimated_bytes()).unwrap_or(usize::MAX),
            )
            .saturating_add(
                self.native_site_occurrences
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceOccurrenceId>()),
            )
            .saturating_add(
                self.native_declaration_sources
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(ResolutionSiteId, SourceDeclarationId)>()),
            )
            .saturating_add(self.declaration_visibilities.as_ref().map_or(0, |facts| {
                facts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceDeclarationVisibilityFact>())
            }))
            .saturating_add(
                self.rust_declaration_properties
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustDeclarationPropertyFact>()),
            )
            .saturating_add(
                self.rust_declaration_properties
                    .iter()
                    .map(RustDeclarationPropertyFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.rust_modules
                    .as_ref()
                    .map_or(0, RustModuleSourceFacts::estimated_retained_bytes),
            )
            .saturating_add(
                self.rust_types
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustTypeSourceFact>()),
            )
            .saturating_add(
                self.rust_types
                    .iter()
                    .map(RustTypeSourceFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.rust_items.estimated_retained_bytes())
            .saturating_add(
                self.imports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceImportFact>()),
            )
            .saturating_add(
                self.imports
                    .iter()
                    .map(SourceImportFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.generic_imports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceImportId>()),
            )
            .saturating_add(
                self.rust_import_contexts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RustImportContextFact>()),
            )
            .saturating_add(
                self.rust_import_contexts
                    .iter()
                    .map(RustImportContextFact::estimated_retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
    }
}

#[derive(Debug, Clone, Default)]
struct DeferredReplacement {
    affected_owners: HashSet<CodeUnit>,
}

const MAX_NAVIGATION_RANGES_PER_CODE_UNIT: usize = 257;

#[derive(Debug, Clone)]
struct DeclarationIdentity(CodeUnit);

impl PartialEq for DeclarationIdentity {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        DECLARATION_IDENTITY_COMPARISON_PROBE.with(|probe| {
            if let Some(comparisons) = probe.get() {
                probe.set(Some(comparisons + 1));
            }
        });
        self.0.source() == other.0.source()
            && self.0.kind() == other.0.kind()
            && self.0.package_name() == other.0.package_name()
            && self.0.short_name() == other.0.short_name()
    }
}

impl Eq for DeclarationIdentity {}

impl Hash for DeclarationIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.source().hash(state);
        self.0.kind().hash(state);
        self.0.package_name().hash(state);
        self.0.short_name().hash(state);
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static DECLARATION_IDENTITY_COMPARISON_PROBE: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(any(test, feature = "test-support"))]
pub fn start_declaration_identity_comparison_probe() {
    DECLARATION_IDENTITY_COMPARISON_PROBE.with(|probe| probe.set(Some(0)));
}

#[cfg(any(test, feature = "test-support"))]
pub fn finish_declaration_identity_comparison_probe() -> usize {
    DECLARATION_IDENTITY_COMPARISON_PROBE.with(|probe| {
        probe
            .replace(None)
            .expect("declaration identity comparison probe should be active")
    })
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CODE_UNIT_REMOVAL_SCAN_PROBE: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

/// Begins counting the `CodeUnit`s that [`ParsedFile::remove_code_unit`] walks
/// past while unlinking a unit.
///
/// This is the work that made a generated type header quadratic (#2358): the
/// count is deterministic for a given source, so a test can pin it directly
/// instead of timing the walk.
#[cfg(any(test, feature = "test-support"))]
pub fn start_code_unit_removal_scan_probe() {
    CODE_UNIT_REMOVAL_SCAN_PROBE.with(|probe| probe.set(Some(0)));
}

#[cfg(any(test, feature = "test-support"))]
pub fn finish_code_unit_removal_scan_probe() -> usize {
    CODE_UNIT_REMOVAL_SCAN_PROBE.with(|probe| {
        probe
            .replace(None)
            .expect("code unit removal scan probe should be active")
    })
}

#[cfg(any(test, feature = "test-support"))]
fn record_removal_scan(scanned: usize) {
    CODE_UNIT_REMOVAL_SCAN_PROBE.with(|probe| {
        if let Some(total) = probe.get() {
            probe.set(Some(total + scanned));
        }
    });
}

#[cfg(not(any(test, feature = "test-support")))]
fn record_removal_scan(_scanned: usize) {}

impl ParsedFile {
    pub fn new(package_name: String) -> Self {
        Self {
            content_qualifier: package_name.clone(),
            package_name,
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            declaration_identities: HashMap::default(),
            definition_lookup_units: HashSet::default(),
            imports: Vec::new(),
            scala_exports: HashMap::default(),
            raw_supertypes: HashMap::default(),
            supertype_lookup_paths: HashMap::default(),
            type_identifiers: HashSet::default(),
            contains_tests: None,
            csharp_semantic_declarations: Vec::new(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
            signature_metadata_signature_ordinals: HashMap::default(),
            cpp_template_metadata: HashMap::default(),
            ruby_method_dispatch_modes: HashMap::default(),
            scala_traits: HashSet::default(),
            type_aliases: HashSet::default(),
            ranges: HashMap::default(),
            navigation_ranges: HashMap::default(),
            navigation_ranges_truncated: HashSet::default(),
            children: HashMap::default(),
            child_owners: HashMap::default(),
            top_level_units: HashSet::default(),
            deferred_replacements: HashMap::default(),
            test_region_units: HashSet::default(),
            rust_usage_facts: RustUsageFacts::default(),
            resolution_facts: FileResolutionFacts::default(),
            source_facts: None,
            source_declaration_units: Vec::new(),
            source_declaration_metadata: Vec::new(),
            materialization_records: Vec::new(),
        }
    }

    /// Records one declaration-materialization provenance fact. Called by the
    /// language walk at the same point it creates (or, for a dynamic site,
    /// declines to create) the declarations the record describes.
    pub fn record_materialization(&mut self, record: MaterializationRecord) {
        self.materialization_records.push(record);
    }

    /// Records that `code_unit` sits in a structurally-evidenced test region.
    /// Idempotent; safe to call after `add_code_unit`.
    pub fn mark_test_region(&mut self, code_unit: &CodeUnit) {
        self.test_region_units.insert(code_unit.clone());
    }

    pub fn add_code_unit(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        _source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.add_code_unit_with_range(code_unit, node_range(node), parent, top_level);
    }

    pub fn add_code_unit_with_range(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        // Every declaration range is 1-based and ordered: that is what
        // `node_range` produces, what the store persists, and what each
        // consumer of a stored range reads (#2428). An adapter that assembles
        // a range from raw tree-sitter rows can silently record a 0-based one
        // -- Scala's recovered `class Foo:` header did (#3303) -- so the
        // convention is checked where the range is recorded rather than where
        // some later reader is one line off.
        debug_assert!(
            range.start_line >= 1
                && range.start_line <= range.end_line
                && range.start_byte <= range.end_byte,
            "declaration range must be 1-based and ordered: {range:?} for {code_unit:?}"
        );
        self.record_navigation_range(code_unit.clone(), range);
        let inserted = self.insert_declaration(code_unit.clone());

        if inserted && parent.is_none() {
            self.top_level_declarations.push(code_unit.clone());
            self.top_level_units.insert(code_unit.clone());
        }

        let ranges = self.ranges.entry(code_unit.clone()).or_default();
        if !ranges.contains(&range) {
            ranges.push(range);
        }

        if let Some(parent) = parent {
            self.link_child(parent, code_unit, true);
        }

        if let Some(top_level) = top_level {
            self.children.entry(top_level).or_default();
        }
    }

    /// Grows the recorded range of `code_unit` that opens nearest before
    /// `range` so it also contains `range`.
    ///
    /// A parse error can truncate a container's node while the declarations
    /// the source nests inside it survive as siblings of that node. An
    /// adapter that re-parents those siblings onto the container (Scala's
    /// recovery owners, `scala/declarations.rs`) must grow the container's
    /// range with them, or the container ends up not containing the members
    /// it claims (#3291).
    pub fn extend_declaration_range(&mut self, code_unit: &CodeUnit, range: Range) {
        let ranges = self
            .ranges
            .get_mut(code_unit)
            .expect("a declaration whose range is extended was recorded with one");
        let opening = ranges
            .iter_mut()
            .filter(|recorded| recorded.start_byte <= range.start_byte)
            .max_by_key(|recorded| recorded.start_byte)
            .expect("a container's recorded range opens before the member it adopts");
        opening.end_byte = opening.end_byte.max(range.end_byte);
        opening.end_line = opening.end_line.max(range.end_line);
    }

    /// Registers a source-backed lookup fact without exposing it through the
    /// public declaration surface.
    pub fn add_definition_lookup_unit(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        _source: &str,
    ) {
        self.definition_lookup_units.insert(code_unit.clone());
        self.ranges
            .entry(code_unit)
            .or_default()
            .push(node_range(node));
    }

    /// Registers a declaration-like code unit for analysis without giving it a source range.
    ///
    /// This is for synthetic owners that should participate in import or usage resolution but
    /// should not render as user-visible declarations in summary output.
    pub fn add_synthetic_code_unit(
        &mut self,
        code_unit: CodeUnit,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        let inserted = self.insert_declaration(code_unit.clone());

        if inserted && parent.is_none() {
            self.top_level_declarations.push(code_unit.clone());
            self.top_level_units.insert(code_unit.clone());
        }

        if let Some(parent) = parent {
            self.link_child(parent, code_unit, true);
        }

        if let Some(top_level) = top_level {
            self.children.entry(top_level).or_default();
        }
    }

    pub fn add_file_scope(&mut self, file: &ProjectFile, source: &str) {
        let code_unit = CodeUnit::file_scope(file.clone());
        if !self.insert_declaration(code_unit.clone()) {
            return;
        }

        self.top_level_declarations.push(code_unit.clone());
        self.top_level_units.insert(code_unit.clone());
        let line_starts = compute_line_starts(source);
        let end_line = line_starts.len().saturating_sub(1);
        self.ranges.entry(code_unit).or_default().push(Range {
            start_byte: 0,
            end_byte: source.len(),
            start_line: 0,
            end_line,
        });
    }

    pub fn replace_code_unit(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.remove_code_unit(&code_unit);
        self.add_code_unit(code_unit, node, source, parent, top_level);
    }

    pub fn replace_code_unit_with_range(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.remove_code_unit(&code_unit);
        self.add_code_unit_with_range(code_unit, range, parent, top_level);
    }

    /// Replaces a declaration while deferring physical ordering cleanup.
    ///
    /// Call [`Self::finalize_deferred_replacements`] after the language walk.
    /// This variant is for parsers such as C++ that first record many forward
    /// declarations and later replace them with definitions. Keeping the old
    /// ordering entries temporarily and compacting every affected vec once
    /// avoids a full sibling/top-level scan for every definition (#2358).
    pub fn replace_code_unit_deferred(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        _source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        let range = node_range(node);
        self.replace_code_unit_with_range_deferred(code_unit, range, parent, top_level);
    }

    /// Range-based form of [`Self::replace_code_unit_deferred`].
    pub fn replace_code_unit_with_range_deferred(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        if !self.prepare_deferred_replacement(&code_unit) {
            self.add_code_unit_with_range(code_unit, range, parent, top_level);
            return;
        }

        self.record_navigation_range(code_unit.clone(), range);
        if parent.is_none() {
            self.top_level_declarations.push(code_unit.clone());
            self.top_level_units.insert(code_unit.clone());
        }
        self.ranges.insert(code_unit.clone(), vec![range]);
        if let Some(parent) = parent {
            // The old physical edge is deliberately still present, so this
            // must append the replacement occurrence even when it is equal.
            self.link_child(parent, code_unit.clone(), false);
        }
        if let Some(top_level) = top_level {
            self.children.entry(top_level).or_default();
        }
    }

    /// Compacts all ordering vectors touched by deferred replacements.
    ///
    /// For each replaced unit the last newly appended occurrence wins, which
    /// is exactly the ordering produced by eager remove-and-reappend. Unrelated
    /// duplicate child edges retain their original multiplicity.
    pub fn finalize_deferred_replacements(&mut self) {
        if self.deferred_replacements.is_empty() {
            return;
        }

        let replacements: HashSet<CodeUnit> = self.deferred_replacements.keys().cloned().collect();
        compact_replacement_occurrences(
            &mut self.top_level_declarations,
            &replacements,
            &self.top_level_units,
        );

        let mut affected_owners = HashSet::default();
        for replacement in self.deferred_replacements.values() {
            affected_owners.extend(replacement.affected_owners.iter().cloned());
        }

        let mut desired_by_owner: HashMap<CodeUnit, HashSet<CodeUnit>> = HashMap::default();
        for unit in &replacements {
            if let Some(owners) = self.child_owners.get(unit) {
                for owner in owners {
                    affected_owners.insert(owner.clone());
                    desired_by_owner
                        .entry(owner.clone())
                        .or_default()
                        .insert(unit.clone());
                }
            }
        }

        for owner in affected_owners {
            if let Some(children) = self.children.get_mut(&owner) {
                let desired = desired_by_owner.get(&owner).cloned().unwrap_or_default();
                compact_replacement_occurrences(children, &replacements, &desired);
            }
        }
        self.deferred_replacements.clear();
    }

    pub fn record_navigation_range(&mut self, code_unit: CodeUnit, range: Range) {
        let ranges = self.navigation_ranges.entry(code_unit.clone()).or_default();
        if ranges.contains(&range) {
            return;
        }
        if ranges.len() < MAX_NAVIGATION_RANGES_PER_CODE_UNIT {
            ranges.push(range);
        } else {
            self.navigation_ranges_truncated.insert(code_unit);
        }
    }

    pub fn declarations(&self) -> &HashSet<CodeUnit> {
        &self.declarations
    }

    /// Moves the declaration set out for the storage pipeline. The set stays
    /// private otherwise, because `declaration_identities` counts it and an
    /// externally inserted declaration would desync that count.
    pub fn take_declarations(&mut self) -> HashSet<CodeUnit> {
        std::mem::take(&mut self.declarations)
    }

    pub fn declaration_ranges(&self, code_unit: &CodeUnit) -> &[Range] {
        self.ranges
            .get(code_unit)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Adds one more declaration range to a declaration that already holds at
    /// least one.
    ///
    /// One declaration can have several declaration sites: a C++ forward
    /// declaration and the definition that completes it, or a prototype and
    /// its body in one translation unit (#1650). A language walk that replaces
    /// the earlier site with the later one restores it here, so resolution
    /// still sees the name from the earlier site.
    pub fn add_declaration_range(&mut self, code_unit: &CodeUnit, range: Range) {
        let ranges = self
            .ranges
            .get_mut(code_unit)
            .expect("a declaration range was added to a unit with no declaration range");
        if ranges.contains(&range) {
            return;
        }
        ranges.push(range);
        ranges.sort_by_key(|range| range.start_byte);
    }

    pub fn contains_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.declarations.contains(code_unit)
    }

    pub fn contains_declaration_identity(&self, code_unit: &CodeUnit) -> bool {
        self.declaration_identities
            .contains_key(&DeclarationIdentity(code_unit.clone()))
    }

    pub fn set_raw_supertypes(&mut self, code_unit: CodeUnit, raw_supertypes: Vec<String>) {
        self.raw_supertypes.insert(code_unit, raw_supertypes);
    }

    pub fn set_supertype_lookup_paths(&mut self, code_unit: CodeUnit, lookup_paths: Vec<String>) {
        self.supertype_lookup_paths.insert(code_unit, lookup_paths);
    }

    pub fn add_raw_supertypes(&mut self, code_unit: CodeUnit, raw_supertypes: Vec<String>) {
        let entries = self.raw_supertypes.entry(code_unit).or_default();
        for raw_supertype in raw_supertypes {
            if !entries.contains(&raw_supertype) {
                entries.push(raw_supertype);
            }
        }
    }

    pub fn add_signature(&mut self, code_unit: CodeUnit, signature: String) -> usize {
        let entries = self.signatures.entry(code_unit).or_default();
        if let Some(ordinal) = entries.iter().position(|entry| entry == &signature) {
            ordinal
        } else {
            let ordinal = entries.len();
            entries.push(signature);
            ordinal
        }
    }

    /// Insert or reuse a complete metadata row and return its per-unit ordinal.
    /// Display labels deduplicate separately, so their ordinals are not metadata
    /// identities.
    pub fn add_signature_with_metadata(
        &mut self,
        code_unit: CodeUnit,
        metadata: SignatureMetadata,
    ) -> usize {
        let signature_ordinal = self.add_signature(code_unit.clone(), metadata.label().to_string());
        self.add_metadata_for_signature(code_unit, signature_ordinal, metadata)
    }

    /// Attach metadata to an already admitted display signature. Some metadata
    /// describes a component, such as a Go embedded type, without introducing
    /// another display signature for the enclosing declaration. Reuse a row
    /// only within the same signature; identical component metadata may belong
    /// to distinct declaration alternatives.
    pub fn add_metadata_for_signature(
        &mut self,
        code_unit: CodeUnit,
        signature_ordinal: usize,
        metadata: SignatureMetadata,
    ) -> usize {
        assert!(
            self.signatures
                .get(&code_unit)
                .is_some_and(|signatures| signature_ordinal < signatures.len()),
            "metadata must reference an admitted signature for {code_unit:?}"
        );
        let entries = self
            .signature_metadata
            .entry(code_unit.clone())
            .or_default();
        let signature_ordinals = self
            .signature_metadata_signature_ordinals
            .entry(code_unit)
            .or_default();
        assert_eq!(
            signature_ordinals.len(),
            entries.len(),
            "metadata signature ordinals stay dense with metadata rows"
        );
        if let Some(ordinal) = entries
            .iter()
            .zip(signature_ordinals.iter())
            .position(|(entry, &recorded)| entry == &metadata && recorded == signature_ordinal)
        {
            ordinal
        } else {
            let ordinal = entries.len();
            entries.push(metadata);
            signature_ordinals.push(signature_ordinal);
            ordinal
        }
    }

    pub fn set_ruby_method_dispatch_mode(
        &mut self,
        code_unit: CodeUnit,
        mode: RubyMethodDispatchMode,
    ) {
        self.ruby_method_dispatch_modes.insert(code_unit, mode);
    }

    pub fn set_cpp_template_metadata(
        &mut self,
        code_unit: CodeUnit,
        metadata: CppTemplateMetadata,
    ) {
        self.cpp_template_metadata.insert(code_unit, metadata);
    }

    pub fn set_scala_trait(&mut self, code_unit: CodeUnit) {
        self.scala_traits.insert(code_unit);
    }

    pub fn add_child(&mut self, parent: CodeUnit, child: CodeUnit) {
        self.link_child(parent, child, false);
    }

    /// Records `parent -> child` and the inverse edge that lets
    /// [`Self::remove_code_unit`] find this list again.
    ///
    /// `deduplicate` reflects the two callers' existing contracts: the
    /// `add_code_unit` family refuses to name the same child twice under one
    /// parent, while `add_child` appends unconditionally. The inverse edge is
    /// always deduplicated -- it answers "which lists name this unit?", and one
    /// answer per owner is enough to unlink every copy.
    fn link_child(&mut self, parent: CodeUnit, child: CodeUnit, deduplicate: bool) {
        let children = self.children.entry(parent.clone()).or_default();
        if deduplicate && children.contains(&child) {
            return;
        }
        children.push(child.clone());
        let owners = self.child_owners.entry(child).or_default();
        if !owners.contains(&parent) {
            owners.push(parent);
        }
    }

    pub fn mark_type_alias(&mut self, code_unit: CodeUnit) {
        self.type_aliases.insert(code_unit);
    }

    pub fn first_range_start(&self, code_unit: &CodeUnit) -> Option<usize> {
        self.ranges
            .get(code_unit)
            .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min())
    }

    /// Drops `code_unit` and everything it owns from every collection here.
    ///
    /// Iterative rather than recursive: the pending set is an explicit stack,
    /// so a deeply nested declaration chain cannot overflow the Rust stack.
    fn remove_code_unit(&mut self, code_unit: &CodeUnit) {
        let removed = self.remove_code_units(std::iter::once(code_unit.clone()));
        self.source_declaration_metadata
            .retain(|link| !removed.contains(&link.unit));
    }

    /// Drops a set of units and everything they own from every collection here,
    /// returning the units actually walked. The caller removes any
    /// placement-dependent links in one pass after the whole batch, rather than
    /// rescanning those links once per descendant.
    fn remove_code_units<I>(&mut self, roots: I) -> HashSet<CodeUnit>
    where
        I: IntoIterator<Item = CodeUnit>,
    {
        let mut pending: Vec<CodeUnit> = roots.into_iter().collect();
        let mut removed = HashSet::default();
        while let Some(unit) = pending.pop() {
            if !removed.insert(unit.clone()) {
                continue;
            }
            if let Some(children) = self.children.remove(&unit) {
                pending.extend(children);
            }

            // Only the owners that actually name this unit are touched. The
            // alternative -- scanning every child list in the file -- is what
            // made a generated type header quadratic (#2358).
            if let Some(owners) = self.child_owners.remove(&unit) {
                for owner in owners {
                    if let Some(siblings) = self.children.get_mut(&owner) {
                        record_removal_scan(siblings.len());
                        siblings.retain(|child| child != &unit);
                    }
                }
            }

            self.remove_declaration(&unit);
            if self.top_level_units.remove(&unit) {
                record_removal_scan(self.top_level_declarations.len());
                self.top_level_declarations
                    .retain(|existing| existing != &unit);
            }
            self.definition_lookup_units.remove(&unit);
            self.raw_supertypes.remove(&unit);
            self.supertype_lookup_paths.remove(&unit);
            self.signatures.remove(&unit);
            self.signature_metadata.remove(&unit);
            self.signature_metadata_signature_ordinals.remove(&unit);
            self.cpp_template_metadata.remove(&unit);
            self.ruby_method_dispatch_modes.remove(&unit);
            self.scala_traits.remove(&unit);
            self.type_aliases.remove(&unit);
            self.ranges.remove(&unit);
        }
        removed
    }

    /// Clears replaceable facts while leaving incoming ordering entries until
    /// the batch finalizer can compact their vectors once.
    fn prepare_deferred_replacement(&mut self, code_unit: &CodeUnit) -> bool {
        if !self.declarations.contains(code_unit) {
            return false;
        }

        let mut affected_owners = self.child_owners.remove(code_unit).unwrap_or_default();
        self.deferred_replacements
            .entry(code_unit.clone())
            .or_default()
            .affected_owners
            .extend(affected_owners.drain(..));
        self.top_level_units.remove(code_unit);

        let children = self.children.remove(code_unit).unwrap_or_default();
        let mut removed = self.remove_code_units(children);
        removed.insert(code_unit.clone());
        self.source_declaration_metadata
            .retain(|link| !removed.contains(&link.unit));
        self.definition_lookup_units.remove(code_unit);
        self.raw_supertypes.remove(code_unit);
        self.supertype_lookup_paths.remove(code_unit);
        self.signatures.remove(code_unit);
        self.signature_metadata.remove(code_unit);
        self.signature_metadata_signature_ordinals.remove(code_unit);
        self.cpp_template_metadata.remove(code_unit);
        self.ruby_method_dispatch_modes.remove(code_unit);
        self.scala_traits.remove(code_unit);
        self.type_aliases.remove(code_unit);
        self.ranges.remove(code_unit);
        true
    }

    fn insert_declaration(&mut self, code_unit: CodeUnit) -> bool {
        if !self.declarations.insert(code_unit.clone()) {
            return false;
        }
        *self
            .declaration_identities
            .entry(DeclarationIdentity(code_unit))
            .or_default() += 1;
        true
    }

    fn remove_declaration(&mut self, code_unit: &CodeUnit) -> bool {
        if !self.declarations.remove(code_unit) {
            return false;
        }
        let identity = DeclarationIdentity(code_unit.clone());
        let remove_identity = {
            let count = self
                .declaration_identities
                .get_mut(&identity)
                .expect("inserted declaration must have a semantic identity count");
            *count = count
                .checked_sub(1)
                .expect("declaration semantic identity count must be positive");
            *count == 0
        };
        if remove_identity {
            self.declaration_identities.remove(&identity);
        }
        true
    }
}

fn compact_replacement_occurrences(
    units: &mut Vec<CodeUnit>,
    replacements: &HashSet<CodeUnit>,
    desired: &HashSet<CodeUnit>,
) {
    let mut seen = HashSet::default();
    let mut compacted = Vec::with_capacity(units.len());
    while let Some(unit) = units.pop() {
        if !replacements.contains(&unit) || desired.contains(&unit) && seen.insert(unit.clone()) {
            compacted.push(unit);
        }
    }
    compacted.reverse();
    *units = compacted;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::model::CodeUnitType;

    fn test_range(start_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte: start_byte + 1,
            start_line: 1,
            end_line: 1,
        }
    }

    #[test]
    fn declaration_identity_multiset_survives_replace_until_last_exact_removal() {
        let file = ProjectFile::new(std::env::temp_dir(), "identity.cpp");
        let first = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "pkg",
            "overloaded",
            Some("(int)".to_string()),
            false,
        );
        let synthetic_variant = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "pkg",
            "overloaded",
            Some("(double)".to_string()),
            true,
        );
        let identity_probe =
            CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg", "overloaded");
        let mut parsed = ParsedFile::new(String::new());
        parsed.add_code_unit_with_range(first.clone(), test_range(0), None, None);
        parsed.add_synthetic_code_unit(synthetic_variant.clone(), None, None);
        assert!(parsed.contains_declaration_identity(&identity_probe));
        assert_eq!(
            Some(&2),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(identity_probe.clone()))
        );

        parsed.replace_code_unit_with_range(first.clone(), test_range(3), None, None);
        assert_eq!(
            Some(&2),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(identity_probe.clone()))
        );

        parsed.remove_code_unit(&first);
        assert!(parsed.contains_declaration_identity(&identity_probe));
        assert_eq!(
            Some(&1),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(identity_probe.clone()))
        );
        parsed.remove_code_unit(&synthetic_variant);
        assert!(!parsed.contains_declaration_identity(&identity_probe));
    }

    #[test]
    fn declaration_identity_index_tracks_file_scope_and_recursive_removal() {
        let file = ProjectFile::new(std::env::temp_dir(), "recursive.cpp");
        let mut parsed = ParsedFile::new(String::new());
        let file_scope = CodeUnit::file_scope(file.clone());
        parsed.add_file_scope(&file, "int value;\n");
        parsed.add_file_scope(&file, "int value;\n");
        assert_eq!(
            Some(&1),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(file_scope.clone()))
        );
        parsed.remove_code_unit(&file_scope);
        assert!(!parsed.contains_declaration_identity(&file_scope));

        let parent = CodeUnit::new(file.clone(), CodeUnitType::Class, "", "Parent");
        let child_one = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "Parent",
            "child",
            Some("(int)".to_string()),
            false,
        );
        let child_two = CodeUnit::with_signature(
            file,
            CodeUnitType::Function,
            "Parent",
            "child",
            Some("(double)".to_string()),
            true,
        );
        let child_identity = CodeUnit::new(
            child_one.source().clone(),
            CodeUnitType::Function,
            "Parent",
            "child",
        );
        parsed.add_code_unit_with_range(parent.clone(), test_range(1), None, None);
        parsed.add_code_unit_with_range(child_one, test_range(2), Some(parent.clone()), None);
        parsed.add_synthetic_code_unit(child_two, Some(parent.clone()), None);
        assert_eq!(
            Some(&2),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(child_identity.clone()))
        );

        parsed.remove_code_unit(&parent);
        assert!(!parsed.contains_declaration_identity(&parent));
        assert!(!parsed.contains_declaration_identity(&child_identity));
    }

    #[test]
    fn deferred_replacements_batch_ordering_cleanup_and_keep_last_occurrence() {
        let file = ProjectFile::new(std::env::temp_dir(), "deferred.cpp");
        let owner = CodeUnit::new(file.clone(), CodeUnitType::Module, "", "generated");
        let unit = |name: &str| CodeUnit::new(file.clone(), CodeUnitType::Class, "generated", name);
        let a = unit("A");
        let b = unit("B");
        let c = unit("C");
        let unrelated = unit("Unrelated");
        let stale_child = CodeUnit::new(file, CodeUnitType::Function, "generated.B", "stale");
        let mut parsed = ParsedFile::new(String::new());
        for (index, declaration) in [&a, &b, &c].into_iter().enumerate() {
            parsed.add_code_unit_with_range(declaration.clone(), test_range(index), None, None);
            parsed.add_child(owner.clone(), declaration.clone());
        }
        parsed.add_child(owner.clone(), unrelated.clone());
        parsed.add_child(owner.clone(), unrelated.clone());
        parsed.add_code_unit_with_range(stale_child.clone(), test_range(4), Some(b.clone()), None);

        start_code_unit_removal_scan_probe();
        parsed.replace_code_unit_with_range_deferred(b.clone(), test_range(10), None, None);
        parsed.add_child(owner.clone(), b.clone());
        parsed.replace_code_unit_with_range_deferred(a.clone(), test_range(11), None, None);
        parsed.add_child(owner.clone(), a.clone());
        parsed.finalize_deferred_replacements();
        assert_eq!(0, finish_code_unit_removal_scan_probe());

        assert_eq!(
            vec![c.clone(), b.clone(), a.clone()],
            parsed.top_level_declarations
        );
        assert_eq!(
            &vec![c, unrelated.clone(), unrelated, b.clone(), a.clone(),],
            parsed.children.get(&owner).unwrap()
        );
        assert_eq!(&[test_range(10)], parsed.declaration_ranges(&b));
        assert_eq!(&[test_range(11)], parsed.declaration_ranges(&a));
        assert!(!parsed.contains_declaration(&stale_child));

        let top_level = parsed.top_level_declarations.clone();
        let children = parsed.children.clone();
        parsed.finalize_deferred_replacements();
        assert_eq!(top_level, parsed.top_level_declarations);
        assert_eq!(children, parsed.children);
    }

    #[test]
    fn metadata_ordinals_deduplicate_full_rows_independently_of_labels() {
        let file = ProjectFile::new(std::env::temp_dir(), "metadata-ordinals.java");
        let unit = CodeUnit::new(file, CodeUnitType::Function, "pkg.Type", "run");
        let first = SignatureMetadata::new("run", Vec::new());
        let same_label_different_metadata = first.clone().with_callable_modifiers(
            false,
            false,
            crate::analyzer::structural::resolution::DeclaredVisibility::Public,
        );
        let different_label = SignatureMetadata::new("other", Vec::new());
        let mut parsed = ParsedFile::new(String::new());

        let first_ordinal = parsed.add_signature_with_metadata(unit.clone(), first.clone());
        let second_ordinal =
            parsed.add_signature_with_metadata(unit.clone(), same_label_different_metadata);
        let repeated_ordinal = parsed.add_signature_with_metadata(unit.clone(), first);
        let different_label_ordinal =
            parsed.add_signature_with_metadata(unit.clone(), different_label);

        assert_eq!((first_ordinal, second_ordinal, repeated_ordinal), (0, 1, 0));
        assert_eq!(different_label_ordinal, 2);
        assert_eq!(
            parsed.signatures.get(&unit).unwrap(),
            &vec!["run".to_string(), "other".to_string()]
        );
        assert_eq!(parsed.signature_metadata.get(&unit).unwrap().len(), 3);
        assert_eq!(
            parsed.signature_metadata_signature_ordinals.get(&unit),
            Some(&vec![0, 0, 1])
        );

        parsed.source_declaration_metadata.extend([
            SourceDeclarationMetadataLink {
                declaration: SourceDeclarationId::new(0),
                unit: unit.clone(),
                metadata_ordinal: first_ordinal,
            },
            SourceDeclarationMetadataLink {
                declaration: SourceDeclarationId::new(1),
                unit,
                metadata_ordinal: repeated_ordinal,
            },
        ]);
        assert_eq!(
            parsed
                .source_declaration_metadata
                .iter()
                .map(|link| (link.declaration, link.metadata_ordinal))
                .collect::<Vec<_>>(),
            vec![
                (SourceDeclarationId::new(0), 0),
                (SourceDeclarationId::new(1), 0),
            ]
        );
    }

    #[test]
    fn metadata_signature_ordinals_capture_plain_and_synthetic_rows() {
        let file = ProjectFile::new(std::env::temp_dir(), "metadata-signature-ordinals.java");
        let ordinary = CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg.Type", "run");
        let synthetic = CodeUnit::with_signature(
            file,
            CodeUnitType::Function,
            "pkg.Type",
            "generated",
            None,
            true,
        );
        let mut parsed = ParsedFile::new(String::new());

        assert_eq!(
            parsed.add_signature(ordinary.clone(), "plain only".to_string()),
            0
        );
        assert_eq!(
            parsed.add_signature(ordinary.clone(), "preexisting".to_string()),
            1
        );
        assert_eq!(
            parsed.add_signature_with_metadata(
                ordinary.clone(),
                SignatureMetadata::new("preexisting", Vec::new()),
            ),
            0
        );
        assert_eq!(
            parsed.add_signature_with_metadata(
                ordinary.clone(),
                SignatureMetadata::new("new", Vec::new()),
            ),
            1
        );
        assert_eq!(
            parsed.signature_metadata_signature_ordinals.get(&ordinary),
            Some(&vec![1, 2])
        );
        let component = SignatureMetadata::new("component", Vec::new());
        assert_eq!(
            parsed.add_metadata_for_signature(ordinary.clone(), 1, component.clone()),
            2
        );
        assert_eq!(
            parsed.add_metadata_for_signature(ordinary.clone(), 2, component.clone()),
            3
        );
        assert_eq!(
            parsed.add_metadata_for_signature(ordinary.clone(), 1, component),
            2
        );
        assert_eq!(parsed.signatures[&ordinary].len(), 3);
        assert_eq!(
            parsed.signature_metadata_signature_ordinals[&ordinary],
            vec![1, 2, 1, 2]
        );

        assert_eq!(
            parsed.add_signature_with_metadata(
                synthetic.clone(),
                SignatureMetadata::new("generated", Vec::new()),
            ),
            0
        );
        assert_eq!(
            parsed.signature_metadata_signature_ordinals.get(&synthetic),
            Some(&vec![0])
        );
        assert!(parsed.source_declaration_metadata.is_empty());
    }

    #[test]
    fn removing_or_replacing_a_unit_cleans_its_source_metadata_links() {
        let file = ProjectFile::new(std::env::temp_dir(), "metadata-links.java");
        let removed = CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg", "removed");
        let retained = CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg", "retained");
        let deferred = CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg", "deferred");
        let child = CodeUnit::new(file, CodeUnitType::Function, "pkg", "child");
        let link =
            |declaration: u32, unit: CodeUnit, metadata_ordinal| SourceDeclarationMetadataLink {
                declaration: SourceDeclarationId::new(declaration),
                unit,
                metadata_ordinal,
            };
        let mut parsed = ParsedFile::new(String::new());
        parsed.add_code_unit_with_range(removed.clone(), test_range(0), None, None);
        parsed.add_code_unit_with_range(retained.clone(), test_range(1), None, None);
        parsed.add_code_unit_with_range(deferred.clone(), test_range(2), None, None);
        parsed.add_code_unit_with_range(child.clone(), test_range(3), Some(removed.clone()), None);
        for unit in [&removed, &retained, &deferred, &child] {
            assert_eq!(
                parsed.add_signature_with_metadata(
                    unit.clone(),
                    SignatureMetadata::new(unit.identifier(), Vec::new()),
                ),
                0
            );
        }
        parsed.source_declaration_metadata.extend([
            link(0, removed.clone(), 0),
            link(1, retained.clone(), 0),
            link(2, deferred.clone(), 0),
            link(3, child.clone(), 0),
        ]);

        parsed.replace_code_unit_with_range(removed.clone(), test_range(3), None, None);
        assert_eq!(
            parsed
                .source_declaration_metadata
                .iter()
                .map(|link| link.unit.clone())
                .collect::<Vec<_>>(),
            vec![retained.clone(), deferred.clone()]
        );
        assert!(!parsed.signature_metadata.contains_key(&child));
        assert!(
            !parsed
                .signature_metadata_signature_ordinals
                .contains_key(&child)
        );
        assert!(
            !parsed
                .signature_metadata_signature_ordinals
                .contains_key(&removed)
        );

        parsed.replace_code_unit_with_range_deferred(deferred.clone(), test_range(4), None, None);
        assert_eq!(
            parsed
                .source_declaration_metadata
                .iter()
                .map(|link| link.unit.clone())
                .collect::<Vec<_>>(),
            vec![retained]
        );
        assert!(
            !parsed
                .signature_metadata_signature_ordinals
                .contains_key(&deferred)
        );
    }
}
