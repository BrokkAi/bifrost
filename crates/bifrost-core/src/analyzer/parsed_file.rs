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
    ScalaExportInfo, SignatureMetadata,
};
use crate::analyzer::rust_facts::RustUsageFacts;
use crate::analyzer::structural::materialization::MaterializationRecord;
use crate::analyzer::tree_walk::node_range;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;

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
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    pub signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
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
    /// Declaration-materialization provenance recorded by the language walk
    /// that created the declarations it describes (issue #1476): generation
    /// sites and their generated units, dynamic generation sites, export
    /// declarations, recovered declarations, and preprocessor-conditional
    /// intervals. Persisted with the file's other analysis facts.
    pub materialization_records: Vec<MaterializationRecord>,
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
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
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

    pub fn add_signature(&mut self, code_unit: CodeUnit, signature: String) {
        let entries = self.signatures.entry(code_unit).or_default();
        if !entries.contains(&signature) {
            entries.push(signature);
        }
    }

    pub fn add_signature_with_metadata(
        &mut self,
        code_unit: CodeUnit,
        metadata: SignatureMetadata,
    ) {
        self.add_signature(code_unit.clone(), metadata.label().to_string());
        let entries = self.signature_metadata.entry(code_unit).or_default();
        if !entries.contains(&metadata) {
            entries.push(metadata);
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

    pub fn set_primary_range(&mut self, code_unit: &CodeUnit, range: Range) {
        self.ranges.insert(code_unit.clone(), vec![range]);
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
        let mut pending = vec![code_unit.clone()];
        while let Some(unit) = pending.pop() {
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
            self.cpp_template_metadata.remove(&unit);
            self.ruby_method_dispatch_modes.remove(&unit);
            self.scala_traits.remove(&unit);
            self.type_aliases.remove(&unit);
            self.ranges.remove(&unit);
        }
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

        if let Some(children) = self.children.remove(code_unit) {
            for child in children {
                self.remove_code_unit(&child);
            }
        }
        self.definition_lookup_units.remove(code_unit);
        self.raw_supertypes.remove(code_unit);
        self.supertype_lookup_paths.remove(code_unit);
        self.signatures.remove(code_unit);
        self.signature_metadata.remove(code_unit);
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
            start_line: 0,
            end_line: 0,
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
}
