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
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub package_name: String,
    pub content_qualifier: String,
    pub top_level_declarations: Vec<CodeUnit>,
    declarations: HashSet<CodeUnit>,
    declaration_identities: HashMap<DeclarationIdentity, usize>,
    pub definition_lookup_units: HashSet<CodeUnit>,
    pub import_statements: Vec<String>,
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
    /// Declarations that lie in a structurally-evidenced test region: a
    /// test-attributed item or any declaration nested inside a `#[cfg(test)]`
    /// (or otherwise test-attributed) module/item. Populated by language walks
    /// that thread test-region taint through their traversal (currently Rust);
    /// other languages leave it empty, so their declarations default untainted.
    pub test_region_units: HashSet<CodeUnit>,
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

impl ParsedFile {
    pub fn new(package_name: String) -> Self {
        Self {
            content_qualifier: package_name.clone(),
            package_name,
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            declaration_identities: HashMap::default(),
            definition_lookup_units: HashSet::default(),
            import_statements: Vec::new(),
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
            test_region_units: HashSet::default(),
        }
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
        }

        let ranges = self.ranges.entry(code_unit.clone()).or_default();
        if !ranges.contains(&range) {
            ranges.push(range);
        }

        if let Some(parent) = parent {
            let children = self.children.entry(parent).or_default();
            if !children.contains(&code_unit) {
                children.push(code_unit.clone());
            }
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
        }

        if let Some(parent) = parent {
            let children = self.children.entry(parent).or_default();
            if !children.contains(&code_unit) {
                children.push(code_unit.clone());
            }
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
        self.children.entry(parent).or_default().push(child);
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

    fn remove_code_unit(&mut self, code_unit: &CodeUnit) {
        if let Some(children) = self.children.remove(code_unit) {
            for child in children {
                self.remove_code_unit(&child);
            }
        }

        for siblings in self.children.values_mut() {
            siblings.retain(|child| child != code_unit);
        }

        self.top_level_declarations
            .retain(|existing| existing != code_unit);
        self.remove_declaration(code_unit);
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
}
