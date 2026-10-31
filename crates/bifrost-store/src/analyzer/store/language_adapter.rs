use super::*;

fn package_storage_content_qualifier(package_name: &str) -> String {
    package_name.to_owned()
}

/// Language-specific storage behavior shared by the analyzer store and resolution.
///
/// Connection-taking hydration hooks run inside the caller's read transaction.
/// Implementations that read store-backed inputs must use that connection rather
/// than checking out another reader, including through their bound project.
pub trait StoreLanguageAdapter: Send + Sync + 'static {
    fn language(&self) -> Language;
    fn claims_included_files(&self) -> bool {
        false
    }
    fn parse_time_semantic_lowerer(
        &self,
    ) -> Option<crate::analyzer::semantic::service::ParseTimeSemanticLowerer> {
        None
    }
    fn storage_language_key_for_file(&self, file: &ProjectFile) -> &'static str {
        if self.claims_included_files() && file.has_unclaimed_extension() {
            return self.language().config_label();
        }
        crate::analyzer::common::language_for_file(file).config_label()
    }
    fn normalize_full_name(&self, fq_name: &str) -> String {
        fq_name.to_string()
    }
    fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
        fq_name.clone()
    }
    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        unit.identifier().to_string()
    }
    fn persist_content_stable_lookup_keys(&self) -> bool {
        false
    }
    fn storage_content_qualifier(&self, code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        package_storage_content_qualifier(code_unit.package_name())
    }
    fn storage_file_content_qualifier(&self, package_name: &str) -> String {
        package_storage_content_qualifier(package_name)
    }
    fn hydrate_content_qualifier(
        &self,
        content_qualifier: &str,
        _file: &ProjectFile,
    ) -> Result<String> {
        Ok(content_qualifier.to_string())
    }
    /// Store hydration hooks must reuse the open read for store-backed inputs.
    fn hydrate_content_qualifier_with_conn(
        &self,
        _conn: &Connection,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> Result<String> {
        self.hydrate_content_qualifier(content_qualifier, file)
    }
    fn default_package_anchor(&self) -> Option<PackageAnchor> {
        None
    }
    fn resolve_package_anchor(
        &self,
        _anchor: PackageAnchor,
        _content_qualifier: &str,
        _file: &ProjectFile,
    ) -> Option<FqName> {
        None
    }
    /// Hydration may reuse a published placement. Publication must instead call
    /// resolve_package_anchor so a configuration edit recomputes the placement.
    fn hydrate_package_anchor(
        &self,
        anchor: PackageAnchor,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> Result<Option<FqName>> {
        Ok(self.resolve_package_anchor(anchor, content_qualifier, file))
    }
    fn hydrate_package_anchor_with_conn(
        &self,
        _conn: &Connection,
        anchor: PackageAnchor,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> Result<Option<FqName>> {
        self.hydrate_package_anchor(anchor, content_qualifier, file)
    }
    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope()
    }
    fn storage_contains_tests(&self, state: &FileState) -> bool {
        state.contains_tests
    }
    fn hydrate_contains_tests(&self, stored: bool, _file: &ProjectFile, _source: &str) -> bool {
        stored
    }
    fn synthesize_hydrated_units(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _state: &mut FileState,
    ) -> Result<()> {
        Ok(())
    }
    fn synthesize_hydrated_units_with_conn(
        &self,
        _conn: &Connection,
        file: &ProjectFile,
        source: &str,
        state: &mut FileState,
    ) -> Result<()> {
        self.synthesize_hydrated_units(file, source, state)
    }
    fn synthesize_summary_projection(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _has_structured_imports: bool,
        _projection: &mut SummaryFileProjection,
    ) {
    }
    fn path_synthetic_module_unit(&self, _file: &ProjectFile) -> Option<CodeUnit> {
        None
    }
    /// Construct a predicate candidate from the selected path projection,
    /// without reading declaration content or looking up the published name.
    fn path_synthetic_module_from_published_name(
        &self,
        file: &ProjectFile,
        _name: &str,
    ) -> Result<Option<CodeUnit>> {
        Ok(self.path_synthetic_module_unit(file))
    }
    /// Query-side module hydration can reuse the selected path publication.
    fn hydrate_path_synthetic_module_unit(&self, file: &ProjectFile) -> Result<Option<CodeUnit>> {
        Ok(self.path_synthetic_module_unit(file))
    }
    fn hydrate_path_synthetic_module_unit_with_conn(
        &self,
        _conn: &Connection,
        file: &ProjectFile,
    ) -> Result<Option<CodeUnit>> {
        self.hydrate_path_synthetic_module_unit(file)
    }
    fn has_path_synthetic_module_units(&self) -> bool {
        false
    }
    fn produces_canonical_source_facts(&self) -> bool {
        false
    }
    fn side_fact_families(&self) -> crate::analyzer::store::SideFactFamilies {
        crate::analyzer::store::SideFactFamilies::EVERY
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        false
    }
    fn declaration_visibility_facts_version(&self) -> Option<i64> {
        None
    }
    fn java_type_constructor_facts_version(&self) -> Option<i64> {
        None
    }
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        None
    }
    fn cpp_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn php_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn go_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn ruby_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn python_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn java_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn scala_source_facts_version(&self) -> Option<i64> {
        None
    }
    fn js_ts_source_facts_version(&self) -> Option<i64> {
        None
    }
}
