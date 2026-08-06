//! The `LanguageAdapter` forwarding shell for Python.
//!
//! Every answer below comes from [`brokk_bifrost_python`] except
//! `synthesize_hydrated_units`, which mutates `FileState` -- an analysis type
//! with `pub(crate)` fields that cannot leave this crate.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile, Range};
use crate::text_utils::compute_line_starts;
use brokk_bifrost_python::adapter::{
    PYTHON_COGNITIVE_CONFIG, PYTHON_FILE_EXTENSION, python_extract_call_receiver,
};
use brokk_bifrost_python::declarations::{
    module_code_unit, parse_python_file, python_module_fq, python_module_name,
};
use brokk_bifrost_python::queries::PYTHON_QUERY_DIRECTORY;
use brokk_bifrost_python::test_detection::python_source_contains_tests;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    /// Relative to `brokk-bifrost-python`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        PYTHON_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        PYTHON_FILE_EXTENSION
    }

    fn storage_content_qualifier(&self, _code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        String::new()
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(&self, _content_qualifier: &str, file: &ProjectFile) -> String {
        python_module_name(file)
    }

    fn default_package_anchor(&self) -> Option<crate::analyzer::PackageAnchor> {
        Some(crate::analyzer::PackageAnchor::OwnModule { pop: 0 })
    }

    /// Every Python declaration is packaged by the module its file backs, so
    /// the file's own module is the only anchor this adapter can place.
    fn resolve_package_anchor(
        &self,
        anchor: crate::analyzer::PackageAnchor,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::FqName> {
        match anchor {
            crate::analyzer::PackageAnchor::OwnModule { pop: 0 } => Some(python_module_fq(file)),
            _ => None,
        }
    }

    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope() && !code_unit.is_module()
    }

    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut crate::analyzer::tree_sitter_analyzer::FileState,
    ) {
        let module_fq = python_module_name(file);
        let Some(module) = module_code_unit(file, &module_fq) else {
            return;
        };
        state.top_level_declarations.insert(0, module.clone());
        state.declarations.insert(module.clone());
        state.ranges.entry(module.clone()).or_default().push(Range {
            start_byte: 0,
            end_byte: source.len(),
            start_line: 1,
            end_line: compute_line_starts(source).len(),
        });
        let module_children: Vec<_> = state
            .top_level_declarations
            .iter()
            .filter(|unit| !unit.is_module() && !unit.is_file_scope())
            .filter(|unit| !unit.short_name().contains(['.', '$']))
            .cloned()
            .collect();
        if !module_children.is_empty() {
            state.children.insert(module, module_children);
        }
    }

    fn path_synthetic_module_unit(&self, file: &ProjectFile) -> Option<CodeUnit> {
        module_code_unit(file, &python_module_name(file))
    }

    fn has_path_synthetic_module_units(&self) -> bool {
        true
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        python_source_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        python_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_python_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&PYTHON_COGNITIVE_CONFIG)
    }
}
