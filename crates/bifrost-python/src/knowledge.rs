//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Python syntax and static language rules.
pub struct PythonKnowledge;

impl LanguageKnowledge for PythonKnowledge {
    fn keyed_property_reads_container_element(&self) -> bool {
        true
    }

    fn language(&self) -> Language {
        Language::Python
    }

    fn path_synthetic_module_unit(
        &self,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<CodeUnit> {
        use crate::declarations::module_code_unit;
        module_code_unit(project, file)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::PYTHON_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_python::HIGHLIGHTS_QUERY)
    }
}
