//! The `LanguageAdapter` forwarding shell for Python.
//!
//! Every answer below comes from [`brokk_bifrost_python`] except
//! `synthesize_hydrated_units`, which mutates `FileState` -- an analysis type
//! with `pub(crate)` fields that cannot leave this crate.

use brokk_bifrost_analysis::analyzer::cognitive_complexity;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_python::adapter::{
    PYTHON_COGNITIVE_CONFIG, PYTHON_FILE_EXTENSION, python_extract_call_receiver,
};
use brokk_bifrost_python::declarations::{
    module_code_unit, parse_python_file, python_module_fq, python_module_name,
};
use brokk_bifrost_python::queries::PYTHON_QUERY_DIRECTORY;
use brokk_bifrost_python::test_detection::python_tree_contains_tests;
use tree_sitter::Tree;

#[derive(Clone, Default)]
pub struct PythonAdapter {
    project: Option<std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project>>,
}

impl std::fmt::Debug for PythonAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PythonAdapter").finish_non_exhaustive()
    }
}

impl PythonAdapter {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn for_test_file(file: &ProjectFile) -> Self {
        Self {
            project: Some(std::sync::Arc::new(
                brokk_bifrost_core::analyzer::project::TestProject::new(
                    file.root(),
                    Language::Python,
                ),
            )),
        }
    }

    pub(crate) fn shared_project(
        &self,
    ) -> std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project> {
        std::sync::Arc::clone(
            self.project
                .as_ref()
                .expect("Python adapter is project bound"),
        )
    }

    pub(crate) fn project(&self) -> &dyn brokk_bifrost_core::analyzer::project::Project {
        self.project
            .as_deref()
            .expect("Python adapter must be bound to its selected project")
    }
}

impl LanguageAdapter for PythonAdapter {
    fn for_project(
        &self,
        project: std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
    ) -> Option<Self> {
        Some(Self {
            project: Some(project),
        })
    }

    fn supports_structural_line_data(&self) -> bool {
        true
    }

    fn is_structural_line_data(
        &self,
        node: tree_sitter::Node<'_>,
        should_stop: &mut dyn FnMut() -> bool,
    ) -> std::ops::ControlFlow<(), bool> {
        brokk_bifrost_python::adapter::is_string_line_data(node, should_stop)
    }

    /// Relative to `brokk-bifrost-python`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        PYTHON_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        PYTHON_FILE_EXTENSION
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    /// Every Python declaration is packaged by the module its file backs, so
    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        python_tree_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        python_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        #[cfg(any(test, feature = "test-support"))]
        if super::trial_native_python_selected() {
            return brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
                self.project(),
                file,
                source,
                tree,
            );
        }
        parse_python_file(self.project(), file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&PYTHON_COGNITIVE_CONFIG)
    }
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter for PythonAdapter {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        Some(&crate::analyzer::python::source_publication::SOURCE_STORAGE)
    }
    fn python_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::python_facts::PYTHON_SOURCE_FACTS_VERSION)
    }
    fn language(&self) -> Language {
        Language::Python
    }
    fn storage_content_qualifier(&self, _code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        String::new()
    }
    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }
    fn hydrate_content_qualifier(&self, _content_qualifier: &str, file: &ProjectFile) -> String {
        python_module_name(self.project(), file)
    }
    fn default_package_anchor(&self) -> Option<brokk_bifrost_core::analyzer::model::PackageAnchor> {
        Some(brokk_bifrost_core::analyzer::model::PackageAnchor::OwnModule { pop: 0 })
    }
    fn resolve_package_anchor(
        &self,
        anchor: brokk_bifrost_core::analyzer::model::PackageAnchor,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<brokk_bifrost_core::analyzer::fq_name::FqName> {
        match anchor {
            brokk_bifrost_core::analyzer::model::PackageAnchor::OwnModule { pop: 0 } => {
                Some(python_module_fq(self.project(), file))
            }
            _ => None,
        }
    }
    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        brokk_bifrost_analysis::analyzer::common::should_persist_code_unit(code_unit)
    }
    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
    ) {
        let Some(module) = module_code_unit(self.project(), file) else {
            return;
        };
        state.top_level_declarations.insert(0, module.clone());
        state.declarations.insert(module.clone());
        state.ranges.entry(module.clone()).or_default().push(
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_source_range(source),
        );
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
        module_code_unit(self.project(), file)
    }
    fn has_path_synthetic_module_units(&self) -> bool {
        true
    }
    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }
    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
}
