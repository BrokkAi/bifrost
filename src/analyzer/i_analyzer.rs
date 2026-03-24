use crate::analyzer::{
    CodeBaseMetrics, CodeUnit, DeclarationInfo, Language, Project, ProjectFile, Range,
    metrics_from_declarations,
};
use std::any::Any;
use std::collections::BTreeSet;

pub trait IAnalyzer: Send + Sync + Any {
    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit>;
    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        BTreeSet::new()
    }
    fn languages(&self) -> BTreeSet<Language>;
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized;
    fn update_all(&self) -> Self
    where
        Self: Sized;
    fn project(&self) -> &dyn Project;
    fn get_all_declarations(&self) -> Vec<CodeUnit>;
    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit>;
    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String>;
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit>;
    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit>;
    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo>;
    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range>;
    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String>;
    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;

    fn as_capability<T: Any>(&self) -> Option<&T>
    where
        Self: Sized,
    {
        (self as &dyn Any).downcast_ref::<T>()
    }

    fn metrics(&self) -> CodeBaseMetrics {
        metrics_from_declarations(self.get_all_declarations())
    }

    fn is_empty(&self) -> bool {
        self.get_all_declarations().is_empty()
    }

    fn contains_tests(&self, _file: &ProjectFile) -> bool {
        false
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        let fq_name = code_unit.fq_name();
        let mut last_index = None;

        for separator in [".", "$", "::", "->"] {
            if let Some(index) = fq_name.rfind(separator) {
                if last_index.map(|current| index > current).unwrap_or(true) {
                    last_index = Some(index);
                }
            }
        }

        let parent_name = fq_name.get(..last_index?)?;
        self.get_definitions(parent_name)
            .into_iter()
            .find(|candidate| candidate.is_class() || candidate.is_module())
    }
}
