use crate::analyzer::{
    CodeUnit, DeclarationInfo, IAnalyzer, Language, Project, ProjectFile, Range,
};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;

pub trait LanguageAdapter: Send + Sync + 'static {
    fn language(&self) -> Language;
    fn query_directory(&self) -> &'static str;
}

pub struct TreeSitterAnalyzer<A> {
    project: Arc<dyn Project>,
    adapter: Arc<A>,
    _state: PhantomData<A>,
}

impl<A> Clone for TreeSitterAnalyzer<A> {
    fn clone(&self) -> Self {
        Self {
            project: Arc::clone(&self.project),
            adapter: Arc::clone(&self.adapter),
            _state: PhantomData,
        }
    }
}

impl<A> TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    pub fn new(project: Arc<dyn Project>, adapter: A) -> Self {
        Self {
            project,
            adapter: Arc::new(adapter),
            _state: PhantomData,
        }
    }

    pub fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    pub fn adapter(&self) -> &A {
        self.adapter.as_ref()
    }
}

impl<A> IAnalyzer for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn get_top_level_declarations(&self, _file: &ProjectFile) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([self.adapter.language()])
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
        self.clone()
    }

    fn update_all(&self) -> Self {
        self.clone()
    }

    fn project(&self) -> &dyn Project {
        self.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn get_declarations(&self, _file: &ProjectFile) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

    fn get_definitions(&self, _fq_name: &str) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn get_direct_children(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn import_statements_of(&self, _file: &ProjectFile) -> Vec<String> {
        Vec::new()
    }

    fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<CodeUnit> {
        None
    }

    fn is_access_expression(&self, _file: &ProjectFile, _start_byte: usize, _end_byte: usize) -> bool {
        true
    }

    fn find_nearest_declaration(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<DeclarationInfo> {
        None
    }

    fn ranges_of(&self, _code_unit: &CodeUnit) -> Vec<Range> {
        Vec::new()
    }

    fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
        None
    }

    fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn search_definitions(&self, _pattern: &str, _auto_quote: bool) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
}
