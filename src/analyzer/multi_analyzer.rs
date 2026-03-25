use crate::analyzer::{
    CodeUnit, CppAnalyzer, DeclarationInfo, GoAnalyzer, IAnalyzer, ImportAnalysisProvider,
    ImportInfo, JavaAnalyzer, JavascriptAnalyzer, Language, Project, ProjectFile, PythonAnalyzer,
    Range, RustAnalyzer, TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider,
    TypescriptAnalyzer,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub enum AnalyzerDelegate {
    Java(JavaAnalyzer),
    Cpp(CppAnalyzer),
    Go(GoAnalyzer),
    JavaScript(JavascriptAnalyzer),
    Python(PythonAnalyzer),
    TypeScript(TypescriptAnalyzer),
    Rust(RustAnalyzer),
}

impl AnalyzerDelegate {
    fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
        }
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => Some(analyzer),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
        }
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Go(analyzer) => analyzer.type_hierarchy_provider(),
            Self::JavaScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Rust(analyzer) => analyzer.type_hierarchy_provider(),
        }
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        match self {
            Self::Java(analyzer) => analyzer.type_alias_provider(),
            Self::Cpp(analyzer) => analyzer.type_alias_provider(),
            Self::Go(analyzer) => analyzer.type_alias_provider(),
            Self::JavaScript(analyzer) => analyzer.type_alias_provider(),
            Self::Python(analyzer) => analyzer.type_alias_provider(),
            Self::TypeScript(analyzer) => analyzer.type_alias_provider(),
            Self::Rust(analyzer) => analyzer.type_alias_provider(),
        }
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => analyzer.test_detection_provider(),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
        }
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update(changed_files)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update(changed_files)),
            Self::Go(analyzer) => Self::Go(analyzer.update(changed_files)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update(changed_files)),
            Self::Python(analyzer) => Self::Python(analyzer.update(changed_files)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update(changed_files)),
            Self::Rust(analyzer) => Self::Rust(analyzer.update(changed_files)),
        }
    }

    fn update_all(&self) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update_all()),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update_all()),
            Self::Go(analyzer) => Self::Go(analyzer.update_all()),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update_all()),
            Self::Python(analyzer) => Self::Python(analyzer.update_all()),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update_all()),
            Self::Rust(analyzer) => Self::Rust(analyzer.update_all()),
        }
    }
}

#[derive(Clone, Default)]
pub struct MultiAnalyzer {
    delegates: BTreeMap<Language, AnalyzerDelegate>,
}

impl MultiAnalyzer {
    pub fn new(delegates: BTreeMap<Language, AnalyzerDelegate>) -> Self {
        Self { delegates }
    }

    pub fn with_java(java: JavaAnalyzer) -> Self {
        Self::new(BTreeMap::from([(
            Language::Java,
            AnalyzerDelegate::Java(java),
        )]))
    }

    pub fn delegates(&self) -> &BTreeMap<Language, AnalyzerDelegate> {
        &self.delegates
    }

    fn delegate_for_file(&self, file: &ProjectFile) -> Option<&AnalyzerDelegate> {
        let extension = file.rel_path().extension().and_then(|ext| ext.to_str())?;
        let language = Language::from_extension(extension);
        self.delegates.get(&language)
    }

    fn delegate_for_code_unit(&self, code_unit: &CodeUnit) -> Option<&AnalyzerDelegate> {
        self.delegate_for_file(code_unit.source())
    }
}

impl ImportAnalysisProvider for MultiAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.imported_code_units_of(file))
            .unwrap_or_default()
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        self.delegates
            .values()
            .filter_map(AnalyzerDelegate::import_analysis_provider)
            .flat_map(|provider| provider.referencing_files_of(file))
            .collect()
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_info_of(file))
            .unwrap_or_default()
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> BTreeSet<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.relevant_imports_for(code_unit))
            .unwrap_or_default()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.could_import_file(source_file, imports, target))
            .unwrap_or(false)
    }
}

impl TypeHierarchyProvider for MultiAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_ancestors(code_unit))
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> BTreeSet<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_descendants(code_unit))
            .unwrap_or_default()
    }
}

impl TypeAliasProvider for MultiAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_alias_provider)
            .map(|provider| provider.is_type_alias(code_unit))
            .unwrap_or(false)
    }
}

impl TestDetectionProvider for MultiAnalyzer {}

impl IAnalyzer for MultiAnalyzer {
    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().get_top_level_declarations(file))
            .unwrap_or_default()
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().get_analyzed_files())
            .collect()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.delegates.keys().copied().collect()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let delegates = self
            .delegates
            .iter()
            .map(|(language, delegate)| (*language, delegate.update(changed_files)))
            .collect();
        Self::new(delegates)
    }

    fn update_all(&self) -> Self {
        let delegates = self
            .delegates
            .iter()
            .map(|(language, delegate)| (*language, delegate.update_all()))
            .collect();
        Self::new(delegates)
    }

    fn project(&self) -> &dyn Project {
        self.delegates
            .values()
            .next()
            .expect("MultiAnalyzer requires at least one delegate")
            .analyzer()
            .project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        let mut declarations: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().get_all_declarations())
            .collect();
        declarations.sort();
        declarations.dedup();
        declarations
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().get_declarations(file))
            .unwrap_or_default()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        let mut definitions: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().get_definitions(fq_name))
            .collect();
        definitions.sort();
        definitions.dedup();
        definitions
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().get_direct_children(code_unit))
            .unwrap_or_default()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.delegates
            .values()
            .find_map(|delegate| delegate.analyzer().extract_call_receiver(reference))
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().import_statements_of(file))
            .unwrap_or_default()
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().enclosing_code_unit(file, range))
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .enclosing_code_unit_for_lines(file, start_line, end_line)
        })
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .is_access_expression(file, start_byte, end_byte)
            })
            .unwrap_or(true)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .find_nearest_declaration(file, start_byte, end_byte, ident)
        })
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().ranges_of(code_unit))
            .unwrap_or_default()
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton_header(code_unit))
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_source(code_unit, include_comments))
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().get_sources(code_unit, include_comments))
            .unwrap_or_default()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().search_definitions(pattern, auto_quote))
            .collect()
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.import_analysis_provider().is_some())
            .then_some(self as &dyn ImportAnalysisProvider)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.type_hierarchy_provider().is_some())
            .then_some(self as &dyn TypeHierarchyProvider)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.type_alias_provider().is_some())
            .then_some(self as &dyn TypeAliasProvider)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.test_detection_provider().is_some())
            .then_some(self as &dyn TestDetectionProvider)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().contains_tests(file))
            .unwrap_or(false)
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            let extension = file
                .rel_path()
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or_default();
            grouped
                .entry(Language::from_extension(extension))
                .or_default()
                .push(file.clone());
        }

        let mut modules = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                modules.extend(delegate.analyzer().get_test_modules(&group));
            } else {
                modules.extend(IAnalyzer::get_test_modules(self, &group));
            }
        }
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            let extension = file
                .rel_path()
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or_default();
            grouped
                .entry(Language::from_extension(extension))
                .or_default()
                .push(file.clone());
        }

        let mut result = BTreeSet::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                result.extend(delegate.analyzer().test_files_to_code_units(&group));
            } else {
                result.extend(IAnalyzer::test_files_to_code_units(self, &group));
            }
        }
        result
    }
}
