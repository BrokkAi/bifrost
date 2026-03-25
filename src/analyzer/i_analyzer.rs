use crate::analyzer::{
    CodeBaseMetrics, CodeUnit, DeclarationInfo, ImportAnalysisProvider, Language, Project,
    ProjectFile, Range, TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider,
    metrics_from_declarations,
};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        None
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        None
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        None
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        None
    }

    fn autocomplete_definitions(&self, query: &str) -> Vec<CodeUnit> {
        if query.is_empty() {
            return Vec::new();
        }

        let base_results = self.search_definitions(&format!(".*?{query}.*?"), false);

        let fuzzy_results = if query.len() < 5 {
            let mut pattern = String::from(".*?");
            for ch in query.chars() {
                pattern.push_str(&regex::escape(&ch.to_string()));
                pattern.push_str(".*?");
            }
            self.search_definitions(&pattern, false)
        } else {
            BTreeSet::new()
        };

        let mut by_fq_name: BTreeMap<String, BTreeSet<CodeUnit>> = BTreeMap::new();
        for code_unit in base_results.into_iter().chain(fuzzy_results.into_iter()) {
            by_fq_name
                .entry(code_unit.fq_name())
                .or_default()
                .insert(code_unit);
        }

        let mut merged: Vec<_> = by_fq_name
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .filter(|code_unit| !code_unit.is_synthetic())
            .collect();
        merged.sort_by(autocomplete_definitions_sort_comparator);
        merged
    }

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

    fn get_skeletons(&self, file: &ProjectFile) -> BTreeMap<CodeUnit, String> {
        let mut skeletons = BTreeMap::new();
        for symbol in self.get_top_level_declarations(file) {
            if let Some(skeleton) = self.get_skeleton(&symbol) {
                skeletons.insert(symbol, skeleton);
            }
        }
        skeletons
    }

    fn get_members_in_class(&self, class_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !class_unit.is_class() && !class_unit.is_module() {
            return Vec::new();
        }

        self.get_direct_children(class_unit)
            .into_iter()
            .filter(|child| child.is_class() || child.is_function() || child.is_field())
            .collect()
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .flat_map(|file| self.get_top_level_declarations(file))
            .map(|code_unit| {
                if code_unit.is_module() {
                    code_unit.fq_name()
                } else {
                    code_unit.package_name().to_string()
                }
            })
            .filter(|module| !module.is_empty())
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        files
            .iter()
            .flat_map(|file| self.get_top_level_declarations(file))
            .filter(|code_unit| {
                code_unit.is_class() || code_unit.is_function() || code_unit.is_module()
            })
            .collect()
    }

    fn get_symbols(&self, sources: &BTreeSet<CodeUnit>) -> BTreeSet<String> {
        let mut symbols = BTreeSet::new();
        for source in sources {
            symbols.insert(source.identifier().to_string());
            if source.is_class() || source.is_module() {
                for child in self.get_direct_children(source) {
                    symbols.insert(child.identifier().to_string());
                }
            }
        }
        symbols
    }

    fn summarize_symbols(&self, file: &ProjectFile) -> String {
        let mut lines = Vec::new();
        for code_unit in self.get_top_level_declarations(file) {
            if code_unit.is_anonymous() {
                continue;
            }
            lines.push(format!("- {}", code_unit.identifier()));
            if code_unit.is_class() || code_unit.is_module() {
                for child in self.get_direct_children(&code_unit) {
                    if child.is_anonymous() {
                        continue;
                    }
                    lines.push(format!("  - {}", child.identifier()));
                }
            }
        }
        lines.join("\n")
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        let fq_name = code_unit.fq_name();
        let mut last_index = None;

        for separator in [".", "$", "::", "->"] {
            if let Some(index) = fq_name.rfind(separator)
                && last_index.map(|current| index > current).unwrap_or(true)
            {
                last_index = Some(index);
            }
        }

        let parent_name = fq_name.get(..last_index?)?;
        self.get_definitions(parent_name)
            .into_iter()
            .find(|candidate| candidate.is_class() || candidate.is_module())
    }
}

fn autocomplete_definitions_sort_comparator(left: &CodeUnit, right: &CodeUnit) -> Ordering {
    autocomplete_rank(left)
        .cmp(&autocomplete_rank(right))
        .then_with(|| {
            left.fq_name()
                .to_lowercase()
                .cmp(&right.fq_name().to_lowercase())
        })
        .then_with(|| {
            left.signature()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&right.signature().unwrap_or("").to_lowercase())
        })
}

fn autocomplete_rank(code_unit: &CodeUnit) -> usize {
    match code_unit.kind() {
        crate::analyzer::CodeUnitType::Class => 0,
        crate::analyzer::CodeUnitType::Function => 1,
        crate::analyzer::CodeUnitType::Field => 2,
        crate::analyzer::CodeUnitType::Module => 3,
    }
}
