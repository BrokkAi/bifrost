use crate::analyzer::{
    CodeBaseMetrics, CodeUnit, CodeUnitType, DeclarationInfo, ImportAnalysisProvider, Language,
    Project, ProjectFile, Range, TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider,
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
    fn signatures_of(&self, _code_unit: &CodeUnit) -> Vec<String> {
        Vec::new()
    }

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
        self.summarize_symbols_with_types(file, &all_code_unit_types())
    }

    fn summarize_symbols_with_types(
        &self,
        file: &ProjectFile,
        types: &BTreeSet<CodeUnitType>,
    ) -> String {
        summarize_code_units_impl(self, &summary_root_units(self, file), types, 0)
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

fn summary_root_units<A: IAnalyzer + ?Sized>(analyzer: &A, file: &ProjectFile) -> Vec<CodeUnit> {
    let declarations: Vec<_> = analyzer.get_declarations(file).into_iter().collect();
    let declaration_set: BTreeSet<_> = declarations.iter().cloned().collect();
    let mut roots: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| {
            analyzer
                .parent_of(code_unit)
                .map(|parent| !declaration_set.contains(&parent))
                .unwrap_or(true)
        })
        .collect();
    roots.sort_by(|left, right| summary_root_order(analyzer, left, right));
    roots
}

fn summary_root_order<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    left: &CodeUnit,
    right: &CodeUnit,
) -> Ordering {
    let left_range = analyzer.ranges_of(left).into_iter().min();
    let right_range = analyzer.ranges_of(right).into_iter().min();
    left_range.cmp(&right_range).then_with(|| left.cmp(right))
}

fn summarize_code_units_impl<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    units: &[CodeUnit],
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
) -> String {
    let indent_str = "  ".repeat(indent);
    let mut summary = String::new();

    if indent == 0 && !units.is_empty() {
        let mut grouped: Vec<(String, Vec<CodeUnit>)> = Vec::new();
        for code_unit in units {
            if code_unit.is_anonymous() || code_unit.is_module() {
                continue;
            }

            let fq_name = code_unit.fq_name();
            let group_prefix = fq_name
                .rfind('.')
                .filter(|index| *index > 0)
                .map(|index| fq_name[..index].to_string())
                .unwrap_or_default();

            if let Some((_, group_units)) = grouped
                .iter_mut()
                .find(|(prefix, _)| prefix == &group_prefix)
            {
                group_units.push(code_unit.clone());
            } else {
                grouped.push((group_prefix, vec![code_unit.clone()]));
            }
        }

        for (group_prefix, group_units) in grouped {
            if !group_prefix.is_empty() {
                summary.push_str("# ");
                summary.push_str(&group_prefix);
                summary.push('\n');
            }

            for code_unit in group_units {
                render_symbol_summary(
                    analyzer,
                    &mut summary,
                    &code_unit,
                    types,
                    indent,
                    &indent_str,
                );
            }
        }
    } else {
        for code_unit in units {
            if code_unit.is_anonymous() {
                continue;
            }
            render_symbol_summary(
                analyzer,
                &mut summary,
                code_unit,
                types,
                indent,
                &indent_str,
            );
        }
    }

    summary.trim_end().to_string()
}

fn render_symbol_summary<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    summary: &mut String,
    code_unit: &CodeUnit,
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
    indent_str: &str,
) {
    summary.push_str(indent_str);
    summary.push_str("- ");
    summary.push_str(code_unit.identifier());

    let children: Vec<_> = ordered_summary_children(
        analyzer,
        code_unit,
        analyzer
            .get_direct_children(code_unit)
            .into_iter()
            .filter(|child| types.contains(&child.kind()))
            .collect(),
    );
    if !children.is_empty() {
        summary.push('\n');
        summary.push_str(&summarize_code_units_impl(
            analyzer,
            &children,
            types,
            indent + 1,
        ));
    }
    summary.push('\n');
}

fn ordered_summary_children<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    parent: &CodeUnit,
    children: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    if children.len() < 2 {
        return children;
    }

    let parent_start = analyzer
        .ranges_of(parent)
        .into_iter()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX);
    let mut ordered = Vec::with_capacity(children.len());
    ordered.extend(children.iter().filter(|child| child.is_field()).cloned());
    ordered.extend(
        children
            .iter()
            .filter(|child| !child.is_field() && child_first_start(analyzer, child) >= parent_start)
            .cloned(),
    );
    ordered.extend(
        children
            .iter()
            .filter(|child| !child.is_field() && child_first_start(analyzer, child) < parent_start)
            .cloned(),
    );
    ordered
}

fn child_first_start<A: IAnalyzer + ?Sized>(analyzer: &A, child: &CodeUnit) -> usize {
    analyzer
        .ranges_of(child)
        .into_iter()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX)
}

fn all_code_unit_types() -> BTreeSet<CodeUnitType> {
    [
        CodeUnitType::Class,
        CodeUnitType::Function,
        CodeUnitType::Field,
        CodeUnitType::Module,
    ]
    .into_iter()
    .collect()
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
