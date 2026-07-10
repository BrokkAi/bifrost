use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder};
use crate::analyzer::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, DefinitionLookupIndex, ExceptionHandlingSmell, ExceptionSmellWeights,
    ImportAnalysisProvider, Language, ParseError, Project, ProjectFile, Range, SemanticDiagnostic,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TypeAliasProvider, TypeHierarchyProvider, UsageFactsIndex, metrics_from_declarations,
};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

pub trait IAnalyzer: Send + Sync + Any {
    fn top_level_declarations(&self, _file: &ProjectFile) -> Vec<CodeUnit> {
        Vec::new()
    }
    fn analyzed_files(&self) -> Vec<ProjectFile> {
        Vec::new()
    }
    /// Source text retained by the analyzer generation that produced this
    /// file's declarations and byte ranges.
    fn indexed_source<'a>(&'a self, file: &ProjectFile) -> Option<&'a str>;
    /// Applies language-specific rendering to an extracted source fragment.
    /// `declaration_start` is the byte offset of the declaration inside the
    /// fragment, after any attached comments. The default preserves the
    /// indexed text unchanged.
    fn render_source_fragment(
        &self,
        _code_unit: &CodeUnit,
        source: String,
        _declaration_start: usize,
    ) -> String {
        source
    }
    /// Whether `file` is one this analyzer has indexed. The default scans
    /// `analyzed_files`; concrete analyzers override with an O(1) lookup so
    /// incremental callers don't pay O(repo) per changed file.
    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.analyzed_files()
            .iter()
            .any(|candidate| candidate == file)
    }
    fn languages(&self) -> BTreeSet<Language>;
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized;
    fn update_all(&self) -> Self
    where
        Self: Sized;
    fn project(&self) -> &dyn Project;
    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_>;
    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.all_declarations()
            .map(|unit| {
                let range = self
                    .ranges(&unit)
                    .into_iter()
                    .min_by_key(|range| (range.start_line, range.start_byte));
                (unit, range)
            })
            .collect()
    }
    fn declarations(&self, _file: &ProjectFile) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
    fn definitions(&self, _fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }
    fn definition_lookup_index(&self) -> &DefinitionLookupIndex {
        static EMPTY: OnceLock<DefinitionLookupIndex> = OnceLock::new();
        EMPTY.get_or_init(DefinitionLookupIndex::default)
    }
    fn usage_facts_index(&self) -> &UsageFactsIndex {
        static EMPTY: OnceLock<UsageFactsIndex> = OnceLock::new();
        EMPTY.get_or_init(UsageFactsIndex::default)
    }
    fn direct_children(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
        Vec::new()
    }
    /// Return the tree-sitter parse errors recorded for `file` during the
    /// most recent `analyze_file` pass. Returns `None` when the analyzer
    /// holds no state for this file (file outside the analyzer's language,
    /// `FileState` hydrated from the persisted baseline this session and
    /// not yet re-parsed, or analysis failed); callers fall back to a fresh
    /// parse in that case. An empty `Some(...)` means the file parsed
    /// cleanly. Today's `TreeSitterAnalyzer` impl clones the cached `Vec`
    /// per call — fine on clean files (the vec is empty), but a buffer
    /// mid-edit with many errors does one alloc per request. Acceptable
    /// while the second-parse cost still dominates; revisit by switching
    /// the return type to `Option<&[ParseError]>` (needs a lifetime on the
    /// trait method) or wrapping in `Arc<[ParseError]>` if it shows up in
    /// profiles.
    fn parse_errors(&self, _file: &ProjectFile) -> Option<Vec<ParseError>> {
        None
    }

    fn semantic_diagnostics(&self, _file: &ProjectFile, _source: &str) -> Vec<SemanticDiagnostic> {
        Vec::new()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    fn import_statements(&self, _file: &ProjectFile) -> Vec<String> {
        Vec::new()
    }
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
    fn ranges(&self, _code_unit: &CodeUnit) -> Vec<Range> {
        Vec::new()
    }
    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String>;
    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    /// Cold-start substring search that runs against the persisted FTS5
    /// symbol index, without requiring `AnalyzerState` to be fully built.
    /// Implementations that have no persistence layer (or whose storage
    /// open failed) should fall back to `search_definitions(pattern, true)`,
    /// which preserves the legacy in-memory behavior.
    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.search_definitions(pattern, true)
    }
    fn signatures(&self, _code_unit: &CodeUnit) -> Vec<String> {
        Vec::new()
    }
    fn signature_metadata(&self, _code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        Vec::new()
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.analyzed_files().into_iter().collect()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.all_declarations().collect()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.definitions(fq_name).collect()
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_children(code_unit)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.import_statements(file)
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.ranges(code_unit)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.signatures(code_unit)
    }

    fn signature_metadata_of(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.signature_metadata(code_unit)
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

    /// Per-language structural-search capabilities (issue #328), one provider
    /// per language whose adapter has a structural spec. Languages without a
    /// spec are absent; `query_code` reports them as capability diagnostics
    /// instead of silently returning nothing.
    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        Vec::new()
    }

    fn autocomplete_definitions(&self, query: &str) -> Vec<CodeUnit> {
        if query.is_empty() {
            return Vec::new();
        }

        let base_results = self.search_definitions(&format!(".*?{query}.*?"), false);

        // Short prefixes additionally run a fuzzy `c.*?h.*?a.*?r` pass to
        // surface camelCase matches the strict substring wouldn't catch. Skip
        // that pass when the strict pass already saturated downstream caps:
        // every reasonable caller truncates somewhere ≤ AUTOCOMPLETE_SATURATION,
        // so the fuzzy pass can only contribute items that will be discarded.
        // This is the dominant cost on per-keystroke completion paths.
        const AUTOCOMPLETE_SATURATION: usize = 1000;
        let fuzzy_results = if query.len() < 5 && base_results.len() < AUTOCOMPLETE_SATURATION {
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
        for code_unit in base_results.into_iter().chain(fuzzy_results) {
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

    /// Find call sites and references to the given overloads using the default
    /// [`UsageFinder`] strategy. The free function [`crate::analyzer::usages::find_usages`] is the
    /// equivalent for callers that hold a `&dyn IAnalyzer`.
    fn find_usages(&self, overloads: &[CodeUnit]) -> FuzzyResult
    where
        Self: Sized,
    {
        UsageFinder::new().find_usages(self, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
    }

    /// Like [`Self::find_usages`] but returns the candidate file set alongside the result.
    fn query_usages(
        &self,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> crate::analyzer::usages::QueryResult
    where
        Self: Sized,
    {
        UsageFinder::new().query(self, overloads, max_files, max_usages)
    }

    fn metrics(&self) -> CodeBaseMetrics {
        metrics_from_declarations(self.all_declarations())
    }

    fn is_empty(&self) -> bool {
        self.all_declarations().next().is_none()
    }

    fn contains_tests(&self, _file: &ProjectFile) -> bool {
        false
    }

    /// Compute heuristic cognitive complexity for every function-like code
    /// unit declared in `file`, preserving source order.
    ///
    /// The default implementation returns an empty vector — analyzers that
    /// expose tree-sitter ASTs override this with a per-language scorer.
    /// Callers must treat a missing key as "not computed" rather than
    /// "complexity is zero".
    fn compute_cognitive_complexities(&self, _file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        Vec::new()
    }

    /// Comment density for a single declaration. Language-specific analyzers
    /// may override; default is unsupported. Mirrors brokk-shared
    /// `IAnalyzer.commentDensity(CodeUnit)`.
    fn comment_density(&self, _code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        None
    }

    /// Comment density for the first resolved declaration that supports it.
    /// Mirrors brokk-shared `IAnalyzer.commentDensity(String)`.
    fn comment_density_by_fq_name(&self, fq_name: &str) -> Option<CommentDensityStats> {
        self.get_definitions(fq_name)
            .into_iter()
            .find_map(|cu| self.comment_density(&cu))
    }

    /// Per-top-level-declaration comment density for a file. Default is an
    /// empty vector — non-Java analyzers stay silent until they add their own
    /// implementation. Mirrors brokk-shared
    /// `IAnalyzer.commentDensityByTopLevel(ProjectFile)`.
    fn comment_density_by_top_level(&self, _file: &ProjectFile) -> Vec<CommentDensityStats> {
        Vec::new()
    }

    /// Detect suspicious exception-handling sites in `file` using `weights`.
    /// Default is an empty vector so analyzers without a port of the
    /// heuristic stay silent. Mirrors brokk-shared
    /// `IAnalyzer.findExceptionHandlingSmells`.
    fn find_exception_handling_smells(
        &self,
        _file: &ProjectFile,
        _weights: ExceptionSmellWeights,
    ) -> Vec<ExceptionHandlingSmell> {
        Vec::new()
    }

    /// Detect suspicious low-value or brittle test assertions in `file`
    /// using `weights`. Default is an empty vector so analyzers that do not
    /// yet implement this heuristic stay silent.
    fn find_test_assertion_smells(
        &self,
        _file: &ProjectFile,
        _weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        Vec::new()
    }

    fn find_structural_clone_smells(
        &self,
        _file: &ProjectFile,
        _weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        Vec::new()
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        files
            .iter()
            .flat_map(|file| self.find_structural_clone_smells(file, weights))
            .collect()
    }

    fn get_skeletons(&self, file: &ProjectFile) -> BTreeMap<CodeUnit, String> {
        let mut skeletons = BTreeMap::new();
        for symbol in self.top_level_declarations(file) {
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

        self.direct_children(class_unit)
            .into_iter()
            .filter(|child| child.is_class() || child.is_function() || child.is_field())
            .collect()
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .flat_map(|file| self.top_level_declarations(file))
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
            .flat_map(|file| self.top_level_declarations(file))
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
                for child in self.direct_children(source) {
                    symbols.insert(child.identifier().to_string());
                }
            }
        }
        symbols
    }

    fn list_symbols(&self, file: &ProjectFile) -> String {
        self.list_symbols_with_types(file, &all_code_unit_types())
    }

    fn list_top_level_symbols(&self, file: &ProjectFile) -> String {
        summarize_code_units_impl(
            self,
            &summary_root_units(self, file),
            &all_code_unit_types(),
            0,
            false,
        )
    }

    fn list_symbols_with_types(
        &self,
        file: &ProjectFile,
        types: &BTreeSet<CodeUnitType>,
    ) -> String {
        summarize_code_units_impl(self, &summary_root_units(self, file), types, 0, true)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        let fq_name = code_unit.fq_name();
        let mut last_index = None;

        for separator in [".", "$", "::", "->"] {
            if let Some(index) = fq_name.rfind(separator)
                && index + separator.len() < fq_name.len()
                && last_index.map(|current| index > current).unwrap_or(true)
            {
                last_index = Some(index);
            }
        }

        let parent_name = fq_name.get(..last_index?)?;
        self.definitions(parent_name).next()
    }
}

fn summary_root_units<A: IAnalyzer + ?Sized>(analyzer: &A, file: &ProjectFile) -> Vec<CodeUnit> {
    let declarations: Vec<_> = analyzer.declarations(file).into_iter().collect();
    let declaration_set: BTreeSet<_> = declarations.iter().cloned().collect();
    let mut roots: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| {
            analyzer
                .parent_of(code_unit)
                .map(|parent| parent.is_module() || !declaration_set.contains(&parent))
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
    let left_range = analyzer.ranges(left).into_iter().min();
    let right_range = analyzer.ranges(right).into_iter().min();
    left_range.cmp(&right_range).then_with(|| left.cmp(right))
}

fn summarize_code_units_impl<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    units: &[CodeUnit],
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
    recursive: bool,
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
                    recursive,
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
                recursive,
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
    recursive: bool,
) {
    summary.push_str(indent_str);
    summary.push_str("- ");
    summary.push_str(&display_identifier_for_target(code_unit));

    if recursive {
        let children: Vec<_> = ordered_summary_children(
            analyzer,
            code_unit,
            analyzer
                .direct_children(code_unit)
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
                recursive,
            ));
        }
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
        .ranges(parent)
        .iter()
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
        .ranges(child)
        .iter()
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
        CodeUnitType::Macro,
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
        crate::analyzer::CodeUnitType::Macro => 3,
        crate::analyzer::CodeUnitType::Module => 4,
        crate::analyzer::CodeUnitType::FileScope => 5,
    }
}
