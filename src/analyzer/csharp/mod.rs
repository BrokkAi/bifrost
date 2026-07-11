mod adapter;
mod cache;
mod clones;
mod declarations;
mod hierarchy;
mod imports;
mod structural;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::usages::visible_names::{FileImportContext, resolve_visible_type};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer,
    ImportAnalysisProvider, Language, Project, ProjectFile, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider,
    UsageFactsIndex,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::{CloneSmell, CloneSmellWeights};
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Node, Parser};

use adapter::CSharpAdapter;
use cache::CSharpMemoCaches;
use clones::{build_csharp_clone_candidate_data, refine_csharp_clone_similarity};
use imports::{csharp_using_alias_from_import, csharp_using_namespace};
use tests::detect_csharp_test_assertion_smells;

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
    memo_caches: Arc<CSharpMemoCaches>,
}

impl CSharpAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, CSharpAdapter, config),
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            CSharpAdapter,
            config,
            store_context,
            progress,
        );
        Self {
            inner,
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        let package = self.inner.package_name_of(file).unwrap_or_default();
        if !package.is_empty() {
            return package.to_string();
        }
        self.declarations(file)
            .into_iter()
            .map(|unit| unit.package_name().to_string())
            .find(|package| !package.is_empty())
            .unwrap_or_default()
    }

    pub fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return (*cached).clone();
        }

        let mut namespaces: Vec<String> = self
            .inner
            .import_info_of(file)
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .collect();
        for namespace in self.global_using_namespaces() {
            if !namespaces.contains(namespace) {
                namespaces.push(namespace.clone());
            }
        }
        self.memo_caches
            .using_namespaces
            .insert(file.clone(), Arc::new(namespaces.clone()));
        namespaces
    }

    pub fn using_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        if let Some(cached) = self.memo_caches.using_aliases.get(file) {
            return (*cached).clone();
        }

        let mut aliases: HashMap<String, String> = self
            .inner
            .import_info_of(file)
            .iter()
            .filter_map(csharp_using_alias_from_import)
            .collect();
        for (alias, target) in self.global_using_aliases() {
            aliases
                .entry(alias.clone())
                .or_insert_with(|| target.clone());
        }
        self.memo_caches
            .using_aliases
            .insert(file.clone(), Arc::new(aliases.clone()));
        aliases
    }

    fn global_using_namespaces(&self) -> &HashSet<String> {
        self.memo_caches.global_using_namespaces.get_or_init(|| {
            self.inner
                .all_files()
                .into_iter()
                .flat_map(|file| self.inner.import_info_of(&file).into_iter())
                .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
                .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
                .collect()
        })
    }

    fn global_using_aliases(&self) -> &HashMap<String, String> {
        self.memo_caches.global_using_aliases.get_or_init(|| {
            self.inner
                .all_files()
                .into_iter()
                .flat_map(|file| self.inner.import_info_of(&file).into_iter())
                .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
                .filter_map(|import| csharp_using_alias_from_import(&import))
                .collect()
        })
    }

    pub fn visible_type_candidates(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        self.visible_type_candidates_inner(file, name, true)
    }

    pub(crate) fn partial_type_parts(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        if !owner.is_class() {
            return Vec::new();
        }
        let owner_key = self.type_declaration_key(owner);
        let mut parts: Vec<_> = self
            .inner
            .get_definitions(&owner.fq_name())
            .into_iter()
            .filter(|unit| unit.is_class() && self.type_declaration_key(unit) == owner_key)
            .collect();
        self.sort_type_candidates(&mut parts);
        parts.dedup();
        parts
    }

    pub(crate) fn sort_dedup_type_candidates(&self, candidates: &mut Vec<CodeUnit>) {
        let mut keyed: Vec<_> = candidates
            .drain(..)
            .map(|unit| {
                let key = self.type_declaration_key(&unit);
                let source = crate::path_utils::rel_path_string(unit.source());
                (unit, key, source)
            })
            .collect();
        keyed.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.2.cmp(&right.2)));
        keyed.dedup_by(|left, right| left.1 == right.1);
        candidates.extend(keyed.into_iter().map(|(unit, _, _)| unit));
    }

    pub(crate) fn sort_type_candidates(&self, candidates: &mut [CodeUnit]) {
        candidates.sort_by_cached_key(|unit| {
            (
                self.type_declaration_key(unit),
                crate::path_utils::rel_path_string(unit.source()),
            )
        });
    }

    pub(crate) fn logical_type_count(&self, candidates: &[CodeUnit]) -> usize {
        candidates
            .iter()
            .map(|unit| self.type_declaration_key(unit))
            .collect::<HashSet<_>>()
            .len()
    }

    pub(crate) fn first_logical_type_fqn(&self, candidates: &[CodeUnit]) -> Option<String> {
        let mut sorted = candidates.to_vec();
        self.sort_type_candidates(&mut sorted);
        sorted.first().map(CodeUnit::fq_name)
    }

    fn type_declaration_key(&self, unit: &CodeUnit) -> (String, usize) {
        (
            unit.fq_name(),
            self.inner
                .signatures(unit)
                .first()
                .map_or(0, |signature| csharp_type_parameter_count(signature)),
        )
    }

    pub fn resolve_visible_type(&self, file: &ProjectFile, name: &str) -> Option<CodeUnit> {
        let ctx = self.file_import_context(file);
        resolve_visible_type(
            self.definition_lookup_index(),
            &ctx,
            name,
            &csharp_normalize_full_name,
            &|_| true,
        )
        .cloned()
    }

    fn visible_type_candidates_inner(
        &self,
        file: &ProjectFile,
        name: &str,
        resolve_aliases: bool,
    ) -> Vec<CodeUnit> {
        let normalized = normalize_csharp_type_fragment(name);
        if normalized.is_empty() {
            return Vec::new();
        }
        if resolve_aliases
            && let Some(target) = self.using_aliases_of(file).get(&normalized)
            && target != &normalized
        {
            return self.visible_type_candidates_inner(file, target, false);
        }

        let mut candidates = self.type_candidates_by_fqn(&normalized);
        if !normalized.contains('.') {
            let mut namespaces = self.using_namespaces_of(file);
            let file_namespace = self.namespace_of_file(file);
            if !file_namespace.is_empty() {
                namespaces.push(file_namespace);
            }
            for namespace in namespaces {
                candidates.extend(
                    self.definition_lookup_index()
                        .types_in_package(&namespace, &normalized)
                        .iter()
                        .cloned(),
                );
            }
        }
        candidates
    }

    fn type_candidates_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let normalized = csharp_normalize_full_name(fqn);
        self.definition_lookup_index()
            .by_fqn(fqn)
            .iter()
            .chain(
                self.definition_lookup_index()
                    .by_normalized_fqn(&normalized)
                    .iter(),
            )
            .filter(|unit| unit.is_class())
            .cloned()
            .collect()
    }

    fn file_import_context(&self, file: &ProjectFile) -> CSharpFileImportContext<'_> {
        CSharpFileImportContext {
            csharp: self,
            package: self.namespace_of_file(file),
            namespaces: self.using_namespaces_of(file),
            aliases: self.using_aliases_of(file),
        }
    }
}

pub(crate) fn csharp_normalize_full_name(fq_name: &str) -> String {
    let normalized = fq_name.replace(['$', '+'], ".");
    let Some(owner) = normalized.strip_suffix(".#ctor") else {
        return normalized;
    };
    if owner.is_empty() {
        return normalized;
    }

    let constructor_name = owner
        .rfind('.')
        .map(|separator| &owner[separator + 1..])
        .unwrap_or(owner);
    if constructor_name.is_empty() {
        normalized
    } else {
        format!("{owner}.{constructor_name}")
    }
}

pub(crate) fn csharp_signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')').map(|(inner, _)| inner))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    count_top_level_comma_separated(inner)
}

pub(crate) fn csharp_signature_return_type(signature: &str, name: &str) -> Option<String> {
    type_text_before_name(signature, name)
}

fn type_text_before_name(signature: &str, name: &str) -> Option<String> {
    let before_name = signature.trim().rsplit_once(name)?.0.trim();
    let before_name = before_name.trim_end_matches(|ch: char| ch == '?' || ch.is_whitespace());
    let type_text = before_name
        .split_whitespace()
        .rfind(|part| !member_modifier(part))?;
    let type_text = normalize_csharp_type_fragment(type_text);
    (!type_text.is_empty()).then_some(type_text)
}

fn member_modifier(part: &str) -> bool {
    matches!(
        part,
        "public"
            | "private"
            | "protected"
            | "internal"
            | "static"
            | "readonly"
            | "volatile"
            | "const"
            | "new"
            | "virtual"
            | "override"
            | "abstract"
            | "sealed"
            | "required"
    )
}

fn normalize_csharp_type_fragment(reference: &str) -> String {
    let trimmed = reference.trim();
    let without_nullable = trimmed.trim_end_matches('?').trim();
    let without_arrays = without_nullable.trim_end_matches("[]").trim();
    without_arrays
        .split('<')
        .next()
        .unwrap_or(without_arrays)
        .trim()
        .to_string()
}

fn count_top_level_comma_separated(text: &str) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    let mut count = 1;
    let mut angle_depth: usize = 0;
    let mut paren_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut string_quote: Option<char> = None;
    let mut escaped = false;

    for ch in text.chars() {
        if let Some(quote) = string_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                string_quote = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => string_quote = Some(ch),
            '<' => angle_depth = angle_depth.saturating_add(1),
            '>' if angle_depth > 0 => angle_depth -= 1,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' if paren_depth > 0 => paren_depth -= 1,
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' if bracket_depth > 0 => bracket_depth -= 1,
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' if brace_depth > 0 => brace_depth -= 1,
            ',' if angle_depth == 0
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0 =>
            {
                count += 1;
            }
            _ => {}
        }
    }

    count
}

struct CSharpFileImportContext<'a> {
    csharp: &'a CSharpAnalyzer,
    package: String,
    namespaces: Vec<String>,
    aliases: HashMap<String, String>,
}

impl FileImportContext for CSharpFileImportContext<'_> {
    fn imported_type_names(&self, simple: &str) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(target) = self.aliases.get(simple)
            && target != simple
        {
            names.push(target.clone());
            if !target.contains('.') {
                names.extend(
                    self.namespaces
                        .iter()
                        .map(|namespace| format!("{namespace}.{target}")),
                );
                if !self.package.is_empty() {
                    names.push(format!("{}.{target}", self.package));
                }
            }
            return names;
        }
        if !simple.contains('.') {
            names.extend(
                self.namespaces
                    .iter()
                    .map(|namespace| format!("{namespace}.{simple}")),
            );
        }
        names
    }

    fn package_of_file(&self) -> &str {
        &self.package
    }

    fn select_unique<'a>(&self, candidates: Vec<&'a CodeUnit>) -> Option<&'a CodeUnit> {
        let mut keyed = candidates
            .into_iter()
            .map(|unit| {
                let key = self.csharp.type_declaration_key(unit);
                let source = rel_path_string(unit.source());
                (unit, key, source)
            })
            .collect::<Vec<_>>();
        keyed.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.2.cmp(&right.2)));
        keyed.dedup_by(|left, right| left.1 == right.1);
        (keyed.len() == 1).then(|| keyed[0].0)
    }
}

fn csharp_type_parameter_count(signature: &str) -> usize {
    let source = if signature.trim_end().ends_with('{') {
        format!("{signature} }}")
    } else {
        signature.to_string()
    };
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .is_err()
    {
        return 0;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return 0;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) {
            return node
                .child_by_field_name("type_parameters")
                .or_else(|| first_named_child_of_kind(node, "type_parameter_list"))
                .map_or(0, count_type_parameters);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    0
}

fn count_type_parameters(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter")
        .count()
}

fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

impl TestDetectionProvider for CSharpAnalyzer {}

impl IAnalyzer for CSharpAnalyzer {
    fn begin_query(&self) {
        self.inner.begin_query();
    }

    fn end_query(&self) {
        self.inner.end_query();
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.top_level_declarations(file)
    }

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>> {
        self.inner.summary_file_projection(file)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.indexed_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.inner.indexed_source_matches(file, source)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn definition_lookup_index(&self) -> &crate::analyzer::DefinitionLookupIndex {
        self.inner.definition_lookup_index()
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata(code_unit)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.inner.is_access_expression(file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        self.inner
            .find_nearest_declaration(file, start_byte, end_byte, ident)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Vec<crate::analyzer::SearchSymbolCandidate> {
        self.inner.search_symbol_candidates(pattern, auto_quote)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::CSharp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_csharp_test_assertion_smells(file, &source, &weights)
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let requested_files: Vec<ProjectFile> = files
            .iter()
            .filter(|file| file_language(file) == Language::CSharp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::CSharp
            })
            .filter_map(|code_unit| build_csharp_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_csharp_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }
}
