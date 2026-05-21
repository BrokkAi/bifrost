use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    compute_ast_refinement_similarity_percent, detect_structural_clone_smells,
};
use crate::analyzer::cognitive_complexity;
use crate::analyzer::tree_sitter_analyzer::expanded_comment_start;
use crate::analyzer::{
    AnalyzerConfig, CloneSmell, CloneSmellWeights, CodeUnit, CommentDensityStats, DeclarationInfo,
    DeclarationKind, ExceptionHandlingSmell, ExceptionSmellWeights, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, Language, LanguageAdapter, Project, ProjectFile,
    SourceContent, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider, build_reverse_import_index,
    direct_descendants_via_ancestors,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::sync::{Arc, LazyLock, OnceLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Java. Mirrors `ai.brokk.analyzer.java.CognitiveComplexityAnalysis`.
static JAVA_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "enhanced_for_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["ternary_expression"],
        case_types: &["switch_label", "switch_rule"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_statement", "continue_statement"],
        anonymous_function_types: &["lambda_expression"],
        default_case_predicate: Some(java_is_default_switch_label),
        ..cognitive_complexity::Config::empty()
    });

fn java_is_default_switch_label(node: Node<'_>, source: &str) -> bool {
    let Some(text) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    text.trim_start().starts_with("default")
}

static CLONE_AST_IDENTIFIER_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from_iter([
        "identifier",
        "type_identifier",
        "scoped_identifier",
        "scoped_type_identifier",
    ])
});
static CLONE_AST_STRING_TYPES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from_iter(["string_literal", "character_literal"]));
static CLONE_AST_NUMBER_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from_iter([
        "decimal_integer_literal",
        "hex_integer_literal",
        "octal_integer_literal",
        "binary_integer_literal",
        "decimal_floating_point_literal",
        "hex_floating_point_literal",
    ])
});
static CLONE_AST_IGNORED_TYPES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from_iter(["modifiers", "type_parameters"]));

#[derive(Debug, Clone, Default)]
pub struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn language(&self) -> Language {
        Language::Java
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/java"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_java::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "java"
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }

    fn is_anonymous_structure(&self, fq_name: &str) -> bool {
        is_java_anonymous_structure(fq_name)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        extract_java_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        java_source_contains_tests(source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let root = tree.root_node();
        let package_name = determine_package_name(root, source);
        let mut parsed =
            crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name.clone());
        collect_type_identifiers(root, source, &mut parsed.type_identifiers);
        let module_code_unit =
            (!package_name.is_empty()).then(|| module_code_unit(file, &package_name));

        if let Some(module) = &module_code_unit {
            parsed.top_level_declarations.push(module.clone());
            parsed.declarations.insert(module.clone());
            parsed.add_signature(module.clone(), format!("package {};", package_name));
        }

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };

            match child.kind() {
                "import_declaration" => {
                    let raw = node_text(child, source).trim().to_string();
                    parsed.import_statements.push(raw.clone());
                    parsed.imports.push(parse_import_info(raw));
                }
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => {
                    let class_code_unit = visit_class_like(
                        file,
                        source,
                        child,
                        &package_name,
                        None,
                        None,
                        &mut parsed,
                    );
                    if let (Some(module), Some(class_code_unit)) =
                        (&module_code_unit, class_code_unit)
                    {
                        parsed.add_child(module.clone(), class_code_unit);
                    }
                }
                _ => {}
            }
        }

        parsed
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&JAVA_COGNITIVE_CONFIG)
    }
}

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
}

#[derive(Clone)]
struct JavaMemoCaches {
    budget_bytes: u64,
    resolved_imports: Cache<ProjectFile, Arc<HashMap<String, CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    relevant_imports: Cache<CodeUnit, Arc<HashSet<String>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    reverse_import_index: OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
}

impl JavaMemoCaches {
    fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            resolved_imports: Self::build_cache(budget_bytes / 4, weight_import_map),
            referencing_files: Self::build_cache(budget_bytes / 8, weight_project_file_set),
            relevant_imports: Self::build_cache(budget_bytes / 8, weight_string_set),
            direct_ancestors: Self::build_cache(budget_bytes / 8, weight_code_unit_vec),
            direct_descendants: Self::build_cache(budget_bytes / 8, weight_code_unit_set),
            reverse_import_index: OnceLock::new(),
        }
    }

    fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    fn build_cache<K, V>(
        budget_bytes: u64,
        weigher: impl Fn(&K, &V) -> u32 + Send + Sync + 'static,
    ) -> Cache<K, V>
    where
        K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let capacity = budget_bytes.max(1);
        Cache::builder()
            .max_capacity(capacity)
            .weigher(weigher)
            .build()
    }
}

impl JavaAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, JavaAdapter, config);
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
        }
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner =
            TreeSitterAnalyzer::new_with_config_and_storage(project, JavaAdapter, config, storage);
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
        }
    }

    pub fn new_with_progress<F>(project: Arc<dyn Project>, progress: F) -> Self
    where
        F: Fn(usize, usize, &ProjectFile) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(project, AnalyzerConfig::default(), progress)
    }

    pub fn new_with_config_and_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        F: Fn(usize, usize, &ProjectFile) + Send + Sync + 'static,
    {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config_and_progress(
            project,
            JavaAdapter,
            config,
            progress,
        );
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn from_project_with_config<P>(project: P, config: AnalyzerConfig) -> Self
    where
        P: Project + 'static,
    {
        Self::new_with_config(Arc::new(project), config)
    }

    pub fn from_project_with_progress<P, F>(project: P, progress: F) -> Self
    where
        P: Project + 'static,
        F: Fn(usize, usize, &ProjectFile) + Send + Sync + 'static,
    {
        Self::new_with_progress(Arc::new(project), progress)
    }

    pub fn from_project_with_config_and_progress<P, F>(
        project: P,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        P: Project + 'static,
        F: Fn(usize, usize, &ProjectFile) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(Arc::new(project), config, progress)
    }

    pub fn inner(&self) -> &TreeSitterAnalyzer<JavaAdapter> {
        &self.inner
    }

    pub fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }

    pub fn is_anonymous_structure(&self, fq_name: &str) -> bool {
        is_java_anonymous_structure(fq_name)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let Some(tree) = parse_tree(source) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_type_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }

    pub fn resolve_type_name_in_file(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        self.resolve_type_name(file, raw_name)
    }

    pub fn package_name_of(&self, file: &ProjectFile) -> Option<&str> {
        self.inner.package_name_of(file)
    }
}

impl ImportAnalysisProvider for JavaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        self.resolve_imports(file).into_values().collect()
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = self.memo_caches.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        let target_identifiers: HashSet<String> = self
            .inner
            .top_level_declarations(file)
            .filter(|code_unit| code_unit.is_class() || code_unit.is_module())
            .map(|code_unit| code_unit.identifier().to_string())
            .collect();

        let target_package = self.inner.package_name_of(file).unwrap_or("");
        for candidate in self.inner.all_files() {
            if candidate == file || result.contains(candidate) {
                continue;
            }
            if self.inner.package_name_of(candidate).unwrap_or("") != target_package {
                continue;
            }

            if self
                .inner
                .type_identifiers_of(candidate)
                .is_some_and(|candidate_identifiers| {
                    candidate_identifiers
                        .iter()
                        .any(|identifier| target_identifiers.contains(identifier))
                })
            {
                result.insert(candidate.clone());
            }
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        if let Some(cached) = self.memo_caches.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }

        let Some(source) = self.get_source(code_unit, false) else {
            return HashSet::default();
        };

        let all_imports = self.import_info_of(code_unit.source());
        if all_imports.is_empty() {
            let empty = HashSet::default();
            self.memo_caches
                .relevant_imports
                .insert(code_unit.clone(), Arc::new(empty.clone()));
            return empty;
        }

        let type_identifiers = self.extract_type_identifiers(&source);
        if type_identifiers.is_empty() {
            let empty = HashSet::default();
            self.memo_caches
                .relevant_imports
                .insert(code_unit.clone(), Arc::new(empty.clone()));
            return empty;
        }

        let explicit_imports: Vec<_> = all_imports
            .iter()
            .filter(|import| !import.is_wildcard && import.identifier.is_some())
            .collect();
        let wildcard_imports: Vec<_> = all_imports
            .iter()
            .filter(|import| import.is_wildcard)
            .collect();

        let mut matched_imports = HashSet::default();
        let mut resolved_identifiers = HashSet::default();

        for import in explicit_imports {
            let Some(identifier) = import.identifier.as_deref() else {
                continue;
            };

            if type_identifiers.contains(identifier) {
                matched_imports.insert(import.raw_snippet.clone());
                resolved_identifiers.insert(identifier.to_string());
            }
        }

        let mut unresolved_identifiers: HashSet<String> = type_identifiers
            .into_iter()
            .filter(|identifier| !resolved_identifiers.contains(identifier))
            .collect();
        if unresolved_identifiers.is_empty() {
            self.memo_caches
                .relevant_imports
                .insert(code_unit.clone(), Arc::new(matched_imports.clone()));
            return matched_imports;
        }

        let import_packages: HashSet<String> = all_imports
            .iter()
            .map(|import| extract_package_from_import(&import.raw_snippet))
            .filter(|package| !package.is_empty())
            .collect();

        unresolved_identifiers.retain(|identifier| {
            if !identifier.contains('.') {
                return true;
            }

            import_packages
                .iter()
                .any(|package| identifier.starts_with(&format!("{package}.")))
        });
        if unresolved_identifiers.is_empty() {
            return matched_imports;
        }

        let mut resolved_via_wildcard = HashSet::default();
        for identifier in &unresolved_identifiers {
            for import in &wildcard_imports {
                let package = extract_package_from_import(&import.raw_snippet);
                if package.is_empty() {
                    continue;
                }

                let lookup_name = format!("{package}.{identifier}");
                if self
                    .definitions(&lookup_name)
                    .any(|code_unit| code_unit.is_class())
                {
                    matched_imports.insert(import.raw_snippet.clone());
                    resolved_via_wildcard.insert(identifier.clone());
                }
            }
        }

        let still_unresolved_simple = unresolved_identifiers.iter().any(|identifier| {
            !resolved_via_wildcard.contains(identifier) && !identifier.contains('.')
        });
        if still_unresolved_simple {
            for import in wildcard_imports {
                matched_imports.insert(import.raw_snippet.clone());
            }
        }

        self.memo_caches
            .relevant_imports
            .insert(code_unit.clone(), Arc::new(matched_imports.clone()));
        matched_imports
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if source_file == target {
            return false;
        }

        let source_package = self.inner.package_name_of(source_file).unwrap_or("");
        let target_package = self.inner.package_name_of(target).unwrap_or("");
        if source_package == target_package {
            return true;
        }

        self.could_import_file_without_source(imports, target)
    }
}

impl TestDetectionProvider for JavaAnalyzer {}

impl JavaAnalyzer {
    pub fn could_import_file_without_source(
        &self,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_package = self.inner.package_name_of(target).unwrap_or("");
        let mut target_name = target
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if let Some(stripped) = target_name.strip_suffix(".java") {
            target_name = stripped.to_string();
        }

        for import in imports {
            let raw = import
                .raw_snippet
                .trim()
                .strip_prefix("import ")
                .unwrap_or(import.raw_snippet.trim())
                .strip_suffix(';')
                .unwrap_or(import.raw_snippet.trim())
                .trim();

            if !import.is_wildcard {
                if import.identifier.as_deref() == Some(target_name.as_str()) {
                    return true;
                }
                if raw.contains(&format!(".{}.", target_name)) {
                    return true;
                }
                continue;
            }

            let import_package = raw.trim_end_matches(".*");
            if import_package == target_package
                || import_package == format!("{}.{}", target_package, target_name)
            {
                return true;
            }
        }

        false
    }

    fn resolve_imports(&self, file: &ProjectFile) -> HashMap<String, CodeUnit> {
        if let Some(cached) = self.memo_caches.resolved_imports.get(file) {
            return (*cached).clone();
        }

        let resolved = self.resolve_imports_uncached(file);
        self.memo_caches
            .resolved_imports
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn resolve_imports_uncached(&self, file: &ProjectFile) -> HashMap<String, CodeUnit> {
        let mut resolved = HashMap::default();

        for import in self.inner.import_info_of(file) {
            if import
                .raw_snippet
                .trim_start()
                .starts_with("import static ")
            {
                continue;
            }

            let import_path = import
                .raw_snippet
                .trim()
                .strip_prefix("import ")
                .unwrap_or(import.raw_snippet.trim())
                .strip_suffix(';')
                .unwrap_or(import.raw_snippet.trim())
                .trim();

            if !import.is_wildcard {
                if let Some(code_unit) = self
                    .inner
                    .definitions(import_path)
                    .find(|code_unit| code_unit.is_class())
                    .cloned()
                {
                    resolved.insert(code_unit.identifier().to_string(), code_unit);
                }
                continue;
            }

            let package_name = import_path.trim_end_matches(".*");
            for code_unit in self.inner.class_declarations_in_package(package_name) {
                resolved
                    .entry(code_unit.identifier().to_string())
                    .or_insert(code_unit.clone());
            }
        }

        resolved
    }

    fn resolve_type_name(&self, file: &ProjectFile, raw_name: &str) -> Option<CodeUnit> {
        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }

        if normalized.contains('.')
            && let Some(code_unit) = self
                .inner
                .definitions(normalized)
                .find(|code_unit| code_unit.is_class())
                .cloned()
        {
            return Some(code_unit);
        }

        let imports = self.resolve_imports(file);
        if let Some(code_unit) = imports.get(normalized) {
            return Some(code_unit.clone());
        }

        let package_name = self.inner.package_name_of(file).unwrap_or("");
        let same_package_fqn = if package_name.is_empty() {
            normalized.to_string()
        } else {
            format!("{}.{}", package_name, normalized)
        };
        if let Some(code_unit) = self
            .inner
            .definitions(&same_package_fqn)
            .find(|code_unit| code_unit.is_class())
            .cloned()
        {
            return Some(code_unit);
        }

        self.inner
            .definitions(normalized)
            .find(|code_unit| code_unit.is_class())
            .cloned()
    }
}

fn determine_package_name(root: Node<'_>, source: &str) -> String {
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };

        if child.kind() == "package_declaration" {
            return node_text(child, source)
                .trim()
                .strip_prefix("package ")
                .unwrap_or("")
                .strip_suffix(';')
                .unwrap_or("")
                .trim()
                .to_string();
        }

        if matches!(
            child.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) {
            break;
        }
    }

    String::new()
}

fn parse_import_info(raw: String) -> ImportInfo {
    let trimmed = raw
        .trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .strip_suffix(';')
        .unwrap_or(raw.trim())
        .trim();
    let trimmed = trimmed.strip_prefix("static ").unwrap_or(trimmed).trim();
    let is_wildcard = trimmed.ends_with(".*");
    let identifier = (!is_wildcard)
        .then(|| trimmed.rsplit('.').next().map(str::to_string))
        .flatten();

    ImportInfo {
        raw_snippet: raw,
        is_wildcard,
        identifier,
        alias: None,
    }
}

fn extract_package_from_import(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .strip_suffix(';')
        .unwrap_or(raw.trim())
        .trim();
    let trimmed = trimmed.strip_prefix("static ").unwrap_or(trimmed).trim();

    if let Some(package) = trimmed.strip_suffix(".*") {
        return package.trim().to_string();
    }

    trimmed
        .rsplit_once('.')
        .map(|(package, _)| package.trim().to_string())
        .unwrap_or_default()
}

fn strip_generic_type_arguments(input: &str) -> String {
    let mut depth = 0usize;
    let mut out = String::with_capacity(input.len());

    for ch in input.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }

    out
}

fn normalize_java_full_name(fq_name: &str) -> String {
    let mut normalized = strip_generic_type_arguments(fq_name);

    if normalized.contains("$anon$") {
        let mut out = String::with_capacity(normalized.len());
        let mut chars = normalized.char_indices();

        while let Some((index, ch)) = chars.next() {
            if normalized[index..].starts_with("$anon$") {
                out.push_str("$anon$");
                for _ in 0.."anon$".len() {
                    chars.next();
                }
                continue;
            }

            out.push(if ch == '$' { '.' } else { ch });
        }

        return out;
    }

    normalized = strip_trailing_numeric_suffix(&normalized);
    normalized = strip_location_suffix(&normalized);
    normalized.replace('$', ".")
}

fn strip_trailing_numeric_suffix(input: &str) -> String {
    let colon_split = input.rsplit_once(':');
    let candidate = colon_split.map(|(head, _)| head).unwrap_or(input);
    let Some((prefix, suffix)) = candidate.rsplit_once('$') else {
        return input.to_string();
    };

    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return input.to_string();
    }

    if let Some((_, location)) = colon_split {
        format!("{prefix}:{location}")
    } else {
        prefix.to_string()
    }
}

fn strip_location_suffix(input: &str) -> String {
    let Some((head, tail)) = input.rsplit_once(':') else {
        return input.to_string();
    };
    if !tail.bytes().all(|byte| byte.is_ascii_digit()) {
        return input.to_string();
    }

    if let Some((grand_head, middle)) = head.rsplit_once(':')
        && middle.bytes().all(|byte| byte.is_ascii_digit())
    {
        return grand_head.to_string();
    }

    head.to_string()
}

fn extract_java_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    if trimmed.is_empty() || !trimmed.is_ascii() {
        return None;
    }

    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed)
        .trim();
    let (receiver, method_name) = before_args.rsplit_once('.')?;
    if receiver.is_empty() || method_name.is_empty() || receiver.contains('$') {
        return None;
    }

    if !looks_like_java_method_name(method_name) {
        return None;
    }

    let segments: Vec<_> = receiver.split('.').collect();
    let last = *segments.last()?;
    if !looks_like_pascal_identifier(last) {
        return None;
    }

    for segment in &segments {
        if segment.is_empty()
            || !segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return None;
        }

        let first = segment.as_bytes()[0] as char;
        if !first.is_ascii_lowercase() && !first.is_ascii_uppercase() {
            return None;
        }
    }

    Some(receiver.to_string())
}

fn looks_like_java_method_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_lowercase() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn looks_like_pascal_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_uppercase() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_java_anonymous_structure(fq_name: &str) -> bool {
    fq_name.contains("$anon$")
        || fq_name
            .rsplit_once('$')
            .map(|(_, suffix)| suffix.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false)
}

fn collect_type_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    match node.kind() {
        "type_identifier" | "scoped_type_identifier" => {
            let text = node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_type_identifiers(child, source, identifiers);
    }
}

fn visit_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: Option<&CodeUnit>,
    top_level_owner: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;

    let simple_name = node_text(name_node, source).trim().to_string();
    if simple_name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), simple_name))
        .unwrap_or(simple_name.clone());

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        short_name,
    );
    let raw_supertypes = extract_raw_supertypes(node, source);
    let signature = class_signature(node, source);

    let top_level = top_level_owner
        .cloned()
        .unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.set_raw_supertypes(code_unit.clone(), raw_supertypes);
    parsed.add_signature(code_unit.clone(), signature);

    if node.kind() == "record_declaration" {
        visit_record_components(
            file,
            source,
            node,
            package_name,
            &code_unit,
            &top_level,
            parsed,
        );
    }

    let mut has_explicit_constructor = false;
    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };

            match child.kind() {
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => {
                    visit_class_like(
                        file,
                        source,
                        child,
                        package_name,
                        Some(&code_unit),
                        Some(&top_level),
                        parsed,
                    );
                }
                "method_declaration" | "constructor_declaration" => {
                    if child.kind() == "constructor_declaration" {
                        has_explicit_constructor = true;
                    }
                    visit_callable(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                    );
                }
                "field_declaration" | "constant_declaration" => {
                    visit_field_declaration(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                    );
                }
                "enum_constant" => {
                    visit_enum_constant(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                    );
                }
                _ => {}
            }
        }
    }

    if should_create_implicit_constructor(node.kind(), has_explicit_constructor) {
        let ctor = CodeUnit::with_signature(
            file.clone(),
            crate::analyzer::CodeUnitType::Function,
            package_name.to_string(),
            format!("{}.{}", code_unit.short_name(), simple_name),
            None,
            true,
        );
        parsed.declarations.insert(ctor.clone());
        parsed.add_child(code_unit.clone(), ctor);
    }

    Some(code_unit)
}

fn visit_callable(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| canonical_parameters_signature(parameters, source));
    let short_name = format!("{}.{}", parent.short_name(), name);
    let callable_sig = callable_signature(node, source);
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature.clone(),
        false,
    );

    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit.clone(), callable_sig);

    if let Some(body) = node.child_by_field_name("body") {
        collect_lambda_expressions(
            file,
            source,
            body,
            package_name,
            &code_unit,
            top_level,
            parsed,
        );
    }
}

fn visit_field_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        parsed.add_code_unit(
            code_unit.clone(),
            node,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, field_signature(node, child, source));

        if let Some(value) = child.child_by_field_name("value") {
            collect_lambda_expressions(
                file,
                source,
                value,
                package_name,
                parent,
                top_level,
                parsed,
            );
        }
    }
}

fn visit_record_components(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };

    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "formal_parameter" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, normalize_whitespace(node_text(child, source)));
    }
}

fn visit_enum_constant(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        format!("{}.{}", parent.short_name(), name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, enum_constant_signature(node, source));
}

fn collect_lambda_expressions(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    if node.kind() == "lambda_expression" {
        let lambda = lambda_code_unit(file, package_name, parent, node);
        parsed.add_code_unit(
            lambda.clone(),
            node,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_lambda_expressions(
                file,
                source,
                child,
                package_name,
                &lambda,
                top_level,
                parsed,
            );
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_lambda_expressions(file, source, child, package_name, parent, top_level, parsed);
    }
}

fn lambda_code_unit(
    file: &ProjectFile,
    package_name: &str,
    parent: &CodeUnit,
    node: Node<'_>,
) -> CodeUnit {
    let line = node.start_position().row;
    let column = node.start_position().column;
    let short_name = if parent.is_function() {
        format!("{}$anon${line}:{column}", parent.short_name())
    } else {
        format!(
            "{}.{}$anon${line}:{column}",
            parent.short_name(),
            parent.identifier()
        )
    };
    CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        None,
        true,
    )
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("failed to load java parser");
    parser.parse(source, None)
}

fn is_comment_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "line_comment" | "block_comment")
}

fn is_declaration_parent(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "field_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "variable_declarator"
            | "formal_parameter"
            | "catch_formal_parameter"
            | "enhanced_for_statement"
            | "resource"
    )
}

fn find_nearest_declaration_from_node(
    start_node: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let mut current = Some(start_node);

    while let Some(node) = current {
        match node.kind() {
            "method_declaration" | "constructor_declaration" => {
                if let Some(found) = check_formal_parameters(node, identifier, source) {
                    return Some(found);
                }
            }
            "enhanced_for_statement" => {
                if let Some(found) = match_named_field(
                    node,
                    "name",
                    identifier,
                    source,
                    DeclarationKind::EnhancedForVariable,
                ) {
                    return Some(found);
                }
            }
            "catch_clause" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "catch_formal_parameter"
                        && let Some(found) = match_named_field(
                            child,
                            "name",
                            identifier,
                            source,
                            DeclarationKind::CatchParameter,
                        )
                    {
                        return Some(found);
                    }
                }
            }
            "try_with_resources_statement" => {
                if let Some(resources) = node.child_by_field_name("resources") {
                    let mut cursor = resources.walk();
                    for child in resources.named_children(&mut cursor) {
                        if child.kind() == "resource"
                            && let Some(found) = match_named_field(
                                child,
                                "name",
                                identifier,
                                source,
                                DeclarationKind::ResourceVariable,
                            )
                        {
                            return Some(found);
                        }
                    }
                }
            }
            "lambda_expression" => {
                if let Some(parameters) = node.child_by_field_name("parameters") {
                    if parameters.kind() == "identifier" {
                        if node_text(parameters, source).trim() == identifier {
                            return Some(declaration_info(
                                identifier,
                                DeclarationKind::LambdaParameter,
                                parameters,
                            ));
                        }
                    } else {
                        let mut cursor = parameters.walk();
                        for child in parameters.named_children(&mut cursor) {
                            if child.kind() == "identifier"
                                && node_text(child, source).trim() == identifier
                            {
                                return Some(declaration_info(
                                    identifier,
                                    DeclarationKind::LambdaParameter,
                                    child,
                                ));
                            }
                            if child.kind() == "formal_parameter"
                                && let Some(found) = match_named_field(
                                    child,
                                    "name",
                                    identifier,
                                    source,
                                    DeclarationKind::LambdaParameter,
                                )
                            {
                                return Some(found);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(found) = check_preceding_local_variables(node, identifier, source) {
            return Some(found);
        }

        current = node.parent();
    }

    None
}

fn check_formal_parameters(
    node: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let params = node.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        if child.kind() == "formal_parameter"
            && let Some(found) = match_named_field(
                child,
                "name",
                identifier,
                source,
                DeclarationKind::Parameter,
            )
        {
            return Some(found);
        }
    }
    None
}

fn check_preceding_local_variables(
    current: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let parent = current.parent()?;
    let mut cursor = parent.walk();
    for sibling in parent.named_children(&mut cursor) {
        if sibling.end_byte() > current.start_byte() {
            break;
        }
        if sibling.kind() != "local_variable_declaration" {
            continue;
        }
        let mut local_cursor = sibling.walk();
        for child in sibling.named_children(&mut local_cursor) {
            if child.kind() == "variable_declarator"
                && let Some(found) = match_named_field(
                    child,
                    "name",
                    identifier,
                    source,
                    DeclarationKind::LocalVariable,
                )
            {
                return Some(found);
            }
        }
    }
    None
}

fn match_named_field(
    node: Node<'_>,
    field_name: &str,
    identifier: &str,
    source: &str,
    kind: DeclarationKind,
) -> Option<DeclarationInfo> {
    let name_node = node.child_by_field_name(field_name)?;
    if node_text(name_node, source).trim() == identifier {
        Some(declaration_info(identifier, kind, name_node))
    } else {
        None
    }
}

fn declaration_info(identifier: &str, kind: DeclarationKind, node: Node<'_>) -> DeclarationInfo {
    DeclarationInfo {
        identifier: identifier.to_string(),
        kind,
        range: crate::analyzer::Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        },
    }
}

fn class_signature(node: Node<'_>, source: &str) -> String {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let header = source
        .get(node.start_byte()..body_start)
        .unwrap_or("")
        .trim_end();
    format!("{} {{", normalize_whitespace(header))
}

fn callable_signature(node: Node<'_>, source: &str) -> String {
    let end = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    normalize_whitespace(source.get(node.start_byte()..end).unwrap_or("").trim_end())
}

fn canonical_parameters_signature(parameters: Node<'_>, source: &str) -> String {
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    let mut ty = normalize_whitespace(node_text(type_node, source));
                    if let Some(dimensions) = child.child_by_field_name("dimensions") {
                        ty.push_str(node_text(dimensions, source).trim());
                    }
                    parts.push(ty);
                }
            }
            "spread_parameter" => {
                let mut spread_cursor = child.walk();
                for grandchild in child.named_children(&mut spread_cursor) {
                    if grandchild.kind() == "variable_declarator" {
                        continue;
                    }
                    if grandchild.kind() == "modifiers"
                        || grandchild.kind() == "annotation"
                        || grandchild.kind() == "marker_annotation"
                    {
                        continue;
                    }
                    parts.push(format!(
                        "{}[]",
                        normalize_whitespace(node_text(grandchild, source))
                    ));
                    break;
                }
            }
            "receiver_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    parts.push(normalize_whitespace(node_text(type_node, source)));
                }
            }
            _ => {}
        }
    }

    format!("({})", parts.join(", "))
}

fn field_signature(field_node: Node<'_>, declarator: Node<'_>, source: &str) -> String {
    let Some(type_node) = field_node.child_by_field_name("type") else {
        return normalize_whitespace(node_text(field_node, source));
    };
    let Some(name_node) = declarator.child_by_field_name("name") else {
        return normalize_whitespace(node_text(field_node, source));
    };

    let prefix = normalize_whitespace(
        source
            .get(field_node.start_byte()..type_node.start_byte())
            .unwrap_or(""),
    );
    let type_text = normalize_whitespace(node_text(type_node, source));
    let name_text = node_text(name_node, source).trim();

    let mut signature = String::new();
    for part in [prefix.as_str(), type_text.as_str(), name_text] {
        if part.is_empty() {
            continue;
        }
        if !signature.is_empty() {
            signature.push(' ');
        }
        signature.push_str(part);
    }

    let suffix = declarator
        .child_by_field_name("value")
        .and_then(|value| literal_field_initializer(value, source))
        .map(|value| format!(" = {value};"))
        .unwrap_or_else(|| ";".to_string());
    signature.push_str(&suffix);
    signature
}

fn literal_field_initializer<'a>(value: Node<'_>, source: &'a str) -> Option<&'a str> {
    let kind = value.kind();
    if kind.ends_with("_literal") || matches!(kind, "true" | "false" | "null_literal" | "null") {
        Some(node_text(value, source).trim())
    } else {
        None
    }
}

fn enum_constant_signature(node: Node<'_>, source: &str) -> String {
    let mut text = node_text(node, source).trim().to_string();
    if node.next_named_sibling().is_some() {
        text.push(',');
    }
    text
}

fn module_code_unit(file: &ProjectFile, package_name: &str) -> CodeUnit {
    match package_name.rsplit_once('.') {
        Some((parent, leaf)) => CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Module,
            parent.to_string(),
            leaf.to_string(),
        ),
        None => CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Module,
            String::new(),
            package_name.to_string(),
        ),
    }
}

fn should_create_implicit_constructor(node_kind: &str, has_explicit_constructor: bool) -> bool {
    node_kind == "class_declaration" && !has_explicit_constructor
}

fn extract_raw_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();

    if let Some(superclass) = node.child_by_field_name("superclass") {
        collect_supertype_nodes(superclass, source, &mut raw);
    }
    if let Some(interfaces) = node.child_by_field_name("interfaces") {
        collect_supertype_nodes(interfaces, source, &mut raw);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "extends_interfaces" {
            collect_supertype_nodes(child, source, &mut raw);
        }
    }

    raw
}

fn collect_supertype_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    match node.kind() {
        "type_identifier" | "scoped_type_identifier" => {
            let text = node_text(node, source).trim();
            if !text.is_empty() {
                raw.push(text.to_string());
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_supertype_nodes(child, source, raw);
    }
}

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw_name| self.resolve_type_name(code_unit.source(), raw_name))
            .collect();
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = direct_descendants_via_ancestors(self, self, code_unit);
        self.memo_caches
            .direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}

impl IAnalyzer for JavaAnalyzer {
    fn top_level_declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.top_level_declarations(file)
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        self.inner.analyzed_files()
    }

    fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.all_declarations()
    }

    fn declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.declarations(file)
    }

    fn definitions<'a>(&'a self, fq_name: &'a str) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.definitions(fq_name)
    }

    fn direct_children<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String] {
        self.inner.import_statements(file)
    }

    fn ranges<'a>(&'a self, code_unit: &CodeUnit) -> &'a [crate::analyzer::Range] {
        self.inner.ranges(code_unit)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.inner.signatures(code_unit)
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.get_top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: self.inner.update(_changed_files),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.get_declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.get_direct_children(code_unit)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements_of(file)
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
        let Ok(source) = self.inner.project().read_source(file) else {
            return true;
        };
        let Some(tree) = parse_tree(&source) else {
            return true;
        };
        let root = tree.root_node();
        let Some(node) = root.named_descendant_for_byte_range(start_byte, end_byte) else {
            return true;
        };

        let mut walk = Some(node);
        while let Some(current) = walk {
            if is_comment_node(current) {
                return false;
            }
            walk = current.parent();
        }

        let mut current = Some(node);
        while let Some(candidate) = current {
            if let Some(parent) = candidate.parent()
                && is_declaration_parent(parent.kind())
                && let Some(name_node) = parent.child_by_field_name("name")
                && name_node.start_byte() == start_byte
            {
                return false;
            }
            current = candidate.parent();
        }

        if let Some(parent) = node.parent() {
            if parent.kind() == "field_access"
                && let Some(field_node) = parent.child_by_field_name("field")
                && field_node.start_byte() == node.start_byte()
            {
                return true;
            }
            if parent.kind() == "method_invocation"
                && let Some(name_node) = parent.child_by_field_name("name")
                && name_node.start_byte() == node.start_byte()
            {
                return true;
            }
        }

        let identifier = node_text(node, &source).trim().to_string();
        if identifier.is_empty() {
            return true;
        }

        match find_nearest_declaration_from_node(node, &identifier, &source) {
            Some(info) => !matches!(
                info.kind,
                DeclarationKind::Parameter
                    | DeclarationKind::LocalVariable
                    | DeclarationKind::CatchParameter
                    | DeclarationKind::EnhancedForVariable
                    | DeclarationKind::ResourceVariable
                    | DeclarationKind::PatternVariable
                    | DeclarationKind::LambdaParameter
            ),
            None => true,
        }
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        let Ok(source) = self.inner.project().read_source(file) else {
            return None;
        };
        let tree = parse_tree(&source)?;
        let root = tree.root_node();
        let node = root.named_descendant_for_byte_range(start_byte, end_byte)?;
        find_nearest_declaration_from_node(node, ident, &source)
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges_of(code_unit)
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

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        // Forward to the inner `TreeSitterAnalyzer`; otherwise the default
        // impl on `IAnalyzer` re-dispatches to `self.search_definitions`,
        // skipping the FTS5 path entirely.
        self.inner.search_definitions_persisted(pattern)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        if file_language(code_unit.source()) != Language::Java {
            return None;
        }
        let source = self.inner.project().read_source(code_unit.source()).ok()?;
        let aggs = collect_java_comment_aggregates(self, code_unit.source(), &source);
        Some(build_java_roll_up_stats(self, code_unit, &aggs))
    }

    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        if file_language(file) != Language::Java {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        let aggs = collect_java_comment_aggregates(self, file, &source);
        // Bifrost emits a top-level Module per Java package declaration; brokk's
        // Java analyzer does not. Skip module-kind tops so this method returns
        // the same set of stats rows as brokk-shared `JavaAnalyzer.commentDensityByTopLevel`.
        self.get_top_level_declarations(file)
            .iter()
            .filter(|cu| !cu.is_module() && !cu.is_synthetic())
            .map(|top| build_java_roll_up_stats(self, top, &aggs))
            .collect()
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> Vec<ExceptionHandlingSmell> {
        if file_language(file) != Language::Java {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_exception_handling_smells_java(self, file, &source, &weights)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if file_language(file) != Language::Java || !self.contains_tests(file) {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_test_assertion_smells_java(self, file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Java)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Java
            })
            .filter_map(|code_unit| self.build_clone_candidate_data(&code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_java_clone_similarity,
        )
    }
}

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

impl JavaAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens = normalized_clone_tokens_java(&source);
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_java_clone_ast_signature(&source),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}

fn normalized_clone_tokens_java(source: &str) -> Vec<String> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let content = SourceContent::new(source);
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_java(tree.root_node(), &content, &mut out);
    out
}

fn collect_normalized_leaf_tokens_java(
    node: Node<'_>,
    source_content: &SourceContent,
    out: &mut Vec<String>,
) {
    if node.named_child_count() == 0 {
        let token = normalize_java_clone_leaf_token(node, source_content);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_java(child, source_content, out);
        }
    }
}

fn normalize_java_clone_leaf_token(node: Node<'_>, source_content: &SourceContent) -> String {
    let kind = node.kind();
    let token = source_content
        .as_str()
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        return String::new();
    }
    if CLONE_AST_IDENTIFIER_TYPES.contains(kind) {
        return "ID".to_string();
    }
    if CLONE_AST_STRING_TYPES.contains(kind) {
        return "STR".to_string();
    }
    if CLONE_AST_NUMBER_TYPES.contains(kind) {
        return "NUM".to_string();
    }
    if token == "true" || token == "false" {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

fn build_java_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_tree(source) else {
        return String::new();
    };
    let content = SourceContent::new(source);
    let mut labels = Vec::new();
    collect_java_clone_ast_labels(tree.root_node(), &content, &mut labels);
    labels.join("|")
}

fn collect_java_clone_ast_labels(
    node: Node<'_>,
    source_content: &SourceContent,
    out: &mut Vec<String>,
) {
    out.push(normalize_java_clone_ast_label(node, source_content));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_java_clone_ast_labels(child, source_content, out);
        }
    }
}

fn normalize_java_clone_ast_label(node: Node<'_>, source_content: &SourceContent) -> String {
    let kind = node.kind();
    let text = source_content
        .as_str()
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if CLONE_AST_IDENTIFIER_TYPES.contains(kind) {
        return "ID".to_string();
    }
    if CLONE_AST_STRING_TYPES.contains(kind) {
        return "STR".to_string();
    }
    if CLONE_AST_NUMBER_TYPES.contains(kind) {
        return "NUM".to_string();
    }
    if kind == "boolean_literal" || text == "true" || text == "false" {
        return "BOOL".to_string();
    }
    if CLONE_AST_IGNORED_TYPES.contains(kind) {
        return "IGN".to_string();
    }
    format!("N:{kind}")
}

fn refine_java_clone_similarity(
    left: &CloneCandidateData,
    right: &CloneCandidateData,
    token_similarity: i32,
    weights: CloneSmellWeights,
) -> i32 {
    if left.ast_signature.is_empty() || right.ast_signature.is_empty() {
        return token_similarity;
    }
    let ast_similarity =
        compute_ast_refinement_similarity_percent(&left.ast_signature, &right.ast_signature);
    if ast_similarity == 0 {
        return token_similarity;
    }
    if ast_similarity < weights.ast_similarity_percent {
        return 0;
    }
    token_similarity.min(ast_similarity)
}

/// Collect per-declaration header/inline comment line counts for a Java file.
/// Walks the parse tree for `line_comment` and `block_comment` nodes, assigns
/// each to the deepest enclosing declaration whose range — expanded to include
/// any leading comment block — contains the comment, then classifies as header
/// (ends on or before the declaration start) or inline. Mirrors brokk-shared
/// `JavaAnalyzer.collectCommentAggregates` byte-for-byte.
fn collect_java_comment_aggregates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> HashMap<String, (u32, u32)> {
    let mut aggs: HashMap<String, (u32, u32)> = HashMap::default();
    let Some(tree) = parse_tree(source) else {
        return aggs;
    };
    let mut comments: Vec<Node<'_>> = Vec::new();
    collect_comment_nodes(tree.root_node(), &mut comments);

    for comment in comments {
        let cs = comment.start_byte();
        let ce = comment.end_byte();
        let Some(cu) = enclosing_code_unit_by_comment_bytes(analyzer, source, file, cs, ce) else {
            continue;
        };
        let ranges = analyzer.ranges_of(&cu);
        let Some(range) = ranges
            .iter()
            .filter(|r| {
                let cstart = expanded_comment_start(source, r.start_byte);
                cs >= cstart && ce <= r.end_byte
            })
            .min_by_key(|r| {
                let cstart = expanded_comment_start(source, r.start_byte);
                r.end_byte.saturating_sub(cstart)
            })
            .copied()
        else {
            continue;
        };
        let header = ce <= range.start_byte;
        let sr = comment.start_position().row;
        let er = comment.end_position().row;
        let lines = (er.saturating_sub(sr) + 1) as u32;
        let entry = aggs.entry(cu.fq_name()).or_default();
        if header {
            entry.0 += lines;
        } else {
            entry.1 += lines;
        }
    }

    aggs
}

fn collect_comment_nodes<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if is_comment_node(node) {
        out.push(node);
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_comment_nodes(child, out);
        }
    }
}

fn enclosing_code_unit_by_comment_bytes(
    analyzer: &dyn IAnalyzer,
    source: &str,
    file: &ProjectFile,
    cs: usize,
    ce: usize,
) -> Option<CodeUnit> {
    if cs > ce {
        return None;
    }
    let mut best: Option<(CodeUnit, usize)> = None;
    for top in analyzer.get_top_level_declarations(file) {
        if let Some(cand) =
            find_deepest_enclosing_by_comment_bytes(analyzer, source, &top, cs, ce, 0)
            && best.as_ref().map(|b| cand.1 > b.1).unwrap_or(true)
        {
            best = Some(cand);
        }
    }
    best.map(|(cu, _)| cu)
}

fn find_deepest_enclosing_by_comment_bytes(
    analyzer: &dyn IAnalyzer,
    source: &str,
    cu: &CodeUnit,
    cs: usize,
    ce: usize,
    depth: usize,
) -> Option<(CodeUnit, usize)> {
    let ranges = analyzer.ranges_of(cu);
    let contains = ranges.iter().any(|r| {
        let cstart = expanded_comment_start(source, r.start_byte);
        cs >= cstart && ce <= r.end_byte
    });
    if !contains {
        return None;
    }
    let mut best: (CodeUnit, usize) = (cu.clone(), depth);
    for child in analyzer.get_direct_children(cu) {
        if let Some(cand) =
            find_deepest_enclosing_by_comment_bytes(analyzer, source, &child, cs, ce, depth + 1)
            && cand.1 > best.1
        {
            best = cand;
        }
    }
    Some(best)
}

/// Build a [`CommentDensityStats`] entry for `cu`, rolling up nested
/// declarations (class-like units only). Mirrors brokk-shared
/// `JavaAnalyzer.buildRollUpStats`.
fn build_java_roll_up_stats(
    analyzer: &dyn IAnalyzer,
    cu: &CodeUnit,
    aggs: &HashMap<String, (u32, u32)>,
) -> CommentDensityStats {
    let own = aggs.get(&cu.fq_name()).copied().unwrap_or((0, 0));
    let span: u32 = analyzer
        .ranges_of(cu)
        .iter()
        .map(|r| (r.end_line.saturating_sub(r.start_line) + 1) as u32)
        .sum();
    let relative_path = rel_path_string(cu.source());
    if !cu.is_class() {
        return CommentDensityStats {
            fq_name: cu.fq_name(),
            relative_path,
            header_comment_lines: own.0,
            inline_comment_lines: own.1,
            span_lines: span,
            rolled_up_header_comment_lines: own.0,
            rolled_up_inline_comment_lines: own.1,
            rolled_up_span_lines: span,
        };
    }
    let mut rh = own.0;
    let mut ri = own.1;
    let mut rs = span;
    for child in analyzer.get_direct_children(cu) {
        let chs = build_java_roll_up_stats(analyzer, &child, aggs);
        rh += chs.rolled_up_header_comment_lines;
        ri += chs.rolled_up_inline_comment_lines;
        rs += chs.rolled_up_span_lines;
    }
    CommentDensityStats {
        fq_name: cu.fq_name(),
        relative_path,
        header_comment_lines: own.0,
        inline_comment_lines: own.1,
        span_lines: span,
        rolled_up_header_comment_lines: rh,
        rolled_up_inline_comment_lines: ri,
        rolled_up_span_lines: rs,
    }
}

// Tree-sitter Java node kinds referenced by the exception-handling
// heuristic. Kept as a private const list so the port stays explicit; do
// not collapse with `is_declaration_parent` — these are *statement* kinds.
const CATCH_BODY_MEANINGFUL_STATEMENT_TYPES: &[&str] = &[
    "expression_statement",
    "throw_statement",
    "return_statement",
    "break_statement",
    "continue_statement",
    "if_statement",
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "switch_expression",
    "try_statement",
    "try_with_resources_statement",
];

const JAVA_COMMENT_NODE_TYPES: &[&str] = &["line_comment", "block_comment"];

const LOG_RECEIVER_NAMES: &[&str] = &["log", "logger"];

const EXCEPTION_EXCERPT_MAX_LEN: usize = 180;
const TEST_ASSERTION_EXCERPT_MAX_LEN: usize = 180;

const TEST_ANNOTATIONS: &[&str] = &[
    "Test",
    "ParameterizedTest",
    "RepeatedTest",
    "TestFactory",
    "TestTemplate",
];
const JUNIT_ASSERTION_NAMES: &[&str] = &[
    "assertArrayEquals",
    "assertDoesNotThrow",
    "assertEquals",
    "assertFalse",
    "assertInstanceOf",
    "assertIterableEquals",
    "assertLinesMatch",
    "assertNotEquals",
    "assertNotNull",
    "assertNotSame",
    "assertNull",
    "assertSame",
    "assertThrows",
    "assertThrowsExactly",
    "assertTimeout",
    "assertTimeoutPreemptively",
    "assertTrue",
    "fail",
];
const SHALLOW_ASSERTION_NAMES: &[&str] = &["assertNotNull", "assertNull", "assertInstanceOf"];
const ASSERTJ_TERMINAL_NAMES: &[&str] = &[
    "isEqualTo",
    "isSameAs",
    "isNotEqualTo",
    "isTrue",
    "isFalse",
    "isNull",
    "isNotNull",
    "isInstanceOf",
    "hasMessage",
    "hasMessageContaining",
    "containsExactly",
    "containsExactlyInAnyOrder",
];
const ASSERTJ_SHALLOW_TERMINAL_NAMES: &[&str] = &["isNull", "isNotNull", "isInstanceOf"];
const MOCKITO_VERIFY_NAMES: &[&str] = &[
    "verify",
    "verifyNoInteractions",
    "verifyNoMoreInteractions",
    "verifyZeroInteractions",
    "inOrder",
];
const CONSTANT_LITERAL_TYPES: &[&str] = &[
    "string_literal",
    "character_literal",
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "decimal_floating_point_literal",
    "hex_floating_point_literal",
    "true",
    "false",
    "null_literal",
];

const TEST_ASSERTION_KIND_JUNIT: &str = "junit-assertion";
const TEST_ASSERTION_KIND_ASSERTJ: &str = "assertj-assertion";
const TEST_ASSERTION_KIND_MOCK_VERIFICATION: &str = "mock-verification";
const TEST_ASSERTION_KIND_NO_ASSERTIONS: &str = "no-assertions";
const TEST_ASSERTION_KIND_CONSTANT_TRUTH: &str = "constant-truth";
const TEST_ASSERTION_KIND_CONSTANT_EQUALITY: &str = "constant-equality";
const TEST_ASSERTION_KIND_SELF_COMPARISON: &str = "self-comparison";
const TEST_ASSERTION_KIND_NULLNESS_ONLY: &str = "nullness-only";
const TEST_ASSERTION_KIND_SHALLOW_ONLY: &str = "shallow-assertions-only";
const TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL: &str = "overspecified-literal";
const TEST_ASSERTION_KIND_ANONYMOUS_TEST_DOUBLE: &str = "anonymous-test-double";
const TEST_ASSERTION_REASON_REUSABLE_TEST_DOUBLE: &str = "reusable-test-double-candidate";

fn detect_exception_handling_smells_java(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    weights: &ExceptionSmellWeights,
) -> Vec<ExceptionHandlingSmell> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let mut catches: Vec<Node<'_>> = Vec::new();
    collect_catch_clauses(tree.root_node(), &mut catches);

    let mut findings: Vec<ExceptionHandlingSmell> = catches
        .into_iter()
        .filter_map(|catch_node| analyze_catch_clause(analyzer, file, source, catch_node, weights))
        .collect();

    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
            .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
            .then_with(|| a.start_byte.cmp(&b.start_byte))
    });
    findings
}

fn collect_catch_clauses<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() == "catch_clause" {
        out.push(node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_catch_clauses(child, out);
        }
    }
}

fn analyze_catch_clause(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    catch_node: Node<'_>,
    weights: &ExceptionSmellWeights,
) -> Option<ExceptionHandlingSmell> {
    let catch_param = named_child_by_kind(catch_node, "catch_formal_parameter")?;
    let catch_type = extract_catch_type(catch_param, source)?;
    let body_node = catch_node
        .child_by_field_name("body")
        .or_else(|| named_child_by_kind(catch_node, "block"))?;

    let body_statements = count_body_meaningful_statements(body_node);
    let has_any_comment = has_descendant_of_any_kind_inclusive(body_node, JAVA_COMMENT_NODE_TYPES);
    let empty_body = body_statements == 0 && !has_any_comment;
    let comment_only_body = body_statements == 0 && has_any_comment;
    let small_body = (body_statements as i32) <= weights.small_body_max_statements.max(0);
    let throw_present = has_descendant_of_kind(body_node, "throw_statement");
    let log_only =
        body_statements == 1 && !throw_present && is_likely_log_only_body(body_node, source);

    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();
    if catch_type.contains("Throwable") {
        score += weights.generic_throwable_weight;
        reasons.push("generic-catch:Throwable".to_string());
    } else if catch_type.contains("Exception") {
        if catch_type.contains("RuntimeException") {
            score += weights.generic_runtime_exception_weight;
            reasons.push("generic-catch:RuntimeException".to_string());
        } else {
            score += weights.generic_exception_weight;
            reasons.push("generic-catch:Exception".to_string());
        }
    }
    if empty_body {
        score += weights.empty_body_weight;
        reasons.push("empty-body".to_string());
    }
    if comment_only_body {
        score += weights.comment_only_body_weight;
        reasons.push("comment-only-body".to_string());
    }
    if small_body {
        score += weights.small_body_weight;
        reasons.push(format!("small-body:{body_statements}"));
    }
    if log_only {
        score += weights.log_only_weight;
        reasons.push("log-only-body".to_string());
    }

    let threshold = weights.meaningful_body_statement_threshold.max(0) as u32;
    let credit_per = weights.meaningful_body_credit_per_statement.max(0);
    let credit_statements = body_statements.min(threshold);
    let body_credit = credit_per.saturating_mul(credit_statements as i32);
    if body_credit > 0 {
        score -= body_credit;
        reasons.push(format!("meaningful-body-credit:{body_credit}"));
    }

    if score <= 0 {
        return None;
    }

    let enclosing = analyzer
        .enclosing_code_unit_for_lines(
            file,
            catch_node.start_position().row,
            catch_node.end_position().row,
        )
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    let excerpt = compact_catch_excerpt(
        source
            .get(catch_node.start_byte()..catch_node.end_byte())
            .unwrap_or(""),
    );
    Some(ExceptionHandlingSmell {
        file: file.clone(),
        enclosing_fq_name: enclosing,
        catch_type,
        score,
        body_statement_count: body_statements,
        reasons,
        excerpt,
        start_byte: catch_node.start_byte(),
    })
}

fn named_child_by_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn extract_catch_type(catch_param: Node<'_>, source: &str) -> Option<String> {
    if let Some(type_node) = catch_param.child_by_field_name("type")
        && let Some(text) = source.get(type_node.start_byte()..type_node.end_byte())
    {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let param_text = source
        .get(catch_param.start_byte()..catch_param.end_byte())?
        .trim()
        .to_string();
    if let Some(name_node) = catch_param.child_by_field_name("name")
        && let Some(name) = source.get(name_node.start_byte()..name_node.end_byte())
    {
        let name = name.trim();
        if let Some(idx) = param_text.rfind(name)
            && idx > 0
        {
            let prefix = param_text[..idx].trim();
            if !prefix.is_empty() {
                return Some(prefix.to_string());
            }
        }
    }
    if param_text.is_empty() {
        None
    } else {
        Some(param_text)
    }
}

fn count_body_meaningful_statements(body: Node<'_>) -> u32 {
    let mut cursor = body.walk();
    let mut count: u32 = 0;
    for child in body.named_children(&mut cursor) {
        let kind = child.kind();
        if JAVA_COMMENT_NODE_TYPES.contains(&kind) {
            continue;
        }
        if CATCH_BODY_MEANINGFUL_STATEMENT_TYPES.contains(&kind) {
            count += 1;
        }
    }
    count
}

/// True when `root` itself or any descendant has a kind in `kinds`. Matches
/// brokk-shared `hasDescendantOfAnyTypeInclusive` (root-inclusive).
fn has_descendant_of_any_kind_inclusive(root: Node<'_>, kinds: &[&str]) -> bool {
    if kinds.contains(&root.kind()) {
        return true;
    }
    for i in 0..root.child_count() {
        if let Some(child) = root.child(i)
            && has_descendant_of_any_kind_inclusive(child, kinds)
        {
            return true;
        }
    }
    false
}

/// True when any descendant (excluding the root itself) has the given kind.
/// Matches brokk-shared `hasDescendantOfType` (descendant-only).
fn has_descendant_of_kind(root: Node<'_>, kind: &str) -> bool {
    for i in 0..root.child_count() {
        if let Some(child) = root.child(i)
            && (child.kind() == kind || has_descendant_of_kind(child, kind))
        {
            return true;
        }
    }
    false
}

fn first_non_comment_named_child<'tree>(
    node: Node<'tree>,
    comment_kinds: &[&str],
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !comment_kinds.contains(&child.kind()))
}

fn find_first_named_descendant<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
        if let Some(found) = find_first_named_descendant(child, kind) {
            return Some(found);
        }
    }
    None
}

fn is_likely_log_only_body(body: Node<'_>, source: &str) -> bool {
    let Some(stmt) = first_non_comment_named_child(body, JAVA_COMMENT_NODE_TYPES) else {
        return false;
    };
    if stmt.kind() != "expression_statement" {
        return false;
    }
    let Some(invocation) = find_first_named_descendant(stmt, "method_invocation") else {
        return false;
    };
    let Some(object_node) = invocation.child_by_field_name("object") else {
        return false;
    };
    let Some(receiver_text) = source.get(object_node.start_byte()..object_node.end_byte()) else {
        return false;
    };
    let receiver = receiver_text.trim().to_ascii_lowercase();
    if receiver.is_empty() {
        return false;
    }
    LOG_RECEIVER_NAMES.contains(&receiver.as_str())
        || LOG_RECEIVER_NAMES
            .iter()
            .any(|name| receiver.ends_with(&format!(".{name}")))
}

fn compact_catch_excerpt(text: &str) -> String {
    let compact = compact_whitespace_for_excerpt(text);
    if compact.chars().count() <= EXCEPTION_EXCERPT_MAX_LEN {
        return compact;
    }
    let mut truncated: String = compact.chars().take(EXCEPTION_EXCERPT_MAX_LEN).collect();
    truncated.push_str("...");
    truncated
}

fn compact_test_assertion_excerpt(text: &str) -> String {
    let compact = compact_whitespace_for_excerpt(text);
    if compact.chars().count() <= TEST_ASSERTION_EXCERPT_MAX_LEN {
        return compact;
    }
    let mut truncated: String = compact
        .chars()
        .take(TEST_ASSERTION_EXCERPT_MAX_LEN)
        .collect();
    truncated.push_str("...");
    truncated
}

fn compact_whitespace_for_excerpt(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut seen_non_ws = false;
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if seen_non_ws {
                pending_space = true;
            }
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        out.push(ch);
        pending_space = false;
        seen_non_ws = true;
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

fn weight_import_map(key: &ProjectFile, value: &Arc<HashMap<String, CodeUnit>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_import_map(value.as_ref()))
}

fn weight_project_file_set(key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_project_file_set(value.as_ref()))
}

fn weight_string_set(key: &CodeUnit, value: &Arc<HashSet<String>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_string_set(value.as_ref()))
}

fn weight_code_unit_vec(key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_code_unit_vec(value.as_ref()))
}

fn weight_code_unit_set(key: &CodeUnit, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_code_unit_set(value.as_ref()))
}

fn weight_bytes(bytes: u64) -> u32 {
    bytes.clamp(1, u32::MAX as u64) as u32
}

fn estimate_path(path: &std::path::Path) -> u64 {
    path.as_os_str().to_string_lossy().len() as u64
}

fn estimate_project_file(file: &ProjectFile) -> u64 {
    size_of::<ProjectFile>() as u64 + estimate_path(file.root()) + estimate_path(file.rel_path())
}

fn estimate_code_unit(code_unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + estimate_project_file(code_unit.source())
        + code_unit.package_name().len() as u64
        + code_unit.short_name().len() as u64
        + code_unit
            .signature()
            .map_or(0, |signature| signature.len() as u64)
}

fn estimate_import_map(imports: &HashMap<String, CodeUnit>) -> u64 {
    size_of::<HashMap<String, CodeUnit>>() as u64
        + imports
            .iter()
            .map(|(name, code_unit)| name.len() as u64 + estimate_code_unit(code_unit))
            .sum::<u64>()
}

fn estimate_project_file_set(files: &HashSet<ProjectFile>) -> u64 {
    size_of::<HashSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}

fn estimate_string_set(values: &HashSet<String>) -> u64 {
    size_of::<HashSet<String>>() as u64 + values.iter().map(|value| value.len() as u64).sum::<u64>()
}

fn estimate_code_unit_vec(values: &[CodeUnit]) -> u64 {
    size_of::<Vec<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_code_unit_set(values: &HashSet<CodeUnit>) -> u64 {
    size_of::<HashSet<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn java_source_contains_tests(source: &str) -> bool {
    source.contains("@Test")
        || source.contains(".Test")
        || source.contains("@ParameterizedTest")
        || source.contains("@RepeatedTest")
        || source.contains("@Rule")
        || source.contains("@ClassRule")
        || source.contains("@Ignore")
        || (source.contains("TestCase")
            && (contains_ignoring_whitespace(source, "extendsTestCase")
                || contains_ignoring_whitespace(source, "extendsjunit.framework.TestCase")))
}

fn contains_ignoring_whitespace(source: &str, needle: &str) -> bool {
    let mut needle_chars = needle.chars();
    let Some(first) = needle_chars.next() else {
        return true;
    };

    for (start, ch) in source.char_indices() {
        if ch.is_whitespace() || ch != first {
            continue;
        }

        let mut chars = source[start + ch.len_utf8()..]
            .chars()
            .filter(|ch| !ch.is_whitespace());
        if needle_chars
            .clone()
            .all(|expected| chars.next() == Some(expected))
        {
            return true;
        }
    }

    false
}

fn detect_test_assertion_smells_java(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let mut methods = Vec::new();
    collect_nodes_by_kind(tree.root_node(), "method_declaration", &mut methods);
    let anonymous_shape_counts = anonymous_test_double_shape_counts(&methods, source);
    let mut findings = Vec::new();
    for method in methods {
        if is_test_method(method, source) {
            analyze_test_method_assertions(analyzer, file, source, method, weights, &mut findings);
            analyze_anonymous_test_doubles(
                analyzer,
                file,
                source,
                method,
                weights,
                &anonymous_shape_counts,
                &mut findings,
            );
        }
    }
    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
            .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
            .then_with(|| a.start_byte.cmp(&b.start_byte))
    });
    findings
}

fn collect_nodes_by_kind<'tree>(node: Node<'tree>, kind: &str, out: &mut Vec<Node<'tree>>) {
    if node.kind() == kind {
        out.push(node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_nodes_by_kind(child, kind, out);
        }
    }
}

fn is_test_method(method: Node<'_>, source: &str) -> bool {
    let Some(modifiers) = named_child_by_kind(method, "modifiers") else {
        return false;
    };
    let mut cursor = modifiers.walk();
    modifiers
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "annotation" || child.kind() == "marker_annotation")
        .filter_map(|annotation| annotation_name(annotation, source))
        .any(|name| TEST_ANNOTATIONS.contains(&name.as_str()))
}

fn annotation_name(annotation: Node<'_>, source: &str) -> Option<String> {
    let raw = if let Some(name_node) = annotation.child_by_field_name("name") {
        source.get(name_node.start_byte()..name_node.end_byte())?
    } else {
        source.get(annotation.start_byte()..annotation.end_byte())?
    };
    let trimmed = raw.trim().trim_start_matches('@');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
    if short.is_empty() {
        None
    } else {
        Some(short.to_string())
    }
}

fn analyze_test_method_assertions(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let Some(body) = method.child_by_field_name("body") else {
        return;
    };
    let mut invocations = Vec::new();
    collect_nodes_by_kind(body, "method_invocation", &mut invocations);
    let assertions: Vec<AssertionSignal> = invocations
        .into_iter()
        .filter_map(|invocation| assertion_signal(invocation, source, weights))
        .collect();
    let enclosing = analyzer
        .enclosing_code_unit_for_lines(file, method.start_position().row, method.end_position().row)
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    let assertion_count = assertions.len() as i32;

    if assertion_count == 0 {
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: TEST_ASSERTION_KIND_NO_ASSERTIONS,
                score: weights.no_assertion_weight,
                assertion_count: 0,
                reasons: vec![TEST_ASSERTION_KIND_NO_ASSERTIONS.to_string()],
                excerpt_source: source
                    .get(method.start_byte()..method.end_byte())
                    .unwrap_or(""),
                start_byte: method.start_byte(),
            },
            out,
        );
        return;
    }

    for assertion in &assertions {
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: &assertion.kind,
                score: assertion.base_score,
                assertion_count,
                reasons: assertion.reasons.clone(),
                excerpt_source: &assertion.excerpt,
                start_byte: assertion.start_byte,
            },
            out,
        );
    }

    if assertions.iter().all(|a| a.shallow) {
        let score = weights.shallow_assertion_only_weight
            - meaningful_assertion_credit(assertions.iter(), weights, |a| a.meaningful);
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: TEST_ASSERTION_KIND_SHALLOW_ONLY,
                score,
                assertion_count,
                reasons: vec![TEST_ASSERTION_KIND_SHALLOW_ONLY.to_string()],
                excerpt_source: source
                    .get(method.start_byte()..method.end_byte())
                    .unwrap_or(""),
                start_byte: method.start_byte(),
            },
            out,
        );
    }
}

fn analyze_anonymous_test_doubles(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    weights: &TestAssertionWeights,
    anonymous_shape_counts: &HashMap<String, i32>,
    out: &mut Vec<TestAssertionSmell>,
) {
    let mut creations = Vec::new();
    collect_nodes_by_kind(method, "object_creation_expression", &mut creations);
    let enclosing = analyzer
        .enclosing_code_unit_for_lines(file, method.start_position().row, method.end_position().row)
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    for creation in creations {
        if named_child_by_kind(creation, "class_body").is_none()
            || creation.child_by_field_name("type").is_none()
        {
            continue;
        }
        let shape = anonymous_test_double_shape(creation, source);
        let repeated = anonymous_shape_counts.get(&shape).copied().unwrap_or(0) > 1;
        let score = if repeated {
            weights.repeated_anonymous_test_double_weight
        } else {
            weights.anonymous_test_double_weight
        };
        let mut reasons = vec![TEST_ASSERTION_KIND_ANONYMOUS_TEST_DOUBLE.to_string()];
        if repeated {
            reasons.push(TEST_ASSERTION_REASON_REUSABLE_TEST_DOUBLE.to_string());
        }
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: TEST_ASSERTION_KIND_ANONYMOUS_TEST_DOUBLE,
                score,
                assertion_count: 0,
                reasons,
                excerpt_source: source
                    .get(creation.start_byte()..creation.end_byte())
                    .unwrap_or(""),
                start_byte: creation.start_byte(),
            },
            out,
        );
    }
}

fn assertion_signal(
    invocation: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<AssertionSignal> {
    let method_name = method_invocation_name(invocation, source)?;
    let text = source
        .get(invocation.start_byte()..invocation.end_byte())?
        .trim()
        .to_string();
    if text.is_empty() {
        return None;
    }
    if JUNIT_ASSERTION_NAMES.contains(&method_name.as_str()) {
        return Some(classify_junit_assertion(
            invocation,
            &method_name,
            source,
            &text,
            weights,
        ));
    }
    if MOCKITO_VERIFY_NAMES.contains(&method_name.as_str()) {
        return Some(AssertionSignal {
            kind: TEST_ASSERTION_KIND_MOCK_VERIFICATION.to_string(),
            base_score: 0,
            shallow: false,
            meaningful: true,
            start_byte: invocation.start_byte(),
            reasons: Vec::new(),
            excerpt: text,
        });
    }
    if ASSERTJ_TERMINAL_NAMES.contains(&method_name.as_str())
        && assert_that_argument(invocation, source).is_some()
    {
        return Some(classify_assertj_assertion(
            invocation,
            &method_name,
            source,
            &text,
            weights,
        ));
    }
    None
}

fn classify_junit_assertion(
    invocation: Node<'_>,
    method_name: &str,
    source: &str,
    text: &str,
    weights: &TestAssertionWeights,
) -> AssertionSignal {
    let args = argument_nodes(invocation);
    let mut score = 0;
    let mut reasons = Vec::new();
    let shallow = SHALLOW_ASSERTION_NAMES.contains(&method_name);
    let mut meaningful = !shallow && method_name != "fail";
    let mut kind = TEST_ASSERTION_KIND_JUNIT.to_string();

    if (method_name == "assertTrue" || method_name == "assertFalse") && !args.is_empty() {
        let arg = *args.last().unwrap();
        let constant_truth = (method_name == "assertTrue" && arg.kind() == "true")
            || (method_name == "assertFalse" && arg.kind() == "false");
        if constant_truth {
            score += weights.constant_truth_weight;
            reasons.push(TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string());
            kind = TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string();
            meaningful = false;
        }
        if is_self_comparison(arg, source) {
            score += weights.tautological_assertion_weight;
            reasons.push(TEST_ASSERTION_KIND_SELF_COMPARISON.to_string());
            kind = TEST_ASSERTION_KIND_SELF_COMPARISON.to_string();
            meaningful = false;
        }
    }

    if (method_name == "assertEquals" || method_name == "assertSame") && args.len() >= 2 {
        let comparable_args = comparable_assertion_args(&args);
        let expected = comparable_args[0];
        let actual = comparable_args[1];
        if is_constant_expression(expected) && is_constant_expression(actual) {
            score += weights.constant_equality_weight;
            reasons.push(TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string());
            kind = TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string();
            meaningful = false;
        } else if same_expression(expected, actual, source) {
            score += weights.tautological_assertion_weight;
            reasons.push(TEST_ASSERTION_KIND_SELF_COMPARISON.to_string());
            kind = TEST_ASSERTION_KIND_SELF_COMPARISON.to_string();
            meaningful = false;
        }
    }

    if (method_name == "assertNotNull" || method_name == "assertNull") && args.len() <= 2 {
        score += weights.nullness_only_weight;
        reasons.push(TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string());
        kind = TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string();
        meaningful = false;
    }

    if contains_overspecified_literal(&args, source, weights) {
        score += weights.overspecified_literal_weight;
        reasons.push(TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string());
        kind = TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string();
    }

    AssertionSignal {
        kind,
        base_score: score,
        shallow,
        meaningful,
        start_byte: invocation.start_byte(),
        reasons,
        excerpt: text.to_string(),
    }
}

fn classify_assertj_assertion(
    invocation: Node<'_>,
    method_name: &str,
    source: &str,
    text: &str,
    weights: &TestAssertionWeights,
) -> AssertionSignal {
    let args = argument_nodes(invocation);
    let mut score = 0;
    let mut reasons = Vec::new();
    let shallow = ASSERTJ_SHALLOW_TERMINAL_NAMES.contains(&method_name);
    let mut meaningful = !shallow;
    let mut kind = TEST_ASSERTION_KIND_ASSERTJ.to_string();

    if let Some(expected) = assert_that_argument(invocation, source)
        && args.len() == 1
    {
        let actual = args[0];
        if (method_name == "isEqualTo" || method_name == "isSameAs")
            && is_constant_expression(expected)
            && is_constant_expression(actual)
        {
            score += weights.constant_equality_weight;
            reasons.push(TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string());
            kind = TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string();
            meaningful = false;
        } else if (method_name == "isEqualTo" || method_name == "isSameAs")
            && same_expression(expected, actual, source)
        {
            score += weights.tautological_assertion_weight;
            reasons.push(TEST_ASSERTION_KIND_SELF_COMPARISON.to_string());
            kind = TEST_ASSERTION_KIND_SELF_COMPARISON.to_string();
            meaningful = false;
        }
    }

    if let Some(arg) = assert_that_argument(invocation, source)
        && ((method_name == "isTrue" && arg.kind() == "true")
            || (method_name == "isFalse" && arg.kind() == "false"))
    {
        score += weights.constant_truth_weight;
        reasons.push(TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string());
        kind = TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string();
        meaningful = false;
    }

    if shallow {
        score += weights.nullness_only_weight;
        reasons.push(TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string());
        kind = TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string();
        meaningful = false;
    }

    if contains_overspecified_literal(&args, source, weights) {
        score += weights.overspecified_literal_weight;
        reasons.push(TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string());
        kind = TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string();
    }

    AssertionSignal {
        kind,
        base_score: score,
        shallow,
        meaningful,
        start_byte: invocation.start_byte(),
        reasons,
        excerpt: text.to_string(),
    }
}

fn add_test_smell(
    file: &ProjectFile,
    enclosing: &str,
    smell: PendingTestSmell<'_>,
    out: &mut Vec<TestAssertionSmell>,
) {
    if smell.score <= 0 || smell.reasons.is_empty() {
        return;
    }
    out.push(TestAssertionSmell {
        file: file.clone(),
        enclosing_fq_name: enclosing.to_string(),
        assertion_kind: smell.assertion_kind.to_string(),
        score: smell.score,
        assertion_count: smell.assertion_count,
        reasons: smell.reasons,
        excerpt: compact_test_assertion_excerpt(smell.excerpt_source),
        start_byte: smell.start_byte,
    });
}

fn method_invocation_name(invocation: Node<'_>, source: &str) -> Option<String> {
    let name_node = invocation.child_by_field_name("name")?;
    let text = source
        .get(name_node.start_byte()..name_node.end_byte())?
        .trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn argument_nodes(invocation: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = invocation.child_by_field_name("arguments") else {
        return Vec::new();
    };
    if arguments.kind() != "argument_list" {
        return Vec::new();
    }
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn comparable_assertion_args<'tree>(args: &'tree [Node<'tree>]) -> &'tree [Node<'tree>] {
    if args.len() >= 4 && is_string_literal(args[0]) {
        &args[1..3]
    } else {
        &args[0..args.len().min(2)]
    }
}

fn assert_that_argument<'tree>(invocation: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut candidate = invocation.child_by_field_name("object");
    while let Some(node) = candidate {
        if node.kind() != "method_invocation" {
            break;
        }
        let name_node = node.child_by_field_name("name")?;
        let name = source
            .get(name_node.start_byte()..name_node.end_byte())?
            .trim();
        if name == "assertThat" {
            return argument_nodes(node).into_iter().next();
        }
        candidate = node.child_by_field_name("object");
    }
    None
}

fn is_self_comparison(node: Node<'_>, source: &str) -> bool {
    if node.kind() == "binary_expression" {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        return left
            .zip(right)
            .is_some_and(|(l, r)| same_expression(l, r, source));
    }
    if node.kind() == "method_invocation"
        && method_invocation_name(node, source).as_deref() == Some("equals")
    {
        let Some(object_node) = node.child_by_field_name("object") else {
            return false;
        };
        return argument_nodes(node)
            .into_iter()
            .next()
            .is_some_and(|arg| same_expression(object_node, arg, source));
    }
    false
}

fn same_expression(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let left_text = source
        .get(left.start_byte()..left.end_byte())
        .unwrap_or("")
        .trim();
    let right_text = source
        .get(right.start_byte()..right.end_byte())
        .unwrap_or("")
        .trim();
    left_text == right_text
}

fn is_constant_expression(node: Node<'_>) -> bool {
    CONSTANT_LITERAL_TYPES.contains(&node.kind())
}

fn is_string_literal(node: Node<'_>) -> bool {
    node.kind() == "string_literal"
}

fn contains_overspecified_literal(
    args: &[Node<'_>],
    source: &str,
    weights: &TestAssertionWeights,
) -> bool {
    let threshold = weights.large_literal_length_threshold.max(0) as usize;
    args.iter().any(|arg| {
        is_string_literal(*arg)
            && source
                .get(arg.start_byte()..arg.end_byte())
                .is_some_and(|text| text.len() >= threshold)
    })
}

fn meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a AssertionSignal>,
    weights: &TestAssertionWeights,
    predicate: impl Fn(&AssertionSignal) -> bool,
) -> i32 {
    let count = assertions.filter(|assertion| predicate(assertion)).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn anonymous_test_double_shape_counts(
    test_methods: &[Node<'_>],
    source: &str,
) -> HashMap<String, i32> {
    let mut counts = HashMap::default();
    for method in test_methods
        .iter()
        .copied()
        .filter(|m| is_test_method(*m, source))
    {
        let mut creations = Vec::new();
        collect_nodes_by_kind(method, "object_creation_expression", &mut creations);
        for creation in creations
            .into_iter()
            .filter(|creation| named_child_by_kind(*creation, "class_body").is_some())
        {
            let shape = anonymous_test_double_shape(creation, source);
            *counts.entry(shape).or_insert(0) += 1;
        }
    }
    counts
}

fn anonymous_test_double_shape(creation: Node<'_>, source: &str) -> String {
    let type_name = creation
        .child_by_field_name("type")
        .and_then(|node| source.get(node.start_byte()..node.end_byte()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("<unknown>");
    let mut methods = Vec::new();
    collect_nodes_by_kind(creation, "method_declaration", &mut methods);
    let method_names = methods
        .into_iter()
        .filter_map(|method| {
            method
                .child_by_field_name("name")
                .and_then(|name| source.get(name.start_byte()..name.end_byte()))
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToString::to_string)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{type_name}#{method_names}")
}

#[derive(Debug, Clone)]
struct AssertionSignal {
    kind: String,
    base_score: i32,
    shallow: bool,
    meaningful: bool,
    start_byte: usize,
    reasons: Vec<String>,
    excerpt: String,
}

struct PendingTestSmell<'a> {
    assertion_kind: &'a str,
    score: i32,
    assertion_count: i32,
    reasons: Vec<String>,
    excerpt_source: &'a str,
    start_byte: usize,
}
