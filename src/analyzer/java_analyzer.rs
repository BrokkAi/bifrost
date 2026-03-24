use crate::analyzer::{
    AnalyzerConfig, CodeUnit, DeclarationInfo, DeclarationKind, IAnalyzer, ImportAnalysisProvider,
    ImportInfo, Language, LanguageAdapter, Project, ProjectFile, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider,
};
use moka::sync::Cache;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

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
}

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
}

#[derive(Clone)]
struct JavaMemoCaches {
    budget_bytes: u64,
    resolved_imports: Cache<ProjectFile, Arc<BTreeMap<String, CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<BTreeSet<ProjectFile>>>,
    relevant_imports: Cache<CodeUnit, Arc<BTreeSet<String>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<BTreeSet<CodeUnit>>>,
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
        let mut identifiers = BTreeSet::new();
        collect_type_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers
    }
}

impl ImportAnalysisProvider for JavaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.resolve_imports(file).into_values().collect()
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }

        let mut result: BTreeSet<ProjectFile> = self
            .inner
            .all_files()
            .into_iter()
            .filter(|candidate| candidate != file)
            .filter(|candidate| {
                self.imported_code_units_of(candidate)
                    .into_iter()
                    .any(|code_unit| code_unit.source() == file)
            })
            .collect();

        let target_identifiers: BTreeSet<String> = self
            .inner
            .get_top_level_declarations(file)
            .into_iter()
            .filter(|code_unit| code_unit.is_class() || code_unit.is_module())
            .map(|code_unit| code_unit.identifier().to_string())
            .collect();

        let target_package = self.inner.package_name_of(file).unwrap_or("");
        for candidate in self.inner.all_files() {
            if candidate == *file || result.contains(&candidate) {
                continue;
            }
            if self.inner.package_name_of(&candidate).unwrap_or("") != target_package {
                continue;
            }

            let candidate_identifiers = self.inner.type_identifiers_of(&candidate);
            if candidate_identifiers
                .iter()
                .any(|identifier| target_identifiers.contains(identifier))
            {
                result.insert(candidate);
            }
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> BTreeSet<String> {
        if let Some(cached) = self.memo_caches.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }

        let Some(source) = self.get_source(code_unit, false) else {
            return BTreeSet::new();
        };

        let all_imports = self.import_info_of(code_unit.source());
        if all_imports.is_empty() {
            let empty = BTreeSet::new();
            self.memo_caches
                .relevant_imports
                .insert(code_unit.clone(), Arc::new(empty.clone()));
            return empty;
        }

        let type_identifiers = self.extract_type_identifiers(&source);
        if type_identifiers.is_empty() {
            let empty = BTreeSet::new();
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

        let mut matched_imports = BTreeSet::new();
        let mut resolved_identifiers = BTreeSet::new();

        for import in explicit_imports {
            let Some(identifier) = import.identifier.as_deref() else {
                continue;
            };

            if type_identifiers.contains(identifier) {
                matched_imports.insert(import.raw_snippet.clone());
                resolved_identifiers.insert(identifier.to_string());
            }
        }

        let mut unresolved_identifiers: BTreeSet<String> = type_identifiers
            .into_iter()
            .filter(|identifier| !resolved_identifiers.contains(identifier))
            .collect();
        if unresolved_identifiers.is_empty() {
            self.memo_caches
                .relevant_imports
                .insert(code_unit.clone(), Arc::new(matched_imports.clone()));
            return matched_imports;
        }

        let import_packages: BTreeSet<String> = all_imports
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

        let mut resolved_via_wildcard = BTreeSet::new();
        for identifier in &unresolved_identifiers {
            for import in &wildcard_imports {
                let package = extract_package_from_import(&import.raw_snippet);
                if package.is_empty() {
                    continue;
                }

                let lookup_name = format!("{package}.{identifier}");
                if self
                    .get_definitions(&lookup_name)
                    .into_iter()
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

    fn resolve_imports(&self, file: &ProjectFile) -> BTreeMap<String, CodeUnit> {
        if let Some(cached) = self.memo_caches.resolved_imports.get(file) {
            return (*cached).clone();
        }

        let resolved = self.resolve_imports_uncached(file);
        self.memo_caches
            .resolved_imports
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn resolve_imports_uncached(&self, file: &ProjectFile) -> BTreeMap<String, CodeUnit> {
        let mut resolved = BTreeMap::new();

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
                    .get_definitions(import_path)
                    .into_iter()
                    .find(|code_unit| code_unit.is_class())
                {
                    resolved.insert(code_unit.identifier().to_string(), code_unit);
                }
                continue;
            }

            let package_name = import_path.trim_end_matches(".*");
            for code_unit in self.inner.get_all_declarations() {
                if !code_unit.is_class() || code_unit.package_name() != package_name {
                    continue;
                }
                resolved
                    .entry(code_unit.identifier().to_string())
                    .or_insert(code_unit);
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
                .get_definitions(normalized)
                .into_iter()
                .find(|code_unit| code_unit.is_class())
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
            .get_definitions(&same_package_fqn)
            .into_iter()
            .find(|code_unit| code_unit.is_class())
        {
            return Some(code_unit);
        }

        self.inner
            .get_definitions(normalized)
            .into_iter()
            .find(|code_unit| code_unit.is_class())
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
        let mut index = 0usize;

        while index < normalized.len() {
            if normalized[index..].starts_with("$anon$") {
                out.push_str("$anon$");
                index += 6;
                continue;
            }

            let ch = normalized.as_bytes()[index] as char;
            out.push(if ch == '$' { '.' } else { ch });
            index += 1;
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

fn collect_type_identifiers(node: Node<'_>, source: &str, identifiers: &mut BTreeSet<String>) {
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
            .into_iter()
            .filter_map(|raw_name| self.resolve_type_name(code_unit.source(), &raw_name))
            .collect();
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> BTreeSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants: BTreeSet<_> = self
            .inner
            .get_all_declarations()
            .into_iter()
            .filter(|candidate| candidate.is_class())
            .filter(|candidate| {
                self.get_direct_ancestors(candidate)
                    .into_iter()
                    .any(|ancestor| ancestor == *code_unit)
            })
            .collect();
        self.memo_caches
            .direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}

impl IAnalyzer for JavaAnalyzer {
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
        let Ok(source) = file.read_to_string() else {
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
        let Ok(source) = file.read_to_string() else {
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }
}

fn weight_import_map(key: &ProjectFile, value: &Arc<BTreeMap<String, CodeUnit>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_import_map(value.as_ref()))
}

fn weight_project_file_set(key: &ProjectFile, value: &Arc<BTreeSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file(key) + estimate_project_file_set(value.as_ref()))
}

fn weight_string_set(key: &CodeUnit, value: &Arc<BTreeSet<String>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_string_set(value.as_ref()))
}

fn weight_code_unit_vec(key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit(key) + estimate_code_unit_vec(value.as_ref()))
}

fn weight_code_unit_set(key: &CodeUnit, value: &Arc<BTreeSet<CodeUnit>>) -> u32 {
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

fn estimate_import_map(imports: &BTreeMap<String, CodeUnit>) -> u64 {
    size_of::<BTreeMap<String, CodeUnit>>() as u64
        + imports
            .iter()
            .map(|(name, code_unit)| name.len() as u64 + estimate_code_unit(code_unit))
            .sum::<u64>()
}

fn estimate_project_file_set(files: &BTreeSet<ProjectFile>) -> u64 {
    size_of::<BTreeSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}

fn estimate_string_set(values: &BTreeSet<String>) -> u64 {
    size_of::<BTreeSet<String>>() as u64
        + values.iter().map(|value| value.len() as u64).sum::<u64>()
}

fn estimate_code_unit_vec(values: &[CodeUnit]) -> u64 {
    size_of::<Vec<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_code_unit_set(values: &BTreeSet<CodeUnit>) -> u64 {
    size_of::<BTreeSet<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn java_source_contains_tests(source: &str) -> bool {
    let compact = source.replace(char::is_whitespace, "");
    compact.contains("@Test")
        || compact.contains(".Test")
        || compact.contains("@ParameterizedTest")
        || compact.contains("@RepeatedTest")
        || compact.contains("@Rule")
        || compact.contains("@ClassRule")
        || compact.contains("@Ignore")
        || compact.contains("extendsTestCase")
        || compact.contains("extendsjunit.framework.TestCase")
}
