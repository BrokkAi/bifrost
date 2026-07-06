use super::external::JavaExternalType;
use super::*;
use crate::analyzer::{ImportInfo, build_reverse_file_index, build_reverse_import_index};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JavaTypeResolution {
    Source(CodeUnit),
    External(JavaExternalType),
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
        if let Some(files) = self.same_package_reference_index().get(file) {
            result.extend(files.iter().cloned());
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
    fn same_package_reference_index(&self) -> &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        self.memo_caches
            .same_package_reference_index
            .get_or_init(|| {
                let mut targets_by_package_and_name: HashMap<(String, String), Vec<ProjectFile>> =
                    HashMap::default();
                for file in self.inner.all_files() {
                    let package = self.inner.package_name_of(file).unwrap_or("").to_string();
                    for declaration in self.inner.top_level_declarations(file) {
                        if declaration.is_class() || declaration.is_module() {
                            targets_by_package_and_name
                                .entry((package.clone(), declaration.identifier().to_string()))
                                .or_default()
                                .push(file.clone());
                        }
                    }
                }

                let files: Vec<_> = self.inner.all_files().cloned().collect();
                build_reverse_file_index(&files, |candidate| {
                    let package = self
                        .inner
                        .package_name_of(candidate)
                        .unwrap_or("")
                        .to_string();
                    let Some(identifiers) = self.inner.type_identifiers_of(candidate) else {
                        return Vec::new();
                    };
                    let mut targets = Vec::new();
                    for identifier in identifiers {
                        if let Some(matching_targets) =
                            targets_by_package_and_name.get(&(package.clone(), identifier.clone()))
                        {
                            targets.extend(matching_targets.iter().cloned());
                        }
                    }
                    targets
                })
            })
    }

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
            let Some(raw) = non_static_import_path(import) else {
                continue;
            };

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
        let mut wildcard_resolved = HashMap::<String, CodeUnit>::default();

        for import in self.inner.import_info_of(file) {
            let Some(import_path) = non_static_import_path(import) else {
                continue;
            };

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
                let identifier = code_unit.identifier().to_string();
                if resolved.contains_key(&identifier)
                    && !wildcard_resolved.contains_key(&identifier)
                {
                    continue;
                }
                if wildcard_resolved.contains_key(&identifier) {
                    continue;
                }
                wildcard_resolved.insert(identifier.clone(), code_unit.clone());
                resolved.insert(identifier, code_unit.clone());
            }
        }

        resolved
    }

    pub(super) fn resolve_type_name(&self, file: &ProjectFile, raw_name: &str) -> Option<CodeUnit> {
        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }

        if normalized.contains('.') {
            if let Some(code_unit) = self
                .inner
                .definitions(normalized)
                .find(|code_unit| code_unit.is_class())
                .cloned()
            {
                return Some(code_unit);
            }
            if let Some(code_unit) = self.resolve_nested_type_name(file, normalized) {
                return Some(code_unit);
            }
        }

        let imports = self.resolve_imports(file);
        if let Some(code_unit) = imports.get(normalized) {
            return Some(code_unit.clone());
        }

        let same_package_fqn = self.same_package_fqn(file, normalized);
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

    pub(crate) fn resolve_type_name_with_external(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<JavaTypeResolution> {
        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }

        if let Some(code_unit) = self.resolve_type_name(file, normalized) {
            return Some(JavaTypeResolution::Source(code_unit));
        }

        let external = self.external_declaration_index();
        if external.is_empty() {
            return None;
        }

        let access_package = self.inner.package_name_of(file).unwrap_or("");
        if normalized.contains('.')
            && let Some(external_type) = external.resolve_qualified_name(normalized, access_package)
        {
            return Some(JavaTypeResolution::External(external_type.clone()));
        }

        if let Some(external_type) = self.resolve_external_imports(file, normalized, access_package)
        {
            return Some(JavaTypeResolution::External(external_type));
        }

        if let Some((first, rest)) = normalized.split_once('.')
            && let Some(owner) =
                self.resolve_visible_external_simple_type(file, first, access_package)
        {
            let nested_fqn = format!("{}.{}", owner.fqn(), rest);
            if let Some(external_type) =
                external.resolve_qualified_name(&nested_fqn, access_package)
            {
                return Some(JavaTypeResolution::External(external_type.clone()));
            }
        }

        let same_package = self.same_package_fqn(file, normalized);
        if let Some(external_type) = external.resolve_same_package(access_package, normalized) {
            return Some(JavaTypeResolution::External(external_type.clone()));
        }

        if same_package != normalized
            && let Some(external_type) =
                external.resolve_qualified_name(&same_package, access_package)
        {
            return Some(JavaTypeResolution::External(external_type.clone()));
        }

        external
            .resolve_java_lang(normalized)
            .cloned()
            .map(JavaTypeResolution::External)
    }

    fn resolve_nested_type_name(&self, file: &ProjectFile, normalized: &str) -> Option<CodeUnit> {
        let (first, rest) = normalized.split_once('.')?;
        let owner = self.resolve_visible_simple_type(file, first)?;
        let nested_fqn = format!("{}.{}", owner.fq_name(), rest);
        self.inner
            .definitions(&nested_fqn)
            .find(|code_unit| code_unit.is_class())
            .cloned()
    }

    fn resolve_visible_external_simple_type(
        &self,
        file: &ProjectFile,
        name: &str,
        access_package: &str,
    ) -> Option<JavaExternalType> {
        if let Some(external_type) = self.resolve_external_imports(file, name, access_package) {
            return Some(external_type);
        }

        let external = self.external_declaration_index();
        external
            .resolve_same_package(access_package, name)
            .or_else(|| external.resolve_java_lang(name))
            .cloned()
    }

    fn resolve_external_imports(
        &self,
        file: &ProjectFile,
        name: &str,
        access_package: &str,
    ) -> Option<JavaExternalType> {
        let external = self.external_declaration_index();
        for import in self.inner.import_info_of(file) {
            let Some(import_path) = non_static_import_path(import) else {
                continue;
            };

            if !import.is_wildcard {
                if import.identifier.as_deref() == Some(name)
                    && let Some(external_type) =
                        external.resolve_explicit_import(import_path, access_package)
                {
                    return Some(external_type.clone());
                }
                continue;
            }
        }

        let mut wildcard_match: Option<JavaExternalType> = None;
        for import in self.inner.import_info_of(file) {
            let Some(import_path) = non_static_import_path(import) else {
                continue;
            };
            if !import.is_wildcard {
                continue;
            }

            let package_name = import_path.trim_end_matches(".*");
            let Some(external_type) =
                external.resolve_wildcard_import(package_name, name, access_package)
            else {
                continue;
            };
            match wildcard_match.as_ref() {
                Some(existing) if existing.fqn() != external_type.fqn() => return None,
                Some(_) => {}
                None => wildcard_match = Some(external_type.clone()),
            }
        }

        wildcard_match
    }

    fn resolve_visible_simple_type(&self, file: &ProjectFile, name: &str) -> Option<CodeUnit> {
        if let Some(code_unit) = self.resolve_imports(file).get(name) {
            return Some(code_unit.clone());
        }
        let same_package_fqn = self.same_package_fqn(file, name);
        self.inner
            .definitions(&same_package_fqn)
            .find(|code_unit| code_unit.is_class())
            .cloned()
            .or_else(|| {
                self.inner
                    .definitions(name)
                    .find(|code_unit| code_unit.is_class())
                    .cloned()
            })
    }

    fn same_package_fqn(&self, file: &ProjectFile, name: &str) -> String {
        let package_name = self.inner.package_name_of(file).unwrap_or("");
        if package_name.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", package_name, name)
        }
    }
}

pub(super) fn parse_import_info(raw: String) -> ImportInfo {
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

fn non_static_import_path(import: &ImportInfo) -> Option<&str> {
    if import
        .raw_snippet
        .trim_start()
        .starts_with("import static ")
    {
        return None;
    }

    Some(import_path_from_raw(&import.raw_snippet))
}

fn import_path_from_raw(raw: &str) -> &str {
    raw.trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .strip_suffix(';')
        .unwrap_or(raw.trim())
        .trim()
}

fn extract_package_from_import(raw: &str) -> String {
    let trimmed = import_path_from_raw(raw);
    let trimmed = trimmed.strip_prefix("static ").unwrap_or(trimmed).trim();

    if let Some(package) = trimmed.strip_suffix(".*") {
        return package.trim().to_string();
    }

    trimmed
        .rsplit_once('.')
        .map(|(package, _)| package.trim().to_string())
        .unwrap_or_default()
}
