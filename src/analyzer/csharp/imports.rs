use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile,
    build_reverse_file_index, build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use super::CSharpAnalyzer;

impl ImportAnalysisProvider for CSharpAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let namespaces = self.using_namespaces_of(file);
        let aliases = self.using_aliases_of(file);
        if namespaces.is_empty() && aliases.is_empty() {
            return HashSet::default();
        }
        let mut imported: HashSet<CodeUnit> = HashSet::default();
        for namespace in &namespaces {
            imported.extend(
                self.inner
                    .class_declarations_in_package(namespace)
                    .iter()
                    .cloned(),
            );
        }
        for target in aliases.values() {
            imported.extend(self.visible_type_candidates(file, target));
        }
        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::new(imported.clone()));
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }
        let target_classes = self
            .get_declarations(file)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .collect::<Vec<_>>();
        let target_namespaces: HashSet<String> = target_classes
            .iter()
            .map(|unit| unit.package_name().to_string())
            .collect();
        if target_namespaces.is_empty() {
            return HashSet::default();
        }
        let reverse_index = self.memo_caches.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        if let Some(files) = self.implicit_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [crate::analyzer::ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[crate::analyzer::ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if self.namespace_of_file(source_file) == self.namespace_of_file(target) {
            return true;
        }
        let target_namespaces: HashSet<String> = self
            .get_declarations(target)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .map(|unit| unit.package_name().to_string())
            .collect();
        let source_imports = self.using_namespaces_of(source_file);
        let source_aliases = self.using_aliases_of(source_file);
        imports
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .chain(source_imports)
            .any(|namespace| target_namespaces.contains(&namespace))
            || source_aliases.values().any(|alias_target| {
                let candidates = self.visible_type_candidates(source_file, alias_target);
                self.get_declarations(target)
                    .into_iter()
                    .filter(|unit| unit.kind() == CodeUnitType::Class)
                    .any(|unit| candidates.contains(&unit))
            })
    }
}

impl CSharpAnalyzer {
    fn implicit_reference_index(&self) -> &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        self.memo_caches.implicit_reference_index.get_or_init(|| {
            let mut by_namespace_and_name: HashMap<(String, String), Vec<ProjectFile>> =
                HashMap::default();
            let mut by_fq_name: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for target in self.inner.all_files() {
                for unit in self
                    .inner
                    .top_level_declarations(target)
                    .filter(|unit| unit.kind() == CodeUnitType::Class)
                {
                    by_namespace_and_name
                        .entry((
                            unit.package_name().to_string(),
                            unit.identifier().to_string(),
                        ))
                        .or_default()
                        .push(target.clone());
                    by_fq_name
                        .entry(unit.fq_name())
                        .or_default()
                        .push(target.clone());
                    by_fq_name
                        .entry(unit.fq_name().replace('$', "."))
                        .or_default()
                        .push(target.clone());
                }
            }

            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_file_index(&files, |candidate| {
                let Some(identifiers) = self.inner.type_identifiers_of(candidate) else {
                    return Vec::new();
                };
                let candidate_namespace = self.namespace_of_file(candidate);
                let mut resolved_targets = Vec::new();
                for identifier in identifiers {
                    if let Some(namespace_targets) = by_namespace_and_name
                        .get(&(candidate_namespace.clone(), identifier.clone()))
                    {
                        resolved_targets.extend(namespace_targets.iter().cloned());
                    }
                    if let Some(fq_targets) = by_fq_name.get(identifier) {
                        resolved_targets.extend(fq_targets.iter().cloned());
                    }
                }
                resolved_targets
            })
        })
    }
}

pub(super) fn csharp_using_namespace(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let rest = trimmed
        .strip_prefix("global ")
        .unwrap_or(trimmed)
        .strip_prefix("using ")?
        .trim();
    if rest.starts_with("static ") || rest.contains('=') || rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

pub(super) fn csharp_import_info(raw: String) -> ImportInfo {
    let identifier = csharp_using_namespace(&raw)
        .and_then(|namespace| namespace.rsplit('.').next().map(str::to_string));
    ImportInfo {
        raw_snippet: raw,
        is_wildcard: true,
        identifier,
        alias: None,
    }
}

pub(super) fn csharp_import_info_from_using_directive(
    node: Node<'_>,
    source: &str,
    raw: String,
) -> Option<ImportInfo> {
    if csharp_using_namespace(&raw).is_some() {
        return Some(csharp_import_info(raw));
    }
    csharp_using_alias_from_node(node, source).map(|(alias, target)| ImportInfo {
        raw_snippet: raw,
        is_wildcard: false,
        identifier: Some(target),
        alias: Some(alias),
    })
}

pub(super) fn csharp_using_alias_from_import(import: &ImportInfo) -> Option<(String, String)> {
    Some((import.alias.clone()?, import.identifier.clone()?))
}

pub(super) fn csharp_using_alias_from_node(
    node: Node<'_>,
    source: &str,
) -> Option<(String, String)> {
    let alias_node = node.child_by_field_name("name")?;
    let alias = node_text(alias_node, source).trim().to_string();
    if alias.is_empty() {
        return None;
    }
    let mut cursor = node.walk();
    let target_node = node.named_children(&mut cursor).find(|child| {
        child.start_byte() >= alias_node.end_byte() && child.id() != alias_node.id()
    })?;
    let target = node_text(target_node, source).trim().to_string();
    (!target.is_empty()).then_some((alias, target))
}

pub(super) fn normalize_csharp_type_name(raw_name: &str) -> String {
    let without_nullable = raw_name.trim().trim_end_matches('?').trim();
    let without_arrays = without_nullable
        .trim_end_matches("[]")
        .trim_end_matches('?')
        .trim();
    without_arrays
        .split('<')
        .next()
        .unwrap_or(without_arrays)
        .trim()
        .to_string()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}
