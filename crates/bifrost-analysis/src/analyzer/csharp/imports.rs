use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{CodeUnit, CodeUnitType, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use super::CSharpAnalyzer;
use super::graph_support::{compute_implicit_reference_index, visible_type_candidates};

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
            imported.extend(visible_type_candidates(self, file, target));
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
            .declarations(file)
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
        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.memo_caches.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
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

    fn import_info_of(&self, file: &ProjectFile) -> Vec<crate::analyzer::ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[crate::analyzer::ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_classes = self
            .declarations(target)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .collect::<Vec<_>>();
        let arity_sensitive = target_classes
            .iter()
            .any(|unit| unit.identifier().contains('`'));
        if self.namespace_of_file(source_file) == self.namespace_of_file(target) && !arity_sensitive
        {
            return true;
        }
        let target_namespaces: HashSet<String> = target_classes
            .iter()
            .map(|unit| unit.package_name().to_string())
            .collect();
        let target_names: HashSet<String> = target_classes
            .iter()
            .flat_map(|unit| {
                let fq_name = unit.fq_name();
                [
                    unit.identifier().to_string(),
                    fq_name.clone(),
                    fq_name.replace('$', "."),
                ]
            })
            .collect();
        let source_aliases = self.using_aliases_of(source_file);
        if let Some(identifiers) = self.inner.type_identifiers_of(source_file) {
            for identifier in identifiers {
                if target_names.contains(&identifier) {
                    return true;
                }
                if identifier
                    .strip_prefix("global::")
                    .is_some_and(|global_name| target_names.contains(global_name))
                {
                    return true;
                }
                let uses_namespace_alias = source_aliases.keys().any(|alias| {
                    identifier
                        .strip_prefix(alias)
                        .is_some_and(|suffix| suffix.starts_with("::"))
                });
                if uses_namespace_alias {
                    let candidates = visible_type_candidates(self, source_file, &identifier);
                    if target_classes
                        .iter()
                        .any(|target| candidates.contains(target))
                    {
                        return true;
                    }
                }
            }
        }
        let source_imports = self.using_namespaces_of(source_file);
        imports
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .chain(source_imports)
            .any(|namespace| target_namespaces.contains(&namespace))
            || source_aliases.values().any(|alias_target| {
                let candidates = visible_type_candidates(self, source_file, alias_target);
                self.declarations(target)
                    .into_iter()
                    .filter(|unit| unit.kind() == CodeUnitType::Class)
                    .any(|unit| candidates.contains(&unit))
            })
    }
}

impl CSharpAnalyzer {
    fn implicit_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.memo_caches.implicit_reference_index.get_or_build(
            || compute_implicit_reference_index(self, true),
            || compute_implicit_reference_index(self, false),
        )
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
        path: None,
        binder_span: None,
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
    if super::csharp_using_directive_is_static(node) {
        let mut cursor = node.walk();
        let target = node
            .named_children(&mut cursor)
            .find(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name"
                )
            })
            .map(|target| super::csharp_type_node_identity(target, source))?;
        return (!target.is_empty()).then_some(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: Some(target),
            alias: None,
            path: None,
            binder_span: None,
        });
    }
    csharp_using_alias_from_node(node, source).map(|(alias, target)| ImportInfo {
        raw_snippet: raw,
        is_wildcard: false,
        identifier: Some(target),
        alias: Some(alias),
        path: None,
        binder_span: None,
    })
}

pub(super) fn csharp_static_using_from_import(import: &ImportInfo) -> Option<&str> {
    if !import.is_wildcard && import.alias.is_none() {
        import.identifier.as_deref()
    } else {
        None
    }
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
    let target = super::csharp_type_node_identity(target_node, source);
    (!target.is_empty()).then_some((alias, target))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}
