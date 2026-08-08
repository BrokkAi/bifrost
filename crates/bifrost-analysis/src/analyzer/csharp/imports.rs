use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile,
    StructuredImportPath, StructuredImportPathKind, build_reverse_file_index,
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
                    let candidates = self.visible_type_candidates(source_file, &identifier);
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
            .filter_map(csharp_using_namespace)
            .chain(source_imports)
            .any(|namespace| target_namespaces.contains(&namespace))
            || source_aliases.values().any(|alias_target| {
                let candidates = self.visible_type_candidates(source_file, alias_target);
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
            || self.compute_implicit_reference_index(true),
            || self.compute_implicit_reference_index(false),
        )
    }

    fn compute_implicit_reference_index(
        &self,
        parallel: bool,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let mut by_namespace_and_name: HashMap<String, HashMap<String, Vec<ProjectFile>>> =
            HashMap::default();
        let mut by_fq_name: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        let mut namespaces_by_file: HashMap<ProjectFile, Vec<String>> = HashMap::default();
        let files: Vec<_> = self.inner.all_files();
        for target in &files {
            let top_level = self.inner.top_level_declarations(target);
            let mut namespaces = HashSet::default();
            for unit in &top_level {
                namespaces.insert(unit.package_name().to_string());
            }
            if namespaces.is_empty() {
                namespaces.insert(String::new());
            }
            namespaces_by_file.insert(target.clone(), namespaces.into_iter().collect());

            for unit in top_level
                .into_iter()
                .filter(|unit| unit.kind() == CodeUnitType::Class)
            {
                by_namespace_and_name
                    .entry(unit.package_name().to_string())
                    .or_default()
                    .entry(unit.identifier().to_string())
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

        build_reverse_file_index(
            &files,
            |candidate| {
                let Some(identifiers) = self.inner.type_identifiers_of(candidate) else {
                    return Vec::new();
                };
                let candidate_namespaces = namespaces_by_file
                    .get(candidate)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let mut resolved_targets = Vec::new();
                for identifier in identifiers {
                    for candidate_namespace in candidate_namespaces {
                        if let Some(namespace_targets) = by_namespace_and_name
                            .get(candidate_namespace)
                            .and_then(|by_name| by_name.get(&identifier))
                        {
                            resolved_targets.extend(namespace_targets.iter().cloned());
                        }
                    }
                    if let Some(fq_targets) = by_fq_name.get(&identifier) {
                        resolved_targets.extend(fq_targets.iter().cloned());
                    }
                    // Attribute names can be structurally alias-qualified or
                    // `global::` qualified. Resolve only those uncommon persisted
                    // identities through the normal C# visible-type resolver so
                    // default candidate routing agrees with authoritative scanning.
                    if identifier.contains("::") {
                        resolved_targets.extend(
                            self.visible_type_candidates(candidate, &identifier)
                                .into_iter()
                                .map(|unit| unit.source().clone()),
                        );
                    }
                }
                resolved_targets
            },
            parallel,
        )
    }
}

/// The namespace a plain `using` directive imports, from its structured path.
///
/// A plain `using System.Text;` is the only form that names a namespace: a
/// `using static` names a type and a `using A = X;` names an alias target, and
/// each records its own `path_kind`. The value is the path's segments rejoined
/// with '.', which is the spelling the parser saw.
pub(super) fn csharp_using_namespace(import: &ImportInfo) -> Option<String> {
    let path = import.path.as_ref()?;
    (path.kind == Some(StructuredImportPathKind::Namespace))
        .then(|| path.render_segments("."))
        .filter(|namespace| !namespace.is_empty())
}

pub(super) fn csharp_import_info_from_using_directive(
    node: Node<'_>,
    source: &str,
    raw: String,
) -> Option<ImportInfo> {
    let is_global = super::csharp_using_directive_is_global(node);
    let declaration_start_byte = node.start_byte();
    let structured_path = |segments: Vec<String>, kind: StructuredImportPathKind| {
        StructuredImportPath {
            segments,
            kind: Some(kind),
            // A C# using directive sits at file or namespace level, and the
            // namespace it sits in is already each unit's own package, so there
            // is no prefix or enclosing block extent to record here.
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte,
        }
    };

    if let Some(target) = super::csharp_using_directive_namespace_node(node) {
        let segments = super::csharp_type_node_segments(target, source);
        if segments.is_empty() {
            return None;
        }
        // A plain `using` imports every name under the namespace, so it binds
        // no single token, and its `identifier` is the namespace's own tail.
        let identifier = segments.last().cloned();
        return Some(ImportInfo {
            raw_snippet: raw,
            is_wildcard: true,
            is_global,
            identifier,
            alias: None,
            path: Some(structured_path(
                segments,
                StructuredImportPathKind::Namespace,
            )),
            binder_span: None,
        });
    }

    if super::csharp_using_directive_is_static(node) {
        let mut cursor = node.walk();
        let target = node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name"
            )
        })?;
        let segments = super::csharp_type_node_segments(target, source);
        if segments.is_empty() {
            return None;
        }
        return Some(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            is_global,
            identifier: Some(segments.join(".")),
            alias: None,
            path: Some(structured_path(
                segments,
                StructuredImportPathKind::StaticMember,
            )),
            binder_span: None,
        });
    }

    let alias_node = node.child_by_field_name("name")?;
    let alias = node_text(alias_node, source).trim();
    if alias.is_empty() {
        return None;
    }
    let mut cursor = node.walk();
    let target_node = node.named_children(&mut cursor).find(|child| {
        child.start_byte() >= alias_node.end_byte() && child.id() != alias_node.id()
    })?;
    let segments = super::csharp_type_node_segments(target_node, source);
    if segments.is_empty() {
        return None;
    }
    // `using A = X.Y;` binds exactly one name, spelled by the alias token.
    Some(ImportInfo {
        raw_snippet: raw,
        is_wildcard: false,
        is_global,
        identifier: Some(segments.join(".")),
        alias: Some(alias.to_string()),
        path: Some(structured_path(
            segments,
            StructuredImportPathKind::ImportFrom,
        )),
        binder_span: Some(crate::analyzer::common::node_span(alias_node)),
    })
}

/// The type a `using static` directive imports, from its structured path.
pub(super) fn csharp_static_using_from_import(import: &ImportInfo) -> Option<&str> {
    let path = import.path.as_ref()?;
    (path.kind == Some(StructuredImportPathKind::StaticMember))
        .then_some(import.identifier.as_deref())
        .flatten()
}

pub(super) fn csharp_using_alias_from_import(import: &ImportInfo) -> Option<(String, String)> {
    Some((import.alias.clone()?, import.identifier.clone()?))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}
