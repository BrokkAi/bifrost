use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, ProjectFile,
    StructuredImportPath, StructuredImportScope, build_reverse_file_index,
};
use crate::hash::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tree_sitter::Node;

use super::ScalaAnalyzer;
use super::wildcard_imports::{
    ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaWildcardImportEnvironment,
    ScalaWildcardImportOwner, ScalaWildcardOwnerFacts, ScalaWildcardOwnerKind,
    resolve_scala_explicit_import_tier, resolve_scala_wildcard_import_environment,
    scala_import_path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ScalaExportSelector {
    Wildcard,
    GivenWildcard,
    Named {
        source_name: String,
        visible_name: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ScalaExportInfo {
    pub(crate) owner_path: Vec<String>,
    pub(crate) selectors: Vec<ScalaExportSelector>,
    pub(crate) declaration_start_byte: usize,
}

impl ScalaAnalyzer {
    fn resolve_import_info(
        &self,
        file: &ProjectFile,
        import_index: usize,
        info: &ImportInfo,
        wildcard_environment: &ScalaWildcardImportEnvironment,
    ) -> Vec<CodeUnit> {
        let Some(path) = scala_import_path(info) else {
            return Vec::new();
        };
        if info.is_wildcard {
            let mut imported = Vec::new();
            for owner in wildcard_environment
                .owners
                .iter()
                .filter(|owner| owner.import_index == import_index)
            {
                imported.extend(self.resolve_wildcard_owner(owner));
            }
            imported.sort();
            imported.dedup();
            return imported;
        }
        let Some(source_package) = self.inner.package_name_of(file) else {
            return Vec::new();
        };
        let Some(tier) =
            self.explicit_import_tier(info, &path, std::slice::from_ref(&source_package))
        else {
            return Vec::new();
        };
        let mut imported = Vec::new();
        if tier.declaration {
            imported.extend(self.inner.definitions(&tier.candidate));
        }
        if tier.package {
            let descendant_prefix = format!("{}.", tier.candidate);
            let packages = self.package_namespaces();
            let start = packages.partition_point(|package| package < &tier.candidate);
            for package in packages[start..].iter().take_while(|package| {
                package.as_str() == tier.candidate || package.starts_with(&descendant_prefix)
            }) {
                if let Some(declarations) = self.importable_declarations_by_package().get(package) {
                    imported.extend(declarations.iter().cloned());
                }
            }
        }
        imported.sort();
        imported.dedup();
        imported
    }

    fn resolve_wildcard_owner(&self, owner: &ScalaWildcardImportOwner) -> Vec<CodeUnit> {
        match owner.kind {
            ScalaWildcardOwnerKind::Package => self
                .importable_declarations_by_package()
                .get(&owner.fqn)
                .map(|units| units.iter().cloned().collect())
                .unwrap_or_default(),
            ScalaWildcardOwnerKind::StableSingleton => {
                let mut imported = Vec::new();
                for declaration in self
                    .inner
                    .definitions(&owner.declaration_fqn())
                    .filter(CodeUnit::is_class)
                {
                    imported.extend(
                        self.inner
                            .direct_children(&declaration)
                            .into_iter()
                            .filter(is_scala_importable_direct_member),
                    );
                    for (_, target_fqn) in self
                        .project_types()
                        .exported_member_bindings(self, &declaration)
                    {
                        imported.extend(
                            self.inner
                                .definitions(&target_fqn)
                                .filter(is_scala_importable_direct_member),
                        );
                    }
                }
                imported.sort();
                imported.dedup();
                imported
            }
        }
    }

    fn wildcard_owner_facts(&self, candidate: &str) -> ScalaWildcardOwnerFacts {
        let singleton_fqn = format!("{}$", candidate.trim_end_matches('$'));
        ScalaWildcardOwnerFacts {
            package: self
                .importable_declarations_by_package()
                .contains_key(candidate),
            stable_singleton: self
                .inner
                .definitions(&singleton_fqn)
                .any(|unit| unit.is_class() && unit.fq_name() == singleton_fqn),
        }
    }

    fn wildcard_import_environment(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> ScalaWildcardImportEnvironment {
        let mut package_prefixes = Vec::new();
        if package_prefixes.is_empty()
            && let Some(package) = self.inner.package_name_of(file)
        {
            package_prefixes.push(package.to_string());
        }
        resolve_scala_wildcard_import_environment(imports, &package_prefixes, |candidate| {
            self.wildcard_owner_facts(candidate)
        })
    }

    fn importable_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>> {
        self.importable_declarations_by_package.get_or_init(|| {
            let mut declarations: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for unit in self.inner.all_declarations() {
                if is_scala_importable_top_level(&unit) {
                    declarations
                        .entry(unit.package_name().to_string())
                        .or_default()
                        .push(unit.clone());
                }
            }
            declarations
                .into_iter()
                .map(|(package, units)| (package, Arc::new(units)))
                .collect()
        })
    }

    fn package_namespaces(&self) -> &[String] {
        self.package_namespaces.get_or_init(|| {
            let mut packages = self
                .importable_declarations_by_package()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            packages.sort_unstable();
            packages
        })
    }

    fn package_namespace_exists(&self, candidate: &str) -> bool {
        let descendant_prefix = format!("{candidate}.");
        let packages = self.package_namespaces();
        let index = packages.partition_point(|package| package.as_str() < candidate);
        packages
            .get(index)
            .is_some_and(|package| package == candidate || package.starts_with(&descendant_prefix))
    }

    fn explicit_import_tier(
        &self,
        info: &ImportInfo,
        path: &str,
        fallback_package_prefixes: &[String],
    ) -> Option<ScalaExplicitImportTier> {
        let lexical_prefixes = info
            .path
            .as_ref()
            .map(|path| path.lexical_prefixes.as_slice())
            .filter(|prefixes| !prefixes.is_empty());
        let package_prefixes = lexical_prefixes.unwrap_or(fallback_package_prefixes);
        resolve_scala_explicit_import_tier(path, package_prefixes, |candidate| {
            ScalaExplicitImportFacts {
                declaration: self.inner.definitions(candidate).next().is_some(),
                package: self.package_namespace_exists(candidate),
            }
        })
    }

    fn same_package_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.same_package_reference_index.get_or_build(
            || self.compute_same_package_reference_index(true),
            || self.compute_same_package_reference_index(false),
        )
    }

    fn compute_same_package_reference_index(
        &self,
        parallel: bool,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let mut files_by_package: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for file in self.inner.all_files() {
            if file_language(&file) != Language::Scala {
                continue;
            }
            if let Some(package) = self.inner.package_name_of(&file) {
                files_by_package
                    .entry(package.to_string())
                    .or_default()
                    .push(file.clone());
            }
        }

        let files: Vec<_> = self.inner.all_files();
        build_reverse_file_index(
            &files,
            |candidate| {
                if file_language(candidate) != Language::Scala {
                    return Vec::new();
                }
                let Some(package) = self.inner.package_name_of(candidate) else {
                    return Vec::new();
                };
                files_by_package.get(&package).cloned().unwrap_or_default()
            },
            parallel,
        )
    }
}

impl ImportAnalysisProvider for ScalaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Scala {
            return HashSet::default();
        }
        let imports = self.inner.import_info_of(file);
        let wildcard_environment = self.wildcard_import_environment(file, &imports);
        let mut imported = HashSet::default();
        for (import_index, info) in imports.iter().enumerate() {
            for code_unit in
                self.resolve_import_info(file, import_index, info, &wildcard_environment)
            {
                imported.insert(code_unit);
            }
        }
        self.imported_code_units
            .insert(file.clone(), Arc::new(imported.clone()));
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Scala {
            return HashSet::default();
        }
        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        if let Some(files) = self.same_package_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        self.referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
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
        if file_language(source_file) != Language::Scala || file_language(target) != Language::Scala
        {
            return false;
        }

        let Some(source_package) = self.inner.package_name_of(source_file) else {
            return false;
        };
        let Some(target_package) = self.inner.package_name_of(target) else {
            return false;
        };
        if source_package == target_package {
            return true;
        }

        let wildcard_environment = self.wildcard_import_environment(source_file, imports);
        if wildcard_environment
            .owners
            .iter()
            .any(|owner| match owner.kind {
                ScalaWildcardOwnerKind::Package => owner.fqn == target_package,
                ScalaWildcardOwnerKind::StableSingleton => self
                    .resolve_wildcard_owner(owner)
                    .iter()
                    .any(|declaration| declaration.source() == target),
            })
        {
            return true;
        }

        imports.iter().any(|info| {
            let Some(path) = scala_import_path(info) else {
                return false;
            };
            if info.is_wildcard {
                return false;
            }
            let Some(tier) =
                self.explicit_import_tier(info, &path, std::slice::from_ref(&source_package))
            else {
                return false;
            };
            let declaration_reaches = tier.declaration
                && self
                    .inner
                    .definitions(&tier.candidate)
                    .any(|declaration| declaration.source() == target);
            let package_reaches = tier.package
                && (target_package == tier.candidate
                    || target_package
                        .strip_prefix(&tier.candidate)
                        .is_some_and(|suffix| suffix.starts_with('.')));
            declaration_reaches || package_reaches
        })
    }
}

pub(crate) fn scala_import_infos_from_node(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    scala_import_infos_from_node_with_prefixes(node, source, &[])
}

pub(crate) fn scala_import_infos_from_node_with_prefixes(
    node: Node<'_>,
    source: &str,
    lexical_prefixes: &[String],
) -> Vec<ImportInfo> {
    if node.kind() != "import_declaration" {
        return Vec::new();
    }
    let mut path_cursor = node.walk();
    let base_path = node
        .children_by_field_name("path", &mut path_cursor)
        .filter(Node::is_named)
        .map(|segment| scala_node_text(segment, source).to_string())
        .collect::<Vec<_>>();
    if base_path.is_empty() {
        return Vec::new();
    }
    let lexical_scopes = scala_lexical_scope_path(node);

    let mut infos = Vec::new();
    let mut cursor = node.walk();
    let direct_children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let Some(selectors) = direct_children
        .iter()
        .find(|child| child.kind() == "namespace_selectors")
    {
        let mut selector_cursor = selectors.walk();
        for selector in selectors.named_children(&mut selector_cursor) {
            if let Some(info) = scala_import_selector_info(
                selector,
                &base_path,
                lexical_prefixes,
                &lexical_scopes,
                node.start_byte(),
                source,
            ) {
                infos.push(info);
            }
        }
        return infos;
    }

    if let Some(selector) = direct_children.iter().find(|child| {
        matches!(
            child.kind(),
            "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
        )
    }) {
        return scala_import_selector_info(
            *selector,
            &base_path,
            lexical_prefixes,
            &lexical_scopes,
            node.start_byte(),
            source,
        )
        .into_iter()
        .collect();
    }

    let identifier = base_path.last().cloned();
    vec![ImportInfo {
        raw_snippet: render_scala_import(&base_path, false, None),
        is_wildcard: false,
        identifier,
        alias: None,
        path: Some(StructuredImportPath {
            segments: base_path,
            lexical_prefixes: lexical_prefixes.to_vec(),
            lexical_scopes,
            declaration_start_byte: node.start_byte(),
        }),
    }]
}

pub(crate) fn scala_export_info_from_node(node: Node<'_>, source: &str) -> Option<ScalaExportInfo> {
    if node.kind() != "export_declaration" {
        return None;
    }
    let mut path_cursor = node.walk();
    let mut owner_path = node
        .children_by_field_name("path", &mut path_cursor)
        .filter(Node::is_named)
        .map(|segment| scala_node_text(segment, source).to_string())
        .collect::<Vec<_>>();
    if owner_path.is_empty() {
        return None;
    }

    let mut selectors = Vec::new();
    let mut cursor = node.walk();
    let direct_children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let Some(namespace_selectors) = direct_children
        .iter()
        .find(|child| child.kind() == "namespace_selectors")
    {
        let mut selector_cursor = namespace_selectors.walk();
        for selector in namespace_selectors.named_children(&mut selector_cursor) {
            if let Some(selector) = scala_export_selector(selector, source) {
                selectors.push(selector);
            }
        }
    } else if let Some(selector) = direct_children.iter().find(|child| {
        matches!(
            child.kind(),
            "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
        )
    }) {
        selectors.push(scala_export_selector(*selector, source)?);
    } else {
        let source_name = owner_path.pop()?;
        selectors.push(ScalaExportSelector::Named {
            visible_name: Some(source_name.clone()),
            source_name,
        });
    }

    (!selectors.is_empty()).then_some(ScalaExportInfo {
        owner_path,
        selectors,
        declaration_start_byte: node.start_byte(),
    })
}

fn scala_export_selector(node: Node<'_>, source: &str) -> Option<ScalaExportSelector> {
    match node.kind() {
        "namespace_wildcard" => {
            let given = (0..node.child_count()).any(|index| {
                node.child(index)
                    .is_some_and(|child| !child.is_named() && child.kind() == "given")
            });
            Some(if given {
                ScalaExportSelector::GivenWildcard
            } else {
                ScalaExportSelector::Wildcard
            })
        }
        "identifier" | "operator_identifier" => {
            let source_name = scala_node_text(node, source).to_string();
            Some(ScalaExportSelector::Named {
                visible_name: Some(source_name.clone()),
                source_name,
            })
        }
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let name = node.child_by_field_name("name")?;
            let alias = node.child_by_field_name("alias")?;
            let source_name = scala_node_text(name, source).to_string();
            let visible_name =
                (alias.kind() != "wildcard").then(|| scala_node_text(alias, source).to_string());
            Some(ScalaExportSelector::Named {
                source_name,
                visible_name,
            })
        }
        _ => None,
    }
}

fn scala_import_selector_info(
    selector: Node<'_>,
    base_path: &[String],
    lexical_prefixes: &[String],
    lexical_scopes: &[StructuredImportScope],
    declaration_start_byte: usize,
    source: &str,
) -> Option<ImportInfo> {
    if selector.kind() == "namespace_wildcard" {
        return Some(ImportInfo {
            raw_snippet: render_scala_import(base_path, true, None),
            is_wildcard: true,
            identifier: None,
            alias: None,
            path: Some(StructuredImportPath {
                segments: base_path.to_vec(),
                lexical_prefixes: lexical_prefixes.to_vec(),
                lexical_scopes: lexical_scopes.to_vec(),
                declaration_start_byte,
            }),
        });
    }

    let (name, alias) = match selector.kind() {
        "identifier" | "operator_identifier" => {
            (scala_node_text(selector, source).to_string(), None)
        }
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let name = selector.child_by_field_name("name")?;
            let alias = selector.child_by_field_name("alias")?;
            if alias.kind() == "wildcard" {
                return None;
            }
            (
                scala_node_text(name, source).to_string(),
                Some(scala_node_text(alias, source).to_string()),
            )
        }
        _ => return None,
    };
    let mut path = base_path.to_vec();
    path.push(name.clone());
    Some(ImportInfo {
        raw_snippet: render_scala_import(&path, false, alias.as_deref()),
        is_wildcard: false,
        identifier: Some(alias.clone().unwrap_or(name)),
        alias,
        path: Some(StructuredImportPath {
            segments: path,
            lexical_prefixes: lexical_prefixes.to_vec(),
            lexical_scopes: lexical_scopes.to_vec(),
            declaration_start_byte,
        }),
    })
}

pub(crate) fn scala_lexical_scope_path(node: Node<'_>) -> Vec<StructuredImportScope> {
    let mut scopes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if is_scala_lexical_scope(parent.kind()) {
            scopes.push(StructuredImportScope {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
            });
        }
        current = parent.parent();
    }
    scopes.reverse();
    scopes
}

pub(crate) fn scala_lexical_scope_path_at(
    root: Node<'_>,
    byte: usize,
) -> Vec<StructuredImportScope> {
    let end = byte.saturating_add(1).min(root.end_byte());
    let node = root
        .descendant_for_byte_range(byte.min(end), end)
        .unwrap_or(root);
    scala_lexical_scope_path(node)
}

fn is_scala_lexical_scope(kind: &str) -> bool {
    matches!(
        kind,
        "package_clause"
            | "template_body"
            | "block"
            | "indented_block"
            | "function_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "extension_definition"
    )
}

fn render_scala_import(path: &[String], wildcard: bool, alias: Option<&str>) -> String {
    let mut rendered = format!("import {}", path.join("."));
    if wildcard {
        rendered.push_str(".*");
    } else if let Some(alias) = alias {
        rendered.push_str(" as ");
        rendered.push_str(alias);
    }
    rendered
}

fn scala_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn is_scala_importable_top_level(unit: &CodeUnit) -> bool {
    if unit.short_name().contains('.') {
        return false;
    }
    unit.is_class() || unit.is_function() || unit.is_field()
}

fn is_scala_importable_direct_member(unit: &CodeUnit) -> bool {
    unit.is_class() || unit.is_function() || unit.is_field()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parsed_export(source: &str) -> ScalaExportInfo {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
            .expect("Scala parser");
        let tree = parser.parse(source, None).expect("Scala syntax tree");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "export_declaration" {
                return scala_export_info_from_node(node, source).expect("structured export");
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("missing export declaration in {source:?}");
    }

    #[test]
    fn scala_export_parser_preserves_selector_semantics() {
        let export = parsed_export(
            "object Facade { export Core.{dropped as _, original as renamed, kept, *} }",
        );
        assert_eq!(export.owner_path, ["Core"]);
        assert_eq!(
            export.selectors,
            [
                ScalaExportSelector::Named {
                    source_name: "dropped".to_string(),
                    visible_name: None,
                },
                ScalaExportSelector::Named {
                    source_name: "original".to_string(),
                    visible_name: Some("renamed".to_string()),
                },
                ScalaExportSelector::Named {
                    source_name: "kept".to_string(),
                    visible_name: Some("kept".to_string()),
                },
                ScalaExportSelector::Wildcard,
            ]
        );
    }

    #[test]
    fn scala_export_parser_distinguishes_given_from_ordinary_wildcard() {
        let given = parsed_export("object Facade { export Core.given }");
        assert_eq!(given.selectors, [ScalaExportSelector::GivenWildcard]);
        let ordinary = parsed_export("object Facade { export Core.* }");
        assert_eq!(ordinary.selectors, [ScalaExportSelector::Wildcard]);
    }
}
