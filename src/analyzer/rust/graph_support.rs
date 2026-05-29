use crate::analyzer::usages::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::HashSet;
use tree_sitter::{Node, Parser};

use super::RustAnalyzer;
use super::declarations::rust_package_name;
use super::imports::{resolve_rust_module_path, split_rust_import_module_and_name};

impl RustAnalyzer {
    pub fn export_index_of(&self, file: &ProjectFile) -> ExportIndex {
        let mut index = ExportIndex::empty();

        for code_unit in self.declarations(file) {
            let identifier = code_unit.identifier().trim();
            if identifier.is_empty() || identifier.starts_with('_') {
                continue;
            }
            if !self.is_module_export_candidate(code_unit) {
                continue;
            }
            index.exports_by_name.insert(
                identifier.to_string(),
                ExportEntry::Local {
                    local_name: identifier.to_string(),
                },
            );
        }

        for import in self.inner.import_info_of(file) {
            let raw = import.raw_snippet.trim();
            if !raw.starts_with("pub use ") {
                continue;
            }
            if let Some(module_specifier) = raw
                .strip_prefix("pub use ")
                .map(str::trim)
                .and_then(|value| value.strip_suffix("::*;"))
                .map(str::trim)
            {
                index.reexport_stars.push(ReexportStar {
                    module_specifier: module_specifier.to_string(),
                });
                continue;
            }
            let Some((module_specifier, imported_name)) =
                split_rust_import_module_and_name(&import.raw_snippet)
            else {
                continue;
            };
            let exported_name = import
                .alias
                .clone()
                .or_else(|| import.identifier.clone())
                .unwrap_or_else(|| imported_name.clone());
            if exported_name == "self" {
                continue;
            }
            index.exports_by_name.insert(
                exported_name,
                ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                },
            );
        }

        index
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(file) {
            let raw = import.raw_snippet.trim();
            if raw.ends_with("::*;") {
                let module_specifier = raw
                    .trim_start_matches("pub ")
                    .trim_start_matches("use ")
                    .trim_end_matches("::*;")
                    .trim()
                    .to_string();
                binder.bindings.insert(
                    format!("*:{module_specifier}"),
                    ImportBinding {
                        module_specifier,
                        kind: ImportKind::Glob,
                        imported_name: None,
                    },
                );
                continue;
            }
            let Some((module_specifier, imported_name)) =
                split_rust_import_module_and_name(&import.raw_snippet)
            else {
                continue;
            };
            let local_name = import
                .alias
                .clone()
                .or_else(|| import.identifier.clone())
                .unwrap_or_else(|| imported_name.clone());
            let (local_name, kind, imported_name, module_specifier) = if imported_name == "self" {
                let namespace_name = module_specifier
                    .rsplit("::")
                    .next()
                    .unwrap_or(module_specifier.as_str())
                    .to_string();
                (
                    namespace_name,
                    ImportKind::Namespace,
                    None,
                    module_specifier,
                )
            } else if !raw.contains('{')
                && imported_name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_')
            {
                (
                    imported_name.clone(),
                    ImportKind::Namespace,
                    None,
                    format!("{module_specifier}::{imported_name}"),
                )
            } else {
                (
                    local_name,
                    ImportKind::Named,
                    Some(imported_name),
                    module_specifier,
                )
            };

            binder.bindings.insert(
                local_name,
                ImportBinding {
                    module_specifier,
                    kind,
                    imported_name,
                },
            );
        }

        binder
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        let package = rust_package_name(importing_file);
        let Some(resolved_module) = resolve_rust_module_path(&package, module_specifier) else {
            return Vec::new();
        };

        let mut files: Vec<_> = self
            .get_analyzed_files()
            .into_iter()
            .filter(|file| rust_package_name(file) == resolved_module)
            .collect();
        files.extend(self.get_analyzed_files().into_iter().filter(|file| {
            self.declarations(file).any(|code_unit| {
                code_unit.is_module()
                    && code_unit.short_name() == resolved_module
                    && (*file == *importing_file || self.is_visible_module_path(code_unit))
            })
        }));
        files.sort();
        files.dedup();
        files
    }

    pub fn exact_member(
        &self,
        source_file: &ProjectFile,
        owner_name: &str,
        member_name: &str,
        _instance_receiver: bool,
    ) -> Option<CodeUnit> {
        self.declarations(source_file)
            .find(|code_unit| {
                code_unit.identifier() == member_name
                    && self
                        .parent_of(code_unit)
                        .map(|parent| parent.identifier() == owner_name)
                        .unwrap_or(false)
            })
            .cloned()
    }

    pub fn rust_usage_candidate_files(
        &self,
        export_names: HashSet<String>,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        let owner_source = self
            .parent_of(target)
            .map(|owner| owner.source().clone())
            .unwrap_or_else(|| target.source().clone());
        let member_name = target.identifier().to_string();

        let project = self.inner.project();
        self.referencing_files_of(&owner_source)
            .into_iter()
            .filter(|file| {
                project.read_source(file).ok().is_some_and(|source| {
                    export_names.iter().any(|name| source.contains(name))
                        || source.contains(&member_name)
                })
            })
            .collect()
    }

    pub fn trait_implementer_names(
        &self,
        trait_owner: &CodeUnit,
        _importer_file: &ProjectFile,
    ) -> HashSet<String> {
        let project = self.inner.project();
        self.get_analyzed_files()
            .into_iter()
            .filter_map(|file| {
                let source = project.read_source(&file).ok()?;
                Some((file, source))
            })
            .flat_map(|(file, source)| {
                let binder = self.import_binder_of(&file);
                trait_implementer_names_from_source(self, trait_owner, &file, &source, &binder)
            })
            .collect()
    }

    pub(crate) fn is_rust_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "trait_item")
    }

    pub(crate) fn is_rust_enum_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "enum_item")
    }

    pub(crate) fn is_rust_public_like_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_visibility_text(node, source)
                .is_some_and(|visibility| visibility.starts_with("pub"))
        })
    }

    fn is_export_public_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_visibility_text(node, source).is_some_and(is_export_visibility)
        })
    }

    fn is_module_export_candidate(&self, code_unit: &CodeUnit) -> bool {
        if !self.is_export_public_declaration(code_unit) {
            return false;
        }

        let mut current = code_unit.clone();
        while let Some(parent) = self.parent_of(&current) {
            if !parent.is_module() || !self.is_export_public_declaration(&parent) {
                return false;
            }
            current = parent;
        }

        !code_unit.is_function() || self.parent_of(code_unit).is_none()
    }

    fn is_visible_module_path(&self, code_unit: &CodeUnit) -> bool {
        let mut current = code_unit.clone();
        loop {
            if !current.is_module() || !self.is_export_public_declaration(&current) {
                return false;
            }
            let Some(parent) = self.parent_of(&current) else {
                return true;
            };
            current = parent;
        }
    }

    fn rust_declaration_node_is<F>(&self, code_unit: &CodeUnit, predicate: F) -> bool
    where
        F: FnOnce(Node<'_>, &str) -> bool,
    {
        let Ok(source) = self.inner.project().read_source(code_unit.source()) else {
            return false;
        };
        let Some(range) = self.ranges(code_unit).first() else {
            return false;
        };
        let Some(tree) = parse_rust_tree(&source) else {
            return false;
        };
        tree.root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
            .map(|node| predicate(node, &source))
            .unwrap_or(false)
    }
}

fn parse_rust_tree(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn rust_visibility_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .find(|child| child.kind() == "visibility_modifier")
        .and_then(|child| source.get(child.start_byte()..child.end_byte()))
        .map(str::trim)
}

fn is_export_visibility(visibility: &str) -> bool {
    let compact: String = visibility
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    compact == "pub" || compact == "pub(crate)" || compact.starts_with("pub(incrate")
}

fn trait_implementer_names_from_source(
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
) -> Vec<String> {
    let Some(tree) = parse_rust_tree(source) else {
        return Vec::new();
    };
    let mut implementers = Vec::new();
    collect_trait_implementer_names(
        tree.root_node(),
        analyzer,
        trait_owner,
        impl_file,
        source,
        binder,
        &mut implementers,
    );
    implementers
}

fn collect_trait_implementer_names(
    node: Node<'_>,
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
    implementers: &mut Vec<String>,
) {
    if node.kind() == "impl_item"
        && let Some((trait_ref, implementer)) = trait_impl_parts(node, source)
        && trait_reference_matches(analyzer, trait_owner, impl_file, &trait_ref, binder)
    {
        implementers.push(implementer);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_trait_implementer_names(
            child,
            analyzer,
            trait_owner,
            impl_file,
            source,
            binder,
            implementers,
        );
    }
}

fn trait_impl_parts(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let trait_node = node.child_by_field_name("trait")?;
    let type_node = node.child_by_field_name("type")?;
    Some((
        node_text(trait_node, source).to_string(),
        simple_type_name(type_node, source)?,
    ))
}

fn simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => Some(node_text(node, source).to_string()),
        "scoped_type_identifier" | "scoped_identifier" => node
            .child_by_field_name("name")
            .map(|name| node_text(name, source).to_string()),
        "generic_type" | "reference_type" => node
            .named_children(&mut node.walk())
            .find_map(|child| simple_type_name(child, source)),
        _ => node
            .named_children(&mut node.walk())
            .find_map(|child| simple_type_name(child, source)),
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}

fn trait_reference_matches(
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    trait_ref: &str,
    impl_binder: &ImportBinder,
) -> bool {
    if let Some((module_specifier, imported_name)) = trait_ref.rsplit_once("::") {
        return imported_name == trait_owner.identifier()
            && analyzer
                .resolve_module_files(impl_file, module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source());
    }

    if impl_file == trait_owner.source() && trait_ref == trait_owner.identifier() {
        return true;
    }

    impl_binder
        .bindings
        .get(trait_ref)
        .filter(|binding| binding.imported_name.as_deref() == Some(trait_owner.identifier()))
        .is_some_and(|binding| {
            analyzer
                .resolve_module_files(impl_file, &binding.module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source())
        })
}
