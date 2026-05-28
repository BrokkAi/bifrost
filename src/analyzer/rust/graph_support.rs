use crate::analyzer::usages::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::HashSet;
use regex::Regex;
use std::sync::LazyLock;

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
                TRAIT_IMPL_RE
                    .captures_iter(&source)
                    .filter_map(|captures| {
                        let trait_ref = captures.get(1)?.as_str().trim();
                        let implementer = captures.get(2)?.as_str().trim();
                        trait_reference_matches(self, trait_owner, &file, trait_ref, &binder)
                            .then(|| implementer.to_string())
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn is_public_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.get_source(code_unit, false)
            .or_else(|| self.get_skeleton_header(code_unit))
            .map(|source| {
                let trimmed = source.trim_start();
                trimmed.starts_with("pub ")
                    || trimmed.starts_with("pub(crate)")
                    || trimmed.starts_with("pub(in crate")
                    || code_unit.is_module() && trimmed.starts_with("pub mod ")
            })
            .unwrap_or(false)
    }

    fn is_module_export_candidate(&self, code_unit: &CodeUnit) -> bool {
        if !self.is_public_declaration(code_unit) {
            return false;
        }

        let mut current = code_unit.clone();
        while let Some(parent) = self.parent_of(&current) {
            if !parent.is_module() || !self.is_public_declaration(&parent) {
                return false;
            }
            current = parent;
        }

        !code_unit.is_function() || self.parent_of(code_unit).is_none()
    }

    fn is_visible_module_path(&self, code_unit: &CodeUnit) -> bool {
        let mut current = code_unit.clone();
        loop {
            if !current.is_module() || !self.is_public_declaration(&current) {
                return false;
            }
            let Some(parent) = self.parent_of(&current) else {
                return true;
            };
            current = parent;
        }
    }
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

static TRAIT_IMPL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bimpl\s+([A-Za-z_][A-Za-z0-9_:]*)\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid trait impl regex")
});
