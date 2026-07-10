use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, ProjectFile,
    build_reverse_file_index, build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

use super::ScalaAnalyzer;
use super::declarations::last_segment;

impl ScalaAnalyzer {
    fn resolve_import_info(&self, info: &ImportInfo) -> Vec<CodeUnit> {
        let Some(path) = scala_import_path(info) else {
            return Vec::new();
        };
        if info.is_wildcard {
            return self
                .importable_declarations_by_package()
                .get(&path)
                .map(|units| units.iter().cloned().collect())
                .unwrap_or_default();
        }
        self.inner.definitions(&path).collect()
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
            if file_language(file) != Language::Scala {
                continue;
            }
            if let Some(package) = self.inner.package_name_of(file) {
                files_by_package
                    .entry(package.to_string())
                    .or_default()
                    .push(file.clone());
            }
        }

        let files: Vec<_> = self.inner.all_files().cloned().collect();
        build_reverse_file_index(
            &files,
            |candidate| {
                if file_language(candidate) != Language::Scala {
                    return Vec::new();
                }
                let Some(package) = self.inner.package_name_of(candidate) else {
                    return Vec::new();
                };
                files_by_package.get(package).cloned().unwrap_or_default()
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
        let mut imported = HashSet::default();
        for info in self.inner.import_info_of(file) {
            for code_unit in self.resolve_import_info(info) {
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
        let reverse_index = self.reverse_import_index.get_or_build(
            || {
                let files: Vec<_> = self.inner.all_files().cloned().collect();
                build_reverse_import_index(
                    &files,
                    |candidate| self.imported_code_units_of(candidate),
                    true,
                )
            },
            || {
                let files: Vec<_> = self.inner.all_files().cloned().collect();
                build_reverse_import_index(
                    &files,
                    |candidate| self.imported_code_units_of(candidate),
                    false,
                )
            },
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

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
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

        let target_names: HashSet<String> = self
            .inner
            .top_level_declarations(target)
            .into_iter()
            .filter(is_scala_importable_top_level)
            .map(|unit| scala_importable_name(&unit))
            .collect();
        imports.iter().any(|info| {
            let Some(path) = scala_import_path(info) else {
                return false;
            };
            if info.is_wildcard {
                return path == target_package;
            }
            let Some((package, imported)) = path.rsplit_once('.') else {
                return false;
            };
            package == target_package && target_names.contains(imported)
        })
    }
}

pub(crate) fn parse_scala_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw
        .trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Some(prefix_end) = trimmed.find(".{") {
        let prefix = trimmed[..prefix_end].trim();
        let grouped = trimmed[prefix_end + 2..].trim_end_matches('}').trim();
        return split_scala_import_group(grouped)
            .into_iter()
            .filter_map(|part| {
                let (imported, alias) = split_scala_alias(&part);
                if imported.is_empty() {
                    return None;
                }
                let is_wildcard = matches!(imported.as_str(), "*" | "_");
                Some(ImportInfo {
                    raw_snippet: if let Some(alias) = &alias {
                        format!("import {prefix}.{imported} as {alias}")
                    } else if is_wildcard {
                        format!("import {prefix}.*")
                    } else {
                        format!("import {prefix}.{imported}")
                    },
                    is_wildcard,
                    identifier: (!is_wildcard)
                        .then(|| alias.clone().unwrap_or_else(|| imported.clone())),
                    alias,
                })
            })
            .collect();
    }

    let is_wildcard = trimmed.ends_with(".*") || trimmed.ends_with("._");
    let path = trimmed.trim_end_matches(".*").trim_end_matches("._").trim();
    let (path, alias) = split_scala_alias(path);
    let identifier = if is_wildcard {
        None
    } else {
        Some(
            alias
                .clone()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()).to_string()),
        )
    };
    vec![ImportInfo {
        raw_snippet: if let Some(alias) = &alias {
            format!("import {path} as {alias}")
        } else if is_wildcard {
            format!("import {path}.*")
        } else {
            format!("import {path}")
        },
        is_wildcard,
        identifier,
        alias,
    }]
}

fn split_scala_import_group(grouped: &str) -> Vec<String> {
    grouped
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_scala_alias(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    if let Some((name, alias)) = trimmed.split_once(" as ") {
        return (name.trim().to_string(), Some(alias.trim().to_string()));
    }
    if let Some((name, alias)) = trimmed.split_once(" => ") {
        return (name.trim().to_string(), Some(alias.trim().to_string()));
    }
    (trimmed.to_string(), None)
}

fn scala_import_path(info: &ImportInfo) -> Option<String> {
    let trimmed = info
        .raw_snippet
        .trim()
        .strip_prefix("import ")
        .unwrap_or(info.raw_snippet.trim())
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    if info.is_wildcard {
        return Some(trimmed.trim_end_matches(".*").to_string());
    }
    let (path, _) = split_scala_alias(trimmed);
    Some(path)
}

fn scala_importable_name(unit: &CodeUnit) -> String {
    last_segment(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}

fn is_scala_importable_top_level(unit: &CodeUnit) -> bool {
    if unit.short_name().contains('.') {
        return false;
    }
    unit.is_class() || unit.is_function() || unit.is_field()
}
