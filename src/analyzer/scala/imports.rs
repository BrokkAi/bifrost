use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, ProjectFile,
};
use crate::hash::HashSet;

use super::ScalaAnalyzer;
use super::declarations::last_segment;

impl ScalaAnalyzer {
    fn resolve_import_info(&self, info: &ImportInfo) -> Vec<CodeUnit> {
        let Some(path) = scala_import_path(info) else {
            return Vec::new();
        };
        if info.is_wildcard {
            return self
                .inner
                .all_declarations()
                .filter(|unit| unit.package_name() == path && is_scala_importable_top_level(unit))
                .cloned()
                .collect();
        }
        self.inner.definitions(&path).cloned().collect()
    }
}

impl ImportAnalysisProvider for ScalaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        let mut imported = HashSet::default();
        for info in self.inner.import_info_of(file) {
            for code_unit in self.resolve_import_info(info) {
                imported.insert(code_unit);
            }
        }
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut result = HashSet::default();
        if file_language(file) != Language::Scala {
            return result;
        }
        let Some(target_package) = self.inner.package_name_of(file) else {
            return result;
        };
        let target_names: HashSet<String> = self
            .inner
            .top_level_declarations(file)
            .filter(|unit| is_scala_importable_top_level(unit))
            .map(scala_importable_name)
            .collect();

        for candidate in self.inner.all_files() {
            if candidate == file {
                continue;
            }
            if self.inner.package_name_of(candidate).unwrap_or("") == target_package
                && self
                    .inner
                    .type_identifiers_of(candidate)
                    .is_some_and(|identifiers| {
                        identifiers
                            .iter()
                            .any(|identifier| target_names.contains(identifier))
                    })
            {
                result.insert(candidate.clone());
                continue;
            }
            if self.could_import_file(candidate, self.import_info_of(candidate), file) {
                result.insert(candidate.clone());
            }
        }
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
            .filter(|unit| is_scala_importable_top_level(unit))
            .map(scala_importable_name)
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
