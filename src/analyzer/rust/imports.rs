use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile,
    build_reverse_import_index,
};
use crate::hash::HashSet;
use std::sync::Arc;

use super::RustAnalyzer;
use super::declarations::rust_package_name;

impl ImportAnalysisProvider for RustAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let package = rust_package_name(file);
        let mut resolved = HashSet::default();
        for import in self.inner.import_info_of(file) {
            if let Some(target_fq_name) =
                resolve_rust_import_fq_name(file, &package, &import.raw_snippet)
            {
                resolved.extend(self.inner.definitions(&target_fq_name).cloned());
            }
        }

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = self.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
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
        let package = rust_package_name(source_file);
        imports.iter().any(|import| {
            resolve_rust_import_fq_name(source_file, &package, &import.raw_snippet)
                .into_iter()
                .any(|fq_name| {
                    self.inner
                        .definitions(&fq_name)
                        .any(|code_unit| code_unit.source() == target)
                })
        })
    }
}

pub(super) fn flatten_rust_use(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let (prefix, body) = if let Some(body) = trimmed.strip_prefix("pub use ") {
        ("pub use ", body)
    } else if let Some(body) = trimmed.strip_prefix("use ") {
        ("use ", body)
    } else {
        return vec![format!("{trimmed};")];
    };
    expand_rust_use_body("", body)
        .into_iter()
        .map(|path| format!("{prefix}{path};"))
        .collect()
}

fn expand_rust_use_body(prefix: &str, body: &str) -> Vec<String> {
    let body = body.trim();
    if let Some(open_index) = body.find('{') {
        let close_index = body.rfind('}').unwrap_or(body.len());
        let base = body[..open_index].trim_end_matches("::").trim();
        let nested = &body[open_index + 1..close_index];
        let nested_prefix = if prefix.is_empty() {
            base.to_string()
        } else if base.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}::{base}")
        };
        split_top_level(nested)
            .into_iter()
            .flat_map(|item| {
                if item.trim() == "self" {
                    vec![nested_prefix.clone()]
                } else {
                    expand_rust_use_body(&nested_prefix, item.trim())
                }
            })
            .collect()
    } else {
        let leaf = if prefix.is_empty() {
            body.to_string()
        } else {
            format!("{prefix}::{body}")
        };
        vec![leaf]
    }
}

fn split_top_level(input: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, ch) in input.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                result.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        result.push(tail);
    }
    result
}

pub(super) fn parse_rust_import_info(raw: String) -> ImportInfo {
    let trimmed = raw
        .trim()
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    let is_wildcard = trimmed.ends_with("::*");
    let alias = trimmed
        .rsplit_once(" as ")
        .map(|(_, alias)| alias.trim().to_string());
    let path = trimmed
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(trimmed);
    let identifier = (!is_wildcard)
        .then(|| {
            path.rsplit("::")
                .next()
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
        })
        .flatten();

    ImportInfo {
        raw_snippet: raw,
        is_wildcard,
        identifier,
        alias,
    }
}

pub(super) fn split_rust_import_module_and_name(raw_import: &str) -> Option<(String, String)> {
    let trimmed = raw_import
        .trim()
        .trim_start_matches("pub ")
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    let path = trimmed
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(trimmed)
        .trim();
    if path.ends_with("::*") {
        return None;
    }

    let (module_specifier, imported_name) = path.rsplit_once("::")?;
    Some((module_specifier.to_string(), imported_name.to_string()))
}

pub(super) fn resolve_rust_module_path_with_crate(
    package: &str,
    crate_package: &str,
    module_specifier: &str,
) -> Option<String> {
    let trimmed = module_specifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "crate" {
        return Some(crate_package.to_string());
    }

    let segments: Vec<_> = trimmed
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }

    let resolved = match segments[0] {
        "crate" => crate_package
            .split('.')
            .filter(|segment| !segment.is_empty())
            .chain(segments[1..].iter().copied())
            .collect::<Vec<_>>()
            .join("."),
        "self" | "super" => {
            let mut package_parts: Vec<_> = package
                .split('.')
                .filter(|segment| !segment.is_empty())
                .collect();
            let mut index = 0usize;
            while matches!(segments.get(index), Some(&"self" | &"super")) {
                if segments[index] == "super" {
                    package_parts.pop()?;
                }
                index += 1;
            }
            package_parts
                .into_iter()
                .chain(segments[index..].iter().copied())
                .collect::<Vec<_>>()
                .join(".")
        }
        _ => segments.join("."),
    };

    Some(resolved)
}

pub(super) fn resolve_rust_import_fq_name(
    source_file: &ProjectFile,
    package: &str,
    raw_import: &str,
) -> Option<String> {
    let trimmed = raw_import
        .trim()
        .trim_start_matches("pub ")
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    let path = trimmed
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(trimmed)
        .trim_end_matches("::*")
        .trim();
    let segments: Vec<_> = path
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }

    let crate_package = rust_crate_root_package(source_file);
    resolve_rust_module_path_with_crate(package, &crate_package, path)
}

pub(super) fn rust_crate_root_package(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    let Some(src_index) = components.iter().position(|component| component == "src") else {
        return rust_package_name(file);
    };
    if src_index == 0 {
        return String::new();
    }
    components.truncate(src_index + 1);
    components.join(".")
}
