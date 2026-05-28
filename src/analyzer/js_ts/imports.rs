use crate::analyzer::{ImportInfo, Language, ProjectFile};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) fn parse_js_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    if trimmed.starts_with("import ") {
        parse_es_import_infos(raw)
    } else if trimmed.contains("require(") {
        parse_require_import_infos(raw)
    } else {
        Vec::new()
    }
}

fn parse_es_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    if !trimmed.starts_with("import ") {
        return Vec::new();
    }
    let Some((head, _path)) = trimmed[7..].rsplit_once(" from ") else {
        return vec![ImportInfo {
            raw_snippet: raw.trim().to_string(),
            is_wildcard: false,
            identifier: None,
            alias: None,
        }];
    };
    let head = strip_import_type_prefix(head.trim());
    if head.starts_with('*') {
        return vec![ImportInfo {
            raw_snippet: raw.trim().to_string(),
            is_wildcard: true,
            identifier: None,
            alias: head.split_whitespace().last().map(str::to_string),
        }];
    }
    if head.starts_with('{') {
        return parse_named_imports(raw, head);
    }
    let mut imports = Vec::new();
    if let Some((default_import, named)) = head.split_once(',') {
        let default_import = default_import.trim();
        if !default_import.is_empty() {
            imports.push(ImportInfo {
                raw_snippet: raw.trim().to_string(),
                is_wildcard: false,
                identifier: Some(default_import.to_string()),
                alias: None,
            });
        }
        imports.extend(parse_named_imports(raw, named));
        return imports;
    }
    vec![ImportInfo {
        raw_snippet: raw.trim().to_string(),
        is_wildcard: false,
        identifier: Some(head.to_string()),
        alias: None,
    }]
}

fn parse_named_imports(raw: &str, named: &str) -> Vec<ImportInfo> {
    named
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .filter_map(|entry| {
            let entry = strip_import_type_prefix(entry.trim());
            if entry.is_empty() {
                return None;
            }
            let (identifier, alias) = entry
                .split_once(" as ")
                .map(|(identifier, alias)| (identifier.trim(), Some(alias.trim().to_string())))
                .unwrap_or((entry, None));
            Some(ImportInfo {
                raw_snippet: raw.trim().to_string(),
                is_wildcard: false,
                identifier: Some(identifier.to_string()),
                alias,
            })
        })
        .collect()
}

fn strip_import_type_prefix(input: &str) -> &str {
    input.strip_prefix("type ").unwrap_or(input)
}

fn parse_require_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let Some((left, _)) = trimmed.split_once("require(") else {
        return Vec::new();
    };
    let left = left.trim();
    if let Some(pattern) = left
        .strip_prefix("const ")
        .or_else(|| left.strip_prefix("let "))
        .or_else(|| left.strip_prefix("var "))
    {
        let pattern = pattern.trim().trim_end_matches('=').trim();
        if pattern.starts_with('{') {
            return pattern
                .trim_start_matches('{')
                .trim_end_matches('}')
                .split(',')
                .filter_map(|entry| {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        return None;
                    }
                    let (identifier, alias) = entry
                        .split_once(':')
                        .map(|(identifier, alias)| {
                            (identifier.trim(), Some(alias.trim().to_string()))
                        })
                        .unwrap_or((entry, None));
                    Some(ImportInfo {
                        raw_snippet: raw.trim().to_string(),
                        is_wildcard: false,
                        identifier: Some(identifier.to_string()),
                        alias,
                    })
                })
                .collect();
        }
        if !pattern.is_empty() {
            return vec![ImportInfo {
                raw_snippet: raw.trim().to_string(),
                is_wildcard: false,
                identifier: Some(pattern.to_string()),
                alias: None,
            }];
        }
    }
    Vec::new()
}
pub(crate) fn resolve_js_ts_import_paths(
    source_file: &ProjectFile,
    raw_import: &str,
    language: Language,
) -> Vec<ProjectFile> {
    let Some(module_path) = extract_import_module_path(raw_import) else {
        return Vec::new();
    };
    resolve_js_ts_module_specifier(source_file, &module_path, language)
}

/// Resolve a relative module specifier (e.g. `"./foo"`) to project files. Bare specifiers
/// are intentionally ignored — `package.json` `exports`/`main` resolution and tsconfig
/// `paths`/`baseUrl` are out of scope. Shared with the JS/TS export-usage graph so both
/// resolvers stay in lock-step.
pub(crate) fn resolve_js_ts_module_specifier(
    source_file: &ProjectFile,
    module_specifier: &str,
    language: Language,
) -> Vec<ProjectFile> {
    if !module_specifier.starts_with('.') {
        return Vec::new();
    }
    let base = source_file.parent().join(module_specifier);
    let mut candidates = Vec::new();
    let exts = language.extensions();
    collect_candidate_paths(source_file.root(), &base, exts, &mut candidates);
    candidates.sort();
    candidates.dedup();
    candidates
}

fn extract_import_module_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim().trim_end_matches(';').trim();
    if trimmed.starts_with("import ") {
        if let Some((_, path)) = trimmed.trim_end_matches(';').rsplit_once(" from ") {
            return Some(path.trim().trim_matches('\'').trim_matches('"').to_string());
        }
        let path = trimmed.split_whitespace().nth(1)?;
        return Some(path.trim().trim_matches('\'').trim_matches('"').to_string());
    }
    let require = trimmed.split_once("require(")?.1;
    let path = require
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_end_matches(';')
        .trim();
    Some(path.trim_matches('\'').trim_matches('"').to_string())
}

fn collect_candidate_paths(
    root: &Path,
    module_path: &Path,
    extensions: &[&str],
    out: &mut Vec<ProjectFile>,
) {
    if module_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| extensions.contains(&ext))
    {
        let file = ProjectFile::new(root.to_path_buf(), module_path.to_path_buf());
        if file.exists() {
            out.push(file);
        }
        return;
    }
    for extension in extensions {
        let with_ext = PathBuf::from(format!("{}.{}", module_path.to_string_lossy(), extension));
        let direct = ProjectFile::new(root.to_path_buf(), with_ext);
        if direct.exists() {
            out.push(direct);
        }
        let index = module_path.join(format!("index.{extension}"));
        let index_file = ProjectFile::new(root.to_path_buf(), index);
        if index_file.exists() {
            out.push(index_file);
        }
    }
}

pub(crate) fn imported_tokens(raw_import: &str) -> BTreeSet<String> {
    parse_js_import_infos(raw_import)
        .into_iter()
        .filter_map(|import| import.alias.or(import.identifier))
        .collect()
}

pub(crate) fn extract_js_ts_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    let (receiver, method) = before_args.rsplit_once('.')?;
    if receiver.is_empty() || method.is_empty() {
        return None;
    }
    Some(receiver.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_js_import_infos;

    #[test]
    fn parses_typescript_type_only_named_imports() {
        let imports = parse_js_import_infos("import type { BubbleState } from '../types';");
        assert_eq!(1, imports.len());
        assert_eq!(Some("BubbleState"), imports[0].identifier.as_deref());
        assert_eq!(None, imports[0].alias.as_deref());
    }

    #[test]
    fn parses_mixed_typescript_named_imports_with_inline_type_modifiers() {
        let imports =
            parse_js_import_infos("import { type BubbleState, SummaryState } from '../types';");
        let identifiers = imports
            .into_iter()
            .map(|import| import.identifier.unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(vec!["BubbleState", "SummaryState"], identifiers);
    }
}
