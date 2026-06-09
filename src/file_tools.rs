use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::model_context;
use crate::path_utils::{normalize_pattern, rel_path_string, workspace_rel_path};
use glob::{MatchOptions, Pattern};
use rayon::prelude::*;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

const STRICT_SEPARATOR: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

const DEFAULT_FIND_FILENAMES_LIMIT: usize = 100;
const DEFAULT_FIND_FILES_CONTAINING_LIMIT: usize = 50;
const DEFAULT_SEARCH_FILE_CONTENTS_CONTEXT: usize = 2;
const DEFAULT_LIST_FILES_MAX_ENTRIES: usize = 500;
const MAX_PER_FILE_SEARCH_MATCHES: usize = 50;
const MAX_FILE_BYTES_FOR_CONTENT_SEARCH: u64 = 5 * 1024 * 1024;
const MAX_CONTEXT_LINES: usize = 20;
const MAX_TOTAL_SEARCH_MATCHES: usize = 500;
const MAX_LINES_PER_FILE_SCAN: usize = 200_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFileContentsParams {
    pub file_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindFilenamesParams {
    pub patterns: Vec<String>,
    #[serde(default = "default_find_filenames_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindFilesContainingParams {
    pub patterns: Vec<String>,
    #[serde(default = "default_find_files_containing_limit")]
    pub limit: usize,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFileContentsParams {
    pub patterns: Vec<String>,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default = "default_search_file_contents_context")]
    pub context_lines: usize,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFilesParams {
    pub directory_path: String,
    #[serde(default = "default_list_files_max_entries")]
    pub max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkimFilesParams {
    pub file_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetFileContentsResult {
    pub files: Vec<FileContent>,
    pub not_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileContent {
    pub path: String,
    pub content: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail_lines: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindFilenamesResult {
    pub files: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindFilesContainingResult {
    pub files: Vec<String>,
    pub truncated: bool,
    pub invalid_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchFileContentsResult {
    pub matches: Vec<FileMatchGroup>,
    pub truncated: bool,
    pub invalid_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileMatchGroup {
    pub path: String,
    pub matches: Vec<LineMatch>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LineMatch {
    pub line: usize,
    pub text: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListFilesResult {
    pub directory: String,
    pub files: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFilesResult {
    pub files: Vec<SkimFileEntry>,
    pub not_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFileEntry {
    pub path: String,
    pub declarations: Vec<SkimDeclaration>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimDeclaration {
    pub symbol: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
}

pub fn get_file_contents(
    analyzer: &dyn IAnalyzer,
    params: GetFileContentsParams,
) -> GetFileContentsResult {
    let project = analyzer.project();
    let mut files = Vec::new();
    let mut not_found = Vec::new();

    for input in params.file_paths {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some(rel) = workspace_rel_path(trimmed) else {
            not_found.push(trimmed.to_string());
            continue;
        };

        match project.file_by_rel_path(&rel) {
            Some(file) => match file.read_to_string() {
                Ok(content) => {
                    let sampled = model_context::sample(&content);
                    files.push(FileContent {
                        path: rel_path_string(&file),
                        content: sampled.text,
                        truncated: sampled.truncated,
                        total_lines: Some(sampled.total_lines),
                        head_lines: sampled.truncated.then_some(sampled.head_shown),
                        tail_lines: sampled.truncated.then_some(sampled.tail_shown),
                    })
                }
                Err(_) => not_found.push(trimmed.to_string()),
            },
            None => not_found.push(trimmed.to_string()),
        }
    }

    GetFileContentsResult { files, not_found }
}

pub fn find_filenames(
    analyzer: &dyn IAnalyzer,
    params: FindFilenamesParams,
) -> FindFilenamesResult {
    let project = analyzer.project();
    let limit = params.limit.max(1);

    let compiled: Vec<(Pattern, bool)> = params
        .patterns
        .iter()
        .filter_map(|pattern| {
            let normalized = normalize_pattern(pattern.trim());
            if normalized.is_empty() {
                return None;
            }
            let basename_only = !normalized.contains('/');
            Pattern::new(&normalized)
                .ok()
                .map(|glob| (glob, basename_only))
        })
        .collect();

    if compiled.is_empty() {
        return FindFilenamesResult {
            files: Vec::new(),
            truncated: false,
        };
    }

    let all_files = match project.all_files() {
        Ok(files) => files,
        Err(_) => {
            return FindFilenamesResult {
                files: Vec::new(),
                truncated: false,
            };
        }
    };

    let mut matched: Vec<String> = Vec::new();
    for file in all_files {
        let rel = rel_path_string(&file);
        let basename = file
            .rel_path()
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let matches = compiled.iter().any(|(glob, basename_only)| {
            if *basename_only {
                glob.matches_with(&basename, STRICT_SEPARATOR)
            } else {
                glob.matches_with(&rel, STRICT_SEPARATOR)
            }
        });
        if matches {
            matched.push(rel);
        }
    }

    matched.sort();
    let truncated = matched.len() > limit;
    matched.truncate(limit);
    FindFilenamesResult {
        files: matched,
        truncated,
    }
}

pub fn find_files_containing(
    analyzer: &dyn IAnalyzer,
    params: FindFilesContainingParams,
) -> FindFilesContainingResult {
    let project = analyzer.project();
    let limit = params.limit.max(1);

    let (regexes, invalid_patterns) = compile_regexes(&params.patterns, params.case_insensitive);
    if regexes.is_empty() {
        return FindFilesContainingResult {
            files: Vec::new(),
            truncated: false,
            invalid_patterns,
        };
    }

    let all_files = match project.all_files() {
        Ok(files) => files,
        Err(_) => {
            return FindFilesContainingResult {
                files: Vec::new(),
                truncated: false,
                invalid_patterns,
            };
        }
    };

    let files: Vec<ProjectFile> = all_files.into_iter().collect();
    let mut matched: Vec<String> = files
        .into_par_iter()
        .filter_map(|file| {
            if !is_searchable_text_file(&file) {
                return None;
            }
            let contents = file.read_to_string().ok()?;
            if regexes.iter().any(|regex| regex.is_match(&contents)) {
                Some(rel_path_string(&file))
            } else {
                None
            }
        })
        .collect();

    matched.sort();
    matched.dedup();
    let truncated = matched.len() > limit;
    matched.truncate(limit);
    FindFilesContainingResult {
        files: matched,
        truncated,
        invalid_patterns,
    }
}

pub fn search_file_contents(
    analyzer: &dyn IAnalyzer,
    params: SearchFileContentsParams,
) -> SearchFileContentsResult {
    let project = analyzer.project();

    let (regexes, invalid_patterns) = compile_regexes(&params.patterns, params.case_insensitive);
    if regexes.is_empty() {
        return SearchFileContentsResult {
            matches: Vec::new(),
            truncated: false,
            invalid_patterns,
        };
    }

    let glob = params.file_path.as_deref().and_then(|raw| {
        let normalized = normalize_pattern(raw.trim());
        if normalized.is_empty() {
            None
        } else {
            Pattern::new(&normalized).ok()
        }
    });

    let all_files = match project.all_files() {
        Ok(files) => files,
        Err(_) => {
            return SearchFileContentsResult {
                matches: Vec::new(),
                truncated: false,
                invalid_patterns,
            };
        }
    };

    let context = params.context_lines.min(MAX_CONTEXT_LINES);
    let candidates: Vec<ProjectFile> = all_files
        .into_iter()
        .filter(|file| {
            let rel = rel_path_string(file);
            glob.as_ref()
                .map(|g| g.matches_with(&rel, STRICT_SEPARATOR))
                .unwrap_or(true)
        })
        .collect();

    let mut groups: Vec<FileMatchGroup> = candidates
        .into_par_iter()
        .filter_map(|file| {
            if !is_searchable_text_file(&file) {
                return None;
            }
            let contents = file.read_to_string().ok()?;
            // Bound the per-file line count before allocating `Vec<&str>`.
            // A 5 MB single-byte-line file would otherwise produce ~5M slices
            // (≈120 MB of Vec headers) across rayon workers — a memory-pressure
            // amplifier despite the byte cap.
            if contents.bytes().filter(|&b| b == b'\n').count() > MAX_LINES_PER_FILE_SCAN {
                return None;
            }
            let lines: Vec<&str> = contents.split('\n').collect();
            let mut hits = Vec::new();
            let mut file_truncated = false;
            for (idx, line) in lines.iter().enumerate() {
                if hits.len() >= MAX_PER_FILE_SEARCH_MATCHES {
                    file_truncated = true;
                    break;
                }
                if regexes.iter().any(|regex| regex.is_match(line)) {
                    let before_start = idx.saturating_sub(context);
                    let before = lines[before_start..idx]
                        .iter()
                        .map(|l| model_context::truncate_line(l))
                        .collect();
                    let after_end = (idx + 1 + context).min(lines.len());
                    let after = lines[idx + 1..after_end]
                        .iter()
                        .map(|l| model_context::truncate_line(l))
                        .collect();
                    hits.push(LineMatch {
                        line: idx + 1,
                        text: model_context::truncate_line(line),
                        before,
                        after,
                    });
                }
            }
            if hits.is_empty() {
                None
            } else {
                Some(FileMatchGroup {
                    path: rel_path_string(&file),
                    matches: hits,
                    truncated: file_truncated,
                })
            }
        })
        .collect();

    groups.sort_by(|left, right| left.path.cmp(&right.path));

    let mut truncated = groups.iter().any(|group| group.truncated);
    let mut total: usize = 0;
    let mut keep = groups.len();
    for (idx, group) in groups.iter().enumerate() {
        total = total.saturating_add(group.matches.len());
        if total > MAX_TOTAL_SEARCH_MATCHES {
            keep = idx;
            truncated = true;
            break;
        }
    }
    groups.truncate(keep);

    SearchFileContentsResult {
        matches: groups,
        truncated,
        invalid_patterns,
    }
}

pub fn list_files(analyzer: &dyn IAnalyzer, params: ListFilesParams) -> ListFilesResult {
    let project = analyzer.project();
    let max_entries = params.max_entries.max(1);

    let normalized = normalize_pattern(params.directory_path.trim());
    let directory_rel = normalized.trim_matches('/');
    let directory_owned = directory_rel.to_string();

    let all_files = match project.all_files() {
        Ok(files) => files,
        Err(_) => {
            return ListFilesResult {
                directory: directory_owned,
                files: Vec::new(),
                truncated: false,
            };
        }
    };

    let mut matched: Vec<String> = all_files
        .into_iter()
        .filter_map(|file| {
            let rel = rel_path_string(&file);
            if directory_owned.is_empty()
                || rel == directory_owned
                || rel.starts_with(&format!("{directory_owned}/"))
            {
                Some(rel)
            } else {
                None
            }
        })
        .collect();

    matched.sort();
    let truncated = matched.len() > max_entries;
    matched.truncate(max_entries);
    ListFilesResult {
        directory: directory_owned,
        files: matched,
        truncated,
    }
}

pub fn skim_files(analyzer: &dyn IAnalyzer, params: SkimFilesParams) -> SkimFilesResult {
    let project = analyzer.project();
    let mut files = Vec::new();
    let mut not_found = Vec::new();

    for input in params.file_paths {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some(rel) = workspace_rel_path(trimmed) else {
            not_found.push(trimmed.to_string());
            continue;
        };

        let Some(file) = project.file_by_rel_path(&rel) else {
            not_found.push(trimmed.to_string());
            continue;
        };

        let declarations: Vec<SkimDeclaration> = analyzer
            .top_level_declarations(&file)
            .flat_map(|code_unit| {
                analyzer
                    .ranges_of(code_unit)
                    .into_iter()
                    .map(move |range| SkimDeclaration {
                        symbol: code_unit.short_name().to_string(),
                        kind: code_unit_kind_label(code_unit),
                        start_line: range.start_line,
                        end_line: range.end_line,
                    })
            })
            .collect();

        files.push(SkimFileEntry {
            path: rel_path_string(&file),
            declarations,
        });
    }

    SkimFilesResult { files, not_found }
}

fn code_unit_kind_label(code_unit: &crate::analyzer::CodeUnit) -> String {
    use crate::analyzer::CodeUnitType;
    match code_unit.kind() {
        CodeUnitType::Class => "class".to_string(),
        CodeUnitType::Function => "function".to_string(),
        CodeUnitType::Field => "field".to_string(),
        CodeUnitType::Module => "module".to_string(),
        CodeUnitType::Macro => "macro".to_string(),
    }
}

fn compile_regexes(patterns: &[String], case_insensitive: bool) -> (Vec<Regex>, Vec<String>) {
    let mut invalid_patterns = Vec::new();
    let regexes: Vec<Regex> = patterns
        .iter()
        .filter_map(|raw| {
            let pattern = raw.trim();
            if pattern.is_empty() {
                return None;
            }
            match RegexBuilder::new(pattern)
                .case_insensitive(case_insensitive)
                .build()
            {
                Ok(regex) => Some(regex),
                Err(_) => {
                    invalid_patterns.push(raw.clone());
                    None
                }
            }
        })
        .collect();
    (regexes, invalid_patterns)
}

// Reject binary files and files large enough to risk OOM if read into memory.
// `is_binary` sniffs only the first 8 KB, so the size cap protects against
// text-prefixed but otherwise massive files (generated artifacts, blobs).
fn is_searchable_text_file(file: &ProjectFile) -> bool {
    if file.is_binary().unwrap_or(true) {
        return false;
    }
    match std::fs::metadata(file.abs_path()) {
        Ok(meta) => meta.len() <= MAX_FILE_BYTES_FOR_CONTENT_SEARCH,
        Err(_) => false,
    }
}

fn default_find_filenames_limit() -> usize {
    DEFAULT_FIND_FILENAMES_LIMIT
}

fn default_find_files_containing_limit() -> usize {
    DEFAULT_FIND_FILES_CONTAINING_LIMIT
}

fn default_search_file_contents_context() -> usize {
    DEFAULT_SEARCH_FILE_CONTENTS_CONTEXT
}

fn default_list_files_max_entries() -> usize {
    DEFAULT_LIST_FILES_MAX_ENTRIES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AnalyzerFixture as Fixture;

    #[test]
    fn get_file_contents_reads_existing_files() {
        let fix = Fixture::new(&[("src/a.rs", "fn a() {}\n"), ("src/b.rs", "fn b() {}\n")]);
        let result = get_file_contents(
            fix.analyzer.analyzer(),
            GetFileContentsParams {
                file_paths: vec!["src/a.rs".to_string(), "missing.rs".to_string()],
            },
        );
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "src/a.rs");
        assert_eq!(result.files[0].content, "fn a() {}\n");
        assert!(!result.files[0].truncated);
        assert_eq!(Some(1), result.files[0].total_lines);
        assert_eq!(None, result.files[0].head_lines);
        assert_eq!(None, result.files[0].tail_lines);
        assert_eq!(result.not_found, vec!["missing.rs"]);
    }

    #[test]
    fn get_file_contents_normalizes_backslashes() {
        let fix = Fixture::new(&[("src/a.rs", "x")]);
        let result = get_file_contents(
            fix.analyzer.analyzer(),
            GetFileContentsParams {
                file_paths: vec!["src\\a.rs".to_string()],
            },
        );
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "src/a.rs");
    }

    #[test]
    fn get_file_contents_rejects_absolute_paths_without_panic() {
        let fix = Fixture::new(&[("src/a.rs", "x")]);
        let result = get_file_contents(
            fix.analyzer.analyzer(),
            GetFileContentsParams {
                file_paths: vec![
                    "/etc/passwd".to_string(),
                    "/".to_string(),
                    "src/a.rs".to_string(),
                ],
            },
        );
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "src/a.rs");
        assert_eq!(
            result.not_found,
            vec!["/etc/passwd".to_string(), "/".to_string()]
        );
    }

    #[test]
    fn get_file_contents_rejects_windows_drive_relative_paths() {
        let fix = Fixture::new(&[("src/a.rs", "x")]);
        let result = get_file_contents(
            fix.analyzer.analyzer(),
            GetFileContentsParams {
                file_paths: vec![
                    "C:foo".to_string(),
                    "C:".to_string(),
                    "d:secrets".to_string(),
                ],
            },
        );
        assert!(result.files.is_empty());
        assert_eq!(
            result.not_found,
            vec![
                "C:foo".to_string(),
                "C:".to_string(),
                "d:secrets".to_string()
            ]
        );
    }

    #[test]
    fn search_file_contents_skips_files_with_too_many_lines() {
        // 200_001 newlines exceeds MAX_LINES_PER_FILE_SCAN; the file must be
        // skipped rather than allocating a `Vec<&str>` for every line.
        let body = "x\n".repeat(MAX_LINES_PER_FILE_SCAN + 1);
        let fix = Fixture::new(&[("src/big.txt", body.as_str())]);
        let result = search_file_contents(
            fix.analyzer.analyzer(),
            SearchFileContentsParams {
                patterns: vec!["x".to_string()],
                file_path: None,
                context_lines: 0,
                case_insensitive: false,
            },
        );
        assert!(
            result.matches.is_empty(),
            "expected no matches, got {result:?}"
        );
    }

    #[test]
    fn get_file_contents_truncates_very_long_lines() {
        let long = "x".repeat(2050);
        let fix = Fixture::new(&[("src/a.rs", long.as_str())]);
        let result = get_file_contents(
            fix.analyzer.analyzer(),
            GetFileContentsParams {
                file_paths: vec!["src/a.rs".to_string()],
            },
        );

        assert_eq!(1, result.files.len());
        assert!(!result.files[0].truncated);
        assert_eq!(Some(1), result.files[0].total_lines);
        assert!(
            result.files[0]
                .content
                .ends_with(" [TRUNCATED at 2048 chars]")
        );
    }

    #[test]
    fn get_file_contents_samples_large_files_as_head_tail() {
        let body = (1..=60)
            .map(|line| format!("line {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let fix = Fixture::new(&[("src/a.rs", body.as_str())]);
        let result = get_file_contents(
            fix.analyzer.analyzer(),
            GetFileContentsParams {
                file_paths: vec!["src/a.rs".to_string()],
            },
        );

        assert_eq!(1, result.files.len());
        let file = &result.files[0];
        assert!(file.truncated);
        assert_eq!(Some(60), file.total_lines);
        assert_eq!(Some(25), file.head_lines);
        assert_eq!(Some(25), file.tail_lines);
        assert!(file.content.contains("line 1"));
        assert!(file.content.contains("line 25"));
        assert!(file.content.contains("----- OMITTED 10 LINES -----"));
        assert!(file.content.contains("line 36"));
        assert!(file.content.contains("line 60"));
    }

    #[test]
    fn skim_files_rejects_absolute_paths_without_panic() {
        let fix = Fixture::new(&[("a.rs", "fn a() {}\n")]);
        let result = skim_files(
            fix.analyzer.analyzer(),
            SkimFilesParams {
                file_paths: vec!["/etc/passwd".to_string()],
            },
        );
        assert!(result.files.is_empty());
        assert_eq!(result.not_found, vec!["/etc/passwd"]);
    }

    #[test]
    fn find_filenames_matches_basename_glob_without_slash() {
        let fix = Fixture::new(&[("src/a.rs", ""), ("src/nested/b.rs", ""), ("README.md", "")]);
        let result = find_filenames(
            fix.analyzer.analyzer(),
            FindFilenamesParams {
                patterns: vec!["*.rs".to_string()],
                limit: 10,
            },
        );
        assert_eq!(result.files, vec!["src/a.rs", "src/nested/b.rs"]);
        assert!(!result.truncated);
    }

    #[test]
    fn find_filenames_matches_full_path_with_slash() {
        let fix = Fixture::new(&[("src/a.rs", ""), ("src/nested/b.rs", "")]);
        let result = find_filenames(
            fix.analyzer.analyzer(),
            FindFilenamesParams {
                patterns: vec!["src/*.rs".to_string()],
                limit: 10,
            },
        );
        assert_eq!(result.files, vec!["src/a.rs"]);
    }

    #[test]
    fn find_filenames_respects_limit() {
        let fix = Fixture::new(&[("a.rs", ""), ("b.rs", ""), ("c.rs", "")]);
        let result = find_filenames(
            fix.analyzer.analyzer(),
            FindFilenamesParams {
                patterns: vec!["*.rs".to_string()],
                limit: 2,
            },
        );
        assert_eq!(result.files.len(), 2);
        assert!(result.truncated);
    }

    #[test]
    fn find_files_containing_matches_regex() {
        let fix = Fixture::new(&[
            ("src/a.rs", "fn alpha() {}\n"),
            ("src/b.rs", "fn beta() {}\n"),
        ]);
        let result = find_files_containing(
            fix.analyzer.analyzer(),
            FindFilesContainingParams {
                patterns: vec!["fn al".to_string()],
                limit: 10,
                case_insensitive: false,
            },
        );
        assert_eq!(result.files, vec!["src/a.rs"]);
    }

    #[test]
    fn find_files_containing_records_invalid_patterns() {
        let fix = Fixture::new(&[("a.rs", "")]);
        let result = find_files_containing(
            fix.analyzer.analyzer(),
            FindFilesContainingParams {
                patterns: vec!["[".to_string()],
                limit: 10,
                case_insensitive: false,
            },
        );
        assert_eq!(result.invalid_patterns, vec!["[".to_string()]);
        assert!(result.files.is_empty());
    }

    #[test]
    fn search_file_contents_returns_context() {
        let fix = Fixture::new(&[("src/a.rs", "line1\nline2\nNEEDLE\nline4\nline5\n")]);
        let result = search_file_contents(
            fix.analyzer.analyzer(),
            SearchFileContentsParams {
                patterns: vec!["NEEDLE".to_string()],
                file_path: None,
                context_lines: 1,
                case_insensitive: false,
            },
        );
        assert_eq!(result.matches.len(), 1);
        let group = &result.matches[0];
        assert_eq!(group.path, "src/a.rs");
        assert!(!group.truncated);
        assert_eq!(group.matches.len(), 1);
        let hit = &group.matches[0];
        assert_eq!(hit.line, 3);
        assert_eq!(hit.text, "NEEDLE");
        assert_eq!(hit.before, vec!["line2".to_string()]);
        assert_eq!(hit.after, vec!["line4".to_string()]);
    }

    #[test]
    fn search_file_contents_respects_filepath_glob() {
        let fix = Fixture::new(&[("src/a.rs", "NEEDLE\n"), ("src/b.txt", "NEEDLE\n")]);
        let result = search_file_contents(
            fix.analyzer.analyzer(),
            SearchFileContentsParams {
                patterns: vec!["NEEDLE".to_string()],
                file_path: Some("**/*.rs".to_string()),
                context_lines: 0,
                case_insensitive: false,
            },
        );
        let paths: Vec<_> = result.matches.iter().map(|m| m.path.clone()).collect();
        assert_eq!(paths, vec!["src/a.rs"]);
    }

    #[test]
    fn search_file_contents_marks_per_file_truncation() {
        let mut body = String::new();
        for _ in 0..(MAX_PER_FILE_SEARCH_MATCHES + 5) {
            body.push_str("NEEDLE\n");
        }
        let fix = Fixture::new(&[("src/a.rs", body.as_str())]);
        let result = search_file_contents(
            fix.analyzer.analyzer(),
            SearchFileContentsParams {
                patterns: vec!["NEEDLE".to_string()],
                file_path: None,
                context_lines: 0,
                case_insensitive: false,
            },
        );
        assert_eq!(result.matches.len(), 1);
        assert!(result.matches[0].truncated);
        assert_eq!(result.matches[0].matches.len(), MAX_PER_FILE_SEARCH_MATCHES);
        assert!(result.truncated);
    }

    #[test]
    fn search_file_contents_clamps_context_lines() {
        let fix = Fixture::new(&[("src/a.rs", "NEEDLE\n")]);
        let result = search_file_contents(
            fix.analyzer.analyzer(),
            SearchFileContentsParams {
                patterns: vec!["NEEDLE".to_string()],
                file_path: None,
                context_lines: usize::MAX,
                case_insensitive: false,
            },
        );
        assert_eq!(result.matches.len(), 1);
        // No panic from oversized context_lines, and only a single line in
        // the file means before/after stay empty regardless of the cap.
        assert!(result.matches[0].matches[0].before.is_empty());
    }

    #[test]
    fn list_files_filters_by_directory_prefix() {
        let fix = Fixture::new(&[("src/a.rs", ""), ("src/nested/b.rs", ""), ("README.md", "")]);
        let result = list_files(
            fix.analyzer.analyzer(),
            ListFilesParams {
                directory_path: "src".to_string(),
                max_entries: 100,
            },
        );
        assert_eq!(
            result.files,
            vec!["src/a.rs".to_string(), "src/nested/b.rs".to_string()]
        );
        assert_eq!(result.directory, "src");
    }

    #[test]
    fn list_files_handles_root_as_empty_path() {
        let fix = Fixture::new(&[("a.rs", ""), ("nested/b.rs", "")]);
        let result = list_files(
            fix.analyzer.analyzer(),
            ListFilesParams {
                directory_path: "".to_string(),
                max_entries: 100,
            },
        );
        assert_eq!(
            result.files,
            vec!["a.rs".to_string(), "nested/b.rs".to_string()]
        );
    }

    #[test]
    fn list_files_respects_max_entries() {
        let fix = Fixture::new(&[("src/a.rs", ""), ("src/b.rs", ""), ("src/c.rs", "")]);
        let result = list_files(
            fix.analyzer.analyzer(),
            ListFilesParams {
                directory_path: "src".to_string(),
                max_entries: 2,
            },
        );
        assert_eq!(result.files.len(), 2);
        assert!(result.truncated);
    }

    #[test]
    fn skim_files_reports_unknown_paths_in_not_found() {
        let fix = Fixture::new(&[("a.rs", "fn a() {}\n")]);
        let result = skim_files(
            fix.analyzer.analyzer(),
            SkimFilesParams {
                file_paths: vec!["missing.rs".to_string()],
            },
        );
        assert!(result.files.is_empty());
        assert_eq!(result.not_found, vec!["missing.rs"]);
        let _ = fix.project_root();
    }

    #[test]
    fn search_file_contents_truncates_long_match_and_context_lines() {
        let long = "x".repeat(2050);
        let fix = Fixture::new(&[(
            "src/a.rs",
            format!("before\nneedle {long}\nafter {long}\n").as_str(),
        )]);
        let result = search_file_contents(
            fix.analyzer.analyzer(),
            SearchFileContentsParams {
                patterns: vec!["needle".to_string()],
                file_path: None,
                context_lines: 1,
                case_insensitive: false,
            },
        );

        let group = &result.matches[0];
        assert!(
            group.matches[0]
                .text
                .ends_with(" [TRUNCATED at 2048 chars]")
        );
        assert_eq!(vec!["before".to_string()], group.matches[0].before);
        assert!(group.matches[0].after[0].ends_with(" [TRUNCATED at 2048 chars]"));
    }
}
