use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::git_file::{parse_rev_path, read_git_file, resolve_git_file_path};
use crate::model_context;
use crate::path_utils::{
    AmbiguousPathInput, ResolvedFileInput, WorkspaceFileResolver, WorkspacePathSelector,
    has_drive_letter_prefix, normalize_pattern, rel_path_string,
};
use rayon::prelude::*;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

const DEFAULT_FIND_FILES_CONTAINING_LIMIT: usize = 50;
const DEFAULT_SEARCH_FILE_CONTENTS_CONTEXT: usize = 2;
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
pub struct SkimFilesParams {
    pub file_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetFileContentsResult {
    pub files: Vec<FileContent>,
    pub not_found: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    /// `file_path` as the caller wrote it, when it names no workspace file and
    /// no workspace directory. Without it an empty result reads as "this
    /// pattern is nowhere in those files" rather than "those files do not
    /// exist" (#3092).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unmatched_paths: Vec<String>,
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
pub struct SkimFilesResult {
    pub files: Vec<SkimFileEntry>,
    pub not_found: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
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
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut files = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous_paths = Vec::new();

    for input in params.file_paths {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let resolved = resolver.resolve_literal(trimmed);
        if let ResolvedFileInput::File(file) = resolved {
            match project.read_source(&file) {
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
            }
            continue;
        }

        if let Some(literal_file) = literal_workspace_file_with_colon(project.root(), trimmed) {
            match literal_file.read_to_string() {
                Ok(content) => {
                    let sampled = model_context::sample(&content);
                    files.push(FileContent {
                        path: rel_path_string(&literal_file),
                        content: sampled.text,
                        truncated: sampled.truncated,
                        total_lines: Some(sampled.total_lines),
                        head_lines: sampled.truncated.then_some(sampled.head_shown),
                        tail_lines: sampled.truncated.then_some(sampled.tail_shown),
                    });
                }
                Err(_) => not_found.push(trimmed.to_string()),
            }
            continue;
        }

        if has_drive_letter_prefix(&normalize_pattern(trimmed)) {
            not_found.push(trimmed.to_string());
            continue;
        }

        if let Some((rev, path)) = parse_rev_path(trimmed) {
            let abs_path = resolve_git_file_path(path, project.root());
            match read_git_file(rev, &abs_path) {
                Ok(content) => {
                    let sampled = model_context::sample(&content);
                    files.push(FileContent {
                        path: trimmed.to_string(),
                        content: sampled.text,
                        truncated: sampled.truncated,
                        total_lines: Some(sampled.total_lines),
                        head_lines: sampled.truncated.then_some(sampled.head_shown),
                        tail_lines: sampled.truncated.then_some(sampled.tail_shown),
                    });
                }
                Err(err) => not_found.push(err),
            }
            continue;
        }

        match resolved {
            ResolvedFileInput::File(_) => unreachable!("file case handled above"),
            ResolvedFileInput::Ambiguous(item) => ambiguous_paths.push(item),
            ResolvedFileInput::NotFound(item) => not_found.push(item),
        }
    }

    GetFileContentsResult {
        files,
        not_found,
        ambiguous_paths,
    }
}

fn literal_workspace_file_with_colon(root: &std::path::Path, input: &str) -> Option<ProjectFile> {
    parse_rev_path(input)?;
    let normalized = normalize_pattern(input);
    let path = std::path::Path::new(&normalized);
    if path.is_absolute() || path.has_root() {
        return None;
    }

    let mut rel = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => rel.push(part),
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => return None,
        }
    }
    if rel.as_os_str().is_empty() {
        return None;
    }

    let file = ProjectFile::new(root.to_path_buf(), rel);
    file.abs_path().is_file().then_some(file)
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
            let contents = project.read_source(&file).ok()?;
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
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);

    let (regexes, invalid_patterns) = compile_regexes(&params.patterns, params.case_insensitive);
    if regexes.is_empty() {
        return SearchFileContentsResult {
            matches: Vec::new(),
            truncated: false,
            invalid_patterns,
            ambiguous_paths: Vec::new(),
            unmatched_paths: Vec::new(),
        };
    }

    let mut ambiguous_paths = Vec::new();
    let mut unmatched_paths = Vec::new();
    let filter_requested = params
        .file_path
        .as_deref()
        .is_some_and(|raw| !raw.trim().is_empty());
    // The same selector reading every path-scoped tool uses: a directory names
    // the files under it, and a selector that names nothing is reported rather
    // than silently searching an empty file set (#3092).
    let path_filter = params.file_path.as_deref().and_then(|raw| {
        match resolver.classify_selector(raw) {
            WorkspacePathSelector::Invalid => None,
            WorkspacePathSelector::Unmatched => {
                unmatched_paths.push(raw.trim().to_string());
                Some(WorkspacePathSelector::Unmatched)
            }
            matcher => {
                // An ambiguous basename is reported as such rather than
                // searched: which file the caller meant decides the answer.
                if let WorkspacePathSelector::Files(paths) = &matcher
                    && paths.len() > 1
                {
                    ambiguous_paths.push(AmbiguousPathInput {
                        input: raw.trim().to_string(),
                        matches: paths.clone(),
                    });
                    return None;
                }
                Some(matcher)
            }
        }
    });

    let all_files = match project.all_files() {
        Ok(files) => files,
        Err(_) => {
            return SearchFileContentsResult {
                matches: Vec::new(),
                truncated: false,
                invalid_patterns,
                ambiguous_paths,
                unmatched_paths,
            };
        }
    };

    let context = params.context_lines.min(MAX_CONTEXT_LINES);
    let candidates: Vec<ProjectFile> = if filter_requested && !ambiguous_paths.is_empty() {
        Vec::new()
    } else {
        all_files
            .into_iter()
            .filter(|file| {
                path_filter
                    .as_ref()
                    .is_none_or(|filter| filter.matches(&rel_path_string(file)))
            })
            .collect()
    };

    let mut groups: Vec<FileMatchGroup> = candidates
        .into_par_iter()
        .filter_map(|file| {
            if !is_searchable_text_file(&file) {
                return None;
            }
            let contents = project.read_source(&file).ok()?;
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
        ambiguous_paths,
        unmatched_paths,
    }
}

pub fn skim_files(analyzer: &dyn IAnalyzer, params: SkimFilesParams) -> SkimFilesResult {
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut files = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous_paths = Vec::new();

    for input in params.file_paths {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let file = match resolver.resolve_literal(trimmed) {
            ResolvedFileInput::File(file) => file,
            ResolvedFileInput::Ambiguous(item) => {
                ambiguous_paths.push(item);
                continue;
            }
            ResolvedFileInput::NotFound(item) => {
                not_found.push(item);
                continue;
            }
        };

        let declarations: Vec<SkimDeclaration> = analyzer
            .top_level_declarations(&file)
            .into_iter()
            .flat_map(|code_unit| {
                analyzer
                    .ranges(&code_unit)
                    .into_iter()
                    .map(move |range| SkimDeclaration {
                        symbol: code_unit.short_name().to_string(),
                        kind: code_unit_kind_label(&code_unit),
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

    SkimFilesResult {
        files,
        not_found,
        ambiguous_paths,
    }
}

fn code_unit_kind_label(code_unit: &crate::analyzer::CodeUnit) -> String {
    code_unit.kind().display_lowercase().to_string()
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

fn default_find_files_containing_limit() -> usize {
    DEFAULT_FIND_FILES_CONTAINING_LIMIT
}

fn default_search_file_contents_context() -> usize {
    DEFAULT_SEARCH_FILE_CONTENTS_CONTEXT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AnalyzerFixture as Fixture;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#60: absolute filesystem inputs must remain outside workspace file access while a valid relative path still works"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#60: Pins rejection of drive-relative forms such as C:foo and C: so they cannot be interpreted as workspace or host paths"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#60: Exercises the 200,000-line scan bound and verifies oversized files are skipped before building an unbounded line index"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#60: skim rejects an absolute host path and returns it as not found without panicking"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#60: Checks per-file match capping and the aggregate truncated status when one file has more than 50 hits"
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#60: Exercises usize::MAX context input on a one-line fixture to ensure the public search path remains bounded and does not panic"
    )]
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
}
