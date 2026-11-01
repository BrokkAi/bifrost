use super::*;
use brokk_bifrost_analysis::test_support::AnalyzerFixture as Fixture;

fn search(
    analyzer: &dyn IAnalyzer,
    patterns: &[&str],
    context_lines: usize,
    insensitive: bool,
) -> SearchFileContentsResult {
    search_file_contents(
        analyzer,
        SearchFileContentsParams {
            patterns: patterns.iter().map(|p| (*p).to_string()).collect(),
            file_path: None,
            context_lines,
            case_insensitive: insensitive,
        },
    )
}

#[test]
fn content_sampling_reports_omitted_lines_and_exact_boundaries() {
    let fifty = (1..=50)
        .map(|n| format!("line {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let sixty = (1..=60)
        .map(|n| format!("line {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fix = Fixture::new(&[("exact.txt", &fifty), ("long.txt", &sixty)]);
    let result = get_file_contents(
        fix.analyzer.analyzer(),
        GetFileContentsParams {
            file_paths: vec!["exact.txt".into(), "long.txt".into()],
        },
    );
    assert_eq!(result.files.len(), 2);
    assert_eq!(result.files[0].content, fifty);
    assert!(!result.files[0].truncated);
    assert_eq!(result.files[0].total_lines, Some(50));
    assert!(result.files[1].truncated);
    assert_eq!(result.files[1].total_lines, Some(60));
    assert_eq!(result.files[1].head_lines, Some(25));
    assert_eq!(result.files[1].tail_lines, Some(25));
    assert!(result.files[1].content.contains("OMITTED 10 LINES"));
}

#[test]
fn content_line_byte_budget_admits_exact_size_and_cuts_after_last_allowed_byte() {
    let exact = "a".repeat(2048);
    let long = format!("{}Xy", "a".repeat(2047));
    let fix = Fixture::new(&[("exact.txt", &exact), ("long.txt", &long)]);
    let result = get_file_contents(
        fix.analyzer.analyzer(),
        GetFileContentsParams {
            file_paths: vec!["exact.txt".into(), "long.txt".into()],
        },
    );
    assert_eq!(result.files[0].content, exact);
    assert_eq!(
        result.files[1].content,
        format!("{}X [TRUNCATED at 2048 chars]", "a".repeat(2047))
    );
}

#[test]
fn alternatives_whitespace_and_case_apply_to_file_and_line_search() {
    let fix = Fixture::new(&[
        ("a.txt", "alpha\n"),
        ("b.txt", "beta\n"),
        ("c.txt", "Alpha\n"),
    ]);
    let found = find_files_containing(
        fix.analyzer.analyzer(),
        FindFilesContainingParams {
            patterns: vec![" alpha ".into(), "beta".into()],
            limit: 2,
            case_insensitive: false,
        },
    );
    assert_eq!(found.files, vec!["a.txt", "b.txt"]);
    assert!(!found.truncated);
    let found = find_files_containing(
        fix.analyzer.analyzer(),
        FindFilesContainingParams {
            patterns: vec!["alpha".into()],
            limit: 1,
            case_insensitive: true,
        },
    );
    assert_eq!(found.files.len(), 1);
    assert!(found.truncated);
    let result = search(fix.analyzer.analyzer(), &[" alpha ", "beta"], 0, false);
    assert_eq!(
        result
            .matches
            .iter()
            .map(|g| g.path.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt", "b.txt"]
    );
    let result = search(fix.analyzer.analyzer(), &["alpha"], 0, true);
    assert_eq!(result.matches.len(), 2);
}

#[test]
fn context_limit_preserves_twenty_preceding_lines() {
    let text = (1..=20)
        .map(|n| format!("line {n}"))
        .chain(std::iter::once("NEEDLE".into()))
        .collect::<Vec<_>>()
        .join("\n");
    let fix = Fixture::new(&[("a.txt", &text)]);
    let result = search(fix.analyzer.analyzer(), &["NEEDLE"], 20, false);
    assert_eq!(result.matches[0].matches[0].before.len(), 20);
    assert_eq!(result.matches[0].matches[0].before[0], "line 1");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "33d7a18877a4: exactly fifty file hits followed by a nonmatching line falsely reported truncation"
)]
fn search_reports_truncation_only_for_an_omitted_hit() {
    let fifty = "NEEDLE\n".repeat(50);
    let fix = Fixture::new(&[
        ("exact.txt", &format!("{fifty}OTHER\n")),
        ("over.txt", &format!("{fifty}NEEDLE\n")),
    ]);
    let result = search(fix.analyzer.analyzer(), &["NEEDLE"], 0, false);
    let exact = result
        .matches
        .iter()
        .find(|g| g.path == "exact.txt")
        .unwrap();
    let over = result
        .matches
        .iter()
        .find(|g| g.path == "over.txt")
        .unwrap();
    assert_eq!(exact.matches.len(), 50);
    assert!(!exact.truncated);
    assert!(over.truncated);
    assert!(result.truncated);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "a6bff4d37851: an over-limit file was silently omitted from a complete search answer"
)]
fn search_reports_skipped_over_limit_file() {
    let text = format!("{}x", "x\n".repeat(MAX_LINES_PER_FILE_SCAN));
    let exact = "x\n".repeat(MAX_LINES_PER_FILE_SCAN);
    let fix = Fixture::new(&[("exact.txt", &exact), ("large.txt", &text)]);
    let result = search(fix.analyzer.analyzer(), &["x"], 0, false);
    assert!(result.truncated);
    assert!(result.matches.iter().any(|group| group.path == "exact.txt"));
    assert!(
        result
            .incomplete_reasons
            .iter()
            .any(|r| r == "line_limit: large.txt")
    );
}

#[cfg(unix)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "33d7a18877a4: workspace enumeration errors looked like complete empty search answers"
)]
fn file_search_reports_workspace_listing_error() {
    use std::os::unix::fs::PermissionsExt;
    let fix = Fixture::new(&[("a.txt", "NEEDLE")]);
    let root = fix.analyzer.analyzer().project().root().to_path_buf();
    let denied = root.join("denied");
    std::fs::create_dir(&denied).unwrap();
    let blocked = denied.join("blocked.txt");
    std::fs::write(&blocked, "NEEDLE").unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root can still read through mode 0o000, so it cannot exercise this error.
    if std::fs::read(&blocked).is_ok() {
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    fix.analyzer
        .analyzer()
        .project()
        .invalidate_cached_file_listing();
    let contents = search(fix.analyzer.analyzer(), &["NEEDLE"], 0, false);
    let files = find_files_containing(
        fix.analyzer.analyzer(),
        FindFilesContainingParams {
            patterns: vec!["NEEDLE".into()],
            limit: 1,
            case_insensitive: false,
        },
    );
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(contents.matches.iter().any(|group| group.path == "a.txt"));
    assert!(
        contents
            .incomplete_reasons
            .iter()
            .any(|r| r.starts_with("all_files:"))
    );
    assert!(!files.incomplete_reasons.is_empty());
}

#[test]
fn three_megabyte_text_file_remains_searchable() {
    let text = format!("{}\nUNIQUE_SENTINEL", "x".repeat(3 * 1024 * 1024));
    let fix = Fixture::new(&[("large.txt", &text)]);
    let result = search(fix.analyzer.analyzer(), &["UNIQUE_SENTINEL"], 0, false);
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].matches[0].text, "UNIQUE_SENTINEL");
    let found = find_files_containing(
        fix.analyzer.analyzer(),
        FindFilesContainingParams {
            patterns: vec!["UNIQUE_SENTINEL".into()],
            limit: 1,
            case_insensitive: false,
        },
    );
    assert_eq!(found.files, vec!["large.txt"]);
}
