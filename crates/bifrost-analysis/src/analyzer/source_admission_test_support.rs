#[doc(hidden)]
pub fn table() -> String {
    table_with_items(1400)
}

#[doc(hidden)]
pub fn table_with_items(items: usize) -> String {
    format!(
        "static const unsigned long long words[] = {{{}}}, sibling = 7;\nint target(int n) {{ while (n > 0) {{ n = n - 1; }} return n; }}\n",
        "0x0123456789abcdef,".repeat(items)
    )
}

use super::*;

/// Source-admission tests assert a classification, not latency. The production
/// [`COMPLETE_FILE_PARSE_BUDGET`] is deliberately tight, so a loaded host can
/// turn a correct budget refusal into [`BoundedParse::TimedOut`] (issue
/// #11726). Keep the test-only deadline well clear of the production budget;
/// nextest's profile-wide terminate-after remains the hang detector.
const TEST_SOURCE_ADMISSION_BUDGET: Duration = Duration::from_secs(300);

#[doc(hidden)]
pub fn parse<A: LanguageAdapter>(adapter: &A, source: &str, setting: Option<&str>) -> BoundedParse {
    let mut parser = Parser::new();
    parser.set_language(&adapter.parser_language()).unwrap();
    parse_admitted_source_with_policy(
        &mut parser,
        adapter,
        source,
        None,
        Instant::now() + TEST_SOURCE_ADMISSION_BUDGET,
        SourceAdmissionPolicy::from_setting(setting),
    )
}
