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
#[doc(hidden)]
pub fn parse<A: LanguageAdapter>(adapter: &A, source: &str, setting: Option<&str>) -> BoundedParse {
    let mut parser = Parser::new();
    parser.set_language(&adapter.parser_language()).unwrap();
    parse_admitted_source_with_policy(
        &mut parser,
        adapter,
        source,
        None,
        Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
        SourceAdmissionPolicy::from_setting(setting),
    )
}
