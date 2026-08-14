//! C# preprocessor-directive-aware parsing.
//!
//! The tree-sitter C# grammar accepts preprocessor directives only at statement
//! and declaration boundaries. A directive inside a declaration -- a modifier
//! list split across `#if NET` / `#else`, or a `#if` inside a ternary
//! expression -- breaks the parse and Bifrost loses every declaration after the
//! break (issue #1803).
//!
//! This module computes, per file, the tree-sitter "included ranges" that hide
//! every directive line and every inactive conditional branch from the parser.
//! Node offsets still refer to the original file, so no transformed source ever
//! exists and cache identity stays the raw checkout bytes.
//!
//! Branch selection is deterministic: within an `#if` / `#elif` / `#else`
//! chain the first branch is active, except a branch whose condition is the
//! literal `false`. There is no compilation-constant model.
//!
//! The line scanner here is a lexical pre-pass, not a fallback for missing
//! structure: before it runs there is no tree, and a real C# lexer likewise
//! handles directives before the syntactic grammar.

use brokk_bifrost_core::analyzer::common::advance_ts_point;
use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;
use brokk_bifrost_core::cancellation::CancellationToken;

/// What a consumer is told when a file's index is partial because a
/// conditional branch was excluded from the parse.
///
/// The exact wording is part of the contract: hosts match on it.
pub const CSHARP_INACTIVE_BRANCHES_DETAIL: &str =
    "conditional compilation: inactive branches excluded from the index";

/// The result of scanning one C# file for preprocessor directives.
pub struct PreprocessorScan {
    /// Byte ranges the parser may read, or `None` when the file has no
    /// directives at all and must simply be parsed whole.
    pub included_ranges: Option<Vec<tree_sitter::Range>>,
    /// True when at least one conditional branch was excluded, which means the
    /// extraction for this file is partial by construction.
    pub has_inactive_regions: bool,
}

/// Lexical mode carried across lines while scanning for directive lines.
///
/// C# directives are recognized only when the lexer is outside comments and
/// strings, so the scanner must know which construct spans a line boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LexMode {
    Normal,
    BlockComment,
    /// `@"..."`, closed by a `"` that is not doubled.
    VerbatimString,
    /// `"""..."""`, closed by a run of at least this many quotes.
    RawString(usize),
}

/// One entry of the `#if` / `#elif` / `#else` / `#endif` stack.
#[derive(Clone, Copy)]
struct ChainState {
    /// True when the branch currently open emits source.
    branch_active: bool,
    /// True once some branch of this chain has been chosen as the active one.
    chosen: bool,
    /// True when the region enclosing this whole chain is active.
    parent_active: bool,
}

/// Scan `source` for preprocessor directives and compute the included ranges.
pub fn scan_preprocessor(source: &str) -> PreprocessorScan {
    let bytes = source.as_bytes();
    let mut mode = LexMode::Normal;
    let mut stack: Vec<ChainState> = Vec::new();
    let mut any_directive = false;
    let mut has_inactive_regions = false;
    // Byte spans that stay in the parse, accumulated as [start, end) pairs.
    let mut kept: Vec<(usize, usize)> = Vec::new();
    let mut line_start = 0usize;

    while line_start <= source.len() {
        let line_end = match bytes[line_start..].iter().position(|&b| b == b'\n') {
            Some(offset) => line_start + offset + 1,
            None => source.len(),
        };
        let line = &source[line_start..line_end];
        let region_active = stack.last().is_none_or(|state| state.branch_active);

        let is_directive = mode == LexMode::Normal && line.trim_start().starts_with('#');
        if is_directive {
            any_directive = true;
            apply_directive(line.trim().trim_start_matches('#').trim_start(), &mut stack);
        } else if region_active {
            kept.push((line_start, line_end));
            // Only active text is lexed, exactly as a C# compiler skips the
            // text of a disabled region without tokenizing it.
            mode = advance_lex_mode(line, mode);
        } else if !line.trim().is_empty() {
            has_inactive_regions = true;
        }

        if line_end == source.len() {
            break;
        }
        line_start = line_end;
    }

    if !any_directive {
        return PreprocessorScan {
            included_ranges: None,
            has_inactive_regions: false,
        };
    }

    PreprocessorScan {
        included_ranges: Some(build_ranges(bytes, &kept)),
        has_inactive_regions,
    }
}

/// Merge adjacent kept spans and turn them into tree-sitter ranges.
///
/// An empty range slice tells tree-sitter to parse the whole file, so a file
/// whose every line is excluded emits one zero-width range instead.
fn build_ranges(bytes: &[u8], kept: &[(usize, usize)]) -> Vec<tree_sitter::Range> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(kept.len());
    for &(start, end) in kept {
        match merged.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => merged.push((start, end)),
        }
    }

    if merged.is_empty() {
        return vec![tree_sitter::Range {
            start_byte: 0,
            end_byte: 0,
            start_point: tree_sitter::Point { row: 0, column: 0 },
            end_point: tree_sitter::Point { row: 0, column: 0 },
        }];
    }

    let mut ranges = Vec::with_capacity(merged.len());
    let mut cursor = 0usize;
    let mut point = tree_sitter::Point { row: 0, column: 0 };
    for (start, end) in merged {
        let start_point = advance_ts_point(bytes, point, cursor, start);
        let end_point = advance_ts_point(bytes, start_point, start, end);
        ranges.push(tree_sitter::Range {
            start_byte: start,
            end_byte: end,
            start_point,
            end_point,
        });
        cursor = end;
        point = end_point;
    }
    ranges
}

/// Update the conditional stack for one directive.
///
/// `body` is the directive text with the leading `#` and whitespace removed.
/// Unbalanced input never panics: a stray `#else`, `#elif`, or `#endif` with no
/// open chain is a no-op, and chains still open at end of file simply end.
fn apply_directive(body: &str, stack: &mut Vec<ChainState>) {
    let (keyword, condition) = match body.find(|c: char| c.is_whitespace()) {
        Some(split) => (&body[..split], body[split..].trim()),
        None => (body, ""),
    };
    let parent_active = stack.last().is_none_or(|state| state.branch_active);
    match keyword {
        "if" => {
            let active = parent_active && !is_literal_false(condition);
            stack.push(ChainState {
                branch_active: active,
                chosen: active,
                parent_active,
            });
        }
        "elif" => {
            if let Some(state) = stack.last_mut() {
                let active = state.parent_active && !state.chosen && !is_literal_false(condition);
                state.branch_active = active;
                state.chosen |= active;
            }
        }
        "else" => {
            if let Some(state) = stack.last_mut() {
                let active = state.parent_active && !state.chosen;
                state.branch_active = active;
                state.chosen |= active;
            }
        }
        "endif" => {
            stack.pop();
        }
        _ => {}
    }
}

/// A condition is decidable only when it is exactly the literal `false`.
fn is_literal_false(condition: &str) -> bool {
    condition.trim() == "false"
}

/// Advance the cross-line lexical mode across one source line.
fn advance_lex_mode(line: &str, mut mode: LexMode) -> LexMode {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match mode {
            LexMode::BlockComment => {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    mode = LexMode::Normal;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            LexMode::VerbatimString => {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        mode = LexMode::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            LexMode::RawString(opener) => {
                if bytes[index] == b'"' {
                    let run = quote_run(bytes, index);
                    if run >= opener {
                        mode = LexMode::Normal;
                    }
                    index += run;
                } else {
                    index += 1;
                }
            }
            LexMode::Normal => {
                match bytes[index] {
                    b'/' if bytes.get(index + 1) == Some(&b'/') => return LexMode::Normal,
                    b'/' if bytes.get(index + 1) == Some(&b'*') => {
                        mode = LexMode::BlockComment;
                        index += 2;
                    }
                    b'@' | b'$' => {
                        // `@"`, `$"`, `$@"`, `@$"`, `$"""` all start here.
                        let mut sigil_end = index;
                        let mut verbatim = false;
                        while let Some(&byte) = bytes.get(sigil_end) {
                            match byte {
                                b'@' => {
                                    verbatim = true;
                                    sigil_end += 1;
                                }
                                b'$' => sigil_end += 1,
                                _ => break,
                            }
                        }
                        if bytes.get(sigil_end) == Some(&b'"') {
                            let run = quote_run(bytes, sigil_end);
                            if run >= 3 {
                                mode = LexMode::RawString(run);
                                index = sigil_end + run;
                            } else if verbatim {
                                mode = LexMode::VerbatimString;
                                index = sigil_end + 1;
                            } else {
                                index = sigil_end + 1 + plain_string_len(bytes, sigil_end + 1);
                            }
                        } else {
                            index = sigil_end.max(index + 1);
                        }
                    }
                    b'"' => {
                        let run = quote_run(bytes, index);
                        if run >= 3 {
                            mode = LexMode::RawString(run);
                            index += run;
                        } else {
                            index += 1 + plain_string_len(bytes, index + 1);
                        }
                    }
                    b'\'' => index += 1 + plain_char_len(bytes, index + 1),
                    _ => index += 1,
                }
            }
        }
    }
    mode
}

/// Length of the run of `"` starting at `index`.
fn quote_run(bytes: &[u8], index: usize) -> usize {
    bytes[index..].iter().take_while(|&&b| b == b'"').count()
}

/// Length of a plain `"..."` string body, including its closing quote.
///
/// A plain string cannot span a line, so an unterminated one ends at the line
/// end and the mode returns to normal.
fn plain_string_len(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1 - start,
            _ => index += 1,
        }
    }
    bytes.len() - start
}

/// Length of a `'x'` character literal body, including its closing quote.
fn plain_char_len(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'\'' => return index + 1 - start,
            _ => index += 1,
        }
    }
    bytes.len() - start
}

/// The included ranges for one C# source, or `None` when it has no directives.
///
/// This is the function pointer form the language-blind parse helpers take.
pub fn csharp_included_ranges(source: &str) -> Option<Vec<tree_sitter::Range>> {
    scan_preprocessor(source).included_ranges
}

/// The C# parse spec: the grammar plus the directive-aware pre-parse.
///
/// Language-blind machinery -- the usage-graph on-demand parse, for one --
/// takes a spec instead of a bare grammar so that no C# parse can forget the
/// pre-parse and produce node ranges the declaration walk disagrees with.
pub fn csharp_parse_spec(language: &tree_sitter::Language) -> ParseSpec<'_> {
    ParseSpec::restricted(language, csharp_included_ranges)
}

/// Parse C# source with preprocessor directives and inactive branches hidden.
///
/// Every C# parse in Bifrost goes through here or through
/// [`csharp_parse_spec`]. If the declaration walk and the usage-graph scan
/// parsed the same file differently, their node ranges would disagree and
/// navigation would break in ways that are hard to see.
pub fn parse_csharp(source: &str) -> Option<tree_sitter::Tree> {
    parse_csharp_with_cancellation(source, None)
}

/// Parse C# source and also report what the scan found.
///
/// A caller that must tell its consumer the index is partial -- the semantic
/// diagnostics pass does -- needs `has_inactive_regions` from the same scan
/// that produced the tree, not a second scan of the same bytes.
pub fn parse_csharp_scanned(source: &str) -> Option<(tree_sitter::Tree, PreprocessorScan)> {
    let scan = scan_preprocessor(source);
    let tree = parse_csharp_scan_with_cancellation(source, &scan, None)?;
    Some((tree, scan))
}

/// Cancellation-aware form of [`parse_csharp`].
pub fn parse_csharp_with_cancellation(
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<tree_sitter::Tree> {
    parse_csharp_scan_with_cancellation(source, &scan_preprocessor(source), cancellation)
}

fn parse_csharp_scan_with_cancellation(
    source: &str,
    scan: &PreprocessorScan,
    cancellation: Option<&CancellationToken>,
) -> Option<tree_sitter::Tree> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return None;
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .ok()?;
    if let Some(ranges) = scan.included_ranges.as_deref() {
        parser.set_included_ranges(ranges).ok()?;
    }
    if let Some(cancellation) = cancellation {
        let mut read = |offset: usize, _| source.as_bytes().get(offset..).unwrap_or(&[][..]);
        let mut progress = |_: &tree_sitter::ParseState| cancellation.is_cancelled();
        parser.parse_with_options(
            &mut read,
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        )
    } else {
        parser.parse(source, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `StringSlice` shape: a member signature split across `#if NET`.
    const STRING_SLICE: &str = r#"namespace Markdig.Helpers
{
    public struct StringSlice
    {
        public string Text;
        public int Start;

#if NET
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public readonly void TrimStart()
#else
        public void TrimStart()
#endif
        {
            Start++;
        }

        public char NextChar()
        {
            return Text[Start];
        }

        public char PeekChar()
        {
            return Text[Start];
        }
    }
}
"#;

    /// The `TypeConverter` shape: `#if` inside a ternary expression.
    const TYPE_CONVERTER: &str = r#"namespace CommandLine.Core
{
    static class TypeConverter
    {
        public static object ChangeType(string value, Type type)
        {
            return type == typeof(int)
                ? ParseInt(value)
#if !SKIP_FSHARP
                : IsFsharpOption(type)
                    ? ParseOption(value)
                    : ParseOther(value);
#else
                : ParseOther(value);
#endif
        }

        public static object ParseInt(string value) { return 0; }
    }
}
"#;

    fn parse_raw(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    /// Collect every method name the tree exposes, in document order.
    fn method_names(tree: &tree_sitter::Tree, source: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_declaration"
                && let Some(name) = node.child_by_field_name("name")
            {
                names.push(source[name.byte_range()].to_string());
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).unwrap());
            }
        }
        names.sort();
        names
    }

    /// Count ERROR and MISSING nodes anywhere in the tree.
    fn error_count(tree: &tree_sitter::Tree) -> usize {
        let mut count = 0;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.is_error() || node.is_missing() {
                count += 1;
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).unwrap());
            }
        }
        count
    }

    #[test]
    #[ignore = "transcript probe; run with --ignored --nocapture to inspect"]
    fn probe_transcript() {
        for (label, source) in [
            ("STRING_SLICE", STRING_SLICE),
            ("TYPE_CONVERTER", TYPE_CONVERTER),
        ] {
            let raw = parse_raw(source);
            println!("== {label} raw ==");
            println!("{}", raw.root_node().to_sexp());
            println!("raw methods: {:?}", method_names(&raw, source));
            let repaired = parse_csharp(source).unwrap();
            println!("== {label} included-ranges ==");
            println!("{}", repaired.root_node().to_sexp());
            println!("repaired methods: {:?}", method_names(&repaired, source));
        }
    }

    #[test]
    fn probe_raw_parse_distorts_a_split_signature() {
        // The raw parse recovers, but it recovers wrongly: `TrimStart` appears
        // twice, once from each branch, and the later members hang inside the
        // `#else` branch of an unterminated `preproc_if`.
        let raw = parse_raw(STRING_SLICE);
        assert!(raw.root_node().has_error(), "expected a broken raw parse");
        assert_eq!(
            method_names(&raw, STRING_SLICE),
            vec![
                "NextChar".to_string(),
                "PeekChar".to_string(),
                "TrimStart".to_string(),
                "TrimStart".to_string()
            ],
            "the raw parse duplicates the split member"
        );

        let repaired = parse_csharp(STRING_SLICE).unwrap();
        assert_eq!(
            method_names(&repaired, STRING_SLICE),
            vec![
                "NextChar".to_string(),
                "PeekChar".to_string(),
                "TrimStart".to_string()
            ],
            "the repaired parse names each member exactly once"
        );
        assert_eq!(error_count(&repaired), 0, "repaired parse must be clean");
        // Every member is a direct child of the struct body again.
        let sexp = repaired.root_node().to_sexp();
        assert!(
            !sexp.contains("preproc"),
            "no directive nodes remain: {sexp}"
        );
    }

    #[test]
    fn a_modifier_only_split_parses_cleanly() {
        let source = concat!(
            "public struct S {\n",
            "    public\n",
            "#if NET\n",
            "    readonly\n",
            "#endif\n",
            "    void TrimStart() { }\n",
            "    public char NextChar() { return 'a'; }\n",
            "}\n",
        );
        assert!(parse_raw(source).root_node().has_error());
        let repaired = parse_csharp(source).unwrap();
        assert_eq!(error_count(&repaired), 0);
        assert_eq!(
            method_names(&repaired, source),
            vec!["NextChar".to_string(), "TrimStart".to_string()]
        );
    }

    #[test]
    fn probe_raw_parse_of_ternary_split_is_broken() {
        let raw = parse_raw(TYPE_CONVERTER);
        assert!(raw.root_node().has_error(), "expected a broken raw parse");
        assert!(error_count(&raw) > 0);

        let repaired = parse_csharp(TYPE_CONVERTER).unwrap();
        assert_eq!(error_count(&repaired), 0, "repaired parse must be clean");
        assert_eq!(
            method_names(&repaired, TYPE_CONVERTER),
            vec!["ChangeType".to_string(), "ParseInt".to_string()]
        );
    }

    #[test]
    fn directive_free_source_has_no_ranges() {
        let scan = scan_preprocessor("class A { void M() {} }\n");
        assert!(scan.included_ranges.is_none());
        assert!(!scan.has_inactive_regions);
    }

    /// The kept text, reconstructed from the ranges, for readable assertions.
    fn kept_text(source: &str) -> String {
        match scan_preprocessor(source).included_ranges {
            None => source.to_string(),
            Some(ranges) => ranges
                .iter()
                .map(|range| &source[range.start_byte..range.end_byte])
                .collect(),
        }
    }

    #[test]
    fn first_branch_of_a_chain_is_active() {
        let source = "#if A\nint a;\n#elif B\nint b;\n#else\nint c;\n#endif\n";
        assert_eq!(kept_text(source), "int a;\n");
        assert!(scan_preprocessor(source).has_inactive_regions);
    }

    #[test]
    fn literal_false_condition_activates_the_next_branch() {
        let source = "#if false\nint a;\n#elif false\nint b;\n#else\nint c;\n#endif\n";
        assert_eq!(kept_text(source), "int c;\n");
    }

    #[test]
    fn nested_chain_inside_an_inactive_branch_stays_inactive() {
        let source = "#if false\n#if A\nint a;\n#else\nint b;\n#endif\n#else\nint c;\n#endif\n";
        assert_eq!(kept_text(source), "int c;\n");
    }

    #[test]
    fn nested_chain_inside_an_active_branch_selects_its_first_branch() {
        let source = "#if A\n#if B\nint a;\n#else\nint b;\n#endif\n#endif\n";
        assert_eq!(kept_text(source), "int a;\n");
    }

    #[test]
    fn hash_inside_comments_and_strings_is_not_a_directive() {
        let source = concat!(
            "// #if A\n",
            "/*\n",
            "#if B\n",
            "*/\n",
            "var v = @\"\n",
            "#if C\n",
            "\";\n",
            "var r = \"\"\"\n",
            "#if D\n",
            "\"\"\";\n",
        );
        let scan = scan_preprocessor(source);
        assert!(
            scan.included_ranges.is_none(),
            "no line here is a directive line"
        );
    }

    #[test]
    fn doubled_quotes_do_not_close_a_verbatim_string() {
        let source = "var v = @\"a\"\"b\n#if A\n\";\nint x;\n";
        assert!(
            scan_preprocessor(source).included_ranges.is_none(),
            "the `#if` sits inside the verbatim string"
        );
    }

    #[test]
    fn interpolated_verbatim_string_spans_lines() {
        let source = "var v = $@\"{x}\n#if A\n\";\n";
        assert!(scan_preprocessor(source).included_ranges.is_none());
    }

    #[test]
    fn raw_string_closes_only_on_an_equal_or_longer_quote_run() {
        let source = "var v = \"\"\"\"\n\"\"\"\n#if A\nint a;\n\"\"\"\"\n";
        assert!(
            scan_preprocessor(source).included_ranges.is_none(),
            "a three-quote run cannot close a four-quote raw string"
        );
    }

    #[test]
    fn unbalanced_directives_do_not_panic() {
        assert_eq!(kept_text("#endif\nint a;\n"), "int a;\n");
        assert_eq!(kept_text("#else\nint a;\n"), "int a;\n");
        assert_eq!(kept_text("#if A\nint a;\n"), "int a;\n");
        assert_eq!(kept_text("#elif A\nint a;\n"), "int a;\n");
    }

    #[test]
    fn crlf_line_endings_scan_as_lines() {
        let source = "#if false\r\nint a;\r\n#else\r\nint b;\r\n#endif\r\n";
        assert_eq!(kept_text(source), "int b;\r\n");
    }

    #[test]
    fn directive_on_the_last_line_without_a_newline() {
        let source = "int a;\n#endif";
        assert_eq!(kept_text(source), "int a;\n");
    }

    #[test]
    fn a_wholly_inactive_file_emits_one_zero_width_range() {
        let source = "#if false\nint a;\n#endif\n";
        let ranges = scan_preprocessor(source).included_ranges.unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_byte, 0);
        assert_eq!(ranges[0].end_byte, 0);
        let tree = parse_csharp(source).unwrap();
        assert_eq!(tree.root_node().named_child_count(), 0);
    }

    #[test]
    fn range_points_match_their_byte_offsets() {
        let ranges = scan_preprocessor(STRING_SLICE).included_ranges.unwrap();
        for range in &ranges {
            let prefix = &STRING_SLICE[..range.start_byte];
            assert_eq!(range.start_point.row, prefix.matches('\n').count());
            let column = prefix.len() - prefix.rfind('\n').map_or(0, |index| index + 1);
            assert_eq!(range.start_point.column, column);
        }
    }

    #[test]
    fn recovered_nodes_keep_raw_file_offsets() {
        let tree = parse_csharp(STRING_SLICE).unwrap();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_declaration"
                && let Some(name) = node.child_by_field_name("name")
                && &STRING_SLICE[name.byte_range()] == "TrimStart"
            {
                let expected = STRING_SLICE.find("void TrimStart").unwrap() + "void ".len();
                assert_eq!(name.start_byte(), expected);
                return;
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).unwrap());
            }
        }
        panic!("TrimStart was not found in the repaired tree");
    }
}
