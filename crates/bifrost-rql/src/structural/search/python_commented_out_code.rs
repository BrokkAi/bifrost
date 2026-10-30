//! Query-scoped Python comment blocks and CodeQL's commented-out-code rules.

use super::*;
use regex::Regex;
use std::sync::OnceLock;

#[derive(Default)]
pub(super) struct PythonCommentedOutCodeCache {
    files: HashMap<ProjectFile, HashMap<usize, python_rule_facts::PythonRuleFactValue>>,
}

impl PythonCommentedOutCodeCache {
    pub(super) fn expansions_for_match(&mut self, seed: &SeedMatch) -> Vec<PipelineExpansion> {
        if seed.language != Language::Python
            || seed.facts.node(seed.fact_match.node).kind != NormalizedKind::Comment
        {
            return Vec::new();
        }
        if !self.files.contains_key(&seed.file) {
            self.files.insert(
                seed.file.clone(),
                commented_out_code_blocks(&seed.file, &seed.facts),
            );
        }
        let start = seed.facts.node(seed.fact_match.node).range.start_byte;
        self.files
            .get(&seed.file)
            .and_then(|blocks| blocks.get(&start))
            .cloned()
            .map(|fact| pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(fact))))
            .into_iter()
            .collect()
    }
}

#[derive(Clone)]
struct CommentLine {
    span: Span,
    start_line: usize,
    end_line: usize,
    text: String,
    indentation: Option<usize>,
}

struct Patterns {
    words: Regex,
    class_start: Regex,
    def_start: Regex,
    if_start: Regex,
    for_start: Regex,
    with_start: Regex,
    try_start: Regex,
    commented_out_comment: Regex,
    comments_after_code: Regex,
    filler: Regex,
    file_or_url: Regex,
    empty: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        words: Regex::new(r"\w+").expect("fixed comment word pattern compiles"),
        class_start: Regex::new(r"#(\S*\s+)?class\s+\w+.*:\s*(#.*)?$")
            .expect("fixed comment class pattern compiles"),
        def_start: Regex::new(r"#(\S*\s+)?def\s.*\(.*\).*:\s*(#.*)?$")
            .expect("fixed comment def pattern compiles"),
        if_start: Regex::new(r"#(\S*\s+)?(el)?if\s.*:\s*(#.*)?$|#(\S*\s+)?else:\s*(#.*)?$")
            .expect("fixed comment if pattern compiles"),
        for_start: Regex::new(r"#(\S*\s+)?for\s.*\sin\s.*:\s*(#.*)?$")
            .expect("fixed comment for pattern compiles"),
        with_start: Regex::new(r"#(\S*\s+)?with\s+.*:\s*(#.*)?$")
            .expect("fixed comment with pattern compiles"),
        try_start: Regex::new(r"#(\S*\s+)?try:\s*(#.*)?$|#(\S*\s+)?except\s*(\w+\s*(\sas\s+\w+\s*)?)?:\s*(#.*)?$|#(\S*\s+)?finally:\s*(#.*)?$")
            .expect("fixed comment try pattern compiles"),
        commented_out_comment: Regex::new(r"#+\s+#.*$")
            .expect("fixed nested-comment pattern compiles"),
        comments_after_code: Regex::new(r"#\S+\s.*#.*$")
            .expect("fixed inline-comment pattern compiles"),
        filler: Regex::new(r"^#+[\s*#\-_=+]*$").expect("fixed comment filler pattern compiles"),
        file_or_url: Regex::new(r#"#[^'"]+(https?|file)://.*|#[^'"]+(/[a-zA-Z]\w*)+\.[a-zA-Z]+.*|#[^'"]+(\\[a-zA-Z]\w*)+\.[a-zA-Z]+.*"#)
            .expect("fixed comment path pattern compiles"),
        empty: Regex::new(r"^#+\s*$").expect("fixed empty comment pattern compiles"),
    })
}

fn commented_out_code_blocks(
    file: &ProjectFile,
    facts: &FileFacts,
) -> HashMap<usize, python_rule_facts::PythonRuleFactValue> {
    let source = facts.source();
    let mut comments = facts
        .nodes()
        .iter()
        .filter(|node| node.kind == NormalizedKind::Comment)
        .filter_map(|node| {
            let span = node.span();
            let text = source.get(span.start_byte..span.end_byte)?.to_owned();
            let range = python_rule_facts::row_range(source, span.start_byte..span.end_byte);
            let first_code_character = text
                .char_indices()
                .find(|(_, character)| !character.is_whitespace() && *character != '#')
                .map(|(index, _)| index);
            let mut comment = CommentLine {
                span,
                start_line: range.start_line,
                end_line: range.end_line,
                text,
                indentation: None,
            };
            if is_maybe_code(&comment, facts) {
                comment.indentation =
                    first_code_character.map(|offset| range.start_column + offset);
            }
            Some(comment)
        })
        .collect::<Vec<_>>();
    comments.sort_unstable_by_key(|comment| (comment.span.start_byte, comment.span.end_byte));
    if comments.is_empty() {
        return HashMap::default();
    }

    let mut rows = HashMap::default();
    let mut group_start = 0;
    for group_end in 1..=comments.len() {
        let connected = group_end < comments.len()
            && comment_nodes_share_comment_block(
                source,
                comments[group_end - 1].span,
                comments[group_end].span,
            );
        if connected {
            continue;
        }
        classify_comment_group(file, facts, &comments[group_start..group_end], &mut rows);
        group_start = group_end;
    }
    rows
}

fn comment_nodes_share_comment_block(source: &str, previous: Span, next: Span) -> bool {
    assert!(previous.end_byte <= next.start_byte);
    source
        .get(previous.end_byte..next.start_byte)
        .expect("comment spans must be UTF-8 aligned source ranges")
        .chars()
        .all(char::is_whitespace)
}

fn classify_comment_group(
    file: &ProjectFile,
    facts: &FileFacts,
    comments: &[CommentLine],
    rows: &mut HashMap<usize, python_rule_facts::PythonRuleFactValue>,
) {
    let code = commented_out_code_members(comments, facts);
    let code_count = comments
        .iter()
        .zip(&code)
        .filter(|(comment, is_code)| **is_code && !is_empty_comment(&comment.text))
        .count();
    if comments.len() > code_count.saturating_mul(2) {
        return;
    }

    let mut index = 0;
    while index < comments.len() {
        if is_empty_comment(&comments[index].text) || !code[index] {
            index += 1;
            continue;
        }
        let start = index;
        let mut end = index;
        let mut next = next_non_empty(comments, end + 1);
        while let Some(next_index) = next {
            if !code[next_index] {
                break;
            }
            end = next_index;
            next = next_non_empty(comments, end + 1);
        }
        if start != end {
            let first = &comments[start];
            let last = &comments[end];
            let anchor = first.span.start_byte..last.span.end_byte;
            let mut fact = python_rule_facts::make_row(
                "commented_out_code_block",
                file,
                anchor.clone(),
                python_rule_facts::row_range(facts.source(), anchor.clone()),
                None,
                "code",
                "proven",
                true,
                None,
            );
            let block_text = facts
                .source()
                .get(anchor.clone())
                .expect("comment block span is a source range")
                .to_owned();
            fact.row.comment_block_lines = Some(block_text.lines().map(str::to_owned).collect());
            fact.row.comment_block_text = Some(block_text);
            rows.insert(first.span.start_byte, fact);
        }
        index = end + 1;
    }
}

fn commented_out_code_members(comments: &[CommentLine], facts: &FileFacts) -> Vec<bool> {
    let mut code = vec![false; comments.len()];
    for (index, comment) in comments.iter().enumerate() {
        if is_scope_start(comment, facts) {
            code[index] = true;
            if let Some(base_indent) = comment.indentation {
                mark_scope_body(comments, index + 1, base_indent, &mut code);
            }
        }
        if is_block_start(comment, facts)
            && let Some(base_indent) = comment.indentation
            && let Some(first_body) = next_non_empty(comments, index + 1)
            && comments[first_body]
                .indentation
                .is_some_and(|indentation| indentation > base_indent)
        {
            code[index] = true;
            let mut current = first_body;
            loop {
                code[current] = true;
                let Some(next_index) = next_non_empty(comments, current + 1) else {
                    break;
                };
                let deeper = comments[next_index]
                    .indentation
                    .is_some_and(|indentation| indentation > base_indent);
                if !deeper && !is_block_start(&comments[next_index], facts) {
                    break;
                }
                current = next_index;
            }
        }
    }
    code
}

fn mark_scope_body(
    comments: &[CommentLine],
    mut index: usize,
    base_indent: usize,
    code: &mut [bool],
) {
    let mut next = next_non_empty(comments, index);
    let mut docstring_delimiter = None;
    while let Some(next_index) = next {
        let comment = &comments[next_index];
        if let Some(delimiter) = docstring_delimiter {
            code[next_index] = true;
            if comment.text.contains(delimiter) {
                docstring_delimiter = None;
            }
            next = next_non_empty(comments, next_index + 1);
            continue;
        }
        if let Some(delimiter) = triple_quote_delimiter(&comment.text) {
            code[next_index] = true;
            if comment.text.matches(delimiter).count() == 1 {
                docstring_delimiter = Some(delimiter);
            }
            next = next_non_empty(comments, next_index + 1);
            continue;
        }
        let Some(indentation) = comment.indentation else {
            break;
        };
        if indentation <= base_indent {
            break;
        }
        code[next_index] = true;
        index = next_index + 1;
        next = next_non_empty(comments, index);
    }
}

fn triple_quote_delimiter(text: &str) -> Option<&'static str> {
    [(r#"""""#, text.find(r#"""""#)), ("'''", text.find("'''"))]
        .into_iter()
        .filter_map(|(delimiter, index)| index.map(|index| (delimiter, index)))
        .min_by_key(|(_, index)| *index)
        .map(|(delimiter, _)| delimiter)
}

fn next_non_empty(comments: &[CommentLine], mut index: usize) -> Option<usize> {
    while index < comments.len() && is_empty_comment(&comments[index].text) {
        index += 1;
    }
    (index < comments.len()).then_some(index)
}

fn is_empty_comment(text: &str) -> bool {
    patterns().empty.is_match(text)
}

fn is_scope_start(comment: &CommentLine, facts: &FileFacts) -> bool {
    let patterns = patterns();
    (patterns.def_start.is_match(&comment.text) || patterns.class_start.is_match(&comment.text))
        && !is_non_code(comment)
        && !is_endline_comment(comment, facts)
        && comment.indentation.is_some()
}

fn is_block_start(comment: &CommentLine, facts: &FileFacts) -> bool {
    let patterns = patterns();
    (patterns.if_start.is_match(&comment.text)
        || patterns.for_start.is_match(&comment.text)
        || patterns.with_start.is_match(&comment.text)
        || patterns.try_start.is_match(&comment.text))
        && !is_non_code(comment)
        && !is_endline_comment(comment, facts)
        && comment.indentation.is_some()
}

fn is_maybe_code(comment: &CommentLine, facts: &FileFacts) -> bool {
    let patterns = patterns();
    patterns.commented_out_comment.is_match(&comment.text)
        || (!is_non_code(comment)
            && !patterns.filler.is_match(&comment.text)
            && !is_endline_comment(comment, facts)
            && !patterns.file_or_url.is_match(&comment.text))
}

fn is_non_code(comment: &CommentLine) -> bool {
    let patterns = patterns();
    if comment.text.contains(">>>") || comment.text.contains("...") {
        return true;
    }
    let words = patterns.words.find_iter(&comment.text).collect::<Vec<_>>();
    for pair in words.windows(2) {
        let first = pair[0];
        let second = pair[1];
        let gap = &comment.text[first.end()..second.start()];
        if gap.is_empty()
            || !gap.chars().all(char::is_whitespace)
            || comment.text[..first.start()].contains('\'')
            || comment.text[..first.start()].contains('"')
        {
            continue;
        }
        let first_word = first.as_str();
        let second_word = second.as_str();
        let operator_keyword = ["import", "and", "is", "or", "in", "not", "as"];
        let keyword_requires_colon = [
            "try", "while", "elif", "else", "if", "except", "def", "class",
        ];
        let other_keyword = [
            "del", "lambda", "raise", "return", "for", "from", "global", "with", "assert", "yield",
            "finally", "print", "exec",
        ];
        let first_is_keyword = operator_keyword.contains(&first_word)
            || keyword_requires_colon.contains(&first_word)
            || other_keyword.contains(&first_word);
        let non_code = !operator_keyword.contains(&second_word)
            && (!first_is_keyword
                || (keyword_requires_colon.contains(&first_word) && !comment.text.contains(':')));
        if non_code && !patterns.comments_after_code.is_match(&comment.text) {
            return true;
        }
    }
    false
}

fn is_endline_comment(comment: &CommentLine, facts: &FileFacts) -> bool {
    facts.nodes().iter().any(|node| {
        node.kind != NormalizedKind::Comment
            && node.range.start_line == comment.start_line
            && node.range.end_line == comment.end_line
            && node.range.end_byte <= comment.span.start_byte
            && node.range.end_byte > line_start(facts.source(), comment.span.start_byte)
    })
}

fn line_start(source: &str, byte: usize) -> usize {
    source[..byte]
        .rfind('\n')
        .map_or(0, |newline| newline.saturating_add(1))
}
