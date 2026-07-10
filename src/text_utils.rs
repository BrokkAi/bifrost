pub(crate) fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    let mut iter = content.char_indices().peekable();

    while let Some((index, ch)) = iter.next() {
        match ch {
            '\r' => {
                let mut next_start = index + ch.len_utf8();
                if let Some((next_index, '\n')) = iter.peek().copied() {
                    next_start = next_index + '\n'.len_utf8();
                    iter.next();
                }
                if next_start <= content.len() {
                    starts.push(next_start);
                }
            }
            '\n' => {
                let next_start = index + ch.len_utf8();
                if next_start <= content.len() {
                    starts.push(next_start);
                }
            }
            _ => {}
        }
    }

    starts
}

pub(crate) fn find_line_index_for_offset(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    }
}

/// Extract the alphanumeric/underscore identifier surrounding `offset` in
/// `content`. Returns `None` if neither the byte at `offset` nor the byte
/// immediately before it is part of an identifier.
#[cfg(test)]
pub(crate) fn identifier_at_offset(content: &str, offset: usize) -> Option<&str> {
    let (start, end) = identifier_span_at_offset(content, offset)?;
    content.get(start..end)
}

/// Like [`identifier_at_offset`] but returns the byte span `(start, end)`
/// inside `content` instead of the slice.
pub(crate) fn identifier_span_at_offset(content: &str, offset: usize) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut start = offset.min(bytes.len());
    let mut end = offset.min(bytes.len());

    if start == bytes.len() && start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
        end = start;
    }
    if start >= bytes.len() || !is_ident_byte(bytes[start]) {
        if start == 0 {
            return None;
        }
        start -= 1;
        end = start;
        if !is_ident_byte(bytes[start]) {
            return None;
        }
    }

    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    if start == end {
        return None;
    }
    Some((start, end))
}

/// Extract the identifier prefix that ends at `offset` (the byte position of
/// the cursor). Walks backward while bytes match [`is_ident_byte`]; does NOT
/// walk forward past the cursor.
pub(crate) fn identifier_prefix_before_offset(content: &str, offset: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    if offset > bytes.len() {
        return None;
    }
    let end = offset;
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    content.get(start..end)
}

pub(crate) fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Find the first occurrence of `needle` in `haystack` that is bounded on
/// both sides by a non-identifier byte (or buffer edge).
pub(crate) fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let needle_bytes = needle.as_bytes();
    let bytes = haystack.as_bytes();
    if needle_bytes.is_empty() || needle_bytes.len() > bytes.len() {
        return None;
    }
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(needle) {
        let candidate = start + rel;
        let before_ok = candidate == 0 || !is_ident_byte(bytes[candidate - 1]);
        let after_idx = candidate + needle_bytes.len();
        let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok && after_ok {
            return Some(candidate);
        }
        // Advance past this candidate's first byte so we don't loop forever.
        start = candidate + 1;
    }
    None
}

pub(crate) fn snippet_around_line(
    source: &str,
    line_starts: &[usize],
    line_idx: usize,
    context_lines: usize,
) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let snippet_start = line_idx.saturating_sub(context_lines);
    let snippet_end = line_idx
        .saturating_add(context_lines)
        .min(line_starts.len().saturating_sub(1));

    let mut snippet = String::new();
    for idx in snippet_start..=snippet_end {
        let start = line_starts[idx];
        let end = line_starts.get(idx + 1).copied().unwrap_or(source.len());
        snippet.push_str(source.get(start..end).unwrap_or_default());
    }
    snippet
}

pub(crate) fn trimmed_snippet_around_line(
    source: &str,
    line_starts: &[usize],
    line_idx: usize,
    context_lines: usize,
) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let line_count = line_starts.len();
    let snippet_start = line_idx.saturating_sub(context_lines);
    let snippet_end = line_idx
        .saturating_add(context_lines)
        .min(line_count.saturating_sub(1));

    let mut buf = String::new();
    for idx in snippet_start..=snippet_end {
        let start = line_starts[idx];
        let end = line_starts.get(idx + 1).copied().unwrap_or(source.len());
        let line = source[start..end]
            .trim_end_matches('\n')
            .trim_end_matches('\r');
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(line);
    }
    buf
}

pub(crate) fn trimmed_snippet_around_range(
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    context_lines: usize,
) -> String {
    let start_line = find_line_index_for_offset(line_starts, start);
    let end_line = find_line_index_for_offset(line_starts, end);
    let snippet_start_line = start_line.saturating_sub(context_lines);
    let snippet_end_line = end_line + context_lines + 1;

    let snippet_start = *line_starts.get(snippet_start_line).unwrap_or(&0);
    let snippet_end = line_starts
        .get(snippet_end_line)
        .copied()
        .unwrap_or(source.len());

    source[snippet_start..snippet_end].trim().to_string()
}

const LOCATION_CONTEXT_LINES: usize = 2;
const LOCATION_LINE_MAX_CHARS: usize = 160;

pub(crate) fn render_location_diagnostic(
    source: &str,
    path: &str,
    line: usize,
    column: Option<usize>,
    reason: &str,
    recovery: &str,
) -> String {
    let line_starts = compute_line_starts(source);
    let line_count = line_starts.len();
    let number_width = line_count.max(line).to_string().len();
    let requested = match column {
        Some(column) => format!("{path}:{line}:{column}"),
        None => format!("{path}:{line} (column not supplied)"),
    };
    let mut rendered = format!("{reason}\nRequested location: {requested}\nSource context:");

    if (1..=line_count).contains(&line) {
        let first = line.saturating_sub(LOCATION_CONTEXT_LINES).max(1);
        let last = line.saturating_add(LOCATION_CONTEXT_LINES).min(line_count);
        for current in first..=last {
            let raw = source_line(source, &line_starts, current);
            let requested_character = (current == line).then(|| {
                column
                    .unwrap_or(1)
                    .saturating_sub(1)
                    .min(raw.chars().count())
            });
            let (display, caret) = render_bounded_source_line(raw, requested_character);
            let marker = if current == line { '>' } else { ' ' };
            rendered.push_str(&format!("\n{marker} {current:>number_width$} | {display}"));
            if let Some(caret) = caret {
                rendered.push_str(&format!(
                    "\n  {:>number_width$} | {}^ {}",
                    "",
                    " ".repeat(caret),
                    requested_location_label(line, column, raw.chars().count())
                ));
            }
        }
    } else if line == 0 {
        render_virtual_requested_line(
            &mut rendered,
            number_width,
            line,
            column,
            "requested line is before the first source line",
        );
        for current in 1..=line_count.min(LOCATION_CONTEXT_LINES + 1) {
            let (display, _) =
                render_bounded_source_line(source_line(source, &line_starts, current), None);
            rendered.push_str(&format!("\n  {current:>number_width$} | {display}"));
        }
    } else {
        let first = line_count.saturating_sub(LOCATION_CONTEXT_LINES).max(1);
        for current in first..=line_count {
            let (display, _) =
                render_bounded_source_line(source_line(source, &line_starts, current), None);
            rendered.push_str(&format!("\n  {current:>number_width$} | {display}"));
        }
        render_virtual_requested_line(
            &mut rendered,
            number_width,
            line,
            column,
            "requested line is after the last source line",
        );
    }

    rendered.push_str("\nRecovery: ");
    rendered.push_str(recovery);
    rendered
}

fn source_line<'a>(source: &'a str, line_starts: &[usize], line: usize) -> &'a str {
    let start = line_starts
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or(0);
    let end = line_starts.get(line).copied().unwrap_or(source.len());
    source
        .get(start..end)
        .unwrap_or_default()
        .trim_end_matches(['\r', '\n'])
}

fn render_bounded_source_line(
    line: &str,
    requested_character: Option<usize>,
) -> (String, Option<usize>) {
    let characters: Vec<char> = line
        .chars()
        .map(|character| if character == '\t' { '→' } else { character })
        .collect();
    let requested_character = requested_character.map(|index| index.min(characters.len()));
    let (start, end) = if characters.len() <= LOCATION_LINE_MAX_CHARS {
        (0, characters.len())
    } else if let Some(requested) = requested_character {
        let start = requested
            .saturating_sub(LOCATION_LINE_MAX_CHARS / 3)
            .min(characters.len() - LOCATION_LINE_MAX_CHARS);
        (start, start + LOCATION_LINE_MAX_CHARS)
    } else {
        (0, LOCATION_LINE_MAX_CHARS)
    };
    let has_prefix = start > 0;
    let has_suffix = end < characters.len();
    let mut display = String::new();
    if has_prefix {
        display.push('…');
    }
    display.extend(&characters[start..end]);
    if has_suffix {
        display.push('…');
    }
    let caret = requested_character.map(|requested| {
        usize::from(has_prefix) + requested.saturating_sub(start).min(end - start)
    });
    (display, caret)
}

fn requested_location_label(line: usize, column: Option<usize>, line_chars: usize) -> String {
    match column {
        Some(0) => {
            format!("requested line {line}, column 0 (before column 1)")
        }
        Some(column) if column > line_chars.saturating_add(1) => format!(
            "requested line {line}, column {column} (past line end at column {})",
            line_chars + 1
        ),
        Some(column) => format!("requested line {line}, column {column}"),
        None => format!("requested line {line}; column not supplied (marker at column 1)"),
    }
}

fn render_virtual_requested_line(
    rendered: &mut String,
    number_width: usize,
    line: usize,
    column: Option<usize>,
    boundary_note: &str,
) {
    rendered.push_str(&format!(
        "\n> {line:>number_width$} | [{boundary_note}]\n  {:>number_width$} | ^ {}",
        "",
        match column {
            Some(column) => format!("requested line {line}, column {column}"),
            None => format!("requested line {line}; column not supplied"),
        }
    ));
}

#[cfg(test)]
mod tests {
    use super::{compute_line_starts, find_line_index_for_offset, render_location_diagnostic};

    #[test]
    fn compute_line_starts_handles_mixed_line_endings() {
        assert_eq!(vec![0, 2, 4, 5], compute_line_starts("a\nb\n\nc"));
        assert_eq!(vec![0, 4, 7], compute_line_starts("ab\r\nc\r\nd"));
        assert_eq!(vec![0, 2, 4], compute_line_starts("x\ry\rz"));
        assert_eq!(vec![0, 3], compute_line_starts("a\r\n"));
        assert_eq!(vec![0], compute_line_starts(""));
    }

    #[test]
    fn find_line_index_tracks_separator_offsets() {
        let starts = compute_line_starts("ab\r\nc\nd\re");
        assert_eq!(vec![0, 4, 6, 8], starts);

        let expected = [0, 0, 0, 0, 1, 1, 2, 2, 3];
        for (offset, expected_line) in expected.into_iter().enumerate() {
            assert_eq!(
                expected_line,
                find_line_index_for_offset(&starts, offset),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn location_diagnostic_marks_unicode_character_column_with_context() {
        let rendered = render_location_diagnostic(
            "one\nαβ target\nthree\nfour\n",
            "src/demo.rs",
            2,
            Some(4),
            "no target at location",
            "move the target to a declaration token",
        );

        assert!(rendered.contains("Requested location: src/demo.rs:2:4"));
        assert!(rendered.contains("  1 | one"));
        assert!(rendered.contains("> 2 | αβ target"));
        assert!(rendered.contains("|    ^ requested line 2, column 4"));
        assert!(rendered.contains("  3 | three"));
        assert!(rendered.contains("Recovery: move the target"));
    }

    #[test]
    fn location_diagnostic_marks_omitted_and_past_end_columns_truthfully() {
        let line_only = render_location_diagnostic(
            "first\nsecond\nthird",
            "demo.rs",
            2,
            None,
            "no declaration",
            "retry",
        );
        assert!(line_only.contains("demo.rs:2 (column not supplied)"));
        assert!(line_only.contains("column not supplied (marker at column 1)"));

        let past_end =
            render_location_diagnostic("short", "demo.rs", 1, Some(99), "invalid column", "retry");
        assert!(past_end.contains("requested line 1, column 99 (past line end at column 6)"));
    }

    #[test]
    fn location_diagnostic_shows_nearest_boundary_for_invalid_line() {
        let before = render_location_diagnostic(
            "one\ntwo\nthree",
            "demo.rs",
            0,
            Some(1),
            "invalid line",
            "retry",
        );
        assert!(before.contains("> 0 | [requested line is before the first source line]"));
        assert!(before.contains("  1 | one"));

        let after = render_location_diagnostic(
            "one\ntwo\nthree",
            "demo.rs",
            8,
            Some(2),
            "invalid line",
            "retry",
        );
        assert!(after.contains("  2 | two"));
        assert!(after.contains("  3 | three"));
        assert!(after.contains("> 8 | [requested line is after the last source line]"));
    }

    #[test]
    fn location_diagnostic_bounds_long_lines_around_requested_column() {
        let source = "x".repeat(500);
        let rendered =
            render_location_diagnostic(&source, "generated.rs", 1, Some(400), "no target", "retry");

        assert!(rendered.contains("…"));
        assert!(rendered.contains("requested line 1, column 400"));
        assert!(rendered.len() < 400, "{rendered}");
    }
}
