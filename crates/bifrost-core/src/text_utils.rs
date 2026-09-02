pub fn compute_line_starts(content: &str) -> Vec<usize> {
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

pub fn find_line_index_for_offset(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    }
}

/// Convert a byte offset to the analyzer's 1-based line and character-column
/// convention using canonical mixed-line-ending boundaries.
pub fn line_column_for_offset(
    content: &str,
    line_starts: &[usize],
    offset: usize,
) -> (usize, usize) {
    let bounded = offset.min(content.len());
    let mut boundary = bounded;
    while boundary > 0 && !content.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let line_index = find_line_index_for_offset(line_starts, boundary);
    let line_start = line_starts.get(line_index).copied().unwrap_or(0);
    let column = content
        .get(line_start..boundary)
        .map_or(1, |prefix| prefix.chars().count() + 1);
    (line_index + 1, column)
}

/// Extract the alphanumeric/underscore identifier surrounding `offset` in
/// `content`. Returns `None` if neither the byte at `offset` nor the byte
/// immediately before it is part of an identifier.
pub fn identifier_at_offset(content: &str, offset: usize) -> Option<&str> {
    let (start, end) = identifier_span_at_offset(content, offset)?;
    content.get(start..end)
}

/// Like [`identifier_at_offset`] but returns the byte span `(start, end)`
/// inside `content` instead of the slice.
pub fn identifier_span_at_offset(content: &str, offset: usize) -> Option<(usize, usize)> {
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
pub fn identifier_prefix_before_offset(content: &str, offset: usize) -> Option<&str> {
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

pub fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Find the first occurrence of `needle` in `haystack` that is bounded on
/// both sides by a non-identifier byte (or buffer edge).
pub fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let needle_bytes = needle.as_bytes();
    let bytes = haystack.as_bytes();
    let first_char = needle.chars().next()?;
    if needle_bytes.len() > bytes.len() {
        return None;
    }
    // A rejected candidate is retried from the next character, not the next
    // byte: restarting mid code point would slice `haystack` off a char
    // boundary, and stepping a whole needle would skip a candidate that
    // overlaps the rejected one.
    let step = first_char.len_utf8();
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(needle) {
        let candidate = start + rel;
        let before_ok = candidate == 0 || !is_ident_byte(bytes[candidate - 1]);
        let after_idx = candidate + needle_bytes.len();
        let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok && after_ok {
            return Some(candidate);
        }
        debug_assert!(
            haystack.is_char_boundary(candidate + step),
            "needle {needle:?} matched at {candidate} of {haystack:?} but its first \
             character does not end on a char boundary"
        );
        start = candidate + step;
    }
    None
}

pub fn snippet_around_line(
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

pub fn trimmed_snippet_around_line(
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
        // Separate on every row after the first, so a blank leading row still
        // occupies a row and snippet row N stays table row `snippet_start + N`.
        if idx > snippet_start {
            buf.push('\n');
        }
        buf.push_str(line);
    }
    buf
}

pub fn trimmed_snippet_around_range(
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

pub fn render_location_diagnostic(
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
    use super::{
        compute_line_starts, find_line_index_for_offset, find_word, line_column_for_offset,
        render_location_diagnostic, trimmed_snippet_around_line,
    };

    #[test]
    fn compute_line_starts_handles_mixed_line_endings() {
        assert_eq!(vec![0, 2, 4, 5], compute_line_starts("a\nb\n\nc"));
        assert_eq!(vec![0, 4, 7], compute_line_starts("ab\r\nc\r\nd"));
        assert_eq!(vec![0, 2, 4], compute_line_starts("x\ry\rz"));
        assert_eq!(vec![0, 3], compute_line_starts("a\r\n"));
        assert_eq!(vec![0], compute_line_starts(""));
    }

    #[test]
    fn line_columns_use_canonical_mixed_line_endings() {
        let source = "a\rb\r\nç\nd";
        let starts = compute_line_starts(source);
        assert_eq!(line_column_for_offset(source, &starts, 2), (2, 1));
        assert_eq!(line_column_for_offset(source, &starts, 5), (3, 1));
        assert_eq!(line_column_for_offset(source, &starts, 7), (3, 2));
        assert_eq!(
            line_column_for_offset(source, &starts, source.len()),
            (4, 2)
        );
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
    fn find_word_retries_after_a_rejected_multi_byte_candidate() {
        // The rejected candidate starts with a 4-byte character, so the retry
        // point must be the next character, not the next byte.
        assert_eq!(find_word("\u{1f600}a", "\u{1f600}"), None);
        assert_eq!(find_word("a\u{1f600} \u{1f600}", "\u{1f600}"), Some(6));
        // A candidate that overlaps a rejected one is still considered.
        assert_eq!(find_word("za.a.a", "a.a"), Some(3));
    }

    #[test]
    fn trimmed_snippet_keeps_blank_rows_before_the_first_content_row() {
        let source = "\n\n\n";
        let starts = compute_line_starts(source);
        assert_eq!(vec![0, 1, 2, 3], starts);
        assert_eq!("\n", trimmed_snippet_around_line(source, &starts, 0, 1));

        let source = "\n\nlast";
        let starts = compute_line_starts(source);
        assert_eq!(
            "\n\nlast",
            trimmed_snippet_around_line(source, &starts, 2, 2)
        );
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

/// Generative properties for the line table and the byte-offset helpers built
/// on top of it.
///
/// The historical defects these cover are all convention mismatches at a seam:
/// a CRLF pair counted as two terminators, a CR-only file whose line count came
/// from `str::lines`, and a byte offset that landed inside a UTF-8 code point
/// and was then used to slice. The generators therefore build content out of
/// line-terminator atoms (`\n`, `\r\n`, lone `\r`) interleaved with characters
/// that are 1, 2, 3, and 4 UTF-8 bytes wide.
#[cfg(test)]
mod text_utils_properties {
    use super::{
        compute_line_starts, find_line_index_for_offset, find_word, identifier_at_offset,
        identifier_prefix_before_offset, identifier_span_at_offset, is_ident_byte,
        line_column_for_offset, render_location_diagnostic, snippet_around_line,
        trimmed_snippet_around_line, trimmed_snippet_around_range,
    };
    use proptest::prelude::*;

    /// Atoms whose concatenations reproduce every line-ending and code-point
    /// width combination the line table claims to support.
    const CONTENT_ATOMS: &[&str] = &[
        "\n",
        "\r\n",
        "\r",
        "a",
        "xyz",
        "\u{e9}",
        "\u{4e16}",
        "\u{1f600}",
    ];

    /// Shapes a uniform concatenation reaches only rarely: an empty file, a
    /// file that is only terminators, and a lone CR at end of file.
    const CONTENT_EDGE_CASES: &[&str] = &[
        "",
        "\n",
        "\r",
        "\r\n",
        "a\n",
        "a\r",
        "a\r\n",
        "\n\n\n",
        "\r\r\r",
        "\r\n\r\n",
        "\u{1f600}\r\n",
        "a\rb\r\n\u{e9}\nd",
    ];

    /// The identifier and word helpers need identifier bytes adjacent to the
    /// multi-byte atoms, so they draw from a superset of [`CONTENT_ATOMS`].
    const IDENTIFIER_ATOMS: &[&str] = &[
        "a",
        "xyz",
        "foo_bar",
        "9",
        "_",
        " ",
        ".",
        "(",
        "\n",
        "\r\n",
        "\r",
        "\u{e9}",
        "\u{4e16}",
        "\u{1f600}",
    ];

    const ASCII_NEEDLES: &[&str] = &["a", "xyz", "foo_bar", "9", "_", "zz"];

    const MULTI_BYTE_NEEDLES: &[&str] = &["\u{e9}", "\u{4e16}", "\u{1f600}", "\u{e9}a"];

    fn content() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => prop::sample::select(CONTENT_EDGE_CASES.to_vec()).prop_map(|atom| atom.to_string()),
            7 => prop::collection::vec(prop::sample::select(CONTENT_ATOMS.to_vec()), 0..12)
                .prop_map(|atoms| atoms.concat()),
        ]
    }

    fn identifier_content() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(IDENTIFIER_ATOMS.to_vec()), 0..10)
            .prop_map(|atoms| atoms.concat())
    }

    fn char_boundaries(content: &str) -> Vec<usize> {
        (0..=content.len())
            .filter(|&offset| content.is_char_boundary(offset))
            .collect()
    }

    /// Count lines with a CR state machine rather than with the lookahead
    /// [`compute_line_starts`] uses, so a defect in the lookahead cannot hide
    /// inside a shared expectation. A file always has at least one line; a CRLF
    /// pair is one terminator, counted at the CR.
    fn expected_line_count(content: &str) -> usize {
        let mut lines = 1usize;
        let mut previous_was_cr = false;
        for ch in content.chars() {
            match ch {
                '\r' => {
                    lines += 1;
                    previous_was_cr = true;
                }
                '\n' => {
                    if !previous_was_cr {
                        lines += 1;
                    }
                    previous_was_cr = false;
                }
                _ => previous_was_cr = false,
            }
        }
        lines
    }

    /// Build the same table by pushing a start after every CR and then, when an
    /// LF follows, correcting that start instead of peeking ahead first.
    fn reference_line_starts(content: &str) -> Vec<usize> {
        let mut starts = vec![0usize];
        let mut previous_was_cr = false;
        for (index, ch) in content.char_indices() {
            match ch {
                '\r' => {
                    starts.push(index + 1);
                    previous_was_cr = true;
                }
                '\n' => {
                    if previous_was_cr {
                        *starts
                            .last_mut()
                            .expect("the table always holds the file start") = index + 1;
                    } else {
                        starts.push(index + 1);
                    }
                    previous_was_cr = false;
                }
                _ => previous_was_cr = false,
            }
        }
        starts
    }

    fn previous_char_boundary(content: &str, offset: usize) -> usize {
        (0..=offset.min(content.len()))
            .rev()
            .find(|&candidate| content.is_char_boundary(candidate))
            .expect("offset 0 is always a char boundary")
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// The table starts at 0, strictly increases, sits on char boundaries,
        /// and holds exactly one entry per line under the mixed-ending
        /// convention.
        #[test]
        fn compute_line_starts_matches_an_independent_line_table(content in content()) {
            let starts = compute_line_starts(&content);

            prop_assert_eq!(starts.first().copied(), Some(0), "table for {:?}", content);
            for window in starts.windows(2) {
                prop_assert!(
                    window[0] < window[1],
                    "line starts must strictly increase, got {starts:?} for {content:?}"
                );
            }
            for &start in &starts {
                prop_assert!(
                    start <= content.len(),
                    "line start {start} past end of {content:?}"
                );
                prop_assert!(
                    content.is_char_boundary(start),
                    "line start {start} is inside a code point of {content:?}"
                );
            }
            prop_assert_eq!(
                starts.len(),
                expected_line_count(&content),
                "line count for {:?}",
                content
            );
            prop_assert_eq!(
                &starts,
                &reference_line_starts(&content),
                "line table for {:?}",
                content
            );
        }

        /// Every char-boundary offset resolves to the line whose table range
        /// contains it, and the reported column counts chars from that line
        /// start. Offsets past end of file clamp instead of panicking.
        #[test]
        fn line_lookups_agree_with_the_line_table(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in char_boundaries(&content) {
                let index = find_line_index_for_offset(&starts, offset);
                prop_assert!(
                    index < starts.len(),
                    "line index {index} out of table {starts:?} for offset {offset}"
                );
                prop_assert!(
                    starts[index] <= offset,
                    "line {index} starts after offset {offset} in {content:?}"
                );
                if let Some(&next) = starts.get(index + 1) {
                    prop_assert!(
                        offset < next,
                        "offset {offset} belongs to a later line than {index} in {content:?}"
                    );
                }

                let (line, column) = line_column_for_offset(&content, &starts, offset);
                prop_assert_eq!(
                    line,
                    index + 1,
                    "1-based line disagrees with the table at offset {} of {:?}",
                    offset,
                    content
                );
                prop_assert_eq!(
                    column,
                    content[starts[index]..offset].chars().count() + 1,
                    "column at offset {} of {:?}",
                    offset,
                    content
                );
            }

            let at_eof = line_column_for_offset(&content, &starts, content.len());
            for past_eof in [1usize, 7, 1024] {
                prop_assert_eq!(
                    line_column_for_offset(&content, &starts, content.len() + past_eof),
                    at_eof,
                    "offset {} past end of {:?} must clamp to end of file",
                    content.len() + past_eof,
                    content
                );
            }
        }

        /// An offset inside a UTF-8 code point resolves as if it were the start
        /// of that code point instead of panicking or slicing mid-char.
        #[test]
        fn line_column_snaps_offsets_inside_a_code_point(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in 0..=content.len() {
                if content.is_char_boundary(offset) {
                    continue;
                }
                prop_assert_eq!(
                    line_column_for_offset(&content, &starts, offset),
                    line_column_for_offset(
                        &content,
                        &starts,
                        previous_char_boundary(&content, offset)
                    ),
                    "offset {} inside a code point of {:?}",
                    offset,
                    content
                );
            }
        }

        /// Identifier spans lie on char boundaries inside the buffer, cover the
        /// requested offset, contain only identifier bytes, and are maximal.
        #[test]
        fn identifier_spans_are_bounded_char_boundary_slices(content in identifier_content()) {
            let bytes = content.as_bytes();

            for offset in 0..=content.len() + 3 {
                let Some((start, end)) = identifier_span_at_offset(&content, offset) else {
                    continue;
                };
                prop_assert!(
                    start < end && end <= content.len(),
                    "span {start}..{end} out of bounds for {content:?}"
                );
                prop_assert!(
                    content.is_char_boundary(start) && content.is_char_boundary(end),
                    "span {start}..{end} is inside a code point of {content:?}"
                );
                let clamped = offset.min(content.len());
                prop_assert!(
                    start <= clamped && clamped <= end,
                    "span {start}..{end} does not touch offset {clamped} of {content:?}"
                );
                prop_assert!(
                    content[start..end].bytes().all(is_ident_byte),
                    "span {start}..{end} of {content:?} holds a non-identifier byte"
                );
                prop_assert!(
                    start == 0 || !is_ident_byte(bytes[start - 1]),
                    "span {start}..{end} of {content:?} is not maximal to the left"
                );
                prop_assert!(
                    end == content.len() || !is_ident_byte(bytes[end]),
                    "span {start}..{end} of {content:?} is not maximal to the right"
                );
                prop_assert_eq!(
                    identifier_at_offset(&content, offset),
                    Some(&content[start..end]),
                    "slice and span disagree at offset {} of {:?}",
                    offset,
                    content
                );
            }
        }

        /// The completion prefix helper never walks past the cursor, never
        /// returns an empty match, and only reports a slice when the cursor is
        /// on a char boundary.
        #[test]
        fn identifier_prefixes_end_at_the_cursor(content in identifier_content()) {
            for offset in 0..=content.len() + 3 {
                let Some(prefix) = identifier_prefix_before_offset(&content, offset) else {
                    continue;
                };
                prop_assert!(offset <= content.len(), "prefix returned past end of file");
                prop_assert!(
                    content.is_char_boundary(offset),
                    "prefix {prefix:?} reported for offset {offset} inside a code point"
                );
                prop_assert!(!prefix.is_empty(), "empty prefix at offset {offset}");
                prop_assert!(
                    prefix.bytes().all(is_ident_byte),
                    "prefix {prefix:?} holds a non-identifier byte"
                );
                prop_assert!(
                    content[..offset].ends_with(prefix),
                    "prefix {prefix:?} does not end at offset {offset} of {content:?}"
                );
                let start = offset - prefix.len();
                prop_assert!(
                    start == 0 || !is_ident_byte(content.as_bytes()[start - 1]),
                    "prefix {prefix:?} at offset {offset} of {content:?} is not maximal"
                );
            }
        }

        /// A word match starts on a char boundary and is bounded by
        /// non-identifier bytes or by the buffer edges.
        #[test]
        fn find_word_matches_are_word_bounded(
            haystack in identifier_content(),
            needle in prop::sample::select(ASCII_NEEDLES.to_vec()),
        ) {
            let Some(index) = find_word(&haystack, needle) else {
                return Ok(());
            };
            prop_assert!(
                haystack.is_char_boundary(index),
                "match at {index} is inside a code point of {haystack:?}"
            );
            prop_assert!(
                haystack[index..].starts_with(needle),
                "match at {index} of {haystack:?} is not {needle:?}"
            );
            let bytes = haystack.as_bytes();
            prop_assert!(
                index == 0 || !is_ident_byte(bytes[index - 1]),
                "match at {index} of {haystack:?} runs into an identifier on the left"
            );
            let after = index + needle.len();
            prop_assert!(
                after >= bytes.len() || !is_ident_byte(bytes[after]),
                "match at {index} of {haystack:?} runs into an identifier on the right"
            );
        }

        /// The same invariant with a needle whose first character is multi-byte.
        #[test]
        fn find_word_handles_multi_byte_needles(
            haystack in identifier_content(),
            needle in prop::sample::select(MULTI_BYTE_NEEDLES.to_vec()),
        ) {
            let Some(index) = find_word(&haystack, needle) else {
                return Ok(());
            };
            prop_assert!(
                haystack.is_char_boundary(index),
                "match at {index} is inside a code point of {haystack:?}"
            );
            prop_assert!(
                haystack[index..].starts_with(needle),
                "match at {index} of {haystack:?} is not {needle:?}"
            );
        }

        /// A snippet is the exact contiguous slice spanned by the requested
        /// table rows, for any row index and context width.
        #[test]
        fn snippets_are_contiguous_slices_of_the_source(
            content in content(),
            line_idx in 0usize..20,
            context_lines in 0usize..4,
        ) {
            let starts = compute_line_starts(&content);
            let snippet = snippet_around_line(&content, &starts, line_idx, context_lines);

            let first = line_idx.saturating_sub(context_lines);
            let last = (line_idx + context_lines).min(starts.len() - 1);
            let expected = if first > last {
                ""
            } else {
                let end = starts.get(last + 1).copied().unwrap_or(content.len());
                &content[starts[first]..end]
            };
            prop_assert_eq!(
                snippet.as_str(),
                expected,
                "rows {}..={} of {:?}",
                first,
                last,
                content
            );
        }

        /// The trimmed snippet drops every line terminator: no CR survives, and
        /// the only LFs are the separators the helper inserts.
        #[test]
        fn trimmed_snippets_drop_line_terminators(
            content in content(),
            line_idx in 0usize..20,
            context_lines in 0usize..4,
        ) {
            let starts = compute_line_starts(&content);
            let trimmed = trimmed_snippet_around_line(&content, &starts, line_idx, context_lines);

            prop_assert!(
                !trimmed.contains('\r'),
                "trimmed snippet {trimmed:?} of {content:?} kept a CR"
            );
            for line in trimmed.split('\n') {
                prop_assert!(
                    content.contains(line),
                    "trimmed line {line:?} is not a slice of {content:?}"
                );
            }
        }

        /// One output row per table row in range.
        #[test]
        fn trimmed_snippets_keep_one_row_per_line(
            content in content(),
            line_idx in 0usize..20,
            context_lines in 0usize..4,
        ) {
            let starts = compute_line_starts(&content);
            let trimmed = trimmed_snippet_around_line(&content, &starts, line_idx, context_lines);

            let first = line_idx.saturating_sub(context_lines);
            let last = (line_idx + context_lines).min(starts.len() - 1);
            if first > last {
                prop_assert!(trimmed.is_empty(), "expected no rows, got {trimmed:?}");
                return Ok(());
            }
            prop_assert_eq!(
                trimmed.split('\n').count(),
                last - first + 1,
                "rows {}..={} of {:?} rendered as {:?}",
                first,
                last,
                content,
                trimmed
            );
        }

        /// The range form is a trimmed substring of the source for any pair of
        /// offsets with `start <= end`, including offsets inside a code point.
        #[test]
        fn trimmed_snippet_around_range_returns_a_source_substring(
            content in content(),
            first in 0usize..64,
            second in 0usize..64,
            context_lines in 0usize..3,
        ) {
            let starts = compute_line_starts(&content);
            let start = first.min(second);
            let end = first.max(second);
            let snippet =
                trimmed_snippet_around_range(&content, &starts, start, end, context_lines);

            prop_assert!(
                content.contains(snippet.as_str()),
                "snippet {snippet:?} for {start}..{end} is not a slice of {content:?}"
            );
        }

        /// The location renderer accepts any 1-based line, including 0 and
        /// lines past end of file, and always reports the recovery hint.
        #[test]
        fn render_location_diagnostic_accepts_any_requested_location(
            content in content(),
            line in 0usize..24,
            column in prop::option::of(0usize..24),
        ) {
            let rendered = render_location_diagnostic(
                &content,
                "src/demo.rs",
                line,
                column,
                "no target at location",
                "move the target to a declaration token",
            );
            prop_assert!(
                rendered.ends_with("Recovery: move the target to a declaration token"),
                "diagnostic for line {line} column {column:?} of {content:?}: {rendered}"
            );
            prop_assert!(
                rendered.contains(&format!("{line}")),
                "diagnostic omitted the requested line {line}: {rendered}"
            );
        }
    }
}
