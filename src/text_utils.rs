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

#[cfg(test)]
mod tests {
    use super::{compute_line_starts, find_line_index_for_offset};

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
}
