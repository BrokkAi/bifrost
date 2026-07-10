use std::fmt;

use lsp_types::{Position, TextDocumentContentChangeEvent};

use crate::text_utils::compute_line_starts;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct TextSyncError {
    change_index: usize,
    kind: TextSyncErrorKind,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum TextSyncErrorKind {
    LineOutOfRange {
        endpoint: &'static str,
        position: Position,
        line_count: usize,
    },
    InvalidUtf16Boundary {
        endpoint: &'static str,
        position: Position,
    },
    ReversedRange {
        start: Position,
        end: Position,
    },
}

impl fmt::Display for TextSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "content change {}: ", self.change_index)?;
        match &self.kind {
            TextSyncErrorKind::LineOutOfRange {
                endpoint,
                position,
                line_count,
            } => write!(
                f,
                "{endpoint} position {}:{} refers to a missing line (document has {line_count} lines)",
                position.line, position.character
            ),
            TextSyncErrorKind::InvalidUtf16Boundary { endpoint, position } => write!(
                f,
                "{endpoint} position {}:{} falls inside a UTF-16 surrogate pair",
                position.line, position.character
            ),
            TextSyncErrorKind::ReversedRange { start, end } => write!(
                f,
                "range start {}:{} is after end {}:{}",
                start.line, start.character, end.line, end.character
            ),
        }
    }
}

/// Apply one `didChange` notification's content changes to `current`.
///
/// Each change is interpreted against the text produced by the preceding
/// change. The function owns its working copy and returns only after every
/// change validates, so callers can commit the result transactionally.
pub(super) fn apply_content_changes(
    current: &str,
    changes: &[TextDocumentContentChangeEvent],
) -> Result<String, TextSyncError> {
    let mut updated = current.to_owned();

    for (change_index, change) in changes.iter().enumerate() {
        let Some(range) = &change.range else {
            updated.clone_from(&change.text);
            continue;
        };

        let line_starts = compute_line_starts(&updated);
        let start =
            position_to_edit_offset(&updated, &line_starts, &range.start, change_index, "start")?;
        let end = position_to_edit_offset(&updated, &line_starts, &range.end, change_index, "end")?;
        if start > end {
            return Err(TextSyncError {
                change_index,
                kind: TextSyncErrorKind::ReversedRange {
                    start: range.start,
                    end: range.end,
                },
            });
        }
        updated.replace_range(start..end, &change.text);
    }

    Ok(updated)
}

fn position_to_edit_offset(
    content: &str,
    line_starts: &[usize],
    position: &Position,
    change_index: usize,
    endpoint: &'static str,
) -> Result<usize, TextSyncError> {
    let line = position.line as usize;
    let Some(&line_start) = line_starts.get(line) else {
        return Err(TextSyncError {
            change_index,
            kind: TextSyncErrorKind::LineOutOfRange {
                endpoint,
                position: *position,
                line_count: line_starts.len(),
            },
        });
    };
    let next_line_start = line_starts.get(line + 1).copied().unwrap_or(content.len());
    let line_with_ending = &content[line_start..next_line_start];
    let visible_line = line_with_ending
        .strip_suffix("\r\n")
        .or_else(|| line_with_ending.strip_suffix('\n'))
        .or_else(|| line_with_ending.strip_suffix('\r'))
        .unwrap_or(line_with_ending);

    let target = position.character;
    let mut utf16_offset = 0u32;
    let mut byte_offset = 0usize;
    if target == 0 {
        return Ok(line_start);
    }

    for ch in visible_line.chars() {
        let next_utf16_offset = utf16_offset.saturating_add(ch.len_utf16() as u32);
        if target < next_utf16_offset {
            return Err(TextSyncError {
                change_index,
                kind: TextSyncErrorKind::InvalidUtf16Boundary {
                    endpoint,
                    position: *position,
                },
            });
        }
        byte_offset += ch.len_utf8();
        utf16_offset = next_utf16_offset;
        if target == utf16_offset {
            return Ok(line_start + byte_offset);
        }
    }

    // LSP specifies that character offsets beyond the line length clamp back
    // to the visible line end. Newline bytes are excluded from that endpoint.
    Ok(line_start + visible_line.len())
}

#[cfg(test)]
mod tests {
    use lsp_types::{Position, Range, TextDocumentContentChangeEvent};

    use super::{TextSyncErrorKind, apply_content_changes};

    fn position(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    fn ranged(start: Position, end: Position, text: &str) -> TextDocumentContentChangeEvent {
        TextDocumentContentChangeEvent {
            range: Some(Range { start, end }),
            range_length: None,
            text: text.to_owned(),
        }
    }

    fn whole(text: &str) -> TextDocumentContentChangeEvent {
        TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: text.to_owned(),
        }
    }

    #[test]
    fn applies_ascii_insert_replace_and_delete_in_order() {
        let changes = vec![
            ranged(position(0, 1), position(0, 1), "X"),
            ranged(position(0, 2), position(0, 4), "Y"),
            ranged(position(0, 1), position(0, 2), ""),
        ];

        assert_eq!(apply_content_changes("abc", &changes).unwrap(), "aY");
    }

    #[test]
    fn counts_bmp_and_supplementary_characters_as_utf16() {
        let changes = [ranged(position(0, 2), position(0, 4), "X")];

        assert_eq!(apply_content_changes("aé😀z", &changes).unwrap(), "aéXz");
    }

    #[test]
    fn rejects_positions_inside_surrogate_pairs() {
        let current = "😀".to_owned();
        let changes = [ranged(position(0, 1), position(0, 1), "X")];

        let error = apply_content_changes(&current, &changes).unwrap_err();
        assert!(matches!(
            error.kind,
            TextSyncErrorKind::InvalidUtf16Boundary { .. }
        ));
        assert_eq!(
            current, "😀",
            "the caller-owned source must remain unchanged"
        );
    }

    #[test]
    fn ranges_can_replace_each_supported_line_ending() {
        for line_ending in ["\n", "\r\n", "\r"] {
            let current = format!("ab{line_ending}cd");
            let changes = [ranged(position(0, 2), position(1, 0), "|")];
            assert_eq!(
                apply_content_changes(&current, &changes).unwrap(),
                "ab|cd",
                "line ending {line_ending:?}"
            );
        }
    }

    #[test]
    fn applies_mixed_whole_document_and_ranged_changes_in_order() {
        let changes = vec![
            whole("hello"),
            ranged(position(0, 0), position(0, 5), "goodbye"),
            ranged(position(0, 7), position(0, 7), "!"),
        ];

        assert_eq!(
            apply_content_changes("discarded", &changes).unwrap(),
            "goodbye!"
        );
    }

    #[test]
    fn clamps_character_overflow_to_visible_line_end() {
        let changes = [ranged(position(0, 99), position(0, 99), "!")];

        assert_eq!(
            apply_content_changes("abc\ndef", &changes).unwrap(),
            "abc!\ndef"
        );
    }

    #[test]
    fn rejects_nonexistent_lines() {
        let changes = [ranged(position(3, 0), position(3, 0), "X")];

        let error = apply_content_changes("one line", &changes).unwrap_err();
        assert!(matches!(
            error.kind,
            TextSyncErrorKind::LineOutOfRange { .. }
        ));
    }

    #[test]
    fn rejects_entire_batch_when_a_later_change_is_invalid() {
        let current = "abc".to_owned();
        let changes = [
            ranged(position(0, 1), position(0, 1), "X"),
            ranged(position(9, 0), position(9, 0), "invalid"),
        ];

        assert!(apply_content_changes(&current, &changes).is_err());
        assert_eq!(
            current, "abc",
            "a later failure must not expose earlier intermediate edits"
        );
    }

    #[test]
    fn rejects_reversed_ranges_after_character_clamping() {
        let changes = [ranged(position(0, 99), position(0, 1), "X")];

        let error = apply_content_changes("abc", &changes).unwrap_err();
        assert!(matches!(
            error.kind,
            TextSyncErrorKind::ReversedRange { .. }
        ));
    }

    #[test]
    fn ignores_deprecated_range_length() {
        let mut change = ranged(position(0, 1), position(0, 2), "X");
        change.range_length = Some(999);

        assert_eq!(apply_content_changes("abc", &[change]).unwrap(), "aXc");
    }
}
