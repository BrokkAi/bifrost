//! Conversion helpers between bifrost's byte-offset world and LSP's wire
//! format.
//!
//! LSP positions are `(line, character)` where `character` counts UTF-16 code
//! units within the line (the default `positionEncoding`). Bifrost stores byte
//! offsets and 0-based line numbers. These helpers bridge the two without
//! requiring callers to recompute line starts on every call — pass an
//! already-computed `line_starts` slice (see [`crate::text_utils`]).

use std::path::{Path, PathBuf};

use lsp_types::{Position, Range as LspRange, Uri};

use crate::analyzer::Range as ByteRange;
use crate::path_utils::percent_decode;
use crate::text_utils::find_line_index_for_offset;

/// Convert a byte offset within `content` to an LSP [`Position`].
///
/// `line_starts` must be the byte offsets of each line start in `content`
/// (typically [`compute_line_starts`]). Offsets past `content.len()` are
/// clamped to the end of file.
///
/// Two byte offsets have no LSP position of their own, and both resolve to the
/// nearest position at or before them:
///
/// * An offset inside a UTF-8 code point resolves as if it were the start of
///   that code point, matching [`line_column_for_offset`].
/// * The byte between a CR and its LF is inside one line terminator, so it
///   belongs to no column on either line. It resolves to the visible end of
///   the line the CR terminates.
///
/// [`compute_line_starts`]: crate::text_utils::compute_line_starts
/// [`line_column_for_offset`]: crate::text_utils::line_column_for_offset
pub fn byte_offset_to_position(
    content: &str,
    line_starts: &[usize],
    byte_offset: usize,
) -> Position {
    // Snap an offset that landed inside a code point down to the start of that
    // code point, so the prefix below always slices on a char boundary. Line
    // starts are char boundaries, so this never moves the offset onto an
    // earlier line.
    let mut boundary = byte_offset.min(content.len());
    while boundary > 0 && !content.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let line = find_line_index_for_offset(line_starts, boundary);
    let line_start = line_starts.get(line).copied().unwrap_or(0);
    // Walk the prefix from line_start to boundary one char at a time, counting
    // UTF-16 code units. This is O(line length) but avoids extra allocation
    // and handles multi-byte characters and surrogate pairs correctly.
    let prefix = content.get(line_start..boundary).unwrap_or("");
    // Stop *before* a line terminator, mirroring position_to_byte_offset:
    // columns reference the visible line, not the newline bytes. A line holds
    // at most its own trailing terminator, and the only offset that can reach
    // it is the byte between a CR and its LF, so this caps the column at the
    // UTF-16 length of the line excluding that terminator.
    let character: u32 = prefix
        .chars()
        .take_while(|&ch| ch != '\n' && ch != '\r')
        .map(|ch| ch.len_utf16() as u32)
        .sum();
    Position {
        line: line as u32,
        character,
    }
}

/// Convert an LSP [`Position`] to a byte offset within `content`. Out-of-range
/// lines clamp to the end of file; out-of-range characters within a line
/// clamp to the end of that line. Returns `content.len()` for any position at
/// or past EOF.
pub fn position_to_byte_offset(content: &str, line_starts: &[usize], position: &Position) -> usize {
    let line = position.line as usize;
    if line >= line_starts.len() {
        return content.len();
    }
    let line_start = line_starts[line];
    let next_line_start = line_starts.get(line + 1).copied().unwrap_or(content.len());
    let line_slice = content.get(line_start..next_line_start).unwrap_or("");

    let target = position.character;
    let mut consumed_utf16: u32 = 0;
    let mut byte_in_line: usize = 0;
    for ch in line_slice.chars() {
        // Stop *before* a line terminator — LSP positions reference columns
        // within the visible line, not into the newline bytes.
        if ch == '\n' || ch == '\r' {
            break;
        }
        if consumed_utf16 >= target {
            break;
        }
        consumed_utf16 += ch.len_utf16() as u32;
        byte_in_line += ch.len_utf8();
    }
    line_start + byte_in_line
}

/// Convert a bifrost byte range to an LSP range.
pub fn byte_range_to_lsp_range(
    content: &str,
    line_starts: &[usize],
    range: &ByteRange,
) -> LspRange {
    let start = byte_offset_to_position(content, line_starts, range.start_byte);
    let end = byte_offset_to_position(content, line_starts, range.end_byte);
    LspRange { start, end }
}

/// Convert a `file://` URI to a filesystem path. Returns `None` for
/// non-`file` schemes or malformed URIs.
pub fn uri_to_path(uri: &Uri) -> Option<PathBuf> {
    let raw = uri.as_str();
    let stripped = raw.strip_prefix("file://")?;
    // RFC 8089 §E.2: Windows file URIs put a leading `/` before the drive
    // letter (`file:///C:/foo` → path `C:/foo`). Strip that leading slash on
    // Windows ONLY when the next chars are a drive-letter pattern; otherwise
    // we'd corrupt POSIX-shaped URIs like `file:///home/foo` into
    // `home/foo`. (Most LSP clients do not send POSIX paths to Windows
    // servers, but the round-trip property must hold either way.)
    #[cfg(windows)]
    let stripped = if has_drive_letter_prefix(stripped) {
        stripped.strip_prefix('/').unwrap_or(stripped)
    } else {
        stripped
    };
    Some(PathBuf::from(percent_decode(stripped)))
}

#[cfg(windows)]
fn has_drive_letter_prefix(s: &str) -> bool {
    // Matches `/C:` or `/C:/...`.
    let bytes = s.as_bytes();
    bytes.len() >= 3
        && bytes[0] == b'/'
        && (bytes[1] as char).is_ascii_alphabetic()
        && bytes[2] == b':'
}

/// Convert a filesystem path to a `file://` URI string. Caller is responsible
/// for parsing into [`Uri`] if a typed value is needed.
pub fn path_to_uri_string(path: &Path) -> String {
    let mut encoded = String::with_capacity(path.as_os_str().len() + 8);
    encoded.push_str("file://");
    let raw = path.to_string_lossy();
    // Windows `Path::canonicalize` returns extended-length paths like
    // `\\?\C:\Users\foo`. The `\\?\` prefix is a Win32 implementation detail
    // that should never appear in a URI; strip it before further processing.
    #[cfg(windows)]
    let raw: std::borrow::Cow<str> = if let Some(rest) = raw.strip_prefix(r"\\?\") {
        std::borrow::Cow::Owned(rest.to_string())
    } else {
        raw
    };
    // RFC 8089: Windows paths use forward slashes inside the URI. Translate
    // backslashes once up front so the per-char loop below sees a uniform
    // separator regardless of platform conventions.
    #[cfg(windows)]
    let s: std::borrow::Cow<str> = if raw.contains('\\') {
        std::borrow::Cow::Owned(raw.replace('\\', "/"))
    } else {
        raw
    };
    #[cfg(not(windows))]
    let s = raw;
    #[cfg(windows)]
    {
        if !s.starts_with('/') {
            encoded.push('/');
        }
    }
    for ch in s.chars() {
        if should_percent_encode(ch) {
            for byte in ch.to_string().as_bytes() {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        } else {
            encoded.push(ch);
        }
    }
    encoded
}

fn should_percent_encode(ch: char) -> bool {
    // Conservative allow-list: ASCII alphanumerics, the unreserved set, and
    // path separators / drive markers. Everything else, including spaces and
    // non-ASCII, is percent-encoded.
    !matches!(
        ch,
        'a'..='z' | 'A'..='Z' | '0'..='9' |
        '-' | '.' | '_' | '~' | '/' | ':'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Range as ByteRange;
    use crate::text_utils::compute_line_starts;

    fn line_starts(s: &str) -> Vec<usize> {
        compute_line_starts(s)
    }

    #[test]
    fn byte_offset_to_position_handles_ascii_lines() {
        let content = "abc\ndef\nghi";
        let starts = line_starts(content);
        assert_eq!(
            byte_offset_to_position(content, &starts, 0),
            Position {
                line: 0,
                character: 0
            }
        );
        assert_eq!(
            byte_offset_to_position(content, &starts, 2),
            Position {
                line: 0,
                character: 2
            }
        );
        assert_eq!(
            byte_offset_to_position(content, &starts, 4),
            Position {
                line: 1,
                character: 0
            }
        );
        assert_eq!(
            byte_offset_to_position(content, &starts, 6),
            Position {
                line: 1,
                character: 2
            }
        );
    }

    #[test]
    fn byte_offset_to_position_counts_utf16_for_supplementary_chars() {
        // U+1F600 GRINNING FACE = 4 UTF-8 bytes, 2 UTF-16 code units (surrogate pair).
        let content = "a😀b";
        let starts = line_starts(content);
        // Before the emoji.
        assert_eq!(
            byte_offset_to_position(content, &starts, 1),
            Position {
                line: 0,
                character: 1
            }
        );
        // After the emoji (4 bytes for emoji + 1 for 'a' = byte 5).
        assert_eq!(
            byte_offset_to_position(content, &starts, 5),
            Position {
                line: 0,
                character: 3
            }
        );
    }

    #[test]
    fn byte_offset_to_position_clamps_past_eof() {
        let content = "abc";
        let starts = line_starts(content);
        let pos = byte_offset_to_position(content, &starts, 99);
        assert_eq!(
            pos,
            Position {
                line: 0,
                character: 3
            }
        );
    }

    #[test]
    fn byte_offset_to_position_snaps_inside_a_code_point() {
        // Offset 1 is inside the two-byte U+00E9, so it names the same
        // position as offset 0.
        let content = "\u{e9}";
        let starts = line_starts(content);
        assert_eq!(
            byte_offset_to_position(content, &starts, 1),
            Position {
                line: 0,
                character: 0
            }
        );

        // Offset 2 is inside the four-byte U+1F600 on a line holding two
        // visible characters; the rest of the file must not be counted.
        let content = "a\u{1f600}\nxyz\nlong tail here";
        let starts = line_starts(content);
        assert_eq!(
            byte_offset_to_position(content, &starts, 2),
            Position {
                line: 0,
                character: 1
            }
        );
    }

    #[test]
    fn byte_offset_to_position_reports_visible_end_inside_crlf() {
        // Line 0 of "\r\n" has no visible characters: the CR and the LF are
        // one terminator, and offset 1 sits inside it.
        let content = "\r\n";
        let starts = line_starts(content);
        assert_eq!(
            byte_offset_to_position(content, &starts, 1),
            Position {
                line: 0,
                character: 0
            }
        );

        // Same rule after visible text: offset 2 is inside the terminator, so
        // it reports the end of "a".
        let content = "a\r\nb";
        let starts = line_starts(content);
        assert_eq!(
            byte_offset_to_position(content, &starts, 2),
            Position {
                line: 0,
                character: 1
            }
        );
        assert_eq!(
            byte_offset_to_position(content, &starts, 3),
            Position {
                line: 1,
                character: 0
            }
        );
    }

    #[test]
    fn position_to_byte_offset_handles_ascii_lines() {
        let content = "abc\ndef\nghi";
        let starts = line_starts(content);
        let cases = [((0, 0), 0), ((0, 3), 3), ((1, 0), 4), ((2, 2), 10)];
        for ((line, character), expected) in cases {
            let pos = Position { line, character };
            assert_eq!(
                position_to_byte_offset(content, &starts, &pos),
                expected,
                "case {line},{character}"
            );
        }
    }

    #[test]
    fn position_to_byte_offset_clamps_overflow() {
        let content = "abc\ndef";
        let starts = line_starts(content);
        // Past end of line 0: clamps to end of line 0 (before the newline).
        assert_eq!(
            position_to_byte_offset(
                content,
                &starts,
                &Position {
                    line: 0,
                    character: 99
                }
            ),
            3
        );
        // Past last line: clamps to EOF.
        assert_eq!(
            position_to_byte_offset(
                content,
                &starts,
                &Position {
                    line: 99,
                    character: 0
                }
            ),
            content.len()
        );
    }

    #[test]
    fn position_to_byte_offset_walks_utf16_surrogates() {
        let content = "😀😀";
        let starts = line_starts(content);
        // After the first emoji (2 UTF-16 code units → 4 UTF-8 bytes).
        assert_eq!(
            position_to_byte_offset(
                content,
                &starts,
                &Position {
                    line: 0,
                    character: 2
                }
            ),
            4
        );
        // After the second emoji (4 UTF-16 code units → 8 UTF-8 bytes).
        assert_eq!(
            position_to_byte_offset(
                content,
                &starts,
                &Position {
                    line: 0,
                    character: 4
                }
            ),
            8
        );
    }

    #[test]
    fn round_trip_position_byte_offset() {
        let content = "fn main() {\n    let s = \"héllo 😀\";\n}\n";
        let starts = line_starts(content);
        for byte_offset in 0..=content.len() {
            if !content.is_char_boundary(byte_offset) {
                continue;
            }
            let pos = byte_offset_to_position(content, &starts, byte_offset);
            let back = position_to_byte_offset(content, &starts, &pos);
            assert_eq!(back, byte_offset, "round trip failed at byte {byte_offset}");
        }
    }

    #[test]
    fn byte_range_to_lsp_range_works() {
        let content = "abc\ndef\nghi";
        let starts = line_starts(content);
        let range = ByteRange {
            start_byte: 4,
            end_byte: 7,
            start_line: 1,
            end_line: 1,
        };
        let lsp = byte_range_to_lsp_range(content, &starts, &range);
        assert_eq!(
            lsp.start,
            Position {
                line: 1,
                character: 0
            }
        );
        assert_eq!(
            lsp.end,
            Position {
                line: 1,
                character: 3
            }
        );
    }

    #[test]
    fn path_to_uri_round_trips_for_simple_paths() {
        let path = PathBuf::from("/home/user/Some File.rs");
        let uri_str = path_to_uri_string(&path);
        assert_eq!(uri_str, "file:///home/user/Some%20File.rs");
    }

    #[cfg(windows)]
    #[test]
    fn has_drive_letter_prefix_distinguishes_windows_uris() {
        // The Windows leading-`/` strip in uri_to_path must only fire for
        // drive-prefixed URIs. POSIX-shaped URIs sent from a tooling layer
        // that doesn't know about Windows semantics must round-trip
        // unchanged.
        assert!(has_drive_letter_prefix("/C:/Users/test"));
        assert!(has_drive_letter_prefix("/d:"));
        assert!(!has_drive_letter_prefix("/home/user"));
        assert!(!has_drive_letter_prefix("/"));
        assert!(!has_drive_letter_prefix(""));
        // The drive position must be a letter, not a digit or punctuation.
        assert!(!has_drive_letter_prefix("/9:/foo"));
    }

    #[test]
    fn uri_path_round_trip_handles_tricky_chars() {
        // Each path is encoded then decoded back. The original must be
        // recovered byte-for-byte: spaces, percent literals, non-ASCII
        // glyphs, and URI-significant punctuation (`?`, `#`, `[`, `]`).
        let cases = [
            "/home/user/file.rs",
            "/home/user/Some File.rs",
            "/home/user/100%done.txt",
            "/home/user/résumé.pdf",
            "/home/user/face 😀.txt",
            "/home/user/q?x=1.txt",
            "/home/user/anchor#frag.md",
            "/home/user/[brackets].rs",
            "/home/user/dir/with spaces/file.txt",
        ];
        for original in cases {
            let path = PathBuf::from(original);
            let uri_str = path_to_uri_string(&path);
            let parsed: Uri = uri_str
                .parse()
                .unwrap_or_else(|err| panic!("uri parse failed for {original}: {err}"));
            let back = uri_to_path(&parsed)
                .unwrap_or_else(|| panic!("uri_to_path returned None for {uri_str}"));
            assert_eq!(
                back,
                PathBuf::from(original),
                "round trip failed for {original} (encoded as {uri_str})"
            );
        }
    }
}

/// Generative properties for the byte-offset <-> UTF-16 position seam.
///
/// Three conventions meet here: bifrost byte offsets, the analyzer's 1-based
/// line table, and LSP's 0-based line with a UTF-16 column. The generators
/// build content out of line-terminator atoms (`\n`, `\r\n`, lone `\r`) and
/// characters that are 1, 2, 3, and 4 UTF-8 bytes wide, which is where the
/// historical CRLF, CR-only, and mid-code-point defects lived.
#[cfg(test)]
mod conversion_properties {
    use super::*;
    use crate::text_utils::{compute_line_starts, line_column_for_offset};
    use proptest::prelude::*;

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

    fn content() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => prop::sample::select(CONTENT_EDGE_CASES.to_vec()).prop_map(|atom| atom.to_string()),
            7 => prop::collection::vec(prop::sample::select(CONTENT_ATOMS.to_vec()), 0..12)
                .prop_map(|atoms| atoms.concat()),
        ]
    }

    /// Adversarial LSP input: mostly small values, plus the saturating end of
    /// the `u32` wire range that a client can legally send.
    fn adversarial_u32() -> impl Strategy<Value = u32> {
        prop_oneof![
            5 => 0u32..6,
            2 => 0u32..=u32::MAX,
            1 => Just(u32::MAX),
            1 => Just(u32::MAX - 1),
            1 => Just(u32::MAX / 2),
        ]
    }

    fn char_boundaries(content: &str) -> Vec<usize> {
        (0..=content.len())
            .filter(|&offset| content.is_char_boundary(offset))
            .collect()
    }

    /// An independent construction of the same mixed-line-ending table: push a
    /// start after every CR, then correct that start when an LF follows,
    /// instead of peeking ahead. There is no shared test helper across the
    /// crate boundary, and deriving the expectation from `compute_line_starts`
    /// would make the UTF-16 column check circular.
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

    fn reference_line_start_for_offset(content: &str, offset: usize) -> usize {
        reference_line_starts(content)
            .into_iter()
            .rev()
            .find(|&start| start <= offset)
            .expect("offset 0 always follows the file start")
    }

    /// LSP cannot address the byte between a CR and its LF: that offset is
    /// inside one line terminator, so it has no column on either line.
    fn is_inside_crlf(content: &str, offset: usize) -> bool {
        let bytes = content.as_bytes();
        offset > 0 && offset < bytes.len() && bytes[offset - 1] == b'\r' && bytes[offset] == b'\n'
    }

    fn previous_char_boundary(content: &str, offset: usize) -> usize {
        (0..=offset.min(content.len()))
            .rev()
            .find(|&candidate| content.is_char_boundary(candidate))
            .expect("offset 0 is always a char boundary")
    }

    /// The offset an LSP position can actually name at or before `offset`:
    /// snapped out of a code point, then out of a CRLF pair. Stepping off the
    /// LF lands on the CR, which is a char boundary and the visible end of its
    /// line, so one step always suffices.
    fn addressable_floor(content: &str, offset: usize) -> usize {
        let boundary = previous_char_boundary(content, offset);
        if is_inside_crlf(content, boundary) {
            boundary - 1
        } else {
            boundary
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// Every char-boundary byte offset resolves to the position of its
        /// addressable floor, and that position converts back to the floor.
        ///
        /// An exact round trip is impossible for the byte between a CR and its
        /// LF: it is inside one line terminator, so no LSP position names it
        /// and no conversion can return it. Such an offset reports the visible
        /// end of its line, which is what the floor is. For every other
        /// char-boundary offset the floor is the offset itself, so this is the
        /// plain round trip.
        #[test]
        fn byte_offsets_round_trip_through_their_addressable_floor(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in char_boundaries(&content) {
                let floor = addressable_floor(&content, offset);
                let position = byte_offset_to_position(&content, &starts, offset);
                prop_assert_eq!(
                    position,
                    byte_offset_to_position(&content, &starts, floor),
                    "offset {} disagrees with its addressable floor {} of {:?}",
                    offset,
                    floor,
                    content
                );
                prop_assert_eq!(
                    position_to_byte_offset(&content, &starts, &position),
                    floor,
                    "round trip through {:?} for {:?}",
                    position,
                    content
                );
            }
        }

        /// The same round trip for every offset an LSP position can name: any
        /// char-boundary offset that is not inside a CRLF pair.
        #[test]
        fn addressable_byte_offsets_round_trip_through_positions(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in char_boundaries(&content) {
                if is_inside_crlf(&content, offset) {
                    continue;
                }
                let position = byte_offset_to_position(&content, &starts, offset);
                prop_assert_eq!(
                    position_to_byte_offset(&content, &starts, &position),
                    offset,
                    "round trip through {:?} for {:?}",
                    position,
                    content
                );
            }
        }

        /// Any position a client can send clamps into the buffer without
        /// panicking, lands on a char boundary, and is already stable: feeding
        /// the clamped offset back through both conversions is the identity.
        #[test]
        fn arbitrary_positions_clamp_into_the_buffer(
            content in content(),
            line in adversarial_u32(),
            character in adversarial_u32(),
        ) {
            let starts = compute_line_starts(&content);
            let position = Position { line, character };
            let offset = position_to_byte_offset(&content, &starts, &position);

            prop_assert!(
                offset <= content.len(),
                "offset {offset} past end of {content:?} for {position:?}"
            );
            prop_assert!(
                content.is_char_boundary(offset),
                "offset {offset} is inside a code point of {content:?} for {position:?}"
            );

            let clamped = byte_offset_to_position(&content, &starts, offset);
            prop_assert_eq!(
                position_to_byte_offset(&content, &starts, &clamped),
                offset,
                "clamping {:?} to {:?} is not stable for {:?}",
                position,
                clamped,
                content
            );
        }

        /// The column counts UTF-16 code units from the start of the offset's
        /// own line, so astral characters count 2. The byte inside a CRLF pair
        /// has no column of its own, so it is measured at the addressable
        /// floor: the visible end of the line the CR terminates.
        #[test]
        fn position_character_counts_utf16_units_on_its_line(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in char_boundaries(&content) {
                let position = byte_offset_to_position(&content, &starts, offset);
                let line_start = reference_line_start_for_offset(&content, offset);
                let prefix = &content[line_start..addressable_floor(&content, offset)];
                prop_assert_eq!(
                    position.character as usize,
                    prefix.encode_utf16().count(),
                    "UTF-16 column at offset {} of {:?}",
                    offset,
                    content
                );
                prop_assert_eq!(
                    position.character,
                    prefix.chars().map(|ch| ch.len_utf16() as u32).sum::<u32>(),
                    "UTF-16 column at offset {} of {:?}",
                    offset,
                    content
                );
            }
        }

        /// The LSP 0-based line and the analyzer's 1-based line describe the
        /// same row of the same file, on every line-ending convention.
        #[test]
        fn lsp_and_analyzer_lines_agree(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in char_boundaries(&content) {
                let position = byte_offset_to_position(&content, &starts, offset);
                let (analyzer_line, _) = line_column_for_offset(&content, &starts, offset);
                prop_assert_eq!(
                    position.line as usize + 1,
                    analyzer_line,
                    "line conventions disagree at offset {} of {:?}",
                    offset,
                    content
                );
                prop_assert_eq!(
                    position.line as usize,
                    reference_line_starts(&content)
                        .iter()
                        .take_while(|&&start| start <= offset)
                        .count()
                        - 1,
                    "line index disagrees with an independent table at offset {} of {:?}",
                    offset,
                    content
                );
            }
        }

        /// An offset inside a UTF-8 code point resolves as if it were the start
        /// of that code point, the way `line_column_for_offset` does.
        #[test]
        fn positions_snap_offsets_inside_a_code_point(content in content()) {
            let starts = compute_line_starts(&content);

            for offset in 0..=content.len() {
                if content.is_char_boundary(offset) {
                    continue;
                }
                prop_assert_eq!(
                    byte_offset_to_position(&content, &starts, offset),
                    byte_offset_to_position(
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

        /// A byte range converts to its two endpoint positions and never
        /// inverts: an ordered byte range stays ordered in LSP coordinates.
        #[test]
        fn byte_ranges_convert_to_ordered_positions(content in content()) {
            let starts = compute_line_starts(&content);
            let boundaries = char_boundaries(&content);

            for &start_byte in &boundaries {
                for &end_byte in boundaries.iter().filter(|&&end| end >= start_byte) {
                    let range = ByteRange {
                        start_byte,
                        end_byte,
                        start_line: line_column_for_offset(&content, &starts, start_byte).0,
                        end_line: line_column_for_offset(&content, &starts, end_byte).0,
                    };
                    let lsp = byte_range_to_lsp_range(&content, &starts, &range);
                    prop_assert_eq!(
                        lsp.start,
                        byte_offset_to_position(&content, &starts, start_byte),
                        "range start for {}..{} of {:?}",
                        start_byte,
                        end_byte,
                        content
                    );
                    prop_assert_eq!(
                        lsp.end,
                        byte_offset_to_position(&content, &starts, end_byte),
                        "range end for {}..{} of {:?}",
                        start_byte,
                        end_byte,
                        content
                    );
                    prop_assert!(
                        (lsp.start.line, lsp.start.character)
                            <= (lsp.end.line, lsp.end.character),
                        "range {start_byte}..{end_byte} of {content:?} inverted to {lsp:?}"
                    );
                }
            }
        }
    }
}
