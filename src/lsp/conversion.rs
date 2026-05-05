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
use crate::text_utils::find_line_index_for_offset;

/// Convert a byte offset within `content` to an LSP [`Position`].
///
/// `line_starts` must be the byte offsets of each line start in `content`
/// (typically [`compute_line_starts`]). Offsets past `content.len()` are
/// clamped to the end of file.
pub fn byte_offset_to_position(
    content: &str,
    line_starts: &[usize],
    byte_offset: usize,
) -> Position {
    let clamped = byte_offset.min(content.len());
    let line = find_line_index_for_offset(line_starts, clamped);
    let line_start = line_starts.get(line).copied().unwrap_or(0);
    // Walk the prefix from line_start to clamped one char at a time, counting
    // UTF-16 code units. This is O(line length) but avoids extra allocation
    // and handles multi-byte characters and surrogate pairs correctly.
    let prefix = content
        .get(line_start..clamped)
        .unwrap_or_else(|| content.get(line_start..content.len()).unwrap_or(""));
    let character: u32 = prefix.chars().map(|ch| ch.len_utf16() as u32).sum();
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

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
    fn percent_decode_handles_unicode_and_spaces() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%E2%9C%93"), "✓");
        assert_eq!(percent_decode("plain/path"), "plain/path");
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
