use super::languages::{LanguageSupport, language_support};
use super::{Language, parser_language_for_path};
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::time::{Duration, Instant};
use tree_sitter::{Decode, ParseOptions, Parser, Query, QueryCursor, StreamingIterator};

const MALFORMED_SOURCE_PARSE_BUDGET: Duration = Duration::from_secs(2);

/// How analyzer source text relates to the bytes supplied by its project backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceIngestionKind {
    /// The source was already valid UTF-8 and was preserved byte-for-byte.
    Exact,
    /// The source did not contain NUL but invalid legacy-encoding bytes were
    /// replaced, preserving the historical revision-scoped behavior.
    Lossy,
    /// Binary-bearing string/comment contents were projected to whitespace.
    Projected,
}

/// Text admitted to the analyzer by the shared byte-ingestion policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedSource {
    text: String,
    kind: SourceIngestionKind,
}

impl IngestedSource {
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn into_string(self) -> String {
        self.text
    }

    pub const fn kind(&self) -> SourceIngestionKind {
        self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIngestionError(String);

impl fmt::Display for SourceIngestionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SourceIngestionError {}

#[derive(Debug, Clone)]
struct OpaqueCapture {
    range: Range<usize>,
    erase_entire_range: bool,
}

/// Convert raw source bytes into analyzer text.
///
/// Ordinary UTF-8 and legacy non-NUL text retain the behavior that preceded
/// this admission layer. A NUL-bearing file is admitted only when the
/// language grammar can parse it and every malformed byte belongs to a
/// syntax-highlight capture classified as a string or comment. Tainted
/// string-content/comment ranges are then replaced with same-length
/// whitespace (newlines are retained), so all tree-sitter byte/line offsets
/// continue to address the original blob.
pub fn ingest_source_bytes(
    path: &Path,
    bytes: &[u8],
) -> Result<IngestedSource, SourceIngestionError> {
    if !bytes.contains(&0) {
        return match std::str::from_utf8(bytes) {
            Ok(text) => Ok(IngestedSource {
                text: text.to_owned(),
                kind: SourceIngestionKind::Exact,
            }),
            Err(_) => Ok(IngestedSource {
                text: String::from_utf8_lossy(bytes).into_owned(),
                kind: SourceIngestionKind::Lossy,
            }),
        };
    }

    if let Some(limit) = super::common::max_line_length_limit()
        && bytes
            .split(|byte| *byte == b'\n')
            .any(|line| line.len() > limit)
    {
        return Err(SourceIngestionError(format!(
            "source has a line longer than the configured {limit}-byte parser limit"
        )));
    }

    let language = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None);
    let parser_language = parser_language_for_path(language, path).ok_or_else(|| {
        SourceIngestionError(format!(
            "no analyzer grammar is registered for `{}`",
            path.display()
        ))
    })?;
    let highlights = language_support(language)
        .and_then(LanguageSupport::highlight_query)
        .ok_or_else(|| {
            SourceIngestionError(format!(
                "no syntax-highlight query is registered for `{}`",
                path.display()
            ))
        })?;

    let malformed = malformed_byte_positions(bytes);
    let mut parser = Parser::new();
    parser
        .set_language(&parser_language)
        .map_err(|error| SourceIngestionError(format!("failed to load source grammar: {error}")))?;
    let deadline = Instant::now() + MALFORMED_SOURCE_PARSE_BUDGET;
    let mut cancelled = |_: &tree_sitter::ParseState| Instant::now() >= deadline;
    let mut reader = |offset: usize, _| &bytes[offset..];
    let tree = parser
        .parse_custom_encoding::<MalformedUtf8Decoder, _, _>(
            &mut reader,
            None,
            Some(ParseOptions::new().progress_callback(&mut cancelled)),
        )
        .ok_or_else(|| {
            SourceIngestionError(
                "language parser rejected malformed source or exceeded its time budget".to_string(),
            )
        })?;

    let query = Query::new(&parser_language, highlights).map_err(|error| {
        SourceIngestionError(format!("failed to load source highlight query: {error}"))
    })?;
    let captures = opaque_captures(&query, tree.root_node(), bytes);
    let selected = select_tainted_captures(&malformed, &captures).ok_or_else(|| {
        SourceIngestionError(
            "malformed bytes occur outside grammar-recognized strings or comments".to_string(),
        )
    })?;

    let mut projected = bytes.to_vec();
    for capture_index in selected {
        let capture = &captures[capture_index];
        if capture.erase_entire_range {
            erase_preserving_newlines(&mut projected[capture.range.clone()]);
        }
    }
    // Captures such as an atomic quoted literal include their delimiters, so
    // erasing the entire node would invalidate the surrounding expression.
    // In that fallback shape, replace only the malformed bytes. Grammars that
    // expose string_content/heredoc-body nodes take the full-content path above.
    for position in malformed {
        projected[position] = b' ';
    }

    let text = String::from_utf8(projected).map_err(|_| {
        SourceIngestionError("source projection did not produce valid UTF-8".to_string())
    })?;
    if super::common::is_unparseable_source(&text) {
        return Err(SourceIngestionError(
            "source projection remains unsafe for the analyzer".to_string(),
        ));
    }
    Ok(IngestedSource {
        text,
        kind: SourceIngestionKind::Projected,
    })
}

fn malformed_byte_positions(bytes: &[u8]) -> Vec<usize> {
    let mut malformed = BTreeSet::new();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            malformed.insert(index);
        }
    }

    let mut offset = 0;
    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(_) => break,
            Err(error) => {
                offset += error.valid_up_to();
                let invalid_len = error.error_len().unwrap_or(bytes.len() - offset).max(1);
                for position in offset..offset.saturating_add(invalid_len).min(bytes.len()) {
                    malformed.insert(position);
                }
                offset = offset.saturating_add(invalid_len);
            }
        }
    }
    malformed.into_iter().collect()
}

fn opaque_captures(query: &Query, root: tree_sitter::Node<'_>, bytes: &[u8]) -> Vec<OpaqueCapture> {
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut query_captures = cursor.captures(query, root, bytes);
    let mut captures = Vec::new();
    while let Some((query_match, capture_index)) = query_captures.next() {
        let capture = query_match.captures[*capture_index];
        let name = capture_names[capture.index as usize];
        let is_comment = name == "comment" || name.starts_with("comment.");
        let is_string = name == "string" || name.starts_with("string.");
        if !is_comment && !is_string {
            continue;
        }
        let kind = capture.node.kind();
        captures.push(OpaqueCapture {
            range: capture.node.byte_range(),
            erase_entire_range: is_comment || kind.contains("content") || kind.ends_with("_body"),
        });
    }
    captures
}

fn select_tainted_captures(
    malformed: &[usize],
    captures: &[OpaqueCapture],
) -> Option<BTreeSet<usize>> {
    let mut selected = BTreeSet::new();
    for position in malformed {
        let (index, _) = captures
            .iter()
            .enumerate()
            .filter(|(_, capture)| capture.range.contains(position))
            .min_by_key(|(_, capture)| capture.range.len())?;
        selected.insert(index);
    }
    Some(selected)
}

fn erase_preserving_newlines(bytes: &mut [u8]) {
    for byte in bytes {
        if !matches!(*byte, b'\r' | b'\n') {
            *byte = b' ';
        }
    }
}

/// UTF-8 decoder that gives malformed bytes a one-byte replacement code point.
/// Tree-sitter offsets therefore continue to address the exact input bytes.
struct MalformedUtf8Decoder;

impl Decode for MalformedUtf8Decoder {
    fn decode(bytes: &[u8]) -> (i32, u32) {
        let Some(&first) = bytes.first() else {
            return (0, 0);
        };
        if first == 0 {
            return ('\u{FFFD}' as i32, 1);
        }
        let width = match first {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return ('\u{FFFD}' as i32, 1),
        };
        if bytes.len() < width {
            return ('\u{FFFD}' as i32, 1);
        }
        match std::str::from_utf8(&bytes[..width])
            .ok()
            .and_then(|text| text.chars().next())
        {
            Some(character) => (character as i32, width as u32),
            None => ('\u{FFFD}' as i32, 1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_and_legacy_text_keep_existing_behavior() {
        let exact = ingest_source_bytes(Path::new("Demo.java"), b"class Demo {}\n").unwrap();
        assert_eq!(exact.kind(), SourceIngestionKind::Exact);
        assert_eq!(exact.as_str(), "class Demo {}\n");

        let legacy =
            ingest_source_bytes(Path::new("Demo.java"), b"// caf\xe9\nclass Demo {}\n").unwrap();
        assert_eq!(legacy.kind(), SourceIngestionKind::Lossy);
        assert!(legacy.as_str().contains('\u{FFFD}'));
    }

    #[test]
    fn packed_php_projects_opaque_payload_and_preserves_offsets() {
        let mut source =
            b"<?php\nfunction visible_wrapper() { return 1; }\neval(gzuncompress('".to_vec();
        source.extend_from_slice(b"packed\x00\xff\x80payload");
        source.extend_from_slice(b"'));//\x00\n");

        let ingested = ingest_source_bytes(Path::new("packed.php"), &source).unwrap();
        assert_eq!(ingested.kind(), SourceIngestionKind::Projected);
        assert_eq!(ingested.as_str().len(), source.len());
        assert_eq!(
            ingested
                .as_str()
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            source.iter().filter(|byte| **byte == b'\n').count()
        );
        assert!(ingested.as_str().contains("visible_wrapper"));
        assert!(ingested.as_str().contains("eval(gzuncompress('"));
        assert!(!ingested.as_str().contains("packed"));
        assert!(!ingested.as_str().contains('\0'));
    }

    #[test]
    fn nul_outside_an_opaque_syntax_node_is_rejected() {
        let source = b"<?php\nfunction bro\x00ken() { return 1; }\n";
        let error = ingest_source_bytes(Path::new("broken.php"), source).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside grammar-recognized strings or comments"),
            "{error}"
        );
    }

    #[test]
    fn pathological_single_line_binary_source_remains_rejected() {
        let mut source = b"<?php eval('".to_vec();
        source.extend(std::iter::repeat_n(
            b'x',
            super::super::common::DEFAULT_MAX_LINE_LENGTH + 1,
        ));
        source.extend_from_slice(b"\x00');\n");
        let error = ingest_source_bytes(Path::new("packed.php"), &source).unwrap_err();
        assert!(error.to_string().contains("line longer"), "{error}");
    }
}
