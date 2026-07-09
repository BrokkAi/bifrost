use crate::analyzer::common::language_for_file;
use crate::analyzer::{Language, ProjectFile, Range};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub(crate) struct SourceLocationRequest {
    pub(crate) file: ProjectFile,
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) start_byte: Option<usize>,
    pub(crate) end_byte: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedReferenceSite {
    pub(crate) path: String,
    pub(crate) text: String,
    pub(crate) range: Range,
    pub(crate) focus_start_byte: usize,
    pub(crate) focus_end_byte: usize,
}

pub(crate) fn resolve_reference_site(
    request: &SourceLocationRequest,
    source: &str,
) -> Result<ResolvedReferenceSite, String> {
    let line_starts = compute_line_starts(source);
    let allow_at_ident = language_for_file(&request.file) == Language::Ruby;
    let (selection_start, selection_end) = match (
        request.start_byte,
        request.end_byte,
        request.line,
        request.column,
    ) {
        (Some(start), Some(end), _, _) => {
            if start >= end || end > source.len() {
                return Err(format!(
                    "invalid byte range [{start}, {end}) for {} byte file",
                    source.len()
                ));
            }
            if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
                return Err(format!(
                    "byte range [{start}, {end}) does not align to UTF-8 character boundaries"
                ));
            }
            if let Some(token) = token_bounds_at(source, start, allow_at_ident) {
                if end > token.1 {
                    return Err(
                        "byte range must identify a single reference token; use start_byte inside the token for qualified expressions"
                            .to_string(),
                    );
                }
                token
            } else {
                (start, end)
            }
        }
        (Some(start), None, _, _) => {
            if start >= source.len() {
                return Err(format!(
                    "start_byte {start} is outside {} byte file",
                    source.len()
                ));
            }
            if !source.is_char_boundary(start) {
                return Err(format!(
                    "start_byte {start} does not align to a UTF-8 character boundary"
                ));
            }
            token_bounds_at(source, start, allow_at_ident)
                .ok_or_else(|| format!("no reference token at byte {start}"))?
        }
        (_, _, Some(line), column) => {
            if line == 0 || line > line_starts.len() {
                return Err(format!(
                    "line {line} is outside 1..={} for this file",
                    line_starts.len()
                ));
            }
            let line_start = line_starts[line - 1];
            let line_end = line_starts.get(line).copied().unwrap_or(source.len());
            let column = column.unwrap_or(1);
            if column == 0 {
                return Err("column must be 1-based".to_string());
            }
            let point =
                byte_offset_for_character_column(source, line_start, line_end, line, column)?;
            token_bounds_at(
                source,
                point.min(source.len().saturating_sub(1)),
                allow_at_ident,
            )
            .ok_or_else(|| format!("no reference token at line {line}, column {column}"))?
        }
        _ => return Err("provide either start_byte or line/column".to_string()),
    };

    let (start, end) =
        expand_reference_expression(source, selection_start, selection_end, allow_at_ident);
    if start >= end {
        return Err("reference selection is empty".to_string());
    }
    if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return Err("reference selection does not align to UTF-8 character boundaries".to_string());
    }
    let text = source[start..end].trim().to_string();
    if text.is_empty() {
        return Err("reference selection is blank".to_string());
    }
    let start_line = find_line_index_for_offset(&line_starts, start) + 1;
    let end_line = find_line_index_for_offset(&line_starts, end.saturating_sub(1)) + 1;
    Ok(ResolvedReferenceSite {
        path: rel_path_string(&request.file),
        text,
        range: Range {
            start_byte: start,
            end_byte: end,
            start_line,
            end_line,
        },
        focus_start_byte: selection_start,
        focus_end_byte: selection_end,
    })
}

pub(crate) fn byte_offset_for_character_column(
    source: &str,
    line_start: usize,
    line_end: usize,
    line_number: usize,
    column: usize,
) -> Result<usize, String> {
    let line = source
        .get(line_start..line_end)
        .ok_or_else(|| format!("line {line_number} is outside valid UTF-8 boundaries"))?;
    let character_offset = column - 1;
    if character_offset == 0 {
        return Ok(line_start);
    }
    if let Some((byte_offset, _)) = line.char_indices().nth(character_offset) {
        return Ok(line_start + byte_offset);
    }
    if character_offset == line.chars().count() {
        return Ok(line_end);
    }
    Err(format!("column {column} is outside line {line_number}"))
}

fn token_bounds_at(source: &str, byte: usize, allow_at_ident: bool) -> Option<(usize, usize)> {
    if source.is_empty() {
        return None;
    }
    let bytes = source.as_bytes();
    let mut idx = byte.min(bytes.len().saturating_sub(1));
    if !is_ident_byte(bytes[idx], allow_at_ident)
        && idx > 0
        && is_ident_byte(bytes[idx - 1], allow_at_ident)
    {
        idx -= 1;
    }
    if !is_ident_byte(bytes[idx], allow_at_ident) {
        return None;
    }
    let mut start = idx;
    while start > 0 && is_ident_byte(bytes[start - 1], allow_at_ident) {
        start -= 1;
    }
    let mut end = idx + 1;
    while end < bytes.len() && is_ident_byte(bytes[end], allow_at_ident) {
        end += 1;
    }
    Some((start, end))
}

pub(crate) fn reference_target_match_offsets<'a>(
    source: &'a str,
    target: &'a str,
    language: Language,
) -> impl Iterator<Item = usize> + 'a {
    let allow_at_ident = language == Language::Ruby;
    let target_is_identifier = target
        .bytes()
        .all(|byte| is_ident_byte(byte, allow_at_ident));
    source.match_indices(target).filter_map(move |(offset, _)| {
        if !target_is_identifier
            || token_bounds_at(source, offset, allow_at_ident)
                .is_some_and(|(start, end)| start == offset && end == offset + target.len())
        {
            Some(offset)
        } else {
            None
        }
    })
}

fn expand_reference_expression(
    source: &str,
    start: usize,
    end: usize,
    allow_at_ident: bool,
) -> (usize, usize) {
    let bytes = source.as_bytes();
    let mut left = start;
    let mut right = end;
    loop {
        if left >= 2 && &bytes[left - 2..left] == b"::" {
            left -= 2;
            while left > 0 && is_ident_byte(bytes[left - 1], allow_at_ident) {
                left -= 1;
            }
            continue;
        }
        if left >= 1 && bytes[left - 1] == b'.' {
            left -= 1;
            while left > 0 && is_ident_byte(bytes[left - 1], allow_at_ident) {
                left -= 1;
            }
            continue;
        }
        break;
    }
    loop {
        if right + 2 <= bytes.len() && &bytes[right..right + 2] == b"::" {
            right += 2;
            while right < bytes.len() && is_ident_byte(bytes[right], allow_at_ident) {
                right += 1;
            }
            continue;
        }
        if right < bytes.len() && bytes[right] == b'.' {
            right += 1;
            while right < bytes.len() && is_ident_byte(bytes[right], allow_at_ident) {
                right += 1;
            }
            continue;
        }
        break;
    }
    (left, right)
}

fn is_ident_byte(byte: u8, allow_at_ident: bool) -> bool {
    byte == b'_' || (allow_at_ident && byte == b'@') || byte.is_ascii_alphanumeric()
}

pub(crate) fn smallest_named_node_covering<'tree>(
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing_child = None;
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= start && child.end_byte() >= end {
                containing_child = Some(child);
                break;
            }
        }
        match containing_child {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceLocationRequest, expand_reference_expression, resolve_reference_site};
    use crate::analyzer::ProjectFile;
    use std::env;

    #[test]
    fn expand_reference_expression_keeps_ascii_separator_checks_byte_pure() {
        let source = "回.helper";
        let start = source.find("helper").expect("target");
        let end = start + "helper".len();

        assert_eq!(
            expand_reference_expression(source, start, end, false),
            (start - 1, end)
        );

        let source = "helper:回";
        let start = source.find("helper").expect("target");
        let end = start + "helper".len();

        assert_eq!(
            expand_reference_expression(source, start, end, false),
            (start, end)
        );
    }

    #[test]
    fn exact_byte_range_can_select_symbolic_reference() {
        let source = "box !\n";
        let start = source.find('!').expect("operator");
        let site = resolve_reference_site(
            &SourceLocationRequest {
                file: ProjectFile::new(env::temp_dir(), "App.scala"),
                line: None,
                column: None,
                start_byte: Some(start),
                end_byte: Some(start + 1),
            },
            source,
        )
        .expect("symbolic reference site");

        assert_eq!(site.text, "!");
        assert_eq!(site.focus_start_byte, start);
        assert_eq!(site.focus_end_byte, start + 1);
    }
}
