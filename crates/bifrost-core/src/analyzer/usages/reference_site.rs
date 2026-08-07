use crate::analyzer::common::language_for_file;
use crate::analyzer::{Language, ProjectFile, Range};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub struct SourceLocationRequest {
    pub file: ProjectFile,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ResolvedReferenceSite {
    pub path: String,
    pub text: String,
    pub range: Range,
    pub focus_start_byte: usize,
    pub focus_end_byte: usize,
}

/// `root` is the parsed root node of `source`, or `None` when the file did not
/// parse. It supplies the member-access chain around the selection, which the
/// byte scan in [`expand_reference_expression`] cannot see across an
/// optional-chaining operator (#1781).
pub fn resolve_reference_site(
    request: &SourceLocationRequest,
    source: &str,
    root: Option<Node<'_>>,
) -> Result<ResolvedReferenceSite, String> {
    let line_starts = compute_line_starts(source);
    resolve_reference_site_with_line_starts(request, source, &line_starts, root)
}

pub fn resolve_reference_site_with_line_starts(
    request: &SourceLocationRequest,
    source: &str,
    line_starts: &[usize],
    root: Option<Node<'_>>,
) -> Result<ResolvedReferenceSite, String> {
    let language = language_for_file(&request.file);
    // A Rust raw identifier (`r#type`) is one token whose `r#` escape prefix
    // is not made of ordinary identifier characters, so the generic
    // ident-byte token scanner below needs to special-case it (#1128) --
    // otherwise a `self.r#type` reference site is seen as the bare one-byte
    // token `r`, and a caller-supplied `[start, end)` spanning the whole
    // `r#type` text is rejected as "not a single reference token".
    let raw_identifier_aware = language == Language::Rust;
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
            if let Some(token) = token_bounds_at(source, start, language, raw_identifier_aware) {
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
            token_bounds_at(source, start, language, raw_identifier_aware)
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
            let point = point.min(source.len().saturating_sub(1));
            token_bounds_at(source, point, language, raw_identifier_aware)
                .or_else(|| single_non_whitespace_character_at(source, point))
                .ok_or_else(|| format!("no reference token at line {line}, column {column}"))?
        }
        _ => return Err("provide either start_byte or line/column".to_string()),
    };

    let (scanned_start, scanned_end) =
        expand_reference_expression(source, selection_start, selection_end, language);
    if scanned_start >= scanned_end {
        return Err("reference selection is empty".to_string());
    }
    if !source.is_char_boundary(scanned_start) || !source.is_char_boundary(scanned_end) {
        return Err("reference selection does not align to UTF-8 character boundaries".to_string());
    }
    // The parsed chain replaces the scan only when it covers what the scan
    // found, so the scan's `::` paths and trailing separators are never
    // narrowed by a member-access node that stops earlier.
    let chain = root
        .and_then(|root| {
            member_access_chain(root, source, selection_start, selection_end, language)
        })
        .filter(|chain| chain.start <= scanned_start && chain.end >= scanned_end);
    let (start, end, text) = match chain {
        Some(chain) => (chain.start, chain.end, chain.text),
        None => (
            scanned_start,
            scanned_end,
            source[scanned_start..scanned_end].trim().to_string(),
        ),
    };
    if text.is_empty() {
        return Err("reference selection is blank".to_string());
    }
    let start_line = find_line_index_for_offset(line_starts, start) + 1;
    let end_line = find_line_index_for_offset(line_starts, end.saturating_sub(1)) + 1;
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

fn single_non_whitespace_character_at(source: &str, byte: usize) -> Option<(usize, usize)> {
    let character = source.get(byte..)?.chars().next()?;
    (!character.is_whitespace()).then_some((byte, byte + character.len_utf8()))
}

pub fn byte_offset_for_character_column(
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

/// Whether the identifier-byte run `[start, end)` in `bytes` is (or borders)
/// a Rust raw identifier's `r#` escape prefix: `r#` sits at the position
/// immediately before `start` (the ordinary case -- the scan already landed
/// on the un-escaped tail, e.g. `type` inside `r#type`), or the run itself is
/// the bare `r` immediately followed by `#` and further ident bytes (the
/// scan landed on the `r` itself). `r#` is escape syntax, not part of the
/// identifier (#1128), but it is not made of ordinary identifier *bytes*
/// either, so the generic ident-byte scan in [`token_bounds_at`] cannot see
/// across it on its own.
fn rust_raw_identifier_bounds(
    bytes: &[u8],
    start: usize,
    end: usize,
    language: Language,
) -> Option<(usize, usize)> {
    if start >= 2
        && bytes[start - 1] == b'#'
        && bytes[start - 2] == b'r'
        && (start == 2 || !is_ident_byte(bytes[start - 3], language))
    {
        return Some((start - 2, end));
    }
    if end - start == 1
        && bytes[start] == b'r'
        && bytes.get(end) == Some(&b'#')
        && bytes
            .get(end + 1)
            .is_some_and(|&byte| is_ident_byte(byte, language))
    {
        let mut extended_end = end + 1;
        while extended_end < bytes.len() && is_ident_byte(bytes[extended_end], language) {
            extended_end += 1;
        }
        return Some((start, extended_end));
    }
    None
}

fn token_bounds_at(
    source: &str,
    byte: usize,
    language: Language,
    raw_identifier_aware: bool,
) -> Option<(usize, usize)> {
    if source.is_empty() {
        return None;
    }
    let bytes = source.as_bytes();
    let mut idx = byte.min(bytes.len().saturating_sub(1));
    if !is_ident_byte(bytes[idx], language) && idx > 0 && is_ident_byte(bytes[idx - 1], language) {
        idx -= 1;
    }
    if !is_ident_byte(bytes[idx], language) {
        return None;
    }
    let mut start = idx;
    while start > 0 && is_ident_byte(bytes[start - 1], language) {
        start -= 1;
    }
    let mut end = idx + 1;
    while end < bytes.len() && is_ident_byte(bytes[end], language) {
        end += 1;
    }
    if raw_identifier_aware
        && let Some(extended) = rust_raw_identifier_bounds(bytes, start, end, language)
    {
        return Some(extended);
    }
    Some((start, end))
}

pub fn reference_target_match_offsets<'a>(
    source: &'a str,
    target: &'a str,
    language: Language,
) -> impl Iterator<Item = usize> + 'a {
    let raw_identifier_aware = language == Language::Rust;
    // A target that is itself a raw identifier (`r#type`) is not made of
    // ordinary identifier bytes (the `#` fails `is_ident_byte`), but it is
    // still exactly one reference token in Rust source, so it must take the
    // same strict token-boundary check below as any other identifier target
    // rather than falling back to unchecked substring matching (#1128).
    let target_is_identifier = target.bytes().all(|byte| is_ident_byte(byte, language))
        || (raw_identifier_aware
            && target.strip_prefix("r#").is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|byte| is_ident_byte(byte, language))
            }));
    source.match_indices(target).filter_map(move |(offset, _)| {
        if !target_is_identifier
            || token_bounds_at(source, offset, language, raw_identifier_aware)
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
    language: Language,
) -> (usize, usize) {
    let bytes = source.as_bytes();
    let mut left = start;
    let mut right = end;
    loop {
        if left >= 2 && &bytes[left - 2..left] == b"::" {
            left -= 2;
            while left > 0 && is_ident_byte(bytes[left - 1], language) {
                left -= 1;
            }
            continue;
        }
        if left >= 1 && bytes[left - 1] == b'.' {
            left -= 1;
            while left > 0 && is_ident_byte(bytes[left - 1], language) {
                left -= 1;
            }
            continue;
        }
        break;
    }
    loop {
        if right + 2 < bytes.len()
            && &bytes[right..right + 2] == b"::"
            && (is_ident_byte(bytes[right + 2], language)
                || matches!(bytes[right + 2], b'{' | b'*'))
        {
            right += 2;
            while right < bytes.len() && is_ident_byte(bytes[right], language) {
                right += 1;
            }
            continue;
        }
        if right < bytes.len() && bytes[right] == b'.' {
            right += 1;
            while right < bytes.len() && is_ident_byte(bytes[right], language) {
                right += 1;
            }
            continue;
        }
        break;
    }
    (left, right)
}

/// One `receiver.member` step of a dotted member-access chain.
struct MemberAccess<'tree> {
    receiver: Node<'tree>,
    member: Node<'tree>,
}

/// The dotted member-access chain that covers `[start, end)`.
struct MemberAccessChain {
    start: usize,
    end: usize,
    text: String,
}

/// The receiver and member of a dot-separated member access, or `None` when
/// `node` is not one in `language`.
///
/// Only a grammar that spells an optional-chaining member access needs an
/// entry here. [`expand_reference_expression`] already spans a plain `a.b.c`
/// chain, and it truncates exactly the chains whose operator carries a `?`,
/// because `?` is not an identifier byte (#1781). A grammar whose member
/// operator is not `.` at all -- PHP's `->`, C++'s `->` -- is deliberately
/// absent: an entry for it would widen every member site of that language
/// rather than repair the optional ones.
fn member_access_parts<'tree>(
    node: Node<'tree>,
    language: Language,
) -> Option<MemberAccess<'tree>> {
    match (language, node.kind()) {
        // `a.b` and `a?.b`; the `?.` is an `optional_chain` child between the
        // `object` and `property` fields.
        (Language::JavaScript | Language::TypeScript, "member_expression") => Some(MemberAccess {
            receiver: node.child_by_field_name("object")?,
            member: node.child_by_field_name("property")?,
        }),
        (Language::CSharp, "member_access_expression") => Some(MemberAccess {
            receiver: node.child_by_field_name("expression")?,
            member: node.child_by_field_name("name")?,
        }),
        // C# spells `a?.b` as a conditional access whose member lives in a
        // separate `member_binding_expression`.
        (Language::CSharp, "conditional_access_expression") => {
            let receiver = node.child_by_field_name("condition")?;
            let mut cursor = node.walk();
            let binding = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "member_binding_expression")?;
            Some(MemberAccess {
                receiver,
                member: binding.child_by_field_name("name")?,
            })
        }
        // Kotlin spells both `a.b` and `a?.b` as a navigation expression whose
        // member lives in a `navigation_suffix`.
        (Language::Kotlin, "navigation_expression") => {
            let mut cursor = node.walk();
            let receiver = node
                .named_children(&mut cursor)
                .find(|child| child.kind() != "navigation_suffix")?;
            let mut cursor = node.walk();
            let suffix = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "navigation_suffix")?;
            let mut cursor = suffix.walk();
            Some(MemberAccess {
                receiver,
                member: suffix.named_children(&mut cursor).next()?,
            })
        }
        _ => None,
    }
}

/// Whether `node` only wraps the member half of a member access, so the ascent
/// in [`member_access_chain`] must pass through it to reach the access itself.
fn is_member_access_wrapper(node: Node<'_>, language: Language) -> bool {
    matches!(
        (language, node.kind()),
        (Language::CSharp, "member_binding_expression") | (Language::Kotlin, "navigation_suffix")
    )
}

/// The text of `node` when it is a single reference name such as `box`, `text`
/// or `this`. A node with named children is a compound expression -- a call, a
/// subscript, a construction -- and a chain that reaches one is not a plain
/// dotted path.
pub fn simple_reference_name<'source>(
    node: Node<'_>,
    source: &'source str,
    language: Language,
) -> Option<&'source str> {
    if node.named_child_count() != 0 {
        return None;
    }
    let text = source.get(node.start_byte()..node.end_byte())?;
    (!text.is_empty() && text.bytes().all(|byte| is_ident_byte(byte, language))).then_some(text)
}

/// The dotted member-access chain around `[start, end)`, read from the tree.
///
/// The chain text is rebuilt from the member names instead of sliced out of the
/// source, so `al.box?.text` reports `al.box.text`: every consumer separates
/// the qualifier from the member by splitting the site text on `.`, and an
/// embedded `?` would hand them the qualifier `box?`.
///
/// `None` means the selection is not part of a plain dotted chain -- either the
/// language has no entry in [`member_access_parts`], or some link of the chain
/// is a call, a subscript or another compound expression that a dotted text
/// cannot name. The caller then keeps the byte-scanned bounds.
fn member_access_chain(
    root: Node<'_>,
    source: &str,
    start: usize,
    end: usize,
    language: Language,
) -> Option<MemberAccessChain> {
    let mut current = smallest_named_node_covering(root, start, end)?;
    while let Some(parent) = current.parent() {
        if is_member_access_wrapper(parent, language) {
            current = parent;
            continue;
        }
        let Some(access) = member_access_parts(parent, language) else {
            break;
        };
        // The selection, not `current`, decides: a wrapper the ascent stepped
        // through spans its own operator (C# `.Text`) and so is wider than the
        // member name it holds.
        let covers_selection =
            |side: Node<'_>| side.start_byte() <= start && end <= side.end_byte();
        if !covers_selection(access.receiver) && !covers_selection(access.member) {
            break;
        }
        current = parent;
    }

    let chain = current;
    let mut names = Vec::new();
    loop {
        match member_access_parts(current, language) {
            Some(access) => {
                names.push(simple_reference_name(access.member, source, language)?);
                current = access.receiver;
            }
            None => {
                names.push(simple_reference_name(current, source, language)?);
                break;
            }
        }
    }
    if names.len() < 2 {
        return None;
    }
    names.reverse();
    Some(MemberAccessChain {
        start: chain.start_byte(),
        end: chain.end_byte(),
        text: names.join("."),
    })
}

fn is_ident_byte(byte: u8, language: Language) -> bool {
    byte == b'_'
        || (language == Language::Ruby && byte == b'@')
        || (matches!(language, Language::JavaScript | Language::TypeScript) && byte == b'$')
        || byte.is_ascii_alphanumeric()
}

pub fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

/// The innermost named node whose span contains `start..end`.
///
/// Tree-sitter named siblings never overlap, so at most one child of any node can contain
/// the span: the containing nodes form a chain from the root, and descending through the
/// single containing child at each level reaches the smallest of them.
pub fn smallest_named_node_covering<'tree>(
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
    use crate::analyzer::{Language, ProjectFile};
    use std::env;

    #[test]
    fn expand_reference_expression_keeps_ascii_separator_checks_byte_pure() {
        let source = "回.helper";
        let start = source.find("helper").expect("target");
        let end = start + "helper".len();

        assert_eq!(
            expand_reference_expression(source, start, end, Language::Java),
            (start - 1, end)
        );

        let source = "helper:回";
        let start = source.find("helper").expect("target");
        let end = start + "helper".len();

        assert_eq!(
            expand_reference_expression(source, start, end, Language::Java),
            (start, end)
        );
    }

    #[test]
    fn javascript_reference_expression_preserves_dollar_identifier_root() {
        let source = "$scope.count";
        let start = source.find("count").expect("property");
        let end = start + "count".len();

        assert_eq!(
            expand_reference_expression(source, start, end, Language::JavaScript),
            (0, source.len())
        );
    }

    #[test]
    fn expand_reference_expression_does_not_absorb_rust_turbofish_separator() {
        let source = "leaf::<Item>()";
        let start = source.find("leaf").expect("free function");
        let end = start + "leaf".len();

        assert_eq!(
            expand_reference_expression(source, start, end, Language::Rust),
            (start, end)
        );

        let source = "Type::make::<Item>()";
        let start = source.find("make").expect("associated function");
        let end = start + "make".len();

        assert_eq!(
            &source[{
                let (start, end) = expand_reference_expression(source, start, end, Language::Rust);
                start..end
            }],
            "Type::make"
        );
    }

    #[test]
    fn expand_reference_expression_retains_grouped_and_glob_path_separators() {
        for source in ["workflow::{job}", "workflow::*"] {
            let start = source.find("workflow").expect("path prefix");
            let end = start + "workflow".len();
            let (expanded_start, expanded_end) =
                expand_reference_expression(source, start, end, Language::Rust);
            assert_eq!(&source[expanded_start..expanded_end], "workflow::");
        }
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
            None,
        )
        .expect("symbolic reference site");

        assert_eq!(site.text, "!");
        assert_eq!(site.focus_start_byte, start);
        assert_eq!(site.focus_end_byte, start + 1);
    }
}
