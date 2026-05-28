use crate::analyzer::ImportInfo;
use tree_sitter::Node;

pub(super) fn balanced_parenthesized_prefix(source: &str) -> Option<&str> {
    let mut chars = source.char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let mut depth = 1usize;
    for (idx, ch) in chars {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&source[1..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (idx, ch) in value.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(value[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts.into_iter().filter(|part| !part.is_empty())
}

pub(super) fn parenthesized_arity(source: &str) -> Option<usize> {
    let inner = balanced_parenthesized_prefix(source)?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(split_top_level_commas(inner).count())
}

pub(crate) fn scala_import_path(info: &ImportInfo) -> Option<String> {
    let trimmed = info
        .raw_snippet
        .trim()
        .strip_prefix("import ")
        .unwrap_or(info.raw_snippet.trim())
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    if info.is_wildcard {
        return Some(
            trimmed
                .trim_end_matches(".*")
                .trim_end_matches("._")
                .to_string(),
        );
    }
    Some(
        trimmed
            .split_once(" as ")
            .map(|(path, _)| path)
            .or_else(|| trimmed.split_once(" => ").map(|(path, _)| path))
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

pub(crate) fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "operator_identifier"
    )
}

pub(crate) fn is_type_like_reference(node: Node<'_>, source: &str) -> bool {
    node.kind() == "type_identifier"
        || is_constructor_like_reference(node, source)
        || parent_kind(node).is_some_and(|kind| {
            matches!(
                kind,
                "type" | "generic_type" | "parameterized_type" | "extends_clause"
            )
        })
}

pub(crate) fn is_constructor_like_reference(node: Node<'_>, source: &str) -> bool {
    let prefix = source[..node.start_byte()].trim_end();
    prefix.ends_with("new")
        || parent_kind(node).is_some_and(|kind| matches!(kind, "call_expression" | "type"))
}

pub(crate) fn parent_kind(node: Node<'_>) -> Option<&str> {
    node.parent().map(|parent| parent.kind())
}

pub(crate) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(crate) fn dot_qualifier_before(node: Node<'_>, source: &str) -> Option<String> {
    let before = &source[..node.start_byte()];
    let before = before.trim_end();
    let without_dot = before.strip_suffix('.')?;
    let qualifier: String = without_dot
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!qualifier.is_empty()).then_some(qualifier.trim_end_matches('$').to_string())
}

pub(crate) fn dotted_qualifier_before(node: Node<'_>, source: &str) -> Option<String> {
    let before = source[..node.start_byte()].trim_end();
    let without_dot = before.strip_suffix('.')?;
    let qualifier: String = without_dot
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '.'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!qualifier.is_empty()).then_some(qualifier.trim_end_matches('$').to_string())
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
