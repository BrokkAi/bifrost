//! Structured facts for the Javadoc language embedded in Java comments.
//!
//! Java's declaration grammar treats comments as extras, while Javadoc has a
//! grammar of its own.  This module deliberately parses only a selected
//! `/** ... */` block; it never searches Java source text for tags.  The
//! resulting block and tag facts are small, query-local values that callers
//! join to the Java declaration which owns the comment.

use tree_sitter::{Node, Parser, Tree};

/// The normalized kind of a Javadoc block tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JavadocTagKind {
    Param,
    Throws,
    Return,
    Other,
}

/// One structured Javadoc block tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavadocTagFact {
    pub kind: JavadocTagKind,
    /// The structured name on `@param` or `@throws`/`@exception`.
    pub name: Option<String>,
    /// The terminal component of a structured type/name node. This avoids
    /// making consumers recover type segments from rendered source text.
    pub terminal_name: Option<String>,
    /// Whether the grammar found a description/body for this tag.
    pub body_present: bool,
    /// Whether the body meets the minimum non-trivial text threshold used by
    /// the documentation rules.
    pub acceptable: bool,
    /// The byte span in the selected Javadoc comment, useful to a consumer
    /// that wants to retain tag provenance without reparsing the comment.
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Structured facts for one selected Javadoc block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavadocBlockFacts {
    /// The nested grammar parsed without an error node.
    pub complete: bool,
    /// The block has at least five non-whitespace characters of prose outside
    /// block tags.
    pub acceptable_text: bool,
    pub tags: Vec<JavadocTagFact>,
}

/// Parse a Java `block_comment` selected by the Java structural layer.
pub fn parse_block_comment(comment: Node<'_>, source: &str) -> Option<JavadocBlockFacts> {
    if comment.kind() != "block_comment" {
        return None;
    }
    let text = source.get(comment.byte_range())?;
    text.starts_with("/**").then_some(())?;
    parse_comment_text(text)
}

/// Find the Javadoc block directly attached to a Java declaration.
///
/// Tree-sitter exposes comments as extra siblings.  The source gap check keeps
/// a separated file header from becoming a declaration's documentation while
/// still accepting the ordinary newline between a comment and its declaration.
pub fn preceding_javadoc_comment<'tree>(
    declaration: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut root = declaration;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut nearest = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "block_comment"
            && node.end_byte() <= declaration.start_byte()
            && nearest.is_none_or(|candidate: Node<'_>| candidate.end_byte() < node.end_byte())
        {
            let text = source.get(node.byte_range())?;
            if text.starts_with("/**") {
                let gap = source.get(node.end_byte()..declaration.start_byte())?;
                if gap.bytes().all(|byte| byte.is_ascii_whitespace()) && line_break_count(gap) <= 1
                {
                    nearest = Some(node);
                }
            }
        }
        for index in (0..node.named_child_count()).rev() {
            stack.push(node.named_child(index).expect("named child exists"));
        }
    }
    nearest
}

/// Parse a Javadoc text slice with the released tree-sitter-javadoc grammar.
pub fn parse_comment_text(text: &str) -> Option<JavadocBlockFacts> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javadoc::LANGUAGE.into())
        .ok()?;
    // The released grammar accepts a line terminator after a single-line
    // block. A Java block_comment node excludes that terminator, so provide
    // one to the nested parser without changing the selected source span.
    let input = if text.ends_with('\n') || text.ends_with('\r') {
        text.to_owned()
    } else {
        format!("{text}\n")
    };
    let tree = parser.parse(&input, None)?;
    Some(block_facts(&tree, &input))
}

fn block_facts(tree: &Tree, source: &str) -> JavadocBlockFacts {
    let root = tree.root_node();
    let mut tags = Vec::new();
    let mut stack = vec![root];
    let mut prose_length = 0usize;
    while let Some(node) = stack.pop() {
        match node.kind() {
            "description"
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "document") =>
            {
                prose_length = prose_length.saturating_add(non_whitespace_len(node, source));
            }
            "param_tag" if is_direct_block_tag(node) => tags.push(tag_fact(
                node,
                JavadocTagKind::Param,
                node.child_by_field_name("parameter_name")
                    .or_else(|| node.child_by_field_name("type_parameter_name")),
                node.child_by_field_name("description"),
                source,
            )),
            "throws_tag" if is_direct_block_tag(node) => tags.push(tag_fact(
                node,
                JavadocTagKind::Throws,
                node.child_by_field_name("exception_type"),
                node.child_by_field_name("description"),
                source,
            )),
            "return_tag" if is_direct_block_tag(node) => tags.push(tag_fact(
                node,
                JavadocTagKind::Return,
                None,
                node.child_by_field_name("description"),
                source,
            )),
            kind if is_direct_block_tag(node) && kind.ends_with("_tag") => tags.push(tag_fact(
                node,
                JavadocTagKind::Other,
                None,
                node.child_by_field_name("description"),
                source,
            )),
            _ => {}
        }
        for index in (0..node.named_child_count()).rev() {
            stack.push(node.named_child(index).expect("named child exists"));
        }
    }
    tags.sort_unstable_by_key(|tag| tag.start_byte);
    JavadocBlockFacts {
        complete: root.kind() == "document" && !root.has_error(),
        acceptable_text: prose_length >= 5,
        tags,
    }
}

fn is_direct_block_tag(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "document")
}

fn tag_fact(
    node: Node<'_>,
    kind: JavadocTagKind,
    name_node: Option<Node<'_>>,
    body_node: Option<Node<'_>>,
    source: &str,
) -> JavadocTagFact {
    let body_present = body_node.is_some_and(|body| {
        meaningful_node_text(body, source).is_some_and(|text| !text.trim().is_empty())
    });
    let acceptable = body_node.is_some_and(|body| acceptable_node_text(body, source));
    JavadocTagFact {
        kind,
        name: name_node.and_then(|name| {
            let text = source.get(name.byte_range()).map(str::trim)?;
            Some(if name.kind() == "type_parameter" {
                format!("<{text}>")
            } else {
                text.to_string()
            })
        }),
        terminal_name: name_node.and_then(|name| terminal_name(name, source)),
        body_present,
        acceptable,
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

fn terminal_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut stack = vec![node];
    let mut terminal = None;
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier" {
            terminal = source
                .get(current.byte_range())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
        }
        for index in (0..current.named_child_count()).rev() {
            stack.push(current.named_child(index).expect("named child exists"));
        }
    }
    terminal
}

fn acceptable_node_text(node: Node<'_>, source: &str) -> bool {
    non_whitespace_len(node, source) >= 5
}

fn non_whitespace_len(node: Node<'_>, source: &str) -> usize {
    meaningful_node_text(node, source)
        .map(|text| {
            text.chars()
                .filter(|character| !character.is_whitespace())
                .count()
        })
        .unwrap_or(0)
}

fn meaningful_node_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source
        .get(node.byte_range())
        .map(|text| text.strip_suffix("*/").unwrap_or(text))
}

fn line_break_count(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'\n' || (byte == b'\r' && bytes.get(index + 1) != Some(&b'\n')) {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_publishes_required_tag_facts() {
        // The released nested grammar is the oracle for provenance. Unicode
        // prose makes byte offsets distinguishable from character offsets.
        let source = "/** Explains \u{03bb} values.\n * @param value the input value\n * @param <T> the value type\n * @throws java.io.IOException when reading\n * @exception RuntimeException unchecked\n * @return the result value\n */\n";
        let facts = parse_comment_text(source).expect("Javadoc grammar parses");
        assert!(facts.complete);
        assert!(facts.acceptable_text);
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javadoc::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let mut cursor = tree.root_node().walk();
        let tags = tree
            .root_node()
            .named_children(&mut cursor)
            .filter(|node| matches!(node.kind(), "param_tag" | "throws_tag" | "return_tag"))
            .collect::<Vec<_>>();
        assert_eq!(tags.len(), 5);
        let expected = [
            (JavadocTagKind::Param, Some("value"), Some("value")),
            (JavadocTagKind::Param, Some("<T>"), Some("T")),
            (
                JavadocTagKind::Throws,
                Some("java.io.IOException"),
                Some("IOException"),
            ),
            (
                JavadocTagKind::Throws,
                Some("RuntimeException"),
                Some("RuntimeException"),
            ),
            (JavadocTagKind::Return, None, None),
        ];
        assert_eq!(facts.tags.len(), tags.len());
        for ((fact, node), (kind, name, terminal)) in facts.tags.iter().zip(tags).zip(expected) {
            assert_eq!(fact.kind, kind);
            assert_eq!(fact.name.as_deref(), name);
            assert_eq!(fact.terminal_name.as_deref(), terminal);
            assert_eq!(fact.start_byte..fact.end_byte, node.byte_range());
            let slice = &source[fact.start_byte..fact.end_byte];
            assert!(slice.starts_with('@'), "{slice:?}");
            let body = node.child_by_field_name("description").unwrap();
            assert!(fact.end_byte >= body.end_byte());
            assert!(fact.body_present);
            assert!(fact.acceptable);
        }
    }

    #[test]
    fn short_prose_and_missing_tag_bodies_are_not_acceptable() {
        let facts = parse_comment_text("/** abc */").expect("Javadoc grammar parses");
        assert!(facts.complete);
        assert!(!facts.acceptable_text);
        let facts =
            parse_comment_text("/** Text.\n * @return\n */").expect("Javadoc grammar parses");
        let return_tag = facts
            .tags
            .iter()
            .find(|tag| tag.kind == JavadocTagKind::Return)
            .expect("return tag");
        assert!(!return_tag.body_present);
        assert!(!return_tag.acceptable);
    }
}
