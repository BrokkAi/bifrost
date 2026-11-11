//! XML documentation selected from C# comment nodes adjacent to a declaration.

use crate::syntax::csharp_has_modifier;
use quick_xml::Reader;
use quick_xml::events::Event;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagKind {
    Param,
    TypeParam,
    InheritDoc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub kind: TagKind,
    pub name: Option<String>,
    pub has_body: bool,
    /// Exact byte span in the original C# source, including intervening comment prefixes.
    pub range: std::ops::Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Documentation {
    Absent,
    Parsed(Vec<Tag>),
    Undecidable(&'static str),
}

/// Select only adjacent comment nodes. A blank line or another declaration breaks
/// attachment. Attribute sections are children of the declaration and may appear
/// between its leading documentation and its name. Each partial declaration is
/// evaluated locally; a documented partial is undecidable because another part
/// may supply tags.
pub fn for_declaration(declaration: Node<'_>, source: &str) -> Documentation {
    let Some(last) = declaration.prev_named_sibling() else {
        return Documentation::Absent;
    };
    if last.kind() != "comment" {
        return Documentation::Absent;
    }
    let Some(gap) = source.get(last.end_byte()..declaration.start_byte()) else {
        return Documentation::Undecidable("invalid documentation source range");
    };
    if !adjacent(gap) {
        return Documentation::Absent;
    }
    let Some(last_text) = source.get(last.byte_range()) else {
        return Documentation::Undecidable("invalid documentation source range");
    };
    let comments = if last_text.starts_with("///") {
        let mut comments = vec![last];
        let mut current = last;
        while let Some(previous) = current.prev_named_sibling() {
            let Some(text) = source.get(previous.byte_range()) else {
                break;
            };
            let Some(gap) = source.get(previous.end_byte()..current.start_byte()) else {
                break;
            };
            if previous.kind() != "comment" || !text.starts_with("///") || !adjacent(gap) {
                break;
            }
            comments.push(previous);
            current = previous;
        }
        comments.reverse();
        comments
    } else if last_text.starts_with("/**") && last_text.len() > 4 {
        vec![last]
    } else {
        return Documentation::Absent;
    };

    // The other part of a partial declaration may contribute documentation.
    if declaration.child_by_field_name("name").is_some()
        && csharp_has_modifier(source, declaration, "partial")
    {
        return Documentation::Undecidable("partial declaration documentation may be elsewhere");
    }
    let mut xml = String::new();
    let mut offsets = Vec::new();
    for comment in comments {
        let text = &source[comment.byte_range()];
        let prefix = 3;
        let suffix = if text.starts_with("/**") && text.ends_with("*/") {
            2
        } else {
            0
        };
        let Some(body) = text.get(prefix..text.len().saturating_sub(suffix)) else {
            return Documentation::Undecidable("invalid documentation comment bounds");
        };
        let mut position = 0;
        for line in body.split_inclusive('\n') {
            let mut cut = 0;
            if !text.starts_with("///") {
                cut = line
                    .bytes()
                    .take_while(|b| matches!(b, b' ' | b'\t'))
                    .count();
                if line.as_bytes().get(cut) == Some(&b'*') {
                    cut += 1;
                }
            }
            let content = &line[cut..];
            xml.push_str(content);
            offsets.extend(
                (0..content.len()).map(|i| comment.start_byte() + prefix + position + cut + i),
            );
            position += line.len();
        }
        xml.push('\n');
        offsets.push(comment.end_byte());
    }
    parse(&xml, &offsets)
}

fn adjacent(gap: &str) -> bool {
    gap.bytes().all(|b| b.is_ascii_whitespace()) && gap.bytes().filter(|b| *b == b'\n').count() <= 1
}

fn parse(xml: &str, offsets: &[usize]) -> Documentation {
    let mut reader = Reader::from_str(xml);
    let mut tags = Vec::new();
    let mut open: Vec<Option<(Tag, bool)>> = Vec::new();
    loop {
        let start = reader.buffer_position() as usize;
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(_) => return Documentation::Undecidable("malformed XML documentation"),
        };
        let end = reader.buffer_position() as usize;
        let is_empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let kind = match element.name().as_ref() {
                    b"param" => Some(TagKind::Param),
                    b"typeparam" => Some(TagKind::TypeParam),
                    b"inheritdoc" => Some(TagKind::InheritDoc),
                    b"include" => {
                        return Documentation::Undecidable("XML include requires external content");
                    }
                    _ => None,
                };
                if let Some((_, body)) = open.iter_mut().rev().find_map(Option::as_mut) {
                    *body = true;
                }
                let Some(kind) = kind else {
                    if !is_empty {
                        open.push(None);
                    }
                    continue;
                };
                let mut name = None;
                for attribute in element.attributes() {
                    let Ok(attribute) = attribute else {
                        return Documentation::Undecidable("malformed XML attribute");
                    };
                    if attribute.key.as_ref() == b"name" {
                        let Ok(value) = attribute.decoded_and_normalized_value(
                            quick_xml::XmlVersion::Implicit1_0,
                            reader.decoder(),
                        ) else {
                            return Documentation::Undecidable("malformed XML attribute value");
                        };
                        name = Some(value.into_owned());
                    }
                }
                if matches!(kind, TagKind::Param | TagKind::TypeParam) && name.is_none() {
                    if !is_empty {
                        open.push(None);
                    }
                    continue;
                }
                let Some(&first) = offsets.get(start) else {
                    return Documentation::Undecidable("invalid XML source map");
                };
                let Some(&last) = offsets.get(end.saturating_sub(1)) else {
                    return Documentation::Undecidable("invalid XML source map");
                };
                let tag = Tag {
                    kind,
                    name,
                    has_body: false,
                    range: first..last + 1,
                };
                if is_empty {
                    tags.push(tag);
                } else {
                    open.push(Some((tag, false)));
                }
            }
            Event::Text(text) => {
                let bytes: &[u8] = text.as_ref();
                if !bytes.iter().all(u8::is_ascii_whitespace)
                    && let Some((_, body)) = open.iter_mut().rev().find_map(Option::as_mut)
                {
                    *body = true;
                }
            }
            Event::End(_) => {
                let Some(frame) = open.pop() else {
                    return Documentation::Undecidable("malformed XML documentation");
                };
                if let Some((mut tag, body)) = frame {
                    tag.has_body = body;
                    if let Some(&last) = offsets.get(end.saturating_sub(1)) {
                        tag.range.end = last + 1;
                    }
                    tags.push(tag);
                }
            }
            Event::Eof => break,
            _ => {
                if !xml[start..end]
                    .bytes()
                    .all(|byte| byte.is_ascii_whitespace())
                    && let Some((_, body)) = open.iter_mut().rev().find_map(Option::as_mut)
                {
                    *body = true;
                }
            }
        }
    }
    if !open.is_empty() {
        return Documentation::Undecidable("malformed XML documentation");
    }
    Documentation::Parsed(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    #[test]
    fn xml_comment_mapping_and_incomplete_content() {
        let source = "class C {\n/// <param name=\"x\">ok</param>\n[Obsolete]\nvoid M(int x) {}\n/**\n * <param name=\"z\"/>\n */\nvoid N(int z) {}\n}";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut methods = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "method_declaration" {
                methods.push(node);
            }
            for i in (0..node.child_count()).rev() {
                stack.push(node.child(i).unwrap());
            }
        }
        let Documentation::Parsed(first) = for_declaration(methods[0], source) else {
            panic!("line documentation lost");
        };
        assert_eq!(first[0].name.as_deref(), Some("x"));
        assert!(first[0].has_body);
        assert_eq!(
            &source[first[0].range.clone()],
            "<param name=\"x\">ok</param>"
        );
        let Documentation::Parsed(second) = for_declaration(methods[1], source) else {
            panic!("block documentation lost");
        };
        assert_eq!(second[0].name.as_deref(), Some("z"));
        assert!(!second[0].has_body);
    }
}
