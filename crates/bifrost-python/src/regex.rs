//! Python `re` pattern-value facts.
//!
//! Source structure comes from tree-sitter-python. This module decodes only a
//! string AST node selected as the pattern argument of a recognized `re` API,
//! then parses that decoded value with Python `re` rules. Unsupported syntax
//! is emitted as an incomplete fact instead of being treated as harmless.

use crate::bindings::{
    PythonLexicalNameResolution, python_comprehension_binds_name_at,
    python_module_or_class_scope_binds_name_bounded, python_name_resolution_at,
};
use crate::syntax::python_static_attribute_path;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::structural::spec::EmbeddedLeafFact;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

use brokk_bifrost_core::analyzer::structural::regex::{
    CharacterSet, ClassAtom, EscapeValue, Fact, GroupPrefix, MAX_PATTERN_CHARS, MappedChar,
    NfaError, RegexAnalysis, RegexFlags, RegexNfa, RegexParser, RegexSyntax, single_character,
};

#[derive(Debug)]
struct DecodedValue {
    value: String,
    chars: Vec<MappedChar>,
    source_range: Range,
    is_bytes: bool,
}

#[derive(Debug, Clone, Copy)]
struct Api {
    flags_position: usize,
    scans_from_each_offset: bool,
}

/// Return facts for a string-literal node or a call node in the Python AST.
/// A string is analyzed only when it is the first positional argument or the
/// `pattern` keyword of a statically named `re` API call.
pub(crate) fn embedded_facts(node: Node<'_>, source: &str) -> Vec<EmbeddedLeafFact> {
    if node.kind() == "call" {
        return dynamic_pattern_fact(node, source).into_iter().collect();
    }
    if !matches!(node.kind(), "string" | "concatenated_string")
        || (node.kind() == "string"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "concatenated_string"))
    {
        return Vec::new();
    }
    let Some((call, api)) = pattern_call(node, source) else {
        return Vec::new();
    };
    let decoded = match decode_regex_pattern_string(node, source) {
        Ok(decoded) => decoded,
        Err(reason) => return vec![incomplete_fact(node, source, reason)],
    };
    let flags = call_flags(call, api, source);
    let facts = parse_pattern(&decoded, flags, api);
    facts_to_embedded(facts, &decoded, source)
}

pub(crate) fn module_assigned_facts(root: Node<'_>, source: &str) -> Vec<EmbeddedLeafFact> {
    assert_eq!(root.kind(), "module");
    let mut assignments = HashMap::<String, (usize, Option<Node<'_>>)>::new();
    let mut calls = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if module_level_statement(node)
            .is_some_and(|statement| statement.kind() == "expression_statement")
            && node.kind() == "assignment"
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            && left.kind() == "identifier"
        {
            let candidate =
                matches!(right.kind(), "string" | "concatenated_string").then_some(right);
            let entry = assignments
                .entry(node_text(left, source).to_owned())
                .or_insert((0, None));
            entry.0 += 1;
            entry.1 = (entry.0 == 1).then_some(candidate).flatten();
        }
        if node.kind() == "call"
            && let Some(function) = node.child_by_field_name("function")
            && let Some(api) = recognized_api(function, source)
            && let Some(arguments) = node.child_by_field_name("arguments")
            && let Some(pattern) = selected_pattern_argument(arguments, source)
            && pattern.kind() == "identifier"
        {
            calls.push((node, pattern, api, node_text(pattern, source).to_owned()));
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }

    let mut facts = Vec::new();
    for (call, pattern, api, name) in calls {
        let resolved = assignments
            .get(&name)
            .and_then(|(writes, candidate)| {
                (*writes == 1)
                    .then_some(*candidate)
                    .flatten()
                    .filter(|candidate| candidate.end_byte() < call.start_byte())
            })
            .filter(|_| module_pattern_binding_is_visible(&name, pattern, source));
        let Some(selected) = resolved else {
            let range = node_range(pattern, source);
            facts.push(EmbeddedLeafFact {
                kind: NormalizedKind::RegexIncomplete,
                range,
                parent: None,
                construct: Some(format!("dynamic-pattern:{}", api.flags_position)),
                occurrence_role: None,
            });
            continue;
        };
        let decoded = match decode_regex_pattern_string(selected, source) {
            Ok(decoded) => decoded,
            Err(reason) => {
                facts.push(incomplete_fact(selected, source, reason));
                continue;
            }
        };
        let flags = call_flags(call, api, source);
        let mut parsed = facts_to_embedded(parse_pattern(&decoded, flags, api), &decoded, source);
        let base = facts.len();
        for fact in &mut parsed {
            fact.parent = fact.parent.map(|parent| base + parent);
        }
        facts.extend(parsed);
    }
    facts
}

fn module_pattern_binding_is_visible(name: &str, reference: Node<'_>, source: &str) -> bool {
    if python_comprehension_binds_name_at(name, reference, source)
        || matches!(
            python_name_resolution_at(name, reference, source),
            PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
        )
    {
        return false;
    }

    let mut current = reference;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "function_definition" | "lambda" => break,
            "class_definition" => {
                return python_module_or_class_scope_binds_name_bounded(
                    parent,
                    name,
                    source,
                    || true,
                ) == Some(false);
            }
            _ => current = parent,
        }
    }
    true
}

fn module_level_statement<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    loop {
        let parent = current.parent()?;
        if parent.kind() == "module" {
            return Some(current);
        }
        current = parent;
    }
}

fn incomplete_fact(node: Node<'_>, source: &str, reason: &str) -> EmbeddedLeafFact {
    let range = node_range(node, source);
    EmbeddedLeafFact {
        kind: NormalizedKind::RegexIncomplete,
        range,
        parent: None,
        construct: Some(reason.to_owned()),
        occurrence_role: None,
    }
}

fn dynamic_pattern_fact(node: Node<'_>, source: &str) -> Option<EmbeddedLeafFact> {
    let function = node.child_by_field_name("function")?;
    let api = recognized_api(function, source)?;
    let arguments = node.child_by_field_name("arguments")?;
    let pattern = selected_pattern_argument(arguments, source)?;
    if matches!(pattern.kind(), "string" | "concatenated_string") {
        return None;
    }
    if pattern.kind() == "identifier" {
        return None;
    }
    let range = node_range(pattern, source);
    Some(EmbeddedLeafFact {
        kind: NormalizedKind::RegexIncomplete,
        range,
        parent: None,
        construct: Some(format!("dynamic-pattern:{}", api.flags_position)),
        occurrence_role: None,
    })
}

fn pattern_call<'tree>(node: Node<'tree>, source: &str) -> Option<(Node<'tree>, Api)> {
    let argument = node.parent()?;
    let (arguments, is_pattern_keyword) = match argument.kind() {
        "keyword_argument" => {
            let name = argument.child_by_field_name("name")?;
            let value = argument.child_by_field_name("value")?;
            (
                argument.parent()?,
                value.id() == node.id() && node_text(name, source) == "pattern",
            )
        }
        "argument_list" => (argument, false),
        _ => return None,
    };
    if arguments.kind() != "argument_list" {
        return None;
    }
    let call = arguments.parent()?;
    if call.kind() != "call" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    let api = recognized_api(function, source)?;
    let selected = if is_pattern_keyword {
        true
    } else {
        selected_pattern_argument(arguments, source)
            .is_some_and(|pattern| pattern.id() == node.id())
    };
    selected.then_some((call, api))
}

fn selected_pattern_argument<'tree>(arguments: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut positional = 0usize;
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        match argument.kind() {
            "comment" => {}
            "keyword_argument" => {
                let name = argument.child_by_field_name("name")?;
                if node_text(name, source) == "pattern" {
                    return argument.child_by_field_name("value");
                }
            }
            _ => {
                if positional == 0 {
                    return Some(argument);
                }
                positional += 1;
            }
        }
    }
    None
}

fn recognized_api(function: Node<'_>, source: &str) -> Option<Api> {
    let path = python_static_attribute_path(function)?;
    if path.len() != 2 || node_text(path[0], source) != "re" {
        return None;
    }
    let (flags_position, scans_from_each_offset) = match node_text(path[1], source) {
        "compile" => (1, false),
        "search" | "findall" | "finditer" => (2, true),
        "match" | "fullmatch" => (2, false),
        "split" => (3, true),
        "sub" | "subn" => (4, true),
        _ => return None,
    };
    Some(Api {
        flags_position,
        scans_from_each_offset,
    })
}

fn call_flags(call: Node<'_>, api: Api, source: &str) -> RegexFlags {
    let mut flags_node = None;
    if let Some(arguments) = call.child_by_field_name("arguments") {
        let mut positional = 0usize;
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            match argument.kind() {
                "comment" => {}
                "keyword_argument" => {
                    if argument
                        .child_by_field_name("name")
                        .is_some_and(|name| node_text(name, source) == "flags")
                    {
                        flags_node = argument.child_by_field_name("value");
                    }
                }
                _ => {
                    if positional == api.flags_position {
                        flags_node = Some(argument);
                    }
                    positional += 1;
                }
            }
        }
    }
    let Some(flags_node) = flags_node else {
        return RegexFlags {
            dialect_flags: 0,
            dotall: false,
            multiline: false,
            ignorecase: false,
            ascii: false,
            verbose: false,
            complete: true,
        };
    };
    let mut pending = vec![flags_node];
    let mut flags = RegexFlags {
        dialect_flags: 0,
        dotall: false,
        multiline: false,
        ignorecase: false,
        ascii: false,
        verbose: false,
        complete: true,
    };
    while let Some(node) = pending.pop() {
        match node.kind() {
            "integer" => {
                let text = node_text(node, source).replace('_', "");
                match python_integer_value(&text) {
                    Some(value) => {
                        flags.ignorecase |= value & 2 != 0;
                        flags.dotall |= value & 16 != 0;
                        flags.multiline |= value & 8 != 0;
                        flags.ascii |= value & 256 != 0;
                        flags.complete &=
                            value & !(2 | 8 | 16 | 32 | 256) == 0 && value & (64 | 128) == 0;
                    }
                    None => flags.complete = false,
                }
            }
            "attribute" | "identifier" => {
                let path = python_static_attribute_path(node);
                let name = path.as_ref().and_then(|path| {
                    (path.len() >= 2
                        && node_text(path[0], source) == "re"
                        && path[1..path.len() - 1]
                            .iter()
                            .all(|part| node_text(*part, source) == "re"))
                    .then(|| node_text(*path.last().expect("flag path is nonempty"), source))
                });
                match name {
                    Some("S" | "DOTALL") => flags.dotall = true,
                    Some("M" | "MULTILINE") => flags.multiline = true,
                    Some("I" | "IGNORECASE") => flags.ignorecase = true,
                    Some("A" | "ASCII") => flags.ascii = true,
                    Some("X" | "VERBOSE") => flags.verbose = true,
                    Some("U" | "UNICODE") => {}
                    Some("DEBUG") => flags.complete = false,
                    _ => flags.complete = false,
                }
            }
            "binary_operator" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    pending.push(right);
                    pending.push(left);
                } else {
                    flags.complete = false;
                }
            }
            _ => flags.complete = false,
        }
    }
    flags
}

fn parse_inline_flags(
    chars: &[char],
    mut index: usize,
    mut flags: RegexFlags,
) -> Option<(usize, RegexFlags)> {
    let mut enabled = true;
    let mut saw_flag = false;
    let mut ascii_mode = None;
    while let Some(character) = chars.get(index).copied() {
        match character {
            ')' | ':' if saw_flag && (enabled || character == ':') => {
                if ascii_mode == Some((true, true)) {
                    return None;
                }
                return Some((index, flags));
            }
            '-' if enabled => {
                enabled = false;
                saw_flag = false;
            }
            'i' | 'm' | 's' | 'x' | 'a' | 'u' => {
                if !enabled && matches!(character, 'a' | 'u') {
                    return None;
                }
                saw_flag = true;
                match character {
                    'i' => flags.ignorecase = enabled,
                    'm' => flags.multiline = enabled,
                    's' => flags.dotall = enabled,
                    'x' => flags.verbose = enabled,
                    'a' => {
                        flags.ascii = enabled;
                        ascii_mode =
                            Some((enabled, ascii_mode.is_some_and(|(_, unicode)| unicode)));
                    }
                    'u' => {
                        flags.ascii = !enabled;
                        ascii_mode = Some((ascii_mode.is_some_and(|(ascii, _)| ascii), enabled));
                    }
                    _ => unreachable!("inline flag arm includes only Python regex flags"),
                }
            }
            _ => return None,
        }
        index += 1;
    }
    None
}

fn python_integer_value(text: &str) -> Option<u64> {
    let (radix, digits) =
        if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (16, digits)
        } else if let Some(digits) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
            (8, digits)
        } else if let Some(digits) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (2, digits)
        } else {
            (10, text)
        };
    u64::from_str_radix(digits, radix).ok()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes())
        .expect("tree-sitter node ranges are valid UTF-8 source")
}

fn node_range(node: Node<'_>, source: &str) -> Range {
    let line_starts = compute_line_starts(source);
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    Range {
        start_byte,
        end_byte,
        start_line: find_line_index_for_offset(&line_starts, start_byte) + 1,
        end_line: find_line_index_for_offset(
            &line_starts,
            end_byte.saturating_sub(1).max(start_byte),
        ) + 1,
    }
}

fn decode_python_string(node: Node<'_>, source: &str) -> Result<DecodedValue, &'static str> {
    let decoded = decode_string_literal(node, source)?;
    if decoded.is_bytes {
        return Err("non-text-or-formatted-string");
    }
    Ok(decoded)
}

fn decode_regex_pattern_string(node: Node<'_>, source: &str) -> Result<DecodedValue, &'static str> {
    decode_string_literal(node, source)
}

fn decode_string_literal(node: Node<'_>, source: &str) -> Result<DecodedValue, &'static str> {
    let mut strings = Vec::new();
    if node.kind() == "string" {
        strings.push(node);
    } else {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current.kind() == "string" {
                strings.push(current);
                continue;
            }
            let mut children = Vec::new();
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if child.kind() == "concatenated_string" || child.kind() == "string" {
                    children.push(child);
                } else {
                    return Err("non-literal-string-segment");
                }
            }
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
    if strings.is_empty() {
        return Err("empty-concatenated-string");
    }
    let mut value = String::new();
    let mut chars = Vec::new();
    let mut byte_string = None;
    for string in strings {
        let is_bytes = decode_string_segment(string, source, &mut value, &mut chars)?;
        if byte_string.is_some_and(|previous| previous != is_bytes) {
            return Err("mixed-bytes-and-text-concatenation");
        }
        byte_string = Some(is_bytes);
        if chars.len() > MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
    }
    Ok(DecodedValue {
        value,
        chars,
        source_range: node_range(node, source),
        is_bytes: byte_string.expect("non-empty literal expression has a string segment"),
    })
}

/// Decode the value of a tree-sitter-selected Python string expression.
///
/// Callers must select the literal from syntax before invoking this helper;
/// this function classifies only the selected expression's value.
pub fn decode_python_string_value(node: Node<'_>, source: &str) -> Result<String, &'static str> {
    decode_python_string(node, source).map(|decoded| decoded.value)
}

/// Decode each literal segment in a selected Python f-string, omitting its
/// interpolation expressions. The parse tree chooses the segments; this
/// helper reads only their decoded values.
pub fn decode_python_fstring_literal_segments(
    node: Node<'_>,
    source: &str,
) -> Result<Vec<String>, &'static str> {
    if node.kind() != "string" {
        return Err("not-a-python-fstring");
    }
    let mut start_token = None;
    let mut segments: Vec<Vec<Node<'_>>> = vec![Vec::new()];
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" if start_token.is_none() => start_token = Some(child),
            "string_start" => return Err("duplicate-fstring-start"),
            "string_end" => break,
            "interpolation" => segments.push(Vec::new()),
            "string_content" | "escape_sequence" => segments
                .last_mut()
                .expect("f-string literal segments retain a current segment")
                .push(child),
            _ => return Err("unsupported-fstring-prefix-node"),
        }
    }
    let start_token = start_token.ok_or("missing-fstring-start")?;
    let prefix = string_prefix(node_text(start_token, source));
    if !prefix.contains('f')
        || prefix
            .chars()
            .any(|character| !matches!(character, 'f' | 'r'))
        || prefix.matches('f').count() != 1
        || prefix.matches('r').count() > 1
    {
        return Err("unsupported-fstring-prefix");
    }
    let raw = prefix.contains('r');
    segments
        .into_iter()
        .map(|parts| {
            let mut value = String::new();
            let mut mapped = Vec::new();
            for part in parts {
                if raw {
                    append_mapped_text(
                        node_text(part, source),
                        part.start_byte(),
                        part.end_byte(),
                        &mut value,
                        &mut mapped,
                    )?;
                } else if part.kind() == "escape_sequence" {
                    decode_literal_escape(
                        node_text(part, source),
                        part.start_byte(),
                        &mut value,
                        &mut mapped,
                        false,
                    )?;
                } else {
                    decode_string_content(part, source, &mut value, &mut mapped, false)?;
                }
            }
            Ok(value.replace("{{", "{").replace("}}", "}"))
        })
        .collect()
}

fn decode_string_segment(
    node: Node<'_>,
    source: &str,
    value: &mut String,
    output: &mut Vec<MappedChar>,
) -> Result<bool, &'static str> {
    let mut start_token = None;
    let mut body = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" => start_token = Some(child),
            "string_end" => {}
            "string_content" | "escape_sequence" => body.push(child),
            "interpolation" => return Err("formatted-string-interpolation"),
            _ => return Err("unsupported-string-segment"),
        }
    }
    let start_token = start_token.ok_or("missing-string-start")?;
    let prefix = string_prefix(node_text(start_token, source));
    if prefix.contains('f') || prefix.contains('t') {
        return Err("non-text-or-formatted-string");
    }
    if prefix
        .chars()
        .any(|prefix| !matches!(prefix, 'r' | 'u' | 'b'))
        || prefix.matches('r').count() > 1
        || prefix.matches('u').count() > 1
        || prefix.matches('b').count() > 1
        || (prefix.contains('r') && prefix.contains('u'))
        || (prefix.contains('b') && prefix.contains('u'))
    {
        return Err("unsupported-string-prefix");
    }
    let is_bytes = prefix.contains('b');
    if is_bytes && !node_text(node, source).is_ascii() {
        return Err("non-ascii-byte-literal");
    }
    let raw = prefix.contains('r');
    for part in body {
        let raw_text = node_text(part, source);
        if raw && matches!(part.kind(), "escape_sequence" | "string_content") {
            append_mapped_text(raw_text, part.start_byte(), part.end_byte(), value, output)?;
        } else if !raw && part.kind() == "escape_sequence" {
            decode_literal_escape(raw_text, part.start_byte(), value, output, is_bytes)?;
        } else if !raw && part.kind() == "string_content" {
            decode_string_content(part, source, value, output, is_bytes)?;
        } else {
            append_mapped_text(raw_text, part.start_byte(), part.end_byte(), value, output)?;
        }
        if output.len() > MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
    }
    if is_bytes && value.chars().any(|character| character as u32 > 0xff) {
        return Err("byte-pattern-value-out-of-range");
    }
    Ok(is_bytes)
}

fn string_prefix(start: &str) -> String {
    start
        .chars()
        .take_while(|character| !matches!(character, '\'' | '"'))
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn append_mapped_text(
    text: &str,
    source_start: usize,
    source_end: usize,
    output_text: &mut String,
    output: &mut Vec<MappedChar>,
) -> Result<(), &'static str> {
    for (offset, value) in text.char_indices() {
        if output.len() >= MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
        let start = source_start + offset;
        let end = start + value.len_utf8();
        output_text.push(value);
        output.push(MappedChar {
            source_start: start,
            source_end: end,
        });
    }
    debug_assert_eq!(source_start + text.len(), source_end);
    Ok(())
}

fn decode_string_content(
    node: Node<'_>,
    source: &str,
    output_text: &mut String,
    output: &mut Vec<MappedChar>,
    bytes: bool,
) -> Result<(), &'static str> {
    let mut position = node.start_byte();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        assert_eq!(child.kind(), "escape_sequence");
        assert!(position <= child.start_byte());
        if position < child.start_byte() {
            let plain = source
                .get(position..child.start_byte())
                .expect("tree-sitter string ranges are valid UTF-8 source");
            append_mapped_text(plain, position, child.start_byte(), output_text, output)?;
        }
        decode_literal_escape(
            node_text(child, source),
            child.start_byte(),
            output_text,
            output,
            bytes,
        )?;
        position = child.end_byte();
    }
    assert!(position <= node.end_byte());
    if position < node.end_byte() {
        let plain = source
            .get(position..node.end_byte())
            .expect("tree-sitter string ranges are valid UTF-8 source");
        append_mapped_text(plain, position, node.end_byte(), output_text, output)?;
    }
    Ok(())
}

fn decode_literal_escape(
    raw: &str,
    source_start: usize,
    output_text: &mut String,
    output: &mut Vec<MappedChar>,
    bytes: bool,
) -> Result<(), &'static str> {
    let chars: Vec<char> = raw.chars().collect();
    if chars.first() != Some(&'\\') || chars.len() < 2 {
        return Err("malformed-literal-escape");
    }
    if bytes && matches!(chars.get(1), Some('u' | 'U' | 'N')) {
        return append_mapped_text(
            raw,
            source_start,
            source_start + raw.len(),
            output_text,
            output,
        );
    }
    let escaped = chars[1];
    let replacement = match escaped {
        '\n' => None,
        '\r' if chars.get(2) == Some(&'\n') => None,
        '\r' => Some('\r'),
        '\\' => Some('\\'),
        '\'' => Some('\''),
        '"' => Some('"'),
        'a' => Some('\u{7}'),
        'b' => Some('\u{8}'),
        'f' => Some('\u{c}'),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'v' => Some('\u{b}'),
        'x' => Some(
            char::from_u32(hex_value(&chars, 2, 2).ok_or("invalid-hex-escape")?)
                .ok_or("invalid-hex-scalar")?,
        ),
        'u' => Some(
            char::from_u32(hex_value(&chars, 2, 4).ok_or("invalid-unicode-escape")?)
                .ok_or("invalid-unicode-scalar")?,
        ),
        'U' => Some(
            char::from_u32(hex_value(&chars, 2, 8).ok_or("invalid-unicode-escape")?)
                .ok_or("invalid-unicode-scalar")?,
        ),
        'N' => return Err("named-unicode-escape"),
        '0'..='7' => {
            let mut value = (escaped as u32) - ('0' as u32);
            let mut digits = 1usize;
            while digits < 3 {
                let Some(digit @ '0'..='7') = chars.get(1 + digits).copied() else {
                    break;
                };
                value = value * 8 + (digit as u32 - '0' as u32);
                digits += 1;
            }
            Some(char::from_u32(value).ok_or("invalid-octal-scalar")?)
        }
        // Python preserves unrecognized escapes, including punctuation; the
        // regex parser must receive the backslash to classify them correctly.
        other => {
            if output.len().saturating_add(2) > MAX_PATTERN_CHARS {
                return Err("pattern-character-budget");
            }
            output_text.push('\\');
            output.push(MappedChar {
                source_start,
                source_end: source_start + 1,
            });
            output_text.push(other);
            output.push(MappedChar {
                source_start: source_start + 1,
                source_end: source_start + 1 + other.len_utf8(),
            });
            return Ok(());
        }
    };
    if let Some(replacement) = replacement {
        if output.len() >= MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
        output_text.push(replacement);
        output.push(MappedChar {
            source_start,
            source_end: source_start + raw.len(),
        });
    }
    Ok(())
}

fn hex_value(chars: &[char], start: usize, digits: usize) -> Option<u32> {
    chars
        .get(start..start + digits)?
        .iter()
        .try_fold(0u32, |value, digit| {
            digit.to_digit(16).map(|digit| value * 16 + digit)
        })
}

/// Python's existing bounded regex-value grammar and Rust-regex bad-tag analysis.
struct PythonRegexSyntax;

impl RegexSyntax for PythonRegexSyntax {
    fn group_prefix(&self, chars: &[char], start: usize) -> GroupPrefix {
        match (chars.get(start + 1), chars.get(start + 2)) {
            (Some(':'), _) => GroupPrefix::Noncapturing,
            (Some('P'), Some('<')) => GroupPrefix::Named { name_offset: 3 },
            (Some('#'), _) => GroupPrefix::Comment,
            (Some('='), _) => GroupPrefix::LookaheadPositive,
            (Some('!'), _) => GroupPrefix::LookaheadNegative,
            (Some('<'), Some('=')) => GroupPrefix::LookbehindPositive,
            (Some('<'), Some('!')) => GroupPrefix::LookbehindNegative,
            (Some('i' | 'm' | 's' | 'x' | 'a' | 'u' | '-'), _) => GroupPrefix::Flags,
            _ => GroupPrefix::Unsupported,
        }
    }
    fn incomplete_group_end(&self, chars: &[char], start: usize) -> Option<usize> {
        if chars.get(start) != Some(&'P') || chars.get(start + 1) != Some(&'<') {
            return None;
        }
        let mut close = start + 2;
        while close < chars.len() && chars[close] != '>' {
            close += 1;
        }
        let name = &chars[start + 2..close.min(chars.len())];
        let valid_name = name
            .first()
            .is_some_and(|first| first.is_alphabetic() || *first == '_')
            && name
                .iter()
                .all(|character| character.is_alphanumeric() || *character == '_');
        if close < chars.len() && valid_name {
            return Some(close + 1);
        }
        None
    }
    fn inline_flags(
        &self,
        chars: &[char],
        start: usize,
        flags: RegexFlags,
    ) -> Option<(usize, RegexFlags)> {
        parse_inline_flags(chars, start, flags)
    }
    fn escape(
        &self,
        chars: &[char],
        start: usize,
        in_class: bool,
        flags: RegexFlags,
    ) -> Option<EscapeValue> {
        parse_regex_escape(chars, start, in_class, flags.ascii)
    }
    fn class_atom(&self, chars: &[char], start: usize, flags: RegexFlags) -> Option<ClassAtom> {
        parse_class_atom(chars, start, flags.ascii)
    }
    fn wildcard(&self, flags: RegexFlags) -> CharacterSet {
        if flags.dotall {
            CharacterSet {
                ranges: vec![(0, 0x10ffff)],
            }
        } else {
            CharacterSet::any_except_newline()
        }
    }
    fn fold_case(&self, set: CharacterSet, flags: RegexFlags) -> CharacterSet {
        if flags.ignorecase {
            set.with_ascii_case_variants()
        } else {
            set
        }
    }
    fn case_folding_is_complete(&self, flags: RegexFlags) -> bool {
        !flags.ignorecase || flags.ascii
    }
    fn verbose_whitespace(&self, character: char) -> bool {
        matches!(character, ' ' | '\t' | '\n' | '\r' | '\x0c' | '\x0b')
    }
    fn verbose_comment_terminator(&self, character: char) -> bool {
        character == '\n'
    }
    fn supports_possessive_quantifiers(&self) -> bool {
        true
    }
    fn analyze(&self, context: &mut RegexAnalysis<'_>) {
        if context.incomplete.is_some() || !context.flags.complete {
            return;
        }
        let value = context.value;
        if !(value.contains('<') && value.contains('>'))
            && !["-->", "--!>", "<--", "<!--"]
                .iter()
                .any(|marker| value.contains(marker))
        {
            return;
        }
        let rust_pattern = value
            .replace("\\/", "/")
            .replace("\\\"", "\"")
            .replace("\\'", "'");
        let mut builder = regex::RegexBuilder::new(&rust_pattern);
        builder
            .case_insensitive(context.flags.ignorecase)
            .multi_line(context.flags.multiline)
            .dot_matches_new_line(context.flags.dotall)
            .unicode(!context.flags.ascii)
            .ignore_whitespace(context.flags.verbose);
        let Ok(regex) = builder.build() else {
            return;
        };
        let capture_nfa = match RegexNfa::compile(context.facts, 0, None) {
            Ok(nfa) => Some(nfa),
            Err(error) => {
                context.mark_incomplete(
                    0,
                    context.chars.len(),
                    match error {
                        NfaError::Unsupported => "bad-tag-nfa-unsupported",
                        NfaError::Budget => "bad-tag-nfa-state-budget",
                    },
                );
                return;
            }
        };
        let matches = |sample: &str| {
            capture_nfa.as_ref().map_or_else(
                || regex.is_match(sample),
                |nfa| nfa.match_prefix_capture_groups(sample).0,
            )
        };
        let groups = |sample: &str| {
            capture_nfa.as_ref().map_or_else(
                || {
                    regex
                        .captures(sample)
                        .map(|captures| {
                            captures
                                .iter()
                                .enumerate()
                                .skip(1)
                                .filter_map(|(index, capture)| capture.map(|_| index))
                                .collect::<HashSet<_>>()
                        })
                        .unwrap_or_default()
                },
                |nfa| nfa.match_prefix_capture_groups(sample).1,
            )
        };
        let comment = "<!-- foo -->";
        let comment_bang = "<!-- foo --!>";
        let comment_groups = groups(comment);
        let comment_bang_groups = groups(comment_bang);
        let comment_group_mismatch = matches(comment)
            && matches(comment_bang)
            && comment_groups.iter().any(|group| {
                !comment_bang_groups.contains(group)
                    && comment_bang_groups.iter().any(|other| group != other)
            });
        let plain_tag_groups = groups("<foo>");
        let only_comment_group = groups(comment).iter().any(|group| {
            plain_tag_groups.iter().any(|other| other != group)
                && !matches(comment_bang)
                && !groups("<!- foo ->").contains(group)
                && !plain_tag_groups.contains(group)
                && !groups("<script>").contains(group)
        });
        let bounded_script_opener = value
            .to_ascii_lowercase()
            .find("<script")
            .map(|start| {
                let start = value[..start].chars().count() + "<script".len();
                context
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == NormalizedKind::RegexLiteral
                            && fact.construct.as_deref() == Some(">")
                            && fact.start >= start
                            && !fact.parent.is_some_and(|parent| {
                                context.facts[parent].kind == NormalizedKind::RegexCharacterClass
                            })
                    })
                    .map(|fact| fact.start)
                    .min()
                    .is_some_and(|tag_end| {
                        context.facts.iter().enumerate().any(|(id, fact)| {
                            fact.kind == NormalizedKind::RegexCharacterClass
                                && fact.start >= start
                                && fact.end <= tag_end
                                && fact
                                    .first_set
                                    .as_ref()
                                    .is_some_and(|set| !set.contains('>'))
                                && context.facts.iter().any(|quantifier| {
                                    quantifier.kind == NormalizedKind::RegexQuantifier
                                        && quantifier.parent == Some(id)
                                        && quantifier
                                            .quantifier
                                            .is_some_and(|quantifier| quantifier.maximum.is_none())
                                })
                        })
                    })
            })
            .unwrap_or(false);
        let script_warning = !bounded_script_opener
            && ((matches("<script>foo</script>")
                && matches("<script src=\"foo\"></script>")
                && !matches("<foo ></foo>")
                && (!matches("<script \n>foo</script>") || !matches("<script >foo\n</script>")))
                || (matches("<script>foo</script>")
                    && matches("<script src=\"foo\"></script>")
                    && !matches("<script src='foo'></script>")
                    && !matches("<foo>"))
                || (matches("<script>foo</script>")
                    && matches("<script src='foo'></script>")
                    && !matches("<script src=\"foo\"></script>")
                    && !matches("<foo>"))
                || (matches("<script>foo</script>")
                    && matches("<script src='foo'></script>")
                    && !matches("<script\tsrc='foo'></script>")
                    && !matches("<foo>")
                    && !matches("<foo src=\"foo\"></foo>"))
                || (matches("<script>foo</script>")
                    && !context.flags.ignorecase
                    && !matches("<foo>")
                    && !matches("<foo ></foo>")
                    && (!matches("<SCRIPT>foo</SCRIPT>")
                        || (matches("<SCRIPT>foo</SCRIPT>") && !matches("<sCrIpT>foo</ScRiPt>"))))
                || (matches("<script src=\"foo\"></script>")
                    && !matches("<foo>")
                    && !matches("<foo ></foo>")
                    && (!matches("<script src=\"foo\">foo</script >")
                        || !matches("<script src=\"foo\">foo</script foo=\"bar\">")
                        || !matches("<script src=\"foo\">foo</script\t\n bar>"))));
        let warning = comment_group_mismatch
            || only_comment_group
            || (matches("-->") && !matches("--!>") && !matches("--"))
            || (matches(comment)
                && !matches("<!-- foo\n -->")
                && !matches("<!- foo ->")
                && !matches("<foo>")
                && !matches("<script>"))
            || script_warning;
        if warning {
            context.pending_risks.push((
                NormalizedKind::RegexRiskBadTag,
                0,
                0,
                context.chars.len(),
                "matches-html-samples-inconsistently".to_owned(),
            ));
        }
    }
}

fn category_character_set(escaped: char, ascii: bool) -> Option<CharacterSet> {
    let (category, negated) = match escaped {
        'd' => ('d', false),
        'D' => ('d', true),
        's' => ('s', false),
        'S' => ('s', true),
        'w' => ('w', false),
        'W' => ('w', true),
        _ => return None,
    };
    let mut set = match category {
        'd' => CharacterSet {
            ranges: vec![(b'0' as u32, b'9' as u32)],
        },
        's' => CharacterSet {
            ranges: vec![(9, 13), (32, 32)],
        },
        'w' => CharacterSet {
            ranges: vec![
                (b'0' as u32, b'9' as u32),
                (b'A' as u32, b'Z' as u32),
                (b'_' as u32, b'_' as u32),
                (b'a' as u32, b'z' as u32),
            ],
        },
        _ => unreachable!("category is selected from d, s, w"),
    };
    if !ascii && negated {
        // A Unicode negated category is not the complement of its ASCII
        // subset. Leave it unknown rather than claim a false overlap.
    }
    if !ascii && negated {
        return None;
    }
    if negated {
        set = set.complement();
    }
    Some(set)
}

fn parse_regex_escape(
    chars: &[char],
    start: usize,
    in_class: bool,
    ascii: bool,
) -> Option<EscapeValue> {
    if chars.get(start) != Some(&'\\') {
        return None;
    }
    let escaped = *chars.get(start + 1)?;
    let mut end = start + 2;
    let mut value = None;
    let mut anchor = false;
    let mut incomplete = None;
    let mut backspace = false;
    let construct = match escaped {
        'A' | 'Z' | 'z' | 'b' | 'B' if !in_class => {
            anchor = true;
            Some(format!("boundary:{escaped}"))
        }
        'd' | 'D' | 's' | 'S' | 'w' | 'W' => Some(format!("category:{escaped}")),
        'a' => {
            value = Some('\u{7}');
            Some("U+0007".to_owned())
        }
        'f' => {
            value = Some('\u{c}');
            Some("U+000C".to_owned())
        }
        'n' => {
            value = Some('\n');
            Some("U+000A".to_owned())
        }
        'r' => {
            value = Some('\r');
            Some("U+000D".to_owned())
        }
        't' => {
            value = Some('\t');
            Some("U+0009".to_owned())
        }
        'v' => {
            value = Some('\u{b}');
            Some("U+000B".to_owned())
        }
        'b' if in_class => {
            value = Some('\u{8}');
            backspace = true;
            Some("backspace".to_owned())
        }
        'x' | 'u' | 'U' => {
            let digits = match escaped {
                'x' => 2,
                'u' => 4,
                _ => 8,
            };
            let scalar = hex_value(chars, start + 2, digits);
            end = start + 2 + digits;
            match scalar.and_then(char::from_u32) {
                Some(character) => {
                    value = Some(character);
                    Some(format!("U+{:04X}", character as u32))
                }
                None => {
                    incomplete = Some("invalid-hex-escape");
                    Some(format!("invalid:{escaped}"))
                }
            }
        }
        'N' => {
            incomplete = Some("named-unicode-escape");
            if chars.get(start + 2) == Some(&'{') {
                let mut close = start + 3;
                while close < chars.len() && chars[close] != '}' {
                    close += 1;
                }
                end = (close + 1).min(chars.len());
            }
            Some("unicode-name".to_owned())
        }
        '0'..='7' => {
            let mut codepoint = escaped as u32 - '0' as u32;
            let mut digits = 1usize;
            while digits < 3 {
                let Some(digit @ '0'..='7') = chars.get(start + 1 + digits).copied() else {
                    break;
                };
                codepoint = codepoint * 8 + (digit as u32 - '0' as u32);
                digits += 1;
            }
            end = start + 1 + digits;
            match char::from_u32(codepoint) {
                Some(character) => {
                    value = Some(character);
                    Some(format!("U+{codepoint:04X}"))
                }
                None => {
                    incomplete = Some("invalid-octal-escape");
                    Some("invalid-octal".to_owned())
                }
            }
        }
        '1'..='9' if !in_class => {
            incomplete = Some("backreference-not-supported");
            Some(format!("backreference:{escaped}"))
        }
        'g' | 'k' if !in_class => {
            incomplete = Some("named-backreference-not-supported");
            Some(format!("backreference:{escaped}"))
        }
        other if other.is_ascii_alphabetic() => {
            incomplete = Some("unknown-regex-escape");
            Some(format!("unknown:{other}"))
        }
        other => {
            value = Some(other);
            Some(other.to_string())
        }
    };
    if end > chars.len() {
        return None;
    }
    let first_set = value
        .map(CharacterSet::one)
        .or_else(|| category_character_set(escaped, ascii));
    Some(EscapeValue {
        end,
        anchor,
        construct,
        first_set,
        incomplete,
        backspace,
    })
}

fn parse_class_atom(chars: &[char], start: usize, ascii: bool) -> Option<ClassAtom> {
    let value = *chars.get(start)?;
    if value != '\\' {
        return Some(ClassAtom {
            start,
            end: start + 1,
            value: Some(value),
            set: Some(CharacterSet::one(value)),
            kind: NormalizedKind::RegexLiteral,
            construct: Some(value.to_string()),
            backspace: false,
            incomplete: None,
        });
    }
    let escape = parse_regex_escape(chars, start, true, ascii)?;
    Some(ClassAtom {
        start,
        end: escape.end,
        value: escape.first_set.as_ref().and_then(single_character),
        set: escape.first_set,
        kind: NormalizedKind::RegexEscape,
        construct: escape.construct,
        backspace: escape.backspace,
        incomplete: escape.incomplete,
    })
}

fn facts_to_embedded(
    facts: Vec<Fact>,
    decoded: &DecodedValue,
    source: &str,
) -> Vec<EmbeddedLeafFact> {
    brokk_bifrost_core::analyzer::structural::regex::facts_to_embedded(
        facts,
        &decoded.chars,
        decoded.source_range,
        source,
    )
}

fn parse_pattern(decoded: &DecodedValue, flags: RegexFlags, api: Api) -> Vec<Fact> {
    RegexParser::new(
        &decoded.value,
        flags,
        api.scans_from_each_offset,
        &PythonRegexSyntax,
    )
    .parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn public_string_value_decoder_decodes_escaped_format_braces() {
        let source = r#"value = "\x7b0\x7d""#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("parser returns a tree");
        let mut pending = vec![tree.root_node()];
        let mut string = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "string" {
                string = Some(node);
                break;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let string = string.expect("fixture contains a string expression");
        let mut cursor = string.walk();
        let parts = string
            .named_children(&mut cursor)
            .map(|child| (child.kind().to_owned(), node_text(child, source).to_owned()))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_python_string_value(string, source).expect("string literal decodes"),
            "{0}",
            "parts={parts:?}; string={}",
            string.to_sexp()
        );
    }

    fn embedded_for_source(source: &str) -> Vec<EmbeddedLeafFact> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("parser returns a tree");
        let root = tree.root_node();
        let mut pending = vec![root];
        let mut facts = module_assigned_facts(root, source);
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "call" | "string" | "concatenated_string") {
                facts.extend(embedded_facts(node, source));
            }
            let mut children = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                children.push(child);
            }
            pending.extend(children.into_iter().rev());
        }
        facts
    }

    #[hardwon(
        "#4874: bounded repetition cloned a fragment after concatenation linked its end outside"
    )]
    #[test]
    fn meshroom_assigned_regex_and_reduced_form_compile_without_incomplete_facts() {
        let patterns = [
            r"(?P<FILESTEM_PREFIX>.*?)(?P<FRAMEID_STR>[-._]\d+)?(?P<EXTENSION>\.\w{3,4})",
            r"(?P<run>a{3})",
        ];

        for pattern in patterns {
            let source = format!("import re\npattern = r\"{pattern}\"\nre.compile(pattern)\n");
            let facts = embedded_for_source(&source);
            assert!(
                facts
                    .iter()
                    .any(|fact| fact.kind == NormalizedKind::RegexPattern),
                "pattern={pattern:?}; facts={facts:#?}"
            );
            assert!(
                facts
                    .iter()
                    .all(|fact| fact.kind != NormalizedKind::RegexIncomplete),
                "pattern={pattern:?}; facts={facts:#?}"
            );
        }

        let unsupported = embedded_for_source(
            "import re\npattern = r\"(?P<anchored>^a)\"\nre.compile(pattern)\n",
        );
        assert!(
            unsupported.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexIncomplete
                    && fact.construct.as_deref() == Some("bad-tag-nfa-unsupported")
            }),
            "unsupported NFA construct must be explicit; facts={unsupported:#?}"
        );
    }

    #[hardwon(
        "#4650: Python regex facts missed byte patterns, nested assigned values, Unicode ranges, and ReDoS"
    )]
    #[test]
    fn codeql_regex_facts_cover_byte_values_assignments_and_safe_redos_controls() {
        let source = r####"import re
re.compile(br"[\b\t ]")
re.compile(b"[AA]")
re.compile(br"(P<name>[\w]+)")
re.compile(b" ^abc")
re.compile(b"(?s) ^abc")
re.compile(b"abc$ ")
re.compile(r"[A-z]")
re.compile(r"^[z-a]$")
re.compile(r"[0-93-5]")
re.compile(r"[0-9\d]")
re.compile('[\U0001D173-\U0001D17A\U000E0020-\U000E007F\U000e0001]')
re.compile(r"<script.*?>.*?</script>", re.I)
re.compile(r"<script.*?>.*?</script>", re.re.DOTALL)
re.compile(r"""(<[a-z\/!$]("[^"]*"|'[^']*'|[^'">])*>|<!(--.*?--\s*)+>)""", re.I)
VERBOSE_REGEX = r"""
        \[
        (?P<header>[^]]+)                  # very permissive!
        \]
        """
re.compile(VERBOSE_REGEX, re.VERBOSE)
re.compile(r"(a|.)*")
re.compile(r"(a|aa?)*b")
re.compile(r"^([a-z]+)+$")
MY_REG = r'X(\u0061|a)*Y'
def matcher(name):
    re.match(MY_REG, name)
def shadowed(name, MY_REG):
    re.match(MY_REG, name)
re.compile(r"((.|[^a])*)\"")
re.compile(r"((a|[^a])*)\"")
re.compile(r"(a+)+aaaaa*a+")
"####;
        let facts = embedded_for_source(source);
        let has = |kind| facts.iter().any(|fact| fact.kind == kind);
        assert!(has(NormalizedKind::RegexRiskBackspaceEscape), "{facts:#?}");
        assert!(
            has(NormalizedKind::RegexRiskDuplicateClassCharacter),
            "{facts:#?}"
        );
        assert!(
            has(NormalizedKind::RegexRiskIncompleteSpecialGroup),
            "{facts:#?}"
        );
        assert!(has(NormalizedKind::RegexRiskUnmatchableCaret), "{facts:#?}");
        assert!(
            has(NormalizedKind::RegexRiskUnmatchableDollar),
            "{facts:#?}"
        );
        assert!(has(NormalizedKind::RegexRiskRange), "{facts:#?}");
        assert!(has(NormalizedKind::RegexRiskBadTag), "{facts:#?}");
        assert!(has(NormalizedKind::RegexRiskExponential), "{facts:#?}");
        let overlapping_range_start = source
            .find("[0-93-5]")
            .expect("overlapping range sample is present")
            + 1;
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskRange
                    && fact.range.start_byte == overlapping_range_start
                    && fact.range.end_byte == overlapping_range_start + 3
            }),
            "{facts:#?}"
        );
        let line_with = |needle: &str| {
            source
                .lines()
                .position(|line| line.contains(needle))
                .expect("regex fixture line is present")
                + 1
        };
        let risk_lines = facts
            .iter()
            .filter(|fact| fact.kind == NormalizedKind::RegexRiskExponential)
            .map(|fact| fact.range.start_line)
            .collect::<HashSet<_>>();
        assert!(risk_lines.contains(&line_with("^([a-z]+)+$")), "{facts:#?}");
        assert!(risk_lines.contains(&line_with("MY_REG =")), "{facts:#?}");
        assert!(risk_lines.contains(&line_with("((.|[^a])*)")), "{facts:#?}");
        assert!(
            !risk_lines.contains(&line_with("((a|[^a])*)")),
            "{facts:#?}"
        );
        assert!(!risk_lines.contains(&line_with("aaaaa*a+")), "{facts:#?}");
        let shadowed_line = source
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                line.contains("re.match(MY_REG, name)").then_some(index + 1)
            })
            .last()
            .expect("shadowed pattern reference is present");
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexIncomplete
                    && fact.range.start_line == shadowed_line
                    && fact
                        .construct
                        .as_deref()
                        .is_some_and(|reason| reason.starts_with("dynamic-pattern:"))
            }),
            "{facts:#?}"
        );
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskRange
                    && fact.range.start_line == line_with("U0001D173")
            }),
            "{facts:#?}"
        );
        assert!(
            !facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskDuplicateClassCharacter
                    && fact.range.start_line == line_with("VERBOSE_REGEX =")
            }),
            "{facts:#?}"
        );
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskBadTag
                    && fact.range.start_line == line_with("<[a-z")
            }),
            "{facts:#?}"
        );
        let nested_flag_line = source
            .lines()
            .position(|line| line.contains("re.re.DOTALL"))
            .expect("upstream nested DOTALL flag case is present")
            + 1;
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexRiskBadTag
                && fact.range.start_line == nested_flag_line
        }));
        let safe_line = source
            .lines()
            .position(|line| line.contains("(a|.)*"))
            .expect("safe redos control is present")
            + 1;
        assert!(!facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexRiskExponential && fact.range.start_line == safe_line
        }));
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexPattern
                && fact
                    .construct
                    .as_deref()
                    .is_some_and(|pattern| pattern.contains("very permissive"))
        }));
    }

    #[test]
    fn decodes_python_unknown_escapes_and_adjacent_literals_before_regex_parse() {
        let source = r#"import re
re.compile("\d" "\." r"\.")
"#;
        let facts = embedded_for_source(source);
        let pattern = facts
            .iter()
            .find(|fact| fact.kind == NormalizedKind::RegexPattern)
            .expect("selected compile call has a regex pattern fact");
        assert_eq!(pattern.construct.as_deref(), Some(r"\d\.\."));
        assert!(
            facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexEscape)
        );
        assert!(
            !facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexIncomplete)
        );
    }

    #[test]
    fn selects_only_recognized_pattern_arguments_and_marks_dynamic_values_incomplete() {
        let source = r#"import re
re.compile("selected")
re.sub("replacement", "pattern", "subject")
other.compile("unrecognized")
re.compile(pattern)
"#;
        let facts = embedded_for_source(source);
        let patterns = facts
            .iter()
            .filter(|fact| fact.kind == NormalizedKind::RegexPattern)
            .map(|fact| fact.construct.as_deref().expect("pattern stores value"))
            .collect::<Vec<_>>();
        assert_eq!(patterns, ["selected", "replacement"]);
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexIncomplete
                && fact
                    .construct
                    .as_deref()
                    .is_some_and(|construct| construct.starts_with("dynamic-pattern:"))
        }));
        assert!(!patterns.contains(&"pattern"));
        assert!(!patterns.contains(&"subject"));
        assert!(!patterns.contains(&"unrecognized"));
    }

    #[test]
    fn supported_lookaround_groups_and_orphan_quantifiers_have_typed_facts() {
        let facts = embedded_for_source(
            "import re\nre.compile(r\"(?=lookahead)\")\nre.compile(r\"a$*\")\n",
        );
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexGroup
                && fact.construct.as_deref() == Some("lookahead-positive")
        }));
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexIncomplete
                && fact.construct.as_deref() == Some("quantifier-without-atom")
        }));
    }

    #[hardwon(
        "#4454: zero-width regex facts escaped their embedded parent and aborted workspace indexing"
    )]
    #[test]
    fn zero_width_regex_facts_stay_within_their_embedded_parents() {
        for (source, malformed) in [
            ("import re\nre.compile(r'^(v)(.*)()$')\n", false),
            ("import re\nre.subn(\"()\"r' am I'\"??\")\n", false),
            (
                "import re\nre.compile(r\"invalid literal for int().*: '?'?\")\n",
                false,
            ),
            ("import re\nre.compile(\"ab()+cd\")\n", false),
            ("import re\nre.sub('()x', r'\\g<0>\\g<0>', 'xx')\n", false),
            ("import re\nre.search('(', 'test')\n", true),
        ] {
            let facts = embedded_for_source(source);
            assert!(
                facts
                    .iter()
                    .any(|fact| fact.kind == NormalizedKind::RegexPattern),
                "source={source:?}; facts={facts:#?}"
            );
            for (fact_id, fact) in facts.iter().enumerate() {
                if let Some(parent) = fact.parent {
                    assert!(parent < fact_id, "source={source:?}; facts={facts:#?}");
                    let parent_fact = &facts[parent];
                    assert!(
                        parent_fact.range.start_byte <= fact.range.start_byte
                            && fact.range.end_byte <= parent_fact.range.end_byte,
                        "source={source:?}; fact={fact:#?}; parent={parent_fact:#?}"
                    );
                }
            }
            if !malformed {
                assert!(
                    facts.iter().any(|fact| {
                        fact.kind == NormalizedKind::RegexSequence
                            && fact.range.start_byte == fact.range.end_byte
                    }),
                    "source={source:?} retains its zero-width empty-group sequence; facts={facts:#?}"
                );
            }
            if malformed {
                assert!(
                    facts
                        .iter()
                        .any(|fact| fact.kind == NormalizedKind::RegexIncomplete),
                    "malformed pattern remains structurally unavailable; facts={facts:#?}"
                );
            }
        }
    }

    #[test]
    fn polynomial_redos_facts_cover_search_restarts_and_overlapping_repetitions() {
        for (source, expected) in [
            ("import re\nre.search(r'\\s+$', value)\n", true),
            ("import re\nre.search(r'^\\s+$', value)\n", false),
            ("import re\nre.search(r'^\\d+E?\\d+$', value)\n", true),
            ("import re\nre.search(r'^\\d+E\\d+$', value)\n", false),
            ("import re\nre.match(r'\\s+$', value)\n", false),
            ("import re\nre.compile(r'\\s+$')\n", false),
        ] {
            let facts = embedded_for_source(source);
            assert_eq!(
                facts
                    .iter()
                    .any(|fact| fact.kind == NormalizedKind::RegexRiskPolynomial),
                expected,
                "source={source:?}; facts={facts:#?}"
            );
        }
    }

    #[test]
    #[hardwon("#4443: an empty embedded regex sequence escaped its parent source range")]
    fn unquantified_empty_group_keeps_embedded_regex_facts_inside_parents() {
        let source = "import re\nre.search(r'function (no)?watchplus()', webpage)\n";
        let facts = embedded_for_source(source);
        assert!(
            facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexPattern)
        );
        for (index, fact) in facts.iter().enumerate() {
            if let Some(parent) = fact.parent {
                assert!(parent < index, "{fact:?}");
                let parent_fact = &facts[parent];
                assert!(
                    parent_fact.range.start_byte <= fact.range.start_byte
                        && fact.range.end_byte <= parent_fact.range.end_byte,
                    "child {fact:?} is outside parent {parent_fact:?}"
                );
            }
        }
        let closing_paren = source.find("()'").expect("trailing empty group") + 1;
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexSequence
                && fact.range.start_byte == closing_paren
                && fact.range.end_byte == closing_paren
        }));
    }
    #[test]
    fn qs6_regex_decoder_and_fact_budgets_keep_ranges_and_parent_links() {
        for (pattern, reason, fact_count) in [
            (
                "f'{dynamic}'".to_owned(),
                "formatted-string-interpolation",
                1,
            ),
            (
                format!("r'{}'", "a".repeat(8193)),
                "pattern-character-budget",
                1,
            ),
            (
                format!("r'{}'", "a|".repeat(2200) + "a"),
                "regex-fact-budget",
                3,
            ),
        ] {
            let prefix = "# \u{e9}\nimport re\nre.compile(";
            let source = format!("{prefix}{pattern})\n");
            let facts = embedded_for_source(&source);
            assert_eq!(facts.len(), fact_count, "reason={reason}; facts={facts:?}");
            let incomplete = facts
                .iter()
                .find(|fact| fact.kind == NormalizedKind::RegexIncomplete)
                .expect("limit explicitly reported");
            assert_eq!(
                incomplete.construct.as_deref(),
                Some(reason),
                "{incomplete:?}"
            );
            let expected = if fact_count == 1 {
                prefix.len()..prefix.len() + pattern.len()
            } else {
                prefix.len() + 2..prefix.len() + pattern.len() - 1
            };
            assert_eq!(
                incomplete.range.start_byte..incomplete.range.end_byte,
                expected
            );
            for (index, fact) in facts.iter().enumerate() {
                assert!(source.is_char_boundary(fact.range.start_byte));
                assert!(source.is_char_boundary(fact.range.end_byte));
                if let Some(parent) = fact.parent {
                    assert!(parent < index, "{facts:?}");
                    assert!(
                        facts[parent].range.start_byte <= fact.range.start_byte
                            && fact.range.end_byte <= facts[parent].range.end_byte,
                        "{facts:?}"
                    );
                }
            }
        }
        assert!(
            embedded_for_source("import re\nre.compile(r'ab')\n")
                .iter()
                .any(|f| f.kind == NormalizedKind::RegexPattern)
        );
    }

    #[test]
    fn qs6_integer_flags_have_radix_independent_semantics() {
        for (mask, complete) in [
            (0_u64, true),
            (2, true),
            (8, true),
            (16, true),
            (256, true),
            (282, true),
            (1, false),
            (64, false),
        ] {
            let mut reference = None;
            for digits in [
                mask.to_string(),
                format!("0x{mask:x}"),
                format!("0o{mask:o}"),
                format!("0b{mask:b}"),
            ] {
                // Python permits separators between digits in every radix.
                let (prefix, digits) = if digits.starts_with('0') && digits.len() > 1 {
                    digits.split_at(2)
                } else {
                    ("", digits.as_str())
                };
                let separated = digits
                    .chars()
                    .map(|ch| ch.to_string())
                    .collect::<Vec<_>>()
                    .join("_");
                let source = format!("import re\nre.compile(r'^a.\\w$', {prefix}{separated})\n");
                let tree = crate::declarations::parse_python_tree(&source).unwrap();
                let call = tree
                    .root_node()
                    .named_child(1)
                    .unwrap()
                    .named_child(0)
                    .unwrap();
                assert_eq!(call.kind(), "call");
                let integer = call
                    .child_by_field_name("arguments")
                    .unwrap()
                    .named_child(1)
                    .unwrap();
                assert_eq!(integer.kind(), "integer");
                assert_eq!(node_text(integer, &source), format!("{prefix}{separated}"));
                let api =
                    recognized_api(call.child_by_field_name("function").unwrap(), &source).unwrap();
                let flags = call_flags(call, api, &source);
                let expected = match mask {
                    2 => (true, false, false, false),
                    8 => (false, true, false, false),
                    16 => (false, false, true, false),
                    256 => (false, false, false, true),
                    282 => (true, true, true, true),
                    _ => (false, false, false, false),
                };
                assert_eq!(
                    (flags.ignorecase, flags.multiline, flags.dotall, flags.ascii),
                    expected
                );
                let facts = embedded_for_source(&source);
                assert!(
                    facts
                        .iter()
                        .any(|fact| fact.kind == NormalizedKind::RegexPattern)
                );
                assert_eq!(
                    !facts
                        .iter()
                        .any(|fact| fact.construct.as_deref() == Some("unsupported-regex-flags")),
                    complete,
                    "mask={mask}: {facts:?}"
                );
                let semantic = facts
                    .iter()
                    .map(|fact| (fact.kind, fact.parent, fact.construct.clone()))
                    .collect::<Vec<_>>();
                if let Some(reference) = &reference {
                    assert_eq!(&semantic, reference);
                } else {
                    reference = Some(semantic);
                }
            }
        }
        for overflow in [
            "18446744073709551616",
            "0x1_0000_0000_0000_0000",
            "0o2_0000_0000_0000_0000_0000_00",
            "0b1_0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let source = format!("import re\nre.compile('a', {overflow})\n");
            assert!(
                embedded_for_source(&source)
                    .iter()
                    .any(|fact| fact.construct.as_deref() == Some("unsupported-regex-flags")),
                "{overflow}"
            );
        }
    }
    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: ignored comments produced duplicate-class warnings"
    )]
    fn qs6_verbose_comments_are_ignored() {
        let facts = embedded_for_source("import re\nre.compile('[a] # xx', re.X)\n");
        assert!(
            facts
                .iter()
                .any(|f| f.kind == NormalizedKind::RegexCharacterClass)
        );
        assert!(
            !facts
                .iter()
                .any(|f| f.kind == NormalizedKind::RegexRiskDuplicateClassCharacter),
            "{facts:?}"
        );
    }

    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: group widths lost quantifiers and comment emptiness"
    )]
    fn qs6_group_width_anchor_regression() {
        for (pattern, risk) in [
            ("(a)*^", false),
            ("(a)?^", false),
            ("(a){0,3}^", false),
            ("(a)+^", true),
            ("(?#ignored)a^", true),
        ] {
            let facts = embedded_for_source(&format!("import re\nre.compile(r'{pattern}')\n"));
            assert_eq!(
                facts
                    .iter()
                    .any(|f| f.kind == NormalizedKind::RegexRiskUnmatchableCaret),
                risk,
                "{pattern}: {facts:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: optional clones lost HTML capture evidence"
    )]
    fn qs6_optional_captures_retain_bad_tag_evidence() {
        let facts = embedded_for_source("import re\nre.compile(r'(?:(<!--.*?--)|(<foo))?>')\n");
        assert!(
            facts
                .iter()
                .any(|f| f.kind == NormalizedKind::RegexRiskBadTag),
            "{facts:?}"
        );
    }

    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: multiple repetition operators were accepted"
    )]
    fn qs6_multiple_repeat_is_incomplete() {
        for pattern in ["a**", "a*+*", "(ab){2}{3}"] {
            let facts = embedded_for_source(&format!("import re\nre.compile(r'{pattern}')\n"));
            assert!(
                facts
                    .iter()
                    .any(|f| f.construct.as_deref() == Some("nested-quantifier")),
                "{pattern}: {facts:?}"
            );
        }
    }

    fn qs6_parse(pattern: &str) -> Vec<Fact> {
        let decoded = DecodedValue {
            value: pattern.to_owned(),
            chars: Vec::new(),
            source_range: Range {
                start_byte: 0,
                end_byte: pattern.len(),
                start_line: 1,
                end_line: 1,
            },
            is_bytes: false,
        };
        parse_pattern(
            &decoded,
            RegexFlags {
                dialect_flags: 0,
                dotall: false,
                multiline: false,
                ignorecase: false,
                ascii: false,
                verbose: false,
                complete: true,
            },
            Api {
                flags_position: 1,
                scans_from_each_offset: false,
            },
        )
    }

    // CPython re.match oracle, generated over every word through length three
    // on {a, b, A, newline}, plus repeat-limit boundary witnesses.
    #[test]
    fn qs6_cpython_prefix_language_corpus() {
        let samples = [
            "",
            "a",
            "b",
            "A",
            "\n",
            "aa",
            "ab",
            "aA",
            "a\n",
            "ba",
            "bb",
            "bA",
            "b\n",
            "Aa",
            "Ab",
            "AA",
            "A\n",
            "\na",
            "\nb",
            "\nA",
            "\n\n",
            "aaa",
            "aab",
            "aaA",
            "aa\n",
            "aba",
            "abb",
            "abA",
            "ab\n",
            "aAa",
            "aAb",
            "aAA",
            "aA\n",
            "a\na",
            "a\nb",
            "a\nA",
            "a\n\n",
            "baa",
            "bab",
            "baA",
            "ba\n",
            "bba",
            "bbb",
            "bbA",
            "bb\n",
            "bAa",
            "bAb",
            "bAA",
            "bA\n",
            "b\na",
            "b\nb",
            "b\nA",
            "b\n\n",
            "Aaa",
            "Aab",
            "AaA",
            "Aa\n",
            "Aba",
            "Abb",
            "AbA",
            "Ab\n",
            "AAa",
            "AAb",
            "AAA",
            "AA\n",
            "A\na",
            "A\nb",
            "A\nA",
            "A\n\n",
            "\naa",
            "\nab",
            "\naA",
            "\na\n",
            "\nba",
            "\nbb",
            "\nbA",
            "\nb\n",
            "\nAa",
            "\nAb",
            "\nAA",
            "\nA\n",
            "\n\na",
            "\n\nb",
            "\n\nA",
            "\n\n\n",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for (pattern, expected) in [
            (
                "a",
                "0100011110000000000001111111111111111000000000000000000000000000000000000000000000000111",
            ),
            (
                "b",
                "0010000001111000000000000000000000000111111111111111100000000000000000000000000000000000",
            ),
            (
                "[a]",
                "0100011110000000000001111111111111111000000000000000000000000000000000000000000000000111",
            ),
            (
                "[a-a]",
                "0100011110000000000001111111111111111000000000000000000000000000000000000000000000000111",
            ),
            (
                "[a-b]",
                "0110011111111000000001111111111111111111111111111111100000000000000000000000000000000111",
            ),
            (
                "[ab]",
                "0110011111111000000001111111111111111111111111111111100000000000000000000000000000000111",
            ),
            (
                "a?",
                "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                "ab?",
                "0100011110000000000001111111111111111000000000000000000000000000000000000000000000000111",
            ),
            (
                "a{0}",
                "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                "a{1}",
                "0100011110000000000001111111111111111000000000000000000000000000000000000000000000000111",
            ),
            (
                "a{3}",
                "0000000000000000000001000000000000000000000000000000000000000000000000000000000000000111",
            ),
            (
                "a{3,3}",
                "0000000000000000000001000000000000000000000000000000000000000000000000000000000000000111",
            ),
            (
                "a{2,3}",
                "0000010000000000000001111000000000000000000000000000000000000000000000000000000000000111",
            ),
            (
                "a{32}",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000011",
            ),
            (
                ".",
                "0111011111111111100001111111111111111111111111111111111111111111111110000000000000000111",
            ),
            (
                "(?s:.)",
                "0111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                "(?ai:a)",
                "0101011110000111100001111111111111111000000000000000011111111111111110000000000000000111",
            ),
            (
                "(?ai:A)",
                "0101011110000111100001111111111111111000000000000000011111111111111110000000000000000111",
            ),
            (
                "(?ai:[a-z])",
                "0111011111111111100001111111111111111111111111111111111111111111111110000000000000000111",
            ),
            (
                "(?ai:[A-Z])",
                "0111011111111111100001111111111111111111111111111111111111111111111110000000000000000111",
            ),
            (
                "(a|aa)",
                "0100011110000000000001111111111111111000000000000000000000000000000000000000000000000111",
            ),
            (
                "(?:ab|b)*",
                "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                "(?:a|b)+",
                "0110011111111000000001111111111111111111111111111111100000000000000000000000000000000111",
            ),
            (
                "a{0,2}b",
                "0010001001111000000000100111100000000111111111111111100000000000000000000000000000000000",
            ),
        ] {
            let facts = qs6_parse(pattern);
            assert!(
                !facts
                    .iter()
                    .any(|f| f.kind == NormalizedKind::RegexIncomplete),
                "{pattern}: {facts:?}"
            );
            let nfa = RegexNfa::compile(&facts, 0, None).unwrap();
            for (sample, expected) in samples.iter().zip(expected.bytes()) {
                assert_eq!(
                    nfa.match_prefix_capture_groups(sample).0,
                    expected == b'1',
                    "{pattern:?} on {sample:?}"
                );
            }
        }
    }

    #[test]
    fn qs6_literal_grammar_and_mapping_corpus() {
        // CPython ast.literal_eval values, preserving each grammar-selected
        // literal's source mapping rather than searching the source for syntax.
        for (literal, expected) in [
            (r"'\u0061'", "a"),
            (r"'\U00000061'", "a"),
            (r"b'\x61'", "a"),
            (r"b'\n'", "\n"),
            (r"r'\u0061'", r"\u0061"),
        ] {
            let tree = crate::declarations::parse_python_tree(literal).unwrap();
            let node = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap();
            assert_eq!(node.kind(), "string");
            let decoded = decode_string_literal(node, literal).unwrap();
            assert_eq!(decoded.value, expected, "{literal}");
        }
        for count in [8191, 8192, 8193] {
            let source = format!("rf'{}{{value}}'", "a".repeat(count));
            let tree = crate::declarations::parse_python_tree(&source).unwrap();
            let node = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap();
            let result = decode_python_fstring_literal_segments(node, &source);
            if count <= 8192 {
                assert_eq!(result.unwrap(), ["a".repeat(count), String::new()]);
            } else {
                assert_eq!(result, Err("pattern-character-budget"));
            }
        }
        for source in [
            "import re\nre.compile(r'''a\nb''')\n",
            "import re\nre.compile('a' '\\n' 'b')\n",
        ] {
            let facts = embedded_for_source(source);
            assert!(facts.iter().any(|f| f.kind == NormalizedKind::RegexLiteral));
            for fact in facts {
                let range = fact.range;
                assert_eq!(
                    range.start_line,
                    source[..range.start_byte]
                        .bytes()
                        .filter(|b| *b == b'\n')
                        .count()
                        + 1
                );
                assert_eq!(
                    range.end_line,
                    source[..range.end_byte.saturating_sub(1).max(range.start_byte)]
                        .bytes()
                        .filter(|b| *b == b'\n')
                        .count()
                        + 1
                );
            }
        }
    }
    #[test]
    fn qs6_anchor_and_redos_fact_corpus() {
        // Safe/unsafe controls follow zero-width assertion semantics and
        // whether a rejecting suffix forces enumeration of ambiguous partitions.
        for (pattern, flags, caret, dollar, exponential) in [
            ("^^a", "0", false, false, false),
            ("a$$", "0", false, false, false),
            ("(?=a)^a", "0", false, false, false),
            ("a^", "0", true, false, false),
            ("(|a)^", "0", false, false, false),
            ("(a|)^", "0", false, false, false),
            ("a$z", "0", false, true, false),
            (r"a\n^b", "re.M", false, false, false),
            ("([ab]+)+[a-b]+", "0", false, false, false),
            ("([a-b]+)+[a-b]+", "0", false, false, false),
            ("(a|aa)*(?=b)", "0", false, false, true),
            ("(a|aa)*(?=bb)", "0", false, false, true),
            ("(a|aa)*", "0", false, false, false),
        ] {
            let facts =
                embedded_for_source(&format!("import re\nre.compile(r'{pattern}', {flags})\n"));
            let has = |kind| facts.iter().any(|f| f.kind == kind);
            assert!(has(NormalizedKind::RegexPattern));
            assert!(
                !has(NormalizedKind::RegexIncomplete),
                "{pattern}: {facts:?}"
            );
            assert_eq!(
                (
                    has(NormalizedKind::RegexRiskUnmatchableCaret),
                    has(NormalizedKind::RegexRiskUnmatchableDollar),
                    has(NormalizedKind::RegexRiskExponential)
                ),
                (caret, dollar, exponential),
                "{pattern}: {facts:?}"
            );
        }
        for pattern in ["(ab)", "(^ab)", "(?:ab)"] {
            let facts = qs6_parse(pattern);
            let group = facts
                .iter()
                .find(|f| f.kind == NormalizedKind::RegexGroup)
                .unwrap();
            let first = group.first_set.as_ref().unwrap();
            assert!(first.contains('a'));
            assert!(!first.contains('b'), "{pattern}: {facts:?}");
        }
        for (pattern, broad) in [
            ("[:-B]", false),
            ("[:-C]", true),
            ("[:-D]", true),
            ("[A-Z]", false),
            ("[0-?]", false),
        ] {
            let facts = embedded_for_source(&format!("import re\nre.compile(r'{pattern}')\n"));
            assert_eq!(
                facts
                    .iter()
                    .any(|f| f.kind == NormalizedKind::RegexRiskRange),
                broad,
                "{pattern}: {facts:?}"
            );
        }
    }

    #[test]
    fn qs6_selected_arguments_and_invalid_token_spans() {
        let source = "import re\nre.compile(pattern='a')\nre.search(string='subject', pattern='b')\nre.compile(other='unselected')\nre.sub('c', 'replacement', 'subject')\n";
        let facts = embedded_for_source(source);
        assert_eq!(
            facts
                .iter()
                .filter(|f| f.kind == NormalizedKind::RegexPattern)
                .map(|f| f.construct.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
        for pattern in ["a|*", "a|+", "a|?", "(?P=name)", "a(?P=name)", "(abc"] {
            let prefix = "import re\nre.compile(r'";
            let source = format!("{prefix}{pattern}')\n");
            let facts = embedded_for_source(&source);
            let incomplete = facts
                .iter()
                .find(|f| f.kind == NormalizedKind::RegexIncomplete)
                .unwrap();
            let expected_start = if pattern.starts_with("a|") {
                2
            } else if pattern == "a(?P=name)" {
                1
            } else {
                0
            };
            let expected_end = if pattern.starts_with("a|") || pattern == "(?P=name)" {
                3
            } else if pattern == "a(?P=name)" {
                4
            } else {
                pattern.len()
            };
            assert_eq!(
                incomplete.range.start_byte..incomplete.range.end_byte,
                prefix.len() + expected_start..prefix.len() + expected_end,
                "{pattern}: {facts:?}"
            );
            // The public fact stream traverses siblings in lexical source order.
            for parent in 0..facts.len() {
                let children = facts
                    .iter()
                    .filter(|f| f.parent == Some(parent))
                    .map(|f| f.range.start_byte)
                    .collect::<Vec<_>>();
                assert!(
                    children.windows(2).all(|w| w[0] <= w[1]),
                    "{pattern}: {facts:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: scoped flags could not start by disabling a flag"
    )]
    fn qs6_scoped_flags_can_disable_without_enabling() {
        for pattern in ["(?i:a)(?-i:b)", "(?-i:ab)"] {
            let facts = qs6_parse(pattern);
            assert!(
                !facts
                    .iter()
                    .any(|f| f.kind == NormalizedKind::RegexIncomplete),
                "{facts:?}"
            );
            let nfa = RegexNfa::compile(&facts, 0, None).unwrap();
            assert!(nfa.match_prefix_capture_groups("ab").0);
            assert!(!nfa.match_prefix_capture_groups("aB").0);
        }
        for pattern in ["(?-a:a)", "(?-u:a)", "(?-i)", "(?i-:a)"] {
            let facts = qs6_parse(pattern);
            assert!(
                facts
                    .iter()
                    .any(|f| f.construct.as_deref() == Some("invalid-inline-flags")),
                "{pattern}: {facts:?}"
            );
        }
    }
}
