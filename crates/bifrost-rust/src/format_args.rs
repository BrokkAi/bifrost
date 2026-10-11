//! Structured parsing helpers for Rust's standard formatting macro arguments.
//!
//! The macro token tree itself is opaque to tree-sitter. This module wraps its
//! exact interior in a temporary ordinary function call and asks tree-sitter
//! for argument expression ranges; it never splits tokens or source text.

use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustFormattingMacro {
    Format,
    FormatArgs,
    Print,
    Println,
    Eprint,
    Eprintln,
    Write,
    Writeln,
    Panic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustValueMacro {
    Assert,
    AssertEq,
    AssertNe,
    DebugAssert,
    DebugAssertEq,
    DebugAssertNe,
    Panic,
    Unreachable,
    Todo,
    Unimplemented,
    Dbg,
    Matches,
    Vec,
}

pub fn rust_value_macro(name: &str) -> Option<RustValueMacro> {
    match name {
        "assert" => Some(RustValueMacro::Assert),
        "assert_eq" => Some(RustValueMacro::AssertEq),
        "assert_ne" => Some(RustValueMacro::AssertNe),
        "debug_assert" => Some(RustValueMacro::DebugAssert),
        "debug_assert_eq" => Some(RustValueMacro::DebugAssertEq),
        "debug_assert_ne" => Some(RustValueMacro::DebugAssertNe),
        "panic" => Some(RustValueMacro::Panic),
        "unreachable" => Some(RustValueMacro::Unreachable),
        "todo" => Some(RustValueMacro::Todo),
        "unimplemented" => Some(RustValueMacro::Unimplemented),
        "dbg" => Some(RustValueMacro::Dbg),
        "matches" => Some(RustValueMacro::Matches),
        "vec" => Some(RustValueMacro::Vec),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustVecMacroArguments {
    Elements(Vec<RustFormatMacroArgument>),
    Repeated(Box<RustVecMacroRepeatedArguments>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustVecMacroRepeatedArguments {
    pub element: RustFormatMacroArgument,
    pub count: RustFormatMacroArgument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustLoggingMacro {
    Log,
}

/// Classify only reviewed, qualified logging macro names. Callers still have
/// to resolve the structured Rust path and reject a shadowed crate root.
pub fn rust_logging_macro(owner: &str, member: &str) -> Option<RustLoggingMacro> {
    match owner {
        "log"
            if matches!(
                member,
                "log" | "error" | "warn" | "info" | "debug" | "trace"
            ) =>
        {
            Some(RustLoggingMacro::Log)
        }
        _ => None,
    }
}

impl RustFormattingMacro {
    pub const fn has_writer_receiver(self) -> bool {
        matches!(self, Self::Write | Self::Writeln)
    }
}

/// Classify only the final AST path segment's formatting grammar candidate.
/// This is a parsing gate; macro identity is still resolved by query dispatch.
pub fn rust_formatting_macro(name: &str) -> Option<RustFormattingMacro> {
    match name {
        "format" => Some(RustFormattingMacro::Format),
        "format_args" => Some(RustFormattingMacro::FormatArgs),
        "print" => Some(RustFormattingMacro::Print),
        "println" => Some(RustFormattingMacro::Println),
        "eprint" => Some(RustFormattingMacro::Eprint),
        "eprintln" => Some(RustFormattingMacro::Eprintln),
        "write" => Some(RustFormattingMacro::Write),
        "writeln" => Some(RustFormattingMacro::Writeln),
        "panic" => Some(RustFormattingMacro::Panic),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustFormatMacroArgument {
    /// Full source range of the written argument, including `name =` when it
    /// is a named formatting argument.
    pub range: tree_sitter::Range,
    /// Source range whose expression value is passed to the formatting macro.
    pub value_range: tree_sitter::Range,
    /// Identifier-expression spans inside the value. Consumers resolve each
    /// against lexical facts at its own source position; this also exposes the
    /// inputs of compound expressions without text-scanning the macro body.
    pub binding_ranges: Box<[tree_sitter::Range]>,
    /// Name from the structured `name = expression` grammar, when present.
    pub name: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustFormatMacroArgumentsError {
    MissingTokenTree,
    InvalidTokenTree,
    InvalidExpressionList,
}

/// Parse a macro token-tree interior as Rust call arguments and return the
/// original-source spans of each expression. The source ranges originate in
/// the macro invocation's tree-sitter delimiter nodes; the temporary wrapper
/// supplies only the grammar context needed to parse its comma-separated
/// expressions.
pub fn rust_format_macro_arguments(
    invocation: Node<'_>,
    source: &str,
) -> Result<Vec<RustFormatMacroArgument>, RustFormatMacroArgumentsError> {
    let prefix = "fn __bifrost_format_arguments() { let _ = __bifrost_args(";
    let parsed = parse_macro_token_tree(invocation, source, prefix, "); }")?;
    if parsed.tree.root_node().has_error() {
        return Err(RustFormatMacroArgumentsError::InvalidExpressionList);
    }
    let call = find_wrapped_argument_call(parsed.tree.root_node())
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let arguments = call
        .child_by_field_name("arguments")
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    macro_arguments(
        arguments,
        &parsed.wrapped,
        parsed.prefix_bytes,
        parsed.interior,
    )
}

/// Return a matches! scrutinee even when the pattern that follows it is not a
/// Rust expression (for example `_`). The first expression and its top-level
/// comma are still selected by tree-sitter from the same argument wrapper used
/// for formatting macros.
pub fn rust_matches_macro_scrutinee(
    invocation: Node<'_>,
    source: &str,
) -> Result<RustFormatMacroArgument, RustFormatMacroArgumentsError> {
    let prefix = "fn __bifrost_matches_argument() { let _ = __bifrost_args(";
    let parsed = parse_macro_token_tree(invocation, source, prefix, "); }")?;
    let call = find_wrapped_argument_call(parsed.tree.root_node())
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let arguments = call
        .child_by_field_name("arguments")
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let mut cursor = arguments.walk();
    let first = arguments
        .named_children(&mut cursor)
        .find(|argument| !matches!(argument.kind(), "line_comment" | "block_comment"))
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let has_top_level_comma = (0..arguments.child_count()).any(|index| {
        arguments
            .child(index)
            .is_some_and(|child| child.kind() == "," && child.start_byte() >= first.end_byte())
    });
    if first.has_error() || !has_top_level_comma {
        return Err(RustFormatMacroArgumentsError::InvalidExpressionList);
    }
    macro_argument(first, &parsed.wrapped, parsed.prefix_bytes, parsed.interior)
}

pub fn rust_vec_macro_arguments(
    invocation: Node<'_>,
    source: &str,
) -> Result<RustVecMacroArguments, RustFormatMacroArgumentsError> {
    let prefix = "fn __bifrost_vec_argument() { let _ = [";
    let parsed = parse_macro_token_tree(invocation, source, prefix, "]; }")?;
    if parsed.tree.root_node().has_error() {
        return Err(RustFormatMacroArgumentsError::InvalidExpressionList);
    }
    let array = find_wrapped_array_expression(parsed.tree.root_node(), prefix.len() - 1)
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let mut cursor = array.walk();
    let mut children = array
        .named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "line_comment" | "block_comment"));
    if contains_direct_child(&array, ";") {
        let element = children
            .next()
            .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
        let count = children
            .next()
            .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
        if children.next().is_some() {
            return Err(RustFormatMacroArgumentsError::InvalidExpressionList);
        }
        return Ok(RustVecMacroArguments::Repeated(Box::new(
            RustVecMacroRepeatedArguments {
                element: macro_argument(
                    element,
                    &parsed.wrapped,
                    parsed.prefix_bytes,
                    parsed.interior,
                )?,
                count: macro_argument(
                    count,
                    &parsed.wrapped,
                    parsed.prefix_bytes,
                    parsed.interior,
                )?,
            },
        )));
    }
    let mut output = Vec::new();
    for child in children {
        output.push(macro_argument(
            child,
            &parsed.wrapped,
            parsed.prefix_bytes,
            parsed.interior,
        )?);
    }
    Ok(RustVecMacroArguments::Elements(output))
}

struct ParsedMacroTokenTree {
    tree: tree_sitter::Tree,
    wrapped: String,
    prefix_bytes: usize,
    interior: tree_sitter::Range,
}

fn parse_macro_token_tree(
    invocation: Node<'_>,
    source: &str,
    prefix: &str,
    suffix: &str,
) -> Result<ParsedMacroTokenTree, RustFormatMacroArgumentsError> {
    if invocation.kind() != "macro_invocation" {
        return Err(RustFormatMacroArgumentsError::MissingTokenTree);
    }
    let token_tree = invocation
        .child_by_field_name("arguments")
        .or_else(|| {
            let mut cursor = invocation.walk();
            invocation
                .named_children(&mut cursor)
                .find(|child| child.kind() == "token_tree")
        })
        .ok_or(RustFormatMacroArgumentsError::MissingTokenTree)?;
    let interior = crate::declarations::rust_macro_token_tree_interior(token_tree)
        .ok_or(RustFormatMacroArgumentsError::InvalidTokenTree)?;
    let fragment = source
        .get(interior.start_byte..interior.end_byte)
        .ok_or(RustFormatMacroArgumentsError::InvalidTokenTree)?;
    let mut wrapped = String::with_capacity(prefix.len() + fragment.len() + suffix.len());
    wrapped.push_str(prefix);
    wrapped.push_str(fragment);
    wrapped.push_str(suffix);
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust grammar is available");
    let tree = parser
        .parse(&wrapped, None)
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    Ok(ParsedMacroTokenTree {
        tree,
        wrapped,
        prefix_bytes: prefix.len(),
        interior,
    })
}

fn macro_arguments(
    arguments: Node<'_>,
    wrapped: &str,
    prefix_bytes: usize,
    interior: tree_sitter::Range,
) -> Result<Vec<RustFormatMacroArgument>, RustFormatMacroArgumentsError> {
    let mut output = Vec::new();
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if matches!(argument.kind(), "line_comment" | "block_comment") {
            continue;
        }
        output.push(macro_argument(argument, wrapped, prefix_bytes, interior)?);
    }
    Ok(output)
}

fn macro_argument(
    argument: Node<'_>,
    wrapped: &str,
    prefix_bytes: usize,
    interior: tree_sitter::Range,
) -> Result<RustFormatMacroArgument, RustFormatMacroArgumentsError> {
    let (value, name) = named_argument_value(argument, wrapped);
    let binding_ranges = expression_binding_ranges(value, prefix_bytes, interior)?;
    Ok(RustFormatMacroArgument {
        range: original_range(argument, prefix_bytes, interior)?,
        value_range: original_range(value, prefix_bytes, interior)?,
        binding_ranges: binding_ranges.into_boxed_slice(),
        name,
    })
}

fn find_wrapped_array_expression(root: Node<'_>, start_byte: usize) -> Option<Node<'_>> {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "array_expression" && node.start_byte() == start_byte {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    None
}

fn contains_direct_child(node: &Node<'_>, kind: &str) -> bool {
    (0..node.child_count()).any(|index| node.child(index).is_some_and(|child| child.kind() == kind))
}

fn expression_binding_ranges(
    expression: Node<'_>,
    prefix_bytes: usize,
    interior: tree_sitter::Range,
) -> Result<Vec<tree_sitter::Range>, RustFormatMacroArgumentsError> {
    let mut ranges = Vec::new();
    let mut pending = vec![expression];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "identifier" | "self")
            && !node.parent().is_some_and(|parent| {
                parent.kind() == "field_expression"
                    && parent.child_by_field_name("field") == Some(node)
            })
        {
            ranges.push(original_range(node, prefix_bytes, interior)?);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    ranges.sort_by_key(|range| range.start_byte);
    ranges.dedup();
    Ok(ranges)
}

fn original_range(
    node: Node<'_>,
    prefix_bytes: usize,
    interior: tree_sitter::Range,
) -> Result<tree_sitter::Range, RustFormatMacroArgumentsError> {
    let start = node
        .start_byte()
        .checked_sub(prefix_bytes)
        .and_then(|start| start.checked_add(interior.start_byte))
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let end = node
        .end_byte()
        .checked_sub(prefix_bytes)
        .and_then(|end| end.checked_add(interior.start_byte))
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    let translate_point = |point: tree_sitter::Point| {
        let row_offset = point.row;
        let column = if row_offset == 0 {
            point.column.checked_sub(prefix_bytes)?
        } else {
            point.column
        };
        Some(tree_sitter::Point {
            row: interior.start_point.row.checked_add(row_offset)?,
            column: if row_offset == 0 {
                interior.start_point.column.checked_add(column)?
            } else {
                column
            },
        })
    };
    Ok(tree_sitter::Range {
        start_byte: start,
        end_byte: end,
        start_point: translate_point(node.start_position())
            .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?,
        end_point: translate_point(node.end_position())
            .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?,
    })
}

fn named_argument_value<'tree>(
    argument: Node<'tree>,
    wrapped: &str,
) -> (Node<'tree>, Option<Box<str>>) {
    if argument.kind() == "assignment_expression"
        && let (Some(left), Some(right)) = (
            argument.child_by_field_name("left"),
            argument.child_by_field_name("right"),
        )
        && left.kind() == "identifier"
        && let Some(name) = wrapped.get(left.byte_range())
    {
        return (right, Some(name.trim_start_matches("r#").into()));
    }
    if argument.kind() == "labeled_expression"
        && let (Some(label), Some(body)) = (
            argument.child_by_field_name("label"),
            argument.child_by_field_name("body"),
        )
        && label.kind() == "identifier"
        && let Some(name) = wrapped.get(label.byte_range())
    {
        return (body, Some(name.trim_start_matches("r#").into()));
    }
    (argument, None)
}

fn find_wrapped_argument_call(root: Node<'_>) -> Option<Node<'_>> {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|function| function.kind() == "identifier")
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustFormatArgumentReference {
    Implicit,
    Index(usize),
    Name(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustFormatString {
    /// Every positional, named, and captured operand referenced by the format
    /// string, in source order. The first entry in each placeholder is its
    /// formatted value; following entries are dynamic width/precision values.
    pub references: Box<[RustFormatArgumentReference]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustFormatStringError {
    pub byte_offset: usize,
}

/// Parse decoded contents of a Rust format string using the documented
/// `std::fmt` placeholder grammar. This validates placeholder and format-spec
/// syntax while returning the value, dynamic width, and dynamic precision
/// argument references needed by semantic lowering.
pub fn parse_rust_format_string(format: &str) -> Result<RustFormatString, RustFormatStringError> {
    let chars = format.chars().collect::<Vec<_>>();
    let mut cursor = 0;
    let mut references = Vec::new();
    let mut byte_offset = Vec::with_capacity(chars.len() + 1);
    let mut bytes = 0;
    for character in &chars {
        byte_offset.push(bytes);
        bytes += character.len_utf8();
    }
    byte_offset.push(bytes);
    while cursor < chars.len() {
        match chars[cursor] {
            '{' if chars.get(cursor + 1) == Some(&'{') => cursor += 2,
            '}' if chars.get(cursor + 1) == Some(&'}') => cursor += 2,
            '{' => {
                cursor += 1;
                parse_placeholder(&chars, &byte_offset, &mut cursor, &mut references)?;
            }
            '}' => return Err(format_error(&byte_offset, cursor)),
            _ => cursor += 1,
        }
    }
    Ok(RustFormatString {
        references: references.into_boxed_slice(),
    })
}

fn parse_placeholder(
    chars: &[char],
    byte_offset: &[usize],
    cursor: &mut usize,
    references: &mut Vec<RustFormatArgumentReference>,
) -> Result<(), RustFormatStringError> {
    let start = *cursor;
    while *cursor < chars.len() && !matches!(chars[*cursor], ':' | '}') {
        *cursor += 1;
    }
    let argument = &chars[start..*cursor];
    push_argument_reference(argument, byte_offset, start, references)?;
    if chars.get(*cursor) == Some(&':') {
        *cursor += 1;
        parse_format_spec(chars, byte_offset, cursor, references)?;
    }
    if chars.get(*cursor) != Some(&'}') {
        return Err(format_error(byte_offset, *cursor));
    }
    *cursor += 1;
    Ok(())
}

fn parse_format_spec(
    chars: &[char],
    byte_offset: &[usize],
    cursor: &mut usize,
    references: &mut Vec<RustFormatArgumentReference>,
) -> Result<(), RustFormatStringError> {
    let end = chars[*cursor..]
        .iter()
        .position(|character| *character == '}')
        .map(|offset| *cursor + offset)
        .ok_or_else(|| format_error(byte_offset, *cursor))?;
    let spec = &chars[*cursor..end];
    let mut index = 0;

    if spec.len() >= 2 && is_alignment(spec[1]) && !matches!(spec[0], '{' | '}') {
        index = 2;
    } else if spec
        .first()
        .is_some_and(|character| is_alignment(*character))
    {
        index = 1;
    }
    if spec
        .get(index)
        .is_some_and(|character| matches!(character, '+' | '-'))
    {
        index += 1;
    }
    if spec.get(index) == Some(&'#') {
        index += 1;
    }
    if spec.get(index) == Some(&'0') {
        index += 1;
    }

    let width_start = index;
    while spec
        .get(index)
        .is_some_and(|character| character.is_ascii_digit())
    {
        index += 1;
    }
    if spec.get(index) == Some(&'$') {
        push_argument_reference(
            &spec[width_start..index],
            byte_offset,
            *cursor + width_start,
            references,
        )?;
        index += 1;
    } else if index == width_start
        && let Some(width_end) = named_dynamic_reference(spec, index)
    {
        push_argument_reference(
            &spec[index..width_end],
            byte_offset,
            *cursor + index,
            references,
        )?;
        index = width_end + 1;
    }

    if spec.get(index) == Some(&'.') {
        index += 1;
        if spec.get(index) == Some(&'*') {
            references.push(RustFormatArgumentReference::Implicit);
            index += 1;
        } else {
            let precision_start = index;
            while spec
                .get(index)
                .is_some_and(|character| character.is_ascii_digit())
            {
                index += 1;
            }
            if spec.get(index) == Some(&'$') {
                push_argument_reference(
                    &spec[precision_start..index],
                    byte_offset,
                    *cursor + precision_start,
                    references,
                )?;
                index += 1;
            } else if let Some(precision_end) = named_dynamic_reference(spec, index) {
                push_argument_reference(
                    &spec[index..precision_end],
                    byte_offset,
                    *cursor + index,
                    references,
                )?;
                index = precision_end + 1;
            } else if index == precision_start {
                return Err(format_error(byte_offset, *cursor + index));
            }
        }
    }

    if index < spec.len() {
        let type_spec = &spec[index..];
        let supported = [
            "?", "x?", "X?", "o?", "b?", "p", "b", "o", "x", "X", "e", "E",
        ];
        if !supported
            .iter()
            .any(|candidate| candidate.chars().eq(type_spec.iter().copied()))
        {
            return Err(format_error(byte_offset, *cursor + index));
        }
    }
    *cursor = end;
    Ok(())
}

fn named_dynamic_reference(spec: &[char], start: usize) -> Option<usize> {
    let mut end = start;
    if spec.get(end) == Some(&'r') && spec.get(end + 1) == Some(&'#') {
        end += 2;
    }
    let first = *spec.get(end)?;
    if !is_identifier_start(first) {
        return None;
    }
    end += 1;
    while spec
        .get(end)
        .is_some_and(|character| is_identifier_continue(*character))
    {
        end += 1;
    }
    (spec.get(end) == Some(&'$')).then_some(end)
}

fn push_argument_reference(
    argument: &[char],
    byte_offset: &[usize],
    start: usize,
    references: &mut Vec<RustFormatArgumentReference>,
) -> Result<(), RustFormatStringError> {
    if argument.is_empty() {
        references.push(RustFormatArgumentReference::Implicit);
    } else if argument.iter().all(|character| character.is_ascii_digit()) {
        let digits = argument.iter().collect::<String>();
        let index = digits
            .parse()
            .map_err(|_| format_error(byte_offset, start))?;
        references.push(RustFormatArgumentReference::Index(index));
    } else {
        let name = argument.iter().copied().collect::<String>();
        if !is_identifier(&name) {
            return Err(format_error(byte_offset, start));
        }
        references.push(RustFormatArgumentReference::Name(
            name.trim_start_matches("r#").into(),
        ));
    }
    Ok(())
}

fn is_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    let first = if name.starts_with("r#") {
        characters.next();
        characters.next();
        characters.next()
    } else {
        characters.next()
    };
    first.is_some_and(is_identifier_start) && characters.all(is_identifier_continue)
}

const fn is_alignment(character: char) -> bool {
    matches!(character, '<' | '^' | '>')
}

fn is_identifier_start(character: char) -> bool {
    character == '_' || character.is_alphabetic()
}

fn is_identifier_continue(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}

fn format_error(byte_offset: &[usize], character: usize) -> RustFormatStringError {
    RustFormatStringError {
        byte_offset: byte_offset
            .get(character)
            .copied()
            .unwrap_or_else(|| byte_offset.last().copied().unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Tree;

    fn parse_rust(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        parser.parse(source, None).expect("Rust tree")
    }

    fn string_literal<'tree>(root: Node<'tree>) -> Node<'tree> {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "string_literal" | "raw_string_literal") {
                return node;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        panic!("format string literal expected")
    }

    fn macro_invocation_named<'tree>(root: Node<'tree>, source: &str, name: &str) -> Node<'tree> {
        let mut pending = vec![root];
        let mut earliest = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "macro_invocation"
                && node
                    .child_by_field_name("macro")
                    .and_then(|path| source.get(path.byte_range()))
                    .is_some_and(|path| path == name)
                && earliest.is_none_or(|found: Node<'_>| node.start_byte() < found.start_byte())
            {
                earliest = Some(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        earliest.unwrap_or_else(|| panic!("expected {name}! invocation"))
    }

    #[test]
    fn escaped_braces_are_literals_and_do_not_add_references() {
        let parsed = parse_rust_format_string("{{column}} = {name}").expect("valid format");
        assert_eq!(
            parsed.references.as_ref(),
            [RustFormatArgumentReference::Name("name".into())]
        );
    }

    #[test]
    fn implicit_positional_and_named_references_are_preserved_in_order() {
        let parsed = parse_rust_format_string("{} {2} {column}").expect("valid format");
        assert_eq!(
            parsed.references.as_ref(),
            [
                RustFormatArgumentReference::Implicit,
                RustFormatArgumentReference::Index(2),
                RustFormatArgumentReference::Name("column".into()),
            ]
        );
    }

    #[test]
    fn dynamic_width_and_precision_arguments_are_collected() {
        let parsed =
            parse_rust_format_string("{value:>width$.precision$}").expect("valid dynamic format");
        assert_eq!(
            parsed.references.as_ref(),
            [
                RustFormatArgumentReference::Name("value".into()),
                RustFormatArgumentReference::Name("width".into()),
                RustFormatArgumentReference::Name("precision".into()),
            ]
        );
        let implicit = parse_rust_format_string("{value:.*}").expect("implicit precision");
        assert_eq!(
            implicit.references.as_ref(),
            [
                RustFormatArgumentReference::Name("value".into()),
                RustFormatArgumentReference::Implicit,
            ]
        );
    }

    #[test]
    fn raw_string_literal_is_decoded_before_parsing() {
        let source = r##"const F: &str = r#"{{x}} {value:?}"#;"##;
        let tree = parse_rust(source);
        let literal = string_literal(tree.root_node());
        let decoded = crate::cargo_routes::rust_static_string_literal(literal, source)
            .expect("raw literal decode");
        let parsed = parse_rust_format_string(&decoded).expect("format string");
        assert_eq!(
            parsed.references.as_ref(),
            [RustFormatArgumentReference::Name("value".into())]
        );
    }

    #[test]
    fn malformed_braces_and_format_specs_are_incomplete() {
        for source in ["{value", "value}", "{value:.}", "{value:q}", "{bad-name}"] {
            assert!(
                parse_rust_format_string(source).is_err(),
                "expected malformed format string to fail: {source}"
            );
        }
    }

    #[test]
    fn macro_argument_parser_returns_original_ranges_and_named_values() {
        let source = "fn f() { format!(\"{} {label}\", value, label = other); }";
        let tree = parse_rust(source);
        let mut pending = vec![tree.root_node()];
        let invocation = loop {
            let node = pending.pop().expect("macro invocation");
            if node.kind() == "macro_invocation" {
                break node;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        };
        let arguments = rust_format_macro_arguments(invocation, source).expect("args");
        assert_eq!(arguments.len(), 3);
        assert_eq!(
            &source[arguments[0].value_range.start_byte..arguments[0].value_range.end_byte],
            "\"{} {label}\""
        );
        assert_eq!(
            &source[arguments[1].value_range.start_byte..arguments[1].value_range.end_byte],
            "value"
        );
        assert_eq!(arguments[2].name.as_deref(), Some("label"));
        assert_eq!(
            &source[arguments[2].value_range.start_byte..arguments[2].value_range.end_byte],
            "other"
        );
        assert_eq!(arguments[1].binding_ranges.len(), 1);
        assert_eq!(
            &source[arguments[1].binding_ranges[0].start_byte
                ..arguments[1].binding_ranges[0].end_byte],
            "value"
        );
    }

    #[test]
    fn value_macro_arguments_keep_scrutinee_and_vector_element_ranges() {
        let source = "fn f(input: Option<u8>, item: String) { let _ = matches!(input, Some(_)); let _ = vec![item; 2]; let _ = vec![item, item]; }";
        let tree = parse_rust(source);

        let matches = macro_invocation_named(tree.root_node(), source, "matches");
        let scrutinee = rust_matches_macro_scrutinee(matches, source).expect("scrutinee");
        assert_eq!(
            &source[scrutinee.value_range.start_byte..scrutinee.value_range.end_byte],
            "input"
        );

        let repeated = macro_invocation_named(tree.root_node(), source, "vec");
        let repeated_arguments = rust_vec_macro_arguments(repeated, source).expect("repeat args");
        let RustVecMacroArguments::Repeated(repeated_arguments) = repeated_arguments else {
            panic!("vec! repetition syntax")
        };
        assert_eq!(
            &source[repeated_arguments.element.value_range.start_byte
                ..repeated_arguments.element.value_range.end_byte],
            "item"
        );
        assert_eq!(
            &source[repeated_arguments.count.value_range.start_byte
                ..repeated_arguments.count.value_range.end_byte],
            "2"
        );

        let list_source = "fn f(item: String) { let _ = vec![item, item]; }";
        let list_tree = parse_rust(list_source);
        let list = macro_invocation_named(list_tree.root_node(), list_source, "vec");
        let list_arguments = rust_vec_macro_arguments(list, list_source).expect("list args");
        let RustVecMacroArguments::Elements(elements) = list_arguments else {
            panic!("vec! list syntax")
        };
        assert_eq!(elements.len(), 2);
        for element in elements {
            assert_eq!(
                &list_source[element.value_range.start_byte..element.value_range.end_byte],
                "item"
            );
        }
    }
}
