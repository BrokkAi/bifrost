//! Structured parsing helpers for Rust's standard formatting macro arguments.
//!
//! Operand metadata is projected from native macro fragments. Their owned
//! trees remain available to consumers that execute or expose the expressions.

use tree_sitter::Node;

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

/// Runtime ports synthesized by standard formatting macros. Recognition here
/// describes syntax only; dispatch must still prove the macro's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustMacroRuntimeArgument {
    Message { first_operand: usize },
    AssertionKind,
    BorrowedOperand(usize),
    OptionalMessage { first_operand: usize },
    DebugOperand,
}

#[derive(Debug, Clone, Copy)]
pub struct RustMacroRuntimeLayout {
    pub owner: &'static str,
    pub member: &'static str,
    pub arguments: &'static [RustMacroRuntimeArgument],
    pub result_owner: Option<&'static str>,
}

/// Call only with a proven owner for dispatch, or as a syntax candidate gate.
pub fn rust_macro_runtime_layout(owner: &str, member: &str) -> Option<RustMacroRuntimeLayout> {
    use RustMacroRuntimeArgument::*;
    let (owner, member, arguments): (_, _, &'static [_]) = match (owner, member) {
        ("std" | "alloc", "format") => {
            return Some(RustMacroRuntimeLayout {
                owner: "alloc.fmt",
                member: "format",
                arguments: &[Message { first_operand: 0 }],
                result_owner: Some("std.string.String"),
            });
        }
        ("std", "print" | "println") => ("std.io.stdio", "_print", &[Message { first_operand: 0 }]),
        ("std", "eprint" | "eprintln") => {
            ("std.io.stdio", "_eprint", &[Message { first_operand: 0 }])
        }
        ("std" | "core", "panic" | "todo" | "unimplemented" | "unreachable") => (
            "core.panicking",
            "panic_fmt",
            &[Message { first_operand: 0 }],
        ),
        ("std" | "core", "assert" | "debug_assert") => (
            "core.panicking",
            "panic_fmt",
            &[Message { first_operand: 1 }],
        ),
        ("std" | "core", "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne") => (
            "core.panicking",
            "assert_failed",
            &[
                AssertionKind,
                BorrowedOperand(0),
                BorrowedOperand(1),
                OptionalMessage { first_operand: 2 },
            ],
        ),
        ("std", "dbg") => ("std.io.stdio", "_eprint", &[DebugOperand]),
        (owner, member) if rust_logging_macro(owner, member).is_some() => (
            "log.__private_api",
            "log",
            &[Message { first_operand: 0 }; 5],
        ),
        _ => return None,
    };
    Some(RustMacroRuntimeLayout {
        owner,
        member,
        arguments,
        result_owner: None,
    })
}

/// Obtain a candidate layout from an AST path. Bare names use the standard
/// prelude candidate; local shadowing is decided by the resolver, not here.
pub fn rust_macro_runtime_layout_for_path(
    path: Node<'_>,
    source: &str,
) -> Option<RustMacroRuntimeLayout> {
    use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
    let segments = crate::graph_support::rust_path_segments(path)?;
    let member = strip_raw_identifier_prefix(crate::declarations::rust_node_text(
        *segments.last()?,
        source,
    ));
    let owner = match segments.as_slice() {
        [_] => "std",
        [owner, _] => {
            strip_raw_identifier_prefix(crate::declarations::rust_node_text(*owner, source))
        }
        _ => return None,
    };
    rust_macro_runtime_layout(owner, member)
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
    pub value_kind: &'static str,
    /// Name from the structured `name = expression` grammar, when present.
    pub name: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustFormatMacroArgumentsError {
    MissingTokenTree,
    InvalidTokenTree,
    InvalidExpressionList,
}

/// Formatting metadata is projected from native operand fragments. No second
/// wrapper grammar or identifier-only interpretation of an expression exists.
pub fn rust_format_macro_arguments(
    invocation: Node<'_>,
    source: &str,
) -> Result<Vec<RustFormatMacroArgument>, RustFormatMacroArgumentsError> {
    let operands = crate::macro_matcher::parse_macro_operands(invocation, source)
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
    Ok(macro_arguments_from_operands(invocation, source, &operands))
}

pub fn rust_matches_macro_scrutinee(
    invocation: Node<'_>,
    source: &str,
) -> Result<RustFormatMacroArgument, RustFormatMacroArgumentsError> {
    rust_format_macro_arguments(invocation, source)?
        .into_iter()
        .next()
        .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)
}

pub fn rust_vec_macro_arguments(
    invocation: Node<'_>,
    source: &str,
) -> Result<RustVecMacroArguments, RustFormatMacroArgumentsError> {
    let arguments = rust_format_macro_arguments(invocation, source)?;
    let token_tree = crate::declarations::rust_macro_invocation_arguments(invocation)
        .ok_or(RustFormatMacroArgumentsError::MissingTokenTree)?;
    let (tokens, _) = crate::macro_matcher::interior_tokens(token_tree);
    if tokens.iter().any(|node| node.kind() == ";") {
        let mut arguments = arguments.into_iter();
        let element = arguments
            .next()
            .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
        let count = arguments
            .next()
            .ok_or(RustFormatMacroArgumentsError::InvalidExpressionList)?;
        if arguments.next().is_some() {
            return Err(RustFormatMacroArgumentsError::InvalidExpressionList);
        }
        Ok(RustVecMacroArguments::Repeated(Box::new(
            RustVecMacroRepeatedArguments { element, count },
        )))
    } else {
        Ok(RustVecMacroArguments::Elements(arguments))
    }
}

/// Select formatting labels only after the format literal. An assignment in
/// an assertion condition, comparison, writer, or vec element stays an
/// executable assignment expression.
pub fn macro_arguments_from_operands(
    invocation: Node<'_>,
    source: &str,
    operands: &[crate::macro_matcher::ParsedMacroOperand],
) -> Vec<RustFormatMacroArgument> {
    let mut arguments = operands
        .iter()
        .map(|operand| {
            let node = operand.node();
            RustFormatMacroArgument {
                range: node.range(),
                value_range: node.range(),
                value_kind: node.kind(),
                name: None,
            }
        })
        .collect::<Vec<_>>();
    if let Some(index) = rust_macro_format_operand(invocation, source, &arguments) {
        for (argument, operand) in arguments.iter_mut().zip(operands).skip(index + 1) {
            let (value, name) = macro_argument_value(operand.node(), source);
            argument.value_range = value.range();
            argument.value_kind = value.kind();
            argument.name = name;
        }
    }
    arguments
}

/// The shared runtime layout defines where a message begins; the grammar
/// candidate defines writer syntax for formatting helpers with no sink slot.
pub fn rust_macro_format_operand(
    invocation: Node<'_>,
    source: &str,
    arguments: &[RustFormatMacroArgument],
) -> Option<usize> {
    let path = invocation.child_by_field_name("macro")?;
    let layout = rust_macro_runtime_layout_for_path(path, source);
    let index = if layout.is_some_and(|layout| layout.owner == "log.__private_api") {
        arguments.iter().position(|argument| {
            matches!(argument.value_kind, "string_literal" | "raw_string_literal")
        })?
    } else if let Some(first_operand) = layout.and_then(|layout| {
        layout.arguments.iter().find_map(|role| match role {
            RustMacroRuntimeArgument::Message { first_operand }
            | RustMacroRuntimeArgument::OptionalMessage { first_operand } => Some(*first_operand),
            _ => None,
        })
    }) {
        first_operand
    } else {
        let name = crate::graph_support::rust_path_segments(path)?
            .last()
            .copied()?;
        usize::from(
            rust_formatting_macro(crate::declarations::rust_node_text(name, source))?
                .has_writer_receiver(),
        )
    };
    arguments
        .get(index)
        .filter(|argument| matches!(argument.value_kind, "string_literal" | "raw_string_literal"))
        .map(|_| index)
}

pub fn macro_argument_value<'tree>(
    argument: Node<'tree>,
    source: &str,
) -> (Node<'tree>, Option<Box<str>>) {
    if argument.kind() == "assignment_expression"
        && let Some(left) = argument.child_by_field_name("left")
        && left.kind() == "identifier"
        && let Some(right) = argument.child_by_field_name("right")
    {
        return (
            right,
            Some(
                brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(left, source),
                )
                .into(),
            ),
        );
    }
    (argument, None)
}

/// Parse implicit captures from an admitted literal value using the format
/// grammar, and obtain executable identifier nodes via native fragments.
pub fn rust_format_capture_trees(
    literal: Node<'_>,
    source: &str,
    named: &[&str],
) -> Vec<brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxTree> {
    let Some(text) = crate::cargo_routes::rust_static_string_literal_with_ranges(literal, source)
    else {
        return Vec::new();
    };
    let Ok(format) = parse_rust_format_string(&text.value) else {
        return Vec::new();
    };
    format
        .references
        .iter()
        .zip(format.reference_ranges.iter())
        .filter_map(|(reference, range)| {
            let RustFormatArgumentReference::Name(name) = reference else {
                return None;
            };
            if named.contains(&name.as_ref()) {
                return None;
            }
            let (decoded, original) = text
                .ranges
                .iter()
                .find(|(decoded, _)| decoded.start <= range.start && range.end <= decoded.end)?;
            let start_byte = original.start + range.start - decoded.start;
            let end_byte = original.start + range.end - decoded.start;
            let binding = crate::macro_matcher::MacroBinding {
                name: name.to_string(),
                fragment: crate::macro_matcher::MacroFragmentKind::Expr,
                start_byte,
                end_byte,
                repetition_path: Vec::new(),
                ident_role: None,
            };
            let tree = crate::macro_matcher::parse_bound_fragment(&binding, source)?;
            let capture = tree
                .root_node()
                .descendant_for_byte_range(start_byte, end_byte)?;
            if tree.root_node().has_error() || !matches!(capture.kind(), "identifier" | "self") {
                return None;
            }
            let range = capture.range();
            Some(
                brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxTree {
                    anchor: literal.id(),
                    tree,
                    range,
                },
            )
        })
        .collect()
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
    pub reference_ranges: Box<[std::ops::Range<usize>]>,
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
        references: references
            .iter()
            .map(|(reference, _)| reference.clone())
            .collect(),
        reference_ranges: references.into_iter().map(|(_, range)| range).collect(),
    })
}

fn parse_placeholder(
    chars: &[char],
    byte_offset: &[usize],
    cursor: &mut usize,
    references: &mut Vec<(RustFormatArgumentReference, std::ops::Range<usize>)>,
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
    references: &mut Vec<(RustFormatArgumentReference, std::ops::Range<usize>)>,
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
            references.push((
                RustFormatArgumentReference::Implicit,
                byte_offset[*cursor + index]..byte_offset[*cursor + index + 1],
            ));
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
    references: &mut Vec<(RustFormatArgumentReference, std::ops::Range<usize>)>,
) -> Result<(), RustFormatStringError> {
    if argument.is_empty() {
        references.push((
            RustFormatArgumentReference::Implicit,
            byte_offset[start]..byte_offset[start],
        ));
    } else if argument.iter().all(|character| character.is_ascii_digit()) {
        let digits = argument.iter().collect::<String>();
        let index = digits
            .parse()
            .map_err(|_| format_error(byte_offset, start))?;
        references.push((
            RustFormatArgumentReference::Index(index),
            byte_offset[start]..byte_offset[start + argument.len()],
        ));
    } else {
        let name = argument.iter().copied().collect::<String>();
        if !is_identifier(&name) {
            return Err(format_error(byte_offset, start));
        }
        references.push((
            RustFormatArgumentReference::Name(name.trim_start_matches("r#").into()),
            byte_offset[start]..byte_offset[start + argument.len()],
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
    use tree_sitter::{Parser, Tree};

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
