//! Translation of Joern flow semantics into the foundry IR.
//!
//! Joern states a semantic as a method full name plus mappings between
//! argument positions, where `0` is the receiver, `-1` is the return value and
//! `1..n` are the parameters. An entry with no mapping states that the method
//! carries no flow at all.
//!
//! Two front ends produce the same value:
//!
//! * [`parse_semantics_dsl`] reads the `.semantics` text format that
//!   `dataflowengineoss/src/main/antlr4/io/joern/dataflowengineoss/Semantics.g4`
//!   defines. This is the format Joern documents for user-supplied semantics.
//! * [`parse_default_semantics_scala`] reads the pinned
//!   `DefaultSemantics.scala`, which is where the shipped default corpus lives.
//!   Joern has no `.semantics` resource file at the pinned revision.

use std::collections::BTreeMap;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer,
};

use super::ir::{
    FoundryCorpus, FoundryEntry, FoundryEntryBuilder, FoundryEvidence, FoundryNote,
    FoundrySignature, FoundrySkip, FoundrySkipReason, FoundryTarget, split_parameter_types,
};

/// Joern's receiver position.
const RECEIVER_INDEX: i64 = 0;
/// Joern's return-value position.
const RETURN_INDEX: i64 = -1;

/// One Joern flow semantic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoernFlowSemantic {
    /// The method full name, or the Scala path of an unresolved constant.
    pub method_full_name: String,
    /// False when `method_full_name` is a Scala constant reference such as
    /// `Operators.assignment`, whose value the reader cannot resolve.
    pub name_is_literal: bool,
    pub mappings: Vec<JoernMapping>,
    pub passthrough: bool,
}

/// One `src -> dst` mapping between argument positions.
///
/// The optional names match keyword arguments in languages that have them.
/// They do not change which port a mapping names, so JVM translation reads the
/// indices alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoernMapping {
    pub source: i64,
    pub source_name: Option<String>,
    pub destination: i64,
    pub destination_name: Option<String>,
}

/// A Joern corpus the reader could not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoernParseError {
    pub line: u32,
    pub message: String,
}

impl std::fmt::Display for JoernParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for JoernParseError {}

/// Everything one Joern corpus translation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoernTranslation {
    pub entries: Vec<FoundryEntry>,
    pub semantics_read: u32,
    pub skips: Vec<FoundrySkip>,
}

// ---------------------------------------------------------------------------
// The `.semantics` DSL front end.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum DslToken {
    Quoted(String),
    Number(i64),
    Arrow,
    Passthrough,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlacedToken {
    token: DslToken,
    line: u32,
}

/// Parse Joern's `.semantics` text format.
///
/// The grammar makes an argument name optional after an index, and an entry's
/// method name is also a quoted string, so a quoted token after an index is
/// ambiguous in the token stream alone. Joern writes one entry per line, so a
/// quoted token binds as an argument name only when it shares the line with
/// the index it follows.
pub fn parse_semantics_dsl(text: &str) -> Result<Vec<JoernFlowSemantic>, JoernParseError> {
    let tokens = lex_semantics_dsl(text)?;
    let mut semantics = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let PlacedToken { token, line } = &tokens[index];
        let DslToken::Quoted(name) = token else {
            return Err(JoernParseError {
                line: *line,
                message: format!("expected a quoted method name, found {token:?}"),
            });
        };
        index += 1;
        let mut semantic = JoernFlowSemantic {
            method_full_name: name.clone(),
            name_is_literal: true,
            mappings: Vec::new(),
            passthrough: false,
        };
        while let Some(PlacedToken { token, line }) = tokens.get(index) {
            match token {
                DslToken::Passthrough => {
                    semantic.passthrough = true;
                    index += 1;
                }
                DslToken::Number(source) => {
                    let source_line = *line;
                    index += 1;
                    let source_name = take_same_line_name(&tokens, &mut index, source_line);
                    match tokens.get(index) {
                        Some(PlacedToken {
                            token: DslToken::Arrow,
                            ..
                        }) => index += 1,
                        other => {
                            return Err(JoernParseError {
                                line: source_line,
                                message: format!(
                                    "expected `->` after index {source}, found {other:?}"
                                ),
                            });
                        }
                    }
                    let Some(PlacedToken {
                        token: DslToken::Number(destination),
                        line: destination_line,
                    }) = tokens.get(index)
                    else {
                        return Err(JoernParseError {
                            line: source_line,
                            message: "expected a destination index after `->`".to_owned(),
                        });
                    };
                    let (destination, destination_line) = (*destination, *destination_line);
                    index += 1;
                    let destination_name =
                        take_same_line_name(&tokens, &mut index, destination_line);
                    semantic.mappings.push(JoernMapping {
                        source: *source,
                        source_name,
                        destination,
                        destination_name,
                    });
                }
                DslToken::Quoted(_) => break,
                DslToken::Arrow => {
                    return Err(JoernParseError {
                        line: *line,
                        message: "`->` without a source index".to_owned(),
                    });
                }
            }
        }
        semantics.push(semantic);
    }
    Ok(semantics)
}

fn take_same_line_name(tokens: &[PlacedToken], index: &mut usize, line: u32) -> Option<String> {
    let PlacedToken {
        token: DslToken::Quoted(name),
        line: name_line,
    } = tokens.get(*index)?
    else {
        return None;
    };
    if *name_line != line {
        return None;
    }
    *index += 1;
    Some(name.clone())
}

fn lex_semantics_dsl(text: &str) -> Result<Vec<PlacedToken>, JoernParseError> {
    let mut tokens = Vec::new();
    let mut line = 1u32;
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        match character {
            '\n' => {
                line += 1;
                rest = &rest[1..];
            }
            character if character.is_whitespace() => {
                rest = &rest[character.len_utf8()..];
            }
            '#' => {
                let end = rest.find('\n').unwrap_or(rest.len());
                rest = &rest[end..];
            }
            '"' => {
                let body = &rest[1..];
                let end = body.find('"').ok_or(JoernParseError {
                    line,
                    message: "unterminated quoted name".to_owned(),
                })?;
                tokens.push(PlacedToken {
                    token: DslToken::Quoted(body[..end].to_owned()),
                    line,
                });
                rest = &body[end + 1..];
            }
            '-' if rest.starts_with("->") => {
                tokens.push(PlacedToken {
                    token: DslToken::Arrow,
                    line,
                });
                rest = &rest[2..];
            }
            '-' | '0'..='9' => {
                let digits_start = usize::from(character == '-');
                let end = rest[digits_start..]
                    .find(|character: char| !character.is_ascii_digit())
                    .map_or(rest.len(), |offset| digits_start + offset);
                let value = rest[..end]
                    .parse::<i64>()
                    .map_err(|error| JoernParseError {
                        line,
                        message: format!("`{}` is not an index: {error}", &rest[..end]),
                    })?;
                tokens.push(PlacedToken {
                    token: DslToken::Number(value),
                    line,
                });
                rest = &rest[end..];
            }
            _ if rest.starts_with("PASSTHROUGH") => {
                tokens.push(PlacedToken {
                    token: DslToken::Passthrough,
                    line,
                });
                rest = &rest["PASSTHROUGH".len()..];
            }
            other => {
                return Err(JoernParseError {
                    line,
                    message: format!("unexpected character `{other}`"),
                });
            }
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// The `DefaultSemantics.scala` front end.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScalaToken {
    Ident(String),
    Number(i64),
    Text(String),
    Punct(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlacedScalaToken {
    token: ScalaToken,
    line: u32,
}

/// Read one `def <name>: List[FlowSemantic] = List(...)` from the pinned
/// `DefaultSemantics.scala`.
///
/// The reader accepts exactly the shape the pinned file uses: `F(name,
/// mappings)` and `PTF(name[, mappings])`, where a name is a string literal or
/// a dotted constant reference and mappings are `List((a, b), ...)` or
/// `List.empty`. Anything else is a parse error, so an upstream refactor
/// fails the foundry run instead of quietly translating less.
pub fn parse_default_semantics_scala(
    text: &str,
    definition: &str,
) -> Result<Vec<JoernFlowSemantic>, JoernParseError> {
    let tokens = lex_scala(text)?;
    let mut index = find_definition(&tokens, definition)?;
    expect_punct(&tokens, &mut index, '=')?;
    expect_ident(&tokens, &mut index, "List")?;
    expect_punct(&tokens, &mut index, '(')?;
    let mut semantics = Vec::new();
    loop {
        if consume_punct(&tokens, &mut index, ')') {
            break;
        }
        semantics.push(parse_scala_entry(&tokens, &mut index)?);
        if !consume_punct(&tokens, &mut index, ',') {
            expect_punct(&tokens, &mut index, ')')?;
            break;
        }
    }
    Ok(semantics)
}

fn find_definition(
    tokens: &[PlacedScalaToken],
    definition: &str,
) -> Result<usize, JoernParseError> {
    let mut index = 0usize;
    while index + 1 < tokens.len() {
        if tokens[index].token == ScalaToken::Ident("def".to_owned())
            && tokens[index + 1].token == ScalaToken::Ident(definition.to_owned())
        {
            let mut cursor = index + 2;
            while cursor < tokens.len() && tokens[cursor].token != ScalaToken::Punct('=') {
                cursor += 1;
            }
            return Ok(cursor);
        }
        index += 1;
    }
    Err(JoernParseError {
        line: 0,
        message: format!("`def {definition}` is not declared in this file"),
    })
}

fn parse_scala_entry(
    tokens: &[PlacedScalaToken],
    index: &mut usize,
) -> Result<JoernFlowSemantic, JoernParseError> {
    let constructor = take_ident(tokens, index)?;
    let passthrough = match constructor.as_str() {
        "F" => false,
        "PTF" => true,
        other => {
            return Err(JoernParseError {
                line: line_of(tokens, *index),
                message: format!("unknown flow constructor `{other}`"),
            });
        }
    };
    expect_punct(tokens, index, '(')?;
    let (method_full_name, name_is_literal) = parse_scala_name(tokens, index)?;
    let mappings = if consume_punct(tokens, index, ',') {
        parse_scala_mappings(tokens, index)?
    } else {
        Vec::new()
    };
    expect_punct(tokens, index, ')')?;
    Ok(JoernFlowSemantic {
        method_full_name,
        name_is_literal,
        mappings,
        passthrough,
    })
}

fn parse_scala_name(
    tokens: &[PlacedScalaToken],
    index: &mut usize,
) -> Result<(String, bool), JoernParseError> {
    match tokens.get(*index).map(|placed| &placed.token) {
        Some(ScalaToken::Text(value)) => {
            *index += 1;
            Ok((value.clone(), true))
        }
        Some(ScalaToken::Ident(_)) => {
            let mut path = take_ident(tokens, index)?;
            while consume_punct(tokens, index, '.') {
                path.push('.');
                path.push_str(&take_ident(tokens, index)?);
            }
            Ok((path, false))
        }
        _ => Err(JoernParseError {
            line: line_of(tokens, *index),
            message: "expected a method name literal or constant reference".to_owned(),
        }),
    }
}

fn parse_scala_mappings(
    tokens: &[PlacedScalaToken],
    index: &mut usize,
) -> Result<Vec<JoernMapping>, JoernParseError> {
    expect_ident(tokens, index, "List")?;
    if consume_punct(tokens, index, '.') {
        expect_ident(tokens, index, "empty")?;
        skip_type_arguments(tokens, index);
        return Ok(Vec::new());
    }
    expect_punct(tokens, index, '(')?;
    let mut mappings = Vec::new();
    loop {
        if consume_punct(tokens, index, ')') {
            break;
        }
        expect_punct(tokens, index, '(')?;
        let source = take_number(tokens, index)?;
        expect_punct(tokens, index, ',')?;
        let destination = take_number(tokens, index)?;
        expect_punct(tokens, index, ')')?;
        mappings.push(JoernMapping {
            source,
            source_name: None,
            destination,
            destination_name: None,
        });
        if !consume_punct(tokens, index, ',') {
            expect_punct(tokens, index, ')')?;
            break;
        }
    }
    Ok(mappings)
}

/// Skip an explicit type argument list such as `[(Int, Int)]`.
fn skip_type_arguments(tokens: &[PlacedScalaToken], index: &mut usize) {
    if !consume_punct(tokens, index, '[') {
        return;
    }
    let mut depth = 1usize;
    while depth > 0 {
        match tokens.get(*index).map(|placed| &placed.token) {
            Some(ScalaToken::Punct('[')) => depth += 1,
            Some(ScalaToken::Punct(']')) => depth -= 1,
            None => return,
            _ => {}
        }
        *index += 1;
    }
}

fn line_of(tokens: &[PlacedScalaToken], index: usize) -> u32 {
    tokens.get(index).map_or(0, |placed| placed.line)
}

fn take_ident(tokens: &[PlacedScalaToken], index: &mut usize) -> Result<String, JoernParseError> {
    match tokens.get(*index).map(|placed| &placed.token) {
        Some(ScalaToken::Ident(value)) => {
            let value = value.clone();
            *index += 1;
            Ok(value)
        }
        other => Err(JoernParseError {
            line: line_of(tokens, *index),
            message: format!("expected an identifier, found {other:?}"),
        }),
    }
}

fn take_number(tokens: &[PlacedScalaToken], index: &mut usize) -> Result<i64, JoernParseError> {
    match tokens.get(*index).map(|placed| &placed.token) {
        Some(ScalaToken::Number(value)) => {
            let value = *value;
            *index += 1;
            Ok(value)
        }
        other => Err(JoernParseError {
            line: line_of(tokens, *index),
            message: format!("expected an index, found {other:?}"),
        }),
    }
}

fn expect_ident(
    tokens: &[PlacedScalaToken],
    index: &mut usize,
    expected: &str,
) -> Result<(), JoernParseError> {
    let found = take_ident(tokens, index)?;
    if found == expected {
        Ok(())
    } else {
        Err(JoernParseError {
            line: line_of(tokens, *index),
            message: format!("expected `{expected}`, found `{found}`"),
        })
    }
}

fn expect_punct(
    tokens: &[PlacedScalaToken],
    index: &mut usize,
    expected: char,
) -> Result<(), JoernParseError> {
    if consume_punct(tokens, index, expected) {
        return Ok(());
    }
    Err(JoernParseError {
        line: line_of(tokens, *index),
        message: format!(
            "expected `{expected}`, found {:?}",
            tokens.get(*index).map(|placed| &placed.token)
        ),
    })
}

fn consume_punct(tokens: &[PlacedScalaToken], index: &mut usize, expected: char) -> bool {
    if tokens.get(*index).map(|placed| &placed.token) == Some(&ScalaToken::Punct(expected)) {
        *index += 1;
        return true;
    }
    false
}

fn lex_scala(text: &str) -> Result<Vec<PlacedScalaToken>, JoernParseError> {
    let mut tokens = Vec::new();
    let mut line = 1u32;
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        if character == '\n' {
            line += 1;
            rest = &rest[1..];
            continue;
        }
        if character.is_whitespace() {
            rest = &rest[character.len_utf8()..];
            continue;
        }
        if rest.starts_with("//") {
            let end = rest.find('\n').unwrap_or(rest.len());
            rest = &rest[end..];
            continue;
        }
        if rest.starts_with("/*") {
            let (consumed, newlines) = block_comment_length(rest, line)?;
            line += newlines;
            rest = &rest[consumed..];
            continue;
        }
        if character == '"' {
            let (value, consumed) = lex_scala_string(rest, line)?;
            tokens.push(PlacedScalaToken {
                token: ScalaToken::Text(value),
                line,
            });
            rest = &rest[consumed..];
            continue;
        }
        if character.is_ascii_digit()
            || (character == '-' && rest[1..].starts_with(|next: char| next.is_ascii_digit()))
        {
            let digits_start = usize::from(character == '-');
            let end = rest[digits_start..]
                .find(|character: char| !character.is_ascii_digit())
                .map_or(rest.len(), |offset| digits_start + offset);
            let value = rest[..end]
                .parse::<i64>()
                .map_err(|error| JoernParseError {
                    line,
                    message: format!("`{}` is not an index: {error}", &rest[..end]),
                })?;
            tokens.push(PlacedScalaToken {
                token: ScalaToken::Number(value),
                line,
            });
            rest = &rest[end..];
            continue;
        }
        if character.is_alphabetic() || character == '_' {
            let end = rest
                .find(|character: char| !(character.is_alphanumeric() || character == '_'))
                .unwrap_or(rest.len());
            tokens.push(PlacedScalaToken {
                token: ScalaToken::Ident(rest[..end].to_owned()),
                line,
            });
            rest = &rest[end..];
            continue;
        }
        tokens.push(PlacedScalaToken {
            token: ScalaToken::Punct(character),
            line,
        });
        rest = &rest[character.len_utf8()..];
    }
    Ok(tokens)
}

/// Scala block comments nest, so the reader counts depth rather than stopping
/// at the first `*/`.
fn block_comment_length(text: &str, line: u32) -> Result<(usize, u32), JoernParseError> {
    let mut depth = 0usize;
    let mut newlines = 0u32;
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"/*") {
            depth += 1;
            index += 2;
            continue;
        }
        if bytes[index..].starts_with(b"*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return Ok((index, newlines));
            }
            continue;
        }
        if bytes[index] == b'\n' {
            newlines += 1;
        }
        index += 1;
    }
    Err(JoernParseError {
        line,
        message: "unterminated block comment".to_owned(),
    })
}

fn lex_scala_string(text: &str, line: u32) -> Result<(String, usize), JoernParseError> {
    let mut value = String::new();
    let mut characters = text.char_indices();
    characters.next();
    while let Some((index, character)) = characters.next() {
        match character {
            '"' => return Ok((value, index + 1)),
            '\\' => {
                let Some((_, escaped)) = characters.next() else {
                    break;
                };
                value.push(match escaped {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => other,
                });
            }
            other => value.push(other),
        }
    }
    Err(JoernParseError {
        line,
        message: "unterminated string literal".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Translation into the foundry IR.
// ---------------------------------------------------------------------------

/// Translate parsed Joern semantics into foundry entries.
pub fn translate_joern_semantics(file: &str, semantics: &[JoernFlowSemantic]) -> JoernTranslation {
    let mut builders: BTreeMap<FoundryTarget, FoundryEntryBuilder> = BTreeMap::new();
    let mut skips = Vec::new();
    for (index, semantic) in semantics.iter().enumerate() {
        let row = index as u32 + 1;
        if !semantic.name_is_literal {
            skips.push(FoundrySkip {
                file: file.to_owned(),
                row,
                reason: FoundrySkipReason::UnresolvedName,
                detail: format!(
                    "`{}` is a constant reference the reader cannot resolve",
                    semantic.method_full_name
                ),
            });
            continue;
        }
        let Some(parsed) = parse_method_full_name(&semantic.method_full_name) else {
            skips.push(FoundrySkip {
                file: file.to_owned(),
                row,
                reason: FoundrySkipReason::UnresolvedName,
                detail: format!(
                    "`{}` does not name a JVM class and member",
                    semantic.method_full_name
                ),
            });
            continue;
        };
        let arity = parsed.parameter_types.len() as u32;
        let target = FoundryTarget {
            artifact_path: parsed.artifact_path,
            member: parsed.member,
            signature: FoundrySignature::Overload {
                types: parsed.parameter_types,
            },
        };
        let mut transfers = Vec::new();
        let mut representable = 0usize;
        for mapping in &semantic.mappings {
            let input = match mapping.source {
                RECEIVER_INDEX => AuthoredSummaryInput::Receiver {},
                RETURN_INDEX => {
                    skips.push(FoundrySkip {
                        file: file.to_owned(),
                        row,
                        reason: FoundrySkipReason::InputPortUnsupported,
                        detail: format!(
                            "`{}` reads back from the return value",
                            semantic.method_full_name
                        ),
                    });
                    continue;
                }
                source if source > 0 => {
                    let ordinal = (source - 1) as u32;
                    if ordinal >= arity {
                        skips.push(FoundrySkip {
                            file: file.to_owned(),
                            row,
                            reason: FoundrySkipReason::OrdinalOutOfRange,
                            detail: format!(
                                "source index {source} exceeds the arity of `{}`",
                                semantic.method_full_name
                            ),
                        });
                        continue;
                    }
                    AuthoredSummaryInput::Parameter { ordinal }
                }
                source => {
                    skips.push(FoundrySkip {
                        file: file.to_owned(),
                        row,
                        reason: FoundrySkipReason::MalformedRow,
                        detail: format!("source index {source} names no port"),
                    });
                    continue;
                }
            };
            let output = match mapping.destination {
                RETURN_INDEX => AuthoredSummaryOutput::NormalReturn {},
                RECEIVER_INDEX => AuthoredSummaryOutput::Receiver {},
                destination if destination > 0 => {
                    skips.push(FoundrySkip {
                        file: file.to_owned(),
                        row,
                        reason: FoundrySkipReason::OutputPortUnsupported,
                        detail: format!(
                            "the authored IR has no parameter output for index {destination}"
                        ),
                    });
                    continue;
                }
                destination => {
                    skips.push(FoundrySkip {
                        file: file.to_owned(),
                        row,
                        reason: FoundrySkipReason::MalformedRow,
                        detail: format!("destination index {destination} names no port"),
                    });
                    continue;
                }
            };
            representable += 1;
            transfers.push(AuthoredSummaryTransfer {
                input,
                exit_kind: AuthoredSummaryExitKind::Normal,
                output,
                value_transfer: None,
            });
        }
        let states_no_flow = semantic.mappings.is_empty() && !semantic.passthrough;
        if representable == 0 && !states_no_flow {
            if semantic.passthrough && semantic.mappings.is_empty() {
                skips.push(FoundrySkip {
                    file: file.to_owned(),
                    row,
                    reason: FoundrySkipReason::PassthroughNotRepresentable,
                    detail: format!("`{}` states only PASSTHROUGH", semantic.method_full_name),
                });
            }
            continue;
        }
        let builder = builders.entry(target).or_default();
        for transfer in transfers {
            builder.add_transfer(transfer);
        }
        if states_no_flow {
            builder.declare_no_flow();
        }
        if semantic.passthrough {
            builder.add_note(FoundryNote::PassthroughNotCarried);
        }
        builder.add_evidence(FoundryEvidence {
            file: file.to_owned(),
            row,
            text: render_semantic(semantic),
        });
    }
    let entries = builders
        .into_iter()
        .map(|(target, builder)| {
            let arity = target.signature.arity();
            builder.finish(FoundryCorpus::Joern, target, arity)
        })
        .collect::<Vec<_>>();
    skips.sort();
    JoernTranslation {
        entries,
        semantics_read: semantics.len() as u32,
        skips,
    }
}

fn render_semantic(semantic: &JoernFlowSemantic) -> String {
    use std::fmt::Write as _;

    let mut rendered = semantic.method_full_name.clone();
    for mapping in &semantic.mappings {
        write!(rendered, " {}->{}", mapping.source, mapping.destination)
            .expect("writing to a String cannot fail");
    }
    if semantic.passthrough {
        rendered.push_str(" PASSTHROUGH");
    }
    rendered
}

struct ParsedMethodFullName {
    artifact_path: String,
    member: String,
    parameter_types: Vec<String>,
}

/// Parse `java.lang.String.concat:java.lang.String(java.lang.String)`.
///
/// The shape is `<qualified method>:<return type>(<parameter types>)`. The
/// qualified method's last segment is the member, which is `<init>` for a
/// constructor, and the rest is the class.
fn parse_method_full_name(name: &str) -> Option<ParsedMethodFullName> {
    let (qualified, signature) = name.split_once(':')?;
    let parameters_start = signature.find('(')?;
    let parameters = signature[parameters_start..]
        .strip_prefix('(')?
        .strip_suffix(')')?;
    let (class_name, member) = qualified.rsplit_once('.')?;
    if class_name.is_empty() || member.is_empty() {
        return None;
    }
    let mut artifact_path = String::with_capacity(class_name.len() + 6);
    for character in class_name.chars() {
        artifact_path.push(if character == '.' { '/' } else { character });
    }
    artifact_path.push_str(".class");
    Some(ParsedMethodFullName {
        artifact_path,
        member: member.to_owned(),
        parameter_types: split_parameter_types(parameters),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary_foundry::codeql::skip_counts;
    use crate::summary_foundry::ir::FoundryClaim;

    const SLICE: &str = include_str!("../../testdata/summary-corpora/joern/DefaultSemantics.scala");

    fn slice_semantics() -> Vec<JoernFlowSemantic> {
        parse_default_semantics_scala(SLICE, "javaFlows").expect("slice parses")
    }

    fn entry<'a>(translation: &'a JoernTranslation, path: &str, symbol: &str) -> &'a FoundryEntry {
        translation
            .entries
            .iter()
            .find(|entry| {
                entry.target.artifact_path == path
                    && entry.target.signature.symbol(&entry.target.member) == symbol
            })
            .unwrap_or_else(|| {
                panic!(
                    "no entry for {path} {symbol}; have {:#?}",
                    translation
                        .entries
                        .iter()
                        .map(|entry| format!(
                            "{} {}",
                            entry.target.artifact_path,
                            entry.target.signature.symbol(&entry.target.member)
                        ))
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn the_dsl_parser_reads_names_mappings_and_passthrough() {
        let text = concat!(
            "# a comment\n",
            "\"java.lang.String.concat:java.lang.String(java.lang.String)\" 0->-1 1->-1\n",
            "\"java.io.PrintStream.print:void(java.lang.String)\" PASSTHROUGH 0->0\n",
            "\"com.example.Nil.sanitize:void(java.lang.String)\"\n",
        );

        let semantics = parse_semantics_dsl(text).expect("dsl parses");

        assert_eq!(semantics.len(), 3);
        assert_eq!(
            semantics[0].mappings,
            vec![
                JoernMapping {
                    source: 0,
                    source_name: None,
                    destination: -1,
                    destination_name: None,
                },
                JoernMapping {
                    source: 1,
                    source_name: None,
                    destination: -1,
                    destination_name: None,
                },
            ]
        );
        assert!(semantics[1].passthrough);
        assert!(semantics[2].mappings.is_empty());
        assert!(!semantics[2].passthrough);
    }

    #[test]
    fn the_dsl_parser_binds_an_argument_name_only_on_its_own_line() {
        let text = "\"a.B.c:void(java.lang.String)\" 1 \"value\" ->0\n\"d.E.f:void()\"\n";

        let semantics = parse_semantics_dsl(text).expect("dsl parses");

        assert_eq!(semantics.len(), 2);
        assert_eq!(
            semantics[0].mappings[0].source_name.as_deref(),
            Some("value")
        );
        assert_eq!(semantics[1].method_full_name, "d.E.f:void()");
    }

    #[test]
    fn the_dsl_parser_rejects_a_mapping_without_an_arrow() {
        let error = parse_semantics_dsl("\"a.B.c:void()\" 1 2\n").expect_err("must fail");

        assert!(error.message.contains("expected `->`"), "{error}");
    }

    #[test]
    fn the_scala_reader_reads_the_pinned_default_corpus_shape() {
        let semantics = slice_semantics();

        assert!(semantics.len() >= 20, "read {} entries", semantics.len());
        let split = semantics
            .iter()
            .find(|semantic| {
                semantic
                    .method_full_name
                    .starts_with("java.lang.String.split:")
            })
            .expect("the slice carries String.split");
        assert!(split.passthrough);
        assert_eq!(
            split.mappings,
            vec![JoernMapping {
                source: 0,
                source_name: None,
                destination: 0,
                destination_name: None,
            }]
        );
    }

    #[test]
    fn the_scala_reader_fails_loudly_on_an_unknown_shape() {
        let text = "object X { def javaFlows: List[FlowSemantic] = List(G(\"a\", List((1, 2)))) }";

        let error = parse_default_semantics_scala(text, "javaFlows").expect_err("must fail");

        assert!(
            error.message.contains("unknown flow constructor"),
            "{error}"
        );
    }

    #[test]
    fn method_full_names_reduce_to_class_file_paths() {
        let parsed = parse_method_full_name(
            "org.apache.http.HttpRequest.<init>:void(java.lang.String,java.lang.String)",
        )
        .expect("parses");

        assert_eq!(parsed.artifact_path, "org/apache/http/HttpRequest.class");
        assert_eq!(parsed.member, "<init>");
        assert_eq!(parsed.parameter_types.len(), 2);
        assert!(parse_method_full_name("<operator>.assignment").is_none());
    }

    #[test]
    fn mappings_become_transfers_and_parameter_writes_are_skipped() {
        let translation = translate_joern_semantics("DefaultSemantics.scala", &slice_semantics());

        let println = entry(
            &translation,
            "java/io/PrintStream.class",
            "println(java.lang.String)",
        );
        assert_eq!(println.claim, FoundryClaim::Flows);
        assert_eq!(
            println.rendered_transfers(),
            vec!["receiver->receiver@normal".to_owned()]
        );
        assert_eq!(println.boundary.parameter_count, 1);

        let counts = skip_counts(&translation.skips);
        assert!(
            counts.get("output_port_unsupported").copied().unwrap_or(0) > 0,
            "parameter writes must be counted: {counts:?}"
        );
    }

    #[test]
    fn a_passthrough_entry_records_the_uncarried_claim() {
        let translation = translate_joern_semantics("DefaultSemantics.scala", &slice_semantics());

        let split = entry(
            &translation,
            "java/lang/String.class",
            "split(java.lang.String)",
        );

        assert!(split.notes.contains(&FoundryNote::PassthroughNotCarried));
    }

    #[test]
    fn translation_is_deterministic() {
        let semantics = slice_semantics();
        let first = translate_joern_semantics("DefaultSemantics.scala", &semantics);
        let second = translate_joern_semantics("DefaultSemantics.scala", &semantics);

        assert_eq!(first, second);
    }
}
