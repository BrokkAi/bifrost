//! Structured printf-format facts and C++ format-call relations.
//!
//! The parser in this module consumes the decoded value of a string literal
//! selected by the structural facts arena. It does not search source text for
//! format syntax. Call identity and argument positions come from the modeled
//! procedure key and the shared call-shape/binding reports.

use super::*;
use crate::analyzer::usages::effects::ModeledProcedureKey;

/// One conversion directive in a printf-family format string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FormatDirective {
    /// Zero-based position in the variadic argument list.
    pub(crate) value_argument: Option<usize>,
    /// Zero-based position of a `*` width argument, if present.
    pub(crate) width_argument: Option<usize>,
    /// Zero-based position of a `*` precision argument, if present.
    pub(crate) precision_argument: Option<usize>,
    pub(crate) length: FormatLength,
    pub(crate) conversion: char,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormatLength {
    None,
    Hh,
    H,
    L,
    Ll,
    J,
    Z,
    T,
    BigL,
    Q,
    I,
    I32,
    I64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedFormat {
    pub(crate) directives: Vec<FormatDirective>,
    /// One past the largest variadic argument position referenced by the
    /// format, including `*` width and precision arguments.
    pub(crate) required_arguments: usize,
    pub(crate) complete: bool,
    pub(crate) positional: bool,
}

impl ParsedFormat {
    fn incomplete() -> Self {
        Self {
            directives: Vec::new(),
            required_arguments: 0,
            complete: false,
            positional: false,
        }
    }
}

/// Parse one decoded printf-family format value.
///
/// Positions are zero-based within the arguments after the fixed format
/// parameter. Positional directives use their one-based source spelling but
/// are normalized to the same zero-based representation. Mixing positional
/// and sequential argument selection is rejected as incomplete because the C
/// formatting contract does not define that combination.
pub(crate) fn parse_printf_format(format: &str) -> ParsedFormat {
    let chars = format.chars().collect::<Vec<_>>();
    let mut directives = Vec::new();
    let mut next_argument = 0usize;
    let mut maximum_argument = 0usize;
    let mut positional = false;
    let mut sequential = false;
    let mut index = 0usize;

    while index < chars.len() {
        if chars[index] != '%' {
            index += 1;
            continue;
        }
        index += 1;
        if index == chars.len() {
            return ParsedFormat::incomplete();
        }
        if chars[index] == '%' {
            index += 1;
            continue;
        }

        let value_position = parse_positional_index(&chars, &mut index);
        if value_position.is_some() {
            positional = true;
        }

        while index < chars.len() && matches!(chars[index], '-' | '+' | ' ' | '#' | '0' | '\'') {
            index += 1;
        }

        let width_argument = if index < chars.len() && chars[index] == '*' {
            index += 1;
            let position = parse_positional_index(&chars, &mut index);
            if position.is_some() {
                positional = true;
                position.map(|position| position - 1)
            } else {
                sequential = true;
                let position = next_argument;
                next_argument += 1;
                Some(position)
            }
        } else {
            consume_digits(&chars, &mut index);
            None
        };

        let precision_argument = if index < chars.len() && chars[index] == '.' {
            index += 1;
            if index < chars.len() && chars[index] == '*' {
                index += 1;
                let position = parse_positional_index(&chars, &mut index);
                if position.is_some() {
                    positional = true;
                    position.map(|position| position - 1)
                } else {
                    sequential = true;
                    let position = next_argument;
                    next_argument += 1;
                    Some(position)
                }
            } else {
                consume_digits(&chars, &mut index);
                None
            }
        } else {
            None
        };

        let length = match parse_length(&chars, &mut index) {
            Some(length) => length,
            None => FormatLength::None,
        };
        let Some(&conversion) = chars.get(index) else {
            return ParsedFormat::incomplete();
        };
        index += 1;
        if !is_conversion(conversion) {
            return ParsedFormat::incomplete();
        }

        let value_argument = if conversion == 'm' {
            None
        } else if let Some(position) = value_position {
            Some(position - 1)
        } else {
            sequential = true;
            let position = next_argument;
            next_argument += 1;
            Some(position)
        };

        for position in [width_argument, precision_argument, value_argument]
            .into_iter()
            .flatten()
        {
            maximum_argument = maximum_argument.max(position.saturating_add(1));
        }
        directives.push(FormatDirective {
            value_argument,
            width_argument,
            precision_argument,
            length,
            conversion,
        });
    }

    if positional && sequential {
        return ParsedFormat::incomplete();
    }
    ParsedFormat {
        directives,
        required_arguments: maximum_argument,
        complete: true,
        positional,
    }
}

fn parse_positional_index(chars: &[char], index: &mut usize) -> Option<usize> {
    let start = *index;
    let mut position = 0usize;
    while let Some(character) = chars.get(*index) {
        if !character.is_ascii_digit() {
            break;
        }
        position = position
            .saturating_mul(10)
            .saturating_add((*character as u8 - b'0') as usize);
        *index += 1;
    }
    if *index > start && chars.get(*index) == Some(&'$') && position != 0 {
        *index += 1;
        Some(position)
    } else {
        *index = start;
        None
    }
}

fn consume_digits(chars: &[char], index: &mut usize) {
    while chars
        .get(*index)
        .is_some_and(|character| character.is_ascii_digit())
    {
        *index += 1;
    }
}

fn parse_length(chars: &[char], index: &mut usize) -> Option<FormatLength> {
    let start = *index;
    let length = match chars.get(*index).copied() {
        Some('h') => {
            *index += 1;
            if chars.get(*index) == Some(&'h') {
                *index += 1;
                FormatLength::Hh
            } else {
                FormatLength::H
            }
        }
        Some('l') => {
            *index += 1;
            if chars.get(*index) == Some(&'l') {
                *index += 1;
                FormatLength::Ll
            } else {
                FormatLength::L
            }
        }
        Some('j') => {
            *index += 1;
            FormatLength::J
        }
        Some('z') => {
            *index += 1;
            FormatLength::Z
        }
        Some('t') => {
            *index += 1;
            FormatLength::T
        }
        Some('L') => {
            *index += 1;
            FormatLength::BigL
        }
        Some('q') => {
            *index += 1;
            FormatLength::Q
        }
        Some('I') => {
            *index += 1;
            match chars.get(*index).copied() {
                Some('3') if chars.get(*index + 1) == Some(&'2') => {
                    *index += 2;
                    FormatLength::I32
                }
                Some('6') if chars.get(*index + 1) == Some(&'4') => {
                    *index += 2;
                    FormatLength::I64
                }
                _ => FormatLength::I,
            }
        }
        _ => return None,
    };
    (*index != start).then_some(length)
}

fn is_conversion(conversion: char) -> bool {
    matches!(
        conversion,
        'd' | 'i'
            | 'o'
            | 'u'
            | 'x'
            | 'X'
            | 'f'
            | 'F'
            | 'e'
            | 'E'
            | 'g'
            | 'G'
            | 'a'
            | 'A'
            | 'c'
            | 's'
            | 'p'
            | 'n'
            | 'm'
    )
}

/// Return the fixed format-argument position for a modeled C printf-family
/// declaration. The owner/member pair is the resolver-owned semantic identity,
/// not a source spelling fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FormatFunctionSpec {
    pub(crate) format_argument: usize,
    pub(crate) variadic: bool,
}

pub(crate) fn format_function_spec(key: &ModeledProcedureKey) -> Option<FormatFunctionSpec> {
    if key.language != "cpp" && key.language != "c" {
        return None;
    }
    if !matches!(key.owner.as_str(), "stdio" | "cstdio") {
        return None;
    }
    let format_argument = match key.member.as_str() {
        "printf" | "vprintf" => 0,
        "fprintf" | "vfprintf" => 1,
        "sprintf" | "vsprintf" => 1,
        "snprintf" | "vsnprintf" => 2,
        _ => return None,
    };
    let variadic = matches!(
        key.member.as_str(),
        "printf" | "fprintf" | "sprintf" | "snprintf"
    );
    Some(FormatFunctionSpec {
        format_argument,
        variadic,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FormatRule {
    NonConstant,
    WrongNumber,
    TooMany,
    WrongType,
    NonPortable,
    OverflowingSnprintf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatValueKind {
    String,
    Integer { long: bool },
    Floating,
    Pointer { void_pointer: bool },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatArgumentOrigin {
    DirectString,
    Identifier,
    Other,
    Missing,
}

fn format_argument_origin(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    argument: &crate::analyzer::usages::call_shape::ArgumentRow,
) -> (FormatArgumentOrigin, Option<String>) {
    let Some(facts) = value.site.shape.facts.as_ref() else {
        return (FormatArgumentOrigin::Missing, None);
    };
    let Some((_, node)) = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| {
            node.range.start_byte == argument.range.start_byte
                && node.range.end_byte == argument.range.end_byte
        })
        .or_else(|| {
            facts
                .nodes()
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    node.range.start_byte >= argument.range.start_byte
                        && node.range.end_byte <= argument.range.end_byte
                })
                .min_by_key(|(_, node)| {
                    (
                        node.range.end_byte.saturating_sub(node.range.start_byte),
                        node.range.start_byte,
                    )
                })
        })
    else {
        return (FormatArgumentOrigin::Missing, None);
    };
    match node.kind {
        NormalizedKind::StringLiteral => (
            node.string_value
                .as_ref()
                .map_or(FormatArgumentOrigin::Missing, |_| {
                    FormatArgumentOrigin::DirectString
                }),
            node.string_value.clone(),
        ),
        NormalizedKind::Identifier => {
            let is_parameter = value
                .site
                .shape
                .source
                .as_ref()
                .and_then(|source| {
                    source
                        .get(argument.range.start_byte..argument.range.end_byte)
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                })
                .and_then(|name| {
                    analyzer
                        .cpp_expression_source_facts(value.file())
                        .map(|source_facts| (name.to_owned(), source_facts))
                })
                .is_some_and(|(name, source_facts)| {
                    let Some(argument_callable) = enclosing_callable(facts, argument.range) else {
                        return false;
                    };
                    let mut parameters = source_facts.expressions.iter().filter(|fact| {
                        fact.kind
                            == brokk_bifrost_core::analyzer::cpp_facts::CppExpressionKind::FunctionParameter
                            && fact.name.as_deref() == Some(name.as_str())
                            && enclosing_callable(
                                facts,
                                source_facts.source.occurrence(fact.occurrence).range,
                            ) == Some(argument_callable)
                    });
                    parameters.next().is_some() && parameters.next().is_none()
                });
            if is_parameter {
                (FormatArgumentOrigin::Other, None)
            } else {
                (FormatArgumentOrigin::Identifier, None)
            }
        }
        NormalizedKind::FieldAccess => (FormatArgumentOrigin::Identifier, None),
        _ => (FormatArgumentOrigin::Other, None),
    }
}

fn enclosing_callable(
    facts: &crate::analyzer::structural::facts::FileFacts,
    range: crate::analyzer::Range,
) -> Option<u32> {
    facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            matches!(
                node.kind,
                NormalizedKind::Function
                    | NormalizedKind::Method
                    | NormalizedKind::Constructor
                    | NormalizedKind::Lambda
            )
        })
        .filter(|(_, node)| {
            node.range.start_byte <= range.start_byte && range.end_byte <= node.range.end_byte
        })
        .min_by_key(|(_, node)| {
            (
                node.range.end_byte.saturating_sub(node.range.start_byte),
                node.range.start_byte,
            )
        })
        .map(|(id, _)| u32::try_from(id).expect("structural fact node ids fit u32"))
}

fn format_call_parts(
    value: &CallBindingValue,
) -> Option<(
    FormatFunctionSpec,
    &crate::analyzer::usages::call_shape::ArgumentRow,
    &[crate::analyzer::usages::call_shape::ArgumentRow],
)> {
    let key = value.site.modeled_key.as_ref()?;
    let spec = format_function_spec(key)?;
    if !spec.variadic {
        return None;
    }
    if !value.site.shape.report.outcome.coverage.is_exact() {
        return None;
    }
    let arguments = value.site.shape.report.arguments.as_slice();
    let format_argument = arguments.get(spec.format_argument)?;
    let variadic_arguments = arguments.get(spec.format_argument + 1..)?;
    Some((spec, format_argument, variadic_arguments))
}

fn report_format_incomplete(
    value: &CallBindingValue,
    rule: FormatRule,
    reason: &'static str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let rule = match rule {
        FormatRule::NonConstant => "cpp-non-constant-format",
        FormatRule::WrongNumber => "cpp-wrong-number-format-arguments",
        FormatRule::TooMany => "cpp-too-many-format-arguments",
        FormatRule::WrongType => "cpp-wrong-type-format-argument",
        FormatRule::NonPortable => "cpp-non-portable-printf",
        FormatRule::OverflowingSnprintf => "cpp-overflowing-snprintf",
    };
    let language = crate::analyzer::common::language_for_file(value.file()).config_label();
    let message = format!(
        "{rule}: structured printf evidence is incomplete ({reason}) for {}",
        rel_path_string(value.file())
    );
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.language == language
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language,
        message,
        exhausted_roots: Vec::new(),
    });
}

fn retain_format_argument(
    value: &CallBindingValue,
    argument: &crate::analyzer::usages::call_shape::ArgumentRow,
    rule: FormatRule,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if value.row().argument_id != Some(argument.id.clone()) {
        return Vec::new();
    }
    let Some(seed) = value.site.shape.seed.as_ref() else {
        report_format_incomplete(
            value,
            rule,
            "source-backed structural seed is unavailable",
            diagnostics,
        );
        return Vec::new();
    };
    vec![pipeline_expansion(PipelineValue::StructuralMatch(
        Arc::clone(seed),
    ))]
}

fn argument_kind(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    argument: &crate::analyzer::usages::call_shape::ArgumentRow,
) -> FormatValueKind {
    let Some(facts) = value.site.shape.facts.as_ref() else {
        return FormatValueKind::Unknown;
    };
    if let Some(node) = facts.nodes().iter().find(|node| {
        node.range.start_byte == argument.range.start_byte
            && node.range.end_byte == argument.range.end_byte
    }) {
        match node.kind {
            NormalizedKind::StringLiteral => return FormatValueKind::String,
            NormalizedKind::NumericLiteral => {
                let long = analyzer
                    .cpp_expression_source_facts(value.file())
                    .and_then(|source_facts| {
                        source_facts.expressions.iter().find(|fact| {
                            fact.kind
                                == brokk_bifrost_core::analyzer::cpp_facts::CppExpressionKind::IntegerLiteral
                                && source_facts
                                    .source
                                    .occurrence(fact.occurrence)
                                    .range
                                    == argument.range
                        })
                        .and_then(|fact| fact.literal_text.as_deref())
                        .map(|literal| {
                            literal
                                .chars()
                                .rev()
                                .take_while(|character| character.is_ascii_alphabetic())
                                .any(|character| character == 'l' || character == 'L')
                        })
                    })
                    .unwrap_or(false);
                return FormatValueKind::Integer { long };
            }
            NormalizedKind::NullLiteral => {
                return FormatValueKind::Pointer {
                    void_pointer: false,
                };
            }
            _ => {}
        }
    }

    let Some(source) = value.site.shape.source.as_ref() else {
        return FormatValueKind::Unknown;
    };
    let name = source
        .get(argument.range.start_byte..argument.range.end_byte)
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let Some(name) = name else {
        return FormatValueKind::Unknown;
    };
    let Some(source_facts) = analyzer.cpp_expression_source_facts(value.file()) else {
        return FormatValueKind::Unknown;
    };
    let Some(argument_callable) = enclosing_callable(facts, argument.range) else {
        return FormatValueKind::Unknown;
    };
    let mut matching_parameters = source_facts.expressions.iter().filter(|fact| {
        fact.kind == brokk_bifrost_core::analyzer::cpp_facts::CppExpressionKind::FunctionParameter
            && fact.name.as_deref() == Some(name)
            && enclosing_callable(facts, source_facts.source.occurrence(fact.occurrence).range)
                == Some(argument_callable)
    });
    let Some(first) = matching_parameters.next() else {
        return FormatValueKind::Unknown;
    };
    if matching_parameters.next().is_some() {
        return FormatValueKind::Unknown;
    }
    parameter_kind(first)
}

fn parameter_kind(
    fact: &brokk_bifrost_core::analyzer::cpp_facts::CppExpressionFact,
) -> FormatValueKind {
    use brokk_bifrost_core::analyzer::cpp_facts::CppTypeForm;
    let type_text = fact.type_text.as_deref().unwrap_or_default();
    match fact.type_form {
        CppTypeForm::Pointer | CppTypeForm::Array => FormatValueKind::Pointer {
            void_pointer: type_text.split_whitespace().any(|part| part == "void"),
        },
        CppTypeForm::Builtin | CppTypeForm::Unknown
            if type_text.split_whitespace().any(|part| {
                matches!(
                    part,
                    "bool"
                        | "char"
                        | "short"
                        | "int"
                        | "long"
                        | "signed"
                        | "unsigned"
                        | "float"
                        | "double"
                )
            }) =>
        {
            if type_text.contains("float") || type_text.contains("double") {
                FormatValueKind::Floating
            } else {
                FormatValueKind::Integer {
                    long: type_text.split_whitespace().any(|part| part == "long"),
                }
            }
        }
        _ => FormatValueKind::Unknown,
    }
}

fn conversion_accepts(conversion: char, length: FormatLength, kind: FormatValueKind) -> bool {
    match conversion {
        's' => matches!(kind, FormatValueKind::String),
        'p' => matches!(kind, FormatValueKind::Pointer { .. }),
        'n' => matches!(kind, FormatValueKind::Pointer { .. }),
        'd' | 'i' | 'o' | 'u' | 'x' | 'X' | 'c' => match kind {
            FormatValueKind::Integer { long } => {
                matches!(length, FormatLength::L | FormatLength::Ll) == long
                    || matches!(length, FormatLength::H | FormatLength::Hh)
            }
            _ => false,
        },
        'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => {
            matches!(kind, FormatValueKind::Floating)
        }
        'm' => true,
        _ => false,
    }
}

fn is_nonportable(conversion: char, length: FormatLength, kind: FormatValueKind) -> bool {
    matches!(
        (conversion, length, kind),
        (
            'd' | 'i' | 'o' | 'u' | 'x' | 'X',
            FormatLength::None,
            FormatValueKind::Integer { long: true },
        ) | (
            'p',
            FormatLength::None,
            FormatValueKind::Pointer { void_pointer: true }
        )
    )
}

pub(super) fn format_rule_expansions(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    rule: FormatRule,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let Some((_, format_argument, variadic_arguments)) = format_call_parts(value) else {
        report_format_incomplete(
            value,
            rule,
            "modeled printf-family call or exact call shape is unavailable",
            diagnostics,
        );
        return Vec::new();
    };
    let (origin, format_value) = format_argument_origin(analyzer, value, format_argument);
    if matches!(origin, FormatArgumentOrigin::Missing) {
        report_format_incomplete(
            value,
            rule,
            "format argument literal facts are unavailable",
            diagnostics,
        );
        return Vec::new();
    }

    match rule {
        FormatRule::NonConstant => match origin {
            FormatArgumentOrigin::Other => {
                retain_format_argument(value, format_argument, rule, diagnostics)
            }
            FormatArgumentOrigin::DirectString | FormatArgumentOrigin::Identifier => Vec::new(),
            FormatArgumentOrigin::Missing => unreachable!("missing origins returned above"),
        },
        FormatRule::WrongNumber
        | FormatRule::TooMany
        | FormatRule::WrongType
        | FormatRule::NonPortable => {
            let Some(format_value) = format_value else {
                report_format_incomplete(
                    value,
                    rule,
                    "format value is not a direct string literal",
                    diagnostics,
                );
                return Vec::new();
            };
            let parsed = parse_printf_format(&format_value);
            if !parsed.complete {
                report_format_incomplete(
                    value,
                    rule,
                    "format directive syntax is incomplete",
                    diagnostics,
                );
                return Vec::new();
            }
            match rule {
                FormatRule::WrongNumber if variadic_arguments.len() < parsed.required_arguments => {
                    retain_format_argument(value, format_argument, rule, diagnostics)
                }
                FormatRule::TooMany if variadic_arguments.len() > parsed.required_arguments => {
                    retain_format_argument(value, format_argument, rule, diagnostics)
                }
                FormatRule::WrongType => parsed
                    .directives
                    .iter()
                    .find_map(|directive| {
                        let position = directive.value_argument?;
                        let argument = variadic_arguments.get(position)?;
                        let kind = argument_kind(analyzer, value, argument);
                        (!matches!(kind, FormatValueKind::Unknown)
                            && !conversion_accepts(directive.conversion, directive.length, kind))
                        .then(|| retain_format_argument(value, format_argument, rule, diagnostics))
                    })
                    .unwrap_or_default(),
                FormatRule::NonPortable => parsed
                    .directives
                    .iter()
                    .find_map(|directive| {
                        let position = directive.value_argument?;
                        let argument = variadic_arguments.get(position)?;
                        let kind = argument_kind(analyzer, value, argument);
                        is_nonportable(directive.conversion, directive.length, kind).then(|| {
                            retain_format_argument(value, format_argument, rule, diagnostics)
                        })
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            }
        }
        FormatRule::OverflowingSnprintf => {
            report_format_incomplete(
                value,
                rule,
                "destination extent and bounded return-value flow are not published",
                diagnostics,
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FormatLength, parse_printf_format};

    #[test]
    fn parses_width_precision_length_and_escaped_percent() {
        let parsed = parse_printf_format("rate=%% %2$*1$.*3$lld");
        assert!(parsed.complete);
        assert!(parsed.positional);
        assert_eq!(parsed.required_arguments, 3);
        assert_eq!(parsed.directives.len(), 1);
        let directive = parsed.directives[0];
        assert_eq!(directive.width_argument, Some(0));
        assert_eq!(directive.precision_argument, Some(2));
        assert_eq!(directive.value_argument, Some(1));
        assert_eq!(directive.length, FormatLength::Ll);
        assert_eq!(directive.conversion, 'd');
    }

    #[test]
    fn counts_sequential_star_arguments() {
        let parsed = parse_printf_format("%*.*f %s");
        assert!(parsed.complete);
        assert_eq!(parsed.required_arguments, 4);
        assert_eq!(parsed.directives[0].width_argument, Some(0));
        assert_eq!(parsed.directives[0].precision_argument, Some(1));
        assert_eq!(parsed.directives[0].value_argument, Some(2));
        assert_eq!(parsed.directives[1].value_argument, Some(3));
    }

    #[test]
    fn rejects_mixed_positional_and_sequential_arguments() {
        let parsed = parse_printf_format("%2$d %s");
        assert!(!parsed.complete);
    }

    #[test]
    fn rejects_incomplete_and_unknown_directives() {
        assert!(!parse_printf_format("unfinished%").complete);
        assert!(!parse_printf_format("%q").complete);
    }

    #[test]
    fn escaped_percent_consumes_no_argument() {
        let parsed = parse_printf_format("100%%");
        assert!(parsed.complete);
        assert!(parsed.directives.is_empty());
        assert_eq!(parsed.required_arguments, 0);
    }
}
