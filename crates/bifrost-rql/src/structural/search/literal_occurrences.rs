//! Query-local scalar literal occurrences (#3543 D4).
//!
//! The row is derived from the normalized facts arena, never from source-text
//! token matching. One selected literal produces one bounded row. The row
//! keeps an incomplete value visible when the language adapter cannot decode
//! the literal, so an unsupported decoder is never mistaken for zero rows.

use super::results::{CodeQueryLiteralOccurrence, CodeQueryRange};
use super::{PipelineExpansion, PipelineValue, SeedMatch, pipeline_expansion};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::structural::occurrence_rows::ast_id;
use crate::analyzer::{ProjectFile, Range};
use brokk_bifrost_core::analyzer::structural::facts::IntegerLiteralValue;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};

const LITERAL_OCCURRENCE_ID_DOMAIN: &[u8] = b"bifrost.code_query.literal_occurrence.v1";
const FILE_SCOPE_ID_DOMAIN: &[u8] = b"bifrost.code_query.literal_scope.file.v1";

#[derive(Debug, Clone)]
pub(super) struct LiteralOccurrenceValue {
    pub(super) row: CodeQueryLiteralOccurrence,
    pub(super) file: ProjectFile,
    pub(super) source_range: Range,
}

fn public_range(seed: &SeedMatch, range: Range) -> CodeQueryRange {
    let (start_line, start_column) = seed.facts.line_column_of_byte(range.start_byte);
    let (end_line, end_column) = seed.facts.line_column_of_byte(range.end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn file_scope_id(seed: &SeedMatch) -> String {
    let mut digest = LengthDelimitedDigest::new(FILE_SCOPE_ID_DOMAIN);
    digest.push(seed.facts.source_identity().as_bytes());
    digest.finish().to_string()
}

fn scope(seed: &SeedMatch, node: u32) -> (String, &'static str) {
    let mut parent = seed.facts.node(node).parent;
    while let Some(candidate) = parent {
        let kind = seed.facts.node(candidate).kind;
        if kind.satisfies(NormalizedKind::Callable) {
            return (ast_id(seed.facts.source_identity(), candidate), "callable");
        }
        if kind == NormalizedKind::Module {
            return (ast_id(seed.facts.source_identity(), candidate), "module");
        }
        parent = seed.facts.node(candidate).parent;
    }
    (file_scope_id(seed), "file")
}

fn call_argument_context(seed: &SeedMatch, node: u32) -> (Option<String>, Option<usize>) {
    let literal = seed.facts.node(node).range;
    let mut parent = seed.facts.node(node).parent;
    while let Some(candidate) = parent {
        if seed.facts.node(candidate).kind == NormalizedKind::Call {
            let mut argument_index = 0usize;
            for role in seed.facts.roles(candidate) {
                if role.role != Role::Arg {
                    continue;
                }
                let contains_literal = role.node == Some(node)
                    || (role.span.start_byte <= literal.start_byte
                        && literal.end_byte <= role.span.end_byte);
                if contains_literal {
                    return (
                        Some(ast_id(seed.facts.source_identity(), candidate)),
                        Some(argument_index),
                    );
                }
                argument_index = argument_index.saturating_add(1);
            }
        }
        parent = seed.facts.node(candidate).parent;
    }
    (None, None)
}

fn literal_kind_and_identity(
    kind: NormalizedKind,
    string_value: Option<&str>,
    integer_value: Option<&IntegerLiteralValue>,
    boolean_value: Option<bool>,
) -> (&'static str, Option<String>) {
    match kind {
        NormalizedKind::StringLiteral => ("string", string_value.map(str::to_owned)),
        NormalizedKind::NumericLiteral => integer_value.map_or(("numeric", None), |value| {
            ("integer", value.signed_decimal())
        }),
        NormalizedKind::BooleanLiteral => (
            "boolean",
            boolean_value.map(|value| {
                if value {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                }
            }),
        ),
        NormalizedKind::NullLiteral => ("null", Some("null".to_owned())),
        NormalizedKind::CharacterLiteral => ("character", None),
        NormalizedKind::CollectionLiteral => ("collection", None),
        _ => ("unsupported", None),
    }
}

fn is_trivial(kind: &str, identity: Option<&str>) -> bool {
    matches!(
        (kind, identity),
        ("string", Some(""))
            | ("integer", Some("0" | "1" | "-1"))
            | ("boolean", Some("true" | "false"))
            | ("null", Some("null"))
    )
}

fn literal_id(seed: &SeedMatch) -> String {
    let mut digest = LengthDelimitedDigest::new(LITERAL_OCCURRENCE_ID_DOMAIN);
    digest.push(seed.facts.source_identity().as_bytes());
    digest.push(&seed.fact_match.node.to_le_bytes());
    digest.finish().to_string()
}

pub(super) fn expansions_for_seed(seed: &SeedMatch) -> Vec<PipelineExpansion> {
    let node_id = seed.fact_match.node;
    let node = seed.facts.node(node_id);
    if !node.kind.satisfies(NormalizedKind::Literal) {
        return Vec::new();
    }

    let (kind, identity) = literal_kind_and_identity(
        node.kind,
        node.string_value.as_deref(),
        node.integer_literal_value.as_ref(),
        node.boolean_value,
    );
    let (scope_id, scope_kind) = scope(seed, node_id);
    let (parent_call_id, argument_index) = call_argument_context(seed, node_id);
    let coverage = if identity.is_some() {
        "exact"
    } else {
        "incomplete"
    };
    let row = CodeQueryLiteralOccurrence {
        id: literal_id(seed),
        scope_id,
        scope_kind,
        path: crate::path_utils::rel_path_string(&seed.file),
        language: seed.language.config_label(),
        range: public_range(seed, node.range),
        kind,
        trivial: is_trivial(kind, identity.as_deref()),
        identity,
        coverage,
        parent_call_id,
        argument_index,
    };
    vec![pipeline_expansion(PipelineValue::LiteralOccurrence(
        LiteralOccurrenceValue {
            row,
            file: seed.file.clone(),
            source_range: node.range,
        },
    ))]
}
