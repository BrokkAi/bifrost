//! Query projection of typed, AST-owned C++ expression facts.

use super::results::{CodeQueryCppExpression, CodeQueryRange};
use super::*;
use brokk_bifrost_core::analyzer::cpp_facts::CppExpressionFact;
use brokk_bifrost_core::analyzer::cpp_facts::CppExpressionSourceFacts;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(super) struct CppExpressionValue {
    pub(super) row: CodeQueryCppExpression,
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
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

fn row(
    seed: &SeedMatch,
    facts: &CppExpressionSourceFacts,
    fact: &CppExpressionFact,
) -> CppExpressionValue {
    let range = facts.source.occurrence(fact.occurrence).range;
    let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
        b"bifrost.code_query.cpp_expression.v1",
    );
    digest.push(rel_path_string(&seed.file).as_bytes());
    digest.push(&(range.start_byte as u64).to_le_bytes());
    digest.push(&(range.end_byte as u64).to_le_bytes());
    digest.push(fact.kind.label().as_bytes());
    digest.push(&(fact.occurrence.get() as u64).to_le_bytes());
    CppExpressionValue {
        row: CodeQueryCppExpression {
            id: digest.finish().to_string(),
            path: rel_path_string(&seed.file),
            language: seed.language.config_label(),
            range: public_range(seed, range),
            kind: fact.kind.label(),
            name: fact.name.clone(),
            type_text: fact.type_text.clone(),
            type_form: fact.type_form.label(),
            signedness: fact.signedness.label(),
            width_bits: fact.width_bits,
            literal_text: fact.literal_text.clone(),
            integer_value: fact.integer_value.map(|value| value.to_string()),
            array_extent: fact.array_extent,
            array_is_reference: fact.array_is_reference,
            parameter_by_value: fact.parameter_by_value,
            bit_field_width: fact.bit_field_width,
            bit_field_anonymous: fact.bit_field_anonymous,
            enum_scoped: fact.enum_scoped,
            enum_ordinal: fact.enum_ordinal,
            enum_value: fact.enum_value.map(|value| value.to_string()),
            has_initializer: fact.has_initializer,
            enum_has_implicit_before_nonreference: fact.enum_has_implicit_before_nonreference,
            return_top_level_const: fact.return_top_level_const,
            member_function: fact.member_function,
            member_function_const: fact.member_function_const,
            type_size_bytes: fact.type_size_bytes,
            type_size_exact: fact.type_size_exact,
            sizeof_operand_kind: fact.sizeof_operand_kind.map(|kind| kind.label()),
            sizeof_operand_is_parameter: fact.sizeof_operand_is_parameter,
            sizeof_has_side_effect: fact.sizeof_has_side_effect,
            loop_has_short_ancestor: fact.loop_has_short_ancestor,
            completeness: fact.completeness.label(),
            completeness_reason: fact.completeness_reason.clone(),
        },
        file: seed.file.clone(),
        anchor: range,
    }
}

pub(super) fn expansions_for_seed(
    analyzer: &dyn IAnalyzer,
    cache: &mut HashMap<ProjectFile, Arc<CppExpressionSourceFacts>>,
    seed: &Arc<SeedMatch>,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Cpp {
        return Vec::new();
    }
    let facts = if let Some(facts) = cache.get(&seed.file).cloned() {
        facts
    } else {
        let Some(facts) = analyzer.cpp_expression_source_facts(&seed.file) else {
            return Vec::new();
        };
        cache.insert(seed.file.clone(), Arc::clone(&facts));
        facts
    };
    let anchor = seed.facts.node(seed.fact_match.node).range;
    facts
        .expressions
        .iter()
        .filter(|fact| {
            let range = facts.source.occurrence(fact.occurrence).range;
            range.start_byte >= anchor.start_byte && range.end_byte <= anchor.end_byte
        })
        .map(|fact| {
            pipeline_expansion(PipelineValue::CppExpression(Box::new(row(
                seed, &facts, fact,
            ))))
        })
        .collect()
}

pub(super) fn result_ref(value: &CppExpressionValue) -> CodeQueryResultRef {
    CodeQueryResultRef::CppExpression {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        kind: value.row.kind,
    }
}

pub(super) fn detailed_key(value: &CppExpressionValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::CppExpression {
        id: value.row.id.clone(),
    }
}
