//! Structured joins between authored configuration facts and code rows.
//!
//! This module owns the shared relation algorithm. Language-specific identity
//! remains in analyzer declarations: configuration scalars are compared with
//! fully qualified declaration identities, member joins use the indexed owner,
//! and same-project joins compare project roots. No source-text lookup is used.

use super::configuration::ScalarValue;
use super::cross_domain::{
    CrossDomainBinding, CrossDomainValue, cross_domain_diagnostic, plan_rows_budget,
};
use super::*;
use crate::query::{ConfigurationCodeMatch, ConfigurationCodeRelation};
use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationFact, ConfigurationFactId, ConfigurationNodeKind,
};

enum JoinDecision {
    Match,
    NoMatch,
    Incomplete(String),
}

fn fact_value_at(value: &ConfigurationFactValue, index: usize) -> ConfigurationFactValue {
    ConfigurationFactValue {
        file: value.file.clone(),
        document: Arc::clone(&value.document),
        source: Arc::clone(&value.source),
        index,
    }
}

fn child_indices(
    value: &ConfigurationFactValue,
    parent: usize,
) -> impl Iterator<Item = usize> + '_ {
    let parent = ConfigurationFactId::new(parent).expect("configuration fact index is bounded");
    value
        .document
        .facts()
        .iter()
        .enumerate()
        .filter(move |(_, fact)| fact.parent() == Some(parent))
        .map(|(index, _)| index)
}

fn member_key(value: &ConfigurationFactValue) -> Option<&str> {
    match value.fact().kind() {
        ConfigurationNodeKind::Member { key, .. } => Some(key.text()),
        _ => None,
    }
}

fn section_for_member(value: &ConfigurationFactValue) -> Option<usize> {
    let ConfigurationNodeKind::Member { value: child, .. } = value.fact().kind() else {
        return None;
    };
    let child = (*child)?.index();
    Some(child)
}

/// The scalar of the first `key` member of `section` that holds one. An
/// undecodable scalar is returned as such, never skipped for a later member.
fn member_value_in_section(
    value: &ConfigurationFactValue,
    section: usize,
    key: &str,
) -> ScalarValue {
    child_indices(value, section)
        .map(|index| fact_value_at(value, index))
        .filter(|candidate| member_key(candidate) == Some(key))
        .map(|candidate| candidate.scalar_value())
        .find(|scalar| !matches!(scalar, ScalarValue::Absent))
        .unwrap_or(ScalarValue::Absent)
}

/// The class member of the nearest enclosing XML/object section carrying one.
fn enclosing_class(value: &ConfigurationFactValue) -> ScalarValue {
    let mut current = Some(value.index);
    while let Some(index) = current {
        let class_name = member_value_in_section(value, index, "class");
        if !matches!(class_name, ScalarValue::Absent) {
            return class_name;
        }
        current = value
            .document
            .facts()
            .get(index)
            .and_then(ConfigurationFact::parent)
            .map(|id| id.index());
    }
    ScalarValue::Absent
}

/// The nearest `name` property at or above the fact. An undecodable `name`
/// is returned as such, never skipped for an outer one.
fn property_name(value: &ConfigurationFactValue) -> ScalarValue {
    let mut current = Some(value.index);
    while let Some(index) = current {
        let candidate = fact_value_at(value, index);
        if member_key(&candidate) == Some("name") {
            let name = candidate.scalar_value();
            if !matches!(name, ScalarValue::Absent) {
                return name;
            }
        }
        if let Some(section) = section_for_member(&candidate) {
            let name = member_value_in_section(value, section, "name");
            if !matches!(name, ScalarValue::Absent) {
                return name;
            }
        }
        current = value
            .document
            .facts()
            .get(index)
            .and_then(ConfigurationFact::parent)
            .map(|id| id.index());
    }
    ScalarValue::Absent
}

/// The generic member-name transform used by `scalar-member`: capitalize the
/// first Unicode scalar and prepend `set`. This keeps the relation independent
/// of a framework while allowing policies to express conventional setter
/// naming from a decoded configuration property value.
fn transformed_member_name(property: &str) -> Option<String> {
    let mut chars = property.chars();
    let first = chars.next()?;
    let mut name = String::from("set");
    name.extend(first.to_uppercase());
    name.extend(chars);
    Some(name)
}

fn owner_for_declaration(
    state: &mut QueryExecutionState<'_>,
    declaration: &DeclarationValue,
    work: &mut usize,
    max_work: usize,
) -> Result<Option<DeclarationValue>, bool> {
    let (owner, exhausted) =
        state
            .indexed_declarations
            .owner_of(state.analyzer, &declaration.unit, work, max_work);
    if exhausted { Err(true) } else { Ok(owner) }
}

fn undecodable_scalar(configuration: &ConfigurationFactValue) -> JoinDecision {
    JoinDecision::Incomplete(format!(
        "configuration scalar in {} could not be decoded",
        rel_path_string(configuration.file())
    ))
}

fn matches_declaration(
    relation: ConfigurationCodeMatch,
    configuration: &ConfigurationFactValue,
    declaration: &DeclarationValue,
    state: &mut QueryExecutionState<'_>,
    owner_work: &mut usize,
    owner_work_limit: usize,
) -> JoinDecision {
    match relation {
        // A scalar the decoder could not read is neither a match nor a
        // non-match, so an absence relation cannot claim it.
        ConfigurationCodeMatch::ScalarDeclaration => match configuration.scalar_value() {
            ScalarValue::Decoded(value) if value == declaration.unit.fq_name_str() => {
                JoinDecision::Match
            }
            ScalarValue::Undecodable => undecodable_scalar(configuration),
            ScalarValue::Decoded(_) | ScalarValue::Absent => JoinDecision::NoMatch,
        },
        ConfigurationCodeMatch::ScalarOwner => {
            let owner =
                match owner_for_declaration(state, declaration, owner_work, owner_work_limit) {
                    Ok(owner) => owner,
                    Err(true) => {
                        return JoinDecision::Incomplete(
                            "owner lookup exceeded the bounded declaration work budget".to_string(),
                        );
                    }
                    Err(false) => unreachable!("owner lookup only reports true exhaustion"),
                };
            match (configuration.scalar_value(), owner) {
                (ScalarValue::Undecodable, _) => undecodable_scalar(configuration),
                (ScalarValue::Decoded(value), Some(owner)) if value == owner.unit.fq_name_str() => {
                    JoinDecision::Match
                }
                _ => JoinDecision::NoMatch,
            }
        }
        ConfigurationCodeMatch::ScalarMember => {
            let property = match property_name(configuration) {
                ScalarValue::Decoded(property) => property,
                ScalarValue::Undecodable => return undecodable_scalar(configuration),
                ScalarValue::Absent => return JoinDecision::NoMatch,
            };
            let Some(expected_member) = transformed_member_name(&property) else {
                return JoinDecision::NoMatch;
            };
            if !declaration.unit.is_callable() || declaration.unit.identifier() != expected_member {
                return JoinDecision::NoMatch;
            }
            let class_name = match enclosing_class(configuration) {
                ScalarValue::Decoded(class_name) => class_name,
                ScalarValue::Undecodable => return undecodable_scalar(configuration),
                ScalarValue::Absent => return JoinDecision::NoMatch,
            };
            let owner =
                match owner_for_declaration(state, declaration, owner_work, owner_work_limit) {
                    Ok(owner) => owner,
                    Err(true) => {
                        return JoinDecision::Incomplete(
                            "setter owner lookup exceeded the bounded declaration work budget"
                                .to_string(),
                        );
                    }
                    Err(false) => unreachable!("owner lookup only reports true exhaustion"),
                };
            match owner {
                Some(owner) if owner.unit.fq_name_str() == class_name => JoinDecision::Match,
                _ => JoinDecision::NoMatch,
            }
        }
        ConfigurationCodeMatch::SameProject => {
            unreachable!("same-project is evaluated without a declaration row")
        }
    }
}

fn matches_same_project(configuration: &ConfigurationFactValue, code: &PipelineValue) -> bool {
    code_row_file(code).root() == configuration.file.root()
}

fn config_key(relation: ConfigurationCodeMatch, value: &ConfigurationFactValue) -> String {
    match relation {
        ConfigurationCodeMatch::SameProject => "same-project".to_string(),
        _ => value
            .scalar_value()
            .decoded()
            .unwrap_or_else(|| value.route()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    relation: &ConfigurationCodeRelation,
    code: PlanExecution,
    configuration: PlanExecution,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let mut truncated = code.is_truncated() || configuration.is_truncated();
    let desired_rows = plan_rows_budget(terminal_cap, state, limits);
    let owner_work_limit = limits.max_pipeline_rows.saturating_mul(64).max(1_024);
    let mut owner_work = 0;
    let mut incomplete_reasons = Vec::new();
    let mut rows = Vec::new();
    let mut indexes = HashMap::default();

    for configuration_row in &configuration.rows {
        let PipelineValue::ConfigurationFact(configuration_fact) = &configuration_row.value else {
            unreachable!("validated configuration-code inputs produce configuration facts");
        };
        let configuration_complete = configuration_fact.document.completeness().is_complete();
        let mut matched = false;
        let mut configuration_incomplete = !configuration_complete;

        for code_row in &code.rows {
            let decision = match relation.match_kind {
                ConfigurationCodeMatch::SameProject => {
                    if matches_same_project(configuration_fact, &code_row.value) {
                        JoinDecision::Match
                    } else {
                        JoinDecision::NoMatch
                    }
                }
                _ => {
                    let PipelineValue::Declaration(declaration) = &code_row.value else {
                        unreachable!(
                            "validated configuration-code declaration relation inputs produce declarations"
                        );
                    };
                    matches_declaration(
                        relation.match_kind,
                        configuration_fact,
                        declaration,
                        state,
                        &mut owner_work,
                        owner_work_limit,
                    )
                }
            };
            match decision {
                JoinDecision::Match => {
                    matched = true;
                    if relation.absence {
                        break;
                    }
                    if rows.len() >= desired_rows {
                        truncated = true;
                        break;
                    }
                    let key = config_key(relation.match_kind, configuration_fact);
                    let binding = CrossDomainBinding::Unique;
                    state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
                    let traces = configuration_row
                        .traces
                        .iter()
                        .chain(&code_row.traces)
                        .cloned()
                        .collect();
                    insert_pipeline_row(
                        &mut rows,
                        &mut indexes,
                        PipelineValue::CrossDomain(Box::new(CrossDomainValue::ConfigurationCode {
                            code: Box::new(code_row.value.clone()),
                            configuration: configuration_fact.clone(),
                            key,
                            binding,
                        })),
                        traces,
                        configuration_row.provenance_truncated || code_row.provenance_truncated,
                    );
                }
                JoinDecision::NoMatch => {}
                JoinDecision::Incomplete(reason) => {
                    configuration_incomplete = true;
                    incomplete_reasons.push(reason);
                }
            }
            if truncated {
                break;
            }
        }

        if relation.absence && !matched && !configuration_incomplete && !code.is_truncated() {
            if rows.len() >= desired_rows {
                truncated = true;
                break;
            }
            state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
            let key = config_key(relation.match_kind, configuration_fact);
            insert_pipeline_row(
                &mut rows,
                &mut indexes,
                PipelineValue::CrossDomain(Box::new(CrossDomainValue::ConfigurationCodeAbsent {
                    configuration: configuration_fact.clone(),
                    key,
                })),
                configuration_row.traces.clone(),
                configuration_row.provenance_truncated,
            );
        }
        if truncated {
            break;
        }
    }

    if relation.absence && (code.is_truncated() || configuration.is_truncated()) {
        incomplete_reasons.push(
            "configuration-code anti-join inputs were truncated, so absence is not provable"
                .to_string(),
        );
    }
    incomplete_reasons.sort();
    incomplete_reasons.dedup();
    if !incomplete_reasons.is_empty() {
        diagnostics.push(QueryExecutionState::diagnostic(state.analyzer, cross_domain_diagnostic(
            CodeQueryDiagnosticCode::CrossDomainDocumentIncomplete,
            CodeQueryDiagnosticImpact::Incomplete,
            format!(
                "configuration_code retained no negative claim for incomplete inputs: {incomplete_reasons:?}"
            ),
        ), (relation.absence && (code.is_truncated() || configuration.is_truncated())).then_some(DerivationExecutionCause::Budget)));
    }

    PlanExecution::new(rows, truncated)
}
