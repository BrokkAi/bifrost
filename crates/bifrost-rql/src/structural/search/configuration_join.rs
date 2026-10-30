//! Structured joins between authored configuration facts and code rows.
//!
//! This module owns the shared relation algorithm. Language-specific identity
//! remains in analyzer declarations: configuration scalars are compared with
//! fully qualified declaration identities, member joins use the indexed owner,
//! and same-project joins compare project roots. No source-text lookup is used.

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

fn scalar_member(value: &ConfigurationFactValue, index: usize) -> Option<String> {
    let member = fact_value_at(value, index);
    member.scalar_value()
}

fn section_for_member(value: &ConfigurationFactValue) -> Option<usize> {
    let ConfigurationNodeKind::Member { value: child, .. } = value.fact().kind() else {
        return None;
    };
    let child = (*child)?.index();
    Some(child)
}

fn member_value_in_section(
    value: &ConfigurationFactValue,
    section: usize,
    key: &str,
) -> Option<(usize, String)> {
    child_indices(value, section).find_map(|index| {
        let candidate = fact_value_at(value, index);
        (member_key(&candidate) == Some(key))
            .then(|| scalar_member(value, index).map(|scalar| (index, scalar)))
            .flatten()
    })
}

/// Find the nearest enclosing XML/object section carrying a class member.
fn enclosing_class(value: &ConfigurationFactValue) -> Option<(usize, String)> {
    let mut current = Some(value.index);
    while let Some(index) = current {
        if let Some((_, class_name)) = member_value_in_section(value, index, "class") {
            return Some((index, class_name));
        }
        current = value
            .document
            .facts()
            .get(index)
            .and_then(ConfigurationFact::parent)
            .map(|id| id.index());
    }
    None
}

fn property_name(value: &ConfigurationFactValue) -> Option<String> {
    let mut current = Some(value.index);
    while let Some(index) = current {
        let candidate = fact_value_at(value, index);
        if member_key(&candidate) == Some("name")
            && let Some(name) = candidate.scalar_value()
        {
            return Some(name);
        }
        if let Some(section) = section_for_member(&candidate)
            && let Some((_, name)) = member_value_in_section(value, section, "name")
        {
            return Some(name);
        }
        current = value
            .document
            .facts()
            .get(index)
            .and_then(ConfigurationFact::parent)
            .map(|id| id.index());
    }
    None
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

fn matches_declaration(
    relation: ConfigurationCodeMatch,
    configuration: &ConfigurationFactValue,
    declaration: &DeclarationValue,
    state: &mut QueryExecutionState<'_>,
    owner_work: &mut usize,
    owner_work_limit: usize,
) -> JoinDecision {
    match relation {
        ConfigurationCodeMatch::ScalarDeclaration => {
            if configuration
                .scalar_value()
                .is_some_and(|value| value == declaration.unit.fq_name_str())
            {
                JoinDecision::Match
            } else {
                JoinDecision::NoMatch
            }
        }
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
                (Some(value), Some(owner)) if value == owner.unit.fq_name_str() => {
                    JoinDecision::Match
                }
                _ => JoinDecision::NoMatch,
            }
        }
        ConfigurationCodeMatch::ScalarMember => {
            let Some(property) = property_name(configuration) else {
                return JoinDecision::NoMatch;
            };
            let Some(expected_member) = transformed_member_name(&property) else {
                return JoinDecision::NoMatch;
            };
            if !declaration.unit.is_callable() || declaration.unit.identifier() != expected_member {
                return JoinDecision::NoMatch;
            }
            let Some((_, class_name)) = enclosing_class(configuration) else {
                return JoinDecision::NoMatch;
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
    terminal_source_file(code).is_some_and(|file| file.root() == configuration.file.root())
}

fn config_key(relation: ConfigurationCodeMatch, value: &ConfigurationFactValue) -> String {
    match relation {
        ConfigurationCodeMatch::SameProject => "same-project".to_string(),
        _ => value.scalar_value().unwrap_or_else(|| value.route()),
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
    let mut truncated = code.truncated || configuration.truncated;
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

        if relation.absence && !matched && !configuration_incomplete && !code.truncated {
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

    if relation.absence && (code.truncated || configuration.truncated) {
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
        ), (relation.absence && (code.truncated || configuration.truncated)).then_some(DerivationExecutionCause::Budget)));
    }

    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}
