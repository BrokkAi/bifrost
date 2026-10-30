//! Structured procedure-local property reaching definitions.
//!
//! This projection deliberately starts from the value-flow oracle.  The
//! oracle owns receiver alias identity, access paths, evidence quality, and
//! strong-update certificates; this module only supplies the property-shaped
//! gen/kill relation and the source-facing view used by consumers.

use crate::analyzer::semantic::oracle::{OracleCallContext, ValueFlowOracle};
use crate::analyzer::semantic::provider::{SemanticBudget, SemanticRequest};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
pub use brokk_bifrost_semantic::analyzer::semantic::property_reaching::*;
use std::collections::HashSet;
impl PropertyReachingProvider for crate::analyzer::MultiAnalyzer {
    fn property_reaching_for_source_range(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
        limits: PropertyReachingLimits,
        cancellation: &CancellationToken,
    ) -> PropertySourceQueryResult {
        property_source_query(self, file, range, limits, cancellation)
    }
}

pub(crate) fn property_source_query(
    analyzer: &crate::analyzer::MultiAnalyzer,
    file: &ProjectFile,
    range: &crate::analyzer::Range,
    limits: PropertyReachingLimits,
    cancellation: &CancellationToken,
) -> PropertySourceQueryResult {
    if cancellation.is_cancelled() {
        return PropertySourceQueryResult::from_parts(
            Vec::new(),
            Vec::new(),
            vec![PropertySourceQueryIncompleteReason::Cancelled],
            Vec::new(),
        );
    }
    let workspace = WorkspaceAnalyzer::Multi(Box::new(analyzer.clone()));
    // A property query owns its allotment. Its answer must not depend on the
    // consuming policy's remaining continuation budget; typed exhaustion is
    // retained below and refuses execution-independent reuse.
    let mut semantic_budget = SemanticBudget::default();
    let mut semantic_request = SemanticRequest::new(&mut semantic_budget, cancellation);
    let artifact_outcome =
        match workspace.materialize_program_semantics(file, &mut semantic_request) {
            Ok(outcome) => outcome,
            Err(error) => {
                return PropertySourceQueryResult::from_parts(
                    Vec::new(),
                    Vec::new(),
                    vec![PropertySourceQueryIncompleteReason::MaterializationFailure(
                        error,
                    )],
                    Vec::new(),
                );
            }
        };
    let mut incomplete_reasons = Vec::new();
    if let Some(state) = source_query_state(&artifact_outcome) {
        incomplete_reasons.push(PropertySourceQueryIncompleteReason::Materialization(state));
    }
    let Some(artifact) = artifact_outcome.available_value().cloned() else {
        return PropertySourceQueryResult::from_parts(
            Vec::new(),
            Vec::new(),
            incomplete_reasons,
            Vec::new(),
        );
    };
    let start_byte = u32::try_from(range.start_byte).expect("source offsets fit semantic IDs");
    let end_byte = u32::try_from(range.end_byte).expect("source offsets fit semantic IDs");
    let mut matches = Vec::new();
    let mut control_reaching_stores = Vec::new();
    let mut evaluations = HashSet::new();
    let mut evaluation_incomplete_reasons = Vec::new();
    let oracle = workspace.semantic_oracle_provider();
    for procedure in artifact.procedures() {
        if cancellation.is_cancelled() {
            incomplete_reasons.push(PropertySourceQueryIncompleteReason::Cancelled);
            break;
        }
        let contains_range = procedure.source_mappings().iter().any(|mapping| {
            let span = mapping.locator.anchor().span();
            span.start_byte() <= start_byte && span.end_byte() >= end_byte
        });
        if !contains_range {
            continue;
        }
        let procedure_handle = artifact
            .procedure_handle(procedure.id())
            .expect("materialized procedure has a scoped handle");
        match control_reaching_field_stores(
            &procedure_handle,
            start_byte,
            end_byte,
            limits,
            cancellation,
        ) {
            Ok(stores) => control_reaching_stores.extend(stores),
            Err(error) => {
                incomplete_reasons.push(PropertySourceQueryIncompleteReason::ControlFlow(error))
            }
        }
        let Some(_active) = ActivePropertyProcedure::enter(&procedure_handle) else {
            incomplete_reasons.push(PropertySourceQueryIncompleteReason::RecursiveProcedure(
                procedure.id(),
            ));
            continue;
        };
        let relation_outcome = match oracle.procedure_relations(
            &procedure_handle,
            &OracleCallContext::default(),
            &mut semantic_request,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                incomplete_reasons.push(
                    PropertySourceQueryIncompleteReason::MaterializationFailure(error),
                );
                continue;
            }
        };
        if let Some(state) = source_query_state(&relation_outcome) {
            incomplete_reasons.push(PropertySourceQueryIncompleteReason::ProcedureRelations(
                state,
            ));
        }
        let Some(snapshot) = relation_outcome.available_value() else {
            continue;
        };
        let projected = derive_property_reaching(snapshot, limits, cancellation);
        if let Some(source_result) = projected.for_source_bytes(start_byte, end_byte) {
            matches.push(source_result);
        }
        evaluations.extend(
            projected
                .evaluations_for_source_bytes(start_byte, end_byte)
                .into_vec(),
        );
        evaluation_incomplete_reasons
            .extend(projected.evaluation_incomplete_reasons().iter().cloned());
        incomplete_reasons.extend(
            projected
                .incomplete_reasons()
                .iter()
                .cloned()
                .map(|reason| {
                    PropertySourceQueryIncompleteReason::PropertyProjection(Box::new(reason))
                }),
        );
        if !projected.is_complete() {
            incomplete_reasons
                .push(PropertySourceQueryIncompleteReason::PropertyProjectionIncomplete);
        }
    }
    if matches.is_empty() {
        incomplete_reasons.push(PropertySourceQueryIncompleteReason::Unknown);
    }
    if evaluations.is_empty() {
        evaluation_incomplete_reasons
            .push(PropertyReachingIncompleteReason::EvaluationSourceUnknown);
    }
    let mut evaluations = evaluations.into_iter().collect::<Vec<_>>();
    evaluations.sort_by_key(|relation| {
        (
            relation.establishment.point.id(),
            relation.establishment.event_index,
            relation.read.point.id(),
            relation.read.event_index,
        )
    });
    let mut result = PropertySourceQueryResult::from_parts(
        matches,
        evaluations,
        incomplete_reasons,
        evaluation_incomplete_reasons,
    );
    result.control_reaching_stores = control_reaching_stores.into_boxed_slice();
    result
}
