//! Query-local consumers for the CSMI callable-values companion.
//!
//! The caller supplies exact identities and structured input evidence from its
//! own analysis. This module does not establish artifact validity, source
//! aliases, or execution.

use std::convert::Infallible;

use brokk_bifrost_core::cancellation::CancellationToken;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesRemapError;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesShape;

use crate::analyzer::semantic_model::csmi::CsmiCallableValuesUnsupportedProjection;

use crate::analyzer::semantic_model::csmi::CsmiCoverageStatus;

use crate::analyzer::semantic_model::csmi::CsmiInputLocation;

use crate::analyzer::semantic_model::model::CallableValuesCoverage;

use crate::analyzer::semantic_model::model::CallableValuesFact;

use crate::analyzer::semantic_model::model::CallableValuesFamily;

use crate::analyzer::semantic_model::model::CallableValuesPayload;

#[derive(Debug, Clone, Copy)]
pub struct CallableValuesQueryLimits {
    /// Maximum facts and coverage rows examined by one query.
    pub max_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallableValuesGap {
    Cancelled,
    RecordBudgetExhausted { max_records: usize },
    UnsupportedProjection(CsmiCallableValuesUnsupportedProjection),
}

#[derive(Debug)]
pub struct CallableValuesQuery<'a> {
    /// All matching records are retained as alternatives; no winner is chosen.
    pub facts: Vec<&'a CallableValuesFact>,
    /// Producer-declared coverage claims are retained independently by scope.
    pub coverage_claims: Vec<&'a CallableValuesCoverage>,
    /// Raw authored coverage is not execution evidence. This remains Unknown
    /// until a consumer joins validated artifact and target-shape evidence.
    pub executable_coverage: CsmiCoverageStatus,
    pub gap: Option<CallableValuesGap>,
}

/// Caller-proven evidence for one callback observation. The type carries no
/// boolean assertion of artifact validation; its producer owns that proof.
#[derive(Debug, Clone, Copy)]
pub struct CallableInvocationEvidence<'a> {
    pub callback: &'a CsmiInputLocation,
    pub target_shape: CsmiCallableValuesShape,
}

/// Find every returned-callable alternative for the exact native callable and
/// result ordinal, alongside independently scoped coverage.
pub fn returned_callable_targets<'a>(
    payload: &'a CallableValuesPayload,
    callable: &str,
    result: u32,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> CallableValuesQuery<'a> {
    query_returned_targets(payload, callable, result, limits, cancellation)
}

/// Match callback facts only when both the exact structured input location and
/// the caller-supplied target shape agree. Unknown arguments remain on the
/// returned fact unchanged; this query does not infer their values.
pub fn callback_invocations<'a>(
    payload: &'a CallableValuesPayload,
    callable: &str,
    evidence: CallableInvocationEvidence<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> CallableValuesQuery<'a> {
    let mut result = CallableValuesQuery {
        facts: Vec::new(),
        coverage_claims: Vec::new(),
        executable_coverage: CsmiCoverageStatus::Unknown,
        gap: None,
    };
    let mut examined = 0;
    if cancellation.is_cancelled() {
        result.gap = Some(CallableValuesGap::Cancelled);
        return result;
    }
    for fact in &payload.facts {
        if cancellation.is_cancelled() {
            result.gap = Some(CallableValuesGap::Cancelled);
            break;
        }
        if examined == limits.max_records {
            result.gap = Some(CallableValuesGap::RecordBudgetExhausted {
                max_records: limits.max_records,
            });
            break;
        }
        examined += 1;
        let CsmiCallableValuesPayload::CallbackInvocation {
            callable: fact_callable,
            callback,
            shape,
            ..
        } = &fact.payload
        else {
            continue;
        };
        if fact_callable != callable || shape != &evidence.target_shape {
            continue;
        }
        if let Err(CsmiCallableValuesRemapError::UnsupportedProjection(error)) =
            validate_profile_locations(&fact.payload)
        {
            result.gap = Some(CallableValuesGap::UnsupportedProjection(error));
            break;
        }
        if callback == evidence.callback {
            result.facts.push(fact);
        }
    }
    if result.gap.is_none() {
        collect_coverage(
            payload,
            CallableValuesFamily::CallbackInvocations,
            callable,
            limits.max_records,
            &mut examined,
            cancellation,
            &mut result,
        );
    }
    result
}

fn query_returned_targets<'a>(
    payload: &'a CallableValuesPayload,
    callable: &str,
    result_ordinal: u32,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> CallableValuesQuery<'a> {
    let mut result = CallableValuesQuery {
        facts: Vec::new(),
        coverage_claims: Vec::new(),
        executable_coverage: CsmiCoverageStatus::Unknown,
        gap: None,
    };
    let mut examined = 0;
    if cancellation.is_cancelled() {
        result.gap = Some(CallableValuesGap::Cancelled);
        return result;
    }
    for fact in &payload.facts {
        if cancellation.is_cancelled() {
            result.gap = Some(CallableValuesGap::Cancelled);
            break;
        }
        if examined == limits.max_records {
            result.gap = Some(CallableValuesGap::RecordBudgetExhausted {
                max_records: limits.max_records,
            });
            break;
        }
        examined += 1;
        if matches!(&fact.payload, CsmiCallableValuesPayload::ReturnedCallable {
            callable: fact_callable, result: fact_result, ..
        } if fact_callable == callable && *fact_result == result_ordinal)
        {
            result.facts.push(fact);
        }
    }
    if result.gap.is_none() {
        collect_coverage(
            payload,
            CallableValuesFamily::ReturnedCallables,
            callable,
            limits.max_records,
            &mut examined,
            cancellation,
            &mut result,
        );
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivatedCallableValuesGap {
    Cancelled,
    RecordBudgetExhausted,
    FactoryUnbound,
    TargetArtifactMismatch,
    Catalog(crate::analyzer::semantic_model::CatalogCallableValuesQueryGap),
}

fn collect_coverage<'a>(
    payload: &'a CallableValuesPayload,
    family: CallableValuesFamily,
    callable: &str,
    max_records: usize,
    examined: &mut usize,
    cancellation: &CancellationToken,
    result: &mut CallableValuesQuery<'a>,
) {
    for coverage in &payload.coverage {
        if cancellation.is_cancelled() {
            result.gap = Some(CallableValuesGap::Cancelled);
            return;
        }
        if *examined == max_records {
            result.gap = Some(CallableValuesGap::RecordBudgetExhausted { max_records });
            return;
        }
        *examined += 1;
        if coverage.family == family && coverage.callable == callable {
            result.coverage_claims.push(coverage);
        }
    }
}

fn validate_profile_locations(
    payload: &CsmiCallableValuesPayload,
) -> Result<(), CsmiCallableValuesRemapError<Infallible>> {
    let mut copy = payload.clone();
    copy.remap_symbols(|symbol| Ok::<_, Infallible>(symbol.to_owned()))
}
