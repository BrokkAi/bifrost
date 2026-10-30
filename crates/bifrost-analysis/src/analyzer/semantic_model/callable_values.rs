//! Query-local consumers for the CSMI callable-values companion.
//!
//! The caller supplies exact identities and structured input evidence from its
//! own analysis. This module does not establish artifact validity, source
//! aliases, or execution.

use crate::CancellationToken;
use crate::analyzer::semantic_model::csmi::CsmiCoverageStatus;
pub use brokk_bifrost_semantic::analyzer::semantic_model::callable_values::*;
/// One demand-scoped SQL result joined to the exact active publishing shard.
/// Catalog availability is not activation and authored coverage is not an
/// observation of callback execution.
#[derive(Debug)]
pub struct ActivatedCallableValuesRows {
    pub shard: std::sync::Arc<crate::analyzer::semantic_model::ActiveSemanticModelShard>,
    pub rows: crate::analyzer::semantic_model::CatalogCallableValuesQueryResult,
}

#[derive(Debug)]
pub struct ActivatedCallableValuesQuery {
    pub publications: Vec<ActivatedCallableValuesRows>,
    pub executable_coverage: CsmiCoverageStatus,
    pub gap: Option<ActivatedCallableValuesGap>,
}

/// Read returned-callable contracts for an already resolver-bound factory.
/// The factory must belong to this activation and carry exact artifact proof.
/// All selected publishing shards are consulted; competing contracts survive.
pub fn activated_returned_callable_targets(
    _catalog: &crate::analyzer::semantic_model::SemanticPackCatalog,
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
    factory: &crate::analyzer::semantic_model::SemanticModelSymbol,
    result: u32,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery, crate::analyzer::semantic_model::CatalogError> {
    let reader = active
        .source_reader()
        .ok_or(crate::analyzer::semantic_model::CatalogError::Unavailable)?;
    activated_returned_callable_targets_from_reader(
        reader,
        active,
        factory,
        result,
        limits,
        cancellation,
    )
}

/// Read returned-callable contracts through the fixed runtime source reader
/// retained by native dispatch. The activation, publication, and exact
/// artifact checks are identical to [`activated_returned_callable_targets`].
pub fn activated_returned_callable_targets_from_reader(
    reader: &crate::analyzer::semantic_model::CatalogRuntimeSourceReader,
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
    factory: &crate::analyzer::semantic_model::SemanticModelSymbol,
    result: u32,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery, crate::analyzer::semantic_model::CatalogError> {
    query_activated_callable_values(
        reader,
        active,
        factory,
        crate::analyzer::semantic_model::CatalogCallableValuesQuestion::ReturnedCallable { result },
        limits,
        cancellation,
    )
}

/// Read during-call invocation contracts using exact structured callback input
/// and shape evidence. This does not promote a partial heap observation or a
/// contract's May invocation into an observed invocation.
pub fn activated_callback_invocations(
    _catalog: &crate::analyzer::semantic_model::SemanticPackCatalog,
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
    factory: &crate::analyzer::semantic_model::SemanticModelSymbol,
    evidence: CallableInvocationEvidence<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery, crate::analyzer::semantic_model::CatalogError> {
    let reader = active
        .source_reader()
        .ok_or(crate::analyzer::semantic_model::CatalogError::Unavailable)?;
    activated_callback_invocations_from_reader(
        reader,
        active,
        factory,
        evidence,
        limits,
        cancellation,
    )
}

/// Read callback invocation contracts through the fixed runtime source reader
/// retained by native dispatch. A contract's `May` modality remains authored
/// evidence until the native observation consumer independently proves an
/// actual invocation.
pub fn activated_callback_invocations_from_reader(
    reader: &crate::analyzer::semantic_model::CatalogRuntimeSourceReader,
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
    factory: &crate::analyzer::semantic_model::SemanticModelSymbol,
    evidence: CallableInvocationEvidence<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery, crate::analyzer::semantic_model::CatalogError> {
    query_activated_callable_values(
        reader,
        active,
        factory,
        crate::analyzer::semantic_model::CatalogCallableValuesQuestion::CallbackInvocation {
            callback: evidence.callback,
            shape: evidence.target_shape,
        },
        limits,
        cancellation,
    )
}

pub(crate) fn query_activated_callable_values(
    reader: &crate::analyzer::semantic_model::CatalogRuntimeSourceReader,
    active: &crate::analyzer::semantic_model::ResolvedActiveSemanticModels,
    factory: &crate::analyzer::semantic_model::SemanticModelSymbol,
    question: crate::analyzer::semantic_model::CatalogCallableValuesQuestion<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery, crate::analyzer::semantic_model::CatalogError> {
    let mut result = ActivatedCallableValuesQuery {
        publications: Vec::new(),
        executable_coverage: CsmiCoverageStatus::Unknown,
        gap: None,
    };
    if cancellation.is_cancelled() {
        result.gap = Some(ActivatedCallableValuesGap::Cancelled);
        return Ok(result);
    }
    let provenance = &factory.provenance;
    let artifact = provenance
        .activation
        .matched_evidence
        .artifact_sha256
        .as_deref();
    if provenance.active_model_set_hash != active.active_model_set_hash()
        || provenance.ambiguous
        || provenance.proof != crate::analyzer::semantic_model::SemanticModelProof::ExactArtifact
        || artifact.is_none()
        || provenance.activation.status != "active"
    {
        result.gap = Some(ActivatedCallableValuesGap::FactoryUnbound);
        return Ok(result);
    }
    let mut remaining = limits.max_records;
    let matched = active.members_with_id(&provenance.record_id);
    let charge = matched
        .candidates_examined
        .saturating_add(matched.fallback_candidates_examined);
    let Some(next) = remaining.checked_sub(charge) else {
        result.gap = Some(ActivatedCallableValuesGap::RecordBudgetExhausted);
        return Ok(result);
    };
    remaining = next;
    let mut bound = 0usize;
    for member in matched.records {
        if cancellation.is_cancelled() {
            result.gap = Some(ActivatedCallableValuesGap::Cancelled);
            return Ok(result);
        }
        if callable_publication_matches(&member.shard, factory)
            && matches!(
                member.record.member_kind,
                super::MemberKind::Constructor
                    | super::MemberKind::Method
                    | super::MemberKind::Function
            )
            && member.record.signature.is_some()
            && !member.shard.guard_excludes(member.record.guard.as_ref())
        {
            bound += 1;
        }
    }
    if bound != 1 {
        result.gap = Some(ActivatedCallableValuesGap::FactoryUnbound);
        return Ok(result);
    }
    for shard in active.shards() {
        if cancellation.is_cancelled() {
            result.gap = Some(ActivatedCallableValuesGap::Cancelled);
            break;
        }
        let Some(next) = remaining.checked_sub(1) else {
            result.gap = Some(ActivatedCallableValuesGap::RecordBudgetExhausted);
            break;
        };
        remaining = next;
        if !callable_publication_matches(&shard, factory) || !shard.has_callable_values {
            continue;
        }
        let request = crate::analyzer::semantic_model::CatalogCallableValuesQuery {
            manifest_digest: &shard.manifest.content_sha256,
            shard_id: shard.descriptor.shard_id.as_str(),
            callable: &provenance.record_id,
            question,
        };
        let rows = reader.query_callable_values(
            &request,
            crate::analyzer::semantic_model::CatalogCallableValuesQueryLimits {
                max_records: remaining,
            },
            cancellation,
        )?;
        remaining = remaining.saturating_sub(rows.examined_records);
        let target_mismatch = rows.facts.iter().any(|fact| {
            if fact
                .anonymous_callable
                .as_ref()
                .is_some_and(|identity| Some(identity.artifact_sha256.as_str()) != artifact)
            {
                // Keep the authored alternative and its exact provenance
                // intact. The consumer must reject this row as a join, while
                // callers still need to see the conflicting identity.
                true
            } else {
                false
            }
        });
        let gap = rows.gap.clone();
        result
            .publications
            .push(ActivatedCallableValuesRows { shard, rows });
        if let Some(gap) = gap {
            result.gap = Some(ActivatedCallableValuesGap::Catalog(gap));
            break;
        }
        if target_mismatch && result.gap.is_none() {
            // Keep querying later active publications so independent
            // alternatives and conflicts remain visible to the consumer.
            result.gap = Some(ActivatedCallableValuesGap::TargetArtifactMismatch);
        }
    }
    Ok(result)
}

#[doc(hidden)]
pub fn callable_publication_matches(
    shard: &crate::analyzer::semantic_model::ActiveSemanticModelShard,
    factory: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> bool {
    let provenance = &factory.provenance;
    shard.manifest.semantic_sha256 == provenance.pack_digest
        && shard.manifest.pack_id == provenance.pack_id
        && shard.manifest.version == provenance.pack_version
        && shard.source_id == provenance.activation.source_id
        && crate::analyzer::semantic_model::overlay::matched_evidence(&shard.matched_evidence)
            == provenance.activation.matched_evidence
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::analyzer::semantic_model::callable_values::go_extraction_support_21::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::CallableInvocationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesCoverage;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFact;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFamily;

    use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::CallableValuesGap;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesPayload;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesPayload;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesShape;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesUnsupportedProjection;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCoverageStatus;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiInputLocation;

    use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::callback_invocations;

    use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::returned_callable_targets;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesArgument;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesModality;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesTiming;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiInputBoundaryRoot;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiInputParameterRoot;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiInputPhase;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiParameterRootRole;

    fn input(position: u32) -> CsmiInputLocation {
        CsmiInputLocation {
            root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                phase: CsmiInputPhase::Input,
                role: CsmiParameterRootRole::Parameter,
                position,
            }),
            projection: None,
        }
    }

    #[test]
    fn returned_targets_preserve_alternatives_and_scoped_coverage() {
        let payload = CallableValuesPayload {
            facts: ["target-a", "target-b"]
                .into_iter()
                .map(|target| CallableValuesFact {
                    payload: CsmiCallableValuesPayload::ReturnedCallable {
                        callable: "dial".into(),
                        result: 0,
                        target: target.into(),
                    },
                    provenance: vec!["reviewed".into()],
                })
                .collect(),
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: "dial".into(),
                status: CsmiCoverageStatus::Complete,
                limitations: Vec::new(),
                provenance: vec!["reviewed".into()],
            }],
            anonymous_callables: Vec::new(),
        };
        let found = returned_callable_targets(
            &payload,
            "dial",
            0,
            limits(8),
            &CancellationToken::default(),
        );
        assert_eq!(found.facts.len(), 2);
        assert_eq!(found.coverage_claims.len(), 1);
        assert_eq!(
            found.coverage_claims[0].status,
            CsmiCoverageStatus::Complete
        );
        assert_eq!(found.executable_coverage, CsmiCoverageStatus::Unknown);
        assert!(found.gap.is_none());
    }

    #[test]
    fn returned_targets_keep_missing_scope_and_bounded_scan_unknown() {
        let payload = CallableValuesPayload {
            facts: Vec::new(),
            coverage: Vec::new(),
            anonymous_callables: Vec::new(),
        };
        let missing = returned_callable_targets(
            &payload,
            "dial",
            0,
            limits(1),
            &CancellationToken::default(),
        );
        assert!(missing.coverage_claims.is_empty());
        assert_eq!(missing.executable_coverage, CsmiCoverageStatus::Unknown);

        let bounded = CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "dial".into(),
                    result: 0,
                    target: "target".into(),
                },
                provenance: Vec::new(),
            }],
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: "dial".into(),
                status: CsmiCoverageStatus::Complete,
                limitations: Vec::new(),
                provenance: Vec::new(),
            }],
            anonymous_callables: Vec::new(),
        };
        let found = returned_callable_targets(
            &bounded,
            "dial",
            0,
            limits(1),
            &CancellationToken::default(),
        );
        assert_eq!(found.facts.len(), 1);
        assert_eq!(found.coverage_claims.len(), 0);
        assert_eq!(found.executable_coverage, CsmiCoverageStatus::Unknown);
        assert_eq!(
            found.gap,
            Some(CallableValuesGap::RecordBudgetExhausted { max_records: 1 })
        );
    }

    #[test]
    fn callback_query_requires_exact_location_and_shape_and_preserves_unknown_arguments() {
        let shape = CsmiCallableValuesShape {
            parameters: 1,
            results: 0,
        };
        let payload = CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::CallbackInvocation {
                    callable: "handshake".into(),
                    callback: input(0),
                    shape,
                    arguments: vec![CsmiCallableValuesArgument::Unknown {
                        limitation:
                            brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesLimitation {
                                kind: "indeterminate".into(),
                                diagnostic: None,
                            },
                    }],
                    timing: CsmiCallableValuesTiming::DuringCall,
                    modality: CsmiCallableValuesModality::May,
                },
                provenance: Vec::new(),
            }],
            coverage: Vec::new(),
            anonymous_callables: Vec::new(),
        };
        let found = callback_invocations(
            &payload,
            "handshake",
            CallableInvocationEvidence {
                callback: &input(0),
                target_shape: shape,
            },
            limits(4),
            &CancellationToken::default(),
        );
        assert_eq!(found.facts.len(), 1);
        let near_miss = callback_invocations(
            &payload,
            "handshake",
            CallableInvocationEvidence {
                callback: &input(1),
                target_shape: shape,
            },
            limits(4),
            &CancellationToken::default(),
        );
        assert!(near_miss.facts.is_empty());
        assert_eq!(near_miss.executable_coverage, CsmiCoverageStatus::Unknown);
        let wrong_shape = callback_invocations(
            &payload,
            "handshake",
            CallableInvocationEvidence {
                callback: &input(0),
                target_shape: CsmiCallableValuesShape {
                    parameters: 2,
                    results: 0,
                },
            },
            limits(4),
            &CancellationToken::default(),
        );
        assert!(wrong_shape.facts.is_empty());
        assert!(matches!(&found.facts[0].payload,
            CsmiCallableValuesPayload::CallbackInvocation { arguments, .. }
            if matches!(arguments[0], CsmiCallableValuesArgument::Unknown { .. })));
        let mut unsupported = payload.clone();
        let CsmiCallableValuesPayload::CallbackInvocation { callback, .. } =
            &mut unsupported.facts[0].payload
        else {
            unreachable!()
        };
        callback.projection = Some(
            brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiProjection {
                scheme: "unsupported.location".into(),
                scheme_version: "0.1.0".into(),
                steps: Vec::new(),
            },
        );
        let unsupported = callback_invocations(
            &unsupported,
            "handshake",
            CallableInvocationEvidence {
                callback: &input(0),
                target_shape: shape,
            },
            limits(4),
            &CancellationToken::default(),
        );
        assert!(unsupported.facts.is_empty());
        assert!(matches!(
            unsupported.gap,
            Some(CallableValuesGap::UnsupportedProjection(
                CsmiCallableValuesUnsupportedProjection::Scheme(_)
            ))
        ));
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_21 {

    use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::CallableValuesQueryLimits;

    #[doc(hidden)]
    pub fn limits(max_records: usize) -> CallableValuesQueryLimits {
        CallableValuesQueryLimits { max_records }
    }
}
