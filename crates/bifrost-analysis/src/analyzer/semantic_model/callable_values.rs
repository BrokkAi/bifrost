//! Query-local consumers for the CSMI callable-values companion.
//!
//! The caller supplies exact identities and structured input evidence from its
//! own analysis. This module does not establish artifact validity, source
//! aliases, or execution.

use std::convert::Infallible;

use crate::CancellationToken;

use super::csmi::{
    CsmiCallableValuesPayload, CsmiCallableValuesRemapError, CsmiCallableValuesShape,
    CsmiCallableValuesUnsupportedProjection, CsmiCoverageStatus, CsmiInputLocation,
};
use super::model::{
    CallableValuesCoverage, CallableValuesFact, CallableValuesFamily, CallableValuesPayload,
};

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

/// One demand-scoped SQL result joined to the exact active publishing shard.
/// Catalog availability is not activation and authored coverage is not an
/// observation of callback execution.
#[derive(Debug)]
pub struct ActivatedCallableValuesRows<'a> {
    pub shard: &'a super::ActiveSemanticModelShard,
    pub rows: super::CatalogCallableValuesQueryResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivatedCallableValuesGap {
    Cancelled,
    RecordBudgetExhausted,
    FactoryUnbound,
    TargetArtifactMismatch,
    Catalog(super::CatalogCallableValuesQueryGap),
}

#[derive(Debug)]
pub struct ActivatedCallableValuesQuery<'a> {
    pub publications: Vec<ActivatedCallableValuesRows<'a>>,
    pub executable_coverage: CsmiCoverageStatus,
    pub gap: Option<ActivatedCallableValuesGap>,
}

/// Read returned-callable contracts for an already resolver-bound factory.
/// The factory must belong to this activation and carry exact artifact proof.
/// All selected publishing shards are consulted; competing contracts survive.
pub fn activated_returned_callable_targets<'a>(
    catalog: &super::SemanticPackCatalog,
    active: &'a super::ResolvedActiveSemanticModels,
    factory: &super::SemanticModelSymbol,
    result: u32,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery<'a>, super::CatalogError> {
    let reader = catalog.runtime_source_reader();
    activated_returned_callable_targets_from_reader(
        &reader,
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
pub fn activated_returned_callable_targets_from_reader<'a>(
    reader: &super::CatalogRuntimeSourceReader,
    active: &'a super::ResolvedActiveSemanticModels,
    factory: &super::SemanticModelSymbol,
    result: u32,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery<'a>, super::CatalogError> {
    query_activated_callable_values(
        reader,
        active,
        factory,
        super::CatalogCallableValuesQuestion::ReturnedCallable { result },
        limits,
        cancellation,
    )
}

/// Read during-call invocation contracts using exact structured callback input
/// and shape evidence. This does not promote a partial heap observation or a
/// contract's May invocation into an observed invocation.
pub fn activated_callback_invocations<'a>(
    catalog: &super::SemanticPackCatalog,
    active: &'a super::ResolvedActiveSemanticModels,
    factory: &super::SemanticModelSymbol,
    evidence: CallableInvocationEvidence<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery<'a>, super::CatalogError> {
    let reader = catalog.runtime_source_reader();
    activated_callback_invocations_from_reader(
        &reader,
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
pub fn activated_callback_invocations_from_reader<'a>(
    reader: &super::CatalogRuntimeSourceReader,
    active: &'a super::ResolvedActiveSemanticModels,
    factory: &super::SemanticModelSymbol,
    evidence: CallableInvocationEvidence<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery<'a>, super::CatalogError> {
    query_activated_callable_values(
        reader,
        active,
        factory,
        super::CatalogCallableValuesQuestion::CallbackInvocation {
            callback: evidence.callback,
            shape: evidence.target_shape,
        },
        limits,
        cancellation,
    )
}

fn query_activated_callable_values<'a>(
    reader: &super::CatalogRuntimeSourceReader,
    active: &'a super::ResolvedActiveSemanticModels,
    factory: &super::SemanticModelSymbol,
    question: super::CatalogCallableValuesQuestion<'_>,
    limits: CallableValuesQueryLimits,
    cancellation: &CancellationToken,
) -> Result<ActivatedCallableValuesQuery<'a>, super::CatalogError> {
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
        || provenance.proof != super::SemanticModelProof::ExactArtifact
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
        if callable_publication_matches(member.shard, factory)
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
        if !callable_publication_matches(shard, factory) || shard.shard.callable_values().is_none()
        {
            continue;
        }
        let request = super::CatalogCallableValuesQuery {
            manifest_digest: &shard.manifest.content_sha256,
            shard_id: shard.shard.shard_id(),
            callable: &provenance.record_id,
            question,
        };
        let rows = reader.query_callable_values(
            &request,
            super::CatalogCallableValuesQueryLimits {
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

fn callable_publication_matches(
    shard: &super::ActiveSemanticModelShard,
    factory: &super::SemanticModelSymbol,
) -> bool {
    let provenance = &factory.provenance;
    shard.manifest.semantic_sha256 == provenance.pack_digest
        && shard.manifest.pack_id == provenance.pack_id
        && shard.manifest.version == provenance.pack_version
        && shard.source_id == provenance.activation.source_id
        && super::overlay::matched_evidence(&shard.matched_evidence)
            == provenance.activation.matched_evidence
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::csmi::{
        CsmiCallableValuesArgument, CsmiCallableValuesModality, CsmiCallableValuesTiming,
        CsmiInputBoundaryRoot, CsmiInputParameterRoot, CsmiInputPhase, CsmiParameterRootRole,
    };

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

    fn limits(max_records: usize) -> CallableValuesQueryLimits {
        CallableValuesQueryLimits { max_records }
    }

    #[test]
    fn activated_sql_contracts_require_current_factory_and_keep_coverage_unknown() {
        use crate::analyzer::semantic_model::*;
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;

        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(include_bytes!(
            "../../../testdata/semantic-model-packs/declarations-v1.json"
        ))
        .unwrap();
        authored.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        authored.compatibility.toolchains.clear();
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "member.widget.create".to_owned(),
                    result: 0,
                    target: "member.widget.create".to_owned(),
                },
                provenance: vec!["source-review".to_owned()],
            }],
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: "member.widget.create".to_owned(),
                status: CsmiCoverageStatus::Complete,
                limitations: Vec::new(),
                provenance: vec!["independent-coverage".to_owned()],
            }],
            anonymous_callables: Vec::new(),
        });
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &compiled,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "fixture-publication".to_owned(),
                },
            )
            .unwrap();
        let cancellation = CancellationToken::new();
        let active = match resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: semver::Version::new(0, 12, 0),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".to_owned(),
                    ecosystem: "maven".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "com.acme:widget".to_owned(),
                        version: Some(semver::Version::new(1, 2, 0)),
                    }),
                    module: None,
                    toolchain: None,
                    target: Some("jvm".to_owned()),
                    configuration: Some("release".to_owned()),
                    artifact_sha256: Some("a".repeat(64)),
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &cancellation,
        ) {
            SemanticModelResolutionOutcome::Ready(active) => active,
            other => panic!("fixture activation must finish: {other:?}"),
        };
        let project = InlineTestProject::with_language(Language::Java)
            .file("Probe.java", "class Probe {}")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let overlay =
            SemanticModelOverlay::build(workspace.analyzer(), &active, &cancellation, 1 << 26)
                .unwrap();
        let factory = overlay
            .symbols()
            .iter()
            .find(|symbol| symbol.provenance.record_id == "member.widget.create")
            .unwrap();
        let limits = CallableValuesQueryLimits { max_records: 64 };
        let query = activated_returned_callable_targets(
            &catalog,
            &active,
            factory,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert!(query.gap.is_none(), "{query:?}");
        assert_eq!(query.publications.len(), 1);
        assert_eq!(query.publications[0].rows.facts.len(), 1);
        assert_eq!(query.publications[0].rows.coverage_claims.len(), 1);
        assert_eq!(query.executable_coverage, CsmiCoverageStatus::Unknown);
        assert_eq!(
            query.publications[0].rows.executable_coverage,
            CsmiCoverageStatus::Unknown
        );
        let reader = catalog.runtime_source_reader();
        let reader_query = activated_returned_callable_targets_from_reader(
            &reader,
            &active,
            factory,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(reader_query.gap, query.gap);
        assert_eq!(reader_query.publications.len(), query.publications.len());
        assert_eq!(
            reader_query.publications[0].rows.facts.len(),
            query.publications[0].rows.facts.len()
        );
        assert_eq!(
            reader_query.publications[0].rows.coverage_claims.len(),
            query.publications[0].rows.coverage_claims.len()
        );
        let missing = activated_returned_callable_targets(
            &catalog,
            &active,
            factory,
            1,
            limits,
            &cancellation,
        )
        .unwrap();
        assert!(missing.publications[0].rows.facts.is_empty());
        assert_eq!(missing.publications[0].rows.coverage_claims.len(), 1);
        assert_eq!(missing.executable_coverage, CsmiCoverageStatus::Unknown);
        let mut stale = factory.clone();
        stale.provenance.active_model_set_hash = "different-activation".to_owned();
        let rejected = activated_returned_callable_targets(
            &catalog,
            &active,
            &stale,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            rejected.gap,
            Some(ActivatedCallableValuesGap::FactoryUnbound)
        );
        assert!(rejected.publications.is_empty());
        let mut foreign_artifact = factory.clone();
        foreign_artifact
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256 = Some("b".repeat(64));
        let rejected = activated_returned_callable_targets(
            &catalog,
            &active,
            &foreign_artifact,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            rejected.gap,
            Some(ActivatedCallableValuesGap::FactoryUnbound)
        );
        assert!(rejected.publications.is_empty());
        let mut foreign_configuration = factory.clone();
        foreign_configuration
            .provenance
            .activation
            .matched_evidence
            .configuration = Some("another-configuration".to_owned());
        let rejected = activated_returned_callable_targets(
            &catalog,
            &active,
            &foreign_configuration,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            rejected.gap,
            Some(ActivatedCallableValuesGap::FactoryUnbound)
        );
        assert!(rejected.publications.is_empty());
        let bounded = activated_returned_callable_targets(
            &catalog,
            &active,
            factory,
            0,
            CallableValuesQueryLimits { max_records: 0 },
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            bounded.gap,
            Some(ActivatedCallableValuesGap::RecordBudgetExhausted)
        );
        cancellation.cancel();
        let stopped = activated_returned_callable_targets(
            &catalog,
            &active,
            factory,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(stopped.gap, Some(ActivatedCallableValuesGap::Cancelled));
    }

    #[test]
    fn activated_sql_preserves_target_identity_from_another_selector_as_a_gap() {
        use crate::analyzer::semantic_model::*;
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;

        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(include_bytes!(
            "../../../testdata/semantic-model-packs/declarations-v1.json"
        ))
        .unwrap();
        authored.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION;
        authored.language = "go".to_owned();
        authored.ecosystem = "go".to_owned();
        authored.compatibility.bifrost = None;
        authored.compatibility.toolchains.clear();
        authored.shards[0].activation[0].package = Some(NameSelector {
            name: "example.test/module/pkg".to_owned(),
            version: None,
        });
        authored.shards[0].activation[0].targets.clear();
        authored.shards[0].activation[0].configurations.clear();
        let artifact_a = "a".repeat(64);
        let artifact_b = "b".repeat(64);
        authored.shards[0].activation[0].artifact_sha256 = Some(artifact_a.clone());
        let mut other_selector = authored.shards[0].activation[0].clone();
        other_selector.artifact_sha256 = Some(artifact_b.clone());
        authored.shards[0].activation.push(other_selector);
        let target_id = "go.literal.target".to_owned();
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "member.widget.create".to_owned(),
                    result: 0,
                    target: target_id.clone(),
                },
                provenance: vec!["source-review".to_owned()],
            }],
            coverage: Vec::new(),
            anonymous_callables: vec![crate::analyzer::semantic_model::AnonymousCallableIdentity {
                id: target_id.clone(),
                artifact_sha256: artifact_b,
                package_identity: "example.test/module/pkg".to_owned(),
                anchor: crate::analyzer::semantic_model::SourceAnchor {
                    file: "callbacks.go".to_owned(),
                    byte_range: crate::analyzer::semantic_model::SourceByteRange {
                        start: 20,
                        end: 50,
                    },
                    kind: crate::analyzer::semantic_model::SourceDeclarationKind::FunctionLiteral,
                },
                lexical_owner_chain: Vec::new(),
                signature: crate::analyzer::semantic_model::SourceCallableShape {
                    function_type: crate::analyzer::semantic_model::SourceTypeNode {
                        file: "callbacks.go".to_owned(),
                        byte_range: crate::analyzer::semantic_model::SourceByteRange {
                            start: 20,
                            end: 30,
                        },
                    },
                    parameters: Vec::new(),
                    results: Vec::new(),
                    declaration_chain: Vec::new(),
                },
            }],
        });
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &compiled,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "fixture-go-publication".to_owned(),
                },
            )
            .unwrap();
        let cancellation = CancellationToken::new();
        let active = match resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: semver::Version::new(0, 12, 0),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "example.test/module/pkg".to_owned(),
                        version: None,
                    }),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: Some(artifact_a),
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &cancellation,
        ) {
            SemanticModelResolutionOutcome::Ready(active) => active,
            other => panic!("fixture activation must finish: {other:?}"),
        };
        let project = InlineTestProject::with_language(Language::Go)
            .file("probe.go", "package probe\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let overlay =
            SemanticModelOverlay::build(workspace.analyzer(), &active, &cancellation, 1 << 26)
                .unwrap();
        let factory = overlay
            .symbols()
            .iter()
            .find(|symbol| symbol.provenance.record_id == "member.widget.create")
            .expect("activated factory symbol");
        let query = activated_returned_callable_targets(
            &catalog,
            &active,
            factory,
            0,
            limits(64),
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            query.gap,
            Some(ActivatedCallableValuesGap::TargetArtifactMismatch)
        );
        assert_eq!(query.publications.len(), 1);
        let row = &query.publications[0].rows.facts[0];
        let foreign_target_artifact = "b".repeat(64);
        assert_eq!(
            row.anonymous_callable
                .as_ref()
                .map(|identity| identity.artifact_sha256.as_str()),
            Some(foreign_target_artifact.as_str())
        );
        assert!(matches!(
            &row.fact.payload,
            CsmiCallableValuesPayload::ReturnedCallable { target, .. } if target == &target_id
        ));
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
                            crate::analyzer::semantic_model::csmi::CsmiCallableValuesLimitation {
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
        callback.projection = Some(crate::analyzer::semantic_model::csmi::CsmiProjection {
            scheme: "unsupported.location".into(),
            scheme_version: "0.1.0".into(),
            steps: Vec::new(),
        });
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
