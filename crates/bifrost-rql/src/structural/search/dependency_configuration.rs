//! Reviewed dependency ownership plus bounded, explicitly ordered file evidence.
//! All data here lives for one request; package evidence comes from the selected
//! SQL publication and configuration facts from the request's ingestion memo.
use super::cross_domain::{cross_domain_diagnostic, plan_rows_budget, single_key_member};
use super::*;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::query::DependencyConfigurationRelation;
use brokk_bifrost_core::analyzer::configuration::*;

#[derive(Debug, Clone)]
pub(super) struct DependencyConfigurationValue {
    pub(super) code: Box<PipelineValue>,
    pub(super) configuration: Option<ConfigurationFactValue>,
    pub(super) contributors: Arc<[ConfigurationFactValue]>,
    pub(super) effective: Option<Arc<ConfigurationResolutionResult>>,
    pub(super) mapping_id: String,
    pub(super) owner: String,
    pub(super) mitigated: bool,
}

fn layer(path: &str) -> ConfigurationLayerId {
    ConfigurationLayerId::new(path).expect("validated mapped documents have nonempty paths")
}

fn mapping_identity(relation: &DependencyConfigurationRelation) -> String {
    let mut hash = LengthDelimitedDigest::new(b"bifrost.dependency-configuration.mapping.v1");
    hash.push(relation.owner.as_bytes());
    hash.push(relation.ecosystem.as_bytes());
    for paths in [
        &relation.documents,
        &relation.version_ranges,
        &relation.values,
    ] {
        hash.push(&(paths.len() as u64).to_le_bytes());
        for path in paths {
            hash.push(path.as_bytes());
        }
    }
    for [lower, higher] in &relation.overrides {
        hash.push(lower.as_bytes());
        hash.push(higher.as_bytes());
    }
    hash.finish().to_string()
}

/// Preserve every affected dependency witness. Only an exhaustive unique
/// effective property and the same instance's supported version prove mitigation.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_dependency_configuration(
    relation: &DependencyConfigurationRelation,
    configuration_seeds: &[crate::query::ConfigurationFactsSeed],
    code: PlanExecution,
    configuration: PlanExecution,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let mut reasons = Vec::new();
    let mut gaps = Vec::new();
    let mut contributors = Vec::new();
    let mut contributions = Vec::new();
    let selected_keys = configuration
        .rows
        .iter()
        .filter_map(|row| {
            let PipelineValue::ConfigurationFact(fact) = &row.value else {
                unreachable!("validated configuration input produces configuration facts");
            };
            single_key_member(fact).map(str::to_owned)
        })
        .collect::<std::collections::BTreeSet<_>>();
    if selected_keys.len() > 1 {
        gaps.push(format!(
            "one flat property key is supported, but input selected {selected_keys:?}"
        ));
        reasons.push(ConfigurationIncompleteReason::ParserLimitation);
    }
    let key_name = (selected_keys.len() == 1).then(|| {
        selected_keys
            .iter()
            .next()
            .expect("one selected key")
            .clone()
    });
    let mut resolution_key = None;
    let mut version_hash =
        LengthDelimitedDigest::new(b"bifrost.dependency-configuration.sources.v1");
    for path in &relation.documents {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        if let Some(reason) =
            super::cross_domain::declared_document_gap(path, configuration_seeds, state)
        {
            gaps.push(format!("{path}: {reason}"));
            reasons.push(ConfigurationIncompleteReason::MissingInclude);
        }
        let Some(mut document) = state
            .configuration_cache
            .ingested_document(state.analyzer, path)
        else {
            continue;
        };
        version_hash.push(path.as_bytes());
        version_hash.push(document.source.as_bytes());
        if !document.document.completeness().is_complete() {
            reasons.push(ConfigurationIncompleteReason::ParserLimitation);
        }
        let features = document.document.features();
        if !features.interpolation().is_resolved() {
            reasons.push(ConfigurationIncompleteReason::UnresolvedInterpolation);
        }
        if !features.includes().is_resolved() || !features.format_merge().is_resolved() {
            reasons.push(ConfigurationIncompleteReason::ParserLimitation);
        }
        let mut source_hash =
            LengthDelimitedDigest::new(b"bifrost.dependency-configuration.source.v1");
        source_hash.push(document.source.as_bytes());
        let source_version = ConfigurationVersionId::new(source_hash.finish().to_string())
            .expect("snapshot identifier");
        let mut occurrences = 0;
        let mut unsupported_spelling = false;
        for index in 0..document.document.facts().len() {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                return cancelled_plan_execution();
            }
            if contributions.len() >= limits.max_pipeline_rows.min(4096) {
                reasons.push(ConfigurationIncompleteReason::ContributionBudgetExhausted);
                gaps.push(format!(
                    "configuration contribution budget reached in {path}"
                ));
                break;
            }
            document.index = index;
            if single_key_member(&document) != key_name.as_deref() || key_name.is_none() {
                continue;
            }
            occurrences += 1;
            let ConfigurationNodeKind::Member {
                value: Some(value), ..
            } = document.fact().kind()
            else {
                reasons.push(ConfigurationIncompleteReason::ParserLimitation);
                continue;
            };
            let scalar = document
                .document
                .fact(*value)
                .expect("validated member value exists");
            if !matches!(scalar.kind(), ConfigurationNodeKind::Scalar { .. }) {
                reasons.push(ConfigurationIncompleteReason::ParserLimitation);
                continue;
            }
            let range = scalar.evidence();
            let spelling = &document.source[range.start_byte()..range.end_byte()];
            // Value classification after the maintained parser selected the
            // exact scalar. No source scanner or partial escape decoder.
            if spelling.contains('\\') || spelling.contains("${") {
                reasons.push(ConfigurationIncompleteReason::UnresolvedInterpolation);
                unsupported_spelling = true;
            }
            let key = ConfigurationResolutionKey::from_route(&ConfigurationRoute::root().child(
                ConfigurationRouteSegment::key(
                    key_name.as_ref().expect("selected member has key"),
                    1,
                    document.fact().evidence(),
                ),
            ));
            resolution_key.get_or_insert_with(|| key.clone());
            contributions.push(ConfigurationContribution::new(
                layer(path),
                key,
                ConfigurationOpaqueValue::new(spelling),
                ConfigurationEvidenceIdentity::new(
                    ConfigurationSourceId::new(format!("{path}#{}", document.fact_id()))
                        .expect("source identity is nonempty"),
                    ConfigurationProviderId::new("bifrost.properties")
                        .expect("provider identifier"),
                    source_version.clone(),
                ),
                ConfigurationSourceKind::AuthoredFile,
            ));
            contributors.push(document.clone());
        }
        if unsupported_spelling {
            gaps.push(format!(
                "{path}: escaped, continued, or interpolated property is unsupported"
            ));
        }
        if occurrences > 1 {
            reasons.push(ConfigurationIncompleteReason::Conflict);
            gaps.push(format!(
                "{path}: duplicate occurrences of {key_name:?}; no duplicate wins by order"
            ));
        }
    }
    if configuration.truncated || code.truncated {
        reasons.push(ConfigurationIncompleteReason::ParserLimitation);
    }
    let mut input = ConfigurationResolutionInput::new(
        relation
            .documents
            .iter()
            .map(|path| ConfigurationLayer::new(layer(path)))
            .collect(),
        contributions,
        relation
            .overrides
            .iter()
            .map(|[lower, higher]| {
                ConfigurationPrecedenceEdge::new(
                    layer(lower),
                    layer(higher),
                    ConfigurationPrecedenceExplanation::ExplicitOverride,
                )
                .expect("validated precedence edges are nonself")
            })
            .collect(),
    )
    .expect("validated relation has a finite acyclic precedence graph");
    for reason in reasons {
        input = input.with_incomplete_reason(reason);
    }
    let cancellation = state.cancellation.cloned().unwrap_or_default();
    let effective = resolution_key.map(|key| {
        resolve_effective_configuration(
            &ConfigurationResolutionRequest::new(key),
            &input,
            ConfigurationResolutionBounds::new(
                limits.max_pipeline_rows.min(4096),
                limits.max_fact_nodes.min(16384),
            ),
            &cancellation,
        )
    });
    if let Some(value) = &effective
        && (!value.completeness().is_complete()
            || !matches!(value.proof(), ConfigurationResolutionProof::Selected { .. }))
    {
        gaps.push(format!(
            "effective property remains unresolved: proof={:?}, completeness={:?}",
            value.proof(),
            value.completeness()
        ));
    }
    let winner = effective.as_ref().and_then(|effective| {
        if !effective.completeness().is_complete() {
            return None;
        }
        let ConfigurationResolutionProof::Selected { layer } = effective.proof() else {
            return None;
        };
        contributors
            .iter()
            .find(|fact| rel_path_string(fact.file()) == layer.as_str())
            .cloned()
    });
    let property_matches = winner.as_ref().is_some_and(|winner| {
        configuration.rows.iter().any(|row| matches!(&row.value, PipelineValue::ConfigurationFact(fact) if fact.key() == winner.key()))
    }) && effective.as_ref().and_then(ConfigurationResolutionResult::value)
        .is_some_and(|value| relation.values.iter().any(|candidate| candidate == value.as_str()));
    // Immutable proof is shared across this invocation's dependency witnesses.
    // Charge a conservative serialized projection for every retained copy in
    // the response, through the query's fair shared evidence-byte lane.
    let citation_bytes = contributors
        .iter()
        .map(|fact| {
            1024usize
                .saturating_add(rel_path_string(fact.file()).len().saturating_mul(6))
                .saturating_add(fact.route().len().saturating_mul(6))
                .saturating_add(
                    single_key_member(fact)
                        .map_or(0, str::len)
                        .saturating_mul(6),
                )
        })
        .collect::<Vec<_>>();
    let proof_bytes = effective
        .as_ref()
        .map_or(0, |value| {
            serde_json::to_vec(value)
                .expect("effective evidence serializes")
                .len()
        })
        .saturating_add(
            citation_bytes
                .iter()
                .fold(0usize, |sum, size| sum.saturating_add(*size)),
        )
        .saturating_add(citation_bytes.iter().copied().max().unwrap_or(0));
    let contributors: Arc<[ConfigurationFactValue]> = contributors.into();
    let effective = effective.map(Arc::new);
    let mapping_id = mapping_identity(relation);
    let source_version = version_hash.finish().to_string();
    let desired_rows = plan_rows_budget(terminal_cap, state, limits);
    let mut rows = Vec::new();
    let mut indexes = HashMap::default();
    let mut truncated = code.truncated || configuration.truncated;
    let supports_version = super::dependency_evidence::mitigation_version_predicate(
        &relation.ecosystem,
        &relation.version_ranges,
    );
    let mut ownership_incomplete = false;
    let mut version_incomplete = false;
    let mut proof_budget_exhausted = false;
    for code_row in code.rows {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        if rows.len() >= desired_rows {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
            truncated = true;
            break;
        }
        let PipelineValue::DependencyEvidence(dependency) = &code_row.value else {
            unreachable!("validated dependency configuration input produces dependency evidence");
        };
        let owner_matches = dependency.row.declared_by.as_deref() == Some(relation.owner.as_str());
        ownership_incomplete |= dependency.row.declared_by.is_none();
        let supported_version = supports_version(&dependency.row);
        version_incomplete |= owner_matches && supported_version.is_none();
        let mut retain_proof = owner_matches && proof_bytes > 0;
        if retain_proof {
            let mut projected = state.budget;
            projected.retained_evidence_bytes = projected
                .retained_evidence_bytes
                .saturating_add(proof_bytes);
            retain_proof = projected.retained_evidence_bytes
                <= limits.semantic.max_retained_bytes.min(8 * 1024 * 1024);
            if retain_proof && let Some(lease) = &state.parallel_seed_budget {
                match lease.admit(projected) {
                    FairSeedBudgetAdmission::Admitted => {}
                    FairSeedBudgetAdmission::Rejected(_) => retain_proof = false,
                    FairSeedBudgetAdmission::Cancelled => return cancelled_plan_execution(),
                }
            }
            if retain_proof {
                state.budget = projected;
            } else {
                proof_budget_exhausted = true;
                truncated = true;
            }
        }
        let mut identity =
            LengthDelimitedDigest::new(b"bifrost.dependency-configuration.selected.v1");
        identity.push(mapping_id.as_bytes());
        identity.push(source_version.as_bytes());
        identity.push(key_name.as_deref().unwrap_or("").as_bytes());
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
        insert_pipeline_row(
            &mut rows,
            &mut indexes,
            PipelineValue::CrossDomain(Box::new(CrossDomainValue::DependencyConfiguration(
                Box::new(DependencyConfigurationValue {
                    code: Box::new(code_row.value),
                    configuration: retain_proof.then(|| winner.clone()).flatten(),
                    contributors: if retain_proof {
                        Arc::clone(&contributors)
                    } else {
                        Arc::from([])
                    },
                    effective: retain_proof.then(|| effective.clone()).flatten(),
                    mapping_id: identity.finish().to_string(),
                    owner: relation.owner.clone(),
                    mitigated: retain_proof
                        && owner_matches
                        && supported_version == Some(true)
                        && property_matches
                        && !truncated,
                }),
            ))),
            code_row.traces,
            code_row.provenance_truncated,
        );
    }
    if ownership_incomplete {
        gaps.push("some dependency witnesses have no established consuming owner; applicability remains unknown".to_owned());
    }
    if version_incomplete {
        gaps.push("some same-owner dependency witnesses have no supported exact locked/installed version evidence".to_owned());
    }
    if proof_budget_exhausted {
        diagnostics.push(cross_domain_diagnostic(CodeQueryDiagnosticCode::PipelineBudgetExhausted, CodeQueryDiagnosticImpact::Incomplete,
            "dependency configuration retained evidence byte budget exhausted; affected witnesses remain with mitigated=false and omitted configuration proof".to_owned()));
    }
    if !gaps.is_empty() {
        diagnostics.push(cross_domain_diagnostic(CodeQueryDiagnosticCode::CrossDomainDocumentIncomplete,
            CodeQueryDiagnosticImpact::Incomplete,
            format!("dependency configuration mitigation is unproved; affected witnesses remain with mitigated=false: {gaps:?}")));
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}
