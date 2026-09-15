//! Consumer decisions for portable runtime contracts. An applicability match is
//! conditional target evidence, not deployment verification or source binding.

use super::csmi::CsmiArtifactSelector;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeContractActivationOutcome {
    Matched,
    NotMatched,
    Unsupported,
    Indeterminate,
    Conflict,
    ReviewRequired,
    Disabled,
}

impl RuntimeContractActivationOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::NotMatched => "not-matched",
            Self::Unsupported => "unsupported",
            Self::Indeterminate => "indeterminate",
            Self::Conflict => "conflict",
            Self::ReviewRequired => "review-required",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContractActivationDecision {
    pub outcome: RuntimeContractActivationOutcome,
    pub selected_ids: Vec<String>,
}

/// Independently accepted consumer evidence. Importing a policy or a review
/// does not populate these lists. The host must validate the exact policy and
/// review evidence, including purpose, expiry/withdrawal and producer trust.
#[derive(Debug, Default)]
pub struct RuntimeContractAuthorization {
    pub accepted_policy_digests: Vec<String>,
    pub accepted_review_digests: Vec<String>,
}

/// Evaluate the selected activation record from a validated native payload.
/// The returned decision does not authorize imported executable observations;
/// their producer, source closure and locator schemes need independent proof.
pub fn decide_runtime_contract_activation(
    carrier: &super::RuntimeContractsPayload,
    activation_id: &str,
    authorization: &RuntimeContractAuthorization,
) -> Result<RuntimeContractActivationDecision, super::csmi::CsmiCanonicalError> {
    let unknown = || RuntimeContractActivationDecision {
        outcome: RuntimeContractActivationOutcome::Indeterminate,
        selected_ids: Vec::new(),
    };
    let Some(envelope) = &carrier.envelope else {
        return Ok(unknown());
    };
    let validation = super::csmi::validate_csmi_document(
        &serde_json::to_vec(envelope)?,
        &super::csmi::CsmiVocabularySupport::support(
            super::RUNTIME_VALUES_VOCABULARY,
            super::RUNTIME_VALUES_V2_VERSION,
            super::RUNTIME_VALUES_V2_SCHEMA,
        ),
    );
    if !validation.valid() {
        return Ok(unknown());
    }
    let Some(super::csmi::CsmiDocument::Semantic(document)) = validation.document else {
        return Ok(unknown());
    };
    let [model] = document.semantic_models.as_slice() else {
        return Ok(unknown());
    };
    let payload = &carrier.payload;
    if !super::runtime_contract_envelope_matches(payload, envelope)? {
        return Ok(unknown());
    }
    let Some(activation) = payload.activation(activation_id) else {
        return Ok(RuntimeContractActivationDecision {
            outcome: RuntimeContractActivationOutcome::Indeterminate,
            selected_ids: Vec::new(),
        });
    };
    let Some(target) = payload.target(&activation.target_id) else {
        return Ok(RuntimeContractActivationDecision {
            outcome: RuntimeContractActivationOutcome::Indeterminate,
            selected_ids: Vec::new(),
        });
    };
    let target_selector = target
        .definition
        .runtime
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        .map(serde_json::from_value::<CsmiArtifactSelector>)
        .transpose()?;
    let outer: Vec<_> = model
        .artifact_selectors
        .iter()
        .map(|selector| runtime_contract_selector_match(selector, target_selector.as_ref()))
        .collect();
    if !outer.contains(&RuntimeContractMatch::Matched) {
        return Ok(RuntimeContractActivationDecision {
            outcome: if outer.contains(&RuntimeContractMatch::Unsupported) {
                RuntimeContractActivationOutcome::Unsupported
            } else if outer.contains(&RuntimeContractMatch::Indeterminate) {
                RuntimeContractActivationOutcome::Indeterminate
            } else {
                RuntimeContractActivationOutcome::NotMatched
            },
            selected_ids: Vec::new(),
        });
    }
    let contracts = payload
        .contracts
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    evaluate_runtime_contract_activation(
        &serde_json::to_value(activation)?,
        &contracts,
        &serde_json::to_value(target)?,
        authorization,
    )
}

fn known_context(scheme: &Value) -> bool {
    scheme["version"] == "0.2.0"
        && matches!(
            scheme["identifier"].as_str(),
            Some(
                "https://csmi.brokk.ai/runtime-context/node"
                    | "https://csmi.brokk.ai/runtime-context/cpython"
            )
        )
}

/// Applicability over schema-validated wire definitions. This intentionally
/// returns only a conditional match; source and producer evidence are separate.
pub(crate) fn runtime_contract_applicability(
    contract: &Value,
    target: &Value,
) -> RuntimeContractMatch {
    let definition = &contract["definition"];
    let observed = &target["definition"];
    let Some(selectors) = definition["applicability"]["selectors"].as_array() else {
        return RuntimeContractMatch::Indeterminate;
    };
    let target_selector = observed
        .get("runtime")
        .cloned()
        .map(serde_json::from_value::<CsmiArtifactSelector>)
        .transpose();
    let Ok(target_selector) = target_selector else {
        return RuntimeContractMatch::Unsupported;
    };
    let mut statuses = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let Ok(selector) = serde_json::from_value::<CsmiArtifactSelector>(selector.clone()) else {
            return RuntimeContractMatch::Unsupported;
        };
        statuses.push(runtime_contract_selector_match(
            &selector,
            target_selector.as_ref(),
        ));
    }
    let selection = if statuses.contains(&RuntimeContractMatch::Matched) {
        RuntimeContractMatch::Matched
    } else if statuses.contains(&RuntimeContractMatch::Unsupported) {
        RuntimeContractMatch::Unsupported
    } else if statuses.contains(&RuntimeContractMatch::Indeterminate) {
        RuntimeContractMatch::Indeterminate
    } else {
        RuntimeContractMatch::NotMatched
    };
    let mut results = vec![selection];
    let equality = &definition["behavior"]["keyEquality"];
    if equality["version"] != "0.2.0"
        || !matches!(
            equality["identifier"].as_str(),
            Some(
                "https://csmi.brokk.ai/key-equality/exact-string"
                    | "https://csmi.brokk.ai/key-equality/exact-index"
                    | "https://csmi.brokk.ai/key-equality/platform-defined"
            )
        )
    {
        results.push(RuntimeContractMatch::Unsupported);
    }
    let required_context = &definition["context"];
    let observed_context = &observed["context"];
    if !known_context(&required_context["scheme"]) || !known_context(&observed_context["scheme"]) {
        results.push(RuntimeContractMatch::Unsupported);
    } else if required_context["scheme"] != observed_context["scheme"] {
        results.push(RuntimeContractMatch::NotMatched);
    } else {
        for dimension in [
            "platform",
            "architecture",
            "realm",
            "moduleMode",
            "launchMode",
            "initializationBoundary",
        ] {
            if observed_context[dimension] == "unknown" || observed_context[dimension].is_null() {
                results.push(RuntimeContractMatch::Indeterminate);
            } else if !required_context[dimension]
                .as_array()
                .is_some_and(|allowed| allowed.contains(&observed_context[dimension]))
            {
                results.push(RuntimeContractMatch::NotMatched);
            }
        }
        if !definition["assumptions"]
            .as_array()
            .is_some_and(|required| {
                observed["assumptions"]
                    .as_array()
                    .is_some_and(|actual| required.iter().all(|value| actual.contains(value)))
            })
        {
            results.push(RuntimeContractMatch::Indeterminate);
        }
    }
    if observed["basis"] == "unknown" || observed["coverage"]["status"] != "complete" {
        results.push(RuntimeContractMatch::Indeterminate);
    }
    RuntimeContractMatch::conjunction(results)
}

/// Recompute a schema-validated activation from its complete candidate records.
/// Validation callers may supply independently constructed fixture approvals to
/// check consistency. Production callers must supply host-validated evidence.
pub(crate) fn evaluate_runtime_contract_activation(
    activation: &Value,
    contracts: &[Value],
    target: &Value,
    authorization: &RuntimeContractAuthorization,
) -> Result<RuntimeContractActivationDecision, super::csmi::CsmiCanonicalError> {
    use RuntimeContractActivationOutcome as Outcome;
    let result = |outcome| RuntimeContractActivationDecision {
        outcome,
        selected_ids: Vec::new(),
    };
    if activation["candidateCoverage"]["status"] != "complete" {
        return Ok(result(Outcome::Indeterminate));
    }
    let Some(candidate_ids) = activation["candidateIds"].as_array() else {
        return Ok(result(Outcome::Indeterminate));
    };
    let inventory: Vec<_> = contracts
        .iter()
        .filter(|contract| contract["definition"]["surface"] == activation["surface"])
        .collect();
    if inventory.len() != candidate_ids.len()
        || inventory
            .iter()
            .any(|contract| !candidate_ids.contains(&contract["contractId"]))
    {
        return Ok(result(Outcome::Indeterminate));
    }
    let Some(disabled) = activation["disabledIds"].as_array() else {
        return Ok(result(Outcome::Indeterminate));
    };
    if disabled.iter().any(|id| !candidate_ids.contains(id)) {
        return Ok(result(Outcome::Indeterminate));
    }
    let candidates: Vec<_> = inventory
        .into_iter()
        .filter(|contract| !disabled.contains(&contract["contractId"]))
        .collect();
    if candidates.is_empty() {
        return Ok(result(if candidate_ids.is_empty() {
            Outcome::NotMatched
        } else {
            Outcome::Disabled
        }));
    }
    let possible: Vec<_> = candidates
        .into_iter()
        .filter_map(|contract| {
            let status = runtime_contract_applicability(contract, target);
            (status != RuntimeContractMatch::NotMatched).then_some((contract, status))
        })
        .collect();
    if possible.is_empty() {
        return Ok(result(Outcome::NotMatched));
    }
    let mut definitions = crate::hash::HashMap::default();
    let mut behavior = None;
    for (contract, _) in &possible {
        let definition = &contract["definition"];
        let key = (
            definition["identifier"].as_str().unwrap_or_default(),
            definition["version"].as_str().unwrap_or_default(),
        );
        let canonical = super::runtime_contract_canonical(definition)?;
        if definitions
            .insert(key, canonical.clone())
            .is_some_and(|previous| previous != canonical)
        {
            return Ok(result(Outcome::Conflict));
        }
        let claims = serde_json::json!({
            "surface":definition["surface"], "languages":definition["languages"],
            "assumptions":definition["assumptions"], "behavior":definition["behavior"]
        });
        let canonical = super::runtime_contract_canonical(&claims)?;
        if behavior
            .as_ref()
            .is_some_and(|previous| previous != &canonical)
        {
            return Ok(result(Outcome::Conflict));
        }
        behavior = Some(canonical);
    }
    if possible
        .iter()
        .any(|(_, status)| *status == RuntimeContractMatch::Unsupported)
    {
        return Ok(result(Outcome::Unsupported));
    }
    if possible
        .iter()
        .any(|(_, status)| *status == RuntimeContractMatch::Indeterminate)
    {
        return Ok(result(Outcome::Indeterminate));
    }
    let policy = &activation["policy"];
    if !authorization
        .accepted_policy_digests
        .contains(&super::runtime_contract_digest(policy)?)
    {
        return Ok(result(Outcome::ReviewRequired));
    }
    let Some(reviews) = activation["reviews"].as_array() else {
        return Ok(result(Outcome::ReviewRequired));
    };
    for (contract, _) in &possible {
        let mut approved = false;
        for review in reviews {
            if review["contractDigest"] != contract["contractDigest"]
                || review["targetDigest"] != target["targetDigest"]
                || review["purpose"] != policy["purpose"]
                || !policy["trustedReviewers"]
                    .as_array()
                    .is_some_and(|trusted| trusted.contains(&review["reviewer"]))
            {
                continue;
            }
            if review["decision"] != "approved" {
                return Ok(result(Outcome::ReviewRequired));
            }
            approved |= authorization
                .accepted_review_digests
                .contains(&super::runtime_contract_digest(review)?);
        }
        if !approved {
            return Ok(result(Outcome::ReviewRequired));
        }
    }
    let mut selected_ids: Vec<_> = possible
        .iter()
        .filter_map(|(contract, _)| contract["contractId"].as_str().map(str::to_owned))
        .collect();
    selected_ids.sort();
    Ok(RuntimeContractActivationDecision {
        outcome: Outcome::Matched,
        selected_ids,
    })
}

/// Result of comparing required semantics with independently supplied evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeContractMatch {
    Matched,
    NotMatched,
    Unsupported,
    Indeterminate,
}

impl RuntimeContractMatch {
    /// A contradiction is sufficient to exclude a candidate. Otherwise retain
    /// unsupported comparisons before missing evidence.
    pub fn conjunction(results: impl IntoIterator<Item = Self>) -> Self {
        let mut result = Self::Matched;
        for next in results {
            match next {
                Self::NotMatched => return Self::NotMatched,
                Self::Unsupported => result = Self::Unsupported,
                Self::Indeterminate if result == Self::Matched => result = Self::Indeterminate,
                _ => {}
            }
        }
        result
    }
}

#[derive(Debug)]
struct StableInterval {
    lower: semver::Version,
    lower_inclusive: bool,
    upper: semver::Version,
    upper_inclusive: bool,
}

// These are the two assignments explicitly defined by runtime-values 0.2. A
// generic PURL does not imply a version comparison scheme for other packages.
fn runtime_coordinate(selector: &CsmiArtifactSelector) -> Option<(&str, &str, Option<&str>)> {
    for (base, scheme) in [
        ("pkg:generic/nodejs.org/node", "semver"),
        ("pkg:generic/python.org/cpython", "pypi"),
    ] {
        if selector.purl == base {
            return Some((base, scheme, None));
        }
        if let Some(version) = selector
            .purl
            .strip_prefix(base)
            .and_then(|tail| tail.strip_prefix('@'))
        {
            return Some((base, scheme, Some(version)));
        }
    }
    None
}

fn stable_release(value: &str) -> Option<semver::Version> {
    // Both registered schemes have the same ordering on this deliberately
    // bounded subset of canonical stable triples. PEP 440 epochs, shortened
    // releases and prereleases, and SemVer prereleases/builds are unsupported.
    let parsed = semver::Version::parse(value).ok()?;
    (parsed.pre.is_empty() && parsed.build.is_empty() && parsed.to_string() == value)
        .then_some(parsed)
}

fn stable_interval(selector: &CsmiArtifactSelector) -> Option<StableInterval> {
    let (_, scheme, exact) = runtime_coordinate(selector)?;
    if let Some(exact) = exact {
        if selector.version_range.is_some() {
            return None;
        }
        let version = stable_release(exact)?;
        return Some(StableInterval {
            lower: version.clone(),
            upper: version,
            lower_inclusive: true,
            upper_inclusive: true,
        });
    }
    let range = selector.version_range.as_deref()?;
    let body = range
        .strip_prefix("vers:")?
        .strip_prefix(scheme)?
        .strip_prefix('/')?;
    if let Some(version) = stable_release(body) {
        return Some(StableInterval {
            lower: version.clone(),
            upper: version,
            lower_inclusive: true,
            upper_inclusive: true,
        });
    }
    // VERS is a serialized version expression, not program source syntax. Only
    // one canonical bounded interval is supported; exclusions and unions stay
    // unsupported rather than being approximated by a representative release.
    let (lower, upper) = body.split_once('|')?;
    let lower = lower.strip_prefix('>')?;
    let lower_inclusive = lower.starts_with('=');
    let lower = stable_release(lower.strip_prefix('=').unwrap_or(lower))?;
    let upper = upper.strip_prefix('<')?;
    let upper_inclusive = upper.starts_with('=');
    let upper = stable_release(upper.strip_prefix('=').unwrap_or(upper))?;
    if lower >= upper {
        return None;
    }
    Some(StableInterval {
        lower,
        lower_inclusive,
        upper,
        upper_inclusive,
    })
}

fn interval_match(required: &StableInterval, target: &StableInterval) -> RuntimeContractMatch {
    if required.upper < target.lower
        || (required.upper == target.lower && !(required.upper_inclusive && target.lower_inclusive))
        || target.upper < required.lower
        || (target.upper == required.lower && !(target.upper_inclusive && required.lower_inclusive))
    {
        return RuntimeContractMatch::NotMatched;
    }
    let lower_covered = required.lower < target.lower
        || (required.lower == target.lower
            && (required.lower_inclusive || !target.lower_inclusive));
    let upper_covered = required.upper > target.upper
        || (required.upper == target.upper
            && (required.upper_inclusive || !target.upper_inclusive));
    if lower_covered && upper_covered {
        RuntimeContractMatch::Matched
    } else {
        RuntimeContractMatch::Indeterminate
    }
}

/// Compare a validated runtime selector with a validated target selector.
/// Stable release intervals use the profile's explicitly registered schemes;
/// valid but unimplemented forms retain `Unsupported`.
pub fn runtime_contract_selector_match(
    required: &CsmiArtifactSelector,
    target: Option<&CsmiArtifactSelector>,
) -> RuntimeContractMatch {
    let Some(target) = target else {
        return RuntimeContractMatch::Indeterminate;
    };
    let (Some((required_base, _, _)), Some((target_base, _, _))) =
        (runtime_coordinate(required), runtime_coordinate(target))
    else {
        return RuntimeContractMatch::Unsupported;
    };
    if required_base != target_base {
        return RuntimeContractMatch::NotMatched;
    }
    let versions = match (stable_interval(required), stable_interval(target)) {
        (Some(required), Some(target)) => interval_match(&required, &target),
        _ => RuntimeContractMatch::Unsupported,
    };
    let mut artifacts = RuntimeContractMatch::Matched;
    for wanted in &required.digests {
        let mut comparable = false;
        for actual in &target.digests {
            if wanted.coverage == actual.coverage
                && wanted.canonicalization == actual.canonicalization
                && wanted.algorithm == actual.algorithm
            {
                comparable = true;
                if wanted.value != actual.value {
                    return RuntimeContractMatch::NotMatched;
                }
            }
        }
        // Alternative algorithms with the same byte coverage are one evidence
        // group. At least one must compare, and every comparable digest agrees.
        if !comparable
            && !required.digests.iter().any(|alternative| {
                alternative.coverage == wanted.coverage
                    && alternative.canonicalization == wanted.canonicalization
                    && target.digests.iter().any(|actual| {
                        actual.coverage == alternative.coverage
                            && actual.canonicalization == alternative.canonicalization
                            && actual.algorithm == alternative.algorithm
                    })
            })
        {
            artifacts = RuntimeContractMatch::Indeterminate;
        }
    }
    RuntimeContractMatch::conjunction([versions, artifacts])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_contract_activation_requires_external_review_evidence() {
        let document: Value =
            serde_json::from_str(include_str!("csmi/profiles/runtime-values-v2.fixture.json"))
                .expect("pinned upstream fixture parses");
        let facts = document["semanticModels"][0]["extensionFacts"]
            .as_array()
            .unwrap();
        let contracts: Vec<_> = facts
            .iter()
            .filter(|fact| fact["family"] == "runtime-contracts")
            .map(|fact| fact["payload"].clone())
            .collect();
        let target = &facts
            .iter()
            .find(|fact| fact["family"] == "runtime-targets")
            .unwrap()["payload"];
        let activation = &facts
            .iter()
            .find(|fact| fact["family"] == "runtime-activations")
            .unwrap()["payload"];
        let mut authorization = RuntimeContractAuthorization::default();
        let evaluate = |authorization: &RuntimeContractAuthorization| {
            evaluate_runtime_contract_activation(activation, &contracts, target, authorization)
                .unwrap()
        };
        assert_eq!(
            evaluate(&authorization).outcome,
            RuntimeContractActivationOutcome::ReviewRequired
        );
        authorization
            .accepted_policy_digests
            .push(super::super::runtime_contract_digest(&activation["policy"]).unwrap());
        assert_eq!(
            evaluate(&authorization).outcome,
            RuntimeContractActivationOutcome::ReviewRequired
        );
        authorization.accepted_review_digests = activation["reviews"]
            .as_array()
            .unwrap()
            .iter()
            .map(|review| super::super::runtime_contract_digest(review).unwrap())
            .collect();
        let decision = evaluate(&authorization);
        assert_eq!(decision.outcome, RuntimeContractActivationOutcome::Matched);
        assert_eq!(
            serde_json::to_value(decision.selected_ids).unwrap(),
            activation["selectedIds"]
        );

        let mut incomplete = activation.clone();
        incomplete["candidateCoverage"] =
            serde_json::json!({"status":"partial","limitations":["inventory-incomplete"]});
        incomplete["disabledIds"] = incomplete["candidateIds"].clone();
        assert_eq!(
            evaluate_runtime_contract_activation(&incomplete, &contracts, target, &authorization)
                .unwrap()
                .outcome,
            RuntimeContractActivationOutcome::Indeterminate
        );
        incomplete["candidateIds"] = serde_json::json!([]);
        incomplete["disabledIds"] = serde_json::json!([]);
        assert_eq!(
            evaluate_runtime_contract_activation(&incomplete, &[], target, &authorization)
                .unwrap()
                .outcome,
            RuntimeContractActivationOutcome::Indeterminate
        );
    }

    fn node(version: &str) -> CsmiArtifactSelector {
        CsmiArtifactSelector {
            purl: format!("pkg:generic/nodejs.org/node@{version}"),
            version_range: None,
            digests: Vec::new(),
        }
    }

    fn range(value: &str) -> CsmiArtifactSelector {
        CsmiArtifactSelector {
            purl: "pkg:generic/nodejs.org/node".into(),
            version_range: Some(format!("vers:semver/{value}")),
            digests: Vec::new(),
        }
    }

    #[test]
    fn runtime_contract_ranges_require_full_coverage() {
        let contract = range(">=22.11.0|<23.0.0");
        for (target, expected) in [
            (node("22.11.0"), RuntimeContractMatch::Matched),
            (node("23.0.0"), RuntimeContractMatch::NotMatched),
            (range(">=22.12.0|<22.13.0"), RuntimeContractMatch::Matched),
            (
                range(">=22.12.0|<24.0.0"),
                RuntimeContractMatch::Indeterminate,
            ),
            (node("22.11.0-rc.1"), RuntimeContractMatch::Unsupported),
            (
                range(">=22.11.0|!=22.12.0|<23.0.0"),
                RuntimeContractMatch::Unsupported,
            ),
        ] {
            assert_eq!(
                runtime_contract_selector_match(&contract, Some(&target)),
                expected,
                "{target:?}"
            );
        }
        let python = CsmiArtifactSelector {
            purl: "pkg:generic/python.org/cpython@3.13.0".into(),
            version_range: None,
            digests: Vec::new(),
        };
        assert_eq!(
            runtime_contract_selector_match(&python, Some(&python)),
            RuntimeContractMatch::Matched
        );
        assert_eq!(
            runtime_contract_selector_match(&contract, Some(&python)),
            RuntimeContractMatch::NotMatched
        );
    }

    #[test]
    fn runtime_contract_artifact_digests_preserve_coverage_and_comparison_groups() {
        use super::super::csmi::{CsmiArtifactDigest, CsmiDigestAlgorithm};
        let mut required = node("22.11.0");
        let sha256 = CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: "artifact-bytes".into(),
            canonicalization: None,
            value: "a".repeat(64),
        };
        let sha512 = CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha512,
            value: "b".repeat(128),
            ..sha256.clone()
        };
        required.digests = vec![sha256.clone(), sha512];
        let mut target = node("22.11.0");
        assert_eq!(
            runtime_contract_selector_match(&required, Some(&target)),
            RuntimeContractMatch::Indeterminate
        );
        target.digests.push(sha256);
        assert_eq!(
            runtime_contract_selector_match(&required, Some(&target)),
            RuntimeContractMatch::Matched
        );
        target.digests[0].coverage = "contract-content".into();
        assert_eq!(
            runtime_contract_selector_match(&required, Some(&target)),
            RuntimeContractMatch::Indeterminate
        );
        target.digests[0].coverage = "artifact-bytes".into();
        target.digests[0].value = "c".repeat(64);
        assert_eq!(
            runtime_contract_selector_match(&required, Some(&target)),
            RuntimeContractMatch::NotMatched
        );
    }
}
