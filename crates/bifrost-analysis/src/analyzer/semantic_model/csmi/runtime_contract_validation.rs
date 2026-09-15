//! Normative semantic validation for CSMI runtime-values 0.2.
//!
//! The profile schema establishes payload structure.  This module validates
//! content identity, exact joins, candidate inventories, bounded applicability
//! evidence, and proof consistency.  It never treats a document's own policy
//! or reviewer list as consumer authorization.

use super::model::{
    CsmiAffectedFactFamilyKind, CsmiAffectedUnit, CsmiArtifactSelector, CsmiSemanticDocument,
    CsmiSemanticModel, CsmiVocabularyRequirement, CsmiVocabularyUse,
};
use super::validate::CsmiDiagnostic;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};

use crate::analyzer::semantic_model::runtime_contract_activation::{
    RuntimeContractAuthorization, RuntimeContractMatch, evaluate_runtime_contract_activation,
    runtime_contract_selector_match,
};
use crate::analyzer::semantic_model::runtime_contract_digest;

pub(super) const RUNTIME_CONTRACT_PROFILE_ID: &str = "csmi.runtime-values";
pub(super) const RUNTIME_CONTRACT_PROFILE_VERSION: &str = "0.2.0";
pub(super) const RUNTIME_CONTRACT_PROFILE_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/runtime-values/0.2/schema.json";

const FAMILIES: &[(&str, &str, &str)] = &[
    ("runtime-contracts", "runtime-contract", "contractId"),
    ("runtime-targets", "runtime-target", "targetId"),
    ("runtime-activations", "runtime-activation", "activationId"),
    ("runtime-bindings", "runtime-binding", "bindingId"),
    (
        "runtime-observations",
        "runtime-observation",
        "observationId",
    ),
];

type Records<'a> = BTreeMap<&'a str, BTreeMap<String, &'a Value>>;

fn runtime_digest(value: &Value) -> Option<String> {
    runtime_contract_digest(value).ok()
}

fn canonical_scope_string(value: &Value) -> String {
    String::from_utf8(
        crate::analyzer::semantic_model::runtime_contract_canonical(value)
            .expect("JSON values are serializable"),
    )
    .expect("canonical JSON is UTF-8")
}

trait DiagnosticSink {
    fn error(
        &mut self,
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    );
}

impl DiagnosticSink for Vec<CsmiDiagnostic> {
    fn error(
        &mut self,
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push(CsmiDiagnostic::error(code, path, message));
    }
}

pub(crate) fn validate_runtime_contract_semantics(
    model: &CsmiSemanticModel,
    document: Option<&CsmiSemanticDocument>,
    prefix: &str,
    sink: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let uses: Vec<(usize, &CsmiVocabularyUse)> = model
        .vocabulary_uses
        .iter()
        .enumerate()
        .filter(|(_, use_)| use_.identifier == RUNTIME_CONTRACT_PROFILE_ID)
        .collect();
    let fact_count = model
        .extension_facts
        .iter()
        .filter(|fact| {
            fact.vocabulary == RUNTIME_CONTRACT_PROFILE_ID
                && fact.version == RUNTIME_CONTRACT_PROFILE_VERSION
        })
        .count();

    if fact_count == 0
        && !uses
            .iter()
            .any(|(_, use_)| use_.version == RUNTIME_CONTRACT_PROFILE_VERSION)
    {
        return true;
    }

    let mut valid = true;
    if fact_count > 0 && uses.len() != 1 {
        sink.error(
            "semantic.runtime_contract_use_count",
            format!("{prefix}.vocabularyUses"),
            "runtime-values 0.2 facts require exactly one vocabulary use",
        );
        valid = false;
    }
    let mut affected = HashSet::new();
    for (index, use_) in &uses {
        let path = format!("{prefix}.vocabularyUses[{index}]");
        if use_.version != RUNTIME_CONTRACT_PROFILE_VERSION
            || use_.schema != RUNTIME_CONTRACT_PROFILE_SCHEMA
        {
            sink.error(
                "semantic.runtime_contract_version",
                format!("{path}.version"),
                "runtime-values facts in a 0.2 profile use require exact version and schema",
            );
            valid = false;
            continue;
        }
        if use_.requirement != CsmiVocabularyRequirement::Required {
            sink.error(
                "semantic.runtime_contract_required_use",
                format!("{path}.requirement"),
                "runtime-values 0.2 uses affecting runtime facts must be required",
            );
            valid = false;
        }
        for (index, affect) in use_.affects.iter().enumerate() {
            let CsmiAffectedUnit::FactFamily(family) = affect else {
                sink.error(
                    "semantic.runtime_contract_affect_kind",
                    format!("{path}.affects[{index}]"),
                    "runtime-values affects must identify a fact family",
                );
                valid = false;
                continue;
            };
            if family.kind != CsmiAffectedFactFamilyKind::FactFamily
                || !is_family_name(&family.family)
            {
                sink.error(
                    "semantic.runtime_contract_affect_family",
                    format!("{path}.affects[{index}].family"),
                    "runtime-values 0.2 affects must use one of the five profile families",
                );
                valid = false;
                continue;
            }
            affected.insert((family.family.clone(), canonical_scope_string(&family.scope)));
        }
    }

    let provenance_ids: HashSet<&str> = document
        .map(|document| {
            document
                .provenance_records
                .iter()
                .map(|record| record.id.as_str())
                .collect()
        })
        .unwrap_or_default();
    let mut records: Records = FAMILIES
        .iter()
        .map(|(family, _, _)| (*family, BTreeMap::new()))
        .collect();
    let mut fact_keys = HashSet::new();
    let mut payload_valid = true;
    for (index, fact) in model.extension_facts.iter().enumerate() {
        if fact.vocabulary != RUNTIME_CONTRACT_PROFILE_ID
            || fact.version != RUNTIME_CONTRACT_PROFILE_VERSION
        {
            continue;
        }
        let path = format!("{prefix}.extensionFacts[{index}]");
        if fact.version != RUNTIME_CONTRACT_PROFILE_VERSION {
            sink.error(
                "semantic.runtime_contract_fact_version",
                format!("{path}.version"),
                "runtime-values fact under a 0.2 profile use must use exact version 0.2.0",
            );
            valid = false;
            continue;
        }
        let Some((_family, identity_field)) = family_fields(&fact.family) else {
            sink.error(
                "semantic.runtime_contract_family",
                format!("{path}.family"),
                "runtime-values fact family is unsupported",
            );
            valid = false;
            continue;
        };
        let Some(identity) = fact.payload.get(identity_field).and_then(Value::as_str) else {
            sink.error(
                "semantic.runtime_contract_identity",
                format!("{path}.payload.{identity_field}"),
                "runtime-values record identity must be a string",
            );
            valid = false;
            continue;
        };
        let expected_scope = serde_json::json!({ identity_field: identity });
        let fact_key = (fact.family.clone(), canonical_scope_string(&expected_scope));
        if !fact_keys.insert(fact_key.clone()) {
            sink.error(
                "semantic.runtime_contract_duplicate",
                &path,
                format!("duplicate runtime-values identity {identity}"),
            );
            valid = false;
        }
        if fact.scope != expected_scope
            || !affected.contains(&(fact.family.clone(), canonical_scope_string(&expected_scope)))
        {
            sink.error(
                "semantic.runtime_contract_scope",
                format!("{path}.scope"),
                "runtime-values fact scope must match its identity and vocabulary affects",
            );
            valid = false;
        }
        let fact_provenance = fact
            .provenance
            .first()
            .map(String::as_str)
            .or_else(|| document.and_then(|document| document.default_provenance.as_deref()));
        let provenance_ok = fact_provenance.is_some_and(|id| provenance_ids.contains(id));
        if !provenance_ok {
            sink.error(
                "semantic.runtime_contract_provenance",
                format!("{path}.provenance"),
                "runtime-values fact requires one resolved provenance reference",
            );
            valid = false;
        }
        if !payload_issues(&fact.payload, &path, sink) {
            payload_valid = false;
            valid = false;
        }
        if let Some(entry) = records.get_mut(fact.family.as_str()) {
            entry.insert(identity.to_owned(), &fact.payload);
        }
    }

    for (family, scope) in &affected {
        if !fact_keys.contains(&(family.clone(), scope.clone())) {
            sink.error(
                "semantic.runtime_contract_missing_fact",
                format!("{prefix}.vocabularyUses"),
                "runtime-values affects must identify an extension fact",
            );
            valid = false;
        }
    }
    if !payload_valid {
        return valid;
    }

    for (family, _, identity_field) in FAMILIES {
        if !validate_completeness(model, &records[*family], identity_field, prefix, sink) {
            valid = false;
        }
    }
    if !validate_contract_applicability(model, &records["runtime-contracts"], prefix, sink) {
        valid = false;
    }
    if !validate_joins(&records, prefix, sink) {
        valid = false;
    }
    if !validate_observations(&records, prefix, sink) {
        valid = false;
    }
    valid
}

fn validate_completeness(
    model: &CsmiSemanticModel,
    records: &BTreeMap<String, &Value>,
    identity_field: &str,
    prefix: &str,
    sink: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    for (index, statement) in model.completeness_statements.iter().enumerate() {
        if statement.vocabulary.as_deref() != Some(RUNTIME_CONTRACT_PROFILE_ID) {
            continue;
        }
        let path = format!("{prefix}.completenessStatements[{index}]");
        if statement.version.as_deref() != Some(RUNTIME_CONTRACT_PROFILE_VERSION)
            || !is_family_name(&statement.family)
        {
            sink.error(
                "semantic.runtime_contract_completeness_version",
                &path,
                "runtime-values completeness statement has unsupported vocabulary, version, or family",
            );
            valid = false;
            continue;
        }
        let Some(record) = records.get(
            statement
                .scope
                .get(identity_field)
                .and_then(Value::as_str)
                .unwrap_or(""),
        ) else {
            sink.error(
                "semantic.runtime_contract_completeness_scope",
                format!("{path}.scope"),
                "runtime completeness scope has no runtime record",
            );
            valid = false;
            continue;
        };
        let coverage = match *record {
            record if record.get("kind").and_then(Value::as_str) == Some("runtime-target") => {
                record
                    .pointer("/definition/coverage")
                    .or(record.pointer("/definition/behavior/coverage"))
            }
            record => record
                .get("coverage")
                .or_else(|| record.pointer("/definition/behavior/coverage")),
        };
        let coverage_complete = coverage
            .and_then(|coverage| coverage.get("status"))
            .and_then(Value::as_str)
            == Some("complete");
        let activation_complete = record
            .pointer("/candidateCoverage/status")
            .and_then(Value::as_str)
            == Some("complete")
            && matches!(
                record.get("outcome").and_then(Value::as_str),
                Some("matched" | "not-matched" | "disabled")
            );
        let expected_complete = if statement.family == "runtime-activations" {
            activation_complete
        } else {
            coverage_complete
        };
        if statement.status == crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Complete
            && !expected_complete
        {
            sink.error(
                "semantic.runtime_contract_completeness_status",
                format!("{path}.status"),
                "complete runtime family contradicts record coverage",
            );
            valid = false;
        }
    }
    valid
}

fn validate_contract_applicability(
    model: &CsmiSemanticModel,
    contracts: &BTreeMap<String, &Value>,
    prefix: &str,
    sink: &mut Vec<CsmiDiagnostic>,
) -> bool {
    let mut valid = true;
    let selectors: Result<Vec<CsmiArtifactSelector>, _> = model
        .artifact_selectors
        .iter()
        .map(serde_json::to_value)
        .map(|value| value.and_then(serde_json::from_value::<CsmiArtifactSelector>))
        .collect();
    let Ok(outer) = selectors else {
        return true;
    };
    for (index, contract) in contracts {
        let Some(selector_values) = contract
            .pointer("/definition/applicability/selectors")
            .and_then(Value::as_array)
        else {
            continue;
        };
        for (selector_index, selector_value) in selector_values.iter().enumerate() {
            let Ok(selector) =
                serde_json::from_value::<CsmiArtifactSelector>(selector_value.clone())
            else {
                continue;
            };
            let covered = outer.iter().any(|candidate| {
                runtime_contract_selector_match(candidate, Some(&selector))
                    == RuntimeContractMatch::Matched
                    || serde_json::to_value(candidate).is_ok_and(|value| value == *selector_value)
            });
            if !covered {
                sink.error(
                    "semantic.runtime_contract_selector_exceeds_model",
                    format!("{prefix}.extensionFacts.runtime-contracts.{index}.definition.applicability.selectors[{selector_index}]"),
                    "contract selector exceeds enclosing model applicability",
                );
                valid = false;
            }
        }
    }
    valid
}

fn validate_joins(records: &Records, prefix: &str, sink: &mut Vec<CsmiDiagnostic>) -> bool {
    let mut valid = true;
    let contracts = &records["runtime-contracts"];
    let targets = &records["runtime-targets"];
    let activations = &records["runtime-activations"];
    let bindings = &records["runtime-bindings"];
    let path = format!("{prefix}.extensionFacts");

    for (identity, activation) in activations {
        let target_id = str_field(activation, "targetId");
        let candidate_ids = string_array(activation.get("candidateIds"));
        if !targets.contains_key(target_id)
            || candidate_ids
                .iter()
                .any(|candidate| !contracts.contains_key(candidate.as_str()))
        {
            sink.error(
                "semantic.runtime_contract_activation_unresolved",
                format!("{path}.runtime-activations.{identity}"),
                "activation target and candidates must resolve",
            );
            valid = false;
            continue;
        }
        let expected_candidates: HashSet<&str> = contracts
            .values()
            .filter(|contract| contract.pointer("/definition/surface") == activation.get("surface"))
            .filter_map(|contract| contract.get("contractId"))
            .filter_map(Value::as_str)
            .collect();
        let actual_candidates: HashSet<&str> = candidate_ids.iter().map(String::as_str).collect();
        if expected_candidates != actual_candidates {
            sink.error(
                "semantic.runtime_contract_candidate_inventory",
                format!("{path}.runtime-activations.{identity}.candidateIds"),
                "candidate inventory must contain every matching-surface contract and no others",
            );
            valid = false;
        }
        let disabled: HashSet<&str> = activation
            .get("disabledIds")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !disabled.is_subset(&actual_candidates) {
            sink.error(
                "semantic.runtime_contract_disabled_candidate",
                format!("{path}.runtime-activations.{identity}.disabledIds"),
                "disabled candidate must resolve in the activation inventory",
            );
            valid = false;
        }
        let digest = activation_digest(activation, contracts, targets);
        let expected = str_field(activation, "activationDigest");
        if digest.as_deref() != Some(expected) {
            sink.error(
                "semantic.runtime_contract_activation_digest",
                format!("{path}.runtime-activations.{identity}.activationDigest"),
                "activation digest must cover target, surface, complete candidates, decision, policy, and reviews",
            );
            valid = false;
        }

        // Recompute the wire decision from the independently supplied claim
        // set. The embedded policy and reviews are used here only to detect a
        // producer inconsistency; host authorization is intentionally absent.
        let Some(target) = targets.get(target_id) else {
            continue;
        };
        let contract_values: Vec<Value> = candidate_ids
            .iter()
            .filter_map(|candidate| contracts.get(candidate.as_str()))
            .map(|contract| (*contract).clone())
            .collect();
        let authorization = RuntimeContractAuthorization {
            accepted_policy_digests: runtime_digest(
                activation.get("policy").unwrap_or(&Value::Null),
            )
            .into_iter()
            .collect(),
            accepted_review_digests: activation
                .get("reviews")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(runtime_digest)
                .collect(),
        };
        match evaluate_runtime_contract_activation(
            activation,
            &contract_values,
            target,
            &authorization,
        ) {
            Ok(decision)
                if decision.outcome.label() == str_field(activation, "outcome")
                    && decision.selected_ids == string_array(activation.get("selectedIds")) => {}
            Ok(decision) => {
                sink.error(
                    "semantic.runtime_contract_activation_outcome",
                    format!("{path}.runtime-activations.{identity}"),
                    format!(
                        "activation wire outcome disagrees with recomputed claim: expected {} {:?}",
                        decision.outcome.label(),
                        decision.selected_ids
                    ),
                );
                valid = false;
            }
            Err(error) => {
                sink.error(
                    "semantic.runtime_contract_activation_outcome",
                    format!("{path}.runtime-activations.{identity}"),
                    format!("activation claims could not be recomputed: {error}"),
                );
                valid = false;
            }
        }
    }

    for (identity, binding) in bindings {
        let activation_id = str_field(binding, "activationId");
        let contract_id = str_field(binding, "contractId");
        let Some(activation) = activations.get(activation_id) else {
            sink.error(
                "semantic.runtime_contract_binding_activation",
                format!("{path}.runtime-bindings.{identity}"),
                "binding activation must resolve",
            );
            valid = false;
            continue;
        };
        let Some(contract) = contracts.get(contract_id) else {
            sink.error(
                "semantic.runtime_contract_binding_contract",
                format!("{path}.runtime-bindings.{identity}"),
                "binding contract must resolve",
            );
            valid = false;
            continue;
        };
        if str_field(activation, "activationDigest") != str_field(binding, "activationDigest")
            || !target_partition_contains(
                targets.get(str_field(activation, "targetId")).copied(),
                binding.get("source"),
            )
        {
            sink.error(
                "semantic.runtime_contract_binding_snapshot",
                format!("{path}.runtime-bindings.{identity}"),
                "binding source must join its activation snapshot and target partition",
            );
            valid = false;
        }
        if binding.get("outcome").and_then(Value::as_str) == Some("exact")
            && (activation.get("outcome").and_then(Value::as_str) != Some("matched")
                || !activation
                    .get("selectedIds")
                    .and_then(Value::as_array)
                    .is_some_and(|values| values.contains(&Value::String(contract_id.into())))
                || !contract
                    .pointer("/definition/languages")
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        values.contains(binding.get("language").unwrap_or(&Value::Null))
                    }))
        {
            sink.error(
                "semantic.runtime_contract_exact_binding",
                format!("{path}.runtime-bindings.{identity}.outcome"),
                "exact binding requires an active interpreted contract and language",
            );
            valid = false;
        }
    }
    valid
}

fn validate_observations(records: &Records, prefix: &str, sink: &mut Vec<CsmiDiagnostic>) -> bool {
    let mut valid = true;
    let path = format!("{prefix}.extensionFacts");
    let bindings = &records["runtime-bindings"];
    let contracts = &records["runtime-contracts"];
    let activations = &records["runtime-activations"];
    let targets = &records["runtime-targets"];
    let mut observation_claims: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (identity, observation) in &records["runtime-observations"] {
        let binding_id = str_field(observation, "bindingId");
        let Some(binding) = bindings.get(binding_id) else {
            sink.error(
                "semantic.runtime_contract_observation_binding",
                format!("{path}.runtime-observations.{identity}"),
                "observation binding must resolve",
            );
            valid = false;
            continue;
        };
        let Some(contract) = contracts.get(str_field(binding, "contractId")) else {
            continue;
        };
        let Some(activation) = activations.get(str_field(binding, "activationId")) else {
            continue;
        };
        let Some(target) = targets.get(str_field(activation, "targetId")) else {
            continue;
        };
        // Observations at one executable point must agree even when a
        // producer gives them different local IDs (for example, an alias
        // binding). Evidence metadata and the derived closure digest are
        // intentionally excluded from the claim: they explain the claim but
        // do not change the observed runtime result.
        let mut execution_key = Map::new();
        execution_key.insert(
            "targetDigest".to_owned(),
            target.get("targetDigest").cloned().unwrap_or(Value::Null),
        );
        for field in ["loadOperation", "point", "phase"] {
            execution_key.insert(
                field.to_owned(),
                observation.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        for field in ["invocation", "realm"] {
            execution_key.insert(
                field.to_owned(),
                observation
                    .get("store")
                    .and_then(|store| store.get(field))
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        let mut claim = Map::new();
        for field in ["baseValue", "resultValue", "key", "storageKey", "origin"] {
            claim.insert(
                field.to_owned(),
                observation.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        claim.insert(
            "proof".to_owned(),
            Value::Object(
                observation
                    .get("proof")
                    .and_then(Value::as_object)
                    .map(|proof| {
                        proof
                            .iter()
                            .filter(|(field, _)| *field != "evidence" && *field != "closureDigest")
                            .map(|(field, value)| (field.clone(), value.clone()))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
        );
        claim.insert(
            "store".to_owned(),
            Value::Object(
                observation
                    .get("store")
                    .and_then(Value::as_object)
                    .map(|store| {
                        store
                            .iter()
                            .filter(|(field, _)| *field != "evidence")
                            .map(|(field, value)| (field.clone(), value.clone()))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
        );
        observation_claims
            .entry(canonical_scope_string(&Value::Object(execution_key)))
            .or_default()
            .insert(canonical_scope_string(&Value::Object(claim)));
        let source = observation.get("source");
        let same_resource =
            source
                .zip(binding.get("source"))
                .is_some_and(|(observation, binding)| {
                    observation.get("resource") == binding.get("resource")
                        && observation.get("resourceDigest") == binding.get("resourceDigest")
                });
        if !same_resource
            || !source.and_then(source_range).is_some_and(|(start, end)| {
                binding.get("source").and_then(source_range).is_some_and(
                    |(binding_start, binding_end)| start <= binding_start && binding_end <= end,
                )
            })
        {
            sink.error(
                "semantic.runtime_contract_observation_source",
                format!("{path}.runtime-observations.{identity}.source"),
                "observation source must contain its binding occurrence",
            );
            valid = false;
        }
        let behavior = contract.pointer("/definition/behavior");
        let key = observation.get("key");
        let key_domain = behavior
            .and_then(|behavior| behavior.get("keyDomain"))
            .and_then(Value::as_str);
        let key_kind = key.and_then(|key| key.get("kind")).and_then(Value::as_str);
        if matches!(key_kind, Some("property" | "index"))
            && key_domain
                != Some(if key_kind == Some("property") {
                    "static-property"
                } else {
                    "static-index"
                })
        {
            sink.error(
                "semantic.runtime_contract_observation_key_domain",
                format!("{path}.runtime-observations.{identity}.key"),
                "observation key must be in the contract behavior key domain",
            );
            valid = false;
        }
        if observation.pointer("/proof/normal").and_then(Value::as_str) == Some("exact")
            && str_field(binding, "outcome") != "exact"
        {
            sink.error(
                "semantic.runtime_contract_observation_exact_binding",
                format!("{path}.runtime-observations.{identity}.proof.normal"),
                "an exact load requires an exact root and container binding",
            );
            valid = false;
        }
        let lookup = observation
            .pointer("/proof/lookup")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let behavior_lookup = behavior
            .and_then(|behavior| behavior.get("lookup"))
            .and_then(Value::as_str);
        if lookup.starts_with("mapping") && behavior_lookup != Some("mapping-entry") {
            sink.error(
                "semantic.runtime_contract_observation_lookup",
                format!("{path}.runtime-observations.{identity}.proof.lookup"),
                "mapping lookup proof cannot satisfy own-value behavior",
            );
            valid = false;
        }
        if matches!(lookup, "own-present" | "absent-no-fallback")
            && behavior_lookup != Some("own-value")
        {
            sink.error(
                "semantic.runtime_contract_observation_lookup",
                format!("{path}.runtime-observations.{identity}.proof.lookup"),
                "own-value lookup proof cannot satisfy mapping behavior",
            );
            valid = false;
        }
        let origin = str_field(observation, "origin");
        if origin == "initial-if-present"
            && !matches!(lookup, "own-present" | "mapping-present" | "unknown")
        {
            sink.error(
                "semantic.runtime_contract_observation_initial_lookup",
                format!("{path}.runtime-observations.{identity}.origin"),
                "initial origin requires an initial entry lookup result",
            );
            valid = false;
        }
        if origin == "absent" && !matches!(lookup, "absent-no-fallback" | "mapping-absent") {
            sink.error(
                "semantic.runtime_contract_observation_absent_lookup",
                format!("{path}.runtime-observations.{identity}.origin"),
                "absent origin requires an absence proof",
            );
            valid = false;
        }
        if observation
            .get("coverage")
            .and_then(|coverage| coverage.get("status"))
            .and_then(Value::as_str)
            == Some("complete")
        {
            let binding_complete =
                binding.pointer("/coverage/status").and_then(Value::as_str) == Some("complete");
            let behavior_complete = behavior
                .and_then(|behavior| behavior.pointer("/coverage/status"))
                .and_then(Value::as_str)
                == Some("complete");
            let storage_key = observation.get("storageKey").unwrap_or(&Value::Null);
            let supported_key = matches!(
                key.and_then(|key| key.get("kind")).and_then(Value::as_str),
                Some("property" | "index")
            ) && matches!(
                storage_key.get("kind").and_then(Value::as_str),
                Some("property" | "index")
            ) && behavior
                .and_then(|behavior| behavior.pointer("/keyEquality/version"))
                .and_then(Value::as_str)
                == Some(RUNTIME_CONTRACT_PROFILE_VERSION);
            if !binding_complete
                || !behavior_complete
                || observation
                    .pointer("/proof/initialization")
                    .and_then(Value::as_str)
                    != Some("closed")
                || observation
                    .pointer("/proof/dependencies")
                    .and_then(Value::as_str)
                    != Some("closed")
                || matches!(
                    observation
                        .pointer("/proof/mutation")
                        .and_then(Value::as_str),
                    None | Some("unknown")
                )
                || matches!(
                    observation.pointer("/proof/lookup").and_then(Value::as_str),
                    None | Some("inherited" | "accessor" | "proxy" | "unknown")
                )
                || observation
                    .pointer("/proof/materialization")
                    .and_then(Value::as_str)
                    != Some("resolved")
                || observation.pointer("/proof/normal").and_then(Value::as_str) != Some("exact")
                || observation
                    .pointer("/proof/exceptional")
                    .and_then(Value::as_str)
                    == Some("unknown")
                || !supported_key
                || origin == "unknown"
                || observation
                    .pointer("/proof/keyNormalization")
                    .and_then(Value::as_str)
                    != Some("exact")
                || observation
                    .pointer("/store/relationship")
                    .and_then(Value::as_str)
                    == Some("unknown")
            {
                sink.error(
                    "semantic.runtime_contract_observation_completeness",
                    format!("{path}.runtime-observations.{identity}.coverage"),
                    "complete observation requires complete binding, behavior, and closed proof obligations",
                );
                valid = false;
            }
        }
        let container = binding.get("container");
        if observation.get("baseValue") != container
            || observation.pointer("/store/container") != container
        {
            sink.error(
                "semantic.runtime_contract_observation_container",
                format!("{path}.runtime-observations.{identity}.baseValue"),
                "observation base and store container must join the binding container",
            );
            valid = false;
        }
        let realm = target
            .pointer("/definition/context/realm")
            .and_then(Value::as_str);
        let relationship = observation
            .pointer("/store/relationship")
            .and_then(Value::as_str);
        if realm == Some("worker-shared") && !matches!(relationship, Some("shared" | "unknown")) {
            sink.error(
                "semantic.runtime_contract_shared_worker_store",
                format!("{path}.runtime-observations.{identity}.store.relationship"),
                "a shared worker cannot claim an isolated or copied environment",
            );
            valid = false;
        }
    }
    if observation_claims.values().any(|claims| claims.len() > 1) {
        sink.error(
            "semantic.runtime_contract_observation_conflict",
            format!("{path}.runtime-observations"),
            "observations at one executable point make contradictory claims",
        );
        valid = false;
    }
    valid
}

fn payload_issues(payload: &Value, path: &str, sink: &mut Vec<CsmiDiagnostic>) -> bool {
    let mut valid = true;
    match payload.get("kind").and_then(Value::as_str) {
        Some("runtime-contract") => {
            let Some(definition) = payload.get("definition") else {
                return false;
            };
            if runtime_digest(definition).as_deref()
                != payload.get("contractDigest").and_then(Value::as_str)
            {
                sink.error(
                    "semantic.runtime_contract_content_digest",
                    format!("{path}.contractDigest"),
                    "contract digest must hash its canonical definition",
                );
                valid = false;
            }
            if definition
                .get("applicability")
                .is_some_and(|applicability| {
                    applicability.get("basis").and_then(Value::as_str) == Some("artifact-specific")
                })
                && definition
                    .pointer("/applicability/selectors")
                    .and_then(Value::as_array)
                    .is_some_and(|selectors| {
                        selectors
                            .iter()
                            .any(|selector| selector.get("versionRange").is_some())
                    })
            {
                sink.error(
                    "semantic.runtime_contract_artifact_specialization",
                    format!("{path}.definition.applicability"),
                    "artifact-specific specialization requires exact artifact versions",
                );
                valid = false;
            }
            let Some(behavior) = definition.get("behavior") else {
                return false;
            };
            let surface_container = definition
                .pointer("/surface/container")
                .and_then(Value::as_str);
            let initial_origins = definition.pointer("/behavior/initialOrigins");
            let coverage_complete =
                behavior.pointer("/coverage/status").and_then(Value::as_str) == Some("complete");
            if coverage_complete
                && (behavior.pointer("/read/exceptions").and_then(Value::as_str) == Some("unknown")
                    || behavior
                        .pointer("/read/materialization")
                        .and_then(Value::as_str)
                        == Some("unknown")
                    || behavior
                        .pointer("/write/conversion")
                        .and_then(Value::as_str)
                        == Some("unknown")
                    || behavior.pointer("/write/normal").and_then(Value::as_str) == Some("unknown")
                    || behavior
                        .pointer("/write/exceptional")
                        .and_then(Value::as_str)
                        == Some("unknown")
                    || behavior.pointer("/delete/normal").and_then(Value::as_str)
                        == Some("unknown")
                    || behavior
                        .pointer("/delete/exceptional")
                        .and_then(Value::as_str)
                        == Some("unknown")
                    || initial_origins
                        .and_then(Value::as_array)
                        .is_some_and(|origins| {
                            origins.iter().any(|origin| {
                                origin.get("origin").and_then(Value::as_str) == Some("unknown")
                            })
                        }))
            {
                sink.error(
                    "semantic.runtime_contract_complete_behavior",
                    format!("{path}.definition.behavior.coverage"),
                    "complete behavior cannot contain unknown semantics",
                );
                valid = false;
            }
            let equality = behavior.pointer("/keyEquality");
            let key_domain = behavior.get("keyDomain").and_then(Value::as_str);
            if equality
                .and_then(|equality| equality.get("version"))
                .and_then(Value::as_str)
                == Some(RUNTIME_CONTRACT_PROFILE_VERSION)
            {
                let equality_name = equality
                    .and_then(|equality| equality.get("identifier"))
                    .and_then(Value::as_str);
                if equality_name == Some("https://csmi.brokk.ai/key-equality/exact-string")
                    && key_domain != Some("static-property")
                {
                    sink.error(
                        "semantic.runtime_contract_key_domain",
                        format!("{path}.definition.behavior.keyDomain"),
                        "exact-string equality requires static-property keys",
                    );
                    valid = false;
                }
                if equality_name == Some("https://csmi.brokk.ai/key-equality/exact-index")
                    && key_domain != Some("static-index")
                {
                    sink.error(
                        "semantic.runtime_contract_key_domain",
                        format!("{path}.definition.behavior.keyDomain"),
                        "exact-index equality requires static-index keys",
                    );
                    valid = false;
                }
            }
            let Some(context) = definition.get("context") else {
                return false;
            };
            let context_scheme = context
                .pointer("/scheme/identifier")
                .and_then(Value::as_str);
            if context_scheme == Some("https://csmi.brokk.ai/runtime-context/node")
                && surface_container == Some("env")
                && context
                    .get("platform")
                    .and_then(Value::as_array)
                    .is_some_and(|platform| platform.iter().any(|value| value == "windows"))
                && context
                    .get("realm")
                    .and_then(Value::as_array)
                    .is_some_and(|realm| {
                        realm
                            .iter()
                            .any(|value| value == "main" || value == "worker-shared")
                    })
                && equality
                    .and_then(|equality| equality.get("identifier"))
                    .and_then(Value::as_str)
                    == Some("https://csmi.brokk.ai/key-equality/exact-string")
            {
                sink.error(
                    "semantic.runtime_contract_windows_equality",
                    format!("{path}.definition.behavior.keyEquality"),
                    "Windows native environment cannot use exact-string equality",
                );
                valid = false;
            }
            if context_scheme == Some("https://csmi.brokk.ai/runtime-context/node")
                && surface_container == Some("argv")
                && context
                    .get("launchMode")
                    .and_then(Value::as_array)
                    .is_some_and(|modes| {
                        modes.len() != 1 || modes.first().and_then(Value::as_str) != Some("script")
                    })
                && initial_origins
                    .and_then(Value::as_array)
                    .is_some_and(|origins| {
                        origins.iter().any(|origin| {
                            matches!(
                                origin.get("origin").and_then(Value::as_str),
                                Some("application-argument" | "entry-path")
                            )
                        })
                    })
            {
                sink.error(
                    "semantic.runtime_contract_argv_launch_mode",
                    format!("{path}.definition.context.launchMode"),
                    "script argv origins cannot cover another launch mode",
                );
                valid = false;
            }
            if context_scheme == Some("https://csmi.brokk.ai/runtime-context/node")
                && surface_container == Some("argv")
                && behavior
                    .pointer("/write/conversion")
                    .and_then(Value::as_str)
                    == Some("string-conversion")
            {
                sink.error(
                    "semantic.runtime_contract_argv_conversion",
                    format!("{path}.definition.behavior.write.conversion"),
                    "ordinary argv writes do not imply string conversion",
                );
                valid = false;
            }
            if context_scheme == Some("https://csmi.brokk.ai/runtime-context/cpython")
                && surface_container == Some("environ")
                && (behavior.get("lookup").and_then(Value::as_str) != Some("mapping-entry")
                    || behavior.get("absent").and_then(Value::as_str) != Some("exception"))
            {
                sink.error(
                    "semantic.runtime_contract_cpython_lookup",
                    format!("{path}.definition.behavior"),
                    "CPython environ subscription requires mapping and missing-key exception behavior",
                );
                valid = false;
            }
            if context_scheme == Some("https://csmi.brokk.ai/runtime-context/cpython")
                && surface_container == Some("environ")
                && behavior
                    .pointer("/write/conversion")
                    .and_then(Value::as_str)
                    == Some("string-conversion")
            {
                sink.error(
                    "semantic.runtime_contract_cpython_conversion",
                    format!("{path}.definition.behavior.write.conversion"),
                    "CPython environ assignments do not imply arbitrary string conversion",
                );
                valid = false;
            }
            let mut ranges = Vec::new();
            if let Some(origins) = initial_origins.and_then(Value::as_array) {
                for origin in origins {
                    let keys = origin.get("keys");
                    let kind = keys
                        .and_then(|keys| keys.get("kind"))
                        .and_then(Value::as_str);
                    if (kind == Some("all-properties")) != (key_domain == Some("static-property")) {
                        sink.error(
                            "semantic.runtime_contract_origin_domain",
                            format!("{path}.definition.behavior.initialOrigins"),
                            "initial origin key domain disagrees with behavior key domain",
                        );
                        valid = false;
                    }
                    if kind == Some("index-range") {
                        let minimum = keys
                            .and_then(|keys| keys.get("minimum"))
                            .and_then(Value::as_u64);
                        let maximum = keys
                            .and_then(|keys| keys.get("maximum"))
                            .and_then(Value::as_u64);
                        if minimum
                            .zip(maximum)
                            .is_none_or(|(minimum, maximum)| minimum > maximum)
                        {
                            sink.error(
                                "semantic.runtime_contract_origin_range",
                                format!("{path}.definition.behavior.initialOrigins"),
                                "initial origin index ranges must be ordered",
                            );
                            valid = false;
                        } else if let Some(range) = minimum.zip(maximum) {
                            ranges.push(range);
                        }
                    }
                }
            }
            ranges.sort_unstable();
            if ranges.windows(2).any(|window| window[0].1 >= window[1].0) {
                sink.error(
                    "semantic.runtime_contract_origin_overlap",
                    format!("{path}.definition.behavior.initialOrigins"),
                    "initial origin index ranges must not overlap",
                );
                valid = false;
            }
        }
        Some("runtime-target") => {
            let Some(definition) = payload.get("definition") else {
                return false;
            };
            if runtime_digest(definition).as_deref()
                != payload.get("targetDigest").and_then(Value::as_str)
            {
                sink.error(
                    "semantic.runtime_contract_target_digest",
                    format!("{path}.targetDigest"),
                    "target digest must hash its canonical definition",
                );
                valid = false;
            }
            if definition.get("basis").and_then(Value::as_str) == Some("unknown")
                && definition
                    .pointer("/coverage/status")
                    .and_then(Value::as_str)
                    == Some("complete")
            {
                sink.error(
                    "semantic.runtime_contract_unknown_target_coverage",
                    format!("{path}.definition.coverage"),
                    "unknown target cannot have complete target coverage",
                );
                valid = false;
            }
            if definition.get("basis").and_then(Value::as_str) == Some("deployment-observation")
                && definition.pointer("/runtime/versionRange").is_some()
            {
                sink.error(
                    "semantic.runtime_contract_deployment_observation",
                    format!("{path}.definition.runtime"),
                    "deployment observation requires an exact observed runtime",
                );
                valid = false;
            }
        }
        Some("runtime-observation") => {
            let proof = payload.get("proof");
            let actual_digest = proof.and_then(Value::as_object).and_then(|proof| {
                let closure = proof.clone();
                let mut without_digest = closure;
                without_digest.remove("closureDigest");
                runtime_digest(&Value::Object(without_digest))
            });
            if actual_digest.as_deref()
                != payload
                    .pointer("/proof/closureDigest")
                    .and_then(Value::as_str)
            {
                sink.error(
                    "semantic.runtime_contract_proof_digest",
                    format!("{path}.proof.closureDigest"),
                    "proof closure digest must exclude the closureDigest field",
                );
                valid = false;
            }
        }
        _ => {}
    }
    valid
}

fn family_fields(family: &str) -> Option<(&'static str, &'static str)> {
    FAMILIES
        .iter()
        .find_map(|(name, _, identity_field)| (*name == family).then_some((*name, *identity_field)))
}

fn is_family_name(family: &str) -> bool {
    FAMILIES.iter().any(|(name, _, _)| *name == family)
}

fn str_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or_default()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn source_range(value: &Value) -> Option<(u64, u64)> {
    Some((
        value.get("startByte")?.as_u64()?,
        value.get("endByte")?.as_u64()?,
    ))
}

fn target_partition_contains(target: Option<&Value>, source: Option<&Value>) -> bool {
    let Some(source) = source else {
        return false;
    };
    let Some(resource) = source.get("resource") else {
        return false;
    };
    let Some(resource_digest) = source.get("resourceDigest") else {
        return false;
    };
    let identity = serde_json::json!({
        "resource": resource,
        "resourceDigest": resource_digest,
    });
    target
        .and_then(|target| target.pointer("/definition/resources"))
        .and_then(Value::as_array)
        .is_some_and(|resources| resources.contains(&identity))
}

fn activation_digest(
    activation: &Value,
    contracts: &BTreeMap<String, &Value>,
    targets: &BTreeMap<String, &Value>,
) -> Option<String> {
    let target = targets.get(str_field(activation, "targetId"))?;
    let mut contracts_in_order = Vec::new();
    for candidate in activation.get("candidateIds")?.as_array()? {
        contracts_in_order.push(contracts.get(candidate.as_str()?)?);
    }
    let mut input = Map::new();
    input.insert("targetDigest".into(), target.get("targetDigest")?.clone());
    input.insert("surface".into(), activation.get("surface")?.clone());
    input.insert(
        "contracts".into(),
        Value::Array(
            contracts_in_order
                .into_iter()
                .map(|value| (**value).clone())
                .collect(),
        ),
    );
    for field in [
        "candidateCoverage",
        "disabledIds",
        "reviews",
        "policy",
        "outcome",
        "selectedIds",
    ] {
        input.insert(field.into(), activation.get(field)?.clone());
    }
    runtime_digest(&Value::Object(input))
}
