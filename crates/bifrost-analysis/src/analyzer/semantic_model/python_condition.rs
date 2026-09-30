//! Pure, conservative evaluation of CSMI Python profile conditions.
//!
//! This module does not discover an interpreter, infer package extras, or
//! select semantic-model shards. A caller must supply an explicit snapshot.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::csmi::{CsmiArtifactDigest, CsmiJson};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonConditionSnapshot {
    /// The interpreter's original version spelling, not a formatted SemVer.
    pub python_version_raw: Option<String>,
    pub implementation: Option<String>,
    pub abi_tag: Option<String>,
    pub platform_tag: Option<String>,
    /// `Some(empty)` proves that no extras are enabled; `None` is unknown.
    pub enabled_extras: Option<BTreeSet<String>>,
    pub project_config: Option<CsmiArtifactDigest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonConditionStatus {
    Compatible,
    Incompatible,
    Indeterminate,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonConditionField {
    Condition,
    Python,
    Implementation,
    Abi,
    Platform,
    Extras,
    ProjectConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonConditionFindingKind {
    Missing,
    Mismatch,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonConditionFinding {
    pub field: PythonConditionField,
    pub kind: PythonConditionFindingKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonConditionEvaluation {
    /// Interpretability priority, not a Boolean conjunction truth value.
    /// Every field finding is retained even when another field decides this.
    pub status: PythonConditionStatus,
    pub findings: Vec<PythonConditionFinding>,
}

/// Evaluate every present field and retain simultaneous mismatches, missing
/// evidence, and unsupported semantics. Only an empty finding set applies.
pub fn evaluate_python_condition(
    condition: Option<&CsmiJson>,
    snapshot: &PythonConditionSnapshot,
) -> PythonConditionEvaluation {
    let mut findings = Vec::new();
    let mut invalid_snapshot = BTreeSet::new();

    for (field, name, value) in [
        (
            PythonConditionField::Python,
            "python",
            snapshot
                .python_version_raw
                .as_ref()
                .map(|value| Value::String(value.clone())),
        ),
        (
            PythonConditionField::Implementation,
            "implementation",
            snapshot
                .implementation
                .as_ref()
                .map(|value| serde_json::json!([value])),
        ),
        (
            PythonConditionField::Abi,
            "abi",
            snapshot
                .abi_tag
                .as_ref()
                .map(|value| serde_json::json!([value])),
        ),
        (
            PythonConditionField::Platform,
            "platform",
            snapshot
                .platform_tag
                .as_ref()
                .map(|value| serde_json::json!([value])),
        ),
    ] {
        if let Some(value) = value {
            let mut errors = validate_field(name, value);
            if field == PythonConditionField::Python
                && snapshot
                    .python_version_raw
                    .as_ref()
                    .is_some_and(|version| version.starts_with("vers:"))
            {
                errors.push("interpreter evidence must be an exact version".to_owned());
            }
            if !errors.is_empty() {
                invalid_snapshot.insert(name);
                findings.push(PythonConditionFinding {
                    field,
                    kind: PythonConditionFindingKind::Unsupported,
                    reason: format!("invalid {name} snapshot evidence: {errors:?}"),
                });
            }
        }
    }
    if let Some(extras) = &snapshot.enabled_extras {
        for extra in extras {
            let errors = validate_field("extras", serde_json::json!([extra]));
            if !errors.is_empty() {
                invalid_snapshot.insert("extras");
                findings.push(PythonConditionFinding {
                    field: PythonConditionField::Extras,
                    kind: PythonConditionFindingKind::Unsupported,
                    reason: format!("invalid enabled extra {extra:?}: {errors:?}"),
                });
            }
        }
    }
    if let Some(digest) = &snapshot.project_config {
        let value = serde_json::to_value(digest).expect("typed CSMI digest serializes");
        let errors = validate_field("projectConfig", value);
        if !errors.is_empty() || !valid_project_config_uri(digest) {
            invalid_snapshot.insert("projectConfig");
            findings.push(PythonConditionFinding {
                field: PythonConditionField::ProjectConfig,
                kind: PythonConditionFindingKind::Unsupported,
                reason: format!(
                    "invalid projectConfig snapshot digest or canonicalization URI: {errors:?}"
                ),
            });
        }
    }

    if let Some(condition) = condition {
        let mut errors = super::csmi::validate_python_profile_condition(condition);
        errors.sort();
        for error in errors {
            findings.push(PythonConditionFinding {
                field: PythonConditionField::Condition,
                kind: PythonConditionFindingKind::Unsupported,
                reason: format!("invalid Python profile condition: {error}"),
            });
        }
        if let Some(fields) = condition.as_object() {
            if let Some(required) = fields.get("python") {
                match (required.as_str(), snapshot.python_version_raw.as_deref()) {
                    (Some(version), _) if version.starts_with("vers:generic/") => {
                        push_unsupported(
                            &mut findings,
                            PythonConditionField::Python,
                            "vers:generic has no specified comparison procedure",
                        );
                    }
                    (Some(_), None) => push_missing(&mut findings, PythonConditionField::Python),
                    (Some(_), Some(_)) if invalid_snapshot.contains("python") => {}
                    (Some(version), Some(actual)) if version == actual => {}
                    (Some(version), Some(actual))
                        if canonical_stable_version(version).is_some()
                            && canonical_stable_version(actual).is_some() =>
                    {
                        push_mismatch(&mut findings, PythonConditionField::Python);
                    }
                    (Some(_), Some(_)) => push_unsupported(
                        &mut findings,
                        PythonConditionField::Python,
                        "distinct noncanonical or nonstable exact versions lack a supported comparison",
                    ),
                    _ => {}
                }
            }
            for (name, field, actual) in [
                (
                    "implementation",
                    PythonConditionField::Implementation,
                    snapshot.implementation.as_deref(),
                ),
                (
                    "abi",
                    PythonConditionField::Abi,
                    snapshot.abi_tag.as_deref(),
                ),
                (
                    "platform",
                    PythonConditionField::Platform,
                    snapshot.platform_tag.as_deref(),
                ),
            ] {
                if let Some(required) = fields.get(name) {
                    if invalid_snapshot.contains(name) {
                        continue;
                    }
                    match actual {
                        None => push_missing(&mut findings, field),
                        Some(actual) => {
                            if let Some(values) = required.as_array()
                                && values.iter().all(Value::is_string)
                                && !values.iter().any(|value| value.as_str() == Some(actual))
                            {
                                push_mismatch(&mut findings, field);
                            }
                        }
                    }
                }
            }
            if let Some(required) = fields.get("extras")
                && !invalid_snapshot.contains("extras")
            {
                match &snapshot.enabled_extras {
                    None => push_missing(&mut findings, PythonConditionField::Extras),
                    Some(actual) => {
                        if let Some(values) = required.as_array()
                            && values.iter().all(Value::is_string)
                            && values
                                .iter()
                                .any(|value| !actual.contains(value.as_str().unwrap()))
                        {
                            push_mismatch(&mut findings, PythonConditionField::Extras);
                        }
                    }
                }
            }
            if let Some(required) = fields.get("projectConfig") {
                let typed = serde_json::from_value::<CsmiArtifactDigest>(required.clone());
                if typed
                    .as_ref()
                    .is_ok_and(|digest| !valid_project_config_uri(digest))
                {
                    push_unsupported(
                        &mut findings,
                        PythonConditionField::ProjectConfig,
                        "projectConfig condition has no absolute canonicalization URI",
                    );
                }
                if !invalid_snapshot.contains("projectConfig") {
                    match &snapshot.project_config {
                        None => push_missing(&mut findings, PythonConditionField::ProjectConfig),
                        Some(actual) => {
                            if let Ok(required) = typed
                                && valid_project_config_uri(&required)
                                && &required != actual
                            {
                                push_mismatch(&mut findings, PythonConditionField::ProjectConfig);
                            }
                        }
                    }
                }
            }
        }
    }
    let status = if findings
        .iter()
        .any(|finding| finding.kind == PythonConditionFindingKind::Unsupported)
    {
        PythonConditionStatus::Unsupported
    } else if findings
        .iter()
        .any(|finding| finding.kind == PythonConditionFindingKind::Missing)
    {
        PythonConditionStatus::Indeterminate
    } else if findings
        .iter()
        .any(|finding| finding.kind == PythonConditionFindingKind::Mismatch)
    {
        PythonConditionStatus::Incompatible
    } else {
        PythonConditionStatus::Compatible
    };
    PythonConditionEvaluation { status, findings }
}

fn valid_project_config_uri(digest: &CsmiArtifactDigest) -> bool {
    digest
        .canonicalization
        .as_ref()
        .is_some_and(|uri| url::Url::parse(uri).is_ok_and(|parsed| !parsed.scheme().is_empty()))
}

fn validate_field(name: &str, value: Value) -> Vec<String> {
    let mut condition = Map::new();
    condition.insert(name.to_owned(), value);
    super::csmi::validate_python_profile_condition(&Value::Object(condition))
}

fn canonical_stable_version(value: &str) -> Option<semver::Version> {
    let parsed = semver::Version::parse(value).ok()?;
    (parsed.pre.is_empty() && parsed.build.is_empty() && parsed.to_string() == value)
        .then_some(parsed)
}

fn push_missing(findings: &mut Vec<PythonConditionFinding>, field: PythonConditionField) {
    findings.push(PythonConditionFinding {
        field,
        kind: PythonConditionFindingKind::Missing,
        reason: "required environment evidence is unavailable".to_owned(),
    });
}

fn push_mismatch(findings: &mut Vec<PythonConditionFinding>, field: PythonConditionField) {
    findings.push(PythonConditionFinding {
        field,
        kind: PythonConditionFindingKind::Mismatch,
        reason: "exact environment evidence does not satisfy this condition".to_owned(),
    });
}

fn push_unsupported(
    findings: &mut Vec<PythonConditionFinding>,
    field: PythonConditionField,
    reason: &str,
) {
    findings.push(PythonConditionFinding {
        field,
        kind: PythonConditionFindingKind::Unsupported,
        reason: reason.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::super::csmi::CsmiDigestAlgorithm;
    use super::*;
    use serde_json::json;

    fn digest(value: &str, canonicalization: &str) -> CsmiArtifactDigest {
        CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: "resolver-affecting-config".to_owned(),
            canonicalization: Some(canonicalization.to_owned()),
            value: value.to_owned(),
        }
    }

    #[test]
    fn python_condition_exact_version_is_bounded_by_raw_evidence() {
        let mut snapshot = PythonConditionSnapshot {
            python_version_raw: Some("3.13.0".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            evaluate_python_condition(Some(&json!({"python":"3.13.0"})), &snapshot).status,
            PythonConditionStatus::Compatible
        );
        assert_eq!(
            evaluate_python_condition(Some(&json!({"python":"3.12.0"})), &snapshot).status,
            PythonConditionStatus::Incompatible
        );
        assert_eq!(
            evaluate_python_condition(Some(&json!({"python":"3.13"})), &snapshot).status,
            PythonConditionStatus::Unsupported
        );
        snapshot.python_version_raw = Some("3.13".to_owned());
        assert_eq!(
            evaluate_python_condition(Some(&json!({"python":"3.13"})), &snapshot).status,
            PythonConditionStatus::Compatible
        );
        snapshot.python_version_raw = None;
        assert_eq!(
            evaluate_python_condition(Some(&json!({"python":"3.13"})), &snapshot).status,
            PythonConditionStatus::Indeterminate
        );
    }

    #[test]
    fn python_condition_generic_range_and_unknown_field_are_unsupported() {
        let snapshot = PythonConditionSnapshot {
            python_version_raw: Some("3.13.0".to_owned()),
            ..Default::default()
        };
        let range = evaluate_python_condition(
            Some(&json!({"python":"vers:generic/>=3.12.0|<4.0.0"})),
            &snapshot,
        );
        assert_eq!(range.status, PythonConditionStatus::Unsupported);
        assert!(range.findings.iter().any(|finding| {
            finding.field == PythonConditionField::Python
                && finding.kind == PythonConditionFindingKind::Unsupported
        }));
        let unknown = evaluate_python_condition(Some(&json!({"futureField":true})), &snapshot);
        assert_eq!(unknown.status, PythonConditionStatus::Unsupported);
        assert!(
            unknown
                .findings
                .iter()
                .any(|finding| finding.field == PythonConditionField::Condition)
        );
    }

    #[test]
    fn python_condition_keeps_all_field_findings_in_stable_order() {
        let snapshot = PythonConditionSnapshot {
            python_version_raw: Some("3.13.0".to_owned()),
            implementation: Some("cpython".to_owned()),
            ..Default::default()
        };
        let left = json!({
            "python":"vers:generic/>=3.12.0",
            "implementation":["pypy"],
            "abi":["cp313"],
            "extras":["fast"]
        });
        let right = json!({
            "extras":["fast"],
            "abi":["cp313"],
            "implementation":["pypy"],
            "python":"vers:generic/>=3.12.0"
        });
        let evaluation = evaluate_python_condition(Some(&left), &snapshot);
        assert_eq!(
            evaluation,
            evaluate_python_condition(Some(&right), &snapshot)
        );
        assert_eq!(evaluation.status, PythonConditionStatus::Unsupported);
        assert_eq!(
            evaluation
                .findings
                .iter()
                .map(|finding| (finding.field, finding.kind))
                .collect::<Vec<_>>(),
            vec![
                (
                    PythonConditionField::Python,
                    PythonConditionFindingKind::Unsupported
                ),
                (
                    PythonConditionField::Implementation,
                    PythonConditionFindingKind::Mismatch,
                ),
                (
                    PythonConditionField::Abi,
                    PythonConditionFindingKind::Missing
                ),
                (
                    PythonConditionField::Extras,
                    PythonConditionFindingKind::Missing
                ),
            ]
        );
        let without_range = evaluate_python_condition(
            Some(&json!({"implementation":["pypy"], "abi":["cp313"]})),
            &snapshot,
        );
        assert_eq!(without_range.status, PythonConditionStatus::Indeterminate);
        assert_eq!(
            without_range
                .findings
                .iter()
                .map(|finding| finding.kind)
                .collect::<Vec<_>>(),
            vec![
                PythonConditionFindingKind::Mismatch,
                PythonConditionFindingKind::Missing
            ]
        );
    }

    #[test]
    fn python_condition_distinguishes_missing_from_known_empty_extras_and_digest_mismatch() {
        let condition = json!({
            "extras":["fast"],
            "projectConfig": {
                "algorithm":"sha-256",
                "coverage":"resolver-affecting-config",
                "canonicalization":"https://example.test/config-v1",
                "value":"a".repeat(64)
            }
        });
        let mut snapshot = PythonConditionSnapshot::default();
        assert_eq!(
            evaluate_python_condition(Some(&condition), &snapshot).status,
            PythonConditionStatus::Indeterminate
        );
        snapshot.enabled_extras = Some(BTreeSet::new());
        snapshot.project_config = Some(digest(&"b".repeat(64), "https://example.test/config-v1"));
        let result = evaluate_python_condition(Some(&condition), &snapshot);
        assert_eq!(result.status, PythonConditionStatus::Incompatible);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.field)
                .collect::<Vec<_>>(),
            vec![
                PythonConditionField::Extras,
                PythonConditionField::ProjectConfig
            ]
        );
        snapshot.enabled_extras = Some(BTreeSet::from(["fast".to_owned()]));
        snapshot.project_config = Some(digest(&"a".repeat(64), "https://example.test/config-v1"));
        assert_eq!(
            evaluate_python_condition(Some(&condition), &snapshot).status,
            PythonConditionStatus::Compatible
        );
    }

    #[test]
    fn python_condition_rejects_malformed_snapshot_values_before_compatibility() {
        let snapshot = PythonConditionSnapshot {
            implementation: Some(String::new()),
            project_config: Some(digest("a", "relative/path")),
            ..Default::default()
        };
        let result = evaluate_python_condition(
            Some(&json!({"implementation":["cpython"], "projectConfig": {
                "algorithm":"sha-256",
                "coverage":"resolver-affecting-config",
                "canonicalization":"https://example.test/config-v1",
                "value":"a".repeat(64)
            }})),
            &snapshot,
        );
        assert_eq!(result.status, PythonConditionStatus::Unsupported);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.field)
                .collect::<Vec<_>>(),
            vec![
                PythonConditionField::Implementation,
                PythonConditionField::ProjectConfig
            ]
        );
        assert_eq!(
            evaluate_python_condition(None, &snapshot).status,
            PythonConditionStatus::Unsupported
        );

        let valid_snapshot = PythonConditionSnapshot {
            project_config: Some(digest(&"a".repeat(64), "https://example.test/config-v1")),
            ..Default::default()
        };
        let bad_condition = evaluate_python_condition(
            Some(&json!({"projectConfig": {
                "algorithm":"sha-256",
                "coverage":"resolver-affecting-config",
                "canonicalization":"relative/path",
                "value":"a".repeat(64)
            }})),
            &valid_snapshot,
        );
        assert_eq!(bad_condition.status, PythonConditionStatus::Unsupported);
        assert!(bad_condition.findings.iter().any(|finding| {
            finding.field == PythonConditionField::ProjectConfig
                && finding.kind == PythonConditionFindingKind::Unsupported
        }));
    }
}
