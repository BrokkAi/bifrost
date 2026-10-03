//! Exact Python runtime declaration identities at the interchange boundary.
//!
//! A portable key is retained with the native declaration. Its descriptor
//! roles, artifact selector, and digest are evidence; display names and native
//! declaration handles are not substitutes for that evidence.

use super::model::*;
use crate::analyzer::semantic_model::TypeRef;

/// A member-local failure while authoring a new, complete Python callable shape.
/// Pack-wide identity, artifact, type, and provenance joins remain the work of
/// native compilation and CSMI export validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsmiShapeAuthoringError {
    UnsupportedMember(&'static str),
    InvalidStatement(&'static str),
    InvalidProvenance(&'static str),
}

impl std::fmt::Display for CsmiShapeAuthoringError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedMember(reason) => {
                write!(formatter, "unsupported Python callable shape: {reason}")
            }
            Self::InvalidStatement(reason) => {
                write!(formatter, "invalid callable-shape statement: {reason}")
            }
            Self::InvalidProvenance(reason) => {
                write!(formatter, "invalid callable-shape provenance: {reason}")
            }
        }
    }
}

impl std::error::Error for CsmiShapeAuthoringError {}

/// Bind an explicit, complete shape claim to this exact native member.
///
/// This does not infer completeness from a signature. The caller supplies a
/// reviewed statement and a producer record. It also does not certify the
/// owner, artifact, referenced types, or record-ID uniqueness across a pack;
/// compile and export the whole pack after attaching the returned evidence.
pub fn author_python_callable_shape_evidence(
    member: &crate::analyzer::semantic_model::MemberFact,
    statement: CsmiCompletenessStatement,
    provenance: CsmiProvenanceRecord,
) -> Result<crate::analyzer::semantic_model::PortableCallableShapeEvidence, CsmiShapeAuthoringError>
{
    use crate::analyzer::semantic_model::{Locator, MemberKind, ParameterPassingMode};
    let Locator::Interchange {
        symbol,
        identity,
        callable_shape_evidence,
        ..
    } = &member.locator
    else {
        return Err(CsmiShapeAuthoringError::UnsupportedMember(
            "portable Python locator required",
        ));
    };
    validate_identity(identity).map_err(|_| {
        CsmiShapeAuthoringError::UnsupportedMember("valid Python portable identity required")
    })?;
    if symbol.is_empty()
        || !matches!(
            member.member_kind,
            MemberKind::Function | MemberKind::Method | MemberKind::Constructor
        )
        || identity.descriptors.last().is_none_or(|descriptor| {
            descriptor.role != CsmiDescriptorRole::Callable
                || descriptor.name.as_deref() != Some(member.name.as_str())
        })
    {
        return Err(CsmiShapeAuthoringError::UnsupportedMember(
            "callable locator and member must agree",
        ));
    }
    let Some(signature) = member.signature.as_ref() else {
        return Err(CsmiShapeAuthoringError::UnsupportedMember(
            "structured signature required",
        ));
    };
    if !signature.type_parameters.is_empty()
        || member
            .receiver
            .as_ref()
            .is_some_and(|receiver| receiver.pointer)
        || member.extension_receiver.is_some()
        || !member.extension_receiver_constraints.is_empty()
    {
        return Err(CsmiShapeAuthoringError::UnsupportedMember(
            "unmapped generic or receiver dimension",
        ));
    }
    if u32::try_from(signature.parameters.len()).is_err()
        || signature.parameters.iter().any(|parameter| {
            !parameter.variadic
                && parameter.passing_mode != ParameterPassingMode::PositionalOnly
                && parameter.name.is_none()
        })
    {
        return Err(CsmiShapeAuthoringError::UnsupportedMember(
            "parameter position or binding cannot be represented",
        ));
    }
    // An absent native result is the exporter's exact zero-result shape.
    // Completeness is the caller's explicit statement, never inferred here.
    if statement.vocabulary.is_some()
        || statement.version.is_some()
        || statement.family != "declaration-aspects"
        || statement.scope != serde_json::json!({"symbol": symbol, "aspect": "callable-shape"})
        || statement.status != CsmiCoverageStatus::Complete
        || !statement.limitations.is_empty()
        || !statement.extensions.is_empty()
    {
        return Err(CsmiShapeAuthoringError::InvalidStatement(
            "expected exact complete core callable-shape scope without limitations",
        ));
    }
    if provenance.id.is_empty()
        || statement.provenance.len() != 1
        || statement.provenance[0] != provenance.id
        || provenance.producer.identifier.is_empty()
        || provenance.producer.version.is_empty()
        || (provenance.generation_method != CsmiGenerationMethod::ManualAuthoring
            && provenance.inputs.is_empty())
        || (provenance.generation_method == CsmiGenerationMethod::Other
            && provenance.diagnostic.is_none())
    {
        return Err(CsmiShapeAuthoringError::InvalidProvenance(
            "one explicit provenance record with required fields is needed",
        ));
    }
    if callable_shape_evidence.as_ref().is_some_and(|old| {
        old.statement.provenance.contains(&provenance.id)
            || old
                .provenance_records
                .iter()
                .any(|record| record.id == provenance.id)
    }) {
        return Err(CsmiShapeAuthoringError::InvalidProvenance(
            "replacement claim requires a new record ID",
        ));
    }
    let mut evidence = crate::analyzer::semantic_model::PortableCallableShapeEvidence {
        native_sha256: native_callable_shape_digest(member),
        statement,
        provenance_records: vec![provenance],
        default_provenance: None,
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = callable_shape_evidence_digest(&evidence);
    Ok(evidence)
}

pub(crate) fn validate_identity(identity: &CsmiPortableSymbolIdentity) -> Result<(), String> {
    if identity.scheme != CSMI_PYTHON_PROFILE_ID
        || identity.scheme_version != CSMI_PYTHON_PROFILE_VERSION
    {
        return Err(format!(
            "unsupported portable identity scheme {}/{}",
            identity.scheme, identity.scheme_version
        ));
    }
    let [artifact] = identity.artifact_selectors.as_slice() else {
        return Err("Python runtime identity requires one exact artifact scope; multi-artifact correspondence remains unsupported".to_owned());
    };
    validate_python_artifact(artifact)?;
    let mut in_namespace = true;
    for (index, descriptor) in identity.descriptors.iter().enumerate() {
        let Some(name) = descriptor.name.as_deref() else {
            return Err("Python declaration identity has an unnamed descriptor".to_owned());
        };
        if name.is_empty() || name.contains('.') || descriptor.disambiguator.is_some() {
            return Err(format!("unsupported Python descriptor {descriptor:?}"));
        }
        match descriptor.role {
            CsmiDescriptorRole::Namespace if in_namespace => {}
            CsmiDescriptorRole::Type if index > 0 => in_namespace = false,
            CsmiDescriptorRole::Callable
                if index > 0 && index + 1 == identity.descriptors.len() =>
            {
                in_namespace = false;
            }
            _ => {
                return Err(format!(
                    "unsupported Python descriptor ownership {descriptor:?}"
                ));
            }
        }
    }
    if identity
        .descriptors
        .first()
        .is_none_or(|descriptor| descriptor.role != CsmiDescriptorRole::Namespace)
    {
        return Err("Python identity must begin with its absolute import module".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_runtime_artifact(artifact: &CsmiArtifactSelector) -> Result<(), String> {
    let mut diagnostics = Vec::new();
    if !super::validate::validate_selector(artifact, "artifact", &mut diagnostics) {
        return Err(format!("invalid Python artifact selector: {diagnostics:?}"));
    }
    let url = url::Url::parse(&artifact.purl).map_err(|error| error.to_string())?;
    let Some(version) = url.path().strip_prefix("generic/python-runtime@") else {
        return Err("Python distributions and declaration artifacts require import/correspondence evidence; only exact runtime artifacts are supported here".to_owned());
    };
    semver::Version::parse(version)
        .map_err(|error| format!("unsupported Python runtime version: {error}"))?;
    let qualifiers = url.query_pairs().collect::<Vec<_>>();
    let [
        (component_key, component),
        (implementation_key, implementation),
    ] = qualifiers.as_slice()
    else {
        return Err(
            "Python runtime PURL requires exactly component and implementation qualifiers"
                .to_owned(),
        );
    };
    if url.scheme() != "pkg"
        || url.fragment().is_some()
        || artifact.version_range.is_some()
        || component_key != "component"
        || !matches!(component.as_ref(), "stdlib" | "interpreter")
        || implementation_key != "implementation"
        || implementation.is_empty()
        || !implementation
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || artifact.purl
            != format!(
                "pkg:generic/python-runtime@{version}?component={component}&implementation={implementation}"
            )
    {
        return Err("unsupported or noncanonical Python runtime artifact selector".to_owned());
    }
    let [digest] = artifact.digests.as_slice() else {
        return Err("Python runtime import requires one exact content digest".to_owned());
    };
    if digest.algorithm != CsmiDigestAlgorithm::Sha256
        || digest.coverage != "artifact"
        || digest.canonicalization.is_some()
    {
        return Err("Python runtime import requires an artifact-byte SHA-256 digest".to_owned());
    }
    Ok(())
}

/// A PyPI distribution is an artifact coordinate, never an import-root key.
/// The separate distribution-imports fact below supplies that binding.
pub(crate) fn validate_python_artifact(artifact: &CsmiArtifactSelector) -> Result<(), String> {
    if artifact.purl.starts_with("pkg:generic/python-runtime@") {
        return validate_runtime_artifact(artifact);
    }
    let mut diagnostics = Vec::new();
    if !super::validate::validate_selector(artifact, "artifact", &mut diagnostics) {
        return Err(format!("invalid Python artifact selector: {diagnostics:?}"));
    }
    let Some(coordinate) = artifact.purl.strip_prefix("pkg:pypi/") else {
        return Err("unsupported Python artifact kind".to_owned());
    };
    let Some((name, version)) = coordinate.split_once('@') else {
        return Err("Python distribution requires an exact PyPI version".to_owned());
    };
    if name.is_empty()
        || version.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || name.starts_with('-')
        || name.ends_with('-')
        || name.contains("--")
        || !version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'!')
        })
        || artifact.version_range.is_some()
    {
        return Err("unsupported or noncanonical exact PyPI selector".to_owned());
    }
    let [digest] = artifact.digests.as_slice() else {
        return Err("Python distribution requires one exact content digest".to_owned());
    };
    if digest.algorithm != CsmiDigestAlgorithm::Sha256
        || digest.coverage != "artifact"
        || digest.canonicalization.is_some()
    {
        return Err("Python distribution requires an artifact-byte SHA-256 digest".to_owned());
    }
    Ok(())
}

pub(crate) fn identity_from_symbol(
    symbol: &CsmiSymbolDefinition,
    model_artifacts: &[CsmiArtifactSelector],
) -> Result<CsmiPortableSymbolIdentity, String> {
    if symbol.stability != CsmiStability::Portable || !symbol.extensions.is_empty() {
        return Err("unsupported Python local identity or identity extension".to_owned());
    }
    let identity = CsmiPortableSymbolIdentity {
        artifact_selectors: symbol
            .artifact_selectors
            .as_deref()
            .unwrap_or(model_artifacts)
            .to_vec(),
        scheme: symbol.scheme.clone(),
        scheme_version: symbol.scheme_version.clone(),
        descriptors: symbol.descriptors.clone(),
    };
    validate_identity(&identity)?;
    Ok(identity)
}

pub(crate) fn native_id(identity: &CsmiPortableSymbolIdentity) -> String {
    format!(
        "csmi.python.{}",
        super::canonical::canonical_digest(identity).expect("portable identity serializes")
    )
}

pub(crate) fn qualified_name(identity: &CsmiPortableSymbolIdentity) -> String {
    identity
        .descriptors
        .iter()
        .map(|descriptor| {
            descriptor
                .name
                .as_deref()
                .expect("validated named descriptor")
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn validate_python_payload(payload: &serde_json::Value) -> Result<(), String> {
    let violations = super::validate::validate_python_profile_payload(payload);
    if !violations.is_empty() {
        return Err(format!(
            "Python profile payload violates its pinned schema: {violations:?}"
        ));
    }
    let mut conditions = Vec::new();
    match payload.get("kind").and_then(serde_json::Value::as_str) {
        Some("distribution-imports") => {
            conditions.extend(payload.get("conditions"));
        }
        Some("import-bindings") => {
            conditions.extend(
                payload
                    .get("bindings")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|binding| binding.get("conditions")),
            );
        }
        Some("declaration-correspondence") => {
            conditions.extend(
                payload
                    .get("mappings")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|mapping| mapping.get("conditions")),
            );
        }
        Some("compatibility") => {}
        _ => unreachable!("the Python profile schema rejected unknown payload kinds above"),
    }
    for condition in conditions {
        let violations = super::validate::validate_python_profile_condition(condition);
        if !violations.is_empty() {
            return Err(format!(
                "Python profile condition violates its pinned schema: {violations:?}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_model(model: &CsmiSemanticModel) -> Result<(), String> {
    let [artifact] = model.artifact_selectors.as_slice() else {
        return Err("Python runtime model requires one exact artifact selector".to_owned());
    };
    validate_python_artifact(artifact)?;
    if !model.extensions.is_empty() || !model.consumer_resolved_dependencies.is_empty() {
        return Err(
            "Python model extensions or external correspondence require additional consumer evidence"
                .to_owned(),
        );
    }
    for constraint in &model.compatibility_constraints {
        if constraint.vocabulary != CSMI_PYTHON_PROFILE_ID
            || constraint.version != CSMI_PYTHON_PROFILE_VERSION
        {
            return Err(
                "Python compatibility constraints require the exact standard profile".to_owned(),
            );
        }
        validate_python_payload(&constraint.value)?;
        if constraint
            .value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            != Some("compatibility")
        {
            return Err(
                "Python compatibility constraint must carry a compatibility payload".into(),
            );
        }
    }
    for fact in model
        .extension_facts
        .iter()
        .filter(|fact| fact.vocabulary == CSMI_PYTHON_PROFILE_ID)
    {
        if fact.version != CSMI_PYTHON_PROFILE_VERSION {
            return Err(
                "Python profile facts require the exact standard profile version".to_owned(),
            );
        }
        validate_python_payload(&fact.payload)?;
    }
    let distribution = artifact.purl.starts_with("pkg:pypi/");
    let mut identity_uses = std::collections::HashSet::new();
    let mut artifact_use = false;
    let mut distribution_use = false;
    let mut binding_uses = std::collections::HashSet::new();
    let mut correspondence_uses = std::collections::HashSet::new();
    for use_ in model
        .vocabulary_uses
        .iter()
        .filter(|use_| use_.identifier == CSMI_PYTHON_PROFILE_ID)
    {
        if use_.version != CSMI_PYTHON_PROFILE_VERSION
            || use_.schema != CSMI_PYTHON_PROFILE_SCHEMA
            || use_.requirement != CsmiVocabularyRequirement::Required
        {
            return Err("Python identity requires the exact required standard profile".to_owned());
        }
        for affected in &use_.affects {
            if let CsmiAffectedUnit::FactFamily(family) = affected {
                if family.kind != CsmiAffectedFactFamilyKind::FactFamily {
                    return Err(format!("unsupported Python profile scope {affected:?}"));
                }
                if family.family == "declaration-correspondence" {
                    let Some(runtime_purl) = family
                        .scope
                        .get("runtimeArtifact")
                        .and_then(serde_json::Value::as_str)
                    else {
                        return Err(format!("invalid Python correspondence scope {affected:?}"));
                    };
                    if family.scope
                        != serde_json::json!({"declarationArtifact":"model","runtimeArtifact":runtime_purl})
                        || !runtime_purl.starts_with("pkg:")
                        || !runtime_purl.contains('@')
                    {
                        return Err(format!(
                            "unsupported Python correspondence scope {affected:?}"
                        ));
                    }
                    correspondence_uses.insert(runtime_purl.to_owned());
                } else if !distribution {
                    return Err(format!("unsupported Python profile scope {affected:?}"));
                } else if family.family == "distribution-imports"
                    && family.scope == serde_json::json!({"artifact":"model"})
                {
                    distribution_use = true;
                } else if family.family == "import-bindings" {
                    let Some(module) = family
                        .scope
                        .get("module")
                        .and_then(serde_json::Value::as_str)
                    else {
                        return Err(format!("unsupported Python binding scope {affected:?}"));
                    };
                    if family.scope != serde_json::json!({"module":module}) {
                        return Err(format!("unsupported Python binding scope {affected:?}"));
                    }
                    binding_uses.insert(module.to_owned());
                } else {
                    return Err(format!("unsupported Python profile scope {affected:?}"));
                }
                continue;
            }
            let CsmiAffectedUnit::CoreSlot(slot) = affected else {
                return Err(format!("unsupported Python profile scope {affected:?}"));
            };
            if slot.slot == "artifact-compatibility"
                && slot.target == serde_json::json!({"semanticModel": "current"})
            {
                artifact_use = true;
            } else if slot.slot == "symbol-identity-scheme"
                && slot.target == serde_json::json!({"model":"self"})
            {
                identity_uses.extend(model.symbols.iter().map(|symbol| symbol.id.as_str()));
            } else if slot.slot == "symbol-identity-scheme" {
                let Some(symbol) = slot
                    .target
                    .get("symbol")
                    .and_then(serde_json::Value::as_str)
                else {
                    return Err(format!("unsupported Python identity scope {affected:?}"));
                };
                if slot.target != serde_json::json!({"symbol": symbol})
                    || !model.symbols.iter().any(|value| value.id == symbol)
                {
                    return Err(format!("unresolved Python identity scope {affected:?}"));
                }
                identity_uses.insert(symbol);
            } else {
                return Err(format!("unsupported Python profile scope {affected:?}"));
            }
        }
    }
    if (!distribution && !artifact_use && correspondence_uses.is_empty())
        || model
            .symbols
            .iter()
            .any(|symbol| !identity_uses.contains(symbol.id.as_str()))
    {
        return Err("Python runtime identity requires its declared identity scope and cannot discard binding/correspondence facts".to_owned());
    }
    if !model.compatibility_constraints.is_empty() && !artifact_use {
        return Err(
            "Python compatibility constraints require the standard profile's artifact-compatibility scope"
                .to_owned(),
        );
    }
    if distribution {
        if !distribution_use {
            return Err(
                "PyPI distribution requires a declared distribution-imports family".to_owned(),
            );
        }
        let roots = model
            .extension_facts
            .iter()
            .filter(|fact| fact.vocabulary == CSMI_PYTHON_PROFILE_ID)
            .try_fold(Vec::new(), |mut roots, fact| {
                if fact.family == "import-bindings" {
                    let Some(module) = fact.scope.get("module").and_then(serde_json::Value::as_str)
                    else {
                        return Err("invalid Python import-binding scope".to_owned());
                    };
                    if !binding_uses.contains(module)
                        || fact.scope != serde_json::json!({"module":module})
                        || !model.symbols.iter().any(|symbol| {
                            symbol.id == module
                                && symbol.descriptors.last().is_some_and(|descriptor| {
                                    descriptor.role == CsmiDescriptorRole::Namespace
                                })
                        })
                        || fact.payload.get("kind").and_then(serde_json::Value::as_str)
                            != Some("import-bindings")
                    {
                        return Err(format!("unsupported Python import-binding fact {fact:?}"));
                    }
                    let Some(bindings) = fact
                        .payload
                        .get("bindings")
                        .and_then(serde_json::Value::as_array)
                    else {
                        return Err("Python import-binding fact has no bindings".to_owned());
                    };
                    for binding in bindings {
                        let Some(target) =
                            binding.get("target").and_then(serde_json::Value::as_str)
                        else {
                            return Err("Python import binding has no target".to_owned());
                        };
                        if !model.symbols.iter().any(|symbol| symbol.id == target) {
                            return Err(format!("unsupported Python import binding {binding:?}"));
                        }
                    }
                    return Ok(roots);
                }
                if fact.family == "declaration-correspondence" {
                    return Ok(roots);
                }
                if fact.version != CSMI_PYTHON_PROFILE_VERSION
                    || fact.family != "distribution-imports"
                    || fact.scope != serde_json::json!({"artifact":"model"})
                    || fact.payload.get("kind").and_then(serde_json::Value::as_str)
                        != Some("distribution-imports")
                {
                    return Err(format!("unsupported Python distribution fact {fact:?}"));
                }
                let Some(import_roots) = fact
                    .payload
                    .get("importRoots")
                    .and_then(serde_json::Value::as_array)
                else {
                    return Err("Python distribution has no import roots".to_owned());
                };
                for root in import_roots {
                    let Some(parts) = root.as_array() else {
                        return Err("invalid Python import root".to_owned());
                    };
                    let Some(parts) = parts
                        .iter()
                        .map(serde_json::Value::as_str)
                        .collect::<Option<Vec<_>>>()
                    else {
                        return Err("invalid Python import root".to_owned());
                    };
                    if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
                        return Err("invalid Python import root".to_owned());
                    }
                    roots.push(parts.into_iter().map(str::to_owned).collect());
                }
                Ok(roots)
            })?;
        if roots.is_empty() {
            return Err("Python distribution has no resolver-proven import roots".to_owned());
        }
        for symbol in model
            .symbols
            .iter()
            .filter(|symbol| symbol.artifact_selectors.is_none())
        {
            let module = symbol
                .descriptors
                .iter()
                .take_while(|descriptor| descriptor.role == CsmiDescriptorRole::Namespace)
                .map(|descriptor| descriptor.name.as_deref().expect("validated descriptor"))
                .collect::<Vec<_>>();
            if !roots.iter().any(|root: &Vec<String>| {
                module.starts_with(&root.iter().map(String::as_str).collect::<Vec<_>>())
            }) {
                return Err(format!(
                    "Python symbol {} is outside resolver-proven import roots",
                    symbol.id
                ));
            }
        }
        for summary in &model.procedure_summaries {
            let callable = model
                .symbols
                .iter()
                .find(|symbol| symbol.id == summary.callable)
                .ok_or_else(|| format!("unresolved Python summary target {}", summary.callable))?;
            if callable
                .artifact_selectors
                .as_ref()
                .is_some_and(|selectors| {
                    selectors.as_slice() != model.artifact_selectors.as_slice()
                })
            {
                // Its exact runtime artifact activates the summary shard. The
                // declaration artifact's import-root facts cannot prove a
                // binding in that separate runtime distribution.
                continue;
            }
            let module = model
                .symbols
                .iter()
                .filter(|symbol| {
                    symbol
                        .descriptors
                        .iter()
                        .all(|descriptor| descriptor.role == CsmiDescriptorRole::Namespace)
                        && callable.descriptors.starts_with(&symbol.descriptors)
                })
                .max_by_key(|symbol| symbol.descriptors.len())
                .ok_or_else(|| format!("Python callable {} has no declared module", callable.id))?;
            let target = if callable.descriptors.len() == module.descriptors.len() + 1 {
                callable
            } else {
                model
                    .symbols
                    .iter()
                    .find(|symbol| {
                        symbol.descriptors.len() == module.descriptors.len() + 1
                            && callable.descriptors.starts_with(&symbol.descriptors)
                    })
                    .ok_or_else(|| {
                        format!(
                            "Python callable {} has no import-visible owner",
                            callable.id
                        )
                    })?
            };
            let bound = model.extension_facts.iter().any(|fact| {
                fact.vocabulary == CSMI_PYTHON_PROFILE_ID
                    && fact.family == "import-bindings"
                    && fact.scope == serde_json::json!({"module":module.id})
                    && fact
                        .payload
                        .get("bindings")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|bindings| {
                            bindings.iter().any(|binding| {
                                binding.get("target").and_then(serde_json::Value::as_str)
                                    == Some(target.id.as_str())
                                    && binding
                                        .get("bindingKind")
                                        .and_then(serde_json::Value::as_str)
                                        == Some("definition")
                                    && binding.get("name").and_then(serde_json::Value::as_str)
                                        == target
                                            .descriptors
                                            .last()
                                            .and_then(|descriptor| descriptor.name.as_deref())
                            })
                        })
            });
            if !bound {
                return Err(format!(
                    "Python summary {} lacks resolver-proven import binding",
                    callable.id
                ));
            }
        }
        if model.extension_facts.iter().any(|fact| {
            fact.vocabulary == CSMI_PYTHON_PROFILE_ID && fact.family == "import-bindings"
        }) && binding_uses.is_empty()
        {
            return Err("Python import bindings lack a required vocabulary use".to_owned());
        }
        for statement in model
            .completeness_statements
            .iter()
            .filter(|statement| statement.vocabulary.as_deref() == Some(CSMI_PYTHON_PROFILE_ID))
        {
            if statement.version.as_deref() != Some(CSMI_PYTHON_PROFILE_VERSION)
                || !matches!(
                    statement.family.as_str(),
                    "distribution-imports" | "import-bindings" | "declaration-correspondence"
                )
                || (statement.family == "distribution-imports"
                    && statement.scope != serde_json::json!({"artifact":"model"}))
                || (statement.family == "declaration-correspondence"
                    && statement
                        .scope
                        .get("runtimeArtifact")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|purl| !correspondence_uses.contains(purl)))
                || (statement.family == "import-bindings"
                    && statement
                        .scope
                        .get("module")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|module| !binding_uses.contains(module)))
            {
                return Err(format!(
                    "unsupported Python completeness statement {statement:?}"
                ));
            }
        }
    } else if model.extension_facts.iter().any(|fact| {
        fact.vocabulary == CSMI_PYTHON_PROFILE_ID && fact.family != "declaration-correspondence"
    }) || model.completeness_statements.iter().any(|statement| {
        statement.vocabulary.as_deref() == Some(CSMI_PYTHON_PROFILE_ID)
            && statement.family != "declaration-correspondence"
    }) {
        return Err(
            "Python runtime identity cannot discard binding/correspondence facts".to_owned(),
        );
    }
    for symbol in &model.symbols {
        let identity = identity_from_symbol(symbol, &model.artifact_selectors)?;
        if identity.artifact_selectors != model.artifact_selectors
            && (symbol.artifact_selectors.is_none()
                || identity.artifact_selectors.len() != 1
                || !correspondence_uses.contains(&identity.artifact_selectors[0].purl))
        {
            return Err(
                "cross-artifact Python symbols require a declared correspondence scope".to_owned(),
            );
        }
    }
    let mut mapped_declarations = std::collections::HashMap::new();
    let mut mapped_runtime_purls = std::collections::HashSet::new();
    for fact in model.extension_facts.iter().filter(|fact| {
        fact.vocabulary == CSMI_PYTHON_PROFILE_ID && fact.family == "declaration-correspondence"
    }) {
        let Some(runtime_purl) = fact
            .scope
            .get("runtimeArtifact")
            .and_then(serde_json::Value::as_str)
        else {
            return Err("Python correspondence has no runtime artifact scope".to_owned());
        };
        if fact.version != CSMI_PYTHON_PROFILE_VERSION
            || fact.scope
                != serde_json::json!({"declarationArtifact":"model","runtimeArtifact":runtime_purl})
            || !correspondence_uses.contains(runtime_purl)
            || fact.payload.get("kind").and_then(serde_json::Value::as_str)
                != Some("declaration-correspondence")
        {
            return Err(format!("unsupported Python correspondence fact {fact:?}"));
        }
        let Some(mappings) = fact
            .payload
            .get("mappings")
            .and_then(serde_json::Value::as_array)
        else {
            return Err("Python correspondence has no mappings".to_owned());
        };
        for mapping in mappings {
            let Some(declaration_id) = mapping
                .get("declaration")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(format!(
                    "Python correspondence has no declaration ID: {mapping:?}"
                ));
            };
            let Some(runtime_id) = mapping.get("runtime").and_then(serde_json::Value::as_str)
            else {
                return Err(format!(
                    "Python correspondence has no runtime ID: {mapping:?}"
                ));
            };
            let declaration = model
                .symbols
                .iter()
                .find(|symbol| symbol.id == declaration_id)
                .ok_or_else(|| {
                    format!("unresolved Python correspondence declaration {declaration_id}")
                })?;
            let runtime = model
                .symbols
                .iter()
                .find(|symbol| symbol.id == runtime_id)
                .ok_or_else(|| format!("unresolved Python correspondence runtime {runtime_id}"))?;
            if identity_from_symbol(declaration, &model.artifact_selectors)?.artifact_selectors
                != model.artifact_selectors
                || runtime.artifact_selectors.as_ref().is_none_or(|selectors| {
                    selectors.len() != 1 || selectors[0].purl != runtime_purl
                })
                || model.artifact_selectors
                    == runtime.artifact_selectors.clone().unwrap_or_default()
            {
                return Err(format!(
                    "Python correspondence requires distinct explicit artifact-scoped symbols: {mapping:?}"
                ));
            }
            if let Some(previous) =
                mapped_declarations.insert(declaration_id, (runtime_id, mapping))
            {
                if previous != (runtime_id, mapping) {
                    return Err(format!(
                        "conflicting Python correspondence for {declaration_id}"
                    ));
                }
                return Err(format!(
                    "duplicate Python correspondence for {declaration_id}"
                ));
            }
            mapped_runtime_purls.insert(runtime_purl);
        }
    }
    if correspondence_uses
        .iter()
        .any(|purl| !mapped_runtime_purls.contains(purl.as_str()))
    {
        return Err("Python correspondence vocabulary use has no mapping fact".to_owned());
    }
    for symbol in &model.symbols {
        let identity = identity_from_symbol(symbol, &model.artifact_selectors)?;
        let required_runtime_owner = mapped_declarations.values().any(|(runtime_id, _)| {
            model
                .symbols
                .iter()
                .find(|candidate| candidate.id == *runtime_id)
                .and_then(|candidate| {
                    identity_from_symbol(candidate, &model.artifact_selectors).ok()
                })
                .is_some_and(|runtime| {
                    runtime.artifact_selectors == identity.artifact_selectors
                        && runtime.descriptors.starts_with(&identity.descriptors)
                })
        });
        if identity.artifact_selectors != model.artifact_selectors && !required_runtime_owner {
            return Err(format!(
                "unmapped cross-artifact Python symbol {}",
                symbol.id
            ));
        }
    }
    if !model.relationships.is_empty() {
        return Err(
            "Python declaration relationships require supported profile evidence".to_owned(),
        );
    }
    for declaration in &model.declarations {
        let symbol = model
            .symbols
            .iter()
            .find(|symbol| symbol.id == declaration.symbol)
            .ok_or_else(|| format!("unresolved Python declaration {}", declaration.symbol))?;
        let role = symbol
            .descriptors
            .last()
            .expect("validated nonempty identity")
            .role;
        if !matches!(
            (declaration.category, role),
            (
                CsmiDeclarationCategory::Namespace,
                CsmiDescriptorRole::Namespace
            ) | (CsmiDeclarationCategory::Type, CsmiDescriptorRole::Type)
                | (
                    CsmiDeclarationCategory::Callable,
                    CsmiDescriptorRole::Callable
                )
        ) || !declaration.generic_parameters.is_empty()
            || !declaration.extensions.is_empty()
        {
            return Err(format!(
                "unsupported Python declaration shape {}",
                declaration.symbol
            ));
        }
        if let Some(owner) = &declaration.owner {
            let owner = model
                .symbols
                .iter()
                .find(|symbol| &symbol.id == owner)
                .ok_or_else(|| format!("unresolved Python owner {owner}"))?;
            if owner.descriptors.as_slice() != &symbol.descriptors[..symbol.descriptors.len() - 1] {
                return Err(format!(
                    "Python declaration owner disagrees with identity {}",
                    declaration.symbol
                ));
            }
        }
    }
    Ok(())
}

/// Check the native declarations against retained keys, including their exact
/// activation scope. Missing cross-shard owners are checked by the ordinary
/// reference validator when the complete pack is available.
pub(crate) fn validate_native_identities(
    pack: &crate::analyzer::semantic_model::AuthoredSemanticModelPack,
) -> Vec<crate::analyzer::semantic_model::Diagnostic> {
    use crate::analyzer::semantic_model::{
        AuthoredPayload, Diagnostic, Locator, MemberKind, TypeKind,
    };
    let types = pack
        .shards
        .iter()
        .filter_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { types, .. } => Some(types),
            _ => None,
        })
        .flatten()
        .map(|fact| (fact.id.as_str(), fact))
        .collect::<std::collections::HashMap<_, _>>();
    let mut diagnostics = Vec::new();
    for shard in &pack.shards {
        let AuthoredPayload::DeclarationFacts {
            types: shard_types,
            members,
            ..
        } = &shard.payload
        else {
            continue;
        };
        for (id, locator) in shard_types
            .iter()
            .map(|fact| (&fact.id, &fact.locator))
            .chain(members.iter().map(|fact| (&fact.id, &fact.locator)))
        {
            let Locator::Interchange { identity, .. } = locator else {
                continue;
            };
            let [artifact] = identity.artifact_selectors.as_slice() else {
                continue;
            };
            let [digest] = artifact.digests.as_slice() else {
                continue;
            };
            if pack.language != "python"
                || pack.ecosystem != "python"
                || shard.activation.is_empty()
                || shard.activation.iter().any(|selector| {
                    selector.package.as_ref().is_none_or(|package| {
                        package.name != artifact.purl || package.version.is_some()
                    }) || selector.artifact_sha256.as_deref() != Some(digest.value.as_str())
                })
            {
                diagnostics.push(Diagnostic::error(
                    "locator.interchange_artifact",
                    format!("shards.{}.{}", shard.id, id),
                    "portable Python declaration requires its exact runtime artifact activation",
                ));
            }
        }
        for fact in shard_types {
            let Locator::Interchange {
                identity,
                callable_shape_evidence,
                ..
            } = &fact.locator
            else {
                continue;
            };
            if callable_shape_evidence.is_some() {
                diagnostics.push(Diagnostic::error(
                    "locator.interchange_callable_shape",
                    format!("types.{}", fact.id),
                    "a type cannot carry callable-shape evidence",
                ));
            }
            // Malformed keys already have locator diagnostics. Do not derive a
            // qualified name until every component has been validated.
            if validate_identity(identity).is_err() {
                continue;
            }
            let role = identity
                .descriptors
                .last()
                .expect("validated descriptor path")
                .role;
            if fact.name != qualified_name(identity)
                || !matches!(
                    (fact.type_kind, role),
                    (TypeKind::Module, CsmiDescriptorRole::Namespace)
                        | (TypeKind::Class, CsmiDescriptorRole::Type)
                )
            {
                diagnostics.push(Diagnostic::error(
                    "locator.interchange_declaration",
                    format!("types.{}", fact.id),
                    "native type name or kind disagrees with its portable identity",
                ));
            }
        }
        for fact in members {
            let Locator::Interchange {
                identity,
                symbol,
                callable_shape_evidence,
                ..
            } = &fact.locator
            else {
                continue;
            };
            if let Some(evidence) = callable_shape_evidence {
                let statement = &evidence.statement;
                if statement.vocabulary.is_some()
                    || statement.version.is_some()
                    || statement.family != "declaration-aspects"
                    || statement.scope
                        != serde_json::json!({"symbol":symbol,"aspect":"callable-shape"})
                    || evidence.native_sha256 != native_callable_shape_digest(fact)
                    || evidence.evidence_sha256 != callable_shape_evidence_digest(evidence)
                    || {
                        let mut ids = std::collections::HashSet::new();
                        evidence
                            .provenance_records
                            .iter()
                            .any(|record| !ids.insert(record.id.as_str()))
                    }
                    || evidence.provenance_records.iter().any(|record| {
                        !statement.provenance.contains(&record.id)
                            && evidence.default_provenance.as_ref() != Some(&record.id)
                    })
                    || statement.provenance.iter().any(|id| {
                        !evidence
                            .provenance_records
                            .iter()
                            .any(|record| &record.id == id)
                    })
                    || evidence.default_provenance.as_ref().is_some_and(|id| {
                        !evidence
                            .provenance_records
                            .iter()
                            .any(|record| &record.id == id)
                    })
                {
                    diagnostics.push(Diagnostic::error(
                        "locator.interchange_callable_shape",
                        format!("members.{}", fact.id),
                        "callable-shape evidence disagrees with its exact native member",
                    ));
                }
            }
            let Some(descriptor) = identity.descriptors.last() else {
                continue;
            };
            if !matches!(
                fact.member_kind,
                MemberKind::Function | MemberKind::Method | MemberKind::Constructor
            ) || descriptor.role != CsmiDescriptorRole::Callable
                || descriptor.name.as_deref() != Some(fact.name.as_str())
            {
                diagnostics.push(Diagnostic::error(
                    "locator.interchange_declaration",
                    format!("members.{}", fact.id),
                    "native callable name or kind disagrees with its portable identity",
                ));
            }
            if let Some(owner) = types.get(fact.owner.as_str()) {
                let agrees = matches!(&owner.locator, Locator::Interchange { identity: owner_identity, .. }
                    if owner_identity.artifact_selectors == identity.artifact_selectors
                    && owner_identity.scheme == identity.scheme && owner_identity.scheme_version == identity.scheme_version
                    && owner_identity.descriptors.as_slice() == &identity.descriptors[..identity.descriptors.len() - 1]);
                if !agrees {
                    diagnostics.push(Diagnostic::error(
                        "locator.interchange_owner",
                        format!("members.{}", fact.id),
                        "native callable owner disagrees with its portable identity",
                    ));
                }
            }
        }
    }
    diagnostics
}

pub(crate) fn native_callable_shape_digest(
    member: &crate::analyzer::semantic_model::MemberFact,
) -> String {
    let mut bare = member.clone();
    if let crate::analyzer::semantic_model::Locator::Interchange {
        callable_shape_evidence,
        ..
    } = &mut bare.locator
    {
        *callable_shape_evidence = None;
    }
    super::canonical::canonical_digest(&bare).expect("native member serializes")
}

pub(crate) fn callable_shape_evidence_digest(
    evidence: &crate::analyzer::semantic_model::PortableCallableShapeEvidence,
) -> String {
    super::canonical::canonical_digest(&(
        &evidence.native_sha256,
        &evidence.statement,
        &evidence.provenance_records,
        &evidence.default_provenance,
    ))
    .expect("callable-shape evidence serializes")
}

pub(crate) fn native_profile_digest(
    pack: &crate::analyzer::semantic_model::AuthoredSemanticModelPack,
) -> String {
    use crate::analyzer::semantic_model::{AuthoredPayload, Locator};
    let mut bare = pack.clone();
    for shard in &mut bare.shards {
        if let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut shard.payload {
            for locator in types
                .iter_mut()
                .map(|fact| &mut fact.locator)
                .chain(members.iter_mut().map(|fact| &mut fact.locator))
            {
                if let Locator::Interchange {
                    profile_evidence, ..
                } = locator
                {
                    *profile_evidence = None;
                }
            }
        }
    }
    if let Some(evidence) = bare.python_correspondence.as_mut() {
        evidence.native_sha256.clear();
    }
    let normalized = crate::analyzer::semantic_model::compiler::normalize(bare);
    super::canonical::sha256_hex(
        &serde_json::to_vec(&normalized).expect("native semantic pack serializes"),
    )
}

/// Bind the typed correspondence and all retained producer evidence to the
/// normalized native pack without hashing the digest field recursively.
pub(crate) fn native_correspondence_digest(
    pack: &crate::analyzer::semantic_model::AuthoredSemanticModelPack,
) -> String {
    let mut bare = pack.clone();
    let evidence = bare
        .python_correspondence
        .as_mut()
        .expect("correspondence digest requires its carrier");
    evidence.native_sha256.clear();
    let normalized = crate::analyzer::semantic_model::compiler::normalize(bare);
    super::canonical::sha256_hex(
        &serde_json::to_vec(&normalized).expect("native correspondence pack serializes"),
    )
}

fn profile_carriers(
    pack: &crate::analyzer::semantic_model::AuthoredSemanticModelPack,
) -> Vec<&crate::analyzer::semantic_model::PortableProfileEvidence> {
    use crate::analyzer::semantic_model::{AuthoredPayload, Locator};
    let mut carriers = Vec::new();
    for shard in &pack.shards {
        if let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload {
            for locator in types
                .iter()
                .map(|fact| &fact.locator)
                .chain(members.iter().map(|fact| &fact.locator))
            {
                if let Locator::Interchange {
                    profile_evidence: Some(evidence),
                    ..
                } = locator
                {
                    carriers.push(evidence.as_ref());
                }
            }
        }
    }
    carriers
}

fn has_python_profile_use(
    evidence: &crate::analyzer::semantic_model::PortableProfileEvidence,
    affects: impl Fn(&CsmiAffectedUnit) -> bool,
) -> bool {
    evidence.vocabulary_uses.iter().any(|use_| {
        use_.identifier == CSMI_PYTHON_PROFILE_ID
            && use_.version == CSMI_PYTHON_PROFILE_VERSION
            && use_.schema == CSMI_PYTHON_PROFILE_SCHEMA
            && use_.requirement == CsmiVocabularyRequirement::Required
            && use_.affects.iter().any(&affects)
    })
}

fn validate_portable_profile_evidence(
    evidence: &crate::analyzer::semantic_model::PortableProfileEvidence,
) -> Vec<crate::analyzer::semantic_model::Diagnostic> {
    use crate::analyzer::semantic_model::Diagnostic;
    fn report(diagnostics: &mut Vec<Diagnostic>, code: &'static str, message: impl Into<String>) {
        diagnostics.push(Diagnostic::error(code, "$.shards", message));
    }
    let mut diagnostics = Vec::new();
    for use_ in &evidence.vocabulary_uses {
        if use_.identifier != CSMI_PYTHON_PROFILE_ID
            || use_.version != CSMI_PYTHON_PROFILE_VERSION
            || use_.schema != CSMI_PYTHON_PROFILE_SCHEMA
            || use_.requirement != CsmiVocabularyRequirement::Required
        {
            report(
                &mut diagnostics,
                "python.profile_vocabulary_use",
                "retained Python profile requires the exact required standard vocabulary",
            );
        }
    }
    if !evidence.compatibility_constraints.is_empty()
        && !has_python_profile_use(evidence, |affected| {
            matches!(affected, CsmiAffectedUnit::CoreSlot(slot)
                if slot.slot == "artifact-compatibility"
                    && slot.target == serde_json::json!({"semanticModel":"current"}))
        })
    {
        report(
            &mut diagnostics,
            "python.profile_compatibility_use",
            "Python compatibility constraints require the exact required artifact-compatibility scope",
        );
    }
    for constraint in &evidence.compatibility_constraints {
        if constraint.vocabulary != CSMI_PYTHON_PROFILE_ID
            || constraint.version != CSMI_PYTHON_PROFILE_VERSION
        {
            report(
                &mut diagnostics,
                "python.profile_compatibility_vocabulary",
                "retained compatibility constraints require the exact standard Python profile",
            );
            continue;
        }
        if constraint
            .value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            != Some("compatibility")
        {
            report(
                &mut diagnostics,
                "python.profile_compatibility_kind",
                "retained compatibility constraint must carry a compatibility payload",
            );
        }
        if let Err(message) = validate_python_payload(&constraint.value) {
            report(
                &mut diagnostics,
                "python.profile_compatibility_schema",
                message,
            );
        }
    }
    for fact in &evidence.extension_facts {
        if fact.vocabulary != CSMI_PYTHON_PROFILE_ID || fact.version != CSMI_PYTHON_PROFILE_VERSION
        {
            report(
                &mut diagnostics,
                "python.profile_fact_vocabulary",
                "retained Python facts require the exact standard vocabulary and version",
            );
            continue;
        }
        if !has_python_profile_use(evidence, |affected| {
            matches!(affected, CsmiAffectedUnit::FactFamily(family)
                if family.family == fact.family && family.scope == fact.scope)
        }) {
            report(
                &mut diagnostics,
                "python.profile_fact_use",
                "retained Python facts require a matching required vocabulary scope",
            );
        }
        if let Err(message) = validate_python_payload(&fact.payload) {
            report(&mut diagnostics, "python.profile_fact_schema", message);
            continue;
        }
        if fact.payload.get("kind").and_then(serde_json::Value::as_str)
            != Some(fact.family.as_str())
        {
            report(
                &mut diagnostics,
                "python.profile_fact_family",
                "retained Python fact family disagrees with its payload kind",
            );
        }
    }
    diagnostics
}

pub(crate) fn validate_profile_evidence(
    pack: &crate::analyzer::semantic_model::AuthoredSemanticModelPack,
) -> Vec<crate::analyzer::semantic_model::Diagnostic> {
    use crate::analyzer::semantic_model::{AuthoredPayload, Diagnostic, Locator};
    let carriers = profile_carriers(pack);
    if let Some(correspondence) = pack.python_correspondence.as_ref() {
        let mut diagnostics = validate_correspondence_evidence(pack);
        if carriers.len() > 1 {
            diagnostics.push(Diagnostic::error(
                "python.correspondence_duplicate_carrier",
                "$.shards",
                "cross-artifact profile evidence must have at most one declaration carrier",
            ));
        } else if let Some(evidence) = carriers.first() {
            if pack.language != "python"
                || pack.ecosystem != "python"
                || evidence.native_sha256 != native_profile_digest(pack)
            {
                diagnostics.push(Diagnostic::error(
                    "python.profile_evidence_mismatch",
                    "$.shards",
                    "retained Python profile evidence no longer matches the native pack",
                ));
            }
            if evidence.vocabulary_uses != correspondence.vocabulary_uses
                || evidence.extension_facts != correspondence.extension_facts
                || evidence.completeness_statements != correspondence.completeness_statements
                || evidence.provenance_records != correspondence.provenance_records
                || evidence.default_provenance != correspondence.default_provenance
            {
                diagnostics.push(Diagnostic::error(
                    "python.correspondence_carrier_mismatch",
                    "$.shards",
                    "declaration and pack-level Python profile evidence disagree",
                ));
            }
            diagnostics.extend(validate_portable_profile_evidence(evidence));
        }
        return diagnostics;
    }
    let mut distribution = false;
    for shard in &pack.shards {
        if let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload {
            for locator in types
                .iter()
                .map(|fact| &fact.locator)
                .chain(members.iter().map(|fact| &fact.locator))
            {
                if let Locator::Interchange { identity, .. } = locator {
                    distribution |= identity
                        .artifact_selectors
                        .iter()
                        .any(|artifact| artifact.purl.starts_with("pkg:pypi/"));
                }
            }
        }
    }
    if (distribution && carriers.len() != 1) || carriers.len() > 1 {
        return vec![Diagnostic::error(
            "python.profile_evidence_count",
            "$.shards",
            "an exact Python distribution pack requires exactly one profile evidence carrier",
        )];
    }
    let Some(evidence) = carriers.first() else {
        return Vec::new();
    };
    let mut diagnostics = validate_portable_profile_evidence(evidence);
    if pack.language != "python"
        || pack.ecosystem != "python"
        || evidence.native_sha256 != native_profile_digest(pack)
    {
        diagnostics.push(Diagnostic::error(
            "python.profile_evidence_mismatch",
            "$.shards",
            "retained Python profile evidence no longer matches the native pack",
        ));
    }
    diagnostics
}

fn validate_correspondence_evidence(
    pack: &crate::analyzer::semantic_model::AuthoredSemanticModelPack,
) -> Vec<crate::analyzer::semantic_model::Diagnostic> {
    use crate::analyzer::semantic_model::{
        AuthoredPayload, Diagnostic, PythonCorrespondenceMapping,
    };
    let evidence = pack
        .python_correspondence
        .as_ref()
        .expect("correspondence validation requires its carrier");
    fn report(diagnostics: &mut Vec<Diagnostic>, code: &'static str, message: impl Into<String>) {
        diagnostics.push(Diagnostic::error(code, "$.python_correspondence", message));
    }
    let mut diagnostics = Vec::new();
    if pack.language != "python" || pack.ecosystem != "python" {
        report(
            &mut diagnostics,
            "python.correspondence_language",
            "Python correspondence requires a Python pack",
        );
    }
    if evidence.native_sha256 != native_correspondence_digest(pack) {
        report(
            &mut diagnostics,
            "python.correspondence_digest",
            "correspondence or native pack differs from the retained full-pack digest",
        );
    }
    if validate_python_artifact(&evidence.declaration_artifact).is_err() {
        report(
            &mut diagnostics,
            "python.correspondence_artifact",
            "declaration artifact is not an exact supported Python selector",
        );
    }
    let mut symbols = std::collections::HashMap::new();
    for symbol in &evidence.symbols {
        if symbols
            .insert(symbol.local_id.as_str(), &symbol.identity)
            .is_some()
            || validate_identity(&symbol.identity).is_err()
        {
            report(
                &mut diagnostics,
                "python.correspondence_symbol",
                "correspondence symbol has a duplicate local ID or unsupported identity",
            );
        }
    }
    let mut native_mappings = std::collections::HashSet::new();
    for mapping in &evidence.mappings {
        let Some(declaration) = symbols.get(mapping.declaration.as_str()) else {
            report(
                &mut diagnostics,
                "python.correspondence_declaration",
                "correspondence declaration ID is not a retained symbol",
            );
            continue;
        };
        let Some(runtime) = symbols.get(mapping.runtime.as_str()) else {
            report(
                &mut diagnostics,
                "python.correspondence_runtime",
                "correspondence runtime ID is not a retained symbol",
            );
            continue;
        };
        if declaration.artifact_selectors.as_slice()
            != std::slice::from_ref(&evidence.declaration_artifact)
            || runtime.artifact_selectors == declaration.artifact_selectors
        {
            report(
                &mut diagnostics,
                "python.correspondence_scope",
                "correspondence endpoints must have distinct exact declaration and runtime artifact scopes",
            );
        }
        let key = serde_json::to_string(mapping).expect("typed mapping serializes");
        if !native_mappings.insert(key) {
            report(
                &mut diagnostics,
                "python.correspondence_duplicate_mapping",
                "duplicate typed correspondence mapping",
            );
        }
    }
    if evidence.mappings.is_empty() || evidence.symbols.is_empty() {
        report(
            &mut diagnostics,
            "python.correspondence_empty",
            "correspondence requires retained symbols and mappings",
        );
    }
    let mut source_mappings = std::collections::HashSet::new();
    for fact in evidence.extension_facts.iter().filter(|fact| {
        fact.vocabulary == CSMI_PYTHON_PROFILE_ID && fact.family == "declaration-correspondence"
    }) {
        for violation in super::validate::validate_python_profile_payload(&fact.payload) {
            let message =
                format!("retained correspondence payload violates the pinned schema: {violation}");
            report(
                &mut diagnostics,
                "python.correspondence_payload_schema",
                message,
            );
        }
        let runtime_purl = fact
            .scope
            .get("runtimeArtifact")
            .and_then(serde_json::Value::as_str);
        if fact.version != CSMI_PYTHON_PROFILE_VERSION
            || runtime_purl.is_none()
            || fact.scope
                != serde_json::json!({"declarationArtifact":"model","runtimeArtifact":runtime_purl})
            || fact.payload.get("kind").and_then(serde_json::Value::as_str)
                != Some("declaration-correspondence")
            || !evidence.vocabulary_uses.iter().any(|use_| {
                use_.identifier == CSMI_PYTHON_PROFILE_ID
                    && use_.version == CSMI_PYTHON_PROFILE_VERSION
                    && use_.schema == CSMI_PYTHON_PROFILE_SCHEMA
                    && use_.requirement == CsmiVocabularyRequirement::Required
                    && use_.affects.iter().any(|affected| match affected {
                        CsmiAffectedUnit::FactFamily(family) => {
                            family.family == "declaration-correspondence"
                                && family.scope == fact.scope
                        }
                        _ => false,
                    })
            })
        {
            report(
                &mut diagnostics,
                "python.correspondence_source_fact",
                "retained correspondence fact lacks its exact required profile use or scope",
            );
        }
        match fact
            .payload
            .get("mappings")
            .and_then(serde_json::Value::as_array)
        {
            Some(mappings) if !mappings.is_empty() => {
                for mapping in mappings {
                    match serde_json::from_value::<PythonCorrespondenceMapping>(mapping.clone()) {
                        Ok(mapping) => {
                            if symbols.get(mapping.runtime.as_str()).is_none_or(|symbol| {
                                symbol.artifact_selectors.len() != 1
                                    || Some(symbol.artifact_selectors[0].purl.as_str())
                                        != runtime_purl
                            }) {
                                report(
                                    &mut diagnostics,
                                    "python.correspondence_runtime_scope",
                                    "retained runtime mapping disagrees with its explicit artifact selector",
                                );
                            }
                            if !source_mappings.insert(
                                serde_json::to_string(&mapping).expect("typed mapping serializes"),
                            ) {
                                report(
                                    &mut diagnostics,
                                    "python.correspondence_duplicate_source",
                                    "duplicate retained correspondence mapping",
                                );
                            }
                        }
                        Err(_) => report(
                            &mut diagnostics,
                            "python.correspondence_source_mapping",
                            "retained correspondence mapping is not a supported typed relation",
                        ),
                    }
                }
            }
            _ => report(
                &mut diagnostics,
                "python.correspondence_source_mapping",
                "retained correspondence fact has no mappings",
            ),
        }
    }
    if native_mappings != source_mappings {
        report(
            &mut diagnostics,
            "python.correspondence_mapping_mismatch",
            "typed correspondence mappings differ from retained producer facts",
        );
    }
    let mut core_scopes = std::collections::HashSet::new();
    for statement in &evidence.core_completeness_statements {
        let key = (statement.family.as_str(), statement.scope.to_string());
        if !core_scopes.insert(key)
            || statement.vocabulary.is_some()
            || statement.version.is_some()
            || (statement.status == CsmiCoverageStatus::Partial && statement.limitations.is_empty())
            || (statement.status == CsmiCoverageStatus::Complete
                && !statement.limitations.is_empty())
        {
            report(
                &mut diagnostics,
                "python.correspondence_core_coverage",
                "retained core completeness has a duplicate, invalid scope, or invalid limitation set",
            );
        }
        if statement.family == "declaration-records"
            && (statement.status == CsmiCoverageStatus::Complete)
                != (pack.completeness == crate::analyzer::semantic_model::Completeness::Complete)
        {
            report(
                &mut diagnostics,
                "python.correspondence_core_coverage_status",
                "original declaration-records coverage disagrees with native pack completeness",
            );
        }
    }
    if !evidence
        .core_completeness_statements
        .iter()
        .any(|statement| statement.family == "declaration-records")
    {
        report(
            &mut diagnostics,
            "python.correspondence_core_coverage_missing",
            "cross-artifact correspondence requires retained declaration-records coverage",
        );
    }
    let mut provenance_ids = std::collections::HashSet::new();
    for record in &evidence.provenance_records {
        if !provenance_ids.insert(record.id.as_str()) {
            report(
                &mut diagnostics,
                "python.correspondence_provenance_duplicate",
                "duplicate retained producer provenance ID",
            );
        }
    }
    if evidence
        .default_provenance
        .as_ref()
        .is_some_and(|id| !provenance_ids.contains(id.as_str()))
        || evidence
            .symbols
            .iter()
            .flat_map(|symbol| &symbol.provenance)
            .chain(
                evidence
                    .extension_facts
                    .iter()
                    .flat_map(|fact| &fact.provenance),
            )
            .chain(
                evidence
                    .completeness_statements
                    .iter()
                    .flat_map(|statement| &statement.provenance),
            )
            .chain(
                evidence
                    .core_completeness_statements
                    .iter()
                    .flat_map(|statement| &statement.provenance),
            )
            .any(|id| !provenance_ids.contains(id.as_str()))
    {
        report(
            &mut diagnostics,
            "python.correspondence_provenance_missing",
            "retained producer provenance reference has no original record",
        );
    }
    for shard in &pack.shards {
        if let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload {
            for locator in types
                .iter()
                .map(|fact| &fact.locator)
                .chain(members.iter().map(|fact| &fact.locator))
            {
                if let crate::analyzer::semantic_model::Locator::Interchange {
                    symbol,
                    identity,
                    ..
                } = locator
                    && symbols.get(symbol.as_str()) != Some(&identity.as_ref())
                {
                    report(
                        &mut diagnostics,
                        "python.correspondence_native_symbol",
                        "native declaration differs from its retained artifact-scoped symbol",
                    );
                }
            }
        }
        if let AuthoredPayload::ProcedureSummaries { summaries } = &shard.payload {
            for summary in summaries {
                let callable = evidence.symbols.iter().find(|symbol| {
                    format!(
                        "csmi-summary.{}",
                        super::canonical::sha256_hex(symbol.local_id.as_bytes())
                    ) == summary.id
                });
                let artifact =
                    callable.and_then(|symbol| symbol.identity.artifact_selectors.first());
                let exact = artifact.is_some_and(|artifact| {
                    artifact.digests.len() == 1
                        && shard.activation.len() == 1
                        && shard.activation[0].package.as_ref().is_some_and(|package| {
                            package.name == artifact.purl && package.version.is_none()
                        })
                        && shard.activation[0].artifact_sha256.as_deref()
                            == Some(artifact.digests[0].value.as_str())
                });
                if !exact {
                    report(
                        &mut diagnostics,
                        "python.correspondence_summary_artifact",
                        "Python procedure summary must activate only for its own exact callable artifact",
                    );
                }
            }
        }
    }
    diagnostics
}

pub(crate) fn narrowing_annotation(
    returns: &TypeRef,
) -> Option<(CsmiConditionalTypeSemantics, &TypeRef)> {
    let TypeRef::Named {
        name,
        arguments,
        nullable: false,
    } = returns
    else {
        return None;
    };
    let semantics = match name.as_str() {
        "typing.TypeIs" | "typing_extensions.TypeIs" => CsmiConditionalTypeSemantics::Biconditional,
        "typing.TypeGuard" | "typing_extensions.TypeGuard" => {
            CsmiConditionalTypeSemantics::PositiveOnly
        }
        _ => return None,
    };
    let [target] = arguments.as_slice() else {
        return None;
    };
    Some((semantics, target))
}

fn export_type_expression(
    root: &TypeRef,
    names: &std::collections::HashMap<String, String>,
    symbols: &std::collections::HashMap<String, String>,
) -> Result<CsmiTypeExpression, super::export::CsmiExportError> {
    use super::export::CsmiExportError;
    enum Work<'a> {
        Visit(&'a TypeRef),
        Finish(String, usize),
    }
    let mut work = vec![Work::Visit(root)];
    let mut values = Vec::new();
    while let Some(next) = work.pop() {
        match next {
            Work::Visit(value) => {
                let (native_id, arguments) = match value {
                    TypeRef::Declared {
                        id,
                        arguments,
                        nullable: false,
                    } => (id, arguments),
                    TypeRef::Named {
                        name,
                        arguments,
                        nullable: false,
                    } => (
                        names
                            .get(name)
                            .ok_or_else(|| CsmiExportError::MissingDeclaration {
                                path: "python.type".to_owned(),
                                target: name.clone(),
                            })?,
                        arguments,
                    ),
                    _ => {
                        return Err(CsmiExportError::Unsupported {
                            path: "python.type".to_owned(),
                            semantic: format!("unrepresentable structured Python type {value:?}"),
                        });
                    }
                };
                let symbol =
                    symbols
                        .get(native_id)
                        .ok_or_else(|| CsmiExportError::MissingDeclaration {
                            path: "python.type".to_owned(),
                            target: native_id.clone(),
                        })?;
                work.push(Work::Finish(symbol.clone(), arguments.len()));
                work.extend(arguments.iter().rev().map(Work::Visit));
            }
            Work::Finish(symbol, count) => {
                assert!(
                    values.len() >= count,
                    "each type argument produces one expression"
                );
                let arguments = values.split_off(values.len() - count);
                values.push(CsmiTypeExpression::Reference(CsmiReferenceType {
                    kind: CsmiReferenceTypeKind::Reference,
                    symbol,
                    arguments,
                }));
            }
        }
    }
    assert_eq!(values.len(), 1, "one root type produces one expression");
    Ok(values.pop().expect("root expression"))
}

pub(super) fn export_document(
    manifest: &crate::analyzer::semantic_model::CompiledPackManifest,
    shards: &[crate::analyzer::semantic_model::CompiledShard],
    artifact: &super::export::CsmiArtifactEvidence,
    options: &super::export::CsmiExportOptions,
) -> Result<(CsmiSemanticDocument, CsmiProvenanceRecord), super::export::CsmiExportError> {
    use super::export::CsmiExportError;
    use crate::analyzer::semantic_model::{
        CompiledPayload, Completeness, ConditionalTypeRefinementFact,
        ConditionalTypeRefinementsPayload, Locator, TypeKind, Visibility,
    };
    use serde_json::json;
    use std::collections::HashMap;
    let unsupported = |semantic: &str| CsmiExportError::Unsupported {
        path: "python".to_owned(),
        semantic: semantic.to_owned(),
    };
    if manifest.cpp_portability.is_some() || !manifest.compatibility.toolchains.is_empty() {
        return Err(unsupported(
            "Python export cannot discard additional portability or toolchain constraints",
        ));
    }
    let selector = CsmiArtifactSelector {
        purl: artifact.purl.clone(),
        version_range: None,
        digests: vec![CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: artifact.coverage.clone(),
            canonicalization: None,
            value: artifact.sha256.clone(),
        }],
    };
    validate_python_artifact(&selector).map_err(CsmiExportError::InvalidEvidence)?;
    let correspondence = manifest.python_correspondence.as_ref();
    if correspondence.is_some_and(|evidence| evidence.declaration_artifact != selector) {
        return Err(unsupported(
            "export artifact disagrees with retained Python declaration artifact",
        ));
    }
    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut summary_shards = Vec::new();
    for shard in shards {
        if shard.runtime_values().is_some()
            || shard.collection_flows().is_some()
            || shard.deferred_yields().is_some()
        {
            return Err(unsupported(
                "additional Python runtime profiles require their own exact export mapping",
            ));
        }
        if shard.activation().iter().any(|activation| {
            let supported_artifact = std::iter::once(&selector)
                .chain(correspondence.into_iter().flat_map(|evidence| {
                    evidence
                        .symbols
                        .iter()
                        .flat_map(|symbol| &symbol.identity.artifact_selectors)
                }))
                .any(|candidate| {
                    candidate.digests.len() == 1
                        && activation.package.as_ref().is_some_and(|package| {
                            package.name == candidate.purl && package.version.is_none()
                        })
                        && activation.artifact_sha256.as_deref()
                            == Some(candidate.digests[0].value.as_str())
                });
            !supported_artifact
                || activation.module.is_some()
                || activation.toolchain.is_some()
                || !activation.targets.is_empty()
                || !activation.configurations.is_empty()
        }) {
            return Err(unsupported(
                "Python artifact evidence must match every native activation constraint exactly",
            ));
        }
        match shard.payload() {
            CompiledPayload::DeclarationFacts {
                types: values,
                members: callables,
                relations,
            } if relations.is_empty() => {
                types.extend(values);
                members.extend(callables);
            }
            CompiledPayload::ProcedureSummaries { summaries } => {
                summary_shards.extend(summaries.iter().map(|summary| (shard, summary)));
            }
            _ => {
                return Err(unsupported(
                    "Python export cannot discard unsupported declarations, relations, generators, or procedure summaries",
                ));
            }
        }
    }
    let profile_evidence = types
        .iter()
        .map(|fact| &fact.locator)
        .chain(members.iter().map(|fact| &fact.locator))
        .filter_map(|locator| match locator {
            Locator::Interchange {
                profile_evidence, ..
            } => profile_evidence.as_deref(),
            _ => None,
        })
        .collect::<Vec<_>>();
    let distribution = selector.purl.starts_with("pkg:pypi/");
    let mut retained_correspondence_profile =
        correspondence.map(
            |retained| crate::analyzer::semantic_model::PortableProfileEvidence {
                native_sha256: retained.native_sha256.clone(),
                vocabulary_uses: retained.vocabulary_uses.clone(),
                compatibility_constraints: Vec::new(),
                extension_facts: retained.extension_facts.clone(),
                completeness_statements: retained.completeness_statements.clone(),
                provenance_records: retained.provenance_records.clone(),
                default_provenance: retained.default_provenance.clone(),
            },
        );
    if let Some(retained) = retained_correspondence_profile.as_mut() {
        if profile_evidence.len() > 1 {
            return Err(unsupported(
                "cross-artifact Python profile has multiple declaration evidence carriers",
            ));
        }
        if let Some(carrier) = profile_evidence.first() {
            let relation = correspondence.expect("retained profile came from correspondence");
            if carrier.vocabulary_uses != relation.vocabulary_uses
                || carrier.extension_facts != relation.extension_facts
                || carrier.completeness_statements != relation.completeness_statements
                || carrier.provenance_records != relation.provenance_records
                || carrier.default_provenance != relation.default_provenance
            {
                return Err(unsupported(
                    "cross-artifact Python declaration and pack-level profile evidence disagree",
                ));
            }
            retained.compatibility_constraints = carrier.compatibility_constraints.clone();
        }
    }
    let evidence = if let Some(retained) = retained_correspondence_profile.as_ref() {
        Some(retained)
    } else {
        match (distribution, profile_evidence.as_slice()) {
            (true, [evidence]) => Some(*evidence),
            (false, []) => None,
            (false, [evidence]) if evidence.extension_facts.is_empty() => Some(*evidence),
            _ => {
                return Err(unsupported(
                    "Python profile evidence must have one owner for a distribution or compatibility constraints only for a runtime",
                ));
            }
        }
    };
    let mut keys = HashMap::new();
    let mut symbol_ids = HashMap::new();
    let mut identity_symbols = HashMap::new();
    let mut symbols = Vec::new();
    let mut occupied_symbols = std::collections::HashSet::new();
    let mut identity_affects = vec![CsmiAffectedUnit::CoreSlot(CsmiAffectedCoreSlot {
        kind: CsmiAffectedCoreSlotKind::CoreSlot,
        slot: "artifact-compatibility".to_owned(),
        target: json!({"semanticModel":"current"}),
    })];
    for (id, locator) in types
        .iter()
        .map(|fact| (&fact.id, &fact.locator))
        .chain(members.iter().map(|fact| (&fact.id, &fact.locator)))
    {
        let Locator::Interchange {
            symbol, identity, ..
        } = locator
        else {
            return Err(unsupported(
                "Python declaration has no retained portable identity; display names cannot supply one",
            ));
        };
        validate_identity(identity).map_err(CsmiExportError::Identity)?;
        let carried_symbol = correspondence.and_then(|evidence| {
            evidence
                .symbols
                .iter()
                .find(|candidate| candidate.local_id == *symbol)
        });
        if correspondence.is_some_and(|_| {
            carried_symbol.is_none_or(|candidate| candidate.identity != **identity)
        }) || (correspondence.is_none()
            && identity.artifact_selectors.as_slice() != std::slice::from_ref(&selector))
        {
            return Err(unsupported(
                "export artifact disagrees with a retained Python declaration identity",
            ));
        }
        let symbol_id = symbol.clone();
        if !occupied_symbols.insert(symbol_id.clone()) {
            return Err(unsupported(
                "multiple native declarations claim one Python runtime identity",
            ));
        }
        symbol_ids.insert(id.clone(), symbol_id.clone());
        identity_symbols.insert(native_id(identity), symbol_id.clone());
        keys.insert(id.as_str(), identity);
        identity_affects.push(CsmiAffectedUnit::CoreSlot(CsmiAffectedCoreSlot {
            kind: CsmiAffectedCoreSlotKind::CoreSlot,
            slot: "symbol-identity-scheme".to_owned(),
            target: json!({"symbol":symbol_id}),
        }));
        symbols.push(CsmiSymbolDefinition {
            id: symbol_id,
            artifact_selectors: (identity.artifact_selectors.as_slice()
                != std::slice::from_ref(&selector))
            .then(|| identity.artifact_selectors.clone()),
            scheme: identity.scheme.clone(),
            scheme_version: identity.scheme_version.clone(),
            stability: CsmiStability::Portable,
            descriptors: identity.descriptors.clone(),
            display_name: None,
            qualified_display_name: None,
            native_signature: None,
            documentation_name: None,
            abi_name: None,
            origin: None,
            external_identities: Vec::new(),
            provenance: carried_symbol.map_or_else(
                || vec![options.provenance_id.clone()],
                |candidate| candidate.provenance.clone(),
            ),
            extensions: Vec::new(),
        });
    }
    if let Some(retained) = correspondence {
        for candidate in &retained.symbols {
            if !occupied_symbols.insert(candidate.local_id.clone()) {
                continue;
            }
            validate_identity(&candidate.identity).map_err(CsmiExportError::Identity)?;
            symbols.push(CsmiSymbolDefinition {
                id: candidate.local_id.clone(),
                artifact_selectors: (candidate.identity.artifact_selectors.as_slice()
                    != std::slice::from_ref(&selector))
                .then(|| candidate.identity.artifact_selectors.clone()),
                scheme: candidate.identity.scheme.clone(),
                scheme_version: candidate.identity.scheme_version.clone(),
                stability: CsmiStability::Portable,
                descriptors: candidate.identity.descriptors.clone(),
                display_name: None,
                qualified_display_name: None,
                native_signature: None,
                documentation_name: None,
                abi_name: None,
                origin: None,
                external_identities: Vec::new(),
                provenance: candidate.provenance.clone(),
                extensions: Vec::new(),
            });
        }
    }
    let mut names = HashMap::new();
    let mut ambiguous_names = std::collections::HashSet::new();
    let mut declarations = Vec::new();
    for fact in types {
        if !matches!(fact.type_kind, TypeKind::Class | TypeKind::Module)
            || fact.visibility != Visibility::Public
            || fact.is_abstract
            || fact.is_sealed
            || fact.has_explicit_type_terms
            || fact.ambient_use.is_some()
            || !fact.type_parameters.is_empty()
            || !fact.type_parameter_constraints.is_empty()
            || fact.underlying_type.is_some()
            || !fact.hierarchy.is_empty()
            || !fact.aliases.is_empty()
            || !fact.extension_surfaces.is_empty()
            || fact.guard.is_some()
            || !fact.embedded_types.is_empty()
            || fact.value_semantics.is_some()
        {
            return Err(unsupported(
                "Python type carries declaration semantics not represented by its portable identity",
            ));
        }
        if fact.type_kind == TypeKind::Class
            && !ambiguous_names.contains(&fact.name)
            && names.insert(fact.name.clone(), fact.id.clone()).is_some()
        {
            names.remove(&fact.name);
            ambiguous_names.insert(fact.name.clone());
        }
        let mut owner_key = keys[&fact.id.as_str()].clone();
        owner_key.descriptors.pop();
        let owner = (!owner_key.descriptors.is_empty())
            .then(|| native_id(&owner_key))
            .and_then(|key| identity_symbols.get(&key).cloned());
        declarations.push(CsmiDeclaration {
            symbol: symbol_ids[&fact.id].clone(),
            category: if fact.type_kind == TypeKind::Module {
                CsmiDeclarationCategory::Namespace
            } else {
                CsmiDeclarationCategory::Type
            },
            owner,
            generic_parameters: Vec::new(),
            callable: None,
            alias_target: None,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    let native_ids = symbol_ids
        .keys()
        .map(|id| (id.clone(), id.clone()))
        .collect::<HashMap<_, _>>();
    let mut annotation_facts = ConditionalTypeRefinementsPayload {
        refinements: Vec::new(),
    };
    let mut shapes = HashMap::new();
    let mut symbol_shapes = HashMap::new();
    let mut summary_targets = HashMap::new();
    let mut callable_shape_statements = Vec::new();
    let mut callable_shape_provenance = Vec::new();
    let mut callable_shape_defaults = Vec::new();
    for member in members {
        let signature = member
            .signature
            .as_ref()
            .ok_or_else(|| unsupported("Python callable has no structured signature"))?;
        if !signature.type_parameters.is_empty()
            || member.visibility != Visibility::Public
            || member.is_abstract
            || member.is_virtual
            || member.ambient_use.is_some()
            || !member.extension_receiver_constraints.is_empty()
            || member
                .receiver
                .as_ref()
                .is_some_and(|receiver| receiver.pointer)
            || !member.aliases.is_empty()
            || member.guard.is_some()
            || member.extension_receiver.is_some()
            || member.implicit_operation.is_some()
        {
            return Err(unsupported(
                "Python callable carries unsupported declaration semantics",
            ));
        }
        let shape_evidence = match &member.locator {
            Locator::Interchange {
                callable_shape_evidence,
                ..
            } => callable_shape_evidence.as_deref(),
            _ => None,
        };
        let complete = shape_evidence
            .is_some_and(|evidence| evidence.statement.status == CsmiCoverageStatus::Complete);
        if let Some(evidence) = shape_evidence {
            callable_shape_statements.push(evidence.statement.clone());
            callable_shape_provenance.extend(evidence.provenance_records.iter().cloned());
            callable_shape_defaults.push(evidence.default_provenance.clone());
        }
        shapes.insert(member.id.clone(), complete);
        symbol_shapes.insert(symbol_ids[&member.id].clone(), complete);
        let owner = keys
            .get(member.owner.as_str())
            .ok_or_else(|| unsupported("Python callable owner has no portable identity"))?;
        let target = (
            keys[&member.id.as_str()].artifact_selectors[0].purl.clone(),
            keys[&member.id.as_str()].artifact_selectors[0].digests[0]
                .value
                .clone(),
            qualified_name(owner),
            qualified_name(keys[&member.id.as_str()]),
            signature.parameters.len() as u32,
            member.receiver.is_some(),
            signature
                .parameters
                .last()
                .is_some_and(|parameter| parameter.variadic),
        );
        if summary_targets
            .insert(target, symbol_ids[&member.id].clone())
            .is_some()
        {
            return Err(unsupported("ambiguous native Python summary target"));
        }
        let shape = if let Some((semantics, target)) =
            signature.returns.as_ref().and_then(narrowing_annotation)
        {
            let target = export_type_expression(target, &names, &native_ids)?;
            annotation_facts
                .refinements
                .push(ConditionalTypeRefinementFact {
                    payload: CsmiConditionalTypeRefinement {
                        kind: CsmiConditionalTypeRefinementKind::ConditionalTypeRefinement,
                        callable: member.id.clone(),
                        subject: CsmiConditionalTypeSubject::Parameter { position: 0 },
                        outcome: CsmiConditionalTypeOutcome::Supported { semantics, target },
                    },
                    coverage: Some(if complete {
                        CsmiCoverageStatus::Complete
                    } else {
                        CsmiCoverageStatus::Partial
                    }),
                    provenance: vec![options.provenance_id.clone()],
                });
            // The annotation describes a Boolean predicate. Clone only this
            // export-local declaration to serialize that distinct result type.
            let mut predicate = member.clone();
            predicate
                .signature
                .as_mut()
                .expect("signature above")
                .returns = Some(TypeRef::Declared {
                id: names
                    .get("builtins.bool")
                    .ok_or_else(|| {
                        unsupported(
                            "predicate export requires the exact Boolean result declaration",
                        )
                    })?
                    .clone(),
                arguments: Vec::new(),
                nullable: false,
            });
            super::export::callable_shape(&predicate, &|value| {
                export_type_expression(value, &names, &symbol_ids)
            })?
        } else {
            super::export::callable_shape(member, &|value| {
                export_type_expression(value, &names, &symbol_ids)
            })?
        };
        declarations.push(CsmiDeclaration {
            symbol: symbol_ids[&member.id].clone(),
            category: CsmiDeclarationCategory::Callable,
            owner: Some(
                symbol_ids
                    .get(&member.owner)
                    .ok_or_else(|| unsupported("Python callable owner has no portable identity"))?
                    .clone(),
            ),
            generic_parameters: Vec::new(),
            callable: Some(shape),
            alias_target: None,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    let mut facts = Vec::new();
    let mut affects = Vec::new();
    let mut completeness = vec![CsmiCompletenessStatement {
        vocabulary: None,
        version: None,
        family: "declaration-records".to_owned(),
        scope: json!({"scheme":CSMI_PYTHON_PROFILE_ID,"schemeVersion":CSMI_PYTHON_PROFILE_VERSION}),
        status: if manifest.completeness == Completeness::Complete {
            CsmiCoverageStatus::Complete
        } else {
            CsmiCoverageStatus::Partial
        },
        limitations: if manifest.completeness == Completeness::Partial {
            vec![CsmiLimitation {
                kind: "coverage-limited".to_owned(),
                diagnostic: None,
            }]
        } else {
            Vec::new()
        },
        provenance: vec![options.provenance_id.clone()],
        extensions: Vec::new(),
    }];
    let mut procedure_summaries = Vec::new();
    let mut partition_affects = Vec::new();
    let mut partition_shape_callables = Vec::new();
    let mut seen_summaries = std::collections::HashSet::new();
    for (shard, summary) in summary_shards {
        let target = &summary.target;
        let activation = shard
            .activation()
            .first()
            .ok_or_else(|| unsupported("Python summary shard has no exact artifact selector"))?;
        let key = (
            activation
                .package
                .as_ref()
                .ok_or_else(|| unsupported("Python summary shard has no package artifact"))?
                .name
                .clone(),
            activation
                .artifact_sha256
                .clone()
                .ok_or_else(|| unsupported("Python summary shard has no artifact digest"))?,
            target.path.clone(),
            target.symbol.clone(),
            target.parameter_count,
            target.has_receiver,
            target.variadic,
        );
        let callable =
            summary_targets
                .get(&key)
                .ok_or_else(|| CsmiExportError::MissingDeclaration {
                    path: format!("procedureSummaries.{}", summary.id),
                    target: format!("{}#{}", target.path, target.symbol),
                })?;
        if !seen_summaries.insert(callable.clone()) {
            return Err(unsupported(
                "multiple Python summaries target one runtime callable",
            ));
        }
        if summary.locations.iter().any(|location| {
            location.location_kind != crate::analyzer::semantic_model::CompiledSummaryLocationKind::Capture
                || !summary.transfer_partitions.iter().any(|partition| matches!(&partition.source,
                    crate::analyzer::semantic_model::TransferPartitionSource::InputCapture { symbol } if symbol == &location.id))
        })
            || !summary.effects.is_empty()
            || !summary.concurrency_effects.is_empty()
            || summary.no_concurrency_effects
            || !summary.declared_effects.is_empty()
            || summary.preconditions.is_some()
            || !summary.result_contracts.is_empty()
            || !summary.result_use_obligations.is_empty()
            || !summary.conditional_result_refinements.is_empty()
            || !summary.conditional_indirect_writes.is_empty()
            || !summary.normal_return_refinements.is_empty()
            || !summary.normal_return_type_refinements.is_empty()
            || summary.class_decorator_identity.is_some()
            || summary.ordinary_heap_unchanged
            || summary.covers_overrides
            || summary.normal_continuation_absent
            || summary
                .transfers
                .iter()
                .any(|transfer| transfer.value_transfer.is_some())
        {
            return Err(unsupported(
                "Python summary has behavior outside supported core transfers",
            ));
        }
        let transfers = summary
            .transfers
            .iter()
            .map(|transfer| super::export::transfer_to_csmi(transfer, &symbol_ids))
            .collect::<Result<Vec<_>, _>>()?;
        procedure_summaries.push(CsmiProcedureSummary {
            callable: callable.clone(),
            transfers,
            extensions: Vec::new(),
        });
        let status = if summary.completeness == Completeness::Complete {
            CsmiCoverageStatus::Complete
        } else {
            CsmiCoverageStatus::Partial
        };
        completeness.push(CsmiCompletenessStatement {
            vocabulary: None,
            version: None,
            family: "procedure-summaries".to_owned(),
            scope: json!({"callable":callable}),
            status,
            limitations: if status == CsmiCoverageStatus::Partial {
                vec![CsmiLimitation {
                    kind: "coverage-limited".to_owned(),
                    diagnostic: None,
                }]
            } else {
                Vec::new()
            },
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
        if !summary.transfer_partitions.is_empty() {
            partition_shape_callables.push(callable.clone());
        }
        for partition in &summary.transfer_partitions {
            use crate::analyzer::semantic_model::{
                TransferPartitionSource, TransferPartitionStatus,
            };
            if symbol_shapes.get(callable) != Some(&true) {
                return Err(unsupported(
                    "scoped transfer coverage requires a complete callable shape",
                ));
            }
            if evidence.is_none()
                && !partition.provenance.is_empty()
                && partition.provenance != [options.provenance_id.as_str()]
            {
                return Err(unsupported(
                    "Python partition provenance requires exact retained producer evidence",
                ));
            }
            let source = match &partition.source {
                TransferPartitionSource::AllInputs => CsmiTransferPartitionSource::AllInputs,
                TransferPartitionSource::InputReceiver => CsmiTransferPartitionSource::InputRoot {
                    root: CsmiInputBoundaryRoot::Receiver(CsmiInputReceiverRoot {
                        phase: CsmiInputPhase::Input,
                        role: CsmiReceiverRootRole::Receiver,
                    }),
                },
                TransferPartitionSource::InputParameter { ordinal } => {
                    CsmiTransferPartitionSource::InputRoot {
                        root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                            phase: CsmiInputPhase::Input,
                            role: CsmiParameterRootRole::Parameter,
                            position: *ordinal,
                        }),
                    }
                }
                TransferPartitionSource::InputCapture { symbol } => {
                    CsmiTransferPartitionSource::InputRoot {
                        root: CsmiInputBoundaryRoot::Capture(CsmiInputCaptureRoot {
                            phase: CsmiInputPhase::Input,
                            role: CsmiCaptureRootRole::Capture,
                            symbol: symbol.clone(),
                        }),
                    }
                }
            };
            let scope = serde_json::to_value(CsmiTransferPartitionScope {
                callable: callable.clone(),
                exit: CsmiTransferPartitionExit::Normal,
                destination: CsmiOutputResultRoot {
                    phase: CsmiOutputPhase::Output,
                    role: CsmiResultRootRole::Result,
                    position: partition.normal_result,
                },
                source,
            })
            .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
            completeness.push(CsmiCompletenessStatement {
                vocabulary: Some(CSMI_TRANSFER_PARTITIONS_PROFILE_ID.to_owned()),
                version: Some(CSMI_TRANSFER_PARTITIONS_PROFILE_VERSION.to_owned()),
                family: "transfer-partitions".to_owned(),
                scope: scope.clone(),
                status: match partition.status {
                    TransferPartitionStatus::Unknown => CsmiCoverageStatus::Unknown,
                    TransferPartitionStatus::Partial => CsmiCoverageStatus::Partial,
                    TransferPartitionStatus::Complete => CsmiCoverageStatus::Complete,
                },
                limitations: partition
                    .limitations
                    .iter()
                    .map(|limitation| CsmiLimitation {
                        kind: limitation.kind.clone(),
                        diagnostic: (limitation.diagnostic_code.is_some()
                            || limitation.diagnostic_message.is_some())
                        .then(|| CsmiDiagnosticMetadata {
                            code: limitation.diagnostic_code.clone(),
                            message: limitation.diagnostic_message.clone(),
                        }),
                    })
                    .collect(),
                provenance: if evidence.is_some() {
                    partition.provenance.clone()
                } else {
                    vec![options.provenance_id.clone()]
                },
                extensions: Vec::new(),
            });
            partition_affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                kind: CsmiAffectedFactFamilyKind::FactFamily,
                family: "transfer-partitions".to_owned(),
                scope,
            }));
        }
    }
    for payload in shards
        .iter()
        .filter_map(|shard| shard.conditional_type_refinements())
        .chain(std::iter::once(&annotation_facts))
    {
        super::export::export_conditional_type_refinements(
            payload,
            options,
            &symbol_ids,
            &shapes,
            &mut facts,
            &mut affects,
            &mut completeness,
        )?;
    }
    for statement in callable_shape_statements {
        if let Some(existing) = completeness.iter_mut().find(|candidate| {
            candidate.vocabulary.is_none()
                && candidate.family == statement.family
                && candidate.scope == statement.scope
        }) {
            if existing.status != statement.status {
                return Err(unsupported(
                    "native refinement conflicts with retained callable-shape coverage",
                ));
            }
            *existing = statement;
        } else {
            completeness.push(statement);
        }
    }
    partition_shape_callables.extend(
        symbol_shapes
            .iter()
            .filter_map(|(callable, complete)| complete.then_some(callable.clone())),
    );
    partition_shape_callables.sort_unstable();
    partition_shape_callables.dedup();
    for callable in partition_shape_callables {
        let scope = json!({"symbol":callable,"aspect":"callable-shape"});
        if let Some(statement) = completeness
            .iter()
            .find(|statement| statement.family == "declaration-aspects" && statement.scope == scope)
        {
            if statement.status != CsmiCoverageStatus::Complete {
                return Err(unsupported(
                    "scoped transfer coverage conflicts with incomplete callable-shape evidence",
                ));
            }
            continue;
        }
        completeness.push(CsmiCompletenessStatement {
            vocabulary: None,
            version: None,
            family: "declaration-aspects".to_owned(),
            scope,
            status: CsmiCoverageStatus::Complete,
            limitations: Vec::new(),
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    if let Some(retained) = correspondence {
        for original in &retained.core_completeness_statements {
            let generated = completeness.iter_mut().find(|candidate| {
                candidate.vocabulary.is_none()
                    && candidate.version.is_none()
                    && candidate.family == original.family
                    && candidate.scope == original.scope
            });
            let Some(generated) = generated else {
                return Err(unsupported(
                    "original Python core completeness scope is absent from native export",
                ));
            };
            if generated.status != original.status {
                return Err(unsupported(
                    "native Python coverage disagrees with original core completeness status",
                ));
            }
            *generated = original.clone();
        }
    }
    let mut uses = if let Some(evidence) = evidence {
        facts.extend(evidence.extension_facts.iter().cloned());
        completeness.extend(evidence.completeness_statements.iter().cloned());
        evidence.vocabulary_uses.clone()
    } else {
        vec![CsmiVocabularyUse {
            identifier: CSMI_PYTHON_PROFILE_ID.to_owned(),
            version: CSMI_PYTHON_PROFILE_VERSION.to_owned(),
            schema: CSMI_PYTHON_PROFILE_SCHEMA.to_owned(),
            requirement: CsmiVocabularyRequirement::Required,
            affects: identity_affects,
        }]
    };
    if !partition_affects.is_empty() {
        uses.push(CsmiVocabularyUse {
            identifier: CSMI_TRANSFER_PARTITIONS_PROFILE_ID.to_owned(),
            version: CSMI_TRANSFER_PARTITIONS_PROFILE_VERSION.to_owned(),
            schema: CSMI_TRANSFER_PARTITIONS_PROFILE_SCHEMA.to_owned(),
            requirement: CsmiVocabularyRequirement::Required,
            affects: partition_affects,
        });
    }
    if !affects.is_empty() {
        uses.push(CsmiVocabularyUse {
            identifier: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID.to_owned(),
            version: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION.to_owned(),
            schema: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA.to_owned(),
            requirement: CsmiVocabularyRequirement::Required,
            affects,
        });
    }
    let model = CsmiSemanticModel {
        artifact_selectors: vec![selector],
        compatibility_constraints: evidence
            .map(|evidence| evidence.compatibility_constraints.clone())
            .unwrap_or_default(),
        vocabulary_uses: uses,
        consumer_resolved_dependencies: Vec::new(),
        symbols,
        declarations,
        relationships: Vec::new(),
        procedure_summaries,
        extension_facts: facts,
        completeness_statements: completeness,
        extensions: Vec::new(),
    };
    validate_model(&model).map_err(CsmiExportError::Identity)?;
    let record = CsmiProvenanceRecord {
        id: options.provenance_id.clone(),
        producer: CsmiProducerIdentity {
            identifier: "https://bifrost.brokk.ai/semantic-pack-producer".to_owned(),
            version: manifest.producer.version.clone(),
        },
        generation_method: CsmiGenerationMethod::Composition,
        inputs: vec![CsmiProvenanceInput {
            role: "target-artifact".to_owned(),
            identifier: None,
            purl: Some(artifact.purl.clone()),
            digest: Some(CsmiArtifactDigest {
                algorithm: CsmiDigestAlgorithm::Sha256,
                coverage: artifact.coverage.clone(),
                canonicalization: None,
                value: artifact.sha256.clone(),
            }),
            pack_digest: None,
            semantic_document_digest: None,
        }],
        created_at: options.created_at.clone(),
        invocation_id: manifest.provenance.revision.clone(),
        diagnostic: None,
    };
    let mut provenance_ids = model
        .extension_facts
        .iter()
        .flat_map(|fact| fact.provenance.iter())
        .chain(
            model
                .completeness_statements
                .iter()
                .flat_map(|fact| fact.provenance.iter()),
        )
        .filter(|id| *id != &options.provenance_id)
        .cloned()
        .collect::<Vec<_>>();
    provenance_ids.sort();
    provenance_ids.dedup();
    if callable_shape_defaults
        .iter()
        .skip(1)
        .any(|default| default != &callable_shape_defaults[0])
    {
        return Err(unsupported(
            "Python callable-shape evidence has conflicting original default provenance",
        ));
    }
    let callable_shape_default = callable_shape_defaults.into_iter().next().flatten();
    if evidence.is_some_and(|retained| {
        callable_shape_default.is_some() && retained.default_provenance != callable_shape_default
    }) {
        return Err(unsupported(
            "Python profile and callable-shape evidence disagree on original default provenance",
        ));
    }
    let mut provenance_records = vec![record.clone()];
    if let Some(evidence) = evidence {
        if evidence
            .provenance_records
            .iter()
            .any(|retained| retained.id == record.id)
        {
            return Err(unsupported(
                "export provenance id conflicts with retained producer evidence",
            ));
        }
        provenance_records.extend(evidence.provenance_records.iter().cloned());
    }
    for retained in callable_shape_provenance {
        if let Some(existing) = provenance_records
            .iter()
            .find(|candidate| candidate.id == retained.id)
        {
            if existing != &retained {
                return Err(unsupported(
                    "Python callable-shape provenance conflicts with another producer record",
                ));
            }
        } else {
            provenance_records.push(retained);
        }
    }
    if provenance_ids
        .iter()
        .any(|id| !provenance_records.iter().any(|record| &record.id == id))
    {
        return Err(unsupported(
            "Python export cannot recover an original producer provenance record",
        ));
    }
    let default_provenance = evidence
        .and_then(|evidence| evidence.default_provenance.clone())
        .or(callable_shape_default)
        .or_else(|| Some(options.provenance_id.clone()));
    if default_provenance
        .as_ref()
        .is_some_and(|id| !provenance_records.iter().any(|record| &record.id == id))
    {
        return Err(unsupported(
            "Python export default provenance has no original producer record",
        ));
    }
    let document = CsmiSemanticDocument {
        document_type: "semantic-document".to_owned(),
        schema: CSMI_SCHEMA_URI.to_owned(),
        semantic_model_version: CSMI_SEMANTIC_MODEL_VERSION.to_owned(),
        serialization_version: CSMI_SERIALIZATION_VERSION.to_owned(),
        provenance_records,
        default_provenance,
        semantic_models: vec![model],
    };
    Ok((document, record))
}
