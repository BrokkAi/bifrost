//! Query-local Python defining-binding resolution from validated CSMI profile facts.

use crate::analyzer::Range;
use crate::analyzer::lexical_definitions::{FormalParameterPassingMode, FormalParameterSlot};
use crate::analyzer::python::runtime_artifact::PythonRuntimeArtifactIdentity;
use crate::analyzer::semantic_model::csmi::CsmiDescriptorRole;
use crate::analyzer::semantic_model::{
    Locator, MemberFact, MemberKind, ParameterPassingMode, PortableCallableShapeEvidence,
    PortableProfileEvidence, ResolvedActiveSemanticModels, SemanticModelActivationEvidence,
    TypeFact, TypeKind,
};
use crate::analyzer::semantic_model::{
    PythonConditionEvaluation, PythonConditionField, PythonConditionFinding,
    PythonConditionFindingKind, PythonConditionSnapshot, PythonConditionStatus,
    evaluate_python_condition,
};
use crate::analyzer::store::WorkspaceSnapshotId;
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

pub(crate) use super::runtime_provider::PythonRuntimeProviderProof;

const PYTHON: &str = "csmi.python";
const VERSION: &str = "0.1.0";
const MAX_HOPS: usize = 64;

/// Opaque profile proof. Its private fields can only be minted by the exact
/// evidence, complete-profile, and definition-edge joins below.
#[derive(Debug, Clone)]
pub(crate) struct PythonDefiningBinding {
    canonical: Vec<String>,
    formal_slots: Vec<FormalParameterSlot>,
    artifact: PythonRuntimeArtifactIdentity,
    touched_modules: Vec<String>,
    source_path: PathBuf,
    snapshot: WorkspaceSnapshotId,
    model_manifest_sha256: String,
}

impl PythonDefiningBinding {
    pub(crate) fn canonical(&self) -> &[String] {
        &self.canonical
    }
    pub(crate) fn formal_slots(&self) -> &[FormalParameterSlot] {
        &self.formal_slots
    }
    pub(crate) fn artifact(&self) -> &PythonRuntimeArtifactIdentity {
        &self.artifact
    }
    pub(crate) fn touched_modules(&self) -> &[String] {
        &self.touched_modules
    }
    pub(crate) fn source_path(&self) -> &Path {
        &self.source_path
    }
    pub(crate) fn model_manifest_sha256(&self) -> &str {
        &self.model_manifest_sha256
    }
    pub(crate) fn snapshot(&self) -> &WorkspaceSnapshotId {
        &self.snapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonRuntimeBindingDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PythonRuntimeBindingError {
    MissingModel(Vec<PythonRuntimeBindingDiagnostic>),
    MissingBinding(Vec<PythonRuntimeBindingDiagnostic>),
    Ambiguous(Vec<PythonRuntimeBindingDiagnostic>),
    Incomplete(Vec<PythonRuntimeBindingDiagnostic>),
    Incompatible(Vec<PythonConditionEvaluation>),
    ConditionIncomplete(Vec<PythonConditionEvaluation>),
}

#[derive(Debug)]
enum ProfileBindingFailure {
    Evidence(String),
    Condition(PythonConditionEvaluation),
}

impl From<String> for ProfileBindingFailure {
    fn from(message: String) -> Self {
        Self::Evidence(message)
    }
}

impl From<&str> for ProfileBindingFailure {
    fn from(message: &str) -> Self {
        Self::Evidence(message.to_owned())
    }
}

/// Inputs are canonical segments produced by the structured source resolver;
/// source-local shadows must already have been handled by that resolver.
pub(crate) fn resolve_python_defining_binding(
    active: &ResolvedActiveSemanticModels,
    selected: &SemanticModelActivationEvidence,
    import_module: &[String],
    member: &str,
    source_path: &Path,
    snapshot: &WorkspaceSnapshotId,
    environment: Option<&PythonConditionSnapshot>,
) -> Result<PythonDefiningBinding, PythonRuntimeBindingError> {
    let diagnostic = |code, message| PythonRuntimeBindingDiagnostic { code, message };
    // Do not inspect any payload or carrier until the complete evidence row matches.
    let shards = active
        .shards()
        .iter()
        .filter(|shard| {
            shard
                .matching_evidence
                .iter()
                .any(|evidence| evidence == selected)
        })
        .collect::<Vec<_>>();
    if shards.is_empty() {
        return Err(PythonRuntimeBindingError::MissingModel(vec![diagnostic(
            "python.runtime_binding.model_missing",
            format!("no active shard matches exact activation evidence {selected:?}"),
        )]));
    }
    if import_module.is_empty() || import_module.iter().any(String::is_empty) || member.is_empty() {
        return Err(PythonRuntimeBindingError::Incomplete(vec![diagnostic(
            "python.runtime_binding.invalid_import",
            "expected structured non-empty module/member segments".into(),
        )]));
    }
    let mut found_carrier = false;
    let mut incomplete = Vec::new();
    let mut ambiguous = Vec::new();
    let mut incompatible = Vec::new();
    let mut condition_incomplete = Vec::new();
    let mut answers = Vec::new();
    for shard in shards {
        let Some((types, members, _)) = shard.shard.payload().declaration_facts() else {
            continue;
        };
        let mut profile: Option<&PortableProfileEvidence> = None;
        let mut disagree = false;
        for locator in types
            .iter()
            .map(|fact| &fact.locator)
            .chain(members.iter().map(|fact| &fact.locator))
        {
            if let Locator::Interchange {
                profile_evidence: Some(candidate),
                ..
            } = locator
            {
                found_carrier = true;
                if profile.is_some_and(|prior| prior != candidate.as_ref()) {
                    disagree = true;
                    break;
                }
                profile = Some(candidate);
            }
        }
        if disagree {
            incomplete.push(diagnostic(
                "python.runtime_binding.carrier_disagreement",
                "validated profile carriers disagree".into(),
            ));
            continue;
        }
        let Some(profile) = profile else { continue };
        match resolve_profile(
            profile,
            types,
            members,
            selected,
            import_module,
            member,
            environment,
        ) {
            Ok(Some(answer)) => answers.push((answer, shard.manifest.content_sha256.clone())),
            Ok(None) => {}
            Err(message) => match profile_resolution_error(message) {
                PythonRuntimeBindingError::Ambiguous(mut diagnostics) => {
                    ambiguous.append(&mut diagnostics)
                }
                PythonRuntimeBindingError::Incomplete(mut diagnostics) => {
                    incomplete.append(&mut diagnostics)
                }
                PythonRuntimeBindingError::Incompatible(mut evaluations) => {
                    incompatible.append(&mut evaluations)
                }
                PythonRuntimeBindingError::ConditionIncomplete(mut evaluations) => {
                    condition_incomplete.append(&mut evaluations)
                }
                PythonRuntimeBindingError::MissingModel(_)
                | PythonRuntimeBindingError::MissingBinding(_) => {
                    unreachable!("profile failures cannot be model-absence results")
                }
            },
        }
    }
    if !ambiguous.is_empty() {
        return Err(PythonRuntimeBindingError::Ambiguous(ambiguous));
    }
    if answers.len() > 1 {
        return Err(PythonRuntimeBindingError::Ambiguous(vec![diagnostic(
            "python.runtime_binding.multiple_definitions",
            format!(
                "multiple exact definitions for {}::{member}",
                import_module.join(".")
            ),
        )]));
    }
    if !condition_incomplete.is_empty() {
        return Err(PythonRuntimeBindingError::ConditionIncomplete(
            condition_incomplete,
        ));
    }
    if !incomplete.is_empty() {
        return Err(PythonRuntimeBindingError::Incomplete(incomplete));
    }
    if let Some((profile_binding, model_manifest_sha256)) = answers.pop() {
        return Ok(PythonDefiningBinding {
            canonical: profile_binding.canonical,
            formal_slots: profile_binding.formal_slots,
            artifact: profile_binding.artifact,
            touched_modules: profile_binding.touched_modules,
            source_path: source_path.to_owned(),
            snapshot: snapshot.clone(),
            model_manifest_sha256,
        });
    }
    if !incompatible.is_empty() {
        return Err(PythonRuntimeBindingError::Incompatible(incompatible));
    }
    if !found_carrier {
        return Err(PythonRuntimeBindingError::Incomplete(vec![diagnostic(
            "python.runtime_binding.carrier_missing",
            "exact active shard has no validated Python profile carrier".into(),
        )]));
    }
    Err(PythonRuntimeBindingError::MissingBinding(vec![diagnostic(
        "python.runtime_binding.binding_missing",
        format!(
            "no complete definition edge for {}::{member}",
            import_module.join(".")
        ),
    )]))
}

#[derive(Debug)]
struct ProfileBinding {
    canonical: Vec<String>,
    formal_slots: Vec<FormalParameterSlot>,
    artifact: PythonRuntimeArtifactIdentity,
    touched_modules: Vec<String>,
}

fn resolve_profile(
    profile: &PortableProfileEvidence,
    types: &[TypeFact],
    members: &[MemberFact],
    selected: &SemanticModelActivationEvidence,
    requested_module: &[String],
    requested_member: &str,
    environment: Option<&PythonConditionSnapshot>,
) -> Result<Option<ProfileBinding>, ProfileBindingFailure> {
    let mut has_project_config_constraint = false;
    for constraint in &profile.compatibility_constraints {
        if constraint.vocabulary != PYTHON || constraint.version != VERSION {
            return Err("unsupported Python compatibility constraint vocabulary or version".into());
        }
        has_project_config_constraint |= constraint.value.get("projectConfig").is_some();
        let mut condition = constraint.value.clone();
        let fields = condition
            .as_object_mut()
            .expect("validated Python compatibility payload is an object");
        assert_eq!(
            fields.remove("kind"),
            Some(Value::String("compatibility".into()))
        );
        require_conditions(Some(&condition), environment)?;
    }
    // A declared provider is applicable only to a model which explicitly
    // binds its claim to that same resolver configuration. Unconditional
    // profile facts cannot silently assert a closed interpreter universe.
    if environment.is_some() && !has_project_config_constraint {
        return Err(ProfileBindingFailure::Condition(PythonConditionEvaluation {
            status: PythonConditionStatus::Indeterminate,
            findings: vec![PythonConditionFinding {
                field: PythonConditionField::ProjectConfig,
                kind: PythonConditionFindingKind::Missing,
                reason: "model has no projectConfig compatibility constraint for the declared provider".into(),
            }],
        }));
    }
    let roots_fact = profile
        .extension_facts
        .iter()
        .find(|fact| fact.vocabulary == PYTHON && fact.family == "distribution-imports")
        .ok_or_else(|| "distribution-imports fact absent".to_owned())?;
    let roots_scope = serde_json::json!({"artifact":"model"});
    if roots_fact.version != VERSION
        || roots_fact.scope != roots_scope
        || roots_fact.payload.get("kind").and_then(Value::as_str) != Some("distribution-imports")
    {
        return Err(
            "distribution-imports fact has unsupported scope, version, or conditions".into(),
        );
    }
    require_conditions(roots_fact.payload.get("conditions"), environment)?;
    let roots = roots_fact
        .payload
        .get("importRoots")
        .and_then(Value::as_array)
        .ok_or("importRoots absent")?;
    let covered = roots.iter().any(|root| {
        root.as_array().is_some_and(|parts| {
            let values = parts.iter().map(Value::as_str).collect::<Option<Vec<_>>>();
            values.is_some_and(|values| {
                !values.is_empty()
                    && requested_module
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .starts_with(&values)
            })
        })
    });
    if !covered {
        return Ok(None);
    }

    let mut artifacts = Vec::new();
    let mut module_ids: HashMap<Vec<String>, Vec<String>> = HashMap::new();
    let mut modules_by_symbol: HashMap<String, (&TypeFact, Vec<String>)> = HashMap::new();
    for ty in types {
        if ty.type_kind != TypeKind::Module {
            continue;
        }
        let Some(identity) = identity_parts(&ty.id, &ty.locator)? else {
            continue;
        };
        artifacts.push(identity.artifact.clone());
        if modules_by_symbol
            .insert(
                identity.portable_symbol.clone(),
                (ty, identity.module.clone()),
            )
            .is_some()
        {
            return Err(format!(
                "multiple module declarations claim portable symbol {:?}",
                identity.portable_symbol
            )
            .into());
        }
        module_ids
            .entry(identity.module)
            .or_default()
            .push(identity.portable_symbol);
    }
    let mut members_by_symbol = HashMap::new();
    for callable in members {
        if let Some(identity) = identity_parts(&callable.id, &callable.locator)? {
            artifacts.push(identity.artifact);
            if members_by_symbol
                .insert(identity.portable_symbol.clone(), callable)
                .is_some()
            {
                return Err(format!(
                    "multiple callable declarations claim portable symbol {:?}",
                    identity.portable_symbol
                )
                .into());
            }
        }
    }
    let Some(artifact) = artifacts.first().cloned() else {
        return Err("profile has no structured exact artifact identity".into());
    };
    if artifacts.iter().any(|candidate| candidate != &artifact) {
        return Err("profile mixes artifact identities".into());
    }
    if selected.artifact_sha256.as_deref() != Some(artifact.archive_sha256())
        || !selected_package_matches(selected, artifact.purl())
    {
        return Err(
            "profile artifact does not match selected PyPI coordinate and raw SHA-256".into(),
        );
    }
    require_complete(profile, "distribution-imports", &roots_scope, &artifact)?;
    require_provenance(profile, &roots_fact.provenance, &artifact)?;
    let initial = module_ids.get(requested_module).cloned().ok_or_else(|| {
        format!("requested module {requested_module:?} is under a declared import root but has no structured namespace declaration")
    })?;
    if initial.is_empty() {
        return Err("requested module has no local namespace symbol".into());
    }

    let mut queue = initial
        .into_iter()
        .map(|id| (id, requested_member.to_owned()))
        .collect::<VecDeque<_>>();
    let mut visited = HashSet::new();
    let mut touched = Vec::new();
    let mut definitions = Vec::new();
    while let Some((module_id, sought_name)) = queue.pop_front() {
        if !visited.insert((module_id.clone(), sought_name.clone())) {
            continue;
        }
        if visited.len() > MAX_HOPS {
            return Err("import binding traversal exceeded bound".into());
        }
        let (module_fact, module) = modules_by_symbol
            .get(&module_id)
            .ok_or_else(|| format!("binding scope {module_id:?} is not an identified module"))?;
        let display_module = module.join(".");
        if !touched.contains(&display_module) {
            touched.push(display_module);
        }
        let scope = serde_json::json!({"module":module_id});
        let facts = profile
            .extension_facts
            .iter()
            .filter(|fact| {
                fact.vocabulary == PYTHON && fact.family == "import-bindings" && fact.scope == scope
            })
            .collect::<Vec<_>>();
        if facts.len() != 1 {
            return Err(format!(
                "module {module:?} has {} import-bindings facts",
                facts.len()
            )
            .into());
        }
        let fact = facts[0];
        if fact.version != VERSION
            || fact.payload.get("kind").and_then(Value::as_str) != Some("import-bindings")
        {
            return Err(
                format!("module {module:?} bindings are conditional or unsupported").into(),
            );
        }
        require_conditions(fact.payload.get("conditions"), environment)?;
        require_complete(profile, "import-bindings", &scope, &artifact)?;
        require_provenance(profile, &fact.provenance, &artifact)?;
        let bindings = fact
            .payload
            .get("bindings")
            .and_then(Value::as_array)
            .ok_or("bindings absent")?;
        for edge in bindings {
            let name = edge
                .get("name")
                .and_then(Value::as_str)
                .ok_or("binding name absent")?;
            if name != sought_name {
                continue;
            }
            require_conditions(edge.get("conditions"), environment)?;
            let kind = edge
                .get("bindingKind")
                .and_then(Value::as_str)
                .ok_or("binding kind absent")?;
            let target = edge
                .get("target")
                .and_then(Value::as_str)
                .ok_or("binding target absent")?;
            match kind {
                "definition" => {
                    if let Some(callable) = members_by_symbol.get(target)
                        && let Some(canonical) = exact_callable_definition(
                            callable,
                            &module_fact.id,
                            module,
                            &sought_name,
                            &artifact,
                        )?
                    {
                        definitions.push((formal_slots(callable)?, canonical));
                    }
                }
                "alias" | "re-export" => {
                    if let Some((_, target_module)) = modules_by_symbol.get(target) {
                        if let Some(ids) = module_ids.get(target_module) {
                            queue.extend(ids.iter().cloned().map(|id| (id, sought_name.clone())));
                        } else {
                            return Err(format!(
                                "re-export target module {target_module:?} has no local module identity"
                            ).into());
                        }
                    } else if let Some(target_member) = members_by_symbol.get(target) {
                        let target_identity =
                            identity_parts(&target_member.id, &target_member.locator)?
                                .ok_or("alias target has no CSMI identity")?;
                        if target_identity.artifact != artifact {
                            return Err("cross-artifact alias correspondence is unsupported".into());
                        }
                        let canonical_name = match &target_member.locator {
                            Locator::Interchange { identity, .. } => identity
                                .descriptors
                                .last()
                                .and_then(|descriptor| descriptor.name.clone())
                                .ok_or("callable descriptor name absent")?,
                            _ => return Err("alias target lacks interchange identity".into()),
                        };
                        if let Some(ids) = module_ids.get(&target_identity.module) {
                            queue
                                .extend(ids.iter().cloned().map(|id| (id, canonical_name.clone())));
                        } else {
                            return Err(format!(
                                "alias target owner module {:?} is absent",
                                target_identity.module
                            )
                            .into());
                        }
                    } else {
                        return Err(format!(
                            "alias target {target:?} has no structured local identity"
                        )
                        .into());
                    }
                }
                other => return Err(format!("unsupported binding kind {other:?}").into()),
            }
        }
    }
    if definitions.len() > 1 {
        return Err(format!(
            "ambiguous: multiple definition edges resolve to {}::{requested_member}",
            requested_module.join(".")
        )
        .into());
    }
    let Some((slots, canonical)) = definitions.pop() else {
        return Ok(None);
    };
    Ok(Some(ProfileBinding {
        canonical,
        formal_slots: slots,
        artifact,
        touched_modules: touched,
    }))
}

/// CSMI binding targets use portable symbol IDs; declaration facts use native
/// hashed IDs. Keep both domains explicit after verifying their exact join.
struct ProfileIdentityParts {
    portable_symbol: String,
    artifact: PythonRuntimeArtifactIdentity,
    module: Vec<String>,
}

fn identity_parts(id: &str, locator: &Locator) -> Result<Option<ProfileIdentityParts>, String> {
    let Locator::Interchange {
        symbol, identity, ..
    } = locator
    else {
        return Ok(None);
    };
    crate::analyzer::semantic_model::csmi::python::validate_identity(identity)?;
    let native_id = crate::analyzer::semantic_model::csmi::python::native_id(identity);
    if native_id.as_str() != id {
        return Err(format!(
            "CSMI portable symbol {symbol:?} maps to native declaration ID {native_id:?}, not {id:?}"
        ));
    }
    let [selector] = identity.artifact_selectors.as_slice() else {
        return Err("identity needs one exact artifact selector".into());
    };
    let digest = selector
        .digests
        .iter()
        .find(|digest| {
            digest.algorithm == crate::analyzer::semantic_model::csmi::CsmiDigestAlgorithm::Sha256
                && digest.coverage == "artifact"
                && digest.canonicalization.is_none()
        })
        .ok_or("raw artifact SHA-256 absent")?;
    let artifact = PythonRuntimeArtifactIdentity::from_validated_profile_selector(
        &selector.purl,
        &digest.value,
    )
    .ok_or("artifact selector is invalid")?;
    let module = identity
        .descriptors
        .iter()
        .take_while(|descriptor| descriptor.role == CsmiDescriptorRole::Namespace)
        .map(|descriptor| descriptor.name.clone().expect("validated descriptor"))
        .collect();
    Ok(Some(ProfileIdentityParts {
        portable_symbol: symbol.clone(),
        artifact,
        module,
    }))
}

fn exact_callable_definition(
    member: &MemberFact,
    module_id: &str,
    module: &[String],
    name: &str,
    artifact: &PythonRuntimeArtifactIdentity,
) -> Result<Option<Vec<String>>, String> {
    if member.member_kind != MemberKind::Function
        || member.is_static
        || member.receiver.is_some()
        || member.extension_receiver.is_some()
        || !member.extension_receiver_constraints.is_empty()
        || member.is_abstract
        || member.owner != module_id
    {
        return Ok(None);
    }
    let Some(actual_identity) = identity_parts(&member.id, &member.locator)? else {
        return Ok(None);
    };
    let Locator::Interchange {
        symbol,
        identity,
        callable_shape_evidence,
        ..
    } = &member.locator
    else {
        return Ok(None);
    };
    let Some(descriptor) = identity.descriptors.last() else {
        return Ok(None);
    };
    if actual_identity.artifact != *artifact
        || actual_identity.module != module
        || member.name != name
        || descriptor.role != CsmiDescriptorRole::Callable
        || descriptor.name.as_deref() != Some(name)
    {
        return Ok(None);
    }
    require_callable_shape_evidence(member, symbol, callable_shape_evidence.as_deref(), artifact)?;
    Ok(Some(
        identity
            .descriptors
            .iter()
            .map(|descriptor| descriptor.name.clone().expect("validated descriptor"))
            .collect(),
    ))
}

fn formal_slots(member: &MemberFact) -> Result<Vec<FormalParameterSlot>, String> {
    let signature = member
        .signature
        .as_ref()
        .ok_or("callable signature absent")?;
    if !signature.type_parameters.is_empty() {
        return Err("generic callable shape unsupported".into());
    }
    let no_source_span = Range {
        start_byte: 0,
        end_byte: 0,
        start_line: 0,
        end_line: 0,
    };
    signature
        .parameters
        .iter()
        .map(|parameter| {
            if parameter.variadic {
                return Err("variadic parameter shape is not represented exactly".into());
            }
            let name = parameter
                .name
                .as_ref()
                .filter(|name| !name.is_empty())
                .ok_or("callable parameter binding name absent")?;
            Ok(FormalParameterSlot {
                names: vec![name.clone()],
                declaration_range: no_source_span,
                receiver: false,
                variadic: None,
                passing_mode: match parameter.passing_mode {
                    ParameterPassingMode::PositionalOnly => {
                        FormalParameterPassingMode::PositionalOnly
                    }
                    ParameterPassingMode::PositionalOrNamed => {
                        FormalParameterPassingMode::PositionalOrNamed
                    }
                    ParameterPassingMode::NamedOnly => FormalParameterPassingMode::NamedOnly,
                },
                default_range: parameter.optional.then_some(no_source_span),
            })
        })
        .collect()
}

fn require_complete(
    profile: &PortableProfileEvidence,
    family: &str,
    scope: &Value,
    artifact: &PythonRuntimeArtifactIdentity,
) -> Result<(), String> {
    let statements = profile
        .completeness_statements
        .iter()
        .filter(|statement| {
            statement.vocabulary.as_deref() == Some(PYTHON)
                && statement.version.as_deref() == Some(VERSION)
                && statement.family == family
                && &statement.scope == scope
        })
        .collect::<Vec<_>>();
    if statements.len() != 1
        || statements[0].status
            != crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Complete
        || !statements[0].limitations.is_empty()
    {
        return Err(format!("{family} scope {scope} is not uniquely complete"));
    }
    require_provenance(profile, &statements[0].provenance, artifact)
}

fn require_conditions(
    condition: Option<&Value>,
    environment: Option<&PythonConditionSnapshot>,
) -> Result<(), ProfileBindingFailure> {
    let Some(condition) = condition else {
        return Ok(());
    };
    let unknown = PythonConditionSnapshot::default();
    let evaluation = evaluate_python_condition(Some(condition), environment.unwrap_or(&unknown));
    if evaluation.status != PythonConditionStatus::Compatible {
        return Err(ProfileBindingFailure::Condition(evaluation));
    }
    Ok(())
}

fn require_provenance(
    profile: &PortableProfileEvidence,
    ids: &[String],
    artifact: &PythonRuntimeArtifactIdentity,
) -> Result<(), String> {
    let records = provenance_for_ids(&profile.provenance_records, ids)?;
    if !records
        .iter()
        .any(|record| provenance_matches_artifact(record, artifact))
    {
        return Err("profile provenance does not identify the selected artifact".into());
    }
    Ok(())
}

fn require_callable_shape_evidence(
    member: &MemberFact,
    portable_symbol: &str,
    evidence: Option<&PortableCallableShapeEvidence>,
    artifact: &PythonRuntimeArtifactIdentity,
) -> Result<(), String> {
    let evidence = evidence.ok_or("callable-shape evidence absent")?;
    let statement = &evidence.statement;
    if statement.vocabulary.is_some()
        || statement.version.is_some()
        || statement.family != "declaration-aspects"
        || statement.scope
            != serde_json::json!({"symbol":portable_symbol,"aspect":"callable-shape"})
        || statement.status != crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Complete
        || !statement.limitations.is_empty()
        || !statement.extensions.is_empty()
    {
        return Err("callable-shape statement is not exact complete core coverage".into());
    }
    let native_digest =
        crate::analyzer::semantic_model::csmi::python::native_callable_shape_digest(member);
    let evidence_digest =
        crate::analyzer::semantic_model::csmi::python::callable_shape_evidence_digest(evidence);
    if evidence.native_sha256 != native_digest || evidence.evidence_sha256 != evidence_digest {
        return Err("callable-shape evidence is not bound to the exact native declaration".into());
    }

    let mut provenance_ids = statement
        .provenance
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if provenance_ids.len() != statement.provenance.len() {
        return Err("callable-shape provenance contains duplicate references".into());
    }
    if let Some(default) = evidence.default_provenance.as_ref() {
        provenance_ids.insert(default.as_str());
    }
    if provenance_ids.is_empty() {
        return Err("callable-shape provenance is absent".into());
    }
    let referenced_ids = provenance_ids
        .iter()
        .map(|id| (*id).to_owned())
        .collect::<Vec<_>>();
    let records = provenance_for_ids(&evidence.provenance_records, &referenced_ids)?;
    if evidence
        .provenance_records
        .iter()
        .any(|record| !provenance_ids.contains(record.id.as_str()))
    {
        return Err("callable-shape evidence retains unreferenced provenance".into());
    }
    if !records
        .iter()
        .any(|record| provenance_matches_artifact(record, artifact))
    {
        return Err("callable-shape provenance does not identify the selected artifact".into());
    }
    Ok(())
}

fn provenance_for_ids<'a>(
    records: &'a [crate::analyzer::semantic_model::csmi::CsmiProvenanceRecord],
    ids: &[String],
) -> Result<Vec<&'a crate::analyzer::semantic_model::csmi::CsmiProvenanceRecord>, String> {
    if ids.is_empty() {
        return Err("profile fact has absent or unresolved provenance".into());
    }
    let mut resolved = Vec::with_capacity(ids.len());
    for id in ids {
        let mut matches = records.iter().filter(|record| record.id == *id);
        let Some(record) = matches.next() else {
            return Err("profile fact has absent or unresolved provenance".into());
        };
        if matches.next().is_some() {
            return Err("provenance ID is not unique".into());
        }
        resolved.push(record);
    }
    Ok(resolved)
}

fn provenance_matches_artifact(
    record: &crate::analyzer::semantic_model::csmi::CsmiProvenanceRecord,
    artifact: &PythonRuntimeArtifactIdentity,
) -> bool {
    record.inputs.iter().any(|input| {
        input.role == "target-artifact"
            && input.purl.as_deref() == Some(artifact.purl())
            && input.digest.as_ref().is_some_and(|digest| {
                digest.algorithm
                    == crate::analyzer::semantic_model::csmi::CsmiDigestAlgorithm::Sha256
                    && digest.coverage == "artifact"
                    && digest.canonicalization.is_none()
                    && digest.value == artifact.archive_sha256()
            })
    })
}

fn selected_package_matches(selected: &SemanticModelActivationEvidence, purl: &str) -> bool {
    selected.language == "python"
        && selected.ecosystem == "python"
        && selected
            .package
            .as_ref()
            .is_some_and(|package| package.name == purl && package.version.is_none())
}

fn profile_resolution_error(
    failure: impl Into<ProfileBindingFailure>,
) -> PythonRuntimeBindingError {
    let message = match failure.into() {
        ProfileBindingFailure::Condition(evaluation) => {
            return match evaluation.status {
                PythonConditionStatus::Incompatible => {
                    PythonRuntimeBindingError::Incompatible(vec![evaluation])
                }
                PythonConditionStatus::Indeterminate | PythonConditionStatus::Unsupported => {
                    PythonRuntimeBindingError::ConditionIncomplete(vec![evaluation])
                }
                PythonConditionStatus::Compatible => {
                    unreachable!("compatible condition is not a failure")
                }
            };
        }
        ProfileBindingFailure::Evidence(message) => message,
    };
    if message.starts_with("ambiguous:") {
        PythonRuntimeBindingError::Ambiguous(vec![PythonRuntimeBindingDiagnostic {
            code: "python.runtime_binding.ambiguous_binding",
            message,
        }])
    } else {
        PythonRuntimeBindingError::Incomplete(vec![PythonRuntimeBindingDiagnostic {
            code: "python.runtime_binding.profile_incomplete",
            message,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::semantic_model::csmi::{
        CSMI_PACK_FORMAT_VERSION, CSMI_PYTHON_PROFILE_ID, CSMI_PYTHON_PROFILE_SCHEMA,
        CSMI_PYTHON_PROFILE_VERSION, CSMI_SCHEMA_URI, CsmiContentDigest,
        CsmiContentDigestAlgorithm, CsmiPackManifest, CsmiProducerIdentity, CsmiResourceDescriptor,
        CsmiResourceRole, CsmiVocabularySupport, InMemoryCsmiResourceResolver,
        import_logical_csmi_pack,
    };
    use crate::analyzer::semantic_model::{
        CatalogCoordinate, CatalogOptions, CompilerOptions, SemanticModelActivationRequest,
        SemanticModelResolutionOutcome, SemanticPackCatalog, SessionPackSource,
        SessionPackSourceKind, resolve_active_semantic_models,
    };
    use crate::analyzer::store::{GenerationId, WorkspaceId, WorkspaceSnapshotId};
    use semver::Version;
    use serde_json::{Value, json};

    const FIXTURE: &[u8] =
        include_bytes!("../semantic_model/csmi/fixtures/python-distribution-beautifulsoup4.json");
    const PURL: &str = "pkg:pypi/beautifulsoup4@4.13.0";
    const RAW_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn logical_pack_from_semantic(
        bytes: &[u8],
    ) -> crate::analyzer::semantic_model::csmi::CsmiLogicalPack {
        let semantic_bytes = crate::analyzer::semantic_model::csmi::canonical_json_bytes(bytes)
            .expect("fixture semantic document canonicalizes");
        let path = "models/profile.csmi.json".to_owned();
        let resources = InMemoryCsmiResourceResolver::new([(path.clone(), semantic_bytes.clone())])
            .expect("fixture resource path is valid");
        crate::analyzer::semantic_model::csmi::CsmiLogicalPack::new(
            CsmiPackManifest {
                document_type: "pack-manifest".to_owned(),
                schema: CSMI_SCHEMA_URI.to_owned(),
                pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
                assembler: CsmiProducerIdentity {
                    identifier: "https://example.org/tools/csmi-pack".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                license: "Apache-2.0".to_owned(),
                created_at: None,
                resources: vec![CsmiResourceDescriptor {
                    path,
                    role: CsmiResourceRole::SemanticDocument,
                    media_type:
                        crate::analyzer::semantic_model::csmi::CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE
                            .to_owned(),
                    size: semantic_bytes.len() as u64,
                    digest: CsmiContentDigest {
                        algorithm: CsmiContentDigestAlgorithm::Sha256,
                        value: crate::analyzer::semantic_model::csmi::sha256_hex(&semantic_bytes),
                    },
                    license: None,
                    schema_identifier: None,
                    license_reference: None,
                }],
                derived_from: Vec::new(),
            },
            resources,
        )
    }

    fn exact_evidence() -> SemanticModelActivationEvidence {
        SemanticModelActivationEvidence {
            language: "python".to_owned(),
            ecosystem: "python".to_owned(),
            package: Some(CatalogCoordinate {
                name: PURL.to_owned(),
                version: None,
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: Some(RAW_SHA256.to_owned()),
        }
    }

    fn activate_fixture(
        edit: impl FnOnce(&mut Value),
    ) -> (
        ResolvedActiveSemanticModels,
        SemanticModelActivationEvidence,
    ) {
        let mut semantic: Value =
            serde_json::from_slice(FIXTURE).expect("checked-in CSMI fixture is JSON");
        edit(&mut semantic);
        let source = serde_json::to_vec(&semantic).expect("edited fixture serializes");
        let support = CsmiVocabularySupport::support(
            CSMI_PYTHON_PROFILE_ID,
            CSMI_PYTHON_PROFILE_VERSION,
            CSMI_PYTHON_PROFILE_SCHEMA,
        );
        let imported = import_logical_csmi_pack(
            &logical_pack_from_semantic(&source),
            &support,
            &CompilerOptions::default(),
        )
        .expect("fixture imports through the validated CSMI path");
        let compiled = imported
            .compile(&CompilerOptions::default())
            .expect("imported fixture compiles");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral test catalog opens");
        catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "runtime-binding-test".to_owned(),
                },
            )
            .expect("validated fixture registers");
        let evidence = exact_evidence();
        let request = SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![evidence.clone()],
            controls: Vec::new(),
            limits: Default::default(),
        };
        let active =
            match resolve_active_semantic_models(&catalog, &request, &CancellationToken::default())
            {
                SemanticModelResolutionOutcome::Ready(active) => active,
                other => panic!("CSMI fixture did not activate: {other:#?}"),
            };
        (active, evidence)
    }

    fn test_snapshot() -> WorkspaceSnapshotId {
        WorkspaceSnapshotId {
            workspace_id: WorkspaceId::for_session(),
            lang: "python".to_owned(),
            generation: GenerationId::BOOTSTRAP,
            revision: 0,
        }
    }

    fn lookup(
        active: &ResolvedActiveSemanticModels,
        evidence: &SemanticModelActivationEvidence,
        name: &str,
    ) -> Result<PythonDefiningBinding, PythonRuntimeBindingError> {
        resolve_python_defining_binding(
            active,
            evidence,
            &["bs4".to_owned()],
            name,
            Path::new("src/caller.py"),
            &test_snapshot(),
            None,
        )
    }

    fn profile_parts(
        active: &ResolvedActiveSemanticModels,
    ) -> (PortableProfileEvidence, Vec<TypeFact>, Vec<MemberFact>) {
        for shard in active.shards() {
            let Some((types, members, _)) = shard.shard.payload().declaration_facts() else {
                continue;
            };
            let profile = types
                .iter()
                .map(|fact| &fact.locator)
                .chain(members.iter().map(|fact| &fact.locator))
                .find_map(|locator| match locator {
                    Locator::Interchange {
                        profile_evidence: Some(profile),
                        ..
                    } => Some(profile.as_ref()),
                    _ => None,
                });
            if let Some(profile) = profile {
                return (profile.clone(), types.to_vec(), members.to_vec());
            }
        }
        panic!("activated fixture has no profile carrier");
    }

    #[test]
    fn normal_fixture_definition_resolves_with_python_ecosystem_evidence() {
        let (active, evidence) = activate_fixture(|_| {});
        assert_eq!(evidence.language, "python");
        assert_eq!(evidence.ecosystem, "python");

        let binding = lookup(&active, &evidence, "parse")
            .expect("exact activated PyPI artifact resolves its definition edge");
        assert_eq!(binding.canonical(), &["bs4".to_owned(), "parse".to_owned()]);
        assert_eq!(binding.artifact().purl(), PURL);
        assert_eq!(binding.artifact().archive_sha256(), RAW_SHA256);
    }

    #[test]
    fn binding_conditions_require_matching_declared_inputs() {
        use crate::analyzer::semantic_model::csmi::{CsmiArtifactDigest, CsmiDigestAlgorithm};
        let digest = CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: "resolver-affecting-config".into(),
            canonicalization: Some(
                "https://brokk.ai/bifrost/python-declared-environment/v1".into(),
            ),
            value: "a".repeat(64),
        };
        let mut snapshot = PythonConditionSnapshot {
            implementation: Some("cpython".into()),
            project_config: Some(digest.clone()),
            ..PythonConditionSnapshot::default()
        };
        let condition = json!({"implementation":["cpython"], "projectConfig":digest});
        assert!(require_conditions(Some(&condition), Some(&snapshot)).is_ok());
        assert!(require_conditions(Some(&condition), None).is_err());
        snapshot
            .project_config
            .as_mut()
            .expect("config evidence")
            .value = "b".repeat(64);
        let mismatch = require_conditions(Some(&condition), Some(&snapshot)).unwrap_err();
        assert!(matches!(
            profile_resolution_error(mismatch),
            PythonRuntimeBindingError::Incompatible(_)
        ));
        let unsupported =
            require_conditions(Some(&json!({"platform":"linux"})), Some(&snapshot)).unwrap_err();
        assert!(
            matches!(profile_resolution_error(unsupported), PythonRuntimeBindingError::ConditionIncomplete(ref evaluations)
            if evaluations[0].status == PythonConditionStatus::Unsupported)
        );
        snapshot.project_config = None;
        let missing = require_conditions(Some(&condition), Some(&snapshot)).unwrap_err();
        assert!(matches!(
            profile_resolution_error(missing),
            PythonRuntimeBindingError::ConditionIncomplete(_)
        ));
    }

    #[test]
    fn declared_provider_requires_a_matching_model_project_config() {
        use crate::analyzer::semantic_model::csmi::{
            CsmiArtifactDigest, CsmiCompatibilityConstraint, CsmiDigestAlgorithm,
        };
        let (active, selected) = activate_fixture(|_| {});
        let (mut profile, types, members) = profile_parts(&active);
        let digest = CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: "resolver-affecting-config".into(),
            canonicalization: Some("https://example.test/declared-resolver-v1".into()),
            value: "a".repeat(64),
        };
        let mut environment = PythonConditionSnapshot {
            project_config: Some(digest.clone()),
            ..Default::default()
        };
        let resolve = |profile: &PortableProfileEvidence, environment: &PythonConditionSnapshot| {
            resolve_profile(
                profile,
                &types,
                &members,
                &selected,
                &["bs4".into()],
                "parse",
                Some(environment),
            )
        };
        assert!(
            matches!(profile_resolution_error(resolve(&profile, &environment).unwrap_err()),
            PythonRuntimeBindingError::ConditionIncomplete(ref evaluations)
            if evaluations[0].status == PythonConditionStatus::Indeterminate)
        );
        profile
            .compatibility_constraints
            .push(CsmiCompatibilityConstraint {
                vocabulary: PYTHON.into(),
                version: VERSION.into(),
                value: json!({"kind":"compatibility", "projectConfig":digest}),
            });
        assert!(
            resolve(&profile, &environment)
                .expect("matching declaration")
                .is_some()
        );
        environment
            .project_config
            .as_mut()
            .expect("config present")
            .value = "b".repeat(64);
        assert!(
            matches!(profile_resolution_error(resolve(&profile, &environment).unwrap_err()),
            PythonRuntimeBindingError::Incompatible(ref evaluations)
            if evaluations[0].status == PythonConditionStatus::Incompatible)
        );
        environment.project_config = None;
        assert!(
            matches!(profile_resolution_error(resolve(&profile, &environment).unwrap_err()),
            PythonRuntimeBindingError::ConditionIncomplete(ref evaluations)
            if evaluations[0].status == PythonConditionStatus::Indeterminate)
        );
    }

    #[test]
    fn alias_resolves_to_exact_defining_member_canonical_descriptors() {
        let (active, evidence) = activate_fixture(|semantic| {
            let bindings = semantic["semanticModels"][0]["extensionFacts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|fact| fact["family"] == "import-bindings")
                .unwrap()["payload"]["bindings"]
                .as_array_mut()
                .unwrap();
            bindings.push(json!({"name":"parse_alias", "bindingKind":"alias", "target":"parse"}));
        });
        let binding = lookup(&active, &evidence, "parse_alias")
            .expect("validated alias reaches a definition edge");
        assert_eq!(binding.canonical(), &["bs4".to_owned(), "parse".to_owned()]);
        assert_eq!(binding.formal_slots().len(), 1);
        assert_eq!(binding.formal_slots()[0].unique_name(), Some("value"));
        assert_eq!(binding.artifact().purl(), PURL);
        assert_eq!(binding.artifact().archive_sha256(), RAW_SHA256);
        assert_eq!(binding.touched_modules(), &["bs4".to_owned()]);
    }

    #[test]
    fn wrong_raw_digest_is_missing_model_before_profile_carrier_inspection() {
        let (active, evidence) = activate_fixture(|_| {});
        let mut wrong = evidence;
        wrong.artifact_sha256 = Some("b".repeat(64));
        assert!(matches!(
            lookup(&active, &wrong, "parse"),
            Err(PythonRuntimeBindingError::MissingModel(_))
        ));
    }

    #[test]
    fn conditional_edges_and_missing_completeness_are_incomplete() {
        let (active, evidence) = activate_fixture(|_| {});
        let (profile, types, members) = profile_parts(&active);
        let mut conditional = profile.clone();
        let fact = conditional
            .extension_facts
            .iter_mut()
            .find(|fact| fact.family == "import-bindings")
            .unwrap();
        fact.payload["bindings"][0]["conditions"] = json!({"platform":"win32"});
        let failure = resolve_profile(
            &conditional,
            &types,
            &members,
            &evidence,
            &["bs4".to_owned()],
            "parse",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            profile_resolution_error(failure),
            PythonRuntimeBindingError::ConditionIncomplete(_)
        ));

        let mut uncovered = profile;
        uncovered.completeness_statements.retain(|statement| {
            !(statement.family == "import-bindings" && statement.scope == json!({"module":"bs4"}))
        });
        let failure = resolve_profile(
            &uncovered,
            &types,
            &members,
            &evidence,
            &["bs4".to_owned()],
            "parse",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            profile_resolution_error(failure),
            PythonRuntimeBindingError::Incomplete(_)
        ));
    }

    #[test]
    fn callable_shape_coverage_and_provenance_are_required_for_definition() {
        let (active, evidence) = activate_fixture(|_| {});
        let (profile, types, members) = profile_parts(&active);
        let fails_incomplete = |members: &[MemberFact]| {
            let failure = resolve_profile(
                &profile,
                &types,
                members,
                &evidence,
                &["bs4".to_owned()],
                "parse",
                None,
            )
            .expect_err("callable without exact complete shape must not resolve");
            matches!(
                profile_resolution_error(failure),
                PythonRuntimeBindingError::Incomplete(_)
            )
        };

        let mut missing = members.clone();
        let callable = missing
            .iter_mut()
            .find(|member| member.name == "parse")
            .expect("fixture callable exists");
        let Locator::Interchange {
            callable_shape_evidence,
            ..
        } = &mut callable.locator
        else {
            panic!("fixture callable has an interchange locator");
        };
        *callable_shape_evidence = None;
        assert!(fails_incomplete(&missing));

        let mut explicit_provenance = members.clone();
        let callable = explicit_provenance
            .iter_mut()
            .find(|member| member.name == "parse")
            .expect("fixture callable exists");
        let Locator::Interchange {
            callable_shape_evidence: Some(shape),
            ..
        } = &mut callable.locator
        else {
            panic!("fixture callable has validated shape evidence");
        };
        shape.statement.provenance = vec![
            shape
                .default_provenance
                .take()
                .expect("fixture retains default callable-shape provenance"),
        ];
        shape.evidence_sha256 =
            crate::analyzer::semantic_model::csmi::python::callable_shape_evidence_digest(shape);
        assert!(
            resolve_profile(
                &profile,
                &types,
                &explicit_provenance,
                &evidence,
                &["bs4".to_owned()],
                "parse",
                None,
            )
            .expect("explicit exact-artifact provenance is supported")
            .is_some()
        );

        let mut partial = members.clone();
        let callable = partial
            .iter_mut()
            .find(|member| member.name == "parse")
            .expect("fixture callable exists");
        let Locator::Interchange {
            callable_shape_evidence: Some(shape),
            ..
        } = &mut callable.locator
        else {
            panic!("fixture callable has validated shape evidence");
        };
        shape.statement.status = crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Partial;
        shape.evidence_sha256 =
            crate::analyzer::semantic_model::csmi::python::callable_shape_evidence_digest(shape);
        assert!(fails_incomplete(&partial));

        let mut unproven = members.clone();
        let callable = unproven
            .iter_mut()
            .find(|member| member.name == "parse")
            .expect("fixture callable exists");
        let Locator::Interchange {
            callable_shape_evidence: Some(shape),
            ..
        } = &mut callable.locator
        else {
            panic!("fixture callable has validated shape evidence");
        };
        shape.statement.provenance.clear();
        shape.default_provenance = None;
        shape.provenance_records.clear();
        shape.evidence_sha256 =
            crate::analyzer::semantic_model::csmi::python::callable_shape_evidence_digest(shape);
        assert!(fails_incomplete(&unproven));

        let mut wrong_artifact = members.clone();
        let callable = wrong_artifact
            .iter_mut()
            .find(|member| member.name == "parse")
            .expect("fixture callable exists");
        let Locator::Interchange {
            callable_shape_evidence: Some(shape),
            ..
        } = &mut callable.locator
        else {
            panic!("fixture callable has validated shape evidence");
        };
        shape.provenance_records[0].inputs[0]
            .digest
            .as_mut()
            .expect("fixture provenance identifies an artifact")
            .value = "b".repeat(64);
        shape.evidence_sha256 =
            crate::analyzer::semantic_model::csmi::python::callable_shape_evidence_digest(shape);
        assert!(fails_incomplete(&wrong_artifact));

        let mut wrong_symbol = members.clone();
        let callable = wrong_symbol
            .iter_mut()
            .find(|member| member.name == "parse")
            .expect("fixture callable exists");
        let Locator::Interchange {
            callable_shape_evidence: Some(shape),
            ..
        } = &mut callable.locator
        else {
            panic!("fixture callable has validated shape evidence");
        };
        shape.statement.scope = json!({"symbol":"other","aspect":"callable-shape"});
        shape.evidence_sha256 =
            crate::analyzer::semantic_model::csmi::python::callable_shape_evidence_digest(shape);
        assert!(fails_incomplete(&wrong_symbol));
    }

    #[test]
    fn definitions_reached_through_distinct_modules_are_ambiguous() {
        let (active, evidence) = activate_fixture(|semantic| {
            let model = &mut semantic["semanticModels"][0];
            model["extensionFacts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|fact| fact["family"] == "import-bindings")
                .unwrap()["payload"]["bindings"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"parse", "bindingKind":"re-export", "target":"other"}));
            model["vocabularyUses"][0]["affects"]
                .as_array_mut()
                .unwrap()
                .push(json!({"kind":"fact-family", "family":"import-bindings", "scope":{"module":"other"}}));
            model["symbols"].as_array_mut().unwrap().extend([
                json!({"id":"other", "scheme":"csmi.python", "schemeVersion":"0.1.0", "stability":"portable", "descriptors":[{"role":"namespace", "name":"other"}]}),
                json!({"id":"other_parse", "scheme":"csmi.python", "schemeVersion":"0.1.0", "stability":"portable", "descriptors":[{"role":"namespace", "name":"other"}, {"role":"callable", "name":"parse"}]}),
            ]);
            model["declarations"].as_array_mut().unwrap().extend([
                json!({"symbol":"other", "category":"namespace"}),
                json!({"symbol":"other_parse", "category":"callable", "owner":"other", "callable":{"kind":"function", "parameters":[{"position":0, "binding":"positional-or-named", "label":"value", "required":true, "type":{"kind":"reference", "symbol":"Text"}}], "results":[{"position":0, "type":{"kind":"reference", "symbol":"Text"}}]}}),
            ]);
            model["extensionFacts"].as_array_mut().unwrap().extend([
                json!({"vocabulary":"csmi.python", "version":"0.1.0", "family":"import-bindings", "scope":{"module":"other"}, "payload":{"kind":"import-bindings", "bindings":[{"name":"parse", "bindingKind":"definition", "target":"other_parse"}]}, "provenance":["resolver"]}),
            ]);
            model["completenessStatements"].as_array_mut().unwrap().push(
                json!({"vocabulary":"csmi.python", "version":"0.1.0", "family":"import-bindings", "scope":{"module":"other"}, "status":"complete", "provenance":["resolver"]}),
            );
            model["completenessStatements"].as_array_mut().unwrap().push(
                json!({"family":"declaration-aspects", "scope":{"symbol":"other_parse", "aspect":"callable-shape"}, "status":"complete", "provenance":["resolver"]}),
            );
            model["extensionFacts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|fact| fact["family"] == "distribution-imports")
                .unwrap()["payload"]["importRoots"]
                .as_array_mut()
                .unwrap()
                .push(json!(["other"]));
        });
        let resolution = lookup(&active, &evidence, "parse");
        assert!(
            matches!(resolution, Err(PythonRuntimeBindingError::Ambiguous(_))),
            "two valid distinct defining declarations must remain ambiguous: {resolution:?}"
        );
    }

    #[test]
    fn bounded_binding_walk_failure_remains_incomplete() {
        assert!(matches!(
            profile_resolution_error("import binding traversal exceeded bound".to_owned()),
            PythonRuntimeBindingError::Incomplete(_)
        ));
    }
}
