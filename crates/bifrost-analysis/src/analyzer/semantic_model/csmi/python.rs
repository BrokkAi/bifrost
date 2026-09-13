//! Exact Python runtime declaration identities at the interchange boundary.
//!
//! A portable key is retained with the native declaration. Its descriptor
//! roles, artifact selector, and digest are evidence; display names and native
//! declaration handles are not substitutes for that evidence.

use super::model::*;
use crate::analyzer::semantic_model::TypeRef;

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
    validate_runtime_artifact(artifact)?;
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

pub(crate) fn validate_model(model: &CsmiSemanticModel) -> Result<(), String> {
    let [artifact] = model.artifact_selectors.as_slice() else {
        return Err("Python runtime model requires one exact artifact selector".to_owned());
    };
    validate_runtime_artifact(artifact)?;
    if !model.compatibility_constraints.is_empty()
        || !model.extensions.is_empty()
        || !model.consumer_resolved_dependencies.is_empty()
    {
        return Err("Python environment constraints, model extensions, or external correspondence require additional consumer evidence".to_owned());
    }
    let mut identity_uses = std::collections::HashSet::new();
    let mut artifact_use = false;
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
            let CsmiAffectedUnit::CoreSlot(slot) = affected else {
                return Err("Python binding and correspondence families are not supported by the runtime identity adapter".to_owned());
            };
            if slot.slot == "artifact-compatibility"
                && slot.target == serde_json::json!({"semanticModel": "current"})
            {
                artifact_use = true;
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
    if !artifact_use
        || model
            .symbols
            .iter()
            .any(|symbol| !identity_uses.contains(symbol.id.as_str()))
        || model
            .extension_facts
            .iter()
            .any(|fact| fact.vocabulary == CSMI_PYTHON_PROFILE_ID)
        || model
            .completeness_statements
            .iter()
            .any(|statement| statement.vocabulary.as_deref() == Some(CSMI_PYTHON_PROFILE_ID))
    {
        return Err("Python runtime identity requires its declared identity scope and cannot discard binding/correspondence facts".to_owned());
    }
    for symbol in &model.symbols {
        let identity = identity_from_symbol(symbol, &model.artifact_selectors)?;
        if identity.artifact_selectors != model.artifact_selectors {
            return Err(
                "cross-artifact Python declarations require explicit correspondence support"
                    .to_owned(),
            );
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
            let Locator::Interchange { identity, .. } = &fact.locator else {
                continue;
            };
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
            let Locator::Interchange { identity, .. } = &fact.locator else {
                continue;
            };
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
    validate_runtime_artifact(&selector).map_err(CsmiExportError::InvalidEvidence)?;
    let mut types = Vec::new();
    let mut members = Vec::new();
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
            activation
                .package
                .as_ref()
                .is_none_or(|package| package.name != selector.purl || package.version.is_some())
                || activation.artifact_sha256.as_deref() != Some(artifact.sha256.as_str())
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
            CompiledPayload::ProcedureSummaries { summaries } if summaries.is_empty() => {}
            _ => {
                return Err(unsupported(
                    "Python export cannot discard unsupported declarations, relations, generators, or procedure summaries",
                ));
            }
        }
    }
    let mut keys = HashMap::new();
    let mut symbol_ids = HashMap::new();
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
        let Locator::Interchange { identity, .. } = locator else {
            return Err(unsupported(
                "Python declaration has no retained portable identity; display names cannot supply one",
            ));
        };
        validate_identity(identity).map_err(CsmiExportError::Identity)?;
        if identity.artifact_selectors.as_slice() != std::slice::from_ref(&selector) {
            return Err(unsupported(
                "export artifact disagrees with a retained Python declaration identity",
            ));
        }
        let symbol_id = native_id(identity);
        if !occupied_symbols.insert(symbol_id.clone()) {
            return Err(unsupported(
                "multiple native declarations claim one Python runtime identity",
            ));
        }
        symbol_ids.insert(id.clone(), symbol_id.clone());
        keys.insert(id.as_str(), identity);
        identity_affects.push(CsmiAffectedUnit::CoreSlot(CsmiAffectedCoreSlot {
            kind: CsmiAffectedCoreSlotKind::CoreSlot,
            slot: "symbol-identity-scheme".to_owned(),
            target: json!({"symbol":symbol_id}),
        }));
        symbols.push(CsmiSymbolDefinition {
            id: symbol_id,
            artifact_selectors: None,
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
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    let mut names = HashMap::new();
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
            && names.insert(fact.name.clone(), fact.id.clone()).is_some()
        {
            return Err(unsupported("ambiguous Python type reference name"));
        }
        let mut owner_key = keys[&fact.id.as_str()].clone();
        owner_key.descriptors.pop();
        let owner = (!owner_key.descriptors.is_empty())
            .then(|| native_id(&owner_key))
            .filter(|id| occupied_symbols.contains(id));
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
        let complete =
            member.callable_family_complete || manifest.completeness == Completeness::Complete;
        shapes.insert(member.id.clone(), complete);
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
        limitations: Vec::new(),
        provenance: vec![options.provenance_id.clone()],
        extensions: Vec::new(),
    }];
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
    let mut uses = vec![CsmiVocabularyUse {
        identifier: CSMI_PYTHON_PROFILE_ID.to_owned(),
        version: CSMI_PYTHON_PROFILE_VERSION.to_owned(),
        schema: CSMI_PYTHON_PROFILE_SCHEMA.to_owned(),
        requirement: CsmiVocabularyRequirement::Required,
        affects: identity_affects,
    }];
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
        compatibility_constraints: Vec::new(),
        vocabulary_uses: uses,
        consumer_resolved_dependencies: Vec::new(),
        symbols,
        declarations,
        relationships: Vec::new(),
        procedure_summaries: Vec::new(),
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
    let mut provenance_records = vec![record.clone()];
    provenance_records.extend(provenance_ids.into_iter().map(|id| {
        let mut retained = record.clone();
        retained.id = id;
        retained
    }));
    let document = CsmiSemanticDocument {
        document_type: "semantic-document".to_owned(),
        schema: CSMI_SCHEMA_URI.to_owned(),
        semantic_model_version: CSMI_SEMANTIC_MODEL_VERSION.to_owned(),
        serialization_version: CSMI_SERIALIZATION_VERSION.to_owned(),
        provenance_records,
        default_provenance: Some(options.provenance_id.clone()),
        semantic_models: vec![model],
    };
    Ok((document, record))
}
