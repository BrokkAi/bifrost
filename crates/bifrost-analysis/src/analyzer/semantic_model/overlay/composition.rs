//! Activation-local composition of artifact structure and curated semantics.

use super::*;
pub use crate::analyzer::store::semantic_composition::{
    ComposedGroup, CompositionGroupKey, RepresentativeIdentity, SemanticModelCompositionDiagnostic,
};
mod rows;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::CatalogError;
pub use rows::RowCompositionReads;
type ReadResult<T> = Result<T, CatalogError>;

use crate::analyzer::semantic_model::{
    ActivatedSemanticModelRecord, CompiledProcedureSummary, ProcedureSummaryMemberKey,
};

/// Reads outside one alias group. The decoded and catalog implementations
/// apply the same selection rules before returning records.
pub trait CompositionReads {
    fn all_type_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>>;
    fn types_with_id(&self, id: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>>;
    fn types_named(&self, name: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>>;
    fn all_member_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>>;
    fn members_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>>;
    fn procedure_summaries_for_member(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> ReadResult<Vec<Arc<CompiledProcedureSummary>>>;
}

struct DecodedCompositionReads<'a> {
    active: &'a ResolvedActiveSemanticModels,
}
impl CompositionReads for DecodedCompositionReads<'_> {
    fn all_type_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(self.active.all_type_records_with_id(id).collect())
    }
    fn types_with_id(&self, id: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(self.active.types_with_id(id).records)
    }
    fn types_named(&self, name: &str) -> ReadResult<Vec<ActivatedSemanticModelRecord<TypeFact>>> {
        Ok(self.active.types_named(name).records)
    }
    fn all_member_records_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        Ok(self.active.all_member_records_with_id(id).collect())
    }
    fn members_with_id(
        &self,
        id: &str,
    ) -> ReadResult<Vec<ActivatedSemanticModelRecord<MemberFact>>> {
        Ok(self.active.members_with_id(id).records)
    }
    fn procedure_summaries_for_member(
        &self,
        key: ProcedureSummaryMemberKey<'_>,
    ) -> ReadResult<Vec<Arc<CompiledProcedureSummary>>> {
        Ok(self
            .active
            .procedure_summaries_for_member(key)
            .records
            .into_iter()
            .map(|r| r.record)
            .collect())
    }
}

/// Derive endpoint identity from owners alone. No member or relation is composed.
pub fn representative_identity(
    owners: &[&SemanticModelSymbol],
    active: &impl CompositionReads,
) -> ReadResult<RepresentativeIdentity> {
    let mut result = RepresentativeIdentity {
        representative_id: None,
        replacements: Vec::new(),
        composed: false,
        disagreement: false,
    };
    let artifacts = owners
        .iter()
        .copied()
        .filter(|s| s.provenance.extraction.is_some())
        .collect::<Vec<_>>();
    let Some(first_symbol) = artifacts.first() else {
        return Ok(result);
    };
    if owners.len() == 1 {
        return Ok(result);
    }
    let mut scopes = HashSet::default();
    if artifacts.iter().all(|s| {
        s.provenance
            .activation
            .matched_evidence
            .artifact_sha256
            .as_deref()
            .is_some_and(|digest| {
                scopes.insert(digest);
                true
            })
    }) && scopes.len() > 1
    {
        return Ok(result);
    }
    let first = active
        .all_type_records_with_id(&first_symbol.id)?
        .into_iter()
        .find(|r| r.shard.manifest.semantic_sha256 == first_symbol.provenance.pack_digest)
        .expect("overlay owner comes from an active type");
    for symbol in &artifacts {
        result.disagreement |= active
            .all_type_records_with_id(&symbol.id)?
            .iter()
            .any(|other| {
                other.shard.manifest.extraction.is_some()
                    && !owner_structure_agrees(&first.record, &other.record)
            });
    }
    if result.disagreement {
        return Ok(result);
    }
    result.composed = true;
    result.representative_id = Some(first_symbol.id.clone());
    result.replacements = owners
        .iter()
        .filter(|s| !std::ptr::eq(**s, *first_symbol))
        .map(|s| (s.id.clone(), first_symbol.id.clone()))
        .collect();
    Ok(result)
}

fn finish(
    mut symbols: Vec<SemanticModelSymbol>,
    relations: Vec<(usize, SemanticModelRelation)>,
    removed: HashSet<usize>,
    mut diagnostics: Vec<SemanticModelCompositionDiagnostic>,
    representative: RepresentativeIdentity,
) -> ComposedGroup {
    let source_indices = (0..symbols.len())
        .filter(|i| !removed.contains(i))
        .collect();
    let mut index = 0;
    symbols.retain(|_| {
        let keep = !removed.contains(&index);
        index += 1;
        keep
    });
    normalize_diagnostics(&mut diagnostics);
    ComposedGroup {
        symbols,
        source_indices,
        relations,
        diagnostics,
        representative,
    }
}

#[derive(Debug, Clone)]
pub(super) struct OriginIdentity {
    replacement: Option<String>,
    composed: bool,
}

// Raw IDs are pack-local. Only relation origins use publication qualification;
// external endpoint resolution keeps its existing identity rules.
pub(super) type OriginRewrites = HashMap<String, HashMap<String, OriginIdentity>>;

pub(super) fn record_origin_identities(
    origins: &mut OriginRewrites,
    owners: &[&SemanticModelSymbol],
    identity: &RepresentativeIdentity,
) {
    for owner in owners {
        origins
            .entry(owner.provenance.pack_digest.clone())
            .or_default()
            .insert(
                owner.id.clone(),
                OriginIdentity {
                    replacement: identity
                        .replacements
                        .iter()
                        .rev()
                        .find(|(id, _)| id == &owner.id)
                        .map(|(_, replacement)| replacement.clone()),
                    composed: identity.composed,
                },
            );
    }
}

/// Compose one alias group in pre-composition source order. Provenance travels
/// with each owner, member and relation. Outside reads never inspect another
/// group's composed members.
pub(super) fn compose(
    mut symbols: Vec<SemanticModelSymbol>,
    relations: Vec<(usize, SemanticModelRelation)>,
    active: &impl CompositionReads,
    representatives: &HashMap<String, String>,
    composed_owners: &HashSet<String>,
    origin_identities: &OriginRewrites,
) -> ReadResult<ComposedGroup> {
    let group = symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.owner_id.is_none())
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    let representative = representative_identity(
        &group.iter().map(|&i| &symbols[i]).collect::<Vec<_>>(),
        active,
    )?;
    let mut members_by_owner = HashMap::<String, Vec<usize>>::default();
    for (index, symbol) in symbols.iter().enumerate() {
        if let Some(owner) = &symbol.owner_id {
            members_by_owner
                .entry(owner.clone())
                .or_default()
                .push(index);
        }
    }
    let mut removed = HashSet::default();
    let mut diagnostics = Vec::new();
    let artifacts = group
        .iter()
        .copied()
        .filter(|index| symbols[*index].provenance.extraction.is_some())
        .collect::<Vec<_>>();
    let Some(&selected) = artifacts.first() else {
        return Ok(finish(
            symbols,
            rewrite_relations(
                relations,
                representatives,
                composed_owners,
                origin_identities,
            ),
            removed,
            diagnostics,
            representative,
        ));
    };
    if group.len() == 1 {
        return Ok(finish(
            symbols,
            rewrite_relations(
                relations,
                representatives,
                composed_owners,
                origin_identities,
            ),
            removed,
            diagnostics,
            representative,
        ));
    }
    // #6542: exact artifact facets are selected by the caller. Two
    // source-bound JDKs (or other exact artifacts) can share an owner name
    // while applying to different source modules. Retain those facets;
    // unscoped lookup stays Conflict and exact lookup can select its own
    // artifact. Activation-wide composition must not erase that selection.
    if !representative.composed {
        if representative.disagreement {
            for &index in &group {
                symbols[index].provenance.ambiguous = true;
            }
        }
        return Ok(finish(
            symbols,
            rewrite_relations(
                relations,
                representatives,
                composed_owners,
                origin_identities,
            ),
            removed,
            diagnostics,
            representative,
        ));
    }
    let artifact = &symbols[selected];
    let first = active
        .all_type_records_with_id(&artifact.id)?
        .into_iter()
        .find(|r| r.shard.manifest.semantic_sha256 == artifact.provenance.pack_digest)
        .expect("overlay owner comes from an active type");
    symbols[selected].provenance.ambiguous = false;
    let representative_id = symbols[selected].id.clone();
    for &index in &group {
        if symbols[index].provenance.extraction.is_some() {
            continue;
        }
        let curated = symbols[index].clone();
        let matched = active.types_with_id(&curated.id)?;
        if let Some(record) = matched
            .iter()
            .find(|r| r.shard.manifest.semantic_sha256 == curated.provenance.pack_digest)
        {
            let curated_owner = &record.record;
            let artifact_owner = &first.record;
            for (field, disagrees) in [
                (
                    "type_kind",
                    curated_owner.type_kind != artifact_owner.type_kind,
                ),
                (
                    "type_parameters",
                    !curated_owner.type_parameters.is_empty()
                        && curated_owner.type_parameters != artifact_owner.type_parameters,
                ),
                (
                    "type_parameter_defaults",
                    !curated_owner.type_parameter_defaults.is_empty()
                        && curated_owner.type_parameter_defaults
                            != artifact_owner.type_parameter_defaults,
                ),
                (
                    "hierarchy",
                    !curated_owner.hierarchy.is_empty()
                        && curated_owner.hierarchy != artifact_owner.hierarchy,
                ),
                (
                    "implemented_traits",
                    !curated_owner.implemented_traits.is_empty()
                        && curated_owner.implemented_traits != artifact_owner.implemented_traits,
                ),
                (
                    "generic_trait_impls",
                    !curated_owner.generic_trait_impls.is_empty()
                        && curated_owner.generic_trait_impls != artifact_owner.generic_trait_impls,
                ),
            ] {
                if disagrees {
                    diagnostic(&mut diagnostics, &curated, &representative_id, field);
                }
            }
        }
        fill_semantics(&mut symbols[selected], &curated);
    }

    let mut aliases = symbols[selected].aliases.clone();
    let mut contributors = Vec::new();
    for &index in &group {
        if index == selected {
            continue;
        }
        let symbol = &symbols[index];
        aliases.push(symbol.qualified_name.clone());
        aliases.extend(symbol.aliases.iter().cloned());
        contributors.push(symbol.provenance.clone());
        removed.insert(index);
    }
    aliases.sort();
    aliases.dedup();
    symbols[selected].aliases = aliases;
    symbols[selected].semantic_contributors.extend(contributors);
    // Every member in the identity group is now in one family namespace.
    let owner_ids = group
        .iter()
        .map(|index| symbols[*index].id.clone())
        .collect::<HashSet<_>>();
    let mut members = owner_ids
        .iter()
        .flat_map(|owner| members_by_owner.get(owner).into_iter().flatten().copied())
        .collect::<Vec<_>>();
    members.sort_unstable();
    members.dedup();
    // Static form is the shared callable receiver form. Free functions
    // have no receiver regardless of a producer's redundant is_static bit.
    // A curated static method can describe an extracted module function:
    // kind is an authoritative structural field, not correspondence (#6542).
    let mut artifact_families = HashMap::<(String, bool, bool), Vec<usize>>::default();
    for &index in &members {
        if symbols[index].provenance.extraction.is_some() {
            let m = &symbols[index];
            artifact_families
                .entry((m.name.clone(), m.has_receiver(), member_is_callable(m)))
                .or_default()
                .push(index);
        }
    }
    for &index in &members {
        symbols[index].owner_id = Some(representative_id.clone());
        let canonical_name = format!(
            "{}.{}",
            symbols[selected].qualified_name, symbols[index].name
        );
        if symbols[index].qualified_name != canonical_name {
            let previous = std::mem::replace(&mut symbols[index].qualified_name, canonical_name);
            symbols[index].aliases.push(previous);
        }
        if symbols[index].provenance.extraction.is_some() {
            // #6542: a curated stub can reuse the artifact's local ID.
            // Its structural disagreement is resolved by composition;
            // disagreement between artifact records must remain visible.
            let mut artifacts = active
                .all_member_records_with_id(&symbols[index].id)?
                .into_iter()
                .filter(|r| r.shard.manifest.extraction.is_some());
            if let Some(first) = artifacts.next() {
                symbols[index].provenance.ambiguous = !owner_ids.contains(&first.record.owner)
                    || artifacts.any(|other| {
                        !owner_ids.contains(&other.record.owner)
                            || !member_declarations_agree(&first.record, &other.record)
                    });
            }
            continue;
        }
        let curated = symbols[index].clone();
        let candidates = artifact_families
            .get(&(
                curated.name.clone(),
                curated.has_receiver(),
                member_is_callable(&curated),
            ))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut corresponding = Vec::new();
        for &candidate in candidates {
            if member_corresponds(&curated, &symbols[candidate], active)? {
                corresponding.push(candidate);
            }
        }
        if corresponding.is_empty() {
            // #6542: owner-present unmatched members are data errors,
            // including missing names/static forms/arity, not silent gaps.
            diagnostic(
                &mut diagnostics,
                &curated,
                &representative_id,
                "signature.parameters",
            );
            continue;
        }
        for &artifact_index in &corresponding {
            let artifact = &mut symbols[artifact_index];
            structural_diagnostics(&curated, artifact, active, &mut diagnostics)?;
            fill_semantics(artifact, &curated);
            artifact
                .semantic_contributors
                .push(curated.provenance.clone());
            artifact.aliases.extend(curated.aliases.iter().cloned());
            artifact.aliases.push(curated.qualified_name.clone());
            artifact.aliases.sort();
            artifact.aliases.dedup();
        }
        check_flow_agreement(
            &symbols[selected].qualified_name,
            &curated,
            &corresponding,
            &symbols,
            active,
            &mut diagnostics,
        )?;
        removed.insert(index);
    }
    Ok(finish(
        symbols,
        rewrite_relations(
            relations,
            representatives,
            composed_owners,
            origin_identities,
        ),
        removed,
        diagnostics,
        representative,
    ))
}

pub(super) fn rewrite_relations(
    mut relations: Vec<(usize, SemanticModelRelation)>,
    representatives: &HashMap<String, String>,
    composed_owners: &HashSet<String>,
    origin_identities: &OriginRewrites,
) -> Vec<(usize, SemanticModelRelation)> {
    let origin = |relation: &SemanticModelRelation| {
        origin_identities
            .get(&relation.provenance.pack_digest)
            .and_then(|ids| ids.get(&relation.from))
    };
    let from_replacement = |relation: &SemanticModelRelation| match origin(relation) {
        Some(origin) => origin.replacement.as_ref(),
        None => representatives.get(&relation.from),
    };
    // Curated hierarchy never overrides the authoritative owner's hierarchy.
    relations.retain(|(_, relation)| {
        relation.provenance.extraction.is_some()
            || from_replacement(relation).is_none()
            || !matches!(
                relation.kind.as_str(),
                "extends"
                    | "implements"
                    | "uses_trait"
                    | "mixin_include"
                    | "mixin_prepend"
                    | "mixin_extend"
            )
    });
    for (_, relation) in &mut relations {
        if relation.provenance.extraction.is_some()
            && origin(relation).map_or_else(
                || composed_owners.contains(&relation.from),
                |origin| origin.composed,
            )
            && matches!(
                relation.kind.as_str(),
                "extends"
                    | "implements"
                    | "uses_trait"
                    | "mixin_include"
                    | "mixin_prepend"
                    | "mixin_extend"
            )
        {
            relation.provenance.ambiguous = false;
        }
        if let Some(replacement) = from_replacement(relation) {
            relation.from.clone_from(replacement);
        }
        if let Some(replacement) = representatives.get(&relation.to) {
            relation.to.clone_from(replacement);
        }
    }
    relations
}

pub(super) fn normalize_diagnostics<
    T: std::borrow::Borrow<SemanticModelCompositionDiagnostic> + PartialEq,
>(
    diagnostics: &mut Vec<T>,
) {
    diagnostics.sort_by(|a, b| {
        let a = a.borrow();
        let b = b.borrow();
        (
            &a.pack_id,
            &a.declaration_id,
            &a.artifact_id,
            &a.conflicting_artifact_id,
            a.field,
        )
            .cmp(&(
                &b.pack_id,
                &b.declaration_id,
                &b.artifact_id,
                &b.conflicting_artifact_id,
                b.field,
            ))
    });
    diagnostics.dedup();
}

fn root(parents: &[usize], mut index: usize) -> usize {
    while parents[index] != index {
        index = parents[index];
    }
    index
}

fn owner_structure_agrees(left: &TypeFact, right: &TypeFact) -> bool {
    let mut normalized = left.clone();
    // Identity spellings, navigation and semantic roles are not structure.
    normalized.id.clone_from(&right.id);
    normalized.name.clone_from(&right.name);
    normalized.aliases.clone_from(&right.aliases);
    normalized.locator.clone_from(&right.locator);
    normalized
        .value_semantics
        .clone_from(&right.value_semantics);
    normalized.ambient_use = right.ambient_use;
    normalized.guard.clone_from(&right.guard);
    normalized == *right
}

fn member_declarations_agree(left: &MemberFact, right: &MemberFact) -> bool {
    let mut normalized = left.clone();
    normalized.owner.clone_from(&right.owner);
    normalized.aliases.clone_from(&right.aliases);
    normalized.locator.clone_from(&right.locator);
    normalized.guard.clone_from(&right.guard);
    normalized == *right
}

fn untyped(ty: &TypeRef) -> bool {
    matches!(ty, TypeRef::Unknown | TypeRef::TypeParameter { .. })
        || matches!(ty, TypeRef::Named { name, .. } if name == "untyped")
}

/// Compare structured type trees iteratively. Canonical identities and aliases
/// are resolved through active type records; source text is never consulted.
fn compatible(
    curated: &TypeRef,
    artifact: &TypeRef,
    active: &impl CompositionReads,
) -> ReadResult<bool> {
    let mut pending = vec![(curated, artifact)];
    while let Some((curated, artifact)) = pending.pop() {
        if untyped(curated) {
            continue;
        }
        if curated == artifact {
            continue;
        }
        match (curated, artifact) {
            (
                TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                },
                TypeRef::Declared {
                    id,
                    arguments: other,
                    nullable: other_nullable,
                },
            )
            | (
                TypeRef::Declared {
                    id,
                    arguments: other,
                    nullable: other_nullable,
                },
                TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                },
            ) => {
                if nullable != other_nullable
                    || arguments.len() != other.len()
                    || !active
                        .types_with_id(id)?
                        .iter()
                        .any(|r| r.record.name == *name || r.record.aliases.contains(name))
                {
                    return Ok(false);
                }
                pending.extend(arguments.iter().zip(other));
            }
            (
                TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                },
                TypeRef::Named {
                    name: other_name,
                    arguments: other,
                    nullable: other_nullable,
                },
            ) => {
                if nullable != other_nullable
                    || arguments.len() != other.len()
                    || (name != other_name
                        && !active.types_named(name)?.iter().any(|r| {
                            r.record.name == *other_name || r.record.aliases.contains(other_name)
                        }))
                {
                    return Ok(false);
                }
                pending.extend(arguments.iter().zip(other));
            }
            (
                TypeRef::ByRef {
                    element,
                    reference_kind,
                },
                TypeRef::ByRef {
                    element: other,
                    reference_kind: other_kind,
                },
            ) if reference_kind == other_kind => pending.push((element, other)),
            (TypeRef::Array { element }, TypeRef::Array { element: other })
            | (TypeRef::Slice { element }, TypeRef::Slice { element: other })
            | (TypeRef::Pointer { element }, TypeRef::Pointer { element: other }) => {
                pending.push((element, other))
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn member_corresponds(
    curated: &SemanticModelSymbol,
    artifact: &SemanticModelSymbol,
    active: &impl CompositionReads,
) -> ReadResult<bool> {
    if let Some(a) = &curated.extension_receiver {
        let Some(b) = &artifact.extension_receiver else {
            return Ok(false);
        };
        if !compatible(a, b, active)? {
            return Ok(false);
        }
    }
    match (
        &curated.structured_signature,
        &artifact.structured_signature,
    ) {
        (Some(a), Some(b)) => {
            if a.parameters.len() != b.parameters.len() {
                return Ok(false);
            }
            for (a, b) in a.parameters.iter().zip(&b.parameters) {
                if !compatible(&a.r#type, &b.r#type, active)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (None, None) => Ok(curated.receiver == artifact.receiver),
        _ => Ok(false),
    }
}

fn diagnostic(
    out: &mut Vec<SemanticModelCompositionDiagnostic>,
    curated: &SemanticModelSymbol,
    artifact_id: &str,
    field: &'static str,
) {
    out.push(SemanticModelCompositionDiagnostic {
        pack_id: curated.provenance.pack_id.clone(),
        declaration_id: curated.id.clone(),
        artifact_id: artifact_id.to_owned(),
        conflicting_artifact_id: None,
        field,
    });
}

fn structural_diagnostics(
    curated: &SemanticModelSymbol,
    artifact: &SemanticModelSymbol,
    active: &impl CompositionReads,
    out: &mut Vec<SemanticModelCompositionDiagnostic>,
) -> ReadResult<()> {
    let curated_records = active.members_with_id(&curated.id)?;
    let artifact_record = active
        .all_member_records_with_id(&artifact.id)?
        .into_iter()
        .find(|r| r.shard.manifest.semantic_sha256 == artifact.provenance.pack_digest);
    if let (Some(curated_record), Some(artifact_record)) = (
        curated_records
            .iter()
            .find(|r| r.shard.manifest.semantic_sha256 == curated.provenance.pack_digest),
        artifact_record,
    ) {
        for (field, disagrees) in [
            ("member_kind", curated.kind != artifact.kind),
            (
                "self_form",
                curated_record.record.self_form.as_ref().is_some_and(|a| {
                    artifact_record
                        .record
                        .self_form
                        .as_ref()
                        .is_some_and(|b| a != b)
                }),
            ),
            (
                "implemented_trait",
                match (
                    &curated_record.record.implemented_trait,
                    &artifact_record.record.implemented_trait,
                ) {
                    (Some(a), Some(b)) => !compatible(a, b, active)?,
                    _ => false,
                },
            ),
        ] {
            if disagrees {
                diagnostic(out, curated, &artifact.id, field);
            }
        }
    }
    for (field, disagrees) in [
        (
            "receiver",
            curated.receiver.is_some() && curated.receiver != artifact.receiver,
        ),
        ("visibility", curated.visibility != artifact.visibility),
        (
            "is_abstract",
            curated.declaration_is_abstract != artifact.declaration_is_abstract,
        ),
        (
            "extension_receiver",
            match (&curated.extension_receiver, &artifact.extension_receiver) {
                (Some(a), Some(b)) => !compatible(a, b, active)?,
                (Some(_), None) => true,
                _ => false,
            },
        ),
    ] {
        if disagrees {
            diagnostic(out, curated, &artifact.id, field);
        }
    }
    if let (Some(a), Some(b)) = (
        &curated.structured_signature,
        &artifact.structured_signature,
    ) {
        if a.parameters.iter().zip(&b.parameters).any(|(a, b)| {
            a.optional != b.optional || a.variadic != b.variadic || a.passing_mode != b.passing_mode
        }) {
            diagnostic(out, curated, &artifact.id, "signature.parameters");
        }
        let returns_disagree = match (&a.returns, &b.returns) {
            (Some(a), Some(b)) => !compatible(a, b, active)?,
            (Some(_), None) => true,
            _ => false,
        };
        if returns_disagree {
            diagnostic(out, curated, &artifact.id, "signature.returns");
        }
    }
    Ok(())
}

fn fill_semantics(artifact: &mut SemanticModelSymbol, curated: &SemanticModelSymbol) {
    if let (Some(target), Some(source)) = (
        &mut artifact.structured_signature,
        &curated.structured_signature,
    ) {
        for (target, source) in target.parameters.iter_mut().zip(&source.parameters) {
            if source.role.is_some() {
                target.role = source.role;
            }
        }
    }
    if !curated.exact_return_classes.is_empty() {
        artifact
            .exact_return_classes
            .clone_from(&curated.exact_return_classes);
    }
    if curated.implicit_operation.is_some() {
        artifact
            .implicit_operation
            .clone_from(&curated.implicit_operation);
    }
    if curated.explicit_operation.is_some() {
        artifact.explicit_operation = curated.explicit_operation;
    }
    if curated.ambient_use.is_some() {
        artifact.ambient_use = curated.ambient_use;
    }
    if curated.proxied_type.is_some() {
        artifact.proxied_type.clone_from(&curated.proxied_type);
    }
    if curated.value_semantics.is_some() {
        artifact
            .value_semantics
            .clone_from(&curated.value_semantics);
    }
}

/// #6542: the flow binder collapses overloads to owner/name/receiver/arity.
/// Check its exact claim predicate here instead of silently allowing an
/// annotation to become an unusable flow summary after composition.
fn check_flow_agreement(
    owner: &str,
    curated: &SemanticModelSymbol,
    corresponding: &[usize],
    symbols: &[SemanticModelSymbol],
    active: &impl CompositionReads,
    diagnostics: &mut Vec<SemanticModelCompositionDiagnostic>,
) -> ReadResult<()> {
    use crate::analyzer::semantic_model::{ProcedureSummaryMemberKey, compiled_flow_claims_agree};
    let mut first: Option<(
        &str,
        std::sync::Arc<crate::analyzer::semantic_model::CompiledProcedureSummary>,
    )> = None;
    for &index in corresponding {
        let symbol = &symbols[index];
        let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
            &symbol.language,
            owner,
            &symbol.name,
            symbol.has_receiver(),
            symbol.structured_signature.as_ref().map_or(0, |s| {
                u32::try_from(s.parameters.len()).expect("validated arity fits u32")
            }),
        ))?;
        for record in matched {
            if let Some((first_id, first_record)) = &first {
                if !compiled_flow_claims_agree(first_record, &record) {
                    diagnostics.push(SemanticModelCompositionDiagnostic {
                        pack_id: curated.provenance.pack_id.clone(),
                        declaration_id: curated.id.clone(),
                        artifact_id: (*first_id).to_owned(),
                        conflicting_artifact_id: Some(symbol.id.clone()),
                        field: "compiled_flow_claims_agree",
                    });
                }
            } else {
                first = Some((symbol.id.as_str(), record));
            }
        }
    }
    Ok(())
}

/// Close owner identities without requiring declaration payloads. IDs are
/// facet addresses supplied by the caller, never pack-local record identities.
pub(super) fn identity_groups<'a>(
    count: usize,
    identities: impl IntoIterator<Item = (usize, &'a str, bool, &'a str)>,
    cancellation: Option<&crate::CancellationToken>,
) -> Option<Vec<Vec<usize>>> {
    let mut parents = (0..count).collect::<Vec<_>>();
    let mut first = HashMap::default();
    let mut present = HashSet::default();
    for (index, language, module, spelling) in identities {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return None;
        }
        present.insert(index);
        if let Some(previous) = first.insert((language, module, spelling), index) {
            let previous = root(&parents, previous);
            let current = root(&parents, index);
            parents[current] = previous;
        }
    }
    let mut groups = HashMap::<usize, Vec<usize>>::default();
    for index in (0..count).filter(|index| present.contains(index)) {
        groups.entry(root(&parents, index)).or_default().push(index);
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by_key(|group| group[0]);
    Some(groups)
}

fn alias_groups(
    symbols: &[SemanticModelSymbol],
    cancellation: &crate::CancellationToken,
) -> Result<Vec<Vec<usize>>, SemanticModelOverlayBuildError> {
    identity_groups(
        symbols.len(),
        symbols
            .iter()
            .enumerate()
            .filter(|(_, symbol)| symbol.owner_id.is_none())
            .flat_map(|(index, symbol)| {
                std::iter::once(&symbol.qualified_name)
                    .chain(&symbol.aliases)
                    .map(move |identity| {
                        (
                            index,
                            symbol.language.as_str(),
                            symbol.kind == SemanticModelSymbolKind::Module,
                            identity.as_str(),
                        )
                    })
            }),
        Some(cancellation),
    )
    .ok_or(SemanticModelOverlayBuildError::Cancelled)
}

pub fn group_key(owners: &[&SemanticModelSymbol]) -> CompositionGroupKey {
    let first = owners.first().expect("an alias group contains an owner");
    CompositionGroupKey {
        language: first.language.clone(),
        module_namespace: first.kind == SemanticModelSymbolKind::Module,
        identity: owners
            .iter()
            .flat_map(|s| std::iter::once(&s.qualified_name).chain(&s.aliases))
            .min()
            .expect("owner has canonical spelling")
            .clone(),
    }
}

/// Eager publication keeps whole-set identity conflict marking and the original
/// source order. Only the composition kernel is group-local.
pub(super) fn compose_eager(
    symbols: &mut Vec<SemanticModelSymbol>,
    relations: &mut Vec<SemanticModelRelation>,
    active: &ResolvedActiveSemanticModels,
    cancellation: &crate::CancellationToken,
) -> Result<Vec<SemanticModelCompositionDiagnostic>, SemanticModelOverlayBuildError> {
    freeze_symbol_order(symbols);
    freeze_relation_order(relations.iter_mut());
    let reads = DecodedCompositionReads { active };
    let groups = alias_groups(symbols, cancellation)?;
    let mut replacements = HashMap::default();
    let mut composed_owners = HashSet::default();
    let mut origin_identities = OriginRewrites::default();
    let mut symbol_groups = HashMap::default();
    for (group_index, group) in groups.iter().enumerate() {
        let owners = group.iter().map(|&i| &symbols[i]).collect::<Vec<_>>();
        let representative = representative_identity(&owners, &reads)
            .expect("decoded composition reads are infallible");
        if representative.composed {
            composed_owners.extend(owners.iter().map(|s| s.id.clone()));
        }
        record_origin_identities(&mut origin_identities, &owners, &representative);
        replacements.extend(representative.replacements);
        for owner in owners {
            symbol_groups
                .entry((owner.provenance.pack_digest.clone(), owner.id.clone()))
                .or_insert(group_index);
        }
    }
    let mut members_by_owner = HashMap::<String, Vec<usize>>::default();
    for (index, symbol) in symbols.iter().enumerate() {
        if let Some(owner) = &symbol.owner_id {
            members_by_owner
                .entry(owner.clone())
                .or_default()
                .push(index);
        }
    }
    let mut inputs = groups
        .iter()
        .map(|group| {
            let mut indices = group.clone();
            for &owner in group {
                indices.extend(
                    members_by_owner
                        .get(&symbols[owner].id)
                        .into_iter()
                        .flatten(),
                );
            }
            indices.sort_unstable();
            indices.dedup();
            (indices, Vec::new())
        })
        .collect::<Vec<_>>();
    let mut relation_output = Vec::new();
    for (index, relation) in std::mem::take(relations).into_iter().enumerate() {
        if let Some(&group) = symbol_groups.get(&(
            relation.provenance.pack_digest.clone(),
            relation.from.clone(),
        )) {
            inputs[group].1.push((index, relation));
        } else {
            relation_output.push((index, relation));
        }
    }
    relation_output = rewrite_relations(
        relation_output,
        &replacements,
        &composed_owners,
        &origin_identities,
    );
    let mut diagnostics = Vec::new();
    let mut removed = HashSet::default();
    for (indices, group_relations) in inputs {
        let group_symbols = indices
            .iter()
            .map(|&i| symbols[i].clone())
            .collect::<Vec<_>>();
        debug_assert_group_backing(&group_symbols, active);
        let result = compose(
            group_symbols,
            group_relations,
            &reads,
            &replacements,
            &composed_owners,
            &origin_identities,
        )
        .expect("decoded composition reads are infallible");
        let kept = result
            .source_indices
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        for (index, &source) in indices.iter().enumerate() {
            if !kept.contains(&index) {
                removed.insert(source);
            }
        }
        for (index, symbol) in result.source_indices.into_iter().zip(result.symbols) {
            symbols[indices[index]] = symbol;
        }
        relation_output.extend(result.relations);
        diagnostics.extend(result.diagnostics);
    }
    let mut index = 0;
    symbols.retain(|_| {
        let keep = !removed.contains(&index);
        index += 1;
        keep
    });
    relation_output.sort_by_key(|(i, _)| *i);
    *relations = relation_output.into_iter().map(|(_, r)| r).collect();
    normalize_diagnostics(&mut diagnostics);
    Ok(diagnostics)
}

pub(super) fn freeze_symbol_order(symbols: &mut [SemanticModelSymbol]) {
    for symbol in symbols {
        symbol
            .pre_composition_qualified_name
            .get_or_insert_with(|| symbol.qualified_name.clone());
    }
}

pub(super) fn symbol_source_order(
    left: &SemanticModelSymbol,
    right: &SemanticModelSymbol,
) -> std::cmp::Ordering {
    semantic_symbol_source_key(left).cmp(&semantic_symbol_source_key(right))
}
pub(super) fn freeze_relation_order<'a>(
    relations: impl IntoIterator<Item = &'a mut SemanticModelRelation>,
) {
    for relation in relations {
        relation
            .pre_composition_endpoints
            .get_or_insert_with(|| (relation.from.clone(), relation.to.clone()));
    }
}

pub(super) fn relation_source_order(
    left: &SemanticModelRelation,
    right: &SemanticModelRelation,
) -> std::cmp::Ordering {
    semantic_relation_source_key(left).cmp(&semantic_relation_source_key(right))
}

fn debug_assert_group_backing(
    symbols: &[SemanticModelSymbol],
    active: &ResolvedActiveSemanticModels,
) {
    let mut backing = None;
    for owner in symbols {
        for shard in active
            .shards
            .iter()
            .filter(|shard| shard.manifest.semantic_sha256 == owner.provenance.pack_digest)
        {
            let decoded = shard.decoded.is_some();
            debug_assert!(
                backing.is_none_or(|previous| previous == decoded),
                "one alias group must share a backing"
            );
            backing = Some(decoded);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn assert_group_parity(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
    symbols: &[SemanticModelSymbol],
    relations: &[SemanticModelRelation],
    generated: &[SemanticModelSymbol],
    generated_relations: &[SemanticModelRelation],
) -> (usize, usize) {
    let groups = alias_groups(symbols, &crate::CancellationToken::new()).unwrap();
    let decoded = DecodedCompositionReads { active };
    let rows = RowCompositionReads {
        active,
        reader,
        generated,
        generated_relations,
    };
    let mut replacements = HashMap::default();
    let mut composed_owners = HashSet::default();
    let mut origin_identities = OriginRewrites::default();
    for group in &groups {
        let owners = group.iter().map(|&i| &symbols[i]).collect::<Vec<_>>();
        let representative = representative_identity(&owners, &decoded).unwrap();
        if representative.composed {
            composed_owners.extend(owners.iter().map(|s| s.id.clone()));
        }
        record_origin_identities(&mut origin_identities, &owners, &representative);
        replacements.extend(representative.replacements);
    }
    let mut generated_groups = 0;
    for group in &groups {
        let owners = group.iter().map(|&i| &symbols[i]).collect::<Vec<_>>();
        let key = group_key(&owners);
        let ids = owners.iter().map(|s| s.id.as_str()).collect::<HashSet<_>>();
        let mut input = symbols
            .iter()
            .filter(|s| {
                if let Some(owner) = &s.owner_id {
                    ids.contains(owner.as_str())
                } else {
                    owners.iter().any(|owner| std::ptr::eq(*owner, *s))
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        debug_assert_group_backing(&input, active);
        generated_groups += usize::from(input.iter().any(|s| s.provenance.rule_id.is_some()));
        let actual_input = rows.group_symbols(analyzer, &key).unwrap();
        assert_eq!(input, actual_input, "raw group input {key:?}");
        let origin_ids = owners
            .iter()
            .map(|s| (s.provenance.pack_digest.as_str(), s.id.as_str()))
            .collect::<HashSet<_>>();
        let mut input_relations: Vec<(usize, SemanticModelRelation)> = relations
            .iter()
            .filter(|r| origin_ids.contains(&(r.provenance.pack_digest.as_str(), r.from.as_str())))
            .cloned()
            .enumerate()
            .collect();
        freeze_symbol_order(&mut input);
        freeze_relation_order(input_relations.iter_mut().map(|(_, relation)| relation));
        let expected = compose(
            input,
            input_relations,
            &decoded,
            &replacements,
            &composed_owners,
            &origin_identities,
        )
        .unwrap();
        let actual = rows.compose_group(analyzer, &key).unwrap();
        assert_eq!(
            expected.symbols, actual.symbols,
            "composed group symbols {key:?}"
        );
        assert_eq!(
            expected.representative, actual.representative,
            "representative {key:?}"
        );
        assert_eq!(
            expected.diagnostics, actual.diagnostics,
            "group diagnostics {key:?}"
        );
        let expected = expected
            .relations
            .into_iter()
            .map(|(_, r)| r)
            .collect::<Vec<_>>();
        let actual = actual
            .relations
            .into_iter()
            .map(|(_, r)| r)
            .collect::<Vec<_>>();
        assert_eq!(expected, actual, "group relations {key:?}");
    }
    (groups.len(), generated_groups)
}
