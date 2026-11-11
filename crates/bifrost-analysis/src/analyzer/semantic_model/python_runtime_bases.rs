//! Query-local Python runtime-base claim adjudication shared by hierarchy and native model reads.
use crate::analyzer::Language;
use crate::analyzer::semantic::type_flow::external_class_identity_with_visits;
use crate::analyzer::semantic::type_flow::{ClassIdentity, ExternalClassCache};
use crate::analyzer::semantic_model::overlay::{SemanticModelOverlay, activated_type_provenance};
use crate::analyzer::semantic_model::runtime::{
    ActivatedSemanticModelRecord, ActiveSemanticModelShard, ResolvedActiveSemanticModels,
};
use crate::analyzer::semantic_model::{TypeFact, TypeKind, TypeRef};
use crate::analyzer::usages::python_class_hierarchy::{
    PythonAncestryBasis, PythonHierarchyReason, PythonModeledClassIdentity, PythonRuntimeBaseClaim,
};
use crate::hash::HashSet;

pub const MAX_PYTHON_HIERARCHY_VISITS: usize = 4096;

pub trait PythonRuntimeClaimBudget {
    fn charge(&mut self, visits: usize, work: usize) -> Result<(), PythonHierarchyReason>;
    fn has_claim(&self, key: (*const ActiveSemanticModelShard, *const TypeFact)) -> bool;
    fn mark_claim(&mut self, key: (*const ActiveSemanticModelShard, *const TypeFact));
}

fn modeled_identity(identity: &ClassIdentity) -> PythonModeledClassIdentity {
    let ClassIdentity::External {
        qualified_name,
        symbol_id,
    } = identity
    else {
        unreachable!("runtime model claims refer to external class identities")
    };
    PythonModeledClassIdentity {
        qualified_name: qualified_name.to_string(),
        symbol_id: symbol_id.to_string(),
    }
}

pub fn exact_external_class_name_with_visits<E>(
    overlay: Option<&SemanticModelOverlay>,
    qualified_name: &str,
    cache: &mut ExternalClassCache,
    visit: &mut impl FnMut() -> Result<(), E>,
) -> Result<Option<ClassIdentity>, E> {
    let Some(identity) = external_class_identity_with_visits(
        overlay,
        Language::Python,
        qualified_name,
        None,
        cache,
        visit,
    )?
    else {
        return Ok(None);
    };
    if identity.qualified_name() == qualified_name {
        return Ok(Some(identity));
    }
    let ClassIdentity::External { symbol_id, .. } = &identity else {
        unreachable!("external class lookup")
    };
    let Some(overlay) = overlay else {
        return Ok(None);
    };
    let mut selected = None;
    for record in overlay.symbol_candidates_with_id(symbol_id) {
        visit()?;
        if selected.is_some() {
            return Ok(None);
        }
        selected = Some(record);
    }
    if let Some(record) = selected {
        for alias in &record.aliases {
            visit()?;
            if alias == qualified_name {
                return Ok(Some(identity));
            }
        }
    }
    Ok(None)
}

fn retain_claim(
    active: &ResolvedActiveSemanticModels,
    activated: &ActivatedSemanticModelRecord<TypeFact>,
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<Option<usize>, PythonHierarchyReason> {
    let Some(declared) = &activated.record.runtime_bases else {
        return Ok(None);
    };
    // Addresses are only query-local deduplication keys, never public identity.
    let key = (
        std::sync::Arc::as_ptr(&activated.shard),
        std::sync::Arc::as_ptr(&activated.record),
    );
    if budget.has_claim(key) {
        return Ok(None);
    }
    budget.charge(declared.len(), declared.len().saturating_add(1))?;
    let mut ambiguous = false;
    if let Some(overlay) = overlay {
        for symbol in overlay.symbol_candidates_with_id(&activated.record.id) {
            budget.charge(1, 1)?;
            ambiguous |= symbol.provenance.ambiguous;
        }
    }
    let provenance = activated_type_provenance(
        active,
        &activated.shard,
        &activated.record,
        ambiguous,
        &mut || budget.charge(1, 1),
    )?;
    budget.mark_claim(key);
    let index = basis.claims.len();
    basis.claims.push(PythonRuntimeBaseClaim {
        declared_class: PythonModeledClassIdentity {
            qualified_name: activated.record.name.clone(),
            symbol_id: activated.record.id.clone(),
        },
        class: None,
        declared_bases: declared.clone(),
        bases: vec![None; declared.len()],
        provenance,
    });
    Ok(Some(index))
}

type RetainedRuntimeClaim = (ActivatedSemanticModelRecord<TypeFact>, usize);

struct CollectedRuntimeClaims {
    records: Vec<RetainedRuntimeClaim>,
    // A previously retained posting still declares a claim. Dedupe is not absence.
    declared: bool,
}

/// Collect raw records for selected IDs, retaining lower-ranked same-ID owner
/// conflicts. Presence is independent of whether a posting was already retained.
fn collect_claim_ids(
    active: &ResolvedActiveSemanticModels,
    ids: &[String],
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<CollectedRuntimeClaims, PythonHierarchyReason> {
    let mut records = Vec::new();
    let mut declared = false;
    for id in ids {
        for activated in python_rows(active.all_type_records_with_id(id)) {
            budget.charge(1, 1)?;
            if activated.shard.manifest.language == "python" {
                declared |= activated.record.runtime_bases.is_some();
                if let Some(index) = retain_claim(active, &activated, overlay, basis, budget)? {
                    records.push((activated, index));
                }
            }
        }
    }
    Ok(CollectedRuntimeClaims { records, declared })
}

fn runtime_claim_owner_ids(
    active: &ResolvedActiveSemanticModels,
    qualified_name: &str,
    symbol_id: &str,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<Vec<String>, PythonHierarchyReason> {
    budget.charge(1, 1)?;
    let mut ids = vec![symbol_id.to_owned()];
    let mut seen_ids = HashSet::default();
    seen_ids.insert(symbol_id.to_owned());
    for activated in python_rows(active.all_type_records_named(qualified_name)) {
        budget.charge(1, 1)?;
        if activated.shard.manifest.language == "python"
            && activated.record.name == qualified_name
            && seen_ids.insert(activated.record.id.clone())
        {
            ids.push(activated.record.id.clone());
        }
    }
    Ok(ids)
}

fn collect_runtime_claims<'a>(
    active: &'a ResolvedActiveSemanticModels,
    owner: &'a ClassIdentity,
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<CollectedRuntimeClaims, PythonHierarchyReason> {
    let ClassIdentity::External {
        qualified_name,
        symbol_id,
    } = owner
    else {
        unreachable!("only external classes have runtime model claims")
    };
    let ids = runtime_claim_owner_ids(active, qualified_name, symbol_id, budget)?;
    collect_claim_ids(active, &ids, overlay, basis, budget)
}

/// Unresolved names have no established canonical owner. Preserve their
/// possible claim evidence conservatively, separately from admitted owners.
pub fn retain_open_claims(
    active: &ResolvedActiveSemanticModels,
    name: &str,
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<bool, PythonHierarchyReason> {
    let mut ids = Vec::new();
    let mut seen_ids = HashSet::default();
    for activated in python_rows(active.all_type_records_named(name)) {
        budget.charge(1, 1)?;
        if activated.shard.manifest.language == "python"
            && seen_ids.insert(activated.record.id.clone())
        {
            ids.push(activated.record.id.clone());
        }
    }
    Ok(collect_claim_ids(active, &ids, overlay, basis, budget)?.declared)
}

fn runtime_claim_target(
    overlay: Option<&SemanticModelOverlay>,
    reference: &TypeRef,
    cache: &mut ExternalClassCache,
    budget: &mut impl PythonRuntimeClaimBudget,
    unresolved: &mut Vec<TypeRef>,
) -> Result<ClassIdentity, PythonHierarchyReason> {
    let target = match reference {
        TypeRef::Named {
            name,
            arguments,
            nullable: false,
        } if arguments.is_empty() => {
            let target = exact_external_class_name_with_visits(overlay, name, cache, &mut || {
                budget.charge(1, 1)
            })?;
            if target.is_none() {
                budget.charge(1, 1)?;
                unresolved.push(reference.clone());
            }
            target
        }
        TypeRef::Declared {
            id,
            arguments,
            nullable: false,
        } if arguments.is_empty() => {
            // ID resolution uses the same canonical class selection and rank
            // boundary as name resolution, not a preferred raw claim.
            let target = external_class_identity_with_visits(
                overlay,
                Language::Python,
                "",
                Some(id),
                cache,
                &mut || budget.charge(1, 1),
            )?;
            if target.is_none() {
                budget.charge(1, 1)?;
                unresolved.push(reference.clone());
            }
            target
        }
        _ => return Err(PythonHierarchyReason::UnsupportedBaseExpression),
    };
    target.ok_or(PythonHierarchyReason::UnresolvedBase)
}

pub fn runtime_bases(
    active: &ResolvedActiveSemanticModels,
    overlay: Option<&SemanticModelOverlay>,
    identity: &ClassIdentity,
    basis: &mut PythonAncestryBasis,
    cache: &mut ExternalClassCache,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<Vec<ClassIdentity>, PythonHierarchyReason> {
    // None abstains; every explicit raw contributor, including lower-ranked
    // owners that cannot bind, is collected before admission checks.
    let records = collect_runtime_claims(active, identity, overlay, basis, budget)?.records;
    if records.is_empty() {
        return Err(PythonHierarchyReason::MissingRuntimeBases);
    }
    let mut failure = None;
    // Retain all contributors before checking their declaration admission.
    for (activated, index) in &records {
        let admitted = active.type_declaration_admitted(activated, &mut || budget.charge(1, 1))?;
        let canonical = external_class_identity_with_visits(
            overlay,
            Language::Python,
            &activated.record.name,
            Some(&activated.record.id),
            cache,
            &mut || budget.charge(1, 1),
        )?;
        if activated.record.type_kind != TypeKind::Class
            || !admitted
            || canonical.as_ref() != Some(identity)
        {
            failure.get_or_insert(PythonHierarchyReason::AmbiguousRuntimeBase);
        } else {
            basis.claims[*index].class = canonical.as_ref().map(modeled_identity);
        }
    }
    let mut agreed = None;
    let mut unresolved = Vec::new();
    for (_, index) in records {
        let claim = &mut basis.claims[index];
        let mut resolved = Vec::new();
        let mut seen = HashSet::default();
        for (slot, reference) in claim.declared_bases.iter().enumerate() {
            budget.charge(0, 1)?;
            match runtime_claim_target(overlay, reference, cache, budget, &mut unresolved) {
                Ok(target) => {
                    claim.bases[slot] = Some(modeled_identity(&target));
                    if !seen.insert(target.clone()) {
                        failure.get_or_insert(PythonHierarchyReason::DuplicateBase);
                    }
                    resolved.push(target);
                }
                Err(
                    reason @ (PythonHierarchyReason::Cancelled | PythonHierarchyReason::VisitLimit),
                ) => return Err(reason),
                Err(reason) => {
                    failure.get_or_insert(reason);
                }
            }
        }
        if resolved.len() == claim.declared_bases.len() {
            match &agreed {
                Some(previous) if *previous != resolved => {
                    failure.get_or_insert(PythonHierarchyReason::ConflictingRuntimeBases);
                }
                None => agreed = Some(resolved),
                _ => {}
            }
        }
    }
    for reference in unresolved {
        match reference {
            TypeRef::Named { name, .. } => {
                retain_open_claims(active, &name, overlay, basis, budget)?;
            }
            TypeRef::Declared { id, .. } => {
                for activated in python_rows(active.all_type_records_with_id(&id)) {
                    budget.charge(1, 1)?;
                    if activated.shard.manifest.language == "python" {
                        let _retained_index =
                            retain_claim(active, &activated, overlay, basis, budget)?;
                    }
                }
            }
            _ => unreachable!("only supported unresolved class references are queued"),
        }
    }
    match failure {
        Some(reason) => Err(reason),
        None => Ok(agreed.expect("all claims resolved, including empty roots")),
    }
}

/// Whether the active model claims runtime bases for this external identity.
///
/// An implicit object root may use the language-intrinsic endpoint only in
/// the absence of claims. Presence does not establish admission or agreement;
/// runtime_bases still adjudicates every contributor to the selected owner IDs.
pub fn runtime_base_claim_declared(
    active: &ResolvedActiveSemanticModels,
    identity: &ClassIdentity,
    budget: &mut impl PythonRuntimeClaimBudget,
) -> Result<bool, PythonHierarchyReason> {
    let ClassIdentity::External {
        qualified_name,
        symbol_id,
    } = identity
    else {
        return Ok(false);
    };
    let ids = runtime_claim_owner_ids(active, qualified_name, symbol_id, budget)?;
    let mut declared = false;
    for id in ids {
        for activated in python_rows(active.all_type_records_with_id(&id)) {
            budget.charge(1, 1)?;
            declared |= activated.shard.manifest.language == "python"
                && activated.record.runtime_bases.is_some();
        }
    }
    Ok(declared)
}

impl From<crate::analyzer::semantic_model::FamilyOpen> for PythonHierarchyReason {
    fn from(_: crate::analyzer::semantic_model::FamilyOpen) -> Self {
        unreachable!("Python runtime bases read no JVM-family part")
    }
}

fn python_rows<T>(
    rows: crate::analyzer::store::active_models::FamilyRows<impl Iterator<Item = T>>,
) -> impl Iterator<Item = T> {
    assert!(rows.open_for_language("python").is_none());
    rows.rows
}
