use crate::analyzer::python::*;

use brokk_bifrost_semantic::analyzer::semantic::type_flow::ClassIdentity;

use brokk_bifrost_semantic::analyzer::semantic::type_flow::ExternalClassCache;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::external_class_identity_with_visits;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActivatedSemanticModelRecord;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ResolvedActiveSemanticModels;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeFact;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeKind;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::activated_type_provenance;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::analyzer::usages::get_definition::python::PythonDefinitionProvider;

use crate::analyzer::usages::get_definition::python::PythonRuntimeClassCandidate;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonAncestryBasis;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonBaseFact;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonBaseOrigin;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonBaseResolution;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonClassHierarchyAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonClassHierarchyProvider;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonHierarchyReason;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonModeledClassIdentity;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonMroMember;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonMroMembersAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonOverrideAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonOverrideOutcome;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonRuntimeBaseClaim;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::analyzer::capabilities::descendants_from_variant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
// Legacy source-only TypeHierarchyProvider below retains its existing path.
use brokk_bifrost_python::graph_support::resolve_base_class;
use std::collections::VecDeque;
use std::sync::Arc;

const MAX_PYTHON_HIERARCHY_VISITS: usize = 4096;
const MAX_PYTHON_C3_WORK: usize = 65_536;
const MAX_PYTHON_MEMBER_VISITS: usize = 32_768;
const PYTHON_OBJECT_ROOT: &str = "builtins.object";

enum ClassWork {
    Enter(ClassIdentity),
    Exit(ClassIdentity),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClassVisit {
    Visiting,
    Done,
}

pub(crate) enum C3Failure {
    Inconsistent,
    VisitLimit,
    Cancelled,
}

/// All accounting and retained state belong to this invocation, not the analyzer.
struct HierarchyBudget<'a> {
    visits: usize,
    session: &'a ResolutionSession,
    provider: &'a PythonDefinitionProvider<'a>,
    retained_claims: HashSet<(*const ActiveSemanticModelShard, *const TypeFact)>,
}

impl HierarchyBudget<'_> {
    fn charge(&mut self, visits: usize, work: usize) -> Result<(), PythonHierarchyReason> {
        if self.visits.saturating_add(visits) > MAX_PYTHON_HIERARCHY_VISITS {
            return Err(PythonHierarchyReason::VisitLimit);
        }
        if !self.session.scope_steps(work.max(visits)) {
            return Err(session_reason(self.session));
        }
        self.visits += visits;
        Ok(())
    }
}

fn session_reason(session: &ResolutionSession) -> PythonHierarchyReason {
    match session.finish(()) {
        BoundedResolution::Cancelled { .. } => PythonHierarchyReason::Cancelled,
        BoundedResolution::Exceeded { .. } => PythonHierarchyReason::VisitLimit,
        BoundedResolution::Complete { .. } => unreachable!("failed charge has a sticky stop"),
    }
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

fn retain_claim(
    active: &ResolvedActiveSemanticModels,
    activated: &ActivatedSemanticModelRecord<'_, TypeFact>,
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut HierarchyBudget<'_>,
) -> Result<Option<usize>, PythonHierarchyReason> {
    let Some(declared) = &activated.record.runtime_bases else {
        return Ok(None);
    };
    // Addresses are only query-local deduplication keys, never public identity.
    let key = (
        std::ptr::from_ref(activated.shard),
        std::ptr::from_ref(activated.record),
    );
    if budget.retained_claims.contains(&key) {
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
        activated.shard,
        activated.record,
        ambiguous,
        &mut || budget.charge(1, 1),
    )?;
    budget.retained_claims.insert(key);
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

type RetainedRuntimeClaim<'a> = (ActivatedSemanticModelRecord<'a, TypeFact>, usize);

struct CollectedRuntimeClaims<'a> {
    records: Vec<RetainedRuntimeClaim<'a>>,
    // A previously retained posting still declares a claim. Dedupe is not absence.
    declared: bool,
}

/// Collect raw records for selected IDs, retaining lower-ranked same-ID owner
/// conflicts. Presence is independent of whether a posting was already retained.
fn collect_claim_ids<'a>(
    active: &'a ResolvedActiveSemanticModels,
    ids: &[&str],
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut HierarchyBudget<'_>,
) -> Result<CollectedRuntimeClaims<'a>, PythonHierarchyReason> {
    let mut records = Vec::new();
    let mut declared = false;
    for id in ids {
        for activated in active.all_type_records_with_id(id) {
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

fn runtime_claim_owner_ids<'a>(
    active: &'a ResolvedActiveSemanticModels,
    qualified_name: &str,
    symbol_id: &'a str,
    budget: &mut HierarchyBudget<'_>,
) -> Result<Vec<&'a str>, PythonHierarchyReason> {
    budget.charge(1, 1)?;
    let mut ids = vec![symbol_id];
    let mut seen_ids = HashSet::default();
    seen_ids.insert(symbol_id);
    for activated in active.all_type_records_named(qualified_name) {
        budget.charge(1, 1)?;
        if activated.shard.manifest.language == "python"
            && activated.record.name == qualified_name
            && seen_ids.insert(activated.record.id.as_str())
        {
            ids.push(activated.record.id.as_str());
        }
    }
    Ok(ids)
}

fn collect_runtime_claims<'a>(
    active: &'a ResolvedActiveSemanticModels,
    owner: &'a ClassIdentity,
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut HierarchyBudget<'_>,
) -> Result<CollectedRuntimeClaims<'a>, PythonHierarchyReason> {
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
fn retain_open_claims(
    active: &ResolvedActiveSemanticModels,
    name: &str,
    overlay: Option<&SemanticModelOverlay>,
    basis: &mut PythonAncestryBasis,
    budget: &mut HierarchyBudget<'_>,
) -> Result<bool, PythonHierarchyReason> {
    let mut ids = Vec::new();
    let mut seen_ids = HashSet::default();
    for activated in active.all_type_records_named(name) {
        budget.charge(1, 1)?;
        if activated.shard.manifest.language == "python"
            && seen_ids.insert(activated.record.id.as_str())
        {
            ids.push(activated.record.id.as_str());
        }
    }
    Ok(collect_claim_ids(active, &ids, overlay, basis, budget)?.declared)
}

fn runtime_claim_target(
    overlay: Option<&SemanticModelOverlay>,
    reference: &TypeRef,
    cache: &mut ExternalClassCache,
    budget: &mut HierarchyBudget<'_>,
    unresolved: &mut Vec<TypeRef>,
) -> Result<ClassIdentity, PythonHierarchyReason> {
    let target = match reference {
        TypeRef::Named {
            name,
            arguments,
            nullable: false,
        } if arguments.is_empty() => {
            let target = crate::analyzer::python::type_flow::exact_external_class_name_with_visits(
                overlay,
                name,
                cache,
                &mut || budget.charge(1, 1),
            )?;
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

fn runtime_bases(
    active: &ResolvedActiveSemanticModels,
    overlay: Option<&SemanticModelOverlay>,
    identity: &ClassIdentity,
    basis: &mut PythonAncestryBasis,
    cache: &mut ExternalClassCache,
    budget: &mut HierarchyBudget<'_>,
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
        let admitted =
            active.type_declaration_admitted(activated.record, &mut || budget.charge(1, 1))?;
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
                for activated in active.all_type_records_with_id(&id) {
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
fn runtime_base_claim_declared(
    active: &ResolvedActiveSemanticModels,
    identity: &ClassIdentity,
    budget: &mut HierarchyBudget<'_>,
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
        for activated in active.all_type_records_with_id(id) {
            budget.charge(1, 1)?;
            declared |= activated.shard.manifest.language == "python"
                && activated.record.runtime_bases.is_some();
        }
    }
    Ok(declared)
}

impl PythonClassHierarchyProvider for PythonAnalyzer {
    fn class_hierarchy(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonClassHierarchyAnswer {
        let mut basis = PythonAncestryBasis::default();
        let mut root_bases = Vec::new();
        let session = ResolutionSession::bounded_with_total_work(
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
            MAX_PYTHON_C3_WORK,
            cancellation,
        );
        let provider = PythonDefinitionProvider::new(self, &session);
        let mut budget = HierarchyBudget {
            visits: 0,
            session: &session,
            provider: &provider,
            retained_claims: HashSet::default(),
        };
        let snapshot = self.active_semantic_model_snapshot();
        let active = snapshot
            .as_ref()
            .map(|snapshot| snapshot.active_models().as_ref());
        let overlay = snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.semantic_model_overlay().map(Arc::as_ref));
        let mut cache = ExternalClassCache::default();
        let root = ClassIdentity::Workspace(class.clone());
        let mut stack = vec![ClassWork::Enter(root.clone())];
        let mut states = HashMap::<ClassIdentity, ClassVisit>::default();
        let mut nodes = HashMap::<ClassIdentity, Vec<ClassIdentity>>::default();
        let mut linearizations = HashMap::<ClassIdentity, Vec<ClassIdentity>>::default();
        let result = (|| -> Result<(), PythonHierarchyReason> {
            budget.charge(1, 1)?;
            if !class.is_class() {
                return Err(PythonHierarchyReason::NotClass);
            }
            if class.is_synthetic() {
                return Err(PythonHierarchyReason::ExternalBase);
            }
            while let Some(work) = stack.pop() {
                budget.charge(1, 1)?;
                let current = match work {
                    ClassWork::Enter(current) => match states.get(&current) {
                        Some(ClassVisit::Done) => continue,
                        Some(ClassVisit::Visiting) => {
                            return Err(PythonHierarchyReason::CyclicBases);
                        }
                        None => current,
                    },
                    ClassWork::Exit(current) => {
                        let mro =
                            merge_c3(&current, &nodes[&current], &linearizations, &mut |amount| {
                                if session.scope_steps(amount) {
                                    Ok(())
                                } else {
                                    Err(match session_reason(&session) {
                                        PythonHierarchyReason::Cancelled => C3Failure::Cancelled,
                                        _ => C3Failure::VisitLimit,
                                    })
                                }
                            })
                            .map_err(|failure| match failure {
                                C3Failure::Inconsistent => {
                                    PythonHierarchyReason::InconsistentLinearization
                                }
                                C3Failure::VisitLimit => PythonHierarchyReason::VisitLimit,
                                C3Failure::Cancelled => PythonHierarchyReason::Cancelled,
                            })?;
                        linearizations.insert(current.clone(), mro);
                        states.insert(current, ClassVisit::Done);
                        continue;
                    }
                };
                let bases = match &current {
                    ClassIdentity::Workspace(owner) => self.runtime_source_bases(
                        owner,
                        snapshot.as_deref(),
                        &mut cache,
                        &mut budget,
                        &mut basis,
                        (current == root).then_some(&mut root_bases),
                    )?,
                    ClassIdentity::Intrinsic { .. } => Vec::new(),
                    ClassIdentity::External { .. } => runtime_bases(
                        active.ok_or(PythonHierarchyReason::MissingRuntimeBases)?,
                        overlay,
                        &current,
                        &mut basis,
                        &mut cache,
                        &mut budget,
                    )?,
                };
                budget.charge(0, bases.len())?;
                let mut seen = HashSet::default();
                for base in &bases {
                    if !seen.insert(base) {
                        return Err(PythonHierarchyReason::DuplicateBase);
                    }
                }
                states.insert(current.clone(), ClassVisit::Visiting);
                stack.push(ClassWork::Exit(current.clone()));
                for base in bases.iter().rev() {
                    stack.push(ClassWork::Enter(base.clone()));
                }
                nodes.insert(current, bases);
            }
            Ok(())
        })();
        let result = match session.finish(result) {
            BoundedResolution::Complete { value, .. } => value,
            BoundedResolution::Exceeded { .. } => Err(PythonHierarchyReason::VisitLimit),
            BoundedResolution::Cancelled { .. } => Err(PythonHierarchyReason::Cancelled),
        };
        match result {
            Ok(()) => PythonClassHierarchyAnswer::complete(
                root_bases,
                linearizations.remove(&root).expect("completed root has C3"),
                basis,
            ),
            Err(reason) => PythonClassHierarchyAnswer::stopped(
                match reason {
                    PythonHierarchyReason::NotClass
                    | PythonHierarchyReason::UnsupportedBaseExpression => {
                        PythonHierarchyOutcome::Unsupported
                    }
                    PythonHierarchyReason::DuplicateBase
                    | PythonHierarchyReason::CyclicBases
                    | PythonHierarchyReason::InconsistentLinearization => {
                        PythonHierarchyOutcome::Inconsistent
                    }
                    _ => PythonHierarchyOutcome::Incomplete,
                },
                reason,
                root_bases,
                basis,
            ),
        }
    }

    fn mro_members(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer {
        self.mro_members_from_hierarchy(self.class_hierarchy(class, cancellation), cancellation)
    }

    fn method_override(
        &self,
        method: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonOverrideAnswer {
        let owner = self.parent_of(method).filter(CodeUnit::is_class);
        if !method.is_function() || owner.is_none() {
            return PythonOverrideAnswer::stopped(
                PythonOverrideOutcome::Unsupported,
                Some(PythonHierarchyReason::NotClass),
                owner,
                PythonAncestryBasis::default(),
            );
        }
        let owner = owner.expect("class owner checked");
        let hierarchy = self.class_hierarchy(&owner, cancellation);
        let stopped = |outcome, reason| {
            PythonOverrideAnswer::stopped(
                outcome,
                reason,
                Some(owner.clone()),
                hierarchy.ancestry_basis.clone(),
            )
        };
        if hierarchy.outcome != PythonHierarchyOutcome::Complete {
            return stopped(
                if hierarchy.outcome == PythonHierarchyOutcome::Unsupported {
                    PythonOverrideOutcome::Unsupported
                } else {
                    PythonOverrideOutcome::Incomplete
                },
                hierarchy.reason,
            );
        }
        let mut visits = 0usize;
        for (rank, identity) in hierarchy.mro.iter().enumerate() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::Cancelled),
                );
            }
            let ClassIdentity::Workspace(mro_owner) = identity else {
                if matches!(identity, ClassIdentity::Intrinsic { .. }) {
                    // The language-supplied object root declares no source
                    // member that could override the selected method.
                    continue;
                }
                // A complete ancestry claim is not a complete member inventory.
                return stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::UnknownMemberSurface),
                );
            };
            let declarations = self.direct_children_in_source_order(mro_owner);
            visits = visits.saturating_add(declarations.len());
            if visits > MAX_PYTHON_MEMBER_VISITS {
                return stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::VisitLimit),
                );
            }
            let selected = declarations
                .into_iter()
                .rev()
                .find(|declaration| declaration.terminal_name() == method.terminal_name());
            if rank == 0 {
                if selected.as_ref() != Some(method) {
                    return stopped(
                        PythonOverrideOutcome::Unsupported,
                        Some(PythonHierarchyReason::NotEffectiveMember),
                    );
                }
                continue;
            }
            if let Some(target) = selected {
                if !target.is_function() {
                    return stopped(PythonOverrideOutcome::NoOverride, None);
                }
                return PythonOverrideAnswer {
                    outcome: PythonOverrideOutcome::Overrides,
                    reason: None,
                    source_owner: Some(owner.clone()),
                    target: Some(target),
                    target_owner: Some(mro_owner.clone()),
                    mro_rank: Some(rank),
                    ancestry_basis: hierarchy.ancestry_basis.clone(),
                };
            }
        }
        stopped(PythonOverrideOutcome::NoOverride, None)
    }
}

impl PythonAnalyzer {
    fn runtime_source_bases(
        &self,
        owner: &CodeUnit,
        models: Option<&ActiveSemanticModelSnapshot>,
        cache: &mut ExternalClassCache,
        budget: &mut HierarchyBudget<'_>,
        basis: &mut PythonAncestryBasis,
        mut root_facts: Option<&mut Vec<PythonBaseFact>>,
    ) -> Result<Vec<ClassIdentity>, PythonHierarchyReason> {
        let active = models.map(|models| models.active_models().as_ref());
        let overlay = models.and_then(|models| models.semantic_model_overlay().map(Arc::as_ref));
        let session = budget.session;
        let prepared = session
            .query(|| {
                crate::analyzer::python::type_flow::current_indexed_prepared(self, owner.source())
            })
            .flatten()
            .ok_or(PythonHierarchyReason::UnresolvedBase)?;
        let class = crate::analyzer::python::type_flow::class_node_for_unit_in_session(
            self, &prepared, owner, session,
        )
        .ok_or(PythonHierarchyReason::UnresolvedBase)?;
        if class.child_by_field_name("type_parameters").is_some() {
            // PEP 695 can insert Generic into runtime bases. A typing origin
            // or the ordinary implicit-object rule does not prove that graph.
            return Err(PythonHierarchyReason::UnsupportedBaseExpression);
        }
        let body = class.child_by_field_name("body");
        let mut cursor = class.walk();
        for child in class.named_children(&mut cursor) {
            if Some(child) != body {
                budget.charge(1, 1)?;
                if child.has_error() || child.is_missing() {
                    return Err(PythonHierarchyReason::UnsupportedBaseExpression);
                }
            }
        }
        if class
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
        {
            return Err(PythonHierarchyReason::UnsupportedBaseExpression);
        }
        let mut base_nodes = Vec::new();
        if let Some(arguments) = class.child_by_field_name("superclasses") {
            if arguments.has_error() {
                return Err(PythonHierarchyReason::UnsupportedBaseExpression);
            }
            let mut cursor = arguments.walk();
            for argument in arguments.named_children(&mut cursor) {
                budget.charge(1, 1)?;
                if argument.kind() == "comment" {
                    continue;
                }
                brokk_bifrost_core::analyzer::tree_walk::try_walk_named_tree_preorder(
                    argument,
                    true,
                    |_| {
                        budget.charge(1, 1)?;
                        Ok::<_, PythonHierarchyReason>(
                            brokk_bifrost_core::analyzer::tree_walk::WalkControl::Continue,
                        )
                    },
                )?;
                if brokk_bifrost_python::syntax::python_static_attribute_path_bounded(
                    argument,
                    || session.scope_step(),
                )
                .is_none()
                {
                    // Calls, subscriptions, splats, and class keywords can
                    // change runtime bases/metaclasses; typing origins cannot
                    // certify those runtime operations.
                    return Err(PythonHierarchyReason::UnsupportedBaseExpression);
                }
                base_nodes.push(argument);
            }
        }
        let scope = AnalyzerQueryScope::new(self);
        let mut bases = Vec::new();
        if base_nodes.is_empty() {
            // A class with no written bases inherits `object` by language
            // rule. A runtime-base claim may refine that endpoint to the
            // model's canonical identity. Only genuine claim absence permits
            // an intrinsic terminal: failed declaration admission must retain
            // raw claims and their unresolved model boundary (#5738).
            let target = match active {
                Some(active) => {
                    let target =
                        crate::analyzer::python::type_flow::exact_external_class_name_with_visits(
                            overlay,
                            PYTHON_OBJECT_ROOT,
                            cache,
                            &mut || budget.charge(1, 1),
                        )?;
                    match target {
                        Some(target) if runtime_base_claim_declared(active, &target, budget)? => {
                            Some(target)
                        }
                        None if retain_open_claims(
                            active,
                            PYTHON_OBJECT_ROOT,
                            overlay,
                            basis,
                            budget,
                        )? =>
                        {
                            None
                        }
                        _ => Some(ClassIdentity::Intrinsic {
                            qualified_name: PYTHON_OBJECT_ROOT.into(),
                        }),
                    }
                }
                None => Some(ClassIdentity::Intrinsic {
                    qualified_name: PYTHON_OBJECT_ROOT.into(),
                }),
            };
            // Implicit object is a language identity, never lexical `object`.
            if let Some(facts) = &mut root_facts {
                facts.push(PythonBaseFact {
                    origin: PythonBaseOrigin::ImplicitObject,
                    ordinal: 0,
                    spelling: PYTHON_OBJECT_ROOT.into(),
                    resolution: if target.is_some() {
                        PythonBaseResolution::Resolved
                    } else {
                        PythonBaseResolution::Unresolved
                    },
                    target: target.clone(),
                });
            }
            bases.push(target.ok_or(PythonHierarchyReason::MissingRuntimeBases)?);
        } else {
            let support = budget.provider;
            for (ordinal, base) in base_nodes.into_iter().enumerate() {
                budget.charge(1, 1)?;
                let raw = base
                    .utf8_text(prepared.source().as_bytes())
                    .map_err(|_| PythonHierarchyReason::UnsupportedBaseExpression)?
                    .to_owned();
                let mut expression = base;
                let mut aliases = HashSet::default();
                let target = loop {
                    let source =
                        crate::analyzer::usages::get_definition::python::python_class_object_base_candidate(
                            support,
                            scope.token(),
                            owner.source(),
                            &prepared,
                            expression,
                        );
                    match source {
                        Some(PythonRuntimeClassCandidate::WorkspaceClass(source))
                            if !source.is_synthetic() =>
                        {
                            debug_assert!(
                                source.is_class(),
                                "class-object proof returned {source:?}"
                            );
                            break Some(ClassIdentity::Workspace(source));
                        }
                        Some(PythonRuntimeClassCandidate::AliasRhs { assignment, rhs }) => {
                            budget.charge(1, 1)?;
                            // Same operation/tree/session: each RHS is evaluated
                            // at its assignment, never at the later class header.
                            // The set retains neither Nodes nor resolved answers.
                            if !aliases.insert((
                                owner.source(),
                                prepared.source_sha256(),
                                assignment.start_byte(),
                                assignment.end_byte(),
                            )) {
                                break None;
                            }
                            expression = rhs;
                        }
                        _ => {
                            break crate::analyzer::python::type_flow::exact_external_base_node_with_lookup(
                                support,
                                owner,
                                &prepared,
                                expression,
                                &mut |name| {
                                    let target =
                                        crate::analyzer::python::type_flow::exact_external_class_name_with_visits(
                                            overlay,
                                            name,
                                            cache,
                                            &mut || budget.charge(1, 1),
                                        )?;
                                    if target.is_none()
                                        && let Some(active) = active
                                    {
                                        retain_open_claims(active, name, overlay, basis, budget)?;
                                    }
                                    Ok::<_, PythonHierarchyReason>(target)
                                },
                            )?;
                        }
                    }
                };
                if let Some(facts) = &mut root_facts {
                    facts.push(PythonBaseFact {
                        origin: PythonBaseOrigin::Source,
                        ordinal,
                        spelling: raw,
                        resolution: if target.is_some() {
                            PythonBaseResolution::Resolved
                        } else {
                            PythonBaseResolution::Unresolved
                        },
                        target: target.clone(),
                    });
                }
                bases.push(target.ok_or(PythonHierarchyReason::UnresolvedBase)?);
            }
        }
        if !self.indexed_source_matches(owner.source(), prepared.source()) {
            return Err(PythonHierarchyReason::UnresolvedBase);
        }
        Ok(bases)
    }

    fn mro_members_from_hierarchy(
        &self,
        hierarchy: PythonClassHierarchyAnswer,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer {
        let mut answer = PythonMroMembersAnswer {
            outcome: hierarchy.outcome,
            reason: hierarchy.reason,
            hierarchy,
            members: Vec::new(),
        };
        if answer.outcome != PythonHierarchyOutcome::Complete {
            return answer;
        }
        let mut selected = HashSet::<String>::default();
        let mut visits = 0usize;
        for (rank, identity) in answer.hierarchy.mro.iter().enumerate() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                answer.outcome = PythonHierarchyOutcome::Incomplete;
                answer.reason = Some(PythonHierarchyReason::Cancelled);
                break;
            }
            let ClassIdentity::Workspace(owner) = identity else {
                // The implicit object root is a language-supplied terminal;
                // it contributes no source declarations. Any other external
                // class leaves the member surface unknown.
                if matches!(identity, ClassIdentity::Intrinsic { .. }) {
                    continue;
                }
                answer.outcome = PythonHierarchyOutcome::Incomplete;
                answer.reason = Some(PythonHierarchyReason::UnknownMemberSurface);
                break;
            };
            let declarations = self.direct_children_in_source_order(owner);
            visits = visits.saturating_add(declarations.len());
            if visits > MAX_PYTHON_MEMBER_VISITS {
                answer.outcome = PythonHierarchyOutcome::Incomplete;
                answer.reason = Some(PythonHierarchyReason::VisitLimit);
                break;
            }
            for member in declarations.into_iter().rev() {
                let name = member.terminal_name().to_owned();
                if selected.insert(name.clone()) {
                    answer.members.push(PythonMroMember {
                        name,
                        member,
                        owner: owner.clone(),
                        rank,
                    });
                }
            }
        }
        answer
            .members
            .sort_by(|left, right| (left.rank, &left.name).cmp(&(right.rank, &right.name)));
        answer
    }

    fn direct_children_in_source_order(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        let mut declarations = self.direct_children(owner);
        declarations.sort_by_key(|member| {
            self.ranges(member)
                .iter()
                .map(|range| range.start_byte)
                .max()
                .unwrap_or(usize::MAX)
        });
        declarations
    }
}

/// C3 mechanics shared by runtime ancestry and the separate typing-edge provider.
pub(crate) fn merge_c3<T: Clone + Eq + std::hash::Hash>(
    class: &T,
    bases: &[T],
    linearizations: &HashMap<T, Vec<T>>,
    charge: &mut impl FnMut(usize) -> Result<(), C3Failure>,
) -> Result<Vec<T>, C3Failure> {
    charge(bases.len().saturating_add(1))?;
    let mut sequences = Vec::<VecDeque<T>>::with_capacity(bases.len() + 1);
    for base in bases {
        let base_mro = linearizations
            .get(base)
            .expect("base MRO is complete before its subclass");
        charge(base_mro.len())?;
        sequences.push(base_mro.iter().cloned().collect());
    }
    sequences.push(bases.iter().cloned().collect());
    let mut result = vec![class.clone()];
    while sequences.iter().any(|sequence| !sequence.is_empty()) {
        let mut tails = HashSet::<T>::default();
        for sequence in &sequences {
            charge(sequence.len())?;
            for tail in sequence.iter().skip(1) {
                tails.insert(tail.clone());
            }
        }
        // Charge even empty sequence heads and the pop sweep.
        charge(sequences.len().saturating_mul(2))?;
        let candidate = sequences
            .iter()
            .filter_map(VecDeque::front)
            .find(|head| !tails.contains(*head))
            .cloned()
            .ok_or(C3Failure::Inconsistent)?;
        charge(1)?;
        result.push(candidate.clone());
        for sequence in &mut sequences {
            if sequence.front() == Some(&candidate) {
                sequence.pop_front();
            }
        }
    }
    Ok(result)
}

pub(crate) fn spend_c3(work: &mut usize, amount: usize) -> Result<(), C3Failure> {
    *work = work.saturating_add(amount);
    if *work > MAX_PYTHON_C3_WORK {
        Err(C3Failure::VisitLimit)
    } else {
        Ok(())
    }
}

impl TypeHierarchyProvider for PythonAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw| resolve_base_class(self, token, code_unit, raw))
            // Resolving a base spelling to a value or module does not prove a
            // superclass. In particular, a rebound builtin can name a field.
            .filter(CodeUnit::is_class)
            .collect();
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant index that cannot stop always completes")
    }
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        descendants_from_variant_index(&self.direct_descendant_index, scope, code_unit, || {
            build_direct_descendant_index(self, self, scope)
        })
    }
}
