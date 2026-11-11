use crate::analyzer::python::*;
use brokk_bifrost_analysis::analyzer::semantic_model::python_runtime_bases::{
    MAX_PYTHON_HIERARCHY_VISITS, PythonRuntimeClaimBudget, retain_open_claims,
    runtime_base_claim_declared, runtime_bases,
};
use brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer;

use brokk_bifrost_semantic::analyzer::semantic::type_flow::ClassIdentity;

use brokk_bifrost_semantic::analyzer::semantic::type_flow::ExternalClassCache;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelShard;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeFact;

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

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonMroMember;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonMroMembersAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonOverrideAnswer;

use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonOverrideOutcome;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
// Legacy source-only TypeHierarchyProvider below retains its existing path.
use brokk_bifrost_python::graph_support::resolve_base_class;
use std::collections::VecDeque;
use std::sync::Arc;

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

impl PythonRuntimeClaimBudget for HierarchyBudget<'_> {
    fn charge(&mut self, visits: usize, work: usize) -> Result<(), PythonHierarchyReason> {
        HierarchyBudget::charge(self, visits, work)
    }
    fn has_claim(&self, key: (*const ActiveSemanticModelShard, *const TypeFact)) -> bool {
        self.retained_claims.contains(&key)
    }
    fn mark_claim(&mut self, key: (*const ActiveSemanticModelShard, *const TypeFact)) {
        self.retained_claims.insert(key);
    }
}

impl HierarchyBudget<'_> {
    fn charge(&mut self, visits: usize, work: usize) -> Result<(), PythonHierarchyReason> {
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            self.visits,
            MAX_PYTHON_HIERARCHY_VISITS,
        )
        .allows(visits)
        {
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
        BoundedResolution::Unavailable { .. } => PythonHierarchyReason::UnknownMemberSurface,
        BoundedResolution::Complete { .. } => unreachable!("failed charge has a sticky stop"),
    }
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
            BoundedResolution::Unavailable { .. } => {
                Err(PythonHierarchyReason::UnknownMemberSurface)
            }
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
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                visits,
                MAX_PYTHON_MEMBER_VISITS,
            )
            .allows(0)
            {
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
                // An imported class from a module outside the workspace that
                // no active model covers is an unknown external endpoint, not
                // a base we failed to infer (#10433).
                let (resolution, failure) = if target.is_some() {
                    (
                        PythonBaseResolution::Resolved,
                        PythonHierarchyReason::UnresolvedBase,
                    )
                } else if crate::analyzer::usages::get_definition::python::python_base_imported_from_external_module_bounded(
                    support,
                    scope.token(),
                    owner.source(),
                    prepared.source(),
                    prepared.tree().root_node(),
                    expression,
                )
                // A stopped walk proves nothing; the failed answer stands.
                .unwrap_or(false)
                {
                    (
                        PythonBaseResolution::External,
                        PythonHierarchyReason::ExternalBase,
                    )
                } else {
                    (
                        PythonBaseResolution::Unresolved,
                        PythonHierarchyReason::UnresolvedBase,
                    )
                };
                if let Some(facts) = &mut root_facts {
                    facts.push(PythonBaseFact {
                        origin: PythonBaseOrigin::Source,
                        ordinal,
                        spelling: raw,
                        resolution,
                        target: target.clone(),
                    });
                }
                bases.push(target.ok_or(failure)?);
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
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                visits,
                MAX_PYTHON_MEMBER_VISITS,
            )
            .allows(0)
            {
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
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let ancestors = super::read_memo(
            self,
            &self.direct_ancestors,
            code_unit.clone(),
            || {
                Arc::new(
                    self.inner
                        .raw_supertypes_of(code_unit)
                        .iter()
                        .filter_map(|raw| resolve_base_class(self, token, code_unit, raw))
                        .filter(CodeUnit::is_class)
                        .collect(),
                )
            },
            super::weight_code_unit_vec,
        );
        HierarchyAnswer::complete((*ancestors).clone())
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a whole-workspace descendant query cannot be cancelled")
    }
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.direct_descendant_index.read(
            &super::memo_attribution(self),
            |(memo, _)| {
                brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
                    self,
                    scope,
                    code_unit,
                    memo,
                    || build_direct_descendant_index(self, self, scope),
                    |_| {},
                )
            },
            |answer| {
                if answer.as_ref().is_ok_and(|answer| answer.is_complete()) {
                    self.descendants_authority_digest()
                        .map_or(super::AuthorityInputs::Unnamed, super::whole_fact)
                } else {
                    // A stopped build has no answer to certify. Do not start
                    // an unbounded build after the request has stopped.
                    super::AuthorityInputs::Unnamed
                }
            },
        )
    }
}
