use super::*;
use crate::analyzer::usages::python_class_hierarchy::{
    PythonBaseFact, PythonBaseResolution, PythonClassHierarchyAnswer, PythonClassHierarchyProvider,
    PythonHierarchyOutcome, PythonHierarchyReason, PythonMroMember, PythonMroMembersAnswer,
    PythonOverrideAnswer, PythonOverrideOutcome,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    DescendantIndexScope, build_direct_descendant_index, descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_python::graph_support::resolve_base_class;
use std::collections::VecDeque;
use std::sync::Arc;

const MAX_PYTHON_HIERARCHY_VISITS: usize = 4096;
const MAX_PYTHON_C3_WORK: usize = 65_536;
const MAX_PYTHON_MEMBER_VISITS: usize = 32_768;

struct ResolvedClassNode {
    bases: Vec<CodeUnit>,
}

enum ClassWork {
    Enter(CodeUnit),
    Exit(CodeUnit),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClassVisit {
    Visiting,
    Done,
}

enum C3Failure {
    Inconsistent,
    VisitLimit,
    Cancelled,
}

impl PythonClassHierarchyProvider for PythonAnalyzer {
    fn class_hierarchy(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonClassHierarchyAnswer {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return PythonClassHierarchyAnswer::stopped(
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::Cancelled,
                Vec::new(),
            );
        }
        if !class.is_class() {
            return PythonClassHierarchyAnswer::stopped(
                PythonHierarchyOutcome::Unsupported,
                PythonHierarchyReason::NotClass,
                Vec::new(),
            );
        }
        if class.is_synthetic() {
            return PythonClassHierarchyAnswer::stopped(
                PythonHierarchyOutcome::Incomplete,
                PythonHierarchyReason::ExternalBase,
                Vec::new(),
            );
        }

        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let mut stack = vec![ClassWork::Enter(class.clone())];
        let mut states = HashMap::<CodeUnit, ClassVisit>::default();
        let mut nodes = HashMap::<CodeUnit, ResolvedClassNode>::default();
        let mut linearizations = HashMap::<CodeUnit, Vec<CodeUnit>>::default();
        let mut root_bases = Vec::new();
        let mut visits = 0usize;
        let mut c3_work = 0usize;

        while let Some(work) = stack.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return PythonClassHierarchyAnswer::stopped(
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::Cancelled,
                    root_bases,
                );
            }

            let current = match work {
                ClassWork::Enter(current) => match states.get(&current) {
                    Some(ClassVisit::Done) => continue,
                    Some(ClassVisit::Visiting) => {
                        return PythonClassHierarchyAnswer::stopped(
                            PythonHierarchyOutcome::Inconsistent,
                            PythonHierarchyReason::CyclicBases,
                            root_bases,
                        );
                    }
                    None => current,
                },
                ClassWork::Exit(current) => {
                    let node = nodes
                        .get(&current)
                        .expect("entered class has a resolved node");
                    match merge_c3(
                        &current,
                        &node.bases,
                        &linearizations,
                        &mut c3_work,
                        cancellation,
                    ) {
                        Ok(mro) => {
                            linearizations.insert(current.clone(), mro);
                            states.insert(current, ClassVisit::Done);
                        }
                        Err(C3Failure::Inconsistent) => {
                            return PythonClassHierarchyAnswer::stopped(
                                PythonHierarchyOutcome::Inconsistent,
                                PythonHierarchyReason::InconsistentLinearization,
                                root_bases,
                            );
                        }
                        Err(C3Failure::VisitLimit) => {
                            return PythonClassHierarchyAnswer::stopped(
                                PythonHierarchyOutcome::Incomplete,
                                PythonHierarchyReason::VisitLimit,
                                root_bases,
                            );
                        }
                        Err(C3Failure::Cancelled) => {
                            return PythonClassHierarchyAnswer::stopped(
                                PythonHierarchyOutcome::Incomplete,
                                PythonHierarchyReason::Cancelled,
                                root_bases,
                            );
                        }
                    }
                    continue;
                }
            };

            if visits == MAX_PYTHON_HIERARCHY_VISITS {
                return PythonClassHierarchyAnswer::stopped(
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::VisitLimit,
                    root_bases,
                );
            }
            visits += 1;
            if current.is_synthetic() {
                return PythonClassHierarchyAnswer::stopped(
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::ExternalBase,
                    root_bases,
                );
            }

            let raw_bases = self.inner.raw_supertypes_of(&current);
            let mut base_facts = Vec::with_capacity(raw_bases.len());
            let mut resolved_bases = Vec::with_capacity(raw_bases.len());
            let mut seen_bases = HashSet::default();
            let mut failure = None;
            for (ordinal, raw) in raw_bases.into_iter().enumerate() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    let bases = if current == *class {
                        base_facts
                    } else {
                        root_bases
                    };
                    return PythonClassHierarchyAnswer::stopped(
                        PythonHierarchyOutcome::Incomplete,
                        PythonHierarchyReason::Cancelled,
                        bases,
                    );
                }
                if visits == MAX_PYTHON_HIERARCHY_VISITS {
                    let bases = if current == *class {
                        base_facts
                    } else {
                        root_bases
                    };
                    return PythonClassHierarchyAnswer::stopped(
                        PythonHierarchyOutcome::Incomplete,
                        PythonHierarchyReason::VisitLimit,
                        bases,
                    );
                }
                visits += 1;
                let target = resolve_base_class(self, token, &current, &raw);
                let (resolution, target) = match target {
                    // Intrinsic builtin roots have no source CodeUnit. Their
                    // identity must be established from the selected base AST
                    // node and lexical bindings before treating them as leaves.
                    None if super::type_flow::python_intrinsic_base_is_unshadowed(
                        self, &current, &raw,
                    ) =>
                    {
                        (PythonBaseResolution::Resolved, None)
                    }
                    None => {
                        failure.get_or_insert((
                            PythonHierarchyOutcome::Incomplete,
                            PythonHierarchyReason::UnresolvedBase,
                        ));
                        (PythonBaseResolution::Unresolved, None)
                    }
                    Some(target) if !target.is_class() => {
                        failure.get_or_insert((
                            PythonHierarchyOutcome::Incomplete,
                            PythonHierarchyReason::NonClassBase,
                        ));
                        (PythonBaseResolution::NonClass, Some(target))
                    }
                    Some(target) if target.is_synthetic() => {
                        failure.get_or_insert((
                            PythonHierarchyOutcome::Incomplete,
                            PythonHierarchyReason::ExternalBase,
                        ));
                        (PythonBaseResolution::External, Some(target))
                    }
                    Some(target) if !seen_bases.insert(target.clone()) => {
                        failure = Some((
                            PythonHierarchyOutcome::Inconsistent,
                            PythonHierarchyReason::DuplicateBase,
                        ));
                        (PythonBaseResolution::Resolved, Some(target))
                    }
                    Some(target) => {
                        resolved_bases.push(target.clone());
                        (PythonBaseResolution::Resolved, Some(target))
                    }
                };
                base_facts.push(PythonBaseFact {
                    ordinal,
                    spelling: raw,
                    resolution,
                    target,
                });
            }

            if current == *class {
                root_bases = base_facts;
            }
            if let Some((outcome, reason)) = failure {
                return PythonClassHierarchyAnswer::stopped(outcome, reason, root_bases);
            }

            nodes.insert(
                current.clone(),
                ResolvedClassNode {
                    bases: resolved_bases.clone(),
                },
            );
            states.insert(current.clone(), ClassVisit::Visiting);
            stack.push(ClassWork::Exit(current));
            for base in resolved_bases.into_iter().rev() {
                stack.push(ClassWork::Enter(base));
            }
        }

        let mro = linearizations
            .remove(class)
            .expect("complete class walk produces the selected class MRO");
        PythonClassHierarchyAnswer::complete(root_bases, mro)
    }

    fn mro_members(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer {
        let hierarchy = self.class_hierarchy(class, cancellation);
        self.mro_members_from_hierarchy(hierarchy, cancellation)
    }

    fn method_override(
        &self,
        method: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonOverrideAnswer {
        if !method.is_function() {
            return PythonOverrideAnswer::stopped(
                PythonOverrideOutcome::Unsupported,
                Some(PythonHierarchyReason::NotClass),
                None,
            );
        }
        let Some(owner) = self.parent_of(method).filter(CodeUnit::is_class) else {
            return PythonOverrideAnswer::stopped(
                PythonOverrideOutcome::Unsupported,
                Some(PythonHierarchyReason::NotClass),
                None,
            );
        };
        let hierarchy = self.class_hierarchy(&owner, cancellation);
        if hierarchy.outcome != PythonHierarchyOutcome::Complete {
            return PythonOverrideAnswer::stopped(
                match hierarchy.outcome {
                    PythonHierarchyOutcome::Unsupported => PythonOverrideOutcome::Unsupported,
                    _ => PythonOverrideOutcome::Incomplete,
                },
                hierarchy.reason,
                Some(owner),
            );
        }
        let name = method.terminal_name();
        let mut visits = 0usize;
        for (rank, mro_owner) in hierarchy.mro.iter().enumerate() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return PythonOverrideAnswer::stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::Cancelled),
                    Some(owner),
                );
            }
            let declarations = self.direct_children_in_source_order(mro_owner);
            visits = visits.saturating_add(declarations.len());
            if visits > MAX_PYTHON_MEMBER_VISITS {
                return PythonOverrideAnswer::stopped(
                    PythonOverrideOutcome::Incomplete,
                    Some(PythonHierarchyReason::VisitLimit),
                    Some(owner),
                );
            }
            let selected = declarations
                .into_iter()
                .rev()
                .find(|declaration| declaration.terminal_name() == name);
            if rank == 0 {
                if selected.as_ref() != Some(method) {
                    return PythonOverrideAnswer::stopped(
                        PythonOverrideOutcome::Unsupported,
                        Some(PythonHierarchyReason::NotEffectiveMember),
                        Some(owner),
                    );
                }
                continue;
            }
            let Some(target) = selected else {
                continue;
            };
            if target.is_function() {
                return PythonOverrideAnswer {
                    outcome: PythonOverrideOutcome::Overrides,
                    reason: None,
                    source_owner: Some(owner),
                    target: Some(target),
                    target_owner: Some(mro_owner.clone()),
                    mro_rank: Some(rank),
                };
            }
            return PythonOverrideAnswer::stopped(
                PythonOverrideOutcome::NoOverride,
                None,
                Some(owner),
            );
        }
        PythonOverrideAnswer::stopped(PythonOverrideOutcome::NoOverride, None, Some(owner))
    }
}

impl PythonAnalyzer {
    fn mro_members_from_hierarchy(
        &self,
        mut hierarchy: PythonClassHierarchyAnswer,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer {
        if hierarchy.outcome != PythonHierarchyOutcome::Complete {
            return PythonMroMembersAnswer {
                hierarchy,
                members: Vec::new(),
            };
        }
        let mut selected = HashSet::<String>::default();
        let mut members = Vec::new();
        let mut visits = 0usize;
        for (rank, owner) in hierarchy.mro.iter().enumerate() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                hierarchy = PythonClassHierarchyAnswer::stopped(
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::Cancelled,
                    hierarchy.bases,
                );
                return PythonMroMembersAnswer {
                    hierarchy,
                    members: Vec::new(),
                };
            }
            let declarations = self.direct_children_in_source_order(owner);
            visits = visits.saturating_add(declarations.len());
            if visits > MAX_PYTHON_MEMBER_VISITS {
                hierarchy = PythonClassHierarchyAnswer::stopped(
                    PythonHierarchyOutcome::Incomplete,
                    PythonHierarchyReason::VisitLimit,
                    hierarchy.bases,
                );
                return PythonMroMembersAnswer {
                    hierarchy,
                    members: Vec::new(),
                };
            }
            for member in declarations.into_iter().rev() {
                let name = member.terminal_name().to_owned();
                if selected.insert(name.clone()) {
                    members.push(PythonMroMember {
                        name,
                        member,
                        owner: owner.clone(),
                        rank,
                    });
                }
            }
        }
        members.sort_by(|left, right| (left.rank, &left.name).cmp(&(right.rank, &right.name)));
        PythonMroMembersAnswer { hierarchy, members }
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

fn merge_c3(
    class: &CodeUnit,
    bases: &[CodeUnit],
    linearizations: &HashMap<CodeUnit, Vec<CodeUnit>>,
    work: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<CodeUnit>, C3Failure> {
    let mut sequences = Vec::<VecDeque<CodeUnit>>::with_capacity(bases.len() + 1);
    for base in bases {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(C3Failure::Cancelled);
        }
        let base_mro = linearizations
            .get(base)
            .expect("base MRO is complete before its subclass");
        spend_c3(work, base_mro.len())?;
        sequences.push(base_mro.iter().cloned().collect());
    }
    spend_c3(work, bases.len())?;
    sequences.push(bases.iter().cloned().collect());

    let mut result = vec![class.clone()];
    while sequences.iter().any(|sequence| !sequence.is_empty()) {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(C3Failure::Cancelled);
        }
        let mut tails = HashSet::<CodeUnit>::default();
        for sequence in &sequences {
            for tail in sequence.iter().skip(1) {
                spend_c3(work, 1)?;
                tails.insert(tail.clone());
            }
        }
        let candidate = sequences
            .iter()
            .filter_map(VecDeque::front)
            .find(|head| !tails.contains(*head))
            .cloned()
            .ok_or(C3Failure::Inconsistent)?;
        spend_c3(work, 1)?;
        result.push(candidate.clone());
        for sequence in &mut sequences {
            if sequence.front() == Some(&candidate) {
                sequence.pop_front();
            }
        }
    }
    Ok(result)
}

fn spend_c3(work: &mut usize, amount: usize) -> Result<(), C3Failure> {
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
