//! Query-local typestate label relations for composition paths.

use super::*;
use crate::analyzer::semantic::partial_flow::PartialFlowPort;
use crate::taint::compose::{ComposeLabels, HopQuality, ObjectAnchor, ObjectReach, SearchOutcome};
use crate::typestate::call_map::SubjectUnprovenPort;
use crate::value_flow::DurableCallSiteKey;
use crate::value_flow::DurableProcedureKey;

/// The first subject-bound unresolved relation retained by one path.
/// A Guard belongs to the alias arm and retains that arm's continuation;
/// the no-alias arm has no Guard relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FirstUnprovenRelation {
    Handoff(Box<SubjectUnprovenPort>),
    UnresolvedCall {
        call: Box<DurableCallSiteKey>,
        argument: PartialFlowPort,
        continuation: PartialFlowPort,
        subject: TypestateSubjectId,
    },
    UnprovenConversion {
        call: Box<DurableCallSiteKey>,
        argument: PartialFlowPort,
        continuation: PartialFlowPort,
        subject: TypestateSubjectId,
    },
    Guard {
        guard: Box<TypestateAliasGuard>,
        subject: TypestateSubjectId,
        site: Box<DurableCallSiteKey>,
    },
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    use crate::analyzer::semantic::*;
    use crate::typestate::{
        ProtocolAnalysisMode, ProtocolSemantics, ProtocolSpec, ProtocolUncertaintyBehavior,
        ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior,
    };
    use brokk_bifrost_core::analyzer::model::Language;

    #[test]
    fn distinct_first_relations_survive_then_choice_and_projection() {
        let artifact = SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"relation-test"),
            WorkspaceRelativePath::new("src/Model.java").unwrap(),
            SemanticLanguage::Standard(Language::Java),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"source"),
            },
            AdapterSemanticsVersion::hash_bytes("relation-test", b"1").unwrap(),
            SemanticIrVersion::current(),
            ConfigurationFingerprint::hash_bytes(b"config"),
            DependencyFingerprint::hash_bytes(b"deps"),
        );
        let guard = TypestateAliasGuard::new(
            (artifact, ProcedureId::new(0)),
            PartialFlowPort::Parameter { ordinal: 0 },
            PartialFlowPort::Parameter { ordinal: 1 },
        );
        let first = FirstUnprovenRelation::Guard {
            guard: Box::new(guard.clone()),
            subject: TypestateSubjectId::new(0),
            site: Box::new((guard.procedure().clone(), CallSiteId::new(0))),
        };
        let second = FirstUnprovenRelation::Guard {
            site: Box::new((guard.procedure().clone(), CallSiteId::new(1))),
            guard: Box::new(guard),
            subject: TypestateSubjectId::new(1),
        };
        let tail = TypestateComposeFunction::identity();
        let paths = TypestateComposeFunction::choice_functions([
            TypestateComposeFunction::first_unproven(first.clone()).then(tail.clone()),
            TypestateComposeFunction::first_unproven(second.clone()).then(tail),
        ]);
        let uncertainty = ProtocolUncertaintyBehavior::PreserveUncertainty;
        let protocol = ProtocolSpec {
            schema_version: crate::typestate::PROTOCOL_SCHEMA_VERSION,
            states: vec!["ready".into()],
            initial_state: "ready".into(),
            accepting_states: vec!["ready".into()],
            error_states: vec![],
            events: vec![],
            transitions: vec![],
            terminal_expectations: vec![],
            semantics: ProtocolSemantics {
                analysis_mode: ProtocolAnalysisMode::May,
                unmatched_event: ProtocolUnmatchedEventBehavior::MarkInconclusive,
                uncertainty: ProtocolUncertaintySemantics {
                    ambiguous_dispatch: uncertainty,
                    unknown_call: uncertainty,
                    external_call: uncertainty,
                    escape: uncertainty,
                    incomplete_analysis: uncertainty,
                },
            },
        }
        .compile()
        .unwrap();
        let bindings =
            TypestateBindingPlan::try_new(&protocol, vec![], vec![], vec![], vec![]).unwrap();
        let labels = TypestateComposeLabels::new(&protocol, &bindings);
        let seed = TypestateComposeFact::new([TypestateFact::zero()]);
        let pairs = labels.apply_with_first_unproven(&paths, &seed);
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&(
            TypestateFact::zero(),
            FirstUnprovenEvent::Relation(first.clone())
        )));
        assert!(pairs.contains(&(
            TypestateFact::zero(),
            FirstUnprovenEvent::Relation(second.clone())
        )));
        let grouped = labels.apply_with_grouped_first_unproven(&paths, &seed);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].1.len(), 2);
        let first_then_second = TypestateComposeFunction::first_unproven(first.clone())
            .then(TypestateComposeFunction::first_unproven(second.clone()));
        assert_eq!(
            labels.apply_with_first_unproven(&first_then_second, &seed),
            vec![(
                TypestateFact::zero(),
                FirstUnprovenEvent::Relation(first.clone())
            )]
        );
        let loss_then_relation =
            TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis)
                .then(TypestateComposeFunction::first_unproven(first.clone()));
        assert_eq!(
            labels.apply_with_first_unproven(&loss_then_relation, &seed)[0].1,
            FirstUnprovenEvent::Lost
        );
        let relation_then_loss = TypestateComposeFunction::first_unproven(first).then(
            TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis),
        );
        assert!(matches!(
            labels.apply_with_first_unproven(&relation_then_loss, &seed)[0].1,
            FirstUnprovenEvent::Relation(_)
        ));
        let open_guard = TypestateComposeFunction::guarded(
            match &second {
                FirstUnprovenRelation::Guard { guard, .. } => *guard.clone(),
                _ => unreachable!(),
            },
            TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis),
            TypestateComposeFunction::first_unproven(second.clone()).then(
                TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis),
            ),
        );
        let guard_pairs = labels.apply_with_first_unproven(&open_guard, &seed);
        assert!(
            guard_pairs
                .iter()
                .any(|(_, event)| event == &FirstUnprovenEvent::Lost)
        );
        assert!(
            guard_pairs
                .iter()
                .any(|(_, event)| event == &FirstUnprovenEvent::Relation(second.clone()))
        );
        let recursive_reentry =
            TypestateComposeFunction::incomplete(TypestateUncertainty::IncompleteAnalysis);
        assert_eq!(
            labels.apply_with_first_unproven(&recursive_reentry, &seed)[0].1,
            FirstUnprovenEvent::Lost
        );
        let baseline =
            labels.apply_with_first_unproven(&TypestateComposeFunction::identity(), &seed);
        let loss =
            labels.apply_with_first_unproven(&TypestateComposeFunction::unproven_hop_loss(), &seed);
        assert_eq!(loss[0].0, baseline[0].0);
        assert_eq!(loss[0].1, FirstUnprovenEvent::Lost);

        let proven_incomplete = HopQuality::new(true, false);
        let function = if proven_incomplete.proven {
            TypestateComposeFunction::identity()
        } else {
            TypestateComposeFunction::unproven_hop_loss()
        };
        assert_eq!(labels.apply_with_first_unproven(&function, &seed), baseline);
    }
}

/// First uncertainty event on a single composed alternative.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FirstUnprovenEvent {
    None,
    Relation(FirstUnprovenRelation),
    Lost,
}

type FirstUnprovenPairs = Vec<(TypestateFact, FirstUnprovenEvent)>;
type GroupedFirstUnproven = Vec<(TypestateFact, Box<[FirstUnprovenEvent]>)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstUnprovenRelationKind {
    Handoff,
    UnresolvedCall,
    UnprovenConversion,
    Guard,
}

impl FirstUnprovenRelation {
    pub fn kind(&self) -> FirstUnprovenRelationKind {
        match self {
            Self::Handoff(_) => FirstUnprovenRelationKind::Handoff,
            Self::UnresolvedCall { .. } => FirstUnprovenRelationKind::UnresolvedCall,
            Self::UnprovenConversion { .. } => FirstUnprovenRelationKind::UnprovenConversion,
            Self::Guard { .. } => FirstUnprovenRelationKind::Guard,
        }
    }
    pub(crate) fn handoff(port: SubjectUnprovenPort) -> Self {
        debug_assert_ne!(port.source(), port.continuation());
        Self::Handoff(Box::new(port))
    }
    pub fn subject(&self) -> TypestateSubjectId {
        match self {
            Self::Handoff(port) => port.subject(),
            Self::Guard { subject, .. }
            | Self::UnresolvedCall { subject, .. }
            | Self::UnprovenConversion { subject, .. } => *subject,
        }
    }
    pub fn site(&self) -> &DurableCallSiteKey {
        match self {
            Self::Handoff(port) => port.site(),
            Self::UnresolvedCall { call, .. } | Self::UnprovenConversion { call, .. } => call,
            Self::Guard { site, .. } => site,
        }
    }
    pub fn source(&self) -> &PartialFlowPort {
        match self {
            Self::Handoff(port) => port.source(),
            Self::UnresolvedCall { argument, .. } | Self::UnprovenConversion { argument, .. } => {
                argument
            }
            Self::Guard { guard, .. } => guard.first(),
        }
    }
    pub fn continuation(&self) -> &PartialFlowPort {
        match self {
            Self::Handoff(port) => port.continuation(),
            Self::UnresolvedCall { continuation, .. }
            | Self::UnprovenConversion { continuation, .. } => continuation,
            Self::Guard { guard, .. } => guard.second(),
        }
    }
    fn remap(mut self, from: TypestateSubjectId, to: TypestateSubjectId) -> Self {
        match &mut self {
            Self::Handoff(port) if port.subject() == from => port.remap_subject(to),
            Self::Guard { subject, .. }
            | Self::UnresolvedCall { subject, .. }
            | Self::UnprovenConversion { subject, .. }
                if *subject == from =>
            {
                *subject = to
            }
            _ => {}
        }
        self
    }
}

/// The state relation at one retained hop, in source-to-terminal order.
#[derive(Debug, Clone)]
pub struct TypestateHopObservation {
    pub hop_index: usize,
    pub before: TypestateComposeFact,
    pub after: TypestateComposeFact,
    pub quality: HopQuality,
    pub events: Vec<TypestateEventObservation>,
}

#[derive(Debug, Clone)]
pub struct TypestateEventObservation {
    pub binding: TypestateEventBindingId,
    pub before: TypestateComposeFact,
    pub after: TypestateComposeFact,
}

/// Fold only evidence already retained by the search. This performs no new
/// graph traversal or witness solve; each hop names its interned function.
pub fn fold_object_reach(
    reach: &ObjectReach<TypestateComposeFact>,
    outcome: &SearchOutcome<TypestateComposeLabels<'_>>,
) -> Vec<TypestateHopObservation> {
    let mut current = reach.source.fact.clone();
    let mut observations = Vec::with_capacity(reach.hops.len());
    for (hop_index, hop) in reach.hops.iter().enumerate() {
        let before = current.clone();
        let events = if let Some(function) = hop.function() {
            let (after, events) = outcome
                .functions
                .labels()
                .apply_with_events(outcome.functions.function(function), &current);
            current = after;
            events
        } else {
            Vec::new()
        };
        observations.push(TypestateHopObservation {
            hop_index,
            before,
            after: current.clone(),
            quality: hop.quality(),
            events,
        });
    }
    debug_assert_eq!(
        current,
        outcome.functions.labels().apply(
            outcome.functions.function(reach.function),
            &reach.source.fact
        ),
        "retained hops compose to the search's path function"
    );
    observations
}

#[derive(Debug, Clone)]
pub struct TypestateObjectJudgment {
    pub binding: TypestateTerminalBindingId,
    pub root: ObjectAnchor,
    pub reached: TypestateComposeFact,
    pub quality: HopQuality,
    pub complete: bool,
    pub closed: bool,
}

/// Judge the whole alternative set of every demanded object terminal. A
/// uncertain hop, abstention, or incomplete search cannot prove closure.
pub fn judge_object_roots(
    roots: &[(TypestateTerminalBindingId, ObjectAnchor)],
    outcome: &SearchOutcome<TypestateComposeLabels<'_>>,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
) -> Vec<TypestateObjectJudgment> {
    roots
        .iter()
        .map(|(binding_id, root)| {
            let binding = bindings
                .terminal_binding(*binding_id)
                .expect("terminal root names a compiled binding");
            let expectation = protocol
                .terminal_expectation(binding.expectation())
                .expect("terminal binding names a compiled expectation");
            let mut alternatives = Vec::new();
            let mut quality = HopQuality::CERTAIN;
            let mut paths = 0_usize;
            for reach in outcome
                .object_reaches
                .iter()
                .filter(|reach| &reach.root == root)
            {
                let function = outcome.functions.function(reach.function);
                if function.is_absent() {
                    continue;
                }
                paths += 1;
                quality = quality.conjoin(reach.quality);
                let reached = outcome
                    .functions
                    .labels()
                    .apply(function, &reach.source.fact);
                if function.has_unresolved_guard() {
                    quality = quality.conjoin(HopQuality::UNCERTAIN);
                    debug_assert!(!quality.is_certain());
                }
                alternatives.extend_from_slice(reached.alternatives());
            }
            let reached = TypestateComposeFact::new(alternatives);
            // A complete zero-reach search proves that this object is absent
            // at the exit. Rust unwind drop glue must be modeled by search;
            // a gap on that exceptional path keeps the search incomplete.
            let complete = outcome.incomplete.is_empty()
                && quality.is_certain()
                && binding.quality().is_definitive()
                && bindings
                    .subject(binding.subject())
                    .is_some_and(|subject| subject.quality().is_definitive())
                && reached
                    .alternatives()
                    .iter()
                    .all(|fact| fact.uncertainty().is_empty() && !fact.abstained());
            let closed = if paths == 0 && complete {
                true
            } else {
                reached.proves_closed(expectation.expected_states(), quality, complete)
            };
            TypestateObjectJudgment {
                binding: *binding_id,
                root: root.clone(),
                reached,
                quality,
                complete,
                closed,
            }
        })
        .collect()
}

/// Alternatives at one port. Every alternative keeps its own uncertainty and
/// abstention, so an incomplete branch cannot certify a clean path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateComposeFact(Box<[TypestateFact]>);

impl TypestateComposeFact {
    pub fn formal_entry(
        bindings: &TypestateBindingPlan,
        subject: TypestateSubjectId,
        initial_state: ProtocolStateId,
    ) -> Self {
        Self::new([TypestateFact::summary_state(
            bindings.hash(),
            subject,
            initial_state,
            TypestateUncertaintySet(0),
            false,
        )])
    }

    pub fn from_initial_seed(
        bindings: &TypestateBindingPlan,
        seed: &BoundTypestateInitialSeed,
    ) -> Self {
        let fact = TypestateFact::summary_state(
            bindings.hash(),
            seed.subject(),
            seed.state(),
            TypestateUncertaintySet(0),
            false,
        );
        Self::new([if seed.quality().is_definitive() {
            fact
        } else {
            mark_incomplete(fact, TypestateUncertainty::IncompleteAnalysis)
        }])
    }

    pub fn new(facts: impl IntoIterator<Item = TypestateFact>) -> Self {
        let mut facts: Vec<_> = facts.into_iter().collect();
        facts.sort_unstable();
        facts.dedup();
        Self(facts.into())
    }

    pub fn alternatives(&self) -> &[TypestateFact] {
        &self.0
    }

    /// A negative lifecycle proof needs every live alternative closed and
    /// every traversed hop and search inventory complete. Observation facts
    /// remain evidence, but a violation or uncertain observation vetoes it.
    pub fn proves_closed(
        &self,
        expected_states: &[ProtocolStateId],
        quality: crate::taint::compose::HopQuality,
        search_complete: bool,
    ) -> bool {
        if !search_complete || !quality.is_certain() || self.0.is_empty() {
            return false;
        }
        let mut saw_state = false;
        for fact in &self.0 {
            if !fact.uncertainty().is_empty() || fact.abstained() {
                return false;
            }
            match fact.0 {
                TypestateFactKind::State { state, .. }
                | TypestateFactKind::Terminal { state, .. } => {
                    saw_state = true;
                    if expected_states.binary_search(&state).is_err() {
                        return false;
                    }
                }
                TypestateFactKind::Violation { .. } | TypestateFactKind::Zero => return false,
                TypestateFactKind::NonViolation { .. } => {}
            }
        }
        saw_state
    }
}

/// One primitive transition of a query-local path relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateComposeStep {
    Event(TypestateEventBindingId),
    Incomplete(TypestateUncertainty),
    MapSubject {
        from: TypestateSubjectId,
        to: TypestateSubjectId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Segment {
    Absent,
    Step(TypestateComposeStep),
    FirstUnproven(Box<FirstUnprovenRelation>),
    UnprovenHopLoss,
    Choice(Box<[TypestateComposeFunction]>),
    Guarded {
        guard: Box<TypestateAliasGuard>,
        no_alias: Box<TypestateComposeFunction>,
        alias: Box<TypestateComposeFunction>,
    },
}

/// A summary-local obligation about two formals of one procedure. It never
/// contains caller values, points, contexts, or an oracle answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateAliasGuard {
    procedure: DurableProcedureKey,
    first: PartialFlowPort,
    second: PartialFlowPort,
    candidate_member_subject: Option<TypestateSubjectId>,
    selected_site: Option<DurableCallSiteKey>,
}

pub enum TypestateGuardResolution {
    NoAlias,
    Alias,
    Keep(TypestateAliasGuard),
    Open(TypestateAliasGuard),
}

impl TypestateAliasGuard {
    pub fn new(
        procedure: DurableProcedureKey,
        first: PartialFlowPort,
        second: PartialFlowPort,
    ) -> Self {
        assert_ne!(first, second);
        assert!(matches!(
            first,
            PartialFlowPort::Parameter { .. } | PartialFlowPort::Receiver
        ));
        assert!(matches!(
            second,
            PartialFlowPort::Parameter { .. } | PartialFlowPort::Receiver
        ));
        Self {
            procedure,
            first,
            second,
            candidate_member_subject: None,
            selected_site: None,
        }
    }

    pub(crate) fn with_candidate_member_subject(mut self, subject: TypestateSubjectId) -> Self {
        self.candidate_member_subject = Some(subject);
        self
    }
    pub(crate) fn with_selected_site(mut self, site: DurableCallSiteKey) -> Self {
        self.selected_site = Some(site);
        self
    }

    pub(crate) fn candidate_member_subject(&self) -> Option<TypestateSubjectId> {
        self.candidate_member_subject
    }

    pub fn procedure(&self) -> &DurableProcedureKey {
        &self.procedure
    }
    pub fn first(&self) -> &PartialFlowPort {
        &self.first
    }
    pub fn second(&self) -> &PartialFlowPort {
        &self.second
    }
}

/// Ordered local transitions with finite alternatives at branch points.
/// Composition appends segments instead of multiplying branch paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateComposeFunction(Box<[Segment]>);

impl TypestateComposeFunction {
    pub fn then(mut self, next: Self) -> Self {
        if self.is_absent() || next.is_absent() {
            return Self::absent();
        }
        let mut segments = self.0.into_vec();
        segments.extend(next.0);
        self.0 = segments.into();
        self
    }

    pub fn identity() -> Self {
        Self(Box::new([]))
    }

    pub fn absent() -> Self {
        Self(vec![Segment::Absent].into())
    }

    pub fn is_absent(&self) -> bool {
        matches!(self.0.as_ref(), [Segment::Absent])
    }

    pub fn has_unresolved_guard(&self) -> bool {
        let mut pending = vec![self];
        while let Some(function) = pending.pop() {
            for segment in &function.0 {
                match segment {
                    Segment::Guarded { .. } => return true,
                    Segment::Choice(paths) => pending.extend(paths.iter()),
                    Segment::Step(_)
                    | Segment::Absent
                    | Segment::FirstUnproven(_)
                    | Segment::UnprovenHopLoss => {}
                }
            }
        }
        false
    }

    pub fn map_subject(from: TypestateSubjectId, to: TypestateSubjectId) -> Self {
        Self(vec![Segment::Step(TypestateComposeStep::MapSubject { from, to })].into())
    }

    pub fn event(binding: TypestateEventBindingId) -> Self {
        Self(vec![Segment::Step(TypestateComposeStep::Event(binding))].into())
    }

    pub fn incomplete(cause: TypestateUncertainty) -> Self {
        Self(vec![Segment::Step(TypestateComposeStep::Incomplete(cause))].into())
    }

    pub(crate) fn first_unproven(relation: FirstUnprovenRelation) -> Self {
        Self(vec![Segment::FirstUnproven(Box::new(relation))].into())
    }

    pub(crate) fn unproven_hop_loss() -> Self {
        Self(vec![Segment::UnprovenHopLoss].into())
    }

    pub fn choice(paths: impl IntoIterator<Item = Vec<TypestateComposeStep>>) -> Self {
        Self::choice_functions(paths.into_iter().map(Self::from_steps))
    }

    pub fn from_steps(steps: impl IntoIterator<Item = TypestateComposeStep>) -> Self {
        Self(steps.into_iter().map(Segment::Step).collect())
    }

    pub fn choice_functions(paths: impl IntoIterator<Item = Self>) -> Self {
        let mut paths: Vec<_> = paths.into_iter().collect();
        paths.retain(|path| !path.is_absent());
        if paths.is_empty() {
            return Self::absent();
        }
        let mut seen = std::collections::HashSet::new();
        paths.retain(|path| seen.insert(path.clone()));
        if paths.len() == 1 {
            return paths.pop().expect("one retained alternative");
        }
        Self(vec![Segment::Choice(paths.into())].into())
    }

    pub fn guarded(guard: TypestateAliasGuard, no_alias: Self, alias: Self) -> Self {
        if no_alias.is_absent() && alias.is_absent() {
            return Self::absent();
        }
        Self(
            vec![Segment::Guarded {
                guard: Box::new(guard),
                no_alias: Box::new(no_alias),
                alias: Box::new(alias),
            }]
            .into(),
        )
    }

    /// Rewrite every nested obligation without a recursive Rust walk. An
    /// untranslatable pair retains both arms and adds independent uncertainty.
    pub fn try_rewrite_guards<E>(
        &self,
        mut resolve: impl FnMut(&TypestateAliasGuard) -> Result<TypestateGuardResolution, E>,
    ) -> Result<Self, E> {
        enum Task<'a> {
            Function(&'a TypestateComposeFunction),
            Segment(&'a Segment),
            FinishFunction(usize),
            FinishChoice(usize),
            FinishGuard(Box<TypestateAliasGuard>, bool),
        }
        let mut tasks = vec![Task::Function(self)];
        let mut built = Vec::<Self>::new();
        while let Some(task) = tasks.pop() {
            match task {
                Task::Function(function) => {
                    tasks.push(Task::FinishFunction(function.0.len()));
                    tasks.extend(function.0.iter().rev().map(Task::Segment));
                }
                Task::Segment(Segment::Step(step)) => built.push(Self::from_steps([*step])),
                Task::Segment(Segment::FirstUnproven(relation)) => {
                    built.push(Self::first_unproven((**relation).clone()))
                }
                Task::Segment(Segment::UnprovenHopLoss) => built.push(Self::unproven_hop_loss()),
                Task::Segment(Segment::Absent) => built.push(Self::absent()),
                Task::Segment(Segment::Choice(paths)) => {
                    tasks.push(Task::FinishChoice(paths.len()));
                    tasks.extend(paths.iter().rev().map(Task::Function));
                }
                Task::Segment(Segment::Guarded {
                    guard,
                    no_alias,
                    alias,
                }) => match resolve(guard)? {
                    TypestateGuardResolution::NoAlias => tasks.push(Task::Function(no_alias)),
                    TypestateGuardResolution::Alias => tasks.push(Task::Function(alias)),
                    TypestateGuardResolution::Keep(guard) => {
                        tasks.push(Task::FinishGuard(Box::new(guard), false));
                        tasks.push(Task::Function(alias));
                        tasks.push(Task::Function(no_alias));
                    }
                    TypestateGuardResolution::Open(guard) => {
                        tasks.push(Task::FinishGuard(Box::new(guard), true));
                        tasks.push(Task::Function(alias));
                        tasks.push(Task::Function(no_alias));
                    }
                },
                Task::FinishFunction(len) => {
                    let parts = built.split_off(built.len() - len);
                    built.push(parts.into_iter().fold(Self::identity(), Self::then));
                }
                Task::FinishChoice(len) => {
                    let paths = built.split_off(built.len() - len);
                    built.push(Self::choice_functions(paths));
                }
                Task::FinishGuard(guard, open) => {
                    let alias = built.pop().expect("guard alias branch was built");
                    let no_alias = built.pop().expect("guard bypass branch was built");
                    let relation = if open {
                        guard.candidate_member_subject().map(|subject| {
                            FirstUnprovenRelation::Guard {
                                site: Box::new(
                                    guard
                                        .selected_site
                                        .clone()
                                        .expect("member guard has a selected site"),
                                ),
                                guard: guard.clone(),
                                subject,
                            }
                        })
                    } else {
                        None
                    };
                    debug_assert!(relation.as_ref().is_none_or(|r| matches!(r, FirstUnprovenRelation::Guard { guard: member_guard, .. } if member_guard.as_ref() == guard.as_ref())));
                    let alias = relation
                        .map(Self::first_unproven)
                        .unwrap_or_else(Self::identity)
                        .then(if open {
                            Self::incomplete(TypestateUncertainty::IncompleteAnalysis).then(alias)
                        } else {
                            alias
                        });
                    let no_alias = if open {
                        Self::incomplete(TypestateUncertainty::IncompleteAnalysis).then(no_alias)
                    } else {
                        no_alias
                    };
                    built.push(Self::guarded(*guard, no_alias, alias));
                }
            }
        }
        assert_eq!(built.len(), 1);
        Ok(built.pop().expect("one rewritten function"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TypestateComposeLabels<'a> {
    protocol: &'a CompiledProtocol,
    bindings: &'a TypestateBindingPlan,
}

impl<'a> TypestateComposeLabels<'a> {
    pub const fn new(protocol: &'a CompiledProtocol, bindings: &'a TypestateBindingPlan) -> Self {
        Self { protocol, bindings }
    }

    fn apply_with_events(
        &self,
        function: &TypestateComposeFunction,
        fact: &TypestateComposeFact,
    ) -> (TypestateComposeFact, Vec<TypestateEventObservation>) {
        let (reached, events, _) = self.evaluate(function, fact, true);
        (reached, events)
    }

    pub fn apply_with_first_unproven(
        &self,
        function: &TypestateComposeFunction,
        fact: &TypestateComposeFact,
    ) -> FirstUnprovenPairs {
        self.evaluate(function, fact, false).2
    }

    pub fn apply_with_grouped_first_unproven(
        &self,
        function: &TypestateComposeFunction,
        fact: &TypestateComposeFact,
    ) -> GroupedFirstUnproven {
        let mut grouped = std::collections::BTreeMap::<_, Vec<_>>::new();
        for (fact, relation) in self.apply_with_first_unproven(function, fact) {
            grouped.entry(fact).or_default().push(relation);
        }
        grouped
            .into_iter()
            .map(|(fact, relations)| (fact, relations.into_boxed_slice()))
            .collect()
    }

    fn evaluate(
        &self,
        function: &TypestateComposeFunction,
        fact: &TypestateComposeFact,
        collect_events: bool,
    ) -> (
        TypestateComposeFact,
        Vec<TypestateEventObservation>,
        FirstUnprovenPairs,
    ) {
        let mut observations = Vec::new();
        let mut alternatives = Vec::new();
        let mut pairs = Vec::new();
        let mut pending = vec![(
            fact.clone(),
            vec![(function.0.as_ref(), 0_usize)],
            FirstUnprovenEvent::None,
        )];
        while let Some((mut current, mut frames, mut relation)) = pending.pop() {
            loop {
                let Some((segments, index)) = frames.last_mut() else {
                    alternatives.extend_from_slice(current.alternatives());
                    pairs.extend(
                        current
                            .alternatives()
                            .iter()
                            .map(|fact| (*fact, relation.clone())),
                    );
                    break;
                };
                if *index == segments.len() {
                    frames.pop();
                    continue;
                }
                let segment = &segments[*index];
                *index += 1;
                match segment {
                    Segment::Absent => break,
                    Segment::FirstUnproven(candidate) => {
                        if relation == FirstUnprovenEvent::None {
                            relation = FirstUnprovenEvent::Relation((**candidate).clone());
                        }
                    }
                    Segment::UnprovenHopLoss => {
                        if relation == FirstUnprovenEvent::None {
                            relation = FirstUnprovenEvent::Lost;
                        }
                    }
                    Segment::Step(step) => {
                        if let TypestateComposeStep::Event(id) = step {
                            let binding = self
                                .bindings
                                .event_binding(*id)
                                .expect("composed event names a bound event");
                            if !binding.quality().is_definitive()
                                && relation == FirstUnprovenEvent::None
                            {
                                relation = FirstUnprovenEvent::Lost;
                            }
                        }
                        let before = collect_events.then(|| current.clone());
                        current = self.apply_step(*step, &current);
                        if let TypestateComposeStep::MapSubject { from, to } = step
                            && let FirstUnprovenEvent::Relation(first) = relation
                        {
                            relation = FirstUnprovenEvent::Relation(first.remap(*from, *to));
                        }
                        if matches!(step, TypestateComposeStep::Incomplete(_))
                            && relation == FirstUnprovenEvent::None
                        {
                            relation = FirstUnprovenEvent::Lost;
                        }
                        if let (Some(before), TypestateComposeStep::Event(binding)) = (before, step)
                        {
                            observations.push(TypestateEventObservation {
                                binding: *binding,
                                before,
                                after: current.clone(),
                            });
                        }
                    }
                    Segment::Choice(paths) => {
                        for path in paths.iter().rev() {
                            let mut branch_frames = frames.clone();
                            branch_frames.push((path.0.as_ref(), 0));
                            pending.push((current.clone(), branch_frames, relation.clone()));
                        }
                        break;
                    }
                    Segment::Guarded {
                        no_alias, alias, ..
                    } => {
                        let uncertain = self.apply_step(
                            TypestateComposeStep::Incomplete(
                                TypestateUncertainty::ConditionalAlias,
                            ),
                            &current,
                        );
                        for path in [alias, no_alias] {
                            let mut branch_frames = frames.clone();
                            let mut branch_relation = relation.clone();
                            // A constructor can issue the alias relation at the
                            // guard boundary, before conditional uncertainty.
                            let mut index = 0;
                            if std::ptr::eq(path, alias)
                                && let Some(Segment::FirstUnproven(candidate)) = path.0.first()
                            {
                                if branch_relation == FirstUnprovenEvent::None {
                                    branch_relation =
                                        FirstUnprovenEvent::Relation((**candidate).clone());
                                }
                                index = 1;
                            }
                            if branch_relation == FirstUnprovenEvent::None {
                                branch_relation = FirstUnprovenEvent::Lost;
                            }
                            branch_frames.push((path.0.as_ref(), index));
                            pending.push((uncertain.clone(), branch_frames, branch_relation));
                        }
                        break;
                    }
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        pairs.retain(|pair| seen.insert(pair.clone()));
        (TypestateComposeFact::new(alternatives), observations, pairs)
    }

    fn apply_step(
        &self,
        step: TypestateComposeStep,
        current: &TypestateComposeFact,
    ) -> TypestateComposeFact {
        let mut next = Vec::new();
        for fact in current.alternatives() {
            match step {
                TypestateComposeStep::Event(id) => {
                    let binding = self
                        .bindings
                        .event_binding(id)
                        .expect("composed event names a bound event");
                    if fact.subject() != Some(binding.subject())
                        || fact.state_observation().is_none()
                    {
                        next.push(*fact);
                    } else if binding.quality().is_definitive() {
                        next.extend(apply_bound_event(
                            self.protocol,
                            self.bindings,
                            *fact,
                            binding,
                        ));
                    } else {
                        next.push(mark_incomplete(
                            *fact,
                            TypestateUncertainty::IncompleteAnalysis,
                        ));
                        next.extend(
                            apply_bound_event(self.protocol, self.bindings, *fact, binding)
                                .into_iter()
                                .map(|fact| {
                                    mark_incomplete(fact, TypestateUncertainty::IncompleteAnalysis)
                                }),
                        );
                    }
                }
                TypestateComposeStep::Incomplete(cause) => next.push(mark_incomplete(*fact, cause)),
                TypestateComposeStep::MapSubject { from, to } => {
                    next.push(if fact.subject() == Some(from) {
                        map_subject(*fact, to)
                    } else {
                        *fact
                    });
                }
            }
        }
        TypestateComposeFact::new(next)
    }
}

impl ComposeLabels for TypestateComposeLabels<'_> {
    type Fact = TypestateComposeFact;
    type Function = TypestateComposeFunction;

    fn identity(&self) -> Self::Function {
        TypestateComposeFunction(Box::new([]))
    }

    fn then(&self, first: &Self::Function, second: &Self::Function) -> Self::Function {
        first.clone().then(second.clone())
    }

    fn apply(&self, function: &Self::Function, fact: &Self::Fact) -> Self::Fact {
        self.evaluate(function, fact, false).0
    }

    fn intersects(&self, left: &Self::Fact, right: &Self::Fact) -> bool {
        // This is only an existential candidate test. Closed lifecycle proofs
        // must inspect every alternative and the search's incompleteness in
        // the typestate client; an accepted alternative does not close its peers.
        left.alternatives()
            .iter()
            .any(|fact| right.alternatives().contains(fact))
    }
}

fn mark_incomplete(fact: TypestateFact, cause: TypestateUncertainty) -> TypestateFact {
    match fact.0 {
        TypestateFactKind::Zero => fact,
        TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty,
            abstained,
        } => TypestateFact(TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty: uncertainty.with(cause),
            abstained,
        }),
        TypestateFactKind::Violation {
            plan,
            subject,
            violation,
            uncertainty,
            abstained,
        } => TypestateFact(TypestateFactKind::Violation {
            plan,
            subject,
            violation,
            uncertainty: uncertainty.with(cause),
            abstained,
        }),
        TypestateFactKind::NonViolation {
            plan,
            subject,
            event_binding,
            uncertainty,
            abstained,
        } => TypestateFact(TypestateFactKind::NonViolation {
            plan,
            subject,
            event_binding,
            uncertainty: uncertainty.with(cause),
            abstained,
        }),
        TypestateFactKind::Terminal {
            plan,
            subject,
            terminal_binding,
            state,
            uncertainty,
            abstained,
        } => TypestateFact(TypestateFactKind::Terminal {
            plan,
            subject,
            terminal_binding,
            state,
            uncertainty: uncertainty.with(cause),
            abstained,
        }),
    }
}

fn map_subject(fact: TypestateFact, subject: TypestateSubjectId) -> TypestateFact {
    match fact.0 {
        TypestateFactKind::Zero => fact,
        TypestateFactKind::State {
            plan,
            state,
            uncertainty,
            abstained,
            ..
        } => TypestateFact(TypestateFactKind::State {
            plan,
            subject,
            state,
            uncertainty,
            abstained,
        }),
        TypestateFactKind::Violation {
            plan,
            violation,
            uncertainty,
            abstained,
            ..
        } => TypestateFact(TypestateFactKind::Violation {
            plan,
            subject,
            violation,
            uncertainty,
            abstained,
        }),
        TypestateFactKind::NonViolation {
            plan,
            event_binding,
            uncertainty,
            abstained,
            ..
        } => TypestateFact(TypestateFactKind::NonViolation {
            plan,
            subject,
            event_binding,
            uncertainty,
            abstained,
        }),
        TypestateFactKind::Terminal {
            plan,
            terminal_binding,
            state,
            uncertainty,
            abstained,
            ..
        } => TypestateFact(TypestateFactKind::Terminal {
            plan,
            subject,
            terminal_binding,
            state,
            uncertainty,
            abstained,
        }),
    }
}

pub(super) fn apply_bound_event(
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    fact: TypestateFact,
    binding: &BoundTypestateEvent,
) -> Vec<TypestateFact> {
    let TypestateFactKind::State {
        plan,
        subject,
        state,
        uncertainty,
        abstained,
    } = fact.0
    else {
        return Vec::new();
    };
    let cardinality = bindings
        .subject(subject)
        .expect("binding-plan facts retain valid subject IDs")
        .cardinality();
    if let Some(transition) = protocol.transition_for(state, binding.event(), cardinality) {
        let target = TypestateFact(TypestateFactKind::State {
            plan,
            subject,
            state: transition.to(),
            uncertainty,
            abstained,
        });
        if protocol.is_error(transition.to()) {
            return vec![
                target,
                TypestateFact(TypestateFactKind::Violation {
                    plan,
                    subject,
                    violation: TypestateViolation {
                        event_binding: binding.id(),
                        from: state,
                        to: transition.to(),
                    },
                    uncertainty,
                    abstained,
                }),
            ];
        }
        return vec![
            target,
            TypestateFact(TypestateFactKind::NonViolation {
                plan,
                subject,
                event_binding: binding.id(),
                uncertainty,
                abstained,
            }),
        ];
    }
    let non_violation = |uncertainty| {
        TypestateFact(TypestateFactKind::NonViolation {
            plan,
            subject,
            event_binding: binding.id(),
            uncertainty,
            abstained,
        })
    };
    match protocol.semantics().unmatched_event {
        ProtocolUnmatchedEventBehavior::PreserveState => {
            vec![fact, non_violation(uncertainty)]
        }
        ProtocolUnmatchedEventBehavior::MarkInconclusive => {
            let uncertainty = uncertainty.with(TypestateUncertainty::UnmatchedEvent);
            vec![
                TypestateFact(TypestateFactKind::State {
                    plan,
                    subject,
                    state,
                    uncertainty,
                    abstained,
                }),
                non_violation(uncertainty),
            ]
        }
    }
}
