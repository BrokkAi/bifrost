use super::super::ids::ProgramPointId;
use super::super::ir::{
    ArgumentDomain, CallArgumentExpansion, CallSiteHandle, FormalMultiplicity, ProcedureHandle,
    ProofStatus, SemanticValueKind, ValueHandle,
};
use super::dispatch::DispatchCandidate;
use super::error::{OracleContractError, require_same_procedure};
use super::limits::OracleLimits;
use super::model::{
    AccessPathAtPoint, ObservationPhase, OracleCallContext, ProcedurePortHandle, ProcedurePortKind,
};
use super::relation::{
    CandidateCoverage, EvidenceBacked, OracleCandidate, OracleRelationHandle, OracleRelationKind,
    OracleRelationOwner, collect_bounded, validate_retained_relation_arenas,
};

/// The caller-side endpoint used by one argument binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgumentEndpoint {
    Value(ValueHandle),
    Location {
        value: ValueHandle,
        location: Box<AccessPathAtPoint>,
    },
}

impl CallArgumentEndpoint {
    pub fn location(value: ValueHandle, location: AccessPathAtPoint) -> Self {
        Self::Location {
            value,
            location: Box::new(location),
        }
    }

    pub fn value(&self) -> &ValueHandle {
        match self {
            Self::Value(value) | Self::Location { value, .. } => value,
        }
    }
}

/// Language-neutral argument passing semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallPassingMode {
    Value,
    SharedReference,
    MutableReference,
    InputOutputReference,
    OutputReference,
    LanguageDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplicitArgumentKind {
    Default,
    Implicit,
    LanguageDefined,
}

/// One member contributed by a syntactic call argument. Direct arguments
/// contribute one `Whole` member; spread arguments contribute structured
/// positional, keyword, or language-defined members.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgumentMember {
    Whole,
    Positional(u32),
    Keyword(Box<str>),
    LanguageDefined(Box<str>),
}

/// One retained actual-to-formal mapping inside an argument group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgumentMapping {
    source_index: u32,
    member: CallArgumentMember,
    actual: CallArgumentEndpoint,
    formal: ProcedurePortHandle,
    mode: CallPassingMode,
}

impl CallArgumentMapping {
    pub fn new(
        source_index: u32,
        member: CallArgumentMember,
        actual: CallArgumentEndpoint,
        formal: ProcedurePortHandle,
        mode: CallPassingMode,
    ) -> Self {
        Self {
            source_index,
            member,
            actual,
            formal,
            mode,
        }
    }

    pub const fn source_index(&self) -> u32 {
        self.source_index
    }

    pub fn member(&self) -> &CallArgumentMember {
        &self.member
    }

    pub fn actual(&self) -> &CallArgumentEndpoint {
        &self.actual
    }

    pub fn formal(&self) -> &ProcedurePortHandle {
        &self.formal
    }

    pub const fn mode(&self) -> CallPassingMode {
        self.mode
    }
}

/// Cardinality derived from group coverage and candidate proof. Callers cannot
/// assert an exact cardinality independently of the validated mapping set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgumentCardinality {
    Exact(usize),
    Between { minimum: usize, maximum: usize },
    AtLeast(usize),
}

/// One evidence-backed group of argument sources and retained mappings.
///
/// The separate closure relation proves that an exhaustive group has no
/// omitted members. Keeping source indices even when no mapping is retained
/// represents an exact empty spread or an open/truncated unknown spread
/// without pretending that the syntactic actual disappeared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallArgumentGroup {
    closure_relation: OracleRelationHandle,
    sources: Box<[u32]>,
    mappings: Box<[EvidenceBacked<CallArgumentMapping>]>,
    coverage: CandidateCoverage,
}

impl CallArgumentGroup {
    pub fn new<I, M>(
        call: &CallSiteHandle,
        closure_relation: OracleRelationHandle,
        sources: I,
        mappings: M,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = u32>,
        M: IntoIterator<Item = EvidenceBacked<CallArgumentMapping>>,
    {
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call-site handles are validated at construction");
        let entry_limit = limits.call_binding_entries();
        let source_limit = entry_limit.min(call_row.arguments.len());
        let sources = sources
            .into_iter()
            .take(source_limit.saturating_add(1))
            .collect::<Vec<_>>();
        if sources.len() > entry_limit {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: entry_limit,
                attempted: sources.len(),
            });
        }
        if sources.len() > call_row.arguments.len() {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group has more sources than the exact call",
            ));
        }
        if sources.is_empty() {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group must name at least one syntactic source",
            ));
        }
        let mut unique_sources = std::collections::HashSet::new();
        if sources.iter().any(|source| !unique_sources.insert(*source)) {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group repeats one syntactic source",
            ));
        }
        if sources
            .iter()
            .any(|source| call_row.arguments.get(*source as usize).is_none())
        {
            return Err(OracleContractError::InvalidCallBinding(
                "argument group names a source outside the exact call",
            ));
        }
        let remaining = entry_limit.saturating_sub(sources.len());
        let mappings = mappings
            .into_iter()
            .take(remaining.saturating_add(1))
            .collect::<Vec<_>>();
        if mappings.len() > remaining {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: entry_limit,
                attempted: sources.len().saturating_add(mappings.len()),
            });
        }
        let mut unique_members = std::collections::HashSet::new();
        if mappings.iter().any(|mapping| {
            !unique_sources.contains(&mapping.value().source_index)
                || !unique_members
                    .insert((mapping.value().source_index, mapping.value().member.clone()))
        }) {
            return Err(OracleContractError::InvalidCallBinding(
                "argument mapping repeats or names an undeclared source member",
            ));
        }
        validate_retained_relation_arenas(
            std::iter::once(&closure_relation)
                .chain(mappings.iter().flat_map(OracleCandidate::provenance)),
            limits,
        )?;
        Ok(Self {
            closure_relation,
            sources: sources.into_boxed_slice(),
            mappings: mappings.into_boxed_slice(),
            coverage,
        })
    }

    pub fn closure_relation(&self) -> &OracleRelationHandle {
        &self.closure_relation
    }

    pub fn sources(&self) -> &[u32] {
        &self.sources
    }

    pub fn mappings(&self) -> &[EvidenceBacked<CallArgumentMapping>] {
        &self.mappings
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn cardinality(&self) -> ArgumentCardinality {
        let proven = self
            .mappings
            .iter()
            .filter(|mapping| matches!(mapping.proof(), ProofStatus::Proven))
            .count();
        match self.coverage {
            CandidateCoverage::Exhaustive if proven == self.mappings.len() => {
                ArgumentCardinality::Exact(proven)
            }
            CandidateCoverage::Exhaustive => ArgumentCardinality::Between {
                minimum: proven,
                maximum: self.mappings.len(),
            },
            CandidateCoverage::Open | CandidateCoverage::Truncated => {
                ArgumentCardinality::AtLeast(proven)
            }
        }
    }
}

/// One candidate-specific caller/callee boundary relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallBinding {
    Receiver {
        relation: OracleRelationHandle,
        actual: ValueHandle,
        formal: ProcedurePortHandle,
    },
    ArgumentGroup(CallArgumentGroup),
    ImplicitArgument {
        relation: OracleRelationHandle,
        formal_ordinal: u32,
        source: ValueHandle,
        formal: ProcedurePortHandle,
        kind: ImplicitArgumentKind,
    },
    NormalReturn {
        relation: OracleRelationHandle,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
    ExceptionalReturn {
        relation: OracleRelationHandle,
        formal: ProcedurePortHandle,
        result: ValueHandle,
    },
}

/// Actual/formal and return bindings for one exact dispatch candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBindings {
    call: CallSiteHandle,
    candidate: DispatchCandidate,
    context: OracleCallContext,
    bindings: Box<[CallBinding]>,
    coverage: CandidateCoverage,
}

fn validate_call_binding_relation(
    relation: &OracleRelationHandle,
    owner: &OracleRelationOwner,
    first: &mut Option<OracleRelationHandle>,
    seen: &mut std::collections::HashSet<OracleRelationHandle>,
) -> Result<(), OracleContractError> {
    if relation.owner() != owner
        || relation.record().kind() != OracleRelationKind::CallBinding
        || relation.record().evidence().is_empty()
        || first
            .as_ref()
            .is_some_and(|first| !first.same_arena(relation))
        || !seen.insert(relation.clone())
    {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    if first.is_none() {
        *first = Some(relation.clone());
    }
    Ok(())
}

fn member_matches_expansion(
    expansion: &CallArgumentExpansion,
    member: &CallArgumentMember,
) -> bool {
    match (expansion, member) {
        (CallArgumentExpansion::Direct(_), CallArgumentMember::Whole) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::Positional),
            CallArgumentMember::Positional(_),
        )
        | (
            CallArgumentExpansion::Spread(ArgumentDomain::Keyword),
            CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::PositionalOrKeyword),
            CallArgumentMember::Positional(_) | CallArgumentMember::Keyword(_),
        ) => true,
        (
            CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(expected)),
            CallArgumentMember::LanguageDefined(actual),
        ) => expected == actual,
        _ => false,
    }
}

fn rest_domain_accepts_mapping(
    rest: &ArgumentDomain,
    expansion: &CallArgumentExpansion,
    member: &CallArgumentMember,
) -> bool {
    let accepts_positional = matches!(
        rest,
        ArgumentDomain::Positional | ArgumentDomain::PositionalOrKeyword
    );
    let accepts_keyword = matches!(
        rest,
        ArgumentDomain::Keyword | ArgumentDomain::PositionalOrKeyword
    );
    match (expansion, member) {
        (CallArgumentExpansion::Direct(ArgumentDomain::Positional), CallArgumentMember::Whole) => {
            accepts_positional
        }
        (CallArgumentExpansion::Direct(ArgumentDomain::Keyword), CallArgumentMember::Whole) => {
            accepts_keyword
        }
        (
            CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword),
            CallArgumentMember::Whole,
        ) => accepts_positional || accepts_keyword,
        (
            CallArgumentExpansion::Direct(ArgumentDomain::LanguageDefined(actual)),
            CallArgumentMember::Whole,
        )
        | (
            CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(actual)),
            CallArgumentMember::LanguageDefined(_),
        ) => matches!(rest, ArgumentDomain::LanguageDefined(expected) if expected == actual),
        (CallArgumentExpansion::Spread(_), CallArgumentMember::Positional(_)) => accepts_positional,
        (CallArgumentExpansion::Spread(_), CallArgumentMember::Keyword(_)) => accepts_keyword,
        _ => false,
    }
}

fn validate_argument_endpoint(
    actual: &CallArgumentEndpoint,
    mode: CallPassingMode,
    caller: &ProcedureHandle,
    call_point: ProgramPointId,
    context: &OracleCallContext,
) -> Result<(), OracleContractError> {
    require_same_procedure(actual.value().procedure(), caller)?;
    if let CallArgumentEndpoint::Location { location, .. } = actual {
        require_same_procedure(location.point().procedure(), caller)?;
        if location.point().id() != call_point
            || location.phase() != ObservationPhase::BeforeEffects
            || location.context() != context
        {
            return Err(OracleContractError::InvalidCallBinding(
                "reference argument locations must be observed immediately before the call effects",
            ));
        }
        if !matches!(
            mode,
            CallPassingMode::SharedReference
                | CallPassingMode::MutableReference
                | CallPassingMode::InputOutputReference
                | CallPassingMode::OutputReference
                | CallPassingMode::LanguageDefined
        ) {
            return Err(OracleContractError::InvalidCallBinding(
                "location arguments require a reference-capable passing mode",
            ));
        }
    } else if matches!(
        mode,
        CallPassingMode::MutableReference
            | CallPassingMode::InputOutputReference
            | CallPassingMode::OutputReference
    ) {
        return Err(OracleContractError::InvalidCallBinding(
            "mutable/output argument modes require a caller location",
        ));
    }
    Ok(())
}

impl CallBindings {
    pub fn new<I>(
        call: CallSiteHandle,
        candidate: &DispatchCandidate,
        context: OracleCallContext,
        bindings: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = CallBinding>,
    {
        candidate.validate_for_call(&call)?;
        let bindings = collect_bounded(
            bindings,
            limits.call_binding_entries(),
            "call_binding_entries",
        )?;
        let retained_entries = bindings.iter().fold(bindings.len(), |total, binding| {
            let CallBinding::ArgumentGroup(group) = binding else {
                return total;
            };
            total
                .saturating_add(group.sources().len())
                .saturating_add(group.mappings().len())
        });
        if retained_entries > limits.call_binding_entries() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "call_binding_entries",
                limit: limits.call_binding_entries(),
                attempted: retained_entries,
            });
        }
        let callee = candidate.target().clone();
        let caller = call.procedure();
        let call_row = caller
            .semantics()
            .call_site(call.id())
            .expect("call-site handles are validated at construction");
        let relation_owner = OracleRelationOwner::CallBinding {
            call: call.clone(),
            callee: callee.clone(),
            context: context.clone(),
        };
        let mut relation_ids = std::collections::HashSet::new();
        let mut first_relation = None;
        let mut actual_sources = std::collections::HashSet::new();
        let mut formal_bindings = std::collections::HashSet::new();
        let mut formal_mapping_counts = std::collections::HashMap::<u32, usize>::new();
        let mut implicit_formals = std::collections::HashSet::new();
        let mut has_receiver = false;
        let mut has_normal_return = false;
        let mut has_exceptional_return = false;
        let mut has_open_group = false;
        let mut has_truncated_group = false;
        for binding in &bindings {
            match binding {
                CallBinding::Receiver {
                    relation,
                    actual,
                    formal,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(actual.procedure(), caller)?;
                    require_same_procedure(formal.procedure(), &callee)?;
                    if call_row.receiver != Some(actual.id())
                        || formal.kind() != ProcedurePortKind::Receiver
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "receiver binding does not match the call receiver and callee receiver port",
                        ));
                    }
                    if has_receiver {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one receiver relation",
                        ));
                    }
                    has_receiver = true;
                }
                CallBinding::ArgumentGroup(group) => {
                    validate_call_binding_relation(
                        group.closure_relation(),
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if group.coverage().is_exhaustive()
                        && !group.closure_relation().record().is_proven_complete()
                    {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    has_open_group |= group.coverage() == CandidateCoverage::Open;
                    has_truncated_group |= group.coverage().is_truncated();
                    for source_index in group.sources() {
                        let Some(argument) = call_row.arguments.get(*source_index as usize) else {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument group names a source outside the exact call",
                            ));
                        };
                        if !actual_sources.insert(*source_index) {
                            return Err(OracleContractError::InvalidCallBinding(
                                "one syntactic argument source appears in multiple groups",
                            ));
                        }
                        let has_mapping = group
                            .mappings()
                            .iter()
                            .any(|mapping| mapping.value().source_index == *source_index);
                        if group.coverage().is_exhaustive()
                            && !argument.expansion.is_spread()
                            && !has_mapping
                        {
                            return Err(OracleContractError::InvalidCallBinding(
                                "an exhaustive direct-argument group omits its mapping",
                            ));
                        }
                    }
                    for backed_mapping in group.mappings() {
                        if backed_mapping.provenance().is_empty() {
                            return Err(OracleContractError::InvalidRelationIdentity);
                        }
                        for relation in backed_mapping.provenance() {
                            validate_call_binding_relation(
                                relation,
                                &relation_owner,
                                &mut first_relation,
                                &mut relation_ids,
                            )?;
                            if !relation.record().supports_quality(
                                backed_mapping.proof(),
                                backed_mapping.completeness(),
                            ) {
                                return Err(OracleContractError::InvalidRelationQuality);
                            }
                        }
                        let mapping = backed_mapping.value();
                        let argument = call_row
                            .arguments
                            .get(mapping.source_index as usize)
                            .expect("group sources were validated above");
                        validate_argument_endpoint(
                            &mapping.actual,
                            mapping.mode,
                            caller,
                            call_row.point,
                            &context,
                        )?;
                        require_same_procedure(mapping.formal.procedure(), &callee)?;
                        let ProcedurePortKind::Parameter { ordinal } = mapping.formal.kind() else {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping does not name a callee parameter port",
                            ));
                        };
                        if argument.value != mapping.actual.value().id()
                            || !member_matches_expansion(&argument.expansion, &mapping.member)
                        {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping does not match the call source expansion",
                            ));
                        }
                        let multiplicity = mapping
                            .formal
                            .formal_multiplicity()
                            .expect("validated parameter port has multiplicity");
                        if implicit_formals.contains(&ordinal) {
                            return Err(OracleContractError::InvalidCallBinding(
                                "argument mapping conflicts with an implicit formal binding",
                            ));
                        }
                        let count = formal_mapping_counts.entry(ordinal).or_default();
                        match multiplicity {
                            FormalMultiplicity::One if *count > 0 => {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "call binding maps one non-rest formal more than once",
                                ));
                            }
                            FormalMultiplicity::Rest(domain)
                                if !rest_domain_accepts_mapping(
                                    domain,
                                    &argument.expansion,
                                    &mapping.member,
                                ) =>
                            {
                                return Err(OracleContractError::InvalidCallBinding(
                                    "argument member domain is incompatible with the rest formal",
                                ));
                            }
                            FormalMultiplicity::One | FormalMultiplicity::Rest(_) => {}
                        }
                        *count = count.saturating_add(1);
                        formal_bindings.insert(ordinal);
                    }
                }
                CallBinding::ImplicitArgument {
                    relation,
                    formal_ordinal,
                    source,
                    formal,
                    ..
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    if source.procedure() != caller && source.procedure() != &callee {
                        return Err(OracleContractError::CrossProcedure);
                    }
                    if formal.kind()
                        != (ProcedurePortKind::Parameter {
                            ordinal: *formal_ordinal,
                        })
                        || formal_bindings.contains(formal_ordinal)
                        || !implicit_formals.insert(*formal_ordinal)
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "implicit argument does not name one unbound callee parameter",
                        ));
                    }
                    formal_bindings.insert(*formal_ordinal);
                }
                CallBinding::NormalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    require_same_procedure(result.procedure(), caller)?;
                    if call_row.result != Some(result.id())
                        || formal.kind() != ProcedurePortKind::NormalReturn
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "normal-return binding does not match the call result and callee return port",
                        ));
                    }
                    if has_normal_return {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one normal-return relation",
                        ));
                    }
                    has_normal_return = true;
                }
                CallBinding::ExceptionalReturn {
                    relation,
                    formal,
                    result,
                } => {
                    validate_call_binding_relation(
                        relation,
                        &relation_owner,
                        &mut first_relation,
                        &mut relation_ids,
                    )?;
                    if !relation.record().is_proven_complete() {
                        return Err(OracleContractError::InvalidRelationQuality);
                    }
                    require_same_procedure(formal.procedure(), &callee)?;
                    require_same_procedure(result.procedure(), caller)?;
                    if call_row.thrown != Some(result.id())
                        || formal.kind() != ProcedurePortKind::ExceptionalReturn
                    {
                        return Err(OracleContractError::InvalidCallBinding(
                            "exceptional-return binding does not match the call thrown value and callee exceptional port",
                        ));
                    }
                    if has_exceptional_return {
                        return Err(OracleContractError::InvalidCallBinding(
                            "call binding contains more than one exceptional-return relation",
                        ));
                    }
                    has_exceptional_return = true;
                }
            }
        }
        if has_truncated_group && coverage != CandidateCoverage::Truncated {
            return Err(OracleContractError::InvalidCallBinding(
                "a truncated argument group requires truncated call-binding coverage",
            ));
        }
        if has_open_group && coverage.is_exhaustive() {
            return Err(OracleContractError::InvalidCallBinding(
                "an open argument group cannot support exhaustive call bindings",
            ));
        }
        if coverage.is_exhaustive() {
            let all_actuals_bound =
                (0..call_row.arguments.len()).all(|index| actual_sources.contains(&(index as u32)));
            let all_formals_bound = callee
                .semantics()
                .values()
                .iter()
                .filter_map(|value| match &value.kind {
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: FormalMultiplicity::One,
                    } => Some(*ordinal),
                    _ => None,
                })
                .all(|ordinal| formal_bindings.contains(&ordinal));
            let receiver_bound = !callee
                .semantics()
                .values()
                .iter()
                .any(|value| value.kind == SemanticValueKind::Receiver)
                || has_receiver;
            let returns_bound = call_row.result.is_none() || has_normal_return;
            let throws_bound = call_row.thrown.is_none() || has_exceptional_return;
            if !all_actuals_bound
                || !all_formals_bound
                || !receiver_bound
                || !returns_bound
                || !throws_bound
            {
                return Err(OracleContractError::InvalidCallBinding(
                    "exhaustive call bindings omit an actual, formal, receiver, or return relation",
                ));
            }
        }
        validate_retained_relation_arenas(
            candidate.provenance().iter().chain(relation_ids.iter()),
            limits,
        )?;
        Ok(Self {
            call,
            candidate: candidate.clone(),
            context,
            bindings: bindings.into_boxed_slice(),
            coverage,
        })
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub fn callee(&self) -> &ProcedureHandle {
        self.candidate.target()
    }

    pub fn candidate(&self) -> &DispatchCandidate {
        &self.candidate
    }

    pub fn bindings(&self) -> &[CallBinding] {
        &self.bindings
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }
}
