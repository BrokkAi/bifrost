//! Canonical method families: the exact override/implements relation between
//! members (issue #1477 Milestone 4).
//!
//! Before this module the analyzer had no production override relation at all.
//! `TypeHierarchyProvider` answers about *types*, and `implementation_of` links
//! a declaration-only signature to its body, which is a different relation. A
//! method family is the set of declarations an analyzer can *prove* are the
//! same overridable member contract.
//!
//! Three rules make the contract honest, and they are the reason this is a
//! capability rather than a shared algorithm:
//!
//! 1. **Only forward edges are resolved.** The walk resolves the members a
//!    member overrides or implements. `overridden_by` and `implemented_by` are
//!    derived by bounded inversion over those same forward edges, so the two
//!    directions cannot disagree. [`MemberFamilyProvider::member_family`]
//!    answers both directions from one walk, which is what lets both share one
//!    visit budget and one cancellation token.
//! 2. **The owner relationship comes from the real hierarchy walk.** Ancestors
//!    are the analyzer's own `get_direct_ancestors` edges, walked iteratively
//!    with a seen set and a metered frontier. Nothing is matched by
//!    fully-qualified name or by rendered signature text.
//! 3. **Member matching respects overload identity, and says so when it
//!    cannot.** Each language states a measured [`MemberFamilyCapability`].
//!    When the recorded evidence cannot single out one ancestor member, the
//!    answer is `incomplete` with [`MemberFamilyReason::OverloadIdentityUnproven`]
//!    and *no* edge -- never a guessed edge and never a silently empty answer.
//!
//! Support is stated, never defaulted: [`IAnalyzer::member_family_provider`]
//! returns `None` for every language that has not landed a family, and a
//! provider that exists still answers `unsupported` for a member outside the
//! language family it implements.

use std::collections::VecDeque;

use brokk_bifrost_core::analyzer::structural::resolution::{
    MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason, MethodFamilyRelation,
};

use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::{CapabilityProvider, CodeUnit, IAnalyzer, Language, TypeHierarchyProvider};
use crate::cancellation::CancellationToken;

/// Domain separator for a canonical method-family id.
const MEMBER_FAMILY_ID_DOMAIN: &[u8] = b"bifrost.member_family.v1";

/// How many type and member visits one member's whole family answer may spend.
///
/// The budget is shared by every walk the answer performs -- the ancestor walk
/// of the queried member, the ancestor walk of each member the root closure
/// reaches, and the descendant walk of the bounded inversion together with the
/// ancestor walk it runs per candidate below. Sharing it is what caps the
/// *product* of the walks rather than each factor: an inversion over 512
/// descendants can no longer spend 512 ancestor visits apiece.
///
/// Exhausting the budget, like cancelling the request, is reported as
/// [`MemberFamilyReason::HierarchyTruncated`]: the walk stopped before it saw
/// the whole hierarchy, so the answer is `incomplete` and carries no edge.
const MAX_FAMILY_VISITS: usize = 4_096;

/// One proven family edge from a member to a member it overrides or
/// implements, or -- after inversion -- from a member to a member that
/// overrides or implements it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberFamilyEdge {
    /// The member at the other end of the edge, by exact `CodeUnit` identity.
    pub target: CodeUnit,
    /// The target's owning type, as the hierarchy walk found it.
    pub owner: CodeUnit,
    /// `overrides`/`implements` for a forward edge, `overridden_by`/
    /// `implemented_by` for an inverted one.
    pub relation: MethodFamilyRelation,
    /// Hierarchy hops between the two owners on the route that found this
    /// edge. Always at least one: a member never overrides its own sibling.
    pub depth: usize,
    /// Whether the ancestor's candidate set singled the target out on
    /// structure alone (one member of that name and arity), rather than
    /// needing the weaker parameter-spelling discriminator.
    pub arity_unique: bool,
}

/// One member's complete family answer.
///
/// `outcome` is the whole answer. `proven` and `no_family` are complete;
/// `incomplete` and `unsupported` never carry edges or a family id.
#[derive(Debug, Clone)]
pub struct MemberFamilyAnswer {
    pub capability: MemberFamilyCapability,
    pub outcome: MemberFamilyOutcome,
    pub reason: Option<MemberFamilyReason>,
    /// The forward edges first, each ordered by target identity, then the
    /// bounded inversion of the same relation, likewise ordered. One vector
    /// because one walk produced both under one budget.
    pub edges: Vec<MemberFamilyEdge>,
    /// The deterministically ordered exact roots of this member's family: the
    /// members reachable by following forward edges that themselves override
    /// or implement nothing. A member with no forward edges is its own root.
    pub roots: Vec<CodeUnit>,
}

impl MemberFamilyAnswer {
    fn not_proven(
        capability: MemberFamilyCapability,
        outcome: MemberFamilyOutcome,
        reason: MemberFamilyReason,
    ) -> Self {
        debug_assert!(
            outcome != MemberFamilyOutcome::Proven,
            "a proven family states no reason"
        );
        Self {
            capability,
            outcome,
            reason: Some(reason),
            edges: Vec::new(),
            roots: Vec::new(),
        }
    }

    /// The complete answer for a member the language excludes from families.
    fn no_family(capability: MemberFamilyCapability, reason: MemberFamilyReason) -> Self {
        debug_assert!(reason.is_proven_exclusion());
        Self::not_proven(capability, MemberFamilyOutcome::NoFamily, reason)
    }

    fn incomplete(capability: MemberFamilyCapability, reason: MemberFamilyReason) -> Self {
        Self::not_proven(capability, MemberFamilyOutcome::Incomplete, reason)
    }

    /// The answer for a member whose language exposes no family provider at
    /// all. Published so the query layer states `unsupported` rather than
    /// inventing an empty exhaustive family.
    pub fn unsupported_answer() -> Self {
        Self::unsupported()
    }

    fn unsupported() -> Self {
        Self::not_proven(
            MemberFamilyCapability::Unsupported,
            MemberFamilyOutcome::Unsupported,
            MemberFamilyReason::UnsupportedLanguage,
        )
    }

    pub fn is_proven(&self) -> bool {
        self.outcome == MemberFamilyOutcome::Proven
    }
}

/// The per-language capability for exact member-family edges.
///
/// There is deliberately no blanket implementation and no default `supported`.
/// A language that has not landed a family exposes no provider at all, and
/// [`crate::analyzer::IAnalyzer::member_family_provider`] returns `None`, which
/// the query layer reports as an `unsupported` outcome row.
pub trait MemberFamilyProvider: CapabilityProvider + Send + Sync {
    /// What this provider can prove about *this* member's overload identity.
    /// A member in a language the provider does not implement is
    /// [`MemberFamilyCapability::Unsupported`].
    fn member_family_capability(&self, member: &CodeUnit) -> MemberFamilyCapability;

    /// One member's whole family: the forward edges (the members it overrides
    /// or implements) followed by the bounded inversion of the same relation
    /// (the members that override or implement it).
    ///
    /// Both directions come from one walk so that they share one visit budget
    /// and one cancellation token; a caller that asked for them separately
    /// would pay for the forward relation twice and could cap neither.
    /// `cancellation` is checked at every visit, and a cancelled or exhausted
    /// walk answers `incomplete` with
    /// [`MemberFamilyReason::HierarchyTruncated`] rather than a partial edge
    /// set.
    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> MemberFamilyAnswer;
}

/// The shared state of one member's family answer: the two sources the walk
/// reads, the request's cancellation token, and the one visit budget every
/// walk of that answer draws from.
struct FamilyWalk<'a> {
    analyzer: &'a dyn IAnalyzer,
    hierarchy: &'a dyn TypeHierarchyProvider,
    cancellation: Option<&'a CancellationToken>,
    remaining: usize,
}

impl<'a> FamilyWalk<'a> {
    fn new(
        analyzer: &'a dyn IAnalyzer,
        hierarchy: &'a dyn TypeHierarchyProvider,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            analyzer,
            hierarchy,
            cancellation,
            remaining: MAX_FAMILY_VISITS,
        }
    }

    /// Charge one type or member visit against the shared budget, and check
    /// the request's cancellation token while doing it.
    ///
    /// Every loop of every walk calls this exactly once per visit it is about
    /// to make, so no loop in this module can run past the budget or past a
    /// cancelled request.
    fn spend(&mut self) -> Result<(), MemberFamilyReason> {
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
            || self.remaining == 0
        {
            return Err(MemberFamilyReason::HierarchyTruncated);
        }
        self.remaining -= 1;
        Ok(())
    }
}

/// What one member's ancestor walk found.
///
/// `Edges` is the only outcome the closure and the inversion continue from.
/// `Answer` is a complete statement about that member on its own -- an
/// exclusion, an unsupported language, or a fact the analyzer never recorded --
/// and it is returned to the caller unchanged when the member is the queried
/// one, or treated as "no forward edges to follow" when it is not.
enum ForwardStep {
    Edges {
        owner: CodeUnit,
        edges: Vec<MemberFamilyEdge>,
    },
    Answer(MemberFamilyAnswer),
}

/// The forward edges of exactly one member, and nothing else.
///
/// This function is the *only* place an ancestor hierarchy is walked, and it
/// never calls itself, [`family_roots`], or [`inverse_edges`]. Root discovery
/// and inversion are separate iterative closures that call it. That layering is
/// what makes an inheritance cycle safe: before this split, root discovery
/// re-entered the forward walk, each frame started a fresh seen set, and
/// `class A extends B` with `class B extends A` -- which javac rejects but
/// Bifrost parses while the file is being edited -- alternated frames until the
/// stack overflowed.
///
/// `Err` is a walk-level failure that ends the whole answer: the shared budget
/// ran out, or the request was cancelled.
fn forward_edges(
    walk: &mut FamilyWalk<'_>,
    member: &CodeUnit,
) -> Result<ForwardStep, MemberFamilyReason> {
    if language_for_file(member.source()) != Language::Java {
        return Ok(ForwardStep::Answer(MemberFamilyAnswer::unsupported()));
    }
    let Some(facts) = MemberFacts::read(walk.analyzer, member) else {
        return Ok(ForwardStep::Answer(MemberFamilyAnswer::incomplete(
            MemberFamilyCapability::Unsupported,
            MemberFamilyReason::ModifiersUnrecorded,
        )));
    };
    let capability = facts.capability;
    if !member.is_function() {
        return Ok(ForwardStep::Answer(MemberFamilyAnswer::no_family(
            capability,
            MemberFamilyReason::NotAMethod,
        )));
    }
    if let Some(reason) = facts.exclusion() {
        return Ok(ForwardStep::Answer(MemberFamilyAnswer::no_family(
            capability, reason,
        )));
    }
    let Some(owner) = walk.analyzer.parent_of(member).filter(CodeUnit::is_class) else {
        return Ok(ForwardStep::Answer(MemberFamilyAnswer::incomplete(
            capability,
            MemberFamilyReason::OwnerUnknown,
        )));
    };

    // Breadth-first over the analyzer's own ancestor edges. A branch stops at
    // the first ancestor that declares a matching member, because the forward
    // relation is to the nearest redeclaration on that route; deeper members of
    // the same chain are reached transitively through that one's own edges.
    let mut edges: Vec<MemberFamilyEdge> = Vec::new();
    let mut seen = vec![owner.clone()];
    let mut frontier = VecDeque::from([(owner.clone(), 0_usize)]);
    while let Some((type_unit, depth)) = frontier.pop_front() {
        for ancestor in walk.hierarchy.get_direct_ancestors(&type_unit) {
            if seen.contains(&ancestor) {
                continue;
            }
            walk.spend()?;
            seen.push(ancestor.clone());
            match java_matching_member(walk.analyzer, &ancestor, &facts) {
                AncestorMatch::None => frontier.push_back((ancestor, depth + 1)),
                AncestorMatch::Unproven(reason) => {
                    return Ok(ForwardStep::Answer(MemberFamilyAnswer::incomplete(
                        capability, reason,
                    )));
                }
                AncestorMatch::One {
                    target,
                    relation,
                    arity_unique,
                } => edges.push(MemberFamilyEdge {
                    target,
                    owner: ancestor,
                    relation,
                    depth: depth + 1,
                    arity_unique,
                }),
            }
        }
    }
    edges.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(ForwardStep::Edges { owner, edges })
}

/// The Java member family in both directions, parameterized over the analyzer
/// that holds members and metadata and over the hierarchy provider that holds
/// ancestor and descendant edges.
///
/// The two are separate parameters because the multi-analyzer must supply its
/// own realm-aware hierarchy: a Kotlin class can extend a Java class, and only
/// the multi-analyzer resolves that edge. Passing the multi-analyzer as both
/// arguments is what makes the delegation correct rather than merely present.
///
/// One call performs three bounded closures under one budget: the queried
/// member's ancestor walk, the root closure over the forward edges that walk
/// found, and the bounded inversion below the member's owner. The forward
/// answer is computed once and reused by the other two.
pub fn java_member_family(
    analyzer: &dyn IAnalyzer,
    hierarchy: &dyn TypeHierarchyProvider,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    let capability = java_member_family_capability(analyzer, member);
    let mut walk = FamilyWalk::new(analyzer, hierarchy, cancellation);
    let (owner, mut edges) = match forward_edges(&mut walk, member) {
        Err(reason) => return MemberFamilyAnswer::incomplete(capability, reason),
        Ok(ForwardStep::Answer(answer)) => return answer,
        Ok(ForwardStep::Edges { owner, edges }) => (owner, edges),
    };
    let roots = match family_roots(&mut walk, member, &edges) {
        Ok(roots) => roots,
        Err(reason) => return MemberFamilyAnswer::incomplete(capability, reason),
    };
    match inverse_edges(&mut walk, member, owner) {
        Ok(inverse) => edges.extend(inverse),
        Err(reason) => return MemberFamilyAnswer::incomplete(capability, reason),
    }
    MemberFamilyAnswer {
        capability,
        outcome: MemberFamilyOutcome::Proven,
        reason: None,
        edges,
        roots,
    }
}

/// The bounded inversion of the forward relation.
///
/// The frontier is the direct-descendant index the hierarchy capability
/// already builds (`get_direct_descendants`, backed by
/// `build_direct_descendant_index`), so inversion never scans the workspace: it
/// visits the types below the member's owner, asks each of their members for
/// its *forward* edges, and retains the ones that name this member. Every
/// inverse edge is therefore a forward edge read backwards, which is what makes
/// the two directions round trip by construction.
///
/// Both the descendant frontier and each candidate's own ancestor walk draw on
/// the caller's shared budget, so the cost of the inversion is the sum of its
/// visits rather than the product of two independent bounds.
fn inverse_edges(
    walk: &mut FamilyWalk<'_>,
    member: &CodeUnit,
    owner: CodeUnit,
) -> Result<Vec<MemberFamilyEdge>, MemberFamilyReason> {
    let mut edges = Vec::new();
    let mut seen = vec![owner.clone()];
    let mut frontier = VecDeque::from([owner]);
    while let Some(type_unit) = frontier.pop_front() {
        for descendant in walk.hierarchy.get_direct_descendants(&type_unit) {
            if seen.contains(&descendant) {
                continue;
            }
            walk.spend()?;
            seen.push(descendant.clone());
            frontier.push_back(descendant.clone());
            let candidates = walk.analyzer.direct_children(&descendant);
            for candidate in candidates {
                if !candidate.is_function() {
                    continue;
                }
                walk.spend()?;
                // A candidate the analyzer cannot state a family for simply
                // holds no forward edge to invert; that is its own row's
                // problem, not this member's.
                let ForwardStep::Edges { edges: below, .. } = forward_edges(walk, &candidate)?
                else {
                    continue;
                };
                for edge in below.into_iter().filter(|edge| &edge.target == member) {
                    edges.push(MemberFamilyEdge {
                        target: candidate.clone(),
                        owner: descendant.clone(),
                        relation: edge.relation.inverse(),
                        depth: edge.depth,
                        arity_unique: edge.arity_unique,
                    });
                }
            }
        }
    }
    edges.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(edges)
}

/// The family id: a domain-separated digest over the deterministically ordered
/// exact family roots of *the queried member* plus the language the roots live
/// in.
///
/// The digest input is each root's structured canonical identity -- the same
/// recipe `canonical_member_id` uses on candidate rows -- never a rendered FQN
/// or signature string.
///
/// The guarantee is exactly this: two members carry the same id when their
/// proven root closures coincide, and different ids when they do not. It is
/// therefore an id of a root set, not of a connected component. A member that
/// redeclares one root shares that root's id, which is what makes an override
/// chain round trip. A member that redeclares *several* roots -- `class C
/// implements I1, I2` where both interfaces declare `run()` -- has the root set
/// `{I1.run, I2.run}`, while `I1.run` has `{I1.run}`, so `C.run` and `I1.run`
/// carry different ids even though one edge joins them. Read the id as "these
/// members answer to the same contracts", never as "these members are joined by
/// edges".
///
/// `None` when the answer is not proven or holds no root: an unproven family
/// never gets an id that would read as exact.
pub fn member_family_id(analyzer: &dyn IAnalyzer, answer: &MemberFamilyAnswer) -> Option<String> {
    if !answer.is_proven() || answer.roots.is_empty() {
        return None;
    }
    let mut digest = LengthDelimitedDigest::new(MEMBER_FAMILY_ID_DOMAIN);
    digest.push(
        language_for_file(answer.roots[0].source())
            .config_label()
            .as_bytes(),
    );
    for root in &answer.roots {
        let identity = crate::analyzer::structural::canonical_identity_of(analyzer, root);
        digest.push(&serde_json::to_vec(&identity).expect("canonical identity serializes"));
    }
    Some(digest.finish().to_string())
}

/// The exact roots of one member's family: follow forward edges until a member
/// overrides and implements nothing.
///
/// One iterative closure with one explicit work stack, one seen set over the
/// *members* it has already expanded, and the caller's shared budget. It calls
/// [`forward_edges`] -- which walks a hierarchy and returns -- and never the
/// whole-family entry point, so no frame of this closure can start a second
/// closure with a fresh seen set.
///
/// A member with no forward edges is its own root, so `Base.run` and
/// `Service.run` agree on the root set and therefore on the family id.
///
/// A parse-level inheritance cycle (`class A extends B` beside `class B extends
/// A`, which javac rejects but Bifrost parses while a file is being edited)
/// reaches every member of the cycle once and then finds nothing left to
/// expand, leaving no member that overrides nothing. There is no root, so there
/// is no exact id, and the family says so with
/// [`MemberFamilyReason::FamilyRootNotCanonical`] instead of publishing a
/// proven family with an empty root set.
fn family_roots(
    walk: &mut FamilyWalk<'_>,
    member: &CodeUnit,
    edges: &[MemberFamilyEdge],
) -> Result<Vec<CodeUnit>, MemberFamilyReason> {
    let mut roots = Vec::new();
    let mut seen = vec![member.clone()];
    let mut stack: Vec<(CodeUnit, Vec<MemberFamilyEdge>)> = vec![(member.clone(), edges.to_vec())];
    while let Some((current, current_edges)) = stack.pop() {
        if current_edges.is_empty() {
            if !roots.contains(&current) {
                roots.push(current);
            }
            continue;
        }
        for edge in current_edges {
            if seen.contains(&edge.target) {
                continue;
            }
            walk.spend()?;
            seen.push(edge.target.clone());
            let ForwardStep::Edges { edges: above, .. } = forward_edges(walk, &edge.target)? else {
                // A root the analyzer cannot canonicalize makes the whole id
                // inexact, so the family reports incomplete instead.
                return Err(MemberFamilyReason::FamilyRootNotCanonical);
            };
            stack.push((edge.target, above));
        }
    }
    if roots.is_empty() {
        return Err(MemberFamilyReason::FamilyRootNotCanonical);
    }
    roots.sort();
    Ok(roots)
}

/// The declaration facts one Java member states about itself.
struct MemberFacts {
    identifier: String,
    is_static: bool,
    is_constructor: bool,
    is_private: bool,
    arity: Option<brokk_bifrost_core::analyzer::model::CallableArity>,
    parameter_types: Option<Vec<String>>,
    capability: MemberFamilyCapability,
}

impl MemberFacts {
    fn read(analyzer: &dyn IAnalyzer, member: &CodeUnit) -> Option<Self> {
        let metadata = analyzer
            .signature_metadata(member)
            .into_iter()
            .find(|metadata| metadata.callable_modifiers_recorded())?;
        let parameter_types = metadata.callable_parameter_types().map(<[String]>::to_vec);
        let capability = if parameter_types.is_some() {
            // Measured level for Java: the declaration walk records each
            // parameter's declared type *spelling* from its own `type` node.
            // It does not resolve or erase those spellings, so a spelling is a
            // discriminator inside an already bounded candidate set, never a
            // proof of type identity on its own.
            MemberFamilyCapability::ParameterTypeSpellings
        } else {
            MemberFamilyCapability::NameAndArity
        };
        Some(Self {
            identifier: member.identifier().to_string(),
            is_static: metadata.callable_is_static(),
            is_constructor: metadata.callable_is_constructor(),
            is_private: metadata.callable_declared_visibility()
                == Some(
                    brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility::Private,
                ),
            arity: metadata.callable_arity(),
            parameter_types,
            capability,
        })
    }

    /// The proven reason this member participates in no family, if any.
    fn exclusion(&self) -> Option<MemberFamilyReason> {
        if self.is_constructor {
            return Some(MemberFamilyReason::ConstructorExcluded);
        }
        if self.is_static {
            return Some(MemberFamilyReason::StaticMemberExcluded);
        }
        if self.is_private {
            return Some(MemberFamilyReason::PrivateMemberExcluded);
        }
        None
    }
}

enum AncestorMatch {
    None,
    One {
        target: CodeUnit,
        relation: MethodFamilyRelation,
        arity_unique: bool,
    },
    Unproven(MemberFamilyReason),
}

/// The one member of `ancestor` that `facts` redefines, if the recorded
/// evidence proves which one it is.
///
/// The candidate set is narrowed structurally first: same terminal identifier,
/// inheritable (not a constructor, not static, not private), and the same
/// recorded [`CallableArity`]. If that leaves exactly one member, the edge is
/// proven on structure alone. If it leaves more than one -- a genuine overload
/// set at the same arity -- the recorded parameter-type spellings are used as a
/// discriminator, and anything other than exactly one match is reported as
/// [`MemberFamilyReason::OverloadIdentityUnproven`] rather than guessed.
fn java_matching_member(
    analyzer: &dyn IAnalyzer,
    ancestor: &CodeUnit,
    facts: &MemberFacts,
) -> AncestorMatch {
    let mut candidates = Vec::new();
    for candidate in analyzer.direct_children(ancestor) {
        if !candidate.is_function() || candidate.identifier() != facts.identifier {
            continue;
        }
        let Some(candidate_facts) = MemberFacts::read(analyzer, &candidate) else {
            return AncestorMatch::Unproven(MemberFamilyReason::ModifiersUnrecorded);
        };
        // A constructor, a static method, and a private method are never
        // inherited, so none of them can be the member this one redefines.
        if candidate_facts.exclusion().is_some() {
            continue;
        }
        if candidate_facts.arity != facts.arity {
            continue;
        }
        candidates.push((candidate, candidate_facts));
    }
    if candidates.is_empty() {
        return AncestorMatch::None;
    }
    let relation = match owner_is_interface(analyzer, ancestor) {
        Some(true) => MethodFamilyRelation::Implements,
        Some(false) => MethodFamilyRelation::Overrides,
        None => return AncestorMatch::Unproven(MemberFamilyReason::OwnerKindUnrecorded),
    };
    if candidates.len() == 1 {
        return AncestorMatch::One {
            target: candidates.remove(0).0,
            relation,
            arity_unique: true,
        };
    }
    let Some(parameter_types) = facts.parameter_types.as_deref() else {
        return AncestorMatch::Unproven(MemberFamilyReason::OverloadIdentityUnproven);
    };
    let mut by_spelling = candidates.into_iter().filter(|(_, candidate_facts)| {
        candidate_facts.parameter_types.as_deref() == Some(parameter_types)
    });
    match (by_spelling.next(), by_spelling.next()) {
        (Some((target, _)), None) => AncestorMatch::One {
            target,
            relation,
            arity_unique: false,
        },
        _ => AncestorMatch::Unproven(MemberFamilyReason::OverloadIdentityUnproven),
    }
}

/// The measured capability for one Java member, read from what its declaration
/// actually recorded.
pub fn java_member_family_capability(
    analyzer: &dyn IAnalyzer,
    member: &CodeUnit,
) -> MemberFamilyCapability {
    if language_for_file(member.source()) != Language::Java {
        return MemberFamilyCapability::Unsupported;
    }
    MemberFacts::read(analyzer, member)
        .map(|facts| facts.capability)
        .unwrap_or(MemberFamilyCapability::Unsupported)
}

/// Whether the owner is an interface, from the kind the declaration walk
/// recorded. `None` when nothing recorded anything about the owner, which makes
/// the edge's relation unstatable rather than guessed.
///
/// A `CodeUnit` can carry more than one metadata entry, and an entry that no
/// producer qualified spells the flag `false` because `false` is its default.
/// Reading only the first entry therefore let an unqualified entry outvote a
/// producer that positively recorded `interface_declaration`. The same `find`
/// discipline [`MemberFacts::read`] uses applies here: the positive record is
/// the one that answers, and `false` is the answer only when no entry claims
/// the owner is an interface.
fn owner_is_interface(analyzer: &dyn IAnalyzer, owner: &CodeUnit) -> Option<bool> {
    let metadata = analyzer.signature_metadata(owner);
    if metadata.is_empty() {
        return None;
    }
    Some(
        metadata
            .iter()
            .any(brokk_bifrost_core::analyzer::model::SignatureMetadata::class_like_is_interface),
    )
}
