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

use brokk_bifrost_core::analyzer::model::CallableOverrideModifier;
use brokk_bifrost_core::analyzer::structural::resolution::{
    MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason, MethodFamilyRelation,
};
pub use brokk_bifrost_jvm::realm::{JvmExternalMemberIdentity, JvmReceiverSemantics};

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

/// What one language answers about method families.
///
/// The table below is *total*: it is an exhaustive `match` over every
/// [`Language`] variant with no wildcard arm, so adding a language to the enum
/// fails to compile until someone states what it answers here. That is the
/// point. Eleven independent resolvers cannot honestly inherit a default
/// `supported`, and a language that has landed no family must say so rather
/// than return an empty set a policy would read as proof (#1721).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberFamilySupport {
    /// The language has a provider, and this is the strongest member-identity
    /// evidence its declaration walk records.
    Supported(MemberFamilyCapability),
    /// The language has no provider. The string names the fact that is
    /// missing, so a reader knows what closing the gap requires.
    Unsupported(&'static str),
}

impl MemberFamilySupport {
    /// The capability a member of this language reports. Unsupported languages
    /// report [`MemberFamilyCapability::Unsupported`], never a weaker-but-real
    /// level that would read as a partial answer.
    pub const fn capability(self) -> MemberFamilyCapability {
        match self {
            Self::Supported(capability) => capability,
            Self::Unsupported(_) => MemberFamilyCapability::Unsupported,
        }
    }

    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

/// The total per-language method-family support table.
///
/// Every capability below is *measured*, not aspirational: it states what the
/// language's declaration walk actually records, which is why no language
/// claims [`MemberFamilyCapability::ErasedParameterTypes`]. No adapter resolves
/// or erases a parameter's declared type; each records the written spelling.
pub const fn member_family_support(language: Language) -> MemberFamilySupport {
    match language {
        // Nominal hierarchies walked by `nominal_member_family` below.
        Language::Java | Language::CSharp | Language::Scala => {
            MemberFamilySupport::Supported(MemberFamilyCapability::ParameterTypeSpellings)
        }
        // Structural: the workspace satisfaction index answers, and Go has no
        // overloading, so a whole method key singles a member out.
        Language::Go => {
            MemberFamilySupport::Supported(MemberFamilyCapability::ParameterTypeSpellings)
        }
        // Trait members and their impls, answered by the Rust hierarchy index.
        Language::Rust => {
            MemberFamilySupport::Supported(MemberFamilyCapability::ParameterTypeSpellings)
        }
        Language::Kotlin => MemberFamilySupport::Unsupported(
            "get_direct_ancestors does not distinguish a Kotlin interface edge from a superclass \
             edge, so an edge's relation would be unstatable",
        ),
        Language::Php => MemberFamilySupport::Unsupported(
            "a `use`d PHP trait flattens its members into the using class, and whether that is an \
             `implements` edge or no edge at all is an unmade contract decision",
        ),
        Language::Cpp => MemberFamilySupport::Unsupported(
            "the C++ declaration store indexes static and non-static members under one \
             `owner.member` form and no structured `virtual` modifier reaches the resolver",
        ),
        Language::JavaScript | Language::Python => {
            MemberFamilySupport::Unsupported("the language declares no override relation")
        }
        Language::TypeScript => MemberFamilySupport::Unsupported(
            "TypeScript typing is structural, so `implements` is a type-level question rather \
             than a member-level declaration",
        ),
        Language::Ruby => MemberFamilySupport::Unsupported(
            "Ruby module inclusion and singleton reopening resolve at run time, so a declaration \
             proves no family",
        ),
        Language::None => MemberFamilySupport::Unsupported("the file has no analyzed language"),
    }
}

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
    pub fn no_family(capability: MemberFamilyCapability, reason: MemberFamilyReason) -> Self {
        debug_assert!(reason.is_proven_exclusion());
        Self::not_proven(capability, MemberFamilyOutcome::NoFamily, reason)
    }

    pub fn incomplete(capability: MemberFamilyCapability, reason: MemberFamilyReason) -> Self {
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

/// Why an external-root workspace member-family query is incomplete even
/// though it is supported and was not cancelled or budget-exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalMemberFamilyIncompleteReason {
    ExternalRootUnresolved,
    HierarchyFactsUnavailable,
    MemberFactsUnavailable,
    OverloadIdentityUnproven,
    MixedJvmRealmUnsupported(Language),
}

/// Completion of an external-root workspace member-family query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalMemberFamilyStatus {
    Complete,
    Incomplete(ExternalMemberFamilyIncompleteReason),
    Unsupported,
    Cancelled,
    BudgetExhausted,
}

/// Exact workspace declarations that can implement or override one external
/// JVM member.
///
/// Only `Complete` carries candidates. Every other status preserves a
/// targetless dispatch boundary and publishes no partial candidate set as an
/// exhaustive answer.
#[derive(Debug, Clone)]
pub struct ExternalMemberFamilyAnswer {
    pub status: ExternalMemberFamilyStatus,
    pub candidates: Vec<CodeUnit>,
    pub visited: usize,
}

impl ExternalMemberFamilyAnswer {
    pub fn unsupported() -> Self {
        Self::stopped(ExternalMemberFamilyStatus::Unsupported, 0)
    }

    pub fn incomplete(reason: ExternalMemberFamilyIncompleteReason, visited: usize) -> Self {
        Self::stopped(ExternalMemberFamilyStatus::Incomplete(reason), visited)
    }

    pub(crate) fn stopped(status: ExternalMemberFamilyStatus, visited: usize) -> Self {
        debug_assert!(status != ExternalMemberFamilyStatus::Complete);
        Self {
            status,
            candidates: Vec::new(),
            visited,
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self.status, ExternalMemberFamilyStatus::Complete)
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

    /// Exact workspace implementations or overrides of an external JVM
    /// member. `max_visits` is supplied by the caller and covers the complete
    /// workspace hierarchy/member scan; cancellation and exhaustion are
    /// distinguishable so neither can be mistaken for a complete-empty proof.
    fn external_member_family(
        &self,
        _identity: &JvmExternalMemberIdentity,
        _max_visits: usize,
        _cancellation: Option<&CancellationToken>,
    ) -> ExternalMemberFamilyAnswer {
        ExternalMemberFamilyAnswer::unsupported()
    }
}

/// The shared state of one member's family answer: the two sources the walk
/// reads, the request's cancellation token, and the one visit budget every
/// walk of that answer draws from.
struct FamilyWalk<'a> {
    analyzer: &'a dyn IAnalyzer,
    hierarchy: &'a dyn TypeHierarchyProvider,
    rules: &'a dyn NominalFamilyRules,
    cancellation: Option<&'a CancellationToken>,
    remaining: usize,
}

impl<'a> FamilyWalk<'a> {
    fn new(
        analyzer: &'a dyn IAnalyzer,
        hierarchy: &'a dyn TypeHierarchyProvider,
        rules: &'a dyn NominalFamilyRules,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            analyzer,
            hierarchy,
            rules,
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
    let language = language_for_file(member.source());
    // Two gates, and they are different questions. The first is whether this
    // rule answers for this member's language at all; the second is whether
    // the support table still lists that language as supported. Consulting the
    // table here is what gives it teeth: removing a language from it disables
    // the provider rather than leaving a stale claim beside live code.
    if language != walk.rules.language() || !member_family_support(language).is_supported() {
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
    if let Some(reason) = walk.rules.exclusion(&facts) {
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
            match matching_member(walk.rules, walk.analyzer, &ancestor, &facts) {
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
    if edges.is_empty() && facts.override_modifier() == Some(CallableOverrideModifier::Override) {
        // The declaration states that it redefines an inherited member and the
        // walk, which saw every ancestor the workspace indexes, found none. The
        // hierarchy above this owner is therefore short: the base lives in a
        // dependency the workspace does not index -- the .NET `object.ToString`
        // a C# `public override string ToString()` redefines, say. That is
        // missing evidence, not a proven empty family, so the answer is
        // incomplete and carries no id (#1721).
        //
        // Stated gap: a language that records no override modifier cannot
        // reach this. Java is the one that matters, because `@Override` is an
        // annotation the compiler checks rather than a modifier that creates
        // the relation, and because every Java class implicitly extends
        // `java.lang.Object` without writing an `extends` clause the walk can
        // see. A Java `toString` therefore still answers `proven` with no
        // edges. Closing that needs the activated dependency-pack overlay's
        // universal root, which is tracked as the next tranche of this issue
        // and pinned by
        // `java_tostring_over_an_unindexed_jdk_is_a_stated_gap`.
        return Ok(ForwardStep::Answer(MemberFamilyAnswer::incomplete(
            capability,
            MemberFamilyReason::AncestorExternalUnindexed,
        )));
    }
    edges.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(ForwardStep::Edges { owner, edges })
}

/// One member's family in both directions for a language whose overriding is
/// *nominal*: a member redefines a member of a named ancestor type.
///
/// Parameterized over three things and no more. `analyzer` holds members and
/// their recorded declaration metadata. `hierarchy` holds ancestor and
/// descendant edges. `rules` is the language's own override rule -- what
/// excludes a member from families, whether an ancestor is a class or an
/// interface, and when an ancestor member is the one this member redefines.
/// Java, C# and Scala differ only in `rules`; the walk, the budget, the seen
/// sets, the root closure, the inversion and the family id are shared, which
/// is what makes their answers comparable rather than merely similar.
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
pub fn nominal_member_family(
    analyzer: &dyn IAnalyzer,
    hierarchy: &dyn TypeHierarchyProvider,
    rules: &dyn NominalFamilyRules,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    let capability = nominal_member_family_capability(analyzer, rules, member);
    let mut walk = FamilyWalk::new(analyzer, hierarchy, rules, cancellation);
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

/// The declaration facts one member states about itself, as its adapter
/// recorded them.
///
/// Public because [`NominalFamilyRules::admits`] receives two of them; the
/// fields stay private because the only facts a language rule needs to read
/// are the ones with accessors below. Everything else the shared walk consumes
/// itself.
pub struct MemberFacts {
    identifier: String,
    is_static: bool,
    is_constructor: bool,
    is_private: bool,
    arity: Option<brokk_bifrost_core::analyzer::model::CallableArity>,
    parameter_types: Option<Vec<String>>,
    /// Which override-family modifier the declaration states, or `None` when
    /// the adapter never read them. The difference matters: a C# member that
    /// declares none *hides* an inherited member, while one whose modifiers
    /// were never read proves nothing either way.
    override_modifier: Option<CallableOverrideModifier>,
    capability: MemberFamilyCapability,
}

impl MemberFacts {
    pub(crate) fn read(analyzer: &dyn IAnalyzer, member: &CodeUnit) -> Option<Self> {
        let metadata = analyzer
            .signature_metadata(member)
            .into_iter()
            .find(|metadata| metadata.callable_modifiers_recorded())?;
        let parameter_types = metadata.callable_parameter_types().map(<[String]>::to_vec);
        let override_modifier = metadata.callable_override_modifier();
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
            override_modifier,
            capability,
        })
    }

    /// Which override-family modifier this declaration states, or `None` when
    /// the adapter never read its modifier nodes for that family.
    pub fn override_modifier(&self) -> Option<CallableOverrideModifier> {
        self.override_modifier
    }

    /// Whether the declaration is recorded as static.
    ///
    /// What that *means* is the language's business, which is why the family
    /// exclusion asks for it rather than applying it: in Java and C# a static
    /// member is not inherited, while Scala has no `static` keyword at all and
    /// records the flag to mean "member of an `object`" -- and an `object`
    /// extending a trait implements that trait's members.
    pub fn is_static(&self) -> bool {
        self.is_static
    }

    pub(crate) fn arity(&self) -> Option<brokk_bifrost_core::analyzer::model::CallableArity> {
        self.arity
    }

    /// The reason this member participates in no family in *any* nominal
    /// language: a constructor is never inherited, and neither is a private
    /// member.
    pub fn universal_exclusion(&self) -> Option<MemberFamilyReason> {
        if self.is_constructor {
            return Some(MemberFamilyReason::ConstructorExcluded);
        }
        if self.is_private {
            return Some(MemberFamilyReason::PrivateMemberExcluded);
        }
        None
    }
}

/// One language's own override rule.
///
/// Everything a nominal method family needs that differs between languages
/// lives behind this trait; everything that does not -- the metered ancestor
/// walk, the root closure, the bounded inversion, the family id -- is shared.
/// It is a trait with one unit struct per language rather than an enum
/// parameter because these are three different rules, not three modes of one.
pub trait NominalFamilyRules {
    /// The language whose members this rule answers for. A member of any other
    /// language is `unsupported`, even when this provider was reached.
    fn language(&self) -> Language;

    /// Whether an ancestor declares its members in an interface-like space
    /// (`implements`) or a class-like one (`overrides`).
    ///
    /// `None` when nothing recorded the ancestor's kind, which makes the
    /// edge's relation unstatable rather than guessed.
    ///
    /// The default reads the `class_like_is_interface` fact the declaration
    /// walk records, which is genuinely one rule across all three languages
    /// here: a Java interface, a C# interface and a Scala trait are the same
    /// declaration space wearing three names, and each adapter records the
    /// flag on the template itself. A language whose owner kinds do not reduce
    /// to that -- one with two distinct interface-like spaces, say -- must
    /// override this rather than stretch the flag.
    fn relation(
        &self,
        analyzer: &dyn IAnalyzer,
        ancestor: &CodeUnit,
    ) -> Option<MethodFamilyRelation> {
        match owner_is_interface(analyzer, ancestor) {
            Some(true) => Some(MethodFamilyRelation::Implements),
            Some(false) => Some(MethodFamilyRelation::Overrides),
            None => None,
        }
    }

    /// The proven reason this member participates in no family at all, if the
    /// language says there is one.
    ///
    /// The default adds `static` to the two universal exclusions, which is the
    /// rule for a language whose `static` members are not inherited. A
    /// language that records the flag to mean something else must override
    /// this.
    fn exclusion(&self, facts: &MemberFacts) -> Option<MemberFamilyReason> {
        facts.universal_exclusion().or_else(|| {
            facts
                .is_static()
                .then_some(MemberFamilyReason::StaticMemberExcluded)
        })
    }

    /// Whether `ancestor_member` -- already narrowed to the same terminal
    /// identifier, the same recorded arity, and inheritable -- may be the
    /// member that `member` redefines across an edge of `relation`.
    ///
    /// The default admits it, which is the rule for a language where a
    /// redeclaration in a subtype *is* an override (Java, Scala). A language
    /// that requires the redeclaration to opt in overrides this.
    fn admits(
        &self,
        _relation: MethodFamilyRelation,
        _ancestor_member: &MemberFacts,
        _member: &MemberFacts,
    ) -> Admission {
        Admission::Yes
    }
}

/// Whether one already-narrowed ancestor member survives the language's own
/// redefinition rule.
pub enum Admission {
    Yes,
    /// The language proves this ancestor member is not the one redefined --
    /// a C# member hidden by `new`, say. A proven exclusion, not missing
    /// evidence, so the answer stays complete.
    No,
    /// The fact the rule needs was never recorded. The whole family answer
    /// becomes `incomplete` with this reason rather than guessing either way.
    Unproven(MemberFamilyReason),
}

/// Java: a redeclaration in a subtype is an override. The language has no
/// opt-in keyword (`@Override` is an annotation the compiler checks, not a
/// modifier that creates the relation), so structure alone decides.
pub struct JavaFamilyRules;

impl NominalFamilyRules for JavaFamilyRules {
    fn language(&self) -> Language {
        Language::Java
    }
}

/// C#: an interface member is implemented with no keyword at all, but a class
/// member is only *overridden* when the derived member writes `override` and
/// the base member is `virtual`, `abstract`, or itself an `override`.
///
/// The class rule is not pedantry. A derived member that writes `new`, or that
/// writes nothing, *hides* the base member: both keep their own identity and a
/// call through the base type still reaches the base member. Reporting hiding
/// as overriding would be wrong rather than incomplete, and would make the
/// class-hierarchy dispatch expansion in
/// `semantic/workspace_oracle/dispatch.rs` offer a body the call can never
/// reach.
pub struct CSharpFamilyRules;

impl NominalFamilyRules for CSharpFamilyRules {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn admits(
        &self,
        relation: MethodFamilyRelation,
        ancestor_member: &MemberFacts,
        member: &MemberFacts,
    ) -> Admission {
        // Implicit interface implementation writes no modifier, so an
        // interface edge is admitted on structure alone. (Explicit
        // implementation -- `void IFoo.Bar()` -- is a known gap: the
        // declaration walk records the written name, so the member does not
        // narrow to the interface member's terminal identifier and never
        // reaches this rule.)
        if relation == MethodFamilyRelation::Implements {
            return Admission::Yes;
        }
        let (Some(derived), Some(base)) = (
            member.override_modifier(),
            ancestor_member.override_modifier(),
        ) else {
            return Admission::Unproven(MemberFamilyReason::ModifiersUnrecorded);
        };
        if derived == CallableOverrideModifier::Override && base.is_overridable() {
            Admission::Yes
        } else {
            Admission::No
        }
    }
}

/// Scala: `override` is mandatory only when redefining a *concrete* member and
/// optional when implementing an abstract one, so the keyword cannot be the
/// gate. Structure decides, exactly as in Java, and the recorded keyword is
/// corroborating evidence rather than a condition.
///
/// The relation follows trait-ness, which the Scala declaration walk records
/// on the template itself. That is the same rule `ScalaAnalyzer::relation_kind`
/// applies to *type* relations, so a member relation and the type relation
/// above it agree by construction rather than by coincidence.
pub struct ScalaFamilyRules;

impl NominalFamilyRules for ScalaFamilyRules {
    fn language(&self) -> Language {
        Language::Scala
    }

    fn exclusion(&self, facts: &MemberFacts) -> Option<MemberFamilyReason> {
        // Scala has no `static` modifier. The declaration walk records the
        // flag to mean "member of an `object`", which the call-shape layer
        // needs in order to describe `Service.run()`, but an `object` is a
        // singleton *type* and `object Service extends Runner` implements
        // `Runner.run` exactly as a class would. Applying the default rule
        // here would exclude every object member from every family.
        facts.universal_exclusion()
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
/// recorded [`CallableArity`]. The language's own rule then decides which of
/// those survive -- for C#, that the redeclaration opted in with `override`.
/// If exactly one survives, the edge is proven on structure alone. If more
/// than one does -- a genuine overload set at the same arity -- the recorded
/// parameter-type spellings are used as a discriminator, and anything other
/// than exactly one match is reported as
/// [`MemberFamilyReason::OverloadIdentityUnproven`] rather than guessed.
fn matching_member(
    rules: &dyn NominalFamilyRules,
    analyzer: &dyn IAnalyzer,
    ancestor: &CodeUnit,
    facts: &MemberFacts,
) -> AncestorMatch {
    let Some(relation) = rules.relation(analyzer, ancestor) else {
        return AncestorMatch::Unproven(MemberFamilyReason::OwnerKindUnrecorded);
    };
    let mut candidates = Vec::new();
    for candidate in analyzer.direct_children(ancestor) {
        if !candidate.is_function() || candidate.identifier() != facts.identifier {
            continue;
        }
        let Some(candidate_facts) = MemberFacts::read(analyzer, &candidate) else {
            return AncestorMatch::Unproven(MemberFamilyReason::ModifiersUnrecorded);
        };
        // A member the language never inherits cannot be the one this member
        // redefines.
        if rules.exclusion(&candidate_facts).is_some() {
            continue;
        }
        if candidate_facts.arity != facts.arity {
            continue;
        }
        match rules.admits(relation, &candidate_facts, facts) {
            Admission::Yes => candidates.push((candidate, candidate_facts)),
            Admission::No => continue,
            Admission::Unproven(reason) => return AncestorMatch::Unproven(reason),
        }
    }
    if candidates.is_empty() {
        return AncestorMatch::None;
    }
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

/// The measured capability for one member of a nominal-family language, read
/// from what its own declaration actually recorded.
///
/// The support table states the language's ceiling; this states what *this*
/// declaration reached. A member whose parameter-type spellings were never
/// recorded is [`MemberFamilyCapability::NameAndArity`] even in a language the
/// table calls `parameter_type_spellings`, because the capability published
/// beside an answer must describe the evidence behind that answer.
pub fn nominal_member_family_capability(
    analyzer: &dyn IAnalyzer,
    rules: &dyn NominalFamilyRules,
    member: &CodeUnit,
) -> MemberFamilyCapability {
    let language = language_for_file(member.source());
    if language != rules.language() || !member_family_support(language).is_supported() {
        return MemberFamilyCapability::Unsupported;
    }
    MemberFacts::read(analyzer, member)
        .map(|facts| facts.capability)
        .unwrap_or(MemberFamilyCapability::Unsupported)
}

/// The Java family, in both directions. See [`nominal_member_family`].
pub fn java_member_family(
    analyzer: &dyn IAnalyzer,
    hierarchy: &dyn TypeHierarchyProvider,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    nominal_member_family(analyzer, hierarchy, &JavaFamilyRules, member, cancellation)
}

pub fn java_member_family_capability(
    analyzer: &dyn IAnalyzer,
    member: &CodeUnit,
) -> MemberFamilyCapability {
    nominal_member_family_capability(analyzer, &JavaFamilyRules, member)
}

/// The C# family, in both directions. See [`nominal_member_family`].
pub fn csharp_member_family(
    analyzer: &dyn IAnalyzer,
    hierarchy: &dyn TypeHierarchyProvider,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    nominal_member_family(
        analyzer,
        hierarchy,
        &CSharpFamilyRules,
        member,
        cancellation,
    )
}

pub fn csharp_member_family_capability(
    analyzer: &dyn IAnalyzer,
    member: &CodeUnit,
) -> MemberFamilyCapability {
    nominal_member_family_capability(analyzer, &CSharpFamilyRules, member)
}

/// The Scala family, in both directions. See [`nominal_member_family`].
pub fn scala_member_family(
    analyzer: &dyn IAnalyzer,
    hierarchy: &dyn TypeHierarchyProvider,
    member: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> MemberFamilyAnswer {
    nominal_member_family(analyzer, hierarchy, &ScalaFamilyRules, member, cancellation)
}

pub fn scala_member_family_capability(
    analyzer: &dyn IAnalyzer,
    member: &CodeUnit,
) -> MemberFamilyCapability {
    nominal_member_family_capability(analyzer, &ScalaFamilyRules, member)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The support table is total and honest.
    ///
    /// Totality is a compile-time property -- [`member_family_support`] is an
    /// exhaustive `match` with no wildcard arm, so a new [`Language`] variant
    /// fails to build until it is listed. This test states the two run-time
    /// properties the match cannot: every unsupported arm names the fact that
    /// is missing, and no arm claims a capability while reporting itself
    /// unsupported.
    #[test]
    fn member_family_support_table_is_total_and_states_every_gap() {
        for language in Language::ALL {
            match member_family_support(language) {
                MemberFamilySupport::Supported(capability) => {
                    assert_ne!(
                        capability,
                        MemberFamilyCapability::Unsupported,
                        "{language:?} claims support with no capability"
                    );
                    assert_ne!(
                        capability,
                        MemberFamilyCapability::ErasedParameterTypes,
                        "{language:?} claims erased parameter types, but no adapter resolves or \
                         erases a declared parameter type; each records the written spelling"
                    );
                }
                MemberFamilySupport::Unsupported(reason) => {
                    assert!(
                        !reason.trim().is_empty(),
                        "{language:?} is unsupported without naming the missing fact"
                    );
                    assert_eq!(
                        member_family_support(language).capability(),
                        MemberFamilyCapability::Unsupported,
                        "{language:?} reports a capability it cannot back"
                    );
                }
            }
        }
    }

    /// Every language the nominal walk implements is listed as supported, and
    /// each rule answers for exactly the language the table names.
    ///
    /// This is what keeps the table from drifting away from the code: adding a
    /// rule without listing it, or listing a language whose rule was removed,
    /// fails here rather than silently answering `unsupported` at run time.
    #[test]
    fn nominal_rules_and_the_support_table_agree() {
        let rules: [&dyn NominalFamilyRules; 3] =
            [&JavaFamilyRules, &CSharpFamilyRules, &ScalaFamilyRules];
        for rule in rules {
            assert!(
                member_family_support(rule.language()).is_supported(),
                "{:?} has a nominal family rule but the table calls it unsupported",
                rule.language()
            );
        }
    }
}
