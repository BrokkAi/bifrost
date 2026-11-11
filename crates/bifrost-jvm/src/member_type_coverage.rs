//! The shared member-type coverage pass of the JVM lowerers (#9546).
//!
//! An inherited member-type tier may treat a source owner as closed only when
//! its producer proves that every type the owner declares through its own type
//! body was published as a member-type row for that owner. This pass makes that
//! proof after the lowering walk: for each type body a lowerer published as its
//! owner's TypeBody scope, it classifies every member of the body with the
//! language's census and checks the emitted member rows, instead of trusting
//! that the walk reached every declaration. A body that no lowerer recorded
//! gets no claim, so its owner stays Unknown.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, MemberTypesCoverage, MemberTypesOpenReason, ResolutionMemberKind,
    ResolutionMemberTypeCoverageFact, ResolutionSiteId,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// How one language's grammar places member declarations in a type body.
///
/// Every named node kind that can be a member of a listed body, directly or
/// through a listed wrapper, appears in exactly one list. Each language's
/// grammar census test enumerates its grammar's node types to prove it, so a
/// grammar upgrade that adds a member form fails until the form is classified.
pub(crate) struct MemberTypeCensus {
    /// The node kinds a lowerer records as owner type bodies.
    pub(crate) type_bodies: &'static [&'static str],
    /// Nodes inside a body that hold more members of the same owner.
    pub(crate) wrappers: &'static [&'static str],
    /// Declarations that must publish a named member-type row for the owner.
    pub(crate) type_declarations: &'static [&'static str],
    /// Members that declare no member type of this owner. A member whose own
    /// body the lowerer gives a separate owner (an anonymous class) is one.
    pub(crate) non_type_members: &'static [&'static str],
    /// Comments and other extras the grammar allows anywhere.
    pub(crate) trivia: &'static [&'static str],
    /// Forms that can make a type a member of this owner without publishing
    /// a member-type row for it.
    pub(crate) opaque: &'static [(&'static str, MemberTypesOpenReason)],
    /// Members whose own body the lowerer keeps in this owner's scope. They
    /// are non-type members unless that body declares a type.
    pub(crate) entry_bodies: &'static [(&'static str, MemberTypesOpenReason)],
    /// The node whose byte range the lowerer gives a member type's declaration
    /// site, or `None` when the declaration has no spelled name.
    pub(crate) declaration_site: for<'tree> fn(Node<'tree>) -> Option<Node<'tree>>,
}

/// Digest of the classified grammar kinds and their open reason labels.
pub fn member_type_census_digest(language: Language) -> [u8; 32] {
    let census = match language {
        Language::Java => &crate::java::resolution::JAVA_MEMBER_TYPE_CENSUS,
        Language::Kotlin => &crate::kotlin::resolution::KOTLIN_MEMBER_TYPE_CENSUS,
        Language::Scala => &crate::scala::resolution::SCALA_MEMBER_TYPE_CENSUS,
        _ => panic!("member-type census requires a JVM language: {language:?}"),
    };
    let mut lines = Vec::new();
    for (category, kinds) in [
        ("type_bodies", census.type_bodies),
        ("wrappers", census.wrappers),
        ("type_declarations", census.type_declarations),
        ("non_type_members", census.non_type_members),
        ("trivia", census.trivia),
    ] {
        lines.extend(kinds.iter().map(|kind| format!("{category}:{kind}")));
    }
    lines.extend(
        census
            .opaque
            .iter()
            .map(|(kind, reason)| format!("opaque:{kind}:{}", reason.label())),
    );
    lines.extend(
        census
            .entry_bodies
            .iter()
            .map(|(kind, reason)| format!("entry_bodies:{kind}:{}", reason.label())),
    );
    lines.sort_unstable();
    sha256_bytes(lines.join("\n").as_bytes())
}

/// A type body that a lowerer published as its owner's TypeBody scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberTypeBody {
    owner: ResolutionSiteId,
    kind: &'static str,
    start_byte: usize,
    end_byte: usize,
}

impl MemberTypeBody {
    pub(crate) fn new(owner: ResolutionSiteId, body: Node<'_>) -> Self {
        Self {
            owner,
            kind: body.kind(),
            start_byte: body.start_byte(),
            end_byte: body.end_byte(),
        }
    }

    pub(crate) fn owner(&self) -> ResolutionSiteId {
        self.owner
    }
}

/// One claim per recorded body, in recording order.
pub(crate) fn member_type_coverage(
    root: Node<'_>,
    bodies: &[MemberTypeBody],
    facts: &FileResolutionFacts,
    census: &MemberTypeCensus,
) -> Vec<ResolutionMemberTypeCoverageFact> {
    let site_ranges = facts
        .sites
        .iter()
        .map(|site| (site.id, (site.start_byte, site.end_byte)))
        .collect::<HashMap<_, _>>();
    let mut emitted = HashMap::<ResolutionSiteId, HashSet<(usize, usize)>>::default();
    for member in facts.member_owners.iter().filter(|member| {
        matches!(
            member.kind,
            ResolutionMemberKind::NestedType | ResolutionMemberKind::AssociatedType
        )
    }) {
        let range = site_ranges[&member.member];
        emitted.entry(member.owner).or_default().insert(range);
    }
    let mut owners = HashSet::default();
    bodies
        .iter()
        .map(|body| {
            assert!(
                owners.insert(body.owner),
                "one recorded type body per owner: {body:?}"
            );
            assert!(
                census.type_bodies.contains(&body.kind),
                "recorded type body kind is in the census: {body:?}"
            );
            let node = recorded_body(root, body);
            ResolutionMemberTypeCoverageFact {
                owner: body.owner,
                coverage: classify_body(
                    node,
                    emitted.get(&body.owner).unwrap_or(&HashSet::default()),
                    census,
                ),
            }
        })
        .collect()
}

/// The recorded body node itself: the smallest node of the recorded kind
/// that spans exactly the recorded range.
fn recorded_body<'tree>(root: Node<'tree>, body: &MemberTypeBody) -> Node<'tree> {
    let mut node = root
        .descendant_for_byte_range(body.start_byte, body.end_byte)
        .expect("a recorded body lies inside its tree");
    while node.kind() != body.kind
        || node.start_byte() != body.start_byte
        || node.end_byte() != body.end_byte
    {
        node = node
            .parent()
            .unwrap_or_else(|| panic!("recorded body is a node of its tree: {body:?}"));
    }
    node
}

fn classify_body(
    body: Node<'_>,
    emitted: &HashSet<(usize, usize)>,
    census: &MemberTypeCensus,
) -> MemberTypesCoverage {
    // Error recovery can absorb a later declaration into an ERROR or MISSING
    // node anywhere in the body, so any error opens the owner.
    if body.has_error() {
        return MemberTypesCoverage::Open(MemberTypesOpenReason::Malformed);
    }
    let mut pending = vec![body];
    while let Some(container) = pending.pop() {
        let mut cursor = container.walk();
        for member in container.named_children(&mut cursor) {
            let kind = member.kind();
            if census.trivia.contains(&kind) || census.non_type_members.contains(&kind) {
                continue;
            }
            if census.wrappers.contains(&kind) {
                pending.push(member);
                continue;
            }
            if let Some(&(_, reason)) = census.opaque.iter().find(|(opaque, _)| *opaque == kind) {
                return MemberTypesCoverage::Open(reason);
            }
            if let Some(&(_, reason)) = census.entry_bodies.iter().find(|(entry, _)| *entry == kind)
            {
                if declares_type(member, census) {
                    return MemberTypesCoverage::Open(reason);
                }
                continue;
            }
            if census.type_declarations.contains(&kind) {
                let Some(site) = (census.declaration_site)(member) else {
                    return MemberTypesCoverage::Open(
                        MemberTypesOpenReason::UnnamedTypeDeclaration,
                    );
                };
                if !emitted.contains(&(site.start_byte(), site.end_byte())) {
                    return MemberTypesCoverage::Open(MemberTypesOpenReason::MemberRowMissing);
                }
                continue;
            }
            return MemberTypesCoverage::Open(MemberTypesOpenReason::UnrecognizedForm);
        }
    }
    MemberTypesCoverage::Complete
}

/// Whether an entry member's own body declares a type. Only that body's
/// members, and members of its wrappers, are searched: a nested type body
/// belongs to the nested declaration.
fn declares_type(entry: Node<'_>, census: &MemberTypeCensus) -> bool {
    let mut pending = vec![entry];
    while let Some(node) = pending.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let kind = child.kind();
            if census.type_declarations.contains(&kind)
                || census.opaque.iter().any(|(opaque, _)| *opaque == kind)
            {
                return true;
            }
            if census.type_bodies.contains(&kind) || census.wrappers.contains(&kind) {
                pending.push(child);
            }
        }
    }
    false
}

/// Assert that `census` classifies every named node kind that the grammar
/// allows as a member of one of its type bodies or wrappers, exactly once.
#[cfg(test)]
pub(crate) fn assert_census_covers_grammar(node_types: &str, census: &MemberTypeCensus) {
    let nodes: Vec<serde_json::Value> = serde_json::from_str(node_types).unwrap();
    let named = |kind: &str| {
        nodes
            .iter()
            .find(|node| node["type"] == kind && node["named"] == true)
            .unwrap_or_else(|| panic!("grammar has named node kind {kind}"))
    };
    // Concrete kinds: a supertype entry expands to its subtypes.
    let concrete = |kind: &str| {
        let mut out = Vec::new();
        let mut pending = vec![kind.to_owned()];
        while let Some(kind) = pending.pop() {
            match named(&kind)["subtypes"].as_array() {
                Some(subtypes) => pending.extend(
                    subtypes
                        .iter()
                        .map(|subtype| subtype["type"].as_str().unwrap().to_owned()),
                ),
                None => out.push(kind),
            }
        }
        out
    };
    let members_of = |kind: &str| {
        let node = named(kind);
        let mut types = Vec::new();
        if let Some(children) = node["children"]["types"].as_array() {
            types.extend(children);
        }
        if let Some(fields) = node["fields"].as_object() {
            for field in fields.values() {
                types.extend(field["types"].as_array().unwrap());
            }
        }
        types
            .into_iter()
            .filter(|ty| ty["named"] == true)
            .flat_map(|ty| concrete(ty["type"].as_str().unwrap()))
            .collect::<Vec<_>>()
    };
    let mut containers = census
        .type_bodies
        .iter()
        .chain(census.wrappers)
        .copied()
        .collect::<Vec<_>>();
    let mut seen = HashSet::default();
    let mut unclassified = Vec::new();
    while let Some(container) = containers.pop() {
        for member in members_of(container) {
            if !seen.insert(member.clone()) {
                continue;
            }
            let classes = [
                census.wrappers.contains(&member.as_str()),
                census.type_declarations.contains(&member.as_str()),
                census.non_type_members.contains(&member.as_str()),
                census.trivia.contains(&member.as_str()),
                census.opaque.iter().any(|(kind, _)| *kind == member),
                census.entry_bodies.iter().any(|(kind, _)| *kind == member),
            ];
            match classes.iter().filter(|class| **class).count() {
                0 => unclassified.push(member),
                1 => {}
                _ => panic!("{member} is classified more than once"),
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "type-body member kinds the census does not classify: {unclassified:?}"
    );
    for kind in census.trivia {
        assert!(
            nodes
                .iter()
                .any(|node| node["type"] == *kind && node["named"] == true),
            "trivia kind {kind} is a named grammar node"
        );
    }
}
