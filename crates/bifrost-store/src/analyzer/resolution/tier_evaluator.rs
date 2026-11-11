//! Query-local precedence evaluation over selected, closed candidate inventories.
//!
//! Producers supply candidates and closure receipts. A positive candidate does
//! not close its tier: every applicable contributor must have been exhausted.

use super::model::{BindingNodeId, SemanticId};
use super::precedence::{BindingScopeCoordinate, BindingScopeRelation};
use super::{batch::ReferenceLocalPathEvidence, fact_source::JvmAccessEndpoint};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use std::collections::HashMap;

/// One inherited member-type answer, rebound to the final operation's identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InheritedTierWitness {
    Absent,
    /// Sorted and deduplicated declaration identities.
    Proven(Vec<SemanticId>),
    Open {
        frontier: Vec<InheritedFrontier>,
        reasons: Vec<&'static str>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InheritedFrontier {
    pub owner: Option<SemanticId>,
    pub reason: &'static str,
}

/// A caller freezes this query-local table before evaluating references.
#[derive(Default)]
pub struct InheritedTierKnowledge {
    entries: HashMap<(SemanticId, SemanticId), InheritedTierWitness>,
}

impl InheritedTierKnowledge {
    pub fn from_entries(
        entries: impl IntoIterator<Item = ((SemanticId, SemanticId), InheritedTierWitness)>,
    ) -> Self {
        let mut result = Self::default();
        for ((owner, lookup), witness) in entries {
            if let InheritedTierWitness::Proven(candidates) = &witness {
                debug_assert!(candidates.windows(2).all(|pair| pair[0] < pair[1]));
            }
            assert!(result.entries.insert((owner, lookup), witness).is_none());
        }
        result
    }

    pub fn witness(&self, owner: SemanticId, lookup: SemanticId) -> InheritedTierWitness {
        self.entries
            .get(&(owner, lookup))
            .cloned()
            .unwrap_or(InheritedTierWitness::Open {
                frontier: Vec::new(),
                reasons: vec!["inherited-witness-missing"],
            })
    }
}

#[cfg(test)]
mod inherited_tier_tests {
    use super::*;

    #[test]
    fn missing_inherited_answer_stays_open() {
        let owner = SemanticId::for_test("owner");
        let name = SemanticId::for_test("name");
        let table =
            InheritedTierKnowledge::from_entries([((owner, name), InheritedTierWitness::Absent)]);
        assert_eq!(table.witness(owner, name), InheritedTierWitness::Absent);
        assert_eq!(
            table.witness(SemanticId::for_test("other owner"), name),
            InheritedTierWitness::Open {
                frontier: Vec::new(),
                reasons: vec!["inherited-witness-missing"],
            }
        );
    }
}

/// Where one lexical definition sits in Java's scope order for a simple type
/// name (JLS 6.3, 6.4.1, 8.5), relative to the reference's enclosing classes,
/// innermost first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexicalTypeLevel {
    /// Inward of the innermost class body: local classes and method type
    /// parameters.
    Local,
    /// Bound in class `i`'s own body: a member type that class declares.
    Declared(usize),
    /// Outward of class `i`'s body and inward of class `i + 1`'s: the type
    /// parameters of class `i`, and for a local class the blocks around it.
    /// Class `i`'s inherited member types shadow these, because the body's
    /// members shadow the scopes around it.
    Outside(usize),
    /// Outward of the outermost class body: the compilation unit's types.
    Unit,
}

/// A placed definition and its binding scope's position on the reference's
/// checkpoint ancestry, counted from the reference outward. Within one level
/// the nearer scope shadows the farther one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacedLexicalType {
    pub level: LexicalTypeLevel,
    pub ancestry_position: usize,
}

/// Place one definition by its binding scope on the reference's checkpoint
/// ancestry. The binder's scope decides shadowing, so no declaration kind is
/// needed: a type binder in class `i`'s body scope is a member type of class
/// `i`, and a binder between two class bodies is in a scope that class `i`'s
/// members shadow. Ancestry positions run from the reference outward. None
/// means the order is not proved: the binding scope is not on the reference's
/// ancestry, or a class body head is not in the same key space.
pub fn place_lexical_type(
    definition: SemanticId,
    evidence: &ReferenceLocalPathEvidence,
    access: &JvmAccessEndpoint,
) -> Option<PlacedLexicalType> {
    let ancestry = evidence.ordered_checkpoint_ancestry();
    let position_of = |node: BindingNodeId| {
        ancestry
            .iter()
            .position(|(candidate, _)| *candidate == node)
    };
    let position = evidence
        .definition_endpoints()
        .iter()
        .find(|(id, _)| *id == definition)
        .and_then(|(_, endpoint)| position_of(*endpoint))?;
    let mut bodies = Vec::with_capacity(access.enclosing_template_heads.len());
    for head in &access.enclosing_template_heads {
        let body = head.and_then(position_of)?;
        // Templates are listed innermost first, so their bodies must lie
        // strictly outward of one another.
        if bodies.last().is_some_and(|inner| *inner >= body) {
            return None;
        }
        bodies.push(body);
    }
    let level = match bodies.iter().position(|body| position <= *body) {
        Some(0) if position < bodies[0] => LexicalTypeLevel::Local,
        Some(level) if position == bodies[level] => LexicalTypeLevel::Declared(level),
        Some(level) => LexicalTypeLevel::Outside(level - 1),
        None => LexicalTypeLevel::Unit,
    };
    Some(PlacedLexicalType {
        level,
        ancestry_position: position,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TierQuestion {
    SimpleTypeName {
        scope: BindingScopeCoordinate,
        name: String,
        namespace: ResolutionNamespace,
    },
}

/// Names the selected read that certified a contributor's inventory.
/// The value is query-local; persistence belongs to the read-key layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierReceipt {
    pub selected_read: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContributorClosure {
    Closed(TierReceipt),
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierContributor<C> {
    pub candidates: Vec<C>,
    pub closure: ContributorClosure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierInput<C> {
    /// Lower values have stronger precedence.
    pub rank: u32,
    pub contributors: Vec<TierContributor<C>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TierWitness<C> {
    Absent {
        receipts: Vec<TierReceipt>,
    },
    Open {
        candidates: Vec<C>,
        receipts: Vec<TierReceipt>,
    },
    Proven {
        candidates: Vec<C>,
        receipts: Vec<TierReceipt>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TierDecision<C> {
    Absent {
        receipts: Vec<TierReceipt>,
    },
    Open {
        possible: Vec<C>,
        receipts: Vec<TierReceipt>,
    },
    Unique {
        selected: C,
        receipts: Vec<TierReceipt>,
    },
    Ambiguous {
        candidates: Vec<C>,
        receipts: Vec<TierReceipt>,
    },
}

/// Enumerate first, then use the language's within-tier rule. The rule may
/// remove dominated candidates but must retain every incomparable candidate.
/// An Open stronger tier prevents a weaker winner from becoming certain.
pub fn evaluate_tiers<C: Clone>(
    tiers: impl IntoIterator<Item = TierInput<C>>,
    mut retain_undominated: impl FnMut(&mut Vec<C>),
) -> (Vec<TierWitness<C>>, TierDecision<C>) {
    let mut tiers: Vec<_> = tiers.into_iter().collect();
    tiers.sort_by_key(|tier| tier.rank);
    let mut witnesses = Vec::with_capacity(tiers.len());
    let mut receipts = Vec::new();
    let mut possible = Vec::new();
    let mut blocked = false;
    let mut selected = None;
    for tier in tiers {
        let mut candidates = Vec::new();
        let mut closed = true;
        let mut tier_receipts = Vec::new();
        for contributor in tier.contributors {
            candidates.extend(contributor.candidates);
            match contributor.closure {
                ContributorClosure::Closed(receipt) => tier_receipts.push(receipt),
                ContributorClosure::Open => closed = false,
            }
        }
        retain_undominated(&mut candidates);
        receipts.extend(tier_receipts.iter().cloned());
        if !closed {
            if selected.is_none() {
                blocked = true;
                possible.extend(candidates.iter().cloned());
            }
            witnesses.push(TierWitness::Open {
                candidates,
                receipts: tier_receipts,
            });
            continue;
        }
        if candidates.is_empty() {
            witnesses.push(TierWitness::Absent {
                receipts: tier_receipts,
            });
            continue;
        }
        witnesses.push(TierWitness::Proven {
            candidates: candidates.clone(),
            receipts: tier_receipts,
        });
        if selected.is_some() {
            continue;
        }
        if blocked {
            possible.extend(candidates);
            continue;
        }
        selected = Some(candidates);
    }
    let decision = if let Some(mut candidates) = selected {
        if candidates.len() == 1 {
            TierDecision::Unique {
                selected: candidates.pop().expect("one candidate"),
                receipts,
            }
        } else {
            TierDecision::Ambiguous {
                candidates,
                receipts,
            }
        }
    } else if blocked {
        TierDecision::Open { possible, receipts }
    } else {
        TierDecision::Absent { receipts }
    };
    (witnesses, decision)
}

/// A nearer scope wins within a language tier; unrelated scopes remain peers.
pub fn scope_relation(
    left: &BindingScopeCoordinate,
    right: &BindingScopeCoordinate,
) -> BindingScopeRelation {
    left.relative_to(right)
}

#[cfg(test)]
mod lexical_placement_tests {
    use super::super::batch::FactReferenceSiteMetadata;
    use super::*;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionSiteId, ResolutionSiteKind};

    /// Ancestry from the reference outward: a method block, class 0's body,
    /// class 0's type-parameter scope, an enclosing method block of class 1,
    /// class 1's body, the compilation unit.
    fn fixture(
        definitions: &[(&str, &str)],
        heads: &[Option<&str>],
    ) -> (ReferenceLocalPathEvidence, JvmAccessEndpoint) {
        let ancestry = ["block", "body0", "params0", "block1", "body1", "unit"]
            .iter()
            .enumerate()
            .map(|(depth, node)| (BindingNodeId::for_test(node), u32::try_from(depth).unwrap()))
            .collect();
        let metadata = FactReferenceSiteMetadata::new(
            ResolutionSiteId::new(0),
            ResolutionNamespace::Type,
            ResolutionSiteKind::TypeReference,
            0,
            1,
            true,
            None,
            None,
        );
        let evidence = ReferenceLocalPathEvidence::new(
            metadata,
            definitions
                .iter()
                .map(|(definition, _)| SemanticId::for_test(definition))
                .collect(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            true,
            false,
        )
        .with_definition_endpoints(
            definitions
                .iter()
                .map(|(definition, scope)| {
                    (
                        SemanticId::for_test(definition),
                        BindingNodeId::for_test(scope),
                    )
                })
                .collect(),
        )
        .with_ordered_checkpoint_ancestry(ancestry);
        let endpoint = JvmAccessEndpoint {
            semantic: SemanticId::for_test("reference"),
            language: Language::Java,
            package: None,
            enclosing_templates: heads
                .iter()
                .enumerate()
                .map(|(level, _)| SemanticId::for_test(format!("class{level}")))
                .collect(),
            enclosing_template_heads: heads
                .iter()
                .map(|head| head.map(BindingNodeId::for_test))
                .collect(),
            outermost_type: None,
        };
        (evidence, endpoint)
    }

    fn level(definition: &str, scope: &str, heads: &[Option<&str>]) -> Option<LexicalTypeLevel> {
        let (evidence, endpoint) = fixture(&[(definition, scope)], heads);
        place_lexical_type(SemanticId::for_test(definition), &evidence, &endpoint)
            .map(|placement| placement.level)
    }

    #[test]
    fn binding_scopes_place_definitions_around_enclosing_class_bodies() {
        let heads = [Some("body0"), Some("body1")];
        assert_eq!(
            level("local", "block", &heads),
            Some(LexicalTypeLevel::Local)
        );
        assert_eq!(
            level("member", "body0", &heads),
            Some(LexicalTypeLevel::Declared(0))
        );
        // Class 0's type parameters and the blocks around a local class 0
        // come after class 0's inherited members (JLS 8.5).
        assert_eq!(
            level("param", "params0", &heads),
            Some(LexicalTypeLevel::Outside(0))
        );
        assert_eq!(
            level("outer local", "block1", &heads),
            Some(LexicalTypeLevel::Outside(0))
        );
        assert_eq!(
            level("outer", "body1", &heads),
            Some(LexicalTypeLevel::Declared(1))
        );
        assert_eq!(level("top", "unit", &heads), Some(LexicalTypeLevel::Unit));
        // An order that is not proved is never guessed.
        assert_eq!(level("elsewhere", "not-on-path", &heads), None);
        assert_eq!(level("member", "body0", &[Some("body0"), None]), None);
        assert_eq!(
            level("member", "body0", &[Some("body1"), Some("body0")]),
            None
        );
    }
}
