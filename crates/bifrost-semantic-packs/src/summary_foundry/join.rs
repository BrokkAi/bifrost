//! The three-way join over translated corpora.
//!
//! Every populated slot states something about a target, or states nothing.
//! The join classifies each target key exactly once:
//!
//! * agreement: every populated slot has a claim and the claims match;
//! * dispute: every populated slot has a claim and at least one field differs;
//! * gap: at least one populated slot has no claim at all.
//!
//! The derived slot holds Bifrost's own generation-time derivation. A run
//! without pinned sources leaves it empty, and the report states that once in
//! `slots` rather than reporting every target as missing from it.
//!
//! Slots are compared at the argument-level projection, because that is the
//! only granularity every slot can state: Models-as-Data rows and the authored
//! IR are both argument-level. A derived entry may know more, so an agreement
//! records whether it holds only at the projection, and every view carries the
//! finer-grained flows and the typed boundaries beside the compared form.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::ir::{FoundryClaim, FoundryCorpus, FoundryEntry, FoundryJoinKey};

/// Whether one slot of the join carries content in this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundrySlotState {
    pub corpus: FoundryCorpus,
    pub populated: bool,
}

/// One slot's merged claim about one target key.
///
/// A corpus can hold more than one entry per key when it pins two overloads
/// with the same arity, so the view is their union: the claim is `no_flow`
/// only when every entry says so, and the shape is the weakest one that fits
/// every entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryClaimView {
    pub claim: FoundryClaim,
    /// The argument-level projection: the form every slot can be compared in.
    pub transfers: Vec<String>,
    pub has_receiver: bool,
    pub parameter_count: u32,
    pub entry_ids: Vec<String>,
    /// Flows this slot derived at a granularity the projection cannot carry.
    /// Empty for a translated corpus, which states argument-level rows.
    pub qualified_flows: Vec<String>,
    /// Typed reasons a derivation stopped short. Empty for a corpus: a
    /// translated row is a claim, not a traversal.
    pub boundaries: Vec<String>,
}

/// One field on which the populated slots disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryFieldDiff {
    pub field: String,
    /// Corpus name to that corpus's rendered value.
    pub values: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryAgreement {
    pub key: FoundryJoinKey,
    pub claim: FoundryClaim,
    pub transfers: Vec<String>,
    /// The slots match on the argument-level projection while at least one of
    /// them states more than the projection carries. The agreement is real at
    /// the compared granularity and silent about the rest.
    pub at_projection_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryDispute {
    pub key: FoundryJoinKey,
    pub fields: Vec<FoundryFieldDiff>,
    pub views: BTreeMap<String, FoundryClaimView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryGap {
    pub key: FoundryJoinKey,
    pub present_in: Vec<FoundryCorpus>,
    pub missing_from: Vec<FoundryCorpus>,
    pub views: BTreeMap<String, FoundryClaimView>,
    /// Keys for the same class and member at another arity, in a slot that has
    /// no claim for this key. A different overload is not the same claim, but
    /// it is what a reviewer needs to see next.
    pub related_keys: Vec<FoundryJoinKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryJoin {
    pub slots: Vec<FoundrySlotState>,
    pub agreement_count: u32,
    /// Agreements that hold only after projecting a finer-grained slot onto
    /// argument level.
    pub agreements_at_projection_only: u32,
    pub dispute_count: u32,
    pub gap_count: u32,
    pub gaps_by_missing_slot: BTreeMap<String, u32>,
    pub agreements: Vec<FoundryAgreement>,
    pub disputes: Vec<FoundryDispute>,
    pub gaps: Vec<FoundryGap>,
}

/// Join the translated slots.
///
/// `slots` lists every corpus the run considers, in report order, with the
/// entries it produced. A slot with no entries is reported as unpopulated and
/// takes no part in classification.
pub fn join_corpora(slots: &[(FoundryCorpus, &[FoundryEntry])]) -> FoundryJoin {
    let populated = slots
        .iter()
        .filter(|(_, entries)| !entries.is_empty())
        .map(|(corpus, _)| *corpus)
        .collect::<Vec<_>>();
    let slot_states = slots
        .iter()
        .map(|(corpus, entries)| FoundrySlotState {
            corpus: *corpus,
            populated: !entries.is_empty(),
        })
        .collect::<Vec<_>>();

    let mut by_key: BTreeMap<FoundryJoinKey, BTreeMap<FoundryCorpus, Vec<&FoundryEntry>>> =
        BTreeMap::new();
    let mut member_index: BTreeMap<(String, String), BTreeSet<(FoundryCorpus, FoundryJoinKey)>> =
        BTreeMap::new();
    for (corpus, entries) in slots {
        for entry in *entries {
            let key = entry.target.join_key();
            member_index
                .entry((key.artifact_path.clone(), key.member.clone()))
                .or_default()
                .insert((*corpus, key.clone()));
            by_key
                .entry(key)
                .or_default()
                .entry(*corpus)
                .or_default()
                .push(entry);
        }
    }

    let mut agreements = Vec::new();
    let mut disputes = Vec::new();
    let mut gaps = Vec::new();
    let mut gaps_by_missing_slot: BTreeMap<String, u32> = BTreeMap::new();
    for (key, by_corpus) in &by_key {
        let views = by_corpus
            .iter()
            .map(|(corpus, entries)| (*corpus, merge_view(entries)))
            .collect::<BTreeMap<_, _>>();
        let missing = populated
            .iter()
            .copied()
            .filter(|corpus| !views.contains_key(corpus))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            let fields = field_diffs(&views);
            if fields.is_empty() {
                let view = views
                    .values()
                    .next()
                    .expect("a classified key has at least one view");
                agreements.push(FoundryAgreement {
                    key: key.clone(),
                    claim: view.claim,
                    transfers: view.transfers.clone(),
                    at_projection_only: views.values().any(|view| !view.qualified_flows.is_empty()),
                });
            } else {
                disputes.push(FoundryDispute {
                    key: key.clone(),
                    fields,
                    views: named_views(&views),
                });
            }
            continue;
        }
        for corpus in &missing {
            *gaps_by_missing_slot
                .entry(corpus.as_str().to_owned())
                .or_default() += 1;
        }
        let related = member_index
            .get(&(key.artifact_path.clone(), key.member.clone()))
            .map(|siblings| {
                siblings
                    .iter()
                    .filter(|(corpus, sibling)| missing.contains(corpus) && sibling != key)
                    .map(|(_, sibling)| sibling.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        gaps.push(FoundryGap {
            key: key.clone(),
            present_in: views.keys().copied().collect(),
            missing_from: missing,
            views: named_views(&views),
            related_keys: related,
        });
    }

    FoundryJoin {
        slots: slot_states,
        agreement_count: agreements.len() as u32,
        agreements_at_projection_only: agreements
            .iter()
            .filter(|agreement| agreement.at_projection_only)
            .count() as u32,
        dispute_count: disputes.len() as u32,
        gap_count: gaps.len() as u32,
        gaps_by_missing_slot,
        agreements,
        disputes,
        gaps,
    }
}

fn named_views(
    views: &BTreeMap<FoundryCorpus, FoundryClaimView>,
) -> BTreeMap<String, FoundryClaimView> {
    views
        .iter()
        .map(|(corpus, view)| (corpus.as_str().to_owned(), view.clone()))
        .collect()
}

fn merge_view(entries: &[&FoundryEntry]) -> FoundryClaimView {
    let mut transfers = BTreeSet::new();
    let mut entry_ids = BTreeSet::new();
    let mut qualified_flows = BTreeSet::new();
    let mut boundaries = BTreeSet::new();
    let mut has_receiver = false;
    let mut parameter_count = 0u32;
    let mut every_entry_states_no_flow = true;
    for entry in entries {
        transfers.extend(entry.rendered_transfers());
        entry_ids.insert(entry.id.clone());
        has_receiver |= entry.boundary.has_receiver;
        parameter_count = parameter_count.max(entry.boundary.parameter_count);
        every_entry_states_no_flow &= entry.claim == FoundryClaim::NoFlow;
        if let Some(derivation) = &entry.derivation {
            qualified_flows.extend(derivation.qualified_flows());
            boundaries.extend(
                derivation
                    .boundaries
                    .iter()
                    .map(|boundary| boundary.kind().to_owned()),
            );
        }
    }
    FoundryClaimView {
        claim: if every_entry_states_no_flow {
            FoundryClaim::NoFlow
        } else {
            FoundryClaim::Flows
        },
        transfers: transfers.into_iter().collect(),
        has_receiver,
        parameter_count,
        entry_ids: entry_ids.into_iter().collect(),
        qualified_flows: qualified_flows.into_iter().collect(),
        boundaries: boundaries.into_iter().collect(),
    }
}

fn field_diffs(views: &BTreeMap<FoundryCorpus, FoundryClaimView>) -> Vec<FoundryFieldDiff> {
    let mut diffs = Vec::new();
    let mut add = |field: &str, values: BTreeMap<String, Vec<String>>| {
        let distinct = values.values().collect::<BTreeSet<_>>();
        if distinct.len() > 1 {
            diffs.push(FoundryFieldDiff {
                field: field.to_owned(),
                values,
            });
        }
    };
    add(
        "claim",
        views
            .iter()
            .map(|(corpus, view)| {
                (
                    corpus.as_str().to_owned(),
                    vec![
                        match view.claim {
                            FoundryClaim::Flows => "flows",
                            FoundryClaim::NoFlow => "no_flow",
                        }
                        .to_owned(),
                    ],
                )
            })
            .collect(),
    );
    add(
        "transfers",
        views
            .iter()
            .map(|(corpus, view)| (corpus.as_str().to_owned(), view.transfers.clone()))
            .collect(),
    );
    add(
        "has_receiver",
        views
            .iter()
            .map(|(corpus, view)| {
                (
                    corpus.as_str().to_owned(),
                    vec![view.has_receiver.to_string()],
                )
            })
            .collect(),
    );
    add(
        "parameter_count",
        views
            .iter()
            .map(|(corpus, view)| {
                (
                    corpus.as_str().to_owned(),
                    vec![view.parameter_count.to_string()],
                )
            })
            .collect(),
    );
    diffs
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput,
        AuthoredSummaryTransfer,
    };

    use super::*;
    use crate::summary_foundry::ir::{
        FoundryAccessPath, FoundryDerivation, FoundryDerivationBoundary, FoundryEntryBuilder,
        FoundryFineGrainedTransfer, FoundrySelector, FoundrySignature, FoundryTarget,
    };

    fn target(member: &str, types: &[&str]) -> FoundryTarget {
        FoundryTarget {
            artifact_path: "java/lang/String.class".to_owned(),
            member: member.to_owned(),
            signature: FoundrySignature::Overload {
                types: types.iter().map(|value| (*value).to_owned()).collect(),
            },
        }
    }

    fn entry(corpus: FoundryCorpus, member: &str, types: &[&str], to_return: bool) -> FoundryEntry {
        let mut builder = FoundryEntryBuilder::default();
        builder.add_transfer(AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Receiver {},
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: if to_return {
                AuthoredSummaryOutput::NormalReturn {}
            } else {
                AuthoredSummaryOutput::Receiver {}
            },
        });
        builder.finish(corpus, target(member, types), Some(types.len() as u32))
    }

    /// One derived entry that states the same argument-level transfer as the
    /// corpus while knowing which element of the parameter carries it.
    fn derived_entry_with_element_granularity(member: &str, types: &[&str]) -> FoundryEntry {
        let mut entry = entry(FoundryCorpus::Derived, member, types, true);
        entry.derivation = Some(FoundryDerivation {
            unproven_transfers: 0,
            closure_procedures: 1,
            boundaries: vec![FoundryDerivationBoundary::UnresolvedCall],
            fine_grained: vec![FoundryFineGrainedTransfer {
                input: FoundryAccessPath {
                    port: "receiver".to_owned(),
                    selectors: vec![FoundrySelector::AnyIndex],
                },
                output: FoundryAccessPath {
                    port: "normal_return".to_owned(),
                    selectors: Vec::new(),
                },
                exit_kind: "normal".to_owned(),
            }],
        });
        entry
    }

    #[test]
    fn an_agreement_says_when_it_holds_only_at_the_argument_level_projection() {
        let codeql = [entry(FoundryCorpus::Codeql, "concat", &["String"], true)];
        let derived = [derived_entry_with_element_granularity(
            "concat",
            &["String"],
        )];

        let join = join_corpora(&[
            (FoundryCorpus::Codeql, &codeql),
            (FoundryCorpus::Derived, &derived),
        ]);

        assert_eq!(join.agreement_count, 1);
        assert_eq!(join.agreements_at_projection_only, 1);
        assert!(join.agreements[0].at_projection_only);
        assert_eq!(join.dispute_count, 0);
    }

    #[test]
    fn a_derived_view_carries_its_boundaries_and_its_finer_flows() {
        // Different arities, so the two keys never meet. The point is that a
        // derived view states its typed extras wherever it is classified, and a
        // translated corpus view never invents them.
        let codeql = [entry(FoundryCorpus::Codeql, "trim", &[], true)];
        let derived = [derived_entry_with_element_granularity("trim", &["String"])];

        let join = join_corpora(&[
            (FoundryCorpus::Codeql, &codeql),
            (FoundryCorpus::Derived, &derived),
        ]);

        let derived_view = join
            .gaps
            .iter()
            .find_map(|gap| gap.views.get("derived"))
            .expect("the derived entry is classified");
        assert_eq!(
            derived_view.qualified_flows,
            vec!["receiver.Element->normal_return@normal".to_owned()]
        );
        assert_eq!(derived_view.boundaries, vec!["unresolved_call".to_owned()]);

        let codeql_view = join
            .gaps
            .iter()
            .find_map(|gap| gap.views.get("codeql"))
            .expect("the corpus entry is classified");
        assert!(codeql_view.qualified_flows.is_empty());
        assert!(codeql_view.boundaries.is_empty());
    }

    #[test]
    fn matching_claims_agree_and_differing_transfers_dispute() {
        let codeql = [
            entry(FoundryCorpus::Codeql, "concat", &["String"], true),
            entry(FoundryCorpus::Codeql, "trim", &[], true),
        ];
        let joern = [
            entry(FoundryCorpus::Joern, "concat", &["java.lang.String"], true),
            entry(FoundryCorpus::Joern, "trim", &[], false),
        ];

        let join = join_corpora(&[
            (FoundryCorpus::Codeql, &codeql),
            (FoundryCorpus::Joern, &joern),
            (FoundryCorpus::Derived, &[]),
        ]);

        assert_eq!(join.agreement_count, 1);
        assert_eq!(join.agreements[0].key.member, "concat");
        assert_eq!(join.dispute_count, 1);
        assert_eq!(join.disputes[0].key.member, "trim");
        let fields = join.disputes[0]
            .fields
            .iter()
            .map(|diff| diff.field.as_str())
            .collect::<Vec<_>>();
        assert_eq!(fields, vec!["transfers"]);
        assert_eq!(join.gap_count, 0);
    }

    #[test]
    fn the_derived_slot_is_reported_unpopulated_rather_than_missing_everywhere() {
        let codeql = [entry(FoundryCorpus::Codeql, "concat", &["String"], true)];
        let joern = [entry(FoundryCorpus::Joern, "concat", &["S"], true)];

        let join = join_corpora(&[
            (FoundryCorpus::Codeql, &codeql),
            (FoundryCorpus::Joern, &joern),
            (FoundryCorpus::Derived, &[]),
        ]);

        assert_eq!(join.gap_count, 0);
        assert_eq!(
            join.slots
                .iter()
                .map(|slot| (slot.corpus, slot.populated))
                .collect::<Vec<_>>(),
            vec![
                (FoundryCorpus::Codeql, true),
                (FoundryCorpus::Joern, true),
                (FoundryCorpus::Derived, false),
            ]
        );
    }

    #[test]
    fn a_one_sided_target_is_a_gap_that_names_its_sibling_overloads() {
        let codeql = [
            entry(FoundryCorpus::Codeql, "concat", &["String"], true),
            entry(FoundryCorpus::Codeql, "concat", &["String", "int"], true),
        ];
        let joern = [entry(FoundryCorpus::Joern, "concat", &["S"], true)];

        let join = join_corpora(&[
            (FoundryCorpus::Codeql, &codeql),
            (FoundryCorpus::Joern, &joern),
        ]);

        assert_eq!(join.gap_count, 1);
        let gap = &join.gaps[0];
        assert_eq!(gap.key.arity, Some(2));
        assert_eq!(gap.present_in, vec![FoundryCorpus::Codeql]);
        assert_eq!(gap.missing_from, vec![FoundryCorpus::Joern]);
        assert_eq!(gap.related_keys.len(), 1);
        assert_eq!(gap.related_keys[0].arity, Some(1));
        assert_eq!(join.gaps_by_missing_slot.get("joern"), Some(&1));
    }

    #[test]
    fn a_no_flow_claim_disputes_a_flow_claim() {
        let mut builder = FoundryEntryBuilder::default();
        builder.declare_no_flow();
        let codeql = [builder.finish(FoundryCorpus::Codeql, target("length", &[]), Some(0))];
        let joern = [entry(FoundryCorpus::Joern, "length", &[], true)];

        let join = join_corpora(&[
            (FoundryCorpus::Codeql, &codeql),
            (FoundryCorpus::Joern, &joern),
        ]);

        assert_eq!(join.dispute_count, 1);
        let fields = join.disputes[0]
            .fields
            .iter()
            .map(|diff| diff.field.as_str())
            .collect::<Vec<_>>();
        assert!(fields.contains(&"claim"), "{fields:?}");
        assert!(fields.contains(&"transfers"), "{fields:?}");
    }
}
