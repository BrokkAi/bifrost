//! Language-neutral receiver/member site projection from canonical structural facts.
//!
//! Language adapters own syntax normalization through [`FileFacts`]. This module only
//! projects their normalized `Call`/`FieldAccess` facts and role edges into exact source
//! ranges. It deliberately does not parse source or classify receivers as static or instance
//! values; those decisions belong to the language's existing type and definition resolvers.

use crate::analyzer::Range;
use crate::analyzer::structural::{FileFacts, NormalizedKind, Role, Span};
use crate::cancellation::CancellationToken;
use std::sync::Arc;

/// The normalized structural shape that supplied a receiver/member site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverSiteKind {
    Call,
    FieldAccess,
}

/// How an input range relates to the receiver site being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverSiteInputMode {
    /// The input is the receiver expression itself.
    Expression,
    /// The input identifies the containing call/member site or its member token.
    ContainingSite,
}

/// Exact source ranges projected from one normalized receiver/member fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverSite {
    pub(crate) kind: ReceiverSiteKind,
    pub(crate) site_range: Range,
    pub(crate) receiver_range: Range,
    pub(crate) member_range: Option<Range>,
}

/// Maximum canonical fact nodes and role edges inspected while building one receiver-site index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceiverSiteIndexLimit {
    pub(crate) max_work_items: usize,
}

/// Maximum indexed receiver sites inspected while selecting one query input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceiverSiteSelectionLimit {
    pub(crate) max_inspected_sites: usize,
}

/// Outcome of a bounded receiver-site index build.
#[derive(Debug)]
pub(crate) enum ReceiverSiteIndexBuild {
    Complete {
        index: ReceiverSiteIndex,
        inspected_work: usize,
    },
    Exceeded {
        inspected_work: usize,
    },
    Cancelled {
        inspected_work: usize,
    },
}

impl ReceiverSiteIndexBuild {
    #[cfg(test)]
    pub(crate) fn inspected_work(&self) -> usize {
        match self {
            Self::Complete { inspected_work, .. }
            | Self::Exceeded { inspected_work }
            | Self::Cancelled { inspected_work } => *inspected_work,
        }
    }
}

/// Outcome of selecting a receiver site without hiding cached-index work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverSiteSelection {
    Complete {
        site: Option<ReceiverSite>,
        inspected_sites: usize,
    },
    Exceeded {
        inspected_sites: usize,
    },
    Cancelled {
        inspected_sites: usize,
    },
}

impl ReceiverSiteSelection {
    #[cfg(test)]
    pub(crate) fn inspected_sites(&self) -> usize {
        match self {
            Self::Complete {
                inspected_sites, ..
            }
            | Self::Exceeded { inspected_sites }
            | Self::Cancelled { inspected_sites } => *inspected_sites,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct IndexedReceiverSite {
    site: ReceiverSite,
    source_order: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReceiverSiteRank {
    match_rank: u8,
    target_width: usize,
    kind_rank: u8,
    site_width: usize,
    site_start: usize,
    source_order: u32,
}

/// Immutable, source-generation-coherent receiver sites for one [`FileFacts`] snapshot.
#[derive(Debug)]
pub(crate) struct ReceiverSiteIndex {
    facts: Arc<FileFacts>,
    sites: Box<[IndexedReceiverSite]>,
}

impl ReceiverSiteIndex {
    pub(crate) fn source(&self) -> &str {
        self.facts.source()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sites.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Select the structurally closest receiver site for `input` within `limit`.
    ///
    /// Exact matches beat containment. Calls beat their nested field-access facts so
    /// `service.Run()` is treated as an invocation rather than a property read. Remaining
    /// ties are resolved by the smallest containing site and canonical fact source order.
    pub(crate) fn select_bounded(
        &self,
        input: Range,
        mode: ReceiverSiteInputMode,
        limit: ReceiverSiteSelectionLimit,
        cancellation: Option<&CancellationToken>,
    ) -> ReceiverSiteSelection {
        if input.start_byte >= input.end_byte {
            return ReceiverSiteSelection::Complete {
                site: None,
                inspected_sites: 0,
            };
        }

        let mut inspected_sites = 0;
        let mut best: Option<(ReceiverSiteRank, ReceiverSite)> = None;
        for indexed in &self.sites {
            if is_cancelled(cancellation) {
                return ReceiverSiteSelection::Cancelled { inspected_sites };
            }
            if inspected_sites >= limit.max_inspected_sites {
                return ReceiverSiteSelection::Exceeded { inspected_sites };
            }
            inspected_sites += 1;

            let (match_rank, target_width) = match mode {
                ReceiverSiteInputMode::Expression => {
                    if same_span(indexed.site.receiver_range, input) {
                        (0, range_width(indexed.site.receiver_range))
                    } else if covers(indexed.site.receiver_range, input) {
                        (1, range_width(indexed.site.receiver_range))
                    } else {
                        continue;
                    }
                }
                ReceiverSiteInputMode::ContainingSite => {
                    if same_span(indexed.site.site_range, input) {
                        (0, range_width(indexed.site.site_range))
                    } else if let Some(member) = indexed
                        .site
                        .member_range
                        .filter(|member| same_span(*member, input))
                    {
                        (1, range_width(member))
                    } else if let Some(member) = indexed
                        .site
                        .member_range
                        .filter(|member| covers(*member, input))
                    {
                        (2, range_width(member))
                    } else if covers(indexed.site.site_range, input) {
                        (3, range_width(indexed.site.site_range))
                    } else {
                        continue;
                    }
                }
            };
            let kind_rank = match indexed.site.kind {
                ReceiverSiteKind::Call => 0,
                ReceiverSiteKind::FieldAccess => 1,
            };
            let site_width = range_width(indexed.site.site_range);
            let candidate = (
                ReceiverSiteRank {
                    match_rank,
                    target_width,
                    kind_rank,
                    site_width,
                    site_start: indexed.site.site_range.start_byte,
                    source_order: indexed.source_order,
                },
                indexed.site,
            );
            if best.is_none_or(|current| candidate.0 < current.0) {
                best = Some(candidate);
            }
        }

        if is_cancelled(cancellation) {
            ReceiverSiteSelection::Cancelled { inspected_sites }
        } else {
            ReceiverSiteSelection::Complete {
                site: best.map(|(_, site)| site),
                inspected_sites,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn select(&self, input: Range, mode: ReceiverSiteInputMode) -> Option<ReceiverSite> {
        match self.select_bounded(
            input,
            mode,
            ReceiverSiteSelectionLimit {
                max_inspected_sites: usize::MAX,
            },
            None,
        ) {
            ReceiverSiteSelection::Complete { site, .. } => site,
            ReceiverSiteSelection::Exceeded { .. } | ReceiverSiteSelection::Cancelled { .. } => {
                unreachable!("unbounded uncancelled test selection")
            }
        }
    }
}

/// Build a bounded receiver-site index from one canonical structural snapshot.
pub(crate) fn build_receiver_site_index(
    facts: Arc<FileFacts>,
    limit: ReceiverSiteIndexLimit,
    cancellation: Option<&CancellationToken>,
) -> ReceiverSiteIndexBuild {
    let mut inspected_work = 0;
    let mut sites = Vec::new();

    if is_cancelled(cancellation) {
        return ReceiverSiteIndexBuild::Cancelled { inspected_work };
    }

    for (source_order, node) in facts.nodes().iter().enumerate() {
        if is_cancelled(cancellation) {
            return ReceiverSiteIndexBuild::Cancelled { inspected_work };
        }
        if inspected_work >= limit.max_work_items {
            return ReceiverSiteIndexBuild::Exceeded { inspected_work };
        }
        inspected_work += 1;

        let (kind, receiver_role, member_role) = match node.kind {
            NormalizedKind::Call => (ReceiverSiteKind::Call, Role::Receiver, Role::Callee),
            NormalizedKind::FieldAccess => {
                (ReceiverSiteKind::FieldAccess, Role::Object, Role::Field)
            }
            _ => continue,
        };
        let fact_id = source_order as u32;
        let mut receiver = None;
        let mut member_span = node.name;
        for target in facts.roles(fact_id) {
            if is_cancelled(cancellation) {
                return ReceiverSiteIndexBuild::Cancelled { inspected_work };
            }
            if inspected_work >= limit.max_work_items {
                return ReceiverSiteIndexBuild::Exceeded { inspected_work };
            }
            inspected_work += 1;

            if receiver.is_none() && target.role == receiver_role {
                receiver = Some(target);
            }
            if member_span.is_none() && target.role == member_role {
                member_span = match kind {
                    ReceiverSiteKind::Call => target.name,
                    ReceiverSiteKind::FieldAccess => Some(target.name.unwrap_or(target.span)),
                };
            }
            if receiver.is_some() && member_span.is_some() {
                break;
            }
        }
        let Some(receiver) = receiver else {
            continue;
        };
        sites.push(IndexedReceiverSite {
            site: ReceiverSite {
                kind,
                site_range: range_for_span(&facts, node.span()),
                receiver_range: range_for_span(&facts, receiver.span),
                member_range: member_span.map(|span| range_for_span(&facts, span)),
            },
            source_order: fact_id,
        });
    }

    if is_cancelled(cancellation) {
        return ReceiverSiteIndexBuild::Cancelled { inspected_work };
    }

    ReceiverSiteIndexBuild::Complete {
        index: ReceiverSiteIndex {
            facts,
            sites: sites.into_boxed_slice(),
        },
        inspected_work,
    }
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn same_span(left: Range, right: Range) -> bool {
    left.start_byte == right.start_byte && left.end_byte == right.end_byte
}

fn covers(container: Range, input: Range) -> bool {
    container.start_byte <= input.start_byte && input.end_byte <= container.end_byte
}

fn range_width(range: Range) -> usize {
    range.end_byte.saturating_sub(range.start_byte)
}

fn range_for_span(facts: &FileFacts, span: Span) -> Range {
    Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: facts.line_of_byte(span.start_byte),
        end_line: facts.line_of_byte(span.end_byte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::csharp::structural::CSHARP_STRUCTURAL_SPEC;
    use crate::analyzer::structural::extract::extract_file_facts;

    fn facts(source: &str) -> Arc<FileFacts> {
        Arc::new(
            extract_file_facts(
                &CSHARP_STRUCTURAL_SPEC,
                &tree_sitter_c_sharp::LANGUAGE.into(),
                source,
            )
            .expect("C# structural facts"),
        )
    }

    fn complete_index(source: &str) -> ReceiverSiteIndex {
        let facts = facts(source);
        let work_item_count = facts.work_item_count();
        match build_receiver_site_index(
            facts,
            ReceiverSiteIndexLimit {
                max_work_items: work_item_count,
            },
            None,
        ) {
            ReceiverSiteIndexBuild::Complete {
                index,
                inspected_work,
            } => {
                assert!(inspected_work <= work_item_count);
                index
            }
            other => panic!("expected complete receiver-site index, got {other:?}"),
        }
    }

    fn range_of(index: &ReceiverSiteIndex, needle: &str) -> Range {
        let start_byte = index.source().rfind(needle).expect("source marker");
        Range {
            start_byte,
            end_byte: start_byte + needle.len(),
            start_line: 0,
            end_line: 0,
        }
    }

    fn text(index: &ReceiverSiteIndex, range: Range) -> &str {
        &index.source()[range.start_byte..range.end_byte]
    }

    #[test]
    fn direct_call_selects_from_exact_site_member_and_receiver_inputs() {
        let index = complete_index(
            "class Service { public void Run() {} }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n",
        );
        let expected_site = range_of(&index, "service.Run()");

        for (input, mode) in [
            (expected_site, ReceiverSiteInputMode::ContainingSite),
            (
                range_of(&index, "Run"),
                ReceiverSiteInputMode::ContainingSite,
            ),
            (
                range_of(&index, "service"),
                ReceiverSiteInputMode::Expression,
            ),
        ] {
            let site = index.select(input, mode).expect("direct receiver site");
            assert_eq!(site.kind, ReceiverSiteKind::Call);
            assert_eq!(text(&index, site.site_range), "service.Run()");
            assert_eq!(text(&index, site.receiver_range), "service");
            assert_eq!(
                site.member_range.map(|range| text(&index, range)),
                Some("Run")
            );
        }
    }

    #[test]
    fn nested_calls_prefer_exact_receiver_then_call_over_field_access() {
        let index = complete_index(
            "class Service { public Service Factory() => this; public void Run() {} }\n\
             class Caller { void Go(Service service) { service.Factory().Run(); } }\n",
        );

        let outer = index
            .select(
                range_of(&index, "service.Factory()"),
                ReceiverSiteInputMode::Expression,
            )
            .expect("outer receiver site");
        assert_eq!(outer.kind, ReceiverSiteKind::Call);
        assert_eq!(text(&index, outer.site_range), "service.Factory().Run()");
        assert_eq!(text(&index, outer.receiver_range), "service.Factory()");
        assert_eq!(
            outer.member_range.map(|range| text(&index, range)),
            Some("Run")
        );

        let inner = index
            .select(
                range_of(&index, "service"),
                ReceiverSiteInputMode::Expression,
            )
            .expect("inner exact receiver site");
        assert_eq!(inner.kind, ReceiverSiteKind::Call);
        assert_eq!(text(&index, inner.site_range), "service.Factory()");
        assert_eq!(
            inner.member_range.map(|range| text(&index, range)),
            Some("Factory")
        );

        let member = index
            .select(
                range_of(&index, "Run"),
                ReceiverSiteInputMode::ContainingSite,
            )
            .expect("outer member site");
        assert_eq!(member.kind, ReceiverSiteKind::Call);
        assert_eq!(text(&index, member.site_range), "service.Factory().Run()");
    }

    #[test]
    fn csharp_conditional_call_and_property_keep_exact_ranges() {
        let index = complete_index(
            "class Service { public void Run() {} public string Name => \"x\"; }\n\
             class Caller { void Go(Service service) { service?.Run(); var name = service?.Name; } }\n",
        );

        let call = index
            .select(
                range_of(&index, "service?.Run()"),
                ReceiverSiteInputMode::ContainingSite,
            )
            .expect("conditional call");
        assert_eq!(call.kind, ReceiverSiteKind::Call);
        assert_eq!(text(&index, call.receiver_range), "service");
        assert_eq!(
            call.member_range.map(|range| text(&index, range)),
            Some("Run")
        );

        let property = index
            .select(
                range_of(&index, "service?.Name"),
                ReceiverSiteInputMode::ContainingSite,
            )
            .expect("conditional property");
        assert_eq!(property.kind, ReceiverSiteKind::FieldAccess);
        assert_eq!(text(&index, property.receiver_range), "service");
        assert_eq!(
            property.member_range.map(|range| text(&index, range)),
            Some("Name")
        );
    }

    #[test]
    fn tiny_build_limit_reports_only_inspected_work() {
        let facts = facts(
            "class Service { public void Run() {} }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n",
        );
        let outcome =
            build_receiver_site_index(facts, ReceiverSiteIndexLimit { max_work_items: 1 }, None);

        assert!(matches!(
            &outcome,
            ReceiverSiteIndexBuild::Exceeded { inspected_work: 1 }
        ));
        assert_eq!(outcome.inspected_work(), 1);
    }

    #[test]
    fn node_only_budget_does_not_hide_role_edge_work() {
        let facts = facts(
            "class Service { public void Run() {} }\n\
             class Caller { void Go(Service service) { service.Run(); } }\n",
        );
        let node_count = facts.nodes().len();
        let outcome = build_receiver_site_index(
            facts,
            ReceiverSiteIndexLimit {
                max_work_items: node_count,
            },
            None,
        );

        assert!(matches!(
            outcome,
            ReceiverSiteIndexBuild::Exceeded {
                inspected_work
            } if inspected_work == node_count
        ));
    }

    #[test]
    fn cached_selection_reports_its_own_bounded_work() {
        let index = complete_index(
            "class Service { public void Run() {} }\n\
             class Caller { void Go(Service first, Service second) { first.Run(); second.Run(); } }\n",
        );
        let outcome = index.select_bounded(
            range_of(&index, "second"),
            ReceiverSiteInputMode::Expression,
            ReceiverSiteSelectionLimit {
                max_inspected_sites: 1,
            },
            None,
        );

        assert_eq!(
            outcome,
            ReceiverSiteSelection::Exceeded { inspected_sites: 1 }
        );
        assert_eq!(outcome.inspected_sites(), 1);
    }

    #[test]
    fn cached_selection_polls_cancellation_between_sites() {
        let index = complete_index(
            "class Service { public void Run() {} }\n\
             class Caller { void Go(Service first, Service second) { first.Run(); second.Run(); } }\n",
        );
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        let outcome = index.select_bounded(
            range_of(&index, "second"),
            ReceiverSiteInputMode::Expression,
            ReceiverSiteSelectionLimit {
                max_inspected_sites: usize::MAX,
            },
            Some(&cancellation),
        );

        let ReceiverSiteSelection::Cancelled { inspected_sites } = outcome else {
            panic!("expected mid-selection cancellation, got {outcome:?}");
        };
        assert!(inspected_sites > 0);
        assert!(inspected_sites < index.len());
    }

    #[test]
    fn pre_cancelled_build_stops_before_inspecting_work() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let outcome = build_receiver_site_index(
            facts("class Service { public void Run() {} }\n"),
            ReceiverSiteIndexLimit {
                max_work_items: usize::MAX,
            },
            Some(&cancellation),
        );

        assert!(matches!(
            outcome,
            ReceiverSiteIndexBuild::Cancelled { inspected_work: 0 }
        ));
    }

    #[test]
    fn mid_build_cancellation_retains_bounded_work_count() {
        let facts = facts(
            "class Service { public void Run() {} }\n\
             class Caller { void Go(Service service) { service.Run(); service.Run(); } }\n",
        );
        let work_item_count = facts.work_item_count();
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        let outcome = build_receiver_site_index(
            facts,
            ReceiverSiteIndexLimit {
                max_work_items: usize::MAX,
            },
            Some(&cancellation),
        );

        let ReceiverSiteIndexBuild::Cancelled { inspected_work } = outcome else {
            panic!("expected mid-build cancellation, got {outcome:?}");
        };
        assert!(inspected_work > 0);
        assert!(inspected_work < work_item_count);
    }

    #[test]
    fn calls_without_explicit_receivers_do_not_create_sites() {
        let index = complete_index(
            "class Service { public Service() {} public static void Run() {} }\n\
             class Caller { void Go() { Run(); var service = new Service(); } }\n",
        );

        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert!(
            index
                .select(
                    range_of(&index, "Run()"),
                    ReceiverSiteInputMode::ContainingSite
                )
                .is_none()
        );
        assert!(
            index
                .select(
                    range_of(&index, "new Service()"),
                    ReceiverSiteInputMode::ContainingSite
                )
                .is_none()
        );
    }
}
