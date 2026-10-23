//! Query-local temporal selection. Languages supply regions and event effects;
//! this module owns coverage, shadowing and residual outer-scope alternatives.

use super::ResolutionCompletion;
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

/// A conjunction of opaque, binary control decisions, in increasing ID order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Region(pub(crate) Vec<(u64, bool)>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Budget,
    Cancelled,
}

pub(crate) trait TemporalBudget {
    fn step(&mut self) -> Result<(), Stop>;
}

pub(crate) struct SessionBudget<'a> {
    pub(crate) session: &'a ResolutionSession,
    pub(crate) cancellation: &'a CancellationToken,
}
impl TemporalBudget for SessionBudget<'_> {
    fn step(&mut self) -> Result<(), Stop> {
        if self.cancellation.is_cancelled() {
            self.session.observe_cancellation();
            Err(Stop::Cancelled)
        } else if self.session.scope_step() {
            Ok(())
        } else if self.cancellation.is_cancelled() {
            Err(Stop::Cancelled)
        } else {
            Err(Stop::Budget)
        }
    }
}

impl Region {
    pub(crate) fn new(mut decisions: Vec<(u64, bool)>) -> Self {
        decisions.sort_unstable_by_key(|entry| entry.0);
        assert!(decisions.windows(2).all(|pair| pair[0].0 != pair[1].0));
        Self(decisions)
    }

    pub(crate) fn intersect(
        &self,
        other: &Self,
        budget: &mut impl TemporalBudget,
    ) -> Result<Option<Self>, Stop> {
        let mut result = self.0.clone();
        for &(decision, value) in &other.0 {
            budget.step()?;
            match result.binary_search_by_key(&decision, |entry| entry.0) {
                Ok(index) if result[index].1 != value => return Ok(None),
                Ok(_) => {}
                Err(index) => result.insert(index, (decision, value)),
            }
        }
        Ok(Some(Self(result)))
    }

    /// Return disjoint pieces of self outside other. Each split is metered.
    pub(crate) fn subtract(
        &self,
        other: &Self,
        budget: &mut impl TemporalBudget,
    ) -> Result<Vec<Self>, Stop> {
        if self.intersect(other, budget)?.is_none() {
            return Ok(vec![self.clone()]);
        }
        let mut inside = self.clone();
        let mut outside = Vec::new();
        for &(decision, value) in &other.0 {
            budget.step()?;
            if let Err(index) = inside.0.binary_search_by_key(&decision, |entry| entry.0) {
                let mut piece = inside.clone();
                piece.0.insert(index, (decision, !value));
                outside.push(piece);
                inside.0.insert(index, (decision, value));
            }
        }
        Ok(outside)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    Write,
    Delete,
    NoWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventOrdering {
    Positioned,
    Unordered,
}

#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub(crate) occurrence: u32,
    pub(crate) point: (usize, u32, u32),
    pub(crate) completion: ResolutionCompletion,
    pub(crate) ordering: EventOrdering,
    pub(crate) region: Region,
    pub(crate) effect: Effect,
    /// False means the occurrence may not execute even within its region.
    pub(crate) certain: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedOccurrence {
    pub(crate) occurrence: u32,
    pub(crate) region: Region,
}

/// All survivors of one reduced lookup share this effective rank. Physical
/// lexical scope and event position remain separate occurrence authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TemporalRank(pub(crate) u32);

#[derive(Debug)]
pub(crate) struct TemporalSelection {
    pub(crate) selected: Vec<SelectedOccurrence>,
    pub(crate) residual: Vec<Region>,
    pub(crate) unbound: Vec<Region>,
    pub(crate) open: bool,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) stopped: Option<Stop>,
}
impl TemporalSelection {
    pub(crate) fn new(observation: Region) -> Self {
        Self {
            selected: Vec::new(),
            residual: vec![observation],
            unbound: Vec::new(),
            open: false,
            completion: ResolutionCompletion::Complete,
            stopped: None,
        }
    }

    /// Positions are semantic commit coordinates, not inventory ordinals.
    /// Shared code orders them. NoWrite supports annotation-only/uncommitted writes.
    pub(crate) fn scope(
        &mut self,
        events: impl IntoIterator<Item = Event>,
        whole_scope: bool,
        budget: &mut impl TemporalBudget,
    ) {
        if self.stopped.is_some() {
            return;
        }
        if let Err(stop) = self.reduce(events, whole_scope, budget) {
            // No partial selection may become an authoritative answer.
            self.selected.clear();
            self.unbound.clear();
            self.stopped = Some(stop);
            self.open = true;
        }
    }

    fn reduce(
        &mut self,
        events: impl IntoIterator<Item = Event>,
        whole_scope: bool,
        budget: &mut impl TemporalBudget,
    ) -> Result<(), Stop> {
        budget.step()?;
        let mut ordered = Vec::new();
        for event in events {
            budget.step()?;
            self.completion = self.completion.combine(&event.completion);
            ordered.push(event);
        }
        let incoming = self.residual.clone();
        ordered.sort_unstable_by_key(|event| std::cmp::Reverse(event.point));
        for event in ordered {
            budget.step()?;
            if event.effect == Effect::NoWrite {
                continue;
            }
            // An event from another invocation cannot be ordered by where its
            // body happens to appear in source. Keep its alternatives even if
            // a positioned write has consumed the same cell's residual region.
            if event.ordering == EventOrdering::Unordered {
                for region in &incoming {
                    budget.step()?;
                    if let Some(overlap) = region.intersect(&event.region, budget)? {
                        if event.effect == Effect::Write {
                            self.selected.push(SelectedOccurrence {
                                occurrence: event.occurrence,
                                region: overlap,
                            });
                        } else {
                            self.unbound.push(overlap);
                        }
                        self.open = true;
                    }
                }
                continue;
            }
            let mut remainder = Vec::new();
            for region in &self.residual {
                budget.step()?;
                if let Some(overlap) = region.intersect(&event.region, budget)? {
                    if event.effect == Effect::Write {
                        self.selected.push(SelectedOccurrence {
                            occurrence: event.occurrence,
                            region: overlap.clone(),
                        });
                    } else {
                        self.unbound.push(overlap);
                    }
                    if !event.certain {
                        self.open = true;
                    }
                }
                if event.certain {
                    remainder.extend(region.subtract(&event.region, budget)?);
                } else {
                    remainder.push(region.clone());
                }
            }
            self.residual = remainder;
        }
        if whole_scope {
            self.unbound.append(&mut self.residual);
        } else {
            self.residual.append(&mut self.unbound);
        }
        Ok(())
    }

    pub(crate) fn outer_can_compete(&self) -> bool {
        self.stopped.is_none() && !self.residual.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Budget(usize);
    impl TemporalBudget for Budget {
        fn step(&mut self) -> Result<(), Stop> {
            if self.0 == 0 {
                Err(Stop::Budget)
            } else {
                self.0 -= 1;
                Ok(())
            }
        }
    }
    fn event(id: u32, arm: Option<bool>, effect: Effect) -> Event {
        Event {
            occurrence: id,
            point: (id as usize, 0, id),
            completion: ResolutionCompletion::Complete,
            ordering: EventOrdering::Positioned,
            region: Region::new(arm.into_iter().map(|b| (1, b)).collect()),
            effect,
            certain: true,
        }
    }
    #[test]
    fn exhaustive_and_partial_sibling_regions() {
        let mut exhaustive = TemporalSelection::new(Region::default());
        exhaustive.scope(
            [
                event(2, Some(false), Effect::Write),
                event(1, Some(true), Effect::Write),
                event(0, None, Effect::Write),
            ],
            false,
            &mut Budget(100),
        );
        assert_eq!(
            exhaustive
                .selected
                .iter()
                .map(|s| s.occurrence)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        let mut partial = TemporalSelection::new(Region::default());
        partial.scope(
            [
                event(1, Some(true), Effect::Write),
                event(0, None, Effect::Write),
            ],
            false,
            &mut Budget(100),
        );
        assert_eq!(partial.selected[1].region, Region::new(vec![(1, false)]));
    }
    #[test]
    fn delete_cleanup_unbound_and_class_residual() {
        let mut before_first_local = TemporalSelection::new(Region::default());
        before_first_local.scope([event(1, None, Effect::NoWrite)], true, &mut Budget(100));
        assert!(before_first_local.selected.is_empty());
        assert!(!before_first_local.outer_can_compete());
        assert_eq!(before_first_local.unbound, [Region::default()]);
        for whole in [false, true] {
            let mut selection = TemporalSelection::new(Region::default());
            selection.scope(
                [
                    event(2, None, Effect::Delete),
                    event(1, None, Effect::Write),
                ],
                whole,
                &mut Budget(100),
            );
            assert!(selection.selected.is_empty());
            assert_eq!(selection.outer_can_compete(), !whole);
            assert_eq!(selection.unbound.is_empty(), !whole);
        }
    }
    #[test]
    fn augment_rhs_and_unknown_activation_keep_previous_write() {
        let mut selection = TemporalSelection::new(Region::default());
        let mut possible = event(2, None, Effect::Write);
        possible.certain = false;
        selection.scope(
            [
                event(3, None, Effect::NoWrite),
                possible,
                event(1, None, Effect::Write),
            ],
            true,
            &mut Budget(100),
        );
        assert_eq!(
            selection
                .selected
                .iter()
                .map(|s| s.occurrence)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        assert!(selection.open);
        assert!(!selection.outer_can_compete());
    }
    #[test]
    fn class_partial_binding_keeps_region_qualified_outer_alternative() {
        let mut selection = TemporalSelection::new(Region::default());
        selection.scope(
            [event(2, Some(true), Effect::Write)],
            false,
            &mut Budget(100),
        );
        assert!(selection.outer_can_compete());
        selection.scope([event(1, None, Effect::Write)], false, &mut Budget(100));
        assert_eq!(selection.selected[0].region, Region::new(vec![(1, true)]));
        assert_eq!(selection.selected[1].region, Region::new(vec![(1, false)]));
        assert!(!selection.outer_can_compete());
        let mut unknown_delete = event(3, None, Effect::Delete);
        unknown_delete.certain = false;
        let mut selection = TemporalSelection::new(Region::default());
        selection.scope(
            [unknown_delete, event(2, None, Effect::Write)],
            false,
            &mut Budget(100),
        );
        assert!(selection.open && selection.outer_can_compete());
        assert_eq!(selection.selected[0].occurrence, 2);
    }

    #[test]
    fn another_invocation_is_not_shadowed_by_later_source_position() {
        let mut external = event(0, None, Effect::Write);
        external.ordering = EventOrdering::Unordered;
        external.certain = false;
        let mut selection = TemporalSelection::new(Region::default());
        selection.scope(
            [
                external,
                event(1, None, Effect::Write),
                event(2, None, Effect::Write),
            ],
            false,
            &mut Budget(100),
        );
        assert_eq!(
            selection
                .selected
                .iter()
                .map(|row| row.occurrence)
                .collect::<Vec<_>>(),
            [2, 0]
        );
        assert!(selection.open);
    }

    #[test]
    fn budget_and_cancellation_never_expose_partial_selection() {
        let mut selection = TemporalSelection::new(Region::default());
        selection.scope(
            [event(2, None, Effect::Write), event(1, None, Effect::Write)],
            true,
            &mut Budget(3),
        );
        assert_eq!(selection.stopped, Some(Stop::Budget));
        assert!(selection.selected.is_empty());
        struct Cancel;
        impl TemporalBudget for Cancel {
            fn step(&mut self) -> Result<(), Stop> {
                Err(Stop::Cancelled)
            }
        }
        selection = TemporalSelection::new(Region::default());
        selection.scope([event(1, None, Effect::Write)], false, &mut Cancel);
        assert_eq!(selection.stopped, Some(Stop::Cancelled));
        assert!(selection.selected.is_empty());
    }
}
