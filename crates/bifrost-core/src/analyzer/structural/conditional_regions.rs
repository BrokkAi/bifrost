//! Query-time activation evidence for conditional compilation, bounded to one file.

use std::ops::Range;

/// A language decides a condition; the shared algorithm does not interpret it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionValue {
    Decided(bool),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activation {
    CertainActive,
    DecidedInactive,
    Uncertain,
}

/// Certainty of a chain's selected prefix. Later conditions cannot affect it.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainActivation {
    pub uncertain: bool,
    selected: Option<usize>,
}

impl ChainActivation {
    pub fn branch(self, index: usize, condition: ConditionValue) -> Activation {
        if condition == ConditionValue::Decided(false) {
            Activation::DecidedInactive
        } else if self.uncertain {
            Activation::Uncertain
        } else if self.selected == Some(index) {
            Activation::CertainActive
        } else {
            Activation::DecidedInactive
        }
    }
}

/// Mirror deterministic first-branch selection while keeping unknown proof
/// separate from selection. An else branch supplies Decided(true).
pub fn chain_activation(conditions: impl IntoIterator<Item = ConditionValue>) -> ChainActivation {
    let mut answer = ChainActivation::default();
    for (index, condition) in conditions.into_iter().enumerate() {
        if answer.selected.is_none() {
            answer.uncertain |= condition == ConditionValue::Unknown;
            if condition != ConditionValue::Decided(false) {
                answer.selected = Some(index);
            }
        }
    }
    answer
}

#[derive(Debug, Clone)]
pub struct ConditionalRegion {
    pub range: Range<usize>,
    pub activation: Activation,
    /// Authored text omitted by the parser, whose absence proves nothing.
    pub omitted: bool,
}

/// Nonoverlapping intervals. Inactive ancestors dominate uncertain descendants;
/// an active nested chain cannot establish that an uncertain ancestor executes.
#[derive(Debug, Clone, Default)]
pub struct ConditionalRegions {
    regions: Vec<ConditionalRegion>,
    omitted_text: Vec<Range<usize>>,
}

impl ConditionalRegions {
    pub fn new(regions: Vec<ConditionalRegion>, source: &str) -> Self {
        let mut events = Vec::with_capacity(regions.len() * 2);
        for region in regions {
            assert!(region.range.start <= region.range.end && region.range.end <= source.len());
            let counts = [
                i32::from(region.activation == Activation::DecidedInactive),
                i32::from(region.activation == Activation::Uncertain),
                i32::from(region.omitted),
            ];
            events.push((region.range.start, counts));
            events.push((region.range.end, counts.map(|count| -count)));
        }
        events.sort_unstable_by_key(|event| event.0);
        let mut result = Self::default();
        let mut counts = [0; 3];
        let mut start = 0;
        for (end, delta) in events {
            if start < end {
                let activation = if counts[0] > 0 {
                    Activation::DecidedInactive
                } else if counts[1] > 0 {
                    Activation::Uncertain
                } else {
                    Activation::CertainActive
                };
                result.regions.push(ConditionalRegion {
                    range: start..end,
                    activation,
                    omitted: counts[2] > 0,
                });
                if activation == Activation::Uncertain && counts[2] > 0 {
                    let text = &source[start..end];
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        let offset = text.len() - text.trim_start().len();
                        result
                            .omitted_text
                            .push(start + offset..start + offset + trimmed.len());
                    }
                }
            }
            for (count, delta) in counts.iter_mut().zip(delta) {
                *count += delta;
            }
            start = end;
        }
        result
    }

    pub fn activation_at(&self, byte: usize) -> Activation {
        let index = self
            .regions
            .partition_point(|region| region.range.end <= byte);
        self.regions
            .get(index)
            .filter(|region| region.range.start <= byte)
            .map_or(Activation::CertainActive, |region| region.activation)
    }

    /// Whether activation of any authored text in this owner is unproven.
    pub fn has_uncertain_text(&self, range: Range<usize>) -> bool {
        let start = self
            .regions
            .partition_point(|region| region.range.end <= range.start);
        self.regions[start..]
            .iter()
            .take_while(|region| region.range.start < range.end)
            .any(|region| region.activation == Activation::Uncertain)
            || self.has_uncertain_omission(range)
    }

    pub fn has_uncertain_omission(&self, range: Range<usize>) -> bool {
        let index = self
            .omitted_text
            .partition_point(|text| text.end <= range.start);
        self.omitted_text
            .get(index)
            .is_some_and(|text| text.start < range.end)
    }
}
