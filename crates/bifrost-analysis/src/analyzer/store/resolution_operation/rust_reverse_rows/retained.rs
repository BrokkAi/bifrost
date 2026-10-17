//! Reverse-specific retained evidence and stable source anchors.

use super::*;
use crate::analyzer::resolution::worker_transport::WorkerAnswer;
use crate::analyzer::resolution::{ResolutionIdentityTranslation, SpliceMount};

fn accumulator(
    value: ResolutionCompletionAccumulator,
    translation: &impl ResolutionIdentityTranslation,
) -> ResolutionCompletionAccumulator {
    let mut answer = ResolutionCompletionAccumulator::default();
    answer.include(&value.finish().splice(translation));
    answer
}

impl RustReverseRetained {
    fn translated(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        let Self {
            references,
            witnesses,
            bindings,
            accounted_references,
            qualified_references,
            inventory,
            confirmed_enumeration,
            evaluated_type_terminals,
            type_terminal_rejections,
            proven_prefixes,
            proven_local_type_prefixes,
            local_prefix_reasons,
            time_budget_exceeded,
            evaluation_count,
        } = self;
        Self {
            references: references
                .iter()
                .map(|&id| translation.semantic(id))
                .collect(),
            witnesses: witnesses
                .iter()
                .map(|value| value.splice(translation))
                .collect(),
            bindings: bindings
                .iter()
                .map(|value| value.splice(translation))
                .collect(),
            accounted_references: accounted_references
                .iter()
                .map(|&id| translation.semantic(id))
                .collect(),
            qualified_references: qualified_references
                .iter()
                .map(|&id| translation.semantic(id))
                .collect(),
            inventory: accumulator(inventory, translation),
            confirmed_enumeration: confirmed_enumeration
                .into_iter()
                .map(|(file, value)| (file, accumulator(value, translation)))
                .collect(),
            evaluated_type_terminals: evaluated_type_terminals
                .iter()
                .map(|&id| translation.semantic(id))
                .collect(),
            type_terminal_rejections: type_terminal_rejections
                .into_iter()
                .map(|(id, value)| (translation.semantic(id), value.splice(translation)))
                .collect(),
            proven_prefixes: proven_prefixes
                .iter()
                .map(|&id| translation.semantic(id))
                .collect(),
            proven_local_type_prefixes: proven_local_type_prefixes
                .iter()
                .map(|&id| translation.semantic(id))
                .collect(),
            local_prefix_reasons: local_prefix_reasons
                .into_iter()
                .map(|(id, reasons)| {
                    let completion = ResolutionCompletion::incomplete(reasons).splice(translation);
                    let ResolutionCompletion::Incomplete(reasons) = completion else {
                        unreachable!("an incomplete local prefix stays incomplete")
                    };
                    (translation.semantic(id), reasons.iter().copied().collect())
                })
                .collect(),
            time_budget_exceeded,
            evaluation_count,
        }
    }

    pub(super) fn append(&mut self, other: Self) {
        let Self {
            references,
            witnesses,
            bindings,
            accounted_references,
            qualified_references,
            inventory,
            confirmed_enumeration,
            evaluated_type_terminals,
            type_terminal_rejections,
            proven_prefixes,
            proven_local_type_prefixes,
            local_prefix_reasons,
            time_budget_exceeded,
            evaluation_count,
        } = other;
        self.references.extend(references);
        self.witnesses.extend(witnesses);
        self.bindings.extend(bindings);
        self.accounted_references.extend(accounted_references);
        self.qualified_references.extend(qualified_references);
        self.inventory.include(&inventory.finish());
        for (file, completion) in confirmed_enumeration {
            self.confirmed_enumeration
                .entry(file)
                .or_default()
                .include(&completion.finish());
        }
        self.evaluated_type_terminals
            .extend(evaluated_type_terminals);
        self.type_terminal_rejections
            .extend(type_terminal_rejections);
        self.proven_prefixes.extend(proven_prefixes);
        self.proven_local_type_prefixes
            .extend(proven_local_type_prefixes);
        for (prefix, reasons) in local_prefix_reasons {
            self.local_prefix_reasons
                .entry(prefix)
                .or_default()
                .extend(reasons);
        }
        self.time_budget_exceeded |= time_budget_exceeded;
        self.evaluation_count += evaluation_count;
    }
}

/// Only reverse vocabulary lives here; worker authority and alias transfer
/// belong to the shared transport boundary.
pub(super) struct RetainedPartition {
    pub(super) retained: RustReverseRetained,
    pub(super) definition: SemanticId,
    pub(super) sites: Vec<(usize, SemanticId)>,
    pub(super) projected_units: Vec<CodeUnit>,
    pub(super) unattempted_blobs: Vec<std::path::PathBuf>,
}

impl WorkerAnswer for RetainedPartition {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self {
            retained: self.retained.translated(translation),
            definition: translation.semantic(self.definition),
            sites: self
                .sites
                .into_iter()
                .map(|(index, reference)| (index, translation.semantic(reference)))
                .collect(),
            projected_units: self.projected_units,
            unattempted_blobs: self.unattempted_blobs,
        }
    }
}

impl RetainedPartition {
    pub(super) fn merge(self) -> RustReverseRetained {
        assert!(self.unattempted_blobs.is_empty() || self.retained.time_budget_exceeded);
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "rust reverse unattempted blobs: {:?}",
                self.unattempted_blobs
            )
        });
        // CodeUnits are stable publication vocabulary. No supplemental catalog
        // or worker reader remains after the shared boundary validated it.
        self.retained
    }
}
