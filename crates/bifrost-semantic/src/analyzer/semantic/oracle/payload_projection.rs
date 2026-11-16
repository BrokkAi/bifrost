//! Query-only selected payload effects. Blob IR never contains these proofs.
//!
//! Paths are ordinary ValueFlowEndpoint locations built from the shared typed
//! PatternProjectionStep vocabulary by the language's selected-model proof.

use crate::analyzer::semantic::{
    ProgramPointId, StableDigest, ValueFlowEndpoint, ValueFlowRelationKind,
};

/// One proven replacement for all raw relations of an exact existing event.
/// An empty relation list is a proved payload-independent result, not a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SelectedPayloadEvent {
    pub point: ProgramPointId,
    pub event: u32,
    pub relations: Box<[SelectedPayloadRelation]>,
    pub constructor_path: Option<crate::analyzer::semantic_model::SummaryEndpointPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SelectedPayloadRelation {
    pub kind: ValueFlowRelationKind,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
}

/// One procedure's selected interpretation. The identity covers enum owner,
/// defining pack digest, variant declaration IDs and payload signatures. A
/// refused event has no replacement: its raw relations remain the only ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SelectedPayloadProjection {
    pub identity: Option<StableDigest>,
    pub replacements: Box<[SelectedPayloadEvent]>,
    pub limitations: Box<[Box<str>]>,
}

impl SelectedPayloadProjection {
    /// Rows retained by this interpretation, separate from proof scan work.
    pub fn retained_census(&self) -> crate::analyzer::semantic::SemanticWork {
        crate::analyzer::semantic::SemanticWork {
            nested_entries: self
                .replacements
                .len()
                .saturating_add(self.limitations.len())
                .saturating_add(
                    self.replacements
                        .iter()
                        .map(|row| row.relations.len())
                        .sum::<usize>(),
                ),
            ..Default::default()
        }
    }

    pub fn affected(&self) -> bool {
        self.identity.is_some()
    }

    fn constructor_event(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> Option<&SelectedPayloadEvent> {
        let row = call.procedure().semantics().call_site(call.id())?;
        let crate::analyzer::semantic::ControlContinuation::Target(point) = row.normal_continuation
        else {
            return None;
        };
        let event = self.replacements.partition_point(|row| row.point < point);
        self.replacements
            .get(event)
            .filter(|row| row.point == point && row.constructor_path.is_some())
    }
    pub fn constructor_path(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> Option<&crate::analyzer::semantic_model::SummaryEndpointPath> {
        self.constructor_event(call)?.constructor_path.as_ref()
    }
    pub fn constructor_output(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> Option<ValueFlowEndpoint> {
        Some(
            self.constructor_event(call)?
                .relations
                .first()?
                .target
                .clone(),
        )
    }

    pub fn projects_call(&self, call: &crate::analyzer::semantic::CallSiteHandle) -> bool {
        let procedure = call.procedure();
        let row = procedure
            .semantics()
            .call_site(call.id())
            .expect("a live call");
        let crate::analyzer::semantic::ControlContinuation::Target(point) = row.normal_continuation
        else {
            return false;
        };
        procedure
            .semantics()
            .point(point)
            .expect("a live continuation")
            .events
            .iter()
            .enumerate()
            .any(|(index, row)| {
                matches!(row.effect, crate::analyzer::semantic::SemanticEffect::CallContinuation {
                call_site, kind: crate::analyzer::semantic::CallContinuationKind::Normal,
            } if call_site == call.id())
                    && self
                        .replacement_at(point, u32::try_from(index).expect("event count fits u32"))
                        .is_some()
            })
    }

    pub fn replacement_at(
        &self,
        point: ProgramPointId,
        event: u32,
    ) -> Option<&SelectedPayloadEvent> {
        self.replacements
            .binary_search_by_key(&(point, event), |row| (row.point, row.event))
            .ok()
            .map(|index| &self.replacements[index])
    }
}
