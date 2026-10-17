//! Bounded, typed evidence about undecided value-type barriers. These notes
//! do not change the proof of the positive taint path or its finding identity.

use crate::finding::{
    PolicySourceLocation, ReportValueError, validate_report_identifier, validate_report_prose,
};
use crate::retained::{RetainedSize, retained_extra};
use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic::{
    SemanticValueKind, ValueTypeBarrierDecision, ValueTypeBarrierReason, ValueTypePredicate,
};
use brokk_bifrost_flow::taint::compose::ValueTypeBarrierCheck;
use serde::{Deserialize, Deserializer, Serialize};

const MAX_NOTES: usize = 64;
const MAX_NOTE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueTypeBarrierNote {
    barrier_id: String,
    predicate: ValueTypePredicate,
    reason: ValueTypeBarrierReason,
    location: PolicySourceLocation,
    mapping_kind: String,
    procedure: String,
    value_id: u32,
    phase: String,
    name: Option<String>,
}

impl ValueTypeBarrierNote {
    pub fn barrier_id(&self) -> &str {
        &self.barrier_id
    }
    pub fn predicate(&self) -> ValueTypePredicate {
        self.predicate
    }
    pub fn reason(&self) -> ValueTypeBarrierReason {
        self.reason
    }
    pub fn location(&self) -> &PolicySourceLocation {
        &self.location
    }
    pub fn procedure(&self) -> &str {
        &self.procedure
    }
    pub fn value_id(&self) -> u32 {
        self.value_id
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub(crate) fn from_check(
        workspace: &WorkspaceAnalyzer,
        check: &ValueTypeBarrierCheck,
    ) -> Result<Self, String> {
        let ValueTypeBarrierDecision::Undecided(reason) = check.decision else {
            return Err("a barrier note requires an undecided proof".into());
        };
        let procedure = check.observation.point().procedure();
        let semantics = procedure.semantics();
        let value = semantics
            .value(check.observation.value())
            .expect("a barrier observation's value is live");
        let mapping = semantics
            .source_mapping(value.source)
            .expect("a live value has a source mapping");
        let span = semantics
            .source_mapping(semantics.source())
            .expect("a procedure has a source mapping")
            .locator
            .anchor()
            .span();
        let note = Self {
            barrier_id: check.id.to_string(),
            predicate: check.predicate,
            reason,
            location: crate::semantic_identity::policy_location(workspace, &mapping.locator)?,
            mapping_kind: mapping.kind.label().into(),
            procedure: format!(
                "{:?} [{}..{}]",
                procedure.id(),
                span.start_byte(),
                span.end_byte()
            ),
            value_id: value.id.get(),
            phase: match check.observation.phase() {
                brokk_bifrost_analysis::analyzer::semantic::ObservationPhase::BeforeEffects => {
                    "before_effects"
                }
                brokk_bifrost_analysis::analyzer::semantic::ObservationPhase::AfterEffects => {
                    "after_effects"
                }
            }
            .into(),
            name: match &value.kind {
                SemanticValueKind::Parameter {
                    name: Some(name), ..
                } if name.len() <= 256 => Some(name.to_string()),
                _ => None,
            },
        };
        note.validate().map_err(|error| error.to_string())?;
        Ok(note)
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        validate_report_identifier(&self.barrier_id)?;
        validate_report_prose(&self.procedure)?;
        if self.procedure.len() > 256
            || !matches!(
                self.mapping_kind.as_str(),
                "exact" | "enclosing" | "synthetic"
            )
            || !matches!(self.phase.as_str(), "before_effects" | "after_effects")
        {
            return Err(ReportValueError::InvalidIdentifier);
        }
        if let Some(name) = &self.name {
            validate_report_prose(name)?;
            if name.len() > 256 {
                return Err(ReportValueError::ProseTooLong { max_bytes: 256 });
            }
        }
        Ok(())
    }

    pub fn message(&self) -> String {
        let region = self.location.region();
        let where_value = format!(
            "{}:{}:{}",
            self.location.path(),
            region.map_or(1, |region| region.start_line()),
            region.map_or(1, |region| region.start_column())
        );
        let value = self.name.as_deref().unwrap_or("value");
        let enclosing = if self.mapping_kind == "exact" {
            ""
        } else {
            " (enclosing location)"
        };
        let reason = match self.reason {
            ValueTypeBarrierReason::UnsupportedLanguage => "unsupported language",
            ValueTypeBarrierReason::UnknownType => "type is unknown",
            ValueTypeBarrierReason::AmbiguousType => "type is ambiguous",
            ValueTypeBarrierReason::IncompleteType => "type evidence is incomplete",
            ValueTypeBarrierReason::IncompleteEnumSurface => "enum variant inventory is incomplete",
            ValueTypeBarrierReason::UnavailableObservation => "value observation is unavailable",
            ValueTypeBarrierReason::BudgetExceeded => "lookup budget",
            ValueTypeBarrierReason::Cancelled => "type proof was cancelled",
        };
        let span = self
            .location
            .byte_span()
            .map(|span| format!(" [{}..{}]", span.start(), span.end()))
            .unwrap_or_default();
        format!(
            "Barrier {} ({:?}) undecided for {value} at {where_value}{span}{enclosing}, {} value {}: {reason}; flow retained.",
            self.barrier_id, self.predicate, self.procedure, self.value_id
        )
    }
}

impl RetainedSize for ValueTypeBarrierNote {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.barrier_id.capacity()
            + retained_extra(&self.location)
            + self.mapping_kind.capacity()
            + self.procedure.capacity()
            + self.phase.capacity()
            + retained_extra(&self.name)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ValueTypeBarrierNotes {
    entries: Vec<ValueTypeBarrierNote>,
    truncated: bool,
    omitted_lower_bound: u64,
}

impl ValueTypeBarrierNotes {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && !self.truncated
    }
    pub fn entries(&self) -> &[ValueTypeBarrierNote] {
        &self.entries
    }
    pub fn omitted_lower_bound(&self) -> u64 {
        self.omitted_lower_bound
    }
    pub(crate) fn note_omitted(&mut self) {
        self.truncated = true;
        self.omitted_lower_bound = 1;
    }
    pub(crate) fn push(&mut self, note: ValueTypeBarrierNote) {
        if self.entries.contains(&note) {
            return;
        }
        let extra = retained_extra(&note)
            + if self.entries.len() == self.entries.capacity() {
                std::mem::size_of::<ValueTypeBarrierNote>()
            } else {
                0
            };
        if self.entries.len() == MAX_NOTES
            || self.retained_size().saturating_add(extra) > MAX_NOTE_BYTES
        {
            self.note_omitted();
            return;
        }
        if self.entries.len() == self.entries.capacity() {
            self.entries.reserve_exact(1);
        }
        self.entries.push(note);
    }
    pub(crate) fn validate(&self) -> Result<(), ReportValueError> {
        if self.entries.len() > MAX_NOTES {
            return Err(ReportValueError::TooManyItems {
                field: "value_type_barrier_notes",
                max_items: MAX_NOTES,
            });
        }
        if self.retained_size() > MAX_NOTE_BYTES {
            return Err(ReportValueError::TooManyBytes {
                field: "value_type_barrier_notes",
                max_bytes: MAX_NOTE_BYTES as u64,
            });
        }
        if self.truncated != (self.omitted_lower_bound > 0) {
            return Err(ReportValueError::InconsistentTruncation {
                field: "value_type_barrier_notes",
            });
        }
        for (index, note) in self.entries.iter().enumerate() {
            note.validate()?;
            if self.entries[..index].contains(note) {
                return Err(ReportValueError::NonCanonicalSet {
                    field: "value_type_barrier_notes",
                });
            }
        }
        Ok(())
    }
}

impl RetainedSize for ValueTypeBarrierNotes {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>() + retained_extra(&self.entries)
    }
}

impl<'de> Deserialize<'de> for ValueTypeBarrierNotes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            entries: Vec<ValueTypeBarrierNote>,
            truncated: bool,
            omitted_lower_bound: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let notes = Self {
            entries: wire.entries,
            truncated: wire.truncated,
            omitted_lower_bound: wire.omitted_lower_bound,
        };
        notes.validate().map_err(serde::de::Error::custom)?;
        Ok(notes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_note_wire_enforces_bounds_and_retains_value_identity() {
        let wire = serde_json::json!({
            "entries": [{
                "barrier_id": "boolean",
                "predicate": "intrinsic_bool",
                "reason": "unknown_type",
                "location": {"path": "src/main.rs", "byte_span": null, "region": null},
                "mapping_kind": "enclosing",
                "procedure": "ProcedureId(1) [0..100]",
                "value_id": 3,
                "phase": "after_effects",
                "name": null
            }],
            "truncated": false,
            "omitted_lower_bound": 0
        });
        let notes: ValueTypeBarrierNotes =
            serde_json::from_value(wire.clone()).expect("valid notes");
        assert_eq!(serde_json::to_value(&notes).expect("serialize notes"), wire);
        let message = notes.entries()[0].message();
        assert!(message.contains("src/main.rs:1:1"), "{message}");
        assert!(message.contains("value 3"), "{message}");
        assert!(message.contains("enclosing location"), "{message}");
        let mut oversized = wire.clone();
        oversized["entries"] =
            serde_json::Value::Array(vec![wire["entries"][0].clone(); MAX_NOTES + 1]);
        assert!(serde_json::from_value::<ValueTypeBarrierNotes>(oversized).is_err());
        let mut invalid = wire;
        invalid["truncated"] = true.into();
        assert!(serde_json::from_value::<ValueTypeBarrierNotes>(invalid).is_err());
        let mut bounded = ValueTypeBarrierNotes::default();
        for value in 0..128 {
            let mut note = notes.entries()[0].clone();
            note.value_id = value;
            bounded.push(note);
        }
        bounded.validate().expect("bounded notes remain valid");
        assert!(bounded.retained_size() <= MAX_NOTE_BYTES);
        assert_eq!(bounded.omitted_lower_bound(), 1);
    }
}
