//! Public wire boundary coverage for retained barrier evidence.
use crate::ValueTypeBarrierNotes;
use serde_json::{Value, json};

fn wire() -> Value {
    json!({"entries": [{"barrier_id":"authored_boolean", "predicate":"intrinsic_bool",
        "reason":"unknown_type", "location":{"path":"src/lib.rs","byte_span":{"start":40,"end":41},
        "region":{"start_line":3,"start_column":17,"end_line":3,"end_column":18}},
        "mapping_kind":"synthetic", "procedure":"entry [0..100]", "value_id":3,
        "phase":"after_effects", "name":null}], "truncated":false,"omitted_lower_bound":0})
}

#[test]
fn barrier_notes_wire_preserves_mapping_and_inclusive_name_bound() {
    for mapping in ["exact", "enclosing", "synthetic"] {
        // The producer accepts parameter names up to and including 256 bytes.
        for length in [255, 256, 257] {
            let mut value = wire();
            value["entries"][0]["mapping_kind"] = mapping.into();
            value["entries"][0]["name"] = "n".repeat(length).into();
            let result = serde_json::from_value::<ValueTypeBarrierNotes>(value.clone());
            if length <= 256 {
                assert_eq!(serde_json::to_value(result.unwrap()).unwrap(), value);
            } else {
                assert!(result.is_err());
            }
        }
    }
    let mut invalid = wire();
    invalid["entries"][0]["mapping_kind"] = "unknown".into();
    assert!(serde_json::from_value::<ValueTypeBarrierNotes>(invalid).is_err());
}

#[test]
fn barrier_notes_wire_preserves_omissions_without_selecting_a_partial_subset() {
    for entries in [json!([]), wire()["entries"].clone()] {
        let value = json!({"entries":entries,"truncated":true,"omitted_lower_bound":2});
        let notes: ValueTypeBarrierNotes = serde_json::from_value(value.clone()).unwrap();
        assert!(!notes.is_empty(), "omission evidence must remain visible");
        assert_eq!(notes.omitted_lower_bound(), 2);
        assert_eq!(serde_json::to_value(notes).unwrap(), value);
    }
    let invalid = json!({"entries":[],"truncated":true,"omitted_lower_bound":0});
    assert!(serde_json::from_value::<ValueTypeBarrierNotes>(invalid).is_err());
}

#[test]
fn barrier_note_message_names_authored_barrier_and_source_coordinates() {
    let notes: ValueTypeBarrierNotes = serde_json::from_value(wire()).unwrap();
    assert_eq!(
        notes.entries()[0].message(),
        "Barrier authored_boolean (IntrinsicBool) undecided for value at src/lib.rs:3:17 [40..41] (enclosing location), entry [0..100] value 3: type is unknown; flow retained."
    );
}
