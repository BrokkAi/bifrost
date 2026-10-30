use crate::typestate::*;

const SOURCE: &[u8] = br#"{
    "schema_version": 1,
    "states": ["ready"],
    "initial_state": "ready",
    "accepting_states": ["ready"],
    "error_states": [],
    "events": [{"id": "tick", "observation": {"occurrence": {"type": "allocation"}}}],
    "transitions": [],
    "terminal_expectations": [{"id": "done", "on": {"type": "analysis_root_exit", "kind": "normal"}, "expected_states": ["ready"]}],
    "semantics": {
        "analysis_mode": "may", "unmatched_event": "preserve_state",
        "uncertainty": {"ambiguous_dispatch": "abstain", "unknown_call": "abstain", "external_call": "abstain", "escape": "abstain", "incomplete_analysis": "abstain"}
    }
}"#;

fn spec() -> ProtocolSpec {
    ProtocolSpec::from_json(SOURCE).unwrap()
}

#[test]
fn json_whitespace_preserves_identity_through_the_inclusive_source_limit() {
    let source = SOURCE;
    let expected = spec().compile().unwrap().hash();
    for bytes in [MAX_PROTOCOL_SOURCE_BYTES / 2 + 1, MAX_PROTOCOL_SOURCE_BYTES] {
        let mut padded = source.to_vec();
        padded.resize(bytes, b' ');
        assert_eq!(
            ProtocolSpec::from_json(&padded)
                .unwrap()
                .compile()
                .unwrap()
                .hash(),
            expected
        );
    }
    let mut padded = source.to_vec();
    padded.resize(MAX_PROTOCOL_SOURCE_BYTES + 1, b' ');
    assert!(
        matches!(ProtocolSpec::from_json(&padded), Err(ProtocolSpecParseError::TooLarge {actual_bytes, max_bytes}) if actual_bytes == MAX_PROTOCOL_SOURCE_BYTES + 1 && max_bytes == MAX_PROTOCOL_SOURCE_BYTES)
    );
}

#[test]
fn event_count_accepts_the_advertised_inclusive_maximum() {
    for count in [
        MAX_PROTOCOL_EVENTS - 1,
        MAX_PROTOCOL_EVENTS,
        MAX_PROTOCOL_EVENTS + 1,
    ] {
        let mut input = spec();
        input.states = vec!["ready".into()];
        input.initial_state = "ready".into();
        input.accepting_states = vec!["ready".into()];
        input.error_states.clear();
        input.transitions.clear();
        input.terminal_expectations.clear();
        input.events = (0..count)
            .map(|i| ProtocolEventSpec {
                id: format!("event{i}"),
                observation: ProtocolObservationSpec {
                    occurrence: ProtocolEventOccurrence::Allocation,
                },
            })
            .collect();
        let compiled = input.compile();
        if count <= MAX_PROTOCOL_EVENTS {
            assert_eq!(compiled.unwrap().events().len(), count);
        } else {
            assert!(
                compiled
                    .unwrap_err()
                    .diagnostics()
                    .iter()
                    .any(|d| d.code() == ProtocolDiagnosticCode::TooManyEvents)
            );
        }
    }
}

#[test]
fn compilation_rejects_padded_identifiers_without_normalizing_them() {
    let source = std::str::from_utf8(SOURCE).unwrap();
    for key in ["ready", "tick", "done"] {
        let padded = format!(" {key} ");
        assert!(ProtocolStateKey::new(&padded).is_err());
        let changed = source.replace(&format!("\"{key}\""), &format!("\"{padded}\""));
        assert_ne!(changed, source);
        let error = ProtocolSpec::from_json(changed.as_bytes())
            .unwrap()
            .compile()
            .unwrap_err();
        assert!(
            error
                .diagnostics()
                .iter()
                .any(|d| d.code() == ProtocolDiagnosticCode::InvalidKey)
        );
    }
}

#[test]
fn disjoint_guard_declaration_order_preserves_identity_and_transition_table() {
    let mut input = spec();
    input.states = vec!["start".into(), "single".into(), "many".into()];
    input.initial_state = "start".into();
    input.accepting_states = input.states.clone();
    input.error_states.clear();
    input.events.truncate(1);
    input.terminal_expectations.clear();
    input.transitions = [
        (vec![ProtocolObjectCardinality::Singleton], "single"),
        (
            vec![
                ProtocolObjectCardinality::Summary,
                ProtocolObjectCardinality::Unknown,
            ],
            "many",
        ),
    ]
    .into_iter()
    .map(|(allowed, to)| ProtocolTransitionSpec {
        from: "start".into(),
        on: "tick".into(),
        to: to.into(),
        guard: ProtocolGuardSpec::ObjectCardinality { allowed },
    })
    .collect();
    let first = input.compile().unwrap();
    input.transitions.reverse();
    let second = input.compile().unwrap();
    assert_eq!(first.hash(), second.hash());
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    for compiled in [&first, &second] {
        for (cardinality, target) in [
            (ProtocolObjectCardinality::Singleton, "single"),
            (ProtocolObjectCardinality::Summary, "many"),
            (ProtocolObjectCardinality::Unknown, "many"),
        ] {
            let transition = compiled
                .transition_for(
                    compiled.initial_state(),
                    compiled
                        .event_id(&ProtocolEventKey::new("tick").unwrap())
                        .unwrap(),
                    cardinality,
                )
                .unwrap();
            assert_eq!(
                compiled.state_key(transition.to()).unwrap().as_str(),
                target
            );
        }
    }
}
