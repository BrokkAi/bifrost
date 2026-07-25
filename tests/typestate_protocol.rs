use brokk_bifrost::analyzer::typestate::{
    MAX_PROTOCOL_SOURCE_BYTES, ObjectBindingRole, ProtocolCompileError, ProtocolDiagnosticCode,
    ProtocolEventKey, ProtocolEventOccurrence, ProtocolEventSpec, ProtocolGuardSpec,
    ProtocolObjectCardinality, ProtocolObservationPhase, ProtocolObservationSpec,
    ProtocolProcedureExitKind, ProtocolSpec, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec,
};

const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("fixtures/typestate/resource-lifecycle.protocol.json");

fn fixture() -> ProtocolSpec {
    ProtocolSpec::from_json(RESOURCE_LIFECYCLE).expect("resource lifecycle fixture should parse")
}

fn diagnostics(error: ProtocolCompileError) -> Vec<ProtocolDiagnosticCode> {
    error
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code())
        .collect()
}

#[test]
fn resource_lifecycle_fixture_exposes_diagnostic_neutral_semantics() {
    let protocol = fixture().compile().expect("fixture should compile");
    let state = |key| {
        protocol
            .state_id(&ProtocolStateKey::new(key).expect("test state key"))
            .expect("fixture state")
    };
    let event = |key| {
        protocol
            .event_id(&ProtocolEventKey::new(key).expect("test event key"))
            .expect("fixture event")
    };

    assert_eq!(
        protocol
            .state_key(protocol.initial_state())
            .unwrap()
            .as_str(),
        "unallocated"
    );
    assert!(protocol.is_accepting(state("unallocated")));
    assert!(protocol.is_accepting(state("closed")));
    assert!(protocol.is_error(state("violated")));
    assert!(!protocol.is_accepting(state("open")));

    let use_after_close = protocol
        .transition_for(
            state("closed"),
            event("use"),
            ProtocolObjectCardinality::Singleton,
        )
        .expect("use-after-close transition");
    assert_eq!(use_after_close.to(), state("violated"));
    assert!(protocol.is_error(use_after_close.to()));

    let recovery = protocol
        .transition_for(
            state("violated"),
            event("acquire"),
            ProtocolObjectCardinality::Unknown,
        )
        .expect("error states are not implicitly absorbing");
    assert_eq!(recovery.to(), state("open"));
    assert!(!protocol.is_error(recovery.to()));

    assert_eq!(protocol.terminal_expectations().len(), 2);
    assert!(
        protocol
            .terminal_expectations()
            .iter()
            .any(|expectation| matches!(
                expectation.on(),
                ProtocolTerminalObservationSpec::AnalysisRootExit {
                    kind: ProtocolProcedureExitKind::Normal,
                }
            ))
    );
    assert!(
        protocol
            .terminal_expectations()
            .iter()
            .any(|expectation| matches!(
                expectation.on(),
                ProtocolTerminalObservationSpec::AnalysisRootExit {
                    kind: ProtocolProcedureExitKind::Exceptional,
                }
            ))
    );
    let normal_expectation =
        brokk_bifrost::analyzer::typestate::ProtocolExpectationKey::new("normal-exit-closed")
            .unwrap();
    let normal_expectation_id = protocol
        .expectation_id(&normal_expectation)
        .expect("durable expectation key lookup");
    assert_eq!(
        protocol
            .terminal_expectation(normal_expectation_id)
            .unwrap()
            .key(),
        &normal_expectation
    );
    assert_eq!(protocol.hash().to_string().len(), 64);
    assert_eq!(
        protocol.hash(),
        brokk_bifrost::policy::TypestateProtocolHash::from_canonical_bytes(
            protocol.canonical_bytes()
        )
    );
}

#[test]
fn canonical_protocol_identity_is_independent_of_declaration_order() {
    let first = fixture().compile().expect("fixture should compile");
    let mut reordered = fixture();
    reordered.states.reverse();
    reordered.accepting_states.reverse();
    reordered.error_states.reverse();
    reordered.events.reverse();
    reordered.transitions.reverse();
    reordered.terminal_expectations.reverse();

    let second = reordered
        .compile()
        .expect("reordered fixture should compile");
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.canonical_rendering(), second.canonical_rendering());
    assert_eq!(first.hash(), second.hash());
}

#[test]
fn validation_reports_conflicting_and_overlapping_transitions() {
    let mut spec = fixture();
    spec.transitions.push(ProtocolTransitionSpec {
        from: "open".to_owned(),
        on: "use".to_owned(),
        to: "closed".to_owned(),
        guard: ProtocolGuardSpec::Always,
    });
    spec.transitions.push(ProtocolTransitionSpec {
        from: "unallocated".to_owned(),
        on: "close".to_owned(),
        to: "violated".to_owned(),
        guard: ProtocolGuardSpec::ObjectCardinality {
            allowed: vec![
                ProtocolObjectCardinality::Singleton,
                ProtocolObjectCardinality::Summary,
            ],
        },
    });
    spec.transitions.push(ProtocolTransitionSpec {
        from: "unallocated".to_owned(),
        on: "close".to_owned(),
        to: "violated".to_owned(),
        guard: ProtocolGuardSpec::ObjectCardinality {
            allowed: vec![
                ProtocolObjectCardinality::Summary,
                ProtocolObjectCardinality::Unknown,
            ],
        },
    });

    let codes = diagnostics(spec.compile().expect_err("invalid transitions should fail"));
    assert!(codes.contains(&ProtocolDiagnosticCode::ConflictingTransition));
    assert!(codes.contains(&ProtocolDiagnosticCode::OverlappingTransitionGuards));
}

#[test]
fn validation_rejects_unreachable_and_nonaccepting_terminal_states() {
    let mut spec = fixture();
    spec.states.push("orphaned".to_owned());
    spec.terminal_expectations[0]
        .expected_states
        .push("open".to_owned());

    let codes = diagnostics(spec.compile().expect_err("invalid states should fail"));
    assert!(codes.contains(&ProtocolDiagnosticCode::UnreachableState));
    assert!(codes.contains(&ProtocolDiagnosticCode::NonAcceptingExpectedState));
}

#[test]
fn one_state_protocol_is_valid_and_source_size_is_bounded() {
    let source = br#"{
        "schema_version": 1,
        "states": ["ready"],
        "initial_state": "ready",
        "accepting_states": ["ready"],
        "error_states": [],
        "events": [],
        "transitions": [],
        "terminal_expectations": [{
            "id": "normal-ready",
            "on": {
                "type": "analysis_root_exit",
                "kind": "normal"
            },
            "expected_states": ["ready"]
        }],
        "semantics": {
            "analysis_mode": "must",
            "unmatched_event": "mark_inconclusive",
            "uncertainty": {
                "ambiguous_dispatch": "conservative_transition",
                "unknown_call": "conservative_transition",
                "external_call": "conservative_transition",
                "escape": "abstain",
                "incomplete_analysis": "abstain"
            }
        }
    }"#;
    let protocol = ProtocolSpec::from_json(source)
        .expect("minimal protocol should parse")
        .compile()
        .expect("minimal protocol should compile");
    assert_eq!(protocol.states().len(), 1);
    assert_eq!(protocol.events().len(), 0);
    assert_eq!(protocol.transitions().len(), 0);

    let oversized = vec![b' '; MAX_PROTOCOL_SOURCE_BYTES + 1];
    assert!(ProtocolSpec::from_json(&oversized).is_err());
}

#[test]
fn invalid_event_binding_shape_is_rejected() {
    let mut spec = fixture();
    spec.events[0].observation.subject = ObjectBindingRole::Receiver;

    let codes = diagnostics(
        spec.compile()
            .expect_err("invalid binding shape should fail"),
    );
    assert!(codes.contains(&ProtocolDiagnosticCode::InvalidEventShape));
}

#[test]
fn public_call_exit_and_terminal_observations_have_neutral_internal_shapes() {
    let mut spec = fixture();
    spec.events.push(ProtocolEventSpec {
        id: "argument-after-call".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterNormalReturn,
            },
            subject: ObjectBindingRole::Actual { index: u32::MAX },
        },
    });
    spec.events.push(ProtocolEventSpec {
        id: "argument-after-exceptional-call".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterExceptionalReturn,
            },
            subject: ObjectBindingRole::Actual { index: 1 },
        },
    });
    spec.events.push(ProtocolEventSpec {
        id: "return-after-call".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterNormalReturn,
            },
            subject: ObjectBindingRole::ReturnValue,
        },
    });
    spec.events.push(ProtocolEventSpec {
        id: "normal-procedure-exit".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::ProcedureExit {
                kind: ProtocolProcedureExitKind::Normal,
            },
            subject: ObjectBindingRole::CurrentObject,
        },
    });
    spec.terminal_expectations
        .push(ProtocolTerminalExpectationSpec {
            id: "closed-after-endpoint".to_owned(),
            on: ProtocolTerminalObservationSpec::Event {
                observation: ProtocolObservationSpec {
                    occurrence: ProtocolEventOccurrence::Endpoint {
                        phase: ProtocolObservationPhase::AfterNormalReturn,
                    },
                    subject: ObjectBindingRole::Actual { index: 0 },
                },
            },
            expected_states: vec!["closed".to_owned()],
        });

    let protocol = spec
        .compile()
        .expect("public trigger surfaces should lower without language branches");
    assert_eq!(protocol.events().len(), 7);
    assert_eq!(protocol.terminal_expectations().len(), 3);
}

#[test]
fn terminal_event_observations_reuse_event_shape_validation() {
    let mut spec = fixture();
    spec.terminal_expectations[0].on = ProtocolTerminalObservationSpec::Event {
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Allocation,
            subject: ObjectBindingRole::Receiver,
        },
    };

    let codes = diagnostics(
        spec.compile()
            .expect_err("invalid terminal observation should fail"),
    );
    assert!(codes.contains(&ProtocolDiagnosticCode::InvalidTerminalObservation));
}

#[test]
fn guard_normalization_is_bounded_by_the_cardinality_domain() {
    let mut spec = fixture();
    spec.transitions[0].guard = ProtocolGuardSpec::ObjectCardinality {
        allowed: vec![ProtocolObjectCardinality::Singleton; 4],
    };

    let codes = diagnostics(spec.compile().expect_err("oversized guard should fail"));
    assert!(codes.contains(&ProtocolDiagnosticCode::TooManyGuardValues));
}

#[test]
fn invalid_key_diagnostics_escape_terminal_control_characters() {
    let mut spec = fixture();
    spec.initial_state = "bad\n\u{1b}[2J".to_owned();

    let error = spec.compile().expect_err("invalid key should fail");
    let diagnostic = error
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == ProtocolDiagnosticCode::InvalidKey)
        .expect("invalid-key diagnostic");
    assert!(diagnostic.message().contains(r"\n"));
    assert!(diagnostic.message().contains(r"\u{1b}"));
    assert!(!diagnostic.message().contains('\n'));
    assert!(!diagnostic.message().contains('\u{1b}'));
}
