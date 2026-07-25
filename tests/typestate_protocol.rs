use brokk_bifrost::analyzer::typestate::{
    MAX_PROTOCOL_EXPECTATIONS, MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS, MAX_PROTOCOL_SOURCE_BYTES,
    ProtocolCompileError, ProtocolDiagnosticCode, ProtocolEventKey, ProtocolEventOccurrence,
    ProtocolEventSpec, ProtocolGuardSpec, ProtocolObjectCardinality, ProtocolObservationPhase,
    ProtocolObservationSpec, ProtocolProcedureExitKind, ProtocolSpec, ProtocolStateKey,
    ProtocolTerminalExpectationSpec, ProtocolTerminalObservationSpec, ProtocolTransitionSpec,
    ProtocolUncertaintyBehavior, ProtocolUncertaintyCause, ProtocolUncertaintyResolution,
};

const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("fixtures/typestate/resource-lifecycle.protocol.json");
const RESOURCE_LIFECYCLE_CANONICAL: &str =
    include_str!("fixtures/typestate/resource-lifecycle.canonical.json");
const RESOURCE_LIFECYCLE_CANONICAL_PRETTY: &str =
    include_str!("fixtures/typestate/resource-lifecycle.canonical.pretty.json");
const RESOURCE_LIFECYCLE_HASH: &str =
    "0e42978dfc9717f75c3a7d543b35103355099712df860b988563f761b5ebbd75";

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
    assert_eq!(
        first.canonical_bytes(),
        RESOURCE_LIFECYCLE_CANONICAL
            .trim_end_matches('\n')
            .as_bytes()
    );
    assert_eq!(
        first.canonical_rendering(),
        RESOURCE_LIFECYCLE_CANONICAL_PRETTY.trim_end_matches('\n')
    );
    assert_eq!(first.hash().to_string(), RESOURCE_LIFECYCLE_HASH);
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
fn public_call_exit_and_terminal_observations_have_neutral_internal_shapes() {
    let mut spec = fixture();
    spec.events.push(ProtocolEventSpec {
        id: "argument-after-call".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterNormalReturn,
            },
        },
    });
    spec.events.push(ProtocolEventSpec {
        id: "argument-after-exceptional-call".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterExceptionalReturn,
            },
        },
    });
    spec.events.push(ProtocolEventSpec {
        id: "return-after-call".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AfterNormalReturn,
            },
        },
    });
    spec.events.push(ProtocolEventSpec {
        id: "normal-procedure-exit".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::ProcedureExit {
                kind: ProtocolProcedureExitKind::Normal,
            },
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
fn uncertainty_behaviors_compile_to_bounded_state_relations() {
    let mut spec = fixture();
    spec.semantics.uncertainty.ambiguous_dispatch =
        ProtocolUncertaintyBehavior::ConservativeTransition;
    spec.semantics.uncertainty.unknown_call = ProtocolUncertaintyBehavior::ConservativeTransition;
    let protocol = spec.compile().expect("fixture should compile");
    let open = protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();
    let event = |key| {
        protocol
            .event_id(&ProtocolEventKey::new(key).unwrap())
            .unwrap()
    };
    let call_events = [event("use"), event("close")];

    let state_names = |resolution: ProtocolUncertaintyResolution| {
        resolution
            .states()
            .expect("conservative transition should produce states")
            .iter()
            .map(|state| protocol.state_key(*state).unwrap().as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        state_names(
            protocol
                .resolve_uncertainty(
                    ProtocolUncertaintyCause::AmbiguousDispatch,
                    open,
                    ProtocolObjectCardinality::Singleton,
                    &call_events,
                )
                .unwrap()
        ),
        vec!["closed", "open"]
    );
    assert_eq!(
        state_names(
            protocol
                .resolve_uncertainty(
                    ProtocolUncertaintyCause::UnknownCall,
                    open,
                    ProtocolObjectCardinality::Singleton,
                    &call_events,
                )
                .unwrap()
        ),
        vec!["closed", "open", "violated"]
    );
    let ProtocolUncertaintyResolution::StateSet(states) = protocol
        .resolve_uncertainty(
            ProtocolUncertaintyCause::UnknownCall,
            open,
            ProtocolObjectCardinality::Singleton,
            &call_events,
        )
        .unwrap()
    else {
        panic!("conservative transition should retain state and transition witnesses");
    };
    let mut error_events = states
        .error_witnesses()
        .iter()
        .map(|witness| {
            protocol
                .event(witness.event())
                .expect("witness event")
                .key()
                .as_str()
        })
        .collect::<Vec<_>>();
    error_events.sort_unstable();
    assert_eq!(error_events, vec!["close", "use"]);
    assert_eq!(
        protocol
            .resolve_uncertainty(
                ProtocolUncertaintyCause::Escape,
                open,
                ProtocolObjectCardinality::Singleton,
                &call_events,
            )
            .unwrap(),
        ProtocolUncertaintyResolution::Abstain
    );
    assert_eq!(
        protocol
            .resolve_uncertainty(
                ProtocolUncertaintyCause::ExternalCall,
                open,
                ProtocolObjectCardinality::Singleton,
                &call_events,
            )
            .unwrap(),
        ProtocolUncertaintyResolution::PreserveUncertainty { state: open }
    );
    assert_eq!(
        state_names(
            protocol
                .resolve_uncertainty(
                    ProtocolUncertaintyCause::AmbiguousDispatch,
                    open,
                    ProtocolObjectCardinality::Singleton,
                    &[event("acquire")],
                )
                .unwrap()
        ),
        vec!["open"]
    );
}

#[test]
fn all_uncertainty_behaviors_reject_foreign_event_ids() {
    let protocol = fixture().compile().expect("fixture should compile");
    let mut foreign_spec = fixture();
    foreign_spec.events.push(ProtocolEventSpec {
        id: "zz-foreign".to_owned(),
        observation: ProtocolObservationSpec {
            occurrence: ProtocolEventOccurrence::FieldRead,
        },
    });
    let foreign_protocol = foreign_spec
        .compile()
        .expect("foreign fixture should compile");
    let foreign_event = foreign_protocol
        .event_id(&ProtocolEventKey::new("zz-foreign").unwrap())
        .expect("foreign event");
    let open = protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();

    for cause in [
        ProtocolUncertaintyCause::ExternalCall,
        ProtocolUncertaintyCause::Escape,
    ] {
        assert_eq!(
            protocol.resolve_uncertainty(
                cause,
                open,
                ProtocolObjectCardinality::Singleton,
                &[foreign_event],
            ),
            None,
            "{cause:?} accepted an event ID from another protocol"
        );
    }
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
fn full_cardinality_guard_has_the_same_identity_as_always() {
    let baseline = fixture().compile().expect("fixture should compile");
    let mut equivalent = fixture();
    equivalent.transitions[0].guard = ProtocolGuardSpec::ObjectCardinality {
        allowed: vec![
            ProtocolObjectCardinality::Unknown,
            ProtocolObjectCardinality::Singleton,
            ProtocolObjectCardinality::Summary,
        ],
    };
    let equivalent = equivalent
        .compile()
        .expect("full-domain guard should compile");

    assert_eq!(baseline.canonical_bytes(), equivalent.canonical_bytes());
    assert_eq!(baseline.hash(), equivalent.hash());
}

#[test]
fn terminal_expectation_memberships_have_an_aggregate_budget() {
    let mut spec = fixture();
    let states_per_expectation =
        MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS / MAX_PROTOCOL_EXPECTATIONS + 1;
    spec.terminal_expectations = (0..MAX_PROTOCOL_EXPECTATIONS)
        .map(|index| ProtocolTerminalExpectationSpec {
            id: format!("expectation-{index}"),
            on: ProtocolTerminalObservationSpec::AnalysisRootExit {
                kind: ProtocolProcedureExitKind::Normal,
            },
            expected_states: vec!["closed".to_owned(); states_per_expectation],
        })
        .collect();

    let codes = diagnostics(
        spec.compile()
            .expect_err("aggregate expectation budget should be enforced"),
    );
    assert!(codes.contains(&ProtocolDiagnosticCode::TooManyExpectedStateMemberships));
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

#[test]
fn json_parse_errors_are_bounded_and_escape_control_characters() {
    let unknown_field = format!(r#"bad\n\u001b{}"#, "x".repeat(1_024));
    let source = std::str::from_utf8(RESOURCE_LIFECYCLE)
        .unwrap()
        .replace("schema_version", &unknown_field);

    let error = ProtocolSpec::from_json(source.as_bytes()).expect_err("unknown field should fail");
    let rendered = error.to_string();
    assert!(rendered.contains(r"\n"));
    assert!(rendered.contains(r"\u{1b}"));
    assert!(!rendered.contains('\n'));
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.len() <= 128);
    assert!(error.line().is_some());
    assert!(error.column().is_some());
}
