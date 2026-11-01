use super::*;
use serde_json::{Value, json};

#[test]
fn semantic_evidence_wire_preserves_distinct_variants_and_fields() {
    let source = TaintSourceEvidence {
        trust_boundary: Some(TaintTrustBoundary::External),
        system_entry: Some(TaintSystemEntry::LocalInput),
    };
    assert_eq!(
        serde_json::to_value(source).unwrap()["trust_boundary"],
        "external"
    );

    let exceptional = PolicySemanticEvent::ExceptionalProcedureExit {
        scope: TypestateExitScope::AnalysisRoot,
    };
    let event_wire = serde_json::to_value(exceptional).unwrap();
    assert_eq!(
        event_wire,
        json!({"type": "exceptional_procedure_exit", "scope": "analysis_root"})
    );
    assert_eq!(
        serde_json::from_value::<PolicySemanticEvent>(event_wire).unwrap(),
        exceptional
    );
    assert!(
        serde_json::from_value::<PolicySemanticEvent>(json!({
            "type": "normal_procedure_exit", "scope": "unknown"
        }))
        .is_err()
    );

    let catalog = ResolvedEndpointIdentity::Catalog {
        catalog: ResolvedCatalogIdentity::try_new(
            PolicyId::new("security.catalog").unwrap(),
            1,
            TaintCatalogHash::from_bytes([7; 32]),
        )
        .unwrap(),
        entry_id: TaintEntryId::new("source").unwrap(),
    };
    let catalog_wire = serde_json::to_value(&catalog).unwrap();
    assert_eq!(catalog_wire["type"], "catalog");
    assert_eq!(
        serde_json::from_value::<ResolvedEndpointIdentity>(catalog_wire).unwrap(),
        catalog
    );

    let endpoint = ResolvedEndpointIdentity::Local {
        policy_id: PolicyId::new("security.flow").unwrap(),
        entry_id: TaintEntryId::new("sink").unwrap(),
    };
    for phase in [
        EndpointObservationPhase::AfterNormalReturn,
        EndpointObservationPhase::AfterExceptionalReturn,
    ] {
        let terminal = ResolvedTypestateTerminal::Endpoint {
            endpoint: endpoint.clone(),
            phase,
        };
        let wire = serde_json::to_value(&terminal).unwrap();
        assert_eq!(wire["phase"], phase.label());
        assert_eq!(
            serde_json::from_value::<ResolvedTypestateTerminal>(wire).unwrap(),
            terminal
        );
    }

    let transition = TypestateViolationEvidence::error_transition(
        TypestateEventId::new("close").unwrap(),
        Some(endpoint),
        TypestateStateId::new("open").unwrap(),
        TypestateStateId::new("error").unwrap(),
    );
    let wire = serde_json::to_value(&transition).unwrap();
    assert_eq!(wire["from"], "open");
    assert_eq!(wire["to"], "error");
    assert_ne!(wire["endpoint"], Value::Null);
    assert_eq!(
        serde_json::from_value::<TypestateViolationEvidence>(wire).unwrap(),
        transition
    );
}

#[test]
fn malformed_baseline_reports_parser_location() {
    let error = parse_policy_baseline_document("{\n  ?\n}").unwrap_err();
    let PolicyBaselineDocumentError::JsonDecode { line, column, .. } = &error else {
        panic!("expected JSON decode error: {error:?}");
    };
    assert_eq!((*line, *column), (2, 3));
    assert!(error.to_string().contains("line 2, column 3"));
}

#[test]
fn byte_budget_counts_utf8_bytes_and_accepts_exact_limit() {
    let value = "é";
    assert!(!is_over_byte_limit(value, 2));
    assert!(is_over_byte_limit(value, 1));
    assert!(!is_over_u64_byte_limit(value, 2));
    assert!(is_over_u64_byte_limit(value, 1));
}
