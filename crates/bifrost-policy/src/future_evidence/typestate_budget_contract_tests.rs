use super::*;

#[test]
fn endpoint_terminal_accounts_for_its_owned_bytes_at_the_budget_boundary() {
    use crate::definition::EndpointObservationPhase;
    use crate::resolved::ResolvedEndpointIdentity;

    let endpoint = ResolvedEndpointIdentity::MatchEndpoint {
        endpoint_id: crate::definition::EndpointId::new("resource.endpoint").expect("endpoint id"),
    };
    let terminal = ResolvedTypestateTerminal::Endpoint {
        endpoint: endpoint.clone(),
        phase: EndpointObservationPhase::BeforeCall,
    };
    let bytes = size_of::<ResolvedTypestateTerminal>() + retained_extra(&endpoint);
    assert!(retained_extra(&endpoint) > 0, "endpoint owns an id string");
    let exact = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(bytes)
        .expect("valid exact byte bound")
        .build()
        .expect("budget");
    ensure_retained_evidence_bound("terminal", &terminal, &exact)
        .expect("exactly at the byte bound is admitted");
    let short = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(bytes - 1)
        .expect("valid lower byte bound")
        .build()
        .expect("budget");
    assert_eq!(
        ensure_retained_evidence_bound("terminal", &terminal, &short),
        Err(FutureEvidenceError::RetainedEvidenceBudget {
            field: "terminal",
            max_bytes: bytes - 1,
        })
    );
}
