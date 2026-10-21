// Keep the old overlay path even when consumers use the root re-export.
#[allow(unused_imports)]
pub use brokk_bifrost_semantic::analyzer::semantic::oracle::retained::*;

#[cfg(test)]
pub(crate) mod tests {

    use crate::analyzer::semantic::OracleRelationSubject;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationOwner;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationRecord;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::retained::RetainedNode;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::retained::visit_retained_artifacts;

    use brokk_bifrost_analysis::analyzer::semantic::ir::go_extraction_support_26::capabilities;

    use brokk_bifrost_analysis::analyzer::semantic::ir::go_extraction_support_26::key;

    use brokk_bifrost_analysis::analyzer::semantic::ir::go_extraction_support_26::minimal_procedure;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::EvidenceHandle;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationArena;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationId;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ProcedureId;

    fn fixture_artifact() -> Arc<SemanticArtifact> {
        let key = key();
        Arc::new(
            SemanticArtifact::try_new(
                key.clone(),
                capabilities(&[]),
                vec![minimal_procedure(&key, ProcedureId::new(0), "retained", 1)],
            )
            .expect("minimal retained-artifact visitor fixture"),
        )
    }

    #[test]
    fn relation_handle_visits_unselected_sibling_record_artifacts_by_exact_allocation() {
        let selected_artifact = fixture_artifact();
        let sibling_artifact = fixture_artifact();
        assert_eq!(selected_artifact.key(), sibling_artifact.key());
        assert!(!Arc::ptr_eq(&selected_artifact, &sibling_artifact));
        let selected = selected_artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("selected fixture procedure");
        let sibling = sibling_artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("sibling fixture procedure");
        let arena = OracleRelationArena::new(
            OracleRelationOwner::ProcedureValueFlow {
                procedure: selected.clone(),
                context: OracleCallContext::empty(),
            },
            vec![
                OracleRelationRecord::dispatch_candidate(
                    selected,
                    std::iter::empty::<EvidenceHandle>(),
                    OracleLimits::default(),
                )
                .expect("selected fixture record"),
                OracleRelationRecord::dispatch_candidate(
                    sibling,
                    std::iter::empty::<EvidenceHandle>(),
                    OracleLimits::default(),
                )
                .expect("sibling fixture record"),
            ],
            OracleLimits::default(),
        )
        .expect("bounded fixture relation arena");
        let relation = arena
            .handle(OracleRelationId::new(0))
            .expect("selected fixture handle");
        assert!(matches!(
            relation.record().subject(),
            Some(OracleRelationSubject::DispatchCandidate(candidate))
                if Arc::ptr_eq(candidate.artifact(), &selected_artifact)
        ));
        assert!(matches!(
            arena
                .handle(OracleRelationId::new(1))
                .expect("unselected sibling fixture handle")
                .record()
                .subject(),
            Some(OracleRelationSubject::DispatchCandidate(candidate))
                if Arc::ptr_eq(candidate.artifact(), &sibling_artifact)
        ));

        let mut selected_allocation_only = true;
        visit_retained_artifacts(RetainedNode::Relation(&relation), |artifact| {
            selected_allocation_only &= Arc::ptr_eq(artifact, &selected_artifact);
        });
        assert!(
            !selected_allocation_only,
            "the selected handle owns its unselected sibling record's distinct artifact allocation"
        );

        let mut exact_window_covered = true;
        visit_retained_artifacts(RetainedNode::Relation(&relation), |artifact| {
            exact_window_covered &= Arc::ptr_eq(artifact, &selected_artifact)
                || Arc::ptr_eq(artifact, &sibling_artifact);
        });
        assert!(exact_window_covered);
    }
}
