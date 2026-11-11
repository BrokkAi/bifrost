use super::*;
use brokk_bifrost_analysis::analyzer::{Language, TestProject};
use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;
use brokk_bifrost_rql::structural::{DetailedCodeQueryKey, DetailedCodeQueryProvenanceRefEvidence};

fn analyzer(source: &str) -> (tempfile::TempDir, TypescriptAnalyzer) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write(source)
        .unwrap();
    (
        temp,
        TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript)),
    )
}

fn rows() -> brokk_bifrost_rql::structural::search::DetailedCodeQueryResult {
    let (_temp, analyzer) = analyzer("function render() {}\n");
    let query = CodeQuery::from_sexp("(function :name \"render\")").unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    brokk_bifrost_rql::structural::search::execute_code_query_detailed_eager_index(
        &analyzer,
        &flow_state,
        &query,
        PolicyBudget::default().query_limits(),
        None,
    )
}

fn different_key() -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::Procedure {
        id: "collision-only-key".to_owned(),
    }
}

#[test]
fn candidate_hop_anchor_carries_candidate_id_across_asts() {
    const SOURCE: &str = "class Base { run() {} }\nclass Child extends Base {}\nfunction caller(x: Child) { x.run(); }\n";
    let (_temp, analyzer) = analyzer(SOURCE);
    let query = CodeQuery::from_sexp("(candidate-hierarchy (occurrences :role [member_position]))")
        .unwrap();
    let result = brokk_bifrost_rql::structural::execute(&analyzer, &query);
    let hop = result
        .results
        .iter()
        .find(|row| matches!(row.value, CodeQueryResultValue::CandidateHop { .. }))
        .unwrap();
    let CodeQueryResultValue::CandidateHop { value } = &hop.value else {
        unreachable!()
    };
    assert_ne!(value.ast_id, value.candidate_id);
    assert!(
        row_lineage_anchors(&hop.value)
            .contains(&RowLineageAnchor::Candidate(value.candidate_id.clone()))
    );
}

#[test]
fn lineage_target_rejects_a_same_site_row_with_a_different_key() {
    let result = rows();
    let right = result.evidence.first().unwrap().clone();
    let mut wrong = right.clone();
    wrong.key = different_key();
    let lineage = CandidateLineage {
        targets: vec![DetailedRowIdentity {
            domain: right.domain,
            key: right.key.clone(),
            file: right.file.clone(),
            byte_span: right.byte_span.clone(),
            identities: right.identities.clone(),
            source_slice_sha256: right.source_slice_sha256,
        }],
        ..Default::default()
    };
    let evidence = [wrong, right.clone()];
    assert_eq!(
        lineage_covering(0, &result.result.results, &evidence, &lineage),
        Some(&right)
    );
}

#[test]
fn lineage_target_rejects_a_same_key_row_from_a_different_file() {
    let result = rows();
    let right = result.evidence.first().unwrap().clone();
    let mut wrong = right.clone();
    wrong.file = ProjectFile::new(right.file.root().to_path_buf(), "other.ts");
    let lineage = CandidateLineage {
        targets: vec![DetailedRowIdentity {
            domain: right.domain,
            key: right.key.clone(),
            file: right.file.clone(),
            byte_span: right.byte_span.clone(),
            identities: right.identities.clone(),
            source_slice_sha256: right.source_slice_sha256,
        }],
        ..Default::default()
    };
    let evidence = [wrong, right.clone()];
    assert_eq!(
        lineage_covering(0, &result.result.results, &evidence, &lineage),
        Some(&right)
    );
}

#[test]
fn provenance_reference_rejects_a_same_site_row_with_a_different_key() {
    let result = rows();
    let right = result.evidence.first().unwrap();
    let reference = DetailedCodeQueryProvenanceRefEvidence {
        domain: right.domain,
        key: right.key.clone(),
        file: right.file.clone(),
        byte_span: right.byte_span.clone(),
        display_range: None,
        identities: right.identities.clone(),
        source_slice_sha256: right.source_slice_sha256,
    };
    let mut wrong = right.clone();
    wrong.key = different_key();
    assert!(evidence_matches_ref(right, &reference));
    assert!(!evidence_matches_ref(&wrong, &reference));
}
