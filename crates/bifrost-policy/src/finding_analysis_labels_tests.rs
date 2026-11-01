use crate::definition::PolicyAnalysisType;

#[test]
fn stored_analysis_labels_round_trip() {
    for analysis in [PolicyAnalysisType::Taint, PolicyAnalysisType::Flow] {
        let wire = serde_json::to_string(&analysis).unwrap();
        let decoded: PolicyAnalysisType = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded, analysis);
    }
}
