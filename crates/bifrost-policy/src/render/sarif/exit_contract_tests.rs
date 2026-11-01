use super::{SarifLog, SarifToolIdentity};
use crate::{POLICY_EXIT_CLEAN, POLICY_EXIT_UNRELIABLE};

#[test]
fn sarif_exit_descriptions_follow_gate_status() {
    let report = super::super::sarif_contract_tests::evaluated_report();
    let tool = SarifToolIdentity::default();
    for (status, expected_word) in [
        (POLICY_EXIT_CLEAN, "passed"),
        (POLICY_EXIT_UNRELIABLE, "unreliable"),
    ] {
        let log = SarifLog::try_from_report(&report, &tool, Some(status)).unwrap();
        let mut bytes = Vec::new();
        crate::render::write_canonical_json(&log, &mut bytes, usize::MAX).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let invocation = &value["runs"][0]["invocations"][0];
        assert_eq!(invocation["exitCode"], status);
        assert!(
            invocation["exitCodeDescription"]
                .as_str()
                .unwrap()
                .contains(expected_word)
        );
        assert_eq!(
            invocation["executionSuccessful"],
            status == POLICY_EXIT_CLEAN
        );
    }
}
