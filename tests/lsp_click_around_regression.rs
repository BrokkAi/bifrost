mod common;

use common::lsp_click::{
    ClickCase, ClickExpectation, ClickFixture, ClickOperation, assert_click_cases,
};

#[test]
fn milestone_0_harness_smoke_definition_references_and_null() {
    let fixture = ClickFixture::new("milestone_0_java_smoke").file(
        "Smoke.java",
        r#"class Smoke {
    void <decl_target>target() {}
    void caller() {
        <call_target>target();
        <missing_target>missing();
    }
}
"#,
    );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "call resolves to declaration",
                "call_target",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["decl_target"]),
            ),
            ClickCase::new(
                "declaration finds call reference",
                "decl_target",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["call_target"]),
            ),
            ClickCase::new(
                "unresolved call returns empty definition",
                "missing_target",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
        ],
    );

    assert_eq!(timings.len(), 3);
    let slowest = timings
        .iter()
        .max_by_key(|timing| timing.elapsed)
        .expect("timing recorded");
    eprintln!(
        "milestone_0_harness_smoke slowest={} marker={} op={} elapsed_ms={}",
        slowest.case_name,
        slowest.marker,
        slowest.operation,
        slowest.elapsed.as_millis()
    );
}
