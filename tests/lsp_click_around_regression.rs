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

#[test]
fn milestone_1_go_embedded_promotion_click_around() {
    let fixture = ClickFixture::new("milestone_1_go_embedded_promotion")
        .file("go.mod", "module example.com/app\n")
        .file(
            "service/audit.go",
            r#"package service

type AuditLog struct {
    <audit_record_decl>Record string
    <audit_id_decl>ID string
}

func (AuditLog) <audit_last_decl>Last() string { return "" }

type Base struct {
    <base_deep_decl>Deep string
    <base_id_decl>ID string
}

type Wrapper struct {
    Base
}

type Service struct {
    Base
    <service_id_decl>ID string
}

type Left struct {
    <left_code_decl>Code string
}

type Right struct {
    <right_code_decl>Code string
}

type Ambiguous struct {
    Left
    Right
}
"#,
        )
        .file(
            "service/worker.go",
            r#"package service

type Worker struct {
    AuditLog
    Wrapper
}

func NewWorker() *Worker { return &Worker{} }

func NewService() *Service { return &Service{} }

func NewAmbiguous() Ambiguous { return Ambiguous{} }
"#,
        )
        .file(
            "main.go",
            r#"package main

import "example.com/app/service"

func use() {
    worker := service.NewWorker()
    _ = worker.<worker_record>Record
    _ = worker.<worker_last>Last()
    _ = worker.<worker_deep>Deep
    _ = worker.<worker_id>ID

    wrapper := service.Wrapper{}
    _ = wrapper.<wrapper_base_id>ID

    svc := service.NewService()
    _ = svc.<service_id>ID

    ambiguous := service.NewAmbiguous()
    _ = ambiguous.<ambiguous_code>Code
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "promoted field resolves through imported factory receiver",
                "worker_record",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["audit_record_decl"]),
            ),
            ClickCase::new(
                "promoted method resolves through embedded receiver",
                "worker_last",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["audit_last_decl"]),
            ),
            ClickCase::new(
                "deep promoted field resolves through shallower wrapper chain",
                "worker_deep",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_deep_decl"]),
            ),
            ClickCase::new(
                "shallower embedded field wins over deeper promoted field",
                "worker_id",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["audit_id_decl"]),
            ),
            ClickCase::new(
                "non-shadowed base field resolves through wrapper embedding",
                "wrapper_base_id",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_id_decl"]),
            ),
            ClickCase::new(
                "explicit outer field shadows embedded field",
                "service_id",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["service_id_decl"]),
            ),
            ClickCase::new(
                "same depth promoted field ambiguity returns empty definition",
                "ambiguous_code",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "canonical embedded field declaration finds promoted call site",
                "audit_record_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["worker_record"]),
            ),
            ClickCase::new(
                "base field declaration selects the base field itself",
                "base_id_decl",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_id_decl"]),
            ),
            ClickCase::new(
                "base field references include only semantically valid promoted use",
                "base_id_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["wrapper_base_id"]),
            ),
        ],
    );

    assert_eq!(timings.len(), 10);
    let slowest = timings
        .iter()
        .max_by_key(|timing| timing.elapsed)
        .expect("timing recorded");
    eprintln!(
        "milestone_1_go_embedded_promotion slowest={} marker={} op={} elapsed_ms={}",
        slowest.case_name,
        slowest.marker,
        slowest.operation,
        slowest.elapsed.as_millis()
    );
}
