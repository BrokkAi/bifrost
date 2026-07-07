mod common;

use common::lsp_click::{
    ClickCase, ClickExpectation, ClickFixture, ClickOperation, assert_click_cases,
};

fn assert_timing_summary(
    milestone: &str,
    timings: &[common::lsp_click::ClickTiming],
    expected_cases: usize,
) {
    assert_eq!(timings.len(), expected_cases);
    let slowest = timings
        .iter()
        .max_by_key(|timing| timing.elapsed)
        .expect("timing recorded");
    eprintln!(
        "{milestone} slowest={} marker={} op={} elapsed_ms={}",
        slowest.case_name,
        slowest.marker,
        slowest.operation,
        slowest.elapsed.as_millis()
    );
}

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

    assert_timing_summary("milestone_0_harness_smoke", &timings, 3);
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

    assert_timing_summary("milestone_1_go_embedded_promotion", &timings, 10);
}

#[test]
fn milestone_2_rust_trait_impl_click_around() {
    let fixture = ClickFixture::new("milestone_2_rust_trait_impls")
        .file(
            "Cargo.toml",
            "[package]\nname = \"click_around_rust\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            r#"pub mod contracts;
pub mod service;
pub mod client;
"#,
        )
        .file(
            "src/contracts.rs",
            r#"<worker_trait_range>pub trait <worker_trait_decl>Worker {
    type <worker_output_decl>Output;

    fn <worker_work_decl>work(&self) -> Self::<worker_output_use>Output;

    fn <worker_describe_decl>describe(&self) -> &'static str {
        "worker"
    }
}
"#,
        )
        .file(
            "src/service.rs",
            r#"use crate::contracts::Worker;

<file_job_range>pub struct <file_job_decl>FileJob;
<memory_job_range>pub struct <memory_job_decl>MemoryJob;
pub struct <helper_decl>Helper;
pub struct <job_result_decl>JobResult;

impl Worker for FileJob {
    type <file_output_impl>Output = JobResult;

    fn <file_work_impl>work(&self) -> Self::Output {
        JobResult
    }
}

impl Worker for MemoryJob {
    type <memory_output_impl>Output = JobResult;

    fn <memory_work_impl>work(&self) -> Self::Output {
        JobResult
    }
}

impl Helper {
    pub fn <helper_work_decl>work(&self) -> JobResult {
        JobResult
    }
}
"#,
        )
        .file(
            "src/client.rs",
            r#"use crate::contracts::Worker;
use crate::service::{FileJob, Helper, MemoryJob};

fn run() {
    let file: <file_type_usage>FileJob = FileJob;
    let memory: MemoryJob = MemoryJob;
    let helper: Helper = Helper;

    let _ = file.<file_work_call>work();
    let _ = memory.<memory_work_call>work();
    let _ = Worker::<ufcs_work_call>work(&file);
    let _ = file.<file_describe_call>describe();
    let _ = helper.<helper_work_call>work();
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "trait method call resolves to concrete impl declaration",
                "file_work_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["file_work_impl"]),
            ),
            ClickCase::new(
                "second implementer method call resolves to its concrete impl declaration",
                "memory_work_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["memory_work_impl"]),
            ),
            ClickCase::new(
                "UFCS trait method call resolves to trait declaration",
                "ufcs_work_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["worker_work_decl"]),
            ),
            ClickCase::new(
                "default trait method call resolves to default declaration",
                "file_describe_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["worker_describe_decl"]),
            ),
            ClickCase::new(
                "unrelated inherent same-name method resolves to inherent declaration",
                "helper_work_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["helper_work_decl"]),
            ),
            ClickCase::new(
                "trait method references include typed calls and UFCS only",
                "worker_work_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&[
                    "file_work_call",
                    "memory_work_call",
                    "ufcs_work_call",
                ]),
            ),
            ClickCase::new(
                "trait method implementation finds both impl methods",
                "worker_work_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["file_work_impl", "memory_work_impl"]),
            ),
            ClickCase::new(
                "trait type implementation finds both implementers",
                "worker_trait_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["file_job_decl", "memory_job_decl"]),
            ),
            ClickCase::new(
                "FileJob type definition resolves from typed local",
                "file_type_usage",
                ClickOperation::TypeDefinition,
                ClickExpectation::Locations(&["file_job_decl"]),
            ),
            ClickCase::new(
                "FileJob supertypes include Worker",
                "file_job_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["worker_trait_range"]),
            ),
            ClickCase::new(
                "Worker subtypes include both implementers",
                "worker_trait_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["file_job_range", "memory_job_range"]),
            ),
            ClickCase::new(
                "trait method associated type use resolves to trait associated type",
                "worker_output_use",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["worker_output_decl"]),
            ),
            ClickCase::new(
                "trait associated type implementation finds impl associated types",
                "worker_output_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["file_output_impl", "memory_output_impl"]),
            ),
            ClickCase::new(
                "associated type implementation declaration selects itself",
                "file_output_impl",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["file_output_impl"]),
            ),
        ],
    );

    assert_timing_summary("milestone_2_rust_trait_impls", &timings, 14);
}
