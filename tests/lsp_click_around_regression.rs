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

#[test]
fn milestone_3_php_interface_trait_click_around() {
    let fixture = ClickFixture::new("milestone_3_php_interface_traits")
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Contracts/Notifier.php",
            r#"<?php
namespace App\Contracts;

interface <notifier_interface_decl>Notifier {
    public function <interface_notify_decl>notify(string $message): void;
}
"#,
        )
        .file(
            "src/Support/LogsEvents.php",
            r#"<?php
namespace App\Support;

trait LogsEvents {
    public function <trait_record_decl>record(string $message): string {
        return $message;
    }
}
"#,
        )
        .file(
            "src/Service/EmailNotifier.php",
            r#"<?php
namespace App\Service;

use App\Contracts\Notifier;
use App\Support\LogsEvents;

class <email_notifier_decl>EmailNotifier implements Notifier {
    use LogsEvents;

    public function <email_notify_decl>notify(string $message): void {
        $this-><this_record_call>record($message);
    }
}
"#,
        )
        .file(
            "src/Factory.php",
            r#"<?php
namespace App;

use App\Service\EmailNotifier;

function makeNotifier(): EmailNotifier {
    return new EmailNotifier();
}
"#,
        )
        .file(
            "src/Other/OtherNotifier.php",
            r#"<?php
namespace App\Other;

class <other_notifier_decl>OtherNotifier {
    public function <other_notify_decl>notify(string $message): void {}
    public function <other_record_decl>record(string $message): string {
        return $message;
    }
}
"#,
        )
        .file(
            "src/Consumer.php",
            r#"<?php
namespace App;

use App\Contracts\Notifier;
use App\Service\EmailNotifier;
use App\Other\OtherNotifier;

function consume(Notifier $notifier, EmailNotifier $mail): void {
    $notifier-><interface_notify_call>notify("contract");
    $mail-><mail_notify_call>notify("concrete");
    $mail-><mail_record_call>record("logged");

    $factory = makeNotifier();
    $factory-><factory_notify_call>notify("factory");

    $other = new OtherNotifier();
    $other-><other_notify_call>notify("other");
    $other-><other_record_call>record("unrelated");
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "interface-typed receiver resolves to interface method",
                "interface_notify_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["interface_notify_decl"]),
            ),
            ClickCase::new(
                "concrete typed receiver resolves to implementation method",
                "mail_notify_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["email_notify_decl"]),
            ),
            ClickCase::new(
                "factory-returned receiver resolves to implementation method",
                "factory_notify_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["email_notify_decl"]),
            ),
            ClickCase::new(
                "trait method imported by use resolves through using class",
                "mail_record_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["trait_record_decl"]),
            ),
            ClickCase::new(
                "in-class trait method call resolves to trait method",
                "this_record_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["trait_record_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name concrete method resolves to unrelated declaration",
                "other_notify_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_notify_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name trait-like method resolves to unrelated declaration",
                "other_record_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_record_decl"]),
            ),
            ClickCase::new(
                "interface method references include implementations and typed concrete calls",
                "interface_notify_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&[
                    "email_notify_decl",
                    "interface_notify_call",
                    "mail_notify_call",
                    "factory_notify_call",
                ]),
            ),
            ClickCase::new(
                "trait method references include using class calls only",
                "trait_record_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["this_record_call", "mail_record_call"]),
            ),
            ClickCase::new(
                "interface method implementation finds concrete method",
                "interface_notify_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["email_notify_decl"]),
            ),
            ClickCase::new(
                "interface type implementation finds implementing class",
                "notifier_interface_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["email_notifier_decl"]),
            ),
        ],
    );

    assert_timing_summary("milestone_3_php_interface_traits", &timings, 11);
}

#[test]
fn milestone_4_scala_extension_trait_click_around() {
    let fixture = ClickFixture::new("milestone_4_scala_extensions_traits")
        .file(
            "src/main/scala/support/Helpers.scala",
            r#"package support

def <helper_decl>helper(): Int = 1
"#,
        )
        .file(
            "src/main/scala/other/Helpers.scala",
            r#"package other

def <other_helper_decl>helper(): Int = 2
"#,
        )
        .file(
            "src/main/scala/example/Workflow.scala",
            r#"package example

import support.*

final case class User(<user_slug_decl>slug: String)

<logging_trait_range>trait <logging_trait_decl>Logging:
  def <logging_info_decl>info(msg: String): Unit = ()

trait Primary:
  def <primary_id_decl>id: String = "primary"

trait Secondary:
  def <secondary_id_decl>id: String = "secondary"

<service_range>class <service_decl>Service extends Logging

class OtherService:
  def <other_info_decl>info(msg: String): Unit = ()

class ConflictService extends Primary with Secondary

object Syntax:
  extension (value: String)
    def <string_slug_decl>slug: String = value.toLowerCase

object Workflow:
  import Syntax.*

  def <local_helper_decl>localHelper(): Int = 3

  def run(service: Service, other: OtherService, conflict: ConflictService, user: User, i: Int): Unit =
    val fromWildcard = <helper_call>helper()
    val local = <local_helper_call>localHelper()
    service.<service_info_call>info("started")
    other.<other_info_call>info("ignored")
    val extensionSlug = "Hello World".<string_slug_call>slug
    val directSlug = user.<direct_slug_call>slug
    val receiverMismatch = i.<mismatch_slug_call>slug
    val ambiguous = conflict.<ambiguous_id_call>id
"#,
        )
        .file(
            "src/main/scala/example/AmbiguousImports.scala",
            r#"package example

import support.*
import other.*

object AmbiguousImports:
  val value = <ambiguous_helper_call>helper()
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "wildcard imported helper resolves to top-level function",
                "helper_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["helper_decl"]),
            ),
            ClickCase::new(
                "enclosing member takes precedence over wildcard import",
                "local_helper_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["local_helper_decl"]),
            ),
            ClickCase::new(
                "ambiguous wildcard imported helper returns empty definition",
                "ambiguous_helper_call",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "same-package relative wildcard import exposes extension method",
                "string_slug_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["string_slug_decl"]),
            ),
            ClickCase::new(
                "direct member takes precedence over imported extension method",
                "direct_slug_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["user_slug_decl"]),
            ),
            ClickCase::new(
                "receiver mismatch does not select visible extension method",
                "mismatch_slug_call",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "conflicting inherited trait members return empty definition",
                "ambiguous_id_call",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "trait default method resolves through inherited receiver",
                "service_info_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["logging_info_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated declaration",
                "other_info_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_info_decl"]),
            ),
            ClickCase::new(
                "extension method references include only matching string receiver",
                "string_slug_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["string_slug_call"]),
            ),
            ClickCase::new(
                "trait default references include inherited receiver call only",
                "logging_info_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["service_info_call"]),
            ),
            ClickCase::new(
                "wildcard imported helper references include helper call",
                "helper_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["helper_call"]),
            ),
            ClickCase::new(
                "trait type implementation finds extending class",
                "logging_trait_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["service_decl"]),
            ),
            ClickCase::new(
                "service supertypes include logging trait",
                "service_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["logging_trait_range"]),
            ),
            ClickCase::new(
                "logging trait subtypes include service",
                "logging_trait_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["service_range"]),
            ),
        ],
    );

    assert_timing_summary("milestone_4_scala_extensions_traits", &timings, 15);
}
