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
fn declaration_and_definition_navigation_contracts() {
    let fixture = ClickFixture::new("declaration_definition_navigation")
        .file(
            "Runner.java",
            r#"interface Runner { void <java_interface>run(); }
class LocalRunner implements Runner { public void run() {} }
class App { void invoke(Runner runner) { runner.<java_call>run(); } }
"#,
        )
        .file(
            "service.h",
            "namespace ns { class Service { public: void <cpp_declaration>run(); }; }\n",
        )
        .file(
            "service.cpp",
            "#include \"service.h\"\nnamespace ns { void Service::<cpp_definition>run() {} }\n",
        )
        .file(
            "app.cpp",
            "#include \"service.h\"\nvoid invoke(ns::Service& service) { service.<cpp_call>run(); }\n",
        )
        .file(
            "same_file.cpp",
            "void <cpp_same_declaration>local();\nvoid <cpp_same_definition>local() {}\nvoid invoke_local() { <cpp_same_call>local(); }\n",
        )
        .file("duplicate.h", "void duplicate();\n")
        .file(
            "duplicate_a.cpp",
            "#include \"duplicate.h\"\nvoid <cpp_duplicate_a>duplicate() {}\n",
        )
        .file(
            "duplicate_b.cpp",
            "#include \"duplicate.h\"\nvoid <cpp_duplicate_b>duplicate() {}\n",
        )
        .file(
            "duplicate_app.cpp",
            "#include \"duplicate.h\"\nvoid invoke_duplicate() { <cpp_duplicate_call>duplicate(); }\n",
        )
        .file(
            "lib.rs",
            r#"trait RustRunner { type <rust_trait>Output; }
struct LocalRustRunner;
impl RustRunner for LocalRustRunner { type <rust_impl>Output = String; }
type Selected = <LocalRustRunner as RustRunner>::<rust_qualified>Output;
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "java declaration uses interface contract",
                "java_call",
                ClickOperation::Declaration,
                ClickExpectation::Locations(&["java_interface"]),
            ),
            ClickCase::new(
                "cpp declaration uses header prototype",
                "cpp_call",
                ClickOperation::Declaration,
                ClickExpectation::Locations(&["cpp_declaration"]),
            ),
            ClickCase::new(
                "cpp definition uses source body",
                "cpp_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["cpp_definition"]),
            ),
            ClickCase::new(
                "cpp same-file declaration uses prototype range",
                "cpp_same_call",
                ClickOperation::Declaration,
                ClickExpectation::Locations(&["cpp_same_declaration"]),
            ),
            ClickCase::new(
                "cpp same-file definition uses body range",
                "cpp_same_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["cpp_same_definition"]),
            ),
            ClickCase::new(
                "cpp same-file prototype navigates to body",
                "cpp_same_declaration",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["cpp_same_definition"]),
            ),
            ClickCase::new(
                "cpp prototype is not its own definition",
                "cpp_declaration",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "cpp ambiguous definitions return every body",
                "cpp_duplicate_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["cpp_duplicate_a", "cpp_duplicate_b"]),
            ),
            ClickCase::new(
                "rust impl associated type declaration uses trait",
                "rust_impl",
                ClickOperation::Declaration,
                ClickExpectation::Locations(&["rust_trait"]),
            ),
            ClickCase::new(
                "rust impl associated type definition stays on itself",
                "rust_impl",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["rust_impl"]),
            ),
            ClickCase::new(
                "rust qualified associated type definition uses concrete impl",
                "rust_qualified",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["rust_impl"]),
            ),
        ],
    );

    assert_timing_summary("declaration_definition_navigation", &timings, 11);
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
                "conflicting inherited trait members return all definitions",
                "ambiguous_id_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["primary_id_decl", "secondary_id_decl"]),
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

#[test]
fn milestone_5_java_interfaces_hierarchy_click_around() {
    let fixture = ClickFixture::new("milestone_5_java_interfaces_hierarchy")
        .file(
            "src/main/java/api/Task.java",
            r#"package api;

<task_iface_range>public interface <task_iface_decl>Task {
    void <task_run_decl>run();
}
"#,
        )
        .file(
            "src/main/java/api/BaseTask.java",
            r#"package api;

<base_task_range>public class <base_task_decl>BaseTask {
    public void <base_run_decl>run() {}
}
"#,
        )
        .file(
            "src/main/java/impl/EmailTask.java",
            r#"package impl;

import api.BaseTask;
import api.Task;

<email_task_range>public class <email_task_decl>EmailTask extends BaseTask implements Task {
    public <email_ctor_decl>EmailTask>() {}

    @Override
    public void <email_run_decl>run() {}

    public static class <nested_decl>Nested {}
}
"#,
        )
        .file(
            "src/main/java/other/OtherTask.java",
            r#"package other;

public class OtherTask {
    public void <other_run_decl>run() {}
}
"#,
        )
        .file(
            "src/main/java/app/Workflow.java",
            r#"package app;

import api.BaseTask;
import api.Task;
import ambiguous.one.*;
import impl.EmailTask;
import other.OtherTask;

public class Workflow {
    void run(Task task, EmailTask email, BaseTask base, OtherTask other) {
        task.<task_run_call>run();
        email.<email_run_call>run();
        base.<base_run_call>run();
        other.<other_run_call>run();

        EmailTask constructed = new <constructor_call>EmailTask();
        EmailTask.<nested_type_use>Nested nested = new EmailTask.Nested();
        <single_wildcard_type_use>Ambiguous imported = null;
    }
}
"#,
        )
        .file(
            "src/main/java/ambiguous/one/Ambiguous.java",
            r#"package ambiguous.one;

public class <ambiguous_one_decl>Ambiguous {}
"#,
        )
        .file(
            "src/main/java/ambiguous/two/Ambiguous.java",
            r#"package ambiguous.two;

public class <ambiguous_two_decl>Ambiguous {}
"#,
        )
        .file(
            "src/main/java/app/AmbiguousImports.java",
            r#"package app;

import ambiguous.one.*;
import ambiguous.two.*;

class AmbiguousImports {
    <ambiguous_type_use>Ambiguous value;
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "interface-typed call resolves to interface method",
                "task_run_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["task_run_decl"]),
            ),
            ClickCase::new(
                "concrete receiver call resolves to override",
                "email_run_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["email_run_decl"]),
            ),
            ClickCase::new(
                "base receiver call resolves to base method",
                "base_run_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_run_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated declaration",
                "other_run_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_run_decl"]),
            ),
            ClickCase::new(
                "constructor call resolves to explicit constructor",
                "constructor_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["email_ctor_decl"]),
            ),
            ClickCase::new(
                "nested type reference resolves to nested class",
                "nested_type_use",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["nested_decl"]),
            ),
            ClickCase::new(
                "ambiguous wildcard imported type returns empty definition",
                "ambiguous_type_use",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "single wildcard imported type resolves to imported class",
                "single_wildcard_type_use",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["ambiguous_one_decl"]),
            ),
            ClickCase::new(
                "interface method references exclude concrete override calls",
                "task_run_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["email_run_decl", "task_run_call"]),
            ),
            ClickCase::new(
                "interface method implementation finds override",
                "task_run_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["email_run_decl"]),
            ),
            ClickCase::new(
                "base method implementation finds inherited override",
                "base_run_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["email_run_decl"]),
            ),
            ClickCase::new(
                "interface type implementation finds implementing class",
                "task_iface_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["email_task_decl"]),
            ),
            ClickCase::new(
                "EmailTask supertypes include base class and interface",
                "email_task_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["task_iface_range", "base_task_range"]),
            ),
            ClickCase::new(
                "Task subtypes include EmailTask",
                "task_iface_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["email_task_range"]),
            ),
        ],
    );

    assert_timing_summary("milestone_5_java_interfaces_hierarchy", &timings, 14);
}

#[test]
fn milestone_6_csharp_partial_interface_click_around() {
    let fixture = ClickFixture::new("milestone_6_csharp_partial_interfaces")
        .file(
            "Contracts/IHandler.cs",
            r#"namespace Contracts;

<handler_iface_range>public interface <handler_iface_decl>IHandler
{
    void <interface_handle_decl>Handle(string message);
}
"#,
        )
        .file(
            "Domain/BaseHandler.cs",
            r#"namespace Domain;

<base_handler_range>public class <base_handler_decl>BaseHandler
{
    public virtual void <base_reset_decl>Reset() {}
}
"#,
        )
        .file(
            "Domain/ConsoleHandler.cs",
            r#"using Contracts;

namespace Domain;

<console_handler_range>public class <console_handler_decl>ConsoleHandler : BaseHandler, IHandler
{
    public void <console_handle_decl>Handle(string message) {}

    public override void <console_reset_decl>Reset() {}
}
"#,
        )
        .file(
            "Domain/OtherHandler.cs",
            r#"namespace Domain;

public class OtherHandler
{
    public void <other_handle_decl>Handle(string message) {}
    public void <other_reset_decl>Reset() {}
}
"#,
        )
        .file(
            "Domain/EventRecord.Part1.cs",
            r#"namespace Domain;

public partial class <event_record_range><event_record_decl>EventRecord
{
    public string <event_name_decl>Name { get; set; }
}
"#,
        )
        .file(
            "Domain/EventRecord.Part2.cs",
            r#"namespace Domain;

public partial class <event_record_part2_decl>EventRecord
{
    public void Rename(string value)
    {
        <self_name_write>Name = value;
    }
}
"#,
        )
        .file(
            "App/Workflow.cs",
            r#"using Contracts;
using Domain;

namespace App;

public class Workflow
{
    public void Run(IHandler handler, ConsoleHandler console, BaseHandler baseHandler, OtherHandler other)
    {
        handler.<interface_handle_call>Handle("via interface");
        console.<console_handle_call>Handle("via concrete");
        baseHandler.<base_reset_call>Reset();
        console.<console_reset_call>Reset();
        other.<other_handle_call>Handle("unrelated");
        other.<other_reset_call>Reset();

        EventRecord <record_local>record = new EventRecord { <initializer_name_label>Name = "created" };
        var copy = record.<record_name_read>Name;
    }
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "interface-typed receiver resolves to interface method",
                "interface_handle_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["interface_handle_decl"]),
            ),
            ClickCase::new(
                "concrete receiver resolves to implementation method",
                "console_handle_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["console_handle_decl"]),
            ),
            ClickCase::new(
                "base receiver resolves to base virtual method",
                "base_reset_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_reset_decl"]),
            ),
            ClickCase::new(
                "derived receiver resolves to override method",
                "console_reset_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["console_reset_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated declaration",
                "other_handle_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_handle_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name inherited method resolves to unrelated declaration",
                "other_reset_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_reset_decl"]),
            ),
            ClickCase::new(
                "object initializer label resolves to partial property",
                "initializer_name_label",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["event_name_decl"]),
            ),
            ClickCase::new(
                "partial self property write resolves to property declaration",
                "self_name_write",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["event_name_decl"]),
            ),
            ClickCase::new(
                "typed receiver property read resolves to partial property",
                "record_name_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["event_name_decl"]),
            ),
            ClickCase::new(
                "record local type definition resolves to EventRecord",
                "record_local",
                ClickOperation::TypeDefinition,
                ClickExpectation::Locations(&["event_record_decl", "event_record_part2_decl"]),
            ),
            ClickCase::new(
                "interface method references include interface-typed call",
                "interface_handle_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["interface_handle_call"]),
            ),
            ClickCase::new(
                "partial property references include initializer and reads",
                "event_name_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&[
                    "self_name_write",
                    "initializer_name_label",
                    "record_name_read",
                ]),
            ),
            ClickCase::new(
                "interface method implementation finds concrete implementation",
                "interface_handle_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["console_handle_decl"]),
            ),
            ClickCase::new(
                "base method implementation finds inherited override",
                "base_reset_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["console_reset_decl"]),
            ),
            ClickCase::new(
                "interface type implementation finds implementing class",
                "handler_iface_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["console_handler_decl"]),
            ),
            ClickCase::new(
                "ConsoleHandler supertypes include base class and interface",
                "console_handler_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["base_handler_range", "handler_iface_range"]),
            ),
            ClickCase::new(
                "IHandler subtypes include ConsoleHandler",
                "handler_iface_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["console_handler_range"]),
            ),
        ],
    );

    assert_timing_summary("milestone_6_csharp_partial_interfaces", &timings, 17);
}

#[test]
fn milestone_7_cpp_typed_receivers_out_of_line_click_around() {
    let fixture = ClickFixture::new("milestone_7_cpp_typed_receivers")
        .file(
            "include/model.h",
            r#"#pragma once

namespace core {

struct Base {
    int <base_id_decl>id;
    void <base_tick_decl>tick();
};

struct Derived : Base {
    int <derived_id_decl>id;
    void <derived_tick_decl>tick();
    void <derived_helper_decl>helper();
};

struct Other {
    int <other_id_decl>id;
    void <other_tick_decl>tick();
};

Derived <make_derived_decl>makeDerived();

}
"#,
        )
        .file(
            "src/model.cpp",
            r#"#include "model.h"

namespace core {

void <base_tick_out_of_line_ref>Base::<base_tick_def>tick() {}

void <derived_tick_out_of_line_ref>Derived::<derived_tick_def>tick() {}

void Derived::<derived_helper_def>helper() {
    <bare_id_in_member>id = 1;
}

void Other::<other_tick_def>tick() {}

Derived <make_derived_def>makeDerived() { return Derived{}; }

}
"#,
        )
        .file(
            "src/app.cpp",
            r#"#include "model.h"

using core::Base;
using core::Derived;
using core::Other;

void run() {
    Derived d;
    d.<derived_tick_call>tick();
    d.<derived_id_read>id = 2;

    Base b;
    b.<base_tick_call>tick();
    b.<base_id_read>id = 3;

    Base* bp = &d;
    bp-><base_ptr_tick_call>tick();

    Other other;
    other.<other_tick_call>tick();
    other.<other_id_read>id = 4;

    Derived made = <make_derived_qualified_call>core::<make_derived_call>makeDerived();
    made.<made_tick_call>tick();

    int id = 0;
    <local_id_read>id++;
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "derived receiver resolves to out-of-line method",
                "derived_tick_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["derived_tick_def"]),
            ),
            ClickCase::new(
                "base receiver resolves to base out-of-line method",
                "base_tick_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_tick_def"]),
            ),
            ClickCase::new(
                "base pointer receiver resolves to base method",
                "base_ptr_tick_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_tick_def"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated owner",
                "other_tick_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_tick_def"]),
            ),
            ClickCase::new(
                "derived field shadows base field for derived receiver",
                "derived_id_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["derived_id_decl"]),
            ),
            ClickCase::new(
                "base field remains available for base receiver",
                "base_id_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_id_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name field resolves to unrelated owner",
                "other_id_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_id_decl"]),
            ),
            ClickCase::new(
                "bare member field in out-of-line method resolves to class field",
                "bare_id_in_member",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["derived_id_decl"]),
            ),
            ClickCase::new(
                "factory call resolves to out-of-line free function",
                "make_derived_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["make_derived_def"]),
            ),
            ClickCase::new(
                "typed factory result receiver resolves to derived method",
                "made_tick_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["derived_tick_def"]),
            ),
            ClickCase::new(
                "free function declaration references call site",
                "make_derived_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["make_derived_call", "make_derived_def"]),
            ),
            ClickCase::new(
                "derived method declaration references out-of-line definition and typed calls",
                "derived_tick_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&[
                    "derived_tick_out_of_line_ref",
                    "derived_tick_call",
                    "made_tick_call",
                ]),
            ),
            ClickCase::new(
                "base method declaration references out-of-line definition and base-typed calls",
                "base_tick_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&[
                    "base_tick_out_of_line_ref",
                    "base_tick_call",
                    "base_ptr_tick_call",
                ]),
            ),
            ClickCase::new(
                "local value shadow does not resolve as member field",
                "local_id_read",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
        ],
    );

    assert_timing_summary("milestone_7_cpp_typed_receivers", &timings, 14);
}

#[test]
fn milestone_8_javascript_commonjs_object_click_around() {
    let fixture = ClickFixture::new("milestone_8_javascript_commonjs_objects")
        .file(
            "lib.js",
            r#"class <widget_decl>Widget {
  constructor(name) {
    this.<widget_label_decl>label = name;
  }

  <widget_render_decl>render() {
    return this.<this_label_read>label;
  }
}

function <make_widget_decl>makeWidget() {
  return new Widget("factory");
}

function <make_toolbox_decl>makeToolbox() {
  return {
    <factory_format_decl>format(value) {
      return value.label;
    },
  };
}

const tools = {
  <tools_format_decl>format(value) {
    return value.label;
  },
  <tools_reset_decl>reset() {
    return "tools";
  },
};

const other = {
  <other_format_decl>format(value) {
    return value.label;
  },
};

module.exports = { Widget, makeWidget, makeToolbox, tools, other };
"#,
        )
        .file(
            "app.js",
            r#"const { Widget, makeWidget, makeToolbox, tools, other } = require("./lib");

function run(getUnknown) {
  const widget = new Widget("direct");
  widget.<widget_render_call>render();
  widget.<widget_label_read>label;

  const factoryWidget = <make_widget_call>makeWidget();
  factoryWidget.<factory_render_call>render();

  const toolbox = <make_toolbox_call>makeToolbox();
  toolbox.<factory_format_call>format(widget);

  tools.<tools_format_call>format(widget);
  other.<other_format_call>format(widget);

  const unknown = getUnknown();
  unknown.<unknown_format_call>format(widget);
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "class instance method resolves from constructed receiver",
                "widget_render_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["widget_render_decl"]),
            ),
            ClickCase::new(
                "class this field read resolves to constructor assignment",
                "this_label_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["widget_label_decl"]),
            ),
            ClickCase::new(
                "constructed receiver field read resolves to class field",
                "widget_label_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["widget_label_decl"]),
            ),
            ClickCase::new(
                "CommonJS imported factory resolves to exported function",
                "make_widget_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["make_widget_decl"]),
            ),
            ClickCase::new(
                "factory-returned object receiver resolves to class method",
                "factory_render_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["widget_render_decl"]),
            ),
            ClickCase::new(
                "factory-returned object literal method resolves to materialized method",
                "factory_format_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["factory_format_decl"]),
            ),
            ClickCase::new(
                "object literal method resolves through CommonJS import",
                "tools_format_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["tools_format_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name object method resolves to unrelated declaration",
                "other_format_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_format_decl"]),
            ),
            ClickCase::new(
                "unknown receiver same-name method stays unresolved",
                "unknown_format_call",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "class method references include constructed and factory receivers",
                "widget_render_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["widget_render_call", "factory_render_call"]),
            ),
            ClickCase::new(
                "class field references include this and constructed receiver reads",
                "widget_label_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["this_label_read", "widget_label_read"]),
            ),
            ClickCase::new(
                "object literal method references include imported call only",
                "tools_format_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["tools_format_call"]),
            ),
            ClickCase::new(
                "hover on class method call describes render",
                "widget_render_call",
                ClickOperation::Hover,
                ClickExpectation::HoverContains("render"),
            ),
            ClickCase::new(
                "JavaScript type definition is unsupported for values",
                "widget_render_call",
                ClickOperation::TypeDefinition,
                ClickExpectation::Empty,
            ),
        ],
    );

    assert_timing_summary("milestone_8_javascript_commonjs_objects", &timings, 14);
}

#[test]
fn milestone_9_typescript_interfaces_type_alias_click_around() {
    let fixture = ClickFixture::new("milestone_9_typescript_interfaces")
        .file(
            "contracts.ts",
            r#"<processor_iface_range>export interface <processor_iface_decl>Processor {
  <interface_process_decl>process(input: Payload): Result;
}

export interface Result {
  <result_status_decl>status: string;
}

export type <payload_alias_decl>Payload = {
  <payload_value_decl>value: string;
  meta: {
    <payload_tag_decl>tag: string;
  };
};
"#,
        )
        .file(
            "service.ts",
            r#"import { Processor, Payload, Result } from "./contracts";

<file_processor_range>export class <file_processor_decl>FileProcessor implements Processor {
  <create_static_range>static <create_static_decl>create(): FileProcessor {
    return new FileProcessor();
  }

  <file_process_decl>process(input: Payload): Result {
    return { <result_status_key>status: input.<input_value_read>value };
  }
}

export class <other_processor_decl>OtherProcessor {
  <other_process_decl>process(input: Payload): Result {
    return { status: input.<other_input_value_read>value };
  }
}

export function consumeContext(handler: (payload: Payload) => void): void {
  handler({ value: "callback", meta: { tag: "ctx" } });
}
"#,
        )
        .file(
            "app.ts",
            r#"import { Processor, Payload } from "./contracts";
import { FileProcessor, OtherProcessor, consumeContext } from "./service";

function run(): void {
  const <processor_local>processor: Processor = new FileProcessor();
  processor.<interface_process_call>process({ value: "typed", meta: { tag: "typed" } });

  const concrete: FileProcessor = FileProcessor.<create_static_call>create();
  concrete.<concrete_process_call>process({ value: "factory", meta: { tag: "factory" } });

  const other = new OtherProcessor();
  other.<other_process_call>process({ value: "other", meta: { tag: "other" } });

  const payload: Payload = { <contextual_value_key>value: "object", meta: { tag: "object" } };
  payload.<payload_value_read>value;

  consumeContext((payload) => {
    payload.<callback_value_read>value;
  });
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "interface typed receiver resolves to interface method",
                "interface_process_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["interface_process_decl"]),
            ),
            ClickCase::new(
                "concrete receiver resolves to implementation method",
                "concrete_process_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["file_process_decl"]),
            ),
            ClickCase::new(
                "static class member resolves to static declaration",
                "create_static_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["create_static_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated declaration",
                "other_process_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_process_decl"]),
            ),
            ClickCase::new(
                "typed parameter property read resolves to type alias member",
                "input_value_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["payload_value_decl"]),
            ),
            ClickCase::new(
                "typed local property read resolves to type alias member",
                "payload_value_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["payload_value_decl"]),
            ),
            ClickCase::new(
                "contextual object value key resolves to type alias member",
                "contextual_value_key",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["payload_value_decl"]),
            ),
            ClickCase::new(
                "contextual callback parameter member resolves to alias member",
                "callback_value_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["payload_value_decl"]),
            ),
            ClickCase::new(
                "type alias member references include typed and contextual reads",
                "payload_value_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::LocationsAllowing(
                    &[
                        "input_value_read",
                        "contextual_value_key",
                        "payload_value_read",
                        "other_input_value_read",
                    ],
                    &["callback_value_read"],
                ),
            ),
            ClickCase::new(
                "interface method references include interface-typed call",
                "interface_process_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["interface_process_call"]),
            ),
            ClickCase::new(
                "interface method implementation finds concrete method",
                "interface_process_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["file_process_decl"]),
            ),
            ClickCase::new(
                "interface type implementation finds implementing class",
                "processor_iface_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&["file_processor_decl"]),
            ),
            ClickCase::new(
                "typed local type definition resolves to interface",
                "processor_local",
                ClickOperation::TypeDefinition,
                ClickExpectation::Locations(&["processor_iface_decl"]),
            ),
            ClickCase::new(
                "FileProcessor supertypes include Processor",
                "file_processor_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["processor_iface_range"]),
            ),
            ClickCase::new(
                "Processor subtypes include FileProcessor",
                "processor_iface_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["file_processor_range"]),
            ),
        ],
    );

    assert_timing_summary("milestone_9_typescript_interfaces", &timings, 15);
}

#[test]
fn milestone_10_python_alias_property_click_around() {
    let fixture = ClickFixture::new("milestone_10_python_alias_property")
        .file(
            "shop/models.py",
            r#"<base_user_range>class <base_user_decl>BaseUser:
    def <base_label_decl>label(self):
        return "base"

<user_range>class <user_class_decl>User(BaseUser):
    def __init__(self, name):
        self.<name_attr_decl>name = name

    @property
    def <normalized_name_decl>normalized_name(self):
        return self.<self_name_read>name.lower()

    @classmethod
    def <guest_decl>guest(cls) -> "User":
        return cls("guest")

class <other_user_decl>OtherUser:
    def <other_label_decl>label(self):
        return "other"
"#,
        )
        .file(
            "shop/__init__.py",
            r#"from .models import User as Account
"#,
        )
        .file(
            "app.py",
            r#"from shop import Account
from shop.models import User, OtherUser

def handle(user: User):
    user.<typed_label_call>label()
    user.<typed_property_read>normalized_name

def run():
    account = <account_class_ref>Account.<guest_call>guest()
    account.<alias_label_call>label()
    account.<alias_property_read>normalized_name

    other = OtherUser()
    other.<other_label_call>label()

def unknown(thing):
    thing.<unknown_label_call>label()
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "reexported class alias resolves to original class",
                "account_class_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["user_class_decl"]),
            ),
            ClickCase::new(
                "classmethod factory resolves through reexported class alias",
                "guest_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["guest_decl"]),
            ),
            ClickCase::new(
                "typed receiver resolves inherited method to base declaration",
                "typed_label_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_label_decl"]),
            ),
            ClickCase::new(
                "factory receiver resolves inherited method to base declaration",
                "alias_label_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["base_label_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated class",
                "other_label_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_label_decl"]),
            ),
            ClickCase::new(
                "decorated property read on typed receiver resolves to getter",
                "typed_property_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["normalized_name_decl"]),
            ),
            ClickCase::new(
                "decorated property read on factory receiver resolves to getter",
                "alias_property_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["normalized_name_decl"]),
            ),
            ClickCase::new(
                "self attribute read resolves to initializer assignment",
                "self_name_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["name_attr_decl"]),
            ),
            ClickCase::new(
                "untyped receiver does not guess same-name method",
                "unknown_label_call",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "classmethod references include reexported alias call",
                "guest_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["guest_call"]),
            ),
            ClickCase::new(
                "inherited method references include typed and factory receiver calls",
                "base_label_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["typed_label_call", "alias_label_call"]),
            ),
            ClickCase::new(
                "decorated property references include typed and factory receiver reads",
                "normalized_name_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["typed_property_read", "alias_property_read"]),
            ),
            ClickCase::new(
                "hover on decorated property read describes normalized_name",
                "alias_property_read",
                ClickOperation::Hover,
                ClickExpectation::HoverContains("normalized_name"),
            ),
            ClickCase::new(
                "User supertypes include BaseUser",
                "user_class_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["base_user_range"]),
            ),
            ClickCase::new(
                "BaseUser subtypes include User",
                "base_user_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["user_range"]),
            ),
        ],
    );

    assert_timing_summary("milestone_10_python_alias_property", &timings, 15);
}

#[test]
fn milestone_11_ruby_constants_mixins_click_around() {
    let fixture = ClickFixture::new("milestone_11_ruby_constants_mixins")
        .file(
            "lib/billing/invoice.rb",
            r#"module Billing
  module Auditable
    def <auditable_audit_decl>audit
    end
  end

  module Formatting
    module_function

    def <format_total_decl>format_total(value)
      value.to_s
    end
  end

  <record_range>class <record_decl>Record
    def <record_save_decl>save
    end
  end

  <invoice_range>class <invoice_decl>Invoice < Record
    include Auditable

    <currency_decl>DEFAULT_CURRENCY = "USD"

    def self.<build_decl>build
      @last_build = Invoice.new
    end
  end

  class <other_invoice_decl>OtherInvoice
    def <other_audit_decl>audit
    end
  end
end
"#,
        )
        .file(
            "app/report.rb",
            r#"require_relative "../lib/billing/invoice"

module Reports
  class InvoiceReport
    def render
      Billing::Invoice::<currency_ref>DEFAULT_CURRENCY
      invoice = Billing::Invoice.<build_call>build
      invoice.<audit_call>audit
      invoice.<save_call>save
      Billing::Formatting.<format_call>format_total(10)

      other = Billing::OtherInvoice.new
      other.<other_audit_call>audit
      unknown.<unknown_audit_call>audit
    end
  end
end
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "namespaced class constant resolves to constant assignment",
                "currency_ref",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["currency_decl"]),
            ),
            ClickCase::new(
                "constructed receiver factory resolves class method",
                "build_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["build_decl"]),
            ),
            ClickCase::new(
                "constructed receiver resolves included mixin method",
                "audit_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["auditable_audit_decl"]),
            ),
            ClickCase::new(
                "constructed receiver resolves inherited method",
                "save_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["record_save_decl"]),
            ),
            ClickCase::new(
                "module function call resolves to module method",
                "format_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["format_total_decl"]),
            ),
            ClickCase::new(
                "unrelated same-name method resolves to unrelated owner",
                "other_audit_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["other_audit_decl"]),
            ),
            ClickCase::new(
                "unknown receiver does not guess same-name method",
                "unknown_audit_call",
                ClickOperation::Definition,
                ClickExpectation::Empty,
            ),
            ClickCase::new(
                "constant references include namespaced constant use",
                "currency_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["currency_ref"]),
            ),
            ClickCase::new(
                "class method references include factory call",
                "build_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["build_call"]),
            ),
            ClickCase::new(
                "mixin method references include constructed receiver call",
                "auditable_audit_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["audit_call"]),
            ),
            ClickCase::new(
                "inherited method references include constructed receiver call",
                "record_save_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["save_call"]),
            ),
            ClickCase::new(
                "module function references include qualified module call",
                "format_total_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["format_call"]),
            ),
            ClickCase::new(
                "Invoice supertypes include Record",
                "invoice_decl",
                ClickOperation::TypeHierarchySupertypes,
                ClickExpectation::Locations(&["record_range"]),
            ),
            ClickCase::new(
                "Record subtypes include Invoice",
                "record_decl",
                ClickOperation::TypeHierarchySubtypes,
                ClickExpectation::Locations(&["invoice_range"]),
            ),
        ],
    );

    assert_timing_summary("milestone_11_ruby_constants_mixins", &timings, 14);
}

#[test]
#[ignore = "stress: generated 24-layer Go embedding navigation; run explicitly with cargo test --test lsp_click_around_regression -- --ignored"]
fn stress_milestone_12_go_embedded_promotion_click_around() {
    let mut service = String::from(
        r#"package service

type Base struct {
    <stress_base_id_decl>ID string
}

"#,
    );
    for index in 0..24 {
        let embedded = if index == 0 {
            "Base".to_string()
        } else {
            format!("Layer{}", index - 1)
        };
        service.push_str(&format!(
            "type Layer{index} struct {{\n    {embedded}\n}}\n\n"
        ));
    }
    service.push_str(
        r#"type Worker struct {
    Layer23
}

func NewWorker() Worker { return Worker{} }
"#,
    );

    let fixture = ClickFixture::new("stress_milestone_12_go_embedded_promotion")
        .file("go.mod", "module example.com/stress\n\ngo 1.22\n")
        .file("service/service.go", service)
        .file(
            "main.go",
            r#"package main

import "example.com/stress/service"

func use() {
    worker := service.NewWorker()
    _ = worker.<stress_worker_id_read>ID
}
"#,
        );

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "deep promoted field resolves through generated embedding chain",
                "stress_worker_id_read",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["stress_base_id_decl"]),
            ),
            ClickCase::new(
                "deep promoted field references include generated call site",
                "stress_base_id_decl",
                ClickOperation::References {
                    include_declaration: false,
                },
                ClickExpectation::Locations(&["stress_worker_id_read"]),
            ),
        ],
    );

    assert_timing_summary("stress_milestone_12_go_embedded_promotion", &timings, 2);
}

#[test]
#[ignore = "stress: generated 16-type Rust trait-implementation navigation; run explicitly with cargo test --test lsp_click_around_regression -- --ignored"]
fn stress_milestone_12_rust_trait_impl_click_around() {
    let mut service = String::from("use crate::contracts::Worker;\n\n");
    let mut client_imports = Vec::new();
    let mut client_body = String::from("use crate::contracts::Worker;\nuse crate::service::{");
    let mut impl_marker_names = Vec::new();
    let mut type_decl_marker_names = Vec::new();

    for index in 0..16 {
        client_imports.push(format!("Job{index}"));
        impl_marker_names.push(format!("stress_job_{index}_work_impl"));
        type_decl_marker_names.push(format!("stress_job_{index}_decl"));
    }
    client_body.push_str(&client_imports.join(", "));
    client_body.push_str("};\n\npub fn run() {\n");

    for index in 0..16 {
        service.push_str(&format!(
            r#"<stress_job_{index}_range>pub struct <stress_job_{index}_decl>Job{index};

impl Worker for Job{index} {{
    fn <stress_job_{index}_work_impl>work(&self) -> usize {{
        {index}
    }}
}}

"#
        ));
        client_body.push_str(&format!(
            "    let job_{index}: Job{index} = Job{index};\n    let _ = job_{index}.<stress_job_{index}_work_call>work();\n"
        ));
    }
    client_body.push_str("}\n");

    let impl_marker_refs: Vec<&str> = impl_marker_names.iter().map(String::as_str).collect();
    let type_decl_marker_refs: Vec<&str> =
        type_decl_marker_names.iter().map(String::as_str).collect();

    let fixture = ClickFixture::new("stress_milestone_12_rust_trait_impls")
        .file(
            "Cargo.toml",
            "[package]\nname = \"stress_click_rust\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "pub mod contracts;\npub mod service;\npub mod client;\n",
        )
        .file(
            "src/contracts.rs",
            r#"<stress_worker_trait_range>pub trait <stress_worker_trait_decl>Worker {
    fn <stress_worker_work_decl>work(&self) -> usize;
}
"#,
        )
        .file("src/service.rs", service)
        .file("src/client.rs", client_body);

    let timings = assert_click_cases(
        fixture,
        &[
            ClickCase::new(
                "generated typed receiver resolves to concrete impl method",
                "stress_job_0_work_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["stress_job_0_work_impl"]),
            ),
            ClickCase::new(
                "tail generated typed receiver resolves to concrete impl method",
                "stress_job_15_work_call",
                ClickOperation::Definition,
                ClickExpectation::Locations(&["stress_job_15_work_impl"]),
            ),
            ClickCase::new(
                "generated trait method implementation finds all impl methods",
                "stress_worker_work_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&impl_marker_refs),
            ),
            ClickCase::new(
                "generated trait type implementation finds all implementers",
                "stress_worker_trait_decl",
                ClickOperation::Implementation,
                ClickExpectation::Locations(&type_decl_marker_refs),
            ),
        ],
    );

    assert_timing_summary("stress_milestone_12_rust_trait_impls", &timings, 4);
}
