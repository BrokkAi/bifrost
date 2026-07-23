mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

#[derive(Clone, Copy)]
struct DirectAllocationCase {
    language: &'static str,
    path: &'static str,
    direct_source: &'static str,
    cap_source: &'static str,
    cap_extra_files: &'static [(&'static str, &'static str)],
    composition_source: &'static str,
    enclosing_kind: &'static str,
    enclosing_name: &'static str,
    member_name: &'static str,
    cap_operation: &'static str,
    expected_outcome: &'static str,
    expected_value_kind: &'static str,
    declaration_field: &'static str,
    expected_type_suffix: &'static str,
}

const NO_EXTRA_FILES: &[(&str, &str)] = &[];

fn run(
    case: DirectAllocationCase,
    source: &str,
    extra_files: &[(&str, &str)],
    query: Value,
) -> Value {
    let mut project = InlineTestProject::new().file(case.path, source);
    for (path, source) in extra_files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    serde_json::to_value(execute_workspace(&workspace, &query))
        .expect("query result should serialize")
}

fn direct_allocation_cases() -> [DirectAllocationCase; 7] {
    [
        DirectAllocationCase {
            language: "cpp",
            path: "receiver.cpp",
            direct_source: r#"
struct Service { void run() {} };
struct Other { void run() {} };

void direct() {
    Service* service = new Service();
    service->run();
}
"#,
            cap_source: r#"
struct Service { void run() {} };

void capped(int which) {
    Service* service;
    if (which == 0) {
        service = new Service();
    } else if (which == 1) {
        service = new Service();
    } else if (which == 2) {
        service = new Service();
    } else if (which == 3) {
        service = new Service();
    } else {
        service = new Service();
    }
    service->run();
}
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"
struct Service { void run() {} };
struct Other { void run() {} };

void consume(Service* value) {}

void composed() {
    consume(new Service());
}
"#,
            enclosing_kind: "function",
            enclosing_name: "direct",
            member_name: "run",
            cap_operation: "points_to",
            expected_outcome: "precise",
            expected_value_kind: "allocation_site",
            declaration_field: "type_declaration",
            expected_type_suffix: "Service",
        },
        DirectAllocationCase {
            language: "go",
            path: "receiver.go",
            direct_source: r#"package receiver

type Service struct{}
func (Service) Run() {}

type Other struct{}
func (Other) Run() {}

func direct() {
    service := Service{}
    service.Run()
}
"#,
            cap_source: r#"package receiver

type A struct{}
func (A) Run() {}
type B struct{}
func (B) Run() {}
type C struct{}
func (C) Run() {}
type D struct{}
func (D) Run() {}
type E struct{}
func (E) Run() {}

type Service struct {
    A
    B
    C
    D
    E
}

func capped(service Service) {
    service.Run()
}
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"package receiver

type Service struct{}
func (Service) Run() {}
type Other struct{}
func (Other) Run() {}
func consume(value Service) {}

func composed() {
    consume(Service{})
}
"#,
            enclosing_kind: "function",
            enclosing_name: "direct",
            member_name: "Run",
            cap_operation: "member_targets",
            expected_outcome: "precise",
            expected_value_kind: "allocation_site",
            declaration_field: "type_declaration",
            expected_type_suffix: "Service",
        },
        DirectAllocationCase {
            language: "php",
            path: "receiver.php",
            direct_source: r#"<?php
namespace Receiver;

class Service {
    public function run(): void {}
}

class Other {
    public function run(): void {}
}

function direct(): void {
    $service = new Service();
    $service->run();
}
"#,
            cap_source: r#"<?php
namespace Receiver;

class Service {
    public function run(): void {}
}

function capped(int $which): void {
    if ($which === 0) {
        $service = new Service();
    } elseif ($which === 1) {
        $service = new Service();
    } elseif ($which === 2) {
        $service = new Service();
    } elseif ($which === 3) {
        $service = new Service();
    } else {
        $service = new Service();
    }
    $service->run();
}
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"<?php
namespace Receiver;

class Service {
    public function run(): void {}
}
class Other {
    public function run(): void {}
}
function consume(Service $value): void {}

function composed(): void {
    consume(new Service());
}
"#,
            enclosing_kind: "function",
            enclosing_name: "direct",
            member_name: "run",
            cap_operation: "points_to",
            expected_outcome: "precise",
            expected_value_kind: "allocation_site",
            declaration_field: "type_declaration",
            expected_type_suffix: "Receiver.Service",
        },
        DirectAllocationCase {
            language: "python",
            path: "receiver.py",
            direct_source: r#"class Service:
    def run(self) -> None:
        pass

class Other:
    def run(self) -> None:
        pass

def direct() -> None:
    service = Service()
    service.run()
"#,
            cap_source: r#"class A:
    def run(self) -> None:
        pass
class B:
    def run(self) -> None:
        pass
class C:
    def run(self) -> None:
        pass
class D:
    def run(self) -> None:
        pass
class E:
    def run(self) -> None:
        pass

def capped(which: int) -> None:
    if which == 0:
        service = A()
    elif which == 1:
        service = B()
    elif which == 2:
        service = C()
    elif which == 3:
        service = D()
    else:
        service = E()
    service.run()
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"class Service:
    def run(self) -> None:
        pass

class Other:
    def run(self) -> None:
        pass

def consume(value: Service) -> None:
    pass

def composed() -> None:
    consume(Service())
"#,
            enclosing_kind: "function",
            enclosing_name: "direct",
            member_name: "run",
            // Public Python receiver queries expose no receiver-budget override.
            // Its five-way structured flow exhausts scope_nodes before max_targets,
            // while same-FQN declarations collapse and conditional values stay open.
            cap_operation: "",
            expected_outcome: "ambiguous",
            expected_value_kind: "instance_type",
            declaration_field: "declaration",
            expected_type_suffix: "Service",
        },
        DirectAllocationCase {
            language: "ruby",
            path: "receiver.rb",
            direct_source: r#"class Service
  def run
  end
end

class Other
  def run
  end
end

def direct
  service = Service.new
  service.run
end
"#,
            cap_source: r#"class Service
  def run
  end
end

def capped(which)
  service = Service.new
  if which == 0
    service = Service.new
  elsif which == 1
    service = Service.new
  elsif which == 2
    service = Service.new
  elsif which == 3
    service = Service.new
  else
    service = Service.new
  end
  service.run
end
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"class Service
  def run
  end
end

class Other
  def run
  end
end

def consume(value)
end

def composed
  consume(Service.new)
end
"#,
            enclosing_kind: "function",
            enclosing_name: "direct",
            member_name: "run",
            cap_operation: "points_to",
            expected_outcome: "precise",
            expected_value_kind: "allocation_site",
            declaration_field: "type_declaration",
            expected_type_suffix: "Service",
        },
        DirectAllocationCase {
            language: "rust",
            path: "receiver.rs",
            direct_source: r#"struct Service;
impl Service {
    fn run(&self) {}
}

struct Other;
impl Other {
    fn run(&self) {}
}

fn direct() {
    let service = Service {};
    service.run();
}
"#,
            cap_source: r#"struct Service;
impl Service {
    fn run(&self) {}
}

fn capped(which: i32) {
    let service: Service;
    if which == 0 {
        service = Service {};
    } else if which == 1 {
        service = Service {};
    } else if which == 2 {
        service = Service {};
    } else if which == 3 {
        service = Service {};
    } else {
        service = Service {};
    }
    service.run();
}
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"struct Service;
impl Service {
    fn run(&self) {}
}
struct Other;
impl Other {
    fn run(&self) {}
}

fn consume(_value: Service) {}

fn composed() {
    consume(Service {});
}
"#,
            enclosing_kind: "function",
            enclosing_name: "direct",
            member_name: "run",
            cap_operation: "points_to",
            expected_outcome: "precise",
            expected_value_kind: "allocation_site",
            declaration_field: "type_declaration",
            expected_type_suffix: "Service",
        },
        DirectAllocationCase {
            language: "scala",
            path: "Receiver.scala",
            direct_source: r#"class Service {
  def run(): Unit = ()
}

class Other {
  def run(): Unit = ()
}

object Caller {
  def direct(): Unit = {
    val service: Service = new Service()
    service.run()
  }
}
"#,
            cap_source: r#"trait A { def run(): Unit = () }
trait B { def run(): Unit = () }
trait C { def run(): Unit = () }
trait D { def run(): Unit = () }
trait E { def run(): Unit = () }

class Service extends A with B with C with D with E

object Caller {
  def capped(service: Service): Unit = {
    service.run()
  }
}
"#,
            cap_extra_files: NO_EXTRA_FILES,
            composition_source: r#"class Service {
  def run(): Unit = ()
}
class Other {
  def run(): Unit = ()
}

object Caller {
  def consume(value: Service): Unit = ()

  def composed(): Unit = {
    consume(new Service())
  }
}
"#,
            enclosing_kind: "method",
            enclosing_name: "direct",
            member_name: "run",
            cap_operation: "member_targets",
            expected_outcome: "precise",
            expected_value_kind: "allocation_site",
            declaration_field: "type_declaration",
            expected_type_suffix: "Service",
        },
    ]
}

fn receiver_type_fq_names(value: &Value) -> Vec<&str> {
    value["values"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|receiver| match receiver["receiver_value_kind"].as_str() {
            Some("allocation_site") => receiver["type_declaration"]["fq_name"].as_str(),
            Some("factory_return") => receiver["returned_value"]["type_declaration"]["fq_name"]
                .as_str()
                .or_else(|| receiver["returned_value"]["declaration"]["fq_name"].as_str()),
            Some(_) => receiver["declaration"]["fq_name"].as_str(),
            None => None,
        })
        .collect()
}

fn expected_capped_type(case: DirectAllocationCase, name: &str) -> bool {
    name.ends_with(case.expected_type_suffix)
}

#[test]
fn direct_allocations_publish_exact_structured_points_to_rows() {
    for case in direct_allocation_cases() {
        let report = run(
            case,
            case.direct_source,
            NO_EXTRA_FILES,
            json!({
                "languages": [case.language],
                "match": {
                    "kind": "call",
                    "callee": { "name": case.member_name },
                    "receiver": { "capture": "receiver" }
                },
                "inside": {
                    "kind": case.enclosing_kind,
                    "name": case.enclosing_name
                },
                "steps": [{ "op": "points_to", "capture": "receiver" }],
                "result_detail": "full"
            }),
        );
        let rows = report["results"]
            .as_array()
            .unwrap_or_else(|| panic!("{} receiver results: {report}", case.language));
        assert_eq!(
            rows.len(),
            1,
            "{} direct receiver result: {report}",
            case.language
        );
        let row = &rows[0];
        assert_eq!(
            row["outcome"], case.expected_outcome,
            "{} direct receiver outcome: {report}",
            case.language
        );
        let values = row["values"]
            .as_array()
            .unwrap_or_else(|| panic!("{} receiver values: {report}", case.language));
        assert_eq!(
            values.len(),
            1,
            "{} direct receiver values: {report}",
            case.language
        );
        let value = &values[0];
        assert_eq!(
            value["receiver_value_kind"], case.expected_value_kind,
            "{} direct receiver value kind: {report}",
            case.language
        );
        assert!(
            value[case.declaration_field]["fq_name"]
                .as_str()
                .is_some_and(|name| name.ends_with(case.expected_type_suffix)),
            "{} structured receiver type: {report}",
            case.language
        );
        if case.expected_value_kind == "allocation_site" {
            assert_eq!(
                value["allocation_site"]["path"], case.path,
                "{} allocation path: {report}",
                case.language
            );
            assert!(
                value["allocation_site"]["range"]["start_line"].is_number()
                    && value["allocation_site"]["range"]["end_line"].is_number(),
                "{} allocation range: {report}",
                case.language
            );
        } else {
            assert!(
                value[case.declaration_field]["node_range"]["start_line"].is_number(),
                "{} declaration range: {report}",
                case.language
            );
        }
        let trace = &row["provenance"][0];
        assert_eq!(
            trace["seed"]["result_type"], "structural_match",
            "{} structured seed provenance: {report}",
            case.language
        );
        let last_step = trace["steps"]
            .as_array()
            .and_then(|steps| steps.last())
            .unwrap_or_else(|| panic!("{} points-to provenance step: {report}", case.language));
        assert_eq!(
            last_step["op"], "points_to",
            "{} points-to provenance: {report}",
            case.language
        );
        assert_eq!(
            last_step["result"]["result_type"], "receiver_analysis",
            "{} receiver-analysis provenance result: {report}",
            case.language
        );
    }
}

#[test]
fn five_receiver_candidates_hit_the_public_receiver_candidate_cap() {
    for case in direct_allocation_cases() {
        if case.cap_operation.is_empty() {
            continue;
        }
        let report = run(
            case,
            case.cap_source,
            case.cap_extra_files,
            json!({
                "languages": [case.language],
                "match": {
                    "kind": "call",
                    "callee": { "name": case.member_name },
                    "receiver": { "capture": "receiver" }
                },
                "inside": {
                    "kind": case.enclosing_kind,
                    "name": "capped"
                },
                "steps": [{ "op": case.cap_operation, "capture": "receiver" }],
                "result_detail": "full"
            }),
        );
        let rows = report["results"]
            .as_array()
            .unwrap_or_else(|| panic!("{} capped receiver results: {report}", case.language));
        assert_eq!(
            rows.len(),
            1,
            "{} capped receiver result: {report}",
            case.language
        );
        let row = &rows[0];
        assert_ne!(
            row["outcome"], "precise",
            "{} capped receiver must not remain precise: {report}",
            case.language
        );
        if case.cap_operation == "member_targets" {
            let members = row["member_targets"].as_array().unwrap_or_else(|| {
                panic!("{} capped receiver member targets: {report}", case.language)
            });
            assert_eq!(
                members.len(),
                4,
                "{} public default max_targets must retain four of five members: {report}",
                case.language
            );
            assert!(
                members
                    .iter()
                    .all(|member| member["fq_name"].as_str().is_some_and(|name| name
                        .rsplit('.')
                        .next()
                        .is_some_and(|member| member == case.member_name))),
                "{} capped structured member declarations: {report}",
                case.language
            );
        } else {
            let values = row["values"]
                .as_array()
                .unwrap_or_else(|| panic!("{} capped receiver values: {report}", case.language));
            assert_eq!(
                values.len(),
                4,
                "{} public default max_targets must retain four of five values: {report}",
                case.language
            );
            let type_names = receiver_type_fq_names(row);
            assert_eq!(
                type_names.len(),
                values.len(),
                "{} every retained candidate must have a structured type: {report}",
                case.language
            );
            assert!(
                type_names
                    .iter()
                    .all(|name| expected_capped_type(case, name)),
                "{} capped receiver types: {report}",
                case.language
            );
        }
        assert_eq!(
            report["truncated"], true,
            "{} capped receiver must mark top-level truncation: {report}",
            case.language
        );
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| {
                    diagnostic["code"] == "receiver_analysis_partial"
                        && diagnostic["impact"] == "incomplete"
                        && diagnostic["message"]
                            .as_str()
                            .is_some_and(|message| message.contains("max_targets"))
                })),
            "{} capped receiver diagnostic: {report}",
            case.language
        );
    }
}

#[test]
fn call_inputs_compose_into_structured_points_to_rows_without_other_owner() {
    for case in direct_allocation_cases() {
        let report = run(
            case,
            case.composition_source,
            NO_EXTRA_FILES,
            json!({
                "languages": [case.language],
                "match": { "kind": "callable", "name": "consume" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 },
                    { "op": "points_to" }
                ],
                "result_detail": "full"
            }),
        );
        let rows = report["results"]
            .as_array()
            .unwrap_or_else(|| panic!("{} composed receiver results: {report}", case.language));
        assert_eq!(
            rows.len(),
            1,
            "{} composed receiver result: {report}",
            case.language
        );
        let row = &rows[0];
        assert_eq!(
            row["result_type"], "receiver_analysis",
            "{} call_input must feed a receiver analysis: {report}",
            case.language
        );
        assert_eq!(
            row["analysis_kind"], "points_to",
            "{} call_input points_to analysis kind: {report}",
            case.language
        );
        assert_ne!(
            row["outcome"], "unsupported",
            "{} call_input composition must be supported: {report}",
            case.language
        );
        let type_names = receiver_type_fq_names(row);
        assert!(
            !type_names.is_empty()
                && type_names
                    .iter()
                    .all(|name| name.ends_with(case.expected_type_suffix)),
            "{} composed structured receiver types: {report}",
            case.language
        );
        assert!(
            type_names.iter().all(|name| !name.contains("Other")),
            "{} unrelated same-name owner leaked into composed result: {report}",
            case.language
        );
        let steps = row["provenance"][0]["steps"]
            .as_array()
            .unwrap_or_else(|| panic!("{} composed provenance: {report}", case.language));
        assert_eq!(
            steps
                .iter()
                .map(|step| step["op"].as_str().expect("provenance op"))
                .collect::<Vec<_>>(),
            ["enclosing_decl", "call_sites_to", "call_input", "points_to"],
            "{} composed operation provenance: {report}",
            case.language
        );
        assert_eq!(
            steps[2]["result"]["result_type"], "expression_site",
            "{} call_input expression provenance: {report}",
            case.language
        );
    }
}
