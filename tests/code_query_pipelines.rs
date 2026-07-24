mod common;

use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryResult, execute,
    execute_with_limits, execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn result_fq_names(value: &Value) -> Vec<String> {
    value["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|result| {
            result["fq_name"]
                .as_str()
                .expect("declaration fq_name")
                .to_string()
        })
        .collect()
}

#[test]
fn receiver_traversal_preserves_factory_allocation_and_exact_member_provenance() {
    let files = [(
        "app.ts",
        r#"class Service { run() {} }
class Other { run() {} }
function makeService() { return new Service(); }
export function caller() {
    const service = makeService();
    service.run();
}
"#,
    )];
    let points_result = run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "service" }
            },
            "steps": [{ "op": "points_to", "capture": "service" }],
            "result_detail": "full"
        }),
    );
    let points_text = points_result.render_text();
    assert!(
        points_text.contains("value -> factory")
            && points_text.contains("-> allocation")
            && points_text.contains("Service"),
        "{points_text}"
    );
    let points_to = serialized(&points_result);
    assert_eq!(
        points_to["results"].as_array().unwrap().len(),
        1,
        "{points_to}"
    );
    let analysis = &points_to["results"][0];
    assert_eq!(analysis["result_type"], "receiver_analysis", "{points_to}");
    assert_eq!(analysis["analysis_kind"], "points_to", "{points_to}");
    assert_eq!(analysis["outcome"], "precise", "{points_to}");
    assert_eq!(points_to["truncated"], false, "{points_to}");
    assert_eq!(analysis["capture"], "service", "{points_to}");
    assert_eq!(
        analysis["values"][0]["receiver_value_kind"], "factory_return",
        "{points_to}"
    );
    assert!(
        analysis["values"][0]["factory"]["fq_name"]
            .as_str()
            .unwrap()
            .ends_with("makeService"),
        "{points_to}"
    );
    assert_eq!(
        analysis["values"][0]["returned_value"]["receiver_value_kind"], "allocation_site",
        "{points_to}"
    );
    assert!(
        analysis["values"][0]["returned_value"]["type_declaration"]["fq_name"]
            .as_str()
            .unwrap()
            .ends_with("Service"),
        "{points_to}"
    );

    let members = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }, { "op": "file_of" }]
        }),
    ));
    assert_eq!(members["results"].as_array().unwrap().len(), 1, "{members}");
    assert_eq!(members["results"][0]["result_type"], "file", "{members}");
    assert_eq!(members["results"][0]["path"], "app.ts", "{members}");

    let exact_members = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        exact_members["results"][0]["outcome"], "precise",
        "{exact_members}"
    );
    assert_eq!(
        exact_members["results"][0]["member_targets"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{exact_members}"
    );
    let target = exact_members["results"][0]["member_targets"][0]["fq_name"]
        .as_str()
        .unwrap();
    assert!(
        target.contains("Service") && !target.contains("Other"),
        "{exact_members}"
    );
}

#[test]
fn java_receiver_traversal_projects_neutral_heap_and_type_facts() {
    let files = [(
        "Sample.java",
        r#"class Service { void run() {} }
class Sample {
    void caller() {
        Service service = new Service();
        service.run();
    }
}
"#,
    )];
    let receiver = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(
        receiver["results"].as_array().unwrap().len(),
        1,
        "{receiver}"
    );
    assert_eq!(receiver["results"][0]["outcome"], "precise", "{receiver}");
    assert_eq!(
        receiver["results"][0]["values"][0]["receiver_value_kind"], "allocation_site",
        "{receiver}"
    );
    assert!(
        receiver["results"][0]["values"][0]["type_declaration"]["fq_name"]
            .as_str()
            .unwrap()
            .ends_with("Service"),
        "{receiver}"
    );

    let members = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(members["results"].as_array().unwrap().len(), 1, "{members}");
    assert_eq!(members["results"][0]["outcome"], "precise", "{members}");
    assert_eq!(
        members["results"][0]["member_targets"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{members}"
    );
    assert!(
        members["results"][0]["member_targets"][0]["fq_name"]
            .as_str()
            .unwrap()
            .contains("Service"),
        "{members}"
    );
}

#[test]
fn java_member_targets_reuse_exact_inherited_method_resolution() {
    let members = serialized(&run(
        &[(
            "Inherited.java",
            r#"class Base { void run() {} }
class Service extends Base { int run; }
class Sample {
    void caller() {
        Service service = new Service();
        service.run();
    }
}
"#,
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }]
        }),
    ));

    assert_eq!(members["results"][0]["outcome"], "precise", "{members}");
    let targets = members["results"][0]["member_targets"]
        .as_array()
        .unwrap_or_else(|| panic!("expected member targets: {members}"));
    assert_eq!(targets.len(), 1, "{members}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Base.run")),
        "the inherited method must win over the same-named field: {members}"
    );
}

#[test]
fn java_receiver_projection_preserves_type_static_current_and_factory_labels() {
    let files = [(
        "Labels.java",
        r#"class Service {
    static Service make() { return new Service(); }
    void run() {}
}
class Labels {
    void helper() {}
    void parameter(Service service) { service.run(); }
    void caller() {
        this.helper();
        Service service = Service.make();
        service.run();
    }
}
"#,
    )];

    let parameter = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" }
            },
            "inside": { "kind": "method", "name": "parameter" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(
        parameter["results"][0]["values"][0]["receiver_value_kind"], "instance_type",
        "{parameter}"
    );

    let current = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "helper" } },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let static_receiver = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "make" } },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(
        static_receiver["results"][0]["values"][0]["receiver_value_kind"], "class_or_static_object",
        "{static_receiver}"
    );

    let factory = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "make" } },
            "steps": [{ "op": "points_to" }]
        }),
    ));
    assert_eq!(factory["results"][0]["outcome"], "ambiguous", "{factory}");
    assert_eq!(
        factory["results"][0]["values"]
            .as_array()
            .expect("Java factory receiver values")
            .len(),
        1,
        "the exact factory result must subsume source-value scaffolding: {factory}"
    );
    assert_eq!(
        factory["results"][0]["values"][0]["receiver_value_kind"], "factory_return",
        "{factory}"
    );
    assert!(
        factory["results"][0]["values"][0]["factory"]["fq_name"]
            .as_str()
            .unwrap()
            .ends_with("Service.make"),
        "{factory}"
    );
}

#[test]
fn go_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "receiver.go",
        r#"package receiver

type Service struct{}
func (service Service) Run() {}
func (service Service) Current() { service.Run() }

type Other struct{}
func (other Other) Run() {}

func MakeService() Service { return Service{} }
func Call() {
    service := Service{}
    service.Run()
    MakeService().Run()
}
"#,
    )];

    let current = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "Run" } },
            "inside": { "kind": "method", "name": "Current" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "Call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_ne!(
        points_to["results"][0]["outcome"], "unsupported",
        "{points_to}"
    );
    assert!(
        points_to["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "{points_to}"
    );

    let member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "service" }
            },
            "inside": { "kind": "function", "name": "Call" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(member["results"][0]["outcome"], "precise", "{member}");
    let targets = member["results"][0]["member_targets"]
        .as_array()
        .expect("Go member targets");
    assert_eq!(targets.len(), 1, "{member}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Service") && name.ends_with(".Run")),
        "{member}"
    );
    assert!(!targets[0]["fq_name"].as_str().unwrap().contains("Other"));

    let factory = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "capture": "factory" }
            },
            "inside": { "kind": "function", "name": "Call" },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory = factory["results"]
        .as_array()
        .expect("Go factory rows")
        .iter()
        .find(|row| row["text"] == "MakeService()")
        .unwrap_or_else(|| panic!("Go factory row: {factory}"));
    assert_ne!(factory["outcome"], "unsupported", "{factory}");
    assert!(
        factory["values"].to_string().contains("Service"),
        "{factory}"
    );
}

#[test]
fn go_container_receivers_do_not_resolve_element_members() {
    let report = serialized(&run(
        &[(
            "container_receiver.go",
            r#"package receiver

type Service struct{}
func (service Service) Run() {}

func Invalid(slice []Service, array [2]Service) {
    slice.Run()
    array.Run()
}
"#,
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "Run" } },
            "inside": { "kind": "function", "name": "Invalid" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));

    let rows = report["results"].as_array().expect("receiver rows");
    assert_eq!(rows.len(), 2, "{report}");
    assert!(
        rows.iter().all(|row| {
            row["member_targets"].as_array().is_none_or(|targets| {
                targets.iter().all(|target| {
                    target["fq_name"]
                        .as_str()
                        .is_none_or(|name| !name.ends_with("Service.Run"))
                })
            })
        }),
        "{report}"
    );
}

#[test]
fn rust_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "receiver.rs",
        r#"struct Service;
impl Service {
    fn run(&self) {}
    fn current(&self) { self.run(); }
    fn make() -> Service { Service {} }
}

struct Other;
impl Other { fn run(&self) {} }

fn call() {
    let service = Service {};
    service.run();
    Service::make().run();
}
"#,
    )];

    let current = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "method", "name": "current" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_ne!(
        points_to["results"][0]["outcome"], "unsupported",
        "{points_to}"
    );
    assert!(
        points_to["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "{points_to}"
    );

    let member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(member["results"][0]["outcome"], "precise", "{member}");
    let targets = member["results"][0]["member_targets"]
        .as_array()
        .expect("Rust member targets");
    assert_eq!(targets.len(), 1, "{member}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Service") && name.ends_with(".run")),
        "{member}"
    );
    assert!(!targets[0]["fq_name"].as_str().unwrap().contains("Other"));

    let factory = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "factory" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory = factory["results"]
        .as_array()
        .expect("Rust factory rows")
        .iter()
        .find(|row| row["text"] == "Service::make()")
        .unwrap_or_else(|| panic!("Rust factory row: {factory}"));
    assert_ne!(factory["outcome"], "unsupported", "{factory}");
    assert!(
        factory["values"].to_string().contains("Service"),
        "{factory}"
    );
}

#[test]
fn scala_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "Receiver.scala",
        r#"class Service {
  def run(): Unit = ()
  def current(): Unit = this.run()
}

class Other {
  def run(): Unit = ()
}

object Factory {
  def makeService(): Service = new Service()
}

object Caller {
  def call(): Unit = {
    val service: Service = new Service()
    service.run()
    Factory.makeService().run()
  }
}
"#,
    )];

    let current = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "method", "name": "current" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "inside": { "kind": "method", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_ne!(
        points_to["results"][0]["outcome"], "unsupported",
        "{points_to}"
    );
    assert!(
        points_to["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "{points_to}"
    );

    let member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            },
            "inside": { "kind": "method", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        member["results"][0]["outcome"], "ambiguous",
        "ordinary Scala class methods remain overridable even when the exact declared member is known: {member}"
    );
    let targets = member["results"][0]["member_targets"]
        .as_array()
        .expect("Scala member targets");
    assert_eq!(targets.len(), 1, "{member}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Service") && name.ends_with(".run")),
        "{member}"
    );
    assert!(!targets[0]["fq_name"].as_str().unwrap().contains("Other"));

    let factory = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "factory" }
            },
            "inside": { "kind": "method", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory = factory["results"]
        .as_array()
        .expect("Scala factory rows")
        .iter()
        .find(|row| row["text"] == "Factory.makeService()")
        .unwrap_or_else(|| panic!("Scala factory row: {factory}"));
    assert_ne!(factory["outcome"], "unsupported", "{factory}");
    assert!(
        factory["values"].to_string().contains("Service"),
        "{factory}"
    );
}

#[test]
fn python_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "receiver.py",
        r#"class Service:
    def run(self) -> None:
        pass

    def current(self) -> None:
        self.run()

class Other:
    def run(self) -> None:
        pass

def make_service() -> Service:
    return Service()

def call() -> None:
    service: Service = Service()
    service.run()
    make_service().run()
"#,
    )];

    let current = serialized(&run(
        &files,
        json!({
            "languages": ["python"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "method", "name": "current" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_ne!(
        points_to["results"][0]["outcome"], "unsupported",
        "{points_to}"
    );
    assert!(
        points_to["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "{points_to}"
    );

    let member = serialized(&run(
        &files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        member["results"][0]["outcome"], "ambiguous",
        "ordinary Python methods retain an open dispatch boundary: {member}"
    );
    let targets = member["results"][0]["member_targets"]
        .as_array()
        .expect("Python member targets");
    assert_eq!(targets.len(), 1, "{member}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Service") && name.ends_with(".run")),
        "{member}"
    );
    assert!(!targets[0]["fq_name"].as_str().unwrap().contains("Other"));

    let factory = serialized(&run(
        &files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "factory" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory = factory["results"]
        .as_array()
        .expect("Python factory rows")
        .iter()
        .find(|row| row["text"] == "make_service()")
        .unwrap_or_else(|| panic!("Python factory row: {factory}"));
    assert_ne!(factory["outcome"], "unsupported", "{factory}");
    assert!(
        factory["values"].to_string().contains("Service"),
        "{factory}"
    );
}

#[test]
fn python_receiver_class_lookup_respects_lexical_visibility() {
    let hidden = serialized(&run(
        &[(
            "hidden.py",
            r#"class Container:
    class Service:
        def run(self) -> None:
            pass

def call() -> None:
    service = Service()
    service.run()
"#,
        )],
        json!({
            "languages": ["python"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(hidden["results"].as_array().unwrap().len(), 1, "{hidden}");
    assert!(
        hidden["results"][0]["member_targets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "a class nested in an unrelated class is not a visible bare receiver type: {hidden}"
    );
    assert!(
        !hidden["results"][0]
            .to_string()
            .contains("Container$Service.run"),
        "{hidden}"
    );

    let visible = serialized(&run(
        &[(
            "visible.py",
            r#"class Service:
    def run(self) -> None:
        pass

def call() -> None:
    service = Service()
    service.run()
"#,
        )],
        json!({
            "languages": ["python"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    let targets = visible["results"][0]["member_targets"]
        .as_array()
        .expect("visible module class member targets");
    assert_eq!(targets.len(), 1, "{visible}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("Service.run")),
        "{visible}"
    );

    let hidden_factory = serialized(&run(
        &[(
            "hidden_factory.py",
            r#"class Service:
    def run(self) -> None:
        pass

def outer() -> None:
    def make() -> Service:
        return Service()

def caller() -> None:
    make().run()
"#,
        )],
        json!({
            "languages": ["python"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        hidden_factory["results"].as_array().unwrap().len(),
        1,
        "{hidden_factory}"
    );
    assert!(
        hidden_factory["results"][0]["member_targets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "an unrelated nested factory is not a visible bare callable: {hidden_factory}"
    );
    assert!(
        !hidden_factory["results"][0]
            .to_string()
            .contains("Service.run"),
        "{hidden_factory}"
    );
}

#[test]
fn python_receiver_local_factory_function_preserves_its_return_type() {
    let members = serialized(&run(
        &[(
            "local_factory.py",
            r#"class Product:
    def run(self) -> None:
        pass

def caller() -> None:
    def make() -> Product:
        return Product()

    value = make()
    value.run()
"#,
        )],
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "value" }
            },
            "inside": { "kind": "function", "name": "caller" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    let targets = members["results"][0]["member_targets"]
        .as_array()
        .unwrap_or_else(|| panic!("local factory member targets: {members}"));
    assert_eq!(targets.len(), 1, "{members}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("Product.run")),
        "the local function binding must retain its structured return type: {members}"
    );
}

#[test]
fn python_receiver_module_class_inventory_rejects_hidden_and_rebound_classes() {
    let hidden = serialized(&run(
        &[(
            "hidden_function_class.py",
            r#"def hidden() -> None:
    class Service:
        def run(self) -> None:
            pass

def caller() -> None:
    value = Service()
    value.run()
"#,
        )],
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "value", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "caller" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert!(
        hidden["results"][0]["values"]
            .as_array()
            .is_none_or(|values| values.iter().all(|value| {
                value["receiver_value_kind"] != "allocation_site"
                    && !value.to_string().contains("Service")
            })),
        "a class hidden in an unrelated function must not create a module allocation: {hidden}"
    );

    let rebound = [(
        "rebound_module_class.py",
        r#"class Service:
    def run(self) -> None:
        pass

Service = lambda: object()

def caller() -> None:
    value = Service()
    value.run()
"#,
    )];
    assert_python_module_service_shadowed(&rebound, "caller");
}

fn assert_python_module_service_shadowed(files: &[(&str, &str)], function: &str) {
    let members = serialized(&run(
        files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "value" }
            },
            "inside": { "kind": "function", "name": function },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(members["results"].as_array().unwrap().len(), 1, "{members}");
    assert!(
        members["results"][0]["member_targets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "a lexical `{function}` binding must suppress the module Service class: {members}"
    );
    assert!(
        !members["results"][0].to_string().contains("Service.run"),
        "{members}"
    );

    let receivers = serialized(&run(
        files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "value", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": function },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        receivers["results"].as_array().unwrap().len(),
        1,
        "{receivers}"
    );
    assert!(
        receivers["results"][0]["values"]
            .as_array()
            .is_none_or(|values| values.iter().all(|value| {
                value["receiver_value_kind"] != "allocation_site"
                    && !value.to_string().contains("Service")
            })),
        "an unresolved lexical `{function}` call must stay unknown: {receivers}"
    );
}

fn assert_python_module_service_visible(files: &[(&str, &str)], function: &str) {
    let members = serialized(&run(
        files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "value" }
            },
            "inside": { "kind": "function", "name": function },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    let targets = members["results"][0]["member_targets"]
        .as_array()
        .unwrap_or_else(|| panic!("module Service targets for {function}: {members}"));
    assert_eq!(targets.len(), 1, "{members}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("Service.run")),
        "the module Service class must remain visible in `{function}`: {members}"
    );

    let receivers = serialized(&run(
        files,
        json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "value", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": function },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert!(
        receivers["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "the module Service allocation must remain visible in `{function}`: {receivers}"
    );
}

#[test]
fn python_receiver_module_class_is_blocked_by_ordinary_lexical_shadowing() {
    let files = [(
        "ordinary_shadowed.py",
        r#"class Service:
    def run(self) -> None:
        pass

def parameter_shadow(Service) -> None:
    value = Service()
    value.run()

def assignment_shadow() -> None:
    Service = lambda: object()
    value = Service()
    value.run()

def destructured_shadow() -> None:
    Service, unused = (lambda: object(), None)
    value = Service()
    value.run()

def function_shadow() -> None:
    def Service():
        return object()
    value = Service()
    value.run()

def header_walrus_shadow() -> None:
    def nested(argument=(Service := lambda: object())):
        return argument
    value = Service()
    value.run()
"#,
    )];

    for function in [
        "parameter_shadow",
        "assignment_shadow",
        "destructured_shadow",
        "function_shadow",
        "header_walrus_shadow",
    ] {
        assert_python_module_service_shadowed(&files, function);
    }
}

#[test]
fn python_receiver_nested_scope_headers_bind_but_bodies_do_not_leak() {
    let shadowed_files = [(
        "nested_headers.py",
        r#"class Service:
    def run(self) -> None:
        pass

def class_header_walrus_shadow() -> None:
    class Nested((Service := lambda: object())):
        pass
    value = Service()
    value.run()

def lambda_header_walrus_shadow() -> None:
    nested = lambda argument=(Service := lambda: object()): argument
    value = Service()
    value.run()
"#,
    )];
    for function in ["class_header_walrus_shadow", "lambda_header_walrus_shadow"] {
        assert_python_module_service_shadowed(&shadowed_files, function);
    }

    let visible_files = [(
        "nested_bodies.py",
        r#"class Service:
    def run(self) -> None:
        pass

def nested_function_body_is_pruned() -> None:
    def nested() -> None:
        Service = lambda: object()

    class Nested:
        Service = lambda: object()

    nested = lambda: (Service := object())
    value = Service()
    value.run()
"#,
    )];
    assert_python_module_service_visible(&visible_files, "nested_function_body_is_pruned");
}

#[test]
fn python_receiver_module_class_is_blocked_by_structured_binding_forms() {
    let files = [(
        "structured_shadowed.py",
        r#"class Service:
    def run(self) -> None:
        pass

def import_alias_shadow() -> None:
    import package as Service
    value = Service()
    value.run()

def direct_import_shadow() -> None:
    from package import Service
    value = Service()
    value.run()

def with_shadow(manager) -> None:
    with manager as Service:
        value = Service()
        value.run()

def except_shadow() -> None:
    try:
        raise RuntimeError()
    except RuntimeError as Service:
        value = Service()
        value.run()

def pattern_shadow(subject) -> None:
    match subject:
        case Service:
            value = Service()
            value.run()

def delete_shadow() -> None:
    del Service
    value = Service()
    value.run()
"#,
    )];

    for function in [
        "import_alias_shadow",
        "direct_import_shadow",
        "with_shadow",
        "except_shadow",
        "pattern_shadow",
        "delete_shadow",
    ] {
        assert_python_module_service_shadowed(&files, function);
    }
}

#[test]
fn python_receiver_comprehension_walrus_and_nonlocal_suppress_module_fallback() {
    let files = [(
        "scoped_shadowed.py",
        r#"class Service:
    def run(self) -> None:
        pass

def comprehension_walrus_shadow(items) -> None:
    [(Service := item) for item in items]
    value = Service()
    value.run()

def nonlocal_outer() -> None:
    Service = lambda: object()

    def nonlocal_shadow() -> None:
        nonlocal Service
        value = Service()
        value.run()

    nonlocal_shadow()

def captured_outer() -> None:
    Service = lambda: object()

    def captured_shadow() -> None:
        value = Service()
        value.run()

    captured_shadow()
"#,
    )];

    for function in [
        "comprehension_walrus_shadow",
        "nonlocal_shadow",
        "captured_shadow",
    ] {
        assert_python_module_service_shadowed(&files, function);
    }
}

#[test]
fn python_receiver_comprehension_target_does_not_leak() {
    let files = [(
        "comprehension_scope.py",
        r#"class Service:
    def run(self) -> None:
        pass

def comprehension_target_does_not_leak(items) -> None:
    [Service for Service in items]
    value = Service()
    value.run()
"#,
    )];
    assert_python_module_service_visible(&files, "comprehension_target_does_not_leak");
}

#[test]
fn python_receiver_global_directive_permits_module_fallback() {
    let files = [(
        "global_scope.py",
        r#"class Service:
    def run(self) -> None:
        pass

def global_binding() -> None:
    global Service
    value = Service()
    value.run()
"#,
    )];
    assert_python_module_service_visible(&files, "global_binding");
}

#[test]
fn php_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "receiver.php",
        r#"<?php
namespace Receiver;

class Service {
    public function run(): void {}
    public function current(): void { $this->run(); }
}

class Other {
    public function run(): void {}
}

function makeService(): Service {
    return new Service();
}

function call(): void {
    $service = new Service();
    $service->run();
    makeService()->run();
}
"#,
    )];

    let current = serialized(&run(
        &files,
        json!({
            "languages": ["php"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "method", "name": "current" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_ne!(
        points_to["results"][0]["outcome"], "unsupported",
        "{points_to}"
    );
    assert!(
        points_to["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "{points_to}"
    );

    let member = serialized(&run(
        &files,
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_ne!(member["results"][0]["outcome"], "unsupported", "{member}");
    let targets = member["results"][0]["member_targets"]
        .as_array()
        .expect("PHP member targets");
    assert_eq!(targets.len(), 1, "{member}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Service") && name.ends_with(".run")),
        "{member}"
    );
    assert!(!targets[0]["fq_name"].as_str().unwrap().contains("Other"));

    let factory = serialized(&run(
        &files,
        json!({
            "languages": ["php"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "factory" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory = factory["results"]
        .as_array()
        .expect("PHP factory rows")
        .iter()
        .find(|row| row["text"] == "makeService()")
        .unwrap_or_else(|| panic!("PHP factory row: {factory}"));
    assert_ne!(factory["outcome"], "unsupported", "{factory}");
    assert!(
        factory["values"].to_string().contains("Service"),
        "{factory}"
    );
}

#[test]
fn ruby_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "receiver.rb",
        r#"class Service
  def run
  end

  def current
    self.run
  end
end

class Other
  def run
  end
end

class Factory
  def self.make_service
    Service.new
  end
end

def call
  service = Service.new
  service.run
  Factory.make_service.run
end
"#,
    )];

    let current = serialized(&run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "method", "name": "current" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_ne!(
        points_to["results"][0]["outcome"], "unsupported",
        "{points_to}"
    );
    assert!(
        points_to["results"][0]["values"]
            .to_string()
            .contains("Service"),
        "{points_to}"
    );

    let member = serialized(&run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        member["results"][0]["outcome"], "ambiguous",
        "ordinary Ruby methods retain an open dispatch boundary: {member}"
    );
    let targets = member["results"][0]["member_targets"]
        .as_array()
        .expect("Ruby member targets");
    assert_eq!(targets.len(), 1, "{member}");
    assert!(
        targets[0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.contains("Service") && name.ends_with(".run")),
        "{member}"
    );
    assert!(!targets[0]["fq_name"].as_str().unwrap().contains("Other"));

    let factory = serialized(&run(
        &files,
        json!({
            "languages": ["ruby"],
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "factory" }
            },
            "inside": { "kind": "function", "name": "call" },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory = factory["results"]
        .as_array()
        .expect("Ruby factory rows")
        .iter()
        .find(|row| row["text"] == "Factory.make_service")
        .unwrap_or_else(|| panic!("Ruby factory row: {factory}"));
    assert_ne!(factory["outcome"], "unsupported", "{factory}");
    assert!(
        factory["values"].to_string().contains("Service"),
        "{factory}"
    );
}

#[test]
fn csharp_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "ReceiverCases.cs",
        r#"namespace Demo;

public class Service
{
    public void Run() {}
    public string Name => "service";
    public Service Next => this;
    public static Service Create() => new Service();

    public void Mixed(bool flag)
    {
        var mixed = flag ? new Service() : new Service();
        mixed.Run();
    }

    public void Folded(Service left, Service right, bool flag)
    {
        var selected = flag ? left : right;
        selected.Run();
    }
}

public class Other
{
    public void Run() {}
}

public static class ServiceExtensions
{
    public static void Extend(this Service value) {}
}

public static class OtherExtensions
{
    public static void Extend(this Other value) {}
}

public class Caller
{
    private readonly Service field = new Service();

    public void Touch(Service value) {}

    public void Call(Service parameter)
    {
        var local = new Service();
        local.Run();
        field.Run();
        local.Extend();
        parameter?.Run();
        var name = parameter?.Name;
        this.Touch(local);
        this.Touch(new Service());
        local.Next.Run();
        Service.Create().Run();
    }
}
"#,
    )];

    let local_points = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "local", "capture": "receiver" }
            },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        local_points["results"][0]["outcome"], "precise",
        "{local_points}"
    );
    assert_eq!(
        local_points["results"][0]["values"][0]["receiver_value_kind"], "allocation_site",
        "{local_points}"
    );
    assert!(
        local_points["results"][0]["values"][0]["type_declaration"]["fq_name"]
            .as_str()
            .is_some_and(|fqn| fqn.ends_with("Demo.Service")),
        "{local_points}"
    );

    let exact_member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "local" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        exact_member["results"][0]["outcome"], "precise",
        "{exact_member}"
    );
    let member_targets = exact_member["results"][0]["member_targets"]
        .as_array()
        .expect("member targets");
    assert_eq!(member_targets.len(), 1, "{exact_member}");
    assert_eq!(
        member_targets[0]["fq_name"], "Demo.Service.Run",
        "{exact_member}"
    );
    assert!(
        !member_targets.iter().any(|target| target["fq_name"]
            .as_str()
            .is_some_and(|fqn| fqn.contains("Demo.Other"))),
        "{exact_member}"
    );

    let mixed_receiver = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "mixed", "capture": "receiver" }
            },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    let mixed_values = mixed_receiver["results"][0]["values"]
        .as_array()
        .expect("mixed receiver values");
    assert_eq!(
        mixed_receiver["results"][0]["outcome"], "ambiguous",
        "{mixed_receiver}"
    );
    assert_eq!(mixed_values.len(), 2, "{mixed_receiver}");
    assert!(
        mixed_values
            .iter()
            .all(|value| value["receiver_value_kind"] == "allocation_site"),
        "{mixed_receiver}"
    );

    let folded_receiver = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "selected", "capture": "receiver" }
            },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        folded_receiver["results"][0]["outcome"], "unknown",
        "{folded_receiver}"
    );
    assert!(
        folded_receiver["results"][0].get("values").is_none(),
        "{folded_receiver}"
    );

    let extension_member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Extend" },
                "receiver": { "name": "local" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(
        extension_member["results"][0]["outcome"], "precise",
        "{extension_member}"
    );
    assert_eq!(
        extension_member["results"][0]["member_targets"][0]["fq_name"],
        "Demo.ServiceExtensions.Extend",
        "{extension_member}"
    );
    assert!(
        !extension_member["results"][0]["member_targets"]
            .as_array()
            .expect("extension targets")
            .iter()
            .any(|target| target["fq_name"] == "Demo.OtherExtensions.Extend"),
        "{extension_member}"
    );

    let parameter = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "parameter", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(parameter["results"][0]["outcome"], "precise", "{parameter}");
    assert_eq!(
        parameter["results"][0]["values"][0]["receiver_value_kind"], "instance_type",
        "{parameter}"
    );

    let field = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "field", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(field["results"][0]["outcome"], "ambiguous", "{field}");
    assert_eq!(
        field["results"][0]["values"][0]["receiver_value_kind"], "instance_type",
        "{field}"
    );
    assert_eq!(
        field["results"][0]["values"][0]["declaration"]["fq_name"], "Demo.Service",
        "{field}"
    );

    let current_receiver = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Touch" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    let current_receiver = current_receiver["results"]
        .as_array()
        .expect("current receiver rows")
        .iter()
        .find(|row| row["text"] == "this")
        .expect("current receiver result");
    assert_eq!(
        current_receiver["outcome"], "ambiguous",
        "{current_receiver}"
    );
    assert_eq!(
        current_receiver["values"][0]["receiver_value_kind"], "current_receiver",
        "{current_receiver}"
    );

    let conditional_property = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "field_access",
                "field": { "name": "Name" },
                "object": { "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        conditional_property["results"][0]["values"][0]["receiver_value_kind"], "instance_type",
        "{conditional_property}"
    );
    assert_eq!(
        conditional_property["results"][0]["outcome"], "ambiguous",
        "{conditional_property}"
    );
    assert_eq!(
        conditional_property["results"][0]["values"][0]["declaration"]["fq_name"], "Demo.Service",
        "{conditional_property}"
    );

    let static_receiver = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Create" },
                "receiver": { "name": "Service", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        static_receiver["results"][0]["values"][0]["receiver_value_kind"], "class_or_static_object",
        "{static_receiver}"
    );
    assert_eq!(
        static_receiver["results"][0]["outcome"], "precise",
        "{static_receiver}"
    );
    assert_eq!(
        static_receiver["results"][0]["values"][0]["declaration"]["fq_name"], "Demo.Service",
        "{static_receiver}"
    );

    let constructor_input = serialized(&run(
        &files,
        json!({
            "match": { "kind": "method", "name": "Touch" },
            "inside": { "kind": "class", "name": "Caller" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_index": 0 },
                { "op": "points_to" }
            ]
        }),
    ));
    let constructor = constructor_input["results"]
        .as_array()
        .expect("constructor call-input rows")
        .iter()
        .find(|row| row["text"] == "new Service()")
        .expect("constructor receiver result");
    assert_eq!(constructor["outcome"], "precise", "{constructor_input}");
    assert_eq!(
        constructor["values"][0]["receiver_value_kind"], "allocation_site",
        "{constructor_input}"
    );

    let dynamic_receiver = serialized(&run(
        &[(
            "DynamicReceiver.cs",
            r#"namespace Demo;
public class Caller
{
    public void Call(dynamic opaque)
    {
        opaque.Run();
    }
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "opaque", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        dynamic_receiver["results"][0]["outcome"], "unsupported",
        "{dynamic_receiver}"
    );
    assert!(
        dynamic_receiver["diagnostics"]
            .as_array()
            .is_some_and(
                |diagnostics| diagnostics.iter().any(|diagnostic| diagnostic["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("dynamic")))
            ),
        "{dynamic_receiver}"
    );

    let factory_result = serialized(&run(
        &[(
            "FactoryReceiver.cs",
            r#"namespace Demo;
public class Service
{
    public void Run() {}
    public static Service Create() => new Service();
}
public class Other
{
    public void Run() {}
    public static Other Create() => new Other();
}
public class Caller
{
    public void Call() { Service.Create().Run(); }
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "capture": "factory" }
            },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory_rows = factory_result["results"]
        .as_array()
        .expect("factory receiver rows");
    let factory = factory_rows
        .iter()
        .find(|row| row["text"] == "Service.Create()")
        .expect("factory-result receiver row");
    assert_eq!(factory["outcome"], "ambiguous", "{factory_result}");
    let factory_value = factory["values"]
        .as_array()
        .and_then(|values| {
            values
                .iter()
                .find(|value| value["receiver_value_kind"] == "factory_return")
        })
        .expect("factory-return value");
    assert_eq!(
        factory_value["factory"]["fq_name"], "Demo.Service.Create",
        "{factory_result}"
    );
    assert_eq!(
        factory_value["returned_value"]["receiver_value_kind"], "instance_type",
        "{factory_result}"
    );
    assert_eq!(
        factory_value["returned_value"]["declaration"]["fq_name"], "Demo.Service",
        "{factory_result}"
    );

    let ambiguous_factory = serialized(&run(
        &[(
            "AmbiguousFactory.cs",
            r#"namespace Demo;
public class Service { public void Run() {} }
public class Factory
{
    public static Service Create(int value) => new Service();
    public static Service Create(string value) => new Service();
    public void Call() { Create(default).Run(); }
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "capture": "factory" }
            },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    assert_eq!(
        ambiguous_factory["results"][0]["outcome"], "ambiguous",
        "{ambiguous_factory}"
    );
}

#[test]
fn csharp_property_receiver_retains_its_exact_closed_member_candidate() {
    let files = [(
        "PropertyReceiver.cs",
        r#"namespace Demo;
class Service
{
    public Service Next => this;
    public void Run() {}
}
class Other
{
    public void Run() {}
}
class Caller
{
    void Call()
    {
        var local = new Service();
        local.Next.Run();
    }
}
"#,
    )];

    let report = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": {
                    "text": { "regex": "^local\\.Next$" },
                    "capture": "receiver"
                }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    assert_eq!(report["results"][0]["outcome"], "ambiguous", "{report}");
    assert_eq!(
        report["results"][0]["member_targets"][0]["fq_name"], "Demo.Service.Run",
        "{report}"
    );
    assert!(
        !report["results"][0]["member_targets"]
            .as_array()
            .expect("member targets")
            .iter()
            .any(|target| target["fq_name"] == "Demo.Other.Run"),
        "{report}"
    );
    assert_eq!(report["truncated"], false, "{report}");
}

#[test]
fn csharp_member_targets_preserve_closed_extensions_and_open_dispatch() {
    let files = [
        (
            "Service.cs",
            r#"namespace Dispatch;

public class Service
{
    public int Count { get; }
}

public interface IService
{
    void Run();
    int Count { get; }
}

public class BaseService
{
    public virtual void Run() {}
    public virtual int Count { get; }
}
"#,
        ),
        (
            "Extensions.cs",
            r#"namespace Dispatch;

public static class ServiceExtensions
{
    public static void Extend(this Service value) {}
}
"#,
        ),
        (
            "Caller.cs",
            r#"namespace Dispatch;

public class Caller
{
    public void Call(Service local, IService contract, BaseService service)
    {
        local.Extend();
        contract.Run();
        service.Run();
        _ = local.Count;
        _ = contract.Count;
        _ = service.Count;
    }
}
"#,
        ),
    ];

    let extension = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Extend" },
                "receiver": { "name": "local" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(extension["results"][0]["outcome"], "precise", "{extension}");
    assert_eq!(
        extension["results"][0]["member_targets"][0]["fq_name"],
        "Dispatch.ServiceExtensions.Extend",
        "{extension}"
    );

    for (receiver, expected_target) in [
        ("contract", "Dispatch.IService.Run"),
        ("service", "Dispatch.BaseService.Run"),
    ] {
        let report = serialized(&run(
            &files,
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "Run" },
                    "receiver": { "name": receiver }
                },
                "steps": [{ "op": "member_targets" }]
            }),
        ));
        assert_eq!(report["results"][0]["outcome"], "ambiguous", "{report}");
        assert_eq!(
            report["results"][0]["member_targets"][0]["fq_name"], expected_target,
            "{report}"
        );
        assert!(
            !report["truncated"].as_bool().unwrap_or(false),
            "open dispatch is ambiguous, not truncated: {report}"
        );
    }

    for (receiver, expected_target, expected_outcome) in [
        ("local", "Dispatch.Service.Count", "precise"),
        ("contract", "Dispatch.IService.Count", "ambiguous"),
        ("service", "Dispatch.BaseService.Count", "ambiguous"),
    ] {
        let report = serialized(&run(
            &files,
            json!({
                "match": {
                    "kind": "field_access",
                    "field": { "name": "Count" },
                    "object": { "name": receiver }
                },
                "steps": [{ "op": "member_targets" }]
            }),
        ));
        assert_eq!(
            report["results"][0]["outcome"], expected_outcome,
            "{report}"
        );
        assert_eq!(
            report["results"][0]["member_targets"][0]["fq_name"], expected_target,
            "{report}"
        );
        assert!(
            !report["truncated"].as_bool().unwrap_or(false),
            "open property dispatch is ambiguous, not truncated: {report}"
        );
    }
}

#[test]
fn csharp_overload_and_delegate_dispatch_never_collapse_to_a_precise_member() {
    let files = [(
        "OpenDispatch.cs",
        r#"namespace Dispatch;

public delegate void Work();

public class Overloaded
{
    public void Run(int value) {}
    public void Run(string value) {}

    public void Call(Overloaded service, Work work)
    {
        service.Run(default);
        work.Invoke();
    }
}
"#,
    )];

    let overload = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "name": "service" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(overload["results"][0]["outcome"], "ambiguous", "{overload}");
    assert_eq!(
        overload["results"][0]["member_targets"]
            .as_array()
            .expect("overload member targets")
            .len(),
        2,
        "{overload}"
    );
    assert!(
        !overload["truncated"].as_bool().unwrap_or(false),
        "a complete overload set is ambiguous, not truncated: {overload}"
    );

    let delegate = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Invoke" },
                "receiver": { "name": "work" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_ne!(
        delegate["results"][0]["outcome"], "precise",
        "delegate invocation stays open until callable targets are modeled: {delegate}"
    );
    assert!(
        !delegate["truncated"].as_bool().unwrap_or(false),
        "delegate uncertainty is semantic, not a resource exit: {delegate}"
    );
}

#[test]
fn csharp_member_targets_compose_from_a_same_file_exact_reference() {
    let files = [(
        "ReferenceComposition.cs",
        r#"namespace Composition;

public class Service
{
    public void Run() {}
}

public class Caller
{
    public void Call(Service service) { service.Run(); }
}
"#,
    )];

    let report = serialized(&run(
        &files,
        json!({
            "match": { "kind": "method", "name": "Run" },
            "inside": { "kind": "class", "name": "Service" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "references_of", "proof": "proven" },
                { "op": "member_targets" }
            ]
        }),
    ));
    assert_eq!(report["results"][0]["outcome"], "precise", "{report}");
    assert_eq!(
        report["results"][0]["member_targets"][0]["fq_name"], "Composition.Service.Run",
        "{report}"
    );
}

#[test]
fn csharp_unresolved_extension_applicability_stays_nonprecise() {
    let files = [(
        "AmbiguousExtensions.cs",
        r#"using Left;
using Right;

namespace Dispatch
{
    public class Service {}

    public class Caller
    {
        public void Call(Service service) { service.Extend(); }
    }
}

namespace Left
{
    public static class Extensions
    {
        public static void Extend(this Dispatch.Service value) {}
    }
}

namespace Right
{
    public static class Extensions
    {
        public static void Extend(this Dispatch.Service value) {}
    }
}
"#,
    )];

    let report = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Extend" },
                "receiver": { "name": "service" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    let outcome = report["results"][0]["outcome"]
        .as_str()
        .expect("receiver outcome");
    assert!(
        matches!(outcome, "unknown" | "ambiguous"),
        "unresolved extension applicability must remain nonprecise: {report}"
    );
    if outcome == "ambiguous" {
        assert_eq!(
            report["results"][0]["member_targets"]
                .as_array()
                .expect("extension candidates")
                .len(),
            2,
            "{report}"
        );
    }
    assert!(
        !report["truncated"].as_bool().unwrap_or(false),
        "unresolved extension applicability is unknown, not truncated: {report}"
    );
}

#[test]
fn csharp_ambiguous_static_receiver_type_cannot_publish_a_precise_member() {
    let files = [
        (
            "Left.cs",
            r#"namespace Left;
public class Service
{
    public static void Run() {}
}
"#,
        ),
        (
            "Right.cs",
            r#"namespace Right;
public class Service {}
"#,
        ),
        (
            "Caller.cs",
            r#"using Left;
using Right;

public class Caller
{
    public void Call() { Service.Run(); }
}
"#,
        ),
    ];

    let receiver = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(receiver["results"][0]["outcome"], "ambiguous", "{receiver}");

    let member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Run" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(member["results"][0]["outcome"], "ambiguous", "{member}");
    assert_eq!(
        member["results"][0]["member_targets"][0]["fq_name"], "Left.Service.Run",
        "{member}"
    );
}

#[test]
fn csharp_partial_static_receiver_uses_one_logical_type_identity() {
    let files = [
        (
            "PartialService.One.cs",
            r#"
namespace Demo;
public partial class PartialService
{
    public static PartialService Create() => new();
}
"#,
        ),
        (
            "PartialService.Two.cs",
            r#"
namespace Demo;
public partial class PartialService
{
    public static int Count => 1;
}
"#,
        ),
        (
            "Caller.cs",
            r#"
namespace Demo;
public class Caller
{
    public void Call() { _ = PartialService.Create(); }
}
"#,
        ),
    ];

    let receivers = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Create" },
                "receiver": { "name": "PartialService", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(receivers["results"][0]["outcome"], "precise", "{receivers}");
    assert_eq!(
        receivers["results"][0]["values"]
            .as_array()
            .expect("receiver values")
            .len(),
        1,
        "{receivers}"
    );
    assert_eq!(
        receivers["results"][0]["values"][0]["declaration"]["fq_name"], "Demo.PartialService",
        "{receivers}"
    );

    let members = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "Create" },
                "receiver": { "name": "PartialService" }
            },
            "steps": [{ "op": "member_targets" }]
        }),
    ));
    assert_eq!(members["results"][0]["outcome"], "precise", "{members}");
    assert_eq!(
        members["results"][0]["member_targets"][0]["fq_name"], "Demo.PartialService.Create",
        "{members}"
    );
}

#[test]
fn csharp_null_and_conversion_receivers_never_publish_precise_objects() {
    let files = [(
        "Conversions.cs",
        r#"
namespace Demo;

public class Service
{
    public void Run() {}
}

public class Source
{
    public static implicit operator Service(Source value) => new();
    public static explicit operator Service(Source value) => new();
}

public class Caller
{
    public void Call()
    {
        Service fromNull = null;
        Service fromDefault = default(Service);
        object opaque = new Source();
        Service fromAs = opaque as Service;
        Service fromCast = (Service)opaque;
        Source source = new Source();
        Service converted = source;

        fromNull.Run();
        fromDefault.Run();
        fromAs.Run();
        fromCast.Run();
        converted.Run();
    }
}
"#,
    )];

    for receiver in ["fromNull", "fromDefault", "fromAs", "fromCast", "converted"] {
        let report = serialized(&run(
            &files,
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "Run" },
                    "receiver": { "name": receiver, "capture": "receiver" }
                },
                "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
            }),
        ));
        assert_ne!(
            report["results"][0]["outcome"], "precise",
            "{receiver} must retain its null/conversion uncertainty: {report}"
        );
        assert!(
            !report["truncated"].as_bool().unwrap_or(false),
            "{receiver} is semantically incomplete, not truncated: {report}"
        );
        assert!(
            report["results"][0]["values"]
                .as_array()
                .is_none_or(|values| values
                    .iter()
                    .all(|value| value["receiver_value_kind"] != "allocation_site")),
            "{receiver} must not relabel a pre-conversion allocation as Service: {report}"
        );
    }
}

#[test]
fn csharp_static_receiver_alias_and_predefined_shapes_are_precise() {
    let files = [(
        "StaticReceivers.cs",
        r#"public class GlobalService
{
    public static GlobalService Create() => new GlobalService();
}

namespace System
{
    public class String
    {
        public static bool IsNullOrEmpty(string value) => false;
    }
}

namespace Demo
{
    public class Caller
    {
        public void Call()
        {
            global::GlobalService.Create();
            string.IsNullOrEmpty("");
        }
    }
}
"#,
    )];

    for (callee, receiver, expected_type, expected_member) in [
        (
            "IsNullOrEmpty",
            "string",
            "System.String",
            "System.String.IsNullOrEmpty",
        ),
        (
            "Create",
            "global::GlobalService",
            "GlobalService",
            "GlobalService.Create",
        ),
    ] {
        for operation in ["receiver_targets", "points_to"] {
            let report = serialized(&run(
                &files,
                json!({
                    "match": {
                        "kind": "call",
                        "callee": { "name": callee },
                        "receiver": { "capture": "receiver" }
                    },
                    "steps": [{ "op": operation, "capture": "receiver" }]
                }),
            ));
            let row = report["results"]
                .as_array()
                .expect("static receiver rows")
                .iter()
                .find(|row| row["text"] == receiver)
                .unwrap_or_else(|| panic!("missing receiver {receiver:?}: {report}"));
            assert_eq!(row["outcome"], "precise", "{report}");
            assert_eq!(
                row["values"][0]["receiver_value_kind"], "class_or_static_object",
                "{report}"
            );
            assert_eq!(
                row["values"][0]["declaration"]["fq_name"], expected_type,
                "{report}"
            );
        }

        let member = serialized(&run(
            &files,
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": callee }
                },
                "steps": [{ "op": "member_targets" }]
            }),
        ));
        assert_eq!(member["results"][0]["outcome"], "precise", "{member}");
        assert_eq!(
            member["results"][0]["member_targets"][0]["fq_name"], expected_member,
            "{member}"
        );
    }
}

#[test]
fn receiver_traversal_keeps_ambiguity_unknown_and_unsupported_as_rows() {
    let ambiguous = serialized(&run(
        &[(
            "ambiguous.ts",
            r#"class A { run() {} }
class B { run() {} }
export function caller(flag: boolean) {
    const service = flag ? new A() : new B();
    service.run();
}
"#,
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(
        ambiguous["results"][0]["outcome"], "ambiguous",
        "{ambiguous}"
    );
    assert_eq!(
        ambiguous["results"][0]["values"].as_array().unwrap().len(),
        2,
        "{ambiguous}"
    );

    let unknown = serialized(&run(
        &[(
            "unknown.ts",
            "export function caller() { external.run(); }\n",
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(unknown["results"][0]["outcome"], "unknown", "{unknown}");

    let unsupported = serialized(&run(
        &[(
            "plain.c",
            "struct Service { void (*run)(void); };\n\
             void invoke(struct Service *service) { service->run(); }\n",
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        unsupported["results"][0]["outcome"], "unsupported",
        "{unsupported}"
    );
    assert_eq!(
        unsupported["results"][0]["reason"], "cpp_c_receiver_unsupported",
        "{unsupported}"
    );
    assert!(
        unsupported["results"][0].get("values").is_none()
            || unsupported["results"][0]["values"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "{unsupported}"
    );
    assert!(
        unsupported["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| {
                diagnostic["language"] == "cpp"
                    && diagnostic["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("plain C"))
            }),
        "{unsupported}"
    );

    let unsupported_shape = serialized(&run(
        &[("shape.ts", "export class Service { run() {} }\n")],
        json!({
            "match": { "kind": "class", "name": "Service" },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(
        unsupported_shape["results"][0]["outcome"], "unsupported",
        "{unsupported_shape}"
    );
    assert_eq!(
        unsupported_shape["results"][0]["reason"], "receiver_site_without_receiver",
        "{unsupported_shape}"
    );
}

#[test]
fn receiver_traversal_composes_with_call_inputs_and_reference_sites() {
    let files = [(
        "compose.ts",
        r#"class Service { run() {} }
function consume(value: Service) { value.run(); }
export function caller() { consume(new Service()); }
"#,
    )];
    let call_input = serialized(&run(
        &files,
        json!({
            "match": { "kind": "function", "name": "consume" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to" },
                { "op": "call_input", "parameter_index": 0 },
                { "op": "points_to" }
            ]
        }),
    ));
    assert_eq!(
        call_input["results"][0]["outcome"], "ambiguous",
        "{call_input}"
    );
    assert_eq!(call_input["truncated"], false, "{call_input}");
    assert_eq!(
        call_input["results"][0]["values"][0]["receiver_value_kind"], "allocation_site",
        "{call_input}"
    );
    assert_eq!(
        call_input["results"][0]["provenance"][0]["steps"][2]["result"]["result_type"],
        "expression_site",
        "{call_input}"
    );

    let reference = serialized(&run(
        &files,
        json!({
            "match": { "kind": "method", "name": "run" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "references_of", "proof": "proven" },
                { "op": "member_targets" }
            ]
        }),
    ));
    assert_eq!(reference["results"][0]["outcome"], "precise", "{reference}");
    assert!(
        reference["results"][0]["member_targets"][0]["fq_name"]
            .as_str()
            .unwrap()
            .contains("Service"),
        "{reference}"
    );
}

#[test]
fn receiver_candidate_cap_retains_bounded_values_and_marks_truncation() {
    let files = [(
        "fanout.ts",
        r#"class A { run() {} }
class B { run() {} }
class C { run() {} }
class D { run() {} }
class E { run() {} }
class F { run() {} }
function make(which: number) {
    if (which === 0) return new A();
    if (which === 1) return new B();
    if (which === 2) return new C();
    if (which === 3) return new D();
    return new E();
}
export function caller(which: number) {
    const service = make(which);
    service.run();
}
export function simple() {
    const service = new F();
    service.run();
}
"#,
    )];
    let result = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 2, "{result}");
    assert_eq!(result["results"][0]["outcome"], "ambiguous", "{result}");
    assert_eq!(
        result["results"][0]["values"].as_array().unwrap().len(),
        4,
        "{result}"
    );
    assert_eq!(result["truncated"], true, "{result}");
    assert!(
        result["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["outcome"] == "precise" && row["text"] == "service"),
        "{result}"
    );
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| {
                diagnostic["code"] == "receiver_analysis_partial"
                    && diagnostic["impact"] == "incomplete"
                    && diagnostic["message"]
                        .as_str()
                        .unwrap()
                        .contains("max_targets")
            }),
        "{result}"
    );

    let composed = serialized(&run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }, { "op": "file_of" }]
        }),
    ));
    assert_eq!(composed["results"][0]["result_type"], "file", "{composed}");
    assert_eq!(composed["results"][0]["path"], "fanout.ts", "{composed}");
    assert_eq!(composed["truncated"], true, "{composed}");
}

#[test]
fn receiver_capture_range_cap_marks_top_level_truncation() {
    let result = serialized(&run(
        &[(
            "captured_ranges.ts",
            r#"class Service {}
function consume(first: Service, second: Service, third: Service) {}
consume(new Service(), new Service(), new Service());
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "consume" },
                "args": [
                    { "capture": "receiver" },
                    { "capture": "receiver" },
                    { "capture": "receiver" }
                ]
            },
            "steps": [{ "op": "points_to", "capture": "receiver" }],
            "limit": 1
        }),
    ));

    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["truncated"], true, "{result}");
    assert!(
        result["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| {
                diagnostic["code"] == "receiver_analysis_partial"
                    && diagnostic["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("pipeline output cap"))
            })),
        "{result}"
    );
}

#[test]
fn receiver_step_does_not_emit_after_prior_steps_consume_pipeline_budget() {
    let project = InlineTestProject::new()
        .file(
            "receiver.ts",
            r#"class Service { run() {} }
export function caller() { new Service().run(); }
"#,
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "method", "name": "run" },
        "inside": { "kind": "class", "name": "Service" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of", "proof": "proven" },
            { "op": "member_targets" }
        ]
    }))
    .expect("query");

    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    let value = serialized(&result);
    assert!(result.results.is_empty(), "{value}");
    assert!(result.truncated, "{value}");
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
        }),
        "{value}"
    );
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ReceiverAnalysisPartial
                && diagnostic.message.contains("pipeline output cap")
        }),
        "{value}"
    );
}

#[test]
fn call_traversal_and_formal_input_projection_share_structured_call_sites() {
    let files = [(
        "Sample.java",
        r#"class Sample {
    static void sink(String payload, int mode) {}
    void recurse() { recurse(); }
    void caller() { sink("secret", 7); this.recurse(); }
}
"#,
    )];

    let callers = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "sink" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "callers", "proof": "proven" }]
        }),
    ));
    assert_eq!(
        result_fq_names(&callers),
        vec!["Sample.caller"],
        "{callers}"
    );
    assert_eq!(
        callers["results"][0]["provenance"][0]["steps"][1]["via"]["result_type"], "call_site",
        "{callers}"
    );

    let callees = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "caller" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "callees" }]
        }),
    ));
    assert_eq!(
        result_fq_names(&callees),
        vec!["Sample.sink", "Sample.recurse"],
        "{callees}"
    );

    let input = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "sink" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_index": 0 }
            ],
            "result_detail": "full"
        }),
    ));
    assert_eq!(input["results"].as_array().unwrap().len(), 1, "{input}");
    assert_eq!(
        input["results"][0]["result_type"], "expression_site",
        "{input}"
    );
    assert_eq!(input["results"][0]["text"], "\"secret\"", "{input}");
    assert_eq!(input["results"][0]["parameter_index"], 0, "{input}");
    assert_eq!(input["results"][0]["parameter_name"], "payload", "{input}");

    let receiver = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "caller" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_from" },
                { "op": "call_input", "receiver": true }
            ]
        }),
    ));
    assert_eq!(
        receiver["results"].as_array().unwrap().len(),
        1,
        "{receiver}"
    );
    assert_eq!(receiver["results"][0]["text"], "this", "{receiver}");
    assert_eq!(
        receiver["results"][0]["input_kind"], "receiver",
        "{receiver}"
    );
}

#[test]
fn call_input_supports_keyword_binding_and_call_cycles_terminate() {
    let files = [(
        "sample.py",
        r#"def sink(payload, mode=0):
    return payload

def first():
    sink(mode=2, payload="named")
    second()

def second():
    first()
"#,
    )];
    let keyword = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "sink" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to" },
                { "op": "call_input", "parameter_name": "payload" }
            ]
        }),
    ));
    assert_eq!(keyword["results"][0]["text"], "\"named\"", "{keyword}");
    assert_eq!(keyword["results"][0]["parameter_index"], 0, "{keyword}");

    let bounded = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "first" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "callees", "depth": 8 }]
        }),
    ));
    assert_eq!(
        result_fq_names(&bounded),
        vec!["sample.sink", "sample.second", "sample.first"],
        "{bounded}"
    );
}

#[test]
fn python_static_method_keeps_its_first_formal_parameter() {
    let result = serialized(&run(
        &[(
            "static.py",
            r#"class Box:
    @staticmethod
    def emit(payload):
        return payload

def caller():
    Box.emit("kept")
"#,
        )],
        json!({
            "match": { "kind": "method", "name": "emit" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_index": 0 }
            ]
        }),
    ));
    assert_eq!(result["results"][0]["text"], "\"kept\"", "{result}");
    assert_eq!(
        result["results"][0]["parameter_name"], "payload",
        "{result}"
    );

    let instance = serialized(&run(
        &[(
            "instance.py",
            r#"class Box:
    def send(self, payload):
        return payload

    def caller(self):
        self.send("instance")
"#,
        )],
        json!({
            "match": { "kind": "method", "name": "caller" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_from", "proof": "proven" },
                { "op": "call_input", "parameter_index": 0 }
            ]
        }),
    ));
    assert_eq!(instance["results"][0]["text"], "\"instance\"", "{instance}");
    assert_eq!(
        instance["results"][0]["parameter_name"], "payload",
        "{instance}"
    );

    let incoming_instance = serialized(&run(
        &[(
            "instance.py",
            r#"class Box:
    def send(self, payload):
        return payload

    def caller(self):
        self.send("instance")
"#,
        )],
        json!({
            "match": { "kind": "method", "name": "send" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_index": 0 }
            ]
        }),
    ));
    assert_eq!(
        incoming_instance["results"][0]["text"], "\"instance\"",
        "{incoming_instance}"
    );
}

#[test]
fn java_reference_steps_preserve_exact_site_and_semantic_owner() {
    let files = [
        ("Target.java", "class Target { int status; }\n"),
        (
            "User.java",
            "class User { int read(Target target) { return target.status; } }\n",
        ),
        (
            "Unrelated.java",
            "class Unrelated { int status; } class Other { int read(Unrelated value) { return value.status; } }\n",
        ),
    ];
    let references = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "references_of", "proof": "proven" }
            ],
            "result_detail": "full"
        }),
    ));
    assert_eq!(
        references["results"].as_array().unwrap().len(),
        1,
        "{references}"
    );
    let site = &references["results"][0];
    assert_eq!(site["result_type"], "reference_site", "{references}");
    assert_eq!(site["path"], "User.java", "{references}");
    assert_eq!(site["target"]["fq_name"], "Target.status", "{references}");
    assert_eq!(
        site["enclosing_declaration"]["fq_name"], "User.read",
        "{references}"
    );
    assert_eq!(site["proof"], "proven", "{references}");
    assert!(
        site["provenance"][0]["steps"][2]["result"]["target_id"].is_string(),
        "{references}"
    );
    assert!(
        site["range"]["start_column"].as_u64().unwrap() > 0,
        "{references}"
    );

    let used_by = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "used_by", "proof": "proven" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&used_by), vec!["User.read"], "{used_by}");
    assert_eq!(
        used_by["results"][0]["provenance"][0]["steps"][2]["via"]["result_type"], "reference_site",
        "{used_by}"
    );
}

#[test]
fn java_uses_is_inverse_of_used_by_and_reference_file_composes() {
    let files = [
        ("Target.java", "class Target { int status; }\n"),
        (
            "User.java",
            "class User { int read(Target target) { return target.status; } }\n",
        ),
    ];
    let uses = serialized(&run(
        &files,
        json!({
            "match": { "kind": "method", "name": "read" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "uses" }
            ]
        }),
    ));
    assert!(
        result_fq_names(&uses)
            .iter()
            .any(|name| name == "Target.status"),
        "{uses}"
    );
    let status = uses["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["fq_name"] == "Target.status")
        .expect("status dependency");
    assert_eq!(
        status["provenance"][0]["steps"][1]["via"]["target_fq_name"], "Target.status",
        "{uses}"
    );

    let files_result = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "references_of" },
                { "op": "file_of" }
            ]
        }),
    ));
    assert_eq!(
        files_result["results"][0]["path"], "User.java",
        "{files_result}"
    );
}

#[test]
fn java_reference_kind_filter_distinguishes_field_writes() {
    let result = serialized(&run(
        &[
            ("Target.java", "class Target { int status; }\n"),
            (
                "User.java",
                "class User { int update(Target target) { target.status = 1; return target.status; } }\n",
            ),
        ],
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "references_of", "reference_kinds": ["field_write"] }
            ]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(
        result["results"][0]["reference_kind"], "field_write",
        "{result}"
    );
}

#[test]
fn java_reference_kinds_cover_type_constructor_static_super_and_inheritance() {
    let files = [(
        "Sample.java",
        "class Base { static int FLAG; Base() {} void run() {} }\n\
         class Child extends Base { void call() { super.run(); int x = Base.FLAG; Base value = new Base(); } }\n",
    )];
    let references_for = |target_kind: &str, target_name: &str, reference_kind: &str| {
        serialized(&run(
            &files,
            json!({
                "languages": ["java"],
                "match": { "kind": target_kind, "name": target_name },
                "steps": [
                    { "op": "enclosing_decl" },
                    {
                        "op": "references_of",
                        "reference_kinds": [reference_kind],
                        "proof": "proven",
                        "surface": "lsp_references"
                    }
                ]
            }),
        ))
    };

    for reference_kind in ["type_reference", "constructor_call", "inheritance"] {
        let result = references_for("class", "Base", reference_kind);
        assert!(
            result["results"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "missing {reference_kind}: {result}"
        );
    }

    let static_reference = serialized(&run(
        &files,
        json!({
            "languages": ["java"],
            "match": { "kind": "class", "name": "Base" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                {
                    "op": "references_of",
                    "reference_kinds": ["static_reference"],
                    "proof": "proven",
                    "surface": "lsp_references"
                }
            ]
        }),
    ));
    assert!(
        static_reference["results"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "{static_reference}"
    );

    let super_call = references_for("method", "run", "super_call");
    assert!(
        super_call["results"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "{super_call}"
    );
}

#[test]
fn reference_traversal_resolves_inbound_and_outbound_across_all_adapters() {
    let cases = [
        (
            "python",
            "sample.py",
            "def target(payload):\n    pass\n\ndef caller():\n    target(\"input\")\n",
        ),
        (
            "java",
            "Sample.java",
            "class Target { static void target(String payload) {} }\nclass Caller { static void caller() { Target.target(\"input\"); } }\n",
        ),
        (
            "javascript",
            "sample.js",
            "function target(payload) {}\nfunction caller() { target(\"input\"); }\n",
        ),
        (
            "typescript",
            "sample.ts",
            "function target(payload: string): void {}\nfunction caller(): void { target(\"input\"); }\n",
        ),
        (
            "go",
            "sample.go",
            "package sample\nfunc target(payload string) {}\nfunc caller() { target(\"input\") }\n",
        ),
        (
            "cpp",
            "sample.cpp",
            "void target(const char* payload) {}\nvoid caller() { target(\"input\"); }\n",
        ),
        (
            "rust",
            "sample.rs",
            "fn target(payload: &str) {}\nfn caller() { target(\"input\"); }\n",
        ),
        (
            "php",
            "sample.php",
            "<?php\nfunction target($payload) {}\nfunction caller() { target(\"input\"); }\n",
        ),
        (
            "scala",
            "Sample.scala",
            "object Target { def target(payload: String): Unit = () }\nobject Caller { def caller(): Unit = Target.target(\"input\") }\n",
        ),
        (
            "csharp",
            "Sample.cs",
            "class Target { public static void target(string payload) {} }\nclass Caller { public static void caller() { Target.target(\"input\"); } }\n",
        ),
        (
            "ruby",
            "sample.rb",
            "class Target\n  def self.target(payload); end\nend\nclass Caller\n  def self.caller; Target.target(\"input\"); end\nend\n",
        ),
    ];

    for (language, path, source) in cases {
        let inbound = serialized(&run(
            &[(path, source)],
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "references_of" }
                ]
            }),
        ));
        assert!(
            inbound["results"].as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row["target"]["fq_name"]
                        .as_str()
                        .is_some_and(|name| name.ends_with("target"))
                })
            }),
            "missing inbound {language} reference: {inbound}"
        );

        let outbound = serialized(&run(
            &[(path, source)],
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": "caller" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "uses" }
                ]
            }),
        ));
        assert!(
            result_fq_names(&outbound)
                .iter()
                .any(|name| name.ends_with("target")),
            "missing outbound {language} reference: {outbound}"
        );

        let callers = serialized(&run(
            &[(path, source)],
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": "target" },
                "steps": [{ "op": "enclosing_decl" }, { "op": "callers", "proof": "proven" }]
            }),
        ));
        assert!(
            result_fq_names(&callers)
                .iter()
                .any(|name| name.ends_with("caller")),
            "missing {language} caller: inbound={inbound}; callers={callers}"
        );

        let callees = serialized(&run(
            &[(path, source)],
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": "caller" },
                "steps": [{ "op": "enclosing_decl" }, { "op": "callees", "proof": "proven" }]
            }),
        ));
        assert!(
            result_fq_names(&callees)
                .iter()
                .any(|name| name.ends_with("target")),
            "missing {language} callee: {callees}"
        );

        let input = serialized(&run(
            &[(path, source)],
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 }
                ]
            }),
        ));
        assert!(
            input["results"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["text"] == "\"input\"" && row["parameter_index"] == 0)),
            "missing {language} positional input: {input}"
        );
    }
}

#[test]
fn named_call_inputs_bind_to_formals_across_keyword_adapters() {
    let cases = [
        (
            "python",
            "sample.py",
            "def target(payload, mode=0):\n    pass\n\ndef caller():\n    target(mode=2, payload=\"named\")\n",
        ),
        (
            "php",
            "sample.php",
            "<?php\nfunction target($payload, $mode = 0) {}\nfunction caller() { target(mode: 2, payload: \"named\"); }\n",
        ),
        (
            "scala",
            "Sample.scala",
            "object Sample { def target(payload: String, mode: Int = 0): Unit = (); def caller(): Unit = target(mode = 2, payload = \"named\") }\n",
        ),
        (
            "csharp",
            "Sample.cs",
            "class Sample { static void target(string payload, int mode = 0) {} static void caller() { target(mode: 2, payload: \"named\"); } }\n",
        ),
        (
            "ruby",
            "sample.rb",
            "def target(payload:, mode: 0); end\ndef caller; target(mode: 2, payload: \"named\"); end\n",
        ),
    ];

    for (language, path, source) in cases {
        let input = serialized(&run(
            &[(path, source)],
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_name": "payload" }
                ]
            }),
        ));
        assert!(
            input["results"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["text"] == "\"named\"" && row["parameter_name"] == "payload")),
            "missing {language} named input: {input}"
        );
    }
}

#[test]
fn call_input_handles_variadics_defaults_and_spreads_without_guessing() {
    let files = [(
        "sample.py",
        r#"def target(required, optional="default", *rest):
    pass

def caller(items):
    target("required", "explicit", "first", "second")
    target("required")
    target("required", *items)
"#,
    )];

    let variadic = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_name": "rest" }
            ]
        }),
    ));
    let mut texts = variadic["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["text"].as_str().unwrap())
        .collect::<Vec<_>>();
    texts.sort_unstable();
    assert_eq!(texts, vec!["\"first\"", "\"second\""]);

    let optional = serialized(&run(
        &files,
        json!({
            "match": { "kind": "callable", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_name": "optional" }
            ]
        }),
    ));
    assert_eq!(
        optional["results"].as_array().unwrap().len(),
        1,
        "{optional}"
    );
    assert_eq!(optional["results"][0]["text"], "\"explicit\"");
}

#[test]
fn incoming_call_discovery_is_not_limited_by_unrelated_calls() {
    let result = serialized(&run(
        &[(
            "Sample.java",
            r#"class Sample {
    static void first() {}
    static void second() {}
    static void target() {}
    static void caller() { first(); second(); target(); }
}
"#,
        )],
        json!({
            "match": { "kind": "callable", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" }
            ],
            "limit": 1
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(
        result["results"][0]["caller"]["fq_name"], "Sample.caller",
        "{result}"
    );
}

#[test]
fn incoming_call_relations_include_direct_self_recursion() {
    let result = serialized(&run(
        &[("recursive.py", "def recurse():\n    recurse()\n")],
        json!({
            "match": { "kind": "callable", "name": "recurse" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" }
            ]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(
        result["results"][0]["caller"]["fq_name"], result["results"][0]["callee"]["fq_name"],
        "{result}"
    );
}

#[test]
fn python_unbound_method_calls_do_not_consume_the_self_parameter() {
    let result = serialized(&run(
        &[(
            "unbound.py",
            r#"class Sink:
    def send(self, payload):
        return payload

def caller(instance):
    Sink.send(instance, "secret")
"#,
        )],
        json!({
            "match": { "kind": "method", "name": "send" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_name": "payload" }
            ]
        }),
    ));
    assert_eq!(result["results"][0]["text"], "\"secret\"", "{result}");
    assert_eq!(result["results"][0]["parameter_index"], 1, "{result}");
}

#[test]
fn class_target_calls_do_not_borrow_an_arbitrary_member_signature() {
    let result = serialized(&run(
        &[(
            "constructor.py",
            r#"class Base:
    def __init__(self, inherited):
        self.inherited = inherited

class Sink(Base):
    def payload(value):
        return value

def caller():
    Sink("secret")
"#,
        )],
        json!({
            "match": { "kind": "class", "name": "Sink" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_name": "value" }
            ]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 0, "{result}");
}

#[test]
fn keyword_variadics_receive_unmatched_named_arguments() {
    let result = serialized(&run(
        &[(
            "kwargs.py",
            r#"def sink(**kwargs):
    return kwargs

def caller():
    sink(payload="secret", mode=2)
"#,
        )],
        json!({
            "match": { "kind": "callable", "name": "sink" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" },
                { "op": "call_input", "parameter_name": "kwargs" }
            ]
        }),
    ));
    let texts = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["text"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(texts, vec!["\"secret\"", "2"], "{result}");
}

#[test]
fn reference_surface_and_proof_filters_preserve_existing_usage_semantics() {
    let files = [(
        "target.js",
        "class Target { target() {} caller() { this.target(); } }\n",
    )];
    let query = |surface: &str, proof: &str| {
        serialized(&run(
            &files,
            json!({
                "match": { "kind": "class", "name": "Target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "members" },
                    {
                        "op": "references_of",
                        "surface": surface,
                        "proof": proof
                    }
                ]
            }),
        ))
    };
    let external = query("external_usages", "proven");
    assert!(
        external["results"].as_array().unwrap().is_empty(),
        "{external}"
    );

    let lsp = query("lsp_references", "proven");
    assert_eq!(lsp["results"].as_array().unwrap().len(), 1, "{lsp}");
    assert_eq!(lsp["results"][0]["usage_kind"], "self_receiver", "{lsp}");
    assert_eq!(lsp["results"][0]["reference_kind"], "method_call", "{lsp}");

    let unproven = query("lsp_references", "unproven");
    assert!(
        unproven["results"].as_array().unwrap().is_empty(),
        "{unproven}"
    );

    let outbound = |surface: &str| {
        serialized(&run(
            &files,
            json!({
                "match": { "kind": "callable", "name": "caller" },
                "steps": [
                    { "op": "enclosing_decl" },
                    {
                        "op": "uses",
                        "surface": surface,
                        "proof": "proven"
                    }
                ]
            }),
        ))
    };
    let external_outbound = outbound("external_usages");
    assert!(
        external_outbound["results"].as_array().unwrap().is_empty(),
        "{external_outbound}"
    );

    let lsp_outbound = outbound("lsp_references");
    assert_eq!(
        result_fq_names(&lsp_outbound),
        vec!["Target.target"],
        "{lsp_outbound}"
    );
    assert_eq!(
        lsp_outbound["results"][0]["provenance"][0]["steps"][1]["via"]["usage_kind"],
        "self_receiver",
        "{lsp_outbound}"
    );
}

#[test]
fn enclosing_decl_is_inclusive_and_excludes_file_scope() {
    let files = [(
        "app.py",
        "class Outer:\n    def inner(self):\n        audit()\n\ndef audit():\n    pass\n\naudit()\n",
    )];
    let nested = run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "inside": { "kind": "method", "name": "inner" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let nested = serialized(&nested);
    assert_eq!(nested["results"][0]["result_type"], "declaration");
    assert_eq!(nested["results"][0]["kind"], "function");
    assert!(
        nested["results"][0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("inner")),
        "{nested}"
    );

    let declaration = run(
        &files,
        json!({
            "match": { "kind": "method", "name": "inner" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let declaration = serialized(&declaration);
    assert!(
        declaration["results"][0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("inner")),
        "{declaration}"
    );

    let top_level = run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "not_inside": { "kind": "callable" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let top_level = serialized(&top_level);
    assert_eq!(
        top_level["results"][0]["result_type"], "declaration",
        "{top_level}"
    );
    assert_ne!(top_level["results"][0]["kind"], "file scope");
}

#[test]
fn enclosing_decl_skips_synthetic_cpp_members_for_real_parent() {
    let result = run(
        &[(
            "widget.cpp",
            "int audit();\nclass Widget {\npublic:\n    void run(int value = audit());\n};\n",
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"][0]["result_type"], "declaration", "{value}");
    assert_eq!(value["results"][0]["kind"], "class", "{value}");
    assert_eq!(value["results"][0]["fq_name"], "Widget", "{value}");
}

#[test]
fn full_results_include_stable_terminal_and_provenance_identities() {
    let result = run(
        &[(
            "app.py",
            "class Outer:\n    def inner(self):\n        audit()\n",
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "enclosing_decl" }],
            "result_detail": "full"
        }),
    );
    let value = serialized(&result);
    let terminal = &value["results"][0];
    assert_eq!(terminal["result_type"], "declaration", "{value}");
    assert!(terminal["id"].is_string(), "{value}");
    assert!(terminal["node_range"].is_object(), "{value}");

    let trace = &terminal["provenance"][0];
    assert_eq!(trace["seed"]["result_type"], "structural_match", "{value}");
    assert!(trace["seed"]["id"].is_string(), "{value}");
    assert!(trace["seed"]["node_range"].is_object(), "{value}");
    assert_eq!(trace["steps"][0]["op"], "enclosing_decl", "{value}");
    assert_eq!(trace["steps"][0]["result"]["id"], terminal["id"], "{value}");
}

#[test]
fn file_of_deduplicates_and_caps_deterministic_provenance() {
    let calls = (0..17)
        .map(|_| "    audit()")
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!("def run():\n{calls}\n");
    let result = run(
        &[("app.py", &source)],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "file_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["result_type"], "file");
    assert_eq!(value["results"][0]["path"], "app.py");
    assert_eq!(
        value["results"][0]["provenance"].as_array().unwrap().len(),
        16
    );
    assert_eq!(value["results"][0]["provenance_truncated"], true);
}

#[test]
fn ruby_importers_are_direct_and_repeat_for_multiple_hops() {
    let files = [
        ("a.rb", "require_relative 'b'\ndef from_a; end\n"),
        ("b.rb", "require_relative 'c'\ndef from_b; end\n"),
        ("c.rb", "def target; end\n"),
    ];
    let direct = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        }),
    );
    let direct = serialized(&direct);
    assert_eq!(direct["results"].as_array().unwrap().len(), 1, "{direct}");
    assert_eq!(direct["results"][0]["path"], "b.rb");

    let repeated = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "file_of" },
                { "op": "importers_of" },
                { "op": "importers_of" }
            ]
        }),
    );
    let repeated = serialized(&repeated);
    assert_eq!(
        repeated["results"].as_array().unwrap().len(),
        1,
        "{repeated}"
    );
    assert_eq!(repeated["results"][0]["path"], "a.rb");
}

#[test]
fn importers_of_does_not_require_target_language_provider() {
    let result = run(
        &[
            (
                "a.rb",
                "require_relative 'target.php'\ndef from_ruby; end\n",
            ),
            ("target.php", "<?php\nfunction target() {}\n"),
        ],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.rb", "{value}");
}

#[test]
fn side_effect_import_keeps_declaration_free_file_edge() {
    let result = run(
        &[
            (
                "entry.js",
                "import './empty.js';\nexport function target() {}\n",
            ),
            ("empty.js", "// side effect only\n"),
        ],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "empty.js", "{value}");
}

#[test]
fn file_level_import_resolvers_keep_declaration_free_targets() {
    let cases = [
        (
            vec![
                ("go.mod", "module example.com/app\n\ngo 1.22\n"),
                (
                    "main.go",
                    "package main\nimport _ \"example.com/app/sideeffects\"\nfunc target() {}\n",
                ),
                ("sideeffects/init.go", "package sideeffects\n"),
            ],
            "sideeffects/init.go",
        ),
        (
            vec![
                (
                    "entry.ts",
                    "import './empty';\nexport function target() {}\n",
                ),
                ("empty.ts", "// side effect only\n"),
            ],
            "empty.ts",
        ),
        (
            vec![
                (
                    "main.cpp",
                    "#include \"empty.h\"\nint target() { return 1; }\n",
                ),
                ("empty.h", "// intentionally empty\n"),
            ],
            "empty.h",
        ),
    ];

    for (files, expected) in cases {
        let result = run(
            &files,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
            }),
        );
        let value = serialized(&result);
        assert_eq!(
            value["results"].as_array().unwrap().len(),
            1,
            "expected {expected}: {value}"
        );
        assert_eq!(value["results"][0]["path"], expected, "{value}");
    }
}

#[test]
fn direct_importers_work_across_supported_language_adapters() {
    let cases = [
        (
            "python",
            "target",
            vec![
                ("target.py", "def target():\n    pass\n"),
                (
                    "consumer.py",
                    "from target import target\n\ndef consume():\n    target()\n",
                ),
            ],
            "consumer.py",
        ),
        (
            "java",
            "target",
            vec![
                (
                    "example/Target.java",
                    "package example;\npublic class Target { public static void target() {} }\n",
                ),
                (
                    "example/Consumer.java",
                    "package example;\nimport example.Target;\npublic class Consumer { void consume() { Target.target(); } }\n",
                ),
            ],
            "example/Consumer.java",
        ),
        (
            "javascript",
            "target",
            vec![
                ("target.js", "export function target() {}\n"),
                (
                    "consumer.js",
                    "import { target } from './target.js';\ntarget();\n",
                ),
            ],
            "consumer.js",
        ),
        (
            "typescript",
            "target",
            vec![
                ("target.ts", "export function target(): void {}\n"),
                (
                    "consumer.ts",
                    "import { target } from './target';\ntarget();\n",
                ),
            ],
            "consumer.ts",
        ),
        (
            "go",
            "Target",
            vec![
                ("go.mod", "module example.com/project\n\ngo 1.22\n"),
                ("target/target.go", "package target\nfunc Target() {}\n"),
                (
                    "main.go",
                    "package main\nimport \"example.com/project/target\"\nfunc consume() { target.Target() }\n",
                ),
            ],
            "main.go",
        ),
        (
            "cpp",
            "target",
            vec![
                ("target.h", "inline int target() { return 0; }\n"),
                (
                    "main.cpp",
                    "#include \"target.h\"\nint consume() { return target(); }\n",
                ),
            ],
            "main.cpp",
        ),
        (
            "rust",
            "target",
            vec![
                (
                    "Cargo.toml",
                    "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                ("src/shared.rs", "pub fn target() {}\n"),
                (
                    "src/main.rs",
                    "mod shared;\nuse crate::shared::target;\nfn consume() { target(); }\n",
                ),
            ],
            "src/main.rs",
        ),
        (
            "scala",
            "target",
            vec![
                (
                    "example/Target.scala",
                    "package example\nobject Target { def target(): Unit = () }\n",
                ),
                (
                    "example/Consumer.scala",
                    "package example\nimport example.Target\nobject Consumer { def consume(): Unit = Target.target() }\n",
                ),
            ],
            "example/Consumer.scala",
        ),
        (
            "csharp",
            "target",
            vec![
                (
                    "Target.cs",
                    "namespace Example; public class Target { public static void target() {} }\n",
                ),
                (
                    "Consumer.cs",
                    "using Example; public class Consumer { void Consume() { Target.target(); } }\n",
                ),
            ],
            "Consumer.cs",
        ),
        (
            "ruby",
            "target",
            vec![
                ("target.rb", "def target; end\n"),
                (
                    "consumer.rb",
                    "require_relative 'target'\ndef consume; target; end\n",
                ),
            ],
            "consumer.rb",
        ),
    ];

    for (language, name, files, expected) in cases {
        let result = run(
            &files,
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": name },
                "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
            }),
        );
        let value = serialized(&result);
        assert_eq!(
            value["results"].as_array().unwrap().len(),
            1,
            "{language}: {value}"
        );
        assert_eq!(value["results"][0]["path"], expected, "{language}: {value}");
    }
}

#[test]
fn imports_of_is_direct_and_cycles_terminate() {
    let files = [
        ("a.rb", "require_relative 'b'\ndef target; end\n"),
        ("b.rb", "require_relative 'c'\ndef from_b; end\n"),
        ("c.rb", "require_relative 'a'\ndef from_c; end\n"),
    ];
    let result = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "file_of" },
                { "op": "imports_of" },
                { "op": "imports_of" },
                { "op": "imports_of" }
            ]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.rb");
    assert!(!result.truncated);
}

#[test]
fn unsupported_import_provider_is_diagnostic_not_silent() {
    let result = run(
        &[("app.php", "<?php\nfunction target() {}\n")],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
        }),
    );
    let value = serialized(&result);
    assert!(value["results"].as_array().unwrap().is_empty(), "{value}");
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "php"
                && diagnostic.code == CodeQueryDiagnosticCode::UnsupportedImportAnalysis
                && diagnostic.message.contains("structured import analysis")),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn terminal_limit_is_applied_after_file_deduplication() {
    let result = run(
        &[
            ("a.py", "audit()\naudit()\n"),
            ("b.py", "audit()\naudit()\n"),
        ],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "file_of" }],
            "limit": 1
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.py");
    assert!(result.truncated);
}

#[test]
fn pipeline_budget_returns_partial_results_with_diagnostic() {
    let project = InlineTestProject::new()
        .file("app.py", "audit()\naudit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "file_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert_eq!(result.results.len(), 1);
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn intermediate_budget_exhaustion_never_returns_wrong_terminal_type() {
    let project = InlineTestProject::new()
        .file("app.py", "def run():\n    audit()\n    audit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "file_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert!(
        result.results.is_empty(),
        "intermediate rows must not escape"
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
            })
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn reference_scans_charge_workspace_budgets_and_do_not_leak_intermediate_sites() {
    let project = InlineTestProject::new()
        .file(
            "Sample.java",
            "class Sample { static void target() {} static void caller() { target(); } }\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "callable", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of" },
            { "op": "file_of" }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );

    assert!(result.truncated, "{:?}", result.diagnostics);
    assert!(
        result.results.is_empty(),
        "reference sites are not the declared file terminal domain"
    );
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                && diagnostic.message.contains("examining 0 references")
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn call_scans_report_zero_remaining_workspace_budget() {
    let project = InlineTestProject::new()
        .file(
            "Sample.java",
            "class Sample { static void target(String value) {} static void caller() { target(\"secret\"); } }\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "callable", "name": "target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "call_sites_to" },
            { "op": "call_input", "parameter_index": 0 }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );

    assert!(result.truncated, "{:?}", result.diagnostics);
    assert!(result.results.is_empty());
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn inbound_reference_scan_admits_candidate_sources_before_graph_work() {
    let target_source = "class Target { static void target() {} }\n";
    let project = InlineTestProject::new()
        .file("Target.java", target_source)
        .file(
            "User.java",
            "class User { static void caller() { Target.target(); } }\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["Target.java"],
        "match": { "kind": "callable", "name": "target" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "references_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: target_source.len() + 1,
            ..CodeQueryExecutionLimits::default()
        },
    );

    assert!(result.truncated, "{:?}", result.diagnostics);
    assert!(result.results.is_empty());
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn hierarchy_steps_are_direct_by_default_and_depth_is_a_bounded_closure() {
    let files = [(
        "hierarchy.py",
        "class Root:\n    pass\n\nclass Left(Root):\n    pass\n\nclass Right(Root):\n    pass\n\nclass Leaf(Left, Right):\n    pass\n",
    )];

    let direct = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Leaf" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    ));
    assert_eq!(
        result_fq_names(&direct),
        vec!["hierarchy.Left", "hierarchy.Right"]
    );

    let bounded = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Leaf" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "supertypes", "depth": 2 }
            ]
        }),
    ));
    assert_eq!(
        result_fq_names(&bounded),
        vec!["hierarchy.Left", "hierarchy.Right", "hierarchy.Root"]
    );
    let root = bounded["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["fq_name"] == "hierarchy.Root")
        .unwrap();
    assert_eq!(root["provenance"].as_array().unwrap().len(), 2, "{bounded}");
    assert!(
        root["provenance"]
            .as_array()
            .unwrap()
            .iter()
            .all(|trace| trace["steps"].as_array().unwrap().len() == 3),
        "enclosing_decl plus two hierarchy edges should be visible: {bounded}"
    );

    let descendants = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Root" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "subtypes", "transitive": true }
            ]
        }),
    ));
    assert_eq!(
        result_fq_names(&descendants),
        vec!["hierarchy.Left", "hierarchy.Right", "hierarchy.Leaf"]
    );
}

#[test]
fn members_and_owner_preserve_overload_identity_and_round_trip() {
    let files = [(
        "Service.java",
        "class Service {\n  int value;\n  int run(int input) { return input; }\n  String run(String input) { return input; }\n  class Nested {}\n}\n",
    )];
    let members = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Service" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
        }),
    ));
    let results = members["results"].as_array().unwrap();
    assert_eq!(
        results
            .iter()
            .filter(|result| result["fq_name"] == "Service.run")
            .count(),
        2,
        "{members}"
    );
    assert!(
        results
            .iter()
            .any(|result| result["fq_name"] == "Service.value"),
        "{members}"
    );
    assert!(
        results
            .iter()
            .any(|result| result["fq_name"] == "Service.Nested"),
        "{members}"
    );

    let owner = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Service" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "owner" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&owner), vec!["Service"]);
    assert!(owner["results"][0]["provenance"].as_array().unwrap().len() >= 4);
}

#[test]
fn ruby_modules_are_type_owners_for_members_and_owner() {
    let result = serialized(&run(
        &[("tools.rb", "module Tools\n  def run\n  end\nend\n")],
        json!({
            "match": { "kind": "class", "name": "Tools" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "owner" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&result), vec!["Tools"]);
    assert_eq!(result["results"][0]["kind"], "module", "{result}");
}

#[test]
fn invalid_semantic_inputs_are_diagnostic_but_supported_leaves_are_not() {
    let files = [(
        "app.py",
        "def helper():\n    pass\n\nclass Leaf:\n    pass\n",
    )];
    let invalid = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "helper" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
        }),
    );
    assert!(invalid.results.is_empty());
    assert!(
        invalid.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                && diagnostic.message.contains("not a type declaration")
        }),
        "{:?}",
        invalid.diagnostics
    );

    let invalid_hierarchy = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "helper" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    );
    assert!(invalid_hierarchy.results.is_empty());
    assert!(
        invalid_hierarchy
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic
                .message
                .contains("not a supported type declaration")),
        "{:?}",
        invalid_hierarchy.diagnostics
    );

    let leaf = run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Leaf" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    );
    assert!(leaf.results.is_empty());
    assert!(leaf.diagnostics.is_empty(), "{:?}", leaf.diagnostics);
}

#[test]
fn mixed_valid_and_invalid_hierarchy_inputs_keep_valid_rows() {
    let result = serialized(&run(
        &[(
            "mixed.py",
            "class Root:\n    pass\n\nclass Child(Root):\n    pass\n\ndef helper():\n    pass\n",
        )],
        json!({
            "match": {
                "kind": "declaration",
                "name": { "regex": "^(Child|helper)$" }
            },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    ));
    assert_eq!(result_fq_names(&result), vec!["mixed.Root"]);
    assert_eq!(
        result["diagnostics"].as_array().unwrap().len(),
        1,
        "{result}"
    );
    assert!(
        result["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("omitted 1 input"),
        "{result}"
    );
}

#[test]
fn hierarchy_preserves_module_scoped_identity_and_cycles_do_not_return_the_seed() {
    let exact = serialized(&run(
        &[
            ("p1/Base.java", "package p1; public class Base {}\n"),
            ("p2/Base.java", "package p2; public class Base {}\n"),
            (
                "p1/Child.java",
                "package p1; public class Child extends Base {}\n",
            ),
        ],
        json!({
            "match": { "kind": "class", "name": "Child" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    ));
    assert_eq!(result_fq_names(&exact), vec!["p1.Base"]);

    let cyclic = serialized(&run(
        &[("cycle.py", "class A(B):\n    pass\nclass B(A):\n    pass\n")],
        json!({
            "match": { "kind": "class", "name": "A" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "supertypes", "transitive": true }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&cyclic), vec!["cycle.B"]);
}

#[test]
fn subtypes_and_owner_preserve_duplicate_fq_name_identity() {
    let files = [
        (
            "left/Types.java",
            "package duplicate; class Base { void leftMember() {} } class LeftChild extends Base {}\n",
        ),
        (
            "right/Types.java",
            "package duplicate; class Base { void rightMember() {} } class RightChild extends Base {}\n",
        ),
    ];
    let subtypes = serialized(&run(
        &files,
        json!({
            "where": ["left/**"],
            "match": { "kind": "class", "name": "Base" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "subtypes" }]
        }),
    ));
    assert_eq!(result_fq_names(&subtypes), vec!["duplicate.LeftChild"]);
    assert_eq!(
        subtypes["results"][0]["path"], "left/Types.java",
        "{subtypes}"
    );

    let owner = serialized(&run(
        &files,
        json!({
            "where": ["left/**"],
            "match": { "kind": "class", "name": "Base" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "owner" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&owner), vec!["duplicate.Base"]);
    assert_eq!(owner["results"][0]["path"], "left/Types.java", "{owner}");
}

#[test]
fn empty_semantic_frontier_does_not_project_workspace_declarations() {
    let project = InlineTestProject::new()
        .file("app.py", "class Present:\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    workspace
        .analyzer()
        .reset_full_declaration_scan_count_for_test();
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Missing" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
    }))
    .unwrap();
    let result = execute(workspace.analyzer(), &query);
    assert!(result.results.is_empty());
    assert_eq!(
        workspace.analyzer().full_declaration_scan_count_for_test(),
        0
    );
}

#[test]
fn narrow_semantic_query_does_not_project_workspace_declarations() {
    let project = InlineTestProject::new()
        .file(
            "target.py",
            "class Target:\n    def member(self):\n        pass\n",
        )
        .file("unrelated_a.py", "class UnrelatedA:\n    pass\n")
        .file("unrelated_b.py", "class UnrelatedB:\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    workspace
        .analyzer()
        .reset_full_declaration_scan_count_for_test();
    let query = CodeQuery::from_json(&json!({
        "where": ["target.py"],
        "match": { "kind": "class", "name": "Target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "members" },
            { "op": "owner" }
        ]
    }))
    .unwrap();
    let result = execute(workspace.analyzer(), &query);
    assert_eq!(result.results.len(), 1);
    assert_eq!(
        workspace.analyzer().full_declaration_scan_count_for_test(),
        0
    );
}

#[test]
fn members_stop_examining_edges_at_the_pipeline_budget() {
    let methods = (0..20)
        .map(|index| format!("    def member_{index}(self):\n        pass\n"))
        .collect::<String>();
    let project = InlineTestProject::new()
        .file("wide.py", format!("class Wide:\n{methods}"))
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Wide" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "members" }],
        "limit": 100
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert_eq!(result.results.len(), 1);
}

#[test]
fn standalone_owner_stops_scanning_at_the_pipeline_budget() {
    let project = InlineTestProject::new()
        .file(
            "Owners.java",
            "class A {} class B {} class ZTarget { void target() { sink(); } void sink() {} }\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "owner" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    let value = serialized(&result);
    assert!(result.truncated, "{value}");
    assert!(result.results.is_empty(), "{value}");
}

#[test]
fn deep_hierarchy_provenance_is_bounded_by_pipeline_work_budget() {
    let mut source = String::from("class C0:\n    pass\n");
    for index in 1..200 {
        source.push_str(&format!("class C{index}(C{}):\n    pass\n", index - 1));
    }
    let project = InlineTestProject::new().file("deep.py", source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "C0" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true }
        ],
        "limit": 1000
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 1000,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert!(result.results.len() < 100, "{}", result.results.len());
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
        })
    );
}

#[test]
fn deep_call_provenance_is_bounded_by_pipeline_work_budget() {
    let mut source = String::new();
    for index in 0..200 {
        if index + 1 < 200 {
            source.push_str(&format!("def f{index}():\n    f{}()\n\n", index + 1));
        } else {
            source.push_str(&format!("def f{index}():\n    pass\n"));
        }
    }
    let project = InlineTestProject::new().file("deep.py", source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "callable", "name": "f0" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callees", "depth": 200 }
        ],
        "limit": 1000
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 1000,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert!(result.results.len() < 100, "{}", result.results.len());
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn transitive_call_provenance_preserves_alternate_paths() {
    let result = serialized(&run(
        &[(
            "Paths.java",
            r#"class Paths {
    static void a() { b(); c(); }
    static void b() { d(); }
    static void c() { d(); }
    static void d() { e(); }
    static void e() {}
}
"#,
        )],
        json!({
            "match": { "kind": "callable", "name": "a" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "callees", "depth": 4 }
            ]
        }),
    ));
    let terminal = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["fq_name"] == "Paths.e")
        .unwrap_or_else(|| panic!("missing terminal e: {result}"));
    assert_eq!(
        terminal["provenance"].as_array().unwrap().len(),
        2,
        "{result}"
    );
}

#[test]
fn hierarchy_does_not_manufacture_unindexed_library_declarations() {
    let result = run(
        &[("app.py", "class Local(ExternalLibraryType):\n    pass\n")],
        json!({
            "match": { "kind": "class", "name": "Local" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    );
    assert!(result.results.is_empty());
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
}

#[test]
fn hierarchy_budget_is_terminally_partial_but_not_intermediately_mistyped() {
    let project = InlineTestProject::new()
        .file(
            "hierarchy.py",
            "class Root:\n    pass\nclass Left(Root):\n    pass\nclass Right(Root):\n    pass\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let terminal = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Root" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true }
        ]
    }))
    .unwrap();
    let terminal = execute_with_limits(
        workspace.analyzer(),
        &terminal,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(terminal.truncated);
    assert_eq!(terminal.results.len(), 1);

    let intermediate = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Root" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true },
            { "op": "members" }
        ]
    }))
    .unwrap();
    let intermediate = execute_with_limits(
        workspace.analyzer(),
        &intermediate,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(intermediate.truncated);
    assert!(intermediate.results.is_empty());
}

#[test]
fn seed_budget_emits_one_aggregated_diagnostic() {
    let project = InlineTestProject::new()
        .file("app.py", "audit()\naudit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "file_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
            })
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn invalid_programmatic_pipeline_is_diagnostic_not_panic() {
    let project = InlineTestProject::new().file("app.py", "audit()\n").build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let mut query = CodeQuery::from_json(&json!({
        "match": { "kind": "call" }
    }))
    .unwrap();
    query.plan.steps = vec![brokk_bifrost::analyzer::structural::QueryStep::ImportsOf];

    let result = execute(workspace.analyzer(), &query);
    assert!(result.results.is_empty());
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::InvalidPlan
                && diagnostic.message.contains("invalid query at steps[0]")
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn empty_seed_frontier_does_not_build_import_graph() {
    let project = InlineTestProject::new()
        .file("a.rb", "require_relative 'b'\ndef present; end\n")
        .file("b.rb", "def other; end\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["a.rb"],
        "match": { "kind": "function", "name": "absent" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(!result.truncated, "{:?}", result.diagnostics);
    assert!(result.diagnostics.iter().all(|diagnostic| {
        diagnostic.code != CodeQueryDiagnosticCode::ImportGraphBudgetExhausted
    }));
}

#[test]
fn reverse_import_graph_work_is_bounded_and_diagnostic() {
    let project = InlineTestProject::new()
        .file("a.rb", "require_relative 'b'\ndef from_a; end\n")
        .file("b.rb", "require_relative 'c'\ndef from_b; end\n")
        .file("c.rb", "def target; end\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["c.rb"],
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated, "{:?}", result.diagnostics);
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::ImportGraphBudgetExhausted
            })
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn import_graph_budget_rolls_forward_to_later_branches() {
    let project = InlineTestProject::new()
        .file(
            "a.py",
            "import b\nimport c\nimport d\ndef from_a():\n    pass\n",
        )
        .file("b.py", "def from_b():\n    pass\n")
        .file("c.py", "def from_c():\n    pass\n")
        .file("d.py", "def from_d():\n    pass\n")
        .file("y.py", "def from_y():\n    pass\n")
        .file("z.py", "import y\ndef from_z():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            {
                "where": ["a.py"],
                "match": { "kind": "function", "name": "from_a" },
                "steps": [
                    { "op": "file_of" },
                    { "op": "imports_of" },
                    { "op": "imports_of" }
                ]
            },
            {
                "where": ["z.py"],
                "match": { "kind": "function", "name": "from_z" },
                "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
            }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 4,
            ..CodeQueryExecutionLimits::default()
        },
    );
    let value = serialized(&result);
    assert!(result.truncated, "{value}");
    assert!(
        value["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "y.py" && item["provenance"][0]["branch"] == json!([1])),
        "{value}"
    );
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["branch"] == json!([0])
                && diagnostic["message"]
                    .as_str()
                    .unwrap()
                    .contains("import graph budget exhausted")),
        "{value}"
    );
}

#[test]
fn typed_set_operators_use_stable_endpoint_identity_and_branch_order() {
    let files = [(
        "app.py",
        "def alpha():\n    pass\ndef beta():\n    pass\ndef gamma():\n    pass\n",
    )];

    let union = serialized(&run(
        &files,
        json!({
            "union": [
                { "match": { "kind": "function", "name": "beta" } },
                { "match": { "kind": "function", "name": "alpha" } },
                { "match": { "kind": "function", "name": "beta" } }
            ]
        }),
    ));
    let union_results = union["results"].as_array().unwrap();
    assert_eq!(union_results.len(), 2, "{union}");
    assert!(
        union_results[0]["text"]
            .as_str()
            .unwrap()
            .starts_with("def beta"),
        "{union}"
    );
    assert!(
        union_results[1]["text"]
            .as_str()
            .unwrap()
            .starts_with("def alpha"),
        "{union}"
    );
    assert_eq!(
        union_results[0]["provenance"][0]["branch"],
        json!([0]),
        "{union}"
    );
    assert_eq!(
        union_results[0]["provenance"][1]["branch"],
        json!([2]),
        "{union}"
    );

    let intersection = serialized(&run(
        &files,
        json!({
            "intersect": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function", "name": { "regex": "^(alpha|gamma)$" } } }
            ]
        }),
    ));
    let intersection_names = intersection["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            result["text"].as_str().unwrap()[4..]
                .split('(')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(intersection_names, ["alpha", "gamma"], "{intersection}");

    let difference = serialized(&run(
        &files,
        json!({
            "except": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function", "name": "beta" } },
                { "match": { "kind": "function", "name": "gamma" } }
            ]
        }),
    ));
    let difference_names = difference["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            result["text"].as_str().unwrap()[4..]
                .split('(')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(difference_names, ["alpha"], "{difference}");
}

#[test]
fn typed_set_composition_supports_nested_paths_and_common_typed_steps() {
    let result = serialized(&run(
        &[("app.py", "def alpha():\n    pass\ndef beta():\n    pass\n")],
        json!({
            "union": [
                { "match": { "kind": "function", "name": "alpha" } },
                {
                    "intersect": [
                        { "match": { "kind": "function", "name": "beta" } },
                        { "match": { "kind": "function" } }
                    ]
                }
            ],
            "steps": [{ "op": "enclosing_decl" }, { "op": "file_of" }]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["result_type"], "file", "{result}");
    let branches = result["results"][0]["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .map(|trace| trace["branch"].clone())
        .collect::<Vec<_>>();
    assert_eq!(branches, [json!([0]), json!([1, 0]), json!([1, 1])]);
}

#[test]
fn capture_sensitive_suffixes_preserve_each_branch_binding() {
    let files = [(
        "app.ts",
        r#"
interface Runner {
  sendRequest(method: string, payload: object): void;
}
declare const runner: Runner;
const method = "run";
runner.sendRequest(method, {});
"#,
    )];
    let branch = |capture_receiver: bool| {
        if capture_receiver {
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "sendRequest" },
                    "receiver": { "capture": "x" }
                }
            })
        } else {
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "sendRequest" },
                    "args": [{ "capture": "x" }]
                }
            })
        }
    };
    let query = |receiver_first: bool| {
        let branches = if receiver_first {
            vec![branch(true), branch(false)]
        } else {
            vec![branch(false), branch(true)]
        };
        json!({
            "union": branches,
            "steps": [{ "op": "points_to", "capture": "x" }],
            "result_detail": "full"
        })
    };

    let forward = serialized(&run(&files, query(true)));
    let reverse = serialized(&run(&files, query(false)));
    let summarize = |value: &serde_json::Value| {
        let mut rows = value["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["text"].as_str().unwrap().to_string(),
                    row["outcome"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    };
    assert_eq!(
        summarize(&forward),
        summarize(&reverse),
        "forward={forward}\nreverse={reverse}"
    );
    assert_eq!(forward["results"].as_array().unwrap().len(), 2, "{forward}");
    assert_eq!(reverse["results"].as_array().unwrap().len(), 2, "{reverse}");
    for result in forward["results"].as_array().unwrap() {
        assert_eq!(
            result["provenance"].as_array().unwrap().len(),
            1,
            "{result}"
        );
        let expected_branch = if result["text"] == "runner" { 0 } else { 1 };
        assert_eq!(
            result["provenance"][0]["branch"],
            json!([expected_branch]),
            "{result}"
        );
    }
    for result in reverse["results"].as_array().unwrap() {
        assert_eq!(
            result["provenance"].as_array().unwrap().len(),
            1,
            "{result}"
        );
        let expected_branch = if result["text"] == "runner" { 1 } else { 0 };
        assert_eq!(
            result["provenance"][0]["branch"],
            json!([expected_branch]),
            "{result}"
        );
    }
}

#[test]
fn except_capture_suffix_uses_the_surviving_first_branch_binding() {
    let result = serialized(&run(
        &[(
            "app.ts",
            r#"
interface Runner {
  sendRequest(method: string): void;
}
declare const runner: Runner;
runner.sendRequest("run");
"#,
        )],
        json!({
            "except": [
                {
                    "match": {
                        "kind": "call",
                        "callee": { "name": "sendRequest" },
                        "receiver": { "capture": "service" }
                    }
                },
                {
                    "match": {
                        "kind": "call",
                        "callee": { "name": "ignored" }
                    }
                }
            ],
            "steps": [{ "op": "points_to", "capture": "service" }]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["text"], "runner", "{result}");
    assert_eq!(result["results"][0]["provenance"][0]["branch"], json!([0]));
}

#[test]
fn identical_composed_seeds_share_structural_scan_work() {
    let project = InlineTestProject::new()
        .file("app.py", "def target():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function", "name": "target" } },
            { "match": { "kind": "function", "name": "target" } }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(!result.truncated, "{:?}", result.diagnostics);
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(
        value["results"][0]["provenance"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn truncated_identical_seeds_reuse_partial_materialization() {
    let project = InlineTestProject::new()
        .file(
            "app.py",
            "def first():\n    pass\ndef second():\n    pass\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    for operator in ["union", "intersect"] {
        let branches = json!([
            { "match": { "kind": "function" } },
            { "match": { "kind": "function" } }
        ]);
        let query_json = if operator == "union" {
            json!({ "union": branches })
        } else {
            json!({ "intersect": branches })
        };
        let query = CodeQuery::from_json(&query_json).unwrap();
        let result = execute_with_limits(
            workspace.analyzer(),
            &query,
            CodeQueryExecutionLimits {
                max_scanned_files: 1,
                max_pipeline_rows: 2,
                ..CodeQueryExecutionLimits::default()
            },
        );
        let value = serialized(&result);
        assert!(result.truncated, "{operator}: {value}");
        assert_eq!(
            value["results"].as_array().unwrap().len(),
            1,
            "{operator}: {value}"
        );
        assert_eq!(
            value["results"][0]["provenance"].as_array().unwrap().len(),
            2,
            "{operator}: {value}"
        );
        assert!(
            value["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .all(|diagnostic| {
                    !diagnostic["message"]
                        .as_str()
                        .unwrap()
                        .contains("scanned 2 files")
                }),
            "{operator}: {value}"
        );
    }
}

#[test]
fn fair_branch_budgets_preserve_later_branches_and_attribute_diagnostics() {
    let project = InlineTestProject::new()
        .file("a.py", "def first():\n    pass\n")
        .file("b.py", "def second():\n    pass\n")
        .file("z.py", "def important():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "function", "name": "important" } }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    let value = serialized(&result);
    assert!(result.truncated, "{value}");
    assert!(
        value["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["text"].as_str().unwrap().starts_with("def important")),
        "{value}"
    );
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["branch"] == json!([0])
                && diagnostic["message"]
                    .as_str()
                    .unwrap()
                    .contains("pipeline budget exhausted")),
        "{value}"
    );
}

#[test]
fn fair_scan_budgets_do_not_charge_rejected_work_to_later_branches() {
    let large_source = format!(
        "# missing\n{}",
        (0..64)
            .map(|index| format!("value_{index} = {index}\n"))
            .collect::<String>()
    );
    let important_source = "def important():\n    pass\n";
    let project = InlineTestProject::new()
        .file("a.py", &large_source)
        .file("b.py", "value = 1\n")
        .file("z.py", important_source)
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            {
                "where": ["a.py", "b.py"],
                "match": { "kind": "function", "name": "missing" }
            },
            {
                "where": ["z.py"],
                "match": { "kind": "function", "name": "important" }
            }
        ]
    }))
    .unwrap();
    let finds_important = |limits| {
        let result = execute_with_limits(workspace.analyzer(), &query, limits);
        let value = serialized(&result);
        assert!(
            value["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["text"].as_str().unwrap().starts_with("def important")),
            "{value}"
        );
    };

    finds_important(CodeQueryExecutionLimits {
        max_scanned_files: 2,
        ..CodeQueryExecutionLimits::default()
    });
    finds_important(CodeQueryExecutionLimits {
        max_scanned_source_bytes: large_source.len(),
        ..CodeQueryExecutionLimits::default()
    });
    finds_important(CodeQueryExecutionLimits {
        max_fact_nodes: 10,
        ..CodeQueryExecutionLimits::default()
    });
}

#[test]
fn global_result_limit_is_applied_after_set_composition() {
    let result = serialized(&run(
        &[(
            "app.py",
            "def alpha():\n    pass\ndef beta():\n    pass\ndef gamma():\n    pass\n",
        )],
        json!({
            "union": [
                { "match": { "kind": "function", "name": "gamma" } },
                { "match": { "kind": "function" } }
            ],
            "limit": 2
        }),
    ));
    assert_eq!(result["truncated"], true, "{result}");
    let names = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            item["text"].as_str().unwrap()[4..]
                .split('(')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["gamma", "alpha"], "{result}");
}

#[test]
fn set_composition_uses_exact_identity_for_every_typed_terminal_domain() {
    let project = InlineTestProject::new()
        .file(
            "app.ts",
            r#"class Service { run(payload: string) {} }
function target(payload: string) {}
export function caller() {
    const service = new Service();
    service.run("member");
    target("input");
}
"#,
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let cases = [
        (
            "structural_match",
            json!({ "match": { "kind": "function", "name": "target" } }),
        ),
        (
            "declaration",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "enclosing_decl" }]
            }),
        ),
        (
            "file",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "file_of" }]
            }),
        ),
        (
            "reference_site",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "references_of", "proof": "proven" }
                ]
            }),
        ),
        (
            "call_site",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" }
                ]
            }),
        ),
        (
            "expression_site",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 }
                ]
            }),
        ),
        (
            "receiver_analysis",
            json!({
                "match": { "kind": "call", "callee": { "name": "run" } },
                "steps": [{ "op": "receiver_targets" }]
            }),
        ),
    ];

    for (expected_type, branch) in cases {
        let query = CodeQuery::from_json(&json!({
            "union": [branch.clone(), branch]
        }))
        .unwrap_or_else(|error| panic!("{expected_type} query: {error}"));
        let value = serialized(&execute(workspace.analyzer(), &query));
        let results = value["results"].as_array().unwrap();
        assert!(!results.is_empty(), "{expected_type}: {value}");
        assert!(
            results
                .iter()
                .all(|result| result["result_type"] == expected_type),
            "{expected_type}: {value}"
        );
        for result in results {
            let branches = result["provenance"]
                .as_array()
                .unwrap()
                .iter()
                .map(|trace| trace["branch"].clone())
                .collect::<Vec<_>>();
            assert_eq!(
                branches,
                [json!([0]), json!([1])],
                "{expected_type}: {value}"
            );
        }
    }
}

#[test]
fn composed_capability_diagnostics_identify_their_branch() {
    let result = serialized(&run(
        &[
            ("app.py", "audit(payload=\"ok\")\n"),
            ("app.js", "audit({ payload: 'unsupported' });\n"),
        ],
        json!({
            "union": [
                {
                    "languages": ["python"],
                    "match": {
                        "kind": "call",
                        "callee": { "name": "audit" },
                        "kwargs": { "payload": { "capture": "value" } }
                    }
                },
                {
                    "languages": ["javascript"],
                    "match": {
                        "kind": "call",
                        "callee": { "name": "audit" },
                        "kwargs": { "payload": { "capture": "value" } }
                    }
                }
            ]
        }),
    ));

    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["provenance"][0]["branch"], json!([0]));
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["branch"] == json!([1])
                && diagnostic["language"] == "javascript"
                && diagnostic["message"].as_str().unwrap().contains("kwargs")),
        "{result}"
    );
}
