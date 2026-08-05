use super::*;

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
