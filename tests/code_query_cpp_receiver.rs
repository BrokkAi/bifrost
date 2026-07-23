mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute_workspace};
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

#[test]
fn cpp_receiver_traversal_uses_neutral_values_and_exact_members() {
    let files = [(
        "receiver.cpp",
        r#"
struct Service {
    void run() {}
    virtual void virtual_run() {}
    void current() { this->run(); }
    static Service make() { return Service{}; }
    static Service* create() { return new Service(); }
};

struct Other {
    void run() {}
};

void caller(Service* parameter) {
    Service service;
    Service* local = new Service();
    service.run();
    local->run();
    local->virtual_run();
    parameter->run();
    Service::make().run();
    Service::create()->run();
}
"#,
    )];

    let receiver = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "local", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(receiver["results"][0]["outcome"], "precise", "{receiver}");
    assert_eq!(
        receiver["results"][0]["values"][0]["receiver_value_kind"], "allocation_site",
        "{receiver}"
    );
    assert_eq!(
        receiver["results"][0]["values"][0]["type_declaration"]["fq_name"], "Service",
        "{receiver}"
    );

    let parameter = serialized(&run(
        &[(
            "parameter.cpp",
            r#"
struct Service {
    void run() {}
};

void caller(Service* parameter) {
    parameter->run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
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
    assert_eq!(
        parameter["results"][0]["values"][0]["declaration"]["fq_name"], "Service",
        "{parameter}"
    );

    let points_to = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "local", "capture": "receiver" }
            },
            "steps": [{ "op": "points_to", "capture": "receiver" }]
        }),
    ));
    assert_eq!(points_to["results"][0]["outcome"], "precise", "{points_to}");
    assert_eq!(
        points_to["results"][0]["values"][0]["receiver_value_kind"], "allocation_site",
        "{points_to}"
    );
    assert_eq!(
        points_to["results"][0]["values"][0]["type_declaration"]["fq_name"], "Service",
        "{points_to}"
    );

    let members = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "local", "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(members["results"][0]["outcome"], "precise", "{members}");
    let targets = members["results"][0]["member_targets"]
        .as_array()
        .expect("member targets");
    assert_eq!(targets.len(), 1, "{members}");
    assert_eq!(targets[0]["fq_name"], "Service.run", "{members}");
    assert!(
        !targets
            .iter()
            .any(|target| target["fq_name"] == "Other.run"),
        "{members}"
    );

    let object_members = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        object_members["results"][0]["outcome"], "ambiguous",
        "{object_members}"
    );
    assert_eq!(
        object_members["results"][0]["member_targets"][0]["fq_name"], "Service.run",
        "{object_members}"
    );

    let current = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "this", "capture": "receiver" }
            },
            "steps": [{ "op": "receiver_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(current["results"][0]["outcome"], "precise", "{current}");
    assert_eq!(
        current["results"][0]["values"][0]["receiver_value_kind"], "current_receiver",
        "{current}"
    );
    assert_eq!(
        current["results"][0]["values"][0]["declaration"]["fq_name"], "Service",
        "{current}"
    );

    let virtual_member = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "virtual_run" },
                "receiver": { "name": "local", "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));
    assert_eq!(
        virtual_member["results"][0]["outcome"], "ambiguous",
        "{virtual_member}"
    );
    assert_eq!(
        virtual_member["results"][0]["member_targets"][0]["fq_name"], "Service.virtual_run",
        "{virtual_member}"
    );

    let factory_files = [(
        "factory.cpp",
        r#"
struct Service {
    void run() {}
    static Service make() { return Service{}; }
    static Service* create() { return new Service(); }
};

void caller() {
    Service::make().run();
    Service::create()->run();
}
"#,
    )];
    let factory = serialized(&run(
        &factory_files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": {
                    "kind": "call",
                    "callee": { "name": "create" },
                    "capture": "factory"
                }
            },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let factory_row = factory["results"]
        .as_array()
        .expect("factory receiver rows")
        .iter()
        .find(|row| row["text"] == "Service::create()")
        .expect("factory-result receiver row");
    assert_eq!(factory_row["outcome"], "ambiguous", "{factory}");
    assert!(
        factory_row["values"]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| {
                value["receiver_value_kind"] == "instance_type"
                    && value["declaration"]["fq_name"] == "Service"
            })),
        "{factory}"
    );

    let factory_member = serialized(&run(
        &factory_files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": {
                    "kind": "call",
                    "callee": { "name": "make" },
                    "capture": "factory"
                }
            },
            "steps": [{ "op": "member_targets", "capture": "factory" }]
        }),
    ));
    let factory_member_row = factory_member["results"]
        .as_array()
        .expect("factory member rows")
        .iter()
        .find(|row| row["text"] == "Service::make()")
        .expect("by-value factory member row");
    assert_eq!(
        factory_member_row["outcome"], "ambiguous",
        "{factory_member}"
    );
    assert_eq!(
        factory_member_row["member_targets"][0]["fq_name"], "Service.run",
        "{factory_member}"
    );
}

#[test]
fn cpp_instance_factory_chains_use_exact_member_and_cross_file_return_metadata() {
    let local_points_to = serialized(&run(
        &[(
            "local.cpp",
            r#"
struct Service {
    void run() {}
};

struct OtherService {
    void run() {}
};

struct Factory {
    Service make() { return Service{}; }
};

struct OtherFactory {
    OtherService make() { return OtherService{}; }
};

void caller() {
    Factory factory;
    factory.make().run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": {
                    "kind": "call",
                    "callee": { "name": "make" },
                    "capture": "factory"
                }
            },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let local_row = local_points_to["results"]
        .as_array()
        .expect("local factory receiver rows")
        .iter()
        .find(|row| row["text"] == "factory.make()")
        .expect("local instance factory-result receiver row");
    assert!(
        local_row["values"].as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value["receiver_value_kind"] == "instance_type"
                    && value["declaration"]["fq_name"] == "Service"
            })
        }),
        "{local_points_to}"
    );
    assert!(
        local_row["values"].as_array().is_some_and(|values| values
            .iter()
            .all(|value| value["declaration"]["fq_name"] != "OtherService")),
        "{local_points_to}"
    );

    let files = [
        (
            "service.hpp",
            r#"
struct Service {
    void run() {}
};

struct OtherService {
    void run() {}
};
"#,
        ),
        (
            "factory.hpp",
            r#"
#include "service.hpp"

struct Factory {
    Service make() { return Service{}; }
};

struct OtherFactory {
    OtherService make() { return OtherService{}; }
};

struct SplitFactory {
    Service make();
};
"#,
        ),
        (
            "factory.cpp",
            r#"
#include "factory.hpp"

Service SplitFactory::make() {
    return Service{};
}
"#,
        ),
        (
            "caller.cpp",
            r#"
#include "factory.hpp"

void caller(Factory& factory) {
    factory.make().run();
}

void split_caller(SplitFactory& split) {
    split.make().run();
}
"#,
        ),
    ];

    let points_to = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": {
                    "kind": "call",
                    "callee": { "name": "make" },
                    "capture": "factory"
                }
            },
            "steps": [{ "op": "points_to", "capture": "factory" }]
        }),
    ));
    let row = points_to["results"]
        .as_array()
        .expect("factory receiver rows")
        .iter()
        .find(|row| row["path"] == "caller.cpp" && row["text"] == "factory.make()")
        .expect("instance factory-result receiver row");
    let values = row["values"].as_array().expect("factory values");
    assert!(
        values.iter().any(|value| {
            value["receiver_value_kind"] == "instance_type"
                && value["declaration"]["fq_name"] == "Service"
        }),
        "{points_to}"
    );
    assert!(
        values
            .iter()
            .all(|value| value["declaration"]["fq_name"] != "OtherService"),
        "{points_to}"
    );
    let split_row = points_to["results"]
        .as_array()
        .expect("factory receiver rows")
        .iter()
        .find(|row| row["path"] == "caller.cpp" && row["text"] == "split.make()")
        .expect("split header/source factory-result receiver row");
    assert!(
        split_row["values"].as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value["receiver_value_kind"] == "instance_type"
                    && value["declaration"]["fq_name"] == "Service"
            })
        }),
        "{points_to}"
    );

    let members = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": {
                    "kind": "call",
                    "callee": { "name": "make" },
                    "capture": "factory"
                }
            },
            "steps": [{ "op": "member_targets", "capture": "factory" }]
        }),
    ));
    let row = members["results"]
        .as_array()
        .expect("factory member rows")
        .iter()
        .find(|row| row["path"] == "caller.cpp" && row["text"] == "factory.make()")
        .expect("cross-file factory member row");
    let targets = row["member_targets"].as_array().expect("member targets");
    assert!(
        targets
            .iter()
            .any(|target| target["fq_name"] == "Service.run"),
        "{members}"
    );
    assert!(
        targets
            .iter()
            .all(|target| target["fq_name"] != "OtherService.run"),
        "{members}"
    );
    let split_row = members["results"]
        .as_array()
        .expect("factory member rows")
        .iter()
        .find(|row| row["path"] == "caller.cpp" && row["text"] == "split.make()")
        .expect("split header/source factory member row");
    assert!(
        split_row["member_targets"]
            .as_array()
            .is_some_and(|targets| targets
                .iter()
                .any(|target| target["fq_name"] == "Service.run")),
        "{members}"
    );
}

#[test]
fn cpp_receiver_type_lookup_respects_lexical_namespace_and_never_prefers_same_file() {
    let files = [
        (
            "a.hpp",
            r#"
namespace A {
struct Service {
    void run() {}
};
}
"#,
        ),
        (
            "b.hpp",
            r#"
namespace B {
struct Service {
    void run() {}
};
}
"#,
        ),
        (
            "caller.cpp",
            r#"
namespace B {
void caller(Service* service) {
    service->run();
}
}

namespace Missing {
void unresolved(Service* unknown) {
    unknown->run();
}
}
"#,
        ),
    ];
    let report = serialized(&run(
        &files,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    let resolved = report["results"]
        .as_array()
        .expect("receiver rows")
        .iter()
        .find(|row| row["text"] == "service")
        .expect("B receiver row");
    assert_eq!(resolved["outcome"], "precise", "{report}");
    assert_eq!(
        resolved["member_targets"][0]["fq_name"], "B.Service.run",
        "{report}"
    );
    assert!(
        !resolved["member_targets"]
            .as_array()
            .expect("resolved member targets")
            .iter()
            .any(|target| target["fq_name"] == "A.Service.run"),
        "{report}"
    );

    let unresolved = report["results"]
        .as_array()
        .expect("receiver rows")
        .iter()
        .find(|row| row["text"] == "unknown")
        .expect("missing-namespace receiver row");
    assert_eq!(unresolved["outcome"], "unknown", "{report}");
    assert!(unresolved.get("member_targets").is_none(), "{report}");
}

#[test]
fn cpp_absolute_receiver_type_excludes_same_named_lexical_namespace() {
    let report = serialized(&run(
        &[(
            "absolute.cpp",
            r#"
namespace A {
struct Service {
    void run() {}
};
}

namespace Inner {
namespace A {
struct Service {
    void run() {}
};
}

void caller(::A::Service& service) {
    service.run();
}
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "name": "service", "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    assert_eq!(report["results"][0]["outcome"], "precise", "{report}");
    assert_eq!(
        report["results"][0]["member_targets"][0]["fq_name"], "A.Service.run",
        "{report}"
    );
    assert!(
        !report["results"][0]["member_targets"]
            .as_array()
            .expect("member targets")
            .iter()
            .any(|target| target["fq_name"] == "Inner.A.Service.run"),
        "{report}"
    );
}

#[test]
fn cpp_local_callable_shadow_never_uses_same_name_global_factory() {
    let report = serialized(&run(
        &[(
            "shadow.cpp",
            r#"
struct Service {
    void run() {}
};

struct Other {
    void run() {}
};

Service make() {
    return Service{};
}

void caller() {
    auto make = []() { return Other{}; };
    make().run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": {
                    "kind": "call",
                    "callee": { "name": "make" },
                    "capture": "receiver"
                }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    let row = report["results"]
        .as_array()
        .expect("receiver rows")
        .iter()
        .find(|row| row["text"] == "make()")
        .expect("shadowed local call receiver");
    assert_ne!(row["outcome"], "precise", "{report}");
    assert!(
        row.get("member_targets")
            .and_then(Value::as_array)
            .is_none_or(|targets| targets
                .iter()
                .all(|target| target["fq_name"] != "Service.run")),
        "{report}"
    );
}

#[test]
fn cpp_member_lookup_uses_nearest_exact_base_declaration() {
    let report = serialized(&run(
        &[(
            "inheritance.cpp",
            r#"
struct Base {
    void run() {}
};

struct Derived : Base {};

struct Override : Base {
    void run() {}
};

void caller(Derived& inherited, Override& overridden) {
    inherited.run();
    overridden.run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    let rows = report["results"].as_array().expect("receiver rows");
    let inherited = rows
        .iter()
        .find(|row| row["text"] == "inherited")
        .expect("inherited receiver");
    let inherited_targets = inherited["member_targets"]
        .as_array()
        .expect("inherited member targets");
    assert_eq!(inherited_targets.len(), 1, "{report}");
    assert_eq!(inherited_targets[0]["fq_name"], "Base.run", "{report}");

    let overridden = rows
        .iter()
        .find(|row| row["text"] == "overridden")
        .expect("overridden receiver");
    let overridden_targets = overridden["member_targets"]
        .as_array()
        .expect("override member targets");
    assert_eq!(overridden_targets.len(), 1, "{report}");
    assert_eq!(overridden_targets[0]["fq_name"], "Override.run", "{report}");
    assert!(
        overridden_targets
            .iter()
            .all(|target| target["fq_name"] != "Base.run"),
        "{report}"
    );
}

#[test]
fn cpp_member_targets_distinguish_virtual_and_non_virtual_diamonds() {
    let report = serialized(&run(
        &[(
            "diamonds.cpp",
            r#"
struct Base {
    void run() {}
};

struct NonVirtualLeft : Base {};
struct NonVirtualRight : Base {};
struct NonVirtualDiamond : NonVirtualLeft, NonVirtualRight {};

struct VirtualLeft : virtual Base {};
struct VirtualRight : virtual Base {};
struct VirtualDiamond : VirtualLeft, VirtualRight {};

void caller(NonVirtualDiamond& non_virtual, VirtualDiamond& virtual_shared) {
    non_virtual.run();
    virtual_shared.run();
}
"#,
        )],
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    let rows = report["results"].as_array().expect("receiver rows");
    let non_virtual = rows
        .iter()
        .find(|row| row["text"] == "non_virtual")
        .expect("non-virtual diamond receiver");
    assert_eq!(non_virtual["outcome"], "ambiguous", "{report}");
    assert_eq!(
        non_virtual["member_targets"][0]["fq_name"], "Base.run",
        "{report}"
    );

    let virtual_shared = rows
        .iter()
        .find(|row| row["text"] == "virtual_shared")
        .expect("virtual diamond receiver");
    assert_eq!(virtual_shared["outcome"], "precise", "{report}");
    assert_eq!(
        virtual_shared["member_targets"][0]["fq_name"], "Base.run",
        "{report}"
    );
}

#[test]
fn cpp_data_field_member_targets_are_precise_without_dispatch_metadata() {
    let report = serialized(&run(
        &[(
            "fields.cpp",
            r#"
struct Service {
    int value;
};

struct Other {
    int value;
};

int read() {
    Service* service = new Service();
    return service->value;
}
"#,
        )],
        json!({
            "match": {
                "kind": "field_access",
                "object": { "name": "service", "capture": "receiver" },
                "field": { "name": "value" }
            },
            "steps": [{ "op": "member_targets", "capture": "receiver" }]
        }),
    ));

    assert_eq!(report["results"][0]["outcome"], "precise", "{report}");
    assert_eq!(
        report["results"][0]["member_targets"][0]["fq_name"], "Service.value",
        "{report}"
    );
    assert!(
        report["results"][0]["member_targets"]
            .as_array()
            .expect("member targets")
            .iter()
            .all(|target| target["fq_name"] != "Other.value"),
        "{report}"
    );
}

#[test]
fn plain_c_receiver_traversal_is_explicitly_unsupported() {
    let report = serialized(&run(
        &[(
            "plain.c",
            r#"
struct Service {
    void (*run)(void);
};

void invoke(struct Service* service) {
    service->run();
}
"#,
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

    assert_eq!(report["results"][0]["outcome"], "unsupported", "{report}");
    assert_eq!(
        report["results"][0]["reason"], "cpp_c_receiver_unsupported",
        "{report}"
    );
    assert!(report["results"][0].get("values").is_none(), "{report}");
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| diagnostics.iter().any(|diagnostic| {
                diagnostic["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("cpp_c_receiver_unsupported"))
            })),
        "{report}"
    );
}
