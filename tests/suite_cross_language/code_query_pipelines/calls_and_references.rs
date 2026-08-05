use super::*;

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
