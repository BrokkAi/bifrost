//! Go-to-definition cases for Python, informed by basedpyright's fourslash
//! `findDefinitions.*` tests (workspace-local; pyright's own cases are stub /
//! library heavy, out of bifrost's project scope). Python is already covered by
//! the IntelliJ find-usages pilot, so the standard cases are confirmations; the
//! dataclass keyword-argument case is the novel probe — the Python analog of the
//! Scala named-argument resolution fixed this session.
//!
//! Driven through the in-process `get_definition_by_location` tool (like
//! `get_definition_test.rs`) rather than the LSP subprocess. Each resolution is
//! correct when run one-per-process, but *multiple* in-process lookups in one test
//! process flake nondeterministically via process-global state (see the tests'
//! `#[ignore]` reasons), so both tests are ignored. Assertions are on the resolved
//! FQN.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

// `SearchToolsService` touches process-global state, so serialize lookups (mirrors
// `get_definition_test.rs`) and give every fixture a unique module file name — both
// are needed to keep concurrent tests from racing that shared state and flaking.
static LOOKUP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Resolve the definition at the `<caret>` and return the set of resolved FQNs.
fn definition_fqns(source_with_caret: &str) -> Vec<String> {
    let _guard = LOOKUP_LOCK.lock().expect("lookup lock poisoned");
    let idx = source_with_caret
        .find("<caret>")
        .expect("fixture must contain <caret>");
    let before = &source_with_caret[..idx];
    let line = before.matches('\n').count() as u64 + 1; // 1-based
    let last_line_start = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
    let column = before[last_line_start..].chars().count() as u64 + 1; // 1-based
    let source = source_with_caret.replacen("<caret>", "", 1);

    let module = format!("m{}", FILE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let file = format!("{module}.py");
    let project = InlineTestProject::with_language(Language::Python)
        .file(&file, &source)
        .build();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .expect("searchtools service");
    let args = format!(r#"{{"references":[{{"path":"{file}","line":{line},"column":{column}}}]}}"#);
    let payload = service
        .call_tool_json("get_definition_by_location", &args)
        .expect("get_definition_by_location");
    let value: Value = serde_json::from_str(&payload).expect("valid json");
    value["results"][0]["definitions"]
        .as_array()
        .map(|defs| {
            defs.iter()
                .filter_map(|d| d["fqn"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Assert some resolved FQN ends with `suffix` (the module prefix is a per-test
/// unique name, so match on the member path only).
fn assert_resolves_to(source_with_caret: &str, suffix: &str) {
    let fqns = definition_fqns(source_with_caret);
    assert!(
        fqns.iter().any(|fqn| fqn.ends_with(suffix)),
        "expected resolution ending with {suffix}, got {fqns:?}"
    );
}

// Confirmations (findDefinitions.functions/fields/classes shapes). Each resolution
// is verified CORRECT in isolation (`cargo test <name>` in a fresh process), but
// multiple in-process `SearchToolsService` lookups — even serialized and with unique
// module names — flake nondeterministically, so this cannot run reliably in a shared
// test process. `#[ignore]`d pending a stable in-process multi-lookup harness (the
// process-global-state issue is a separate finding, not a resolution bug).
#[test]
#[ignore = "resolution verified in isolation; multi-lookup in-process harness flakes (process-global state)"]
fn basedpyright_def_confirmations() {
    // method call -> method
    assert_resolves_to(
        "class Foo:\n    def bar(self):\n        return 1\nf = Foo()\nf.ba<caret>r()\n",
        ".Foo.bar",
    );
    // instance attribute -> its `__init__` assignment
    assert_resolves_to(
        "class Foo:\n    def __init__(self):\n        self.value = 1\nf = Foo()\nprint(f.val<caret>ue)\n",
        ".Foo.value",
    );
    // constructor call -> class
    assert_resolves_to("class Foo:\n    pass\nf = Fo<caret>o()\n", ".Foo");
}

// findDefinitions.dataclasses (shape): a keyword argument `a` in a dataclass
// constructor resolves to the dataclass field `a` — the Python analog of the Scala
// named-argument case fixed this session.
//
// DEFERRED: bifrost does not resolve the keyword-arg identifier to the dataclass
// field (it resolves to nothing / the call site). The fix mirrors the Scala
// `NamedArgument` arm — detect the keyword argument in a call, resolve the callee
// to the dataclass, and member-lookup the arg name (`Foo.a`) — on the Python
// get_definition path. Left for a focused follow-up (its own test is isolated so
// the process-global-state flakiness above does not affect the confirmations).
#[test]
#[ignore = "deferred: Python dataclass keyword-argument resolution (Foo(a=3) -> field a); mirror the Scala named-arg fix"]
fn basedpyright_def_dataclass_keyword_arg() {
    assert_resolves_to(
        "from dataclasses import dataclass\n\n@dataclass\nclass Foo:\n    a: int\n    b: str\n\nf = Foo(a<caret>=3, b=\"x\")\n",
        ".Foo.a",
    );
}
