//! Go-to-definition corner cases borrowed from rust-analyzer's own
//! `crates/ide/src/goto_definition.rs` inline test corpus (the `check(r#"..."#)`
//! fixtures with `$0` cursor + `//^^^` definition markers). Each case here cites
//! the upstream test name it was ported from.
//!
//! Scope: only rust-analyzer cases that land inside bifrost's CodeUnit envelope
//! (struct/enum/trait/impl items, methods, fields, associated functions). Cases
//! that target locals, params, ranges, macros, or control-flow keywords are out
//! of bifrost's model by architecture and are intentionally not ported.
//!
//! Driven through the real LSP server (`textDocument/definition`) so this also
//! exercises cursor resolution, exactly like the upstream tests drive the IDE.

mod common;

use common::lsp_client::{LspServer, uri_for};
use serde_json::Value;
use std::path::PathBuf;
use tempfile::TempDir;

fn split_caret(source: &str) -> (String, u64, u64) {
    let idx = source
        .find("<caret>")
        .expect("fixture must contain <caret>");
    let before = &source[..idx];
    let line = before.matches('\n').count() as u64;
    let last_line_start = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
    let character = before[last_line_start..].chars().count() as u64;
    (source.replacen("<caret>", "", 1), line, character)
}

fn definition_lines(name: &str, source_with_caret: &str) -> (TempDir, Vec<u64>) {
    definition_lines_in_project(&[(name, source_with_caret)], name, name)
}

fn definition_lines_in_project(
    files: &[(&str, &str)],
    caret_file: &str,
    target_file: &str,
) -> (TempDir, Vec<u64>) {
    let source_with_caret = files
        .iter()
        .find(|(name, _)| *name == caret_file)
        .map(|(_, source)| *source)
        .expect("caret file must exist");
    let (source, line, character) = split_caret(source_with_caret);
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    for (name, contents) in files {
        let file = root.join(name);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).expect("create fixture parent");
        }
        let contents = if *name == caret_file {
            source.as_str()
        } else {
            contents
        };
        std::fs::write(file, contents).expect("write fixture");
    }

    let mut server = LspServer::start(&root);
    let file: PathBuf = root.join(caret_file);
    let response = server.text_document_position_response(
        "textDocument/definition",
        &uri_for(&file),
        line,
        character,
    );
    server.shutdown();

    let file_uri = uri_for(&root.join(target_file));
    let lines = match &response["result"] {
        Value::Array(items) => items
            .iter()
            .filter(|loc| loc["uri"].as_str() == Some(file_uri.as_str()))
            .filter_map(|loc| loc["range"]["start"]["line"].as_u64())
            .collect(),
        Value::Object(loc) => loc["range"]["start"]["line"].as_u64().into_iter().collect(),
        _ => Vec::new(),
    };
    (temp, lines)
}

fn assert_resolves_to_line(name: &str, source_with_caret: &str, expected: u64) {
    let (_t, lines) = definition_lines(name, source_with_caret);
    assert!(
        lines.contains(&expected),
        "expected {name} to resolve to line {expected}, got {lines:?}"
    );
}

fn assert_project_resolves_to_line(
    files: &[(&str, &str)],
    caret_file: &str,
    target_file: &str,
    expected: u64,
) {
    let (_t, lines) = definition_lines_in_project(files, caret_file, target_file);
    assert!(
        lines.contains(&expected),
        "expected {caret_file} to resolve to {target_file}:{expected}, got {lines:?}"
    );
}

fn assert_project_resolves_to_nothing(files: &[(&str, &str)], caret_file: &str) {
    let (_t, lines) = definition_lines_in_project(files, caret_file, caret_file);
    assert!(
        lines.is_empty(),
        "expected {caret_file} to resolve to nothing, got {lines:?}"
    );
}

fn assert_resolves_to_nothing(name: &str, source_with_caret: &str) {
    let (_t, lines) = definition_lines(name, source_with_caret);
    assert!(
        lines.is_empty(),
        "expected {name} to resolve to nothing, got {lines:?}"
    );
}

// rust-analyzer: goto_def_for_methods — `foo.frobnicate()` where `foo: &Foo` is a
// typed parameter; resolves to the inherent method declaration (line 2).
#[test]
fn ra_goto_def_for_methods() {
    assert_resolves_to_line(
        "m.rs",
        "struct Foo;\nimpl Foo {\n    fn frobnicate(&self) { }\n}\n\nfn bar(foo: &Foo) {\n    foo.frobnicate<caret>();\n}\n",
        2,
    );
}

// rust-analyzer: goto_def_for_fields — `foo.spam` field access on a typed
// parameter resolves to the field declaration (line 1).
#[test]
fn ra_goto_def_for_fields() {
    assert_resolves_to_line(
        "f.rs",
        "struct Foo {\n    spam: u32,\n}\n\nfn bar(foo: &Foo) {\n    foo.spam<caret>;\n}\n",
        1,
    );
}

#[test]
fn rust_field_access_honors_receiver_focus() {
    assert_resolves_to_nothing(
        "receiver.rs",
        "struct Args {\n    dry_run: bool,\n}\nfn apply(arg: &Args) {\n    let _ = arg<caret>.dry_run;\n}\n",
    );
    assert_resolves_to_line(
        "field.rs",
        "struct Args {\n    dry_run: bool,\n}\nfn apply(arg: &Args) {\n    let _ = arg.dry_run<caret>;\n}\n",
        1,
    );
}

#[test]
fn rust_self_method_receiver_resolves_to_enclosing_type() {
    assert_resolves_to_line(
        "self_receiver.rs",
        "struct Problem;\nimpl Problem {\n    fn execute_shared(&self) {}\n    fn execute(&self) {\n        self<caret>.execute_shared();\n    }\n}\n",
        0,
    );
}

// rust-analyzer: goto_def_for_ufcs_inherent_methods — `Foo::frobnicate()`
// associated-function call resolves to the inherent method (line 2).
#[test]
fn ra_goto_def_for_ufcs_inherent_methods() {
    assert_resolves_to_line(
        "u.rs",
        "struct Foo;\nimpl Foo {\n    fn frobnicate() { }\n}\n\nfn bar(foo: &Foo) {\n    Foo::frobnicate<caret>();\n}\n",
        2,
    );
}

// rust-analyzer: goto_def_for_ufcs_trait_methods_through_traits — `Foo::frob()`
// where `Foo` is a trait resolves to the trait method signature (line 1).
#[test]
fn ra_goto_def_for_ufcs_trait_methods_through_traits() {
    assert_resolves_to_line(
        "t.rs",
        "trait Foo {\n    fn frobnicate();\n}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
        1,
    );
}

// rust-analyzer: goto_def_for_ufcs_trait_methods_through_self — `Foo::frob()`
// where `Foo: Trait` resolves through the trait-candidate lookup (#433) to the
// trait method signature (line 2).
#[test]
fn ra_goto_def_for_ufcs_trait_methods_through_self() {
    assert_resolves_to_line(
        "ts.rs",
        "struct Foo;\ntrait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
        2,
    );
}

#[test]
fn rust_ufcs_trait_method_ambiguity_resolves_to_nothing() {
    assert_resolves_to_nothing(
        "ambiguous.rs",
        "struct Foo;\ntrait One {\n    fn frobnicate();\n}\ntrait Two {\n    fn frobnicate();\n}\nimpl One for Foo {}\nimpl Two for Foo {}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
    );
}

#[test]
fn rust_ufcs_trait_method_resolves_through_module_qualified_implementer() {
    assert_project_resolves_to_line(
        &[
            (
                "src/service.rs",
                "pub struct Foo;\npub trait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n",
            ),
            (
                "src/main.rs",
                "mod service;\nuse service::Trait;\n\nfn bar() {\n    service::Foo::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/main.rs",
        "src/service.rs",
        2,
    );
}

#[test]
fn rust_ufcs_trait_method_requires_visible_trait() {
    assert_project_resolves_to_nothing(
        &[
            (
                "src/service.rs",
                "pub struct Foo;\npub trait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n",
            ),
            (
                "src/main.rs",
                "mod service;\n\nfn bar() {\n    service::Foo::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/main.rs",
    );
}

// #433: a glob import (`use service::*;`) makes the trait visible at the call
// site even though glob bindings never land in the file's named-import maps.
// Glob visibility resolves through the module's export index, so the fixture
// needs a real crate shape (`Cargo.toml` + a `pub mod` chain from the root).
#[test]
fn rust_ufcs_trait_method_resolves_through_glob_imported_trait() {
    assert_project_resolves_to_line(
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/service.rs",
                "pub struct Foo;\npub trait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n",
            ),
            (
                "src/lib.rs",
                "pub mod service;\nuse service::*;\n\nfn bar() {\n    service::Foo::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/lib.rs",
        "src/service.rs",
        2,
    );
}

// #433: cross-file `Worker::frobnicate()` resolves through an imported trait
// implemented for `Worker`.
#[test]
fn ra_goto_def_ufcs_trait_method_cross_file() {
    assert_project_resolves_to_line(
        &[
            (
                "src/contracts.rs",
                "pub trait Runnable {\n    fn frobnicate();\n}\n",
            ),
            (
                "src/main.rs",
                "mod contracts;\nuse contracts::Runnable;\npub struct Worker;\nimpl Runnable for Worker {}\nfn bar() {\n    Worker::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/main.rs",
        "src/contracts.rs",
        1,
    );
}

// #433: when two implemented traits declare the method, call-site scope filters
// candidates to the imported trait.
#[test]
fn ra_goto_def_ufcs_trait_method_scope_filtered() {
    assert_project_resolves_to_line(
        &[
            (
                "src/contracts.rs",
                "pub trait Runnable {\n    fn frobnicate();\n}\npub trait Hidden {\n    fn frobnicate();\n}\n",
            ),
            (
                "src/main.rs",
                "mod contracts;\nuse contracts::Runnable;\npub struct Worker;\nimpl Runnable for Worker {}\nimpl contracts::Hidden for Worker {}\nfn bar() {\n    Worker::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/main.rs",
        "src/contracts.rs",
        1,
    );
}

// #433: `Self::assoc()` inside an inherent impl resolves through a trait the
// enclosing type implements (line 2 is the trait method signature).
#[test]
fn rust_self_assoc_fn_resolves_through_implemented_trait() {
    assert_resolves_to_line(
        "sa.rs",
        "struct Foo;\ntrait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\nimpl Foo {\n    fn call() {\n        Self::frobnicate<caret>();\n    }\n}\n",
        2,
    );
}

// rust-analyzer: goto_definition_on_self — `Self {}` in an inherent impl resolves
// to the struct declaration (line 0).
#[test]
fn ra_goto_definition_on_self() {
    assert_resolves_to_line(
        "s.rs",
        "struct Foo;\nimpl Foo {\n    pub fn new() -> Self {\n        Self<caret> {}\n    }\n}\n",
        0,
    );
}

#[test]
fn rust_self_variant_honors_owner_focus() {
    assert_resolves_to_line(
        "self_owner.rs",
        "enum Pattern {\n    Empty,\n}\nimpl Pattern {\n    fn empty() -> Self {\n        Self<caret>::Empty\n    }\n}\n",
        0,
    );
    assert_resolves_to_line(
        "self_variant.rs",
        "enum Pattern {\n    Empty,\n}\nimpl Pattern {\n    fn empty() -> Self {\n        Self::Empty<caret>\n    }\n}\n",
        1,
    );
}

#[test]
fn rust_binding_declarations_do_not_resolve_to_same_file_members() {
    assert_resolves_to_nothing(
        "parameter.rs",
        "struct CallbackPattern;\nstruct BuiltIns;\nimpl BuiltIns {\n    fn call(&self) {}\n}\nfn invoke(call<caret>: &CallbackPattern) {}\n",
    );
    assert_resolves_to_nothing(
        "let_binding.rs",
        "struct WrappedResult {\n    actual_sample: usize,\n}\nfn sample() {\n    let mut actual_sample<caret> = 0;\n    actual_sample += 1;\n}\n",
    );
    assert_resolves_to_nothing(
        "pattern.rs",
        "enum Value { Item(i32) }\nstruct BuiltIns;\nimpl BuiltIns {\n    fn call(&self) {}\n}\nfn inspect(value: Value) {\n    match value {\n        Value::Item(call<caret>) => {}\n    }\n}\n",
    );
}

#[test]
fn rust_local_references_do_not_resolve_to_same_file_members() {
    assert_resolves_to_nothing(
        "local_reference.rs",
        "struct WrappedResult {\n    actual_sample: usize,\n}\nfn sample(actual_sample: usize) {\n    let _ = actual_sample<caret>;\n}\n",
    );
}

// Module-qualified associated-fn call: `foo::Foo::new()` from outside an inline
// `mod foo { .. }` should resolve to `new` (line 4).
//
// DEFERRED (resolver architecture). Making this work needs two things: (1) impl
// methods inside inline modules to be extracted — `visit_rust_module` never
// dispatches `impl_item`, so `mod foo { impl Foo { fn m } }` yields `foo.Foo` but
// not `foo.Foo.m`; and (2) scope-sensitive name resolution. (1) is a small fix,
// but it exposes (2): `RustReferenceContext.same_file` is keyed by short
// `identifier()`, so same-named declarations in sibling inline modules collide
// nondeterministically in the HashMap, and `collect_factory_return_types` keys
// module-level factories via `resolve_bare` — together yielding nondeterministic
// and spurious cross-module edges in the inverted usage graph (verified: it
// flakes `usage_graph_rust_test::factory_receiver_uses_resolved_callable_...`).
// The real fix is a position/scope-aware `resolve_bare`, which ripples through
// every Rust resolution caller — its own ExecPlan, not a burndown bolt-on.
#[test]
#[ignore = "deferred: needs scope-sensitive Rust name resolution (see suite comment)"]
fn ra_goto_def_module_qualified_assoc_fn() {
    assert_resolves_to_line(
        "p.rs",
        "mod foo {\n    pub struct Foo;\n\n    impl Foo {\n        pub fn new() -> Foo { Foo }\n    }\n}\n\nfn main() {\n    let _f = foo::Foo::new<caret>();\n}\n",
        4,
    );
}

// #431 (scope-aware resolution): a bare `Config` inside `mod b` resolves to
// `b::Config` (line 4), not the same-named `a::Config` (line 1). Previously the
// flat same-file name map picked one nondeterministically; now the shared
// enclosing-scope resolver (generalized from Java) resolves by position.
#[test]
fn ra_goto_def_bare_type_in_enclosing_module() {
    assert_resolves_to_line(
        "lib.rs",
        "mod a {\n    pub struct Config;\n}\nmod b {\n    pub struct Config;\n    pub struct User {\n        c: Config<caret>,\n    }\n}\n",
        4,
    );
}

#[test]
fn self_referential_let_initializer_does_not_reenter_binding_inference() {
    let (_temp, lines) = definition_lines(
        "self_init.rs",
        "struct Value;\nimpl Value {\n    fn run(&self) {}\n}\nfn demo() {\n    let value = value;\n    value.run<caret>();\n}\n",
    );
    assert!(
        lines.is_empty(),
        "a binding is not in scope in its own initializer: {lines:?}"
    );
}

#[test]
fn shadowing_initializer_can_infer_from_the_outer_binding() {
    assert_resolves_to_line(
        "shadow_init.rs",
        "struct Value;\nimpl Value {\n    fn run(&self) {}\n}\nfn demo() {\n    let value = Value {};\n    {\n        let value = value;\n        value.run<caret>();\n    }\n}\n",
        2,
    );
}
